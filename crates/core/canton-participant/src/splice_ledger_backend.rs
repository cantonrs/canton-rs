//! Participant Ledger API v2 backend client for [`SpliceAppRuntime`](crate::splice_apps::SpliceAppRuntime) (`S-SPL-037`).
//!
//! Connects a Splice application server (`SV`, `Validator`, `Wallet`, `Automation`, `Scan`, and Token
//! Standard `/registry/*`) to an external participant node (`canton-rs json-api` or Canton 3.7.2 JVM)
//! over HTTP/1.1 JSON Ledger API v2 without adding external HTTP client dependencies.
//!
//! Responsibilities:
//! - Pure-Rust HS256 JWT signing (`--ledger-auth-unsafe-secret`) and Admin vs User bearer token routing
//! - Initial DAR upload, hosted party allocation (`DSO`, `sv`, `validator`), and user rights provisioning
//! - Adopting existing `DsoRules` parties when attaching to an already-bootstrapped participant ledger
//! - Incremental `/v2/updates` (`TRANSACTION_SHAPE_LEDGER_EFFECTS`, `includeCreatedEventBlob: true`) sync
//!   into active contracts, V12 `authentication_data` salts, and Scan [`UpdateHistory`](crate::scan_api::UpdateHistory) items
//! - Automatic `disclosedContracts` attachment for DSO reference contracts and non-stakeholder inputs

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lf_eval::fat_contract::{decode_fat_contract_blob, decode_strict_base64, encode_base64};
use lf_eval::scan_state::parse_micros;
use lf_eval::typed_json::{
    format_timestamp, format_timestamp_micros, format_timestamp_trimmed, Types,
};
use lf_eval::{Contract, World};
use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256};

use crate::splice_apps::{SpliceAppError, SpliceBootstrapConfig};

const DSO_DISCLOSURE_TEMPLATES: &[&str] = &[
    "Splice.AmuletRules:AmuletRules",
    "Splice.DsoRules:DsoRules",
    "Splice.ExternalPartyAmuletRules:ExternalPartyAmuletRules",
    "Splice.Ans:AnsRules",
    "Splice.Round:OpenMiningRound",
    "Splice.Round:IssuingMiningRound",
    "Splice.Round:SummarizingMiningRound",
    "Splice.Amulet:FeaturedAppRight",
];

/// Configuration for connecting [`SpliceAppRuntime`](crate::splice_apps::SpliceAppRuntime) to a participant's JSON Ledger API v2.
#[derive(Clone, Debug)]
pub struct ParticipantLedgerConfig {
    pub host: String,
    pub port: u16,
    pub admin_token: Option<String>,
    pub user_id: String,
    pub user_token: Option<String>,
    pub auth_unsafe_secret: Option<String>,
    pub jwt_audience: String,
    pub synchronizer_id: Option<String>,
    pub scan_history_path: Option<PathBuf>,
}

impl Default for ParticipantLedgerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 7575,
            admin_token: None,
            user_id: "ledger-api-user".to_string(),
            user_token: None,
            auth_unsafe_secret: None,
            jwt_audience: "https://canton.network.global".to_string(),
            synchronizer_id: None,
            scan_history_path: None,
        }
    }
}

/// Commit output returned by [`ParticipantLedgerClient::submit_create`] and [`ParticipantLedgerClient::submit_exercise`].
#[derive(Clone, Debug)]
pub struct LedgerSubmitOutcome {
    pub update_id: String,
    pub created: Vec<Contract>,
    pub result: Json,
}

/// Client maintaining synchronized local projections and command submission against a participant JSON API v2.
#[derive(Clone, Debug)]
pub struct ParticipantLedgerClient {
    config: ParticipantLedgerConfig,
    synchronizer_id: String,
    participant_id: String,
    dso_party: String,
    sv_party: String,
    validator_party: String,
    last_synced_offset: u64,
    last_effective_micros: i64,
    next_command_seq: u64,
    known_parties: Vec<String>,
    local_service_parties: BTreeSet<String>,
    granted_act_as: HashSet<String>,
    granted_read_as: HashSet<String>,
    active_contracts: BTreeMap<String, Contract>,
    created_blobs: HashMap<String, String>,
    authentication_data: HashMap<String, Vec<u8>>,
    updates: Vec<Json>,
}

impl ParticipantLedgerClient {
    /// Connects to the configured participant, uploads `dar_paths`, provisions `DSO`/`sv`/`validator` and `user_id`,
    /// syncs any pre-existing ledger history, and adopts existing `DsoRules` parties if already bootstrapped.
    pub fn connect_and_setup(
        config: ParticipantLedgerConfig,
        dar_paths: &[PathBuf],
        world: &World,
        base_cfg: &SpliceBootstrapConfig,
    ) -> Result<Self, String> {
        let mut client = Self {
            config: config.clone(),
            synchronizer_id: config
                .synchronizer_id
                .unwrap_or_else(|| base_cfg.synchronizer_id.clone()),
            participant_id: base_cfg.sv_participant_id.clone(),
            dso_party: String::new(),
            sv_party: String::new(),
            validator_party: String::new(),
            last_synced_offset: 0,
            last_effective_micros: 0,
            next_command_seq: 1,
            known_parties: Vec::new(),
            local_service_parties: BTreeSet::new(),
            granted_act_as: HashSet::new(),
            granted_read_as: HashSet::new(),
            active_contracts: BTreeMap::new(),
            created_blobs: HashMap::new(),
            authentication_data: HashMap::new(),
            updates: Vec::new(),
        };

        client.json("GET", "/v2/version", None).map_err(|e| {
            format!(
                "cannot reach participant JSON Ledger API at {}:{}: {e}",
                client.config.host, client.config.port
            )
        })?;

        if client.config.synchronizer_id.is_none() {
            let syncs = client.json("GET", "/v2/state/connected-synchronizers", None)?;
            client.synchronizer_id = syncs["connectedSynchronizers"][0]["synchronizerId"]
                .as_str()
                .ok_or_else(|| "participant is connected to no synchronizer".to_string())?
                .to_string();
        }

        if let Ok(pid_resp) = client.json("GET", "/v2/parties/participant-id", None) {
            if let Some(pid) = pid_resp["participantId"].as_str().filter(|s| !s.is_empty()) {
                client.participant_id = pid.to_string();
            }
        }

        for dar in dar_paths {
            client.upload_dar(dar)?;
        }

        let listed = client.json("GET", "/v2/parties", None)?;
        if let Some(arr) = listed["partyDetails"].as_array() {
            for entry in arr {
                if let Some(p) = entry["party"].as_str() {
                    if !client.known_parties.iter().any(|k| k == p) {
                        client.known_parties.push(p.to_string());
                    }
                    if entry["isLocal"].as_bool() == Some(true) {
                        client.local_service_parties.insert(p.to_string());
                    }
                }
            }
        }

        // Allocate or adopt core bootstrap parties (`DSO`, `sv`, `validator`).
        let dso = client.ensure_hosted_party_no_rights("DSO")?;
        let sv = client.ensure_hosted_party_no_rights(&base_cfg.sv_name)?;
        let validator = client.ensure_hosted_party_no_rights("validator")?;
        client.dso_party = dso.clone();
        client.sv_party = sv.clone();
        client.validator_party = validator.clone();

        client.ensure_user_with_initial_rights(&[&dso, &sv, &validator])?;

        // Sync existing ledger state; if `DsoRules` is already present, adopt its DSO & SV parties.
        client
            .sync_to_ledger_end(world)
            .map_err(|e| format!("initial ledger sync failed: {e}"))?;
        if let Some(dso_rules) = client
            .active_contracts
            .values()
            .find(|c| c.active && c.template_id == "Splice.DsoRules:DsoRules")
            .cloned()
        {
            let types = Types::new(world);
            if let Ok(tpl_ty) = types.template(&dso_rules.package_id, &dso_rules.template_id) {
                if let Ok(payload_json) = types.encode(&tpl_ty, &dso_rules.payload) {
                    if let Some(existing_dso) = payload_json["dso"].as_str() {
                        client.dso_party = existing_dso.to_string();
                    }
                    if let Some(first_sv) = payload_json["svs"]
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|pair| pair[0].as_str())
                    {
                        client.sv_party = first_sv.to_string();
                    }
                }
            }
        }

        Ok(client)
    }

    pub fn synchronizer_id(&self) -> &str {
        &self.synchronizer_id
    }

    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    pub fn dso_party(&self) -> &str {
        &self.dso_party
    }

    pub fn sv_party(&self) -> &str {
        &self.sv_party
    }

    pub fn validator_party(&self) -> &str {
        &self.validator_party
    }

    pub fn last_synced_offset(&self) -> u64 {
        self.last_synced_offset
    }

    pub fn last_effective_micros(&self) -> i64 {
        self.last_effective_micros
    }

    pub fn active_contracts(&self) -> &BTreeMap<String, Contract> {
        &self.active_contracts
    }

    pub fn authentication_data(&self) -> &HashMap<String, Vec<u8>> {
        &self.authentication_data
    }

    pub fn created_blobs(&self) -> &HashMap<String, String> {
        &self.created_blobs
    }

    pub fn updates(&self) -> &[Json] {
        &self.updates
    }

    pub fn scan_history_path(&self) -> Option<&std::path::Path> {
        self.config.scan_history_path.as_deref()
    }

    pub fn lookup_known_party(&self, hint: &str) -> Option<&str> {
        if hint.contains("::") {
            self.known_parties
                .iter()
                .find(|p| p.as_str() == hint)
                .map(String::as_str)
        } else {
            let prefix = format!("{hint}::");
            self.known_parties
                .iter()
                .find(|p| p.starts_with(&prefix))
                .map(String::as_str)
        }
    }

    /// Ensures `hint_or_party` exists on the participant (if bare hint) and grants read/act rights to `config.user_id`.
    pub fn ensure_party_and_grant(
        &mut self,
        hint_or_party: &str,
    ) -> Result<String, SpliceAppError> {
        if hint_or_party.contains("::") {
            let full = hint_or_party.to_string();
            if !self.known_parties.iter().any(|p| p == &full) {
                self.known_parties.push(full.clone());
            }
            if self.is_local_party(&full) {
                self.local_service_parties.insert(full.clone());
                self.grant_party_rights(&full, true)
                    .map_err(SpliceAppError::Internal)?;
            } else {
                self.grant_party_rights(&full, false)
                    .map_err(SpliceAppError::Internal)?;
            }
            return Ok(full);
        }

        let party = self
            .ensure_hosted_party_no_rights(hint_or_party)
            .map_err(SpliceAppError::Internal)?;
        self.grant_party_rights(&party, true)
            .map_err(SpliceAppError::Internal)?;
        Ok(party)
    }

    /// Pulls committed updates from `(last_synced_offset, ledger_end]` using `TRANSACTION_SHAPE_LEDGER_EFFECTS`
    /// and updates `active_contracts`, `created_blobs`, `authentication_data`, and Scan `updates`.
    pub fn sync_to_ledger_end(&mut self, world: &World) -> Result<bool, SpliceAppError> {
        let end_resp = self
            .json("GET", "/v2/state/ledger-end", None)
            .map_err(SpliceAppError::Internal)?;
        let ledger_end = end_resp["offset"]
            .as_u64()
            .or_else(|| {
                end_resp["offset"]
                    .as_i64()
                    .and_then(|v| u64::try_from(v).ok())
            })
            .unwrap_or(0);
        if ledger_end <= self.last_synced_offset {
            return Ok(false);
        }

        self.refresh_known_parties()
            .map_err(SpliceAppError::Internal)?;

        let filters_by_party: Map<String, Json> = self
            .known_parties
            .iter()
            .map(|party| {
                (
                    party.clone(),
                    json!({
                        "cumulative": [{
                            "identifierFilter": {
                                "WildcardFilter": {
                                    "value": { "includeCreatedEventBlob": true }
                                }
                            }
                        }]
                    }),
                )
            })
            .collect();
        if filters_by_party.is_empty() {
            self.last_synced_offset = ledger_end;
            return Ok(false);
        }

        let req_body = json!({
            "beginExclusive": self.last_synced_offset,
            "endInclusive": ledger_end,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": {
                        "filtersByParty": filters_by_party,
                        "verbose": true
                    },
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        });
        let raw_updates = self
            .json("POST", "/v2/updates", Some(&req_body))
            .map_err(SpliceAppError::Internal)?;
        let Some(items) = raw_updates.as_array() else {
            return Err(SpliceAppError::Internal(format!(
                "/v2/updates returned non-array: {raw_updates}"
            )));
        };

        let mut changed = false;
        let types = Types::new(world);
        for item in items {
            let Some(tx) = item.pointer("/update/Transaction/value") else {
                continue;
            };
            if self
                .ingest_transaction(&types, world, tx)
                .map_err(SpliceAppError::Internal)?
            {
                changed = true;
            }
        }
        self.last_synced_offset = ledger_end;
        Ok(changed)
    }

    /// Attaches active DSO reference contract blobs (`AmuletRules`, `DsoRules`, rounds, etc.), `target_cid`,
    /// and any active contract IDs referenced inside `arg_json`.
    pub fn build_disclosed_contracts(
        &self,
        target_cid: Option<&str>,
        arg_json: &Json,
    ) -> Vec<Json> {
        let mut candidate_cids: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for (cid, contract) in &self.active_contracts {
            if contract.active
                && DSO_DISCLOSURE_TEMPLATES.contains(&contract.template_id.as_str())
                && seen.insert(cid.clone())
            {
                candidate_cids.push(cid.clone());
            }
        }
        if let Some(cid) = target_cid {
            if seen.insert(cid.to_string()) {
                candidate_cids.push(cid.to_string());
            }
        }
        collect_referenced_cids(
            arg_json,
            &self.active_contracts,
            &mut seen,
            &mut candidate_cids,
        );

        let mut out = Vec::new();
        for cid in candidate_cids {
            let Some(contract) = self.active_contracts.get(&cid) else {
                continue;
            };
            if !contract.active {
                continue;
            }
            let Some(blob) = self.created_blobs.get(&cid).filter(|b| !b.is_empty()) else {
                continue;
            };
            out.push(json!({
                "templateId": format!("{}:{}", contract.package_id, contract.template_id),
                "contractId": cid,
                "createdEventBlob": blob,
                "synchronizerId": self.synchronizer_id,
            }));
        }
        out
    }

    /// Submits a `CreateCommand` via `/v2/commands/submit-and-wait-for-transaction`, syncs ledger state,
    /// and returns the created contract(s) and update ID.
    pub fn submit_create(
        &mut self,
        world: &World,
        act_as: &[&str],
        package_id: &str,
        template_id: &str,
        payload_json: &Json,
        workflow_id: &str,
    ) -> Result<LedgerSubmitOutcome, SpliceAppError> {
        let types = Types::new(world);
        let tpl_ty = types
            .template(package_id, template_id)
            .map_err(SpliceAppError::BadRequest)?;
        let decoded = types
            .decode(&tpl_ty, payload_json)
            .map_err(|e| SpliceAppError::BadRequest(format!("{template_id}: {e}")))?;
        let lapi_arg = types
            .encode_ledger_api_omitting_nulls(&tpl_ty, &decoded)
            .map_err(SpliceAppError::Internal)?;

        let disclosed = self.build_disclosed_contracts(None, payload_json);
        let command = json!({
            "CreateCommand": {
                "templateId": format!("{package_id}:{template_id}"),
                "createArguments": lapi_arg,
            }
        });
        let tx = self.submit_command(act_as, workflow_id, command, disclosed)?;
        let update_id = tx["updateId"].as_str().unwrap_or_default().to_string();
        let created_cids = extract_created_cids(&tx);

        self.sync_to_ledger_end(world)?;
        let created = self.contracts_by_cids(&created_cids);
        let result = match created_cids.first() {
            Some(cid) => json!({ "contract_id": cid }),
            None => json!({}),
        };
        Ok(LedgerSubmitOutcome {
            update_id,
            created,
            result,
        })
    }

    /// Submits an `ExerciseCommand` via `/v2/commands/submit-and-wait-for-transaction`, syncs ledger state,
    /// and returns the created contracts and Scan-encoded exercise result.
    pub fn submit_exercise(
        &mut self,
        world: &World,
        act_as: &[&str],
        target: &Contract,
        choice: &str,
        arg_json: &Json,
        workflow_id: &str,
    ) -> Result<LedgerSubmitOutcome, SpliceAppError> {
        let types = Types::new(world);
        let choice_types = types
            .choice(&target.package_id, &target.template_id, choice)
            .map_err(SpliceAppError::Internal)?;
        let decoded_arg = types
            .decode(&choice_types.argument, arg_json)
            .map_err(|e| SpliceAppError::BadRequest(format!("{choice}: {e}")))?;
        let lapi_arg = types
            .encode_ledger_api_omitting_nulls(&choice_types.argument, &decoded_arg)
            .map_err(SpliceAppError::Internal)?;

        let disclosed = self.build_disclosed_contracts(Some(&target.contract_id), arg_json);
        let command = json!({
            "ExerciseCommand": {
                "templateId": format!("{}:{}", target.package_id, target.template_id),
                "contractId": target.contract_id,
                "choice": choice,
                "choiceArgument": lapi_arg,
            }
        });
        let tx = self.submit_command(act_as, workflow_id, command, disclosed)?;
        let update_id = tx["updateId"].as_str().unwrap_or_default().to_string();
        let created_cids = extract_created_cids(&tx);
        let result = extract_root_exercise_result(&tx, &target.contract_id, choice)
            .and_then(|raw_res| {
                types
                    .decode(&choice_types.result, &raw_res)
                    .ok()
                    .and_then(|val| types.encode(&choice_types.result, &val).ok())
                    .or(Some(raw_res))
            })
            .unwrap_or(Json::Null);

        self.sync_to_ledger_end(world)?;
        let created = self.contracts_by_cids(&created_cids);
        Ok(LedgerSubmitOutcome {
            update_id,
            created,
            result,
        })
    }

    fn contracts_by_cids(&self, cids: &[String]) -> Vec<Contract> {
        cids.iter()
            .filter_map(|cid| self.active_contracts.get(cid).cloned())
            .collect()
    }

    fn submit_command(
        &mut self,
        act_as: &[&str],
        workflow_id: &str,
        command: Json,
        disclosed: Vec<Json>,
    ) -> Result<Json, SpliceAppError> {
        let mut act_vec: Vec<String> = Vec::new();
        for p in act_as {
            let resolved = self.ensure_party_and_grant(p)?;
            if !act_vec.contains(&resolved) {
                act_vec.push(resolved);
            }
        }
        let read_as: Vec<String> = self
            .local_service_parties
            .iter()
            .filter(|p| !act_vec.contains(*p))
            .cloned()
            .collect();

        let mut filters: Map<String, Json> = Map::new();
        for p in act_vec.iter().chain(&read_as) {
            filters.insert(
                p.clone(),
                json!({
                    "cumulative": [{
                        "identifierFilter": {
                            "WildcardFilter": {
                                "value": { "includeCreatedEventBlob": true }
                            }
                        }
                    }]
                }),
            );
        }

        const MAX_TOPOLOGY_ATTEMPTS: usize = 6;
        for attempt in 0..MAX_TOPOLOGY_ATTEMPTS {
            let seq = self.next_command_seq;
            self.next_command_seq += 1;
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let command_id = format!("splice-serve-{nanos}-{seq}");

            let body = json!({
                "commands": {
                    "commands": [command.clone()],
                    "commandId": command_id,
                    "workflowId": workflow_id,
                    "userId": self.config.user_id,
                    "actAs": act_vec,
                    "readAs": read_as,
                    "synchronizerId": self.synchronizer_id,
                    "disclosedContracts": disclosed.clone(),
                },
                "transactionFormat": {
                    "eventFormat": {
                        "filtersByParty": filters.clone(),
                        "verbose": true
                    },
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            });
            let (status, answer) = self
                .call(
                    "POST",
                    "/v2/commands/submit-and-wait-for-transaction",
                    Some(&body),
                )
                .map_err(SpliceAppError::Internal)?;
            if status / 100 == 2 {
                return Ok(answer["transaction"].clone());
            }
            if is_retryable_submit_response(status, &answer) && attempt + 1 < MAX_TOPOLOGY_ATTEMPTS
            {
                std::thread::sleep(Duration::from_millis(300));
                continue;
            }
            return Err(map_ledger_error(status, &answer));
        }
        Err(SpliceAppError::Internal(
            "submit_command exhausted retry attempts".into(),
        ))
    }

    fn ingest_transaction(
        &mut self,
        types: &Types<'_>,
        world: &World,
        tx: &Json,
    ) -> Result<bool, String> {
        let Some(update_id) = tx["updateId"].as_str().filter(|s| !s.is_empty()) else {
            return Ok(false);
        };
        if self
            .updates
            .iter()
            .any(|u| u["update_id"].as_str() == Some(update_id))
        {
            return Ok(false);
        }
        let workflow_id = tx["workflowId"].as_str().unwrap_or("");
        let effective_str = tx["effectiveAt"]
            .as_str()
            .ok_or_else(|| format!("transaction {update_id} missing effectiveAt"))?;
        let effective_micros = parse_micros(effective_str)
            .map_err(|e| format!("transaction {update_id} effectiveAt '{effective_str}': {e}"))?;
        let record_micros = tx["recordTime"]
            .as_str()
            .and_then(|s| parse_micros(s).ok())
            .unwrap_or(effective_micros);
        let sync_id = tx["synchronizerId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.synchronizer_id);
        self.last_effective_micros = self.last_effective_micros.max(effective_micros);

        let raw_events = tx["events"].as_array().cloned().unwrap_or_default();
        let mut by_id: Map<String, Json> = Map::new();
        let mut roots: Vec<String> = Vec::new();
        let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut open: Vec<(u64, String)> = Vec::new();
        let mut event_seq: usize = 0;

        for raw in &raw_events {
            if let Some(ce) = raw.get("CreatedEvent") {
                let cid = ce["contractId"].as_str().unwrap_or_default();
                let full_tpl = ce["templateId"].as_str().unwrap_or_default();
                let Some((pkg_id, local_tpl)) = full_tpl.split_once(':') else {
                    continue;
                };
                if !world.has_package(pkg_id) {
                    continue;
                }
                let Ok(tpl_ty) = types.template(pkg_id, local_tpl) else {
                    continue;
                };
                let Ok(payload) = types.decode(&tpl_ty, &ce["createArgument"]) else {
                    continue;
                };
                let mut signatories = string_array(&ce["signatories"]);
                signatories.sort();
                signatories.dedup();
                let mut observers = string_array(&ce["observers"]);
                observers.sort();
                observers.dedup();
                let key = ce
                    .get("contractKey")
                    .filter(|v| !v.is_null())
                    .and_then(|kv| {
                        types
                            .template_key_type(pkg_id, local_tpl)
                            .ok()
                            .flatten()
                            .and_then(|kt| types.decode(&kt, kv).ok())
                    });

                let contract = Contract {
                    contract_id: cid.to_string(),
                    package_id: pkg_id.to_string(),
                    template_id: local_tpl.to_string(),
                    payload: payload.clone(),
                    signatories: signatories.clone(),
                    observers: observers.clone(),
                    active: true,
                    key,
                };
                self.active_contracts.insert(cid.to_string(), contract);

                if let Some(blob) = ce["createdEventBlob"].as_str().filter(|b| !b.is_empty()) {
                    self.created_blobs.insert(cid.to_string(), blob.to_string());
                    if let Ok(bytes) = decode_strict_base64(blob) {
                        if let Ok(fat) = decode_fat_contract_blob(&bytes) {
                            if !fat.authentication_data.is_empty() {
                                self.authentication_data
                                    .insert(cid.to_string(), fat.authentication_data);
                            }
                        }
                    }
                }

                let node_id = ce["nodeId"].as_u64().unwrap_or(event_seq as u64);
                let event_id = format!("{update_id}:{event_seq}");
                event_seq += 1;
                place_event_in_tree(
                    node_id,
                    None,
                    &event_id,
                    &mut open,
                    &mut roots,
                    &mut children_map,
                );

                let created_micros = ce["createdAt"]
                    .as_str()
                    .and_then(|s| parse_micros(s).ok())
                    .unwrap_or(effective_micros);
                let pkg_name = types
                    .package_name(pkg_id)
                    .ok()
                    .or_else(|| ce["packageName"].as_str().map(String::from))
                    .unwrap_or_default();
                let create_arguments = types
                    .encode(&tpl_ty, &payload)
                    .unwrap_or_else(|_| ce["createArgument"].clone());
                by_id.insert(
                    event_id.clone(),
                    json!({
                        "event_type": "created_event",
                        "event_id": event_id,
                        "contract_id": cid,
                        "template_id": full_tpl,
                        "package_name": pkg_name,
                        "create_arguments": create_arguments,
                        "created_at": format_timestamp_trimmed(created_micros),
                        "signatories": signatories,
                        "observers": observers,
                    }),
                );
            } else if let Some(ex) = raw.get("ExercisedEvent") {
                let cid = ex["contractId"].as_str().unwrap_or_default();
                let full_tpl = ex["templateId"].as_str().unwrap_or_default();
                let choice = ex["choice"].as_str().unwrap_or_default();
                let consuming = ex["consuming"].as_bool().unwrap_or(false);
                let iface_id = ex["interfaceId"].as_str().filter(|s| !s.is_empty());

                if consuming {
                    self.active_contracts.remove(cid);
                }

                let choice_types = if let Some(iface) = iface_id {
                    iface.split_once(':').and_then(|(ipkg, ilocal)| {
                        types.interface_choice(ipkg, ilocal, choice).ok()
                    })
                } else {
                    full_tpl
                        .split_once(':')
                        .and_then(|(tpkg, tlocal)| types.choice(tpkg, tlocal, choice).ok())
                };
                if choice_types.is_none()
                    && !full_tpl
                        .split_once(':')
                        .is_some_and(|(p, _)| world.has_package(p))
                {
                    continue;
                }

                let node_id = ex["nodeId"].as_u64().unwrap_or(event_seq as u64);
                let last_desc = ex["lastDescendantNodeId"].as_u64().unwrap_or(node_id);
                let event_id = format!("{update_id}:{event_seq}");
                event_seq += 1;
                place_event_in_tree(
                    node_id,
                    Some(last_desc),
                    &event_id,
                    &mut open,
                    &mut roots,
                    &mut children_map,
                );

                let choice_argument = choice_types
                    .as_ref()
                    .and_then(|ct| {
                        let val = types.decode(&ct.argument, &ex["choiceArgument"]).ok()?;
                        types.encode(&ct.argument, &val).ok()
                    })
                    .unwrap_or_else(|| ex["choiceArgument"].clone());
                let exercise_result = choice_types
                    .as_ref()
                    .and_then(|ct| {
                        let val = types.decode(&ct.result, &ex["exerciseResult"]).ok()?;
                        types.encode(&ct.result, &val).ok()
                    })
                    .unwrap_or_else(|| ex["exerciseResult"].clone());
                let mut acting = string_array(&ex["actingParties"]);
                acting.sort();
                let pkg_name = full_tpl
                    .split_once(':')
                    .and_then(|(p, _)| types.package_name(p).ok())
                    .or_else(|| ex["packageName"].as_str().map(String::from))
                    .unwrap_or_default();

                by_id.insert(
                    event_id.clone(),
                    json!({
                        "event_type": "exercised_event",
                        "event_id": event_id,
                        "contract_id": cid,
                        "template_id": full_tpl,
                        "package_name": pkg_name,
                        "choice": choice,
                        "choice_argument": choice_argument,
                        "child_event_ids": [],
                        "exercise_result": exercise_result,
                        "consuming": consuming,
                        "acting_parties": acting,
                        "interface_id": iface_id,
                    }),
                );
            } else if let Some(ar) = raw.get("ArchivedEvent") {
                if let Some(cid) = ar["contractId"].as_str() {
                    self.active_contracts.remove(cid);
                }
            }
        }

        if by_id.is_empty() {
            return Ok(false);
        }

        for (eid, ev) in by_id.iter_mut() {
            if ev["event_type"] == "exercised_event" {
                if let Some(ch) = children_map.get(eid) {
                    ev["child_event_ids"] = Json::Array(ch.iter().map(|s| json!(s)).collect());
                }
            }
        }

        self.updates.push(json!({
            "update_id": update_id,
            "migration_id": 0,
            "workflow_id": workflow_id,
            "record_time": format_timestamp_micros(record_micros),
            "synchronizer_id": sync_id,
            "effective_at": format_timestamp(effective_micros),
            "root_event_ids": roots,
            "events_by_id": by_id,
        }));
        Ok(true)
    }

    fn is_local_party(&self, party: &str) -> bool {
        self.local_service_parties.contains(party)
    }

    fn refresh_known_parties(&mut self) -> Result<(), String> {
        let listed = self.json("GET", "/v2/parties", None)?;
        let Some(arr) = listed["partyDetails"].as_array() else {
            return Ok(());
        };
        let mut to_grant: Vec<(String, bool)> = Vec::new();
        for entry in arr {
            let Some(p) = entry["party"].as_str() else {
                continue;
            };
            let is_local = entry["isLocal"].as_bool() == Some(true);
            if !self.known_parties.iter().any(|k| k == p) {
                self.known_parties.push(p.to_string());
            }
            if is_local {
                self.local_service_parties.insert(p.to_string());
            }
            if !self.granted_read_as.contains(p) {
                to_grant.push((p.to_string(), is_local));
            }
        }
        for (party, is_local) in to_grant {
            // Best-effort grant so external parties created concurrently become visible in `/v2/updates`
            let _ = self.grant_party_rights(&party, is_local);
        }
        Ok(())
    }

    fn ensure_hosted_party_no_rights(&mut self, hint: &str) -> Result<String, String> {
        if hint.contains("::") {
            if !self.known_parties.iter().any(|p| p == hint) {
                self.known_parties.push(hint.to_string());
            }
            self.local_service_parties.insert(hint.to_string());
            return Ok(hint.to_string());
        }
        let listed = self.json("GET", "/v2/parties", None)?;
        let prefix = format!("{hint}::");
        if let Some(found) = listed["partyDetails"].as_array().and_then(|all| {
            all.iter()
                .filter(|p| p["isLocal"].as_bool() != Some(false))
                .filter_map(|p| p["party"].as_str())
                .find(|p| p.starts_with(&prefix))
        }) {
            let full = found.to_string();
            if !self.known_parties.iter().any(|p| p == &full) {
                self.known_parties.push(full.clone());
            }
            self.local_service_parties.insert(full.clone());
            return Ok(full);
        }
        let made = self.json(
            "POST",
            "/v2/parties",
            Some(&json!({ "partyIdHint": hint, "identityProviderId": "" })),
        )?;
        let full = made["partyDetails"]["party"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("allocating party {hint}: no party in {made}"))?;
        if !self.known_parties.iter().any(|p| p == &full) {
            self.known_parties.push(full.clone());
        }
        self.local_service_parties.insert(full.clone());
        Ok(full)
    }

    fn ensure_user_with_initial_rights(&mut self, parties: &[&str]) -> Result<(), String> {
        let mut rights: Vec<Json> = Vec::new();
        for p in parties {
            rights.push(json!({ "kind": { "CanActAs": { "value": { "party": p } } } }));
            rights.push(json!({ "kind": { "CanReadAs": { "value": { "party": p } } } }));
        }
        rights.push(json!({ "kind": { "ParticipantAdmin": { "value": {} } } }));
        rights.push(json!({ "kind": { "CanReadAsAnyParty": { "value": {} } } }));

        let body = json!({
            "user": {
                "id": self.config.user_id,
                "isDeactivated": false,
                "primaryParty": "",
                "identityProviderId": "",
                "metadata": { "resourceVersion": "", "annotations": {} }
            },
            "rights": rights,
        });
        let (status, answer) = self.call("POST", "/v2/users", Some(&body))?;
        match status {
            200 | 201 => {
                for p in parties {
                    self.granted_act_as.insert((*p).to_string());
                    self.granted_read_as.insert((*p).to_string());
                }
                Ok(())
            }
            409 => {
                let rights_path = format!("/v2/users/{}/rights", url_encode(&self.config.user_id));
                let grant_body = json!({
                    "userId": self.config.user_id,
                    "identityProviderId": "",
                    "rights": rights,
                });
                self.json("POST", &rights_path, Some(&grant_body))?;
                for p in parties {
                    self.granted_act_as.insert((*p).to_string());
                    self.granted_read_as.insert((*p).to_string());
                }
                Ok(())
            }
            other => Err(format!(
                "POST /v2/users for '{}' answered {other}: {}",
                self.config.user_id,
                error_cause(&answer)
            )),
        }
    }

    fn grant_party_rights(&mut self, party: &str, act_as: bool) -> Result<(), String> {
        let need_act = act_as && !self.granted_act_as.contains(party);
        let need_read = !self.granted_read_as.contains(party);
        if !need_act && !need_read {
            return Ok(());
        }
        let mut rights = Vec::new();
        if need_act {
            rights.push(json!({ "kind": { "CanActAs": { "value": { "party": party } } } }));
        }
        if need_read {
            rights.push(json!({ "kind": { "CanReadAs": { "value": { "party": party } } } }));
        }
        let rights_path = format!("/v2/users/{}/rights", url_encode(&self.config.user_id));
        let (status, answer) = self.call(
            "POST",
            &rights_path,
            Some(&json!({
                "userId": self.config.user_id,
                "identityProviderId": "",
                "rights": rights,
            })),
        )?;
        if status / 100 != 2 {
            return Err(format!(
                "POST {rights_path} answered {status}: {}",
                error_cause(&answer)
            ));
        }
        if need_act {
            self.granted_act_as.insert(party.to_string());
        }
        if need_read {
            self.granted_read_as.insert(party.to_string());
        }
        Ok(())
    }

    fn upload_dar(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (status, answer) = self.call_raw(
            "POST",
            "/v2/dars",
            Some((&bytes, "application/octet-stream")),
        )?;
        if status / 100 == 2
            || status == 409
            || answer["code"]
                .as_str()
                .is_some_and(|c| c.contains("ALREADY"))
        {
            return Ok(());
        }
        Err(format!(
            "uploading {} answered {status}: {}",
            path.display(),
            error_cause(&answer)
        ))
    }

    fn json(&self, method: &str, path: &str, body: Option<&Json>) -> Result<Json, String> {
        let (status, answer) = self.call(method, path, body)?;
        if status / 100 != 2 {
            return Err(format!(
                "{method} {path} answered {status}: {}",
                error_cause(&answer)
            ));
        }
        Ok(answer)
    }

    fn call(&self, method: &str, path: &str, body: Option<&Json>) -> Result<(u16, Json), String> {
        let serialized = body.map(|b| b.to_string());
        self.call_raw(
            method,
            path,
            serialized
                .as_deref()
                .map(|s| (s.as_bytes(), "application/json")),
        )
    }

    fn call_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<(u16, Json), String> {
        // [CANTON-NOTE: DEFENSIVE] Upstream Splice/Canton proxies and onboarding validators can emit
        // transient 502/503/504 responses without a structured Daml rejection code during startup warmup.
        const MAX_TRANSIENT_HTTP_ATTEMPTS: usize = 6;
        let token = self.token_for(path);
        for attempt in 0..MAX_TRANSIENT_HTTP_ATTEMPTS {
            let (status, answer) = http_call_with_token(
                &self.config.host,
                self.config.port,
                method,
                path,
                body,
                token.as_deref(),
            )?;
            if is_transient_http_response(status, &answer)
                && attempt + 1 < MAX_TRANSIENT_HTTP_ATTEMPTS
            {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            return Ok((status, answer));
        }
        Err(format!("{method} {path}: transient HTTP retries exhausted"))
    }

    /// Selects the user token for ledger stream/command routes and admin token for DAR/party/user routes.
    pub fn token_for(&self, path: &str) -> Option<String> {
        let is_user_route = path.starts_with("/v2/state/ledger-end")
            || path.starts_with("/v2/state/active-contracts")
            || path.starts_with("/v2/updates")
            || path.starts_with("/v2/commands/")
            || path.starts_with("/v2/events/")
            || path.starts_with("/v2/contracts/");
        if is_user_route {
            if let Some(tok) = self
                .config
                .user_token
                .as_ref()
                .or(self.config.admin_token.as_ref())
            {
                return Some(tok.clone());
            }
            return self
                .config
                .auth_unsafe_secret
                .as_deref()
                .map(|s| sign_hs256_jwt(s, &self.config.user_id, &self.config.jwt_audience));
        }
        if let Some(tok) = self
            .config
            .admin_token
            .as_ref()
            .or(self.config.user_token.as_ref())
        {
            return Some(tok.clone());
        }
        self.config
            .auth_unsafe_secret
            .as_deref()
            .map(|s| sign_hs256_jwt(s, "participant_admin", &self.config.jwt_audience))
    }
}

fn place_event_in_tree(
    node_id: u64,
    last_descendant_if_exercise: Option<u64>,
    event_id: &str,
    open: &mut Vec<(u64, String)>,
    roots: &mut Vec<String>,
    children_map: &mut HashMap<String, Vec<String>>,
) {
    while open
        .last()
        .is_some_and(|(last_desc, _)| node_id > *last_desc)
    {
        open.pop();
    }
    match open.last() {
        Some((_, parent_eid)) => {
            children_map
                .entry(parent_eid.clone())
                .or_default()
                .push(event_id.to_string());
        }
        None => roots.push(event_id.to_string()),
    }
    if let Some(last_desc) = last_descendant_if_exercise {
        open.push((last_desc, event_id.to_string()));
    }
}

fn collect_referenced_cids(
    v: &Json,
    active: &BTreeMap<String, Contract>,
    seen: &mut HashSet<String>,
    out: &mut Vec<String>,
) {
    match v {
        Json::String(s) => {
            if active.contains_key(s.as_str()) && seen.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        Json::Array(arr) => {
            for item in arr {
                collect_referenced_cids(item, active, seen, out);
            }
        }
        Json::Object(obj) => {
            for val in obj.values() {
                collect_referenced_cids(val, active, seen, out);
            }
        }
        _ => {}
    }
}

fn extract_created_cids(tx: &Json) -> Vec<String> {
    let mut out = Vec::new();
    let mut archived_here: HashSet<&str> = HashSet::new();
    if let Some(events) = tx["events"].as_array() {
        for ev in events {
            if let Some(ar) = ev.get("ArchivedEvent") {
                if let Some(cid) = ar["contractId"].as_str() {
                    archived_here.insert(cid);
                }
            } else if let Some(ex) = ev.get("ExercisedEvent") {
                if ex["consuming"].as_bool() == Some(true) {
                    if let Some(cid) = ex["contractId"].as_str() {
                        archived_here.insert(cid);
                    }
                }
            }
        }
        for ev in events {
            if let Some(ce) = ev.get("CreatedEvent") {
                if let Some(cid) = ce["contractId"].as_str() {
                    if !archived_here.contains(cid) {
                        out.push(cid.to_string());
                    }
                }
            }
        }
    }
    out
}

fn extract_root_exercise_result(tx: &Json, target_cid: &str, choice: &str) -> Option<Json> {
    let events = tx["events"].as_array()?;
    events
        .iter()
        .find_map(|ev| {
            let ex = ev.get("ExercisedEvent")?;
            (ex["contractId"].as_str() == Some(target_cid) && ex["choice"].as_str() == Some(choice))
                .then(|| ex["exerciseResult"].clone())
        })
        .or_else(|| {
            events.iter().find_map(|ev| {
                ev.get("ExercisedEvent")
                    .map(|ex| ex["exerciseResult"].clone())
            })
        })
}

fn string_array(v: &Json) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(String::from))
        .collect()
}

fn map_ledger_error(status: u16, body: &Json) -> SpliceAppError {
    let msg = error_cause(body);
    let code = body["code"].as_str().unwrap_or_default();
    match status {
        401 | 403 => SpliceAppError::Unauthorized(msg),
        404 => SpliceAppError::NotFound(msg),
        409 => SpliceAppError::Conflict(msg),
        400 => {
            if code.contains("NOT_FOUND") || code.contains("CONTRACT_NOT_ACTIVE") {
                SpliceAppError::NotFound(msg)
            } else if code.contains("LOCKED")
                || code.contains("DUPLICATE")
                || code.contains("CONFLICT")
            {
                SpliceAppError::Conflict(msg)
            } else {
                SpliceAppError::BadRequest(msg)
            }
        }
        _ => SpliceAppError::Internal(msg),
    }
}

fn is_transient_http_response(status: u16, answer: &Json) -> bool {
    let has_structured_code =
        answer.is_object() && answer.get("code").and_then(Json::as_str).is_some();
    matches!(status, 502..=504) && !has_structured_code
}

fn is_retryable_submit_response(status: u16, answer: &Json) -> bool {
    if matches!(status, 502..=504) {
        return true;
    }
    matches!(status, 400 | 404 | 409) && {
        let cause = error_cause(answer);
        cause.contains("NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT")
            || cause.contains("UNKNOWN_INFORMEES")
            || cause.contains("PACKAGE_NOT_FOUND")
            || cause.contains("NOT_VETTED")
    }
}

fn error_cause(body: &Json) -> String {
    match body {
        Json::Object(o) => match (o.get("code"), o.get("cause")) {
            (Some(code), Some(cause)) => format!(
                "{}: {}",
                code.as_str().unwrap_or_default(),
                cause.as_str().unwrap_or_default()
            ),
            _ => body.to_string(),
        },
        other => other.to_string(),
    }
}

/// Generates a compact HS256 JWT matching Canton / Splice `--auth-unsafe-secret` settings.
pub fn sign_hs256_jwt(secret: &str, subject: &str, audience: &str) -> String {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let header = encode_b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = json!({
        "sub": subject,
        "aud": audience,
        "exp": now_secs + 3600,
    });
    let payload = encode_b64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mac = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let sig = encode_b64url(&mac);
    format!("{signing_input}.{sig}")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed: [u8; 32] = Sha256::digest(key).into();
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut o_pad = [0x5cu8; 64];
    let mut i_pad = [0x36u8; 64];
    for i in 0..64 {
        o_pad[i] ^= k_block[i];
        i_pad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(i_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn encode_b64url(bytes: &[u8]) -> String {
    encode_base64(bytes)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

fn url_encode(part: &str) -> String {
    part.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn http_call_with_token(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&[u8], &str)>,
    token: Option<&str>,
) -> Result<(u16, Json), String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("cannot reach the JSON Ledger API at {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    let (payload, content_type): (&[u8], &str) = body.unwrap_or((b"", "application/json"));
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: {content_type}\r\nAccept: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(payload))
        .map_err(|e| format!("{method} {path}: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("{method} {path}: {e}"))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("{method} {path}: no HTTP header in the answer"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body_bytes = raw[split + 4..].to_vec();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("{method} {path}: bad status line"))?;
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body_bytes = dechunk(&body_bytes);
    }
    let json = if body_bytes.is_empty() {
        Json::Null
    } else {
        serde_json::from_slice(&body_bytes)
            .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(&body_bytes).to_string()))
    };
    Ok((status, json))
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let Some(eol) = body[at..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_text = String::from_utf8_lossy(&body[at..at + eol]).to_string();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        at += eol + 2;
        if size == 0 || at + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[at..at + size]);
        at += size + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    fn test_client(port: u16) -> ParticipantLedgerClient {
        ParticipantLedgerClient {
            config: ParticipantLedgerConfig {
                host: "127.0.0.1".to_string(),
                port,
                ..Default::default()
            },
            synchronizer_id: "sync::1".to_string(),
            participant_id: "par::1".to_string(),
            dso_party: "DSO::1".to_string(),
            sv_party: "sv::1".to_string(),
            validator_party: "val::1".to_string(),
            last_synced_offset: 0,
            last_effective_micros: 0,
            next_command_seq: 1,
            known_parties: Vec::new(),
            local_service_parties: BTreeSet::new(),
            granted_act_as: HashSet::new(),
            granted_read_as: HashSet::new(),
            active_contracts: BTreeMap::new(),
            created_blobs: HashMap::new(),
            authentication_data: HashMap::new(),
            updates: Vec::new(),
        }
    }

    fn spawn_sequence_http_server(
        responses: Vec<(u16, &'static str, &'static str)>,
    ) -> (u16, Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http server");
        let port = listener.local_addr().expect("mock addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = Arc::clone(&hits);
        let handle = std::thread::spawn(move || {
            for (status, reason, body) in responses {
                let (mut stream, _) = listener.accept().expect("accept mock client");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                hits_bg.fetch_add(1, Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).expect("write mock http");
            }
        });
        (port, hits, handle)
    }

    #[test]
    fn call_raw_retries_transient_503_until_200() {
        let (port, hits, server) = spawn_sequence_http_server(vec![
            (503, "Service Unavailable", "warming up"),
            (503, "Service Unavailable", "still warming"),
            (200, "OK", r#"{"version":"3.7.2"}"#),
        ]);
        let client = test_client(port);
        let body = client
            .json("GET", "/v2/version", None)
            .expect("transient 503s must retry until 200");
        server.join().expect("mock server thread");
        assert_eq!(body["version"], "3.7.2");
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn call_raw_fails_immediately_on_structured_400_negative_control() {
        let (port, hits, server) = spawn_sequence_http_server(vec![(
            400,
            "Bad Request",
            r#"{"code":"INVALID_ARGUMENT","cause":"bad party hint"}"#,
        )]);
        let client = test_client(port);
        let err = client
            .json("POST", "/v2/parties", None)
            .expect_err("structured 400 must fail without retrying");
        server.join().expect("mock server thread");
        assert!(err.contains("answered 400"), "{err}");
        assert!(err.contains("INVALID_ARGUMENT"), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn submit_retry_policy_treats_502_503_504_as_retryable_and_rejects_plain_400() {
        assert!(is_retryable_submit_response(502, &Json::Null));
        assert!(is_retryable_submit_response(
            503,
            &json!({"code": "SERVICE_UNAVAILABLE", "cause": "warming up"})
        ));
        assert!(is_retryable_submit_response(
            504,
            &Json::String("timeout".into())
        ));
        assert!(is_retryable_submit_response(
            400,
            &json!({"code": "NOT_VETTED", "cause": "NOT_VETTED"})
        ));
        assert!(!is_retryable_submit_response(
            400,
            &json!({"code": "INVALID_ARGUMENT", "cause": "negative amount"})
        ));
    }
}
