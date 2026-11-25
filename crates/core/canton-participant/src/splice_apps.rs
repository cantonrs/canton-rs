//! Real DAR-backed Splice 0.10.1 application services (`SV`, `Validator`, `Wallet`, and `Automation`)
//! executing the unmodified official DARs on `lf_eval::Engine` with V12 contract blobs and
//! feeding `crate::scan_api::UpdateHistory` directly.
//!
//! References in `references/splice`:
//! - `apps/sv/src/main/openapi/sv-internal.yaml`
//! - `apps/validator/src/main/openapi/validator-internal.yaml`
//! - `apps/wallet/src/main/openapi/{wallet-internal.yaml,wallet-external.yaml}`
//! - `daml/splice-{dso-governance,amulet,wallet,validator-lifecycle}/daml/...`

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lf_eval::fat_contract::{
    compute_contract_hash, compute_key_hash, compute_unicum, encode_auth_data_v30,
    format_v12_contract_id,
};
use lf_eval::scan_update::{render_update, UpdateMeta};
use lf_eval::typed_json::Types;
use lf_eval::{Contract, ContractIdAllocator, Engine, NewContract, World};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use crate::scan_api::{DsoInfoConfig, Response, UpdateHistory};
use crate::splice_ledger_backend::{ParticipantLedgerClient, ParticipantLedgerConfig};

mod automation;
mod http;
mod lookup;
mod sv_ops;
mod util;
mod wallet;

pub use http::handle_splice_http;
pub use sv_ops::dso_bootstrap_payload;

use http::json_response;
use util::{
    deterministic_party, load_dar_dir, map_exec_error, merge_scan_auth_file, sha256_hex,
    wall_clock_micros,
};

const DEFAULT_INITIAL_TIME_MICROS: i64 = 1_794_620_100_465_024; // 2026-11-14T01:35:00.465024Z
const SCALE_10: i128 = 10_000_000_000;

/// Errors returned by [`SpliceAppRuntime`], carrying an HTTP-mappable category.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SpliceAppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Internal(String),
}

impl SpliceAppError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::Internal(_) => 500,
        }
    }

    pub fn to_response(&self) -> Response {
        json_response(self.status_code(), &json!({ "error": self.to_string() }))
    }
}

/// Configuration used to bootstrap the native Splice 0.10.1 DSO and application services.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpliceBootstrapConfig {
    pub dso_party: String,
    pub sv_party: String,
    pub sv_name: String,
    pub sv_user: String,
    pub sv_participant_id: String,
    pub validator_party: String,
    pub synchronizer_id: String,
    pub mediator_id: String,
    pub sequencer_id: String,
    pub scan_url: String,
    pub sequencer_url: String,
    pub amulet_price: String,
    pub round_tick_duration_micros: i64,
    pub initial_time_micros: i64,
}

impl Default for SpliceBootstrapConfig {
    fn default() -> Self {
        Self {
            dso_party: deterministic_party("DSO"),
            sv_party: deterministic_party("sv"),
            sv_name: "sv".to_string(),
            sv_user: "ledger-api-user".to_string(),
            sv_participant_id: format!("PAR::sv::1220{}", sha256_hex("canton-participant:sv")),
            validator_party: deterministic_party("validator"),
            synchronizer_id: format!(
                "global-domain::1220{}",
                sha256_hex("canton-domain:global-domain")
            ),
            mediator_id: format!("MED::sv::1220{}", sha256_hex("canton-mediator:sv")),
            sequencer_id: format!("SEQ::sv::1220{}", sha256_hex("canton-sequencer:sv")),
            scan_url: "http://127.0.0.1:5012".to_string(),
            sequencer_url: "http://127.0.0.1:5008".to_string(),
            amulet_price: "0.0050000000".to_string(),
            round_tick_duration_micros: 600_000_000,
            initial_time_micros: DEFAULT_INITIAL_TIME_MICROS,
        }
    }
}

/// Per-tick summary produced by [`SpliceAppRuntime::run_automation_tick`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomationTickReport {
    pub transfers_completed: usize,
    pub traffic_requests_completed: usize,
    pub offers_expired: usize,
    pub traffic_requests_expired: usize,
    pub validator_liveness_recorded: usize,
    pub sv_reward_coupons_collected: usize,
    pub mining_rounds_advanced: usize,
    pub vote_requests_closed: usize,
    pub errors: Vec<String>,
}

impl AutomationTickReport {
    pub fn total_actions(&self) -> usize {
        self.transfers_completed
            + self.traffic_requests_completed
            + self.offers_expired
            + self.traffic_requests_expired
            + self.validator_liveness_recorded
            + self.sv_reward_coupons_collected
            + self.mining_rounds_advanced
            + self.vote_requests_closed
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnboardingSecret {
    expires_at_micros: i64,
    party_hint: Option<String>,
    used: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TransferTrackingSpec {
    sender: String,
    receiver: String,
    amount: String,
    description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum TransferTrackingState {
    Created {
        offer_cid: String,
        tx_id: String,
    },
    Accepted {
        accepted_cid: String,
        tx_id: String,
    },
    Completed {
        amulet_cid: String,
        tx_id: String,
    },
    Failed {
        failure_kind: String,
        withdrawn_reason: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransferTrackingEntry {
    spec: TransferTrackingSpec,
    state: TransferTrackingState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TrafficTrackingSpec {
    buyer: String,
    member_id: String,
    synchronizer_id: String,
    traffic_amount: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum TrafficTrackingState {
    Created {
        request_cid: String,
    },
    Completed {
        traffic_cid: String,
        tx_id: String,
    },
    Failed {
        failure_reason: String,
        rejection_reason: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrafficTrackingEntry {
    spec: TrafficTrackingSpec,
    state: TrafficTrackingState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VotedOutcome {
    request_cid: String,
    update_id: String,
    outcome: Json,
}

enum SpliceBackend {
    InProcess,
    ParticipantLedger(Box<ParticipantLedgerClient>),
}

/// Real DAR-backed Splice application runtime hosting SV, Validator, Wallet, Automation, and Scan.
pub struct SpliceAppRuntime {
    config: SpliceBootstrapConfig,
    dar_paths: Vec<PathBuf>,
    world: World,
    backend: SpliceBackend,
    now_micros: i64,
    manual_time_offset_micros: i64,
    next_cid_seq: u64,
    next_update_seq: u64,
    active_contracts: BTreeMap<String, Contract>,
    authentication_data: HashMap<String, Vec<u8>>,
    updates: Vec<Json>,
    onboarding_secrets: HashMap<String, OnboardingSecret>,
    transfer_tracking: HashMap<String, TransferTrackingEntry>,
    traffic_tracking: HashMap<String, TrafficTrackingEntry>,
    vote_outcomes: HashMap<String, VotedOutcome>,
    cached_scan: Option<UpdateHistory>,
}

struct V12RuntimeAllocator<'w> {
    world: &'w World,
    created_at_micros: i64,
    seq: Arc<Mutex<u64>>,
    auth_out: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl ContractIdAllocator for V12RuntimeAllocator<'_> {
    fn allocate(&mut self, new: &NewContract<'_>) -> String {
        let next = {
            let mut guard = self.seq.lock().expect("seq lock");
            let current = *guard;
            *guard += 1;
            current
        };
        let salt: [u8; 32] = Sha256::digest(format!("splice:v12-salt:{next}").as_bytes()).into();
        let disc: [u8; 32] = Sha256::digest(format!("splice:v12-disc:{next}").as_bytes()).into();

        let build = || -> Option<String> {
            let types = Types::new(self.world);
            let pkg_name = types.package_name(new.package_id).ok()?;
            let tpl_ty = types.template(new.package_id, new.template_id).ok()?;
            let contract_hash =
                compute_contract_hash(&types, &pkg_name, new.template_id, &tpl_ty, new.payload)
                    .ok()?;
            let (key_maintainers, key_hash) = match new.key {
                Some((kv, km)) => {
                    let key_ty = types
                        .template_key_type(new.package_id, new.template_id)
                        .ok()??;
                    let kh =
                        compute_key_hash(&types, &pkg_name, new.template_id, &key_ty, kv).ok()?;
                    (km.to_vec(), Some(kh))
                }
                None => (Vec::new(), None),
            };
            let non_sig_obs: Vec<String> = new
                .observers
                .iter()
                .filter(|o| !new.signatories.contains(o))
                .cloned()
                .collect();
            let unicum = compute_unicum(
                &salt,
                self.created_at_micros,
                new.signatories,
                &non_sig_obs,
                key_hash.as_ref(),
                &key_maintainers,
                &contract_hash,
            );
            Some(format_v12_contract_id(&disc, &unicum))
        };

        let cid = build().unwrap_or_else(|| format!("00{:064x}", next + 1));
        if let Ok(mut guard) = self.auth_out.lock() {
            guard.insert(cid.clone(), encode_auth_data_v30(&salt));
        }
        cid
    }
}

struct TxCommitResult {
    update_id: String,
    created: Vec<Contract>,
    result: Json,
}

impl SpliceAppRuntime {
    /// Load every `.dar` inside `dar_dir` (e.g. `tests/oracle/splice-dars`) and prepare the runtime.
    pub fn from_dar_dir(dar_dir: &Path, config: SpliceBootstrapConfig) -> Result<Self, String> {
        let (dar_paths, world) = load_dar_dir(dar_dir)?;

        let initial_time = config.initial_time_micros;
        Ok(Self {
            config,
            dar_paths,
            world,
            backend: SpliceBackend::InProcess,
            now_micros: initial_time,
            manual_time_offset_micros: 0,
            next_cid_seq: 1,
            next_update_seq: 1,
            active_contracts: BTreeMap::new(),
            authentication_data: HashMap::new(),
            updates: Vec::new(),
            onboarding_secrets: HashMap::new(),
            transfer_tracking: HashMap::new(),
            traffic_tracking: HashMap::new(),
            vote_outcomes: HashMap::new(),
            cached_scan: None,
        })
    }

    /// Connect the runtime to an external participant JSON Ledger API v2 server (S-SPL-038).
    pub fn from_participant_ledger(
        dar_dir: &Path,
        mut config: SpliceBootstrapConfig,
        ledger_config: ParticipantLedgerConfig,
    ) -> Result<Self, String> {
        let (dar_paths, world) = load_dar_dir(dar_dir)?;
        let client = ParticipantLedgerClient::connect_and_setup(
            ledger_config.clone(),
            &dar_paths,
            &world,
            &config,
        )?;
        config.dso_party = client.dso_party().to_string();
        config.sv_party = client.sv_party().to_string();
        config.validator_party = client.validator_party().to_string();
        config.synchronizer_id = client.synchronizer_id().to_string();
        config.sv_participant_id = client.participant_id().to_string();
        config.sv_user = ledger_config.user_id;

        let active_contracts = client.active_contracts().clone();
        let authentication_data = client.authentication_data().clone();
        let updates = client.updates().to_vec();
        let now_micros = wall_clock_micros().max(client.last_effective_micros());

        Ok(Self {
            config,
            dar_paths,
            world,
            backend: SpliceBackend::ParticipantLedger(Box::new(client)),
            now_micros,
            manual_time_offset_micros: 0,
            next_cid_seq: 1,
            next_update_seq: 1,
            active_contracts,
            authentication_data,
            updates,
            onboarding_secrets: HashMap::new(),
            transfer_tracking: HashMap::new(),
            traffic_tracking: HashMap::new(),
            vote_outcomes: HashMap::new(),
            cached_scan: None,
        })
    }

    pub fn is_participant_ledger(&self) -> bool {
        matches!(self.backend, SpliceBackend::ParticipantLedger(_))
    }

    pub fn sync_ledger(&mut self) -> Result<(), SpliceAppError> {
        let manual_offset = self.manual_time_offset_micros;
        let SpliceBackend::ParticipantLedger(client) = &mut self.backend else {
            return Ok(());
        };
        let changed = client.sync_to_ledger_end(&self.world)?;
        self.now_micros = wall_clock_micros()
            .max(client.last_effective_micros())
            .saturating_add(manual_offset);
        if changed
            || self.active_contracts.len() != client.active_contracts().len()
            || self.updates.len() != client.updates().len()
        {
            self.active_contracts = client.active_contracts().clone();
            self.authentication_data = client.authentication_data().clone();
            self.updates = client.updates().to_vec();
            self.cached_scan = None;
            self.adopt_parties_from_dso_rules();
        }
        Ok(())
    }

    fn adopt_parties_from_dso_rules(&mut self) {
        let Some(dso_rules) = self
            .active_contracts
            .values()
            .find(|c| c.active && c.template_id == "Splice.DsoRules:DsoRules")
            .cloned()
        else {
            return;
        };
        if let Ok(payload) = self.encoded_payload(&dso_rules) {
            if let Some(dso) = payload["dso"].as_str() {
                self.config.dso_party = dso.to_string();
            }
            if let Some(first_sv) = payload["svs"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|pair| pair[0].as_str())
            {
                self.config.sv_party = first_sv.to_string();
            }
        }
    }

    /// Snapshot off-chain application metadata for persistence in participant-ledger mode.
    pub fn export_offchain_state(&self) -> Json {
        json!({
            "onboarding_secrets": self.onboarding_secrets,
            "transfer_tracking": self.transfer_tracking,
            "traffic_tracking": self.traffic_tracking,
            "vote_outcomes": self.vote_outcomes,
            "manual_time_offset_micros": self.manual_time_offset_micros,
        })
    }

    /// Restore off-chain application metadata persisted in `splice-ledger-meta`.
    pub fn import_offchain_state(&mut self, value: &Json) -> Result<(), String> {
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Snapshot {
            onboarding_secrets: HashMap<String, OnboardingSecret>,
            transfer_tracking: HashMap<String, TransferTrackingEntry>,
            traffic_tracking: HashMap<String, TrafficTrackingEntry>,
            vote_outcomes: HashMap<String, VotedOutcome>,
            manual_time_offset_micros: i64,
        }
        let snap: Snapshot = serde_json::from_value(value.clone())
            .map_err(|e| format!("invalid splice-ledger-meta snapshot: {e}"))?;
        self.onboarding_secrets = snap.onboarding_secrets;
        self.transfer_tracking = snap.transfer_tracking;
        self.traffic_tracking = snap.traffic_tracking;
        self.vote_outcomes = snap.vote_outcomes;
        self.manual_time_offset_micros = snap.manual_time_offset_micros;
        if let SpliceBackend::ParticipantLedger(client) = &self.backend {
            self.now_micros = wall_clock_micros()
                .max(client.last_effective_micros())
                .saturating_add(self.manual_time_offset_micros);
        }
        Ok(())
    }

    pub fn offchain_fingerprint(&self) -> [i64; 7] {
        let mut state_tag_sum = 0i64;
        for entry in self.transfer_tracking.values() {
            state_tag_sum += match entry.state {
                TransferTrackingState::Created { .. } => 1,
                TransferTrackingState::Accepted { .. } => 2,
                TransferTrackingState::Completed { .. } => 3,
                TransferTrackingState::Failed { .. } => 4,
            };
        }
        for entry in self.traffic_tracking.values() {
            state_tag_sum += match entry.state {
                TrafficTrackingState::Created { .. } => 10,
                TrafficTrackingState::Completed { .. } => 20,
                TrafficTrackingState::Failed { .. } => 30,
            };
        }
        [
            self.manual_time_offset_micros,
            self.onboarding_secrets.len() as i64,
            self.onboarding_secrets.values().filter(|s| s.used).count() as i64,
            self.transfer_tracking.len() as i64,
            self.traffic_tracking.len() as i64,
            self.vote_outcomes.len() as i64,
            state_tag_sum,
        ]
    }

    pub fn config(&self) -> &SpliceBootstrapConfig {
        &self.config
    }

    pub fn now_micros(&self) -> i64 {
        self.now_micros
    }

    /// Advance the simulated ledger clock by `delta_micros`.
    pub fn advance_time(&mut self, delta_micros: i64) -> Result<i64, SpliceAppError> {
        if delta_micros < 0 {
            return Err(SpliceAppError::BadRequest(
                "time advance delta must be non-negative".into(),
            ));
        }
        match &self.backend {
            SpliceBackend::InProcess => {
                self.now_micros = self.now_micros.saturating_add(delta_micros);
            }
            SpliceBackend::ParticipantLedger(client) => {
                self.manual_time_offset_micros =
                    self.manual_time_offset_micros.saturating_add(delta_micros);
                self.now_micros = wall_clock_micros()
                    .max(client.last_effective_micros())
                    .saturating_add(self.manual_time_offset_micros);
            }
        }
        Ok(self.now_micros)
    }

    pub fn updates(&self) -> &[Json] {
        &self.updates
    }

    /// A cheap summary of everything a request or an automation tick can change (S-STORE-020): when it is the same before and after,
    /// the call left no trace and need not be journaled.
    pub fn state_fingerprint(&self) -> [i64; 10] {
        [
            self.now_micros,
            self.next_cid_seq as i64,
            self.next_update_seq as i64,
            self.active_contracts.len() as i64,
            self.updates.len() as i64,
            self.onboarding_secrets.len() as i64,
            self.onboarding_secrets.values().filter(|s| s.used).count() as i64,
            self.transfer_tracking.len() as i64,
            self.traffic_tracking.len() as i64,
            self.vote_outcomes.len() as i64,
        ]
    }

    pub fn active_contract_count(&self) -> usize {
        self.active_contracts.len()
    }

    pub fn find_contracts(&self, template_id: &str) -> Vec<&Contract> {
        self.active_contracts
            .values()
            .filter(|c| c.active && c.template_id == template_id)
            .collect()
    }

    /// Build a fresh [`UpdateHistory`] reflecting every committed DAR update and V12 contract salt.
    pub fn scan_history(&self) -> Result<UpdateHistory, String> {
        let mut worlds = Vec::with_capacity(self.dar_paths.len());
        for path in &self.dar_paths {
            worlds.push(World::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
        }
        let mut auth = self.authentication_data.clone();
        if let SpliceBackend::ParticipantLedger(client) = &self.backend {
            if let Some(hist_path) = client.scan_history_path() {
                let auth_path = PathBuf::from(format!("{}.auth", hist_path.display()));
                merge_scan_auth_file(&auth_path, &mut auth)?;
            }
        }
        Ok(UpdateHistory::new(self.updates.clone())
            .with_contracts(worlds, auth)?
            .with_dso_info(DsoInfoConfig {
                sv_user: self.config.sv_user.clone(),
                sv_party: Some(self.config.sv_party.clone()),
                initial_round: "0".into(),
            }))
    }

    fn ensure_cached_scan(&mut self) -> Result<&UpdateHistory, String> {
        if self.cached_scan.is_none() {
            self.cached_scan = Some(self.scan_history()?);
        }
        Ok(self.cached_scan.as_ref().expect("cached_scan initialized"))
    }

    fn scan_response(&mut self, method: &str, path: &str, body: &str) -> Response {
        if let Err(e) = self.sync_ledger() {
            return e.to_response();
        }
        match self.ensure_cached_scan() {
            Ok(history) => history.handle(method, path, body),
            Err(e) => Response {
                status: 500,
                content_type: "application/json",
                body: json!({ "error": e }).to_string(),
            },
        }
    }

    fn package_for_template(&self, template_id: &str) -> Result<String, SpliceAppError> {
        let (module, entity) = template_id.split_once(':').ok_or_else(|| {
            SpliceAppError::Internal(format!("invalid template id {template_id}"))
        })?;
        self.world
            .template_package(None, module, entity)
            .ok_or_else(|| {
                SpliceAppError::Internal(format!(
                    "template {template_id} is not loaded in DAR world"
                ))
            })
    }

    fn encoded_payload(&self, contract: &Contract) -> Result<Json, SpliceAppError> {
        let types = Types::new(&self.world);
        let ty = types
            .template(&contract.package_id, &contract.template_id)
            .map_err(SpliceAppError::Internal)?;
        types
            .encode(&ty, &contract.payload)
            .map_err(SpliceAppError::Internal)
    }

    fn contract_json(&self, contract: &Contract) -> Result<Json, SpliceAppError> {
        let payload = self.encoded_payload(contract)?;
        Ok(json!({
            "template_id": format!("{}:{}", contract.package_id, contract.template_id),
            "contract_id": contract.contract_id,
            "payload": payload,
            "signatories": contract.signatories,
            "observers": contract.observers,
        }))
    }

    fn prepare_engine<'w>(
        &'w self,
        seq: Arc<Mutex<u64>>,
        auth_out: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ) -> Result<Engine<'w>, SpliceAppError> {
        let mut engine = Engine::new(&self.world);
        engine.set_time_micros(self.now_micros);
        engine.set_contract_id_allocator(V12RuntimeAllocator {
            world: &self.world,
            created_at_micros: self.now_micros,
            seq,
            auth_out,
        });
        for contract in self.active_contracts.values() {
            if !contract.active {
                continue;
            }
            engine
                .import_contract(contract.clone())
                .map_err(|e| SpliceAppError::Internal(format!("import contract: {e}")))?;
            // Explicit disclosure makes DSO-owned reference contracts (AmuletRules, rounds, etc.)
            // visible to executing users while keeping Daml signatory/controller authorization intact.
            engine.disclose(&contract.contract_id);
        }
        Ok(engine)
    }

    fn apply_rendered_tx(
        &mut self,
        update_id: String,
        created: Vec<Contract>,
        archived: Vec<String>,
        rendered: Json,
        result_json: Json,
        seq: Arc<Mutex<u64>>,
        auth_out: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ) -> TxCommitResult {
        self.next_update_seq += 1;
        self.next_cid_seq = *seq.lock().expect("seq lock");
        if let Ok(salts) = auth_out.lock() {
            for (cid, auth) in salts.iter() {
                self.authentication_data.insert(cid.clone(), auth.clone());
            }
        }
        for cid in &archived {
            self.active_contracts.remove(cid);
        }
        for contract in &created {
            self.active_contracts
                .insert(contract.contract_id.clone(), contract.clone());
        }
        self.updates.push(rendered);
        self.cached_scan = None;
        self.now_micros += 1_000;

        TxCommitResult {
            update_id,
            created,
            result: result_json,
        }
    }

    fn run_create(
        &mut self,
        act_as: &[&str],
        template_id: &str,
        payload_json: &Json,
        workflow_id: &str,
    ) -> Result<TxCommitResult, SpliceAppError> {
        let package_id = self.package_for_template(template_id)?;
        if self.is_participant_ledger() {
            self.sync_ledger()?;
            let manual_offset = self.manual_time_offset_micros;
            let SpliceBackend::ParticipantLedger(client) = &mut self.backend else {
                unreachable!();
            };
            let outcome = client.submit_create(
                &self.world,
                act_as,
                &package_id,
                template_id,
                payload_json,
                workflow_id,
            )?;
            self.active_contracts = client.active_contracts().clone();
            self.authentication_data = client.authentication_data().clone();
            self.updates = client.updates().to_vec();
            self.cached_scan = None;
            self.now_micros = wall_clock_micros()
                .max(client.last_effective_micros())
                .saturating_add(manual_offset);
            return Ok(TxCommitResult {
                update_id: outcome.update_id,
                created: outcome.created,
                result: outcome.result,
            });
        }
        let seq = Arc::new(Mutex::new(self.next_cid_seq));
        let auth_out = Arc::new(Mutex::new(HashMap::new()));
        let (update_id, created, archived, rendered, result_json) = {
            let types = Types::new(&self.world);
            let tpl_ty = types
                .template(&package_id, template_id)
                .map_err(SpliceAppError::BadRequest)?;
            let payload = types
                .decode(&tpl_ty, payload_json)
                .map_err(|e| SpliceAppError::BadRequest(format!("{template_id}: {e}")))?;

            let mut engine = self.prepare_engine(Arc::clone(&seq), Arc::clone(&auth_out))?;
            let contract = engine
                .execute_create_in(act_as, &package_id, template_id, &payload)
                .map_err(map_exec_error)?;
            let created_id = contract.contract_id.clone();
            let result_json = json!({ "contract_id": created_id });

            let update_id = format!(
                "1220{}",
                sha256_hex(&format!("splice-update:{}", self.next_update_seq))
            );
            let meta = UpdateMeta {
                update_id: &update_id,
                migration_id: 0,
                workflow_id,
                synchronizer_id: &self.config.synchronizer_id,
                record_time_micros: self.now_micros + 500,
                effective_at_micros: self.now_micros,
            };
            let rendered = render_update(&types, &engine, &meta, engine.events())
                .map_err(SpliceAppError::Internal)?;
            (update_id, vec![contract], Vec::new(), rendered, result_json)
        };

        Ok(self.apply_rendered_tx(
            update_id,
            created,
            archived,
            rendered,
            result_json,
            seq,
            auth_out,
        ))
    }

    fn run_exercise(
        &mut self,
        act_as: &[&str],
        contract_id: &str,
        choice: &str,
        arg_json: &Json,
        workflow_id: &str,
    ) -> Result<TxCommitResult, SpliceAppError> {
        if self.is_participant_ledger() {
            self.sync_ledger()?;
            let target = self
                .active_contracts
                .get(contract_id)
                .ok_or_else(|| {
                    SpliceAppError::NotFound(format!("contract {contract_id} not found"))
                })?
                .clone();
            let manual_offset = self.manual_time_offset_micros;
            let SpliceBackend::ParticipantLedger(client) = &mut self.backend else {
                unreachable!();
            };
            let outcome = client.submit_exercise(
                &self.world,
                act_as,
                &target,
                choice,
                arg_json,
                workflow_id,
            )?;
            self.active_contracts = client.active_contracts().clone();
            self.authentication_data = client.authentication_data().clone();
            self.updates = client.updates().to_vec();
            self.cached_scan = None;
            self.now_micros = wall_clock_micros()
                .max(client.last_effective_micros())
                .saturating_add(manual_offset);
            return Ok(TxCommitResult {
                update_id: outcome.update_id,
                created: outcome.created,
                result: outcome.result,
            });
        }
        let target = self
            .active_contracts
            .get(contract_id)
            .ok_or_else(|| SpliceAppError::NotFound(format!("contract {contract_id} not found")))?
            .clone();

        let seq = Arc::new(Mutex::new(self.next_cid_seq));
        let auth_out = Arc::new(Mutex::new(HashMap::new()));
        let (update_id, created, archived, rendered, result_json) = {
            let types = Types::new(&self.world);
            let choice_types = types
                .choice(&target.package_id, &target.template_id, choice)
                .map_err(SpliceAppError::Internal)?;
            let arg = types
                .decode(&choice_types.argument, arg_json)
                .map_err(|e| SpliceAppError::BadRequest(format!("{choice}: {e}")))?;

            let mut engine = self.prepare_engine(Arc::clone(&seq), Arc::clone(&auth_out))?;
            let outcome = engine
                .execute_exercise(act_as, contract_id, choice, &arg)
                .map_err(map_exec_error)?;
            let result_json = types
                .encode(&choice_types.result, &outcome.result)
                .map_err(SpliceAppError::Internal)?;

            let update_id = format!(
                "1220{}",
                sha256_hex(&format!("splice-update:{}", self.next_update_seq))
            );
            let meta = UpdateMeta {
                update_id: &update_id,
                migration_id: 0,
                workflow_id,
                synchronizer_id: &self.config.synchronizer_id,
                record_time_micros: self.now_micros + 500,
                effective_at_micros: self.now_micros,
            };
            let rendered = render_update(&types, &engine, &meta, &outcome.events)
                .map_err(SpliceAppError::Internal)?;
            (
                update_id,
                outcome.created,
                outcome.archived,
                rendered,
                result_json,
            )
        };

        Ok(self.apply_rendered_tx(
            update_id,
            created,
            archived,
            rendered,
            result_json,
            seq,
            auth_out,
        ))
    }

    // -------------------------------------------------------------------------
    // SV Service
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Validator Service
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Wallet Service
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Automation Loop (Wallet + Validator + SV DSO)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Internal Query & Formatting Helpers
    // -------------------------------------------------------------------------
}

// =============================================================================
// Unified HTTP Handler for SV / Validator / Wallet / Automation / Scan
// =============================================================================
