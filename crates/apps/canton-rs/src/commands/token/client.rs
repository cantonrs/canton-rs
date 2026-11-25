//! Ledger JSON API v2 and DAR inspection client for `canton-rs token` (`S-DX-008`).
//!
//! Resolves target endpoints from the `S-DX-002` instance registry (or explicit `--url`) and
//! automatically signs `S-DX-007` development JWTs when the target instance uses `--dev-auth`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use serde_json::{json, Value as Json};

use crate::commands::exit_code::{exit_with_message, EXIT_PREFLIGHT};
use crate::commands::json_http::{call_with_token, error_cause};
use crate::commands::supervisor::creds::resolve_dev_auth_token;
use crate::commands::supervisor::query::resolve_endpoint;

/// Output format for `canton-rs token` commands.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Shared connection arguments (`S-DX-002` registry + `S-DX-007` dev JWT + explicit overrides).
#[derive(Args, Clone, Debug, Default)]
pub struct ConnArgs {
    /// Target `canton-rs daemon` instance name (`S-DX-002` registry).
    #[arg(long)]
    pub name: Option<String>,

    /// Explicit instance state directory (alternative to `--name`).
    #[arg(long)]
    pub state_dir: Option<PathBuf>,

    /// Participant service name inside the daemon instance.
    #[arg(long)]
    pub participant: Option<String>,

    /// Explicit JSON Ledger API v2 base URL (e.g. `http://127.0.0.1:22975`).
    #[arg(long)]
    pub url: Option<String>,

    /// Explicit Bearer JWT token (auto-signed via S-DX-007 when omitted against `--dev-auth` instances).
    #[arg(long)]
    pub token: Option<String>,

    /// Ledger API userId (`sub`) for commands and dev-JWT signing.
    #[arg(long, default_value = "participant_admin")]
    pub user: String,

    /// Optional Splice Scan base URL (e.g. `http://127.0.0.1:25012/api/scan`) for Amulet lookups.
    #[arg(long)]
    pub scan_url: Option<String>,

    /// Optional synchronizer ID override for submissions.
    #[arg(long)]
    pub synchronizer: Option<String>,

    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

/// A parsed `http://host:port[/prefix]` endpoint.
#[derive(Clone, Debug)]
pub struct HttpTarget {
    pub host: String,
    pub port: u16,
    pub prefix: String,
}

impl HttpTarget {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim().trim_end_matches('/');
        let rest = trimmed
            .strip_prefix("http://")
            .ok_or_else(|| format!("unsupported URL '{raw}': expected http://..."))?;
        let (authority, prefix) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, String::new()),
        };
        let (host, port_str) = authority
            .rsplit_once(':')
            .ok_or_else(|| format!("URL '{raw}' is missing ':port'"))?;
        let host = host.trim_matches(['[', ']']).to_string();
        if host.is_empty() {
            return Err(format!("URL '{raw}' has an empty host"));
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port in URL '{raw}'"))?;
        Ok(Self { host, port, prefix })
    }

    pub fn full_path(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}{}", self.prefix, path)
        }
    }
}

/// Disclosed contract entry for JSON API v2 `disclosedContracts`.
#[derive(Clone, Debug)]
pub struct DisclosedContract {
    pub contract_id: String,
    pub template_id: String,
    pub created_event_blob: String,
    pub synchronizer_id: String,
}

impl DisclosedContract {
    pub fn to_json(&self) -> Json {
        json!({
            "contractId": self.contract_id,
            "templateId": self.template_id,
            "createdEventBlob": self.created_event_blob,
            "synchronizerId": self.synchronizer_id,
        })
    }
}

/// Active contract record returned by `/v2/state/active-contracts`.
#[derive(Clone, Debug)]
pub struct ActiveContract {
    pub contract_id: String,
    pub template_id: String,
    pub create_argument: Json,
    pub created_event_blob: String,
    pub synchronizer_id: String,
    pub interface_views: Vec<Json>,
}

/// JSON API v2 + Scan HTTP client for token commands.
#[derive(Clone, Debug)]
pub struct TokenClient {
    pub ledger: HttpTarget,
    pub scan: Option<HttpTarget>,
    pub token: Option<String>,
    dev_admin_token: Option<String>,
    granted_parties: RefCell<BTreeSet<String>>,
    pub user_id: String,
    pub synchronizer: Option<String>,
}

impl TokenClient {
    /// Connects to a target daemon instance or explicit URL, signing an S-DX-007 dev JWT if configured.
    pub fn connect(conn: &ConnArgs) -> Result<Self, String> {
        let ep = resolve_endpoint(
            conn.url.as_deref(),
            conn.name.as_deref(),
            conn.state_dir.as_deref(),
            conn.participant.as_deref(),
        )?;
        let ledger =
            HttpTarget::parse(&ep.base_url).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;

        let (token, dev_admin_token) = if let Some(ref explicit) = conn.token {
            (Some(explicit.clone()), None)
        } else if conn.url.is_none() {
            match resolve_dev_auth_token(
                conn.name.as_deref(),
                conn.state_dir.as_deref(),
                conn.participant.as_deref(),
                &conn.user,
                Some(&ep.base_url),
            )
            .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?
            {
                Some(t) => (Some(t.user_token), Some(t.admin_token)),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        let scan = match conn.scan_url.as_deref() {
            Some(raw) => {
                Some(HttpTarget::parse(raw).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?)
            }
            None => None,
        };

        Ok(Self {
            ledger,
            scan,
            token,
            dev_admin_token,
            granted_parties: RefCell::new(BTreeSet::new()),
            user_id: conn.user.clone(),
            synchronizer: conn.synchronizer.clone(),
        })
    }

    /// Returns true when the caller supplied an explicit Bearer `--token` (rather than `--dev-auth`).
    pub fn has_explicit_token(&self) -> bool {
        self.token.is_some() && self.dev_admin_token.is_none()
    }

    /// Under `--dev-auth` only, grants `CanActAs` and `CanReadAs` on `self.user_id` for listed parties.
    pub fn ensure_dev_party_rights(&self, parties: &[String]) -> Result<(), String> {
        let Some(ref admin_token) = self.dev_admin_token else {
            return Ok(());
        };
        let missing: Vec<String> = {
            let granted = self.granted_parties.borrow();
            let mut uniq = BTreeSet::new();
            for p in parties {
                let trimmed = p.trim();
                if !trimmed.is_empty() && !granted.contains(trimmed) {
                    uniq.insert(trimmed.to_string());
                }
            }
            uniq.into_iter().collect()
        };
        if missing.is_empty() {
            return Ok(());
        }

        let rights: Vec<Json> = missing
            .iter()
            .flat_map(|p| {
                [
                    json!({ "kind": { "CanActAs": { "value": { "party": p } } } }),
                    json!({ "kind": { "CanReadAs": { "value": { "party": p } } } }),
                ]
            })
            .collect();

        let encoded_user = percent_encode_segment(&self.user_id);
        let grant_path = self
            .ledger
            .full_path(&format!("/v2/users/{encoded_user}/rights"));
        let grant_bytes = serde_json::to_vec(&json!({
            "userId": self.user_id,
            "rights": rights,
        }))
        .map_err(|e| e.to_string())?;
        let (st, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "POST",
            &grant_path,
            Some((&grant_bytes, "application/json")),
            Some(admin_token.as_str()),
        )?;

        if st == 404 {
            let create_path = self.ledger.full_path("/v2/users");
            let create_bytes = serde_json::to_vec(&json!({
                "user": {
                    "id": self.user_id,
                    "primaryParty": missing[0],
                },
                "rights": rights,
            }))
            .map_err(|e| e.to_string())?;
            let (cst, cbody) = call_with_token(
                &self.ledger.host,
                self.ledger.port,
                "POST",
                &create_path,
                Some((&create_bytes, "application/json")),
                Some(admin_token.as_str()),
            )?;
            if cst >= 300 {
                return Err(format!(
                    "POST {create_path} failed with HTTP {cst}: {}",
                    error_cause(&cbody)
                ));
            }
        } else if st >= 300 {
            return Err(format!(
                "POST {grant_path} failed with HTTP {st}: {}",
                error_cause(&body)
            ));
        }

        let mut granted = self.granted_parties.borrow_mut();
        for p in missing {
            granted.insert(p);
        }
        Ok(())
    }

    /// Returns parties this client may read (user rights under explicit `--token`, else local parties).
    pub fn readable_parties(&self) -> Result<Vec<String>, String> {
        if self.dev_admin_token.is_some() || self.token.is_none() {
            return self.list_local_parties();
        }
        let encoded_user = percent_encode_segment(&self.user_id);
        let path = self
            .ledger
            .full_path(&format!("/v2/users/{encoded_user}/rights"));
        let (st, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "GET",
            &path,
            None,
            self.token.as_deref(),
        )?;
        if (200..300).contains(&st) {
            if let Some(arr) = body["rights"].as_array() {
                if arr
                    .iter()
                    .any(|r| !r["kind"]["CanReadAsAnyParty"].is_null())
                {
                    return self.list_local_parties();
                }
                let mut parties = BTreeSet::new();
                for r in arr {
                    let kind = &r["kind"];
                    if let Some(p) = kind["CanReadAs"]["value"]["party"].as_str() {
                        parties.insert(p.to_string());
                    }
                    if let Some(p) = kind["CanActAs"]["value"]["party"].as_str() {
                        parties.insert(p.to_string());
                    }
                }
                if !parties.is_empty() {
                    return Ok(parties.into_iter().collect());
                }
            }
        }
        self.list_local_parties()
    }

    pub fn get_json(&self, path: &str) -> Result<Json, String> {
        let full = self.ledger.full_path(path);
        let (status, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "GET",
            &full,
            None,
            self.token.as_deref(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "GET {full} failed with HTTP {status}: {}",
                error_cause(&body)
            ));
        }
        Ok(body)
    }

    pub fn post_json(&self, path: &str, payload: &Json) -> Result<Json, String> {
        let full = self.ledger.full_path(path);
        let bytes = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
        let (status, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "POST",
            &full,
            Some((&bytes, "application/json")),
            self.token.as_deref(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "POST {full} failed with HTTP {status}: {}",
                error_cause(&body)
            ));
        }
        Ok(body)
    }

    pub fn scan_call(
        &self,
        method: &str,
        path: &str,
        payload: Option<&Json>,
    ) -> Result<Json, String> {
        let scan = self
            .scan
            .as_ref()
            .ok_or_else(|| "Scan API query requested without --scan-url".to_string())?;
        let full = scan.full_path(path);
        let encoded = match payload {
            Some(v) => Some(serde_json::to_vec(v).map_err(|e| e.to_string())?),
            None => None,
        };
        let body_arg = encoded.as_deref().map(|b| (b, "application/json"));
        let (status, body) = call_with_token(&scan.host, scan.port, method, &full, body_arg, None)?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "Scan {method} {full} failed with HTTP {status}: {}",
                error_cause(&body)
            ));
        }
        Ok(body)
    }

    /// Uploads a `.dar` archive via `POST /v2/packages`.
    pub fn upload_dar(&self, dar_path: &Path) -> Result<(), String> {
        let bytes = fs::read(dar_path)
            .map_err(|e| format!("cannot read DAR '{}': {e}", dar_path.display()))?;
        let full = self.ledger.full_path("/v2/packages");
        let (status, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "POST",
            &full,
            Some((&bytes, "application/octet-stream")),
            self.token.as_deref(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "DAR upload failed (HTTP {status}): {}",
                error_cause(&body)
            ));
        }
        Ok(())
    }

    /// Lists loaded package IDs via `GET /v2/packages`.
    pub fn list_packages(&self) -> Result<Vec<String>, String> {
        let res = self.get_json("/v2/packages")?;
        let ids = res["packageIds"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(ids)
    }

    /// Lists vetted package IDs via `POST /v2/package-vetting/list`, falling back to loaded packages if unavailable.
    pub fn list_vetted_packages(&self, package_ids: &[String]) -> Result<Vec<String>, String> {
        let full = self.ledger.full_path("/v2/package-vetting/list");
        let payload = json!({
            "packageMetadataFilter": {
                "packageIds": package_ids,
                "packageNamePrefixes": []
            },
            "topologyStateFilter": {
                "participantIds": [],
                "synchronizerIds": []
            }
        });
        let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let (status, body) = call_with_token(
            &self.ledger.host,
            self.ledger.port,
            "POST",
            &full,
            Some((&bytes, "application/json")),
            self.token.as_deref(),
        )?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "POST {full} failed with HTTP {status}: {}",
                error_cause(&body)
            ));
        }
        let mut out = Vec::new();
        if let Some(states) = body["vettingStates"].as_array() {
            for st in states {
                if let Some(pkgs) = st["packages"].as_array() {
                    for p in pkgs {
                        if let Some(id) = p["packageId"].as_str() {
                            if !out.iter().any(|existing| existing == id) {
                                out.push(id.to_string());
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Resolves a full party ID (`Hint::1220...`) or unique hint prefix via `GET /v2/parties`.
    pub fn resolve_party(&self, raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty party identifier".to_string());
        }
        if trimmed.contains("::") {
            return Ok(trimmed.to_string());
        }
        let parties = self.list_parties()?;
        let prefix = format!("{trimmed}::");
        let matches: Vec<String> = parties
            .into_iter()
            .filter(|p| p == trimmed || p.starts_with(&prefix))
            .collect();
        match matches.as_slice() {
            [] => Err(format!("party '{trimmed}' not found on ledger")),
            [one] => Ok(one.clone()),
            many => Err(format!(
                "ambiguous party hint '{trimmed}', matches: {}",
                many.join(", ")
            )),
        }
    }

    /// Lists local parties hosted on this participant via `GET /v2/parties` (`isLocal == true`).
    pub fn list_local_parties(&self) -> Result<Vec<String>, String> {
        let res = self.get_json("/v2/parties")?;
        let mut out = Vec::new();
        if let Some(details) = res["partyDetails"].as_array() {
            for item in details {
                if item["isLocal"].as_bool().unwrap_or(true) {
                    if let Some(p) = item["party"].as_str() {
                        out.push(p.to_string());
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Lists all parties known to the participant via `GET /v2/parties`.
    pub fn list_parties(&self) -> Result<Vec<String>, String> {
        let res = self.get_json("/v2/parties")?;
        let mut out = Vec::new();
        if let Some(details) = res["partyDetails"].as_array() {
            for item in details {
                if let Some(p) = item["party"].as_str() {
                    out.push(p.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Fetches the current ledger end offset via `GET /v2/state/ledger-end`.
    pub fn ledger_end(&self) -> Result<u64, String> {
        let res = self.get_json("/v2/state/ledger-end")?;
        res["offset"]
            .as_u64()
            .or_else(|| res["offset"].as_str().and_then(|s| s.parse::<u64>().ok()))
            .ok_or_else(|| format!("missing offset in /v2/state/ledger-end response: {res}"))
    }

    /// Queries `/v2/state/active-contracts` using a `TemplateFilter` for `parties`.
    pub fn active_template_contracts(
        &self,
        parties: &[String],
        template_id: &str,
        include_blob: bool,
    ) -> Result<Vec<ActiveContract>, String> {
        self.ensure_dev_party_rights(parties)?;
        let mut filters_by_party = serde_json::Map::new();
        for p in parties {
            filters_by_party.insert(
                p.clone(),
                json!({
                    "cumulative": [{
                        "identifierFilter": {
                            "TemplateFilter": {
                                "value": {
                                    "templateId": template_id,
                                    "includeCreatedEventBlob": include_blob
                                }
                            }
                        }
                    }]
                }),
            );
        }
        self.query_acs(filters_by_party)
    }

    /// Queries `/v2/state/active-contracts` using an `InterfaceFilter` (`includeInterfaceView: true`).
    pub fn active_interface_contracts(
        &self,
        parties: &[String],
        interface_id: &str,
        include_blob: bool,
    ) -> Result<Vec<ActiveContract>, String> {
        self.ensure_dev_party_rights(parties)?;
        let mut filters_by_party = serde_json::Map::new();
        for p in parties {
            filters_by_party.insert(
                p.clone(),
                json!({
                    "cumulative": [{
                        "identifierFilter": {
                            "InterfaceFilter": {
                                "value": {
                                    "interfaceId": interface_id,
                                    "includeInterfaceView": true,
                                    "includeCreatedEventBlob": include_blob
                                }
                            }
                        }
                    }]
                }),
            );
        }
        self.query_acs(filters_by_party)
    }

    fn query_acs(
        &self,
        filters_by_party: serde_json::Map<String, Json>,
    ) -> Result<Vec<ActiveContract>, String> {
        if filters_by_party.is_empty() {
            return Ok(Vec::new());
        }
        let end = self.ledger_end()?;
        let body = self.post_json(
            "/v2/state/active-contracts",
            &json!({
                "eventFormat": {
                    "filtersByParty": filters_by_party,
                    "verbose": false
                },
                "activeAtOffset": end
            }),
        )?;
        let rows = body.as_array().ok_or_else(|| {
            format!("expected JSON array from /v2/state/active-contracts: {body}")
        })?;
        let mut seen = BTreeMap::new();
        for row in rows {
            let entry = &row["contractEntry"]["JsActiveContract"];
            if !entry.is_object() {
                continue;
            }
            let ce = &entry["createdEvent"];
            let Some(cid) = ce["contractId"].as_str() else {
                continue;
            };
            let Some(tid) = ce["templateId"].as_str() else {
                continue;
            };
            let sync = entry["synchronizerId"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let blob = ce["createdEventBlob"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let views = ce["interfaceViews"].as_array().cloned().unwrap_or_default();
            seen.entry(cid.to_string())
                .or_insert_with(|| ActiveContract {
                    contract_id: cid.to_string(),
                    template_id: tid.to_string(),
                    create_argument: ce["createArgument"].clone(),
                    created_event_blob: blob,
                    synchronizer_id: sync,
                    interface_views: views,
                });
        }
        Ok(seen.into_values().collect())
    }

    /// Queries `/v2/updates` in `[begin_exclusive, end_inclusive]` with interface views enabled.
    pub fn query_updates(
        &self,
        begin_exclusive: u64,
        end_inclusive: u64,
        parties: &[String],
        interface_filters: &[&str],
    ) -> Result<Vec<Json>, String> {
        self.ensure_dev_party_rights(parties)?;
        let cumulative: Vec<Json> = if interface_filters.is_empty() {
            vec![json!({
                "identifierFilter": {
                    "WildcardFilter": { "value": { "includeCreatedEventBlob": false } }
                }
            })]
        } else {
            interface_filters
                .iter()
                .map(|id| {
                    json!({
                        "identifierFilter": {
                            "InterfaceFilter": {
                                "value": {
                                    "interfaceId": id,
                                    "includeInterfaceView": true,
                                    "includeCreatedEventBlob": false
                                }
                            }
                        }
                    })
                })
                .collect()
        };
        let mut filters_by_party = serde_json::Map::new();
        for p in parties {
            filters_by_party.insert(p.clone(), json!({ "cumulative": cumulative }));
        }
        let body = self.post_json(
            "/v2/updates",
            &json!({
                "beginExclusive": begin_exclusive,
                "endInclusive": end_inclusive,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": {
                            "filtersByParty": filters_by_party,
                            "verbose": false
                        },
                        "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                    }
                }
            }),
        )?;
        Ok(body.as_array().cloned().unwrap_or_default())
    }

    /// Submits a synchronous command batch via `POST /v2/commands/submit-and-wait-for-transaction`.
    pub fn submit_tx(
        &self,
        command_id: &str,
        act_as: &[String],
        read_as: &[String],
        commands: Vec<Json>,
        disclosed: &[DisclosedContract],
    ) -> Result<Json, String> {
        let mut required_parties = Vec::with_capacity(act_as.len() + read_as.len());
        required_parties.extend(act_as.iter().cloned());
        required_parties.extend(read_as.iter().cloned());
        self.ensure_dev_party_rights(&required_parties)?;
        let mut filters_by_party = serde_json::Map::new();
        for p in act_as {
            filters_by_party.insert(
                p.clone(),
                json!({
                    "cumulative": [{
                        "identifierFilter": {
                            "WildcardFilter": { "value": { "includeCreatedEventBlob": false } }
                        }
                    }]
                }),
            );
        }
        let mut cmds_obj = json!({
            "commands": commands,
            "commandId": command_id,
            "actAs": act_as,
            "readAs": read_as,
            "userId": self.user_id,
        });
        if let Some(sync) = &self.synchronizer {
            cmds_obj["synchronizerId"] = Json::String(sync.clone());
        }
        if !disclosed.is_empty() {
            cmds_obj["disclosedContracts"] = Json::Array(
                disclosed
                    .iter()
                    .filter(|d| !d.created_event_blob.is_empty())
                    .map(DisclosedContract::to_json)
                    .collect(),
            );
        }
        let res = self.post_json(
            "/v2/commands/submit-and-wait-for-transaction",
            &json!({
                "commands": cmds_obj,
                "transactionFormat": {
                    "eventFormat": {
                        "filtersByParty": filters_by_party,
                        "verbose": false
                    },
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }),
        )?;
        Ok(res["transaction"].clone())
    }
}

/// Extracts `package_name -> hex package_id` from a DAR archive.
pub fn package_map_from_dar(dar_path: &Path) -> Result<BTreeMap<String, String>, String> {
    let loaded = lf_archive::load_dar_file_allow_dev(dar_path)
        .map_err(|e| format!("failed to load DAR '{}': {e}", dar_path.display()))?;
    let mut map = BTreeMap::new();
    for dalf in &loaded.archive.dalfs {
        if let Some(ref name) = dalf.package_name {
            map.entry(name.clone())
                .or_insert_with(|| dalf.package_id.clone());
        }
    }
    Ok(map)
}

/// Generates a unique `commandId` prefixed by `tag`.
pub fn unique_command_id(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("canton-rs-token-{tag}-{nanos}")
}

/// Formats UTC `SystemTime::now() + offset_secs` as RFC3339 `YYYY-MM-DDTHH:MM:SSZ`.
pub fn rfc3339_offset(offset_secs: i64) -> String {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0i64, |d| d.as_secs() as i64);
    let secs = now_secs.saturating_add(offset_secs);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts days since 1970-01-01 to `(year, month, day)` in proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    (year, m as u32, d as u32)
}

fn percent_encode_segment(raw: &str) -> String {
    raw.bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect()
}
