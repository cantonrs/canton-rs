//! Declarative Enterprise Topology Scenario & Load Runner (`canton-rs daemon scenario <list|run>`
//! and `daemon top` `[t]` interactive lab modal).
//!
//! Executes live Canton 3.7.2 Ledger JSON API v2 operations (`/v2/parties`,
//! `/v2/commands/submit-and-wait`, `/v2/state/active-contracts`, `/readyz`) against supervised
//! slots to verify end-to-end quorum ordering, sub-transaction privacy (`0` contracts visible on
//! non-informee witness nodes), and burst transaction throughput while illuminating 4-Hop
//! `Protocol X-Ray` traces.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use lf_archive::{ModuleSurface, SurfaceType, TemplateSurface};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use yaml_rust2::Yaml;

use super::creds::{
    ensure_dev_admin_rights, jwt_subject_unverified, resolve_dev_auth_token_for_dir,
    resolve_explicit_token, ExplicitTokenArgs, CLI_AUTO_DEV_JWT_TTL_SECS,
};
use super::ipc::{
    call_unary, call_unary_typed, resolve_client_state_dir, IpcCallError, IpcRequest, IpcResponse,
};
use super::probe::{http_request, http_request_bearer, http_request_bearer_bytes};
use super::registry::resolve_target_state_dir;
use super::{now_unix_ms, ClusterSnapshot, NodeLifecycleState, NodeRole, NodeSnapshot};

/// Declarative scenario definition parsed from `canton-daemon.yaml` or synthesized automatically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioSpec {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub builtin: bool,
    pub steps: Vec<ScenarioStep>,
}

/// Atomic scenario step executed sequentially against a live supervised stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ScenarioStep {
    /// Probes `/readyz` across online nodes and triggers cluster ping if available.
    HealthPing,
    /// Allocates (or reuses) a party with `party_hint` on `node` via `POST /v2/parties`.
    AllocateParty { node: String, party_hint: String },
    /// Submits a `CreateCommand` via `POST /v2/commands/submit-and-wait` on `node`.
    SubmitCreate { node: String, party_hint: String },
    /// Proves Canton sub-transaction privacy: asserts `informee_node` sees `>= 1` active contract
    /// for `informee_party_hint` while `witness_node` sees `0` contracts for `witness_party_hint`.
    AssertAcsVisibility {
        informee_node: String,
        informee_party_hint: String,
        witness_node: String,
        witness_party_hint: String,
    },
    /// Fires `count` sequential `submit-and-wait` creates on `node` and reports throughput & p99.
    BurstCreates {
        node: String,
        party_hint: String,
        count: usize,
    },
}

/// Outcome of a single step inside [`ScenarioRunReport`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioStepResult {
    pub index: usize,
    pub action: String,
    pub ok: bool,
    pub elapsed_ms: f64,
    pub summary: String,
}

/// Complete execution report returned by `execute_scenario`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioRunReport {
    pub scenario: String,
    pub description: String,
    pub ok: bool,
    pub total_elapsed_ms: f64,
    pub steps: Vec<ScenarioStepResult>,
}

/// CLI arguments for `canton-rs daemon scenario <list|run>`.
#[derive(Args, Debug, Clone)]
pub struct ScenarioCliArgs {
    #[command(subcommand)]
    pub action: ScenarioCliAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ScenarioCliAction {
    /// List declarative and built-in scenarios available for the running stack (or `-f` manifest).
    List(ScenarioListArgs),
    /// Execute a named scenario against the running stack and report step-by-step verification.
    Run(ScenarioRunArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ScenarioListArgs {
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    /// Registered instance name (`<root>/instances/<name>`).
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ScenarioRunArgs {
    /// Scenario name (see `canton-rs daemon scenario list`).
    #[arg(value_name = "SCENARIO")]
    pub name: String,
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    /// Registered instance name (`<root>/instances/<name>`).
    #[arg(long = "name", visible_alias = "instance")]
    pub instance_name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Environment variable supplying a bearer token for participant Ledger JSON API calls.
    #[arg(long)]
    pub token_env: Option<String>,
    /// File supplying a bearer token for participant Ledger JSON API calls.
    #[arg(long, conflicts_with = "token_env")]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

/// Per-node bearer auth for scenario execution (`M-002`).
#[derive(Clone, Debug)]
pub struct ScenarioNodeAuth {
    pub token: String,
    /// `true` iff minted from `<state_dir>/dev-jwt.key`, permitting automatic dev-admin party grants.
    pub is_dev_auto_signed: bool,
}

/// Parses optional top-level `scenarios:` mapping from `canton-daemon.yaml`.
pub fn parse_scenarios_yaml(doc: &Yaml) -> Result<Vec<ScenarioSpec>, String> {
    let raw = &doc["scenarios"];
    if raw.is_badvalue() || raw.is_null() {
        return Ok(Vec::new());
    }
    let Some(map) = raw.as_hash() else {
        return Err("'scenarios' must be a mapping of <scenario_name>: { ... }".to_string());
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let name = k
            .as_str()
            .ok_or_else(|| "scenario key in 'scenarios' must be a string".to_string())?
            .trim()
            .to_string();
        if name.is_empty() {
            return Err("scenario name cannot be empty".to_string());
        }
        let description = v["description"]
            .as_str()
            .unwrap_or("Declarative topology verification scenario")
            .to_string();
        let Some(steps_arr) = v["steps"].as_vec() else {
            return Err(format!("scenario '{name}' must define a 'steps:' list"));
        };
        if steps_arr.is_empty() {
            return Err(format!("scenario '{name}' 'steps:' list cannot be empty"));
        }
        let mut steps = Vec::with_capacity(steps_arr.len());
        for (idx, item) in steps_arr.iter().enumerate() {
            let action = item["action"]
                .as_str()
                .ok_or_else(|| format!("scenario '{name}' step #{idx} missing 'action'"))?;
            let step = match action.trim() {
                "health_ping" => ScenarioStep::HealthPing,
                "allocate_party" => ScenarioStep::AllocateParty {
                    node: req_field(item, &name, idx, "node")?,
                    party_hint: req_field(item, &name, idx, "party_hint")?,
                },
                "submit_create" => ScenarioStep::SubmitCreate {
                    node: req_field(item, &name, idx, "node")?,
                    party_hint: req_field(item, &name, idx, "party_hint")?,
                },
                "assert_acs_visibility" => ScenarioStep::AssertAcsVisibility {
                    informee_node: req_field(item, &name, idx, "informee_node")?,
                    informee_party_hint: req_field(item, &name, idx, "informee_party_hint")?,
                    witness_node: req_field(item, &name, idx, "witness_node")?,
                    witness_party_hint: req_field(item, &name, idx, "witness_party_hint")?,
                },
                "burst_creates" => {
                    let count = item["count"]
                        .as_i64()
                        .and_then(|n| usize::try_from(n).ok())
                        .unwrap_or(5)
                        .max(1);
                    ScenarioStep::BurstCreates {
                        node: req_field(item, &name, idx, "node")?,
                        party_hint: req_field(item, &name, idx, "party_hint")?,
                        count,
                    }
                }
                other => {
                    return Err(format!(
                        "scenario '{name}' step #{idx} unsupported action '{other}'"
                    ))
                }
            };
            steps.push(step);
        }
        out.push(ScenarioSpec {
            name,
            description,
            builtin: false,
            steps,
        });
    }
    Ok(out)
}

fn req_field(item: &Yaml, scenario: &str, idx: usize, key: &str) -> Result<String, String> {
    item[key]
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("scenario '{scenario}' step #{idx} requires '{key}'"))
}

/// Combines manifest-defined scenarios with auto-synthesized built-in scenarios tailored to the
/// currently discovered participant slots in `nodes`.
pub fn available_scenarios_for_nodes(
    custom: &[ScenarioSpec],
    nodes: &[NodeSnapshot],
) -> Vec<ScenarioSpec> {
    let mut out = custom.to_vec();
    let mut existing_names: std::collections::BTreeSet<String> =
        out.iter().map(|s| s.name.clone()).collect();

    if existing_names.insert("ping-mesh".to_string()) {
        out.push(ScenarioSpec {
            name: "ping-mesh".to_string(),
            description: "Probe /readyz across all online nodes and trigger synchronizer ping"
                .to_string(),
            builtin: true,
            steps: vec![ScenarioStep::HealthPing],
        });
    }

    let participants: Vec<&NodeSnapshot> = nodes
        .iter()
        .filter(|n| {
            n.role == NodeRole::Participant && n.ports.http_json.or(n.ports.public).is_some()
        })
        .collect();

    if let Some(p1) = participants.first() {
        if existing_names.insert("smoke-create".to_string()) {
            out.push(ScenarioSpec {
                name: "smoke-create".to_string(),
                description: format!(
                    "Allocate SmokeAlice on '{}' and commit 1 Daml contract (emits X-Ray trace)",
                    p1.name
                ),
                builtin: true,
                steps: vec![
                    ScenarioStep::AllocateParty {
                        node: p1.name.clone(),
                        party_hint: "SmokeAlice".to_string(),
                    },
                    ScenarioStep::SubmitCreate {
                        node: p1.name.clone(),
                        party_hint: "SmokeAlice".to_string(),
                    },
                ],
            });
        }

        if existing_names.insert("steady-burst-5".to_string()) {
            out.push(ScenarioSpec {
                name: "steady-burst-5".to_string(),
                description: format!(
                    "Submit 5 sequential commits on '{}' and measure throughput & p99 latency",
                    p1.name
                ),
                builtin: true,
                steps: vec![
                    ScenarioStep::AllocateParty {
                        node: p1.name.clone(),
                        party_hint: "BurstTrader".to_string(),
                    },
                    ScenarioStep::BurstCreates {
                        node: p1.name.clone(),
                        party_hint: "BurstTrader".to_string(),
                        count: 5,
                    },
                ],
            });
        }
    }

    if participants.len() >= 2 {
        let p_inf = participants[0];
        let p_wit = participants.last().copied().unwrap_or(p_inf);
        if existing_names.insert("privacy-isolation-audit".to_string()) {
            out.push(ScenarioSpec {
                name: "privacy-isolation-audit".to_string(),
                description: format!(
                    "Commit on '{}' and prove non-informee '{}' observes 0 contract bytes",
                    p_inf.name, p_wit.name
                ),
                builtin: true,
                steps: vec![
                    ScenarioStep::AllocateParty {
                        node: p_inf.name.clone(),
                        party_hint: "PrivacyInformee".to_string(),
                    },
                    ScenarioStep::AllocateParty {
                        node: p_wit.name.clone(),
                        party_hint: "PrivacyWitness".to_string(),
                    },
                    ScenarioStep::SubmitCreate {
                        node: p_inf.name.clone(),
                        party_hint: "PrivacyInformee".to_string(),
                    },
                    ScenarioStep::AssertAcsVisibility {
                        informee_node: p_inf.name.clone(),
                        informee_party_hint: "PrivacyInformee".to_string(),
                        witness_node: p_wit.name.clone(),
                        witness_party_hint: "PrivacyWitness".to_string(),
                    },
                ],
            });
        }
    }

    out
}

/// Executes a `ScenarioSpec` end-to-end against a running supervisor stack, auto-signing
/// loopback `--dev-auth` tokens when `state_dir` contains `dev-jwt.key`.
pub fn execute_scenario(
    state_dir: Option<&Path>,
    snapshot: &ClusterSnapshot,
    spec: &ScenarioSpec,
) -> ScenarioRunReport {
    let auth_map = state_dir
        .map(|sd| resolve_dev_auth_map(sd, snapshot))
        .unwrap_or_default();
    execute_scenario_with_auth(state_dir, snapshot, spec, &auth_map)
}

/// Runs `spec` against live HTTP JSON APIs in `snapshot` with per-node auth provenance (`M-002`).
pub fn execute_scenario_with_auth(
    state_dir: Option<&Path>,
    snapshot: &ClusterSnapshot,
    spec: &ScenarioSpec,
    auth_map: &BTreeMap<String, ScenarioNodeAuth>,
) -> ScenarioRunReport {
    let overall_start = Instant::now();
    let mut step_results = Vec::with_capacity(spec.steps.len());
    let mut party_cache: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut all_ok = true;
    let auth_of = |node: &str| auth_map.get(node);

    for (idx, step) in spec.steps.iter().enumerate() {
        let t0 = Instant::now();
        let (action_name, outcome) = match step {
            ScenarioStep::HealthPing => ("health_ping", run_step_health_ping(state_dir, snapshot)),
            ScenarioStep::AllocateParty { node, party_hint } => (
                "allocate_party",
                run_step_allocate_party(
                    snapshot,
                    node,
                    party_hint,
                    auth_of(node),
                    &mut party_cache,
                ),
            ),
            ScenarioStep::SubmitCreate { node, party_hint } => (
                "submit_create",
                run_step_submit_create(snapshot, node, party_hint, auth_of(node), &mut party_cache),
            ),
            ScenarioStep::AssertAcsVisibility {
                informee_node,
                informee_party_hint,
                witness_node,
                witness_party_hint,
            } => (
                "assert_acs_visibility",
                run_step_assert_privacy(
                    snapshot,
                    &PrivacyCheckSpec {
                        informee: PrivacyParticipant {
                            node: informee_node,
                            party_hint: informee_party_hint,
                            auth: auth_of(informee_node),
                        },
                        witness: PrivacyParticipant {
                            node: witness_node,
                            party_hint: witness_party_hint,
                            auth: auth_of(witness_node),
                        },
                    },
                    &mut party_cache,
                ),
            ),
            ScenarioStep::BurstCreates {
                node,
                party_hint,
                count,
            } => (
                "burst_creates",
                run_step_burst_creates(
                    snapshot,
                    node,
                    party_hint,
                    *count,
                    auth_of(node),
                    &mut party_cache,
                ),
            ),
        };
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        match outcome {
            Ok(summary) => step_results.push(ScenarioStepResult {
                index: idx + 1,
                action: action_name.to_string(),
                ok: true,
                elapsed_ms,
                summary,
            }),
            Err(err) => {
                all_ok = false;
                step_results.push(ScenarioStepResult {
                    index: idx + 1,
                    action: action_name.to_string(),
                    ok: false,
                    elapsed_ms,
                    summary: err,
                });
                break;
            }
        }
    }

    ScenarioRunReport {
        scenario: spec.name.clone(),
        description: spec.description.clone(),
        ok: all_ok,
        total_elapsed_ms: overall_start.elapsed().as_secs_f64() * 1000.0,
        steps: step_results,
    }
}

fn resolve_dev_auth_map(
    state_dir: &Path,
    snapshot: &ClusterSnapshot,
) -> BTreeMap<String, ScenarioNodeAuth> {
    let mut map = BTreeMap::new();
    for node in &snapshot.nodes {
        if node.role != NodeRole::Participant {
            continue;
        }
        let Some(port) = node.ports.http_json.or(node.ports.public) else {
            continue;
        };
        let live_url = format!("http://127.0.0.1:{port}");
        if let Ok(Some(dev_tokens)) = resolve_dev_auth_token_for_dir(
            state_dir,
            Some(&node.name),
            "participant_admin",
            Some(&live_url),
            CLI_AUTO_DEV_JWT_TTL_SECS,
        ) {
            map.insert(
                node.name.clone(),
                ScenarioNodeAuth {
                    token: dev_tokens.admin_token,
                    is_dev_auto_signed: true,
                },
            );
        }
    }
    map
}

fn participant_port(snapshot: &ClusterSnapshot, node: &str) -> Result<u16, String> {
    let found = snapshot
        .nodes
        .iter()
        .find(|n| n.name == node)
        .ok_or_else(|| format!("node '{node}' not found in running cluster"))?;
    if found.state != NodeLifecycleState::Online {
        return Err(format!(
            "node '{node}' is currently {} (start it first)",
            found.state.display_label()
        ));
    }
    found
        .ports
        .http_json
        .or(found.ports.public)
        .ok_or_else(|| format!("participant '{node}' has no HTTP JSON API port"))
}

fn run_step_health_ping(
    state_dir: Option<&Path>,
    snapshot: &ClusterSnapshot,
) -> Result<String, String> {
    let online = snapshot
        .nodes
        .iter()
        .filter(|n| n.state == NodeLifecycleState::Online)
        .count();
    if online == 0 {
        return Err("0 nodes are Online".to_string());
    }
    let mut ready_checked = 0usize;
    for n in &snapshot.nodes {
        if n.state != NodeLifecycleState::Online {
            continue;
        }
        if let Some(p) = n.ports.http_json.or(n.ports.admin).or(n.ports.metrics) {
            let url = format!("http://127.0.0.1:{p}/readyz");
            if let Ok((code, _)) =
                http_request(&url, "GET", None, None, Duration::from_millis(1200))
            {
                if (200..300).contains(&code) {
                    ready_checked += 1;
                }
            }
        }
    }
    if let Some(sd) = state_dir {
        if let Ok(IpcResponse::Ping {
            ok: true,
            rtt_ms,
            detail,
        }) = call_unary(sd, &IpcRequest::TriggerPing)
        {
            return Ok(format!(
                "{online}/{} nodes Online ({ready_checked} /readyz 200), ping {detail} ({rtt_ms:.1}ms)",
                snapshot.nodes.len()
            ));
        }
    }
    Ok(format!(
        "{online}/{} nodes Online ({ready_checked} HTTP /readyz probes passed)",
        snapshot.nodes.len()
    ))
}

fn grant_dev_party_rights_if_needed(
    port: u16,
    auth: Option<&ScenarioNodeAuth>,
    party: Option<&str>,
    read_any_party: bool,
) -> Result<(), String> {
    let Some(a) = auth.filter(|a| a.is_dev_auto_signed) else {
        return Ok(());
    };
    let base_url = format!("http://127.0.0.1:{port}");
    ensure_dev_admin_rights(&base_url, &a.token, party, read_any_party)
}

fn run_step_allocate_party(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    auth: Option<&ScenarioNodeAuth>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    let token = auth.map(|a| a.token.as_str());
    if let Some(existing) = find_existing_party(port, party_hint, token)? {
        grant_dev_party_rights_if_needed(port, auth, Some(&existing), false)?;
        party_cache.insert((node.to_string(), party_hint.to_string()), existing.clone());
        return Ok(format!("{node}: reused party {existing}"));
    }

    let url = format!("http://127.0.0.1:{port}/v2/parties");
    let payload = json!({
        "partyIdHint": party_hint,
        "identityProviderId": ""
    });
    let body_str = payload.to_string();
    let (status, resp_body) = http_request_bearer(
        &url,
        "POST",
        Some(body_str.as_bytes()),
        Some("application/json"),
        Duration::from_secs(8),
        token,
    )?;
    if !(200..300).contains(&status) {
        // Re-check `/v2/parties` in case another concurrent step just allocated it.
        if let Some(existing) = find_existing_party(port, party_hint, token)? {
            grant_dev_party_rights_if_needed(port, auth, Some(&existing), false)?;
            party_cache.insert((node.to_string(), party_hint.to_string()), existing.clone());
            return Ok(format!("{node}: reused party {existing}"));
        }
        return Err(format!(
            "{node} POST /v2/parties ({party_hint}) returned HTTP {status}: {resp_body}"
        ));
    }
    let val: Json = serde_json::from_str(&resp_body)
        .map_err(|e| format!("invalid /v2/parties JSON from {node}: {e}"))?;
    let party = val["partyDetails"]["party"]
        .as_str()
        .or_else(|| val["party"].as_str())
        .ok_or_else(|| format!("missing partyDetails.party in response: {resp_body}"))?
        .to_string();
    grant_dev_party_rights_if_needed(port, auth, Some(&party), false)?;
    party_cache.insert((node.to_string(), party_hint.to_string()), party.clone());
    Ok(format!("{node}: allocated {party}"))
}

fn find_existing_party(
    port: u16,
    party_hint: &str,
    token: Option<&str>,
) -> Result<Option<String>, String> {
    let url = format!("http://127.0.0.1:{port}/v2/parties");
    let (status, body) =
        http_request_bearer(&url, "GET", None, None, Duration::from_secs(4), token)?;
    if !(200..300).contains(&status) {
        return Ok(None);
    }
    let Ok(val) = serde_json::from_str::<Json>(&body) else {
        return Ok(None);
    };
    let prefix = format!("{party_hint}::");
    if let Some(arr) = val["partyDetails"].as_array() {
        for item in arr {
            if let Some(p) = item["party"].as_str() {
                if p == party_hint || p.starts_with(&prefix) {
                    return Ok(Some(p.to_string()));
                }
            }
        }
    }
    Ok(None)
}

fn resolve_party(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    auth: Option<&ScenarioNodeAuth>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    if let Some(p) = party_cache.get(&(node.to_string(), party_hint.to_string())) {
        return Ok(p.clone());
    }
    let _ = run_step_allocate_party(snapshot, node, party_hint, auth, party_cache)?;
    party_cache
        .get(&(node.to_string(), party_hint.to_string()))
        .cloned()
        .ok_or_else(|| format!("failed to resolve party '{party_hint}' on '{node}'"))
}

/// Discovers a single-party creatable Daml template directly from the participant's loaded
/// packages (`GET /v2/packages` + `GET /v2/packages/{id}`), independent of the caller's CWD (`M-003`).
fn discover_create_payload_for_party(
    port: u16,
    party: &str,
    seq_num: u64,
    token: Option<&str>,
) -> Result<(String, Json), String> {
    let pkg_list_url = format!("http://127.0.0.1:{port}/v2/packages");
    let (status, pkg_body) = http_request_bearer(
        &pkg_list_url,
        "GET",
        None,
        None,
        Duration::from_secs(4),
        token,
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "GET /v2/packages on port {port} returned HTTP {status}: {pkg_body}"
        ));
    }
    let loaded_pkgs: Vec<String> = serde_json::from_str::<Json>(&pkg_body)
        .map_err(|e| format!("invalid GET /v2/packages JSON on port {port}: {e}"))?
        .get("packageIds")
        .and_then(Json::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if loaded_pkgs.is_empty() {
        return Err(format!(
            "no creatable Daml template discovered on port {port} (checked 0 packages: participant has no loaded DARs). Upload a DAR first or initialize with `canton-rs daemon init --with-sample-dar`."
        ));
    }

    let mut first_creatable: Option<(String, Json)> = None;
    let mut utility_pkgs = 0usize;
    let mut internal_pkgs = 0usize;
    let mut skip_reasons: Vec<String> = Vec::new();

    for pkg_id in &loaded_pkgs {
        if pkg_id == ledger_json_api::v2_packages::ADMIN_PING_PACKAGE_ID {
            internal_pkgs += 1;
            continue;
        }
        let short_id = &pkg_id[..pkg_id.len().min(12)];
        let pkg_url = format!("http://127.0.0.1:{port}/v2/packages/{pkg_id}");
        let (st, raw_bytes) =
            http_request_bearer_bytes(&pkg_url, "GET", None, None, Duration::from_secs(6), token)?;
        if st == 401 || st == 403 {
            return Err(format!(
                "GET /v2/packages/{pkg_id} on port {port} returned HTTP {st}: {}",
                String::from_utf8_lossy(&raw_bytes)
            ));
        }
        if !(200..300).contains(&st) {
            skip_reasons.push(format!("{short_id}: HTTP {st}"));
            continue;
        }
        let loaded = match lf_archive::load_dalf_payload(pkg_id, &raw_bytes)
            .or_else(|_| lf_archive::load_dalf_allow_dev(&raw_bytes))
        {
            Ok(dalf) => dalf,
            Err(e) => {
                skip_reasons.push(format!("{short_id}: DALF decode failed ({e})"));
                continue;
            }
        };
        let surfaces = match lf_archive::decode::extract_module_surfaces(&loaded.package) {
            Ok(s) => s,
            Err(e) => {
                skip_reasons.push(format!("{short_id}: surface extraction failed ({e})"));
                continue;
            }
        };
        match pick_creatable_template_from_surfaces(pkg_id, &surfaces, party, seq_num) {
            TemplateScanOutcome::Preferred(found) => return Ok(found),
            TemplateScanOutcome::Creatable(found) => {
                if first_creatable.is_none() {
                    first_creatable = Some(found);
                }
            }
            TemplateScanOutcome::NoTemplates => {
                utility_pkgs += 1;
            }
            TemplateScanOutcome::AllInternal => {
                internal_pkgs += 1;
            }
            TemplateScanOutcome::Skipped(reasons) => {
                for r in reasons {
                    if skip_reasons.len() < 6 {
                        skip_reasons.push(format!("{short_id}:{r}"));
                    }
                }
            }
        }
    }

    if let Some(found) = first_creatable {
        return Ok(found);
    }

    let mut summary_parts = Vec::new();
    if utility_pkgs > 0 {
        summary_parts.push(format!(
            "{utility_pkgs} utility/stdlib package(s) without templates"
        ));
    }
    if internal_pkgs > 0 {
        summary_parts.push(format!(
            "{internal_pkgs} internal admin workflow package(s)"
        ));
    }
    if !skip_reasons.is_empty() {
        summary_parts.push(format!("skipped: {}", skip_reasons.join("; ")));
    }
    let detail = if summary_parts.is_empty() {
        "no templates found".to_string()
    } else {
        summary_parts.join(", ")
    };
    Err(format!(
        "no creatable Daml template discovered on port {port} (checked {} package(s): {detail}). Upload a DAR first or initialize with `canton-rs daemon init --with-sample-dar`.",
        loaded_pkgs.len()
    ))
}

enum TemplateScanOutcome {
    Preferred((String, Json)),
    Creatable((String, Json)),
    NoTemplates,
    AllInternal,
    Skipped(Vec<String>),
}

fn pick_creatable_template_from_surfaces(
    package_id: &str,
    surfaces: &[ModuleSurface],
    party: &str,
    seq_num: u64,
) -> TemplateScanOutcome {
    let mut total_templates = 0usize;
    let mut internal_templates = 0usize;
    let mut first_creatable: Option<(String, Json)> = None;
    let mut skip_reasons = Vec::new();

    for m in surfaces {
        for t in &m.templates {
            total_templates += 1;
            if m.name.starts_with("Canton.Internal.") {
                internal_templates += 1;
                continue;
            }
            match build_creatable_template_args(package_id, &m.name, t, party, seq_num) {
                Ok(found) => {
                    if m.name == "AssetHolding" && t.name == "AssetHolding" {
                        return TemplateScanOutcome::Preferred(found);
                    }
                    if first_creatable.is_none() {
                        first_creatable = Some(found);
                    }
                }
                Err(reason) => skip_reasons.push(reason),
            }
        }
    }

    if let Some(found) = first_creatable {
        return TemplateScanOutcome::Creatable(found);
    }
    if total_templates == 0 {
        TemplateScanOutcome::NoTemplates
    } else if internal_templates == total_templates {
        TemplateScanOutcome::AllInternal
    } else {
        TemplateScanOutcome::Skipped(skip_reasons)
    }
}

fn build_creatable_template_args(
    package_id: &str,
    module_name: &str,
    template: &TemplateSurface,
    party: &str,
    seq_num: u64,
) -> Result<(String, Json), String> {
    let mut map = serde_json::Map::new();
    for f in &template.fields {
        if matches!(f.ty, SurfaceType::ContractId(_)) {
            return Err(format!(
                "{module_name}:{} requires ContractId field '{}'",
                template.name, f.name
            ));
        }
        let Some(v) = synth_json_arg(&f.ty, party, seq_num) else {
            return Err(format!(
                "{module_name}:{} has unsupported field '{}' ({})",
                template.name, f.name, f.type_str
            ));
        };
        map.insert(f.name.clone(), v);
    }
    let tmpl_id = format!("{package_id}:{module_name}:{}", template.name);
    Ok((tmpl_id, Json::Object(map)))
}

fn synth_json_arg(ty: &SurfaceType, party: &str, seq_num: u64) -> Option<Json> {
    match ty {
        SurfaceType::Party => Some(Json::String(party.to_string())),
        SurfaceType::Text => Some(Json::String(format!("SCENARIO_ASSET_{seq_num}"))),
        SurfaceType::Numeric(scale_opt) => {
            let scale = scale_opt.unwrap_or(2);
            if scale == 0 {
                Some(Json::String(format!("{}", 1000 + seq_num)))
            } else {
                Some(Json::String(format!("{}.0", 1000 + seq_num)))
            }
        }
        SurfaceType::Int64 => Some(Json::Number((100 + seq_num).into())),
        SurfaceType::Bool => Some(Json::Bool(true)),
        SurfaceType::Date => Some(Json::String("2026-11-19".to_string())),
        SurfaceType::Timestamp => Some(Json::String("2026-11-19T12:00:00Z".to_string())),
        SurfaceType::Unit => Some(json!({})),
        SurfaceType::List(_) => Some(json!([])),
        SurfaceType::GenMap { .. } => Some(json!([])),
        SurfaceType::Optional(_) => Some(Json::Null),
        _ => None,
    }
}

fn submit_one_create(
    port: u16,
    node: &str,
    party: &str,
    seq_num: u64,
    token: Option<&str>,
) -> Result<(i64, String), String> {
    let (template_id, create_args) =
        discover_create_payload_for_party(port, party, seq_num, token)?;
    let cmd_id = format!("crs-scen-{node}-{}-{seq_num}", now_unix_ms());
    let user_id = token
        .and_then(jwt_subject_unverified)
        .unwrap_or_else(|| "scenario-runner".to_string());
    let payload = json!({
        "commands": [
            {
                "CreateCommand": {
                    "templateId": template_id,
                    "createArguments": create_args
                }
            }
        ],
        "userId": user_id,
        "commandId": cmd_id,
        "actAs": [party],
        "readAs": []
    });
    let url = format!("http://127.0.0.1:{port}/v2/commands/submit-and-wait");
    let raw = payload.to_string();
    let (status, resp_body) = http_request_bearer(
        &url,
        "POST",
        Some(raw.as_bytes()),
        Some("application/json"),
        Duration::from_secs(15),
        token,
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "{node} submit-and-wait failed (HTTP {status}): {resp_body}"
        ));
    }
    let val: Json = serde_json::from_str(&resp_body)
        .map_err(|e| format!("invalid submit-and-wait JSON from {node}: {e}"))?;
    let offset = val["completionOffset"].as_i64().unwrap_or(0);
    let short_tmpl = template_id
        .split_once(':')
        .map_or(template_id.as_str(), |(_, rest)| rest)
        .to_string();
    Ok((offset, short_tmpl))
}

fn run_step_submit_create(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    auth: Option<&ScenarioNodeAuth>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    let party = resolve_party(snapshot, node, party_hint, auth, party_cache)?;
    let token = auth.map(|a| a.token.as_str());
    let (offset, short_tmpl) = submit_one_create(port, node, &party, 1, token)?;
    Ok(format!(
        "{node}: committed {short_tmpl} at ledger offset #{offset}"
    ))
}

/// The contract IDs active on the participant at `port` for `parties` (`None`: every party it hosts), at its ledger end.
///
/// An unreadable ledger end or a response that is not an array is an error, so a privacy check never passes on a failed read.
fn active_contract_ids(
    port: u16,
    parties: Option<&str>,
    token: Option<&str>,
) -> Result<BTreeSet<String>, String> {
    let end_url = format!("http://127.0.0.1:{port}/v2/state/ledger-end");
    let (end_status, end_body) =
        http_request_bearer(&end_url, "GET", None, None, Duration::from_secs(4), token)?;
    if !(200..300).contains(&end_status) {
        return Err(format!(
            "GET /v2/state/ledger-end on port {port} returned HTTP {end_status}: {end_body}"
        ));
    }
    let offset = serde_json::from_str::<Json>(&end_body)
        .ok()
        .and_then(|v| v["offset"].as_i64())
        .ok_or_else(|| {
            format!("GET /v2/state/ledger-end on port {port}: no offset in {end_body}")
        })?;
    if offset <= 0 {
        return Ok(BTreeSet::new());
    }

    let wildcard = json!({
        "cumulative": [
            { "identifierFilter": { "WildcardFilter": { "value": { "includeCreatedEventBlob": false } } } }
        ]
    });
    let event_format = match parties {
        Some(party) => json!({ "filtersByParty": { party: wildcard }, "verbose": true }),
        None => json!({ "filtersForAnyParty": wildcard, "verbose": true }),
    };
    let query = json!({ "eventFormat": event_format, "activeAtOffset": offset });
    let acs_url = format!("http://127.0.0.1:{port}/v2/state/active-contracts");
    let raw = query.to_string();
    let (status, body) = http_request_bearer(
        &acs_url,
        "POST",
        Some(raw.as_bytes()),
        Some("application/json"),
        Duration::from_secs(6),
        token,
    )?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "POST /v2/state/active-contracts on port {port} returned HTTP {status}: {body}"
        ));
    }
    let arr: Vec<Json> = serde_json::from_str(&body).map_err(|e| {
        format!("POST /v2/state/active-contracts on port {port}: not an array ({e})")
    })?;
    Ok(arr
        .iter()
        .filter_map(|entry| {
            let ce = &entry["contractEntry"];
            let created = if ce["JsActiveContract"].is_object() {
                &ce["JsActiveContract"]["createdEvent"]
            } else if ce["activeContract"].is_object() {
                &ce["activeContract"]["createdEvent"]
            } else {
                &entry["createdEvent"]
            };
            created["contractId"].as_str().map(str::to_string)
        })
        .collect())
}

/// Checks that the witness participant holds none of the contracts the informee party sees on its own participant.
fn assert_witness_holds_none(
    informee_node: &str,
    inf_port: u16,
    inf_party: &str,
    inf_token: Option<&str>,
    witness_node: &str,
    wit_port: u16,
    wit_token: Option<&str>,
) -> Result<String, String> {
    let informee_ids = active_contract_ids(inf_port, Some(inf_party), inf_token)?;
    if informee_ids.is_empty() {
        return Err(format!(
            "privacy check precondition failed: informee '{informee_node}' ({inf_party}) has 0 active contracts"
        ));
    }
    let witness_ids = active_contract_ids(wit_port, None, wit_token)?;
    let leaked: Vec<&String> = informee_ids.intersection(&witness_ids).collect();
    if !leaked.is_empty() {
        return Err(format!(
            "PRIVACY VIOLATION: non-informee participant '{witness_node}' holds {} of {informee_node}'s contracts: {leaked:?}",
            leaked.len()
        ));
    }
    Ok(format!(
        "PASS sub-transaction privacy: {informee_node} holds {} active contract(s) for {inf_party}; participant {witness_node} holds none of them",
        informee_ids.len()
    ))
}

struct PrivacyParticipant<'a> {
    node: &'a str,
    party_hint: &'a str,
    auth: Option<&'a ScenarioNodeAuth>,
}

struct PrivacyCheckSpec<'a> {
    informee: PrivacyParticipant<'a>,
    witness: PrivacyParticipant<'a>,
}

fn run_step_assert_privacy(
    snapshot: &ClusterSnapshot,
    spec: &PrivacyCheckSpec<'_>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let inf_port = participant_port(snapshot, spec.informee.node)?;
    let wit_port = participant_port(snapshot, spec.witness.node)?;
    let inf_party = resolve_party(
        snapshot,
        spec.informee.node,
        spec.informee.party_hint,
        spec.informee.auth,
        party_cache,
    )?;
    // The witness party is resolved so a misnamed witness still fails loudly; the check itself covers every party the
    // witness participant hosts.
    let _ = resolve_party(
        snapshot,
        spec.witness.node,
        spec.witness.party_hint,
        spec.witness.auth,
        party_cache,
    )?;
    grant_dev_party_rights_if_needed(wit_port, spec.witness.auth, None, true)?;
    assert_witness_holds_none(
        spec.informee.node,
        inf_port,
        &inf_party,
        spec.informee.auth.map(|a| a.token.as_str()),
        spec.witness.node,
        wit_port,
        spec.witness.auth.map(|a| a.token.as_str()),
    )
}

fn run_step_burst_creates(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    count: usize,
    auth: Option<&ScenarioNodeAuth>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    let party = resolve_party(snapshot, node, party_hint, auth, party_cache)?;
    let token = auth.map(|a| a.token.as_str());
    let mut latencies_ms = Vec::with_capacity(count);
    let burst_start = Instant::now();
    let mut last_offset = 0i64;
    for seq in 1..=count {
        let t0 = Instant::now();
        let (off, _) = submit_one_create(port, node, &party, seq as u64, token)?;
        last_offset = off;
        latencies_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    let wall_secs = burst_start.elapsed().as_secs_f64().max(0.001);
    let tps = (count as f64) / wall_secs;
    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = latencies_ms[latencies_ms.len() / 2];
    let p99 = latencies_ms[(latencies_ms.len() * 99) / 100];
    Ok(format!(
        "{node}: {count}/{count} committed up to #{last_offset} ({tps:.1} tx/s, p50={p50:.1}ms, p99={p99:.1}ms)"
    ))
}

/// Builds a failed [`ScenarioRunReport`] when daemon IPC fails after sending `RunScenario`.
pub fn failed_scenario_report(spec: &ScenarioSpec, err: String) -> ScenarioRunReport {
    ScenarioRunReport {
        scenario: spec.name.clone(),
        description: spec.description.clone(),
        ok: false,
        total_elapsed_ms: 0.0,
        steps: vec![ScenarioStepResult {
            index: 0,
            action: "ipc_run_scenario".to_string(),
            ok: false,
            elapsed_ms: 0.0,
            summary: err,
        }],
    }
}

/// Runs `spec` through daemon IPC and falls back locally ONLY when the daemon socket is unreachable (`NotFound`/`ConnectionRefused`).
pub fn run_scenario_via_ipc_or_local(
    state_dir: &Path,
    snapshot: &ClusterSnapshot,
    spec: &ScenarioSpec,
    timeout: Duration,
) -> Result<ScenarioRunReport, String> {
    run_scenario_via_ipc_or_local_with(state_dir, timeout, spec, || {
        execute_scenario(Some(state_dir), snapshot, spec)
    })
}

fn run_scenario_via_ipc_or_local_with<F>(
    state_dir: &Path,
    req_timeout: Duration,
    spec: &ScenarioSpec,
    run_local: F,
) -> Result<ScenarioRunReport, String>
where
    F: FnOnce() -> ScenarioRunReport,
{
    match call_unary_typed(
        state_dir,
        &IpcRequest::RunScenario { spec: spec.clone() },
        Some(req_timeout),
    ) {
        Ok(IpcResponse::ScenarioReport { report, .. }) => Ok(report),
        Ok(other) => Err(format!(
            "unexpected IPC response for run_scenario after request was sent: {other:?}"
        )),
        Err(IpcCallError::Unreachable(_)) => Ok(run_local()),
        Err(IpcCallError::PostSend(e)) => Err(e),
    }
}

fn resolve_scenario_state_dir(
    instance_name: Option<&str>,
    state_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let raw = resolve_target_state_dir(instance_name, state_dir)?;
    Ok(if instance_name.is_none() && state_dir.is_none() {
        resolve_client_state_dir(&raw)
    } else {
        raw
    })
}

/// CLI dispatcher for `canton-rs daemon scenario <list|run>`.
pub fn cmd_scenario(args: ScenarioCliArgs) -> Result<(), String> {
    match args.action {
        ScenarioCliAction::List(list_args) => {
            let eff_sd = resolve_scenario_state_dir(
                list_args.name.as_deref(),
                list_args.state_dir.as_deref(),
            )?;
            let (custom, nodes) = load_scenarios_context(list_args.file.as_deref(), &eff_sd)?;
            let all = available_scenarios_for_nodes(&custom, &nodes);
            if list_args.json {
                let s = serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?;
                println!("{s}");
                return Ok(());
            }
            println!(
                "{:<26} {:<9} {:<6} DESCRIPTION",
                "SCENARIO", "SOURCE", "STEPS"
            );
            for sc in &all {
                let src = if sc.builtin { "builtin" } else { "manifest" };
                println!(
                    "{:<26} {:<9} {:<6} {}",
                    sc.name,
                    src,
                    sc.steps.len(),
                    sc.description
                );
            }
            Ok(())
        }
        ScenarioCliAction::Run(run_args) => {
            let explicit_tok = resolve_explicit_token(&ExplicitTokenArgs {
                token_env: run_args.token_env.as_deref(),
                token_file: run_args.token_file.as_deref(),
            })?;
            let eff_sd = resolve_scenario_state_dir(
                run_args.instance_name.as_deref(),
                run_args.state_dir.as_deref(),
            )?;
            let snapshot = match call_unary(&eff_sd, &IpcRequest::GetSnapshot)? {
                IpcResponse::Snapshot { snapshot, .. } => snapshot,
                IpcResponse::Error { error, .. } => return Err(error),
                _ => return Err("unexpected IPC response for get_snapshot".to_string()),
            };
            let custom = match &run_args.file {
                Some(path) => load_custom_scenarios_from_file(path)?,
                None => snapshot.scenarios.clone(),
            };
            let all = available_scenarios_for_nodes(&custom, &snapshot.nodes);
            let spec = all
                .iter()
                .find(|s| s.name == run_args.name)
                .ok_or_else(|| {
                    let known: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
                    format!(
                        "unknown scenario '{}' (available: {})",
                        run_args.name,
                        known.join(", ")
                    )
                })?;

            // [CANTON-NOTE: WHY] When the user passes an explicit --token-env/--token-file, execute
            // locally with that exact token (never auto-signing or delegating to the supervisor's
            // DevJwt) so explicit credentials always override --dev-auth (M-002).
            let report = if let Some(tok) = explicit_tok {
                let auth_map: BTreeMap<String, ScenarioNodeAuth> = snapshot
                    .nodes
                    .iter()
                    .filter(|n| n.role == NodeRole::Participant)
                    .map(|n| {
                        (
                            n.name.clone(),
                            ScenarioNodeAuth {
                                token: tok.clone(),
                                is_dev_auto_signed: false,
                            },
                        )
                    })
                    .collect();
                execute_scenario_with_auth(Some(&eff_sd), &snapshot, spec, &auth_map)
            } else {
                run_scenario_via_ipc_or_local(&eff_sd, &snapshot, spec, Duration::from_secs(120))?
            };
            if run_args.json {
                let s = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
                println!("{s}");
            } else {
                println!(
                    "Scenario '{}' — {} ({:.1} ms)",
                    report.scenario,
                    if report.ok { "PASS" } else { "FAIL" },
                    report.total_elapsed_ms
                );
                for st in &report.steps {
                    let badge = if st.ok { "[OK]" } else { "[ERR]" };
                    println!(
                        "  {badge:<5} step {:>2} ({:<22} {:>6.1}ms): {}",
                        st.index, st.action, st.elapsed_ms, st.summary
                    );
                }
            }
            if report.ok {
                Ok(())
            } else {
                Err(format!("scenario '{}' failed", report.scenario))
            }
        }
    }
}

fn load_custom_scenarios_from_file(path: &Path) -> Result<Vec<ScenarioSpec>, String> {
    match super::manifest::load_yaml_manifest(path)? {
        super::manifest::ParsedYamlManifest::ModeA(spec) => Ok(spec.scenarios),
        super::manifest::ParsedYamlManifest::ModeB(mb) => Ok(mb.scenarios),
    }
}

fn load_scenarios_context(
    file: Option<&Path>,
    state_dir: &Path,
) -> Result<(Vec<ScenarioSpec>, Vec<NodeSnapshot>), String> {
    let eff_sd = resolve_client_state_dir(state_dir);
    if let Ok(IpcResponse::Snapshot { snapshot, .. }) =
        call_unary(&eff_sd, &IpcRequest::GetSnapshot)
    {
        let custom = match file {
            Some(f) => load_custom_scenarios_from_file(f)?,
            None => snapshot.scenarios.clone(),
        };
        return Ok((custom, snapshot.nodes));
    }
    let yaml_path = match file {
        Some(f) => f.to_path_buf(),
        None => PathBuf::from("canton-daemon.yaml"),
    };
    if yaml_path.exists() {
        let parsed = super::manifest::load_yaml_manifest(&yaml_path)?;
        if let super::manifest::ParsedYamlManifest::ModeA(spec) = parsed {
            let dummy_nodes: Vec<NodeSnapshot> = spec
                .services
                .iter()
                .map(|s| NodeSnapshot {
                    slot_id: s.slot_id,
                    role: s.role,
                    name: s.name.clone(),
                    group: s.group.clone(),
                    synchronizer_domain: s.synchronizer_domain.clone(),
                    host_label: None,
                    pid: None,
                    ports: s.ports.clone(),
                    state: NodeLifecycleState::Stopped,
                    restart_policy: s.restart,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 0,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: Default::default(),
                    history_60s: Vec::new(),
                    domain: super::DomainMetrics::Sequencer {
                        head_offset: 0,
                        connected_members: 0,
                        bft_quorum_peers: None,
                    },
                })
                .collect();
            return Ok((spec.scenarios, dummy_nodes));
        }
    }
    Ok((Vec::new(), Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Serves `(status, body)` for `GET /v2/state/ledger-end` and `POST /v2/state/active-contracts` until `n` requests,
    /// draining each HTTP request head + `Content-Length` body before responding.
    fn participant(
        end: (u16, &'static str),
        acs: &'static str,
        n: usize,
    ) -> (u16, std::thread::JoinHandle<()>) {
        participant_with_auth(end, acs, None, n)
    }

    fn participant_with_auth(
        end: (u16, &'static str),
        acs: &'static str,
        required_token: Option<&'static str>,
        n: usize,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            for _ in 0..n {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut raw = Vec::new();
                let mut chunk = [0u8; 2048];
                let mut head_end = None;
                let mut content_len = 0usize;
                loop {
                    let read = match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => k,
                    };
                    raw.extend_from_slice(&chunk[..read]);
                    if head_end.is_none() {
                        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            head_end = Some(pos + 4);
                            let head_str = String::from_utf8_lossy(&raw[..pos]);
                            content_len = head_str
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                        }
                    }
                    if let Some(he) = head_end {
                        if raw.len() >= he + content_len {
                            break;
                        }
                    }
                }
                let head_slice = head_end.map_or(&raw[..], |he| &raw[..he]);
                let head = String::from_utf8_lossy(head_slice);
                let authorized = match required_token {
                    Some(tok) => head.lines().any(|l| {
                        l.trim()
                            .eq_ignore_ascii_case(&format!("Authorization: Bearer {tok}"))
                    }),
                    None => true,
                };
                let (status, body) = if !authorized {
                    (401, "unauthorized")
                } else if head.starts_with("GET /v2/state/ledger-end") {
                    end
                } else {
                    (200, acs)
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.flush();
            }
        });
        (port, h)
    }

    const ONE: &str =
        r#"[{"contractEntry":{"JsActiveContract":{"createdEvent":{"contractId":"00aa"}}}}]"#;

    /// A witness participant whose ledger cannot be read fails the check; it used to count as 0 contracts and pass.
    #[test]
    fn privacy_check_fails_when_the_witness_cannot_be_read() {
        let (inf, h1) = participant((200, r#"{"offset":5}"#), ONE, 2);
        let (wit, h2) = participant((500, "boom"), "[]", 1);
        let err = assert_witness_holds_none("p1", inf, "alice::x", None, "p2", wit, None)
            .expect_err("an unreadable witness is not a pass");
        assert!(err.contains("HTTP 500"), "{err}");
        let _ = (h1.join(), h2.join());
    }

    /// The check fails when the witness participant holds the informee's contract and passes when it holds none of them.
    #[test]
    fn privacy_check_compares_contract_ids_across_participants() {
        let (inf, h1) = participant((200, r#"{"offset":5}"#), ONE, 2);
        let (wit, h2) = participant((200, r#"{"offset":5}"#), ONE, 2);
        let err = assert_witness_holds_none("p1", inf, "alice::x", None, "p2", wit, None)
            .expect_err("a held contract is a violation");
        assert!(err.contains("PRIVACY VIOLATION"), "{err}");
        let _ = (h1.join(), h2.join());

        let (inf, h1) = participant((200, r#"{"offset":5}"#), ONE, 2);
        let (wit, h2) = participant((200, r#"{"offset":0}"#), "[]", 1);
        let ok =
            assert_witness_holds_none("p1", inf, "alice::x", None, "p2", wit, None).expect("pass");
        assert!(ok.contains("holds none"), "{ok}");
        let _ = (h1.join(), h2.join());
    }

    #[test]
    fn privacy_check_sends_per_participant_bearer_tokens() {
        let (inf, h1) = participant_with_auth((200, r#"{"offset":5}"#), ONE, Some("tok-1"), 3);
        let (wit, h2) = participant_with_auth((200, r#"{"offset":0}"#), "[]", Some("tok-2"), 1);
        let err = assert_witness_holds_none("p1", inf, "alice::x", None, "p2", wit, None)
            .expect_err("missing token fails with 401");
        assert!(err.contains("HTTP 401"), "{err}");
        let ok = assert_witness_holds_none(
            "p1",
            inf,
            "alice::x",
            Some("tok-1"),
            "p2",
            wit,
            Some("tok-2"),
        )
        .expect("matching bearer tokens pass");
        assert!(ok.contains("holds none"), "{ok}");
        let _ = (h1.join(), h2.join());
    }

    #[cfg(unix)]
    #[test]
    fn post_send_ipc_failure_does_not_rerun_scenario_locally() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("cr12-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).expect("bind unix socket");

        let http_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
        http_listener
            .set_nonblocking(true)
            .expect("set_nonblocking");
        let http_port = http_listener.local_addr().expect("addr").port();
        let local_hits = Arc::new(AtomicUsize::new(0));
        let stop_http = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let http_hits = Arc::clone(&local_hits);
        let http_stop = Arc::clone(&stop_http);
        let http_h = std::thread::spawn(move || {
            while !http_stop.load(Ordering::SeqCst) {
                match http_listener.accept() {
                    Ok((mut s, _)) => {
                        http_hits.fetch_add(1, Ordering::SeqCst);
                        let body = r#"{"partyDetails":{"party":"alice::1220"}}"#;
                        let _ = write!(
                            s,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let snapshot = ClusterSnapshot {
            stack_name: "r12-test".into(),
            synchronizer: "sync1".into(),
            storage_mode: "files".into(),
            collected_at_unix_ms: 0,
            total_cpu_percent: 0.0,
            total_rss_bytes: 0,
            last_ping: None,
            shadow_verify: None,
            wiretap_dropped_events: 0,
            scenarios: vec![ScenarioSpec {
                name: "probe-local".into(),
                description: "r12 fail-first".into(),
                builtin: false,
                steps: vec![ScenarioStep::AllocateParty {
                    node: "p1".into(),
                    party_hint: "alice".into(),
                }],
            }],
            metrics_port: None,
            metrics_bind: None,
            nodes: vec![NodeSnapshot {
                slot_id: 0,
                role: NodeRole::Participant,
                name: "p1".into(),
                group: None,
                synchronizer_domain: None,
                host_label: None,
                pid: Some(1234),
                ports: super::super::NodePorts {
                    http_json: Some(http_port),
                    ..Default::default()
                },
                state: NodeLifecycleState::Online,
                restart_policy: super::super::RestartPolicy::No,
                restarts_total: 0,
                consecutive_failures: 0,
                uptime_secs: 1,
                stopped_at_unix_ms: None,
                last_exit_reason: None,
                resources: Default::default(),
                history_60s: Vec::new(),
                domain: super::super::DomainMetrics::Participant {
                    ledger_end_offset: 1,
                    active_contracts: 0,
                    hosted_parties: 0,
                    loaded_dars: 0,
                    ready: true,
                    ready_reason: "ok".into(),
                    api_requests_total: 0,
                },
            }],
        };

        let ipc_h = std::thread::spawn(move || {
            // Connection 1: GetSnapshot
            if let Ok((mut s1, _)) = listener.accept() {
                let mut r = BufReader::new(s1.try_clone().expect("clone s1"));
                let mut line = String::new();
                let _ = r.read_line(&mut line);
                let resp = serde_json::to_string(&IpcResponse::Snapshot { ok: true, snapshot })
                    .expect("serialize snapshot");
                let _ = writeln!(s1, "{resp}");
                let _ = s1.flush();
            }
            // Connection 2: RunScenario — read request then drop with EOF before replying!
            if let Ok((s2, _)) = listener.accept() {
                let mut r = BufReader::new(s2);
                let mut line = String::new();
                let _ = r.read_line(&mut line);
            }
        });

        let res = cmd_scenario(ScenarioCliArgs {
            action: ScenarioCliAction::Run(ScenarioRunArgs {
                name: "probe-local".into(),
                file: None,
                instance_name: None,
                state_dir: Some(dir.clone()),
                token_env: None,
                token_file: None,
                json: true,
            }),
        });

        stop_http.store(true, Ordering::SeqCst);
        let _ = (ipc_h.join(), http_h.join());
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            res.is_err(),
            "post-send IPC disconnect must fail loudly instead of silently re-running locally: {res:?}"
        );
        assert_eq!(
            local_hits.load(Ordering::SeqCst),
            0,
            "scenario must NEVER execute locally after IPC request was already sent"
        );

        // (b) Timeout after request sent must also NOT execute locally
        let stalled_dir =
            std::env::temp_dir().join(format!("canton-r12-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stalled_dir);
        std::fs::create_dir_all(&stalled_dir).expect("mkdir stalled");
        let stalled_sock = stalled_dir.join("daemon.sock");
        let stalled_listener = UnixListener::bind(&stalled_sock).expect("bind stalled");
        let stalled_h = std::thread::spawn(move || {
            if let Ok((s, _)) = stalled_listener.accept() {
                let mut r = BufReader::new(s);
                let mut line = String::new();
                let _ = r.read_line(&mut line);
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let timeout_local_runs = Arc::new(AtomicUsize::new(0));
        let timeout_runs_ref = Arc::clone(&timeout_local_runs);
        let timeout_spec = ScenarioSpec {
            name: "probe-timeout".into(),
            description: "r12 timeout".into(),
            builtin: false,
            steps: Vec::new(),
        };
        let timeout_spec_closure = timeout_spec.clone();
        let timeout_res = run_scenario_via_ipc_or_local_with(
            &stalled_dir,
            Duration::from_millis(60),
            &timeout_spec,
            move || {
                timeout_runs_ref.fetch_add(1, Ordering::SeqCst);
                failed_scenario_report(&timeout_spec_closure, "should not run".into())
            },
        );
        let _ = stalled_h.join();
        let _ = std::fs::remove_dir_all(&stalled_dir);
        assert!(timeout_res.is_err(), "post-send timeout must return Err");
        assert_eq!(timeout_local_runs.load(Ordering::SeqCst), 0);

        // (c) Positive control: missing socket (Unreachable) runs locally once
        let missing_dir =
            std::env::temp_dir().join(format!("canton-r12-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing_dir);
        let missing_runs = Arc::new(AtomicUsize::new(0));
        let missing_runs_ref = Arc::clone(&missing_runs);
        let missing_spec = ScenarioSpec {
            name: "probe-missing".into(),
            description: "r12 missing sock".into(),
            builtin: false,
            steps: Vec::new(),
        };
        let missing_spec_closure = missing_spec.clone();
        let local_res = run_scenario_via_ipc_or_local_with(
            &missing_dir,
            Duration::from_secs(1),
            &missing_spec,
            move || {
                missing_runs_ref.fetch_add(1, Ordering::SeqCst);
                ScenarioRunReport {
                    scenario: missing_spec_closure.name,
                    description: missing_spec_closure.description,
                    ok: true,
                    total_elapsed_ms: 1.0,
                    steps: Vec::new(),
                }
            },
        );
        assert!(local_res.expect("local fallback ok").ok);
        assert_eq!(missing_runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn discover_create_payload_fetches_sample_dar_over_http_and_enforces_auth() {
        let dar_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let dar_bytes = std::fs::read(&dar_path).expect("read sample-contract.dar");
        let parsed = lf_archive::parse_dar_bytes(&dar_bytes).expect("parse sample dar");
        let main_pkg_id = parsed.main_package_id;
        let payloads: BTreeMap<String, Vec<u8>> = lf_archive::dalf_payloads(&dar_bytes)
            .expect("dalf payloads")
            .into_iter()
            .collect();
        let pkg_ids: Vec<String> = std::iter::once(main_pkg_id.clone())
            .chain(payloads.keys().filter(|k| *k != &main_pkg_id).cloned())
            .collect();
        let pkg_list_json = json!({ "packageIds": pkg_ids }).to_string();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let required_tok = "good-test-token";
        let h = std::thread::spawn(move || {
            // Serve 3 requests: 1 unauthorized GET /v2/packages, 1 authorized GET /v2/packages, 1 authorized GET /v2/packages/<main>
            for _ in 0..3 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let req_line = head.lines().next().unwrap_or("");
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let authorized = head.lines().any(|l| {
                    l.trim()
                        .eq_ignore_ascii_case(&format!("Authorization: Bearer {required_tok}"))
                });
                if !authorized {
                    let body = b"unauthorized";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                } else if path == "/v2/packages" {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{pkg_list_json}",
                        pkg_list_json.len()
                    );
                } else if let Some(id) = path.strip_prefix("/v2/packages/") {
                    if let Some(bytes) = payloads.get(id) {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        );
                        let _ = stream.write_all(bytes);
                    } else {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                }
                let _ = stream.flush();
            }
        });

        // Negative control: wrong token returns 401 loudly instead of "no creatable template".
        let err = discover_create_payload_for_party(port, "SmokeAlice::1220aa", 1, Some("bad-tok"))
            .expect_err("wrong token must fail with 401");
        assert!(err.contains("HTTP 401"), "expected HTTP 401, got: {err}");

        // Positive control: discovers AssetHolding:AssetHolding with all 5 fields over HTTP!
        let (tmpl_id, args) =
            discover_create_payload_for_party(port, "SmokeAlice::1220aa", 1, Some(required_tok))
                .expect("should discover AssetHolding over HTTP");
        assert_eq!(tmpl_id, format!("{main_pkg_id}:AssetHolding:AssetHolding"));
        assert_eq!(args["bank"], "SmokeAlice::1220aa");
        assert_eq!(args["owner"], "SmokeAlice::1220aa");
        assert_eq!(args["auditor"], "SmokeAlice::1220aa");
        assert_eq!(args["assetSymbol"], "SCENARIO_ASSET_1");
        assert_eq!(args["amount"], "1001.0");
        let _ = h.join();
    }

    #[test]
    fn discover_create_payload_diagnoses_zero_dar_and_skips_uncreatable_templates() {
        // (a) Zero-DAR server returning empty packageIds list
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            for body in [
                r#"{"packageIds":[]}"#,
                &json!({ "packageIds": [ledger_json_api::v2_packages::ADMIN_PING_PACKAGE_ID] })
                    .to_string(),
            ] {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf);
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            }
        });

        let zero_err = discover_create_payload_for_party(port, "Alice::1220", 1, None)
            .expect_err("zero-DAR must fail");
        assert!(
            zero_err.contains("checked 0 packages") && zero_err.contains("--with-sample-dar"),
            "unexpected zero-DAR diagnostic: {zero_err}"
        );

        let admin_only_err = discover_create_payload_for_party(port, "Alice::1220", 1, None)
            .expect_err("admin-ping-only must fail");
        assert!(
            admin_only_err.contains("internal admin workflow")
                && admin_only_err.contains("--with-sample-dar"),
            "unexpected admin-only diagnostic: {admin_only_err}"
        );
        let _ = h.join();

        // (b) Custom user DAR surfaces: skips ContractId template and picks single-party creatable template
        let surfaces = vec![ModuleSurface {
            name: "CustomMod".into(),
            templates: vec![
                TemplateSurface {
                    name: "NeedsCid".into(),
                    param_name: "this".into(),
                    fields: vec![lf_archive::FieldDef::new(
                        "refCid",
                        SurfaceType::ContractId(Box::new(SurfaceType::Unit)),
                    )],
                    signatories: vec!["owner".into()],
                    observers: Vec::new(),
                    choices: Vec::new(),
                    ensure: lf_archive::BytePresence::absent(),
                },
                TemplateSurface {
                    name: "SimpleNote".into(),
                    param_name: "this".into(),
                    fields: vec![
                        lf_archive::FieldDef::new("owner", SurfaceType::Party),
                        lf_archive::FieldDef::new("label", SurfaceType::Text),
                    ],
                    signatories: vec!["owner".into()],
                    observers: Vec::new(),
                    choices: Vec::new(),
                    ensure: lf_archive::BytePresence::absent(),
                },
            ],
        }];
        match pick_creatable_template_from_surfaces("deadbeef", &surfaces, "Bob::1220", 3) {
            TemplateScanOutcome::Creatable((tid, args)) => {
                assert_eq!(tid, "deadbeef:CustomMod:SimpleNote");
                assert_eq!(args["owner"], "Bob::1220");
                assert_eq!(args["label"], "SCENARIO_ASSET_3");
            }
            _ => panic!("expected CustomMod:SimpleNote to be selected"),
        }
    }

    #[test]
    fn scenario_cli_parses_instance_name_and_token_flags() {
        use clap::Parser;

        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: ScenarioCliArgs,
        }

        let parsed = Wrapper::try_parse_from([
            "scenario",
            "run",
            "smoke-create",
            "--name",
            "dev",
            "--token-env",
            "MY_TOKEN",
        ])
        .expect("parse scenario run with --name and --token-env");
        match parsed.args.action {
            ScenarioCliAction::Run(run) => {
                assert_eq!(run.name, "smoke-create");
                assert_eq!(run.instance_name.as_deref(), Some("dev"));
                assert_eq!(run.token_env.as_deref(), Some("MY_TOKEN"));
                assert!(run.token_file.is_none());
            }
            ScenarioCliAction::List(_) => panic!("expected Run"),
        }
    }
}
