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
use lf_archive::{DarArchive, SurfaceType};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use yaml_rust2::Yaml;

use super::ipc::{
    call_unary, call_unary_typed, resolve_client_state_dir, IpcCallError, IpcRequest, IpcResponse,
};
use super::probe::{http_request, http_request_bearer};
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
    #[arg(long, default_value = "canton-rs-state")]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ScenarioRunArgs {
    /// Scenario name (see `canton-rs daemon scenario list`).
    pub name: String,
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    #[arg(long, default_value = "canton-rs-state")]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
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

/// Executes a `ScenarioSpec` end-to-end against a running supervisor stack.
/// Runs `spec` against live HTTP JSON APIs in `snapshot`, returning a complete step-by-step report.
pub fn execute_scenario(
    state_dir: Option<&Path>,
    snapshot: &ClusterSnapshot,
    spec: &ScenarioSpec,
) -> ScenarioRunReport {
    execute_scenario_with_tokens(state_dir, snapshot, spec, &BTreeMap::new())
}

/// Runs `spec` against live HTTP JSON APIs in `snapshot` using optional per-node bearer tokens.
pub fn execute_scenario_with_tokens(
    state_dir: Option<&Path>,
    snapshot: &ClusterSnapshot,
    spec: &ScenarioSpec,
    tokens: &BTreeMap<String, String>,
) -> ScenarioRunReport {
    let overall_start = Instant::now();
    let mut step_results = Vec::with_capacity(spec.steps.len());
    let mut party_cache: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut all_ok = true;
    let tok = |node: &str| tokens.get(node).map(String::as_str);

    for (idx, step) in spec.steps.iter().enumerate() {
        let t0 = Instant::now();
        let (action_name, outcome) = match step {
            ScenarioStep::HealthPing => ("health_ping", run_step_health_ping(state_dir, snapshot)),
            ScenarioStep::AllocateParty { node, party_hint } => (
                "allocate_party",
                run_step_allocate_party(snapshot, node, party_hint, tok(node), &mut party_cache),
            ),
            ScenarioStep::SubmitCreate { node, party_hint } => (
                "submit_create",
                run_step_submit_create(snapshot, node, party_hint, tok(node), &mut party_cache),
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
                            token: tok(informee_node),
                        },
                        witness: PrivacyParticipant {
                            node: witness_node,
                            party_hint: witness_party_hint,
                            token: tok(witness_node),
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
                    tok(node),
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

fn run_step_allocate_party(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    token: Option<&str>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    if let Some(existing) = find_existing_party(port, party_hint, token)? {
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
    token: Option<&str>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    if let Some(p) = party_cache.get(&(node.to_string(), party_hint.to_string())) {
        return Ok(p.clone());
    }
    let _ = run_step_allocate_party(snapshot, node, party_hint, token, party_cache)?;
    party_cache
        .get(&(node.to_string(), party_hint.to_string()))
        .cloned()
        .ok_or_else(|| format!("failed to resolve party '{party_hint}' on '{node}'"))
}

fn discover_create_payload_for_party(
    port: u16,
    party: &str,
    seq_num: u64,
    token: Option<&str>,
) -> Result<(String, Json), String> {
    // Prefer local sample-contract.dar when available and vetted on this participant; otherwise
    // fall back to inspecting packages exposed by `GET /v2/packages`.
    let pkg_list_url = format!("http://127.0.0.1:{port}/v2/packages");
    let (status, pkg_body) = http_request_bearer(
        &pkg_list_url,
        "GET",
        None,
        None,
        Duration::from_secs(4),
        token,
    )?;
    let loaded_pkgs: Vec<String> = if (200..300).contains(&status) {
        serde_json::from_str::<Json>(&pkg_body)
            .ok()
            .and_then(|v| {
                v["packageIds"].as_array().map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let sample_dar = PathBuf::from("contracts/target/sample-contract.dar");
    if sample_dar.exists() {
        if let Ok(archive) = lf_archive::parse_dar_file(&sample_dar) {
            if loaded_pkgs.is_empty() || loaded_pkgs.contains(&archive.main_package_id) {
                if let Some((tmpl_id, args)) = pick_creatable_template(&archive, party, seq_num) {
                    return Ok((tmpl_id, args));
                }
            }
        }
    }

    Err(format!(
        "no creatable Daml template discovered on port {port} (ensure sample-contract.dar is loaded)"
    ))
}

fn pick_creatable_template(
    archive: &DarArchive,
    party: &str,
    seq_num: u64,
) -> Option<(String, Json)> {
    // Prefer a template whose fields contain only primitives + Party (no pre-existing ContractId needed).
    for m in &archive.module_surfaces {
        for t in &m.templates {
            let needs_cid = t
                .fields
                .iter()
                .any(|f| matches!(f.ty, SurfaceType::ContractId(_)));
            if needs_cid {
                continue;
            }
            let mut map = serde_json::Map::new();
            let mut supported = true;
            for f in &t.fields {
                match synth_json_arg(&f.ty, party, seq_num) {
                    Some(v) => {
                        map.insert(f.name.clone(), v);
                    }
                    None => {
                        supported = false;
                        break;
                    }
                }
            }
            if supported {
                let tmpl_id = format!("{}:{}:{}", archive.main_package_id, m.name, t.name);
                return Some((tmpl_id, Json::Object(map)));
            }
        }
    }
    None
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
    let payload = json!({
        "commands": [
            {
                "CreateCommand": {
                    "templateId": template_id,
                    "createArguments": create_args
                }
            }
        ],
        "userId": "scenario-runner",
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
    token: Option<&str>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    let party = resolve_party(snapshot, node, party_hint, token, party_cache)?;
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
    token: Option<&'a str>,
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
        spec.informee.token,
        party_cache,
    )?;
    // The witness party is resolved so a misnamed witness still fails loudly; the check itself covers every party the
    // witness participant hosts.
    let _ = resolve_party(
        snapshot,
        spec.witness.node,
        spec.witness.party_hint,
        spec.witness.token,
        party_cache,
    )?;
    assert_witness_holds_none(
        spec.informee.node,
        inf_port,
        &inf_party,
        spec.informee.token,
        spec.witness.node,
        wit_port,
        spec.witness.token,
    )
}

fn run_step_burst_creates(
    snapshot: &ClusterSnapshot,
    node: &str,
    party_hint: &str,
    count: usize,
    token: Option<&str>,
    party_cache: &mut BTreeMap<(String, String), String>,
) -> Result<String, String> {
    let port = participant_port(snapshot, node)?;
    let party = resolve_party(snapshot, node, party_hint, token, party_cache)?;
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

/// CLI dispatcher for `canton-rs daemon scenario <list|run>`.
pub fn cmd_scenario(args: ScenarioCliArgs) -> Result<(), String> {
    match args.action {
        ScenarioCliAction::List(list_args) => {
            let (custom, nodes) =
                load_scenarios_context(list_args.file.as_deref(), &list_args.state_dir)?;
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
            let eff_sd = resolve_client_state_dir(&run_args.state_dir);
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

            let report =
                run_scenario_via_ipc_or_local(&eff_sd, &snapshot, spec, Duration::from_secs(120))?;
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
                state_dir: dir.clone(),
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
}
