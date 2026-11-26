//! Cluster-wide quiesce/drain and post-restore identity/ledger-end verification (`S-DX-004`).

use std::collections::BTreeMap;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value as Json;

use super::super::creds::{
    is_loopback_host, resolve_dev_auth_token_for_dir, resolve_explicit_token, ExplicitTokenArgs,
    CLI_AUTO_DEV_JWT_TTL_SECS,
};
use super::super::query::{parse_http_url, EndpointTarget};
use super::super::status::{EndpointState, EndpointStatus};
use super::DaemonRecipe;
use crate::commands::exit_code::{exit_with_message, EXIT_MISMATCH, EXIT_PREFLIGHT};
use crate::commands::json_http;

/// Kind of HTTP control endpoint exposed by a supervised node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRole {
    Participant,
    Mediator,
    Sequencer,
}

/// Discovered HTTP control endpoint for one service listed in `DaemonRecipe`.
#[derive(Clone, Debug)]
pub struct ControlNode {
    pub name: String,
    pub role: ControlRole,
    pub target: EndpointTarget,
    /// Optional bearer token attached to participant control/ledger HTTP requests (`M-002`).
    pub token: Option<String>,
}

/// Expected pre-snapshot ledger state and cryptographic identities captured before shutdown.
#[derive(Clone, Debug, Default)]
pub struct LiveExpectations {
    pub ledger_ends: BTreeMap<String, u64>,
    pub node_identities: BTreeMap<String, String>,
    pub scan_history_lines: Option<usize>,
}

/// Resolves unambiguous HTTP control endpoints using `recipe.services` roles and live `endpoints`.
pub fn resolve_control_nodes(
    recipe: &DaemonRecipe,
    endpoints: &BTreeMap<String, EndpointStatus>,
) -> Result<Vec<ControlNode>, String> {
    let mut nodes = Vec::new();
    for svc in &recipe.services {
        let (role, key) = match svc.role.as_str() {
            "participant" => (ControlRole::Participant, format!("{}.json", svc.name)),
            "mediator" => {
                let primary = format!("{}.admin", svc.name);
                let alt = format!("{}.metrics", svc.name);
                let key = if endpoints.contains_key(&primary) {
                    primary
                } else {
                    alt
                };
                (ControlRole::Mediator, key)
            }
            "sequencer" => {
                let primary = format!("{}.metrics", svc.name);
                let alt = format!("{}.admin", svc.name);
                let key = if endpoints.contains_key(&primary) {
                    primary
                } else {
                    alt
                };
                (ControlRole::Sequencer, key)
            }
            _ => continue,
        };
        let Some(ep) = endpoints.get(&key) else {
            continue;
        };
        if ep.state == EndpointState::Up || ep.state == EndpointState::Starting {
            nodes.push(ControlNode {
                name: svc.name.clone(),
                role,
                target: parse_http_url(&ep.url)?,
                token: None,
            });
        }
    }
    Ok(nodes)
}

/// Attaches explicit (`--token-env`/`--token-file`) or loopback auto-signed `dev-jwt.key` bearer
/// tokens to every participant [`ControlNode`] (`M-002`).
pub(crate) fn attach_participant_tokens(
    state_dir: &Path,
    nodes: &mut [ControlNode],
    explicit: &ExplicitTokenArgs<'_>,
) -> Result<(), String> {
    let explicit_tok = resolve_explicit_token(explicit)?;
    for node in nodes.iter_mut() {
        if node.role != ControlRole::Participant {
            continue;
        }
        if let Some(ref tok) = explicit_tok {
            node.token = Some(tok.clone());
            continue;
        }
        if !is_loopback_host(&node.target.host) {
            continue;
        }
        if let Some(dev_tokens) = resolve_dev_auth_token_for_dir(
            state_dir,
            Some(&node.name),
            "participant_admin",
            Some(&node.target.base_url),
            CLI_AUTO_DEV_JWT_TTL_SECS,
        )
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?
        {
            node.token = Some(dev_tokens.admin_token);
        }
    }
    Ok(())
}

/// Pauses command/submission acceptance across every reachable node and waits up to `timeout`
/// for all in-flight operations to drain to `0`. On timeout, resumes all paused nodes and exits `3`.
pub fn quiesce_and_drain(nodes: &[ControlNode], timeout: Duration) -> Result<(), String> {
    if nodes.is_empty() {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            "cannot snapshot: no active control endpoints discovered",
        ));
    }
    let mut paused: Vec<&ControlNode> = Vec::new();
    for node in nodes {
        match json_http::call_with_token(
            &node.target.host,
            node.target.port,
            "POST",
            "/_quiesce/pause",
            None,
            node.token.as_deref(),
        ) {
            Ok((200, _)) => {
                paused.push(node);
            }
            Ok((status, body)) => {
                resume_all(&paused);
                return Err(exit_with_message(
                    EXIT_MISMATCH,
                    format!(
                        "quiesce failed on {} ({}): HTTP {status}: {}",
                        node.name,
                        node.target.base_url,
                        json_http::error_cause(&body)
                    ),
                ));
            }
            Err(err) => {
                resume_all(&paused);
                return Err(exit_with_message(
                    EXIT_MISMATCH,
                    format!("quiesce failed on {}: {err}", node.name),
                ));
            }
        }
    }

    let deadline = Instant::now() + timeout;
    loop {
        let mut total_in_flight = 0u64;
        let mut details = Vec::new();
        for node in nodes {
            match query_in_flight(&node.target, node.token.as_deref()) {
                Ok(n) => {
                    total_in_flight = total_in_flight.saturating_add(n);
                    if n > 0 {
                        details.push(format!("{}={n}", node.name));
                    }
                }
                Err(err) => {
                    resume_all(&paused);
                    return Err(exit_with_message(
                        EXIT_MISMATCH,
                        format!("failed polling quiesce status on {}: {err}", node.name),
                    ));
                }
            }
        }
        if total_in_flight == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            resume_all(&paused);
            return Err(exit_with_message(
                EXIT_MISMATCH,
                format!(
                    "quiesce timed out after {}s with in-flight work remaining ({})",
                    timeout.as_secs(),
                    details.join(", ")
                ),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Best-effort resume sent to every paused node when quiesce/drain aborts.
pub fn resume_all(nodes: &[&ControlNode]) {
    for node in nodes {
        let _ = json_http::call_with_token(
            &node.target.host,
            node.target.port,
            "POST",
            "/_quiesce/resume",
            None,
            node.token.as_deref(),
        );
    }
}

fn query_in_flight(ep: &EndpointTarget, token: Option<&str>) -> Result<u64, String> {
    let (status, resp) =
        json_http::call_with_token(&ep.host, ep.port, "GET", "/_quiesce", None, token)?;
    if status != 200 {
        return Err(format!(
            "GET {}/_quiesce returned HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    }
    resp.get("in_flight")
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("missing 'in_flight' counter in /_quiesce response: {resp}"))
}

/// Captures participant `ledgerEnd` offsets and node cryptographic IDs while quiesced before shutdown.
pub fn collect_live_expectations(
    state_dir: &Path,
    nodes: &[ControlNode],
) -> Result<LiveExpectations, String> {
    let mut out = LiveExpectations::default();
    for node in nodes {
        match node.role {
            ControlRole::Participant => {
                let end = fetch_participant_ledger_end(&node.target, node.token.as_deref())?;
                out.ledger_ends.insert(node.name.clone(), end);
                let pid = fetch_participant_id(&node.target, node.token.as_deref())?;
                out.node_identities.insert(node.name.clone(), pid);
            }
            ControlRole::Mediator => {
                let uid = fetch_status_str(&node.target, "member")?;
                out.node_identities.insert(node.name.clone(), uid);
            }
            ControlRole::Sequencer => {
                let phys = fetch_status_str(&node.target, "physical_synchronizer_id")?;
                out.node_identities.insert(node.name.clone(), phys);
            }
        }
    }
    let scan_path = state_dir.join("scan-history.jsonl");
    if scan_path.is_file() {
        let raw = std::fs::read_to_string(&scan_path)
            .map_err(|e| format!("read {}: {e}", scan_path.display()))?;
        let count = raw.lines().filter(|l| !l.trim().is_empty()).count();
        out.scan_history_lines = Some(count);
    }
    Ok(out)
}

/// Verifies every participant's restored `ledgerEnd` matches `expected_ledger_ends` (`exit=3` on drift).
pub fn verify_restored_ledger_ends(
    nodes: &[ControlNode],
    expected_ledger_ends: &BTreeMap<String, u64>,
) -> Result<(), String> {
    for (name, expected_end) in expected_ledger_ends {
        let node = nodes
            .iter()
            .find(|n| n.role == ControlRole::Participant && &n.name == name)
            .ok_or_else(|| {
                exit_with_message(
                    EXIT_MISMATCH,
                    format!("participant '{name}' missing after restore"),
                )
            })?;
        let actual_end = fetch_participant_ledger_end(&node.target, node.token.as_deref())
            .map_err(|e| exit_with_message(EXIT_MISMATCH, e))?;
        if actual_end != *expected_end {
            return Err(exit_with_message(
                EXIT_MISMATCH,
                format!(
                    "participant '{name}' ledger_end mismatch after restore: expected {expected_end}, got {actual_end}"
                ),
            ));
        }
    }
    Ok(())
}

/// Verifies sequencer, mediator, and participant identities match the snapshot manifest (`exit=3` on drift).
pub fn verify_restored_node_identities(
    nodes: &[ControlNode],
    expected_identities: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (name, expected_id) in expected_identities {
        let node = nodes.iter().find(|n| &n.name == name).ok_or_else(|| {
            exit_with_message(
                EXIT_MISMATCH,
                format!("node '{name}' missing after restore"),
            )
        })?;
        let actual_id = match node.role {
            ControlRole::Participant => fetch_participant_id(&node.target, node.token.as_deref()),
            ControlRole::Mediator => fetch_status_str(&node.target, "member"),
            ControlRole::Sequencer => fetch_status_str(&node.target, "physical_synchronizer_id"),
        }
        .map_err(|e| exit_with_message(EXIT_MISMATCH, e))?;
        if &actual_id != expected_id {
            return Err(exit_with_message(
                EXIT_MISMATCH,
                format!(
                    "node '{name}' identity mismatch after restore: expected '{expected_id}', got '{actual_id}'"
                ),
            ));
        }
    }
    Ok(())
}

/// Verifies `scan-history.jsonl` line count matches when scan history was part of the snapshot.
pub fn verify_scan_history(state_dir: &Path, expected_lines: Option<usize>) -> Result<(), String> {
    let Some(expected) = expected_lines else {
        return Ok(());
    };
    let scan_path = state_dir.join("scan-history.jsonl");
    if !scan_path.is_file() {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!("scan-history.jsonl missing at {}", scan_path.display()),
        ));
    }
    let raw = std::fs::read_to_string(&scan_path).map_err(|e| {
        exit_with_message(EXIT_MISMATCH, format!("read {}: {e}", scan_path.display()))
    })?;
    let actual = raw.lines().filter(|l| !l.trim().is_empty()).count();
    if actual != expected {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!("scan-history.jsonl line count mismatch: expected {expected}, got {actual}"),
        ));
    }
    Ok(())
}

fn fetch_participant_ledger_end(ep: &EndpointTarget, token: Option<&str>) -> Result<u64, String> {
    let (status, body) = json_http::call_with_token(
        &ep.host,
        ep.port,
        "GET",
        "/v2/state/ledger-end",
        None,
        token,
    )?;
    if status != 200 {
        return Err(format!(
            "GET {}/v2/state/ledger-end failed HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&body)
        ));
    }
    body.get("offset")
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("missing 'offset' in /v2/state/ledger-end: {body}"))
}

fn fetch_participant_id(ep: &EndpointTarget, token: Option<&str>) -> Result<String, String> {
    let (status, body) = json_http::call_with_token(
        &ep.host,
        ep.port,
        "GET",
        "/v2/parties/participant-id",
        None,
        token,
    )?;
    if status != 200 {
        return Err(format!(
            "GET {}/v2/parties/participant-id failed HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&body)
        ));
    }
    body.get("participantId")
        .and_then(Json::as_str)
        .map(String::from)
        .ok_or_else(|| format!("missing 'participantId' in /v2/parties/participant-id: {body}"))
}

fn fetch_status_str(ep: &EndpointTarget, field: &str) -> Result<String, String> {
    let (status, body) = json_http::call(&ep.host, ep.port, "GET", "/status", None)?;
    if status != 200 {
        return Err(format!(
            "GET {}/status failed HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&body)
        ));
    }
    body.get(field)
        .and_then(Json::as_str)
        .map(String::from)
        .ok_or_else(|| format!("missing '{field}' in /status: {body}"))
}
