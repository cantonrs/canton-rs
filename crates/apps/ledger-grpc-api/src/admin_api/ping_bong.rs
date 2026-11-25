//! `com.digitalasset.canton.admin.participant.v30.PingService/Ping` handler & built-in Nanobot responder
//! supporting both single-target 0-level `Ping` and multi-target / multi-level `Bong` explode-collapse workflows.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use ledger_json_api::{
    admin_state::format_rfc3339_micros,
    clock::now_micros,
    service::GenericContract,
    v2_packages::{load_builtin_ping_dar, ADMIN_PING_PACKAGE_ID},
    ExecutionService, HttpRequest,
};
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::Status;

use super::{decode_typed, encode_typed, map_admin_err};

pub const BUILTIN_PING_DAR: &[u8] =
    include_bytes!("../../assets/canton-builtin-admin-workflow-ping.dar");
const MAX_BONG_LEVEL: u32 = 10;
static PING_SEQ: AtomicU64 = AtomicU64::new(1);

struct NanobotEntry {
    service: Weak<ExecutionService>,
    vetted_committer: bool,
}

static NANOBOT_REGISTRY: OnceLock<Mutex<Vec<NanobotEntry>>> = OnceLock::new();
static BONG_WINNERS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn nanobot_registry() -> &'static Mutex<Vec<NanobotEntry>> {
    NANOBOT_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn bong_winners() -> &'static Mutex<HashMap<String, String>> {
    BONG_WINNERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn logical_sync_id(s: &str) -> &str {
    match s.split_once("::") {
        Some((name, rest)) => match rest.split_once("::") {
            Some((fp, _)) => &s[..name.len() + 2 + fp.len()],
            None => s,
        },
        None => s,
    }
}

fn ping_failure(
    method: &MethodDescriptor,
    reason: impl Into<String>,
) -> Result<DynamicMessage, Status> {
    encode_typed(
        method,
        &p30::PingResponse {
            response: Some(p30::ping_response::Response::Failure(p30::PingFailure {
                reason: reason.into(),
            })),
        },
    )
}

fn str_field<'a>(c: &'a GenericContract, field: &str) -> Option<&'a str> {
    c.json_payload.get(field).and_then(|v| v.as_str())
}

fn party_list_field(c: &GenericContract, field: &str) -> Vec<String> {
    c.json_payload
        .get(field)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn first_local_in(service: &ExecutionService, candidates: &[String]) -> Option<String> {
    candidates
        .iter()
        .find(|p| service.is_local_ping_responder(p))
        .cloned()
}

struct ExerciseSpec<'a> {
    cmd_prefix: &'a str,
    template_id: &'a str,
    contract_id: &'a str,
    choice: &'a str,
    arg: serde_json::Value,
    act_as: &'a str,
}

fn submit_exercise(
    service: &ExecutionService,
    spec: ExerciseSpec<'_>,
    attempts: &mut HashMap<String, (u32, Instant)>,
    now: Instant,
) -> bool {
    if let Some((count, last)) = attempts.get(spec.contract_id) {
        if *count >= 5 || now.duration_since(*last) < Duration::from_millis(80) {
            return false;
        }
    }
    let seq = PING_SEQ.fetch_add(1, Ordering::Relaxed);
    let body = serde_json::json!({
        "commands": [{
            "ExerciseCommand": {
                "templateId": spec.template_id,
                "contractId": spec.contract_id,
                "choice": spec.choice,
                "choiceArgument": spec.arg,
            }
        }],
        "commandId": format!("{}-{}-{}", spec.cmd_prefix, seq, spec.contract_id),
        "actAs": [spec.act_as],
        "userId": "canton-admin-ping",
    });
    let req = HttpRequest {
        method: "POST".into(),
        path: "/v2/commands/submit-and-wait".into(),
        query_params: Default::default(),
        headers: [("content-type".into(), "application/json".into())].into(),
        body: serde_json::to_vec(&body).unwrap_or_default(),
    };
    let resp = ledger_json_api::route_internal(service, &req);
    if resp.status < 300 {
        attempts.insert(spec.contract_id.to_string(), (u32::MAX, now));
        true
    } else {
        let entry = attempts
            .entry(spec.contract_id.to_string())
            .or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
        false
    }
}

fn run_nanobot_step(service: &ExecutionService, attempts: &mut HashMap<String, (u32, Instant)>) {
    let now = Instant::now();
    let active = service.v2_active_contracts();
    let active_ids: HashSet<&str> = active.iter().map(|c| c.contract_id.as_str()).collect();
    attempts.retain(|cid, _| active_ids.contains(cid.as_str()));

    let ping_tpl = format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Ping:Ping");
    let proposal_tpl = format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Bong:BongProposal");
    let explode_tpl = format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Bong:Explode");
    let merge_tpl = format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Bong:Merge");
    let bong_tpl = format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Bong:Bong");

    // Pre-index active Collapse contracts by `(id, path)` so Merge matches pairs in O(1).
    let mut collapses: HashMap<(String, String), Vec<String>> = HashMap::new();
    for c in &active {
        if c.package_id == ADMIN_PING_PACKAGE_ID
            && c.template_id.module_name == "Canton.Internal.Bong"
            && c.template_id.entity_name == "Collapse"
        {
            if let (Some(id), Some(path)) = (str_field(c, "id"), str_field(c, "path")) {
                collapses
                    .entry((id.to_string(), path.to_string()))
                    .or_default()
                    .push(c.contract_id.clone());
            }
        }
    }

    for c in &active {
        if c.package_id != ADMIN_PING_PACKAGE_ID {
            continue;
        }
        match (
            c.template_id.module_name.as_str(),
            c.template_id.entity_name.as_str(),
        ) {
            ("Canton.Internal.Ping", "Ping") => {
                let Some(responder) = str_field(c, "responder") else {
                    continue;
                };
                if service.is_local_ping_responder(responder) {
                    submit_exercise(
                        service,
                        ExerciseSpec {
                            cmd_prefix: "ping-respond",
                            template_id: &ping_tpl,
                            contract_id: &c.contract_id,
                            choice: "Respond",
                            arg: serde_json::json!({}),
                            act_as: responder,
                        },
                        attempts,
                        now,
                    );
                }
            }
            ("Canton.Internal.Bong", "BongProposal") => {
                let candidates = party_list_field(c, "candidates");
                if let Some(validator) = first_local_in(service, &candidates) {
                    submit_exercise(
                        service,
                        ExerciseSpec {
                            cmd_prefix: "bong-accept",
                            template_id: &proposal_tpl,
                            contract_id: &c.contract_id,
                            choice: "Accept",
                            arg: serde_json::json!({ "validator": validator }),
                            act_as: &validator,
                        },
                        attempts,
                        now,
                    );
                }
            }
            ("Canton.Internal.Bong", "Explode") => {
                let responders = party_list_field(c, "responders");
                if let Some(winner) = first_local_in(service, &responders) {
                    submit_exercise(
                        service,
                        ExerciseSpec {
                            cmd_prefix: "bong-explode",
                            template_id: &explode_tpl,
                            contract_id: &c.contract_id,
                            choice: "ProcessExplode",
                            arg: serde_json::json!({ "winner": winner }),
                            act_as: &winner,
                        },
                        attempts,
                        now,
                    );
                }
            }
            ("Canton.Internal.Bong", "Merge") => {
                let (Some(id), Some(path)) = (str_field(c, "id"), str_field(c, "path")) else {
                    continue;
                };
                let Some(pair) = collapses.get(&(id.to_string(), path.to_string())) else {
                    continue;
                };
                if pair.len() < 2 {
                    continue;
                }
                let responders = party_list_field(c, "responders");
                if let Some(winner) = first_local_in(service, &responders) {
                    submit_exercise(
                        service,
                        ExerciseSpec {
                            cmd_prefix: "bong-merge",
                            template_id: &merge_tpl,
                            contract_id: &c.contract_id,
                            choice: "ProcessMerge",
                            arg: serde_json::json!({
                                "winner": winner,
                                "leftId": pair[0],
                                "rightId": pair[1],
                            }),
                            act_as: &winner,
                        },
                        attempts,
                        now,
                    );
                }
            }
            ("Canton.Internal.Bong", "Bong") => {
                let (Some(id), Some(initiator), Some(responder)) = (
                    str_field(c, "id"),
                    str_field(c, "initiator"),
                    str_field(c, "responder"),
                ) else {
                    continue;
                };
                if service.is_local_ping_responder(initiator)
                    && submit_exercise(
                        service,
                        ExerciseSpec {
                            cmd_prefix: "bong-ack",
                            template_id: &bong_tpl,
                            contract_id: &c.contract_id,
                            choice: "Ack",
                            arg: serde_json::json!({}),
                            act_as: initiator,
                        },
                        attempts,
                        now,
                    )
                {
                    if let Ok(mut w) = bong_winners().lock() {
                        w.insert(id.to_string(), responder.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

fn run_nanobot_loop(weak: Weak<ExecutionService>) {
    let mut attempts: HashMap<String, (u32, Instant)> = HashMap::new();
    while let Some(service) = weak.upgrade() {
        run_nanobot_step(&service, &mut attempts);
        drop(service);
        std::thread::sleep(Duration::from_millis(20));
    }

    if let Ok(mut entries) = nanobot_registry().lock() {
        entries.retain(|e| e.service.strong_count() > 0);
    }
}

/// Ensures the built-in admin Ping DAR is loaded/vetted and one background Nanobot responder is running for `ledger`.
pub fn ensure_ping_workflow(ledger: &Arc<ExecutionService>) -> Result<(), Status> {
    load_builtin_ping_dar(ledger, BUILTIN_PING_DAR).map_err(map_admin_err)?;

    let (need_spawn, need_vet) = {
        let mut entries = nanobot_registry()
            .lock()
            .map_err(|_| Status::internal("nanobot registry lock poisoned"))?;
        entries.retain(|e| e.service.strong_count() > 0);
        let ptr = Arc::as_ptr(ledger);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| std::ptr::eq(e.service.as_ptr(), ptr))
        {
            let need_vet = !entry.vetted_committer && ledger.has_committer();
            (false, need_vet)
        } else {
            let has_c = ledger.has_committer();
            entries.push(NanobotEntry {
                service: Arc::downgrade(ledger),
                vetted_committer: false,
            });
            (true, has_c)
        }
    };

    if need_vet {
        ledger
            .vet_dar(BUILTIN_PING_DAR)
            .map_err(|e| Status::internal(format!("failed to vet built-in ping DAR: {e}")))?;
        if let Ok(mut entries) = nanobot_registry().lock() {
            let ptr = Arc::as_ptr(ledger);
            if let Some(entry) = entries
                .iter_mut()
                .find(|e| std::ptr::eq(e.service.as_ptr(), ptr))
            {
                entry.vetted_committer = true;
            }
        }
    }

    if need_spawn {
        let weak = Arc::downgrade(ledger);
        std::thread::Builder::new()
            .name("admin-ping-nanobot".into())
            .spawn(move || run_nanobot_loop(weak))
            .map_err(|e| Status::internal(format!("failed to start ping nanobot: {e}")))?;
    }

    Ok(())
}

fn parse_ping_timeout(req: &p30::PingRequest) -> Result<Duration, Status> {
    let Some(timeout_proto) = req.timeout else {
        return Err(Status::invalid_argument(
            "PROTO_DESERIALIZATION_ERROR: FieldNotSet(timeout)",
        ));
    };
    if timeout_proto.seconds < 0 || timeout_proto.nanos < 0 || timeout_proto.nanos >= 1_000_000_000
    {
        return Err(Status::invalid_argument(
            "PROTO_DESERIALIZATION_ERROR: timeout must be a valid non-negative duration",
        ));
    }
    Ok(Duration::from_secs(timeout_proto.seconds as u64)
        + Duration::from_nanos(timeout_proto.nanos as u64))
}

/// Handles `com.digitalasset.canton.admin.participant.v30.PingService/Ping`.
pub async fn handle_ping(
    ledger: &Arc<ExecutionService>,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Result<DynamicMessage, Status> {
    let req: p30::PingRequest = decode_typed(request)?;
    let timeout = parse_ping_timeout(&req)?;

    if req.target_parties.is_empty() {
        return ping_failure(method, "No target parties specified for ping");
    }
    if req.levels > MAX_BONG_LEVEL {
        return ping_failure(
            method,
            format!(
                "Max level {} exceeds supported max level {}",
                req.levels, MAX_BONG_LEVEL
            ),
        );
    }

    if !req.synchronizer_id.is_empty() {
        let req_logical = logical_sync_id(&req.synchronizer_id);
        let connected = ledger.connected_synchronizers();
        let matched = connected
            .iter()
            .any(|(_, id)| id == &req.synchronizer_id || logical_sync_id(id) == req_logical);
        if !matched {
            return ping_failure(
                method,
                format!(
                    "Unknown or disconnected synchronizer '{}'",
                    req.synchronizer_id
                ),
            );
        }
    }

    let ledger_setup = Arc::clone(ledger);
    tokio::task::spawn_blocking(move || ensure_ping_workflow(&ledger_setup))
        .await
        .map_err(|e| Status::internal(format!("ping setup task panicked: {e}")))??;

    let initiator = ledger.participant_id();
    let seq = PING_SEQ.fetch_add(1, Ordering::Relaxed);
    let ping_id = if req.id.is_empty() {
        format!("ping-{}-{seq}", std::process::id())
    } else {
        req.id.clone()
    };

    let use_simple_ping =
        req.validators.is_empty() && req.target_parties.len() == 1 && req.levels == 0;

    let start = Instant::now();
    let (template_id, create_arguments) = if use_simple_ping {
        (
            format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Ping:Ping"),
            serde_json::json!({
                "id": ping_id,
                "initiator": initiator,
                "responder": req.target_parties[0],
            }),
        )
    } else {
        let candidates = if req.validators.is_empty() {
            vec![initiator.clone()]
        } else {
            req.validators.clone()
        };
        let expires_micros = now_micros().saturating_add(timeout.as_micros() as i64);
        (
            format!("{ADMIN_PING_PACKAGE_ID}:Canton.Internal.Bong:BongProposal"),
            serde_json::json!({
                "id": ping_id,
                "initiator": initiator,
                "candidates": candidates,
                "validators": [],
                "responders": req.target_parties,
                "maxLevel": req.levels as i64,
                "timeout": format_rfc3339_micros(expires_micros),
            }),
        )
    };

    let create_body = serde_json::json!({
        "commands": {
            "commands": [{
                "CreateCommand": {
                    "templateId": template_id,
                    "createArguments": create_arguments,
                }
            }],
            "commandId": format!("ping-create-{seq}-{ping_id}"),
            "actAs": [initiator],
            "workflowId": req.workflow_id,
            "userId": "canton-admin-ping",
        }
    });
    let http_req = HttpRequest {
        method: "POST".into(),
        path: "/v2/commands/submit-and-wait-for-transaction".into(),
        query_params: Default::default(),
        headers: [("content-type".into(), "application/json".into())].into(),
        body: serde_json::to_vec(&create_body).unwrap_or_default(),
    };
    let ledger_exec = Arc::clone(ledger);
    let resp = tokio::task::spawn_blocking(move || {
        ledger_json_api::route_internal(&ledger_exec, &http_req)
    })
    .await
    .map_err(|e| Status::internal(format!("ping create task panicked: {e}")))?;
    if resp.status >= 400 {
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
        let cause = parsed
            .get("cause")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| String::from_utf8_lossy(&resp.body).into_owned());
        return ping_failure(method, format!("Failed to initiate ping: {cause}"));
    }

    let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    let contract_id = parsed
        .pointer("/transaction/events")
        .and_then(|v| v.as_array())
        .and_then(|events| {
            events.iter().find_map(|ev| {
                ev.pointer("/CreatedEvent/contractId")
                    .or_else(|| ev.pointer("/createdEvent/contractId"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
        });
    let Some(contract_id) = contract_id else {
        return ping_failure(
            method,
            "Ping creation did not produce a CreatedEvent contractId",
        );
    };

    let deadline = start + timeout;
    loop {
        if use_simple_ping {
            if ledger.v2_contract(&contract_id).is_some_and(|c| !c.active) {
                let ping_time = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
                return encode_typed(
                    method,
                    &p30::PingResponse {
                        response: Some(p30::ping_response::Response::Success(p30::PingSuccess {
                            ping_time,
                            responder: req.target_parties[0].clone(),
                        })),
                    },
                );
            }
        } else if let Some(responder) = bong_winners()
            .lock()
            .ok()
            .and_then(|mut w| w.remove(&ping_id))
        {
            let ping_time = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            return encode_typed(
                method,
                &p30::PingResponse {
                    response: Some(p30::ping_response::Response::Success(p30::PingSuccess {
                        ping_time,
                        responder,
                    })),
                },
            );
        }
        if Instant::now() >= deadline {
            return ping_failure(
                method,
                "Timeout: We were able to create the ping contract, but responder did not respond in time",
            );
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}
