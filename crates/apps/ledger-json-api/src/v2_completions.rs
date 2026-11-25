//! S-API-009: the completion reads of the JSON API v2 (`/v2/commands/completions`, `.../command-completions`,
//! `.../completion-by-hash`) and the asynchronous submit, checked against the Canton 3.7.2 sandbox by
//! `scripts/verify-json-api.sh`.
//!
//! [CANTON-NOTE: SEMANTICS] The HTTP completion endpoints are blocking reads: they answer with the array of what the
//! ledger holds after `beginExclusive`. `completions` (per user and parties) interleaves `OffsetCheckpoint` items the
//! participant emits on a timer; `command-completions` returns only completions. A completion shows the act-as parties
//! restricted to the requested parties.
use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{canton_error, Kind};

/// A completion of a submission (accepted with `status_code == 0`, or rejected by the synchronizer with non-zero `status_code` and empty `update_id`).
#[derive(Clone)]
pub(crate) struct Completion {
    pub(crate) offset: u64,
    pub(crate) update_id: String,
    pub(crate) command_id: String,
    pub(crate) user_id: String,
    pub(crate) submission_id: String,
    pub(crate) act_as: Vec<String>,
    pub(crate) record_time: String,
    /// Base64-encoded 32-byte `preparedTransactionHash` for externally signed interactive submissions.
    pub(crate) transaction_hash: Option<String>,
    pub(crate) status_code: i32,
    pub(crate) status_message: String,
    /// What the refusing participant's reason added (see `ApiError::SynchronizerRejected::details`): the status's `details` are built from it.
    pub(crate) refusal: Option<String>,
    /// What an official participant recorded of a completion of its history (`--official-pg-url`): shown instead of this service's own values.
    pub(crate) official: Option<Box<OfficialCompletionMeta>>,
    /// The W3C `traceparent` of the submission (see `trace_context`).
    pub(crate) trace_parent: Option<String>,
}

/// The values of a completion adopted from an official participant's database that the service does not make up itself.
#[derive(Clone)]
pub(crate) struct OfficialCompletionMeta {
    pub(crate) deduplication_period: Json,
    pub(crate) trace_parent: Option<String>,
    pub(crate) synchronizer_id: String,
    pub(crate) traffic_cost: i64,
    /// The `details` of the status, decoded from what the participant stored.
    pub(crate) details: Vec<Json>,
}

fn ctx_error(
    status: u16,
    code: &str,
    cause: String,
    category: u64,
    grpc: u64,
    retry: Option<&'static str>,
    resources: Json,
) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: false,
            definite: true,
            field: None,
            retry,
        },
        status,
        code,
        cause,
        category,
        grpc,
        resources,
    )
}

fn completion_value_json(c: &Completion, act_as: Vec<&String>, synchronizer: &str) -> Json {
    json!({
        "commandId": c.command_id,
        "status": { "code": c.status_code, "message": c.status_message, "details": match &c.official {
            Some(o) => o.details.clone(),
            None => crate::v2_commands::refusal_status_details(c.refusal.as_deref(), &c.status_message),
        } },
        "updateId": c.update_id,
        "userId": c.user_id,
        "actAs": act_as,
        "submissionId": c.submission_id,
        "deduplicationPeriod": c.official.as_ref().map_or(json!({ "DeduplicationOffset": { "value": 0 } }), |o| o.deduplication_period.clone()),
        // [CANTON-NOTE: SEMANTICS] a completion of the official history shows the trace context the participant recorded
        "traceContext": crate::trace_context::json(
            c.official.as_ref().map(|o| o.trace_parent.as_deref()),
            c.trace_parent.as_deref(),
        ),
        "offset": c.offset,
        "synchronizerTime": { "synchronizerId": c.official.as_ref().map_or(synchronizer, |o| o.synchronizer_id.as_str()), "recordTime": c.record_time },
        "paidTrafficCost": c.official.as_ref().map_or(0, |o| o.traffic_cost),
        "transactionHash": c.transaction_hash
    })
}

fn completion_json(c: &Completion, act_as: Vec<&String>, synchronizer: &str) -> Json {
    json!({ "completionResponse": { "Completion": { "value": completion_value_json(c, act_as, synchronizer) } } })
}

fn offset_checkpoint(state: &crate::v2::V2State, offset: u64) -> Json {
    json!({ "completionResponse": { "OffsetCheckpoint": { "value": {
        "offset": offset,
        "synchronizerTimes": match state.official_checkpoint() {
            // [CANTON-NOTE: SEMANTICS] on an official database the checkpoint carries the record time each synchronizer has at the ledger end
            Some(times) => times.iter().map(|(id, time)| json!({ "synchronizerId": id, "recordTime": time })).collect::<Vec<_>>(),
            None => vec![json!({ "synchronizerId": state.synchronizer_id(), "recordTime": crate::v2_commands::now_rfc3339() })],
        }
    } } } })
}

/// A completion stream answer holding the `OffsetCheckpoint` at `offset` alone (what a live stream sends once it caught up).
pub fn offset_checkpoint_body(service: &ExecutionService, offset: u64) -> Vec<u8> {
    serde_json::to_vec(&json!([offset_checkpoint(service.v2_state(), offset)])).unwrap_or_default()
}

/// `with_user`: `completions` (needs a user id and parties); otherwise `command-completions`.
pub fn completions(service: &ExecutionService, req: &HttpRequest, with_user: bool) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let parties: Vec<String> = body
        .get("parties")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let user = body.get("userId").and_then(Json::as_str).unwrap_or("");
    if with_user {
        if parties.is_empty() {
            return canton_error(
                Kind::Ctx {
                    submission: false,
                    definite: true,
                    field: Some("parties"),
                    retry: None,
                },
                400,
                "MISSING_FIELD",
                "The submitted command is missing a mandatory field: parties".into(),
                8,
                3,
                json!([]),
            );
        }
        if user.is_empty() {
            return ctx_error(
                400,
                "INVALID_TOKEN",
                "The submitted request is missing a user-id: Cannot default user_id field because claims do not specify an user-id. Is authentication turned on?".into(),
                8,
                3,
                None,
                json!([]),
            );
        }
    }
    let begin = body
        .get("beginExclusive")
        .and_then(|b| b.as_u64().or_else(|| b.as_str()?.parse().ok()))
        .unwrap_or(0);
    let state = service.v2_state();
    let end = state.ledger_end.load(std::sync::atomic::Ordering::SeqCst);
    if begin > end {
        return ctx_error(
            400,
            "OFFSET_AFTER_LEDGER_END",
            format!("Begin offset ({begin}) is after ledger end ({end})"),
            12,
            11,
            Some("1 second"),
            json!([]),
        );
    }
    let pruned = state.pruned_up_to.load(std::sync::atomic::Ordering::SeqCst);
    if begin < pruned {
        return crate::v2_prune::pruned_error(
            format!(
                "Command completions request for offset range [{}, {end}] overlaps with pruned offset {pruned}",
                begin + 1
            ),
            pruned,
            None,
        );
    }
    let limit = match crate::v2_updates::parse_stream_list_limit(req) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let mut out: Vec<Json> = Vec::new();
    let official = state.official_checkpoint().is_some();
    // the participant's timer checkpoint at the start of the stream (measured for beginExclusive 0)
    let checkpoint = (with_user && (begin == 0 || official)).then(|| offset_checkpoint(state, end));
    // [CANTON-NOTE: SEMANTICS] The hub's official participant (a stream over its whole history, measured with `beginExclusive` 0) ends the answer with the
    // checkpoint, after the completions, also when it does not begin at 0 (a read after offset 60 got it too); a fresh ledger shows it first
    // (the measurement above).
    if !official {
        out.extend(checkpoint.clone());
    }
    for c in state.completions().iter().filter(|c| c.offset > begin) {
        if with_user && c.user_id != user {
            continue;
        }
        let shown: Vec<&String> = c
            .act_as
            .iter()
            .filter(|p| parties.is_empty() || parties.contains(p))
            .collect();
        if shown.is_empty() {
            continue;
        }
        out.push(completion_json(c, shown, &state.synchronizer_id()));
    }
    if official {
        out.extend(checkpoint);
    }
    crate::v2_updates::finish_stream_list(service, limit, out)
}

/// `POST /v2/commands/completion-by-hash`: looks up an interactive completion by `transactionHash` (base64 of 32 bytes).
pub fn completion_by_hash(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let body: Json = serde_json::from_slice(&req.body).unwrap_or(Json::Null);
    let Some(hash) = body
        .get("transactionHash")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return ctx_error(
            400,
            "INVALID_ARGUMENT",
            "The submitted request has invalid arguments: Missing field: transaction_hash".into(),
            8,
            3,
            None,
            json!([]),
        );
    };
    let req_bytes = crate::v2::unbase64(hash).unwrap_or_default();
    let req_parties: Vec<String> = body
        .get("parties")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !req_bytes.is_empty() {
        let pruned = service
            .v2_state()
            .pruned_up_to
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut accepted: Option<Json> = None;
        let mut rejected: Vec<Json> = Vec::new();
        for c in service.v2_state().completions().into_iter().rev() {
            if c.offset <= pruned {
                continue;
            }
            let Some(ref stored_b64) = c.transaction_hash else {
                continue;
            };
            if crate::v2::unbase64(stored_b64).as_deref() != Some(req_bytes.as_slice()) {
                continue;
            }
            let shown: Vec<&String> = c
                .act_as
                .iter()
                .filter(|p| req_parties.is_empty() || req_parties.contains(p))
                .collect();
            if shown.is_empty() {
                continue;
            }
            let val = completion_value_json(&c, shown, &service.v2_state().synchronizer_id());
            if c.status_code == 0 {
                if accepted.is_none() {
                    accepted = Some(val);
                }
            } else {
                rejected.push(val);
            }
        }
        if accepted.is_some() || !rejected.is_empty() {
            return HttpResponse::json(
                200,
                &json!({
                    "acceptedCompletion": accepted,
                    "lastRejectedCompletions": rejected
                }),
            );
        }
    }
    // Canton echoes the hash as hex of its base64 decoding (measured)
    let shown: String = req_bytes.iter().map(|b| format!("{b:02x}")).collect();
    ctx_error(
        404,
        "COMPLETION_NOT_FOUND",
        "Completion not found, or not visible.".into(),
        11,
        5,
        None,
        json!([["TRANSACTION_HASH", shown]]),
    )
}
