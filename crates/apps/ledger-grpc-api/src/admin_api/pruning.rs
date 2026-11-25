//! Participant Admin `PruningService` gRPC handlers (`Prune`, `GetSafePruningOffset`).

use std::collections::HashMap;

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use ledger_json_api::{dispatch_request, v2_prune, ExecutionService, HttpRequest};
use prost_reflect::{DynamicMessage, MethodDescriptor};
use serde_json::json;
use tonic::Status;

use crate::server::status_of;

use super::{decode_typed, encode_typed};

fn ignore_commitments(commitment_state: Option<i32>) -> bool {
    commitment_state == Some(p30::SafeToPruneCommitmentState::All as i32)
}

/// Dispatches unary `com.digitalasset.canton.admin.participant.v30.PruningService` RPCs.
///
/// `authorization` is the caller's token: `Prune` runs as the JSON API's `/v2/admin/prune` (so that it is written to the request log
/// like any other change), which authenticates the call again.
pub fn handle_pruning_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    authorization: Option<&str>,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.parent_service().full_name()
        != "com.digitalasset.canton.admin.participant.v30.PruningService"
    {
        return None;
    }
    match method.name() {
        "Prune" => Some((|| {
            let req: p30::PruneRequest = decode_typed(request)?;
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            if let Some(a) = authorization {
                headers.insert("authorization".to_string(), a.to_string());
            }
            let body = serde_json::to_vec(&json!({
                "pruneUpTo": req.prune_up_to,
                "ignoreCommitments": ignore_commitments(req.counter_participants_commitments_state),
            }))
            .map_err(|e| Status::internal(e.to_string()))?;
            let resp = dispatch_request(
                ledger,
                &HttpRequest {
                    method: "POST".to_string(),
                    path: "/v2/admin/prune".to_string(),
                    query_params: HashMap::new(),
                    headers,
                    body,
                },
            );
            if resp.status >= 400 {
                return Err(status_of(resp.status, &resp.body));
            }
            Ok(vec![encode_typed(method, &p30::PruneResponse {})?])
        })()),
        "GetSafePruningOffset" => Some((|| {
            let req: p30::GetSafePruningOffsetRequest = decode_typed(request)?;
            let before_or_at_micros = req.before_or_at.map(|ts| {
                ts.seconds
                    .saturating_mul(1_000_000)
                    .saturating_add(i64::from(ts.nanos) / 1_000)
            });
            let safe = v2_prune::safe_pruning_offset(
                ledger,
                before_or_at_micros,
                req.ledger_end,
                ignore_commitments(req.counter_participants_commitments_state),
            )
            .map_err(Status::invalid_argument)?;
            let response = match safe {
                Some(offset) => {
                    p30::get_safe_pruning_offset_response::Response::SafePruningOffset(offset)
                }
                None => p30::get_safe_pruning_offset_response::Response::NoSafePruningOffset(
                    p30::get_safe_pruning_offset_response::NoSafePruningOffset {},
                ),
            };
            Ok(vec![encode_typed(
                method,
                &p30::GetSafePruningOffsetResponse {
                    response: Some(response),
                },
            )?])
        })()),
        _ => None,
    }
}
