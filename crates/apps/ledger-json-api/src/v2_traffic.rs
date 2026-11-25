//! Traffic enforcement endpoints (`/v2/traffic/accounts`, `/v2/traffic/prune`, `/v2/traffic/events/prune`),
//! gated behind `traffic_enforcement_enabled()` (disabled by default in sandbox mode to match Canton 3.7.2).

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use serde_json::{json, Value as Json};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;
use crate::v2_commands::{bad_body, canton_error, Kind};
use crate::v2_updates::parse_micros;

/// In-memory traffic enforcement state attached to [`crate::v2::V2State`].
#[derive(Default, Clone, Debug)]
pub struct TrafficState {
    pub accounts: BTreeMap<String, i64>,
    /// `deduplicationId -> recorded_micros` correlations.
    pub correlations: BTreeMap<String, i64>,
    /// Recorded account update timestamps (microseconds).
    pub events: Vec<i64>,
}

/// `GET /v2/traffic/accounts/{account-id}`.
pub fn get_account(service: &ExecutionService, account_id: &str) -> HttpResponse {
    if account_id.is_empty() {
        return bad_body("Invalid value for: account-id".into());
    }
    let balance = service
        .v2_state()
        .traffic
        .lock()
        .ok()
        .and_then(|t| t.accounts.get(account_id).copied())
        .unwrap_or(0);
    HttpResponse::json(200, &json!({ "accountId": account_id, "balance": balance }))
}

/// `POST /v2/traffic/accounts`.
pub fn update_account(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".into());
    };
    let Some(account_id) = body
        .get("accountId")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return bad_body("Invalid value for: body (Missing required field at 'accountId')".into());
    };
    let Some(dedup_id) = body
        .get("deduplicationId")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return bad_body(
            "Invalid value for: body (Missing required field at 'deduplicationId')".into(),
        );
    };
    let delta = body.get("balanceDelta").and_then(Json::as_i64).unwrap_or(0);
    let Ok(mut traffic) = service.v2_state().traffic.lock() else {
        return canton_error(
            Kind::Request,
            500,
            "INTERNAL",
            "traffic state unavailable".into(),
            13,
            13,
            json!([]),
        );
    };
    let balance = if traffic.correlations.contains_key(dedup_id) {
        traffic.accounts.get(account_id).copied().unwrap_or(0)
    } else {
        let now_micros = crate::clock::now_micros();
        traffic
            .correlations
            .insert(dedup_id.to_string(), now_micros);
        traffic.events.push(now_micros);
        let entry = traffic.accounts.entry(account_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(delta);
        *entry
    };
    HttpResponse::json(
        200,
        &json!({ "response": { "accountId": account_id, "balance": balance } }),
    )
}

/// `POST /v2/traffic/prune` (`include_correlations == true`) and `POST /v2/traffic/events/prune`.
pub fn prune(
    service: &ExecutionService,
    req: &HttpRequest,
    include_correlations: bool,
) -> HttpResponse {
    let Ok(body) = serde_json::from_slice::<Json>(&req.body) else {
        return bad_body("Invalid value for: body".into());
    };
    let Some(before_str) = body.get("beforeOrAt").and_then(Json::as_str) else {
        return bad_body("Invalid value for: body (Missing required field at 'beforeOrAt')".into());
    };
    let Some(before_micros) = parse_micros(before_str) else {
        return bad_body(format!(
            "Invalid value for: body (invalid beforeOrAt timestamp {before_str:?})"
        ));
    };
    let max_dedup = service.v2_state().max_dedup_micros.load(Ordering::SeqCst);
    let now_micros = crate::clock::now_micros();
    if before_micros > now_micros.saturating_sub(max_dedup) {
        return canton_error(
            Kind::Request,
            400,
            "TRAFFIC_UNSAFE_TO_PRUNE",
            format!(
                "Cannot prune traffic data up to {before_str}: timestamp is within the participant's maximum deduplication window"
            ),
            9,
            9,
            json!([]),
        );
    }
    let Ok(mut traffic) = service.v2_state().traffic.lock() else {
        return canton_error(
            Kind::Request,
            500,
            "INTERNAL",
            "traffic state unavailable".into(),
            13,
            13,
            json!([]),
        );
    };
    let before_events = traffic.events.len();
    traffic.events.retain(|&ts| ts > before_micros);
    let pruned_events = (before_events - traffic.events.len()) as i32;

    if include_correlations {
        let before_corr = traffic.correlations.len();
        traffic.correlations.retain(|_, &mut ts| ts > before_micros);
        let pruned_correlations = (before_corr - traffic.correlations.len()) as i32;
        HttpResponse::json(
            200,
            &json!({
                "prunedEventCount": pruned_events,
                "prunedCorrelationCount": pruned_correlations
            }),
        )
    } else {
        HttpResponse::json(200, &json!({ "prunedEventCount": pruned_events }))
    }
}
