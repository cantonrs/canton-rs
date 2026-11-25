//! Command deduplication: the deduplication period of a submission, the change ids accepted inside it (`DUPLICATE_COMMAND`), and the
//! change ids whose submission still runs (`SUBMISSION_ALREADY_IN_FLIGHT`).
//!
//! [CANTON-NOTE: SEMANTICS] Canton registers a submission in flight (`InFlightSubmissionTracker.register`) before it deduplicates
//! it, so of two concurrent submissions of one change id only one passes; the other gets `SubmissionAlreadyInFlight`. Here the
//! check against the accepted change ids and the in-flight registration happen under one lock ([`reserve`]), and the registration
//! ends when the outcome is recorded ([`record`]), or when the submission failed. A submission whose API wait ended first
//! (`REQUEST_TIME_OUT`) stays registered ([`Reservation::keep_in_flight`]) until its late fate is recorded (`protocol_late`).
//!
//! [CANTON-NOTE: LIMITATION] The registrations are in memory: after a restart a submission the node still has in flight is not
//! seen here, and a resubmission of its change id is judged by the accepted change ids alone.
use std::collections::BTreeSet;
use std::sync::Mutex;

use serde_json::{json, Value as Json};

use crate::http::HttpResponse;
use crate::service::ExecutionService;
use crate::v2::V2State;
use crate::v2_commands::{canton_error, unix_micros_now, Kind, SYNCHRONIZER};

/// `(user id, command id, act-as parties sorted)`: Canton's `ChangeId`.
pub(crate) type ChangeId = (String, String, Vec<String>);

/// The change ids whose submission is in flight.
pub(crate) type InFlightChanges = Mutex<BTreeSet<ChangeId>>;

/// `CommandsValidator.validateDeduplicationPeriod`: a duration must not be negative, an offset must not be negative.
pub(crate) fn validate_period(period: Option<&Json>) -> Result<(), HttpResponse> {
    let Some(period) = period else {
        return Ok(());
    };
    if let Some(d) = period.pointer("/DeduplicationDuration/value") {
        let secs = d["seconds"].as_i64().unwrap_or(0);
        let nanos = d["nanos"].as_i64().unwrap_or(0);
        if secs < 0 || (secs == 0 && nanos < 0) {
            return Err(canton_error(
                Kind::RequestCorrelated,
                400,
                "INVALID_FIELD",
                "The submitted command has a field with invalid value: Invalid field deduplication_period: Duration must be positive".into(),
                8,
                3,
                json!([]),
            ));
        }
    }
    if let Some(offset) = period
        .pointer("/DeduplicationOffset/value")
        .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
        .filter(|o| *o < 0)
    {
        return Err(canton_error(
            Kind::BadOffset,
            400,
            "NEGATIVE_OFFSET",
            format!("Offset {offset} in deduplication_period is a negative integer: the deduplication offset has to be a non-negative integer and not {offset}"),
            8,
            3,
            json!([]),
        ));
    }
    Ok(())
}

/// A change id registered in flight by [`reserve`]; dropping it ends the registration.
pub(crate) struct Reservation<'a> {
    state: &'a V2State,
    key: Option<ChangeId>,
}

impl Reservation<'_> {
    pub(crate) fn key(&self) -> ChangeId {
        self.key.clone().unwrap_or_default()
    }

    /// The submission stays in flight after this request ends: its late fate ends the registration ([`release`]).
    pub(crate) fn keep_in_flight(mut self) {
        self.key = None;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            release(self.state, &key);
        }
    }
}

/// Ends the in-flight registration of `key`.
pub(crate) fn release(state: &V2State, key: &ChangeId) {
    state
        .in_flight
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(key);
}

/// Refuses `(user_id, command_id, act_as)` when an accepted command of that change id is inside the deduplication period (`409
/// DUPLICATE_COMMAND`) or a submission of it is in flight (`409 SUBMISSION_ALREADY_IN_FLIGHT`); else registers it in flight.
pub(crate) fn reserve<'a>(
    service: &'a ExecutionService,
    user_id: &str,
    command_id: &str,
    act_as: &[String],
    dedup_period: Option<&Json>,
) -> Result<Reservation<'a>, HttpResponse> {
    let state = service.v2_state();
    let mut act_sorted = act_as.to_vec();
    act_sorted.sort();
    let key: ChangeId = (user_id.to_string(), command_id.to_string(), act_sorted);
    let dedup = state
        .dedup
        .lock()
        .map_err(|_| HttpResponse::error_json(500, "the deduplication table is poisoned"))?;
    if let Some((offset, at, existing)) = dedup.get(&key) {
        if inside_period(state, dedup_period, *offset, *at) {
            return Err(duplicate(&key, *offset, existing));
        }
    }
    let mut in_flight = state
        .in_flight
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !in_flight.insert(key.clone()) {
        return Err(already_in_flight(&key));
    }
    Ok(Reservation {
        state,
        key: Some(key),
    })
}

/// [CANTON-NOTE: SEMANTICS] Measured on the node (AT-T03): the period is a duration back from now, an offset (the earlier command
/// counts when its completion is after that offset), or, when absent, the maximum deduplication duration.
fn inside_period(state: &V2State, period: Option<&Json>, offset: u64, at: i64) -> bool {
    let age = unix_micros_now() - at;
    if let Some(v) = period.and_then(|p| p.pointer("/DeduplicationOffset/value")) {
        let from = v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0);
        return offset > from;
    }
    if let Some(d) = period.and_then(|p| p.pointer("/DeduplicationDuration/value")) {
        let secs = d["seconds"].as_i64().unwrap_or(0);
        let nanos = d["nanos"].as_i64().unwrap_or(0);
        return age <= secs * 1_000_000 + nanos / 1_000;
    }
    age <= state
        .max_dedup_micros
        .load(std::sync::atomic::Ordering::SeqCst)
}

fn duplicate(key: &ChangeId, offset: u64, existing: &str) -> HttpResponse {
    let (user, cmd, parties) = key;
    HttpResponse::json(
        409,
        &json!({
            "code": "DUPLICATE_COMMAND",
            "cause": "Command submission already exists.",
            "correlationId": Json::Null,
            "traceId": "0000000000000000",
            "context": {
                "accepted": "true",
                "category": "10",
                "changeId": format!("ChangeId({user},{cmd},Set({}))", parties.join(", ")),
                "completion_offset": offset.to_string(),
                "definite_answer": "true",
                "existingSubmissionId": format!("Some({existing})"),
                "participant": "rust",
                "psid": SYNCHRONIZER,
                "tid": "0000000000000000"
            },
            "resources": [],
            "errorCategory": 10,
            "grpcCodeValue": 6,
            "retryInfo": Json::Null,
            "definiteAnswer": Json::Null
        }),
    )
}

/// `TransactionProcessor.SubmissionErrors.SubmissionAlreadyInFlight` (`ConsistencyErrors.SubmissionAlreadyInFlight`, category
/// `ContentionOnSharedResources`: gRPC `ABORTED`, retryable).
fn already_in_flight(key: &ChangeId) -> HttpResponse {
    let (user, cmd, parties) = key;
    HttpResponse::json(
        409,
        &json!({
            "code": "SUBMISSION_ALREADY_IN_FLIGHT",
            "cause": "The submission is already in-flight",
            "correlationId": Json::Null,
            "traceId": "0000000000000000",
            "context": {
                "category": "2",
                "changeId": format!("ChangeId({user},{cmd},Set({}))", parties.join(", ")),
                "definite_answer": "false",
                "existingSubmissionSynchronizerId": SYNCHRONIZER,
                "participant": "rust",
                "tid": "0000000000000000"
            },
            "resources": [],
            "errorCategory": 2,
            "grpcCodeValue": 10,
            "retryInfo": "1 second",
            "definiteAnswer": Json::Null
        }),
    )
}

/// Records the accepted command of `key` at `offset`.
pub(crate) fn record(
    service: &ExecutionService,
    key: ChangeId,
    offset: u64,
    submission_id: String,
) {
    let at = unix_micros_now();
    service.v2_state().journal("dedup.journal", || {
        crate::snapshot::dedup_line(&key, (offset, at, submission_id.as_str()))
    });
    if let Ok(mut m) = service.v2_state().dedup.lock() {
        m.insert(key, (offset, at, submission_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_id_kept_in_flight_is_refused_until_its_fate_releases_it() {
        let service = ExecutionService::new();
        let parties = vec!["alice".to_string()];
        let first = reserve(&service, "u", "c", &parties, None).expect("the first passes");
        let key = first.key();
        first.keep_in_flight();
        let refused = reserve(&service, "u", "c", &parties, None)
            .err()
            .expect("the same change id is in flight");
        assert_eq!(refused.status, 409);
        let body: Json = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(body["code"], "SUBMISSION_ALREADY_IN_FLIGHT");
        assert_eq!(body["grpcCodeValue"], 10);
        release(service.v2_state(), &key);
        assert!(reserve(&service, "u", "c", &parties, None).is_ok());
    }
}
