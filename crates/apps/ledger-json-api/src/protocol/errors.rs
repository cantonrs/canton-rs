use crate::service::ApiError;

/// The JSON API's `INVALID_ARGUMENT` (400, category 8), as the JVM answers a reassignment it refuses before sending (S-NET-040 recording).
pub(super) fn invalid_argument(cause: String) -> ApiError {
    ApiError::SynchronizerRejected {
        code: "INVALID_ARGUMENT".into(),
        cause: format!("The submitted request has invalid arguments: {cause}"),
        grpc_code: 3,
        http_status: 400,
        category: 8,
        details: None,
    }
}

pub(super) fn refuse(why: impl std::fmt::Display) -> ApiError {
    ApiError::Ledger(format!("the protocol committer: {why}"))
}

/// The error a rejecting verdict carried (`Node`'s note `rejected by the verdict: <gRPC code>:<CODE>(<category>,<id>): <cause>`), as the API
/// reports it.
///
/// [CANTON-NOTE: SEMANTICS] The submitting participant reports **the refusing participant's error** for the command, its code, category and
/// cause unchanged (measured, S-G11-001 / U-31: p2 vetoed p1's command and p1 answered `404 LOCAL_VERDICT_INACTIVE_CONTRACTS`, category 11,
/// gRPC 5, cause "Rejected transaction is referring to inactive contracts " with its trailing space, and recorded a completion with status
/// code 5 and that message). The HTTP status follows the gRPC code as the JSON API maps it.
pub(super) fn verdict_error(notes: &[String]) -> Option<ApiError> {
    let note = notes
        .iter()
        .find_map(|n| n.strip_prefix(canton_participant::node::REJECTION_NOTE))?;
    let details = notes
        .iter()
        .find_map(|n| n.strip_prefix(canton_participant::node::REJECTION_CONTEXT_NOTE))
        .map(String::from);
    status_error(note, details)
}

/// A Canton status `<gRPC code>:<CODE>(<category>,<id>): <cause>` as the API reports it.
pub(super) fn status_error(note: &str, details: Option<String>) -> Option<ApiError> {
    let (grpc, message) = note.split_once(':')?;
    let grpc_code: i32 = grpc.parse().ok()?;
    let (head, cause) = message.split_once("): ")?;
    let (code, rest) = head.split_once('(')?;
    let category: u64 = rest.split(',').next()?.parse().ok()?;
    let http_status = match grpc_code {
        3 | 9 | 11 => 400,
        5 => 404,
        6 | 10 => 409,
        7 => 403,
        16 => 401,
        4 => 504,
        14 => 503,
        _ => 500,
    };
    Some(ApiError::SynchronizerRejected {
        code: code.to_string(),
        cause: cause.to_string(),
        grpc_code,
        http_status,
        category,
        details,
    })
}

pub(crate) fn sync_rejected(kind: &str, notes: &[String]) -> ApiError {
    if let Some(error) = verdict_error(notes) {
        return error;
    }
    let joined = notes.join(" ");
    let lower = joined.to_ascii_lowercase();
    if joined.contains("ContractNotFound")
        || joined.contains("ArchivedContract")
        || lower.contains("inactive")
        || lower.contains("not active")
    {
        ApiError::SynchronizerRejected {
            code: "LOCAL_VERDICT_INACTIVE_CONTRACTS".into(),
            cause: format!(
                "Rejected transaction is referring to inactive contracts ({kind}: {notes:?})"
            ),
            grpc_code: 5,
            http_status: 404,
            category: 11,
            details: None,
        }
    } else if lower.contains("locked") {
        ApiError::SynchronizerRejected {
            code: "LOCAL_VERDICT_LOCKED_CONTRACTS".into(),
            cause: format!("Local verdict: contract is locked ({kind}: {notes:?})"),
            grpc_code: 10,
            http_status: 409,
            category: 2,
            details: None,
        }
    } else if lower.contains("timed out")
        || lower.contains("timed_out")
        || lower.contains("timeout")
    {
        ApiError::SynchronizerRejected {
            code: "MEDIATOR_SAYS_TX_TIMED_OUT".into(),
            cause: format!("Rejected transaction timed out at mediator ({kind}: {notes:?})"),
            grpc_code: 10,
            http_status: 409,
            category: 2,
            details: None,
        }
    } else {
        ApiError::SynchronizerRejected {
            code: "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK".into(),
            cause: format!(
                "Rejected transaction due to a failed model conformance check: {kind} ({notes:?})"
            ),
            grpc_code: 3,
            http_status: 400,
            category: 5,
            details: None,
        }
    }
}

/// The tag a submission of the command the current thread submits carries: who its completion is for (see `protocol_late`).
pub(super) fn command_tag() -> String {
    crate::service::current_command()
        .and_then(|c| serde_json::to_string(&c).ok())
        .unwrap_or_default()
}

pub(super) fn map_submit_err(err: String) -> ApiError {
    // [CANTON-NOTE: SEMANTICS] The wait for the verdict ended first: the command service's `REQUEST_TIME_OUT` (504), not a rejection. The
    // command stays in flight and its completion is recorded when its fate is known (`protocol_late`).
    if err.starts_with(canton_participant::node::STILL_IN_FLIGHT) {
        let command = crate::service::current_command().unwrap_or_default();
        return ApiError::SynchronizerRejected {
            code: crate::service::REQUEST_TIME_OUT.into(),
            cause: format!(
                "Timed out while awaiting for a completion corresponding to a command submission with command-id={} and submission-id={}.",
                command.command_id, command.submission_id
            ),
            grpc_code: 4,
            http_status: 504,
            category: 3,
            details: None,
        };
    }
    // [CANTON-NOTE: SEMANTICS] The submitter's routing refuses the command before anything is sent, with Canton's routing error
    // (`TransactionRoutingError`), not a verdict.
    if let Some(error) = err
        .strip_prefix(canton_participant::routing::ROUTING_REFUSAL)
        .and_then(|status| status_error(status, None))
    {
        return error;
    }
    let lower = err.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        ApiError::SynchronizerRejected {
            code: "MEDIATOR_SAYS_TX_TIMED_OUT".into(),
            cause: err,
            grpc_code: 10,
            http_status: 409,
            category: 2,
            details: None,
        }
    } else {
        refuse(err)
    }
}

#[cfg(test)]
mod reassignment_check_words {
    use super::super::shorten_member;
    use crate::v2_commands::shorten_id;

    /// The words the official participant prints for a synchronizer and a member in the vetting refusal
    /// (`tests/oracle/reassignment/json-api-checks-vetting.jsonl`: "... on synchronizer `syncB::12207a1857f3...::37-0`: Participant
    /// PAR::p1::122037a0652f... has not vetted 0fe75100f5ff...").
    #[test]
    fn a_synchronizer_and_a_member_are_cut_to_twelve_characters_of_the_fingerprint() {
        assert_eq!(
            shorten_id(
                "syncB::12207a1857f3d3e1c0b2a49586766e8d9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0::37-0"
            ),
            "syncB::12207a1857f3...::37-0"
        );
        assert_eq!(
            shorten_member(
                "PAR::p1::122037a0652f28226f271154594f7e4f4f64fba962d8dd0f3d67741e3263b4825435"
            ),
            "PAR::p1::122037a0652f..."
        );
    }
}

#[cfg(test)]
mod routing_refusal {
    use super::{map_submit_err, ApiError};
    use canton_participant::routing::{check_submitters, SUBMISSION};

    #[test]
    fn a_command_for_a_party_hosted_elsewhere_is_refused_with_the_routing_error() {
        let elsewhere = |_: &str| Some((1, vec![("other".to_string(), SUBMISSION)]));
        let error = check_submitters(&["bob".to_string()], "me", &elsewhere)
            .expect_err("bob is hosted elsewhere");
        match map_submit_err(error) {
            ApiError::SynchronizerRejected {
                code,
                cause,
                grpc_code,
                http_status,
                category,
                details,
            } => {
                assert_eq!(code, "NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT");
                assert_eq!(
                    cause,
                    "This participant cannot submit as the given submitter on any connected synchronizer"
                );
                assert_eq!((grpc_code, http_status, category), (5, 404, 11));
                assert_eq!(details, None);
            }
            other => panic!("not the routing error: {other:?}"),
        }
    }
}
