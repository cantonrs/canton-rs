//! The W3C trace context of a submission, kept with the update and the completion it leads to (their `traceContext`).
//!
//! [CANTON-NOTE: SEMANTICS] Canton's submitting participant processes a command under the trace of the call that submitted it (the
//! `traceparent` the gRPC metadata or the HTTP headers carried) and records that trace with the update and the completion
//! (`Update.traceContext`, `Completion.traceContext`).
//! [CANTON-NOTE: LIMITATION] Only the submitting participant's own update and completion: the trace does not travel with the confirmation
//! request to other participants (Canton sends it as the `traceparent` of `SendAsync` and the sequencer hands it out with each event), and a
//! command whose completion comes after its wait shows the empty trace. A command submitted without a valid `traceparent` shows the empty
//! trace this service always showed, not a new one as Canton's would.
use serde_json::{json, Value as Json};

/// The header the HTTP server adds to a request whose `traceparent` it made up for its request log (the client sent none).
pub const GENERATED_HEADER: &str = "x-canton-rs-generated-traceparent";

/// The trace context of a command that names none.
const EMPTY: &str = "00-00000000000000000000000000000000-0000000000000000-00";

thread_local! {
    static SUBMISSION: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The submission the current thread runs carries `traceparent` until the guard is dropped.
pub(crate) struct SubmissionTrace;

impl Drop for SubmissionTrace {
    fn drop(&mut self) {
        SUBMISSION.with(|s| *s.borrow_mut() = None);
    }
}

/// The client's `traceparent` of a request (none when the server made it up or it is not a W3C trace context).
pub(crate) fn of_request(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    if headers.contains_key(GENERATED_HEADER) {
        return None;
    }
    let given = headers
        .get("traceparent")
        .or_else(|| headers.get("Traceparent"))?;
    valid(given).then(|| given.to_ascii_lowercase())
}

/// `00-<32 hex trace id>-<16 hex parent id>-<2 hex flags>`, neither id all zeros (the W3C Trace Context's `traceparent`).
fn valid(traceparent: &str) -> bool {
    let parts: Vec<&str> = traceparent.split('-').collect();
    let hex = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit());
    let nonzero = |s: &str| s.bytes().any(|b| b != b'0');
    matches!(parts.as_slice(), [version, trace, parent, flags]
        if hex(version, 2) && *version != "ff" && hex(trace, 32) && nonzero(trace)
            && hex(parent, 16) && nonzero(parent) && hex(flags, 2))
}

pub(crate) fn enter(traceparent: Option<String>) -> SubmissionTrace {
    SUBMISSION.with(|s| *s.borrow_mut() = traceparent);
    SubmissionTrace
}

/// The `traceparent` of the submission the current thread runs.
pub(crate) fn current() -> Option<String> {
    SUBMISSION.with(|s| s.borrow().clone())
}

/// The `traceContext` of an update or a completion: the official participant's when it recorded one, else the submission's, else empty.
pub(crate) fn json(official: Option<Option<&str>>, own: Option<&str>) -> Json {
    match official {
        Some(recorded) => json!({ "traceparent": recorded, "tracestate": null }),
        None => json!({ "traceparent": own.unwrap_or(EMPTY), "tracestate": null }),
    }
}

#[cfg(test)]
mod tests {
    use super::valid;

    #[test]
    fn only_a_w3c_traceparent_is_kept() {
        assert!(valid(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ));
        assert!(!valid(
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        ));
        assert!(!valid(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
        ));
        assert!(!valid(
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ));
        assert!(!valid(
            "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01"
        ));
        assert!(!valid("not a trace"));
    }
}
