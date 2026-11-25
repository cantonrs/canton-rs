//! The `grpc-status-details-bin` of an error: the `google.rpc.Status` Canton attaches to every Ledger API error
//! (`NonSecuritySensitiveErrorCodeComponents.toStatusProto`, Canton 3.7.2), built from the JSON API's error body.
//!
//! [CANTON-NOTE: SEMANTICS] The details are, in this order: an `ErrorInfo` (reason: the error code id; metadata: the error's
//! context with `category`, `tid` and `definite_answer`), a `RetryInfo` when the category is retryable, a `RequestInfo` with
//! the correlation id (or the trace id without one), and a `ResourceInfo` per resource. A security-sensitive error
//! (`SecuritySensitiveErrorCodeComponents`) carries the `RequestInfo` alone.
use std::collections::BTreeMap;

use canton_proto::google::rpc::{RequestInfo, ResourceInfo, RetryInfo, Status as RpcStatus};
use prost::Message;
use prost_reflect::prost_types::{Any, Duration};
use serde_json::Value as Json;

/// `google.rpc.ErrorInfo` with its metadata in key order, so the same error always encodes to the same bytes.
#[derive(Clone, PartialEq, Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
    #[prost(btree_map = "string, string", tag = "3")]
    metadata: BTreeMap<String, String>,
}

fn any(type_name: &str, value: Vec<u8>) -> Any {
    Any {
        type_url: format!("type.googleapis.com/{type_name}"),
        value,
    }
}

fn text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A Scala `FiniteDuration` as the JSON body prints it (`1 second`, `500 milliseconds`).
fn retry_delay(text: &str) -> Option<Duration> {
    let (amount, unit) = text.trim().split_once(' ')?;
    let amount: i64 = amount.parse().ok()?;
    let nanos_per = match unit.trim_end_matches('s') {
        "nanosecond" => 1,
        "microsecond" => 1_000,
        "millisecond" => 1_000_000,
        "second" => 1_000_000_000,
        "minute" => 60_000_000_000,
        "hour" => 3_600_000_000_000,
        "day" => 86_400_000_000_000,
        _ => return None,
    };
    let total = amount.checked_mul(nanos_per)?;
    Some(Duration {
        seconds: total / 1_000_000_000,
        nanos: i32::try_from(total % 1_000_000_000).ok()?,
    })
}

/// The encoded `google.rpc.Status` for the JSON API error `body` reported as gRPC `code` with `message`. `correlation_id` is the
/// request's own id when Canton correlates the error with it (a submission's id).
pub(crate) fn encode(
    code: i32,
    message: &str,
    body: &Json,
    correlation_id: Option<&str>,
) -> Vec<u8> {
    let request_id = correlation_id
        .filter(|c| !c.is_empty())
        .or_else(|| body.get("correlationId").and_then(Json::as_str))
        .or_else(|| body.get("traceId").and_then(Json::as_str))
        .map(String::from);
    let request_info = request_id.map(|request_id| {
        any(
            "google.rpc.RequestInfo",
            RequestInfo {
                request_id,
                serving_data: String::new(),
            }
            .encode_to_vec(),
        )
    });
    let mut details = Vec::new();
    if body.get("code").and_then(Json::as_str) != Some("NA") {
        let metadata = body
            .get("context")
            .and_then(Json::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), text(v))).collect())
            .unwrap_or_default();
        details.push(any(
            "google.rpc.ErrorInfo",
            ErrorInfo {
                reason: body
                    .get("code")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string(),
                domain: String::new(),
                metadata,
            }
            .encode_to_vec(),
        ));
        if let Some(delay) = body
            .get("retryInfo")
            .and_then(Json::as_str)
            .and_then(retry_delay)
        {
            details.push(any(
                "google.rpc.RetryInfo",
                RetryInfo {
                    retry_delay: Some(delay),
                }
                .encode_to_vec(),
            ));
        }
        details.extend(request_info);
        for resource in body
            .get("resources")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let part = |i: usize| resource.get(i).map(text).unwrap_or_default();
            details.push(any(
                "google.rpc.ResourceInfo",
                ResourceInfo {
                    resource_type: part(0),
                    resource_name: part(1),
                    owner: String::new(),
                    description: String::new(),
                }
                .encode_to_vec(),
            ));
        }
    } else {
        details.extend(request_info);
    }
    RpcStatus {
        code,
        message: message.to_string(),
        details,
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decoded(bytes: &[u8]) -> RpcStatus {
        RpcStatus::decode(bytes).expect("a google.rpc.Status")
    }

    #[test]
    fn an_error_carries_its_info_retry_request_and_resources() {
        let body = json!({
            "code": "SUBMISSION_ALREADY_IN_FLIGHT", "cause": "The submission is already in-flight",
            "correlationId": "00000000-0000-0000-0000-000000000000", "traceId": "0000000000000000",
            "context": {"category": "2", "definite_answer": "false", "tid": "0000000000000000"},
            "resources": [["CONTRACT_ID", "00ab"]], "errorCategory": 2, "grpcCodeValue": 10, "retryInfo": "1 second"
        });
        let status = decoded(&encode(10, "m", &body, Some("my-submission")));
        let types: Vec<&str> = status.details.iter().map(|d| d.type_url.as_str()).collect();
        assert_eq!(
            types,
            [
                "type.googleapis.com/google.rpc.ErrorInfo",
                "type.googleapis.com/google.rpc.RetryInfo",
                "type.googleapis.com/google.rpc.RequestInfo",
                "type.googleapis.com/google.rpc.ResourceInfo"
            ]
        );
        let info = ErrorInfo::decode(status.details[0].value.as_slice()).unwrap();
        assert_eq!(info.reason, "SUBMISSION_ALREADY_IN_FLIGHT");
        assert_eq!(info.metadata["category"], "2");
        let retry = RetryInfo::decode(status.details[1].value.as_slice()).unwrap();
        assert_eq!(retry.retry_delay.map(|d| d.seconds), Some(1));
        let request = RequestInfo::decode(status.details[2].value.as_slice()).unwrap();
        assert_eq!(request.request_id, "my-submission");
        let resource = ResourceInfo::decode(status.details[3].value.as_slice()).unwrap();
        assert_eq!(
            (
                resource.resource_type.as_str(),
                resource.resource_name.as_str()
            ),
            ("CONTRACT_ID", "00ab")
        );
    }

    #[test]
    fn the_server_attaches_the_details_to_the_status_it_returns() {
        let body = json!({"code": "DUPLICATE_COMMAND", "cause": "Command submission already exists.",
            "correlationId": null, "traceId": "0000000000000000", "context": {"category": "10"}, "resources": [],
            "errorCategory": 10, "grpcCodeValue": 6});
        let status = crate::server::status_of(409, body.to_string().as_bytes());
        let details = decoded(status.details());
        assert_eq!(details.code, 6);
        assert_eq!(
            ErrorInfo::decode(details.details[0].value.as_slice())
                .unwrap()
                .reason,
            "DUPLICATE_COMMAND"
        );
    }

    #[test]
    fn a_security_sensitive_error_carries_the_request_info_alone() {
        let body = json!({"code": "NA", "correlationId": "abc", "context": {}, "resources": []});
        let status = decoded(&encode(7, "m", &body, None));
        assert_eq!(status.details.len(), 1);
        assert_eq!(
            RequestInfo::decode(status.details[0].value.as_slice())
                .unwrap()
                .request_id,
            "abc"
        );
    }
}
