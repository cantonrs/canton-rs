//! The W3C trace context a client submits a command with is the one its update and its completion carry (`traceContext`), as Canton's
//! submitting participant records the trace of the submission; a command submitted without one shows the empty trace as before.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::HashMap;

use ledger_json_api::{dispatch_request, ExecutionService, HttpRequest};
use serde_json::{json, Value};

const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const EMPTY: &str = "00-00000000000000000000000000000000-0000000000000000-00";

fn call(svc: &ExecutionService, path: &str, body: Vec<u8>, trace: Option<&str>) -> (u16, Value) {
    let mut headers = HashMap::new();
    if let Some(t) = trace {
        headers.insert("traceparent".to_string(), t.to_string());
    }
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers,
            body,
        },
    );
    (
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
    )
}

fn submit(svc: &ExecutionService, alice: &str, command_id: &str, trace: Option<&str>) -> Value {
    let body = json!({"commands": {
        "commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "1.0"}
        }}],
        "userId": "u-trace",
        "commandId": command_id,
        "actAs": [alice]
    }});
    let (status, body) = call(
        svc,
        "/v2/commands/submit-and-wait-for-transaction",
        body.to_string().into_bytes(),
        trace,
    );
    assert_eq!(status, 200, "{body}");
    body
}

#[test]
fn a_submissions_trace_context_is_its_update_and_completions() {
    let svc = ExecutionService::new();
    let dar = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    assert_eq!(call(&svc, "/v2/dars", dar, None).0, 200);
    let (s, b) = call(
        &svc,
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""})
            .to_string()
            .into_bytes(),
        None,
    );
    assert_eq!(s, 200, "{b}");
    let alice = b["partyDetails"]["party"].as_str().unwrap().to_string();

    let traced = submit(&svc, &alice, "traced", Some(TRACE));
    assert_eq!(
        traced["transaction"]["traceContext"]["traceparent"], TRACE,
        "{traced}"
    );
    let plain = submit(&svc, &alice, "plain", None);
    assert_eq!(
        plain["transaction"]["traceContext"]["traceparent"], EMPTY,
        "{plain}"
    );
    let (s, completions) = call(
        &svc,
        "/v2/commands/completions",
        json!({ "userId": "u-trace", "parties": [alice], "beginExclusive": 0 })
            .to_string()
            .into_bytes(),
        None,
    );
    assert_eq!(s, 200, "{completions}");
    let trace_of = |command: &str| {
        completions
            .as_array()
            .unwrap()
            .iter()
            .map(|i| &i["completionResponse"]["Completion"]["value"])
            .find(|c| c["commandId"] == command)
            .map(|c| c["traceContext"]["traceparent"].clone())
    };
    assert_eq!(trace_of("traced"), Some(json!(TRACE)), "{completions}");
    assert_eq!(trace_of("plain"), Some(json!(EMPTY)), "{completions}");
    // the update read back by its id carries it too
    let update_id = traced["transaction"]["updateId"].as_str().unwrap();
    let (s, by_id) = call(
        &svc,
        "/v2/updates/update-by-id",
        json!({"updateId": update_id, "updateFormat": {"includeTransactions": {
            "eventFormat": {"filtersByParty": {alice: {}}, "verbose": false},
            "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}}})
        .to_string()
        .into_bytes(),
        None,
    );
    assert_eq!(s, 200, "{by_id}");
    assert_eq!(
        by_id["update"]["Transaction"]["value"]["traceContext"]["traceparent"], TRACE,
        "{by_id}"
    );
}
