//! S-SIM-001 K-01 and K-07 on a synchronizer without traffic control (`τ = ⊥`): the `costEstimation` of a `prepare` answer has the shape
//! the official Canton 3.7.2 participant gave for the same four requests (recorded answers in
//! `doc/evidence/2026-11-24-S-SIM-001/oracle/`, measured by `jvm_peer_tests::p1_prepare_cost_estimation_shapes_are_recorded`).
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;

use common::{call, dar_bytes, post};
use ledger_json_api::ExecutionService;
use serde_json::{json, Value};

fn oracle(label: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../doc/evidence/2026-11-24-S-SIM-001/oracle")
        .join(format!("{label}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the recorded official answer {} is readable: {e}",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// The answer with the time of the estimate taken out (`estimationTimestamp`, A1).
fn shape(answer: &Value) -> Value {
    let mut cost = answer
        .get("costEstimation")
        .cloned()
        .unwrap_or(json!("<absent>"));
    if let Some(obj) = cost.as_object_mut() {
        obj.remove("estimationTimestamp");
    }
    cost
}

#[test]
fn cost_estimation_shapes_match_the_official_participant_without_traffic_control() {
    let svc = ExecutionService::new();
    assert_eq!(call(&svc, "POST", "/v2/dars", dar_bytes()).0, 200);
    let (_, sync) = call(&svc, "GET", "/v2/state/connected-synchronizers", vec![]);
    let sync = sync["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, alloc) = post(&svc, "/v2/parties", json!({"partyIdHint": "sim001"}));
    assert_eq!(s, 200, "{alloc}");
    let party = alloc["partyDetails"]["party"].as_str().unwrap().to_string();
    for label in [
        "no-hints",
        "disabled",
        "expected-signatures",
        "disabled-without-signatures",
    ] {
        let official = oracle(label);
        let mut body = official["request"].clone();
        body["actAs"] = json!([&party]);
        body["synchronizerId"] = json!(&sync);
        body["commands"][0]["CreateCommand"]["createArguments"] = json!({"bank": &party, "owner": &party, "auditor": &party, "assetSymbol": "USD", "amount": "1.0"});
        let (status, answer) = post(&svc, "/v2/interactive-submission/prepare", body);
        assert_eq!(
            status,
            official["status"].as_u64().unwrap() as u16,
            "{label}: status, answer {answer}"
        );
        if status == 200 {
            assert_eq!(
                shape(&answer),
                shape(&official["response"]),
                "{label}: costEstimation"
            );
            assert!(
                answer.as_object().unwrap().contains_key("costEstimation"),
                "{label}: the key is present (null when disabled), as in the official answer"
            );
        } else {
            // the official error body is plain text (the codec's decode failure), recorded as a JSON string
            let raw = ledger_json_api::dispatch_request(
                &svc,
                &ledger_json_api::HttpRequest {
                    method: "POST".into(),
                    path: "/v2/interactive-submission/prepare".into(),
                    query_params: Default::default(),
                    headers: Default::default(),
                    body: serde_json::to_vec(&official["request"]).unwrap(),
                },
            );
            assert_eq!(
                String::from_utf8_lossy(&raw.body),
                official["response"].as_str().unwrap(),
                "{label}: error body"
            );
        }
    }
}
