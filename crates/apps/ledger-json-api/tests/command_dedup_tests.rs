//! Command deduplication: concurrent submissions of one change id, and the validation of the deduplication period
//! (`CommandsValidator.validateDeduplicationPeriod`, Canton 3.7.2).
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;

use std::sync::{Arc, Barrier};

use common::{call, dar_bytes, post};
use ledger_json_api::ExecutionService;
use serde_json::{json, Value};

fn ledger() -> (Arc<ExecutionService>, String) {
    let svc = ExecutionService::new();
    assert_eq!(call(&svc, "POST", "/v2/dars", dar_bytes()).0, 200);
    let (s, b) = post(
        &svc,
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""}),
    );
    assert_eq!(s, 200, "{b}");
    let alice = b["partyDetails"]["party"].as_str().unwrap().to_string();
    (Arc::new(svc), alice)
}

fn create(alice: &str, command_id: &str, period: Option<Value>) -> Value {
    let mut body = json!({"commands": [{"CreateCommand": {
        "templateId": "#sample-contract:AssetHolding:AssetHolding",
        "createArguments": {"bank": alice, "owner": alice, "auditor": alice, "assetSymbol": "USD", "amount": "1.0"}}}],
        "commandId": command_id, "actAs": [alice], "userId": "participant_admin"});
    if let Some(p) = period {
        body["deduplicationPeriod"] = p;
    }
    body
}

#[test]
fn of_concurrent_submissions_of_one_command_only_one_is_accepted() {
    let (svc, alice) = ledger();
    let runners = 8;
    let barrier = Arc::new(Barrier::new(runners));
    let handles: Vec<_> = (0..runners)
        .map(|_| {
            let (svc, barrier, alice) = (Arc::clone(&svc), Arc::clone(&barrier), alice.clone());
            std::thread::spawn(move || {
                barrier.wait();
                post(
                    &svc,
                    "/v2/commands/submit-and-wait",
                    create(&alice, "same", None),
                )
            })
        })
        .collect();
    let answers: Vec<(u16, Value)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let accepted = answers.iter().filter(|(s, _)| *s == 200).count();
    assert_eq!(accepted, 1, "{answers:?}");
    for (status, body) in answers.iter().filter(|(s, _)| *s != 200) {
        assert_eq!(*status, 409, "{body}");
        let code = body["code"].as_str().unwrap();
        assert!(
            code == "DUPLICATE_COMMAND" || code == "SUBMISSION_ALREADY_IN_FLIGHT",
            "{body}"
        );
    }
}

#[test]
fn a_negative_deduplication_period_is_refused_before_the_command_runs() {
    let (svc, alice) = ledger();
    let (s, b) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create(
            &alice,
            "neg-duration",
            Some(json!({"DeduplicationDuration": {"value": {"seconds": -1, "nanos": 0}}})),
        ),
    );
    assert_eq!((s, b["code"].as_str()), (400, Some("INVALID_FIELD")), "{b}");
    assert!(b["cause"]
        .as_str()
        .unwrap()
        .contains("Invalid field deduplication_period: Duration must be positive"));
    let (s, b) = post(
        &svc,
        "/v2/commands/submit-and-wait",
        create(
            &alice,
            "neg-offset",
            Some(json!({"DeduplicationOffset": {"value": -5}})),
        ),
    );
    assert_eq!(
        (s, b["code"].as_str()),
        (400, Some("NEGATIVE_OFFSET")),
        "{b}"
    );
}
