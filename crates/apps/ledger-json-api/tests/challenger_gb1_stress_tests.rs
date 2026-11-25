//! Adversarial Challenge Test Harness for Gate G-B: ledger-json-api (challenger_gb_1)
//!
//! Empirically stress-tests:
//! 1. Authorization bypass attacks on both Generic Engine path and Fallback SingleContractLedger path
//! 2. Error classification (403 Forbidden for unauthorized, 404 Not Found for non-existent contracts)
//! 3. Concurrency stress testing on ExecutionService (Racing exercises, double-spend prevention)

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::{ApiError, ExecutionService};

fn sample_dar_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn sample_holding_payload() -> serde_json::Value {
    serde_json::json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0",
    })
}

// -----------------------------------------------------------------------------
// 1. Generic Engine Path Authorization Bypass Tests (With DAR Loaded)
// -----------------------------------------------------------------------------

#[test]
fn test_generic_path_create_partial_signatories_rejected() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // Attack 1: Only Alice in act_as (missing Bank)
    let res1 = service.json_create(&["Alice".into()], req.clone());
    assert!(
        matches!(&res1, Err(ApiError::Unauthorized(msg)) if msg.contains("requires authorizers")),
        "Generic create with missing Bank must return 403 Unauthorized, got: {res1:?}"
    );

    // Attack 2: Only Bank in act_as (missing Alice)
    let res2 = service.json_create(&["Bank".into()], req.clone());
    assert!(
        matches!(&res2, Err(ApiError::Unauthorized(msg)) if msg.contains("requires authorizers")),
        "Generic create with missing Alice must return 403 Unauthorized, got: {res2:?}"
    );

    // Attack 3: Empty act_as
    let res3 = service.json_create(&[], req);
    assert!(
        matches!(&res3, Err(ApiError::Unauthorized(_))),
        "Generic create with empty act_as must return 403 Unauthorized, got: {res3:?}"
    );

    // Verify ledger has 0 active contracts
    assert_eq!(service.active_ledger_state().active_contracts.len(), 0);
}

#[test]
fn test_generic_path_exercise_unauthorized_controller_rejected() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // Create valid contract
    let create_res = service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create");
    let cid = create_res.result.contract_id;

    // Attack 1: Bank attempts Transfer (controlled by Alice)
    let res1 = service.json_exercise(
        &["Bank".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: cid.clone(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Bank" }),
            meta: None,
        },
    );
    assert!(
        matches!(&res1, Err(ApiError::Unauthorized(msg)) if msg.contains("requires controller")),
        "Bank exercising Transfer must fail with Unauthorized 403, got: {res1:?}"
    );

    // Attack 2: Alice attempts Settle (controlled by Bank)
    let res2 = service.json_exercise(
        &["Alice".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: cid.clone(),
            choice: "Settle".into(),
            argument: serde_json::json!({}),
            meta: None,
        },
    );
    assert!(
        matches!(&res2, Err(ApiError::Unauthorized(msg)) if msg.contains("requires controller")),
        "Alice exercising Settle must fail with Unauthorized 403, got: {res2:?}"
    );

    // Attack 3: Third party Bob attempts Transfer
    let res3 = service.json_exercise(
        &["Bob".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: cid,
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(&res3, Err(ApiError::ContractNotActive(_))),
        "Bob is not a stakeholder: the contract is invisible to him (not found, S-TX-001), got: {res3:?}"
    );

    // Verify contract is still active
    assert_eq!(service.active_ledger_state().active_contracts.len(), 1);
}

// -----------------------------------------------------------------------------
// 2. Fallback Path Authorization Bypass Tests (Without DAR Loaded)
// -----------------------------------------------------------------------------

#[test]
fn test_fallback_path_create_and_exercise_authorization() {
    let service = ExecutionService::new(); // No DAR loaded -> SingleContractLedger fallback

    let req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // Attack 1: Partial act_as in fallback create
    let res1 = service.json_create(&["Alice".into()], req);
    assert!(
        matches!(&res1, Err(ApiError::Unauthorized(msg)) if msg.contains("requires authorizers Bank,Alice") || msg.contains("requires act_as authorization from both bank")),
        "Fallback create must fail with 403 if Bank is missing, got: {res1:?}"
    );

    // Valid create in fallback
    let create_res = service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("fallback create");
    let cid = create_res.result.contract_id;

    // Attack 2: Bank attempts Transfer in fallback
    let res2 = service.json_exercise(
        &["Bank".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: cid.clone(),
            choice: "Transfer".into(),
            argument: serde_json::json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(&res2, Err(ApiError::Unauthorized(msg)) if msg.contains("requires controller Alice")),
        "Fallback Transfer by Bank must fail with 403, got: {res2:?}"
    );

    // Attack 3: Alice attempts Settle in fallback
    let res3 = service.json_exercise(
        &["Alice".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: cid,
            choice: "Settle".into(),
            argument: serde_json::json!({}),
            meta: None,
        },
    );
    assert!(
        matches!(&res3, Err(ApiError::Unauthorized(msg)) if msg.contains("requires controller Bank")),
        "Fallback Settle by Alice must fail with 403, got: {res3:?}"
    );
}

// -----------------------------------------------------------------------------
// 3. Concurrency Stress Tests on ExecutionService
// -----------------------------------------------------------------------------

#[test]
fn test_stress_concurrent_exercises_in_execution_service() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // Create contract
    let create_res = service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create");
    let cid = create_res.result.contract_id;

    let service_arc = Arc::new(service);
    let mut handles = Vec::new();
    let num_threads = 16;

    for i in 0..num_threads {
        let s = Arc::clone(&service_arc);
        let c = cid.clone();
        let handle = thread::spawn(move || {
            s.json_exercise(
                &["Bank".into()],
                ExerciseRequest {
                    template_id: TemplateId::asset_holding(),
                    contract_id: c,
                    choice: "Settle".into(),
                    argument: serde_json::json!({}),
                    meta: None,
                },
            )
        });
        handles.push((i, handle));
    }

    let mut successes = 0;
    let mut not_active = 0;

    for (_i, handle) in handles {
        let res = handle.join().expect("thread join");
        match res {
            Ok(exercise_res) => {
                assert_eq!(exercise_res.status, 200);
                successes += 1;
            }
            Err(ApiError::ContractNotActive(_)) => {
                not_active += 1;
            }
            Err(other) => panic!("Unexpected error in concurrent exercise: {other:?}"),
        }
    }

    println!("[CONCURRENCY STRESS RESULT] Total threads: {num_threads}, Successful consumes: {successes}, ContractNotActive rejections: {not_active}");
    if successes > 1 {
        panic!(
            "VULNERABILITY REPRODUCED: TOCTOU race condition detected in ExecutionService! \
             {successes} concurrent exercises succeeded in consuming the same contract {cid}. \
             Only 1 should have succeeded; {} double-spent!",
            successes - 1
        );
    }
    assert_eq!(successes, 1, "Exactly ONE concurrent exercise must succeed");
}
