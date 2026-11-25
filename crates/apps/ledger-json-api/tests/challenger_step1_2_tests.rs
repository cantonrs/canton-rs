//! Adversarial Stress & Challenge Test Suite for Step 1
//! Written by challenger_step1_2
//!
//! Vectors:
//! 1. Ghost Contract Resurrection: Promoted contract consumed under loaded DAR resurfaces in query APIs.
//! 2. Concurrency Race: Concurrent exercises during/after load_dar never reach legacy choice arms.
//! 3. Promotion Double Spend: Two concurrent threads trying to consume the promoted contract.
//! 4. Unloaded Fallback Isolation: Strict boundary enforcement before and after load_dar.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::{ApiError, ExecutionService};
use serde_json::json;

fn sample_dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn sample_holding_payload() -> serde_json::Value {
    json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0"
    })
}

// =======================================================================================
// Vector 1: Ghost Contract Resurrection via Query APIs (Storage Isolation / Promotion)
// =======================================================================================

#[test]
fn challenge_promoted_contract_consumed_does_not_resurrect_in_active_contracts() {
    let service = ExecutionService::new();
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // 1. Create contract in unloaded state
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("unloaded create must succeed");
    let cid0 = create_res.result.contract_id;
    assert_eq!(cid0, "#0:0");

    // 2. Load DAR -> promotes #0:0 into generic_contracts
    let dar_p = sample_dar_path();
    service.load_dar(&dar_p).expect("load_dar must succeed");

    // Verify #0:0 is listed once in get_active_contracts
    let ac_before = service
        .get_active_contracts(&[])
        .expect("get_active_contracts must succeed");
    let cids_before: Vec<_> = ac_before
        .active_contracts
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();
    assert_eq!(
        cids_before,
        vec!["#0:0"],
        "promoted contract should appear once before exercise"
    );

    // Also check json_contracts
    let jc_before = service
        .json_contracts(&[], None)
        .expect("json_contracts must succeed");
    assert_eq!(jc_before.result.len(), 1);
    assert_eq!(jc_before.result[0].contract_id, "#0:0");

    // 3. Exercise consuming choice (Transfer to Bank) on #0:0 under loaded DAR
    // In Daml-LF, transfer to Bank is authorized by the consumed contract's signatories (Bank, Alice).
    let exercise_res = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid0,
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("exercise under loaded DAR must succeed");

    assert_eq!(exercise_res.status, 200);
    // Under generic engine, exercise_result is populated with the new contract id
    assert_eq!(
        exercise_res.result.exercise_result,
        Some(json!("#1:0")),
        "loaded DAR must populate exercise_result"
    );

    // 4. CRITICAL CHECK: Does #0:0 resurrect in get_active_contracts?
    let ac_after = service
        .get_active_contracts(&[])
        .expect("get_active_contracts must succeed");
    let cids_after: Vec<_> = ac_after
        .active_contracts
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();

    println!(
        "Active contract IDs after consuming exercise: {:?}",
        cids_after
    );

    // The active contracts MUST only contain "#1:0" and MUST NOT contain "#0:0"!
    assert!(
        !cids_after.contains(&"#0:0".to_string()),
        "VULNERABILITY: Consumed promoted contract #0:0 resurrected as active in get_active_contracts! Found: {:?}",
        cids_after
    );
    assert_eq!(
        cids_after,
        vec!["#1:0"],
        "Expected exactly [#1:0], but got {:?}",
        cids_after
    );

    // 5. CRITICAL CHECK: Does #0:0 resurrect in json_contracts?
    let jc_after = service
        .json_contracts(&[], None)
        .expect("json_contracts must succeed");
    let jc_cids: Vec<_> = jc_after
        .result
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();
    assert!(
        !jc_cids.contains(&"#0:0".to_string()),
        "VULNERABILITY: Consumed promoted contract #0:0 resurrected as active in json_contracts! Found: {:?}",
        jc_cids
    );
    assert_eq!(
        jc_cids,
        vec!["#1:0"],
        "Expected exactly [#1:0] in json_contracts, but got {:?}",
        jc_cids
    );
}

// =======================================================================================
// Vector 2: Concurrency Race during load_dar
// =======================================================================================

#[test]
fn challenge_concurrent_exercise_during_load_dar_never_hits_legacy_transfer_arm() {
    let dar_p = sample_dar_path();

    for iteration in 0..10 {
        let service = Arc::new(ExecutionService::new());
        let act_as = vec!["Bank".to_string(), "Alice".to_string()];

        // Create contract #0:0 in unloaded mode
        service
            .json_create(
                &act_as,
                CreateRequest {
                    template_id: TemplateId::asset_holding(),
                    payload: sample_holding_payload(),
                    meta: None,
                },
            )
            .expect("create");

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        // Spawn 4 exerciser threads trying to exercise Transfer to Bank concurrently
        for _ in 0..4 {
            let s = Arc::clone(&service);
            let st = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                let mut attempts = 0;
                while !st.load(Ordering::Relaxed) && attempts < 100 {
                    attempts += 1;
                    let res = s.json_exercise(
                        &["Alice".to_string()],
                        ExerciseRequest {
                            template_id: TemplateId::asset_holding(),
                            contract_id: "#0:0".to_string(),
                            choice: "Transfer".to_string(),
                            argument: json!({ "newOwner": "Bank" }),
                            meta: None,
                        },
                    );
                    if let Ok(resp) = res {
                        if s.dar_info().is_some() {
                            assert!(
                                resp.result.exercise_result.is_some(),
                                "DAR was loaded, but exercise returned None! Reached legacy arm!"
                            );
                        }
                    } else if let Err(e) = res {
                        let err_str = e.to_string();
                        // Under loaded DAR, legacy choice error format must NEVER appear
                        if s.dar_info().is_some() {
                            assert!(
                                !err_str.contains("Transfer choice requires controller"),
                                "Legacy choice error string found under loaded DAR: {err_str}"
                            );
                        }
                    }
                }
            }));
        }

        // Thread that loads DAR
        let s_load = Arc::clone(&service);
        let p_load = dar_p.clone();
        let load_handle = thread::spawn(move || {
            s_load.load_dar(&p_load).expect("load_dar");
        });

        load_handle.join().expect("load thread join");
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("exercise thread join");
        }

        // Once DAR is loaded, any further exercise on #0:0 MUST return ContractNotActive
        // and must NOT hit legacy arm!
        let post_res = service.json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: "#0:0".to_string(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        );
        match post_res {
            Err(ApiError::ContractNotActive(cid)) => {
                assert_eq!(cid, "#0:0");
            }
            Err(ApiError::Ledger(msg)) => {
                panic!("Iteration {iteration}: Unexpected Ledger error: {msg}");
            }
            Ok(_) => {
                // Succeeded if not previously consumed
            }
            Err(other) => {
                panic!("Iteration {iteration}: Unexpected error: {other:?}");
            }
        }
    }
}

// =======================================================================================
// Vector 3: Promotion Double-Spend Prevention under Concurrent Load
// =======================================================================================

#[test]
fn challenge_promoted_contract_double_spend_strictly_rejected() {
    let dar_p = sample_dar_path();
    let service = Arc::new(ExecutionService::new());
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // Create #0:0 before DAR load
    service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create");

    // Load DAR
    service.load_dar(&dar_p).expect("load_dar");

    // Spawn 10 concurrent threads attempting to consume #0:0
    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = Arc::clone(&service);
        handles.push(thread::spawn(move || {
            s.json_exercise(
                &["Alice".to_string()],
                ExerciseRequest {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#0:0".to_string(),
                    choice: "Transfer".to_string(),
                    argument: json!({ "newOwner": "Bank" }),
                    meta: None,
                },
            )
        }));
    }

    let mut successes = 0;
    let mut contract_not_active = 0;

    for h in handles {
        let res = h.join().expect("join");
        match res {
            Ok(resp) => {
                successes += 1;
                assert!(resp.result.exercise_result.is_some());
            }
            Err(ApiError::ContractNotActive(cid)) => {
                assert_eq!(cid, "#0:0");
                contract_not_active += 1;
            }
            Err(other) => {
                panic!("Unexpected error in double-spend challenge: {other:?}");
            }
        }
    }

    println!(
        "Double spend results: successes={successes}, contract_not_active={contract_not_active}"
    );
    assert_eq!(
        successes, 1,
        "Exactly ONE concurrent exercise must succeed on #0:0"
    );
    assert_eq!(
        contract_not_active, 9,
        "All other 9 concurrent attempts must be rejected with ContractNotActive"
    );
}

// =======================================================================================
// Vector 4: Unloaded Fallback Isolation & Ingress Lockdown
// =======================================================================================

#[test]
fn challenge_unloaded_fallback_and_loaded_ingress_lockdown() {
    let service = ExecutionService::new();

    // 1. Unloaded mode: unknown template MUST return TemplateNotFound, not fallback
    let unknown_tmpl = TemplateId {
        package_id: "some_pkg".to_string(),
        module_name: "SomeMod".to_string(),
        entity_name: "SomeTemplate".to_string(),
    };
    let res = service.json_exercise(
        &["Alice".to_string()],
        ExerciseRequest {
            template_id: unknown_tmpl.clone(),
            contract_id: "#0:0".to_string(),
            choice: "Transfer".to_string(),
            argument: json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(res, Err(ApiError::TemplateNotFound(_))),
        "Unloaded mode with unknown template must return TemplateNotFound"
    );

    // 2. Load DAR
    let dar_p = sample_dar_path();
    service.load_dar(&dar_p).expect("load_dar");

    // 3. Loaded mode: unknown template MUST return TemplateNotFound
    let res = service.json_exercise(
        &["Alice".to_string()],
        ExerciseRequest {
            template_id: unknown_tmpl,
            contract_id: "#0:0".to_string(),
            choice: "Transfer".to_string(),
            argument: json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(res, Err(ApiError::TemplateNotFound(_))),
        "Loaded mode with unknown template must return TemplateNotFound"
    );

    // 4. Loaded mode: target AssetHolding with non-existent contract ID
    // MUST return ContractNotActive (HTTP 404), NEVER reach legacy arm
    let res = service.json_exercise(
        &["Alice".to_string()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#999:0".to_string(),
            choice: "Transfer".to_string(),
            argument: json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(res, Err(ApiError::ContractNotActive(cid)) if cid == "#999:0"),
        "Loaded mode with non-existent CID must return ContractNotActive"
    );

    // 5. Loaded mode: target AssetHolding with malformed/opaque contract ID
    // MUST return ContractNotActive without attempting legacy parse_contract_id
    let res = service.json_exercise(
        &["Alice".to_string()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "opaque-arbitrary-canton-cid-xyz".to_string(),
            choice: "Transfer".to_string(),
            argument: json!({ "newOwner": "Bob" }),
            meta: None,
        },
    );
    assert!(
        matches!(res, Err(ApiError::ContractNotActive(cid)) if cid == "opaque-arbitrary-canton-cid-xyz"),
        "Loaded mode with opaque CID must return ContractNotActive"
    );
}
