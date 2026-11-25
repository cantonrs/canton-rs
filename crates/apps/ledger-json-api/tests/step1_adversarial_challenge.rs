//! Step 1 Empirical Adversarial Challenge Test Suite
//!
//! Validates Step 1 G3 residual:
//! "로드된 DAR 요청이 service.rs의 'Transfer' / 'SplitTransfer' 팔에 도달하지 않게 잠금.
//!  그 팔에 떨어지지 않는 테스트. 미로드 DAR 폴백을 남기면 그 사실만 테스트로 고정."
//!
//! Adversarial challenge vectors tested:
//! 1. Non-existent contract ID rejection (404 ContractNotActive, never reaches legacy SingleContractLedger)
//! 2. Corrupt/malformed/boundary contract IDs (opaque strings, special characters, long strings)
//! 3. Template ID spoofing and bypass attempts (partial package matches, fake packages, traversal strings)
//! 4. Unauthorized and unauthenticated exercise requests (Daml-LF bytecode authorization errors, not legacy string errors)
//! 5. Malformed choice payloads (schema validation errors with qualified template name)
//! 6. Concurrency stress testing (race on single contract, double spend prevention)
//! 7. Lifecycle transition & contract promotion (unloaded -> loaded transition preserves lock)
//! 8. Combinatorial template resolution fuzzing

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
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

// -----------------------------------------------------------------------------
// Vector 1: Non-Existent Contract ID Rejection
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_nonexistent_contract_never_reaches_legacy() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    let non_existent_cids = vec![
        "#999:0",
        "#0:0",
        "#1:0",
        "non-existent-contract-id",
        "contract-42",
        "invalid-hash-cid",
    ];

    for cid in non_existent_cids {
        // 1. Via json_exercise
        let err_json = service
            .json_exercise(
                &act_as,
                ExerciseRequest {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cid.to_string(),
                    choice: "Transfer".to_string(),
                    argument: json!({ "newOwner": "Bob" }),
                    meta: None,
                },
            )
            .unwrap_err();

        assert_eq!(
            err_json.status_code(),
            404,
            "Non-existent contract ID '{cid}' must fail with HTTP 404 ContractNotActive"
        );
        assert_eq!(
            err_json,
            ApiError::ContractNotActive(cid.to_string()),
            "Error must be ContractNotActive, proving legacy SingleContractLedger was bypassed"
        );

        // 2. Via submit_and_wait (Ledger API Command::Exercise)
        let err_submit = service
            .submit_and_wait(SubmitAndWaitRequest {
                commands: Commands {
                    application_id: "test-app".into(),
                    command_id: format!("cmd-test-{}", cid),
                    act_as: act_as.clone(),
                    read_as: vec![],
                    submission_id: None,
                    workflow_id: None,
                    deduplication_period: None,
                    commands: vec![Command::Exercise(ExerciseCommand {
                        template_id: TemplateId::asset_holding(),
                        contract_id: cid.to_string(),
                        choice: "Transfer".to_string(),
                        choice_argument: json!({ "newOwner": "Bob" }),
                    })],
                },
            })
            .unwrap_err();

        assert_eq!(
            err_submit.status_code(),
            404,
            "Ledger API non-existent contract '{cid}' must fail with HTTP 404 ContractNotActive"
        );
        assert_eq!(
            err_submit,
            ApiError::ContractNotActive(cid.to_string()),
            "Ledger API error must be ContractNotActive, proving legacy SingleContractLedger was bypassed"
        );
    }
}

// -----------------------------------------------------------------------------
// Vector 2: Corrupted, Boundary, and Special Contract IDs
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_corrupted_and_boundary_contract_ids() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    let long_cid = format!("#{:0>500}:0", 99);
    let boundary_cids = vec![
        "",                         // Empty contract ID
        "   ",                      // Whitespace only
        "#abc",                     // Malformed format that fails parse_contract_id in legacy
        "../../etc/passwd",         // Path traversal payload
        "DROP TABLE contracts; --", // SQL injection payload
        "#{123}:0",                 // Corrupted punctuation
        &long_cid,                  // Excessively long contract ID (500 chars)
    ];

    for cid in boundary_cids {
        let err = service
            .json_exercise(
                &act_as,
                ExerciseRequest {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cid.to_string(),
                    choice: "Transfer".to_string(),
                    argument: json!({ "newOwner": "Bob" }),
                    meta: None,
                },
            )
            .unwrap_err();

        // In the legacy path, `#abc` would return ApiError::InvalidArgument("Invalid contract ID format '#abc'").
        // In the generic locked path, it MUST return ApiError::ContractNotActive(cid) (404)!
        assert_eq!(
            err.status_code(),
            404,
            "Boundary CID '{cid}' must return 404 ContractNotActive, never 400 InvalidArgument from legacy parser"
        );
        assert_eq!(
            err,
            ApiError::ContractNotActive(cid.to_string()),
            "Must be ContractNotActive for '{cid}'"
        );
    }
}

// -----------------------------------------------------------------------------
// Vector 3: Template ID Spoofing and Bypass Attempts
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_template_id_spoofing_attempts() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create contract");
    let cid = create_res.result.contract_id;

    let spoofed_template_ids = vec![
        // 1. Wrong package ID
        TemplateId {
            package_id: "deadbeefcafebabe000000000000000000000000000000000000000000000000".into(),
            module_name: "AssetHolding".into(),
            entity_name: "AssetHolding".into(),
        },
        // 2. Empty package, wrong module
        TemplateId {
            package_id: "".into(),
            module_name: "AssetHoldingFake".into(),
            entity_name: "AssetHolding".into(),
        },
        // 3. Empty package, wrong entity
        TemplateId {
            package_id: "".into(),
            module_name: "AssetHolding".into(),
            entity_name: "AssetHoldingFake".into(),
        },
        // 4. All fields empty
        TemplateId {
            package_id: "".into(),
            module_name: "".into(),
            entity_name: "".into(),
        },
        // 5. Injection strings
        TemplateId {
            package_id: "../../../dar".into(),
            module_name: "AssetHolding".into(),
            entity_name: "AssetHolding".into(),
        },
    ];

    for tmpl in spoofed_template_ids {
        let err = service
            .json_exercise(
                &act_as,
                ExerciseRequest {
                    template_id: tmpl.clone(),
                    contract_id: cid.clone(),
                    choice: "Transfer".to_string(),
                    argument: json!({ "newOwner": "Bob" }),
                    meta: None,
                },
            )
            .unwrap_err();

        // Must reject with TemplateNotFound (404), never falling back to LegacyAssetHolding
        assert_eq!(
            err.status_code(),
            404,
            "Spoofed template {:?} must return 404 TemplateNotFound",
            tmpl
        );
        match err {
            ApiError::TemplateNotFound(t) => {
                assert!(t.contains(&tmpl.entity_name) || t == tmpl.to_string());
            }
            other => panic!("Expected TemplateNotFound, got {:?}", other),
        }
    }
}

// -----------------------------------------------------------------------------
// Vector 4: Unauthorized and Unauthenticated Exercise Requests
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_unauthorized_and_unauthenticated_requests() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // Create holding owned by Alice, bank is Bank
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create contract");
    let cid = create_res.result.contract_id;

    // Sub-attack 1: Empty act_as
    let err_empty = service
        .json_exercise(
            &[],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bob" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_empty.status_code(), 403);
    match &err_empty {
        ApiError::Unauthorized(msg) => {
            // Must be from generic Daml-LF Engine, NOT legacy "Transfer choice requires controller Bank, but only ... were given"
            assert!(
                msg.contains("requires authorization of") || msg.contains("authorized:"),
                "Error message must originate from lf-eval::Engine, got: {msg}"
            );
            assert!(
                !msg.contains("were given"),
                "Error message must NOT originate from legacy string arm"
            );
        }
        other => panic!("Expected Unauthorized, got {:?}", other),
    }

    // Sub-attack 2: Bank acting on Transfer (which is controlled by owner Alice)
    let err_bank = service
        .json_exercise(
            &["Bank".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bob" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err_bank.status_code(), 403);
    match &err_bank {
        ApiError::Unauthorized(msg) => {
            assert!(
                msg.contains("requires authorization of [\"Alice\"]"),
                "Generic engine correctly detects Alice is required controller, got: {msg}"
            );
            assert!(
                !msg.contains("were given"),
                "Legacy arm string must not be present"
            );
        }
        other => panic!("Expected Unauthorized, got {:?}", other),
    }

    // Sub-attack 3: Unauthorized third-party "Eve"
    let err_eve = service
        .json_exercise(
            &["Eve".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Eve" }),
                meta: None,
            },
        )
        .unwrap_err();
    // Eve is neither signatory nor observer, so the contract is invisible to her: not found (404), the same answer
    // `daml script --ide-ledger` gives a non-stakeholder submitter (S-TX-001), not an authorization failure.
    assert_eq!(err_eve.status_code(), 404);
    assert!(
        matches!(&err_eve, ApiError::ContractNotActive(_)),
        "Got: {err_eve:?}"
    );

    // Verify contract is still intact and unconsumed
    let contracts = service.get_active_contracts(&[]).expect("get active");
    assert_eq!(contracts.active_contracts.len(), 1);
    assert_eq!(contracts.active_contracts[0].contract_id, cid);
}

// -----------------------------------------------------------------------------
// Vector 5: Malformed Choice Payloads
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_malformed_choice_payloads_never_reach_legacy() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create contract");
    let cid = create_res.result.contract_id;

    // 1. Missing required field 'newOwner'
    let err1 = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({}),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err1.status_code(), 400);
    match &err1 {
        ApiError::InvalidArgument(msg) => {
            assert!(
                msg.contains("Invalid choice argument") || msg.contains("missing field `newOwner`"),
                "Got: {msg}"
            );
            // Legacy arm uses `ApiError::InvalidArgument("missing 'newOwner' argument".into())`
            assert!(
                !msg.starts_with("missing 'newOwner' argument"),
                "Must NOT use legacy string arm error format"
            );
        }
        other => panic!("Expected InvalidArgument, got {:?}", other),
    }

    // 2. Choice argument with wrong type (integer instead of Party/Text)
    let err2 = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": 4242 }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err2.status_code(), 400);

    // 3. Unknown choice name
    let err3 = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "FakeNonExistentChoice".to_string(),
                argument: json!({}),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err3.status_code(), 400);
    match &err3 {
        ApiError::InvalidArgument(msg) => {
            // Qualified name check: "Unknown choice 'FakeNonExistentChoice' on template AssetHolding:AssetHolding"
            assert!(
                msg.contains("AssetHolding:AssetHolding"),
                "Generic path must identify qualified template AssetHolding:AssetHolding, got: {msg}"
            );
        }
        other => panic!("Expected InvalidArgument, got {:?}", other),
    }
}

// -----------------------------------------------------------------------------
// Vector 6: Concurrency Stress Testing: Double-Spend Race on Loaded DAR
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_concurrent_exercise_double_spend_race() {
    let service = Arc::new(ExecutionService::new());
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create contract");
    let cid = create_res.result.contract_id;

    // Launch 30 threads attempting to consume the same contract simultaneously
    let thread_count = 30;
    let mut handles = Vec::new();
    let success_count = Arc::new(AtomicUsize::new(0));
    let not_active_count = Arc::new(AtomicUsize::new(0));
    let other_error_count = Arc::new(AtomicUsize::new(0));

    for i in 0..thread_count {
        let s = Arc::clone(&service);
        let c = cid.clone();
        let succ = Arc::clone(&success_count);
        let not_act = Arc::clone(&not_active_count);
        let other = Arc::clone(&other_error_count);

        handles.push(thread::spawn(move || {
            let res = s.json_exercise(
                &["Alice".to_string(), "Bank".to_string()],
                ExerciseRequest {
                    template_id: TemplateId::asset_holding(),
                    contract_id: c,
                    choice: "Transfer".to_string(),
                    argument: json!({ "newOwner": "Bank" }),
                    meta: None,
                },
            );

            match res {
                Ok(resp) => {
                    // Must have a valid newly allocated contract ID
                    assert!(
                        resp.result.exercise_result.is_some(),
                        "Loaded DAR exercise result MUST be Some(cid), not None from legacy arm"
                    );
                    succ.fetch_add(1, Ordering::SeqCst);
                }
                Err(ApiError::ContractNotActive(_)) => {
                    not_act.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Unexpected error in race thread {i}: {:?}", e);
                    other.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "EXACTLY ONE concurrent exercise must succeed on a consuming choice"
    );
    assert_eq!(
        not_active_count.load(Ordering::SeqCst),
        thread_count - 1,
        "All other concurrent attempts must be rejected with ContractNotActive"
    );
    assert_eq!(
        other_error_count.load(Ordering::SeqCst),
        0,
        "No unexpected errors or legacy fallbacks allowed"
    );
}

// -----------------------------------------------------------------------------
// Vector 7: Dynamic DAR Loading & Contract Promotion Transition
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_dynamic_dar_loading_promotes_contracts_and_locks_fallback() {
    // 1. Initialize service WITHOUT a DAR
    let service = ExecutionService::new();
    assert!(service.dar_info().is_none());

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let legacy_create = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("unloaded create");
    let legacy_cid = legacy_create.result.contract_id;
    assert_eq!(legacy_cid, "#0:0");

    // 2. Dynamically load DAR
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");
    assert!(service.dar_info().is_some());

    // 3. Exercise the previously-created legacy contract.
    // Because DAR is now loaded, this contract MUST be promoted and executed via Daml-LF Engine!
    let transfer_res = service
        .json_exercise(
            &["Alice".to_string(), "Bank".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: legacy_cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("exercise on promoted contract");

    // Daml-LF Engine returns the new contract ID in exercise_result (legacy arm returned None)
    assert!(
        transfer_res.result.exercise_result.is_some(),
        "Promoted contract MUST be evaluated by Daml-LF Engine and return exercise_result Some(cid), got None"
    );

    // 4. Double spend attempt on the promoted contract must return ContractNotActive (404)
    let err = service
        .json_exercise(
            &["Alice".to_string(), "Bank".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: legacy_cid,
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err.status_code(), 404);
}

// -----------------------------------------------------------------------------
// Vector 8: Ledger API submit_and_wait Full LifeCycle under Loaded DAR
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_submit_and_wait_loaded_dar_guarantees_engine_execution() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // 1. Create via submit_and_wait
    let create_tree = service
        .submit_and_wait(SubmitAndWaitRequest {
            commands: Commands {
                application_id: "test-app".into(),
                command_id: "cmd-create-1".into(),
                act_as,
                read_as: vec![],
                submission_id: None,
                workflow_id: None,
                deduplication_period: None,
                commands: vec![Command::Create(CreateCommand {
                    template_id: TemplateId::asset_holding(),
                    create_arguments: sample_holding_payload(),
                })],
            },
        })
        .expect("create via submit_and_wait");

    let root_event = create_tree
        .events_by_id
        .get(&create_tree.root_event_ids[0])
        .unwrap();
    let created_cid = match root_event {
        TreeEvent::Created(c) => c.contract_id.clone(),
        _ => panic!("Expected Created event"),
    };

    // 2. Exercise Transfer via submit_and_wait
    let exercise_tree = service
        .submit_and_wait(SubmitAndWaitRequest {
            commands: Commands {
                application_id: "test-app".into(),
                command_id: "cmd-exercise-1".into(),
                act_as: vec!["Alice".to_string(), "Bank".to_string()],
                read_as: vec![],
                submission_id: None,
                workflow_id: None,
                deduplication_period: None,
                commands: vec![Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: created_cid.clone(),
                    choice: "Transfer".to_string(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                })],
            },
        })
        .expect("exercise via submit_and_wait");

    let root_exercise_event = exercise_tree
        .events_by_id
        .get(&exercise_tree.root_event_ids[0])
        .unwrap();
    match root_exercise_event {
        TreeEvent::Exercised(ex) => {
            assert!(
                ex.exercise_result.is_some(),
                "ExercisedEvent under loaded DAR MUST have exercise_result populated by Daml bytecode, got None"
            );
            assert_eq!(ex.choice, "Transfer");
            assert_eq!(ex.child_event_ids.len(), 1);
        }
        _ => panic!("Expected Exercised event"),
    }

    // 3. Re-exercising consumed contract MUST fail with ContractNotActive
    let err = service
        .submit_and_wait(SubmitAndWaitRequest {
            commands: Commands {
                application_id: "test-app".into(),
                command_id: "cmd-exercise-repeat".into(),
                act_as: vec!["Alice".to_string(), "Bank".to_string()],
                read_as: vec![],
                submission_id: None,
                workflow_id: None,
                deduplication_period: None,
                commands: vec![Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: created_cid,
                    choice: "Transfer".to_string(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                })],
            },
        })
        .unwrap_err();

    assert_eq!(err.status_code(), 404);
}

// -----------------------------------------------------------------------------
// Vector 9: Ghost Contract Resurrection in Active Contract Set (Bug Reproduction)
// -----------------------------------------------------------------------------
#[test]
fn test_challenge_consumed_promoted_contract_ghost_resurrection() {
    let service = ExecutionService::new();
    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("unloaded create");
    let cid = res.result.contract_id;
    assert_eq!(cid, "#0:0");

    service.load_dar(&sample_dar_path()).expect("load dar");

    // Consume contract under loaded DAR
    let ex_res = service
        .json_exercise(
            &["Alice".to_string(), "Bank".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        )
        .expect("consume contract");
    assert!(ex_res.result.exercise_result.is_some());

    // Query active contracts via get_active_contracts
    let active = service.get_active_contracts(&[]).expect("active");
    let active_ids: Vec<_> = active
        .active_contracts
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();

    // Query active contracts via json_contracts
    let json_active = service.json_contracts(&[], None).expect("json contracts");
    let json_active_ids: Vec<_> = json_active
        .result
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();

    assert!(
        !active_ids.contains(&cid),
        "BUG: Consumed promoted contract {cid} must NOT appear in get_active_contracts, but found in {active_ids:?}"
    );
    assert!(
        !json_active_ids.contains(&cid),
        "BUG: Consumed promoted contract {cid} must NOT appear in json_contracts, but found in {json_active_ids:?}"
    );
}
