//! Empirical Challenge Test Suite for ledger-json-api
//!
//! Adversarial verification targeting:
//! 1. Dual-path routing and isolation between SingleContractLedger (unloaded) and lf_eval::Engine (loaded DAR)
//! 2. Poisoning resistance and state containment across failure boundaries
//! 3. Malformed payload and boundary handling in ExecutionService
//! 4. Identification of contract ID collision & shadowing between uncoordinated counters

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::ExecutionService;
use serde_json::json;

fn dar_path() -> PathBuf {
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
// Section 1: Unloaded DAR Routes Cleanly to SingleContractLedger
// =======================================================================================

#[test]
fn challenge_unloaded_dar_routes_cleanly_to_single_contract_ledger() {
    let service = ExecutionService::new();
    assert!(
        service.dar_info().is_none(),
        "no DAR should be loaded initially"
    );

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // 1. Create on unloaded service -> Routes to Legacy SingleContractLedger
    let create_res = service
        .json_create(&act_as, create_req)
        .expect("legacy create should succeed");
    assert_eq!(create_res.status, 200);
    let cid = create_res.result.contract_id;
    assert_eq!(cid, "#0:0");

    // 2. Exercise Transfer to Bank on legacy path (Bank is already signatory so choice body create is authorized)
    let transfer_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Transfer".to_string(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };

    let act_as_transfer = vec!["Alice".to_string(), "Bank".to_string()];
    let exercise_res = service
        .json_exercise(&act_as_transfer, transfer_req)
        .expect("legacy transfer to Bank");
    assert_eq!(exercise_res.status, 200);
    // Legacy SingleContractLedger path returns exercise_result: None, but events contains Created event
    assert_eq!(exercise_res.result.exercise_result, None);
    assert_eq!(exercise_res.result.events.len(), 2);

    // 3. Old contract is consumed in SingleContractLedger -> Attempting to exercise again must return 404 ContractNotActive
    let reuse_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Transfer".to_string(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let err = service
        .json_exercise(&act_as_transfer, reuse_req)
        .unwrap_err();
    assert_eq!(err.status_code(), 404);
}

// =======================================================================================
// Section 2: Loaded DAR Routes to Generic Engine and Isolates State
// =======================================================================================

#[test]
fn challenge_loaded_dar_routes_to_generic_engine_with_state_isolation() {
    let service = ExecutionService::new();
    let dar = dar_path();
    assert!(dar.exists(), "DAR file must exist at {:?}", dar);

    service.load_dar(&dar).expect("load_dar failed");
    assert!(service.dar_info().is_some());

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];
    let create_req = CreateRequest {
        template_id: TemplateId::asset_holding(),
        payload: sample_holding_payload(),
        meta: None,
    };

    // 1. Create on loaded service -> Routes to Generic Engine
    let create_res = service
        .json_create(&act_as, create_req)
        .expect("generic create should succeed");
    assert_eq!(create_res.status, 200);
    let cid = create_res.result.contract_id;
    assert_eq!(cid, "#0:0");

    // 2. Exercise SplitTransfer to Bank (recipient = Bank, which is already a signatory)
    // Transfer 40.0 to Bank, keeping 60.0 with Alice
    let split_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "SplitTransfer".to_string(),
        argument: json!({
            "recipient": "Bank",
            "transferAmount": "40.0"
        }),
        meta: None,
    };

    // Alice is controller; Bank is co-signatory
    let split_act_as = vec!["Alice".to_string(), "Bank".to_string()];
    let split_res = service
        .json_exercise(&split_act_as, split_req)
        .expect("generic split_transfer to Bank");
    assert_eq!(split_res.status, 200);

    // 3. Verify original contract is consumed in generic path
    let reuse_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Settle".to_string(),
        argument: json!({}),
        meta: None,
    };
    let err = service
        .json_exercise(&["Bank".to_string()], reuse_req)
        .unwrap_err();
    assert_eq!(err.status_code(), 404);
}

// =======================================================================================
// Section 3: Cross-Path Shadowing Vulnerability & Failure Containment
// =======================================================================================

#[test]
fn challenge_cross_path_contract_id_collision_and_shadowing() {
    let service = ExecutionService::new();

    // Step A: Create a legacy contract L0 BEFORE loading DAR
    let act_as_legacy = vec!["Bank".to_string(), "Alice".to_string()];
    let legacy_create = service
        .json_create(
            &act_as_legacy,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create L0 in SingleContractLedger");
    let l0_id = legacy_create.result.contract_id;

    // Step B: Now load DAR dynamically
    service.load_dar(&dar_path()).expect("load DAR");

    // Step C: Create a generic contract G0 AFTER loading DAR
    let act_as_generic = vec!["Bank".to_string(), "Alice".to_string()];
    let generic_create = service
        .json_create(
            &act_as_generic,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({
                    "bank": "Bank",
                    "owner": "Alice",
                    "auditor": "Auditor",
                    "assetSymbol": "USD",
                    "amount": "500.0"
                }),
                meta: None,
            },
        )
        .expect("create G0 in Generic Engine");
    let g0_id = generic_create.result.contract_id;

    // VERIFICATION OF REMEDIATED ID COORDINATION:
    // SingleContractLedger and Engine contract IDs are globally distinct!
    assert_ne!(
        l0_id, g0_id,
        "l0_id ({l0_id}) and g0_id ({g0_id}) must be globally distinct across paths"
    );
    assert_eq!(l0_id, "#0:0");
    assert_eq!(g0_id, "#1:0");

    // Step D: Active contracts query returns distinct IDs (no collision)
    let active_res = service
        .get_active_contracts(&[])
        .expect("get active contracts");
    assert_eq!(active_res.active_contracts.len(), 2);
    let ids: HashSet<String> = active_res
        .active_contracts
        .iter()
        .map(|c| c.contract_id.clone())
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "ACS must contain 2 distinct contract IDs with no duplicates"
    );
    assert!(ids.contains(&l0_id));
    assert!(ids.contains(&g0_id));

    // Step E: Exercising generic contract g0_id succeeds and archives generic contract
    let settle_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: g0_id,
        choice: "Settle".to_string(),
        argument: json!({}),
        meta: None,
    };
    let settle_res = service
        .json_exercise(&["Bank".to_string()], settle_req)
        .expect("settle generic contract");
    assert_eq!(settle_res.status, 200);

    // Step F: Legacy contract l0_id in SingleContractLedger remains accessible and exercisable!
    let transfer_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: l0_id,
        choice: "Transfer".to_string(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let act_as_transfer = vec!["Alice".to_string(), "Bank".to_string()];
    let transfer_res = service
        .json_exercise(&act_as_transfer, transfer_req)
        .expect("legacy transfer must succeed and not be shadowed or locked out");
    assert_eq!(transfer_res.status, 200);
}

#[test]
fn challenge_failure_containment_in_dual_path() {
    let service = ExecutionService::new();
    service.load_dar(&dar_path()).expect("load DAR");

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
        .unwrap();
    let cid = create_res.result.contract_id;

    // Inject assertion failure into generic SplitTransfer
    let bad_split = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "SplitTransfer".to_string(),
        argument: json!({
            "recipient": "Bank",
            "transferAmount": "200.0" // > 100.0
        }),
        meta: None,
    };
    let split_act_as = vec!["Alice".to_string(), "Bank".to_string()];
    let err = service.json_exercise(&split_act_as, bad_split).unwrap_err();
    assert_eq!(err.status_code(), 400);

    // Verify contract is STILL ACTIVE and uncorrupted
    let settle_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Settle".to_string(),
        argument: json!({}),
        meta: None,
    };
    let settle_res = service
        .json_exercise(&["Bank".to_string()], settle_req)
        .expect("still active");
    assert_eq!(settle_res.status, 200);
}

// =======================================================================================
// Section 4: Malformed Payloads & Boundary Conditions in ExecutionService
// =======================================================================================

#[test]
fn challenge_service_malformed_payloads_and_boundary_rejections() {
    let service = ExecutionService::new();
    service.load_dar(&dar_path()).expect("load DAR");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // 1. Malformed template: non-existent template
    let bad_tmpl = TemplateId {
        package_id: "".into(),
        module_name: "NonExistent".into(),
        entity_name: "BadTemplate".into(),
    };
    let err1 = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: bad_tmpl,
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err1.status_code(), 404);

    // 2. Malformed payload: Array instead of Object
    let err2 = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!([1, 2, 3]),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err2.status_code(), 400);

    // 3. Malformed payload: Missing required field
    let mut incomplete = sample_holding_payload();
    incomplete.as_object_mut().unwrap().remove("amount");
    let err3 = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: incomplete,
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err3.status_code(), 400);

    // 4. Malformed payload: Typo / extra field
    let mut typo = sample_holding_payload();
    typo["extraField"] = json!("typo");
    let err4 = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: typo,
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err4.status_code(), 400);

    // 5. Invalid choice arguments
    // First create a valid contract
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .unwrap();
    let cid = create_res.result.contract_id;

    // Send string instead of object for choice argument
    let err5 = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".to_string(),
                argument: json!("not an object"),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err5.status_code(), 400);

    // Send unknown choice name
    let err6 = service
        .json_exercise(
            &["Alice".to_string()],
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "NoSuchChoice".to_string(),
                argument: json!({}),
                meta: None,
            },
        )
        .unwrap_err();
    assert_eq!(err6.status_code(), 400);
}

// =======================================================================================
// Section 5: NEXT-05 Proof Tests (Refutation of Legacy Choice Fallback & Fact Pinning)
// =======================================================================================

#[test]
fn test_next05_proof1_loaded_dar_transfer_never_reaches_legacy_arm() {
    // [CANTON-NOTE: SEMANTICS] When a DAR is loaded, AssetHolding::Transfer must execute via Daml-LF bytecode
    // [CANTON-NOTE: INVARIANT] Legacy arm error sentences ("missing 'newOwner' argument", "exercise_transfer")
    // must never appear, proving the request was routed exclusively to lf_eval::Engine.
    let service = ExecutionService::new();
    service.load_dar(&dar_path()).expect("load DAR");

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
        .expect("create under loaded DAR");
    let cid = create_res.result.contract_id;

    // Subcase 1A: Malformed argument to Transfer - must produce schema/engine error, NEVER legacy arm string
    let bad_transfer = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "Transfer".to_string(),
        argument: json!({}), // missing newOwner field in schema
        meta: None,
    };
    let err = service
        .json_exercise(&["Alice".to_string()], bad_transfer)
        .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains("missing 'newOwner' argument"),
        "Proof 1 failed: Legacy arm error string appeared: {err_msg}"
    );
    assert!(
        !err_msg.contains("exercise_transfer"),
        "Proof 1 failed: Legacy exercise_transfer appeared: {err_msg}"
    );
    assert_eq!(err.status_code(), 400);

    // Subcase 1B: Valid Transfer - executes via Engine, returning exercise_result Some(new_cid)
    let good_transfer = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Transfer".to_string(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let res = service
        .json_exercise(&["Alice".to_string()], good_transfer)
        .expect("Transfer via Engine must succeed");
    assert_eq!(res.status, 200);
    assert!(
        res.result.exercise_result.is_some(),
        "Proof 1 failed: loaded DAR Transfer must populate exercise_result via Daml bytecode"
    );
}

#[test]
fn test_next05_proof2_loaded_dar_non_transfer_choice_never_hits_legacy_unknown_choice() {
    // [CANTON-NOTE: SEMANTICS] In loaded DAR mode, choices defined on the template (e.g. Settle)
    // or unknown choices must be evaluated by the package's module surface and Engine.
    // [CANTON-NOTE: INVARIANT] "Unknown choice ... on template AssetHolding" is the legacy arm error string;
    // its appearance on any request proves fallback to legacy arm occurred.
    let service = ExecutionService::new();
    service.load_dar(&dar_path()).expect("load DAR");

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
        .expect("create under loaded DAR");
    let cid = create_res.result.contract_id;

    // Subcase 2A: "Settle" choice exists in DAR, but is NOT Transfer or SplitTransfer.
    // Legacy arm only handled Transfer/SplitTransfer and rejected everything else with "Unknown choice".
    let settle_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Settle".to_string(),
        argument: json!({}),
        meta: None,
    };
    let settle_res = service
        .json_exercise(&["Bank".to_string()], settle_req)
        .expect("Settle must be executed by Engine, not rejected by legacy arm");
    assert_eq!(settle_res.status, 200);

    // Subcase 2B: Non-existent choice on loaded DAR template
    // Must fail via RecordSchema (ChoiceNotFound), NEVER via legacy arm ("Unknown choice 'Foo' on template AssetHolding")
    let create_res2 = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create second contract under loaded DAR");
    let cid2 = create_res2.result.contract_id;

    let fake_choice_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid2,
        choice: "NoSuchChoice".to_string(),
        argument: json!({}),
        meta: None,
    };
    let err = service
        .json_exercise(&["Alice".to_string()], fake_choice_req)
        .unwrap_err();
    let err_msg = err.to_string();
    // Legacy arm error is unqualified: "Unknown choice 'NoSuchChoice' on template AssetHolding"
    // Loaded DAR schema error is qualified: "Unknown choice 'NoSuchChoice' on template AssetHolding:AssetHolding"
    assert!(
        err_msg.contains("on template AssetHolding:AssetHolding"),
        "Expected qualified schema error from Daml-LF surface, got: {err_msg}"
    );
    assert!(
        !err_msg.ends_with("on template AssetHolding"),
        "Proof 2 failed: Legacy unqualified arm error appeared: {err_msg}"
    );
}

#[test]
fn test_next05_proof3_unloaded_dar_requests_route_to_legacy_arm() {
    // [CANTON-NOTE: SEMANTICS] When no DAR is loaded, the service operates in backward-compatible
    // legacy mode, routing requests to SingleContractLedger's hardcoded AssetHolding fixtures.
    // [CANTON-NOTE: WHY] Pins down the exact behavior: unloaded DAR requests route to legacy arm,
    // where exercise_result is None and unknown choices emit "Unknown choice ... on template AssetHolding".
    let service = ExecutionService::new();
    assert!(service.dar_info().is_none(), "DAR must not be loaded");

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
        .expect("create on legacy arm");
    let cid = create_res.result.contract_id;

    // Unknown choice on unloaded service emits legacy arm error sentence
    let bad_choice = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid.clone(),
        choice: "NoSuchChoice".to_string(),
        argument: json!({}),
        meta: None,
    };
    let err = service
        .json_exercise(&["Alice".to_string()], bad_choice)
        .unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Unknown choice 'NoSuchChoice' on template AssetHolding"),
        "Unloaded DAR request must route to legacy arm: {err_msg}"
    );

    // Valid transfer on unloaded service routes to legacy exercise_transfer (exercise_result is None)
    let transfer_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: cid,
        choice: "Transfer".to_string(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let res = service
        .json_exercise(&["Alice".to_string(), "Bank".to_string()], transfer_req)
        .expect("transfer on legacy arm");
    assert_eq!(res.status, 200);
    assert_eq!(
        res.result.exercise_result, None,
        "Legacy arm does not evaluate Daml bytecode so exercise_result is None"
    );
}
