//! Milestone 2 Atomic Commands and Multi-Command Transaction Rollback Tests
//!
//! Validates:
//! 1. Atomic rollback across commands in `submit_and_wait`:
//!    If Command 1 is a valid Transfer on C1 and Command 2 fails (e.g. non-existent contract),
//!    the entire transaction is rejected, and C1 remains active and untouched in ACS.
//! 2. Contract promotion validation during `load_dar`:
//!    Corrupted or malformed legacy contracts produce explicit `ApiError::Internal`, aborting
//!    `load_dar` without silently dropping contracts.
//! 3. Single active set synchronization between `generic_contracts` and `ActiveLedgerState`:
//!    Contracts promoted or created are mirrored in `active_state`, and exercise consuming them
//!    updates both `generic_contracts` and `active_state` atomically.
//! 4. Refutation test: `test_atomic_rollback_if_second_exercise_fails_first_contract_remains_active_in_acs`

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::service::{ApiError, ExecutionService, TransactionCommit};
use lf_eval::ledger::{Holding, SingleContractLedger};
use lf_eval::tx_model::{ContractId, Node, TransactionTree as LfTransactionTree};
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

#[test]
fn test_atomic_rollback_if_second_exercise_fails_first_contract_remains_active_in_acs() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // 1. Create contract C1 via json_create
    let create_res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create initial contract");
    let c1_id = create_res.result.contract_id;
    assert_eq!(c1_id, "#0:0");

    // Verify initial ACS has exactly 1 contract (C1)
    let initial_acs = service
        .get_active_contracts(&[])
        .expect("get active contracts");
    assert_eq!(initial_acs.active_contracts.len(), 1);
    assert_eq!(initial_acs.active_contracts[0].contract_id, c1_id);

    let initial_journal_len = service.ledger_journal().len();
    let initial_updates_len = service.get_updates(0, None, &[]).len();

    // 2. Submit multi-command transaction:
    // Command 1: Valid Transfer on C1 (moving ownership to Bank)
    // Command 2: Invalid Exercise on non-existent contract "#999:0"
    let submit_req = SubmitAndWaitRequest {
        commands: Commands {
            application_id: "test-app".into(),
            command_id: "atomic-batch-cmd-1".into(),
            act_as: vec!["Alice".into(), "Bank".into()],
            read_as: vec![],
            submission_id: None,
            workflow_id: Some("test-workflow".into()),
            deduplication_period: None,
            commands: vec![
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: c1_id.clone(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#999:0".into(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
            ],
        },
    };

    let result = service.submit_and_wait(submit_req);

    // [CANTON-NOTE: SEMANTICS] Must reject with ContractNotActive on "#999:0"
    assert!(
        matches!(&result, Err(ApiError::ContractNotActive(cid)) if cid == "#999:0"),
        "Expected ContractNotActive for #999:0, got {:?}",
        result
    );

    // 3. Verify Refutation Proof: Contract C1 remains active in ACS!
    let acs_after = service
        .get_active_contracts(&[])
        .expect("get active contracts after failure");
    assert_eq!(
        acs_after.active_contracts.len(),
        1,
        "ACS must still have exactly 1 active contract after rollback"
    );
    assert_eq!(
        acs_after.active_contracts[0].contract_id, c1_id,
        "C1 must remain active in ACS after rollback"
    );

    // JSON contracts query must still return C1
    let contracts_view = service
        .json_contracts(&["Alice".into()], None)
        .expect("query contracts");
    assert_eq!(
        contracts_view.result.len(),
        1,
        "json_contracts must still return C1"
    );
    assert_eq!(contracts_view.result[0].contract_id, c1_id);

    // ActiveLedgerState internal state must still contain C1 and NOT any child contract
    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 1);
    assert!(
        state
            .active_contracts
            .contains_key(&ContractId(c1_id.clone())),
        "ActiveLedgerState must still contain C1"
    );
    assert!(
        !state
            .active_contracts
            .contains_key(&ContractId("#1:0".into())),
        "Child contract must NOT exist in ActiveLedgerState after rollback"
    );

    // Journal and Update stream must NOT have recorded the aborted transaction
    assert_eq!(
        service.ledger_journal().len(),
        initial_journal_len,
        "LedgerJournal must not record aborted transaction"
    );
    assert_eq!(
        service.get_updates(0, None, &[]).len(),
        initial_updates_len,
        "Update stream must not record aborted transaction"
    );

    // 4. Verify C1 is still fully spendable on its own
    let exercise_req = ExerciseRequest {
        template_id: TemplateId::asset_holding(),
        contract_id: c1_id.clone(),
        choice: "Transfer".into(),
        argument: json!({ "newOwner": "Bank" }),
        meta: None,
    };
    let ex_res = service.json_exercise(&["Alice".into(), "Bank".into()], exercise_req);
    assert!(
        ex_res.is_ok(),
        "C1 must be spendable after aborted multi-command: {:?}",
        ex_res
    );

    // Now C1 is consumed and child contract is active
    let acs_final = service.get_active_contracts(&[]).expect("get acs final");
    assert_eq!(acs_final.active_contracts.len(), 1);
    assert_ne!(acs_final.active_contracts[0].contract_id, c1_id);
    // [CANTON-NOTE: SEMANTICS] Contract counter advances monotonically across transaction attempts,
    // guaranteeing cross-thread collision freedom and isolation without duplicate ID collisions.
    // The aborted exercise evaluated with #1:0, so the subsequent successful exercise produces #2:0.
    assert_eq!(acs_final.active_contracts[0].contract_id, "#2:0");
}

#[test]
fn test_promotion_failure_returns_load_error_instead_of_silent_skip() {
    // Create a legacy ledger containing a corrupted contract with an invalid/empty party
    let bad_holding = Holding {
        bank: "".into(), // Empty party violates Daml-LF syntax
        owner: "Alice".into(),
        auditor: "Auditor".into(),
        symbol: "USD".into(),
        tenths: 1000,
    };
    let bad_ledger = SingleContractLedger {
        contracts: vec![Some(bad_holding)],
        contract_ids: vec!["#0:0".into()],
        submission_count: 0,
    };

    let service = ExecutionService::with_ledger(bad_ledger);
    let res = service.load_dar(&sample_dar_path());

    // Must return an explicit load error (ApiError::Internal), not Ok with silent contract disappearance
    assert!(
        matches!(&res, Err(ApiError::Internal(msg)) if msg.contains("Contract promotion failed")),
        "Expected ApiError::Internal with promotion failure message, got {:?}",
        res
    );

    // DAR info must NOT have been committed
    assert!(
        service.dar_info().is_none(),
        "DAR info must not be set if promotion fails"
    );
}

#[test]
fn test_single_active_set_synchronization_with_ledger_and_load_dar() {
    // Create a legacy ledger with a valid contract
    let valid_holding = Holding {
        bank: "Bank".into(),
        owner: "Alice".into(),
        auditor: "Auditor".into(),
        symbol: "USD".into(),
        tenths: 1000,
    };
    let ledger = SingleContractLedger {
        contracts: vec![Some(valid_holding)],
        contract_ids: vec!["#0:0".into()],
        submission_count: 0,
    };

    let service = ExecutionService::with_ledger(ledger);

    // 1. Verify ActiveLedgerState is synchronized immediately upon with_ledger
    let state_before = service.active_ledger_state();
    assert_eq!(state_before.active_contracts.len(), 1);
    assert!(state_before
        .active_contracts
        .contains_key(&ContractId("#0:0".into())));

    // 2. Load DAR - contract is promoted into generic_contracts and active_state
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let contracts = service
        .json_contracts(&["Alice".into()], None)
        .expect("query contracts");
    assert_eq!(contracts.result.len(), 1);
    assert_eq!(contracts.result[0].contract_id, "#0:0");

    let state_after_load = service.active_ledger_state();
    assert_eq!(state_after_load.active_contracts.len(), 1);
    assert!(state_after_load
        .active_contracts
        .contains_key(&ContractId("#0:0".into())));

    // 3. Exercise promoted contract under loaded DAR
    let ex_res = service.json_exercise(
        &["Alice".into(), "Bank".into()],
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: "#0:0".into(),
            choice: "Transfer".into(),
            argument: json!({ "newOwner": "Bank" }),
            meta: None,
        },
    );
    assert!(ex_res.is_ok(), "exercise promoted contract: {:?}", ex_res);

    // 4. Verify ActiveLedgerState and generic_contracts are both updated
    let state_final = service.active_ledger_state();
    assert_eq!(state_final.active_contracts.len(), 1);
    assert!(
        !state_final
            .active_contracts
            .contains_key(&ContractId("#0:0".into())),
        "#0:0 must be consumed in ActiveLedgerState"
    );
    assert!(
        state_final
            .active_contracts
            .contains_key(&ContractId("#1:0".into())),
        "#1:0 must be active in ActiveLedgerState"
    );
}

#[test]
fn test_multi_command_successful_atomic_execution() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // Submit multi-command where Command 1 creates a contract and Command 2 creates another contract
    let submit_req = SubmitAndWaitRequest {
        commands: Commands {
            application_id: "test-app".into(),
            command_id: "atomic-create-two".into(),
            act_as: vec!["Alice".into(), "Bank".into()],
            read_as: vec![],
            submission_id: None,
            workflow_id: Some("test-workflow".into()),
            deduplication_period: None,
            commands: vec![
                Command::Create(CreateCommand {
                    template_id: TemplateId::asset_holding(),
                    create_arguments: sample_holding_payload(),
                }),
                Command::Create(CreateCommand {
                    template_id: TemplateId::asset_holding(),
                    create_arguments: json!({
                        "bank": "Bank",
                        "owner": "Alice",
                        "auditor": "Auditor",
                        "assetSymbol": "EUR",
                        "amount": "50.0"
                    }),
                }),
            ],
        },
    };

    let tree = service
        .submit_and_wait(submit_req)
        .expect("submit and wait succeeds");
    assert_eq!(tree.root_event_ids.len(), 2);

    let acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(acs.active_contracts.len(), 2);

    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 2);
}

#[test]
fn test_adversarial_three_command_batch_create_exercise_and_fail_aborts_entire_batch() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // Pre-condition: initial ACS is completely empty
    let initial_acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(initial_acs.active_contracts.len(), 0);
    assert_eq!(service.active_ledger_state().active_contracts.len(), 0);

    // Three commands in a single atomic batch:
    // Cmd 1: Create contract C1 (expected id #0:0)
    // Cmd 2: Exercise Transfer on C1 (moving Alice -> Bank)
    // Cmd 3: Exercise Transfer on non-existent contract #999:0 (FAIL)
    let submit_req = SubmitAndWaitRequest {
        commands: Commands {
            application_id: "adversarial-app".into(),
            command_id: "batch-create-exercise-fail".into(),
            act_as: vec!["Alice".into(), "Bank".into()],
            read_as: vec![],
            submission_id: None,
            workflow_id: Some("adversarial-wf".into()),
            deduplication_period: None,
            commands: vec![
                Command::Create(CreateCommand {
                    template_id: TemplateId::asset_holding(),
                    create_arguments: sample_holding_payload(),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#0:0".into(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#999:0".into(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
            ],
        },
    };

    let res = service.submit_and_wait(submit_req);
    assert!(
        matches!(&res, Err(ApiError::ContractNotActive(cid)) if cid == "#999:0"),
        "Expected ContractNotActive for #999:0, got {:?}",
        res
    );

    // Empirically verify that C1 was NEVER created in final ACS!
    let acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(
        acs.active_contracts.len(),
        0,
        "ACS must be empty: C1 must never have been created in final ACS"
    );

    let json_view = service
        .json_contracts(&["Alice".into(), "Bank".into()], None)
        .expect("json contracts");
    assert_eq!(json_view.result.len(), 0);

    let state = service.active_ledger_state();
    assert_eq!(
        state.active_contracts.len(),
        0,
        "ActiveLedgerState must have 0 contracts after rollback"
    );

    assert_eq!(service.ledger_journal().len(), 0);
    assert_eq!(service.get_updates(0, None, &[]).len(), 0);

    // [CANTON-NOTE: SEMANTICS] Contract ID allocation advances monotonically across transaction attempts,
    // ensuring global thread-safety without duplicate ID collisions.
    // The aborted attempt evaluated with #0:0 and #1:0, so fresh_create allocates #2:0.
    let fresh_create = service
        .json_create(
            &["Bank".into(), "Alice".into()],
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("fresh create succeeds");
    assert_eq!(fresh_create.result.contract_id, "#2:0");
    assert_eq!(
        service
            .get_active_contracts(&[])
            .expect("acs")
            .active_contracts
            .len(),
        1
    );
}

#[test]
fn test_adversarial_batch_of_5_exercises_where_fourth_fails_preserves_all_contracts() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // Create 5 contracts C0..C4
    let mut cids = Vec::new();
    for i in 0..5 {
        let payload = json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": format!("{}.0", (i + 1) * 10)
        });
        let res = service
            .json_create(
                &act_as,
                CreateRequest {
                    template_id: TemplateId::asset_holding(),
                    payload,
                    meta: None,
                },
            )
            .expect("create contract");
        cids.push(res.result.contract_id);
    }
    assert_eq!(cids.len(), 5);
    assert_eq!(cids, vec!["#0:0", "#1:0", "#2:0", "#3:0", "#4:0"]);

    let acs_before = service.get_active_contracts(&[]).expect("acs before");
    assert_eq!(acs_before.active_contracts.len(), 5);

    // Batch of 5 exercises where 4th (index 3) targets non-existent "#999:0"
    let submit_req = SubmitAndWaitRequest {
        commands: Commands {
            application_id: "adversarial-batch-5".into(),
            command_id: "cmd-batch-5".into(),
            act_as: vec!["Alice".into(), "Bank".into()],
            read_as: vec![],
            submission_id: None,
            workflow_id: None,
            deduplication_period: None,
            commands: vec![
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cids[0].clone(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cids[1].clone(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cids[2].clone(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: "#999:0".into(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
                Command::Exercise(ExerciseCommand {
                    template_id: TemplateId::asset_holding(),
                    contract_id: cids[4].clone(),
                    choice: "Transfer".into(),
                    choice_argument: json!({ "newOwner": "Bank" }),
                }),
            ],
        },
    };

    let res = service.submit_and_wait(submit_req);
    assert!(
        matches!(&res, Err(ApiError::ContractNotActive(cid)) if cid == "#999:0"),
        "Expected ContractNotActive for #999:0, got {:?}",
        res
    );

    // Verify: NONE of the contracts were consumed!
    let acs_after = service.get_active_contracts(&[]).expect("acs after");
    assert_eq!(
        acs_after.active_contracts.len(),
        5,
        "ACS must still contain exactly 5 contracts"
    );
    let mut after_cids: Vec<String> = acs_after
        .active_contracts
        .into_iter()
        .map(|c| c.contract_id)
        .collect();
    after_cids.sort();
    assert_eq!(after_cids, cids, "All 5 original contracts must be present");

    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 5);
    for cid in &cids {
        assert!(
            state
                .active_contracts
                .contains_key(&ContractId(cid.clone())),
            "Contract {} must still be active in ActiveLedgerState",
            cid
        );
    }

    // Verify all 5 contracts are still individually spendable
    for cid in &cids {
        let ex = service.json_exercise(
            &act_as,
            ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid.clone(),
                choice: "Transfer".into(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            },
        );
        assert!(ex.is_ok(), "Contract {} must be spendable: {:?}", cid, ex);
    }
}

#[test]
fn test_adversarial_concurrent_submissions_attempting_to_spend_same_contract() {
    let service = Arc::new(ExecutionService::new());
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let act_as = vec!["Bank".to_string(), "Alice".to_string()];

    // Create single contract C0
    let res = service
        .json_create(
            &act_as,
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: sample_holding_payload(),
                meta: None,
            },
        )
        .expect("create contract");
    let target_cid = res.result.contract_id;
    assert_eq!(target_cid, "#0:0");

    let num_threads = 16;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let s = Arc::clone(&service);
        let b = Arc::clone(&barrier);
        let cid = target_cid.clone();
        let handle = thread::spawn(move || {
            b.wait();
            if i % 2 == 0 {
                // Half call submit_and_wait
                s.submit_and_wait(SubmitAndWaitRequest {
                    commands: Commands {
                        application_id: format!("app-{i}"),
                        command_id: format!("cmd-{i}"),
                        act_as: vec!["Alice".into(), "Bank".into()],
                        read_as: vec![],
                        submission_id: None,
                        workflow_id: None,
                        deduplication_period: None,
                        commands: vec![Command::Exercise(ExerciseCommand {
                            template_id: TemplateId::asset_holding(),
                            contract_id: cid,
                            choice: "Transfer".into(),
                            choice_argument: json!({ "newOwner": "Bank" }),
                        })],
                    },
                })
                .map(|_| ())
            } else {
                // Half call json_exercise
                s.json_exercise(
                    &["Alice".into(), "Bank".into()],
                    ExerciseRequest {
                        template_id: TemplateId::asset_holding(),
                        contract_id: cid,
                        choice: "Transfer".into(),
                        argument: json!({ "newOwner": "Bank" }),
                        meta: None,
                    },
                )
                .map(|_| ())
            }
        });
        handles.push(handle);
    }

    let mut successes = 0;
    let mut failures = 0;
    for h in handles {
        let res = h.join().expect("thread join");
        match res {
            Ok(()) => successes += 1,
            Err(ApiError::ContractNotActive(ref c)) if c == &target_cid => failures += 1,
            Err(other) => panic!("Unexpected error from concurrent exercise: {:?}", other),
        }
    }

    assert_eq!(
        successes, 1,
        "Exactly one concurrent submission must succeed"
    );
    assert_eq!(
        failures,
        num_threads - 1,
        "All other concurrent submissions must fail with ContractNotActive"
    );

    // Final ACS must contain exactly 1 contract (the new child contract), and target_cid must be consumed
    let acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(acs.active_contracts.len(), 1);
    assert_ne!(acs.active_contracts[0].contract_id, target_cid);

    let state = service.active_ledger_state();
    assert_eq!(state.active_contracts.len(), 1);
    assert!(!state.active_contracts.contains_key(&ContractId(target_cid)));
}

#[test]
fn test_adversarial_promotion_failure_with_corrupt_payload_bytes_aborts_cleanly() {
    // Legacy ledger with 2 contracts: first is valid, second has corrupt party with spaces
    let valid_holding = Holding {
        bank: "Bank".into(),
        owner: "Alice".into(),
        auditor: "Auditor".into(),
        symbol: "USD".into(),
        tenths: 1000,
    };
    let corrupt_holding = Holding {
        bank: "Bank@Invalid!".into(), // '@' and '!' violate Daml-LF party syntax!
        owner: "Alice".into(),
        auditor: "Auditor".into(),
        symbol: "USD".into(),
        tenths: 1000,
    };

    let ledger = SingleContractLedger {
        contracts: vec![Some(valid_holding), Some(corrupt_holding)],
        contract_ids: vec!["#0:0".into(), "#1:0".into()],
        submission_count: 0,
    };

    let service = ExecutionService::with_ledger(ledger);

    let res = service.load_dar(&sample_dar_path());
    assert!(
        matches!(&res, Err(ApiError::Internal(msg)) if msg.contains("Contract promotion failed")),
        "Expected ApiError::Internal with promotion failure message, got {:?}",
        res
    );

    // Verify DAR was NOT loaded and no partial promotion occurred
    assert!(service.dar_info().is_none());

    // generic_contracts must not have leaked promoted contract #0:0
    let acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(
        acs.active_contracts.len(),
        2,
        "Legacy ledger remains intact"
    );
}

#[test]
fn test_adversarial_mutation_resistance_commit_transaction_aborts_before_generic_mutation() {
    let service = ExecutionService::new();
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    // 1. Create initial contract C0 (#0:0)
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
        .expect("create initial contract");
    let c0_id = create_res.result.contract_id;
    assert_eq!(c0_id, "#0:0");

    let acs_initial = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(acs_initial.active_contracts.len(), 1);
    assert_eq!(acs_initial.active_contracts[0].contract_id, c0_id);

    // 2. Craft a TransactionCommit where apply_transaction MUST fail:
    // We construct a tree with Node::Exercise requiring controller "Alice",
    // but act_as_set only provides "Bob", missing required controller!
    let mut lf_tree = LfTransactionTree::new();
    let mut acting = HashSet::new();
    acting.insert("Alice".to_string());
    lf_tree.insert_node(
        Node::Exercise {
            contract_id: ContractId(c0_id.clone()),
            choice: "Transfer".into(),
            acting_parties: acting,
            consuming: true,
            children: vec![],
        },
        true,
    );

    let mut deficient_act_as = HashSet::new();
    deficient_act_as.insert("Bob".to_string()); // Missing "Alice"!

    let commit = TransactionCommit {
        consumed_cids: vec![c0_id.clone()],
        archived_cids: vec![],
        created_contracts: vec![],
        legacy_archived_cids: vec![],
        working_ledger: None,
        lf_tree,
        act_as_set: deficient_act_as,
        tx_tree_record: None,
        root_argument: None,
        engine_events: Vec::new(),
        engine_rolled_back: Vec::new(),
        engine_key_lookups: Vec::new(),
        root_by_key: false,
        root_package_id: None,
        disclosed_contracts: Vec::new(),
        history: None,
    };

    // 3. Execute commit_transaction
    let res = service.commit_transaction(commit);
    assert!(
        res.is_err(),
        "commit_transaction must fail when apply_transaction rejects: {:?}",
        res
    );

    // 4. Verify MUTATION RESISTANCE:
    // C0 must NOT have been deactivated in generic_contracts!
    let acs_after = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(
        acs_after.active_contracts.len(),
        1,
        "generic_contracts must NOT have been mutated before apply_transaction"
    );
    assert_eq!(acs_after.active_contracts[0].contract_id, c0_id);

    // C0 must still be spendable!
    let ex = service.json_exercise(
        &act_as,
        ExerciseRequest {
            template_id: TemplateId::asset_holding(),
            contract_id: c0_id,
            choice: "Transfer".into(),
            argument: json!({ "newOwner": "Bank" }),
            meta: None,
        },
    );
    assert!(ex.is_ok(), "C0 must still be spendable: {:?}", ex);
}

#[test]
fn test_concurrent_exercises_on_distinct_contracts_never_allocate_duplicate_contract_ids() {
    let service = Arc::new(ExecutionService::new());
    service
        .load_dar(&sample_dar_path())
        .expect("load sample dar");

    let num_contracts = 32;

    // Create 32 distinct initial contracts with distinct owners Alice_0..Alice_31
    let mut initial_cids = Vec::new();
    for i in 0..num_contracts {
        let payload = json!({
            "bank": "Bank",
            "owner": format!("Alice_{i}"),
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": format!("{}.0", (i + 1) * 10)
        });
        let act = vec!["Bank".to_string(), format!("Alice_{i}")];
        let res = service
            .json_create(
                &act,
                CreateRequest {
                    template_id: TemplateId::asset_holding(),
                    payload,
                    meta: None,
                },
            )
            .expect("create contract");
        initial_cids.push(res.result.contract_id);
    }
    assert_eq!(initial_cids.len(), num_contracts);

    let barrier = Arc::new(Barrier::new(num_contracts));
    let mut handles = Vec::new();

    // 32 threads concurrently exercise Transfer on their distinct contracts
    for (i, cid) in initial_cids.iter().cloned().enumerate() {
        let s = Arc::clone(&service);
        let b = Arc::clone(&barrier);
        let act = vec!["Bank".to_string(), format!("Alice_{i}")];
        let handle = thread::spawn(move || {
            b.wait();
            let ex_req = ExerciseRequest {
                template_id: TemplateId::asset_holding(),
                contract_id: cid,
                choice: "Transfer".into(),
                argument: json!({ "newOwner": "Bank" }),
                meta: None,
            };
            s.json_exercise(&act, ex_req)
        });
        handles.push(handle);
    }

    let mut new_cids = Vec::new();
    for h in handles {
        let res = h
            .join()
            .expect("thread join")
            .expect("exercise must succeed");
        // Extract child contract ID from ExerciseResponse
        // In Transfer, the result value is the ContractId of the newly created holding
        let returned_cid = match res.result.exercise_result {
            Some(serde_json::Value::String(cid)) => cid,
            other => panic!("Expected string contract ID, got {:?}", other),
        };
        new_cids.push(returned_cid);
    }

    assert_eq!(
        new_cids.len(),
        num_contracts,
        "All 32 concurrent exercises must have succeeded and returned a contract ID"
    );

    // Verify all 32 newly created contract IDs are strictly unique (NO duplicates!)
    let unique_new_cids: HashSet<_> = new_cids.iter().cloned().collect();
    assert_eq!(
        unique_new_cids.len(),
        num_contracts,
        "CRITICAL: Duplicate contract ID allocated during concurrent exercises! Total: {}, Unique: {}",
        new_cids.len(),
        unique_new_cids.len()
    );

    // Verify final ACS has exactly 32 active contracts and all IDs match unique_new_cids
    let acs = service.get_active_contracts(&[]).expect("get acs");
    assert_eq!(acs.active_contracts.len(), num_contracts);
    let acs_cids: HashSet<_> = acs
        .active_contracts
        .into_iter()
        .map(|c| c.contract_id)
        .collect();
    assert_eq!(acs_cids, unique_new_cids);
}
