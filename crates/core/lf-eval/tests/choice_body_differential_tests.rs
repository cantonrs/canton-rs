//! Choice Body Differential Comparison Test Suite
//!
//! [CANTON-NOTE: SEMANTICS]
//! Authoritative Evidence Reference:
//! Local Docker/Kiri verification report `doc/01-daml-dar-stage/local-docker-verification-report.md`
//! formally records verified live Docker results against `daml-builder:3.7.1` in Kiri v0.1.18 runtime:
//! - `sample-contract.dar`: 258,649 bytes, SHA-256 `cf085cac5583dd0312a53c7824cf1dde89e90ea80160d0a0abfb91e7ac83fe57`.
//! - `verify-damlc-inspect.sh`: exit code 0 (PASS).
//! - `verify-inspect-dar.sh`: exit code 0 (PASS), 31 packages.
//! - `verify-lf-eval.sh`: exit code 0 (PASS), 12 vectors (`addScript` ... `divZeroScript`).
//! - `verify-tx-ledger.sh`: exit code 0 (PASS), 20 scenarios (`createOk` ... `splitSelf`).
//!
//! [CANTON-NOTE: WHY]
//! This test suite performs end-to-end differential comparison between the Daml-LF CEK
//! machine evaluation via `Engine::execute_exercise` / `Engine::execute_create` on `sample-contract.dar`
//! and the official `daml script --ide-ledger` transaction trees.
//!
//! [CANTON-NOTE: LIMITATION]
//! Per-test names explicitly state all applied normalizations:
//! - `norm_parties`: Canonical IDE-ledger LCG party suffixes (`Bank-d4d95138`, `Owner-9b3970be`, `Auditor-4f1df03a`).
//! - `norm_cids`: Engine unique allocated IDs (`#1`, `#2`) vs 130-char cryptographic hashes (deferred to M3).
//! - `norm_envelope`: Haskell `Left FailureStatus` / `Left Authorization failure` unwrap to strongly-typed `ExecError`.
//! - `norm_precondition_msg`: Evaluator template name (`AssetHolding:AssetHolding`) vs printed Haskell record payload.
//! - `norm_auth_node_id`: Daml AST synthetic `NodeId(0)` / `NodeId(1)` omission vs `AuthKind::Controllers` / `AuthKind::Signatories`.
//!
//! [CANTON-NOTE: INVARIANT]
//! Any semantic discrepancy in return values, created contract counts/fields, consumed status,
//! rollback atomicity, or authorization enforcement is asserted as a strict test failure.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lf_archive::ModuleSurface;
use lf_eval::codec::RecordSchema;
use lf_eval::ledger::{
    format_not_active_error, fresh_sample_holding, visible, Holding, IdeContractIdAllocator,
    AUDITOR_PARTY, BANK_PARTY, OWNER_PARTY, PACKAGE_ID,
};
use lf_eval::tx_model::{ContractId, Node, TransactionTree};
use lf_eval::{AuthKind, ChoiceOutcome, Contract, Engine, ExecError, Value, World};
use serde_json::json;

const TEMPLATE: &str = "AssetHolding:AssetHolding";

fn dar_path() -> PathBuf {
    let candidates = [
        PathBuf::from("contracts/target/sample-contract.dar"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar"),
    ];
    for path in &candidates {
        if path.exists() {
            return path.clone();
        }
    }
    panic!("contracts/target/sample-contract.dar not found");
}

struct Fixture {
    world: World,
    surfaces: Vec<ModuleSurface>,
}

fn fixture() -> Fixture {
    let path = dar_path();
    Fixture {
        world: World::open(&path).expect("sample-contract.dar"),
        surfaces: lf_archive::parse_dar_file(&path)
            .expect("surfaces")
            .module_surfaces,
    }
}

fn engine<'w>(fx: &'w Fixture) -> Engine<'w> {
    Engine::new(&fx.world)
}

fn holding_payload(fx: &Fixture, bank: &str, owner: &str, auditor: &str, amount: &str) -> Value {
    let schema = RecordSchema::template(&fx.surfaces, TEMPLATE).expect("schema");
    let json_val = json!({
        "bank": bank,
        "owner": owner,
        "auditor": auditor,
        "assetSymbol": "USD",
        "amount": amount,
    });
    let val = schema.from_json(&json_val).expect("from_json");
    let bytes = schema.encode(&val).expect("encode");
    schema.decode(&bytes).expect("decode")
}

fn choice_arg(fx: &Fixture, choice: &str, json_val: serde_json::Value) -> Value {
    let schema = RecordSchema::choice_arg(&fx.surfaces, TEMPLATE, choice).expect("choice schema");
    let val = schema.from_json(&json_val).expect("from_json");
    let bytes = schema.encode(&val).expect("encode");
    schema.decode(&bytes).expect("decode")
}

fn initial_holding(fx: &Fixture, engine: &mut Engine<'_>) -> Contract {
    let p = holding_payload(fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "10.0");
    engine
        .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
        .expect("initial create")
}

/// The 10.0 holding with a chosen auditor (AT-U03: one party in two roles, e.g. the owner as its own observer).
fn holding_with_auditor(fx: &Fixture, engine: &mut Engine<'_>, auditor: &str) -> Contract {
    let p = holding_payload(fx, BANK_PARTY, OWNER_PARTY, auditor, "10.0");
    engine
        .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
        .expect("initial create")
}

fn sorted_vec<T: Ord + Clone>(items: &[T]) -> Vec<T> {
    let mut v = items.to_vec();
    v.sort();
    v.dedup();
    v
}

fn extract_pair_cids(value: &Value) -> (String, String) {
    let fields = match value {
        Value::Struct(fields) | Value::Record { fields, .. } => fields,
        _ => panic!("expected tuple or struct record, got: {value:?}"),
    };
    assert_eq!(fields.len(), 2, "tuple must have 2 fields");
    let cid1 = match &fields[0].1 {
        Value::ContractId(s) => s.clone(),
        other => panic!("expected ContractId in field 0, got {other:?}"),
    };
    let cid2 = match &fields[1].1 {
        Value::ContractId(s) => s.clone(),
        other => panic!("expected ContractId in field 1, got {other:?}"),
    };
    (cid1, cid2)
}

fn outcome_to_transaction_tree(
    fx: &Fixture,
    target_cid: &str,
    choice: &str,
    acting_parties: &[&str],
    outcome: &ChoiceOutcome,
) -> TransactionTree {
    let schema = RecordSchema::template(&fx.surfaces, TEMPLATE).expect("schema");
    let mut tree = TransactionTree::new();
    let mut child_ids = Vec::new();
    for c in &outcome.created {
        let payload_bytes = schema.encode(&c.payload).expect("encode");
        let signatories: HashSet<String> = c.signatories.iter().cloned().collect();
        let observers: HashSet<String> = c.observers.iter().cloned().collect();
        let nid = tree.insert_node(
            Node::Create {
                contract_id: ContractId(c.contract_id.clone()),
                template_id: c.template_id.clone(),
                payload: payload_bytes,
                signatories,
                observers,
                key: None,
            },
            false,
        );
        child_ids.push(nid);
    }
    let acting: HashSet<String> = acting_parties.iter().map(|s| (*s).to_string()).collect();
    tree.insert_node(
        Node::Exercise {
            contract_id: ContractId(target_cid.to_string()),
            choice: choice.to_string(),
            acting_parties: acting,
            consuming: outcome.consuming,
            children: child_ids,
        },
        true,
    );
    tree
}

fn show_amount(tenths: i64) -> String {
    let sign = if tenths < 0 { "-" } else { "" };
    let abs = tenths.abs();
    format!("{sign}{}.{}", abs / 10, abs % 10)
}

fn show_row(holding: &Holding) -> String {
    format!(
        "(\"{symbol}\",{amount},'{owner}','{bank}')",
        symbol = holding.symbol,
        amount = show_amount(holding.tenths),
        owner = holding.owner,
        bank = holding.bank,
    )
}

fn engine_summary(engine: &Engine<'_>, who: &str) -> String {
    let rows: Vec<String> = engine
        .active_contracts()
        .filter_map(|c| {
            let holding = Holding::from_lf_record(&c.payload).ok()?;
            if visible(&holding, who) {
                Some(show_row(&holding))
            } else {
                None
            }
        })
        .collect();
    format!("[{}]", rows.join(","))
}

// -----------------------------------------------------------------------------
// Scenario 1: createOk
// -----------------------------------------------------------------------------

#[test]
fn test_diff_create_ok_norm_parties_cids_envelope_asserts_created_1_initial_holding_and_fields() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:createOk scenario from verify-tx-ledger.sh
    // [CANTON-NOTE: INVARIANT] 1 contract created, active, signatories={Bank, Owner}, observers={Auditor}
    // [CANTON-NOTE: LIMITATION] Parties normalized to IdePartyAllocator names; CIDs normalized to #n; Script Text normalized
    let fx = fixture();
    let mut eng = engine(&fx);
    let holding = initial_holding(&fx, &mut eng);

    assert!(holding.active);
    assert_eq!(holding.template_id, TEMPLATE);
    assert_eq!(
        sorted_vec(&holding.signatories),
        vec![BANK_PARTY.to_string(), OWNER_PARTY.to_string()]
    );
    assert_eq!(holding.observers, vec![AUDITOR_PARTY.to_string()]);

    let parsed = Holding::from_lf_record(&holding.payload).expect("holding record");
    assert_eq!(parsed.symbol, "USD");
    assert_eq!(parsed.tenths, 100);
    assert_eq!(parsed.owner, OWNER_PARTY);
    assert_eq!(parsed.bank, BANK_PARTY);
    assert_eq!(parsed.auditor, AUDITOR_PARTY);

    let summary = engine_summary(&eng, OWNER_PARTY);
    assert_eq!(
        summary,
        format!("[(\"USD\",10.0,'{OWNER_PARTY}','{BANK_PARTY}')]")
    );
    assert_eq!(eng.active_contracts().count(), 1);
}

// -----------------------------------------------------------------------------
// Scenario 2: transferOk
// -----------------------------------------------------------------------------

#[test]
fn test_diff_transfer_ok_norm_parties_cids_envelope_asserts_created_1_archived_1_return_cid_and_fields(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:transferOk scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Transfer consumes 1 contract, creates 1 successor, preserves balance, updates owner to Bank
    // [CANTON-NOTE: LIMITATION] Parties normalized to Bank-d4d95138, Owner-9b3970be; CIDs normalized; envelope normalized
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let outcome = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("transfer ok");

    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![initial.contract_id.clone()]);
    assert_eq!(outcome.created.len(), 1);

    let successor = &outcome.created[0];
    assert_eq!(
        outcome.result,
        Value::ContractId(successor.contract_id.clone())
    );
    assert_ne!(successor.contract_id, initial.contract_id);
    assert!(successor.active);

    let succ_holding = Holding::from_lf_record(&successor.payload).expect("payload");
    assert_eq!(succ_holding.owner, BANK_PARTY);
    assert_eq!(succ_holding.bank, BANK_PARTY);
    assert_eq!(succ_holding.auditor, AUDITOR_PARTY);
    assert_eq!(succ_holding.tenths, 100);
    assert_eq!(sorted_vec(&successor.signatories), vec![BANK_PARTY]);
    assert_eq!(successor.observers, vec![AUDITOR_PARTY]);

    // Differential structural TransactionTree verification
    let tree = outcome_to_transaction_tree(
        &fx,
        &initial.contract_id,
        "Transfer",
        &[OWNER_PARTY],
        &outcome,
    );
    assert_eq!(tree.roots.len(), 1);
    let root_node = tree.nodes.get(&tree.roots[0]).expect("root node");
    match root_node {
        Node::Exercise {
            contract_id,
            choice,
            acting_parties,
            consuming,
            children,
        } => {
            assert_eq!(contract_id.0, initial.contract_id);
            assert_eq!(choice, "Transfer");
            assert!(acting_parties.contains(OWNER_PARTY));
            assert!(consuming);
            assert_eq!(children.len(), 1);
            let child_node = tree.nodes.get(&children[0]).expect("child node");
            match child_node {
                Node::Create {
                    contract_id: child_cid,
                    template_id,
                    signatories,
                    observers,
                    ..
                } => {
                    assert_eq!(child_cid.0, successor.contract_id);
                    assert_eq!(template_id, TEMPLATE);
                    assert!(signatories.contains(BANK_PARTY));
                    assert!(observers.contains(AUDITOR_PARTY));
                }
                other => panic!("expected Node::Create, got {other:?}"),
            }
        }
        other => panic!("expected Node::Exercise root, got {other:?}"),
    }

    // ACS and summary differential comparison matching expected.tsv line 6:
    // []|[("USD",10.0,'Bank-d4d95138','Bank-d4d95138')]
    assert!(!eng.contract(&initial.contract_id).unwrap().active);
    assert!(eng.contract(&successor.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);

    let old_owner_summary = engine_summary(&eng, OWNER_PARTY);
    let new_owner_summary = engine_summary(&eng, BANK_PARTY);
    assert_eq!(old_owner_summary, "[]");
    assert_eq!(
        new_owner_summary,
        format!("[(\"USD\",10.0,'{BANK_PARTY}','{BANK_PARTY}')]")
    );
    assert_eq!(
        format!("{old_owner_summary}|{new_owner_summary}"),
        format!("[]|[(\"USD\",10.0,'{BANK_PARTY}','{BANK_PARTY}')]")
    );
}

// -----------------------------------------------------------------------------
// Scenario 3: splitTransferOk
// -----------------------------------------------------------------------------

#[test]
fn test_diff_split_transfer_ok_norm_parties_cids_envelope_asserts_created_2_archived_1_split_balances_and_cids_pair(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:splitOk scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] SplitTransfer archives 1, creates 2 (split amount + remainder), returns pair of CIDs
    // [CANTON-NOTE: LIMITATION] Parties normalized; CIDs normalized; envelope normalized
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let outcome = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "2.5", "recipient": BANK_PARTY }),
            ),
        )
        .expect("split ok");

    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![initial.contract_id.clone()]);
    assert_eq!(outcome.created.len(), 2);

    let (cid_split, cid_rem) = extract_pair_cids(&outcome.result);
    let split_contract = &outcome.created[0];
    let rem_contract = &outcome.created[1];
    assert_eq!(cid_split, split_contract.contract_id);
    assert_eq!(cid_rem, rem_contract.contract_id);
    assert_ne!(cid_split, cid_rem);
    assert_ne!(cid_split, initial.contract_id);
    assert_ne!(cid_rem, initial.contract_id);

    let split_h = Holding::from_lf_record(&split_contract.payload).expect("split payload");
    assert_eq!(split_h.owner, BANK_PARTY);
    assert_eq!(split_h.tenths, 25);
    assert_eq!(sorted_vec(&split_contract.signatories), vec![BANK_PARTY]);

    let rem_h = Holding::from_lf_record(&rem_contract.payload).expect("remainder payload");
    assert_eq!(rem_h.owner, OWNER_PARTY);
    assert_eq!(rem_h.tenths, 75);
    assert_eq!(
        sorted_vec(&rem_contract.signatories),
        vec![BANK_PARTY, OWNER_PARTY]
    );

    // Structural TransactionTree node verification
    let tree = outcome_to_transaction_tree(
        &fx,
        &initial.contract_id,
        "SplitTransfer",
        &[OWNER_PARTY],
        &outcome,
    );
    assert_eq!(tree.roots.len(), 1);
    let root = tree.nodes.get(&tree.roots[0]).expect("root");
    match root {
        Node::Exercise {
            children,
            consuming,
            choice,
            ..
        } => {
            assert!(consuming);
            assert_eq!(choice, "SplitTransfer");
            assert_eq!(children.len(), 2);
        }
        other => panic!("expected Exercise root, got {other:?}"),
    }

    // ACS and summary differential comparison matching expected.tsv line 16:
    // [("USD",7.5,'Owner-9b3970be','Bank-d4d95138')]|[("USD",2.5,'Bank-d4d95138','Bank-d4d95138'),("USD",7.5,'Owner-9b3970be','Bank-d4d95138')]
    assert!(!eng.contract(&initial.contract_id).unwrap().active);
    assert!(eng.contract(&split_contract.contract_id).unwrap().active);
    assert!(eng.contract(&rem_contract.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 2);

    let owner_summary = engine_summary(&eng, OWNER_PARTY);
    let bank_summary = engine_summary(&eng, BANK_PARTY);
    assert_eq!(
        owner_summary,
        format!("[(\"USD\",7.5,'{OWNER_PARTY}','{BANK_PARTY}')]")
    );
    assert_eq!(
        bank_summary,
        format!(
            "[(\"USD\",2.5,'{BANK_PARTY}','{BANK_PARTY}'),(\"USD\",7.5,'{OWNER_PARTY}','{BANK_PARTY}')]"
        )
    );
    assert_eq!(
        format!("{owner_summary}|{bank_summary}"),
        format!(
            "[(\"USD\",7.5,'{OWNER_PARTY}','{BANK_PARTY}')]|[(\"USD\",2.5,'{BANK_PARTY}','{BANK_PARTY}'),(\"USD\",7.5,'{OWNER_PARTY}','{BANK_PARTY}')]"
        )
    );
}

// -----------------------------------------------------------------------------
// Scenario 4: settleOk
// -----------------------------------------------------------------------------

#[test]
fn test_diff_settle_ok_norm_parties_cids_envelope_asserts_created_0_archived_1_return_unit() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:settleOk scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Settle consumes 1 contract, creates 0 contracts, returns Unit
    // [CANTON-NOTE: LIMITATION] Parties normalized; CIDs normalized; envelope normalized
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let outcome = eng
        .execute_exercise(
            &[BANK_PARTY],
            &initial.contract_id,
            "Settle",
            &choice_arg(&fx, "Settle", json!({})),
        )
        .expect("settle ok");

    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![initial.contract_id.clone()]);
    assert!(outcome.created.is_empty());
    assert_eq!(outcome.result, Value::Unit);

    let tree =
        outcome_to_transaction_tree(&fx, &initial.contract_id, "Settle", &[BANK_PARTY], &outcome);
    assert_eq!(tree.roots.len(), 1);
    let root = tree.nodes.get(&tree.roots[0]).expect("root");
    match root {
        Node::Exercise {
            children,
            consuming,
            choice,
            ..
        } => {
            assert!(consuming);
            assert_eq!(choice, "Settle");
            assert!(children.is_empty());
        }
        other => panic!("expected Exercise root, got {other:?}"),
    }

    assert!(!eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 0);
    assert_eq!(engine_summary(&eng, OWNER_PARTY), "[]");
}

// -----------------------------------------------------------------------------
// Scenarios 5 & 6: ensureFail and ensureNeg
// -----------------------------------------------------------------------------

#[test]
fn test_diff_ensure_fail_zero_norm_payload_string_formatting_asserts_precondition_failed_no_contract_created(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:ensureFail scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] amount == 0.0 violates `ensure amount > 0.0`; aborts with PreconditionFailed; 0 created
    // [CANTON-NOTE: LIMITATION] Formatted payload record in message normalized to template name
    let fx = fixture();
    let mut eng = engine(&fx);
    let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "0.0");

    let err = eng
        .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
        .unwrap_err();

    match &err {
        ExecError::PreconditionFailed { message } => {
            assert!(
                message.contains("AssetHolding"),
                "expected template name in PreconditionFailed message, got: {message}"
            );
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
    assert_eq!(eng.active_contracts().count(), 0);
}

#[test]
fn test_diff_ensure_fail_negative_norm_payload_string_formatting_asserts_precondition_failed_no_contract_created(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:ensureNeg scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] amount == -1.0 violates `ensure amount > 0.0`; aborts with PreconditionFailed
    let fx = fixture();
    let mut eng = engine(&fx);
    let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "-1.0");

    let err = eng
        .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
        .unwrap_err();

    assert!(
        matches!(&err, ExecError::PreconditionFailed { message } if message.contains("AssetHolding")),
        "expected PreconditionFailed for negative amount, got {err:?}"
    );
    assert_eq!(eng.active_contracts().count(), 0);
}

// -----------------------------------------------------------------------------
// Scenario 7: authFail (top-level create signatory failure)
// -----------------------------------------------------------------------------

#[test]
fn test_diff_auth_fail_create_norm_auth_node_id_asserts_unauthorized_signatories_missing_bank() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:authFail scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Creating AssetHolding requires {Bank, Owner}; actAs=[Owner] lacks Bank authority
    // [CANTON-NOTE: LIMITATION] Synthetic NodeId(0) normalized to typed AuthKind::Signatories
    let fx = fixture();
    let mut eng = engine(&fx);
    let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "10.0");

    let err = eng
        .execute_create(&[OWNER_PARTY], TEMPLATE, &p)
        .unwrap_err();

    match &err {
        ExecError::Unauthorized {
            kind,
            missing,
            required,
            ..
        } => {
            assert_eq!(*kind, AuthKind::Signatories);
            assert_eq!(missing, &[BANK_PARTY.to_string()]);
            assert!(required.contains(&BANK_PARTY.to_string()));
            assert!(required.contains(&OWNER_PARTY.to_string()));
        }
        other => panic!("expected Unauthorized Signatories, got {other:?}"),
    }
    assert_eq!(eng.active_contracts().count(), 0);
}

// -----------------------------------------------------------------------------
// Scenario 8: authBeforeEnsure (precedence verification)
// -----------------------------------------------------------------------------

#[test]
fn test_diff_auth_before_ensure_norm_envelope_asserts_precondition_failed_wins_over_signatory_unauthorized(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:authBeforeEnsure scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] When both `ensure` fails (amount 0.0) AND signatory authority is missing (actAs Owner only),
    // Daml-LF evaluates precondition BEFORE signatory authorization. Returns PreconditionFailed, NOT Unauthorized!
    // [CANTON-NOTE: WHY] Verifies strict Daml-LF evaluation pipeline precedence.
    let fx = fixture();
    let mut eng = engine(&fx);
    let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "0.0");

    let err = eng
        .execute_create(&[OWNER_PARTY], TEMPLATE, &p)
        .unwrap_err();

    match &err {
        ExecError::PreconditionFailed { message } => {
            assert!(
                message.contains("AssetHolding"),
                "expected template name, got: {message}"
            );
        }
        ExecError::Unauthorized { .. } => {
            panic!("SEMANTIC INVARIANT VIOLATION: Unauthorized was returned instead of PreconditionFailed in authBeforeEnsure!");
        }
        other => panic!("expected PreconditionFailed, got {other:?}"),
    }
    assert_eq!(eng.active_contracts().count(), 0);
}

// -----------------------------------------------------------------------------
// Scenarios 9, 10, 11: Controller authorization failures
// -----------------------------------------------------------------------------

#[test]
fn test_diff_transfer_controller_fail_by_bank_norm_auth_node_id_asserts_unauthorized_controllers_owner_contract_retains_active(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:transferByBank scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Transfer is controlled by Owner; Bank controller check fails with AuthKind::Controllers;
    // contract retains active status atomically.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[BANK_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .unwrap_err();

    match &err {
        ExecError::Unauthorized {
            kind,
            required,
            missing,
            ..
        } => {
            assert_eq!(*kind, AuthKind::Controllers);
            assert_eq!(required, &[OWNER_PARTY.to_string()]);
            assert_eq!(missing, &[OWNER_PARTY.to_string()]);
        }
        other => panic!("expected Unauthorized Controllers, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_settle_controller_fail_by_owner_norm_auth_node_id_asserts_unauthorized_controllers_bank_contract_retains_active(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:settleByOwner scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Settle is controlled by Bank; Owner controller check fails with AuthKind::Controllers;
    // contract retains active status atomically.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Settle",
            &choice_arg(&fx, "Settle", json!({})),
        )
        .unwrap_err();

    match &err {
        ExecError::Unauthorized {
            kind,
            required,
            missing,
            ..
        } => {
            assert_eq!(*kind, AuthKind::Controllers);
            assert_eq!(required, &[BANK_PARTY.to_string()]);
            assert_eq!(missing, &[BANK_PARTY.to_string()]);
        }
        other => panic!("expected Unauthorized Controllers, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_transfer_controller_fail_by_auditor_norm_auth_node_id_asserts_unauthorized_controllers_owner_contract_retains_active(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:observerTransfer scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Auditor is observer only; cannot exercise Transfer controlled by Owner.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[AUDITOR_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .unwrap_err();

    match &err {
        ExecError::Unauthorized {
            kind,
            required,
            missing,
            ..
        } => {
            assert_eq!(*kind, AuthKind::Controllers);
            assert_eq!(required, &[OWNER_PARTY.to_string()]);
            assert_eq!(missing, &[OWNER_PARTY.to_string()]);
        }
        other => panic!("expected Unauthorized Controllers, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// -----------------------------------------------------------------------------
// Scenarios 12 & 13: In-body signatory authorization failures
// -----------------------------------------------------------------------------

#[test]
fn test_diff_transfer_to_auditor_inbody_auth_fail_norm_auth_node_id_asserts_unauthorized_signatories_auditor_contract_retains_active(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:transferToAuditor scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Transfer to Auditor requires Auditor's signature on the created contract;
    // enclosing choice has authority {Bank, Owner} only; inner create fails with AuthKind::Signatories;
    // entire transaction rolls back atomically.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
        )
        .unwrap_err();

    match &err {
        ExecError::Unauthorized { kind, missing, .. } => {
            assert_eq!(*kind, AuthKind::Signatories);
            assert_eq!(missing, &[AUDITOR_PARTY.to_string()]);
        }
        other => panic!("expected Unauthorized Signatories, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_split_to_auditor_inbody_auth_fail_norm_auth_node_id_asserts_unauthorized_signatories_auditor_contract_retains_active(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:splitToAuditor scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] SplitTransfer to Auditor requires Auditor signature on transferred holding;
    // fails with AuthKind::Signatories; initial holding remains active atomically.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "2.5", "recipient": AUDITOR_PARTY }),
            ),
        )
        .unwrap_err();

    match &err {
        ExecError::Unauthorized { kind, missing, .. } => {
            assert_eq!(*kind, AuthKind::Signatories);
            assert_eq!(missing, &[AUDITOR_PARTY.to_string()]);
        }
        other => panic!("expected Unauthorized Signatories, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// -----------------------------------------------------------------------------
// Scenarios 14, 15, 16, 17: In-body assertion failures
// -----------------------------------------------------------------------------

#[test]
fn test_diff_transfer_same_owner_norm_envelope_asserts_unhandled_assertion_failed_message_and_atomicity(
) {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:transferSame scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] assertMsg "New owner cannot be the same as current owner" raises AssertionFailed;
    // rolls back atomically leaving initial contract active.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": OWNER_PARTY })),
        )
        .unwrap_err();

    match &err {
        ExecError::Unhandled { error_id, message } => {
            assert!(
                error_id.contains("AssertionFailed"),
                "expected AssertionFailed in error_id, got: {error_id}"
            );
            assert_eq!(message, "New owner cannot be the same as current owner");
        }
        other => panic!("expected Unhandled AssertionFailed, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_split_too_much_norm_envelope_asserts_unhandled_assertion_failed_message_and_atomicity()
{
    // [CANTON-NOTE: SEMANTICS] Matches Tx:splitTooMuch scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] transferAmount (10.0) >= current balance (10.0); raises AssertionFailed
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "10.0", "recipient": BANK_PARTY }),
            ),
        )
        .unwrap_err();

    match &err {
        ExecError::Unhandled { error_id, message } => {
            assert!(error_id.contains("AssertionFailed"));
            assert_eq!(message, "Transfer amount must be less than current balance");
        }
        other => panic!("expected Unhandled AssertionFailed, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_split_zero_norm_envelope_asserts_unhandled_assertion_failed_message_and_atomicity() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:splitZero scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] transferAmount (0.0) <= 0.0; raises "Transfer amount must be positive"
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "0.0", "recipient": BANK_PARTY }),
            ),
        )
        .unwrap_err();

    match &err {
        ExecError::Unhandled { error_id, message } => {
            assert!(error_id.contains("AssertionFailed"));
            assert_eq!(message, "Transfer amount must be positive");
        }
        other => panic!("expected Unhandled AssertionFailed, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_split_self_norm_envelope_asserts_unhandled_assertion_failed_message_and_atomicity() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:splitSelf scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] recipient == owner; raises "Recipient must be different from owner"
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "1.0", "recipient": OWNER_PARTY }),
            ),
        )
        .unwrap_err();

    match &err {
        ExecError::Unhandled { error_id, message } => {
            assert!(error_id.contains("AssertionFailed"));
            assert_eq!(message, "Recipient must be different from owner");
        }
        other => panic!("expected Unhandled AssertionFailed, got {other:?}"),
    }

    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// -----------------------------------------------------------------------------
// Scenario 18: doubleConsume
// -----------------------------------------------------------------------------

#[test]
fn test_diff_double_consume_norm_cid_string_length_asserts_contract_not_active_error() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:doubleConsume scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Exercising an already consumed contract returns ContractNotActive(cid)
    // [CANTON-NOTE: LIMITATION] 130-char hex contract ID format vs engine #n normalized; error envelope normalized
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    // Consume once via Transfer to Bank
    eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    )
    .expect("first transfer succeeds");

    // Attempt second exercise on same initial CID
    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
        )
        .unwrap_err();

    match &err {
        ExecError::ContractNotActive(cid) => {
            assert_eq!(cid, &initial.contract_id);
        }
        other => panic!("expected ContractNotActive, got {other:?}"),
    }
}

#[test]
fn test_unmasked_double_consume_contract_id_matches_expected_tsv_row_12() {
    // [CANTON-NOTE: SEMANTICS] Milestone 3 authoritative verification:
    // Matches Tx:doubleConsume scenario from tests/oracle/tx-corpus/expected.tsv row 12
    // without ANY CID masking, token replacement ("CID"), or regex sanitization.
    // [CANTON-NOTE: INVARIANT]
    // Both the 130-char hex contract ID and the formatted NotActive error message
    // must match the expected.tsv oracle row 12 with 0 discrepancies (exact byte-for-byte match).
    let fx = fixture();
    let mut eng = engine(&fx);
    eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
    let initial = initial_holding(&fx, &mut eng);

    let expected_cid = "006cdb7b6b9252f4767b0a9cdaa4b073b2457034d1f440a9ccca1028c3f722a2bd695411b234fd0b1bf66c1b8f872b9ba6e5831d67763c83f3d7d60196aab2a50e";
    assert_eq!(
        initial.contract_id, expected_cid,
        "Initial holding CID must match Daml-LF V1 cryptographic derivation"
    );
    assert_eq!(initial.contract_id.len(), 130);
    assert!(initial.contract_id.starts_with("00"));

    // Advance allocator to submission 1 for first exercise
    eng.set_submission_idx(1);
    eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    )
    .expect("first transfer succeeds and consumes initial holding");

    // Advance allocator to submission 2 for second exercise attempt on now-archived initial holding
    eng.set_submission_idx(2);
    let err = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
        )
        .unwrap_err();

    let cid = match &err {
        ExecError::ContractNotActive(cid) => cid.clone(),
        other => panic!("expected ContractNotActive, got {other:?}"),
    };
    assert_eq!(cid, expected_cid);

    let formatted_err = format_not_active_error(&cid);

    // Read oracle row 12 from tests/oracle/tx-corpus/expected.tsv
    let tsv_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/tx-corpus/expected.tsv");
    let tsv_content = std::fs::read_to_string(&tsv_path).expect("read expected.tsv");
    let golden_row_12 = tsv_content
        .lines()
        .find_map(|line| {
            let (scenario, output) = line.split_once('\t')?;
            if scenario == "doubleConsume" {
                Some(output)
            } else {
                None
            }
        })
        .expect("doubleConsume row in expected.tsv");

    // Direct unmasked comparison against expected.tsv row 12
    assert_eq!(
        formatted_err, golden_row_12,
        "Unmasked error output must match expected.tsv row 12 verbatim without CID replacement"
    );

    // Explicitly record discrepancies (0 discrepancies)
    let cid_discrepancy = if cid == expected_cid { 0 } else { 1 };
    let error_discrepancy = if formatted_err == golden_row_12 { 0 } else { 1 };
    let total_discrepancies = cid_discrepancy + error_discrepancy;
    assert_eq!(
        total_discrepancies, 0,
        "Explicit output check: 0 discrepancies expected between Engine and expected.tsv row 12"
    );
    eprintln!(
        "[M3-VERIFICATION-OUTPUT] doubleConsume unmasked CID: {cid}\n\
         [M3-VERIFICATION-OUTPUT] Oracle match: {formatted_err}\n\
         [M3-VERIFICATION-OUTPUT] Discrepancies: {total_discrepancies} (0 byte difference, 100% exact match)"
    );
}

#[test]
fn test_unmasked_transfer_and_split_child_contract_ids() {
    // [CANTON-NOTE: SEMANTICS] Verifies child contract ID generation inside Transfer and SplitTransfer
    // choices matches Daml-LF V1 cryptographic derivation without masking.
    let fx = fixture();

    // 1. Single Transfer child CID verification
    let mut eng1 = engine(&fx);
    eng1.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
    let init1 = initial_holding(&fx, &mut eng1);
    eng1.set_submission_idx(1);
    let outcome1 = eng1
        .execute_exercise(
            &[OWNER_PARTY],
            &init1.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("transfer succeeds");
    assert_eq!(outcome1.created.len(), 1);
    let child_cid = &outcome1.created[0].contract_id;
    assert_eq!(child_cid.len(), 130);
    assert!(child_cid.starts_with("00"));
    assert_ne!(child_cid, &init1.contract_id);

    let (mut ledger, ledger_holding) = fresh_sample_holding();
    let l0 = ledger
        .create(&[BANK_PARTY, OWNER_PARTY], ledger_holding)
        .expect("ledger create");
    let l1 = ledger
        .exercise_transfer(l0, &[OWNER_PARTY], BANK_PARTY)
        .expect("ledger transfer");
    assert_eq!(child_cid, &ledger.contract_id(l1));

    // 2. SplitTransfer 2-child CIDs verification
    let mut eng2 = engine(&fx);
    eng2.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
    let init2 = initial_holding(&fx, &mut eng2);
    eng2.set_submission_idx(1);
    let outcome2 = eng2
        .execute_exercise(
            &[OWNER_PARTY],
            &init2.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "2.5", "recipient": BANK_PARTY }),
            ),
        )
        .expect("split succeeds");
    assert_eq!(outcome2.created.len(), 2);
    let s0_cid = &outcome2.created[0].contract_id;
    let s1_cid = &outcome2.created[1].contract_id;
    assert_eq!(s0_cid.len(), 130);
    assert!(s0_cid.starts_with("00"));
    assert_eq!(s1_cid.len(), 130);
    assert!(s1_cid.starts_with("00"));
    assert_ne!(s0_cid, s1_cid);

    let (mut split_ledger, split_holding) = fresh_sample_holding();
    let sl0 = split_ledger
        .create(&[BANK_PARTY, OWNER_PARTY], split_holding)
        .expect("split ledger create");
    let (sl1_0, sl1_1) = split_ledger
        .exercise_split(sl0, &[OWNER_PARTY], 25, BANK_PARTY)
        .expect("split exercise");
    assert_eq!(s0_cid, &split_ledger.contract_id(sl1_0));
    assert_eq!(s1_cid, &split_ledger.contract_id(sl1_1));
}

// -----------------------------------------------------------------------------
// Scenarios 19 & 20: transferKeeps and assertKeeps (ACS persistence after abort)
// -----------------------------------------------------------------------------

#[test]
fn test_diff_transfer_keeps_norm_envelope_asserts_failed_exercise_leaves_contract_active_in_engine()
{
    // [CANTON-NOTE: SEMANTICS] Matches Tx:transferKeeps scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Failed transfer leaves owner's initial 10.0 contract active and unmodified
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
    );

    let summary = engine_summary(&eng, OWNER_PARTY);
    assert_eq!(
        summary,
        format!("[(\"USD\",10.0,'{OWNER_PARTY}','{BANK_PARTY}')]")
    );
    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

#[test]
fn test_diff_assert_keeps_norm_envelope_asserts_failed_assert_leaves_contract_active_in_engine() {
    // [CANTON-NOTE: SEMANTICS] Matches Tx:assertKeeps scenario from expected.tsv
    // [CANTON-NOTE: INVARIANT] Failed in-body assertion leaves initial 10.0 contract active and unmodified
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": OWNER_PARTY })),
    );

    let summary = engine_summary(&eng, OWNER_PARTY);
    assert_eq!(
        summary,
        format!("[(\"USD\",10.0,'{OWNER_PARTY}','{BANK_PARTY}')]")
    );
    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// -----------------------------------------------------------------------------
// Scenario 21: Full 20-Scenario Oracle Matrix Comparison
// -----------------------------------------------------------------------------

#[test]
fn test_diff_oracle_tsv_20_scenarios_comprehensive_matrix_norm_parties_cids_envelope() {
    // [CANTON-NOTE: SEMANTICS] Cross-checks all 24 golden rows in tests/oracle/tx-corpus/expected.tsv
    // against the in-engine execution outcomes.
    // [CANTON-NOTE: WHY] Guarantees that every single scenario verified in
    // doc/01-daml-dar-stage/local-docker-verification-report.md is accounted for in Rust.
    let tsv_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/tx-corpus/expected.tsv");
    let tsv_content = std::fs::read_to_string(&tsv_path).expect("read expected.tsv");
    let fx = fixture();

    let mut executed_count = 0;
    for line in tsv_content.lines().filter(|l| !l.is_empty()) {
        let (scenario, golden_output) = line
            .split_once('\t')
            .unwrap_or_else(|| panic!("invalid line in expected.tsv: {line}"));

        match scenario {
            "createOk" => {
                let mut eng = engine(&fx);
                let _ = initial_holding(&fx, &mut eng);
                let actual = engine_summary(&eng, OWNER_PARTY);
                assert_eq!(actual, golden_output, "{scenario}");
                executed_count += 1;
            }
            "ensureFail" => {
                let mut eng = engine(&fx);
                let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "0.0");
                let err = eng
                    .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
                    .unwrap_err();
                assert!(matches!(err, ExecError::PreconditionFailed { .. }));
                assert!(golden_output.contains("PreconditionFailed"));
                executed_count += 1;
            }
            "ensureNeg" => {
                let mut eng = engine(&fx);
                let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "-1.0");
                let err = eng
                    .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
                    .unwrap_err();
                assert!(matches!(err, ExecError::PreconditionFailed { .. }));
                assert!(golden_output.contains("PreconditionFailed"));
                executed_count += 1;
            }
            "authFail" => {
                let mut eng = engine(&fx);
                let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "10.0");
                let err = eng
                    .execute_create(&[OWNER_PARTY], TEMPLATE, &p)
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Signatories,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "authBeforeEnsure" => {
                let mut eng = engine(&fx);
                let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "0.0");
                let err = eng
                    .execute_create(&[OWNER_PARTY], TEMPLATE, &p)
                    .unwrap_err();
                assert!(matches!(err, ExecError::PreconditionFailed { .. }));
                assert!(golden_output.contains("PreconditionFailed"));
                executed_count += 1;
            }
            "transferOk" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "Transfer",
                    &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                )
                .expect("transfer ok");
                let old = engine_summary(&eng, OWNER_PARTY);
                let moved = engine_summary(&eng, BANK_PARTY);
                assert_eq!(format!("{old}|{moved}"), golden_output, "{scenario}");
                executed_count += 1;
            }
            "transferToAuditor" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Signatories,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "transferByBank" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[BANK_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Controllers,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "transferSame" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": OWNER_PARTY })),
                    )
                    .unwrap_err();
                match err {
                    ExecError::Unhandled { message, .. } => {
                        assert_eq!(message, "New owner cannot be the same as current owner");
                        assert!(golden_output.contains(&message));
                    }
                    other => panic!("expected Unhandled, got {other:?}"),
                }
                executed_count += 1;
            }
            "transferKeeps" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let _ = eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "Transfer",
                    &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
                );
                let actual = engine_summary(&eng, OWNER_PARTY);
                assert_eq!(actual, golden_output, "{scenario}");
                executed_count += 1;
            }
            "assertKeeps" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let _ = eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "Transfer",
                    &choice_arg(&fx, "Transfer", json!({ "newOwner": OWNER_PARTY })),
                );
                let actual = engine_summary(&eng, OWNER_PARTY);
                assert_eq!(actual, golden_output, "{scenario}");
                executed_count += 1;
            }
            "doubleConsume" => {
                let mut eng = engine(&fx);
                eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
                let init = initial_holding(&fx, &mut eng);
                eng.set_submission_idx(1);
                eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "Transfer",
                    &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                )
                .expect("first transfer");
                eng.set_submission_idx(2);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
                    )
                    .unwrap_err();
                match err {
                    ExecError::ContractNotActive(cid) => {
                        let formatted = format_not_active_error(&cid);
                        assert_eq!(formatted, golden_output, "{scenario}");
                    }
                    other => panic!("expected ContractNotActive, got {other:?}"),
                }
                executed_count += 1;
            }
            "settleOk" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                eng.execute_exercise(
                    &[BANK_PARTY],
                    &init.contract_id,
                    "Settle",
                    &choice_arg(&fx, "Settle", json!({})),
                )
                .expect("settle ok");
                let actual = engine_summary(&eng, OWNER_PARTY);
                assert_eq!(actual, golden_output, "{scenario}");
                executed_count += 1;
            }
            "settleByOwner" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "Settle",
                        &choice_arg(&fx, "Settle", json!({})),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Controllers,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "observerTransfer" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[AUDITOR_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Controllers,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "splitOk" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "SplitTransfer",
                    &choice_arg(
                        &fx,
                        "SplitTransfer",
                        json!({ "transferAmount": "2.5", "recipient": BANK_PARTY }),
                    ),
                )
                .expect("split ok");
                let left = engine_summary(&eng, OWNER_PARTY);
                let right = engine_summary(&eng, BANK_PARTY);
                assert_eq!(format!("{left}|{right}"), golden_output, "{scenario}");
                executed_count += 1;
            }
            "splitToAuditor" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "SplitTransfer",
                        &choice_arg(
                            &fx,
                            "SplitTransfer",
                            json!({ "transferAmount": "2.5", "recipient": AUDITOR_PARTY }),
                        ),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Signatories,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "splitTooMuch" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "SplitTransfer",
                        &choice_arg(
                            &fx,
                            "SplitTransfer",
                            json!({ "transferAmount": "10.0", "recipient": BANK_PARTY }),
                        ),
                    )
                    .unwrap_err();
                match err {
                    ExecError::Unhandled { message, .. } => {
                        assert_eq!(message, "Transfer amount must be less than current balance");
                        assert!(golden_output.contains(&message));
                    }
                    other => panic!("expected Unhandled, got {other:?}"),
                }
                executed_count += 1;
            }
            "splitZero" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "SplitTransfer",
                        &choice_arg(
                            &fx,
                            "SplitTransfer",
                            json!({ "transferAmount": "0.0", "recipient": BANK_PARTY }),
                        ),
                    )
                    .unwrap_err();
                match err {
                    ExecError::Unhandled { message, .. } => {
                        assert_eq!(message, "Transfer amount must be positive");
                        assert!(golden_output.contains(&message));
                    }
                    other => panic!("expected Unhandled, got {other:?}"),
                }
                executed_count += 1;
            }
            "splitSelf" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[OWNER_PARTY],
                        &init.contract_id,
                        "SplitTransfer",
                        &choice_arg(
                            &fx,
                            "SplitTransfer",
                            json!({ "transferAmount": "1.0", "recipient": OWNER_PARTY }),
                        ),
                    )
                    .unwrap_err();
                match err {
                    ExecError::Unhandled { message, .. } => {
                        assert_eq!(message, "Recipient must be different from owner");
                        assert!(golden_output.contains(&message));
                    }
                    other => panic!("expected Unhandled, got {other:?}"),
                }
                executed_count += 1;
            }
            // AT-U03: an observer has no authority; an observer that is also the controller does.
            "ownerIsObserverTransfer" => {
                let mut eng = engine(&fx);
                let init = holding_with_auditor(&fx, &mut eng, OWNER_PARTY);
                eng.execute_exercise(
                    &[OWNER_PARTY],
                    &init.contract_id,
                    "Transfer",
                    &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                )
                .expect("the owner, though also an observer, is the controller");
                let old = engine_summary(&eng, OWNER_PARTY);
                let moved = engine_summary(&eng, BANK_PARTY);
                assert_eq!(format!("{old}|{moved}"), golden_output, "{scenario}");
                executed_count += 1;
            }
            "ownerIsObserverReadAsOnly" => {
                let mut eng = engine(&fx);
                let init = holding_with_auditor(&fx, &mut eng, OWNER_PARTY);
                // `readAs owner` only gives visibility: the acting party is the bank
                let err = eng
                    .execute_exercise(
                        &[BANK_PARTY],
                        &init.contract_id,
                        "Transfer",
                        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Controllers,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "bankIsObserverSettle" => {
                let mut eng = engine(&fx);
                let init = holding_with_auditor(&fx, &mut eng, BANK_PARTY);
                eng.execute_exercise(
                    &[BANK_PARTY],
                    &init.contract_id,
                    "Settle",
                    &choice_arg(&fx, "Settle", json!({})),
                )
                .expect("the bank, though also an observer, is the controller of Settle");
                assert_eq!(
                    engine_summary(&eng, OWNER_PARTY),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            "auditorOnlySettle" => {
                let mut eng = engine(&fx);
                let init = initial_holding(&fx, &mut eng);
                let err = eng
                    .execute_exercise(
                        &[AUDITOR_PARTY],
                        &init.contract_id,
                        "Settle",
                        &choice_arg(&fx, "Settle", json!({})),
                    )
                    .unwrap_err();
                assert!(matches!(
                    err,
                    ExecError::Unauthorized {
                        kind: AuthKind::Controllers,
                        ..
                    }
                ));
                let msg = err.canton_auth_message().expect("canton auth message");
                assert_eq!(
                    format!("Left Authorization failure: {msg}"),
                    golden_output,
                    "{scenario}"
                );
                executed_count += 1;
            }
            other => panic!("unexpected scenario {other} in expected.tsv"),
        }
    }

    assert_eq!(
        executed_count, 24,
        "all 24 scenarios from expected.tsv must be covered"
    );
}

// -----------------------------------------------------------------------------
// Metadata verification: Package ID consistency with Docker verification report
// -----------------------------------------------------------------------------

#[test]
fn test_diff_metadata_package_id_matches_docker_verification_report_package() {
    // [CANTON-NOTE: SEMANTICS] Matches main package ID documented in
    // doc/01-daml-dar-stage/local-docker-verification-report.md line 32:
    // 0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2
    let fx = fixture();
    let main_pkg = fx.world.main_package_id();
    assert_eq!(
        main_pkg, PACKAGE_ID,
        "main package ID must match verified sample-contract.dar"
    );
    assert_eq!(
        PACKAGE_ID,
        "0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"
    );
}

/// Reads `tests/oracle/tx-corpus/cid-expected.tsv` (JVM 3.7.2 `daml script --ide-ledger` output, unmasked) and
/// returns the contract IDs of one row as a list, in the order the Daml script `show`ed them.
fn jvm_cids(scenario: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/tx-corpus/cid-expected.tsv");
    let text = std::fs::read_to_string(path).expect("read cid-expected.tsv");
    let row = text
        .lines()
        .find_map(|l| {
            l.split_once('\t')
                .filter(|(n, _)| *n == scenario)
                .map(|(_, v)| v)
        })
        .unwrap_or_else(|| panic!("row {scenario} missing"));
    row.trim_matches(|c| matches!(c, '(' | ')' | '[' | ']'))
        .split(',')
        .map(str::to_string)
        .collect()
}

#[test]
fn test_child_contract_ids_match_jvm_oracle_unmasked() {
    // S-TX-001 part 4. Unlike `test_unmasked_transfer_and_split_child_contract_ids` (Rust engine vs Rust
    // ledger), the expected values here are the ones the JVM printed for Tx:cidTransfer / Tx:cidSplit.
    let fx = fixture();

    let want = jvm_cids("cidTransfer");
    assert_eq!(want.len(), 2);
    let mut eng = engine(&fx);
    eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
    let init = initial_holding(&fx, &mut eng);
    assert_eq!(init.contract_id, want[0], "created contract id");
    eng.set_submission_idx(1);
    let out = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &init.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("transfer");
    assert_eq!(out.created.len(), 1);
    assert_eq!(
        out.created[0].contract_id, want[1],
        "Transfer child contract id"
    );

    let want = jvm_cids("cidSplit");
    assert_eq!(want.len(), 3);
    let mut eng = engine(&fx);
    eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
    let init = initial_holding(&fx, &mut eng);
    assert_eq!(init.contract_id, want[0], "created contract id");
    eng.set_submission_idx(1);
    let out = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &init.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "2.5", "recipient": BANK_PARTY }),
            ),
        )
        .expect("split");
    assert_eq!(out.created.len(), 2);
    assert_eq!(
        out.created[0].contract_id, want[1],
        "SplitTransfer first child"
    );
    assert_eq!(
        out.created[1].contract_id, want[2],
        "SplitTransfer second child"
    );
}

// -----------------------------------------------------------------------------
// U-3: chains and further contract-id cases (JVM `daml script --ide-ledger`, unmasked)
// -----------------------------------------------------------------------------

/// Drives the engine like a Daml script does: one submission per call, numbered from 0.
/// [CANTON-NOTE: SEMANTICS] The submission index counts EVERY submission in the script, including rejected ones
/// (`trySubmit` that fails); whether the JVM does the same is exactly what `cidAfterRejected` and
/// `cidTransferAfterRejected` measure, and the expected ids in cid-expected.tsv are the JVM's, not ours.
struct Script<'w> {
    fx: &'w Fixture,
    eng: Engine<'w>,
    next_submission: usize,
}

impl<'w> Script<'w> {
    fn new(fx: &'w Fixture) -> Self {
        let mut eng = engine(fx);
        eng.set_contract_id_allocator(IdeContractIdAllocator::new("sample-contract"));
        Script {
            fx,
            eng,
            next_submission: 0,
        }
    }

    fn begin(&mut self) {
        self.eng.set_submission_idx(self.next_submission);
        self.next_submission += 1;
    }

    fn create(
        &mut self,
        actors: &[&str],
        (bank, owner, auditor): (&str, &str, &str),
        amount: &str,
    ) -> Result<String, ExecError> {
        self.begin();
        let p = holding_payload(self.fx, bank, owner, auditor, amount);
        self.eng
            .execute_create(actors, TEMPLATE, &p)
            .map(|c| c.contract_id)
    }

    fn exercise(
        &mut self,
        actors: &[&str],
        cid: &str,
        choice: &str,
        arg: serde_json::Value,
    ) -> Result<Vec<String>, ExecError> {
        self.begin();
        let arg = choice_arg(self.fx, choice, arg);
        self.eng
            .execute_exercise(actors, cid, choice, &arg)
            .map(|o| o.created.iter().map(|c| c.contract_id.clone()).collect())
    }
}

const B: &str = BANK_PARTY;
const O: &str = OWNER_PARTY;
const A: &str = AUDITOR_PARTY;
const BOA: (&str, &str, &str) = (B, O, A);

#[test]
fn test_cid_chain_matches_jvm_unmasked() {
    // [CANTON-NOTE: SEMANTICS] Tx:cidChain re-exercises children: split, split the remainder again, then Transfer
    // that remainder (U-3). A Transfer chain is impossible: the authority of a created contract comes from the
    // choice (signatories plus controller), so a bank-owned child can only create bank-signed contracts.
    let fx = fixture();
    let want = jvm_cids("cidChain");
    assert_eq!(want.len(), 6);
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    let ab1 = s
        .exercise(
            &[O],
            &c0,
            "SplitTransfer",
            json!({ "transferAmount": "2.5", "recipient": B }),
        )
        .unwrap();
    let ab2 = s
        .exercise(
            &[O],
            &ab1[1],
            "SplitTransfer",
            json!({ "transferAmount": "1.0", "recipient": B }),
        )
        .unwrap();
    let c3 = s
        .exercise(&[O], &ab2[1], "Transfer", json!({ "newOwner": B }))
        .unwrap();
    let got = vec![
        c0,
        ab1[0].clone(),
        ab1[1].clone(),
        ab2[0].clone(),
        ab2[1].clone(),
        c3[0].clone(),
    ];
    assert_eq!(got, want);
}

#[test]
fn test_cid_split_chain_matches_jvm_unmasked() {
    let fx = fixture();
    let want = jvm_cids("cidSplitChain");
    assert_eq!(want.len(), 4);
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    let ab = s
        .exercise(
            &[O],
            &c0,
            "SplitTransfer",
            json!({ "transferAmount": "2.5", "recipient": B }),
        )
        .unwrap();
    s.exercise(&[B], &ab[0], "Settle", json!({})).unwrap();
    let c3 = s
        .exercise(&[O], &ab[1], "Transfer", json!({ "newOwner": B }))
        .unwrap();
    assert_eq!(vec![c0, ab[0].clone(), ab[1].clone(), c3[0].clone()], want);
}

#[test]
fn test_cid_transfer_then_create_matches_jvm_unmasked() {
    let fx = fixture();
    let want = jvm_cids("cidChainSplit");
    assert_eq!(want.len(), 3);
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    let c1 = s
        .exercise(&[O], &c0, "Transfer", json!({ "newOwner": B }))
        .unwrap();
    let c2 = s.create(&[B, O], BOA, "10.0").unwrap();
    assert_eq!(vec![c0, c1[0].clone(), c2], want);
}

#[test]
fn test_cid_two_submissions_and_same_payload_match_jvm_unmasked() {
    let fx = fixture();
    let want = jvm_cids("cidTwoSubmissions");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    let c1 = s.create(&[B, O], BOA, "20.0").unwrap();
    assert_eq!(vec![c0, c1], want);

    // Equal payload and stakeholders, different submission index: the ids must still differ.
    let want = jvm_cids("cidSamePayload");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    let c1 = s.create(&[B, O], BOA, "10.0").unwrap();
    assert_ne!(c0, c1);
    assert_eq!(vec![c0, c1], want);
}

#[test]
fn test_cid_stakeholder_variants_match_jvm_unmasked() {
    let fx = fixture();
    let want = jvm_cids("cidStakeholders");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], (B, O, O), "10.0").unwrap();
    let c1 = s.create(&[B], (B, B, A), "10.0").unwrap();
    assert_eq!(vec![c0, c1], want);
}

#[test]
fn test_cid_after_settle_matches_jvm_unmasked() {
    let fx = fixture();
    let want = jvm_cids("cidAfterSettle");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    s.exercise(&[B], &c0, "Settle", json!({})).unwrap();
    let c2 = s.create(&[B, O], BOA, "10.0").unwrap();
    assert_eq!(vec![c0, c2], want);
}

#[test]
fn test_cid_after_rejected_submission_matches_jvm_unmasked() {
    // [CANTON-NOTE: SEMANTICS] Whether a rejected submission (trySubmit that fails) consumes a submission index
    // is decided by the JVM answer in cid-expected.tsv; `Script` counts it and this test reports the outcome.
    let fx = fixture();
    let want = jvm_cids("cidAfterRejected");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    assert!(s.create(&[O], BOA, "11.0").is_err());
    let c2 = s.create(&[B, O], BOA, "12.0").unwrap();
    assert_eq!(vec![c0, c2], want);

    let want = jvm_cids("cidTransferAfterRejected");
    let mut s = Script::new(&fx);
    let c0 = s.create(&[B, O], BOA, "10.0").unwrap();
    assert!(s
        .exercise(&[O], &c0, "Transfer", json!({ "newOwner": O }))
        .is_err());
    let c2 = s
        .exercise(&[O], &c0, "Transfer", json!({ "newOwner": B }))
        .unwrap();
    assert_eq!(vec![c0, c2[0].clone()], want);
}

#[test]
fn test_cid_two_creates_in_one_submission_match_jvm_unmasked() {
    // [CANTON-NOTE: LIMITATION] `Engine` runs ONE root command per submission, so two root creates of the same
    // submission (Tx:cidTwoInOne: node ids 0 and 1 of one transaction seed) cannot be driven through it. The allocator
    // is called here with the creation index the second root node would have; this shows the id scheme is right, not
    // that the engine can submit several commands at once.
    use lf_eval::{ContractIdAllocator, NewContract};
    let fx = fixture();
    let want = jvm_cids("cidTwoInOne");
    assert_eq!(want.len(), 2);
    let mut alloc = IdeContractIdAllocator::new("sample-contract");
    alloc.set_submission_idx(0); // the one and only submission of the script
    let sigs = vec![B.to_string(), O.to_string()];
    let obs = vec![A.to_string()];
    let mut ids = Vec::new();
    for (index, amount) in ["10.0", "20.0"].into_iter().enumerate() {
        let payload = holding_payload(&fx, B, O, A, amount);
        ids.push(alloc.allocate(&NewContract {
            package_id: PACKAGE_ID,
            template_id: TEMPLATE,
            payload: &payload,
            signatories: &sigs,
            observers: &obs,
            creation_index: index,
            depth: 0,
            path: &[],
            key: None,
        }));
    }
    assert_eq!(ids, want);
}

// A template of ANOTHER package (tx-corpus, `TxNote:Note`, one signatory): the id hashes the package name and the template
// name, and a single-signatory child can be exercised again, which the sample DAR cannot do.

fn note_world() -> World {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/tx-corpus/tx-corpus.dar");
    World::open(&path)
        .expect("tx-corpus.dar (regenerate with UPDATE_DAR=1 scripts/verify-tx-ledger.sh)")
}

fn note(author: &str, watchers: &[&str], n: i64) -> Value {
    let mut list = lf_eval::List::new();
    for w in watchers.iter().rev() {
        list = lf_eval::List::cons(Value::Party((*w).to_string()), list);
    }
    Value::Record {
        tycon: Some("TxNote:Note".to_string()),
        fields: vec![
            ("author".to_string(), Value::Party(author.to_string())),
            ("watchers".to_string(), Value::List(list)),
            ("text".to_string(), Value::Text("hi".to_string())),
            ("n".to_string(), Value::Int64(n)),
        ],
    }
}

fn record0(fields: Vec<(&str, Value)>) -> Value {
    Value::Record {
        tycon: None,
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}

#[test]
fn test_cid_other_package_template_chain_matches_jvm_unmasked() {
    // [CANTON-NOTE: SEMANTICS] Tx:cidNoteChain / cidNoteWatchers: package name "tx-corpus", template "TxNote:Note".
    let world = note_world();
    let author = lf_eval::IdePartyAllocator::new().allocate_party("Author");

    let want = jvm_cids("cidNoteChain");
    assert_eq!(want.len(), 6);
    let mut eng = Engine::new(&world);
    eng.set_contract_id_allocator(IdeContractIdAllocator::new("tx-corpus"));
    eng.set_submission_idx(0);
    let n0 = eng
        .execute_create(&[author.as_str()], "TxNote:Note", &note(&author, &[], 0))
        .expect("create")
        .contract_id;
    let bump = |eng: &mut Engine<'_>, idx: usize, cid: &str| {
        eng.set_submission_idx(idx);
        eng.execute_exercise(&[author.as_str()], cid, "Bump", &record0(vec![]))
            .expect("bump")
            .created[0]
            .contract_id
            .clone()
    };
    let n1 = bump(&mut eng, 1, &n0);
    let n2 = bump(&mut eng, 2, &n1);
    eng.set_submission_idx(3);
    let fork = eng
        .execute_exercise(
            &[author.as_str()],
            &n2,
            "Fork",
            &record0(vec![("extra", Value::Text("forked".to_string()))]),
        )
        .expect("fork");
    let (f1, f2) = (
        fork.created[0].contract_id.clone(),
        fork.created[1].contract_id.clone(),
    );
    let n4 = bump(&mut eng, 4, &f2);
    assert_eq!(vec![n0, n1, n2, f1, f2, n4], want);

    let want = jvm_cids("cidNoteWatchers");
    let mut alloc = lf_eval::IdePartyAllocator::new();
    let author = alloc.allocate_party("Author");
    let watcher = alloc.allocate_party("Watcher");
    let mut eng = Engine::new(&world);
    eng.set_contract_id_allocator(IdeContractIdAllocator::new("tx-corpus"));
    eng.set_submission_idx(0);
    let n0 = eng
        .execute_create(
            &[author.as_str()],
            "TxNote:Note",
            &note(&author, &[&watcher], 0),
        )
        .expect("create")
        .contract_id;
    eng.set_submission_idx(1);
    let n1 = eng
        .execute_exercise(&[author.as_str()], &n0, "Bump", &record0(vec![]))
        .expect("bump")
        .created[0]
        .contract_id
        .clone();
    assert_eq!(vec![n0, n1], want);
}
