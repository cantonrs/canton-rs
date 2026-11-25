//! End-to-end check of the generic command API on the real `sample-contract.dar`.
//!
//! What is real: the template, its `ensure`, signatories/observers, the controllers and the
//! bodies of `Transfer` / `SplitTransfer` / `Settle` / the implicit `Archive` are the DAR's
//! compiled Daml-LF, evaluated by `Engine::execute_create` / `execute_exercise`; every
//! payload and argument is built through `codec` (JSON -> `Value` -> wire bytes -> `Value`),
//! i.e. the same path a participant would use, with an injected `#domain:participant:n`
//! contract-id scheme.
//!
//! What this is NOT: no oracle. `daml script --ide-ledger` is not run here, and the model
//! has no topology, no confirmation by other signatories' participants, no Canton contract
//! ids and no party-id syntax beyond the LF character set. The expected authorization
//! outcomes below follow the Daml authorization rules (a create needs *all* signatories'
//! authority; an exercise needs all controllers; inside a choice the authority is
//! signatories + controllers) as implemented by the `Engine` model; the one cross-check
//! against another implementation is the final differential with `SingleContractLedger`
//! (itself compared with the IDE-ledger corpus in `tx_ledger.rs`), and it only covers the
//! "transfer to a non-signatory fails" outcome.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use lf_archive::ModuleSurface;
use lf_eval::codec::RecordSchema;
use lf_eval::ledger::{Holding, SingleContractLedger, AUDITOR_PARTY, BANK_PARTY, OWNER_PARTY};
use lf_eval::{AuthKind, ChoiceOutcome, Contract, Engine, ExecError, NewContract, Value, World};
use serde_json::json;

const TEMPLATE: &str = "AssetHolding:AssetHolding";
const BANK: &str = "Bank::fp1";
const OWNER_A: &str = "OwnerA::fp2";
const OWNER_B: &str = "OwnerB::fp3";
const AUDITOR: &str = "Auditor::fp4";

fn dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

struct Fixture {
    world: World,
    surfaces: Vec<ModuleSurface>,
}

fn fixture() -> Fixture {
    Fixture {
        world: World::open(&dar_path()).expect("sample-contract.dar"),
        surfaces: lf_archive::parse_dar_file(dar_path())
            .expect("surfaces")
            .module_surfaces,
    }
}

/// Engine whose ids look like the participant's `#domain:participant:n`. The counter is shared
/// with the test so it can observe that ids are never reused.
fn engine<'w>(fx: &'w Fixture) -> (Engine<'w>, Rc<Cell<u64>>) {
    let counter = Rc::new(Cell::new(0));
    let shared = std::rc::Rc::clone(&counter);
    let mut engine = Engine::new(&fx.world);
    engine.set_contract_id_allocator(move |_: &NewContract<'_>| {
        shared.set(shared.get() + 1);
        format!("#global-domain:participant-1:{}", shared.get())
    });
    (engine, counter)
}

/// JSON -> Value -> wire bytes -> Value: the value the executor sees has crossed the wire.
fn through_wire(schema: &RecordSchema, json: serde_json::Value) -> Value {
    let value = schema.from_json(&json).expect("json -> value");
    let bytes = schema.encode(&value).expect("encode");
    schema.decode(&bytes).expect("decode")
}

fn holding_json(owner: &str, amount: &str) -> serde_json::Value {
    json!({ "bank": BANK, "owner": owner, "auditor": AUDITOR, "assetSymbol": "USD", "amount": amount })
}

fn payload(fx: &Fixture, owner: &str, amount: &str) -> Value {
    let schema = RecordSchema::template(&fx.surfaces, TEMPLATE).unwrap();
    through_wire(&schema, holding_json(owner, amount))
}

fn arg(fx: &Fixture, choice: &str, json: serde_json::Value) -> Value {
    let schema = RecordSchema::choice_arg(&fx.surfaces, TEMPLATE, choice).unwrap();
    through_wire(&schema, json)
}

fn create(fx: &Fixture, engine: &mut Engine<'_>, owner: &str, amount: &str) -> Contract {
    engine
        .execute_create(&[BANK, OWNER_A], TEMPLATE, &payload(fx, owner, amount))
        .expect("create")
}

fn field<'v>(value: &'v Value, name: &str) -> &'v Value {
    let Value::Record { fields, .. } = value else {
        panic!("not a record: {value:?}")
    };
    &fields.iter().find(|(k, _)| k == name).expect("field").1
}

fn numeric(value: &Value) -> String {
    let Value::Numeric { coeff, scale } = value else {
        panic!("not numeric: {value:?}")
    };
    lf_eval::render_numeric(*coeff, *scale)
}

fn sorted(mut parties: Vec<String>) -> Vec<String> {
    parties.sort();
    parties.dedup();
    parties
}

#[test]
fn create_evaluates_signatories_observers_ensure_and_uses_the_injected_id() {
    let fx = fixture();
    let (mut engine, counter) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");

    assert_eq!(holding.contract_id, "#global-domain:participant-1:1");
    assert_eq!(holding.template_id, TEMPLATE);
    assert_eq!(sorted(holding.signatories.clone()), vec![BANK, OWNER_A]);
    assert_eq!(holding.observers, vec![AUDITOR.to_string()]);
    assert!(holding.active);
    assert_eq!(counter.get(), 1);
}

#[test]
fn create_without_every_signatory_or_with_a_false_ensure_is_rejected_and_leaves_no_trace() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let p = payload(&fx, OWNER_A, "100.0");

    // Bank alone cannot authorize a contract that OwnerA also signs.
    let err = engine.execute_create(&[BANK], TEMPLATE, &p).unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Signatories, missing, .. }
            if missing == &[OWNER_A.to_string()]),
        "{err:?}"
    );
    // The auditor is only an observer: authority from an observer does not count.
    let err = engine
        .execute_create(&[BANK, AUDITOR], TEMPLATE, &p)
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { missing, .. } if missing == &[OWNER_A.to_string()]),
        "{err:?}"
    );

    // `ensure amount > 0.0`
    for bad in ["0.0", "-1.0"] {
        let err = engine
            .execute_create(&[BANK, OWNER_A], TEMPLATE, &payload(&fx, OWNER_A, bad))
            .unwrap_err();
        assert!(
            matches!(&err, ExecError::PreconditionFailed { message } if message.contains("AssetHolding")),
            "{bad}: {err:?}"
        );
    }
    assert_eq!(engine.active_contracts().count(), 0);
}

#[test]
fn transfer_to_a_non_signatory_lacks_that_partys_authority() {
    let fx = fixture();
    let (mut engine, counter) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    let ids_used = counter.get();

    // The body is `create this with owner = newOwner`; its signatories {Bank, OwnerB} need
    // OwnerB's authority, but the body only has {Bank, OwnerA} (signatories + controller).
    let err = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": OWNER_B })),
        )
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Signatories, missing, .. }
            if missing == &[OWNER_B.to_string()]),
        "{err:?}"
    );
    // Commit-on-Ok: the holding is untouched (still active, no half-created successor)...
    assert_eq!(
        engine
            .active_contracts()
            .map(|c| c.contract_id.clone())
            .collect::<Vec<_>>(),
        vec![holding.contract_id.clone()]
    );
    // The authorization check comes before id allocation, so a rejected create does not
    // consume an id here (a body that creates and *then* fails would; allocators must not
    // assume gap-free ids).
    assert_eq!(counter.get(), ids_used);
}

#[test]
fn only_controllers_may_exercise_and_the_error_names_them() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");

    // Transfer is controlled by `owner`; the bank (a signatory!) is not a controller.
    let err = engine
        .execute_exercise(
            &[BANK],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": BANK })),
        )
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Controllers, required, missing, .. }
            if required == &[OWNER_A.to_string()] && missing == &[OWNER_A.to_string()]),
        "{err:?}"
    );

    // Settle is controlled by `bank`, not by the owner.
    let err = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Settle",
            &arg(&fx, "Settle", json!({})),
        )
        .unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Controllers, required, .. }
            if required == &[BANK.to_string()]),
        "{err:?}"
    );
    assert!(engine.contract(&holding.contract_id).unwrap().active);
}

#[test]
fn transfer_to_the_bank_archives_the_original_and_creates_the_successor() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");

    // Newowner = Bank is the transfer the model *can* authorize: Bank already is a signatory.
    let outcome: ChoiceOutcome = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": BANK })),
        )
        .unwrap();
    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![holding.contract_id.clone()]);
    assert_eq!(outcome.created.len(), 1);
    let successor = &outcome.created[0];
    assert_eq!(
        outcome.result,
        Value::ContractId(successor.contract_id.clone())
    );
    assert_eq!(successor.contract_id, "#global-domain:participant-1:2");
    assert_eq!(
        field(&successor.payload, "owner"),
        &Value::Party(BANK.into())
    );
    assert_eq!(
        numeric(field(&successor.payload, "amount")),
        "100.0000000000"
    );
    // Both signatories collapse to the bank (a set, not a list: the evaluator may repeat it).
    assert_eq!(sorted(successor.signatories.clone()), vec![BANK]);
    assert!(!engine.contract(&holding.contract_id).unwrap().active);

    // The archived original can no longer be exercised.
    let err = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": BANK })),
        )
        .unwrap_err();
    assert!(matches!(&err, ExecError::ContractNotActive(id) if id == &holding.contract_id));
}

#[test]
fn transfer_body_assertion_failure_aborts_without_effects() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    // `assertMsg "New owner cannot be the same as current owner"`.
    let err = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": OWNER_A })),
        )
        .unwrap_err();
    // `assertMsg` raises Daml's built-in AssertionFailed exception; nothing catches it here.
    assert!(
        matches!(&err, ExecError::Unhandled { error_id, message }
            if error_id.contains("AssertionFailed")
                && message == "New owner cannot be the same as current owner"),
        "{err:?}"
    );
    assert!(engine.contract(&holding.contract_id).unwrap().active);
    assert_eq!(engine.active_contracts().count(), 1);
}

#[test]
fn split_transfer_honours_the_amounts_and_still_needs_the_recipients_authority() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");

    // Recipient = Bank (already a signatory, so the create inside the body is authorized).
    let outcome = engine
        .execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "SplitTransfer",
            &arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "25.0", "recipient": BANK }),
            ),
        )
        .unwrap();
    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![holding.contract_id.clone()]);
    assert_eq!(outcome.created.len(), 2);
    let (transferred, remaining) = (&outcome.created[0], &outcome.created[1]);
    assert_eq!(
        field(&transferred.payload, "owner"),
        &Value::Party(BANK.into())
    );
    assert_eq!(
        numeric(field(&transferred.payload, "amount")),
        "25.0000000000"
    );
    assert_eq!(
        field(&remaining.payload, "owner"),
        &Value::Party(OWNER_A.into())
    );
    assert_eq!(
        numeric(field(&remaining.payload, "amount")),
        "75.0000000000"
    );
    assert_eq!(sorted(remaining.signatories.clone()), vec![BANK, OWNER_A]);
    // The result is the pair of the two new ids, in creation order.
    assert!(
        format!("{:?}", outcome.result).contains(&transferred.contract_id)
            && format!("{:?}", outcome.result).contains(&remaining.contract_id),
        "{:?}",
        outcome.result
    );
    assert_eq!(engine.active_contracts().count(), 2);
}

#[test]
fn split_transfer_rejections_cover_authority_and_the_body_assertions() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    let split = |engine: &mut Engine<'_>, amount: &str, recipient: &str| {
        engine.execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "SplitTransfer",
            &arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": amount, "recipient": recipient }),
            ),
        )
    };

    // Recipient OwnerB would become a signatory without having authorized anything.
    let err = split(&mut engine, "25.0", OWNER_B).unwrap_err();
    assert!(
        matches!(&err, ExecError::Unauthorized { kind: AuthKind::Signatories, missing, .. }
            if missing == &[OWNER_B.to_string()]),
        "{err:?}"
    );
    for (amount, recipient, reason) in [
        ("0.0", BANK, "Transfer amount must be positive"),
        (
            "100.0",
            BANK,
            "Transfer amount must be less than current balance",
        ),
        ("25.0", OWNER_A, "Recipient must be different from owner"),
    ] {
        let err = split(&mut engine, amount, recipient).unwrap_err();
        assert!(
            err.to_string().contains(reason),
            "{amount}/{recipient}: {err:?}"
        );
    }
    assert!(engine.contract(&holding.contract_id).unwrap().active);
    assert_eq!(engine.active_contracts().count(), 1);
}

#[test]
fn settle_needs_the_bank_and_archives_without_creating() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");

    let outcome = engine
        .execute_exercise(
            &[BANK],
            &holding.contract_id,
            "Settle",
            &arg(&fx, "Settle", json!({})),
        )
        .unwrap();
    assert!(outcome.consuming);
    assert_eq!(outcome.result, Value::Unit);
    assert!(outcome.created.is_empty());
    assert_eq!(outcome.archived, vec![holding.contract_id.clone()]);
    assert_eq!(engine.active_contracts().count(), 0);
}

#[test]
fn archive_needs_every_signatory_as_controller() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    // The implicit Archive has no parameters, so its argument is an empty record.
    let empty = Value::Record {
        tycon: None,
        fields: Vec::new(),
    };

    // controllers = signatories = {Bank, OwnerA}: one of them alone is not enough.
    let err = engine
        .execute_exercise(&[BANK], &holding.contract_id, "Archive", &empty)
        .unwrap_err();
    let ExecError::Unauthorized {
        kind,
        required,
        missing,
        ..
    } = &err
    else {
        panic!("{err:?}")
    };
    assert_eq!(*kind, AuthKind::Controllers);
    assert_eq!(sorted(required.clone()), vec![BANK, OWNER_A]);
    assert_eq!(missing, &[OWNER_A.to_string()]);
    assert!(engine.contract(&holding.contract_id).unwrap().active);

    let outcome = engine
        .execute_exercise(&[BANK, OWNER_A], &holding.contract_id, "Archive", &empty)
        .unwrap();
    assert!(outcome.consuming);
    assert_eq!(outcome.archived, vec![holding.contract_id.clone()]);
    assert!(outcome.created.is_empty());
    assert_eq!(engine.active_contracts().count(), 0);
}

#[test]
fn unknown_template_choice_and_contract_are_typed() {
    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    let empty = arg(&fx, "Settle", json!({}));

    assert!(matches!(
        engine.execute_exercise(&[BANK], &holding.contract_id, "Mint", &empty),
        Err(ExecError::UnknownChoice { choice, .. }) if choice == "Mint"
    ));
    assert!(matches!(
        engine.execute_exercise(&[BANK], "#global-domain:participant-1:99", "Settle", &empty),
        Err(ExecError::ContractNotFound(_))
    ));
    assert!(matches!(
        engine.execute_create(&[BANK], "AssetHolding:Other", &empty),
        Err(ExecError::UnknownTemplate { .. })
    ));
}

#[test]
fn acs_style_round_trip_through_wire_bytes_keeps_the_contract_exercisable() {
    // A participant stores `payload` as bytes in its ACS and rebuilds an engine per command.
    let fx = fixture();
    let (mut first, _) = engine(&fx);
    let holding = create(&fx, &mut first, OWNER_A, "100.0");

    let schema = RecordSchema::template(&fx.surfaces, TEMPLATE).unwrap();
    let stored: Vec<u8> = schema.encode(&holding.payload).unwrap();

    let (mut second, _) = engine(&fx);
    second
        .import_contract(Contract {
            payload: schema.decode(&stored).unwrap(),
            ..holding.clone()
        })
        .unwrap();
    let outcome = second
        .execute_exercise(
            &[BANK],
            &holding.contract_id,
            "Settle",
            &arg(&fx, "Settle", json!({})),
        )
        .unwrap();
    assert_eq!(outcome.archived, vec![holding.contract_id.clone()]);
}

#[test]
fn transfer_to_a_non_signatory_also_fails_in_the_single_contract_ledger() {
    // Differential with the other implementation in this crate (`SingleContractLedger`, whose
    // own cases are compared with the IDE-ledger corpus in `tx_ledger.rs`). Only the outcome
    // class is compared: that ledger formats IDE-style strings and uses hashed ids.
    let mut ledger = SingleContractLedger::new();
    let id = ledger
        .create(
            &[BANK_PARTY, OWNER_PARTY],
            Holding::new(BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "USD", 1000),
        )
        .unwrap();
    let message = ledger
        .exercise_transfer(id, &[OWNER_PARTY], AUDITOR_PARTY)
        .unwrap_err();
    assert!(message.contains("Authorization failure"), "{message}");
    assert!(ledger.is_active(id));

    let fx = fixture();
    let (mut engine, _) = engine(&fx);
    let holding = create(&fx, &mut engine, OWNER_A, "100.0");
    assert!(matches!(
        engine.execute_exercise(
            &[OWNER_A],
            &holding.contract_id,
            "Transfer",
            &arg(&fx, "Transfer", json!({ "newOwner": AUDITOR })),
        ),
        Err(ExecError::Unauthorized {
            kind: AuthKind::Signatories,
            ..
        })
    ));
}
