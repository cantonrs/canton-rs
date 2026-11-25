//! Real-DAR checks for the nested-Update machinery, using `sample-contract.dar`.
//!
//! What is real here: the `Update::Exercise` / `Update::Fetch` nodes below are decoded from
//! the DAR's own generated `HasExercise*` / `HasFetch*` instance values, and the choice
//! bodies they trigger (`Transfer`, `SplitTransfer`, `Settle`) are the DAR's compiled code.
//!
//! What is NOT: there is no `daml script --ide-ledger` oracle for these runs. They are
//! differentials against `SingleContractLedger`, whose 20 cases are themselves compared with
//! `expected.tsv` in `tx_ledger.rs`; agreement here shows the generic `Engine` path and the
//! single-contract path behave alike on these inputs, nothing more. The DAR has no choice
//! that exercises or fetches from inside its body, so nested-in-body behaviour is covered
//! only by the synthetic tests in `src/synthetic_tests.rs`.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::{Path, PathBuf};

use lf_eval::ledger::{Holding, SingleContractLedger, AUDITOR_PARTY, BANK_PARTY, OWNER_PARTY};
use lf_eval::{Engine, EvalError, Value, World};

const TEMPLATE: &str = "AssetHolding:AssetHolding";

fn dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn world() -> World {
    World::open(&dar_path()).expect("sample-contract.dar")
}

/// Finds a generated instance value by the parts of its mangled name, so the test does not
/// hard-code the compiler's `$f…` escaping.
fn instance_name(prefix: &str, suffix_part: &str) -> String {
    let loaded = lf_archive::load_dar_file(dar_path()).expect("load dar");
    let package = &loaded.packages[&loaded.archive.main_package_id];
    let mut found = Vec::new();
    for module in &package.modules {
        for value in &module.values {
            let Some(named) = &value.name_with_type else {
                continue;
            };
            let name = lf_archive::resolve_interned_dotted_name(
                package,
                named.name_interned_dname,
                "test",
            )
            .unwrap();
            if name.contains(prefix) && name.contains(suffix_part) {
                found.push(name);
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected one match for {prefix}/{suffix_part}"
    );
    found.remove(0)
}

fn holding(tenths: i64) -> Holding {
    Holding::new(BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "USD", tenths)
}

fn transfer_arg(new_owner: &str) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:Transfer".into()),
        fields: vec![("newOwner".into(), Value::Party(new_owner.into()))],
    }
}

fn split_arg(tenths: i64, recipient: &str) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:SplitTransfer".into()),
        fields: vec![
            (
                "transferAmount".into(),
                Value::Numeric {
                    coeff: i128::from(tenths) * 1_000_000_000,
                    scale: 10,
                },
            ),
            ("recipient".into(), Value::Party(recipient.into())),
        ],
    }
}

fn exercise_instance(choice_part: &str) -> String {
    instance_name("HasExerciseAssetHolding", choice_part)
}

/// Drives the DAR's `m_exercise` for `choice_part` as a root Update through the Engine.
fn root_exercise(
    engine: &mut Engine<'_>,
    act_as: &[&str],
    choice_part: &str,
    cid: &str,
    arg: Value,
) -> Result<Value, EvalError> {
    engine.run_update_val_as(
        act_as,
        "AssetHolding",
        &exercise_instance(choice_part),
        &["m_exercise"],
        // First argument is the unit "dictionary dummy" of the compiled method.
        &[Value::Unit, Value::ContractId(cid.into()), arg],
    )
}

fn holding_of(engine: &Engine<'_>, cid: &str) -> Holding {
    Holding::from_lf_record(&engine.contract(cid).expect("contract").payload).unwrap()
}

fn cids_in(value: &Value) -> Vec<String> {
    match value {
        Value::ContractId(c) => vec![c.clone()],
        Value::Record { fields, .. } | Value::Struct(fields) => {
            fields.iter().flat_map(|(_, v)| cids_in(v)).collect()
        }
        _ => Vec::new(),
    }
}

#[test]
fn has_exercise_transfer_matches_single_contract_ledger() {
    let world = world();
    let mut engine = Engine::new(&world);
    let h = holding(100);
    let cid = engine
        .create_as(
            &[BANK_PARTY, OWNER_PARTY],
            world.main_package_id(),
            TEMPLATE,
            &h.to_lf_record(),
        )
        .unwrap();

    let result = root_exercise(
        &mut engine,
        &[OWNER_PARTY],
        "TransferContractId",
        &cid,
        transfer_arg(BANK_PARTY),
    )
    .unwrap();
    let new_cids = cids_in(&result);
    assert_eq!(new_cids.len(), 1, "Transfer returns the new holding's id");

    // Same scenario through the single-contract ledger (which uses eval_choice_update).
    let mut ledger = SingleContractLedger::new();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], h).unwrap();
    let new_id = ledger
        .exercise_transfer(id, &[OWNER_PARTY], BANK_PARTY)
        .unwrap();

    assert_eq!(
        holding_of(&engine, &new_cids[0]),
        ledger.contracts[new_id].clone().unwrap()
    );
    // Transfer is consuming in the DAR: the source is archived, exactly one holding is live.
    assert!(!engine.contract(&cid).unwrap().active);
    assert_eq!(engine.active_contracts().count(), 1);
}

#[test]
fn has_exercise_split_transfer_matches_single_contract_ledger() {
    let world = world();
    let mut engine = Engine::new(&world);
    let h = holding(100);
    let cid = engine
        .create_as(
            &[BANK_PARTY, OWNER_PARTY],
            world.main_package_id(),
            TEMPLATE,
            &h.to_lf_record(),
        )
        .unwrap();
    let result = root_exercise(
        &mut engine,
        &[OWNER_PARTY],
        "SplitTransfer",
        &cid,
        split_arg(30, BANK_PARTY),
    )
    .unwrap();
    let new_cids = cids_in(&result);
    assert_eq!(new_cids.len(), 2);

    let mut ledger = SingleContractLedger::new();
    let id = ledger.create(&[BANK_PARTY, OWNER_PARTY], h).unwrap();
    let (sent, kept) = ledger
        .exercise_split(id, &[OWNER_PARTY], 30, BANK_PARTY)
        .unwrap();
    assert_eq!(
        holding_of(&engine, &new_cids[0]),
        ledger.contracts[sent].clone().unwrap()
    );
    assert_eq!(
        holding_of(&engine, &new_cids[1]),
        ledger.contracts[kept].clone().unwrap()
    );
}

#[test]
fn has_exercise_rejects_what_the_single_contract_ledger_rejects() {
    let world = world();
    let h = holding(100);

    // (act_as, choice part, arg): wrong controller, wrong controller, failing assertMsg,
    // and a Transfer to the auditor: the new holding's signatory (auditor) never authorized
    // the nested create, the `transferToAuditor` shape from the tx corpus.
    let cases: Vec<(Vec<&str>, &str, Value)> = vec![
        (
            vec![BANK_PARTY],
            "TransferContractId",
            transfer_arg(AUDITOR_PARTY),
        ),
        (
            vec![OWNER_PARTY],
            "Settle",
            Value::Record {
                tycon: Some("AssetHolding:Settle".into()),
                fields: Vec::new(),
            },
        ),
        (
            vec![OWNER_PARTY],
            "TransferContractId",
            transfer_arg(OWNER_PARTY),
        ),
    ];
    for (act_as, choice_part, arg) in cases {
        let mut engine = Engine::new(&world);
        let cid = engine
            .create_as(
                &[BANK_PARTY, OWNER_PARTY],
                world.main_package_id(),
                TEMPLATE,
                &h.to_lf_record(),
            )
            .unwrap();
        let engine_result = root_exercise(&mut engine, &act_as, choice_part, &cid, arg.clone());

        let mut ledger = SingleContractLedger::new();
        let id = ledger
            .create(&[BANK_PARTY, OWNER_PARTY], h.clone())
            .unwrap();
        let ledger_result = match choice_part {
            "Settle" => ledger.exercise_settle(id, &act_as).map(|_| ()),
            _ => {
                let Value::Record { fields, .. } = &arg else {
                    unreachable!()
                };
                let Value::Party(new_owner) = &fields[0].1 else {
                    unreachable!()
                };
                ledger.exercise_transfer(id, &act_as, new_owner).map(|_| ())
            }
        };
        assert!(
            engine_result.is_err() && ledger_result.is_err(),
            "{choice_part} as {act_as:?}: engine {engine_result:?} vs ledger {ledger_result:?}"
        );
        // Failure aborts the command: the contract is still active, nothing new exists.
        assert!(engine.contract(&cid).unwrap().active);
        assert_eq!(engine.active_contracts().count(), 1);
    }
}

#[test]
fn failing_assert_in_choice_body_surfaces_its_message() {
    let world = world();
    let mut engine = Engine::new(&world);
    let cid = engine
        .create_as(
            &[BANK_PARTY, OWNER_PARTY],
            world.main_package_id(),
            TEMPLATE,
            &holding(100).to_lf_record(),
        )
        .unwrap();
    let err = root_exercise(
        &mut engine,
        &[OWNER_PARTY],
        "TransferContractId",
        &cid,
        transfer_arg(OWNER_PARTY),
    )
    .unwrap_err();
    let EvalError::UnhandledException { message, .. } = &err else {
        panic!("expected the assertMsg failure, got {err:?}");
    };
    assert!(
        message.contains("New owner cannot be the same as current owner"),
        "{message}"
    );
}

#[test]
fn has_settle_by_bank_consumes_and_returns_unit() {
    let world = world();
    let mut engine = Engine::new(&world);
    let cid = engine
        .create_as(
            &[BANK_PARTY, OWNER_PARTY],
            world.main_package_id(),
            TEMPLATE,
            &holding(100).to_lf_record(),
        )
        .unwrap();
    let result = root_exercise(
        &mut engine,
        &[BANK_PARTY],
        "Settle",
        &cid,
        Value::Record {
            tycon: Some("AssetHolding:Settle".into()),
            fields: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(result, Value::Unit);
    assert_eq!(engine.active_contracts().count(), 0);
}

#[test]
fn has_fetch_returns_payload_then_reports_archived_and_unknown_contracts() {
    let world = world();
    let mut engine = Engine::new(&world);
    let h = holding(100);
    let cid = engine
        .create_as(
            &[BANK_PARTY, OWNER_PARTY],
            world.main_package_id(),
            TEMPLATE,
            &h.to_lf_record(),
        )
        .unwrap();
    let fetch_name = instance_name("HasFetchAssetHolding", "");
    let fetch = |engine: &mut Engine<'_>, id: &str| {
        engine.run_update_val_as(
            &[OWNER_PARTY],
            "AssetHolding",
            &fetch_name,
            &["m_fetch"],
            &[Value::Unit, Value::ContractId(id.into())],
        )
    };

    // Active: the stored payload comes back verbatim.
    let payload = fetch(&mut engine, &cid).unwrap();
    assert_eq!(payload, h.to_lf_record());

    // After a consuming exercise the same fetch is a typed ContractNotActive.
    root_exercise(
        &mut engine,
        &[OWNER_PARTY],
        "TransferContractId",
        &cid,
        transfer_arg(BANK_PARTY),
    )
    .unwrap();
    assert!(matches!(
        fetch(&mut engine, &cid),
        Err(EvalError::ContractNotActive { .. })
    ));

    // An id the engine never issued is ContractNotFound.
    assert!(matches!(
        fetch(&mut engine, "#does-not-exist"),
        Err(EvalError::ContractNotFound { .. })
    ));
}
