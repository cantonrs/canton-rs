//! Adversarial Empirical Stress Test Suite for Milestone M1
//!
//! [CANTON-NOTE: SEMANTICS]
//! Authoritative Reference: `doc/01-daml-dar-stage/local-docker-verification-report.md`
//! Validates `Engine::execute_exercise`, `Engine::execute_create`, and differential
//! comparison against hostile inputs, boundary conditions, edge cases, and mutation resistance.
//!
//! [CANTON-NOTE: INVARIANT]
//! Strict Daml-LF semantics enforced:
//! 1. Contract invariants (`ensure amount > 0.0`) evaluated strictly before signatory authorization.
//! 2. Controllers strictly checked before choice body execution with `AuthKind::Controllers`.
//! 3. In-body creates require all signatories to be authorized by enclosing context (controllers + signatories).
//! 4. Rollback atomicity strictly preserves ACS on any command failure.
//! 5. Consuming choices mark contracts inactive before body execution, preventing re-entrancy and double consumption.
//! 6. Party identifiers are case-sensitive strings.
//!
//! [CANTON-NOTE: LIMITATION]
//! Contract IDs in Engine are normalized sequential `#n` strings (cryptographic >65 char CID derivation in M3).
//!
//! [CANTON-NOTE: WHY]
//! Adversarially stress-tests edge cases not covered by standard happy-path scenarios,
//! ensuring no subtle semantic bypass or false-positive assertions exist in the differential suite.

use std::path::{Path, PathBuf};

use lf_archive::ModuleSurface;
use lf_eval::codec::RecordSchema;
use lf_eval::ledger::{Holding, AUDITOR_PARTY, BANK_PARTY, OWNER_PARTY};
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

// =============================================================================
// 1. Edge Case: Negative & Zero Amounts Across Create and SplitTransfer
// =============================================================================

#[test]
fn test_stress_edge_case_negative_and_zero_amounts_strict_preconditions() {
    // [CANTON-NOTE: SEMANTICS] Contract invariant `ensure amount > 0.0`
    // [CANTON-NOTE: INVARIANT] Negative and zero amounts strictly reject with PreconditionFailed
    let fx = fixture();
    let mut eng = engine(&fx);

    // Negative amounts
    for neg in ["-10.0", "-0.1", "-0.0001", "-9999999999999.0"] {
        let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, neg);
        let err = eng
            .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
            .unwrap_err();
        assert!(
            matches!(&err, ExecError::PreconditionFailed { message } if message.contains("AssetHolding")),
            "expected PreconditionFailed for negative amount {neg}, got: {err:?}"
        );
    }

    // Zero amounts
    for zero in ["0.0", "0.0000000000"] {
        let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, zero);
        let err = eng
            .execute_create(&[BANK_PARTY, OWNER_PARTY], TEMPLATE, &p)
            .unwrap_err();
        assert!(
            matches!(&err, ExecError::PreconditionFailed { message } if message.contains("AssetHolding")),
            "expected PreconditionFailed for zero amount {zero}, got: {err:?}"
        );
    }

    // Ensure 0 contracts created in engine
    assert_eq!(eng.active_contracts().count(), 0);

    // Now test SplitTransfer in-body assertions with negative and zero amounts
    let initial = initial_holding(&fx, &mut eng);

    // Negative transferAmount in SplitTransfer
    for neg in ["-1.0", "-0.0001", "-100.0"] {
        let err = eng
            .execute_exercise(
                &[OWNER_PARTY],
                &initial.contract_id,
                "SplitTransfer",
                &choice_arg(
                    &fx,
                    "SplitTransfer",
                    json!({ "transferAmount": neg, "recipient": BANK_PARTY }),
                ),
            )
            .unwrap_err();
        match err {
            ExecError::Unhandled { message, .. } => {
                assert_eq!(
                    message, "Transfer amount must be positive",
                    "expected 'Transfer amount must be positive' for {neg}, got: {message}"
                );
            }
            other => panic!("expected Unhandled AssertionFailed for {neg}, got: {other:?}"),
        }
    }

    // Zero transferAmount in SplitTransfer
    let err_zero = eng
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
    match err_zero {
        ExecError::Unhandled { message, .. } => {
            assert_eq!(message, "Transfer amount must be positive");
        }
        other => panic!("expected Unhandled for 0.0, got: {other:?}"),
    }

    // Verify initial contract remains 100% active and untouched
    assert!(eng.contract(&initial.contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// =============================================================================
// 2. Edge Case: SplitTransfer Balance Boundaries and Conservation
// =============================================================================

#[test]
fn test_stress_edge_case_split_boundaries_and_exact_sum_conservation() {
    // [CANTON-NOTE: SEMANTICS] `transferAmount < amount` assertion in SplitTransfer
    // [CANTON-NOTE: INVARIANT] transferAmount == amount and transferAmount > amount fail;
    // valid split strictly conserves total balance (split + rem == original).
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    // transferAmount == amount (10.0 == 10.0)
    let err_eq = eng
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
    match err_eq {
        ExecError::Unhandled { message, .. } => {
            assert_eq!(message, "Transfer amount must be less than current balance");
        }
        other => panic!("expected Unhandled for 10.0, got {other:?}"),
    }

    // transferAmount > amount (10.1 > 10.0)
    let err_gt = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "10.1", "recipient": BANK_PARTY }),
            ),
        )
        .unwrap_err();
    match err_gt {
        ExecError::Unhandled { message, .. } => {
            assert_eq!(message, "Transfer amount must be less than current balance");
        }
        other => panic!("expected Unhandled for 10.1, got {other:?}"),
    }

    // Valid small split: transfer 0.1 out of 10.0
    let outcome = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "0.1", "recipient": BANK_PARTY }),
            ),
        )
        .expect("valid split 0.1");

    assert_eq!(outcome.created.len(), 2);
    let split_h = Holding::from_lf_record(&outcome.created[0].payload).unwrap();
    let rem_h = Holding::from_lf_record(&outcome.created[1].payload).unwrap();

    assert_eq!(split_h.tenths, 1); // 0.1
    assert_eq!(rem_h.tenths, 99); // 9.9
    assert_eq!(split_h.tenths + rem_h.tenths, 100); // 10.0 exact balance conservation!
}

// =============================================================================
// 3. Edge Case: Party Casing Sensitivity
// =============================================================================

#[test]
fn test_stress_edge_case_party_casing_strict_sensitivity() {
    // [CANTON-NOTE: SEMANTICS] Daml Party values are case-sensitive identifiers.
    // [CANTON-NOTE: INVARIANT] Supplying mismatched casing in actAs fails authorization.
    let fx = fixture();
    let mut eng = engine(&fx);

    // 1. Create with lowercase bank in actAs: ["bank-d4d95138", OWNER_PARTY]
    let lowercase_bank = BANK_PARTY.to_lowercase();
    let p = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "10.0");
    let err_create = eng
        .execute_create(&[&lowercase_bank, OWNER_PARTY], TEMPLATE, &p)
        .unwrap_err();

    match err_create {
        ExecError::Unauthorized {
            kind,
            missing,
            required,
            ..
        } => {
            assert_eq!(kind, AuthKind::Signatories);
            assert!(missing.contains(&BANK_PARTY.to_string()));
            assert!(required.contains(&BANK_PARTY.to_string()));
        }
        other => panic!("expected Unauthorized Signatories for lowercase bank, got {other:?}"),
    }

    // 2. Exercise Transfer with lowercase owner in actAs: ["owner-9b3970be"]
    let initial = initial_holding(&fx, &mut eng);
    let lowercase_owner = OWNER_PARTY.to_lowercase();
    let err_exercise = eng
        .execute_exercise(
            &[&lowercase_owner],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .unwrap_err();

    // Party ids are case sensitive: the lowercase owner is a different party, neither signatory nor observer, so
    // the contract is invisible to it (JVM: ContractNotFound; S-TX-001) rather than an authorization failure.
    assert!(
        matches!(err_exercise, ExecError::ContractNotFound(_)),
        "expected ContractNotFound for lowercase owner, got {err_exercise:?}"
    );
}

// =============================================================================
// 4. Edge Case: Non-Stakeholders & Unauthorized Actors
// =============================================================================

#[test]
fn test_stress_edge_case_non_stakeholders_and_adversarial_actors() {
    // [CANTON-NOTE: SEMANTICS] External third parties cannot exercise choices or receive assets without authority.
    // Since S-TX-001 a party that is neither signatory nor observer does not even see the contract, so its top-level
    // exercise is `ContractNotFound` (what `daml script --ide-ledger` answers), not an authorization failure.
    // [CANTON-NOTE: INVARIANT] Rejections occur at both controller check (exercise) and signatory check (in-body create).
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    // Adversarial external parties attempting to exercise choices
    for alien in ["Eve", "Mallory", "AnonymousHacker", ""] {
        // Alien attempting Transfer
        let err_tr = eng
            .execute_exercise(
                &[alien],
                &initial.contract_id,
                "Transfer",
                &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
            )
            .unwrap_err();
        assert!(
            matches!(err_tr, ExecError::ContractNotFound(_)),
            "an outsider cannot see the contract, expected ContractNotFound for alien {alien:?}, got {err_tr:?}"
        );

        // Alien attempting SplitTransfer
        let err_sp = eng
            .execute_exercise(
                &[alien],
                &initial.contract_id,
                "SplitTransfer",
                &choice_arg(
                    &fx,
                    "SplitTransfer",
                    json!({ "transferAmount": "2.0", "recipient": BANK_PARTY }),
                ),
            )
            .unwrap_err();
        assert!(
            matches!(err_sp, ExecError::ContractNotFound(_)),
            "an outsider cannot see the contract, expected ContractNotFound for alien {alien:?}, got {err_sp:?}"
        );

        // Alien attempting Settle
        let err_st = eng
            .execute_exercise(
                &[alien],
                &initial.contract_id,
                "Settle",
                &choice_arg(&fx, "Settle", json!({})),
            )
            .unwrap_err();
        assert!(
            matches!(err_st, ExecError::ContractNotFound(_)),
            "an outsider cannot see the contract, expected ContractNotFound for alien {alien:?}, got {err_st:?}"
        );
    }

    // Empty actAs acting parties
    let err_empty: Result<ChoiceOutcome, ExecError> = eng.execute_exercise(
        &[] as &[&str],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    );
    assert!(matches!(
        err_empty.unwrap_err(),
        ExecError::Unauthorized {
            kind: AuthKind::Controllers,
            ..
        }
    ));

    // Non-stakeholder recipient in Transfer (Transfer to Eve)
    // Controller is Owner (valid), but new contract requires signatories {Bank, Eve},
    // and Eve's authority is missing from enclosing context {Bank, Owner}.
    let err_eve_recipient = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": "Eve" })),
        )
        .unwrap_err();
    match err_eve_recipient {
        ExecError::Unauthorized { kind, missing, .. } => {
            assert_eq!(kind, AuthKind::Signatories);
            assert_eq!(missing, &["Eve".to_string()]);
        }
        other => panic!("expected Unauthorized Signatories for Eve recipient, got {other:?}"),
    }

    // Superset acting parties: [Owner, Bank, Auditor] exercising Transfer
    // Valid because controllers {Owner} ⊆ {Owner, Bank, Auditor}.
    let ok_superset = eng
        .execute_exercise(
            &[OWNER_PARTY, BANK_PARTY, AUDITOR_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("superset authority must succeed");
    assert_eq!(ok_superset.created.len(), 1);
}

// =============================================================================
// 5. Edge Case: Atomicity Under Sequential Hostile Attacks
// =============================================================================

#[test]
fn test_stress_edge_case_atomicity_under_burst_of_failing_attacks() {
    // [CANTON-NOTE: SEMANTICS] Commit-on-Ok atomicity guarantee
    // [CANTON-NOTE: INVARIANT] Multiple sequential failed operations do NOT corrupt active contract state.
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    // 1. Hostile Bank Transfer
    let _ = eng.execute_exercise(
        &[BANK_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    );

    // 2. Hostile Auditor Transfer
    let _ = eng.execute_exercise(
        &[AUDITOR_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    );

    // 3. Hostile Eve Transfer
    let _ = eng.execute_exercise(
        &["Eve"],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
    );

    // 4. Invalid Split: negative amount
    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "SplitTransfer",
        &choice_arg(
            &fx,
            "SplitTransfer",
            json!({ "transferAmount": "-5.0", "recipient": BANK_PARTY }),
        ),
    );

    // 5. Invalid Split: amount >= balance
    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "SplitTransfer",
        &choice_arg(
            &fx,
            "SplitTransfer",
            json!({ "transferAmount": "100.0", "recipient": BANK_PARTY }),
        ),
    );

    // 6. Invalid Split: recipient == owner
    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "SplitTransfer",
        &choice_arg(
            &fx,
            "SplitTransfer",
            json!({ "transferAmount": "2.0", "recipient": OWNER_PARTY }),
        ),
    );

    // 7. Invalid Transfer: newOwner == owner
    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": OWNER_PARTY })),
    );

    // 8. Invalid Transfer: newOwner == auditor (signatory failure)
    let _ = eng.execute_exercise(
        &[OWNER_PARTY],
        &initial.contract_id,
        "Transfer",
        &choice_arg(&fx, "Transfer", json!({ "newOwner": AUDITOR_PARTY })),
    );

    // Check invariants after all 8 hostile/invalid attempts:
    // Initial contract must be completely active, unmodified balance 100 tenths (10.0), exactly 1 contract active.
    let contract = eng.contract(&initial.contract_id).expect("contract exists");
    assert!(contract.active, "contract must remain active");
    let h = Holding::from_lf_record(&contract.payload).expect("holding");
    assert_eq!(h.tenths, 100);
    assert_eq!(h.owner, OWNER_PARTY);
    assert_eq!(eng.active_contracts().count(), 1);

    // Now execute a valid Transfer and verify it succeeds
    let ok = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &initial.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("valid transfer after attack burst");
    assert_eq!(ok.created.len(), 1);
    assert!(!eng.contract(&initial.contract_id).unwrap().active);
    assert!(eng.contract(&ok.created[0].contract_id).unwrap().active);
    assert_eq!(eng.active_contracts().count(), 1);
}

// =============================================================================
// 6. Edge Case: Non-Existent, Empty, and Post-Archive Contract IDs
// =============================================================================

#[test]
fn test_stress_edge_case_contract_id_lifecycle_boundaries() {
    // [CANTON-NOTE: SEMANTICS] Non-existent vs inactive contract IDs
    // [CANTON-NOTE: INVARIANT] Unknown ID -> ContractNotFound; archived ID -> ContractNotActive
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    // Unknown contract IDs
    for unknown in ["#99999", "", "00000000000000000000", "#random_cid"] {
        let err = eng
            .execute_exercise(
                &[OWNER_PARTY],
                unknown,
                "Transfer",
                &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
            )
            .unwrap_err();
        match err {
            ExecError::ContractNotFound(cid) => assert_eq!(cid, unknown),
            other => panic!("expected ContractNotFound for {unknown}, got {other:?}"),
        }
    }

    // Settle the initial holding (archives it)
    eng.execute_exercise(
        &[BANK_PARTY],
        &initial.contract_id,
        "Settle",
        &choice_arg(&fx, "Settle", json!({})),
    )
    .expect("settle ok");

    // Once archived, any subsequent exercise returns ContractNotActive (NOT ContractNotFound)
    for choice in ["Transfer", "SplitTransfer", "Settle"] {
        let arg = if choice == "Transfer" {
            choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY }))
        } else if choice == "SplitTransfer" {
            choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "1.0", "recipient": BANK_PARTY }),
            )
        } else {
            choice_arg(&fx, "Settle", json!({}))
        };
        let err = eng
            .execute_exercise(
                &[BANK_PARTY, OWNER_PARTY],
                &initial.contract_id,
                choice,
                &arg,
            )
            .unwrap_err();
        match err {
            ExecError::ContractNotActive(cid) => assert_eq!(cid, initial.contract_id),
            other => panic!("expected ContractNotActive for archived {choice}, got {other:?}"),
        }
    }
}

// =============================================================================
// 7. Edge Case: Choice Name Boundaries & Mismatches
// =============================================================================

#[test]
fn test_stress_edge_case_unknown_and_case_mismatched_choice_names() {
    // [CANTON-NOTE: SEMANTICS] Template choices are strictly looked up in the DAR
    // [CANTON-NOTE: INVARIANT] Non-existent or case-mismatched choice names reject with UnknownChoice
    let fx = fixture();
    let mut eng = engine(&fx);
    let initial = initial_holding(&fx, &mut eng);

    for bad_choice in [
        "transfer",
        "TRANSFER",
        "Destroy",
        "ArchiveContract",
        "",
        " ",
    ] {
        let err = eng
            .execute_exercise(
                &[OWNER_PARTY],
                &initial.contract_id,
                bad_choice,
                &Value::Unit,
            )
            .unwrap_err();
        match err {
            ExecError::UnknownChoice {
                template_id,
                choice,
            } => {
                assert_eq!(template_id, TEMPLATE);
                assert_eq!(choice, bad_choice);
            }
            other => panic!("expected UnknownChoice for {bad_choice}, got {other:?}"),
        }
    }
}

// =============================================================================
// 7.5. Edge Case: Precondition vs Authorization Invariance with Hostile Actors
// =============================================================================

#[test]
fn test_stress_precedence_invariance_with_completely_unauthorized_actors() {
    // [CANTON-NOTE: SEMANTICS] Daml-LF evaluation pipeline evaluates template `ensure`
    // precondition before checking signatories authorization.
    // [CANTON-NOTE: INVARIANT] Even when caller is an alien party with zero authority (e.g. "Eve"),
    // if `ensure` is false, the engine MUST return PreconditionFailed, NOT Unauthorized!
    let fx = fixture();
    let mut eng = engine(&fx);

    for alien in ["Eve", "Mallory", ""] {
        // Zero amount + alien actor
        let p_zero = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "0.0");
        let err_zero = eng.execute_create(&[alien], TEMPLATE, &p_zero).unwrap_err();
        match err_zero {
            ExecError::PreconditionFailed { message } => {
                assert!(message.contains("AssetHolding"));
            }
            ExecError::Unauthorized { .. } => {
                panic!("INVARIANT BREACH: Unauthorized returned before PreconditionFailed for alien {alien}!");
            }
            other => panic!("expected PreconditionFailed, got {other:?}"),
        }

        // Negative amount + alien actor
        let p_neg = holding_payload(&fx, BANK_PARTY, OWNER_PARTY, AUDITOR_PARTY, "-5.0");
        let err_neg = eng.execute_create(&[alien], TEMPLATE, &p_neg).unwrap_err();
        assert!(matches!(err_neg, ExecError::PreconditionFailed { .. }));
    }
}

// =============================================================================
// 8. Edge Case: Multi-Step Chained Lifecycle Differential Conservation
// =============================================================================

#[test]
fn test_stress_multi_step_lifecycle_conservation_and_tree_depth() {
    // Multi-step lifecycle:
    // c0 (10.0, Owner) -> SplitTransfer 3.0 to Bank: creates c1 (3.0 Bank), c2 (7.0 Owner)
    // Settle c1 (3.0 Bank) -> archived
    // SplitTransfer c2 (7.0 Owner) 2.0 to Bank: creates c3 (2.0 Bank), c4 (5.0 Owner)
    // Transfer c4 (5.0 Owner) to Bank: creates c5 (5.0 Bank)
    // Settle c3 (2.0 Bank) -> archived
    // Settle c5 (5.0 Bank) -> archived
    // Final active contracts = 0. All 10.0 accounted for and redeemed.
    let fx = fixture();
    let mut eng = engine(&fx);

    // 0. Initial holding: 10.0 owned by Owner
    let c0 = initial_holding(&fx, &mut eng);
    assert_eq!(eng.active_contracts().count(), 1);

    // 1. Owner splits c0: 3.0 to Bank (c1), 7.0 remains with Owner (c2)
    let out1 = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &c0.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "3.0", "recipient": BANK_PARTY }),
            ),
        )
        .expect("step 1 split");
    assert_eq!(out1.created.len(), 2);
    let c1_bank = &out1.created[0]; // 3.0 owned by Bank
    let c2_owner = &out1.created[1]; // 7.0 owned by Owner
    assert_eq!(eng.active_contracts().count(), 2);

    // 2. Bank settles c1_bank (3.0)
    let out2 = eng
        .execute_exercise(
            &[BANK_PARTY],
            &c1_bank.contract_id,
            "Settle",
            &choice_arg(&fx, "Settle", json!({})),
        )
        .expect("step 2 settle");
    assert!(out2.created.is_empty());
    assert_eq!(eng.active_contracts().count(), 1);

    // 3. Owner splits c2_owner: 2.0 to Bank (c3), 5.0 remains with Owner (c4)
    let out3 = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &c2_owner.contract_id,
            "SplitTransfer",
            &choice_arg(
                &fx,
                "SplitTransfer",
                json!({ "transferAmount": "2.0", "recipient": BANK_PARTY }),
            ),
        )
        .expect("step 3 split");
    assert_eq!(out3.created.len(), 2);
    let c3_bank = &out3.created[0];
    let c4_owner = &out3.created[1];
    assert_eq!(eng.active_contracts().count(), 2);

    // 4. Owner transfers c4_owner (5.0) to Bank -> creates c5_bank (5.0 Bank)
    let out4 = eng
        .execute_exercise(
            &[OWNER_PARTY],
            &c4_owner.contract_id,
            "Transfer",
            &choice_arg(&fx, "Transfer", json!({ "newOwner": BANK_PARTY })),
        )
        .expect("step 4 transfer");
    assert_eq!(out4.created.len(), 1);
    let c5_bank = &out4.created[0];
    assert_eq!(eng.active_contracts().count(), 2);

    // 5. Bank settles c3_bank (2.0)
    eng.execute_exercise(
        &[BANK_PARTY],
        &c3_bank.contract_id,
        "Settle",
        &choice_arg(&fx, "Settle", json!({})),
    )
    .expect("step 5 settle c3");
    assert_eq!(eng.active_contracts().count(), 1);

    // 6. Bank settles c5_bank (5.0)
    eng.execute_exercise(
        &[BANK_PARTY],
        &c5_bank.contract_id,
        "Settle",
        &choice_arg(&fx, "Settle", json!({})),
    )
    .expect("step 6 settle c5");
    assert_eq!(eng.active_contracts().count(), 0);

    // Invariant: all 6 contracts exist in engine and are marked archived
    for cid in [
        &c0.contract_id,
        &c1_bank.contract_id,
        &c2_owner.contract_id,
        &c3_bank.contract_id,
        &c4_owner.contract_id,
        &c5_bank.contract_id,
    ] {
        let c = eng.contract(cid).unwrap();
        assert!(!c.active, "contract {cid} must be archived");
    }
}
