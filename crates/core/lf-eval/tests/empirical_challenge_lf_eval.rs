//! Empirical Challenge Test Suite for lf-eval
//!
//! Adversarial verification targeting:
//! 1. TryCatch rollback, nested evaluations, and ACS mutation isolation
//! 2. Codec boundary conditions, invalid wire encodings, and malformed JSON payloads

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lf_archive::{FieldDef, ModuleSurface, SurfaceType};
use lf_eval::codec::{CodecError, RecordSchema};
use lf_eval::engine::{Contract as EngineContract, Engine, ExecError};
use lf_eval::tx_model::{ActiveLedgerState, ContractId, Node, TransactionTree};
use lf_eval::{EvalError, TryCheckpoint, UpdateHost, Value, World};
use serde_json::json;

fn dar_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

struct TestFixture {
    world: World,
    surfaces: Vec<ModuleSurface>,
}

fn fixture() -> TestFixture {
    TestFixture {
        world: World::open(&dar_path()).expect("sample-contract.dar open failed"),
        surfaces: lf_archive::parse_dar_file(dar_path())
            .expect("parse_dar_file failed")
            .module_surfaces,
    }
}

// =======================================================================================
// Section 1: TryCatch Rollback & Nested Evaluation Challenge
// =======================================================================================

#[test]
fn challenge_engine_update_host_direct_checkpoint_mechanics() {
    let fx = fixture();
    let mut engine = Engine::new(&fx.world);

    let payload = Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party("Bank".into())),
            ("owner".into(), Value::Party("Alice".into())),
            ("auditor".into(), Value::Party("Auditor".into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 100_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };

    let make_contract = |id: &str| EngineContract {
        contract_id: id.to_string(),
        package_id: fx.world.main_package_id().to_string(),
        template_id: "AssetHolding:AssetHolding".to_string(),
        payload: payload.clone(),
        signatories: vec!["Bank".into(), "Alice".into()],
        observers: vec!["Auditor".into()],
        active: true,
        key: None,
    };

    let c0 = "c0".to_string();
    let c1 = "c1".to_string();
    engine
        .import_contract(make_contract(&c0))
        .expect("import c0");
    engine
        .import_contract(make_contract(&c1))
        .expect("import c1");

    assert_eq!(engine.open_checkpoints(), 0);
    assert_eq!(engine.active_contracts().count(), 2);

    // CP1 (Level 1)
    let cp1 = engine.begin_try().expect("begin_try cp1");
    assert_eq!(engine.open_checkpoints(), 1);

    // In Level 1: import c2
    let c2 = "c2".to_string();
    engine
        .import_contract(make_contract(&c2))
        .expect("import c2");

    // CP2 (Level 2, nested)
    let cp2 = engine.begin_try().expect("begin_try cp2");
    assert_eq!(engine.open_checkpoints(), 2);

    // In Level 2: import c3
    let c3 = "c3".to_string();
    engine
        .import_contract(make_contract(&c3))
        .expect("import c3");

    // CP3 (Level 3, deepest nested)
    let cp3 = engine.begin_try().expect("begin_try cp3");
    assert_eq!(engine.open_checkpoints(), 3);

    // In Level 3: import c4
    let c4 = "c4".to_string();
    engine
        .import_contract(make_contract(&c4))
        .expect("import c4");
    assert_eq!(engine.active_contracts().count(), 5);

    // --- Action 1: Abort Level 3 (innermost) ---
    engine.abort_try(cp3).expect("abort cp3");
    assert_eq!(engine.open_checkpoints(), 2);
    // c4 MUST be completely purged!
    assert!(
        engine.contract(&c4).is_none(),
        "c4 must be purged after cp3 abort"
    );
    assert!(engine.contract(&c3).is_some(), "c3 must remain from cp2");

    // --- Action 2: Abort Level 2 ---
    engine.abort_try(cp2).expect("abort cp2");
    assert_eq!(engine.open_checkpoints(), 1);
    // c3 must be purged!
    assert!(
        engine.contract(&c3).is_none(),
        "c3 must be purged after cp2 abort"
    );
    assert!(engine.contract(&c2).is_some(), "c2 must remain from cp1");

    // --- Action 3: Commit Level 1 ---
    engine.end_try(cp1).expect("end_try cp1");
    assert_eq!(engine.open_checkpoints(), 0);

    // Final state: c0, c1, c2 exist; c3, c4 are completely gone!
    assert!(engine.contract(&c0).is_some());
    assert!(engine.contract(&c1).is_some());
    assert!(engine.contract(&c2).is_some());
    assert!(engine.contract(&c3).is_none());
    assert!(engine.contract(&c4).is_none());
    assert_eq!(engine.active_contracts().count(), 3);
}

#[test]
fn challenge_engine_invalid_and_stale_checkpoint_rejection() {
    let fx = fixture();
    let mut engine = Engine::new(&fx.world);

    // Non-existent checkpoint token
    let bogus = TryCheckpoint(999);
    let err_end = engine.end_try(bogus).unwrap_err();
    assert!(matches!(err_end, EvalError::Host(_)));

    let err_abort = engine.abort_try(bogus).unwrap_err();
    assert!(matches!(err_abort, EvalError::Host(_)));

    // Begin a valid checkpoint, abort it, then attempt to abort it again (double abort)
    let cp = engine.begin_try().expect("begin_try");
    assert_eq!(engine.open_checkpoints(), 1);
    engine.abort_try(cp).expect("abort first time");
    assert_eq!(engine.open_checkpoints(), 0);

    // Second abort with the same stale token MUST FAIL
    let err_stale = engine.abort_try(cp).unwrap_err();
    assert!(matches!(err_stale, EvalError::Host(_)));
}

#[test]
fn challenge_active_ledger_state_deep_rollback_with_keys_and_double_spend() {
    let mut state = ActiveLedgerState::new();
    let mut act_as = HashSet::new();
    act_as.insert("Alice".into());

    let mut sigs = HashSet::new();
    sigs.insert("Alice".into());

    // Root Tx: create K1 (key1) and K2 (key2)
    let mut tx0 = TransactionTree::new();
    let cid1 =
        ContractId("001111111111111111111111111111111111111111111111111111111111111111".into());
    let cid2 =
        ContractId("002222222222222222222222222222222222222222222222222222222222222222".into());

    tx0.insert_node(
        Node::Create {
            contract_id: cid1.clone(),
            template_id: "T".into(),
            payload: vec![1],
            signatories: sigs.clone(),
            observers: HashSet::new(),
            key: Some("key1".into()),
        },
        true,
    );
    tx0.insert_node(
        Node::Create {
            contract_id: cid2.clone(),
            template_id: "T".into(),
            payload: vec![2],
            signatories: sigs.clone(),
            observers: HashSet::new(),
            key: Some("key2".into()),
        },
        true,
    );
    state.apply_transaction(&tx0, &act_as).expect("tx0 apply");
    assert_eq!(state.active_contracts.len(), 2);
    assert_eq!(state.keys.get("key1"), Some(&cid1));
    assert_eq!(state.keys.get("key2"), Some(&cid2));

    // Tx1: Contains a Node::Rollback that consumes K1, steals "key1" for K3, consumes K2,
    // and nests another Rollback that creates K4 with "key3".
    let mut tx1 = TransactionTree::new();
    let cid3 =
        ContractId("003333333333333333333333333333333333333333333333333333333333333333".into());
    let cid4 =
        ContractId("004444444444444444444444444444444444444444444444444444444444444444".into());

    let nid_consume_k1 = tx1.insert_node(
        Node::Exercise {
            contract_id: cid1.clone(),
            choice: "Archive".into(),
            acting_parties: sigs.clone(),
            consuming: true,
            children: vec![],
        },
        false,
    );
    let nid_create_k3 = tx1.insert_node(
        Node::Create {
            contract_id: cid3.clone(),
            template_id: "T".into(),
            payload: vec![3],
            signatories: sigs.clone(),
            observers: HashSet::new(),
            key: Some("key1".into()), // reuses key1 after K1 archive
        },
        false,
    );
    let nid_create_k4 = tx1.insert_node(
        Node::Create {
            contract_id: cid4.clone(),
            template_id: "T".into(),
            payload: vec![4],
            signatories: sigs.clone(),
            observers: HashSet::new(),
            key: Some("key3".into()),
        },
        false,
    );
    let nid_inner_rollback = tx1.insert_node(
        Node::Rollback {
            children: vec![nid_create_k4],
        },
        false,
    );

    tx1.insert_node(
        Node::Rollback {
            children: vec![nid_consume_k1, nid_create_k3, nid_inner_rollback],
        },
        true,
    );

    // Apply tx1 (which has the top-level Rollback)
    state.apply_transaction(&tx1, &act_as).expect("tx1 apply");

    // VERIFY ZERO LEAKAGE:
    // cid1 must be active with key1!
    assert!(state.active_contracts.contains_key(&cid1));
    assert!(state.active_contracts.contains_key(&cid2));
    assert!(!state.active_contracts.contains_key(&cid3));
    assert!(!state.active_contracts.contains_key(&cid4));

    assert_eq!(state.keys.get("key1"), Some(&cid1));
    assert_eq!(state.keys.get("key2"), Some(&cid2));
    assert_eq!(state.keys.get("key3"), None);
}

#[test]
fn challenge_real_dar_exercise_assertion_failure_leaves_acs_clean() {
    let fx = fixture();
    let mut engine = Engine::new(&fx.world);

    // Create an AssetHolding: Bank, Alice, 100.0 USD
    let holding_schema = RecordSchema::template(&fx.surfaces, "AssetHolding:AssetHolding").unwrap();
    let initial_json = json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0"
    });
    let initial_val = holding_schema.from_json(&initial_json).unwrap();
    let created = engine
        .execute_create(
            &["Bank".to_string(), "Alice".to_string()],
            "AssetHolding:AssetHolding",
            &initial_val,
        )
        .expect("create holding");

    let cid = created.contract_id;
    assert_eq!(engine.active_contracts().count(), 1);
    assert_eq!(engine.open_checkpoints(), 0);

    // SplitTransfer choice schema
    let split_schema =
        RecordSchema::choice_arg(&fx.surfaces, "AssetHolding:AssetHolding", "SplitTransfer")
            .unwrap();

    // Adversarial vector 1: transferAmount > amount (150.0 > 100.0)
    // The Daml code contains: `assertMsg "Transfer amount must be less than current balance" (transferAmount < amount)`
    let bad_split_json = json!({
        "recipient": "Bob",
        "transferAmount": "150.0"
    });
    let bad_split_val = split_schema.from_json(&bad_split_json).unwrap();

    // Alice is controller, Bank and Bob must also actAs for co-signatory
    let act_as = vec!["Alice".to_string(), "Bank".to_string(), "Bob".to_string()];
    let res = engine.execute_exercise(&act_as, &cid, "SplitTransfer", &bad_split_val);

    // MUST FAIL with assertion error
    let err = res.expect_err("should fail split assertion");
    match err {
        ExecError::Unhandled { message, .. } => {
            assert!(message.contains("Transfer amount must be less than current balance"));
        }
        other => panic!("expected Unhandled assertion failure, got {other:?}"),
    }

    // ACS MUST BE COMPLETELY UNTOUCHED:
    // Original contract MUST STILL BE ACTIVE!
    assert_eq!(engine.active_contracts().count(), 1);
    assert!(engine.contract(&cid).unwrap().active);
    assert_eq!(engine.open_checkpoints(), 0);

    // Adversarial vector 2: transferAmount == 0.0 (violating transferAmount > 0.0)
    let zero_split_json = json!({
        "recipient": "Bob",
        "transferAmount": "0.0"
    });
    let zero_split_val = split_schema.from_json(&zero_split_json).unwrap();
    let res2 = engine.execute_exercise(&act_as, &cid, "SplitTransfer", &zero_split_val);
    let err2 = res2.expect_err("should fail positive amount assertion");
    match err2 {
        ExecError::Unhandled { message, .. } => {
            assert!(message.contains("Transfer amount must be positive"));
        }
        other => panic!("expected Unhandled assertion failure, got {other:?}"),
    }

    assert_eq!(engine.active_contracts().count(), 1);
    assert!(engine.contract(&cid).unwrap().active);
    assert_eq!(engine.open_checkpoints(), 0);

    // Adversarial vector 3: Transfer to current owner (violating newOwner /= owner)
    let transfer_schema =
        RecordSchema::choice_arg(&fx.surfaces, "AssetHolding:AssetHolding", "Transfer").unwrap();
    let self_transfer_json = json!({
        "newOwner": "Alice"
    });
    let self_transfer_val = transfer_schema.from_json(&self_transfer_json).unwrap();
    let res3 = engine.execute_exercise(&act_as, &cid, "Transfer", &self_transfer_val);
    let err3 = res3.expect_err("should fail self transfer assertion");
    match err3 {
        ExecError::Unhandled { message, .. } => {
            assert!(message.contains("New owner cannot be the same as current owner"));
        }
        other => panic!("expected Unhandled assertion failure, got {other:?}"),
    }

    assert_eq!(engine.active_contracts().count(), 1);
    assert!(engine.contract(&cid).unwrap().active);
    assert_eq!(engine.open_checkpoints(), 0);
}

// =======================================================================================
// Section 2: Codec Boundary Challenge
// =======================================================================================

#[test]
fn challenge_codec_empty_truncated_and_non_canonical_wire() {
    let fx = fixture();
    let schema = RecordSchema::template(&fx.surfaces, "AssetHolding:AssetHolding").unwrap();

    // 1. Empty input -> EmptyInput
    assert_eq!(schema.decode(&[]).unwrap_err(), CodecError::EmptyInput);

    // 2. Truncated single/double bytes -> Wire error
    assert!(matches!(
        schema.decode(&[0x08]).unwrap_err(),
        CodecError::Wire(_)
    ));
    assert!(matches!(
        schema.decode(&[0x0a, 0x05]).unwrap_err(),
        CodecError::Wire(_)
    ));

    // 3. Valid wire encoding
    let val = schema
        .from_json(&json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "100.0"
        }))
        .unwrap();
    let canonical_bytes = schema.encode(&val).unwrap();
    assert!(!canonical_bytes.is_empty());

    // Appending illegal tag 0 -> Wire error
    let mut illegal_tag = canonical_bytes.clone();
    illegal_tag.push(0x00);
    assert!(matches!(
        schema.decode(&illegal_tag).unwrap_err(),
        CodecError::Wire(_)
    ));

    // Appending an unknown protobuf field 20 (varint 0) -> NonCanonical error
    let mut unknown_field_bytes = canonical_bytes;
    unknown_field_bytes.extend_from_slice(&[0xa0, 0x01, 0x00]);
    assert_eq!(
        schema.decode(&unknown_field_bytes).unwrap_err(),
        CodecError::NonCanonical
    );
}

#[test]
fn challenge_codec_json_schema_edge_cases_and_boundary_types() {
    let fx = fixture();
    let schema = RecordSchema::template(&fx.surfaces, "AssetHolding:AssetHolding").unwrap();

    // 1. Primitives instead of Object
    assert!(matches!(
        schema.from_json(&json!(42)).unwrap_err(),
        CodecError::NotARecord { .. }
    ));
    assert!(matches!(
        schema.from_json(&json!("not an object")).unwrap_err(),
        CodecError::NotARecord { .. }
    ));
    assert!(matches!(
        schema.from_json(&json!([1, 2, 3])).unwrap_err(),
        CodecError::NotARecord { .. }
    ));

    // 2. Missing required field (missing 'amount')
    let missing_amount = json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD"
    });
    assert_eq!(
        schema.from_json(&missing_amount).unwrap_err(),
        CodecError::MissingField {
            record: "AssetHolding:AssetHolding".into(),
            field: "amount".into()
        }
    );

    // 3. Unknown field (detecting typos)
    let typo_field = json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0",
        "extra": "typo"
    });
    assert_eq!(
        schema.from_json(&typo_field).unwrap_err(),
        CodecError::UnknownField {
            record: "AssetHolding:AssetHolding".into(),
            field: "extra".into()
        }
    );

    // 4. Null for non-optional fields
    let null_field = json!({
        "bank": null,
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.0"
    });
    assert!(matches!(
        schema.from_json(&null_field).unwrap_err(),
        CodecError::TypeMismatch { .. }
    ));

    // 5. Party syntax validation at from_json (and encode) time:
    for invalid_party in &["", " Alice", "Alice ", "   ", "Alice@Daml!"] {
        let bad_party_json = json!({
            "bank": invalid_party,
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": "100.0"
        });
        let json_res = schema.from_json(&bad_party_json);
        assert!(
            matches!(json_res, Err(CodecError::Wire(_))),
            "party '{invalid_party}' must be rejected during from_json parsing"
        );
    }

    // 6. Numeric boundary testing
    // Extra precision beyond Decimal scale 10: 100.00000000001 (11 fraction digits)
    let lossy_numeric = json!({
        "bank": "Bank",
        "owner": "Alice",
        "auditor": "Auditor",
        "assetSymbol": "USD",
        "amount": "100.00000000001"
    });
    assert!(matches!(
        schema.from_json(&lossy_numeric).unwrap_err(),
        CodecError::NumericScale { .. }
    ));

    // Malformed numeric representations
    for bad_num in &["abc", "--1", "1.2.3", "1e10", "NaN", "Infinity", ""] {
        let bad_num_json = json!({
            "bank": "Bank",
            "owner": "Alice",
            "auditor": "Auditor",
            "assetSymbol": "USD",
            "amount": bad_num
        });
        assert!(
            schema.from_json(&bad_num_json).is_err(),
            "numeric '{bad_num}' must be rejected"
        );
    }
}

#[test]
fn challenge_codec_unsupported_types_and_invalid_utf8_contract_id() {
    // 1. Nested Optionals: Optional (Optional Text) must be refused
    let field = |name: &str, ty: SurfaceType| {
        let def = FieldDef::new(name, ty);
        (def.name, def.ty)
    };
    let nested_opt_schema = RecordSchema {
        tycon: "Bad:NestedOpt".into(),
        fields: vec![field(
            "bad_opt",
            SurfaceType::Optional(Box::new(SurfaceType::Optional(Box::new(SurfaceType::Text)))),
        )],
    };
    let rec = Value::Record {
        tycon: None,
        fields: vec![("bad_opt".into(), Value::Optional(None))],
    };
    assert!(matches!(
        nested_opt_schema.encode(&rec).unwrap_err(),
        CodecError::UnsupportedType { .. }
    ));

    // 2. Invalid UTF-8 bytes for ContractId on decode
    let cid_schema = RecordSchema {
        tycon: "Cid:Test".into(),
        fields: vec![field(
            "cid",
            SurfaceType::ContractId(Box::new(SurfaceType::Text)),
        )],
    };
    let bad_utf8_bytes = lf_archive::Value::Record {
        fields: vec![lf_archive::Value::ContractId(vec![0xff, 0xfe, 0x80])],
    }
    .encode_to_vec();
    assert!(matches!(
        cid_schema.decode(&bad_utf8_bytes).unwrap_err(),
        CodecError::InvalidContractId { .. }
    ));
}
