//! Empirical Oracle Challenge & Adversarial Stress Tests for M1 Module Surface Decoding.
//!
//! Objectives:
//! 1. Oracle Verification: Compare decoded `ModuleSurface` against the golden AST dump
//!    from `damlc inspect` (`tests/e2e/fixtures/damlc_inspect_sample_contract.txt`).
//! 2. Exhaustive Field/Choice Audit: Field names, types, signatories, observers, choices,
//!    controllers, choice params, return types, and ensure/do byte presence.
//! 3. Serde Round-Trip & Schema Invariants: Verify JSON serialization and round-trip equality.
//! 4. Adversarial Failure Modes: Verify fail-closed behavior on missing signatories,
//!    unresolved controllers, missing template records, variant-as-template, OOB type indices,
//!    and recursion depth bombs.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::proto::daml_lf::{
    archive_payload::Sum as PayloadSum, Archive, ArchivePayload, HashFunction,
};
use lf_archive::proto::daml_lf_2::def_data_type::Fields;
use lf_archive::proto::daml_lf_2::{
    def_data_type, expr, r#type, DefDataType, DefTemplate, Expr, FieldWithType, InternedDottedName,
    Module, Package, PackageMetadata, TemplateChoice, Type,
};
use lf_archive::surface::SurfaceType;
use lf_archive::{decode_dalf, parse_dar_file, DarArchive, DecodeError};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

// ===========================================================================
// Test 1: Oracle Verification Against damlc inspect Dump
// ===========================================================================

#[test]
fn test_oracle_damlc_inspect_alignment() {
    // The tracked fixture is the only source.
    let inspect_dump_path =
        repo_root().join("tests/e2e/fixtures/damlc_inspect_sample_contract.txt");
    assert!(
        inspect_dump_path.exists(),
        "damlc inspect fixture must exist at {:?}",
        inspect_dump_path
    );

    let inspect_dump =
        fs::read_to_string(&inspect_dump_path).expect("failed to read damlc inspect dump");

    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    assert!(dar_path.exists(), "sample-contract.dar must exist");

    let archive = parse_dar_file(&dar_path).expect("failed to parse sample-contract.dar");

    // --- 1. Package ID Oracle Check ---
    let first_line = inspect_dump.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("package "),
        "expected line 1 to start with 'package '"
    );
    let oracle_pkg_id = first_line.strip_prefix("package ").unwrap().trim();
    assert_eq!(
        archive.main_package_id, oracle_pkg_id,
        "main package ID does not match damlc inspect"
    );

    // --- 2. Daml-LF Version Oracle Check ---
    let second_line = inspect_dump.lines().nth(1).unwrap_or("");
    assert!(
        second_line.starts_with("daml-lf "),
        "expected line 2 to start with 'daml-lf '"
    );
    let oracle_lf_ver = second_line.strip_prefix("daml-lf ").unwrap().trim();
    assert_eq!(
        archive.lf_version, oracle_lf_ver,
        "Daml-LF version does not match damlc inspect"
    );

    // --- 3. Module & Template Surface Oracle Check ---
    assert_eq!(archive.module_surfaces.len(), 1);
    let module = &archive.module_surfaces[0];
    assert_eq!(module.name, "AssetHolding");
    assert_eq!(module.templates.len(), 1);

    let template = &module.templates[0];
    assert_eq!(template.name, "AssetHolding");
    assert_eq!(template.param_name, "this");

    // Oracle record check in damlc inspect:
    // record @serializable AssetHolding =
    //   {bank : Party;
    //    owner : Party;
    //    auditor : Party;
    //    assetSymbol : Text;
    //    amount : Numeric 10}
    assert!(
        inspect_dump.contains("record @serializable AssetHolding ="),
        "damlc inspect must define record AssetHolding"
    );
    assert_eq!(template.fields.len(), 5);

    let expected_oracle_fields = [
        ("bank", SurfaceType::Party, "Party"),
        ("owner", SurfaceType::Party, "Party"),
        ("auditor", SurfaceType::Party, "Party"),
        ("assetSymbol", SurfaceType::Text, "Text"),
        ("amount", SurfaceType::Numeric(Some(10)), "Decimal"),
    ];

    for (i, (fname, fty, fstr)) in expected_oracle_fields.iter().enumerate() {
        let actual = &template.fields[i];
        assert_eq!(actual.name, *fname, "field {} name mismatch", i);
        assert_eq!(&actual.ty, fty, "field {} type mismatch", i);
        assert_eq!(&actual.type_str, fstr, "field {} type_str mismatch", i);
    }

    // --- 4. Signatories & Observers Oracle Check ---
    // In damlc inspect:
    // signatory AssetHolding:$csignatory this
    // observer AssetHolding:$cobserver this
    // def $csignatory -> projects bank, owner
    // def $cobserver -> projects auditor
    assert_eq!(template.signatories, vec!["bank", "owner"]);
    assert_eq!(template.observers, vec!["auditor"]);

    // --- 5. Precondition (ensure) Oracle Check ---
    // In damlc inspect:
    // ensure case AssetHolding:$censure this of ...
    assert!(
        inspect_dump.contains("ensure case AssetHolding:$censure this of"),
        "damlc inspect must have ensure expression"
    );
    assert!(template.ensure.present, "ensure must be marked present");
    assert!(
        template.ensure.bytes_len > 0,
        "ensure bytecode length must be non-zero"
    );

    // --- 6. Choices Oracle Check ---
    // In damlc inspect: 4 choices defined:
    // Transfer, SplitTransfer, Archive, Settle
    assert_eq!(template.choices.len(), 4);

    let choice_names: HashSet<&str> = template.choices.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        choice_names,
        HashSet::from(["Transfer", "SplitTransfer", "Archive", "Settle"])
    );

    // 6a. Choice: Transfer
    // consuming choice Transfer (self : ContractId AssetHolding:AssetHolding) (arg : AssetHolding:Transfer) : ContractId AssetHolding:AssetHolding
    //   controller AssetHolding:$$sc_AssetHolding_3 this arg -> owner
    //   record @serializable Transfer = {newOwner : Party}
    let transfer = template
        .choices
        .iter()
        .find(|c| c.name == "Transfer")
        .unwrap();
    assert!(transfer.consuming);
    assert_eq!(transfer.controllers, vec!["owner"]);
    assert!(transfer.observers.is_empty());
    assert_eq!(transfer.params.len(), 1);
    assert_eq!(transfer.params[0].name, "newOwner");
    assert_eq!(transfer.params[0].ty, SurfaceType::Party);
    assert_eq!(transfer.params[0].type_str, "Party");
    assert_eq!(transfer.return_type_str, "ContractId AssetHolding");
    assert!(transfer.do_body.present);
    assert!(transfer.do_body.bytes_len > 0);

    // 6b. Choice: SplitTransfer
    // consuming choice SplitTransfer ... : Tuple2 (ContractId AssetHolding) (ContractId AssetHolding)
    //   controller AssetHolding:$$sc_AssetHolding_7 this arg -> owner
    //   record @serializable SplitTransfer = {transferAmount : Numeric 10; recipient : Party}
    let split = template
        .choices
        .iter()
        .find(|c| c.name == "SplitTransfer")
        .unwrap();
    assert!(split.consuming);
    assert_eq!(split.controllers, vec!["owner"]);
    assert!(split.observers.is_empty());
    assert_eq!(split.params.len(), 2);
    assert_eq!(split.params[0].name, "transferAmount");
    assert_eq!(split.params[0].ty, SurfaceType::Numeric(Some(10)));
    assert_eq!(split.params[0].type_str, "Decimal");
    assert_eq!(split.params[1].name, "recipient");
    assert_eq!(split.params[1].ty, SurfaceType::Party);
    assert_eq!(split.params[1].type_str, "Party");
    assert_eq!(
        split.return_type_str,
        "(ContractId AssetHolding, ContractId AssetHolding)"
    );
    assert!(split.do_body.present);
    assert!(split.do_body.bytes_len > 0);

    // 6c. Choice: Settle
    // consuming choice Settle ... : Unit
    //   controller AssetHolding:$$sc_AssetHolding_15 this arg -> bank
    //   record @serializable Settle = {}
    let settle = template
        .choices
        .iter()
        .find(|c| c.name == "Settle")
        .unwrap();
    assert!(settle.consuming);
    assert_eq!(settle.controllers, vec!["bank"]);
    assert!(settle.observers.is_empty());
    assert!(settle.params.is_empty());
    assert_eq!(settle.return_type, SurfaceType::Unit);
    assert_eq!(settle.return_type_str, "()");
    assert!(settle.do_body.present);
    assert!(settle.do_body.bytes_len > 0);

    // 6d. Choice: Archive
    // consuming choice Archive ... : Unit
    //   controller AssetHolding:$$sc_AssetHolding_13 this arg -> $csignatory -> bank, owner
    let archive_ch = template
        .choices
        .iter()
        .find(|c| c.name == "Archive")
        .unwrap();
    assert!(archive_ch.consuming);
    assert_eq!(archive_ch.controllers, vec!["bank", "owner"]);
    assert!(archive_ch.observers.is_empty());
    assert!(archive_ch.params.is_empty());
    assert_eq!(archive_ch.return_type, SurfaceType::Unit);
    assert_eq!(archive_ch.return_type_str, "()");
    assert!(archive_ch.do_body.present);
    assert!(archive_ch.do_body.bytes_len > 0);
}

// ===========================================================================
// Test 2: Serde Round-Trip & JSON Schema Audit
// ===========================================================================

#[test]
fn test_serde_json_roundtrip_and_schema_validation() {
    let dar_path = repo_root().join("contracts/target/sample-contract.dar");
    let archive = parse_dar_file(&dar_path).expect("failed to parse sample-contract.dar");

    // 1. Serialize to JSON string
    let json_str =
        serde_json::to_string_pretty(&archive).expect("DarArchive must serialize to JSON");

    // 2. Parse into generic serde_json::Value to check exact schema keys
    let val: serde_json::Value =
        serde_json::from_str(&json_str).expect("serialized JSON must be valid");

    assert!(val.get("main_package_id").is_some());
    assert!(val.get("lf_version").is_some());
    assert!(val.get("module_surfaces").is_some());

    let mod_surfaces = val["module_surfaces"]
        .as_array()
        .expect("module_surfaces must be array");
    assert_eq!(mod_surfaces.len(), 1);

    let mod0 = &mod_surfaces[0];
    assert_eq!(mod0["name"].as_str(), Some("AssetHolding"));

    let tmpls = mod0["templates"]
        .as_array()
        .expect("templates must be array");
    assert_eq!(tmpls.len(), 1);

    let tmpl0 = &tmpls[0];
    assert_eq!(tmpl0["name"].as_str(), Some("AssetHolding"));
    assert_eq!(tmpl0["param_name"].as_str(), Some("this"));

    // Check fields array
    let fields = tmpl0["fields"].as_array().expect("fields must be array");
    assert_eq!(fields.len(), 5);
    for f in fields {
        assert!(f.get("name").is_some());
        assert!(f.get("ty").is_some());
        assert!(f.get("type_str").is_some());
    }

    // Check signatories and observers
    let sigs = tmpl0["signatories"]
        .as_array()
        .expect("signatories must be array");
    assert_eq!(
        sigs.iter().map(|s| s.as_str().unwrap()).collect::<Vec<_>>(),
        vec!["bank", "owner"]
    );

    let obs = tmpl0["observers"]
        .as_array()
        .expect("observers must be array");
    assert_eq!(
        obs.iter().map(|s| s.as_str().unwrap()).collect::<Vec<_>>(),
        vec!["auditor"]
    );

    // Check ensure byte presence marker
    let ensure = &tmpl0["ensure"];
    assert_eq!(ensure["present"].as_bool(), Some(true));
    assert!(ensure["bytes_len"].as_u64().unwrap() > 0);

    // Check choices
    let choices = tmpl0["choices"].as_array().expect("choices must be array");
    assert_eq!(choices.len(), 4);

    // 3. Round-trip deserialization back to DarArchive
    let deserialized: DarArchive =
        serde_json::from_str(&json_str).expect("must deserialize JSON back to DarArchive");
    assert_eq!(deserialized, archive, "roundtrip must be identically equal");
}

// ===========================================================================
// Test Helpers for Synthetic Protobuf Construction
// ===========================================================================

fn package_to_dalf_bytes(pkg: Package) -> Vec<u8> {
    let mut pkg_bytes = Vec::new();
    pkg.encode(&mut pkg_bytes).unwrap();

    let payload = ArchivePayload {
        minor: "1".to_string(),
        patch: 0,
        sum: Some(PayloadSum::DamlLf2(pkg_bytes)),
    };
    let mut payload_bytes = Vec::new();
    payload.encode(&mut payload_bytes).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&payload_bytes);
    let hash = hex::encode(hasher.finalize());

    let archive = Archive {
        hash_function: HashFunction::Sha256 as i32,
        payload: payload_bytes,
        hash,
    };
    let mut archive_bytes = Vec::new();
    archive.encode(&mut archive_bytes).unwrap();
    archive_bytes
}

fn make_base_package() -> Package {
    // Strings:
    // 0: "TestMod"
    // 1: "TestTemplate"
    // 2: "this"
    // 3: "party"
    // 4: "Transfer"
    let interned_strings = vec![
        "TestMod".to_string(),
        "TestTemplate".to_string(),
        "this".to_string(),
        "party".to_string(),
        "Transfer".to_string(),
    ];

    // Dotted names:
    // 0: ["TestMod"]
    // 1: ["TestTemplate"]
    let interned_dotted_names = vec![
        InternedDottedName {
            segments_interned_str: vec![0],
        },
        InternedDottedName {
            segments_interned_str: vec![1],
        },
    ];

    Package {
        modules: Vec::new(),
        interned_strings,
        interned_dotted_names,
        metadata: Some(PackageMetadata {
            name_interned_str: 0,
            version_interned_str: 0,
            ..Default::default()
        }),
        interned_types: Vec::new(),
        ..Default::default()
    }
}

// ===========================================================================
// Test 3: Adversarial Challenge - Missing Signatory Rejection
// ===========================================================================

#[test]
fn test_challenge_missing_signatory_rejected() {
    let mut pkg = make_base_package();

    // Module with template that has NO signatories
    let record_type = DefDataType {
        name_interned_dname: 1, // "TestTemplate"
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 3, // "party"
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: 6, // Party
                        args: vec![],
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    let tmpl = DefTemplate {
        tycon_interned_dname: 1, // "TestTemplate"
        param_interned_str: 2,   // "this"
        precond: None,
        signatories: None, // NO SIGNATORIES!
        choices: vec![],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0, // "TestMod"
        data_types: vec![record_type],
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject template without signatories");
    assert!(
        matches!(&err, DecodeError::MissingSignatory(name) if name == "TestTemplate"),
        "expected MissingSignatory('TestTemplate'), got {:?}",
        err
    );
}

// ===========================================================================
// Test 4: Adversarial Challenge - Unresolved Choice Controller Rejection
// ===========================================================================

#[test]
fn test_challenge_unresolved_choice_controller_rejected() {
    let mut pkg = make_base_package();

    // Template record with field "party"
    let record_type = DefDataType {
        name_interned_dname: 1, // "TestTemplate"
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 3, // "party"
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: 6, // Party
                        args: vec![],
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    // Valid signatory: projection on field "party" (str index 3)
    let sig_expr = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 3,
            record: None,
        }))),
        ..Default::default()
    };

    // Choice with empty controller expression (cannot be resolved to any party)
    let choice = TemplateChoice {
        name_interned_str: 4, // "Transfer"
        consuming: true,
        controllers: None, // No controller expression!
        observers: None,
        arg_binder: None,
        ret_type: None,
        update: None,
        self_binder_interned_str: 0,
        ..Default::default()
    };

    let tmpl = DefTemplate {
        tycon_interned_dname: 1, // "TestTemplate"
        param_interned_str: 2,   // "this"
        precond: None,
        signatories: Some(sig_expr),
        choices: vec![choice],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![record_type],
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject choice with unresolved controller");
    assert!(
        matches!(&err, DecodeError::UnresolvedChoiceController(name) if name == "Transfer"),
        "expected UnresolvedChoiceController('Transfer'), got {:?}",
        err
    );
}

// ===========================================================================
// Test 5: Adversarial Challenge - Template Record Not Found
// ===========================================================================

#[test]
fn test_challenge_template_record_not_found_rejected() {
    let mut pkg = make_base_package();

    // Module has DefTemplate "TestTemplate" but NO matching DefDataType in data_types!
    let tmpl = DefTemplate {
        tycon_interned_dname: 1, // "TestTemplate"
        param_interned_str: 2,
        precond: None,
        signatories: None,
        choices: vec![],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![], // Empty!
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject missing template record");
    assert!(
        matches!(&err, DecodeError::TemplateRecordNotFound { template } if template == "TestTemplate"),
        "expected TemplateRecordNotFound, got {:?}",
        err
    );
}

// ===========================================================================
// Test 6: Adversarial Challenge - Variant Cannot Be Template Record
// ===========================================================================

#[test]
fn test_challenge_variant_as_template_rejected() {
    let mut pkg = make_base_package();

    // Define DefDataType as a Variant instead of a Record!
    let variant_type = DefDataType {
        name_interned_dname: 1, // "TestTemplate"
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Variant(Fields { fields: vec![] })),
        ..Default::default()
    };

    let tmpl = DefTemplate {
        tycon_interned_dname: 1,
        param_interned_str: 2,
        precond: None,
        signatories: None,
        choices: vec![],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![variant_type],
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject variant as template");
    assert!(
        matches!(&err, DecodeError::InvalidTemplateRecord { template, .. } if template == "TestTemplate"),
        "expected InvalidTemplateRecord, got {:?}",
        err
    );
}

// ===========================================================================
// Test 7: Adversarial Challenge - Out-of-Bounds Interned Type Index
// ===========================================================================

#[test]
fn test_challenge_interned_type_oob_rejected() {
    let mut pkg = make_base_package();

    // Field type points to interned_type index 42, but table has length 0!
    let record_type = DefDataType {
        name_interned_dname: 1,
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 3,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::InternedType(42)),
                }),
            }],
        })),
        ..Default::default()
    };

    let tmpl = DefTemplate {
        tycon_interned_dname: 1,
        param_interned_str: 2,
        precond: None,
        signatories: None,
        choices: vec![],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![record_type],
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject oob interned type index");
    assert!(
        matches!(
            &err,
            DecodeError::InternedIndexOutOfBounds {
                index: 42,
                table_size: 0,
                ..
            }
        ),
        "expected InternedIndexOutOfBounds for index 42, got {:?}",
        err
    );
}

// ===========================================================================
// Test 8: Adversarial Challenge - Cyclic / Deep Recursion Bomb Guard
// ===========================================================================

#[test]
fn test_challenge_cyclic_type_recursion_depth_limit() {
    let mut pkg = make_base_package();

    // Construct a self-referencing cyclic interned type: index 0 points to index 0
    pkg.interned_types = vec![Type {
        sum: Some(r#type::Sum::InternedType(0)),
    }];

    let record_type = DefDataType {
        name_interned_dname: 1,
        serializable: true,
        data_cons: Some(def_data_type::DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 3,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::InternedType(0)), // Cycle!
                }),
            }],
        })),
        ..Default::default()
    };

    let tmpl = DefTemplate {
        tycon_interned_dname: 1,
        param_interned_str: 2,
        precond: None,
        signatories: None,
        choices: vec![],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![record_type],
        values: vec![],
        templates: vec![tmpl],
        ..Default::default()
    };
    pkg.modules.push(module);

    let dalf_bytes = package_to_dalf_bytes(pkg);
    let err = decode_dalf(&dalf_bytes).expect_err("must reject cyclic interned type");
    assert!(
        matches!(&err, DecodeError::RecursionLimitExceeded { .. }),
        "expected RecursionLimitExceeded, got {:?}",
        err
    );
}
