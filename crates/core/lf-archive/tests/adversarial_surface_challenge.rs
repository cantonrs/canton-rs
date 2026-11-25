//! Adversarial stress tests and boundary challenges for Daml-LF2 surface decoding (M1).
//!
//! Validates:
//! 1. Cyclic type DAGs and recursion ceilings.
//! 2. Cyclic DefValue references in AST walkers.
//! 3. Deeply nested expression trees (depth limit enforcement).
//! 4. Missing and malformed template record definitions.
//! 5. Missing signatories and unresolved choice controllers (fail-closed behavior).
//! 6. Negative, extreme, and out-of-bounds interned indices across all tables.
//! 7. Complex SurfaceType variants, canonical Daml display formatting, and Serde roundtrips.
//! 8. BytePresence unexecuted preservation.
//! 9. End-to-end synthetic DAR construction and tamper resilience.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::decode::{
    extract_module_surfaces, resolve_interned_dotted_name, resolve_interned_string,
    resolve_surface_type,
};
use lf_archive::proto::daml_lf::{
    archive_payload::Sum as PayloadSum, Archive, ArchivePayload, HashFunction,
};
use lf_archive::proto::daml_lf_2::def_data_type::Fields;
use lf_archive::proto::daml_lf_2::def_value::NameWithType as DefValueNameWithType;
use lf_archive::proto::daml_lf_2::{
    def_data_type::DataCons, expr, r#type, BuiltinType, DefDataType, DefTemplate, DefValue, Expr,
    FieldWithType, InternedDottedName, Module, Package, TemplateChoice, Type, TypeConId,
};
use lf_archive::{
    compute_sha256, parse_dar_bytes, BytePresence, ChoiceDef, ChoiceParam, DarError, DecodeError,
    FieldDef, ModuleSurface, SurfaceType, TemplateSurface,
};
use prost::Message;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

// ===========================================================================
// Helper Functions for Building Synthetic Protobuf Structures
// ===========================================================================

fn make_interned_dname(segments: Vec<i32>) -> InternedDottedName {
    InternedDottedName {
        segments_interned_str: segments,
    }
}

fn wrap_package_into_dalf(package: &Package, minor: &str) -> Vec<u8> {
    let pkg_bytes = package.encode_to_vec();
    let payload = ArchivePayload {
        minor: minor.to_string(),
        patch: 0,
        sum: Some(PayloadSum::DamlLf2(pkg_bytes)),
    };
    let payload_bytes = payload.encode_to_vec();
    let hash = compute_sha256(&payload_bytes);

    let archive = Archive {
        hash_function: HashFunction::Sha256 as i32,
        payload: payload_bytes,
        hash,
    };
    archive.encode_to_vec()
}

fn build_synthetic_dar(manifest_text: &str, dalfs: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        zip.write_all(manifest_text.as_bytes()).unwrap();

        for (name, bytes) in dalfs {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }

        zip.finish().unwrap();
    }
    buf
}

// ===========================================================================
// Challenge 1: Cyclic Type DAG Stress Tests
// ===========================================================================

#[test]
fn challenge_cyclic_interned_type_dag_self_loop() {
    // interned_types[0] points to interned_types[0]
    let package = Package {
        modules: Vec::new(),
        interned_strings: vec!["Dummy".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: vec![Type {
            sum: Some(r#type::Sum::InternedType(0)),
        }],
        ..Default::default()
    };

    let target = &package.interned_types[0];
    let res = resolve_surface_type(&package, target);
    assert!(
        matches!(res, Err(DecodeError::RecursionLimitExceeded { context }) if context == "resolve_surface_type"),
        "expected RecursionLimitExceeded, got: {:?}",
        res
    );
}

#[test]
fn challenge_cyclic_interned_type_dag_mutual_cycle() {
    // 0 -> 1 -> 0
    let package = Package {
        modules: Vec::new(),
        interned_strings: vec!["T0".to_string(), "T1".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0]), make_interned_dname(vec![1])],
        metadata: None,
        interned_types: vec![
            Type {
                sum: Some(r#type::Sum::InternedType(1)),
            },
            Type {
                sum: Some(r#type::Sum::InternedType(0)),
            },
        ],
        ..Default::default()
    };

    let target = &package.interned_types[0];
    let res = resolve_surface_type(&package, target);
    assert!(
        matches!(res, Err(DecodeError::RecursionLimitExceeded { context }) if context == "resolve_surface_type"),
        "expected RecursionLimitExceeded for mutual cycle, got: {:?}",
        res
    );
}

#[test]
fn challenge_cyclic_interned_type_dag_large_ring() {
    // 50-element ring: 0 -> 1 -> 2 -> ... -> 49 -> 0
    let ring_size = 50;
    let mut interned_types = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let next = ((i + 1) % ring_size) as i32;
        interned_types.push(Type {
            sum: Some(r#type::Sum::InternedType(next)),
        });
    }

    let package = Package {
        modules: Vec::new(),
        interned_strings: vec!["RingNode".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types,
        ..Default::default()
    };

    let res = resolve_surface_type(&package, &package.interned_types[0]);
    assert!(
        matches!(res, Err(DecodeError::RecursionLimitExceeded { .. })),
        "expected RecursionLimitExceeded for 50-ring, got: {:?}",
        res
    );
}

#[test]
fn challenge_cyclic_type_con_args_recursion() {
    // TypeCon referencing itself as its first argument
    let package = Package {
        modules: Vec::new(),
        interned_strings: vec!["RecursiveCon".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: vec![Type {
            sum: Some(r#type::Sum::Con(r#type::Con {
                tycon: Some(TypeConId {
                    module: None,
                    name_interned_dname: 0,
                }),
                args: vec![Type {
                    sum: Some(r#type::Sum::InternedType(0)),
                }],
            })),
        }],
        ..Default::default()
    };

    let res = resolve_surface_type(&package, &package.interned_types[0]);
    assert!(
        matches!(res, Err(DecodeError::RecursionLimitExceeded { .. })),
        "expected RecursionLimitExceeded for recursive TypeCon, got: {:?}",
        res
    );
}

// ===========================================================================
// Challenge 2: Cyclic DefValue References in Expression AST Walker
// ===========================================================================

#[test]
fn challenge_cyclic_def_value_mutual_reference() {
    // DefValue 0 refers to DefValue 1; DefValue 1 refers to DefValue 0
    let val0_expr = Expr {
        sum: Some(expr::Sum::Val(lf_archive::proto::daml_lf_2::ValueId {
            module: None,
            name_interned_dname: 1,
        })),
        ..Default::default()
    };
    let val1_expr = Expr {
        sum: Some(expr::Sum::Val(lf_archive::proto::daml_lf_2::ValueId {
            module: None,
            name_interned_dname: 0,
        })),
        ..Default::default()
    };

    let values = vec![
        DefValue {
            name_with_type: Some(DefValueNameWithType {
                name_interned_dname: 0,
                r#type: None,
            }),
            expr: Some(val0_expr),
            ..Default::default()
        },
        DefValue {
            name_with_type: Some(DefValueNameWithType {
                name_interned_dname: 1,
                r#type: None,
            }),
            expr: Some(val1_expr),
            ..Default::default()
        },
    ];

    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    // Template whose signatory refers to val 0
    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(Expr {
            sum: Some(expr::Sum::Val(lf_archive::proto::daml_lf_2::ValueId {
                module: None,
                name_interned_dname: 0,
            })),
            ..Default::default()
        }),
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values,
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["owner".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0]), make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // Must terminate cleanly (cycle detected via visited_values HashSet) and fail-closed
    // because no RecProj was found in the mutually recursive loop
    let res = extract_module_surfaces(&package);
    assert!(
        matches!(res, Err(DecodeError::MissingSignatory(_))),
        "expected MissingSignatory due to cycle termination, got: {:?}",
        res
    );
}

// ===========================================================================
// Challenge 3: Deeply Nested AST Expressions (Depth Limit Enforcement)
// ===========================================================================

#[test]
fn challenge_deeply_nested_ast_expression_tree() {
    // Build a 50-level nested App tree: App(App(App(...)))
    let mut current_expr = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };

    for _ in 0..50 {
        current_expr = Expr {
            sum: Some(expr::Sum::App(Box::new(expr::App {
                fun: Some(Box::new(current_expr)),
                args: Vec::new(),
            }))),
            ..Default::default()
        };
    }

    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(current_expr),
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["owner".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // The RecProj is at depth 50 (> 32), so depth limit will cut off before reaching RecProj.
    // Result: signatories is empty -> MissingSignatory error, NO stack overflow!
    let res = extract_module_surfaces(&package);
    assert!(
        matches!(res, Err(DecodeError::MissingSignatory(_))),
        "deeply nested AST must terminate safely with MissingSignatory, got: {:?}",
        res
    );
}

// ===========================================================================
// Challenge 4: Missing & Malformed Template Record Definitions
// ===========================================================================

#[test]
fn challenge_template_record_missing_entirely() {
    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: None,
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: Vec::new(), // EMPTY data_types!
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["MissingRecordTmpl".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = extract_module_surfaces(&package);
    assert!(
        matches!(&res, Err(DecodeError::TemplateRecordNotFound { template }) if template == "MissingRecordTmpl"),
        "expected TemplateRecordNotFound, got: {:?}",
        res
    );
}

#[test]
fn challenge_template_record_is_variant_instead_of_record() {
    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Variant(Fields { fields: Vec::new() })), // VARIANT!,
        ..Default::default()
    };

    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: None,
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["VariantTmpl".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = extract_module_surfaces(&package);
    assert!(
        matches!(&res, Err(DecodeError::InvalidTemplateRecord { template, reason }) if template == "VariantTmpl" && reason.contains("variant")),
        "expected InvalidTemplateRecord variant, got: {:?}",
        res
    );
}

#[test]
fn challenge_template_record_has_no_data_cons() {
    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: None, // Missing data_cons!,
        ..Default::default()
    };

    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: None,
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["NoDataConsTmpl".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = extract_module_surfaces(&package);
    assert!(
        matches!(&res, Err(DecodeError::InvalidTemplateRecord { template, reason }) if template == "NoDataConsTmpl" && reason.contains("missing")),
        "expected InvalidTemplateRecord missing data_cons, got: {:?}",
        res
    );
}

// ===========================================================================
// Challenge 5: Missing Signatories & Unresolved Choice Controllers
// ===========================================================================

#[test]
fn challenge_missing_signatories_returns_fail_closed_error() {
    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    // Case A: signatories is None
    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: None,
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt.clone()],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["TestTmpl".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = extract_module_surfaces(&package);
    assert!(
        matches!(&res, Err(DecodeError::MissingSignatory(name)) if name == "TestTmpl"),
        "expected MissingSignatory for None signatories, got: {:?}",
        res
    );

    // Case B: signatories projects a non-existent field
    let template_invalid_sig = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(Expr {
            sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
                tycon: None,
                field_interned_str: 1, // "nonExistentField"
                record: None,
            }))),
            ..Default::default()
        }),
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let module2 = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template_invalid_sig],
        ..Default::default()
    };

    let package2 = Package {
        modules: vec![module2],
        interned_strings: vec!["TestTmpl".to_string(), "nonExistentField".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res2 = extract_module_surfaces(&package2);
    assert!(
        matches!(&res2, Err(DecodeError::MissingSignatory(name)) if name == "TestTmpl"),
        "expected MissingSignatory when signatory field is not on template, got: {:?}",
        res2
    );
}

#[test]
fn challenge_unresolved_choice_controller_fail_closed() {
    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    // Valid signatory ("owner")
    let sig_expr = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };

    // Choice with no controllers
    let choice = TemplateChoice {
        name_interned_str: 1, // "CustomChoice"
        consuming: true,
        controllers: None, // MISSING controller!
        observers: None,
        arg_binder: None,
        ret_type: None,
        update: None,
        self_binder_interned_str: 0,
        ..Default::default()
    };

    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(sig_expr.clone()),
        choices: vec![choice],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt.clone()],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["owner".to_string(), "CustomChoice".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = extract_module_surfaces(&package);
    assert!(
        matches!(&res, Err(DecodeError::UnresolvedChoiceController(name)) if name == "CustomChoice"),
        "expected UnresolvedChoiceController, got: {:?}",
        res
    );

    // Defense-in-depth: verify that choice named "Archive" WITH empty controller
    // successfully falls back to signatories!
    let archive_choice = TemplateChoice {
        name_interned_str: 2, // "Archive"
        consuming: true,
        controllers: None,
        observers: None,
        arg_binder: None,
        ret_type: None,
        update: None,
        self_binder_interned_str: 0,
        ..Default::default()
    };

    let template_archive = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(sig_expr),
        choices: vec![archive_choice],
        observers: None,
        ..Default::default()
    };

    let module_archive = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template_archive],
        ..Default::default()
    };

    let package_archive = Package {
        modules: vec![module_archive],
        interned_strings: vec![
            "owner".to_string(),
            "CustomChoice".to_string(),
            "Archive".to_string(),
        ],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res_archive = extract_module_surfaces(&package_archive);
    assert!(res_archive.is_ok(), "Archive fallback should succeed");
    let surfaces = res_archive.unwrap();
    assert_eq!(surfaces[0].templates[0].choices[0].name, "Archive");
    assert_eq!(
        surfaces[0].templates[0].choices[0].controllers,
        vec!["owner"]
    );
}

// ===========================================================================
// Challenge 6: Boundary & Out-of-Bounds Interned Indices
// ===========================================================================

#[test]
fn challenge_boundary_and_oob_interned_indices() {
    let package = Package {
        modules: Vec::new(),
        interned_strings: vec!["ValidString".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // Test extreme indices: -1, i32::MIN, table.len(), i32::MAX
    let test_indices = [-1, -100, i32::MIN, 1, 2, 99999, i32::MAX];

    for &idx in &test_indices {
        let str_res = resolve_interned_string(&package, idx, "test");
        assert!(
            matches!(str_res, Err(DecodeError::InternedIndexOutOfBounds { index, .. }) if index == idx),
            "resolve_interned_string should reject index {}",
            idx
        );

        let dname_res = resolve_interned_dotted_name(&package, idx, "test");
        assert!(
            matches!(dname_res, Err(DecodeError::InternedIndexOutOfBounds { index, .. }) if index == idx),
            "resolve_interned_dotted_name should reject index {}",
            idx
        );

        let ty_oob = Type {
            sum: Some(r#type::Sum::InternedType(idx)),
        };
        let ty_res = resolve_surface_type(&package, &ty_oob);
        assert!(
            matches!(ty_res, Err(DecodeError::InternedIndexOutOfBounds { index, .. }) if index == idx),
            "resolve_surface_type should reject interned type index {}",
            idx
        );
    }
}

// ===========================================================================
// Challenge 7: SurfaceType Display & Serde Roundtrip
// ===========================================================================

#[test]
fn challenge_surface_type_display_and_serde_roundtrip() {
    let test_types = vec![
        (SurfaceType::Party, "Party"),
        (SurfaceType::Text, "Text"),
        (SurfaceType::Numeric(Some(10)), "Decimal"),
        (SurfaceType::Numeric(None), "Decimal"),
        (SurfaceType::Numeric(Some(5)), "Numeric 5"),
        (SurfaceType::Numeric(Some(38)), "Numeric 38"),
        (SurfaceType::Int64, "Int64"),
        (SurfaceType::Bool, "Bool"),
        (SurfaceType::Date, "Date"),
        (SurfaceType::Timestamp, "Timestamp"),
        (SurfaceType::Unit, "()"),
        (
            SurfaceType::ContractId(Box::new(SurfaceType::TypeCon {
                package_id: None,
                module_name: None,
                name: "AssetHolding".to_string(),
                args: Vec::new(),
            })),
            "ContractId AssetHolding",
        ),
        (
            SurfaceType::List(Box::new(SurfaceType::Int64)),
            "List Int64",
        ),
        (
            SurfaceType::Optional(Box::new(SurfaceType::Text)),
            "Optional Text",
        ),
        (
            SurfaceType::GenMap {
                key: Box::new(SurfaceType::Party),
                value: Box::new(SurfaceType::Numeric(Some(10))),
            },
            "Map Party Decimal",
        ),
        (SurfaceType::Tuple(Vec::new()), "()"),
        (SurfaceType::Tuple(vec![SurfaceType::Party]), "(Party)"),
        (
            SurfaceType::Tuple(vec![
                SurfaceType::ContractId(Box::new(SurfaceType::TypeCon {
                    package_id: None,
                    module_name: None,
                    name: "AssetHolding".to_string(),
                    args: Vec::new(),
                })),
                SurfaceType::ContractId(Box::new(SurfaceType::TypeCon {
                    package_id: None,
                    module_name: None,
                    name: "AssetHolding".to_string(),
                    args: Vec::new(),
                })),
            ]),
            "(ContractId AssetHolding, ContractId AssetHolding)",
        ),
        (SurfaceType::TypeVar("a".to_string()), "a"),
        (
            SurfaceType::Arrow(Box::new(SurfaceType::Party), Box::new(SurfaceType::Bool)),
            "Party -> Bool",
        ),
        (
            SurfaceType::Other("CustomUninterpreted".to_string()),
            "CustomUninterpreted",
        ),
    ];

    for (ty, expected_display) in &test_types {
        // 1. Verify display formatting
        assert_eq!(ty.display_daml(), *expected_display);

        // 2. Verify Serde JSON roundtrip
        let json = serde_json::to_string(ty).expect("serialization failed");
        let deserialized: SurfaceType =
            serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(ty, &deserialized);
    }
}

#[test]
fn challenge_full_surface_structs_serde_roundtrip() {
    let module = ModuleSurface {
        name: "TestModule".to_string(),
        templates: vec![TemplateSurface {
            name: "TestTemplate".to_string(),
            param_name: "this".to_string(),
            fields: vec![
                FieldDef::new("owner", SurfaceType::Party),
                FieldDef::new("amount", SurfaceType::Numeric(Some(10))),
            ],
            signatories: vec!["owner".to_string()],
            observers: vec!["auditor".to_string()],
            choices: vec![ChoiceDef {
                name: "Transfer".to_string(),
                consuming: true,
                controllers: vec!["owner".to_string()],
                observers: Vec::new(),
                params: vec![ChoiceParam::new("newOwner", SurfaceType::Party)],
                return_type: SurfaceType::Unit,
                return_type_str: "()".to_string(),
                do_body: BytePresence::present(128),
            }],
            ensure: BytePresence::present(64),
        }],
    };

    let json = serde_json::to_string_pretty(&module).expect("ModuleSurface serialization failed");
    let deserialized: ModuleSurface =
        serde_json::from_str(&json).expect("ModuleSurface deserialization failed");
    assert_eq!(module, deserialized);
}

// ===========================================================================
// Challenge 8: BytePresence Zero-Evaluation Verification
// ===========================================================================

#[test]
fn challenge_byte_presence_preserves_encoded_bytes_without_evaluating() {
    let dummy_expr = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };
    let encoded_len = dummy_expr.encoded_len();
    assert!(encoded_len > 0);

    let dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                r#type: Some(Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                }),
            }],
        })),
        ..Default::default()
    };

    let template = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: Some(dummy_expr.clone()),
        signatories: Some(dummy_expr.clone()),
        choices: vec![TemplateChoice {
            name_interned_str: 1,
            consuming: false,
            controllers: Some(dummy_expr.clone()),
            observers: None,
            arg_binder: None,
            ret_type: None,
            update: Some(dummy_expr),
            self_binder_interned_str: 0,
            ..Default::default()
        }],
        observers: None,
        ..Default::default()
    };

    let module = Module {
        name_interned_dname: 0,
        data_types: vec![dt],
        values: Vec::new(),
        templates: vec![template],
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings: vec!["owner".to_string(), "Ping".to_string()],
        interned_dotted_names: vec![make_interned_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let surfaces = extract_module_surfaces(&package).expect("extraction failed");
    let tmpl = &surfaces[0].templates[0];

    assert!(tmpl.ensure.present);
    assert_eq!(tmpl.ensure.bytes_len, encoded_len);

    let choice = &tmpl.choices[0];
    assert!(choice.do_body.present);
    assert_eq!(choice.do_body.bytes_len, encoded_len);
}

// ===========================================================================
// Challenge 9: Synthetic Full DAR Construction & Tamper Defense Stress
// ===========================================================================

#[test]
fn challenge_synthetic_dar_parsing_and_tamper_defense() {
    // 1. Build a synthetic package with multiple templates
    let num_templates = 5;
    let mut data_types = Vec::new();
    let mut templates = Vec::new();
    let mut interned_strings = vec!["owner".to_string(), "Archive".to_string()];
    let mut interned_dotted_names = Vec::new();

    for i in 0..num_templates {
        let name_str = format!("Template{}", i);
        interned_strings.push(name_str.clone());
        let str_idx = (interned_strings.len() - 1) as i32;
        interned_dotted_names.push(make_interned_dname(vec![str_idx]));
        let dname_idx = (interned_dotted_names.len() - 1) as i32;

        data_types.push(DefDataType {
            name_interned_dname: dname_idx,
            serializable: true,
            data_cons: Some(DataCons::Record(Fields {
                fields: vec![FieldWithType {
                    field_interned_str: 0, // "owner"
                    // [CANTON-NOTE: ORACLE] a field type is a reference into the interning table (S-LF-009)
                    r#type: Some(Type {
                        sum: Some(r#type::Sum::InternedType(0)),
                    }),
                }],
            })),
            ..Default::default()
        });

        templates.push(DefTemplate {
            tycon_interned_dname: dname_idx,
            param_interned_str: 0,
            precond: None,
            signatories: Some(Expr {
                sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
                    tycon: None,
                    field_interned_str: 0,
                    record: None,
                }))),
                ..Default::default()
            }),
            choices: vec![TemplateChoice {
                name_interned_str: 1, // "Archive"
                consuming: true,
                controllers: None,
                observers: None,
                arg_binder: None,
                ret_type: None,
                update: None,
                self_binder_interned_str: 0,
                ..Default::default()
            }],
            observers: None,
            ..Default::default()
        });
    }

    let module = Module {
        name_interned_dname: 0,
        data_types,
        values: Vec::new(),
        templates,
        ..Default::default()
    };

    let package = Package {
        modules: vec![module],
        interned_strings,
        interned_dotted_names,
        metadata: None,
        interned_types: vec![Type {
            sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                builtin: BuiltinType::Party as i32,
                args: Vec::new(),
            })),
        }],
        ..Default::default()
    };

    // 2. Wrap into DALF bytes
    let main_dalf_bytes = wrap_package_into_dalf(&package, "1");

    // 3. Construct DAR in memory
    let manifest = "Manifest-Version: 1.0\r\nMain-Dalf: main.dalf\r\nFormat: daml-lf\r\n";
    let dar_bytes = build_synthetic_dar(manifest, &[("main.dalf", &main_dalf_bytes)]);

    // 4. Parse DAR and verify all templates were decoded
    let archive = parse_dar_bytes(&dar_bytes).expect("synthetic DAR must parse");
    assert_eq!(archive.module_surfaces.len(), 1);
    assert_eq!(archive.module_surfaces[0].templates.len(), num_templates);
    for (i, tmpl) in archive.module_surfaces[0].templates.iter().enumerate() {
        assert_eq!(tmpl.name, format!("Template{}", i));
        assert_eq!(tmpl.signatories, vec!["owner"]);
        assert_eq!(tmpl.choices.len(), 1);
        assert_eq!(tmpl.choices[0].name, "Archive");
    }

    // 5. Tamper with DALF payload and verify PackageIdMismatch
    let mut tampered_dalf = main_dalf_bytes.clone();
    let last = tampered_dalf.len() - 5;
    tampered_dalf[last] ^= 0xFF; // flip bits
    let tampered_dar = build_synthetic_dar(manifest, &[("main.dalf", &tampered_dalf)]);
    let err = parse_dar_bytes(&tampered_dar).expect_err("tampered DAR must fail");
    assert!(
        matches!(err, DarError::Decode(DecodeError::PackageIdMismatch { .. }))
            || matches!(err, DarError::Decode(DecodeError::Protobuf(_))),
        "expected tamper rejection, got: {:?}",
        err
    );

    // 6. Truncated DALF entry
    let truncated_dalf = &main_dalf_bytes[..main_dalf_bytes.len() / 2];
    let truncated_dar = build_synthetic_dar(manifest, &[("main.dalf", truncated_dalf)]);
    let err_trunc = parse_dar_bytes(&truncated_dar).expect_err("truncated DAR must fail");
    assert!(
        matches!(err_trunc, DarError::Decode(_)),
        "expected decode failure on truncated DALF, got: {:?}",
        err_trunc
    );
}
