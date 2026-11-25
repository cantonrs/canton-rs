//! Empirical surface stress tests and boundary challenges for Daml-LF2 decoding.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::decode::{extract_module_surfaces, resolve_surface_type};
use lf_archive::proto::daml_lf::{
    archive_payload::Sum as PayloadSum, Archive, ArchivePayload, HashFunction,
};
use lf_archive::proto::daml_lf_2::def_data_type::Fields;
use lf_archive::proto::daml_lf_2::def_value::NameWithType as DefValueNameWithType;
use lf_archive::proto::daml_lf_2::{
    def_data_type::DataCons, expr, r#type, BuiltinType, DefDataType, DefTemplate, DefValue, Expr,
    FieldWithType, InternedDottedName, Module, Package, TemplateChoice, Type, TypeConId,
};
use lf_archive::{compute_sha256, parse_dar_bytes, DecodeError, SurfaceType};
use prost::Message;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn make_dname(segments: Vec<i32>) -> InternedDottedName {
    InternedDottedName {
        segments_interned_str: segments,
    }
}

fn wrap_package_dalf(package: &Package, minor: &str) -> Vec<u8> {
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

fn create_test_dar(manifest_text: &str, dalfs: &[(&str, &[u8])]) -> Vec<u8> {
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
// Test 1: Recursion Limits in SurfaceType, Nat, unwrap_type_con, and AST
// ===========================================================================

#[test]
fn test_recursion_limit_surface_type_exact_boundary() {
    // Chain length 32: 0 -> 1 -> ... -> 32 (resolves to Party)
    let depth_ok = 32;
    let mut types_ok = Vec::new();
    for i in 0..depth_ok {
        types_ok.push(Type {
            sum: Some(r#type::Sum::InternedType(i + 1)),
        });
    }
    types_ok.push(Type {
        sum: Some(r#type::Sum::Builtin(r#type::Builtin {
            builtin: BuiltinType::Party as i32,
            args: Vec::new(),
        })),
    });

    let pkg_ok = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: types_ok,
        ..Default::default()
    };

    let res_ok = resolve_surface_type(&pkg_ok, &pkg_ok.interned_types[0]);
    assert_eq!(res_ok.unwrap(), SurfaceType::Party);

    // Chain length 33: 0 -> 1 -> ... -> 33 (fails with RecursionLimitExceeded)
    let depth_fail = 33;
    let mut types_fail = Vec::new();
    for i in 0..depth_fail {
        types_fail.push(Type {
            sum: Some(r#type::Sum::InternedType(i + 1)),
        });
    }
    types_fail.push(Type {
        sum: Some(r#type::Sum::Builtin(r#type::Builtin {
            builtin: BuiltinType::Party as i32,
            args: Vec::new(),
        })),
    });

    let pkg_fail = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: types_fail,
        ..Default::default()
    };

    let res_fail = resolve_surface_type(&pkg_fail, &pkg_fail.interned_types[0]);
    assert!(
        matches!(
            &res_fail,
            Err(DecodeError::RecursionLimitExceeded { context }) if *context == "resolve_surface_type"
        ),
        "expected RecursionLimitExceeded, got: {:?}",
        res_fail
    );
}

#[test]
fn test_recursion_limit_nat_resolution() {
    // Nat resolved via chain of 33 interned types
    let depth_fail = 33;
    let mut types = Vec::new();
    for i in 0..depth_fail {
        types.push(Type {
            sum: Some(r#type::Sum::InternedType(i + 1)),
        });
    }
    types.push(Type {
        sum: Some(r#type::Sum::Nat(10)),
    });

    // Builtin Numeric with arg pointing to the chain
    let num_ty = Type {
        sum: Some(r#type::Sum::Builtin(r#type::Builtin {
            builtin: BuiltinType::Numeric as i32,
            args: vec![Type {
                sum: Some(r#type::Sum::InternedType(0)),
            }],
        })),
    };

    let pkg = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: types,
        ..Default::default()
    };

    let res = resolve_surface_type(&pkg, &num_ty);
    assert!(
        matches!(
            &res,
            Err(DecodeError::RecursionLimitExceeded { context }) if *context == "resolve_nat_from_type"
        ),
        "expected RecursionLimitExceeded in resolve_nat_from_type, got: {:?}",
        res
    );
}

// ===========================================================================
// Test 2: Cycle Prevention in visited_values (Diamond & 3-Cycle)
// ===========================================================================

#[test]
fn test_cycle_prevention_three_value_ring() {
    // Ring: Val0 -> Val1 -> Val2 -> Val0
    let v0 = Expr {
        sum: Some(expr::Sum::Val(lf_archive::proto::daml_lf_2::ValueId {
            module: None,
            name_interned_dname: 1,
        })),
        ..Default::default()
    };
    let v1 = Expr {
        sum: Some(expr::Sum::Val(lf_archive::proto::daml_lf_2::ValueId {
            module: None,
            name_interned_dname: 2,
        })),
        ..Default::default()
    };
    let v2 = Expr {
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
            expr: Some(v0),
            ..Default::default()
        },
        DefValue {
            name_with_type: Some(DefValueNameWithType {
                name_interned_dname: 1,
                r#type: None,
            }),
            expr: Some(v1),
            ..Default::default()
        },
        DefValue {
            name_with_type: Some(DefValueNameWithType {
                name_interned_dname: 2,
                r#type: None,
            }),
            expr: Some(v2),
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
        interned_strings: vec!["party".to_string()],
        interned_dotted_names: vec![
            make_dname(vec![0]),
            make_dname(vec![0]),
            make_dname(vec![0]),
        ],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // Cycle must be broken safely by visited_values, leading to MissingSignatory fail-closed
    let res = extract_module_surfaces(&package);
    assert!(
        matches!(res, Err(DecodeError::MissingSignatory(_))),
        "expected MissingSignatory due to 3-value cycle termination, got: {:?}",
        res
    );
}

// ===========================================================================
// Test 3: Corrupted or Invalid Type Tags
// ===========================================================================

#[test]
fn test_corrupted_type_sum_none() {
    let empty_ty = Type { sum: None };
    let pkg = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = resolve_surface_type(&pkg, &empty_ty);
    assert!(
        matches!(&res, Err(DecodeError::InvalidType(ref msg)) if msg.contains("empty Type sum")),
        "expected InvalidType for sum: None, got: {:?}",
        res
    );
}

#[test]
fn test_unknown_builtin_type_code() {
    let unknown_ty = Type {
        sum: Some(r#type::Sum::Builtin(r#type::Builtin {
            builtin: 999, // Unknown code
            args: Vec::new(),
        })),
    };
    let pkg = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = resolve_surface_type(&pkg, &unknown_ty);
    assert_eq!(
        res.unwrap(),
        SurfaceType::Other("BuiltinType(999)".to_string())
    );
}

#[test]
fn test_type_con_without_tycon() {
    let con_without_id = Type {
        sum: Some(r#type::Sum::Con(r#type::Con {
            tycon: None,
            args: Vec::new(),
        })),
    };
    let pkg = Package {
        modules: Vec::new(),
        interned_strings: Vec::new(),
        interned_dotted_names: Vec::new(),
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    let res = resolve_surface_type(&pkg, &con_without_id);
    assert_eq!(
        res.unwrap(),
        SurfaceType::TypeCon {
            package_id: None,
            module_name: None,
            name: "UnknownCon".to_string(),
            args: Vec::new(),
        }
    );
}

// ===========================================================================
// Test 4: Precondition (ensure) and Choice (do) Bytecode Non-Evaluation
// ===========================================================================

#[test]
fn test_unexecuted_ensure_and_do_preservation_with_malformed_expr() {
    // Malformed Expr that contains invalid nested fields
    let malformed_expr = Expr {
        sum: Some(expr::Sum::App(Box::new(expr::App {
            fun: None, // Missing fun
            args: vec![Expr {
                sum: None,
                ..Default::default()
            }], // Empty sum
        }))),
        ..Default::default()
    };
    let raw_len = malformed_expr.encoded_len();
    assert!(raw_len > 0);

    let sig_expr = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };

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
        precond: Some(malformed_expr.clone()),
        signatories: Some(sig_expr.clone()),
        choices: vec![TemplateChoice {
            name_interned_str: 1,
            consuming: true,
            controllers: Some(sig_expr),
            observers: None,
            arg_binder: None,
            ret_type: None,
            update: Some(malformed_expr),
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
        interned_strings: vec!["owner".to_string(), "Execute".to_string()],
        interned_dotted_names: vec![make_dname(vec![0])],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // The malformed bytecode MUST NOT be evaluated or crash decoding.
    // It must simply record present: true and raw bytes_len.
    let surfaces = extract_module_surfaces(&package).expect("surface extraction must succeed");
    let tmpl = &surfaces[0].templates[0];
    assert!(tmpl.ensure.present);
    assert_eq!(tmpl.ensure.bytes_len, raw_len);

    let choice = &tmpl.choices[0];
    assert!(choice.do_body.present);
    assert_eq!(choice.do_body.bytes_len, raw_len);
}

// ===========================================================================
// Test 5: Strict Dependency Isolation (No Template Leaks)
// ===========================================================================

#[test]
fn test_strict_dependency_dalf_isolation_synthetic() {
    // 1. Construct Main Package with MainTemplate
    let main_dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                // [CANTON-NOTE: ORACLE] a field type is a reference into the interning table (S-LF-009)
                r#type: Some(Type {
                    sum: Some(r#type::Sum::InternedType(0)),
                }),
            }],
        })),
        ..Default::default()
    };

    let main_sig = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };

    let main_tmpl = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(main_sig),
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let main_mod = Module {
        name_interned_dname: 0,
        data_types: vec![main_dt],
        values: Vec::new(),
        templates: vec![main_tmpl],
        ..Default::default()
    };

    let main_pkg = Package {
        modules: vec![main_mod],
        interned_strings: vec!["MainOwner".to_string(), "MainTmpl".to_string()],
        interned_dotted_names: vec![make_dname(vec![1])],
        metadata: None,
        interned_types: vec![Type {
            sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                builtin: BuiltinType::Party as i32,
                args: Vec::new(),
            })),
        }],
        ..Default::default()
    };

    let main_dalf = wrap_package_dalf(&main_pkg, "1");

    // 2. Construct Dependency Package with DepTemplate
    let dep_dt = DefDataType {
        name_interned_dname: 0,
        serializable: true,
        data_cons: Some(DataCons::Record(Fields {
            fields: vec![FieldWithType {
                field_interned_str: 0,
                // [CANTON-NOTE: ORACLE] a field type is a reference into the interning table (S-LF-009)
                r#type: Some(Type {
                    sum: Some(r#type::Sum::InternedType(0)),
                }),
            }],
        })),
        ..Default::default()
    };

    let dep_sig = Expr {
        sum: Some(expr::Sum::RecProj(Box::new(expr::RecProj {
            tycon: None,
            field_interned_str: 0,
            record: None,
        }))),
        ..Default::default()
    };

    let dep_tmpl = DefTemplate {
        tycon_interned_dname: 0,
        param_interned_str: 0,
        precond: None,
        signatories: Some(dep_sig),
        choices: Vec::new(),
        observers: None,
        ..Default::default()
    };

    let dep_mod = Module {
        name_interned_dname: 0,
        data_types: vec![dep_dt],
        values: Vec::new(),
        templates: vec![dep_tmpl],
        ..Default::default()
    };

    let dep_pkg = Package {
        modules: vec![dep_mod],
        interned_strings: vec!["DepOwner".to_string(), "DepTmpl".to_string()],
        interned_dotted_names: vec![make_dname(vec![1])],
        metadata: None,
        interned_types: vec![Type {
            sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                builtin: BuiltinType::Party as i32,
                args: Vec::new(),
            })),
        }],
        ..Default::default()
    };

    let dep_dalf = wrap_package_dalf(&dep_pkg, "1");

    // 3. Assemble DAR archive with main.dalf and dep.dalf
    let manifest =
        "Manifest-Version: 1.0\r\nMain-Dalf: main.dalf\r\nDalfs: dep.dalf\r\nFormat: daml-lf\r\n";
    let dar_bytes = create_test_dar(
        manifest,
        &[("main.dalf", &main_dalf), ("dep.dalf", &dep_dalf)],
    );

    // 4. Parse DAR
    let archive = parse_dar_bytes(&dar_bytes).expect("synthetic multi-dalf DAR must parse");

    // Check inventory
    assert_eq!(archive.dalfs.len(), 2);
    assert_eq!(archive.dalfs[0].name, "main.dalf");
    assert!(archive.dalfs[0].is_main);
    assert_eq!(archive.dalfs[1].name, "dep.dalf");
    assert!(!archive.dalfs[1].is_main);

    // CRUCIAL: archive.module_surfaces must contain ONLY templates from main.dalf!
    assert_eq!(archive.module_surfaces.len(), 1);
    assert_eq!(archive.module_surfaces[0].templates.len(), 1);
    assert_eq!(archive.module_surfaces[0].templates[0].name, "MainTmpl");

    // Verify DepTmpl was NOT leaked into archive.module_surfaces
    let all_surface_names: Vec<String> = archive
        .module_surfaces
        .iter()
        .flat_map(|m| m.templates.iter().map(|t| t.name.clone()))
        .collect();
    assert!(
        !all_surface_names.contains(&"DepTmpl".to_string()),
        "DepTmpl must NOT leak into DarArchive.module_surfaces"
    );
}

// ===========================================================================
// Test 6: Nominal Type Con vs Tuple Classification Stress Probe
// ===========================================================================

#[test]
fn test_nominal_type_con_vs_tuple_classification() {
    let pkg = Package {
        modules: Vec::new(),
        interned_strings: vec![
            "Tuple2".to_string(),
            "TupleStore".to_string(),
            "NonTuple".to_string(),
        ],
        interned_dotted_names: vec![
            make_dname(vec![0]),
            make_dname(vec![1]),
            make_dname(vec![2]),
        ],
        metadata: None,
        interned_types: Vec::new(),
        ..Default::default()
    };

    // Case A: Tuple2 with 2 arguments -> correctly classified as SurfaceType::Tuple
    let ty_tuple2 = Type {
        sum: Some(r#type::Sum::Con(r#type::Con {
            tycon: Some(TypeConId {
                module: None,
                name_interned_dname: 0,
            }),
            args: vec![
                Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Party as i32,
                        args: Vec::new(),
                    })),
                },
                Type {
                    sum: Some(r#type::Sum::Builtin(r#type::Builtin {
                        builtin: BuiltinType::Text as i32,
                        args: Vec::new(),
                    })),
                },
            ],
        })),
    };
    let res_tuple2 = resolve_surface_type(&pkg, &ty_tuple2).unwrap();
    assert_eq!(
        res_tuple2,
        SurfaceType::Tuple(vec![SurfaceType::Party, SurfaceType::Text])
    );
    assert_eq!(res_tuple2.display_daml(), "(Party, Text)");

    // Case B: NonTuple -> correctly classified as SurfaceType::TypeCon
    let ty_nontuple = Type {
        sum: Some(r#type::Sum::Con(r#type::Con {
            tycon: Some(TypeConId {
                module: None,
                name_interned_dname: 2,
            }),
            args: Vec::new(),
        })),
    };
    let res_nontuple = resolve_surface_type(&pkg, &ty_nontuple).unwrap();
    assert_eq!(
        res_nontuple,
        SurfaceType::TypeCon {
            package_id: None,
            module_name: None,
            name: "NonTuple".to_string(),
            args: Vec::new(),
        }
    );
    assert_eq!(res_nontuple.display_daml(), "NonTuple");

    // Case C: Probe behavior on "TupleStore"
    // Because decode.rs checks `name.starts_with("Tuple")`, TupleStore is classified as Tuple
    let ty_tuplestore = Type {
        sum: Some(r#type::Sum::Con(r#type::Con {
            tycon: Some(TypeConId {
                module: None,
                name_interned_dname: 1,
            }),
            args: Vec::new(),
        })),
    };
    let res_tuplestore = resolve_surface_type(&pkg, &ty_tuplestore).unwrap();
    // Empirical finding: TupleStore gets classified as Tuple([]) due to `name.starts_with("Tuple")`
    assert_eq!(res_tuplestore, SurfaceType::Tuple(Vec::new()));
}
