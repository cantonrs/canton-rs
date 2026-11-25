//! Generates the mutated main DALFs of the AT-A08 cases (tests/oracle/dar-input/dalfs/a08-*.dalf): the pinned sample
//! package with one interned reference (string, dotted name, type) pointing somewhere it must not, re-wrapped with a
//! correct SHA-256 so the only defect is the reference (the hash check cannot be what rejects it).
//!
//!   cargo run -q -p lf-archive --example gen_interned_dalfs -- <sample.dar> <out-dir>
//!
//! scripts/gen-dar-input.py puts each file into a copy of the sample DAR as its main DALF.
//! [CANTON-NOTE: ORACLE] Each case is then uploaded to the JVM (`POST /v2/dars`) and loaded by the Rust loader;
//! see crates/core/lf-archive/tests/dar_input_oracle.rs.
#![allow(clippy::unwrap_used, reason = "offline DAR fixture generator example")]

use std::io::Read;

use canton_proto::daml_lf::{
    archive_payload::Sum as PayloadSum, Archive, ArchivePayload, HashFunction,
};
use canton_proto::daml_lf_2::{
    def_data_type::DataCons, r#type::Builtin, r#type::Con, r#type::Sum as TypeSum, BuiltinType,
    InternedDottedName, ModuleId, Package, SelfOrImportedPackageId, Type, TypeConId,
};
use lf_archive::compute_sha256;
use prost::Message;

/// The index of the value `name` (dotted) in the first module.
fn value_index(p: &Package, name: &str) -> usize {
    p.modules[0]
        .values
        .iter()
        .position(|v| {
            let n = v.name_with_type.as_ref().unwrap().name_interned_dname as usize;
            p.interned_dotted_names[n]
                .segments_interned_str
                .iter()
                .map(|s| p.interned_strings[*s as usize].clone())
                .collect::<Vec<_>>()
                .join(".")
                == name
        })
        .unwrap_or_else(|| panic!("no value {name}"))
}

/// The first field of the record construction a wrapper lambda (`\x -> R {f = x}`) is made of.
fn wrapper_first_field(
    v: &mut canton_proto::daml_lf_2::DefValue,
) -> &mut canton_proto::daml_lf_2::FieldWithExpr {
    use canton_proto::daml_lf_2::expr::Sum;
    let Some(Sum::Abs(abs)) = &mut v.expr.as_mut().unwrap().sum else {
        panic!("the wrapper is not a lambda");
    };
    let Some(Sum::RecCon(rc)) = &mut abs.body.as_mut().unwrap().sum else {
        panic!("the wrapper body is not a record construction");
    };
    &mut rc.fields[0]
}

/// The first `let` block inside an expression (looking through lambdas, applications and type abstractions).
fn find_let(e: &mut canton_proto::daml_lf_2::Expr) -> Option<&mut canton_proto::daml_lf_2::Block> {
    use canton_proto::daml_lf_2::expr::Sum;
    match e.sum.as_mut()? {
        Sum::Let(b) => Some(b),
        Sum::Abs(a) => find_let(a.body.as_mut()?),
        Sum::TyAbs(a) => find_let(a.body.as_mut()?),
        Sum::TyApp(a) => find_let(a.expr.as_mut()?),
        Sum::App(a) => {
            if let Some(f) = a.fun.as_mut() {
                if let Some(b) = find_let(f) {
                    return Some(b);
                }
            }
            a.args.iter_mut().find_map(find_let)
        }
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dar, out) = (&args[1], &args[2]);
    std::fs::create_dir_all(out).unwrap();

    let mut zip = zip::ZipArchive::new(std::fs::File::open(dar).unwrap()).unwrap();
    let manifest = {
        let mut s = String::new();
        zip.by_name("META-INF/MANIFEST.MF")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    };
    let main_name = manifest
        .replace("\r\n", "\n")
        .replace("\n ", "")
        .lines()
        .find_map(|l| l.strip_prefix("Main-Dalf:").map(|v| v.trim().to_string()))
        .expect("Main-Dalf");
    let mut bytes = Vec::new();
    zip.by_name(&main_name)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();

    let archive = Archive::decode(bytes.as_slice()).unwrap();
    let payload = ArchivePayload::decode(archive.payload.as_slice()).unwrap();
    let minor = payload.minor.clone();
    let pkg = match payload.sum {
        Some(PayloadSum::DamlLf2(b)) => Package::decode(b.as_slice()).unwrap(),
        _ => panic!("sample main DALF is not LF2"),
    };
    let ns = pkg.interned_strings.len() as i32;
    let nd = pkg.interned_dotted_names.len() as i32;
    let nt = pkg.interned_types.len() as i32;
    eprintln!(
        "strings {ns} dotted {nd} types {nt} modules {}",
        pkg.modules.len()
    );

    let mut cases: Vec<(&str, Package)> = Vec::new();
    let mut m = |name: &'static str, f: &dyn Fn(&mut Package)| {
        let mut p = pkg.clone();
        f(&mut p);
        cases.push((name, p));
    };
    // The package name string index points past the string table / is negative.
    m("string-out-of-range", &|p| {
        p.metadata.as_mut().unwrap().name_interned_str = ns + 7
    });
    m("string-negative", &|p| {
        p.metadata.as_mut().unwrap().name_interned_str = -1
    });
    // A module name points past the dotted-name table / is negative.
    m("dname-out-of-range", &|p| {
        p.modules[0].name_interned_dname = nd + 3
    });
    m("dname-negative", &|p| p.modules[0].name_interned_dname = -5);
    // A data type name points past the dotted-name table.
    m("datatype-name-out-of-range", &|p| {
        p.modules[0].data_types[0].name_interned_dname = nd + 9
    });
    // A dotted name whose segment is not a string index (the module name is made to use it).
    m("dotted-segment-out-of-range", &|p| {
        p.interned_dotted_names.push(InternedDottedName {
            segments_interned_str: vec![ns + 1],
        });
        p.modules[0].name_interned_dname = nd;
    });
    // A record field whose type is an interned type index past the table (a type outside the table must be an
    // interned reference; an *entry* of the table that is itself a bare reference is a different, structural error).
    m("type-out-of-range", &|p| {
        for d in p.modules[0].data_types.iter_mut() {
            if let Some(DataCons::Record(r)) = &mut d.data_cons {
                if let Some(f) = r.fields.first_mut() {
                    f.r#type = Some(Type {
                        sum: Some(TypeSum::InternedType(nt + 4)),
                    });
                    return;
                }
            }
        }
        panic!("no record data type");
    });
    // A table entry that mentions itself as an argument (types may only refer to smaller indices).
    m("type-self-reference", &|p| {
        let me = p.interned_types.len() as i32;
        p.interned_types.push(Type {
            sum: Some(TypeSum::Builtin(Builtin {
                builtin: BuiltinType::List as i32,
                args: vec![Type {
                    sum: Some(TypeSum::InternedType(me)),
                }],
            })),
        });
    });
    // A table entry that is only a reference to another entry ("immediate interned type"): a structural error.
    m("type-table-entry-is-a-reference", &|p| {
        p.interned_types.push(Type {
            sum: Some(TypeSum::InternedType(0)),
        });
    });
    // Unreferenced garbage in the tables: tests whether the reference validates tables nobody uses.
    m("unused-dotted-segment-out-of-range", &|p| {
        p.interned_dotted_names.push(InternedDottedName {
            segments_interned_str: vec![ns + 100],
        });
    });
    // 5,000 duplicate strings at the end of the table: benign duplication, nothing refers to them.
    // The package version is changed too: with the sample's own name and version the JVM would answer
    // KNOWN_PACKAGE_VERSION, which says nothing about the table.
    m("string-table-duplicates", &|p| {
        let v = p.metadata.as_ref().unwrap().version_interned_str as usize;
        p.interned_strings[v] = "9.9.9".to_string();
        for _ in 0..5000 {
            p.interned_strings.push(p.interned_strings[0].clone());
        }
    });

    // ---- AT-L01: validation defects that interning checks do not catch (file prefix a09-) ----
    // helper pieces
    let self_pkg = || SelfOrImportedPackageId {
        sum: Some(
            canton_proto::daml_lf_2::self_or_imported_package_id::Sum::SelfPackageId(
                canton_proto::daml_lf_2::Unit {},
            ),
        ),
    };
    // a type outside the table is always a reference into the table
    fn add(p: &mut Package, t: Type) -> Type {
        p.interned_types.push(t);
        Type {
            sum: Some(TypeSum::InternedType(p.interned_types.len() as i32 - 1)),
        }
    }
    let con = move |module_dname: i32, name_dname: i32| Type {
        sum: Some(TypeSum::Con(Con {
            tycon: Some(TypeConId {
                module: Some(ModuleId {
                    package_id: Some(self_pkg()),
                    module_name_interned_dname: module_dname,
                }),
                name_interned_dname: name_dname,
            }),
            args: vec![],
        })),
    };
    let builtin = |b: BuiltinType, args: Vec<Type>| Type {
        sum: Some(TypeSum::Builtin(Builtin {
            builtin: b as i32,
            args,
        })),
    };
    // 1. the module name appears twice
    let dup_module = |p: &mut Package| {
        let m = p.modules[0].clone();
        p.modules.push(m);
    };
    // 2. a record field whose type names a type constructor that does not exist in the (existing) module
    let unresolved_tycon = move |p: &mut Package| {
        let seg = p.interned_strings.len() as i32;
        p.interned_strings.push("NoSuchType".to_string());
        let dn = p.interned_dotted_names.len() as i32;
        p.interned_dotted_names.push(InternedDottedName {
            segments_interned_str: vec![seg],
        });
        let module = p.modules[0].name_interned_dname;
        let t0 = con(module, dn);
        let t = add(p, t0);
        for d in p.modules[0].data_types.iter_mut() {
            if let Some(DataCons::Record(r)) = &mut d.data_cons {
                if let Some(f) = r.fields.first_mut() {
                    f.r#type = Some(t);
                    return;
                }
            }
        }
        panic!("no record data type");
    };
    // 3. a record field of a template payload whose type is a function (not serializable)
    let function_field = move |p: &mut Package| {
        let i64t = add(p, builtin(BuiltinType::Int64, vec![]));
        let t0 = builtin(BuiltinType::Arrow, vec![i64t.clone(), i64t]);
        let t = add(p, t0);
        let tycons: Vec<i32> = p.modules[0]
            .templates
            .iter()
            .map(|t| t.tycon_interned_dname)
            .collect();
        for d in p.modules[0].data_types.iter_mut() {
            if tycons.contains(&d.name_interned_dname) {
                if let Some(DataCons::Record(r)) = &mut d.data_cons {
                    if let Some(f) = r.fields.first_mut() {
                        f.r#type = Some(t);
                        return;
                    }
                }
            }
        }
        panic!("no template record");
    };
    // 4. the declared type of a value is changed (its expression stays): a type mismatch
    let value_type_mismatch = |p: &mut Package| {
        let base = p.interned_types.len() as i32;
        let mut p_types: Vec<Type> = Vec::new();
        for v in p.modules[0].values.iter_mut() {
            if let Some(n) = &mut v.name_with_type {
                let t = builtin(BuiltinType::Text, vec![]);
                p_types.push(t);
                n.r#type = Some(Type {
                    sum: Some(TypeSum::InternedType(base + p_types.len() as i32 - 1)),
                });
                break;
            }
        }
        p.interned_types.extend(p_types);
    };
    // 5. the lambda parameter of a record wrapper (`$$WTransfer`) is typed Text while the field it fills is a Party: the
    //    record construction gives a field an expression of the wrong type (EFieldTypeMismatch on a node)
    let wrapper_param_type = |p: &mut Package| {
        let text = add(p, builtin(BuiltinType::Text, vec![]));
        let names: Vec<String> = p.modules[0]
            .values
            .iter()
            .map(|v| {
                let n = v.name_with_type.as_ref().unwrap().name_interned_dname as usize;
                p.interned_dotted_names[n]
                    .segments_interned_str
                    .iter()
                    .map(|s| p.interned_strings[*s as usize].clone())
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect();
        let at = names
            .iter()
            .position(|n| n == "$$WTransfer")
            .expect("$$WTransfer");
        if let Some(canton_proto::daml_lf_2::expr::Sum::Abs(abs)) =
            &mut p.modules[0].values[at].expr.as_mut().unwrap().sum
        {
            abs.param[0].r#type = Some(text);
        } else {
            panic!("$$WTransfer is not a lambda");
        }
    };
    // 6. a field selector applied to the wrong record: its lambda parameter is typed with another record type
    let selector_param_record = |p: &mut Package| {
        let module = p.modules[0].name_interned_dname;
        let names: Vec<String> = p.modules[0]
            .values
            .iter()
            .map(|v| {
                let n = v.name_with_type.as_ref().unwrap().name_interned_dname as usize;
                p.interned_dotted_names[n]
                    .segments_interned_str
                    .iter()
                    .map(|s| p.interned_strings[*s as usize].clone())
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect();
        let at = names
            .iter()
            .position(|n| n.starts_with("$$sel$u003aowner$u003a"))
            .expect("owner selector");
        // the record the selector projects from, and another data type of the module to type its parameter with instead
        let projected = match &p.modules[0].values[at].expr.as_ref().unwrap().sum {
            Some(canton_proto::daml_lf_2::expr::Sum::Abs(abs)) => {
                match abs.body.as_ref().unwrap().sum.as_ref() {
                    Some(canton_proto::daml_lf_2::expr::Sum::RecProj(rp)) => {
                        rp.tycon
                            .as_ref()
                            .unwrap()
                            .tycon
                            .as_ref()
                            .unwrap()
                            .name_interned_dname
                    }
                    _ => panic!("the selector body is not a projection"),
                }
            }
            _ => panic!("the selector is not a lambda"),
        };
        let other = p.modules[0]
            .data_types
            .iter()
            .map(|d| d.name_interned_dname)
            .find(|n| *n != projected)
            .expect("a second data type");
        let t0 = con(module, other);
        let t = add(p, t0);
        if let Some(canton_proto::daml_lf_2::expr::Sum::Abs(abs)) =
            &mut p.modules[0].values[at].expr.as_mut().unwrap().sum
        {
            abs.param[0].r#type = Some(t);
        } else {
            panic!("the selector is not a lambda");
        }
    };
    // 7. the first field of the record wrapper `$$WTransfer` is given an Int64 literal instead of the Party it is declared as
    let wrapper_field_literal = |p: &mut Package| {
        let at = value_index(p, "$$WTransfer");
        let field = wrapper_first_field(&mut p.modules[0].values[at]);
        field.expr = Some(canton_proto::daml_lf_2::Expr {
            location: None,
            sum: Some(canton_proto::daml_lf_2::expr::Sum::BuiltinLit(
                canton_proto::daml_lf_2::BuiltinLit {
                    sum: Some(canton_proto::daml_lf_2::builtin_lit::Sum::Int64(7)),
                },
            )),
        });
    };
    // 8. the same field is given a reference to a function value (a field selector) instead of a Party
    let wrapper_field_value_ref = |p: &mut Package| {
        let at = value_index(p, "$$WTransfer");
        let sel = value_index(p, "$$sel$u003aowner$u003aAssetHolding");
        let module = p.modules[0].name_interned_dname;
        let name = p.modules[0].values[sel]
            .name_with_type
            .as_ref()
            .unwrap()
            .name_interned_dname;
        let field = wrapper_first_field(&mut p.modules[0].values[at]);
        field.expr = Some(canton_proto::daml_lf_2::Expr {
            location: None,
            sum: Some(canton_proto::daml_lf_2::expr::Sum::Val(
                canton_proto::daml_lf_2::ValueId {
                    module: Some(ModuleId {
                        package_id: Some(self_pkg()),
                        module_name_interned_dname: module,
                    }),
                    name_interned_dname: name,
                },
            )),
        });
    };
    // 9. the first field of a dictionary struct (`$$fHasCreateAssetHolding`) is an Int64 literal instead of the function it is declared as
    let struct_field_literal = |p: &mut Package| {
        use canton_proto::daml_lf_2::expr::Sum;
        let at = value_index(p, "$$fHasCreateAssetHolding");
        let Some(Sum::StructCon(sc)) = &mut p.modules[0].values[at].expr.as_mut().unwrap().sum
        else {
            panic!("the dictionary is not a struct construction");
        };
        sc.fields[0].expr = Some(canton_proto::daml_lf_2::Expr {
            location: None,
            sum: Some(Sum::BuiltinLit(canton_proto::daml_lf_2::BuiltinLit {
                sum: Some(canton_proto::daml_lf_2::builtin_lit::Sum::Int64(7)),
            })),
        });
    };
    // 10. the declared type of that dictionary is Text while its expression is a struct
    let struct_declared_text = |p: &mut Package| {
        let at = value_index(p, "$$fHasCreateAssetHolding");
        let t = add(p, builtin(BuiltinType::Text, vec![]));
        p.modules[0].values[at]
            .name_with_type
            .as_mut()
            .unwrap()
            .r#type = Some(t);
    };
    // 11. the first `let` of the package binds a variable declared as Text although it is bound to something else
    let let_binder_text = |p: &mut Package| {
        let t = add(p, builtin(BuiltinType::Text, vec![]));
        for v in p.modules[0].values.iter_mut() {
            if let Some(b) = find_let(v.expr.as_mut().unwrap()) {
                b.bindings[0].binder.as_mut().unwrap().r#type = Some(t);
                return;
            }
        }
        panic!("no let in the package");
    };
    let mut m = |name: &'static str, f: &dyn Fn(&mut Package)| {
        let mut p = pkg.clone();
        f(&mut p);
        cases.push((name, p));
    };
    // a bare type constructor at a field instead of a reference into the table (the JVM refuses the form)
    m("validate-type-outside-table", &move |p| {
        let module = p.modules[0].name_interned_dname;
        let t = con(module, p.modules[0].data_types[0].name_interned_dname);
        for d in p.modules[0].data_types.iter_mut() {
            if let Some(DataCons::Record(r)) = &mut d.data_cons {
                if let Some(f) = r.fields.first_mut() {
                    f.r#type = Some(t);
                    return;
                }
            }
        }
    });
    m("validate-duplicate-module", &dup_module);
    m("validate-unresolved-tycon", &unresolved_tycon);
    m("validate-function-field", &function_field);
    m("validate-value-type-mismatch", &value_type_mismatch);
    m("validate-record-field-type", &wrapper_param_type);
    m("validate-record-field-literal", &wrapper_field_literal);
    m("validate-record-field-value-ref", &wrapper_field_value_ref);
    m("validate-selector-record", &selector_param_record);
    m("validate-struct-field-literal", &struct_field_literal);
    m("validate-struct-declared-text", &struct_declared_text);
    m("validate-let-binder-text", &let_binder_text);
    // defects combined, to see which one the reference reports (the order of validation)
    m("order-duplicate-module-and-mismatch", &|p| {
        value_type_mismatch(p);
        dup_module(p);
    });
    m("order-unresolved-tycon-and-mismatch", &|p| {
        value_type_mismatch(p);
        unresolved_tycon(p);
    });
    m("order-function-field-and-mismatch", &|p| {
        value_type_mismatch(p);
        function_field(p);
    });
    m("order-function-field-and-unresolved-tycon", &|p| {
        // the first record field gets the unresolved type, the template's gets the function type
        function_field(p);
        unresolved_tycon(p);
    });

    for (name, p) in &cases {
        let payload = ArchivePayload {
            minor: minor.clone(),
            patch: 0,
            sum: Some(PayloadSum::DamlLf2(p.encode_to_vec())),
        };
        let pb = payload.encode_to_vec();
        let hash = compute_sha256(&pb);
        let a = Archive {
            hash_function: HashFunction::Sha256 as i32,
            payload: pb,
            hash,
        };
        let prefix = if name.starts_with("validate-") || name.starts_with("order-") {
            "a09"
        } else {
            "a08"
        };
        std::fs::write(format!("{out}/{prefix}-{name}.dalf"), a.encode_to_vec()).unwrap();
    }
    eprintln!("wrote {} DALFs", cases.len());
}
