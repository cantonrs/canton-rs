#![allow(clippy::unwrap_used, reason = "offline DAR fixture generator example")]

use lf_archive::crypto::compute_sha256;
use lf_archive::proto::daml_lf::{archive_payload, Archive, ArchivePayload, HashFunction};
use lf_archive::proto::daml_lf_2 as pb;
use prost::Message;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

struct PkgBuilder {
    name: String,
    version: String,
    minor: String,
    strings: Vec<String>,
    str_idx: HashMap<String, i32>,
    dnames: Vec<pb::InternedDottedName>,
    dname_idx: HashMap<Vec<String>, i32>,
    types: Vec<pb::Type>,
    imports: Vec<String>,
    modules: Vec<pb::Module>,
}

impl PkgBuilder {
    fn new(name: &str, version: &str, minor: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            minor: minor.to_string(),
            strings: Vec::new(),
            str_idx: HashMap::new(),
            dnames: Vec::new(),
            dname_idx: HashMap::new(),
            types: Vec::new(),
            imports: Vec::new(),
            modules: Vec::new(),
        }
    }

    fn s(&mut self, value: &str) -> i32 {
        if let Some(&idx) = self.str_idx.get(value) {
            return idx;
        }
        let idx = self.strings.len() as i32;
        self.strings.push(value.to_string());
        self.str_idx.insert(value.to_string(), idx);
        idx
    }

    fn dname(&mut self, segments: &[&str]) -> i32 {
        let key: Vec<String> = segments.iter().map(|s| (*s).to_string()).collect();
        if let Some(&idx) = self.dname_idx.get(&key) {
            return idx;
        }
        let seg_ids: Vec<i32> = segments.iter().map(|s| self.s(s)).collect();
        let idx = self.dnames.len() as i32;
        self.dnames.push(pb::InternedDottedName {
            segments_interned_str: seg_ids,
        });
        self.dname_idx.insert(key, idx);
        idx
    }

    fn pkg_ref(&mut self, pkg_id: Option<&str>) -> pb::SelfOrImportedPackageId {
        let sum = match pkg_id {
            None => pb::self_or_imported_package_id::Sum::SelfPackageId(pb::Unit {}),
            Some(pid) if self.minor == "dev" => {
                let idx = if let Some(pos) = self.imports.iter().position(|p| p == pid) {
                    pos as i32
                } else {
                    let pos = self.imports.len() as i32;
                    self.imports.push(pid.to_string());
                    pos
                };
                pb::self_or_imported_package_id::Sum::PackageImportId(idx)
            }
            Some(pid) => {
                pb::self_or_imported_package_id::Sum::ImportedPackageIdInternedStr(self.s(pid))
            }
        };
        pb::SelfOrImportedPackageId { sum: Some(sum) }
    }

    fn tycon_id(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::TypeConId {
        pb::TypeConId {
            module: Some(pb::ModuleId {
                package_id: Some(self.pkg_ref(pkg_id)),
                module_name_interned_dname: self.dname(module),
            }),
            name_interned_dname: self.dname(name),
        }
    }

    fn intern_type(&mut self, sum: pb::r#type::Sum) -> pb::Type {
        // Top-level entries in `interned_types` must not be `InternedType`.
        assert!(!matches!(sum, pb::r#type::Sum::InternedType(_)));
        let candidate = pb::Type { sum: Some(sum) };
        if let Some(pos) = self.types.iter().position(|t| t == &candidate) {
            return pb::Type {
                sum: Some(pb::r#type::Sum::InternedType(pos as i32)),
            };
        }
        let idx = self.types.len() as i32;
        self.types.push(candidate);
        pb::Type {
            sum: Some(pb::r#type::Sum::InternedType(idx)),
        }
    }

    fn k_star() -> pb::Kind {
        pb::Kind {
            sum: Some(pb::kind::Sum::Star(pb::Unit {})),
        }
    }

    fn k_nat() -> pb::Kind {
        pb::Kind {
            sum: Some(pb::kind::Sum::Nat(pb::Unit {})),
        }
    }

    fn t_builtin(&mut self, bt: pb::BuiltinType) -> pb::Type {
        self.intern_type(pb::r#type::Sum::Builtin(pb::r#type::Builtin {
            builtin: bt as i32,
            args: Vec::new(),
        }))
    }

    fn t_nat(&mut self, n: i64) -> pb::Type {
        self.intern_type(pb::r#type::Sum::Nat(n))
    }

    fn t_var(&mut self, name: &str) -> pb::Type {
        let vid = self.s(name);
        self.intern_type(pb::r#type::Sum::Var(pb::r#type::Var {
            var_interned_str: vid,
            args: Vec::new(),
        }))
    }

    fn t_con(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::Type {
        let tc = self.tycon_id(pkg_id, module, name);
        self.intern_type(pb::r#type::Sum::Con(pb::r#type::Con {
            tycon: Some(tc),
            args: Vec::new(),
        }))
    }

    /// Type application respecting LF minor version:
    /// - `2.dev`: nested `TApp` (`featureFlatArchive`)
    /// - `2.1`: flat `.args` on `Con`/`Builtin`/`Var` when possible
    fn t_app(&mut self, lhs: pb::Type, rhs: pb::Type) -> pb::Type {
        self.intern_type(pb::r#type::Sum::Tapp(Box::new(pb::r#type::TApp {
            lhs: Some(Box::new(lhs)),
            rhs: Some(Box::new(rhs)),
        })))
    }

    fn t_con_app(
        &mut self,
        pkg_id: Option<&str>,
        module: &[&str],
        name: &[&str],
        args: Vec<pb::Type>,
    ) -> pb::Type {
        if self.minor == "1" || self.minor == "2.1" {
            let tc = self.tycon_id(pkg_id, module, name);
            return self.intern_type(pb::r#type::Sum::Con(pb::r#type::Con {
                tycon: Some(tc),
                args,
            }));
        }
        let mut cur = self.t_con(pkg_id, module, name);
        for arg in args {
            cur = self.t_app(cur, arg);
        }
        cur
    }

    fn t_builtin_app(&mut self, bt: pb::BuiltinType, args: Vec<pb::Type>) -> pb::Type {
        if self.minor == "1" || self.minor == "2.1" {
            return self.intern_type(pb::r#type::Sum::Builtin(pb::r#type::Builtin {
                builtin: bt as i32,
                args,
            }));
        }
        let mut cur = self.t_builtin(bt);
        for arg in args {
            cur = self.t_app(cur, arg);
        }
        cur
    }

    fn t_arrow(&mut self, from: pb::Type, to: pb::Type) -> pb::Type {
        self.t_builtin_app(pb::BuiltinType::Arrow, vec![from, to])
    }

    fn t_struct(&mut self, fields: &[(&str, pb::Type)]) -> pb::Type {
        let mut fs = Vec::with_capacity(fields.len());
        for (name, ty) in fields {
            fs.push(pb::FieldWithType {
                field_interned_str: self.s(name),
                r#type: Some(ty.clone()),
            });
        }
        self.intern_type(pb::r#type::Sum::Struct(pb::r#type::Struct { fields: fs }))
    }

    fn t_forall(&mut self, vars: &[(&str, pb::Kind)], body: pb::Type) -> pb::Type {
        if self.minor == "dev" {
            let mut cur = body;
            for (v, k) in vars.iter().rev() {
                let vid = self.s(v);
                cur = self.intern_type(pb::r#type::Sum::Forall(Box::new(pb::r#type::Forall {
                    vars: vec![pb::TypeVarWithKind {
                        var_interned_str: vid,
                        kind: Some(k.clone()),
                    }],
                    body: Some(Box::new(cur)),
                })));
            }
            cur
        } else {
            let mut vs = Vec::with_capacity(vars.len());
            for (v, k) in vars {
                vs.push(pb::TypeVarWithKind {
                    var_interned_str: self.s(v),
                    kind: Some(k.clone()),
                });
            }
            self.intern_type(pb::r#type::Sum::Forall(Box::new(pb::r#type::Forall {
                vars: vs,
                body: Some(Box::new(body)),
            })))
        }
    }

    fn val_id(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::Expr {
        e(pb::expr::Sum::Val(pb::ValueId {
            module: Some(pb::ModuleId {
                package_id: Some(self.pkg_ref(pkg_id)),
                module_name_interned_dname: self.dname(module),
            }),
            name_interned_dname: self.dname(name),
        }))
    }

    fn build_dalf(mut self) -> (String, Vec<u8>) {
        let name_idx = self.s(&self.name.clone());
        let ver_idx = self.s(&self.version.clone());
        let imports_sum = if self.minor == "dev" {
            Some(pb::package::ImportsSum::PackageImports(
                pb::PackageImports {
                    imported_packages: self.imports,
                },
            ))
        } else {
            None
        };
        let pkg = pb::Package {
            modules: self.modules,
            interned_strings: self.strings,
            interned_dotted_names: self.dnames,
            metadata: Some(pb::PackageMetadata {
                name_interned_str: name_idx,
                version_interned_str: ver_idx,
                upgraded_package_id: None,
            }),
            interned_types: self.types,
            interned_kinds: Vec::new(),
            interned_exprs: Vec::new(),
            imports_sum,
        };
        let pkg_bytes = pkg.encode_to_vec();
        let payload = ArchivePayload {
            minor: self.minor.clone(),
            patch: 0,
            sum: Some(archive_payload::Sum::DamlLf2(pkg_bytes)),
        };
        let payload_bytes = payload.encode_to_vec();
        let hash = compute_sha256(&payload_bytes);
        let archive = Archive {
            hash_function: HashFunction::Sha256 as i32,
            payload: payload_bytes,
            hash: hash.clone(),
        };
        (hash, archive.encode_to_vec())
    }
}

fn e(sum: pb::expr::Sum) -> pb::Expr {
    pb::Expr {
        location: None,
        sum: Some(sum),
    }
}

fn e_int(n: i64) -> pb::Expr {
    e(pb::expr::Sum::BuiltinLit(pb::BuiltinLit {
        sum: Some(pb::builtin_lit::Sum::Int64(n)),
    }))
}

fn e_bool(b: bool) -> pb::Expr {
    e(pb::expr::Sum::BuiltinCon(if b {
        pb::BuiltinCon::ConTrue as i32
    } else {
        pb::BuiltinCon::ConFalse as i32
    }))
}

fn e_text(p: &mut PkgBuilder, text: &str) -> pb::Expr {
    let idx = p.s(text);
    e(pb::expr::Sum::BuiltinLit(pb::BuiltinLit {
        sum: Some(pb::builtin_lit::Sum::TextInternedStr(idx)),
    }))
}

fn e_numeric(p: &mut PkgBuilder, lit: &str) -> pb::Expr {
    let idx = p.s(lit);
    e(pb::expr::Sum::BuiltinLit(pb::BuiltinLit {
        sum: Some(pb::builtin_lit::Sum::NumericInternedStr(idx)),
    }))
}

fn e_var(p: &mut PkgBuilder, name: &str) -> pb::Expr {
    e(pb::expr::Sum::VarInternedStr(p.s(name)))
}

fn e_builtin(bf: pb::BuiltinFunction) -> pb::Expr {
    e(pb::expr::Sum::Builtin(bf as i32))
}

fn e_app(fun: pb::Expr, args: Vec<pb::Expr>) -> pb::Expr {
    e(pb::expr::Sum::App(Box::new(pb::expr::App {
        fun: Some(Box::new(fun)),
        args,
    })))
}

fn e_tyapp(mut expr: pb::Expr, types: Vec<pb::Type>) -> pb::Expr {
    for ty in types {
        expr = e(pb::expr::Sum::TyApp(Box::new(pb::expr::TyApp {
            expr: Some(Box::new(expr)),
            types: vec![ty],
        })));
    }
    expr
}

fn e_abs(p: &mut PkgBuilder, params: &[(&str, pb::Type)], mut body: pb::Expr) -> pb::Expr {
    for (n, ty) in params.iter().rev() {
        let var_interned_str = p.s(n);
        body = e(pb::expr::Sum::Abs(Box::new(pb::expr::Abs {
            param: vec![pb::VarWithType {
                var_interned_str,
                r#type: Some(ty.clone()),
            }],
            body: Some(Box::new(body)),
        })));
    }
    body
}

fn e_tyabs(p: &mut PkgBuilder, params: &[(&str, pb::Kind)], mut body: pb::Expr) -> pb::Expr {
    for (n, k) in params.iter().rev() {
        let var_interned_str = p.s(n);
        body = e(pb::expr::Sum::TyAbs(Box::new(pb::expr::TyAbs {
            param: vec![pb::TypeVarWithKind {
                var_interned_str,
                kind: Some(k.clone()),
            }],
            body: Some(Box::new(body)),
        })));
    }
    body
}

fn e_reccon(
    p: &mut PkgBuilder,
    pkg_id: Option<&str>,
    module: &[&str],
    name: &[&str],
    args: Vec<pb::Type>,
    fields: Vec<(&str, pb::Expr)>,
) -> pb::Expr {
    let tycon = p.tycon_id(pkg_id, module, name);
    let fs = fields
        .into_iter()
        .map(|(f, expr)| pb::FieldWithExpr {
            field_interned_str: p.s(f),
            expr: Some(expr),
        })
        .collect();
    e(pb::expr::Sum::RecCon(pb::expr::RecCon {
        tycon: Some(pb::r#type::Con {
            tycon: Some(tycon),
            args,
        }),
        fields: fs,
    }))
}

fn e_recproj(
    p: &mut PkgBuilder,
    pkg_id: Option<&str>,
    module: &[&str],
    name: &[&str],
    args: Vec<pb::Type>,
    field: &str,
    record: pb::Expr,
) -> pb::Expr {
    let tycon = p.tycon_id(pkg_id, module, name);
    let field_interned_str = p.s(field);
    e(pb::expr::Sum::RecProj(Box::new(pb::expr::RecProj {
        tycon: Some(pb::r#type::Con {
            tycon: Some(tycon),
            args,
        }),
        field_interned_str,
        record: Some(Box::new(record)),
    })))
}

fn e_structcon(p: &mut PkgBuilder, fields: Vec<(&str, pb::Expr)>) -> pb::Expr {
    let fs = fields
        .into_iter()
        .map(|(f, expr)| pb::FieldWithExpr {
            field_interned_str: p.s(f),
            expr: Some(expr),
        })
        .collect();
    e(pb::expr::Sum::StructCon(pb::expr::StructCon { fields: fs }))
}

fn e_structproj(p: &mut PkgBuilder, field: &str, r#struct: pb::Expr) -> pb::Expr {
    let fid = p.s(field);
    e(pb::expr::Sum::StructProj(Box::new(pb::expr::StructProj {
        field_interned_str: fid,
        r#struct: Some(Box::new(r#struct)),
    })))
}

fn e_nil(ty: pb::Type) -> pb::Expr {
    e(pb::expr::Sum::Nil(pb::expr::Nil { r#type: Some(ty) }))
}

fn e_cons(ty: pb::Type, front: Vec<pb::Expr>, tail: pb::Expr) -> pb::Expr {
    e(pb::expr::Sum::Cons(Box::new(pb::expr::Cons {
        r#type: Some(ty),
        front,
        tail: Some(Box::new(tail)),
    })))
}

fn e_to_any(ty: pb::Type, expr: pb::Expr) -> pb::Expr {
    e(pb::expr::Sum::ToAny(Box::new(pb::expr::ToAny {
        r#type: Some(ty),
        expr: Some(Box::new(expr)),
    })))
}

fn e_from_any(ty: pb::Type, expr: pb::Expr) -> pb::Expr {
    e(pb::expr::Sum::FromAny(Box::new(pb::expr::FromAny {
        r#type: Some(ty),
        expr: Some(Box::new(expr)),
    })))
}

fn e_type_rep(ty: pb::Type) -> pb::Expr {
    e(pb::expr::Sum::TypeRep(ty))
}

fn e_if_else(cond: pb::Expr, then_e: pb::Expr, else_e: pb::Expr) -> pb::Expr {
    e(pb::expr::Sum::Case(Box::new(pb::Case {
        scrut: Some(Box::new(cond)),
        alts: vec![
            pb::CaseAlt {
                sum: Some(pb::case_alt::Sum::BuiltinCon(
                    pb::BuiltinCon::ConTrue as i32,
                )),
                body: Some(then_e),
            },
            pb::CaseAlt {
                sum: Some(pb::case_alt::Sum::BuiltinCon(
                    pb::BuiltinCon::ConFalse as i32,
                )),
                body: Some(else_e),
            },
        ],
    })))
}

fn e_case_opt(
    p: &mut PkgBuilder,
    scrut: pb::Expr,
    binder: &str,
    some_body: pb::Expr,
    none_body: pb::Expr,
) -> pb::Expr {
    let bid = p.s(binder);
    e(pb::expr::Sum::Case(Box::new(pb::Case {
        scrut: Some(Box::new(scrut)),
        alts: vec![
            pb::CaseAlt {
                sum: Some(pb::case_alt::Sum::OptionalSome(
                    pb::case_alt::OptionalSome {
                        var_body_interned_str: bid,
                    },
                )),
                body: Some(some_body),
            },
            pb::CaseAlt {
                sum: Some(pb::case_alt::Sum::OptionalNone(pb::Unit {})),
                body: Some(none_body),
            },
        ],
    })))
}

fn def_val(p: &mut PkgBuilder, name: &str, ty: pb::Type, body: pb::Expr) -> pb::DefValue {
    pb::DefValue {
        location: None,
        name_with_type: Some(pb::def_value::NameWithType {
            name_interned_dname: p.dname(&[name]),
            r#type: Some(ty),
        }),
        expr: Some(body),
    }
}

fn std_flags() -> pb::FeatureFlags {
    pb::FeatureFlags {
        forbid_party_literals: true,
        dont_divulge_contract_ids_in_create_arguments: true,
        dont_disclose_non_consuming_choices_to_observers: true,
    }
}

fn build_dep_pkg(pkg_name: &str) -> (String, Vec<u8>) {
    let mut p = PkgBuilder::new(pkg_name, "1.0.0", "dev");

    // record Wrap a = { val : a }
    let t_a = p.t_var("a");
    let wrap_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Wrap"]),
        params: vec![pb::TypeVarWithKind {
            var_interned_str: p.s("a"),
            kind: Some(PkgBuilder::k_star()),
        }],
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![pb::FieldWithType {
                    field_interned_str: p.s("val"),
                    r#type: Some(t_a.clone()),
                }],
            },
        )),
    };

    // record Pair a b = { fst : a, snd : b }
    let t_b = p.t_var("b");
    let pair_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Pair"]),
        params: vec![
            pb::TypeVarWithKind {
                var_interned_str: p.s("a"),
                kind: Some(PkgBuilder::k_star()),
            },
            pb::TypeVarWithKind {
                var_interned_str: p.s("b"),
                kind: Some(PkgBuilder::k_star()),
            },
        ],
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![
                    pb::FieldWithType {
                        field_interned_str: p.s("fst"),
                        r#type: Some(t_a.clone()),
                    },
                    pb::FieldWithType {
                        field_interned_str: p.s("snd"),
                        r#type: Some(t_b),
                    },
                ],
            },
        )),
    };

    // record MyRec = { x : Int64 }
    let t_int = p.t_builtin(pb::BuiltinType::Int64);
    let myrec_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["MyRec"]),
        params: Vec::new(),
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![pb::FieldWithType {
                    field_interned_str: p.s("x"),
                    r#type: Some(t_int),
                }],
            },
        )),
    };

    // record Box (k : Nat) a = { n : Numeric k, payload : a }
    let t_k = p.t_var("k");
    let t_num_k = p.t_builtin_app(pb::BuiltinType::Numeric, vec![t_k]);
    let box_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Box"]),
        params: vec![
            pb::TypeVarWithKind {
                var_interned_str: p.s("k"),
                kind: Some(PkgBuilder::k_nat()),
            },
            pb::TypeVarWithKind {
                var_interned_str: p.s("a"),
                kind: Some(PkgBuilder::k_star()),
            },
        ],
        serializable: false,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![
                    pb::FieldWithType {
                        field_interned_str: p.s("n"),
                        r#type: Some(t_num_k),
                    },
                    pb::FieldWithType {
                        field_interned_str: p.s("payload"),
                        r#type: Some(t_a),
                    },
                ],
            },
        )),
    };

    let mod_dname = p.dname(&["Dep"]);
    p.modules.push(pb::Module {
        name_interned_dname: mod_dname,
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![wrap_def, pair_def, myrec_def, box_def],
        values: Vec::new(),
        templates: Vec::new(),
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    });
    p.build_dalf()
}

fn write_dar(path: &PathBuf, main_name: &str, main_bytes: &[u8], deps: &[(&str, &[u8])]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create oracle dir");
    }
    let file = File::create(path).expect("create dar file");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    let mut dalf_list = vec![main_name.to_string()];
    for (name, _) in deps {
        dalf_list.push((*name).to_string());
    }
    let manifest = format!(
        "Manifest-Version: 1.0\nCreated-By: gen_any_typerep_dar\nSdk-Version: 3.7.2\nMain-Dalf: {main_name}\nDalfs: {}\nFormat: daml-lf\nEncryption: non-encrypted\n",
        dalf_list.join(", ")
    );
    zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();

    zip.start_file(main_name, opts).unwrap();
    zip.write_all(main_bytes).unwrap();
    for (name, bytes) in deps {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn build_main_dar(out_dir: &std::path::Path) {
    let (dep_a_id, dep_a_bytes) = build_dep_pkg("any-dep-a");
    let (dep_b_id, dep_b_bytes) = build_dep_pkg("any-dep-b");

    let mut p = PkgBuilder::new("any-main", "1.0.0", "dev");

    // Module `A`: record P = { z : Int64 }
    let t_int = p.t_builtin(pb::BuiltinType::Int64);
    let a_mod = pb::Module {
        name_interned_dname: p.dname(&["A"]),
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["P"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Record(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("z"),
                        r#type: Some(t_int.clone()),
                    }],
                },
            )),
        }],
        values: Vec::new(),
        templates: Vec::new(),
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    };

    // Module `A.Z`: record R = { r : Int64 }
    let az_mod = pb::Module {
        name_interned_dname: p.dname(&["A", "Z"]),
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["R"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Record(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("r"),
                        r#type: Some(t_int.clone()),
                    }],
                },
            )),
        }],
        values: Vec::new(),
        templates: Vec::new(),
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    };

    // Module `M`: record X.Y = { v : Int64 }, record XZ = { v : Int64 }
    let m_mod = pb::Module {
        name_interned_dname: p.dname(&["M"]),
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![
            pb::DefDataType {
                location: None,
                name_interned_dname: p.dname(&["X", "Y"]),
                params: Vec::new(),
                serializable: true,
                data_cons: Some(pb::def_data_type::DataCons::Record(
                    pb::def_data_type::Fields {
                        fields: vec![pb::FieldWithType {
                            field_interned_str: p.s("v"),
                            r#type: Some(t_int.clone()),
                        }],
                    },
                )),
            },
            pb::DefDataType {
                location: None,
                name_interned_dname: p.dname(&["XZ"]),
                params: Vec::new(),
                serializable: true,
                data_cons: Some(pb::def_data_type::DataCons::Record(
                    pb::def_data_type::Fields {
                        fields: vec![pb::FieldWithType {
                            field_interned_str: p.s("v"),
                            r#type: Some(t_int.clone()),
                        }],
                    },
                )),
            },
        ],
        values: Vec::new(),
        templates: Vec::new(),
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    };

    // Types in `Main`
    let t_unit = p.t_builtin(pb::BuiltinType::Unit);
    let t_bool = p.t_builtin(pb::BuiltinType::Bool);
    let t_text = p.t_builtin(pb::BuiltinType::Text);
    let t_date = p.t_builtin(pb::BuiltinType::Date);
    let t_timestamp = p.t_builtin(pb::BuiltinType::Timestamp);
    let t_party = p.t_builtin(pb::BuiltinType::Party);
    let t_bignum = p.t_builtin(pb::BuiltinType::Bignumeric);
    let t_rmode = p.t_builtin(pb::BuiltinType::RoundingMode);
    let t_any = p.t_builtin(pb::BuiltinType::Any);
    let t_typerep = p.t_builtin(pb::BuiltinType::TypeRep);

    let t_nat5 = p.t_nat(5);
    let t_nat10 = p.t_nat(10);
    let t_num5 = p.t_builtin_app(pb::BuiltinType::Numeric, vec![t_nat5.clone()]);
    let t_num10 = p.t_builtin_app(pb::BuiltinType::Numeric, vec![t_nat10.clone()]);

    let t_a_myrec = p.t_con(Some(&dep_a_id), &["Dep"], &["MyRec"]);
    let t_b_myrec = p.t_con(Some(&dep_b_id), &["Dep"], &["MyRec"]);
    let t_a_wrap_int = p.t_con_app(Some(&dep_a_id), &["Dep"], &["Wrap"], vec![t_int.clone()]);
    let t_a_wrap_text = p.t_con_app(Some(&dep_a_id), &["Dep"], &["Wrap"], vec![t_text.clone()]);
    let t_b_wrap_int = p.t_con_app(Some(&dep_b_id), &["Dep"], &["Wrap"], vec![t_int.clone()]);
    let t_a_wrap_wrap_int = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_a_wrap_int.clone()],
    );
    let t_a_pair_int_text = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Pair"],
        vec![t_int.clone(), t_text.clone()],
    );
    let t_a_pair_text_int = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Pair"],
        vec![t_text.clone(), t_int.clone()],
    );
    let t_a_pair_int_int = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Pair"],
        vec![t_int.clone(), t_int.clone()],
    );
    let t_a_box_5_int = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Box"],
        vec![t_nat5.clone(), t_int.clone()],
    );
    let t_a_box_10_int = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Box"],
        vec![t_nat10, t_int.clone()],
    );

    let t_list_int = p.t_builtin_app(pb::BuiltinType::List, vec![t_int.clone()]);
    let t_list_party = p.t_builtin_app(pb::BuiltinType::List, vec![t_party.clone()]);
    let t_opt_text = p.t_builtin_app(pb::BuiltinType::Optional, vec![t_text.clone()]);
    let t_opt_wrap_int = p.t_builtin_app(pb::BuiltinType::Optional, vec![t_a_wrap_int.clone()]);
    let t_textmap_wrap = p.t_builtin_app(pb::BuiltinType::Textmap, vec![t_a_wrap_int.clone()]);
    let t_genmap_int_wrap_text = p.t_builtin_app(
        pb::BuiltinType::Genmap,
        vec![t_int.clone(), t_a_wrap_text.clone()],
    );
    let t_cid_wrap_int = p.t_builtin_app(pb::BuiltinType::ContractId, vec![t_a_wrap_int.clone()]);
    let t_arrow_int_text = p.t_arrow(t_int.clone(), t_text.clone());
    let t_arrow_int_int = p.t_arrow(t_int.clone(), t_int.clone());
    let t_arrow_text_text = p.t_arrow(t_text.clone(), t_text.clone());

    let t_struct_za = p.t_struct(&[("z", t_int.clone()), ("a", t_text.clone())]);
    let t_struct_ba = p.t_struct(&[("b", t_int.clone()), ("a", t_text.clone())]);
    let t_struct_ab = p.t_struct(&[("a", t_text.clone()), ("b", t_int.clone())]);
    let t_wrap_struct = p.t_con_app(
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_struct_za.clone()],
    );
    let t_struct_a_int = p.t_struct(&[("a", t_int.clone())]);
    let t_struct_a_text_b_int = p.t_struct(&[("a", t_text.clone()), ("b", t_int.clone())]);
    let t_struct_a_int_c_int = p.t_struct(&[("a", t_int.clone()), ("c", t_int.clone())]);

    let t_az_r = p.t_con(None, &["A", "Z"], &["R"]);
    let t_a_z = p.t_con(None, &["A"], &["P"]);
    let t_m_xy = p.t_con(None, &["M"], &["X", "Y"]);
    let t_m_xz = p.t_con(None, &["M"], &["XZ"]);

    // Local Main types: Either a b, Color, ITestView, ITest, ImplRec
    let tv_a = p.t_var("a");
    let tv_b = p.t_var("b");
    let either_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Either"]),
        params: vec![
            pb::TypeVarWithKind {
                var_interned_str: p.s("a"),
                kind: Some(PkgBuilder::k_star()),
            },
            pb::TypeVarWithKind {
                var_interned_str: p.s("b"),
                kind: Some(PkgBuilder::k_star()),
            },
        ],
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Variant(
            pb::def_data_type::Fields {
                fields: vec![
                    pb::FieldWithType {
                        field_interned_str: p.s("Left"),
                        r#type: Some(tv_a),
                    },
                    pb::FieldWithType {
                        field_interned_str: p.s("Right"),
                        r#type: Some(tv_b),
                    },
                ],
            },
        )),
    };
    let t_either_int_text = p.t_con_app(
        None,
        &["Main"],
        &["Either"],
        vec![t_int.clone(), t_text.clone()],
    );

    let color_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Color"]),
        params: Vec::new(),
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Enum(
            pb::def_data_type::EnumConstructors {
                constructors_interned_str: vec![p.s("Red"), p.s("Green"), p.s("Blue")],
            },
        )),
    };
    let t_color = p.t_con(None, &["Main"], &["Color"]);

    let itest_view_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["ITestView"]),
        params: Vec::new(),
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields { fields: Vec::new() },
        )),
    };
    let t_itest_view = p.t_con(None, &["Main"], &["ITestView"]);

    let itest_datatype = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["ITest"]),
        params: Vec::new(),
        serializable: false,
        data_cons: Some(pb::def_data_type::DataCons::Interface(pb::Unit {})),
    };
    let itest_iface = pb::DefInterface {
        location: None,
        tycon_interned_dname: p.dname(&["ITest"]),
        methods: Vec::new(),
        param_interned_str: p.s("this"),
        choices: Vec::new(),
        view: Some(t_itest_view),
        requires: Vec::new(),
    };

    let impl_rec_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["ImplRec"]),
        params: Vec::new(),
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![
                    pb::FieldWithType {
                        field_interned_str: p.s("sig"),
                        r#type: Some(t_party.clone()),
                    },
                    pb::FieldWithType {
                        field_interned_str: p.s("x"),
                        r#type: Some(t_int.clone()),
                    },
                ],
            },
        )),
    };
    let t_impl_rec = p.t_con(None, &["Main"], &["ImplRec"]);

    let impl_rec_view = e_reccon(
        &mut p,
        None,
        &["Main"],
        &["ITestView"],
        Vec::new(),
        Vec::new(),
    );
    let impl_this = e_var(&mut p, "this");
    let impl_sig_proj = e_recproj(
        &mut p,
        None,
        &["Main"],
        &["ImplRec"],
        Vec::new(),
        "sig",
        impl_this,
    );
    let impl_rec_tpl = pb::DefTemplate {
        tycon_interned_dname: p.dname(&["ImplRec"]),
        param_interned_str: p.s("this"),
        precond: None,
        signatories: Some(e_cons(
            t_party.clone(),
            vec![impl_sig_proj],
            e_nil(t_party.clone()),
        )),
        choices: Vec::new(),
        observers: Some(e_nil(t_party)),
        location: None,
        key: None,
        implements: vec![pb::def_template::Implements {
            interface: Some(p.tycon_id(None, &["Main"], &["ITest"])),
            body: Some(pb::InterfaceInstanceBody {
                methods: Vec::new(),
                view: Some(impl_rec_view),
            }),
            location: None,
        }],
    };
    let _ = t_list_party;

    // Helper: `cmp_typerep : TypeRep -> TypeRep -> Int64` returning -1, 0, or 1
    let cmp_tr_inner = p.t_arrow(t_typerep.clone(), t_int.clone());
    let cmp_tr_ty = p.t_arrow(t_typerep.clone(), cmp_tr_inner);
    let tr_vx = e_var(&mut p, "x");
    let tr_vy = e_var(&mut p, "y");
    let e_cmp_lt = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::Less),
            vec![t_typerep.clone()],
        ),
        vec![tr_vx.clone(), tr_vy.clone()],
    );
    let e_cmp_eq = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::Equal),
            vec![t_typerep.clone()],
        ),
        vec![tr_vx, tr_vy],
    );
    let cmp_tr_body = e_abs(
        &mut p,
        &[("x", t_typerep.clone()), ("y", t_typerep.clone())],
        e_if_else(e_cmp_lt, e_int(-1), e_if_else(e_cmp_eq, e_int(0), e_int(1))),
    );

    let cmp_any_inner = p.t_arrow(t_any.clone(), t_int.clone());
    let cmp_any_ty = p.t_arrow(t_any.clone(), cmp_any_inner);
    let any_vx = e_var(&mut p, "x");
    let any_vy = e_var(&mut p, "y");
    let e_any_lt = e_app(
        e_tyapp(e_builtin(pb::BuiltinFunction::Less), vec![t_any.clone()]),
        vec![any_vx.clone(), any_vy.clone()],
    );
    let e_any_eq = e_app(
        e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
        vec![any_vx, any_vy],
    );
    let cmp_any_body = e_abs(
        &mut p,
        &[("x", t_any.clone()), ("y", t_any.clone())],
        e_if_else(e_any_lt, e_int(-1), e_if_else(e_any_eq, e_int(0), e_int(1))),
    );

    let mut values = Vec::new();
    values.push(def_val(&mut p, "cmp_tr", cmp_tr_ty, cmp_tr_body));
    values.push(def_val(&mut p, "cmp_any", cmp_any_ty, cmp_any_body));

    // TypeRep rendering cases
    let tr_cases: Vec<(&str, pb::Type)> = vec![
        ("tr_unit", t_unit),
        ("tr_bool", t_bool.clone()),
        ("tr_int64", t_int.clone()),
        ("tr_text", t_text.clone()),
        ("tr_date", t_date),
        ("tr_timestamp", t_timestamp),
        ("tr_numeric10", t_num10.clone()),
        ("tr_bignumeric", t_bignum),
        ("tr_rounding_mode", t_rmode),
        ("tr_unapplied", t_a_myrec.clone()),
        ("tr_wrap_int", t_a_wrap_int.clone()),
        ("tr_pair_int_text", t_a_pair_int_text.clone()),
        ("tr_nested_wrap", t_a_wrap_wrap_int),
        ("tr_list_int", t_list_int),
        ("tr_opt_wrap", t_opt_wrap_int),
        ("tr_textmap_wrap", t_textmap_wrap),
        ("tr_genmap", t_genmap_int_wrap_text),
        ("tr_cid_wrap", t_cid_wrap_int),
        ("tr_arrow", t_arrow_int_text),
        ("tr_struct_unsorted", t_struct_za),
        ("tr_wrap_struct", t_wrap_struct),
        ("tr_tapp_nat", t_a_box_5_int.clone()),
        ("tr_enum_color", t_color.clone()),
    ];
    for (name, ty) in &tr_cases {
        values.push(def_val(
            &mut p,
            name,
            t_typerep.clone(),
            e_type_rep(ty.clone()),
        ));
    }

    // InterfaceTemplateTypeRep
    let alice_txt = e_text(&mut p, "alice");
    let parsed_alice = e_app(e_builtin(pb::BuiltinFunction::TextToParty), vec![alice_txt]);
    let sp_var = e_var(&mut p, "sp");
    let impl_ok = e_reccon(
        &mut p,
        None,
        &["Main"],
        &["ImplRec"],
        Vec::new(),
        vec![("sig", sp_var), ("x", e_int(42))],
    );
    let err_msg = e_text(&mut p, "bad");
    let impl_err = e_app(
        e_tyapp(e_builtin(pb::BuiltinFunction::Error), vec![t_impl_rec]),
        vec![err_msg],
    );
    let impl_val = e_case_opt(&mut p, parsed_alice, "sp", impl_ok, impl_err);
    let to_iface = e(pb::expr::Sum::ToInterface(Box::new(
        pb::expr::ToInterface {
            interface_type: Some(p.tycon_id(None, &["Main"], &["ITest"])),
            template_type: Some(p.tycon_id(None, &["Main"], &["ImplRec"])),
            template_expr: Some(Box::new(impl_val)),
        },
    )));
    let iface_tr_expr = e(pb::expr::Sum::InterfaceTemplateTypeRep(Box::new(
        pb::expr::InterfaceTemplateTypeRep {
            interface: Some(p.tycon_id(None, &["Main"], &["ITest"])),
            expr: Some(Box::new(to_iface)),
        },
    )));
    values.push(def_val(
        &mut p,
        "tr_iface_impl",
        t_typerep.clone(),
        iface_tr_expr.clone(),
    ));

    // TYPE_REP_TYCON_NAME (3011)
    let tycon_name_cases = vec![
        ("tycon_name_unapplied", e_type_rep(t_a_myrec.clone())),
        ("tycon_name_iface", iface_tr_expr),
        ("tycon_name_applied", e_type_rep(t_a_wrap_int.clone())),
        ("tycon_name_numeric", e_type_rep(t_num10.clone())),
        ("tycon_name_builtin", e_type_rep(t_int.clone())),
        ("tycon_name_struct", e_type_rep(t_struct_ba.clone())),
        (
            "tycon_name_list",
            e_type_rep(p.t_builtin_app(pb::BuiltinType::List, vec![t_int.clone()])),
        ),
    ];
    for (name, tr_expr) in tycon_name_cases {
        let body = e_app(
            e_builtin(pb::BuiltinFunction::TypeRepTyconName),
            vec![tr_expr],
        );
        values.push(def_val(&mut p, name, t_opt_text.clone(), body));
    }

    // ToAny / FromAny round-trips & mismatches
    let wrap_99 = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(99))],
    );
    let any_wrap_99 = e_to_any(t_a_wrap_int.clone(), wrap_99);
    let fa_wrap_int = e_from_any(t_a_wrap_int.clone(), any_wrap_99.clone());
    let e_r = e_var(&mut p, "r");
    let proj_val = e_recproj(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        "val",
        e_r.clone(),
    );
    let c_any_wrap_int_ok = e_case_opt(&mut p, fa_wrap_int, "r", proj_val, e_int(-1));
    values.push(def_val(
        &mut p,
        "any_wrap_int_ok",
        t_int.clone(),
        c_any_wrap_int_ok,
    ));

    let fa_wrap_text = e_from_any(t_a_wrap_text.clone(), any_wrap_99);
    let c_any_wrap_int_vs_text = e_case_opt(&mut p, fa_wrap_text, "_", e_bool(true), e_bool(false));
    values.push(def_val(
        &mut p,
        "any_wrap_int_vs_text",
        t_bool.clone(),
        c_any_wrap_int_vs_text,
    ));

    let e_hi = e_text(&mut p, "hi");
    let pair_7_hi = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Pair"],
        vec![t_int.clone(), t_text.clone()],
        vec![("fst", e_int(7)), ("snd", e_hi)],
    );
    let any_pair_7_hi = e_to_any(t_a_pair_int_text.clone(), pair_7_hi);
    let fa_pair_swap = e_from_any(t_a_pair_text_int, any_pair_7_hi.clone());
    let c_any_pair_swap = e_case_opt(&mut p, fa_pair_swap, "_", e_bool(true), e_bool(false));
    values.push(def_val(
        &mut p,
        "any_pair_swapped_mismatch",
        t_bool.clone(),
        c_any_pair_swap,
    ));

    let fa_pair_ok = e_from_any(t_a_pair_int_text, any_pair_7_hi);
    let proj_snd = e_recproj(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Pair"],
        vec![t_int.clone(), t_text.clone()],
        "snd",
        e_r,
    );
    let e_bad = e_text(&mut p, "bad");
    let c_any_pair_match = e_case_opt(&mut p, fa_pair_ok, "r", proj_snd, e_bad.clone());
    values.push(def_val(
        &mut p,
        "any_pair_match",
        t_text.clone(),
        c_any_pair_match,
    ));

    let num_10_val = e_numeric(&mut p, "1.2300000000");
    let any_num_10 = e_to_any(t_num10.clone(), num_10_val);
    let fa_num_5 = e_from_any(t_num5, any_num_10.clone());
    let c_any_num_mismatch = e_case_opt(&mut p, fa_num_5, "_", e_bool(true), e_bool(false));
    values.push(def_val(
        &mut p,
        "any_numeric_mismatch",
        t_bool.clone(),
        c_any_num_mismatch,
    ));
    let t_opt_num10 = p.t_builtin_app(pb::BuiltinType::Optional, vec![t_num10.clone()]);
    values.push(def_val(
        &mut p,
        "any_numeric_match",
        t_opt_num10,
        e_from_any(t_num10, any_num_10),
    ));

    let e_ok = e_text(&mut p, "ok");
    let struct_ba_val = e_structcon(&mut p, vec![("b", e_int(5)), ("a", e_ok)]);
    let any_struct_ba = e_to_any(t_struct_ba.clone(), struct_ba_val);
    let fa_struct_ab = e_from_any(t_struct_ab.clone(), any_struct_ba.clone());
    let e_s = e_var(&mut p, "s");
    let proj_a = e_structproj(&mut p, "a", e_s);
    let c_any_struct_match = e_case_opt(&mut p, fa_struct_ab, "s", proj_a, e_bad);
    values.push(def_val(
        &mut p,
        "any_struct_reorder_match",
        t_text.clone(),
        c_any_struct_match,
    ));

    let num_5_val = e_numeric(&mut p, "1.00000");
    let box_5_val = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Box"],
        vec![t_nat5, t_int.clone()],
        vec![("n", num_5_val), ("payload", e_int(3))],
    );
    let fa_box_10 = e_from_any(
        t_a_box_10_int.clone(),
        e_to_any(t_a_box_5_int.clone(), box_5_val),
    );
    let c_any_box_mismatch = e_case_opt(&mut p, fa_box_10, "_", e_bool(true), e_bool(false));
    values.push(def_val(
        &mut p,
        "any_box_nat_mismatch",
        t_bool.clone(),
        c_any_box_mismatch,
    ));

    let wrap_a_1 = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(1))],
    );
    let wrap_b_1 = e_reccon(
        &mut p,
        Some(&dep_b_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(1))],
    );
    let fa_wrap_b = e_from_any(
        t_b_wrap_int.clone(),
        e_to_any(t_a_wrap_int.clone(), wrap_a_1.clone()),
    );
    let c_any_pkg_mismatch = e_case_opt(&mut p, fa_wrap_b, "_", e_bool(true), e_bool(false));
    values.push(def_val(
        &mut p,
        "any_pkg_mismatch",
        t_bool.clone(),
        c_any_pkg_mismatch,
    ));

    let enum_green = e(pb::expr::Sum::EnumCon(pb::expr::EnumCon {
        tycon: Some(p.tycon_id(None, &["Main"], &["Color"])),
        enum_con_interned_str: p.s("Green"),
    }));
    let opt_green = e(pb::expr::Sum::OptionalSome(Box::new(
        pb::expr::OptionalSome {
            r#type: Some(t_color.clone()),
            value: Some(Box::new(enum_green.clone())),
        },
    )));
    let t_opt_color = p.t_builtin_app(pb::BuiltinType::Optional, vec![t_color.clone()]);
    values.push(def_val(
        &mut p,
        "any_enum_match",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_opt_color]),
            vec![
                e_from_any(t_color.clone(), e_to_any(t_color, enum_green)),
                opt_green,
            ],
        ),
    ));

    // Variant / Closure / Struct Any Equality
    let v_left_1 = e(pb::expr::Sum::VariantCon(Box::new(pb::expr::VariantCon {
        tycon: Some(pb::r#type::Con {
            tycon: Some(p.tycon_id(None, &["Main"], &["Either"])),
            args: vec![t_int.clone(), t_text.clone()],
        }),
        variant_con_interned_str: p.s("Left"),
        variant_arg: Some(Box::new(e_int(1))),
    })));
    let v_left_2 = e(pb::expr::Sum::VariantCon(Box::new(pb::expr::VariantCon {
        tycon: Some(pb::r#type::Con {
            tycon: Some(p.tycon_id(None, &["Main"], &["Either"])),
            args: vec![t_int.clone(), t_text.clone()],
        }),
        variant_con_interned_str: p.s("Left"),
        variant_arg: Some(Box::new(e_int(2))),
    })));
    let v_right_a = e(pb::expr::Sum::VariantCon(Box::new(pb::expr::VariantCon {
        tycon: Some(pb::r#type::Con {
            tycon: Some(p.tycon_id(None, &["Main"], &["Either"])),
            args: vec![t_int.clone(), t_text.clone()],
        }),
        variant_con_interned_str: p.s("Right"),
        variant_arg: Some(Box::new(e_text(&mut p, "a"))),
    })));
    let any_left_1 = e_to_any(t_either_int_text.clone(), v_left_1.clone());
    let any_left_1b = e_to_any(t_either_int_text.clone(), v_left_1);
    let any_left_2 = e_to_any(t_either_int_text.clone(), v_left_2);
    let any_right_a = e_to_any(t_either_int_text, v_right_a);

    values.push(def_val(
        &mut p,
        "any_variant_eq_same_diff_con",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![any_left_1.clone(), any_right_a],
        ),
    ));
    values.push(def_val(
        &mut p,
        "any_variant_eq_same_con",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![any_left_1.clone(), any_left_1b],
        ),
    ));
    values.push(def_val(
        &mut p,
        "any_variant_eq_same_con_diff_val",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![any_left_1, any_left_2],
        ),
    ));

    let vx = e_var(&mut p, "x");
    let fn_int = e_abs(&mut p, &[("x", t_int.clone())], vx);
    let vs = e_var(&mut p, "s");
    let fn_text = e_abs(&mut p, &[("s", t_text.clone())], vs);
    values.push(def_val(
        &mut p,
        "any_fn_diff_type_eq",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![
                e_to_any(t_arrow_int_int, fn_int),
                e_to_any(t_arrow_text_text, fn_text),
            ],
        ),
    ));

    let e_a = e_text(&mut p, "a");
    let wrap_text_a = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_text.clone()],
        vec![("val", e_a)],
    );
    values.push(def_val(
        &mut p,
        "any_wrap_eq_diff_tyarg",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![
                e_to_any(t_a_wrap_int.clone(), wrap_a_1.clone()),
                e_to_any(t_a_wrap_text.clone(), wrap_text_a.clone()),
            ],
        ),
    ));
    values.push(def_val(
        &mut p,
        "any_wrap_eq_diff_pkg",
        t_bool.clone(),
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![
                e_to_any(t_a_wrap_int.clone(), wrap_a_1.clone()),
                e_to_any(t_b_wrap_int.clone(), wrap_b_1),
            ],
        ),
    ));

    let e_ok2 = e_text(&mut p, "ok");
    let struct_ab_val = e_structcon(&mut p, vec![("a", e_ok2), ("b", e_int(5))]);
    values.push(def_val(
        &mut p,
        "any_struct_reordered_eq",
        t_bool,
        e_app(
            e_tyapp(e_builtin(pb::BuiltinFunction::Equal), vec![t_any.clone()]),
            vec![any_struct_ba.clone(), e_to_any(t_struct_ab, struct_ab_val)],
        ),
    ));

    // TypeOrdering / Any Ordering tests using cmp_tr and cmp_any
    let cmp_tr_ref = p.val_id(None, &["Main"], &["cmp_tr"]);
    let cmp_any_ref = p.val_id(None, &["Main"], &["cmp_any"]);

    let tr_ord_cases = vec![
        ("ord_tr_builtin_lt_tycon", t_int.clone(), t_a_myrec.clone()),
        (
            "ord_tr_tycon_lt_app",
            t_a_myrec.clone(),
            t_a_wrap_int.clone(),
        ),
        (
            "ord_tr_builtin_lt_struct",
            t_int.clone(),
            t_struct_a_int.clone(),
        ),
        (
            "ord_tr_tycon_lt_struct",
            t_a_myrec.clone(),
            t_struct_a_int.clone(),
        ),
        (
            "ord_tr_struct_lt_app",
            t_struct_a_int,
            t_list_int_type(&mut p, &t_int),
        ),
        ("ord_tr_nat5_lt_nat10", t_a_box_5_int, t_a_box_10_int),
        (
            "ord_tr_struct_names_before_types",
            t_struct_a_text_b_int.clone(),
            t_struct_a_int_c_int,
        ),
        (
            "ord_tr_wrap_vs_pair",
            t_a_wrap_int.clone(),
            t_a_pair_int_int,
        ),
        ("ord_tr_dotted_mod", t_a_z, t_az_r),
        ("ord_tr_dotted_name", t_m_xy, t_m_xz),
        ("ord_tr_multi_pkg_wrap", t_a_wrap_int.clone(), t_b_wrap_int),
        ("ord_tr_multi_pkg_myrec", t_a_myrec, t_b_myrec),
    ];
    for (name, t1, t2) in tr_ord_cases {
        let body = e_app(cmp_tr_ref.clone(), vec![e_type_rep(t1), e_type_rep(t2)]);
        values.push(def_val(&mut p, name, t_int.clone(), body));
    }

    let wrap_a_2 = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(2))],
    );
    let wrap_a_10 = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(10))],
    );
    let wrap_a_100 = e_reccon(
        &mut p,
        Some(&dep_a_id),
        &["Dep"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(100))],
    );
    values.push(def_val(
        &mut p,
        "ord_any_tycon_vs_val",
        t_int.clone(),
        e_app(
            cmp_any_ref.clone(),
            vec![
                e_to_any(t_a_wrap_int.clone(), wrap_a_100),
                e_to_any(t_a_wrap_text.clone(), wrap_text_a.clone()),
            ],
        ),
    ));
    values.push(def_val(
        &mut p,
        "ord_any_same_type_diff_val",
        t_int.clone(),
        e_app(
            cmp_any_ref,
            vec![
                e_to_any(t_a_wrap_int.clone(), wrap_a_2),
                e_to_any(t_a_wrap_int.clone(), wrap_a_10),
            ],
        ),
    ));

    // GenMap TypeRep keys: insert Int64 -> "int", Wrap Int64 -> "wrapInt", <b,a> -> "struct"
    let t_gm_tr = p.t_builtin_app(
        pb::BuiltinType::Genmap,
        vec![t_typerep.clone(), t_text.clone()],
    );
    let gm_tr_0 = e_tyapp(
        e_builtin(pb::BuiltinFunction::GenmapEmpty),
        vec![t_typerep.clone(), t_text.clone()],
    );
    let gm_tr_1 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_typerep.clone(), t_text.clone()],
        ),
        vec![e_type_rep(t_int.clone()), e_text(&mut p, "int"), gm_tr_0],
    );
    let gm_tr_2 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_typerep.clone(), t_text.clone()],
        ),
        vec![
            e_type_rep(t_a_wrap_int.clone()),
            e_text(&mut p, "wrapInt"),
            gm_tr_1,
        ],
    );
    let gm_tr_3 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_typerep.clone(), t_text.clone()],
        ),
        vec![e_type_rep(t_struct_ba), e_text(&mut p, "struct"), gm_tr_2],
    );
    let t_list_text = p.t_builtin_app(pb::BuiltinType::List, vec![t_text.clone()]);
    let tr_vals_expr = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapValues),
            vec![t_typerep.clone(), t_text.clone()],
        ),
        vec![gm_tr_3.clone()],
    );
    values.push(def_val(
        &mut p,
        "genmap_typerep_values_order",
        t_list_text,
        tr_vals_expr,
    ));
    let tr_lookup_expr = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapLookup),
            vec![t_typerep, t_text],
        ),
        vec![e_type_rep(t_struct_a_text_b_int.clone()), gm_tr_3],
    );
    values.push(def_val(
        &mut p,
        "genmap_typerep_lookup_struct",
        t_opt_text,
        tr_lookup_expr,
    ));

    // GenMap Any keys: Wrap Int64(1) -> 10, Wrap Text("a") -> 20, <b,a> -> 30
    let t_gm_any = p.t_builtin_app(pb::BuiltinType::Genmap, vec![t_any.clone(), t_int.clone()]);
    let gm_any_0 = e_tyapp(
        e_builtin(pb::BuiltinFunction::GenmapEmpty),
        vec![t_any.clone(), t_int.clone()],
    );
    let gm_any_1 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_any.clone(), t_int.clone()],
        ),
        vec![e_to_any(t_a_wrap_int, wrap_a_1), e_int(10), gm_any_0],
    );
    let gm_any_2 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_any.clone(), t_int.clone()],
        ),
        vec![e_to_any(t_a_wrap_text, wrap_text_a), e_int(20), gm_any_1],
    );
    let gm_any_3 = e_app(
        e_tyapp(
            e_builtin(pb::BuiltinFunction::GenmapInsert),
            vec![t_any.clone(), t_int.clone()],
        ),
        vec![any_struct_ba, e_int(30), gm_any_2],
    );
    let t_list_int = p.t_builtin_app(pb::BuiltinType::List, vec![t_int.clone()]);
    values.push(def_val(
        &mut p,
        "genmap_any_values_order",
        t_list_int,
        e_app(
            e_tyapp(
                e_builtin(pb::BuiltinFunction::GenmapValues),
                vec![t_any.clone(), t_int.clone()],
            ),
            vec![gm_any_3.clone()],
        ),
    ));
    let e_ok3 = e_text(&mut p, "ok");
    let struct_ab_val2 = e_structcon(&mut p, vec![("a", e_ok3), ("b", e_int(5))]);
    let t_opt_int = p.t_builtin_app(pb::BuiltinType::Optional, vec![t_int.clone()]);
    values.push(def_val(
        &mut p,
        "genmap_any_lookup_reordered_struct",
        t_opt_int,
        e_app(
            e_tyapp(
                e_builtin(pb::BuiltinFunction::GenmapLookup),
                vec![t_any, t_int],
            ),
            vec![e_to_any(t_struct_a_text_b_int, struct_ab_val2), gm_any_3],
        ),
    ));
    let _ = (t_gm_tr, t_gm_any);

    let main_mod = pb::Module {
        name_interned_dname: p.dname(&["Main"]),
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![
            either_def,
            color_def,
            itest_view_def,
            itest_datatype,
            impl_rec_def,
        ],
        values,
        templates: vec![impl_rec_tpl],
        exceptions: Vec::new(),
        interfaces: vec![itest_iface],
    };

    p.modules = vec![a_mod, az_mod, m_mod, main_mod];
    let (main_id, main_bytes) = p.build_dalf();

    let main_file = format!("any-main-{main_id}.dalf");
    let dep_a_file = format!("any-dep-a-{dep_a_id}.dalf");
    let dep_b_file = format!("any-dep-b-{dep_b_id}.dalf");
    let dar_path = out_dir.join("any-typerep.dar");
    write_dar(
        &dar_path,
        &main_file,
        &main_bytes,
        &[(&dep_a_file, &dep_a_bytes), (&dep_b_file, &dep_b_bytes)],
    );

    // Emit `cases.tsv`
    let case_names = vec![
        "tr_unit",
        "tr_bool",
        "tr_int64",
        "tr_text",
        "tr_date",
        "tr_timestamp",
        "tr_numeric10",
        "tr_bignumeric",
        "tr_rounding_mode",
        "tr_unapplied",
        "tr_wrap_int",
        "tr_pair_int_text",
        "tr_nested_wrap",
        "tr_list_int",
        "tr_opt_wrap",
        "tr_textmap_wrap",
        "tr_genmap",
        "tr_cid_wrap",
        "tr_arrow",
        "tr_struct_unsorted",
        "tr_wrap_struct",
        "tr_tapp_nat",
        "tr_enum_color",
        "tr_iface_impl",
        "tycon_name_unapplied",
        "tycon_name_iface",
        "tycon_name_applied",
        "tycon_name_numeric",
        "tycon_name_builtin",
        "tycon_name_struct",
        "tycon_name_list",
        "any_wrap_int_ok",
        "any_wrap_int_vs_text",
        "any_pair_swapped_mismatch",
        "any_pair_match",
        "any_numeric_mismatch",
        "any_numeric_match",
        "any_struct_reorder_match",
        "any_box_nat_mismatch",
        "any_pkg_mismatch",
        "any_enum_match",
        "any_variant_eq_same_diff_con",
        "any_variant_eq_same_con",
        "any_variant_eq_same_con_diff_val",
        "any_fn_diff_type_eq",
        "any_wrap_eq_diff_tyarg",
        "any_wrap_eq_diff_pkg",
        "any_struct_reordered_eq",
        "ord_tr_builtin_lt_tycon",
        "ord_tr_tycon_lt_app",
        "ord_tr_builtin_lt_struct",
        "ord_tr_tycon_lt_struct",
        "ord_tr_struct_lt_app",
        "ord_tr_nat5_lt_nat10",
        "ord_tr_struct_names_before_types",
        "ord_tr_wrap_vs_pair",
        "ord_tr_dotted_mod",
        "ord_tr_dotted_name",
        "ord_tr_multi_pkg_wrap",
        "ord_tr_multi_pkg_myrec",
        "ord_any_tycon_vs_val",
        "ord_any_same_type_diff_val",
        "genmap_typerep_values_order",
        "genmap_typerep_lookup_struct",
        "genmap_any_values_order",
        "genmap_any_lookup_reordered_struct",
    ];
    let mut tsv = String::new();
    for name in case_names {
        tsv.push_str(name);
        tsv.push('\t');
        tsv.push_str(name);
        tsv.push('\n');
    }
    fs::write(out_dir.join("cases.tsv"), tsv).expect("write cases.tsv");
}

fn t_list_int_type(p: &mut PkgBuilder, t_int: &pb::Type) -> pb::Type {
    p.t_builtin_app(pb::BuiltinType::List, vec![t_int.clone()])
}

/// LF 2.1 valid DAR using `Con.args` (flat archive is 2.dev-only) and template Any
fn build_lf21_args_dar(out_dir: &std::path::Path) {
    let mut p = PkgBuilder::new("any-lf21", "1.0.0", "1");
    let t_a = p.t_var("a");
    let t_int = p.t_builtin(pb::BuiltinType::Int64);
    let t_party = p.t_builtin(pb::BuiltinType::Party);
    let t_bool = p.t_builtin(pb::BuiltinType::Bool);
    let t_typerep = p.t_builtin(pb::BuiltinType::TypeRep);

    let wrap_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["Wrap"]),
        params: vec![pb::TypeVarWithKind {
            var_interned_str: p.s("a"),
            kind: Some(PkgBuilder::k_star()),
        }],
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![pb::FieldWithType {
                    field_interned_str: p.s("val"),
                    r#type: Some(t_a),
                }],
            },
        )),
    };
    let my_tmpl_def = pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&["MyTmpl"]),
        params: Vec::new(),
        serializable: true,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: vec![pb::FieldWithType {
                    field_interned_str: p.s("p"),
                    r#type: Some(t_party.clone()),
                }],
            },
        )),
    };
    let v_this = e_var(&mut p, "this");
    let sig_p = e_recproj(
        &mut p,
        None,
        &["Main"],
        &["MyTmpl"],
        Vec::new(),
        "p",
        v_this,
    );
    let my_tmpl_tpl = pb::DefTemplate {
        tycon_interned_dname: p.dname(&["MyTmpl"]),
        param_interned_str: p.s("this"),
        precond: None,
        signatories: Some(e_cons(t_party.clone(), vec![sig_p], e_nil(t_party.clone()))),
        choices: Vec::new(),
        observers: Some(e_nil(t_party)),
        location: None,
        key: None,
        implements: Vec::new(),
    };

    let t_wrap_int = p.t_con_app(None, &["Main"], &["Wrap"], vec![t_int.clone()]);
    let t_my_tmpl = p.t_con(None, &["Main"], &["MyTmpl"]);
    let wrap_42 = e_reccon(
        &mut p,
        None,
        &["Main"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(42))],
    );
    let proj_42 = e_recproj(
        &mut p,
        None,
        &["Main"],
        &["Wrap"],
        vec![t_int.clone()],
        "val",
        wrap_42,
    );
    let tr_tmpl = e_type_rep(t_my_tmpl);

    let wrap_7 = e_reccon(
        &mut p,
        None,
        &["Main"],
        &["Wrap"],
        vec![t_int.clone()],
        vec![("val", e_int(7))],
    );
    let vals = vec![
        def_val(&mut p, "lf21_wrap_args", t_int, proj_42),
        def_val(&mut p, "lf21_tr_tmpl", t_typerep, tr_tmpl),
        def_val(&mut p, "lf21_wrap_ty", t_wrap_int, wrap_7),
        def_val(&mut p, "lf21_ok", t_bool, e_bool(true)),
    ];

    let mod_dname = p.dname(&["Main"]);
    p.modules.push(pb::Module {
        name_interned_dname: mod_dname,
        flags: Some(std_flags()),
        synonyms: Vec::new(),
        data_types: vec![wrap_def, my_tmpl_def],
        values: vals,
        templates: vec![my_tmpl_tpl],
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    });
    let (pkg_id, pkg_bytes) = p.build_dalf();
    write_dar(
        &out_dir.join("any-lf21.dar"),
        &format!("any-lf21-{pkg_id}.dalf"),
        &pkg_bytes,
        &[],
    );
    fs::write(
        out_dir.join("cases-lf21.tsv"),
        "lf21_wrap_args\tlf21_wrap_args\nlf21_tr_tmpl\tlf21_tr_tmpl\nlf21_ok\tlf21_ok\n",
    )
    .expect("write cases-lf21.tsv");
}

/// Tampered DARs expected to be rejected by Canton Validation
fn build_negative_dars(out_dir: &std::path::Path) {
    // 1. `bad-any-tvar-lf2dev.dar`: TypeRep(TVar a) in 2.dev
    {
        let mut p = PkgBuilder::new("bad-any-tvar", "1.0.0", "dev");
        let t_a = p.t_var("a");
        let t_typerep = p.t_builtin(pb::BuiltinType::TypeRep);
        let t_poly = p.t_forall(&[("a", PkgBuilder::k_star())], t_typerep);
        let body = e_tyabs(&mut p, &[("a", PkgBuilder::k_star())], e_type_rep(t_a));
        let dv = def_val(&mut p, "bad", t_poly, body);
        let md = p.dname(&["Main"]);
        p.modules.push(pb::Module {
            name_interned_dname: md,
            flags: Some(std_flags()),
            synonyms: Vec::new(),
            data_types: Vec::new(),
            values: vec![dv],
            templates: Vec::new(),
            exceptions: Vec::new(),
            interfaces: Vec::new(),
        });
        let (pid, bytes) = p.build_dalf();
        write_dar(
            &out_dir.join("bad-any-tvar-lf2dev.invalid-dar"),
            &format!("bad-any-tvar-{pid}.dalf"),
            &bytes,
            &[],
        );
    }

    // 2. `bad-complex-any-lf21.dar`: TypeRep(Int64) in 2.1 (disallowed before 2.dev)
    {
        let mut p = PkgBuilder::new("bad-complex-any", "1.0.0", "1");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let t_typerep = p.t_builtin(pb::BuiltinType::TypeRep);
        let dv = def_val(&mut p, "bad", t_typerep, e_type_rep(t_int));
        let md = p.dname(&["Main"]);
        p.modules.push(pb::Module {
            name_interned_dname: md,
            flags: Some(std_flags()),
            synonyms: Vec::new(),
            data_types: Vec::new(),
            values: vec![dv],
            templates: Vec::new(),
            exceptions: Vec::new(),
            interfaces: Vec::new(),
        });
        let (pid, bytes) = p.build_dalf();
        write_dar(
            &out_dir.join("bad-complex-any-lf21.invalid-dar"),
            &format!("bad-complex-any-{pid}.dalf"),
            &bytes,
            &[],
        );
    }
}

fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/oracle/any-typerep");
    build_main_dar(&out_dir);
    build_lf21_args_dar(&out_dir);
    build_negative_dars(&out_dir);
    println!("Generated any-typerep oracle DARs in {}", out_dir.display());
}
