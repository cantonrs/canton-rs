#![allow(clippy::unwrap_used, reason = "offline DAR fixture generator example")]

use lf_archive::crypto::compute_sha256;
use lf_archive::proto::daml_lf::{archive_payload, Archive, ArchivePayload, HashFunction};
use lf_archive::proto::daml_lf_2 as pb;
use prost::Message;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
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

    fn mod_id(&mut self, pkg_id: Option<&str>, module: &[&str]) -> pb::ModuleId {
        pb::ModuleId {
            package_id: Some(self.pkg_ref(pkg_id)),
            module_name_interned_dname: self.dname(module),
        }
    }

    fn tycon_id(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::TypeConId {
        pb::TypeConId {
            module: Some(self.mod_id(pkg_id, module)),
            name_interned_dname: self.dname(name),
        }
    }

    fn intern_type(&mut self, sum: pb::r#type::Sum) -> pb::Type {
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

    fn k_arrow(param: pb::Kind, result: pb::Kind) -> pb::Kind {
        pb::Kind {
            sum: Some(pb::kind::Sum::Arrow(Box::new(pb::kind::Arrow {
                params: vec![param],
                result: Some(Box::new(result)),
            }))),
        }
    }

    fn t_builtin(&mut self, bt: pb::BuiltinType) -> pb::Type {
        self.intern_type(pb::r#type::Sum::Builtin(pb::r#type::Builtin {
            builtin: bt as i32,
            args: Vec::new(),
        }))
    }

    fn t_app(&mut self, lhs: pb::Type, rhs: pb::Type) -> pb::Type {
        self.intern_type(pb::r#type::Sum::Tapp(Box::new(pb::r#type::TApp {
            lhs: Some(Box::new(lhs)),
            rhs: Some(Box::new(rhs)),
        })))
    }

    fn t_builtin_app(&mut self, bt: pb::BuiltinType, args: Vec<pb::Type>) -> pb::Type {
        if self.minor == "1" || self.minor == "2.1" {
            return self.intern_type(pb::r#type::Sum::Builtin(pb::r#type::Builtin {
                builtin: bt as i32,
                args,
            }));
        }
        let mut cur = self.t_builtin(bt);
        for a in args {
            cur = self.t_app(cur, a);
        }
        cur
    }

    fn t_arrow(&mut self, from: pb::Type, to: pb::Type) -> pb::Type {
        self.t_builtin_app(pb::BuiltinType::Arrow, vec![from, to])
    }

    fn t_list(&mut self, elem: pb::Type) -> pb::Type {
        self.t_builtin_app(pb::BuiltinType::List, vec![elem])
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

    fn t_syn(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::Type {
        let ts = pb::TypeSynId {
            module: Some(self.mod_id(pkg_id, module)),
            name_interned_dname: self.dname(name),
        };
        self.intern_type(pb::r#type::Sum::Syn(pb::r#type::Syn {
            tysyn: Some(ts),
            args: Vec::new(),
        }))
    }

    fn e_val(&mut self, pkg_id: Option<&str>, module: &[&str], name: &[&str]) -> pb::Expr {
        e(pb::expr::Sum::Val(pb::ValueId {
            module: Some(self.mod_id(pkg_id, module)),
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

fn e_unit() -> pb::Expr {
    e(pb::expr::Sum::BuiltinCon(pb::BuiltinCon::ConUnit as i32))
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

fn e_text(p: &mut PkgBuilder, s: &str) -> pb::Expr {
    let idx = p.s(s);
    e(pb::expr::Sum::BuiltinLit(pb::BuiltinLit {
        sum: Some(pb::builtin_lit::Sum::TextInternedStr(idx)),
    }))
}

fn e_nil(ty: pb::Type) -> pb::Expr {
    e(pb::expr::Sum::Nil(pb::expr::Nil { r#type: Some(ty) }))
}

fn e_app(fun: pb::Expr, args: Vec<pb::Expr>) -> pb::Expr {
    e(pb::expr::Sum::App(Box::new(pb::expr::App {
        fun: Some(Box::new(fun)),
        args,
    })))
}

fn e_abs(p: &mut PkgBuilder, param: &str, ty: pb::Type, body: pb::Expr) -> pb::Expr {
    let vid = p.s(param);
    e(pb::expr::Sum::Abs(Box::new(pb::expr::Abs {
        param: vec![pb::VarWithType {
            var_interned_str: vid,
            r#type: Some(ty),
        }],
        body: Some(Box::new(body)),
    })))
}

fn e_var(p: &mut PkgBuilder, name: &str) -> pb::Expr {
    e(pb::expr::Sum::VarInternedStr(p.s(name)))
}

fn def_val(p: &mut PkgBuilder, name: &str, ty: pb::Type, expr: pb::Expr) -> pb::DefValue {
    pb::DefValue {
        location: None,
        name_with_type: Some(pb::def_value::NameWithType {
            name_interned_dname: p.dname(&[name]),
            r#type: Some(ty),
        }),
        expr: Some(expr),
    }
}

fn empty_mod(p: &mut PkgBuilder, name: &str) -> pb::Module {
    pb::Module {
        name_interned_dname: p.dname(&[name]),
        flags: Some(pb::FeatureFlags {
            forbid_party_literals: true,
            dont_divulge_contract_ids_in_create_arguments: true,
            dont_disclose_non_consuming_choices_to_observers: true,
        }),
        synonyms: Vec::new(),
        data_types: Vec::new(),
        values: Vec::new(),
        templates: Vec::new(),
        exceptions: Vec::new(),
        interfaces: Vec::new(),
    }
}

fn record_def(
    p: &mut PkgBuilder,
    name: &str,
    serializable: bool,
    params: Vec<(&str, pb::Kind)>,
    fields: Vec<(&str, pb::Type)>,
) -> pb::DefDataType {
    pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&[name]),
        params: params
            .into_iter()
            .map(|(n, k)| pb::TypeVarWithKind {
                var_interned_str: p.s(n),
                kind: Some(k),
            })
            .collect(),
        serializable,
        data_cons: Some(pb::def_data_type::DataCons::Record(
            pb::def_data_type::Fields {
                fields: fields
                    .into_iter()
                    .map(|(fn_s, ft)| pb::FieldWithType {
                        field_interned_str: p.s(fn_s),
                        r#type: Some(ft),
                    })
                    .collect(),
            },
        )),
    }
}

fn iface_datatype(p: &mut PkgBuilder, name: &str) -> pb::DefDataType {
    pb::DefDataType {
        location: None,
        name_interned_dname: p.dname(&[name]),
        params: Vec::new(),
        serializable: false,
        data_cons: Some(pb::def_data_type::DataCons::Interface(pb::Unit {})),
    }
}

fn write_dar(path: &Path, main_name: &str, main_bytes: &[u8], deps: &[(&str, &[u8])]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create validation oracle dir");
    }
    let file = File::create(path).expect("create dar file");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut dalf_list = vec![main_name.to_string()];
    for (n, _) in deps {
        dalf_list.push((*n).to_string());
    }
    let manifest = format!(
        "Manifest-Version: 1.0\nCreated-By: gen_validation_dars\nSdk-Version: 3.7.2\nMain-Dalf: {main_name}\nDalfs: {}\nFormat: daml-lf\nEncryption: non-encrypted\n",
        dalf_list.join(", ")
    );
    zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();
    zip.start_file(main_name, opts).unwrap();
    zip.write_all(main_bytes).unwrap();
    for (n, b) in deps {
        zip.start_file(*n, opts).unwrap();
        zip.write_all(b).unwrap();
    }
    zip.finish().unwrap();
}

struct CaseOut<'a> {
    dir: &'a Path,
    manifest: Vec<String>,
}

impl<'a> CaseOut<'a> {
    fn emit_pkg(
        &mut self,
        id: &str,
        mode: &str,
        valid: bool,
        p: PkgBuilder,
        deps: &[(&str, &[u8])],
    ) {
        let (pid, bytes) = p.build_dalf();
        let ext = if valid { "dar" } else { "invalid-dar" };
        let fname = format!("{id}.{ext}");
        write_dar(
            &self.dir.join(&fname),
            &format!("{id}-{pid}.dalf"),
            &bytes,
            deps,
        );
        self.manifest.push(format!("{id}\t{mode}\t{fname}"));
    }

    fn emit_existing(&mut self, id: &str, mode: &str, rel_path: &str) {
        self.manifest.push(format!("{id}\t{mode}\t{rel_path}"));
    }
}

fn minimal_valid_tpl(p: &mut PkgBuilder, tpl_name: &str) -> (pb::DefDataType, pb::DefTemplate) {
    let t_party = p.t_builtin(pb::BuiltinType::Party);
    let dt = record_def(
        p,
        tpl_name,
        true,
        Vec::new(),
        vec![("owner", t_party.clone())],
    );
    let dt_ty = p.t_con(None, &["Main"], &[tpl_name]);
    let owner_expr = e(pb::expr::Sum::RecProj(Box::new(pb::expr::RecProj {
        tycon: Some(pb::r#type::Con {
            tycon: Some(p.tycon_id(None, &["Main"], &[tpl_name])),
            args: Vec::new(),
        }),
        field_interned_str: p.s("owner"),
        record: Some(Box::new(e_var(p, "this"))),
    })));
    let parties_expr = e(pb::expr::Sum::Cons(Box::new(pb::expr::Cons {
        r#type: Some(t_party),
        front: vec![owner_expr],
        tail: Some(Box::new(e_nil(dt_ty))), // placeholder, overwritten below
    })));
    // Wait: Cons.tail must be `Nil Party`!
    let t_party2 = p.t_builtin(pb::BuiltinType::Party);
    let parties_expr = match parties_expr.sum {
        Some(pb::expr::Sum::Cons(mut c)) => {
            c.tail = Some(Box::new(e_nil(t_party2)));
            e(pb::expr::Sum::Cons(c))
        }
        _ => unreachable!(),
    };
    let t_party3 = p.t_builtin(pb::BuiltinType::Party);
    let tpl = pb::DefTemplate {
        location: None,
        tycon_interned_dname: p.dname(&[tpl_name]),
        param_interned_str: p.s("this"),
        precond: Some(e_bool(true)),
        signatories: Some(parties_expr),
        observers: Some(e_nil(t_party3)),
        choices: Vec::new(),
        key: None,
        implements: Vec::new(),
    };
    (dt, tpl)
}

fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/oracle/validation");
    fs::create_dir_all(&out_dir).unwrap();

    let mut out = CaseOut {
        dir: &out_dir,
        manifest: Vec::new(),
    };

    // External oracle DARs from U-1 and U-10
    out.emit_existing(
        "u1_valid_any_typerep_dev",
        "dev",
        "../any-typerep/any-typerep.dar",
    );
    out.emit_existing(
        "u10_valid_bignumeric_dev",
        "dev",
        "../lf-bignumeric-eval/lf-bignumeric-eval.dar",
    );
    out.emit_existing(
        "u1_bad_any_tvar_dev",
        "dev",
        "../any-typerep/bad-any-tvar-lf2dev.invalid-dar",
    );
    out.emit_existing(
        "u1_bad_complex_any_lf21",
        "default",
        "../any-typerep/bad-complex-any-lf21.invalid-dar",
    );
    out.emit_existing(
        "err_default_rejects_2dev",
        "default",
        "../any-typerep/any-typerep.dar",
    );

    // 1. Valid minimal
    {
        let mut p = PkgBuilder::new("val-ok-min", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        m.values.push(def_val(&mut p, "x", t_int, e_int(42)));
        p.modules.push(m);
        out.emit_pkg("ok_minimal", "default", true, p, &[]);
    }

    // 2. Valid collision exception: Variant constructor `Item` + Record `Item`
    {
        let mut p = PkgBuilder::new("val-ok-varcon-recdef", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let box_v = pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["Box"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Variant(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("Item"),
                        r#type: Some(t_int.clone()),
                    }],
                },
            )),
        };
        let item_r = record_def(&mut p, "Item", true, Vec::new(), vec![("v", t_int)]);
        m.data_types.push(box_v);
        m.data_types.push(item_r);
        p.modules.push(m);
        out.emit_pkg("ok_collision_varcon_recdef", "default", true, p, &[]);
    }

    // 3. Valid unserializable DefValue + non-serializable Record
    {
        let mut p = PkgBuilder::new("val-ok-unser-defval", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let t_fn = p.t_arrow(t_int.clone(), t_int.clone());
        let no_ser = record_def(
            &mut p,
            "NoSer",
            false,
            Vec::new(),
            vec![("fn", t_fn.clone())],
        );
        let x_ref = e_var(&mut p, "x");
        let id_fn = e_abs(&mut p, "x", t_int, x_ref);
        m.data_types.push(no_ser);
        m.values.push(def_val(&mut p, "idFn", t_fn, id_fn));
        p.modules.push(m);
        out.emit_pkg("ok_unserializable_defval", "default", true, p, &[]);
    }

    // 4. Valid closed transitive interface hierarchy + full template implementation
    {
        let mut p = PkgBuilder::new("val-ok-iface", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_unit = p.t_builtin(pb::BuiltinType::Unit);
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let view_r = record_def(
            &mut p,
            "ViewR",
            true,
            Vec::new(),
            vec![("n", t_int.clone())],
        );
        let view_ty = p.t_con(None, &["Main"], &["ViewR"]);
        let view_con = pb::r#type::Con {
            tycon: Some(p.tycon_id(None, &["Main"], &["ViewR"])),
            args: Vec::new(),
        };
        let view_expr = e(pb::expr::Sum::RecCon(pb::expr::RecCon {
            tycon: Some(view_con),
            fields: vec![pb::FieldWithExpr {
                field_interned_str: p.s("n"),
                expr: Some(e_int(1)),
            }],
        }));
        let i1_dt = iface_datatype(&mut p, "I1");
        let i2_dt = iface_datatype(&mut p, "I2");
        let i3_dt = iface_datatype(&mut p, "I3");
        let i1 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I1"]),
            param_interned_str: p.s("self"),
            requires: Vec::new(),
            methods: vec![pb::InterfaceMethod {
                location: None,
                method_interned_name: p.s("m1"),
                r#type: Some(t_int),
            }],
            choices: Vec::new(),
            view: Some(view_ty.clone()),
        };
        let i1_tc = p.tycon_id(None, &["Main"], &["I1"]);
        let i2_tc = p.tycon_id(None, &["Main"], &["I2"]);
        let i3_tc = p.tycon_id(None, &["Main"], &["I3"]);
        let i2 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I2"]),
            param_interned_str: p.s("self"),
            requires: vec![i1_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(view_ty.clone()),
        };
        let i3 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I3"]),
            param_interned_str: p.s("self"),
            requires: vec![i1_tc, i2_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(view_ty),
        };
        let (tpl_dt, mut tpl) = minimal_valid_tpl(&mut p, "T");
        let m1_name = p.s("m1");
        tpl.implements = vec![
            pb::def_template::Implements {
                interface: Some(i1_tc),
                body: Some(pb::InterfaceInstanceBody {
                    methods: vec![pb::interface_instance_body::InterfaceInstanceMethod {
                        method_interned_name: m1_name,
                        value: Some(e_int(7)),
                    }],
                    view: Some(view_expr.clone()),
                }),
                location: None,
            },
            pb::def_template::Implements {
                interface: Some(i2_tc),
                body: Some(pb::InterfaceInstanceBody {
                    methods: Vec::new(),
                    view: Some(view_expr.clone()),
                }),
                location: None,
            },
            pb::def_template::Implements {
                interface: Some(i3_tc),
                body: Some(pb::InterfaceInstanceBody {
                    methods: Vec::new(),
                    view: Some(view_expr),
                }),
                location: None,
            },
        ];
        m.values.push(def_val(&mut p, "u", t_unit, e_unit()));
        m.data_types.extend([view_r, i1_dt, i2_dt, i3_dt, tpl_dt]);
        m.interfaces.extend([i1, i2, i3]);
        m.templates.push(tpl);
        p.modules.push(m);
        out.emit_pkg("ok_interface_transitive_closed", "default", true, p, &[]);
    }

    // 5. Collision: module case collision
    {
        let mut p = PkgBuilder::new("val-err-mod-col", "1.0.0", "1");
        let m1 = empty_mod(&mut p, "Foo");
        let m2 = empty_mod(&mut p, "foo");
        p.modules.extend([m1, m2]);
        out.emit_pkg("err_collision_module_case", "default", false, p, &[]);
    }

    // 6. Collision: data type case collision
    {
        let mut p = PkgBuilder::new("val-err-type-col", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let d1 = record_def(
            &mut p,
            "MyRec",
            true,
            Vec::new(),
            vec![("a", t_int.clone())],
        );
        let d2 = record_def(&mut p, "myrec", true, Vec::new(), vec![("b", t_int)]);
        m.data_types.extend([d1, d2]);
        p.modules.push(m);
        out.emit_pkg("err_collision_type_case", "default", false, p, &[]);
    }

    // 7. Collision: record field case collision
    {
        let mut p = PkgBuilder::new("val-err-field-col", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let d1 = record_def(
            &mut p,
            "R",
            true,
            Vec::new(),
            vec![("foo", t_int.clone()), ("Foo", t_int)],
        );
        m.data_types.push(d1);
        p.modules.push(m);
        out.emit_pkg("err_collision_field_case", "default", false, p, &[]);
    }

    // 8a. Collision: variant constructors of DIFFERENT variants differing only in case (valid)
    {
        let mut p = PkgBuilder::new("val-ok-varcon-diff", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let v1 = pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["VA"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Variant(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("Ctor"),
                        r#type: Some(t_int.clone()),
                    }],
                },
            )),
        };
        let v2 = pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["VB"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Variant(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("ctor"),
                        r#type: Some(t_int),
                    }],
                },
            )),
        };
        m.data_types.extend([v1, v2]);
        p.modules.push(m);
        out.emit_pkg("ok_collision_variant_across_types", "default", true, p, &[]);
    }

    // 8b. Collision: variant constructor case collision within SAME variant
    {
        let mut p = PkgBuilder::new("val-err-varcon-same", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let v1 = pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["VA"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Variant(
                pb::def_data_type::Fields {
                    fields: vec![
                        pb::FieldWithType {
                            field_interned_str: p.s("Ctor"),
                            r#type: Some(t_int.clone()),
                        },
                        pb::FieldWithType {
                            field_interned_str: p.s("ctor"),
                            r#type: Some(t_int),
                        },
                    ],
                },
            )),
        };
        m.data_types.push(v1);
        p.modules.push(m);
        out.emit_pkg("err_collision_same_variant_case", "default", false, p, &[]);
    }

    // 9. Recursion: intra-package module import cycle A <-> B
    {
        let mut p = PkgBuilder::new("val-err-imp-cycle", "1.0.0", "1");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let mut ma = empty_mod(&mut p, "A");
        let vb_ref = p.e_val(None, &["B"], &["vb"]);
        ma.values.push(def_val(&mut p, "va", t_int.clone(), vb_ref));
        let mut mb = empty_mod(&mut p, "B");
        let va_ref = p.e_val(None, &["A"], &["va"]);
        mb.values.push(def_val(&mut p, "vb", t_int, va_ref));
        p.modules.extend([ma, mb]);
        out.emit_pkg("err_import_cycle", "default", false, p, &[]);
    }

    // 10. Recursion: type synonym cycle S1 <-> S2
    {
        let mut p = PkgBuilder::new("val-err-syn-cycle", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let s2_ty = p.t_syn(None, &["Main"], &["S2"]);
        let s1_ty = p.t_syn(None, &["Main"], &["S1"]);
        m.synonyms.push(pb::DefTypeSyn {
            location: None,
            name_interned_dname: p.dname(&["S1"]),
            params: Vec::new(),
            r#type: Some(s2_ty),
        });
        m.synonyms.push(pb::DefTypeSyn {
            location: None,
            name_interned_dname: p.dname(&["S2"]),
            params: Vec::new(),
            r#type: Some(s1_ty),
        });
        p.modules.push(m);
        out.emit_pkg("err_typesyn_cycle", "default", false, p, &[]);
    }

    // 11. DependencyVersion: 2.1 package depending on 2.3 package
    {
        let mut dep = PkgBuilder::new("dep-23", "1.0.0", "3");
        let mut dm = empty_mod(&mut dep, "Dep");
        let d_int = dep.t_builtin(pb::BuiltinType::Int64);
        dm.values.push(def_val(&mut dep, "val23", d_int, e_int(9)));
        dep.modules.push(dm);
        let (dep_id, dep_bytes) = dep.build_dalf();

        let mut p = PkgBuilder::new("main-21", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let m_int = p.t_builtin(pb::BuiltinType::Int64);
        let ref23 = p.e_val(Some(&dep_id), &["Dep"], &["val23"]);
        m.values.push(def_val(&mut p, "bad", m_int, ref23));
        p.modules.push(m);
        let dep_fname = format!("dep-23-{dep_id}.dalf");
        out.emit_pkg(
            "err_dep_version_21_on_23",
            "default",
            false,
            p,
            &[(&dep_fname, &dep_bytes)],
        );
    }

    // 12. Kind: ENatKindRightOfArrow (* -> Nat)
    {
        let mut p = PkgBuilder::new("val-err-nat-rhs", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let bad_kind = PkgBuilder::k_arrow(PkgBuilder::k_star(), PkgBuilder::k_nat());
        let dt = record_def(
            &mut p,
            "BadK",
            false,
            vec![("f", bad_kind)],
            vec![("x", t_int)],
        );
        m.data_types.push(dt);
        p.modules.push(m);
        out.emit_pkg("err_nat_kind_right_of_arrow", "default", false, p, &[]);
    }

    // 13. Kind: EKindMismatch (`List Numeric`)
    {
        let mut p = PkgBuilder::new("val-err-kind-mis", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_num_unapplied = p.t_builtin(pb::BuiltinType::Numeric);
        let bad_ty = p.t_list(t_num_unapplied);
        m.values
            .push(def_val(&mut p, "bad", bad_ty.clone(), e_nil(bad_ty)));
        p.modules.push(m);
        out.emit_pkg("err_kind_mismatch", "default", false, p, &[]);
    }

    // 14. Kind / Scope: EUnknownTypeVar
    {
        let mut p = PkgBuilder::new("val-err-unk-tvar", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_bad = p.t_var("ghost");
        m.values.push(def_val(&mut p, "bad", t_bad, e_unit()));
        p.modules.push(m);
        out.emit_pkg("err_unknown_type_var", "default", false, p, &[]);
    }

    // 15. Typing: DefValue body type mismatch (`Int64 = True`)
    {
        let mut p = PkgBuilder::new("val-err-ty-defval", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        m.values.push(def_val(&mut p, "bad", t_int, e_bool(true)));
        p.modules.push(m);
        out.emit_pkg("err_type_mismatch_defval", "default", false, p, &[]);
    }

    // 16. Typing: App argument type mismatch
    {
        let mut p = PkgBuilder::new("val-err-ty-app", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let x_ref = e_var(&mut p, "x");
        let f = e_abs(&mut p, "x", t_int.clone(), x_ref);
        m.values
            .push(def_val(&mut p, "bad", t_int, e_app(f, vec![e_bool(true)])));
        p.modules.push(m);
        out.emit_pkg("err_type_mismatch_app", "default", false, p, &[]);
    }

    // 17. Typing: Let binding type mismatch
    {
        let mut p = PkgBuilder::new("val-err-ty-let", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let expr = e(pb::expr::Sum::Let(Box::new(pb::Block {
            bindings: vec![pb::Binding {
                binder: Some(pb::VarWithType {
                    var_interned_str: p.s("x"),
                    r#type: Some(t_int.clone()),
                }),
                bound: Some(e_bool(false)),
            }],
            body: Some(Box::new(e_var(&mut p, "x"))),
        })));
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_type_mismatch_let", "default", false, p, &[]);
    }

    // 18. Typing: Case branch type mismatch
    {
        let mut p = PkgBuilder::new("val-err-case-branch", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let txt = e_text(&mut p, "oops");
        let expr = e(pb::expr::Sum::Case(Box::new(pb::Case {
            scrut: Some(Box::new(e_bool(true))),
            alts: vec![
                pb::CaseAlt {
                    sum: Some(pb::case_alt::Sum::BuiltinCon(
                        pb::BuiltinCon::ConTrue as i32,
                    )),
                    body: Some(e_int(1)),
                },
                pb::CaseAlt {
                    sum: Some(pb::case_alt::Sum::BuiltinCon(
                        pb::BuiltinCon::ConFalse as i32,
                    )),
                    body: Some(txt),
                },
            ],
        })));
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_type_mismatch_case_branch", "default", false, p, &[]);
    }

    // 19. Typing: EExpectedFunctionType (`1 2`)
    {
        let mut p = PkgBuilder::new("val-err-exp-fun", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        m.values.push(def_val(
            &mut p,
            "bad",
            t_int,
            e_app(e_int(1), vec![e_int(2)]),
        ));
        p.modules.push(m);
        out.emit_pkg("err_expected_function_type", "default", false, p, &[]);
    }

    // 20. Typing: EExpectedUniversalType (`TyApp(1, [Int64])`)
    {
        let mut p = PkgBuilder::new("val-err-exp-univ", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let expr = e(pb::expr::Sum::TyApp(Box::new(pb::expr::TyApp {
            expr: Some(Box::new(e_int(1))),
            types: vec![t_int.clone()],
        })));
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_expected_universal_type", "default", false, p, &[]);
    }

    // 21. Typing: EFieldMismatch (RecCon missing field `b`)
    {
        let mut p = PkgBuilder::new("val-err-field-mis", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let t_bool = p.t_builtin(pb::BuiltinType::Bool);
        let rec = record_def(
            &mut p,
            "R",
            true,
            Vec::new(),
            vec![("a", t_int), ("b", t_bool)],
        );
        let r_ty = p.t_con(None, &["Main"], &["R"]);
        let expr = e(pb::expr::Sum::RecCon(pb::expr::RecCon {
            tycon: Some(pb::r#type::Con {
                tycon: Some(p.tycon_id(None, &["Main"], &["R"])),
                args: Vec::new(),
            }),
            fields: vec![pb::FieldWithExpr {
                field_interned_str: p.s("a"),
                expr: Some(e_int(1)),
            }],
        }));
        m.data_types.push(rec);
        m.values.push(def_val(&mut p, "bad", r_ty, expr));
        p.modules.push(m);
        out.emit_pkg("err_field_mismatch_reccon", "default", false, p, &[]);
    }

    // 22. Typing: RecCon field type mismatch
    {
        let mut p = PkgBuilder::new("val-err-field-ty", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let rec = record_def(&mut p, "R", true, Vec::new(), vec![("a", t_int)]);
        let r_ty = p.t_con(None, &["Main"], &["R"]);
        let expr = e(pb::expr::Sum::RecCon(pb::expr::RecCon {
            tycon: Some(pb::r#type::Con {
                tycon: Some(p.tycon_id(None, &["Main"], &["R"])),
                args: Vec::new(),
            }),
            fields: vec![pb::FieldWithExpr {
                field_interned_str: p.s("a"),
                expr: Some(e_bool(true)),
            }],
        }));
        m.data_types.push(rec);
        m.values.push(def_val(&mut p, "bad", r_ty, expr));
        p.modules.push(m);
        out.emit_pkg("err_field_type_mismatch_reccon", "default", false, p, &[]);
    }

    // 23. Typing: EUnknownField in RecProj
    {
        let mut p = PkgBuilder::new("val-err-unk-field", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let rec = record_def(&mut p, "R", true, Vec::new(), vec![("a", t_int.clone())]);
        let r_con = e(pb::expr::Sum::RecCon(pb::expr::RecCon {
            tycon: Some(pb::r#type::Con {
                tycon: Some(p.tycon_id(None, &["Main"], &["R"])),
                args: Vec::new(),
            }),
            fields: vec![pb::FieldWithExpr {
                field_interned_str: p.s("a"),
                expr: Some(e_int(1)),
            }],
        }));
        let expr = e(pb::expr::Sum::RecProj(Box::new(pb::expr::RecProj {
            tycon: Some(pb::r#type::Con {
                tycon: Some(p.tycon_id(None, &["Main"], &["R"])),
                args: Vec::new(),
            }),
            field_interned_str: p.s("nope"),
            record: Some(Box::new(r_con)),
        })));
        m.data_types.push(rec);
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_unknown_field_recproj", "default", false, p, &[]);
    }

    // 24. Typing: EEmptyCase
    {
        let mut p = PkgBuilder::new("val-err-empty-case", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let expr = e(pb::expr::Sum::Case(Box::new(pb::Case {
            scrut: Some(Box::new(e_bool(true))),
            alts: Vec::new(),
        })));
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_empty_case", "default", false, p, &[]);
    }

    // 25. Typing: ENonExhaustivePatterns
    {
        let mut p = PkgBuilder::new("val-err-nonexh", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let expr = e(pb::expr::Sum::Case(Box::new(pb::Case {
            scrut: Some(Box::new(e_bool(true))),
            alts: vec![pb::CaseAlt {
                sum: Some(pb::case_alt::Sum::BuiltinCon(
                    pb::BuiltinCon::ConTrue as i32,
                )),
                body: Some(e_int(1)),
            }],
        })));
        m.values.push(def_val(&mut p, "bad", t_int, expr));
        p.modules.push(m);
        out.emit_pkg("err_non_exhaustive_patterns", "default", false, p, &[]);
    }

    // 26. Serializability: serializable record with arrow field
    {
        let mut p = PkgBuilder::new("val-err-ser-arrow", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let t_fn = p.t_arrow(t_int.clone(), t_int);
        m.data_types.push(record_def(
            &mut p,
            "BadSer",
            true,
            Vec::new(),
            vec![("f", t_fn)],
        ));
        p.modules.push(m);
        out.emit_pkg("err_non_serializable_arrow_field", "default", false, p, &[]);
    }

    // 27. Serializability: serializable record with Nat type parameter
    {
        let mut p = PkgBuilder::new("val-err-ser-natp", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        m.data_types.push(record_def(
            &mut p,
            "BadNat",
            true,
            vec![("n", PkgBuilder::k_nat())],
            vec![("x", t_int)],
        ));
        p.modules.push(m);
        out.emit_pkg("err_non_serializable_nat_param", "default", false, p, &[]);
    }

    // 28. Serializability: serializable record referencing non-serializable record
    {
        let mut p = PkgBuilder::new("val-err-ser-nested", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let inner = record_def(&mut p, "NotSer", false, Vec::new(), vec![("x", t_int)]);
        let inner_ty = p.t_con(None, &["Main"], &["NotSer"]);
        let outer = record_def(
            &mut p,
            "SerWrap",
            true,
            Vec::new(),
            vec![("inner", inner_ty)],
        );
        m.data_types.extend([inner, outer]);
        p.modules.push(m);
        out.emit_pkg(
            "err_non_serializable_nested_field",
            "default",
            false,
            p,
            &[],
        );
    }

    // 29. Template: DefTemplate on a Variant (not Record)
    {
        let mut p = PkgBuilder::new("val-err-tpl-var", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_party = p.t_builtin(pb::BuiltinType::Party);
        let t_var = pb::DefDataType {
            location: None,
            name_interned_dname: p.dname(&["BadTpl"]),
            params: Vec::new(),
            serializable: true,
            data_cons: Some(pb::def_data_type::DataCons::Variant(
                pb::def_data_type::Fields {
                    fields: vec![pb::FieldWithType {
                        field_interned_str: p.s("V"),
                        r#type: Some(t_party.clone()),
                    }],
                },
            )),
        };
        let tpl = pb::DefTemplate {
            location: None,
            tycon_interned_dname: p.dname(&["BadTpl"]),
            param_interned_str: p.s("this"),
            precond: Some(e_bool(true)),
            signatories: Some(e_nil(t_party.clone())),
            observers: Some(e_nil(t_party)),
            choices: Vec::new(),
            key: None,
            implements: Vec::new(),
        };
        m.data_types.push(t_var);
        m.templates.push(tpl);
        p.modules.push(m);
        out.emit_pkg("err_template_non_record", "default", false, p, &[]);
    }

    // 30. Template: wrong signatory type (`List Int64` instead of `List Party`)
    {
        let mut p = PkgBuilder::new("val-err-tpl-sig", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let (dt, mut tpl) = minimal_valid_tpl(&mut p, "BadSig");
        tpl.signatories = Some(e_nil(t_int));
        m.data_types.push(dt);
        m.templates.push(tpl);
        p.modules.push(m);
        out.emit_pkg(
            "err_template_wrong_signatory_type",
            "default",
            false,
            p,
            &[],
        );
    }

    // 31. Template: key with unserializable type (`Int64 -> Int64`, LF 2.3 for keys)
    {
        let mut p = PkgBuilder::new("val-err-tpl-key", "1.0.0", "3");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let t_fn = p.t_arrow(t_int.clone(), t_int.clone());
        let t_party = p.t_builtin(pb::BuiltinType::Party);
        let (dt, mut tpl) = minimal_valid_tpl(&mut p, "BadKey");
        let z_ref = e_var(&mut p, "z");
        let id_fn = e_abs(&mut p, "z", t_int, z_ref);
        let maint_fn = e_abs(&mut p, "k", t_fn.clone(), e_nil(t_party));
        tpl.key = Some(pb::def_template::DefKey {
            r#type: Some(t_fn),
            key_expr: Some(id_fn),
            maintainers: Some(maint_fn),
        });
        m.data_types.push(dt);
        m.templates.push(tpl);
        p.modules.push(m);
        out.emit_pkg(
            "err_template_key_non_serializable",
            "default",
            false,
            p,
            &[],
        );
    }

    // 32. Interface: circular `requires` (I1 requires I2, I2 requires I1)
    {
        let mut p = PkgBuilder::new("val-err-iface-cycle", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let vr = record_def(&mut p, "VR", true, Vec::new(), vec![("n", t_int)]);
        let v_ty = p.t_con(None, &["Main"], &["VR"]);
        let i1_dt = iface_datatype(&mut p, "I1");
        let i2_dt = iface_datatype(&mut p, "I2");
        let i1_tc = p.tycon_id(None, &["Main"], &["I1"]);
        let i2_tc = p.tycon_id(None, &["Main"], &["I2"]);
        let i1 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I1"]),
            param_interned_str: p.s("self"),
            requires: vec![i2_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(v_ty.clone()),
        };
        let i2 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I2"]),
            param_interned_str: p.s("self"),
            requires: vec![i1_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(v_ty),
        };
        m.data_types.extend([vr, i1_dt, i2_dt]);
        m.interfaces.extend([i1, i2]);
        p.modules.push(m);
        out.emit_pkg("err_interface_cycle", "default", false, p, &[]);
    }

    // 33. Interface: unclosed transitive `requires` (I3 -> I2 -> I1, I3 omits I1)
    {
        let mut p = PkgBuilder::new("val-err-iface-unclosed", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let vr = record_def(&mut p, "VR", true, Vec::new(), vec![("n", t_int)]);
        let v_ty = p.t_con(None, &["Main"], &["VR"]);
        let i1_dt = iface_datatype(&mut p, "I1");
        let i2_dt = iface_datatype(&mut p, "I2");
        let i3_dt = iface_datatype(&mut p, "I3");
        let i1_tc = p.tycon_id(None, &["Main"], &["I1"]);
        let i2_tc = p.tycon_id(None, &["Main"], &["I2"]);
        let i1 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I1"]),
            param_interned_str: p.s("self"),
            requires: Vec::new(),
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(v_ty.clone()),
        };
        let i2 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I2"]),
            param_interned_str: p.s("self"),
            requires: vec![i1_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(v_ty.clone()),
        };
        let i3 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I3"]),
            param_interned_str: p.s("self"),
            requires: vec![i2_tc],
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(v_ty),
        };
        m.data_types.extend([vr, i1_dt, i2_dt, i3_dt]);
        m.interfaces.extend([i1, i2, i3]);
        p.modules.push(m);
        out.emit_pkg("err_interface_unclosed_requires", "default", false, p, &[]);
    }

    // 34. Interface: non-record view type (`Int64`)
    {
        let mut p = PkgBuilder::new("val-err-iface-view", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let i1_dt = iface_datatype(&mut p, "IBad");
        let i1 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["IBad"]),
            param_interned_str: p.s("self"),
            requires: Vec::new(),
            methods: Vec::new(),
            choices: Vec::new(),
            view: Some(t_int),
        };
        m.data_types.push(i1_dt);
        m.interfaces.push(i1);
        p.modules.push(m);
        out.emit_pkg("err_interface_bad_view", "default", false, p, &[]);
    }

    // 35. Interface impl missing method in template
    {
        let mut p = PkgBuilder::new("val-err-iface-missing-m", "1.0.0", "1");
        let mut m = empty_mod(&mut p, "Main");
        let t_int = p.t_builtin(pb::BuiltinType::Int64);
        let vr = record_def(&mut p, "VR", true, Vec::new(), vec![("n", t_int.clone())]);
        let v_ty = p.t_con(None, &["Main"], &["VR"]);
        let view_expr = e(pb::expr::Sum::RecCon(pb::expr::RecCon {
            tycon: Some(pb::r#type::Con {
                tycon: Some(p.tycon_id(None, &["Main"], &["VR"])),
                args: Vec::new(),
            }),
            fields: vec![pb::FieldWithExpr {
                field_interned_str: p.s("n"),
                expr: Some(e_int(1)),
            }],
        }));
        let i1_dt = iface_datatype(&mut p, "I");
        let i1 = pb::DefInterface {
            location: None,
            tycon_interned_dname: p.dname(&["I"]),
            param_interned_str: p.s("self"),
            requires: Vec::new(),
            methods: vec![pb::InterfaceMethod {
                location: None,
                method_interned_name: p.s("needed"),
                r#type: Some(t_int),
            }],
            choices: Vec::new(),
            view: Some(v_ty),
        };
        let i1_tc = p.tycon_id(None, &["Main"], &["I"]);
        let (dt, mut tpl) = minimal_valid_tpl(&mut p, "T");
        tpl.implements = vec![pb::def_template::Implements {
            interface: Some(i1_tc),
            body: Some(pb::InterfaceInstanceBody {
                methods: Vec::new(),
                view: Some(view_expr),
            }),
            location: None,
        }];
        m.data_types.extend([vr, i1_dt, dt]);
        m.interfaces.push(i1);
        m.templates.push(tpl);
        p.modules.push(m);
        out.emit_pkg(
            "err_interface_impl_missing_method",
            "default",
            false,
            p,
            &[],
        );
    }

    fs::write(out_dir.join("manifest.tsv"), out.manifest.join("\n") + "\n").unwrap();
    println!(
        "Generated {} validation oracle entries in {}",
        out.manifest.len(),
        out_dir.display()
    );
}
