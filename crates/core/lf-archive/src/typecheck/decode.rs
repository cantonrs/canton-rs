//! Decoding of the archive's interned names, kinds, types and definitions into the checker's own forms.

use std::collections::BTreeMap;

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::def_data_type::DataCons;
use crate::proto::daml_lf_2::kind::Sum as KindSum;
use crate::proto::daml_lf_2::package::ImportsSum;
use crate::proto::daml_lf_2::r#type::Sum as TypeSum;
use crate::proto::daml_lf_2::self_or_imported_package_id::Sum as PkgRefSum;
use crate::proto::daml_lf_2::{BuiltinType, Package, Type};

use super::types::{Ident, LKind, LType};
use super::{TypeError, MAX_RESOLVE_DEPTH};

#[derive(Debug, Clone)]
pub(crate) enum DecodedDataCons {
    Record(Vec<(String, LType)>),
    Variant(Vec<(String, LType)>),
    Enum(Vec<String>),
    Interface,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedDataType {
    pub(crate) serializable: bool,
    pub(crate) params: Vec<(String, LKind)>,
    pub(crate) cons: DecodedDataCons,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedTypeSyn {
    pub(super) params: Vec<(String, LKind)>,
    pub(super) replacement: LType,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedValue {
    pub(super) typ: LType,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedChoice<'a> {
    pub(crate) name: String,
    pub(super) arg_name: String,
    pub(super) arg_type: LType,
    pub(crate) ret_type: LType,
    pub(super) self_name: String,
    pub(super) controllers: Option<&'a daml_lf_2::Expr>,
    pub(super) observers: Option<&'a daml_lf_2::Expr>,
    pub(super) authorizers: Option<&'a daml_lf_2::Expr>,
    pub(super) update: Option<&'a daml_lf_2::Expr>,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedKey<'a> {
    pub(super) typ: LType,
    pub(super) body: Option<&'a daml_lf_2::Expr>,
    pub(super) maintainers: Option<&'a daml_lf_2::Expr>,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedImplements<'a> {
    pub(super) iface: Ident,
    pub(super) view: Option<&'a daml_lf_2::Expr>,
    pub(super) methods: Vec<(String, Option<&'a daml_lf_2::Expr>)>,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedTemplate<'a> {
    pub(super) param: String,
    pub(super) precond: Option<&'a daml_lf_2::Expr>,
    pub(super) signatories: Option<&'a daml_lf_2::Expr>,
    pub(super) observers: Option<&'a daml_lf_2::Expr>,
    pub(super) choices: Vec<DecodedChoice<'a>>,
    pub(super) key: Option<DecodedKey<'a>>,
    pub(super) implements: Vec<DecodedImplements<'a>>,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedInterface<'a> {
    pub(super) requires: Vec<Ident>,
    pub(super) param: String,
    pub(super) view: LType,
    pub(super) methods: Vec<(String, LType)>,
    pub(super) choices: Vec<DecodedChoice<'a>>,
}

#[derive(Debug, Clone)]
pub(super) struct DecodedException<'a> {
    pub(super) message: Option<&'a daml_lf_2::Expr>,
}

pub(crate) fn err(pkg_id: &str, kind: &'static str, detail: impl Into<String>) -> TypeError {
    TypeError {
        kind,
        package_id: pkg_id.to_string(),
        detail: detail.into(),
    }
}

pub(crate) fn interned_str<'a>(
    pkg_id: &str,
    pkg: &'a Package,
    idx: i32,
    ctx: &str,
) -> Result<&'a str, TypeError> {
    usize::try_from(idx)
        .ok()
        .and_then(|i| pkg.interned_strings.get(i))
        .map(String::as_str)
        .ok_or_else(|| {
            err(
                pkg_id,
                "EUnknownDefinition",
                format!("invalid interned string index {idx} for {ctx}"),
            )
        })
}

pub(crate) fn dotted_segments<'a>(
    pkg_id: &str,
    pkg: &'a Package,
    idx: i32,
    ctx: &str,
) -> Result<Vec<&'a str>, TypeError> {
    let dn = usize::try_from(idx)
        .ok()
        .and_then(|i| pkg.interned_dotted_names.get(i))
        .ok_or_else(|| {
            err(
                pkg_id,
                "EUnknownDefinition",
                format!("invalid interned dotted-name index {idx} for {ctx}"),
            )
        })?;
    let mut parts = Vec::with_capacity(dn.segments_interned_str.len());
    for &s_idx in &dn.segments_interned_str {
        parts.push(interned_str(pkg_id, pkg, s_idx, ctx)?);
    }
    Ok(parts)
}

pub(crate) fn dotted_string(
    pkg_id: &str,
    pkg: &Package,
    idx: i32,
    ctx: &str,
) -> Result<String, TypeError> {
    Ok(dotted_segments(pkg_id, pkg, idx, ctx)?.join("."))
}

fn resolve_pkg_ref(
    pkg_id: &str,
    pkg: &Package,
    r: Option<&daml_lf_2::SelfOrImportedPackageId>,
) -> Result<String, TypeError> {
    match r.and_then(|p| p.sum.as_ref()) {
        Some(PkgRefSum::SelfPackageId(_)) => Ok(pkg_id.to_string()),
        Some(PkgRefSum::ImportedPackageIdInternedStr(idx)) => {
            Ok(interned_str(pkg_id, pkg, *idx, "ImportedPackageId")?.to_string())
        }
        Some(PkgRefSum::PackageImportId(idx)) => match &pkg.imports_sum {
            Some(ImportsSum::PackageImports(imports)) => usize::try_from(*idx)
                .ok()
                .and_then(|i| imports.imported_packages.get(i))
                .cloned()
                .ok_or_else(|| {
                    err(
                        pkg_id,
                        "EUnknownDefinition",
                        format!("package_import_id {idx} out of bounds"),
                    )
                }),
            _ => Err(err(
                pkg_id,
                "EUnknownDefinition",
                format!("package_import_id {idx} used without package_imports table"),
            )),
        },
        None => Err(err(
            pkg_id,
            "EUnknownDefinition",
            "missing package reference in identifier",
        )),
    }
}

fn resolve_module_ref(
    pkg_id: &str,
    pkg: &Package,
    m: Option<&daml_lf_2::ModuleId>,
) -> Result<(String, String), TypeError> {
    let m = m.ok_or_else(|| err(pkg_id, "EUnknownDefinition", "missing ModuleId"))?;
    let target_pkg = resolve_pkg_ref(pkg_id, pkg, m.package_id.as_ref())?;
    let mod_name = dotted_string(pkg_id, pkg, m.module_name_interned_dname, "ModuleId.name")?;
    Ok((target_pkg, mod_name))
}

pub(crate) fn resolve_type_con_id(
    pkg_id: &str,
    pkg: &Package,
    tc: Option<&daml_lf_2::TypeConId>,
) -> Result<Ident, TypeError> {
    let tc = tc.ok_or_else(|| err(pkg_id, "EUnknownDefinition", "missing TypeConId"))?;
    let (target_pkg, module) = resolve_module_ref(pkg_id, pkg, tc.module.as_ref())?;
    let name = dotted_string(pkg_id, pkg, tc.name_interned_dname, "TypeConId.name")?;
    Ok(Ident {
        pkg: target_pkg,
        module,
        name,
    })
}

fn resolve_type_syn_id(
    pkg_id: &str,
    pkg: &Package,
    ts: Option<&daml_lf_2::TypeSynId>,
) -> Result<Ident, TypeError> {
    let ts = ts.ok_or_else(|| err(pkg_id, "EUnknownDefinition", "missing TypeSynId"))?;
    let (target_pkg, module) = resolve_module_ref(pkg_id, pkg, ts.module.as_ref())?;
    let name = dotted_string(pkg_id, pkg, ts.name_interned_dname, "TypeSynId.name")?;
    Ok(Ident {
        pkg: target_pkg,
        module,
        name,
    })
}

pub(super) fn resolve_value_id(
    pkg_id: &str,
    pkg: &Package,
    vid: Option<&daml_lf_2::ValueId>,
) -> Result<Ident, TypeError> {
    let vid = vid.ok_or_else(|| err(pkg_id, "EUnknownDefinition", "missing ValueId"))?;
    let (target_pkg, module) = resolve_module_ref(pkg_id, pkg, vid.module.as_ref())?;
    let name = dotted_string(pkg_id, pkg, vid.name_interned_dname, "ValueId.name")?;
    Ok(Ident {
        pkg: target_pkg,
        module,
        name,
    })
}

pub(super) fn decode_kind(
    pkg_id: &str,
    pkg: &Package,
    kind: Option<&daml_lf_2::Kind>,
    depth: usize,
) -> Result<LKind, TypeError> {
    if depth > MAX_RESOLVE_DEPTH {
        return Err(err(pkg_id, "EKindMismatch", "kind nesting limit exceeded"));
    }
    let kind = kind.ok_or_else(|| err(pkg_id, "EKindMismatch", "missing Kind"))?;
    match &kind.sum {
        Some(KindSum::Star(_)) => Ok(LKind::Star),
        Some(KindSum::Nat(_)) => Ok(LKind::Nat),
        Some(KindSum::InternedKind(idx)) => {
            let target = usize::try_from(*idx)
                .ok()
                .and_then(|i| pkg.interned_kinds.get(i))
                .ok_or_else(|| {
                    err(
                        pkg_id,
                        "EUnknownDefinition",
                        format!("invalid interned kind index {idx}"),
                    )
                })?;
            decode_kind(pkg_id, pkg, Some(target), depth + 1)
        }
        Some(KindSum::Arrow(arr)) => {
            if arr.params.is_empty() {
                return Err(err(pkg_id, "EKindMismatch", "empty Kind::Arrow params"));
            }
            let mut acc = decode_kind(pkg_id, pkg, arr.result.as_deref(), depth + 1)?;
            for p in arr.params.iter().rev() {
                let pk = decode_kind(pkg_id, pkg, Some(p), depth + 1)?;
                acc = LKind::k_arrow(pk, acc);
            }
            Ok(acc)
        }
        None => Err(err(pkg_id, "EKindMismatch", "empty Kind sum")),
    }
}

pub(crate) fn decode_type(
    pkg_id: &str,
    pkg: &Package,
    ty: Option<&Type>,
    depth: usize,
) -> Result<LType, TypeError> {
    if depth > MAX_RESOLVE_DEPTH {
        return Err(err(pkg_id, "ETypeMismatch", "type nesting limit exceeded"));
    }
    let ty = ty.ok_or_else(|| err(pkg_id, "ETypeMismatch", "missing Type"))?;
    match &ty.sum {
        Some(TypeSum::InternedType(idx)) => {
            let target = usize::try_from(*idx)
                .ok()
                .and_then(|i| pkg.interned_types.get(i))
                .ok_or_else(|| {
                    err(
                        pkg_id,
                        "EUnknownDefinition",
                        format!("invalid interned type index {idx}"),
                    )
                })?;
            decode_type(pkg_id, pkg, Some(target), depth + 1)
        }
        Some(TypeSum::Var(v)) => {
            let name = interned_str(pkg_id, pkg, v.var_interned_str, "Type.Var")?.to_string();
            let mut acc = LType::Var(name);
            for arg in &v.args {
                let a = decode_type(pkg_id, pkg, Some(arg), depth + 1)?;
                acc = LType::app(acc, a);
            }
            Ok(acc)
        }
        Some(TypeSum::Nat(n)) => {
            if !(0..=37).contains(n) {
                return Err(err(
                    pkg_id,
                    "ETypeMismatch",
                    format!("TNat({n}) outside valid Numeric scale range 0..=37"),
                ));
            }
            Ok(LType::Nat(*n))
        }
        Some(TypeSum::Con(c)) => {
            let id = resolve_type_con_id(pkg_id, pkg, c.tycon.as_ref())?;
            let mut acc = LType::Con(id);
            for arg in &c.args {
                let a = decode_type(pkg_id, pkg, Some(arg), depth + 1)?;
                acc = LType::app(acc, a);
            }
            Ok(acc)
        }
        Some(TypeSum::Builtin(b)) => {
            let bt = BuiltinType::try_from(b.builtin).map_err(|_| {
                err(
                    pkg_id,
                    "EUnknownDefinition",
                    format!("unknown BuiltinType tag {}", b.builtin),
                )
            })?;
            let mut acc = LType::Builtin(bt);
            for arg in &b.args {
                let a = decode_type(pkg_id, pkg, Some(arg), depth + 1)?;
                acc = LType::app(acc, a);
            }
            Ok(acc)
        }
        Some(TypeSum::Tapp(tapp)) => {
            let lhs = decode_type(pkg_id, pkg, tapp.lhs.as_deref(), depth + 1)?;
            let rhs = decode_type(pkg_id, pkg, tapp.rhs.as_deref(), depth + 1)?;
            Ok(LType::app(lhs, rhs))
        }
        Some(TypeSum::Forall(fa)) => {
            let mut body = decode_type(pkg_id, pkg, fa.body.as_deref(), depth + 1)?;
            for tv in fa.vars.iter().rev() {
                let param =
                    interned_str(pkg_id, pkg, tv.var_interned_str, "Forall.var")?.to_string();
                let kind = decode_kind(pkg_id, pkg, tv.kind.as_ref(), depth + 1)?;
                body = LType::Forall {
                    param,
                    kind,
                    body: Box::new(body),
                };
            }
            Ok(body)
        }
        Some(TypeSum::Struct(st)) => {
            let mut fields = BTreeMap::new();
            for f in &st.fields {
                let fname =
                    interned_str(pkg_id, pkg, f.field_interned_str, "Struct.field")?.to_string();
                let ftype = decode_type(pkg_id, pkg, f.r#type.as_ref(), depth + 1)?;
                if fields.insert(fname.clone(), ftype).is_some() {
                    return Err(err(
                        pkg_id,
                        "EDuplicateField",
                        format!("duplicate struct field {fname}"),
                    ));
                }
            }
            Ok(LType::Struct(fields))
        }
        Some(TypeSum::Syn(syn)) => {
            let id = resolve_type_syn_id(pkg_id, pkg, syn.tysyn.as_ref())?;
            let mut args = Vec::with_capacity(syn.args.len());
            for a in &syn.args {
                args.push(decode_type(pkg_id, pkg, Some(a), depth + 1)?);
            }
            Ok(LType::SynApp { syn: id, args })
        }
        None => Err(err(pkg_id, "ETypeMismatch", "empty Type sum")),
    }
}

pub(super) fn decode_type_con_app(
    pkg_id: &str,
    pkg: &Package,
    con: Option<&daml_lf_2::r#type::Con>,
) -> Result<(Ident, Vec<LType>), TypeError> {
    let con = con.ok_or_else(|| err(pkg_id, "EUnknownDefinition", "missing Type.Con"))?;
    let id = resolve_type_con_id(pkg_id, pkg, con.tycon.as_ref())?;
    let mut args = Vec::with_capacity(con.args.len());
    for arg in &con.args {
        args.push(decode_type(pkg_id, pkg, Some(arg), 0)?);
    }
    Ok((id, args))
}

pub(crate) fn decode_type_params(
    pkg_id: &str,
    pkg: &Package,
    params: &[daml_lf_2::TypeVarWithKind],
) -> Result<Vec<(String, LKind)>, TypeError> {
    let mut out = Vec::with_capacity(params.len());
    for tv in params {
        let name = interned_str(pkg_id, pkg, tv.var_interned_str, "TypeVarWithKind")?.to_string();
        let kind = decode_kind(pkg_id, pkg, tv.kind.as_ref(), 0)?;
        out.push((name, kind));
    }
    Ok(out)
}

/// Decodes a data type definition into its name and signature.
pub(crate) fn decode_data_type(
    pkg_id: &str,
    pkg: &Package,
    mod_name: &str,
    def: &daml_lf_2::DefDataType,
) -> Result<(String, DecodedDataType), TypeError> {
    let name = dotted_string(pkg_id, pkg, def.name_interned_dname, "DefDataType.name")?;
    let params = decode_type_params(pkg_id, pkg, &def.params)?;
    let cons = match &def.data_cons {
        Some(DataCons::Record(r)) => {
            let mut fields = Vec::with_capacity(r.fields.len());
            for f in &r.fields {
                let fn_s =
                    interned_str(pkg_id, pkg, f.field_interned_str, "Record.field")?.to_string();
                let ft = decode_type(pkg_id, pkg, f.r#type.as_ref(), 0)?;
                fields.push((fn_s, ft));
            }
            DecodedDataCons::Record(fields)
        }
        Some(DataCons::Variant(v)) => {
            let mut vars = Vec::with_capacity(v.fields.len());
            for f in &v.fields {
                let vn =
                    interned_str(pkg_id, pkg, f.field_interned_str, "Variant.con")?.to_string();
                let vt = decode_type(pkg_id, pkg, f.r#type.as_ref(), 0)?;
                vars.push((vn, vt));
            }
            DecodedDataCons::Variant(vars)
        }
        Some(DataCons::Enum(e)) => {
            let mut cons = Vec::with_capacity(e.constructors_interned_str.len());
            for &c_idx in &e.constructors_interned_str {
                cons.push(interned_str(pkg_id, pkg, c_idx, "Enum.con")?.to_string());
            }
            DecodedDataCons::Enum(cons)
        }
        Some(DataCons::Interface(_)) => DecodedDataCons::Interface,
        None => {
            return Err(err(
                pkg_id,
                "EUnknownDefinition",
                format!("DefDataType {mod_name}:{name} missing DataCons"),
            ));
        }
    };
    Ok((
        name,
        DecodedDataType {
            serializable: def.serializable,
            params,
            cons,
        },
    ))
}

pub(crate) fn decode_choice<'a>(
    pkg_id: &str,
    pkg: &Package,
    ch: &'a daml_lf_2::TemplateChoice,
) -> Result<DecodedChoice<'a>, TypeError> {
    let name = interned_str(pkg_id, pkg, ch.name_interned_str, "TemplateChoice.name")?.to_string();
    let binder = ch.arg_binder.as_ref().ok_or_else(|| {
        err(
            pkg_id,
            "ETypeMismatch",
            format!("choice {name} missing arg_binder"),
        )
    })?;
    let arg_name =
        interned_str(pkg_id, pkg, binder.var_interned_str, "TemplateChoice.arg")?.to_string();
    let arg_type = decode_type(pkg_id, pkg, binder.r#type.as_ref(), 0)?;
    let ret_type = decode_type(pkg_id, pkg, ch.ret_type.as_ref(), 0)?;
    let self_name = interned_str(
        pkg_id,
        pkg,
        ch.self_binder_interned_str,
        "TemplateChoice.self",
    )?
    .to_string();
    Ok(DecodedChoice {
        name,
        arg_name,
        arg_type,
        ret_type,
        self_name,
        controllers: ch.controllers.as_ref(),
        observers: ch.observers.as_ref(),
        authorizers: ch.authorizers.as_ref(),
        update: ch.update.as_ref(),
    })
}
