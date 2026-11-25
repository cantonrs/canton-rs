//! Deterministic Daml-LF 2 DAR package/template/interface inspection (`canton-rs dar inspect`, `S-DX-006`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use lf_archive::proto::daml_lf_2::{
    self, def_data_type::DataCons, package::ImportsSum, r#type::Sum as TypeSum,
    self_or_imported_package_id::Sum as PkgRefSum, BuiltinType, Package, Type,
};
use lf_archive::{
    referenced_package_ids, resolve_interned_dotted_name, resolve_interned_string, DarError,
    DecodeError, LoadedDar,
};
use serde::{Deserialize, Serialize};

use crate::commands::exit_code::{exit_with_message, EXIT_MISMATCH, EXIT_PREFLIGHT};

const MAX_TYPE_DEPTH: usize = 128;

/// Verified full inspection output of a `.dar` archive (`R-A1`, `R-A7`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DarInspection {
    pub main_package_id: String,
    pub main_package_name: Option<String>,
    pub main_package_version: Option<String>,
    pub packages: Vec<PackageInspection>,
    pub dependencies: Vec<DependencySummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencySummary {
    pub package_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub lf_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageInspection {
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub lf_version: String,
    pub is_main: bool,
    pub dependencies: Vec<String>,
    pub modules: Vec<ModuleInspection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInspection {
    pub name: String,
    pub templates: Vec<TemplateInspection>,
    pub interfaces: Vec<InterfaceInspection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldInspection {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChoiceInspection {
    pub name: String,
    pub arg_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arg_fields: Vec<FieldInspection>,
    pub ret_type: String,
    pub consuming: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateInspection {
    pub name: String,
    pub fields: Vec<FieldInspection>,
    pub key_type: Option<String>,
    pub choices: Vec<ChoiceInspection>,
    pub implements: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInspection {
    pub name: String,
    pub view_type: String,
    pub choices: Vec<ChoiceInspection>,
    pub requires: Vec<String>,
}

/// Loads a `.dar` archive while enforcing `R-A1` (`id(pkg) == sha256(payload(pkg))` -> `exit = 3` on mismatch).
pub fn load_dar_verified(path: &Path) -> Result<LoadedDar, String> {
    lf_archive::load_dar_file_allow_dev(path).map_err(|e| match e {
        DarError::Decode(DecodeError::PackageIdMismatch { .. }) => exit_with_message(
            EXIT_MISMATCH,
            format!("DAR package id hash mismatch in {}: {e}", path.display()),
        ),
        other => exit_with_message(
            EXIT_PREFLIGHT,
            format!("Error reading DAR from {}: {other}", path.display()),
        ),
    })
}

/// Inspects a loaded DAR deterministically (`BTreeMap`/`BTreeSet` sorted names across packages, modules, templates, choices, interfaces, and dependencies).
pub fn inspect_loaded_dar(dar: &LoadedDar) -> Result<DarInspection, String> {
    let mut pkg_names: BTreeMap<String, String> = BTreeMap::new();
    let mut pkg_versions: BTreeMap<String, String> = BTreeMap::new();
    for info in &dar.archive.dalfs {
        if let Some(name) = &info.package_name {
            pkg_names.insert(info.package_id.clone(), name.clone());
        }
        if let Some(ver) = &info.package_version {
            pkg_versions.insert(info.package_id.clone(), ver.clone());
        }
    }

    let mut packages = Vec::with_capacity(dar.packages.len());
    let mut external_deps: BTreeSet<String> = BTreeSet::new();

    for (pkg_id, pkg) in &dar.packages {
        let is_main = pkg_id == &dar.archive.main_package_id;
        let lf_version = dar
            .package_versions
            .get(pkg_id)
            .cloned()
            .unwrap_or_else(|| dar.archive.lf_version.clone());
        let name = pkg_names.get(pkg_id).cloned().unwrap_or_default();
        let version = pkg_versions.get(pkg_id).cloned().unwrap_or_default();
        let deps: Vec<String> = referenced_package_ids(pkg_id, pkg)
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for dep in &deps {
            if !dar.packages.contains_key(dep) {
                external_deps.insert(dep.clone());
            }
        }

        let modules = inspect_package_modules(pkg_id, pkg, &pkg_names)?;
        packages.push(PackageInspection {
            package_id: pkg_id.clone(),
            name,
            version,
            lf_version,
            is_main,
            dependencies: deps,
            modules,
        });
    }

    packages.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str(), a.package_id.as_str()).cmp(&(
            b.name.as_str(),
            b.version.as_str(),
            b.package_id.as_str(),
        ))
    });

    let mut dependencies: Vec<DependencySummary> = packages
        .iter()
        .filter(|p| !p.is_main)
        .map(|p| DependencySummary {
            package_id: p.package_id.clone(),
            name: (!p.name.is_empty()).then(|| p.name.clone()),
            version: (!p.version.is_empty()).then(|| p.version.clone()),
            lf_version: Some(p.lf_version.clone()),
        })
        .collect();
    for ext in external_deps {
        dependencies.push(DependencySummary {
            package_id: ext,
            name: None,
            version: None,
            lf_version: None,
        });
    }
    dependencies.sort_by(|a, b| {
        (
            a.name.as_deref().unwrap_or(""),
            a.version.as_deref().unwrap_or(""),
            a.package_id.as_str(),
        )
            .cmp(&(
                b.name.as_deref().unwrap_or(""),
                b.version.as_deref().unwrap_or(""),
                b.package_id.as_str(),
            ))
    });

    Ok(DarInspection {
        main_package_id: dar.archive.main_package_id.clone(),
        main_package_name: dar.archive.package_name.clone(),
        main_package_version: dar.archive.package_version.clone(),
        packages,
        dependencies,
    })
}

fn inspect_package_modules(
    pkg_id: &str,
    pkg: &Package,
    pkg_names: &BTreeMap<String, String>,
) -> Result<Vec<ModuleInspection>, String> {
    let mut modules_map: BTreeMap<String, ModuleInspection> = BTreeMap::new();

    for module in &pkg.modules {
        let mod_name = resolve_interned_dotted_name(pkg, module.name_interned_dname, "Module.name")
            .map_err(|e| format!("failed to decode module name in {pkg_id}: {e}"))?;

        let mut record_fields: BTreeMap<String, Vec<FieldInspection>> = BTreeMap::new();
        for dt in &module.data_types {
            let dt_name =
                resolve_interned_dotted_name(pkg, dt.name_interned_dname, "DefDataType.name")
                    .map_err(|e| format!("failed to decode data type in {pkg_id}: {e}"))?;
            if let Some(DataCons::Record(rec)) = &dt.data_cons {
                let mut fields = Vec::with_capacity(rec.fields.len());
                for f in &rec.fields {
                    let fname =
                        resolve_interned_string(pkg, f.field_interned_str, "FieldWithType.field")
                            .map_err(|e| format!("failed to decode field name in {pkg_id}: {e}"))?;
                    let ftype = format_type_opt(pkg_id, pkg, f.r#type.as_ref(), pkg_names, 0)?;
                    fields.push(FieldInspection {
                        name: fname,
                        field_type: ftype,
                    });
                }
                record_fields.insert(dt_name, fields);
            }
        }

        let mut templates = Vec::with_capacity(module.templates.len());
        for tmpl in &module.templates {
            let tname =
                resolve_interned_dotted_name(pkg, tmpl.tycon_interned_dname, "DefTemplate.tycon")
                    .map_err(|e| format!("failed to decode template name in {pkg_id}: {e}"))?;
            let fields = record_fields.get(&tname).cloned().unwrap_or_default();
            let key_type = match &tmpl.key {
                Some(k) => Some(format_type_opt(
                    pkg_id,
                    pkg,
                    k.r#type.as_ref(),
                    pkg_names,
                    0,
                )?),
                None => None,
            };

            let mut choices = Vec::with_capacity(tmpl.choices.len());
            for ch in &tmpl.choices {
                choices.push(inspect_choice(
                    pkg_id,
                    pkg,
                    ch,
                    &mod_name,
                    &record_fields,
                    pkg_names,
                )?);
            }
            choices.sort_by(|a, b| a.name.cmp(&b.name));

            let mut implements_set = BTreeSet::new();
            for imp in &tmpl.implements {
                if let Some(tc) = &imp.interface {
                    implements_set.insert(format_type_con_id(pkg_id, pkg, tc, pkg_names)?);
                }
            }
            let implements: Vec<String> = implements_set.into_iter().collect();

            templates.push(TemplateInspection {
                name: tname,
                fields,
                key_type,
                choices,
                implements,
            });
        }
        templates.sort_by(|a, b| a.name.cmp(&b.name));

        let mut interfaces = Vec::with_capacity(module.interfaces.len());
        for iface in &module.interfaces {
            let iname =
                resolve_interned_dotted_name(pkg, iface.tycon_interned_dname, "DefInterface.tycon")
                    .map_err(|e| format!("failed to decode interface name in {pkg_id}: {e}"))?;
            let view_type = format_type_opt(pkg_id, pkg, iface.view.as_ref(), pkg_names, 0)?;

            let mut choices = Vec::with_capacity(iface.choices.len());
            for ch in &iface.choices {
                choices.push(inspect_choice(
                    pkg_id,
                    pkg,
                    ch,
                    &mod_name,
                    &record_fields,
                    pkg_names,
                )?);
            }
            choices.sort_by(|a, b| a.name.cmp(&b.name));

            let mut requires_set = BTreeSet::new();
            for req in &iface.requires {
                requires_set.insert(format_type_con_id(pkg_id, pkg, req, pkg_names)?);
            }
            let requires: Vec<String> = requires_set.into_iter().collect();

            interfaces.push(InterfaceInspection {
                name: iname,
                view_type,
                choices,
                requires,
            });
        }
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        modules_map.insert(
            mod_name.clone(),
            ModuleInspection {
                name: mod_name,
                templates,
                interfaces,
            },
        );
    }

    Ok(modules_map.into_values().collect())
}

fn inspect_choice(
    pkg_id: &str,
    pkg: &Package,
    ch: &daml_lf_2::TemplateChoice,
    mod_name: &str,
    record_fields: &BTreeMap<String, Vec<FieldInspection>>,
    pkg_names: &BTreeMap<String, String>,
) -> Result<ChoiceInspection, String> {
    let name = resolve_interned_string(pkg, ch.name_interned_str, "TemplateChoice.name")
        .map_err(|e| format!("failed to decode choice name in {pkg_id}: {e}"))?;
    let arg_ty = ch.arg_binder.as_ref().and_then(|b| b.r#type.as_ref());
    let arg_type = format_type_opt(pkg_id, pkg, arg_ty, pkg_names, 0)?;
    let arg_fields = arg_type
        .strip_prefix(&format!("{mod_name}:"))
        .and_then(|local_name| record_fields.get(local_name))
        .cloned()
        .unwrap_or_default();
    let ret_type = format_type_opt(pkg_id, pkg, ch.ret_type.as_ref(), pkg_names, 0)?;
    Ok(ChoiceInspection {
        name,
        arg_type,
        arg_fields,
        ret_type,
        consuming: ch.consuming,
    })
}

fn resolve_pkg_ref(
    pkg_id: &str,
    pkg: &Package,
    r: Option<&daml_lf_2::SelfOrImportedPackageId>,
) -> Result<String, String> {
    match r.and_then(|p| p.sum.as_ref()) {
        Some(PkgRefSum::SelfPackageId(_)) => Ok(pkg_id.to_string()),
        Some(PkgRefSum::ImportedPackageIdInternedStr(idx)) => {
            resolve_interned_string(pkg, *idx, "ImportedPackageId")
                .map_err(|e| format!("failed to resolve imported pkg id in {pkg_id}: {e}"))
        }
        Some(PkgRefSum::PackageImportId(idx)) => match &pkg.imports_sum {
            Some(ImportsSum::PackageImports(imports)) => usize::try_from(*idx)
                .ok()
                .and_then(|i| imports.imported_packages.get(i))
                .cloned()
                .ok_or_else(|| format!("package_import_id {idx} out of bounds in {pkg_id}")),
            _ => Err(format!(
                "package_import_id {idx} used without imports table in {pkg_id}"
            )),
        },
        None => Err(format!("missing package ref in {pkg_id}")),
    }
}

fn format_qualified(
    self_pkg_id: &str,
    target_pkg: &str,
    mod_name: &str,
    name: &str,
    pkg_names: &BTreeMap<String, String>,
) -> String {
    if target_pkg == self_pkg_id {
        format!("{mod_name}:{name}")
    } else if let Some(pkg_name) = pkg_names.get(target_pkg) {
        format!("{pkg_name}:{mod_name}:{name}")
    } else {
        format!("{target_pkg}:{mod_name}:{name}")
    }
}

fn format_type_con_id(
    self_pkg_id: &str,
    pkg: &Package,
    tc: &daml_lf_2::TypeConId,
    pkg_names: &BTreeMap<String, String>,
) -> Result<String, String> {
    let m = tc
        .module
        .as_ref()
        .ok_or_else(|| format!("missing ModuleId in TypeConId of {self_pkg_id}"))?;
    let target_pkg = resolve_pkg_ref(self_pkg_id, pkg, m.package_id.as_ref())?;
    let mod_name = resolve_interned_dotted_name(pkg, m.module_name_interned_dname, "ModuleId.name")
        .map_err(|e| format!("failed to decode module id in {self_pkg_id}: {e}"))?;
    let name = resolve_interned_dotted_name(pkg, tc.name_interned_dname, "TypeConId.name")
        .map_err(|e| format!("failed to decode type constructor name in {self_pkg_id}: {e}"))?;
    Ok(format_qualified(
        self_pkg_id,
        &target_pkg,
        &mod_name,
        &name,
        pkg_names,
    ))
}

fn format_type_opt(
    self_pkg_id: &str,
    pkg: &Package,
    ty: Option<&Type>,
    pkg_names: &BTreeMap<String, String>,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_TYPE_DEPTH {
        return Err(format!("type nesting limit exceeded in {self_pkg_id}"));
    }
    let Some(ty) = ty else {
        return Ok("<unknown>".to_string());
    };
    match &ty.sum {
        Some(TypeSum::InternedType(idx)) => {
            let target = usize::try_from(*idx)
                .ok()
                .and_then(|i| pkg.interned_types.get(i))
                .ok_or_else(|| format!("invalid interned type index {idx} in {self_pkg_id}"))?;
            format_type_opt(self_pkg_id, pkg, Some(target), pkg_names, depth + 1)
        }
        Some(TypeSum::Var(v)) => {
            let base = resolve_interned_string(pkg, v.var_interned_str, "Type.Var")
                .map_err(|e| format!("failed to decode Type.Var in {self_pkg_id}: {e}"))?;
            format_applied(&base, &v.args, self_pkg_id, pkg, pkg_names, depth)
        }
        Some(TypeSum::Nat(n)) => Ok(n.to_string()),
        Some(TypeSum::Con(c)) => {
            let base = match &c.tycon {
                Some(tc) => format_type_con_id(self_pkg_id, pkg, tc, pkg_names)?,
                None => "<unknown>".to_string(),
            };
            format_applied(&base, &c.args, self_pkg_id, pkg, pkg_names, depth)
        }
        Some(TypeSum::Builtin(b)) => {
            format_builtin(b.builtin, &b.args, self_pkg_id, pkg, pkg_names, depth)
        }
        Some(TypeSum::Tapp(tapp)) => {
            let lhs = format_type_opt(self_pkg_id, pkg, tapp.lhs.as_deref(), pkg_names, depth + 1)?;
            let rhs = format_type_opt(self_pkg_id, pkg, tapp.rhs.as_deref(), pkg_names, depth + 1)?;
            Ok(format!("({lhs} {rhs})"))
        }
        Some(TypeSum::Forall(fa)) => {
            let body = format_type_opt(self_pkg_id, pkg, fa.body.as_deref(), pkg_names, depth + 1)?;
            let mut vars = Vec::with_capacity(fa.vars.len());
            for v in &fa.vars {
                vars.push(
                    resolve_interned_string(pkg, v.var_interned_str, "Forall.var").map_err(
                        |e| format!("failed to decode Forall var in {self_pkg_id}: {e}"),
                    )?,
                );
            }
            if vars.is_empty() {
                Ok(body)
            } else {
                Ok(format!("forall {}. {body}", vars.join(" ")))
            }
        }
        Some(TypeSum::Struct(st)) => {
            let mut parts = Vec::with_capacity(st.fields.len());
            for f in &st.fields {
                let fname = resolve_interned_string(pkg, f.field_interned_str, "Struct.field")
                    .map_err(|e| format!("failed to decode struct field in {self_pkg_id}: {e}"))?;
                let ftype =
                    format_type_opt(self_pkg_id, pkg, f.r#type.as_ref(), pkg_names, depth + 1)?;
                parts.push(format!("{fname}: {ftype}"));
            }
            Ok(format!("{{ {} }}", parts.join(", ")))
        }
        Some(TypeSum::Syn(syn)) => {
            let base = if let Some(ts) = &syn.tysyn {
                let m = ts
                    .module
                    .as_ref()
                    .ok_or_else(|| format!("missing ModuleId in TypeSynId of {self_pkg_id}"))?;
                let target_pkg = resolve_pkg_ref(self_pkg_id, pkg, m.package_id.as_ref())?;
                let mod_name = resolve_interned_dotted_name(
                    pkg,
                    m.module_name_interned_dname,
                    "TypeSynId.mod",
                )
                .map_err(|e| format!("failed to decode TypeSynId module in {self_pkg_id}: {e}"))?;
                let name =
                    resolve_interned_dotted_name(pkg, ts.name_interned_dname, "TypeSynId.name")
                        .map_err(|e| {
                            format!("failed to decode TypeSynId name in {self_pkg_id}: {e}")
                        })?;
                format_qualified(self_pkg_id, &target_pkg, &mod_name, &name, pkg_names)
            } else {
                "<syn>".to_string()
            };
            format_applied(&base, &syn.args, self_pkg_id, pkg, pkg_names, depth)
        }
        None => Ok("<empty>".to_string()),
    }
}

fn format_applied(
    base: &str,
    args: &[Type],
    self_pkg_id: &str,
    pkg: &Package,
    pkg_names: &BTreeMap<String, String>,
    depth: usize,
) -> Result<String, String> {
    if args.is_empty() {
        return Ok(base.to_string());
    }
    let mut rendered = Vec::with_capacity(args.len());
    for a in args {
        rendered.push(format_type_opt(
            self_pkg_id,
            pkg,
            Some(a),
            pkg_names,
            depth + 1,
        )?);
    }
    Ok(format!("{base}({})", rendered.join(", ")))
}

fn format_builtin(
    code: i32,
    args: &[Type],
    self_pkg_id: &str,
    pkg: &Package,
    pkg_names: &BTreeMap<String, String>,
    depth: usize,
) -> Result<String, String> {
    let mut rendered = Vec::with_capacity(args.len());
    for a in args {
        rendered.push(format_type_opt(
            self_pkg_id,
            pkg,
            Some(a),
            pkg_names,
            depth + 1,
        )?);
    }
    let Ok(bt) = BuiltinType::try_from(code) else {
        return Ok(format!("Builtin({code})"));
    };
    let name = match bt {
        BuiltinType::Int64 => "Int64",
        BuiltinType::Numeric => {
            return Ok(match rendered.as_slice() {
                [scale] => format!("Numeric({scale})"),
                _ => "Numeric".to_string(),
            });
        }
        BuiltinType::Text => "Text",
        BuiltinType::Timestamp => "Timestamp",
        BuiltinType::Party => "Party",
        BuiltinType::Unit => "Unit",
        BuiltinType::Bool => "Bool",
        BuiltinType::Date => "Date",
        BuiltinType::Any => "Any",
        BuiltinType::TypeRep => "TypeRep",
        BuiltinType::AnyException => "AnyException",
        BuiltinType::RoundingMode => "RoundingMode",
        BuiltinType::Bignumeric => "BigNumeric",
        BuiltinType::FailureCategory => "FailureCategory",
        BuiltinType::List => "List",
        BuiltinType::Optional => "Optional",
        BuiltinType::Update => "Update",
        BuiltinType::ContractId => "ContractId",
        BuiltinType::Textmap => "TextMap",
        BuiltinType::Genmap => "GenMap",
        BuiltinType::Arrow => {
            return Ok(match rendered.as_slice() {
                [from, to] => format!("({from} -> {to})"),
                _ => "Arrow".to_string(),
            });
        }
    };
    if rendered.is_empty() {
        Ok(name.to_string())
    } else {
        Ok(format!("{name}({})", rendered.join(", ")))
    }
}

/// Renders deterministic human-readable text output for `canton-rs dar inspect`.
pub fn render_inspect_text(ins: &DarInspection) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Main Package: {}", ins.main_package_id);
    if let Some(name) = &ins.main_package_name {
        let ver = ins.main_package_version.as_deref().unwrap_or("");
        let _ = writeln!(out, "Main Name/Ver: {name} v{ver}");
    }
    let _ = writeln!(out, "Packages ({}):", ins.packages.len());
    for pkg in &ins.packages {
        let _ = writeln!(
            out,
            "  - {} ({} v{}, LF {}, main={})",
            pkg.package_id, pkg.name, pkg.version, pkg.lf_version, pkg.is_main
        );
        for m in &pkg.modules {
            let _ = writeln!(out, "    Module {}:", m.name);
            for t in &m.templates {
                let key_str = t.key_type.as_deref().unwrap_or("<none>");
                let impl_str = if t.implements.is_empty() {
                    "<none>".to_string()
                } else {
                    t.implements.join(", ")
                };
                let _ = writeln!(
                    out,
                    "      template {} (key={}, implements=[{}])",
                    t.name, key_str, impl_str
                );
                for f in &t.fields {
                    let _ = writeln!(out, "        field {}: {}", f.name, f.field_type);
                }
                for c in &t.choices {
                    let kind = if c.consuming {
                        "consuming"
                    } else {
                        "nonconsuming"
                    };
                    let _ = writeln!(
                        out,
                        "        choice {} ({kind}) arg={} -> {}",
                        c.name, c.arg_type, c.ret_type
                    );
                }
            }
            for i in &m.interfaces {
                let _ = writeln!(
                    out,
                    "      interface {} (view={}, requires=[{}])",
                    i.name,
                    i.view_type,
                    i.requires.join(", ")
                );
                for c in &i.choices {
                    let kind = if c.consuming {
                        "consuming"
                    } else {
                        "nonconsuming"
                    };
                    let _ = writeln!(
                        out,
                        "        choice {} ({kind}) arg={} -> {}",
                        c.name, c.arg_type, c.ret_type
                    );
                }
            }
        }
    }
    let _ = writeln!(out, "Dependencies ({}):", ins.dependencies.len());
    for dep in &ins.dependencies {
        let name = dep.name.as_deref().unwrap_or("<external>");
        let ver = dep.version.as_deref().unwrap_or("?");
        let lf = dep.lf_version.as_deref().unwrap_or("?");
        let _ = writeln!(out, "  - {} ({name} v{ver}, LF {lf})", dep.package_id);
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::exit_code::decode_exit;
    use std::io::Write as _;

    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            }
        }
        !crc
    }

    fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for &(name, data) in entries {
            let offset = out.len() as u32;
            let crc = crc32_ieee(data);
            let len = data.len() as u32;
            let nb = name.as_bytes();
            let nlen = nb.len() as u16;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(nb);
            out.extend_from_slice(data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&nlen.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(nb);
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        let count = entries.len() as u16;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn r_a1_tampered_dalf_hash_exits_3() {
        use lf_archive::proto::daml_lf::{Archive, HashFunction};
        use prost::Message as _;

        let archive = Archive {
            hash_function: HashFunction::Sha256 as i32,
            hash: "00".repeat(32),
            payload: b"tampered-payload".to_vec(),
        };
        let dalf = archive.encode_to_vec();
        let manifest =
            b"Manifest-Version: 1.0\nMain-Dalf: main.dalf\nDalfs: main.dalf\nFormat: daml-lf\n";
        let zip = build_stored_zip(&[("META-INF/MANIFEST.MF", manifest), ("main.dalf", &dalf)]);

        let path = std::env::temp_dir().join(format!("sdx006-tamper-{}.dar", std::process::id()));
        let mut f = std::fs::File::create(&path).expect("create temp dar");
        f.write_all(&zip).expect("write zip");
        drop(f);

        let err = load_dar_verified(&path)
            .err()
            .expect("must reject hash mismatch");
        let _ = std::fs::remove_file(&path);
        assert_eq!(decode_exit(&err).0, EXIT_MISMATCH, "err={err}");
    }

    #[test]
    fn r_a7_inspect_sample_contract_is_deterministic_and_sorted() {
        let dar_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let loaded = load_dar_verified(&dar_path).expect("load sample-contract");
        let first = inspect_loaded_dar(&loaded).expect("inspect 1");
        let second = inspect_loaded_dar(&loaded).expect("inspect 2");
        assert_eq!(
            serde_json::to_string_pretty(&first).expect("json 1"),
            serde_json::to_string_pretty(&second).expect("json 2")
        );
        assert_eq!(render_inspect_text(&first), render_inspect_text(&second));
    }
}
