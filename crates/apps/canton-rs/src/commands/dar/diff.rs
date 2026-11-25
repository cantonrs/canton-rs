//! Deterministic semantic DAR diff and upgrade verdict comparison (`canton-rs dar diff`, `S-DX-006`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use lf_archive::LoadedDar;
use serde::{Deserialize, Serialize};

use super::check_upgrade_refs;
use super::inspect::{
    inspect_loaded_dar, ChoiceInspection, InterfaceInspection, PackageInspection,
    TemplateInspection,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDiff {
    pub name: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeDiff {
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChoiceDiff {
    pub name: String,
    pub before: ChoiceInspection,
    pub after: ChoiceInspection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateDiff {
    pub template: String,
    pub fields_added: Vec<String>,
    pub fields_removed: Vec<String>,
    pub fields_changed: Vec<FieldDiff>,
    pub key_changed: Option<TypeDiff>,
    pub choices_added: Vec<String>,
    pub choices_removed: Vec<String>,
    pub choices_changed: Vec<ChoiceDiff>,
    pub implements_added: Vec<String>,
    pub implements_removed: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceDiff {
    pub interface: String,
    pub view_changed: Option<TypeDiff>,
    pub choices_added: Vec<String>,
    pub choices_removed: Vec<String>,
    pub choices_changed: Vec<ChoiceDiff>,
    pub requires_added: Vec<String>,
    pub requires_removed: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePairDiff {
    pub name: String,
    pub version_a: String,
    pub version_b: String,
    pub package_id_a: String,
    pub package_id_b: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub interfaces_added: Vec<String>,
    pub interfaces_removed: Vec<String>,
    pub interfaces_changed: Vec<String>,
    pub template_changes: Vec<TemplateDiff>,
    pub interface_changes: Vec<InterfaceDiff>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeVerdict {
    pub passed: bool,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DarDiffReport {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub interfaces_added: Vec<String>,
    pub interfaces_removed: Vec<String>,
    pub interfaces_changed: Vec<String>,
    pub template_changes: Vec<TemplateDiff>,
    pub interface_changes: Vec<InterfaceDiff>,
    pub packages: Vec<PackagePairDiff>,
    pub upgrade_check: UpgradeVerdict,
}

/// Computes `diff(a, b)` paired by package name and attaches `check-upgrade(a, b)`.
pub fn diff_loaded_dars(a: &LoadedDar, b: &LoadedDar) -> Result<DarDiffReport, String> {
    let ins_a = inspect_loaded_dar(a)?;
    let ins_b = inspect_loaded_dar(b)?;

    let by_name_a = group_packages_by_name(&ins_a.packages);
    let by_name_b = group_packages_by_name(&ins_b.packages);

    let mut added_all = BTreeSet::new();
    let mut removed_all = BTreeSet::new();
    let mut changed_all = BTreeSet::new();
    let mut iface_added_all = BTreeSet::new();
    let mut iface_removed_all = BTreeSet::new();
    let mut iface_changed_all = BTreeSet::new();
    let mut all_template_changes = Vec::new();
    let mut all_interface_changes = Vec::new();
    let mut packages = Vec::new();

    for (pkg_name, pa) in &by_name_a {
        let Some(pb) = by_name_b.get(pkg_name) else {
            continue;
        };
        if pa.package_id == pb.package_id {
            continue;
        }
        let pair = diff_package_pair(pkg_name, pa, pb);
        added_all.extend(pair.added.iter().cloned());
        removed_all.extend(pair.removed.iter().cloned());
        changed_all.extend(pair.changed.iter().cloned());
        iface_added_all.extend(pair.interfaces_added.iter().cloned());
        iface_removed_all.extend(pair.interfaces_removed.iter().cloned());
        iface_changed_all.extend(pair.interfaces_changed.iter().cloned());
        all_template_changes.extend(pair.template_changes.iter().cloned());
        all_interface_changes.extend(pair.interface_changes.iter().cloned());
        packages.push(pair);
    }

    let upgrade_check = match check_upgrade_refs(&[a, b]) {
        Ok(()) => UpgradeVerdict {
            passed: true,
            reasons: Vec::new(),
        },
        Err(msg) => UpgradeVerdict {
            passed: false,
            reasons: vec![msg],
        },
    };

    Ok(DarDiffReport {
        added: added_all.into_iter().collect(),
        removed: removed_all.into_iter().collect(),
        changed: changed_all.into_iter().collect(),
        interfaces_added: iface_added_all.into_iter().collect(),
        interfaces_removed: iface_removed_all.into_iter().collect(),
        interfaces_changed: iface_changed_all.into_iter().collect(),
        template_changes: all_template_changes,
        interface_changes: all_interface_changes,
        packages,
        upgrade_check,
    })
}

fn group_packages_by_name<'a>(
    pkgs: &'a [PackageInspection],
) -> BTreeMap<String, &'a PackageInspection> {
    let mut map: BTreeMap<String, &'a PackageInspection> = BTreeMap::new();
    for p in pkgs {
        if p.name.is_empty() {
            continue;
        }
        map.entry(p.name.clone())
            .and_modify(|existing| {
                if !existing.is_main && p.is_main {
                    *existing = p;
                }
            })
            .or_insert(p);
    }
    map
}

fn collect_templates(pkg: &PackageInspection) -> BTreeMap<String, &TemplateInspection> {
    let mut out = BTreeMap::new();
    for m in &pkg.modules {
        for t in &m.templates {
            out.insert(format!("{}:{}", m.name, t.name), t);
        }
    }
    out
}

fn collect_interfaces(pkg: &PackageInspection) -> BTreeMap<String, &InterfaceInspection> {
    let mut out = BTreeMap::new();
    for m in &pkg.modules {
        for i in &m.interfaces {
            out.insert(format!("{}:{}", m.name, i.name), i);
        }
    }
    out
}

fn diff_package_pair(
    name: &str,
    pa: &PackageInspection,
    pb: &PackageInspection,
) -> PackagePairDiff {
    let tmpl_a = collect_templates(pa);
    let tmpl_b = collect_templates(pb);

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut template_changes = Vec::new();

    for k in tmpl_b.keys() {
        if !tmpl_a.contains_key(k) {
            added.push(k.clone());
        }
    }
    for k in tmpl_a.keys() {
        if !tmpl_b.contains_key(k) {
            removed.push(k.clone());
        }
    }
    for (k, ta) in &tmpl_a {
        if let Some(tb) = tmpl_b.get(k) {
            if let Some(td) = compute_template_diff(k, ta, tb) {
                changed.push(k.clone());
                template_changes.push(td);
            }
        }
    }

    let iface_a = collect_interfaces(pa);
    let iface_b = collect_interfaces(pb);
    let mut interfaces_added = Vec::new();
    let mut interfaces_removed = Vec::new();
    let mut interfaces_changed = Vec::new();
    let mut interface_changes = Vec::new();

    for k in iface_b.keys() {
        if !iface_a.contains_key(k) {
            interfaces_added.push(k.clone());
        }
    }
    for k in iface_a.keys() {
        if !iface_b.contains_key(k) {
            interfaces_removed.push(k.clone());
        }
    }
    for (k, ia) in &iface_a {
        if let Some(ib) = iface_b.get(k) {
            if let Some(idiff) = compute_interface_diff(k, ia, ib) {
                interfaces_changed.push(k.clone());
                interface_changes.push(idiff);
            }
        }
    }

    PackagePairDiff {
        name: name.to_string(),
        version_a: pa.version.clone(),
        version_b: pb.version.clone(),
        package_id_a: pa.package_id.clone(),
        package_id_b: pb.package_id.clone(),
        added,
        removed,
        changed,
        interfaces_added,
        interfaces_removed,
        interfaces_changed,
        template_changes,
        interface_changes,
    }
}

fn diff_choice_lists(
    choices_a: &[ChoiceInspection],
    choices_b: &[ChoiceInspection],
) -> (Vec<String>, Vec<String>, Vec<ChoiceDiff>) {
    let map_a: BTreeMap<&str, &ChoiceInspection> =
        choices_a.iter().map(|c| (c.name.as_str(), c)).collect();
    let map_b: BTreeMap<&str, &ChoiceInspection> =
        choices_b.iter().map(|c| (c.name.as_str(), c)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for &k in map_b.keys() {
        if !map_a.contains_key(k) {
            added.push(k.to_string());
        }
    }
    for &k in map_a.keys() {
        if !map_b.contains_key(k) {
            removed.push(k.to_string());
        }
    }
    for (&k, &ca) in &map_a {
        if let Some(&cb) = map_b.get(k) {
            if ca != cb {
                changed.push(ChoiceDiff {
                    name: k.to_string(),
                    before: ca.clone(),
                    after: cb.clone(),
                });
            }
        }
    }
    (added, removed, changed)
}

fn compute_template_diff(
    name: &str,
    ta: &TemplateInspection,
    tb: &TemplateInspection,
) -> Option<TemplateDiff> {
    let fa: BTreeMap<&str, &str> = ta
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.field_type.as_str()))
        .collect();
    let fb: BTreeMap<&str, &str> = tb
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.field_type.as_str()))
        .collect();

    let fields_added: Vec<String> = fb
        .keys()
        .filter(|k| !fa.contains_key(*k))
        .map(|k| (*k).to_string())
        .collect();
    let fields_removed: Vec<String> = fa
        .keys()
        .filter(|k| !fb.contains_key(*k))
        .map(|k| (*k).to_string())
        .collect();
    let mut fields_changed = Vec::new();
    for (&k, &ty_a) in &fa {
        if let Some(&ty_b) = fb.get(k) {
            if ty_a != ty_b {
                fields_changed.push(FieldDiff {
                    name: k.to_string(),
                    before: ty_a.to_string(),
                    after: ty_b.to_string(),
                });
            }
        }
    }
    let field_order_changed = ta
        .fields
        .iter()
        .map(|f| (&f.name, &f.field_type))
        .ne(tb.fields.iter().map(|f| (&f.name, &f.field_type)));

    let key_changed = if ta.key_type != tb.key_type {
        Some(TypeDiff {
            before: ta.key_type.clone(),
            after: tb.key_type.clone(),
        })
    } else {
        None
    };

    let (choices_added, choices_removed, choices_changed) =
        diff_choice_lists(&ta.choices, &tb.choices);

    let impl_a: BTreeSet<&str> = ta.implements.iter().map(String::as_str).collect();
    let impl_b: BTreeSet<&str> = tb.implements.iter().map(String::as_str).collect();
    let implements_added: Vec<String> = impl_b
        .difference(&impl_a)
        .map(|s| (*s).to_string())
        .collect();
    let implements_removed: Vec<String> = impl_a
        .difference(&impl_b)
        .map(|s| (*s).to_string())
        .collect();

    let differs = !fields_added.is_empty()
        || !fields_removed.is_empty()
        || !fields_changed.is_empty()
        || field_order_changed
        || key_changed.is_some()
        || !choices_added.is_empty()
        || !choices_removed.is_empty()
        || !choices_changed.is_empty()
        || !implements_added.is_empty()
        || !implements_removed.is_empty();

    differs.then(|| TemplateDiff {
        template: name.to_string(),
        fields_added,
        fields_removed,
        fields_changed,
        key_changed,
        choices_added,
        choices_removed,
        choices_changed,
        implements_added,
        implements_removed,
    })
}

fn compute_interface_diff(
    name: &str,
    ia: &InterfaceInspection,
    ib: &InterfaceInspection,
) -> Option<InterfaceDiff> {
    let view_changed = if ia.view_type != ib.view_type {
        Some(TypeDiff {
            before: Some(ia.view_type.clone()),
            after: Some(ib.view_type.clone()),
        })
    } else {
        None
    };
    let (choices_added, choices_removed, choices_changed) =
        diff_choice_lists(&ia.choices, &ib.choices);
    let req_a: BTreeSet<&str> = ia.requires.iter().map(String::as_str).collect();
    let req_b: BTreeSet<&str> = ib.requires.iter().map(String::as_str).collect();
    let requires_added: Vec<String> = req_b.difference(&req_a).map(|s| (*s).to_string()).collect();
    let requires_removed: Vec<String> =
        req_a.difference(&req_b).map(|s| (*s).to_string()).collect();

    let differs = view_changed.is_some()
        || !choices_added.is_empty()
        || !choices_removed.is_empty()
        || !choices_changed.is_empty()
        || !requires_added.is_empty()
        || !requires_removed.is_empty();

    differs.then(|| InterfaceDiff {
        interface: name.to_string(),
        view_changed,
        choices_added,
        choices_removed,
        choices_changed,
        requires_added,
        requires_removed,
    })
}

/// Renders deterministic human-readable text output for `canton-rs dar diff`.
pub fn render_diff_text(report: &DarDiffReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Added templates ({}):", report.added.len());
    for t in &report.added {
        let _ = writeln!(out, "  + {t}");
    }
    let _ = writeln!(out, "Removed templates ({}):", report.removed.len());
    for t in &report.removed {
        let _ = writeln!(out, "  - {t}");
    }
    let _ = writeln!(out, "Changed templates ({}):", report.changed.len());
    for td in &report.template_changes {
        let _ = writeln!(out, "  ~ {}", td.template);
        for f in &td.fields_added {
            let _ = writeln!(out, "      + field {f}");
        }
        for f in &td.fields_removed {
            let _ = writeln!(out, "      - field {f}");
        }
        for fd in &td.fields_changed {
            let _ = writeln!(
                out,
                "      ~ field {}: {} -> {}",
                fd.name, fd.before, fd.after
            );
        }
        if let Some(kd) = &td.key_changed {
            let _ = writeln!(
                out,
                "      ~ key: {} -> {}",
                kd.before.as_deref().unwrap_or("<none>"),
                kd.after.as_deref().unwrap_or("<none>")
            );
        }
        for c in &td.choices_added {
            let _ = writeln!(out, "      + choice {c}");
        }
        for c in &td.choices_removed {
            let _ = writeln!(out, "      - choice {c}");
        }
        for cd in &td.choices_changed {
            let _ = writeln!(out, "      ~ choice {}", cd.name);
        }
        for imp in &td.implements_added {
            let _ = writeln!(out, "      + implements {imp}");
        }
        for imp in &td.implements_removed {
            let _ = writeln!(out, "      - implements {imp}");
        }
    }
    let _ = writeln!(
        out,
        "Interfaces: +{} -{} ~{}",
        report.interfaces_added.len(),
        report.interfaces_removed.len(),
        report.interfaces_changed.len()
    );
    if report.upgrade_check.passed {
        let _ = writeln!(out, "Upgrade check: PASS");
    } else {
        let _ = writeln!(out, "Upgrade check: FAIL");
        for r in &report.upgrade_check.reasons {
            let _ = writeln!(out, "  - {r}");
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::dar::inspect::load_dar_verified;
    use std::path::{Path, PathBuf};

    fn sdx006_fixture(dir: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/fixtures")
            .join(dir)
            .join("target/sdx006-pkg.dar")
    }

    #[test]
    fn r_a2_r_a3_r_a4_and_key_diff_hold_on_fixtures() {
        let v1 = load_dar_verified(&sdx006_fixture("sdx006-v1")).expect("v1");
        let v2 = load_dar_verified(&sdx006_fixture("sdx006-v2")).expect("v2");
        let v2_add = load_dar_verified(&sdx006_fixture("sdx006-v2-added")).expect("v2-added");
        let v3_drop = load_dar_verified(&sdx006_fixture("sdx006-v3-dropfield")).expect("v3-drop");
        let v4_key = load_dar_verified(&sdx006_fixture("sdx006-v4-keychange")).expect("v4-key");

        let refl = diff_loaded_dars(&v1, &v1).expect("refl");
        assert!(refl.added.is_empty());
        assert!(refl.removed.is_empty());
        assert!(refl.changed.is_empty());
        assert!(refl.upgrade_check.passed);

        let d12 = diff_loaded_dars(&v1, &v2).expect("d12");
        assert_eq!(d12.changed, vec!["Main:Vault"]);
        assert!(d12.upgrade_check.passed);
        assert_eq!(d12.template_changes[0].fields_added, vec!["note"]);

        let d1add = diff_loaded_dars(&v1, &v2_add).expect("d1add");
        let dadd1 = diff_loaded_dars(&v2_add, &v1).expect("dadd1");
        assert_eq!(d1add.added, dadd1.removed);
        assert_eq!(d1add.removed, dadd1.added);
        assert_eq!(d1add.changed, dadd1.changed);

        let ddrop = diff_loaded_dars(&v1, &v3_drop).expect("ddrop");
        assert_eq!(ddrop.changed, vec!["Main:Vault"]);
        assert!(!ddrop.upgrade_check.passed);
        assert_eq!(ddrop.template_changes[0].fields_removed, vec!["balance"]);

        let drem_tmpl = diff_loaded_dars(&v2_add, &v3_drop).expect("drem_tmpl");
        assert_eq!(drem_tmpl.removed, vec!["Main:Receipt"]);
        assert!(!drem_tmpl.upgrade_check.passed);

        let dkey = diff_loaded_dars(&v1, &v4_key).expect("dkey");
        assert_eq!(dkey.changed, vec!["Main:Vault"]);
        assert!(dkey.template_changes[0].key_changed.is_some());
        assert!(!dkey.upgrade_check.passed);
    }
}
