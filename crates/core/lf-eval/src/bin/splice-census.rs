//! `splice-census <dar>...`: which Daml-LF forms do the packages of the given DARs use, and does `lf-eval` evaluate them?
//!
//! For every package of every DAR the decoded `Package` is rendered with `Debug` into a streaming scanner that counts
//! every oneof variant (`sum: Some(<Variant>(`). Packages named `splice-*` are counted separately from the rest
//! (stdlib, prim, ...). The output is a TSV: kind, name, uses in splice packages, uses elsewhere, supported by lf-eval.
//! The counts are over everything the packages define (not only what a given choice reaches), so they bound what an
//! execution can meet.
//!
//! `splice-census --any-types <dar>...` instead classifies the type written on every `ToAny`, `FromAny`, and `TypeRep`
//! (U-1). A nullary type constructor is `Type.Con` with an empty argument list after interned types are expanded.
//! Anything else (an applied constructor, a builtin such as `list` or `numeric`, a type variable, a synonym, `TApp`)
//! is reported with a sketch, because that is the case the JVM differential cannot compile.
use std::collections::{BTreeMap, BTreeSet};
use std::{env, fmt::Write as _, process::ExitCode};

use lf_archive::proto::daml_lf_2::{self, expr, BuiltinFunction, Expr, Package, Type};
use lf_archive::{
    resolve_interned_dotted_name, resolve_interned_string, resolve_single_module_name,
};
use lf_eval::{builtin_supported, SUPPORTED_EXPR_FORMS, SUPPORTED_UPDATE_FORMS};

const UPDATE_FORMS: &[&str] = &[
    "Pure",
    "Block",
    "Create",
    "Exercise",
    "ExerciseByKey",
    "Fetch",
    "GetTime",
    "QueryNByKey",
    "FetchByKey",
    "EmbedExpr",
    "TryCatch",
    "CreateInterface",
    "ExerciseInterface",
    "FetchInterface",
    "LedgerTimeLt",
    "UnpackTemplate",
    "UnpackInterface",
];
const EXPR_FORMS: &[&str] = &[
    "VarInternedStr",
    "Val",
    "Builtin",
    "BuiltinCon",
    "BuiltinLit",
    "RecCon",
    "RecProj",
    "RecUpd",
    "VariantCon",
    "EnumCon",
    "StructCon",
    "StructProj",
    "StructUpd",
    "App",
    "TyApp",
    "Abs",
    "TyAbs",
    "Case",
    "Let",
    "Nil",
    "Cons",
    "Update",
    "OptionalNone",
    "OptionalSome",
    "ToAny",
    "FromAny",
    "TypeRep",
    "ToAnyException",
    "FromAnyException",
    "Throw",
    "ToInterface",
    "FromInterface",
    "CallInterface",
    "SignatoryInterface",
    "ObserverInterface",
    "ViewInterface",
    "UnsafeFromInterface",
    "InterfaceTemplateTypeRep",
    "ToRequiredInterface",
    "FromRequiredInterface",
    "UnsafeFromRequiredInterface",
    "InternedExpr",
    "ChoiceController",
    "ChoiceObserver",
    "Experimental",
];
const LITERALS: &[&str] = &[
    "Int64",
    "TextInternedStr",
    "NumericInternedStr",
    "FailureCategory",
    "TimestampMicros",
    "DateDays",
    "RoundingMode",
    "BigNumericInternedStr",
    "Party",
];

/// Counts `sum: Some(<Ident>(` (and the enumeration name for `Builtin(<Name>)`) in a stream of `Debug` output.
#[derive(Default)]
struct Scanner {
    buf: String,
    counts: BTreeMap<String, u64>,
}

impl std::fmt::Write for Scanner {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.buf.push_str(s);
        let mut start = 0;
        let mut keep_from = None;
        while let Some(i) = self.buf[start..].find("sum: Some(") {
            let at = start + i;
            let j = at + "sum: Some(".len();
            let rest = &self.buf[j..];
            let Some(e) = rest.find(|c: char| !(c.is_alphanumeric() || c == '_')) else {
                keep_from = Some(at);
                break;
            };
            let name = rest[..e].to_string();
            let after = &rest[e..];
            let mut key = name.clone();
            if (name == "Builtin" || name == "BuiltinCon") && after.starts_with('(') {
                let inner = &after[1..];
                match inner.find(|c: char| !(c.is_alphanumeric() || c == '_')) {
                    None => {
                        keep_from = Some(at);
                        break;
                    }
                    Some(k) if inner[k..].starts_with(')') && k > 0 => {
                        key = format!("{name}:{}", &inner[..k])
                    }
                    Some(_) => {}
                }
            }
            *self.counts.entry(key).or_default() += 1;
            start = j + e;
        }
        let from = keep_from.unwrap_or_else(|| self.buf.len().saturating_sub(96).max(start));
        let mut from = from.min(self.buf.len());
        while !self.buf.is_char_boundary(from) {
            from -= 1;
        }
        self.buf.drain(..from);
        Ok(())
    }
}

fn main() -> ExitCode {
    let raw: Vec<String> = env::args().skip(1).collect();
    let any_types = raw.iter().any(|a| a == "--any-types");
    let dars: Vec<String> = raw.into_iter().filter(|a| a != "--any-types").collect();
    if dars.is_empty() {
        eprintln!("usage: splice-census [--any-types] <dar>...");
        return ExitCode::from(2);
    }
    if any_types {
        return any_type_census(&dars);
    }
    let builtin_codes: BTreeMap<String, i32> = (0..4000)
        .filter_map(|n| {
            BuiltinFunction::try_from(n)
                .ok()
                .map(|b| (format!("{b:?}"), n))
        })
        .collect();
    let (mut splice, mut other): (BTreeMap<String, u64>, BTreeMap<String, u64>) =
        Default::default();
    let mut seen = std::collections::BTreeSet::new();
    for dar in &dars {
        let loaded = match lf_archive::load_dar_file(dar) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error: {dar}: {e}");
                return ExitCode::from(1);
            }
        };
        for info in &loaded.archive.dalfs {
            // a package shared by several DARs is counted once
            if !seen.insert(info.package_id.clone()) {
                continue;
            }
            let Some(package) = loaded.packages.get(&info.package_id) else {
                continue;
            };
            let mut scanner = Scanner::default();
            write!(scanner, "{package:?}").expect("scan");
            let is_splice = info
                .package_name
                .as_deref()
                .is_some_and(|n| n.starts_with("splice-"));
            for (k, v) in scanner.counts {
                *(if is_splice { &mut splice } else { &mut other })
                    .entry(k)
                    .or_default() += v;
            }
        }
    }
    println!("kind\tname\tsplice_uses\tother_uses\tsupported");
    let names: std::collections::BTreeSet<&String> = splice.keys().chain(other.keys()).collect();
    for name in names {
        let (kind, supported) = if let Some(b) = name.strip_prefix("Builtin:") {
            let ok = builtin_codes.get(b).is_some_and(|c| builtin_supported(*c));
            ("builtin", ok.to_string())
        } else if name.starts_with("BuiltinCon:") {
            ("builtin_con", "n/a".to_string())
        } else if UPDATE_FORMS.contains(&name.as_str()) {
            (
                "update",
                SUPPORTED_UPDATE_FORMS.contains(&name.as_str()).to_string(),
            )
        } else if EXPR_FORMS.contains(&name.as_str()) {
            (
                "expr",
                SUPPORTED_EXPR_FORMS.contains(&name.as_str()).to_string(),
            )
        } else if LITERALS.contains(&name.as_str()) {
            ("literal", "n/a".to_string())
        } else {
            ("other", "n/a".to_string())
        };
        println!(
            "{kind}\t{name}\t{}\t{}\t{supported}",
            splice.get(name).unwrap_or(&0),
            other.get(name).unwrap_or(&0)
        );
    }
    ExitCode::SUCCESS
}

/// One loaded package, named the way `splice-census` splits splice from the rest.
struct PkgRef<'a> {
    id: String,
    name: String,
    splice: bool,
    package: &'a Package,
}

fn any_type_census(dars: &[String]) -> ExitCode {
    let mut loaded = Vec::new();
    for dar in dars {
        match lf_archive::load_dar_file(dar) {
            Ok(archive) => loaded.push(archive),
            Err(err) => {
                eprintln!("Error: {dar}: {err}");
                return ExitCode::from(1);
            }
        }
    }
    let mut refs: Vec<PkgRef<'_>> = Vec::new();
    let mut seen = BTreeSet::new();
    for archive in &loaded {
        for info in &archive.archive.dalfs {
            if !seen.insert(info.package_id.clone()) {
                continue;
            }
            let Some(package) = archive.packages.get(&info.package_id) else {
                continue;
            };
            let name = info
                .package_name
                .clone()
                .unwrap_or_else(|| info.package_id.chars().take(8).collect());
            refs.push(PkgRef {
                id: info.package_id.clone(),
                splice: name.starts_with("splice-"),
                name,
                package,
            });
        }
    }

    // (scope, form, class) and, for everything that is not a nullary constructor, the sketch.
    let mut totals: BTreeMap<(String, &'static str, String), u64> = BTreeMap::new();
    let mut sketches: BTreeMap<(String, &'static str, String, String), u64> = BTreeMap::new();
    let mut con0_names: BTreeSet<String> = BTreeSet::new();
    for pkg_index in 0..refs.len() {
        let scope = if refs[pkg_index].splice {
            "splice"
        } else {
            "other"
        };
        let mut roots: Vec<&Expr> = Vec::new();
        roots.extend(refs[pkg_index].package.interned_exprs.iter());
        for module in &refs[pkg_index].package.modules {
            for value in &module.values {
                push_plain(&mut roots, &value.expr);
            }
            for template in &module.templates {
                push_plain(&mut roots, &template.precond);
                push_plain(&mut roots, &template.signatories);
                push_plain(&mut roots, &template.observers);
                if let Some(key) = &template.key {
                    push_plain(&mut roots, &key.key_expr);
                    push_plain(&mut roots, &key.maintainers);
                }
                for choice in &template.choices {
                    push_choice(&mut roots, choice);
                }
                for instance in &template.implements {
                    let Some(body) = &instance.body else {
                        continue;
                    };
                    push_plain(&mut roots, &body.view);
                    for method in &body.methods {
                        push_plain(&mut roots, &method.value);
                    }
                }
            }
            for exception in &module.exceptions {
                push_plain(&mut roots, &exception.message);
            }
            for interface in &module.interfaces {
                for choice in &interface.choices {
                    push_choice(&mut roots, choice);
                }
            }
        }
        let mut stack = roots;
        while let Some(expr) = stack.pop() {
            if let Some((form, ty)) = any_form(expr) {
                let (class, sketch) = classify(&refs, pkg_index, ty);
                *totals
                    .entry((scope.to_string(), form, class.clone()))
                    .or_default() += 1;
                if class == "con0" {
                    con0_names.insert(sketch);
                } else {
                    let row = format!("{} :: {sketch}", refs[pkg_index].name);
                    *sketches
                        .entry((scope.to_string(), form, class, clip(row)))
                        .or_default() += 1;
                }
            }
            stack.extend(child_exprs(expr));
        }
    }

    println!("scope\tform\tclass\tuses");
    for ((scope, form, class), uses) in &totals {
        println!("{scope}\t{form}\t{class}\t{uses}");
    }
    println!("scope\tform\tclass\tuses\tsketch");
    for ((scope, form, class, sketch), uses) in &sketches {
        println!("{scope}\t{form}\t{class}\t{uses}\t{sketch}");
    }
    for scope in ["splice", "other"] {
        let mut nullary = 0u64;
        let mut rest = 0u64;
        for ((row_scope, _, class), uses) in &totals {
            if row_scope != scope {
                continue;
            }
            if class == "con0" {
                nullary += uses;
            } else {
                rest += uses;
            }
        }
        println!("# {scope} nullary_tycon={nullary} not_nullary={rest}");
    }
    println!("# distinct_con0 {}", con0_names.len());
    ExitCode::SUCCESS
}

fn push_choice<'a>(out: &mut Vec<&'a Expr>, choice: &'a daml_lf_2::TemplateChoice) {
    push_plain(out, &choice.controllers);
    push_plain(out, &choice.observers);
    push_plain(out, &choice.update);
    push_plain(out, &choice.authorizers);
}

fn push_box<'a>(out: &mut Vec<&'a Expr>, expr: &'a Option<Box<Expr>>) {
    if let Some(expr) = expr {
        out.push(expr);
    }
}

fn push_plain<'a>(out: &mut Vec<&'a Expr>, expr: &'a Option<Expr>) {
    if let Some(expr) = expr {
        out.push(expr);
    }
}

/// `ToAny` / `FromAny` / `TypeRep`, and the type written on that node.
fn any_form(expr: &Expr) -> Option<(&'static str, Option<&Type>)> {
    match expr.sum.as_ref()? {
        expr::Sum::ToAny(node) => Some(("ToAny", node.r#type.as_ref())),
        expr::Sum::FromAny(node) => Some(("FromAny", node.r#type.as_ref())),
        expr::Sum::TypeRep(ty) => Some(("TypeRep", Some(ty))),
        _ => None,
    }
}

/// Child expressions, not following `InternedExpr`: each interned expression is already a root.
fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    let mut out = Vec::new();
    let Some(sum) = expr.sum.as_ref() else {
        return out;
    };
    match sum {
        expr::Sum::VarInternedStr(_)
        | expr::Sum::Val(_)
        | expr::Sum::Builtin(_)
        | expr::Sum::BuiltinCon(_)
        | expr::Sum::BuiltinLit(_)
        | expr::Sum::EnumCon(_)
        | expr::Sum::Nil(_)
        | expr::Sum::OptionalNone(_)
        | expr::Sum::TypeRep(_)
        | expr::Sum::InternedExpr(_)
        | expr::Sum::Experimental(_) => {}
        expr::Sum::RecCon(node) => {
            for field in &node.fields {
                push_plain(&mut out, &field.expr);
            }
        }
        expr::Sum::RecProj(node) => push_box(&mut out, &node.record),
        expr::Sum::RecUpd(node) => {
            push_box(&mut out, &node.record);
            push_box(&mut out, &node.update);
        }
        expr::Sum::VariantCon(node) => push_box(&mut out, &node.variant_arg),
        expr::Sum::StructCon(node) => {
            for field in &node.fields {
                push_plain(&mut out, &field.expr);
            }
        }
        expr::Sum::StructProj(node) => push_box(&mut out, &node.r#struct),
        expr::Sum::StructUpd(node) => {
            push_box(&mut out, &node.r#struct);
            push_box(&mut out, &node.update);
        }
        expr::Sum::App(node) => {
            push_box(&mut out, &node.fun);
            out.extend(node.args.iter());
        }
        expr::Sum::TyApp(node) => push_box(&mut out, &node.expr),
        expr::Sum::Abs(node) => push_box(&mut out, &node.body),
        expr::Sum::TyAbs(node) => push_box(&mut out, &node.body),
        expr::Sum::Case(node) => {
            push_box(&mut out, &node.scrut);
            for alt in &node.alts {
                push_plain(&mut out, &alt.body);
            }
        }
        expr::Sum::Let(node) => {
            for binding in &node.bindings {
                push_plain(&mut out, &binding.bound);
            }
            push_box(&mut out, &node.body);
        }
        expr::Sum::Cons(node) => {
            out.extend(node.front.iter());
            push_box(&mut out, &node.tail);
        }
        expr::Sum::Update(node) => child_update(&mut out, node),
        expr::Sum::OptionalSome(node) => push_box(&mut out, &node.value),
        expr::Sum::ToAny(node) => push_box(&mut out, &node.expr),
        expr::Sum::FromAny(node) => push_box(&mut out, &node.expr),
        expr::Sum::ToAnyException(node) => push_box(&mut out, &node.expr),
        expr::Sum::FromAnyException(node) => push_box(&mut out, &node.expr),
        expr::Sum::Throw(node) => push_box(&mut out, &node.exception_expr),
        expr::Sum::ToInterface(node) => push_box(&mut out, &node.template_expr),
        expr::Sum::FromInterface(node) => push_box(&mut out, &node.interface_expr),
        expr::Sum::CallInterface(node) => push_box(&mut out, &node.interface_expr),
        expr::Sum::SignatoryInterface(node) => push_box(&mut out, &node.expr),
        expr::Sum::ObserverInterface(node) => push_box(&mut out, &node.expr),
        expr::Sum::ViewInterface(node) => push_box(&mut out, &node.expr),
        expr::Sum::UnsafeFromInterface(node) => {
            push_box(&mut out, &node.contract_id_expr);
            push_box(&mut out, &node.interface_expr);
        }
        expr::Sum::InterfaceTemplateTypeRep(node) => push_box(&mut out, &node.expr),
        expr::Sum::ToRequiredInterface(node) => push_box(&mut out, &node.expr),
        expr::Sum::FromRequiredInterface(node) => push_box(&mut out, &node.expr),
        expr::Sum::UnsafeFromRequiredInterface(node) => {
            push_box(&mut out, &node.contract_id_expr);
            push_box(&mut out, &node.interface_expr);
        }
        expr::Sum::ChoiceController(node) => {
            push_box(&mut out, &node.contract_expr);
            push_box(&mut out, &node.choice_arg_expr);
        }
        expr::Sum::ChoiceObserver(node) => {
            push_box(&mut out, &node.contract_expr);
            push_box(&mut out, &node.choice_arg_expr);
        }
    }
    out
}

fn child_update<'a>(out: &mut Vec<&'a Expr>, update: &'a daml_lf_2::Update) {
    let Some(sum) = update.sum.as_ref() else {
        return;
    };
    match sum {
        daml_lf_2::update::Sum::Pure(node) => push_box(out, &node.expr),
        daml_lf_2::update::Sum::Block(node) => {
            for binding in &node.bindings {
                push_plain(out, &binding.bound);
            }
            push_box(out, &node.body);
        }
        daml_lf_2::update::Sum::Create(node) => push_box(out, &node.expr),
        daml_lf_2::update::Sum::Exercise(node) => {
            push_box(out, &node.cid);
            push_box(out, &node.arg);
        }
        daml_lf_2::update::Sum::ExerciseByKey(node) => {
            push_box(out, &node.key);
            push_box(out, &node.arg);
        }
        daml_lf_2::update::Sum::Fetch(node) => push_box(out, &node.cid),
        daml_lf_2::update::Sum::GetTime(_)
        | daml_lf_2::update::Sum::QueryNByKey(_)
        | daml_lf_2::update::Sum::FetchByKey(_) => {}
        daml_lf_2::update::Sum::EmbedExpr(node) => push_box(out, &node.body),
        daml_lf_2::update::Sum::TryCatch(node) => {
            push_box(out, &node.try_expr);
            push_box(out, &node.catch_expr);
        }
        daml_lf_2::update::Sum::CreateInterface(node) => push_box(out, &node.expr),
        daml_lf_2::update::Sum::ExerciseInterface(node) => {
            push_box(out, &node.cid);
            push_box(out, &node.arg);
            push_box(out, &node.guard);
        }
        daml_lf_2::update::Sum::FetchInterface(node) => push_box(out, &node.cid),
        daml_lf_2::update::Sum::LedgerTimeLt(node) => out.push(node),
        daml_lf_2::update::Sum::UnpackTemplate(node) => push_box(out, &node.cid),
        daml_lf_2::update::Sum::UnpackInterface(node) => push_box(out, &node.cid),
    }
}

/// Class of the type written on the node, after interned types are expanded.
/// `con0` is a type constructor applied to no arguments. `con0_unsat` is that shape whose definition
/// still has type parameters. Every other class is a type this census was opened to find.
fn classify(refs: &[PkgRef<'_>], pkg_index: usize, ty: Option<&Type>) -> (String, String) {
    let Some(ty) = ty else {
        return ("missing".to_string(), "-".to_string());
    };
    let mut current = ty;
    let package = refs[pkg_index].package;
    for _ in 0..64 {
        let Some(daml_lf_2::r#type::Sum::InternedType(index)) = current.sum.as_ref() else {
            break;
        };
        let Some(next) = usize::try_from(*index)
            .ok()
            .and_then(|i| package.interned_types.get(i))
        else {
            return ("missing".to_string(), format!("interned:{index}"));
        };
        current = next;
    }
    match current.sum.as_ref() {
        Some(daml_lf_2::r#type::Sum::Con(con)) => {
            let qname = con
                .tycon
                .as_ref()
                .and_then(|id| qualified(refs, pkg_index, id))
                .unwrap_or_else(|| "?".to_string());
            let args = con
                .args
                .iter()
                .map(|arg| sketch(refs, pkg_index, arg, 0))
                .collect::<Vec<_>>();
            if args.is_empty() {
                let params = con
                    .tycon
                    .as_ref()
                    .and_then(|id| defined_params(refs, pkg_index, id));
                match params {
                    Some(0) => ("con0".to_string(), qname),
                    None => ("con0_unknown".to_string(), qname),
                    Some(n) => ("con0_unsat".to_string(), format!("{qname} !params={n}")),
                }
            } else {
                ("conN".to_string(), format!("{qname}<{}>", args.join(",")))
            }
        }
        Some(daml_lf_2::r#type::Sum::Builtin(builtin)) => {
            let name = builtin_name(builtin.builtin);
            if builtin.args.is_empty() {
                ("builtin0".to_string(), name)
            } else {
                let args = builtin
                    .args
                    .iter()
                    .map(|arg| sketch(refs, pkg_index, arg, 0))
                    .collect::<Vec<_>>();
                (
                    "builtinN".to_string(),
                    format!("{name}<{}>", args.join(",")),
                )
            }
        }
        Some(daml_lf_2::r#type::Sum::Var(var)) => {
            let name = resolve_interned_string(package, var.var_interned_str, "Type.var")
                .map(|n| format!("${n}"))
                .unwrap_or_else(|_| "?var".to_string());
            if var.args.is_empty() {
                ("var".to_string(), name)
            } else {
                let args = var
                    .args
                    .iter()
                    .map(|arg| sketch(refs, pkg_index, arg, 0))
                    .collect::<Vec<_>>();
                ("varN".to_string(), format!("{name}<{}>", args.join(",")))
            }
        }
        Some(daml_lf_2::r#type::Sum::Syn(syn)) => {
            let name = syn
                .tysyn
                .as_ref()
                .and_then(|id| qualified_syn(refs, pkg_index, id))
                .unwrap_or_else(|| "?syn".to_string());
            let args = syn
                .args
                .iter()
                .map(|arg| sketch(refs, pkg_index, arg, 0))
                .collect::<Vec<_>>();
            if args.is_empty() {
                ("syn".to_string(), name)
            } else {
                ("synN".to_string(), format!("{name}<{}>", args.join(",")))
            }
        }
        Some(daml_lf_2::r#type::Sum::Struct(st)) => (
            "struct".to_string(),
            format!("struct{{{}}}", sketch_fields(refs, pkg_index, st)),
        ),
        Some(daml_lf_2::r#type::Sum::Tapp(app)) => (
            "tapp".to_string(),
            format!(
                "({} {})",
                app.lhs
                    .as_ref()
                    .map(|t| sketch(refs, pkg_index, t, 0))
                    .unwrap_or_else(|| "?".to_string()),
                app.rhs
                    .as_ref()
                    .map(|t| sketch(refs, pkg_index, t, 0))
                    .unwrap_or_else(|| "?".to_string())
            ),
        ),
        Some(daml_lf_2::r#type::Sum::Forall(_)) => ("forall".to_string(), "forall".to_string()),
        Some(daml_lf_2::r#type::Sum::Nat(n)) => ("nat".to_string(), format!("nat{n}")),
        Some(daml_lf_2::r#type::Sum::InternedType(index)) => {
            ("missing".to_string(), format!("interned-cycle:{index}"))
        }
        None => ("missing".to_string(), "-".to_string()),
    }
}

fn sketch(refs: &[PkgRef<'_>], pkg_index: usize, ty: &Type, depth: usize) -> String {
    if depth > 32 {
        return "...".to_string();
    }
    let package = refs[pkg_index].package;
    let mut current = ty;
    for _ in 0..64 {
        let Some(daml_lf_2::r#type::Sum::InternedType(index)) = current.sum.as_ref() else {
            break;
        };
        let Some(next) = usize::try_from(*index)
            .ok()
            .and_then(|i| package.interned_types.get(i))
        else {
            return format!("interned:{index}");
        };
        current = next;
    }
    match current.sum.as_ref() {
        Some(daml_lf_2::r#type::Sum::Con(con)) => {
            let qname = con
                .tycon
                .as_ref()
                .and_then(|id| qualified(refs, pkg_index, id))
                .unwrap_or_else(|| "?".to_string());
            if con.args.is_empty() {
                qname
            } else {
                let args = con
                    .args
                    .iter()
                    .map(|arg| sketch(refs, pkg_index, arg, depth + 1))
                    .collect::<Vec<_>>();
                format!("{qname}<{}>", args.join(","))
            }
        }
        Some(daml_lf_2::r#type::Sum::Builtin(builtin)) => {
            let name = builtin_name(builtin.builtin);
            if builtin.args.is_empty() {
                name
            } else {
                let args = builtin
                    .args
                    .iter()
                    .map(|arg| sketch(refs, pkg_index, arg, depth + 1))
                    .collect::<Vec<_>>();
                format!("{name}<{}>", args.join(","))
            }
        }
        Some(daml_lf_2::r#type::Sum::Var(var)) => {
            let name = resolve_interned_string(package, var.var_interned_str, "Type.var")
                .unwrap_or_else(|_| "?".to_string());
            if var.args.is_empty() {
                format!("${name}")
            } else {
                let args = var
                    .args
                    .iter()
                    .map(|arg| sketch(refs, pkg_index, arg, depth + 1))
                    .collect::<Vec<_>>();
                format!("${name}<{}>", args.join(","))
            }
        }
        Some(daml_lf_2::r#type::Sum::Nat(n)) => format!("nat{n}"),
        Some(daml_lf_2::r#type::Sum::Tapp(app)) => format!(
            "({} {})",
            app.lhs
                .as_ref()
                .map(|t| sketch(refs, pkg_index, t, depth + 1))
                .unwrap_or_else(|| "?".to_string()),
            app.rhs
                .as_ref()
                .map(|t| sketch(refs, pkg_index, t, depth + 1))
                .unwrap_or_else(|| "?".to_string())
        ),
        Some(daml_lf_2::r#type::Sum::Struct(st)) => {
            format!("struct{{{}}}", sketch_fields(refs, pkg_index, st))
        }
        Some(daml_lf_2::r#type::Sum::Syn(_)) => "syn".to_string(),
        Some(daml_lf_2::r#type::Sum::Forall(_)) => "forall".to_string(),
        Some(daml_lf_2::r#type::Sum::InternedType(_)) => "interned-cycle".to_string(),
        None => "-".to_string(),
    }
}

fn sketch_fields(refs: &[PkgRef<'_>], pkg_index: usize, st: &daml_lf_2::r#type::Struct) -> String {
    let package = refs[pkg_index].package;
    let mut parts = Vec::new();
    for field in &st.fields {
        let name = resolve_interned_string(package, field.field_interned_str, "Type.struct.field")
            .unwrap_or_else(|_| "?".to_string());
        let ty = field
            .r#type
            .as_ref()
            .map(|ty| sketch(refs, pkg_index, ty, 1))
            .unwrap_or_else(|| "-".to_string());
        parts.push(format!("{name}:{ty}"));
    }
    parts.join(",")
}

fn builtin_name(code: i32) -> String {
    daml_lf_2::BuiltinType::try_from(code)
        .map(|builtin| format!("{builtin:?}").to_lowercase())
        .unwrap_or_else(|_| format!("builtin{code}"))
}

fn qualified(refs: &[PkgRef<'_>], pkg_index: usize, id: &daml_lf_2::TypeConId) -> Option<String> {
    let (package_id, qname) = resolve_con(refs[pkg_index].package, &refs[pkg_index].id, id).ok()?;
    let label = refs
        .iter()
        .find(|pkg| pkg.id == package_id)
        .map(|pkg| pkg.name.as_str())
        .unwrap_or(package_id.as_str());
    Some(format!("{label}/{qname}"))
}

fn qualified_syn(
    refs: &[PkgRef<'_>],
    pkg_index: usize,
    id: &daml_lf_2::TypeSynId,
) -> Option<String> {
    let module = id.module.as_ref()?;
    let package = refs[pkg_index].package;
    let package_id = package_of(package, &refs[pkg_index].id, module.package_id.as_ref()).ok()?;
    let module_name = resolve_interned_dotted_name(
        package,
        module.module_name_interned_dname,
        "TypeSynId.module",
    )
    .ok()?;
    let name =
        resolve_interned_dotted_name(package, id.name_interned_dname, "TypeSynId.name").ok()?;
    let label = refs
        .iter()
        .find(|pkg| pkg.id == package_id)
        .map(|pkg| pkg.name.as_str())
        .unwrap_or(package_id.as_str());
    Some(format!("{label}/{module_name}:{name}"))
}

/// Type-parameter count of a data type, when the defining package is in one of the DARs.
fn defined_params(
    refs: &[PkgRef<'_>],
    pkg_index: usize,
    id: &daml_lf_2::TypeConId,
) -> Option<usize> {
    let package = refs[pkg_index].package;
    let (package_id, qname) = resolve_con(package, &refs[pkg_index].id, id).ok()?;
    let (module_name, ty_name) = qname.split_once(':')?;
    let def = refs.iter().find(|pkg| pkg.id == package_id)?;
    for module in &def.package.modules {
        let Ok(name) = resolve_single_module_name(def.package, module) else {
            continue;
        };
        if name != module_name {
            continue;
        }
        for data in &module.data_types {
            let Ok(data_name) = resolve_interned_dotted_name(
                def.package,
                data.name_interned_dname,
                "DefDataType.name",
            ) else {
                continue;
            };
            if data_name == ty_name {
                return Some(data.params.len());
            }
        }
        return None;
    }
    None
}

fn resolve_con(
    package: &Package,
    self_id: &str,
    id: &daml_lf_2::TypeConId,
) -> Result<(String, String), ()> {
    let module = id.module.as_ref().ok_or(())?;
    let package_id = package_of(package, self_id, module.package_id.as_ref())?;
    let module_name = resolve_interned_dotted_name(
        package,
        module.module_name_interned_dname,
        "TypeConId.module",
    )
    .map_err(|_| ())?;
    let name = resolve_interned_dotted_name(package, id.name_interned_dname, "TypeConId.name")
        .map_err(|_| ())?;
    Ok((package_id, format!("{module_name}:{name}")))
}

fn package_of(
    package: &Package,
    self_id: &str,
    reference: Option<&daml_lf_2::SelfOrImportedPackageId>,
) -> Result<String, ()> {
    use daml_lf_2::self_or_imported_package_id::Sum as Reference;
    match reference.and_then(|r| r.sum.as_ref()) {
        Some(Reference::SelfPackageId(_)) | None => Ok(self_id.to_string()),
        Some(Reference::ImportedPackageIdInternedStr(index)) => {
            resolve_interned_string(package, *index, "TypeConId.package").map_err(|_| ())
        }
        Some(Reference::PackageImportId(index)) => match &package.imports_sum {
            Some(daml_lf_2::package::ImportsSum::PackageImports(imports)) => {
                usize::try_from(*index)
                    .ok()
                    .and_then(|i| imports.imported_packages.get(i))
                    .cloned()
                    .ok_or(())
            }
            _ => Err(()),
        },
    }
}

fn clip(text: String) -> String {
    if text.chars().count() <= 200 {
        text
    } else {
        let mut cut: String = text.chars().take(197).collect();
        cut.push_str("...");
        cut
    }
}
