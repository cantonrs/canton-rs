//! Dependency collection, recursion and name-collision checks of the validator.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::def_data_type::DataCons;
use crate::proto::daml_lf_2::expr::Sum as ExprSum;
use crate::proto::daml_lf_2::update::Sum as UpdateSum;
use crate::proto::daml_lf_2::{Package, Type};

use super::builtins::minor_rank;
use super::decode::{
    decode_type, dotted_segments, dotted_string, err, interned_str, resolve_type_con_id,
    resolve_value_id, DecodedDataCons,
};
use super::types::{Ident, LType};
use super::{topo_check, NamedEntity, NamedEntityKind, TypeError, Validator, MAX_RESOLVE_DEPTH};

impl<'a> Validator<'a> {
    fn collect_expr_deps(
        &self,
        pkg_id: &str,
        pkg: &Package,
        expr: &daml_lf_2::Expr,
        depth: usize,
        out_pkgs: &mut HashSet<String>,
        self_mods: &mut BTreeSet<String>,
    ) -> Result<(), TypeError> {
        if depth > MAX_RESOLVE_DEPTH {
            return Err(err(pkg_id, "ETypeMismatch", "expression depth exceeded"));
        }
        #[inline]
        fn record_ident(
            pkg_id: &str,
            id: &Ident,
            out_pkgs: &mut HashSet<String>,
            self_mods: &mut BTreeSet<String>,
        ) {
            if id.pkg == pkg_id {
                self_mods.insert(id.module.clone());
            } else {
                out_pkgs.insert(id.pkg.clone());
            }
        }
        let walk_ty = |checker: &Self,
                       t: Option<&Type>,
                       out_pkgs: &mut HashSet<String>,
                       self_mods: &mut BTreeSet<String>|
         -> Result<(), TypeError> {
            if let Some(t) = t {
                let lt = decode_type(pkg_id, pkg, Some(t), 0)?;
                checker.collect_ltype_deps(pkg_id, &lt, out_pkgs, self_mods);
            }
            Ok(())
        };
        match &expr.sum {
            None
            | Some(ExprSum::VarInternedStr(_))
            | Some(ExprSum::Builtin(_))
            | Some(ExprSum::BuiltinCon(_))
            | Some(ExprSum::BuiltinLit(_)) => {}
            Some(ExprSum::InternedExpr(idx)) => {
                if let Some(inner) = usize::try_from(*idx)
                    .ok()
                    .and_then(|i| pkg.interned_exprs.get(i))
                {
                    self.collect_expr_deps(pkg_id, pkg, inner, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Val(v)) => {
                record_ident(
                    pkg_id,
                    &resolve_value_id(pkg_id, pkg, Some(v))?,
                    out_pkgs,
                    self_mods,
                );
            }
            Some(ExprSum::RecCon(rc)) => {
                if let Some(c) = &rc.tycon {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, c.tycon.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    for a in &c.args {
                        walk_ty(self, Some(a), out_pkgs, self_mods)?;
                    }
                }
                for f in &rc.fields {
                    if let Some(e) = &f.expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
            }
            Some(ExprSum::RecProj(rp)) => {
                if let Some(c) = &rp.tycon {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, c.tycon.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    for a in &c.args {
                        walk_ty(self, Some(a), out_pkgs, self_mods)?;
                    }
                }
                if let Some(e) = &rp.record {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::RecUpd(ru)) => {
                if let Some(c) = &ru.tycon {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, c.tycon.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    for a in &c.args {
                        walk_ty(self, Some(a), out_pkgs, self_mods)?;
                    }
                }
                if let Some(e) = &ru.record {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &ru.update {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::VariantCon(vc)) => {
                if let Some(c) = &vc.tycon {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, c.tycon.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    for a in &c.args {
                        walk_ty(self, Some(a), out_pkgs, self_mods)?;
                    }
                }
                if let Some(e) = &vc.variant_arg {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::EnumCon(ec)) => record_ident(
                pkg_id,
                &resolve_type_con_id(pkg_id, pkg, ec.tycon.as_ref())?,
                out_pkgs,
                self_mods,
            ),
            Some(ExprSum::StructCon(sc)) => {
                for f in &sc.fields {
                    if let Some(e) = &f.expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
            }
            Some(ExprSum::StructProj(sp)) => {
                if let Some(e) = &sp.r#struct {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::StructUpd(su)) => {
                if let Some(e) = &su.r#struct {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &su.update {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::App(app)) => {
                if let Some(f) = &app.fun {
                    self.collect_expr_deps(pkg_id, pkg, f, depth + 1, out_pkgs, self_mods)?;
                }
                for a in &app.args {
                    self.collect_expr_deps(pkg_id, pkg, a, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::TyApp(ta)) => {
                if let Some(e) = &ta.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                for t in &ta.types {
                    walk_ty(self, Some(t), out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Abs(abs)) => {
                for p in &abs.param {
                    walk_ty(self, p.r#type.as_ref(), out_pkgs, self_mods)?;
                }
                if let Some(b) = &abs.body {
                    self.collect_expr_deps(pkg_id, pkg, b, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::TyAbs(ta)) => {
                if let Some(b) = &ta.body {
                    self.collect_expr_deps(pkg_id, pkg, b, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Case(c)) => {
                if let Some(s) = &c.scrut {
                    self.collect_expr_deps(pkg_id, pkg, s, depth + 1, out_pkgs, self_mods)?;
                }
                for alt in &c.alts {
                    match &alt.sum {
                        Some(daml_lf_2::case_alt::Sum::Variant(v)) => {
                            record_ident(
                                pkg_id,
                                &resolve_type_con_id(pkg_id, pkg, v.con.as_ref())?,
                                out_pkgs,
                                self_mods,
                            );
                        }
                        Some(daml_lf_2::case_alt::Sum::Enum(e)) => {
                            record_ident(
                                pkg_id,
                                &resolve_type_con_id(pkg_id, pkg, e.con.as_ref())?,
                                out_pkgs,
                                self_mods,
                            );
                        }
                        _ => {}
                    }
                    if let Some(b) = &alt.body {
                        self.collect_expr_deps(pkg_id, pkg, b, depth + 1, out_pkgs, self_mods)?;
                    }
                }
            }
            Some(ExprSum::Let(blk)) => {
                for b in &blk.bindings {
                    if let Some(binder) = &b.binder {
                        walk_ty(self, binder.r#type.as_ref(), out_pkgs, self_mods)?;
                    }
                    if let Some(bound) = &b.bound {
                        self.collect_expr_deps(pkg_id, pkg, bound, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                if let Some(body) = &blk.body {
                    self.collect_expr_deps(pkg_id, pkg, body, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Nil(n)) => walk_ty(self, n.r#type.as_ref(), out_pkgs, self_mods)?,
            Some(ExprSum::Cons(c)) => {
                walk_ty(self, c.r#type.as_ref(), out_pkgs, self_mods)?;
                for e in &c.front {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(t) = &c.tail {
                    self.collect_expr_deps(pkg_id, pkg, t, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::OptionalNone(n)) => {
                walk_ty(self, n.r#type.as_ref(), out_pkgs, self_mods)?
            }
            Some(ExprSum::OptionalSome(s)) => {
                walk_ty(self, s.r#type.as_ref(), out_pkgs, self_mods)?;
                if let Some(v) = &s.value {
                    self.collect_expr_deps(pkg_id, pkg, v, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ToAny(ta)) => {
                walk_ty(self, ta.r#type.as_ref(), out_pkgs, self_mods)?;
                if let Some(e) = &ta.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::FromAny(fa)) => {
                walk_ty(self, fa.r#type.as_ref(), out_pkgs, self_mods)?;
                if let Some(e) = &fa.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::TypeRep(tr)) => walk_ty(self, Some(tr), out_pkgs, self_mods)?,
            Some(ExprSum::ToAnyException(te)) => {
                walk_ty(self, te.r#type.as_ref(), out_pkgs, self_mods)?;
                if let Some(e) = &te.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::FromAnyException(fe)) => {
                walk_ty(self, fe.r#type.as_ref(), out_pkgs, self_mods)?;
                if let Some(e) = &fe.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Throw(th)) => {
                walk_ty(self, th.return_type.as_ref(), out_pkgs, self_mods)?;
                walk_ty(self, th.exception_type.as_ref(), out_pkgs, self_mods)?;
                if let Some(e) = &th.exception_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ToInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.template_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.template_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::FromInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.template_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.interface_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::UnsafeFromInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.template_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.contract_id_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &x.interface_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::CallInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface_type.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.interface_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::SignatoryInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ObserverInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ViewInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::InterfaceTemplateTypeRep(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ToRequiredInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.required_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.requiring_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::FromRequiredInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.required_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.requiring_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::UnsafeFromRequiredInterface(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.required_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.requiring_interface.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.contract_id_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &x.interface_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ChoiceController(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.contract_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &x.choice_arg_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::ChoiceObserver(x)) => {
                record_ident(
                    pkg_id,
                    &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                    out_pkgs,
                    self_mods,
                );
                if let Some(e) = &x.contract_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                if let Some(e) = &x.choice_arg_expr {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
            }
            Some(ExprSum::Experimental(x)) => {
                walk_ty(self, x.r#type.as_ref(), out_pkgs, self_mods)?
            }
            Some(ExprSum::Update(u)) => match &u.sum {
                None | Some(UpdateSum::GetTime(_)) => {}
                Some(UpdateSum::Pure(p)) => {
                    walk_ty(self, p.r#type.as_ref(), out_pkgs, self_mods)?;
                    if let Some(e) = &p.expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::Block(blk)) => {
                    for b in &blk.bindings {
                        if let Some(binder) = &b.binder {
                            walk_ty(self, binder.r#type.as_ref(), out_pkgs, self_mods)?;
                        }
                        if let Some(bound) = &b.bound {
                            self.collect_expr_deps(
                                pkg_id,
                                pkg,
                                bound,
                                depth + 1,
                                out_pkgs,
                                self_mods,
                            )?;
                        }
                    }
                    if let Some(body) = &blk.body {
                        self.collect_expr_deps(pkg_id, pkg, body, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::Create(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::CreateInterface(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::Exercise(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                    if let Some(e) = &x.arg {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::ExerciseInterface(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                    if let Some(e) = &x.arg {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                    if let Some(g) = &x.guard {
                        self.collect_expr_deps(pkg_id, pkg, g, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::ExerciseByKey(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.key {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                    if let Some(e) = &x.arg {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::Fetch(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::FetchInterface(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::UnpackTemplate(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::UnpackInterface(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.interface.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                    if let Some(e) = &x.cid {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::EmbedExpr(x)) => {
                    walk_ty(self, x.r#type.as_ref(), out_pkgs, self_mods)?;
                    if let Some(e) = &x.body {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
                Some(UpdateSum::FetchByKey(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                }
                Some(UpdateSum::QueryNByKey(x)) => {
                    record_ident(
                        pkg_id,
                        &resolve_type_con_id(pkg_id, pkg, x.template.as_ref())?,
                        out_pkgs,
                        self_mods,
                    );
                }
                Some(UpdateSum::LedgerTimeLt(e)) => {
                    self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                }
                Some(UpdateSum::TryCatch(tc)) => {
                    walk_ty(self, tc.return_type.as_ref(), out_pkgs, self_mods)?;
                    if let Some(e) = &tc.try_expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                    if let Some(e) = &tc.catch_expr {
                        self.collect_expr_deps(pkg_id, pkg, e, depth + 1, out_pkgs, self_mods)?;
                    }
                }
            },
        }
        Ok(())
    }

    fn collect_ltype_deps(
        &self,
        pkg_id: &str,
        ty: &LType,
        out_pkgs: &mut HashSet<String>,
        self_mods: &mut BTreeSet<String>,
    ) {
        match ty {
            LType::Var(_) | LType::Nat(_) | LType::Builtin(_) => {}
            LType::Con(id) => {
                if id.pkg == pkg_id {
                    self_mods.insert(id.module.clone());
                } else {
                    out_pkgs.insert(id.pkg.clone());
                }
            }
            LType::App(f, a) => {
                self.collect_ltype_deps(pkg_id, f, out_pkgs, self_mods);
                self.collect_ltype_deps(pkg_id, a, out_pkgs, self_mods);
            }
            LType::Forall { body, .. } => {
                self.collect_ltype_deps(pkg_id, body, out_pkgs, self_mods);
            }
            LType::Struct(fields) => {
                for t in fields.values() {
                    self.collect_ltype_deps(pkg_id, t, out_pkgs, self_mods);
                }
            }
            LType::SynApp { syn, args } => {
                if syn.pkg == pkg_id {
                    self_mods.insert(syn.module.clone());
                } else {
                    out_pkgs.insert(syn.pkg.clone());
                }
                for a in args {
                    self.collect_ltype_deps(pkg_id, a, out_pkgs, self_mods);
                }
            }
        }
    }

    fn collect_syn_refs(ty: &LType, out: &mut BTreeSet<String>, pkg_id: &str, mod_name: &str) {
        match ty {
            LType::SynApp { syn, args } => {
                if syn.pkg == pkg_id && syn.module == mod_name {
                    out.insert(syn.name.clone());
                }
                for a in args {
                    Self::collect_syn_refs(a, out, pkg_id, mod_name);
                }
            }
            LType::App(f, a) => {
                Self::collect_syn_refs(f, out, pkg_id, mod_name);
                Self::collect_syn_refs(a, out, pkg_id, mod_name);
            }
            LType::Forall { body, .. } => Self::collect_syn_refs(body, out, pkg_id, mod_name),
            LType::Struct(fields) => {
                for t in fields.values() {
                    Self::collect_syn_refs(t, out, pkg_id, mod_name);
                }
            }
            LType::Var(_) | LType::Nat(_) | LType::Con(_) | LType::Builtin(_) => {}
        }
    }

    /// Pass 1 (`DependencyVersion`) + Pass 3 (`Recursion`).
    pub(super) fn check_dependencies_and_recursion(
        &self,
        pkg_id: &str,
        pkg: &Package,
    ) -> Result<(), TypeError> {
        let mut ext_pkgs = HashSet::new();
        let mut mod_graph: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut mod_order = Vec::with_capacity(pkg.modules.len());

        for module in &pkg.modules {
            let mod_name = dotted_string(pkg_id, pkg, module.name_interned_dname, "Module.name")?;
            mod_order.push(mod_name.clone());
            let mut deps = BTreeSet::new();

            for def in &module.data_types {
                let name = dotted_string(pkg_id, pkg, def.name_interned_dname, "DefDataType")?;
                if let Some(d) = self.data_types.get(&Ident {
                    pkg: pkg_id.to_string(),
                    module: mod_name.clone(),
                    name,
                }) {
                    match &d.cons {
                        DecodedDataCons::Record(fs) | DecodedDataCons::Variant(fs) => {
                            for (_, t) in fs {
                                self.collect_ltype_deps(pkg_id, t, &mut ext_pkgs, &mut deps);
                            }
                        }
                        DecodedDataCons::Enum(_) | DecodedDataCons::Interface => {}
                    }
                }
            }

            let mut syn_graph: HashMap<String, BTreeSet<String>> = HashMap::new();
            let mut syn_names = Vec::new();
            for syn in &module.synonyms {
                let name = dotted_string(pkg_id, pkg, syn.name_interned_dname, "DefTypeSyn")?;
                syn_names.push(name.clone());
                if let Some(s) = self.type_syns.get(&Ident {
                    pkg: pkg_id.to_string(),
                    module: mod_name.clone(),
                    name: name.clone(),
                }) {
                    self.collect_ltype_deps(pkg_id, &s.replacement, &mut ext_pkgs, &mut deps);
                    let mut syn_deps = BTreeSet::new();
                    Self::collect_syn_refs(&s.replacement, &mut syn_deps, pkg_id, &mod_name);
                    syn_graph.insert(name, syn_deps);
                }
            }
            topo_check(
                pkg_id,
                "ETypeSynCycle",
                syn_names.iter().map(String::as_str),
                &syn_graph,
            )?;

            for val in &module.values {
                if let Some(nwt) = &val.name_with_type {
                    let vname = dotted_string(pkg_id, pkg, nwt.name_interned_dname, "DefValue")?;
                    if let Some(v) = self.values.get(&Ident {
                        pkg: pkg_id.to_string(),
                        module: mod_name.clone(),
                        name: vname,
                    }) {
                        self.collect_ltype_deps(pkg_id, &v.typ, &mut ext_pkgs, &mut deps);
                    }
                }
                if let Some(expr) = &val.expr {
                    self.collect_expr_deps(pkg_id, pkg, expr, 0, &mut ext_pkgs, &mut deps)?;
                }
            }

            for tmpl in &module.templates {
                let tname = dotted_string(pkg_id, pkg, tmpl.tycon_interned_dname, "DefTemplate")?;
                if let Some(t) = self.templates.get(&Ident {
                    pkg: pkg_id.to_string(),
                    module: mod_name.clone(),
                    name: tname,
                }) {
                    for expr in [t.precond, t.signatories, t.observers]
                        .into_iter()
                        .flatten()
                    {
                        self.collect_expr_deps(pkg_id, pkg, expr, 0, &mut ext_pkgs, &mut deps)?;
                    }
                    for ch in &t.choices {
                        self.collect_ltype_deps(pkg_id, &ch.arg_type, &mut ext_pkgs, &mut deps);
                        self.collect_ltype_deps(pkg_id, &ch.ret_type, &mut ext_pkgs, &mut deps);
                        for expr in [ch.controllers, ch.observers, ch.authorizers, ch.update]
                            .into_iter()
                            .flatten()
                        {
                            self.collect_expr_deps(pkg_id, pkg, expr, 0, &mut ext_pkgs, &mut deps)?;
                        }
                    }
                    if let Some(k) = &t.key {
                        self.collect_ltype_deps(pkg_id, &k.typ, &mut ext_pkgs, &mut deps);
                        for expr in [k.body, k.maintainers].into_iter().flatten() {
                            self.collect_expr_deps(pkg_id, pkg, expr, 0, &mut ext_pkgs, &mut deps)?;
                        }
                    }
                    for imp in &t.implements {
                        if imp.iface.pkg == pkg_id {
                            deps.insert(imp.iface.module.clone());
                        } else {
                            ext_pkgs.insert(imp.iface.pkg.clone());
                        }
                        if let Some(v) = imp.view {
                            self.collect_expr_deps(pkg_id, pkg, v, 0, &mut ext_pkgs, &mut deps)?;
                        }
                        for (_, e) in &imp.methods {
                            if let Some(expr) = e {
                                self.collect_expr_deps(
                                    pkg_id,
                                    pkg,
                                    expr,
                                    0,
                                    &mut ext_pkgs,
                                    &mut deps,
                                )?;
                            }
                        }
                    }
                }
            }

            for iface in &module.interfaces {
                let iname = dotted_string(pkg_id, pkg, iface.tycon_interned_dname, "DefInterface")?;
                if let Some(i) = self.interfaces.get(&Ident {
                    pkg: pkg_id.to_string(),
                    module: mod_name.clone(),
                    name: iname,
                }) {
                    for req in &i.requires {
                        if req.pkg == pkg_id {
                            deps.insert(req.module.clone());
                        } else {
                            ext_pkgs.insert(req.pkg.clone());
                        }
                    }
                    self.collect_ltype_deps(pkg_id, &i.view, &mut ext_pkgs, &mut deps);
                    for (_, mt) in &i.methods {
                        self.collect_ltype_deps(pkg_id, mt, &mut ext_pkgs, &mut deps);
                    }
                    for ch in &i.choices {
                        self.collect_ltype_deps(pkg_id, &ch.arg_type, &mut ext_pkgs, &mut deps);
                        self.collect_ltype_deps(pkg_id, &ch.ret_type, &mut ext_pkgs, &mut deps);
                        for expr in [ch.controllers, ch.observers, ch.authorizers, ch.update]
                            .into_iter()
                            .flatten()
                        {
                            self.collect_expr_deps(pkg_id, pkg, expr, 0, &mut ext_pkgs, &mut deps)?;
                        }
                    }
                }
            }

            for exc in &module.exceptions {
                if let Some(msg) = &exc.message {
                    self.collect_expr_deps(pkg_id, pkg, msg, 0, &mut ext_pkgs, &mut deps)?;
                }
            }

            deps.remove(&mod_name);
            mod_graph.insert(mod_name, deps);
        }

        topo_check(
            pkg_id,
            "EImportCycle",
            mod_order.iter().map(String::as_str),
            &mod_graph,
        )?;

        if let Some(pkg_ver) = self.versions.get(pkg_id).and_then(|v| minor_rank(v)) {
            let mut sorted_deps: Vec<&String> = ext_pkgs.iter().collect();
            sorted_deps.sort();
            for dep_pkg_id in sorted_deps {
                if let Some(dep_ver_str) = self.versions.get(dep_pkg_id) {
                    if let Some(dep_ver) = minor_rank(dep_ver_str) {
                        if pkg_ver < dep_ver {
                            return Err(err(
                                pkg_id,
                                "EModuleVersionDependencies",
                                format!(
                                    "package {pkg_id} (version {:?}) depends on {dep_pkg_id} with newer version {dep_ver_str}",
                                    self.versions.get(pkg_id)
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Pass 2 (`Collision.scala`).
    pub(super) fn check_collisions(&self, pkg_id: &str, pkg: &Package) -> Result<(), TypeError> {
        let mut entities = Vec::new();
        for module in &pkg.modules {
            let mod_segs: Vec<String> =
                dotted_segments(pkg_id, pkg, module.name_interned_dname, "Module.name")?
                    .into_iter()
                    .map(str::to_string)
                    .collect();
            let mod_name = mod_segs.join(".");
            let mod_upper: Vec<String> = mod_segs.iter().map(|s| s.to_ascii_uppercase()).collect();
            entities.push(NamedEntity {
                kind: NamedEntityKind::ModDef,
                pretty: format!("module {mod_name}"),
                upper_segments: mod_upper.clone(),
            });

            for syn in &module.synonyms {
                let segs =
                    dotted_segments(pkg_id, pkg, syn.name_interned_dname, "DefTypeSyn.name")?;
                let sname = segs.join(".");
                let mut upper = mod_upper.clone();
                upper.extend(segs.iter().map(|s| s.to_ascii_uppercase()));
                entities.push(NamedEntity {
                    kind: NamedEntityKind::SynDef,
                    pretty: format!("type synonym {mod_name}:{sname}"),
                    upper_segments: upper,
                });
            }

            for def in &module.data_types {
                let segs =
                    dotted_segments(pkg_id, pkg, def.name_interned_dname, "DefDataType.name")?;
                let dname = segs.join(".");
                let mut def_upper = mod_upper.clone();
                def_upper.extend(segs.iter().map(|s| s.to_ascii_uppercase()));
                match &def.data_cons {
                    Some(DataCons::Record(r)) => {
                        entities.push(NamedEntity {
                            kind: NamedEntityKind::RecDef,
                            pretty: format!("record {mod_name}:{dname}"),
                            upper_segments: def_upper.clone(),
                        });
                        for f in &r.fields {
                            let fn_s =
                                interned_str(pkg_id, pkg, f.field_interned_str, "Record.field")?;
                            let mut f_upper = def_upper.clone();
                            f_upper.push(fn_s.to_ascii_uppercase());
                            entities.push(NamedEntity {
                                kind: NamedEntityKind::Field,
                                pretty: format!("record field {mod_name}:{dname}:{fn_s}"),
                                upper_segments: f_upper,
                            });
                        }
                    }
                    Some(DataCons::Variant(v)) => {
                        entities.push(NamedEntity {
                            kind: NamedEntityKind::VarDef,
                            pretty: format!("variant {mod_name}:{dname}"),
                            upper_segments: def_upper.clone(),
                        });
                        for f in &v.fields {
                            let vn =
                                interned_str(pkg_id, pkg, f.field_interned_str, "Variant.con")?;
                            let mut v_upper = def_upper.clone();
                            v_upper.push(vn.to_ascii_uppercase());
                            entities.push(NamedEntity {
                                kind: NamedEntityKind::VarCon,
                                pretty: format!("variant constructor {mod_name}:{dname}:{vn}"),
                                upper_segments: v_upper,
                            });
                        }
                    }
                    Some(DataCons::Enum(e)) => {
                        entities.push(NamedEntity {
                            kind: NamedEntityKind::EnumDef,
                            pretty: format!("enum {mod_name}:{dname}"),
                            upper_segments: def_upper.clone(),
                        });
                        for &c_idx in &e.constructors_interned_str {
                            let cname = interned_str(pkg_id, pkg, c_idx, "Enum.con")?;
                            let mut e_upper = def_upper.clone();
                            e_upper.push(cname.to_ascii_uppercase());
                            entities.push(NamedEntity {
                                kind: NamedEntityKind::EnumCon,
                                pretty: format!("enum constructor {mod_name}:{dname}:{cname}"),
                                upper_segments: e_upper,
                            });
                        }
                    }
                    Some(DataCons::Interface(_)) | None => {}
                }
            }

            for tmpl in &module.templates {
                let segs = dotted_segments(pkg_id, pkg, tmpl.tycon_interned_dname, "DefTemplate")?;
                let tname = segs.join(".");
                let mut tpl_upper = mod_upper.clone();
                tpl_upper.extend(segs.iter().map(|s| s.to_ascii_uppercase()));
                for ch in &tmpl.choices {
                    let cname = interned_str(pkg_id, pkg, ch.name_interned_str, "TemplateChoice")?;
                    let mut c_upper = tpl_upper.clone();
                    c_upper.push(cname.to_ascii_uppercase());
                    entities.push(NamedEntity {
                        kind: NamedEntityKind::Choice,
                        pretty: format!("template choice {mod_name}:{tname}:{cname}"),
                        upper_segments: c_upper,
                    });
                }
            }

            for iface in &module.interfaces {
                let segs =
                    dotted_segments(pkg_id, pkg, iface.tycon_interned_dname, "DefInterface")?;
                let iname = segs.join(".");
                let mut if_upper = mod_upper.clone();
                if_upper.extend(segs.iter().map(|s| s.to_ascii_uppercase()));
                entities.push(NamedEntity {
                    kind: NamedEntityKind::Interface,
                    pretty: format!("interface {mod_name}:{iname}"),
                    upper_segments: if_upper.clone(),
                });
                for ch in &iface.choices {
                    let cname = interned_str(pkg_id, pkg, ch.name_interned_str, "InterfaceChoice")?;
                    let mut c_upper = if_upper.clone();
                    c_upper.push(cname.to_ascii_uppercase());
                    entities.push(NamedEntity {
                        kind: NamedEntityKind::InterfaceChoice,
                        pretty: format!("interface choice {mod_name}:{iname}:{cname}"),
                        upper_segments: c_upper,
                    });
                }
            }
        }

        let mut seen: HashMap<Vec<String>, Vec<NamedEntity>> = HashMap::new();
        for ent in entities {
            let group = seen.entry(ent.upper_segments.clone()).or_default();
            for prev in group.iter() {
                let allowed = matches!(
                    (&prev.kind, &ent.kind),
                    (NamedEntityKind::VarCon, NamedEntityKind::RecDef)
                        | (NamedEntityKind::RecDef, NamedEntityKind::VarCon)
                );
                if !allowed {
                    return Err(err(
                        pkg_id,
                        "ECollision",
                        format!("collision between {} and {}", prev.pretty, ent.pretty),
                    ));
                }
            }
            group.push(ent);
        }

        Ok(())
    }
}
