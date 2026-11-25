//! Typing of expressions (`TypingEnv::type_of_expr` and its main dispatch).

use std::collections::BTreeMap;

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::expr::Sum as ExprSum;
use crate::proto::daml_lf_2::{BuiltinCon, BuiltinFunction};

use super::builtins::type_of_builtin_fn;
use super::decode::{
    decode_kind, decode_type, decode_type_con_app, interned_str, resolve_type_con_id,
    resolve_value_id, DecodedDataCons,
};
use super::types::{subst_one, LKind, LType};
use super::typing_env::TypingEnv;
use super::{check_kind, TypeError, MAX_RESOLVE_DEPTH};

impl<'a, 'b> TypingEnv<'a, 'b> {
    pub(super) fn type_of_expr(&self, expr: &daml_lf_2::Expr) -> Result<LType, TypeError> {
        let cur = self.expr_depth.get();
        if cur > MAX_RESOLVE_DEPTH {
            return Err(self.err("ETypeMismatch", "expression typecheck depth exceeded"));
        }
        struct Reset<'c>(&'c std::cell::Cell<usize>, usize);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.set(self.1);
            }
        }
        self.expr_depth.set(cur + 1);
        let _guard = Reset(&self.expr_depth, cur);
        self.type_of_expr_inner(expr)
    }

    fn type_of_expr_inner(&self, expr: &daml_lf_2::Expr) -> Result<LType, TypeError> {
        match &expr.sum {
            None => Err(self.err("ETypeMismatch", "empty Expr sum")),
            Some(ExprSum::InternedExpr(idx)) => {
                let target = usize::try_from(*idx)
                    .ok()
                    .and_then(|i| self.pkg.interned_exprs.get(i))
                    .ok_or_else(|| {
                        self.err(
                            "EUnknownDefinition",
                            format!("invalid interned_expr index {idx}"),
                        )
                    })?;
                self.type_of_expr(target)
            }
            Some(ExprSum::VarInternedStr(idx)) => {
                let name = interned_str(self.pkg_id, self.pkg, *idx, "Expr.var")?;
                self.e_vars.get(name).cloned().ok_or_else(|| {
                    self.err("EUnknownExprVar", format!("unknown expr variable: {name}"))
                })
            }
            Some(ExprSum::Val(val_id)) => {
                let id = resolve_value_id(self.pkg_id, self.pkg, Some(val_id))?;
                match self.v.lookup_value(self.pkg_id, &id)? {
                    Some(dv) => Ok(dv.typ.clone()),
                    None => Err(self.err(
                        "EUnknownDefinition",
                        format!("external value {} not loaded", id.pretty()),
                    )),
                }
            }
            Some(ExprSum::Builtin(b)) => {
                let bf = BuiltinFunction::try_from(*b).map_err(|_| {
                    self.err("EUnknownDefinition", format!("unknown BuiltinFunction {b}"))
                })?;
                Ok(type_of_builtin_fn(bf))
            }
            Some(ExprSum::BuiltinCon(bc)) => match BuiltinCon::try_from(*bc) {
                Ok(BuiltinCon::ConUnit) => Ok(LType::t_unit()),
                Ok(BuiltinCon::ConFalse | BuiltinCon::ConTrue) => Ok(LType::t_bool()),
                Err(_) => Err(self.err("EUnknownDefinition", format!("unknown BuiltinCon {bc}"))),
            },
            Some(ExprSum::BuiltinLit(lit)) => {
                use daml_lf_2::builtin_lit::Sum as LitSum;
                match &lit.sum {
                    Some(LitSum::Int64(_)) => Ok(LType::t_int64()),
                    Some(LitSum::NumericInternedStr(idx)) => {
                        let s = interned_str(self.pkg_id, self.pkg, *idx, "BuiltinLit.numeric")?;
                        let scale = s.split_once('.').map_or(0, |(_, frac)| frac.len() as i64);
                        if !(0..=37).contains(&scale) {
                            return Err(self.err(
                                "ETypeMismatch",
                                format!("Numeric literal {s:?} has invalid scale {scale}"),
                            ));
                        }
                        Ok(LType::t_numeric(LType::Nat(scale)))
                    }
                    Some(LitSum::TextInternedStr(_)) => Ok(LType::t_text()),
                    Some(LitSum::Timestamp(_)) => Ok(LType::t_timestamp()),
                    Some(LitSum::Date(_)) => Ok(LType::t_date()),
                    Some(LitSum::RoundingMode(_)) => Ok(LType::t_rounding_mode()),
                    Some(LitSum::FailureCategory(_)) => Ok(LType::t_failure_category()),
                    None => Err(self.err("ETypeMismatch", "empty BuiltinLit")),
                }
            }
            Some(ExprSum::RecCon(rc)) => {
                let (con_id, args) = decode_type_con_app(self.pkg_id, self.pkg, rc.tycon.as_ref())?;
                let tycon_ty = Self::typecon_app_to_type(&con_id, &args);
                let Some(cons) = self.check_tycon_app(&con_id, &args)? else {
                    return Ok(tycon_ty);
                };
                let DecodedDataCons::Record(expected_fields) = cons else {
                    return Err(self.err(
                        "EExpectedRecordType",
                        format!("expected record type: {}", tycon_ty.pretty()),
                    ));
                };
                if rc.fields.len() != expected_fields.len() {
                    return Err(self.err(
                        "EFieldMismatch",
                        format!(
                            "record {} expects {} fields, got {}",
                            con_id.pretty(),
                            expected_fields.len(),
                            rc.fields.len()
                        ),
                    ));
                }
                for (fexpr, (want_name, want_ty)) in rc.fields.iter().zip(expected_fields.iter()) {
                    let given_name = interned_str(
                        self.pkg_id,
                        self.pkg,
                        fexpr.field_interned_str,
                        "RecCon.field",
                    )?;
                    if given_name != want_name {
                        return Err(self.err(
                            "EFieldMismatch",
                            format!(
                                "record {} field order/name mismatch: expected {want_name}, got {given_name}",
                                con_id.pretty()
                            ),
                        ));
                    }
                    if let Some(e) = &fexpr.expr {
                        self.check_expr(e, want_ty)?;
                    }
                }
                Ok(tycon_ty)
            }
            Some(ExprSum::RecProj(rp)) => {
                let (con_id, args) = decode_type_con_app(self.pkg_id, self.pkg, rp.tycon.as_ref())?;
                let tycon_ty = Self::typecon_app_to_type(&con_id, &args);
                let field_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    rp.field_interned_str,
                    "RecProj.field",
                )?;
                let Some(cons) = self.check_tycon_app(&con_id, &args)? else {
                    return Err(self.err(
                        "EUnknownDefinition",
                        format!("external record {} not loaded", con_id.pretty()),
                    ));
                };
                let DecodedDataCons::Record(fields) = cons else {
                    return Err(self.err(
                        "EExpectedRecordType",
                        format!("expected record type: {}", tycon_ty.pretty()),
                    ));
                };
                let (_, field_ty) = fields
                    .into_iter()
                    .find(|(n, _)| n == field_name)
                    .ok_or_else(|| {
                        self.err(
                            "EUnknownField",
                            format!("record {} has no field {field_name}", con_id.pretty()),
                        )
                    })?;
                if let Some(rec) = &rp.record {
                    self.check_expr(rec, &tycon_ty)?;
                }
                Ok(field_ty)
            }
            Some(ExprSum::RecUpd(ru)) => {
                let (con_id, args) = decode_type_con_app(self.pkg_id, self.pkg, ru.tycon.as_ref())?;
                let tycon_ty = Self::typecon_app_to_type(&con_id, &args);
                let field_name =
                    interned_str(self.pkg_id, self.pkg, ru.field_interned_str, "RecUpd.field")?;
                let Some(cons) = self.check_tycon_app(&con_id, &args)? else {
                    return Err(self.err(
                        "EUnknownDefinition",
                        format!("external record {} not loaded", con_id.pretty()),
                    ));
                };
                let DecodedDataCons::Record(fields) = cons else {
                    return Err(self.err(
                        "EExpectedRecordType",
                        format!("expected record type: {}", tycon_ty.pretty()),
                    ));
                };
                if let Some(rec) = &ru.record {
                    self.check_expr(rec, &tycon_ty)?;
                }
                let (_, field_ty) = fields
                    .into_iter()
                    .find(|(n, _)| n == field_name)
                    .ok_or_else(|| {
                        self.err(
                            "EUnknownField",
                            format!("record {} has no field {field_name}", con_id.pretty()),
                        )
                    })?;
                if let Some(upd) = &ru.update {
                    let found = self.type_of_expr(upd)?;
                    if !self.alpha_equiv(&found, &field_ty)? {
                        return Err(self.err(
                            "EFieldTypeMismatch",
                            format!(
                                "field {field_name} of {} expects {}, found {}",
                                tycon_ty.pretty(),
                                field_ty.pretty(),
                                found.pretty()
                            ),
                        ));
                    }
                }
                Ok(tycon_ty)
            }
            Some(ExprSum::VariantCon(vc)) => {
                let (con_id, args) = decode_type_con_app(self.pkg_id, self.pkg, vc.tycon.as_ref())?;
                let tycon_ty = Self::typecon_app_to_type(&con_id, &args);
                let con_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    vc.variant_con_interned_str,
                    "VariantCon.con",
                )?;
                let Some(cons) = self.check_tycon_app(&con_id, &args)? else {
                    return Ok(tycon_ty);
                };
                let DecodedDataCons::Variant(variants) = cons else {
                    return Err(self.err(
                        "EExpectedVariantType",
                        format!("expected variant type: {}", con_id.pretty()),
                    ));
                };
                let (_, arg_ty) = variants
                    .into_iter()
                    .find(|(n, _)| n == con_name)
                    .ok_or_else(|| {
                        self.err(
                            "EUnknownVariantCon",
                            format!("unknown variant constructor: {con_name}"),
                        )
                    })?;
                if let Some(arg) = &vc.variant_arg {
                    self.check_expr(arg, &arg_ty)?;
                }
                Ok(tycon_ty)
            }
            Some(ExprSum::EnumCon(ec)) => {
                let con_id = resolve_type_con_id(self.pkg_id, self.pkg, ec.tycon.as_ref())?;
                let con_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    ec.enum_con_interned_str,
                    "EnumCon.con",
                )?;
                if let Some(def) = self.v.lookup_data_type(self.pkg_id, &con_id)? {
                    match &def.cons {
                        DecodedDataCons::Enum(cons) => {
                            if !cons.iter().any(|c| c == con_name) {
                                return Err(self.err(
                                    "EUnknownEnumCon",
                                    format!("unknown enum constructor: {con_name}"),
                                ));
                            }
                        }
                        _ => {
                            return Err(self.err(
                                "EExpectedEnumType",
                                format!("expected enum type: {}", con_id.pretty()),
                            ));
                        }
                    }
                }
                Ok(LType::Con(con_id))
            }
            Some(ExprSum::StructCon(sc)) => {
                let mut fields = BTreeMap::new();
                for f in &sc.fields {
                    let fname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        f.field_interned_str,
                        "StructCon.field",
                    )?
                    .to_string();
                    let fty = match &f.expr {
                        Some(e) => self.type_of_expr(e)?,
                        None => return Err(self.err("ETypeMismatch", "StructCon missing expr")),
                    };
                    if fields.insert(fname.clone(), fty).is_some() {
                        return Err(self.err(
                            "EDuplicateField",
                            format!("duplicate struct field: {fname}"),
                        ));
                    }
                }
                Ok(LType::Struct(fields))
            }
            Some(ExprSum::StructProj(sp)) => {
                let field_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    sp.field_interned_str,
                    "StructProj.field",
                )?;
                let target_ty = match &sp.r#struct {
                    Some(e) => self.type_of_expr(e)?,
                    None => return Err(self.err("ETypeMismatch", "StructProj missing struct")),
                };
                let fields = self.to_struct(&target_ty)?;
                fields.get(field_name).cloned().ok_or_else(|| {
                    self.err(
                        "EUnknownField",
                        format!("unknown struct field {field_name}"),
                    )
                })
            }
            Some(ExprSum::StructUpd(su)) => {
                let field_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    su.field_interned_str,
                    "StructUpd.field",
                )?;
                let target_ty = match &su.r#struct {
                    Some(e) => self.type_of_expr(e)?,
                    None => return Err(self.err("ETypeMismatch", "StructUpd missing struct")),
                };
                let fields = self.to_struct(&target_ty)?;
                let want_ty = fields.get(field_name).ok_or_else(|| {
                    self.err(
                        "EUnknownField",
                        format!("unknown struct field {field_name}"),
                    )
                })?;
                if let Some(upd) = &su.update {
                    self.check_expr(upd, want_ty)?;
                }
                Ok(LType::Struct(fields))
            }
            Some(ExprSum::App(app)) => {
                let mut fun_ty = match &app.fun {
                    Some(f) => self.type_of_expr(f)?,
                    None => return Err(self.err("ETypeMismatch", "App missing fun")),
                };
                for arg in &app.args {
                    let (param_ty, res_ty) = self.to_function(&fun_ty)?;
                    self.check_expr(arg, &param_ty)?;
                    fun_ty = res_ty;
                }
                Ok(fun_ty)
            }
            Some(ExprSum::TyApp(ta)) => {
                let mut expr_ty = match &ta.expr {
                    Some(e) => self.type_of_expr(e)?,
                    None => return Err(self.err("ETypeMismatch", "TyApp missing expr")),
                };
                for t in &ta.types {
                    let lt = decode_type(self.pkg_id, self.pkg, Some(t), 0)?;
                    let (v, k, body) = self.to_forall(&expr_ty)?;
                    self.check_type(&lt, &k)?;
                    expr_ty = subst_one(&v, &lt, &body);
                }
                Ok(expr_ty)
            }
            Some(ExprSum::Abs(abs)) => {
                let mut env = self.clone();
                let mut param_tys = Vec::with_capacity(abs.param.len());
                for p in &abs.param {
                    let pname =
                        interned_str(self.pkg_id, self.pkg, p.var_interned_str, "Abs.param")?;
                    let pt = decode_type(self.pkg_id, self.pkg, p.r#type.as_ref(), 0)?;
                    self.check_type(&pt, &LKind::Star)?;
                    env.e_vars.insert(pname.to_string(), pt.clone());
                    param_tys.push(pt);
                }
                let body_ty = match &abs.body {
                    Some(b) => env.type_of_expr(b)?,
                    None => return Err(self.err("ETypeMismatch", "Abs missing body")),
                };
                let mut acc = body_ty;
                for pt in param_tys.into_iter().rev() {
                    acc = LType::arrow(pt, acc);
                }
                Ok(acc)
            }
            Some(ExprSum::TyAbs(ta)) => {
                let mut env = self.clone();
                let mut binders = Vec::with_capacity(ta.param.len());
                for p in &ta.param {
                    let pname =
                        interned_str(self.pkg_id, self.pkg, p.var_interned_str, "TyAbs.param")?
                            .to_string();
                    let k = decode_kind(self.pkg_id, self.pkg, p.kind.as_ref(), 0)?;
                    check_kind(self.pkg_id, &k)?;
                    env.t_vars.insert(pname.clone(), k.clone());
                    binders.push((pname, k));
                }
                let mut acc = match &ta.body {
                    Some(b) => env.type_of_expr(b)?,
                    None => return Err(self.err("ETypeMismatch", "TyAbs missing body")),
                };
                for (pname, k) in binders.into_iter().rev() {
                    acc = LType::Forall {
                        param: pname,
                        kind: k,
                        body: Box::new(acc),
                    };
                }
                Ok(acc)
            }
            Some(ExprSum::Let(blk)) => {
                let mut env = self.clone();
                for b in &blk.bindings {
                    let binder = b
                        .binder
                        .as_ref()
                        .ok_or_else(|| self.err("ETypeMismatch", "Let binding missing binder"))?;
                    let vname =
                        interned_str(self.pkg_id, self.pkg, binder.var_interned_str, "Let.var")?;
                    let declared = decode_type(self.pkg_id, self.pkg, binder.r#type.as_ref(), 0)?;
                    env.check_type(&declared, &LKind::Star)?;
                    let bound = b
                        .bound
                        .as_ref()
                        .ok_or_else(|| self.err("ETypeMismatch", "Let binding missing bound"))?;
                    let resolved = env.check_expr(bound, &declared)?;
                    env.e_vars.insert(vname.to_string(), resolved);
                }
                match &blk.body {
                    Some(body) => env.type_of_expr(body),
                    None => Err(self.err("ETypeMismatch", "Let missing body")),
                }
            }
            Some(ExprSum::Nil(n)) => {
                let elem = decode_type(self.pkg_id, self.pkg, n.r#type.as_ref(), 0)?;
                self.check_type(&elem, &LKind::Star)?;
                Ok(LType::t_list(elem))
            }
            Some(ExprSum::Cons(c)) => {
                let elem = decode_type(self.pkg_id, self.pkg, c.r#type.as_ref(), 0)?;
                self.check_type(&elem, &LKind::Star)?;
                if c.front.is_empty() {
                    return Err(self.err("EEmptyConsFront", "empty Cons front"));
                }
                for e in &c.front {
                    self.check_expr(e, &elem)?;
                }
                let list_ty = LType::t_list(elem);
                if let Some(tail) = &c.tail {
                    self.check_expr(tail, &list_ty)?;
                }
                Ok(list_ty)
            }
            Some(ExprSum::OptionalNone(n)) => {
                let elem = decode_type(self.pkg_id, self.pkg, n.r#type.as_ref(), 0)?;
                self.check_type(&elem, &LKind::Star)?;
                Ok(LType::t_optional(elem))
            }
            Some(ExprSum::OptionalSome(s)) => {
                let elem = decode_type(self.pkg_id, self.pkg, s.r#type.as_ref(), 0)?;
                self.check_type(&elem, &LKind::Star)?;
                if let Some(v) = &s.value {
                    self.check_expr(v, &elem)?;
                }
                Ok(LType::t_optional(elem))
            }
            Some(ExprSum::ToAny(ta)) => {
                let ty = decode_type(self.pkg_id, self.pkg, ta.r#type.as_ref(), 0)?;
                self.check_any_type(&ty)?;
                if let Some(e) = &ta.expr {
                    self.check_expr(e, &ty)?;
                }
                Ok(LType::t_any())
            }
            Some(ExprSum::FromAny(fa)) => {
                let ty = decode_type(self.pkg_id, self.pkg, fa.r#type.as_ref(), 0)?;
                self.check_any_type(&ty)?;
                if let Some(e) = &fa.expr {
                    self.check_expr(e, &LType::t_any())?;
                }
                Ok(LType::t_optional(ty))
            }
            Some(ExprSum::TypeRep(tr)) => {
                let ty = decode_type(self.pkg_id, self.pkg, Some(tr), 0)?;
                self.check_any_type(&ty)?;
                Ok(LType::t_typerep())
            }
            Some(ExprSum::ToAnyException(te)) => {
                let ty = decode_type(self.pkg_id, self.pkg, te.r#type.as_ref(), 0)?;
                self.check_exception_type(&ty)?;
                if let Some(e) = &te.expr {
                    self.check_expr(e, &ty)?;
                }
                Ok(LType::t_any_exception())
            }
            Some(ExprSum::FromAnyException(fe)) => {
                let ty = decode_type(self.pkg_id, self.pkg, fe.r#type.as_ref(), 0)?;
                self.check_exception_type(&ty)?;
                if let Some(e) = &fe.expr {
                    self.check_expr(e, &LType::t_any_exception())?;
                }
                Ok(LType::t_optional(ty))
            }
            Some(ExprSum::Throw(th)) => {
                let ret_ty = decode_type(self.pkg_id, self.pkg, th.return_type.as_ref(), 0)?;
                self.check_type(&ret_ty, &LKind::Star)?;
                let ex_ty = decode_type(self.pkg_id, self.pkg, th.exception_type.as_ref(), 0)?;
                self.check_exception_type(&ex_ty)?;
                if let Some(e) = &th.exception_expr {
                    self.check_expr(e, &ex_ty)?;
                }
                Ok(ret_ty)
            }
            Some(ExprSum::Case(c)) => self.type_of_case(c),
            Some(ExprSum::Update(u)) => self.type_of_update(u),
            Some(ExprSum::ToInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface_type.as_ref())?;
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, x.template_type.as_ref())?;
                self.check_interface_instance(&iface, &tpl)?;
                if let Some(e) = &x.template_expr {
                    self.check_expr(e, &LType::Con(tpl))?;
                }
                Ok(LType::Con(iface))
            }
            Some(ExprSum::FromInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface_type.as_ref())?;
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, x.template_type.as_ref())?;
                self.check_interface_instance(&iface, &tpl)?;
                if let Some(e) = &x.interface_expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(LType::t_optional(LType::Con(tpl)))
            }
            Some(ExprSum::UnsafeFromInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface_type.as_ref())?;
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, x.template_type.as_ref())?;
                self.check_interface_instance(&iface, &tpl)?;
                if let Some(cid) = &x.contract_id_expr {
                    self.check_expr(cid, &LType::t_contract_id(LType::Con(iface.clone())))?;
                }
                if let Some(e) = &x.interface_expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(LType::Con(tpl))
            }
            Some(ExprSum::CallInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface_type.as_ref())?;
                let mname = interned_str(
                    self.pkg_id,
                    self.pkg,
                    x.method_interned_name,
                    "CallInterface.method",
                )?;
                let ret_ty = match self.v.lookup_interface(self.pkg_id, &iface)? {
                    Some(def) => def
                        .methods
                        .iter()
                        .find(|(n, _)| n == mname)
                        .map(|(_, t)| t.clone())
                        .ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("interface {} has no method {mname}", iface.pretty()),
                            )
                        })?,
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external interface {} not loaded", iface.pretty()),
                        ));
                    }
                };
                if let Some(e) = &x.interface_expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(ret_ty)
            }
            Some(ExprSum::SignatoryInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(LType::t_parties())
            }
            Some(ExprSum::ObserverInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(LType::t_parties())
            }
            Some(ExprSum::ViewInterface(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface.as_ref())?;
                let view_ty = match self.v.lookup_interface(self.pkg_id, &iface)? {
                    Some(def) => def.view.clone(),
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external interface {} not loaded", iface.pretty()),
                        ));
                    }
                };
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(view_ty)
            }
            Some(ExprSum::InterfaceTemplateTypeRep(x)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, x.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(iface))?;
                }
                Ok(LType::t_typerep())
            }
            Some(ExprSum::ToRequiredInterface(x)) => {
                let req =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.required_interface.as_ref())?;
                let reqing =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.requiring_interface.as_ref())?;
                if let Some(def) = self.v.lookup_interface(self.pkg_id, &reqing)? {
                    if !def.requires.contains(&req) {
                        return Err(self.err(
                            "EWrongInterfaceRequirement",
                            format!(
                                "interface {} does not require {}",
                                reqing.pretty(),
                                req.pretty()
                            ),
                        ));
                    }
                }
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(reqing))?;
                }
                Ok(LType::Con(req))
            }
            Some(ExprSum::FromRequiredInterface(x)) => {
                let req =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.required_interface.as_ref())?;
                let reqing =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.requiring_interface.as_ref())?;
                if let Some(def) = self.v.lookup_interface(self.pkg_id, &reqing)? {
                    if !def.requires.contains(&req) {
                        return Err(self.err(
                            "EWrongInterfaceRequirement",
                            format!(
                                "interface {} does not require {}",
                                reqing.pretty(),
                                req.pretty()
                            ),
                        ));
                    }
                }
                if let Some(e) = &x.expr {
                    self.check_expr(e, &LType::Con(req))?;
                }
                Ok(LType::t_optional(LType::Con(reqing)))
            }
            Some(ExprSum::UnsafeFromRequiredInterface(x)) => {
                let req =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.required_interface.as_ref())?;
                let reqing =
                    resolve_type_con_id(self.pkg_id, self.pkg, x.requiring_interface.as_ref())?;
                if let Some(def) = self.v.lookup_interface(self.pkg_id, &reqing)? {
                    if !def.requires.contains(&req) {
                        return Err(self.err(
                            "EWrongInterfaceRequirement",
                            format!(
                                "interface {} does not require {}",
                                reqing.pretty(),
                                req.pretty()
                            ),
                        ));
                    }
                }
                if let Some(cid) = &x.contract_id_expr {
                    self.check_expr(cid, &LType::t_contract_id(LType::Con(req.clone())))?;
                }
                if let Some(e) = &x.interface_expr {
                    self.check_expr(e, &LType::Con(req))?;
                }
                Ok(LType::Con(reqing))
            }
            Some(ExprSum::ChoiceController(x)) => {
                let target = resolve_type_con_id(self.pkg_id, self.pkg, x.template.as_ref())?;
                let ch_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    x.choice_interned_str,
                    "ChoiceController.choice",
                )?;
                self.type_of_choice_parties(
                    &target,
                    ch_name,
                    x.contract_expr.as_deref(),
                    x.choice_arg_expr.as_deref(),
                )
            }
            Some(ExprSum::ChoiceObserver(x)) => {
                let target = resolve_type_con_id(self.pkg_id, self.pkg, x.template.as_ref())?;
                let ch_name = interned_str(
                    self.pkg_id,
                    self.pkg,
                    x.choice_interned_str,
                    "ChoiceObserver.choice",
                )?;
                self.type_of_choice_parties(
                    &target,
                    ch_name,
                    x.contract_expr.as_deref(),
                    x.choice_arg_expr.as_deref(),
                )
            }
            Some(ExprSum::Experimental(exp)) => {
                let ty = decode_type(self.pkg_id, self.pkg, exp.r#type.as_ref(), 0)?;
                self.check_type(&ty, &LKind::Star)?;
                Ok(ty)
            }
        }
    }
}
