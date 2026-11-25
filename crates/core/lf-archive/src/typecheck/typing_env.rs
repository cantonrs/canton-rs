//! The typing environment (`TypingEnv`): type and expression variables, kinds, synonym expansion and the checks of types.

use std::collections::{BTreeMap, HashMap};

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::{BuiltinType, Package};

use super::builtins::kind_of_builtin;
use super::decode::{err, DecodedChoice, DecodedDataCons};
use super::types::{alpha_equiv_nominal, subst_type, Ident, LKind, LType};
use super::{check_kind, TypeError, Validator, MAX_RESOLVE_DEPTH};

#[derive(Clone)]
pub(super) struct TypingEnv<'a, 'b> {
    pub(super) v: &'b Validator<'a>,
    pub(super) pkg_id: &'a str,
    pub(super) pkg: &'a Package,
    pub(super) t_vars: HashMap<String, LKind>,
    pub(super) e_vars: HashMap<String, LType>,
    pub(super) expr_depth: std::cell::Cell<usize>,
}

impl<'a, 'b> TypingEnv<'a, 'b> {
    pub(super) fn new(
        v: &'b Validator<'a>,
        pkg_id: &'a str,
        pkg: &'a Package,
        _mod_name: &str,
    ) -> Self {
        Self {
            v,
            pkg_id,
            pkg,
            t_vars: HashMap::new(),
            e_vars: HashMap::new(),
            expr_depth: std::cell::Cell::new(0),
        }
    }

    pub(super) fn err(&self, kind: &'static str, detail: impl Into<String>) -> TypeError {
        err(self.pkg_id, kind, detail)
    }

    fn with_tvar(&self, name: &str, kind: LKind) -> Self {
        let mut copy = self.clone();
        copy.t_vars.insert(name.to_string(), kind);
        copy
    }

    pub(super) fn with_evar(&self, name: &str, ty: LType) -> Self {
        let mut copy = self.clone();
        copy.e_vars.insert(name.to_string(), ty);
        copy
    }

    fn kind_of(&self, ty: &LType) -> Result<LKind, TypeError> {
        match ty {
            LType::SynApp { syn, args } => {
                let expanded = self.expand_syn_app(syn, args)?;
                self.check_type(&expanded, &LKind::Star)?;
                Ok(LKind::Star)
            }
            LType::Var(v) => {
                self.t_vars.get(v).cloned().ok_or_else(|| {
                    self.err("EUnknownTypeVar", format!("unknown type variable: {v}"))
                })
            }
            LType::Nat(_) => Ok(LKind::Nat),
            LType::Con(id) => match self.v.lookup_data_type(self.pkg_id, id)? {
                Some(def) => {
                    let mut acc = LKind::Star;
                    for (_, k) in def.params.iter().rev() {
                        acc = LKind::k_arrow(k.clone(), acc);
                    }
                    Ok(acc)
                }
                None => Err(self.err(
                    "EUnknownDefinition",
                    format!("external data type {} not loaded", id.pretty()),
                )),
            },
            LType::App(lhs, rhs) => match self.kind_of(lhs)? {
                LKind::Arrow(arg_k, res_k) => {
                    self.check_type(rhs, &arg_k)?;
                    Ok(*res_k)
                }
                other => Err(self.err(
                    "EExpectedHigherKind",
                    format!("expected higher-kinded type, found {}", other.pretty()),
                )),
            },
            LType::Builtin(bt) => Ok(kind_of_builtin(*bt)),
            LType::Forall { param, kind, body } => {
                check_kind(self.pkg_id, kind)?;
                self.with_tvar(param, kind.clone())
                    .check_type(body, &LKind::Star)?;
                Ok(LKind::Star)
            }
            LType::Struct(fields) => {
                for ft in fields.values() {
                    self.check_type(ft, &LKind::Star)?;
                }
                Ok(LKind::Star)
            }
        }
    }

    pub(super) fn check_type(&self, ty: &LType, expected: &LKind) -> Result<(), TypeError> {
        // External-package constructors whose package wasn't passed in `packages` cannot have their kind verified.
        if let LType::Con(id) = ty {
            if !self.v.packages.contains_key(&id.pkg) && !self.v.data_types.contains_key(id) {
                return Ok(());
            }
        }
        let actual = self.kind_of(ty)?;
        if &actual != expected {
            return Err(self.err(
                "EKindMismatch",
                format!(
                    "expected kind {}, found {} for {}",
                    expected.pretty(),
                    actual.pretty(),
                    ty.pretty()
                ),
            ));
        }
        Ok(())
    }

    fn expand_syn_app(&self, syn: &Ident, args: &[LType]) -> Result<LType, TypeError> {
        let Some(def) = self.v.lookup_type_syn(self.pkg_id, syn)? else {
            return Ok(LType::SynApp {
                syn: syn.clone(),
                args: args.to_vec(),
            });
        };
        if def.params.len() != args.len() {
            return Err(self.err(
                "ETypeSynAppWrongArity",
                format!(
                    "type synonym {} expects {} arguments, got {}",
                    syn.pretty(),
                    def.params.len(),
                    args.len()
                ),
            ));
        }
        let mut map = HashMap::new();
        for ((p, k), arg) in def.params.iter().zip(args.iter()) {
            self.check_type(arg, k)?;
            map.insert(p.clone(), arg.clone());
        }
        Ok(subst_type(&map, &def.replacement))
    }

    fn expand_type_synonyms(&self, ty: &LType, depth: usize) -> Result<LType, TypeError> {
        if depth > MAX_RESOLVE_DEPTH {
            return Err(self.err("ETypeSynCycle", "type synonym expansion depth exceeded"));
        }
        match ty {
            LType::SynApp { syn, args } => {
                let Some(def) = self.v.lookup_type_syn(self.pkg_id, syn)? else {
                    return Ok(ty.clone());
                };
                if def.params.len() != args.len() {
                    return Err(self.err(
                        "ETypeSynAppWrongArity",
                        format!("wrong arity in {}", syn.pretty()),
                    ));
                }
                let mut map = HashMap::new();
                for ((p, _), arg) in def.params.iter().zip(args.iter()) {
                    map.insert(p.clone(), self.expand_type_synonyms(arg, depth + 1)?);
                }
                let expanded = subst_type(&map, &def.replacement);
                self.expand_type_synonyms(&expanded, depth + 1)
            }
            LType::Var(_) | LType::Nat(_) | LType::Con(_) | LType::Builtin(_) => Ok(ty.clone()),
            LType::App(f, a) => Ok(LType::app(
                self.expand_type_synonyms(f, depth + 1)?,
                self.expand_type_synonyms(a, depth + 1)?,
            )),
            LType::Forall { param, kind, body } => Ok(LType::Forall {
                param: param.clone(),
                kind: kind.clone(),
                body: Box::new(
                    self.with_tvar(param, kind.clone())
                        .expand_type_synonyms(body, depth + 1)?,
                ),
            }),
            LType::Struct(fields) => {
                let mut out = BTreeMap::new();
                for (k, v) in fields {
                    out.insert(k.clone(), self.expand_type_synonyms(v, depth + 1)?);
                }
                Ok(LType::Struct(out))
            }
        }
    }

    pub(super) fn alpha_equiv(&self, t1: &LType, t2: &LType) -> Result<bool, TypeError> {
        if alpha_equiv_nominal(t1, t2) {
            return Ok(true);
        }
        if t1.contains_syn_app() || t2.contains_syn_app() {
            let e1 = self.expand_type_synonyms(t1, 0)?;
            let e2 = self.expand_type_synonyms(t2, 0)?;
            return Ok(alpha_equiv_nominal(&e1, &e2));
        }
        Ok(false)
    }

    pub(super) fn to_function(&self, ty: &LType) -> Result<(LType, LType), TypeError> {
        if let LType::App(lhs, res) = ty {
            if let LType::App(head, arg) = &**lhs {
                if matches!(**head, LType::Builtin(BuiltinType::Arrow)) {
                    return Ok(((**arg).clone(), (**res).clone()));
                }
            }
        }
        if ty.contains_syn_app() {
            let exp = self.expand_type_synonyms(ty, 0)?;
            if let LType::App(lhs, res) = exp {
                if let LType::App(head, arg) = *lhs {
                    if matches!(*head, LType::Builtin(BuiltinType::Arrow)) {
                        return Ok((*arg, *res));
                    }
                }
            }
        }
        Err(self.err(
            "EExpectedFunctionType",
            format!("expected function type, found {}", ty.pretty()),
        ))
    }

    pub(super) fn to_forall(&self, ty: &LType) -> Result<(String, LKind, LType), TypeError> {
        if let LType::Forall { param, kind, body } = ty {
            return Ok((param.clone(), kind.clone(), (**body).clone()));
        }
        if ty.contains_syn_app() {
            if let LType::Forall { param, kind, body } = self.expand_type_synonyms(ty, 0)? {
                return Ok((param, kind, *body));
            }
        }
        Err(self.err(
            "EExpectedUniversalType",
            format!("expected universal type, found {}", ty.pretty()),
        ))
    }

    pub(super) fn to_struct(&self, ty: &LType) -> Result<BTreeMap<String, LType>, TypeError> {
        if let LType::Struct(fields) = ty {
            return Ok(fields.clone());
        }
        if ty.contains_syn_app() {
            if let LType::Struct(fields) = self.expand_type_synonyms(ty, 0)? {
                return Ok(fields);
            }
        }
        Err(self.err(
            "EExpectedStructType",
            format!("expected struct type, found {}", ty.pretty()),
        ))
    }

    pub(super) fn to_update(&self, ty: &LType) -> Result<LType, TypeError> {
        if let LType::App(head, _) = ty {
            if matches!(**head, LType::Builtin(BuiltinType::Update)) {
                return Ok(ty.clone());
            }
        }
        if ty.contains_syn_app() {
            let exp = self.expand_type_synonyms(ty, 0)?;
            if let LType::App(head, _) = &exp {
                if matches!(**head, LType::Builtin(BuiltinType::Update)) {
                    return Ok(exp);
                }
            }
        }
        Err(self.err(
            "EExpectedUpdateType",
            format!("expected Update type, found {}", ty.pretty()),
        ))
    }

    pub(super) fn check_top_expr(
        &self,
        expr: &daml_lf_2::Expr,
        expected: &LType,
    ) -> Result<(), TypeError> {
        self.check_top_expr_with_kind(expr, expected, "ETypeMismatch")
    }

    pub(super) fn check_top_expr_with_kind(
        &self,
        expr: &daml_lf_2::Expr,
        expected: &LType,
        mismatch_kind: &'static str,
    ) -> Result<(), TypeError> {
        let found = self.type_of_expr(expr)?;
        if !self.alpha_equiv(&found, expected)? {
            return Err(self.err(
                mismatch_kind,
                format!(
                    "expected type {}, found {}",
                    expected.pretty(),
                    found.pretty()
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn check_expr(
        &self,
        expr: &daml_lf_2::Expr,
        expected: &LType,
    ) -> Result<LType, TypeError> {
        let found = self.type_of_expr(expr)?;
        if !self.alpha_equiv(&found, expected)? {
            return Err(self.err(
                "ETypeMismatch",
                format!(
                    "expected type {}, found {}",
                    expected.pretty(),
                    found.pretty()
                ),
            ));
        }
        Ok(found)
    }

    pub(super) fn check_choice_typing(
        &self,
        parent_id: &Ident,
        parent_ty: &LType,
        ch: &DecodedChoice<'a>,
    ) -> Result<(), TypeError> {
        self.check_type(&ch.arg_type, &LKind::Star)?;
        self.check_type(&ch.ret_type, &LKind::Star)?;
        let ch_env = self.with_evar(&ch.arg_name, ch.arg_type.clone());
        if let Some(ctrl) = ch.controllers {
            ch_env.check_top_expr(ctrl, &LType::t_parties())?;
        }
        if let Some(obs) = ch.observers {
            ch_env.check_top_expr(obs, &LType::t_parties())?;
        }
        if let Some(auth) = ch.authorizers {
            ch_env.check_top_expr(auth, &LType::t_parties())?;
        }
        let body_env = ch_env.with_evar(&ch.self_name, LType::t_contract_id(parent_ty.clone()));
        if let Some(update) = ch.update {
            body_env.check_top_expr(update, &LType::t_update(ch.ret_type.clone()))?;
        } else {
            return Err(self.err(
                "EUnknownDefinition",
                format!(
                    "choice {} on {} missing update",
                    ch.name,
                    parent_id.pretty()
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn check_tycon_app(
        &self,
        con_id: &Ident,
        args: &[LType],
    ) -> Result<Option<DecodedDataCons>, TypeError> {
        let Some(def) = self.v.lookup_data_type(self.pkg_id, con_id)? else {
            return Ok(None);
        };
        if def.params.len() != args.len() {
            return Err(self.err(
                "ETypeConAppWrongArity",
                format!(
                    "{} expects {} type arguments, got {}",
                    con_id.pretty(),
                    def.params.len(),
                    args.len()
                ),
            ));
        }
        let mut map = HashMap::new();
        for ((p, k), arg) in def.params.iter().zip(args.iter()) {
            self.check_type(arg, k)?;
            map.insert(p.clone(), arg.clone());
        }
        let sub_list = |xs: &[(String, LType)]| -> Vec<(String, LType)> {
            xs.iter()
                .map(|(n, t)| (n.clone(), subst_type(&map, t)))
                .collect()
        };
        Ok(Some(match &def.cons {
            DecodedDataCons::Record(fs) => DecodedDataCons::Record(sub_list(fs)),
            DecodedDataCons::Variant(vs) => DecodedDataCons::Variant(sub_list(vs)),
            DecodedDataCons::Enum(es) => DecodedDataCons::Enum(es.clone()),
            DecodedDataCons::Interface => DecodedDataCons::Interface,
        }))
    }

    pub(super) fn typecon_app_to_type(con_id: &Ident, args: &[LType]) -> LType {
        let mut acc = LType::Con(con_id.clone());
        for a in args {
            acc = LType::app(acc, a.clone());
        }
        acc
    }

    pub(super) fn check_any_type(&self, ty: &LType) -> Result<(), TypeError> {
        self.check_type(ty, &LKind::Star)?;
        if self.v.is_dev(self.pkg_id) {
            fn no_polymorphic(ty: &LType) -> bool {
                match ty {
                    LType::Var(_) | LType::Forall { .. } | LType::SynApp { .. } => false,
                    LType::Nat(_) | LType::Con(_) | LType::Builtin(_) => true,
                    LType::App(f, a) => no_polymorphic(f) && no_polymorphic(a),
                    LType::Struct(fs) => fs.values().all(no_polymorphic),
                }
            }
            if !no_polymorphic(ty) {
                return Err(self.err(
                    "EExpectedAnyType",
                    format!("expected a any type but found: {}", ty.pretty()),
                ));
            }
            Ok(())
        } else {
            if let LType::Con(con_id) = ty {
                if let Some(def) = self.v.lookup_data_type(self.pkg_id, con_id)? {
                    if def.params.is_empty() {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }
            Err(self.err(
                "EExpectedAnyType",
                format!("expected a any type but found: {}", ty.pretty()),
            ))
        }
    }

    pub(super) fn check_exception_type(&self, ty: &LType) -> Result<(), TypeError> {
        match ty {
            LType::Con(ex_id) => {
                let _ = self.v.lookup_exception(self.pkg_id, ex_id)?;
                Ok(())
            }
            _ => Err(self.err(
                "EExpectedExceptionType",
                format!("expected an exception type, found {}", ty.pretty()),
            )),
        }
    }

    pub(super) fn check_interface_instance(
        &self,
        iface: &Ident,
        tpl: &Ident,
    ) -> Result<(), TypeError> {
        let Some(t) = self.v.lookup_template(self.pkg_id, tpl)? else {
            return Ok(());
        };
        if !t.implements.iter().any(|i| &i.iface == iface) {
            return Err(self.err(
                "EUnknownDefinition",
                format!(
                    "template {} does not implement interface {}",
                    tpl.pretty(),
                    iface.pretty()
                ),
            ));
        }
        Ok(())
    }

    pub(super) fn type_of_choice_parties(
        &self,
        target: &Ident,
        ch_name: &str,
        contract_expr: Option<&daml_lf_2::Expr>,
        arg_expr: Option<&daml_lf_2::Expr>,
    ) -> Result<LType, TypeError> {
        let arg_ty = if let Some(tpl) = self.v.templates.get(target) {
            let ch = tpl
                .choices
                .iter()
                .find(|c| c.name == ch_name)
                .ok_or_else(|| {
                    self.err(
                        "EUnknownDefinition",
                        format!("unknown choice {ch_name} on template {}", target.pretty()),
                    )
                })?;
            Some(ch.arg_type.clone())
        } else if let Some(iface) = self.v.interfaces.get(target) {
            let ch = iface
                .choices
                .iter()
                .find(|c| c.name == ch_name)
                .ok_or_else(|| {
                    self.err(
                        "EUnknownDefinition",
                        format!("unknown choice {ch_name} on interface {}", target.pretty()),
                    )
                })?;
            Some(ch.arg_type.clone())
        } else if !self.v.packages.contains_key(&target.pkg) {
            None
        } else {
            return Err(self.err(
                "EUnknownDefinition",
                format!("unknown template or interface {}", target.pretty()),
            ));
        };
        if let Some(ce) = contract_expr {
            self.check_expr(ce, &LType::Con(target.clone()))?;
        }
        if let (Some(ae), Some(want)) = (arg_expr, arg_ty) {
            self.check_expr(ae, &want)?;
        }
        Ok(LType::t_parties())
    }
}
