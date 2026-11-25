//! Typing of `case` expressions and `Update` expressions (`TypingEnv::type_of_case`, `TypingEnv::type_of_update`).

use std::collections::{HashMap, HashSet};

use crate::proto::daml_lf_2;
use crate::proto::daml_lf_2::update::Sum as UpdateSum;
use crate::proto::daml_lf_2::{BuiltinCon, BuiltinType};

use super::decode::{decode_type, interned_str, resolve_type_con_id, DecodedDataCons};
use super::types::{subst_type, Ident, LKind, LType};
use super::typing_env::TypingEnv;
use super::TypeError;

impl<'a, 'b> TypingEnv<'a, 'b> {
    pub(super) fn type_of_case(&self, case: &daml_lf_2::Case) -> Result<LType, TypeError> {
        use daml_lf_2::case_alt::Sum as PatSum;
        if case.alts.is_empty() {
            return Err(self.err("EEmptyCase", "empty case"));
        }
        let scrut_ty = match &case.scrut {
            Some(s) => self.type_of_expr(s)?,
            None => return Err(self.err("ETypeMismatch", "Case missing scrutinee")),
        };

        // Unwrap TTyConApp `(con_id, args)` for data types or builtins.
        enum ScrutKind<'x> {
            Variant {
                con: Ident,
                args: Vec<LType>,
                params: &'x [(String, LKind)],
                variants: &'x [(String, LType)],
            },
            Enum {
                con: Ident,
                cons: &'x [String],
            },
            Unit,
            Bool,
            List(LType),
            Optional(LType),
            DefaultOnly,
        }

        let mut head = &scrut_ty;
        let mut rev_args = Vec::new();
        while let LType::App(f, a) = head {
            rev_args.push((**a).clone());
            head = f;
        }
        rev_args.reverse();

        let scrut_kind = match (head, rev_args.as_slice()) {
            (LType::Con(con_id), _) => match self.v.lookup_data_type(self.pkg_id, con_id)? {
                Some(def) => match &def.cons {
                    DecodedDataCons::Variant(variants) => ScrutKind::Variant {
                        con: con_id.clone(),
                        args: rev_args,
                        params: &def.params,
                        variants,
                    },
                    DecodedDataCons::Enum(cons) => ScrutKind::Enum {
                        con: con_id.clone(),
                        cons,
                    },
                    DecodedDataCons::Record(_) | DecodedDataCons::Interface => {
                        ScrutKind::DefaultOnly
                    }
                },
                None => ScrutKind::DefaultOnly,
            },
            (LType::Builtin(BuiltinType::Unit), []) => ScrutKind::Unit,
            (LType::Builtin(BuiltinType::Bool), []) => ScrutKind::Bool,
            (LType::Builtin(BuiltinType::List), [elem]) => ScrutKind::List(elem.clone()),
            (LType::Builtin(BuiltinType::Optional), [elem]) => ScrutKind::Optional(elem.clone()),
            _ => ScrutKind::DefaultOnly,
        };

        let expected_ranks = match &scrut_kind {
            ScrutKind::Variant { variants, .. } => variants.len(),
            ScrutKind::Enum { cons, .. } => cons.len(),
            ScrutKind::Unit => 1,
            ScrutKind::Bool | ScrutKind::List(_) | ScrutKind::Optional(_) => 2,
            ScrutKind::DefaultOnly => 1,
        };

        let mut all_covered = false;
        let mut ranks: HashSet<usize> = HashSet::new();
        let mut result_ty: Option<LType> = None;

        for alt in &case.alts {
            let mut branch_env = self.clone();
            match (&scrut_kind, &alt.sum) {
                (_, Some(PatSum::Default(_))) => {
                    all_covered = true;
                }
                (
                    ScrutKind::Variant {
                        con,
                        args,
                        params,
                        variants,
                    },
                    Some(PatSum::Variant(v)),
                ) => {
                    let pat_con = resolve_type_con_id(self.pkg_id, self.pkg, v.con.as_ref())?;
                    if &pat_con != con {
                        return Err(self.err(
                            "EPatternTypeMismatch",
                            format!(
                                "variant pattern {} does not match scrutinee {}",
                                pat_con.pretty(),
                                scrut_ty.pretty()
                            ),
                        ));
                    }
                    let vname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        v.variant_interned_str,
                        "CaseAlt.variant",
                    )?;
                    let bname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        v.binder_interned_str,
                        "CaseAlt.binder",
                    )?;
                    let (rank, (_, con_arg_ty)) = variants
                        .iter()
                        .enumerate()
                        .find(|(_, (n, _))| n == vname)
                        .ok_or_else(|| {
                            self.err(
                                "EUnknownVariantCon",
                                format!("unknown variant constructor: {vname}"),
                            )
                        })?;
                    ranks.insert(rank);
                    let map: HashMap<String, LType> = params
                        .iter()
                        .map(|(p, _)| p.clone())
                        .zip(args.iter().cloned())
                        .collect();
                    let bound_ty = subst_type(&map, con_arg_ty);
                    branch_env.e_vars.insert(bname.to_string(), bound_ty);
                }
                (ScrutKind::Enum { con, cons }, Some(PatSum::Enum(e))) => {
                    let pat_con = resolve_type_con_id(self.pkg_id, self.pkg, e.con.as_ref())?;
                    if &pat_con != con {
                        return Err(self.err(
                            "EPatternTypeMismatch",
                            format!(
                                "enum pattern {} does not match scrutinee {}",
                                pat_con.pretty(),
                                scrut_ty.pretty()
                            ),
                        ));
                    }
                    let cname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        e.constructor_interned_str,
                        "CaseAlt.enum",
                    )?;
                    let rank = cons.iter().position(|c| c == cname).ok_or_else(|| {
                        self.err(
                            "EUnknownEnumCon",
                            format!("unknown enum constructor: {cname}"),
                        )
                    })?;
                    ranks.insert(rank);
                }
                (ScrutKind::Unit, Some(PatSum::BuiltinCon(bc)))
                    if BuiltinCon::try_from(*bc).ok() == Some(BuiltinCon::ConUnit) =>
                {
                    ranks.insert(0);
                }
                (ScrutKind::Bool, Some(PatSum::BuiltinCon(bc))) => {
                    match BuiltinCon::try_from(*bc) {
                        Ok(BuiltinCon::ConTrue) => {
                            ranks.insert(0);
                        }
                        Ok(BuiltinCon::ConFalse) => {
                            ranks.insert(1);
                        }
                        _ => {
                            return Err(self.err(
                                "EPatternTypeMismatch",
                                "pattern does not match Bool scrutinee".to_string(),
                            ));
                        }
                    }
                }
                (ScrutKind::List(_), Some(PatSum::Nil(_))) => {
                    ranks.insert(0);
                }
                (ScrutKind::List(elem), Some(PatSum::Cons(c))) => {
                    let head_v = interned_str(
                        self.pkg_id,
                        self.pkg,
                        c.var_head_interned_str,
                        "CaseAlt.head",
                    )?;
                    let tail_v = interned_str(
                        self.pkg_id,
                        self.pkg,
                        c.var_tail_interned_str,
                        "CaseAlt.tail",
                    )?;
                    if head_v == tail_v {
                        return Err(self.err(
                            "EClashingPatternVariables",
                            format!("{head_v} is used more than once in pattern"),
                        ));
                    }
                    branch_env.e_vars.insert(head_v.to_string(), elem.clone());
                    branch_env
                        .e_vars
                        .insert(tail_v.to_string(), LType::t_list(elem.clone()));
                    ranks.insert(1);
                }
                (ScrutKind::Optional(_), Some(PatSum::OptionalNone(_))) => {
                    ranks.insert(0);
                }
                (ScrutKind::Optional(elem), Some(PatSum::OptionalSome(s))) => {
                    let bname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        s.var_body_interned_str,
                        "CaseAlt.some",
                    )?;
                    branch_env.e_vars.insert(bname.to_string(), elem.clone());
                    ranks.insert(1);
                }
                (_, _) => {
                    return Err(self.err(
                        "EPatternTypeMismatch",
                        format!(
                            "pattern does not match scrutinee type {}",
                            scrut_ty.pretty()
                        ),
                    ));
                }
            }

            let body = alt
                .body
                .as_ref()
                .ok_or_else(|| self.err("ETypeMismatch", "CaseAlt missing body"))?;
            let branch_ty = branch_env.type_of_expr(body)?;
            if let Some(first_ty) = &result_ty {
                if !self.alpha_equiv(&branch_ty, first_ty)? {
                    return Err(self.err(
                        "ETypeMismatch",
                        format!(
                            "case branch type mismatch: expected {}, found {}",
                            first_ty.pretty(),
                            branch_ty.pretty()
                        ),
                    ));
                }
            } else {
                result_ty = Some(branch_ty);
            }
        }

        if !all_covered && ranks.len() < expected_ranks {
            return Err(self.err(
                "ENonExhaustivePatterns",
                format!(
                    "non-exhaustive pattern match on {}: covered {} of {expected_ranks}",
                    scrut_ty.pretty(),
                    ranks.len()
                ),
            ));
        }

        result_ty.ok_or_else(|| {
            self.err(
                "ENonExhaustivePatterns",
                "case expression with no alternatives",
            )
        })
    }

    pub(super) fn type_of_update(&self, upd: &daml_lf_2::Update) -> Result<LType, TypeError> {
        match &upd.sum {
            None => Err(self.err("ETypeMismatch", "empty Update sum")),
            Some(UpdateSum::Pure(p)) => {
                let ty = decode_type(self.pkg_id, self.pkg, p.r#type.as_ref(), 0)?;
                self.check_type(&ty, &LKind::Star)?;
                if let Some(e) = &p.expr {
                    self.check_expr(e, &ty)?;
                }
                Ok(LType::t_update(ty))
            }
            Some(UpdateSum::Block(blk)) => {
                let mut env = self.clone();
                for b in &blk.bindings {
                    let binder = b.binder.as_ref().ok_or_else(|| {
                        self.err("ETypeMismatch", "UpdateBlock binding missing binder")
                    })?;
                    let vname = interned_str(
                        self.pkg_id,
                        self.pkg,
                        binder.var_interned_str,
                        "UpdateBlock.var",
                    )?;
                    let ty = decode_type(self.pkg_id, self.pkg, binder.r#type.as_ref(), 0)?;
                    env.check_type(&ty, &LKind::Star)?;
                    if let Some(bound) = &b.bound {
                        env.check_expr(bound, &LType::t_update(ty.clone()))?;
                    }
                    env.e_vars.insert(vname.to_string(), ty);
                }
                let body_ty = match &blk.body {
                    Some(body) => env.type_of_expr(body)?,
                    None => return Err(self.err("ETypeMismatch", "UpdateBlock missing body")),
                };
                self.to_update(&body_ty)
            }
            Some(UpdateSum::Create(c)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, c.template.as_ref())?;
                let _ = self.v.lookup_template(self.pkg_id, &tpl)?;
                let tpl_ty = LType::Con(tpl);
                if let Some(e) = &c.expr {
                    self.check_expr(e, &tpl_ty)?;
                }
                Ok(LType::t_update(LType::t_contract_id(tpl_ty)))
            }
            Some(UpdateSum::CreateInterface(ci)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, ci.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                let if_ty = LType::Con(iface);
                if let Some(e) = &ci.expr {
                    self.check_expr(e, &if_ty)?;
                }
                Ok(LType::t_update(LType::t_contract_id(if_ty)))
            }
            Some(UpdateSum::Exercise(ex)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, ex.template.as_ref())?;
                let cname = interned_str(
                    self.pkg_id,
                    self.pkg,
                    ex.choice_interned_str,
                    "Exercise.choice",
                )?;
                let tpl_ty = LType::Con(tpl.clone());
                let (arg_ty, ret_ty) = match self.v.lookup_template(self.pkg_id, &tpl)? {
                    Some(t) => {
                        let ch = t.choices.iter().find(|c| c.name == cname).ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("unknown choice {cname} on template {}", tpl.pretty()),
                            )
                        })?;
                        (ch.arg_type.clone(), ch.ret_type.clone())
                    }
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external template {} not loaded", tpl.pretty()),
                        ));
                    }
                };
                if let Some(cid) = &ex.cid {
                    self.check_expr(cid, &LType::t_contract_id(tpl_ty))?;
                }
                if let Some(arg) = &ex.arg {
                    self.check_expr(arg, &arg_ty)?;
                }
                Ok(LType::t_update(ret_ty))
            }
            Some(UpdateSum::ExerciseInterface(ex)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, ex.interface.as_ref())?;
                let cname = interned_str(
                    self.pkg_id,
                    self.pkg,
                    ex.choice_interned_str,
                    "ExerciseInterface.choice",
                )?;
                let if_ty = LType::Con(iface.clone());
                if let Some(cid) = &ex.cid {
                    self.check_expr(cid, &LType::t_contract_id(if_ty.clone()))?;
                }
                let (arg_ty, ret_ty) = match self.v.lookup_interface(self.pkg_id, &iface)? {
                    Some(def) => {
                        let ch = def
                            .choices
                            .iter()
                            .find(|c| c.name == cname)
                            .ok_or_else(|| {
                                self.err(
                                    "EUnknownDefinition",
                                    format!(
                                        "unknown choice {cname} on interface {}",
                                        iface.pretty()
                                    ),
                                )
                            })?;
                        (ch.arg_type.clone(), ch.ret_type.clone())
                    }
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external interface {} not loaded", iface.pretty()),
                        ));
                    }
                };
                if let Some(arg) = &ex.arg {
                    self.check_expr(arg, &arg_ty)?;
                }
                if let Some(guard) = &ex.guard {
                    self.check_expr(guard, &LType::arrow(if_ty, LType::t_bool()))?;
                }
                Ok(LType::t_update(ret_ty))
            }
            Some(UpdateSum::ExerciseByKey(ex)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, ex.template.as_ref())?;
                let cname = interned_str(
                    self.pkg_id,
                    self.pkg,
                    ex.choice_interned_str,
                    "ExerciseByKey.choice",
                )?;
                let (key_ty, arg_ty, ret_ty) = match self.v.lookup_template(self.pkg_id, &tpl)? {
                    Some(t) => {
                        let k = t.key.as_ref().ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("template {} has no key", tpl.pretty()),
                            )
                        })?;
                        let ch = t.choices.iter().find(|c| c.name == cname).ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("unknown choice {cname} on template {}", tpl.pretty()),
                            )
                        })?;
                        (k.typ.clone(), ch.arg_type.clone(), ch.ret_type.clone())
                    }
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external template {} not loaded", tpl.pretty()),
                        ));
                    }
                };
                if let Some(kexpr) = &ex.key {
                    self.check_expr(kexpr, &key_ty)?;
                }
                if let Some(arg) = &ex.arg {
                    self.check_expr(arg, &arg_ty)?;
                }
                Ok(LType::t_update(ret_ty))
            }
            Some(UpdateSum::Fetch(f)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, f.template.as_ref())?;
                let _ = self.v.lookup_template(self.pkg_id, &tpl)?;
                let tpl_ty = LType::Con(tpl);
                if let Some(cid) = &f.cid {
                    self.check_expr(cid, &LType::t_contract_id(tpl_ty.clone()))?;
                }
                Ok(LType::t_update(tpl_ty))
            }
            Some(UpdateSum::UnpackTemplate(u)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, u.template.as_ref())?;
                let _ = self.v.lookup_template(self.pkg_id, &tpl)?;
                let tpl_ty = LType::Con(tpl);
                if let Some(cid) = &u.cid {
                    self.check_expr(cid, &LType::t_contract_id(tpl_ty.clone()))?;
                }
                Ok(LType::t_update(tpl_ty))
            }
            Some(UpdateSum::FetchInterface(fi)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, fi.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                let if_ty = LType::Con(iface);
                if let Some(cid) = &fi.cid {
                    self.check_expr(cid, &LType::t_contract_id(if_ty.clone()))?;
                }
                Ok(LType::t_update(if_ty))
            }
            Some(UpdateSum::UnpackInterface(ui)) => {
                let iface = resolve_type_con_id(self.pkg_id, self.pkg, ui.interface.as_ref())?;
                let _ = self.v.lookup_interface(self.pkg_id, &iface)?;
                let if_ty = LType::Con(iface);
                if let Some(cid) = &ui.cid {
                    self.check_expr(cid, &LType::t_contract_id(if_ty.clone()))?;
                }
                Ok(LType::t_update(if_ty))
            }
            Some(UpdateSum::GetTime(_)) => Ok(LType::t_update(LType::t_timestamp())),
            Some(UpdateSum::LedgerTimeLt(e)) => {
                self.check_expr(e, &LType::t_timestamp())?;
                Ok(LType::t_update(LType::t_bool()))
            }
            Some(UpdateSum::EmbedExpr(ee)) => {
                let ty = decode_type(self.pkg_id, self.pkg, ee.r#type.as_ref(), 0)?;
                self.check_type(&ty, &LKind::Star)?;
                let upd_ty = LType::t_update(ty);
                if let Some(body) = &ee.body {
                    self.check_expr(body, &upd_ty)?;
                }
                Ok(upd_ty)
            }
            Some(UpdateSum::FetchByKey(fk)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, fk.template.as_ref())?;
                let key_ty = match self.v.lookup_template(self.pkg_id, &tpl)? {
                    Some(t) => t
                        .key
                        .as_ref()
                        .ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("template {} has no key", tpl.pretty()),
                            )
                        })?
                        .typ
                        .clone(),
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external template {} not loaded", tpl.pretty()),
                        ));
                    }
                };
                let tpl_ty = LType::Con(tpl);
                Ok(LType::arrow(
                    key_ty,
                    LType::t_update(LType::t_tuple2(
                        LType::t_contract_id(tpl_ty.clone()),
                        tpl_ty,
                    )),
                ))
            }
            Some(UpdateSum::QueryNByKey(qk)) => {
                let tpl = resolve_type_con_id(self.pkg_id, self.pkg, qk.template.as_ref())?;
                let key_ty = match self.v.lookup_template(self.pkg_id, &tpl)? {
                    Some(t) => t
                        .key
                        .as_ref()
                        .ok_or_else(|| {
                            self.err(
                                "EUnknownDefinition",
                                format!("template {} has no key", tpl.pretty()),
                            )
                        })?
                        .typ
                        .clone(),
                    None => {
                        return Err(self.err(
                            "EUnknownDefinition",
                            format!("external template {} not loaded", tpl.pretty()),
                        ));
                    }
                };
                let tpl_ty = LType::Con(tpl);
                Ok(LType::arrow(
                    LType::t_int64(),
                    LType::arrow(
                        key_ty,
                        LType::t_update(LType::t_optional(LType::t_list(LType::t_tuple2(
                            LType::t_contract_id(tpl_ty.clone()),
                            tpl_ty,
                        )))),
                    ),
                ))
            }
            Some(UpdateSum::TryCatch(tc)) => {
                let ret_ty = decode_type(self.pkg_id, self.pkg, tc.return_type.as_ref(), 0)?;
                self.check_type(&ret_ty, &LKind::Star)?;
                let upd_ret = LType::t_update(ret_ty);
                if let Some(te) = &tc.try_expr {
                    self.check_expr(te, &upd_ret)?;
                }
                let var_name =
                    interned_str(self.pkg_id, self.pkg, tc.var_interned_str, "TryCatch.var")?;
                if let Some(ce) = &tc.catch_expr {
                    self.with_evar(var_name, LType::t_any_exception())
                        .check_expr(ce, &LType::t_optional(upd_ret.clone()))?;
                }
                Ok(upd_ret)
            }
        }
    }
}
