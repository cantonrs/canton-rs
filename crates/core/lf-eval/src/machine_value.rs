//! Machine: returning values to continuation frames, `case` matching and reduction of applications.

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{BuiltinCon, Expr, Type};
use lf_archive::resolve_interned_string;

use crate::env::{Env, TypeEnv};
use crate::eval_builtins::{arity, exec_builtin_checked};
use crate::eval_error::EvalError;
use crate::kont::Kont;
use crate::list::List;
use crate::update_host::{ExerciseRequest, FetchRequest, MAX_CONTRACT_KEY_FETCHES};
use crate::value::Value;
use crate::value_nesting::check_nesting;
use crate::{
    Control, Ledger, Machine, ANY_EXCEPTION_MESSAGE, ARITHMETIC_ERROR, CONTRACT_ID_TO_TEXT,
    EQUAL_LIST, FOLDL, FOLDR,
};

impl<'a> Machine<'a> {
    pub(super) fn step_value(&mut self, value: Value) -> Result<(), EvalError> {
        let Some(kont) = self.kont.pop() else {
            self.control = Control::Value(value);
            return Ok(());
        };
        match kont {
            Kont::ArgsRev {
                fun,
                mut pending,
                mut collected_rev,
                env,
                type_env,
                package_id,
            } => {
                collected_rev.push(value);
                if let Some(next) = pending.pop() {
                    self.kont.push(Kont::ArgsRev {
                        fun,
                        pending,
                        collected_rev,
                        env: env.clone(),
                        type_env: type_env.clone(),
                        package_id: package_id.clone(),
                    });
                    self.enter(next, env, type_env, package_id);
                    return Ok(());
                }
                collected_rev.reverse();
                self.kont.push(Kont::ApplyValues {
                    args: collected_rev,
                });
                self.enter(fun, env, type_env, package_id);
                Ok(())
            }
            Kont::Args {
                func,
                mut rest,
                env,
                type_env,
                package_id,
            } => {
                let func = match func {
                    None => value,
                    Some(func) => {
                        let reduced = reduce_app(func, value, self.ledger)?;
                        return self.finish_reduced(reduced, rest, env, type_env, package_id);
                    }
                };
                if rest.is_empty() {
                    self.control = Control::Value(func);
                    return Ok(());
                }
                let arg = rest.remove(0);
                self.kont.push(Kont::Args {
                    func: Some(func),
                    rest,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                });
                self.enter(arg, env, type_env, package_id);
                Ok(())
            }
            Kont::ApplyValues { mut args } => {
                if args.is_empty() {
                    self.control = Control::Value(value);
                    return Ok(());
                }
                let arg = args.remove(0);
                if !args.is_empty() {
                    self.kont.push(Kont::ApplyValues { args });
                }
                let reduced = reduce_app(value, arg, self.ledger)?;
                self.finish_reduced(
                    reduced,
                    Vec::new(),
                    self.env.clone(),
                    self.type_env.clone(),
                    self.package_id.clone(),
                )
            }
            Kont::Types { types, keys } => {
                let reduced = apply_types(value, &types, &keys)?;
                self.finish_reduced(
                    reduced,
                    Vec::new(),
                    self.env.clone(),
                    self.type_env.clone(),
                    self.package_id.clone(),
                )
            }
            Kont::StructField {
                is_record,
                tycon,
                mut got,
                mut rest,
                env,
                type_env,
                package_id,
            } => {
                if let Some(last) = got.last_mut() {
                    last.1 = value;
                }
                if rest.is_empty() {
                    if !is_record {
                        // [CANTON-NOTE: SEMANTICS] Speedy `SBStructCon` evaluates fields in source order
                        // and sorts the resulting struct canonically by field name for comparison.
                        got.sort_by(|a, b| a.0.cmp(&b.0));
                    }
                    self.control = Control::Value(if is_record {
                        Value::Record { tycon, fields: got }
                    } else {
                        Value::Struct(got)
                    });
                    return Ok(());
                }
                let (name, expr) = rest.remove(0);
                got.push((name, Value::Unit));
                self.kont.push(Kont::StructField {
                    is_record,
                    tycon,
                    got,
                    rest,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                });
                self.enter(expr, env, type_env, package_id);
                Ok(())
            }
            Kont::FieldProj { field } => {
                let fields = match &value {
                    Value::Record { fields, .. } | Value::Struct(fields) => fields,
                    _ => return Err(EvalError::unsupported()),
                };
                let projected = fields
                    .iter()
                    .find(|(name, _)| name == &field)
                    .map(|(_, v)| v.clone())
                    .ok_or(EvalError::unsupported())?;
                self.control = Control::Value(projected);
                Ok(())
            }
            Kont::FieldUpdRecord {
                field,
                update,
                env,
                type_env,
                package_id,
            } => {
                self.kont.push(Kont::FieldUpdValue {
                    record: value,
                    field,
                });
                self.enter(update, env, type_env, package_id);
                Ok(())
            }
            Kont::FieldUpdValue { mut record, field } => {
                let fields = match &mut record {
                    Value::Record { fields, .. } | Value::Struct(fields) => fields,
                    _ => return Err(EvalError::unsupported()),
                };
                let slot = fields
                    .iter_mut()
                    .find(|(name, _)| name == &field)
                    .ok_or(EvalError::unsupported())?;
                slot.1 = value;
                self.control = Control::Value(record);
                Ok(())
            }
            Kont::VariantCon {
                tycon,
                constructor,
                rank,
            } => {
                self.control = Control::Value(Value::Variant {
                    tycon,
                    constructor,
                    rank,
                    value: Box::new(value),
                });
                Ok(())
            }
            Kont::OptionalSome => {
                self.control = Control::Value(Value::Optional(Some(Box::new(value))));
                Ok(())
            }
            Kont::CacheVal { key } => {
                self.world.val_cache.put(key, value.clone());
                self.control = Control::Value(value);
                Ok(())
            }
            Kont::ConsFront {
                mut got,
                mut rest_front,
                tail,
                env,
                type_env,
                package_id,
            } => {
                got.push(value);
                if rest_front.is_empty() {
                    self.kont.push(Kont::ConsTail { front: got });
                    self.enter(tail, env, type_env, package_id);
                    return Ok(());
                }
                let next = rest_front.remove(0);
                self.kont.push(Kont::ConsFront {
                    got,
                    rest_front,
                    tail,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                });
                self.enter(next, env, type_env, package_id);
                Ok(())
            }
            Kont::ConsTail { front } => match value {
                Value::List(tail) => {
                    // [CANTON-NOTE: WHY] the elements are consed onto the shared tail: no copy of the tail (U-15)
                    self.control = Control::Value(Value::List(tail.prepend_all(front)));
                    Ok(())
                }
                _ => Err(EvalError::unsupported()),
            },
            Kont::Case {
                alts,
                env,
                type_env,
                package_id,
            } => self.step_case(value, alts, env, type_env, package_id),
            Kont::LetBind {
                binder,
                mut rest,
                body,
                mut env,
                type_env,
                package_id,
            } => {
                env.push((binder, value));
                if rest.is_empty() {
                    self.enter(body, env, type_env, package_id);
                    return Ok(());
                }
                let (next_binder, expr) = rest.remove(0);
                self.kont.push(Kont::LetBind {
                    binder: next_binder,
                    rest,
                    body,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                });
                self.enter(expr, env, type_env, package_id);
                Ok(())
            }
            Kont::Throw { exception_tycon } => {
                // `throw @σ @τ e` is `ToAnyException @τ e` followed by raising it. The
                // type annotation wins over the record's runtime tag (see
                // `Value::AnyException`); an already-wrapped value is raised as is.
                let exception = match value {
                    exception @ Value::AnyException { .. } => exception,
                    payload => {
                        let tycon = exception_tycon
                            .or_else(|| match &payload {
                                Value::Record { tycon, .. } => tycon.clone(),
                                _ => None,
                            })
                            .unwrap_or_else(|| "Exception".into());
                        Value::AnyException {
                            tycon,
                            payload: Box::new(payload),
                        }
                    }
                };
                Err(EvalError::Thrown(Box::new(exception)))
            }
            Kont::ToAnyException { tycon } => {
                self.control = Control::Value(Value::AnyException {
                    tycon,
                    payload: Box::new(value),
                });
                Ok(())
            }
            Kont::FromAnyException { tycon } => {
                let Value::AnyException {
                    tycon: actual,
                    payload,
                } = value
                else {
                    return Err(EvalError::unsupported());
                };
                // Exact static-type match only; Daml has no exception subtyping.
                self.control = Control::Value(Value::Optional(if actual == tycon {
                    Some(payload)
                } else {
                    None
                }));
                Ok(())
            }
            Kont::Catch { checkpoint, .. } => {
                // Body finished without an exception: keep its effects, drop the checkpoint.
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                host.end_try(checkpoint)?;
                self.control = Control::Value(value);
                Ok(())
            }
            Kont::CatchResult { exception } => match value {
                // The try frame is gone already, so exceptions thrown by the handler's
                // own action propagate to the *enclosing* try, as in Daml.
                Value::Optional(Some(action)) => {
                    self.kont.push(Kont::Run);
                    self.control = Control::Value(*action);
                    Ok(())
                }
                Value::Optional(None) => Err(EvalError::Thrown(Box::new(exception))),
                _ => Err(EvalError::unsupported()),
            },
            Kont::Operands(frame) => self.step_operands(*frame, value),
            Kont::UpdateCreate {
                package_id,
                template_id,
            } => {
                check_nesting(&value)?;
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let cid = host.create_contract_in(&package_id, &template_id, &value)?;
                self.control = Control::Value(Value::ContractId(cid));
                Ok(())
            }
            Kont::Run => match value {
                // Resume a suspended Update: restore the environment it captured when it was
                // built, not the one that happens to be current where it is run.
                Value::Action {
                    expr,
                    env,
                    type_env,
                    package_id,
                } => {
                    self.env = env;
                    self.type_env = type_env;
                    self.package_id = package_id;
                    self.control = Control::Run(*expr);
                    Ok(())
                }
                Value::KeyAction {
                    query_n,
                    package_id,
                    template_id,
                    key,
                    n,
                } => {
                    if n < 1 {
                        // [CANTON-NOTE: DEFENSIVE] Daml's `lookupNByKey` returned an empty list for n = 0 on the JVM
                        // (`queryNZero`), so this is only reachable from hand-written LF. Speedy crashes (not a Daml exception) on a non-positive n.
                        return Err(EvalError::Host(format!(
                            "Invalid argument n for QueryNByKey: {n}. Expected a positive integer."
                        )));
                    }
                    let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                    let found = host.lookup_by_key(
                        &package_id,
                        &template_id,
                        &key,
                        n.min(MAX_CONTRACT_KEY_FETCHES) as usize,
                        query_n,
                    )?;
                    // [CANTON-NOTE: SEMANTICS] `fetchByKey` returns `(ContractId, payload)` and `queryNByKey`
                    // `Some [(ContractId, payload)]`, both as `DA.Types:Tuple2` (Speedy `SPair`/`Tuple2`).
                    let pair = |cid: String, payload: Value| Value::Record {
                        tycon: Some("DA.Types:Tuple2".to_string()),
                        fields: vec![
                            ("_1".to_string(), Value::ContractId(cid)),
                            ("_2".to_string(), payload),
                        ],
                    };
                    self.control = Control::Value(if query_n {
                        Value::Optional(Some(Box::new(Value::List(
                            found.into_iter().map(|(c, p)| pair(c, p)).collect(),
                        ))))
                    } else {
                        let (cid, payload) =
                            found
                                .into_iter()
                                .next()
                                .ok_or(EvalError::ContractKeyNotFound {
                                    template_id: template_id.clone(),
                                })?;
                        // [CANTON-NOTE: SEMANTICS] `fetchByKey` also records a fetch node for the contract it found
                        // (`SBUInsertFetchNode`), `queryNByKey` records a query node instead; the journal here only
                        // has fetch events.
                        host.fetch(&FetchRequest {
                            package_id: &package_id,
                            template_id: &template_id,
                            contract_id: &cid,
                        })?;
                        pair(cid, payload)
                    });
                    Ok(())
                }
                _ => Err(EvalError::NotAnUpdate),
            },
            Kont::UpdBind {
                binder,
                mut rest,
                body,
                mut env,
                type_env,
                package_id,
            } => {
                // `value` is the *result* of the previous bound action (it has been run),
                // which is what Daml's `x <- action` binds.
                env.push((binder, value));
                if rest.is_empty() {
                    self.enter_run(body, env, type_env, package_id);
                    return Ok(());
                }
                let (next_binder, expr) = rest.remove(0);
                self.kont.push(Kont::UpdBind {
                    binder: next_binder,
                    rest,
                    body,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                });
                self.enter_run(expr, env, type_env, package_id);
                Ok(())
            }
            Kont::ExerciseCid {
                template,
                choice,
                arg,
                env,
                type_env,
                package_id,
            } => {
                let Value::ContractId(cid) = value else {
                    return Err(EvalError::unsupported());
                };
                self.kont.push(Kont::ExerciseArg {
                    template,
                    choice,
                    cid,
                });
                self.enter(arg, env, type_env, package_id);
                Ok(())
            }
            Kont::ExerciseArg {
                template,
                choice,
                cid,
            } => {
                check_nesting(&value)?;
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let result = host.exercise(&ExerciseRequest {
                    package_id: &template.package_id,
                    template_id: &template.template_id,
                    contract_id: &cid,
                    choice: &choice,
                    arg: &value,
                })?;
                check_nesting(&result)?;
                self.control = Control::Value(result);
                Ok(())
            }
            Kont::FetchCid { template } => {
                let Value::ContractId(cid) = value else {
                    return Err(EvalError::unsupported());
                };
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let payload = host.fetch(&FetchRequest {
                    package_id: &template.package_id,
                    template_id: &template.template_id,
                    contract_id: &cid,
                })?;
                self.control = Control::Value(payload);
                Ok(())
            }
            Kont::Foldl { func, items } => {
                // [CANTON-NOTE: WHY] `uncons` is O(1); `Vec::remove(0)` made a left fold over n elements O(n^2) (U-15)
                let Some((item, rest_items)) = items.uncons().map(|(h, t)| (h.clone(), t.clone()))
                else {
                    self.control = Control::Value(value);
                    return Ok(());
                };
                if !rest_items.is_empty() {
                    self.kont.push(Kont::Foldl {
                        func: func.clone(),
                        items: rest_items,
                    });
                }
                self.kont.push(Kont::ApplyValues {
                    args: vec![value, item],
                });
                self.control = Control::Value(func);
                Ok(())
            }
            Kont::Foldr { func, mut items } => {
                let Some(item) = items.pop() else {
                    self.control = Control::Value(value);
                    return Ok(());
                };
                if !items.is_empty() {
                    self.kont.push(Kont::Foldr {
                        func: func.clone(),
                        items,
                    });
                }
                self.kont.push(Kont::ApplyValues {
                    args: vec![item, value],
                });
                self.control = Control::Value(func);
                Ok(())
            }
            Kont::LedgerTimeLt => {
                let Value::Int64(operand) = value else {
                    return Err(EvalError::unsupported());
                };
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                self.control = Control::Value(Value::Bool(host.get_time()? < operand));
                Ok(())
            }
            Kont::EqualList { func, xs, ys } => match value {
                Value::Bool(true) => {
                    self.equal_list_step(func, xs, ys);
                    Ok(())
                }
                Value::Bool(false) => {
                    self.control = Control::Value(Value::Bool(false));
                    Ok(())
                }
                _ => Err(EvalError::unsupported()),
            },
        }
    }

    /// `EQUAL_LIST` (Speedy `SBEqualList`): compare the lists pairwise in order with `func`, stopping at the
    /// first `False`; lists of different length are unequal.
    fn equal_list_step(&mut self, func: Value, mut xs: Vec<Value>, mut ys: Vec<Value>) {
        if xs.is_empty() || ys.is_empty() {
            self.control = Control::Value(Value::Bool(xs.is_empty() && ys.is_empty()));
            return;
        }
        let x = xs.remove(0);
        let y = ys.remove(0);
        self.kont.push(Kont::EqualList {
            func: func.clone(),
            xs,
            ys,
        });
        self.kont.push(Kont::ApplyValues { args: vec![x, y] });
        self.control = Control::Value(func);
    }

    fn step_case(
        &mut self,
        scrut: Value,
        alts: Vec<daml_lf_2::CaseAlt>,
        mut env: Env,
        type_env: TypeEnv,
        package_id: String,
    ) -> Result<(), EvalError> {
        let package =
            self.world
                .packages
                .get(&package_id)
                .ok_or_else(|| EvalError::MissingDef {
                    module: package_id.clone(),
                    name: "package".to_string(),
                })?;
        for alt in alts {
            let body = alt.body.ok_or(EvalError::unsupported())?;
            let Some(sum) = alt.sum else {
                return Err(EvalError::unsupported());
            };
            match sum {
                daml_lf_2::case_alt::Sum::Default(_) => {
                    self.enter(body, env, type_env, package_id);
                    return Ok(());
                }
                daml_lf_2::case_alt::Sum::BuiltinCon(code) => {
                    let matched = matches!(
                        (BuiltinCon::try_from(code), &scrut),
                        (Ok(BuiltinCon::ConUnit), Value::Unit)
                            | (Ok(BuiltinCon::ConTrue), Value::Bool(true))
                            | (Ok(BuiltinCon::ConFalse), Value::Bool(false))
                    );
                    if matched {
                        self.enter(body, env, type_env, package_id);
                        return Ok(());
                    }
                }
                daml_lf_2::case_alt::Sum::Nil(_) => {
                    if let Value::List(items) = &scrut {
                        if items.is_empty() {
                            self.enter(body, env, type_env, package_id);
                            return Ok(());
                        }
                    }
                }
                daml_lf_2::case_alt::Sum::Cons(cons_alt) => {
                    if let Value::List(items) = &scrut {
                        if let Some((head, tail)) = items.uncons() {
                            let head_name = resolve_interned_string(
                                package,
                                cons_alt.var_head_interned_str,
                                "CaseAlt.Cons.head",
                            )
                            .map_err(|err| EvalError::Archive(err.to_string()))?;
                            let tail_name = resolve_interned_string(
                                package,
                                cons_alt.var_tail_interned_str,
                                "CaseAlt.Cons.tail",
                            )
                            .map_err(|err| EvalError::Archive(err.to_string()))?;
                            env.push((head_name, head.clone()));
                            env.push((tail_name, Value::List(tail.clone())));
                            self.enter(body, env, type_env, package_id);
                            return Ok(());
                        }
                    }
                }
                daml_lf_2::case_alt::Sum::OptionalNone(_) => {
                    if let Value::Optional(None) = &scrut {
                        self.enter(body, env, type_env, package_id);
                        return Ok(());
                    }
                }
                daml_lf_2::case_alt::Sum::OptionalSome(some_alt) => {
                    if let Value::Optional(Some(inner)) = &scrut {
                        let binder = resolve_interned_string(
                            package,
                            some_alt.var_body_interned_str,
                            "CaseAlt.OptionalSome.binder",
                        )
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                        env.push((binder, (**inner).clone()));
                        self.enter(body, env, type_env, package_id);
                        return Ok(());
                    }
                }
                daml_lf_2::case_alt::Sum::Variant(var_alt) => {
                    if let Value::Variant {
                        constructor, value, ..
                    } = &scrut
                    {
                        let target_con = resolve_interned_string(
                            package,
                            var_alt.variant_interned_str,
                            "CaseAlt.Variant.con",
                        )
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                        if constructor == &target_con {
                            let binder = resolve_interned_string(
                                package,
                                var_alt.binder_interned_str,
                                "CaseAlt.Variant.binder",
                            )
                            .map_err(|err| EvalError::Archive(err.to_string()))?;
                            env.push((binder, (**value).clone()));
                            self.enter(body, env, type_env, package_id);
                            return Ok(());
                        }
                    }
                }
                daml_lf_2::case_alt::Sum::Enum(enum_alt) => {
                    if let Value::Enum { constructor, .. } = &scrut {
                        let target_con = resolve_interned_string(
                            package,
                            enum_alt.constructor_interned_str,
                            "CaseAlt.Enum.con",
                        )
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                        if constructor == &target_con {
                            self.enter(body, env, type_env, package_id);
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(EvalError::unsupported())
    }

    fn finish_reduced(
        &mut self,
        reduced: Reduced,
        rest: Vec<Expr>,
        arg_env: Env,
        arg_type_env: TypeEnv,
        arg_package_id: String,
    ) -> Result<(), EvalError> {
        match reduced {
            Reduced::Value(value) => {
                if rest.is_empty() {
                    self.control = Control::Value(value);
                    return Ok(());
                }
                let mut rest = rest;
                let arg = rest.remove(0);
                self.kont.push(Kont::Args {
                    func: Some(value),
                    rest,
                    env: arg_env.clone(),
                    type_env: arg_type_env.clone(),
                    package_id: arg_package_id.clone(),
                });
                self.enter(arg, arg_env, arg_type_env, arg_package_id);
                Ok(())
            }
            Reduced::ExceptionMessage { tycon, payload } => {
                // [CANTON-NOTE: SEMANTICS] Speedy `SBAnyExceptionMessage`: the message of an exception is whatever its
                // `message` definition (`DefException.message`, a function from the exception record to Text)
                // computes; only `ArithmeticError` is special-cased to its first field.
                // [CANTON-NOTE: LIMITATION] The exception type is known here as `Module:Name` without a package id, so
                // the current package is searched first and then every other one; two packages that both define
                // `Module:Name` as an exception would be confused.
                let world = self.world;
                let found = if tycon == ARITHMETIC_ERROR {
                    None
                } else {
                    world.find_exception_message(&self.package_id, &tycon)?
                };
                let Some((package_id, message)) = found else {
                    let text = match &payload {
                        Value::Record { fields, .. } => fields
                            .first()
                            .map(|(_, v)| v.clone())
                            .ok_or(EvalError::unsupported())?,
                        other => other.clone(),
                    };
                    return self.finish_reduced(
                        Reduced::Value(text),
                        rest,
                        arg_env,
                        arg_type_env,
                        arg_package_id,
                    );
                };
                if !rest.is_empty() {
                    self.kont.push(Kont::Args {
                        func: None,
                        rest,
                        env: arg_env,
                        type_env: arg_type_env,
                        package_id: arg_package_id,
                    });
                }
                self.kont.push(Kont::ApplyValues {
                    args: vec![payload],
                });
                self.enter(message, Env::new(), Vec::new(), package_id);
                Ok(())
            }
            Reduced::Enter {
                expr,
                env,
                type_env,
                package_id,
            } => {
                if !rest.is_empty() {
                    self.kont.push(Kont::Args {
                        func: None,
                        rest,
                        env: arg_env,
                        type_env: arg_type_env,
                        package_id: arg_package_id,
                    });
                }
                self.enter(expr, env, type_env, package_id);
                Ok(())
            }
            Reduced::Foldl { func, acc, items } => {
                if !rest.is_empty() {
                    self.kont.push(Kont::Args {
                        func: None,
                        rest,
                        env: arg_env,
                        type_env: arg_type_env,
                        package_id: arg_package_id,
                    });
                }
                let Some((item, rest_items)) = items.uncons().map(|(h, t)| (h.clone(), t.clone()))
                else {
                    self.control = Control::Value(acc);
                    return Ok(());
                };
                if !rest_items.is_empty() {
                    self.kont.push(Kont::Foldl {
                        func: func.clone(),
                        items: rest_items,
                    });
                }
                self.kont.push(Kont::ApplyValues {
                    args: vec![acc, item],
                });
                self.control = Control::Value(func);
                Ok(())
            }
            Reduced::Foldr {
                func,
                acc,
                mut items,
            } => {
                if !rest.is_empty() {
                    self.kont.push(Kont::Args {
                        func: None,
                        rest,
                        env: arg_env,
                        type_env: arg_type_env,
                        package_id: arg_package_id,
                    });
                }
                let Some(item) = items.pop() else {
                    self.control = Control::Value(acc);
                    return Ok(());
                };
                if !items.is_empty() {
                    self.kont.push(Kont::Foldr {
                        func: func.clone(),
                        items,
                    });
                }
                self.kont.push(Kont::ApplyValues {
                    args: vec![item, acc],
                });
                self.control = Control::Value(func);
                Ok(())
            }
            Reduced::EqualList { func, xs, ys } => {
                if !rest.is_empty() {
                    self.kont.push(Kont::Args {
                        func: None,
                        rest,
                        env: arg_env,
                        type_env: arg_type_env,
                        package_id: arg_package_id,
                    });
                }
                self.equal_list_step(func, xs, ys);
                Ok(())
            }
        }
    }
}

enum Reduced {
    Value(Value),
    Enter {
        expr: Expr,
        env: Env,
        type_env: TypeEnv,
        package_id: String,
    },
    Foldl {
        func: Value,
        acc: Value,
        items: List,
    },
    Foldr {
        func: Value,
        acc: Value,
        items: Vec<Value>,
    },
    EqualList {
        func: Value,
        xs: Vec<Value>,
        ys: Vec<Value>,
    },
    /// `ANY_EXCEPTION_MESSAGE e`: needs the package (the exception's `message` definition), so the machine finishes it.
    ExceptionMessage {
        tycon: String,
        payload: Value,
    },
}

fn reduce_app(fun: Value, arg: Value, ledger: Ledger) -> Result<Reduced, EvalError> {
    match fun {
        Value::Closure {
            mut params,
            body,
            mut env,
            package_id,
            type_env,
        } => {
            let name = params.remove(0);
            env.push((name, arg));
            if params.is_empty() {
                Ok(Reduced::Enter {
                    expr: body,
                    env,
                    type_env,
                    package_id,
                })
            } else {
                Ok(Reduced::Value(Value::Closure {
                    params,
                    body,
                    env,
                    package_id,
                    type_env,
                }))
            }
        }
        Value::Partial {
            builtin,
            types,
            mut args,
        } => {
            args.push(arg);
            if args.len() >= arity(builtin) {
                if builtin == FOLDL {
                    let [func, acc, Value::List(items)] =
                        <[Value; 3]>::try_from(args).map_err(|_| EvalError::unsupported())?
                    else {
                        return Err(EvalError::unsupported());
                    };
                    return Ok(Reduced::Foldl { func, acc, items });
                }
                if builtin == FOLDR {
                    let [func, acc, Value::List(items)] =
                        <[Value; 3]>::try_from(args).map_err(|_| EvalError::unsupported())?
                    else {
                        return Err(EvalError::unsupported());
                    };
                    return Ok(Reduced::Foldr {
                        func,
                        acc,
                        items: items.to_vec(),
                    });
                }
                if builtin == ANY_EXCEPTION_MESSAGE {
                    let [Value::AnyException { tycon, payload }] =
                        <[Value; 1]>::try_from(args).map_err(|_| EvalError::unsupported())?
                    else {
                        return Err(EvalError::unsupported());
                    };
                    return Ok(Reduced::ExceptionMessage {
                        tycon,
                        payload: *payload,
                    });
                }
                if builtin == EQUAL_LIST {
                    let [func, Value::List(xs), Value::List(ys)] =
                        <[Value; 3]>::try_from(args).map_err(|_| EvalError::unsupported())?
                    else {
                        return Err(EvalError::unsupported());
                    };
                    return Ok(Reduced::EqualList {
                        func,
                        xs: xs.to_vec(),
                        ys: ys.to_vec(),
                    });
                }
                // [CANTON-NOTE: SEMANTICS] Speedy `SBContractIdToText`: `Some` text in a `PureMachine`, `None` in an
                // `UpdateMachine` or `CmdMachine`, so a transaction never depends on a contract id's text.
                if builtin == CONTRACT_ID_TO_TEXT && ledger == Ledger::On {
                    let [Value::ContractId(_)] = args.as_slice() else {
                        return Err(EvalError::unsupported());
                    };
                    return Ok(Reduced::Value(Value::Optional(None)));
                }
                Ok(Reduced::Value(exec_builtin_checked(builtin, &args)?))
            } else {
                Ok(Reduced::Value(Value::Partial {
                    builtin,
                    types,
                    args,
                }))
            }
        }
        Value::KeyFn {
            query_n,
            package_id,
            template_id,
            mut args,
        } => {
            args.push(arg);
            if args.len() < 1 + usize::from(query_n) {
                return Ok(Reduced::Value(Value::KeyFn {
                    query_n,
                    package_id,
                    template_id,
                    args,
                }));
            }
            let (n, key) = if query_n {
                let mut it = args.into_iter();
                let (Some(Value::Int64(n)), Some(key)) = (it.next(), it.next()) else {
                    return Err(EvalError::unsupported());
                };
                (n, key)
            } else {
                (1, args.remove(0))
            };
            Ok(Reduced::Value(Value::KeyAction {
                query_n,
                package_id,
                template_id,
                key: Box::new(key),
                n,
            }))
        }
        _ => Err(EvalError::unsupported()),
    }
}

fn apply_types(fun: Value, types: &[Type], keys: &[String]) -> Result<Reduced, EvalError> {
    let resolved = types.to_vec();
    match fun {
        Value::Partial {
            builtin,
            mut types,
            args,
        } => {
            types.extend(resolved);
            Ok(Reduced::Value(Value::Partial {
                builtin,
                types,
                args,
            }))
        }
        Value::TyClosure {
            mut params,
            body,
            env,
            package_id,
            mut type_env,
        } => {
            for key in keys {
                if params.is_empty() {
                    return Err(EvalError::unsupported());
                }
                let name = params.remove(0);
                type_env.push((name, key.clone()));
            }
            if params.is_empty() {
                Ok(Reduced::Enter {
                    expr: body,
                    env,
                    type_env,
                    package_id,
                })
            } else {
                Ok(Reduced::Value(Value::TyClosure {
                    params,
                    body,
                    env,
                    package_id,
                    type_env,
                }))
            }
        }
        // `GENMAP_EMPTY @k @v`, `TEXTMAP_EMPTY @t`: the empty map is already a value; applying types to it changes
        // nothing.
        Value::Map(entries) => Ok(Reduced::Value(Value::Map(entries))),
        _ => Err(EvalError::unsupported()),
    }
}
