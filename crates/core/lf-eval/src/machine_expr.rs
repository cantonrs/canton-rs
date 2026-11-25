//! Machine: expression steps and builtin operand evaluation.

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{expr, BuiltinCon, Expr};
use lf_archive::resolve_interned_string;

use crate::env::{Env, TypeEnv};
use crate::eval_builtins::{arity, builtin_supported, exec_builtin_checked};
use crate::eval_error::EvalError;
use crate::kont::Kont;
use crate::list::List;
use crate::machine_resolve::split_module_name;
use crate::update_host::{ExerciseInterfaceRequest, ExerciseRequest};
use crate::value::Value;
use crate::value_nesting::check_nesting;
use crate::{lookup, Control, Machine, TemplateRef, UNRESOLVED_TYPE};

impl<'a> Machine<'a> {
    /// Evaluate `operands` left to right in the current environment, then apply `op` to the values.
    pub(super) fn start_operands(
        &mut self,
        op: OperandOp,
        mut operands: Vec<Expr>,
    ) -> Result<(), EvalError> {
        if operands.is_empty() {
            return Err(EvalError::unsupported());
        }
        let first = operands.remove(0);
        self.kont.push(Kont::Operands(Box::new(OperandsFrame {
            op,
            values: Vec::new(),
            rest: operands.into(),
            env: self.env.clone(),
            type_env: self.type_env.clone(),
            package_id: self.package_id.clone(),
        })));
        self.control = Control::Expr(first);
        Ok(())
    }

    /// One operand of an interface form has been evaluated (`value`): evaluate the next one, or apply the form.
    /// Kept out of `step_value`, whose stack frame is on the recursion chain of nested exercises.
    #[inline(never)]
    pub(super) fn step_operands(
        &mut self,
        frame: OperandsFrame,
        value: Value,
    ) -> Result<(), EvalError> {
        let OperandsFrame {
            op,
            mut values,
            mut rest,
            env,
            type_env,
            package_id,
        } = frame;
        values.push(value);
        match rest.pop_front() {
            Some(next) => {
                self.kont.push(Kont::Operands(Box::new(OperandsFrame {
                    op,
                    values,
                    rest,
                    env: env.clone(),
                    type_env: type_env.clone(),
                    package_id: package_id.clone(),
                })));
                self.enter(next, env, type_env, package_id);
                Ok(())
            }
            None => self.apply_operands(op, values),
        }
    }

    /// The operands of an interface form are all evaluated: compute its result.
    ///
    /// Not inlined: `step_value` sits on the recursion chain of nested exercises, so its stack frame must stay small.
    #[inline(never)]
    fn apply_operands(&mut self, op: OperandOp, mut values: Vec<Value>) -> Result<(), EvalError> {
        let world = self.world;
        // the interface value is always the last operand of the pure forms
        let take_iface = |values: &mut Vec<Value>| match values.pop() {
            Some(Value::Iface {
                package_id,
                template,
                payload,
            }) => Ok((package_id, template, payload)),
            _ => Err(EvalError::unsupported()),
        };
        let wrong_template = |what: &str, template: &str, wanted: &str| {
            EvalError::Host(format!("{what}: the value is a {template}, not a {wanted}"))
        };
        match op {
            OperandOp::ToAny { key } => {
                let payload = values.pop().ok_or(EvalError::unsupported())?;
                self.control = Control::Value(Value::Any {
                    key,
                    payload: Box::new(payload),
                });
            }
            OperandOp::FromAny { key } => {
                let Some(Value::Any {
                    key: actual,
                    payload,
                }) = values.pop()
                else {
                    return Err(EvalError::unsupported());
                };
                if actual == UNRESOLVED_TYPE {
                    return Err(EvalError::unsupported());
                }
                self.control = Control::Value(Value::Optional((actual == key).then_some(payload)));
            }
            OperandOp::TemplateTypeRep => {
                let (package_id, template, _) = take_iface(&mut values)?;
                let key = format!("{package_id}:{template}");
                self.control = Control::Value(Value::TypeRep {
                    tycon: Some(key.clone()),
                    key,
                });
            }
            OperandOp::ToInterface { template } => {
                let payload = values.pop().ok_or(EvalError::unsupported())?;
                self.control = Control::Value(Value::Iface {
                    package_id: template.package_id,
                    template: template.template_id,
                    payload: Box::new(payload),
                });
            }
            OperandOp::FromInterface { template } => {
                let (package_id, t, payload) = take_iface(&mut values)?;
                let hit = package_id == template.package_id && t == template.template_id;
                self.control = Control::Value(Value::Optional(hit.then_some(payload)));
            }
            OperandOp::UnsafeFromInterface { template } => {
                let (package_id, t, payload) = take_iface(&mut values)?;
                if package_id != template.package_id || t != template.template_id {
                    return Err(wrong_template(
                        "unsafe_from_interface",
                        &t,
                        &template.template_id,
                    ));
                }
                self.control = Control::Value(*payload);
            }
            OperandOp::CallInterface { interface, method } => {
                let (package_id, template, payload) = take_iface(&mut values)?;
                let inst = world
                    .interface_instance(
                        &package_id,
                        &template,
                        &interface.package_id,
                        &interface.template_id,
                    )?
                    .ok_or_else(|| {
                        EvalError::Host(format!(
                            "{template} does not implement {}",
                            interface.template_id
                        ))
                    })?;
                let param = resolve_interned_string(
                    inst.package,
                    inst.template.param_interned_str,
                    "DefTemplate.param",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let mut found = None;
                for m in &inst.body.methods {
                    let name = resolve_interned_string(
                        inst.package,
                        m.method_interned_name,
                        "InterfaceInstanceMethod.name",
                    )
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                    if name == method {
                        found = m.value.clone();
                        break;
                    }
                }
                let expr = found.ok_or_else(|| {
                    EvalError::Host(format!(
                        "{template} has no method {method} of {}",
                        interface.template_id
                    ))
                })?;
                self.enter(
                    expr,
                    Env::from(vec![(param, *payload)]),
                    Vec::new(),
                    package_id,
                );
            }
            OperandOp::ViewInterface { interface } => {
                let (package_id, template, payload) = take_iface(&mut values)?;
                let inst = world
                    .interface_instance(
                        &package_id,
                        &template,
                        &interface.package_id,
                        &interface.template_id,
                    )?
                    .ok_or_else(|| {
                        EvalError::Host(format!(
                            "{template} does not implement {}",
                            interface.template_id
                        ))
                    })?;
                let param = resolve_interned_string(
                    inst.package,
                    inst.template.param_interned_str,
                    "DefTemplate.param",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let view = inst.body.view.clone().ok_or(EvalError::unsupported())?;
                self.enter(
                    view,
                    Env::from(vec![(param, *payload)]),
                    Vec::new(),
                    package_id,
                );
            }
            OperandOp::Signatories | OperandOp::Observers => {
                let (package_id, template, payload) = take_iface(&mut values)?;
                let (module, name) = split_module_name(&template)?;
                let parties = if matches!(op, OperandOp::Signatories) {
                    world.eval_template_signatories_in(&package_id, module, name, &payload)?
                } else {
                    world.eval_template_observers_in(&package_id, module, name, &payload)?
                };
                self.control =
                    Control::Value(Value::List(parties.into_iter().map(Value::Party).collect()));
            }
            OperandOp::ToRequired => {
                let value = values.pop().ok_or(EvalError::unsupported())?;
                self.control = Control::Value(value);
            }
            OperandOp::FromRequired { requiring } => {
                let iface = values.pop().ok_or(EvalError::unsupported())?;
                let Value::Iface {
                    package_id,
                    template,
                    ..
                } = &iface
                else {
                    return Err(EvalError::unsupported());
                };
                let ok = world.template_implements(
                    package_id,
                    template,
                    &requiring.package_id,
                    &requiring.template_id,
                )?;
                self.control = Control::Value(Value::Optional(ok.then(|| Box::new(iface))));
            }
            OperandOp::UnsafeFromRequired { requiring } => {
                let iface = values.pop().ok_or(EvalError::unsupported())?;
                let Value::Iface {
                    package_id,
                    template,
                    ..
                } = &iface
                else {
                    return Err(EvalError::unsupported());
                };
                if !world.template_implements(
                    package_id,
                    template,
                    &requiring.package_id,
                    &requiring.template_id,
                )? {
                    return Err(wrong_template(
                        "unsafe_from_required_interface",
                        template,
                        &requiring.template_id,
                    ));
                }
                self.control = Control::Value(iface);
            }
            OperandOp::CreateInterface => {
                let (package_id, template, payload) = take_iface(&mut values)?;
                check_nesting(&payload)?;
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let cid = host.create_contract_in(&package_id, &template, &payload)?;
                self.control = Control::Value(Value::ContractId(cid));
            }
            OperandOp::ExerciseInterface {
                interface,
                choice,
                has_guard,
            } => {
                let guard = if has_guard { values.pop() } else { None };
                let arg = values.pop().ok_or(EvalError::unsupported())?;
                let Some(Value::ContractId(cid)) = values.pop() else {
                    return Err(EvalError::unsupported());
                };
                check_nesting(&arg)?;
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let result = host.exercise_interface(&ExerciseInterfaceRequest {
                    interface_package_id: &interface.package_id,
                    interface_id: &interface.template_id,
                    contract_id: &cid,
                    choice: &choice,
                    arg: &arg,
                    guard: guard.as_ref(),
                })?;
                check_nesting(&result)?;
                self.control = Control::Value(result);
            }
            OperandOp::ExerciseByKey { template, choice } => {
                let arg = values.pop().ok_or(EvalError::unsupported())?;
                let key = values.pop().ok_or(EvalError::unsupported())?;
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let (cid, _) = host
                    .lookup_by_key(&template.package_id, &template.template_id, &key, 1, false)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| EvalError::ContractKeyNotFound {
                        template_id: template.template_id.clone(),
                    })?;
                check_nesting(&arg)?;
                let result = host.exercise(&ExerciseRequest {
                    package_id: &template.package_id,
                    template_id: &template.template_id,
                    contract_id: &cid,
                    choice: &choice,
                    arg: &arg,
                })?;
                check_nesting(&result)?;
                self.control = Control::Value(result);
            }
            OperandOp::FetchInterface { interface } => {
                let Some(Value::ContractId(cid)) = values.pop() else {
                    return Err(EvalError::unsupported());
                };
                let iface_fq = format!("{}:{}", interface.package_id, interface.template_id);
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let fetched = host.fetch_contract(&cid, Some(&iface_fq))?;
                if !world.template_implements(
                    &fetched.package_id,
                    &fetched.template_id,
                    &interface.package_id,
                    &interface.template_id,
                )? {
                    return Err(EvalError::Host(format!(
                        "fetch_interface: contract {cid} ({}) does not implement {}",
                        fetched.template_id, interface.template_id
                    )));
                }
                self.control = Control::Value(Value::Iface {
                    package_id: fetched.package_id,
                    template: fetched.template_id,
                    payload: Box::new(fetched.payload),
                });
            }
        }
        Ok(())
    }

    pub(super) fn resolve_interned_expr(&self, mut expr: Expr) -> Result<Expr, EvalError> {
        let package = self.package()?;
        for _ in 0..=package.interned_exprs.len() {
            match expr.sum {
                Some(expr::Sum::InternedExpr(index)) => {
                    expr = usize::try_from(index)
                        .ok()
                        .and_then(|i| package.interned_exprs.get(i))
                        .cloned()
                        .ok_or_else(|| {
                            EvalError::Archive(format!(
                                "Expr.interned_expr index {index} is outside the package table of {}",
                                package.interned_exprs.len()
                            ))
                        })?;
                }
                _ => return Ok(expr),
            }
        }
        Err(EvalError::Archive(
            "Expr.interned_expr references form a cycle".to_string(),
        ))
    }

    #[inline(never)]
    pub(super) fn step_expr(&mut self, expr: Expr) -> Result<(), EvalError> {
        let expr = self.resolve_interned_expr(expr)?;
        let Some(sum) = expr.sum else {
            return Err(EvalError::unsupported());
        };
        match sum {
            expr::Sum::VarInternedStr(index) => {
                let package = self.package()?;
                let name = resolve_interned_string(package, index, "Expr.var")
                    .map_err(|err| EvalError::Archive(err.to_string()))?;
                let value = lookup(&self.env, &name)?;
                self.control = Control::Value(value);
                Ok(())
            }
            expr::Sum::Val(id) => {
                let (package_id, key, expr) = self.locate_val(&id)?;
                if let Some(value) = self.world.val_cache.get(&key) {
                    self.control = Control::Value(value);
                    return Ok(());
                }
                self.kont.push(Kont::CacheVal { key });
                self.package_id = package_id;
                self.env.clear();
                self.type_env.clear();
                self.control = Control::Expr(expr);
                Ok(())
            }
            expr::Sum::Builtin(code) => {
                if !builtin_supported(code) {
                    return Err(EvalError::unsupported());
                }
                if arity(code) == 0 {
                    // a constant builtin (`GENMAP_EMPTY`, `TEXTMAP_EMPTY`): its value, then type applications
                    self.control = Control::Value(exec_builtin_checked(code, &[])?);
                    return Ok(());
                }
                self.control = Control::Value(Value::Partial {
                    builtin: code,
                    types: Vec::new(),
                    args: Vec::new(),
                });
                Ok(())
            }
            expr::Sum::BuiltinCon(code) => {
                let value = match BuiltinCon::try_from(code) {
                    Ok(BuiltinCon::ConUnit) => Value::Unit,
                    Ok(BuiltinCon::ConTrue) => Value::Bool(true),
                    Ok(BuiltinCon::ConFalse) => Value::Bool(false),
                    Err(_) => return Err(EvalError::unsupported()),
                };
                self.control = Control::Value(value);
                Ok(())
            }
            expr::Sum::BuiltinLit(lit) => {
                self.control = Control::Value(self.literal(lit)?);
                Ok(())
            }
            expr::Sum::Abs(abs) => {
                let package = self.package()?;
                let mut params = Vec::new();
                for param in abs.param {
                    let name =
                        resolve_interned_string(package, param.var_interned_str, "Abs.param")
                            .map_err(|err| EvalError::Archive(err.to_string()))?;
                    params.push(name);
                }
                let body = abs.body.map(|body| *body).ok_or(EvalError::unsupported())?;
                self.control = Control::Value(Value::Closure {
                    params,
                    body,
                    env: self.env.clone(),
                    package_id: self.package_id.clone(),
                    type_env: self.type_env.clone(),
                });
                Ok(())
            }
            expr::Sum::TyAbs(abs) => {
                let package = self.package()?;
                let mut params = Vec::new();
                for param in abs.param {
                    let name =
                        resolve_interned_string(package, param.var_interned_str, "TyAbs.param")
                            .map_err(|err| EvalError::Archive(err.to_string()))?;
                    params.push(name);
                }
                let body = abs.body.map(|body| *body).ok_or(EvalError::unsupported())?;
                self.control = Control::Value(Value::TyClosure {
                    params,
                    body,
                    env: self.env.clone(),
                    package_id: self.package_id.clone(),
                    type_env: self.type_env.clone(),
                });
                Ok(())
            }
            expr::Sum::App(app) => {
                let fun = app.fun.map(|fun| *fun).ok_or(EvalError::unsupported())?;
                let mut pending = app.args;
                let Some(last) = pending.pop() else {
                    self.control = Control::Expr(fun);
                    return Ok(());
                };
                self.kont.push(Kont::ArgsRev {
                    fun,
                    pending,
                    collected_rev: Vec::new(),
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(last);
                Ok(())
            }
            expr::Sum::TyApp(app) => {
                let fun = app.expr.map(|fun| *fun).ok_or(EvalError::unsupported())?;
                let keys = app
                    .types
                    .iter()
                    .map(|t| self.type_key_or_unresolved(t))
                    .collect();
                self.kont.push(Kont::Types {
                    types: app.types,
                    keys,
                });
                self.control = Control::Expr(fun);
                Ok(())
            }
            expr::Sum::ToInterface(to) => {
                let template = self.template_ref(to.template_type.as_ref())?;
                let operand = to
                    .template_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::ToInterface { template }, vec![operand])
            }
            expr::Sum::FromInterface(from) => {
                let template = self.template_ref(from.template_type.as_ref())?;
                let operand = from
                    .interface_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::FromInterface { template }, vec![operand])
            }
            expr::Sum::UnsafeFromInterface(from) => {
                let template = self.template_ref(from.template_type.as_ref())?;
                let cid = from
                    .contract_id_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                let operand = from
                    .interface_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.start_operands(
                    OperandOp::UnsafeFromInterface { template },
                    vec![cid, operand],
                )
            }
            expr::Sum::CallInterface(call) => {
                let interface = self.template_ref(call.interface_type.as_ref())?;
                let package = self.package()?;
                let method = resolve_interned_string(
                    package,
                    call.method_interned_name,
                    "CallInterface.method",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let operand = call
                    .interface_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.start_operands(
                    OperandOp::CallInterface { interface, method },
                    vec![operand],
                )
            }
            expr::Sum::ViewInterface(view) => {
                let interface = self.template_ref(view.interface.as_ref())?;
                let operand = view.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::ViewInterface { interface }, vec![operand])
            }
            expr::Sum::SignatoryInterface(sig) => {
                let operand = sig.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::Signatories, vec![operand])
            }
            expr::Sum::ObserverInterface(obs) => {
                let operand = obs.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::Observers, vec![operand])
            }
            expr::Sum::ToRequiredInterface(to) => {
                let operand = to.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::ToRequired, vec![operand])
            }
            expr::Sum::FromRequiredInterface(from) => {
                let requiring = self.template_ref(from.requiring_interface.as_ref())?;
                let operand = from.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::FromRequired { requiring }, vec![operand])
            }
            expr::Sum::UnsafeFromRequiredInterface(from) => {
                let requiring = self.template_ref(from.requiring_interface.as_ref())?;
                let cid = from
                    .contract_id_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                let operand = from
                    .interface_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.start_operands(
                    OperandOp::UnsafeFromRequired { requiring },
                    vec![cid, operand],
                )
            }
            expr::Sum::StructCon(con) => self.step_fields(false, None, con.fields),
            expr::Sum::RecCon(con) => {
                let tycon = con
                    .tycon
                    .as_ref()
                    .and_then(|tc| tc.tycon.as_ref())
                    .and_then(|id| self.resolve_tycon_id(id).ok());
                self.step_fields(true, tycon, con.fields)
            }
            expr::Sum::RecProj(proj) => {
                let package = self.package()?;
                let field =
                    resolve_interned_string(package, proj.field_interned_str, "RecProj.field")
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                let record = proj.record.map(|r| *r).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FieldProj { field });
                self.control = Control::Expr(record);
                Ok(())
            }
            expr::Sum::StructProj(proj) => {
                let package = self.package()?;
                let field =
                    resolve_interned_string(package, proj.field_interned_str, "StructProj.field")
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                let record = proj.r#struct.map(|r| *r).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FieldProj { field });
                self.control = Control::Expr(record);
                Ok(())
            }
            expr::Sum::RecUpd(upd) => {
                let package = self.package()?;
                let field =
                    resolve_interned_string(package, upd.field_interned_str, "RecUpd.field")
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                let record = upd.record.map(|r| *r).ok_or(EvalError::unsupported())?;
                let update = upd.update.map(|u| *u).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FieldUpdRecord {
                    field,
                    update,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(record);
                Ok(())
            }
            expr::Sum::StructUpd(upd) => {
                let package = self.package()?;
                let field =
                    resolve_interned_string(package, upd.field_interned_str, "StructUpd.field")
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                let record = upd.r#struct.map(|r| *r).ok_or(EvalError::unsupported())?;
                let update = upd.update.map(|u| *u).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FieldUpdRecord {
                    field,
                    update,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(record);
                Ok(())
            }
            expr::Sum::VariantCon(con) => {
                let package = self.package()?;
                let constructor = resolve_interned_string(
                    package,
                    con.variant_con_interned_str,
                    "VariantCon.con",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let id = con
                    .tycon
                    .as_ref()
                    .and_then(|tc| tc.tycon.as_ref())
                    .ok_or(EvalError::unsupported())?;
                let tycon = self.resolve_tycon_id(id).ok();
                let rank = self.constructor_rank(id, &constructor)?;
                let arg = con
                    .variant_arg
                    .map(|a| *a)
                    .ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::VariantCon {
                    tycon,
                    constructor,
                    rank,
                });
                self.control = Control::Expr(arg);
                Ok(())
            }
            expr::Sum::EnumCon(con) => {
                let package = self.package()?;
                let constructor =
                    resolve_interned_string(package, con.enum_con_interned_str, "EnumCon.con")
                        .map_err(|err| EvalError::Archive(err.to_string()))?;
                let id = con.tycon.as_ref().ok_or(EvalError::unsupported())?;
                let tycon = self.resolve_tycon_id(id).ok();
                let rank = self.constructor_rank(id, &constructor)?;
                self.control = Control::Value(Value::Enum {
                    tycon,
                    constructor,
                    rank,
                });
                Ok(())
            }
            expr::Sum::Nil(_) => {
                self.control = Control::Value(Value::List(List::new()));
                Ok(())
            }
            expr::Sum::Cons(cons) => {
                let tail = cons.tail.map(|t| *t).ok_or(EvalError::unsupported())?;
                let mut front = cons.front;
                if front.is_empty() {
                    self.control = Control::Expr(tail);
                    return Ok(());
                }
                let first = front.remove(0);
                self.kont.push(Kont::ConsFront {
                    got: Vec::new(),
                    rest_front: front,
                    tail,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(first);
                Ok(())
            }
            expr::Sum::OptionalNone(_) => {
                self.control = Control::Value(Value::Optional(None));
                Ok(())
            }
            expr::Sum::OptionalSome(some) => {
                let inner = some.value.map(|v| *v).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::OptionalSome);
                self.control = Control::Expr(inner);
                Ok(())
            }
            expr::Sum::Case(case_expr) => {
                let scrut = case_expr
                    .scrut
                    .map(|s| *s)
                    .ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::Case {
                    alts: case_expr.alts,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(scrut);
                Ok(())
            }
            expr::Sum::Let(block) => self.step_block(*block),
            expr::Sum::ToAny(to_any) => {
                let key = to_any.r#type.as_ref().map_or_else(
                    || UNRESOLVED_TYPE.to_string(),
                    |t| self.type_key_or_unresolved(t),
                );
                let inner = to_any.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::ToAny { key }, vec![inner])
            }
            expr::Sum::FromAny(from_any) => {
                let key =
                    self.type_key(from_any.r#type.as_ref().ok_or(EvalError::unsupported())?)?;
                let inner = from_any.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::FromAny { key }, vec![inner])
            }
            expr::Sum::TypeRep(ty) => {
                let canon = self.canon_type(&ty)?;
                let key = canon.to_key();
                let tycon = canon.unapplied_tycon();
                self.control = Control::Value(Value::TypeRep { key, tycon });
                Ok(())
            }
            expr::Sum::InterfaceTemplateTypeRep(rep) => {
                let operand = rep.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::TemplateTypeRep, vec![operand])
            }
            expr::Sum::ToAnyException(to_any) => {
                let tycon = to_any
                    .r#type
                    .as_ref()
                    .map(|ty| self.resolve_type_tycon(ty))
                    .transpose()?
                    .ok_or(EvalError::unsupported())?;
                let inner = to_any.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::ToAnyException { tycon });
                self.control = Control::Expr(inner);
                Ok(())
            }
            expr::Sum::FromAnyException(from_any) => {
                // A type we cannot name must fail loudly: guessing "no match" would make
                // a handler silently decline exceptions it was written for.
                let tycon = from_any
                    .r#type
                    .as_ref()
                    .map(|ty| self.resolve_type_tycon(ty))
                    .transpose()?
                    .ok_or(EvalError::unsupported())?;
                let inner = from_any.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FromAnyException { tycon });
                self.control = Control::Expr(inner);
                Ok(())
            }
            expr::Sum::Throw(throw_expr) => {
                let exception_tycon = throw_expr
                    .exception_type
                    .as_ref()
                    .and_then(|ty| self.resolve_type_tycon(ty).ok());
                let exc = throw_expr
                    .exception_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::Throw { exception_tycon });
                self.control = Control::Expr(exc);
                Ok(())
            }
            expr::Sum::Update(upd)
                if matches!(
                    upd.sum,
                    Some(daml_lf_2::update::Sum::FetchByKey(_))
                        | Some(daml_lf_2::update::Sum::QueryNByKey(_))
                ) =>
            {
                // `FetchByKey T` and `QueryNByKey T` are not actions but functions that produce one once they are given
                // the key (and n); they gather those arguments in `reduce_app`.
                let (query_n, template) = match &upd.sum {
                    Some(daml_lf_2::update::Sum::FetchByKey(r)) => (false, r.template.as_ref()),
                    Some(daml_lf_2::update::Sum::QueryNByKey(q)) => (true, q.template.as_ref()),
                    _ => unreachable!(),
                };
                let template = self.template_ref(template)?;
                self.control = Control::Value(Value::KeyFn {
                    query_n,
                    package_id: template.package_id,
                    template_id: template.template_id,
                    args: Vec::new(),
                });
                Ok(())
            }
            expr::Sum::Update(upd) => {
                // An `Update a` is a *description* of ledger effects, not the effects
                // themselves. Evaluating the expression (as an argument, a `let`, a closure
                // body, ...) must therefore not touch the host: `when False (create x)` has
                // to leave the ledger alone. We capture the environment so that the action
                // can be run later, wherever the value ends up (see `Kont::Run`).
                self.control = Control::Value(Value::Action {
                    expr: Box::new(Expr {
                        location: None,
                        sum: Some(expr::Sum::Update(upd)),
                    }),
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                Ok(())
            }
            _ => Err(EvalError::unsupported()),
        }
    }
}

pub(super) struct OperandsFrame {
    op: OperandOp,
    values: Vec<Value>,
    rest: std::collections::VecDeque<Expr>,
    env: Env,
    type_env: TypeEnv,
    package_id: String,
}

/// What to do once the operand expressions of an interface form have been evaluated, in order
/// (`ToInterface`, `CallInterface`, `ExerciseInterface`, ...). Interface and template references are resolved
/// when the form is entered; `template_id` of a `TemplateRef` is `"Module:Name"`.
#[derive(Clone)]
pub(super) enum OperandOp {
    ToAny {
        key: String,
    },
    FromAny {
        key: String,
    },
    TemplateTypeRep,
    ToInterface {
        template: TemplateRef,
    },
    FromInterface {
        template: TemplateRef,
    },
    UnsafeFromInterface {
        template: TemplateRef,
    },
    CallInterface {
        interface: TemplateRef,
        method: String,
    },
    ViewInterface {
        interface: TemplateRef,
    },
    Signatories,
    Observers,
    ToRequired,
    FromRequired {
        requiring: TemplateRef,
    },
    UnsafeFromRequired {
        requiring: TemplateRef,
    },
    CreateInterface,
    ExerciseInterface {
        interface: TemplateRef,
        choice: String,
        has_guard: bool,
    },
    FetchInterface {
        interface: TemplateRef,
    },
    ExerciseByKey {
        template: TemplateRef,
        choice: String,
    },
}
