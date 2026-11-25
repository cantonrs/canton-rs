//! Machine: run-mode steps of `Update` expressions and blocks.

use lf_archive::proto::daml_lf_2;
use lf_archive::proto::daml_lf_2::{expr, Expr};
use lf_archive::resolve_interned_string;

use crate::eval_error::EvalError;
use crate::kont::Kont;
use crate::machine_expr::OperandOp;
use crate::machine_resolve::update_form_name;
use crate::value::Value;
use crate::{Control, Machine, TemplateRef};

impl<'a> Machine<'a> {
    /// Run mode: execute an `Update` expression for its ledger effects. Entered only from
    /// the choice root, a `Block` binding/body, an `EmbedExpr` body, or `Kont::Run`.
    #[inline(never)]
    pub(super) fn step_run(&mut self, expr: Expr) -> Result<(), EvalError> {
        let expr = self.resolve_interned_expr(expr)?;
        match expr.sum {
            Some(expr::Sum::Update(upd)) => self.step_update(*upd),
            // Not syntactically an Update (e.g. `when b u`, a `Val`, an application):
            // evaluate it normally to an `Action` value and run that. Any effect
            // inside it stays suspended until `Kont::Run` fires.
            _ => {
                self.kont.push(Kont::Run);
                self.control = Control::Expr(expr);
                Ok(())
            }
        }
    }

    #[inline(never)]
    fn step_update(&mut self, upd: daml_lf_2::Update) -> Result<(), EvalError> {
        let Some(upd_sum) = upd.sum else {
            return Err(EvalError::UnsupportedUpdate("update without a form"));
        };
        match upd_sum {
            daml_lf_2::update::Sum::Pure(pure_upd) => {
                let inner = pure_upd.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.control = Control::Expr(inner);
                Ok(())
            }
            daml_lf_2::update::Sum::Block(block) => self.step_update_block(*block),
            daml_lf_2::update::Sum::EmbedExpr(embed) => {
                // The body has type `Update t`: run it rather than merely evaluate it.
                let body = embed.body.map(|b| *b).ok_or(EvalError::unsupported())?;
                self.control = Control::Run(body);
                Ok(())
            }
            daml_lf_2::update::Sum::Create(create) => {
                // Historical leniency kept: an unresolvable package id degrades to the
                // current package, as `create_contract` callers have always seen.
                let (package_id, template_id) = create
                    .template
                    .as_ref()
                    .and_then(|id| {
                        self.resolve_tycon_ref(id).ok().or_else(|| {
                            let name = self.resolve_tycon_id(id).ok()?;
                            Some((self.package_id.clone(), name))
                        })
                    })
                    .unwrap_or_default();
                let payload_expr = create.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::UpdateCreate {
                    package_id,
                    template_id,
                });
                self.control = Control::Expr(payload_expr);
                Ok(())
            }
            daml_lf_2::update::Sum::Exercise(exercise) => {
                let template = exercise
                    .template
                    .as_ref()
                    .map(|id| self.resolve_tycon_ref(id))
                    .transpose()?
                    .ok_or(EvalError::unsupported())?;
                let package = self.package()?;
                let choice = resolve_interned_string(
                    package,
                    exercise.choice_interned_str,
                    "Update.Exercise.choice",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let cid = exercise.cid.map(|e| *e).ok_or(EvalError::unsupported())?;
                let arg = exercise.arg.map(|e| *e).ok_or(EvalError::unsupported())?;
                // Daml evaluates the contract id before the choice argument.
                self.kont.push(Kont::ExerciseCid {
                    template: TemplateRef {
                        package_id: template.0,
                        template_id: template.1,
                    },
                    choice,
                    arg,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                self.control = Control::Expr(cid);
                Ok(())
            }
            daml_lf_2::update::Sum::Fetch(fetch) => {
                let template = fetch
                    .template
                    .as_ref()
                    .map(|id| self.resolve_tycon_ref(id))
                    .transpose()?
                    .ok_or(EvalError::unsupported())?;
                let cid = fetch.cid.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.kont.push(Kont::FetchCid {
                    template: TemplateRef {
                        package_id: template.0,
                        template_id: template.1,
                    },
                });
                self.control = Control::Expr(cid);
                Ok(())
            }
            daml_lf_2::update::Sum::GetTime(_) => {
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                // Timestamps are Int64 microseconds throughout this evaluator.
                self.control = Control::Value(Value::Int64(host.get_time()?));
                Ok(())
            }
            // `ledgerTimeLT t`: true iff the ledger time is before `t` (Speedy `SBULedgerTimeLT`). The time-boundary
            // bookkeeping the engine uses to validate the chosen ledger time is not modelled here.
            daml_lf_2::update::Sum::LedgerTimeLt(operand) => {
                self.kont.push(Kont::LedgerTimeLt);
                self.control = Control::Expr(*operand);
                Ok(())
            }
            daml_lf_2::update::Sum::CreateInterface(create) => {
                let operand = create.expr.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::CreateInterface, vec![operand])
            }
            daml_lf_2::update::Sum::ExerciseInterface(exercise) => {
                let interface = self.template_ref(exercise.interface.as_ref())?;
                let package = self.package()?;
                let choice = resolve_interned_string(
                    package,
                    exercise.choice_interned_str,
                    "Update.ExerciseInterface.choice",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let cid = exercise.cid.map(|e| *e).ok_or(EvalError::unsupported())?;
                let arg = exercise.arg.map(|e| *e).ok_or(EvalError::unsupported())?;
                // Daml evaluates the contract id, the choice argument, then the guard.
                let mut operands = vec![cid, arg];
                let has_guard = exercise.guard.is_some();
                if let Some(guard) = exercise.guard {
                    operands.push(*guard);
                }
                self.start_operands(
                    OperandOp::ExerciseInterface {
                        interface,
                        choice,
                        has_guard,
                    },
                    operands,
                )
            }
            daml_lf_2::update::Sum::ExerciseByKey(exercise) => {
                // [CANTON-NOTE: SEMANTICS] Speedy `ChoiceByKeyDefRef`: resolve the key to the most recently created
                // visible active contract, then run the ordinary exercise on it. A missing key is
                // `ContractKeyNotFound`, which a Daml `try` does not catch (measured: `caughtMissing`).
                let template = self.template_ref(exercise.template.as_ref())?;
                let package = self.package()?;
                let choice = resolve_interned_string(
                    package,
                    exercise.choice_interned_str,
                    "Update.ExerciseByKey.choice",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let key = exercise.key.map(|e| *e).ok_or(EvalError::unsupported())?;
                let arg = exercise.arg.map(|e| *e).ok_or(EvalError::unsupported())?;
                // The key is evaluated before the choice argument.
                self.start_operands(
                    OperandOp::ExerciseByKey { template, choice },
                    vec![key, arg],
                )
            }
            daml_lf_2::update::Sum::FetchInterface(fetch) => {
                let interface = self.template_ref(fetch.interface.as_ref())?;
                let cid = fetch.cid.map(|e| *e).ok_or(EvalError::unsupported())?;
                self.start_operands(OperandOp::FetchInterface { interface }, vec![cid])
            }
            daml_lf_2::update::Sum::TryCatch(try_catch) => {
                let package = self.package()?;
                let var = resolve_interned_string(
                    package,
                    try_catch.var_interned_str,
                    "Update.TryCatch.var",
                )
                .map_err(|err| EvalError::Archive(err.to_string()))?;
                let try_expr = try_catch
                    .try_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                let catch_expr = try_catch
                    .catch_expr
                    .map(|e| *e)
                    .ok_or(EvalError::unsupported())?;
                // Checkpoint first: nothing of the body may run before the host can undo it.
                let host = self.host.as_deref_mut().ok_or(EvalError::unsupported())?;
                let checkpoint = host.begin_try()?;
                self.kont.push(Kont::Catch {
                    checkpoint,
                    var,
                    catch_expr,
                    env: self.env.clone(),
                    type_env: self.type_env.clone(),
                    package_id: self.package_id.clone(),
                });
                // `try_expr : Update a` is executed (run mode), not merely evaluated.
                self.control = Control::Run(try_expr);
                Ok(())
            }
            // The official schema also decodes ExerciseByKey, FetchByKey, LookupByKey, QueryN*, interface and
            // other update forms that the evaluator does not implement. They are an explicit error now.
            other => Err(EvalError::UnsupportedUpdate(update_form_name(&other))),
        }
    }

    pub(super) fn step_fields(
        &mut self,
        is_record: bool,
        tycon: Option<String>,
        raw_fields: Vec<daml_lf_2::FieldWithExpr>,
    ) -> Result<(), EvalError> {
        let mut fields = Vec::new();
        let package = self.package()?;
        for field in raw_fields {
            let name = resolve_interned_string(package, field.field_interned_str, "Field.name")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            let expr = field.expr.ok_or(EvalError::unsupported())?;
            fields.push((name, expr));
        }
        if fields.is_empty() {
            self.control = Control::Value(if is_record {
                Value::Record {
                    tycon,
                    fields: Vec::new(),
                }
            } else {
                Value::Struct(Vec::new())
            });
            return Ok(());
        }
        let (name, expr) = fields.remove(0);
        self.kont.push(Kont::StructField {
            is_record,
            tycon,
            got: vec![(name, Value::Unit)],
            rest: fields,
            env: self.env.clone(),
            type_env: self.type_env.clone(),
            package_id: self.package_id.clone(),
        });
        self.control = Control::Expr(expr);
        Ok(())
    }

    pub(super) fn step_block(&mut self, block: daml_lf_2::Block) -> Result<(), EvalError> {
        let body = block
            .body
            .map(|body| *body)
            .ok_or(EvalError::unsupported())?;
        let package = self.package()?;
        let mut bindings = Vec::new();
        for binding in block.bindings {
            let binder = binding.binder.ok_or(EvalError::unsupported())?;
            let name = resolve_interned_string(package, binder.var_interned_str, "Block.binder")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            let bound = binding.bound.ok_or(EvalError::unsupported())?;
            bindings.push((name, bound));
        }
        if bindings.is_empty() {
            self.control = Control::Expr(body);
            return Ok(());
        }
        let (binder, expr) = bindings.remove(0);
        self.kont.push(Kont::LetBind {
            binder,
            rest: bindings,
            body,
            env: self.env.clone(),
            type_env: self.type_env.clone(),
            package_id: self.package_id.clone(),
        });
        self.control = Control::Expr(expr);
        Ok(())
    }

    /// `Update::Block` is monadic bind, unlike `Expr::Let` (pure): every binding and the
    /// body are *Update* expressions that are run in order, and the binder receives the
    /// run's result. Sharing `step_block` would just evaluate them to inert `Action`s.
    fn step_update_block(&mut self, block: daml_lf_2::Block) -> Result<(), EvalError> {
        let body = block
            .body
            .map(|body| *body)
            .ok_or(EvalError::unsupported())?;
        let package = self.package()?;
        let mut bindings = Vec::new();
        for binding in block.bindings {
            let binder = binding.binder.ok_or(EvalError::unsupported())?;
            let name = resolve_interned_string(package, binder.var_interned_str, "Block.binder")
                .map_err(|err| EvalError::Archive(err.to_string()))?;
            let bound = binding.bound.ok_or(EvalError::unsupported())?;
            bindings.push((name, bound));
        }
        if bindings.is_empty() {
            self.control = Control::Run(body);
            return Ok(());
        }
        let (binder, expr) = bindings.remove(0);
        self.kont.push(Kont::UpdBind {
            binder,
            rest: bindings,
            body,
            env: self.env.clone(),
            type_env: self.type_env.clone(),
            package_id: self.package_id.clone(),
        });
        self.control = Control::Run(expr);
        Ok(())
    }
}
