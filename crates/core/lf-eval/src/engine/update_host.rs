//! The engine as the machine's ledger host (`impl UpdateHost for Engine`) and its authorization checks.

use std::collections::BTreeSet;

use crate::{
    AuthDetail, AuthKind, AuthRule, EvalError, ExerciseRequest, FetchRequest, TryCheckpoint,
    UpdateHost, Value,
};

use super::{
    Checkpoint, Contract, Engine, EngineEvent, KeyLookup, RecordedKeyLookup, RolledBack,
    MAX_EXERCISE_DEPTH, PRECONDITION_FAILED,
};

/// Key maintainers must be signatories of the contract that carries the key.
fn require_subset_of_signatories(
    node_id: usize,
    package_id: &str,
    template_id: &str,
    maintainers: &[String],
    signatories: &[String],
) -> Result<(), EvalError> {
    let missing: Vec<String> = maintainers
        .iter()
        .filter(|m| !signatories.contains(m))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let authorized: BTreeSet<String> = signatories.iter().cloned().collect();
    Err(EvalError::Unauthorized {
        kind: AuthKind::Signatories,
        what: format!("key of {template_id} (maintainers must be signatories)"),
        required: maintainers.to_vec(),
        missing,
        authorized: authorized.clone(),
        detail: Some(Box::new(AuthDetail {
            node_id,
            rule: AuthRule::MaintainersNotSubsetOfSignatories,
            template_id: format!("{package_id}:{template_id}"),
            required_parties: maintainers.to_vec(),
            context_parties: authorized,
        })),
    })
}

pub(super) fn split_template(template_id: &str) -> Result<(&str, &str), EvalError> {
    template_id
        .split_once(':')
        .ok_or_else(|| EvalError::Host(format!("template id {template_id} is not Module:Type")))
}

/// `kind` records which Daml rule is being enforced; the check itself is the same set
/// inclusion (`required ⊆ authorized`). A failure is a typed `Unauthorized`, which a Daml
/// `try` does not catch.
fn require_covered(
    kind: AuthKind,
    rule: AuthRule,
    node_id: usize,
    full_template_id: &str,
    what: &str,
    required: &[String],
    authorized: &BTreeSet<String>,
) -> Result<(), EvalError> {
    let missing: Vec<&str> = required
        .iter()
        .filter(|party| !authorized.contains(*party))
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(EvalError::Unauthorized {
        kind,
        what: what.to_string(),
        required: required.to_vec(),
        missing: missing.into_iter().map(str::to_string).collect(),
        authorized: authorized.clone(),
        detail: Some(Box::new(AuthDetail {
            node_id,
            rule,
            template_id: full_template_id.to_string(),
            required_parties: required.to_vec(),
            context_parties: authorized.clone(),
        })),
    })
}

impl UpdateHost for Engine<'_> {
    fn create_contract(&mut self, template_id: &str, payload: &Value) -> Result<String, EvalError> {
        let package_id = self.world.main_package_id().to_string();
        self.create_contract_in(&package_id, template_id, payload)
    }

    fn create_contract_in(
        &mut self,
        package_id: &str,
        template_id: &str,
        payload: &Value,
    ) -> Result<String, EvalError> {
        // [CANTON-NOTE: SEMANTICS] A contract payload with a NUL character in a Text is refused (uncatchable); measured on
        // the JVM both for a command argument and for a create inside a choice (tests/oracle/lf-fatal).
        if crate::value_contains_nul(payload) {
            return Err(EvalError::MalformedText);
        }
        let (module, template) = split_template(template_id)?;
        // Daml checks the `ensure` precondition on creation; a violation is the built-in
        // PreconditionFailed Daml exception (so a surrounding `try` may catch it), not a
        // ledger error. That Daml lets `try` catch a failed `ensure` is documented
        // behaviour as far as we know, but it is not verified against Speedy here.
        // `into_uncaught` yields the same error_id/message strings as before this was a
        // catchable exception.
        if !self
            .world
            .eval_template_precond_in(package_id, module, template, payload)?
        {
            return Err(EvalError::Thrown(Box::new(Value::AnyException {
                tycon: PRECONDITION_FAILED.to_string(),
                payload: Box::new(Value::Record {
                    tycon: Some(PRECONDITION_FAILED.to_string()),
                    fields: vec![(
                        "message".to_string(),
                        Value::Text(format!("Template precondition violated: {template_id}")),
                    )],
                }),
            })));
        }
        let node_id = self.next_node_idx;
        let full_template = format!("{package_id}:{template_id}");
        let signatories = self
            .world
            .eval_template_signatories_in(package_id, module, template, payload)?;
        let observers = self
            .world
            .eval_template_observers_in(package_id, module, template, payload)?;
        let key = self
            .world
            .eval_template_key_in(package_id, module, template, payload)?;
        if let Some((_, maintainers)) = &key {
            // [CANTON-NOTE: INVARIANT] Speedy `SBUCreate` checks empty key maintainers before `insertCreate` authorization,
            // and checks `maintainers ⊆ signatories` inside `authorizeCreate` (JVM 3.7.2: tests/oracle/key-diff).
            if maintainers.is_empty() {
                return Err(EvalError::EmptyKeyMaintainers {
                    template_id: template_id.to_string(),
                });
            }
        }
        // Every signatory must have authorized the create (`CreateMissingAuthorization`), then `NoSignatories` if empty,
        // then `MaintainersNotSubsetOfSignatories` (matching `AuthorizationChecker.authorizeCreate`).
        let authorizers = self.current_authorizers()?.clone();
        require_covered(
            AuthKind::Signatories,
            AuthRule::CreateMissingAuthorization,
            node_id,
            &full_template,
            &format!("create of {template_id}"),
            &signatories,
            &authorizers,
        )?;
        if signatories.is_empty() {
            return Err(EvalError::Unauthorized {
                kind: AuthKind::Signatories,
                what: format!("create of {template_id} (no signatories)"),
                required: Vec::new(),
                missing: Vec::new(),
                authorized: authorizers.clone(),
                detail: Some(Box::new(AuthDetail {
                    node_id,
                    rule: AuthRule::NoSignatories,
                    template_id: full_template,
                    required_parties: Vec::new(),
                    context_parties: authorizers,
                })),
            });
        }
        if let Some((_, maintainers)) = &key {
            require_subset_of_signatories(
                node_id,
                package_id,
                template_id,
                maintainers,
                &signatories,
            )?;
        }
        let contract_id = self.allocate_contract_id(
            package_id,
            template_id,
            payload,
            &signatories,
            &observers,
            key.as_ref().map(|(k, m)| (k, m.as_slice())),
        )?;
        let key_value = key.as_ref().map(|(k, _)| k.clone());
        if let Some((key, _maintainers)) = key {
            self.record_key(&contract_id, key);
        }
        self.next_node_idx += 1;
        self.ledger_effects += 1;
        self.command_created.insert(contract_id.clone());
        self.contracts.insert(
            contract_id.clone(),
            Contract {
                contract_id: contract_id.clone(),
                package_id: package_id.to_string(),
                template_id: template_id.to_string(),
                payload: payload.clone(),
                signatories,
                observers,
                active: true,
                key: key_value,
            },
        );
        self.events.push(EngineEvent::Create {
            contract_id: contract_id.clone(),
            template_id: template_id.to_string(),
            depth: self.depth,
        });
        Ok(contract_id)
    }

    fn exercise(&mut self, request: &ExerciseRequest<'_>) -> Result<Value, EvalError> {
        if self.depth >= MAX_EXERCISE_DEPTH {
            return Err(EvalError::Host(format!(
                "exercise nesting exceeds {MAX_EXERCISE_DEPTH}"
            )));
        }
        let (module, template) = split_template(request.template_id)?;
        let (payload, signatories) = {
            let contract =
                self.lookup_typed(request.contract_id, request.package_id, request.template_id)?;
            (contract.payload.clone(), contract.signatories.clone())
        };
        let controllers = self.world.eval_choice_controllers_in(
            request.package_id,
            module,
            template,
            request.choice,
            &payload,
            request.arg,
        )?;
        let observers = self.world.eval_choice_observers_in(
            request.package_id,
            module,
            template,
            request.choice,
            &payload,
            request.arg,
        )?;
        // [CANTON-NOTE: SEMANTICS] A choice whose controllers evaluate to the empty set cannot be exercised by anyone:
        // the JVM answers with an authorization failure (measured: `vote_close_without_sv_party`, a `controller sv`
        // with `sv = None`), it does not run the body.
        let node_id = self.next_node_idx;
        let full_template = format!("{}:{}", request.package_id, request.template_id);
        let authorizers = self.current_authorizers()?.clone();
        if controllers.is_empty() {
            return Err(EvalError::Unauthorized {
                kind: AuthKind::Controllers,
                what: format!(
                    "exercise of {}:{} (no controllers)",
                    request.template_id, request.choice
                ),
                required: Vec::new(),
                missing: Vec::new(),
                authorized: authorizers.clone(),
                detail: Some(Box::new(AuthDetail {
                    node_id,
                    rule: AuthRule::NoControllers,
                    template_id: full_template,
                    required_parties: Vec::new(),
                    context_parties: authorizers,
                })),
            });
        }
        // The actors of an exercise must be authorized by the *enclosing* context: the
        // top-level `act_as`, or the signatories+controllers of the parent exercise.
        require_covered(
            AuthKind::Controllers,
            AuthRule::ExerciseMissingAuthorization,
            node_id,
            &full_template,
            &format!("exercise of {}:{}", request.template_id, request.choice),
            &controllers,
            &authorizers,
        )?;
        self.next_node_idx += 1;
        let consuming =
            self.world
                .choice_is_consuming(request.package_id, module, template, request.choice)?;
        // Consuming choices archive the contract *before* the body runs: the body then
        // cannot fetch or exercise `self` (it sees ContractNotActive).
        if consuming {
            if let Some(contract) = self.contracts.get_mut(request.contract_id) {
                contract.active = false;
                self.ledger_effects += 1;
            }
        }
        let event_at = self.events.len();
        self.events.push(EngineEvent::Exercise {
            contract_id: request.contract_id.to_string(),
            choice: request.choice.to_string(),
            consuming,
            actors: controllers.clone(),
            depth: self.depth,
            argument: request.arg.clone(),
            result: None,
            interface_id: None,
            observers,
        });
        // Authority inside the body = contract signatories + choice controllers, nothing
        // else. Observers/other stakeholders confer no authority (cf. tx_model.rs, which
        // over-authorizes by using all stakeholders for children).
        let mut inner: BTreeSet<String> = signatories.into_iter().collect();
        inner.extend(controllers);
        self.authorizers.push(inner);
        self.depth += 1;
        let world = self.world;
        let result = world.eval_choice_update_in(
            request.package_id,
            module,
            template,
            request.choice,
            request.contract_id,
            &payload,
            request.arg,
            self,
        );
        self.depth -= 1;
        self.authorizers.pop();
        if let Ok(value) = &result {
            if let Some(EngineEvent::Exercise { result: slot, .. }) = self.events.get_mut(event_at)
            {
                *slot = Some(value.clone());
            }
        }
        result
    }

    fn lookup_by_key(
        &mut self,
        package_id: &str,
        template_id: &str,
        key: &Value,
        n: usize,
        authorize: bool,
    ) -> Result<Vec<(String, Value)>, EvalError> {
        let (module, template) = split_template(template_id)?;
        let maintainers = self
            .world
            .eval_key_maintainers_in(package_id, module, template, key)?;
        if maintainers.is_empty() {
            return Err(EvalError::EmptyKeyMaintainers {
                template_id: template_id.to_string(),
            });
        }
        if authorize {
            // [CANTON-NOTE: SEMANTICS] Speedy `authorizeQueryByKey`: the maintainers must be covered by the current authority.
            let full_template = format!("{package_id}:{template_id}");
            require_covered(
                AuthKind::Controllers,
                AuthRule::LookupByKeyMissingAuthorization,
                self.next_node_idx,
                &full_template,
                &format!("query by key of {template_id}"),
                &maintainers,
                self.current_authorizers()?,
            )?;
        }
        // [CANTON-NOTE: SEMANTICS] A key lookup sees: (1) contracts created in this command newest-first, (2) explicitly
        // disclosed contracts in caller-supplied disclosure order, (3) participant-known global contracts visible to
        // `actAs ∪ readAs` newest-first (deduplicated). Measured on JVM 3.7.2 (`NUCKTests.daml` & `tests/oracle/key-diff`).
        // Canton 3.7.2 has no divulgence (`tests/oracle/divulgence`).
        let submitters = self.authorizers.first().cloned().unwrap_or_default();
        let hits =
            self.resolve_keys(package_id, template_id, key, n, |p| submitters.contains(p))?;
        let found: Vec<(String, Value)> = hits
            .into_iter()
            .map(|c| (c.contract_id.clone(), c.payload.clone()))
            .collect();
        let contract_ids: Vec<String> = found.iter().map(|(id, _)| id.clone()).collect();
        let missed_in_view = if self.view_key_resolutions.is_some() && contract_ids.len() < n {
            self.active_contracts_matching_key(package_id, template_id, key, &contract_ids, |p| {
                submitters.contains(p)
            })?
        } else {
            Vec::new()
        };
        let consumed_before: BTreeSet<String> = self
            .contracts
            .iter()
            .filter(|(_, c)| !c.active)
            .map(|(id, _)| id.clone())
            .collect();
        let lookup = KeyLookup {
            template_id: template_id.to_string(),
            key: key.clone(),
            contract_ids,
            limit: n,
            submitters,
            missed_in_view,
            consumed_before,
        };
        self.recorded_key_lookups.push(RecordedKeyLookup {
            package_id: package_id.to_string(),
            lookup: lookup.clone(),
            event_pos: self.events.len().saturating_sub(self.command_events_start),
            depth: self.depth,
            is_query: authorize,
        });
        self.key_lookups.push(lookup);
        if authorize {
            self.next_node_idx += 1;
        }
        Ok(found)
    }

    fn fetch(&mut self, request: &FetchRequest<'_>) -> Result<Value, EvalError> {
        let contract =
            self.lookup_typed(request.contract_id, request.package_id, request.template_id)?;
        if !self.visible_to_submitters(contract) {
            return Err(EvalError::ContractNotFound {
                contract_id: request.contract_id.to_string(),
            });
        }
        self.authorize_fetch(contract)?;
        let payload = contract.payload.clone();
        let stakeholders: BTreeSet<&String> = contract
            .signatories
            .iter()
            .chain(contract.observers.iter())
            .collect();
        let authorizers = self
            .current_authorizers()?
            .iter()
            .filter(|p| stakeholders.contains(p))
            .cloned()
            .collect();
        self.events.push(EngineEvent::Fetch {
            contract_id: request.contract_id.to_string(),
            depth: self.depth,
            authorizers,
            interface_id: None,
        });
        self.next_node_idx += 1;
        Ok(payload)
    }

    fn exercise_interface(
        &mut self,
        request: &crate::ExerciseInterfaceRequest<'_>,
    ) -> Result<Value, EvalError> {
        if self.depth >= MAX_EXERCISE_DEPTH {
            return Err(EvalError::Host(format!(
                "exercise nesting exceeds {MAX_EXERCISE_DEPTH}"
            )));
        }
        let (package_id, template_id, payload, signatories) = {
            let contract = self.lookup(request.contract_id)?;
            (
                contract.package_id.clone(),
                contract.template_id.clone(),
                contract.payload.clone(),
                contract.signatories.clone(),
            )
        };
        if !self.world.template_implements(
            &package_id,
            &template_id,
            request.interface_package_id,
            request.interface_id,
        )? {
            return Err(EvalError::Host(format!(
                "contract {} ({template_id}) does not implement {}",
                request.contract_id, request.interface_id
            )));
        }
        let iface_val = Value::Iface {
            package_id: package_id.clone(),
            template: template_id.clone(),
            payload: Box::new(payload),
        };
        if let Some(guard) = request.guard {
            match self.world.apply_closed(guard, vec![iface_val.clone()])? {
                Value::Bool(true) => {}
                _ => return Err(EvalError::Host("Exercise guard failed".to_string())),
            }
        }
        let controllers = self.world.eval_interface_choice_controllers_in(
            request.interface_package_id,
            request.interface_id,
            request.choice,
            &iface_val,
            request.arg,
        )?;
        let observers = self.world.eval_interface_choice_observers_in(
            request.interface_package_id,
            request.interface_id,
            request.choice,
            &iface_val,
            request.arg,
        )?;
        // [CANTON-NOTE: SEMANTICS] Same rule as for template choices: an interface choice whose controllers are the
        // empty set (`controller actors` with `actors = []`) is an authorization failure on the JVM (measured:
        // `t2_actors_empty`, `ti2_accept_empty_actors`), not a body that runs.
        let node_id = self.next_node_idx;
        let full_template = format!("{package_id}:{template_id}");
        let authorizers = self.current_authorizers()?.clone();
        if controllers.is_empty() {
            return Err(EvalError::Unauthorized {
                kind: AuthKind::Controllers,
                what: format!(
                    "exercise of {}:{} (no controllers)",
                    request.interface_id, request.choice
                ),
                required: Vec::new(),
                missing: Vec::new(),
                authorized: authorizers.clone(),
                detail: Some(Box::new(AuthDetail {
                    node_id,
                    rule: AuthRule::NoControllers,
                    template_id: full_template,
                    required_parties: Vec::new(),
                    context_parties: authorizers,
                })),
            });
        }
        require_covered(
            AuthKind::Controllers,
            AuthRule::ExerciseMissingAuthorization,
            node_id,
            &full_template,
            &format!("exercise of {}:{}", request.interface_id, request.choice),
            &controllers,
            &authorizers,
        )?;
        self.next_node_idx += 1;
        let consuming = self.world.interface_choice_is_consuming(
            request.interface_package_id,
            request.interface_id,
            request.choice,
        )?;
        if consuming {
            if let Some(contract) = self.contracts.get_mut(request.contract_id) {
                contract.active = false;
                self.ledger_effects += 1;
            }
        }
        let event_at = self.events.len();
        self.events.push(EngineEvent::Exercise {
            contract_id: request.contract_id.to_string(),
            choice: request.choice.to_string(),
            consuming,
            actors: controllers.clone(),
            depth: self.depth,
            argument: request.arg.clone(),
            result: None,
            interface_id: Some(format!(
                "{}:{}",
                request.interface_package_id, request.interface_id
            )),
            observers,
        });
        // Authority inside the body = contract signatories + choice controllers (as for template choices).
        let mut inner: BTreeSet<String> = signatories.into_iter().collect();
        inner.extend(controllers);
        self.authorizers.push(inner);
        self.depth += 1;
        let world = self.world;
        let result = world.eval_interface_choice_update_in(
            request.interface_package_id,
            request.interface_id,
            request.choice,
            request.contract_id,
            &iface_val,
            request.arg,
            self,
        );
        self.depth -= 1;
        self.authorizers.pop();
        if let Ok(value) = &result {
            if let Some(EngineEvent::Exercise { result: slot, .. }) = self.events.get_mut(event_at)
            {
                *slot = Some(value.clone());
            }
        }
        result
    }

    fn fetch_contract(
        &mut self,
        contract_id: &str,
        interface_id: Option<&str>,
    ) -> Result<crate::FetchedContract, EvalError> {
        let contract = self.lookup(contract_id)?;
        if !self.visible_to_submitters(contract) {
            return Err(EvalError::ContractNotFound {
                contract_id: contract_id.to_string(),
            });
        }
        self.authorize_fetch(contract)?;
        let fetched = crate::FetchedContract {
            package_id: contract.package_id.clone(),
            template_id: contract.template_id.clone(),
            payload: contract.payload.clone(),
        };
        let stakeholders: BTreeSet<&String> = contract
            .signatories
            .iter()
            .chain(contract.observers.iter())
            .collect();
        let authorizers = self
            .current_authorizers()?
            .iter()
            .filter(|p| stakeholders.contains(p))
            .cloned()
            .collect();
        self.events.push(EngineEvent::Fetch {
            contract_id: contract_id.to_string(),
            depth: self.depth,
            authorizers,
            interface_id: interface_id.map(String::from),
        });
        self.next_node_idx += 1;
        Ok(fetched)
    }

    fn get_time(&mut self) -> Result<i64, EvalError> {
        Ok(self.now_micros)
    }

    fn begin_try(&mut self) -> Result<TryCheckpoint, EvalError> {
        // [CANTON-NOTE: SEMANTICS] `PartialTransaction.beginTry` reserves `NodeId(nextNodeIdx)` for the
        // `Rollback` node and never rewinds `nextNodeIdx` on `endTry` or `rollbackTry`.
        self.next_node_idx += 1;
        self.checkpoints.push(Checkpoint {
            effects: self.ledger_effects,
            contracts: self.contracts.clone(),
            keys: self.keys.clone(),
            events_len: self.events.len(),
            recorded_lookups_len: self.recorded_key_lookups.len(),
            authorizers: self.authorizers.clone(),
            depth: self.depth,
        });
        Ok(TryCheckpoint(self.checkpoints.len() - 1))
    }

    fn end_try(&mut self, checkpoint: TryCheckpoint) -> Result<(), EvalError> {
        // Dropping the snapshot keeps the body's effects. Newer checkpoints cannot be open
        // on a normal exit (try frames nest properly); truncating keeps the stack honest
        // even if one leaked.
        self.take_checkpoint(checkpoint).map(|_| ())
    }

    fn abort_try(&mut self, checkpoint: TryCheckpoint) -> Result<(), EvalError> {
        let snapshot = self.take_checkpoint(checkpoint)?;
        // [CANTON-NOTE: SEMANTICS] Speedy refuses to roll back a `try` body that had a ledger effect: if any contract
        // was created or consumed (archived) since `begin_try`, the exception that reaches the `try` becomes an
        // `EffectfulRollbackError` instead of being handled (`ContractStateMachine.Journal.abortTry`:
        // `createdInThisTimeline` or `consumedBy` grew). This happens even when the `catch` would not have matched the
        // exception, because Speedy rolls back before it looks at the handler. Non-consuming exercises, fetches and key
        // lookups are not effects, and a nested `try` that rolled back cleanly leaves no trace. Measured on JVM 3.7.2
        // for LF 2.1 and 2.3 (`rb*` scenarios in tests/oracle/key-diff).
        // [CANTON-NOTE: WHY] Effects are counted (`ledger_effects`), not derived from the contract set, because
        // `import_contract` also adds contracts and is ACS seeding, not a transaction node; the contract set is only
        // used to name the offending ids in the error.
        if self.ledger_effects != snapshot.effects {
            let mut contracts: Vec<String> = self
                .contracts
                .iter()
                .filter(|(id, c)| match snapshot.contracts.get(*id) {
                    None => true,
                    Some(before) => before.active && !c.active,
                })
                .map(|(id, _)| id.clone())
                .collect();
            contracts.sort();
            return Err(EvalError::EffectfulRollback { contracts });
        }
        // Restores consumed flags (archived contracts become active again), removes
        // contracts created inside the failed body, and forgets their journal events.
        self.contracts = snapshot.contracts;
        self.keys = snapshot.keys;
        self.recorded_key_lookups
            .truncate(snapshot.recorded_lookups_len);
        // keep what the body journaled for the positions of what follows (a rollback takes no index, its nodes do)
        let mut removed: Vec<EngineEvent> = Vec::new();
        let nested: Vec<RolledBack> = {
            let (inside, outside): (Vec<_>, Vec<_>) = std::mem::take(&mut self.rolled_back)
                .into_iter()
                .partition(|g| g.at >= snapshot.events_len);
            self.rolled_back = outside;
            inside
        };
        let body: Vec<EngineEvent> = self.events.drain(snapshot.events_len..).collect();
        for offset in 0..=body.len() {
            for group in nested
                .iter()
                .filter(|g| g.at - snapshot.events_len == offset)
            {
                removed.extend(group.events.iter().cloned());
            }
            if let Some(event) = body.get(offset) {
                removed.push(event.clone());
            }
        }
        if !removed.is_empty() {
            self.rolled_back.push(RolledBack {
                at: snapshot.events_len,
                events: removed,
            });
        }
        self.authorizers = snapshot.authorizers;
        self.depth = snapshot.depth;
        Ok(())
    }
}
