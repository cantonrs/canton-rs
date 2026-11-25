//! Synchronous `submit_and_wait` execution path for the Ledger API service.

use super::context::{compute_key_hash_b64, decoded_disclosed_blobs};
use super::{
    map_codec_error, map_exec_error, root_exercise_actors, ApiError, Arc, Command, ContractId,
    CreatedEvent, Engine, EngineContract, ExecutionService, ExercisedEvent, GenericContract,
    HashMap, HashSet, LfTransactionTree, Node, Ordering, PayloadSchema, SubmitAndWaitRequest,
    TemplateId, TemplateResolution, TransactionCommit, TransactionTree, TreeEvent,
};

impl ExecutionService {
    /// Execute SubmitAndWaitRequest from Ledger API.
    pub fn submit_and_wait(&self, req: SubmitAndWaitRequest) -> Result<TransactionTree, ApiError> {
        let now = crate::clock::now_secs();
        let offset = self.next_offset();

        // Enforce Command Deduplication window (AT-U01, AT-T03)
        if let Ok(mut dedup) = self.dedup_store.write() {
            dedup.check_and_insert(
                &req.commands.application_id,
                &req.commands.command_id,
                req.commands.deduplication_period.as_ref(),
                now,
                offset,
            )?;
        }

        let act_as_refs: Vec<&str> = req.commands.act_as.iter().map(|s| s.as_str()).collect();

        // [CANTON-NOTE: SEMANTICS] In-flight transactional staging for multi-command submissions.
        // [CANTON-NOTE: INVARIANT] In Canton / Daml-LF transaction semantics, multiple commands within a single
        // submission form an atomic transaction. If ANY command fails or if apply_transaction rejects,
        // all in-flight changes are discarded without mutating generic_contracts, active_state, or journal.
        // [CANTON-NOTE: WHY] Prevents partial execution where earlier commands commit active state changes while
        // subsequent commands fail, violating the atomicity guarantee of submit_and_wait.
        let mut working_generic = self
            .generic_contracts
            .read()
            .map_err(|e| ApiError::Ledger(e.to_string()))?
            .clone();
        let mut working_ledger = self
            .ledger
            .read()
            .map_err(|e| ApiError::Ledger(e.to_string()))?
            .clone();

        let mut staged_consumed_cids = Vec::new();
        let mut staged_archived_cids = Vec::new();
        let mut staged_created_contracts = Vec::new();
        let mut staged_root_argument: Option<lf_eval::Value> = None;
        let mut staged_root_package_id: Option<String> = None;
        let mut staged_engine_events: Vec<lf_eval::EngineEvent> = Vec::new();
        let mut staged_rolled_back: Vec<lf_eval::engine::RolledBack> = Vec::new();
        let mut staged_key_lookups: Vec<lf_eval::engine::RecordedKeyLookup> = Vec::new();
        let mut staged_history: Option<crate::history::HistoryInput> = None;
        let mut staged_legacy_archived_cids = Vec::new();
        let mut staged_lf_tree = LfTransactionTree::new();
        let mut has_legacy_mutations = false;

        let mut events_by_id = HashMap::new();
        let mut root_event_ids = Vec::new();

        for cmd in req.commands.commands {
            match cmd {
                Command::Create(create_cmd) => {
                    match self.resolve_template(&create_cmd.template_id) {
                        TemplateResolution::NotFound(id) => {
                            return Err(ApiError::TemplateNotFound(id))
                        }
                        TemplateResolution::Interface { interface_id, .. } => {
                            return Err(ApiError::TemplateNotFound(interface_id))
                        }
                        TemplateResolution::LegacyAssetHolding => {
                            let holding = Self::value_to_holding(&create_cmd.create_arguments)?;

                            // Check authorization: bank and owner must be in act_as
                            if !act_as_refs.contains(&holding.bank.as_str())
                                || !act_as_refs.contains(&holding.owner.as_str())
                            {
                                return Err(ApiError::Unauthorized(format!(
                                    "Node requires authorizers {},{}, but only {} were given",
                                    holding.bank,
                                    holding.owner,
                                    req.commands.act_as.join(",")
                                )));
                            }

                            if holding.tenths <= 0 {
                                return Err(ApiError::PreconditionFailed(format!(
                                    "Template precondition violated: amount must be positive, got {}",
                                    Self::format_amount(holding.tenths)
                                )));
                            }

                            let cid = working_ledger
                                .create(&act_as_refs, holding.clone())
                                .map_err(ApiError::Ledger)?;
                            has_legacy_mutations = true;

                            let event_id = self.next_event_id();
                            let contract_id = Self::format_contract_id(cid);

                            let created_event = CreatedEvent {
                                event_id: event_id.clone(),
                                contract_id: contract_id.clone(),
                                template_id: create_cmd.template_id.clone(),
                                create_arguments: Self::holding_to_value(&holding),
                                signatories: vec![holding.bank.clone(), holding.owner.clone()],
                                observers: vec![holding.auditor.clone()],
                                witness_parties: vec![
                                    holding.bank.clone(),
                                    holding.owner.clone(),
                                    holding.auditor.clone(),
                                ],
                            };

                            let mut sigs = HashSet::new();
                            sigs.insert(holding.bank.clone());
                            sigs.insert(holding.owner.clone());
                            let mut obs = HashSet::new();
                            obs.insert(holding.auditor.clone());
                            staged_lf_tree.insert_node(
                                Node::Create {
                                    contract_id: ContractId(contract_id.clone()),
                                    template_id: create_cmd.template_id.to_string(),
                                    payload: serde_json::to_vec(&create_cmd.create_arguments)
                                        .unwrap_or_default(),
                                    signatories: sigs,
                                    observers: obs,
                                    key: None,
                                },
                                true,
                            );

                            root_event_ids.push(event_id.clone());
                            events_by_id.insert(event_id, TreeEvent::Created(created_event));
                        }
                        TemplateResolution::Generic {
                            package,
                            local_id,
                            package_id,
                        } => {
                            // Generic create using bytecode evaluator: checks Daml ensure invariant and all signatories in act_as
                            let schema = PayloadSchema::template(&package, &package_id, &local_id)
                                .map_err(map_codec_error)?;
                            let val =
                                schema
                                    .from_json(&create_cmd.create_arguments)
                                    .map_err(|e| {
                                        ApiError::InvalidArgument(format!(
                                            "Invalid arguments for {local_id}: {e}"
                                        ))
                                    })?;

                            self.contract_counter
                                .fetch_max(working_ledger.contracts.len() as u64, Ordering::SeqCst);

                            let mut engine = Engine::new(&package.world);
                            // [CANTON-NOTE: SEMANTICS] `getTime` of a choice is the ledger time of the command (the clock of the service), not 0: the rounds
                            // of the official Splice DARs open at the bootstrap time and their `opensAt` checks compare with it.
                            engine.set_time_micros(crate::clock::now_micros());
                            engine.set_contract_id_allocator(self.contract_id_allocator());

                            let created = engine
                                .execute_create(&req.commands.act_as, &local_id, &val)
                                .map_err(map_exec_error)?;
                            self.pad_ledger_slots();
                            {
                                let events = [lf_eval::EngineEvent::Create {
                                    contract_id: created.contract_id.clone(),
                                    template_id: local_id.clone(),
                                    depth: 0,
                                }];
                                staged_history
                                    .get_or_insert_with(|| {
                                        crate::history::HistoryInput::new(Arc::clone(&package))
                                    })
                                    .remember(&events, |id| engine.contract(id).cloned());
                            }

                            let json_payload = schema.to_json(&created.payload).map_err(|e| {
                                ApiError::Ledger(format!(
                                    "Failed to serialize contract payload: {e}"
                                ))
                            })?;

                            let mut witness = created.signatories.clone();
                            for obs in &created.observers {
                                if !witness.contains(obs) {
                                    witness.push(obs.clone());
                                }
                            }

                            let contract_key_hash = compute_key_hash_b64(
                                &package.world,
                                &package_id,
                                &local_id,
                                created.key.as_ref(),
                            );
                            let g_contract = GenericContract {
                                contract_id: created.contract_id.clone(),
                                package_id: package_id.clone(),
                                template_id: create_cmd.template_id.clone(),
                                payload_value: created.payload.clone(),
                                json_payload: json_payload.clone(),
                                signatories: created.signatories.clone(),
                                observers: created.observers.clone(),
                                witness_parties: witness.clone(),
                                active: true,
                                key_value: created.key.clone(),
                                created_at_micros: crate::clock::now_micros(),
                                created_event_blob: String::new(),
                                contract_key_hash,
                                key_maintainers: Vec::new(),
                                creation_seq: self.next_creation_seq(),
                            };

                            working_generic.insert(created.contract_id.clone(), g_contract.clone());
                            staged_created_contracts.push(g_contract);

                            let event_id = self.next_event_id();
                            let created_event = CreatedEvent {
                                event_id: event_id.clone(),
                                contract_id: created.contract_id.clone(),
                                template_id: create_cmd.template_id.clone(),
                                create_arguments: json_payload.clone(),
                                signatories: created.signatories.clone(),
                                observers: created.observers.clone(),
                                witness_parties: witness,
                            };

                            let mut sigs = HashSet::new();
                            for s in &created.signatories {
                                sigs.insert(s.clone());
                            }
                            let mut obs = HashSet::new();
                            for o in &created.observers {
                                obs.insert(o.clone());
                            }
                            staged_lf_tree.insert_node(
                                Node::Create {
                                    contract_id: ContractId(created.contract_id.clone()),
                                    template_id: create_cmd.template_id.to_string(),
                                    payload: serde_json::to_vec(&json_payload).unwrap_or_default(),
                                    signatories: sigs,
                                    observers: obs,
                                    key: None,
                                },
                                true,
                            );

                            root_event_ids.push(event_id.clone());
                            events_by_id.insert(event_id, TreeEvent::Created(created_event));
                        }
                    }
                }
                Command::Exercise(exec_cmd) => {
                    let resolution = self.resolve_template(&exec_cmd.template_id);
                    match resolution {
                        TemplateResolution::NotFound(id) => {
                            return Err(ApiError::TemplateNotFound(id));
                        }
                        TemplateResolution::Generic { .. }
                        | TemplateResolution::Interface { .. } => {
                            let (package, local_id, iface_exec) = match resolution {
                                TemplateResolution::Generic {
                                    package, local_id, ..
                                } => (package, local_id, None),
                                TemplateResolution::Interface {
                                    package,
                                    interface_id,
                                    interface_package_id,
                                } => (
                                    package,
                                    interface_id.clone(),
                                    Some((interface_package_id, interface_id)),
                                ),
                                _ => unreachable!(),
                            };
                            // [CANTON-NOTE: INVARIANT] Loaded DAR requests must be evaluated exclusively by lf-eval::Engine
                            // and must NEVER reach the legacy "Transfer"/"SplitTransfer" string arms. If the target contract
                            // does not exist or is inactive in working_generic, it must immediately fail with ContractNotActive.
                            // [CANTON-NOTE: WHY] In Daml-LF semantics, once a package is loaded, choice execution is governed
                            // by compiled bytecode and type schemas, not static host string dispatch.
                            // [CANTON-NOTE: SEMANTICS] When a template resolves to Generic, non-existent or consumed contracts
                            // must immediately fail with ContractNotActive (HTTP 404) rather than attempting legacy ledger fallback.
                            let existing = working_generic
                                .get(&exec_cmd.contract_id)
                                .cloned()
                                .ok_or_else(|| {
                                    ApiError::ContractNotActive(exec_cmd.contract_id.clone())
                                })?;

                            if !existing.active {
                                return Err(ApiError::ContractNotActive(exec_cmd.contract_id));
                            }

                            let existing_local_id = format!(
                                "{}:{}",
                                existing.template_id.module_name, existing.template_id.entity_name
                            );
                            if iface_exec.is_none() && existing_local_id != local_id {
                                return Err(ApiError::InvalidArgument(format!(
                                    "Contract {} is of template {}, not {}",
                                    exec_cmd.contract_id, existing_local_id, local_id
                                )));
                            }

                            let package = self.resolve_exercise_package(
                                package,
                                &existing.package_id,
                                iface_exec.as_ref().map(|(pid, _)| pid.as_str()),
                            );
                            let arg_val = self.decode_choice_arg(
                                &package,
                                &existing.package_id,
                                &local_id,
                                iface_exec
                                    .as_ref()
                                    .map(|(pid, iid)| (pid.as_str(), iid.as_str())),
                                &exec_cmd.choice,
                                &exec_cmd.choice_argument,
                            )?;

                            self.contract_counter
                                .fetch_max(working_ledger.contracts.len() as u64, Ordering::SeqCst);

                            staged_root_argument = Some(arg_val.clone());
                            if iface_exec.is_none() && staged_root_package_id.is_none() {
                                staged_root_package_id = Some(package.main_package_id.clone());
                            }
                            let mut engine = Engine::new(&package.world);
                            // [CANTON-NOTE: SEMANTICS] `getTime` of a choice is the ledger time of the command (the clock of the service), not 0: the rounds
                            // of the official Splice DARs open at the bootstrap time and their `opensAt` checks compare with it.
                            engine.set_time_micros(crate::clock::now_micros());
                            engine.set_contract_id_allocator(self.contract_id_allocator());

                            // Seed target contract
                            let seed = EngineContract {
                                contract_id: existing.contract_id.clone(),
                                package_id: existing.package_id.clone(),
                                template_id: existing_local_id,
                                payload: existing.payload_value.clone(),
                                signatories: existing.signatories.clone(),
                                observers: existing.observers.clone(),
                                active: true,
                                key: existing.key_value.clone(),
                            };
                            engine
                                .import_contract(seed)
                                .map_err(|e| ApiError::Ledger(e.to_string()))?;

                            // Seed other active generic contracts of the same package for nested fetch/exercise
                            let mut other_active: Vec<&GenericContract> = working_generic
                                .values()
                                .filter(|other| {
                                    other.active
                                        && other.contract_id != existing.contract_id
                                        && other.package_id == existing.package_id
                                })
                                .collect();
                            other_active.sort_by_key(|c| (c.creation_seq, c.contract_id.as_str()));
                            for other in other_active {
                                let other_local = format!(
                                    "{}:{}",
                                    other.template_id.module_name, other.template_id.entity_name
                                );
                                let other_seed = EngineContract {
                                    contract_id: other.contract_id.clone(),
                                    package_id: other.package_id.clone(),
                                    template_id: other_local,
                                    payload: other.payload_value.clone(),
                                    signatories: other.signatories.clone(),
                                    observers: other.observers.clone(),
                                    active: true,
                                    key: other.key_value.clone(),
                                };
                                let _ = engine.import_contract(other_seed);
                            }

                            let outcome = match &iface_exec {
                                Some((iface_pkg_id, iface_id)) => engine
                                    .execute_exercise_interface(
                                        &req.commands.act_as,
                                        iface_pkg_id,
                                        iface_id,
                                        &exec_cmd.contract_id,
                                        &exec_cmd.choice,
                                        &arg_val,
                                    )
                                    .map_err(map_exec_error)?,
                                None => engine
                                    .execute_exercise(
                                        &req.commands.act_as,
                                        &exec_cmd.contract_id,
                                        &exec_cmd.choice,
                                        &arg_val,
                                    )
                                    .map_err(map_exec_error)?,
                            };
                            self.pad_ledger_slots();
                            let offset = staged_engine_events.len();
                            staged_rolled_back.extend(outcome.rolled_back.iter().map(|g| {
                                lf_eval::engine::RolledBack {
                                    at: g.at + offset,
                                    events: g.events.clone(),
                                }
                            }));
                            staged_key_lookups.extend(
                                engine.recorded_key_lookups().iter().cloned().map(|mut lk| {
                                    lk.event_pos += offset;
                                    lk
                                }),
                            );
                            staged_engine_events.extend(outcome.events.iter().cloned());
                            staged_history
                                .get_or_insert_with(|| {
                                    crate::history::HistoryInput::new(Arc::clone(&package))
                                })
                                .remember(&outcome.events, |id| engine.contract(id).cloned());

                            // Staged deactivation in working_generic
                            if outcome.consuming {
                                if let Some(c) = working_generic.get_mut(&exec_cmd.contract_id) {
                                    c.active = false;
                                }
                                staged_consumed_cids.push(exec_cmd.contract_id.clone());
                                staged_legacy_archived_cids.push(exec_cmd.contract_id.clone());
                            }
                            for arch_id in &outcome.archived {
                                if let Some(c) = working_generic.get_mut(arch_id) {
                                    c.active = false;
                                }
                                staged_archived_cids.push(arch_id.clone());
                                staged_legacy_archived_cids.push(arch_id.clone());
                            }

                            let mut child_event_ids = Vec::new();
                            let mut created_contracts = Vec::new();
                            for created in &outcome.created {
                                let tmpl_schema = PayloadSchema::template(
                                    &package,
                                    &created.package_id,
                                    &created.template_id,
                                )
                                .map_err(|e| {
                                    ApiError::Ledger(format!(
                                        "failed to get schema for created template {}: {e}",
                                        created.template_id
                                    ))
                                })?;
                                let c_json =
                                    tmpl_schema.to_json(&created.payload).map_err(|e| {
                                        ApiError::Ledger(format!(
                                            "failed to serialize created payload: {e}"
                                        ))
                                    })?;
                                let mut witness = created.signatories.clone();
                                for obs in &created.observers {
                                    if !witness.contains(obs) {
                                        witness.push(obs.clone());
                                    }
                                }
                                let (mod_name, ent_name) = created
                                    .template_id
                                    .split_once(':')
                                    .unwrap_or(("", &created.template_id));
                                let c_template_id = TemplateId {
                                    package_id: created.package_id.clone(),
                                    module_name: mod_name.to_string(),
                                    entity_name: ent_name.to_string(),
                                };
                                let contract_key_hash = compute_key_hash_b64(
                                    &package.world,
                                    &created.package_id,
                                    &created.template_id,
                                    created.key.as_ref(),
                                );
                                let g_created = GenericContract {
                                    contract_id: created.contract_id.clone(),
                                    package_id: created.package_id.clone(),
                                    template_id: c_template_id.clone(),
                                    payload_value: created.payload.clone(),
                                    json_payload: c_json.clone(),
                                    signatories: created.signatories.clone(),
                                    observers: created.observers.clone(),
                                    witness_parties: witness.clone(),
                                    active: created.active,
                                    key_value: created.key.clone(),
                                    created_at_micros: crate::clock::now_micros(),
                                    created_event_blob: String::new(),
                                    contract_key_hash,
                                    key_maintainers: Vec::new(),
                                    creation_seq: self.next_creation_seq(),
                                };
                                working_generic
                                    .insert(created.contract_id.clone(), g_created.clone());
                                staged_created_contracts.push(g_created.clone());
                                created_contracts.push((g_created, c_json));
                            }

                            for (gc, c_json) in &created_contracts {
                                if !gc.active {
                                    continue;
                                }
                                let child_id = self.next_event_id();
                                child_event_ids.push(child_id.clone());
                                events_by_id.insert(
                                    child_id.clone(),
                                    TreeEvent::Created(CreatedEvent {
                                        event_id: child_id,
                                        contract_id: gc.contract_id.clone(),
                                        template_id: gc.template_id.clone(),
                                        create_arguments: c_json.clone(),
                                        signatories: gc.signatories.clone(),
                                        observers: gc.observers.clone(),
                                        witness_parties: gc.witness_parties.clone(),
                                    }),
                                );
                            }

                            let mut child_node_ids = Vec::new();
                            for (gc, c_json) in &created_contracts {
                                let mut sigs = HashSet::new();
                                for s in &gc.signatories {
                                    sigs.insert(s.clone());
                                }
                                let mut obs = HashSet::new();
                                for o in &gc.observers {
                                    obs.insert(o.clone());
                                }
                                let nid = staged_lf_tree.insert_node(
                                    Node::Create {
                                        contract_id: ContractId(gc.contract_id.clone()),
                                        template_id: gc.template_id.to_string(),
                                        payload: serde_json::to_vec(c_json).unwrap_or_default(),
                                        signatories: sigs,
                                        observers: obs,
                                        key: None,
                                    },
                                    false,
                                );
                                child_node_ids.push(nid);
                            }

                            let mut acting = HashSet::new();
                            let root_actors = root_exercise_actors(&outcome, &req.commands.act_as);
                            acting.extend(root_actors.clone());
                            staged_lf_tree.insert_node(
                                Node::Exercise {
                                    contract_id: ContractId(exec_cmd.contract_id.clone()),
                                    choice: exec_cmd.choice.clone(),
                                    acting_parties: acting,
                                    consuming: outcome.consuming,
                                    children: child_node_ids,
                                },
                                true,
                            );

                            let event_id = self.next_event_id();
                            let result_val = match &outcome.result {
                                lf_eval::Value::ContractId(cid) => {
                                    Some(serde_json::Value::String(cid.clone()))
                                }
                                _ => None,
                            };
                            let exercised = ExercisedEvent {
                                event_id: event_id.clone(),
                                contract_id: exec_cmd.contract_id,
                                template_id: exec_cmd.template_id,
                                choice: exec_cmd.choice,
                                choice_argument: exec_cmd.choice_argument,
                                acting_parties: root_actors,
                                consuming: outcome.consuming,
                                witness_parties: existing.witness_parties,
                                child_event_ids,
                                exercise_result: result_val,
                            };

                            root_event_ids.push(event_id.clone());
                            events_by_id.insert(event_id, TreeEvent::Exercised(exercised));
                        }
                        TemplateResolution::LegacyAssetHolding => {
                            // [CANTON-NOTE: LIMITATION] Unloaded DAR fallback: when no DAR is loaded, requests fall back
                            // to SingleContractLedger string matching strictly for backward compatibility with unloaded fixture suites.
                            // This arm is strictly unreachable when any DAR package has been loaded.
                            let cid = Self::parse_contract_id(&exec_cmd.contract_id)?;
                            let holding = working_ledger
                                .fetch(cid)
                                .map_err(ApiError::ContractNotActive)?;
                            has_legacy_mutations = true;

                            let event_id = self.next_event_id();
                            let mut child_event_ids = Vec::new();
                            let mut created_holdings = Vec::new();

                            match exec_cmd.choice.as_str() {
                                "Transfer" => {
                                    if !act_as_refs.contains(&holding.owner.as_str()) {
                                        return Err(ApiError::Unauthorized(format!(
                                        "Transfer choice requires controller {}, but only {} were given",
                                        holding.owner,
                                        req.commands.act_as.join(",")
                                    )));
                                    }
                                    let new_owner = exec_cmd
                                        .choice_argument
                                        .get("newOwner")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| {
                                            ApiError::InvalidArgument(
                                                "missing 'newOwner' argument".into(),
                                            )
                                        })?;

                                    if new_owner == holding.owner {
                                        return Err(ApiError::InvalidArgument(
                                            "New owner cannot be the same as current owner".into(),
                                        ));
                                    }

                                    let new_cid = working_ledger
                                        .exercise_transfer(cid, &act_as_refs, new_owner)
                                        .map_err(ApiError::Ledger)?;

                                    let child_id = self.next_event_id();
                                    let new_holding =
                                        working_ledger.fetch(new_cid).map_err(ApiError::Ledger)?;
                                    created_holdings.push((
                                        Self::format_contract_id(new_cid),
                                        new_holding.clone(),
                                    ));

                                    let created = CreatedEvent {
                                        event_id: child_id.clone(),
                                        contract_id: Self::format_contract_id(new_cid),
                                        template_id: exec_cmd.template_id.clone(),
                                        create_arguments: Self::holding_to_value(&new_holding),
                                        signatories: vec![
                                            new_holding.bank.clone(),
                                            new_holding.owner.clone(),
                                        ],
                                        observers: vec![new_holding.auditor.clone()],
                                        witness_parties: vec![
                                            new_holding.bank,
                                            new_holding.owner,
                                            new_holding.auditor,
                                        ],
                                    };

                                    child_event_ids.push(child_id.clone());
                                    events_by_id.insert(child_id, TreeEvent::Created(created));
                                }
                                "SplitTransfer" => {
                                    if !act_as_refs.contains(&holding.owner.as_str()) {
                                        return Err(ApiError::Unauthorized(format!(
                                        "SplitTransfer choice requires controller {}, but only {} were given",
                                        holding.owner,
                                        req.commands.act_as.join(",")
                                    )));
                                    }
                                    let recipient = exec_cmd
                                        .choice_argument
                                        .get("recipient")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| {
                                            ApiError::InvalidArgument(
                                                "missing 'recipient' argument".into(),
                                            )
                                        })?;
                                    let transfer_amt_val = exec_cmd
                                        .choice_argument
                                        .get("transferAmount")
                                        .ok_or_else(|| {
                                            ApiError::InvalidArgument(
                                                "missing 'transferAmount' argument".into(),
                                            )
                                        })?;
                                    let transfer_tenths = Self::parse_tenths(transfer_amt_val)?;

                                    let (moved_cid, left_cid) = working_ledger
                                        .exercise_split(
                                            cid,
                                            &act_as_refs,
                                            transfer_tenths,
                                            recipient,
                                        )
                                        .map_err(ApiError::Ledger)?;

                                    for child_cid in [moved_cid, left_cid] {
                                        let child_id = self.next_event_id();
                                        let child_holding = working_ledger
                                            .fetch(child_cid)
                                            .map_err(ApiError::Ledger)?;
                                        created_holdings.push((
                                            Self::format_contract_id(child_cid),
                                            child_holding.clone(),
                                        ));
                                        let created = CreatedEvent {
                                            event_id: child_id.clone(),
                                            contract_id: Self::format_contract_id(child_cid),
                                            template_id: exec_cmd.template_id.clone(),
                                            create_arguments: Self::holding_to_value(
                                                &child_holding,
                                            ),
                                            signatories: vec![
                                                child_holding.bank.clone(),
                                                child_holding.owner.clone(),
                                            ],
                                            observers: vec![child_holding.auditor.clone()],
                                            witness_parties: vec![
                                                child_holding.bank,
                                                child_holding.owner,
                                                child_holding.auditor,
                                            ],
                                        };
                                        child_event_ids.push(child_id.clone());
                                        events_by_id.insert(child_id, TreeEvent::Created(created));
                                    }
                                }
                                "Settle" => {
                                    if !act_as_refs.contains(&holding.bank.as_str()) {
                                        return Err(ApiError::Unauthorized(format!(
                                        "Settle choice requires controller {}, but only {} were given",
                                        holding.bank,
                                        req.commands.act_as.join(",")
                                    )));
                                    }
                                    working_ledger
                                        .exercise_settle(cid, &act_as_refs)
                                        .map_err(ApiError::Ledger)?;
                                }
                                other => {
                                    return Err(ApiError::InvalidArgument(format!(
                                        "Unknown choice '{other}' on template AssetHolding"
                                    )));
                                }
                            }

                            staged_consumed_cids.push(exec_cmd.contract_id.clone());

                            let mut child_node_ids = Vec::new();
                            for (child_cid, child_holding) in &created_holdings {
                                let mut sigs = HashSet::new();
                                sigs.insert(child_holding.bank.clone());
                                sigs.insert(child_holding.owner.clone());
                                let mut obs = HashSet::new();
                                obs.insert(child_holding.auditor.clone());
                                let nid = staged_lf_tree.insert_node(
                                    Node::Create {
                                        contract_id: ContractId(child_cid.clone()),
                                        template_id: exec_cmd.template_id.to_string(),
                                        payload: serde_json::to_vec(&Self::holding_to_value(
                                            child_holding,
                                        ))
                                        .unwrap_or_default(),
                                        signatories: sigs,
                                        observers: obs,
                                        key: None,
                                    },
                                    false,
                                );
                                child_node_ids.push(nid);
                            }

                            let mut acting = HashSet::new();
                            acting.extend(req.commands.act_as.clone());
                            staged_lf_tree.insert_node(
                                Node::Exercise {
                                    contract_id: ContractId(exec_cmd.contract_id.clone()),
                                    choice: exec_cmd.choice.clone(),
                                    acting_parties: acting,
                                    consuming: true,
                                    children: child_node_ids,
                                },
                                true,
                            );

                            let exercised = ExercisedEvent {
                                event_id: event_id.clone(),
                                contract_id: exec_cmd.contract_id,
                                template_id: exec_cmd.template_id,
                                choice: exec_cmd.choice,
                                choice_argument: exec_cmd.choice_argument,
                                acting_parties: req.commands.act_as.clone(),
                                consuming: true,
                                witness_parties: vec![holding.bank, holding.owner, holding.auditor],
                                child_event_ids,
                                exercise_result: None,
                            };

                            root_event_ids.push(event_id.clone());
                            events_by_id.insert(event_id, TreeEvent::Exercised(exercised));
                        }
                    }
                }
            }
        }

        let tx_tree = TransactionTree {
            update_id: format!("tx-{offset}"),
            command_id: req.commands.command_id,
            workflow_id: req.commands.workflow_id.unwrap_or_default(),
            effective_at: 1_700_000_000,
            offset,
            events_by_id,
            root_event_ids,
        };

        let act_as_set: HashSet<String> = req.commands.act_as.into_iter().collect();

        // [CANTON-NOTE: INVARIANT] Two-phase commit: validate apply_transaction before mutating active state.
        // If validation fails, in-flight mutations are completely rolled back.
        self.commit_transaction(TransactionCommit {
            consumed_cids: staged_consumed_cids,
            archived_cids: staged_archived_cids,
            created_contracts: staged_created_contracts,
            legacy_archived_cids: staged_legacy_archived_cids,
            working_ledger: if has_legacy_mutations {
                Some(working_ledger)
            } else {
                None
            },
            lf_tree: staged_lf_tree,
            act_as_set,
            tx_tree_record: Some(tx_tree.clone()),
            root_argument: staged_root_argument,
            engine_events: staged_engine_events,
            engine_rolled_back: staged_rolled_back,
            engine_key_lookups: staged_key_lookups,
            root_by_key: false,
            root_package_id: staged_root_package_id,
            disclosed_contracts: decoded_disclosed_blobs(),
            history: staged_history,
        })?;

        Ok(tx_tree)
    }
}
