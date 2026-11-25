//! JSON API v1 create/exercise/query execution handlers and LF transaction tree construction.

use super::context::{
    compute_key_hash_b64, current_disclosed_contracts, current_exercise_by_key, current_read_as,
    decoded_disclosed_blobs, disclosed_contract_by_id, AllocatedContractMeta,
};
use super::{
    map_codec_error, map_exec_error, root_exercise_actors, translate_payload, visible, ApiError,
    Arc, ArchivedContract, ContractId, ContractView, CreateRequest, CreateResult, CreatedContract,
    CreatedEvent, Engine, EngineContract, ExecutionService, ExerciseRequest, ExerciseResult,
    ExercisedEvent, GenericContract, HashMap, HashSet, JsonApiResponse, JsonEvent,
    LfTransactionTree, Mutex, Node, PayloadSchema, QueryContractsRequest, TemplateId,
    TemplateResolution, TransactionCommit, TransactionTree, TreeEvent, PACKAGE_ID,
};

impl ExecutionService {
    /// JSON API POST /v1/create implementation.
    ///
    /// Evaluates template creation through the generic Daml-LF evaluator if the template
    /// is defined in a loaded DAR package, or falls back to the legacy SingleContractLedger.
    pub fn json_create(
        &self,
        act_as: &[String],
        req: CreateRequest,
    ) -> Result<JsonApiResponse<CreateResult>, ApiError> {
        let effective_act_as: Vec<String> = if let Some(meta) = &req.meta {
            if let Some(meta_act) = &meta.act_as {
                meta_act.clone()
            } else {
                act_as.to_vec()
            }
        } else {
            act_as.to_vec()
        };

        match self.resolve_template(&req.template_id) {
            TemplateResolution::NotFound(id) => Err(ApiError::TemplateNotFound(id)),
            TemplateResolution::Interface { interface_id, .. } => {
                Err(ApiError::TemplateNotFound(interface_id))
            }
            TemplateResolution::LegacyAssetHolding => {
                // Legacy path for SingleContractLedger test fixtures
                let holding = Self::value_to_holding(&req.payload)?;

                // Authorization check: bank and owner must both be in act_as
                if !effective_act_as.contains(&holding.bank)
                    || !effective_act_as.contains(&holding.owner)
                {
                    return Err(ApiError::Unauthorized(format!(
                        "Left Authorization failure: node NodeId(0) ({}:AssetHolding:AssetHolding) requires authorizers {},{}, but only {} were given",
                        PACKAGE_ID,
                        holding.bank,
                        holding.owner,
                        effective_act_as.join(",")
                    )));
                }

                if holding.tenths <= 0 {
                    return Err(ApiError::PreconditionFailed(format!(
                        "Template precondition violated: amount must be positive, got {}",
                        Self::format_amount(holding.tenths)
                    )));
                }

                let act_as_refs: Vec<&str> = effective_act_as.iter().map(|s| s.as_str()).collect();
                let mut working_ledger = self
                    .ledger
                    .read()
                    .map_err(|e| ApiError::Ledger(e.to_string()))?
                    .clone();

                let cid = working_ledger
                    .create(&act_as_refs, holding.clone())
                    .map_err(ApiError::Ledger)?;

                let contract_id = Self::format_contract_id(cid);
                let offset = self.next_offset();

                let effective_tpl = if req.template_id.package_id.is_empty()
                    || req.template_id.module_name.is_empty()
                {
                    TemplateId::asset_holding()
                } else {
                    req.template_id.clone()
                };
                // Sync to lf-eval ActiveLedgerState and LedgerJournal
                let mut lf_tree = LfTransactionTree::new();
                let mut sigs = HashSet::new();
                sigs.insert(holding.bank.clone());
                sigs.insert(holding.owner.clone());
                let mut obs = HashSet::new();
                obs.insert(holding.auditor.clone());
                lf_tree.insert_node(
                    Node::Create {
                        contract_id: ContractId(contract_id.clone()),
                        template_id: effective_tpl.to_string(),
                        payload: serde_json::to_vec(&req.payload).unwrap_or_default(),
                        signatories: sigs,
                        observers: obs,
                        key: None,
                    },
                    true,
                );
                let act_as_set: HashSet<String> = effective_act_as.iter().cloned().collect();

                let event_id = self.next_event_id();
                let mut events_by_id = HashMap::new();
                events_by_id.insert(
                    event_id.clone(),
                    TreeEvent::Created(CreatedEvent {
                        event_id: event_id.clone(),
                        contract_id: contract_id.clone(),
                        template_id: effective_tpl,
                        create_arguments: req.payload.clone(),
                        signatories: vec![holding.bank.clone(), holding.owner.clone()],
                        observers: vec![holding.auditor.clone()],
                        witness_parties: vec![
                            holding.bank.clone(),
                            holding.owner.clone(),
                            holding.auditor.clone(),
                        ],
                    }),
                );

                let tx_tree = TransactionTree {
                    update_id: format!("tx-{offset}"),
                    command_id: format!("json-create-{cid}"),
                    workflow_id: String::new(),
                    effective_at: 1_700_000_000,
                    offset,
                    events_by_id,
                    root_event_ids: vec![event_id],
                };

                self.commit_transaction(TransactionCommit {
                    consumed_cids: vec![],
                    archived_cids: vec![],
                    created_contracts: vec![],
                    legacy_archived_cids: vec![],
                    working_ledger: Some(working_ledger),
                    lf_tree,
                    act_as_set,
                    tx_tree_record: Some(tx_tree),
                    root_argument: None,
                    engine_events: Vec::new(),
                    engine_rolled_back: Vec::new(),
                    engine_key_lookups: Vec::new(),
                    root_by_key: false,
                    root_package_id: None,
                    disclosed_contracts: Vec::new(),
                    history: None,
                })?;

                let result = CreateResult {
                    contract_id,
                    template_id: req.template_id,
                    key: None,
                    payload: Self::holding_to_value(&holding),
                    signatories: vec![holding.bank, holding.owner],
                    observers: vec![holding.auditor],
                    agreement_text: String::new(),
                };

                Ok(JsonApiResponse::ok(result))
            }
            TemplateResolution::Generic {
                package,
                local_id,
                package_id,
            } => {
                // Generic execution path using lf-eval::Engine and bytecode evaluation
                let schema = PayloadSchema::template(&package, &package_id, &local_id)
                    .map_err(map_codec_error)?;
                let val = schema.from_json(&req.payload).map_err(|e| {
                    ApiError::InvalidArgument(format!("Invalid payload for {local_id}: {e}"))
                })?;

                if let Ok(l) = self.ledger.read() {
                    self.sync_contract_counter_from_ledger(&l);
                }

                let created_at_micros = crate::clock::now_micros();
                let allocated_meta =
                    Arc::new(Mutex::new(HashMap::<String, AllocatedContractMeta>::new()));
                let mut engine = Engine::new(&package.world);
                // [CANTON-NOTE: SEMANTICS] `getTime` of a choice is the ledger time of the command (the clock of the service), not 0: the rounds
                // of the official Splice DARs open at the bootstrap time and their `opensAt` checks compare with it.
                engine.set_time_micros(crate::clock::now_micros());
                engine.set_contract_id_allocator(self.v2_contract_id_allocator(
                    &package,
                    created_at_micros,
                    Arc::clone(&allocated_meta),
                ));
                let read_as = current_read_as();
                engine.set_read_as(&read_as);
                let disclosed = current_disclosed_contracts();
                let disclosed_ids: Vec<&str> =
                    disclosed.iter().map(|c| c.contract_id.as_str()).collect();
                engine.set_disclosed(disclosed_ids);

                let created = engine
                    .execute_create(&effective_act_as, &local_id, &val)
                    .map_err(map_exec_error)?;
                self.pad_ledger_slots();
                let history = {
                    let mut history = crate::history::HistoryInput::new(Arc::clone(&package));
                    history.remember(
                        &[lf_eval::EngineEvent::Create {
                            contract_id: created.contract_id.clone(),
                            template_id: local_id.clone(),
                            depth: 0,
                        }],
                        |id| engine.contract(id).cloned(),
                    );
                    history
                };

                let json_payload = schema.to_json(&created.payload).map_err(|e| {
                    ApiError::Ledger(format!("Failed to serialize contract payload: {e}"))
                })?;

                let mut witness = created.signatories.clone();
                for obs in &created.observers {
                    if !witness.contains(obs) {
                        witness.push(obs.clone());
                    }
                }

                let meta = allocated_meta
                    .lock()
                    .ok()
                    .and_then(|mut m| m.remove(&created.contract_id));
                let contract_key_hash = meta.as_ref().map_or_else(
                    || {
                        compute_key_hash_b64(
                            &package.world,
                            &package_id,
                            &local_id,
                            created.key.as_ref(),
                        )
                    },
                    |m| m.contract_key_hash.clone(),
                );
                let (mod_name, ent_name) =
                    local_id.split_once(':').unwrap_or(("", local_id.as_str()));
                let resolved_tpl = TemplateId::new(&package_id, mod_name, ent_name);
                let g_contract = GenericContract {
                    contract_id: created.contract_id.clone(),
                    package_id,
                    template_id: resolved_tpl.clone(),
                    payload_value: created.payload.clone(),
                    json_payload: json_payload.clone(),
                    signatories: created.signatories.clone(),
                    observers: created.observers.clone(),
                    witness_parties: witness.clone(),
                    active: true,
                    key_value: created.key.clone(),
                    created_at_micros: meta
                        .as_ref()
                        .map_or(created_at_micros, |m| m.created_at_micros),
                    created_event_blob: meta
                        .as_ref()
                        .map_or_else(String::new, |m| m.created_event_blob.clone()),
                    contract_key_hash,
                    key_maintainers: meta.map_or_else(Vec::new, |m| m.key_maintainers),
                    creation_seq: self.next_creation_seq(),
                };

                let offset = self.next_offset();

                // Synchronize created contract with ActiveLedgerState and LedgerJournal
                let mut lf_tree = LfTransactionTree::new();
                let mut sigs = HashSet::new();
                for s in &created.signatories {
                    sigs.insert(s.clone());
                }
                let mut obs = HashSet::new();
                for o in &created.observers {
                    obs.insert(o.clone());
                }
                lf_tree.insert_node(
                    Node::Create {
                        contract_id: ContractId(created.contract_id.clone()),
                        template_id: resolved_tpl.to_string(),
                        payload: serde_json::to_vec(&json_payload).unwrap_or_default(),
                        signatories: sigs,
                        observers: obs,
                        key: None,
                    },
                    true,
                );
                let act_as_set: HashSet<String> = effective_act_as.iter().cloned().collect();

                let event_id = self.next_event_id();
                let mut events_by_id = HashMap::new();
                events_by_id.insert(
                    event_id.clone(),
                    TreeEvent::Created(CreatedEvent {
                        event_id: event_id.clone(),
                        contract_id: created.contract_id.clone(),
                        template_id: resolved_tpl.clone(),
                        create_arguments: json_payload.clone(),
                        signatories: created.signatories.clone(),
                        observers: created.observers.clone(),
                        witness_parties: witness,
                    }),
                );

                let tx_tree = TransactionTree {
                    update_id: format!("tx-{offset}"),
                    command_id: format!("json-create-{}", created.contract_id),
                    workflow_id: String::new(),
                    effective_at: 1_700_000_000,
                    offset,
                    events_by_id,
                    root_event_ids: vec![event_id],
                };

                self.commit_transaction(TransactionCommit {
                    consumed_cids: vec![],
                    archived_cids: vec![],
                    created_contracts: vec![g_contract],
                    legacy_archived_cids: vec![],
                    working_ledger: None,
                    lf_tree,
                    act_as_set,
                    tx_tree_record: Some(tx_tree),
                    root_argument: None,
                    engine_events: Vec::new(),
                    engine_rolled_back: Vec::new(),
                    engine_key_lookups: Vec::new(),
                    root_by_key: false,
                    root_package_id: None,
                    disclosed_contracts: Vec::new(),
                    history: Some(history),
                })?;

                let result = CreateResult {
                    contract_id: created.contract_id,
                    template_id: resolved_tpl,
                    key: None,
                    payload: json_payload,
                    signatories: created.signatories,
                    observers: created.observers,
                    agreement_text: String::new(),
                };

                Ok(JsonApiResponse::ok(result))
            }
        }
    }

    /// JSON API POST /v1/exercise implementation.
    ///
    /// If the target contract was created through the generic path, evaluates choice
    /// execution using Daml-LF bytecode (`Engine::execute_exercise`), archiving consuming
    /// contracts and dynamically instantiating resulting contracts. If the target contract
    /// is not in `generic_contracts`, falls back to legacy `SingleContractLedger`.
    pub fn json_exercise(
        &self,
        act_as: &[String],
        req: ExerciseRequest,
    ) -> Result<JsonApiResponse<ExerciseResult>, ApiError> {
        let effective_act_as: Vec<String> = if let Some(meta) = &req.meta {
            if let Some(meta_act) = &meta.act_as {
                meta_act.clone()
            } else {
                act_as.to_vec()
            }
        } else {
            act_as.to_vec()
        };

        let resolution = self.resolve_template(&req.template_id);
        match resolution {
            TemplateResolution::NotFound(id) => Err(ApiError::TemplateNotFound(id)),
            TemplateResolution::Generic { .. } | TemplateResolution::Interface { .. } => {
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
                // does not exist or is inactive in generic_contracts, it must immediately fail with ContractNotActive.
                // [CANTON-NOTE: WHY] In Daml-LF semantics, once a package is loaded, choice execution is governed
                // by compiled bytecode and type schemas, not static host string dispatch.
                // [CANTON-NOTE: SEMANTICS] When a template resolves to Generic, non-existent or consumed contracts
                // must immediately fail with ContractNotActive (HTTP 404) rather than attempting legacy ledger fallback.
                let existing = {
                    let g_lock = self
                        .generic_contracts
                        .read()
                        .map_err(|e| ApiError::Ledger(e.to_string()))?;
                    g_lock
                        .get(&req.contract_id)
                        .cloned()
                        .or_else(|| disclosed_contract_by_id(&req.contract_id))
                }
                .ok_or_else(|| ApiError::ContractNotActive(req.contract_id.clone()))?;

                if !existing.active {
                    return Err(ApiError::ContractNotActive(req.contract_id));
                }

                let existing_local_id = format!(
                    "{}:{}",
                    existing.template_id.module_name, existing.template_id.entity_name
                );
                if iface_exec.is_none() && existing_local_id != local_id {
                    return Err(ApiError::InvalidArgument(format!(
                        "Contract {} is of template {}, not {}",
                        req.contract_id, existing_local_id, local_id
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
                    &req.choice,
                    &req.argument,
                )?;

                if let Ok(l) = self.ledger.read() {
                    self.sync_contract_counter_from_ledger(&l);
                }

                let created_at_micros = crate::clock::now_micros();
                let allocated_meta =
                    Arc::new(Mutex::new(HashMap::<String, AllocatedContractMeta>::new()));
                let mut engine = Engine::new(&package.world);
                // [CANTON-NOTE: SEMANTICS] `getTime` of a choice is the ledger time of the command (the clock of the service), not 0: the rounds
                // of the official Splice DARs open at the bootstrap time and their `opensAt` checks compare with it.
                engine.set_time_micros(crate::clock::now_micros());
                engine.set_contract_id_allocator(self.v2_contract_id_allocator(
                    &package,
                    created_at_micros,
                    Arc::clone(&allocated_meta),
                ));
                let read_as = current_read_as();
                engine.set_read_as(&read_as);
                let disclosed = current_disclosed_contracts();
                let disclosed_ids: Vec<&str> =
                    disclosed.iter().map(|c| c.contract_id.as_str()).collect();
                engine.set_disclosed(disclosed_ids);

                let cmd_pkg_name = self.v2_package_name(&package.main_package_id);
                let world_types = lf_eval::typed_json::Types::new(&package.world);
                let seed_for_contract = |c: &GenericContract| -> Result<EngineContract, ApiError> {
                    let (seed_package, seed_payload) = if c.package_id == package.main_package_id
                        || (self.v2_package_name(&c.package_id) != cmd_pkg_name
                            && world_types.package_name(&c.package_id).is_ok())
                    {
                        (c.package_id.clone(), c.payload_value.clone())
                    } else {
                        let fields = package
                            .surfaces
                            .iter()
                            .filter(|m| m.name == c.template_id.module_name)
                            .flat_map(|m| m.templates.iter())
                            .find(|t| t.name == c.template_id.entity_name)
                            .map(|t| t.fields.clone())
                            .ok_or_else(|| ApiError::ContractNotActive(c.contract_id.clone()))?;
                        let translated =
                            translate_payload(&c.payload_value, &fields).map_err(|e| {
                                ApiError::Ledger(format!(
                                    "INTERPRETATION_UPGRADE_ERROR_TRANSLATION_FAILED: {e}"
                                ))
                            })?;
                        (package.main_package_id.clone(), translated)
                    };
                    Ok(EngineContract {
                        contract_id: c.contract_id.clone(),
                        package_id: seed_package,
                        template_id: format!(
                            "{}:{}",
                            c.template_id.module_name, c.template_id.entity_name
                        ),
                        payload: seed_payload,
                        signatories: c.signatories.clone(),
                        observers: c.observers.clone(),
                        active: true,
                        key: c.key_value.clone(),
                    })
                };

                // Seed all active contracts (including target if on-ledger) in `creation_seq` order so
                // Engine Tier 3 NUCK LIFO matches ledger creation order across templates/packages.
                let mut to_seed: Vec<GenericContract> = {
                    let g_lock = self
                        .generic_contracts
                        .read()
                        .map_err(|e| ApiError::Ledger(e.to_string()))?;
                    g_lock
                        .values()
                        .filter(|c| {
                            c.active
                                && (c.contract_id == existing.contract_id
                                    || c.package_id == package.main_package_id
                                    || (cmd_pkg_name.is_some()
                                        && self.v2_package_name(&c.package_id) == cmd_pkg_name))
                        })
                        .cloned()
                        .collect()
                };
                to_seed.sort_by(|a, b| {
                    a.creation_seq
                        .cmp(&b.creation_seq)
                        .then_with(|| a.contract_id.cmp(&b.contract_id))
                });

                let mut seeded_ids: HashSet<String> = HashSet::new();
                for c in &to_seed {
                    let is_target = c.contract_id == existing.contract_id;
                    let seed = match seed_for_contract(c) {
                        Ok(s) => s,
                        Err(e) if is_target => return Err(e),
                        Err(_) => continue,
                    };
                    match engine.import_contract(seed) {
                        Ok(()) => {
                            seeded_ids.insert(c.contract_id.clone());
                        }
                        Err(e) if is_target => return Err(ApiError::Ledger(e.to_string())),
                        Err(_) => {}
                    }
                }

                // Also seed explicitly disclosed contracts not already in active local state
                // (e.g., unseen foreign disclosed contracts or target foreign contract).
                for disc in &disclosed {
                    if seeded_ids.contains(&disc.contract_id) {
                        continue;
                    }
                    let is_target = disc.contract_id == existing.contract_id;
                    if !is_target
                        && disc.package_id != package.main_package_id
                        && !(cmd_pkg_name.is_some()
                            && self.v2_package_name(&disc.package_id) == cmd_pkg_name)
                        && world_types.package_name(&disc.package_id).is_err()
                    {
                        continue;
                    }
                    let seed = match seed_for_contract(disc) {
                        Ok(s) => s,
                        Err(e) if is_target => return Err(e),
                        Err(_) => continue,
                    };
                    match engine.import_contract(seed) {
                        Ok(()) => {
                            seeded_ids.insert(disc.contract_id.clone());
                        }
                        Err(e) if is_target => return Err(ApiError::Ledger(e.to_string())),
                        Err(_) => {}
                    }
                }

                let outcome = match &iface_exec {
                    Some((iface_pkg_id, iface_id)) => engine
                        .execute_exercise_interface(
                            &effective_act_as,
                            iface_pkg_id,
                            iface_id,
                            &req.contract_id,
                            &req.choice,
                            &arg_val,
                        )
                        .map_err(map_exec_error)?,
                    None => engine
                        .execute_exercise(
                            &effective_act_as,
                            &req.contract_id,
                            &req.choice,
                            &arg_val,
                        )
                        .map_err(map_exec_error)?,
                };
                self.pad_ledger_slots();

                let mut events = Vec::new();
                let mut staged_consumed_cids = Vec::new();
                let mut staged_archived_cids = Vec::new();
                let mut staged_legacy_archived_cids = Vec::new();

                if outcome.consuming {
                    events.push(JsonEvent::Archived(ArchivedContract {
                        contract_id: req.contract_id.clone(),
                        template_id: req.template_id.clone(),
                        witness_parties: existing.witness_parties.clone(),
                    }));
                    staged_consumed_cids.push(req.contract_id.clone());
                    staged_legacy_archived_cids.push(req.contract_id.clone());
                }

                for arch_id in &outcome.archived {
                    // [CANTON-NOTE: SEMANTICS] A consuming root choice already recorded `req.contract_id` above;
                    // a nonconsuming root choice (e.g. CIP-0112 TransferInstruction_Accept) may execute a child
                    // `Archive` on `req.contract_id`, which must still be staged in `events` and `staged_archived_cids`.
                    if !outcome.consuming || arch_id != &req.contract_id {
                        let (arch_tmpl, arch_witness) = {
                            let g_lock = self
                                .generic_contracts
                                .read()
                                .map_err(|e| ApiError::Ledger(e.to_string()))?;
                            g_lock
                                .get(arch_id)
                                .cloned()
                                .or_else(|| disclosed_contract_by_id(arch_id))
                                .map(|c| (c.template_id, c.witness_parties))
                                .unwrap_or((req.template_id.clone(), Vec::new()))
                        };
                        events.push(JsonEvent::Archived(ArchivedContract {
                            contract_id: arch_id.clone(),
                            template_id: arch_tmpl,
                            witness_parties: arch_witness,
                        }));
                        staged_archived_cids.push(arch_id.clone());
                        staged_legacy_archived_cids.push(arch_id.clone());
                    }
                }

                let mut staged_created_contracts = Vec::new();
                let mut created_contracts_with_json = Vec::new();
                for created in &outcome.created {
                    // [CANTON-NOTE: SEMANTICS] Transient contracts created and consumed in the
                    // same exercise (`!created.active`) remain in `staged_created_contracts`
                    // with `active: false` so protocol commit views and ID allocation stay 1:1
                    // with engine events while ACS queries and V1 flat events skip them.
                    let tmpl_schema = self.schema_for_created_template(
                        &package,
                        &created.package_id,
                        &created.template_id,
                    )?;
                    let c_json = tmpl_schema.to_json(&created.payload).map_err(|e| {
                        ApiError::Ledger(format!("failed to serialize created payload: {e}"))
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
                    let meta = allocated_meta
                        .lock()
                        .ok()
                        .and_then(|mut m| m.remove(&created.contract_id));
                    let contract_key_hash = meta.as_ref().map_or_else(
                        || {
                            compute_key_hash_b64(
                                &package.world,
                                &created.package_id,
                                &created.template_id,
                                created.key.as_ref(),
                            )
                        },
                        |m| m.contract_key_hash.clone(),
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
                        created_at_micros: meta
                            .as_ref()
                            .map_or(created_at_micros, |m| m.created_at_micros),
                        created_event_blob: meta
                            .as_ref()
                            .map_or_else(String::new, |m| m.created_event_blob.clone()),
                        contract_key_hash,
                        key_maintainers: meta.map_or_else(Vec::new, |m| m.key_maintainers),
                        creation_seq: self.next_creation_seq(),
                    };
                    staged_created_contracts.push(g_created.clone());
                    created_contracts_with_json.push((g_created, c_json));
                }

                for (gc, c_json) in &created_contracts_with_json {
                    if !gc.active {
                        continue;
                    }
                    events.push(JsonEvent::Created(CreatedContract {
                        contract_id: gc.contract_id.clone(),
                        template_id: gc.template_id.clone(),
                        payload: c_json.clone(),
                        signatories: gc.signatories.clone(),
                        observers: gc.observers.clone(),
                        witness_parties: gc.witness_parties.clone(),
                    }));
                }

                let offset = self.next_offset();

                let root_actors = root_exercise_actors(&outcome, &effective_act_as);
                let lf_tree = build_lf_tree_from_outcome(
                    &outcome,
                    &engine,
                    &req.contract_id,
                    &req.choice,
                    &root_actors,
                    &created_contracts_with_json,
                );
                let act_as_set: HashSet<String> = effective_act_as.iter().cloned().collect();

                let event_id = self.next_event_id();
                let mut child_event_ids = Vec::new();
                let mut events_by_id = HashMap::new();
                for (gc, c_json) in &created_contracts_with_json {
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

                let outcome_result = outcome.result.clone();
                let result_val = match &outcome.result {
                    lf_eval::Value::ContractId(cid) => Some(serde_json::Value::String(cid.clone())),
                    _ => None,
                };

                events_by_id.insert(
                    event_id.clone(),
                    TreeEvent::Exercised(ExercisedEvent {
                        event_id: event_id.clone(),
                        contract_id: req.contract_id.clone(),
                        template_id: req.template_id,
                        choice: req.choice,
                        choice_argument: req.argument,
                        acting_parties: root_actors,
                        consuming: outcome.consuming,
                        witness_parties: existing.witness_parties,
                        child_event_ids,
                        exercise_result: result_val.clone(),
                    }),
                );

                let tx_tree = TransactionTree {
                    update_id: format!("tx-{offset}"),
                    command_id: format!("json-exercise-{}", req.contract_id),
                    workflow_id: String::new(),
                    effective_at: 1_700_000_000,
                    offset,
                    events_by_id,
                    root_event_ids: vec![event_id],
                };

                // [CANTON-NOTE: INVARIANT] Single unified commit path for json_exercise.
                // Guarantees atomic verification and ActiveLedgerState synchronization.
                self.commit_transaction(TransactionCommit {
                    consumed_cids: staged_consumed_cids,
                    archived_cids: staged_archived_cids,
                    created_contracts: staged_created_contracts,
                    legacy_archived_cids: staged_legacy_archived_cids,
                    working_ledger: None,
                    lf_tree,
                    act_as_set,
                    tx_tree_record: Some(tx_tree),
                    root_argument: Some(arg_val.clone()),
                    engine_events: outcome.events.clone(),
                    engine_rolled_back: outcome.rolled_back.clone(),
                    engine_key_lookups: engine.recorded_key_lookups().to_vec(),
                    root_by_key: current_exercise_by_key(),
                    root_package_id: iface_exec
                        .is_none()
                        .then(|| package.main_package_id.clone()),
                    disclosed_contracts: decoded_disclosed_blobs(),
                    history: {
                        let mut history = crate::history::HistoryInput::new(Arc::clone(&package));
                        history.remember(&outcome.events, |id| engine.contract(id).cloned());
                        Some(history)
                    },
                })?;

                let remapped = super::take_last_commit_remapped_cids();
                let mut result_val = result_val;
                let mut events = events;
                let mut outcome_result = outcome_result;
                if !remapped.is_empty() {
                    super::commit::rewrite_exercise_result_cids(
                        &mut result_val,
                        &mut events,
                        &mut outcome_result,
                        &remapped,
                    );
                }

                Ok(JsonApiResponse::ok(ExerciseResult {
                    exercise_result: result_val,
                    events,
                    result_value: Some(crate::models::json_api::ValueBox(outcome_result)),
                }))
            }
            TemplateResolution::LegacyAssetHolding => {
                // [CANTON-NOTE: LIMITATION] Unloaded DAR fallback: when no DAR is loaded, requests fall back
                // to SingleContractLedger string matching strictly for backward compatibility with unloaded fixture suites.
                // This arm is strictly unreachable when any DAR package has been loaded.
                let cid = Self::parse_contract_id(&req.contract_id)?;

                let act_as_refs: Vec<&str> = effective_act_as.iter().map(|s| s.as_str()).collect();
                let mut working_ledger = self
                    .ledger
                    .read()
                    .map_err(|e| ApiError::Ledger(e.to_string()))?
                    .clone();

                let holding = working_ledger
                    .fetch(cid)
                    .map_err(ApiError::ContractNotActive)?;

                let mut events = vec![JsonEvent::Archived(ArchivedContract {
                    contract_id: req.contract_id.clone(),
                    template_id: req.template_id.clone(),
                    witness_parties: vec![
                        holding.bank.clone(),
                        holding.owner.clone(),
                        holding.auditor.clone(),
                    ],
                })];

                let mut created_holdings = Vec::new();

                match req.choice.as_str() {
                    "Transfer" => {
                        if !effective_act_as.contains(&holding.owner) {
                            return Err(ApiError::Unauthorized(format!(
                                "Transfer choice requires controller {}, but only {} were given",
                                holding.owner,
                                effective_act_as.join(",")
                            )));
                        }
                        let new_owner = req
                            .argument
                            .get("newOwner")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                ApiError::InvalidArgument("missing 'newOwner' argument".into())
                            })?;

                        if new_owner == holding.owner {
                            return Err(ApiError::InvalidArgument(
                                "New owner cannot be the same as current owner".into(),
                            ));
                        }

                        let new_cid = working_ledger
                            .exercise_transfer(cid, &act_as_refs, new_owner)
                            .map_err(ApiError::Ledger)?;

                        let created_holding =
                            working_ledger.fetch(new_cid).map_err(ApiError::Ledger)?;
                        created_holdings
                            .push((Self::format_contract_id(new_cid), created_holding.clone()));

                        events.push(JsonEvent::Created(CreatedContract {
                            contract_id: Self::format_contract_id(new_cid),
                            template_id: req.template_id.clone(),
                            payload: Self::holding_to_value(&created_holding),
                            signatories: vec![
                                created_holding.bank.clone(),
                                created_holding.owner.clone(),
                            ],
                            observers: vec![created_holding.auditor.clone()],
                            witness_parties: vec![
                                created_holding.bank,
                                created_holding.owner,
                                created_holding.auditor,
                            ],
                        }));
                    }
                    "SplitTransfer" => {
                        if !effective_act_as.contains(&holding.owner) {
                            return Err(ApiError::Unauthorized(format!(
                        "SplitTransfer choice requires controller {}, but only {} were given",
                        holding.owner,
                        effective_act_as.join(",")
                    )));
                        }
                        let recipient = req
                            .argument
                            .get("recipient")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                ApiError::InvalidArgument("missing 'recipient' argument".into())
                            })?;
                        let transfer_val = req.argument.get("transferAmount").ok_or_else(|| {
                            ApiError::InvalidArgument("missing 'transferAmount' argument".into())
                        })?;
                        let transfer_tenths = Self::parse_tenths(transfer_val)?;

                        let (moved_cid, left_cid) = working_ledger
                            .exercise_split(cid, &act_as_refs, transfer_tenths, recipient)
                            .map_err(ApiError::Ledger)?;

                        for child_cid in [moved_cid, left_cid] {
                            let child_holding =
                                working_ledger.fetch(child_cid).map_err(ApiError::Ledger)?;
                            created_holdings
                                .push((Self::format_contract_id(child_cid), child_holding.clone()));
                            events.push(JsonEvent::Created(CreatedContract {
                                contract_id: Self::format_contract_id(child_cid),
                                template_id: req.template_id.clone(),
                                payload: Self::holding_to_value(&child_holding),
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
                            }));
                        }
                    }
                    "Settle" => {
                        if !effective_act_as.contains(&holding.bank) {
                            return Err(ApiError::Unauthorized(format!(
                                "Settle choice requires controller {}, but only {} were given",
                                holding.bank,
                                effective_act_as.join(",")
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

                let offset = self.next_offset();

                // Sync exercise and child effects to lf-eval ActiveLedgerState and LedgerJournal
                let mut lf_tree = LfTransactionTree::new();
                let mut child_node_ids = Vec::new();
                for (child_cid, child_holding) in &created_holdings {
                    let mut sigs = HashSet::new();
                    sigs.insert(child_holding.bank.clone());
                    sigs.insert(child_holding.owner.clone());
                    let mut obs = HashSet::new();
                    obs.insert(child_holding.auditor.clone());
                    let nid = lf_tree.insert_node(
                        Node::Create {
                            contract_id: ContractId(child_cid.clone()),
                            template_id: req.template_id.to_string(),
                            payload: serde_json::to_vec(&Self::holding_to_value(child_holding))
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
                acting.extend(effective_act_as.clone());
                lf_tree.insert_node(
                    Node::Exercise {
                        contract_id: ContractId(req.contract_id.clone()),
                        choice: req.choice.clone(),
                        acting_parties: acting,
                        consuming: true,
                        children: child_node_ids,
                    },
                    true,
                );
                let act_as_set: HashSet<String> = effective_act_as.iter().cloned().collect();

                let event_id = self.next_event_id();
                let mut child_event_ids = Vec::new();
                let mut events_by_id = HashMap::new();
                for (child_cid, child_holding) in &created_holdings {
                    let child_id = self.next_event_id();
                    child_event_ids.push(child_id.clone());
                    events_by_id.insert(
                        child_id.clone(),
                        TreeEvent::Created(CreatedEvent {
                            event_id: child_id,
                            contract_id: child_cid.clone(),
                            template_id: req.template_id.clone(),
                            create_arguments: Self::holding_to_value(child_holding),
                            signatories: vec![
                                child_holding.bank.clone(),
                                child_holding.owner.clone(),
                            ],
                            observers: vec![child_holding.auditor.clone()],
                            witness_parties: vec![
                                child_holding.bank.clone(),
                                child_holding.owner.clone(),
                                child_holding.auditor.clone(),
                            ],
                        }),
                    );
                }

                events_by_id.insert(
                    event_id.clone(),
                    TreeEvent::Exercised(ExercisedEvent {
                        event_id: event_id.clone(),
                        contract_id: req.contract_id.clone(),
                        template_id: req.template_id,
                        choice: req.choice,
                        choice_argument: req.argument,
                        acting_parties: effective_act_as,
                        consuming: true,
                        witness_parties: vec![holding.bank, holding.owner, holding.auditor],
                        child_event_ids,
                        exercise_result: None,
                    }),
                );

                let tx_tree = TransactionTree {
                    update_id: format!("tx-{offset}"),
                    command_id: format!("json-exercise-{}", req.contract_id),
                    workflow_id: String::new(),
                    effective_at: 1_700_000_000,
                    offset,
                    events_by_id,
                    root_event_ids: vec![event_id],
                };

                // [CANTON-NOTE: INVARIANT] Single unified commit path for json_exercise.
                // Guarantees atomic verification and ActiveLedgerState synchronization.
                self.commit_transaction(TransactionCommit {
                    consumed_cids: vec![req.contract_id.clone()],
                    archived_cids: vec![],
                    created_contracts: vec![],
                    legacy_archived_cids: vec![],
                    working_ledger: Some(working_ledger),
                    lf_tree,
                    act_as_set,
                    tx_tree_record: Some(tx_tree),
                    root_argument: None,
                    engine_events: Vec::new(),
                    engine_rolled_back: Vec::new(),
                    engine_key_lookups: Vec::new(),
                    root_by_key: false,
                    root_package_id: None,
                    disclosed_contracts: Vec::new(),
                    history: None,
                })?;

                Ok(JsonApiResponse::ok(ExerciseResult {
                    exercise_result: None,
                    events,
                    result_value: None,
                }))
            }
        }
    }

    /// JSON API GET/POST /v1/contracts implementation.
    ///
    /// Aggregates active contracts from both `generic_contracts` (populated by `Engine`)
    /// and `SingleContractLedger`, respecting party visibility (`read_as`) and template query filters.
    pub fn json_contracts(
        &self,
        read_as: &[String],
        query: Option<QueryContractsRequest>,
    ) -> Result<JsonApiResponse<Vec<ContractView>>, ApiError> {
        let mut results = Vec::new();

        // 1. Query generic contracts
        if let Ok(g_lock) = self.generic_contracts.read() {
            for contract in g_lock.values() {
                if !contract.active {
                    continue;
                }
                let is_vis = if read_as.is_empty() {
                    true
                } else {
                    read_as.iter().any(|p| contract.witness_parties.contains(p))
                };
                if !is_vis {
                    continue;
                }

                if let Some(q) = &query {
                    if let Some(templates) = &q.template_ids {
                        if !templates.is_empty() {
                            let matches = templates.iter().any(|t| {
                                (t.package_id.is_empty()
                                    || t.package_id == contract.template_id.package_id)
                                    && (t.module_name.is_empty()
                                        || t.module_name == contract.template_id.module_name)
                                    && t.entity_name == contract.template_id.entity_name
                            });
                            if !matches {
                                continue;
                            }
                        }
                    }
                }

                results.push(ContractView {
                    contract_id: contract.contract_id.clone(),
                    template_id: contract.template_id.clone(),
                    key: None,
                    payload: contract.json_payload.clone(),
                    signatories: contract.signatories.clone(),
                    observers: contract.observers.clone(),
                });
            }
        }

        // [CANTON-NOTE: INVARIANT] If any DAR is loaded, generic_contracts is the sole source of truth for active contracts.
        // [CANTON-NOTE: SEMANTICS] When packages are loaded, ACS queries must not resurrect contracts archived in generic mode.
        // [CANTON-NOTE: WHY] Legacy SingleContractLedger holds un-promoted fixtures only in unloaded mode.
        // [CANTON-NOTE: LIMITATION] Unloaded mode falls back to SingleContractLedger only for contracts not tracked in generic_contracts.
        let dar_loaded = self
            .lf_packages
            .read()
            .map(|pkgs| !pkgs.is_empty())
            .unwrap_or(false);

        if !dar_loaded {
            // 2. Query legacy SingleContractLedger
            let ledger = self
                .ledger
                .read()
                .map_err(|e| ApiError::Ledger(e.to_string()))?;

            let all_active = ledger.active_contracts(None);
            let g_lock = self.generic_contracts.read().ok();

            for (cid, holding) in all_active {
                let cid_str = Self::format_contract_id(cid);
                // If generic_contracts has ever tracked this contract (whether active or inactive/consumed),
                // DO NOT add it from SingleContractLedger.
                if let Some(ref gl) = g_lock {
                    if gl.contains_key(&cid_str) {
                        continue;
                    }
                }
                if results.iter().any(|c| c.contract_id == cid_str) {
                    continue;
                }

                // Check party visibility
                let is_vis = if read_as.is_empty() {
                    true
                } else {
                    read_as.iter().any(|p| visible(&holding, p.as_str()))
                };

                if !is_vis {
                    continue;
                }

                // Check template filter if provided
                if let Some(q) = &query {
                    if let Some(templates) = &q.template_ids {
                        if !templates.is_empty()
                            && !templates.iter().any(|t| t.entity_name == "AssetHolding")
                        {
                            continue;
                        }
                    }
                }

                results.push(ContractView {
                    contract_id: cid_str,
                    template_id: TemplateId::asset_holding(),
                    key: None,
                    payload: Self::holding_to_value(&holding),
                    signatories: vec![holding.bank, holding.owner],
                    observers: vec![holding.auditor],
                });
            }
        }

        Ok(JsonApiResponse::ok(results))
    }
}

fn lf_event_depth(ev: &lf_eval::EngineEvent) -> usize {
    match ev {
        lf_eval::EngineEvent::Create { depth, .. }
        | lf_eval::EngineEvent::Exercise { depth, .. }
        | lf_eval::EngineEvent::Fetch { depth, .. } => *depth,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn walk_lf_events(
    events: &[lf_eval::EngineEvent],
    idx: &mut usize,
    min_depth: usize,
    is_root_level: bool,
    outcome: &lf_eval::ChoiceOutcome,
    engine: &lf_eval::Engine<'_>,
    req_contract_id: &str,
    req_choice: &str,
    root_actors: &[String],
    created_contracts_with_json: &[(GenericContract, serde_json::Value)],
    lf_tree: &mut LfTransactionTree,
) -> Vec<lf_eval::tx_model::NodeId> {
    let mut node_ids = Vec::new();
    while *idx < events.len() && lf_event_depth(&events[*idx]) >= min_depth {
        match &events[*idx] {
            lf_eval::EngineEvent::Create {
                contract_id,
                template_id,
                ..
            } => {
                *idx += 1;
                let (tmpl_str, payload, sigs, obs) = created_contracts_with_json
                    .iter()
                    .find(|(gc, _)| gc.contract_id == *contract_id)
                    .map(|(gc, c_json)| {
                        (
                            gc.template_id.to_string(),
                            serde_json::to_vec(c_json).unwrap_or_default(),
                            gc.signatories.iter().cloned().collect::<HashSet<String>>(),
                            gc.observers.iter().cloned().collect::<HashSet<String>>(),
                        )
                    })
                    .or_else(|| {
                        outcome
                            .created
                            .iter()
                            .find(|c| c.contract_id == *contract_id)
                            .or_else(|| engine.contract(contract_id))
                            .map(|c| {
                                (
                                    format!("{}:{}", c.package_id, c.template_id),
                                    Vec::new(),
                                    c.signatories.iter().cloned().collect(),
                                    c.observers.iter().cloned().collect(),
                                )
                            })
                    })
                    .unwrap_or_else(|| {
                        (
                            template_id.clone(),
                            Vec::new(),
                            HashSet::new(),
                            HashSet::new(),
                        )
                    });
                let nid = lf_tree.insert_node(
                    Node::Create {
                        contract_id: ContractId(contract_id.clone()),
                        template_id: tmpl_str,
                        payload,
                        signatories: sigs,
                        observers: obs,
                        key: None,
                    },
                    false,
                );
                node_ids.push(nid);
            }
            lf_eval::EngineEvent::Exercise {
                contract_id,
                choice,
                consuming,
                actors,
                depth,
                ..
            } => {
                let is_root = is_root_level && *depth == 0;
                let cur_depth = *depth;
                *idx += 1;
                let children = walk_lf_events(
                    events,
                    idx,
                    cur_depth + 1,
                    false,
                    outcome,
                    engine,
                    req_contract_id,
                    req_choice,
                    root_actors,
                    created_contracts_with_json,
                    lf_tree,
                );
                let acting: HashSet<String> = if is_root {
                    root_actors.iter().cloned().collect()
                } else {
                    actors.iter().cloned().collect()
                };
                let (ex_cid, ex_choice, ex_consuming) = if is_root {
                    (
                        req_contract_id.to_string(),
                        req_choice.to_string(),
                        outcome.consuming,
                    )
                } else {
                    (contract_id.clone(), choice.clone(), *consuming)
                };
                let nid = lf_tree.insert_node(
                    Node::Exercise {
                        contract_id: ContractId(ex_cid),
                        choice: ex_choice,
                        acting_parties: acting,
                        consuming: ex_consuming,
                        children,
                    },
                    is_root,
                );
                node_ids.push(nid);
            }
            lf_eval::EngineEvent::Fetch { .. } => {
                *idx += 1;
            }
        }
    }
    node_ids
}

fn build_lf_tree_from_outcome(
    outcome: &lf_eval::ChoiceOutcome,
    engine: &lf_eval::Engine<'_>,
    req_contract_id: &str,
    req_choice: &str,
    root_actors: &[String],
    created_contracts_with_json: &[(GenericContract, serde_json::Value)],
) -> LfTransactionTree {
    let mut lf_tree = LfTransactionTree::new();
    if outcome.events.is_empty() {
        let mut child_node_ids = Vec::new();
        for (gc, c_json) in created_contracts_with_json {
            let nid = lf_tree.insert_node(
                Node::Create {
                    contract_id: ContractId(gc.contract_id.clone()),
                    template_id: gc.template_id.to_string(),
                    payload: serde_json::to_vec(c_json).unwrap_or_default(),
                    signatories: gc.signatories.iter().cloned().collect(),
                    observers: gc.observers.iter().cloned().collect(),
                    key: None,
                },
                false,
            );
            child_node_ids.push(nid);
        }
        lf_tree.insert_node(
            Node::Exercise {
                contract_id: ContractId(req_contract_id.to_string()),
                choice: req_choice.to_string(),
                acting_parties: root_actors.iter().cloned().collect(),
                consuming: outcome.consuming,
                children: child_node_ids,
            },
            true,
        );
        return lf_tree;
    }

    let mut idx = 0;
    walk_lf_events(
        &outcome.events,
        &mut idx,
        0,
        true,
        outcome,
        engine,
        req_contract_id,
        req_choice,
        root_actors,
        created_contracts_with_json,
        &mut lf_tree,
    );
    lf_tree
}
