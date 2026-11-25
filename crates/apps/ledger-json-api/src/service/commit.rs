//! Contract ID allocation, two-phase transaction commits, remote application, and holding codecs.

use super::context::{
    clear_protocol_remapped_cids, current_disclosed_contracts, disclosed_contract_by_id,
    is_v2_command_mode, is_v2_prepare_dry_run, prepare_v12_material, set_last_commit_remapped_cids,
    take_protocol_remapped_cids, AllocatedContractMeta, DRY_RUN_COMMITS, ENGINE_CAPTURE,
};
use super::{
    compute_contract_hash, compute_key_hash, compute_unicum, encode_base64, encode_fat_contract,
    enter_v2_command, format_v12_contract_id, ApiError, Arc, ContractId, CreatedEvent, Digest,
    ExecutionService, ExercisedEvent, FatContractInput, GenericContract, HashMap, HashSet, Holding,
    LedgerUndo, LfPackage, LfTransactionTree, Mutex, NewContract, Node, Ordering, PayloadSchema,
    RemoteApplied, RemoteCreated, RemoteTxEvent, TemplateId, TransactionCommit, TransactionTree,
    TreeEvent, TxError,
};

impl ExecutionService {
    /// Notifies the backing protocol committer (when attached) to vet a dynamically uploaded DAR.
    pub fn vet_dar(&self, dar_bytes: &[u8]) -> Result<(), ApiError> {
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        match committer {
            Some(c) => c.vet_dar(dar_bytes),
            None => Ok(()),
        }
    }

    /// Notifies the backing protocol committer (when attached) to vet a pre-parsed DAR.
    pub fn vet_loaded_dar(&self, loaded: &lf_archive::LoadedDar) -> Result<(), ApiError> {
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        match committer {
            Some(c) => c.vet_loaded_dar(loaded),
            None => Ok(()),
        }
    }

    /// Returns the raw `Versioned(FatContractInstance)` bytes of a contract known to the backing protocol committer, if any.
    pub fn v2_instance_bytes(&self, contract_id: &str) -> Option<Vec<u8>> {
        let committer = self.committer.read().ok()?.clone()?;
        committer.instance_bytes(contract_id)
    }

    /// The allocator of the ids of the contracts an engine creates: the synchronizer's when there is one and it chooses, else the numbering.
    pub(super) fn contract_id_allocator(&self) -> impl FnMut(&NewContract<'_>) -> String + 'static {
        let counter = Arc::clone(&self.contract_counter);
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        let mut session: Option<u64> = None;
        move |new: &NewContract<'_>| {
            if let Some(id) = committer
                .as_ref()
                .and_then(|c| super::batch::allocate(c.as_ref(), new, &mut session))
            {
                return id;
            }
            let next = counter.fetch_add(1, Ordering::SeqCst);
            Self::format_contract_id(next as usize)
        }
    }

    /// Allocator used by `json_create` / `json_exercise`: emits deterministic Canton V12 contract IDs
    /// and pre-computes canonical `Versioned(FatContractInstance)` blobs + `contractKeyHash` when
    /// running inside `V2_COMMAND_MODE` without an external protocol committer overriding IDs.
    pub(super) fn v2_contract_id_allocator(
        &self,
        package: &Arc<LfPackage>,
        created_at_micros: i64,
        meta_out: Arc<Mutex<HashMap<String, AllocatedContractMeta>>>,
    ) -> impl FnMut(&NewContract<'_>) -> String + 'static {
        let counter = Arc::clone(&self.contract_counter);
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        let recorder = self.recorder.read().ok().and_then(|r| r.clone());
        let pkg = Arc::clone(package);
        let v2_mode = is_v2_command_mode();
        let mut session: Option<u64> = None;
        move |new: &NewContract<'_>| {
            let record_with_salt = |cid: &str, salt: &[u8; 32]| {
                let types = lf_eval::typed_json::Types::new(&pkg.world);
                let Ok(pkg_name) = types.package_name(new.package_id) else {
                    return;
                };
                let (key_val, key_maintainers, key_hash) = match new.key {
                    Some((kv, km)) => {
                        let Ok(Some(key_ty)) =
                            types.template_key_type(new.package_id, new.template_id)
                        else {
                            return;
                        };
                        let Ok(kh) =
                            compute_key_hash(&types, &pkg_name, new.template_id, &key_ty, kv)
                        else {
                            return;
                        };
                        (Some(kv), km.to_vec(), Some(kh))
                    }
                    None => (None, Vec::new(), None),
                };
                let non_sig_obs: Vec<String> = new
                    .observers
                    .iter()
                    .filter(|o| !new.signatories.contains(o))
                    .cloned()
                    .collect();
                let (module_name, entity_name) = new
                    .template_id
                    .split_once(':')
                    .unwrap_or(("", new.template_id));
                let blob_b64 = if cid.len() == 138 {
                    encode_fat_contract(
                        &pkg.world,
                        &FatContractInput {
                            contract_id: cid,
                            package_id: new.package_id,
                            package_name: &pkg_name,
                            module_name,
                            entity_name,
                            payload: new.payload,
                            signatories: new.signatories,
                            observers: &non_sig_obs,
                            created_at_micros,
                            salt,
                            key: key_val,
                            key_maintainers: &key_maintainers,
                            key_hash: key_hash.as_ref(),
                        },
                    )
                    .map(|b| encode_base64(&b))
                    .unwrap_or_default()
                } else {
                    String::new()
                };
                let meta = AllocatedContractMeta {
                    created_event_blob: blob_b64,
                    contract_key_hash: key_hash.map(|kh| encode_base64(&kh)).unwrap_or_default(),
                    key_maintainers,
                    created_at_micros,
                };
                if let Ok(mut guard) = meta_out.lock() {
                    guard.insert(cid.to_string(), meta);
                }
            };

            // [CANTON-NOTE: SEMANTICS] a protocol node chooses the ids, also for a prepare: the request it will send for an interactive
            // submission is the one its prepared transaction is read from (U-56), so the ids are the protocol's, not the prepare's own
            if let Some(id) = committer
                .as_ref()
                .and_then(|c| super::batch::allocate(c.as_ref(), new, &mut session))
            {
                record_with_salt(&id, &[0u8; 32]);
                return id;
            }
            let (next, salt, disc) = if let Some((prep_salt, prep_disc)) = prepare_v12_material() {
                (0u64, prep_salt, prep_disc)
            } else {
                let next = counter.fetch_add(1, Ordering::SeqCst);
                if !v2_mode {
                    return Self::format_contract_id(next as usize);
                }

                let salt: [u8; 32] =
                    sha2::Sha256::digest(format!("canton-rs:v12-salt:{next}").as_bytes()).into();
                let disc: [u8; 32] =
                    sha2::Sha256::digest(format!("canton-rs:v12-disc:{next}").as_bytes()).into();
                (next, salt, disc)
            };

            let build_v12 = || -> Option<(String, AllocatedContractMeta)> {
                let types = lf_eval::typed_json::Types::new(&pkg.world);
                let pkg_name = types.package_name(new.package_id).ok()?;
                let tpl_ty = types.template(new.package_id, new.template_id).ok()?;
                let contract_hash =
                    compute_contract_hash(&types, &pkg_name, new.template_id, &tpl_ty, new.payload)
                        .ok()?;
                let (key_val, key_maintainers, key_hash) = match new.key {
                    Some((kv, km)) => {
                        let key_ty = types
                            .template_key_type(new.package_id, new.template_id)
                            .ok()??;
                        let kh = compute_key_hash(&types, &pkg_name, new.template_id, &key_ty, kv)
                            .ok()?;
                        (Some(kv), km.to_vec(), Some(kh))
                    }
                    None => (None, Vec::new(), None),
                };
                let non_sig_obs: Vec<String> = new
                    .observers
                    .iter()
                    .filter(|o| !new.signatories.contains(o))
                    .cloned()
                    .collect();
                let unicum = compute_unicum(
                    &salt,
                    created_at_micros,
                    new.signatories,
                    &non_sig_obs,
                    key_hash.as_ref(),
                    &key_maintainers,
                    &contract_hash,
                );
                let cid = format_v12_contract_id(&disc, &unicum);
                let (module_name, entity_name) = new
                    .template_id
                    .split_once(':')
                    .unwrap_or(("", new.template_id));
                let blob_bytes = encode_fat_contract(
                    &pkg.world,
                    &FatContractInput {
                        contract_id: &cid,
                        package_id: new.package_id,
                        package_name: &pkg_name,
                        module_name,
                        entity_name,
                        payload: new.payload,
                        signatories: new.signatories,
                        observers: &non_sig_obs,
                        created_at_micros,
                        salt: &salt,
                        key: key_val,
                        key_maintainers: &key_maintainers,
                        key_hash: key_hash.as_ref(),
                    },
                )
                .ok()?;
                let meta = AllocatedContractMeta {
                    created_event_blob: encode_base64(&blob_bytes),
                    contract_key_hash: key_hash.map(|kh| encode_base64(&kh)).unwrap_or_default(),
                    key_maintainers,
                    created_at_micros,
                };
                Some((cid, meta))
            };

            if let Some((cid, meta)) = build_v12() {
                // [CANTON-NOTE: SEMANTICS] A simulation-mode contract's salt exists nowhere but in its blob; the scan history gets it (as the
                // protocol mode writes the salt of a contract its node holds) so `canton-rs scan serve` can state the same blob (U-25).
                if let Some(recorder) = &recorder {
                    recorder.note_created_at(&cid, created_at_micros);
                    if let Err(e) = recorder.note_authentication(
                        &cid,
                        &lf_eval::fat_contract::encode_auth_data_v30(&salt),
                    ) {
                        crate::diag::diag_eprintln!(
                            "scan history: the salt of {cid} not recorded: {e}"
                        );
                    }
                }
                if let Ok(mut guard) = meta_out.lock() {
                    guard.insert(cid.clone(), meta);
                }
                cid
            } else {
                Self::format_contract_id(next as usize)
            }
        }
    }

    /// The contract a remotely created contract is in this service: its payload as JSON by the schema of its package, its witnesses and its
    /// created-event blob. `None` when no loaded package has the contract's package.
    pub(crate) fn remote_contract(
        &self,
        packages: &[Arc<LfPackage>],
        c: &RemoteCreated,
    ) -> Result<Option<GenericContract>, ApiError> {
        let Some(package) = packages
            .iter()
            .find(|p| p.main_package_id == c.package_id)
            .or_else(|| packages.iter().find(|p| p.world.has_package(&c.package_id)))
        else {
            return Ok(None);
        };
        let schema = PayloadSchema::template(package, &c.package_id, &c.template)
            .map_err(|e| ApiError::Ledger(format!("no schema for {}: {e}", c.template)))?;
        let json = schema
            .to_json(&c.payload)
            .map_err(|e| ApiError::Ledger(format!("cannot show {}: {e}", c.contract_id)))?;
        let mut witness = c.signatories.clone();
        for o in &c.observers {
            if !witness.contains(o) {
                witness.push(o.clone());
            }
        }
        let (module, entity) = c.template.split_once(':').unwrap_or(("", &c.template));
        let template_id = TemplateId {
            package_id: c.package_id.clone(),
            module_name: module.to_string(),
            entity_name: entity.to_string(),
        };
        let created_event_blob = if let Some(blob) = &c.blob {
            encode_base64(blob)
        } else if c.contract_id.len() == 138 {
            let pkg_name = self.v2_package_name(&c.package_id).unwrap_or_default();
            let non_sig_obs: Vec<String> = c
                .observers
                .iter()
                .filter(|o| !c.signatories.contains(o))
                .cloned()
                .collect();
            encode_fat_contract(
                &package.world,
                &FatContractInput {
                    contract_id: &c.contract_id,
                    package_id: &c.package_id,
                    package_name: &pkg_name,
                    module_name: module,
                    entity_name: entity,
                    payload: &c.payload,
                    signatories: &c.signatories,
                    observers: &non_sig_obs,
                    created_at_micros: c.created_at_micros,
                    salt: c.salt.as_ref().unwrap_or(&[0u8; 32]),
                    key: None,
                    key_maintainers: &[],
                    key_hash: None,
                },
            )
            .map(|b| encode_base64(&b))
            .unwrap_or_default()
        } else {
            String::new()
        };
        let contract = GenericContract {
            contract_id: c.contract_id.clone(),
            package_id: c.package_id.clone(),
            template_id,
            payload_value: c.payload.clone(),
            json_payload: json,
            signatories: c.signatories.clone(),
            observers: c.observers.clone(),
            witness_parties: witness.clone(),
            active: true,
            key_value: None,
            created_at_micros: c.created_at_micros,
            created_event_blob,
            contract_key_hash: String::new(),
            key_maintainers: Vec::new(),
            creation_seq: self.next_creation_seq(),
        };
        Ok(Some(contract))
    }

    /// Shows the parties of this participant a transaction **another participant** got approved: the contracts it created (read from the
    /// views this participant was sent) and the ones it consumed. It was judged by the synchronizer already, so it is applied without a
    /// verdict of its own.
    ///
    /// [CANTON-NOTE: LIMITATION] The views a participant is sent for a contract it is only a stakeholder of say which contracts were created and
    /// consumed; the service records the consumed ones as an `Archive` exercise of their signatories, and does not know the choice that was
    /// Shows a transaction approved on the synchronizer without this service's submission and publishes it to v2 updates & ExEx.
    pub fn apply_remote(&self, tx: RemoteApplied) -> Result<(), ApiError> {
        self.apply_remote_inner(tx, true)
    }

    /// Applies remote contracts/consumptions into ledger state without emitting a separate v2 update or ExEx notification.
    pub fn apply_remote_without_v2(&self, tx: RemoteApplied) -> Result<(), ApiError> {
        self.apply_remote_inner(tx, false)
    }

    fn apply_remote_inner(&self, tx: RemoteApplied, publish_v2: bool) -> Result<(), ApiError> {
        let packages: Vec<Arc<LfPackage>> = self
            .lf_packages
            .read()
            .map_err(|e| ApiError::Ledger(e.to_string()))?
            .clone();
        let mut created_contracts = Vec::new();
        let mut tree = LfTransactionTree::new();
        let mut events_by_id = HashMap::new();
        let mut child_node_ids = Vec::new();
        let mut child_event_ids = Vec::new();
        let mut authorizers: HashSet<String> = HashSet::new();
        for c in &tx.created {
            // [CANTON-NOTE: DEFENSIVE] P-13: a transaction handed over again after a restart shows only what is not shown yet
            if self.has_known_contract(&c.contract_id) {
                continue;
            }
            let Some(contract) = self.remote_contract(&packages, c)? else {
                continue;
            };
            let json = contract.json_payload.clone();
            let witness = contract.witness_parties.clone();
            let template_id = contract.template_id.clone();
            authorizers.extend(c.signatories.iter().cloned());
            let node_id = tree.insert_node(
                Node::Create {
                    contract_id: ContractId(c.contract_id.clone()),
                    template_id: c.template.clone(),
                    payload: serde_json::to_vec(&json).unwrap_or_default(),
                    signatories: c.signatories.iter().cloned().collect(),
                    observers: c.observers.iter().cloned().collect(),
                    key: None,
                },
                tx.consumed.is_empty(),
            );
            child_node_ids.push(node_id);
            let event_id = self.next_event_id();
            child_event_ids.push(event_id.clone());
            events_by_id.insert(
                event_id.clone(),
                TreeEvent::Created(CreatedEvent {
                    event_id,
                    contract_id: contract.contract_id.clone(),
                    template_id,
                    create_arguments: json,
                    signatories: contract.signatories.clone(),
                    observers: contract.observers.clone(),
                    witness_parties: witness,
                }),
            );
            created_contracts.push(contract);
        }
        // only the consumed contracts this service knows: a contract it never showed cannot be archived in it
        let known: Vec<GenericContract> = {
            let g = self
                .generic_contracts
                .read()
                .map_err(|e| ApiError::Ledger(e.to_string()))?;
            tx.consumed
                .iter()
                .filter_map(|id| g.get(id).filter(|c| c.active).cloned())
                .collect()
        };
        let mut root_event_ids: Vec<String> = Vec::new();
        for c in &known {
            authorizers.extend(c.signatories.iter().cloned());
            tree.insert_node(
                Node::Exercise {
                    contract_id: ContractId(c.contract_id.clone()),
                    choice: "Archive".to_string(),
                    acting_parties: c.signatories.iter().cloned().collect(),
                    consuming: true,
                    children: std::mem::take(&mut child_node_ids),
                },
                true,
            );
            let event_id = self.next_event_id();
            events_by_id.insert(
                event_id.clone(),
                TreeEvent::Exercised(ExercisedEvent {
                    event_id: event_id.clone(),
                    contract_id: c.contract_id.clone(),
                    template_id: c.template_id.clone(),
                    choice: "Archive".to_string(),
                    choice_argument: serde_json::json!({}),
                    acting_parties: c.signatories.clone(),
                    consuming: true,
                    witness_parties: c.witness_parties.clone(),
                    child_event_ids: std::mem::take(&mut child_event_ids),
                    exercise_result: None,
                }),
            );
            root_event_ids.push(event_id);
        }
        if known.is_empty() {
            root_event_ids = child_event_ids;
        }
        if created_contracts.is_empty() && known.is_empty() && tx.events.is_empty() {
            return Ok(());
        }
        // [CANTON-NOTE: SEMANTICS] R-13k: Canton Ledger API `updateId` is the transaction's
        // Merkle root hash (`1220...` hex; `Tags.scala:92-135`, `TransactionProcessingSteps.scala:1201-1216, 1272, 1316-1331`),
        // so both submitting and non-submitting participants observe the same `updateId`.
        let root_update_id = tx
            .root_hash
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(hex::encode);
        let offset = self.next_offset();
        let tx_tree = TransactionTree {
            update_id: root_update_id
                .clone()
                .unwrap_or_else(|| crate::v2_commands::update_id(offset)),
            command_id: String::new(),
            workflow_id: String::new(),
            effective_at: (crate::clock::now_secs()),
            offset,
            events_by_id,
            root_event_ids,
        };
        let history =
            if tx.request_id > 0 && self.recorder.read().ok().and_then(|r| r.clone()).is_some() {
                let target_pkg = created_contracts
                    .first()
                    .map(|c| c.package_id.as_str())
                    .or_else(|| known.first().map(|c| c.package_id.as_str()))
                    .and_then(|pid| {
                        packages
                            .iter()
                            .find(|p| p.main_package_id == pid)
                            .or_else(|| packages.iter().find(|p| p.world.has_package(pid)))
                            .cloned()
                    })
                    .or_else(|| packages.first().cloned());
                target_pkg.map(|pkg| {
                    let mut h = crate::history::HistoryInput::new(pkg);
                    h.record_time_micros = Some(tx.request_id);
                    h.effective_at_micros = Some(tx.request_id);
                    let mut child_depth = 0usize;
                    for (idx, kc) in known.iter().enumerate() {
                        let local_tmpl = format!(
                            "{}:{}",
                            kc.template_id.module_name, kc.template_id.entity_name
                        );
                        h.contracts.insert(
                            kc.contract_id.clone(),
                            lf_eval::engine::Contract {
                                contract_id: kc.contract_id.clone(),
                                package_id: kc.package_id.clone(),
                                template_id: local_tmpl,
                                payload: kc.payload_value.clone(),
                                signatories: kc.signatories.clone(),
                                observers: kc.observers.clone(),
                                active: true,
                                key: None,
                            },
                        );
                        h.events.push(lf_eval::EngineEvent::Exercise {
                            contract_id: kc.contract_id.clone(),
                            choice: "Archive".to_string(),
                            consuming: true,
                            actors: kc.signatories.clone(),
                            depth: 0,
                            argument: lf_eval::Value::Record {
                                tycon: None,
                                fields: vec![],
                            },
                            result: Some(lf_eval::Value::Unit),
                            interface_id: None,
                            observers: Vec::new(),
                        });
                        if idx == 0 {
                            child_depth = 1;
                        }
                    }
                    for cc in &created_contracts {
                        let local_tmpl = format!(
                            "{}:{}",
                            cc.template_id.module_name, cc.template_id.entity_name
                        );
                        h.contracts.insert(
                            cc.contract_id.clone(),
                            lf_eval::engine::Contract {
                                contract_id: cc.contract_id.clone(),
                                package_id: cc.package_id.clone(),
                                template_id: local_tmpl.clone(),
                                payload: cc.payload_value.clone(),
                                signatories: cc.signatories.clone(),
                                observers: cc.observers.clone(),
                                active: true,
                                key: None,
                            },
                        );
                        h.events.push(lf_eval::EngineEvent::Create {
                            contract_id: cc.contract_id.clone(),
                            template_id: local_tmpl,
                            depth: child_depth,
                        });
                    }
                    h
                })
            } else {
                None
            };
        let mut v2_events: Vec<crate::v2_commands::Ev> = Vec::new();
        if !tx.events.is_empty() {
            let mut local_contracts: std::collections::BTreeMap<String, GenericContract> =
                std::collections::BTreeMap::new();
            for c in &known {
                local_contracts.insert(c.contract_id.clone(), c.clone());
            }
            for c in &created_contracts {
                local_contracts.insert(c.contract_id.clone(), c.clone());
            }
            let mut resolve_contract = |cid: &str,
                                        hint: Option<&RemoteCreated>|
             -> Result<Option<GenericContract>, ApiError> {
                if let Some(found) = local_contracts.get(cid).cloned() {
                    return Ok(Some(found));
                }
                if let Some(found) = self.v2_contract(cid) {
                    local_contracts.insert(cid.to_string(), found.clone());
                    return Ok(Some(found));
                }
                if let Some(rc) = hint {
                    if let Some(opened) = self.remote_contract(&packages, rc)? {
                        local_contracts.insert(cid.to_string(), opened.clone());
                        return Ok(Some(opened));
                    }
                }
                Ok(None)
            };
            let mut open: Vec<(usize, usize)> = Vec::new();
            let mut node_id = 0u64;
            for rev in &tx.events {
                let depth = match rev {
                    RemoteTxEvent::Create { depth, .. } | RemoteTxEvent::Fetch { depth } => *depth,
                    RemoteTxEvent::Exercise(ex) => ex.depth,
                };
                while let Some((d, idx)) = open.last().copied() {
                    if d < depth {
                        break;
                    }
                    open.pop();
                    if let Some(x) = v2_events[idx].exercise.as_mut() {
                        x.last_descendant = node_id - 1;
                    }
                }
                let this_node = node_id;
                node_id += 1;
                match rev {
                    RemoteTxEvent::Fetch { .. } => {}
                    RemoteTxEvent::Create {
                        contract_id,
                        contract,
                        ..
                    } => {
                        if let Some(gc) = resolve_contract(contract_id, contract.as_deref())? {
                            v2_events.push(crate::v2_commands::Ev {
                                contract: gc,
                                created: true,
                                node: this_node,
                                exercise: None,
                            });
                        }
                    }
                    RemoteTxEvent::Exercise(ex) => {
                        if let Some(gc) = resolve_contract(&ex.contract_id, ex.contract.as_ref())? {
                            let (arg_json, res_json) = crate::v2_commands::encode_choice_values(
                                self,
                                &gc.template_id,
                                ex.interface_id.as_deref(),
                                &ex.choice,
                                Some(&ex.argument),
                                None,
                                ex.result.as_ref(),
                                None,
                            );
                            open.push((depth, v2_events.len()));
                            v2_events.push(crate::v2_commands::Ev {
                                contract: gc,
                                created: false,
                                node: this_node,
                                exercise: Some(crate::v2_commands::ExInfo {
                                    choice: ex.choice.clone(),
                                    argument: arg_json,
                                    argument_value: Some(ex.argument.clone()),
                                    acting: ex.actors.clone(),
                                    consuming: ex.consuming,
                                    result: res_json,
                                    result_value: ex.result.clone(),
                                    last_descendant: this_node,
                                    interface_id: ex.interface_id.clone(),
                                    choice_observers: ex.observers.clone(),
                                }),
                            });
                        }
                    }
                }
            }
            while let Some((_, idx)) = open.pop() {
                if let Some(x) = v2_events[idx].exercise.as_mut() {
                    x.last_descendant = node_id.saturating_sub(1);
                }
            }
        } else {
            let mut v2_node_id = 0u64;
            for c in &known {
                v2_events.push(crate::v2_commands::Ev {
                    contract: c.clone(),
                    created: false,
                    node: v2_node_id,
                    exercise: None,
                });
                v2_node_id += 1;
            }
            for c in &created_contracts {
                v2_events.push(crate::v2_commands::Ev {
                    contract: c.clone(),
                    created: true,
                    node: v2_node_id,
                    exercise: None,
                });
                v2_node_id += 1;
            }
        }
        let apply_res = self.apply_commit(TransactionCommit {
            consumed_cids: known.iter().map(|c| c.contract_id.clone()).collect(),
            archived_cids: vec![],
            created_contracts,
            legacy_archived_cids: vec![],
            working_ledger: None,
            lf_tree: tree,
            act_as_set: authorizers,
            tx_tree_record: Some(tx_tree),
            root_argument: None,
            engine_events: Vec::new(),
            engine_rolled_back: Vec::new(),
            engine_key_lookups: Vec::new(),
            root_by_key: false,
            root_package_id: None,
            disclosed_contracts: Vec::new(),
            history,
        });
        if apply_res.is_ok() && publish_v2 && !v2_events.is_empty() {
            let state = self.v2_state();
            let _publish_guard = state
                .commit_publish_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let offset = state.ledger_end.load(Ordering::SeqCst) + 1;
            let update = crate::v2_commands::StoredUpdate {
                update_id: root_update_id.unwrap_or_else(|| crate::v2_commands::update_id(offset)),
                offset,
                command_id: String::new(),
                effective_at: crate::v2_commands::now_rfc3339(),
                events: v2_events,
                at_micros: if tx.request_id > 0 {
                    tx.request_id
                } else {
                    crate::clock::now_micros()
                },
                external_transaction_hash: None,
                reassignment: None,
                topology: None,
                official: None,
                trace_parent: None,
                act_as: Vec::new(),
            };
            if !state.record_update(update) {
                return Err(ApiError::Ledger(format!(
                    "failed to persist remote update journal at offset {offset}"
                )));
            }
            // Publish ledger_end only after StoredUpdate is visible to concurrent stream readers.
            state.ledger_end.store(offset, Ordering::SeqCst);
        }
        apply_res
    }

    pub fn commit_transaction(&self, mut commit: TransactionCommit) -> Result<(), ApiError> {
        if is_v2_prepare_dry_run() {
            record_engine_capture(&commit);
            DRY_RUN_COMMITS.with(|c| c.borrow_mut().push(commit.clone()));
            return self.apply_commit(commit);
        }
        // [CANTON-NOTE: SEMANTICS] The synchronizer judges the transaction **before** any lock is taken: the wait for its verdict must not
        // stop every reader of the ledger. A transaction the synchronizer rejects is never applied.
        let started = std::time::Instant::now();
        let (v1_recording_id, _v1_recording_guard) = (!is_v2_command_mode())
            .then(super::enter_v1_recording)
            .map_or((String::new(), None), |(id, guard)| (id, Some(guard)));
        let committer = self.committer.read().ok().and_then(|c| c.clone());
        let mut captured_early = false;
        if let Some(committer) = committer {
            // a command of a batch is judged with the batch's other commands (`finish_protocol_batch`)
            if super::batch::keep(&commit) {
                record_engine_capture(&commit);
                captured_early = true;
            } else {
                if let Err(err) = committer.commit(&commit) {
                    super::clear_protocol_update_id();
                    clear_protocol_remapped_cids();
                    self.record_commit_xray(&commit, started.elapsed(), false);
                    if !is_v2_command_mode() && !err.is_request_time_out() {
                        committer.command_recorded_for(&v1_recording_id);
                    }
                    return Err(err);
                }
                let remapped = take_protocol_remapped_cids();
                if !remapped.is_empty() {
                    rewrite_commit_cids(&mut commit, &remapped);
                    set_last_commit_remapped_cids(remapped);
                }
            }
            for c in &mut commit.created_contracts {
                if let Some(bytes) = committer.instance_bytes(&c.contract_id) {
                    c.created_event_blob = lf_eval::fat_contract::encode_base64(&bytes);
                }
            }
        }
        if !captured_early {
            record_engine_capture(&commit);
        }
        let apply_res = self.apply_commit(commit.clone());
        if apply_res.is_err() || !is_v2_command_mode() {
            super::clear_protocol_update_id();
        }
        self.record_commit_xray(&commit, started.elapsed(), apply_res.is_ok());
        // a command of the v2 API is recorded with its completion (`finish_with_hash`); a v1 one with its transaction, here
        if !is_v2_command_mode() && apply_res.is_ok() {
            self.command_recorded_for(&v1_recording_id);
        }
        apply_res
    }

    /// See [`super::ProtocolCommitter::command_recorded_for`].
    pub(crate) fn command_recorded_for(&self, command_id: &str) {
        if let Some(committer) = self.committer.read().ok().and_then(|c| c.clone()) {
            committer.command_recorded_for(command_id);
        }
    }

    fn record_commit_xray(
        &self,
        commit: &TransactionCommit,
        elapsed: std::time::Duration,
        approved: bool,
    ) {
        if !self.observability.wiretap_active.load(Ordering::Relaxed) {
            return;
        }
        let mut cids: Vec<&str> = Vec::new();
        for c in &commit.created_contracts {
            cids.push(c.contract_id.as_str());
        }
        for id in &commit.archived_cids {
            cids.push(id.as_str());
        }
        for cid in &commit.consumed_cids {
            cids.push(cid.as_str());
        }
        let root_hash = crate::exex::participant_tx_digest("", 0, &cids);
        let (pkg_id, tmpl) = commit
            .created_contracts
            .first()
            .map(|c| {
                (
                    c.package_id.chars().take(12).collect::<String>(),
                    Some(format!(
                        "{}:{}",
                        c.template_id.module_name, c.template_id.entity_name
                    )),
                )
            })
            .unwrap_or_else(|| {
                (
                    commit
                        .root_package_id
                        .as_deref()
                        .unwrap_or("unknown")
                        .chars()
                        .take(12)
                        .collect(),
                    None,
                )
            });
        let informees: Vec<String> = commit
            .created_contracts
            .iter()
            .flat_map(|c| c.signatories.iter().chain(c.observers.iter()))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let recipient_member_count = u32::try_from(informees.len().max(1)).unwrap_or(1);
        let total_latency_ms = elapsed.as_secs_f64() * 1000.0;
        let eval_us = u64::try_from(elapsed.as_micros()).unwrap_or(0);
        let short_digest = root_hash.strip_prefix("1220").unwrap_or(&root_hash);
        let views = vec![crate::observability::XRayViewRecord {
            view_hash: format!("0x{}", short_digest.get(..8).unwrap_or(short_digest)),
            threshold: u32::try_from(informees.len().max(1)).unwrap_or(1),
            approved_parties: informees,
            latency_ms: total_latency_ms,
        }];
        let envelope_bytes = u64::try_from(
            commit
                .created_contracts
                .iter()
                .map(|c| c.created_event_blob.len())
                .sum::<usize>(),
        )
        .unwrap_or(0);
        let record = crate::observability::XRayNodeRecord {
            root_hash,
            started_at_unix_ms: crate::observability::now_unix_ms(),
            submitter_participant: self.v2_state().participant_id(),
            package_id: pkg_id,
            template_qualified_name: tmpl,
            daml_eval_us: eval_us,
            blinded_view_count: u32::try_from(views.len()).unwrap_or(1),
            sealed_envelope_bytes: envelope_bytes,
            traffic_cost_bytes: envelope_bytes,
            recipient_member_count,
            verdict: if approved {
                "approved".to_string()
            } else {
                "rejected".to_string()
            },
            total_latency_ms,
            views,
            is_participant_estimate: true,
        };
        if !super::batch::keep_xray(&record) {
            self.observability.record_xray(record);
        }
    }

    pub(crate) fn commit_prepared_transaction(
        &self,
        commits: Vec<TransactionCommit>,
        required_active_inputs: &[String],
        disclosed_inputs: Vec<GenericContract>,
        read_as: Vec<String>,
    ) -> Result<(), ApiError> {
        let _cmd_guard = enter_v2_command(disclosed_inputs, read_as);
        self.v2_atomic(|| {
            {
                let g_lock = self
                    .generic_contracts
                    .read()
                    .map_err(|e| ApiError::Ledger(e.to_string()))?;
                for cid in required_active_inputs {
                    match g_lock.get(cid) {
                        Some(c) if c.active => {}
                        Some(_) => return Err(ApiError::ContractNotActive(cid.clone())),
                        None if disclosed_contract_by_id(cid).is_some()
                            || commits.iter().any(|cm| {
                                cm.created_contracts.iter().any(|gc| &gc.contract_id == cid)
                            }) => {}
                        None => return Err(ApiError::ContractNotActive(cid.clone())),
                    }
                }
            }
            for commit in commits {
                self.commit_transaction(commit)?;
            }
            Ok(())
        })
    }

    /// Applies a transaction that was judged already (by the synchronizer, or by another participant's request that this participant confirmed).
    pub(super) fn apply_commit(&self, commit: TransactionCommit) -> Result<(), ApiError> {
        let mut g_lock = self
            .generic_contracts
            .write()
            .map_err(|e| ApiError::Ledger(e.to_string()))?;

        // 1. TOCTOU concurrency validation under write lock
        for cid in &commit.consumed_cids {
            match g_lock.get(cid) {
                Some(c) if !c.active => return Err(ApiError::ContractNotActive(cid.clone())),
                None if !commit
                    .created_contracts
                    .iter()
                    .any(|gc| &gc.contract_id == cid)
                    && disclosed_contract_by_id(cid).is_none() =>
                {
                    let dar_loaded = self
                        .lf_packages
                        .read()
                        .map(|pkgs| !pkgs.is_empty())
                        .unwrap_or(false);
                    if dar_loaded {
                        return Err(ApiError::ContractNotActive(cid.clone()));
                    }
                }
                _ => {}
            }
        }
        for cid in &commit.archived_cids {
            if let Some(c) = g_lock.get(cid) {
                if !c.active {
                    return Err(ApiError::ContractNotActive(cid.clone()));
                }
            }
        }

        // [CANTON-NOTE: DEFENSIVE] Validate that no newly created contract ID is already active in generic_contracts.
        for gc in &commit.created_contracts {
            if let Some(existing) = g_lock.get(&gc.contract_id) {
                if existing.active {
                    return Err(ApiError::Ledger(format!(
                        "contract id {} already active",
                        gc.contract_id
                    )));
                }
            }
        }

        // 2. Validate and apply to ActiveLedgerState FIRST
        // Transiently seed unseen foreign disclosed contracts so ActiveLedgerState can verify
        // exercises against them, then unconditionally remove any untouched foreign entries so
        // non-consuming exercises never leak into local ACS.
        {
            let mut state = self
                .active_state
                .write()
                .map_err(|e| ApiError::Ledger(e.to_string()))?;
            let disclosed = current_disclosed_contracts();
            let mut transient_foreign: Vec<ContractId> = Vec::new();
            for disc in &disclosed {
                let cid = ContractId(disc.contract_id.clone());
                if !state.active_contracts.contains_key(&cid) {
                    let stakeholders: HashSet<String> = disc
                        .signatories
                        .iter()
                        .chain(&disc.observers)
                        .cloned()
                        .collect();
                    state.active_contracts.insert(
                        cid.clone(),
                        lf_eval::tx_model::ActiveContract {
                            template_id: disc.template_id.to_string(),
                            payload: Vec::new(),
                            stakeholders,
                            key: None,
                        },
                    );
                    transient_foreign.push(cid);
                }
            }
            let apply_res = state.apply_transaction(&commit.lf_tree, &commit.act_as_set);
            for cid in &transient_foreign {
                state.active_contracts.remove(cid);
            }
            apply_res.map_err(|e| match e {
                TxError::ContractAlreadyConsumed(cid) => ApiError::ContractNotActive(cid.0),
                TxError::ContractNotFound(cid) => ApiError::ContractNotActive(cid.0),
                other => ApiError::Ledger(other.to_string()),
            })?;
        }

        // 3. Only after apply_transaction succeeds, mutate generic_contracts
        let transient_cids: Vec<String> = commit
            .created_contracts
            .iter()
            .filter(|gc| !gc.active)
            .map(|gc| gc.contract_id.clone())
            .collect();
        for gc in commit.created_contracts {
            let old = g_lock.insert(gc.contract_id.clone(), gc.clone());
            self.note_contract(&gc.contract_id, old);
        }
        let completed = self.tick();
        if let Ok(mut m) = self.consumed_at.write() {
            for cid in commit
                .consumed_cids
                .iter()
                .chain(&commit.archived_cids)
                .chain(&transient_cids)
            {
                m.insert(cid.clone(), completed);
            }
        }
        for cid in commit.consumed_cids.iter().chain(&commit.archived_cids) {
            if let Some(c) = g_lock.get_mut(cid) {
                let before = c.clone();
                c.active = false;
                self.note_contract(cid, Some(before));
            } else if let Some(mut foreign) = disclosed_contract_by_id(cid) {
                foreign.active = false;
                g_lock.insert(cid.clone(), foreign);
                self.note_contract(cid, None);
            }
        }

        // 4. Update legacy SingleContractLedger
        if let Some(working_ledger) = commit.working_ledger {
            self.sync_contract_counter_from_ledger(&working_ledger);
            if let Ok(mut l) = self.ledger.write() {
                let old = std::mem::replace(&mut *l, working_ledger);
                self.note_ledger(|| LedgerUndo::Replaced(Box::new(old)));
            }
        } else {
            for cid in &commit.legacy_archived_cids {
                self.mark_ledger_contract_archived(cid);
            }
        }

        // 5. Pad ledger slots
        self.pad_ledger_slots();

        // 7. Append to LedgerJournal
        let now = crate::clock::now_secs();
        if let Ok(mut j) = self.journal.write() {
            let _ = j.append(commit.lf_tree, commit.act_as_set, (now * 1_000_000) as i64);
        }

        // 8. Record to update_stream
        if let Some(tx_tree) = commit.tx_tree_record {
            // the scan history: a failure to render or write it is reported, it never undoes the commit
            if !is_v2_prepare_dry_run() {
                let recorder = self.recorder.read().ok().and_then(|r| r.clone());
                let kept = commit.history.as_ref().is_some_and(|input| {
                    super::batch::keep_history(input, &tx_tree.update_id, &tx_tree.workflow_id)
                });
                if let (false, Some(recorder), Some(input)) = (kept, recorder, &commit.history) {
                    if let Err(e) = recorder.record(input, &tx_tree.update_id, &tx_tree.workflow_id)
                    {
                        crate::diag::diag_eprintln!(
                            "scan history: {} not recorded: {e}",
                            tx_tree.update_id
                        );
                    }
                }
            }
            if let Ok(mut stream) = self.update_stream.write() {
                stream.push(tx_tree);
            }
        }

        Ok(())
    }

    pub(super) fn next_offset(&self) -> u64 {
        self.offset_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) fn next_event_id(&self) -> String {
        let id = self.event_counter.fetch_add(1, Ordering::SeqCst);
        format!("#event-{id}")
    }

    pub fn format_contract_id(id: usize) -> String {
        format!("#{id}:0")
    }

    pub fn parse_contract_id(s: &str) -> Result<usize, ApiError> {
        let cleaned = s.trim().trim_start_matches('#');
        let id_part = cleaned.split(':').next().unwrap_or(cleaned);
        id_part
            .parse::<usize>()
            .map_err(|_| ApiError::InvalidArgument(format!("Invalid contract ID format '{s}'")))
    }

    pub fn parse_tenths(val: &serde_json::Value) -> Result<i64, ApiError> {
        match val {
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(i * 10)
                } else if let Some(f) = n.as_f64() {
                    Ok((f * 10.0).round() as i64)
                } else {
                    Err(ApiError::InvalidArgument(
                        "Invalid number format for amount".into(),
                    ))
                }
            }
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if let Ok(i) = trimmed.parse::<i64>() {
                    Ok(i * 10)
                } else if let Ok(f) = trimmed.parse::<f64>() {
                    Ok((f * 10.0).round() as i64)
                } else {
                    Err(ApiError::InvalidArgument(format!(
                        "Cannot parse amount string: '{s}'"
                    )))
                }
            }
            _ => Err(ApiError::InvalidArgument(
                "Expected string or number for amount".into(),
            )),
        }
    }

    pub fn format_amount(tenths: i64) -> String {
        let sign = if tenths < 0 { "-" } else { "" };
        let abs = tenths.abs();
        format!("{sign}{}.{}", abs / 10, abs % 10)
    }

    pub fn value_to_holding(val: &serde_json::Value) -> Result<Holding, ApiError> {
        let bank = val
            .get("bank")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'bank'".into()))?;
        let owner = val
            .get("owner")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'owner'".into()))?;
        let auditor = val
            .get("auditor")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'auditor'".into()))?;
        let symbol = val
            .get("assetSymbol")
            .or_else(|| val.get("symbol"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ApiError::InvalidArgument("missing required field 'assetSymbol'".into())
            })?;
        let amount_val = val
            .get("amount")
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'amount'".into()))?;
        let tenths = Self::parse_tenths(amount_val)?;
        Ok(Holding::new(bank, owner, auditor, symbol, tenths))
    }

    pub fn holding_to_value(holding: &Holding) -> serde_json::Value {
        serde_json::json!({
            "bank": holding.bank,
            "owner": holding.owner,
            "auditor": holding.auditor,
            "assetSymbol": holding.symbol,
            "amount": Self::format_amount(holding.tenths),
        })
    }
}

fn record_engine_capture(commit: &TransactionCommit) {
    ENGINE_CAPTURE.with(|c| {
        if let Some(captured) = c.borrow_mut().as_mut() {
            captured.events.extend(commit.engine_events.iter().cloned());
            if let Some(history) = &commit.history {
                for (cid, contract) in &history.contracts {
                    captured.contracts.insert(cid.clone(), contract.clone());
                }
            }
        }
    });
}

fn remap_id(s: &mut String, map: &std::collections::BTreeMap<String, String>) {
    if let Some(to) = map.get(s.as_str()) {
        *s = to.clone();
    }
}

fn rewrite_json_value(
    val: &mut serde_json::Value,
    map: &std::collections::BTreeMap<String, String>,
) {
    match val {
        serde_json::Value::String(s) => remap_id(s, map),
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite_json_value(item, map);
            }
        }
        serde_json::Value::Object(obj) => {
            let old = std::mem::take(obj);
            for (mut k, mut v) in old {
                remap_id(&mut k, map);
                rewrite_json_value(&mut v, map);
                obj.insert(k, v);
            }
        }
        _ => {}
    }
}

fn rewrite_lf_eval_value(
    val: &mut lf_eval::Value,
    map: &std::collections::BTreeMap<String, String>,
) {
    use lf_eval::Value as V;
    match val {
        V::ContractId(id) => remap_id(id, map),
        V::List(items) => {
            let updated: Vec<V> = items
                .iter()
                .map(|item| {
                    let mut copy = item.clone();
                    rewrite_lf_eval_value(&mut copy, map);
                    copy
                })
                .collect();
            *items = lf_eval::List::from(updated);
        }
        V::Optional(Some(inner))
        | V::Variant { value: inner, .. }
        | V::AnyException { payload: inner, .. }
        | V::Any { payload: inner, .. }
        | V::Iface { payload: inner, .. } => rewrite_lf_eval_value(inner, map),
        V::Record { fields, .. } | V::Struct(fields) => {
            for (_, v) in fields {
                rewrite_lf_eval_value(v, map);
            }
        }
        V::Map(entries) => {
            for (k, v) in entries {
                rewrite_lf_eval_value(k, map);
                rewrite_lf_eval_value(v, map);
            }
        }
        _ => {}
    }
}

fn rewrite_engine_event(
    ev: &mut lf_eval::EngineEvent,
    map: &std::collections::BTreeMap<String, String>,
) {
    match ev {
        lf_eval::EngineEvent::Create { contract_id, .. } => remap_id(contract_id, map),
        lf_eval::EngineEvent::Exercise {
            contract_id,
            argument,
            result,
            ..
        } => {
            remap_id(contract_id, map);
            rewrite_lf_eval_value(argument, map);
            if let Some(res) = result {
                rewrite_lf_eval_value(res, map);
            }
        }
        lf_eval::EngineEvent::Fetch { contract_id, .. } => remap_id(contract_id, map),
    }
}

fn rewrite_commit_cids(
    commit: &mut TransactionCommit,
    map: &std::collections::BTreeMap<String, String>,
) {
    for cid in &mut commit.consumed_cids {
        remap_id(cid, map);
    }
    for cid in &mut commit.archived_cids {
        remap_id(cid, map);
    }
    for cid in &mut commit.legacy_archived_cids {
        remap_id(cid, map);
    }
    for c in &mut commit.created_contracts {
        remap_id(&mut c.contract_id, map);
        rewrite_lf_eval_value(&mut c.payload_value, map);
        rewrite_json_value(&mut c.json_payload, map);
        if let Some(ref mut kv) = c.key_value {
            rewrite_lf_eval_value(kv, map);
        }
    }
    if let Some(ref mut root_arg) = commit.root_argument {
        rewrite_lf_eval_value(root_arg, map);
    }
    for ev in &mut commit.engine_events {
        rewrite_engine_event(ev, map);
    }
    for rb in &mut commit.engine_rolled_back {
        for ev in &mut rb.events {
            rewrite_engine_event(ev, map);
        }
    }
    for lk in &mut commit.engine_key_lookups {
        for cid in &mut lk.lookup.contract_ids {
            remap_id(cid, map);
        }
    }
    for node in commit.lf_tree.nodes.values_mut() {
        match node {
            Node::Create { contract_id, .. }
            | Node::Exercise { contract_id, .. }
            | Node::Fetch { contract_id, .. } => remap_id(&mut contract_id.0, map),
            Node::LookupByKey {
                found: Some(cid), ..
            } => remap_id(&mut cid.0, map),
            _ => {}
        }
    }
    if let Some(ref mut tree) = commit.tx_tree_record {
        for ev in tree.events_by_id.values_mut() {
            match ev {
                TreeEvent::Created(c) => {
                    remap_id(&mut c.contract_id, map);
                    rewrite_json_value(&mut c.create_arguments, map);
                }
                TreeEvent::Exercised(e) => {
                    remap_id(&mut e.contract_id, map);
                    rewrite_json_value(&mut e.choice_argument, map);
                    if let Some(ref mut res) = e.exercise_result {
                        rewrite_json_value(res, map);
                    }
                }
            }
        }
    }
    if let Some(ref mut history) = commit.history {
        for ev in &mut history.events {
            rewrite_engine_event(ev, map);
        }
        let old = std::mem::take(&mut history.contracts);
        for (mut k, mut contract) in old {
            remap_id(&mut k, map);
            remap_id(&mut contract.contract_id, map);
            rewrite_lf_eval_value(&mut contract.payload, map);
            if let Some(ref mut kv) = contract.key {
                rewrite_lf_eval_value(kv, map);
            }
            history.contracts.insert(k, contract);
        }
    }
}

pub(super) fn rewrite_exercise_result_cids(
    exercise_result: &mut Option<serde_json::Value>,
    events: &mut [crate::models::json_api::JsonEvent],
    outcome_result: &mut lf_eval::Value,
    map: &std::collections::BTreeMap<String, String>,
) {
    if let Some(ref mut res) = exercise_result {
        rewrite_json_value(res, map);
    }
    rewrite_lf_eval_value(outcome_result, map);
    for ev in events {
        match ev {
            crate::models::json_api::JsonEvent::Created(c) => {
                remap_id(&mut c.contract_id, map);
                rewrite_json_value(&mut c.payload, map);
            }
            crate::models::json_api::JsonEvent::Archived(a) => {
                remap_id(&mut a.contract_id, map);
            }
        }
    }
}
