use super::errors::{map_submit_err, refuse, sync_rejected};
use super::{command_tag, transaction, NodeCommitter, Recorded, Recording, Replay};
use crate::service::{ApiError, ProtocolCommitter, TransactionCommit};
use canton_participant::node::{ExerciseCommand, Verdict};
use lf_eval::engine::NewContract;
use lf_eval::tx_model::Node as TxNode;

impl ProtocolCommitter for NodeCommitter {
    fn vetting_transaction(
        &self,
        package_ids: &[String],
        serial: u32,
    ) -> Option<crate::service::SignedTopologyRecord> {
        let signed = self
            .node
            .with(|n| {
                n.identity
                    .vetting_transaction_at_serial(package_ids, serial)
            })
            .ok()?;
        Some(crate::service::SignedTopologyRecord {
            transaction: signed.transaction.clone(),
            signatures: signed
                .signatures
                .iter()
                .map(prost::Message::encode_to_vec)
                .collect(),
            stored: canton_participant::topology_wire::stored_form(&signed),
        })
    }

    fn hosting_transaction(&self, hint: &str) -> Option<crate::service::HostedParty> {
        // the signature is deterministic (Ed25519), so this is the transaction the synchronizer was given
        let (party, signed) = self
            .node
            .with(|n| {
                (
                    n.identity.party_id(hint),
                    n.identity.party_hosting_transaction(hint),
                )
            })
            .ok()?;
        Some(crate::service::HostedParty {
            party,
            transaction: signed.transaction.clone(),
            signatures: signed
                .signatures
                .iter()
                .map(prost::Message::encode_to_vec)
                .collect(),
            stored: canton_participant::topology_wire::stored_form(&signed),
        })
    }

    fn allocate_party(&self, hint: &str) -> Option<Result<String, ApiError>> {
        // [CANTON-NOTE: SEMANTICS] on every synchronizer: the participant's party is the same id everywhere (its namespace), and a
        // contract can only move to a synchronizer where its stakeholders are hosted
        let mut hosted = None;
        for node in self.all_nodes() {
            let one = node
                .with(|node| node.host_party(hint, self.timeout))
                .map_err(refuse)
                .and_then(|r| r.map_err(refuse));
            if hosted.is_none() || one.is_err() {
                hosted = Some(one);
            }
        }
        hosted
    }

    fn traffic_cost_inputs(
        &self,
        act_as: &[String],
        at_micros: i64,
    ) -> Option<crate::cost_estimation::TrafficCostInputs> {
        self.node
            .with(|n| {
                let params = n.runtime.traffic_control()?;
                Some(crate::cost_estimation::TrafficCostInputs {
                    read_vs_write_scaling: u64::from(params.read_vs_write_scaling_factor),
                    base_event_cost: params.base_event_cost.unwrap_or(0),
                    free_confirmation_responses: params.free_confirmation_responses,
                    response: n
                        .runtime
                        .estimated_confirmation_response(act_as, at_micros)
                        .map(|e| (e.size, e.recipients)),
                })
            })
            .ok()
            .flatten()
    }

    fn prepared_transaction(
        &self,
        commits: &[TransactionCommit],
        command_id: &str,
        max_record_time: Option<i64>,
    ) -> Option<
        Result<
            canton_proto::com::daml::ledger::api::v2::interactive::PreparedTransaction,
            ApiError,
        >,
    > {
        // [CANTON-NOTE: LIMITATION] a transaction of one root (a create or an exercise) is offered; several commands are not
        let [commit] = commits else {
            return None;
        };
        let (roots, nodes, _) = commit.lf_tree.parts();
        let [root] = roots else {
            return None;
        };
        let submission = canton_participant::submit::Submission {
            external_authorization: Some(
                canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization {
                    authentications: Vec::new(),
                    hashing_scheme_version: 0,
                    max_record_time,
                },
            ),
        };
        let read = |node: &mut canton_participant::node::Node,
                    built: canton_participant::submit::Built| {
            canton_participant::external_hash::prepared_transaction(
                &node.runtime.engine,
                &built.tree,
            )
        };
        match nodes.get(root)? {
            TxNode::Create { .. } => {
                let [created] = commit.created_contracts.as_slice() else {
                    return None;
                };
                // the draws the contract id was allocated with: the same request is rebuilt, under the submission's command id
                // [CANTON-NOTE: DEFENSIVE] an id the protocol did not allocate (it could not build the request yet, e.g. a host of a
                // stakeholder is not in its topology) gives no prepared transaction its confirmers would accept: refused, not replaced
                let Some(recorded) = self
                    .recorded
                    .lock()
                    .ok()
                    .and_then(|r| r.get(&created.contract_id).cloned())
                else {
                    return Some(Err(refuse(format!(
                        "the protocol did not allocate {}: the request cannot be prepared yet",
                        created.contract_id
                    ))));
                };
                let template = transaction::qualified_template(created);
                let mut replay = Replay {
                    draws: recorded.draws,
                    at: 0,
                };
                let built = self.node.with(|node| {
                    let prepared = node.prepare_create_as(
                        &self.package_name,
                        &template,
                        &created.payload_value,
                        command_id,
                        recorded.now,
                        &mut replay,
                        submission,
                    )?;
                    read(node, prepared.built)
                });
                Some(built.map_err(refuse).and_then(|r| r.map_err(refuse)))
            }
            TxNode::Exercise {
                contract_id,
                choice,
                acting_parties,
                consuming,
                ..
            } => {
                let parts = match transaction::exercise_parts(
                    commit,
                    &contract_id.0,
                    *consuming,
                    acting_parties.iter().cloned().collect(),
                ) {
                    Ok(parts) => parts,
                    Err(e) => return Some(Err(e)),
                };
                let created = &commit.created_contracts;
                // the plan of the request: the one the ids of its creates were promised under, or a new one kept for the execution
                let plan = if created.is_empty() {
                    let plan = match self.node_holding(&contract_id.0).with(|n| n.plan_roots(1)) {
                        Ok(Ok(mut plans)) => plans.pop()?,
                        Ok(Err(e)) => return Some(Err(refuse(e))),
                        Err(e) => return Some(Err(refuse(e))),
                    };
                    let mut kept = self.prepared_plans.lock().ok()?;
                    if kept.len() >= super::MAX_PROMISES {
                        kept.pop_first();
                    }
                    kept.insert(command_id.to_string(), plan.clone());
                    plan
                } else {
                    let plan = self
                        .session_of
                        .lock()
                        .ok()
                        .and_then(|s| s.get(&created[0].contract_id).copied())
                        .and_then(|key| Some(self.exercises.lock().ok()?.get(&key)?.plan.clone()));
                    match plan {
                        Some(plan) => plan,
                        None => {
                            return Some(Err(refuse(format!(
                            "the protocol did not promise {}: the request cannot be prepared yet",
                            created[0].contract_id
                        ))))
                        }
                    }
                };
                let entries = transaction::tree_entries(&parts, created);
                let root = canton_participant::node::ExerciseRoot {
                    contract_id_hex: &contract_id.0,
                    choice,
                    argument: &parts.argument,
                    actors: &parts.actors,
                    observers: &parts.observers,
                    entries: &entries,
                    root_interface_id: transaction::root_interface_id(commit),
                    root_by_key: commit.root_by_key,
                    root_package_id: commit.root_package_id.as_deref(),
                };
                let built = self.node_holding(&contract_id.0).with(|node| {
                    let built = node.prepare_exercise_as(
                        &self.package_name,
                        &root,
                        command_id,
                        Some(plan),
                        &commit.disclosed_contracts,
                        &submission,
                    )?;
                    read(node, built)
                });
                Some(built.map_err(refuse).and_then(|r| r.map_err(refuse)))
            }
            _ => None,
        }
    }

    fn priced_confirmation_request(
        &self,
        commits: &[TransactionCommit],
        command_id: &str,
        external: Option<
            &canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization,
        >,
    ) -> Option<Result<Vec<(usize, usize)>, ApiError>> {
        // [CANTON-NOTE: LIMITATION] a transaction of one root (a create or an exercise) is built without sending; several commands in
        // one transaction (`commit_roots`) are not priced yet
        let [commit] = commits else {
            return None;
        };
        let (roots, nodes, _) = commit.lf_tree.parts();
        let [root] = roots else {
            return None;
        };
        // [CANTON-NOTE: SEMANTICS] the official estimator builds the request with the submitter info of the prepare (its command id) and, for
        // external parties, the mock signatures `external` carries (`TrafficCostEstimator.estimateConfirmationRequestCost`)
        let submission = canton_participant::submit::Submission {
            external_authorization: external.cloned(),
        };
        let priced = match nodes.get(root)? {
            TxNode::Create { .. } => {
                let [created] = commit.created_contracts.as_slice() else {
                    return None;
                };
                let template = transaction::qualified_template(created);
                self.node
                    .with(|node| {
                        node.priced_create_request(
                            &self.package_name,
                            &template,
                            &created.payload_value,
                            command_id,
                            &submission,
                        )
                    })
                    .map_err(refuse)
                    .and_then(|r| r.map_err(map_submit_err))
            }
            TxNode::Exercise {
                contract_id,
                choice,
                acting_parties,
                consuming,
                ..
            } => {
                let parts = match transaction::exercise_parts(
                    commit,
                    &contract_id.0,
                    *consuming,
                    acting_parties.iter().cloned().collect(),
                ) {
                    Ok(parts) => parts,
                    Err(e) => return Some(Err(e)),
                };
                let entries = transaction::tree_entries(&parts, &commit.created_contracts);
                let root = canton_participant::node::ExerciseRoot {
                    contract_id_hex: &contract_id.0,
                    choice,
                    argument: &parts.argument,
                    actors: &parts.actors,
                    observers: &parts.observers,
                    entries: &entries,
                    root_interface_id: transaction::root_interface_id(commit),
                    root_by_key: commit.root_by_key,
                    root_package_id: commit.root_package_id.as_deref(),
                };
                self.node_holding(&contract_id.0)
                    .with(|node| {
                        node.priced_exercise_request(
                            &self.package_name,
                            &root,
                            command_id,
                            &commit.disclosed_contracts,
                            &submission,
                        )
                    })
                    .map_err(refuse)
                    .and_then(|r| r.map_err(map_submit_err))
            }
            _ => return None,
        };
        match priced {
            Ok(Some(envelopes)) => Some(Ok(envelopes
                .into_iter()
                .map(|e| (e.size, e.recipients))
                .collect())),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    fn synchronizers(&self) -> Vec<(String, String)> {
        // [CANTON-NOTE: SEMANTICS] one synchronizer with a configured alias (the daemon names it from its bootstrap script) is listed under
        // that alias; one without an alias keeps the default answer of the single-synchronizer API
        if self.others.is_empty() && self.aliases.is_empty() {
            return Vec::new();
        }
        self.all_nodes()
            .iter()
            .zip(&self.aliases)
            .filter_map(|(n, alias)| {
                let physical = n.with(|n| n.physical_synchronizer_id().to_string()).ok()?;
                Some((
                    alias.clone(),
                    canton_participant::multi_node::logical(&physical),
                ))
            })
            .collect()
    }

    fn participant_id(&self) -> Option<String> {
        self.node.with(|n| n.identity.uid()).ok()
    }

    fn party_signing_keys(
        &self,
        party: &str,
    ) -> Option<(
        u32,
        Vec<canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey>,
    )> {
        self.node
            .with(|n| n.runtime.topology()?.party_signing_keys(party))
            .ok()
            .flatten()
    }

    fn reassign(
        &self,
        command: &crate::service::ReassignCommand,
    ) -> Option<Result<crate::service::ReassignOutcome, ApiError>> {
        if self.others.is_empty() {
            return None;
        }
        Some(self.reassign_command(command))
    }

    fn allocate_contract_id(
        &self,
        new: &NewContract<'_>,
        session: &mut Option<u64>,
    ) -> Option<String> {
        if new.depth > 0 {
            return self.allocate_created_by_exercise(new, session);
        }
        let mut recording = Recording::default();
        let qualified = if new.package_id.len() == 64 {
            format!("{}:{}", new.package_id, new.template_id)
        } else {
            new.template_id.to_string()
        };
        let (now, prepared) = self
            .node
            .with(|node| {
                let now = node.current_time()?;
                let prepared = node.prepare_create_for_allocation(
                    &self.package_name,
                    &qualified,
                    new.payload,
                    Some(now),
                    &mut recording,
                )?;
                Ok::<_, String>((now, prepared))
            })
            .ok()?
            .ok()?;
        let id = prepared.built.contract_id_hex;
        self.recorded.lock().ok()?.insert(
            id.clone(),
            Recorded {
                draws: recording.0,
                now,
            },
        );
        Some(id)
    }

    fn commit(&self, commit: &TransactionCommit) -> Result<(), ApiError> {
        let (roots, nodes, _) = commit.lf_tree.parts();
        let [root] = roots else {
            return Err(refuse(format!(
                "a transaction with {} roots is not supported",
                roots.len()
            )));
        };
        match nodes.get(root) {
            Some(TxNode::Create { .. }) => {
                let [created] = commit.created_contracts.as_slice() else {
                    return Err(refuse("a create transaction creates one contract"));
                };
                let recorded = self
                    .recorded
                    .lock()
                    .map_err(refuse)?
                    .remove(&created.contract_id)
                    .ok_or_else(|| {
                        refuse(format!(
                            "{} was not allocated by the protocol",
                            created.contract_id
                        ))
                    })?;
                let template = if created.package_id.len() == 64 {
                    format!(
                        "{}:{}:{}",
                        created.package_id,
                        created.template_id.module_name,
                        created.template_id.entity_name
                    )
                } else {
                    format!(
                        "{}:{}",
                        created.template_id.module_name, created.template_id.entity_name
                    )
                };
                let mut replay = Replay {
                    draws: recorded.draws,
                    at: 0,
                };
                let command_id = self.recording_command_id();
                // [CANTON-NOTE: SEMANTICS] an interactive submission's request carries its external parties' authorization (U-56); the
                // replayed draws make it the request its prepared transaction was read from
                let external = crate::service::current_external_authorization();
                let prepared = self
                    .node
                    .with(|node| match external {
                        Some(authorization) => node.prepare_create_as(
                            &self.package_name,
                            &template,
                            &created.payload_value,
                            &command_id,
                            recorded.now,
                            &mut replay,
                            canton_participant::submit::Submission {
                                external_authorization: Some(authorization),
                            },
                        ),
                        None => node.prepare_create(
                            &self.package_name,
                            &template,
                            &created.payload_value,
                            &command_id,
                            Some(recorded.now),
                            &mut replay,
                        ),
                    })
                    .map_err(refuse)?
                    .map_err(map_submit_err)?;
                if prepared.built.contract_id_hex != created.contract_id {
                    return Err(refuse(
                        "the replayed request names another contract id than the one promised",
                    ));
                }
                match self
                    .node
                    .submit_prepared_tagged(prepared, self.tracking_timeout, &command_tag())
                    .map_err(map_submit_err)?
                {
                    (Verdict::Approved, _) => {
                        if let Some(hash) =
                            canton_participant::node::SharedNode::take_last_approved_root_hash()
                        {
                            crate::service::set_protocol_update_id(hex::encode(hash));
                        }
                        let remapped =
                            canton_participant::node::SharedNode::take_last_remapped_cids();
                        self.note_salts_with_remap(commit, &remapped);
                        if !remapped.is_empty() {
                            crate::service::set_protocol_remapped_cids(remapped);
                        }
                        Ok(())
                    }
                    (Verdict::Rejected, notes) => Err(sync_rejected("create", &notes)),
                }
            }
            Some(TxNode::Exercise {
                contract_id,
                choice,
                acting_parties,
                consuming,
                ..
            }) => {
                let created = &commit.created_contracts;
                let parts = transaction::exercise_parts(
                    commit,
                    &contract_id.0,
                    *consuming,
                    acting_parties.iter().cloned().collect(),
                )?;
                // the plan the promised ids were derived from, and proof that nothing was created out of order
                let external = crate::service::current_external_authorization();
                let plan = if created.is_empty() {
                    // an interactive exercise is built with the plan its prepared transaction was read from (U-56)
                    external.as_ref().and_then(|_| {
                        self.prepared_plans
                            .lock()
                            .ok()
                            .and_then(|mut kept| kept.remove(&self.recording_command_id()))
                    })
                } else {
                    let key = *self
                        .session_of
                        .lock()
                        .map_err(refuse)?
                        .get(&created[0].contract_id)
                        .ok_or_else(|| {
                            refuse(format!(
                                "{} was not allocated by the protocol",
                                created[0].contract_id
                            ))
                        })?;
                    let record = self
                        .exercises
                        .lock()
                        .map_err(refuse)?
                        .remove(&key)
                        .ok_or_else(|| refuse("the promised ids of this exercise are gone"))?;
                    let promised: Vec<&str> =
                        record.ids.iter().map(|(_, id)| id.as_str()).collect();
                    let made: Vec<&str> = created.iter().map(|c| c.contract_id.as_str()).collect();
                    let in_order = record
                        .ids
                        .iter()
                        .enumerate()
                        .all(|(i, (index, _))| i == *index);
                    if promised != made || !in_order {
                        return Err(refuse(format!(
                            "the contracts created ({made:?}) are not the ones whose ids were promised in order ({promised:?}); \
                             a create that was rolled back or reordered is not supported"
                        )));
                    }
                    Some(record.plan)
                };
                let root_interface_id = transaction::root_interface_id(commit);
                let entries = transaction::tree_entries(&parts, created);
                let tag = command_tag();
                let scope_command_id = self.recording_command_id();
                match self
                    .node_holding(&contract_id.0)
                    .submit_exercise_command(ExerciseCommand {
                        package_name: &self.package_name,
                        contract_id_hex: &contract_id.0,
                        choice,
                        argument: &parts.argument,
                        actors: &parts.actors,
                        observers: &parts.observers,
                        command_id: &scope_command_id,
                        plan,
                        entries: &entries,
                        root_interface_id,
                        root_by_key: commit.root_by_key,
                        root_package_id: commit.root_package_id.as_deref(),
                        disclosed_instances: &commit.disclosed_contracts,
                        timeout: self.tracking_timeout,
                        tag: &tag,
                        submission: canton_participant::submit::Submission {
                            external_authorization: external,
                        },
                    })
                    .map_err(map_submit_err)?
                {
                    (Verdict::Approved, _) => {
                        if let Some(hash) =
                            canton_participant::node::SharedNode::take_last_approved_root_hash()
                        {
                            crate::service::set_protocol_update_id(hex::encode(hash));
                        }
                        let remapped =
                            canton_participant::node::SharedNode::take_last_remapped_cids();
                        self.note_salts_with_remap(commit, &remapped);
                        if !remapped.is_empty() {
                            crate::service::set_protocol_remapped_cids(remapped);
                        }
                        Ok(())
                    }
                    (Verdict::Rejected, notes) => Err(sync_rejected("exercise", &notes)),
                }
            }
            other => Err(refuse(format!(
                "a transaction whose root is {other:?} is not supported"
            ))),
        }
    }

    fn instance_bytes(&self, contract_id: &str) -> Option<Vec<u8>> {
        self.pending_instance(contract_id)
            .or_else(|| self.node_holding(contract_id).instance_bytes(contract_id))
    }

    fn command_recorded(&self) {
        self.command_recorded_for("");
    }

    fn command_recorded_for(&self, command_id: &str) {
        for node in self.all_nodes() {
            if let Err(e) = node.awaited_recorded_for(command_id) {
                crate::diag::diag_eprintln!(
                    "the fates of this thread's commands could not be marked shown: {e}"
                );
            }
        }
    }

    fn begin_transaction(&self, roots: usize) -> Option<Result<u64, ApiError>> {
        Some(self.begin(roots))
    }

    fn allocate_in_transaction(
        &self,
        transaction: u64,
        root: usize,
        new: &NewContract<'_>,
    ) -> Option<String> {
        self.allocate_in(transaction, root, new)
    }

    fn commit_transaction(
        &self,
        transaction: u64,
        commits: &[TransactionCommit],
    ) -> Result<(), ApiError> {
        self.commit_roots(transaction, commits)
    }

    fn abort_transaction(&self, transaction: u64) {
        self.abort(transaction);
    }

    fn vet_dar(&self, dar_bytes: &[u8]) -> Result<(), ApiError> {
        static VET_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "v2-vet-{}-{}.dar",
            std::process::id(),
            VET_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::write(&path, dar_bytes).map_err(refuse)?;
        let mut res = Ok(());
        for node in self.all_nodes() {
            if let Err(e) = node.upload_and_vet_dar(&path, self.timeout).map_err(refuse) {
                res = Err(e);
                break;
            }
        }
        let _ = std::fs::remove_file(&path);
        res
    }

    fn vet_loaded_dar(&self, loaded: &lf_archive::LoadedDar) -> Result<(), ApiError> {
        for node in self.all_nodes() {
            node.upload_and_vet_loaded_dar(loaded, self.timeout)
                .map_err(refuse)?;
        }
        Ok(())
    }

    fn protocol_in_flight(&self) -> usize {
        self.all_nodes().iter().map(|n| n.in_flight_count()).sum()
    }

    fn sync_vetted_packages(
        &self,
        synchronizer_id: Option<&str>,
        vetted_pkg_ids: &[String],
    ) -> Result<(), ApiError> {
        let nodes = self.all_nodes();
        if let Some(target) = synchronizer_id.filter(|s| !s.is_empty()) {
            let target_logical = canton_participant::multi_node::logical(target);
            for node in nodes {
                let phys = node
                    .with(|n| n.physical_synchronizer_id().to_string())
                    .map_err(refuse)?;
                if phys == target
                    || canton_participant::multi_node::logical(&phys) == target_logical
                {
                    node.sync_vetted_packages(vetted_pkg_ids, self.timeout)
                        .map_err(refuse)?;
                }
            }
            return Ok(());
        }
        for node in nodes {
            node.sync_vetted_packages(vetted_pkg_ids, self.timeout)
                .map_err(refuse)?;
        }
        Ok(())
    }

    fn repair_add(&self, contracts: &[(String, Vec<u8>)]) -> Option<Result<Vec<String>, String>> {
        Some(
            self.node
                .with(|n| {
                    let ids = n.runtime.repair_add(contracts)?;
                    for (_, instance) in contracts {
                        n.adopt_instance(instance)?;
                    }
                    Ok(ids)
                })
                .and_then(|r| r),
        )
    }

    fn repair_purge(&self, ids: &[String], ignore_inactive: bool) -> Option<Result<(), String>> {
        Some(
            self.node
                .with(|n| n.runtime.repair_purge(ids, ignore_inactive))
                .and_then(|r| r),
        )
    }

    /// The latest commitment tick of every synchronizer's node, the earliest of them (`i64::MIN` while a node has had none).
    ///
    /// [CANTON-NOTE: SEMANTICS] `FirstUnsafeOffsetComputation` (3.7.2) refuses to prune past the latest ACS digest checkpoint ("ACS digest
    /// ingestion"); with no checkpoint the first offset is already unsafe. A checkpoint here is a reconciliation tick (the node also makes
    /// one at hosting changes and received commitments, so this bound is the stricter one).
    fn safe_to_prune_micros(&self) -> Option<i64> {
        self.all_nodes()
            .into_iter()
            .map(|n| {
                n.with(|n| n.runtime.commitment_safe_to_prune())
                    .ok()
                    .flatten()
                    .unwrap_or(i64::MIN)
            })
            .min()
    }

    fn pending_topology_changes(&self) -> usize {
        self.all_nodes()
            .into_iter()
            .map(|n| n.pending_topology_changes())
            .sum()
    }

    fn check_ready(&self) -> Result<(), String> {
        for node in self.all_nodes() {
            node.sequencer_status()?;
        }
        Ok(())
    }
}
