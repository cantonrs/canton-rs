use super::errors::{invalid_argument, map_submit_err, refuse, sync_rejected};
use super::{shorten_member, NodeCommitter};
use crate::service::ApiError;
use crate::v2_commands::shorten_id;
use canton_participant::node::{SharedNode, Verdict};

impl NodeCommitter {
    /// The participants hosting one of `parties` on both synchronizers (`ReassigningParticipantsComputation`).
    pub(super) fn reassigning(
        from: &SharedNode,
        to: &SharedNode,
        parties: &[String],
    ) -> Result<Vec<String>, ApiError> {
        let a = from
            .with(|n| n.hosting_participants(parties))
            .map_err(refuse)?;
        let b = to
            .with(|n| n.hosting_participants(parties))
            .map_err(refuse)?;
        Ok(a.intersection(&b).cloned().collect())
    }

    pub(super) fn reassign_command(
        &self,
        command: &crate::service::ReassignCommand,
    ) -> Result<crate::service::ReassignOutcome, ApiError> {
        use crate::service::{ReassignCommand, ReassignOutcome};
        use canton_participant::multi_node::logical;
        use canton_participant::reassignment_submit::contract_parties;
        match command {
            ReassignCommand::Unassign {
                contract_id,
                source,
                target,
                submitter,
                command_id,
            } => {
                let (from, to) = (self.node_of(source)?, self.node_of(target)?);
                let instance = from
                    .with(|n| n.instance_bytes(contract_id))
                    .map_err(refuse)?
                    .ok_or_else(|| {
                        invalid_argument(format!(
                            "Cannot unassign contract `ContractId({contract_id})` because it's not active"
                        ))
                    })?;
                let parties = contract_parties(&instance).map_err(refuse)?;
                // [CANTON-NOTE: SEMANTICS] What the target synchronizer lacks is refused before anything is sent, in the official words
                // (tests/oracle/reassignment/json-api-checks-hosting.jsonl, -vetting.jsonl): stakeholders that no participant hosts there, and a
                // package this participant has not vetted there.
                let inactive: std::collections::BTreeSet<&String> = parties
                    .stakeholders
                    .iter()
                    .filter(|p| !to.party_is_active(p))
                    .collect();
                if !inactive.is_empty() {
                    return Err(invalid_argument(format!(
                        "Submission failed because: The following stakeholders are not active on the target synchronizer: TreeSet({})",
                        inactive.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
                    )));
                }
                if !to.has_vetted(&parties.package_id) {
                    let (target_id, member) = (
                        to.with(|n| n.physical_synchronizer_id().to_string())
                            .map_err(refuse)?,
                        to.with(|n| n.identity_member()).map_err(refuse)?,
                    );
                    return Err(invalid_argument(format!(
                        "Submission failed because: Cannot unassign contracts `Set(ContractId({contract_id}))` on synchronizer `{}`: Participant {} has not vetted {}...",
                        shorten_id(&target_id),
                        shorten_member(&member),
                        &parties.package_id[..parties.package_id.len().min(12)]
                    )));
                }
                let reassigning = Self::reassigning(from, to, &parties.stakeholders)?;
                let (target_physical, target_time) = to
                    .with(|n| {
                        Ok::<_, String>((
                            n.physical_synchronizer_id().to_string(),
                            n.current_time()?,
                        ))
                    })
                    .map_err(refuse)?
                    .map_err(refuse)?;
                let done = from
                    .with(|n| {
                        n.unassign(
                            contract_id,
                            &target_physical,
                            target_time,
                            submitter,
                            command_id,
                            &reassigning,
                            self.timeout,
                        )
                    })
                    .map_err(refuse)?
                    .map_err(map_submit_err)?;
                if done.verdict != Verdict::Approved {
                    let notes = from.with(|n| n.last_notes.clone()).unwrap_or_default();
                    return Err(sync_rejected("unassignment", &notes));
                }
                let source_physical = from
                    .with(|n| n.physical_synchronizer_id().to_string())
                    .map_err(refuse)?;
                let outcome = ReassignOutcome {
                    reassignment_id: done.reassignment_id.clone(),
                    contract_id: contract_id.clone(),
                    source: logical(&source_physical),
                    target: logical(&target_physical),
                    counter: done.counter,
                    record_time_micros: done.request_id.unwrap_or_default(),
                };
                self.unassigned
                    .lock()
                    .map_err(|_| refuse("poisoned"))?
                    .insert(
                        done.reassignment_id.clone(),
                        (done, source_physical, target_physical),
                    );
                Ok(outcome)
            }
            ReassignCommand::Assign {
                reassignment_id,
                source: _, // not compared: the stored unassignment names its own source
                target,
                submitter,
                command_id,
            } => {
                let to = self.node_of(target)?;
                // [CANTON-NOTE: SEMANTICS] The stored unassignment is looked up on the TARGET's side by its id: an id nobody unassigned, and an
                // id asked for on the wrong synchronizer (the directions swapped), are the same "unknown reassignment id"; one whose assignment
                // was approved is "reassignment already completed"; the source in the command is not compared
                // (tests/oracle/reassignment/json-api-checks-assign.jsonl).
                let cannot_find = |why: &str| {
                    invalid_argument(format!(
                        "Cannot find reassignment data for reassignment `ReassignmentId({reassignment_id})`: {why}"
                    ))
                };
                let stored = self
                    .unassigned
                    .lock()
                    .map_err(|_| refuse("poisoned"))?
                    .get(reassignment_id)
                    .cloned();
                let Some((done, source_physical, _)) = stored.filter(|(_, _, t)| {
                    logical(t)
                        == logical(
                            &to.with(|n| n.physical_synchronizer_id().to_string())
                                .unwrap_or_default(),
                        )
                }) else {
                    let completed = self
                        .completed
                        .lock()
                        .map_err(|_| refuse("poisoned"))?
                        .contains(reassignment_id);
                    return Err(cannot_find(if completed {
                        "reassignment already completed"
                    } else {
                        "unknown reassignment id"
                    }));
                };
                let from = self.node_of(&source_physical)?;
                let parties = contract_parties(&done.instance).map_err(refuse)?;
                let reassigning = Self::reassigning(from, to, &parties.stakeholders)?;
                // [CANTON-NOTE: SEMANTICS] R-6e / U-60 F4: `to` reads the participant's shared `SharedUnassignments` directly
                // (populated in Phase 7 of the unassignment on `from` and rehydrated across restarts by `MultiNode`); never synthesize
                // assign-time inputs as historical unassignment data (`AssignmentValidation.scala:74-105`).
                let assigned = to
                    .with(|n| {
                        n.assign(
                            &done,
                            &source_physical,
                            submitter,
                            command_id,
                            &reassigning,
                            self.timeout,
                        )
                    })
                    .map_err(refuse)?
                    .map_err(map_submit_err)?;
                if assigned.verdict != Verdict::Approved {
                    let notes = to.with(|n| n.last_notes.clone()).unwrap_or_default();
                    return Err(sync_rejected("assignment", &notes));
                }
                let target_physical = to
                    .with(|n| n.physical_synchronizer_id().to_string())
                    .map_err(refuse)?;
                self.unassigned
                    .lock()
                    .map_err(|_| refuse("poisoned"))?
                    .remove(reassignment_id);
                if let Ok(mut done_ids) = self.completed.lock() {
                    done_ids.insert(reassignment_id.clone());
                }
                from.forget_unassignment(reassignment_id);
                let contract_id =
                    canton_participant::reassignment_submit::contract_parties(&done.instance)
                        .map_err(refuse)?
                        .contract_id;
                Ok(ReassignOutcome {
                    reassignment_id: reassignment_id.clone(),
                    contract_id,
                    source: logical(&source_physical),
                    target: logical(&target_physical),
                    counter: assigned.counter,
                    record_time_micros: assigned.request_id.unwrap_or_default(),
                })
            }
        }
    }
}
