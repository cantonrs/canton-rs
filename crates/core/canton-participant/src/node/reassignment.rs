use super::{stored_from, Node, ReassignmentDone, Verdict};
use crate::submit::{Os, Peer};
use crate::view_conformance::open_instance;
use std::collections::BTreeMap;
use std::time::Duration;

/// Reassignments (G7 B1, S-NET-040 part 7): a node is one synchronizer's connection, so an unassignment is submitted by the source's node and
/// the assignment by the target's (see [`crate::multi_node::MultiNode`], which holds both with one identity).
impl Node {
    /// The view's recipients for a request about `parties`: every host of one of them here with its encryption key (this node included).
    pub(super) fn reassignment_recipients(&self, parties: &[String]) -> Vec<Peer> {
        let mut out: BTreeMap<String, Peer> = BTreeMap::new();
        for party in parties {
            if self.runtime.config.hosted_parties.contains(party) {
                let me = self.me();
                out.insert(me.member.clone(), me);
            }
            for (member, _, key) in self.runtime.hosts_of(party) {
                if member == self.identity.member() {
                    out.insert(member, self.me());
                } else if let Some(k) = key {
                    out.insert(
                        member.clone(),
                        Peer {
                            member,
                            encryption_spki: k.spki,
                            fingerprint: k.fingerprint,
                        },
                    );
                }
            }
        }
        out.into_values().collect()
    }

    /// The reassignment counter of a contract on this synchronizer.
    pub fn reassignment_counter(&self, contract_id_hex: &str) -> i64 {
        self.runtime.ledger.counter_of(contract_id_hex)
    }

    pub(super) fn signed(&self, built: &crate::reassignment_submit::Built, now: i64) -> Vec<u8> {
        crate::sequencing_wire::signed_submission_request(
            built.submission_request(&self.identity.member(), now + 60_000_000),
            &self.identity.signing_key,
        )
    }

    /// Submits the unassignment of `contract_id_hex` (active on this node's synchronizer) to `target` (a physical id, whose time is
    /// `target_time_micros`) as `submitter`, and waits for the verdict. `reassigning` are the participants hosting a stakeholder on both
    /// synchronizers. On approval the contract can no longer be exercised here.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn unassign(
        &mut self,
        contract_id_hex: &str,
        target: &str,
        target_time_micros: i64,
        submitter: &str,
        command_id: &str,
        reassigning: &[String],
        timeout: Duration,
    ) -> Result<ReassignmentDone, String> {
        use crate::reassignment_submit as rs;
        if !self.runtime.ledger.is_active(contract_id_hex) {
            return Err(format!(
                "the contract {contract_id_hex} is not active on {}",
                self.physical
            ));
        }
        let instance = self
            .instance_bytes(contract_id_hex)
            .ok_or_else(|| format!("this node has no instance of {contract_id_hex}"))?;
        let parties = rs::contract_parties(&instance)?;
        let counter = self.reassignment_counter(contract_id_hex);
        let recipients = self.reassignment_recipients(&parties.stakeholders);
        let now = self.current_time()?;
        let source = self.physical.clone();
        let built = rs::unassignment(
            &self.identity,
            &rs::Unassignment {
                source: &source,
                target,
                target_time_micros,
                instance: &instance,
                current_counter: counter,
                submitter,
                command_id,
                user_id: &self.user_id.clone(),
                reassigning_participant_uids: reassigning,
                recipients: &recipients,
                now_micros: now,
            },
            &mut Os,
        )?;
        let request = self.signed(&built, now);
        self.send_raw(&built.message_id, request)?;
        let verdict = self.wait_for(&built.message_id, timeout)?;
        let request_id = self.runtime.ledger.unassigned_by(contract_id_hex);
        let logical = |p: &str| {
            p.rsplit_once("::")
                .map(|x| x.0.to_string())
                .unwrap_or_default()
        };
        let reassignment_id = request_id
            .map(|t| {
                crate::reassignment_wire::reassignment_id(
                    &logical(&source),
                    &logical(target),
                    t,
                    &[(contract_id_hex, counter + 1)],
                )
            })
            .unwrap_or_default();
        if verdict == Verdict::Approved {
            self.forget(contract_id_hex);
        }
        let done = ReassignmentDone {
            verdict,
            request_id,
            reassignment_id,
            counter: counter + 1,
            instance,
        };
        if verdict == Verdict::Approved {
            self.remember_unassignment(&done, target);
        }
        Ok(done)
    }

    /// Submits the assignment, on this node's synchronizer (the target), of the unassignment `unassigned` that `source`'s node submitted
    /// (`reassigning` as for the unassignment), and waits for the verdict. On approval the contract can be exercised here.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire builders and state handlers pass explicit field arguments directly"
    )]
    pub fn assign(
        &mut self,
        unassigned: &ReassignmentDone,
        source: &str,
        submitter: &str,
        command_id: &str,
        reassigning: &[String],
        timeout: Duration,
    ) -> Result<ReassignmentDone, String> {
        use crate::reassignment_submit as rs;
        let unassignment_time = unassigned
            .request_id
            .ok_or("the unassignment has no request id")?;
        let parties = rs::contract_parties(&unassigned.instance)?;
        let recipients = self.reassignment_recipients(&parties.stakeholders);
        let now = self.current_time()?;
        let target = self.physical.clone();
        let built = rs::assignment(
            &self.identity,
            &rs::Assignment {
                source,
                target: &target,
                unassignment_time_micros: unassignment_time,
                reassignment_id: &unassigned.reassignment_id,
                instance: &unassigned.instance,
                counter: unassigned.counter,
                submitter,
                command_id,
                user_id: &self.user_id.clone(),
                reassigning_participant_uids: reassigning,
                recipients: &recipients,
                now_micros: now,
            },
            &mut Os,
        )?;
        let request = self.signed(&built, now);
        self.send_raw(&built.message_id, request)?;
        let verdict = self.wait_for(&built.message_id, timeout)?;
        let request_id = self.board.last_approved.lock().ok().and_then(|g| *g);
        if verdict == Verdict::Approved {
            let opened = open_instance(&self.runtime.engine, &unassigned.instance)?;
            self.remember(stored_from(&opened, &unassigned.instance));
        }
        Ok(ReassignmentDone {
            verdict,
            request_id: request_id.filter(|_| verdict == Verdict::Approved),
            reassignment_id: unassigned.reassignment_id.clone(),
            counter: unassigned.counter,
            instance: unassigned.instance.clone(),
        })
    }
}
