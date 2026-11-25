//! The runtime's side of the ACS commitments ([`crate::acs_commitment_runtime`]): the changes and ticks of each event, the commitments
//! received, and the sending.
use super::{Runtime, Step};
use crate::acs_commitment::PeriodStatus;
use crate::acs_commitment_runtime::{Outgoing, DEFAULT_RECONCILIATION_INTERVAL_MICROS};
use crate::sequencer_connect::{SequencerConnect, Token};
use crate::sequencing_wire::{signed_submission_request, submission_request_to_groups};
use crate::topology_state::Tracker;
use crate::topology_wire::Ed25519Key;
use std::collections::BTreeSet;

/// The participants (uids) that host `party` now, whatever their permission.
fn hosts_of(tracker: Option<&Tracker>, party: &str) -> Vec<String> {
    tracker
        .and_then(|t| t.hosts_of(party))
        .map(|(_, hosts)| hosts.into_iter().map(|(uid, _)| uid).collect())
        .unwrap_or_default()
}

impl Runtime {
    fn own_uid(&self) -> String {
        self.config.member.trim_start_matches("PAR::").to_string()
    }

    /// The reconciliation interval of the dynamic parameters in force.
    fn reconciliation_interval_micros(&self) -> i64 {
        self.tracker
            .as_ref()
            .and_then(|t| t.parameters())
            .and_then(|(_, p)| p.reconciliation_interval.as_ref())
            .map(|d| d.seconds * 1_000_000 + i64::from(d.nanos) / 1_000)
            .filter(|micros| *micros > 0)
            .unwrap_or(DEFAULT_RECONCILIATION_INTERVAL_MICROS)
    }

    /// The stakeholders of `stakeholders` this participant hosts now.
    pub(super) fn hosted_here(&self, stakeholders: &BTreeSet<String>) -> BTreeSet<String> {
        let me = self.own_uid();
        let tracker = self.tracker.as_ref();
        stakeholders
            .iter()
            .filter(|party| {
                self.config.hosted_parties.contains(party) || hosts_of(tracker, party).contains(&me)
            })
            .cloned()
            .collect()
    }

    /// Checks and compares a commitment another participant sent; `false` when the envelope is no commitment.
    pub(super) fn receive_commitment(
        &mut self,
        envelope: &[u8],
        delivered_at: i64,
        step: &mut Step,
    ) -> bool {
        let me = self.own_uid();
        let tracker = self.tracker.as_ref();
        let keys_of = |member: &str| tracker.and_then(|t| t.signing_keys_of(member));
        match self.commitments.receive(
            envelope,
            delivered_at,
            &me,
            &self.config.physical_synchronizer_id,
            &keys_of,
        ) {
            Some(note) => {
                step.notes.push(note);
                true
            }
            None => false,
        }
    }

    /// Takes in what the event's verdicts changed, notes the boundary the event passed (`previous` is the time of the event before), and
    /// puts the commitments of the ticks that are complete into `step`.
    pub(super) fn track_commitments(
        &mut self,
        previous: i64,
        now: i64,
        step: &mut Step,
    ) -> Result<(), String> {
        let me = self.own_uid();
        let tracker = self.tracker.as_ref();
        let configured = &self.config.hosted_parties;
        let hosted_here = |party: &str| {
            configured.iter().any(|p| p == party) || hosts_of(tracker, party).contains(&me)
        };
        for applied in &step.applied {
            let notes = self.commitments.apply(applied, &hosted_here)?;
            step.notes.extend(notes);
        }
        let interval = self.reconciliation_interval_micros();
        self.commitments.pass(previous, now, interval);
        let tracker = self.tracker.as_ref();
        let (outgoing, notes) =
            self.commitments
                .take_due(self.ledger.earliest_in_flight(), &me, &|party| {
                    hosts_of(tracker, party)
                })?;
        step.commitments.extend(outgoing);
        step.notes.extend(notes);
        Ok(())
    }

    /// Sends `commitments` (of one event) in one batch, each envelope to its counter-participant alone.
    pub(super) fn send_commitments(
        &self,
        connection: &mut SequencerConnect,
        token: &Token,
        signing_key: &Ed25519Key,
        commitments: &[Outgoing],
        event_time: i64,
    ) -> Result<(), String> {
        let Some(first) = commitments.first() else {
            return Ok(());
        };
        let me = self.own_uid();
        let psid = &self.config.physical_synchronizer_id;
        let envelopes: Vec<(Vec<String>, Vec<u8>)> = commitments
            .iter()
            .map(|c| {
                (
                    vec![format!("PAR::{}", c.counter_participant)],
                    crate::acs_commitment::commitment_message(
                        psid,
                        &me,
                        &c.counter_participant,
                        c.from_exclusive,
                        c.to_inclusive,
                        &c.digest,
                        signing_key,
                    ),
                )
            })
            .collect();
        // an event read while catching up is old: the sequencer's clock, not the event's, says until when it can still sequence the batch
        let now = connection
            .sequencer_time(&self.config.member, psid, Some(token))
            .ok()
            .flatten()
            .map_or(event_time, |t| t.max(event_time));
        let request = submission_request_to_groups(
            &self.config.member,
            &format!("acs-commitment-{}", first.to_inclusive),
            &envelopes,
            now + self.reconciliation_interval_micros(),
        );
        connection
            .send_async(
                &self.config.member,
                psid,
                token,
                self.pay(signed_submission_request(request, signing_key), signing_key),
            )
            .map_err(|e| e.to_string())
    }

    /// Every commitment comparison so far (counter-participant, tick, verdict): what `ACS_COMMITMENT_MISMATCH` was reported for.
    pub fn commitment_periods(&self) -> Vec<PeriodStatus> {
        self.commitments.periods()
    }

    /// The latest tick it is safe to prune up to as far as the ACS commitments go (see `Commitments::safe_to_prune`).
    pub fn commitment_safe_to_prune(&self) -> Option<i64> {
        self.commitments.safe_to_prune()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{config, engine, event};
    use super::super::Runtime;

    /// P-9: a contract shared with another participant gives that participant a commitment at the first event past a reconciliation
    /// boundary; the other participant's commitment for the same tick is verified and compared, and a different digest is a mismatch.
    #[test]
    fn a_shared_contract_is_committed_to_at_each_tick_and_compared_with_the_peer() {
        use crate::lthash::{commitment_digest, digest_element, ordered_pair, LtHash16};
        use crate::topology_wire::ParticipantIdentity;
        let me = ParticipantIdentity::generate("cmt-me");
        let peer = ParticipantIdentity::generate("cmt-peer");
        let mut signed = me.onboarding_transactions("sync::1220aa");
        signed.extend(peer.onboarding_transactions("sync::1220aa"));
        signed.push(me.party_hosting_transaction("alice"));
        signed.push(peer.party_hosting_transaction("bob"));
        let state: Vec<(i64, Vec<u8>)> = signed
            .iter()
            .map(|t| (0, crate::topology_wire::stored_form(t)))
            .collect();
        let entries = crate::topology_state::decode(&state).unwrap();
        let mut cfg = config();
        cfg.member = me.member();
        cfg.follow_topology = true;
        cfg.physical_synchronizer_id = "sync::1220aa::37-0".into();
        let mut rt = Runtime::open(cfg, engine(), None, 0).unwrap();
        rt.load_topology_state(&entries).unwrap();
        let (alice, bob) = (me.party_id("alice"), peer.party_id("bob"));

        // the contract is created by a request sequenced at 10 s
        rt.commitments
            .activate(
                "00aa",
                10_000_000,
                0,
                [alice.clone(), bob.clone()].into(),
                [alice.clone()].into(),
            )
            .unwrap();
        assert!(rt.step(&event(30_000_000)).unwrap().commitments.is_empty());
        let step = rt.step(&event(61_000_000)).unwrap();
        let mut set = LtHash16::empty();
        let (a, b) = ordered_pair(&alice, &bob);
        set.add(&digest_element("00aa", 0, a, b));
        let expected = commitment_digest(&set);
        assert_eq!(
            step.commitments,
            vec![crate::acs_commitment_runtime::Outgoing {
                counter_participant: peer.uid(),
                from_exclusive: 9_999_999,
                to_inclusive: 60_000_000,
                digest: expected.clone(),
            }],
            "{:?}",
            step.notes
        );

        // the peer's commitment for that tick, signed by it
        let mut theirs = event(70_000_000);
        theirs.envelopes = vec![crate::acs_commitment::commitment_message(
            "sync::1220aa::37-0",
            &peer.uid(),
            &me.uid(),
            9_999_999,
            60_000_000,
            &expected,
            &peer.signing_key,
        )];
        let step = rt.step(&theirs).unwrap();
        assert!(
            !step.notes.iter().any(|n| n.contains("ACS_COMMITMENT")),
            "{:?}",
            step.notes
        );
        assert_eq!(
            rt.commitment_periods(),
            vec![crate::acs_commitment::PeriodStatus {
                counter_participant: peer.uid(),
                to_inclusive: 60_000_000,
                verdict: crate::acs_commitment::PeriodVerdict::Matched,
            }]
        );

        // the next tick: the peer thinks nothing is shared any more
        rt.step(&event(121_000_000)).unwrap();
        let mut wrong = event(125_000_000);
        wrong.envelopes = vec![crate::acs_commitment::commitment_message(
            "sync::1220aa::37-0",
            &peer.uid(),
            &me.uid(),
            9_999_999,
            120_000_000,
            &commitment_digest(&LtHash16::empty()),
            &peer.signing_key,
        )];
        let step = rt.step(&wrong).unwrap();
        assert!(
            step.notes
                .iter()
                .any(|n| n.contains("ACS_COMMITMENT_MISMATCH") && n.contains(&peer.uid())),
            "{:?}",
            step.notes
        );
        // a commitment signed by a key that is not the sender's is set aside
        let mut forged = event(126_000_000);
        forged.envelopes = vec![crate::acs_commitment::commitment_message(
            "sync::1220aa::37-0",
            &peer.uid(),
            &me.uid(),
            9_999_999,
            120_000_000,
            &expected,
            &me.signing_key,
        )];
        let step = rt.step(&forged).unwrap();
        assert!(
            step.notes
                .iter()
                .any(|n| n.contains("ACS_COMMITMENT_ALARM")),
            "{:?}",
            step.notes
        );
        assert_eq!(rt.commitment_safe_to_prune(), Some(120_000_000));
    }
}
