//! What submissions cost their senders while traffic control is on (see [`crate::traffic`]): checked when `SendAsync` answers and again
//! at the sequencing time, spent then, and journaled.
use super::{wall_micros, Sequencer};
use crate::submission::Submission;
use canton_participant::topology_wire as tw;
use tonic::Status;

impl Sequencer {
    /// Whether `member` can pay `cost` at the sequencing time `timestamp`: if not, the refusal of its submission and the receipt that spent
    /// nothing.
    ///
    /// [CANTON-NOTE: SEMANTICS] The balance is checked again at the sequencing time (`TrafficControlValidator.enforceTrafficControl`): a
    /// sender that cannot pay then (it sent to several sequencers at once, or this one checked with a stale state) gets
    /// `SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT` with the `AboveTrafficLimit` text in place of whatever its submission would have become, and
    /// nothing is delivered.
    pub(super) fn afford(
        &self,
        member: &str,
        cost: u64,
        timestamp: i64,
        params: &crate::traffic::TrafficParams,
    ) -> Result<(), ((i32, String), (u64, u64, u64))> {
        let Err(crate::traffic::Unpaid::NotEnough { cost, state, .. }) =
            self.inner
                .traffic
                .check(member, Some(cost), cost, timestamp, params)
        else {
            return Ok(());
        };
        let (_, extra_consumed, base_remainder, _, _, _) =
            self.inner.traffic.state(member, timestamp, params);
        Err((
            (
                9,
                format!(
                    "SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT: AboveTrafficLimit(\n  member = {member},\n  trafficCost = {cost},\n  trafficState = {state}\n)"
                ),
            ),
            (0, extra_consumed, base_remainder),
        ))
    }

    /// `member` pays `cost` for a submission sequenced at `timestamp` (checked with [`Self::afford`]), and the spend is journaled. Returns
    /// the receipt of its event.
    pub(super) fn spend(
        &self,
        member: &str,
        cost: u64,
        timestamp: i64,
        params: &crate::traffic::TrafficParams,
    ) -> (u64, u64, u64) {
        let after = self.inner.traffic.consume(member, cost, timestamp, params);
        crate::diag::diag_eprintln!(
            "TRAFFIC {member} spent {cost}: base {} left, extra consumed {}",
            after.base_remainder,
            after.extra_consumed
        );
        self.journal_traffic(member);
        (cost, after.extra_consumed, after.base_remainder)
    }

    pub(super) fn journal_traffic(&self, member: &str) {
        if let Some(journal) = self.inner.journal.get() {
            for line in self.inner.traffic.journal_lines(member) {
                journal.write(&line);
            }
        }
    }

    /// Takes a journaled traffic line back (no journaling).
    pub(crate) fn restore_traffic(&self, line: &str) -> Option<()> {
        self.inner.traffic.restore(line)
    }

    /// What `request` costs its sender under the traffic control in force, checked against what the sender has (see [`crate::traffic`]):
    /// `None` while traffic control is off or the sender does not pay; the refusal of a submission that is not paid for. A submission the
    /// ordering cluster already admitted is not refused again: it pays what it carries.
    pub(super) fn pay(
        &self,
        submission: &Submission,
        member: &str,
        now: i64,
        admitted: bool,
    ) -> Result<Option<(u64, crate::traffic::TrafficParams)>, Status> {
        let (submitted, recipients, envelopes) = (
            submission.submitted_cost,
            &submission.recipients,
            &submission.envelopes,
        );
        let Some(params) = self.inner.store.traffic_at(now) else {
            return Ok(None);
        };
        // only participants and mediators pay
        if !params.enforce || !(member.starts_with("PAR::") || member.starts_with("MED::")) {
            return Ok(None);
        }
        // [CANTON-NOTE: SEMANTICS] the group of all members counts every member the topology knows (`GroupAddressResolver` with
        // `knownMembers`): the registered participants, the mediators and the sequencer
        let members = self.inner.registry.members().len() + self.inner.mediators.len() + 1;
        let sizes: Vec<(usize, usize)> = recipients
            .iter()
            .zip(envelopes)
            .map(|(trees, envelope)| {
                let mut all: Vec<&String> = trees.iter().flatten().collect();
                all.sort();
                all.dedup();
                // a group address counts its members; a member counts once, and so does a mediator group (one mediator each here)
                let count = all
                    .iter()
                    .map(|a| if *a == tw::ALL_MEMBERS { members } else { 1 })
                    .sum();
                (envelope.content.len(), count)
            })
            .collect();
        let cost = params.event_cost(&sizes);
        if admitted {
            return Ok(Some((submitted.unwrap_or(cost).max(cost), params)));
        }
        let at = canton_participant::topology_state::iso_utc(now);
        match self
            .inner
            .traffic
            .check(member, submitted, cost, now, &params)
        {
            Ok(spend) => Ok(Some((spend, params))),
            // [CANTON-NOTE: SEMANTICS] the texts are the official sequencer's (measured, `ORACLE_TRAFFIC_ON`); the node shortens the ids in
            // them (`PAR::name::12209433b0e6...`), this one writes them whole
            Err(crate::traffic::Unpaid::IncorrectCost { submitted, cost }) => {
                Err(Status::failed_precondition(format!(
                    "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Submission was refused because traffic control validation failed: IncorrectEventCost(\n  member = {member},\n  submissionTimestamp = None(),\n{}  validationTimestamp = {at},\n  orderingSequencerId = None(),\n  correctCostDetails = EventCostDetails(\n    event cost = {cost},\n    cost multiplier = {}\n  )\n)",
                    submitted.map_or(String::new(), |s| format!("  submittedEventCost = {s},\n")),
                    params.scaling
                )))
            }
            Err(crate::traffic::Unpaid::NotEnough { cost, state, .. }) => {
                Err(Status::failed_precondition(format!(
                    "SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT(9,0): Submission was rejected because no traffic is available: AboveTrafficLimit(\n  member = {member},\n  trafficCost = {cost},\n  trafficState = {state}\n)"
                )))
            }
        }
    }

    /// The traffic state of `member` now, while traffic control is on.
    pub fn traffic_state(
        &self,
        member: &str,
    ) -> Option<canton_proto::com::digitalasset::canton::protocol::v30::TrafficState> {
        let now = wall_micros();
        let params = self.inner.store.traffic_at(now)?;
        let (purchased, consumed, base, last, at, serial) =
            self.inner.traffic.state(member, now, &params);
        Some(
            canton_proto::com::digitalasset::canton::protocol::v30::TrafficState {
                extra_traffic_purchased: purchased as i64,
                extra_traffic_consumed: consumed as i64,
                base_traffic_remainder: base as i64,
                last_consumed_cost: last,
                timestamp: at,
                serial,
            },
        )
    }
}
