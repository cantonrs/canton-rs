//! What a traffic cost estimate of a submission is made from (S-SIM-001): the traffic control parameters in force and the confirmation
//! response this participant would send, built but never sent.
//!
//! [CANTON-NOTE: SEMANTICS] Canton 3.7.2 `TrafficCostEstimator.estimateConfirmationResponseCost`: the estimated response is the one of
//! the executing participant, for the **root** view position, approving (`LocalApprove`), for its admin party and every `actAs` party it
//! hosts; its request id is the topology snapshot time and its root hash a mock hash. It goes to mediator group 0, which counts its
//! active and passive members (`GroupAddressResolver`). A sequencer prices an envelope by its content size, and the signatures travel
//! outside the content, so the mock signature of the official estimator does not change the cost.
use super::Runtime;
use crate::confirmation_wire::{confirmation_responses, Outcome, ViewResponse};
use crate::topology_wire::Ed25519Key;
use canton_proto::com::digitalasset::canton::protocol::v30::TrafficControlParameters;
use std::collections::BTreeSet;

/// One envelope as a sequencer prices it: its content size and how many members receive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PricedEnvelope {
    pub size: usize,
    pub recipients: usize,
}

/// A multihash of SHA-256 (`0x12 0x20` and 32 bytes): the size of the official mock root hash.
const MOCK_ROOT_HASH: [u8; 34] = {
    let mut h = [0u8; 34];
    h[0] = 0x12;
    h[1] = 0x20;
    h
};

impl Runtime {
    /// The traffic control parameters in force: `None` while traffic control is off, or when this runtime does not follow the topology
    /// (a hand-configured runtime knows no synchronizer parameters).
    pub fn traffic_control(&self) -> Option<&TrafficControlParameters> {
        self.tracker.as_ref()?.traffic_control()
    }

    /// The confirmation response this participant would send for a submission by `act_as` at `at_micros`, as a sequencer prices it.
    /// `None` without a followed topology or without mediator group 0.
    pub fn estimated_confirmation_response(
        &self,
        act_as: &[String],
        at_micros: i64,
    ) -> Option<PricedEnvelope> {
        let tracker = self.tracker.as_ref()?;
        let group = tracker.mediator_groups().get(&0)?;
        let recipients = group
            .active
            .iter()
            .chain(&group.observers)
            .collect::<BTreeSet<_>>()
            .len();
        let admin = self.own_admin_party.clone().unwrap_or_else(|| {
            self.config
                .member
                .strip_prefix("PAR::")
                .unwrap_or(&self.config.member)
                .to_string()
        });
        // [CANTON-NOTE: SEMANTICS] a party counts when this participant is among its active hosts (`activeParticipantsOfParties`)
        let mut confirming: BTreeSet<String> = act_as
            .iter()
            .filter(|party| {
                tracker
                    .hosts_of(party)
                    .is_some_and(|(_, hosts)| hosts.iter().any(|(host, _)| *host == admin))
            })
            .cloned()
            .collect();
        confirming.insert(admin);
        let confirming: Vec<String> = confirming.into_iter().collect();
        Some(mock_confirmation_response(
            &self.config.physical_synchronizer_id,
            &self.config.member,
            &confirming,
            at_micros,
            recipients,
        ))
    }
}

impl Runtime {
    /// The envelopes of a batch (each with its recipients) as a sequencer prices them: the content size and the number of members the
    /// recipients resolve to. `None` without a followed topology.
    pub fn priced_envelopes(
        &self,
        envelopes: &[(Vec<String>, Vec<u8>)],
    ) -> Option<Vec<PricedEnvelope>> {
        let tracker = self.tracker.as_ref()?;
        Some(
            envelopes
                .iter()
                .map(|(recipients, content)| PricedEnvelope {
                    size: content.len(),
                    recipients: recipients
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .map(|r| resolved_members(tracker, r))
                        .sum(),
                })
                .collect(),
        )
    }

    /// What a signed submission request costs under the traffic control in force: `None` while traffic control is off (or without a
    /// followed topology, or when the request does not decode).
    pub fn submission_cost(&self, signed_request: &[u8]) -> Option<u64> {
        submission_cost_with(self.tracker.as_ref()?, signed_request)
    }

    /// `signed_request` carrying the traffic cost it has under the traffic control in force, signed again by `key`; unchanged while
    /// traffic control is off (see [`pay_with`]).
    pub fn pay(&self, signed_request: Vec<u8>, key: &Ed25519Key) -> Vec<u8> {
        match self.tracker.as_ref() {
            Some(tracker) => pay_with(tracker, signed_request, key),
            None => signed_request,
        }
    }
}

/// How many members `address` resolves to when a sequencer prices an envelope: a mediator group (`MGR::<n>`) its active and passive
/// members, all members (`ALL::All`) every member the topology knows, a member one.
///
/// [CANTON-NOTE: SEMANTICS] `GroupAddressResolver.resolveGroupsToMembers`, which both the sending participant
/// (`TrafficStateController.computeCost`) and the sequencer (`SequencerRateLimitManagerImpl`) use; an unknown group counts none.
pub(crate) fn resolved_members(tracker: &crate::topology_state::Tracker, address: &str) -> usize {
    if address == crate::topology_wire::ALL_MEMBERS {
        return tracker.known_member_count();
    }
    match address
        .strip_prefix("MGR::")
        .and_then(|n| n.parse::<u32>().ok())
    {
        Some(n) => tracker.mediator_groups().get(&n).map_or(0, |g| {
            g.active
                .iter()
                .chain(&g.observers)
                .collect::<BTreeSet<_>>()
                .len()
        }),
        None => 1,
    }
}

/// What a signed submission request costs under the traffic control `tracker` has in force: `None` while traffic control is off (or when the
/// request does not decode). One reading for every member that submits: a participant ([`Runtime::submission_cost`]) and a mediator.
pub fn submission_cost_with(
    tracker: &crate::topology_state::Tracker,
    signed_request: &[u8],
) -> Option<u64> {
    let params = tracker.traffic_control()?;
    let envelopes: Vec<(usize, usize)> =
        crate::sequencing_wire::submission_envelopes(signed_request)?
            .into_iter()
            .map(|(size, addresses)| {
                (
                    size,
                    addresses.iter().map(|a| resolved_members(tracker, a)).sum(),
                )
            })
            .collect();
    Some(canton_algo::traffic_cost::event_cost(
        u64::from(params.read_vs_write_scaling_factor),
        params.base_event_cost.unwrap_or(0),
        &envelopes,
    ))
}

/// `signed_request` carrying the traffic cost it has under the traffic control `tracker` has in force, signed again by `key`; unchanged
/// while traffic control is off.
///
/// [CANTON-NOTE: SEMANTICS] A sequencer with traffic control on refuses a submission of a participant or mediator that carries no cost or
/// less than its cost (`IncorrectEventCost`); the official sequencer client computes the cost of every submission before it signs it
/// (`SequencerClientImpl` with `TrafficStateController.computeCost`), time proofs included.
pub fn pay_with(
    tracker: &crate::topology_state::Tracker,
    signed_request: Vec<u8>,
    key: &Ed25519Key,
) -> Vec<u8> {
    let paid = submission_cost_with(tracker, &signed_request).and_then(|cost| {
        crate::sequencing_wire::with_submission_cost(
            &signed_request,
            i64::try_from(cost).ok()?,
            key,
        )
    });
    paid.unwrap_or(signed_request)
}

/// The mock confirmation response of the official estimator (root view, approve, `confirming` parties, a mock root hash) from `member` on
/// `physical_synchronizer_id` at `at_micros`, to a mediator group of `recipients` members, as a sequencer prices it.
pub fn mock_confirmation_response(
    physical_synchronizer_id: &str,
    member: &str,
    confirming: &[String],
    at_micros: i64,
    recipients: usize,
) -> PricedEnvelope {
    // [CANTON-NOTE: WHY] the signature is thrown away (it is not part of the priced content), so any key will do
    let key = Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]));
    let (content, _) = confirmation_responses(
        at_micros,
        &MOCK_ROOT_HASH,
        physical_synchronizer_id,
        member,
        &[ViewResponse {
            view_position: &[],
            outcome: Outcome::Approve,
            confirming_parties: confirming,
        }],
        &key,
    );
    PricedEnvelope {
        size: content.len(),
        recipients,
    }
}
