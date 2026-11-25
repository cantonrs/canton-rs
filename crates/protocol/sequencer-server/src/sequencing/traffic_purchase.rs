//! A traffic purchase (`SequencerAdministrationService.SetTrafficPurchased`) is a message the sequencers send to themselves: a
//! `SetTrafficPurchasedMessage` signed by the sequencer, addressed to the sequencer group (and to the member when it is registered), with the
//! sequencer group's aggregation rule. It is in force once it is sequenced, from its sequencing time on, on every sequencer that orders it.
//!
//! [CANTON-NOTE: SEMANTICS] Read from 3.7.2 `BlockSequencer.setTrafficPurchased`, `TrafficPurchasedSubmissionHandler`,
//! `TrafficControlProcessor` and `TrafficPurchasedManager`:
//! - the call is refused when traffic control is off (`TRAFFIC_CONTROL_DISABLED`) or the serial is not above the member's latest applied one
//!   (`TRAFFIC_CONTROL_SERIAL_TOO_LOW`); otherwise the message is submitted with the maximum sequencing time at the end of the current
//!   `set_balance_request_submission_window_size` window, and also at the end of the next one in the last quarter of a window, so that the
//!   sequencers of a group submit the same request and it aggregates;
//! - the message is applied where it is delivered to the sequencer group with the group's signatures: a serial not above the latest one is
//!   ignored, and the balance counts from right after the sequencing time (`balances.maxBefore(timestamp)`).
use super::{overloaded, wall_micros, Sequencer};
use crate::aggregation::SEQUENCER_GROUP;
use crate::submission::Submission;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    typed_signed_protocol_message_content::SomeSignedProtocolMessage, AggregationRule,
    RecipientsTree, SetTrafficPurchasedMessage, TypedSignedProtocolMessageContent,
};
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use prost::Message;
use tonic::Status;

/// What a purchase submission says.
pub struct PurchaseRequest<'a> {
    /// The sequencer that submits it (`SEQ::...`).
    pub sender: &'a str,
    pub physical_synchronizer_id: &'a str,
    /// The member the traffic is for.
    pub member: &'a str,
    /// Whether the member is a recipient too (only a registered member may be addressed).
    pub address_member: bool,
    pub serial: u32,
    /// The member's new total of extra traffic.
    pub total: u64,
    pub max_sequencing_time: i64,
    pub message_id: &'a str,
}

/// The signed submission request of a purchase, signed (request and message) with `key`.
pub fn purchase_submission(request: &PurchaseRequest, key: &tw::Ed25519Key) -> Vec<u8> {
    let message = SetTrafficPurchasedMessage {
        member: request.member.to_string(),
        serial: request.serial,
        total_traffic_purchased: request.total,
        physical_synchronizer_id: request.physical_synchronizer_id.to_string(),
    };
    let typed = TypedSignedProtocolMessageContent {
        some_signed_protocol_message: Some(SomeSignedProtocolMessage::SetTrafficPurchased(
            tw::versioned(message.encode_to_vec(), 30),
        )),
    };
    let content = tw::versioned(typed.encode_to_vec(), 30);
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, &content));
    let signature = key.sign_bytes(&hash);
    let sequencers = RecipientsTree {
        recipients: vec![SEQUENCER_GROUP.to_string()],
        children: Vec::new(),
    };
    // the member is the root, so that it can see that the sequencers were addressed too
    let tree = if request.address_member {
        RecipientsTree {
            recipients: vec![request.member.to_string()],
            children: vec![sequencers],
        }
    } else {
        sequencers
    };
    let plain = tw::versioned(
        SubmissionRequest {
            sender: request.sender.to_string(),
            message_id: request.message_id.to_string(),
            batch: Some(sw::compressed_batch_recipient_trees(&[(
                vec![tree],
                content,
                vec![signature],
            )])),
            max_sequencing_time: request.max_sequencing_time,
            // `AggregationRule.activeSequencers`: the sequencer group, its threshold applies (the wire's is ignored)
            aggregation_rule: Some(AggregationRule {
                eligible_members: vec![SEQUENCER_GROUP.to_string()],
                threshold: 0,
            }),
            submission_cost: None,
        }
        .encode_to_vec(),
        sw::SUBMISSION_REQUEST_VERSION,
    );
    sw::signed_submission_request(plain, key)
}

/// The purchase an envelope carries, when it is one for `physical`.
fn purchased(content: &[u8], physical: &str) -> Option<SetTrafficPurchasedMessage> {
    let (typed, _) = tw::unversioned(content)?;
    let Some(SomeSignedProtocolMessage::SetTrafficPurchased(bytes)) =
        TypedSignedProtocolMessageContent::decode(typed.as_slice())
            .ok()?
            .some_signed_protocol_message
    else {
        return None;
    };
    let (data, _) = tw::unversioned(&bytes)?;
    let message = SetTrafficPurchasedMessage::decode(data.as_slice()).ok()?;
    (message.physical_synchronizer_id == physical).then_some(message)
}

/// The maximum sequencing times a purchase is submitted with at `now` (`computeMaxSequencingTimes`): the end of the current window, and the
/// end of the next one too in the last quarter of a window.
fn max_sequencing_times(window_micros: i64, now: i64) -> Vec<i64> {
    let window = window_micros.max(1);
    let upper = (now / window + 1) * window;
    if upper - now <= window / 4 {
        vec![upper, upper + window]
    } else {
        vec![upper]
    }
}

impl Sequencer {
    /// A purchase of extra traffic for `member`: submitted as a sequenced message (see the module), so it counts from its sequencing time.
    pub fn purchase_traffic(&self, member: &str, serial: u32, total: u64) -> Result<(), Status> {
        let now = wall_micros();
        let Some(params) = self.inner.store.traffic_at(now) else {
            return Err(Status::not_found(
                "TRAFFIC_CONTROL_DISABLED(11,00000000): TrafficControlDisabled",
            ));
        };
        if let Some(last) = self
            .inner
            .traffic
            .last_serial(member)
            .filter(|last| serial <= *last)
        {
            return Err(Status::not_found(format!(
                "TRAFFIC_CONTROL_SERIAL_TOO_LOW(11,00000000): The provided serial value {serial} is too low. Latest serial used by this member is Some({last})"
            )));
        }
        let sender = self.own_member(now).ok_or_else(|| {
            Status::internal("this sequencer is not in the sequencer group in force")
        })?;
        let address_member = self.inner.registry.is_registered(member);
        let mut failure = None;
        let mut sent = false;
        for (index, max_sequencing_time) in
            max_sequencing_times(params.submission_window_micros, now)
                .into_iter()
                .enumerate()
        {
            let message_id = format!("traffic-purchase-{serial}-{now}-{index}");
            let signed = purchase_submission(
                &PurchaseRequest {
                    sender: &sender,
                    physical_synchronizer_id: &self.inner.physical_synchronizer_id,
                    member,
                    address_member,
                    serial,
                    total,
                    max_sequencing_time,
                    message_id: &message_id,
                },
                &self.inner.keys.sequencer_signing,
            );
            match self.submit_own(&sender, &signed) {
                Ok(()) => sent = true,
                Err(why) => failure = Some(why),
            }
        }
        match (sent, failure) {
            (false, Some(why)) => Err(Status::not_found(format!(
                "TRAFFIC_CONTROL_TOP_UP_SUBMISSION_FAILED(11,00000000): {}",
                why.message()
            ))),
            _ => Ok(()),
        }
    }

    /// This sequencer's member: the one it was told, or the sequencer of the group in force whose key mapping lists its signing key.
    fn own_member(&self, at: i64) -> Option<String> {
        if let Some(member) = self.inner.self_member.get() {
            return Some(member.clone());
        }
        let (_, active) = self.inner.store.sequencer_group_at(at)?;
        let own = &self.inner.keys.sequencer_signing.fingerprint;
        active
            .into_iter()
            .map(|uid| format!("SEQ::{uid}"))
            .find(|member| {
                self.inner
                    .store
                    .signing_keys_of(member)
                    .is_some_and(|keys| keys.iter().any(|k| &k.id == own))
            })
    }

    /// Hands a request of this sequencer's own to the order: the orderer decides its place in BFT mode, it is sequenced now otherwise.
    fn submit_own(&self, sender: &str, signed: &[u8]) -> Result<(), Status> {
        if self.is_observer() {
            let orderer = self
                .inner
                .orderer
                .get()
                .ok_or_else(|| Status::unavailable("there is no orderer to give it to"))?;
            return orderer(sender, signed).map_err(overloaded);
        }
        match self.inner.ordering.get() {
            Some(ordering) => {
                ordering.order(sender, signed);
                Ok(())
            }
            None => self.sequence_submission(sender, signed, None),
        }
    }

    /// Applies the purchases a delivered submission of a sequencer carries to the sequencer group, at its sequencing time `timestamp`.
    ///
    /// [CANTON-NOTE: WHY] The sequencer group's aggregation rule is what makes the group's threshold of sequencers sign it (each contribution's
    /// envelope signature was checked against its sender), which is what `TrafficControlProcessor.validateSetTrafficPurchased` checks.
    pub(super) fn apply_purchases(&self, submission: &Submission, member: &str, timestamp: i64) {
        let by_group = submission
            .aggregation_rule
            .as_ref()
            .is_some_and(|rule| rule.eligible_members == [SEQUENCER_GROUP]);
        if !member.starts_with("SEQ::") || !by_group {
            return;
        }
        let Some(params) = self.inner.store.traffic_at(timestamp) else {
            return;
        };
        for (trees, envelope) in submission.recipients.iter().zip(&submission.envelopes) {
            if !trees.iter().flatten().any(|a| a == SEQUENCER_GROUP) {
                continue;
            }
            let Some(message) = purchased(&envelope.content, &self.inner.physical_synchronizer_id)
            else {
                continue;
            };
            match self.inner.traffic.purchase(
                &message.member,
                message.serial,
                message.total_traffic_purchased,
                timestamp,
                &params,
            ) {
                Ok(()) => {
                    crate::diag::diag_eprintln!(
                        "TRAFFIC {} purchased {} (serial {}) at {timestamp}",
                        message.member,
                        message.total_traffic_purchased,
                        message.serial
                    );
                    self.journal_traffic(&message.member);
                }
                Err(last) => crate::diag::diag_eprintln!(
                    "TRAFFIC ignored the purchase of {} with serial {}: the latest is {last}",
                    message.member,
                    message.serial
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::max_sequencing_times;

    #[test]
    fn a_purchase_late_in_a_window_is_also_sent_for_the_next_one() {
        let window = 120_000_000;
        assert_eq!(max_sequencing_times(window, 10_000_000), vec![window]);
        assert_eq!(
            max_sequencing_times(window, window - 1_000_000),
            vec![window, 2 * window]
        );
    }
}
