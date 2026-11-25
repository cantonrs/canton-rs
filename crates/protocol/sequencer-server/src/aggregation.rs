//! Aggregated submissions (`InFlightAggregations`): a request that carries an aggregation rule is delivered once enough eligible senders have
//! sent the same request; until its maximum sequencing time passes the sequencer remembers who contributed, so that a later request of the
//! same aggregation is refused, also after a restart.
//!
//! [CANTON-NOTE: SEMANTICS] Read from `InFlightAggregationHandler`, `InFlightAggregation` and `AggregationRule` (3.7.2):
//! - the rule's input is a mediator group (`MGR::<index>`), the sequencer group (`SOD::`) or the empty list (the sender's own requests
//!   are deduplicated); the wire threshold is ignored and the group's threshold applies;
//! - an aggregation is dropped once the sequencing time reaches its maximum sequencing time (`InFlightAggregation.expired`:
//!   `timestamp >= maxSequencingTimestamp`; `InFlightAggregations.cleanExpired`).
use canton_participant::topology_state::MediatorGroup;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v31::EnvelopeWithoutRecipients;
use prost::Message;
use std::collections::BTreeMap;

/// A group whose members may send a rule's aggregation, with how many of them complete it.
pub(crate) struct Group<'a> {
    pub(crate) threshold: u32,
    /// The active members' uids (without the member prefix).
    pub(crate) active: &'a [String],
}

/// What the rule needs to know of the topology at the sequencing time.
pub(crate) struct RuleTopology<'a> {
    pub(crate) mediator_groups: &'a BTreeMap<u32, MediatorGroup>,
    pub(crate) sequencer_group: Option<Group<'a>>,
}

/// How many eligible senders complete an aggregation under `rule`, or why `sender` may not contribute to it
/// (`InFlightAggregationHandler.senderIsAuthorizedAndAggregationRuleIsWellFormed`).
pub(crate) fn threshold(
    rule: &AggregationRule,
    sender: &str,
    topology: &RuleTopology,
) -> Result<usize, String> {
    let uid = sender.split_once("::").map_or("", |(_, uid)| uid);
    match rule.eligible_members.as_slice() {
        [] => Ok(1),
        [group] if group.starts_with("MGR::") => {
            let index = group.trim_start_matches("MGR::");
            let found = index
                .parse::<u32>()
                .ok()
                .and_then(|g| topology.mediator_groups.get(&g));
            let Some(found) = found else {
                return Err(format!(
                    "Invalid aggregation rule with mediator index {index} as there is no such mediator group"
                ));
            };
            if sender.starts_with("MED::") && found.active.iter().any(|m| m == uid) {
                Ok(found.threshold.max(1) as usize)
            } else {
                Err(format!(
                    "Sender [{sender}] is not part of the mediator group with index {index}"
                ))
            }
        }
        [group] if group == SEQUENCER_GROUP => {
            let Some(found) = &topology.sequencer_group else {
                return Err(
                    "Invalid sequencer aggregation rule as there is no sequencer group".to_string(),
                );
            };
            if sender.starts_with("SEQ::") && found.active.iter().any(|m| m == uid) {
                Ok(found.threshold.max(1) as usize)
            } else {
                Err(format!(
                    "Sender [{sender}] is not part of the sequencer group"
                ))
            }
        }
        // [CANTON-NOTE: SEMANTICS] 3.7.2 parses only the three inputs above (`AggregationRule.fromProtoV30`): a rule that lists members is
        // not one it reads.
        _ => Err(format!(
            "Unsupported eligible members {:?}: only a mediator group, the sequencer group or none",
            rule.eligible_members
        )),
    }
}

/// `SequencersOfSynchronizer` as a recipient and as a rule's input.
pub(crate) const SEQUENCER_GROUP: &str = "SOD::";

/// `SubmissionRequest.aggregationId` for protocol version 37 (`HashPurpose.AggregationId`): the number of envelopes, for each its content and
/// recipients (each with a four-byte length in front, as `DeterministicEncoding.encodeBytes` has it) and one byte for whether it is signed, the
/// maximum sequencing time, and the rule's own part (`AggregationRuleInput.appendForAggregationId`: a magic number, and the index of the
/// mediator group or the sender's id).
pub(crate) fn aggregation_id(
    envelopes: &[EnvelopeWithoutRecipients],
    recipient_protos: &[Vec<u8>],
    max_sequencing_time: i64,
    rule: &AggregationRule,
    sender: &str,
) -> Option<[u8; 32]> {
    let purpose = canton_algo::purpose_by_description("AggregationId")?.id;
    let mut h = canton_algo::PurposeHash::new(purpose);
    let encode_bytes = |b: &[u8]| {
        let mut out = (b.len() as i32).to_be_bytes().to_vec();
        out.extend_from_slice(b);
        out
    };
    h.add_int(envelopes.len() as i32).ok()?;
    for (i, envelope) in envelopes.iter().enumerate() {
        h.add_byte_string(&encode_bytes(&envelope.content)).ok()?;
        h.add_byte_string(&encode_bytes(
            recipient_protos.get(i).map_or(&[][..], |v| &v[..]),
        ))
        .ok()?;
        h.add_byte_string(&[u8::from(!envelope.signatures.is_empty())])
            .ok()?;
    }
    h.add_long(max_sequencing_time).ok()?;
    match rule.eligible_members.as_slice() {
        [group] if group.starts_with("MGR::") => {
            h.add_int(0x01).ok()?;
            h.add_int(group.trim_start_matches("MGR::").parse::<i32>().ok()?)
                .ok()?;
        }
        [group] if group == SEQUENCER_GROUP => {
            h.add_int(0x02).ok()?;
        }
        _ => {
            h.add_int(0x03).ok()?;
            h.add_string(sender).ok()?;
        }
    }
    h.finish().ok()
}

/// What the sequencer knows of one aggregation.
struct InFlight {
    max_sequencing_time: i64,
    /// The senders that have contributed (in the order of the member names, as `SortedMap[Member, AggregationBySender]`), each with the
    /// signatures it put on each envelope.
    senders: BTreeMap<String, Vec<Vec<Signature>>>,
    delivered_at: Option<i64>,
}

/// What became of a contribution.
pub(crate) enum Contribution {
    /// Below the threshold: the sender gets its receipt, nobody else anything yet.
    Pending,
    /// The threshold is reached: the envelopes are delivered with the signatures of every sender so far, per envelope.
    Delivered(Vec<Vec<Signature>>),
    /// The aggregation was delivered before (at that time).
    AlreadyDelivered { at: i64 },
    /// The sender contributed before.
    Stubborn,
}

/// The aggregations in flight, by aggregation id.
#[derive(Default)]
pub(crate) struct Aggregations {
    by_id: BTreeMap<[u8; 32], InFlight>,
}

impl Aggregations {
    /// Forgets the aggregations whose maximum sequencing time is before `at`: no request of theirs can be sequenced any more.
    ///
    /// [CANTON-NOTE: WHY] Before, not at: a request sequenced exactly at its maximum sequencing time is still valid
    /// (`sequencingTimestamp <= maxSequencingTime`) and has to see the aggregation it joins. `BlockChunkProcessor` cleans with the time of
    /// the chunk before, which keeps those too.
    pub(crate) fn expire_before(&mut self, at: i64) {
        self.by_id.retain(|_, a| a.max_sequencing_time >= at);
    }

    /// `sender` contributes `signatures` (per envelope) at `at` to the aggregation `id` that `threshold` senders complete.
    pub(crate) fn contribute(
        &mut self,
        id: [u8; 32],
        max_sequencing_time: i64,
        sender: &str,
        signatures: Vec<Vec<Signature>>,
        threshold: usize,
        at: i64,
    ) -> Contribution {
        let entry = self.by_id.entry(id).or_insert_with(|| InFlight {
            max_sequencing_time,
            senders: BTreeMap::new(),
            delivered_at: None,
        });
        if let Some(at) = entry.delivered_at {
            return Contribution::AlreadyDelivered { at };
        }
        if entry.senders.contains_key(sender) {
            return Contribution::Stubborn;
        }
        entry.senders.insert(sender.to_string(), signatures);
        if entry.senders.len() < threshold {
            return Contribution::Pending;
        }
        entry.delivered_at = Some(at);
        // [CANTON-NOTE: SEMANTICS] The delivered envelopes carry the signatures of all the senders so far, ordered by sender, not by when
        // the requests were sequenced (`InFlightAggregation.aggregatedSignatures`).
        let envelopes = entry.senders.values().map(Vec::len).max().unwrap_or(0);
        Contribution::Delivered(
            (0..envelopes)
                .map(|i| {
                    entry
                        .senders
                        .values()
                        .flat_map(|per_envelope| per_envelope.get(i).cloned().unwrap_or_default())
                        .collect()
                })
                .collect(),
        )
    }

    /// Takes a journaled contribution back (see [`contribution_line`]).
    pub(crate) fn restore(&mut self, line: &str) -> Option<()> {
        let (id, max, sender, delivered_at, signatures) = decode_contribution(line)?;
        let entry = self.by_id.entry(id).or_insert_with(|| InFlight {
            max_sequencing_time: max,
            senders: BTreeMap::new(),
            delivered_at: None,
        });
        entry.senders.insert(sender, signatures);
        if delivered_at.is_some() {
            entry.delivered_at = delivered_at;
        }
        Some(())
    }
}

/// A contribution to an aggregation: `G <hex id> <max sequencing time> <sender> <delivered at|-> <signatures|->`, the signatures per envelope
/// comma separated and each envelope's hex signatures joined by `+`.
pub(crate) fn contribution_line(
    id: &[u8; 32],
    max_sequencing_time: i64,
    sender: &str,
    delivered_at: Option<i64>,
    signatures: &[Vec<Signature>],
) -> String {
    let signatures = if signatures.is_empty() {
        "-".to_string()
    } else {
        signatures
            .iter()
            .map(|per_envelope| {
                if per_envelope.is_empty() {
                    return UNSIGNED.to_string();
                }
                per_envelope
                    .iter()
                    .map(|s| crate::persistence::hex(&s.encode_to_vec()))
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "G {} {max_sequencing_time} {sender} {} {signatures}",
        crate::persistence::hex(id),
        delivered_at.map_or("-".to_string(), |t| t.to_string())
    )
}

/// An envelope without signatures in a contribution line (a line ends without blanks: the journal trims them).
const UNSIGNED: &str = "~";

type DecodedContribution = ([u8; 32], i64, String, Option<i64>, Vec<Vec<Signature>>);

fn decode_contribution(line: &str) -> Option<DecodedContribution> {
    let mut f = line.strip_prefix("G ")?.split(' ');
    let id = <[u8; 32]>::try_from(crate::persistence::unhex(f.next()?)?).ok()?;
    let max = f.next()?.parse().ok()?;
    let sender = f.next()?.to_string();
    let delivered_at = match f.next()? {
        "-" => None,
        t => Some(t.parse().ok()?),
    };
    let signatures = match f.next()? {
        "-" => Vec::new(),
        all => all
            .split(',')
            .map(|per_envelope| {
                per_envelope
                    .split('+')
                    .filter(|h| *h != UNSIGNED)
                    .map(|h| Signature::decode(crate::persistence::unhex(h)?.as_slice()).ok())
                    .collect::<Option<Vec<_>>>()
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some((id, max, sender, delivered_at, signatures))
}

/// The maximum sequencing time of a journaled contribution: the compaction drops the ones that expired.
pub(crate) fn contribution_expiry(line: &str) -> Option<i64> {
    decode_contribution(line).map(|(_, max, _, _, _)| max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_names_a_mediator_group_the_sequencer_group_or_nobody() {
        let groups = BTreeMap::from([(
            0,
            MediatorGroup {
                serial: 1,
                threshold: 2,
                active: vec!["m1::1220aa".into(), "m2::1220aa".into()],
                observers: vec!["m3::1220aa".into()],
            },
        )]);
        let sequencers = ["s1::1220cc".to_string()];
        let topology = RuleTopology {
            mediator_groups: &groups,
            sequencer_group: Some(Group {
                threshold: 1,
                active: &sequencers,
            }),
        };
        let rule = |eligible: &[&str]| AggregationRule {
            eligible_members: eligible.iter().map(|m| m.to_string()).collect(),
            threshold: 0,
        };
        assert_eq!(
            threshold(&rule(&["MGR::0"]), "MED::m2::1220aa", &topology),
            Ok(2),
            "the group's threshold, not the wire's"
        );
        assert!(threshold(&rule(&["MGR::0"]), "MED::m3::1220aa", &topology).is_err());
        assert!(threshold(&rule(&["MGR::0"]), "PAR::p::1220bb", &topology).is_err());
        assert!(threshold(&rule(&["MGR::1"]), "MED::m1::1220aa", &topology).is_err());
        assert_eq!(threshold(&rule(&[]), "PAR::p::1220bb", &topology), Ok(1));
        assert_eq!(
            threshold(&rule(&["SOD::"]), "SEQ::s1::1220cc", &topology),
            Ok(1)
        );
        assert!(
            threshold(&rule(&["SOD::"]), "SEQ::s2::1220cc", &topology).is_err(),
            "a sequencer outside the group"
        );
        assert!(threshold(&rule(&["SOD::"]), "PAR::p::1220bb", &topology).is_err());
        assert!(
            threshold(&rule(&["PAR::p::1220bb"]), "PAR::p::1220bb", &topology).is_err(),
            "a rule that lists members is not one 3.7.2 reads"
        );
        let none = RuleTopology {
            mediator_groups: &groups,
            sequencer_group: None,
        };
        assert!(threshold(&rule(&["SOD::"]), "SEQ::s1::1220cc", &none).is_err());
    }

    #[test]
    fn an_aggregation_expires_after_its_maximum_sequencing_time_and_survives_a_journal_round_trip()
    {
        let mut aggregations = Aggregations::default();
        let id = [7u8; 32];
        assert!(matches!(
            aggregations.contribute(id, 100, "MED::a::1", vec![Vec::new()], 2, 10),
            Contribution::Pending
        ));
        let line = contribution_line(&id, 100, "MED::a::1", None, &[Vec::new()]);
        let mut restored = Aggregations::default();
        restored.restore(&line).unwrap();
        assert!(
            matches!(
                restored.contribute(id, 100, "MED::a::1", vec![Vec::new()], 2, 20),
                Contribution::Stubborn
            ),
            "a restart remembers the contribution"
        );
        aggregations.expire_before(100);
        assert!(
            matches!(
                aggregations.contribute(id, 100, "MED::b::1", vec![Vec::new()], 2, 100),
                Contribution::Delivered(_)
            ),
            "at its maximum sequencing time the aggregation is still in flight"
        );
        aggregations.expire_before(101);
        assert!(
            matches!(
                aggregations.contribute(id, 100, "MED::c::1", vec![Vec::new()], 2, 101),
                Contribution::Pending
            ),
            "after it, the aggregation is forgotten"
        );
    }
}
