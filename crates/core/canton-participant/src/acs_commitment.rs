//! The ACS commitment a participant receives (G5 5.7b, S-NET-028): the message `AcsCommitmentProtocolMessage` in an envelope of the
//! participant's event stream, decoded.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on Canton 3.7.2: a participant sends its commitments **when a ledger event crosses a
//! reconciliation boundary** (a checkpoint is made by the first event after `...:00` of an interval; with an interval of 60 s and
//! no event after the boundary nothing is sent, however long one waits) and about 20 s after that event. The message is a v32
//! `AcsCommitmentProtocolMessage { acs_commitment (versioned `AcsCommitment`), signature }`; the commitment names the sender, the
//! counterparticipant, the period `(from_exclusive, to_inclusive]` and the digest ([`crate::lthash::commitment_digest`]).
use crate::topology_wire::unversioned;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v32::{
    envelope_content::SomeEnvelopeContent, AcsCommitment, EnvelopeContent,
};
use prost::Message;
use std::collections::BTreeMap;

/// A decoded commitment message.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedCommitment {
    pub physical_synchronizer_id: String,
    pub sender: String,
    pub counterparticipant: String,
    pub from_exclusive: i64,
    pub to_inclusive: i64,
    /// The digest as sent (the multihash of the hashed set digest).
    pub digest: Vec<u8>,
    /// The bytes the signature covers' source: the versioned `AcsCommitment` as carried.
    pub commitment_bytes: Vec<u8>,
    pub signature: Option<Signature>,
}

/// The commitment an envelope carries (`None` if the envelope is something else or does not decode).
pub fn decode(envelope_content: &[u8]) -> Option<ReceivedCommitment> {
    let (data, _) = unversioned(envelope_content)?;
    let SomeEnvelopeContent::AcsCommitmentProtocolMessage(m) =
        EnvelopeContent::decode(data.as_slice())
            .ok()?
            .some_envelope_content?
    else {
        return None;
    };
    let (inner, _) = unversioned(&m.acs_commitment)?;
    let c = AcsCommitment::decode(inner.as_slice()).ok()?;
    let period = c.period?;
    Some(ReceivedCommitment {
        physical_synchronizer_id: c.physical_synchronizer_id,
        sender: c.sending_participant_uid,
        counterparticipant: c.counterparticipant_uid,
        from_exclusive: period.from_exclusive,
        to_inclusive: period.to_inclusive,
        digest: c.digest,
        commitment_bytes: m.acs_commitment,
        signature: m.signature,
    })
}

/// The period `(from_exclusive, to_inclusive]` of the commitment for a shared-contract change **sequenced at `change_time`**, with a
/// reconciliation interval of `interval_micros`.
///
/// [CANTON-NOTE: SEMANTICS] Measured on Canton 3.7.2: a participant's digest for a counterparticipant is stamped with the
/// sequencing time of the **request** that last changed it (not the verdict's), the period starts **just before** that stamp
/// (`immediatePredecessor`: one microsecond), and it ends on the **first reconciliation boundary after it** (a multiple of the
/// interval since the epoch). p1's periods were equal to this on the creation of a shared contract.
pub fn period_after(change_time: i64, interval_micros: i64) -> (i64, i64) {
    (
        change_time - 1,
        (change_time.div_euclid(interval_micros) + 1) * interval_micros,
    )
}

/// The version of the `AcsCommitment` wrapper and of the envelope content (protocol version 37 writes both as 32).
pub const MESSAGE_VERSION: i32 = 32;

/// The hash a commitment is signed over: `HashPurpose.AcsCommitment` (22) over the versioned `AcsCommitment` bytes, as a multihash.
pub fn signing_hash(commitment_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend(canton_algo::hash::sha256_with_purpose(22, commitment_bytes));
    out
}

/// The envelope content of a commitment message: the versioned `AcsCommitment` and the sender's signature over it.
pub fn commitment_message(
    physical_synchronizer_id: &str,
    sender_uid: &str,
    counterparticipant_uid: &str,
    from_exclusive: i64,
    to_inclusive: i64,
    digest: &[u8],
    signing_key: &crate::topology_wire::Ed25519Key,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v32::AcsCommitmentProtocolMessage;
    use canton_proto::com::digitalasset::canton::protocol::v32::CommitmentPeriod;
    let commitment = crate::topology_wire::versioned(
        AcsCommitment {
            physical_synchronizer_id: physical_synchronizer_id.to_string(),
            sending_participant_uid: sender_uid.to_string(),
            counterparticipant_uid: counterparticipant_uid.to_string(),
            period: Some(CommitmentPeriod {
                from_exclusive,
                to_inclusive,
            }),
            digest: digest.to_vec(),
        }
        .encode_to_vec(),
        MESSAGE_VERSION,
    );
    let signature = signing_key.sign_bytes(&signing_hash(&commitment));
    crate::topology_wire::versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::AcsCommitmentProtocolMessage(
                AcsCommitmentProtocolMessage {
                    acs_commitment: commitment,
                    signature: Some(signature),
                },
            )),
        }
        .encode_to_vec(),
        MESSAGE_VERSION,
    )
}

/// Comparison state for one counter-participant's ACS commitment at one tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeriodVerdict {
    Pending,
    Matched,
    Mismatched { local: [u8; 32], remote: [u8; 32] },
}

#[derive(Debug, Clone, Default)]
struct PeriodSlot {
    local: Option<[u8; 32]>,
    remote: Option<[u8; 32]>,
}

/// Where the comparison of one counter-participant's commitment for one tick stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodStatus {
    pub counter_participant: String,
    pub to_inclusive: i64,
    pub verdict: PeriodVerdict,
}

impl PeriodSlot {
    fn verdict(&self) -> PeriodVerdict {
        match (self.local, self.remote) {
            (Some(l), Some(r)) if l == r => PeriodVerdict::Matched,
            (Some(l), Some(r)) => PeriodVerdict::Mismatched {
                local: l,
                remote: r,
            },
            _ => PeriodVerdict::Pending,
        }
    }
}

fn extract_digest32(raw: &[u8]) -> Result<[u8; 32], String> {
    if raw.len() == 34 && raw[0] == 0x12 && raw[1] == 0x20 {
        raw[2..34]
            .try_into()
            .map_err(|_| "invalid SHA-256 multihash commitment digest".to_string())
    } else if raw.len() == 32 {
        raw.try_into()
            .map_err(|_| "invalid 32-byte commitment digest".to_string())
    } else {
        Err(format!(
            "unexpected commitment digest length {} (expected 32 raw or 34 SHA-256 multihash bytes)",
            raw.len()
        ))
    }
}

/// Tracks local and remote ACS commitments across consecutive reconciliation periods and counter-participants (U-20).
#[derive(Debug, Default)]
pub struct AcsCommitmentTracker {
    /// Keyed by `(counter_participant, to_inclusive)`.
    ///
    /// [CANTON-NOTE: SEMANTICS] The two sides compare the digests **at the tick**, whatever start each gave its period:
    /// `ReceivedAcsCommitmentMatcher` matches a received period against the local periods it overlaps, not against one with the same
    /// start. A start is the last change of the shared set as each side saw it, which a hosting change can move on one side only.
    periods: BTreeMap<(String, i64), PeriodSlot>,
    /// Tracks the latest `to_inclusive` recorded locally per counter-participant for contiguity checks.
    local_watermarks: BTreeMap<String, i64>,
}

impl AcsCommitmentTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the locally computed 32-byte commitment digest for `(counter_participant, from_exclusive, to_inclusive)`.
    /// Enforces `from_exclusive < to_inclusive` and, per peer, a commitment tick (`to_inclusive`) later than the last one.
    ///
    /// [CANTON-NOTE: SEMANTICS] A period does **not** start where the last one ended: it runs from just before the last change of the set
    /// shared with that peer to the commitment tick (`AcsCommitmentSender.commitmentFromDigest`: `fromExclusive =
    /// digest.timestamp.immediatePredecessor`, `toInclusive` = the tick). While nothing changes, the periods of consecutive ticks share
    /// their start (measured, S-G11-001: p1 sent `(t, 360 s]` and then `(t, 420 s]` for the same contract). The old rule
    /// `from_exclusive == previous to_inclusive` refused the official participant's commitments.
    pub fn record_local(
        &mut self,
        counter_participant: &str,
        from_exclusive: i64,
        to_inclusive: i64,
        digest: [u8; 32],
    ) -> Result<PeriodVerdict, String> {
        if from_exclusive >= to_inclusive {
            return Err(format!(
                "invalid commitment period [{from_exclusive}, {to_inclusive}]: from_exclusive must be < to_inclusive"
            ));
        }
        if let Some(&prev_to) = self.local_watermarks.get(counter_participant) {
            if to_inclusive <= prev_to {
                return Err(format!(
                    "commitment period for {counter_participant} ends at {to_inclusive}, not after the last tick {prev_to}"
                ));
            }
        }
        self.local_watermarks
            .insert(counter_participant.to_string(), to_inclusive);
        let slot = self
            .periods
            .entry((counter_participant.to_string(), to_inclusive))
            .or_default();
        slot.local = Some(digest);
        Ok(slot.verdict())
    }

    /// Decodes, domain-checks, and verifies (with one of `sender_keys`, the sender's signing keys) a signed incoming
    /// `AcsCommitmentProtocolMessage` envelope, recording the remote digest even if it arrives before the local calculation finishes.
    pub fn receive_signed(
        &mut self,
        envelope: &[u8],
        expected_domain: &str,
        sender_keys: &[canton_algo::signing::PublicKey],
    ) -> Result<PeriodVerdict, String> {
        let msg = decode(envelope)
            .ok_or_else(|| "envelope does not contain a valid AcsCommitment".to_string())?;
        if msg.physical_synchronizer_id != expected_domain {
            return Err(format!(
                "commitment synchronizer mismatch: expected {expected_domain}, got {}",
                msg.physical_synchronizer_id
            ));
        }
        if msg.from_exclusive >= msg.to_inclusive {
            return Err(format!(
                "invalid remote commitment period [{}, {}]",
                msg.from_exclusive, msg.to_inclusive
            ));
        }
        let sig_proto = msg
            .signature
            .as_ref()
            .ok_or_else(|| "ACS commitment message has no signature".to_string())?;
        let hash = signing_hash(&msg.commitment_bytes);
        // [CANTON-NOTE: SEMANTICS] `checkCommitmentSignature` verifies at the snapshot of `period.toInclusive`, which also follows a session
        // key the sender delegated to (`SyncCryptoVerifier`).
        canton_algo::member_signature::verify_by_keys_at(
            sender_keys,
            &hash,
            sig_proto,
            &canton_algo::member_signature::protocol_only(),
            &canton_algo::member_signature::DelegationScope {
                synchronizer_id: canton_algo::member_signature::logical_synchronizer_id(
                    expected_domain,
                ),
                at_micros: msg.to_inclusive,
            },
        )
        .map_err(|e| format!("ACS commitment signature verification failed: {e}"))?;

        let remote_digest = extract_digest32(&msg.digest)?;
        let slot = self
            .periods
            .entry((msg.sender.clone(), msg.to_inclusive))
            .or_default();
        slot.remote = Some(remote_digest);
        Ok(slot.verdict())
    }

    /// Every period compared so far, by counter-participant and tick.
    pub fn periods(&self) -> Vec<PeriodStatus> {
        self.periods
            .iter()
            .map(|((counter_participant, to_inclusive), slot)| PeriodStatus {
                counter_participant: counter_participant.clone(),
                to_inclusive: *to_inclusive,
                verdict: slot.verdict(),
            })
            .collect()
    }

    /// Returns the greatest `to_inclusive` timestamp at which at least one period exists and every tracked
    /// period up to and including that timestamp across all counter-participants has verdict `Matched`.
    pub fn safe_to_prune_timestamp(&self) -> Option<i64> {
        if self.periods.is_empty() {
            return None;
        }
        let mut timestamps: Vec<i64> = self.periods.keys().map(|(_, to)| *to).collect();
        timestamps.sort_unstable();
        timestamps.dedup();
        let mut safe = None;
        for ts in timestamps {
            let all_matched = self
                .periods
                .iter()
                .filter(|((_, to), _)| *to <= ts)
                .all(|(_, slot)| slot.verdict() == PeriodVerdict::Matched);
            if all_matched {
                safe = Some(ts);
            } else {
                break;
            }
        }
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commitment_message_decodes_to_what_was_put_in() {
        let key = crate::topology_wire::Ed25519Key::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        );
        let message = commitment_message("sync", "a::fp", "b::fp", 10, 20, &[1, 2, 3], &key);
        let got = decode(&message).expect("a commitment");
        assert_eq!(
            (
                got.sender.as_str(),
                got.counterparticipant.as_str(),
                got.from_exclusive,
                got.to_inclusive,
                got.digest.as_slice()
            ),
            ("a::fp", "b::fp", 10, 20, &[1u8, 2, 3][..])
        );
        assert_eq!(got.signature.expect("signed").signed_by, key.fingerprint);
    }

    #[test]
    fn the_period_starts_before_the_change_and_ends_on_the_next_boundary() {
        assert_eq!(
            period_after(1_000_000_000_000_001, 60_000_000),
            (1_000_000_000_000_000, 1_000_000_020_000_000)
        );
        // a change exactly on a boundary belongs to the period after it
        assert_eq!(
            period_after(120_000_000, 60_000_000),
            (119_999_999, 180_000_000)
        );
    }

    #[test]
    fn an_envelope_that_is_not_a_commitment_is_not_taken_for_one() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[1, 2, 3]), None);
    }

    #[test]
    fn tracker_handles_multi_period_in_order_and_out_of_order_and_blocks_prune_on_mismatch() {
        let sender_key = crate::topology_wire::Ed25519Key::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        );
        let pubkey =
            vec![canton_algo::member_signature::own_ed25519_key(&sender_key.spki_der).unwrap()];
        let d1 = [1u8; 32];
        let d2 = [2u8; 32];
        let d3 = [3u8; 32];
        let bad = [9u8; 32];
        let multihash = |d: &[u8; 32]| {
            let mut v = vec![0x12, 0x20];
            v.extend_from_slice(d);
            v
        };

        let mut tracker = AcsCommitmentTracker::new();
        assert_eq!(tracker.safe_to_prune_timestamp(), None);

        // Period 1: local recorded first -> Pending; remote arrives (multihash) -> Matched.
        assert_eq!(
            tracker.record_local("p2::fp", 0, 60_000_000, d1).unwrap(),
            PeriodVerdict::Pending
        );
        assert_eq!(tracker.safe_to_prune_timestamp(), None);
        let env1 = commitment_message(
            "sync::1::0",
            "p2::fp",
            "p1::fp",
            0,
            60_000_000,
            &multihash(&d1),
            &sender_key,
        );
        assert_eq!(
            tracker
                .receive_signed(&env1, "sync::1::0", &pubkey)
                .unwrap(),
            PeriodVerdict::Matched
        );
        assert_eq!(tracker.safe_to_prune_timestamp(), Some(60_000_000));

        // Period 2: remote arrives BEFORE local -> Pending, then local matches -> safe watermark moves to 120s.
        let env2 = commitment_message(
            "sync::1::0",
            "p2::fp",
            "p1::fp",
            60_000_000,
            120_000_000,
            &d2,
            &sender_key,
        );
        assert_eq!(
            tracker
                .receive_signed(&env2, "sync::1::0", &pubkey)
                .unwrap(),
            PeriodVerdict::Pending
        );
        assert_eq!(tracker.safe_to_prune_timestamp(), Some(60_000_000));
        assert_eq!(
            tracker
                .record_local("p2::fp", 60_000_000, 120_000_000, d2)
                .unwrap(),
            PeriodVerdict::Matched
        );
        assert_eq!(tracker.safe_to_prune_timestamp(), Some(120_000_000));

        // Period 3: mismatch halts pruning at 120_000_000.
        assert_eq!(
            tracker
                .record_local("p2::fp", 120_000_000, 180_000_000, d3)
                .unwrap(),
            PeriodVerdict::Pending
        );
        let env3 = commitment_message(
            "sync::1::0",
            "p2::fp",
            "p1::fp",
            120_000_000,
            180_000_000,
            &multihash(&bad),
            &sender_key,
        );
        assert_eq!(
            tracker
                .receive_signed(&env3, "sync::1::0", &pubkey)
                .unwrap(),
            PeriodVerdict::Mismatched {
                local: d3,
                remote: bad,
            }
        );
        assert_eq!(tracker.safe_to_prune_timestamp(), Some(120_000_000));

        // Wrong domain and corrupted signature are both rejected.
        assert!(tracker
            .receive_signed(&env1, "other-sync::1::0", &pubkey)
            .is_err());
        let mut tampered = env1.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(tracker
            .receive_signed(&tampered, "sync::1::0", &pubkey)
            .is_err());
        // A tick that does not advance is rejected; a period that starts at an earlier change (overlapping the last ones) is the
        // official participant's shape and is accepted.
        assert!(tracker
            .record_local("p2::fp", 100_000_000, 180_000_000, d1)
            .is_err());
        assert!(tracker
            .record_local("p2::fp", 130_000_000, 170_000_000, d1)
            .is_err());
        assert!(tracker
            .record_local("p2::fp", 30_000_000, 240_000_000, d1)
            .is_ok());
    }

    /// C-4: a commitment signed by a session key the sender's long-term key delegated to, for a period that covers the commitment's end,
    /// is the sender's (`AcsCommitmentProcessor.checkCommitmentSignature` at `period.toInclusive`); outside the period it is not.
    #[test]
    fn a_commitment_signed_by_a_delegated_session_key_is_the_senders() {
        use canton_proto::com::digitalasset::canton::crypto::v30::{
            Signature, SignatureDelegation,
        };
        use ed25519_dalek::Signer;
        let long_term = crate::topology_wire::Ed25519Key::from_seed([41; 32]);
        let key = canton_algo::member_signature::own_ed25519_key(&long_term.spki_der).unwrap();
        let session = crate::topology_wire::Ed25519Key::from_seed([42; 32]);
        let session_signing = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let delegated = |valid_from: i64| -> Vec<u8> {
            let plain = commitment_message(
                "sync::1220aa::37-0",
                "p2::fp",
                "p1::fp",
                0,
                60_000_000,
                &[[0x12, 0x20].as_slice(), &[1; 32]].concat(),
                &long_term,
            );
            let (inner, version) = crate::topology_wire::unversioned(&plain).unwrap();
            let mut content = EnvelopeContent::decode(inner.as_slice()).unwrap();
            let Some(SomeEnvelopeContent::AcsCommitmentProtocolMessage(m)) =
                content.some_envelope_content.as_mut()
            else {
                panic!("a commitment")
            };
            let mut delegation = SignatureDelegation {
                session_key: session.spki_der.clone(),
                session_key_spec: 1,
                validity_period_from_inclusive: valid_from,
                validity_period_duration_seconds: 120,
                format: 3,
                signing_algorithm_spec: 1,
                signature: Vec::new(),
            };
            let unsigned = Signature {
                format: 3,
                signing_algorithm_spec: 1,
                signature: Vec::new(),
                signed_by: key.id.clone(),
                signature_delegation: Some(delegation.clone()),
            };
            let parsed = canton_algo::member_signature::signature_from_proto(&unsigned).unwrap();
            let to_authorize = canton_algo::signature_delegation::delegation_hash(
                "sync::1220aa",
                parsed.delegation.as_ref().unwrap(),
            )
            .unwrap();
            delegation.signature = long_term.sign_bytes(&to_authorize).signature;
            m.signature = Some(Signature {
                signature: session_signing
                    .sign(&signing_hash(&m.acs_commitment))
                    .to_bytes()
                    .to_vec(),
                signature_delegation: Some(delegation),
                ..unsigned
            });
            crate::topology_wire::versioned(content.encode_to_vec(), version)
        };
        let keys = std::slice::from_ref(&key);
        let mut tracker = AcsCommitmentTracker::new();
        let accepted = tracker.receive_signed(&delegated(0), "sync::1220aa::37-0", keys);
        assert!(accepted.is_ok(), "{accepted:?}");
        assert!(tracker
            .receive_signed(&delegated(70_000_000), "sync::1220aa::37-0", keys)
            .is_err());
    }
}
