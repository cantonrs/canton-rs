//! The checks a participant runs on an event its sequencer delivers before it handles it (P-6): Canton's `SequencedEventValidatorImpl`
//! (`sequencing/client/SequencedEventValidator.scala`) as the sequencer client's `SubscriptionHandlerImpl` calls it.
//!
//! [CANTON-NOTE: SEMANTICS]
//! - An event after the last one handled (`validate`), in this order: its physical synchronizer id is this participant's
//!   (`BadSynchronizerId`); its `previous_timestamp` is the timestamp of the last event handled, `None` when there is none
//!   (`PreviousTimestampMismatch`); its timestamp is after that one (`NonIncreasingTimestamp`); it sets no timestamp of signing key and is
//!   signed by the sequencer with a key the topology at its timestamp gives that sequencer (`SignatureInvalid`). An event whose
//!   `previous_timestamp` is `None` is the start of a fresh subscription and its signature is not checked (`verifySignatureAndDecompress`:
//!   "Skipping signature verification of the first sequenced event due to a fresh subscription").
//! - The event at the timestamp of the last one handled (`validateOnReconnect`; a resubscription starts at that timestamp): the synchronizer
//!   id, then the signature, then its content must equal the content of the event handled (`ForkHappened`). It is not handled again.
//! - A refusal ends the subscription for good: `SubscriptionHandlerImpl` returns it as `EventValidationError`, the subscription closes with
//!   `HandlerError` and `SequencerSubscriptionWrapper.giveUp` calls `connection.fatal` instead of retrying. An event that does not parse ends it
//!   the same way (`deserializingSubscriptionHandler` fails, `HandlerException`, `giveUp`).
use crate::sequencing_wire::{decode_delivered, decompress, event_hash, Delivered};
use crate::topology_wire::unversioned;
use canton_algo::member_signature::{
    logical_synchronizer_id, protocol_only, verify_by_keys, verify_by_keys_at, DelegationScope,
};
use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v31::EnvelopeWithoutRecipients;
use canton_proto::com::digitalasset::canton::protocol::v32::{
    compressed_batch::DecompressedRecipients, SequencedEvent,
};
use prost::Message;
use sha2::{Digest, Sha256};

/// The last event a participant handled: what the next event follows, and what the first event of a resubscription must equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastEvent {
    pub timestamp_micros: i64,
    pub previous_timestamp_micros: Option<i64>,
    /// The digest of the event's content (see [`content_digest`]).
    pub content_digest: [u8; 32],
}

impl LastEvent {
    pub fn of(event: &Delivered) -> Self {
        LastEvent {
            timestamp_micros: event.timestamp_micros,
            previous_timestamp_micros: event.previous_timestamp_micros,
            content_digest: content_digest(&event.event_bytes),
        }
    }

    /// One line: `<timestamp> <previous timestamp, or -> <content digest, hex>`.
    pub fn record(&self) -> String {
        let previous = self
            .previous_timestamp_micros
            .map_or_else(|| "-".to_string(), |t| t.to_string());
        format!(
            "{} {previous} {}",
            self.timestamp_micros,
            hex::encode(self.content_digest)
        )
    }

    /// Reads back a [`LastEvent::record`] line.
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split_whitespace();
        let timestamp_micros = parts.next()?.parse().ok()?;
        let previous_timestamp_micros = match parts.next()? {
            "-" => None,
            t => Some(t.parse().ok()?),
        };
        let content_digest = hex::decode(parts.next()?).ok()?.try_into().ok()?;
        parts.next().is_none().then_some(LastEvent {
            timestamp_micros,
            previous_timestamp_micros,
            content_digest,
        })
    }
}

/// The stored cursor: the cursor alone, or the [`LastEvent::record`] of the event at it (one value, so that one write replaces both).
pub fn cursor_record(cursor: i64, last: Option<&LastEvent>) -> String {
    match last.filter(|last| last.timestamp_micros == cursor) {
        Some(last) => format!("{}\n", last.record()),
        None => format!("{cursor}\n"),
    }
}

/// Reads back a [`cursor_record`].
pub fn parse_cursor(text: &str) -> Option<(i64, Option<LastEvent>)> {
    let cursor = text.split_whitespace().next()?.parse().ok()?;
    Some((cursor, LastEvent::parse(text)))
}

/// What the next event is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prior {
    /// The last event handled.
    Event(LastEvent),
    /// No event handled: the participant reads the events after this time.
    ///
    /// [CANTON-NOTE: LIMITATION] Canton always starts from the member's first event or from the last event it stored. A runtime that is
    /// opened at a time (or rewound to one) does not know the event before it, so its first event only has to have no previous event or one
    /// at or before that time; from then on the chain is checked exactly.
    Time(i64),
}

/// Whose signature makes an event the sequencer's.
#[derive(Debug, Clone, Copy)]
pub enum SequencerTrust<'a> {
    /// The signing keys the topology in force at the event's timestamp gives the sequencer this participant is connected to (none when it
    /// names none).
    Keys(&'a [PublicKey]),
    /// [CANTON-NOTE: LIMITATION] A runtime configured by hand (`Config::follow_topology` unset) has no topology to read the sequencer's keys
    /// from: the signature is not checked. Every other check is.
    Unchecked,
}

/// Why an event was not handled. Each one ends the subscription.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("Unable to parse response from sequencer: the event does not decode (or one of its envelopes does not decompress)")]
    Undecodable,
    #[error("BadSynchronizerId(expected = {expected}, received = {received})")]
    BadSynchronizerId { expected: String, received: String },
    #[error("PreviousTimestampMismatch(received previous event timestamp = {received:?}, expected previous event timestamp = {expected:?})")]
    PreviousTimestampMismatch {
        received: Option<i64>,
        expected: Option<i64>,
    },
    #[error("PreviousTimestampMismatch(received previous event timestamp = {received}, expected one at or before {start}, where reading started)")]
    PreviousTimestampAfterStart { received: i64, start: i64 },
    #[error("NonIncreasingTimestamp(new timestamp = {new}, old timestamp = {old})")]
    NonIncreasingTimestamp { new: i64, old: i64 },
    #[error("TimestampOfSigningKeyNotAllowed(sequenced timestamp = {timestamp}, declared signing key timestamp = {declared})")]
    TimestampOfSigningKeyNotAllowed { timestamp: i64, declared: i64 },
    #[error("SignatureInvalid(sequenced timestamp = {timestamp}): {why}")]
    SignatureInvalid { timestamp: i64, why: String },
    #[error("ForkHappened(sequencing timestamp = {timestamp}): The sequencer responded with a different message for the same sequencing timestamp, which means the sequencer forked.")]
    ForkHappened { timestamp: i64 },
}

/// Why an event was not handled: refused (the subscription stops), or its handling failed.
#[derive(Debug, thiserror::Error)]
pub enum NotHandled {
    #[error(transparent)]
    Refused(#[from] Refusal),
    #[error("{0}")]
    Failed(String),
}

/// What the sequencer client keeps of a subscription (`SubscriptionHandlerImpl.priorEvent`), and whether it goes on.
#[derive(Debug)]
pub struct Subscription {
    last: Option<LastEvent>,
    /// The next subscription starts at the last event handled, to check it again.
    reconnecting: bool,
    halted: Option<Refusal>,
    /// The sequencer this participant is connected to (`SEQ::<uid>`): whose keys sign its events.
    sequencer: Option<String>,
}

impl Subscription {
    /// A subscription that resumes after `last` (a process that starts is reconnecting).
    pub fn resumed(last: Option<LastEvent>) -> Self {
        Subscription {
            last,
            reconnecting: true,
            halted: None,
            sequencer: None,
        }
    }

    pub fn last(&self) -> Option<&LastEvent> {
        self.last.as_ref()
    }

    /// `last` is now the last event handled (`None`: reading starts at a time again).
    pub fn handled(&mut self, last: Option<LastEvent>) {
        self.last = last;
    }

    pub fn sequencer(&self) -> Option<&str> {
        self.sequencer.as_deref()
    }

    pub fn connected_to(&mut self, sequencer_uid: &str) {
        self.sequencer = Some(format!("SEQ::{sequencer_uid}"));
    }

    /// Why the subscription stopped, once an event was refused.
    pub fn halted(&self) -> Option<&Refusal> {
        self.halted.as_ref()
    }

    /// The stream broke: the next subscription is a resubscription.
    pub fn broken(&mut self) {
        self.reconnecting = true;
    }

    /// Where the next subscription starts (inclusive).
    ///
    /// [CANTON-NOTE: SEMANTICS] A resubscription starts at the last event handled, which comes again and is checked against the one kept
    /// (`SubscriptionHandlerImpl`: "we actually subscribe from the event we last successfully processed").
    pub fn subscribe_from(&self, cursor: i64) -> i64 {
        match (&self.last, self.reconnecting) {
            (Some(last), true) => last.timestamp_micros,
            _ => cursor + 1,
        }
    }

    /// Decodes `raw` and makes the checks that need no topology. Returns the event and whether it is the last one handled, again
    /// (`isReplayOfPriorEvent`: same timestamp).
    pub fn admit(
        &mut self,
        raw: &[u8],
        cursor: i64,
        psid: &str,
    ) -> Result<(Delivered, bool), Refusal> {
        if let Some(refused) = &self.halted {
            return Err(refused.clone());
        }
        let admitted = decode_delivered(raw)
            .ok_or(Refusal::Undecodable)
            .and_then(|event| {
                let prior = match &self.last {
                    Some(last) if last.timestamp_micros == event.timestamp_micros => {
                        check_synchronizer_id(&event, psid)?;
                        return Ok((event, true));
                    }
                    Some(last) => Prior::Event(last.clone()),
                    None => Prior::Time(cursor),
                };
                check_order(&prior, &event, psid).map(|()| (event, false))
            });
        self.halt_on(admitted)
    }

    /// The checks that need the sequencer's keys in force at the event's timestamp (`None`: see [`SequencerTrust::Unchecked`]).
    pub fn authenticate(
        &mut self,
        event: &Delivered,
        replay: bool,
        psid: &str,
        keys: Option<&[PublicKey]>,
    ) -> Result<(), Refusal> {
        let trust = keys.map_or(SequencerTrust::Unchecked, SequencerTrust::Keys);
        let checked = match (&self.last, replay) {
            (Some(last), true) => check_replay(last, event, psid, trust),
            _ => check_signature(event, trust),
        };
        self.halt_on(checked)?;
        self.reconnecting = false;
        Ok(())
    }

    fn halt_on<T>(&mut self, result: Result<T, Refusal>) -> Result<T, Refusal> {
        if let Err(refused) = &result {
            self.halted = Some(refused.clone());
        }
        result
    }
}

/// The checks of an event after `prior` that need no topology: its synchronizer, its previous timestamp, its timestamp (`validate` up to the
/// signature).
pub fn check_order(prior: &Prior, event: &Delivered, psid: &str) -> Result<(), Refusal> {
    check_synchronizer_id(event, psid)?;
    let received = event.previous_timestamp_micros;
    let old = match prior {
        Prior::Event(last) => {
            if received != Some(last.timestamp_micros) {
                return Err(Refusal::PreviousTimestampMismatch {
                    received,
                    expected: Some(last.timestamp_micros),
                });
            }
            last.timestamp_micros
        }
        Prior::Time(start) => {
            if let Some(received) = received.filter(|t| t > start) {
                return Err(Refusal::PreviousTimestampAfterStart {
                    received,
                    start: *start,
                });
            }
            *start
        }
    };
    if event.timestamp_micros <= old {
        return Err(Refusal::NonIncreasingTimestamp {
            new: event.timestamp_micros,
            old,
        });
    }
    Ok(())
}

/// The signature check of `verifySignatureAndDecompress`, with `trust` read from the topology at the event's timestamp.
pub fn check_signature(event: &Delivered, trust: SequencerTrust<'_>) -> Result<(), Refusal> {
    if let Some(declared) = event.timestamp_of_signing_key_micros {
        return Err(Refusal::TimestampOfSigningKeyNotAllowed {
            timestamp: event.timestamp_micros,
            declared,
        });
    }
    if event.previous_timestamp_micros.is_none() {
        return Ok(());
    }
    let SequencerTrust::Keys(keys) = trust else {
        return Ok(());
    };
    // [CANTON-NOTE: SEMANTICS] `SignedContent.signature` is the last of the signatures.
    let Some(signature) = event.signatures.last() else {
        return Err(Refusal::SignatureInvalid {
            timestamp: event.timestamp_micros,
            why: "the event carries no signature".into(),
        });
    };
    if keys.is_empty() {
        return Err(Refusal::SignatureInvalid {
            timestamp: event.timestamp_micros,
            why: "the topology gives the sequencer no signing key".into(),
        });
    }
    if !verifies_at(
        keys,
        signature,
        &event_hash(&event.event_bytes),
        &event.physical_synchronizer_id,
        event.timestamp_micros,
    ) {
        return Err(Refusal::SignatureInvalid {
            timestamp: event.timestamp_micros,
            why: "no signing key of the sequencer made the signature over the event".into(),
        });
    }
    Ok(())
}

/// `validateOnReconnect`: the event a resubscription starts with, at the timestamp of `last`.
pub fn check_replay(
    last: &LastEvent,
    event: &Delivered,
    psid: &str,
    trust: SequencerTrust<'_>,
) -> Result<(), Refusal> {
    check_synchronizer_id(event, psid)?;
    check_signature(event, trust)?;
    // [CANTON-NOTE: SEMANTICS] The contents are compared, not the bytes: "the SequencerReader serializes the `SequencedEvent` afresh upon each
    // resubscription and the serialization may therefore differ".
    if content_digest(&event.event_bytes) != last.content_digest {
        return Err(Refusal::ForkHappened {
            timestamp: last.timestamp_micros,
        });
    }
    Ok(())
}

fn check_synchronizer_id(event: &Delivered, psid: &str) -> Result<(), Refusal> {
    if event.physical_synchronizer_id != psid {
        return Err(Refusal::BadSynchronizerId {
            expected: psid.to_string(),
            received: event.physical_synchronizer_id.clone(),
        });
    }
    Ok(())
}

/// The SHA-256 of an event's content in one canonical form: the `SequencedEvent` with its recipients and envelopes decompressed and every
/// message encoded again, so that two serializations of the same content give the same digest.
pub fn content_digest(event_bytes: &[u8]) -> [u8; 32] {
    let canonical = unversioned(event_bytes).and_then(|(bytes, version)| {
        let mut event = SequencedEvent::decode(bytes.as_slice()).ok()?;
        if let Some(batch) = event.batch.as_mut() {
            if let Some(recipients) = decompress(&batch.compressed_recipients).and_then(|b| {
                canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok()
            }) {
                batch.compressed_recipients = recipients.encode_to_vec();
            }
            for envelope in &mut batch.compressed_envelopes {
                if let Some(decoded) = decompress(envelope)
                    .and_then(|b| EnvelopeWithoutRecipients::decode(b.as_slice()).ok())
                {
                    *envelope = decoded.encode_to_vec();
                }
            }
        }
        let mut out = version.to_be_bytes().to_vec();
        out.extend(event.encode_to_vec());
        Some(out)
    });
    Sha256::digest(canonical.as_deref().unwrap_or(event_bytes)).into()
}

/// Whether one of the signer's `keys` made the protocol `signature` over `message` (a signature by a session key is refused).
pub(crate) fn verifies(keys: &[PublicKey], signature: &Signature, message: &[u8]) -> bool {
    verify_by_keys(keys, message, signature, &protocol_only()).is_ok()
}

/// [`verifies`] at the topology snapshot of `at_micros` on the synchronizer `physical`: a session key that one of `keys` delegated to
/// then signs as well.
pub(crate) fn verifies_at(
    keys: &[PublicKey],
    signature: &Signature,
    message: &[u8],
    physical: &str,
    at_micros: i64,
) -> bool {
    let scope = DelegationScope {
        synchronizer_id: logical_synchronizer_id(physical),
        at_micros,
    };
    verify_by_keys_at(keys, message, signature, &protocol_only(), &scope).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sequencing_wire::{SEQUENCED_EVENT_VERSION, SIGNED_CONTENT_VERSION};
    use crate::topology_wire::versioned;
    use canton_proto::com::digitalasset::canton::protocol::v30::SignedContent;
    use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;

    /// An event after another one, signed with an ECDSA P-256 key by `sign`.
    fn delivered_signed_with(key: &p256::ecdsa::SigningKey, signed_by: &str) -> Delivered {
        use p256::ecdsa::signature::Signer;
        let event = SequencedEvent {
            previous_timestamp: Some(1),
            timestamp: 2,
            physical_synchronizer_id: "sync::1220aa::37-0".into(),
            ..Default::default()
        };
        let event_bytes = versioned(event.encode_to_vec(), SEQUENCED_EVENT_VERSION);
        let der: p256::ecdsa::Signature = key.sign(&event_hash(&event_bytes));
        let signature = Signature {
            format: 2,                 // DER
            signing_algorithm_spec: 2, // EC-DSA-SHA256
            signature: der.to_der().as_bytes().to_vec(),
            signed_by: signed_by.to_string(),
            signature_delegation: None,
        };
        let bytes = versioned(
            SignedContent {
                content: Some(event_bytes),
                signatures: vec![signature],
                timestamp_of_signing_key: None,
            }
            .encode_to_vec(),
            SIGNED_CONTENT_VERSION,
        );
        decode_delivered(&bytes).expect("an event")
    }

    fn p256_key(seed: u8) -> (p256::ecdsa::SigningKey, PublicKey) {
        use p256::pkcs8::EncodePublicKey;
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let key = canton_algo::signing::create_public_key(
            canton_algo::signing::KeyFormat::DerX509Spki,
            spki.as_bytes(),
            canton_algo::signing::KeySpec::EcP256,
            protocol_only(),
        )
        .unwrap();
        (sk, key)
    }

    /// C-4: an event signed by a session key the sequencer's long-term key delegated to is the sequencer's while the delegation is
    /// valid at the event's timestamp, and not after.
    #[test]
    fn an_event_signed_by_a_delegated_session_key_is_the_sequencers_while_the_delegation_lasts() {
        use canton_proto::com::digitalasset::canton::crypto::v30::SignatureDelegation;
        use ed25519_dalek::Signer;
        let long_term = crate::topology_wire::Ed25519Key::from_seed([31; 32]);
        let key = canton_algo::member_signature::own_ed25519_key(&long_term.spki_der).unwrap();
        let session = crate::topology_wire::Ed25519Key::from_seed([32; 32]);
        let session_signing = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
        let psid = "sync::1220aa::37-0";
        let event = |at: i64| {
            let e = SequencedEvent {
                previous_timestamp: Some(at - 1),
                timestamp: at,
                physical_synchronizer_id: psid.into(),
                ..Default::default()
            };
            versioned(e.encode_to_vec(), SEQUENCED_EVENT_VERSION)
        };
        let mut delegation = SignatureDelegation {
            session_key: session.spki_der,
            session_key_spec: 1,
            validity_period_from_inclusive: 1_000,
            validity_period_duration_seconds: 60,
            format: 3,
            signing_algorithm_spec: 1,
            signature: Vec::new(),
        };
        let unsigned = Signature {
            format: 3,
            signing_algorithm_spec: 1,
            signature: vec![0; 64],
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
        let delivered_at = |at: i64| {
            let bytes = event(at);
            let signature = Signature {
                signature: session_signing
                    .sign(&event_hash(&bytes))
                    .to_bytes()
                    .to_vec(),
                signature_delegation: Some(delegation.clone()),
                ..unsigned.clone()
            };
            decode_delivered(&versioned(
                SignedContent {
                    content: Some(bytes),
                    signatures: vec![signature],
                    timestamp_of_signing_key: None,
                }
                .encode_to_vec(),
                SIGNED_CONTENT_VERSION,
            ))
            .unwrap()
        };
        let keys = std::slice::from_ref(&key);
        assert_eq!(
            check_signature(&delivered_at(2_000), SequencerTrust::Keys(keys)),
            Ok(())
        );
        assert!(matches!(
            check_signature(&delivered_at(61_000_000), SequencerTrust::Keys(keys)),
            Err(Refusal::SignatureInvalid { .. })
        ));
    }

    /// C-1: a sequencer whose topology gives it an ECDSA P-256 protocol key signs events the participant accepts; another key does not.
    #[test]
    fn an_event_signed_with_the_sequencers_p256_key_is_the_sequencers() {
        let (sk, key) = p256_key(3);
        let event = delivered_signed_with(&sk, &key.id);
        assert_eq!(
            check_signature(&event, SequencerTrust::Keys(std::slice::from_ref(&key))),
            Ok(())
        );
        let (_, other) = p256_key(4);
        assert!(matches!(
            check_signature(&event, SequencerTrust::Keys(&[other])),
            Err(Refusal::SignatureInvalid { .. })
        ));
    }
}
