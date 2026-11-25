//! What the mediator of its own process reads from its subscription: the events the sequencer delivers it, checked as the sequencer client
//! checks them (`SequencedEventValidator`, the same checks a participant runs: [`canton_participant::sequenced_event_validation`]).
use canton_participant::sequenced_event_validation::{LastEvent, Refusal, Subscription};
use canton_participant::sequencing_wire::Delivered;

/// How far the mediator has read and what the next event is checked against.
///
/// [CANTON-NOTE: SEMANTICS] A refused event, one that does not decode included, ends the reading for good (`SubscriptionHandlerImpl`
/// returns it, `SequencerSubscriptionWrapper.giveUp` makes the connection fatal): nothing after it is read and nothing is decided.
pub(crate) struct Reader {
    cursor: i64,
    physical: String,
    subscription: Subscription,
}

impl Reader {
    /// A reader that reads the events of the synchronizer `physical` after `cursor`.
    pub(crate) fn new(cursor: i64, physical: &str) -> Self {
        Reader {
            cursor,
            physical: physical.to_string(),
            subscription: Subscription::resumed(None),
        }
    }

    /// The timestamp of the last event read.
    pub(crate) fn cursor(&self) -> i64 {
        self.cursor
    }

    /// Where the next subscription starts (inclusive): at the last event read after the stream broke, to check it again.
    pub(crate) fn subscribe_from(&self) -> i64 {
        self.subscription.subscribe_from(self.cursor)
    }

    /// The stream broke: the next subscription is a resubscription.
    pub(crate) fn broken(&mut self) {
        self.subscription.broken();
    }

    /// Why reading stopped for good, once an event was refused.
    pub(crate) fn halted(&self) -> Option<&Refusal> {
        self.subscription.halted()
    }

    /// Checks one delivered event (`signed_sequenced_event` bytes) and takes it as read. `keys_at` puts into force what took effect before
    /// the event's timestamp and gives the sequencer's signing keys then. `None`: the last event read, delivered again.
    pub(crate) fn receive(
        &mut self,
        raw: &[u8],
        keys_at: impl FnOnce(i64) -> Option<Vec<canton_algo::signing::PublicKey>>,
    ) -> Result<Option<Delivered>, Refusal> {
        let (event, replay) = self.subscription.admit(raw, self.cursor, &self.physical)?;
        let keys = keys_at(event.timestamp_micros).unwrap_or_default();
        self.subscription
            .authenticate(&event, replay, &self.physical, Some(&keys))?;
        if replay {
            return Ok(None);
        }
        self.subscription.handled(Some(LastEvent::of(&event)));
        self.cursor = event.timestamp_micros;
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_participant::sequencing_wire as sw;
    use canton_participant::topology_wire::Ed25519Key;
    use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;

    const SYNC: &str = "sync::1220ff::37-0";

    fn sequencer_key() -> Ed25519Key {
        Ed25519Key::from_seed([7; 32])
    }

    fn raw_key(key: &Ed25519Key) -> canton_algo::signing::PublicKey {
        canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap()
    }

    fn event(at: i64, previous: Option<i64>, content: &[u8]) -> SequencedEvent {
        SequencedEvent {
            previous_timestamp: previous,
            timestamp: at,
            physical_synchronizer_id: SYNC.into(),
            message_id: None,
            batch: Some(sw::compressed_batch_to_groups(&[(
                vec!["MGR::0".to_string()],
                content.to_vec(),
            )])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        }
    }

    fn signed(event: &SequencedEvent) -> Vec<u8> {
        sw::signed_sequenced_event(event, &sequencer_key())
    }

    fn keys(_: i64) -> Option<Vec<canton_algo::signing::PublicKey>> {
        Some(vec![raw_key(&sequencer_key())])
    }

    #[test]
    fn an_event_that_does_not_decode_stops_the_reading_where_it_is() {
        let mut reader = Reader::new(0, SYNC);
        assert!(reader
            .receive(&signed(&event(10, None, b"one")), keys)
            .unwrap()
            .is_some());
        let mut broken = event(20, Some(10), b"two");
        if let Some(batch) = broken.batch.as_mut() {
            batch.compressed_envelopes.push(b"not compressed".to_vec());
        }
        assert_eq!(
            reader.receive(&signed(&broken), keys).err(),
            Some(Refusal::Undecodable)
        );
        assert_eq!(reader.cursor(), 10, "not read past the event");
        assert_eq!(
            reader
                .receive(&signed(&event(20, Some(10), b"two")), keys)
                .err(),
            Some(Refusal::Undecodable),
            "nothing is read after it"
        );
        assert!(reader.halted().is_some());
    }

    #[test]
    fn an_event_off_the_chain_of_the_synchronizer_or_not_signed_by_its_sequencer_is_refused() {
        let first = signed(&event(10, None, b"one"));
        let refused = |raw: &[u8]| {
            let mut reader = Reader::new(0, SYNC);
            reader.receive(&first, keys).unwrap();
            reader.receive(raw, keys).err()
        };
        assert!(matches!(
            refused(&signed(&event(20, Some(15), b"two"))),
            Some(Refusal::PreviousTimestampMismatch { .. })
        ));
        let mut elsewhere = event(20, Some(10), b"two");
        elsewhere.physical_synchronizer_id = "other::1220ff::37-0".into();
        assert!(matches!(
            refused(&signed(&elsewhere)),
            Some(Refusal::BadSynchronizerId { .. })
        ));
        let forged = sw::signed_sequenced_event(
            &event(20, Some(10), b"two"),
            &Ed25519Key::from_seed([8; 32]),
        );
        assert!(matches!(
            refused(&forged),
            Some(Refusal::SignatureInvalid { .. })
        ));
        // control: the same event, signed by the sequencer, is read
        assert_eq!(refused(&signed(&event(20, Some(10), b"two"))), None);
    }

    #[test]
    fn a_resubscription_starts_at_the_last_event_read_and_refuses_a_different_one_there() {
        let mut reader = Reader::new(0, SYNC);
        reader
            .receive(&signed(&event(10, None, b"one")), keys)
            .unwrap();
        assert_eq!(reader.subscribe_from(), 11);
        reader.broken();
        assert_eq!(reader.subscribe_from(), 10, "the last event comes again");
        assert!(
            reader
                .receive(&signed(&event(10, None, b"one")), keys)
                .unwrap()
                .is_none(),
            "checked, not read again"
        );
        assert_eq!(reader.subscribe_from(), 11);
        reader.broken();
        assert_eq!(
            reader
                .receive(&signed(&event(10, None, b"forked")), keys)
                .err(),
            Some(Refusal::ForkHappened { timestamp: 10 })
        );
    }
}
