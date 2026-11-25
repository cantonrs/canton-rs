//! A sequencer that observes an **official** synchronizer (`canton-rs sequencer bft-peer --observe-sequencing`): it makes events of what
//! the BFT orderer decided, for members it read from the official nodes. Its own topology store is not the synchronizer's, so the
//! mediator groups, which decide who may send an aggregated verdict, have to be read from the official nodes too.
//!
//! Found by `scripts/bft-oracle.sh join` (2026-11-20): without the groups, every verdict of the official mediators was refused as
//! "not part of the mediator group" and the participants' events of them were missing at the Rust sequencer.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::BTreeMap;
use std::sync::Arc;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_state::MediatorGroup;
use canton_participant::topology_wire::{unversioned, versioned, Ed25519Key};
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::Sequencer;
use canton_sequencer_server::synchronizer_state::{SynchronizerKeys, TopologyStore};
use prost::Message as _;
use tokio_stream::StreamExt as _;

const PHYSICAL: &str =
    "da::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::37-0";

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

/// A member of the official synchronizer as the observer reads it from the official nodes: its id and its signing key.
fn member(kind: &str, name: &str, seed: u8) -> (String, Ed25519Key, Registered) {
    let key = Ed25519Key::from_seed([seed; 32]);
    let id = format!("{kind}::{name}::{}", key.fingerprint);
    let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
    let registered = Registered {
        member: id.clone(),
        signing_keys: vec![raw.clone()],
        authentication_keys: vec![raw],
        encryption_keys: Vec::new(),
    };
    (id, key, registered)
}

/// `sender`'s verdict-like request to `recipient` under the aggregation rule of mediator group 0.
fn verdict(sender: &str, key: &Ed25519Key, id: &str, recipient: &str) -> Vec<u8> {
    let plain = sw::submission_request_to_groups(
        sender,
        id,
        &[(vec![recipient.to_string()], b"verdict".to_vec())],
        now_micros() + 60_000_000,
    );
    let (data, version) = unversioned(&plain).unwrap();
    let mut request = SubmissionRequest::decode(data.as_slice()).unwrap();
    request.aggregation_rule = Some(AggregationRule {
        eligible_members: vec!["MGR::0".to_string()],
        threshold: 0,
    });
    sw::signed_submission_request(versioned(request.encode_to_vec(), version), key)
}

/// The observer as `bft-peer --observe-sequencing` builds it: a placeholder store of its own keys, the members of the official nodes.
fn observer(members: Vec<Registered>) -> (Sequencer, Arc<TopologyStore>) {
    let keys = Arc::new(SynchronizerKeys::for_sequencer([1; 32], [2; 32], [3; 32]));
    let store = Arc::new(TopologyStore::initial(
        "observed", "observed", "observed", &keys,
    ));
    let registry = Arc::new(Registry::default());
    for m in members {
        registry.insert(m);
    }
    let sequencer = Sequencer::new(PHYSICAL.to_string(), keys, registry, Arc::clone(&store));
    sequencer.set_observer();
    (sequencer, store)
}

/// The envelopes of the events `member` has so far.
async fn delivered(sequencer: &Sequencer, member: &str) -> Vec<Vec<u8>> {
    let mut stream = sequencer.subscribe(member.to_string(), None);
    let mut out = Vec::new();
    while let Ok(Some(Ok(response))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await
    {
        let event = sw::decode_delivered(&response.signed_sequenced_event).unwrap();
        out.extend(event.envelopes);
    }
    out
}

#[test]
fn an_observed_synchronizers_mediator_group_decides_who_sends_its_verdicts() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (mediator, mediator_key, mediator_reg) = member("MED", "mediator1", 11);
        let (participant, _, participant_reg) = member("PAR", "participant1", 12);
        let (other, other_key, other_reg) = member("PAR", "participant2", 13);
        let (sequencer, store) = observer(vec![mediator_reg, participant_reg, other_reg]);
        // what the official synchronizer's topology says of its mediator group (read from the official nodes at the start)
        store.observe_mediator_groups(BTreeMap::from([(
            0,
            MediatorGroup {
                serial: 1,
                threshold: 1,
                active: vec![mediator.strip_prefix("MED::").unwrap().to_string()],
                observers: Vec::new(),
            },
        )]));

        // negative control: a participant sends a verdict under the group's rule
        sequencer.apply_ordered_at(
            &other,
            &verdict(&other, &other_key, "forged", &participant),
            now_micros(),
        );
        assert!(
            delivered(&sequencer, &participant).await.is_empty(),
            "a participant is not the mediator group"
        );

        // the official mediator's verdict, decided by the orderer, becomes the participant's event
        sequencer.apply_ordered_at(
            &mediator,
            &verdict(&mediator, &mediator_key, "genuine", &participant),
            now_micros(),
        );
        assert_eq!(
            delivered(&sequencer, &participant).await,
            vec![b"verdict".to_vec()],
            "the verdict of the observed synchronizer's mediator is delivered"
        );
    });
}

/// Without the observed synchronizer's groups the observer cannot tell a mediator of the group from anyone else: it delivers nothing
/// (what `scripts/bft-oracle.sh join` saw as events missing at the Rust sequencer).
#[test]
fn an_observer_that_does_not_know_the_mediator_group_delivers_no_verdict() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (mediator, mediator_key, mediator_reg) = member("MED", "mediator1", 21);
        let (participant, _, participant_reg) = member("PAR", "participant1", 22);
        let (sequencer, _store) = observer(vec![mediator_reg, participant_reg]);
        sequencer.apply_ordered_at(
            &mediator,
            &verdict(&mediator, &mediator_key, "unknown-group", &participant),
            now_micros(),
        );
        assert!(delivered(&sequencer, &participant).await.is_empty());
    });
}
