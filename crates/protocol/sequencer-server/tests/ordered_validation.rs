//! What the sequencer decides about a submission once the orderer gave it its time (`SubmissionRequestValidator.performIndependentValidations`):
//! every check reads the sequencing time and the topology at that time, so every sequencer of a synchronizer, and the same sequencer after a
//! restart, makes the same events of the same ordered submissions.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{self as tw, Ed25519Key};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::Sequencer;
use canton_sequencer_server::synchronizer_state::{
    parameters_transaction, SynchronizerKeys, TopologyStore,
};
use tokio_stream::StreamExt as _;

const PHYSICAL: &str =
    "da::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::37-0";

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

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

fn sequencer(members: Vec<Registered>) -> (Sequencer, Arc<TopologyStore>, Arc<SynchronizerKeys>) {
    let keys = Arc::new(SynchronizerKeys::for_sequencer([1; 32], [2; 32], [3; 32]));
    let store = Arc::new(TopologyStore::initial("sync", "seq", "med", &keys));
    let registry = Arc::new(Registry::default());
    for m in members {
        registry.insert(m);
    }
    let sequencer = Sequencer::new(
        PHYSICAL.to_string(),
        Arc::clone(&keys),
        registry,
        Arc::clone(&store),
    );
    (sequencer, store, keys)
}

/// The events `member` has so far.
async fn events(sequencer: &Sequencer, member: &str) -> Vec<sw::Delivered> {
    let mut stream = sequencer.subscribe(member.to_string(), None);
    let mut out = Vec::new();
    while let Ok(Some(Ok(response))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await
    {
        out.push(sw::decode_delivered(&response.signed_sequenced_event).unwrap());
    }
    out
}

/// The signature of `key` on an envelope's content (`HashPurpose.SignedProtocolMessageSignature`, 38).
fn envelope_signature(key: &Ed25519Key, content: &[u8]) -> Signature {
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, content));
    key.sign_bytes(&hash)
}

fn signed(sender: &str, key: &Ed25519Key, id: &str, to: &str, max: i64) -> Vec<u8> {
    let plain = sw::submission_request(sender, id, &[(to.to_string(), b"hello".to_vec())], max);
    sw::signed_submission_request(plain, key)
}

#[test]
fn a_submission_sequenced_past_its_max_sequencing_time_is_dropped() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (alice, alice_key, alice_reg) = member("PAR", "alice", 31);
        let (bob, _, bob_reg) = member("PAR", "bob", 32);
        let (sequencer, _, _) = sequencer(vec![alice_reg, bob_reg]);
        let at = now_micros();
        sequencer.apply_ordered_at(
            &alice,
            &signed(&alice, &alice_key, "late", &bob, at - 1),
            at,
        );
        assert!(
            events(&sequencer, &alice).await.is_empty(),
            "a request ordered after its maximum sequencing time gets no event, not even an error"
        );
        // negative control: ordered at its maximum sequencing time, it is delivered
        sequencer.apply_ordered_at(
            &alice,
            &signed(&alice, &alice_key, "in-time", &bob, at + 10),
            at + 10,
        );
        let got = events(&sequencer, &alice).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message_id.as_deref(), Some("in-time"));
        assert_eq!(got[0].error, None);
    });
}

#[test]
fn an_envelope_signed_by_a_key_that_is_not_the_senders_is_rejected() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (alice, alice_key, alice_reg) = member("PAR", "alice", 41);
        let (bob, bob_key, bob_reg) = member("PAR", "bob", 42);
        let (sequencer, _, _) = sequencer(vec![alice_reg, bob_reg]);
        let at = now_micros();
        let request = |id: &str, by: &Ed25519Key| {
            let plain = sw::submission_request_signed(
                &alice,
                id,
                &[(
                    vec![bob.clone()],
                    b"response".to_vec(),
                    vec![envelope_signature(by, b"response")],
                )],
                at + 60_000_000,
            );
            sw::signed_submission_request(plain, &alice_key)
        };
        sequencer.apply_ordered_at(&alice, &request("forged", &bob_key), at);
        let answer = events(&sequencer, &alice).await;
        assert_eq!(answer.len(), 1, "the sender is told: {answer:?}");
        let why = answer[0].error.clone().expect("an error event");
        assert!(
            why.contains("SEQUENCER_SUBMISSION_REQUEST_MALFORMED_REJECTED")
                && why.contains("checkClosedEnvelopesSignatures"),
            "{why}"
        );
        assert!(
            events(&sequencer, &bob).await.is_empty(),
            "nothing is delivered"
        );
        // negative control: the sender's own signature is delivered with the envelope
        sequencer.apply_ordered_at(&alice, &request("genuine", &alice_key), at + 1);
        let got = events(&sequencer, &bob).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].envelopes, vec![b"response".to_vec()]);
    });
}

#[test]
fn a_recipient_that_is_no_member_is_refused_whatever_its_kind() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (alice, alice_key, alice_reg) = member("PAR", "alice", 51);
        let (bob, _, bob_reg) = member("PAR", "bob", 52);
        let (sequencer, _, _) = sequencer(vec![alice_reg, bob_reg]);
        let at = now_micros();
        let ghost = format!(
            "MED::ghost::{}",
            Ed25519Key::from_seed([53; 32]).fingerprint
        );
        sequencer.apply_ordered_at(
            &alice,
            &signed(&alice, &alice_key, "ghost", &ghost, at + 60_000_000),
            at,
        );
        let answer = events(&sequencer, &alice).await;
        assert_eq!(answer.len(), 1);
        let why = answer[0].error.clone().expect("an error event");
        assert!(
            why.contains("SEQUENCER_UNKNOWN_RECIPIENTS") && why.contains(&ghost),
            "{why}"
        );
        // negative control: a member is delivered to
        sequencer.apply_ordered_at(
            &alice,
            &signed(&alice, &alice_key, "bob", &bob, at + 60_000_000),
            at + 1,
        );
        assert_eq!(events(&sequencer, &bob).await.len(), 1);
    });
}

#[test]
fn the_request_size_limit_is_the_one_in_force_at_the_sequencing_time() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (alice, alice_key, alice_reg) = member("PAR", "alice", 61);
        let (bob, _, bob_reg) = member("PAR", "bob", 62);
        let (sequencer, store, keys) = sequencer(vec![alice_reg, bob_reg]);
        // a limit of 64 bytes, sequenced ten seconds ago (in force since then plus the topology change delay)
        let changed = now_micros() - 10_000_000;
        let mut parameters = tw::default_dynamic_parameters();
        parameters.max_request_size = 64;
        let tx = parameters_transaction(&keys, &store.synchronizer_uid(), 2, parameters);
        let outcomes = store
            .accept_broadcast(&tw::topology_broadcast(PHYSICAL, &[tx]), changed)
            .expect("a topology broadcast");
        assert!(
            outcomes.iter().all(|o| o.is_in_force()),
            "{:?}",
            outcomes.iter().map(|o| o.note()).collect::<Vec<_>>()
        );
        let big = vec![7u8; 1000];
        let request = |id: &str, max: i64| {
            let plain = sw::submission_request(&alice, id, &[(bob.clone(), big.clone())], max);
            sw::signed_submission_request(plain, &alice_key)
        };
        // ordered before the limit took effect: the old limit applies
        let before = changed - 1_000_000;
        sequencer.apply_ordered_at(&alice, &request("before", before + 60_000_000), before);
        let got = events(&sequencer, &bob).await;
        assert_eq!(
            got.len(),
            1,
            "sequenced before the change, the request is delivered"
        );
        // negative control: ordered after it took effect, the request is too large
        let after = now_micros();
        sequencer.apply_ordered_at(&alice, &request("after", after + 60_000_000), after);
        assert_eq!(
            events(&sequencer, &bob).await.len(),
            1,
            "nothing more is delivered"
        );
    });
}
