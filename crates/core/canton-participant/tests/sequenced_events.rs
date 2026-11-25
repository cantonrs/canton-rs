//! P-6 and P-14: what a participant checks of the events its sequencer delivers before it handles them (`SequencedEventValidator`), and the
//! two event kinds it used to mishandle (a deliver error to its own submission, an event that does not decode). The events are built and
//! signed as the Rust sequencer builds them (`sequencing_wire::signed_sequenced_event`) around a request built by the submitting code, and
//! handed to `Runtime::receive`; no sequencer or JVM is involved.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "sequencer-grpc")]
use canton_participant::participant_runtime::{Config, Runtime, Step};
use canton_participant::sequenced_event_validation::{NotHandled, Refusal};
use canton_participant::sequencing_wire::{compressed_batch_to_groups, signed_sequenced_event};
use canton_participant::submit::{build_create, Context, Create, Peer, Randomness};
use canton_participant::topology_wire::{self as tw, Ed25519Key, ParticipantIdentity};
use canton_participant::value_forms::forms;
use canton_participant::view_acs::Timeouts;
use canton_participant::view_conformance::Engine;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    SignedContent, SignedTopologyTransaction,
};
use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;
use lf_eval::typed_json::Types;
use lf_eval::{Value, World};
use prost::Message;
use std::path::Path;

const SYNC: &str = "sync::1220aa::37-0";
const NOW: i64 = 1_000_000_000_000;

struct Counter(u64);
impl Randomness for Counter {
    fn fresh(&mut self, label: &str) -> [u8; 32] {
        self.0 += 1;
        canton_algo::hash::sha256_with_purpose(1, format!("{label}-{}", self.0).as_bytes())
    }
}

fn dar() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn raw_key(key: &Ed25519Key) -> canton_algo::signing::PublicKey {
    canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap()
}

/// A participant, its party erin, the sequencer it is connected to, and the envelopes of a create by erin addressed to the participant.
struct Setup {
    me: ParticipantIdentity,
    erin: String,
    sequencer: ParticipantIdentity,
    envelopes: Vec<(Vec<String>, Vec<u8>)>,
}

fn world() -> Setup {
    let me = ParticipantIdentity::generate("receiver");
    let erin = me.party_id("erin");
    let world = World::open(&dar()).unwrap();
    let types = Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let holding = Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(erin.clone())),
            ("owner".into(), Value::Party(erin.clone())),
            ("auditor".into(), Value::Party(erin.clone())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 1_000_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };
    let (arg, hash_arg) = forms(&types, &ty, &holding).unwrap();
    let built = build_create(
        &Context {
            identity: &me,
            synchronizer: SYNC,
            mediator_group: 0,
            user_id: "rust-user",
        },
        &Create {
            package_name: "sample-contract",
            package_id: world.main_package_id(),
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            arg,
            hash_arg,
            signatories: vec![erin.clone()],
            stakeholders: vec![erin.clone()],
            hosts: vec![Peer {
                member: me.member(),
                encryption_spki: me.encryption_spki().to_vec(),
                fingerprint: me.encryption_fingerprint(),
            }],
            command_id: "cmd-1".into(),
            key: None,
        },
        NOW,
        &mut Counter(0),
    )
    .unwrap();
    let envelopes = built
        .envelopes
        .into_iter()
        .filter(|(to, _)| to.contains(&me.member()))
        .collect();
    Setup {
        me,
        erin,
        sequencer: ParticipantIdentity::generate("sequencer"),
        envelopes,
    }
}

/// An event at `at` after `previous`, carrying the create when `with_request`.
fn event(w: &Setup, at: i64, previous: Option<i64>, with_request: bool) -> SequencedEvent {
    let envelopes = if with_request {
        w.envelopes.clone()
    } else {
        Vec::new()
    };
    SequencedEvent {
        previous_timestamp: previous,
        timestamp: at,
        physical_synchronizer_id: SYNC.into(),
        message_id: None,
        batch: Some(compressed_batch_to_groups(&envelopes)),
        deliver_error_reason: None,
        topology_timestamp: None,
        traffic_receipt: None,
    }
}

/// `event` as the sequencer delivers it: signed by its signing key.
fn by_sequencer(w: &Setup, event: &SequencedEvent) -> Vec<u8> {
    signed_sequenced_event(event, &w.sequencer.signing_key)
}

/// A runtime configured by hand (it follows no topology) that hosts erin.
fn configured(w: &Setup, state: Option<&Path>, start: i64) -> Runtime {
    let config = Config {
        member: w.me.member(),
        encryption_fingerprint: w.me.encryption_fingerprint(),
        encryption_secret: *w.me.encryption_secret(),
        hosted_parties: vec![w.erin.clone(), w.me.uid()],
        timeouts: Timeouts::default(),
        submitter_keys: vec![raw_key(&w.me.signing_key)],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: SYNC.into(),
        follow_topology: false,
        topology_change_delay_micros: 250_000,
    };
    Runtime::open(config, Engine::load(&dar()).unwrap(), state, start).unwrap()
}

/// The sequencer's identity in the topology: its namespace and the key mapping that names its signing key.
fn sequencer_onboarding(sequencer: &ParticipantIdentity) -> Vec<SignedTopologyTransaction> {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let delegation = tw::namespace_delegation(
        sequencer.namespace(),
        sequencer
            .namespace_key
            .public_key(&[SigningKeyUsage::Namespace]),
    );
    let mapping = tw::owner_to_key_mapping(
        &format!("SEQ::{}", sequencer.uid()),
        vec![PublicKey {
            key: Some(Key::SigningPublicKey(sequencer.signing_key.public_key(&[
                SigningKeyUsage::Protocol,
                SigningKeyUsage::ProofOfOwnership,
            ]))),
        }],
    );
    vec![
        tw::signed(
            delegation.clone(),
            vec![sequencer.namespace_key.sign_transaction(&delegation)],
        ),
        tw::signed(
            mapping.clone(),
            vec![
                sequencer.namespace_key.sign_transaction(&mapping),
                sequencer.signing_key.sign_transaction(&mapping),
            ],
        ),
    ]
}

/// A runtime that follows a topology in which `w.sequencer` is the sequencer it is connected to, reading the events after `start`.
fn following(w: &Setup, start: i64) -> Runtime {
    let mut transactions = w.me.onboarding_transactions("sync::1220aa");
    transactions.extend(sequencer_onboarding(&w.sequencer));
    let state: Vec<(i64, Vec<u8>)> = transactions
        .iter()
        .map(|t| (0, tw::stored_form(t)))
        .collect();
    let mut rt = configured(w, None, start);
    rt.config.follow_topology = true;
    rt.load_topology_state(&canton_participant::topology_state::decode(&state).unwrap())
        .unwrap();
    rt.connected_to(&w.sequencer.uid());
    rt
}

fn refused(result: Result<Option<Step>, NotHandled>) -> Refusal {
    match result {
        Err(NotHandled::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn handled(result: Result<Option<Step>, NotHandled>) -> Step {
    match result {
        Ok(Some(step)) => step,
        other => panic!("expected the event to be handled, got {other:?}"),
    }
}

/// Replaces the signature of a signed event.
fn resigned(
    raw: &[u8],
    signature: canton_proto::com::digitalasset::canton::crypto::v30::Signature,
) -> Vec<u8> {
    let (data, version) = tw::unversioned(raw).unwrap();
    let mut signed = SignedContent::decode(data.as_slice()).unwrap();
    signed.signatures = vec![signature];
    tw::versioned(signed.encode_to_vec(), version)
}

const START: i64 = NOW;

#[test]
fn an_event_the_sequencer_signed_is_handled() {
    let w = world();
    let mut rt = following(&w, START);
    handled(rt.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), true),
    )));
    assert_eq!(rt.cursor(), START + 10);
    assert_eq!(
        rt.last_event().map(|e| e.timestamp_micros),
        Some(START + 10)
    );
}

#[test]
fn a_forged_signature_is_refused_and_stops_the_subscription() {
    let w = world();
    let mut rt = following(&w, START);
    let genuine = event(&w, START + 10, Some(START - 5), true);
    // the sequencer's signature over another event
    let mut other = genuine.clone();
    other.timestamp += 1;
    let (data, _) = tw::unversioned(&by_sequencer(&w, &other)).unwrap();
    let foreign = SignedContent::decode(data.as_slice()).unwrap().signatures[0].clone();
    let forged = resigned(&by_sequencer(&w, &genuine), foreign);
    assert!(matches!(
        refused(rt.receive(&forged)),
        Refusal::SignatureInvalid { timestamp, .. } if timestamp == START + 10
    ));
    assert_eq!(rt.cursor(), START, "the cursor does not move");
    assert!(
        matches!(
            refused(rt.receive(&by_sequencer(&w, &genuine))),
            Refusal::SignatureInvalid { .. }
        ),
        "the subscription is stopped: nothing after the refusal is handled"
    );
    // control: a runtime that was not fed the forgery handles the genuine event
    let mut control = following(&w, START);
    handled(control.receive(&by_sequencer(&w, &genuine)));
}

#[test]
fn a_signature_by_a_key_that_is_not_the_sequencers_is_refused() {
    let w = world();
    let mut rt = following(&w, START);
    let genuine = event(&w, START + 10, Some(START - 5), true);
    // signed by the participant's own signing key, which the topology names too, but not for the sequencer
    let raw = signed_sequenced_event(&genuine, &w.me.signing_key);
    assert!(matches!(
        refused(rt.receive(&raw)),
        Refusal::SignatureInvalid { .. }
    ));
    let mut control = following(&w, START);
    handled(control.receive(&by_sequencer(&w, &genuine)));
}

/// [CANTON-NOTE: SEMANTICS] `verifySignatureAndDecompress` does not check the signature of the first event of a fresh subscription (no
/// previous timestamp): there is no topology to check it with yet.
#[test]
fn the_first_event_of_a_fresh_subscription_is_not_signature_checked() {
    let w = world();
    let mut rt = following(&w, 0);
    let raw = signed_sequenced_event(&event(&w, START, None, false), &w.me.signing_key);
    handled(rt.receive(&raw));
}

#[test]
fn an_event_of_another_synchronizer_is_refused() {
    let w = world();
    let mut rt = configured(&w, None, START);
    let mut foreign = event(&w, START + 10, Some(START - 5), true);
    foreign.physical_synchronizer_id = "other::1220aa::37-0".into();
    assert_eq!(
        refused(rt.receive(&by_sequencer(&w, &foreign))),
        Refusal::BadSynchronizerId {
            expected: SYNC.into(),
            received: "other::1220aa::37-0".into()
        }
    );
    assert_eq!(rt.cursor(), START);
    let mut control = configured(&w, None, START);
    let step = handled(control.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), true),
    )));
    assert_eq!(
        step.to_send.len(),
        1,
        "the request is answered: {:?}",
        step.notes
    );
}

#[test]
fn an_event_that_does_not_follow_the_last_one_handled_is_refused() {
    let w = world();
    let mut rt = configured(&w, None, START);
    handled(rt.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), false),
    )));
    // an event in between was left out
    let gap = event(&w, START + 30, Some(START + 20), true);
    assert_eq!(
        refused(rt.receive(&by_sequencer(&w, &gap))),
        Refusal::PreviousTimestampMismatch {
            received: Some(START + 20),
            expected: Some(START + 10)
        }
    );
    assert_eq!(rt.cursor(), START + 10);
    let mut control = configured(&w, None, START);
    handled(control.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), false),
    )));
    handled(control.receive(&by_sequencer(
        &w,
        &event(&w, START + 30, Some(START + 10), true),
    )));
    assert_eq!(control.cursor(), START + 30);
}

#[test]
fn a_first_event_whose_previous_event_is_after_the_start_is_refused() {
    let w = world();
    let mut rt = configured(&w, None, START);
    assert_eq!(
        refused(rt.receive(&by_sequencer(
            &w,
            &event(&w, START + 10, Some(START + 5), false)
        ))),
        Refusal::PreviousTimestampAfterStart {
            received: START + 5,
            start: START
        }
    );
}

#[test]
fn an_event_whose_timestamp_does_not_increase_is_refused() {
    let w = world();
    let mut rt = configured(&w, None, START);
    handled(rt.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), false),
    )));
    // it names the last event as its previous one but is sequenced before it
    assert_eq!(
        refused(rt.receive(&by_sequencer(
            &w,
            &event(&w, START + 8, Some(START + 10), true)
        ))),
        Refusal::NonIncreasingTimestamp {
            new: START + 8,
            old: START + 10
        }
    );
    let mut control = configured(&w, None, START);
    handled(control.receive(&by_sequencer(
        &w,
        &event(&w, START + 10, Some(START - 5), false),
    )));
    handled(control.receive(&by_sequencer(
        &w,
        &event(&w, START + 12, Some(START + 10), true),
    )));
}

#[test]
fn an_event_that_declares_a_timestamp_of_signing_key_is_refused() {
    let w = world();
    let mut rt = configured(&w, None, START);
    let raw = by_sequencer(&w, &event(&w, START + 10, Some(START - 5), false));
    let (data, version) = tw::unversioned(&raw).unwrap();
    let mut signed = SignedContent::decode(data.as_slice()).unwrap();
    signed.timestamp_of_signing_key = Some(START);
    let declared = tw::versioned(signed.encode_to_vec(), version);
    assert!(matches!(
        refused(rt.receive(&declared)),
        Refusal::TimestampOfSigningKeyNotAllowed { .. }
    ));
}

fn state_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "canton-rs-sequenced-events-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// P-6 on reconnect: the last event handled is kept with the cursor; after a restart the subscription starts with it again, it is checked
/// against what was kept and not handled again, and the events after it follow it.
#[test]
fn a_resubscription_starts_with_the_last_event_handled_and_it_must_be_the_same() {
    let w = world();
    let dir = state_dir("replay");
    let first = event(&w, START + 10, Some(START - 5), false);
    let last = event(&w, START + 20, Some(START + 10), true);
    {
        let mut rt = configured(&w, Some(&dir), START);
        handled(rt.receive(&by_sequencer(&w, &first)));
        handled(rt.receive(&by_sequencer(&w, &last)));
    }
    let mut rt = configured(&w, Some(&dir), START);
    assert_eq!(rt.cursor(), START + 20);
    assert_eq!(
        rt.last_event().map(|e| e.timestamp_micros),
        Some(START + 20),
        "the last event is kept across the restart"
    );
    assert!(
        matches!(rt.receive(&by_sequencer(&w, &last)), Ok(None)),
        "the same event again is checked, not handled"
    );
    handled(rt.receive(&by_sequencer(
        &w,
        &event(&w, START + 30, Some(START + 20), false),
    )));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_resubscription_that_starts_with_another_event_at_the_same_time_is_a_fork() {
    let w = world();
    let dir = state_dir("fork");
    let last = event(&w, START + 20, Some(START - 5), true);
    {
        let mut rt = configured(&w, Some(&dir), START);
        handled(rt.receive(&by_sequencer(&w, &last)));
    }
    let mut rt = configured(&w, Some(&dir), START);
    let mut forked = last.clone();
    forked.batch = Some(compressed_batch_to_groups(&[]));
    assert_eq!(
        refused(rt.receive(&by_sequencer(&w, &forked))),
        Refusal::ForkHappened {
            timestamp: START + 20
        }
    );
    assert_eq!(rt.cursor(), START + 20);
    // control: the same content, compressed differently, is the same event
    let mut control = configured(&w, Some(&dir), START);
    let mut recompressed = last.clone();
    if let Some(batch) = recompressed.batch.as_mut() {
        for envelope in &mut batch.compressed_envelopes {
            let plain = canton_participant::sequencing_wire::decompress(envelope).unwrap();
            *envelope = without_content_size(&plain);
        }
    }
    assert!(recompressed != last, "another serialization");
    assert!(matches!(
        control.receive(&by_sequencer(&w, &recompressed)),
        Ok(None)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Zstd frame without the content size in its header (what the streaming encoder writes).
fn without_content_size(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(bytes, 1).unwrap()
}

/// P-14: an event that does not decode stops the subscription; it is not skipped by moving the cursor past it.
#[test]
fn an_event_that_does_not_decode_stops_the_subscription() {
    let w = world();
    let mut rt = configured(&w, None, START);
    assert_eq!(refused(rt.receive(b"not an event")), Refusal::Undecodable);
    assert_eq!(rt.cursor(), START, "not skipped");
    let good = by_sequencer(&w, &event(&w, START + 10, Some(START - 5), true));
    assert_eq!(
        refused(rt.receive(&good)),
        Refusal::Undecodable,
        "nothing after it is handled"
    );
    // an envelope that does not decompress makes the whole event undecodable, rather than an event without that envelope
    let mut broken = event(&w, START + 10, Some(START - 5), true);
    if let Some(batch) = broken.batch.as_mut() {
        batch.compressed_envelopes[0] = b"not zstd".to_vec();
    }
    let mut rt = configured(&w, None, START);
    assert_eq!(
        refused(rt.receive(&by_sequencer(&w, &broken))),
        Refusal::Undecodable
    );
    let mut control = configured(&w, None, START);
    handled(control.receive(&good));
}

/// P-14: a deliver error addressed to this participant's own submission is that submission's failure, not a sequenced request.
#[test]
fn a_deliver_error_is_reported_for_the_submission_it_refuses() {
    let w = world();
    let mut rt = configured(&w, None, START);
    let mut error = event(&w, START + 10, Some(START - 5), false);
    error.message_id = Some("msg-1".into());
    error.batch = None;
    error.deliver_error_reason = Some(canton_proto::google::rpc::Status {
        code: 9,
        message: "SEQUENCER_MAX_SEQUENCING_TIME_EXCEEDED(9,0): too late".into(),
        details: vec![],
    });
    let step = handled(rt.receive(&by_sequencer(&w, &error)));
    assert_eq!(
        step.deliver_errors,
        vec![(
            "msg-1".to_string(),
            9,
            "SEQUENCER_MAX_SEQUENCING_TIME_EXCEEDED(9,0): too late".to_string()
        )]
    );
    assert!(
        step.own_requests.is_empty(),
        "it is not a sequenced request"
    );
    // control: a delivery with the same message id is the submission sequenced
    let mut control = configured(&w, None, START);
    let mut delivered = event(&w, START + 10, Some(START - 5), false);
    delivered.message_id = Some("msg-1".into());
    let step = handled(control.receive(&by_sequencer(&w, &delivered)));
    assert_eq!(step.own_requests, vec![("msg-1".to_string(), START + 10)]);
    assert!(step.deliver_errors.is_empty());
}
