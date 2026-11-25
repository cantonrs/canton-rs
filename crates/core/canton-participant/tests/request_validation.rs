//! The checks a receiving participant makes of a confirmation request beyond its content (internal review 4.3, bundle 1): the request's times
//! against its sequencing time, who authorized its root action, who signed it, and whether a verdict is about it. Requests are built by the
//! submitting code (`submit`) and handed to `Runtime::step`, as in `tests/submit.rs`; no sequencer or JVM is involved.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "sequencer-grpc")]
use canton_participant::confirmation_wire::Outcome;
use canton_participant::participant_runtime::{Config, Runtime, Step};
use canton_participant::sequencing_wire::Delivered;
use canton_participant::submit::{build_create, Context, Create, Peer, Randomness, StoredContract};
use canton_participant::topology_wire::ParticipantIdentity;
use canton_participant::value_forms::forms;
use canton_participant::view_acs::Timeouts;
use canton_participant::view_conformance::Engine;
use canton_participant::view_tree::{build_transaction, Action, Transaction};
use lf_eval::typed_json::Types;
use lf_eval::{Value, World};
use std::path::Path;

/// A physical synchronizer id that parses (a runtime that follows the topology needs one).
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

fn raw_key(identity: &ParticipantIdentity) -> canton_algo::signing::PublicKey {
    canton_algo::member_signature::own_ed25519_key(&identity.signing_key.spki_der).unwrap()
}

/// An envelope's recipients and content.
type Addressed = (Vec<String>, Vec<u8>);

/// A create of `AssetHolding` signed by erin (a party of `me`), submitted by `me` with ledger and preparation time `NOW`.
struct Built {
    me: ParticipantIdentity,
    erin: String,
    /// The envelopes addressed to `me`, each with the recipients the submitting code gave it.
    envelopes: Vec<Addressed>,
    root_hash: Vec<u8>,
    stored: StoredContract,
}

fn build(me: ParticipantIdentity) -> Built {
    build_for_group(me, 0)
}

/// Like [`build`], with the request naming mediator group `group`.
fn build_for_group(me: ParticipantIdentity, group: u32) -> Built {
    build_holding(me, group, None)
}

/// Like [`build_for_group`]; with `auditor` set, the holding's auditor is that party while the create still claims erin as its only
/// stakeholder (the engine computes the auditor as an observer, so the view does not conform).
fn build_holding(me: ParticipantIdentity, group: u32, auditor: Option<&str>) -> Built {
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
            (
                "auditor".into(),
                Value::Party(auditor.map_or_else(|| erin.clone(), str::to_string)),
            ),
            ("assetSymbol".into(), Value::Text("USD".into())),
            (
                "amount".into(),
                Value::Numeric {
                    coeff: 1_005_000_000_000,
                    scale: 10,
                },
            ),
        ],
    };
    let (arg, hash_arg) = forms(&types, &ty, &holding).unwrap();
    let host = Peer {
        member: me.member(),
        encryption_spki: me.encryption_spki().to_vec(),
        fingerprint: me.encryption_fingerprint(),
    };
    let built = build_create(
        &Context {
            identity: &me,
            synchronizer: SYNC,
            mediator_group: group,
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
            hosts: vec![host],
            command_id: "cmd-1".into(),
            key: None,
        },
        NOW,
        &mut Counter(0),
    )
    .unwrap();
    let envelopes = built
        .envelopes
        .iter()
        .filter(|(to, _)| to.contains(&me.member()))
        .cloned()
        .collect();
    let stored = StoredContract {
        contract_id_hex: built.contract_id_hex.clone(),
        instance: built.instance.clone(),
        package_id: world.main_package_id().to_string(),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        signatories: vec![erin.clone()],
        stakeholders: vec![erin.clone()],
    };
    Built {
        me,
        erin,
        envelopes,
        root_hash: built.root_hash,
        stored,
    }
}

/// A consuming `Settle` of the created contract by `actor`, submitted by `me` acting as `act_as`: the envelopes addressed to `me`.
fn settle(b: &Built, actor: &str, act_as: &[String]) -> Vec<Addressed> {
    settle_observed(b, actor, act_as, &[])
}

/// Like [`settle`], with the exercise claiming `choice_observers` (`Settle` has none).
fn settle_observed(
    b: &Built,
    actor: &str,
    act_as: &[String],
    choice_observers: &[String],
) -> Vec<Addressed> {
    request_of(
        b,
        Action::Exercise {
            contract: b.stored.clone(),
            choice: "Settle".into(),
            argument: Some(canton_participant::contract_wire::LfValue::Record(vec![])),
            consuming: true,
            actors: vec![actor.to_string()],
            choice_observers: choice_observers.to_vec(),
            children: vec![],
            interface_id: None,
        },
        act_as,
    )
}

/// A fetch of `contract` by erin, submitted by `me` acting as erin: the envelopes addressed to `me`.
fn fetch(b: &Built, contract: &StoredContract) -> Vec<Addressed> {
    request_of(
        b,
        Action::Fetch {
            contract: contract.clone(),
            actors: vec![b.erin.clone()],
            interface_id: None,
        },
        std::slice::from_ref(&b.erin),
    )
}

/// The one-node transaction `action`, submitted by `me` acting as `act_as`: the envelopes addressed to `me`.
fn request_of(b: &Built, action: Action, act_as: &[String]) -> Vec<Addressed> {
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let tx = Transaction {
        nodes: vec![action],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let member = b.me.member();
    let built = build_transaction(
        &Context {
            identity: &b.me,
            synchronizer: SYNC,
            mediator_group: 0,
            user_id: "rust-user",
        },
        &tx,
        &[host],
        &|_: &str| [member.clone()].into(),
        act_as,
        "request",
        NOW,
        None,
        &mut Counter(100),
    )
    .unwrap();
    built
        .envelopes
        .into_iter()
        .filter(|(to, _)| to.contains(&b.me.member()))
        .collect()
}

fn delivered(b: &Built, at: i64) -> Delivered {
    delivery(b.envelopes.clone(), at)
}

fn delivery(envelopes: Vec<Addressed>, at: i64) -> Delivered {
    Delivered {
        timestamp_micros: at,
        previous_timestamp_micros: None,
        physical_synchronizer_id: SYNC.into(),
        message_id: None,
        recipients: envelopes.iter().map(|(to, _)| to.clone()).collect(),
        envelope_signatures: envelopes.iter().map(|_| vec![]).collect(),
        envelopes: envelopes.into_iter().map(|(_, c)| c).collect(),
        signatures: vec![],
        error: None,
        event_bytes: vec![],
        timestamp_of_signing_key_micros: None,
    }
}

/// A runtime configured by hand (no topology followed) that hosts erin and trusts `me`'s signature.
fn configured(b: &Built) -> Runtime {
    let config = Config {
        member: b.me.member(),
        encryption_fingerprint: b.me.encryption_fingerprint(),
        encryption_secret: *b.me.encryption_secret(),
        hosted_parties: vec![b.erin.clone(), b.me.uid()],
        timeouts: Timeouts::default(),
        submitter_keys: vec![raw_key(&b.me)],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: SYNC.into(),
        follow_topology: false,
        topology_change_delay_micros: 250_000,
    };
    Runtime::open(config, Engine::load(&dar()).unwrap(), None, 0).unwrap()
}

/// A runtime that follows the topology `extra` adds to `me`'s onboarding (and trusts its own submissions, as `node.rs` does).
fn following(
    b: &Built,
    extra: &[canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction],
) -> Runtime {
    use canton_participant::topology_wire::stored_form;
    let mut transactions = b.me.onboarding_transactions("sync::1220aa");
    transactions.extend_from_slice(extra);
    let state: Vec<(i64, Vec<u8>)> = transactions.iter().map(|t| (0, stored_form(t))).collect();
    let entries = canton_participant::topology_state::decode(&state).unwrap();
    let mut rt = configured(b);
    rt.config.follow_topology = true;
    rt.config.hosted_parties = vec![];
    rt.config.submitter_keys = vec![];
    rt.load_topology_state(&entries).unwrap();
    rt.trust_own_submissions(raw_key(&b.me), &b.me.uid());
    rt
}

/// `me` hosts its party erin with `permission` (1 submission, 2 confirmation, 3 observation).
fn erin_hosted(
    b: &Built,
    permission: i32,
) -> canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction {
    b.me.party_hosting_at_serial("erin", &[(&b.me.uid(), permission)], 1)
}

fn malformed_with(step: &Step, text: &str) -> bool {
    matches!(outcome(step), Outcome::Malformed(why) if why.contains(text))
}

/// The one decision of the one answer of `step`.
fn outcome(step: &Step) -> Outcome {
    assert_eq!(step.to_send.len(), 1, "one answer: {:?}", step.notes);
    step.to_send[0].decision().outcome.clone()
}

fn rejected_with(step: &Step, error_id: &str) -> bool {
    matches!(outcome(step), Outcome::Reject(why) if why.contains(error_id))
}

/// P-2: the ledger time may be at most `ledgerTimeRecordTimeTolerance` (60 s by default) away from the sequencing time.
#[test]
fn a_request_sequenced_too_long_after_its_ledger_time_is_rejected_and_locks_nothing() {
    let b = build(ParticipantIdentity::generate("late"));
    // the submitter itself answers this request malformed: it is sequenced after its max sequencing time (see the P-3 tests below)
    let mut rt = observing(&b);
    let step = rt.step(&delivered(&b, NOW + 60_000_001)).unwrap();
    assert!(
        rejected_with(&step, "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    assert_eq!(rt.ledger.in_flight(), 0, "a refused request locks nothing");
}

#[test]
fn a_request_sequenced_too_long_before_its_ledger_time_is_rejected() {
    let b = build(ParticipantIdentity::generate("early"));
    let mut rt = configured(&b);
    let step = rt.step(&delivered(&b, NOW - 60_000_001)).unwrap();
    assert!(
        rejected_with(&step, "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"),
        "{:?}",
        outcome(&step)
    );
}

#[test]
fn a_request_sequenced_within_the_tolerance_is_approved() {
    let b = build(ParticipantIdentity::generate("in-time"));
    let mut rt = configured(&b);
    let step = rt.step(&delivered(&b, NOW + 60_000_000)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    assert_eq!(rt.ledger.in_flight(), 1);
}

/// P-1: the authorizers of a top-level view's root action (an exercise's actors) must be among the submitting parties.
#[test]
fn an_exercise_whose_actor_is_not_a_submitting_party_is_malformed() {
    let b = build(ParticipantIdentity::generate("unauthorized"));
    let mut rt = configured(&b);
    rt.ledger
        .import(&b.stored.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    let envelopes = settle(&b, &b.erin, &[b.me.uid()]);
    let step = rt.step(&delivery(envelopes, NOW + 5)).unwrap();
    assert!(
        malformed_with(&step, "Missing authorization"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    assert_eq!(
        rt.ledger.in_flight(),
        0,
        "a malformed request locks nothing"
    );
}

#[test]
fn an_exercise_by_a_submitting_party_is_approved() {
    let b = build(ParticipantIdentity::generate("authorized"));
    let mut rt = configured(&b);
    rt.ledger
        .import(&b.stored.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    let envelopes = settle(&b, &b.erin, std::slice::from_ref(&b.erin));
    let step = rt.step(&delivery(envelopes, NOW + 5)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// P-1: when the topology is followed, the submitting participant must host every submitting party with submission permission.
#[test]
fn a_submitting_participant_that_only_confirms_for_the_submitting_party_is_refused() {
    let b = build(ParticipantIdentity::generate("confirming"));
    let mut rt = following(&b, &[erin_hosted(&b, 2)]);
    assert!(
        rt.config.hosted_parties.contains(&b.erin),
        "erin is hosted to confirm"
    );
    let step = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert!(
        malformed_with(&step, "is not authorized to submit on behalf of"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

#[test]
fn a_submitting_participant_with_submission_permission_is_approved() {
    let b = build(ParticipantIdentity::generate("submitting"));
    let mut rt = following(&b, &[erin_hosted(&b, 1)]);
    let step = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// The envelopes with the view message's submitting participant signature replaced by `by`'s signature over the root hash.
fn signed_by(b: &Built, by: &ParticipantIdentity) -> Vec<Addressed> {
    use canton_participant::topology_wire::{unversioned, versioned};
    use canton_proto::com::digitalasset::canton::protocol::v32::{
        envelope_content::SomeEnvelopeContent, EnvelopeContent,
    };
    use prost::Message;
    b.envelopes
        .iter()
        .map(|(to, e)| {
            let Some((inner, version)) = unversioned(e) else {
                return (to.clone(), e.clone());
            };
            let Ok(mut content) = EnvelopeContent::decode(inner.as_slice()) else {
                return (to.clone(), e.clone());
            };
            match content.some_envelope_content.as_mut() {
                Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(m)) => {
                    m.submitting_participant_signature =
                        Some(by.signing_key.sign_bytes(&b.root_hash));
                    (to.clone(), versioned(content.encode_to_vec(), version))
                }
                _ => (to.clone(), e.clone()),
            }
        })
        .collect()
}

/// P-3: the signature over the root hash is the submitting participant's, the one the submitter metadata names; another participant's key,
/// even one the topology lists, does not do.
#[test]
fn a_request_signed_by_another_participant_than_the_submitting_one_is_malformed() {
    let b = build(ParticipantIdentity::generate("named"));
    let other = ParticipantIdentity::generate("other");
    let mut transactions = vec![erin_hosted(&b, 1)];
    transactions.extend(other.onboarding_transactions("sync::1220aa"));
    let mut rt = following(&b, &transactions);
    assert!(
        rt.config
            .submitter_keys
            .iter()
            .any(|k| k.id == other.signing_key.fingerprint),
        "the other participant's key is known"
    );
    let step = rt.step(&delivery(signed_by(&b, &other), NOW + 5)).unwrap();
    assert!(
        malformed_with(&step, "BadSignature"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    assert_eq!(rt.ledger.in_flight(), 0);
}

#[test]
fn a_request_signed_by_the_submitting_participant_is_approved() {
    let b = build(ParticipantIdentity::generate("named-ok"));
    let other = ParticipantIdentity::generate("other-ok");
    let mut transactions = vec![erin_hosted(&b, 1)];
    transactions.extend(other.onboarding_transactions("sync::1220aa"));
    let mut rt = following(&b, &transactions);
    let step = rt.step(&delivery(signed_by(&b, &b.me), NOW + 5)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// Without the topology there is no telling whose key is whose: a runtime configured by hand trusts each key it is given for any submitter.
#[test]
fn a_runtime_configured_by_hand_keeps_trusting_every_key_it_was_given() {
    let b = build(ParticipantIdentity::generate("by-hand"));
    let other = ParticipantIdentity::generate("other-by-hand");
    let mut rt = configured(&b);
    rt.config.submitter_keys.push(raw_key(&other));
    let step = rt.step(&delivery(signed_by(&b, &other), NOW + 5)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    let stranger = ParticipantIdentity::generate("stranger");
    let mut rt = configured(&b);
    let step = rt
        .step(&delivery(signed_by(&b, &stranger), NOW + 5))
        .unwrap();
    assert!(
        malformed_with(&step, "BadSignature"),
        "{:?}",
        outcome(&step)
    );
}

/// The content of a mediator's verdict envelope about `request_id` with `root_hash`, and the hash its signatures cover.
fn verdict_content(request_id: i64, root_hash: &[u8], approve: bool) -> (Vec<u8>, Vec<u8>) {
    use canton_participant::topology_wire::versioned;
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        typed_signed_protocol_message_content::SomeSignedProtocolMessage, verdict::SomeVerdict,
        ConfirmationResultMessage, MediatorReject, TypedSignedProtocolMessageContent, Verdict,
    };
    use prost::Message;
    let verdict = if approve {
        SomeVerdict::Approve(())
    } else {
        SomeVerdict::MediatorReject(MediatorReject {
            reason: None,
            is_malformed: false,
        })
    };
    let message = ConfirmationResultMessage {
        physical_synchronizer_id: SYNC.into(),
        view_type: 1,
        request_id,
        root_hash: root_hash.to_vec(),
        verdict: Some(Verdict {
            some_verdict: Some(verdict),
        }),
    };
    let typed = TypedSignedProtocolMessageContent {
        some_signed_protocol_message: Some(SomeSignedProtocolMessage::ConfirmationResult(
            versioned(message.encode_to_vec(), 30),
        )),
    };
    let content = versioned(typed.encode_to_vec(), 30);
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, &content));
    (content, hash)
}

/// The event that delivers a verdict on `request_id` with `root_hash`, signed by each of `signers`, sequenced at `at`.
fn verdict_event(
    b: &Built,
    request_id: i64,
    root_hash: &[u8],
    signers: &[&ParticipantIdentity],
    at: i64,
) -> Delivered {
    let (content, hash) = verdict_content(request_id, root_hash, true);
    let mut event = delivery(vec![(vec![b.me.member()], content)], at);
    event.envelope_signatures = vec![signers
        .iter()
        .map(|m| m.signing_key.sign_bytes(&hash))
        .collect()];
    event
}

/// A mediator's key mapping (`MED::<uid>`) and nothing else of it: the identity only lends its signing key.
fn mediator_keys(
    mediator: &ParticipantIdentity,
) -> canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction {
    use canton_participant::topology_wire::{owner_to_key_mapping, signed};
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        public_key::Key, PublicKey, SigningKeyUsage,
    };
    let bytes = owner_to_key_mapping(
        &format!("MED::{}", mediator.uid()),
        vec![PublicKey {
            key: Some(Key::SigningPublicKey(
                mediator
                    .signing_key
                    .public_key(&[SigningKeyUsage::Protocol]),
            )),
        }],
    );
    signed(bytes, vec![])
}

fn mediator_group(
    group: u32,
    threshold: u32,
    active: &[&ParticipantIdentity],
) -> canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction {
    let uids: Vec<String> = active.iter().map(|m| m.uid()).collect();
    let refs: Vec<&str> = uids.iter().map(String::as_str).collect();
    canton_participant::topology_wire::signed(
        canton_participant::topology_wire::mediator_synchronizer_state(
            "sync::1220aa",
            group,
            threshold,
            &refs,
        ),
        vec![],
    )
}

const REQUEST: i64 = NOW + 5;

/// A configured runtime that approved the create and waits for its verdict, trusting `mediator`'s key.
fn approved_by_hand(b: &Built, mediator: &ParticipantIdentity) -> Runtime {
    let mut rt = configured(b);
    rt.config.mediator_keys = vec![raw_key(mediator)];
    let step = rt.step(&delivered(b, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    rt
}

fn applied(step: &Step) -> bool {
    step.verdicts == vec![(REQUEST, true)]
}

/// P-5: a verdict is about the request whose root hash it names; one with another root hash changes nothing.
#[test]
fn a_verdict_with_another_root_hash_is_not_applied() {
    let b = build(ParticipantIdentity::generate("other-root"));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = approved_by_hand(&b, &mediator);
    let mut root = b.root_hash.clone();
    root[5] ^= 1;
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &root,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(!applied(&step), "{:?}", step.notes);
    assert!(
        step.notes.iter().any(|n| n.contains("root hash")),
        "{:?}",
        step.notes
    );
    assert_eq!(rt.ledger.in_flight(), 1, "still waiting for its verdict");
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &b.root_hash,
            &[&mediator],
            REQUEST + 20,
        ))
        .unwrap();
    assert!(
        applied(&step),
        "the right verdict still resolves it: {:?}",
        step.notes
    );
}

/// P-5: a verdict sequenced after the request's decision time comes too late; the request times out instead.
#[test]
fn a_verdict_after_the_decision_time_is_ignored_and_the_request_expires() {
    let b = build(ParticipantIdentity::generate("late-verdict"));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = approved_by_hand(&b, &mediator);
    let decision_time = Timeouts::default().decision_time(REQUEST);
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &b.root_hash,
            &[&mediator],
            decision_time + 1,
        ))
        .unwrap();
    assert!(!applied(&step), "{:?}", step.notes);
    assert_eq!(step.expired, vec![REQUEST], "{:?}", step.notes);
    assert!(step.applied.is_empty(), "nothing created");
}

#[test]
fn a_verdict_at_the_decision_time_is_applied() {
    let b = build(ParticipantIdentity::generate("on-time-verdict"));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = approved_by_hand(&b, &mediator);
    let decision_time = Timeouts::default().decision_time(REQUEST);
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &b.root_hash,
            &[&mediator],
            decision_time,
        ))
        .unwrap();
    assert!(applied(&step), "{:?}", step.notes);
    assert_eq!(step.applied.len(), 1);
}

/// P-5: a verdict that comes again after the request expired is set aside like the first late one (what the participant kept of the
/// request is gone by then).
#[test]
fn a_second_verdict_after_the_request_expired_is_set_aside_too() {
    let b = build(ParticipantIdentity::generate("late-twice"));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = approved_by_hand(&b, &mediator);
    let decision_time = Timeouts::default().decision_time(REQUEST);
    let late = |rt: &mut Runtime, at: i64| {
        rt.step(&verdict_event(&b, REQUEST, &b.root_hash, &[&mediator], at))
            .unwrap()
    };
    assert_eq!(late(&mut rt, decision_time + 1).expired, vec![REQUEST]);
    let again = late(&mut rt, decision_time + 2);
    assert!(
        again
            .notes
            .iter()
            .any(|n| n.contains("after the decision time")),
        "{:?}",
        again.notes
    );
    assert!(again.verdicts.is_empty() && again.applied.is_empty());
}

/// A runtime of `b` configured by hand that keeps its state in `dir` and trusts `mediator`'s key.
fn kept_in(b: &Built, mediator: &ParticipantIdentity, dir: &Path) -> Runtime {
    let mut config = configured(b).config;
    config.mediator_keys = vec![raw_key(mediator)];
    Runtime::open(config, Engine::load(&dar()).unwrap(), Some(dir), 0).unwrap()
}

fn state_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "canton-rs-request-validation-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// P-5: what a verdict is checked against survives a restart: a verdict with another root hash is still refused, the right one applied.
#[test]
fn a_restarted_participant_still_checks_the_verdict_against_the_request() {
    let b = build(ParticipantIdentity::generate("restart"));
    let mediator = ParticipantIdentity::generate("mediator");
    let dir = state_dir("restart");
    let mut rt = kept_in(&b, &mediator, &dir);
    let step = rt.step(&delivered(&b, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    drop(rt);

    let mut rt = kept_in(&b, &mediator, &dir);
    let mut root = b.root_hash.clone();
    root[5] ^= 1;
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &root,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(!applied(&step), "{:?}", step.notes);
    assert!(
        step.notes.iter().any(|n| n.contains("root hash")),
        "{:?}",
        step.notes
    );
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &b.root_hash,
            &[&mediator],
            REQUEST + 20,
        ))
        .unwrap();
    assert!(applied(&step), "{:?}", step.notes);
    let _ = std::fs::remove_dir_all(&dir);
}

/// What is kept of a request does not outlive its decision time: after a restart the store holds only the requests still in flight.
#[test]
fn a_restart_drops_what_was_kept_of_the_requests_that_expired() {
    let b = build(ParticipantIdentity::generate("kept"));
    let mediator = ParticipantIdentity::generate("mediator");
    let dir = state_dir("kept");
    let journal = || std::fs::read_to_string(dir.join("requests.journal")).unwrap_or_default();

    let mut rt = kept_in(&b, &mediator, &dir);
    rt.step(&delivered(&b, REQUEST)).unwrap();
    drop(rt);
    drop(kept_in(&b, &mediator, &dir));
    assert_eq!(
        journal().lines().count(),
        1,
        "a request in flight is kept across a restart"
    );

    let mut rt = kept_in(&b, &mediator, &dir);
    let decision_time = Timeouts::default().decision_time(REQUEST);
    let step = rt.step(&delivery(vec![], decision_time + 1)).unwrap();
    assert_eq!(step.expired, vec![REQUEST], "{:?}", step.notes);
    drop(rt);
    drop(kept_in(&b, &mediator, &dir));
    assert_eq!(journal(), "", "an expired request is not kept");
    let _ = std::fs::remove_dir_all(&dir);
}

/// P-5: with the topology followed, the verdict is signed by the threshold of distinct active mediators of the group the request named.
#[test]
fn a_verdict_needs_the_threshold_of_the_requests_mediator_group() {
    let b = build(ParticipantIdentity::generate("group"));
    let (m1, m2, outsider) = (
        ParticipantIdentity::generate("m1"),
        ParticipantIdentity::generate("m2"),
        ParticipantIdentity::generate("m-other"),
    );
    let topology = [
        erin_hosted(&b, 1),
        mediator_keys(&m1),
        mediator_keys(&m2),
        mediator_keys(&outsider),
        mediator_group(0, 2, &[&m1, &m2]),
        mediator_group(1, 1, &[&outsider]),
    ];
    let mut rt = following(&b, &topology);
    let step = rt.step(&delivered(&b, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    for (signers, why) in [
        (vec![&outsider], "a mediator of another group"),
        (vec![&m1], "one mediator of a group of threshold 2"),
        (vec![&m1, &m1], "the same mediator twice"),
    ] {
        let step = rt
            .step(&verdict_event(
                &b,
                REQUEST,
                &b.root_hash,
                &signers,
                REQUEST + 10,
            ))
            .unwrap();
        assert!(!applied(&step), "{why}: {:?}", step.notes);
        assert_eq!(rt.ledger.in_flight(), 1, "{why}");
    }
    let step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &b.root_hash,
            &[&m1, &m2],
            REQUEST + 20,
        ))
        .unwrap();
    assert!(applied(&step), "{:?}", step.notes);
}

fn is_root_hash_message(content: &[u8]) -> bool {
    canton_participant::view_receive::root_hash_of_message(content).is_some()
}

/// The envelopes of `b` with the root hash message's recipients and content replaced by what `change` makes of them.
fn with_root_hash_message(
    b: &Built,
    change: impl Fn(&Addressed) -> Vec<Addressed>,
) -> Vec<Addressed> {
    b.envelopes
        .iter()
        .flat_map(|e| {
            if is_root_hash_message(&e.1) {
                change(e)
            } else {
                vec![e.clone()]
            }
        })
        .collect()
}

fn noted(step: &Step, text: &str) -> bool {
    step.notes.iter().any(|n| n.contains(text))
}

/// P-11: a root hash message counts only when it is sent to a mediator group; without one the views are no request.
#[test]
fn views_whose_root_hash_message_is_not_sent_to_a_mediator_are_not_answered() {
    let b = build(ParticipantIdentity::generate("no-mediator"));
    let mut rt = configured(&b);
    let envelopes = with_root_hash_message(&b, |(_, c)| vec![(vec![b.me.member()], c.clone())]);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(step.to_send.is_empty(), "{:?}", step.to_send);
    assert!(noted(&step, "not sent to a mediator"), "{:?}", step.notes);
    assert_eq!(rt.ledger.in_flight(), 0);

    let mut rt = configured(&b);
    let step = rt.step(&delivered(&b, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// P-11: two root hash messages to the mediator: the mediator refuses the request, so the participant drops it without an answer.
#[test]
fn a_request_with_two_root_hash_messages_is_dropped_without_an_answer() {
    let b = build(ParticipantIdentity::generate("two-hashes"));
    let mut rt = configured(&b);
    let envelopes = with_root_hash_message(&b, |e| vec![e.clone(), e.clone()]);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(step.to_send.is_empty(), "{:?}", step.to_send);
    assert!(
        noted(&step, "Multiple root hash messages"),
        "{:?}",
        step.notes
    );
    assert_eq!(rt.ledger.in_flight(), 0);
}

/// P-11: a root hash message of another view type than the views is answered as malformed, to the message's mediator group.
#[test]
fn views_of_another_type_than_the_root_hash_message_are_answered_as_malformed() {
    use canton_participant::confirmation_wire::root_hash_message_of_type;
    use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;
    let b = build(ParticipantIdentity::generate("other-type"));
    let mut rt = configured(&b);
    let envelopes = with_root_hash_message(&b, |(to, _)| {
        vec![(
            to.clone(),
            root_hash_message_of_type(ViewType::Assignment, &b.root_hash, SYNC, NOW),
        )]
    });
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        malformed_with(&step, "LOCAL_VERDICT_BAD_ROOT_HASH_MESSAGES"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    assert_eq!(step.to_send[0].root_hash, b.root_hash);
    assert_eq!(step.to_send[0].mediator_group, 0);
    assert_eq!(rt.ledger.in_flight(), 0, "nothing is locked");
}

/// The view message of `b` relabelled with `view_type`.
fn view_of_type(
    b: &Built,
    view_type: canton_proto::com::digitalasset::canton::protocol::v30::ViewType,
) -> Addressed {
    use canton_participant::topology_wire::{unversioned, versioned};
    use canton_proto::com::digitalasset::canton::protocol::v32::{
        envelope_content::SomeEnvelopeContent, EnvelopeContent,
    };
    use prost::Message;
    b.envelopes
        .iter()
        .find_map(|(to, e)| {
            let (inner, version) = unversioned(e)?;
            let mut content = EnvelopeContent::decode(inner.as_slice()).ok()?;
            match content.some_envelope_content.as_mut() {
                Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(m)) => {
                    m.view_type = view_type as i32;
                    Some((to.clone(), versioned(content.encode_to_vec(), version)))
                }
                _ => None,
            }
        })
        .unwrap()
}

/// P-11: a view of another type next to the views of the message's type is set aside with an alarm; the request goes on.
#[test]
fn a_view_of_another_type_beside_the_request_is_set_aside() {
    use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;
    let b = build(ParticipantIdentity::generate("extra-view"));
    let mut rt = configured(&b);
    let mut envelopes = b.envelopes.clone();
    envelopes.push(view_of_type(&b, ViewType::Assignment));
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    assert!(noted(&step, "Expected view type"), "{:?}", step.notes);
}

/// P-11: a batch with both a request and a topology broadcast is dropped (every recipient of the request got the broadcast too).
#[test]
fn a_request_in_a_batch_with_a_topology_broadcast_is_dropped() {
    use canton_participant::topology_wire::{topology_broadcast, ALL_MEMBERS};
    let b = build(ParticipantIdentity::generate("with-topology"));
    let mut rt = configured(&b);
    let mut envelopes = b.envelopes;
    envelopes.push((vec![ALL_MEMBERS.into()], topology_broadcast(SYNC, &[])));
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(step.to_send.is_empty(), "{:?}", step.to_send);
    assert!(step.topology_changed);
    assert!(
        noted(&step, "both a request and topology transaction"),
        "{:?}",
        step.notes
    );
    assert_eq!(rt.ledger.in_flight(), 0);
}

/// P-11: the views must declare the mediator group the root hash message goes to; otherwise the request is not processed.
#[test]
fn views_that_declare_another_mediator_than_the_root_hash_message_are_not_processed() {
    let b = build_for_group(ParticipantIdentity::generate("other-mediator"), 1);
    let mut rt = configured(&b);
    let envelopes = with_root_hash_message(&b, |(_, c)| {
        vec![(vec!["MGR::0".into(), b.me.member()], c.clone())]
    });
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(step.to_send.is_empty(), "{:?}", step.to_send);
    assert!(noted(&step, "declared in views"), "{:?}", step.notes);
    assert_eq!(rt.ledger.in_flight(), 0);

    let mut rt = configured(&b);
    let step = rt.step(&delivered(&b, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    assert_eq!(
        step.to_send[0].mediator_group, 1,
        "answered to the request's group"
    );
}

/// P-11: a root hash message with recipients of another shape only raises an alarm.
#[test]
fn a_root_hash_message_with_more_recipients_is_noted_and_processed() {
    let b = build(ParticipantIdentity::generate("wide-hash"));
    let mut rt = configured(&b);
    let envelopes = with_root_hash_message(&b, |(to, c)| {
        let mut to = to.clone();
        to.push("PAR::someone::1220ff".into());
        vec![(to, c.clone())]
    });
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    assert!(noted(&step, "invalid recipient groups"), "{:?}", step.notes);
}

/// The verdict event approving or rejecting the request `b` at `REQUEST`, signed by `mediator`.
fn verdict_on(b: &Built, mediator: &ParticipantIdentity, approve: bool, at: i64) -> Delivered {
    let (content, hash) = verdict_content(REQUEST, &b.root_hash, approve);
    let mut event = delivery(vec![(vec![b.me.member()], content)], at);
    event.envelope_signatures = vec![vec![mediator.signing_key.sign_bytes(&hash)]];
    event
}

/// P-12: a request this participant rejected (here: sequenced too late) that the mediator approves is committed, as Canton does after its
/// warning; a rejecting verdict changes nothing.
#[test]
fn a_request_rejected_here_that_the_mediator_approves_is_committed() {
    let b = build(ParticipantIdentity::generate("overruled"));
    let mediator = ParticipantIdentity::generate("mediator");
    let late = REQUEST + 60_000_001;
    for approve in [true, false] {
        // not the submitter, which answers a request sequenced after its max sequencing time malformed (P-3)
        let mut rt = observing(&b);
        rt.config.mediator_keys = vec![raw_key(&mediator)];
        let step = rt.step(&delivered(&b, late)).unwrap();
        assert!(
            rejected_with(&step, "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"),
            "{:?}",
            outcome(&step)
        );
        assert_eq!(rt.ledger.in_flight(), 0, "a refused request locks nothing");
        let (content, hash) = verdict_content(late, &b.root_hash, approve);
        let mut event = delivery(vec![(vec![b.me.member()], content)], late + 10);
        event.envelope_signatures = vec![vec![mediator.signing_key.sign_bytes(&hash)]];
        let step = rt.step(&event).unwrap();
        assert_eq!(step.verdicts, vec![(late, approve)], "{:?}", step.notes);
        assert_eq!(
            rt.ledger.is_active(&b.stored.contract_id_hex),
            approve,
            "approved: {approve} {:?}",
            step.notes
        );
        assert_eq!(step.applied.len(), usize::from(approve));
        assert_eq!(
            noted(
                &step,
                "Mediator approved a request that has been locally rejected"
            ),
            approve,
            "{:?}",
            step.notes
        );
    }
}

/// P-12: a view that does not conform has no effects Canton trusts: an approving verdict commits nothing of it.
#[test]
fn a_view_that_does_not_conform_is_not_committed_when_the_mediator_approves() {
    let me = ParticipantIdentity::generate("nonconforming");
    let zed = me.party_id("zed");
    let b = build_holding(me, 0, Some(&zed));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = configured(&b);
    rt.config.mediator_keys = vec![raw_key(&mediator)];
    let step = rt.step(&delivered(&b, REQUEST)).unwrap();
    assert!(
        malformed_with(&step, "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "{:?}",
        outcome(&step)
    );
    assert!(
        !step.to_send[0].decision().view_position.is_empty(),
        "a malformed view is answered for its position"
    );
    let step = rt
        .step(&verdict_on(&b, &mediator, true, REQUEST + 10))
        .unwrap();
    assert!(step.applied.is_empty(), "{:?}", step.applied);
    assert!(!rt.ledger.is_active(&b.stored.contract_id_hex));
}

/// What a participant keeps of a request it rejected survives a restart: the approving verdict still commits it.
#[test]
fn a_request_rejected_here_is_committed_on_approval_after_a_restart() {
    let b = build(ParticipantIdentity::generate("overruled-restart"));
    let mediator = ParticipantIdentity::generate("mediator");
    let dir = state_dir("overruled");
    let late = REQUEST + 60_000_001;
    // not the submitter, which answers a request sequenced after its max sequencing time malformed (P-3)
    let observer = |dir: &Path| {
        let mut config = observing(&b).config;
        config.mediator_keys = vec![raw_key(&mediator)];
        Runtime::open(config, Engine::load(&dar()).unwrap(), Some(dir), 0).unwrap()
    };
    let mut rt = observer(&dir);
    let step = rt.step(&delivered(&b, late)).unwrap();
    assert!(matches!(outcome(&step), Outcome::Reject(_)));
    drop(rt);
    let mut rt = observer(&dir);
    let (content, hash) = verdict_content(late, &b.root_hash, true);
    let mut event = delivery(vec![(vec![b.me.member()], content)], late + 10);
    event.envelope_signatures = vec![vec![mediator.signing_key.sign_bytes(&hash)]];
    let step = rt.step(&event).unwrap();
    assert_eq!(step.verdicts, vec![(late, true)], "{:?}", step.notes);
    assert!(rt.ledger.is_active(&b.stored.contract_id_hex));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A runtime of `b` that knows the created holding as active (an import), trusting `mediator`.
fn holding_known(b: &Built, mediator: &ParticipantIdentity) -> Runtime {
    let mut rt = configured(b);
    rt.config.mediator_keys = vec![raw_key(mediator)];
    rt.ledger
        .import(&b.stored.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    rt
}

/// P-4: a fetch of an active contract is approved and does not lock it: a request that consumes it may follow.
#[test]
fn a_fetch_of_an_active_contract_is_approved_without_locking_it() {
    let b = build(ParticipantIdentity::generate("fetch-active"));
    let mut rt = holding_known(&b, &ParticipantIdentity::generate("mediator"));
    let step = rt.step(&delivery(fetch(&b, &b.stored), REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    let step = rt
        .step(&delivery(
            settle(&b, &b.erin, std::slice::from_ref(&b.erin)),
            REQUEST + 1,
        ))
        .unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// P-4: a fetch of an archived contract is rejected.
#[test]
fn a_fetch_of_an_archived_contract_is_rejected() {
    let b = build(ParticipantIdentity::generate("fetch-archived"));
    let mut rt = holding_known(&b, &ParticipantIdentity::generate("mediator"));
    rt.ledger
        .begin(
            REQUEST - 1,
            canton_participant::view_acs::Effects {
                consumes: vec![b.stored.contract_id_hex.clone()],
                creates: vec![],
                instances: vec![],
                remote_events: vec![],
            },
        )
        .unwrap();
    rt.ledger.resolve(REQUEST - 1, true).unwrap();
    let step = rt.step(&delivery(fetch(&b, &b.stored), REQUEST)).unwrap();
    assert!(
        rejected_with(&step, "ArchivedContract"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-4: a fetch of a contract another request in flight consumes is rejected as locked.
#[test]
fn a_fetch_of_a_contract_another_request_consumes_is_rejected() {
    let b = build(ParticipantIdentity::generate("fetch-locked"));
    let mut rt = holding_known(&b, &ParticipantIdentity::generate("mediator"));
    let step = rt
        .step(&delivery(
            settle(&b, &b.erin, std::slice::from_ref(&b.erin)),
            REQUEST - 1,
        ))
        .unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    let step = rt.step(&delivery(fetch(&b, &b.stored), REQUEST)).unwrap();
    assert!(
        rejected_with(&step, "LockedContract"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-4: a contract none of whose stakeholders this participant hosts is not checked for activeness (it need not know it).
#[test]
fn a_fetch_of_a_contract_of_no_hosted_stakeholder_is_not_checked() {
    let b = build(ParticipantIdentity::generate("fetch-foreign"));
    let mut rt = configured(&b);
    rt.config.hosted_parties = vec![b.me.uid()];
    let step = rt.step(&delivery(fetch(&b, &b.stored), REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    let mut rt = configured(&b);
    let step = rt.step(&delivery(fetch(&b, &b.stored), REQUEST)).unwrap();
    assert!(
        rejected_with(&step, "UnknownContract"),
        "hosted, the unknown contract is refused: {:?}",
        outcome(&step)
    );
}

/// `stored` with its contract id changed in the last byte (its instance then no longer authenticates the id).
fn forged(stored: &StoredContract) -> StoredContract {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use prost::Message;
    let mut versioned = Versioned::decode(stored.instance.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(versioned.payload.as_slice()).unwrap();
    let last = fci.contract_id.len() - 1;
    fci.contract_id[last] ^= 1;
    versioned.payload = fci.encode_to_vec();
    StoredContract {
        contract_id_hex: hex::encode(&fci.contract_id),
        instance: versioned.encode_to_vec(),
        ..stored.clone()
    }
}

/// P-4: the fetched contract's id must be the one its instance and salt give (`SerializableContractAuthenticator`).
#[test]
fn a_fetch_of_a_contract_whose_id_does_not_authenticate_is_malformed() {
    let b = build(ParticipantIdentity::generate("fetch-forged"));
    let fake = forged(&b.stored);
    let mut rt = configured(&b);
    rt.ledger
        .import(&fake.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    let step = rt.step(&delivery(fetch(&b, &fake), REQUEST)).unwrap();
    // the reinterpretation authenticates the input contracts: a failure there is a failed model conformance check
    assert!(
        malformed_with(&step, "ContractIdDiffers"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-10: the informees of a view are exactly those its action gives: an exercise that claims a choice observer the choice does not have
/// informs a party it should not, and does not conform.
#[test]
fn an_exercise_with_an_informee_its_action_does_not_give_is_malformed() {
    let b = build(ParticipantIdentity::generate("extra-informee"));
    let zed = b.me.party_id("zed");
    let mut rt = holding_known(&b, &ParticipantIdentity::generate("mediator"));
    let envelopes = settle_observed(&b, &b.erin, std::slice::from_ref(&b.erin), &[zed]);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        malformed_with(&step, "InformeesDiffer"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    let mut rt = holding_known(&b, &ParticipantIdentity::generate("mediator"));
    let envelopes = settle(&b, &b.erin, std::slice::from_ref(&b.erin));
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

fn chain_dar() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/chain/target/nested-chain.dar")
}

/// `Chain.Inbox.Start` submitted by `me` for its owner, with `peer1` on `me` and `peer2` on another participant: the root view holds the
/// `Hop` create and the `Forward` exercise in its core, and the `Note` that `peer2` observes is a subview. The envelopes addressed to `me`,
/// the inbox and a runtime of `me` that knows it.
struct Chain {
    envelopes: Vec<Addressed>,
    runtime: Runtime,
}

fn chain(me: ParticipantIdentity) -> Chain {
    use canton_participant::view_tree::NewContract;
    let other = ParticipantIdentity::generate("chain-other");
    let (owner, peer1, peer2) = (
        me.party_id("owner"),
        me.party_id("peer1"),
        other.party_id("peer2"),
    );
    let world = World::open(&chain_dar()).unwrap();
    let types = Types::new(&world);
    let package = world.main_package_id().to_string();
    let record = |template: &str, fields: Vec<(&str, Value)>| {
        let ty = types.template(&package, template).unwrap();
        let value = Value::Record {
            tycon: Some(template.into()),
            fields: fields.into_iter().map(|(n, v)| (n.into(), v)).collect(),
        };
        forms(&types, &ty, &value).unwrap()
    };
    let peer_of = |id: &ParticipantIdentity| Peer {
        member: id.member(),
        encryption_spki: id.encryption_spki().to_vec(),
        fingerprint: id.encryption_fingerprint(),
    };
    let context = Context {
        identity: &me,
        synchronizer: SYNC,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let (arg, hash_arg) = record("Chain:Inbox", vec![("owner", Value::Party(owner.clone()))]);
    let inbox = build_create(
        &context,
        &Create {
            package_name: "nested-chain",
            package_id: &package,
            module: vec!["Chain".into()],
            name: vec!["Inbox".into()],
            arg,
            hash_arg,
            signatories: vec![owner.clone()],
            stakeholders: vec![owner.clone()],
            hosts: vec![peer_of(&me)],
            command_id: "inbox".into(),
            key: None,
        },
        NOW,
        &mut Counter(0),
    )
    .unwrap();
    let new = |name: &str, signatories: Vec<String>, stakeholders: Vec<String>, fields| {
        let (arg, hash_arg) = record(&format!("Chain:{name}"), fields);
        NewContract {
            package_name: "nested-chain".into(),
            package_id: package.clone(),
            module: vec!["Chain".into()],
            name: vec![name.into()],
            arg,
            hash_arg,
            signatories,
            stakeholders,
            key: None,
        }
    };
    let msg = || Value::Text("hi".into());
    let parties = || {
        vec![
            ("owner", Value::Party(owner.clone())),
            ("peer1", Value::Party(peer1.clone())),
            ("peer2", Value::Party(peer2.clone())),
            ("msg", msg()),
        ]
    };
    let hop = new(
        "Hop",
        vec![owner.clone()],
        vec![owner.clone(), peer1.clone()],
        parties(),
    );
    let note = new(
        "Note",
        vec![owner.clone()],
        vec![owner.clone(), peer1.clone(), peer2.clone()],
        parties(),
    );
    let stored_inbox = StoredContract {
        contract_id_hex: inbox.contract_id_hex.clone(),
        instance: inbox.instance.clone(),
        package_id: package.clone(),
        module: vec!["Chain".into()],
        name: vec!["Inbox".into()],
        signatories: vec![owner.clone()],
        stakeholders: vec![owner.clone()],
    };
    use canton_participant::contract_wire::LfValue;
    let tx = Transaction {
        nodes: vec![
            Action::Exercise {
                contract: stored_inbox,
                choice: "Start".into(),
                argument: Some(LfValue::Record(vec![
                    LfValue::Party(peer1.clone()),
                    LfValue::Party(peer2.clone()),
                    LfValue::Text("hi".into()),
                ])),
                consuming: false,
                actors: vec![owner.clone()],
                choice_observers: vec![],
                children: vec![1, 2],
                interface_id: None,
            },
            Action::Create(hop),
            Action::Exercise {
                contract: StoredContract {
                    contract_id_hex: "#1".into(),
                    instance: Vec::new(),
                    package_id: package.clone(),
                    module: vec!["Chain".into()],
                    name: vec!["Hop".into()],
                    signatories: vec![owner.clone()],
                    stakeholders: vec![owner.clone(), peer1.clone()],
                },
                choice: "Forward".into(),
                argument: Some(LfValue::Record(vec![])),
                consuming: true,
                actors: vec![owner.clone()],
                choice_observers: vec![],
                children: vec![3],
                interface_id: None,
            },
            Action::Create(note),
        ],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: [("#1".to_string(), 1)].into_iter().collect(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let (me_member, other_member) = (me.member(), other.member());
    let peer2_hosted = peer2.clone();
    let built = build_transaction(
        &context,
        &tx,
        &[peer_of(&me), peer_of(&other)],
        &move |party: &str| {
            if party == peer2_hosted {
                [other_member.clone()].into()
            } else {
                [me_member.clone()].into()
            }
        },
        std::slice::from_ref(&owner),
        "start",
        NOW,
        None,
        &mut Counter(100),
    )
    .unwrap();
    let envelopes = built
        .envelopes
        .into_iter()
        .filter(|(to, _)| to.contains(&me.member()))
        .collect();
    let config = Config {
        member: me.member(),
        encryption_fingerprint: me.encryption_fingerprint(),
        encryption_secret: *me.encryption_secret(),
        hosted_parties: vec![owner, peer1, me.uid()],
        timeouts: Timeouts::default(),
        submitter_keys: vec![raw_key(&me)],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: SYNC.into(),
        follow_topology: false,
        topology_change_delay_micros: 250_000,
    };
    let mut runtime = Runtime::open(config, Engine::load(&chain_dar()).unwrap(), None, 0).unwrap();
    runtime
        .ledger
        .import(&inbox.contract_id_hex, "Chain:Inbox")
        .unwrap();
    Chain { envelopes, runtime }
}

/// P-10: a view with subviews and creates in its core: the discriminators are checked with the replay's positions, and the request the
/// submitting code built passes.
#[test]
fn a_view_with_a_subview_and_creates_in_its_core_is_approved() {
    let mut c = chain(ParticipantIdentity::generate("chain"));
    let step = c
        .runtime
        .step(&delivery(c.envelopes.clone(), REQUEST))
        .unwrap();
    assert_eq!(step.to_send.len(), 1, "{:?}", step.notes);
    let decisions = &step.to_send[0].decisions;
    assert!(
        decisions.len() >= 2,
        "the root view and its subview: {decisions:?}"
    );
    assert!(
        decisions.iter().all(|d| d.outcome == Outcome::Approve),
        "{decisions:?} {:?}",
        step.notes
    );
}

/// P-10: with the replay's positions, the discriminators of the creates in the core of a view **with subviews** are checked: the same root view
/// of the chain request fails with another preparation time.
#[test]
fn the_discriminators_of_a_view_with_subviews_are_checked() {
    use canton_participant::view_conformance::{
        check_discriminators_at, check_exercise_view_in_request, Nonconformance,
    };
    use canton_participant::view_receive::{
        check_views, decrypt_views, revealed_common_metadata, revealed_participant_metadata,
        root_hash_of_message,
    };
    let me = ParticipantIdentity::generate("chain-discriminators");
    let (fingerprint, secret) = (me.encryption_fingerprint(), *me.encryption_secret());
    let c = chain(me);
    let root_hash = c
        .envelopes
        .iter()
        .find_map(|(_, e)| root_hash_of_message(e))
        .unwrap();
    let mut revealed = Vec::new();
    let mut tree = None;
    for (_, e) in &c.envelopes {
        if let Ok(views) = decrypt_views(e, &fingerprint, &secret) {
            tree = views.view_trees[0].tree.clone();
            revealed.extend(check_views(&views, &root_hash, |_, _| true).unwrap());
        }
    }
    let tree = tree.unwrap();
    let root = revealed.iter().find(|v| v.position.len() == 1).unwrap();
    assert!(root.has_subviews, "the Note is a subview of the root");
    assert!(
        !root.participant_data.created_core.is_empty(),
        "the Hop is created in the root's core"
    );
    let subviews: Vec<_> = revealed.iter().filter(|v| v.position.len() > 1).collect();
    let common = revealed_common_metadata(&tree).unwrap();
    let (_, positions, _) =
        check_exercise_view_in_request(&c.runtime.engine, root, &subviews, &common).unwrap();
    let preparation = revealed_participant_metadata(&tree)
        .unwrap()
        .preparation_time;
    assert_eq!(
        check_discriminators_at(root, preparation, Some(&positions)),
        Ok(())
    );
    assert!(matches!(
        check_discriminators_at(root, preparation + 1, Some(&positions)),
        Err(Nonconformance::DiscriminatorDiffers { .. })
    ));
}

/// A runtime like [`configured`] that is not the submitting participant of `b`'s requests (its uid is another one).
fn observing(b: &Built) -> Runtime {
    let mut rt = configured(b);
    rt.config.member = "PAR::observer::1220bb".into();
    rt
}

/// P-3: the submitting participant answers a request with the root hash of one it already saw as malformed (`SubmissionTracker`).
#[test]
fn a_replay_of_an_own_request_is_answered_malformed_by_its_submitter() {
    let b = build(ParticipantIdentity::generate("replayed"));
    let mut rt = configured(&b);
    let first = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert_eq!(outcome(&first), Outcome::Approve, "{:?}", first.notes);
    let again = rt.step(&delivered(&b, NOW + 10)).unwrap();
    assert!(
        malformed_with(&again, "replayed"),
        "{:?} {:?}",
        outcome(&again),
        again.notes
    );
}

/// The replay check is the submitter's only: another participant judges the replay on its content (here its create conflicts).
#[test]
fn a_replay_is_not_answered_malformed_by_another_participant() {
    let b = build(ParticipantIdentity::generate("replay-seen"));
    let mut rt = observing(&b);
    let first = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert_eq!(outcome(&first), Outcome::Approve, "{:?}", first.notes);
    let again = rt.step(&delivered(&b, NOW + 10)).unwrap();
    assert!(
        matches!(outcome(&again), Outcome::Reject(_)),
        "{:?}",
        outcome(&again)
    );
}

/// P-3: an own request sequenced after its max sequencing time (60 s after `NOW`) is not timely: the submitter answers it malformed.
#[test]
fn an_own_request_sequenced_after_its_max_sequencing_time_is_malformed() {
    let b = build(ParticipantIdentity::generate("untimely"));
    let mut rt = configured(&b);
    let step = rt.step(&delivered(&b, NOW + 60_000_001)).unwrap();
    assert!(
        malformed_with(&step, "replayed"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-3: what makes a request fresh survives a restart: the replay is still refused, the request itself read again is not.
#[test]
fn a_replay_after_a_restart_is_still_detected() {
    let b = build(ParticipantIdentity::generate("replay-restart"));
    let mediator = ParticipantIdentity::generate("mediator");
    let dir = state_dir("replay-restart");
    let mut rt = kept_in(&b, &mediator, &dir);
    let first = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert_eq!(outcome(&first), Outcome::Approve, "{:?}", first.notes);
    drop(rt);
    let mut rt = kept_in(&b, &mediator, &dir);
    let again = rt.step(&delivered(&b, NOW + 10)).unwrap();
    assert!(
        malformed_with(&again, "replayed"),
        "{:?} {:?}",
        outcome(&again),
        again.notes
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The event of a mediator's timeout verdict (`MEDIATOR_SAYS_TX_TIMED_OUT`) on `b`'s request, signed by `mediator`, sequenced at `at`.
fn timeout_event(b: &Built, mediator: &ParticipantIdentity, at: i64) -> Delivered {
    use canton_participant::topology_wire::{unversioned, versioned};
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        typed_signed_protocol_message_content::SomeSignedProtocolMessage, verdict::SomeVerdict,
        ConfirmationResultMessage, MediatorReject, TypedSignedProtocolMessageContent, Verdict,
    };
    use prost::Message;
    let (content, _) = verdict_content(REQUEST, &b.root_hash, false);
    let typed =
        TypedSignedProtocolMessageContent::decode(unversioned(&content).unwrap().0.as_slice())
            .unwrap();
    let Some(SomeSignedProtocolMessage::ConfirmationResult(bytes)) =
        typed.some_signed_protocol_message
    else {
        panic!("a confirmation result")
    };
    let mut message =
        ConfirmationResultMessage::decode(unversioned(&bytes).unwrap().0.as_slice()).unwrap();
    message.verdict = Some(Verdict {
        some_verdict: Some(SomeVerdict::MediatorReject(MediatorReject {
            reason: Some(canton_proto::google::rpc::Status {
                code: 9,
                message: "MEDIATOR_SAYS_TX_TIMED_OUT(2,0): Rejected transaction as the mediator did not receive sufficient confirmations within the expected timeframe.".into(),
                details: vec![],
            }),
            is_malformed: false,
        })),
    });
    let typed = TypedSignedProtocolMessageContent {
        some_signed_protocol_message: Some(SomeSignedProtocolMessage::ConfirmationResult(
            versioned(message.encode_to_vec(), 30),
        )),
    };
    let content = versioned(typed.encode_to_vec(), 30);
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, &content));
    let mut event = delivery(vec![(vec![b.me.member()], content)], at);
    event.envelope_signatures = vec![vec![mediator.signing_key.sign_bytes(&hash)]];
    event
}

/// P-5: a timeout verdict sequenced before the participant response deadline is set aside (`TimeoutResultTooEarly`); after it, it rejects.
#[test]
fn a_timeout_verdict_before_the_response_deadline_is_set_aside() {
    let b = build(ParticipantIdentity::generate("early-timeout"));
    let mediator = ParticipantIdentity::generate("mediator");
    let mut rt = approved_by_hand(&b, &mediator);
    let deadline = Timeouts::default().response_deadline(REQUEST);
    let early = rt.step(&timeout_event(&b, &mediator, deadline)).unwrap();
    assert!(early.verdicts.is_empty(), "{:?}", early.notes);
    assert!(
        early.notes.iter().any(|n| n.contains("response deadline")),
        "{:?}",
        early.notes
    );
    assert_eq!(rt.ledger.in_flight(), 1, "still waiting for its verdict");
    let late = rt
        .step(&timeout_event(&b, &mediator, deadline + 1))
        .unwrap();
    assert_eq!(late.verdicts, vec![(REQUEST, false)], "{:?}", late.notes);
}

/// U-57 (review R1-F1): an unassignment to two recipient participants carries ONE root hash message envelope addressed to two recipient
/// groups `{mediator group, participant}`, as the official request does (`UnassignmentProcessingSteps.scala:337`,
/// `Recipients.recipientGroups`), not one envelope per participant.
#[test]
fn an_unassignment_sends_one_root_hash_message_to_a_group_per_participant() {
    use canton_participant::reassignment_submit::{unassignment, Unassignment};
    let b = build(ParticipantIdentity::generate("u57-unassign"));
    let other = ParticipantIdentity::generate("u57-other");
    let peer_of = |p: &ParticipantIdentity| Peer {
        member: p.member(),
        encryption_spki: p.encryption_spki().to_vec(),
        fingerprint: p.encryption_fingerprint(),
    };
    let built = unassignment(
        &b.me,
        &Unassignment {
            source: SYNC,
            target: "sync2::1220cc::37-0",
            target_time_micros: NOW,
            instance: &b.stored.instance,
            current_counter: 0,
            submitter: &b.erin,
            command_id: "unassign-u57",
            user_id: "rust-user",
            reassigning_participant_uids: &[b.me.uid(), other.uid()],
            recipients: &[peer_of(&b.me), peer_of(&other)],
            now_micros: NOW,
        },
        &mut Counter(300),
    )
    .unwrap();
    let grouped: Vec<&Vec<Vec<String>>> = built
        .envelopes
        .iter()
        .map(|(groups, _)| groups)
        .filter(|groups| groups.len() > 1)
        .collect();
    assert_eq!(
        grouped,
        vec![&vec![
            vec!["MGR::0".to_string(), b.me.member()],
            vec!["MGR::0".to_string(), other.member()],
        ]],
        "one root hash message envelope, one group per recipient participant: {:?}",
        built.envelopes.iter().map(|(g, _)| g).collect::<Vec<_>>()
    );
    assert_eq!(
        built.envelopes.len(),
        3,
        "mediator message, view, root hash message"
    );
}

/// The envelopes addressed to `me` of an unassignment of `b`'s holding to another synchronizer, submitted by `me` for `submitter`.
fn unassignment_of(b: &Built, submitter: &str) -> Vec<Addressed> {
    use canton_participant::reassignment_submit::{unassignment, Unassignment};
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let built = unassignment(
        &b.me,
        &Unassignment {
            source: SYNC,
            target: "sync2::1220cc::37-0",
            target_time_micros: NOW,
            instance: &b.stored.instance,
            current_counter: 0,
            submitter,
            command_id: "unassign-1",
            user_id: "rust-user",
            reassigning_participant_uids: &[b.me.uid()],
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(300),
    )
    .unwrap();
    built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect()
}

/// A runtime that knows `b`'s holding as active here.
fn holding_here(mut rt: Runtime, b: &Built) -> Runtime {
    rt.ledger
        .import(&b.stored.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    rt
}

/// P-14: the submitter of a reassignment must be a stakeholder of its contracts (`ReassignmentValidation.checkSubmitter`).
#[test]
fn an_unassignment_whose_submitter_is_not_a_stakeholder_is_rejected() {
    let b = build(ParticipantIdentity::generate("unassign-submitter"));
    let mut rt = holding_here(configured(&b), &b);
    let step = rt
        .step(&delivery(unassignment_of(&b, &b.erin), REQUEST))
        .unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
    let zed = b.me.party_id("zed");
    let mut rt = holding_here(configured(&b), &b);
    let step = rt
        .step(&delivery(unassignment_of(&b, &zed), REQUEST))
        .unwrap();
    assert!(
        rejected_with(&step, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-14: with the topology followed, the submitter is hosted on the submitting participant, which signs the request.
#[test]
fn an_unassignment_for_a_party_the_submitting_participant_does_not_host_is_rejected() {
    let b = build(ParticipantIdentity::generate("unassign-host"));
    let mut rt = holding_here(following(&b, &[]), &b);
    let step = rt
        .step(&delivery(unassignment_of(&b, &b.erin), REQUEST))
        .unwrap();
    assert!(
        rejected_with(&step, "is not hosted on"),
        "{:?} {:?}",
        outcome(&step),
        step.notes
    );
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let mut rt = holding_here(following(&b, &[erin_hosted(&b, 3), vetted]), &b);
    let step = rt
        .step(&delivery(unassignment_of(&b, &b.erin), REQUEST))
        .unwrap();
    assert_eq!(outcome(&step), Outcome::Approve, "{:?}", step.notes);
}

/// P-14: a reassignment whose common data names another mediator group than the root hash message's is not processed.
#[test]
fn an_unassignment_sent_to_another_mediator_group_is_not_processed() {
    let b = build(ParticipantIdentity::generate("unassign-mediator"));
    let envelopes: Vec<Addressed> = unassignment_of(&b, &b.erin)
        .into_iter()
        .map(|(to, c)| {
            if is_root_hash_message(&c) {
                (vec!["MGR::1".into(), b.me.member()], c)
            } else {
                (to, c)
            }
        })
        .collect();
    let mut rt = holding_here(configured(&b), &b);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(step.to_send.is_empty(), "{:?}", step.to_send);
    assert!(noted(&step, "declared in"), "{:?}", step.notes);
}

/// P-13: with the approved transactions kept until shown, one applied just before a crash (the cursor moved, whoever shows it did not record
/// it yet) is there again after the restart, its consumptions included; once shown it is not.
#[test]
fn an_applied_transaction_not_yet_shown_is_kept_across_a_restart() {
    let b = build(ParticipantIdentity::generate("outbox"));
    let mediator = ParticipantIdentity::generate("mediator");
    let dir = state_dir("outbox");
    let mut rt = kept_in(&b, &mediator, &dir);
    rt.keep_applied_until_shown();
    rt.step(&delivered(&b, REQUEST)).unwrap();
    let step = rt
        .step(&verdict_on(&b, &mediator, true, REQUEST + 10))
        .unwrap();
    assert_eq!(step.applied.len(), 1, "{:?}", step.notes);
    drop(rt);
    let mut rt = kept_in(&b, &mediator, &dir);
    let unshown = rt.unshown_applied();
    assert_eq!(unshown, step.applied, "kept across the restart");
    rt.applied_shown(REQUEST).unwrap();
    drop(rt);
    assert!(kept_in(&b, &mediator, &dir).unshown_applied().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

fn unassignment_with_reassigning(
    b: &Built,
    submitter: &str,
    reassigning: &[&str],
    instance: &[u8],
) -> Vec<Addressed> {
    use canton_participant::reassignment_submit::{unassignment, Unassignment};
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let reassigning: Vec<String> = reassigning.iter().map(|s| (*s).to_string()).collect();
    let built = unassignment(
        &b.me,
        &Unassignment {
            source: SYNC,
            target: "sync2::1220cc::37-0",
            target_time_micros: NOW,
            instance,
            current_counter: 0,
            submitter,
            command_id: "unassign-1",
            user_id: "rust-user",
            reassigning_participant_uids: &reassigning,
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(310),
    )
    .unwrap();
    built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect()
}

/// P-14: a confirming participant that is not in `reassigning_participant_uids` responds `LocalAbstain`
/// instead of approving or rejecting (`ReassignmentProcessingSteps.responsesForWellformedPayloads`).
#[test]
fn a_non_reassigning_participant_abstains_on_reassignment() {
    let b = build(ParticipantIdentity::generate("unassign-abstain"));
    let other_uid = format!("other::{}", b.me.namespace());
    let envelopes = unassignment_with_reassigning(&b, &b.erin, &[&other_uid], &b.stored.instance);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let mut rt = holding_here(following(&b, &[erin_hosted(&b, 2), vetted]), &b);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        matches!(outcome(&step), Outcome::Abstain(_)),
        "expected LocalAbstain, got {:?} (notes: {:?})",
        outcome(&step),
        step.notes
    );
    let mut expected = vec![b.erin.clone(), b.me.uid()];
    expected.sort();
    assert_eq!(step.to_send[0].decision().confirming_parties, expected);
    assert!(rt.ledger.is_active(&b.stored.contract_id_hex));
}

/// P-14: if a participant's `VettedPackages` omits the contract's validation package, reassignment answers `Malformed` (`ModelConformance`).
#[test]
fn a_reassignment_with_an_unvetted_package_is_malformed() {
    let b = build(ParticipantIdentity::generate("unassign-vetting"));
    let unvetted = b.me.vetting_transaction(&["00".repeat(32)]);
    let mut rt = holding_here(following(&b, &[erin_hosted(&b, 3), unvetted]), &b);
    let step = rt
        .step(&delivery(unassignment_of(&b, &b.erin), REQUEST))
        .unwrap();
    assert!(
        malformed_with(&step, "PackageIdUnknownOrUnvetted"),
        "expected PackageIdUnknownOrUnvetted malformed, got {:?} {:?}",
        outcome(&step),
        step.notes
    );
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let mut rt_ok = holding_here(following(&b, &[erin_hosted(&b, 3), vetted]), &b);
    let step_ok = rt_ok
        .step(&delivery(unassignment_of(&b, &b.erin), REQUEST))
        .unwrap();
    assert_eq!(outcome(&step_ok), Outcome::Approve, "{:?}", step_ok.notes);
}

/// P-14: a tampered contract instance inside a reassignment fails `authenticate_instance` -> `Malformed` (`ModelConformance`).
#[test]
fn a_reassignment_with_an_unauthentic_contract_is_malformed() {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use prost::Message;
    let b = build(ParticipantIdentity::generate("unassign-auth"));
    let mut ver = Versioned::decode(b.stored.instance.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(ver.payload.as_slice()).unwrap();
    let last = fci.contract_id.len() - 1;
    fci.contract_id[last] ^= 0xff;
    ver.payload = fci.encode_to_vec();
    let bad_instance = ver.encode_to_vec();
    let envelopes = unassignment_with_reassigning(&b, &b.erin, &[&b.me.uid()], &bad_instance);
    let mut rt = following(&b, &[erin_hosted(&b, 3)]);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        malformed_with(&step, "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "expected model conformance malformed, got {:?} {:?}",
        outcome(&step),
        step.notes
    );
}

/// P-14: an assignment matching a previously remembered unassignment succeeds, while a counter mismatch is rejected.
#[test]
fn an_assignment_mismatched_with_stored_unassignment_is_rejected() {
    use canton_participant::reassignment_receive::{StoredReassignedContract, StoredUnassignment};
    use canton_participant::reassignment_submit::{assignment, Assignment};
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("assign-stored"));
    let source_logical = "src::1220bb";
    let target_logical = "sync::1220aa";
    let rid = reassignment_id(
        source_logical,
        target_logical,
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let built = assignment(
        &b.me,
        &Assignment {
            source: "src::1220bb::37-0",
            target: SYNC,
            unassignment_time_micros: REQUEST - 10,
            reassignment_id: &rid,
            instance: &b.stored.instance,
            counter: 1,
            submitter: &b.erin,
            command_id: "assign-1",
            user_id: "rust-user",
            reassigning_participant_uids: &[b.me.uid()],
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(320),
    )
    .unwrap();
    let envelopes: Vec<Addressed> = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    let stakeholders: std::collections::BTreeSet<String> = [b.erin.clone()].into_iter().collect();
    let reassigning: std::collections::BTreeSet<String> = [b.me.uid()].into_iter().collect();
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    let mut rt_bad = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt_bad
        .remember_unassignment(
            rid.clone(),
            StoredUnassignment {
                contracts: vec![StoredReassignedContract {
                    contract_id: b.stored.contract_id_hex.clone(),
                    counter: 99,
                    source_validation_package_id: b.stored.package_id.clone(),
                    target_validation_package_id: b.stored.package_id.clone(),
                    instance: b.stored.instance.clone(),
                }],
                stakeholders: stakeholders.clone(),
                reassigning_participants: reassigning.clone(),
                unassignment_ts: REQUEST - 10,
            },
        )
        .unwrap();
    let step_bad = rt_bad.step(&delivery(envelopes.clone(), REQUEST)).unwrap();
    assert!(
        rejected_with(&step_bad, "REASSIGNMENT_VALIDATION_FAILED"),
        "expected stored unassignment mismatch rejection, got {:?} {:?}",
        outcome(&step_bad),
        step_bad.notes
    );

    let mut rt_ok = following(&b, &[erin_hosted(&b, 3), vetted]);
    rt_ok
        .remember_unassignment(
            rid,
            StoredUnassignment {
                contracts: vec![StoredReassignedContract {
                    contract_id: b.stored.contract_id_hex,
                    counter: 1,
                    source_validation_package_id: b.stored.package_id.clone(),
                    target_validation_package_id: b.stored.package_id,
                    instance: b.stored.instance,
                }],
                stakeholders,
                reassigning_participants: reassigning,
                unassignment_ts: REQUEST - 10,
            },
        )
        .unwrap();
    let step_ok = rt_ok.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&step_ok), Outcome::Approve, "{:?}", step_ok.notes);
}

/// P-10: under topology hosting (`hosts_of`), a parent exercise with a `NewView` subview yields `CoreInformees::Exact`
/// (containing `owner`, `peer1` + admin party, and excluding `peer2` in the subview), so adding `peer2` to parent informees fails.
#[test]
fn the_core_informees_of_a_view_with_subviews_are_exact_under_topology() {
    use canton_participant::view_conformance::{check_exercise_view_with_topology, Nonconformance};
    use canton_participant::view_informees::{check_informees, CoreInformees};
    use canton_participant::view_receive::{
        check_views, decrypt_views, revealed_common_metadata, revealed_submitter_metadata,
        root_hash_of_message,
    };
    let me = ParticipantIdentity::generate("chain-exact");
    let me_uid = me.uid();
    let (fingerprint, secret) = (me.encryption_fingerprint(), *me.encryption_secret());
    let c = chain(ParticipantIdentity::from_text(&me.to_text()).unwrap());
    let root_hash = c
        .envelopes
        .iter()
        .find_map(|(_, e)| root_hash_of_message(e))
        .unwrap();
    let mut revealed = Vec::new();
    let mut tree = None;
    for (_, env) in &c.envelopes {
        if let Ok(views) = decrypt_views(env, &fingerprint, &secret) {
            if let Some(t) = views.view_trees.first().and_then(|vt| vt.tree.as_ref()) {
                if revealed_submitter_metadata(t).is_ok() {
                    tree = Some(t.clone());
                }
            }
            revealed.extend(check_views(&views, &root_hash, |_, _| true).unwrap());
        }
    }
    let tree = tree.unwrap();
    let mut root = revealed
        .iter()
        .find(|v| v.position.len() == 1)
        .unwrap()
        .clone();
    let subviews: Vec<_> = revealed.iter().filter(|v| v.position.len() > 1).collect();
    let peer2 = subviews
        .iter()
        .flat_map(|v| &v.common_data.informees)
        .find(|p| p.starts_with("peer2::"))
        .unwrap()
        .clone();
    let common = revealed_common_metadata(&tree).unwrap();
    let submitter = revealed_submitter_metadata(&tree).unwrap();
    let peer2_party = peer2.clone();
    let me_uid_closure = me_uid;
    let hosts_of = |party: &str| -> Option<(u32, Vec<(String, i32)>)> {
        if party == peer2_party {
            Some((1, vec![("other::1220ff".to_string(), 1)]))
        } else {
            Some((1, vec![(me_uid_closure.clone(), 1)]))
        }
    };
    let (_, _, core) = check_exercise_view_with_topology(
        &c.runtime.engine,
        &root,
        &subviews,
        &common,
        Some(&submitter.submitting_participant_uid),
        Some(&hosts_of),
    )
    .unwrap();
    assert!(matches!(core, CoreInformees::Exact(_)), "{core:?}");
    check_informees(&root, &core, Some(&submitter.submitting_participant_uid)).unwrap();
    // Mutating root view informees to claim `peer2` (who belongs only to the subview) is refused under Exact.
    root.common_data.informees.push(peer2);
    let err =
        check_informees(&root, &core, Some(&submitter.submitting_participant_uid)).unwrap_err();
    assert!(matches!(err, Nonconformance::InformeesDiffer(_)), "{err:?}");
}

fn unassignment_built(
    b: &Built,
    source: &str,
    submitter: &str,
    reassigning: &[&str],
    instance: &[u8],
) -> (Vec<Addressed>, Vec<u8>) {
    use canton_participant::reassignment_submit::{unassignment, Unassignment};
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let reassigning: Vec<String> = reassigning.iter().map(|s| (*s).to_string()).collect();
    let built = unassignment(
        &b.me,
        &Unassignment {
            source,
            target: "sync2::1220cc::37-0",
            target_time_micros: NOW,
            instance,
            current_counter: 0,
            submitter,
            command_id: "unassign-r",
            user_id: "rust-user",
            reassigning_participant_uids: &reassigning,
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(410),
    )
    .unwrap();
    let envelopes = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    (envelopes, built.root_hash)
}

#[test]
fn r2_non_reassigning_abstain_applies_approved_unassignment_without_storing() {
    let b = build(ParticipantIdentity::generate("r2-unassign"));
    let mediator = ParticipantIdentity::generate("r2-med-u");
    let other_uid = format!("other::{}", b.me.namespace());
    let (envelopes, root_hash) =
        unassignment_built(&b, SYNC, &b.erin, &[&other_uid], &b.stored.instance);

    let mut rt = holding_here(configured(&b), &b);
    rt.config.mediator_keys = vec![raw_key(&mediator)];
    let step = rt.step(&delivery(envelopes.clone(), REQUEST)).unwrap();
    assert!(
        matches!(outcome(&step), Outcome::Abstain(_)),
        "expected Abstain, got {:?}",
        outcome(&step)
    );
    let v_step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &root_hash,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(
        v_step.unresolved_verdicts.is_empty(),
        "approved abstained unassignment must resolve in-flight entry: {:?}",
        v_step.notes
    );
    assert!(
        !rt.ledger.is_active(&b.stored.contract_id_hex),
        "approved non-reassigning unassignment must remove contract from active ACS"
    );
    assert_eq!(
        rt.ledger.unassigned_by(&b.stored.contract_id_hex),
        Some(REQUEST)
    );
    let rid = canton_participant::reassignment_wire::reassignment_id(
        "sync::1220aa",
        "sync2::1220cc",
        REQUEST,
        &[(&b.stored.contract_id_hex, 1)],
    );
    assert!(
        rt.stored_unassignment(&rid).is_none(),
        "non-reassigning participant must not write stored_unassignments on approved unassignment"
    );

    // Negative control: rejected abstained unassignment leaves contract active.
    let mut rt_rej = holding_here(configured(&b), &b);
    rt_rej.config.mediator_keys = vec![raw_key(&mediator)];
    let step_rej_req = rt_rej.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(matches!(outcome(&step_rej_req), Outcome::Abstain(_)));
    let (content, hash) = verdict_content(REQUEST, &root_hash, false);
    let mut rej_event = delivery(vec![(vec![b.me.member()], content)], REQUEST + 10);
    rej_event.envelope_signatures = vec![vec![mediator.signing_key.sign_bytes(&hash)]];
    rt_rej.step(&rej_event).unwrap();
    assert!(rt_rej.ledger.is_active(&b.stored.contract_id_hex));
    assert_eq!(rt_rej.ledger.unassigned_by(&b.stored.contract_id_hex), None);
}

#[test]
fn r2_non_reassigning_abstain_applies_approved_assignment() {
    use canton_participant::reassignment_submit::{assignment, Assignment};
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r2-assign"));
    let mediator = ParticipantIdentity::generate("r2-med-a");
    let other_uid = format!("other::{}", b.me.namespace());
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let built = assignment(
        &b.me,
        &Assignment {
            source: "src::1220bb::37-0",
            target: SYNC,
            unassignment_time_micros: REQUEST - 10,
            reassignment_id: &rid,
            instance: &b.stored.instance,
            counter: 1,
            submitter: &b.erin,
            command_id: "r2-assign-1",
            user_id: "rust-user",
            reassigning_participant_uids: &[other_uid],
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(420),
    )
    .unwrap();
    let envelopes: Vec<Addressed> = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    let mut rt = configured(&b);
    rt.config.mediator_keys = vec![raw_key(&mediator)];
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        matches!(outcome(&step), Outcome::Abstain(_)),
        "expected Abstain, got {:?}",
        outcome(&step)
    );
    let v_step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &built.root_hash,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(
        v_step.unresolved_verdicts.is_empty(),
        "approved abstained assignment must resolve: {:?}",
        v_step.notes
    );
    assert!(
        rt.ledger.is_active(&b.stored.contract_id_hex),
        "approved non-reassigning assignment must activate contract"
    );
    assert_eq!(rt.ledger.counter_of(&b.stored.contract_id_hex), 1);
}

#[test]
fn r2_non_reassigning_abstain_with_phase3_activeness_conflict_still_abstains_and_applies_on_approve(
) {
    let b = build(ParticipantIdentity::generate("r2-conflict"));
    let mediator = ParticipantIdentity::generate("r2-med-c");
    let other_uid = format!("other::{}", b.me.namespace());
    let (envelopes, root_hash) =
        unassignment_built(&b, SYNC, &b.erin, &[&other_uid], &b.stored.instance);

    let mut rt = holding_here(configured(&b), &b);
    rt.config.mediator_keys = vec![raw_key(&mediator)];
    rt.ledger
        .begin_until(
            REQUEST - 5,
            canton_participant::view_acs::Effects {
                consumes: vec![b.stored.contract_id_hex.clone()],
                creates: vec![],
                instances: vec![],
                remote_events: vec![],
            },
            REQUEST + 100,
        )
        .unwrap();
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        matches!(outcome(&step), Outcome::Abstain(_)),
        "non-reassigning participant with Phase 3 activeness conflict must still abstain, got {:?}",
        outcome(&step)
    );
    assert!(rt.ledger.resolve(REQUEST - 5, false).unwrap());
    let v_step = rt
        .step(&verdict_event(
            &b,
            REQUEST,
            &root_hash,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(
        !rt.ledger.is_active(&b.stored.contract_id_hex),
        "approved request must commit despite Phase 3 activeness conflict ({:?})",
        v_step.notes
    );
    assert_eq!(
        rt.ledger.unassigned_by(&b.stored.contract_id_hex),
        Some(REQUEST)
    );
    let rid = canton_participant::reassignment_wire::reassignment_id(
        "sync::1220aa",
        "sync2::1220cc",
        REQUEST,
        &[(&b.stored.contract_id_hex, 1)],
    );
    assert!(
        rt.stored_unassignment(&rid).is_none(),
        "non-reassigning participant must not write stored_unassignments on approved unassignment"
    );
}

#[test]
fn r6a_pv36_skips_package_vetting_while_pv37_rejects() {
    let b = build(ParticipantIdentity::generate("r6a-pv"));
    let pv36 = "sync::1220aa::36-0";
    let unvetted = b.me.vetting_transaction(&["00".repeat(32)]);
    let (envelopes_pv36, _) =
        unassignment_built(&b, pv36, &b.erin, &[&b.me.uid()], &b.stored.instance);
    let mut rt_pv36 = holding_here(following(&b, &[erin_hosted(&b, 3), unvetted.clone()]), &b);
    rt_pv36.config.physical_synchronizer_id = pv36.into();
    let mut ev_pv36 = delivery(envelopes_pv36, REQUEST);
    ev_pv36.physical_synchronizer_id = pv36.into();
    let step_pv36 = rt_pv36.step(&ev_pv36).unwrap();
    assert_eq!(
        outcome(&step_pv36),
        Outcome::Approve,
        "PV 36 must skip reassignment package vetting, got {:?} ({:?})",
        outcome(&step_pv36),
        step_pv36.notes
    );

    let (envelopes_pv37, _) =
        unassignment_built(&b, SYNC, &b.erin, &[&b.me.uid()], &b.stored.instance);
    let mut rt_pv37 = holding_here(following(&b, &[erin_hosted(&b, 3), unvetted]), &b);
    let step_pv37 = rt_pv37.step(&delivery(envelopes_pv37, REQUEST)).unwrap();
    assert!(malformed_with(&step_pv37, "PackageIdUnknownOrUnvetted"));
}

#[test]
fn r6b_untracked_host_vetted_packages_is_rejected_on_pv37() {
    let b = build(ParticipantIdentity::generate("r6b-untracked"));
    let (envelopes, _) = unassignment_built(&b, SYNC, &b.erin, &[&b.me.uid()], &b.stored.instance);
    let mut rt = holding_here(following(&b, &[erin_hosted(&b, 3)]), &b);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        malformed_with(&step, "PackageIdUnknownOrUnvetted"),
        "missing VettedPackages mapping for host must fail closed on PV 37, got {:?} {:?}",
        outcome(&step),
        step.notes
    );
}

#[test]
fn r6c_contract_authenticated_against_validation_package_id() {
    use canton_participant::confirmation_wire::root_hash_message_of_type;
    use canton_participant::merkle_wire::Tree;
    use canton_participant::reassignment_wire::{
        unassignment_common_data, unassignment_view, view_tree, CommonParts, Reassigned, Submitter,
    };
    use canton_participant::view_message::encrypted_view_message_of_type;
    use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;

    let b = build(ParticipantIdentity::generate("r6c-valpkg"));
    let root_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let v1_dar = root_dir.join("tests/oracle/upgrade/upg-1.0.0.dar");
    let v2_dar = root_dir.join("tests/oracle/upgrade/upg-2.0.0.dar");
    let v1_world = World::open(&v1_dar).unwrap();
    let v2_world = World::open(&v2_dar).unwrap();
    let v1_pkg = v1_world.main_package_id().to_string();
    let v2_pkg = v2_world.main_package_id().to_string();
    let v1_types = Types::new(&v1_world);
    let ty = v1_types.template(&v1_pkg, "Main:Account").unwrap();
    let acc = Value::Record {
        tycon: Some("Main:Account".into()),
        fields: vec![
            ("owner".into(), Value::Party(b.erin.clone())),
            ("balance".into(), Value::Int64(1)),
        ],
    };
    let (arg, hash_arg) = forms(&v1_types, &ty, &acc).unwrap();
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let created = build_create(
        &Context {
            identity: &b.me,
            synchronizer: SYNC,
            mediator_group: 0,
            user_id: "rust-user",
        },
        &Create {
            package_name: "upg",
            package_id: &v1_pkg,
            module: vec!["Main".into()],
            name: vec!["Account".into()],
            arg,
            hash_arg,
            signatories: vec![b.erin.clone()],
            stakeholders: vec![b.erin.clone()],
            hosts: vec![host],
            command_id: "create-acc".into(),
            key: None,
        },
        NOW,
        &mut Counter(430),
    )
    .unwrap();

    let make_envelopes = |val_pkg: &str| -> Vec<Addressed> {
        let mut rng = Counter(440);
        let common = unassignment_common_data(
            SYNC,
            &CommonParts {
                stakeholders: &[&b.erin],
                signatories: &[&b.erin],
                reassigning_participant_uids: &[&b.me.uid()],
                uuid: "00000000-0000-4000-8000-000000000001",
                mediator_group: 0,
                submitter: Submitter {
                    submitter: &b.erin,
                    submitting_participant_uid: &b.me.uid(),
                    command_id: "r6c-cmd",
                    submission_id: None,
                    user_id: "rust-user",
                    workflow_id: None,
                },
            },
            &rng.fresh("csalt"),
        );
        let view = unassignment_view(
            "sync2::1220cc::37-0",
            NOW,
            &[Reassigned {
                contract_id: &created.contract_id_hex,
                encoded: &created.instance,
                source_validation_package_id: val_pkg,
                target_validation_package_id: val_pkg,
                counter: 1,
            }],
            &rng.fresh("vsalt"),
        );
        let tree = view_tree(&common, &Tree::leaf(&view));
        let sig = b.me.signing_key.sign_bytes(&tree.root_hash);
        let enc = encrypted_view_message_of_type(
            ViewType::Unassignment,
            &tree.bytes(),
            &tree.view_hash,
            &rng.fresh("rnd")[..16].try_into().unwrap(),
            &rng.fresh("iv")[..12].try_into().unwrap(),
            &[canton_participant::view_message::Recipient {
                encryption_spki: b.me.encryption_spki(),
                fingerprint: &b.me.encryption_fingerprint(),
                ecies_iv: rng.fresh("eiv")[..16].try_into().unwrap(),
                ecies_ephemeral_scalar: rng.fresh("eeph"),
            }],
            SYNC,
            Some(sig),
        );
        let rhm = root_hash_message_of_type(ViewType::Unassignment, &tree.root_hash, SYNC, NOW);
        vec![
            (vec![b.me.member()], enc),
            (vec!["MGR::0".into(), b.me.member()], rhm),
        ]
    };

    let vetted =
        b.me.vetting_transaction(&[b.stored.package_id.clone(), v1_pkg, v2_pkg.clone()]);
    let mut rt_bad = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt_bad.engine.add_dar(&v1_dar).unwrap();
    rt_bad.engine.add_dar(&v2_dar).unwrap();
    rt_bad
        .ledger
        .import(&created.contract_id_hex, "Main:Account")
        .unwrap();
    // Use `sample-contract` (which lacks `Main:Account`) as validation package id.
    let step_bad = rt_bad
        .step(&delivery(make_envelopes(&b.stored.package_id), REQUEST))
        .unwrap();
    assert!(
        malformed_with(&step_bad, "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK"),
        "authenticating against non-matching validation_package_id must fail conformance, got {:?} {:?}",
        outcome(&step_bad),
        step_bad.notes
    );

    let mut rt_ok = following(&b, &[erin_hosted(&b, 3), vetted]);
    rt_ok.engine.add_dar(&v1_dar).unwrap();
    rt_ok.engine.add_dar(&v2_dar).unwrap();
    rt_ok
        .ledger
        .import(&created.contract_id_hex, "Main:Account")
        .unwrap();
    // Upgraded package `upg-2.0.0` validates the v1 contract via trailing Optional field rules.
    let step_ok = rt_ok
        .step(&delivery(make_envelopes(&v2_pkg), REQUEST))
        .unwrap();
    assert_eq!(
        outcome(&step_ok),
        Outcome::Approve,
        "upgraded validation_package_id must pass conformance: {:?}",
        step_ok.notes
    );
}

#[test]
#[expect(
    deprecated,
    reason = "populates deprecated protobuf field VettedPackages::package_ids"
)]
fn r6d_vetting_validity_window_enforced_at_request_time() {
    use canton_participant::topology_wire::{signed, versioned, TOPOLOGY_TRANSACTION_VERSION};
    use canton_proto::com::digitalasset::canton::protocol::v30::vetted_packages::VettedPackage;
    use canton_proto::com::digitalasset::canton::protocol::v30::VettedPackages;
    use canton_proto::com::digitalasset::canton::protocol::v31;
    use prost::Message;

    let vetted_window =
        |b: &Built, serial: u32, from_micros: Option<i64>, until_micros: Option<i64>| {
            let ts = |m: i64| prost_types::Timestamp {
                seconds: m.div_euclid(1_000_000),
                nanos: (m.rem_euclid(1_000_000) * 1_000) as i32,
            };
            let tx = v31::TopologyTransaction {
                operation: 1,
                serial,
                mapping: Some(v31::TopologyMapping {
                    mapping: Some(v31::topology_mapping::Mapping::VettedPackages(
                        VettedPackages {
                            participant_uid: b.me.uid(),
                            package_ids: Vec::new(),
                            packages: vec![VettedPackage {
                                package_id: b.stored.package_id.clone(),
                                valid_from_inclusive: from_micros.map(ts),
                                valid_until_exclusive: until_micros.map(ts),
                            }],
                        },
                    )),
                }),
            };
            let bytes = versioned(tx.encode_to_vec(), TOPOLOGY_TRANSACTION_VERSION);
            signed(
                bytes.clone(),
                vec![b.me.namespace_key.sign_transaction(&bytes)],
            )
        };

    let b = build(ParticipantIdentity::generate("r6d-window"));
    let (envelopes, _) = unassignment_built(&b, SYNC, &b.erin, &[&b.me.uid()], &b.stored.instance);

    let future = vetted_window(&b, 1, Some(REQUEST + 60_000_000), None);
    let mut rt_future = holding_here(following(&b, &[erin_hosted(&b, 3), future]), &b);
    let step_future = rt_future
        .step(&delivery(envelopes.clone(), REQUEST))
        .unwrap();
    assert!(
        malformed_with(&step_future, "PackageIdUnknownOrUnvetted"),
        "future vetting window must be treated as unvetted at REQUEST, got {:?} {:?}",
        outcome(&step_future),
        step_future.notes
    );

    let expired = vetted_window(&b, 1, None, Some(REQUEST - 1_000_000));
    let mut rt_expired = holding_here(following(&b, &[erin_hosted(&b, 3), expired]), &b);
    let step_expired = rt_expired
        .step(&delivery(envelopes.clone(), REQUEST))
        .unwrap();
    assert!(
        malformed_with(&step_expired, "PackageIdUnknownOrUnvetted"),
        "expired vetting window must be treated as unvetted at REQUEST, got {:?} {:?}",
        outcome(&step_expired),
        step_expired.notes
    );

    let active = vetted_window(
        &b,
        1,
        Some(REQUEST - 10_000_000),
        Some(REQUEST + 10_000_000),
    );
    let mut rt_ok = holding_here(following(&b, &[erin_hosted(&b, 3), active]), &b);
    let step_ok = rt_ok.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&step_ok), Outcome::Approve, "{:?}", step_ok.notes);
}

#[test]
fn r6e_missing_stored_unassignment_abstains_for_reassigning_participant() {
    use canton_participant::reassignment_submit::{assignment, Assignment};
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r6e-missing"));
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let built = assignment(
        &b.me,
        &Assignment {
            source: "src::1220bb::37-0",
            target: SYNC,
            unassignment_time_micros: REQUEST - 10,
            reassignment_id: &rid,
            instance: &b.stored.instance,
            counter: 1,
            submitter: &b.erin,
            command_id: "r6e-assign-missing",
            user_id: "rust-user",
            reassigning_participant_uids: &[b.me.uid()],
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(450),
    )
    .unwrap();
    let envelopes: Vec<Addressed> = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let mut rt = following(&b, &[erin_hosted(&b, 3), vetted]);
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        matches!(outcome(&step), Outcome::Abstain(_)),
        "missing StoredUnassignment for reassigning participant must Abstain, got {:?} {:?}",
        outcome(&step),
        step.notes
    );
}

#[test]
fn r6e_stored_unassignment_field_mismatches_rejected() {
    use canton_participant::reassignment_receive::{StoredReassignedContract, StoredUnassignment};
    use canton_participant::reassignment_submit::{assignment, Assignment};
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r6e-fields"));
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let make_assign = |rid_arg: &str| {
        assignment(
            &b.me,
            &Assignment {
                source: "src::1220bb::37-0",
                target: SYNC,
                unassignment_time_micros: REQUEST - 10,
                reassignment_id: rid_arg,
                instance: &b.stored.instance,
                counter: 1,
                submitter: &b.erin,
                command_id: "r6e-fields",
                user_id: "rust-user",
                reassigning_participant_uids: &[b.me.uid()],
                recipients: std::slice::from_ref(&host),
                now_micros: NOW,
            },
            &mut Counter(460),
        )
        .unwrap()
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect::<Vec<Addressed>>()
    };
    let envelopes = make_assign(&rid);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let baseline = StoredUnassignment {
        contracts: vec![StoredReassignedContract {
            contract_id: b.stored.contract_id_hex.clone(),
            counter: 1,
            source_validation_package_id: b.stored.package_id.clone(),
            target_validation_package_id: b.stored.package_id.clone(),
            instance: b.stored.instance.clone(),
        }],
        stakeholders: [b.erin.clone()].into_iter().collect(),
        reassigning_participants: [b.me.uid()].into_iter().collect(),
        unassignment_ts: REQUEST - 10,
    };

    // 1. reassigning_participants mismatch
    let mut bad_reassigning = baseline.clone();
    bad_reassigning
        .reassigning_participants
        .insert(format!("extra::{}", b.me.namespace()));
    let mut rt1 = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt1.remember_unassignment(rid.clone(), bad_reassigning)
        .unwrap();
    let s1 = rt1.step(&delivery(envelopes.clone(), REQUEST)).unwrap();
    assert!(
        rejected_with(&s1, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?}",
        outcome(&s1)
    );

    // 2. unassignment_ts mismatch
    let mut bad_ts = baseline.clone();
    bad_ts.unassignment_ts = REQUEST - 99;
    let mut rt2 = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt2.remember_unassignment(rid.clone(), bad_ts).unwrap();
    let s2 = rt2.step(&delivery(envelopes.clone(), REQUEST)).unwrap();
    assert!(
        rejected_with(&s2, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?}",
        outcome(&s2)
    );

    // 3. validation_package_id / instance mismatch
    let mut bad_pkg = baseline.clone();
    bad_pkg.contracts[0].target_validation_package_id = "deadbeef".into();
    let mut rt3 = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt3.remember_unassignment(rid.clone(), bad_pkg).unwrap();
    let s3 = rt3.step(&delivery(envelopes.clone(), REQUEST)).unwrap();
    assert!(
        rejected_with(&s3, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?}",
        outcome(&s3)
    );

    // 4. InconsistentReassignmentId
    let bad_rid = reassignment_id(
        "wrong::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let mut rt4 = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt4.remember_unassignment(bad_rid.clone(), baseline.clone())
        .unwrap();
    let s4 = rt4.step(&delivery(make_assign(&bad_rid), REQUEST)).unwrap();
    assert!(
        rejected_with(&s4, "InconsistentReassignmentId"),
        "{:?}",
        outcome(&s4)
    );

    // U-60: the participant's runtime on the source synchronizer holds the unassignment (it saw it approved, whoever submitted it); its
    // runtime on the target synchronizer judges the assignment by it because the two share the participant's store. Without the
    // sharing the target runtime abstains (`UnassignmentDataNotFound`), as a participant that never saw the unassignment does.
    let mut rt_source = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt_source
        .remember_unassignment(rid.clone(), baseline.clone())
        .unwrap();
    let mut rt_alone = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    let s_alone = rt_alone
        .step(&delivery(envelopes.clone(), REQUEST))
        .unwrap();
    assert!(
        matches!(outcome(&s_alone), Outcome::Abstain(ref why) if why.contains("UnassignmentDataNotFound")),
        "{:?}",
        outcome(&s_alone)
    );
    let shared = canton_participant::participant_runtime::SharedUnassignments::default();
    let mut rt_target = following(&b, &[erin_hosted(&b, 3), vetted.clone()]);
    rt_target.share_unassignments(shared.clone());
    rt_source.share_unassignments(shared);
    let s_shared = rt_target
        .step(&delivery(envelopes.clone(), REQUEST))
        .unwrap();
    assert_eq!(outcome(&s_shared), Outcome::Approve, "{:?}", s_shared.notes);

    // Positive control: exact match approves.
    let mut rt_ok = following(&b, &[erin_hosted(&b, 3), vetted]);
    rt_ok.remember_unassignment(rid, baseline).unwrap();
    let s_ok = rt_ok.step(&delivery(envelopes, REQUEST)).unwrap();
    assert_eq!(outcome(&s_ok), Outcome::Approve, "{:?}", s_ok.notes);
}

fn assign_envelopes_for(
    b: &Built,
    submitter: &str,
    reassigning: &[&str],
    rid: &str,
    instance: &[u8],
) -> (Vec<Addressed>, Vec<u8>) {
    use canton_participant::reassignment_submit::{assignment, Assignment};
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let reassigning: Vec<String> = reassigning.iter().map(|s| (*s).to_string()).collect();
    let built = assignment(
        &b.me,
        &Assignment {
            source: "src::1220bb::37-0",
            target: SYNC,
            unassignment_time_micros: REQUEST - 10,
            reassignment_id: rid,
            instance,
            counter: 1,
            submitter,
            command_id: "r2-phase7-cmd",
            user_id: "rust-user",
            reassigning_participant_uids: &reassigning,
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(470),
    )
    .unwrap();
    let envelopes = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    (envelopes, built.root_hash)
}

fn baseline_stored_unassignment(
    b: &Built,
) -> canton_participant::reassignment_receive::StoredUnassignment {
    use canton_participant::reassignment_receive::{StoredReassignedContract, StoredUnassignment};
    StoredUnassignment {
        contracts: vec![StoredReassignedContract {
            contract_id: b.stored.contract_id_hex.clone(),
            counter: 1,
            source_validation_package_id: b.stored.package_id.clone(),
            target_validation_package_id: b.stored.package_id.clone(),
            instance: b.stored.instance.clone(),
        }],
        stakeholders: [b.erin.clone()].into_iter().collect(),
        reassigning_participants: [b.me.uid()].into_iter().collect(),
        unassignment_ts: REQUEST - 10,
    }
}

/// R-2 Phase 7 (§3.2): submitterCheckFailure must prevent commit on Approve for BOTH reassigning
/// and non-reassigning participants (`ReassignmentProcessingSteps.checkPhase7Validations`).
#[test]
fn r2_phase7_submitter_failure_prevents_commit_for_reassigning_and_non_reassigning() {
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r2-p7-sub"));
    let mediator = ParticipantIdentity::generate("r2-p7-sub-m");
    let zed = b.me.party_id("zed");
    let other_uid = format!("other::{}", b.me.namespace());
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let (envelopes, root_hash) =
        assign_envelopes_for(&b, &zed, &[&b.me.uid()], &rid, &b.stored.instance);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    // (a) Reassigning participant: common checks valid except submitter (`zed` not stakeholder).
    let mut rt_r = following(
        &b,
        &[
            erin_hosted(&b, 1),
            b.me.party_hosting_at_serial("zed", &[(&b.me.uid(), 1)], 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted.clone(),
        ],
    );
    rt_r.remember_unassignment(rid.clone(), baseline_stored_unassignment(&b))
        .unwrap();
    let s_r = rt_r.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        rejected_with(&s_r, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?}",
        outcome(&s_r)
    );
    rt_r.step(&verdict_event(
        &b,
        REQUEST,
        &root_hash,
        &[&mediator],
        REQUEST + 10,
    ))
    .unwrap();
    assert!(
        !rt_r.ledger.is_active(&b.stored.contract_id_hex),
        "reassigning submitter failure must not commit on mediator Approve"
    );

    // (b) Non-reassigning participant: emits Abstain at Phase 3, must still NOT commit on Approve.
    let (envelopes_nr, root_hash_nr) =
        assign_envelopes_for(&b, &zed, &[&other_uid], &rid, &b.stored.instance);
    let mut rt_nr = following(
        &b,
        &[
            erin_hosted(&b, 1),
            b.me.party_hosting_at_serial("zed", &[(&b.me.uid(), 1)], 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted,
        ],
    );
    let s_nr = rt_nr.step(&delivery(envelopes_nr, REQUEST)).unwrap();
    assert!(matches!(outcome(&s_nr), Outcome::Abstain(_)));
    rt_nr
        .step(&verdict_event(
            &b,
            REQUEST,
            &root_hash_nr,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(
        !rt_nr.ledger.is_active(&b.stored.contract_id_hex),
        "non-reassigning participant with submitter check failure must not commit on mediator Approve"
    );
}

/// R-2 Phase 7 (§3.2): stored unassignment mismatch is a ReassigningParticipantValidation error
/// (not CommonValidation), so if the mediator approves anyway, Phase 7 commits it.
#[test]
fn r2_phase7_stored_unassignment_mismatch_still_commits_on_mediator_approve() {
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r2-p7-stored"));
    let mediator = ParticipantIdentity::generate("r2-p7-stored-m");
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let (envelopes, root_hash) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &rid, &b.stored.instance);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));
    let mut rt = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted,
        ],
    );
    let mut mismatched = baseline_stored_unassignment(&b);
    mismatched.unassignment_ts = REQUEST - 99;
    rt.remember_unassignment(rid, mismatched).unwrap();
    let step = rt.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        rejected_with(&step, "REASSIGNMENT_VALIDATION_FAILED"),
        "{:?}",
        outcome(&step)
    );
    rt.step(&verdict_event(
        &b,
        REQUEST,
        &root_hash,
        &[&mediator],
        REQUEST + 10,
    ))
    .unwrap();
    assert!(
        rt.ledger.is_active(&b.stored.contract_id_hex),
        "stored unassignment mismatch must still commit when mediator approves"
    );
}

/// R-2 Phase 3/7 (§3.2): for a reassigning participant with no StoredUnassignment, an activeness
/// conflict must yield LocalReject (outranking Abstain) and commit if Phase 7 passes & mediator approves.
#[test]
fn r2_reassigning_abstain_with_activeness_conflict_emits_local_reject_and_commits_on_approve() {
    use canton_participant::reassignment_wire::reassignment_id;
    let b = build(ParticipantIdentity::generate("r2-p3-act"));
    let mediator = ParticipantIdentity::generate("r2-p3-act-m");
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let (envelopes, root_hash) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &rid, &b.stored.instance);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    // Case (a): contract already active in ACS + missing StoredUnassignment -> LocalReject in Phase 3.
    let mut rt_active = holding_here(
        following(
            &b,
            &[
                erin_hosted(&b, 1),
                mediator_keys(&mediator),
                mediator_group(0, 1, &[&mediator]),
                vetted.clone(),
            ],
        ),
        &b,
    );
    let s_active = rt_active
        .step(&delivery(envelopes.clone(), REQUEST))
        .unwrap();
    assert!(
        matches!(outcome(&s_active), Outcome::Reject(_)),
        "reassigning active conflict must emit LocalReject over Abstain, got {:?}",
        outcome(&s_active)
    );

    // Case (b): contract locked by an earlier in-flight request (begin_reassignment conflict)
    // + missing StoredUnassignment -> Phase 3 emits LocalReject; once earlier request rejects,
    // mediator Approve still commits the assignment because Phase 7 common checks passed.
    let mut rt_locked = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted,
        ],
    );
    rt_locked
        .ledger
        .begin_until(
            REQUEST - 5,
            canton_participant::view_acs::Effects {
                consumes: vec![],
                creates: vec![(
                    b.stored.contract_id_hex.clone(),
                    "AssetHolding:AssetHolding".into(),
                )],
                instances: vec![b.stored.instance.clone()],
                remote_events: vec![],
            },
            REQUEST + 100,
        )
        .unwrap();
    let s_locked = rt_locked.step(&delivery(envelopes, REQUEST)).unwrap();
    assert!(
        matches!(outcome(&s_locked), Outcome::Reject(_)),
        "reassigning begin_reassignment conflict must override Abstain with LocalReject, got {:?}",
        outcome(&s_locked)
    );
    assert!(rt_locked.ledger.resolve(REQUEST - 5, false).unwrap());
    rt_locked
        .step(&verdict_event(
            &b,
            REQUEST,
            &root_hash,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(
        rt_locked.ledger.is_active(&b.stored.contract_id_hex),
        "valid Phase 7 assignment approved after earlier conflict clears must commit"
    );
}

/// R-2 (§3.2): deactivated mediator group at result time (threshold = 0, then REMOVE)
/// must not validate/commit Approve (`ensureMediatorActive`, `Member.scala:633`).
#[test]
fn r2_phase7_deactivated_mediator_at_result_time_prevents_commit() {
    use canton_participant::reassignment_submit::{assignment, Assignment};
    use canton_participant::reassignment_wire::reassignment_id;
    use canton_participant::topology_wire::{
        mediator_synchronizer_state, mediator_synchronizer_state_at, namespace_delegation, signed,
        stored_form, topology_broadcast, ALL_MEMBERS,
    };
    use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage::Namespace;

    let b = build(ParticipantIdentity::generate("r2-med-deact"));
    let sync_root = ParticipantIdentity::generate("sync-root");
    let sync_uid = format!("sync::{}", sync_root.namespace());
    let sync_phys = format!("{sync_uid}::37-0");
    let m1 = ParticipantIdentity::generate("r2-med-d1");
    let root_delegation_bytes = namespace_delegation(
        sync_root.namespace(),
        sync_root.namespace_key.public_key(&[Namespace]),
    );
    let root_delegation = signed(
        root_delegation_bytes.clone(),
        vec![sync_root
            .namespace_key
            .sign_transaction(&root_delegation_bytes)],
    );
    let initial_group_bytes = mediator_synchronizer_state(&sync_uid, 0, 1, &[&m1.uid()]);
    let initial_group = signed(
        initial_group_bytes.clone(),
        vec![sync_root
            .namespace_key
            .sign_transaction(&initial_group_bytes)],
    );
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    let mut initial_txs = b.me.onboarding_transactions(&sync_uid);
    initial_txs.extend([
        root_delegation,
        erin_hosted(&b, 1),
        mediator_keys(&m1),
        initial_group,
        vetted,
    ]);
    let state: Vec<(i64, Vec<u8>)> = initial_txs.iter().map(|t| (0, stored_form(t))).collect();
    let entries = canton_participant::topology_state::decode(&state).unwrap();
    let mut rt = configured(&b);
    rt.config.physical_synchronizer_id = sync_phys.clone();
    rt.config.follow_topology = true;
    rt.config.hosted_parties = vec![];
    rt.config.submitter_keys = vec![];
    rt.load_topology_state(&entries).unwrap();
    rt.trust_own_submissions(raw_key(&b.me), &b.me.uid());

    let rid = reassignment_id(
        "src::1220bb",
        &sync_uid,
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let built = assignment(
        &b.me,
        &Assignment {
            source: "src::1220bb::37-0",
            target: &sync_phys,
            unassignment_time_micros: REQUEST - 10,
            reassignment_id: &rid,
            instance: &b.stored.instance,
            counter: 1,
            submitter: &b.erin,
            command_id: "r2-med-deact-cmd",
            user_id: "rust-user",
            reassigning_participant_uids: &[b.me.uid()],
            recipients: &[host],
            now_micros: NOW,
        },
        &mut Counter(475),
    )
    .unwrap();
    let envelopes: Vec<Addressed> = built
        .envelopes
        .into_iter()
        .filter_map(|(groups, content)| {
            groups_with_member(&groups, &b.me.member()).map(|to| (to, content))
        })
        .collect();
    rt.remember_unassignment(rid, baseline_stored_unassignment(&b))
        .unwrap();
    let mut req_ev = delivery(envelopes, REQUEST);
    req_ev.physical_synchronizer_id = sync_phys.clone();
    let req_step = rt.step(&req_ev).unwrap();
    assert_eq!(outcome(&req_step), Outcome::Approve, "{:?}", req_step.notes);

    // Broadcast serial 2 mediator group with threshold = 0 (inactive per Member.scala:633: threshold >= 1).
    let deact_bytes = mediator_synchronizer_state_at(&sync_uid, 0, 0, &[m1.uid()], &[], 2);
    let deact_tx = signed(
        deact_bytes.clone(),
        vec![sync_root.namespace_key.sign_transaction(&deact_bytes)],
    );
    let bcast = topology_broadcast(&sync_phys, &[deact_tx]);
    let mut bcast_ev = delivery(vec![(vec![ALL_MEMBERS.into()], bcast)], REQUEST + 1);
    bcast_ev.physical_synchronizer_id = sync_phys.clone();
    rt.step(&bcast_ev).unwrap();

    let mut v_ev = verdict_event(&b, REQUEST, &built.root_hash, &[&m1], REQUEST + 300_000);
    v_ev.physical_synchronizer_id = sync_phys;
    let v_step = rt.step(&v_ev).unwrap();
    assert!(
        !rt.ledger.is_active(&b.stored.contract_id_hex),
        "deactivated mediator group (threshold=0) at result time must not commit Approve: {:?}",
        v_step.notes
    );
}

/// R-2 Phase 7 (§3.2): common validation failures (contract auth, vetting, reassignment-id) also refuse commit.
#[test]
fn r2_phase7_common_auth_vetting_rid_failures_prevent_commit() {
    use canton_participant::reassignment_wire::reassignment_id;
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use prost::Message;

    let b = build(ParticipantIdentity::generate("r2-p7-common"));
    let mediator = ParticipantIdentity::generate("r2-p7-common-m");
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    // 1. Contract authentication failure + Approve -> must not commit.
    let mut ver = Versioned::decode(b.stored.instance.as_slice()).unwrap();
    let mut fci = FatContractInstance::decode(ver.payload.as_slice()).unwrap();
    let last = fci.contract_id.len() - 1;
    fci.contract_id[last] ^= 0xff;
    ver.payload = fci.encode_to_vec();
    let (auth_env, auth_root) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &rid, &ver.encode_to_vec());
    let mut rt_auth = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted.clone(),
        ],
    );
    let _ = rt_auth.step(&delivery(auth_env, REQUEST)).unwrap();
    let _ = rt_auth
        .step(&verdict_event(
            &b,
            REQUEST,
            &auth_root,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(!rt_auth.ledger.is_active(&b.stored.contract_id_hex));

    // 2. Vetting failure + Approve -> must not commit.
    let unvetted = b.me.vetting_transaction(&["00".repeat(32)]);
    let (vet_env, vet_root) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &rid, &b.stored.instance);
    let mut rt_vet = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            unvetted,
        ],
    );
    rt_vet
        .remember_unassignment(rid, baseline_stored_unassignment(&b))
        .unwrap();
    let _ = rt_vet.step(&delivery(vet_env, REQUEST)).unwrap();
    let _ = rt_vet
        .step(&verdict_event(
            &b,
            REQUEST,
            &vet_root,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(!rt_vet.ledger.is_active(&b.stored.contract_id_hex));

    // 3. InconsistentReassignmentId + Approve -> must not commit.
    let bad_rid = reassignment_id(
        "wrong::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let (rid_env, rid_root) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &bad_rid, &b.stored.instance);
    let mut rt_rid = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted,
        ],
    );
    rt_rid
        .remember_unassignment(bad_rid, baseline_stored_unassignment(&b))
        .unwrap();
    let _ = rt_rid.step(&delivery(rid_env, REQUEST)).unwrap();
    let _ = rt_rid
        .step(&verdict_event(
            &b,
            REQUEST,
            &rid_root,
            &[&mediator],
            REQUEST + 10,
        ))
        .unwrap();
    assert!(!rt_rid.ledger.is_active(&b.stored.contract_id_hex));
}

/// R-2 (§3.4): failing `keep_refused_reassignment` persistence on BOTH participant_runtime.rs:828
/// (begin_reassignment conflict) and :888 (Outcome::Reject phase7_valid) must return Err, hold
/// the sequencer cursor, and succeed on retry once storage recovers.
#[test]
fn r2_keep_refused_reassignment_persistence_error_propagates_and_holds_cursor() {
    use canton_participant::reassignment_wire::reassignment_id;
    use canton_participant::state_store::StateStore;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct FailingStore {
        files: Mutex<BTreeMap<String, String>>,
        fail_f: AtomicBool,
    }
    impl StateStore for FailingStore {
        fn read(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.files.lock().unwrap().get(key).cloned())
        }
        fn write(&self, key: &str, text: &str) -> Result<(), String> {
            self.files
                .lock()
                .unwrap()
                .insert(key.to_string(), text.to_string());
            Ok(())
        }
        fn append(&self, key: &str, line: &str) -> Result<(), String> {
            if self.fail_f.load(Ordering::SeqCst)
                && key == "ledger.journal"
                && (line.starts_with("F\t") || line.starts_with("FX\t"))
            {
                return Err("injected keep_refused_reassignment failure".into());
            }
            self.files
                .lock()
                .unwrap()
                .entry(key.to_string())
                .or_default()
                .push_str(&format!("{line}\n"));
            Ok(())
        }
        fn create_new(&self, key: &str, text: &str) -> Result<bool, String> {
            let mut g = self.files.lock().unwrap();
            if g.contains_key(key) {
                return Ok(false);
            }
            g.insert(key.to_string(), text.to_string());
            Ok(true)
        }
        fn describe(&self) -> String {
            "FailingStore".into()
        }
    }

    let b = build(ParticipantIdentity::generate("r2-keep-err"));
    let mediator = ParticipantIdentity::generate("r2-keep-err-m");
    let rid = reassignment_id(
        "src::1220bb",
        "sync::1220aa",
        REQUEST - 10,
        &[(&b.stored.contract_id_hex, 1)],
    );
    let (envelopes, _) =
        assign_envelopes_for(&b, &b.erin, &[&b.me.uid()], &rid, &b.stored.instance);
    let vetted =
        b.me.vetting_transaction(std::slice::from_ref(&b.stored.package_id));

    // Site 1 (line 888): stored unassignment mismatch (Outcome::Reject, phase7_valid=true) with F-line append failing.
    let store1 = Arc::new(FailingStore {
        files: Mutex::new(BTreeMap::new()),
        fail_f: AtomicBool::new(false),
    });
    let mut config1 = following(
        &b,
        &[
            erin_hosted(&b, 1),
            mediator_keys(&mediator),
            mediator_group(0, 1, &[&mediator]),
            vetted,
        ],
    )
    .config;
    config1.follow_topology = false;
    config1.hosted_parties = vec![b.erin.clone(), b.me.uid()];
    config1.submitter_keys = vec![raw_key(&b.me)];
    let mut rt1 = Runtime::open_in(
        config1,
        Engine::load(&dar()).unwrap(),
        Some(Arc::clone(&store1) as Arc<dyn StateStore>),
        0,
    )
    .unwrap();
    let mut bad_stored = baseline_stored_unassignment(&b);
    bad_stored.unassignment_ts = REQUEST - 99;
    rt1.remember_unassignment(rid, bad_stored).unwrap();
    store1.fail_f.store(true, Ordering::SeqCst);
    let err1 = rt1
        .step(&delivery(envelopes.clone(), REQUEST))
        .expect_err("line 888 keep_refused_reassignment failure must propagate Err");
    assert!(err1.contains("Journal"), "got: {err1}");
    assert_eq!(
        rt1.cursor(),
        0,
        "cursor must not advance when persistence fails"
    );
    store1.fail_f.store(false, Ordering::SeqCst);
    rt1.step(&delivery(envelopes.clone(), REQUEST))
        .expect("retry after storage recovery must succeed");
    assert_eq!(rt1.cursor(), REQUEST);

    // Site 2 (line 828): begin_reassignment activeness conflict with F-line append failing.
    let store2 = Arc::new(FailingStore {
        files: Mutex::new(BTreeMap::new()),
        fail_f: AtomicBool::new(false),
    });
    let mut config2 = configured(&b).config;
    config2.mediator_keys = vec![raw_key(&mediator)];
    let mut rt2 = Runtime::open_in(
        config2,
        Engine::load(&dar()).unwrap(),
        Some(Arc::clone(&store2) as Arc<dyn StateStore>),
        0,
    )
    .unwrap();
    rt2.ledger
        .begin_until(
            REQUEST - 5,
            canton_participant::view_acs::Effects {
                consumes: vec![],
                creates: vec![(
                    b.stored.contract_id_hex.clone(),
                    "AssetHolding:AssetHolding".into(),
                )],
                instances: vec![b.stored.instance],
                remote_events: vec![],
            },
            REQUEST + 100,
        )
        .unwrap();
    store2.fail_f.store(true, Ordering::SeqCst);
    let err2 = rt2
        .step(&delivery(envelopes.clone(), REQUEST))
        .expect_err("line 828 keep_refused_reassignment failure must propagate Err");
    assert!(err2.contains("Journal"), "got: {err2}");
    assert_eq!(
        rt2.cursor(),
        0,
        "cursor must not advance on line 828 failure"
    );
    store2.fail_f.store(false, Ordering::SeqCst);
    rt2.step(&delivery(envelopes, REQUEST))
        .expect("retry on line 828 after recovery must succeed");
    assert_eq!(rt2.cursor(), REQUEST);
}

#[test]
fn r16_unhosted_subview_party_triggers_informees_differ_not_at_most() {
    use canton_participant::view_conformance::{check_exercise_view_with_topology, Nonconformance};
    use canton_participant::view_informees::{check_informees, CoreInformees};
    use canton_participant::view_receive::{
        check_views, decrypt_views, revealed_common_metadata, revealed_submitter_metadata,
        root_hash_of_message,
    };
    let me = ParticipantIdentity::generate("r16-chain");
    let me_uid = me.uid();
    let (fingerprint, secret) = (me.encryption_fingerprint(), *me.encryption_secret());
    let c = chain(ParticipantIdentity::from_text(&me.to_text()).unwrap());
    let root_hash = c
        .envelopes
        .iter()
        .find_map(|(_, e)| root_hash_of_message(e))
        .unwrap();
    let mut revealed = Vec::new();
    let mut tree = None;
    for (_, env) in &c.envelopes {
        if let Ok(views) = decrypt_views(env, &fingerprint, &secret) {
            if let Some(t) = views.view_trees.first().and_then(|vt| vt.tree.as_ref()) {
                if revealed_submitter_metadata(t).is_ok() {
                    tree = Some(t.clone());
                }
            }
            revealed.extend(check_views(&views, &root_hash, |_, _| true).unwrap());
        }
    }
    let tree = tree.unwrap();
    let root = revealed.iter().find(|v| v.position.len() == 1).unwrap();
    let subviews: Vec<_> = revealed.iter().filter(|v| v.position.len() > 1).collect();
    let peer2 = subviews
        .iter()
        .flat_map(|v| &v.common_data.informees)
        .find(|p| p.starts_with("peer2::"))
        .unwrap()
        .clone();
    let common = revealed_common_metadata(&tree).unwrap();
    let submitter = revealed_submitter_metadata(&tree).unwrap();

    // Positive control: with `peer2` hosted on another participant, root excludes `peer2` and approves.
    let hosts_with_peer2 = |party: &str| -> Option<(u32, Vec<(String, i32)>)> {
        if party == peer2 {
            Some((1, vec![("other::1220ff".to_string(), 1)]))
        } else {
            Some((1, vec![(me_uid.clone(), 1)]))
        }
    };
    let (_, _, ok_core) = check_exercise_view_with_topology(
        &c.runtime.engine,
        root,
        &subviews,
        &common,
        Some(&submitter.submitting_participant_uid),
        Some(&hosts_with_peer2),
    )
    .unwrap();
    assert!(matches!(ok_core, CoreInformees::Exact(_)), "{ok_core:?}");
    check_informees(root, &ok_core, Some(&submitter.submitting_participant_uid)).unwrap();

    // Negative test (R-16): omitting `peer2`'s host yields Exact (not AtMost fallback), pulling `peer2` into root -> InformeesDiffer.
    let hosts_without_peer2 = |party: &str| -> Option<(u32, Vec<(String, i32)>)> {
        if party == peer2 {
            None
        } else {
            Some((1, vec![(me_uid.clone(), 1)]))
        }
    };
    let (_, _, core) = check_exercise_view_with_topology(
        &c.runtime.engine,
        root,
        &subviews,
        &common,
        Some(&submitter.submitting_participant_uid),
        Some(&hosts_without_peer2),
    )
    .unwrap();
    assert!(
        matches!(core, CoreInformees::Exact(_)),
        "expected Exact core informees even when subview party has empty/None hosts, got {core:?}"
    );
    let err =
        check_informees(root, &core, Some(&submitter.submitting_participant_uid)).unwrap_err();
    assert!(matches!(err, Nonconformance::InformeesDiffer(_)), "{err:?}");
}

/// R-15: wrong view signature must emit `LOCAL_VERDICT_MALFORMED_REQUEST` (keeping `"BadSignature"`).
#[test]
fn r15_bad_signature_emits_local_verdict_malformed_request() {
    let b = build(ParticipantIdentity::generate("r15-badsig"));
    let stranger = ParticipantIdentity::generate("r15-stranger");
    let mut rt = configured(&b);
    let step = rt
        .step(&delivery(signed_by(&b, &stranger), NOW + 5))
        .unwrap();
    assert!(
        matches!(
            outcome(&step),
            Outcome::Malformed(why)
                if why.starts_with("LOCAL_VERDICT_MALFORMED_REQUEST:") && why.contains("BadSignature")
        ),
        "expected LOCAL_VERDICT_MALFORMED_REQUEST for BadSignature, got {:?}",
        outcome(&step)
    );
}

/// R-15: recreating a committed contract must emit `Outcome::Malformed("LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS: ...")`,
/// while recreating a contract still in flight (locked) emits `Outcome::Reject("LOCAL_VERDICT_LOCKED_CONTRACTS: ...")`.
#[test]
fn r15_recreate_committed_contract_emits_creates_existing_contracts_malformed() {
    let b = build(ParticipantIdentity::generate("r15-create-dup"));
    let mut rt = observing(&b);

    let first = rt.step(&delivered(&b, NOW + 5)).unwrap();
    assert_eq!(outcome(&first), Outcome::Approve, "{:?}", first.notes);

    // Unresolved in-flight duplicate create -> Locked (non-malformed Reject).
    let inflight_again = rt.step(&delivered(&b, NOW + 7)).unwrap();
    assert!(
        matches!(
            outcome(&inflight_again),
            Outcome::Reject(why) if why.starts_with("LOCAL_VERDICT_LOCKED_CONTRACTS:")
        ),
        "in-flight duplicate create must emit LOCAL_VERDICT_LOCKED_CONTRACTS Reject, got {:?}",
        outcome(&inflight_again)
    );
    assert!(rt.ledger.resolve(NOW + 7, false).unwrap());

    // Committed contract duplicate create -> CreatesExistingContracts (Malformed).
    assert!(rt.ledger.resolve(NOW + 5, true).unwrap());
    let committed_again = rt.step(&delivered(&b, NOW + 10)).unwrap();
    assert!(
        matches!(
            outcome(&committed_again),
            Outcome::Malformed(why) if why.starts_with("LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS:")
        ),
        "committed duplicate create must emit LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS Malformed, got {:?}",
        outcome(&committed_again)
    );
}

/// The recipients a sequencer writes on an envelope delivered to `member`: the members of every recipient group that contains it (the
/// groups of a root hash message to several participants), or `None` when no group does.
fn groups_with_member(groups: &[Vec<String>], member: &str) -> Option<Vec<String>> {
    let mut to: Vec<String> = groups
        .iter()
        .filter(|g| g.iter().any(|m| m == member))
        .flatten()
        .cloned()
        .collect();
    to.sort();
    to.dedup();
    (!to.is_empty()).then_some(to)
}
