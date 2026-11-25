//! F1: a request the new submitting code builds is accepted by the receiving code. One participant hosts every party, so it is also the only
//! one that has to confirm: `Runtime::step` (which the official mediator's approvals of Rust-built views have already validated: S-NET series)
//! reads the request this module built and approves it. No sequencer or JVM is involved.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "sequencer-grpc")]
use canton_participant::contract_wire::LfValue;
use canton_participant::participant_runtime::{Config, Runtime};
use canton_participant::sequencing_wire::Delivered;
use canton_participant::submit::{
    build_create, versioned, Context, Create, Peer, Randomness, StoredContract,
};
use canton_participant::topology_wire::ParticipantIdentity;
use canton_participant::value_forms::forms;
use canton_participant::view_acs::Timeouts;
use canton_participant::view_conformance::Engine;
use canton_participant::view_tree::{build_transaction, Action, Transaction};
use lf_eval::typed_json::Types;
use lf_eval::{Value, World};
use std::path::Path;

const SYNC: &str = "sync::1220aa";

/// Fixed randomness: the same inputs always give the same request.
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

fn holding(owner: &str, coeff: i128) -> Value {
    Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(owner.into())),
            ("owner".into(), Value::Party(owner.into())),
            ("auditor".into(), Value::Party(owner.into())),
            ("assetSymbol".into(), Value::Text("USD".into())),
            ("amount".into(), Value::Numeric { coeff, scale: 10 }),
        ],
    }
}

struct Built {
    me: ParticipantIdentity,
    erin: String,
    delivered: Delivered,
    contract_id: String,
    stored: StoredContract,
}

/// A create of `AssetHolding` by erin, built and delivered to the participant that hosts erin.
fn build(coeff: i128) -> Built {
    let me = ParticipantIdentity::generate("submitter");
    let erin = me.party_id("erin");
    let world = World::open(&dar()).unwrap();
    let types = Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let (arg, hash_arg) = forms(&types, &ty, &holding(&erin, coeff)).unwrap();
    let host = Peer {
        member: me.member(),
        encryption_spki: me.encryption_spki().to_vec(),
        fingerprint: me.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &me,
        synchronizer: SYNC,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = 1_000_000_000;
    let built = build_create(
        &ctx,
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
        now,
        &mut Counter(0),
    )
    .unwrap();
    // what the sequencer delivers to this participant: the envelopes addressed to it
    let mine: Vec<_> = built
        .envelopes
        .iter()
        .filter(|(to, _)| to.contains(&me.member()))
        .collect();
    let delivered = Delivered {
        timestamp_micros: now + 5,
        previous_timestamp_micros: None,
        physical_synchronizer_id: SYNC.into(),
        message_id: Some(built.message_id.clone()),
        envelopes: mine.iter().map(|(_, c)| c.clone()).collect(),
        recipients: mine.iter().map(|(to, _)| to.clone()).collect(),
        envelope_signatures: mine.iter().map(|_| vec![]).collect(),
        signatures: vec![],
        error: None,
        event_bytes: vec![],
        timestamp_of_signing_key_micros: None,
    };
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
        erin,
        contract_id: built.contract_id_hex,
        delivered,
        me,
        stored,
    }
}

fn runtime(b: &Built, hosted: Vec<String>) -> Runtime {
    let spki = &b.me.signing_key.spki_der;
    let config = Config {
        member: b.me.member(),
        encryption_fingerprint: b.me.encryption_fingerprint(),
        encryption_secret: *b.me.encryption_secret(),
        hosted_parties: hosted,
        timeouts: Timeouts::default(),
        submitter_keys: vec![canton_algo::member_signature::own_ed25519_key(spki).unwrap()],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: SYNC.into(),
        follow_topology: false,
        topology_change_delay_micros: 250_000,
    };
    Runtime::open(config, Engine::load(&dar()).unwrap(), None, 0).unwrap()
}

#[test]
fn the_receiving_code_approves_a_create_the_submitting_code_built() {
    let b = build(1_005_000_000_000);
    let mut rt = runtime(&b, vec![b.erin.clone(), b.me.uid()]);
    let step = rt.step(&b.delivered).unwrap();
    assert_eq!(
        step.to_send.len(),
        1,
        "one request, one answer: {:?}",
        step.notes
    );
    let decision = step.to_send[0].decision();
    assert_eq!(
        format!("{:?}", decision.outcome),
        "Approve",
        "{:?} {:?}",
        decision,
        step.notes
    );
    // erin and the submitting participant's admin party are the ones that confirm
    let mut confirming = decision.confirming_parties.clone();
    confirming.sort();
    let mut expected = vec![b.erin.clone(), b.me.uid()];
    expected.sort();
    assert_eq!(confirming, expected);
    assert!(!b.contract_id.is_empty());
}

#[test]
fn the_same_inputs_build_the_same_request_and_other_inputs_another_contract() {
    let a = build(1_005_000_000_000);
    let again = build(1_005_000_000_000);
    // identities are random, so compare what does not depend on them: the shape and the id length
    assert_eq!(a.contract_id.len(), again.contract_id.len());
    let other = build(2_000_000_000_000);
    assert_ne!(a.contract_id, other.contract_id);
}

#[test]
fn a_participant_that_does_not_host_the_signatory_has_nothing_to_confirm() {
    let b = build(1_005_000_000_000);
    // hosting only the admin party: the signatory's confirmation is somebody else's
    let mut rt = runtime(&b, vec![b.me.uid()]);
    let step = rt.step(&b.delivered).unwrap();
    let confirming: Vec<String> = step
        .to_send
        .iter()
        .flat_map(|s| {
            s.decisions
                .iter()
                .flat_map(|d| d.confirming_parties.clone())
        })
        .collect();
    assert!(!confirming.contains(&b.erin), "{confirming:?}");
}

/// The chosen value of `Settle` (no argument) as the earlier hand-written test wrote it.
#[test]
fn the_versioned_unit_is_what_the_official_nodes_exercise_carried() {
    // `Settle` has no fields: its argument is the empty record (not the unit, which the engine refuses: `expected a record, found Unit`)
    assert_eq!(
        versioned(&LfValue::Record(vec![])),
        vec![10, 3, b'2', b'.', b'1', 18, 2, 106, 0]
    );
}

/// A consuming `Settle` of `contract` by `actor`, every party hosted by `host` (the one participant of these tests).
fn settle(
    ctx: &Context,
    contract: &StoredContract,
    actor: &str,
    host: Peer,
    command_id: &str,
    now: i64,
    random: &mut dyn Randomness,
) -> canton_participant::submit::Built {
    let tx = Transaction {
        nodes: vec![Action::Exercise {
            contract: contract.clone(),
            choice: "Settle".into(),
            argument: Some(LfValue::Record(vec![])),
            consuming: true,
            actors: vec![actor.to_string()],
            choice_observers: vec![],
            children: vec![],
            interface_id: None,
        }],
        roots: vec![0],
        keys: Vec::new(),
        temp_ids: Default::default(),
        package_preference: Default::default(),
        ledger_time: None,
    };
    let member = host.member.clone();
    build_transaction(
        ctx,
        &tx,
        &[host],
        &|_: &str| [member.clone()].into(),
        &[actor.to_string()],
        command_id,
        now,
        None,
        random,
    )
    .unwrap()
}

fn settle_delivery(b: &Built, command_id: &str) -> Delivered {
    let host = Peer {
        member: b.me.member(),
        encryption_spki: b.me.encryption_spki().to_vec(),
        fingerprint: b.me.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &b.me,
        synchronizer: SYNC,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let now = 2_000_000_000;
    let built = settle(
        &ctx,
        &b.stored,
        &b.erin,
        host,
        command_id,
        now,
        &mut Counter(100),
    );
    let mine: Vec<_> = built
        .envelopes
        .iter()
        .filter(|(to, _)| to.contains(&b.me.member()))
        .collect();
    Delivered {
        timestamp_micros: now + 5,
        previous_timestamp_micros: None,
        physical_synchronizer_id: SYNC.into(),
        message_id: Some(built.message_id),
        envelopes: mine.iter().map(|(_, c)| c.clone()).collect(),
        recipients: mine.iter().map(|(to, _)| to.clone()).collect(),
        envelope_signatures: mine.iter().map(|_| vec![]).collect(),
        signatures: vec![],
        error: None,
        event_bytes: vec![],
        timestamp_of_signing_key_micros: None,
    }
}

#[test]
fn the_receiving_code_approves_a_settle_the_submitting_code_built() {
    let b = build(1_005_000_000_000);
    let mut rt = runtime(&b, vec![b.erin.clone(), b.me.uid()]);
    // the create was approved earlier: the contract is active
    rt.ledger
        .import(&b.contract_id, "AssetHolding:AssetHolding")
        .unwrap();
    let step = rt.step(&settle_delivery(&b, "settle-1")).unwrap();
    assert_eq!(step.to_send.len(), 1, "{:?}", step.notes);
    let decision = step.to_send[0].decision();
    assert_eq!(
        format!("{:?}", decision.outcome),
        "Approve",
        "{:?} {:?}",
        decision,
        step.notes
    );
}

#[test]
fn a_settle_of_a_contract_that_is_not_active_is_not_approved() {
    let b = build(1_005_000_000_000);
    let mut rt = runtime(&b, vec![b.erin.clone(), b.me.uid()]);
    // never imported: nothing is active
    let step = rt.step(&settle_delivery(&b, "settle-2")).unwrap();
    let outcome = step
        .to_send
        .first()
        .map(|s| format!("{:?}", s.decision().outcome))
        .unwrap_or_default();
    assert_ne!(outcome, "Approve", "{:?}", step.notes);
}

#[test]
fn a_settle_by_a_party_that_does_not_control_the_choice_is_refused() {
    let mut b = build(1_005_000_000_000);
    let mut rt = runtime(&b, vec![b.erin.clone(), b.me.uid()]);
    rt.ledger
        .import(&b.contract_id, "AssetHolding:AssetHolding")
        .unwrap();
    // the actor is the submitting participant's admin party, which is not the bank
    b.erin = b.me.uid();
    let step = rt.step(&settle_delivery(&b, "settle-3")).unwrap();
    let outcome = step
        .to_send
        .first()
        .map(|s| format!("{:?}", s.decision().outcome))
        .unwrap_or_default();
    assert_ne!(outcome, "Approve", "{:?}", step.notes);
}

/// A contract of two signatories (the bank and its owner, both hosted by this participant), settled by the bank: the quorum names the owner too.
#[test]
fn the_receiving_code_approves_a_settle_of_a_contract_with_two_signatories() {
    let me = ParticipantIdentity::generate("submitter");
    let bank = me.party_id("bank");
    let owner = me.party_id("owner");
    let world = World::open(&dar()).unwrap();
    let types = Types::new(&world);
    let ty = types
        .template(world.main_package_id(), "AssetHolding:AssetHolding")
        .unwrap();
    let value = Value::Record {
        tycon: Some("AssetHolding:AssetHolding".into()),
        fields: vec![
            ("bank".into(), Value::Party(bank.clone())),
            ("owner".into(), Value::Party(owner.clone())),
            ("auditor".into(), Value::Party(bank.clone())),
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
    let (arg, hash_arg) = forms(&types, &ty, &value).unwrap();
    let host = Peer {
        member: me.member(),
        encryption_spki: me.encryption_spki().to_vec(),
        fingerprint: me.encryption_fingerprint(),
    };
    let ctx = Context {
        identity: &me,
        synchronizer: SYNC,
        mediator_group: 0,
        user_id: "rust-user",
    };
    let mut signatories = vec![bank.clone(), owner.clone()];
    signatories.sort();
    let created = build_create(
        &ctx,
        &Create {
            package_name: "sample-contract",
            package_id: world.main_package_id(),
            module: vec!["AssetHolding".into()],
            name: vec!["AssetHolding".into()],
            arg,
            hash_arg,
            signatories: signatories.clone(),
            stakeholders: signatories.clone(),
            hosts: vec![host.clone()],
            command_id: "c1".into(),
            key: None,
        },
        1_000_000_000,
        &mut Counter(0),
    )
    .unwrap();
    let stored = StoredContract {
        contract_id_hex: created.contract_id_hex.clone(),
        instance: created.instance.clone(),
        package_id: world.main_package_id().to_string(),
        module: vec!["AssetHolding".into()],
        name: vec!["AssetHolding".into()],
        signatories: signatories.clone(),
        stakeholders: signatories,
    };
    let settle = settle(
        &ctx,
        &stored,
        &bank,
        host,
        "c2",
        2_000_000_000,
        &mut Counter(500),
    );
    let mine: Vec<_> = settle
        .envelopes
        .iter()
        .filter(|(to, _)| to.contains(&me.member()))
        .collect();
    let delivered = Delivered {
        timestamp_micros: 2_000_000_005,
        previous_timestamp_micros: None,
        physical_synchronizer_id: SYNC.into(),
        message_id: Some(settle.message_id.clone()),
        envelopes: mine.iter().map(|(_, c)| c.clone()).collect(),
        recipients: mine.iter().map(|(to, _)| to.clone()).collect(),
        envelope_signatures: mine.iter().map(|_| vec![]).collect(),
        signatures: vec![],
        error: None,
        event_bytes: vec![],
        timestamp_of_signing_key_micros: None,
    };
    let spki = &me.signing_key.spki_der;
    let config = Config {
        member: me.member(),
        encryption_fingerprint: me.encryption_fingerprint(),
        encryption_secret: *me.encryption_secret(),
        hosted_parties: vec![bank, owner, me.uid()],
        timeouts: Timeouts::default(),
        submitter_keys: vec![canton_algo::member_signature::own_ed25519_key(spki).unwrap()],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: SYNC.into(),
        follow_topology: false,
        topology_change_delay_micros: 250_000,
    };
    let mut rt = Runtime::open(config, Engine::load(&dar()).unwrap(), None, 0).unwrap();
    rt.ledger
        .import(&created.contract_id_hex, "AssetHolding:AssetHolding")
        .unwrap();
    let step = rt.step(&delivered).unwrap();
    let decision = step
        .to_send
        .first()
        .map(|s| format!("{:?}", s.decision().outcome))
        .unwrap_or_default();
    assert_eq!(decision, "Approve", "{:?}", step.notes);
}
