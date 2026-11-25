use super::*;
use crate::view_acs::Effects;
use std::path::PathBuf;

pub(super) fn config() -> Config {
    Config {
        member: "PAR::test::fp".into(),
        encryption_fingerprint: "fp".into(),
        encryption_secret: [7; 32],
        hosted_parties: vec![],
        timeouts: Timeouts::default(),
        submitter_keys: vec![],
        mediator_keys: vec![],
        peer_encryption_keys: Default::default(),
        physical_synchronizer_id: "sync".into(),
        topology_change_delay_micros: 250_000,
        follow_topology: false,
    }
}

pub(super) fn engine() -> Engine {
    Engine::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .expect("the sample DAR is in the repository")
}

pub(super) fn event(at: i64) -> Delivered {
    Delivered {
        timestamp_micros: at,
        previous_timestamp_micros: None,
        physical_synchronizer_id: "sync".into(),
        message_id: None,
        envelopes: vec![],
        recipients: vec![],
        envelope_signatures: vec![],
        signatures: vec![],
        error: None,
        event_bytes: vec![],
        timestamp_of_signing_key_micros: None,
    }
}

fn temp_dir(label: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("canton-rs-runtime-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn the_cursor_follows_the_events_and_survives_a_restart() {
    let dir = temp_dir("cursor");
    let mut rt = Runtime::open(config(), engine(), Some(&dir), 100).unwrap();
    assert_eq!(rt.cursor(), 100, "a new state starts where it is told to");
    rt.step(&event(150)).unwrap();
    assert_eq!(rt.cursor(), 150);
    drop(rt);
    let mut rt = Runtime::open(config(), engine(), Some(&dir), 100).unwrap();
    assert_eq!(
        rt.cursor(),
        150,
        "an existing state continues where it stopped"
    );
    rt.rewind(120).unwrap();
    drop(rt);
    let rt = Runtime::open(config(), engine(), Some(&dir), 100).unwrap();
    assert_eq!(rt.cursor(), 120, "a rewind is saved too");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_time_of_an_event_expires_the_requests_whose_decision_time_has_passed() {
    let mut rt = Runtime::open(config(), engine(), None, 0).unwrap();
    rt.ledger
        .begin_until(
            10,
            Effects {
                consumes: vec![],
                creates: vec![("cid".into(), "T".into())],
                instances: Vec::new(),
                remote_events: Vec::new(),
            },
            1_000,
        )
        .unwrap();
    let early = rt.step(&event(999)).unwrap();
    assert!(
        early.expired.is_empty(),
        "before the decision time nothing expires"
    );
    assert_eq!(rt.ledger.in_flight(), 1);
    let late = rt.step(&event(1_000)).unwrap();
    assert_eq!(late.expired, vec![10]);
    assert_eq!(rt.ledger.in_flight(), 0);
    assert!(
        !rt.ledger.is_active("cid"),
        "an expired request creates nothing"
    );
}

/// A topology change is in force from its sequencing time plus the topology change delay: what the runtime reads from an event
/// sequenced inside that delay is still judged by the state before it, and the change counts once an event past the delay arrives.
#[test]
fn a_topology_change_waits_for_its_effective_time() {
    use crate::topology_wire::{topology_broadcast, ParticipantIdentity};
    let me = ParticipantIdentity::generate("effective");
    let synchronizer_uid = "sync::1220aa";
    let onboarding = me.onboarding_transactions(synchronizer_uid);
    let state: Vec<(i64, Vec<u8>)> = onboarding
        .iter()
        .map(|t| (0, crate::topology_wire::stored_form(t)))
        .collect();
    let entries = crate::topology_state::decode(&state).unwrap();
    let mut cfg = config();
    cfg.member = me.member();
    cfg.follow_topology = true;
    cfg.physical_synchronizer_id = "sync::1220aa::37-0".into();
    let mut rt = Runtime::open(cfg, engine(), None, 0).unwrap();
    rt.load_topology_state(&entries).unwrap();
    assert!(rt.config.hosted_parties.is_empty());

    // the hosting is sequenced at 1 000 000 and takes effect at 1 250 000
    let erin = me.party_id("erin");
    let mut hosting = event(1_000_000);
    hosting.envelopes = vec![topology_broadcast(
        "sync",
        &[me.party_hosting_transaction("erin")],
    )];
    // addressed to this participant alone: discarded
    hosting.recipients = vec![vec![me.member()]];
    let step = rt.step(&hosting).unwrap();
    assert_eq!(rt.pending_topology_changes(), 0, "{:?}", step.notes);
    hosting.recipients = vec![vec![crate::topology_wire::ALL_MEMBERS.to_string()]];
    let step = rt.step(&hosting).unwrap();
    assert!(step.topology_changed);
    assert_eq!(
        rt.pending_topology_changes(),
        1,
        "it waits for its effective time"
    );
    assert!(
        rt.config.hosted_parties.is_empty(),
        "not in force on the event that carries it"
    );
    // an event inside the delay is judged by the old state
    rt.step(&event(1_100_000)).unwrap();
    assert!(
        rt.config.hosted_parties.is_empty(),
        "inside the delay: still the old state"
    );
    // an event exactly at the effective time is too: the state at a time is what took effect strictly before it
    rt.step(&event(1_250_000)).unwrap();
    assert!(
        rt.config.hosted_parties.is_empty(),
        "at the effective time itself: still the old state"
    );
    // past it, the change is in force and nothing waits any more
    let step = rt.step(&event(1_250_001)).unwrap();
    assert_eq!(rt.config.hosted_parties, vec![erin], "{:?}", step.notes);
    assert_eq!(rt.pending_topology_changes(), 0);
    assert!(
        step.notes.iter().any(|n| n.contains("is in force")),
        "{:?}",
        step.notes
    );
}

/// T-3: the runtime follows the synchronizer it is configured for: parameters of another synchronizer, signed by that synchronizer's
/// namespace, do not change its time limits.
#[test]
fn the_runtime_takes_no_parameters_of_another_synchronizer() {
    use crate::topology_wire::{topology_broadcast, ParticipantIdentity};
    let me = ParticipantIdentity::generate("elsewhere");
    let onboarding = me.onboarding_transactions("sync::1220aa");
    let state: Vec<(i64, Vec<u8>)> = onboarding
        .iter()
        .map(|t| (0, crate::topology_wire::stored_form(t)))
        .collect();
    let entries = crate::topology_state::decode(&state).unwrap();
    let mut cfg = config();
    cfg.member = me.member();
    cfg.follow_topology = true;
    cfg.physical_synchronizer_id = "sync::1220aa::37-0".into();
    let mut unparsed = Runtime::open(config(), engine(), None, 0).unwrap();
    assert!(
        unparsed.load_topology_state(&entries).is_err(),
        "a synchronizer id that does not parse is an error, not a tracker that follows any synchronizer"
    );
    let mut rt = Runtime::open(cfg, engine(), None, 0).unwrap();
    rt.load_topology_state(&entries).unwrap();
    let before = rt.config.timeouts;

    // synchronizer `other` is in the participant's own namespace, so the participant's key is that synchronizer's owner
    let mut parameters = crate::topology_wire::default_dynamic_parameters();
    parameters.confirmation_response_timeout = Some(prost_types::Duration {
        seconds: 77,
        nanos: 0,
    });
    let other = format!("other::{}", me.namespace());
    let bytes = crate::topology_wire::synchronizer_parameters_state(&other, parameters);
    let signed = crate::topology_wire::signed(
        bytes.clone(),
        vec![me.namespace_key.sign_transaction(&bytes)],
    );
    let mut broadcast = event(1_000_000);
    broadcast.envelopes = vec![topology_broadcast("sync", &[signed])];
    broadcast.recipients = vec![vec![crate::topology_wire::ALL_MEMBERS.to_string()]];
    rt.step(&broadcast).unwrap();
    let step = rt.step(&event(2_000_000)).unwrap();
    assert_eq!(rt.config.timeouts, before, "{:?}", step.notes);
    assert!(
        step.notes.iter().any(|n| n.contains("while following")),
        "{:?}",
        step.notes
    );
}
