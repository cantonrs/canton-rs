//! A logical synchronizer upgrade between two Rust sequencers (S-NET-038): the predecessor announces the upgrade and the sequencer's
//! connection on the successor, its topology freezes, and the successor seeded from the predecessor's state directory is the same
//! synchronizer one serial on, with the same sequencer, members and topology and none of the events.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect, Token};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{self as tw, ParticipantIdentity};
use canton_sequencer_server::{new_synchronizer_in, SynchronizerConfig};
use std::time::Duration;

struct Running {
    runtime: tokio::runtime::Runtime,
    config: SynchronizerConfig,
    url: String,
}

fn start(dir: &std::path::Path, port: u16, control: Option<std::path::PathBuf>) -> Running {
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = new_synchronizer_in(dir, "upsync", "us1", 1).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (served, state) = (config.clone(), dir.to_path_buf());
    runtime.spawn(async move {
        canton_sequencer_server::serve_with(
            address,
            served,
            canton_sequencer_server::ServeOptions {
                state_dir: Some(state),
                control,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Running {
        runtime,
        config,
        url: format!("http://{address}"),
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn authenticate(
    client: &mut SequencerConnect,
    identity: &ParticipantIdentity,
    physical: &str,
) -> Token {
    let challenge = client.challenge(&identity.member(), &[37]).unwrap();
    let signature = identity
        .sequencer_auth_key
        .sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, physical).unwrap());
    client
        .authenticate(&identity.member(), &challenge.nonce, signature)
        .unwrap()
}

/// `(timestamp, previous timestamp, contents)` of the events a member reads from the beginning.
fn events(
    client: &mut SequencerConnect,
    identity: &ParticipantIdentity,
    physical: &str,
    token: &Token,
    count: usize,
) -> Vec<(i64, Option<i64>, Vec<Vec<u8>>)> {
    client
        .subscribe(
            &identity.member(),
            physical,
            token,
            Some(0),
            count,
            Duration::from_secs(3),
        )
        .unwrap()
        .iter()
        .map(|e| {
            let d = sw::decode_delivered(e).unwrap();
            (d.timestamp_micros, d.previous_timestamp_micros, d.envelopes)
        })
        .collect()
}

fn in_a_minute() -> i64 {
    canton_sequencer_server::sequencing::wall_micros() + 60_000_000
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_successor_is_the_same_synchronizer_one_serial_on_with_the_members_and_topology_and_no_events(
) {
    let base = std::env::temp_dir().join(format!("canton-rs-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (old_dir, new_dir) = (base.join("predecessor"), base.join("successor"));
    let control = base.join("control");
    std::fs::create_dir_all(&base).unwrap();
    let (old_port, new_port) = (free_port(), free_port());
    let old = start(&old_dir, old_port, Some(control.clone()));
    let physical = old.config.physical_synchronizer_id();
    assert!(physical.ends_with("::37-0"), "{physical}");
    let synchronizer_uid = old.config.synchronizer_uid();
    let a = ParticipantIdentity::generate("up-a");
    let mut ca = SequencerConnect::connect(&old.url).unwrap();
    ca.register_onboarding(
        &a.member(),
        &physical,
        a.onboarding_transactions(&synchronizer_uid),
    )
    .unwrap();
    let ta = authenticate(&mut ca, &a, &physical);
    std::thread::sleep(Duration::from_millis(900));
    let hash_before = ca
        .download_topology_state_hash(&a.member(), &physical, &ta)
        .unwrap();

    // ---- the operator announces the upgrade, with the sequencer's connection on the successor
    let endpoint = format!("http://127.0.0.1:{new_port}");
    // the upgrade 25 seconds from now: the frozen predecessor and the successor before its upgrade time are looked at before then
    let upgrade_at = canton_sequencer_server::sequencing::wall_micros() + 25_000_000;
    std::fs::write(&control, format!("upgrade 25 {endpoint}\n")).unwrap();
    // the announcement, then (once it is in force) the connection
    std::thread::sleep(Duration::from_millis(2800));
    let seen = events(&mut ca, &a, &physical, &ta, 30);
    let successor_psid = format!("{synchronizer_uid}::37-1");
    assert!(
        seen.iter()
            .flat_map(|e| &e.2)
            .any(|c| contains(c, successor_psid.as_bytes()) && contains(c, endpoint.as_bytes())),
        "the members are sent the announcement and the connection on the successor"
    );
    let hash_announced = ca
        .download_topology_state_hash(&a.member(), &physical, &ta)
        .unwrap();
    assert_ne!(
        hash_announced, hash_before,
        "the announcement is in the topology state"
    );

    // ---- the topology is frozen: a hosting change is not taken, and a new member cannot register
    let hosting = sw::submission_request_to_groups(
        &a.member(),
        "hosting",
        &[(
            vec![tw::ALL_MEMBERS.to_string()],
            tw::topology_broadcast(&physical, &[a.party_hosting_transaction("alice")]),
        )],
        in_a_minute(),
    );
    ca.send_async(
        &a.member(),
        &physical,
        &ta,
        sw::signed_submission_request(hosting, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(
        ca.download_topology_state_hash(&a.member(), &physical, &ta)
            .unwrap(),
        hash_announced,
        "a topology change after the announcement is not taken"
    );
    let late = ParticipantIdentity::generate("up-late");
    let refused = ca
        .register_onboarding(
            &late.member(),
            &physical,
            late.onboarding_transactions(&synchronizer_uid),
        )
        .expect_err("no new member while the topology is frozen");
    assert!(
        format!("{refused:?}").contains("is frozen due to an announced LSU"),
        "{refused:?}"
    );
    let old_events = events(&mut ca, &a, &physical, &ta, 40);

    // ---- the successor, seeded from the predecessor's state directory
    assert_eq!(
        canton_sequencer_server::persistence::seed_successor(&old_dir, &new_dir).unwrap(),
        1
    );
    let new = start(&new_dir, new_port, None);
    let mut cn = SequencerConnect::connect(&new.url).unwrap();
    let id = cn.synchronizer_id().unwrap();
    assert_eq!(id.physical_synchronizer_id, successor_psid, "one serial on");
    assert_eq!(
        id.sequencer_uid,
        old.config.sequencer_uid(),
        "the same sequencer"
    );
    let (version, parameters) = cn.synchronizer_parameters().unwrap();
    assert_eq!(version, "v32");
    assert!(parameters.contains("serial: 1"), "{parameters}");
    // the member is known there and authenticates against the successor's id
    assert!(cn.is_active_as(&a.member(), &successor_psid, None).unwrap());
    let tn = authenticate(&mut cn, &a, &successor_psid);
    // the same topology (the announcement that led here is not one the successor is under: it is not frozen)
    let hash_new = cn
        .download_topology_state_hash(&a.member(), &successor_psid, &tn)
        .unwrap();
    assert_eq!(
        hash_new, hash_announced,
        "the successor's topology is the predecessor's"
    );
    // none of the predecessor's events
    assert!(events(&mut cn, &a, &successor_psid, &tn, 5).is_empty());
    // before the upgrade time the successor onboards no one, and what is sent is not sequenced (only time proofs would be)
    assert!(
        canton_sequencer_server::sequencing::wall_micros() < upgrade_at,
        "the checks before the upgrade time ran before it"
    );
    let early = ParticipantIdentity::generate("up-early");
    let refused = cn
        .register_onboarding(
            &early.member(),
            &successor_psid,
            early.onboarding_transactions(&synchronizer_uid),
        )
        .expect_err("no onboarding before the upgrade time");
    assert!(
        format!("{refused:?}").contains("Onboarding is possible only after"),
        "{refused:?}"
    );
    let too_early = sw::submission_request_to_groups(
        &a.member(),
        "too-early",
        &[(vec![a.member()], b"before the upgrade time".to_vec())],
        in_a_minute(),
    );
    cn.send_async(
        &a.member(),
        &successor_psid,
        &tn,
        sw::signed_submission_request(too_early, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert!(
        events(&mut cn, &a, &successor_psid, &tn, 5).is_empty(),
        "a submission before the upgrade time is not sequenced"
    );
    // the server reads its control file about twice a second: its upgrade time is up to half a second after `upgrade_at`
    let wait = upgrade_at - canton_sequencer_server::sequencing::wall_micros() + 1_500_000;
    std::thread::sleep(Duration::from_micros(wait.max(0) as u64));
    // after it: what the member reads there starts with no previous event, after everything before
    let hello = sw::submission_request_to_groups(
        &a.member(),
        "hello",
        &[(vec![a.member()], b"hello on the successor".to_vec())],
        in_a_minute(),
    );
    cn.send_async(
        &a.member(),
        &successor_psid,
        &tn,
        sw::signed_submission_request(hello, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    let first = events(&mut cn, &a, &successor_psid, &tn, 5);
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(
        first[0].1, None,
        "the first event on the successor has no previous one"
    );
    assert!(first[0]
        .2
        .iter()
        .any(|c| contains(c, b"hello on the successor")));
    assert!(first[0].0 > old_events.last().unwrap().0);
    // a topology change is taken again on the successor
    let hosting = sw::submission_request_to_groups(
        &a.member(),
        "hosting-new",
        &[(
            vec![tw::ALL_MEMBERS.to_string()],
            tw::topology_broadcast(&successor_psid, &[a.party_hosting_transaction("alice")]),
        )],
        in_a_minute(),
    );
    cn.send_async(
        &a.member(),
        &successor_psid,
        &tn,
        sw::signed_submission_request(hosting, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(900));
    assert_ne!(
        cn.download_topology_state_hash(&a.member(), &successor_psid, &tn)
            .unwrap(),
        hash_new,
        "the successor is not frozen"
    );
    // seeding again does nothing: the successor keeps what it has
    assert_eq!(
        canton_sequencer_server::persistence::seed_successor(&old_dir, &new_dir).unwrap(),
        1
    );
    drop((ca, cn));
    old.runtime.shutdown_background();
    new.runtime.shutdown_background();
    let _ = std::fs::remove_dir_all(&base);
}
