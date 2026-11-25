//! A Rust sequencer restarted on its state directory is the same synchronizer: the same identity, the same members, the same topology
//! state and the same events (S-NET-037 part 16).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;
use canton_participant::confirmation_wire as cw;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect, Token};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::ParticipantIdentity;
use canton_sequencer_server::{new_synchronizer_in, SynchronizerConfig};
use std::time::Duration;

struct Running {
    runtime: tokio::runtime::Runtime,
    config: SynchronizerConfig,
    url: String,
}

fn start(dir: &std::path::Path, port: u16) -> Running {
    start_with(dir, port, None)
}

/// Like [`start`], and the running server shortens its journal every `compact_every`.
fn start_with(dir: &std::path::Path, port: u16, compact_every: Option<Duration>) -> Running {
    let address: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = new_synchronizer_in(dir, "persync", "ps1", 1).unwrap();
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
                compact_every,
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

impl Running {
    /// Stops the server (its tasks are dropped with the runtime): what it did not journal is lost, as in a crash.
    fn stop(self) {
        self.runtime.shutdown_background();
        std::thread::sleep(Duration::from_millis(300));
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

type Shape = (
    i64,
    Option<i64>,
    Option<String>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
    Vec<Vec<canton_proto::com::digitalasset::canton::crypto::v30::Signature>>,
    Vec<canton_proto::com::digitalasset::canton::crypto::v30::Signature>,
);

/// Everything a member can tell apart in the events it reads from the beginning.
fn events(
    client: &mut SequencerConnect,
    identity: &ParticipantIdentity,
    physical: &str,
    token: &Token,
    count: usize,
) -> Vec<Shape> {
    client
        .subscribe(
            &identity.member(),
            physical,
            token,
            Some(0),
            count,
            Duration::from_secs(4),
        )
        .unwrap()
        .iter()
        .map(|e| {
            let d = sw::decode_delivered(e).unwrap();
            (
                d.timestamp_micros,
                d.previous_timestamp_micros,
                d.message_id,
                d.envelopes,
                d.recipients,
                d.envelope_signatures,
                d.signatures,
            )
        })
        .collect()
}

fn far_future() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
        + 60_000_000
}

#[test]
fn a_restarted_sequencer_is_the_same_synchronizer_with_the_same_members_topology_and_events() {
    let dir = std::env::temp_dir().join(format!("canton-rs-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let first = start(&dir, port);
    let physical = first.config.physical_synchronizer_id();
    let synchronizer_uid = format!(
        "{}::{}",
        first.config.name, first.config.namespace_fingerprint
    );
    let (a, b) = (
        ParticipantIdentity::generate("pers-a"),
        ParticipantIdentity::generate("pers-b"),
    );
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&first.url).unwrap(),
        SequencerConnect::connect(&first.url).unwrap(),
    );
    for (c, id) in [(&mut ca, &a), (&mut cb, &b)] {
        c.register_onboarding(
            &id.member(),
            &physical,
            id.onboarding_transactions(&synchronizer_uid),
        )
        .unwrap();
    }
    let (ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    std::thread::sleep(Duration::from_millis(900));
    // a hosting broadcast the state takes, and a message from a to b
    let hosting = a.party_hosting_transaction("alice");
    let broadcast = sw::submission_request_to_groups(
        &a.member(),
        "hosting",
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            canton_participant::topology_wire::topology_broadcast(&physical, &[hosting]),
        )],
        far_future(),
    );
    ca.send_async(
        &a.member(),
        &physical,
        &ta,
        sw::signed_submission_request(broadcast, &a.signing_key),
    )
    .unwrap();
    let message = sw::submission_request_to_groups(
        &a.member(),
        "hello",
        &[(vec![b.member()], b"hello before the restart".to_vec())],
        far_future(),
    );
    ca.send_async(
        &a.member(),
        &physical,
        &ta,
        sw::signed_submission_request(message, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    let before_b = events(&mut cb, &b, &physical, &tb, 30);
    let before_a = events(&mut ca, &a, &physical, &ta, 30);
    let state_hash_before = ca
        .download_topology_state_hash(&a.member(), &physical, &ta)
        .unwrap();
    assert!(
        before_b.iter().any(|e| e
            .3
            .iter()
            .any(|c| c.windows(24).any(|w| w == b"hello before the restart"))),
        "b was sent the message"
    );
    drop((ca, cb));
    first.stop();

    // ---- the restart on the same directory
    let second = start(&dir, port);
    assert_eq!(
        second.config.physical_synchronizer_id(),
        physical,
        "the keys are the synchronizer's identity"
    );
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&second.url).unwrap(),
        SequencerConnect::connect(&second.url).unwrap(),
    );
    // the members are still registered and authenticate again (a token is not kept)
    assert!(ca.is_active_as(&a.member(), &physical, None).unwrap());
    let (ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    // the events are the same: timestamps, chain links, envelopes, recipients, signatures
    assert_eq!(events(&mut cb, &b, &physical, &tb, 30), before_b);
    assert_eq!(events(&mut ca, &a, &physical, &ta, 30), before_a);
    // the topology state is the same
    assert_eq!(
        ca.download_topology_state_hash(&a.member(), &physical, &ta)
            .unwrap(),
        state_hash_before
    );
    // what is sequenced now comes after everything before, and continues the chain the old events left
    let message = sw::submission_request_to_groups(
        &a.member(),
        "after",
        &[(vec![b.member()], b"hello after the restart".to_vec())],
        far_future(),
    );
    ca.send_async(
        &a.member(),
        &physical,
        &ta,
        sw::signed_submission_request(message, &a.signing_key),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    let later = events(&mut cb, &b, &physical, &tb, 40);
    assert_eq!(later.len(), before_b.len() + 1);
    let (old, new) = (before_b.last().unwrap(), later.last().unwrap());
    assert!(new.0 > old.0, "later than everything before the restart");
    assert_eq!(new.1, Some(old.0), "the chain continues");
    drop((ca, cb));
    second.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A request in flight when the sequencer is killed is still decided afterwards: the mediator's state is rebuilt from the journal.
#[test]
fn a_request_in_flight_when_the_sequencer_restarts_is_decided_when_its_answer_arrives() {
    use canton_participant::view_acs::{decode_verdict, mediator_signed};
    let dir = std::env::temp_dir().join(format!("canton-rs-inflight-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let first = start(&dir, port);
    let physical = first.config.physical_synchronizer_id();
    let mut m = common::join(&first.url, &first.config, "inflight");
    m.settle(&physical);
    let party = common::host(&mut m, &physical, "erin");
    m.settle(&physical);
    let now = m
        .client
        .sequencer_time(&m.identity.member(), &physical, Some(&m.token))
        .unwrap()
        .unwrap();
    let tree = common::request_tree(&m.identity, &[&party], 1, 0, now, &physical);
    let mediator = cw::mediator_group(0);
    m.send(
        &physical,
        &[
            (
                vec![mediator.clone()],
                cw::informee_message_signed_over(&tree, &m.identity.signing_key, &tree.root_hash),
            ),
            (
                vec![mediator.clone(), m.identity.member()],
                cw::root_hash_message(&tree.root_hash, &physical, now),
            ),
        ],
        "confirmation-request",
        now + 60_000_000,
    )
    .unwrap();
    let request_id = m
        .events(&physical, Some(0), 40)
        .iter()
        .rev()
        .find(|e| e.message_id.as_deref() == Some("confirmation-request"))
        .expect("the request is sequenced")
        .timestamp_micros;
    // killed with the request waiting for its answer
    drop(m.client);
    first.stop();
    let second = start(&dir, port);
    let mut client = SequencerConnect::connect(&second.url).unwrap();
    let token = authenticate(&mut client, &m.identity, &physical);
    let (content, signatures) = cw::confirmation_responses(
        request_id,
        &tree.root_hash,
        &physical,
        &m.identity.member(),
        &[cw::ViewResponse {
            view_position: &[vec![]],
            outcome: cw::Outcome::Approve,
            confirming_parties: std::slice::from_ref(&party),
        }],
        &m.identity.signing_key,
    );
    client
        .send_async(
            &m.identity.member(),
            &physical,
            &token,
            sw::signed_submission_request(
                sw::submission_request_signed(
                    &m.identity.member(),
                    "response",
                    &[(vec![mediator], content, signatures)],
                    request_id + 30_000_000,
                ),
                &m.identity.signing_key,
            ),
        )
        .unwrap();
    let mediator_key = canton_algo::member_signature::own_ed25519_key(
        &second.config.keys.mediator_key(0).spki_der,
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut approved = None;
    while approved.is_none() && std::time::Instant::now() < deadline {
        for e in client
            .subscribe(
                &m.identity.member(),
                &physical,
                &token,
                Some(request_id + 1),
                20,
                Duration::from_secs(2),
            )
            .unwrap_or_default()
        {
            let d = sw::decode_delivered(&e).unwrap();
            for (content, signatures) in d.envelopes.iter().zip(&d.envelope_signatures) {
                if let Some((verdict, hash)) = decode_verdict(content) {
                    if verdict.request_id == request_id {
                        assert!(mediator_signed(
                            signatures,
                            &hash,
                            std::slice::from_ref(&mediator_key)
                        ));
                        approved = Some(verdict.approved);
                    }
                }
            }
        }
    }
    assert_eq!(
        approved,
        Some(true),
        "the mediator that was restarted still knew the request and approved it"
    );
    second.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// What a member acknowledged is forgotten at the next start, and the journal is shorter for it; what it did not acknowledge, and what
/// the others were sent, stays.
#[test]
fn what_a_member_acknowledged_is_forgotten_at_the_next_start_and_the_journal_shrinks() {
    let dir = std::env::temp_dir().join(format!("canton-rs-ack-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let first = start(&dir, port);
    let physical = first.config.physical_synchronizer_id();
    let uid = format!(
        "{}::{}",
        first.config.name, first.config.namespace_fingerprint
    );
    let (a, b) = (
        ParticipantIdentity::generate("ack-a"),
        ParticipantIdentity::generate("ack-b"),
    );
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&first.url).unwrap(),
        SequencerConnect::connect(&first.url).unwrap(),
    );
    for (c, id) in [(&mut ca, &a), (&mut cb, &b)] {
        c.register_onboarding(&id.member(), &physical, id.onboarding_transactions(&uid))
            .unwrap();
    }
    let (ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    std::thread::sleep(Duration::from_millis(900));
    for text in ["one", "two", "three"] {
        let request = sw::submission_request_to_groups(
            &a.member(),
            text,
            &[(vec![b.member()], text.as_bytes().to_vec())],
            far_future(),
        );
        ca.send_async(
            &a.member(),
            &physical,
            &ta,
            sw::signed_submission_request(request, &a.signing_key),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(150));
    }
    let all_b = events(&mut cb, &b, &physical, &tb, 40);
    let all_a = events(&mut ca, &a, &physical, &ta, 40);
    let second_message = all_b
        .iter()
        .find(|e| e.2.is_none() && e.3.iter().any(|c| c.ends_with(b"two")))
        .expect("b was sent the second message")
        .0;
    // b acknowledges up to the second message; a stranger's and a forged acknowledgement are refused
    cb.acknowledge_signed(
        &b.member(),
        &physical,
        &tb,
        sw::signed_acknowledge_request(&b.member(), second_message, &b.signing_key),
    )
    .unwrap();
    let refused = |r: Result<(), canton_participant::sequencer_connect::ConnectError>| {
        r.expect_err("refused").to_string()
    };
    assert!(
        refused(cb.acknowledge_signed(
            &b.member(),
            &physical,
            &tb,
            sw::signed_acknowledge_request(&a.member(), second_message, &b.signing_key),
        ))
        .contains("on behalf of"),
        "an acknowledgement for another member"
    );
    assert!(
        refused(cb.acknowledge_signed(
            &b.member(),
            &physical,
            &tb,
            sw::signed_acknowledge_request(&b.member(), second_message, &a.signing_key),
        ))
        .contains("does not verify"),
        "an acknowledgement signed with another member's key"
    );
    // an acknowledgement of a time the sequencer has not reached yet is refused and not kept
    let ahead = all_b.last().unwrap().0 + 3_600_000_000;
    let why = refused(cb.acknowledge_signed(
        &b.member(),
        &physical,
        &tb,
        sw::signed_acknowledge_request(&b.member(), ahead, &b.signing_key),
    ));
    assert!(
        why.contains("INVALID_ACKNOWLEDGEMENT_TIMESTAMP") && why.contains("invalid argument"),
        "{why}"
    );
    let lines_before = std::fs::read_to_string(dir.join("journal"))
        .unwrap()
        .lines()
        .count();
    drop((ca, cb));
    first.stop();

    let second = start(&dir, port);
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&second.url).unwrap(),
        SequencerConnect::connect(&second.url).unwrap(),
    );
    let (ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    let after_b = events(&mut cb, &b, &physical, &tb, 40);
    assert!(
        after_b.iter().all(|e| e.0 > second_message),
        "b reads nothing it acknowledged: {:?}",
        after_b.iter().map(|e| e.0).collect::<Vec<_>>()
    );
    assert!(
        after_b
            .iter()
            .any(|e| e.3.iter().any(|c| c.ends_with(b"three"))),
        "the message after the acknowledgement is still there"
    );
    assert_eq!(
        events(&mut ca, &a, &physical, &ta, 40),
        all_a,
        "a acknowledged nothing: everything it was sent is still there"
    );
    let lines_after = std::fs::read_to_string(dir.join("journal"))
        .unwrap()
        .lines()
        .count();
    assert!(
        lines_after < lines_before,
        "the journal shrank: {lines_before} -> {lines_after}"
    );
    drop((ca, cb));
    second.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AT-P03: the mediator crashes after some of the confirmations a request needs and restarts. It recovers what it needs from its journal,
/// and never makes a verdict that contradicts another: one verdict per request, the one the confirmations make, also when the sequencer
/// restarts again afterwards or a late response comes in.
#[test]
fn a_mediator_that_crashes_after_some_confirmations_decides_once_and_never_both_ways() {
    use canton_participant::view_acs::decode_verdict;
    for second_approves in [true, false] {
        let dir = std::env::temp_dir().join(format!(
            "canton-rs-p03-{}-{second_approves}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let port = free_port();
        let first = start(&dir, port);
        let physical = first.config.physical_synchronizer_id();
        let mut m1 = common::join(&first.url, &first.config, "p03-one");
        let mut m2 = common::join(&first.url, &first.config, "p03-two");
        m1.settle(&physical);
        m2.settle(&physical);
        let ann = common::host(&mut m1, &physical, "ann");
        let ben = common::host(&mut m2, &physical, "ben");
        m1.settle(&physical);
        let now = m1
            .client
            .sequencer_time(&m1.identity.member(), &physical, Some(&m1.token))
            .unwrap()
            .unwrap();
        // a request that both ann and ben have to confirm (threshold 2)
        let tree = common::request_tree(&m1.identity, &[&ann, &ben], 2, 0, now, &physical);
        let mediator = cw::mediator_group(0);
        m1.send(
            &physical,
            &[
                (
                    vec![mediator.clone()],
                    cw::informee_message_signed_over(
                        &tree,
                        &m1.identity.signing_key,
                        &tree.root_hash,
                    ),
                ),
                (
                    vec![mediator.clone(), m1.identity.member()],
                    cw::root_hash_message(&tree.root_hash, &physical, now),
                ),
                (
                    vec![mediator.clone(), m2.identity.member()],
                    cw::root_hash_message(&tree.root_hash, &physical, now),
                ),
            ],
            "confirmation-request",
            now + 60_000_000,
        )
        .unwrap();
        let request_id = m1
            .events(&physical, Some(0), 40)
            .iter()
            .rev()
            .find(|e| e.message_id.as_deref() == Some("confirmation-request"))
            .expect("the request is sequenced")
            .timestamp_micros;
        let respond = |client: &mut SequencerConnect,
                       identity: &ParticipantIdentity,
                       token: &Token,
                       party: &str,
                       outcome: cw::Outcome,
                       id: &str| {
            let (content, signatures) = cw::confirmation_responses(
                request_id,
                &tree.root_hash,
                &physical,
                &identity.member(),
                &[cw::ViewResponse {
                    view_position: &[vec![]],
                    outcome,
                    confirming_parties: &[party.to_string()],
                }],
                &identity.signing_key,
            );
            client
                .send_async(
                    &identity.member(),
                    &physical,
                    token,
                    sw::signed_submission_request(
                        sw::submission_request_signed(
                            &identity.member(),
                            id,
                            &[(vec![cw::mediator_group(0)], content, signatures)],
                            request_id + 30_000_000,
                        ),
                        &identity.signing_key,
                    ),
                )
                .unwrap();
        };
        // ann confirms; ben has not yet: no verdict, and the mediator crashes
        respond(
            &mut m1.client,
            &m1.identity,
            &m1.token,
            &ann,
            cw::Outcome::Approve,
            "r-ann",
        );
        std::thread::sleep(Duration::from_millis(800));
        let verdicts = |events: &[canton_participant::sequencing_wire::Delivered]| -> Vec<bool> {
            events
                .iter()
                .flat_map(|e| e.envelopes.iter())
                .filter_map(|c| decode_verdict(c))
                .filter(|(v, _)| v.request_id == request_id)
                .map(|(v, _)| v.approved)
                .collect()
        };
        assert!(
            verdicts(&m1.events(&physical, Some(0), 60)).is_empty(),
            "one confirmation of two decides nothing"
        );
        let (id1, id2) = (m1.identity.member(), m2.identity.member());
        drop((m1.client, m2.client));
        first.stop();

        // restarted: the mediator remembers the request and the confirmation it had
        let second = start(&dir, port);
        let (mut c1, mut c2) = (
            SequencerConnect::connect(&second.url).unwrap(),
            SequencerConnect::connect(&second.url).unwrap(),
        );
        let (t1, t2) = (
            authenticate(&mut c1, &m1.identity, &physical),
            authenticate(&mut c2, &m2.identity, &physical),
        );
        let outcome = if second_approves {
            cw::Outcome::Approve
        } else {
            cw::Outcome::Reject("ben says no".into())
        };
        respond(&mut c2, &m2.identity, &t2, &ben, outcome, "r-ben");
        let read = |c: &mut SequencerConnect, id: &ParticipantIdentity, t: &Token| {
            verdicts(
                &c.subscribe(
                    &id.member(),
                    &physical,
                    t,
                    Some(0),
                    80,
                    Duration::from_secs(3),
                )
                .unwrap_or_default()
                .iter()
                .map(|e| sw::decode_delivered(e).unwrap())
                .collect::<Vec<_>>(),
            )
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while read(&mut c1, &m1.identity, &t1).is_empty() && std::time::Instant::now() < deadline {}
        assert_eq!(
            read(&mut c1, &m1.identity, &t1),
            vec![second_approves],
            "one verdict, the one the two confirmations make ({id1})"
        );
        assert_eq!(
            read(&mut c2, &m2.identity, &t2),
            vec![second_approves],
            "and the same for the other participant ({id2})"
        );
        // a response that comes in after the verdict changes nothing
        respond(
            &mut c1,
            &m1.identity,
            &t1,
            &ann,
            cw::Outcome::Reject("too late".into()),
            "r-late",
        );
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(read(&mut c1, &m1.identity, &t1), vec![second_approves]);
        drop((c1, c2));
        second.stop();

        // restarted again after the verdict: replaying the journal makes no second verdict
        let third = start(&dir, port);
        let mut c1 = SequencerConnect::connect(&third.url).unwrap();
        let t1 = authenticate(&mut c1, &m1.identity, &physical);
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            read(&mut c1, &m1.identity, &t1),
            vec![second_approves],
            "still exactly one verdict"
        );
        drop(c1);
        third.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The running server shortens its own journal and forgets what was acknowledged, without a restart and without losing or reordering what
/// is still wanted.
#[test]
fn a_running_server_shortens_its_journal_and_forgets_what_was_acknowledged() {
    let dir = std::env::temp_dir().join(format!("canton-rs-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let server = start_with(&dir, port, Some(Duration::from_secs(1)));
    let physical = server.config.physical_synchronizer_id();
    let uid = format!(
        "{}::{}",
        server.config.name, server.config.namespace_fingerprint
    );
    let (a, b) = (
        ParticipantIdentity::generate("live-a"),
        ParticipantIdentity::generate("live-b"),
    );
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&server.url).unwrap(),
        SequencerConnect::connect(&server.url).unwrap(),
    );
    for (c, id) in [(&mut ca, &a), (&mut cb, &b)] {
        c.register_onboarding(&id.member(), &physical, id.onboarding_transactions(&uid))
            .unwrap();
    }
    let (ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    std::thread::sleep(Duration::from_millis(900));
    let send = |ca: &mut SequencerConnect, text: &str| {
        let request = sw::submission_request_to_groups(
            &a.member(),
            text,
            &[(vec![b.member()], text.as_bytes().to_vec())],
            far_future(),
        );
        ca.send_async(
            &a.member(),
            &physical,
            &ta,
            sw::signed_submission_request(request, &a.signing_key),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(150));
    };
    for text in ["one", "two", "three", "four", "five", "six"] {
        send(&mut ca, text);
    }
    let all_b = events(&mut cb, &b, &physical, &tb, 40);
    let all_a = events(&mut ca, &a, &physical, &ta, 40);
    let fourth = all_b
        .iter()
        .find(|e| e.2.is_none() && e.3.iter().any(|c| c.ends_with(b"four")))
        .expect("b was sent the fourth message")
        .0;
    let lines = || {
        std::fs::read_to_string(dir.join("journal"))
            .unwrap()
            .lines()
            .count()
    };
    let before = lines();
    cb.acknowledge_signed(
        &b.member(),
        &physical,
        &tb,
        sw::signed_acknowledge_request(&b.member(), fourth, &b.signing_key),
    )
    .unwrap();
    // the running server compacts about once a second
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while lines() >= before && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        lines() < before,
        "the journal shrank while the server ran: {before} -> {}",
        lines()
    );
    let now_b = events(&mut cb, &b, &physical, &tb, 40);
    assert!(
        now_b.iter().all(|e| e.0 > fourth),
        "b no longer reads what it acknowledged"
    );
    assert!(
        now_b
            .iter()
            .any(|e| e.3.iter().any(|c| c.ends_with(b"six"))),
        "what it did not acknowledge is there"
    );
    assert_eq!(
        events(&mut ca, &a, &physical, &ta, 40),
        all_a,
        "a acknowledged nothing: its events are all still there"
    );
    // the server goes on after compacting: a new message is sequenced after the old ones and continues the chain
    send(&mut ca, "seven");
    let later = events(&mut cb, &b, &physical, &tb, 40);
    assert_eq!(later.len(), now_b.len() + 1);
    assert_eq!(
        later.last().unwrap().1,
        Some(now_b.last().unwrap().0),
        "the chain continues across the compaction"
    );
    // and a restart sees the same state
    drop((ca, cb));
    server.stop();
    let second = start(&dir, port);
    let (mut ca, mut cb) = (
        SequencerConnect::connect(&second.url).unwrap(),
        SequencerConnect::connect(&second.url).unwrap(),
    );
    let (_ta, tb) = (
        authenticate(&mut ca, &a, &physical),
        authenticate(&mut cb, &b, &physical),
    );
    assert_eq!(
        events(&mut cb, &b, &physical, &tb, 40),
        later,
        "a restart after compacting replays the same events"
    );
    drop((ca, cb));
    second.stop();
    let _ = std::fs::remove_dir_all(&dir);
}
