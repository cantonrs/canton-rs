//! The Rust sequencer orders submissions into events that this repository's client (decoding what the official sequencer sends) reads.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
mod common;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::ParticipantIdentity;
use canton_sequencer_server::SynchronizerConfig;
use common::{far_future, host, join, request_tree, Member};
use std::time::Duration;

#[test]
fn a_message_reaches_its_recipient_as_a_signed_event_and_the_sender_gets_a_receipt() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut a = join(&url, &config, "seq-a");
    let mut b = join(&url, &config, "seq-b");
    a.settle(&physical);
    b.settle(&physical);
    a.send(
        &physical,
        &[(vec![b.identity.member()], b"hello".to_vec())],
        "m-1",
        far_future(),
    )
    .unwrap();
    // the recipient: the envelope, no message id, the first event of its log
    let got = b.events(&physical, None, 1);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].envelopes, vec![b"hello".to_vec()]);
    assert_eq!(got[0].message_id, None);
    assert_eq!(
        got[0].previous_timestamp_micros,
        Some(b.cursor),
        "the chain continues from the member's setup events"
    );
    assert_eq!(got[0].physical_synchronizer_id, physical);
    // signed by the sequencer's signing key over the event
    let signature = &got[0].signatures[0];
    assert_eq!(
        signature.signed_by,
        config.keys.sequencer_signing.fingerprint
    );
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &config.keys.sequencer_signing.spki_der[12..]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(key
        .verify_strict(
            &sw::event_hash(&got[0].event_bytes),
            &ed25519_dalek::Signature::from_bytes(&signature.signature.clone().try_into().unwrap()),
        )
        .is_ok());
    // the sender: a receipt with its message id and no envelope (nothing was addressed to it)
    let receipt = a.events(&physical, None, 1);
    assert_eq!(receipt[0].message_id.as_deref(), Some("m-1"));
    assert!(receipt[0].envelopes.is_empty());
    assert_eq!(
        receipt[0].timestamp_micros, got[0].timestamp_micros,
        "one timestamp for the submission"
    );
    // a second message: the recipient's `previous_timestamp` is the first event's
    a.send(
        &physical,
        &[(vec![b.identity.member()], b"again".to_vec())],
        "m-2",
        far_future(),
    )
    .unwrap();
    let both = b.events(&physical, None, 2);
    assert_eq!(both.len(), 2);
    assert_eq!(
        both[1].previous_timestamp_micros,
        Some(both[0].timestamp_micros)
    );
    assert!(both[1].timestamp_micros > both[0].timestamp_micros);
    // a subscription from a time is inclusive of that time
    let from_second = b.events(&physical, Some(both[1].timestamp_micros), 2);
    assert_eq!(from_second.len(), 1);
    assert_eq!(from_second[0].envelopes, vec![b"again".to_vec()]);
    // an empty batch is a time proof: the sender gets its own receipt and nobody else an event
    a.send(&physical, &[], "tick-1", far_future()).unwrap();
    let a_events = a.events(&physical, None, 3);
    assert_eq!(
        a_events.last().unwrap().message_id.as_deref(),
        Some("tick-1")
    );
    assert_eq!(
        b.events(&physical, None, 3).len(),
        2,
        "b is not told about a's time proof"
    );
    // the group of all members reaches both, each with its own chain
    a.send(
        &physical,
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            b"all".to_vec(),
        )],
        "m-3",
        far_future(),
    )
    .unwrap();
    // ... and, as a submission to all members is how topology changes travel, a tick follows once such a change would have taken effect
    // (the topology change delay, 250 ms): the event after it for both members is an empty one at least that much later
    std::thread::sleep(Duration::from_millis(500));
    let b_all = b.events(&physical, None, 4);
    let at = b_all
        .iter()
        .position(|e| e.envelopes == vec![b"all".to_vec()])
        .expect("b received the message to all members");
    let tick = b_all
        .get(at + 1)
        .expect("a tick follows the message to all members");
    assert!(tick.envelopes.is_empty() && tick.message_id.is_none());
    assert!(tick.timestamp_micros >= b_all[at].timestamp_micros + 250_000);
    let a_all = a.events(&physical, None, 7);
    let mine = a_all
        .iter()
        .find(|e| e.message_id.as_deref() == Some("m-3"))
        .expect("the sender's receipt");
    assert_eq!(
        mine.envelopes,
        vec![b"all".to_vec()],
        "the sender is a member of the group too"
    );
}

#[test]
fn a_submission_that_is_not_the_senders_or_has_expired_is_refused_or_answered_with_an_error() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut a = join(&url, &config, "seq-bad-a");
    let b = join(&url, &config, "seq-bad-b");
    a.settle(&physical);
    // signed by a key the sender did not register
    let request = sw::submission_request_to_groups(&a.identity.member(), "m-x", &[], far_future());
    let stranger = ParticipantIdentity::generate("stranger");
    let why = match a
        .client
        .send_async(
            &a.identity.member(),
            &physical,
            &a.token,
            sw::signed_submission_request(request, &stranger.signing_key),
        )
        .unwrap_err()
    {
        canton_participant::sequencer_connect::ConnectError::Status(s) => s,
        other => panic!("{other}"),
    };
    assert!(
        why.contains("SEQUENCER_SUBMISSION_REQUEST_REFUSED")
            && why.contains("SignatureWithWrongKey"),
        "{why}"
    );
    // a request that names another member as the sender
    let request = sw::submission_request_to_groups(&b.identity.member(), "m-y", &[], far_future());
    let why = match a
        .client
        .send_async(
            &a.identity.member(),
            &physical,
            &a.token,
            sw::signed_submission_request(request, &a.identity.signing_key),
        )
        .unwrap_err()
    {
        canton_participant::sequencer_connect::ConnectError::Status(s) => s,
        other => panic!("{other}"),
    };
    assert!(why.contains("without permission"), "{why}");
    // a maximum sequencing time in the past: the answer of SendAsync, as the official sequencer's (ABORTED)
    let why = match a
        .send(
            &physical,
            &[(vec![b.identity.member()], b"late".to_vec())],
            "m-late",
            1,
        )
        .unwrap_err()
    {
        canton_participant::sequencer_connect::ConnectError::Status(s) => s,
        other => panic!("{other}"),
    };
    assert!(
        why.contains("operation was aborted") && why.contains("MAX_SEQUENCING_TIME_EXCEEDED(2,0)"),
        "{why}"
    );
    // a recipient nobody registered: refused by SendAsync, nothing is delivered
    let before_b = b_cursor_events(&mut a, &physical);
    let why = match a
        .send(
            &physical,
            &[(
                vec![b.identity.member(), "PAR::nobody::1220aa".to_string()],
                b"to a stranger".to_vec(),
            )],
            "m-unknown",
            far_future(),
        )
        .unwrap_err()
    {
        canton_participant::sequencer_connect::ConnectError::Status(s) => s,
        other => panic!("{other}"),
    };
    assert!(
        why.contains("not in a state required")
            && why.contains(
                "SEQUENCER_UNKNOWN_RECIPIENTS(9,0): Unknown recipients: PAR::nobody::1220aa"
            ),
        "{why}"
    );
    // a mediator group that does not exist
    a.send(
        &physical,
        &[(vec!["MGR::7".to_string()], b"to no mediator".to_vec())],
        "m-group",
        far_future(),
    )
    .unwrap();
    let events = a.events(&physical, Some(before_b + 1), 8);
    let told = events
        .iter()
        .find(|e| e.message_id.as_deref() == Some("m-group"))
        .expect("the sender gets an event for its message id");
    assert!(
        told.error
            .as_deref()
            .unwrap_or("")
            .contains("The following mediator groups do not exist List(7)"),
        "{:?}",
        told.error
    );
}

/// The time of the last event `m` has been sent so far.
fn b_cursor_events(m: &mut Member, physical: &str) -> i64 {
    m.events(physical, Some(0), 60)
        .last()
        .map_or(0, |e| e.timestamp_micros)
}

// ---------------------------------------------------------------------------------------------------------------------
// The mediator, with a Rust participant as the only participant of the request (the same requests the G5 tests send the official mediator,
// answered here by the Rust mediator; the verdict is read as the official one is).
// ---------------------------------------------------------------------------------------------------------------------

use canton_participant::confirmation_wire as cw;
use canton_participant::view_acs::{decode_verdict, mediator_signed, VerdictKind};

/// A verdict as a participant is told it: the decoded verdict, the hash the mediator's signature covers, the envelope's signatures.
type Told = (
    canton_participant::view_acs::Verdict,
    Vec<u8>,
    Vec<canton_proto::com::digitalasset::canton::crypto::v30::Signature>,
);

/// What the Rust participant sends as a request and as its answer.
enum Answer {
    Approve,
    Reject,
    Malformed,
    /// An approval for a view position the tree does not have.
    UnknownPosition,
    /// No answer at all.
    None,
}

/// How a request departs from the plain one (one view, informee erin, threshold 1, one root hash message to the submitter).
#[derive(Default)]
struct Shape {
    /// What the informee message is signed over instead of the root hash.
    signed_instead: Option<Vec<u8>>,
    /// More informees of the view (each a confirmer with weight 1).
    more_informees: Vec<String>,
    /// The quorum's threshold (1 when not given).
    threshold: Option<i32>,
    /// More members a root hash message is addressed to (each in its own tree with the mediator group).
    more_root_hash_recipients: Vec<String>,
    /// A topology transaction travels in the same batch as the request.
    with_topology: bool,
    /// The mediator group the request is addressed to (0 when not given).
    group: Option<u32>,
    /// The synchronizer's confirmation response timeout is set to this many seconds before the request.
    timeout_seconds: Option<i64>,
}

/// A Rust participant hosts `erin`, sends a confirmation request for it (shaped as `shape` says), answers it as `answer` says and
/// returns the verdict it is told (if any within `wait`) with the request's sequencing time.
fn rust_participant_runs_a_request(
    url: &str,
    config: &SynchronizerConfig,
    shape: Shape,
    answer: Answer,
    wait: Duration,
) -> (Option<Told>, i64) {
    let physical = config.physical_synchronizer_id();
    let mut m = join(url, config, "mediated");
    m.settle(&physical);
    let party = host(&mut m, &physical, "erin");
    if let Some(seconds) = shape.timeout_seconds {
        m.send(
            &physical,
            &[(
                vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
                common::parameters_broadcast(config, 2, seconds),
            )],
            "parameters",
            far_future(),
        )
        .unwrap();
        // the change takes effect after the topology change delay
        std::thread::sleep(Duration::from_millis(600));
    }
    let signed_instead = shape.signed_instead.clone();
    let now = m
        .client
        .sequencer_time(&m.identity.member(), &physical, Some(&m.token))
        .unwrap()
        .unwrap();
    let mut informees: Vec<&str> = vec![&party];
    informees.extend(shape.more_informees.iter().map(String::as_str));
    let tree = request_tree(
        &m.identity,
        &informees,
        shape.threshold.unwrap_or(1),
        shape.group.unwrap_or(0),
        now,
        &physical,
    );
    let mediator = cw::mediator_group(shape.group.unwrap_or(0));
    let mut envelopes = vec![
        (
            vec![mediator.clone()],
            cw::informee_message_signed_over(
                &tree,
                &m.identity.signing_key,
                signed_instead.as_deref().unwrap_or(&tree.root_hash),
            ),
        ),
        (
            vec![mediator.clone(), m.identity.member()],
            cw::root_hash_message(&tree.root_hash, &physical, now),
        ),
    ];
    for other in &shape.more_root_hash_recipients {
        envelopes.push((
            vec![mediator.clone(), other.clone()],
            cw::root_hash_message(&tree.root_hash, &physical, now),
        ));
    }
    if shape.with_topology {
        envelopes.push((
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            canton_participant::topology_wire::topology_broadcast(
                &physical,
                &[m.identity.party_hosting_transaction("gina")],
            ),
        ));
    }
    let request = sw::submission_request_to_groups(
        &m.identity.member(),
        "confirmation-request",
        &envelopes,
        now + 60_000_000,
    );
    m.client
        .send_async(
            &m.identity.member(),
            &physical,
            &m.token,
            sw::signed_submission_request(request, &m.identity.signing_key),
        )
        .unwrap();
    // the request id is the sequencing time of our own submission
    let events = m.events(&physical, Some(0), 40);
    let request_id = events
        .iter()
        .rev()
        .find(|e| e.message_id.as_deref() == Some("confirmation-request"))
        .expect("our request comes back")
        .timestamp_micros;
    let outcome = match answer {
        Answer::None => None,
        a => Some((
            match a {
                Answer::Reject => cw::Outcome::Reject("rejected by the test".into()),
                Answer::Malformed => cw::Outcome::Malformed("cannot read".into()),
                _ => cw::Outcome::Approve,
            },
            if a_position(&a) {
                vec![vec![true, true]]
            } else {
                vec![vec![]]
            },
        )),
    };
    fn a_position(a: &Answer) -> bool {
        matches!(a, Answer::UnknownPosition)
    }
    if let Some((outcome, position)) = outcome {
        let (content, signatures) = cw::confirmation_responses(
            request_id,
            &tree.root_hash,
            &physical,
            &m.identity.member(),
            &[cw::ViewResponse {
                view_position: &position,
                outcome,
                confirming_parties: &[party],
            }],
            &m.identity.signing_key,
        );
        m.client
            .send_async(
                &m.identity.member(),
                &physical,
                &m.token,
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
    }
    // the verdict: an event after the request whose envelope is a signed confirmation result for the request id
    let deadline = std::time::Instant::now() + wait;
    while std::time::Instant::now() < deadline {
        for e in m.events(&physical, Some(request_id + 1), 20) {
            for (content, signatures) in e.envelopes.iter().zip(&e.envelope_signatures) {
                if let Some((verdict, hash)) = decode_verdict(content) {
                    if verdict.request_id == request_id {
                        return (Some((verdict, hash, signatures.clone())), request_id);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    (None, request_id)
}

fn mediator_key(config: &SynchronizerConfig) -> canton_algo::signing::PublicKey {
    mediator_key_of(config, 0)
}

fn mediator_key_of(config: &SynchronizerConfig, group: usize) -> canton_algo::signing::PublicKey {
    canton_algo::member_signature::own_ed25519_key(&config.keys.mediator_key(group).spki_der)
        .unwrap()
}

#[test]
fn the_rust_mediator_approves_a_request_the_rust_participant_confirms_for_its_own_party() {
    let (config, url) = common::start();
    let (verdict, request_id) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape::default(),
        Answer::Approve,
        Duration::from_secs(6),
    );
    let (verdict, hash, signatures) = verdict.expect("a verdict");
    assert_eq!(verdict.request_id, request_id);
    assert!(verdict.approved, "{verdict:?}");
    assert!(mediator_signed(
        &signatures,
        &hash,
        &[mediator_key(&config)]
    ));
    assert!(
        !mediator_signed(
            &signatures,
            &hash,
            &[canton_algo::member_signature::own_ed25519_key(
                &canton_participant::topology_wire::Ed25519Key::from_seed([7; 32]).spki_der
            )
            .unwrap()]
        ),
        "another key's signature is not the mediator's"
    );
}

#[test]
fn the_rust_mediator_rejects_a_request_the_participant_rejects_and_one_it_cannot_read() {
    let (config, url) = common::start();
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape::default(),
        Answer::Reject,
        Duration::from_secs(6),
    );
    let (verdict, hash, signatures) = verdict.expect("a verdict");
    assert!(
        matches!(verdict.kind, VerdictKind::ParticipantReject),
        "{:?}",
        verdict.kind
    );
    assert!(mediator_signed(
        &signatures,
        &hash,
        &[mediator_key(&config)]
    ));
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape::default(),
        Answer::Malformed,
        Duration::from_secs(6),
    );
    // [CANTON-NOTE: SEMANTICS] erin's only confirming participant answers malformed: a rejection on her behalf that leaves her quorum
    // unreachable, so a `ParticipantReject` (`ResponseAggregator.validateResponse`, Canton 3.7.2)
    assert!(
        matches!(
            verdict.expect("a verdict").0.kind,
            VerdictKind::ParticipantReject
        ),
        "an answer that says the request cannot be read rejects for the confirming party its sender hosts"
    );
}

#[test]
fn the_rust_mediator_does_not_decide_on_what_does_not_count() {
    let (config, url) = common::start();
    // an informee message signed over something else than the root hash: malformed
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape {
            signed_instead: Some(b"not the root hash".to_vec()),
            ..Default::default()
        },
        Answer::Approve,
        Duration::from_secs(6),
    );
    assert!(
        matches!(
            verdict.expect("a verdict").0.kind,
            VerdictKind::MediatorReject { malformed: true }
        ),
        "a signature over another hash than the root hash"
    );
    // an answer for a view position the tree does not have, and no answer at all: no verdict inside the response time
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape::default(),
        Answer::UnknownPosition,
        Duration::from_secs(3),
    );
    assert!(
        verdict.is_none(),
        "an unknown view position confirms nothing"
    );
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape::default(),
        Answer::None,
        Duration::from_secs(3),
    );
    assert!(
        verdict.is_none(),
        "nobody answered: the verdict comes at the time-out, not before"
    );
}

/// The request checks of the official mediator (`validateRequest`): each broken rule is answered at once with a rejection, before any
/// participant answers.
#[test]
fn the_rust_mediator_rejects_a_request_that_breaks_a_rule_of_the_official_mediator() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let kind = |shape: Shape| {
        rust_participant_runs_a_request(&url, &config, shape, Answer::None, Duration::from_secs(6))
            .0
            .expect("a verdict without any answer")
            .0
            .kind
    };
    // an informee nobody hosts: invalid, which is not the same as malformed
    let ghost = format!("ghost::{}", "12".repeat(34));
    assert!(
        matches!(
            kind(Shape {
                more_informees: vec![ghost],
                threshold: Some(1),
                ..Default::default()
            }),
            VerdictKind::MediatorReject { malformed: false }
        ),
        "an informee without an active participant"
    );
    // another participant hosts frank
    let mut b = join(&url, &config, "other");
    b.settle(&physical);
    let frank = host(&mut b, &physical, "frank");
    // frank is an informee, but his participant gets no root hash message
    assert!(
        matches!(
            kind(Shape {
                more_informees: vec![frank.clone()],
                ..Default::default()
            }),
            VerdictKind::MediatorReject { malformed: true }
        ),
        "a root hash message is missing for an informee participant"
    );
    // a root hash message for a participant that hosts no informee
    assert!(
        matches!(
            kind(Shape {
                more_root_hash_recipients: vec![b.identity.member()],
                ..Default::default()
            }),
            VerdictKind::MediatorReject { malformed: true }
        ),
        "a superfluous root hash message"
    );
    // a threshold the confirmers cannot reach
    assert!(
        matches!(
            kind(Shape {
                threshold: Some(2),
                ..Default::default()
            }),
            VerdictKind::MediatorReject { malformed: true }
        ),
        "one confirmer of weight 1 cannot reach a threshold of 2"
    );
    // a topology transaction in the same batch
    assert!(
        matches!(
            kind(Shape {
                with_topology: true,
                ..Default::default()
            }),
            VerdictKind::MediatorReject { malformed: true }
        ),
        "a request that travels with a topology transaction"
    );
    // and with frank's participant addressed too, the same request is registered (no verdict before an answer)
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape {
            more_informees: vec![frank],
            more_root_hash_recipients: vec![b.identity.member()],
            ..Default::default()
        },
        Answer::None,
        Duration::from_secs(3),
    );
    assert!(
        verdict.is_none(),
        "a request that keeps every rule waits for its answers"
    );
}

/// The timeout a request is given is the one in force when it is sequenced: after the owner changed the parameters, a request nobody
/// answers is timed out after the new timeout and not the default 30 s.
#[test]
fn the_rust_mediator_times_a_request_out_after_the_timeout_the_parameters_set() {
    let (config, url) = common::start();
    let started = std::time::Instant::now();
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape {
            timeout_seconds: Some(3),
            ..Default::default()
        },
        Answer::None,
        Duration::from_secs(15),
    );
    let (verdict, hash, signatures) = verdict.expect("a time-out verdict well before 30 seconds");
    assert!(
        matches!(
            verdict.kind,
            VerdictKind::MediatorReject { malformed: false }
        ),
        "{:?}",
        verdict.kind
    );
    assert!(mediator_signed(
        &signatures,
        &hash,
        &[mediator_key(&config)]
    ));
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "timed out by the 3 s timeout, not the default 30 s: {:?}",
        started.elapsed()
    );
}

/// The mediator of its own process times a request out by the synchronizer's time: nothing is sequenced after the request, so it asks the
/// sequencer for a time proof and decides at the time the proof is sequenced.
#[test]
fn a_mediator_of_its_own_times_a_request_out_on_a_quiet_synchronizer() {
    let dir = std::env::temp_dir().join(format!("quiet-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (config, url) = common::start_external_mediator(&dir);
    let _mediator =
        canton_sequencer_server::mediator_node::start(&url, &dir, 0).expect("the mediator joins");
    let (verdict, _) = rust_participant_runs_a_request(
        &url,
        &config,
        Shape {
            timeout_seconds: Some(3),
            ..Default::default()
        },
        Answer::None,
        Duration::from_secs(15),
    );
    let (verdict, hash, signatures) = verdict.expect("a time-out verdict");
    assert!(
        verdict.reason.contains("MEDIATOR_SAYS_TX_TIMED_OUT"),
        "{:?} {}",
        verdict.kind,
        verdict.reason
    );
    assert!(mediator_signed(
        &signatures,
        &hash,
        &[mediator_key(&config)]
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two mediator groups, each served by its own mediator with its own key: a request addressed to a group is decided by that group's
/// mediator, and its verdict verifies against that group's key and no other.
#[test]
fn each_mediator_group_decides_its_own_requests_with_its_own_key() {
    let (config, url) = common::start_with_groups(2);
    assert_ne!(
        mediator_key_of(&config, 0),
        mediator_key_of(&config, 1),
        "one key for each mediator"
    );
    for group in [0usize, 1] {
        let (verdict, request_id) = rust_participant_runs_a_request(
            &url,
            &config,
            Shape {
                group: Some(group as u32),
                ..Default::default()
            },
            Answer::Approve,
            Duration::from_secs(6),
        );
        let (verdict, hash, signatures) = verdict.expect("a verdict");
        assert_eq!(verdict.request_id, request_id);
        assert!(verdict.approved, "{verdict:?}");
        assert!(
            mediator_signed(&signatures, &hash, &[mediator_key_of(&config, group)]),
            "signed by the mediator of group {group}"
        );
        assert!(
            !mediator_signed(&signatures, &hash, &[mediator_key_of(&config, 1 - group)]),
            "not by the mediator of the other group"
        );
    }
    // a group the synchronizer does not have: the submission is refused, nobody decides
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = join(&url, &config, "no-group");
    m.settle(&physical);
    m.send(
        &physical,
        &[(vec![cw::mediator_group(1)], b"to group 1".to_vec())],
        "group-1",
        far_future(),
    )
    .unwrap();
    let told = m
        .events(&physical, Some(0), 20)
        .into_iter()
        .find(|e| e.message_id.as_deref() == Some("group-1"))
        .expect("the sender is told");
    assert!(told
        .error
        .unwrap_or_default()
        .contains("mediator groups do not exist"));
}
