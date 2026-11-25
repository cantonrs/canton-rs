//! AT-P08: the Rust sequencer answers a submission that breaks one of its limits or shapes as the official 3.7.2 sequencer does. The
//! expected answers are the ones measured on the official sequencer by `the_official_sequencer_refuses_submissions_that_break_its_limits_and_says_how`
//! (canton-participant's `tests/sequencer_connect.rs`, `ORACLE_LIMIT` lines): the gRPC status, the error code and the text that names the rule.
mod common;
use canton_participant::sequencer_connect::ConnectError;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::Ed25519Key;

/// Which of the member's keys signs the request.
#[derive(Clone, Copy)]
enum Key {
    Signing,
    Authentication,
}

fn answer(m: &mut common::Member, physical: &str, request: Vec<u8>, which: Key) -> String {
    let key: &Ed25519Key = match which {
        Key::Signing => &m.identity.signing_key,
        Key::Authentication => &m.identity.sequencer_auth_key,
    };
    let signed = sw::signed_submission_request(request, key);
    send_raw(m, physical, signed)
}

fn send_raw(m: &mut common::Member, physical: &str, signed: Vec<u8>) -> String {
    match m
        .client
        .send_async(&m.identity.member(), physical, &m.token, signed)
    {
        Ok(()) => "ACCEPTED".to_string(),
        Err(ConnectError::Status(s)) => s,
        Err(other) => panic!("{other}"),
    }
}

fn expect(what: &str, got: &str, parts: &[&str]) {
    for p in parts {
        assert!(got.contains(p), "{what}: expected `{p}` in `{got}`");
    }
}

#[test]
fn submissions_that_break_a_limit_or_a_shape_are_refused_as_the_official_sequencer_refuses_them() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "limits");
    m.settle(&physical);
    let me = m.identity.member();
    let ok_time = common::far_future();
    let one = |recipients: Vec<String>, content: Vec<u8>| vec![(recipients, content)];

    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(
            &me,
            "no-recipients",
            &one(vec![], b"x".to_vec()),
            ok_time,
        ),
        Key::Signing,
    );
    expect(
        "an envelope without recipients",
        &a,
        &[
            "Client specified an invalid argument",
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [] from sender [] is malformed. Discarding request.",
            "ValueConversionError(RecipientsTree.recipients,RecipientsTree.recipients must be non-empty)",
        ],
    );
    // the official sequencer accepts an envelope without content
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(
            &me,
            "no-content",
            &one(vec![me.clone()], vec![]),
            ok_time,
        ),
        Key::Signing,
    );
    assert_eq!(a, "ACCEPTED");
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(
            &me,
            "two-groups",
            &one(vec!["MGR::0".into(), "MGR::1".into()], b"x".to_vec()),
            ok_time,
        ),
        Key::Signing,
    );
    expect(
        "two mediator groups",
        &a,
        &[
            "not in a state required for the operation's execution",
            "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Request 'two-groups' from '",
            "refused: Batch contains multiple mediators as recipients.",
        ],
    );
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(
            &me,
            "too-big",
            &one(vec![me.clone()], vec![0u8; 11 * 1024 * 1024]),
            ok_time,
        ),
        Key::Signing,
    );
    expect(
        "an envelope over max_request_size",
        &a,
        &[
            "Client specified an invalid argument",
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [too-big] from sender [",
            "Batch contains envelope with max bytes exceeded. The limit is 10485760 bytes.",
        ],
    );
    let many: Vec<String> = (0..10_001)
        .map(|i| format!("PAR::p{i}::1220{}", "a".repeat(64)))
        .collect();
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(&me, "many", &one(many, b"x".to_vec()), ok_time),
        Key::Signing,
    );
    expect(
        "too many recipients",
        &a,
        &[
            "Client specified an invalid argument",
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [] from sender [] is malformed. Discarding request.",
            "InvariantViolation(Some(RecipientsTreeProto.recipients),repeated field has 10001 elements, exceeding the maximum of 10000)",
        ],
    );
    let a = send_raw(&mut m, &physical, vec![1, 2, 3, 4, 5]);
    expect(
        "bytes that are no signed content",
        &a,
        &[
            "Client specified an invalid argument",
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [] from sender [] is malformed. Discarding request.",
        ],
    );
    let a = send_raw(
        &mut m,
        &physical,
        canton_participant::topology_wire::versioned(Vec::new(), 99),
    );
    expect(
        "a signed content of another version",
        &a,
        &[
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0)",
            "Unable to find deserializer for version ProtoVersion(99) and message SignedContent.",
        ],
    );
    // the refusals of the request itself
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request(
            &me,
            "unknown",
            &[(
                format!("PAR::nobody::1220{}", "a".repeat(64)),
                b"x".to_vec(),
            )],
            ok_time,
        ),
        Key::Signing,
    );
    expect(
        "an unknown recipient",
        &a,
        &[
            "not in a state required for the operation's execution",
            "SEQUENCER_UNKNOWN_RECIPIENTS(9,0): Unknown recipients: PAR::nobody::1220",
        ],
    );
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request(&me, "past", &[(me.clone(), b"x".to_vec())], 1),
        Key::Signing,
    );
    expect(
        "a max sequencing time that has passed",
        &a,
        &[
            "The operation was aborted",
            "MAX_SEQUENCING_TIME_EXCEEDED(2,0): The sequencer time [",
            "has exceeded the max-sequencing-time of the send request [",
            "Estimation for message id past",
        ],
    );
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request(&me, "wrong-key", &[(me.clone(), b"x".to_vec())], ok_time),
        Key::Authentication,
    );
    expect(
        "a signature by a key that may not sign protocol messages",
        &a,
        &[
            "not in a state required for the operation's execution",
            "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Sequencer could not verify client's signature on [SubmissionRequest]",
            "SignatureWithWrongKey(",
        ],
    );
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request(
            "PAR::other::1220bbbb",
            "not-me",
            &[(me, b"x".to_vec())],
            ok_time,
        ),
        Key::Signing,
    );
    expect(
        "a sender that is not the authenticated member",
        &a,
        &[
            "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Request 'not-me' from 'PAR::other::1220bbbb' refused: PAR::other::1220bbbb is not authorized to send:",
            "just tried to use sequencer on behalf of PAR::other::1220bbbb without permission",
        ],
    );
}

/// AT-O08: after the announced upgrade time the old synchronizer takes no more submissions and sends one last event at the end of the
/// upgrade's time offset, as the official sequencer does (`ORACLE_LSU_AFTER` of `the_official_sequencer_after_the_upgrade_time`).
#[test]
fn after_the_upgrade_time_submissions_are_refused_and_a_last_event_closes_the_synchronizer() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "lsu-member");
    m.settle(&physical);
    let me = m.identity.member();
    let now = m
        .client
        .sequencer_time(&me, &physical, Some(&m.token))
        .unwrap()
        .unwrap();
    let upgrade = now + 3_000_000;
    m.send(
        &physical,
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            common::announcement_broadcast(&config, 1, upgrade),
        )],
        "announce",
        common::far_future(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let before = answer(
        &mut m,
        &physical,
        sw::submission_request(
            &me,
            "before",
            &[(me.clone(), b"x".to_vec())],
            common::far_future(),
        ),
        Key::Signing,
    );
    assert_eq!(before, "ACCEPTED", "before the upgrade time");
    std::thread::sleep(std::time::Duration::from_secs(4));
    let after = answer(
        &mut m,
        &physical,
        sw::submission_request(
            &me,
            "after",
            &[(me.clone(), b"x".to_vec())],
            common::far_future(),
        ),
        Key::Signing,
    );
    expect(
        "a submission after the upgrade time",
        &after,
        &[
            "not in a state required for the operation's execution",
            "SEQUENCER_SUBMISSION_AFTER_UPGRADE_TIME(9,0): Submission request was refused because the sequencer can no longer accept transactions on",
            "exceeds the upgrade time of",
        ],
    );
    // the last event: at exactly the upgrade time + the decision timeout (30 s + 30 s with the default parameters)
    std::thread::sleep(std::time::Duration::from_secs(2));
    let last = m
        .events(&physical, Some(0), 60)
        .last()
        .map(|e| e.timestamp_micros)
        .unwrap();
    assert_eq!(
        last,
        upgrade + 60_000_000,
        "the last event closes the synchronizer at the end of the offset"
    );
}

/// The size limit of an envelope is the synchronizer's `max_request_size` in force, not a constant: lowered by the owners, a bigger envelope is
/// refused with the new limit in the text.
#[test]
fn the_size_limit_follows_the_parameters_in_force() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "size-member");
    m.settle(&physical);
    let me = m.identity.member();
    let send = |m: &mut common::Member, id: &str, size: usize| {
        let request = sw::submission_request_to_groups(
            &me,
            id,
            &[(vec![me.clone()], vec![1u8; size])],
            common::far_future(),
        );
        answer(m, &physical, request, Key::Signing)
    };
    assert_eq!(
        send(&mut m, "big-before", 2000),
        "ACCEPTED",
        "2000 bytes are far below the default 10 MiB"
    );
    m.send(
        &physical,
        &[(
            vec![canton_participant::topology_wire::ALL_MEMBERS.to_string()],
            common::parameters_broadcast_with(&config, 2, |p| p.max_request_size = 1000),
        )],
        "lower-the-limit",
        common::far_future(),
    )
    .unwrap();
    // the change takes effect after the topology change delay
    std::thread::sleep(std::time::Duration::from_millis(600));
    expect(
        "an envelope over the lowered limit",
        &send(&mut m, "big-after", 2000),
        &[
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0)",
            "Batch contains envelope with max bytes exceeded. The limit is 1000 bytes.",
        ],
    );
    assert_eq!(send(&mut m, "small-after", 500), "ACCEPTED");
    // [CANTON-NOTE: SEMANTICS] From protocol version 36 the limit bounds the batch's envelopes together (`DecompressionPolicy.Cumulative`):
    // two envelopes of 600 bytes are over 1000 although each is under it
    let two = sw::submission_request_to_groups(
        &me,
        "two-halves",
        &[
            (vec![me.clone()], vec![1u8; 600]),
            (vec![me.clone()], vec![2u8; 600]),
        ],
        common::far_future(),
    );
    expect(
        "two envelopes together over the lowered limit",
        &answer(&mut m, &physical, two, Key::Signing),
        &["Batch contains envelope with max bytes exceeded. The limit is 1000 bytes."],
    );
}

/// A message id is at most 73 characters (`MessageId`, a `String73`). The longer one is refused before anything else is read, with the text
/// the official sequencer gave a Rust mediator whose verdict id was 102 characters long (S-LOCAL-011, `verify-mediator-onboarding.sh`).
#[test]
fn a_message_id_longer_than_73_characters_is_refused_as_the_official_sequencer_refuses_it() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "longid");
    m.settle(&physical);
    let me = m.identity.member();
    let to_me = vec![(vec![me.clone()], b"x".to_vec())];
    let longest = "i".repeat(73);
    let a = answer(
        &mut m,
        &physical,
        sw::submission_request_to_groups(&me, &longest, &to_me, common::far_future()),
        Key::Signing,
    );
    assert_eq!(a, "ACCEPTED", "73 characters are allowed");
    let too_long = "i".repeat(74);
    let a = answer(
        &mut m,
        &physical,
        // no recipients either: the id is read first, so its refusal is the one given
        sw::submission_request_to_groups(
            &me,
            &too_long,
            &[(vec![], b"x".to_vec())],
            common::far_future(),
        ),
        Key::Signing,
    );
    expect(
        "a message id of 74 characters",
        &a,
        &[
            "Client specified an invalid argument",
            "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [] from sender [] is malformed. Discarding request.",
            &format!("InvariantViolation(Some(message_id),The given message_id has a maximum length of 73 but a message_id of length 74 ('{too_long}') was given)"),
        ],
    );
}
