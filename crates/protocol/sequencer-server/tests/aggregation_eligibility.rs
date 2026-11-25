//! Who may contribute to an aggregation (`InFlightAggregationHandler.senderIsAuthorizedAndAggregationRuleIsWellFormed`): for a mediator
//! group rule, an active mediator of that group. A rule that lists members is not one 3.7.2 reads (`AggregationRule.fromProtoV30` takes a
//! mediator group, the sequencer group or none). Any other sender's request is refused and delivers nothing.
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;
use canton_participant::sequencer_connect::{AuthKey, SequencerConnect};
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{unversioned, versioned, Ed25519Key};
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use common::{far_future, join};
use prost::Message as _;

/// `sender`'s request (signed with `key`) of one envelope to `recipient`, carrying a rule that names `eligible`.
fn aggregated(
    sender: &str,
    key: &Ed25519Key,
    id: &str,
    recipient: &str,
    eligible: &[String],
) -> Vec<u8> {
    let plain = sw::submission_request_to_groups(
        sender,
        id,
        &[(vec![recipient.to_string()], b"verdict".to_vec())],
        far_future(),
    );
    let (data, version) = unversioned(&plain).unwrap();
    let mut request = SubmissionRequest::decode(data.as_slice()).unwrap();
    request.aggregation_rule = Some(AggregationRule {
        eligible_members: eligible.to_vec(),
        threshold: 0,
    });
    sw::signed_submission_request(versioned(request.encode_to_vec(), version), key)
}

#[test]
fn only_an_active_mediator_of_the_group_contributes_to_a_mediator_group_aggregation() {
    let state =
        std::env::temp_dir().join(format!("aggregation-eligibility-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).unwrap();
    let (config, url) = common::start_external_mediator(&state);
    let physical = config.physical_synchronizer_id();
    let (mut a, mut c) = (join(&url, &config, "elig-a"), join(&url, &config, "elig-c"));
    a.settle(&physical);
    c.settle(&physical);
    let to = c.identity.member();
    let group = vec!["MGR::0".to_string()];
    // a participant claims to be the mediator group: refused, nobody gets the envelope
    let forged = aggregated(
        &a.identity.member(),
        &a.identity.signing_key,
        "forged",
        &to,
        &group,
    );
    a.client
        .send_async(&a.identity.member(), &physical, &a.token, forged)
        .unwrap();
    let answer = a.events(&physical, None, 1);
    assert_eq!(answer[0].message_id.as_deref(), Some("forged"));
    let why = answer[0]
        .error
        .clone()
        .expect("the participant's request is refused");
    assert!(
        why.contains("is not part of the mediator group with index 0"),
        "{why}"
    );
    assert!(
        c.events(&physical, None, 1).is_empty(),
        "nothing delivered for a forged verdict"
    );
    // control: the group's active mediator sends the same request and it is delivered
    let mediator = canton_sequencer_server::mediator_member(&config, 0);
    let key = Ed25519Key::from_seed(config.keys.mediator_key(0).seed());
    let mut client = SequencerConnect::connect(&url).unwrap();
    let challenge = client.challenge(&mediator, &[37]).unwrap();
    let token = client
        .authenticate(
            &mediator,
            &challenge.nonce,
            key.sign_bytes(&AuthKey::challenge_hash(&challenge.nonce, &physical).unwrap()),
        )
        .unwrap();
    let genuine = aggregated(&mediator, &key, "genuine", &to, &group);
    client
        .send_async(&mediator, &physical, &token, genuine)
        .unwrap();
    let got = c.events(&physical, None, 1);
    assert_eq!(got.len(), 1, "the mediator's request is delivered");
    assert_eq!(got[0].envelopes, vec![b"verdict".to_vec()]);
    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn a_rule_that_lists_members_is_refused_even_from_a_member_it_names() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let (mut b, mut c) = (
        join(&url, &config, "elig2-b"),
        join(&url, &config, "elig2-c"),
    );
    for m in [&mut b, &mut c] {
        m.settle(&physical);
    }
    let to = c.identity.member();
    let listed = aggregated(
        &b.identity.member(),
        &b.identity.signing_key,
        "listed",
        &to,
        &[b.identity.member()],
    );
    b.client
        .send_async(&b.identity.member(), &physical, &b.token, listed)
        .unwrap();
    let answer = b.events(&physical, None, 1);
    let why = answer[0]
        .error
        .clone()
        .expect("a member-list rule is refused");
    assert!(
        why.contains("SEQUENCER_SUBMISSION_REQUEST_MALFORMED_REJECTED"),
        "{why}"
    );
    assert!(c.events(&physical, None, 1).is_empty(), "nothing delivered");
    // control: the empty rule from the same sender is delivered
    let dedup = aggregated(
        &b.identity.member(),
        &b.identity.signing_key,
        "dedup",
        &to,
        &[],
    );
    b.client
        .send_async(&b.identity.member(), &physical, &b.token, dedup)
        .unwrap();
    let got = c.events(&physical, None, 1);
    assert_eq!(got.len(), 1, "the sender's own request is delivered");
}
