//! Aggregated submissions: a request with an aggregation rule is delivered once enough of the eligible senders have sent the same request
//! (`InFlightAggregationHandler`); the others only get a receipt, and a request that comes after the delivery is refused. This is how the mediators of a group
//! send one verdict: the participants get it from the first and the second mediator is told "already sent" (seen on the official nodes in the BFT oracle).
//! The rules of several senders (a mediator or the sequencer group) are in `aggregation_rules.rs`.
mod common;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{unversioned, versioned};
use canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use common::{far_future, join, Member};
use prost::Message as _;

/// The request of `sender` for `recipient` with the same envelope, carrying an aggregation rule.
fn aggregated_request(
    sender: &Member,
    id: &str,
    recipient: &str,
    eligible: &[&Member],
    threshold: i32,
    max: i64,
) -> Vec<u8> {
    let plain = sw::submission_request_to_groups(
        &sender.identity.member(),
        id,
        &[(vec![recipient.to_string()], b"verdict".to_vec())],
        max,
    );
    let (data, version) = unversioned(&plain).expect("a versioned request");
    let mut request = SubmissionRequest::decode(data.as_slice()).expect("a submission request");
    request.aggregation_rule = Some(AggregationRule {
        eligible_members: eligible.iter().map(|m| m.identity.member()).collect(),
        threshold,
    });
    sw::signed_submission_request(
        versioned(request.encode_to_vec(), version),
        &sender.identity.signing_key,
    )
}

fn send(member: &mut Member, physical: &str, signed: Vec<u8>) {
    member
        .client
        .send_async(&member.identity.member(), physical, &member.token, signed)
        .expect("the sequencer takes the request");
}

#[test]
fn a_request_sent_again_after_its_delivery_is_refused_and_the_recipient_gets_it_once() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let (mut a, mut c) = (join(&url, &config, "agg-a"), join(&url, &config, "agg-c"));
    for m in [&mut a, &mut c] {
        m.settle(&physical);
    }
    let to = c.identity.member();
    // the empty rule (`AggregationRuleInput.SenderDedup`): threshold one, the aggregation id names the sender; the same request again (the
    // maximum sequencing time included: it is part of the aggregation id) is the same aggregation
    let max = far_future();
    let first = aggregated_request(&a, "agg-1", &to, &[], 0, max);
    let second = aggregated_request(&a, "agg-2", &to, &[], 0, max);
    send(&mut a, &physical, first);
    send(&mut a, &physical, second);
    let got = c.events(&physical, None, 2);
    assert_eq!(got.len(), 1, "the recipient gets the verdict once: {got:?}");
    assert_eq!(got[0].envelopes, vec![b"verdict".to_vec()]);
    // the first request gets its receipt, the second the refusal (and nobody else)
    let answers = a.events(&physical, None, 2);
    assert_eq!(answers[0].message_id.as_deref(), Some("agg-1"));
    assert_eq!(answers[0].error, None);
    assert_eq!(answers[1].message_id.as_deref(), Some("agg-2"));
    let why = answers[1]
        .error
        .clone()
        .expect("the second request is answered with an error");
    assert!(
        why.contains("SEQUENCER_AGGREGATE_SUBMISSION_ALREADY_SENT"),
        "the refusal names the reason: {why}"
    );
}
