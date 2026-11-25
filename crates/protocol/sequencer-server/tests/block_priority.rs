//! The priority `BlockReorderer` gives a submission in its block (`SubmissionRequestType`): what decides is the sender and the kinds of its recipients.
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::Ed25519Key;
use canton_sequencer_server::sequencing::submission_priority;

fn priority(sender: &str, recipients: &[&str]) -> Option<u8> {
    let plain = sw::submission_request_to_groups(
        sender,
        "m",
        &[(recipients.iter().map(|r| r.to_string()).collect(), b"x".to_vec())],
        i64::MAX,
    );
    let key = Ed25519Key::from_seed([7u8; 32]);
    submission_priority(&sw::signed_submission_request(plain, &key))
}

#[test]
fn the_priority_follows_the_kind_of_message() {
    // the mediator's verdict goes first, then the responses, then the requests of the participants, then commitments, then the broadcast of a topology transaction
    assert_eq!(priority("MED::m::12", &["PAR::p::12"]), Some(0), "a verdict");
    assert_eq!(priority("PAR::p::12", &["MGR::0"]), Some(1), "a confirmation response");
    assert_eq!(priority("PAR::p::12", &["MGR::0", "PAR::q::12"]), Some(2), "a confirmation request");
    assert_eq!(priority("PAR::p::12", &["PAR::q::12"]), Some(3), "a commitment");
    assert_eq!(priority("PAR::p::12", &["ALL::All"]), Some(4), "a topology transaction");
    assert_eq!(priority("PAR::p::12", &[]), Some(5), "a time proof");
    assert_eq!(priority("SEQ::s::12", &["SEQ::t::12"]), Some(6), "a top-up before onboarding");
    assert_eq!(priority("PAR::p::12", &["SEQ::t::12"]), Some(0), "a type the official nodes do not expect");
    assert_eq!(submission_priority(b"not a submission"), None);
}
