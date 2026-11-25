//! The per-participant rate of confirmation requests (internal review S-6): `GrpcSequencerService.checkRate` refuses a participant's
//! confirmation request past the synchronizer's `participant_synchronizer_limits.confirmation_requests_max_rate` (1000000/s by default),
//! with bursts of `max-confirmation-requests-burst-factor` (0.5) times the rate, as `SEQUENCER_OVERLOADED`. Other requests are not limited.
mod common;
use canton_participant::sequencer_connect::ConnectError;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::ALL_MEMBERS;

#[test]
fn confirmation_requests_past_the_rate_are_refused_as_overloaded() {
    let (config, url) = common::start();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "rate-member");
    m.settle(&physical);
    let me = m.identity.member();
    let send = |m: &mut common::Member, id: &str, recipients: Vec<String>| {
        let request = sw::submission_request_to_groups(
            &me,
            id,
            &[(recipients, vec![1u8; 10])],
            common::far_future(),
        );
        match m.client.send_async(
            &m.identity.member(),
            &physical,
            &m.token,
            sw::signed_submission_request(request, &m.identity.signing_key),
        ) {
            Ok(()) => "ACCEPTED".to_string(),
            Err(ConnectError::Status(s)) => s,
            Err(other) => panic!("{other}"),
        }
    };
    let confirmation = || vec![me.clone(), "MGR::0".to_string()];
    assert_eq!(send(&mut m, "c-default-1", confirmation()), "ACCEPTED");
    assert_eq!(
        send(&mut m, "c-default-2", confirmation()),
        "ACCEPTED",
        "the default rate is far above two requests"
    );
    m.send(
        &physical,
        &[(
            vec![ALL_MEMBERS.to_string()],
            common::parameters_broadcast_with(&config, 2, |p| {
                p.participant_synchronizer_limits = Some(
                    canton_proto::com::digitalasset::canton::protocol::v30::ParticipantSynchronizerLimits {
                        confirmation_requests_max_rate: 1,
                    },
                )
            }),
        )],
        "lower-the-rate",
        common::far_future(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert_eq!(send(&mut m, "c-1", confirmation()), "ACCEPTED");
    let refused = send(&mut m, "c-2", confirmation());
    assert!(
        refused.contains("SEQUENCER_OVERLOADED")
            && refused.contains("Submission rate exceeds rate limit of 1/s."),
        "{refused}"
    );
    assert_eq!(
        send(&mut m, "to-self", vec![me.clone()]),
        "ACCEPTED",
        "a request that is not a confirmation request is not limited"
    );
}
