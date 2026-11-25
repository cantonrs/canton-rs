//! AT-O07: traffic purchases, duplicated and for a member that is not registered. The expected answers are the ones measured on the official
//! 3.7.2 sequencer (`ORACLE_TRAFFIC` lines of `the_official_sequencer_answers_traffic_purchases_for_registered_and_unregistered_members`,
//! canton-participant's `tests/sequencer_connect.rs`): with traffic control off, **every** purchase is refused `NOT_FOUND`
//! `TRAFFIC_CONTROL_DISABLED`, so nothing is ever credited and no balance can be credited twice.
mod common;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    sequencer_administration_service_client::SequencerAdministrationServiceClient,
    SetTrafficPurchasedRequest, TrafficControlStateRequest,
};

#[test]
fn every_traffic_purchase_is_refused_while_traffic_control_is_off_and_no_balance_appears() {
    let (config, url, admin_url) = common::start_with_admin();
    let physical = config.physical_synchronizer_id();
    let m = common::join(&url, &config, "traffic-buyer");
    let registered = m.identity.member();
    let ghost = format!("PAR::ghost::1220{}", "ab".repeat(32));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = physical;
    runtime.block_on(async {
        let channel = tonic::transport::Channel::from_shared(admin_url.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut admin = SequencerAdministrationServiceClient::new(channel);
        let buy = |member: &str, serial: u32, total: i64| {
            let request = SetTrafficPurchasedRequest {
                member: member.to_string(),
                serial,
                total_traffic_purchased: total,
            };
            let mut admin = admin.clone();
            async move { admin.set_traffic_purchased(request).await.unwrap_err() }
        };
        // a registered member: a first purchase, the same one again, another one, and one with a lower serial
        for (serial, total) in [(1, 1000), (1, 1000), (2, 2500), (1, 9)] {
            let e = buy(&registered, serial, total).await;
            assert_eq!(e.code(), tonic::Code::NotFound, "serial {serial}");
            assert!(
                e.message().contains("TRAFFIC_CONTROL_DISABLED(11,")
                    && e.message().contains("TrafficControlDisabled"),
                "{}",
                e.message()
            );
        }
        // a member that is not registered, twice
        for _ in 0..2 {
            let e = buy(&ghost, 1, 700).await;
            assert_eq!(e.code(), tonic::Code::NotFound);
            assert!(
                e.message().contains("TRAFFIC_CONTROL_DISABLED(11,"),
                "{}",
                e.message()
            );
        }
        // nothing was credited: the registered member's state is all zeros, the unregistered one is not in the answer
        let state = admin
            .traffic_control_state(TrafficControlStateRequest {
                members: vec![registered.clone()],
                timestamp_selector: None,
            })
            .await
            .unwrap()
            .into_inner();
        let own = state
            .traffic_states
            .get(&registered)
            .expect("a registered member has a state");
        assert_eq!(
            (
                own.extra_traffic_purchased,
                own.extra_traffic_consumed,
                own.base_traffic_remainder,
                own.last_consumed_cost
            ),
            (0, 0, 0, 0)
        );
        let none = admin
            .traffic_control_state(TrafficControlStateRequest {
                members: vec![ghost.clone()],
                timestamp_selector: None,
            })
            .await
            .unwrap()
            .into_inner();
        assert!(
            none.traffic_states.is_empty(),
            "a member that is not registered is not in the answer"
        );
    });
}

/// AT-O07 with traffic control on, against what the official sequencer did in the same steps (`ORACLE_TRAFFIC_ON`, S-NET-038 part 11):
/// 1000 bytes of base traffic over 10 minutes, factor 200, base event cost 7; a 100-byte envelope to one recipient costs 109.
#[test]
fn with_traffic_control_on_a_submission_pays_its_cost_and_one_that_cannot_is_refused() {
    use canton_participant::sequencing_wire as sw;
    use canton_participant::topology_wire::ALL_MEMBERS;
    use canton_proto::com::digitalasset::canton::protocol::v30::TrafficControlParameters;
    let (config, url, admin_url) = common::start_with_admin();
    let physical = config.physical_synchronizer_id();
    let mut m = common::join(&url, &config, "traffic-payer");
    let me = m.identity.member();
    let send =
        |m: &mut common::Member, groups: Vec<String>, content: Vec<u8>, cost: Option<i64>| {
            let request = sw::submission_request_costed(
                &me,
                &format!("t{}", canton_sequencer_server::sequencing::wall_micros()),
                &[(groups[0].clone(), content)],
                common::far_future(),
                cost,
            );
            m.client.send_async(
                &me,
                &physical,
                &m.token,
                sw::signed_submission_request(request, &m.identity.signing_key),
            )
        };
    let refusal = |r: Result<(), canton_participant::sequencer_connect::ConnectError>| {
        format!("{:?}", r.expect_err("refused"))
    };
    // the owners turn traffic control on (parameters at serial 2)
    let on = common::parameters_broadcast_with(&config, 2, |p| {
        p.traffic_control = Some(TrafficControlParameters {
            max_base_traffic_amount: 1000,
            max_base_traffic_accumulation_duration: Some(prost_types::Duration {
                seconds: 600,
                nanos: 0,
            }),
            read_vs_write_scaling_factor: 200,
            set_balance_request_submission_window_size: Some(prost_types::Duration {
                seconds: 120,
                nanos: 0,
            }),
            enforce_rate_limiting: true,
            base_event_cost: Some(7),
            free_confirmation_responses: false,
        })
    });
    m.send(
        &physical,
        &[(vec![ALL_MEMBERS.to_string()], on)],
        "traffic-on",
        common::far_future(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let hundred = vec![b'x'; 100];
    // no cost, and less than the cost: refused, naming the cost
    let none = refusal(send(&mut m, vec![me.clone()], hundred.clone(), None));
    assert!(
        none.contains("SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Submission was refused because traffic control validation failed: IncorrectEventCost(")
            && none.contains("event cost = 109")
            && none.contains("The system is not in a state required"),
        "{none}"
    );
    let low = refusal(send(&mut m, vec![me.clone()], hundred.clone(), Some(108)));
    assert!(low.contains("submittedEventCost = 108"), "{low}");
    // more than the cost is accepted and what was sent is spent; then the right cost
    send(&mut m, vec![me.clone()], hundred.clone(), Some(114)).unwrap();
    send(&mut m, vec![me.clone()], hundred.clone(), Some(109)).unwrap();
    // 5000 bytes cost 5107: more than there is
    let big = vec![b'y'; 5000];
    let over = refusal(send(&mut m, vec![me.clone()], big.clone(), Some(5107)));
    assert!(
        over.contains("SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT(9,0): Submission was rejected because no traffic is available: AboveTrafficLimit(")
            && over.contains("trafficCost = 5107")
            && over.contains("lastConsumedCost = 109"),
        "{over}"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut admin = runtime.block_on(async {
        SequencerAdministrationServiceClient::new(
            tonic::transport::Channel::from_shared(admin_url.clone())
                .unwrap()
                .connect()
                .await
                .unwrap(),
        )
    });
    let state = |admin: &mut SequencerAdministrationServiceClient<tonic::transport::Channel>| {
        runtime
            .block_on(admin.traffic_control_state(TrafficControlStateRequest {
                members: vec![me.clone()],
                timestamp_selector: None,
            }))
            .unwrap()
            .into_inner()
            .traffic_states[&me]
    };
    let before = state(&mut admin);
    // 1000 - 114 - 109, refilled a little since
    assert!(
        (777..790).contains(&before.base_traffic_remainder) && before.extra_traffic_consumed == 0,
        "{before:?}"
    );
    let buy = |admin: &mut SequencerAdministrationServiceClient<tonic::transport::Channel>,
               serial: u32| {
        runtime.block_on(admin.set_traffic_purchased(SetTrafficPurchasedRequest {
            member: me.clone(),
            serial,
            total_traffic_purchased: 10_000,
        }))
    };
    buy(&mut admin, 1).unwrap();
    let again = buy(&mut admin, 1).unwrap_err();
    assert_eq!(again.code(), tonic::Code::NotFound);
    assert!(
        again.message().contains("TRAFFIC_CONTROL_SERIAL_TOO_LOW"),
        "{}",
        again.message()
    );
    // with the purchase the 5107 goes through: the base traffic first, the rest from the extra traffic
    send(&mut m, vec![me.clone()], big, Some(5107)).unwrap();
    let after = state(&mut admin);
    assert_eq!(
        (after.extra_traffic_purchased, after.serial),
        (10_000, Some(1))
    );
    assert_eq!(after.base_traffic_remainder, 0, "{after:?}");
    assert!(
        (4300..4335).contains(&after.extra_traffic_consumed),
        "{after:?}"
    );
    // the owners turn it off again: the broadcast to every member pays its own cost, and every member is the member, the mediator and the
    // sequencer (three)
    let off = common::parameters_broadcast_with(&config, 3, |p| p.traffic_control = None);
    let cost = off.len() as i64 + off.len() as i64 * 3 * 200 / 10_000 + 7;
    let wrong = refusal(send(
        &mut m,
        vec![ALL_MEMBERS.to_string()],
        off.clone(),
        Some(off.len() as i64 + off.len() as i64 * 200 / 10_000 + 7),
    ));
    assert!(
        wrong.contains("IncorrectEventCost"),
        "counting the one member only is too little: {wrong}"
    );
    send(&mut m, vec![ALL_MEMBERS.to_string()], off, Some(cost)).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    send(&mut m, vec![me.clone()], hundred, None).unwrap();
    let disabled = buy(&mut admin, 2).unwrap_err();
    assert!(
        disabled.message().contains("TRAFFIC_CONTROL_DISABLED(11,"),
        "{}",
        disabled.message()
    );
}
