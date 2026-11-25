//! The pruning administration of the sequencer and of the mediators inside it (`SequencerPruningAdministrationService`,
//! `MediatorAdministrationService`), with the answers 3.7.2 gives: a block sequencer prunes up to the earliest safe pruning point and does not
//! support scheduled pruning or `FindPruningTimestamp`; a mediator prunes up to its clean time less the confirmation response timeout.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::Ed25519Key;
use canton_proto::com::digitalasset::canton::admin::pruning::v30::{
    FindPruningTimestampRequest, GetScheduleRequest,
};
use canton_proto::com::digitalasset::canton::mediator::admin::v30::mediator_administration_service_server::MediatorAdministrationService;
use canton_proto::com::digitalasset::canton::mediator::admin::v30::mediator_pruning;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_administration_service_server::SequencerAdministrationService;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::sequencer_pruning_administration_service_server::SequencerPruningAdministrationService;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    PruneRequest, PruningStatusRequest,
};
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::pruning_admin::{MediatorPruning, SequencerPruning};
use canton_sequencer_server::synchronizer_state::TopologyStore;
use canton_sequencer_server::ConnectService;
use tokio_stream::StreamExt as _;
use tonic::Request;

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn timestamp(micros: i64) -> Option<prost_types::Timestamp> {
    Some(prost_types::Timestamp {
        seconds: micros.div_euclid(1_000_000),
        nanos: (micros.rem_euclid(1_000_000) * 1000) as i32,
    })
}

fn open() -> (ConnectService, String, Ed25519Key) {
    let config = canton_sequencer_server::new_synchronizer("prunesync", "pseq");
    let store = Arc::new(TopologyStore::initial(
        &config.name,
        &config.sequencer_name,
        "rm1",
        &config.keys,
    ));
    let key = Ed25519Key::from_seed([151; 32]);
    let id = format!("PAR::a::{}", key.fingerprint);
    let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
    let registry = Arc::new(Registry::default());
    registry.insert(Registered {
        member: id.clone(),
        signing_keys: vec![raw.clone()],
        authentication_keys: vec![raw],
        encryption_keys: Vec::new(),
    });
    let service = ConnectService::open_seeded(config, store, registry, None, None).unwrap();
    (service, id, key)
}

fn to_self(member: &str, key: &Ed25519Key, id: &str) -> Vec<u8> {
    let plain = sw::submission_request(
        member,
        id,
        &[(member.to_string(), b"x".to_vec())],
        now_micros() + 60_000_000,
    );
    sw::signed_submission_request(plain, key)
}

async fn stored(service: &ConnectService, member: &str) -> Vec<i64> {
    let mut stream = service.sequencer().subscribe(member.to_string(), None);
    let mut out = Vec::new();
    while let Ok(Some(Ok(response))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await
    {
        out.push(
            sw::decode_delivered(&response.signed_sequenced_event)
                .unwrap()
                .timestamp_micros,
        );
    }
    out
}

#[test]
fn the_sequencer_prunes_up_to_the_safe_point_and_no_further() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (service, a, key) = open();
        let sequencer = service.sequencer();
        let pruning = SequencerPruning::new(service.sequencer());
        sequencer.submit(&a, &to_self(&a, &key, "one")).unwrap();
        sequencer.submit(&a, &to_self(&a, &key, "two")).unwrap();
        let events = stored(&service, &a).await;
        assert_eq!(events.len(), 2);
        // nothing is acknowledged: pruning at the second event would take the first from a member that has not read it
        let refused = pruning
            .prune(Request::new(PruneRequest {
                timestamp: timestamp(events[1]),
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(
            refused.message().starts_with("Could not prune at [")
                && refused
                    .message()
                    .contains("as the earliest safe pruning point is ["),
            "{}",
            refused.message()
        );
        assert_eq!(stored(&service, &a).await.len(), 2, "nothing was pruned");
        // once the member acknowledged the second event, the first may go
        sequencer
            .acknowledge(&a, &sw::signed_acknowledge_request(&a, events[1], &key))
            .unwrap();
        let admin = canton_sequencer_server::admin::AdminService::new(
            service.registry(),
            service.sequencer(),
        );
        let status = admin
            .pruning_status(Request::new(PruningStatusRequest {}))
            .await
            .unwrap()
            .into_inner()
            .pruning_status
            .unwrap();
        let own = status.members.iter().find(|m| m.member == a).unwrap();
        assert_eq!(own.last_acknowledged, Some(events[1]));
        assert!(own.enabled);
        pruning
            .prune(Request::new(PruneRequest {
                timestamp: timestamp(events[1]),
            }))
            .await
            .unwrap();
        assert_eq!(stored(&service, &a).await, vec![events[1]]);
        // a block sequencer neither schedules pruning nor finds pruning timestamps (`BlockSequencer`, `PruningError.NotSupported`)
        let find = pruning
            .find_pruning_timestamp(Request::new(FindPruningTimestampRequest { index: 1 }))
            .await
            .unwrap_err();
        assert_eq!(find.code(), tonic::Code::Unimplemented);
        assert_eq!(find.message(), "This sequencer does not support pruning");
        let schedule = pruning
            .get_schedule(Request::new(GetScheduleRequest {}))
            .await
            .unwrap_err();
        assert_eq!(schedule.code(), tonic::Code::Unimplemented);
        assert_eq!(
            schedule.message(),
            "This sequencer does not support scheduled pruning"
        );
    });
}

#[test]
fn the_mediator_prunes_only_what_it_has_processed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (service, _, _) = open();
        let pruning = MediatorPruning::new(service.sequencer());
        let prune = |at: i64| {
            pruning.prune(Request::new(mediator_pruning::PruneRequest {
                timestamp: timestamp(at),
            }))
        };
        let nothing = prune(now_micros()).await.unwrap_err();
        assert_eq!(nothing.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            nothing.message(),
            "There is no mediator data available for pruning"
        );
        // the mediator has seen the synchronizer's time now
        service.sequencer().expire_requests();
        let late = prune(now_micros() + 3_600_000_000).await.unwrap_err();
        assert_eq!(late.code(), tonic::Code::InvalidArgument);
        assert!(
            late.message()
                .contains("is later than the earliest available pruning timestamp"),
            "{}",
            late.message()
        );
        // a time before the clean time less the confirmation response timeout (30 s) is safe
        prune(now_micros() - 120_000_000).await.unwrap();
        let first = pruning
            .find_pruning_timestamp(Request::new(FindPruningTimestampRequest { index: 1 }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first.timestamp, None, "no finalized response yet");
    });
}
