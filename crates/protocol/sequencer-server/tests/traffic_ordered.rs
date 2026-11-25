//! Traffic control after ordering (`TrafficControlValidator.applyTrafficControl`): the balance is checked at the sequencing time, also for a
//! submission the orderer admitted, and what members spent survives a restart.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{self as tw, Ed25519Key};
use canton_proto::com::digitalasset::canton::protocol::v30::TrafficControlParameters;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::Sequencer;
use canton_sequencer_server::synchronizer_state::{parameters_transaction, TopologyStore};
use canton_sequencer_server::{ConnectService, SynchronizerConfig};
use tokio_stream::StreamExt as _;

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn member(name: &str, seed: u8) -> (String, Ed25519Key, Registered) {
    let key = Ed25519Key::from_seed([seed; 32]);
    let id = format!("PAR::{name}::{}", key.fingerprint);
    let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
    let registered = Registered {
        member: id.clone(),
        signing_keys: vec![raw.clone()],
        authentication_keys: vec![raw],
        encryption_keys: Vec::new(),
    };
    (id, key, registered)
}

/// A sequencer with traffic control on since ten seconds ago (1000 bytes of base traffic over ten minutes, factor 200, base cost 7: the
/// parameters of the oracle measurement), with its state in `dir` when given.
fn open(
    config: &SynchronizerConfig,
    dir: Option<&std::path::Path>,
    members: &[Registered],
) -> ConnectService {
    let store = Arc::new(TopologyStore::initial(
        &config.name,
        &config.sequencer_name,
        "rm1",
        &config.keys,
    ));
    let mut parameters = tw::default_dynamic_parameters();
    parameters.traffic_control = Some(TrafficControlParameters {
        max_base_traffic_amount: 1000,
        read_vs_write_scaling_factor: 200,
        max_base_traffic_accumulation_duration: Some(prost_types::Duration {
            seconds: 600,
            nanos: 0,
        }),
        enforce_rate_limiting: true,
        base_event_cost: Some(7),
        ..Default::default()
    });
    let tx = parameters_transaction(&config.keys, &store.synchronizer_uid(), 2, parameters);
    store.append(&[tx], now_micros() - 10_000_000);
    let registry = Arc::new(Registry::default());
    for m in members {
        registry.insert(m.clone());
    }
    ConnectService::open_seeded(config.clone(), store, registry, None, dir).unwrap()
}

fn costed(sender: &str, key: &Ed25519Key, id: &str, to: &str, size: usize, cost: i64) -> Vec<u8> {
    let plain = sw::submission_request_costed(
        sender,
        id,
        &[(to.to_string(), vec![1u8; size])],
        now_micros() + 60_000_000,
        Some(cost),
    );
    sw::signed_submission_request(plain, key)
}

async fn events(sequencer: &Sequencer, member: &str) -> Vec<sw::Delivered> {
    let mut stream = sequencer.subscribe(member.to_string(), None);
    let mut out = Vec::new();
    while let Ok(Some(Ok(response))) =
        tokio::time::timeout(std::time::Duration::from_millis(300), stream.next()).await
    {
        out.push(sw::decode_delivered(&response.signed_sequenced_event).unwrap());
    }
    out
}

#[test]
fn an_ordered_submission_its_sender_cannot_pay_for_is_rejected() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("trafficsync", "tseq");
        let (a, a_key, a_reg) = member("a", 101);
        let (b, _, b_reg) = member("b", 102);
        let service = open(&config, None, &[a_reg, b_reg]);
        let sequencer = service.sequencer();
        // 5000 bytes cost 5107, more than the 1000 of base traffic: the orderer admitted it, the sequencing time decides
        sequencer.apply_ordered_at(
            &a,
            &costed(&a, &a_key, "too-much", &b, 5000, 5107),
            now_micros(),
        );
        let answer = events(&sequencer, &a).await;
        assert_eq!(answer.len(), 1, "the sender is answered");
        let why = answer[0].error.clone().expect("an error event");
        assert!(why.contains("SEQUENCER_NOT_ENOUGH_TRAFFIC_CREDIT"), "{why}");
        assert!(
            events(&sequencer, &b).await.is_empty(),
            "nothing is delivered"
        );
        // negative control: 100 bytes (109) are paid for and delivered
        sequencer.apply_ordered_at(
            &a,
            &costed(&a, &a_key, "affordable", &b, 100, 109),
            now_micros(),
        );
        assert_eq!(events(&sequencer, &b).await.len(), 1);
    });
}

#[test]
fn what_a_member_spent_survives_a_restart() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dir = std::env::temp_dir().join(format!("seq5-traffic-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = canton_sequencer_server::new_synchronizer("trafficrs", "trs");
        let (a, a_key, a_reg) = member("a", 111);
        let (b, _, b_reg) = member("b", 112);
        let members = [a_reg, b_reg];
        {
            let service = open(&config, Some(&dir), &members);
            service.sequencer().apply_ordered_at(
                &a,
                &costed(&a, &a_key, "spend", &b, 500, 517),
                now_micros(),
            );
            let spent = service.sequencer().traffic_state(&a).unwrap();
            assert!(spent.base_traffic_remainder < 500, "{spent:?}");
        }
        let service = open(&config, Some(&dir), &members);
        let after = service.sequencer().traffic_state(&a).unwrap();
        assert!(
            after.base_traffic_remainder < 500,
            "the base traffic spent before the restart is still spent: {after:?}"
        );
        assert_eq!(after.last_consumed_cost, 0);
        drop(service);
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// `SubmissionRequestValidationResult.shouldTryToConsumeTraffic`: a rejected submission whose sender signed it pays its cost; a dropped one
/// (its signature does not verify) pays nothing.
#[test]
fn a_rejected_submission_pays_its_cost_and_a_dropped_one_does_not() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("trafficrej", "trej");
        let (a, a_key, a_reg) = member("a", 121);
        let service = open(&config, None, &[a_reg]);
        let sequencer = service.sequencer();
        let ghost = format!("PAR::ghost::1220{}", "ab".repeat(32));
        // a recipient that is not registered: an error event for the sender, and the 109 are spent
        sequencer.apply_ordered_at(
            &a,
            &costed(&a, &a_key, "to-ghost", &ghost, 100, 109),
            now_micros(),
        );
        let answer = events(&sequencer, &a).await;
        let why = answer[0].error.clone().expect("an error event");
        assert!(why.contains("SEQUENCER_UNKNOWN_RECIPIENTS"), "{why}");
        let after_reject = sequencer.traffic_state(&a).unwrap();
        assert!(
            after_reject.base_traffic_remainder <= 1000 - 109 + 2,
            "the rejected submission was charged: {after_reject:?}"
        );
        // negative control: signed by another key, the submission is dropped and costs nothing
        let other = Ed25519Key::from_seed([122; 32]);
        sequencer.apply_ordered_at(
            &a,
            &costed(&a, &other, "forged", &ghost, 100, 109),
            now_micros(),
        );
        let after_drop = sequencer.traffic_state(&a).unwrap();
        assert!(
            after_drop.base_traffic_remainder >= after_reject.base_traffic_remainder,
            "a dropped submission is not charged: {after_drop:?}"
        );
    });
}
