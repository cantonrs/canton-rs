//! An open subscription follows its member's events by timestamp: the events the running server forgets once they are acknowledged
//! (`compact_running`) do not move it (S-7: a cursor counted in events skipped the next one).
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;
use std::time::Duration;

use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::Ed25519Key;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::synchronizer_state::TopologyStore;
use canton_sequencer_server::ConnectService;
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

type Events = tokio_stream::wrappers::ReceiverStream<
    Result<
        canton_proto::com::digitalasset::canton::sequencer::api::v30::SubscriptionResponse,
        tonic::Status,
    >,
>;

async fn next(stream: &mut Events) -> sw::Delivered {
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("the next event reaches the open subscription")
        .unwrap()
        .unwrap();
    sw::decode_delivered(&response.signed_sequenced_event).unwrap()
}

#[test]
fn a_subscription_keeps_its_place_when_acknowledged_events_are_forgotten() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dir = std::env::temp_dir().join(format!("seq5-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = canton_sequencer_server::new_synchronizer("cursor", "cs");
        let (a, a_key, a_reg) = member("a", 121);
        let (b, b_key, b_reg) = member("b", 122);
        let store = Arc::new(TopologyStore::initial(
            &config.name,
            &config.sequencer_name,
            "rm1",
            &config.keys,
        ));
        let registry = Arc::new(Registry::default());
        registry.insert(a_reg);
        registry.insert(b_reg);
        let service =
            ConnectService::open_seeded(config.clone(), store, registry, None, Some(&dir)).unwrap();
        let sequencer = service.sequencer();
        let send = |id: &str, at: i64| {
            let plain = sw::submission_request(
                &a,
                id,
                &[(b.clone(), id.as_bytes().to_vec())],
                at + 60_000_000,
            );
            sequencer.apply_ordered_at(&a, &sw::signed_submission_request(plain, &a_key), at);
        };
        let mut stream = sequencer.subscribe(b.clone(), None);
        let start = now_micros();
        send("first", start);
        send("second", start + 1);
        let first = next(&mut stream).await;
        let second = next(&mut stream).await;
        assert_eq!(second.envelopes, vec![b"second".to_vec()]);
        // b has read the first: the running server forgets it (a member's last event stays, the next one names it)
        sequencer
            .acknowledge(
                &b,
                &sw::signed_acknowledge_request(&b, first.timestamp_micros, &b_key),
            )
            .unwrap();
        let (forgotten, _, _) = sequencer.compact_running().unwrap();
        assert!(forgotten >= 1, "the acknowledged event is forgotten");
        send("third", start + 2);
        let third = next(&mut stream).await;
        assert_eq!(third.envelopes, vec![b"third".to_vec()]);
        assert_eq!(
            third.previous_timestamp_micros,
            Some(second.timestamp_micros)
        );
        drop(stream);
        drop(service);
        let _ = std::fs::remove_dir_all(&dir);
    });
}
