//! A traffic purchase is a `SetTrafficPurchasedMessage` the sequencers send to themselves (`TrafficPurchasedSubmissionHandler`), aggregated over
//! the sequencer group and applied where it is sequenced (`TrafficControlProcessor`): every sequencer that orders it applies it at the same time.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_participant::topology_wire::{self as tw, Ed25519Key};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    typed_signed_protocol_message_content::SomeSignedProtocolMessage, SetTrafficPurchasedMessage,
    TrafficControlParameters, TypedSignedProtocolMessageContent,
};
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::traffic_purchase::{purchase_submission, PurchaseRequest};
use canton_sequencer_server::synchronizer_state::{parameters_transaction, TopologyStore};
use canton_sequencer_server::{ConnectService, SynchronizerConfig};
use prost::Message;
use tokio_stream::StreamExt as _;

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn member(name: &str, seed: u8) -> (String, Registered) {
    let key = Ed25519Key::from_seed([seed; 32]);
    let id = format!("PAR::{name}::{}", key.fingerprint);
    let raw = canton_algo::member_signature::own_ed25519_key(&key.spki_der).unwrap();
    let registered = Registered {
        member: id.clone(),
        signing_keys: vec![raw.clone()],
        authentication_keys: vec![raw],
        encryption_keys: Vec::new(),
    };
    (id, registered)
}

fn open(config: &SynchronizerConfig, members: &[Registered]) -> ConnectService {
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
    ConnectService::open_seeded(config.clone(), store, registry, None, None).unwrap()
}

fn sequencer_member(config: &SynchronizerConfig) -> String {
    format!(
        "SEQ::{}::{}",
        config.sequencer_name, config.keys.namespace.fingerprint
    )
}

fn purchase(config: &SynchronizerConfig, key: &Ed25519Key, member: &str) -> Vec<u8> {
    let sender = sequencer_member(config);
    purchase_submission(
        &PurchaseRequest {
            sender: &sender,
            physical_synchronizer_id: &config.physical_synchronizer_id(),
            member,
            address_member: true,
            serial: 1,
            total: 10_000,
            max_sequencing_time: now_micros() + 60_000_000,
            message_id: "purchase-1",
        },
        key,
    )
}

#[test]
fn the_admin_purchase_reaches_its_member_as_a_sequenced_message() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let config = canton_sequencer_server::new_synchronizer("purchasemsg", "pseq");
        let (a, a_reg) = member("a", 131);
        let service = open(&config, &[a_reg]);
        let sequencer = service.sequencer();
        sequencer.purchase_traffic(&a, 1, 10_000).unwrap();
        let mut stream = sequencer.subscribe(a.clone(), None);
        let event = tokio::time::timeout(std::time::Duration::from_millis(500), stream.next())
            .await
            .expect("the member is sent the purchase")
            .unwrap()
            .unwrap();
        let delivered =
            canton_participant::sequencing_wire::decode_delivered(&event.signed_sequenced_event)
                .unwrap();
        let (typed, _) = tw::unversioned(&delivered.envelopes[0]).unwrap();
        let Some(SomeSignedProtocolMessage::SetTrafficPurchased(bytes)) =
            TypedSignedProtocolMessageContent::decode(typed.as_slice())
                .unwrap()
                .some_signed_protocol_message
        else {
            panic!("not a SetTrafficPurchasedMessage");
        };
        let message =
            SetTrafficPurchasedMessage::decode(tw::unversioned(&bytes).unwrap().0.as_slice())
                .unwrap();
        assert_eq!(
            (
                message.member.as_str(),
                message.serial,
                message.total_traffic_purchased
            ),
            (a.as_str(), 1, 10_000)
        );
        assert_eq!(
            message.physical_synchronizer_id,
            config.physical_synchronizer_id()
        );
        assert_eq!(
            delivered.envelope_signatures[0].len(),
            1,
            "signed by the sequencer"
        );
        let state = sequencer.traffic_state(&a).unwrap();
        assert_eq!(
            (state.extra_traffic_purchased, state.serial),
            (10_000, Some(1))
        );
    });
}

#[test]
fn an_ordered_purchase_is_applied_by_every_sequencer_and_a_forged_one_by_none() {
    let config = canton_sequencer_server::new_synchronizer("purchaseord", "pord");
    let (a, a_reg) = member("a", 141);
    // a sequencer that did not take the admin call: it applies the purchase the orderer gives it
    let other = open(&config, std::slice::from_ref(&a_reg));
    other.sequencer().apply_ordered_at(
        &sequencer_member(&config),
        &purchase(&config, &config.keys.sequencer_signing, &a),
        now_micros(),
    );
    let state = other.sequencer().traffic_state(&a).unwrap();
    assert_eq!(
        (state.extra_traffic_purchased, state.serial),
        (10_000, Some(1)),
        "the ordered purchase is in force"
    );
    // negative control: the same purchase signed by a key that is not the sequencer's
    let forged = open(&config, &[a_reg]);
    forged.sequencer().apply_ordered_at(
        &sequencer_member(&config),
        &purchase(&config, &Ed25519Key::from_seed([142; 32]), &a),
        now_micros(),
    );
    let state = forged.sequencer().traffic_state(&a).unwrap();
    assert_eq!((state.extra_traffic_purchased, state.serial), (0, None));
}
