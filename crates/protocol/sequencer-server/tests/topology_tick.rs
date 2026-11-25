//! Unit & integration tests for O3 (BFT post-ordering & epoch-end topology ticks).
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire::{self as tw, Ed25519Key};
use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
use canton_proto::com::digitalasset::canton::protocol::v30::SignedContent;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    DynamicSynchronizerParameters, SynchronizerParametersState,
};
use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;
use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;
use canton_sequencer_server::onboarding::{Registered, Registry};
use canton_sequencer_server::sequencing::{may_change_ordering_topology, Sequencer};
use canton_sequencer_server::synchronizer_state::{SynchronizerKeys, TopologyStore};
use prost::Message as _;
use std::sync::Arc;
use tokio_stream::StreamExt;

#[test]
fn may_change_ordering_topology_respects_all_recipient_and_stricter_mode() {
    let key = Ed25519Key::from_seed([11u8; 32]);
    let sender = format!("PAR::alice::{}", key.fingerprint);
    let sync_id = format!("testsync::{}", key.fingerprint);
    let phys_id = format!("{sync_id}::37-0");

    // 1. Direct message to PAR recipient -> false in both default and stricter mode.
    let direct_req = sw::submission_request(
        &sender,
        "direct-1",
        &[("PAR::bob::1220".into(), b"hello".to_vec())],
        9_999_999,
    );
    let direct_signed = sw::signed_submission_request(direct_req, &key);
    assert!(!may_change_ordering_topology(&direct_signed, false));
    assert!(!may_change_ordering_topology(&direct_signed, true));

    // 2. PartyToParticipant broadcast to ALL -> true under default (stricter=false), false under stricter=true.
    let party_id = format!("carol::{}", key.fingerprint);
    let p2p_bytes = tw::party_to_participant(&party_id, &format!("alice::{}", key.fingerprint));
    let p2p_signed = tw::signed(p2p_bytes.clone(), vec![key.sign_transaction(&p2p_bytes)]);
    let p2p_broadcast = tw::topology_broadcast(&phys_id, &[p2p_signed]);
    let p2p_req = sw::submission_request(
        &sender,
        "topo-p2p",
        &[(tw::ALL_MEMBERS.into(), p2p_broadcast)],
        9_999_999,
    );
    let p2p_signed_req = sw::signed_submission_request(p2p_req, &key);
    assert!(may_change_ordering_topology(&p2p_signed_req, false));
    assert!(!may_change_ordering_topology(&p2p_signed_req, true));

    // 3. SynchronizerParametersState broadcast to ALL -> true in both default and stricter=true.
    let params = tw::versioned(
        TopologyTransaction {
            operation: 1,
            serial: 2,
            mapping: Some(canton_proto::com::digitalasset::canton::protocol::v31::TopologyMapping {
                mapping: Some(
                    canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping::SynchronizerParametersState(
                        SynchronizerParametersState {
                            synchronizer_id: sync_id,
                            synchronizer_parameters: Some(DynamicSynchronizerParameters::default()),
                        },
                    ),
                ),
            }),
        }
        .encode_to_vec(),
        tw::TOPOLOGY_TRANSACTION_VERSION,
    );
    let params_signed = tw::signed(params.clone(), vec![key.sign_transaction(&params)]);
    let params_broadcast = tw::topology_broadcast(&phys_id, &[params_signed]);
    let params_req = sw::submission_request(
        &sender,
        "topo-params",
        &[(tw::ALL_MEMBERS.into(), params_broadcast)],
        9_999_999,
    );
    let params_signed_req = sw::signed_submission_request(params_req, &key);
    assert!(may_change_ordering_topology(&params_signed_req, false));
    assert!(may_change_ordering_topology(&params_signed_req, true));

    // 4. Sequencer OwnerToKeyMapping broadcast to ALL -> true under stricter=true too.
    let seq_okm = tw::owner_to_key_mapping(
        &format!("SEQ::s2::{}", key.fingerprint),
        vec![canton_proto::com::digitalasset::canton::crypto::v30::PublicKey {
            key: Some(canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key::SigningPublicKey(
                key.public_key(&[SigningKeyUsage::SequencerAuthentication, SigningKeyUsage::ProofOfOwnership]),
            )),
        }],
    );
    let okm_signed = tw::signed(seq_okm.clone(), vec![key.sign_transaction(&seq_okm)]);
    let okm_broadcast = tw::topology_broadcast(&phys_id, &[okm_signed]);
    let okm_req = sw::submission_request(
        &sender,
        "topo-seq-key",
        &[(tw::ALL_MEMBERS.into(), okm_broadcast)],
        9_999_999,
    );
    let okm_signed_req = sw::signed_submission_request(okm_req, &key);
    assert!(may_change_ordering_topology(&okm_signed_req, true));
}

#[tokio::test]
async fn finish_ordered_block_emits_sequencer_and_all_member_ticks_at_exact_boundaries() {
    let raw_key =
        |k: &Ed25519Key| canton_algo::member_signature::own_ed25519_key(&k.spki_der).unwrap();
    let keys = Arc::new(SynchronizerKeys::generate());
    let phys_id = format!("testsync::{}::37-0", keys.namespace.fingerprint);
    let registry = Arc::new(Registry::default());
    let seq_member = format!("SEQ::seq1::{}", keys.namespace.fingerprint);
    registry.insert(Registered {
        member: seq_member.clone(),
        signing_keys: vec![raw_key(&keys.sequencer_signing)],
        authentication_keys: vec![raw_key(&keys.sequencer_authentication)],
        encryption_keys: vec![],
    });
    let par_key = Ed25519Key::from_seed([22u8; 32]);
    let par_member = format!("PAR::p1::{}", par_key.fingerprint);
    registry.insert(Registered {
        member: par_member.clone(),
        signing_keys: vec![raw_key(&par_key)],
        authentication_keys: vec![raw_key(&par_key)],
        encryption_keys: vec![],
    });

    let store = Arc::new(TopologyStore::initial("testsync", "seq1", &phys_id, &keys));
    let sequencer = Sequencer::new(phys_id.clone(), keys, registry, store);
    sequencer.set_observer();
    sequencer.set_self_member(&seq_member);

    let mut seq_stream = sequencer.subscribe(seq_member.clone(), Some(0));
    let mut par_stream = sequencer.subscribe(par_member.clone(), Some(0));

    // Submit a topology broadcast addressed to ALL at t = 1_000_000 (epoch 0, block 0).
    let party_id = format!("carol::{}", par_key.fingerprint);
    let p2p_bytes = tw::party_to_participant(&party_id, &format!("p1::{}", par_key.fingerprint));
    let p2p_signed = tw::signed(
        p2p_bytes.clone(),
        vec![par_key.sign_transaction(&p2p_bytes)],
    );
    let topo_broadcast = tw::topology_broadcast(&phys_id, &[p2p_signed]);
    let req = sw::submission_request(
        &par_member,
        "topo-1",
        &[(tw::ALL_MEMBERS.into(), topo_broadcast)],
        9_000_000,
    );
    let signed_req = sw::signed_submission_request(req, &par_key);
    sequencer.apply_ordered_at(&par_member, &signed_req, 1_000_000);

    // Block 0 ends epoch 0 at 1_000_000 (within 250ms delay): only SequencersOfSynchronizer tick emits at 1_000_001,
    // and has_pending reports true because 1_000_000 + 250_000 > 1_000_000.
    let (emitted, pending) = sequencer.finish_ordered_block(0, 1_000_000, Some(1_000_000));
    assert_eq!(emitted, Some(("sequencers", 1_000_001)));
    assert!(pending);

    // Block 1 empty at exact boundary ts + 250_000 (1_250_000): eff == block_end (not strictly < block_end) -> no early ALL tick.
    let (emitted, pending) = sequencer.finish_ordered_block(1, 1_250_000, None);
    assert_eq!(emitted, None);
    assert!(!pending);

    // Block 2 empty past 1_250_000 (1_251_000): ALL tick emits for every member at 1_251_000 and clears pending.
    let (emitted, pending) = sequencer.finish_ordered_block(2, 1_251_000, Some(1_251_000));
    assert_eq!(emitted, Some(("all", 1_251_000)));
    assert!(!pending);

    // Block 3 with no topology change and tick_topology_at_least = None -> no tick emitted.
    let (emitted, pending) = sequencer.finish_ordered_block(3, 1_252_000, None);
    assert_eq!(emitted, None);
    assert!(!pending);

    let decode_ev = |bytes: Vec<u8>| {
        let (sc_bytes, _) = tw::unversioned(&bytes).unwrap();
        let sc = SignedContent::decode(sc_bytes.as_slice()).unwrap();
        let (ev_bytes, _) = tw::unversioned(&sc.content.unwrap()).unwrap();
        SequencedEvent::decode(ev_bytes.as_slice()).unwrap()
    };

    // Participant should see:
    //  - ts=1_000_000 (the broadcast event itself),
    //  - ts=1_251_000 (AllMembersOfSynchronizer tick with empty message_id; NOT the 1_000_001 SequencersOfSynchronizer tick!).
    let p_ev1 = decode_ev(
        par_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .signed_sequenced_event,
    );
    assert_eq!(p_ev1.timestamp, 1_000_000);
    assert_eq!(p_ev1.message_id.as_deref(), Some("topo-1"));

    let p_ev2 = decode_ev(
        par_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .signed_sequenced_event,
    );
    assert_eq!(p_ev2.timestamp, 1_251_000);
    assert_eq!(p_ev2.message_id, None);
    assert_eq!(p_ev2.batch.unwrap().compressed_envelopes.len(), 0);

    // Sequencer sees topo-1 (ALL broadcast at 1_000_000), the 1_000_001 Sequencers tick (message_id topology-tick-0),
    // and the 1_251_000 AllMembers tick (message_id topology-tick-2).
    let s_ev0 = decode_ev(
        seq_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .signed_sequenced_event,
    );
    assert_eq!(s_ev0.timestamp, 1_000_000);
    assert_eq!(s_ev0.message_id, None);

    let s_ev1 = decode_ev(
        seq_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .signed_sequenced_event,
    );
    assert_eq!(s_ev1.timestamp, 1_000_001);
    assert_eq!(s_ev1.message_id.as_deref(), Some("topology-tick-0"));

    let s_ev2 = decode_ev(
        seq_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .signed_sequenced_event,
    );
    assert_eq!(s_ev2.timestamp, 1_251_000);
    assert_eq!(s_ev2.message_id.as_deref(), Some("topology-tick-2"));
}
