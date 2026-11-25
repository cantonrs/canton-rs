use super::*;

#[test]
fn poisoned_nodes_mutex_recovers_topology_instead_of_dropping_peers() {
    let reg = Arc::new(Registry::default());
    let consensus = Consensus::new(
        "SEQ::self::1220aa".into(),
        [7u8; 32],
        "1220aa".into(),
        Some(10),
        reg,
    );
    consensus.set_nodes(vec![
        "SEQ::self::1220aa".into(),
        "SEQ::peer-b::1220bb".into(),
    ]);

    let nodes_arc = Arc::clone(&consensus.nodes);
    let res = std::thread::spawn(move || {
        let _g = nodes_arc.lock().expect("lock nodes to poison");
        panic!("simulated panic while holding Consensus::nodes mutex");
    })
    .join();
    assert!(res.is_err(), "spawning thread must panic to poison mutex");

    let (_epoch, ep_nodes, _leaders, _blacklisted) = consensus.ordering_topology();
    assert!(
        ep_nodes.iter().any(|n| n == "SEQ::peer-b::1220bb"),
        "ordering_topology must recover poisoned nodes mutex instead of dropping peer-b: {ep_nodes:?}"
    );
}

#[test]
fn poisoned_batches_mutex_recovers_stored_batch() {
    use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
        availability_message, bft_ordering_message_body::Message, Batch, BatchRequest,
        OrderingRequest,
    };
    use prost::Message as _;

    let reg = Arc::new(Registry::default());
    let consensus = Consensus::new(
        "SEQ::self::1220aa".into(),
        [7u8; 32],
        "1220aa".into(),
        Some(10),
        reg,
    );
    let batch_id = b"batch-poison-test".to_vec();
    let expected_batch = Batch {
        ordering_requests: vec![OrderingRequest {
            trace_context: String::new(),
            tag: "send".into(),
            message_id: "m1".into(),
            payload: b"payload".to_vec(),
            ordering_start_instant: None,
        }],
        epoch_number: 3,
    };
    {
        let mut bmap = lock_or_recover(&consensus.batches, "batches");
        bmap.insert(batch_id.clone(), expected_batch.clone());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    consensus.register_peer("SEQ::peer-c::1220cc", tx);

    let res = std::thread::scope(|s| {
        s.spawn(|| {
            let _g = consensus.batches.lock().expect("lock batches to poison");
            panic!("simulated panic while holding Consensus::batches mutex");
        })
        .join()
    });
    assert!(
        res.is_err(),
        "spawning thread must panic to poison batches mutex"
    );

    consensus.on_batch_request(
        "SEQ::peer-c::1220cc",
        BatchRequest {
            batch_id: batch_id.clone(),
            epoch_number: 3,
        },
    );
    let msg = rx
        .try_recv()
        .expect("on_batch_request must recover poisoned batches mutex instead of dropping batch");
    let Some(Message::AvailabilityMessage(signed)) = msg.body.and_then(|b| b.message) else {
        panic!("expected AvailabilityMessage");
    };
    let inner = canton_bft_orderer::wire::unwrap_versioned(&signed.message, 30).expect("unwrap");
    let avail = canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::AvailabilityMessage::decode(inner.as_slice()).expect("decode avail");
    let Some(availability_message::Message::BatchResponse(resp)) = avail.message else {
        panic!("expected BatchResponse");
    };
    assert_eq!(resp.batch_id, batch_id);
    assert_eq!(resp.batch, Some(expected_batch));
}

#[test]
fn poisoned_node_lock_halts_tick_with_error() {
    let reg = Arc::new(Registry::default());
    let consensus = Consensus::new(
        "SEQ::self::1220aa".into(),
        [7u8; 32],
        "1220aa".into(),
        Some(10),
        reg,
    );
    consensus.set_nodes(vec![
        "SEQ::self::1220aa".into(),
        "SEQ::peer-b::1220bb".into(),
    ]);
    consensus
        .start_genesis_or_resume()
        .expect("start genesis node");
    assert!(consensus.is_started());

    std::thread::scope(|s| {
        let h = s.spawn(|| {
            let _g = consensus.node.lock().expect("lock node to poison");
            panic!("deliberate test poison of Consensus::node");
        });
        assert!(h.join().is_err());
    });
    assert!(consensus.node.is_poisoned());
    assert!(
        !consensus.is_started(),
        "poisoned node mutex must report not started"
    );

    let err = consensus
        .tick()
        .expect_err("poisoned node lock must halt tick() with error instead of recovering");
    assert!(
        err.contains("node") && err.contains("poisoned"),
        "expected poisoned node error message, got: {err}"
    );
}
