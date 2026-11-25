//! The orderer's queues have the bounds of the official one, and what goes over them is refused: the mempool
//! (`DefaultMaxMempoolQueueSize`) and the batches a peer may have this node store before they are ordered
//! (`DefaultAvailabilityMaxNonOrderedBatchesPerNode`).
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_bft_orderer::availability::{batch_id, Request};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use canton_sequencer_server::bft_p2p::Consensus;
use canton_sequencer_server::onboarding::Registry;

fn node() -> Consensus {
    Consensus::new(
        "SEQ::rs1::1220aa".into(),
        [3; 32],
        "1220aa".into(),
        None,
        Arc::new(Registry::default()),
    )
}

#[test]
fn a_full_mempool_refuses_a_request() {
    let c = node();
    for i in 0..10 * 1_024 {
        assert!(
            c.order_request("send", &format!("m{i}"), vec![1]),
            "request {i} fits"
        );
    }
    assert!(
        !c.order_request("send", "one-more", vec![1]),
        "the 10241st request is refused"
    );
}

#[test]
fn a_peer_cannot_have_more_than_a_thousand_unordered_batches_stored() {
    let c = node();
    let (sender, mut acks) = tokio::sync::mpsc::channel(4_096);
    c.register_peer("SEQ::b", sender);
    let store = |i: u32| {
        let requests = [Request {
            tag: "send".into(),
            payload: i.to_be_bytes().to_vec(),
        }];
        let id = batch_id(
            &requests,
            0,
            canton_sequencer_server::PROTOCOL_VERSION as u32,
        )
        .unwrap();
        c.on_store_request(
            "SEQ::b",
            bft::StoreRequest {
                batch_id: id.0,
                batch: Some(bft::Batch {
                    ordering_requests: vec![bft::OrderingRequest {
                        trace_context: String::new(),
                        tag: "send".into(),
                        message_id: format!("m{i}"),
                        payload: i.to_be_bytes().to_vec(),
                        ordering_start_instant: None,
                    }],
                    epoch_number: 0,
                }),
            },
        )
        .unwrap();
    };
    for i in 0..1_001 {
        store(i);
    }
    let mut acked = 0;
    while acks.try_recv().is_ok() {
        acked += 1;
    }
    assert_eq!(
        acked, 1_000,
        "the batch over the quota is not stored nor acked"
    );
}
