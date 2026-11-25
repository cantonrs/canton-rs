//! Mempool, batch availability dissemination, and ordered output delivery for [`Consensus`].

use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::BftOrderingMessage;

use super::ordering::report;
use super::{
    lock_critical, lock_or_recover, pbft_discriminator, BlockEndSink, Consensus, Dissemination,
    OutputRequest, OutputSink, SignedMessage, MAX_MEMPOOL_QUEUE_SIZE,
    MAX_NON_ORDERED_BATCHES_PER_NODE,
};

impl Consensus {
    /// The view change timeout the official nodes were configured with (`view-change-timeout-override`).
    pub fn set_view_change_timeout_ms(&mut self, millis: u64) {
        self.view_change_timeout_ms = Some(millis);
    }

    /// A request the sequencer of this node was sent (`BftBlockOrderer.send`: the tag `send`, the message id, the signed submission as payload): it waits to be made
    /// into a batch. Returns false when the mempool is full and the request is refused (`MempoolModule`, `RequestRejected.QueueFull`).
    pub fn order_request(&self, tag: &str, message_id: &str, payload: Vec<u8>) -> bool {
        let mut mempool = lock_or_recover(&self.mempool, "mempool");
        if mempool.len() >= MAX_MEMPOOL_QUEUE_SIZE {
            crate::diag::diag_eprintln!(
                "MEMPOOL full ({MAX_MEMPOOL_QUEUE_SIZE} requests): request {message_id} refused"
            );
            return false;
        }
        mempool.push((tag.to_string(), message_id.to_string(), payload));
        true
    }

    /// Forgets the batches no block can name any more: a batch is valid for `BATCH_VALIDITY_EPOCHS` epochs after the one it was made in (`OrderingRequestBatch`), so
    /// what is older than that, counted from the epoch the node is in, is dropped (once a minute at most).
    fn prune_batches(&self, current_epoch: i64) {
        {
            let mut last = lock_or_recover(&self.last_prune, "last_prune");
            if last.elapsed() < std::time::Duration::from_secs(60) {
                return;
            }
            *last = std::time::Instant::now();
        }
        let oldest = current_epoch - canton_bft_orderer::node::BATCH_VALIDITY_EPOCHS - 1;
        let mut batches = lock_or_recover(&self.batches, "batches");
        let before = batches.len();
        batches.retain(|_, b| b.epoch_number >= oldest);
        {
            let mut quota = lock_or_recover(&self.store_quota, "store_quota");
            for ids in quota.values_mut() {
                ids.retain(|id| batches.contains_key(id));
            }
        }
        if batches.len() < before {
            crate::diag::diag_eprintln!(
                "AVAILABILITY forgot {} batch(es) older than epoch {oldest}",
                before - batches.len()
            );
        }
    }

    /// Makes a batch of what waits in the mempool and asks the others to store it (`AvailabilityModule`, the dissemination of a batch): the batch, stored here and acked
    /// by this node, goes to every peer in a `StoreRequest`; the proof of availability is made when enough nodes have acked (`on_store_response`).
    pub(super) fn disseminate(&self) -> Result<(), String> {
        use canton_bft_orderer::availability::{batch_id, sign_ack, Request as BatchRequest};
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            availability_message, AvailabilityMessage, Batch, OrderingRequest, StoreRequest,
        };
        let epoch = match lock_critical(&self.node, "node")?.as_ref() {
            Some(n) => n.epoch_number(),
            None => return Ok(()),
        };
        self.prune_batches(epoch);
        let requests: Vec<(String, String, Vec<u8>)> = {
            let mut m = lock_or_recover(&self.mempool, "mempool");
            if m.is_empty() {
                return Ok(());
            }
            let take = m.len().min(50);
            m.drain(..take).collect()
        };
        let batch = Batch {
            ordering_requests: requests
                .iter()
                .map(|(tag, id, payload)| OrderingRequest {
                    trace_context: String::new(),
                    tag: tag.clone(),
                    message_id: id.clone(),
                    payload: payload.clone(),
                    ordering_start_instant: None,
                })
                .collect(),
            epoch_number: epoch,
        };
        let for_hash: Vec<BatchRequest> = requests
            .iter()
            .map(|(tag, _, payload)| BatchRequest {
                tag: tag.clone(),
                payload: payload.clone(),
            })
            .collect();
        let Ok(id) = batch_id(&for_hash, epoch, crate::PROTOCOL_VERSION as u32) else {
            return Ok(());
        };
        let Ok(own_ack) = sign_ack(
            &id,
            epoch,
            &self.member,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return Ok(());
        };
        lock_or_recover(&self.batches, "batches").insert(id.0.clone(), batch.clone());
        self.save_batch_to_ord(&id.0, epoch, &batch)?;
        {
            let mut d = lock_critical(&self.disseminating, "disseminating")?;
            let mut acks = std::collections::BTreeMap::new();
            acks.insert(self.member.clone(), own_ack);
            d.insert(
                id.0.clone(),
                Dissemination {
                    epoch,
                    acks,
                    proof_queued: false,
                },
            );
        }
        let peers: Vec<String> = lock_or_recover(&self.peer_senders, "peer_senders")
            .keys()
            .cloned()
            .collect();
        for peer in &peers {
            self.send_availability(
                peer,
                AvailabilityMessage {
                    message: Some(availability_message::Message::StoreRequest(StoreRequest {
                        batch_id: id.0.clone(),
                        batch: Some(batch.clone()),
                    })),
                },
            );
        }
        crate::diag::diag_eprintln!("AVAILABILITY made a batch of {} request(s) for epoch {epoch} and asked {} peer(s) to store it", requests.len(), peers.len());
        self.finish_dissemination(&id.0)
    }

    /// A peer's `StoreResponse`: its ack of one of this node's batches, checked against the key the topology lists for it.
    pub fn on_store_response(
        &self,
        from: &str,
        response: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::StoreResponse,
    ) -> Result<(), String> {
        use canton_bft_orderer::availability::{verify_ack, BatchId};
        let Some(signature) = response.signature else {
            return Ok(());
        };
        let epoch =
            match lock_critical(&self.disseminating, "disseminating")?.get(&response.batch_id) {
                Some(entry) => entry.epoch,
                None => return Ok(()),
            };
        let keys = self
            .registry
            .get(from)
            .map(|r| r.signing_keys)
            .unwrap_or_default();
        let verified = keys.iter().any(|key| {
            verify_ack(
                &BatchId(response.batch_id.clone()),
                epoch,
                from,
                &signature,
                key,
            )
            .is_ok()
        });
        if !verified {
            crate::diag::diag_eprintln!("AVAILABILITY an ack of {from} that does not verify");
            return Ok(());
        }
        if let Some(entry) =
            lock_critical(&self.disseminating, "disseminating")?.get_mut(&response.batch_id)
        {
            entry.acks.insert(from.to_string(), signature);
        }
        self.finish_dissemination(&response.batch_id)
    }

    /// When a batch has acks from at least a weak quorum of the nodes, its proof of availability goes to the consensus (the node proposes it in its next block).
    fn finish_dissemination(&self, id: &[u8]) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{AvailabilityAck, ProofOfAvailability};
        let weak = canton_bft_orderer::topology::weak_quorum_size(
            lock_or_recover(&self.nodes, "nodes").len().max(1),
        );
        let proof = {
            let mut d = lock_critical(&self.disseminating, "disseminating")?;
            let Some(entry) = d.get_mut(id) else {
                return Ok(());
            };
            if entry.proof_queued || entry.acks.len() < weak {
                return Ok(());
            }
            entry.proof_queued = true;
            let proof = ProofOfAvailability {
                batch_id: id.to_vec(),
                acks: entry
                    .acks
                    .iter()
                    .map(|(from, signature)| AvailabilityAck {
                        from: from.clone(),
                        signature: Some(signature.clone()),
                    })
                    .collect(),
                epoch_number: entry.epoch,
            };
            // the acks are done: later ones are ignored
            d.remove(id);
            proof
        };
        if let Some(n) = lock_critical(&self.node, "node")?.as_mut() {
            n.queue_proof(proof);
            crate::diag::diag_eprintln!(
                "AVAILABILITY a batch is available: its proof waits for this node's next block"
            );
        }
        Ok(())
    }

    /// Gives the requests of the decided blocks to a sequencer.
    pub fn set_sink(&self, sink: OutputSink) {
        *lock_or_recover(&self.sink, "sink") = Some(sink);
    }

    /// Registers a callback invoked after all requests of each decided block are handed to [`OutputSink`].
    pub fn set_block_end_sink(&self, sink: BlockEndSink) {
        *lock_or_recover(&self.block_end_sink, "block_end_sink") = Some(sink);
    }

    /// What the node reported: printed, persisted to `ord_*` when attached, and the blocks that left the orderer go to the output stage.
    pub(super) fn after_events(
        &self,
        events: Vec<canton_bft_orderer::node::Event>,
    ) -> Result<(), String> {
        use prost::Message as _;
        {
            let mut output = self.lock_output()?;
            for e in &events {
                if let canton_bft_orderer::node::Event::BlockOutput {
                    epoch,
                    block,
                    bft_time_micros,
                    is_last_in_epoch,
                    batches,
                    original_leader,
                    ..
                } = e
                {
                    output.waiting.push_back((
                        *epoch,
                        *block,
                        *bft_time_micros,
                        *is_last_in_epoch,
                        original_leader.clone(),
                        batches.clone(),
                    ));
                }
            }
        }
        let ord_store = lock_critical(&self.ord_store, "ord_store")?.clone();
        if let Some(store) = ord_store {
            let nodes_count = lock_or_recover(&self.nodes, "nodes").len().max(1) as i64;
            let epoch_length = self.epoch_length.unwrap_or(10 * nodes_count);
            for e in &events {
                match e {
                    canton_bft_orderer::node::Event::EpochStarted { epoch, start_block } => {
                        let write_epoch = {
                            let mut s =
                                lock_critical(&self.saved_epoch_started, "saved_epoch_started")?;
                            if *epoch > *s {
                                *s = *epoch;
                                true
                            } else {
                                false
                            }
                        };
                        if write_epoch {
                            if *epoch > 0 {
                                store.complete_epoch(*epoch - 1);
                            }
                            store.start_epoch(crate::ord_store::OrdEpoch {
                                epoch_number: *epoch,
                                start_block_number: *start_block,
                                epoch_length,
                                topology_ts: self.now().1,
                                in_progress: true,
                            });
                        }
                    }
                    canton_bft_orderer::node::Event::BlockOrdered { epoch, block, .. } => {
                        let mut cache = lock_or_recover(&self.recent_pbft, "recent_pbft");
                        if let Some(msgs) = cache.get(block) {
                            for m in msgs {
                                if let Some((_, _, _, disc)) = pbft_discriminator(m) {
                                    if matches!(disc, 0 | 2) {
                                        store.save_pbft_completed(
                                            *block,
                                            *epoch,
                                            disc,
                                            m.from.clone(),
                                            m.encode_to_vec(),
                                        );
                                    }
                                }
                            }
                        }
                        let keep_from = block.saturating_sub(200);
                        cache.retain(|b, _| *b >= keep_from);
                    }
                    _ => {}
                }
            }
        }
        report(events);
        self.release_output()
    }

    /// Lets the blocks out in the order of their numbers once every batch they name is here; a batch that is not is asked for from a node that acked it
    /// (`BatchRequest`), again after a few seconds if nobody answered. The number of requests of a block is the number of requests in its batches.
    pub fn release_output(&self) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            availability_message, AvailabilityMessage, BatchRequest,
        };
        loop {
            let front = self.lock_output()?.waiting.front().cloned();
            let Some((epoch, block, block_time, is_last_in_epoch, leader, batches)) = front else {
                return Ok(());
            };
            let mut requests = 0usize;
            let mut missing = Vec::new();
            {
                let stored = lock_or_recover(&self.batches, "batches");
                for b in &batches {
                    match stored.get(&b.id) {
                        Some(batch) => requests += batch.ordering_requests.len(),
                        None => missing.push(b.clone()),
                    }
                }
            }
            let already_restored = self
                .lock_output()?
                .restored_last_output_block
                .is_some_and(|last| block <= last);
            if !missing.is_empty() && !already_restored {
                for b in missing {
                    let due = {
                        let mut o = self.lock_output()?;
                        let now = std::time::Instant::now();
                        let due = o
                            .asked
                            .get(&b.id)
                            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(3));
                        if due {
                            o.asked.insert(b.id.clone(), now);
                        }
                        due
                    };
                    if !due {
                        continue;
                    }
                    // one of the nodes that acked the batch, not this one; the first that has a stream
                    let target = b.ackers.iter().find(|a| {
                        **a != self.member
                            && lock_or_recover(&self.peer_senders, "peer_senders").contains_key(*a)
                    });
                    match target {
                        Some(node) => {
                            self.send_availability(
                                node,
                                AvailabilityMessage {
                                    message: Some(availability_message::Message::BatchRequest(
                                        BatchRequest {
                                            batch_id: b.id.clone(),
                                            epoch_number: b.epoch,
                                        },
                                    )),
                                },
                            );
                            crate::diag::diag_eprintln!(
                                "OUTPUT asked {node} for a batch of block {block}"
                            );
                        }
                        None => crate::diag::diag_eprintln!(
                            "OUTPUT no node to ask for a batch of block {block}"
                        ),
                    }
                }
                return Ok(());
            }
            self.lock_output()?.waiting.pop_front();
            // the block's batches are ordered: they no longer count against the quota of the peers that had them stored
            {
                let mut quota = lock_or_recover(&self.store_quota, "store_quota");
                for ids in quota.values_mut() {
                    for b in &batches {
                        ids.remove(&b.id);
                    }
                }
            }
            // the requests of the block in order (the batches in the order of the proofs, the requests in a batch in order): each gets the block's BFT time plus its
            // index in the block, a microsecond apart (`OutputModule.blockDataToOrderedRequests`, `BftTime.requestBftTime`); the tag says what the body is
            let mut to_sink: Vec<OutputRequest> = Vec::new();
            let mut block_alters_topology = false;
            let mut block_latest_topo_ts: Option<i64> = None;
            {
                let stored = lock_or_recover(&self.batches, "batches");
                // [CANTON-NOTE: SEMANTICS] The `send` requests of a block are a microsecond apart from the block's time on: the k-th `send` gets the block time plus k.
                // An acknowledgement does not take a slot: measured against the official nodes (a block of `[acknowledge, send]` gives the send the block's time itself,
                // not one microsecond more), the source of that rule is not found yet (`OutputModule.blockDataToOrderedRequests` counts every request).
                // (for the study of the order the official nodes give the batches of a block: for each batch in the order of the proofs its id, its epoch, its number
                // of requests and the nodes that acked it)
                crate::diag::diag_eprintln!(
                    "OUTPUT-BATCHES block {block} leader {} {}",
                    leader.split("::").nth(1).unwrap_or(""),
                    batches
                        .iter()
                        .map(|b| format!(
                            "{}:e{}:n{}:a{}",
                            b.id.iter()
                                .take(6)
                                .map(|x| format!("{x:02x}"))
                                .collect::<String>(),
                            b.epoch,
                            stored.get(&b.id).map_or(0, |x| x.ordering_requests.len()),
                            b.ackers
                                .join("+")
                                .replace("SEQ::", "")
                                .split('+')
                                .map(|n| n.split("::").next().unwrap_or("").to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        ))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                // [CANTON-NOTE: SEMANTICS] `BlockReorderer.reordered` (it runs before the timestamps are fixed): the events of a block are sorted by (priority of their
                // request type, index in the block) -- verdicts 0, confirmation responses 1, confirmation requests 2, commitments 3, topology transactions 4, time
                // proofs 5, top-ups 6, acknowledgements 7 -- and then they get the block's time plus 0, 1, 2... in the **sorted** order. That is why an acknowledgement takes
                // no slot a send could have (it is last) and why a mediator's verdict is numbered before the participants' requests of the same block.
                let mut events: Vec<(u8, usize, usize, &str, &Vec<u8>)> = Vec::new();
                let mut index = 0usize;
                for (batch_position, b) in batches.iter().enumerate() {
                    let Some(batch) = stored.get(&b.id) else {
                        continue;
                    };
                    for r in &batch.ordering_requests {
                        let priority = match r.tag.as_str() {
                            "send" => {
                                crate::sequencing::submission_priority(&r.payload).unwrap_or(0)
                            }
                            _ => 7,
                        };
                        events.push((priority, index, batch_position, r.tag.as_str(), &r.payload));
                        index += 1;
                    }
                }
                events.sort_by_key(|e| (e.0, e.1));
                for (slot, (_, index, batch_position, tag, payload)) in
                    events.into_iter().enumerate()
                {
                    let time = canton_bft_orderer::bft_time::request_bft_time(block_time, slot);
                    if tag == "send"
                        && crate::sequencing::may_change_ordering_topology(payload, false)
                    {
                        block_alters_topology = true;
                        block_latest_topo_ts = Some(time);
                    }
                    match (tag, crate::sequencing::read_submission(payload)) {
                        ("send", Some((sender, id))) => {
                            crate::diag::diag_eprintln!("OUTPUT-REQUEST block {block} index {index} time_micros {time} send {sender} id {id} batch {batch_position}");
                        }
                        _ => {
                            crate::diag::diag_eprintln!("OUTPUT-REQUEST block {block} index {index} time_micros {time} {tag} batch {batch_position}");
                        }
                    }
                    to_sink.push(OutputRequest {
                        block,
                        time_micros: time,
                        tag: tag.to_string(),
                        body: payload.clone(),
                        orderer: leader.clone(),
                    });
                }
            }
            let (already_output, epoch_could_alter, tick_topology, tick_at_least) = {
                let mut o = self.lock_output()?;
                let already = o
                    .restored_last_output_block
                    .is_some_and(|last| block <= last);
                if o.current_epoch != Some(epoch) {
                    o.epoch_could_alter_topology = o.pending_next_epoch_topology;
                    o.current_epoch = Some(epoch);
                }
                if block_alters_topology {
                    o.epoch_could_alter_topology = true;
                }
                if let Some(ts) = block_latest_topo_ts {
                    o.latest_topology_tx_ts = Some(ts);
                }
                let could_alter = o.epoch_could_alter_topology;
                let tick_topology = is_last_in_epoch && could_alter;
                let tick_at_least = tick_topology.then(|| {
                    canton_bft_orderer::bft_time::epoch_end_bft_time(block_time, requests)
                });
                if !already {
                    o.latest_output = Some((epoch, block, block_time));
                }
                (already, could_alter, tick_topology, tick_at_least)
            };
            crate::diag::diag_eprintln!(
                "OUTPUT-READY block {block} epoch {epoch} requests {requests} is_last_in_epoch {is_last_in_epoch} could_alter_topology {epoch_could_alter} tick_topology {tick_topology}"
            );
            if !already_output {
                let ord_store = lock_critical(&self.ord_store, "ord_store")?.clone();
                if let Some(store) = ord_store {
                    store.save_output_block(epoch, block, block_time);
                    if is_last_in_epoch || block_alters_topology {
                        store.save_output_epoch(epoch, epoch_could_alter);
                    }
                }
                let store_path = lock_critical(&self.store, "store")?
                    .as_ref()
                    .map(|(p, _, _)| p.clone());
                if let Some(path) = store_path {
                    let out_tmp = path.with_extension("output.tmp");
                    if std::fs::write(&out_tmp, format!("{block} {block_time}\n")).is_ok() {
                        let _ = std::fs::rename(&out_tmp, path.with_extension("output"));
                    }
                    if is_last_in_epoch {
                        use std::io::Write as _;
                        if let Ok(mut bf) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path.with_extension("output_boundary"))
                        {
                            let _ = writeln!(bf, "{block} {block_time}");
                        }
                    }
                    if is_last_in_epoch || block_alters_topology {
                        let ep_tmp = path.with_extension("output_epoch.tmp");
                        if std::fs::write(&ep_tmp, format!("{epoch} {epoch_could_alter}\n")).is_ok()
                        {
                            let _ = std::fs::rename(&ep_tmp, path.with_extension("output_epoch"));
                        }
                    }
                }
                // the sequencer, if this node has one, takes the requests in the order of the block (the locks above are let go: it may take its time)
                let sink = lock_or_recover(&self.sink, "sink").clone();
                if let Some(sink) = sink {
                    for request in to_sink {
                        sink(request);
                    }
                }
                let end_sink = lock_or_recover(&self.block_end_sink, "block_end_sink").clone();
                let has_pending = match end_sink {
                    Some(end_sink) => end_sink(block, block_time, tick_at_least),
                    None => match tick_at_least {
                        Some(epoch_end) => {
                            let out = self.lock_output()?;
                            out.latest_topology_tx_ts.is_some_and(|tx| {
                                tx + crate::synchronizer_state::TOPOLOGY_CHANGE_DELAY_MICROS
                                    > epoch_end
                            })
                        }
                        None => false,
                    },
                };
                if is_last_in_epoch {
                    self.lock_output()?.pending_next_epoch_topology =
                        if tick_topology { has_pending } else { false };
                }
            } else if is_last_in_epoch {
                self.lock_output()?.pending_next_epoch_topology = false;
            }
        }
    }

    /// A `BatchResponse` of a peer: the batch, if its id is the hash of its content, is kept, and the output moves on.
    pub fn on_batch_response(
        &self,
        response: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::BatchResponse,
    ) -> Result<(), String> {
        use canton_bft_orderer::availability::{batch_id, BatchId, Request as BatchRequest};
        let Some(batch) = response.batch else {
            return Ok(());
        };
        let requests: Vec<BatchRequest> = batch
            .ordering_requests
            .iter()
            .map(|r| BatchRequest {
                tag: r.tag.clone(),
                payload: r.payload.clone(),
            })
            .collect();
        let Ok(computed) = batch_id(
            &requests,
            batch.epoch_number,
            crate::PROTOCOL_VERSION as u32,
        ) else {
            return Ok(());
        };
        if BatchId::from_proto(&response.batch_id).ok().as_ref() != Some(&computed) {
            crate::diag::diag_eprintln!(
                "OUTPUT a batch response whose id does not match its content"
            );
            return Ok(());
        }
        lock_or_recover(&self.batches, "batches").insert(computed.0.clone(), batch.clone());
        self.save_batch_to_ord(&computed.0, batch.epoch_number, &batch)?;
        self.release_output()
    }

    /// Remembers the stream to a peer, by the identity the peer gave in its answer headers.
    pub fn register_peer(
        &self,
        member: &str,
        sender: tokio::sync::mpsc::Sender<BftOrderingMessage>,
    ) {
        let mut peers = lock_or_recover(&self.peer_senders, "peer_senders");
        peers.retain(|_, s| !s.is_closed());
        peers.insert(member.to_string(), sender);
    }

    /// A `StoreRequest` of a peer (its signature checked by the caller): the node checks the batch id, stores the batch and answers with its signed ack
    /// (`AvailabilityModule.handleRemoteProtocolMessage`, `StoreRequest`). The answer goes to the peer that asked.
    pub fn on_store_request(
        &self,
        from: &str,
        request: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::StoreRequest,
    ) -> Result<(), String> {
        use canton_bft_orderer::availability::{batch_id, sign_ack, BatchId, Request as BatchRequest};
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            availability_message, bft_ordering_message_body::Message, AvailabilityMessage, BftOrderingMessageBody, StoreResponse,
        };
        use prost::Message as _;
        let Some(batch) = request.batch else {
            return Ok(());
        };
        let requests: Vec<BatchRequest> = batch
            .ordering_requests
            .iter()
            .map(|r| BatchRequest {
                tag: r.tag.clone(),
                payload: r.payload.clone(),
            })
            .collect();
        let Ok(computed) = batch_id(
            &requests,
            batch.epoch_number,
            crate::PROTOCOL_VERSION as u32,
        ) else {
            return Ok(());
        };
        // a batch whose id is not the hash of its content is refused (`BatchId` check of the official module)
        if BatchId::from_proto(&request.batch_id).ok().as_ref() != Some(&computed) {
            crate::diag::diag_eprintln!(
                "AVAILABILITY a store request of {from} whose batch id does not match its content"
            );
            return Ok(());
        }
        let epoch = batch.epoch_number;
        {
            let mut quota = lock_or_recover(&self.store_quota, "store_quota");
            let held = quota.entry(from.to_string()).or_default();
            if !held.contains(&computed.0) && held.len() >= MAX_NON_ORDERED_BATCHES_PER_NODE {
                crate::diag::diag_eprintln!(
                    "AVAILABILITY a batch of {from} is not stored: it has {MAX_NON_ORDERED_BATCHES_PER_NODE} unordered batches here"
                );
                return Ok(());
            }
            held.insert(computed.0.clone());
        }
        lock_or_recover(&self.batches, "batches").insert(computed.0.clone(), batch.clone());
        self.save_batch_to_ord(&computed.0, epoch, &batch)?;
        let Ok(ack) = sign_ack(
            &computed,
            epoch,
            &self.member,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return Ok(());
        };
        let body = AvailabilityMessage {
            message: Some(availability_message::Message::StoreResponse(
                StoreResponse {
                    batch_id: computed.0,
                    signature: Some(ack),
                },
            )),
        };
        let evidence = canton_bft_orderer::wire::wrap_versioned(30, &body.encode_to_vec());
        let Ok(signature) = canton_bft_orderer::wire::sign_message(
            canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedAvailabilityMessage,
            &self.member,
            &evidence,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return Ok(());
        };
        let signed = SignedMessage {
            message: evidence,
            from: self.member.clone(),
            signature: Some(signature),
        };
        let message = BftOrderingMessage {
            trace_context: String::new(),
            body: Some(BftOrderingMessageBody {
                message: Some(Message::AvailabilityMessage(signed)),
            }),
            sent_by: self.member.clone(),
            sent_at: None,
        };
        let target = lock_or_recover(&self.peer_senders, "peer_senders")
            .get(from)
            .cloned();
        match target {
            Some(sender) => {
                let _ = sender.try_send(message);
                crate::diag::diag_eprintln!("AVAILABILITY stored a batch for {from} and acked it");
            }
            None => crate::diag::diag_eprintln!(
                "AVAILABILITY stored a batch for {from}, but there is no stream to answer on"
            ),
        }
        Ok(())
    }

    /// Signs an availability message and sends it to one peer (the stream this node opened to it).
    fn send_availability(
        &self,
        to: &str,
        body: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::AvailabilityMessage,
    ) -> bool {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            bft_ordering_message_body::Message, BftOrderingMessageBody,
        };
        use prost::Message as _;
        let evidence = canton_bft_orderer::wire::wrap_versioned(30, &body.encode_to_vec());
        let Ok(signature) = canton_bft_orderer::wire::sign_message(
            canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedAvailabilityMessage,
            &self.member,
            &evidence,
            &ed25519_dalek::SigningKey::from_bytes(&self.signing_seed),
            &self.fingerprint,
        ) else {
            return false;
        };
        let signed = SignedMessage {
            message: evidence,
            from: self.member.clone(),
            signature: Some(signature),
        };
        let message = BftOrderingMessage {
            trace_context: String::new(),
            body: Some(BftOrderingMessageBody {
                message: Some(Message::AvailabilityMessage(signed)),
            }),
            sent_by: self.member.clone(),
            sent_at: None,
        };
        let target = {
            let mut p = lock_or_recover(&self.peer_senders, "peer_senders");
            p.retain(|_, s| !s.is_closed());
            p.get(to).cloned()
        };
        match target {
            Some(sender) => sender.try_send(message).is_ok(),
            None => false,
        }
    }

    /// A `BatchRequest` of a peer (its output module fetches the batches of an ordered block from the nodes that acked them): the stored batch goes back
    /// (`AvailabilityModule`, `BatchRequest` → `BatchResponse`). A node that acked a batch has to serve it.
    pub fn on_batch_request(
        &self,
        from: &str,
        request: canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::BatchRequest,
    ) {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            availability_message, AvailabilityMessage, BatchResponse,
        };
        let batch = lock_or_recover(&self.batches, "batches")
            .get(&request.batch_id)
            .cloned();
        let Some(batch) = batch else {
            crate::diag::diag_eprintln!(
                "AVAILABILITY {from} asked for a batch this node does not have"
            );
            return;
        };
        let sent = self.send_availability(
            from,
            AvailabilityMessage {
                message: Some(availability_message::Message::BatchResponse(
                    BatchResponse {
                        batch_id: request.batch_id,
                        batch: Some(batch),
                    },
                )),
            },
        );
        crate::diag::diag_eprintln!("AVAILABILITY served a batch to {from}: {sent}");
    }

    pub fn is_started(&self) -> bool {
        self.node.lock().is_ok_and(|g| g.is_some())
    }

    pub fn set_nodes(&self, mut nodes: Vec<String>) {
        if !nodes.contains(&self.member) {
            nodes.push(self.member.clone());
        }
        *lock_or_recover(&self.nodes, "nodes") = nodes;
    }

    pub(super) fn now(&self) -> (u64, i64) {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as i64);
        (self.started.elapsed().as_millis() as u64, micros)
    }

    pub fn add_sender(&self, sender: tokio::sync::mpsc::Sender<BftOrderingMessage>) {
        let mut s = lock_or_recover(&self.senders, "senders");
        s.retain(|x| !x.is_closed());
        s.push(sender);
    }

    /// Sends the messages to every peer on this node's own streams.
    pub(super) fn broadcast(&self, messages: Vec<SignedMessage>) -> Result<(), String> {
        use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30::{
            bft_ordering_message_body::Message, BftOrderingMessageBody,
        };
        let senders: Vec<_> = lock_or_recover(&self.senders, "senders")
            .iter()
            .filter(|x| !x.is_closed())
            .cloned()
            .collect();
        if !messages.is_empty() && std::env::var_os("BFT_P2P_TRACE").is_some() {
            crate::diag::diag_eprintln!(
                "CONSENSUS sends {} message(s) to {} peer(s)",
                messages.len(),
                senders.len()
            );
        }
        // what was signed is written before it is sent: a restart never signs another thing for the same block
        self.remember(&messages)?;
        for signed in messages {
            for sender in &senders {
                let _ = sender.try_send(BftOrderingMessage {
                    trace_context: String::new(),
                    body: Some(BftOrderingMessageBody {
                        message: Some(Message::ConsensusMessage(signed.clone())),
                    }),
                    sent_by: self.member.clone(),
                    sent_at: None,
                });
            }
        }
        Ok(())
    }
}
