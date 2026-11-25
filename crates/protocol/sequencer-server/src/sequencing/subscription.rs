//! A member reads the events addressed to it (`Subscribe`), as a stream that stays open for the ones that come.
use super::{wall_micros, Sequencer, StoredEvent};
use canton_participant::sequencing_wire as sw;
use canton_proto::com::digitalasset::canton::protocol::v30::RecipientsTree;
use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;
use canton_proto::com::digitalasset::canton::sequencer::api::v30::SubscriptionResponse;
use tonic::Status;

impl Sequencer {
    /// The events addressed to `member` from `from_inclusive` on, as a stream that stays open for the ones that come.
    pub fn subscribe(
        &self,
        member: String,
        from_inclusive: Option<i64>,
    ) -> tokio_stream::wrappers::ReceiverStream<Result<SubscriptionResponse, Status>> {
        self.subscribe_until(member, from_inclusive, None)
    }

    /// Like [`Self::subscribe`], for a subscription made with a token that expires at `expires_at` (wall clock, microseconds): the stream
    /// ends then with `UNAVAILABLE` (`SubscriptionPool`: `ServerSubscriptionCloseReason.TokenExpired`), and the member subscribes again
    /// with a new token.
    pub fn subscribe_until(
        &self,
        member: String,
        from_inclusive: Option<i64>,
        expires_at: Option<i64>,
    ) -> tokio_stream::wrappers::ReceiverStream<Result<SubscriptionResponse, Status>> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let this = self.clone();
        tokio::spawn(async move {
            // [CANTON-NOTE: INVARIANT] The cursor is the timestamp of the last event handed out, not a count: the running server forgets
            // acknowledged events from the front of the log (`compact_running`), and a member's timestamps only grow.
            let mut after: Option<i64> = None;
            // a member the topology disables is disconnected (`GrpcSequencerService.disconnectMember`): its stream ends
            let served = this.inner.registry.is_registered(&member);
            loop {
                let mut notified = std::pin::pin!(this.inner.news.notified());
                notified.as_mut().enable();
                if served && !this.inner.registry.is_registered(&member) {
                    return;
                }
                let pending: Vec<StoredEvent> = {
                    let events = this
                        .inner
                        .events
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    events
                        .get(&member)
                        .map(|log| {
                            // [CANTON-NOTE: WHY] Seek directly to `from_inclusive` on the initial pass so short-window
                            // pollers (`READ_SLICE`) do not scan or sign historical events on every reconnect.
                            let from = match after {
                                Some(t) => log.partition_point(|e| e.timestamp <= t),
                                None => from_inclusive
                                    .map_or(0, |t| log.partition_point(|e| e.timestamp < t)),
                            };
                            log[from..].to_vec()
                        })
                        .unwrap_or_default()
                };
                for event in pending {
                    after = Some(event.timestamp);
                    if from_inclusive.is_some_and(|t| event.timestamp < t) {
                        continue;
                    }
                    // [CANTON-NOTE: WHY] Reserve a channel slot before Zstd compression + Ed25519 signing and yield
                    // after handing the frame to tonic so frame 1 flushes promptly before short client timeouts.
                    let Ok(permit) = tx.reserve().await else {
                        return;
                    };
                    // [CANTON-NOTE: SEMANTICS] An observer starts its log when it joins: the first event it has for a member has no event before it here, but it
                    // follows the one the member last processed (the member resumes from the time after it), and the member checks the chain of previous times
                    let mut event = event;
                    if event.previous.is_none() && this.is_observer() {
                        event.previous = from_inclusive.filter(|&t| t > 0).map(|t| t - 1);
                    }
                    let bytes = this.signed_event(&event);
                    permit.send(Ok(SubscriptionResponse {
                        signed_sequenced_event: bytes,
                        // [CANTON-NOTE: SEMANTICS] the subscriber refuses a response without a trace context field set
                        // ("Failed to deserialize provided trace context: FieldNotSet(traceContext)", measured)
                        trace_context: Some(Default::default()),
                    }));
                    tokio::task::yield_now().await;
                }
                match expires_at {
                    None => notified.await,
                    Some(at) => {
                        let left = (at - wall_micros()).max(0) as u64;
                        tokio::select! {
                            () = notified => {}
                            () = tokio::time::sleep(std::time::Duration::from_micros(left)) => {
                                let _ = tx
                                    .send(Err(Status::unavailable("Subscription token has expired")))
                                    .await;
                                return;
                            }
                        }
                    }
                }
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    /// The `signed_sequenced_event` bytes of `event` for `member`.
    pub(super) fn signed_event(&self, event: &StoredEvent) -> Vec<u8> {
        let batch = sw::compressed_batch_recipient_trees(
            &event
                .envelopes
                .iter()
                .map(|e| {
                    let trees = if !e.recipient_trees.is_empty() {
                        e.recipient_trees.clone()
                    } else {
                        e.recipients
                            .iter()
                            .map(|group| RecipientsTree {
                                recipients: group.clone(),
                                children: Vec::new(),
                            })
                            .collect()
                    };
                    (trees, e.content.clone(), e.signatures.clone())
                })
                .collect::<Vec<_>>(),
        );
        let sequenced = SequencedEvent {
            previous_timestamp: event.previous,
            timestamp: event.timestamp,
            physical_synchronizer_id: self.inner.physical_synchronizer_id.clone(),
            message_id: event.message_id.clone(),
            // a delivery has a batch and no error, an error has no batch
            batch: event.error.is_none().then_some(batch),
            deliver_error_reason: event.error.as_ref().map(|(code, message)| {
                canton_proto::google::rpc::Status {
                    code: *code,
                    message: message.clone(),
                    details: event
                        .error_details
                        .iter()
                        .map(|(url, value)| prost_types::Any {
                            type_url: url.clone(),
                            value: value.clone(),
                        })
                        .collect(),
                }
            }),
            topology_timestamp: None,
            traffic_receipt: event.receipt.map(
                |(consumed_cost, extra_traffic_consumed, base_traffic_remainder)| {
                    canton_proto::com::digitalasset::canton::protocol::v30::TrafficReceipt {
                        consumed_cost,
                        extra_traffic_consumed,
                        base_traffic_remainder,
                    }
                },
            ),
        };
        sw::signed_sequenced_event(&sequenced, &self.inner.keys.sequencer_signing)
    }
}
