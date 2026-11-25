//! A submission gets its place in the order: `SendAsync` answers it after the checks at the estimated sequencing time, and once it has its
//! time it is checked again at that time and made into events (delivered, answered with an error, or dropped).
use super::{
    advance_clock_to, error_info, now_micros, short_psid, wall_micros, Sequencer, StoredEnvelope,
    StoredEvent,
};
use crate::submission::{flatten_tree_members, trees_for_member, Submission};
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use std::collections::BTreeMap;
use tonic::Status;

impl Sequencer {
    /// Checks a submission; with `sequence` it also gives it its place in the order.
    ///
    /// [CANTON-NOTE: SEMANTICS] What the official sequencer answers a submission it refuses (measured against 3.7.2, S-NET-038 part 3; the
    /// texts are the node's, so a client that reads them reads the same): a request that does not decode, has an envelope without recipients,
    /// more than 10 000 recipients in a tree, or an envelope that decompresses past `max_request_size` is **`INVALID_ARGUMENT`
    /// `SEQUENCER_SUBMISSION_REQUEST_MALFORMED`**; a sender that is not the authenticated member, a signature that does not verify, or
    /// several mediator groups in one batch is **`FAILED_PRECONDITION` `SEQUENCER_SUBMISSION_REQUEST_REFUSED`**; a recipient that is
    /// not a registered member is `FAILED_PRECONDITION` `SEQUENCER_UNKNOWN_RECIPIENTS`; a maximum sequencing time that has passed is
    /// `ABORTED` `MAX_SEQUENCING_TIME_EXCEEDED`. All of them are answers of `SendAsync` itself. An envelope **without content** is accepted.
    pub(super) fn submit_checked(
        &self,
        member: &str,
        signed_request: &[u8],
        sequence: bool,
    ) -> Result<(), Status> {
        self.submit_checked_at(member, signed_request, sequence, None)
    }

    /// The same, with the sequencing time given (`at`: what the BFT orderer decided, `BftTime.requestBftTime`) instead of the node's clock: every sequencer of the
    /// synchronizer then gives a submission the same time.
    pub(super) fn submit_checked_at(
        &self,
        member: &str,
        signed_request: &[u8],
        sequence: bool,
        at: Option<i64>,
    ) -> Result<(), Status> {
        // a submission the ordering cluster already admitted is not refused for what was true when it arrived (its time may have passed
        // while it waited): it is checked again at its sequencing time
        let admitted = sequence && (self.inner.ordering.get().is_some() || at.is_some());
        if !admitted {
            self.answer_send_async(member, signed_request)?;
        }
        if sequence {
            self.sequence_submission(member, signed_request, at)?;
        }
        Ok(())
    }

    /// What this sequencer knows at the time `at`.
    pub(super) fn snapshot_at<'a>(
        &'a self,
        at: i64,
        serves_group: &'a dyn Fn(&str) -> bool,
    ) -> crate::submission_validator::Snapshot<'a> {
        crate::submission_validator::Snapshot {
            at,
            physical: &self.inner.physical_synchronizer_id,
            registry: &self.inner.registry,
            store: &self.inner.store,
            self_member: self.inner.self_member.get().map(String::as_str),
            serves_group,
        }
    }

    /// The checks `SendAsync` answers, at the estimated sequencing time (now), and the traffic the submission has to pay.
    pub(super) fn answer_send_async(
        &self,
        member: &str,
        signed_request: &[u8],
    ) -> Result<(), Status> {
        use crate::submission_validator::{validate, Invalid, Scope};
        let now = wall_micros();
        let submission =
            Submission::parse(signed_request, self.inner.store.max_request_size_at(now))?;
        let serves_group = |_: &str| true;
        let checked = validate(
            &submission,
            member,
            &self.snapshot_at(now, &serves_group),
            Scope::SendAsync,
        );
        // who sent it is settled before anything else is said about it
        if let Err(
            why @ (Invalid::NotTheSender { .. } | Invalid::SenderUnknown | Invalid::Signature),
        ) = &checked
        {
            return Err(why.send_async_status(&submission, member, now));
        }
        // [CANTON-NOTE: SEMANTICS] Once the announced upgrade time has passed, this synchronizer takes no more submissions (measured on the
        // official sequencer, `ORACLE_LSU_AFTER`): `FAILED_PRECONDITION` `SEQUENCER_SUBMISSION_AFTER_UPGRADE_TIME`, naming as the sequencing time
        // the end of the upgrade's time offset (upgrade time + decision timeout) when that is later than now.
        if let Some(lsu) = self.inner.store.announced_upgrade() {
            if now > lsu.upgrade_micros {
                let end = lsu.upgrade_micros + self.upgrade_offset(lsu.upgrade_micros);
                return Err(Status::failed_precondition(format!(
                    "SEQUENCER_SUBMISSION_AFTER_UPGRADE_TIME(9,0): Submission request was refused because the sequencer can no longer accept transactions on {} as sequencing time of {} exceeds the upgrade time of {}",
                    short_psid(&self.inner.physical_synchronizer_id),
                    canton_participant::topology_state::iso_utc(now.max(end) + 1),
                    canton_participant::topology_state::iso_utc(lsu.upgrade_micros)
                )));
            }
        }
        checked.map_err(|why| why.send_async_status(&submission, member, now))?;
        self.inner.confirmation_rates.check(
            &submission,
            self.inner.store.confirmation_requests_max_rate(),
        )?;
        // traffic control, when the parameters in force turn it on: the submission pays its cost
        self.pay(&submission, member, now, false)?;
        Ok(())
    }

    /// Gives a submission its place in the order at `at` (the orderer's time; the node's clock when `None`) and makes its events: the
    /// checks at that time decide whether it is delivered, answered with an error event, or dropped.
    pub(super) fn sequence_submission(
        &self,
        member: &str,
        signed_request: &[u8],
        at: Option<i64>,
    ) -> Result<(), Status> {
        use crate::submission_validator::{validate, Scope};
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // [CANTON-NOTE: SEMANTICS] A submission the orderer decided has the time the orderer gave it; the clock moves up to it, so nothing the node sequences
        // itself later (a tick, a time proof) is before it.
        let timestamp = match at {
            Some(time) => {
                advance_clock_to(time);
                time
            }
            None => now_micros(),
        };
        let submission = Submission::parse(
            signed_request,
            self.inner.store.max_request_size_at(timestamp),
        )?;
        let external = self.mediator_routes(timestamp);
        let serves_group =
            |group: &str| match group.parse::<u32>().ok().and_then(|g| external.get(&g)) {
                Some(members) => !members.is_empty(),
                None => self.inner.mediators.iter().any(|m| m.serves_group(group)),
            };
        let snapshot = self.snapshot_at(timestamp, &serves_group);
        // [CANTON-NOTE: SEMANTICS] In BFT mode, register any onboarded participant carried inside an AllMembers topology broadcast before resolving `ALL_MEMBERS`
        // and checking the recipients, so every BFT sequencer admits the participant at the exact same block and delivers its first event with `previous = None`.
        // Only a broadcast its sender signed and that is not past its maximum sequencing time.
        if submission.sends_to_all()
            && submission.max_sequencing_time >= timestamp
            && crate::submission_validator::authenticate(&submission, member, &snapshot).is_ok()
        {
            for (trees, envelope) in submission.recipients.iter().zip(&submission.envelopes) {
                if trees.iter().flatten().any(|a| a == tw::ALL_MEMBERS) {
                    crate::onboarding::register_onboarding_in_broadcast(
                        &envelope.content,
                        &self.inner.physical_synchronizer_id,
                        &self.inner.registry,
                        self.inner.journal.get(),
                    );
                }
            }
        }
        let checked = validate(&submission, member, &snapshot, Scope::Sequenced);
        let (id, sender) = (&submission.message_id, &submission.sender);
        let mut refusal: Option<(i32, String)> = None;
        let mut threshold = None;
        match checked {
            Ok(valid) => threshold = valid.aggregation_threshold,
            Err(why) => match why.sequenced() {
                None => {
                    crate::diag::diag_eprintln!(
                        "SUBMIT dropped message {id} of {sender} at {timestamp}: {why:?}"
                    );
                    return Ok(());
                }
                Some(error) => refusal = Some(error),
            },
        }
        // [CANTON-NOTE: SEMANTICS] On a successor, before the upgrade time only time proofs (an empty batch) are sequenced; anything else is
        // dropped where it would be sequenced (`BlockUpdateGenerator.checkLsuSequencingBounds`, read from the source): `SendAsync` answers as
        // usual and the sender learns of it only when its maximum sequencing time passes.
        if let Some(upgrade) = self.inner.store.upgrade_time_here() {
            if timestamp <= upgrade && !submission.envelopes.is_empty() {
                crate::diag::diag_eprintln!(
                    "SEQUENCING_TIME_NOT_ADMISSIBLE(9,0): The sequencing time [{}] is not admissible (sequencing time is before the lower bound ({})) for message {id} of {sender}",
                    canton_participant::topology_state::iso_utc(timestamp),
                    canton_participant::topology_state::iso_utc(upgrade)
                );
                return Ok(());
            }
        }
        let paid = self.pay(&submission, member, timestamp, true)?;
        let recipients = &submission.recipients;
        let envelopes = &submission.envelopes;
        let addresses_mediator = submission.addresses_mediator();
        let _unshown = addresses_mediator.then(|| self.inner.mediator_clock.sequenced(timestamp));
        // who receives which envelope: a member named, or every member for the group of all members
        let known: Vec<String> = self.inner.registry.members();
        let resolve = |address: &str| -> Vec<String> {
            if address == tw::ALL_MEMBERS {
                known.clone()
            } else if known.iter().any(|m| m == address) {
                vec![address.to_string()]
            } else if let Some(members) = address
                .strip_prefix("MGR::")
                .and_then(|g| g.parse::<u32>().ok())
                .and_then(|g| external.get(&g))
            {
                members.clone()
            } else {
                Vec::new()
            }
        };
        let mut addressed: BTreeMap<String, Vec<StoredEnvelope>> = BTreeMap::new();
        // which envelope of the batch each stored envelope of a member is (the aggregation puts the signatures of all the senders on them)
        let mut addressed_index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, ((trees, raw_tree_list), envelope)) in recipients
            .iter()
            .zip(&submission.trees)
            .zip(envelopes)
            .enumerate()
        {
            let mut to: Vec<String> = trees.iter().flatten().flat_map(|a| resolve(a)).collect();
            to.sort();
            to.dedup();
            for m in to {
                // [CANTON-NOTE: SEMANTICS] A receiver gets the recipient subtrees computed by `RecipientsTree.forMember` with all
                // informees and descendant paths intact.
                let visible_trees = trees_for_member(raw_tree_list, &m, &resolve);
                let visible: Vec<Vec<String>> = visible_trees
                    .iter()
                    .map(|t| {
                        let mut flat = Vec::new();
                        flatten_tree_members(t, &mut flat);
                        flat
                    })
                    .collect();
                addressed_index.entry(m.clone()).or_default().push(index);
                addressed.entry(m).or_default().push(StoredEnvelope {
                    recipients: visible,
                    recipient_trees: visible_trees,
                    content: envelope.content.clone(),
                    signatures: envelope.signatures.clone(),
                });
            }
        }
        crate::diag::diag_eprintln!(
            "SUBMIT sender={member} message_id={id} max={} envelopes={:?}",
            submission.max_sequencing_time,
            recipients
                .iter()
                .zip(envelopes)
                .map(|(r, e)| format!("{r:?}:{}B:{}sigs", e.content.len(), e.signatures.len()))
                .collect::<Vec<_>>()
        );
        if let Some((_, why)) = &refusal {
            crate::diag::diag_eprintln!("SUBMIT refused: {why}");
        }
        // [CANTON-NOTE: SEMANTICS] A submission its sender signed pays its cost whether it is delivered, still aggregating or rejected
        // (`SubmissionRequestValidationResult.shouldTryToConsumeTraffic`: only a dropped one does not); one the sender cannot pay for is
        // refused instead and changes no aggregation. What was spent travels back in the sender's own event (`TrafficReceipt`).
        let mut receipt = None;
        if let Some((cost, params)) = &paid {
            if let Err((why, unpaid)) = self.afford(member, *cost, timestamp, params) {
                refusal = Some(why);
                receipt = Some(unpaid);
            }
        }
        // [CANTON-NOTE: SEMANTICS] A request with an aggregation rule is delivered once enough of the eligible senders have sent the same request
        // (`InFlightAggregationHandler`): the mediators of a group send the same verdict and the participants get it once, when the group's
        // threshold of them have sent it; a sender that sends it again, or any sender after the delivery, is refused (`SEQUENCER_AGGREGATE_SUBMISSION_ALREADY_SENT`,
        // `…_STUBBORN_SENDER`). Until the threshold is reached, the sender only gets its receipt.
        let mut aggregation_pending = false;
        let mut refusal_details: Vec<(String, Vec<u8>)> = Vec::new();
        if let (None, Some(threshold), Some(rule)) =
            (&refusal, threshold, &submission.aggregation_rule)
        {
            match self.aggregate(&submission, rule, member, threshold, timestamp) {
                None => {
                    refusal = Some((
                        9,
                        format!("SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): the aggregation id of the request from '{member}' cannot be computed"),
                    ));
                }
                Some((outcome, aggregation)) => match outcome {
                    crate::aggregation::Contribution::Pending => aggregation_pending = true,
                    crate::aggregation::Contribution::Delivered(merged) => {
                        for (m, stored) in addressed.iter_mut() {
                            for (envelope, index) in stored
                                .iter_mut()
                                .zip(addressed_index.get(m).into_iter().flatten())
                            {
                                envelope.signatures =
                                    merged.get(*index).cloned().unwrap_or_default();
                            }
                        }
                    }
                    crate::aggregation::Contribution::AlreadyDelivered { at } => {
                        // [CANTON-NOTE: SEMANTICS] The status as the official nodes build it (read off an event of theirs): gRPC `ALREADY_EXISTS`, the error id with its category
                        // and no correlation id, and an `ErrorInfo` that names the id, the error class and the message once more.
                        let cause = format!(
                        "The aggregatable request with aggregation ID {aggregation} was previously delivered at {}",
                        canton_participant::topology_state::iso_utc(at)
                    );
                        refusal = Some((
                            6,
                            format!("SEQUENCER_AGGREGATE_SUBMISSION_ALREADY_SENT(10,0): {cause}"),
                        ));
                        refusal_details = vec![(
                            "type.googleapis.com/google.rpc.ErrorInfo".to_string(),
                            error_info(
                                "SEQUENCER_AGGREGATE_SUBMISSION_ALREADY_SENT",
                                &[
                                    ("outer", "AggregateSubmissionAlreadySentV2"),
                                    ("message1", &cause),
                                    ("definite_answer", "true"),
                                    ("category", "10"),
                                ],
                            ),
                        )];
                    }
                    crate::aggregation::Contribution::Stubborn => {
                        refusal = Some((
                        9,
                        format!("SEQUENCER_AGGREGATE_SUBMISSION_STUBBORN_SENDER: The sender {member} has already contributed to the aggregation {aggregation}"),
                    ));
                    }
                },
            }
        }
        if let (None, Some((cost, params))) = (&receipt, &paid) {
            receipt = Some(self.spend(member, *cost, timestamp, params));
        }
        let expired = refusal.is_some();
        if !expired && !aggregation_pending {
            self.apply_purchases(&submission, member, timestamp);
        }
        // the sender always gets an event for its message id (a receipt, or the error); the others get the envelopes addressed to them
        let mut receivers: Vec<String> = if expired || aggregation_pending {
            Vec::new()
        } else {
            addressed.keys().cloned().collect()
        };
        if !receivers.iter().any(|m| m == member) {
            receivers.push(member.to_string());
        }
        for receiver in receivers {
            let log = events.entry(receiver.clone()).or_default();
            let previous = log.last().map(|e| e.timestamp);
            let is_sender = receiver == member;
            if std::env::var_os("BFT_SEQUENCED_TRACE").is_some() {
                // what a member's event log gets (the participant logs of the official nodes say the same: counter, time, message id, envelopes)
                let envelopes = if expired {
                    0
                } else {
                    addressed.get(&receiver).map_or(0, |v| v.len())
                };
                crate::diag::diag_eprintln!(
                    "SEQUENCED member={receiver} index={} ts={timestamp} envelopes={envelopes} message_id={}",
                    log.len(),
                    if is_sender { id.as_str() } else { "" }
                );
            }
            self.push_event(
                &receiver,
                log,
                StoredEvent {
                    timestamp,
                    previous,
                    message_id: is_sender.then(|| id.clone()),
                    envelopes: if expired || aggregation_pending {
                        Vec::new()
                    } else {
                        addressed.remove(&receiver).unwrap_or_default()
                    },
                    error: refusal.clone().filter(|_| is_sender),
                    error_details: if is_sender {
                        refusal_details.clone()
                    } else {
                        Vec::new()
                    },
                    receipt: receipt.filter(|_| is_sender),
                },
            );
        }
        drop(events);
        self.inner.news.notify_waiters();
        let sends_to_all = submission.sends_to_all();
        if !expired && !aggregation_pending {
            let mut bt = self
                .inner
                .block_ticks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !bt.initialized {
                bt.initialized = true;
                bt.last_block_ts = timestamp - 1;
            }
            bt.last_chunk_ts = bt.last_chunk_ts.max(timestamp);
            bt.latest_bft_block_ts = Some(
                bt.latest_bft_block_ts
                    .map_or(timestamp, |t| t.max(timestamp)),
            );
            if sends_to_all {
                bt.latest_pending_topology_tx_ts = Some(timestamp);
                bt.latest_topology_tx_ts = Some(timestamp);
            }
        }
        // a topology broadcast changes the synchronizer's topology state (if it is authorized) before anyone reads the state at a later time
        if !expired {
            for (trees, envelope) in recipients.iter().zip(envelopes) {
                if trees.iter().flatten().any(|a| a == tw::ALL_MEMBERS) {
                    if let Some(outcomes) = self
                        .inner
                        .store
                        .accept_broadcast(&envelope.content, timestamp)
                    {
                        for outcome in &outcomes {
                            crate::diag::diag_eprintln!("TOPOLOGY {}", outcome.note());
                        }
                        crate::membership::follow_broadcast(
                            &self.inner.registry,
                            &self.inner.store,
                            &envelope.content,
                            &outcomes,
                        );
                        self.follow_mediators();
                        self.inner.news.notify_waiters();
                    }
                }
            }
        }
        // the mediator reads what is addressed to its group; what it answers is sequenced as new events
        let seen: Vec<crate::mediator::SeenEnvelope> = recipients
            .iter()
            .zip(envelopes)
            .map(|(r, e)| (r.clone(), e.content.clone(), e.signatures.clone()))
            .collect();
        // what is addressed to a mediator group is journaled before the mediator sees it: a restart replays it to rebuild the requests in flight
        if let Some(journal) = self.inner.journal.get() {
            if addresses_mediator {
                let stored: Vec<StoredEnvelope> = seen
                    .iter()
                    .zip(&submission.trees)
                    .map(|((r, c, s), rt)| StoredEnvelope {
                        recipients: r.clone(),
                        recipient_trees: rt.clone(),
                        content: c.clone(),
                        signatures: s.clone(),
                    })
                    .collect();
                journal.write(&crate::persistence::mediator_input_line(
                    timestamp, member, &stored,
                ));
            }
        }
        // the mediators of their own processes read this as events of their own; the ones inside the sequencer run only when there are none
        // [CANTON-NOTE: INVARIANT] Only what is journaled for them: a mediator also times out what is due when it is shown a submission, and a
        // restart replays exactly the journaled inputs.
        for mediator in &self.inner.mediators {
            if !addresses_mediator || self.is_observer() || external.contains_key(&mediator.group())
            {
                continue;
            }
            for outgoing in mediator.handle(timestamp, member, &seen) {
                self.deliver(outgoing);
            }
        }
        // a submission to the group of all members is how topology changes travel (a topology broadcast): once the change takes effect, a
        // tick moves every member's clock past its effective time
        if sends_to_all {
            self.tick_after_topology_change();
        }
        Ok(())
    }

    /// `member` contributes `submission` at `timestamp` to its aggregation; the contribution is journaled. Returns what became of it and the
    /// aggregation id as the official nodes print it (`Hash.toString`: the algorithm and the first twelve hex digits).
    pub(super) fn aggregate(
        &self,
        submission: &Submission,
        rule: &canton_proto::com::digitalasset::canton::protocol::v30::AggregationRule,
        member: &str,
        threshold: usize,
        timestamp: i64,
    ) -> Option<(crate::aggregation::Contribution, String)> {
        let digest = crate::aggregation::aggregation_id(
            &submission.envelopes,
            &submission.recipient_protos,
            submission.max_sequencing_time,
            rule,
            member,
        )?;
        let printed = format!(
            "SHA-256:{}...",
            digest
                .iter()
                .take(6)
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let signatures: Vec<Vec<Signature>> = submission
            .envelopes
            .iter()
            .map(|e| e.signatures.clone())
            .collect();
        let mut aggregations = self
            .inner
            .aggregations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        aggregations.expire_before(timestamp);
        let outcome = aggregations.contribute(
            digest,
            submission.max_sequencing_time,
            member,
            signatures.clone(),
            threshold,
            timestamp,
        );
        let delivered_at = match &outcome {
            crate::aggregation::Contribution::Pending => Some(None),
            crate::aggregation::Contribution::Delivered(_) => Some(Some(timestamp)),
            _ => None,
        };
        if let (Some(delivered_at), Some(journal)) = (delivered_at, self.inner.journal.get()) {
            journal.write(&crate::aggregation::contribution_line(
                &digest,
                submission.max_sequencing_time,
                member,
                delivered_at,
                &signatures,
            ));
        }
        Some((outcome, printed))
    }

    /// Takes a journaled aggregation contribution back (no journaling).
    pub(crate) fn restore_aggregation(&self, line: &str) -> Option<()> {
        self.inner
            .aggregations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .restore(line)
    }
}
