//! How a [`Node`] learns the fate of its own submissions: it sends them in flight, reads the sequencer's events, hands each fate to whoever
//! waits for it or keeps it for later, and asks the sequencer for the time when no event would bring a fate (P-7, P-13).
//!
//! [CANTON-NOTE: SEMANTICS] A wait has a deadline of the caller's clock; a submission's fate does not. When the wait ends first the
//! submission stays in flight (`in_flight`), and its fate, when the synchronizer's time decides it, is a [`LateFate`] with what it changed:
//! the Ledger API's `SubmissionTracker` answers the caller with `REQUEST_TIME_OUT` and the completion comes later, in the stream.
use super::{
    open_instance, stored_from, Board, LateFate, Node, PreparedCreate, RemoteTransaction,
    SharedNode, StoredContract, TreeEntry, TreeNode, Verdict, STILL_IN_FLIGHT,
};
use crate::participant_runtime::Step;
use crate::sequencer_time::TIME_PROOF_EXPIRY_MICROS;
use crate::sequencing_wire as sw;
use crate::submit::ExercisePlan;
use crate::submit::Randomness;
use crate::view_acs::Applied;
use lf_eval::Value;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

impl Node {
    /// Sends a signed submission request, kept in flight with `tag` (what the submitter needs to know about its fate after a restart) before it
    /// is sent, a caller waiting for it.
    pub(super) fn send_tagged(
        &mut self,
        message_id: &str,
        request: Vec<u8>,
        tag: &str,
    ) -> Result<(), String> {
        let max_sequencing_time =
            sw::max_sequencing_time_of(&request).ok_or("the submission request does not decode")?;
        self.runtime
            .in_flight
            .register(message_id, max_sequencing_time, tag)?;
        self.most_in_flight = self.most_in_flight.max(self.runtime.in_flight.len());
        let request = self.runtime.pay(request, &self.identity.signing_key);
        let sent = self.client.send_async(
            &self.identity.member(),
            &self.physical,
            &self.token,
            request,
        );
        if let Err(e) = sent {
            // refused before it was sequenced: it never will be
            self.runtime.in_flight.cancel(message_id)?;
            return Err(e.to_string());
        }
        Ok(())
    }

    /// Reads the sequencer's events for up to `wait` (and returns early when a fate somebody waits for arrives), answers what this node has to
    /// answer, hands every fate to its waiter on the board or keeps it as a [`LateFate`], and keeps what other participants got approved.
    pub(super) fn poll_slice(&mut self, wait: Duration) -> Result<(), String> {
        self.keep_time();
        let board = std::sync::Arc::clone(&self.board);
        let Node {
            runtime,
            client,
            token,
            identity,
            ..
        } = self;
        let mut fresh: Vec<Applied> = Vec::new();
        let mut late: Vec<(crate::in_flight::Settled, Option<Applied>)> = Vec::new();
        let outcome = runtime.poll_until(
            client,
            token,
            &identity.signing_key,
            wait,
            &mut |step: &Step| sort_step(step, &board, &mut fresh, &mut late),
        );
        let mut late_fates = Vec::new();
        for (settled, applied) in late {
            late_fates.push(LateFate {
                settled,
                transaction: applied.map(|a| self.show(a)),
            });
        }
        for applied in fresh {
            let tx = self.show(applied);
            self.remote.push(tx);
        }
        self.late.extend(late_fates);
        self.clock.observed(Instant::now(), self.runtime.cursor());
        outcome?;
        Ok(())
    }

    /// An approved transaction this node did not apply for a waiter: what it created and consumed is what this node can exercise from now
    /// on, and how it is shown.
    pub(super) fn show(&mut self, applied: Applied) -> RemoteTransaction {
        let mut created = Vec::new();
        let mut kept: Vec<StoredContract> = Vec::new();
        for (_, bytes) in &applied.created {
            if let Ok(c) = open_instance(&self.runtime.engine, bytes) {
                kept.push(stored_from(&c, bytes));
                created.push(c);
            }
        }
        for id in &applied.consumed {
            self.forget(id);
        }
        for stored in kept {
            self.remember(stored);
        }
        RemoteTransaction {
            request_id: applied.request_id,
            created,
            consumed: applied.consumed,
            reassignment: applied.reassignment,
            root_hash: applied.root_hash,
            events: applied.remote_events,
        }
    }

    /// Asks the sequencer for a time proof when a fate waits for a time no event brings, and acknowledges what was read when that is due
    /// (`sequencer_time`). A failure is the next call's to retry: neither changes what was read.
    fn keep_time(&mut self) {
        let now = Instant::now();
        let cursor = self.runtime.cursor();
        self.clock.observed(now, cursor);
        let wall = wall_micros();
        let wanted = self
            .runtime
            .in_flight
            .wanted_time(&self.runtime.config.timeouts);
        let member = self.identity.member();
        if self.clock.ask_for_time(now, wall, cursor, wanted) {
            let id = format!(
                "{}{}",
                sw::TIME_PROOF_PREFIX,
                crate::submit::uuid(&crate::submit::Os.fresh("time proof"))
            );
            let request = self.runtime.pay(
                sw::signed_time_proof_request(
                    &member,
                    &id,
                    wall.saturating_add(TIME_PROOF_EXPIRY_MICROS),
                    &self.identity.signing_key,
                ),
                &self.identity.signing_key,
            );
            // [CANTON-NOTE: SEMANTICS] A request that fails is asked again after the max sequencing delay (`TimeProofRequestSubmitter`).
            let _ = self
                .client
                .send_async(&member, &self.physical, &self.token, request);
        }
        let healthy = self.runtime.last_subscribe_error.is_none();
        if let Some(at) = self.clock.acknowledgement(now, cursor, healthy) {
            let request = sw::signed_acknowledge_request(&member, at, &self.identity.signing_key);
            // [CANTON-NOTE: SEMANTICS] `PeriodicAcknowledgements` logs a failed acknowledgement and tries again at the next interval.
            let _ = self
                .client
                .acknowledge_signed(&member, &self.physical, &self.token, request);
        }
    }

    /// Reads events until the verdict about `message_id` (sent before) is known, or `timeout` passes: then the submission stays in flight and
    /// the error starts with [`STILL_IN_FLIGHT`].
    pub(super) fn wait_for(
        &mut self,
        message_id: &str,
        timeout: Duration,
    ) -> Result<Verdict, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some((verdict, notes)) = self.board.take(message_id) {
                self.last_notes = notes;
                return Ok(verdict);
            }
            if Instant::now() >= deadline {
                let (verdict, notes) = self.give_up(message_id, timeout)?;
                self.last_notes = notes;
                return Ok(verdict);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if let Err(e) = self.poll_slice(left) {
                // the submission is in flight whatever the reading did: its fate comes later
                self.runtime.in_flight.stop_awaiting(message_id);
                return Err(format!(
                    "{STILL_IN_FLIGHT}reading the sequencer failed: {e}"
                ));
            }
        }
    }

    /// Stops waiting for `message_id`: its verdict if it came meanwhile, else an error saying it is still in flight (its fate will be a
    /// [`LateFate`]).
    pub(super) fn give_up(
        &mut self,
        message_id: &str,
        timeout: Duration,
    ) -> Result<(Verdict, Vec<String>), String> {
        if let Some(found) = self.board.take(message_id) {
            return Ok(found);
        }
        let tracked = self.runtime.in_flight.stop_awaiting(message_id);
        Err(format!(
            "{STILL_IN_FLIGHT}no verdict for {message_id} within {timeout:?}{}",
            if tracked { "" } else { " (not tracked)" }
        ))
    }

    /// The late fates read so far, handed over: they are done once taken (see [`Node::fate_handed_over`] for a taker that marks them itself).
    pub fn take_late_fates(&mut self) -> Result<Vec<LateFate>, String> {
        let fates = std::mem::take(&mut self.late);
        for fate in &fates {
            self.fate_handed_over(&fate.settled.message_id)?;
        }
        Ok(fates)
    }

    /// The late fate of `message_id` reached whoever shows it: it is not handed over again after a restart.
    pub(crate) fn fate_handed_over(&mut self, message_id: &str) -> Result<(), String> {
        self.runtime.in_flight.take_settled(message_id)
    }

    /// Makes the contracts this node can exercise the ones its contract set holds after the replay of its journal: an approval read before a
    /// restart whose contracts were not kept yet (or a consumption not forgotten yet) is caught up with here.
    ///
    /// [CANTON-NOTE: INVARIANT] The contract set's journal is written before the contracts this node keeps, so it is the one to trust.
    pub(super) fn reconcile_contracts(&mut self) {
        let replayed = self.runtime.ledger.take_replayed_instances();
        for (id, bytes) in replayed {
            if self.contracts.contains_key(&id) {
                continue;
            }
            if let Ok(c) = open_instance(&self.runtime.engine, &bytes) {
                self.remember(stored_from(&c, &bytes));
            }
        }
        let archived: Vec<String> = self
            .contracts
            .keys()
            .filter(|id| self.runtime.ledger.archived_by(id).is_some())
            .cloned()
            .collect();
        for id in archived {
            self.forget(&id);
        }
    }
}

/// An exercise submitted through a [`SharedNode`] (the arguments of [`Node::prepare_exercise_with_options`]), how long its caller waits for
/// the verdict, and its tag.
pub struct ExerciseCommand<'a> {
    pub package_name: &'a str,
    pub contract_id_hex: &'a str,
    pub choice: &'a str,
    pub argument: &'a Value,
    pub actors: &'a [String],
    /// The root choice's own observers (`ExerciseNode.choiceObservers`).
    pub observers: &'a [String],
    pub command_id: &'a str,
    pub plan: Option<ExercisePlan>,
    pub entries: &'a [TreeEntry<'a>],
    pub root_interface_id: Option<&'a str>,
    pub root_by_key: bool,
    pub root_package_id: Option<&'a str>,
    pub disclosed_instances: &'a [(String, Vec<u8>)],
    pub timeout: Duration,
    /// What the submitter needs to know about the submission's fate when it comes after the wait or after a restart (a [`LateFate`]).
    pub tag: &'a str,
    /// A classic submission, or one its external parties authorized (U-56).
    pub submission: crate::submit::Submission,
}

impl SharedNode {
    /// Like [`SharedNode::submit_prepared`], kept in flight with `tag` (see [`ExerciseCommand::tag`]).
    pub fn submit_prepared_tagged(
        &self,
        prepared: PreparedCreate,
        timeout: Duration,
        tag: &str,
    ) -> Result<(Verdict, Vec<String>), String> {
        let message_id = prepared.built.message_id.clone();
        let command_id = prepared.command_id;
        let root_hash = prepared.built.root_hash.clone();
        self.with(|n| n.send_tagged(&message_id, prepared.built.request.clone(), tag))??;
        Self::clear_approved_root_hash();
        let (verdict, notes) = self.wait(&message_id, timeout)?;
        if verdict == Verdict::Approved {
            Self::note_approved_root_hash(root_hash);
            self.with(|n| n.remember(prepared.stored))?;
        }
        self.note_awaited(&command_id, &message_id)?;
        Ok((verdict, notes))
    }

    /// Exercises a choice as [`SharedNode::submit_exercise_with_options`] does, kept in flight with the command's tag.
    pub fn submit_exercise_command(
        &self,
        command: ExerciseCommand<'_>,
    ) -> Result<(Verdict, Vec<String>), String> {
        let (built, consuming, remapped) = self.with(|n| {
            let (built, consuming, remapped) = n.prepare_exercise_with_remap(
                command.package_name,
                &super::multi_root::ExerciseRoot {
                    contract_id_hex: command.contract_id_hex,
                    choice: command.choice,
                    argument: command.argument,
                    actors: command.actors,
                    observers: command.observers,
                    entries: command.entries,
                    root_interface_id: command.root_interface_id,
                    root_by_key: command.root_by_key,
                    root_package_id: command.root_package_id,
                },
                command.command_id,
                command.plan,
                command.disclosed_instances,
                &command.submission,
            )?;
            n.send_tagged(&built.message_id, built.request.clone(), command.tag)?;
            Ok::<_, String>((built, consuming, remapped))
        })??;
        let root_hash = built.root_hash.clone();
        Self::clear_approved_root_hash();
        Self::clear_remapped_cids();
        let (verdict, notes) = self.wait(&built.message_id, command.timeout)?;
        if verdict == Verdict::Approved {
            Self::note_approved_root_hash(root_hash);
            Self::note_remapped_cids(remapped.clone());
            self.with(|n| {
                n.apply_exercise(command.contract_id_hex, consuming, built.created);
                for entry in command.entries {
                    if let TreeNode::Exercise {
                        contract_id,
                        consuming: true,
                        ..
                    } = &entry.node
                    {
                        let forget_id = remapped
                            .get(*contract_id)
                            .map(String::as_str)
                            .unwrap_or(*contract_id);
                        n.forget(forget_id);
                    }
                }
            })?;
        }
        self.note_awaited(command.command_id, &built.message_id)?;
        Ok((verdict, notes))
    }
}

/// Sorts what one event decided: a fate somebody waits for goes on the board, the others are kept late (an approval with its transaction);
/// what an approval changed goes to the waiter's caller, with its late fate, or to the transactions of others. Returns whether a waiter's fate
/// arrived.
fn sort_step(
    step: &Step,
    board: &Board,
    fresh: &mut Vec<Applied>,
    late: &mut Vec<(crate::in_flight::Settled, Option<Applied>)>,
) -> bool {
    let mut awaited_approvals = BTreeSet::new();
    let mut woke = false;
    let mut found = Vec::new();
    for settled in &step.settled {
        if settled.awaited {
            if settled.verdict == Verdict::Approved {
                board.note_approved_time(settled.request_id);
                awaited_approvals.extend(settled.request_id);
            }
            board.note_request(&settled.message_id, settled.request_id);
            board.put(&settled.message_id, settled.verdict, settled.notes.clone());
            woke = true;
        } else {
            found.push(settled.clone());
        }
    }
    for applied in &step.applied {
        if awaited_approvals.contains(&applied.request_id) {
            continue;
        }
        let owner = found.iter().position(|s| {
            s.verdict == Verdict::Approved && s.request_id == Some(applied.request_id)
        });
        match owner {
            Some(i) => late.push((found.remove(i), Some(applied.clone()))),
            None => fresh.push(applied.clone()),
        }
    }
    late.extend(found.into_iter().map(|s| (s, None)));
    woke
}

fn wall_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::super::parse_dar_package_names;
    use super::*;
    use crate::participant_runtime::{Config, Runtime};
    use crate::sequencer_connect::{SequencerConnect, Token};
    use crate::sequencer_time::TimeKeeper;
    use crate::submit::Os;
    use crate::topology_wire::{versioned, Ed25519Key, ParticipantIdentity};
    use crate::view_acs::Timeouts;
    use crate::view_conformance::Engine;
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        typed_signed_protocol_message_content::SomeSignedProtocolMessage, verdict::SomeVerdict,
        ConfirmationResultMessage, Verdict as ProtoVerdict,
    };
    use canton_proto::com::digitalasset::canton::protocol::v32::SequencedEvent;
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_service_server::{
        SequencerService, SequencerServiceServer,
    };
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
        AcknowledgeSignedRequest, AcknowledgeSignedResponse,
        DownloadTopologyStateForInitHashRequest, DownloadTopologyStateForInitHashResponse,
        DownloadTopologyStateForInitRequest, DownloadTopologyStateForInitResponse, GetTimeRequest,
        GetTimeResponse, GetTrafficStateForMemberRequest, GetTrafficStateForMemberResponse,
        SendAsyncRequest, SendAsyncResponse, SubscriptionRequest, SubscriptionResponse,
    };
    use lf_eval::World;
    use prost::Message;
    use std::collections::{BTreeMap, VecDeque};
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tonic::{Request, Response, Status};

    struct VecStream(VecDeque<Result<SubscriptionResponse, Status>>);

    impl tonic::codegen::tokio_stream::Stream for VecStream {
        type Item = Result<SubscriptionResponse, Status>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct MockSeq {
        sequencer_time: i64,
        events: Mutex<Vec<(i64, Vec<u8>)>>,
    }

    #[tonic::async_trait]
    impl SequencerService for MockSeq {
        async fn get_time(
            &self,
            _: Request<GetTimeRequest>,
        ) -> Result<Response<GetTimeResponse>, Status> {
            Ok(Response::new(GetTimeResponse {
                sequencing_timestamp: Some(self.sequencer_time),
            }))
        }

        async fn get_traffic_state_for_member(
            &self,
            _: Request<GetTrafficStateForMemberRequest>,
        ) -> Result<Response<GetTrafficStateForMemberResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn send_async(
            &self,
            _: Request<SendAsyncRequest>,
        ) -> Result<Response<SendAsyncResponse>, Status> {
            Ok(Response::new(SendAsyncResponse {}))
        }

        type SubscribeStream = VecStream;

        async fn subscribe(
            &self,
            request: Request<SubscriptionRequest>,
        ) -> Result<Response<Self::SubscribeStream>, Status> {
            let from = request.into_inner().timestamp;
            let items: VecDeque<_> = self
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|(ts, _)| from.is_none_or(|a| *ts >= a))
                .take(1)
                .map(|(_, bytes)| {
                    Ok(SubscriptionResponse {
                        signed_sequenced_event: bytes.clone(),
                        trace_context: Some(Default::default()),
                    })
                })
                .collect();
            Ok(Response::new(VecStream(items)))
        }

        async fn acknowledge_signed(
            &self,
            _: Request<AcknowledgeSignedRequest>,
        ) -> Result<Response<AcknowledgeSignedResponse>, Status> {
            Ok(Response::new(AcknowledgeSignedResponse {}))
        }

        type DownloadTopologyStateForInitStream = Pin<
            Box<
                dyn tonic::codegen::tokio_stream::Stream<
                        Item = Result<DownloadTopologyStateForInitResponse, Status>,
                    > + Send,
            >,
        >;

        async fn download_topology_state_for_init(
            &self,
            _: Request<DownloadTopologyStateForInitRequest>,
        ) -> Result<Response<Self::DownloadTopologyStateForInitStream>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn download_topology_state_for_init_hash(
            &self,
            _: Request<DownloadTopologyStateForInitHashRequest>,
        ) -> Result<Response<DownloadTopologyStateForInitHashResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
    }

    #[test]
    fn r13a_note_awaited_overflow_still_applies_approved_contract_locally() {
        let dar = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let me = ParticipantIdentity::generate("r13a-overflow");
        let med = ParticipantIdentity::generate("r13a-med");
        let seq_key = Ed25519Key::from_seed([7u8; 32]);
        let me_member = me.member();
        let erin = format!("erin::{}", me.namespace());
        let physical = "sync::1220aa".to_string();

        let engine = Engine::load(&dar).expect("load sample dar");
        let world = World::open(&dar).expect("open sample world");
        let boot_package_ids: BTreeSet<String> = world.package_ids().into_iter().collect();
        let mut package_names_by_id = BTreeMap::new();
        parse_dar_package_names(&dar, &mut package_names_by_id).expect("parse package names");

        let me_pub =
            canton_algo::member_signature::own_ed25519_key(&me.signing_key.spki_der).unwrap();
        let med_pub =
            canton_algo::member_signature::own_ed25519_key(&med.signing_key.spki_der).unwrap();

        let now = 1_700_000_000_000_000i64;
        let config = Config {
            member: me.member(),
            encryption_fingerprint: me.encryption_fingerprint(),
            encryption_secret: *me.encryption_secret(),
            hosted_parties: vec![erin.clone(), me.uid()],
            timeouts: Timeouts::default(),
            submitter_keys: vec![me_pub],
            mediator_keys: vec![med_pub],
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: physical.clone(),
            follow_topology: false,
            topology_change_delay_micros: 250_000,
        };
        let runtime = Runtime::open_in(config, engine, None, 0).expect("open runtime");

        let mock = Arc::new(MockSeq {
            sequencer_time: now,
            events: Mutex::new(Vec::new()),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let svc = Arc::clone(&mock);
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(
                    tonic::transport::Server::builder()
                        .add_service(SequencerServiceServer::from_arc(svc))
                        .serve(addr),
                )
        });
        let url = format!("http://{addr}");
        let mut client = None;
        for _ in 0..40 {
            if let Ok(c) = SequencerConnect::connect(&url) {
                client = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let client = client.expect("connect to mock sequencer");
        let token = Token {
            token: vec![1],
            expires_at_seconds: i64::MAX,
        };
        let mut node = Node {
            runtime,
            last_notes: Vec::new(),
            identity: me,
            client,
            token,
            physical: physical.clone(),
            mediator_group: 0,
            user_id: "u-overflow".to_string(),
            world,
            vetted_package_ids: boot_package_ids.clone(),
            boot_package_ids,
            package_names_by_id,
            contracts: BTreeMap::new(),
            unassigned: BTreeMap::new(),
            store: None,
            directory: BTreeMap::new(),
            board: std::sync::Arc::new(Board::default()),
            most_in_flight: 0,
            remote: Vec::new(),
            late: Vec::new(),
            clock: TimeKeeper::new(Instant::now(), 0),
        };
        let payload = Value::Record {
            tycon: Some("AssetHolding:AssetHolding".into()),
            fields: vec![
                ("bank".into(), Value::Party(erin.clone())),
                ("owner".into(), Value::Party(erin.clone())),
                ("auditor".into(), Value::Party(erin)),
                ("assetSymbol".into(), Value::Text("USD".into())),
                (
                    "amount".into(),
                    Value::Numeric {
                        coeff: 100_000_000_000,
                        scale: 10,
                    },
                ),
            ],
        };
        let prepared = node
            .prepare_create(
                "sample-contract",
                "AssetHolding:AssetHolding",
                &payload,
                "cmd-overflow",
                Some(now),
                &mut Os,
            )
            .expect("prepare create");
        let cid = prepared.built.contract_id_hex.clone();

        // Queue Event 1 (submission delivery) + Event 2 (Approved verdict signed by `med`).
        let delivery_ts = now + 100;
        let to_me: Vec<(Vec<String>, Vec<u8>)> = prepared
            .built
            .envelopes
            .iter()
            .filter(|(to, _)| to.contains(&me_member))
            .cloned()
            .collect();
        let req_event = SequencedEvent {
            previous_timestamp: None,
            timestamp: delivery_ts,
            physical_synchronizer_id: physical.clone(),
            message_id: Some(prepared.built.message_id.clone()),
            batch: Some(sw::compressed_batch_to_groups(&to_me)),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        let verdict_msg = ConfirmationResultMessage {
            physical_synchronizer_id: physical.clone(),
            view_type: 1,
            request_id: delivery_ts,
            root_hash: prepared.built.root_hash.clone(),
            verdict: Some(ProtoVerdict {
                some_verdict: Some(SomeVerdict::Approve(())),
            }),
        };
        let inner_content = versioned(
            canton_proto::com::digitalasset::canton::protocol::v30::TypedSignedProtocolMessageContent {
                some_signed_protocol_message: Some(
                    SomeSignedProtocolMessage::ConfirmationResult(versioned(
                        verdict_msg.encode_to_vec(),
                        30,
                    )),
                ),
            }
            .encode_to_vec(),
            30,
        );
        let mut digest = vec![0x12, 0x20];
        digest.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, &inner_content));
        let med_sig = med.signing_key.sign_bytes(&digest);
        let verdict_event = SequencedEvent {
            previous_timestamp: Some(delivery_ts),
            timestamp: delivery_ts + 100,
            physical_synchronizer_id: physical,
            message_id: None,
            batch: Some(sw::compressed_batch_signed(&[(
                vec![me_member],
                inner_content,
                vec![med_sig],
            )])),
            deliver_error_reason: None,
            topology_timestamp: None,
            traffic_receipt: None,
        };
        {
            let mut q = mock.events.lock().unwrap();
            q.push((
                delivery_ts,
                sw::signed_sequenced_event(&req_event, &seq_key),
            ));
            q.push((
                delivery_ts + 100,
                sw::signed_sequenced_event(&verdict_event, &seq_key),
            ));
        }

        let shared = SharedNode::new(node);
        // Fill thread-local AWAITED up to MAX_AWAITED (1024).
        for i in 0..1024 {
            shared
                .note_awaited(&format!("cmd-fill-{i}"), &format!("fill-{i}"))
                .expect("pre-fill within MAX_AWAITED");
        }
        let msg_id = prepared.built.message_id.clone();
        let res = shared.submit_prepared_tagged(prepared, Duration::from_secs(5), "overflow-tag");
        let remembered = shared.with(|n| n.contracts.contains_key(&cid)).unwrap();
        let kept_root_hash = SharedNode::take_last_approved_root_hash().is_some();
        let kept_board_req = shared.board.requests.lock().unwrap().contains_key(&msg_id);
        let _ = shared.awaited_recorded();
        let err = res.expect_err("overflow past MAX_AWAITED must return Err");
        assert!(
            err.contains("overflow"),
            "expected overflow error, got: {err}"
        );
        assert!(
            remembered,
            "approved contract {cid} must still be remembered in node.contracts even when note_awaited overflows"
        );
        assert!(
            kept_root_hash,
            "approved root_hash must still be recorded even when note_awaited overflows"
        );
        assert!(
            kept_board_req,
            "board.requests must not be popped when note_awaited rejects on overflow"
        );
    }
}
