//! The mediator (G6): it registers a confirmation request, collects the participants' responses and tells the informee participants the
//! verdict.
//!
//! [CANTON-NOTE: SEMANTICS] Read from the official mediator's messages as the Rust participant decodes them (S-NET-007, S-NET-011,
//! S-NET-021, S-NET-022) and the Canton source:
//! - A confirmation request is one submission with an **`InformeeMessage`** (the informee tree and the submitting participant's signature
//!   over the tree's root hash) addressed to the mediator group alone, and a **`RootHashMessage`** for each informee participant addressed to
//!   the pair {mediator group, participant}; its **request id is the sequencing time** of that submission.
//! - Each informee participant answers with a **signed `ConfirmationResponses`** to the mediator group (the envelope's signature is the
//!   participant's over hash purpose 38 of the content): per view (by position) its local verdict and the parties it confirms for.
//! - A view's quorum is met when the weights of the parties **confirmed** reach its threshold; a party is confirmed when at least its hosting
//!   threshold of the participants that host it with confirmation permission approved. All views' quorums met is an **approval**; a
//!   participant's rejection that makes a quorum unreachable is a **`ParticipantReject`** (a `LocalMalformed` answer is a rejection for
//!   the confirming parties its sender hosts with confirmation permission, and nothing for a sender hosting none); an answer the mediator cannot read, or a request
//!   whose root hash does not match, is a **`MediatorReject`** (malformed); no answer before the response timeout is a **`MediatorReject`**
//!   (`MEDIATOR_SAYS_TX_TIMED_OUT`).
//! - The verdict is a **`ConfirmationResultMessage`** in a signed protocol message (versioned 30) addressed to the informee participants,
//!   signed by the mediator's key (hash purpose 38).
//!
//! [CANTON-NOTE: SEMANTICS] Who hosts a party is read from the synchronizer's topology store **as of the request's sequencing time**
//! (`TopologyStore::hosting_at`): only a `PartyToParticipant` with verified signatures of the namespaces that have to authorize it and the
//! next serial is there, and only from its effective time on. Responses are counted against the hosting of the request's time too.
//!
//! [CANTON-NOTE: LIMITATION] deduplication and the second `submitting_participant` rules of the official mediator
//! are not done. The pending requests are kept in memory and rebuilt after a restart by replaying the journal ([`crate::persistence`]).
use crate::onboarding::Registry;
use crate::synchronizer_state::{Hosting, SynchronizerKeys, TopologyStore};
use canton_algo::signing::PublicKey;
use canton_participant::confirmation_wire::{mediator_group, ENVELOPE_CONTENT_VERSION};
use canton_participant::reassignment_wire as rw;
use canton_participant::topology_wire as tw;
use canton_participant::view_acs::Timeouts;
use canton_participant::view_receive::{informee_views, recompute_root_hash};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    local_verdict::VerdictCode, typed_signed_protocol_message_content::SomeSignedProtocolMessage,
    verdict::SomeVerdict, ConfirmationResponses, ConfirmationResultMessage, MediatorReject,
    ParticipantReject, RejectionReason, TypedSignedProtocolMessageContent, Verdict, ViewType,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    envelope_content::SomeEnvelopeContent, EnvelopeContent,
};
use prost::Message;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

mod aggregation;
use aggregation::{Decision, LocalVote, QuorumState, ViewState};

/// The `confirmation_response_timeout` of the default parameters (30 s): how long after a request the mediator waits for the answers when
/// the synchronizer's parameters say nothing else. A request is timed out after the timeout **in force at its sequencing time**.
const RESPONSE_TIMEOUT_MICROS: i64 = 30_000_000;

/// A message the mediator has the sequencer deliver: an envelope to `to` signed by the mediator.
pub struct Outgoing {
    pub to: Vec<String>,
    pub content: Vec<u8>,
    pub signatures: Vec<Signature>,
    pub approved: bool,
}

/// One envelope of a submission as the sequencer saw it: the recipients the sender wrote, the content and the envelope's signatures.
pub type SeenEnvelope = (Vec<Vec<String>>, Vec<u8>, Vec<Signature>);

struct Pending {
    /// The kind of request (transaction, unassignment, assignment): the verdict names it.
    view_type: ViewType,
    /// Who may confirm for each party **as of the request's time**, kept from the registration: the answers are counted against the hosting
    /// of the request, whatever changed since.
    hosting: BTreeMap<String, Hosting>,
    /// How long after the request's time the answers are waited for (the parameters' `confirmation_response_timeout` at that time).
    response_timeout: i64,
    root_hash: Vec<u8>,
    informee_participants: Vec<String>,
    views: Vec<ViewState>,
    answered: BTreeSet<String>,
}

#[derive(Default)]
struct State {
    pending: BTreeMap<i64, Pending>,
    /// The requests decided or timed out, by request time, until pruned (`FinalizedResponseStore`).
    finalized: BTreeSet<i64>,
    /// The latest time the mediator processed (the clean time pruning is bounded by).
    clean: Option<i64>,
}

/// What the mediator needs to know about the synchronizer to judge a request: who the participants are (their signing keys), who hosts which
/// party, and the response timeout. The mediator that lives inside the sequencer reads it from the sequencer's own registry and topology store
/// ([`EmbeddedView`]); a mediator of its own process follows the topology it downloads and the broadcasts it is sent.
pub trait MediatorView: Send + Sync {
    /// The signing keys of `member`, if it is a member the synchronizer knows.
    fn signing_keys(&self, member: &str) -> Option<Vec<PublicKey>>;
    /// The member whose signing keys include the key with this fingerprint (to name the sender of a request that carries only a signature).
    fn member_with_key(&self, fingerprint: &str) -> Option<String>;
    /// Every participant that hosts a party at `at`, whatever its permission.
    fn hosts_at(&self, at: i64) -> BTreeMap<String, Vec<String>>;
    /// Who may confirm for each party at `at`, with the hosting threshold.
    fn hosting_at(&self, at: i64) -> BTreeMap<String, Hosting>;
    fn timeouts_at(&self, at: i64) -> Timeouts;
}

/// The view of the mediator that lives inside the sequencer: its member registry and topology store.
pub struct EmbeddedView {
    pub registry: Arc<Registry>,
    pub store: Arc<TopologyStore>,
}

impl MediatorView for EmbeddedView {
    fn signing_keys(&self, member: &str) -> Option<Vec<PublicKey>> {
        self.registry.get(member).map(|r| r.signing_keys)
    }
    fn member_with_key(&self, fingerprint: &str) -> Option<String> {
        self.registry.members().into_iter().find(|m| {
            self.registry
                .get(m)
                .is_some_and(|r| r.signing_keys.iter().any(|key| key.id == fingerprint))
        })
    }
    fn hosts_at(&self, at: i64) -> BTreeMap<String, Vec<String>> {
        self.store.hosts_at(at)
    }
    fn hosting_at(&self, at: i64) -> BTreeMap<String, Hosting> {
        self.store.hosting_at(at)
    }
    fn timeouts_at(&self, at: i64) -> Timeouts {
        self.store.timeouts_at(at)
    }
}

/// The mediator of the synchronizer.
#[derive(Clone)]
pub struct Mediator {
    /// The index of the mediator group this mediator serves (`MGR::<group>`).
    group: u32,
    physical_synchronizer_id: String,
    /// The key the mediator signs its verdicts with: the signing key its key mapping lists.
    signing: Arc<tw::Ed25519Key>,
    view: Arc<dyn MediatorView>,
    state: Arc<Mutex<State>>,
}

fn versioned_typed(typed: &TypedSignedProtocolMessageContent) -> Vec<u8> {
    tw::versioned(typed.encode_to_vec(), 30)
}

impl Mediator {
    pub fn new(
        group: u32,
        physical_synchronizer_id: String,
        keys: Arc<SynchronizerKeys>,
        registry: Arc<Registry>,
        store: Arc<TopologyStore>,
    ) -> Self {
        let signing = Arc::new(tw::Ed25519Key::from_seed(
            keys.mediator_key(group as usize).seed(),
        ));
        Self::with_view(
            group,
            physical_synchronizer_id,
            signing,
            Arc::new(EmbeddedView { registry, store }),
        )
    }

    /// A mediator that reads the synchronizer through `view` (a mediator of its own process).
    pub fn with_view(
        group: u32,
        physical_synchronizer_id: String,
        signing: Arc<tw::Ed25519Key>,
        view: Arc<dyn MediatorView>,
    ) -> Self {
        Self {
            group,
            physical_synchronizer_id,
            signing,
            view,
            state: Default::default(),
        }
    }

    /// The sequencing time of the oldest request still waiting for its verdict.
    pub fn earliest_pending(&self) -> Option<i64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .keys()
            .next()
            .copied()
    }

    /// The earliest response deadline of a pending request: it times out at the first time observed after it.
    pub fn next_deadline(&self) -> Option<i64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .iter()
            .map(|(t, p)| t + p.response_timeout)
            .min()
    }

    /// Number of confirmation requests currently awaiting quorum responses in memory.
    pub fn pending_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .len()
    }

    /// The latest time this mediator processed, once it processed any.
    pub fn clean_time(&self) -> Option<i64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clean
    }

    /// The request times of the finalized responses kept, oldest first.
    pub fn finalized_requests(&self) -> Vec<i64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .finalized
            .iter()
            .copied()
            .collect()
    }

    /// Forgets the finalized responses of requests up to `at` (inclusive, `FinalizedResponseStore.prune`); returns how many.
    pub fn prune_finalized(&self, at: i64) -> usize {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let kept = state.finalized.split_off(&(at + 1));
        std::mem::replace(&mut state.finalized, kept).len()
    }

    /// The index of the mediator group this mediator serves.
    pub fn group(&self) -> u32 {
        self.group
    }

    /// Whether this mediator serves the mediator group with the index `group` (as written in a recipient `MGR::<group>`).
    pub fn serves_group(&self, group: &str) -> bool {
        group.parse::<u32>().is_ok_and(|g| g == self.group)
    }

    /// Looks at one submission (sequenced at `time` from `sender`) and returns the messages the mediator sends because of it.
    ///
    /// [CANTON-NOTE: SEMANTICS] `sender` is empty for a mediator of its own process, which is delivered envelopes without being told who sent
    /// them (as on the official synchronizer, where the batch does not name its sender). The sender is then **read from the message and
    /// authenticated by its signature**: a request names its submitter by the signature over the root hash, and a response names its sender
    /// and must verify against that member's keys.
    ///
    /// [CANTON-NOTE: SEMANTICS] The time-outs due at `time` come first (`handleMediatorEvent`: `handleTimeouts(sequencingTimestamp)`, then
    /// the event), so an answer sequenced after its request's deadline finds the request timed out and one at the deadline still counts.
    pub fn handle(&self, time: i64, sender: &str, envelopes: &[SeenEnvelope]) -> Vec<Outgoing> {
        let mut out = self.expire(time);
        let group = mediator_group(self.group);
        // an envelope addressed to the mediator group alone (one tree of one address)
        let alone =
            |trees: &[Vec<String>]| trees.len() == 1 && trees[0].len() == 1 && trees[0][0] == group;
        // a confirmation request: the informee message to the mediator group alone, the root hash messages to the mediator and a participant
        // [CANTON-NOTE: SEMANTICS] an unassignment or assignment request is the same protocol with a `ReassignmentViewTree` in place of the
        // informee tree (`ReassignmentMediatorMessage` is a `MediatorConfirmationRequest`): the same checks, the same root hash messages
        let informee = envelopes.iter().find_map(|(trees, content, _)| {
            if alone(trees) {
                let (data, _) = tw::unversioned(content)?;
                match EnvelopeContent::decode(data.as_slice())
                    .ok()?
                    .some_envelope_content?
                {
                    SomeEnvelopeContent::InformeeMessage(m) => Some(Request::transaction(m)),
                    SomeEnvelopeContent::UnassignmentMediatorMessage(m) => {
                        Some(Request::reassignment(
                            rw::Kind::Unassignment,
                            m.tree,
                            m.submitting_participant_signature,
                        ))
                    }
                    SomeEnvelopeContent::AssignmentMediatorMessage(m) => {
                        Some(Request::reassignment(
                            rw::Kind::Assignment,
                            m.tree,
                            m.submitting_participant_signature,
                        ))
                    }
                    _ => None,
                }
            } else {
                None
            }
        });
        if let Some(message) = informee {
            // a root hash message goes to each informee participant: one tree {mediator group, participant} for each, in one envelope or
            // in one envelope per participant
            let root_hash_messages: Vec<(String, Vec<u8>)> = envelopes
                .iter()
                .flat_map(|(trees, content, _)| {
                    let root_hash = tw::unversioned(content)
                        .and_then(|(data, _)| EnvelopeContent::decode(data.as_slice()).ok())
                        .and_then(|c| c.some_envelope_content)
                        .and_then(|c| match c {
                            SomeEnvelopeContent::RootHashMessage(m) => Some(m.root_hash),
                            _ => None,
                        });
                    trees
                        .iter()
                        .filter(|t| t.len() == 2 && t.contains(&group))
                        .filter_map(|t| t.iter().find(|m| **m != group).cloned())
                        .filter_map(|p| root_hash.clone().map(|h| (p, h)))
                        .collect::<Vec<_>>()
                })
                .collect();
            let with_topology = envelopes.iter().any(|(_, content, _)| {
                canton_participant::topology_state::is_topology_broadcast(content)
            });
            out.extend(self.register(time, sender, message, &root_hash_messages, with_topology));
        }
        // a participant's responses
        for (trees, content, signatures) in envelopes {
            if alone(trees) {
                if let Some(o) = self.responses(time, sender, content, signatures) {
                    out.extend(o);
                }
            }
        }
        out
    }

    /// The messages for the requests whose response time has passed at `now`: a time-out verdict.
    pub fn expire(&self, now: i64) -> Vec<Outgoing> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.clean = Some(state.clean.map_or(now, |c| c.max(now)));
        let due: Vec<i64> = state
            .pending
            .iter()
            .filter(|(t, p)| **t + p.response_timeout < now)
            .map(|(t, _)| *t)
            .collect();
        let mut out = Vec::new();
        for request in due {
            let Some(pending) = state.pending.remove(&request) else {
                continue;
            };
            state.finalized.insert(request);
            let unresponsive: Vec<&String> = pending
                .informee_participants
                .iter()
                .filter(|p| !pending.answered.contains(*p))
                .collect();
            out.push(self.result(
                request,
                &pending,
                SomeVerdict::MediatorReject(MediatorReject {
                    reason: Some(canton_proto::google::rpc::Status {
                        code: 9,
                        message: format!(
                            "MEDIATOR_SAYS_TX_TIMED_OUT: Rejected transaction as the mediator did not receive sufficient confirmations within the expected timeframe (unresponsive: {unresponsive:?})"
                        ),
                        details: Vec::new(),
                    }),
                    is_malformed: false,
                }),
            ));
        }
        out
    }

    /// The uids that confirm for `party`: a participant's own admin party (named by its uid) is hosted by that participant alone.
    pub(super) fn hosts_of(
        hosting: &BTreeMap<String, (u32, Vec<String>)>,
        party: &str,
    ) -> (u32, Vec<String>) {
        match hosting.get(party) {
            Some((t, h)) => (*t, h.clone()),
            None => (1, vec![party.to_string()]),
        }
    }

    /// Checks a confirmation request as the official mediator does (`ConfirmationRequestAndResponseProcessor.validateRequest`, in its
    /// order) and keeps it pending, or answers at once with the rejection.
    ///
    /// [CANTON-NOTE: SEMANTICS] The checks, each read against the topology **at the request's time**:
    /// 1. the submitting participant signed the root hash (else malformed);
    /// 2. every informee is hosted by an active participant (else `MEDIATOR_INVALID_MESSAGE`, which is **not** malformed);
    /// 3. the root hash messages: none repeated for a participant, all carrying the tree's root hash, exactly one for each participant
    ///    that hosts an informee - none missing, none superfluous (else malformed);
    /// 4. every view has a quorum with a threshold of at least 1 (else malformed);
    /// 5. in every view, the confirmers that a participant may confirm for can reach every quorum's threshold (else malformed);
    /// 6. the batch carries no topology transaction besides the request (else malformed).
    fn register(
        &self,
        time: i64,
        sender: &str,
        message: (ViewType, Result<Request, String>),
        root_hash_messages: &[(String, Vec<u8>)],
        batch_has_topology: bool,
    ) -> Vec<Outgoing> {
        let (view_type, message) = message;
        let signature = match &message {
            Ok(r) => r.signature.clone(),
            Err(_) => None,
        };
        let derived;
        let sender: &str = if sender.is_empty() {
            derived = signature
                .as_ref()
                .and_then(|s| self.view.member_with_key(&s.signed_by))
                .unwrap_or_default();
            &derived
        } else {
            sender
        };
        let mut participants: Vec<String> = Vec::new();
        let mut repeated: Vec<String> = Vec::new();
        for (p, _) in root_hash_messages {
            if participants.contains(p) {
                repeated.push(p.clone());
            } else {
                participants.push(p.clone());
            }
        }
        let reject = |code: i32, message: String, is_malformed: bool| {
            let pending = Pending {
                view_type,
                response_timeout: RESPONSE_TIMEOUT_MICROS,
                hosting: BTreeMap::new(),
                root_hash: Vec::new(),
                informee_participants: participants.clone(),
                views: Vec::new(),
                answered: Default::default(),
            };
            crate::diag::diag_eprintln!("MEDIATOR rejected request {time}: {message}");
            vec![self.result(
                time,
                &pending,
                SomeVerdict::MediatorReject(MediatorReject {
                    reason: Some(canton_proto::google::rpc::Status {
                        code,
                        message,
                        details: Vec::new(),
                    }),
                    is_malformed,
                }),
            )]
        };
        let malformed = |why: &str| reject(3, format!("MEDIATOR_SAYS_MALFORMED: {why}"), true);
        let request = match message {
            Ok(r) => r,
            Err(why) => return malformed(&why),
        };
        let root_hash = request.root_hash.clone();
        // 1. the submitting participant signed the root hash
        let signed = signature.is_some_and(|s| {
            self.view.signing_keys(sender).is_some_and(|keys| {
                crate::submission_validator::verifies_on(
                    &keys,
                    &s,
                    &root_hash,
                    &self.physical_synchronizer_id,
                    time,
                )
            })
        });
        if !signed {
            return malformed(
                "the submitting participant's signature over the root hash does not verify",
            );
        }
        // 2. every informee has an active participant. A participant's own admin party (named by its uid) is hosted by that participant.
        let hosts = self.view.hosts_at(time);
        let confirmers = self.view.hosting_at(time);
        let registered = |party: &str| self.view.signing_keys(&format!("PAR::{party}")).is_some();
        let hosts_of = |party: &str| -> Vec<String> {
            match hosts.get(party) {
                Some(h) => h.clone(),
                None if registered(party) => vec![party.to_string()],
                None => Vec::new(),
            }
        };
        let informees: BTreeSet<String> = request.informees.clone();
        let unhosted: Vec<&String> = informees
            .iter()
            .filter(|party| hosts_of(party).is_empty())
            .collect();
        if !unhosted.is_empty() {
            return reject(
                9,
                format!(
                    "MEDIATOR_INVALID_MESSAGE: Received a mediator confirmation request with id {time} with some informees not being hosted by an active participant: {unhosted:?}. Rejecting request..."
                ),
                false,
            );
        }
        // 3. the root hash messages
        if !repeated.is_empty() {
            return malformed(&format!(
                "Several root hash messages for recipients: {repeated:?}"
            ));
        }
        if root_hash_messages.iter().any(|(_, h)| *h != root_hash) {
            return malformed(
                "a root hash message does not carry the root hash of the informee tree",
            );
        }
        let expected: BTreeSet<String> = informees
            .iter()
            .flat_map(|party| hosts_of(party))
            .map(|uid| format!("PAR::{uid}"))
            .collect();
        let given: BTreeSet<String> = participants.iter().cloned().collect();
        let missing: Vec<&String> = expected.difference(&given).collect();
        if !missing.is_empty() {
            return malformed(&format!(
                "Missing root hash message for informee participants: {missing:?}"
            ));
        }
        let superfluous: Vec<&String> = given.difference(&expected).collect();
        if !superfluous.is_empty() {
            return malformed(&format!(
                "Superfluous root hash message for members: {superfluous:?}"
            ));
        }
        let state = ViewStates(request.views);
        for view in &state.0 {
            // 4. the minimum threshold
            if !view.quorums.iter().any(|q| q.threshold >= 1) {
                return malformed(&format!(
                    "the transaction view at {:?} has no quorum that satisfies the minimum threshold",
                    view.position
                ));
            }
            // 5. the confirmers somebody may confirm for can reach every quorum
            let authorized = |party: &str| match confirmers.get(party) {
                Some((_, hosts)) => !hosts.is_empty(),
                None => registered(party),
            };
            let reachable = view.quorums.iter().all(|q| {
                q.confirmers
                    .iter()
                    .filter(|(party, _)| authorized(party))
                    .map(|(_, weight)| *weight)
                    .sum::<u32>()
                    >= q.threshold
            });
            if !reachable {
                return malformed(&format!(
                    "insufficient authorized confirming parties for transaction view at {:?}",
                    view.position
                ));
            }
        }
        // 6. no topology transaction in the same batch
        if batch_has_topology {
            return malformed("the request's batch also contains a topology transaction");
        }
        let pending = Pending {
            view_type,
            response_timeout: self.view.timeouts_at(time).confirmation_response_micros,
            hosting: confirmers,
            root_hash,
            informee_participants: participants.clone(),
            views: state.0,
            answered: Default::default(),
        };
        crate::diag::diag_eprintln!(
            "MEDIATOR registered {}request {time} with {} view(s) for {:?} in group {}",
            reassignment_label(view_type),
            pending.views.len(),
            pending.informee_participants,
            self.group
        );
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .insert(time, pending);
        Vec::new()
    }

    fn responses(
        &self,
        time: i64,
        sender: &str,
        content: &[u8],
        signatures: &[Signature],
    ) -> Option<Vec<Outgoing>> {
        let (typed_bytes, _) = tw::unversioned(content)?;
        let typed = TypedSignedProtocolMessageContent::decode(typed_bytes.as_slice()).ok()?;
        let Some(SomeSignedProtocolMessage::ConfirmationResponses(bytes)) =
            typed.some_signed_protocol_message
        else {
            return None;
        };
        let (data, _) = tw::unversioned(&bytes)?;
        let responses = ConfirmationResponses::decode(data.as_slice()).ok()?;
        // signed by a key the sender registered (hash purpose 38 over the envelope content)
        let mut hash = vec![0x12, 0x20];
        hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, content));
        // a mediator of its own process is not told who sent a message: the sender is the one the message names, and the signature has to
        // verify against that member's keys
        let sender: &str = if sender.is_empty() {
            &responses.sender
        } else {
            sender
        };
        let registered_keys = self.view.signing_keys(sender)?;
        let verified = signatures.iter().any(|s| {
            crate::submission_validator::verifies_on(
                &registered_keys,
                s,
                &hash,
                &self.physical_synchronizer_id,
                time,
            )
        });
        if !verified || responses.sender != sender {
            crate::diag::diag_eprintln!(
                "MEDIATOR ignored a response of {sender}: signature or sender wrong"
            );
            return None;
        }
        let uid = sender.strip_prefix("PAR::").unwrap_or(sender).to_string();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request = responses.request_id;
        let pending = state.pending.get_mut(&request)?;
        let hosting = pending.hosting.clone();
        // Only an informee participant may answer for the request's root hash.
        // Per-view/per-party duplicate responses from the same participant are ignored by
        // `ConsortiumVotingState::has_already_responded` (`ResponseAggregation.scala:186-222, 478-489`).
        if !pending.informee_participants.iter().any(|p| p == sender)
            || pending.root_hash != responses.root_hash
        {
            return None;
        }
        pending.answered.insert(sender.to_string());
        // a participant confirms only for the parties it hosts with confirmation permission (a claim for another's party counts for nothing)
        let hosted = |party: &str| match hosting.get(party) {
            Some((_, hosts)) => hosts.contains(&uid),
            None => party == uid,
        };
        for r in &responses.responses {
            let position: Vec<Vec<bool>> = r
                .view_position
                .as_ref()
                .map(|p| p.position.iter().map(|i| i.is_right.clone()).collect())
                .unwrap_or_default();
            let code = r.local_verdict.as_ref().map(|v| v.code);
            let reason = r
                .local_verdict
                .as_ref()
                .and_then(|v| v.reason.as_ref())
                .map(|s| s.message.clone())
                .unwrap_or_default();
            let vote = match code {
                c if c == Some(VerdictCode::LocalApprove as i32) => LocalVote::Approve,
                c if c == Some(VerdictCode::LocalAbstain as i32) => LocalVote::Abstain(reason),
                // [CANTON-NOTE: SEMANTICS] A malformed response is a rejection on behalf of every confirming party of the view (of every view
                // when it names no view position) that the sender hosts with confirmation permission, whatever parties it names; a sender
                // hosting none has no effect (`ResponseAggregator.validateResponse`, Canton 3.7.2). Whether the request then fails is the
                // quorum's reachability, as for any rejection (`ResponseAggregation.progressView`).
                c if c == Some(VerdictCode::LocalMalformed as i32) => LocalVote::Malformed(reason),
                _ => LocalVote::Reject(reason),
            };
            let is_malformed = matches!(vote, LocalVote::Malformed(_));
            for view in pending
                .views
                .iter_mut()
                .filter(|v| v.position == position || (is_malformed && r.view_position.is_none()))
            {
                let authorized_parties: BTreeSet<String> = if is_malformed {
                    view.quorums
                        .iter()
                        .flat_map(|q| q.confirmers.keys())
                        .filter(|party| hosted(party))
                        .cloned()
                        .collect()
                } else {
                    r.confirming_parties
                        .iter()
                        .filter(|party| hosted(party))
                        .cloned()
                        .collect()
                };
                view.apply_response(&hosting, sender, &uid, &authorized_parties, &vote);
            }
        }
        // Decides strictly from remaining view `quorums` (`threshold == 0` vs `confirmers.sum() < threshold`).
        let pending = state.pending.get(&request)?;
        if let Some(decision) = aggregation::decide(&pending.views) {
            let done = state.pending.remove(&request)?;
            state.finalized.insert(request);
            let verdict = match decision {
                Decision::Approve => SomeVerdict::Approve(()),
                Decision::Reject(reasons) => SomeVerdict::ParticipantReject(ParticipantReject {
                    reasons: reasons
                        .into_iter()
                        .map(|entry| RejectionReason {
                            parties: entry.parties,
                            reject: Some(
                                canton_proto::com::digitalasset::canton::protocol::v30::LocalVerdict {
                                    code: entry.verdict_code,
                                    reason: Some(canton_proto::google::rpc::Status {
                                        code: 9,
                                        message: entry.reason,
                                        details: Vec::new(),
                                    }),
                                },
                            ),
                            participant_id: entry.participant,
                        })
                        .collect(),
                }),
            };
            return Some(vec![self.result(request, &done, verdict)]);
        }
        Some(Vec::new())
    }

    /// The signed `ConfirmationResultMessage` for `request` to the informee participants of `pending`.
    fn result(&self, request: i64, pending: &Pending, verdict: SomeVerdict) -> Outgoing {
        let approved = matches!(verdict, SomeVerdict::Approve(_));
        let message = ConfirmationResultMessage {
            physical_synchronizer_id: self.physical_synchronizer_id.clone(),
            view_type: pending.view_type as i32,
            request_id: request,
            root_hash: pending.root_hash.clone(),
            verdict: Some(Verdict {
                some_verdict: Some(verdict),
            }),
        };
        let typed = TypedSignedProtocolMessageContent {
            some_signed_protocol_message: Some(SomeSignedProtocolMessage::ConfirmationResult(
                tw::versioned(message.encode_to_vec(), 30),
            )),
        };
        let content = versioned_typed(&typed);
        let mut hash = vec![0x12, 0x20];
        hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, &content));
        let signature = self.signing.sign_bytes(&hash);
        crate::diag::diag_eprintln!(
            "MEDIATOR verdict for {}request {request} to {:?}",
            reassignment_label(pending.view_type),
            pending.informee_participants
        );
        Outgoing {
            to: pending.informee_participants.clone(),
            content,
            signatures: vec![signature],
            approved,
        }
    }
}

/// `"reassignment (unassignment) "` etc. in the log lines, nothing for a transaction (the scripts look for `MEDIATOR verdict for request`).
fn reassignment_label(view_type: ViewType) -> &'static str {
    match view_type {
        ViewType::Unassignment => "reassignment (unassignment) ",
        ViewType::Assignment => "reassignment (assignment) ",
        _ => "",
    }
}

/// A confirmation request as the mediator checks it, whatever its kind: the root hash, the submitter's signature over it, the informees and
/// the views with their quorums.
pub struct Request {
    root_hash: Vec<u8>,
    signature: Option<Signature>,
    informees: BTreeSet<String>,
    views: Vec<ViewState>,
}

impl Request {
    /// An `InformeeMessage`: the informee tree's views.
    fn transaction(
        message: canton_proto::com::digitalasset::canton::protocol::v30::InformeeMessage,
    ) -> (ViewType, Result<Request, String>) {
        let read = || {
            let tree = message
                .full_informee_tree
                .and_then(|t| t.tree)
                .ok_or("no informee tree")?;
            let root_hash =
                recompute_root_hash(&tree).map_err(|_| "the informee tree does not hash")?;
            let views =
                informee_views(&tree).map_err(|_| "the informee tree's views cannot be read")?;
            Ok(Request {
                root_hash,
                signature: message.submitting_participant_signature,
                informees: views
                    .iter()
                    .flat_map(|(_, common)| common.informees.iter().cloned())
                    .collect(),
                views: ViewStates::from(&views).0,
            })
        };
        (ViewType::Transaction, read())
    }

    /// An `UnassignmentMediatorMessage` or `AssignmentMediatorMessage`: one view at the root position.
    ///
    /// [CANTON-NOTE: SEMANTICS] `ReassignmentMediatorMessage.informeesAndConfirmationParamsByViewPosition`: the confirming parties
    /// (signatories and the submitting participant's admin party) with weight 1, the other stakeholders with weight 0, threshold = the number
    /// of confirming parties; the view position is `ViewPosition.root` (empty).
    fn reassignment(
        kind: rw::Kind,
        tree: Option<canton_proto::com::digitalasset::canton::protocol::v30::ReassignmentViewTree>,
        signature: Option<Signature>,
    ) -> (ViewType, Result<Request, String>) {
        let view_type = match kind {
            rw::Kind::Unassignment => ViewType::Unassignment,
            rw::Kind::Assignment => ViewType::Assignment,
        };
        let read = || {
            let tree = tree.ok_or("no reassignment tree")?;
            let common = rw::read_tree(kind, &tree)
                .map_err(|e| format!("the reassignment tree cannot be read: {e}"))?;
            let confirming = common.confirming_parties();
            let quorum = QuorumState::new(
                confirming.iter().map(|p| (p.clone(), 1)),
                confirming.len() as u32,
            );
            let informees: BTreeSet<String> = confirming
                .into_iter()
                .chain(common.non_confirming_parties())
                .collect();
            Ok(Request {
                root_hash: common.root_hash,
                signature,
                informees,
                views: vec![ViewState {
                    position: Vec::new(),
                    quorums: vec![quorum],
                    consortium_voting: BTreeMap::new(),
                    rejections: Vec::new(),
                }],
            })
        };
        (view_type, read())
    }
}

struct ViewStates(Vec<ViewState>);

impl ViewStates {
    fn from(
        views: &[(
            Vec<Vec<bool>>,
            canton_proto::com::digitalasset::canton::protocol::v30::ViewCommonData,
        )],
    ) -> Self {
        Self(
            views
                .iter()
                .map(|(position, common)| ViewState {
                    position: position.clone(),
                    quorums: common
                        .quorums
                        .iter()
                        .map(|q| {
                            QuorumState::new(
                                q.party_index_and_weight.iter().filter_map(|m| {
                                    Some((
                                        common.informees.get(m.index as usize)?.clone(),
                                        m.weight.max(0) as u32,
                                    ))
                                }),
                                q.threshold.max(0) as u32,
                            )
                        })
                        .collect(),
                    consortium_voting: BTreeMap::new(),
                    rejections: Vec::new(),
                })
                .collect(),
        )
    }
}

const _: i32 = ENVELOPE_CONTENT_VERSION;

#[cfg(test)]
mod tests;
