//! View quorum and consortium voting state aggregation (`ResponseAggregation`, Canton `3.7.2`).
//!
//! [CANTON-NOTE: SEMANTICS] Aligns with `ResponseAggregation.scala` (`:109-119`, `:186-352`, `:455-502`) and `Quorum.scala` (`:25-31`):
//! - Each view maintains its remaining `confirmers` (only positive-weight parties) and remaining `threshold` per quorum.
//! - Confirming votes for a party are tracked per participant UID in [`ConsortiumVotingState`], ignoring duplicate/conflicting second
//!   votes from the same participant (`hasAlreadyResponded`).
//! - Once a party reaches full approval or full rejection, it is removed from every quorum's `confirmers` (locked out so subsequent votes
//!   from other hosts cannot un-approve or un-reject it). Full approval decrements each quorum's threshold by the party's weight; full
//!   rejection leaves the threshold unchanged.
//! - Final decision depends strictly on the remaining quorum state: all quorums at `threshold == 0` approves; any quorum where remaining
//!   confirmer weights total less than `threshold` rejects.
use canton_proto::com::digitalasset::canton::protocol::v30::local_verdict::VerdictCode;
use std::collections::{BTreeMap, BTreeSet};

/// One quorum of a view's confirmation parameters (`Quorum` in `Quorum.scala:25-31`).
#[derive(Debug, Clone)]
pub(super) struct QuorumState {
    pub confirmers: BTreeMap<String, u32>,
    pub threshold: u32,
}

impl QuorumState {
    /// Builds a quorum retaining only positive-weight confirming parties (`Quorum.confirmers: Map[LfPartyId, PositiveInt]`).
    pub fn new(members: impl IntoIterator<Item = (String, u32)>, threshold: u32) -> Self {
        let confirmers = members
            .into_iter()
            .filter(|(_, weight)| *weight > 0)
            .collect();
        Self {
            confirmers,
            threshold,
        }
    }

    pub fn is_satisfied(&self) -> bool {
        self.threshold == 0
    }

    pub fn can_be_satisfied(&self) -> bool {
        let available: u32 = self
            .confirmers
            .values()
            .copied()
            .fold(0u32, u32::saturating_add);
        self.threshold <= available
    }
}

/// Reason tuple preserved for `ParticipantReject` when a view quorum becomes unreachable.
#[derive(Debug, Clone)]
pub(super) struct RejectionEntry {
    pub parties: Vec<String>,
    pub participant: String,
    pub reason: String,
    pub verdict_code: i32,
}

/// Normalized local verdict kinds fed into [`ConsortiumVotingState`] and [`ViewState::apply_response`].
#[derive(Debug, Clone)]
pub(super) enum LocalVote {
    Approve,
    Reject(String),
    Malformed(String),
    Abstain(String),
}

impl LocalVote {
    fn kind_tag(&self) -> &'static str {
        match self {
            Self::Approve => "LocalApprove",
            Self::Reject(_) => "LocalReject",
            Self::Malformed(_) => "LocalMalformed",
            Self::Abstain(_) => "LocalAbstain",
        }
    }
}

/// Outcome of deciding a pending request from its view quorums.
pub(super) enum Decision {
    Approve,
    Reject(Vec<RejectionEntry>),
}

/// Per-party consortium voting state (`ResponseAggregation.ConsortiumVotingState`, `ResponseAggregation.scala:455-502`).
#[derive(Debug, Clone)]
pub(super) struct ConsortiumVotingState {
    threshold: u32,
    hosting_participants: BTreeSet<String>,
    approvals: BTreeSet<String>,
    /// Rejecting participant UIDs with `(participant_uid, reason, verdict_code)`, newest at front (`::`).
    rejections: Vec<(String, String, i32)>,
    abstains: BTreeSet<String>,
}

impl ConsortiumVotingState {
    pub fn for_party(hosting: &BTreeMap<String, (u32, Vec<String>)>, party: &str) -> Self {
        let (needed, hosts) = super::Mediator::hosts_of(hosting, party);
        Self {
            threshold: needed.max(1),
            hosting_participants: hosts.into_iter().collect(),
            approvals: BTreeSet::new(),
            rejections: Vec::new(),
            abstains: BTreeSet::new(),
        }
    }

    fn host_count(&self) -> u32 {
        (self.hosting_participants.len() as u32).max(1)
    }

    fn has_already_responded(&self, sender_uid: &str) -> bool {
        self.approvals.contains(sender_uid)
            || self.rejections.iter().any(|(uid, _, _)| uid == sender_uid)
            || self.abstains.contains(sender_uid)
    }

    fn previous_vote_kind(&self, sender_uid: &str) -> Option<&'static str> {
        if self.approvals.contains(sender_uid) {
            Some("LocalApprove")
        } else if self.rejections.iter().any(|(uid, _, _)| uid == sender_uid) {
            Some("LocalReject")
        } else if self.abstains.contains(sender_uid) {
            Some("LocalAbstain")
        } else {
            None
        }
    }

    /// Updates consortium voting if `sender_uid` has not already responded (`ResponseAggregation.scala:478-489`).
    pub fn update(&mut self, sender_uid: &str, party: &str, vote: &LocalVote) {
        if self.has_already_responded(sender_uid) {
            if let Some(prev) = self.previous_vote_kind(sender_uid) {
                if prev != vote.kind_tag() {
                    crate::diag::diag_eprintln!(
                        "MEDIATOR equivocation ignored: {sender_uid} already responded {prev} for {party}, ignoring {}",
                        vote.kind_tag()
                    );
                }
            }
            return;
        }
        match vote {
            LocalVote::Approve => {
                self.approvals.insert(sender_uid.to_string());
            }
            LocalVote::Reject(reason) | LocalVote::Malformed(reason) => {
                self.rejections.insert(
                    0,
                    (
                        sender_uid.to_string(),
                        reason.clone(),
                        VerdictCode::LocalReject as i32,
                    ),
                );
            }
            LocalVote::Abstain(_) => {
                self.abstains.insert(sender_uid.to_string());
            }
        }
    }

    pub fn is_approved(&self) -> bool {
        (self.approvals.len() as u32) >= self.threshold
    }

    /// [CANTON-NOTE: SEMANTICS] `ResponseAggregation.ConsortiumVotingState.isRejected` (`ResponseAggregation.scala:490-495`):
    /// rejected when `rejections >= threshold` OR remaining non-rejecting/non-abstaining hosts cannot reach `threshold`
    /// (`rejections + abstains + threshold > hosts.len()`).
    pub fn is_rejected(&self) -> bool {
        let rej = self.rejections.len() as u32;
        let abs = self.abstains.len() as u32;
        rej >= self.threshold
            || rej.saturating_add(abs).saturating_add(self.threshold) > self.host_count()
    }

    pub fn latest_reject(&self) -> Option<&(String, String, i32)> {
        self.rejections.first()
    }
}

/// Confirmation aggregation state for one view (`ResponseAggregation.ViewState`, `ResponseAggregation.scala:568-578`).
pub(super) struct ViewState {
    pub position: Vec<Vec<bool>>,
    pub quorums: Vec<QuorumState>,
    pub consortium_voting: BTreeMap<String, ConsortiumVotingState>,
    pub rejections: Vec<RejectionEntry>,
}

impl ViewState {
    pub fn quorums_satisfied(&self) -> bool {
        self.quorums.iter().all(QuorumState::is_satisfied)
    }

    pub fn quorums_can_be_satisfied(&self) -> bool {
        self.quorums.iter().all(QuorumState::can_be_satisfied)
    }

    /// Processes a response on this view (`ResponseAggregation.progressView`, `ResponseAggregation.scala:186-352`).
    pub fn apply_response(
        &mut self,
        hosting: &BTreeMap<String, (u32, Vec<String>)>,
        sender_member: &str,
        sender_uid: &str,
        authorized_parties: &BTreeSet<String>,
        vote: &LocalVote,
    ) {
        let pending_confirming: BTreeSet<String> = self
            .quorums
            .iter()
            .flat_map(|q| q.confirmers.keys().cloned())
            .collect();
        let newly_responded: BTreeSet<String> = pending_confirming
            .intersection(authorized_parties)
            .cloned()
            .collect();
        if newly_responded.is_empty() {
            return;
        }

        // Snapshot prior LocalReject reasons across all `authorized_parties` present in the view before mutating
        // `consortium_voting` (`ResponseAggregation.scala:258-261, 276-286`).
        let mut prior_rejects: BTreeMap<String, (String, String, i32)> = BTreeMap::new();
        for party in authorized_parties {
            if let Some(prev) = self
                .consortium_voting
                .get(party)
                .and_then(ConsortiumVotingState::latest_reject)
            {
                prior_rejects.insert(party.clone(), prev.clone());
            }
        }
        for party in &newly_responded {
            let state = self
                .consortium_voting
                .entry(party.clone())
                .or_insert_with(|| ConsortiumVotingState::for_party(hosting, party));
            if let Some(prev) = state.latest_reject() {
                prior_rejects.insert(party.clone(), prev.clone());
            }
            state.update(sender_uid, party, vote);
        }

        match vote {
            LocalVote::Approve => {
                let full_votes: BTreeSet<String> = newly_responded
                    .into_iter()
                    .filter(|p| {
                        self.consortium_voting
                            .get(p)
                            .is_some_and(ConsortiumVotingState::is_approved)
                    })
                    .collect();
                if !full_votes.is_empty() {
                    for quorum in &mut self.quorums {
                        let contribution: u32 = quorum
                            .confirmers
                            .iter()
                            .filter(|(p, _)| full_votes.contains(*p))
                            .map(|(_, w)| *w)
                            .fold(0u32, u32::saturating_add);
                        quorum.threshold = quorum.threshold.saturating_sub(contribution);
                        quorum.confirmers.retain(|p, _| !full_votes.contains(p));
                    }
                }
            }
            LocalVote::Reject(reason) | LocalVote::Malformed(reason) => {
                // [CANTON-NOTE: SEMANTICS] `ResponseAggregation.scala:258-261`: `newRejectionsFullVotes` filters
                // `authorizedParties`, not only `newlyResponded`, so previously rejected parties hosted by the sender are included.
                let full_rejects: BTreeSet<String> = authorized_parties
                    .iter()
                    .filter(|p| {
                        self.consortium_voting
                            .get(*p)
                            .is_some_and(ConsortiumVotingState::is_rejected)
                    })
                    .cloned()
                    .collect();
                if !full_rejects.is_empty() {
                    for quorum in &mut self.quorums {
                        quorum.confirmers.retain(|p, _| !full_rejects.contains(p));
                    }
                    let mut next = vec![RejectionEntry {
                        parties: full_rejects.into_iter().collect(),
                        participant: sender_member.to_string(),
                        reason: reason.clone(),
                        verdict_code: VerdictCode::LocalReject as i32,
                    }];
                    next.append(&mut self.rejections);
                    self.rejections = next;
                }
            }
            LocalVote::Abstain(reason) => {
                let full_rejects: BTreeSet<String> = authorized_parties
                    .iter()
                    .filter(|p| {
                        self.consortium_voting
                            .get(*p)
                            .is_some_and(ConsortiumVotingState::is_rejected)
                    })
                    .cloned()
                    .collect();
                if !full_rejects.is_empty() {
                    for quorum in &mut self.quorums {
                        quorum.confirmers.retain(|p, _| !full_rejects.contains(p));
                    }
                    // [CANTON-NOTE: SEMANTICS] `ResponseAggregation.scala:268-297`: when a `LocalAbstain` pushes a party into
                    // rejection, preserve any stronger prior `LocalReject` for that party and emit `LocalAbstain` only for parties
                    // without one.
                    let mut next_entries = Vec::new();
                    let mut without_prev = Vec::new();
                    let mut prev_entries = Vec::new();
                    for party in full_rejects {
                        if let Some((prev_uid, prev_reason, prev_code)) = prior_rejects.get(&party)
                        {
                            let participant = if prev_uid.starts_with("PAR::") {
                                prev_uid.clone()
                            } else {
                                format!("PAR::{prev_uid}")
                            };
                            prev_entries.push(RejectionEntry {
                                parties: vec![party],
                                participant,
                                reason: prev_reason.clone(),
                                verdict_code: *prev_code,
                            });
                        } else {
                            without_prev.push(party);
                        }
                    }
                    if !without_prev.is_empty() {
                        next_entries.push(RejectionEntry {
                            parties: without_prev,
                            participant: sender_member.to_string(),
                            reason: reason.clone(),
                            verdict_code: VerdictCode::LocalAbstain as i32,
                        });
                    }
                    next_entries.extend(prev_entries);
                    next_entries.append(&mut self.rejections);
                    self.rejections = next_entries;
                }
            }
        }
    }
}

/// Decides a pending request strictly from remaining view `quorums` (`threshold == 0` vs `confirmers.sum() < threshold`).
///
/// [CANTON-NOTE: SEMANTICS] `ResponseAggregation.scala:247-251, 298-303`: a single view with an unsatisfiable quorum rejects immediately;
/// approval waits until every view's quorums have reached `threshold == 0`.
pub(super) fn decide(views: &[ViewState]) -> Option<Decision> {
    if let Some(rejected) = views.iter().find(|v| !v.quorums_can_be_satisfied()) {
        return Some(Decision::Reject(rejected.rejections.clone()));
    }
    views
        .iter()
        .all(ViewState::quorums_satisfied)
        .then_some(Decision::Approve)
}
