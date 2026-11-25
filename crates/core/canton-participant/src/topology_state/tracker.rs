//! The topology as a member follows it, and the order in which a transaction is judged: the node's `TopologyStateProcessor.validateAndMerge`
//! (merge the signatures, the serial, the mapping's own checks, then the authorization) applied to one transaction at a time.
use std::collections::{BTreeMap, BTreeSet};

use super::VettedPackageEntry;

use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    DynamicSynchronizerParameters, MediatorSynchronizerState, SignedTopologyTransaction,
    TrafficControlParameters,
};
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_proto::com::digitalasset::canton::protocol::v31::TopologyTransaction;

use super::auth::{
    mapped_signing_keys, namespace_of, required_auth, restricted_to, unique_key, Authorizers, Code,
    RequiredAuth, UniqueKey,
};
use super::graph::{Authorizations, Decentralized};
use super::keys::{key_fingerprint, parse_delegation, signing_key, verifies, Delegation, Usage};
use super::psid::{Lsu, Psid};
use super::{
    decode, encryption_keys_of, learn, mapping, signing_keys_of, Entry, Learned, MemberKeys, REMOVE,
};
use crate::topology_wire as tw;
use crate::view_acs::Timeouts;

/// What became of a transaction the tracker took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It is authorized and changed the state (the note says what is in force now).
    InForce(String),
    /// A proposal that is well formed but lacks an authorization: its signatures add up over later broadcasts.
    Waiting(String),
    /// It can never take effect as it is (a serial that is not the next one, bytes that do not decode).
    Refused(String),
    /// A mapping this tracker does not follow.
    Unfollowed(String),
}

impl Outcome {
    pub fn note(&self) -> &str {
        match self {
            Outcome::InForce(n)
            | Outcome::Waiting(n)
            | Outcome::Refused(n)
            | Outcome::Unfollowed(n) => n,
        }
    }

    pub fn is_in_force(&self) -> bool {
        matches!(self, Outcome::InForce(_))
    }
}

/// Why a transaction can never take effect as it is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("a topology transaction that does not decode: {0}")]
    Malformed(String),
    /// The mapping does not parse as the node parses it (a delegation's key usage or restriction, serial 0).
    #[error("{0}")]
    InvalidMapping(String),
    /// `SerialMismatch`: the unique key has a transaction in force and this one is not exactly the next serial.
    #[error("{subject}: serial {actual} is not the next one after {in_force}")]
    SerialMismatch {
        subject: String,
        actual: u32,
        in_force: u32,
    },
    /// `SignatureCheckFailed`: a key signed for a use its usages do not allow.
    #[error("{subject}: the key {key} signed it but may not sign for that use")]
    KeyUsage { subject: String, key: String },
    #[error("The topology state of synchronizer {0} is frozen due to an announced LSU. No more topology changes are allowed until upgrade completion.")]
    Frozen(String),
    /// A rule of the mapping itself (`TopologyMappingChecks`), with the node's text.
    #[error("{0}")]
    Check(String),
    /// `NotAuthorized`: a transaction that is not a proposal has to be fully authorized when it is taken
    /// (`TopologyStateProcessor`: `expectFullAuthorization || !tx.isProposal`).
    #[error("{0}")]
    NotAuthorized(String),
}

impl From<Refusal> for Outcome {
    fn from(r: Refusal) -> Outcome {
        Outcome::Refused(r.to_string())
    }
}

/// A transaction the tracker took: what became of it, and the transaction with **every verified signature seen for it so far** (the
/// signatures of one transaction arrive in separate broadcasts; a store keeps the merged form once it is in force). `merged` is `None`
/// when there is nothing to keep: the bytes did not decode, or the transaction is the one already in force, broadcast again.
#[derive(Debug, Clone)]
pub struct Applied {
    pub outcome: Outcome,
    pub merged: Option<SignedTopologyTransaction>,
}

/// The topology as the participant follows it: the state it downloaded when it joined, then every transaction the synchronizer
/// broadcast since, accepted **only when it is authorized**.
///
/// [CANTON-NOTE: SEMANTICS] A download returns the state **as of the member's onboarding**; what is authorized afterwards (a party
/// is hosted, a hosting changes) reaches a participant only as `TopologyTransactionsBroadcast` envelopes in its event stream (a
/// party hosted by a participant *after* it joined was absent from every later download, measured). The signatures of one transaction
/// arrive in **separate broadcasts** (the proposer's, then each co-signer's) and are merged by the transaction's hash.
///
/// A transaction is judged in the node's order: its serial (exactly the next one after the transaction in force for its unique key,
/// a REMOVE included), the mapping's own checks, then its authorization: the namespaces and keys [`super::required_auth`] names, each
/// namespace through its own authorization graph and only by keys whose delegation may sign the mapping's code.
pub struct Tracker {
    pub(super) me_uid: String,
    pub(super) auth: Authorizations,
    /// Unique key -> the transaction in force for it (a REMOVE included) and its hash: what the next serial follows, what
    /// `requiredAuth` compares with, and what a later signature of the same transaction merges into.
    pub(super) head: BTreeMap<UniqueKey, (TopologyTransaction, Vec<u8>)>,
    /// Transaction hash -> the transaction and its verified signatures by signing key, until it is in force.
    pending: BTreeMap<Vec<u8>, (TopologyTransaction, BTreeMap<String, Signature>)>,
    /// Party -> (serial in force, hosting participants with their permission).
    pub(super) parties: BTreeMap<String, (u32, Vec<(String, i32)>)>,
    /// Party -> the hosting threshold in force (how many of the confirming hosts have to approve for the party).
    pub(super) party_thresholds: BTreeMap<String, u32>,
    /// The physical synchronizer this tracker follows (what an upgrade announcement is checked against), when known.
    pub(super) current_psid: Option<Psid>,
    /// The upgrade announced for the synchronizer, if any.
    pub(super) lsu: Option<Lsu>,
    /// While a batch (one broadcast) is applied: the announcement as it was before the batch. The checks of a mapping read the state the
    /// batch started from, not what earlier transactions of the same batch changed (see [`Tracker::begin_batch`]).
    batch_lsu: Option<Option<Lsu>>,
    /// Member (`PAR::...`, `MED::...`) -> (serial in force, its Ed25519 signing keys, its P-256 encryption keys).
    pub(super) members: BTreeMap<String, MemberKeys>,
    /// The serial of the synchronizer parameters in force (`None` when none were seen).
    pub(super) params_serial: Option<u32>,
    pub(super) parameters: Option<DynamicSynchronizerParameters>,
    /// Static synchronizer crypto specs & topology limits from `GetSynchronizerParameters`, when fetched (`T-12`).
    pub(super) crypto_specs: Option<crate::crypto_handshake::Required>,
    pub(super) vetted_packages: BTreeMap<String, BTreeSet<String>>,
    pub(super) vetted_package_windows: BTreeMap<String, Vec<VettedPackageEntry>>,
    /// Mediator group -> the `MediatorSynchronizerState` in force for it.
    pub(super) mediator_groups: BTreeMap<u32, MediatorGroup>,
    /// The `SequencerSynchronizerState` in force, if any.
    pub(super) sequencer_group: Option<SequencerGroup>,
    pub(super) base: Learned,
}

/// A mediator group as the synchronizer's `MediatorSynchronizerState` names it: the members are **uids** (`name::namespace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatorGroup {
    pub serial: u32,
    pub threshold: u32,
    pub active: Vec<String>,
    pub observers: Vec<String>,
}

impl MediatorGroup {
    /// Whether this mediator group can actively finalize confirmations (`Member.scala:633`: `active.size >= threshold` and `threshold >= 1`).
    pub fn is_active(&self) -> bool {
        self.threshold >= 1 && {
            let unique_active: BTreeSet<&str> = self.active.iter().map(String::as_str).collect();
            unique_active.len() >= usize::try_from(self.threshold).unwrap_or(usize::MAX)
        }
    }
}

/// The sequencers of the synchronizer as its `SequencerSynchronizerState` names them (uids), in the shape of a mediator group.
pub type SequencerGroup = MediatorGroup;

pub(super) fn sequencer_group_of(
    s: &canton_proto::com::digitalasset::canton::protocol::v30::SequencerSynchronizerState,
    serial: u32,
) -> SequencerGroup {
    SequencerGroup {
        serial,
        threshold: s.threshold,
        active: s.active.clone(),
        observers: s.observers.clone(),
    }
}

pub(super) fn mediator_group_of(m: &MediatorSynchronizerState, serial: u32) -> MediatorGroup {
    MediatorGroup {
        serial,
        threshold: m.threshold,
        active: m.active.clone(),
        observers: m.observers.clone(),
    }
}

/// The mappings this tracker follows; the others are left to the node that needs them.
fn is_followed(code: Code) -> bool {
    matches!(
        code,
        Code::NamespaceDelegation
            | Code::DecentralizedNamespaceDefinition
            | Code::OwnerToKeyMapping
            | Code::SynchronizerTrustCertificate
            | Code::ParticipantPermission
            | Code::VettedPackages
            | Code::PartyToParticipant
            | Code::PartyToKeyMapping
            | Code::SynchronizerParametersState
            | Code::MediatorSynchronizerState
            | Code::SequencerSynchronizerState
            | Code::LsuAnnouncement
            | Code::LsuSequencerConnectionSuccessor
    )
}

/// How a mapping is named in the tracker's notes.
fn subject(mapping: &Mapping) -> String {
    match mapping {
        Mapping::NamespaceDelegation(d) => format!("a delegation for namespace {}", d.namespace),
        Mapping::DecentralizedNamespaceDefinition(d) => {
            format!("decentralized namespace {}", d.decentralized_namespace)
        }
        Mapping::OwnerToKeyMapping(m) => m.member.clone(),
        Mapping::PartyToParticipant(p) => p.party.clone(),
        #[expect(
            deprecated,
            reason = "PartyToKeyMapping is a deprecated v31 variant still accepted and tracked"
        )]
        Mapping::PartyToKeyMapping(p) => p.party.clone(),
        Mapping::SynchronizerParametersState(_) => "synchronizer parameters".into(),
        Mapping::MediatorSynchronizerState(m) => format!("mediator group {}", m.group),
        Mapping::VettedPackages(v) => format!("vetted packages of {}", v.participant_uid),
        Mapping::SynchronizerTrustCertificate(c) => {
            format!("trust certificate of {}", c.participant_uid)
        }
        Mapping::SynchronizerUpgradeAnnouncement(_) => "synchronizer upgrade announcement".into(),
        Mapping::SequencerConnectionSuccessor(c) => {
            format!("sequencer successor of {}", c.sequencer_id)
        }
        other => format!("{:?}", Code::of(other)),
    }
}

fn missing_note(subject: &str, lead: &str, missing: &Authorizers) -> String {
    let mut parts = Vec::new();
    if !missing.namespaces.is_empty() {
        parts.push(format!(
            "the authorization of namespace(s) {:?}",
            missing.namespaces
        ));
    }
    if !missing.extra_keys.is_empty() {
        let keys: Vec<&str> = missing
            .extra_keys
            .iter()
            .map(|f| &f[..f.len().min(12)])
            .collect();
        parts.push(format!(
            "the signature of the key(s) {keys:?} it names (proof of possession)"
        ));
    }
    format!("{subject}: {lead} {}", parts.join(" and "))
}

impl Tracker {
    fn empty(me: &str, base: Learned) -> Tracker {
        Tracker {
            me_uid: me.strip_prefix("PAR::").unwrap_or(me).to_string(),
            auth: Authorizations::default(),
            head: BTreeMap::new(),
            pending: BTreeMap::new(),
            parties: BTreeMap::new(),
            party_thresholds: BTreeMap::new(),
            current_psid: None,
            lsu: None,
            batch_lsu: None,
            members: BTreeMap::new(),
            params_serial: None,
            parameters: None,
            crypto_specs: None,
            vetted_packages: base.vetted_packages.clone(),
            vetted_package_windows: base.vetted_package_windows.clone(),
            mediator_groups: BTreeMap::new(),
            sequencer_group: None,
            base,
        }
    }

    /// The tracker for the member `me` of the physical synchronizer `physical`, from the state it downloaded. An id that does not parse
    /// is an error: without it the mappings of another synchronizer would be taken
    /// (`TopologyTransactionAuthorizationValidator.verifySynchronizer`).
    pub fn for_synchronizer(entries: &[Entry], me: &str, physical: &str) -> Result<Self, String> {
        let psid = Psid::parse(physical)?;
        let mut tracker = Self::from_state(entries, me);
        tracker.set_current_psid(psid);
        Ok(tracker)
    }

    /// The tracker for the participant `me`, from the state it downloaded: of each unique key the transaction with the highest serial
    /// that is not a proposal is in force (nothing when it is a REMOVE), and the namespaces' graphs are built from the delegations in
    /// force. A proposal waits for its signatures as one that was broadcast. The download leaves out what the synchronizer rejected.
    ///
    /// [CANTON-NOTE: SEMANTICS] A transaction with a signature that does not verify with the key it names, a key some mapping of the state
    /// holds, is left out (`InitialTopologySnapshotValidator` replays the snapshot through the signature checks).
    ///
    /// [CANTON-NOTE: LIMITATION] The rest is taken as the synchronizer's store holds it: whether the signatures authorize the transaction
    /// (the namespaces' graphs at its time) is not checked again, nor is a signature by a key no mapping holds any more or by a session key
    /// (`signature_delegation`). A delegation still authorizes only through its namespace's graph, from the keys that signed it.
    pub fn from_state(entries: &[Entry], me: &str) -> Self {
        let entries = &without_forged_signatures(entries);
        let mut tracker = Tracker::empty(me, learn(entries, me));
        let mut head: BTreeMap<UniqueKey, &Entry> = BTreeMap::new();
        for e in entries.iter().filter(|e| !e.signed.proposal) {
            let Some(m) = mapping(e) else { continue };
            let key = unique_key(m);
            if head.get(&key).is_none_or(|old| old.tx.serial < e.tx.serial) {
                head.insert(key, e);
            }
        }
        for (key, e) in &head {
            tracker.head.insert(
                key.clone(),
                (e.tx.clone(), tw::transaction_hash(&e.signed.transaction)),
            );
            if e.tx.operation == REMOVE {
                continue;
            }
            let serial = e.tx.serial;
            match mapping(e) {
                Some(Mapping::NamespaceDelegation(d)) => {
                    if let Ok(Some(delegation)) = parse_delegation(d) {
                        let signed_by = e
                            .signed
                            .signatures
                            .iter()
                            .map(|s| s.signed_by.clone())
                            .collect();
                        tracker.auth.replace(delegation, signed_by);
                    }
                }
                Some(Mapping::DecentralizedNamespaceDefinition(d)) => {
                    tracker.auth.define_decentralized(
                        &d.decentralized_namespace,
                        Decentralized {
                            threshold: usize::try_from(d.threshold).unwrap_or(usize::MAX),
                            owners: d.owners.iter().cloned().collect(),
                        },
                    );
                }
                Some(Mapping::PartyToParticipant(p)) => {
                    tracker.parties.insert(
                        p.party.clone(),
                        (
                            serial,
                            p.participants
                                .iter()
                                .map(|h| (h.participant_uid.clone(), h.permission))
                                .collect(),
                        ),
                    );
                    tracker
                        .party_thresholds
                        .insert(p.party.clone(), p.threshold.max(1));
                }
                Some(Mapping::OwnerToKeyMapping(m)) => {
                    tracker.members.insert(
                        m.member.clone(),
                        (serial, signing_keys_of(m), encryption_keys_of(m)),
                    );
                }
                Some(Mapping::SynchronizerParametersState(p)) => {
                    tracker.params_serial = Some(serial);
                    tracker.parameters = p.synchronizer_parameters;
                }
                Some(Mapping::MediatorSynchronizerState(m)) => {
                    tracker
                        .mediator_groups
                        .insert(m.group, mediator_group_of(m, serial));
                }
                Some(Mapping::SequencerSynchronizerState(s)) => {
                    tracker.sequencer_group = Some(sequencer_group_of(s, serial));
                }
                _ => {}
            }
        }
        for e in entries.iter().filter(|e| e.signed.proposal) {
            let hash = tw::transaction_hash(&e.signed.transaction);
            let signatures = tracker
                .verified_signatures(e, &hash)
                .into_iter()
                .map(|s| (s.signed_by.clone(), s.clone()))
                .collect();
            tracker.pending.insert(hash, (e.tx.clone(), signatures));
        }
        tracker
    }

    /// The signatures of `entry` that verify against a key the tracker knows (a delegation's target, a key the mapping names).
    fn verified_signatures<'a>(&self, entry: &'a Entry, hash: &[u8]) -> Vec<&'a Signature> {
        let own_keys = mapping(entry).map(signature_keys_of).unwrap_or_default();
        entry
            .signed
            .signatures
            .iter()
            .filter(|s| {
                own_keys
                    .get(&s.signed_by)
                    .or_else(|| self.auth.key(&s.signed_by))
                    .is_some_and(|key| verifies(key, hash, s))
            })
            .collect()
    }

    /// The keys that authorized `entry` by signing a hash of several transactions that includes its own (`multi_transaction_signatures`),
    /// with a signature that verifies against a key the tracker knows.
    ///
    /// [CANTON-NOTE: SEMANTICS] `MultiTransactionSignature`: the signature is over `computeCombinedHash` of the covered transactions'
    /// hashes and counts for each of them (`coversHash`); an external party's onboarding transactions are authorized this way.
    ///
    /// [CANTON-NOTE: LIMITATION] These signers count for the transaction as it arrives; they are not kept with a proposal that waits for
    /// more signatures (only single-transaction signatures are).
    fn multi_signers(&self, entry: &Entry, hash: &[u8]) -> BTreeSet<String> {
        let own_keys = mapping(entry).map(signature_keys_of).unwrap_or_default();
        let mut signers = BTreeSet::new();
        for multi in &entry.signed.multi_transaction_signatures {
            if !multi
                .transaction_hashes
                .iter()
                .any(|h| h.as_slice() == hash)
            {
                continue;
            }
            let Ok(combined) =
                canton_algo::hash::multi_topology_transaction_hash(&multi.transaction_hashes)
            else {
                continue;
            };
            for s in &multi.signatures {
                if own_keys
                    .get(&s.signed_by)
                    .or_else(|| self.auth.key(&s.signed_by))
                    .is_some_and(|key| verifies(key, &combined, s))
                {
                    signers.insert(s.signed_by.clone());
                }
            }
        }
        signers
    }

    /// The mediator groups in force, by group index.
    pub fn mediator_groups(&self) -> &BTreeMap<u32, MediatorGroup> {
        &self.mediator_groups
    }

    /// How many members the topology knows (`TopologySnapshot.knownMembers`): what the address of all members resolves to.
    pub fn known_member_count(&self) -> usize {
        self.members.len()
    }

    /// The sequencer group in force (`None` before any `SequencerSynchronizerState`, or after its removal).
    pub fn sequencer_group(&self) -> Option<&SequencerGroup> {
        self.sequencer_group.as_ref()
    }

    /// Whether the sequencer `uid` (`name::namespace`) is active or an observer in the group in force: a sequencer that left its group is not
    /// (what a member registry deactivates it on).
    pub fn is_in_sequencer_group(&self, uid: &str) -> bool {
        self.sequencer_group
            .as_ref()
            .is_some_and(|g| g.active.iter().chain(&g.observers).any(|x| x == uid))
    }

    pub fn vetted_serial_of(&self, participant_uid: &str) -> Option<u32> {
        self.head
            .get(&UniqueKey {
                code: Code::VettedPackages,
                key: participant_uid.to_string(),
            })
            .map(|(tx, _)| tx.serial)
    }

    /// Active vetted package IDs in force for `participant_uid`, if a `VettedPackages` mapping is tracked.
    pub fn vetted_packages_of_participant(
        &self,
        participant_uid: &str,
    ) -> Option<&BTreeSet<String>> {
        self.vetted_packages.get(participant_uid)
    }

    /// Vetted package IDs valid at `at_micros` (`validFrom <= ts < validUntil`, `TopologyMapping.scala:1760-1761`).
    pub fn vetted_packages_of_participant_at(
        &self,
        participant_uid: &str,
        at_micros: i64,
    ) -> Option<BTreeSet<String>> {
        self.vetted_package_windows
            .get(participant_uid)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.is_valid_at(at_micros))
                    .map(|e| e.package_id.clone())
                    .collect()
            })
    }

    /// Who hosts `party` now and with which threshold: the uids of the participants that may confirm for it (permission submission or
    /// confirmation) and the number of them that has to approve. `None` for a party no authorized mapping names.
    ///
    /// [CANTON-NOTE: SEMANTICS] Only transactions that passed this tracker's checks (signatures of keys the state lists, the namespaces
    /// that have to authorize, the serial rule) count: what a mediator reads here cannot be forged by a member that merely broadcasts.
    /// A participant's admin party shares its `uid` and is implicitly hosted by that participant when `PAR::<uid>` is registered without
    /// a separate `PartyToParticipant` mapping (`BaseTopologySnapshot.scala`).
    pub fn hosting_of(&self, party: &str) -> Option<(u32, Vec<String>)> {
        if let Some((_, hosts)) = self.parties.get(party) {
            return Some((
                self.party_thresholds.get(party).copied().unwrap_or(1),
                hosts
                    .iter()
                    .filter(|(_, perm)| matches!(perm, 1 | 2))
                    .map(|(uid, _)| uid.clone())
                    .collect(),
            ));
        }
        if self.members.contains_key(&format!("PAR::{party}")) {
            return Some((1, vec![party.to_string()]));
        }
        None
    }

    /// Every participant that hosts `party` now, with its permission (1 submission, 2 confirmation, 3 observation), and the hosting
    /// threshold. `None` for a party no authorized mapping names, except an active participant's implicit admin party (`PAR::<party>`).
    pub fn hosts_of(&self, party: &str) -> Option<(u32, Vec<(String, i32)>)> {
        if let Some((_, hosts)) = self.parties.get(party) {
            return Some((
                self.party_thresholds.get(party).copied().unwrap_or(1),
                hosts.clone(),
            ));
        }
        if self.members.contains_key(&format!("PAR::{party}")) {
            return Some((1, vec![(party.to_string(), 1)]));
        }
        None
    }

    /// The physical synchronizer this state is of, when it was told (see [`Self::set_current_psid`]): what an upgrade announcement is
    /// checked against.
    pub fn current_psid(&self) -> Option<&Psid> {
        self.current_psid.as_ref()
    }

    pub fn set_current_psid(&mut self, psid: Psid) {
        self.current_psid = Some(psid);
    }

    /// Sets the static synchronizer crypto specs and key-count bounds from `GetSynchronizerParameters`.
    pub fn set_crypto_specs(&mut self, specs: crate::crypto_handshake::Required) {
        self.crypto_specs = Some(specs);
    }

    /// The `max_request_size` of the synchronizer parameters in force (bytes), when parameters were seen.
    pub fn max_request_size(&self) -> Option<u32> {
        self.parameters.as_ref().map(|d| d.max_request_size)
    }

    /// The dynamic synchronizer parameters in force and their serial, when parameters were seen.
    pub fn parameters(&self) -> Option<(u32, &DynamicSynchronizerParameters)> {
        Some((self.params_serial?, self.parameters.as_ref()?))
    }

    /// The traffic control parameters in force: `None` while traffic control is off (or no parameters were seen).
    pub fn traffic_control(&self) -> Option<&TrafficControlParameters> {
        self.parameters.as_ref()?.traffic_control.as_ref()
    }

    /// The upgrade that **led to** this synchronizer (its announcement names this synchronizer as the successor): on a successor, when the
    /// predecessor's upgrade time is.
    pub fn upgrade_into_current(&self) -> Option<&Lsu> {
        self.lsu
            .as_ref()
            .filter(|lsu| self.current_psid.as_ref() == Some(&lsu.successor))
    }

    /// The transactions applied from now until [`Self::end_batch`] are one batch (one topology broadcast).
    ///
    /// [CANTON-NOTE: SEMANTICS] The official checks of a mapping (`TopologyMappingChecks`) read the topology store, which does not yet hold
    /// the batch being processed: a sequencer's successor connection broadcast **together with** the upgrade announcement it depends on is
    /// rejected ("no LSU is announced", measured with the JVM participant, S-NET-038 part 12), and an announcement does not freeze the rest
    /// of its own batch. Authorization (signatures, namespace delegations) does see the batch's earlier transactions.
    pub fn begin_batch(&mut self) {
        self.batch_lsu = Some(self.lsu.clone());
    }

    pub fn end_batch(&mut self) {
        self.batch_lsu = None;
    }

    /// The announcement the checks of a mapping read: the one before the batch while a batch is applied.
    pub(super) fn lsu_for_checks(&self) -> Option<&Lsu> {
        match &self.batch_lsu {
            Some(before) => before.as_ref(),
            None => self.lsu.as_ref(),
        }
    }

    /// The upgrade the synchronizer announced (in force), if any.
    pub fn announced_upgrade(&self) -> Option<&Lsu> {
        // [CANTON-NOTE: SEMANTICS] only an upgrade **to a greater** synchronizer is one this synchronizer is under: an announcement of the
        // current id is accepted but changes nothing, and on a successor the announcement that led to it is past (`announcedLsu`)
        self.lsu.as_ref().filter(|lsu| {
            self.current_psid
                .as_ref()
                .is_none_or(|current| lsu.successor > *current)
        })
    }

    /// The signing keys of `member` as its key mapping in force lists them; `None` for a member no mapping names.
    pub fn signing_keys_of(&self, member: &str) -> Option<Vec<PublicKey>> {
        self.members.get(member).map(|(_, keys, _)| keys.clone())
    }

    /// The signing keys an external `party` signs its transactions with and how many of them must sign, as the mappings in force
    /// name them: its `PartyToParticipant`'s `party_signing_keys`, else its `PartyToKeyMapping`'s.
    #[expect(
        deprecated,
        reason = "PartyToKeyMapping is a deprecated variant of the v31 mapping oneof but still a mapping the node accepts"
    )]
    pub fn party_signing_keys(
        &self,
        party: &str,
    ) -> Option<(
        u32,
        Vec<canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey>,
    )> {
        let in_force = || {
            self.head
                .values()
                .filter(|(tx, _)| tx.operation != REMOVE)
                .filter_map(|(tx, _)| tx.mapping.as_ref()?.mapping.as_ref())
        };
        in_force()
            .find_map(|m| match m {
                Mapping::PartyToParticipant(p) if p.party == party => p
                    .party_signing_keys
                    .as_ref()
                    .map(|k| (k.threshold, k.keys.clone())),
                _ => None,
            })
            .or_else(|| {
                in_force().find_map(|m| match m {
                    Mapping::PartyToKeyMapping(p) if p.party == party => {
                        Some((p.threshold, p.signing_keys.clone()))
                    }
                    _ => None,
                })
            })
    }

    /// The member whose signing keys include the key with this fingerprint.
    pub fn member_with_key(&self, fingerprint: &str) -> Option<String> {
        self.members
            .iter()
            .find(|(_, (_, keys, _))| keys.iter().any(|key| key.id == fingerprint))
            .map(|(member, _)| member.clone())
    }

    /// Every participant that hosts each party now, whatever its permission.
    pub fn hosts_now(&self) -> BTreeMap<String, Vec<String>> {
        self.parties
            .iter()
            .map(|(party, (_, hosts))| {
                (
                    party.clone(),
                    hosts.iter().map(|(uid, _)| uid.clone()).collect(),
                )
            })
            .collect()
    }

    /// Who may confirm for each party now (permission 1 or 2) with the hosting threshold.
    pub fn hosting_now(&self) -> BTreeMap<String, (u32, Vec<String>)> {
        self.parties
            .keys()
            .filter_map(|party| Some((party.clone(), self.hosting_of(party)?)))
            .collect()
    }

    /// What the participant learns now: the downloaded keys and parameters, and the hosting as followed.
    pub fn learned(&self) -> Learned {
        let mut out = self.base.clone();
        out.submitter_keys.clear();
        out.mediator_keys.clear();
        out.encryption_keys.clear();
        for (member, (_, keys, encryption)) in &self.members {
            if member.starts_with("PAR::")
                && member.strip_prefix("PAR::") != Some(self.me_uid.as_str())
            {
                out.submitter_keys.extend(keys.iter().cloned());
                out.encryption_keys
                    .insert(member.clone(), encryption.clone());
            } else if member.starts_with("MED::") {
                out.mediator_keys.extend(keys.iter().cloned());
            }
        }
        out.hosted_parties = self
            .parties
            .iter()
            .filter(|(_, (_, hosts))| {
                hosts
                    .iter()
                    .any(|(uid, perm)| *uid == self.me_uid && matches!(perm, 1 | 2))
            })
            .map(|(party, _)| party.clone())
            .collect();
        out.vetted_packages = self.vetted_packages.clone();
        out.vetted_package_windows = self.vetted_package_windows.clone();
        out
    }

    /// Whether the signing keys `signers` (fingerprints) authorize a mapping of `code` for `namespace` now.
    pub fn authorizes(&self, namespace: &str, signers: &BTreeSet<String>, code: Code) -> bool {
        self.auth.authorizes(namespace, signers, code)
    }

    /// Takes one stored signed transaction of a broadcast. Returns what became of it (for the log of the loop).
    pub fn apply_stored(&mut self, stored: &[u8]) -> String {
        self.apply(stored).outcome.note().to_string()
    }

    /// Takes one stored signed transaction of a broadcast or of a state. Returns what became of it and the transaction with every
    /// verified signature seen for it so far.
    pub fn apply(&mut self, stored: &[u8]) -> Applied {
        self.apply_at(stored, None)
    }

    /// Like [`Self::apply`], knowing the time the transaction takes effect (what an upgrade time has to be after).
    pub fn apply_at(&mut self, stored: &[u8], effective: Option<i64>) -> Applied {
        let mut entries = match decode(&[(0, stored.to_vec())]) {
            Ok(e) => e,
            Err(e) => {
                return Applied {
                    outcome: Refusal::Malformed(e).into(),
                    merged: None,
                }
            }
        };
        let Some(entry) = entries.pop() else {
            return Applied {
                outcome: Refusal::Malformed("no transaction".into()).into(),
                merged: None,
            };
        };
        let hash = tw::transaction_hash(&entry.signed.transaction);
        let verified = self.verified_signatures(&entry, &hash);
        // the signatures seen before for the same transaction count with these; they are kept only while it waits as a proposal
        let mut signatures: BTreeMap<String, Signature> = self
            .pending
            .get(&hash)
            .map(|(_, s)| s.clone())
            .unwrap_or_default();
        for s in verified {
            signatures
                .entry(s.signed_by.clone())
                .or_insert_with(|| s.clone());
        }
        let mut signers: BTreeSet<String> = signatures.keys().cloned().collect();
        signers.extend(self.multi_signers(&entry, &hash));
        let (outcome, stored) =
            self.decide(&entry.tx, &hash, &signers, effective, entry.signed.proposal);
        match &outcome {
            Outcome::Waiting(_) => {
                self.pending
                    .insert(hash.clone(), (entry.tx.clone(), signatures.clone()));
            }
            Outcome::InForce(_) => {
                self.pending.remove(&hash);
            }
            Outcome::Refused(_) | Outcome::Unfollowed(_) => {}
        }
        let signatures: Vec<Signature> = signatures.into_values().collect();
        if stored == Stored::AlreadyInForce {
            return Applied {
                outcome,
                merged: None,
            };
        }
        Applied {
            merged: Some(SignedTopologyTransaction {
                // in force means complete: it is no proposal any more
                proposal: entry.signed.proposal && !outcome.is_in_force(),
                signatures,
                ..entry.signed
            }),
            outcome,
        }
    }

    fn decide(
        &mut self,
        tx: &TopologyTransaction,
        hash: &[u8],
        signers: &BTreeSet<String>,
        effective: Option<i64>,
        proposal: bool,
    ) -> (Outcome, Stored) {
        // [CANTON-NOTE: SEMANTICS] `mergeSignatures`: the transaction in force again, with more signatures (an owner signing after the
        // threshold was reached), is accepted as it is: no serial rule, nothing changes, nothing new to store
        let key = tx
            .mapping
            .as_ref()
            .and_then(|m| m.mapping.as_ref())
            .map(unique_key);
        let in_force_again = key
            .and_then(|k| self.head.get(&k))
            .is_some_and(|(_, h)| h == hash);
        let outcome = self.judge(tx, hash, signers, effective, proposal);
        if in_force_again && outcome.is_in_force() {
            return (outcome, Stored::AlreadyInForce);
        }
        (outcome, Stored::New)
    }

    fn judge(
        &mut self,
        tx: &TopologyTransaction,
        hash: &[u8],
        signers: &BTreeSet<String>,
        effective: Option<i64>,
        proposal: bool,
    ) -> Outcome {
        let Some(mapping) = tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) else {
            return Outcome::Unfollowed("a transaction this participant does not follow".into());
        };
        let code = Code::of(mapping);
        // [CANTON-NOTE: SEMANTICS] Once an upgrade is announced the topology is frozen: only the upgrade's own mappings (the announcement
        // and the sequencers' successor connections) change it until the upgrade is done (`TopologyMappingChecks`, the successor then
        // starts from exactly this state).
        if let Some(lsu) = self.lsu_for_checks().filter(|lsu| {
            self.current_psid
                .as_ref()
                .is_none_or(|current| lsu.successor > *current)
        }) {
            if !matches!(
                code,
                Code::LsuAnnouncement | Code::LsuSequencerConnectionSuccessor
            ) {
                return Refusal::Frozen(lsu.successor.logical.clone()).into();
            }
        }
        if !is_followed(code) {
            return Outcome::Unfollowed("a transaction this participant does not follow".into());
        }
        let subject = subject(mapping);
        // [CANTON-NOTE: SEMANTICS] `verifySynchronizer`: a mapping restricted to a synchronizer (`restrictedToSynchronizer`) is taken
        // only by that synchronizer's store
        if let (Some(restricted), Some(current)) = (restricted_to(mapping), &self.current_psid) {
            if restricted != current.logical {
                return Refusal::Check(format!(
                    "{subject}: restricted to synchronizer {restricted} while following {}",
                    current.logical
                ))
                .into();
            }
        }
        let delegation = match mapping {
            Mapping::NamespaceDelegation(d) => match parse_delegation(d) {
                Ok(Some(delegation)) => Some(delegation),
                Ok(None) => {
                    return Outcome::Unfollowed(
                        "a delegation to a key this participant does not follow".into(),
                    )
                }
                Err(e) => return Refusal::InvalidMapping(e).into(),
            },
            _ => None,
        };
        if tx.serial == 0 {
            return Refusal::InvalidMapping(format!("{subject}: serial 0 is not a serial")).into();
        }
        let key = unique_key(mapping);
        let in_store = self.head.get(&key);
        if in_store.is_some_and(|(_, h)| h == hash) {
            return Outcome::InForce(format!(
                "{subject}: serial {} is in force (signatures merged)",
                tx.serial
            ));
        }
        let previous = in_store.map(|(tx, _)| tx);
        // [CANTON-NOTE: SEMANTICS] `TopologyStateProcessor.serialIsMonotonicallyIncreasing`: once the store holds a transaction for the
        // unique key (a REMOVE too: it stays the head of the key), the next one has exactly the next serial; a key never seen takes any.
        if let Some(previous) = previous {
            if tx.serial != previous.serial.saturating_add(1) {
                return Refusal::SerialMismatch {
                    subject,
                    actual: tx.serial,
                    in_force: previous.serial,
                }
                .into();
            }
        }
        if let Err(refusal) = self
            .required_checks(mapping, tx.operation, tx.serial, previous, effective)
            .and_then(|()| self.check(mapping, tx.operation, previous, effective))
        {
            return refusal.into();
        }
        let signed_by = match self.authorize(
            mapping,
            tx.operation,
            code,
            previous,
            signers,
            delegation.as_ref(),
        ) {
            Ok(signed_by) => signed_by,
            Err(AuthorizationError::Missing(missing)) if proposal => {
                return Outcome::Waiting(missing_note(&subject, "waiting for", &missing))
            }
            Err(AuthorizationError::Missing(missing)) => {
                return Refusal::NotAuthorized(missing_note(
                    &subject,
                    "not a proposal and not authorized, it lacks",
                    &missing,
                ))
                .into()
            }
            Err(AuthorizationError::KeyUsage(key)) => {
                return Refusal::KeyUsage { subject, key }.into()
            }
        };
        let outcome = self.effect(mapping, tx, signed_by, delegation);
        if outcome.is_in_force() {
            self.head.insert(key, (tx.clone(), hash.to_vec()));
        }
        outcome
    }

    /// The authorization of a transaction signed by `signers`: the keys that authorize it (what a delegation's edges come from), or what
    /// is missing.
    ///
    /// [CANTON-NOTE: SEMANTICS] `TopologyTransactionAuthorizationValidator`: a root certificate (a delegation to the namespace's own key,
    /// signed only by that key) authorizes itself, its removal too. Otherwise a namespace counts when a key chained to its root in its own
    /// graph, by a delegation that may sign this mapping's code, signed; a decentralized namespace when `threshold` of its owners do. An
    /// extra key counts when it signed and its usages allow a proof of possession (`NamespaceOrProofOfOwnership`); a key that signed
    /// although its usages forbid it refuses the transaction (`SignatureCheckFailed`).
    fn authorize(
        &self,
        mapping: &Mapping,
        operation: i32,
        code: Code,
        previous: Option<&TopologyTransaction>,
        signers: &BTreeSet<String>,
        delegation: Option<&Delegation>,
    ) -> Result<BTreeSet<String>, AuthorizationError> {
        if let Some(d) = delegation.filter(|d| d.is_root()) {
            if !signers.is_empty() && signers.iter().all(|s| *s == d.namespace) {
                return Ok(signers.clone());
            }
        }
        // [CANTON-NOTE: SEMANTICS] `requiredAuthFor`: the synchronizer's owners may remove any mapping of their synchronizer
        let or_synchronizer = |required: RequiredAuth| match &self.current_psid {
            Some(psid) if operation == REMOVE => {
                required.or(RequiredAuth::namespaces([psid.namespace()]))
            }
            _ => required,
        };
        let required = or_synchronizer(required_auth(mapping, previous));
        let permissible = or_synchronizer(required_auth(mapping, None))
            .referenced()
            .union(required.referenced());
        let mut extra_keys = BTreeSet::new();
        for (key, usages) in mapped_signing_keys(mapping) {
            let fingerprint = key_fingerprint(&key.public_key);
            if !permissible.extra_keys.contains(&fingerprint) || !signers.contains(&fingerprint) {
                continue;
            }
            if !usages.allows(&[Usage::Namespace, Usage::ProofOfOwnership]) {
                return Err(AuthorizationError::KeyUsage(fingerprint));
            }
            extra_keys.insert(fingerprint);
        }
        let self_authorized = self_authorizing_namespace(mapping, operation, signers);
        let provided = Authorizers {
            namespaces: permissible
                .namespaces
                .iter()
                .filter(|ns| {
                    self_authorized.as_deref() == Some(ns.as_str())
                        || self.auth.authorizes(ns, signers, code)
                })
                .cloned()
                .collect(),
            extra_keys,
        };
        if let Some(missing) = required.missing(&provided) {
            return Err(AuthorizationError::Missing(missing));
        }
        Ok(permissible
            .namespaces
            .iter()
            .flat_map(|ns| self.auth.supporting(ns, signers, code))
            .collect())
    }
}

/// `namespaceKeyForSelfAuthorization`: a hosting (a REPLACE) that lists a party signing key whose fingerprint is the party's namespace,
/// signed by that key, authorizes the party's namespace itself (an external party needs no namespace delegation).
fn self_authorizing_namespace(
    mapping: &Mapping,
    operation: i32,
    signers: &BTreeSet<String>,
) -> Option<String> {
    let Mapping::PartyToParticipant(p) = mapping else {
        return None;
    };
    let namespace = namespace_of(&p.party);
    (operation != REMOVE
        && signers.contains(namespace)
        && mapped_signing_keys(mapping).iter().any(|(k, usages)| {
            key_fingerprint(&k.public_key) == namespace && usages.allows(&[Usage::Namespace])
        }))
    .then(|| namespace.to_string())
}

/// Whether a transaction the tracker took is new for the store, or the one in force again with more signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stored {
    New,
    AlreadyInForce,
}

enum AuthorizationError {
    Missing(Authorizers),
    KeyUsage(String),
}

/// The keys a transaction's own mapping names, by fingerprint: a signature by one of them is verified with it even before any state
/// knows it (a root certificate's key, a key mapping's keys proving possession).
/// `entries` without the ones carrying a signature that the key it names, as some mapping of `entries` holds it, does not verify.
fn without_forged_signatures(entries: &[Entry]) -> Vec<Entry> {
    let known: BTreeMap<String, PublicKey> = entries
        .iter()
        .filter_map(mapping)
        .flat_map(signature_keys_of)
        .collect();
    use canton_algo::signing::Usage as U;
    let any_usage: BTreeSet<U> = [
        U::Namespace,
        U::SequencerAuthentication,
        U::Protocol,
        U::ProofOfOwnership,
    ]
    .into();
    entries
        .iter()
        .filter(|e| {
            let hash = tw::transaction_hash(&e.signed.transaction);
            // [CANTON-NOTE: DEFENSIVE] Only the cryptography is judged here (any usage): which usage a key needs is the authorization's.
            e.signed.signatures.iter().all(|s| {
                s.signature_delegation.is_some()
                    || known.get(&s.signed_by).is_none_or(|key| {
                        canton_algo::member_signature::verify_by_keys(
                            std::slice::from_ref(key),
                            &hash,
                            s,
                            &any_usage,
                        )
                        .is_ok()
                    })
            })
        })
        .cloned()
        .collect()
}

fn signature_keys_of(mapping: &Mapping) -> BTreeMap<String, PublicKey> {
    let mut keys: BTreeMap<String, PublicKey> = mapped_signing_keys(mapping)
        .into_iter()
        .filter_map(|(k, _)| signing_key(k))
        .map(|k| (k.id.clone(), k))
        .collect();
    if let Mapping::NamespaceDelegation(d) = mapping {
        if let Some(key) = d.target_key.as_ref().and_then(signing_key) {
            keys.insert(key.id.clone(), key);
        }
    }
    keys
}

pub(super) fn timeouts_of(p: &DynamicSynchronizerParameters) -> Option<Timeouts> {
    let micros = |d: &Option<prost_types::Duration>| {
        d.as_ref()
            .map(|d| d.seconds * 1_000_000 + i64::from(d.nanos) / 1_000)
    };
    Some(Timeouts {
        confirmation_response_micros: micros(&p.confirmation_response_timeout)?,
        mediator_reaction_micros: micros(&p.mediator_reaction_timeout)?,
    })
}
