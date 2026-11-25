//! Who has to authorize a topology transaction: `TopologyMapping.requiredAuth(previous)` as one table, the mapping codes a delegation
//! can be restricted to, and the unique key the serial rule is kept by.
use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
use canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey;
use canton_proto::com::digitalasset::canton::protocol::v31::party_to_participant::{
    hosting_participant::HostingState, HostingParticipant,
};
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_proto::com::digitalasset::canton::protocol::v31::{
    PartyToParticipant, TopologyTransaction,
};

use super::keys::{key_fingerprint, Usages};
use super::psid::Psid;

/// `TopologyMapping.Code`, numbered as the proto enum `TopologyMappingCode` numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    NamespaceDelegation = 1,
    DecentralizedNamespaceDefinition = 3,
    OwnerToKeyMapping = 4,
    SynchronizerTrustCertificate = 5,
    ParticipantPermission = 6,
    PartyHostingLimits = 7,
    VettedPackages = 8,
    PartyToParticipant = 9,
    SynchronizerParametersState = 11,
    MediatorSynchronizerState = 12,
    SequencerSynchronizerState = 13,
    SequencingParametersState = 17,
    PartyToKeyMapping = 18,
    LsuAnnouncement = 19,
    LsuSequencerConnectionSuccessor = 20,
}

impl Code {
    const ALL: [Code; 15] = [
        Code::NamespaceDelegation,
        Code::DecentralizedNamespaceDefinition,
        Code::OwnerToKeyMapping,
        Code::SynchronizerTrustCertificate,
        Code::ParticipantPermission,
        Code::PartyHostingLimits,
        Code::VettedPackages,
        Code::PartyToParticipant,
        Code::SynchronizerParametersState,
        Code::MediatorSynchronizerState,
        Code::SequencerSynchronizerState,
        Code::SequencingParametersState,
        Code::PartyToKeyMapping,
        Code::LsuAnnouncement,
        Code::LsuSequencerConnectionSuccessor,
    ];

    /// The code of a proto enum value; `None` for `UNSPECIFIED`, the reserved values and unknown ones (`Code.fromProtoV30` refuses them).
    pub fn from_proto(value: i32) -> Option<Code> {
        Code::ALL.into_iter().find(|c| *c as i32 == value)
    }

    #[expect(
        deprecated,
        reason = "PartyToKeyMapping is a deprecated variant of the v31 mapping oneof but still a mapping the node accepts"
    )]
    pub fn of(mapping: &Mapping) -> Code {
        match mapping {
            Mapping::NamespaceDelegation(_) => Code::NamespaceDelegation,
            Mapping::DecentralizedNamespaceDefinition(_) => Code::DecentralizedNamespaceDefinition,
            Mapping::OwnerToKeyMapping(_) => Code::OwnerToKeyMapping,
            Mapping::SynchronizerTrustCertificate(_) => Code::SynchronizerTrustCertificate,
            Mapping::ParticipantPermission(_) => Code::ParticipantPermission,
            Mapping::PartyHostingLimits(_) => Code::PartyHostingLimits,
            Mapping::VettedPackages(_) => Code::VettedPackages,
            Mapping::PartyToParticipant(_) => Code::PartyToParticipant,
            Mapping::SynchronizerParametersState(_) => Code::SynchronizerParametersState,
            Mapping::MediatorSynchronizerState(_) => Code::MediatorSynchronizerState,
            Mapping::SequencerSynchronizerState(_) => Code::SequencerSynchronizerState,
            Mapping::SequencingDynamicParametersState(_) => Code::SequencingParametersState,
            Mapping::PartyToKeyMapping(_) => Code::PartyToKeyMapping,
            Mapping::SynchronizerUpgradeAnnouncement(_) => Code::LsuAnnouncement,
            Mapping::SequencerConnectionSuccessor(_) => Code::LsuSequencerConnectionSuccessor,
        }
    }
}

/// `MappingHash`: what makes two transactions versions of the same mapping. The serial rule is kept per unique key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UniqueKey {
    pub code: Code,
    pub key: String,
}

/// The unique key of `mapping`, with the same fields as the node's `uniqueKey` of each mapping.
#[expect(
    deprecated,
    reason = "PartyToKeyMapping is a deprecated variant of the v31 mapping oneof but still a mapping the node accepts"
)]
pub fn unique_key(mapping: &Mapping) -> UniqueKey {
    let key = match mapping {
        Mapping::NamespaceDelegation(d) => format!(
            "{}/{}",
            d.namespace,
            d.target_key
                .as_ref()
                .map(|k| key_fingerprint(&k.public_key))
                .unwrap_or_default()
        ),
        Mapping::DecentralizedNamespaceDefinition(d) => d.decentralized_namespace.clone(),
        Mapping::OwnerToKeyMapping(m) => m.member.clone(),
        Mapping::SynchronizerTrustCertificate(c) => {
            format!("{}/{}", c.participant_uid, c.synchronizer_id)
        }
        Mapping::ParticipantPermission(p) => format!("{}/{}", p.synchronizer_id, p.participant_uid),
        Mapping::PartyHostingLimits(p) => format!("{}/{}", p.synchronizer_id, p.party),
        Mapping::VettedPackages(v) => v.participant_uid.clone(),
        Mapping::PartyToParticipant(p) => p.party.clone(),
        Mapping::SynchronizerParametersState(p) => p.synchronizer_id.clone(),
        Mapping::MediatorSynchronizerState(m) => format!("{}/{}", m.synchronizer_id, m.group),
        Mapping::SequencerSynchronizerState(s) => s.synchronizer_id.clone(),
        Mapping::SequencingDynamicParametersState(s) => s.synchronizer_id.clone(),
        Mapping::PartyToKeyMapping(p) => p.party.clone(),
        Mapping::SynchronizerUpgradeAnnouncement(a) => {
            Psid::parse(&a.successor_physical_synchronizer_id).map_or_else(
                |_| a.successor_physical_synchronizer_id.clone(),
                |p| p.logical,
            )
        }
        Mapping::SequencerConnectionSuccessor(c) => format!(
            "{}/{}",
            c.sequencer_id,
            Psid::parse(&c.successor_physical_synchronizer_id).map_or_else(
                |_| c.successor_physical_synchronizer_id.clone(),
                |p| p.logical
            )
        ),
    };
    UniqueKey {
        code: Code::of(mapping),
        key,
    }
}

/// The namespace of a uid (`name::namespace`), a member (`PAR::name::namespace`) or a synchronizer id: its last part.
pub fn namespace_of(id: &str) -> &str {
    id.rsplit("::").next().unwrap_or_default()
}

/// `restrictedToSynchronizer`: the logical synchronizer a mapping belongs to, for the mappings that belong to one.
pub fn restricted_to(mapping: &Mapping) -> Option<String> {
    let logical =
        |physical: &str| Psid::parse(physical).map_or_else(|_| physical.to_string(), |p| p.logical);
    match mapping {
        Mapping::SynchronizerTrustCertificate(c) => Some(c.synchronizer_id.clone()),
        Mapping::ParticipantPermission(p) => Some(p.synchronizer_id.clone()),
        Mapping::PartyHostingLimits(p) => Some(p.synchronizer_id.clone()),
        Mapping::SynchronizerParametersState(p) => Some(p.synchronizer_id.clone()),
        Mapping::SequencingDynamicParametersState(p) => Some(p.synchronizer_id.clone()),
        Mapping::MediatorSynchronizerState(m) => Some(m.synchronizer_id.clone()),
        Mapping::SequencerSynchronizerState(s) => Some(s.synchronizer_id.clone()),
        Mapping::SynchronizerUpgradeAnnouncement(a) => {
            Some(logical(&a.successor_physical_synchronizer_id))
        }
        Mapping::SequencerConnectionSuccessor(c) => {
            Some(logical(&c.successor_physical_synchronizer_id))
        }
        _ => None,
    }
}

/// `ReferencedAuthorizations`: namespaces and extra keys (by fingerprint).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authorizers {
    pub namespaces: BTreeSet<String>,
    pub extra_keys: BTreeSet<String>,
}

impl Authorizers {
    pub fn union(mut self, other: Authorizers) -> Authorizers {
        self.namespaces.extend(other.namespaces);
        self.extra_keys.extend(other.extra_keys);
        self
    }
}

/// `TopologyMapping.RequiredAuth`: who has to sign for a transaction to be fully authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredAuth {
    /// Every namespace and every extra key (the proof of possession of a key a mapping names).
    All(Authorizers),
    And(Box<RequiredAuth>, Box<RequiredAuth>),
    Or(Box<RequiredAuth>, Box<RequiredAuth>),
}

impl RequiredAuth {
    pub fn namespaces<I: IntoIterator<Item = S>, S: Into<String>>(namespaces: I) -> RequiredAuth {
        RequiredAuth::All(Authorizers {
            namespaces: namespaces.into_iter().map(Into::into).collect(),
            extra_keys: BTreeSet::new(),
        })
    }

    pub fn with_extra_keys(self, keys: BTreeSet<String>) -> RequiredAuth {
        self.and(RequiredAuth::All(Authorizers {
            namespaces: BTreeSet::new(),
            extra_keys: keys,
        }))
    }

    /// `and`, squashing two plain requirements into one as the node does.
    pub fn and(self, next: RequiredAuth) -> RequiredAuth {
        match (self, next) {
            (RequiredAuth::All(a), RequiredAuth::All(b)) => RequiredAuth::All(a.union(b)),
            (a, b) => RequiredAuth::And(Box::new(a), Box::new(b)),
        }
    }

    pub fn or(self, next: RequiredAuth) -> RequiredAuth {
        RequiredAuth::Or(Box::new(self), Box::new(next))
    }

    /// Every namespace and key this requirement mentions: whose signatures are worth looking at (an `or` counts both sides).
    pub fn referenced(&self) -> Authorizers {
        match self {
            RequiredAuth::All(a) => a.clone(),
            RequiredAuth::And(a, b) | RequiredAuth::Or(a, b) => {
                a.referenced().union(b.referenced())
            }
        }
    }

    /// `satisfiedByActualAuthorizers`: `None` when `provided` satisfies the requirement, else what is missing.
    pub fn missing(&self, provided: &Authorizers) -> Option<Authorizers> {
        match self {
            RequiredAuth::All(required) => {
                let missing = Authorizers {
                    namespaces: required
                        .namespaces
                        .difference(&provided.namespaces)
                        .cloned()
                        .collect(),
                    extra_keys: required
                        .extra_keys
                        .difference(&provided.extra_keys)
                        .cloned()
                        .collect(),
                };
                (!missing.namespaces.is_empty() || !missing.extra_keys.is_empty())
                    .then_some(missing)
            }
            RequiredAuth::And(a, b) => match (a.missing(provided), b.missing(provided)) {
                (None, None) => None,
                (x, y) => Some(x.unwrap_or_default().union(y.unwrap_or_default())),
            },
            RequiredAuth::Or(a, b) => a.missing(provided).and(b.missing(provided)),
        }
    }
}

/// The signing keys a mapping itself names (an `OwnerToKeyMapping`'s, a `PartyToKeyMapping`'s), with their usages: the keys whose
/// signature proves possession. A key whose usages do not parse is left out (it cannot prove anything).
#[expect(
    deprecated,
    reason = "PartyToKeyMapping is a deprecated variant of the v31 mapping oneof but still a mapping the node accepts"
)]
pub fn mapped_signing_keys(mapping: &Mapping) -> Vec<(&SigningPublicKey, Usages)> {
    let keys: Vec<&SigningPublicKey> = match mapping {
        Mapping::OwnerToKeyMapping(m) => m
            .public_keys
            .iter()
            .filter_map(|k| match &k.key {
                Some(Key::SigningPublicKey(s)) => Some(s),
                _ => None,
            })
            .collect(),
        Mapping::PartyToKeyMapping(p) => p.signing_keys.iter().collect(),
        Mapping::PartyToParticipant(p) => p
            .party_signing_keys
            .iter()
            .flat_map(|k| k.keys.iter())
            .collect(),
        _ => Vec::new(),
    };
    keys.into_iter()
        .filter_map(|k| Some((k, Usages::parse(&k.usage).ok()?)))
        .collect()
}

fn fingerprints(keys: &[(&SigningPublicKey, Usages)]) -> BTreeSet<String> {
    keys.iter()
        .map(|(k, _)| key_fingerprint(&k.public_key))
        .collect()
}

/// `requiredAuth(previous)` of every mapping: `previous` is the transaction in force for the same unique key (a REMOVE included).
#[expect(
    deprecated,
    reason = "PartyToKeyMapping is a deprecated variant of the v31 mapping oneof but still a mapping the node accepts"
)]
pub fn required_auth(mapping: &Mapping, previous: Option<&TopologyTransaction>) -> RequiredAuth {
    let previous_mapping = previous
        .and_then(|p| p.mapping.as_ref())
        .and_then(|m| m.mapping.as_ref());
    let previous_replace = previous
        .filter(|p| p.operation != super::REMOVE)
        .and(previous_mapping);
    match mapping {
        Mapping::NamespaceDelegation(d) => RequiredAuth::namespaces([d.namespace.as_str()]),
        Mapping::DecentralizedNamespaceDefinition(d) => match previous_mapping {
            // [CANTON-NOTE: SEMANTICS] the previous definition counts whatever its operation: a removed decentralized namespace can only be
            // redefined by itself, which no longer authorizes anything
            Some(Mapping::DecentralizedNamespaceDefinition(p))
                if p.decentralized_namespace == d.decentralized_namespace =>
            {
                let added = d.owners.iter().filter(|o| !p.owners.contains(*o));
                RequiredAuth::namespaces(added.chain(std::iter::once(&d.decentralized_namespace)))
            }
            _ => RequiredAuth::namespaces(d.owners.iter().map(String::as_str)),
        },
        // [CANTON-NOTE: SEMANTICS] `TopologyMapping.newSigningKeys`: only a signing key the previous mapping (a REPLACE) did not list
        // has to prove possession; a rotation keeps the old keys' proofs
        Mapping::OwnerToKeyMapping(m) => RequiredAuth::namespaces([namespace_of(&m.member)])
            .with_extra_keys(new_signing_keys(mapping, previous_replace)),
        Mapping::PartyToKeyMapping(p) => RequiredAuth::namespaces([namespace_of(&p.party)])
            .with_extra_keys(new_signing_keys(mapping, previous_replace)),
        Mapping::SynchronizerTrustCertificate(c) => {
            RequiredAuth::namespaces([namespace_of(&c.participant_uid)])
        }
        Mapping::VettedPackages(v) => RequiredAuth::namespaces([namespace_of(&v.participant_uid)]),
        Mapping::ParticipantPermission(p) => {
            RequiredAuth::namespaces([namespace_of(&p.synchronizer_id)])
        }
        Mapping::PartyHostingLimits(p) => {
            RequiredAuth::namespaces([namespace_of(&p.synchronizer_id)])
        }
        Mapping::SynchronizerParametersState(p) => {
            RequiredAuth::namespaces([namespace_of(&p.synchronizer_id)])
        }
        Mapping::SequencingDynamicParametersState(p) => {
            RequiredAuth::namespaces([namespace_of(&p.synchronizer_id)])
        }
        Mapping::MediatorSynchronizerState(m) => {
            RequiredAuth::namespaces([namespace_of(&m.synchronizer_id)])
        }
        Mapping::SequencerSynchronizerState(s) => {
            RequiredAuth::namespaces([namespace_of(&s.synchronizer_id)])
        }
        Mapping::SynchronizerUpgradeAnnouncement(a) => {
            RequiredAuth::namespaces([Psid::parse(&a.successor_physical_synchronizer_id)
                .map(|p| p.namespace().to_string())
                .unwrap_or_default()])
        }
        Mapping::SequencerConnectionSuccessor(c) => {
            RequiredAuth::namespaces([namespace_of(&c.sequencer_id)])
        }
        Mapping::PartyToParticipant(p) => match previous_replace {
            Some(Mapping::PartyToParticipant(before)) => party_to_participant(p, Some(before)),
            _ => party_to_participant(p, None),
        },
    }
}

/// The signing keys `mapping` names that `previous` (of the same kind) did not, by fingerprint.
fn new_signing_keys(mapping: &Mapping, previous: Option<&Mapping>) -> BTreeSet<String> {
    let before = previous
        .filter(|p| Code::of(p) == Code::of(mapping))
        .map(|p| fingerprints(&mapped_signing_keys(p)))
        .unwrap_or_default();
    fingerprints(&mapped_signing_keys(mapping))
        .difference(&before)
        .cloned()
        .collect()
}

/// `HostingState` in its forward order (`Nominated < Freezing < Onboarding < Active`). An unset state is taken as Active, the state of a
/// mapping written before states existed.
pub(super) fn hosting_state(h: &HostingParticipant) -> i32 {
    match h.state {
        0 => 4,
        s => s,
    }
}

/// `ParticipantPermission` ordered by what it allows (`Observation < Confirmation < Submission`); the proto numbers it the other way.
fn permission_rank(permission: i32) -> i32 {
    -permission
}

/// `PartyToParticipant.requiredAuth` (`topology.proto` gives the rules): each change against the previous REPLACE needs its own
/// authorization and all of them are needed; a transaction that changes nothing (a REMOVE) needs the party.
///
/// [CANTON-NOTE: SEMANTICS] A participant removed from the hosting, or downgraded, needs the party **or** that participant (a
/// participant leaves alone); an upgrade needs both; a hosting state moved forward needs the participant, backward the party; an added
/// participant needs the party and the participant, except one added as Nominated (the party alone); a changed threshold needs the
/// party; changed party signing keys need the party and every new key.
fn party_to_participant(
    p: &PartyToParticipant,
    before: Option<&PartyToParticipant>,
) -> RequiredAuth {
    let party = namespace_of(&p.party);
    let party_only = || RequiredAuth::namespaces([party]);
    let participant = |uid: &str| RequiredAuth::namespaces([namespace_of(uid)]);
    let signing_keys = |m: &PartyToParticipant| -> BTreeSet<String> {
        m.party_signing_keys
            .iter()
            .flat_map(|k| k.keys.iter())
            .map(|k| key_fingerprint(&k.public_key))
            .collect()
    };
    let previous_hosts: Vec<&HostingParticipant> = before
        .map(|b| b.participants.iter().collect())
        .unwrap_or_default();
    let previous_of = |uid: &str| previous_hosts.iter().find(|h| h.participant_uid == uid);
    let added_keys: BTreeSet<String> = signing_keys(p)
        .difference(&before.map(signing_keys).unwrap_or_default())
        .cloned()
        .collect();
    let added: Vec<&HostingParticipant> = p
        .participants
        .iter()
        .filter(|h| previous_of(&h.participant_uid).is_none())
        .collect();

    let mut all: Vec<RequiredAuth> = Vec::new();
    if before.map(|b| b.threshold) != Some(p.threshold) {
        all.push(party_only());
    }
    if before.and_then(|b| b.party_signing_keys.as_ref()) != p.party_signing_keys.as_ref() {
        all.push(party_only().with_extra_keys(added_keys.clone()));
    }
    if !added.is_empty() {
        all.push(RequiredAuth::namespaces(
            std::iter::once(party).chain(
                added
                    .iter()
                    .filter(|h| h.state != HostingState::Nominated as i32)
                    .map(|h| namespace_of(&h.participant_uid)),
            ),
        ));
    }
    for h in &p.participants {
        if let Some(prev) = previous_of(&h.participant_uid) {
            match hosting_state(prev).cmp(&hosting_state(h)) {
                std::cmp::Ordering::Less => all.push(participant(&h.participant_uid)),
                std::cmp::Ordering::Greater => all.push(party_only()),
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    let removed: BTreeSet<&str> = previous_hosts
        .iter()
        .map(|h| h.participant_uid.as_str())
        .filter(|uid| !p.participants.iter().any(|h| h.participant_uid == *uid))
        .collect();
    for uid in removed {
        all.push(party_only().or(participant(uid)));
    }
    for h in &p.participants {
        if let Some(prev) = previous_of(&h.participant_uid) {
            match permission_rank(prev.permission).cmp(&permission_rank(h.permission)) {
                std::cmp::Ordering::Less => all.push(RequiredAuth::namespaces([
                    party,
                    namespace_of(&h.participant_uid),
                ])),
                std::cmp::Ordering::Greater => {
                    all.push(party_only().or(participant(&h.participant_uid)))
                }
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    all.into_iter()
        .reduce(RequiredAuth::and)
        .unwrap_or_else(|| {
            RequiredAuth::namespaces(
                std::iter::once(party)
                    .chain(added.iter().map(|h| namespace_of(&h.participant_uid))),
            )
            .with_extra_keys(added_keys)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn provided(namespaces: &[&str], keys: &[&str]) -> Authorizers {
        Authorizers {
            namespaces: set(namespaces),
            extra_keys: set(keys),
        }
    }

    #[test]
    fn and_needs_both_or_needs_either_and_extra_keys_count() {
        let a = RequiredAuth::namespaces(["a"]);
        let b = RequiredAuth::namespaces(["b"]);
        let both = a.clone().and(b.clone());
        assert_eq!(both, RequiredAuth::namespaces(["a", "b"]), "squashed");
        assert!(both.missing(&provided(&["a", "b"], &[])).is_none());
        assert_eq!(
            both.missing(&provided(&["a"], &[])),
            Some(provided(&["b"], &[]))
        );
        let either = a.or(b);
        assert!(either.missing(&provided(&["b"], &[])).is_none());
        assert!(either.missing(&provided(&["c"], &[])).is_some());
        assert_eq!(either.referenced(), provided(&["a", "b"], &[]));
        let with_key = RequiredAuth::namespaces(["a"]).with_extra_keys(set(&["k"]));
        assert_eq!(
            with_key.missing(&provided(&["a"], &[])),
            Some(provided(&[], &["k"]))
        );
        assert!(with_key.missing(&provided(&["a"], &["k"])).is_none());
    }

    #[test]
    fn every_proto_code_round_trips_and_reserved_codes_do_not_parse() {
        for code in Code::ALL {
            assert_eq!(Code::from_proto(code as i32), Some(code));
        }
        for reserved in [0, 2, 10, 14, 15, 16, 21] {
            assert_eq!(Code::from_proto(reserved), None, "{reserved}");
        }
    }
}
