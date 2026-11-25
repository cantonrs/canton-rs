//! Who the sequencer serves, and with which keys, follows the topology in force: the [`Registry`] is changed by every topology
//! transaction the state takes, as the official sequencer's `MemberAuthenticationService.observed` reacts to them.
//!
//! - a replaced `OwnerToKeyMapping` gives the member the keys it names (a key it no longer names neither authenticates nor signs, and the
//!   tokens given for it stop working);
//! - a removed `OwnerToKeyMapping`, a removed `SynchronizerTrustCertificate` (participant) or a `MediatorSynchronizerState` that no longer
//!   names a mediator disables the member: no challenge, no token, and its open subscription ends.
//!
//! [CANTON-NOTE: LIMITATION] A change acts when the state takes it (the head state), not after the topology change delay: Canton refuses
//! a member that is inactive in the head state too (`isMemberActive` checks both), but verifies a signature against the keys effective at
//! the time. A sequencer that leaves its group is not followed: the state does not take `SequencerSynchronizerState` changes.
use crate::onboarding::{Registered, Registry};
use crate::synchronizer_state::TopologyStore;
use canton_algo::signing::{PublicKey, Usage};
use canton_participant::topology_state::{broadcast_transactions, decode, Outcome};
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::{public_key::Key, SigningKeyUsage};
use canton_proto::com::digitalasset::canton::protocol::v30::OwnerToKeyMapping;
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use std::collections::{BTreeMap, BTreeSet};

/// `TopologyChangeOp.Remove` as the proto numbers it.
const REMOVE: i32 = 2;

/// The signing keys of a key mapping that may be used for `usage`; `None` gives every signing key.
///
/// [CANTON-NOTE: SEMANTICS] A key signs only what its usage says: a key registered for sequencer authentication does not sign submissions or
/// responses (the official sequencer refuses such a signature with `SignatureWithWrongKey`, measured). A key without usages has every
/// usage (`SigningKeyUsage.fromProtoListWithDefaultV30`).
fn signing_keys(m: &OwnerToKeyMapping, usage: Option<SigningKeyUsage>) -> Vec<PublicKey> {
    m.public_keys
        .iter()
        .filter_map(|k| match &k.key {
            Some(Key::SigningPublicKey(s))
                if usage.is_none_or(|u| s.usage.is_empty() || s.usage.contains(&(u as i32))) =>
            {
                canton_algo::signing::parse_public_key(s).ok()
            }
            _ => None,
        })
        .collect()
}

/// The keys of `m` that may be used for `usage`.
pub(crate) fn keys_for(m: &OwnerToKeyMapping, usage: SigningKeyUsage) -> Vec<PublicKey> {
    signing_keys(m, Some(usage))
}

/// `keys` made usable to answer an authentication challenge whatever usage their mapping gives them.
///
/// [CANTON-NOTE: DEFENSIVE] A mediator registered by hand or from its group (the Rust mediator's mapping has one key, for the protocol)
/// authenticates with its signing keys; the official node would refuse those keys for `SequencerAuthenticationOnly`.
pub(crate) fn for_authentication(mut keys: Vec<PublicKey>) -> Vec<PublicKey> {
    for key in &mut keys {
        key.usage.insert(Usage::SequencerAuthentication);
    }
    keys
}

/// Takes what the transactions of a topology broadcast (`content`) changed for the members, once the state took them with `outcomes`.
pub fn follow_broadcast(
    registry: &Registry,
    store: &TopologyStore,
    content: &[u8],
    outcomes: &[Outcome],
) {
    let Some(stored) = broadcast_transactions(content) else {
        return;
    };
    let mut groups_changed = false;
    for (raw, outcome) in stored.into_iter().zip(outcomes) {
        if !outcome.is_in_force() {
            continue;
        }
        let Ok(entries) = decode(&[(0, raw)]) else {
            continue;
        };
        let Some(entry) = entries.first() else {
            continue;
        };
        let removed = entry.tx.operation == REMOVE;
        match entry.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) {
            Some(Mapping::OwnerToKeyMapping(m)) if removed => registry.disable(&m.member),
            Some(Mapping::OwnerToKeyMapping(m)) => {
                if let Some(previous) = registry.get(&m.member) {
                    registry.insert(rekeyed(previous, m, store));
                }
            }
            Some(Mapping::SynchronizerTrustCertificate(c)) if removed => {
                registry.disable(&format!("PAR::{}", c.participant_uid));
            }
            Some(Mapping::MediatorSynchronizerState(_)) => groups_changed = true,
            _ => {}
        }
    }
    if groups_changed {
        let named = named_mediators(store);
        for member in registry.members() {
            if member.starts_with("MED::") && !named.contains(&member) {
                registry.disable(&member);
            }
        }
    }
}

/// `previous` with the keys of the mapping `m` now in force: the keys `m` gives the usage, and the keys `previous` had that `m` still names
/// (a mediator registered by hand or from its group authenticates with keys whose usage does not say so).
fn rekeyed(previous: Registered, m: &OwnerToKeyMapping, store: &TopologyStore) -> Registered {
    let named = signing_keys(m, None);
    let keep = |had: &[PublicKey], usage: SigningKeyUsage| {
        let mut keys = keys_for(m, usage);
        for k in had {
            if named.iter().any(|n| n.id == k.id) && !keys.iter().any(|x| x.id == k.id) {
                keys.push(k.clone());
            }
        }
        keys
    };
    Registered {
        signing_keys: keep(&previous.signing_keys, SigningKeyUsage::Protocol),
        authentication_keys: keep(
            &previous.authentication_keys,
            SigningKeyUsage::SequencerAuthentication,
        ),
        encryption_keys: store.encryption_keys_of(&m.member),
        member: previous.member,
    }
}

/// The member ids of every mediator a group in force names (active or observer).
fn named_mediators(store: &TopologyStore) -> BTreeSet<String> {
    store
        .mediator_groups_at(i64::MAX)
        .values()
        .flat_map(|g| g.active.iter().chain(&g.observers))
        .map(|uid| format!("MED::{uid}"))
        .collect()
}

/// Every member the state in force serves, with its keys: a member with a key mapping in force, and for a participant a trust certificate in
/// force, for a mediator a group that names it (`isParticipantActive`, `isMediatorActive`).
pub(crate) fn in_force(store: &TopologyStore) -> Vec<Registered> {
    let stored: Vec<(i64, Vec<u8>)> = store
        .snapshot()
        .iter()
        .filter(|e| !e.signed.proposal)
        .map(|e| (e.valid_from_micros, tw::stored_form(&e.signed)))
        .collect();
    let Ok(entries) = decode(&stored) else {
        return Vec::new();
    };
    // of each member's mapping and each participant's certificate, the transaction with the highest serial
    let mut mappings: BTreeMap<&str, (u32, Option<&OwnerToKeyMapping>)> = BTreeMap::new();
    let mut certified: BTreeMap<&str, (u32, bool)> = BTreeMap::new();
    for e in &entries {
        let (serial, removed) = (e.tx.serial, e.tx.operation == REMOVE);
        match e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) {
            Some(Mapping::OwnerToKeyMapping(m))
                if mappings
                    .get(m.member.as_str())
                    .is_none_or(|(s, _)| serial >= *s) =>
            {
                mappings.insert(&m.member, (serial, (!removed).then_some(m)));
            }
            Some(Mapping::SynchronizerTrustCertificate(c))
                if certified
                    .get(c.participant_uid.as_str())
                    .is_none_or(|(s, _)| serial >= *s) =>
            {
                certified.insert(&c.participant_uid, (serial, !removed));
            }
            _ => {}
        }
    }
    let mediators = named_mediators(store);
    mappings
        .into_iter()
        .filter_map(|(member, (_, m))| Some((member, m?)))
        .filter(|(member, _)| match member.split_once("::") {
            Some(("PAR", uid)) => certified.get(uid).is_some_and(|(_, on)| *on),
            Some(("MED", _)) => mediators.contains(*member),
            _ => true,
        })
        .map(|(member, m)| Registered {
            member: member.to_string(),
            signing_keys: keys_for(m, SigningKeyUsage::Protocol),
            authentication_keys: keys_for(m, SigningKeyUsage::SequencerAuthentication),
            encryption_keys: store.encryption_keys_of(member),
        })
        .collect()
}
