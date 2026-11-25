//! The server's check of the identity a participant registers when it first connects (`RegisterOnboardingTopologyTransactions`).
//!
//! The participant sends its own topology transactions: the **namespace delegation** of its root key, the **owner-to-key mapping** of its
//! keys and the **synchronizer trust certificate**. This is the check the official sequencer makes (the refusals below are the ones
//! it gives, measured in G5 S-NET-002 against the official node): exactly one trust certificate for a participant, every mapping about
//! the member that registers, and signatures that verify and authorize. The authorization rules are the ones `Tracker` follows for a
//! participant reading a synchronizer's topology; this module reuses it with an empty state, so there is one set of rules, not two.
//!
//! [CANTON-NOTE: LIMITATION] The registered identity is kept in memory (no topology store, no effective times), and the check is for a
//! participant (a mediator's or a sequencer's onboarding is not served).
use canton_participant::topology_state::{decode, Tracker};
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::SigningKeyUsage;
use canton_proto::com::digitalasset::canton::protocol::v30::SignedTopologyTransaction;
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use tonic::Status;

/// What a member registered: its signing keys and its encryption keys, as the accepted mapping lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub member: String,
    pub signing_keys: Vec<canton_algo::signing::PublicKey>,
    /// The signing keys whose usage lists sequencer authentication: the keys a challenge may be answered with.
    pub authentication_keys: Vec<canton_algo::signing::PublicKey>,
    pub encryption_keys: Vec<canton_participant::topology_state::EncryptionKey>,
}

/// The members the sequencer serves, by member id, with the keys the topology in force gives them (see [`crate::membership`]).
#[derive(Default)]
pub struct Registry {
    members: Mutex<Members>,
}

#[derive(Default)]
struct Members {
    active: BTreeMap<String, Registered>,
    /// The members the topology took away (a removed trust certificate or key mapping, a mediator no group names): refused as disabled,
    /// not as unknown.
    disabled: BTreeSet<String>,
}

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Members> {
        self.members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn is_registered(&self, member: &str) -> bool {
        self.lock().active.contains_key(member)
    }

    /// Whether the topology took `member` away after it was served (`MemberAccessDisabled`).
    pub fn is_disabled(&self, member: &str) -> bool {
        self.lock().disabled.contains(member)
    }

    /// The ids of the members that registered.
    pub fn members(&self) -> Vec<String> {
        self.lock().active.keys().cloned().collect()
    }

    pub fn get(&self, member: &str) -> Option<Registered> {
        self.lock().active.get(member).cloned()
    }

    /// Whether `member` is served and the key with `fingerprint` is one it authenticates with now: what a token given for that key needs.
    pub fn authenticates_with(&self, member: &str, fingerprint: &str) -> bool {
        self.lock()
            .active
            .get(member)
            .is_some_and(|r| r.authentication_keys.iter().any(|k| k.id == fingerprint))
    }

    pub fn insert(&self, registered: Registered) {
        let mut members = self.lock();
        members.disabled.remove(&registered.member);
        members.active.insert(registered.member.clone(), registered);
    }

    /// The topology took `member` away: it is no longer served.
    pub fn disable(&self, member: &str) {
        let mut members = self.lock();
        if members.active.remove(member).is_some() {
            members.disabled.insert(member.to_string());
        }
    }
}

fn refused(why: &str) -> Status {
    // the official sequencer answers a bad registration with "not in a state required" (FAILED_PRECONDITION)
    Status::failed_precondition(why.to_string())
}

/// Checks the transactions `member` (`PAR::name::fingerprint`) sent for onboarding on the synchronizer `synchronizer_uid`
/// (`name::fingerprint`) and returns what it registered.
pub fn validate(
    member: &str,
    synchronizer_uid: &str,
    transactions: &[SignedTopologyTransaction],
) -> Result<Registered, Status> {
    let uid = member
        .strip_prefix("PAR::")
        .ok_or_else(|| refused("only a participant can onboard"))?;
    let namespace = uid.rsplit("::").next().unwrap_or_default();
    let stored: Vec<Vec<u8>> = transactions.iter().map(tw::stored_form).collect();
    let entries =
        decode(&stored.iter().cloned().map(|s| (0, s)).collect::<Vec<_>>()).map_err(|e| {
            refused(&format!(
                "Unable to register onboarding topology transactions: {e}"
            ))
        })?;
    // exactly one trust certificate
    let certificates: Vec<_> = entries
        .iter()
        .filter_map(|e| match e.tx.mapping.as_ref()?.mapping.as_ref()? {
            Mapping::SynchronizerTrustCertificate(c) => Some(c),
            _ => None,
        })
        .collect();
    if certificates.len() != 1 {
        return Err(refused(
            "Exactly one SynchronizerTrustCertificate is required for Participants",
        ));
    }
    // every transaction is about this member
    for e in &entries {
        let unexpected = match e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) {
            Some(Mapping::NamespaceDelegation(d)) => d.namespace != namespace,
            Some(Mapping::OwnerToKeyMapping(m)) => m.member != member,
            Some(Mapping::SynchronizerTrustCertificate(c)) => c.participant_uid != uid,
            _ => true,
        };
        if unexpected {
            return Err(refused(&format!(
                "Mappings for unexpected UIDs for onboarding: not about {uid}"
            )));
        }
    }
    // the certificate is for this synchronizer
    if certificates[0].synchronizer_id != synchronizer_uid {
        return Err(refused(
            "Unable to register onboarding topology transactions: the trust certificate is for another synchronizer",
        ));
    }
    // signatures and authorization: the delegations first (they make the key that signs the rest), then the key mapping, through the same
    // tracker a participant follows a synchronizer's topology with
    let mut tracker = Tracker::from_state(&[], member);
    tracker.set_current_psid(canton_participant::topology_state::Psid {
        logical: synchronizer_uid.to_string(),
        serial: 0,
        protocol_version: crate::PROTOCOL_VERSION,
    });
    tracker.set_crypto_specs(canton_participant::crypto_handshake::Required::from_v32(
        &crate::static_parameters(0),
    ));
    let is_kind = |e: &&canton_participant::topology_state::Entry, delegation: bool| {
        matches!(
            e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()),
            Some(Mapping::NamespaceDelegation(_))
        ) == delegation
    };
    let mut delegated = false;
    for (stored, e) in stored.iter().zip(&entries) {
        if !is_kind(&e, true) {
            continue;
        }
        let outcome = tracker.apply(stored).outcome;
        if !outcome.is_in_force() {
            return Err(refused(&format!(
                "Unable to register onboarding topology transactions: {}",
                outcome.note()
            )));
        }
        delegated = true;
    }
    if !delegated {
        return Err(refused(
            "Unable to register onboarding topology transactions: no namespace delegation",
        ));
    }
    let mut registered = None;
    for (stored, e) in stored.iter().zip(&entries) {
        match e.tx.mapping.as_ref().and_then(|m| m.mapping.as_ref()) {
            Some(Mapping::OwnerToKeyMapping(m)) => {
                let outcome = tracker.apply(stored).outcome;
                if !outcome.is_in_force() {
                    return Err(refused(&format!(
                        "Unable to register onboarding topology transactions: {}",
                        outcome.note()
                    )));
                }
                let learned = tracker.learned();
                let signing_keys = crate::membership::keys_for(m, SigningKeyUsage::Protocol);
                let authentication_keys =
                    crate::membership::keys_for(m, SigningKeyUsage::SequencerAuthentication);
                registered = Some(Registered {
                    member: member.to_string(),
                    signing_keys,
                    authentication_keys,
                    encryption_keys: learned
                        .encryption_keys
                        .get(member)
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            Some(Mapping::SynchronizerTrustCertificate(_)) => {
                // authorized in the participant's namespace, through the same graph as everything else
                let outcome = tracker.apply(stored).outcome;
                if !outcome.is_in_force() {
                    return Err(refused(&format!(
                        "Unable to register onboarding topology transactions: the trust certificate is not signed in the namespace ({})",
                        outcome.note()
                    )));
                }
            }
            _ => {}
        }
    }
    registered.ok_or_else(|| {
        refused("Unable to register onboarding topology transactions: no key mapping")
    })
}

/// Inspects a topology broadcast's envelope `content` for a participant's onboarding transactions (`NamespaceDelegation` + `OwnerToKeyMapping` +
/// `SynchronizerTrustCertificate` for `PAR::<uid>`). When valid and not yet registered, inserts the member into `registry` and writes an `R` line
/// to `journal` if attached. Used when a BFT-ordered topology broadcast delivers an onboarding registered through a peer sequencer.
pub fn register_onboarding_in_broadcast(
    content: &[u8],
    physical_synchronizer_id: &str,
    registry: &Registry,
    journal: Option<&std::sync::Arc<crate::persistence::Journal>>,
) -> bool {
    use prost::Message as _;
    let Some(stored_list) = canton_participant::topology_state::broadcast_transactions(content)
    else {
        return false;
    };
    let mut txs = Vec::with_capacity(stored_list.len());
    for raw in &stored_list {
        let Some((data, _)) = tw::unversioned(raw) else {
            return false;
        };
        let Ok(signed) = SignedTopologyTransaction::decode(data.as_slice()) else {
            return false;
        };
        txs.push(signed);
    }
    let items: Vec<(i64, Vec<u8>)> = stored_list.into_iter().map(|s| (0, s)).collect();
    let Ok(entries) = decode(&items) else {
        return false;
    };
    let participant_uid =
        entries
            .iter()
            .find_map(|e| match e.tx.mapping.as_ref()?.mapping.as_ref()? {
                Mapping::SynchronizerTrustCertificate(c) => Some(c.participant_uid.clone()),
                _ => None,
            });
    let Some(uid) = participant_uid else {
        return false;
    };
    let member = format!("PAR::{uid}");
    if registry.is_registered(&member) {
        return false;
    }
    let sync_uid = physical_synchronizer_id
        .rsplit_once("::")
        .map_or(physical_synchronizer_id, |(prefix, _)| prefix);
    let Ok(registered) = validate(&member, sync_uid, &txs) else {
        return false;
    };
    if let Some(j) = journal {
        j.write(&crate::persistence::registration_line(&member, &txs));
    }
    registry.insert(registered);
    crate::diag::diag_eprintln!("BFT topology broadcast registered participant {member}");
    true
}
