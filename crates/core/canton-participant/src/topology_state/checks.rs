//! `RequiredTopologyMappingChecks`: the invariants every transaction keeps against the state in force, before its authorization is
//! looked at (T-12). The texts name the node's rejection.
//!
//! [CANTON-NOTE: LIMITATION] Without synchronizer parameters in force (`DynamicSynchronizerParameters` for onboarding restriction;
//! `StaticSynchronizerParameters` / `Tracker::set_crypto_specs` for `checkKeyMappingKeyCount` and supported signing/encryption specs)
//! those parameter-dependent checks are not enforced (a node bootstrap validates namespace delegations without synchronizer parameters).
use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::crypto::v30::public_key::Key;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    MediatorSynchronizerState, OwnerToKeyMapping, SynchronizerTrustCertificate,
};
use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;
use canton_proto::com::digitalasset::canton::protocol::v31::{
    PartyToParticipant, TopologyTransaction,
};

use super::auth::{hosting_state, unique_key, Code, UniqueKey};
use super::keys::parse_delegation;
use super::tracker::{Refusal, Tracker};
use super::REMOVE;

const SUBMISSION: i32 = 1;
/// `OnboardingRestriction`: unrestricted and open, unrestricted and locked, restricted and open, restricted and locked.
const UNRESTRICTED_LOCKED: i32 = 2;
const RESTRICTED_OPEN: i32 = 3;
const RESTRICTED_LOCKED: i32 = 4;

fn invalid(text: String) -> Result<(), Refusal> {
    Err(Refusal::Check(text))
}

impl Tracker {
    /// The mappings in force (a REMOVE is none) of `code`.
    fn in_force(&self, code: Code) -> impl Iterator<Item = &Mapping> {
        self.head
            .range(
                UniqueKey {
                    code,
                    key: String::new(),
                }..,
            )
            .take_while(move |(k, _)| k.code == code)
            .filter(|(_, (tx, _))| tx.operation != REMOVE)
            .filter_map(|(_, (tx, _))| tx.mapping.as_ref()?.mapping.as_ref())
    }

    fn has_keys(&self, member: &str) -> bool {
        self.head
            .get(&UniqueKey {
                code: Code::OwnerToKeyMapping,
                key: member.to_string(),
            })
            .is_some_and(|(tx, _)| tx.operation != REMOVE)
    }

    fn has_certificate(&self, participant_uid: &str) -> bool {
        self.in_force(Code::SynchronizerTrustCertificate)
            .any(|m| matches!(m, Mapping::SynchronizerTrustCertificate(c) if c.participant_uid == participant_uid))
    }

    /// `RequiredTopologyMappingChecks.checkTransaction`, the parts that do not depend on the mapping, then the mapping's own.
    pub(super) fn required_checks(
        &self,
        mapping: &Mapping,
        operation: i32,
        serial: u32,
        previous: Option<&TopologyTransaction>,
        effective: Option<i64>,
    ) -> Result<(), Refusal> {
        let removing = operation == REMOVE;
        let previous_mapping = previous.and_then(|p| p.mapping.as_ref()?.mapping.as_ref());
        let is_root_certificate = matches!(
            mapping,
            Mapping::NamespaceDelegation(d) if matches!(parse_delegation(d), Ok(Some(ref x)) if x.is_root())
        );
        if removing && previous.is_none() && !is_root_certificate {
            return invalid(format!(
                "NoCorrespondingActiveTxToRevoke: no transaction in force to remove for {:?}",
                Code::of(mapping)
            ));
        }
        if !removing && serial >= i32::MAX.unsigned_abs() {
            return invalid(format!(
                "The serial for a REPLACE must be less than {}.",
                i32::MAX
            ));
        }
        if let (true, Some(expected)) = (removing, previous_mapping) {
            let changed = match (mapping, expected) {
                // removing a certificate need not repeat its feature flags
                (
                    Mapping::SynchronizerTrustCertificate(_),
                    Mapping::SynchronizerTrustCertificate(_),
                ) => unique_key(mapping) != unique_key(expected),
                _ => mapping != expected,
            };
            if changed {
                return invalid(
                    "RemoveMustNotChangeMapping: a REMOVE must name the mapping it removes".into(),
                );
            }
        }
        let previous_replace = previous
            .filter(|p| p.operation != REMOVE)
            .and(previous_mapping);
        // [CANTON-NOTE: SEMANTICS] `TopologyMappingChecks.scala:415-427`: `checkKeyMappingKeyCount` runs on every `Replace` of a
        // `KeyMapping` (`OwnerToKeyMapping`, `PartyToKeyMapping`, `PartyToParticipant`) before mapping-specific checks.
        if !removing {
            let key_count = match mapping {
                Mapping::OwnerToKeyMapping(m) => Some(m.public_keys.len()),
                #[expect(
                    deprecated,
                    reason = "PartyToKeyMapping is a deprecated v31 variant still subject to KeyMapping max-keys checks"
                )]
                Mapping::PartyToKeyMapping(p) => Some(p.signing_keys.len()),
                Mapping::PartyToParticipant(p) => {
                    Some(p.party_signing_keys.as_ref().map_or(0, |k| k.keys.len()))
                }
                _ => None,
            };
            if let Some(count) = key_count {
                self.check_key_count(count)?;
            }
        }
        match mapping {
            Mapping::SynchronizerParametersState(_) if removing => {
                invalid("CannotRemoveMapping: the synchronizer parameters cannot be removed".into())
            }
            Mapping::SynchronizerTrustCertificate(c) if !removing => {
                self.check_certificate(c, previous, effective)
            }
            Mapping::PartyToParticipant(p) if !removing => {
                self.check_not_self_signed_with_a_revoked_root(p)?;
                match previous_replace {
                    Some(Mapping::PartyToParticipant(before)) => {
                        self.check_hosting(p, Some(before))
                    }
                    _ => self.check_hosting(p, None),
                }
            }
            Mapping::OwnerToKeyMapping(m) if removing => self.check_key_removal(m),
            Mapping::OwnerToKeyMapping(m) => self.check_keys(m, previous),
            #[expect(
                deprecated,
                reason = "PartyToKeyMapping key count is already checked above for all KeyMapping variants"
            )]
            Mapping::PartyToKeyMapping(_) if !removing => Ok(()),
            Mapping::SequencerSynchronizerState(s) if !removing => self.check_sequencers(s),
            Mapping::MediatorSynchronizerState(m) if !removing => match previous_replace {
                Some(Mapping::MediatorSynchronizerState(before)) => {
                    self.check_mediators(m, Some(before))
                }
                _ => self.check_mediators(m, None),
            },
            Mapping::DecentralizedNamespaceDefinition(d) if !removing => {
                let namespace = &d.decentralized_namespace;
                if self.in_force(Code::NamespaceDelegation).any(
                    |m| matches!(m, Mapping::NamespaceDelegation(n) if n.namespace == *namespace),
                ) {
                    return invalid(format!("NamespaceAlreadyInUse: {namespace}"));
                }
                let rooted: BTreeSet<&str> = self
                    .in_force(Code::NamespaceDelegation)
                    .filter_map(|m| match m {
                        Mapping::NamespaceDelegation(n)
                            if matches!(parse_delegation(n), Ok(Some(ref x)) if x.is_root()) =>
                        {
                            Some(n.namespace.as_str())
                        }
                        _ => None,
                    })
                    .collect();
                let missing: Vec<&String> = d
                    .owners
                    .iter()
                    .filter(|o| !rooted.contains(o.as_str()))
                    .collect();
                if missing.is_empty() {
                    Ok(())
                } else {
                    invalid(format!("No root certificate found for {missing:?}"))
                }
            }
            Mapping::NamespaceDelegation(d) if !removing => {
                if self.in_force(Code::DecentralizedNamespaceDefinition).any(|m| {
                    matches!(m, Mapping::DecentralizedNamespaceDefinition(x) if x.decentralized_namespace == d.namespace)
                }) {
                    return invalid(format!("NamespaceAlreadyInUse: {}", d.namespace));
                }
                if previous.is_some_and(|p| p.operation == REMOVE) {
                    return invalid(format!(
                        "NamespaceHasBeenRevoked: the delegation of namespace {} to this key was removed",
                        d.namespace
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// `checkSynchronizerTrustCertificateReplace`.
    fn check_certificate(
        &self,
        c: &SynchronizerTrustCertificate,
        previous: Option<&TopologyTransaction>,
        effective: Option<i64>,
    ) -> Result<(), Refusal> {
        let participant = &c.participant_uid;
        if previous.is_some_and(|p| p.operation == REMOVE) {
            return invalid(format!(
                "ParticipantCannotRejoinSynchronizer: {participant} left the synchronizer"
            ));
        }
        let party_of_same_uid = self
            .in_force(Code::PartyToParticipant)
            .find_map(|m| match m {
                Mapping::PartyToParticipant(p) if p.party == *participant => Some(p),
                _ => None,
            });
        if party_of_same_uid.is_some_and(|p| !is_explicit_admin_party(p)) {
            return invalid(format!(
                "ParticipantIdConflictWithPartyId: a party {participant} exists"
            ));
        }
        let restriction = self
            .parameters
            .as_ref()
            .map_or(0, |p| p.onboarding_restriction);
        let refused = || {
            invalid(format!(
                "OnboardingRestrictionInPlace: {participant} may not join under the restriction {restriction}"
            ))
        };
        match restriction {
            UNRESTRICTED_LOCKED | RESTRICTED_LOCKED => return refused(),
            RESTRICTED_OPEN => {
                let permission = self
                    .head
                    .get(&UniqueKey {
                        code: Code::ParticipantPermission,
                        key: format!("{}/{participant}", c.synchronizer_id),
                    })
                    .filter(|(tx, _)| tx.operation != REMOVE)
                    .and_then(|(tx, _)| match tx.mapping.as_ref()?.mapping.as_ref()? {
                        Mapping::ParticipantPermission(p) => Some(p),
                        _ => None,
                    });
                match permission {
                    None => return refused(),
                    Some(p) if p.login_after.zip(effective).is_some_and(|(l, e)| l > e) => {
                        return refused()
                    }
                    Some(_) => {}
                }
            }
            _ => {}
        }
        if !self.has_keys(&format!("PAR::{participant}")) {
            return invalid(format!("InsufficientKeys: {participant} has no keys"));
        }
        Ok(())
    }

    /// `checkPartyToParticipant`.
    fn check_hosting(
        &self,
        p: &PartyToParticipant,
        before: Option<&PartyToParticipant>,
    ) -> Result<(), Refusal> {
        let mut seen = BTreeSet::new();
        let duplicates: BTreeSet<&str> = p
            .participants
            .iter()
            .map(|h| h.participant_uid.as_str())
            .filter(|uid| !seen.insert(*uid))
            .collect();
        if !duplicates.is_empty() {
            return invalid(format!("Duplicate participants ids: {duplicates:?}"));
        }
        let protocol_37 = self
            .current_psid
            .as_ref()
            .is_some_and(|psid| psid.protocol_version >= 37);
        if protocol_37 {
            let backward: Vec<String> = p
                .participants
                .iter()
                .filter_map(|h| {
                    let prev = before?
                        .participants
                        .iter()
                        .find(|b| b.participant_uid == h.participant_uid)?;
                    (hosting_state(prev) > hosting_state(h)).then(|| {
                        format!(
                            "{}: {} -> {}",
                            h.participant_uid,
                            hosting_state(prev),
                            hosting_state(h)
                        )
                    })
                })
                .collect();
            if !backward.is_empty() {
                return invalid(format!(
                    "Invalid hosting state transitions for party {}: {}",
                    p.party,
                    backward.join(", ")
                ));
            }
        }
        if self.has_certificate(&p.party) && !is_explicit_admin_party(p) {
            return invalid(format!("PartyIdConflictWithAdminParty: {}", p.party));
        }
        let new: Vec<&str> = p
            .participants
            .iter()
            .map(|h| h.participant_uid.as_str())
            .filter(|uid| {
                before.is_none_or(|b| !b.participants.iter().any(|h| h.participant_uid == *uid))
            })
            .collect();
        let unknown: Vec<&str> = new
            .iter()
            .copied()
            .filter(|uid| !self.has_certificate(uid))
            .collect();
        if !unknown.is_empty() {
            return invalid(format!("UnknownMembers: {unknown:?}"));
        }
        let without_keys: Vec<&str> = new
            .iter()
            .copied()
            .filter(|uid| !self.has_keys(&format!("PAR::{uid}")))
            .collect();
        if !without_keys.is_empty() {
            return invalid(format!("InsufficientKeys: {without_keys:?}"));
        }
        Ok(())
    }

    /// `checkOwnerToKeyMappingRemove`: the keys of a participant with a trust certificate, or of a mediator in a group, stay.
    fn check_key_removal(&self, m: &OwnerToKeyMapping) -> Result<(), Refusal> {
        let still_used = if let Some(uid) = m.member.strip_prefix("PAR::") {
            self.has_certificate(uid)
        } else if let Some(uid) = m.member.strip_prefix("MED::") {
            self.mediator_groups
                .values()
                .any(|g| g.active.iter().chain(&g.observers).any(|x| x == uid))
        } else if let Some(uid) = m.member.strip_prefix("SEQ::") {
            self.is_in_sequencer_group(uid)
        } else {
            false
        };
        if still_used {
            return invalid(format!(
                "InvalidOwnerToKeyMappingRemoval: {} is still a member of the synchronizer",
                m.member
            ));
        }
        Ok(())
    }

    /// `checkIsNotSelfSignedWithARevokedRootNSDKey`: a hosting that lists the party's namespace key among its signing keys
    /// (`isSelfSigned`) is refused when a root certificate of that namespace was removed.
    fn check_not_self_signed_with_a_revoked_root(
        &self,
        p: &PartyToParticipant,
    ) -> Result<(), Refusal> {
        let namespace = p.party.rsplit_once("::").map_or("", |(_, ns)| ns);
        let self_signed = p.party_signing_keys.as_ref().is_some_and(|k| {
            k.keys
                .iter()
                .any(|key| super::keys::key_fingerprint(&key.public_key) == namespace)
        });
        let revoked = self
            .head
            .range(
                UniqueKey {
                    code: Code::NamespaceDelegation,
                    key: String::new(),
                }..,
            )
            .take_while(|(k, _)| k.code == Code::NamespaceDelegation)
            .filter(|(_, (tx, _))| tx.operation == REMOVE)
            .filter_map(
                |(_, (tx, _))| match tx.mapping.as_ref()?.mapping.as_ref()? {
                    Mapping::NamespaceDelegation(d) => Some(d),
                    _ => None,
                },
            )
            .any(|d| {
                d.namespace == namespace
                    && matches!(parse_delegation(d), Ok(Some(ref x)) if x.is_root())
            });
        if self_signed && revoked {
            return invalid(format!(
                "NamespaceHasBeenRevoked: the namespace {namespace} has been revoked"
            ));
        }
        Ok(())
    }

    /// `checkSequencerSynchronizerStateReplace` with `SequencerSynchronizerState.create`: no duplicates, at least one active sequencer, a
    /// threshold of at most their number, keys for every new sequencer.
    fn check_sequencers(
        &self,
        s: &canton_proto::com::digitalasset::canton::protocol::v30::SequencerSynchronizerState,
    ) -> Result<(), Refusal> {
        no_duplicates(&s.active, "active")?;
        no_duplicates(&s.observers, "observers")?;
        let all: Vec<String> = s.active.iter().chain(&s.observers).cloned().collect();
        no_duplicates(&all, "across active and observers")?;
        if s.active.is_empty() {
            return invalid(
                "sequencer synchronizer state requires at least one active sequencer".into(),
            );
        }
        if s.active.len() < usize::try_from(s.threshold).unwrap_or(usize::MAX) {
            return invalid(format!(
                "threshold ({}) of sequencer synchronizer state higher than number of active sequencers {}",
                s.threshold,
                s.active.len()
            ));
        }
        let without_keys: Vec<&String> = all
            .iter()
            .filter(|uid| !self.is_in_sequencer_group(uid))
            .filter(|uid| !self.has_keys(&format!("SEQ::{uid}")))
            .collect();
        if !without_keys.is_empty() {
            return invalid(format!("InsufficientKeys: {without_keys:?}"));
        }
        Ok(())
    }

    /// `checkMediatorSynchronizerStateReplace`.
    fn check_mediators(
        &self,
        m: &MediatorSynchronizerState,
        before: Option<&MediatorSynchronizerState>,
    ) -> Result<(), Refusal> {
        no_duplicates(&m.active, "active")?;
        no_duplicates(&m.observers, "observers")?;
        let all: Vec<String> = m.active.iter().chain(&m.observers).cloned().collect();
        no_duplicates(&all, "across active and observers")?;
        // `MediatorSynchronizerState.create`: the node cannot even read a group without an active mediator
        if m.active.is_empty() {
            return invalid(
                "mediator synchronizer state requires at least one active mediator".into(),
            );
        }
        if m.active.len() < usize::try_from(m.threshold).unwrap_or(usize::MAX) {
            return invalid(format!(
                "Threshold {} is larger than num active {}",
                m.threshold,
                m.active.len()
            ));
        }
        let new: Vec<&String> = all
            .iter()
            .filter(|x| before.is_none_or(|b| !b.active.contains(x) && !b.observers.contains(x)))
            .collect();
        let elsewhere: Vec<String> = self
            .mediator_groups
            .iter()
            .filter(|(group, _)| **group != m.group)
            .flat_map(|(group, g)| {
                g.active
                    .iter()
                    .chain(&g.observers)
                    .filter(|x| new.contains(x))
                    .map(move |x| format!("{x} in group {group}"))
            })
            .collect();
        if !elsewhere.is_empty() {
            return invalid(format!(
                "MediatorsAlreadyInOtherGroups: group {}: {elsewhere:?}",
                m.group
            ));
        }
        let without_keys: Vec<&&String> = new
            .iter()
            .filter(|uid| !self.has_keys(&format!("MED::{uid}")))
            .collect();
        if !without_keys.is_empty() {
            return invalid(format!("InsufficientKeys: {without_keys:?}"));
        }
        Ok(())
    }

    /// `checkKeyMappingKeyCount`: enforces `KeyMapping.maxKeys(maxSigningKeysPerEntity)` for PV >= 37 (or default 20 below PV 37).
    fn check_key_count(&self, count: usize) -> Result<(), Refusal> {
        const DEFAULT_MAX_KEYS: usize = 20;
        let Some(specs) = &self.crypto_specs else {
            return Ok(());
        };
        let protocol_37_or_newer = self
            .current_psid
            .as_ref()
            .is_none_or(|psid| psid.protocol_version >= 37);
        let max_keys = if protocol_37_or_newer {
            specs
                .max_signing_keys_per_entity
                .and_then(|n| usize::try_from(n).ok())
                .filter(|&n| n > 0)
                .unwrap_or(DEFAULT_MAX_KEYS)
        } else {
            DEFAULT_MAX_KEYS
        };
        if count > max_keys {
            return invalid(format!(
                "InvalidTopologyMapping: At most {max_keys} key(s) can be specified, got {count}."
            ));
        }
        Ok(())
    }

    /// `checkOwnerToKeyMappingReplace`: key count bound, no keys again after a REMOVE, at least one signing key (in required specs), and
    /// an encryption key (in required specs) for a participant.
    fn check_keys(
        &self,
        m: &OwnerToKeyMapping,
        previous: Option<&TopologyTransaction>,
    ) -> Result<(), Refusal> {
        self.check_key_count(m.public_keys.len())?;
        if previous.is_some_and(|p| p.operation == REMOVE) {
            return invalid(format!(
                "CannotReregisterKeys: the keys of {} were removed",
                m.member
            ));
        }
        let specs = self.crypto_specs.as_ref();
        let has_signing = m.public_keys.iter().any(|k| match &k.key {
            Some(Key::SigningPublicKey(sk)) => specs
                .is_none_or(|s| s.signing_keys.is_empty() || s.signing_keys.contains(&sk.key_spec)),
            _ => false,
        });
        if !has_signing {
            let detail = if specs.is_some() {
                "has no signing key matching required specs"
            } else {
                "has no signing key"
            };
            return invalid(format!("InvalidOwnerToKeyMapping: {} {detail}", m.member));
        }
        let has_encryption = m.public_keys.iter().any(|k| match &k.key {
            Some(Key::EncryptionPublicKey(ek)) => specs.is_none_or(|s| {
                s.encryption_keys.is_empty() || s.encryption_keys.contains(&ek.key_spec)
            }),
            _ => false,
        });
        if m.member.starts_with("PAR::") && !has_encryption {
            let detail = if specs.is_some() {
                "has no encryption key matching required specs"
            } else {
                "has no encryption key"
            };
            return invalid(format!(
                "InvalidOwnerToKeyMapping: the participant {} {detail}",
                m.member
            ));
        }
        Ok(())
    }
}

/// `isExplicitAdminPartyAllocation`: hosted by the participant of the same uid only, with submission permission, threshold 1.
fn is_explicit_admin_party(p: &PartyToParticipant) -> bool {
    p.threshold == 1
        && matches!(p.participants.as_slice(), [h] if h.participant_uid == p.party && h.permission == SUBMISSION)
}

fn no_duplicates(ids: &[String], what: &str) -> Result<(), Refusal> {
    let mut seen = BTreeSet::new();
    let duplicates: BTreeSet<&String> = ids.iter().filter(|x| !seen.insert(*x)).collect();
    if duplicates.is_empty() {
        Ok(())
    } else {
        invalid(format!("Duplicate {what} ids: {duplicates:?}"))
    }
}
