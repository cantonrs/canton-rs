//! Keys as topology transactions carry them: fingerprints, the usages a signing key is allowed, the signature check, and a namespace
//! delegation parsed as the node parses it (`NamespaceDelegation.fromProtoV30` / `create`).
use std::collections::BTreeSet;

use canton_algo::member_signature::{namespace_or_proof_of_ownership, verify_by_keys};
use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::{Signature, SigningPublicKey};
use canton_proto::com::digitalasset::canton::protocol::v30::namespace_delegation::Restriction as RestrictionProto;
use canton_proto::com::digitalasset::canton::protocol::v30::NamespaceDelegation;

use super::auth::Code;
use crate::topology_wire as tw;

/// The raw 32 bytes of an Ed25519 DER SubjectPublicKeyInfo (a 12-byte header and the key).
pub fn ed25519_raw(public_key: &[u8]) -> Option<[u8; 32]> {
    (public_key.len() == 44).then(|| public_key[12..].try_into().ok())?
}

/// The fingerprint of a public key as signatures name it (`signed_by`): of the raw key for Ed25519, of the bytes otherwise.
pub fn key_fingerprint(public_key: &[u8]) -> String {
    ed25519_raw(public_key).map_or_else(|| tw::fingerprint(public_key), |raw| tw::fingerprint(&raw))
}

/// A signing key a topology mapping names, as `SigningPublicKey.fromProtoV30` reads it (any key spec); `None` for one that does not parse.
pub fn signing_key(key: &SigningPublicKey) -> Option<PublicKey> {
    canton_algo::signing::parse_public_key(key).ok()
}

/// Whether `signature` of a topology transaction's `hash` was made by `key`.
pub fn verifies(key: &PublicKey, hash: &[u8], signature: &Signature) -> bool {
    verify_by_keys(
        std::slice::from_ref(key),
        hash,
        signature,
        &namespace_or_proof_of_ownership(),
    )
    .is_ok()
}

/// `SigningKeyUsage`, without the retired identity delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Usage {
    Namespace,
    SequencerAuthentication,
    Protocol,
    ProofOfOwnership,
}

/// The usages of a signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usages(BTreeSet<Usage>);

impl Usages {
    /// `SigningKeyUsage.fromProtoListWithDefaultV30`: an unset or unknown value does not parse; the identity delegation usage is
    /// ignored; no usage at all means every usage (keys of before usages existed).
    pub fn parse(values: &[i32]) -> Result<Usages, String> {
        let mut usages = BTreeSet::new();
        for value in values {
            match value {
                1 => usages.insert(Usage::Namespace),
                2 => false,
                3 => usages.insert(Usage::SequencerAuthentication),
                4 => usages.insert(Usage::Protocol),
                5 => usages.insert(Usage::ProofOfOwnership),
                other => return Err(format!("the key usage {other} is not one")),
            };
        }
        if usages.is_empty() {
            usages = [
                Usage::Namespace,
                Usage::SequencerAuthentication,
                Usage::Protocol,
                Usage::ProofOfOwnership,
            ]
            .into();
        }
        Ok(Usages(usages))
    }

    /// `compatibleUsageForSignAndVerify`: the key has one of `allowed`.
    pub fn allows(&self, allowed: &[Usage]) -> bool {
        allowed.iter().any(|u| self.0.contains(u))
    }
}

/// `DelegationRestriction`: which mappings the target key of a delegation may sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restriction {
    All,
    AllButNamespaceDelegations,
    Specific(BTreeSet<Code>),
}

impl Restriction {
    pub fn can_sign(&self, code: Code) -> bool {
        match self {
            Restriction::All => true,
            Restriction::AllButNamespaceDelegations => code != Code::NamespaceDelegation,
            Restriction::Specific(codes) => codes.contains(&code),
        }
    }
}

/// A namespace delegation to a signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub namespace: String,
    pub target: PublicKey,
    pub target_fingerprint: String,
    pub restriction: Restriction,
}

impl Delegation {
    /// A root certificate's delegation: to the key the namespace is the fingerprint of.
    pub fn is_root(&self) -> bool {
        self.target_fingerprint == self.namespace
    }
}

/// `DelegationRestriction.MaxMappings`.
const MAX_SPECIFIC_MAPPINGS: usize = 50;

/// Parses a delegation as the node does. `Ok(None)`: a delegation to a key that does not parse as a signing key, which this tracker
/// does not follow.
///
/// [CANTON-NOTE: SEMANTICS] `NamespaceDelegation.create`: the target key must have the `Namespace` usage, and a root certificate must be
/// able to sign other delegations. Without a restriction, the deprecated `is_root_delegation` decides (`CanSignAllMappings` when set,
/// `CanSignAllButNamespaceDelegations` otherwise); with one, the flag must not be set.
#[expect(
    deprecated,
    reason = "is_root_delegation is deprecated in the proto but still decides the restriction of a delegation without one"
)]
pub fn parse_delegation(d: &NamespaceDelegation) -> Result<Option<Delegation>, String> {
    let Some(key) = d.target_key.as_ref() else {
        return Err(format!(
            "a delegation for namespace {} without a target key",
            d.namespace
        ));
    };
    let Some(target) = signing_key(key) else {
        return Ok(None);
    };
    let target_fingerprint = target.id.clone();
    let usages = Usages::parse(&key.usage)?;
    if !usages.allows(&[Usage::Namespace]) {
        return Err(format!(
            "The key {target_fingerprint} must include a Namespace usage."
        ));
    }
    let restriction = match &d.restriction {
        None if d.is_root_delegation => Restriction::All,
        None => Restriction::AllButNamespaceDelegations,
        Some(_) if d.is_root_delegation => {
            return Err(
                "is_root_delegation was set to true, but the list of mapping restrictions did not contain NamespaceDelegation"
                    .into(),
            )
        }
        Some(RestrictionProto::CanSignAllMappings(_)) => Restriction::All,
        Some(RestrictionProto::CanSignAllButNamespaceDelegations(_)) => {
            Restriction::AllButNamespaceDelegations
        }
        Some(RestrictionProto::CanSignSpecificMapings(s)) => {
            if s.mappings.is_empty() || s.mappings.len() > MAX_SPECIFIC_MAPPINGS {
                return Err(format!(
                    "a delegation restricted to {} mappings",
                    s.mappings.len()
                ));
            }
            let codes = s
                .mappings
                .iter()
                .map(|c| Code::from_proto(*c).ok_or_else(|| format!("unknown mapping code {c}")))
                .collect::<Result<BTreeSet<Code>, String>>()?;
            Restriction::Specific(codes)
        }
    };
    let delegation = Delegation {
        namespace: d.namespace.clone(),
        target,
        target_fingerprint,
        restriction,
    };
    if delegation.is_root() && !delegation.restriction.can_sign(Code::NamespaceDelegation) {
        return Err(format!(
            "Root certificate for {} needs to be be able to sign other NamespaceDelegations",
            d.namespace
        ));
    }
    Ok(Some(delegation))
}
