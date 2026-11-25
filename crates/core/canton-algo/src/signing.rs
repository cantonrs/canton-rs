//! Canton signing keys and the `Signature` message, accepted and refused as the Canton 3.7.2 node does (U-12, U-13 part i).
//!
//! - [`parse_public_key`] is `SigningPublicKey.fromProtoV30`: format and key spec (with the legacy `scheme` fallback), usages,
//!   the legacy DER/RAW migrations, and the key validation of `CryptoKeyValidation.parseAndValidatePublicKey`.
//! - [`parse_private_key`] is `SigningPrivateKey.fromProtoV30` and also derives the public key.
//! - [`parse_signature`] / [`parse_versioned_signature`] are `Signature.fromProtoV30` / `Signature.fromTrustedByteString`,
//!   reading the wire bytes as protobuf-java does.
//! - [`verify_signature`] is `JcePureCrypto.verifySignature`: the order of its checks and Bouncy Castle's signature rules.
//!
//! [CANTON-NOTE: ORACLE] Every rule here was measured on a Canton 3.7.2 node through the console
//! (tests/oracle/canton-crypto, `pk`, `sk`, `sg`, `sgp` lines, produced by scripts/gen-canton-crypto.py) and read from
//! `Signing.scala`, `CryptoKeyValidation.scala` and `JcePureCrypto.scala` of the same release.
//!
//! [CANTON-NOTE: LIMITATION] ML-DSA-65 (an experimental spec) is this crate's own FIPS 204 code (`mldsa65.rs`), accepted only by
//! [`verify_signature_allowing_experimental`]. It is checked by round trips of its own keys and signatures; no key or signature made
//! by the node (Bouncy Castle) and no NIST ACVP vector was compared with it, so agreement with the node is not established.
//! EC keys with explicit curve parameters, curves other than P-256, P-384 and secp256k1, PKCS#8 attributes and Ed25519
//! keys that mix a valid point with a torsion component were not measured.
//! [CANTON-NOTE: LIMITATION] The node's key validation is cached by key fingerprint, which does not include the key spec:
//! after a key was validated once, the same bytes declared with another key spec can be accepted (measured: `pkcache`
//! lines). This module has no such cache; the recorded matrix was taken with the caches cleared before every case.
use std::collections::BTreeSet;

use crate::proto_wire::WireError;

mod curves;
mod format;
mod keys;
mod verify;

pub use format::{
    parse_signature, parse_versioned_signature, AlgorithmSpec, Delegation, Signature,
    SignatureFormat,
};
pub use keys::{
    create_public_key, parse_private_key, parse_private_key_bytes, parse_public_key,
    parse_public_key_bytes, sign_usage_check, PrivateKey, PublicKey,
};
pub use verify::{verify_signature, verify_signature_allowing_experimental, VerifyError};

use curves::Curve;

// ---------------------------------------------------------------------------------------------------------------------
// errors

/// A failure of one of the parsers, named as the node's exception or error class is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    FieldNotSet(String),
    UnrecognizedEnum(String, i32),
    CryptoDeserialization(String),
    StringConversion(String),
    InvariantViolation(String),
    TimestampConversion(String),
    /// `OtherError`: no deserializer for the version in the wrapper.
    Other(String),
    /// The node threw an exception instead of returning an error (the reader failed, or a coordinate was out of range).
    Thrown(&'static str, String),
}

impl ProtoError {
    /// The simple class name the node reports (`FieldNotSet`, `CryptoDeserializationError`, ...).
    pub fn class(&self) -> &'static str {
        match self {
            ProtoError::FieldNotSet(_) => "FieldNotSet",
            ProtoError::UnrecognizedEnum(..) => "UnrecognizedEnum",
            ProtoError::CryptoDeserialization(_) => "CryptoDeserializationError",
            ProtoError::StringConversion(_) => "StringConversionError",
            ProtoError::InvariantViolation(_) => "InvariantViolation",
            ProtoError::TimestampConversion(_) => "TimestampConversionError",
            ProtoError::Other(_) => "OtherError",
            ProtoError::Thrown(class, _) => class,
        }
    }

    /// The node answered with an exception (`THROW`), not with a `Left`.
    pub fn is_thrown(&self) -> bool {
        matches!(self, ProtoError::Thrown(..))
    }
}

impl From<WireError> for ProtoError {
    fn from(e: WireError) -> Self {
        ProtoError::Thrown(e.class(), format!("{e:?}"))
    }
}

fn crypto_err(msg: impl Into<String>) -> ProtoError {
    ProtoError::CryptoDeserialization(msg.into())
}

// ---------------------------------------------------------------------------------------------------------------------
// enums

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    EcCurve25519,
    EcP256,
    EcP384,
    EcSecp256k1,
    MlDsa65,
}

impl KeySpec {
    /// The name the node prints.
    pub fn name(self) -> &'static str {
        match self {
            KeySpec::EcCurve25519 => "EC-Curve25519",
            KeySpec::EcP256 => "EC-P256",
            KeySpec::EcP384 => "EC-P384",
            KeySpec::EcSecp256k1 => "EC-Secp256k1",
            KeySpec::MlDsa65 => "ML-DSA-65",
        }
    }

    fn from_proto(v: i32, field: &str) -> Result<KeySpec, ProtoError> {
        match v {
            0 => Err(ProtoError::FieldNotSet(field.into())),
            1 => Ok(KeySpec::EcCurve25519),
            2 => Ok(KeySpec::EcP256),
            3 => Ok(KeySpec::EcP384),
            4 => Ok(KeySpec::EcSecp256k1),
            5 => Ok(KeySpec::MlDsa65),
            v => Err(ProtoError::UnrecognizedEnum(field.into(), v)),
        }
    }

    fn curve(self) -> Option<Curve> {
        match self {
            KeySpec::EcP256 => Some(Curve::P256),
            KeySpec::EcP384 => Some(Curve::P384),
            KeySpec::EcSecp256k1 => Some(Curve::K256),
            _ => None,
        }
    }
}

/// `SigningKeySpec.fromProtoEnumWithDefaultScheme`: the deprecated `scheme` decides only when `key_spec` is unspecified.
fn key_spec_with_default_scheme(key_spec: i32, scheme: i32) -> Result<KeySpec, ProtoError> {
    if key_spec == 0 && scheme == 0 {
        return Err(ProtoError::FieldNotSet("key_spec and scheme".into()));
    }
    if key_spec != 0 {
        return KeySpec::from_proto(key_spec, "key_spec");
    }
    match scheme {
        1 => Ok(KeySpec::EcCurve25519),
        2 => Ok(KeySpec::EcP256),
        3 => Ok(KeySpec::EcP384),
        v => Err(ProtoError::UnrecognizedEnum("scheme".into(), v)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// Legacy DER (migrated to the X.509 or PKCS#8 form where the node does so).
    Der,
    Raw,
    DerX509Spki,
    DerPkcs8Pki,
    Symbolic,
}

impl KeyFormat {
    /// The name the node prints.
    pub fn name(self) -> &'static str {
        match self {
            KeyFormat::Der => "DER",
            KeyFormat::Raw => "Raw",
            KeyFormat::DerX509Spki => "DER-encoded X.509 SubjectPublicKeyInfo",
            KeyFormat::DerPkcs8Pki => "DER-encoded PKCS #8 PrivateKeyInfo",
            KeyFormat::Symbolic => "Symbolic",
        }
    }

    fn from_proto(v: i32) -> Result<KeyFormat, ProtoError> {
        match v {
            0 => Err(ProtoError::FieldNotSet("format".into())),
            2 => Ok(KeyFormat::Der),
            3 => Ok(KeyFormat::Raw),
            4 => Ok(KeyFormat::DerX509Spki),
            5 => Ok(KeyFormat::DerPkcs8Pki),
            10000 => Ok(KeyFormat::Symbolic),
            v => Err(ProtoError::UnrecognizedEnum("format".into(), v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Usage {
    Namespace,
    SequencerAuthentication,
    Protocol,
    ProofOfOwnership,
}

impl Usage {
    /// The name the node prints.
    pub fn name(self) -> &'static str {
        match self {
            Usage::Namespace => "namespace",
            Usage::SequencerAuthentication => "sequencer-auth",
            Usage::Protocol => "signing",
            Usage::ProofOfOwnership => "proof-of-ownership",
        }
    }

    /// The set the node uses when a key lists no usage.
    pub fn all() -> BTreeSet<Usage> {
        [
            Usage::Namespace,
            Usage::SequencerAuthentication,
            Usage::Protocol,
            Usage::ProofOfOwnership,
        ]
        .into()
    }
}

/// `SigningKeyUsage.fromProtoListWithDefaultV30`.
///
/// [CANTON-NOTE: SEMANTICS] The retired identity-delegation usage (2) is dropped; a list that ends up empty means ALL usages.
fn usages_from_proto(list: &[i32]) -> Result<BTreeSet<Usage>, ProtoError> {
    let mut out = BTreeSet::new();
    for &u in list {
        match u {
            0 => return Err(ProtoError::FieldNotSet("usage".into())),
            1 => {
                out.insert(Usage::Namespace);
            }
            2 => {}
            3 => {
                out.insert(Usage::SequencerAuthentication);
            }
            4 => {
                out.insert(Usage::Protocol);
            }
            5 => {
                out.insert(Usage::ProofOfOwnership);
            }
            v => return Err(ProtoError::UnrecognizedEnum("usage".into(), v)),
        }
    }
    Ok(if out.is_empty() { Usage::all() } else { out })
}

/// `SigningKeyUsage.isUsageValid`: proof-of-ownership alone, and namespace with proof-of-ownership, are invalid.
fn usage_is_valid(usage: &BTreeSet<Usage>) -> bool {
    let po = Usage::ProofOfOwnership;
    !(usage.len() == 1 && usage.contains(&po)
        || usage.len() == 2 && usage.contains(&po) && usage.contains(&Usage::Namespace))
}

/// `SigningKeyUsage.addProofOfOwnership`.
fn add_proof_of_ownership(usage: &BTreeSet<Usage>) -> BTreeSet<Usage> {
    let mut with = usage.clone();
    with.insert(Usage::ProofOfOwnership);
    if usage_is_valid(&with) {
        with
    } else {
        usage.clone()
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// curves and points

// ---------------------------------------------------------------------------------------------------------------------
// Ed25519

// ---------------------------------------------------------------------------------------------------------------------
// public keys

// ---------------------------------------------------------------------------------------------------------------------
// private keys

// ---------------------------------------------------------------------------------------------------------------------
// signatures

// ---------------------------------------------------------------------------------------------------------------------
// verification
