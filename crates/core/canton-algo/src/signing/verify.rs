//! Signature verification (`verify_signature*`) with strict DER and ECDSA checks.

use std::collections::BTreeSet;

use ed25519_dalek::Verifier;

use crate::ber;
use crate::ber::Params;

use super::curves::{be_ge, be_is_zero, decode_point, trim_zeros, Curve};
use super::format::{AlgorithmSpec, Signature};
use super::keys::PublicKey;
use super::{KeyFormat, Usage};

/// What `CryptoPureApi.verifySignature` answers (the simple class name of `SignatureCheckError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    SignatureWithWrongKey,
    KeyAlgoSpecsMismatch,
    NoMatchingAlgorithmSpec,
    InvalidKeyUsage,
    UnsupportedSignatureFormat,
    InvalidSignature,
    InvalidKeyError,
}

impl VerifyError {
    pub fn class(self) -> &'static str {
        match self {
            VerifyError::SignatureWithWrongKey => "SignatureWithWrongKey",
            VerifyError::KeyAlgoSpecsMismatch => "KeyAlgoSpecsMismatch",
            VerifyError::NoMatchingAlgorithmSpec => "NoMatchingAlgorithmSpec",
            VerifyError::InvalidKeyUsage => "InvalidKeyUsage",
            VerifyError::UnsupportedSignatureFormat => "UnsupportedSignatureFormat",
            VerifyError::InvalidSignature => "InvalidSignature",
            VerifyError::InvalidKeyError => "InvalidKeyError",
        }
    }
}

/// `JcePureCrypto.verifySignature`.
///
/// [CANTON-NOTE: SEMANTICS] The checks run in this order and the first failure is the answer (measured with inputs that are
/// wrong in two ways at once): the signer is the key; the algorithm spec fits the key spec (or, without a spec, the first
/// allowed algorithm that supports the key spec); the key's usages and `expected_usage` intersect; the signature format
/// is the algorithm's (`Concat` for Ed25519, `Der` for ECDSA); then the cryptographic check. The ECDSA check hashes the
/// message with SHA-256 (P-256, secp256k1) or SHA-384 (P-384) and accepts a high-S signature.
pub fn verify_signature(
    message: &[u8],
    key: &PublicKey,
    sig: &Signature,
    expected_usage: &BTreeSet<Usage>,
) -> Result<(), VerifyError> {
    verify_signature_with_experimental(message, key, sig, expected_usage, false)
}

/// `JcePureCrypto.verifySignature` allowing experimental signing algorithm specs (`ML-DSA-65`).
pub fn verify_signature_allowing_experimental(
    message: &[u8],
    key: &PublicKey,
    sig: &Signature,
    expected_usage: &BTreeSet<Usage>,
) -> Result<(), VerifyError> {
    verify_signature_with_experimental(message, key, sig, expected_usage, true)
}

fn verify_signature_with_experimental(
    message: &[u8],
    key: &PublicKey,
    sig: &Signature,
    expected_usage: &BTreeSet<Usage>,
    allow_experimental: bool,
) -> Result<(), VerifyError> {
    if sig.signed_by != key.id {
        return Err(VerifyError::SignatureWithWrongKey);
    }
    let allowed: &[AlgorithmSpec] = if allow_experimental {
        &[
            AlgorithmSpec::Ed25519,
            AlgorithmSpec::EcDsaSha256,
            AlgorithmSpec::EcDsaSha384,
            AlgorithmSpec::MlDsa65,
        ]
    } else {
        &[
            AlgorithmSpec::Ed25519,
            AlgorithmSpec::EcDsaSha256,
            AlgorithmSpec::EcDsaSha384,
        ]
    };
    let algorithm = match sig.spec {
        Some(a) => {
            if !a.supported_key_specs().contains(&key.key_spec) {
                return Err(VerifyError::KeyAlgoSpecsMismatch);
            }
            if !allowed.contains(&a) {
                return Err(VerifyError::NoMatchingAlgorithmSpec);
            }
            a
        }
        None => allowed
            .iter()
            .copied()
            .find(|a| a.supported_key_specs().contains(&key.key_spec))
            .ok_or(VerifyError::NoMatchingAlgorithmSpec)?,
    };
    if key.usage.intersection(expected_usage).next().is_none() {
        return Err(VerifyError::InvalidKeyUsage);
    }
    if sig.format != algorithm.supported_format() {
        return Err(VerifyError::UnsupportedSignatureFormat);
    }
    if key.format != KeyFormat::DerX509Spki {
        return Err(VerifyError::InvalidKeyError);
    }
    let spki = ber::parse_spki(&key.key).map_err(|_| VerifyError::InvalidKeyError)?;
    match algorithm {
        AlgorithmSpec::Ed25519 => {
            let pk: [u8; 32] = spki
                .key_bits
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::InvalidKeyError)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .map_err(|_| VerifyError::InvalidKeyError)?;
            let raw: [u8; 64] = sig
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::InvalidSignature)?;
            // a non-canonical S (not below the group order) is refused by the library
            vk.verify(message, &ed25519_dalek::Signature::from_bytes(&raw))
                .map_err(|_| VerifyError::InvalidSignature)
        }
        AlgorithmSpec::EcDsaSha256 | AlgorithmSpec::EcDsaSha384 => {
            let curve = Curve::from_algorithm_params(&spki.algorithm.params)
                .map_err(|_| VerifyError::InvalidKeyError)?;
            let (x, y) =
                decode_point(curve, &spki.key_bits).map_err(|_| VerifyError::InvalidKeyError)?;
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let (r, s) =
                strict_der_signature(&sig.signature, curve).ok_or(VerifyError::InvalidSignature)?;
            ecdsa_verify(curve, &sec1, message, &r, &s)
        }
        AlgorithmSpec::MlDsa65 => {
            if spki.algorithm.oid != crate::mldsa65::OID_ML_DSA_65
                || !matches!(spki.algorithm.params, Params::Absent)
                || spki.indefinite
                || spki.unused_bits != 0
                || spki.key_bits.len() != crate::mldsa65::PUBLIC_KEY_LEN
            {
                return Err(VerifyError::InvalidKeyError);
            }
            if crate::mldsa65::verify(&spki.key_bits, message, b"", &sig.signature) {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            }
        }
    }
}

/// An ECDSA signature as Bouncy Castle reads it: canonical DER of two INTEGERs, each in `[1, n-1]`.
///
/// [CANTON-NOTE: SEMANTICS] BC decodes the signature and compares its re-encoding with the input, so any non-canonical form
/// (padded integers, long-form or indefinite lengths, trailing bytes) is refused; a negative integer or a value outside
/// `[1, n-1]` fails the verification. High-S signatures are accepted.
fn strict_der_signature(sig: &[u8], curve: Curve) -> Option<(Vec<u8>, Vec<u8>)> {
    let (&tag, rest) = sig.split_first()?;
    if tag != 0x30 {
        return None;
    }
    let (len, rest) = match rest.split_first()? {
        (&l, rest) if l < 0x80 => (usize::from(l), rest),
        (&0x81, rest) => {
            let (&l, rest) = rest.split_first()?;
            if l < 0x80 {
                return None; // not the minimal form
            }
            (usize::from(l), rest)
        }
        _ => return None,
    };
    if rest.len() != len {
        return None;
    }
    let (r, rest) = der_unsigned_integer(rest)?;
    let (s, rest) = der_unsigned_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let n = curve.order();
    if be_is_zero(&r) || be_is_zero(&s) || be_ge(&r, n) || be_ge(&s, n) {
        return None;
    }
    Some((r, s))
}

/// A minimally encoded non-negative INTEGER (a leading 00 only when the next byte has its high bit set).
fn der_unsigned_integer(input: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&len, rest) = rest.split_first()?;
    if tag != 0x02 || len == 0 || len >= 0x80 || rest.len() < usize::from(len) {
        return None;
    }
    let (body, rest) = rest.split_at(usize::from(len));
    if body[0] & 0x80 != 0 {
        return None; // negative
    }
    if body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
        return None; // padded
    }
    Some((trim_zeros(body).to_vec(), rest))
}

fn ecdsa_verify(
    curve: Curve,
    sec1: &[u8],
    message: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<(), VerifyError> {
    let n = curve.size();
    let mut raw = vec![0u8; 2 * n];
    raw[n - r.len()..n].copy_from_slice(r);
    raw[2 * n - s.len()..].copy_from_slice(s);
    macro_rules! check {
        ($c:ident, $normalize:expr) => {{
            use $c::ecdsa::signature::Verifier;
            let vk = $c::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                .map_err(|_| VerifyError::InvalidKeyError)?;
            let sig = $c::ecdsa::Signature::from_slice(&raw)
                .map_err(|_| VerifyError::InvalidSignature)?;
            // a high-S signature verifies with the same equation as its low-S twin
            let sig = ($normalize)(sig);
            vk.verify(message, &sig)
                .map_err(|_| VerifyError::InvalidSignature)
        }};
    }
    match curve {
        // ecdsa 0.17 (p256, p384) returns the normalized signature, ecdsa 0.16 (k256) an Option of it
        Curve::P256 => check!(p256, |s: p256::ecdsa::Signature| s.normalize_s()),
        Curve::P384 => check!(p384, |s: p384::ecdsa::Signature| s.normalize_s()),
        Curve::K256 => check!(k256, |s: k256::ecdsa::Signature| s
            .normalize_s()
            .unwrap_or(s)),
    }
}
