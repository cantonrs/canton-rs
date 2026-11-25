//! Cryptographic Key and Signature Accept Matrix for Canton & Daml-LF.
//!
//! Enforces:
//! - Strict key curve and length verification (AT-C04)
//! - Non-malleability rules: Ed25519 canonical order check, ECDSA Low-S canonical check (AT-C05)
//! - Canton domain-separated HashPurpose (`1220` multihash) signature verification and cross-purpose rejection (AT-C02)

use ed25519_dalek::{
    pkcs8::DecodePublicKey as EdDecodePublicKey, Signature as EdSignature, Verifier as EdVerifier,
    VerifyingKey as EdVerifyingKey,
};
use k256::ecdsa::{
    signature::Verifier as K256Verifier, DerSignature as K256DerSignature,
    Signature as K256Signature, VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{
    signature::Verifier as P256Verifier, DerSignature as P256DerSignature,
    Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    signature::Verifier as P384Verifier, DerSignature as P384DerSignature,
    Signature as P384Signature, VerifyingKey as P384VerifyingKey,
};

/// Supported Canton cryptographic signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    Ed25519,
    EcDsaSecp256k1,
    EcDsaSecp256r1,
    EcDsaSecp384r1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoAcceptError {
    InvalidKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidKeyFormat(String),
    InvalidSignatureLength {
        expected: usize,
        actual: usize,
    },
    SignatureMalleabilityRejected(String),
    SignatureVerificationFailed,
    CrossPurposeMismatch,
    KeyAlgoSpecsMismatch {
        key_spec: String,
        algorithm_spec: String,
    },
    InvalidKeyUsage {
        key_usage: String,
        expected_usage: String,
    },
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for CryptoAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            Self::InvalidKeyFormat(msg) => write!(f, "invalid key format: {msg}"),
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "invalid signature length: expected {expected}, got {actual}"
                )
            }
            Self::SignatureMalleabilityRejected(msg) => {
                write!(f, "signature malleability rejected: {msg}")
            }
            Self::SignatureVerificationFailed => {
                write!(f, "cryptographic signature verification failed")
            }
            Self::CrossPurposeMismatch => write!(f, "cross-purpose hash mismatch"),
            Self::KeyAlgoSpecsMismatch {
                key_spec,
                algorithm_spec,
            } => write!(
                f,
                "key spec '{key_spec}' is incompatible with algorithm spec '{algorithm_spec}'"
            ),
            Self::InvalidKeyUsage {
                key_usage,
                expected_usage,
            } => write!(
                f,
                "invalid signing key usage '{key_usage}', expected '{expected_usage}'"
            ),
            Self::UnsupportedAlgorithm(msg) => write!(f, "unsupported algorithm: {msg}"),
        }
    }
}

impl std::error::Error for CryptoAcceptError {}

/// Resolve `(SigningKeySpec, SigningAlgorithmSpec)` names as defined in Canton's `Signing.scala`
/// and verify that the key curve specification matches the signing algorithm specification.
pub fn resolve_signing_specs(
    key_spec: &str,
    algorithm_spec: &str,
) -> Result<CryptoAlgorithm, CryptoAcceptError> {
    match (key_spec, algorithm_spec) {
        ("EC-Curve25519", "Ed25519") | ("EC-Curve25519", "-") => Ok(CryptoAlgorithm::Ed25519),
        ("EC-P256", "EC-DSA-SHA256") | ("EC-P256", "-") => Ok(CryptoAlgorithm::EcDsaSecp256r1),
        ("EC-Secp256k1", "EC-DSA-SHA256") | ("EC-Secp256k1", "-") => {
            Ok(CryptoAlgorithm::EcDsaSecp256k1)
        }
        ("EC-P384", "EC-DSA-SHA384") | ("EC-P384", "-") => Ok(CryptoAlgorithm::EcDsaSecp384r1),
        (
            "EC-Curve25519" | "EC-P256" | "EC-Secp256k1" | "EC-P384",
            "Ed25519" | "EC-DSA-SHA256" | "EC-DSA-SHA384",
        ) => Err(CryptoAcceptError::KeyAlgoSpecsMismatch {
            key_spec: key_spec.to_string(),
            algorithm_spec: algorithm_spec.to_string(),
        }),
        _ => Err(CryptoAcceptError::UnsupportedAlgorithm(format!(
            "{key_spec}/{algorithm_spec}"
        ))),
    }
}

/// Verify `SigningKeyUsage.compatibleUsageForSignAndVerify` (`Signing.scala` L922-L926):
/// the intersection of `key_usages` and `expected_usages` must be non-empty.
pub fn validate_signing_key_usage(
    key_usages: &[&str],
    expected_usages: &[&str],
) -> Result<(), CryptoAcceptError> {
    if key_usages
        .iter()
        .any(|ku| expected_usages.iter().any(|eu| ku == eu))
    {
        Ok(())
    } else {
        Err(CryptoAcceptError::InvalidKeyUsage {
            key_usage: key_usages.join(","),
            expected_usage: expected_usages.join(","),
        })
    }
}

/// Compute Canton's `Fingerprint` (`HashPurpose.PublicKeyFingerprint` = 12, `1220` multihash)
/// matching `SigningPublicKey.getDataForFingerprint` (`Signing.scala` L1532-L1544) and
/// `Fingerprint.create` (`CryptoKeys.scala` L93-L98):
/// - For `Ed25519` (`EC-Curve25519`), Canton extracts the 32-byte raw public key from X.509 SPKI DER
///   before hashing with purpose 12.
/// - For `EC-P256`, `EC-Secp256k1`, and `EC-P384`, Canton hashes the X.509 SPKI DER bytes directly.
pub fn compute_public_key_fingerprint(
    algo: CryptoAlgorithm,
    public_key: &[u8],
) -> Result<String, CryptoAcceptError> {
    validate_public_key(algo, public_key)?;
    let data_for_fp: Vec<u8> = match algo {
        CryptoAlgorithm::Ed25519 => {
            if public_key.len() == 32 {
                public_key.to_vec()
            } else {
                let vk = <EdVerifyingKey as EdDecodePublicKey>::from_public_key_der(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?;
                vk.to_bytes().to_vec()
            }
        }
        CryptoAlgorithm::EcDsaSecp256r1
        | CryptoAlgorithm::EcDsaSecp256k1
        | CryptoAlgorithm::EcDsaSecp384r1 => public_key.to_vec(),
    };
    let purpose_id = crate::hash::purpose_by_description("PublicKeyFingerprint")
        .expect("PublicKeyFingerprint purpose id 12")
        .id;
    let digest = crate::hash::sha256_with_purpose(purpose_id, &data_for_fp);
    Ok(crate::hash::multihash_sha256_hex(&digest))
}

// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
// In little-endian bytes:
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// Secp256k1 curve order half: n / 2 in big-endian bytes
const SECP256K1_HALF_ORDER_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

// Secp256r1 (P-256) curve order half: n / 2 in big-endian bytes
const SECP256R1_HALF_ORDER_BE: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCE, 0x42, 0x79, 0xDC, 0xF5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

// Secp384r1 (P-384) curve order half: n / 2 in big-endian bytes
const SECP384R1_HALF_ORDER_BE: [u8; 48] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x63, 0xB1, 0xA3, 0xB9, 0x2C, 0x0C, 0xA2, 0x40,
    0xF0, 0xA5, 0x6B, 0x98, 0x8F, 0xB0, 0x56, 0x7C, 0xB9, 0x66, 0xE8, 0x32, 0xEE, 0x55, 0xA9, 0x39,
];

/// Validate public key according to Canton crypto accept matrix (AT-C04).
/// Accepts both X.509 SubjectPublicKeyInfo (SPKI) DER and raw/SEC1 public key bytes.
pub fn validate_public_key(
    algo: CryptoAlgorithm,
    key_bytes: &[u8],
) -> Result<(), CryptoAcceptError> {
    match algo {
        CryptoAlgorithm::Ed25519 => {
            // Check 32-byte raw key first so a valid 32-byte Ed25519 point starting with 0x30
            // is not misclassified as an X.509 SPKI DER header (which is 44 bytes).
            if key_bytes.len() == 32 {
                let arr: [u8; 32] =
                    key_bytes
                        .try_into()
                        .map_err(|_| CryptoAcceptError::InvalidKeyLength {
                            expected: 32,
                            actual: key_bytes.len(),
                        })?;
                EdVerifyingKey::from_bytes(&arr).map_err(|e| {
                    CryptoAcceptError::InvalidKeyFormat(format!("invalid ed25519 point: {e}"))
                })?;
                return Ok(());
            }
            if key_bytes.first() == Some(&0x30) {
                <EdVerifyingKey as EdDecodePublicKey>::from_public_key_der(key_bytes).map_err(
                    |e| {
                        CryptoAcceptError::InvalidKeyFormat(format!(
                            "invalid ed25519 SPKI DER: {e}"
                        ))
                    },
                )?;
                return Ok(());
            }
            Err(CryptoAcceptError::InvalidKeyLength {
                expected: 32,
                actual: key_bytes.len(),
            })
        }
        CryptoAlgorithm::EcDsaSecp256k1 => {
            if key_bytes.first() == Some(&0x30) {
                <K256VerifyingKey as k256::pkcs8::DecodePublicKey>::from_public_key_der(key_bytes)
                    .map_err(|e| {
                        CryptoAcceptError::InvalidKeyFormat(format!(
                            "invalid secp256k1 SPKI DER: {e}"
                        ))
                    })?;
                return Ok(());
            }
            if key_bytes.len() != 33 && key_bytes.len() != 65 {
                return Err(CryptoAcceptError::InvalidKeyLength {
                    expected: 33,
                    actual: key_bytes.len(),
                });
            }
            K256VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                CryptoAcceptError::InvalidKeyFormat(format!("invalid secp256k1 SEC1 point: {e}"))
            })?;
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp256r1 => {
            if key_bytes.first() == Some(&0x30) {
                <P256VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(key_bytes)
                    .map_err(|e| {
                        CryptoAcceptError::InvalidKeyFormat(format!(
                            "invalid secp256r1 SPKI DER: {e}"
                        ))
                    })?;
                return Ok(());
            }
            if key_bytes.len() != 33 && key_bytes.len() != 65 {
                return Err(CryptoAcceptError::InvalidKeyLength {
                    expected: 33,
                    actual: key_bytes.len(),
                });
            }
            P256VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                CryptoAcceptError::InvalidKeyFormat(format!("invalid secp256r1 SEC1 point: {e}"))
            })?;
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp384r1 => {
            if key_bytes.first() == Some(&0x30) {
                <P384VerifyingKey as p384::pkcs8::DecodePublicKey>::from_public_key_der(key_bytes)
                    .map_err(|e| {
                        CryptoAcceptError::InvalidKeyFormat(format!(
                            "invalid secp384r1 SPKI DER: {e}"
                        ))
                    })?;
                return Ok(());
            }
            if key_bytes.len() != 49 && key_bytes.len() != 97 {
                return Err(CryptoAcceptError::InvalidKeyLength {
                    expected: 49,
                    actual: key_bytes.len(),
                });
            }
            P384VerifyingKey::from_sec1_bytes(key_bytes).map_err(|e| {
                CryptoAcceptError::InvalidKeyFormat(format!("invalid secp384r1 SEC1 point: {e}"))
            })?;
            Ok(())
        }
    }
}

/// Validate signature malleability according to Canton crypto accept matrix (AT-C05).
pub fn validate_signature_malleability(
    algo: CryptoAlgorithm,
    sig_bytes: &[u8],
) -> Result<(), CryptoAcceptError> {
    match algo {
        CryptoAlgorithm::Ed25519 => {
            if sig_bytes.len() != 64 {
                return Err(CryptoAcceptError::InvalidSignatureLength {
                    expected: 64,
                    actual: sig_bytes.len(),
                });
            }
            // S component is the second 32 bytes (in little-endian).
            let s_bytes = &sig_bytes[32..64];
            // Compare s_bytes with ED25519_ORDER_LE in little endian (from MSB down)
            for i in (0..32).rev() {
                if s_bytes[i] > ED25519_ORDER_LE[i] {
                    return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                        "Ed25519 signature S component >= group order L (non-canonical)"
                            .to_string(),
                    ));
                } else if s_bytes[i] < ED25519_ORDER_LE[i] {
                    break;
                }
                if i == 0 {
                    // Exactly equal to L -> also invalid
                    return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                        "Ed25519 signature S component == group order L (non-canonical)"
                            .to_string(),
                    ));
                }
            }
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp256k1 => {
            if sig_bytes.len() != 64 {
                return Err(CryptoAcceptError::InvalidSignatureLength {
                    expected: 64,
                    actual: sig_bytes.len(),
                });
            }
            let r_bytes = &sig_bytes[0..32];
            let s_bytes = &sig_bytes[32..64];
            if r_bytes.iter().all(|&b| b == 0) || s_bytes.iter().all(|&b| b == 0) {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp256k1 signature R or S component cannot be zero".to_string(),
                ));
            }
            if s_bytes > &SECP256K1_HALF_ORDER_BE[..] {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp256k1 signature S component > n/2 (high-S malleable signature rejected)".to_string(),
                ));
            }
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp256r1 => {
            if sig_bytes.len() != 64 {
                return Err(CryptoAcceptError::InvalidSignatureLength {
                    expected: 64,
                    actual: sig_bytes.len(),
                });
            }
            let r_bytes = &sig_bytes[0..32];
            let s_bytes = &sig_bytes[32..64];
            if r_bytes.iter().all(|&b| b == 0) || s_bytes.iter().all(|&b| b == 0) {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp256r1 signature R or S component cannot be zero".to_string(),
                ));
            }
            if s_bytes > &SECP256R1_HALF_ORDER_BE[..] {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp256r1 signature S component > n/2 (high-S malleable signature rejected)".to_string(),
                ));
            }
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp384r1 => {
            if sig_bytes.len() != 96 {
                return Err(CryptoAcceptError::InvalidSignatureLength {
                    expected: 96,
                    actual: sig_bytes.len(),
                });
            }
            let r_bytes = &sig_bytes[0..48];
            let s_bytes = &sig_bytes[48..96];
            if r_bytes.iter().all(|&b| b == 0) || s_bytes.iter().all(|&b| b == 0) {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp384r1 signature R or S component cannot be zero".to_string(),
                ));
            }
            if s_bytes > &SECP384R1_HALF_ORDER_BE[..] {
                return Err(CryptoAcceptError::SignatureMalleabilityRejected(
                    "ECDSA secp384r1 signature S component > n/2 (high-S malleable signature rejected)".to_string(),
                ));
            }
            Ok(())
        }
    }
}

/// Verify a signature over a Canton `1220` multihash (AT-C02, AT-C04, AT-C05).
///
/// Accepts the SPKI DER (or raw/SEC1) public key, `1220`-prefixed 34-byte SHA-256 multihash,
/// and signature bytes (64-byte Concat for Ed25519; ASN.1 DER or raw Concat for ECDSA)
/// directly as recorded in `tests/oracle/provenance/crypto-accept-vectors.tsv`.
pub fn verify_purpose_signature(
    algo: CryptoAlgorithm,
    public_key: &[u8],
    multihash: &[u8],
    sig_bytes: &[u8],
) -> Result<(), CryptoAcceptError> {
    validate_public_key(algo, public_key)?;

    if multihash.len() != 34 || !multihash.starts_with(&[0x12, 0x20]) {
        return Err(CryptoAcceptError::CrossPurposeMismatch);
    }

    match algo {
        CryptoAlgorithm::Ed25519 => {
            validate_signature_malleability(algo, sig_bytes)?;

            let vk = if public_key.len() == 32 {
                let key_arr: [u8; 32] =
                    public_key
                        .try_into()
                        .map_err(|_| CryptoAcceptError::InvalidKeyLength {
                            expected: 32,
                            actual: public_key.len(),
                        })?;
                EdVerifyingKey::from_bytes(&key_arr)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            } else {
                <EdVerifyingKey as EdDecodePublicKey>::from_public_key_der(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            };

            let sig_arr: [u8; 64] =
                sig_bytes
                    .try_into()
                    .map_err(|_| CryptoAcceptError::InvalidSignatureLength {
                        expected: 64,
                        actual: sig_bytes.len(),
                    })?;
            let ed_sig = EdSignature::from_bytes(&sig_arr);

            vk.verify(multihash, &ed_sig)
                .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?;
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp256r1 => {
            let vk = if public_key.first() == Some(&0x30) {
                <P256VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            } else {
                P256VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            };

            let sig = if sig_bytes.first() == Some(&0x30) {
                if let Ok(der_sig) = P256DerSignature::from_bytes(sig_bytes) {
                    P256Signature::try_from(der_sig)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
                } else if sig_bytes.len() == 64 {
                    validate_signature_malleability(algo, sig_bytes)?;
                    P256Signature::from_slice(sig_bytes)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
                } else {
                    return Err(CryptoAcceptError::SignatureVerificationFailed);
                }
            } else {
                validate_signature_malleability(algo, sig_bytes)?;
                P256Signature::from_slice(sig_bytes)
                    .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
            };

            P256Verifier::verify(&vk, multihash, &sig)
                .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?;
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp256k1 => {
            let vk = if public_key.first() == Some(&0x30) {
                <K256VerifyingKey as k256::pkcs8::DecodePublicKey>::from_public_key_der(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            } else {
                K256VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            };

            let sig = if sig_bytes.first() == Some(&0x30) {
                if let Ok(der_sig) = K256DerSignature::from_bytes(sig_bytes) {
                    let raw_sig = K256Signature::try_from(der_sig)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?;
                    raw_sig.normalize_s().unwrap_or(raw_sig)
                } else if sig_bytes.len() == 64 {
                    validate_signature_malleability(algo, sig_bytes)?;
                    K256Signature::from_slice(sig_bytes)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
                } else {
                    return Err(CryptoAcceptError::SignatureVerificationFailed);
                }
            } else {
                validate_signature_malleability(algo, sig_bytes)?;
                K256Signature::from_slice(sig_bytes)
                    .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
            };

            K256Verifier::verify(&vk, multihash, &sig)
                .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?;
            Ok(())
        }
        CryptoAlgorithm::EcDsaSecp384r1 => {
            let vk = if public_key.first() == Some(&0x30) {
                <P384VerifyingKey as p384::pkcs8::DecodePublicKey>::from_public_key_der(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            } else {
                P384VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|e| CryptoAcceptError::InvalidKeyFormat(e.to_string()))?
            };

            let sig = if sig_bytes.first() == Some(&0x30) {
                if let Ok(der_sig) = P384DerSignature::from_bytes(sig_bytes) {
                    P384Signature::try_from(der_sig)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
                } else if sig_bytes.len() == 96 {
                    validate_signature_malleability(algo, sig_bytes)?;
                    P384Signature::from_slice(sig_bytes)
                        .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
                } else {
                    return Err(CryptoAcceptError::SignatureVerificationFailed);
                }
            } else {
                validate_signature_malleability(algo, sig_bytes)?;
                P384Signature::from_slice(sig_bytes)
                    .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?
            };

            P384Verifier::verify(&vk, multihash, &sig)
                .map_err(|_| CryptoAcceptError::SignatureVerificationFailed)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS_TSV: &str =
        include_str!("../../../../tests/oracle/provenance/crypto-accept-vectors.tsv");

    struct OracleVector<'a> {
        vector_id: &'a str,
        expected_outcome: &'a str,
        key_spec: &'a str,
        algorithm_spec: &'a str,
        key_fingerprint: &'a str,
        spki_der: Vec<u8>,
        multihash: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
        error_or_note: &'a str,
    }

    fn parse_tsv_vectors() -> Vec<OracleVector<'static>> {
        VECTORS_TSV
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                assert_eq!(cols.len(), 9, "expected 9 columns in TSV row: {line}");
                OracleVector {
                    vector_id: cols[0],
                    expected_outcome: cols[1],
                    key_spec: cols[2],
                    algorithm_spec: cols[3],
                    key_fingerprint: cols[4],
                    spki_der: hex::decode(cols[5]).expect("valid spki_der_hex"),
                    multihash: (cols[6] != "-")
                        .then(|| hex::decode(cols[6]).expect("valid hash_hex")),
                    signature: (cols[7] != "-")
                        .then(|| hex::decode(cols[7]).expect("valid signature_hex")),
                    error_or_note: cols[8],
                }
            })
            .collect()
    }

    fn find_vector(id: &str) -> OracleVector<'static> {
        parse_tsv_vectors()
            .into_iter()
            .find(|v| v.vector_id == id)
            .unwrap_or_else(|| panic!("missing vector {id} in crypto-accept-vectors.tsv"))
    }

    /// Evaluate a single TSV row through the full Canton key/spec/usage/fingerprint/signature pipeline.
    fn evaluate_oracle_vector(v: &OracleVector<'_>) -> Result<(), CryptoAcceptError> {
        // 1. Check (key_spec, algorithm_spec) compatibility (`Signing.scala` scheme check)
        let algo = resolve_signing_specs(v.key_spec, v.algorithm_spec)?;

        // 2. Validate public key SPKI DER and curve membership (`CryptoKeyValidation.scala`)
        validate_public_key(algo, &v.spki_der)?;

        // 3. Verify key_fingerprint (`HashPurpose.PublicKeyFingerprint` = 12 + `1220` multihash)
        if v.key_fingerprint != "-" {
            let computed_fp = compute_public_key_fingerprint(algo, &v.spki_der)?;
            assert_eq!(
                computed_fp, v.key_fingerprint,
                "PublicKeyFingerprint mismatch for vector {}",
                v.vector_id
            );
        }

        // 4. Check keyUsage if the vector encodes a usage constraint (`SigningKeyUsage.compatibleUsageForSignAndVerify`)
        if v.error_or_note.contains("keyUsage = namespace")
            && v.error_or_note.contains("expectedKeyUsage = signing")
        {
            validate_signing_key_usage(&["namespace"], &["signing"])?;
        }

        // 5. Verify cryptographic signature over the `1220` multihash
        let multihash = v.multihash.as_deref().ok_or_else(|| {
            CryptoAcceptError::InvalidKeyFormat("missing multihash for signature vector".into())
        })?;
        let signature =
            v.signature
                .as_deref()
                .ok_or(CryptoAcceptError::InvalidSignatureLength {
                    expected: 64,
                    actual: 0,
                })?;
        verify_purpose_signature(algo, &v.spki_der, multihash, signature)
    }

    #[test]
    fn test_at_c02_all_13_tsv_vectors_exhaustive() {
        let vectors = parse_tsv_vectors();
        assert_eq!(vectors.len(), 13, "expected exactly 13 oracle vectors");

        let mut accept_count = 0;
        let mut reject_count = 0;

        for v in &vectors {
            let res = evaluate_oracle_vector(v);
            match v.expected_outcome {
                "ACCEPT" => {
                    assert_eq!(
                        res,
                        Ok(()),
                        "expected ACCEPT for vector {}, got {res:?}",
                        v.vector_id
                    );
                    accept_count += 1;
                }
                "REJECT" => {
                    assert!(
                        res.is_err(),
                        "expected REJECT for vector {}, got Ok(())",
                        v.vector_id
                    );
                    reject_count += 1;
                }
                other => panic!("unexpected outcome {other} in vector {}", v.vector_id),
            }
        }

        assert_eq!(accept_count, 4);
        assert_eq!(reject_count, 9);
    }

    #[test]
    fn test_at_c02_ed25519_tsv_vectors_accept_and_wrong_purpose_reject() {
        let accept_row = find_vector("ed25519_valid_accept");
        assert_eq!(accept_row.expected_outcome, "ACCEPT");
        assert_eq!(accept_row.algorithm_spec, "Ed25519");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::Ed25519,
                &accept_row.spki_der,
                accept_row.multihash.as_deref().unwrap(),
                accept_row.signature.as_deref().unwrap(),
            ),
            Ok(())
        );

        let reject_row = find_vector("ed25519_wrong_hash_purpose_reject");
        assert_eq!(reject_row.expected_outcome, "REJECT");
        assert_eq!(reject_row.algorithm_spec, "Ed25519");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::Ed25519,
                &reject_row.spki_der,
                reject_row.multihash.as_deref().unwrap(),
                reject_row.signature.as_deref().unwrap(),
            ),
            Err(CryptoAcceptError::SignatureVerificationFailed)
        );

        let corrupted_row = find_vector("ed25519_corrupted_sig_reject");
        assert_eq!(corrupted_row.expected_outcome, "REJECT");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::Ed25519,
                &corrupted_row.spki_der,
                corrupted_row.multihash.as_deref().unwrap(),
                corrupted_row.signature.as_deref().unwrap(),
            ),
            Err(CryptoAcceptError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn test_at_c02_ecdsa_tsv_vectors_p256_secp256k1_p384() {
        let p256_accept = find_vector("ecdsa_p256_valid_accept");
        assert_eq!(p256_accept.expected_outcome, "ACCEPT");
        assert_eq!(p256_accept.key_spec, "EC-P256");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp256r1,
                &p256_accept.spki_der,
                p256_accept.multihash.as_deref().unwrap(),
                p256_accept.signature.as_deref().unwrap(),
            ),
            Ok(())
        );

        let p256_wrong_purpose = find_vector("ecdsa_p256_wrong_hash_purpose_reject");
        assert_eq!(p256_wrong_purpose.expected_outcome, "REJECT");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp256r1,
                &p256_wrong_purpose.spki_der,
                p256_wrong_purpose.multihash.as_deref().unwrap(),
                p256_wrong_purpose.signature.as_deref().unwrap(),
            ),
            Err(CryptoAcceptError::SignatureVerificationFailed)
        );

        let k256_accept = find_vector("ecdsa_secp256k1_valid_accept");
        assert_eq!(k256_accept.expected_outcome, "ACCEPT");
        assert_eq!(k256_accept.key_spec, "EC-Secp256k1");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp256k1,
                &k256_accept.spki_der,
                k256_accept.multihash.as_deref().unwrap(),
                k256_accept.signature.as_deref().unwrap(),
            ),
            Ok(())
        );

        // Mutating the secp256k1 signature or using the wrong purpose multihash must fail cryptographic verification
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp256k1,
                &k256_accept.spki_der,
                p256_wrong_purpose.multihash.as_deref().unwrap(),
                k256_accept.signature.as_deref().unwrap(),
            ),
            Err(CryptoAcceptError::SignatureVerificationFailed)
        );

        let p384_accept = find_vector("ecdsa_p384_valid_accept");
        assert_eq!(p384_accept.expected_outcome, "ACCEPT");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp384r1,
                &p384_accept.spki_der,
                p384_accept.multihash.as_deref().unwrap(),
                p384_accept.signature.as_deref().unwrap(),
            ),
            Ok(())
        );

        let p384_corrupted = find_vector("ecdsa_p384_corrupted_sig_reject");
        assert_eq!(p384_corrupted.expected_outcome, "REJECT");
        assert_eq!(
            verify_purpose_signature(
                CryptoAlgorithm::EcDsaSecp384r1,
                &p384_corrupted.spki_der,
                p384_corrupted.multihash.as_deref().unwrap(),
                p384_corrupted.signature.as_deref().unwrap(),
            ),
            Err(CryptoAcceptError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn test_at_c04_key_validation() {
        // SPKI DER keys from TSV oracle
        let ed_valid = find_vector("ed25519_valid_accept");
        assert!(validate_public_key(CryptoAlgorithm::Ed25519, &ed_valid.spki_der).is_ok());
        assert!(validate_public_key(CryptoAlgorithm::Ed25519, &ed_valid.spki_der[12..]).is_ok());

        // 32-byte raw Ed25519 public key whose first byte is 0x30 must not be misparsed as SPKI DER
        let raw_ed_0x30: [u8; 32] = [
            0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            validate_public_key(CryptoAlgorithm::Ed25519, &raw_ed_0x30),
            Ok(())
        );

        // Cross-curve and malformed SPKI rejections from TSV oracle
        let wrong_alg = find_vector("ed25519_wrong_alg_spec_reject");
        assert_eq!(
            resolve_signing_specs(wrong_alg.key_spec, wrong_alg.algorithm_spec),
            Err(CryptoAcceptError::KeyAlgoSpecsMismatch {
                key_spec: "EC-Curve25519".to_string(),
                algorithm_spec: "EC-DSA-SHA256".to_string(),
            })
        );
        assert!(validate_public_key(CryptoAlgorithm::EcDsaSecp256r1, &wrong_alg.spki_der).is_err());

        let p256_as_p384 = find_vector("key_parse_p256_as_p384_reject");
        assert!(
            validate_public_key(CryptoAlgorithm::EcDsaSecp384r1, &p256_as_p384.spki_der).is_err()
        );

        let k256_as_p256 = find_vector("key_parse_secp256k1_as_p256_reject");
        assert!(
            validate_public_key(CryptoAlgorithm::EcDsaSecp256r1, &k256_as_p256.spki_der).is_err()
        );

        let malformed_spki = find_vector("key_parse_malformed_spki_reject");
        assert!(validate_public_key(CryptoAlgorithm::Ed25519, &malformed_spki.spki_der).is_err());

        // Invalid raw key lengths rejected
        assert_eq!(
            validate_public_key(CryptoAlgorithm::Ed25519, &[0u8; 16]),
            Err(CryptoAcceptError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
        assert_eq!(
            validate_public_key(CryptoAlgorithm::Ed25519, &[0u8; 33]),
            Err(CryptoAcceptError::InvalidKeyLength {
                expected: 32,
                actual: 33
            })
        );

        // Raw SEC1 ECDSA keys
        let valid_comp = [0x02; 33];
        assert!(validate_public_key(CryptoAlgorithm::EcDsaSecp256k1, &valid_comp).is_ok());
        let invalid_comp_prefix = [0x05; 33];
        assert!(
            validate_public_key(CryptoAlgorithm::EcDsaSecp256k1, &invalid_comp_prefix).is_err()
        );
    }

    #[test]
    fn test_at_c05_signature_malleability_rejection() {
        // High-S ECDSA signature rejected
        let mut high_s_sig = [0u8; 64];
        // R = 1
        high_s_sig[31] = 1;
        // S = 0xFF... (greater than half order)
        high_s_sig[32..64].fill(0xFF);
        let res = validate_signature_malleability(CryptoAlgorithm::EcDsaSecp256k1, &high_s_sig);
        assert!(matches!(
            res,
            Err(CryptoAcceptError::SignatureMalleabilityRejected(_))
        ));

        // Valid low-S signature accepted
        let mut low_s_sig = [0u8; 64];
        low_s_sig[31] = 1;
        low_s_sig[63] = 1;
        assert!(
            validate_signature_malleability(CryptoAlgorithm::EcDsaSecp256k1, &low_s_sig).is_ok()
        );

        // Zero R or S ECDSA signature rejected
        let mut zero_r_sig = [0u8; 64];
        zero_r_sig[63] = 1; // S = 1, R = 0
        assert!(
            validate_signature_malleability(CryptoAlgorithm::EcDsaSecp256k1, &zero_r_sig).is_err()
        );
        let mut zero_s_sig = [0u8; 64];
        zero_s_sig[31] = 1; // R = 1, S = 0
        assert!(
            validate_signature_malleability(CryptoAlgorithm::EcDsaSecp256k1, &zero_s_sig).is_err()
        );

        // Ed25519 non-canonical S rejected (S >= L)
        let mut malformed_ed = [0u8; 64];
        malformed_ed[32..64].copy_from_slice(&ED25519_ORDER_LE);
        // Make S > L
        malformed_ed[32] = 0xee;
        assert!(matches!(
            validate_signature_malleability(CryptoAlgorithm::Ed25519, &malformed_ed),
            Err(CryptoAcceptError::SignatureMalleabilityRejected(_))
        ));
    }
}
