//! The crypto handshake a participant runs before it joins a synchronizer (`CryptoHandshakeValidator.validate`, called by
//! `GrpcSynchronizerRegistry` right after it read the static synchronizer parameters): every scheme the synchronizer requires must be
//! one this participant supports, and this participant's default of each kind must be a required one.
use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::crypto::v30::{
    CryptoKeyFormat, EncryptionAlgorithmSpec, EncryptionKeySpec, HashAlgorithm, SignatureFormat,
    SigningAlgorithmSpec, SigningKeySpec, SymmetricKeyScheme,
};

/// The `required_*` fields of `StaticSynchronizerParameters` (any version), as proto enum numbers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Required {
    pub signing_algorithms: BTreeSet<i32>,
    pub signing_keys: BTreeSet<i32>,
    pub encryption_algorithms: BTreeSet<i32>,
    pub encryption_keys: BTreeSet<i32>,
    pub symmetric_key_schemes: BTreeSet<i32>,
    pub hash_algorithms: BTreeSet<i32>,
    pub crypto_key_formats: BTreeSet<i32>,
    pub signature_formats: BTreeSet<i32>,
    /// `synchronizer_limits.topology_limits.max_signing_keys_per_entity` when provided (`StaticSynchronizerParameters` v31/v32).
    pub max_signing_keys_per_entity: Option<u32>,
}

/// Reads [`Required`] from a `StaticSynchronizerParameters` message of any version (they share these fields).
macro_rules! required_schemes_of {
    ($p:expr) => {
        required_schemes_of!($p, None)
    };
    ($p:expr, $max_keys:expr) => {{
        let p = $p;
        let set = |v: &[i32]| {
            v.iter()
                .copied()
                .collect::<std::collections::BTreeSet<i32>>()
        };
        let signing = p.required_signing_specs.clone().unwrap_or_default();
        let encryption = p.required_encryption_specs.clone().unwrap_or_default();
        $crate::crypto_handshake::Required {
            signing_algorithms: set(&signing.algorithms),
            signing_keys: set(&signing.keys),
            encryption_algorithms: set(&encryption.algorithms),
            encryption_keys: set(&encryption.keys),
            symmetric_key_schemes: set(&p.required_symmetric_key_schemes),
            hash_algorithms: set(&p.required_hash_algorithms),
            crypto_key_formats: set(&p.required_crypto_key_formats),
            signature_formats: set(&p.required_signature_formats),
            max_signing_keys_per_entity: $max_keys,
        }
    }};
}

pub(crate) use required_schemes_of;

impl Required {
    /// Extracts [`Required`] from a v32 `StaticSynchronizerParameters` protobuf message (`synchronizer_parameters.proto`).
    pub fn from_v32(
        p: &canton_proto::com::digitalasset::canton::protocol::v32::StaticSynchronizerParameters,
    ) -> Self {
        let max_keys = p
            .synchronizer_limits
            .as_ref()
            .and_then(|l| l.topology_limits.as_ref())
            .map(|t| t.max_signing_keys_per_entity)
            .filter(|&n| n > 0);
        required_schemes_of!(p, max_keys)
    }
}

/// `SynchronizerRegistryError.HandshakeErrors.SynchronizerCryptoHandshakeFailed` with its reason.
pub fn handshake_failed(reason: &str) -> String {
    format!(
        "SYNCHRONIZER_CRYPTO_HANDSHAKE_FAILED(9,0): Crypto method handshake with synchronizer failed (reason = {reason})"
    )
}

/// What this participant allows of one kind of scheme, and its default (the one it uses itself).
struct Scheme {
    name: &'static str,
    allowed: &'static [i32],
    default: i32,
}

/// The signing schemes are the ones `canton_algo::signing::verify_signature` checks; the participant signs with Ed25519.
const SIGNING_ALGORITHMS: Scheme = Scheme {
    name: "signing algorithm",
    allowed: &[
        SigningAlgorithmSpec::Ed25519 as i32,
        SigningAlgorithmSpec::EcDsaSha256 as i32,
        SigningAlgorithmSpec::EcDsaSha384 as i32,
    ],
    default: SigningAlgorithmSpec::Ed25519 as i32,
};
const SIGNING_KEYS: Scheme = Scheme {
    name: "signing key",
    allowed: &[
        SigningKeySpec::EcCurve25519 as i32,
        SigningKeySpec::EcP256 as i32,
        SigningKeySpec::EcP384 as i32,
        SigningKeySpec::EcSecp256k1 as i32,
    ],
    default: SigningKeySpec::EcCurve25519 as i32,
};
/// [CANTON-NOTE: LIMITATION] RSA-OAEP (and RSA-2048 keys) is allowed although this participant cannot encrypt for an RSA key: every
/// synchronizer made with the default JCE configuration requires it (`CryptoProvider.Jce`, `toStaticSynchronizerParameters` requires all
/// allowed schemes), so refusing it would refuse every official synchronizer. A view for a peer whose only encryption key is RSA cannot be
/// sent (`topology_state::encryption_keys_of` reads only P-256 keys).
const ENCRYPTION_ALGORITHMS: Scheme = Scheme {
    name: "encryption algorithm",
    allowed: &[
        EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc as i32,
        EncryptionAlgorithmSpec::RsaOaepSha256 as i32,
    ],
    default: EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc as i32,
};
const ENCRYPTION_KEYS: Scheme = Scheme {
    name: "encryption key",
    allowed: &[
        EncryptionKeySpec::EcP256 as i32,
        EncryptionKeySpec::Rsa2048 as i32,
    ],
    default: EncryptionKeySpec::EcP256 as i32,
};
const SYMMETRIC_KEY_SCHEMES: Scheme = Scheme {
    name: "symmetric key",
    allowed: &[SymmetricKeyScheme::Aes128gcm as i32],
    default: SymmetricKeyScheme::Aes128gcm as i32,
};
const HASH_ALGORITHMS: Scheme = Scheme {
    name: "hash algorithm",
    allowed: &[HashAlgorithm::Sha256 as i32],
    default: HashAlgorithm::Sha256 as i32,
};
/// The key formats `canton_algo::signing` parses (`Raw` and the legacy `Der` are migrated) and the signature formats it verifies.
const CRYPTO_KEY_FORMATS: &[i32] = &[
    CryptoKeyFormat::Der as i32,
    CryptoKeyFormat::Raw as i32,
    CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32,
    CryptoKeyFormat::DerPkcs8PrivateKeyInfo as i32,
];
const SIGNATURE_FORMATS: &[i32] = &[
    SignatureFormat::Raw as i32,
    SignatureFormat::Der as i32,
    SignatureFormat::Concat as i32,
];

/// `CryptoHandshakeValidator.validateScheme`: required but not allowed, then the default must be required.
fn validate_scheme(required: &BTreeSet<i32>, scheme: &Scheme) -> Result<(), String> {
    let unsupported: Vec<i32> = required
        .iter()
        .copied()
        .filter(|r| !scheme.allowed.contains(r))
        .collect();
    if !unsupported.is_empty() {
        return Err(format!(
            "Required schemes {unsupported:?} are not supported/allowed ({} {:?})",
            scheme.name, scheme.allowed
        ));
    }
    if !required.contains(&scheme.default) {
        return Err(format!(
            "The default {} {} scheme is not a required scheme: {required:?}",
            scheme.name, scheme.default
        ));
    }
    Ok(())
}

/// `CryptoHandshakeValidator.validateFormats`.
fn validate_formats(required: &BTreeSet<i32>, supported: &[i32]) -> Result<(), String> {
    let unsupported: Vec<i32> = required
        .iter()
        .copied()
        .filter(|r| !supported.contains(r))
        .collect();
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Required formats {unsupported:?} are not supported ({supported:?})"
        ))
    }
}

/// `CryptoHandshakeValidator.validate` against what this participant supports, in the node's order; the error is the one
/// `GrpcSynchronizerRegistry` answers with.
pub fn validate(required: &Required) -> Result<(), String> {
    validate_scheme(&required.signing_algorithms, &SIGNING_ALGORITHMS)
        .and_then(|()| validate_scheme(&required.signing_keys, &SIGNING_KEYS))
        .and_then(|()| validate_scheme(&required.encryption_algorithms, &ENCRYPTION_ALGORITHMS))
        .and_then(|()| validate_scheme(&required.encryption_keys, &ENCRYPTION_KEYS))
        .and_then(|()| validate_scheme(&required.symmetric_key_schemes, &SYMMETRIC_KEY_SCHEMES))
        .and_then(|()| validate_scheme(&required.hash_algorithms, &HASH_ALGORITHMS))
        .and_then(|()| validate_formats(&required.crypto_key_formats, CRYPTO_KEY_FORMATS))
        .and_then(|()| validate_formats(&required.signature_formats, SIGNATURE_FORMATS))
        .map_err(|reason| handshake_failed(&reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the official 3.7.2 node puts in the static parameters of a synchronizer with the default JCE configuration
    /// (`SynchronizerParametersConfig.toStaticSynchronizerParameters`: every allowed scheme is required).
    fn official_default() -> Required {
        Required {
            signing_algorithms: [
                SigningAlgorithmSpec::Ed25519,
                SigningAlgorithmSpec::EcDsaSha256,
                SigningAlgorithmSpec::EcDsaSha384,
            ]
            .map(|s| s as i32)
            .into(),
            signing_keys: [
                SigningKeySpec::EcCurve25519,
                SigningKeySpec::EcP256,
                SigningKeySpec::EcP384,
                SigningKeySpec::EcSecp256k1,
            ]
            .map(|s| s as i32)
            .into(),
            encryption_algorithms: [
                EncryptionAlgorithmSpec::EciesHkdfHmacSha256Aes128cbc,
                EncryptionAlgorithmSpec::RsaOaepSha256,
            ]
            .map(|s| s as i32)
            .into(),
            encryption_keys: [EncryptionKeySpec::EcP256, EncryptionKeySpec::Rsa2048]
                .map(|s| s as i32)
                .into(),
            symmetric_key_schemes: [SymmetricKeyScheme::Aes128gcm as i32].into(),
            hash_algorithms: [HashAlgorithm::Sha256 as i32].into(),
            crypto_key_formats: [
                CryptoKeyFormat::Raw,
                CryptoKeyFormat::DerX509SubjectPublicKeyInfo,
                CryptoKeyFormat::DerPkcs8PrivateKeyInfo,
            ]
            .map(|s| s as i32)
            .into(),
            signature_formats: [SignatureFormat::Der, SignatureFormat::Concat]
                .map(|s| s as i32)
                .into(),
            max_signing_keys_per_entity: Some(20),
        }
    }

    #[test]
    fn the_official_default_synchronizer_passes_the_handshake() {
        assert_eq!(validate(&official_default()), Ok(()));
    }

    #[test]
    fn a_required_scheme_this_participant_does_not_support_fails_the_handshake() {
        let mut required = official_default();
        required
            .signing_algorithms
            .insert(SigningAlgorithmSpec::MlDsa65 as i32);
        let refused = validate(&required).unwrap_err();
        assert!(
            refused.starts_with("SYNCHRONIZER_CRYPTO_HANDSHAKE_FAILED(9,0)"),
            "{refused}"
        );
        assert!(refused.contains("Required schemes"), "{refused}");
    }

    #[test]
    fn a_synchronizer_that_does_not_require_this_participants_default_fails_the_handshake() {
        let mut required = official_default();
        required
            .signing_keys
            .remove(&(SigningKeySpec::EcCurve25519 as i32));
        let refused = validate(&required).unwrap_err();
        assert!(refused.contains("is not a required scheme"), "{refused}");
        let mut required = official_default();
        required
            .signature_formats
            .insert(SignatureFormat::Raw as i32 + 100);
        assert!(validate(&required)
            .unwrap_err()
            .contains("Required formats"));
    }
}
