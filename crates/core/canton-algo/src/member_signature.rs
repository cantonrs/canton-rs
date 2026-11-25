//! `SyncCryptoVerifier.verifySignature` once the signer's long-term keys at the relevant time are known: the key the signature
//! names among them, then `JcePureCrypto.verifySignature` by that key's spec and the signature's format.
use std::collections::BTreeSet;

use canton_proto::com::digitalasset::canton::crypto::v30::Signature as PbSignature;
use prost::Message as _;

use crate::signature_delegation;
use crate::signing::{self, ProtoError, PublicKey, Signature, Usage, VerifyError};

/// Why a member's signature was refused (the class names of `SignatureCheckError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheckError {
    /// The signature message itself does not parse (`Signature.fromProtoV30`).
    Parse(ProtoError),
    SignerHasNoValidKeys,
    /// None of the signer's keys with the expected usage is the one the signature names.
    SignatureWithWrongKey(String),
    /// The check of `JcePureCrypto.verifySignature` failed.
    Pure(VerifyError),
    /// The signature carries a session-key delegation, which this verifier does not follow.
    UnsupportedDelegation,
    /// The delegation is not valid at the time, or its signature by the long-term key does not verify.
    InvalidSignatureDelegation(String),
    /// A session key signs only protocol messages.
    UnsupportedDelegationSignatureError(String),
    /// The hash of the delegation could not be built.
    DelegationHashingError(String),
}

impl std::fmt::Display for SignatureCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureCheckError::Parse(e) => write!(f, "the signature does not parse: {e:?}"),
            SignatureCheckError::SignerHasNoValidKeys => f.write_str("SignerHasNoValidKeys"),
            SignatureCheckError::SignatureWithWrongKey(k) => {
                write!(
                    f,
                    "SignatureWithWrongKey: {k} is not a valid key of the signer"
                )
            }
            SignatureCheckError::Pure(e) => f.write_str(e.class()),
            SignatureCheckError::UnsupportedDelegation => {
                f.write_str("a signature with a session-key delegation is not supported here")
            }
            SignatureCheckError::InvalidSignatureDelegation(why) => {
                write!(f, "InvalidSignatureDelegation: {why}")
            }
            SignatureCheckError::UnsupportedDelegationSignatureError(why) => {
                write!(f, "UnsupportedDelegationSignatureError: {why}")
            }
            SignatureCheckError::DelegationHashingError(why) => {
                write!(f, "DelegationHashingError: {why}")
            }
        }
    }
}

impl std::error::Error for SignatureCheckError {}

/// `Signature.fromProtoV30` of a message prost decoded.
pub fn signature_from_proto(signature: &PbSignature) -> Result<Signature, ProtoError> {
    signing::parse_signature(&signature.encode_to_vec())
}

/// Whether `signature` over `hash` was made by one of `keys` (the signer's long-term keys) allowed one of `usage`.
///
/// [CANTON-NOTE: SEMANTICS] `SyncCryptoVerifier.verifySignatureInternal` without a delegation: the keys with a matching usage, the
/// one whose fingerprint is the signature's `signed_by` (`SignerHasNoValidKeys` / `SignatureWithWrongKey` otherwise), then
/// `JcePureCrypto.verifySignature` (Ed25519, ECDSA P-256/P-384/secp256k1).
pub fn verify_by_keys(
    keys: &[PublicKey],
    hash: &[u8],
    signature: &PbSignature,
    usage: &BTreeSet<Usage>,
) -> Result<(), SignatureCheckError> {
    let signature = signature_from_proto(signature).map_err(SignatureCheckError::Parse)?;
    if signature.delegation.is_some() {
        return Err(SignatureCheckError::UnsupportedDelegation);
    }
    let key = long_term_key(keys, &signature.authorizing_key, usage)?;
    signing::verify_signature(hash, key, &signature, usage).map_err(SignatureCheckError::Pure)
}

/// Where and when a session-key delegation is checked: the logical synchronizer id (`name::namespace`) and the timestamp of the topology
/// snapshot the signature is verified at (microseconds since the epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationScope<'a> {
    pub synchronizer_id: &'a str,
    pub at_micros: i64,
}

/// The logical synchronizer id (`name::namespace`) of a physical one (`name::namespace::<protocol version>-<serial>`).
pub fn logical_synchronizer_id(physical: &str) -> &str {
    match physical.rsplit_once("::") {
        Some((logical, _)) if logical.contains("::") => logical,
        _ => physical,
    }
}

/// [`verify_by_keys`] that also follows a session-key delegation (`SyncCryptoVerifier.verifySignatureWithSessionKey`).
///
/// [CANTON-NOTE: SEMANTICS] `determineSessionKeyIsValid`, in its order: the usage must be exactly `ProtocolOnly`; the delegation must
/// cover `scope.at_micros`; the long-term key it names must be one of `keys` with the usage; its signature over
/// `SignatureDelegation.generateHash` (with the logical synchronizer id) must verify with that key. Then the signature itself is verified
/// with the session key. Producing session-key signatures is not done here.
pub fn verify_by_keys_at(
    keys: &[PublicKey],
    hash: &[u8],
    signature: &PbSignature,
    usage: &BTreeSet<Usage>,
    scope: &DelegationScope<'_>,
) -> Result<(), SignatureCheckError> {
    let signature = signature_from_proto(signature).map_err(SignatureCheckError::Parse)?;
    let Some(delegation) = &signature.delegation else {
        let key = long_term_key(keys, &signature.authorizing_key, usage)?;
        return signing::verify_signature(hash, key, &signature, usage)
            .map_err(SignatureCheckError::Pure);
    };
    if *usage != protocol_only() {
        return Err(SignatureCheckError::UnsupportedDelegationSignatureError(format!(
            "Session signing keys are not supposed to be used for non-protocol messages. Requested usage: {usage:?}"
        )));
    }
    if !signature_delegation::covers(delegation, scope.at_micros) {
        return Err(SignatureCheckError::InvalidSignatureDelegation(format!(
            "The current signature delegation is only valid from {} for {} s while the current timestamp is {}",
            delegation.valid_from_micros, delegation.duration_seconds, scope.at_micros
        )));
    }
    let long_term = long_term_key(keys, &signature.authorizing_key, usage)?;
    let delegation_hash = signature_delegation::delegation_hash(scope.synchronizer_id, delegation)
        .map_err(|e| SignatureCheckError::DelegationHashingError(format!("{e:?}")))?;
    let authorization = Signature {
        format: delegation.signature_format,
        signature: delegation.signature.clone(),
        signed_by: signature.authorizing_key.clone(),
        spec: delegation.signature_spec,
        delegation: None,
        authorizing_key: signature.authorizing_key.clone(),
    };
    signing::verify_signature(&delegation_hash, long_term, &authorization, usage)
        .map_err(|e| SignatureCheckError::InvalidSignatureDelegation(e.class().to_string()))?;
    signing::verify_signature(hash, &delegation.session_key, &signature, usage)
        .map_err(SignatureCheckError::Pure)
}

/// `determineLongTermKeyForVerification` over the keys `signingKeys(member, usage)` returns.
fn long_term_key<'a>(
    keys: &'a [PublicKey],
    authorizing_key: &str,
    usage: &BTreeSet<Usage>,
) -> Result<&'a PublicKey, SignatureCheckError> {
    let mut valid = keys
        .iter()
        .filter(|k| k.usage.intersection(usage).next().is_some())
        .peekable();
    if valid.peek().is_none() {
        return Err(SignatureCheckError::SignerHasNoValidKeys);
    }
    valid
        .find(|k| k.id == authorizing_key)
        .ok_or_else(|| SignatureCheckError::SignatureWithWrongKey(authorizing_key.to_string()))
}

/// A key this node made itself (its Ed25519 DER SubjectPublicKeyInfo), trusted for every usage.
pub fn own_ed25519_key(spki_der: &[u8]) -> Result<PublicKey, ProtoError> {
    signing::create_public_key(
        signing::KeyFormat::DerX509Spki,
        spki_der,
        signing::KeySpec::EcCurve25519,
        Usage::all(),
    )
}

/// `SigningKeyUsage.ProtocolOnly`.
pub fn protocol_only() -> BTreeSet<Usage> {
    [Usage::Protocol].into()
}

/// `SigningKeyUsage.SequencerAuthenticationOnly`.
pub fn sequencer_authentication_only() -> BTreeSet<Usage> {
    [Usage::SequencerAuthentication].into()
}

/// `SigningKeyUsage.NamespaceOrProofOfOwnership`.
pub fn namespace_or_proof_of_ownership() -> BTreeSet<Usage> {
    [Usage::Namespace, Usage::ProofOfOwnership].into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{create_public_key, KeyFormat, KeySpec};
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    const HASH: [u8; 34] = {
        let mut h = [7u8; 34];
        h[0] = 0x12;
        h[1] = 0x20;
        h
    };

    fn pb(format: i32, spec: i32, signature: Vec<u8>, signed_by: &str) -> PbSignature {
        PbSignature {
            format,
            signature,
            signed_by: signed_by.to_string(),
            signing_algorithm_spec: spec,
            signature_delegation: None,
        }
    }

    fn ed25519(seed: u8, usage: BTreeSet<Usage>) -> (ed25519_dalek::SigningKey, PublicKey) {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let key = create_public_key(
            KeyFormat::DerX509Spki,
            spki.as_bytes(),
            KeySpec::EcCurve25519,
            usage,
        )
        .unwrap();
        (sk, key)
    }

    fn p256_key(usage: BTreeSet<Usage>) -> (p256::ecdsa::SigningKey, PublicKey) {
        use p256::pkcs8::EncodePublicKey;
        let sk = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap();
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let key = create_public_key(
            KeyFormat::DerX509Spki,
            spki.as_bytes(),
            KeySpec::EcP256,
            usage,
        )
        .unwrap();
        (sk, key)
    }

    #[test]
    fn an_ecdsa_p256_signature_verifies_by_the_key_spec() {
        use p256::ecdsa::signature::Signer;
        let (sk, key) = p256_key(protocol_only());
        let sig: p256::ecdsa::Signature = sk.sign(&HASH);
        let der = sig.to_der().as_bytes().to_vec();
        let signature = pb(2, 2, der.clone(), &key.id);
        assert_eq!(
            verify_by_keys(
                std::slice::from_ref(&key),
                &HASH,
                &signature,
                &protocol_only()
            ),
            Ok(())
        );
        let mut tampered = der;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            verify_by_keys(
                &[key],
                &HASH,
                &pb(2, 2, tampered, &signature.signed_by),
                &protocol_only()
            ),
            Err(SignatureCheckError::Pure(VerifyError::InvalidSignature))
        );
    }

    #[test]
    fn the_signer_must_hold_the_named_key_with_the_usage() {
        use ed25519_dalek::Signer;
        let (sk, key) = ed25519(1, protocol_only());
        let (_, other) = ed25519(2, protocol_only());
        let signature = pb(3, 1, sk.sign(&HASH).to_bytes().to_vec(), &key.id);
        assert_eq!(
            verify_by_keys(
                &[other.clone(), key.clone()],
                &HASH,
                &signature,
                &protocol_only()
            ),
            Ok(())
        );
        assert_eq!(
            verify_by_keys(&[other], &HASH, &signature, &protocol_only()),
            Err(SignatureCheckError::SignatureWithWrongKey(key.id.clone()))
        );
        assert_eq!(
            verify_by_keys(&[key], &HASH, &signature, &sequencer_authentication_only()),
            Err(SignatureCheckError::SignerHasNoValidKeys)
        );
    }

    /// [CANTON-NOTE: SEMANTICS] A small-order `R` (here the identity) is what separates `verify_strict` from the rule
    /// `JcePureCrypto` and the oracle vectors follow (`verify`: S below the group order, the cofactorless equation on a key
    /// validated as `validatePublicKeyFull`). No honest signer produces it; it is accepted as Bouncy Castle accepts it.
    #[test]
    fn an_ed25519_signature_with_a_small_order_r_follows_the_jce_rule() {
        let (sk, key) = ed25519(5, protocol_only());
        let mut r = [0u8; 32];
        r[0] = 1;
        let a = sk.verifying_key().to_bytes();
        let k = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(r)
                .chain_update(a)
                .chain_update(HASH)
                .finalize()
                .into(),
        );
        let s = k * sk.to_scalar();
        let mut raw = r.to_vec();
        raw.extend_from_slice(s.as_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&raw).unwrap();
        assert!(sk.verifying_key().verify_strict(&HASH, &sig).is_err());
        assert_eq!(
            verify_by_keys(
                std::slice::from_ref(&key),
                &HASH,
                &pb(3, 1, raw, &key.id),
                &protocol_only()
            ),
            Ok(())
        );
    }
}

#[cfg(test)]
mod delegation_tests {
    use super::*;
    use crate::signing::{create_public_key, KeyFormat, KeySpec};
    use canton_proto::com::digitalasset::canton::crypto::v30::SignatureDelegation as PbDelegation;
    use ed25519_dalek::pkcs8::EncodePublicKey as _;
    use ed25519_dalek::Signer as _;

    const SYNC: &str = "da::1220aa";
    const FROM: i64 = 1_700_000_000_000_000;
    const SECONDS: i32 = 300;
    const HASH: [u8; 34] = {
        let mut h = [9u8; 34];
        h[0] = 0x12;
        h[1] = 0x20;
        h
    };

    /// `SignatureDelegation.generateHash` written out from Signing.scala, independently of the code under test.
    fn delegation_hash(session_id: &str, spec: i32, synchronizer: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let string = |s: &str| {
            [
                (s.len() as i32).to_be_bytes().to_vec(),
                s.as_bytes().to_vec(),
            ]
            .concat()
        };
        let usage = [2i32, 4, 5]
            .iter()
            .flat_map(|i| i.to_be_bytes())
            .collect::<Vec<u8>>();
        let validity = [FROM.to_be_bytes(), i64::from(SECONDS).to_be_bytes()].concat();
        let mut h = Sha256::new();
        h.update(56i32.to_be_bytes());
        h.update(string(session_id));
        h.update(spec.to_be_bytes());
        h.update(4i32.to_be_bytes()); // DER X.509 SubjectPublicKeyInfo
        h.update([(usage.len() as i32).to_be_bytes().to_vec(), usage].concat());
        h.update([(validity.len() as i32).to_be_bytes().to_vec(), validity].concat());
        h.update(string(synchronizer));
        [vec![0x12, 0x20], h.finalize().to_vec()].concat()
    }

    /// A long-term Ed25519 key, and a signature of [`HASH`] by a P-256 session key it delegated to for [`SECONDS`] from [`FROM`].
    fn delegated(synchronizer_in_hash: &str) -> (PublicKey, PbSignature) {
        use p256::ecdsa::signature::Signer as _;
        use p256::pkcs8::EncodePublicKey as _;
        let long_term = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let long_term_key = create_public_key(
            KeyFormat::DerX509Spki,
            long_term
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
            KeySpec::EcCurve25519,
            protocol_only(),
        )
        .unwrap();
        let session = p256::ecdsa::SigningKey::from_slice(&[22; 32]).unwrap();
        let session_spki = session
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let session_id = create_public_key(
            KeyFormat::DerX509Spki,
            &session_spki,
            KeySpec::EcP256,
            protocol_only(),
        )
        .unwrap()
        .id;
        let authorization = long_term.sign(&delegation_hash(&session_id, 2, synchronizer_in_hash));
        let message: p256::ecdsa::Signature = session.sign(&HASH);
        let signature = PbSignature {
            format: 2,                 // DER
            signing_algorithm_spec: 2, // EC-DSA-SHA256
            signature: message.to_der().as_bytes().to_vec(),
            signed_by: long_term_key.id.clone(),
            signature_delegation: Some(PbDelegation {
                session_key: session_spki,
                session_key_spec: 2,
                validity_period_from_inclusive: FROM,
                validity_period_duration_seconds: SECONDS as u32,
                format: 3,                 // concat
                signing_algorithm_spec: 1, // Ed25519
                signature: authorization.to_bytes().to_vec(),
            }),
        };
        (long_term_key, signature)
    }

    fn at(micros: i64) -> DelegationScope<'static> {
        DelegationScope {
            synchronizer_id: SYNC,
            at_micros: micros,
        }
    }

    #[test]
    fn a_session_key_signature_verifies_through_its_delegation() {
        let (key, signature) = delegated(SYNC);
        assert_eq!(
            verify_by_keys_at(&[key], &HASH, &signature, &protocol_only(), &at(FROM + 1)),
            Ok(())
        );
    }

    #[test]
    fn a_delegation_is_refused_outside_its_period_elsewhere_or_for_another_usage() {
        let (key, signature) = delegated(SYNC);
        let keys = std::slice::from_ref(&key);
        let ends = FROM + i64::from(SECONDS) * 1_000_000;
        assert!(matches!(
            verify_by_keys_at(keys, &HASH, &signature, &protocol_only(), &at(ends)),
            Err(SignatureCheckError::InvalidSignatureDelegation(_))
        ));
        assert!(matches!(
            verify_by_keys_at(keys, &HASH, &signature, &protocol_only(), &at(FROM - 1)),
            Err(SignatureCheckError::InvalidSignatureDelegation(_))
        ));
        let (key, elsewhere) = delegated("other::1220bb");
        assert!(matches!(
            verify_by_keys_at(
                std::slice::from_ref(&key),
                &HASH,
                &elsewhere,
                &protocol_only(),
                &at(FROM)
            ),
            Err(SignatureCheckError::InvalidSignatureDelegation(_))
        ));
        assert!(matches!(
            verify_by_keys_at(
                keys,
                &HASH,
                &signature,
                &[Usage::Protocol, Usage::Namespace].into(),
                &at(FROM)
            ),
            Err(SignatureCheckError::UnsupportedDelegationSignatureError(_))
        ));
        let mut other_message = HASH;
        other_message[5] ^= 1;
        assert_eq!(
            verify_by_keys_at(
                keys,
                &other_message,
                &signature,
                &protocol_only(),
                &at(FROM)
            ),
            Err(SignatureCheckError::Pure(VerifyError::InvalidSignature))
        );
        assert!(matches!(
            verify_by_keys_at(&[], &HASH, &signature, &protocol_only(), &at(FROM)),
            Err(SignatureCheckError::SignerHasNoValidKeys)
        ));
    }
}
