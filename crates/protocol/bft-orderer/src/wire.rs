//! The envelope the BFT orderers of a synchronizer send each other (B1).
//!
//! [CANTON-NOTE: SEMANTICS] Source: `framework/data/SignedMessage.scala` and `core/integration/canton/crypto/CryptoProvider.scala`.
//! - `v30.SignedMessage.message` is the bytes of an `UntypedVersionedMessage` (`version`, `data`); `data` is the inner proto (`AvailabilityMessage`,
//!   `ConsensusMessage`, `StateTransferMessage`). The receiver refuses a wrapper whose version is not the one the runtime protocol version expects.
//! - What is signed is `Hash.build(<purpose of the message kind>, Sha256).addString(from).addByteString(<the message bytes as sent>).finish()`.
use canton_algo::signing::PublicKey;
use canton_algo::{HashBuildError, PurposeHash};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use canton_proto::com::digitalasset::canton::version::v1::{
    untyped_versioned_message::Wrapper, UntypedVersionedMessage,
};
use prost::Message;

/// The kinds of authenticated data, each with its own hash purpose (`CryptoProvider.AuthenticatedMessageType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticatedMessageType {
    BftOrderingPbftBlock,
    BftAvailabilityAck,
    BftBatchId,
    BftSignedAvailabilityMessage,
    BftSignedConsensusMessage,
    BftSignedStateTransferMessage,
    BftSignedRetransmissionMessage,
}

impl AuthenticatedMessageType {
    /// The name of the hash purpose in `HashPurpose.scala` (the same as the kind's name).
    pub fn purpose_name(self) -> &'static str {
        match self {
            Self::BftOrderingPbftBlock => "BftOrderingPbftBlock",
            Self::BftAvailabilityAck => "BftAvailabilityAck",
            Self::BftBatchId => "BftBatchId",
            Self::BftSignedAvailabilityMessage => "BftSignedAvailabilityMessage",
            Self::BftSignedConsensusMessage => "BftSignedConsensusMessage",
            Self::BftSignedStateTransferMessage => "BftSignedStateTransferMessage",
            Self::BftSignedRetransmissionMessage => "BftSignedRetransmissionMessage",
        }
    }

    /// The hash purpose id (`HashPurpose.scala`: 40, BftAvailabilityAck, BftBatchId, 47, 52, 53, 54).
    pub fn purpose_id(self) -> i32 {
        canton_algo::purpose_by_description(self.purpose_name())
            .map(|p| p.id)
            .expect("every BFT purpose is in the purpose table")
    }
}

/// `CryptoProvider.hashForMessage`: the hash a node signs (and a peer verifies) for a message of `kind` sent `from` a node.
pub fn hash_for_message(
    kind: AuthenticatedMessageType,
    from: &str,
    message_bytes: &[u8],
) -> Result<[u8; 32], HashBuildError> {
    let mut h = PurposeHash::new(kind.purpose_id());
    h.add_string(from)?;
    h.add_byte_string(message_bytes)?;
    h.finish()
}

/// The bytes a node's signature is made over: `hash.getCryptographicEvidence`, the multi-hash `uvarint(0x12) ++ uvarint(32) ++ digest`
/// (`Hash.scala:110`; `Signing.scala` signs `hash.getCryptographicEvidence`, the signing key usage is `ProtocolOnly`).
pub fn bytes_to_sign(digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.push(0x12);
    out.push(0x20);
    out.extend_from_slice(digest);
    out
}

/// Checks the signature of a message the way a node verifies it (`CryptoProvider.verifySignedMessage`): over [`bytes_to_sign`] of the hash of
/// [`hash_for_message`], with the sender's protocol key in the topology, by that key's spec.
pub fn verify_message_signature(
    kind: AuthenticatedMessageType,
    from: &str,
    message_bytes: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), String> {
    let digest = hash_for_message(kind, from, message_bytes).map_err(|e| format!("{e:?}"))?;
    verify_protocol_signature(&bytes_to_sign(&digest), signature, public_key)
}

/// An Ed25519 key of a test node, named `id` (its real fingerprint when `None`).
#[cfg(test)]
pub(crate) fn test_key(key: &ed25519_dalek::VerifyingKey, id: Option<&str>) -> PublicKey {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    let spki = key.to_public_key_der().unwrap();
    let mut key = canton_algo::member_signature::own_ed25519_key(spki.as_bytes()).unwrap();
    if let Some(id) = id {
        key.id = id.to_string();
    }
    key
}

/// An Ed25519 signature message (`r || s`) by the key `signed_by`.
#[cfg(test)]
pub(crate) fn test_signature(signature: Vec<u8>, signed_by: &str) -> Signature {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        SignatureFormat, SigningAlgorithmSpec,
    };
    Signature {
        format: SignatureFormat::Concat as i32,
        signature,
        signed_by: signed_by.to_string(),
        signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
        signature_delegation: None,
    }
}

/// Whether `signature` over `bytes` was made by `key` for the protocol (`SigningKeyUsage.ProtocolOnly`).
pub(crate) fn verify_protocol_signature(
    bytes: &[u8],
    signature: &Signature,
    key: &PublicKey,
) -> Result<(), String> {
    canton_algo::member_signature::verify_by_keys(
        std::slice::from_ref(key),
        bytes,
        signature,
        &canton_algo::member_signature::protocol_only(),
    )
    .map_err(|e| e.to_string())
}

/// Signs a message the way a node signs it (`CryptoProvider.signMessage`): Ed25519 (`r || s`) over [`bytes_to_sign`] of [`hash_for_message`], by the key named
/// `fingerprint`. The signature message is the one the peers read (`format` concat, `signing_algorithm_spec` Ed25519).
pub fn sign_message(
    kind: AuthenticatedMessageType,
    from: &str,
    message_bytes: &[u8],
    key: &ed25519_dalek::SigningKey,
    fingerprint: &str,
) -> Result<Signature, HashBuildError> {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        SignatureFormat, SigningAlgorithmSpec,
    };
    use ed25519_dalek::Signer;
    let digest = hash_for_message(kind, from, message_bytes)?;
    Ok(Signature {
        format: SignatureFormat::Concat as i32,
        signature: key.sign(&bytes_to_sign(&digest)).to_bytes().to_vec(),
        signed_by: fingerprint.to_string(),
        signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
        signature_delegation: None,
    })
}

/// `UntypedVersionedMessage(data, version)` as bytes: what `SignedMessage.message` holds around the inner proto.
pub fn wrap_versioned(version: i32, inner: &[u8]) -> Vec<u8> {
    UntypedVersionedMessage {
        wrapper: Some(Wrapper::Data(inner.to_vec())),
        version,
    }
    .encode_to_vec()
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnwrapError {
    Undecodable(String),
    /// "Wire protobuf version {got} does not match the expected version {expected}": refused even when the payload would parse.
    VersionMismatch {
        got: i32,
        expected: i32,
    },
    MissingData,
}

/// The inner bytes of a versioned message, after the check of the version (`SignedMessage.fromProtoWithNodeId`).
pub fn unwrap_versioned(bytes: &[u8], expected_version: i32) -> Result<Vec<u8>, UnwrapError> {
    let m = UntypedVersionedMessage::decode(bytes)
        .map_err(|e| UnwrapError::Undecodable(e.to_string()))?;
    if m.version != expected_version {
        return Err(UnwrapError::VersionMismatch {
            got: m.version,
            expected: expected_version,
        });
    }
    match m.wrapper {
        Some(Wrapper::Data(d)) => Ok(d),
        None => Err(UnwrapError::MissingData),
    }
}

/// A message as it travels: the bytes sent (kept as they were, the signature covers them), who sent it and the signature.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedMessage {
    pub message: Vec<u8>,
    pub from: String,
    pub signature: Signature,
}

impl SignedMessage {
    pub fn to_proto(&self) -> bft::SignedMessage {
        bft::SignedMessage {
            message: self.message.clone(),
            from: self.from.clone(),
            signature: Some(self.signature.clone()),
        }
    }

    /// `Signature.fromProtoV30(proto.getSignature)`: a message without a signature is refused.
    pub fn from_proto(p: bft::SignedMessage) -> Result<Self, &'static str> {
        Ok(Self {
            message: p.message,
            from: p.from,
            signature: p.signature.ok_or("a signed message without a signature")?,
        })
    }

    /// The hash to verify the signature against.
    pub fn hash(&self, kind: AuthenticatedMessageType) -> Result<[u8; 32], HashBuildError> {
        hash_for_message(kind, &self.from, &self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_are_the_ids_of_hash_purpose_scala() {
        use AuthenticatedMessageType::*;
        assert_eq!(BftOrderingPbftBlock.purpose_id(), 40);
        assert_eq!(BftSignedAvailabilityMessage.purpose_id(), 47);
        assert_eq!(BftSignedConsensusMessage.purpose_id(), 52);
        assert_eq!(BftSignedStateTransferMessage.purpose_id(), 53);
        assert_eq!(BftSignedRetransmissionMessage.purpose_id(), 54);
    }

    #[test]
    fn a_wrapped_message_unwraps_only_with_the_expected_version() {
        let wrapped = wrap_versioned(30, b"inner");
        assert_eq!(unwrap_versioned(&wrapped, 30).unwrap(), b"inner");
        assert_eq!(
            unwrap_versioned(&wrapped, 31),
            Err(UnwrapError::VersionMismatch {
                got: 30,
                expected: 31
            })
        );
        // an empty inner message still has its `data` (the `oneof` exists for this)
        assert_eq!(
            unwrap_versioned(&wrap_versioned(0, b""), 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn the_hash_depends_on_the_kind_the_sender_and_every_byte() {
        let base = hash_for_message(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            "node-1",
            b"abc",
        )
        .unwrap();
        for other in [
            hash_for_message(
                AuthenticatedMessageType::BftSignedAvailabilityMessage,
                "node-1",
                b"abc",
            ),
            hash_for_message(
                AuthenticatedMessageType::BftSignedConsensusMessage,
                "node-2",
                b"abc",
            ),
            hash_for_message(
                AuthenticatedMessageType::BftSignedConsensusMessage,
                "node-1",
                b"abd",
            ),
        ] {
            assert_ne!(base, other.unwrap());
        }
        assert_eq!(
            base,
            hash_for_message(
                AuthenticatedMessageType::BftSignedConsensusMessage,
                "node-1",
                b"abc"
            )
            .unwrap()
        );
    }

    #[test]
    fn the_signature_covers_the_multihash_of_the_digest() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let m = SignedMessage {
            message: wrap_versioned(30, b"inner"),
            from: "node-1".into(),
            signature: Signature::default(),
        };
        let digest = m
            .hash(AuthenticatedMessageType::BftSignedConsensusMessage)
            .unwrap();
        let to_sign = bytes_to_sign(&digest);
        assert_eq!(&to_sign[..2], &[0x12, 0x20]);
        assert_eq!(to_sign.len(), 34);
        let sig = key.sign(&to_sign);
        assert!(key.verifying_key().verify(&to_sign, &sig).is_ok());
        // a signature over the bare digest does not verify against the multi-hash
        let bare = key.sign(&digest);
        assert!(key.verifying_key().verify(&to_sign, &bare).is_err());
    }

    #[test]
    fn what_a_node_signs_verifies_for_its_peers() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let message = wrap_versioned(30, b"consensus");
        let sig = sign_message(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            "SEQ::rs1::x",
            &message,
            &key,
            "1220ab",
        )
        .unwrap();
        assert_eq!(sig.signed_by, "1220ab");
        verify_message_signature(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            "SEQ::rs1::x",
            &message,
            &sig,
            &test_key(&key.verifying_key(), Some("1220ab")),
        )
        .unwrap();
    }

    #[test]
    fn a_signed_message_without_a_signature_is_refused() {
        let p = bft::SignedMessage {
            message: vec![1],
            from: "n".into(),
            signature: None,
        };
        assert!(SignedMessage::from_proto(p).is_err());
    }
    /// A message the official 3.7.2 sequencer `sequencer2` sent a peer over the p2p stream of the oracle cluster (`scripts/bft-oracle.sh`, U-49 B2c): an
    /// `EpochStatus` in its signed wrapper, with the signature and the public key its topology lists. Our signing rules verify it: the hash purpose
    /// (`BftSignedRetransmissionMessage`), the sender, the bytes as sent and the multi-hash are the ones the official node signed.
    #[test]
    fn a_message_signed_by_the_official_sequencer_verifies() {
        let from =
            "SEQ::sequencer2::1220f2cffa12dff75f19519bdbcf4b4e01b54c5b8ec1c6f8f5fb72305373fa8b4108";
        let message = hex("0a47081a12151213080112030001011a0a0000000000000000000012151213080112030001011a0a0000000000000000000012151213080112030001011a0a00000000000000000000101e");
        let raw: [u8; 32] = hex("e2946bab140426146128ccd82d79fbc801103b31e2b5c7bfdb7c38c4d52fd844")
            .try_into()
            .unwrap();
        let key = test_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap(),
            None,
        );
        let signature = test_signature(hex("4d5ee2c198a17d234043bb7d1ef4cee774e3abf66fcfedc92640d512297312425dcf51718e99613fa322c7db4e3e3dcaeae408b5e62b82370f385caff922590f"), &key.id);
        verify_message_signature(
            AuthenticatedMessageType::BftSignedRetransmissionMessage,
            from,
            &message,
            &signature,
            &key,
        )
        .expect("the official signature verifies");
        // any change is refused: another kind, another sender, another byte
        assert!(verify_message_signature(
            AuthenticatedMessageType::BftSignedConsensusMessage,
            from,
            &message,
            &signature,
            &key
        )
        .is_err());
        assert!(verify_message_signature(
            AuthenticatedMessageType::BftSignedRetransmissionMessage,
            "SEQ::other::x",
            &message,
            &signature,
            &key
        )
        .is_err());
        let mut changed = message.clone();
        changed[0] ^= 1;
        assert!(verify_message_signature(
            AuthenticatedMessageType::BftSignedRetransmissionMessage,
            from,
            &changed,
            &signature,
            &key
        )
        .is_err());
        // the message is the versioned wrapper of version 30 around an `EpochStatus`
        assert!(unwrap_versioned(&message, 30).is_ok());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
