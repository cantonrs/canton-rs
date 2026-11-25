//! The data of the availability stage (B1): batch ids, availability acks and the hashes they are signed over.
//!
//! [CANTON-NOTE: SEMANTICS] Source: `framework/data/availability/BatchId.scala`, `AvailabilityAck.scala`, `framework/data/OrderingRequest.scala`.
//! - A batch id is the multi-hash (`0x12 0x20 ++ digest`) of `Hash.build(BftBatchId, Sha256)` over the epoch number (`addLong`) and every request: from protocol
//!   version 37 on, a request adds `addByteString(payload)` and `addString(tag)` and nothing else. (Before 37 each request also added the constant 34 and its trace
//!   context, and the `orderingStartInstant`; that older format is not ported: [`batch_id`] refuses it. Canton 3.7.2's stable versions are 36 and 37.)
//! - An availability ack is signed over `Hash.build(BftAvailabilityAck, Sha256).addByteString(<batch id bytes>).addLong(epoch).addString(from)`.
use canton_algo::{HashBuildError, PurposeHash};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;

/// The first protocol version with the new batch hash format (`OrderingRequestBatch.addToHashBuilder`).
pub const NEW_BATCH_HASH_FORMAT_FROM: u32 = 37;

/// `HashPurpose.BftBatchId` and `BftAvailabilityAck` (see `purposes`).
const BATCH_ID_PURPOSE: &str = "BftBatchId";
const AVAILABILITY_ACK_PURPOSE: &str = "BftAvailabilityAck";

fn purpose(name: &str) -> i32 {
    canton_algo::purpose_by_description(name)
        .map(|p| p.id)
        .expect("the BFT purposes are in the purpose table")
}

/// One ordering request of a batch (`OrderingRequest`: the fields the hash covers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub tag: String,
    pub payload: Vec<u8>,
}

/// A batch id: the multi-hash bytes (`BatchId.getCryptographicEvidence`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchId(pub Vec<u8>);

impl BatchId {
    /// `BatchId.fromProto` (`Hash.fromProtoPrimitive`): SHA-256 multi-hash bytes only (`0x12 0x20` and 32 bytes).
    pub fn from_proto(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() == 34 && bytes[0] == 0x12 && bytes[1] == 0x20 {
            Ok(Self(bytes.to_vec()))
        } else {
            Err("not a SHA-256 multi-hash")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BatchIdError {
    /// The batch hash format of protocol versions below 37 is not ported.
    OldHashFormatNotPorted(u32),
    Hash(HashBuildError),
}

/// `BatchId.from`: the id of the batch of `requests` of `epoch`, for the synchronizer's protocol version.
pub fn batch_id(
    requests: &[Request],
    epoch: i64,
    protocol_version: u32,
) -> Result<BatchId, BatchIdError> {
    if protocol_version < NEW_BATCH_HASH_FORMAT_FROM {
        return Err(BatchIdError::OldHashFormatNotPorted(protocol_version));
    }
    let mut h = PurposeHash::new(purpose(BATCH_ID_PURPOSE));
    let hash = (|| {
        h.add_long(epoch)?;
        for r in requests {
            h.add_byte_string(&r.payload)?;
            h.add_string(&r.tag)?;
        }
        h.finish()
    })()
    .map_err(BatchIdError::Hash)?;
    Ok(BatchId(crate::wire::bytes_to_sign(&hash)))
}

/// `AvailabilityAck.hashFor`: the digest a node signs to acknowledge that it stores the batch (sign [`crate::wire::bytes_to_sign`] of it).
pub fn ack_hash(batch: &BatchId, epoch: i64, from: &str) -> Result<[u8; 32], HashBuildError> {
    let mut h = PurposeHash::new(purpose(AVAILABILITY_ACK_PURPOSE));
    h.add_byte_string(&batch.0)?;
    h.add_long(epoch)?;
    h.add_string(from)?;
    h.finish()
}

/// Signs an availability ack: the node `from` says it stores the batch (`AvailabilityAck.hashFor` signed with the node's protocol key). The `signature` of a
/// `StoreResponse`.
pub fn sign_ack(
    batch: &BatchId,
    epoch: i64,
    from: &str,
    key: &ed25519_dalek::SigningKey,
    fingerprint: &str,
) -> Result<canton_proto::com::digitalasset::canton::crypto::v30::Signature, HashBuildError> {
    use canton_proto::com::digitalasset::canton::crypto::v30::{
        Signature, SignatureFormat, SigningAlgorithmSpec,
    };
    use ed25519_dalek::Signer;
    let digest = ack_hash(batch, epoch, from)?;
    Ok(Signature {
        format: SignatureFormat::Concat as i32,
        signature: key
            .sign(&crate::wire::bytes_to_sign(&digest))
            .to_bytes()
            .to_vec(),
        signed_by: fingerprint.to_string(),
        signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
        signature_delegation: None,
    })
}

/// Checks the signature of an availability ack the way a node does (`AvailabilityAck.hashFor` signed with the node's protocol key): over the
/// multi-hash of [`ack_hash`], with the acknowledging node's key.
pub fn verify_ack(
    batch: &BatchId,
    epoch: i64,
    from: &str,
    signature: &Signature,
    public_key: &canton_algo::signing::PublicKey,
) -> Result<(), String> {
    let digest = ack_hash(batch, epoch, from).map_err(|e| format!("{e:?}"))?;
    crate::wire::verify_protocol_signature(
        &crate::wire::bytes_to_sign(&digest),
        signature,
        public_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn req(tag: &str, payload: &[u8]) -> Request {
        Request {
            tag: tag.into(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn the_batch_id_is_the_multihash_of_the_epoch_and_each_payload_and_tag() {
        let id = batch_id(&[req("send", b"ab"), req("ack", b"c")], 7, 37).unwrap();
        // the same bytes by hand: purpose, epoch (8), then per request len+payload, len+tag
        let mut m = Sha256::new();
        m.update(purpose(BATCH_ID_PURPOSE).to_be_bytes());
        m.update(7i64.to_be_bytes());
        for (tag, payload) in [("send", &b"ab"[..]), ("ack", &b"c"[..])] {
            m.update((payload.len() as i32).to_be_bytes());
            m.update(payload);
            m.update((tag.len() as i32).to_be_bytes());
            m.update(tag.as_bytes());
        }
        let mut expect = vec![0x12, 0x20];
        expect.extend_from_slice(&m.finalize());
        assert_eq!(id.0, expect);
        assert!(BatchId::from_proto(&id.0).is_ok());
    }

    #[test]
    fn the_batch_id_depends_on_the_epoch_the_order_and_the_content() {
        let a = [req("send", b"1"), req("send", b"2")];
        let base = batch_id(&a, 1, 37).unwrap();
        assert_ne!(base, batch_id(&a, 2, 37).unwrap());
        assert_ne!(
            base,
            batch_id(&[a[1].clone(), a[0].clone()], 1, 37).unwrap()
        );
        assert_ne!(base, batch_id(&a[..1], 1, 37).unwrap());
        assert_eq!(base, batch_id(&a, 1, 37).unwrap());
    }

    #[test]
    fn the_older_hash_format_is_refused_not_guessed() {
        assert_eq!(
            batch_id(&[], 1, 36),
            Err(BatchIdError::OldHashFormatNotPorted(36))
        );
    }

    #[test]
    fn the_ack_hash_covers_the_batch_the_epoch_and_the_acking_node() {
        let b = batch_id(&[req("send", b"x")], 3, 37).unwrap();
        let base = ack_hash(&b, 3, "node-1").unwrap();
        assert_ne!(base, ack_hash(&b, 4, "node-1").unwrap());
        assert_ne!(base, ack_hash(&b, 3, "node-2").unwrap());
        let other = batch_id(&[req("send", b"y")], 3, 37).unwrap();
        assert_ne!(base, ack_hash(&other, 3, "node-1").unwrap());
        assert!(BatchId::from_proto(&[1, 2, 3]).is_err());
    }
    /// An availability ack of the official sequencer `sequencer1` for a batch of the oracle cluster (`scripts/bft-oracle.sh join`, U-49): the batch id, the epoch, the
    /// acknowledging node, its signature and the public key its topology lists. Our hash rule verifies it.
    #[test]
    fn an_ack_this_node_signs_verifies_the_way_the_official_ones_do() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let id = batch_id(&[req("tag", b"payload")], 12, 37).unwrap();
        let sig = sign_ack(&id, 12, "SEQ::rs1", &key, "fp").unwrap();
        let public = crate::wire::test_key(&key.verifying_key(), Some("fp"));
        assert_eq!(verify_ack(&id, 12, "SEQ::rs1", &sig, &public), Ok(()));
        // another acknowledging node, epoch or batch does not verify
        assert!(verify_ack(&id, 12, "SEQ::other", &sig, &public).is_err());
        assert!(verify_ack(&id, 13, "SEQ::rs1", &sig, &public).is_err());
    }

    #[test]
    fn an_ack_signed_by_the_official_sequencer_verifies() {
        let batch = BatchId::from_proto(&hex(
            "1220f95b49e6515b71032f886bb298120bd348d9ad66865c279073216a78f09bd7c5",
        ))
        .unwrap();
        let from =
            "SEQ::sequencer1::1220cfcf30c0ed0aa343160f6ad690d1ecc922f0ee91243dac37c8dd2f7157f2661d";
        let raw: [u8; 32] = hex("332b40f7b3f8833977bcbf151dfa1ff4b1c10461e3d0a840980fd3b971d1be71")
            .try_into()
            .unwrap();
        let key = crate::wire::test_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&raw).unwrap(),
            None,
        );
        let signature = crate::wire::test_signature(hex("ef04a30c799953bba2d3cc8972220e001601fbc47a8596b650111e326543f4ba5daf6044c52d50cb0d40dcd220f320bfda5584105eedbdd9860a397c29ca830d"), &key.id);
        verify_ack(&batch, 31, from, &signature, &key).expect("the official ack verifies");
        assert!(verify_ack(&batch, 32, from, &signature, &key).is_err());
        assert!(verify_ack(&batch, 31, "SEQ::other::x", &signature, &key).is_err());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
}
