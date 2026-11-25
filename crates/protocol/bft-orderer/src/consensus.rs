//! The consensus messages of the BFT orderer and the hash a block is known by (B1).
//!
//! [CANTON-NOTE: SEMANTICS] Source: `framework/modules/ConsensusSegment.scala` (`PrePrepare`, `Prepare`, `Commit`), `SupportedVersions.scala`
//! (`ProtoData30 = ProtoVersion(30)`).
//! - The bytes of a consensus message as it is sent and signed (`getCryptographicEvidence`) are an `UntypedVersionedMessage` of version 30 around the
//!   serialized `v30.ConsensusMessage`.
//! - The hash of a block is the hash of its `PrePrepare`: `Hash.build(BftOrderingPbftBlock, Sha256).addByteString(<the PrePrepare's evidence>)`. It covers the
//!   whole message (block metadata, view number, ordering block, canonical commit set, sender). `Prepare.block_hash` and `Commit.block_hash` carry it as multi-hash
//!   bytes (`0x12 0x20 ++ digest`).
use crate::wire::{bytes_to_sign, wrap_versioned};
use canton_algo::{HashBuildError, PurposeHash};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use prost::Message;

/// `SupportedVersions.ProtoData30`: the wire version of every BFT message of protocol versions 36 and 37.
pub const PROTO_DATA_30: i32 = 30;

/// `getCryptographicEvidence` of a consensus message: what is signed and what a block hash covers.
pub fn consensus_evidence(message: &bft::ConsensusMessage) -> Vec<u8> {
    wrap_versioned(PROTO_DATA_30, &message.encode_to_vec())
}

/// `PrePrepare.hash`: the digest a block is known by.
pub fn pre_prepare_hash(pre_prepare: &bft::ConsensusMessage) -> Result<[u8; 32], HashBuildError> {
    let purpose = canton_algo::purpose_by_description("BftOrderingPbftBlock")
        .map(|p| p.id)
        .expect("BftOrderingPbftBlock is in the purpose table");
    let mut h = PurposeHash::new(purpose);
    h.add_byte_string(&consensus_evidence(pre_prepare))?;
    h.finish()
}

/// The hash a block is known by, from the evidence bytes of its `PrePrepare` **as they were sent or received** (`Hash.build(BftOrderingPbftBlock, Sha256)
/// .addByteString(<evidence>)`): a node that received the message hashes the bytes it received, it does not encode the message again. Multi-hash bytes, the
/// `block_hash` field of a `Prepare` or a `Commit`.
pub fn block_hash_of_evidence(evidence: &[u8]) -> Result<Vec<u8>, HashBuildError> {
    let purpose = canton_algo::purpose_by_description("BftOrderingPbftBlock")
        .map(|p| p.id)
        .expect("BftOrderingPbftBlock is in the purpose table");
    let mut h = PurposeHash::new(purpose);
    h.add_byte_string(evidence)?;
    Ok(block_hash_field(&h.finish()?))
}

/// The `block_hash` field of a `Prepare` or `Commit` for a block: the multi-hash bytes of its digest.
pub fn block_hash_field(digest: &[u8; 32]) -> Vec<u8> {
    bytes_to_sign(digest)
}

/// A `ConsensusMessage` carrying a `PrePrepare` (`PrePrepare.toProto`).
pub fn pre_prepare_message(
    epoch: i64,
    block: i64,
    view: i64,
    from: &str,
    ordering_block: bft::OrderingBlock,
    canonical_commit_set: bft::CanonicalCommitSet,
) -> bft::ConsensusMessage {
    bft::ConsensusMessage {
        block_metadata: Some(bft::BlockMetadata {
            epoch_number: epoch,
            block_number: block,
        }),
        view_number: view,
        from: from.to_string(),
        message: Some(bft::consensus_message::Message::PrePrepare(
            bft::PrePrepare {
                block: Some(ordering_block),
                bft_time_canonical_commit_set: Some(canonical_commit_set),
            },
        )),
    }
}

/// A `ConsensusMessage` carrying a `Prepare` for the block with `block_hash` (`Prepare.toProto`).
pub fn prepare_message(
    epoch: i64,
    block: i64,
    view: i64,
    from: &str,
    block_hash: Vec<u8>,
) -> bft::ConsensusMessage {
    bft::ConsensusMessage {
        block_metadata: Some(bft::BlockMetadata {
            epoch_number: epoch,
            block_number: block,
        }),
        view_number: view,
        from: from.to_string(),
        message: Some(bft::consensus_message::Message::Prepare(bft::Prepare {
            block_hash,
        })),
    }
}

/// A `ConsensusMessage` carrying a `Commit`: the block hash and the local creation time in microseconds (`Commit.toProto`).
pub fn commit_message(
    epoch: i64,
    block: i64,
    view: i64,
    from: &str,
    block_hash: Vec<u8>,
    local_timestamp_micros: i64,
) -> bft::ConsensusMessage {
    bft::ConsensusMessage {
        block_metadata: Some(bft::BlockMetadata {
            epoch_number: epoch,
            block_number: block,
        }),
        view_number: view,
        from: from.to_string(),
        message: Some(bft::consensus_message::Message::Commit(bft::Commit {
            block_hash,
            local_timestamp: local_timestamp_micros,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn empty_pre_prepare(view: i64, from: &str) -> bft::ConsensusMessage {
        pre_prepare_message(
            1,
            5,
            view,
            from,
            bft::OrderingBlock { proofs: vec![] },
            bft::CanonicalCommitSet {
                canonical_commits: vec![],
            },
        )
    }

    #[test]
    fn the_evidence_is_a_version_30_wrapper_around_the_message() {
        let m = empty_pre_prepare(0, "n1");
        let e = consensus_evidence(&m);
        assert_eq!(
            crate::wire::unwrap_versioned(&e, PROTO_DATA_30).unwrap(),
            m.encode_to_vec()
        );
        assert!(crate::wire::unwrap_versioned(&e, 31).is_err());
    }

    #[test]
    fn the_block_hash_is_the_hash_of_the_whole_pre_prepare_evidence() {
        let m = empty_pre_prepare(0, "n1");
        let e = consensus_evidence(&m);
        let mut h = Sha256::new();
        h.update(40i32.to_be_bytes()); // HashPurpose.BftOrderingPbftBlock
        h.update((e.len() as i32).to_be_bytes());
        h.update(&e);
        let by_hand: [u8; 32] = h.finalize().into();
        assert_eq!(pre_prepare_hash(&m).unwrap(), by_hand);
        // every field of the message is covered: the view, the sender, the position
        assert_ne!(
            pre_prepare_hash(&m).unwrap(),
            pre_prepare_hash(&empty_pre_prepare(1, "n1")).unwrap()
        );
        assert_ne!(
            pre_prepare_hash(&m).unwrap(),
            pre_prepare_hash(&empty_pre_prepare(0, "n2")).unwrap()
        );
    }

    #[test]
    fn a_prepare_and_a_commit_name_the_block_by_its_multihash() {
        let digest = pre_prepare_hash(&empty_pre_prepare(0, "n1")).unwrap();
        let field = block_hash_field(&digest);
        assert_eq!(field.len(), 34);
        assert_eq!(&field[..2], &[0x12, 0x20]);
        let p = prepare_message(1, 5, 0, "n2", field.clone());
        let c = commit_message(1, 5, 0, "n2", field.clone(), 1_700_000_000_000_000);
        match (p.message, c.message) {
            (
                Some(bft::consensus_message::Message::Prepare(p)),
                Some(bft::consensus_message::Message::Commit(c)),
            ) => {
                assert_eq!(p.block_hash, field);
                assert_eq!(c.block_hash, field);
                assert_eq!(c.local_timestamp, 1_700_000_000_000_000);
            }
            _ => panic!("wrong message kinds"),
        }
    }
}
