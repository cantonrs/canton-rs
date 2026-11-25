//! Hashes and signatures of the ordering messages.
//!
//! [CANTON-NOTE: INVARIANT] Every signature is over a digest that starts with the **kind** of the message (`PrePrepare`, `Prepare`,
//! `Commit`, ...), so a signature made for one kind is worth nothing as another: a `Prepare` of a block cannot be presented as the `Commit`
//! that block's certificate needs. The old engine signed the block hash for both, which made that substitution possible.
use canton_algo::hash::sha256_with_purpose;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub type Hash = [u8; 32];

/// `HashPurpose.BftOrderingPbftBlock`: proposals and the chain of committed blocks.
pub const PURPOSE_BLOCK: i32 = 40;
/// `HashPurpose.BftSignedConsensusMessage`: every signed consensus message.
pub const PURPOSE_CONSENSUS_MESSAGE: i32 = 52;

/// A length-prefixed encoding for what is hashed (no two different field lists encode to the same bytes).
#[derive(Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u64(v.len() as u64);
        self.0.extend_from_slice(v);
        self
    }
    pub fn hash(&mut self, v: &Hash) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn finish(&self, purpose: i32) -> Hash {
        sha256_with_purpose(purpose, &self.0)
    }
}

/// The digest of a proposal: the slot, the block it follows and the requests. It does **not** contain the view, so a proposal that is
/// proposed again in a later view keeps its digest.
pub fn proposal_digest(seq: u64, prev: &Hash, requests: &[Vec<u8>]) -> Hash {
    let mut e = Enc::default();
    e.u64(seq).hash(prev).u64(requests.len() as u64);
    for r in requests {
        e.bytes(r);
    }
    e.finish(PURPOSE_BLOCK)
}

/// The hash of the chain after the block `seq` with digest `digest` that follows the chain `prev`: committing a block fixes the whole
/// history before it.
pub fn entry_hash(prev: &Hash, seq: u64, digest: &Hash) -> Hash {
    let mut e = Enc::default();
    e.hash(prev).u64(seq).hash(digest);
    e.finish(PURPOSE_BLOCK)
}

/// The hash of one request (what the nodes remember as already ordered).
pub fn request_id(request: &[u8]) -> Hash {
    let mut e = Enc::default();
    e.bytes(request);
    e.finish(PURPOSE_BLOCK)
}

pub fn sign(key: &SigningKey, digest: &Hash) -> [u8; 64] {
    key.sign(digest).to_bytes()
}

pub fn verify(key: &VerifyingKey, digest: &Hash, signature: &[u8; 64]) -> bool {
    key.verify(digest, &Signature::from_bytes(signature))
        .is_ok()
}
