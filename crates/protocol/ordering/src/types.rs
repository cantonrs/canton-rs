//! The ordering messages and the checks that make a certificate worth anything.
use crate::crypto::{self, entry_hash, proposal_digest, Enc, Hash, PURPOSE_CONSENSUS_MESSAGE};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::BTreeSet;

pub type NodeId = usize;
pub type View = u64;
pub type Seq = u64;

/// The cluster: `n = 3f + 1` nodes with their public keys. A node is its index.
#[derive(Clone)]
pub struct Config {
    pub n: usize,
    pub f: usize,
    pub keys: Vec<VerifyingKey>,
}

impl Config {
    pub fn new(keys: Vec<VerifyingKey>) -> Self {
        let n = keys.len();
        assert!(
            n >= 4 && (n - 1).is_multiple_of(3),
            "n = 3f + 1 with f >= 1"
        );
        Self {
            n,
            f: (n - 1) / 3,
            keys,
        }
    }

    /// The leader of `view` (rotating).
    pub fn leader(&self, view: View) -> NodeId {
        (view % self.n as u64) as usize
    }

    /// Votes that settle a decision: `2f + 1`, so that any two sets of them share an honest node.
    pub fn quorum(&self) -> usize {
        2 * self.f + 1
    }
}

/// What a message is: its kind tag and the fields that are signed.
pub trait Body {
    const KIND: u8;
    fn encode(&self, e: &mut Enc);
}

/// A message with the node that sent it and its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T> {
    pub body: T,
    pub from: NodeId,
    pub sig: [u8; 64],
}

impl<T: Body> Signed<T> {
    pub fn sign(body: T, from: NodeId, key: &SigningKey) -> Self {
        let sig = crypto::sign(key, &Self::digest_of(&body));
        Self { body, from, sig }
    }

    pub fn digest_of(body: &T) -> Hash {
        let mut e = Enc::default();
        e.u8(T::KIND);
        body.encode(&mut e);
        e.finish(PURPOSE_CONSENSUS_MESSAGE)
    }

    pub fn digest(&self) -> Hash {
        Self::digest_of(&self.body)
    }

    /// Signed by the node it says it is from, and that node is in the cluster.
    pub fn verifies(&self, cfg: &Config) -> bool {
        cfg.keys
            .get(self.from)
            .is_some_and(|k| crypto::verify(k, &self.digest(), &self.sig))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrePrepare {
    pub view: View,
    pub seq: Seq,
    /// The chain hash of the block before (`[0; 32]` before the first block): what ties the block to its history.
    pub prev: Hash,
    pub requests: Vec<Vec<u8>>,
}

impl PrePrepare {
    pub fn digest(&self) -> Hash {
        proposal_digest(self.seq, &self.prev, &self.requests)
    }
}

impl Body for PrePrepare {
    const KIND: u8 = 1;
    fn encode(&self, e: &mut Enc) {
        e.u64(self.view).hash(&self.digest());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepare {
    pub view: View,
    pub seq: Seq,
    pub digest: Hash,
}

impl Body for Prepare {
    const KIND: u8 = 2;
    fn encode(&self, e: &mut Enc) {
        e.u64(self.view).u64(self.seq).hash(&self.digest);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub view: View,
    pub seq: Seq,
    pub digest: Hash,
}

impl Body for Commit {
    const KIND: u8 = 3;
    fn encode(&self, e: &mut Enc) {
        e.u64(self.view).u64(self.seq).hash(&self.digest);
    }
}

/// A proposal and `2f` backups' `Prepare`s for it: proof that it was prepared (no other proposal for the slot can have been committed in
/// that view).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCert {
    pub pre_prepare: Signed<PrePrepare>,
    pub prepares: Vec<Signed<Prepare>>,
}

/// A proposal and `2f + 1` `Commit`s for it: proof that it is committed. A committed block is what state transfer hands out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBlock {
    pub pre_prepare: Signed<PrePrepare>,
    pub commits: Vec<Signed<Commit>>,
}

impl CommittedBlock {
    pub fn seq(&self) -> Seq {
        self.pre_prepare.body.seq
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewChange {
    pub new_view: View,
    /// The sender's last committed block, with the chain hash after it.
    pub head_seq: Seq,
    pub head_hash: Hash,
    /// The proof that block is committed (none before the first block).
    pub head_proof: Option<Box<CommittedBlock>>,
    /// The sender's prepared proposal for the next slot, if it has one.
    pub prepared: Option<PreparedCert>,
}

impl Body for ViewChange {
    const KIND: u8 = 4;
    fn encode(&self, e: &mut Enc) {
        e.u64(self.new_view)
            .u64(self.head_seq)
            .hash(&self.head_hash);
        match &self.prepared {
            None => {
                e.u8(0);
            }
            Some(c) => {
                e.u8(1)
                    .u64(c.pre_prepare.body.view)
                    .hash(&c.pre_prepare.body.digest());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewView {
    pub view: View,
    pub view_changes: Vec<Signed<ViewChange>>,
    /// The proposal the new leader makes again because some node had prepared it (none when no node had).
    pub reproposal: Option<Signed<PrePrepare>>,
}

impl Body for NewView {
    const KIND: u8 = 5;
    fn encode(&self, e: &mut Enc) {
        e.u64(self.view).u64(self.view_changes.len() as u64);
        for vc in &self.view_changes {
            e.u64(vc.from as u64).hash(&vc.digest());
        }
        match &self.reproposal {
            None => {
                e.u8(0);
            }
            Some(pp) => {
                e.u8(1).hash(&pp.digest());
            }
        }
    }
}

/// What nodes send each other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// A client's request, to be ordered.
    Request(Vec<u8>),
    PrePrepare(Signed<PrePrepare>),
    Prepare(Signed<Prepare>),
    Commit(Signed<Commit>),
    ViewChange(Signed<ViewChange>),
    NewView(Signed<NewView>),
    /// "I am at this head": a hint to a node that is behind (what it then asks for is verified, not believed).
    Status {
        head_seq: Seq,
    },
    /// "Send me the blocks from `from_seq` on."
    StateRequest {
        from_seq: Seq,
    },
    StateResponse(Vec<CommittedBlock>),
}

/// Why a message or certificate was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    NotInCluster,
    BadSignature,
    WrongLeader,
    WrongView,
    WrongSlot,
    ChainMismatch,
    NotEnoughVotes(usize),
    DuplicateVoter,
    VoteForOtherBlock,
    Malformed(&'static str),
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A committed block is worth believing when the leader of its view signed the proposal, `2f + 1` distinct nodes signed a `Commit` for
/// exactly that proposal in that view, and the block follows the chain `prev`. Returns the chain hash after it.
pub fn verify_committed_block(
    cfg: &Config,
    block: &CommittedBlock,
    prev: &Hash,
) -> Result<Hash, Reject> {
    let pp = &block.pre_prepare;
    if !pp.verifies(cfg) {
        return Err(if pp.from >= cfg.n {
            Reject::NotInCluster
        } else {
            Reject::BadSignature
        });
    }
    if pp.from != cfg.leader(pp.body.view) {
        return Err(Reject::WrongLeader);
    }
    if pp.body.prev != *prev {
        return Err(Reject::ChainMismatch);
    }
    let digest = pp.body.digest();
    let mut voters = BTreeSet::new();
    for c in &block.commits {
        if c.body.view != pp.body.view || c.body.seq != pp.body.seq || c.body.digest != digest {
            return Err(Reject::VoteForOtherBlock);
        }
        if !c.verifies(cfg) {
            return Err(if c.from >= cfg.n {
                Reject::NotInCluster
            } else {
                Reject::BadSignature
            });
        }
        if !voters.insert(c.from) {
            return Err(Reject::DuplicateVoter);
        }
    }
    if voters.len() < cfg.quorum() {
        return Err(Reject::NotEnoughVotes(voters.len()));
    }
    Ok(entry_hash(prev, pp.body.seq, &digest))
}

/// A prepared certificate is worth believing when the leader of its view signed the proposal and `2f` distinct **backups** signed a
/// `Prepare` for exactly that proposal in that view.
pub fn verify_prepared_cert(cfg: &Config, cert: &PreparedCert) -> Result<(), Reject> {
    let pp = &cert.pre_prepare;
    if !pp.verifies(cfg) {
        return Err(if pp.from >= cfg.n {
            Reject::NotInCluster
        } else {
            Reject::BadSignature
        });
    }
    if pp.from != cfg.leader(pp.body.view) {
        return Err(Reject::WrongLeader);
    }
    let digest = pp.body.digest();
    let mut voters = BTreeSet::new();
    for p in &cert.prepares {
        if p.body.view != pp.body.view || p.body.seq != pp.body.seq || p.body.digest != digest {
            return Err(Reject::VoteForOtherBlock);
        }
        if !p.verifies(cfg) {
            return Err(if p.from >= cfg.n {
                Reject::NotInCluster
            } else {
                Reject::BadSignature
            });
        }
        // the leader's proposal is its vote: a Prepare from it is not a second one
        if p.from == pp.from || !voters.insert(p.from) {
            return Err(Reject::DuplicateVoter);
        }
    }
    if voters.len() < 2 * cfg.f {
        return Err(Reject::NotEnoughVotes(voters.len()));
    }
    Ok(())
}

/// A view change message is worth believing when it is signed, its head proof really commits `head_seq` on top of a chain that ends in
/// `head_hash`, and its prepared proposal (if any) is for the slot after the head and extends that chain.
pub fn verify_view_change(cfg: &Config, vc: &Signed<ViewChange>) -> Result<(), Reject> {
    if !vc.verifies(cfg) {
        return Err(if vc.from >= cfg.n {
            Reject::NotInCluster
        } else {
            Reject::BadSignature
        });
    }
    let b = &vc.body;
    match &b.head_proof {
        None => {
            if b.head_seq != 0 || b.head_hash != [0; 32] {
                return Err(Reject::Malformed("a head without a proof"));
            }
        }
        Some(block) => {
            if block.seq() != b.head_seq {
                return Err(Reject::WrongSlot);
            }
            // the chain before the head is not shown, so the head is checked against the hash the block itself names
            let prev = block.pre_prepare.body.prev;
            let hash = verify_committed_block(cfg, block, &prev)?;
            if hash != b.head_hash {
                return Err(Reject::ChainMismatch);
            }
        }
    }
    if let Some(cert) = &b.prepared {
        verify_prepared_cert(cfg, cert)?;
        let pp = &cert.pre_prepare.body;
        if pp.seq != b.head_seq + 1 {
            return Err(Reject::WrongSlot);
        }
        if pp.prev != b.head_hash {
            return Err(Reject::ChainMismatch);
        }
        if pp.view >= b.new_view {
            return Err(Reject::WrongView);
        }
    }
    Ok(())
}
