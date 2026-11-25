//! What a node checks in the messages other messages embed: signatures, consensus certificates, proofs of availability and canonical commit sets.
//!
//! [CANTON-NOTE: SEMANTICS] Sources: `IssConsensusSignatureVerifier` (every embedded message verifies with its sender's key in the topology),
//! `ConsensusCertificateValidator` (a certificate's votes), `PbftMessageValidatorImpl` (a proposal's proofs and canonical commit set). These are free
//! functions over a membership and a key lookup so that a node that has not started (a state transfer) checks a certificate exactly like a running one.
use crate::consensus::block_hash_of_evidence;
use crate::topology::strong_quorum_size;
use crate::wire::{unwrap_versioned, verify_message_signature, AuthenticatedMessageType};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use prost::Message;
use std::collections::BTreeSet;

/// The key of the node `from` that has the fingerprint `signed_by` (its protocol key in the topology).
pub type KeyLookup = Box<dyn Fn(&str, &str) -> Option<canton_algo::signing::PublicKey> + Send>;

/// How long a batch stays valid, in epochs (`OrderingRequestBatch.BatchValidityDurationEpochs`).
pub const BATCH_VALIDITY_EPOCHS: i64 = 500;

/// `SequencingParameters.DefaultMaxBatchesPerProposal`.
pub const MAX_PROOFS_PER_PROPOSAL: usize = 16;

pub(crate) fn decode_consensus(signed: &bft::SignedMessage) -> Option<bft::ConsensusMessage> {
    let inner = unwrap_versioned(&signed.message, 30).ok()?;
    bft::ConsensusMessage::decode(inner.as_slice()).ok()
}

/// The signature of a message another message embeds verifies with the key its sender has in the topology.
pub fn verify_embedded(keys: &KeyLookup, signed: &bft::SignedMessage) -> Result<(), String> {
    let Some(signature) = &signed.signature else {
        return Err("an embedded message without a signature".into());
    };
    let Some(key) = keys(&signed.from, &signature.signed_by) else {
        return Err(format!(
            "no key of {} for the embedded message",
            signed.from
        ));
    };
    verify_message_signature(
        AuthenticatedMessageType::BftSignedConsensusMessage,
        &signed.from,
        &signed.message,
        signature,
        &key,
    )
    .map_err(|e| {
        format!(
            "an embedded message of {} that does not verify: {e:?}",
            signed.from
        )
    })
}

/// Who may vote and how many votes a certificate needs.
pub struct Membership<'a> {
    pub nodes: &'a [String],
    pub strong_quorum: usize,
}

impl<'a> Membership<'a> {
    /// The nodes of a topology with its own strong quorum.
    pub fn of(nodes: &'a [String]) -> Self {
        Self {
            nodes,
            strong_quorum: strong_quorum_size(nodes.len()),
        }
    }
}

/// `ConsensusCertificateValidator.validateConsensusCertificate` with `IssConsensusSignatureVerifier.verifyConsensusCertificate`: the votes are of one
/// epoch, one view and the block of the proposal, from distinct nodes of the membership (a strong quorum of them), name the proposal's hash and each
/// verifies with its sender's key; the proposal and the commits of its canonical commit set verify too. With `new_view`, the votes of a prepare
/// certificate are of a view before it (`validateNewViewConsensusCertificate`).
pub fn verify_certificate(
    cert: &bft::ConsensusCertificate,
    membership: &Membership<'_>,
    keys: &KeyLookup,
    new_view: Option<i64>,
) -> Result<(), String> {
    let (pre_prepare, others, name, prepare) = match &cert.certificate {
        Some(bft::consensus_certificate::Certificate::CommitCertificate(c)) => {
            (&c.pre_prepare, &c.commits, "commit", false)
        }
        Some(bft::consensus_certificate::Certificate::PrepareCertificate(c)) => {
            (&c.pre_prepare, &c.prepares, "prepare", true)
        }
        None => return Err("an empty certificate".into()),
    };
    let Some(pp) = pre_prepare else {
        return Err("a certificate without its pre-prepare".into());
    };
    verify_embedded(keys, pp)?;
    let Some(proposal) = decode_consensus(pp) else {
        return Err("a certificate with an undecodable pre-prepare".into());
    };
    if let Some(bft::consensus_message::Message::PrePrepare(body)) = &proposal.message {
        for commit in body
            .bft_time_canonical_commit_set
            .iter()
            .flat_map(|s| &s.canonical_commits)
        {
            verify_embedded(keys, commit)?;
        }
    }
    let meta = proposal.block_metadata.unwrap_or_default();
    if others.is_empty() {
        return Err(format!(
            "a {name} certificate for block {} without {name}s",
            meta.block_number
        ));
    }
    let hash = block_hash_of_evidence(&pp.message).map_err(|e| format!("{e:?}"))?;
    let mut senders = BTreeSet::new();
    let mut views = BTreeSet::new();
    for m in others {
        verify_embedded(keys, m)?;
        let Some(vote) = decode_consensus(m) else {
            return Err(format!("an undecodable {name}"));
        };
        let vote_meta = vote.block_metadata.unwrap_or_default();
        if vote_meta.epoch_number != meta.epoch_number {
            return Err(format!(
                "{name}s of epoch {} for a proposal of epoch {}",
                vote_meta.epoch_number, meta.epoch_number
            ));
        }
        if vote_meta.block_number != meta.block_number {
            return Err(format!(
                "{name}s for the wrong block {}",
                vote_meta.block_number
            ));
        }
        // [CANTON-NOTE: INVARIANT] The signature binds the outer sender; a vote counts for the sender it names only when the two agree (in Canton a
        // signed message's sender is its message's), or one node could sign a quorum alone.
        if vote.from != m.from || !membership.nodes.contains(&vote.from) {
            return Err(format!(
                "a {name} of {} signed as {}, or not from a node",
                vote.from, m.from
            ));
        }
        if !senders.insert(vote.from.clone()) {
            return Err(format!("more than one {name} from {}", vote.from));
        }
        views.insert(vote.view_number);
        let voted_hash = match vote.message {
            Some(bft::consensus_message::Message::Prepare(p)) if prepare => p.block_hash,
            Some(bft::consensus_message::Message::Commit(c)) if !prepare => c.block_hash,
            _ => {
                return Err(format!(
                    "a {name} certificate with a vote that is not a {name}"
                ))
            }
        };
        if voted_hash != hash {
            return Err(format!(
                "a {name} from {} has a non-matching hash",
                vote.from
            ));
        }
    }
    if views.len() > 1 {
        return Err(format!("{name}s of several views ({views:?})"));
    }
    if let Some(current_view) = new_view {
        if prepare && views.iter().any(|v| *v >= current_view) {
            return Err(format!(
                "{name}s of view {views:?}, which is not before the view {current_view}"
            ));
        }
    }
    if senders.len() < membership.strong_quorum {
        return Err(format!(
            "expected at least {} {name}s, but only got {}",
            membership.strong_quorum,
            senders.len()
        ));
    }
    Ok(())
}

/// `PbftMessageValidatorImpl.validateProofsOfAvailability` (`PMV:87-174`): every proof has acks of at least a weak quorum of distinct nodes of the
/// topology, the batch is not older than [`BATCH_VALIDITY_EPOCHS`] epochs and not from a later one, and each ack's signature verifies with the key its
/// node has in the topology.
pub fn check_proofs(
    proofs: &[bft::ProofOfAvailability],
    nodes: &[String],
    keys: &KeyLookup,
    epoch: i64,
) -> Result<(), String> {
    let weak = crate::topology::weak_quorum_size(nodes.len());
    for proof in proofs {
        if proof.epoch_number > epoch || proof.epoch_number + BATCH_VALIDITY_EPOCHS < epoch {
            return Err(format!(
                "a batch of epoch {} is not valid in epoch {epoch}",
                proof.epoch_number
            ));
        }
        let batch = crate::availability::BatchId::from_proto(&proof.batch_id)
            .map_err(|e| format!("a batch id: {e}"))?;
        let mut seen = BTreeSet::new();
        for ack in &proof.acks {
            if !nodes.contains(&ack.from) {
                return Err(format!("an ack of {}, which is not a node", ack.from));
            }
            if !seen.insert(ack.from.clone()) {
                return Err(format!("two acks of {}", ack.from));
            }
            let signature = ack.signature.as_ref().ok_or("an ack without a signature")?;
            let key = keys(&ack.from, &signature.signed_by)
                .ok_or_else(|| format!("{} is not a key of {}", signature.signed_by, ack.from))?;
            crate::availability::verify_ack(&batch, proof.epoch_number, &ack.from, signature, &key)
                .map_err(|e| format!("an ack of {} does not verify: {e}", ack.from))?;
        }
        if seen.len() < weak {
            return Err(format!("{} acks of a batch, {weak} needed", seen.len()));
        }
    }
    Ok(())
}

/// Where a proposal sits, for the checks of `PbftMessageValidatorImpl.validatePrePrepare`.
pub struct ProposalPlace<'a> {
    pub epoch: i64,
    pub block: i64,
    pub epoch_start_block: i64,
    /// The block before this one in its segment; `None` for the first block of a segment.
    pub previous_in_segment: Option<i64>,
    /// The topology of the epoch, and of the one before when the node knows it (it ran that epoch).
    pub current: &'a [String],
    pub previous: Option<&'a [String]>,
}

/// `PbftMessageValidatorImpl.validatePrePrepare` without the proofs (checked on their own): at most [`MAX_PROOFS_PER_PROPOSAL`] batches, the first block
/// of a genesis segment empty, and `validateCanonicalCommitSet` with the commits' signatures (`IssConsensusSignatureVerifier.validatePrePrepare`).
pub fn check_pre_prepare(
    pp: &bft::PrePrepare,
    place: &ProposalPlace<'_>,
    keys: &KeyLookup,
) -> Result<(), String> {
    let proofs = pp.block.as_ref().map_or(0, |b| b.proofs.len());
    let first_in_segment = place.previous_in_segment.is_none();
    if proofs > MAX_PROOFS_PER_PROPOSAL {
        return Err(format!(
            "{proofs} proofs of availability, at most {MAX_PROOFS_PER_PROPOSAL}"
        ));
    }
    if place.epoch == 0 && first_in_segment && proofs > 0 {
        return Err("the first block of a genesis segment has to be empty".into());
    }
    let commits: &[bft::SignedMessage] = pp
        .bft_time_canonical_commit_set
        .as_ref()
        .map_or(&[], |s| s.canonical_commits.as_slice());
    if commits.is_empty() {
        // [CANTON-NOTE: SEMANTICS] "A canonical commit set for a non-empty block should only be empty for the first block after state transfer".
        return if proofs == 0 || first_in_segment {
            Ok(())
        } else {
            Err("an empty canonical commit set for a block with batches".into())
        };
    }
    let mut senders = BTreeSet::new();
    let mut at = BTreeSet::new();
    for signed in commits {
        verify_embedded(keys, signed)?;
        let Some(commit) = decode_consensus(signed) else {
            return Err("an undecodable commit in the canonical commit set".into());
        };
        if !matches!(
            commit.message,
            Some(bft::consensus_message::Message::Commit(_))
        ) || commit.from != signed.from
        {
            return Err(format!(
                "a canonical commit of {} that is not its own commit",
                signed.from
            ));
        }
        if !senders.insert(commit.from) {
            return Err(format!(
                "the canonical commit set has {} twice",
                signed.from
            ));
        }
        let meta = commit.block_metadata.unwrap_or_default();
        at.insert((meta.epoch_number, meta.block_number));
    }
    let mut at = at.into_iter();
    let (Some((epoch, block)), None) = (at.next(), at.next()) else {
        return Err("the canonical commit set names several blocks".into());
    };
    let expected = match place.previous_in_segment {
        Some(previous) => (place.epoch, previous),
        None => (place.epoch - 1, place.epoch_start_block - 1),
    };
    if (epoch, block) != expected {
        return Err(format!(
            "the canonical commit set is of block {block} of epoch {epoch}, not of block {} of epoch {}",
            expected.1, expected.0
        ));
    }
    // [CANTON-NOTE: LIMITATION] The commits of the epoch before are checked against that epoch's topology (`previousMembership`); a node that did
    // not run that epoch (it started in this one) does not know it and checks their signatures and shape only.
    let topology = if epoch == place.epoch {
        Some(place.current)
    } else {
        place.previous
    };
    if let Some(nodes) = topology {
        if let Some(stranger) = senders.iter().find(|s| !nodes.contains(s)) {
            return Err(format!(
                "a canonical commit of {stranger}, which is not in the topology"
            ));
        }
        let strong = strong_quorum_size(nodes.len());
        if senders.len() < strong {
            return Err(format!(
                "{} canonical commits, a strong quorum is {strong}",
                senders.len()
            ));
        }
    }
    Ok(())
}
