//! The commit certificates a node receives by state transfer are checked like the ones it receives live (S-20, S-10): every commit is signed by
//! the node it names, the commits are of the proposal's block and hash, and they come from a strong quorum of distinct nodes.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::sync::Arc;

use canton_bft_orderer::consensus::{block_hash_of_evidence, commit_message, pre_prepare_message};
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v30 as bft;
use canton_sequencer_server::bft_p2p::Consensus;
use canton_sequencer_server::onboarding::{Registered, Registry};
use prost::Message as _;

struct Peer {
    member: String,
    key: ed25519_dalek::SigningKey,
    fingerprint: String,
}

fn peer(name: &str, seed: u8) -> Peer {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let fingerprint =
        canton_participant::topology_wire::fingerprint(&key.verifying_key().to_bytes());
    Peer {
        member: format!("SEQ::{name}::{fingerprint}"),
        key,
        fingerprint,
    }
}

/// `message` signed with `by`'s key, sent as `as_member` with `as_fingerprint`.
fn signed_as(
    by: &Peer,
    as_member: &str,
    as_fingerprint: &str,
    message: &bft::ConsensusMessage,
) -> bft::SignedMessage {
    let evidence = canton_bft_orderer::wire::wrap_versioned(30, &message.encode_to_vec());
    let signature = canton_bft_orderer::wire::sign_message(
        canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedConsensusMessage,
        as_member,
        &evidence,
        &by.key,
        as_fingerprint,
    )
    .unwrap();
    bft::SignedMessage {
        message: evidence,
        from: as_member.to_string(),
        signature: Some(signature),
    }
}

fn signed(by: &Peer, message: &bft::ConsensusMessage) -> bft::SignedMessage {
    signed_as(by, &by.member, &by.fingerprint, message)
}

/// A fresh node `me` next to `a` and `b`, in a state transfer of epoch 0 (twenty blocks, ten per node).
fn fresh_node_in_state_transfer(a: &Peer, b: &Peer, me: &Peer) -> Consensus {
    node_in_state_transfer(a, b, me, |_| {})
}

/// The same, with `prepare` run on the node before the peers' first proposal reaches it (a state file to resume from, a sink).
fn node_in_state_transfer(
    a: &Peer,
    b: &Peer,
    me: &Peer,
    prepare: impl FnOnce(&Consensus),
) -> Consensus {
    let registry = Arc::new(Registry::default());
    for p in [a, b] {
        let raw = canton_algo::member_signature::own_ed25519_key(
            &canton_participant::topology_wire::Ed25519Key::from_signing_key(p.key.clone())
                .spki_der,
        )
        .unwrap();
        registry.insert(Registered {
            member: p.member.clone(),
            signing_keys: vec![raw.clone()],
            authentication_keys: vec![raw],
            encryption_keys: Vec::new(),
        });
    }
    let fresh = Consensus::new(
        me.member.clone(),
        [3; 32],
        me.fingerprint.clone(),
        None,
        registry,
    );
    fresh.set_nodes(vec![a.member.clone(), b.member.clone()]);
    prepare(&fresh);
    let last_commit_of_epoch_0 = signed(b, &commit_message(0, 19, 0, &b.member, vec![0; 34], 1));
    fresh
        .on_message(signed(
            b,
            &pre_prepare_message(
                1,
                20,
                0,
                &b.member,
                bft::OrderingBlock { proofs: vec![] },
                bft::CanonicalCommitSet {
                    canonical_commits: vec![last_commit_of_epoch_0],
                },
            ),
        ))
        .unwrap();
    assert!(!fresh.is_started(), "epoch 0 is transferred first");
    fresh
}

/// The certificates of the twenty blocks of epoch 0, proposed by `b`, with the commits `commits` makes of a block and its hash.
fn epoch_0(
    b: &Peer,
    commits: impl Fn(i64, &[u8]) -> Vec<bft::SignedMessage>,
) -> Vec<bft::CommitCertificate> {
    (0..20)
        .map(|block| {
            let pre_prepare = signed(
                b,
                &pre_prepare_message(
                    0,
                    block,
                    0,
                    &b.member,
                    bft::OrderingBlock { proofs: vec![] },
                    bft::CanonicalCommitSet {
                        canonical_commits: vec![],
                    },
                ),
            );
            let hash = block_hash_of_evidence(&pre_prepare.message).unwrap();
            bft::CommitCertificate {
                pre_prepare: Some(pre_prepare),
                commits: commits(block, &hash),
            }
        })
        .collect()
}

#[test]
fn a_transferred_certificate_counts_only_with_a_quorum_of_genuine_commits() {
    let (a, b, me) = (peer("sequencer1", 1), peer("sequencer2", 2), peer("rs1", 3));
    let commit = |by: &Peer, block: i64, hash: &[u8]| {
        signed(
            by,
            &commit_message(0, block, 0, &by.member, hash.to_vec(), 1),
        )
    };
    let fresh = fresh_node_in_state_transfer(&a, &b, &me);

    // b's commit twice, and one under a's name that b signed: one node's vote only
    let one_voter = epoch_0(&b, |block, hash| {
        vec![
            commit(&b, block, hash),
            commit(&b, block, hash),
            signed_as(
                &b,
                &a.member,
                &a.fingerprint,
                &commit_message(0, block, 0, &a.member, hash.to_vec(), 1),
            ),
        ]
    });
    fresh.on_block_transfer_response("test", one_voter).unwrap();
    assert!(
        !fresh.is_started(),
        "commits of one node, repeated or under another's name, are not a quorum"
    );

    // genuine commits of both nodes, for a hash that is not the proposal's
    let other_hash = epoch_0(&b, |block, _| {
        vec![commit(&a, block, &[7; 34]), commit(&b, block, &[7; 34])]
    });
    fresh
        .on_block_transfer_response("test", other_hash)
        .unwrap();
    assert!(
        !fresh.is_started(),
        "commits of another hash do not certify the proposal"
    );

    let genuine = epoch_0(&b, |block, hash| {
        vec![commit(&a, block, hash), commit(&b, block, hash)]
    });
    fresh.on_block_transfer_response("test", genuine).unwrap();
    assert!(
        fresh.is_started(),
        "genuine certificates of the whole epoch let the node join epoch 1"
    );
}

fn genuine_epoch_0(a: &Peer, b: &Peer) -> Vec<bft::CommitCertificate> {
    let commit = |by: &Peer, block: i64, hash: &[u8]| {
        signed(
            by,
            &commit_message(0, block, 0, &by.member, hash.to_vec(), 1),
        )
    };
    epoch_0(b, |block, hash| {
        vec![commit(a, block, hash), commit(b, block, hash)]
    })
}

/// The heights and BFT times the node hands its sequencer (`BlockEndSink`, once per block).
fn recording_blocks(c: &Consensus) -> Arc<std::sync::Mutex<Vec<(i64, i64)>>> {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    c.set_block_end_sink(Arc::new(move |block, time, _| {
        sink.lock().unwrap().push((block, time));
        false
    }));
    seen
}

#[test]
fn a_restarted_node_outputs_the_transferred_blocks_after_the_last_one_it_output() {
    // `OutputModule`: a node that restarts provides blocks from the one after the last its sequencer got, the ones state transfer brings
    // (`OrderingMode.StateTransfer`) among them; the blocks before were provided already
    let (a, b, me) = (peer("sequencer1", 1), peer("sequencer2", 2), peer("rs1", 3));
    let dir = std::env::temp_dir().join(format!("bftsim-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("rs1.state");
    std::fs::write(state.with_extension("output"), "7 7000\n").unwrap();
    let policy = canton_bft_orderer::blacklist::PolicyState::first(
        &[a.member.clone(), b.member.clone()],
        20,
    );
    std::fs::write(state.with_extension("policy"), policy.to_text()).unwrap();
    let mut seen = None;
    let node = node_in_state_transfer(&a, &b, &me, |c| {
        c.persist_to(&state).unwrap();
        seen = Some(recording_blocks(c));
    });
    let seen = seen.unwrap();
    node.on_block_transfer_response("test", genuine_epoch_0(&a, &b))
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(node.is_started(), "the node joins epoch 1");
    let blocks: Vec<(i64, i64)> = seen.lock().unwrap().clone();
    assert_eq!(
        blocks.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
        (8..20).collect::<Vec<_>>(),
        "blocks 8 to 19 of the transferred epoch, not the eight it had output"
    );
    // empty canonical commit sets: each block is a millisecond after the one before, from the time of block 7
    assert_eq!(blocks[0].1, 8_000);
    assert!(blocks.windows(2).all(|w| w[1].1 == w[0].1 + 1_000));
}

#[test]
fn a_fresh_node_outputs_nothing_of_the_epochs_before_the_one_it_joins() {
    // no state to resume from and no onboarding snapshot: the first height it provides is the first block of the epoch it joins
    let (a, b, me) = (peer("sequencer1", 1), peer("sequencer2", 2), peer("rs1", 3));
    let mut seen = None;
    let node = node_in_state_transfer(&a, &b, &me, |c| seen = Some(recording_blocks(c)));
    node.on_block_transfer_response("test", genuine_epoch_0(&a, &b))
        .unwrap();
    assert!(node.is_started());
    assert!(
        seen.unwrap().lock().unwrap().is_empty(),
        "nothing before epoch 1 reaches the sequencer"
    );
}
