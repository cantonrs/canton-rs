//! A node that joins a running BFT cluster for the first time (no leader selection state of its own) transfers the epochs before the
//! one it joins. Those epochs belong to the topology the cluster had then, which the joining node is not part of.
//!
//! Found by `scripts/bft-oracle.sh join` on a clean work directory (2026-11-20): with two official sequencers an epoch has 20 blocks
//! (ten per node); the joining node counted itself in, waited for 30 blocks of epoch 0 and never started
//! ("state transfer: 20 of the 30 blocks of epoch 0").
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::BTreeSet;
use std::sync::Arc;

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

fn signed(by: &Peer, message: bft::ConsensusMessage) -> bft::SignedMessage {
    let evidence = canton_bft_orderer::wire::wrap_versioned(30, &message.encode_to_vec());
    let signature = canton_bft_orderer::wire::sign_message(
        canton_bft_orderer::wire::AuthenticatedMessageType::BftSignedConsensusMessage,
        &by.member,
        &evidence,
        &by.key,
        &by.fingerprint,
    )
    .unwrap();
    bft::SignedMessage {
        message: evidence,
        from: by.member.clone(),
        signature: Some(signature),
    }
}

#[test]
fn a_fresh_node_transfers_a_past_epoch_of_the_topology_it_had() {
    let (a, b, me) = (peer("sequencer1", 1), peer("sequencer2", 2), peer("rs1", 3));
    let registry = Arc::new(Registry::default());
    for p in [&a, &b] {
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
    // ten blocks per node (no configured epoch length), as the official nodes run
    let fresh = Consensus::new(
        me.member,
        [3; 32],
        me.fingerprint,
        None,
        Arc::clone(&registry),
    );
    fresh.set_nodes(vec![a.member.clone(), b.member.clone()]);

    // the first proposal of epoch 1 it sees: its canonical commit set names the last block of epoch 0 (block 19 of a two-node epoch)
    let last_commit_of_epoch_0 = signed(
        &b,
        bft::ConsensusMessage {
            block_metadata: Some(bft::BlockMetadata {
                epoch_number: 0,
                block_number: 19,
            }),
            view_number: 0,
            from: b.member.clone(),
            message: Some(bft::consensus_message::Message::Commit(
                bft::Commit::default(),
            )),
        },
    );
    fresh
        .on_message(signed(
            &b,
            bft::ConsensusMessage {
                block_metadata: Some(bft::BlockMetadata {
                    epoch_number: 1,
                    block_number: 20,
                }),
                view_number: 0,
                from: b.member.clone(),
                message: Some(bft::consensus_message::Message::PrePrepare(
                    bft::PrePrepare {
                        block: Some(bft::OrderingBlock { proofs: vec![] }),
                        bft_time_canonical_commit_set: Some(bft::CanonicalCommitSet {
                            canonical_commits: vec![last_commit_of_epoch_0],
                        }),
                    },
                )),
            },
        ))
        .unwrap();
    assert!(
        !fresh.is_started(),
        "epoch 0 has to be transferred before the node joins epoch 1"
    );

    let voters_of_epoch_0: BTreeSet<String> = [a.member, b.member].into();
    // the peers answer in parts: the first ten blocks are not the epoch yet
    fresh
        .on_transferred_blocks(
            0,
            (0..10).map(|block| (block, 0)).collect(),
            &voters_of_epoch_0,
        )
        .unwrap();
    assert!(!fresh.is_started(), "half of epoch 0");
    // the twenty blocks of the two-node epoch are all of it: the node joins epoch 1
    fresh
        .on_transferred_blocks(
            0,
            (10..20).map(|block| (block, 0)).collect(),
            &voters_of_epoch_0,
        )
        .unwrap();
    assert!(
        fresh.is_started(),
        "the 20 blocks of a two-node epoch are the whole epoch, although the joining node makes three"
    );
    let (epoch, nodes, _, _) = fresh.ordering_topology();
    assert_eq!(epoch, 1);
    assert_eq!(
        nodes.len(),
        3,
        "the epoch it joins has the current nodes: {nodes:?}"
    );
}
