use super::*;
use crate::consensus::{
    block_hash_of_evidence, commit_message, pre_prepare_message, prepare_message,
};
use crate::wire::verify_message_signature;

/// The keys of `names` as the cluster signs: node i has the seed `[i + 1; 32]` and the fingerprint `fp-<name>`.
fn keys_of(names: &[String]) -> KeyLookup {
    let names = names.to_vec();
    Box::new(move |from, fp| {
        let i = names.iter().position(|n| n == from)?;
        (fp == format!("fp-{from}")).then(|| {
            crate::wire::test_key(
                &ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32]).verifying_key(),
                Some(fp),
            )
        })
    })
}

struct Cluster {
    /// Nodes that are away: they neither tick nor receive.
    dead: Vec<bool>,
    nodes: Vec<ConsensusNode>,
    keys: Vec<ed25519_dalek::VerifyingKey>,
    names: Vec<String>,
    /// Messages in flight: (sender index, message).
    bus: Vec<(usize, bft::SignedMessage)>,
    now_ms: u64,
    delivered: usize,
}

impl Cluster {
    fn new(names: &[&str], info: EpochInfo) -> Self {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let mut nodes = Vec::new();
        let mut keys = Vec::new();
        for (i, n) in names.iter().enumerate() {
            let key = ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32]);
            keys.push(key.verifying_key());
            nodes.push(ConsensusNode::new(
                n,
                &names,
                info,
                Signer {
                    key,
                    fingerprint: format!("fp-{n}"),
                },
                keys_of(&names),
                0,
            ));
        }
        let dead = vec![false; nodes.len()];
        Self {
            nodes,
            keys,
            names,
            bus: Vec::new(),
            now_ms: 0,
            delivered: 0,
            dead,
        }
    }

    /// Moves the clock by `ms` and delivers everything until the bus is empty. Every signature is checked the way a peer checks it.
    fn run(&mut self, ms: u64) {
        for _ in 0..ms / 50 {
            self.now_ms += 50;
            let micros = self.now_ms as i64 * 1000;
            for i in 0..self.nodes.len() {
                if self.dead[i] {
                    continue;
                }
                for m in self.nodes[i].tick(self.now_ms, micros) {
                    self.bus.push((i, m));
                }
            }
            while !self.bus.is_empty() {
                let (from, m) = self.bus.remove(0);
                let sender = self.names.iter().position(|n| *n == m.from).unwrap();
                assert_eq!(sender, from);
                verify_message_signature(
                    AuthenticatedMessageType::BftSignedConsensusMessage,
                    &m.from,
                    &m.message,
                    m.signature.as_ref().unwrap(),
                    &crate::wire::test_key(&self.keys[sender], Some(&format!("fp-{}", m.from))),
                )
                .expect("what a node sends verifies for its peers");
                for to in 0..self.nodes.len() {
                    if to != from && !self.dead[to] {
                        self.delivered += 1;
                        for out in self.nodes[to].on_message(m.clone(), self.now_ms, micros) {
                            self.bus.push((to, out));
                        }
                    }
                }
            }
        }
    }
}

fn info() -> EpochInfo {
    EpochInfo {
        number: 3,
        start_block_number: 60,
        length: 12,
    }
}

#[test]
fn the_others_change_the_view_of_a_segment_whose_leader_is_away_and_go_on() {
    // four nodes (strong quorum 3), epoch of 12 blocks, one segment per node; "SEQ::d" never answers
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    for node in &mut c.nodes {
        node.set_view_change_timeout(2_000, 0);
    }
    c.dead[3] = true;
    let d_segment = c.nodes[0].epoch.segment_of("SEQ::d").unwrap().slots.clone();
    c.run(4_000);
    let mut started = Vec::new();
    let mut completed = 0;
    let mut ordered = Vec::new();
    for i in 0..3 {
        for e in c.nodes[i].take_events() {
            match e {
                Event::ViewChangeStarted {
                    first_block,
                    view,
                    leader,
                    ..
                } => started.push((i, first_block, view, leader)),
                Event::ViewChangeCompleted { .. } => completed += 1,
                Event::BlockOrdered {
                    epoch: 3, block, ..
                } => ordered.push((i, block)),
                _ => {}
            }
        }
    }
    // the three alive nodes moved the segment of d to view 1, led by the next leader of the list
    for i in 0..3 {
        assert!(
            started
                .iter()
                .any(|(n, first, view, _)| *n == i && *first == d_segment[0] && *view == 1),
            "node {i} started the view change of d's segment: {started:?}"
        );
    }
    assert!(completed >= 3, "every alive node finished it");
    // and every alive node ordered all twelve blocks of the epoch, d's among them (empty blocks of the new view)
    for i in 0..3 {
        let mut mine: Vec<i64> = ordered
            .iter()
            .filter(|(n, _)| *n == i)
            .map(|(_, b)| *b)
            .collect();
        mine.sort();
        assert_eq!(
            mine,
            (60..72).collect::<Vec<i64>>(),
            "node {i} ordered the whole epoch"
        );
    }
}

#[test]
fn a_leader_with_an_available_batch_proposes_it_without_waiting_for_the_empty_block_timer() {
    let names: Vec<String> = ["SEQ::a", "SEQ::b", "SEQ::c"]
        .iter()
        .map(|n| n.to_string())
        .collect();
    let key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let mut node = ConsensusNode::new(
        "SEQ::b",
        &names,
        info(),
        Signer {
            key,
            fingerprint: "fp-b".into(),
        },
        keys_of(&names),
        0,
    );
    // nothing to order and the empty block is not due yet: no proposal
    assert!(node.tick(10, 10_000).is_empty());
    node.queue_proof(bft::ProofOfAvailability {
        batch_id: vec![1; 34],
        acks: vec![bft::AvailabilityAck {
            from: "SEQ::b".into(),
            signature: None,
        }],
        epoch_number: 3,
    });
    let sent = node.tick(20, 20_000);
    let proposal = sent
        .iter()
        .filter_map(ConsensusNode::decode_consensus)
        .find_map(|c| match c.message {
            Some(bft::consensus_message::Message::PrePrepare(p)) => Some(p),
            _ => None,
        })
        .expect("the leader proposes");
    assert_eq!(
        proposal.block.unwrap().proofs.len(),
        1,
        "the proposal names the batch"
    );
}

#[test]
fn a_certificate_has_to_hold_what_the_official_validator_demands() {
    let c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let leader = &c.nodes[0];
    let block = 60;
    let pre_prepare = leader.sign(&pre_prepare_message(
        3,
        block,
        0,
        "SEQ::a",
        bft::OrderingBlock { proofs: vec![] },
        bft::CanonicalCommitSet {
            canonical_commits: vec![],
        },
    ));
    let hash = block_hash_of_evidence(&pre_prepare.message).unwrap();
    let prepare_by = |i: usize, hash: Vec<u8>, view: i64, block: i64| {
        c.nodes[i].sign(&prepare_message(3, block, view, &c.names[i], hash))
    };
    let cert = |prepares: Vec<bft::SignedMessage>| bft::ConsensusCertificate {
        certificate: Some(bft::consensus_certificate::Certificate::PrepareCertificate(
            bft::PrepareCertificate {
                pre_prepare: Some(pre_prepare.clone()),
                prepares,
            },
        )),
    };
    // a strong quorum (3 of 4) of prepares of view 0 for the proposal: it holds in view 1
    let good = cert(vec![
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(1, hash.clone(), 0, block),
        prepare_by(2, hash.clone(), 0, block),
    ]);
    assert_eq!(leader.verify_certificate(&good, 1), Ok(()));
    // a quorum that is too small, a wrong hash, a repeated sender, another block, a view that is not before the new one
    let few = cert(vec![
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(1, hash.clone(), 0, block),
    ]);
    assert!(leader
        .verify_certificate(&few, 1)
        .unwrap_err()
        .contains("at least 3"));
    let wrong_hash = cert(vec![
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(1, hash.clone(), 0, block),
        prepare_by(2, vec![1, 2, 3], 0, block),
    ]);
    assert!(leader
        .verify_certificate(&wrong_hash, 1)
        .unwrap_err()
        .contains("non-matching hash"));
    let twice = cert(vec![
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(1, hash.clone(), 0, block),
    ]);
    assert!(leader
        .verify_certificate(&twice, 1)
        .unwrap_err()
        .contains("more than one"));
    let other_block = cert(vec![
        prepare_by(0, hash.clone(), 0, block),
        prepare_by(1, hash.clone(), 0, block),
        prepare_by(2, hash, 0, block + 1),
    ]);
    assert!(leader
        .verify_certificate(&other_block, 1)
        .unwrap_err()
        .contains("wrong block"));
    assert!(leader
        .verify_certificate(&good, 0)
        .unwrap_err()
        .contains("not before"));
    assert!(leader
        .verify_certificate(&cert(vec![]), 1)
        .unwrap_err()
        .contains("without"));
}

#[test]
fn a_leader_that_needed_a_view_change_sits_out_the_next_epoch() {
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    for node in &mut c.nodes {
        node.set_view_change_timeout(2_000, 0);
    }
    c.dead[3] = true;
    c.run(8_000);
    let mut changes: Vec<(i64, i64)> = Vec::new();
    let mut epoch4_blocks = std::collections::BTreeSet::new();
    for e in c.nodes[0].take_events() {
        match e {
            Event::ViewChangeStarted {
                epoch, first_block, ..
            } => changes.push((epoch, first_block)),
            Event::BlockOrdered {
                epoch: 4, block, ..
            } => {
                epoch4_blocks.insert(block);
            }
            _ => {}
        }
    }
    // epoch 3: d led a segment and the others moved it to a new view; epoch 4: d is blacklisted, it leads nothing, and no view change is needed
    assert!(
        changes.iter().any(|(e, _)| *e == 3),
        "d's segment changed its view in epoch 3: {changes:?}"
    );
    assert!(
        !changes.iter().any(|(e, _)| *e == 4),
        "no view change in epoch 4: {changes:?}"
    );
    assert_eq!(
        epoch4_blocks,
        (72..84).collect(),
        "the others ordered all of epoch 4"
    );
    assert!(c.nodes[0].epoch.info.number >= 5);
    // the epoch after (5) is the one d is back on trial in: the node computed the same leader lists as the official nodes would
    assert!(c.nodes[0].policy.blacklist.contains_key("SEQ::d"));
}

#[test]
fn a_restarted_leader_does_not_propose_a_slot_that_already_has_a_proposal() {
    // a node restarted in the middle of an epoch learns its earlier proposals again from the peers' retransmission: it must not make a second proposal for them
    let names: Vec<String> = ["SEQ::a", "SEQ::b", "SEQ::c"]
        .iter()
        .map(|n| n.to_string())
        .collect();
    let key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let mut node = ConsensusNode::new(
        "SEQ::b",
        &names,
        info(),
        Signer {
            key,
            fingerprint: "fp-b".into(),
        },
        keys_of(&names),
        0,
    );
    let slots = node.epoch.segment_of("SEQ::b").unwrap().slots.clone();
    // its own proposal for its first slot, as the others would send it back
    let earlier = node.sign(&pre_prepare_message(
        3,
        slots[0],
        0,
        "SEQ::b",
        bft::OrderingBlock { proofs: vec![] },
        bft::CanonicalCommitSet {
            canonical_commits: vec![],
        },
    ));
    node.on_message(earlier, 10, 10_000);
    assert!(node
        .blocks
        .get(&slots[0])
        .is_some_and(|b| b.pre_prepare.is_some()));
    // its clock runs far past the time it would propose
    let sent = node.tick(5_000, 5_000_000);
    let again = sent.iter().any(|m| {
        unwrap_versioned(&m.message, 30)
            .ok()
            .and_then(|i| bft::ConsensusMessage::decode(i.as_slice()).ok())
            .is_some_and(|c| {
                matches!(
                    c.message,
                    Some(bft::consensus_message::Message::PrePrepare(_))
                ) && c.block_metadata.is_some_and(|m| m.block_number == slots[0])
            })
    });
    assert!(!again, "no second proposal for a slot that has one");
    // the next slot waits for the first one to be ordered
    assert!(sent.is_empty());
}

#[test]
fn three_nodes_order_the_blocks_of_an_epoch_and_go_on_to_the_next() {
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c"], info());
    // 12 blocks, each leader proposes four, 500 ms apart: a few seconds
    c.run(6_000);
    for node in &mut c.nodes {
        let ordered: Vec<i64> = node
            .take_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::BlockOrdered {
                    epoch: 3,
                    block,
                    empty: true,
                } => Some(block),
                _ => None,
            })
            .collect();
        let mut sorted = ordered.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            (60..72).collect::<Vec<i64>>(),
            "every node ordered all the blocks of epoch 3"
        );
        // and went on: epoch 4 started at block 72
        assert!(node.epoch().info.number >= 4);
    }
}

#[test]
fn a_node_that_does_not_answer_stops_the_cluster_of_three() {
    // the strong quorum of three nodes is three: without the vote of one of them nothing is ordered
    let names = ["SEQ::a", "SEQ::b", "SEQ::c"];
    let mut c = Cluster::new(&names, info());
    let silent = 2;
    for _ in 0..40 {
        c.now_ms += 50;
        let micros = c.now_ms as i64 * 1000;
        for i in 0..2 {
            for m in c.nodes[i].tick(c.now_ms, micros) {
                c.bus.push((i, m));
            }
        }
        while !c.bus.is_empty() {
            let (from, m) = c.bus.remove(0);
            for to in 0..2 {
                if to != from && to != silent {
                    for out in c.nodes[to].on_message(m.clone(), c.now_ms, micros) {
                        c.bus.push((to, out));
                    }
                }
            }
        }
    }
    assert!(c.nodes[0]
        .take_events()
        .iter()
        .all(|e| !matches!(e, Event::BlockOrdered { .. })));
}

#[test]
fn a_pre_prepare_of_a_node_that_does_not_lead_the_block_is_dropped() {
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c"], info());
    c.nodes[0].take_events();
    // epoch 3 rotates by 0: a leads 60, b leads 61; b sends a pre-prepare for 60
    let forged = {
        let m = pre_prepare_message(
            3,
            60,
            0,
            "SEQ::b",
            bft::OrderingBlock { proofs: vec![] },
            bft::CanonicalCommitSet {
                canonical_commits: vec![],
            },
        );
        let evidence = consensus_evidence(&m);
        bft::SignedMessage {
            message: evidence,
            from: "SEQ::b".into(),
            signature: None,
        }
    };
    let out = c.nodes[0].on_message(forged, 0, 0);
    assert!(out.is_empty());
    assert!(c.nodes[0]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::Dropped(_))));
}

fn acked_proposal(
    c: &Cluster,
    ackers: &[usize],
    epoch: i64,
    key_of: impl Fn(usize) -> ed25519_dalek::SigningKey,
) -> bft::PrePrepare {
    use ed25519_dalek::Signer;
    let batch = crate::availability::batch_id(
        &[crate::availability::Request {
            tag: "send".into(),
            payload: b"x".to_vec(),
        }],
        epoch,
        37,
    )
    .unwrap();
    let acks = ackers
        .iter()
        .map(|&i| {
            let digest = crate::availability::ack_hash(&batch, epoch, &c.names[i]).unwrap();
            bft::AvailabilityAck {
                from: c.names[i].clone(),
                signature: Some(
                    canton_proto::com::digitalasset::canton::crypto::v30::Signature {
                        format: 1,
                        signature: key_of(i)
                            .sign(&crate::wire::bytes_to_sign(&digest))
                            .to_bytes()
                            .to_vec(),
                        signed_by: format!("fp-{}", c.names[i]),
                        signing_algorithm_spec: 1,
                        signature_delegation: None,
                    },
                ),
            }
        })
        .collect();
    bft::PrePrepare {
        block: Some(bft::OrderingBlock {
            proofs: vec![bft::ProofOfAvailability {
                batch_id: batch.0,
                acks,
                epoch_number: epoch,
            }],
        }),
        bft_time_canonical_commit_set: Some(bft::CanonicalCommitSet {
            canonical_commits: vec![],
        }),
    }
}

#[test]
fn the_proofs_of_a_proposal_are_checked() {
    let c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c"], info());
    let key_of = |i: usize| ed25519_dalek::SigningKey::from_bytes(&[i as u8 + 1; 32]);
    // two acks of three nodes are a weak quorum (one) many times over
    let good = acked_proposal(&c, &[1, 2], 3, key_of);
    assert_eq!(c.nodes[0].check_proofs(&good.block.unwrap().proofs), Ok(()));
    // an ack signed by another node's key
    let forged = acked_proposal(&c, &[1, 2], 3, |i| key_of((i + 1) % 3));
    assert!(c.nodes[0]
        .check_proofs(&forged.block.unwrap().proofs)
        .is_err());
    // no acks, a duplicate ack, a node that is not in the topology, a batch of a later epoch, a batch that expired
    let none = acked_proposal(&c, &[], 3, key_of);
    assert!(c.nodes[0]
        .check_proofs(&none.block.unwrap().proofs)
        .is_err());
    let twice = acked_proposal(&c, &[1, 1], 3, key_of);
    assert!(c.nodes[0]
        .check_proofs(&twice.block.unwrap().proofs)
        .is_err());
    let later = acked_proposal(&c, &[1, 2], 4, key_of);
    assert!(c.nodes[0]
        .check_proofs(&later.block.unwrap().proofs)
        .is_err());
    let old = acked_proposal(&c, &[1, 2], 3 - BATCH_VALIDITY_EPOCHS - 1, key_of);
    assert!(c.nodes[0].check_proofs(&old.block.unwrap().proofs).is_err());
}

/// `message` signed by node `signer` with its own key and fingerprint, under its own name.
fn signed_by(c: &Cluster, signer: usize, message: &bft::ConsensusMessage) -> bft::SignedMessage {
    let evidence = consensus_evidence(message);
    let signature = sign_message(
        AuthenticatedMessageType::BftSignedConsensusMessage,
        &c.names[signer],
        &evidence,
        &ed25519_dalek::SigningKey::from_bytes(&[signer as u8 + 1; 32]),
        &format!("fp-{}", c.names[signer]),
    )
    .unwrap();
    bft::SignedMessage {
        message: evidence,
        from: c.names[signer].clone(),
        signature: Some(signature),
    }
}

#[test]
fn a_retransmitted_commit_certificate_orders_a_block_only_when_it_verifies() {
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let epoch = info().number;
    let block = c.nodes[0].epoch.segment_of("SEQ::b").unwrap().slots[0];
    let pre_prepare = signed_by(
        &c,
        1,
        &pre_prepare_message(
            epoch,
            block,
            0,
            "SEQ::b",
            bft::OrderingBlock { proofs: vec![] },
            bft::CanonicalCommitSet {
                canonical_commits: vec![],
            },
        ),
    );
    let hash = block_hash_of_evidence(&pre_prepare.message).unwrap();
    // a commit naming `claimed` as its sender, signed by `signer`
    let commit = |signer: usize, claimed: usize, hash: &[u8]| {
        signed_by(
            &c,
            signer,
            &commit_message(epoch, block, 0, &c.names[claimed], hash.to_vec(), 1),
        )
    };
    let certificate = |commits: Vec<bft::SignedMessage>| bft::CommitCertificate {
        pre_prepare: Some(pre_prepare.clone()),
        commits,
    };
    let forged: Vec<bft::SignedMessage> = (1..4)
        .map(|i| {
            let mut m = commit(0, i, &hash);
            m.from = c.names[i].clone();
            if let Some(s) = m.signature.as_mut() {
                s.signed_by = format!("fp-{}", c.names[i]);
            }
            m
        })
        .collect();
    let impersonated: Vec<bft::SignedMessage> = (1..4).map(|i| commit(1, i, &hash)).collect();
    let duplicated = vec![
        commit(1, 1, &hash),
        commit(1, 1, &hash),
        commit(1, 1, &hash),
    ];
    let other_hash: Vec<bft::SignedMessage> = (1..4).map(|i| commit(i, i, &[7u8; 34])).collect();
    let genuine: Vec<bft::SignedMessage> = (1..4).map(|i| commit(i, i, &hash)).collect();

    for (what, commits) in [
        ("signatures by another node's key", forged),
        ("one node signing for the others", impersonated),
        ("one sender three times", duplicated),
        ("commits of another hash", other_hash),
    ] {
        let _ = c.nodes[0].on_commit_certificate(certificate(commits), 0, 0);
        assert!(
            !c.nodes[0].is_ordered(block),
            "a certificate with {what} must not order the block"
        );
    }
    let _ = c.nodes[0].on_commit_certificate(certificate(genuine), 0, 0);
    assert!(
        c.nodes[0].is_ordered(block),
        "a genuine certificate orders the block"
    );
}

#[test]
fn a_commit_certificate_completes_a_block_whose_proposal_here_is_of_an_earlier_view() {
    // `SegmentBlockState.completeBlock`: a verified commit certificate completes the block whatever is in progress here. Found by the simulation
    // (`testing`): a node that restarted with b's view-0 proposal of a block the others ordered in view 1 stayed in the view change for good.
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let epoch = info().number;
    let si = c.nodes[0]
        .epoch
        .segments
        .iter()
        .position(|s| s.original_leader == "SEQ::b")
        .unwrap();
    let block = c.nodes[0].epoch.segments[si].slots[0];
    let proposal = |c: &Cluster, signer: usize, view: i64| {
        signed_by(
            c,
            signer,
            &pre_prepare_message(
                epoch,
                block,
                view,
                &c.names[signer],
                bft::OrderingBlock { proofs: vec![] },
                bft::CanonicalCommitSet {
                    canonical_commits: vec![],
                },
            ),
        )
    };
    let by_b = proposal(&c, 1, 0);
    c.nodes[0].on_message(by_b, 0, 0);
    let new_leader = c.nodes[0].leader_in_view(si, 1).unwrap();
    let new_leader = c.names.iter().position(|n| *n == new_leader).unwrap();
    let ordered_in_view_1 = proposal(&c, new_leader, 1);
    let hash = block_hash_of_evidence(&ordered_in_view_1.message).unwrap();
    let commits = [1, 2, 3]
        .into_iter()
        .map(|i| {
            signed_by(
                &c,
                i,
                &commit_message(epoch, block, 1, &c.names[i], hash.clone(), 1),
            )
        })
        .collect();
    let sent = c.nodes[0]
        .on_commit_certificate(
            bft::CommitCertificate {
                pre_prepare: Some(ordered_in_view_1),
                commits,
            },
            0,
            0,
        )
        .unwrap();
    assert!(
        c.nodes[0].is_ordered(block),
        "the certificate completes the block"
    );
    assert!(
        sent.is_empty(),
        "a block completed by a certificate is not voted on"
    );
}

#[test]
fn a_vote_counts_only_for_the_node_that_signed_it() {
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let epoch = info().number;
    let block = c.nodes[0].epoch.segment_of("SEQ::b").unwrap().slots[0];
    let pre_prepare = signed_by(
        &c,
        1,
        &pre_prepare_message(
            epoch,
            block,
            0,
            "SEQ::b",
            bft::OrderingBlock { proofs: vec![] },
            bft::CanonicalCommitSet {
                canonical_commits: vec![],
            },
        ),
    );
    let hash = block_hash_of_evidence(&pre_prepare.message).unwrap();
    // a commit naming `claimed` as its sender inside, sent and signed by `signer`
    let commit = |signer: usize, claimed: usize| {
        signed_by(
            &c,
            signer,
            &commit_message(epoch, block, 0, &c.names[claimed], hash.clone(), 1),
        )
    };
    let (own, as_c, as_d) = (commit(1, 1), commit(1, 2), commit(1, 3));
    let (from_c, from_d) = (commit(2, 2), commit(3, 3));
    c.nodes[0].on_message(pre_prepare, 0, 0);
    for vote in [own, as_c, as_d] {
        c.nodes[0].on_message(vote, 0, 0);
    }
    assert!(
        !c.nodes[0].is_ordered(block),
        "one node's commits under the others' names are not a quorum"
    );
    for vote in [from_c, from_d] {
        c.nodes[0].on_message(vote, 0, 0);
    }
    assert!(
        c.nodes[0].is_ordered(block),
        "the commits of three nodes order the block"
    );
}

#[test]
fn a_node_checks_the_signatures_a_certificate_embeds_without_further_setup() {
    // S-19: a node as constructed knows its peers' keys; no later call is needed to switch signature checks on
    let c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let block = 60;
    let pre_prepare = signed_by(
        &c,
        0,
        &pre_prepare_message(
            3,
            block,
            0,
            "SEQ::a",
            bft::OrderingBlock { proofs: vec![] },
            bft::CanonicalCommitSet {
                canonical_commits: vec![],
            },
        ),
    );
    let hash = block_hash_of_evidence(&pre_prepare.message).unwrap();
    // node a signs the prepares of b, c and d under their names and fingerprints
    let forged: Vec<bft::SignedMessage> = (1..4)
        .map(|i| {
            let mut m = signed_by(
                &c,
                0,
                &prepare_message(3, block, 0, &c.names[i], hash.clone()),
            );
            m.from = c.names[i].clone();
            if let Some(s) = m.signature.as_mut() {
                s.signed_by = format!("fp-{}", c.names[i]);
            }
            m
        })
        .collect();
    let cert = bft::ConsensusCertificate {
        certificate: Some(bft::consensus_certificate::Certificate::PrepareCertificate(
            bft::PrepareCertificate {
                pre_prepare: Some(pre_prepare),
                prepares: forged,
            },
        )),
    };
    assert!(
        c.nodes[0].verify_certificate(&cert, 1).is_err(),
        "prepares signed with another node's key are refused"
    );
}

#[test]
fn a_proposal_is_taken_only_with_a_canonical_commit_set_that_holds() {
    // S-8 (`PbftMessageValidatorImpl.validateCanonicalCommitSet`): the second block of b's segment carries the commits that ordered the first one,
    // a strong quorum (3 of 4) of distinct nodes, each signed by the node it names
    let names = ["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"];
    let slots = Cluster::new(&names, info()).nodes[0]
        .epoch
        .segment_of("SEQ::b")
        .unwrap()
        .slots
        .clone();
    let (previous, block) = (slots[0], slots[1]);
    let taken = |commits: &dyn Fn(&Cluster) -> Vec<bft::SignedMessage>| {
        let mut c = Cluster::new(&names, info());
        let set = commits(&c);
        let proposal = signed_by(
            &c,
            1,
            &pre_prepare_message(
                3,
                block,
                0,
                "SEQ::b",
                bft::OrderingBlock { proofs: vec![] },
                bft::CanonicalCommitSet {
                    canonical_commits: set,
                },
            ),
        );
        c.nodes[0].on_message(proposal, 0, 0);
        c.nodes[0]
            .blocks
            .get(&block)
            .is_some_and(|b| b.pre_prepare.is_some())
    };
    let commit = |c: &Cluster, signer: usize, claimed: usize, of_block: i64| {
        let mut m = signed_by(
            c,
            signer,
            &commit_message(3, of_block, 0, &c.names[claimed], vec![5; 34], 7),
        );
        m.from = c.names[claimed].clone();
        if let Some(s) = m.signature.as_mut() {
            s.signed_by = format!("fp-{}", c.names[claimed]);
        }
        m
    };
    assert!(
        taken(&|c| vec![
            commit(c, 0, 0, previous),
            commit(c, 2, 2, previous),
            commit(c, 3, 3, previous)
        ]),
        "the commits of three nodes for the previous block of the segment"
    );
    assert!(
        !taken(&|c| vec![commit(c, 0, 0, previous), commit(c, 2, 2, previous)]),
        "two commits are below the strong quorum"
    );
    assert!(
        !taken(&|c| vec![
            commit(c, 0, 0, previous),
            commit(c, 0, 0, previous),
            commit(c, 2, 2, previous)
        ]),
        "a sender twice"
    );
    assert!(
        !taken(&|c| vec![
            commit(c, 0, 0, previous),
            commit(c, 2, 2, previous),
            commit(c, 0, 3, previous)
        ]),
        "a commit signed by another node than the one it names"
    );
    assert!(
        !taken(&|c| vec![
            commit(c, 0, 0, block),
            commit(c, 2, 2, block),
            commit(c, 3, 3, block)
        ]),
        "commits of a block that is not the previous one of the segment"
    );
}

#[test]
fn a_node_takes_the_topology_in_force_at_every_epoch_boundary() {
    // S-9: from epoch 4 on the topology no longer has d; the nodes leave it out of the leaders, the quorums and the epoch length
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    for node in &mut c.nodes {
        node.set_topology_source(Box::new(|epoch| {
            (epoch >= 4).then(|| EpochTopology {
                nodes: ["SEQ::a", "SEQ::b", "SEQ::c"].map(String::from).to_vec(),
                length: 9,
            })
        }));
    }
    c.run(4_000);
    let a = &c.nodes[0];
    assert!(a.epoch().info.number >= 4, "epoch 3 is over");
    assert_eq!(
        a.epoch().leaders.len(),
        3,
        "d leads nothing: {:?}",
        a.epoch().leaders
    );
    assert!(!a.epoch().leaders.contains(&"SEQ::d".to_string()));
    // the three nodes order a whole epoch of nine blocks without d (its votes would not count)
    c.dead[3] = true;
    c.run(8_000);
    assert!(
        c.nodes[0].epoch().info.number >= 5,
        "epoch 4 was ordered without d"
    );
    let ordered: std::collections::BTreeSet<i64> = c.nodes[0]
        .take_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::BlockOrdered {
                epoch: 4, block, ..
            } => Some(block),
            _ => None,
        })
        .collect();
    assert_eq!(
        ordered,
        (72..81).collect(),
        "epoch 4 has the nine blocks of its topology"
    );
}

#[test]
fn one_node_cannot_fill_the_queue_of_future_epochs() {
    // `IssConsensusModule.futurePbftMessageQueue`: 1024 messages a node, the newest dropped
    let mut c = Cluster::new(&["SEQ::a", "SEQ::b", "SEQ::c", "SEQ::d"], info());
    let flood: Vec<bft::SignedMessage> = (0..2_000)
        .map(|i| {
            signed_by(
                &c,
                1,
                &prepare_message(4, 72, 0, "SEQ::b", vec![i as u8; 34]),
            )
        })
        .collect();
    for m in flood {
        c.nodes[0].on_message(m, 0, 0);
    }
    let from_c = signed_by(&c, 2, &prepare_message(4, 72, 0, "SEQ::c", vec![1; 34]));
    c.nodes[0].on_message(from_c, 0, 0);
    assert_eq!(
        c.nodes[0].future.len(),
        crate::fair_queue::CONSENSUS_QUEUE_PER_NODE_QUOTA + 1,
        "b's quota is full, c still has room"
    );
}
