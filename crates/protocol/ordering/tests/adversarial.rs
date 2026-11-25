//! AT-P06: an ordering peer that lies. Equivocating leaders, forged and replayed certificates, forked or stale state transfers, forged new
//! views. Each attack is made with real keys (an attacker that owns more than `f` keys is the strongest one: what still holds is checked).
use canton_ordering::types::{
    verify_committed_block, Commit, CommittedBlock, Config, NewView, PrePrepare, Prepare,
    PreparedCert, Reject, Signed, ViewChange,
};
use canton_ordering::{BftNode, Cluster, Event, Msg};
use ed25519_dalek::SigningKey;

fn zero() -> [u8; 32] {
    [0; 32]
}

fn pp(
    keys: &[SigningKey],
    view: u64,
    seq: u64,
    prev: [u8; 32],
    requests: &[&[u8]],
) -> Signed<PrePrepare> {
    let leader = (view % keys.len() as u64) as usize;
    Signed::sign(
        PrePrepare {
            view,
            seq,
            prev,
            requests: requests.iter().map(|r| r.to_vec()).collect(),
        },
        leader,
        &keys[leader],
    )
}

fn commit_vote(keys: &[SigningKey], from: usize, p: &Signed<PrePrepare>) -> Signed<Commit> {
    Signed::sign(
        Commit {
            view: p.body.view,
            seq: p.body.seq,
            digest: p.body.digest(),
        },
        from,
        &keys[from],
    )
}

fn prepare_vote(keys: &[SigningKey], from: usize, p: &Signed<PrePrepare>) -> Signed<Prepare> {
    Signed::sign(
        Prepare {
            view: p.body.view,
            seq: p.body.seq,
            digest: p.body.digest(),
        },
        from,
        &keys[from],
    )
}

/// A committed block as the cluster would have made it: the leader's proposal and the commits of nodes `0..=2f`.
fn block(
    keys: &[SigningKey],
    view: u64,
    seq: u64,
    prev: [u8; 32],
    requests: &[&[u8]],
) -> CommittedBlock {
    let p = pp(keys, view, seq, prev, requests);
    let commits = (0..3).map(|i| commit_vote(keys, i, &p)).collect();
    CommittedBlock {
        pre_prepare: p,
        commits,
    }
}

fn chain_hash(prev: &[u8; 32], b: &CommittedBlock) -> [u8; 32] {
    canton_ordering::crypto::entry_hash(prev, b.seq(), &b.pre_prepare.body.digest())
}

fn cluster() -> (Cluster, Vec<SigningKey>, Config) {
    let c = Cluster::new(1, 21);
    let (keys, cfg) = (c.keys.clone(), c.cfg.clone());
    (c, keys, cfg)
}

fn rejected(events: &[Event]) -> Vec<Reject> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Rejected { why, .. } => Some(why.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn an_equivocating_leader_cannot_split_the_honest_nodes() {
    let (mut c, keys, _) = cluster();
    // node 0, the leader of view 0, is faulty: it tells nodes 1 and 2 one thing and node 3 another
    c.silent.insert(0);
    let a = pp(&keys, 0, 1, zero(), &[b"a"]);
    let b = pp(&keys, 0, 1, zero(), &[b"b"]);
    c.inject(0, 1, Msg::PrePrepare(a.clone()));
    c.inject(0, 2, Msg::PrePrepare(a.clone()));
    c.inject(0, 3, Msg::PrePrepare(b));
    // node 3 is told of the other proposal right after: it sees the leader contradict itself before anything is committed
    c.inject(0, 3, Msg::PrePrepare(a.clone()));
    // and votes for a with its own key, enough to commit a on nodes 1 and 2
    for to in [1, 2, 3] {
        c.inject(0, to, Msg::Commit(commit_vote(&keys, 0, &a)));
    }
    c.run(60);
    c.assert_safety();
    let events = c.events();
    assert!(
        events
            .iter()
            .any(|(n, e)| *n == 3 && matches!(e, Event::Equivocation { view: 0, seq: 1 })),
        "node 3 saw the leader contradict itself: {events:?}"
    );
    // the honest nodes agree on a (never b) and go on without the faulty leader
    for n in 1..4 {
        c.submit(n, b"next");
    }
    assert!(
        c.run_until(3000, |c| (1..4)
            .all(|n| c.nodes[n].ordered_requests().len() == 2)),
        "{:?}",
        c.head_seqs()
    );
    c.assert_safety();
    for n in 1..4 {
        let got = c.nodes[n].ordered_requests();
        assert_eq!(
            got[0],
            b"a".to_vec(),
            "node {n} committed what the commit quorum had, never the other proposal"
        );
        assert!(!got.contains(&b"b".to_vec()));
    }
}

#[test]
fn a_signature_made_for_one_kind_of_message_is_no_good_as_another() {
    let (_, keys, cfg) = cluster();
    let p = pp(&keys, 0, 1, zero(), &[b"x"]);
    let real_commit = commit_vote(&keys, 1, &p);
    let real_prepare = prepare_vote(&keys, 1, &p);
    // a Commit presented as a Prepare, and a Prepare presented as a Commit, with the other's signature
    let as_prepare = Signed {
        body: Prepare {
            view: 0,
            seq: 1,
            digest: p.body.digest(),
        },
        from: 1,
        sig: real_commit.sig,
    };
    let as_commit = Signed {
        body: Commit {
            view: 0,
            seq: 1,
            digest: p.body.digest(),
        },
        from: 1,
        sig: real_prepare.sig,
    };
    assert!(real_commit.verifies(&cfg) && real_prepare.verifies(&cfg));
    assert!(
        !as_prepare.verifies(&cfg),
        "a Commit signature is not a Prepare"
    );
    assert!(
        !as_commit.verifies(&cfg),
        "a Prepare signature is not a Commit: it cannot make a commit certificate"
    );
    // so a block whose commits are relabelled prepares does not verify
    let forged = CommittedBlock {
        pre_prepare: p.clone(),
        commits: (0..3)
            .map(|i| Signed {
                body: Commit {
                    view: 0,
                    seq: 1,
                    digest: p.body.digest(),
                },
                from: i,
                sig: prepare_vote(&keys, i, &p).sig,
            })
            .collect(),
    };
    assert_eq!(
        verify_committed_block(&cfg, &forged, &zero()),
        Err(Reject::BadSignature)
    );
}

#[test]
fn a_certificate_is_refused_for_every_way_it_can_be_wrong() {
    let (_, keys, cfg) = cluster();
    let good = block(&keys, 0, 1, zero(), &[b"x"]);
    assert!(verify_committed_block(&cfg, &good, &zero()).is_ok());
    // too few commits
    let mut few = good.clone();
    few.commits.truncate(2);
    assert_eq!(
        verify_committed_block(&cfg, &few, &zero()),
        Err(Reject::NotEnoughVotes(2))
    );
    // one commit counted twice
    let mut twice = good.clone();
    twice.commits = vec![
        good.commits[0].clone(),
        good.commits[0].clone(),
        good.commits[1].clone(),
    ];
    assert_eq!(
        verify_committed_block(&cfg, &twice, &zero()),
        Err(Reject::DuplicateVoter)
    );
    // the proposal changed after it was signed
    let mut tampered = good.clone();
    tampered.pre_prepare.body.requests = vec![b"y".to_vec()];
    assert_eq!(
        verify_committed_block(&cfg, &tampered, &zero()),
        Err(Reject::BadSignature)
    );
    // a block on another chain
    assert_eq!(
        verify_committed_block(&cfg, &good, &[9; 32]),
        Err(Reject::ChainMismatch)
    );
    // a commit from a node outside the cluster
    let mut outsider = good.clone();
    outsider.commits[2] = Signed {
        from: 9,
        ..good.commits[2].clone()
    };
    assert_eq!(
        verify_committed_block(&cfg, &outsider, &zero()),
        Err(Reject::NotInCluster)
    );
    // commits for another block
    let other = pp(&keys, 0, 1, zero(), &[b"z"]);
    let mut wrong = good.clone();
    wrong.commits[2] = commit_vote(&keys, 2, &other);
    assert_eq!(
        verify_committed_block(&cfg, &wrong, &zero()),
        Err(Reject::VoteForOtherBlock)
    );
    // a proposal that the leader of its view did not sign
    let imposter = Signed::sign(good.pre_prepare.body.clone(), 2, &keys[2]);
    let mut not_leader = good;
    not_leader.pre_prepare = imposter;
    assert_eq!(
        verify_committed_block(&cfg, &not_leader, &zero()),
        Err(Reject::WrongLeader)
    );
}

/// A node that is behind is given blocks by a peer that lies.
#[test]
fn state_transfer_takes_only_certified_blocks_that_extend_the_chain() {
    let (_, keys, cfg) = cluster();
    let b1 = block(&keys, 0, 1, zero(), &[b"one"]);
    let h1 = chain_hash(&zero(), &b1);
    let b2 = block(&keys, 0, 2, h1, &[b"two"]);
    let h2 = chain_hash(&h1, &b2);
    let b3 = block(&keys, 0, 3, h2, &[b"three"]);
    let fresh = || BftNode::new(3, cfg.clone(), keys[3].clone());
    let try_take = |node: &mut BftNode, blocks: Vec<CommittedBlock>| -> Vec<Reject> {
        node.handle(1, Msg::StateResponse(blocks));
        rejected(&node.take_events())
    };

    // a gap
    let mut n = fresh();
    assert_eq!(try_take(&mut n, vec![b3.clone()]), vec![Reject::WrongSlot]);
    assert_eq!(n.head_seq(), 0);
    // tampered payload
    let mut tampered = b1.clone();
    tampered.pre_prepare.body.requests = vec![b"evil".to_vec()];
    assert_eq!(try_take(&mut n, vec![tampered]), vec![Reject::BadSignature]);
    // a certificate with too few commits (f + 1 of them)
    let mut thin = b1.clone();
    thin.commits.truncate(2);
    assert_eq!(
        try_take(&mut n, vec![thin]),
        vec![Reject::NotEnoughVotes(2)]
    );
    assert_eq!(n.head_seq(), 0, "nothing of that was taken");
    // a good prefix followed by a block that does not extend it ends the response, the prefix stays
    let off_chain = block(&keys, 0, 3, [7; 32], &[b"three"]);
    assert_eq!(
        try_take(&mut n, vec![b1.clone(), b2.clone(), off_chain]),
        vec![Reject::ChainMismatch]
    );
    assert_eq!(n.head_seq(), 2);
    // stale and repeated blocks are ignored without complaint
    assert_eq!(try_take(&mut n, vec![b1, b2]), vec![]);
    assert_eq!(n.head_seq(), 2);
    // and the real third block is taken
    assert_eq!(try_take(&mut n, vec![b3]), vec![]);
    assert_eq!(n.head_seq(), 3);
    assert_eq!(
        n.ordered_requests(),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
}

/// Two valid certificates for different blocks in one slot mean that more than f nodes are faulty: the node reports a fork and keeps
/// its own block.
#[test]
fn a_forked_history_with_valid_certificates_is_reported_and_not_taken() {
    let (_, keys, cfg) = cluster();
    let ours = block(&keys, 0, 1, zero(), &[b"ours"]);
    let theirs = block(&keys, 0, 1, zero(), &[b"theirs"]);
    let mut n = BftNode::new(3, cfg, keys[3].clone());
    n.handle(1, Msg::StateResponse(vec![ours]));
    assert_eq!(n.head_seq(), 1);
    n.take_events();
    n.handle(2, Msg::StateResponse(vec![theirs]));
    let events = n.take_events();
    assert!(events.contains(&Event::Fork { seq: 1 }), "{events:?}");
    assert_eq!(
        n.ordered_requests(),
        vec![b"ours".to_vec()],
        "the node keeps what it committed"
    );
    // a different block for a slot with a certificate that does not verify is only refused
    let mut bad = block(&keys, 0, 1, zero(), &[b"forged"]);
    bad.commits.truncate(1);
    n.handle(2, Msg::StateResponse(vec![bad]));
    let events = n.take_events();
    assert!(!events.iter().any(|e| matches!(e, Event::Fork { .. })));
    assert_eq!(rejected(&events).len(), 1);
}

fn vc(
    keys: &[SigningKey],
    from: usize,
    new_view: u64,
    prepared: Option<PreparedCert>,
) -> Signed<ViewChange> {
    Signed::sign(
        ViewChange {
            new_view,
            head_seq: 0,
            head_hash: zero(),
            head_proof: None,
            prepared,
        },
        from,
        &keys[from],
    )
}

fn prepared_cert(keys: &[SigningKey], requests: &[&[u8]]) -> PreparedCert {
    let p = pp(keys, 0, 1, zero(), requests);
    PreparedCert {
        prepares: (1..3).map(|i| prepare_vote(keys, i, &p)).collect(),
        pre_prepare: p,
    }
}

#[test]
fn a_new_view_that_does_not_follow_from_its_proofs_is_refused() {
    let (_, keys, cfg) = cluster();
    let leader = 1; // view 1
    let make =
        |vcs: Vec<Signed<ViewChange>>, reproposal: Option<Signed<PrePrepare>>, from: usize| {
            Signed::sign(
                NewView {
                    view: 1,
                    view_changes: vcs,
                    reproposal,
                },
                from,
                &keys[from],
            )
        };
    let fresh = || BftNode::new(2, cfg.clone(), keys[2].clone());
    let check = |nv: Signed<NewView>| -> (Vec<Reject>, u64) {
        let mut n = fresh();
        n.handle(leader, Msg::NewView(nv));
        let view = n.view();
        (rejected(&n.take_events()), view)
    };
    // node 3 had prepared "x" in view 0: the new view must propose it again
    let cert = prepared_cert(&keys, &[b"x"]);
    let honest = vec![
        vc(&keys, 1, 1, None),
        vc(&keys, 2, 1, None),
        vc(&keys, 3, 1, Some(cert.clone())),
    ];
    let good_repropose = pp(&keys, 1, 1, zero(), &[b"x"]);
    let (why, view) = check(make(honest.clone(), Some(good_repropose.clone()), leader));
    assert!(
        why.is_empty() && view == 1,
        "the honest new view is taken: {why:?}"
    );

    // too few view changes
    let (why, view) = check(make(
        honest[..2].to_vec(),
        Some(good_repropose.clone()),
        leader,
    ));
    assert_eq!((why, view), (vec![Reject::NotEnoughVotes(2)], 0));
    // the same node's view change counted twice
    let twice = vec![honest[0].clone(), honest[0].clone(), honest[2].clone()];
    let (why, _) = check(make(twice, Some(good_repropose.clone()), leader));
    assert_eq!(why, vec![Reject::DuplicateVoter]);
    // the leader proposes other requests than the ones a node had prepared
    let (why, view) = check(make(
        honest.clone(),
        Some(pp(&keys, 1, 1, zero(), &[b"y"])),
        leader,
    ));
    assert_eq!(view, 0);
    assert!(matches!(why[0], Reject::Malformed(_)), "{why:?}");
    // the leader leaves out what had been prepared
    let (why, view) = check(make(honest.clone(), None, leader));
    assert_eq!(view, 0);
    assert!(matches!(why[0], Reject::Malformed(_)), "{why:?}");
    // a view change whose proof is made up (a head with no proof)
    let mut liar = vc(&keys, 3, 1, None);
    liar.body.head_seq = 5;
    let liar = Signed::sign(liar.body, 3, &keys[3]);
    let (why, _) = check(make(
        vec![honest[0].clone(), honest[1].clone(), liar],
        None,
        leader,
    ));
    assert!(matches!(why[0], Reject::Malformed(_)), "{why:?}");
    // a prepared certificate with too few prepares
    let mut thin = cert;
    thin.prepares.truncate(1);
    let (why, _) = check(make(
        vec![
            honest[0].clone(),
            honest[1].clone(),
            vc(&keys, 3, 1, Some(thin)),
        ],
        Some(good_repropose),
        leader,
    ));
    assert_eq!(why, vec![Reject::NotEnoughVotes(1)]);
    // a new view from a node that is not the leader of view 1
    let (why, view) = check(make(honest, None, 3));
    assert_eq!((why, view), (vec![Reject::WrongLeader], 0));
}

/// A node that asked for a new view takes no part in the old one any more: what a new leader reads from the view changes would go stale.
#[test]
fn a_node_that_asked_for_a_new_view_ignores_the_old_one() {
    let (_, keys, cfg) = cluster();
    let mut n = BftNode::new(2, cfg.clone(), keys[2].clone());
    n.submit(b"waiting".to_vec());
    for _ in 0..40 {
        n.tick();
    }
    assert!(n.in_view_change());
    let late = pp(&keys, 0, 1, zero(), &[b"waiting"]);
    let outs = n.handle(0, Msg::PrePrepare(late));
    assert!(
        outs.iter()
            .all(|o| !matches!(o, canton_ordering::Out::Broadcast(Msg::Prepare(_)))),
        "no Prepare for a view it left"
    );
    // the promise survives a crash
    let durable = n.durable();
    let back = BftNode::recover(2, cfg, keys[2].clone(), durable);
    assert!(back.in_view_change(), "it did not forget what it promised");
}

#[test]
fn messages_from_outside_the_cluster_or_with_wrong_signatures_are_refused() {
    let (_, keys, cfg) = cluster();
    let mut n = BftNode::new(1, cfg, keys[1].clone());
    let p = pp(&keys, 0, 1, zero(), &[b"x"]);
    // signed by someone else than the leader it claims to be from
    let forged = Signed {
        from: 0,
        ..Signed::sign(p.body.clone(), 0, &keys[2])
    };
    n.handle(0, Msg::PrePrepare(forged));
    assert_eq!(rejected(&n.take_events()), vec![Reject::BadSignature]);
    // from a node that is not in the cluster
    let outsider = Signed {
        from: 9,
        ..prepare_vote(&keys, 2, &p)
    };
    n.handle(9, Msg::Prepare(outsider));
    assert_eq!(rejected(&n.take_events()), vec![Reject::BadSignature]);
    // a proposal from a node that is not the leader of the view
    let not_leader = Signed::sign(p.body, 2, &keys[2]);
    n.handle(2, Msg::PrePrepare(not_leader));
    assert_eq!(rejected(&n.take_events()), vec![Reject::WrongLeader]);
}
