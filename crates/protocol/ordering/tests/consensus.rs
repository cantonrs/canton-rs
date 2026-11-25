//! The ordering engine on a simulated network: agreement, crash, partition (AT-P05) and a noisy network.
use canton_ordering::Cluster;

fn requests(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("request-{i}").into_bytes())
        .collect()
}

fn ordered(c: &Cluster, node: usize) -> usize {
    c.nodes[node].ordered_requests().len()
}

fn same_order(c: &Cluster, nodes: &[usize]) {
    let first = c.nodes[nodes[0]].ordered_requests();
    for n in nodes {
        assert_eq!(
            c.nodes[*n].ordered_requests(),
            first,
            "node {n} ordered differently"
        );
    }
}

#[test]
fn four_nodes_order_requests_the_same_way_exactly_once() {
    let mut c = Cluster::new(1, 7);
    let all = requests(20);
    for (i, r) in all.iter().enumerate() {
        c.submit(i % 4, r);
    }
    assert!(
        c.run_until(600, |c| (0..4).all(|n| ordered(c, n) == 20)),
        "{:?}",
        c.head_seqs()
    );
    c.assert_safety();
    same_order(&c, &[0, 1, 2, 3]);
    let mut got = c.nodes[0].ordered_requests();
    got.sort();
    let mut want = all;
    want.sort();
    assert_eq!(got, want, "every request once");
}

#[test]
fn seven_nodes_tolerate_two_faults() {
    let mut c = Cluster::new(2, 11);
    c.crash(5);
    c.crash(6);
    for (i, r) in requests(12).iter().enumerate() {
        c.submit(i % 5, r);
    }
    assert!(
        c.run_until(900, |c| (0..5).all(|n| ordered(c, n) == 12)),
        "{:?}",
        c.head_seqs()
    );
    c.assert_safety();
    same_order(&c, &[0, 1, 2, 3, 4]);
}

#[test]
fn a_crashed_leader_is_replaced_and_comes_back_up_to_date() {
    let mut c = Cluster::new(1, 3);
    c.crash(0);
    for (i, r) in requests(5).iter().enumerate() {
        c.submit(1 + i % 3, r);
    }
    assert!(
        c.run_until(1500, |c| (1..4).all(|n| ordered(c, n) == 5)),
        "{:?}",
        c.head_seqs()
    );
    assert!(
        c.nodes[1].view() >= 1,
        "a view change replaced the crashed leader"
    );
    c.assert_safety();
    // the old leader returns with what it kept and catches up
    c.restart(0);
    for (i, r) in requests(8).iter().skip(5).enumerate() {
        c.submit(1 + i % 3, r);
    }
    assert!(
        c.run_until(1500, |c| (0..4).all(|n| ordered(c, n) == 8)),
        "{:?}",
        c.head_seqs()
    );
    c.assert_safety();
    same_order(&c, &[0, 1, 2, 3]);
}

/// AT-P05: a partition without a quorum commits nothing (safety), and the cluster goes on once it is healed (liveness).
#[test]
fn a_partition_without_a_quorum_commits_nothing_and_the_cluster_recovers_when_it_heals() {
    let mut c = Cluster::new(1, 5);
    c.partition(&[0, 0, 1, 1]);
    c.submit(0, b"left");
    c.submit(2, b"right");
    c.run(400);
    assert_eq!(
        c.head_seqs(),
        vec![0, 0, 0, 0],
        "no side has 2f + 1 nodes: nothing is committed"
    );
    c.assert_safety();
    c.heal();
    // a client asks again (the requests were not lost, but a request is only sent to the leader when it is submitted)
    c.submit(0, b"left");
    c.submit(2, b"right");
    assert!(
        c.run_until(6000, |c| (0..4).all(|n| ordered(c, n) == 2)),
        "the cluster does not stay stopped after the partition: {:?} views {:?}",
        c.head_seqs(),
        c.nodes.iter().map(|n| n.view()).collect::<Vec<_>>()
    );
    c.assert_safety();
    same_order(&c, &[0, 1, 2, 3]);
}

/// AT-P05: the side with a quorum goes on, the node cut off catches up when the partition heals.
#[test]
fn the_side_with_a_quorum_goes_on_and_the_isolated_node_catches_up() {
    let mut c = Cluster::new(1, 9);
    c.partition(&[0, 0, 0, 1]);
    for (i, r) in requests(6).iter().enumerate() {
        c.submit(i % 3, r);
    }
    assert!(
        c.run_until(500, |c| (0..3).all(|n| ordered(c, n) == 6)),
        "{:?}",
        c.head_seqs()
    );
    assert_eq!(c.nodes[3].head_seq(), 0, "the isolated node saw nothing");
    c.assert_safety();
    c.heal();
    assert!(
        c.run_until(500, |c| ordered(c, 3) == 6),
        "the isolated node fetched the blocks: {:?}",
        c.head_seqs()
    );
    c.assert_safety();
    same_order(&c, &[0, 1, 2, 3]);
}

/// A node that was cut off with a request of its own escalates its view change alone; it still gets the blocks when it comes back,
/// and the cluster keeps committing without waiting for it.
#[test]
fn a_node_that_was_cut_off_with_a_request_does_not_hold_the_cluster_back() {
    let mut c = Cluster::new(1, 13);
    c.partition(&[0, 0, 0, 1]);
    c.submit(3, b"stuck");
    for (i, r) in requests(4).iter().enumerate() {
        c.submit(i % 3, r);
    }
    c.run(800);
    assert!(
        c.nodes[3].in_view_change(),
        "alone, it asked for a new view"
    );
    c.heal();
    c.submit(0, b"after");
    assert!(
        c.run_until(1500, |c| (0..3).all(|n| ordered(c, n) >= 5)),
        "{:?}",
        c.head_seqs()
    );
    assert!(
        c.run_until(1500, |c| c.nodes[3].head_seq() == c.nodes[0].head_seq()),
        "{:?}",
        c.head_seqs()
    );
    c.assert_safety();
}

/// Loss, duplication and reordering never break agreement, and the requests still get ordered.
#[test]
fn loss_duplication_and_reordering_never_break_agreement() {
    for seed in 1..=12u64 {
        let mut c = Cluster::new(1, seed);
        c.net.drop_pct = 5;
        c.net.dup_pct = 10;
        c.net.max_delay = 4;
        for r in requests(6) {
            // a client that does not hear back asks every node
            for n in 0..4 {
                c.submit(n, &r);
            }
        }
        let done = c.run_until(8000, |c| (0..4).all(|n| ordered(c, n) == 6));
        c.assert_safety();
        assert!(done, "seed {seed}: {:?}", c.head_seqs());
        same_order(&c, &[0, 1, 2, 3]);
    }
}
