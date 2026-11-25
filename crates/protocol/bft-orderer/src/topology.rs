//! The ordering topology and the quorum arithmetic of the BFT orderer (B1).
//!
//! [CANTON-NOTE: SEMANTICS] Source: `framework/data/topology/OrderingTopology.scala` (the object at its end), `framework/data/ordering/iss/EpochInfo.scala`.
//! With `n` nodes: `f = (n - 1) / 3` faults are tolerated, a weak quorum is `f + 1` (one honest vote at least), a strong quorum is `n` for `n <= 3` and
//! `ceil(2n / 3)` above that (`2f + 1` when `n = 3f + 1`). Nodes are only ever iterated in sorted order (`sortedNodes`): a map's order is not deterministic.
use std::collections::{BTreeMap, BTreeSet};

/// `numToleratedFaults`: `(n - 1) / 3`.
pub fn num_tolerated_faults(nodes: usize) -> usize {
    nodes.saturating_sub(1) / 3
}

/// `weakQuorumSize`: `f + 1`.
pub fn weak_quorum_size(nodes: usize) -> usize {
    num_tolerated_faults(nodes) + 1
}

/// `strongQuorumSize`: all the nodes up to three of them, `ceil(2n / 3)` above.
pub fn strong_quorum_size(nodes: usize) -> usize {
    if nodes <= 3 {
        nodes
    } else {
        (2 * nodes).div_ceil(3)
    }
}

pub fn is_weak_quorum_reached(nodes: usize, valid_votes: usize) -> bool {
    valid_votes >= weak_quorum_size(nodes)
}

pub fn is_strong_quorum_reached(nodes: usize, valid_votes: usize) -> bool {
    valid_votes >= strong_quorum_size(nodes)
}

/// The nodes of an epoch with the key ids each may sign with (`OrderingTopology.nodesTopologyInfo`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderingTopology {
    pub nodes: BTreeMap<String, BTreeSet<String>>,
}

impl OrderingTopology {
    pub fn size(&self) -> usize {
        self.nodes.len()
    }
    /// `sortedNodes`.
    pub fn sorted_nodes(&self) -> Vec<&str> {
        self.nodes.keys().map(String::as_str).collect()
    }
    pub fn contains(&self, node: &str) -> bool {
        self.nodes.contains_key(node)
    }
    pub fn weak_quorum(&self) -> usize {
        weak_quorum_size(self.size())
    }
    pub fn strong_quorum(&self) -> usize {
        strong_quorum_size(self.size())
    }
    pub fn has_weak_quorum(&self, valid_votes: usize) -> bool {
        is_weak_quorum_reached(self.size(), valid_votes)
    }
    pub fn has_strong_quorum(&self, valid_votes: usize) -> bool {
        is_strong_quorum_reached(self.size(), valid_votes)
    }
    /// `isAuthorized`: the node is in the topology and `key_id` is one of its keys.
    pub fn is_authorized(&self, from: &str, key_id: &str) -> bool {
        self.nodes
            .get(from)
            .is_some_and(|keys| keys.contains(key_id))
    }
}

/// An epoch: its number, the first block it orders and its length in blocks (`EpochInfo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochInfo {
    pub number: i64,
    pub start_block_number: i64,
    pub length: i64,
}

impl EpochInfo {
    /// `relativeBlockIndex`.
    pub fn relative_block_index(&self, block_number: i64) -> i64 {
        block_number - self.start_block_number
    }
    /// `startOfNextEpochBlockNumber`.
    pub fn start_of_next_epoch_block_number(&self) -> i64 {
        self.start_block_number + self.length
    }
    /// `lastBlockNumber`.
    pub fn last_block_number(&self) -> i64 {
        self.start_block_number + self.length - 1
    }
    /// `next`: the epoch after this one, which starts where this one ends, with its own length.
    pub fn next(&self, length: i64) -> Self {
        Self {
            number: self.number + 1,
            start_block_number: self.start_of_next_epoch_block_number(),
            length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorums_follow_the_scala_formulas() {
        // (nodes, faults, weak, strong); two nodes: the oracle cluster logs `weakQuorum = 1, strongQuorum = 2`
        for (n, f, weak, strong) in [
            (1, 0, 1, 1),
            (2, 0, 1, 2),
            (3, 0, 1, 3),
            (4, 1, 2, 3),
            (5, 1, 2, 4),
            (6, 1, 2, 4),
            (7, 2, 3, 5),
            (10, 3, 4, 7),
        ] {
            assert_eq!(num_tolerated_faults(n), f, "faults of {n}");
            assert_eq!(weak_quorum_size(n), weak, "weak of {n}");
            assert_eq!(strong_quorum_size(n), strong, "strong of {n}");
        }
        // with n = 3f + 1 the strong quorum is 2f + 1
        for f in 1..20 {
            assert_eq!(strong_quorum_size(3 * f + 1), 2 * f + 1);
        }
    }

    #[test]
    fn a_quorum_is_reached_at_its_size_and_not_below() {
        assert!(!is_strong_quorum_reached(4, 2));
        assert!(is_strong_quorum_reached(4, 3));
        assert!(!is_weak_quorum_reached(4, 1));
        assert!(is_weak_quorum_reached(4, 2));
    }

    #[test]
    fn the_topology_authorizes_a_node_only_for_its_own_keys() {
        let mut t = OrderingTopology::default();
        t.nodes
            .insert("SEQ::b".into(), BTreeSet::from(["kb".to_string()]));
        t.nodes
            .insert("SEQ::a".into(), BTreeSet::from(["ka".to_string()]));
        assert_eq!(t.sorted_nodes(), vec!["SEQ::a", "SEQ::b"]);
        assert!(t.is_authorized("SEQ::a", "ka"));
        assert!(!t.is_authorized("SEQ::a", "kb"));
        assert!(!t.is_authorized("SEQ::z", "ka"));
        assert_eq!((t.weak_quorum(), t.strong_quorum()), (1, 2));
    }

    #[test]
    fn epochs_follow_each_other_without_a_gap() {
        // the oracle cluster logs epoch length 20
        let e = EpochInfo {
            number: 14,
            start_block_number: 280,
            length: 20,
        };
        assert_eq!(e.last_block_number(), 299);
        assert_eq!(e.relative_block_index(285), 5);
        let n = e.next(20);
        assert_eq!((n.number, n.start_block_number), (15, 300));
    }
}
