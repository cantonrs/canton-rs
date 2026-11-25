//! A queue with a total bound and a quota per node that keeps the arrival order (`utils/FairBoundedQueue.scala` with `DropStrategy.DropNewest`):
//! what goes over either bound is refused, so one node cannot fill the queue for the others.
use std::collections::{BTreeMap, VecDeque};

/// `BftBlockOrdererConfig.DefaultConsensusQueueMaxSize`.
pub const CONSENSUS_QUEUE_MAX_SIZE: usize = 10 * 1_024;
/// `BftBlockOrdererConfig.DefaultConsensusQueuePerNodeQuota`.
pub const CONSENSUS_QUEUE_PER_NODE_QUOTA: usize = 1_024;

/// Why an item was not queued (`FairBoundedQueue.EnqueueResult`).
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    TotalCapacityExceeded,
    PerNodeQuotaExceeded,
    Duplicate,
}

pub struct FairBoundedQueue<T> {
    max_size: usize,
    per_node_quota: usize,
    /// `DeduplicationStrategy.PerNode`: an item a node already has in the queue is refused.
    deduplicate: bool,
    items: VecDeque<(String, T)>,
    per_node: BTreeMap<String, usize>,
}

impl<T: PartialEq> FairBoundedQueue<T> {
    pub fn new(max_size: usize, per_node_quota: usize, deduplicate: bool) -> Self {
        Self {
            max_size,
            per_node_quota,
            deduplicate,
            items: VecDeque::new(),
            per_node: BTreeMap::new(),
        }
    }

    /// The consensus queues' bounds.
    pub fn consensus(deduplicate: bool) -> Self {
        Self::new(
            CONSENSUS_QUEUE_MAX_SIZE,
            CONSENSUS_QUEUE_PER_NODE_QUOTA,
            deduplicate,
        )
    }

    /// Queues `item` that `node` sent, unless that takes the node over its quota or the queue over its size.
    pub fn enqueue(&mut self, node: &str, item: T) -> Result<(), Refused> {
        if self.deduplicate && self.items.iter().any(|(n, i)| n == node && *i == item) {
            return Err(Refused::Duplicate);
        }
        let count = self.per_node.get(node).copied().unwrap_or(0);
        if count >= self.per_node_quota {
            return Err(Refused::PerNodeQuotaExceeded);
        }
        if self.items.len() >= self.max_size {
            return Err(Refused::TotalCapacityExceeded);
        }
        self.per_node.insert(node.to_string(), count + 1);
        self.items.push_back((node.to_string(), item));
        Ok(())
    }

    /// Everything, in the order it arrived; the queue is empty after.
    pub fn drain(&mut self) -> Vec<T> {
        self.per_node.clear();
        self.items.drain(..).map(|(_, item)| item).collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_over_its_quota_or_a_full_queue_is_refused_and_the_order_kept() {
        let mut q = FairBoundedQueue::new(3, 2, true);
        assert_eq!(q.enqueue("a", 1), Ok(()));
        assert_eq!(q.enqueue("a", 1), Err(Refused::Duplicate));
        assert_eq!(q.enqueue("a", 2), Ok(()));
        assert_eq!(q.enqueue("a", 3), Err(Refused::PerNodeQuotaExceeded));
        assert_eq!(q.enqueue("b", 4), Ok(()));
        assert_eq!(q.enqueue("c", 5), Err(Refused::TotalCapacityExceeded));
        assert_eq!(q.drain(), vec![1, 2, 4]);
        assert_eq!(q.enqueue("a", 3), Ok(()), "the quota is free again");
    }
}
