//! The prepared transactions an `execute` call may find instead of recomputing them (internal review A-11).
//!
//! [CANTON-NOTE: WHY] Canton keeps no such cache: `ExecuteSubmission` carries the whole prepared transaction, and a miss here recomputes
//! the plan from it (`v2_interactive::commit_from_prepared`). The cache is only a shortcut, so it is bounded in size and age: an entry
//! older than [`TTL`] or past [`MAX_ENTRIES`] is dropped, oldest first.
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::v2_interactive::CachedPrepared;

/// The most prepared transactions kept.
pub const MAX_ENTRIES: usize = 1024;
/// How long a prepared transaction is kept.
pub const TTL: Duration = Duration::from_secs(10 * 60);

/// `(logical synchronizer, prepared transaction hash)`.
pub(crate) type Key = (String, [u8; 32]);

/// The cache, with its entries in insertion order.
#[derive(Default)]
pub struct PreparedCache {
    entries: HashMap<Key, (Instant, CachedPrepared)>,
    order: VecDeque<(Instant, Key)>,
}

impl PreparedCache {
    pub(crate) fn insert(&mut self, key: Key, value: CachedPrepared) {
        self.insert_at(key, value, Instant::now());
    }

    fn insert_at(&mut self, key: Key, value: CachedPrepared, now: Instant) {
        self.entries.insert(key.clone(), (now, value));
        self.order.push_back((now, key));
        self.evict(now);
    }

    pub(crate) fn remove(&mut self, key: &Key) -> Option<CachedPrepared> {
        self.remove_at(key, Instant::now())
    }

    fn remove_at(&mut self, key: &Key, now: Instant) -> Option<CachedPrepared> {
        self.evict(now);
        self.entries.remove(key).map(|(_, v)| v)
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Drops the expired entries and, past the size bound, the oldest ones. An order entry whose key was since removed or re-inserted
    /// (a newer time) is skipped.
    fn evict(&mut self, now: Instant) {
        while let Some((at, key)) = self.order.front() {
            let current = self
                .entries
                .get(key)
                .is_some_and(|(inserted, _)| inserted == at);
            let expired = now.saturating_duration_since(*at) > TTL;
            if current && !expired && self.entries.len() <= MAX_ENTRIES {
                break;
            }
            if current {
                self.entries.remove(key);
            }
            self.order.pop_front();
        }
        // re-inserted keys leave stale order entries behind the front: keep the queue within twice the bound
        if self.order.len() > 2 * MAX_ENTRIES {
            let entries = &self.entries;
            self.order
                .retain(|(at, key)| entries.get(key).is_some_and(|(inserted, _)| inserted == at));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CachedPrepared {
        CachedPrepared {
            commits: Vec::new(),
            disclosed: Vec::new(),
            read_as: Vec::new(),
            required_active_inputs: Vec::new(),
            events: Vec::new(),
            max_record_time_micros: None,
            has_disclosed_inputs: false,
        }
    }

    fn key(n: u8) -> Key {
        ("sync".into(), [n; 32])
    }

    #[test]
    fn past_the_size_bound_the_oldest_entry_is_dropped() {
        let mut cache = PreparedCache::default();
        let now = Instant::now();
        for i in 0..=MAX_ENTRIES {
            let mut k = key(0);
            k.1[..8].copy_from_slice(&(i as u64).to_le_bytes());
            cache.insert_at(k, entry(), now);
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        let mut first = key(0);
        first.1[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(cache.remove_at(&first, now).is_none(), "the oldest is gone");
    }

    #[test]
    fn an_entry_older_than_the_ttl_is_dropped() {
        let mut cache = PreparedCache::default();
        let now = Instant::now();
        cache.insert_at(key(1), entry(), now);
        cache.insert_at(key(2), entry(), now + TTL / 2);
        assert!(cache
            .remove_at(&key(1), now + TTL + Duration::from_secs(1))
            .is_none());
        assert!(cache
            .remove_at(&key(2), now + TTL + Duration::from_secs(1))
            .is_some());
    }
}
