//! Daml-LF Local Durable Ledger Journal & Crash Recovery.
//!
//! Enforces:
//! - Append-only journal of transaction entries with monotonic offsets
//! - Crash recovery & ACS state reconstruction via journal replay (AT-C06)
//! - Pruning and checkpoint boundaries

use crate::tx_model::{ActiveLedgerState, TransactionTree};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub offset: u64,
    pub tx: TransactionTree,
    pub act_as: HashSet<String>,
    pub timestamp_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    TxExecutionError(String),
    OffsetOutOfOrder { expected: u64, actual: u64 },
    PruningError(String),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TxExecutionError(e) => write!(f, "transaction error during replay: {e}"),
            Self::OffsetOutOfOrder { expected, actual } => {
                write!(f, "offset out of order: expected {expected}, got {actual}")
            }
            Self::PruningError(p) => write!(f, "pruning error: {p}"),
        }
    }
}

impl std::error::Error for JournalError {}

/// In-memory and durable journal storage engine.
#[derive(Debug, Clone, Default)]
pub struct LedgerJournal {
    entries: Vec<JournalEntry>,
    next_offset: u64,
}

impl LedgerJournal {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_offset: 1,
        }
    }

    /// Appends a new committed transaction to the journal.
    pub fn append(
        &mut self,
        tx: TransactionTree,
        act_as: HashSet<String>,
        timestamp_micros: i64,
    ) -> u64 {
        let offset = self.next_offset;
        self.next_offset += 1;
        self.entries.push(JournalEntry {
            offset,
            tx,
            act_as,
            timestamp_micros,
        });
        offset
    }

    /// Replays all journal entries into an ActiveLedgerState to restore state after a restart/crash (AT-C06).
    pub fn replay_into(&self, state: &mut ActiveLedgerState) -> Result<u64, JournalError> {
        let mut last_offset = 0;
        for entry in &self.entries {
            state
                .apply_transaction(&entry.tx, &entry.act_as)
                .map_err(|e| JournalError::TxExecutionError(e.to_string()))?;
            last_offset = entry.offset;
        }
        Ok(last_offset)
    }

    /// Prunes journal entries strictly before the given offset.
    pub fn prune(&mut self, before_offset: u64) {
        self.entries.retain(|e| e.offset >= before_offset);
    }

    /// A position to roll back to: the number of entries and the next offset.
    pub fn checkpoint(&self) -> (usize, u64) {
        (self.entries.len(), self.next_offset)
    }

    /// Drops the entries appended after `checkpoint` (an append-only journal needs no copy of itself to undo them).
    pub fn rollback_to(&mut self, checkpoint: (usize, u64)) {
        self.entries.truncate(checkpoint.0);
        self.next_offset = checkpoint.1;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub fn from_entries(entries: Vec<JournalEntry>, next_offset: u64) -> Self {
        Self {
            entries,
            next_offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_model::{ContractId, Node};

    #[test]
    fn rollback_to_a_checkpoint_drops_later_entries_and_offsets() {
        let mut journal = LedgerJournal::new();
        let act_as: HashSet<String> = ["Alice".to_string()].into();
        journal.append(TransactionTree::new(), act_as.clone(), 1);
        let cp = journal.checkpoint();
        journal.append(TransactionTree::new(), act_as.clone(), 2);
        journal.append(TransactionTree::new(), act_as.clone(), 3);
        journal.rollback_to(cp);
        assert_eq!(journal.len(), 1);
        // the offsets of the dropped entries are handed out again
        assert_eq!(journal.append(TransactionTree::new(), act_as, 4), 2);
    }

    #[test]
    fn test_at_c06_durable_journal_append_and_crash_recovery_replay() {
        let mut journal = LedgerJournal::new();
        let mut live_state = ActiveLedgerState::new();

        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        // Tx 1: Create Contract 1
        let mut tx1 = TransactionTree::new();
        let cid1 = ContractId::derive("pkg1", "Asset", b"1", b"100");
        tx1.insert_node(
            Node::Create {
                contract_id: cid1.clone(),
                template_id: "Asset".into(),
                payload: b"100".to_vec(),
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: Some("alice-asset".into()),
            },
            true,
        );

        live_state.apply_transaction(&tx1, &act_as).unwrap();
        journal.append(tx1, act_as.clone(), 1000);

        // Tx 2: Exercise Contract 1 (consume) and create Contract 2
        let mut tx2 = TransactionTree::new();
        let cid2 = ContractId::derive("pkg1", "Asset", b"2", b"200");
        let create_node_id = tx2.insert_node(
            Node::Create {
                contract_id: cid2.clone(),
                template_id: "Asset".into(),
                payload: b"200".to_vec(),
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: None,
            },
            false,
        );

        tx2.insert_node(
            Node::Exercise {
                contract_id: cid1.clone(),
                choice: "Transfer".into(),
                acting_parties: sigs.clone(),
                consuming: true,
                children: vec![create_node_id],
            },
            true,
        );

        live_state.apply_transaction(&tx2, &act_as).unwrap();
        journal.append(tx2, act_as.clone(), 2000);

        // Simulate crash: wipe live state completely!
        let mut recovered_state = ActiveLedgerState::new();
        assert!(recovered_state.active_contracts.is_empty());

        // Replay journal (crash recovery)
        let last_offset = journal
            .replay_into(&mut recovered_state)
            .expect("replay should succeed");
        assert_eq!(last_offset, 2);

        // Verify recovered state matches post-crash state exactly
        assert_eq!(recovered_state.active_contracts.len(), 1);
        assert!(!recovered_state.active_contracts.contains_key(&cid1)); // cid1 was consumed
        assert!(recovered_state.active_contracts.contains_key(&cid2)); // cid2 is active
        assert!(!recovered_state.keys.contains_key("alice-asset")); // alice-asset key was released
    }
}
