//! The journal of the topology broadcasts this participant read (`topology.journal`, one stored transaction in hex a line), replayed onto
//! the downloaded state when the runtime starts again (P-13).
//!
//! [CANTON-NOTE: INVARIANT] Reading an event again (after a crash before the cursor moved past it, or a rewind) journals nothing new: a line
//! already in the journal is not appended again, and a line repeated in an older journal is replayed once. Applying the same signed
//! transaction twice never changes the tracker (in force again, or refused by its serial), so replaying it once gives the same state.
use super::Runtime;

pub(super) const JOURNAL: &str = "topology.journal";

impl Runtime {
    /// Keeps `stored` before it is used, unless it is kept already.
    pub(super) fn journal_topology(&self, stored: &[u8]) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let line = hex::encode(stored);
        if store
            .read(JOURNAL)?
            .unwrap_or_default()
            .lines()
            .any(|kept| kept.trim() == line)
        {
            return Ok(());
        }
        store.append(JOURNAL, &line)
    }

    /// The transactions the journal keeps, each once, in the order they were first read.
    pub(super) fn journaled_topology(&self) -> Vec<Vec<u8>> {
        let Some(journal) = self
            .store
            .as_ref()
            .and_then(|store| store.read(JOURNAL).ok().flatten())
        else {
            return Vec::new();
        };
        let mut seen = std::collections::BTreeSet::new();
        journal
            .lines()
            .filter_map(|line| hex::decode(line.trim()).ok())
            .filter(|stored| seen.insert(stored.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{config, engine, event};
    use super::{Runtime, JOURNAL};
    use crate::topology_wire::{topology_broadcast, ParticipantIdentity, ALL_MEMBERS};

    /// P-13: an event with a topology broadcast read again is journaled once, and the restarted runtime comes to the same state.
    #[test]
    fn a_broadcast_read_again_is_journaled_once_and_replays_to_the_same_state() {
        let me = ParticipantIdentity::generate("journal-once");
        let state: Vec<(i64, Vec<u8>)> = me
            .onboarding_transactions("sync::1220aa")
            .iter()
            .map(|t| (0, crate::topology_wire::stored_form(t)))
            .collect();
        let entries = crate::topology_state::decode(&state).unwrap();
        let dir = std::env::temp_dir().join(format!("topology-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let open = || {
            let mut cfg = config();
            cfg.member = me.member();
            cfg.follow_topology = true;
            cfg.physical_synchronizer_id = "sync::1220aa::37-0".into();
            let mut rt = Runtime::open(cfg, engine(), Some(&dir), 0).unwrap();
            rt.load_topology_state(&entries).unwrap();
            rt
        };
        let mut rt = open();
        let mut hosting = event(1_000_000);
        hosting.envelopes = vec![topology_broadcast(
            "sync",
            &[me.party_hosting_transaction("erin")],
        )];
        hosting.recipients = vec![vec![ALL_MEMBERS.to_string()]];
        rt.step(&hosting).unwrap();
        rt.rewind(999_999).unwrap();
        rt.step(&hosting).unwrap();
        let journal = std::fs::read_to_string(dir.join(JOURNAL)).unwrap();
        assert_eq!(journal.lines().count(), 1, "journaled once");
        rt.step(&event(1_250_001)).unwrap();
        let hosted = rt.config.hosted_parties.clone();
        assert_eq!(hosted, vec![me.party_id("erin")]);
        drop(rt);
        let rt = open();
        assert_eq!(
            rt.config.hosted_parties, hosted,
            "the same state after a restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
