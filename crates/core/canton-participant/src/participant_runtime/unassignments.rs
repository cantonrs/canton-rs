use super::{Runtime, STORED_UNASSIGNMENTS_JOURNAL};
use crate::reassignment_receive::StoredUnassignment;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};

/// State of a reassignment id within a target synchronizer's partition of the participant's reassignment store (U-60 C1/C3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReassignmentEntry {
    /// Unassignment approved on the source synchronizer targeting this synchronizer; awaiting assignment completion.
    Unassigned(StoredUnassignment),
    /// Assignment completed on this target synchronizer; any replay must be rejected with `AssignmentCompleted`.
    Completed,
}

/// The approved unassignments and completed assignments of one participant, partitioned by target logical synchronizer id (U-60 C1/C3).
///
/// [CANTON-NOTE: SEMANTICS] The official `ReassignmentStore` belongs to the participant and is partitioned per target logical synchronizer
/// (`ReassignmentCoordination.scala:294-307`, `reassignmentStoreFor(targetPsid.map(_.logical))`): every reassigning participant writes the
/// unassignment data in phase 7 of the unassignment on the source synchronizer (`UnassignmentProcessingSteps`), its validation of the
/// assignment on the target synchronizer looks it up in that target's partition (`AssignmentValidation.scala:74-105`), and phase 7 of an
/// approved assignment marks the id completed so replays are rejected with `AssignmentCompleted`.
#[derive(Debug, Clone, Default)]
pub struct SharedUnassignments(Arc<Mutex<BTreeMap<(String, String), ReassignmentEntry>>>);

impl SharedUnassignments {
    // [CANTON-NOTE: DEFENSIVE] a poisoned lock is recovered: the map holds whole entries only (one insert or remove under the lock)
    fn insert_unassigned(
        &self,
        target_logical: String,
        reassignment_id: String,
        unassignment: StoredUnassignment,
    ) {
        // [CANTON-NOTE: INVARIANT] Legacy records with empty target_synchronizer never enter the shared map (fail-closed, U-60 C1).
        if target_logical.is_empty() {
            return;
        }
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (target_logical, reassignment_id);
        // [CANTON-NOTE: INVARIANT] `Completed` dominates `Unassigned`: on restart, source and target runtimes may join `SharedUnassignments`
        // in any order, and an already-completed assignment must never revert to `Unassigned`.
        if !matches!(map.get(&key), Some(ReassignmentEntry::Completed)) {
            map.insert(key, ReassignmentEntry::Unassigned(unassignment));
        }
    }

    fn mark_completed(&self, target_logical: String, reassignment_id: String) {
        if target_logical.is_empty() {
            return;
        }
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                (target_logical, reassignment_id),
                ReassignmentEntry::Completed,
            );
    }

    fn get(&self, target_logical: &str, reassignment_id: &str) -> Option<ReassignmentEntry> {
        if target_logical.is_empty() {
            return None;
        }
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(target_logical.to_string(), reassignment_id.to_string()))
            .cloned()
    }

    fn remove_unassigned(&self, target_logical: &str, reassignment_id: &str) {
        if target_logical.is_empty() {
            return;
        }
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (target_logical.to_string(), reassignment_id.to_string());
        if matches!(map.get(&key), Some(ReassignmentEntry::Unassigned(_))) {
            map.remove(&key);
        }
    }
}

#[derive(Default)]
pub(super) struct RestoredReassignments {
    pub(super) pending_unassignments: BTreeMap<i64, (String, StoredUnassignment)>,
    pub(super) stored_unassignments: BTreeMap<String, StoredUnassignment>,
    pub(super) pending_assignments: BTreeMap<i64, String>,
    pub(super) completed_assignments: BTreeSet<String>,
}

impl Runtime {
    fn own_logical_synchronizer(&self) -> String {
        crate::multi_node::logical(&self.config.physical_synchronizer_id)
    }

    /// Makes this runtime one of the runtimes of a participant that share `shared`: what it holds already (kept across a restart) is put
    /// there under each entry's target logical synchronizer, and from now on every unassignment and completed assignment it witnesses is.
    pub fn share_unassignments(&mut self, shared: SharedUnassignments) {
        for (reassignment_id, unassignment) in &self.stored_unassignments {
            if !unassignment.target_synchronizer.is_empty() {
                let target_logical = crate::multi_node::logical(&unassignment.target_synchronizer);
                shared.insert_unassigned(
                    target_logical,
                    reassignment_id.clone(),
                    unassignment.clone(),
                );
            }
        }
        let own_logical = self.own_logical_synchronizer();
        for reassignment_id in &self.completed_assignments {
            shared.mark_completed(own_logical.clone(), reassignment_id.clone());
        }
        self.shared_unassignments = Some(shared);
    }

    /// Holds an approved unassignment in memory, here and in the target synchronizer's partition of the participant's shared store.
    pub(super) fn hold_unassignment(
        &mut self,
        reassignment_id: String,
        unassignment: StoredUnassignment,
    ) {
        if let Some(shared) = &self.shared_unassignments {
            if !unassignment.target_synchronizer.is_empty() {
                let target_logical = crate::multi_node::logical(&unassignment.target_synchronizer);
                shared.insert_unassigned(
                    target_logical,
                    reassignment_id.clone(),
                    unassignment.clone(),
                );
            }
        }
        self.stored_unassignments
            .insert(reassignment_id, unassignment);
    }

    /// Records an in-flight assignment awaiting its Phase 7 verdict so approval marks it completed (U-60 C3).
    pub(super) fn record_pending_assignment(
        &mut self,
        request_time: i64,
        reassignment_id: String,
    ) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.append(
                STORED_UNASSIGNMENTS_JOURNAL,
                &format!("PA\t{request_time}\t{reassignment_id}"),
            )?;
        }
        self.pending_assignments
            .insert(request_time, reassignment_id);
        Ok(())
    }

    /// Marks an assignment completed on this target synchronizer, evicting any stored unassignment payload from memory and persisting
    /// completion across restarts (U-60 C3).
    pub(super) fn complete_assignment(
        &mut self,
        request_time: i64,
        reassignment_id: String,
    ) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.append(STORED_UNASSIGNMENTS_JOURNAL, &format!("CA\t{request_time}"))?;
        }
        self.stored_unassignments.remove(&reassignment_id);
        self.completed_assignments.insert(reassignment_id.clone());
        if let Some(shared) = &self.shared_unassignments {
            shared.mark_completed(self.own_logical_synchronizer(), reassignment_id);
        }
        Ok(())
    }

    /// Target-synchronizer-scoped lookup of `reassignment_id` for this runtime (U-60 C1/C3).
    pub(super) fn lookup_reassignment_entry(
        &self,
        reassignment_id: &str,
    ) -> Option<ReassignmentEntry> {
        let own_logical = self.own_logical_synchronizer();
        if self.completed_assignments.contains(reassignment_id) {
            return Some(ReassignmentEntry::Completed);
        }
        if let Some(shared) = &self.shared_unassignments {
            if matches!(
                shared.get(&own_logical, reassignment_id),
                Some(ReassignmentEntry::Completed)
            ) {
                return Some(ReassignmentEntry::Completed);
            }
        }
        if let Some(u) = self.stored_unassignments.get(reassignment_id) {
            if !u.target_synchronizer.is_empty()
                && crate::multi_node::logical(&u.target_synchronizer) == own_logical
            {
                return Some(ReassignmentEntry::Unassigned(u.clone()));
            }
        }
        self.shared_unassignments
            .as_ref()?
            .get(&own_logical, reassignment_id)
    }

    /// The approved unassignment `reassignment_id` targeting this runtime's synchronizer, if present and not yet completed (U-60 C1/C3/F4).
    pub fn known_unassignment(&self, reassignment_id: &str) -> Option<StoredUnassignment> {
        match self.lookup_reassignment_entry(reassignment_id) {
            Some(ReassignmentEntry::Unassigned(u)) => Some(u),
            Some(ReassignmentEntry::Completed) | None => None,
        }
    }

    /// Returns true if `reassignment_id` has already completed assignment on this runtime's synchronizer (U-60 C3).
    pub fn is_assignment_completed(&self, reassignment_id: &str) -> bool {
        matches!(
            self.lookup_reassignment_entry(reassignment_id),
            Some(ReassignmentEntry::Completed)
        )
    }

    /// Records an approved unassignment (for example in unit tests or explicit transfer) so a matching assignment is cross-checked (`P-14`).
    pub fn remember_unassignment(
        &mut self,
        reassignment_id: String,
        unassignment: crate::reassignment_receive::StoredUnassignment,
    ) -> Result<(), String> {
        if let Some(store) = &self.store {
            let line = encode_stored_unassignment_add(&reassignment_id, &unassignment)?;
            store.append(STORED_UNASSIGNMENTS_JOURNAL, &line)?;
        }
        self.hold_unassignment(reassignment_id, unassignment);
        Ok(())
    }

    /// Removes a stored approved unassignment record durably from both store and memory without clearing completed-assignment markers.
    pub fn forget_stored_unassignment(&mut self, reassignment_id: &str) -> Result<(), String> {
        let removed = self.stored_unassignments.remove(reassignment_id);
        if let Some(shared) = &self.shared_unassignments {
            let target_logical = removed
                .as_ref()
                .filter(|u| !u.target_synchronizer.is_empty())
                .map(|u| crate::multi_node::logical(&u.target_synchronizer))
                .unwrap_or_else(|| self.own_logical_synchronizer());
            shared.remove_unassigned(&target_logical, reassignment_id);
        }
        if removed.is_some() {
            if let Some(store) = &self.store {
                store.append(
                    STORED_UNASSIGNMENTS_JOURNAL,
                    &format!("-\t{reassignment_id}"),
                )?;
            }
        }
        Ok(())
    }

    /// Returns the stored summary of an approved unassignment held directly by this runtime (irrespective of target synchronizer).
    pub fn stored_unassignment(
        &self,
        reassignment_id: &str,
    ) -> Option<&crate::reassignment_receive::StoredUnassignment> {
        self.stored_unassignments.get(reassignment_id)
    }
}

fn encode_stored_unassignment_add(
    reassignment_id: &str,
    unassignment: &crate::reassignment_receive::StoredUnassignment,
) -> Result<String, String> {
    let json = serde_json::to_string(unassignment)
        .map_err(|e| format!("encode stored unassignment: {e}"))?;
    Ok(format!("+\t{reassignment_id}\t{json}"))
}

pub(super) fn open_stored_unassignments(
    store: &dyn crate::state_store::StateStore,
) -> Result<RestoredReassignments, String> {
    let journal = store
        .read(STORED_UNASSIGNMENTS_JOURNAL)?
        .unwrap_or_default();
    let recorded = journal.lines().count();
    let mut restored = RestoredReassignments::default();
    for line in journal.lines() {
        let mut parts = line.splitn(4, '\t');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("P"), Some(req), Some(rid), Some(json)) => {
                if let (Ok(req), Ok(u)) = (
                    req.parse::<i64>(),
                    serde_json::from_str::<crate::reassignment_receive::StoredUnassignment>(json),
                ) {
                    restored
                        .pending_unassignments
                        .insert(req, (rid.to_string(), u));
                }
            }
            (Some("A"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    if let Some((rid, u)) = restored.pending_unassignments.remove(&req) {
                        restored.stored_unassignments.insert(rid, u);
                    }
                }
            }
            (Some("R"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    restored.pending_unassignments.remove(&req);
                }
            }
            (Some("+"), Some(rid), Some(json), None) => {
                if let Ok(u) =
                    serde_json::from_str::<crate::reassignment_receive::StoredUnassignment>(json)
                {
                    restored.stored_unassignments.insert(rid.to_string(), u);
                }
            }
            (Some("-"), Some(rid), None, None) => {
                restored.stored_unassignments.remove(rid);
            }
            (Some("PA"), Some(req), Some(rid), None) => {
                if let Ok(req) = req.parse::<i64>() {
                    restored.pending_assignments.insert(req, rid.to_string());
                }
            }
            (Some("CA"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    if let Some(rid) = restored.pending_assignments.remove(&req) {
                        restored.stored_unassignments.remove(&rid);
                        restored.completed_assignments.insert(rid);
                    }
                }
            }
            (Some("RA"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    restored.pending_assignments.remove(&req);
                }
            }
            (Some("C"), Some(rid), None, None) => {
                restored.stored_unassignments.remove(rid);
                restored.completed_assignments.insert(rid.to_string());
            }
            _ => {}
        }
    }
    let live_count = restored.pending_unassignments.len()
        + restored.stored_unassignments.len()
        + restored.pending_assignments.len()
        + restored.completed_assignments.len();
    if live_count < recorded {
        let mut kept = String::new();
        for (req, (rid, u)) in &restored.pending_unassignments {
            if let Ok(json) = serde_json::to_string(u) {
                kept.push_str(&format!("P\t{req}\t{rid}\t{json}\n"));
            }
        }
        for (rid, u) in &restored.stored_unassignments {
            if let Ok(line) = encode_stored_unassignment_add(rid, u) {
                kept.push_str(&line);
                kept.push('\n');
            }
        }
        for (req, rid) in &restored.pending_assignments {
            kept.push_str(&format!("PA\t{req}\t{rid}\n"));
        }
        for rid in &restored.completed_assignments {
            kept.push_str(&format!("C\t{rid}\n"));
        }
        store.write(STORED_UNASSIGNMENTS_JOURNAL, &kept)?;
    }
    Ok(restored)
}
