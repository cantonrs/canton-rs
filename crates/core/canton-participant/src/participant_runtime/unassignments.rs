use super::{Runtime, STORED_UNASSIGNMENTS_JOURNAL};
use crate::reassignment_receive::StoredUnassignment;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The approved unassignments of one participant, seen by its runtime on every synchronizer it is connected to (U-60).
///
/// [CANTON-NOTE: SEMANTICS] The official `ReassignmentStore` belongs to the participant, not to a synchronizer connection: every
/// reassigning participant writes the unassignment data in phase 7 of the unassignment on the source synchronizer, whoever submitted it
/// (`UnassignmentProcessingSteps`), and its validation of the assignment on the target synchronizer reads it
/// (`AssignmentValidation.scala:74-105`: without it the participant abstains with `UnassignmentDataNotFound`). A Rust participant has one
/// runtime per synchronizer; they share this so that an unassignment one witnessed is there when the other judges its assignment.
#[derive(Debug, Clone, Default)]
pub struct SharedUnassignments(Arc<Mutex<BTreeMap<String, StoredUnassignment>>>);

impl SharedUnassignments {
    // [CANTON-NOTE: DEFENSIVE] a poisoned lock is recovered: the map holds whole entries only (one insert or remove under the lock)
    fn insert(&self, reassignment_id: String, unassignment: StoredUnassignment) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(reassignment_id, unassignment);
    }

    fn get(&self, reassignment_id: &str) -> Option<StoredUnassignment> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(reassignment_id)
            .cloned()
    }

    fn remove(&self, reassignment_id: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(reassignment_id);
    }
}

impl Runtime {
    /// Makes this runtime one of the runtimes of a participant that share `shared`: what it holds already (kept across a restart) is put
    /// there, and from now on every unassignment it sees approved is.
    pub fn share_unassignments(&mut self, shared: SharedUnassignments) {
        for (reassignment_id, unassignment) in &self.stored_unassignments {
            shared.insert(reassignment_id.clone(), unassignment.clone());
        }
        self.shared_unassignments = Some(shared);
    }

    /// Holds an approved unassignment in memory, here and for the participant's other runtimes.
    pub(super) fn hold_unassignment(
        &mut self,
        reassignment_id: String,
        unassignment: StoredUnassignment,
    ) {
        if let Some(shared) = &self.shared_unassignments {
            shared.insert(reassignment_id.clone(), unassignment.clone());
        }
        self.stored_unassignments
            .insert(reassignment_id, unassignment);
    }

    /// The approved unassignment `reassignment_id` as this participant knows it: from this runtime, or from the one on the source
    /// synchronizer.
    pub(super) fn known_unassignment(&self, reassignment_id: &str) -> Option<StoredUnassignment> {
        self.stored_unassignments
            .get(reassignment_id)
            .cloned()
            .or_else(|| self.shared_unassignments.as_ref()?.get(reassignment_id))
    }

    /// Records an approved unassignment (for example transferred from a source synchronizer runtime) so a matching assignment is cross-checked (`P-14`).
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

    /// Removes a stored approved unassignment record durably from both store and memory.
    pub fn forget_stored_unassignment(&mut self, reassignment_id: &str) -> Result<(), String> {
        if let Some(shared) = &self.shared_unassignments {
            shared.remove(reassignment_id);
        }
        if self.stored_unassignments.remove(reassignment_id).is_some() {
            if let Some(store) = &self.store {
                store.append(
                    STORED_UNASSIGNMENTS_JOURNAL,
                    &format!("-\t{reassignment_id}"),
                )?;
            }
        }
        Ok(())
    }

    /// Returns the stored summary of an approved unassignment by `reassignment_id`, if held by this runtime.
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

#[allow(
    clippy::type_complexity,
    reason = "pair of runtime maps returned cleanly to Runtime::open_in"
)]
pub(super) fn open_stored_unassignments(
    store: &dyn crate::state_store::StateStore,
) -> Result<
    (
        std::collections::BTreeMap<i64, (String, crate::reassignment_receive::StoredUnassignment)>,
        std::collections::BTreeMap<String, crate::reassignment_receive::StoredUnassignment>,
    ),
    String,
> {
    let journal = store
        .read(STORED_UNASSIGNMENTS_JOURNAL)?
        .unwrap_or_default();
    let recorded = journal.lines().count();
    let mut pending: std::collections::BTreeMap<
        i64,
        (String, crate::reassignment_receive::StoredUnassignment),
    > = std::collections::BTreeMap::new();
    let mut stored: std::collections::BTreeMap<
        String,
        crate::reassignment_receive::StoredUnassignment,
    > = std::collections::BTreeMap::new();
    for line in journal.lines() {
        let mut parts = line.splitn(4, '\t');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("P"), Some(req), Some(rid), Some(json)) => {
                if let (Ok(req), Ok(u)) = (
                    req.parse::<i64>(),
                    serde_json::from_str::<crate::reassignment_receive::StoredUnassignment>(json),
                ) {
                    pending.insert(req, (rid.to_string(), u));
                }
            }
            (Some("A"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    if let Some((rid, u)) = pending.remove(&req) {
                        stored.insert(rid, u);
                    }
                }
            }
            (Some("R"), Some(req), None, None) => {
                if let Ok(req) = req.parse::<i64>() {
                    pending.remove(&req);
                }
            }
            (Some("+"), Some(rid), Some(json), None) => {
                if let Ok(u) =
                    serde_json::from_str::<crate::reassignment_receive::StoredUnassignment>(json)
                {
                    stored.insert(rid.to_string(), u);
                }
            }
            (Some("-"), Some(rid), None, None) => {
                stored.remove(rid);
            }
            _ => {}
        }
    }
    if pending.len() + stored.len() < recorded {
        let mut kept = String::new();
        for (req, (rid, u)) in &pending {
            if let Ok(json) = serde_json::to_string(u) {
                kept.push_str(&format!("P\t{req}\t{rid}\t{json}\n"));
            }
        }
        for (rid, u) in &stored {
            if let Ok(line) = encode_stored_unassignment_add(rid, u) {
                kept.push_str(&line);
                kept.push('\n');
            }
        }
        store.write(STORED_UNASSIGNMENTS_JOURNAL, &kept)?;
    }
    Ok((pending, stored))
}
