//! Repair (P-14): contracts added to or purged from the participant's protocol ledger without a transaction, as the repair service's
//! `ImportAcs` and `PurgeContracts` do.
//!
//! [CANTON-NOTE: SEMANTICS] `RepairService` changes the synchronizer's `ActiveContractStore` (what requests are judged against), not only the
//! Ledger API store, and `ContractAuthenticationImportProcessor` authenticates every imported contract first ("Failed to authenticate contract
//! with id: ..."). The whole batch is checked before anything changes. The ACS commitments take the change in at the cursor's time, so a
//! counter-participant that was not repaired the same way reports a mismatch, as Canton's documentation of `ACS_COMMITMENT_MISMATCH` says.
use super::Runtime;
use std::collections::BTreeSet;

impl Runtime {
    /// Authenticates each `(expected id, serialized instance)` and, when all are authentic and none is known here, adds them to the contract
    /// set. Returns the ids.
    pub fn repair_add(&mut self, contracts: &[(String, Vec<u8>)]) -> Result<Vec<String>, String> {
        let mut checked = Vec::new();
        for (expected, instance) in contracts {
            let (id, template) =
                crate::view_conformance::authenticate_instance(&self.engine, instance).map_err(
                    |e| format!("Failed to authenticate contract with id: {expected}: {e:?}"),
                )?;
            if &id != expected {
                return Err(format!(
                    "Failed to authenticate contract with id: {expected}: the instance is of contract {id}"
                ));
            }
            if self.ledger.is_active(&id) || self.ledger.knows_contract(&id) {
                return Err(format!(
                    "Contract {id} already exists in the contract store"
                ));
            }
            let parties = crate::reassignment_submit::contract_parties(instance)?;
            checked.push((id, template, parties.stakeholders));
        }
        let at = self.cursor;
        for (id, template, stakeholders) in &checked {
            self.ledger
                .import(id, template)
                .map_err(|c| format!("{c:?}"))?;
            let stakeholders: BTreeSet<String> = stakeholders.iter().cloned().collect();
            let local = self.hosted_here(&stakeholders);
            self.commitments.activate(id, at, 0, stakeholders, local)?;
        }
        Ok(checked.into_iter().map(|(id, _, _)| id).collect())
    }

    /// Purges `ids` from the contract set when every one of them is active and not in use by a request in flight; with `ignore_inactive`, the
    /// ones that are not active are passed over.
    pub fn repair_purge(&mut self, ids: &[String], ignore_inactive: bool) -> Result<(), String> {
        let mut purge = Vec::new();
        for id in ids {
            if let Some(request) = self.ledger.locked_by(id) {
                return Err(format!(
                    "Cannot purge contract {id} because the request {request} in flight uses it"
                ));
            }
            if self.ledger.is_active(id) {
                purge.push(id);
            } else if !ignore_inactive {
                return Err(format!(
                    "Cannot purge contract {id} because it is not active"
                ));
            }
        }
        let at = self.cursor;
        for id in purge {
            self.ledger.purge(id).map_err(|c| format!("{c:?}"))?;
            self.commitments.deactivate(id, at)?;
        }
        Ok(())
    }
}
