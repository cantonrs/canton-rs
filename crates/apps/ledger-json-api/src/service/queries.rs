//! Read queries and stream projection endpoints for the Ledger API service.

use super::{
    visible, ActiveContract, ActiveLedgerState, ApiError, CommandCompletion,
    CompletionStreamResponse, ExecutionService, GenericContract, GetActiveContractsResponse,
    LedgerJournal, Ordering, TemplateId, TransactionTree, TreeEvent,
};

impl ExecutionService {
    /// A contract of the generic (DAR-loaded) ledger by id, active or not (S-API-002).
    pub fn v2_contract(&self, id: &str) -> Option<GenericContract> {
        self.generic_contracts.read().ok()?.get(id).cloned()
    }

    /// The active contracts of the generic ledger, ordered by creation sequence then contract id (S-API-002 / S-API-023).
    pub fn v2_active_contracts(&self) -> Vec<GenericContract> {
        let mut all: Vec<GenericContract> = self
            .generic_contracts
            .read()
            .map(|m| m.values().filter(|c| c.active).cloned().collect())
            .unwrap_or_default();
        all.sort_by(|a, b| {
            a.creation_seq
                .cmp(&b.creation_seq)
                .then_with(|| a.contract_id.cmp(&b.contract_id))
        });
        all
    }

    /// The active contracts as of ledger `offset`: the current ones, with what later updates created taken away and what they
    /// archived put back (S-STORE-007; `activeAtOffset` below the end of the ledger).
    pub fn v2_active_contracts_at(&self, offset: u64) -> Vec<GenericContract> {
        let mut set: std::collections::BTreeMap<String, GenericContract> = self
            .v2_active_contracts()
            .into_iter()
            .map(|c| (c.contract_id.clone(), c))
            .collect();
        for update in self.v2.updates().iter().rev().filter(|u| u.offset > offset) {
            for ev in update.events.iter().rev() {
                if ev.created {
                    set.remove(&ev.contract.contract_id);
                } else if ev.exercise.as_ref().is_none_or(|x| x.consuming) {
                    let mut c = ev.contract.clone();
                    c.active = true;
                    set.insert(c.contract_id.clone(), c);
                }
            }
        }
        // [CANTON-NOTE: SEMANTICS] same order as the current set: by creation sequence then contract id
        let mut out: Vec<GenericContract> = set.into_values().collect();
        out.sort_by(|a, b| {
            a.creation_seq
                .cmp(&b.creation_seq)
                .then_with(|| a.contract_id.cmp(&b.contract_id))
        });
        out
    }

    pub fn v2_ledger_end(&self) -> u64 {
        self.v2.ledger_end.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Number of currently active contracts visible to this service.
    pub fn active_contract_count(&self) -> u64 {
        let generic = self
            .generic_contracts
            .read()
            .map(|g| g.values().filter(|c| c.active).count() as u64)
            .unwrap_or(0);
        if generic > 0 {
            return generic;
        }
        self.ledger
            .read()
            .map(|l| l.contracts.iter().filter(|c| c.is_some()).count() as u64)
            .unwrap_or(0)
    }

    /// Retrieve transaction trees from begin_offset to optional end_offset,
    /// optionally filtered by requesting party visibility.
    pub fn get_updates(
        &self,
        begin: u64,
        end: Option<u64>,
        parties: &[String],
    ) -> Vec<TransactionTree> {
        let stream = match self.update_stream.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        stream
            .iter()
            .filter(|tx| {
                if tx.offset < begin {
                    return false;
                }
                if let Some(end_offset) = end {
                    if tx.offset > end_offset {
                        return false;
                    }
                }
                if parties.is_empty() {
                    return true;
                }
                tx.events_by_id.values().any(|ev| match ev {
                    TreeEvent::Created(c) => parties.iter().any(|p| c.witness_parties.contains(p)),
                    TreeEvent::Exercised(e) => {
                        parties.iter().any(|p| e.witness_parties.contains(p))
                    }
                })
            })
            .cloned()
            .collect()
    }

    /// Retrieve command completions for a specific application ID at/after offset.
    pub fn get_completions(&self, app_id: &str, offset: u64) -> CompletionStreamResponse {
        let stream = match self.update_stream.read() {
            Ok(s) => s,
            Err(_) => {
                return CompletionStreamResponse {
                    offset,
                    completions: Vec::new(),
                }
            }
        };

        let mut completions = Vec::new();
        for tx in stream.iter() {
            if tx.offset >= offset {
                completions.push(CommandCompletion {
                    command_id: tx.command_id.clone(),
                    application_id: app_id.to_string(),
                    status_code: 0,
                    offset: tx.offset,
                });
            }
        }

        CompletionStreamResponse {
            offset: self.offset_counter.load(Ordering::SeqCst),
            completions,
        }
    }

    /// Prune stream up to specified offset.
    pub fn prune_stream(&self, up_to_offset: u64) -> Result<u64, ApiError> {
        let mut stream = self
            .update_stream
            .write()
            .map_err(|e| ApiError::Ledger(e.to_string()))?;
        let initial_len = stream.len();
        stream.retain(|tx| tx.offset > up_to_offset);
        let pruned = (initial_len - stream.len()) as u64;
        Ok(pruned)
    }

    /// Get a snapshot clone of the underlying general ActiveLedgerState.
    pub fn active_ledger_state(&self) -> ActiveLedgerState {
        self.active_state
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Get a snapshot clone of the durable LedgerJournal.
    pub fn ledger_journal(&self) -> LedgerJournal {
        self.journal.read().map(|j| j.clone()).unwrap_or_default()
    }

    /// Get active contracts visible to given parties (or all if parties is empty).
    ///
    /// Aggregates active contracts from both generic Daml-LF contracts (`generic_contracts`)
    /// and legacy SingleContractLedger instances, evaluating Daml party visibility against
    /// stakeholders (signatories ∪ observers).
    pub fn get_active_contracts(
        &self,
        parties: &[String],
    ) -> Result<GetActiveContractsResponse, ApiError> {
        let mut active_contracts = Vec::new();

        // 1. Collect from generic contracts created via lf-eval Engine
        if let Ok(g_lock) = self.generic_contracts.read() {
            for contract in g_lock.values() {
                if !contract.active {
                    continue;
                }
                let is_vis = if parties.is_empty() {
                    true
                } else {
                    parties.iter().any(|p| contract.witness_parties.contains(p))
                };

                if is_vis {
                    active_contracts.push(ActiveContract {
                        contract_id: contract.contract_id.clone(),
                        template_id: contract.template_id.clone(),
                        create_arguments: contract.json_payload.clone(),
                        signatories: contract.signatories.clone(),
                        observers: contract.observers.clone(),
                        witness_parties: contract.witness_parties.clone(),
                    });
                }
            }
        }

        // [CANTON-NOTE: INVARIANT] If any DAR is loaded, generic_contracts is the sole source of truth for active contracts.
        // [CANTON-NOTE: SEMANTICS] In Daml-LF semantics, loaded packages govern the active contract set (ACS).
        // Contracts promoted from SingleContractLedger are managed exclusively by generic_contracts.
        // [CANTON-NOTE: WHY] Consulting SingleContractLedger when generic_contracts has already tracked or consumed
        // a contract causes "ghost contract resurrection", where an archived contract resurfaces as active.
        // [CANTON-NOTE: LIMITATION] SingleContractLedger is only consulted when no DAR package has been loaded.
        let dar_loaded = self
            .lf_packages
            .read()
            .map(|pkgs| !pkgs.is_empty())
            .unwrap_or(false);

        if !dar_loaded {
            // 2. Collect from legacy SingleContractLedger fixtures
            let ledger = self
                .ledger
                .read()
                .map_err(|e| ApiError::Ledger(e.to_string()))?;

            let all_active = ledger.active_contracts(None);
            let g_lock = self.generic_contracts.read().ok();

            for (cid, holding) in all_active {
                let cid_str = Self::format_contract_id(cid);
                // If generic_contracts has ever tracked this contract (whether active or inactive/consumed),
                // DO NOT add it from SingleContractLedger.
                if let Some(ref gl) = g_lock {
                    if gl.contains_key(&cid_str) {
                        continue;
                    }
                }
                if active_contracts.iter().any(|c| c.contract_id == cid_str) {
                    continue;
                }

                // Check visibility
                let is_vis = if parties.is_empty() {
                    true
                } else {
                    parties.iter().any(|p| visible(&holding, p.as_str()))
                };

                if is_vis {
                    active_contracts.push(ActiveContract {
                        contract_id: cid_str,
                        template_id: TemplateId::asset_holding(),
                        create_arguments: Self::holding_to_value(&holding),
                        signatories: vec![holding.bank.clone(), holding.owner.clone()],
                        observers: vec![holding.auditor.clone()],
                        witness_parties: vec![holding.bank, holding.owner, holding.auditor],
                    });
                }
            }
        }

        Ok(GetActiveContractsResponse {
            offset: self.offset_counter.load(Ordering::SeqCst),
            workflow_id: None,
            active_contracts,
        })
    }
}
