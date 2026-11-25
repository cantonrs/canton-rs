//! Checkpoint snapshot serialization & restoration for `ExecutionService` and `V2State` (`U-16`, `S-STORE-019`).
//!
//! Uses **exhaustive struct destructuring** on both [`ExecutionService`] and [`V2State`] so adding any new persistent
//! field without handling it in checkpoints is a compile error rather than silent drift across restarts.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use canton_algo::signing::PublicKey;
use lf_eval::journal::{JournalEntry, LedgerJournal};
use lf_eval::ledger::{Holding, SingleContractLedger};
use lf_eval::tx_model::{ActiveContract as TxActiveContract, ActiveLedgerState, ContractId};

use crate::ledger_v2::{DedupEntry, DeduplicationStore};
use crate::service::{ExecutionService, LfPackage};
use crate::v2_commands::{Ev, ExInfo, StoredUpdate};
use crate::v2_completions::Completion;
use crate::v2_interactive::ExternalPartyInfo;

mod repr;
mod v2_state;

pub(crate) use repr::StoredUpdateRepr;

use repr::{
    ActiveStateRepr, CompletionRepr, DedupEntryRepr, EvRepr, ExInfoRepr, ExecutionCheckpointRepr,
    GenericContractRepr, HoldingRepr, JournalEntryRepr, LedgerJournalRepr, ReassignmentRepr,
    SingleContractLedgerRepr, TxActiveContractRepr, ValueRepr,
};
use v2_state::{decode_lf_tree, encode_lf_tree, encode_v2_state, restore_v2_state};

struct ExternalPartyReprInto {
    party_id: String,
    fingerprint: String,
    keys: Vec<PublicKey>,
    threshold: u32,
    synchronizer_id: String,
}

impl ExternalPartyReprInto {
    fn into_info(self) -> ExternalPartyInfo {
        ExternalPartyInfo {
            party_id: self.party_id,
            fingerprint: self.fingerprint,
            keys: self.keys,
            threshold: self.threshold,
            synchronizer_id: self.synchronizer_id,
        }
    }
}

/// Serializes the full state of `service` into a checkpoint blob (`ExecutionCheckpointRepr`).
/// One update as the snapshot and the update journal of a protocol-mode participant keep it.
pub(crate) fn encode_update(u: &StoredUpdate) -> Result<StoredUpdateRepr, String> {
    let StoredUpdate {
        update_id,
        offset,
        command_id,
        effective_at,
        events,
        at_micros,
        external_transaction_hash,
        reassignment,
        topology,
        official: _,
        trace_parent,
        act_as,
    } = u;
    let evs = events
        .iter()
        .map(|ev| {
            let Ev {
                contract,
                created,
                node,
                exercise,
            } = ev;
            let ex = exercise
                .as_ref()
                .map(|ex| {
                    let ExInfo {
                        choice,
                        argument,
                        argument_value,
                        acting,
                        consuming,
                        result,
                        result_value,
                        last_descendant,
                        interface_id,
                        choice_observers,
                    } = ex;
                    Ok::<_, String>(ExInfoRepr {
                        choice: choice.clone(),
                        argument: argument.clone(),
                        argument_value: argument_value
                            .as_ref()
                            .map(ValueRepr::from_value)
                            .transpose()?,
                        acting: acting.clone(),
                        consuming: *consuming,
                        result: result.clone(),
                        result_value: result_value
                            .as_ref()
                            .map(ValueRepr::from_value)
                            .transpose()?,
                        last_descendant: *last_descendant,
                        interface_id: interface_id.clone(),
                        choice_observers: choice_observers.clone(),
                    })
                })
                .transpose()?;
            Ok(EvRepr {
                contract: GenericContractRepr::from_contract(contract)?,
                created: *created,
                node: *node,
                exercise: ex,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(StoredUpdateRepr {
        update_id: update_id.clone(),
        offset: *offset,
        command_id: command_id.clone(),
        effective_at: effective_at.clone(),
        events: evs,
        at_micros: *at_micros,
        external_transaction_hash: external_transaction_hash.clone(),
        reassignment: reassignment.as_deref().map(ReassignmentRepr::from_stored),
        topology: topology.as_deref().cloned(),
        trace_parent: trace_parent.clone(),
        act_as: act_as.clone(),
    })
}

/// The update `encode_update` made.
pub(crate) fn decode_update(u: StoredUpdateRepr) -> Result<StoredUpdate, String> {
    let evs = u
        .events
        .into_iter()
        .map(|ev| {
            let ex = ev
                .exercise
                .map(|ex| {
                    Ok::<_, String>(ExInfo {
                        choice: ex.choice,
                        argument: ex.argument,
                        argument_value: ex.argument_value.map(ValueRepr::into_value).transpose()?,
                        acting: ex.acting,
                        consuming: ex.consuming,
                        result: ex.result,
                        result_value: ex.result_value.map(ValueRepr::into_value).transpose()?,
                        last_descendant: ex.last_descendant,
                        interface_id: ex.interface_id,
                        choice_observers: ex.choice_observers,
                    })
                })
                .transpose()?;
            Ok(Ev {
                contract: ev.contract.into_contract()?,
                created: ev.created,
                node: ev.node,
                exercise: ex,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(StoredUpdate {
        update_id: u.update_id,
        offset: u.offset,
        command_id: u.command_id,
        effective_at: u.effective_at,
        events: evs,
        at_micros: u.at_micros,
        external_transaction_hash: u.external_transaction_hash,
        reassignment: u.reassignment.map(|r| Box::new(r.into_stored())),
        topology: u.topology.map(Box::new),
        official: None,
        trace_parent: u.trace_parent,
        act_as: u.act_as,
    })
}

/// An update as one line of the update journal (JSON, no line break).
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "used by the protocol-mode committer")
)]
pub(crate) fn update_line(u: &StoredUpdate) -> Result<String, String> {
    serde_json::to_string(&encode_update(u)?).map_err(|e| e.to_string())
}

/// A completion as one line of the completion journal.
pub(crate) fn completion_line(c: &Completion) -> Result<String, String> {
    serde_json::to_string(&CompletionRepr {
        offset: c.offset,
        update_id: c.update_id.clone(),
        command_id: c.command_id.clone(),
        user_id: c.user_id.clone(),
        submission_id: c.submission_id.clone(),
        act_as: c.act_as.clone(),
        record_time: c.record_time.clone(),
        transaction_hash: c.transaction_hash.clone(),
        status_code: c.status_code,
        status_message: c.status_message.clone(),
        refusal: c.refusal.clone(),
        trace_parent: c.trace_parent.clone(),
    })
    .map_err(|e| e.to_string())
}

/// The completion one line of the completion journal holds.
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "used by the protocol-mode committer")
)]
pub(crate) fn completion_from_line(line: &str) -> Result<Completion, String> {
    let c: CompletionRepr = serde_json::from_str(line).map_err(|e| e.to_string())?;
    Ok(Completion {
        offset: c.offset,
        update_id: c.update_id,
        command_id: c.command_id,
        user_id: c.user_id,
        submission_id: c.submission_id,
        act_as: c.act_as,
        record_time: c.record_time,
        transaction_hash: c.transaction_hash,
        status_code: c.status_code,
        status_message: c.status_message,
        refusal: c.refusal,
        official: None,
        trace_parent: c.trace_parent,
    })
}

/// A deduplication entry (the change id, the completion offset, when it was recorded, the submission id) as one journal line.
pub(crate) fn dedup_line(
    key: &(String, String, Vec<String>),
    (offset, at_micros, submission_id): (u64, i64, &str),
) -> Result<String, String> {
    serde_json::to_string(&(key, offset, at_micros, submission_id)).map_err(|e| e.to_string())
}

/// The entry one line of the deduplication journal holds.
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "used by the protocol-mode committer")
)]
#[allow(
    clippy::type_complexity,
    reason = "protocol or ledger hook signature uses an inline composite type"
)]
pub(crate) fn dedup_from_line(
    line: &str,
) -> Result<((String, String, Vec<String>), (u64, i64, String)), String> {
    let (key, offset, at, submission): ((String, String, Vec<String>), u64, i64, String) =
        serde_json::from_str(line).map_err(|e| e.to_string())?;
    Ok((key, (offset, at, submission)))
}

/// The update one line of the update journal holds.
#[cfg_attr(
    not(feature = "protocol"),
    allow(dead_code, reason = "used by the protocol-mode committer")
)]
pub(crate) fn update_from_line(line: &str) -> Result<StoredUpdate, String> {
    decode_update(serde_json::from_str(line).map_err(|e| e.to_string())?)
}

pub(crate) fn encode_checkpoint(service: &ExecutionService) -> Result<Vec<u8>, String> {
    let ExecutionService {
        ledger,
        active_state,
        journal,
        dedup_store,
        update_stream,
        offset_counter,
        event_counter,
        contract_counter,
        dar_info,
        package_names,
        dar_blobs,
        clock,
        consumed_at,
        lf_packages: _,
        generic_contracts,
        creation_seq_counter,
        v2,
        v2_submit_lock: _,
        auth: _,
        persist: _,
        batch: _,
        persist_failed: _,
        committer: _,
        recorder: _,
        snapshot_every: _,
        traffic_enforcement: _,
        http_list_max_elements_limit: _,
        http_list_wait_time_ms: _,
        observability: _,
        quiesced: _,
        in_flight_writes: _,
    } = service;

    let ledger_guard = ledger.read().map_err(|_| "ledger lock poisoned")?;
    let ledger_repr = SingleContractLedgerRepr {
        contracts: ledger_guard
            .contracts
            .iter()
            .map(|opt| {
                opt.as_ref().map(|h| HoldingRepr {
                    bank: h.bank.clone(),
                    owner: h.owner.clone(),
                    auditor: h.auditor.clone(),
                    symbol: h.symbol.clone(),
                    tenths: h.tenths,
                })
            })
            .collect(),
        contract_ids: ledger_guard.contract_ids.clone(),
        submission_count: ledger_guard.submission_count,
    };

    let active_guard = active_state
        .read()
        .map_err(|_| "active_state lock poisoned")?;
    let active_repr = ActiveStateRepr {
        active_contracts: active_guard
            .active_contracts
            .iter()
            .map(|(cid, ac)| {
                (
                    cid.0.clone(),
                    TxActiveContractRepr {
                        template_id: ac.template_id.clone(),
                        payload: ac.payload.clone(),
                        stakeholders: ac.stakeholders.iter().cloned().collect(),
                        key: ac.key.clone(),
                    },
                )
            })
            .collect(),
        keys: active_guard
            .keys
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect(),
    };

    let journal_guard = journal.read().map_err(|_| "journal lock poisoned")?;
    let journal_repr = LedgerJournalRepr {
        entries: journal_guard
            .entries()
            .iter()
            .map(|e| JournalEntryRepr {
                offset: e.offset,
                tx: encode_lf_tree(&e.tx),
                act_as: e.act_as.iter().cloned().collect(),
                timestamp_micros: e.timestamp_micros,
            })
            .collect(),
        next_offset: journal_guard.next_offset(),
    };

    let dedup_guard = dedup_store
        .read()
        .map_err(|_| "dedup_store lock poisoned")?;
    let dedup_repr = dedup_guard
        .entries()
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                DedupEntryRepr {
                    submission_time: v.submission_time,
                    expiry_time: v.expiry_time,
                    offset: v.offset,
                },
            )
        })
        .collect();

    let generic_guard = generic_contracts
        .read()
        .map_err(|_| "generic_contracts lock poisoned")?;
    let mut encoded_contracts = HashMap::with_capacity(generic_guard.len());
    for (k, c) in generic_guard.iter() {
        encoded_contracts.insert(k.clone(), GenericContractRepr::from_contract(c)?);
    }

    let checkpoint = ExecutionCheckpointRepr {
        format_version: 1,
        ledger: ledger_repr,
        active_state: active_repr,
        journal: journal_repr,
        dedup_store: dedup_repr,
        update_stream: update_stream
            .read()
            .map_err(|_| "update_stream lock poisoned")?
            .clone(),
        offset_counter: offset_counter.load(Ordering::SeqCst),
        event_counter: event_counter.load(Ordering::SeqCst),
        contract_counter: contract_counter.load(Ordering::SeqCst),
        dar_info: dar_info
            .read()
            .map_err(|_| "dar_info lock poisoned")?
            .clone(),
        package_names: package_names
            .read()
            .map_err(|_| "package_names lock poisoned")?
            .clone(),
        dar_blobs: dar_blobs
            .read()
            .map_err(|_| "dar_blobs lock poisoned")?
            .clone(),
        clock: clock.load(Ordering::SeqCst),
        consumed_at: consumed_at
            .read()
            .map_err(|_| "consumed_at lock poisoned")?
            .clone(),
        generic_contracts: encoded_contracts,
        creation_seq_counter: creation_seq_counter.load(Ordering::SeqCst),
        v2: encode_v2_state(v2)?,
    };

    serde_json::to_vec(&checkpoint).map_err(|e| format!("encode checkpoint: {e}"))
}

fn load_lf_package_from_blob(bytes: &[u8]) -> Result<Arc<LfPackage>, String> {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!(
        "canton-rs-snap-dar-{}-{}.dar",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, bytes).map_err(|e| format!("write temp dar for snapshot: {e}"))?;
    let res = (|| {
        let archive = lf_archive::parse_dar_file(&path)
            .map_err(|e| format!("parse dar from snapshot: {e}"))?;
        let world = lf_eval::World::open(&path)
            .map_err(|e| format!("open dar world from snapshot: {e}"))?;
        Ok(Arc::new(LfPackage {
            main_package_id: archive.main_package_id,
            world,
            surfaces: archive.module_surfaces,
        }))
    })();
    let _ = std::fs::remove_file(&path);
    res
}

/// Restores `service` from a serialized checkpoint blob.
pub(crate) fn restore_checkpoint(service: &ExecutionService, bytes: &[u8]) -> Result<(), String> {
    let checkpoint: ExecutionCheckpointRepr =
        serde_json::from_slice(bytes).map_err(|e| format!("decode checkpoint: {e}"))?;
    if checkpoint.format_version != 1 {
        return Err(format!(
            "unsupported checkpoint format version {}",
            checkpoint.format_version
        ));
    }

    let mut rebuilt_packages: Vec<Arc<LfPackage>> = Vec::with_capacity(checkpoint.dar_blobs.len());
    for blob in &checkpoint.dar_blobs {
        let pkg = load_lf_package_from_blob(blob)?;
        if let Some(pos) = rebuilt_packages
            .iter()
            .position(|p| p.main_package_id == pkg.main_package_id)
        {
            rebuilt_packages[pos] = pkg;
        } else {
            rebuilt_packages.push(pkg);
        }
    }

    let mut decoded_generic = HashMap::with_capacity(checkpoint.generic_contracts.len());
    for (k, c) in checkpoint.generic_contracts {
        decoded_generic.insert(k, c.into_contract()?);
    }

    let ExecutionService {
        ledger,
        active_state,
        journal,
        dedup_store,
        update_stream,
        offset_counter,
        event_counter,
        contract_counter,
        dar_info,
        package_names,
        dar_blobs,
        clock,
        consumed_at,
        lf_packages,
        generic_contracts,
        creation_seq_counter,
        v2,
        v2_submit_lock: _,
        auth: _,
        persist: _,
        batch: _,
        persist_failed: _,
        committer: _,
        recorder: _,
        snapshot_every: _,
        traffic_enforcement: _,
        http_list_max_elements_limit: _,
        http_list_wait_time_ms: _,
        observability: _,
        quiesced: _,
        in_flight_writes: _,
    } = service;

    let restored_ledger = SingleContractLedger {
        contracts: checkpoint
            .ledger
            .contracts
            .into_iter()
            .map(|opt| {
                opt.map(|h| Holding {
                    bank: h.bank,
                    owner: h.owner,
                    auditor: h.auditor,
                    symbol: h.symbol,
                    tenths: h.tenths,
                })
            })
            .collect(),
        contract_ids: checkpoint.ledger.contract_ids,
        submission_count: checkpoint.ledger.submission_count,
    };

    let mut restored_active = ActiveLedgerState::new();
    restored_active.active_contracts = checkpoint
        .active_state
        .active_contracts
        .into_iter()
        .map(|(cid, ac)| {
            (
                ContractId(cid),
                TxActiveContract {
                    template_id: ac.template_id,
                    payload: ac.payload,
                    stakeholders: ac.stakeholders.into_iter().collect(),
                    key: ac.key,
                },
            )
        })
        .collect();
    restored_active.keys = checkpoint
        .active_state
        .keys
        .into_iter()
        .map(|(k, v)| (k, ContractId(v)))
        .collect();

    let restored_journal = LedgerJournal::from_entries(
        checkpoint
            .journal
            .entries
            .into_iter()
            .map(|e| JournalEntry {
                offset: e.offset,
                tx: decode_lf_tree(e.tx),
                act_as: e.act_as.into_iter().collect::<HashSet<_>>(),
                timestamp_micros: e.timestamp_micros,
            })
            .collect(),
        checkpoint.journal.next_offset,
    );

    let restored_dedup = DeduplicationStore::from_entries(
        checkpoint
            .dedup_store
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    DedupEntry {
                        submission_time: v.submission_time,
                        expiry_time: v.expiry_time,
                        offset: v.offset,
                    },
                )
            })
            .collect(),
    );

    restore_v2_state(v2, checkpoint.v2)?;

    *ledger.write().map_err(|_| "ledger lock poisoned")? = restored_ledger;
    *active_state
        .write()
        .map_err(|_| "active_state lock poisoned")? = restored_active;
    *journal.write().map_err(|_| "journal lock poisoned")? = restored_journal;
    *dedup_store
        .write()
        .map_err(|_| "dedup_store lock poisoned")? = restored_dedup;
    *update_stream
        .write()
        .map_err(|_| "update_stream lock poisoned")? = checkpoint.update_stream;
    offset_counter.store(checkpoint.offset_counter, Ordering::SeqCst);
    event_counter.store(checkpoint.event_counter, Ordering::SeqCst);
    contract_counter.store(checkpoint.contract_counter, Ordering::SeqCst);
    *dar_info.write().map_err(|_| "dar_info lock poisoned")? = checkpoint.dar_info;
    *package_names
        .write()
        .map_err(|_| "package_names lock poisoned")? = checkpoint.package_names;
    *dar_blobs.write().map_err(|_| "dar_blobs lock poisoned")? = checkpoint.dar_blobs.clone();
    if let Ok(mut dars) = v2.loaded_dars.lock() {
        dars.clear();
        for blob in &checkpoint.dar_blobs {
            if let Ok(loaded) = lf_archive::parse_loaded_dar(std::io::Cursor::new(blob)) {
                let archive = loaded.archive;
                let mut package_ids = vec![archive.main_package_id.clone()];
                for d in &archive.dalfs {
                    if !package_ids.contains(&d.package_id) {
                        package_ids.push(d.package_id.clone());
                    }
                }
                dars.push(crate::v2::LoadedDarEntry {
                    main_package_id: archive.main_package_id,
                    name: archive.package_name.unwrap_or_default(),
                    version: archive.package_version.unwrap_or_default(),
                    description: String::new(),
                    bytes: blob.clone(),
                    package_ids,
                });
            }
        }
        v2.dar_ever_loaded.store(!dars.is_empty(), Ordering::SeqCst);
    }
    clock.store(checkpoint.clock, Ordering::SeqCst);
    *consumed_at
        .write()
        .map_err(|_| "consumed_at lock poisoned")? = checkpoint.consumed_at;
    *lf_packages
        .write()
        .map_err(|_| "lf_packages lock poisoned")? = rebuilt_packages;
    *generic_contracts
        .write()
        .map_err(|_| "generic_contracts lock poisoned")? = decoded_generic;
    creation_seq_counter.store(checkpoint.creation_seq_counter, Ordering::SeqCst);

    Ok(())
}

#[cfg(test)]
mod update_journal_tests {
    use super::{update_from_line, update_line};
    use crate::service::ReassignOutcome;
    use crate::v2_commands::StoredUpdate;
    use crate::v2_reassign::StoredReassignment;

    /// A reassignment update is one line of the update journal and comes back as it was (U-44: it has no events, so the transaction fields alone
    /// would not carry it).
    #[test]
    fn a_reassignment_update_survives_one_journal_line() {
        let update = StoredUpdate {
            update_id: "12200000000000000000000000000000000000000000000000000000000000000007"
                .into(),
            offset: 7,
            command_id: "unassign-1".into(),
            effective_at: "2026-11-17T04:00:00.000000Z".into(),
            events: Vec::new(),
            at_micros: 1_794_000_000_000_000,
            external_transaction_hash: None,
            official: None,
            trace_parent: None,
            act_as: Vec::new(),
            reassignment: Some(Box::new(StoredReassignment {
                unassign: true,
                outcome: ReassignOutcome {
                    reassignment_id: "00122001".into(),
                    contract_id: "00ab".into(),
                    source: "syncA::1220aa".into(),
                    target: "syncB::1220bb".into(),
                    counter: 1,
                    record_time_micros: 1_794_000_000_000_001,
                },
                submitter: "alice::1220cc".into(),
                witnesses: vec!["alice::1220cc".into()],
            })),
            topology: None,
        };
        let line = update_line(&update).expect("encodes");
        assert!(!line.contains('\n'), "one line");
        let back = update_from_line(&line).expect("decodes");
        assert_eq!(
            (
                back.update_id.as_str(),
                back.offset,
                back.command_id.as_str()
            ),
            (update.update_id.as_str(), 7, "unassign-1")
        );
        let (a, b) = (
            back.reassignment.expect("a reassignment"),
            update.reassignment.expect("a reassignment"),
        );
        assert_eq!(
            (
                a.unassign,
                a.outcome.reassignment_id,
                a.outcome.target,
                a.outcome.counter,
                a.outcome.record_time_micros,
                a.submitter,
                a.witnesses
            ),
            (
                b.unassign,
                b.outcome.reassignment_id,
                b.outcome.target,
                b.outcome.counter,
                b.outcome.record_time_micros,
                b.submitter,
                b.witnesses
            )
        );
    }
}
