//! Encoding and restoring the v2 service state and Daml-LF transaction trees.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::Ordering;

use canton_algo::signing::PublicKey;
use lf_eval::tx_model::{ContractId, Node as TxNode, TransactionTree as LfTransactionTree};

use crate::v2::V2State;
use crate::v2_completions::Completion;

use super::repr::{
    decode_key_format, decode_key_spec, decode_usage, encode_key_format, encode_key_spec,
    encode_usage, CompletionRepr, ExternalPartyRepr, LfTxTreeRepr, PublicKeyRepr, TxNodeRepr,
    V2StateRepr,
};
use super::{decode_update, encode_update, ExternalPartyReprInto};

pub(super) fn encode_lf_tree(tree: &LfTransactionTree) -> LfTxTreeRepr {
    let (roots, nodes, next_node_id) = tree.parts();
    LfTxTreeRepr {
        roots: roots.to_vec(),
        nodes: nodes
            .iter()
            .map(|(nid, n)| {
                let repr = match n {
                    TxNode::Create {
                        contract_id,
                        template_id,
                        payload,
                        signatories,
                        observers,
                        key,
                    } => TxNodeRepr::Create {
                        contract_id: contract_id.0.clone(),
                        template_id: template_id.clone(),
                        payload: payload.clone(),
                        signatories: signatories.iter().cloned().collect(),
                        observers: observers.iter().cloned().collect(),
                        key: key.clone(),
                    },
                    TxNode::Exercise {
                        contract_id,
                        choice,
                        acting_parties,
                        consuming,
                        children,
                    } => TxNodeRepr::Exercise {
                        contract_id: contract_id.0.clone(),
                        choice: choice.clone(),
                        acting_parties: acting_parties.iter().cloned().collect(),
                        consuming: *consuming,
                        children: children.clone(),
                    },
                    TxNode::Fetch {
                        contract_id,
                        template_id,
                        stakeholders,
                    } => TxNodeRepr::Fetch {
                        contract_id: contract_id.0.clone(),
                        template_id: template_id.clone(),
                        stakeholders: stakeholders.iter().cloned().collect(),
                    },
                    TxNode::LookupByKey {
                        template_id,
                        key,
                        found,
                    } => TxNodeRepr::LookupByKey {
                        template_id: template_id.clone(),
                        key: key.clone(),
                        found: found.as_ref().map(|c| c.0.clone()),
                    },
                    TxNode::Rollback { children } => TxNodeRepr::Rollback {
                        children: children.clone(),
                    },
                };
                (*nid, repr)
            })
            .collect(),
        next_node_id,
    }
}

pub(super) fn decode_lf_tree(repr: LfTxTreeRepr) -> LfTransactionTree {
    let nodes = repr
        .nodes
        .into_iter()
        .map(|(nid, n)| {
            let node = match n {
                TxNodeRepr::Create {
                    contract_id,
                    template_id,
                    payload,
                    signatories,
                    observers,
                    key,
                } => TxNode::Create {
                    contract_id: ContractId(contract_id),
                    template_id,
                    payload,
                    signatories: signatories.into_iter().collect(),
                    observers: observers.into_iter().collect(),
                    key,
                },
                TxNodeRepr::Exercise {
                    contract_id,
                    choice,
                    acting_parties,
                    consuming,
                    children,
                } => TxNode::Exercise {
                    contract_id: ContractId(contract_id),
                    choice,
                    acting_parties: acting_parties.into_iter().collect(),
                    consuming,
                    children,
                },
                TxNodeRepr::Fetch {
                    contract_id,
                    template_id,
                    stakeholders,
                } => TxNode::Fetch {
                    contract_id: ContractId(contract_id),
                    template_id,
                    stakeholders: stakeholders.into_iter().collect(),
                },
                TxNodeRepr::LookupByKey {
                    template_id,
                    key,
                    found,
                } => TxNode::LookupByKey {
                    template_id,
                    key,
                    found: found.map(ContractId),
                },
                TxNodeRepr::Rollback { children } => TxNode::Rollback { children },
            };
            (nid, node)
        })
        .collect();
    LfTransactionTree::from_parts(repr.roots, nodes, repr.next_node_id)
}

pub(super) fn encode_v2_state(v2: &V2State) -> Result<V2StateRepr, String> {
    let V2State {
        participant,
        parties,
        ledger_end,
        updates,
        packages,
        loaded_dars: _,
        dar_ever_loaded: _,
        party_meta,
        completions,
        dedup,
        // what is in flight belongs to the running requests, not to the ledger state
        in_flight: _,
        vetting_serial,
        idps,
        users,
        submission_seq,
        pruned_up_to,
        max_dedup_micros,
        acs_safe_to_prune_micros,
        external_parties,
        prepared_cache: _,
        synchronizer,
        // [CANTON-NOTE: LIMITATION] reassignment locations are not in the snapshot (S-NET-040)
        reassign: _,
        // the sink is the running service's, not state
        journal_sink: _,
        remote_parties: _,
        official_parties: _,
        party_idp: _,
        known_packages: _,
        created_offsets: _,
        official_checkpoint: _,
        api_parties: _,
        official_admin_sink: _,
        official_dar_sink: _,
        official_topology_sink: _,
        official_update_sink: _,
        official_rejection_sink: _,
        implemented_interfaces_cache: _,
        registered_syncs: _,
        slow_counter_configs: _,
        ignored_events: _,
        pending_repair_ops: _,
        extra_topology_txs: _,
        admin_log_level: _,
        admin_ports: _,
        official_prune_sink: _,
        journal_prune_sink: _,
        traffic: _,
        exex: _,
        commit_publish_lock: _,
    } = v2;

    let encoded_updates = updates
        .lock()
        .map_err(|_| "updates mutex poisoned")?
        .iter()
        .map(encode_update)
        .collect::<Result<Vec<_>, String>>()?;

    let encoded_completions = completions
        .lock()
        .map_err(|_| "completions mutex poisoned")?
        .iter()
        .map(|c| {
            let Completion {
                offset,
                update_id,
                command_id,
                user_id,
                submission_id,
                act_as,
                record_time,
                transaction_hash,
                status_code,
                status_message,
                refusal,
                official: _,
                trace_parent,
            } = c;
            CompletionRepr {
                offset: *offset,
                update_id: update_id.clone(),
                command_id: command_id.clone(),
                user_id: user_id.clone(),
                submission_id: submission_id.clone(),
                act_as: act_as.clone(),
                record_time: record_time.clone(),
                transaction_hash: transaction_hash.clone(),
                status_code: *status_code,
                status_message: status_message.clone(),
                refusal: refusal.clone(),
                trace_parent: trace_parent.clone(),
            }
        })
        .collect();

    let encoded_external = external_parties
        .lock()
        .map_err(|_| "external_parties mutex poisoned")?
        .iter()
        .map(|(k, ep)| {
            let keys = ep
                .keys
                .iter()
                .map(|pk| PublicKeyRepr {
                    key_spec: encode_key_spec(pk.key_spec),
                    format: encode_key_format(pk.format),
                    usage: pk.usage.iter().copied().map(encode_usage).collect(),
                    key: pk.key.clone(),
                    id: pk.id.clone(),
                })
                .collect();
            (
                k.clone(),
                ExternalPartyRepr {
                    party_id: ep.party_id.clone(),
                    fingerprint: ep.fingerprint.clone(),
                    keys,
                    threshold: ep.threshold,
                    synchronizer_id: ep.synchronizer_id.clone(),
                },
            )
        })
        .collect();

    Ok(V2StateRepr {
        participant: participant.read().map(|p| p.clone()).unwrap_or_default(),
        parties: parties.lock().map_err(|_| "parties poisoned")?.clone(),
        ledger_end: ledger_end.load(Ordering::SeqCst),
        updates: encoded_updates,
        packages: packages.lock().map_err(|_| "packages poisoned")?.clone(),
        party_meta: party_meta
            .lock()
            .map_err(|_| "party_meta poisoned")?
            .clone(),
        completions: encoded_completions,
        dedup: dedup
            .lock()
            .map_err(|_| "dedup poisoned")?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        vetting_serial: *vetting_serial
            .lock()
            .map_err(|_| "vetting_serial poisoned")?,
        idps: idps.lock().map_err(|_| "idps poisoned")?.clone(),
        users: users.lock().map_err(|_| "users poisoned")?.clone(),
        submission_seq: submission_seq.load(Ordering::SeqCst),
        pruned_up_to: pruned_up_to.load(Ordering::SeqCst),
        max_dedup_micros: max_dedup_micros.load(Ordering::SeqCst),
        acs_safe_to_prune_micros: *acs_safe_to_prune_micros
            .lock()
            .map_err(|_| "acs_safe_to_prune_micros poisoned")?,
        external_parties: encoded_external,
        synchronizer: synchronizer
            .lock()
            .map_err(|_| "synchronizer poisoned")?
            .clone(),
    })
}

pub(super) fn restore_v2_state(v2: &V2State, repr: V2StateRepr) -> Result<(), String> {
    let V2State {
        participant: _,
        parties,
        ledger_end,
        updates,
        packages,
        loaded_dars: _,
        dar_ever_loaded: _,
        party_meta,
        completions,
        dedup,
        // what is in flight belongs to the running requests, not to the ledger state
        in_flight: _,
        vetting_serial,
        idps,
        users,
        submission_seq,
        pruned_up_to,
        max_dedup_micros,
        acs_safe_to_prune_micros,
        external_parties,
        prepared_cache,
        synchronizer,
        reassign: _,
        // the sink is the running service's, not state
        journal_sink: _,
        remote_parties: _,
        official_parties: _,
        party_idp: _,
        known_packages: _,
        created_offsets: _,
        official_checkpoint: _,
        api_parties: _,
        official_admin_sink: _,
        official_dar_sink: _,
        official_topology_sink: _,
        official_update_sink: _,
        official_rejection_sink: _,
        implemented_interfaces_cache,
        registered_syncs: _,
        slow_counter_configs: _,
        ignored_events: _,
        pending_repair_ops: _,
        extra_topology_txs: _,
        admin_log_level: _,
        admin_ports: _,
        official_prune_sink: _,
        journal_prune_sink: _,
        traffic: _,
        exex: _,
        commit_publish_lock: _,
    } = v2;

    let current_participant = v2.participant_id();
    if repr.participant != current_participant {
        return Err(format!(
            "snapshot participant '{}' differs from service participant '{}'",
            repr.participant, current_participant
        ));
    }

    let decoded_updates = repr
        .updates
        .into_iter()
        .map(decode_update)
        .collect::<Result<Vec<_>, String>>()?;

    let decoded_completions = repr
        .completions
        .into_iter()
        .map(|c| Completion {
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
        .collect();

    let mut decoded_external = HashMap::new();
    for (k, ep) in repr.external_parties {
        let mut keys = Vec::with_capacity(ep.keys.len());
        for pk in ep.keys {
            let mut usage = BTreeSet::new();
            for u in pk.usage {
                usage.insert(decode_usage(u)?);
            }
            keys.push(PublicKey {
                key_spec: decode_key_spec(pk.key_spec)?,
                format: decode_key_format(pk.format)?,
                usage,
                key: pk.key,
                id: pk.id,
            });
        }
        decoded_external.insert(
            k,
            ExternalPartyReprInto {
                party_id: ep.party_id,
                fingerprint: ep.fingerprint,
                keys,
                threshold: ep.threshold,
                synchronizer_id: ep.synchronizer_id,
            }
            .into_info(),
        );
    }

    *parties.lock().map_err(|_| "parties poisoned")? = repr.parties;
    ledger_end.store(repr.ledger_end, Ordering::SeqCst);
    *updates.lock().map_err(|_| "updates poisoned")? = decoded_updates;
    *packages.lock().map_err(|_| "packages poisoned")? = repr.packages;
    *party_meta.lock().map_err(|_| "party_meta poisoned")? = repr.party_meta;
    *completions.lock().map_err(|_| "completions poisoned")? = decoded_completions;
    *dedup.lock().map_err(|_| "dedup poisoned")? = repr.dedup.into_iter().collect();
    *vetting_serial
        .lock()
        .map_err(|_| "vetting_serial poisoned")? = repr.vetting_serial;
    *idps.lock().map_err(|_| "idps poisoned")? = repr.idps;
    *users.lock().map_err(|_| "users poisoned")? = repr.users;
    submission_seq.store(repr.submission_seq, Ordering::SeqCst);
    pruned_up_to.store(repr.pruned_up_to, Ordering::SeqCst);
    max_dedup_micros.store(repr.max_dedup_micros, Ordering::SeqCst);
    *acs_safe_to_prune_micros
        .lock()
        .map_err(|_| "acs_safe_to_prune_micros poisoned")? = repr.acs_safe_to_prune_micros;
    *external_parties
        .lock()
        .map_err(|_| "external_parties poisoned")? = decoded_external;
    prepared_cache
        .lock()
        .map_err(|_| "prepared_cache poisoned")?
        .clear();
    implemented_interfaces_cache
        .lock()
        .map_err(|_| "implemented_interfaces_cache poisoned")?
        .clear();
    *synchronizer.lock().map_err(|_| "synchronizer poisoned")? = repr.synchronizer;
    Ok(())
}
