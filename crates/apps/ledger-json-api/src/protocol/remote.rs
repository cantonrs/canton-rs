use super::NodeCommitter;
use crate::service::{ExecutionService, RemoteApplied, RemoteCreated};
use canton_participant::node::SharedNode;
use std::sync::Mutex;

impl NodeCommitter {
    pub fn show_remote_transactions_in(&self, service: std::sync::Arc<ExecutionService>) {
        // Hold a Weak reference so `on_remote` never creates a reference cycle preventing `into_node()`.
        let node = std::sync::Arc::downgrade(&self.node);
        let recorder = std::sync::Arc::clone(&self.recorder);
        // the fates of this service's own submissions that came after their wait, or after a restart, on every synchronizer
        for shared in self.all_nodes() {
            let late_service = std::sync::Arc::clone(&service);
            let late_node = std::sync::Arc::downgrade(shared);
            let late_recorder = std::sync::Arc::clone(&recorder);
            shared.on_late(Box::new(move |fate| {
                let applied = fate
                    .transaction
                    .clone()
                    .map(|tx| remote_applied(&late_node, &late_recorder, tx));
                crate::protocol_late::settle(&late_service, fate, applied)
            }));
        }
        // P-13: what the node applied before this service showed it (before a restart, or before this handler was set) is shown first
        let unshown = self.node.take_unshown().unwrap_or_else(|e| {
            crate::diag::diag_eprintln!("the transactions not shown yet could not be read: {e}");
            Vec::new()
        });
        for tx in unshown {
            let request_id = tx.request_id;
            if let Err(e) = service.apply_remote(remote_applied(&node, &recorder, tx)) {
                crate::diag::diag_eprintln!(
                    "a transaction not shown before could not be shown: {e}"
                );
                continue;
            }
            if let Err(e) = self.node.applied_shown(request_id) {
                crate::diag::diag_eprintln!(
                    "transaction {request_id} could not be marked shown: {e}"
                );
            }
        }
        self.node.on_remote(Box::new(move |tx| {
            let applied = remote_applied(&node, &recorder, tx);
            service.apply_remote(applied).map_err(|e| {
                format!("a transaction of another participant could not be shown: {e}")
            })
        }));
    }
}

/// Keeps what `node` applies, and the fates of its awaited submissions, until this service recorded them (P-13, see
/// `canton_participant::node::SharedNode::hold_until_shown`).
pub(super) fn hold_until_shown(node: &SharedNode) {
    if let Err(e) = node.hold_until_shown() {
        crate::diag::diag_eprintln!(
            "the participant does not keep what it applied until shown: {e}"
        );
    }
}

pub(super) fn open_remote_from_instance(
    node_ref: Option<&std::sync::Arc<SharedNode>>,
    bytes: &[u8],
    with_salt_and_blob: bool,
) -> Option<RemoteCreated> {
    if bytes.is_empty() {
        return None;
    }
    let c = node_ref?.open_instance_bytes(bytes)?;
    let salt_32 = if with_salt_and_blob {
        canton_participant::contract_wire::instance_facts(bytes)
            .ok()
            .and_then(|(auth, _)| {
                (auth.len() >= 32)
                    .then(|| auth[auth.len() - 32..].try_into().ok())
                    .flatten()
            })
    } else {
        None
    };
    Some(RemoteCreated {
        observers: c.stakeholders.difference(&c.signatories).cloned().collect(),
        signatories: c.signatories.into_iter().collect(),
        contract_id: c.contract_id,
        package_id: c.package_id,
        template: c.template,
        payload: c.arg,
        created_at_micros: c.created_at_micros,
        salt: salt_32,
        blob: with_salt_and_blob.then(|| bytes.to_vec()),
    })
}

/// A transaction the node read, as the service shows it: with the salts and creation times of what it created, written to the scan history
/// when one is recorded.
pub(super) fn remote_applied(
    node: &std::sync::Weak<SharedNode>,
    recorder: &std::sync::Arc<Mutex<Option<std::sync::Arc<crate::history::UpdateRecorder>>>>,
    tx: canton_participant::node::RemoteTransaction,
) -> RemoteApplied {
    let rec = recorder.lock().ok().and_then(|r| r.clone());
    let node_ref = node.upgrade();
    let created = tx
        .created
        .into_iter()
        .map(|c| {
            let facts = node_ref
                .as_ref()
                .and_then(|n| n.instance_bytes(&c.contract_id))
                .and_then(|bytes| canton_participant::contract_wire::instance_facts(&bytes).ok());
            let salt_32 = facts.as_ref().and_then(|(auth, _)| {
                (auth.len() >= 32)
                    .then(|| auth[auth.len() - 32..].try_into().ok())
                    .flatten()
            });
            if let (Some(ref recorder), Some((ref salt, created_at))) = (&rec, facts) {
                recorder.note_created_at(&c.contract_id, created_at);
                if let Err(e) = recorder.note_authentication(&c.contract_id, salt) {
                    crate::diag::diag_eprintln!(
                        "scan history: the salt of {} not recorded: {e}",
                        c.contract_id
                    );
                }
            }
            RemoteCreated {
                observers: c.stakeholders.difference(&c.signatories).cloned().collect(),
                signatories: c.signatories.into_iter().collect(),
                contract_id: c.contract_id,
                package_id: c.package_id,
                template: c.template,
                payload: c.arg,
                created_at_micros: c.created_at_micros,
                salt: salt_32,
                blob: None,
            }
        })
        .collect();
    let events = tx
        .events
        .into_iter()
        .map(|ev| match ev {
            canton_participant::view_acs::RemoteEvent::Fetch { depth, .. } => {
                crate::service::RemoteTxEvent::Fetch { depth }
            }
            canton_participant::view_acs::RemoteEvent::Create {
                depth,
                contract_id,
                instance,
            } => crate::service::RemoteTxEvent::Create {
                depth,
                contract_id,
                contract: open_remote_from_instance(node_ref.as_ref(), &instance, false)
                    .map(Box::new),
            },
            canton_participant::view_acs::RemoteEvent::Exercise(ex) => {
                crate::service::RemoteTxEvent::Exercise(Box::new(
                    crate::service::RemoteTxExercise {
                        depth: ex.depth,
                        contract_id: ex.contract_id,
                        contract: open_remote_from_instance(
                            node_ref.as_ref(),
                            &ex.input_instance,
                            false,
                        ),
                        choice: ex.choice,
                        consuming: ex.consuming,
                        actors: ex.actors,
                        observers: ex.observers,
                        interface_id: ex.interface_id,
                        argument: ex.argument,
                        result: ex.result,
                    },
                ))
            }
        })
        .collect();
    RemoteApplied {
        request_id: tx.request_id,
        created,
        consumed: tx.consumed,
        root_hash: (!tx.root_hash.is_empty()).then_some(tx.root_hash),
        events,
    }
}
