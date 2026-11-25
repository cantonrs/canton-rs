//! The commands of one submission sent as one transaction of several roots (P-8), and what a commit whose root is an exercise sends.
//!
//! [CANTON-NOTE: SEMANTICS] Canton interprets every command of a submission into one transaction, a root per command (two for a
//! `CreateAndExerciseCommand`), and submits it as one confirmation request: the synchronizer approves or rejects all of them. The ids of the
//! contracts depend on the position of their root view among all roots, so the plans of the request are drawn before the first command runs,
//! from the number of roots the commands make, and every id is promised from its root's plan.
use super::{
    below_root, map_submit_err, refuse, sync_rejected, Below, NodeCommitter, TreeEntry, TreeNode,
};
use crate::service::{ApiError, GenericContract, TransactionCommit};
use canton_participant::node::{
    CreatedByExercise, ExerciseRoot, RootCommand, TransactionCommand, Verdict,
};
use canton_participant::submit::{ExercisePlan, StoredContract};
use lf_eval::engine::NewContract;
use lf_eval::tx_model::Node as TxNode;
use lf_eval::{EngineEvent, Value};

/// A transaction whose ids are being promised: the plans of its root views, and the contracts promised so far in the order of creation.
pub(super) struct Pending {
    plans: Vec<ExercisePlan>,
    created: Vec<StoredContract>,
}

/// What a commit whose root exercises `contract_id` sends below its root, checked against what the transaction archived.
pub(super) struct ExerciseParts {
    pub(super) below: Vec<(usize, Below)>,
    pub(super) templates: Vec<String>,
    pub(super) actors: Vec<String>,
    /// The root choice's own observers, from the root exercise event.
    pub(super) observers: Vec<String>,
    pub(super) argument: Value,
}

pub(super) fn exercise_parts(
    commit: &TransactionCommit,
    contract_id: &str,
    root_consuming: bool,
    actors: Vec<String>,
) -> Result<ExerciseParts, ApiError> {
    let created = &commit.created_contracts;
    let below = below_root(
        &commit.engine_events,
        &commit.engine_rolled_back,
        &commit.engine_key_lookups,
        contract_id,
    )?;
    let below_creates = below
        .iter()
        .filter(|(_, b)| matches!(b, Below::Create(_)))
        .count();
    if below_creates != created.len() {
        return Err(refuse(format!(
            "the contracts created ({}) do not match the creates below the root ({below_creates})",
            created.len()
        )));
    }
    // [CANTON-NOTE: SEMANTICS] A consuming root Exercise consumes `contract_id` via its root node,
    // so `below` only contains child archives; a nonconsuming root Exercise (e.g., CIP-0112 TransferInstruction_Accept)
    // may archive `contract_id` inside a child `consuming: true` Exercise node, which belongs in `below`.
    // Transient contracts created and consumed inside the same exercise (`!c.active`) also appear as
    // consuming child `Below::Exercise` nodes alongside archived pre-existing contracts.
    let archived: std::collections::BTreeSet<&str> = commit
        .archived_cids
        .iter()
        .map(String::as_str)
        .filter(|id| !root_consuming || *id != contract_id)
        .collect();
    let created_ids: std::collections::BTreeSet<&str> =
        created.iter().map(|c| c.contract_id.as_str()).collect();
    if !archived.is_disjoint(&created_ids) {
        return Err(refuse(
            "a newly created contract cannot also be archived as a pre-existing contract",
        ));
    }
    let transient_created: std::collections::BTreeSet<&str> = created
        .iter()
        .filter(|c| !c.active)
        .map(|c| c.contract_id.as_str())
        .collect();
    let expected_consumed: std::collections::BTreeSet<&str> = archived
        .iter()
        .copied()
        .chain(transient_created.iter().copied())
        .collect();
    let consumed: std::collections::BTreeSet<&str> = below
        .iter()
        .filter_map(|(_, b)| match b {
            Below::Exercise {
                contract_id,
                consuming: true,
                ..
            } => Some(contract_id.as_str()),
            _ => None,
        })
        .collect();
    if expected_consumed != consumed {
        return Err(refuse(format!(
            "the contracts archived ({expected_consumed:?}) are not the ones the subtree consumes ({consumed:?})"
        )));
    }
    let templates = created.iter().map(qualified_template).collect();
    let observers = match commit.engine_events.first() {
        Some(lf_eval::engine::EngineEvent::Exercise { observers, .. }) => observers.clone(),
        _ => Vec::new(),
    };
    Ok(ExerciseParts {
        below,
        templates,
        actors,
        observers,
        argument: commit.root_argument.clone().unwrap_or(Value::Record {
            tycon: None,
            fields: vec![],
        }),
    })
}

/// `<package id>:<module>:<entity>` (`<module>:<entity>` for a contract without a package id).
pub(super) fn qualified_template(c: &GenericContract) -> String {
    if c.package_id.len() == 64 {
        format!(
            "{}:{}:{}",
            c.package_id, c.template_id.module_name, c.template_id.entity_name
        )
    } else {
        format!(
            "{}:{}",
            c.template_id.module_name, c.template_id.entity_name
        )
    }
}

/// The nodes below the root of `parts`, as the participant builds them.
pub(super) fn tree_entries<'a>(
    parts: &'a ExerciseParts,
    created: &'a [GenericContract],
) -> Vec<TreeEntry<'a>> {
    parts
        .below
        .iter()
        .map(|(depth, b)| TreeEntry {
            depth: *depth,
            node: match b {
                Below::Exercise {
                    contract_id,
                    choice,
                    argument,
                    consuming,
                    actors,
                    observers,
                    interface_id,
                    by_key,
                } => TreeNode::Exercise {
                    contract_id,
                    choice,
                    argument: argument.as_ref(),
                    consuming: *consuming,
                    actors: actors.clone(),
                    observers: observers.clone(),
                    interface_id: interface_id.as_deref(),
                    by_key: *by_key,
                },
                Below::Fetch {
                    contract_id,
                    actors,
                    by_key,
                } => TreeNode::Fetch {
                    contract_id,
                    actors: actors.clone(),
                    interface_id: None,
                    by_key: *by_key,
                },
                Below::Lookup {
                    template,
                    key,
                    contract_ids,
                } => TreeNode::Lookup {
                    template,
                    key,
                    contract_ids: contract_ids.iter().map(String::as_str).collect(),
                },
                Below::Rollback => TreeNode::Rollback,
                Below::Create(i) => TreeNode::Create(CreatedByExercise {
                    template: &parts.templates[*i],
                    payload: &created[*i].payload_value,
                    expected_id: &created[*i].contract_id,
                }),
            },
        })
        .collect()
}

/// The interface the root exercise of `commit` goes through.
pub(super) fn root_interface_id(commit: &TransactionCommit) -> Option<&str> {
    match commit.engine_events.first() {
        Some(EngineEvent::Exercise { interface_id, .. }) => interface_id.as_deref(),
        _ => None,
    }
}

/// What one commit of a transaction of several roots sends at its root.
enum RootParts {
    Create {
        template: String,
    },
    Exercise {
        contract_id: String,
        choice: String,
        parts: Box<ExerciseParts>,
    },
}

impl NodeCommitter {
    pub(super) fn begin(&self, roots: usize) -> Result<u64, ApiError> {
        let plans = self.node.with(|n| n.plan_roots(roots)).map_err(refuse)?;
        let plans = plans.map_err(refuse)?;
        let id = self
            .sessions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.transactions.lock().map_err(refuse)?.insert(
            id,
            Pending {
                plans,
                created: Vec::new(),
            },
        );
        Ok(id)
    }

    pub(super) fn allocate_in(
        &self,
        transaction: u64,
        root: usize,
        new: &NewContract<'_>,
    ) -> Option<String> {
        let mut transactions = self.transactions.lock().ok()?;
        let pending = transactions.get_mut(&transaction)?;
        let plan = pending.plans.get(root)?;
        let qualified = if new.package_id.len() == 64 {
            format!("{}:{}", new.package_id, new.template_id)
        } else {
            new.template_id.to_string()
        };
        let path: Vec<i32> = new.path.iter().map(|i| *i as i32).collect();
        let below = (new.depth > 0).then_some((new.creation_index, path.as_slice()));
        let stored = self
            .node
            .with(|n| n.promise_in_root(&self.package_name, plan, below, &qualified, new.payload))
            .ok()?
            .ok()?;
        let id = stored.contract_id_hex.clone();
        pending.created.push(stored);
        Some(id)
    }

    /// The instance of a contract promised to a transaction not committed yet.
    pub(super) fn pending_instance(&self, contract_id: &str) -> Option<Vec<u8>> {
        self.transactions.lock().ok()?.values().find_map(|p| {
            p.created
                .iter()
                .find(|c| c.contract_id_hex == contract_id)
                .map(|c| c.instance.clone())
        })
    }

    pub(super) fn abort(&self, transaction: u64) {
        if let Ok(mut transactions) = self.transactions.lock() {
            transactions.remove(&transaction);
        }
    }

    /// Sends the commits of a transaction, one per root in order, as one request and waits for its verdict.
    pub(super) fn commit_roots(
        &self,
        transaction: u64,
        commits: &[TransactionCommit],
    ) -> Result<(), ApiError> {
        let pending = self
            .transactions
            .lock()
            .map_err(refuse)?
            .remove(&transaction)
            .ok_or_else(|| refuse("the plans of this transaction are gone"))?;
        if pending.plans.len() != commits.len() {
            return Err(refuse(format!(
                "a transaction planned with {} roots has {}",
                pending.plans.len(),
                commits.len()
            )));
        }
        let mut parts = Vec::with_capacity(commits.len());
        for commit in commits {
            let (roots, nodes, _) = commit.lf_tree.parts();
            let [root] = roots else {
                return Err(refuse(format!(
                    "a command with {} roots is not supported",
                    roots.len()
                )));
            };
            parts.push(match nodes.get(root) {
                Some(TxNode::Create { .. }) => {
                    let [created] = commit.created_contracts.as_slice() else {
                        return Err(refuse("a create command creates one contract"));
                    };
                    RootParts::Create {
                        template: qualified_template(created),
                    }
                }
                Some(TxNode::Exercise {
                    contract_id,
                    choice,
                    acting_parties,
                    consuming,
                    ..
                }) => {
                    if !self.others.is_empty()
                        && !std::sync::Arc::ptr_eq(self.node_holding(&contract_id.0), &self.node)
                    {
                        return Err(refuse(
                            "a transaction of several commands on another synchronizer than the first is not supported",
                        ));
                    }
                    RootParts::Exercise {
                        contract_id: contract_id.0.clone(),
                        choice: choice.clone(),
                        parts: Box::new(exercise_parts(
                            commit,
                            &contract_id.0,
                            *consuming,
                            acting_parties.iter().cloned().collect(),
                        )?),
                    }
                }
                other => {
                    return Err(refuse(format!(
                        "a transaction whose root is {other:?} is not supported"
                    )))
                }
            });
        }
        let entries: Vec<Vec<TreeEntry>> = parts
            .iter()
            .zip(commits)
            .map(|(p, commit)| match p {
                RootParts::Exercise { parts, .. } => tree_entries(parts, &commit.created_contracts),
                RootParts::Create { .. } => Vec::new(),
            })
            .collect();
        let roots: Vec<RootCommand> = parts
            .iter()
            .zip(commits)
            .zip(&entries)
            .map(|((p, commit), entries)| match p {
                RootParts::Create { template } => RootCommand::Create(CreatedByExercise {
                    template,
                    payload: &commit.created_contracts[0].payload_value,
                    expected_id: &commit.created_contracts[0].contract_id,
                }),
                RootParts::Exercise {
                    contract_id,
                    choice,
                    parts,
                } => RootCommand::Exercise(ExerciseRoot {
                    contract_id_hex: contract_id,
                    choice,
                    argument: &parts.argument,
                    actors: &parts.actors,
                    observers: &parts.observers,
                    entries,
                    root_interface_id: root_interface_id(commit),
                    root_by_key: commit.root_by_key,
                    root_package_id: commit.root_package_id.as_deref(),
                }),
            })
            .collect();
        let disclosed: Vec<(String, Vec<u8>)> = commits
            .iter()
            .flat_map(|c| c.disclosed_contracts.iter().cloned())
            .collect();
        let act_as = match crate::service::current_command() {
            Some(cmd) => cmd.act_as,
            None => {
                // Fallback only when no command guard is active on the thread; reconstructs from root authorizers.
                let mut root_auth = std::collections::BTreeSet::new();
                for (p, commit) in parts.iter().zip(commits) {
                    match p {
                        RootParts::Create { .. } => {
                            if let Some(created) = commit.created_contracts.first() {
                                root_auth.extend(created.signatories.iter().cloned());
                            }
                        }
                        RootParts::Exercise { parts, .. } => {
                            root_auth.extend(parts.actors.iter().cloned());
                        }
                    }
                }
                root_auth.into_iter().collect()
            }
        };
        let tag = super::command_tag();
        let scope_command_id = self.recording_command_id();
        match self
            .node
            .submit_transaction_command(TransactionCommand {
                package_name: &self.package_name,
                roots: &roots,
                command_id: &scope_command_id,
                act_as: &act_as,
                plans: &pending.plans,
                created_before: &pending.created,
                disclosed_instances: &disclosed,
                timeout: self.tracking_timeout,
                tag: &tag,
            })
            .map_err(map_submit_err)?
        {
            (Verdict::Approved, _) => {
                if let Some(hash) =
                    canton_participant::node::SharedNode::take_last_approved_root_hash()
                {
                    crate::service::set_protocol_update_id(hex::encode(hash));
                }
                let remapped = canton_participant::node::SharedNode::take_last_remapped_cids();
                for commit in commits {
                    self.note_salts_with_remap(commit, &remapped);
                }
                if !remapped.is_empty() {
                    crate::service::set_protocol_remapped_cids(remapped);
                }
                Ok(())
            }
            (Verdict::Rejected, notes) => Err(sync_rejected("transaction", &notes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::exercise_parts;
    use crate::protocol::Below;
    use crate::service::TransactionCommit;

    fn sample_commit(
        archived_cids: Vec<String>,
        engine_events: Vec<lf_eval::EngineEvent>,
    ) -> TransactionCommit {
        TransactionCommit {
            consumed_cids: archived_cids.clone(),
            archived_cids,
            created_contracts: Vec::new(),
            legacy_archived_cids: Vec::new(),
            working_ledger: None,
            lf_tree: lf_eval::tx_model::TransactionTree::default(),
            act_as_set: std::collections::HashSet::from(["Alice::1".to_string()]),
            tx_tree_record: None,
            root_argument: None,
            engine_events,
            engine_rolled_back: Vec::new(),
            engine_key_lookups: Vec::new(),
            root_by_key: false,
            root_package_id: None,
            disclosed_contracts: Vec::new(),
            history: None,
        }
    }

    #[test]
    fn nonconsuming_root_allows_child_archive_of_target() {
        let cid = "00aabbcc";
        let commit = sample_commit(
            vec![cid.to_string()],
            vec![
                lf_eval::EngineEvent::Exercise {
                    contract_id: cid.to_string(),
                    choice: "TransferInstruction_Accept".to_string(),
                    consuming: false,
                    actors: vec!["Alice::1".to_string()],
                    depth: 0,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
                lf_eval::EngineEvent::Exercise {
                    contract_id: cid.to_string(),
                    choice: "Archive".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 1,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
            ],
        );
        let res = exercise_parts(&commit, cid, false, vec!["Alice::1".to_string()]);
        let Ok(parts) = res else {
            panic!("nonconsuming root with child self-archive must succeed");
        };
        assert!(parts.below.iter().any(|(_, b)| matches!(
            b,
            Below::Exercise {
                contract_id,
                consuming: true,
                ..
            } if contract_id == cid
        )));
    }

    #[test]
    fn nonconsuming_root_rejects_unexplained_archive() {
        let cid = "00aabbcc";
        let commit = sample_commit(
            vec![cid.to_string()],
            vec![lf_eval::EngineEvent::Exercise {
                contract_id: cid.to_string(),
                choice: "TransferInstruction_Accept".to_string(),
                consuming: false,
                actors: vec!["Alice::1".to_string()],
                depth: 0,
                argument: lf_eval::Value::Unit,
                result: Some(lf_eval::Value::Unit),
                interface_id: None,
                observers: Vec::new(),
            }],
        );
        let res = exercise_parts(&commit, cid, false, vec!["Alice::1".to_string()]);
        assert!(res.is_err());
    }

    fn sample_created_contract(contract_id: &str, active: bool) -> crate::service::GenericContract {
        crate::service::GenericContract {
            contract_id: contract_id.to_string(),
            package_id: "11".repeat(32),
            template_id: crate::TemplateId {
                package_id: "11".repeat(32),
                module_name: "M".to_string(),
                entity_name: "T".to_string(),
            },
            payload_value: lf_eval::Value::Unit,
            json_payload: serde_json::json!({}),
            signatories: vec!["Alice::1".to_string()],
            observers: Vec::new(),
            witness_parties: vec!["Alice::1".to_string()],
            active,
            key_value: None,
            created_at_micros: 1_700_000_000_000_000,
            created_event_blob: String::new(),
            contract_key_hash: String::new(),
            key_maintainers: Vec::new(),
            creation_seq: 1,
        }
    }

    #[test]
    fn transient_created_and_consumed_in_exercise_succeeds() {
        let root_cid = "00aabbcc";
        let transient_cid = "00112233";
        let surviving_cid = "00445566";
        let mut commit = sample_commit(
            vec![root_cid.to_string()],
            vec![
                lf_eval::EngineEvent::Exercise {
                    contract_id: root_cid.to_string(),
                    choice: "TransferInstruction_Accept".to_string(),
                    consuming: false,
                    actors: vec!["Alice::1".to_string()],
                    depth: 0,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
                lf_eval::EngineEvent::Create {
                    contract_id: transient_cid.to_string(),
                    template_id: "M:T".to_string(),
                    depth: 1,
                },
                lf_eval::EngineEvent::Exercise {
                    contract_id: transient_cid.to_string(),
                    choice: "Archive".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 1,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
                lf_eval::EngineEvent::Create {
                    contract_id: surviving_cid.to_string(),
                    template_id: "M:T".to_string(),
                    depth: 1,
                },
                lf_eval::EngineEvent::Exercise {
                    contract_id: root_cid.to_string(),
                    choice: "Archive".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 1,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
            ],
        );
        commit.created_contracts = vec![
            sample_created_contract(transient_cid, false),
            sample_created_contract(surviving_cid, true),
        ];
        let parts = exercise_parts(&commit, root_cid, false, vec!["Alice::1".to_string()])
            .expect("transient create consumed in exercise must succeed");
        let entries = super::tree_entries(&parts, &commit.created_contracts);
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn transient_created_without_consuming_child_rejected() {
        let root_cid = "00aabbcc";
        let transient_cid = "00112233";
        let mut commit = sample_commit(
            vec![],
            vec![
                lf_eval::EngineEvent::Exercise {
                    contract_id: root_cid.to_string(),
                    choice: "Accept".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 0,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
                lf_eval::EngineEvent::Create {
                    contract_id: transient_cid.to_string(),
                    template_id: "M:T".to_string(),
                    depth: 1,
                },
            ],
        );
        commit.created_contracts = vec![sample_created_contract(transient_cid, false)];
        let res = exercise_parts(&commit, root_cid, true, vec!["Alice::1".to_string()]);
        assert!(res.is_err());
    }

    #[test]
    fn surviving_created_consumed_by_child_rejected() {
        let root_cid = "00aabbcc";
        let surviving_cid = "00445566";
        let mut commit = sample_commit(
            vec![],
            vec![
                lf_eval::EngineEvent::Exercise {
                    contract_id: root_cid.to_string(),
                    choice: "Accept".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 0,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
                lf_eval::EngineEvent::Create {
                    contract_id: surviving_cid.to_string(),
                    template_id: "M:T".to_string(),
                    depth: 1,
                },
                lf_eval::EngineEvent::Exercise {
                    contract_id: surviving_cid.to_string(),
                    choice: "Archive".to_string(),
                    consuming: true,
                    actors: vec!["Alice::1".to_string()],
                    depth: 1,
                    argument: lf_eval::Value::Unit,
                    result: Some(lf_eval::Value::Unit),
                    interface_id: None,
                    observers: Vec::new(),
                },
            ],
        );
        commit.created_contracts = vec![sample_created_contract(surviving_cid, true)];
        let res = exercise_parts(&commit, root_cid, true, vec!["Alice::1".to_string()]);
        assert!(res.is_err());
    }
}
