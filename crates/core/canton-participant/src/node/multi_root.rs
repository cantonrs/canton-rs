//! One confirmation request for a transaction of several roots (P-8): the commands of one submission, a root each, assembled into one
//! [`Transaction`] and judged together.
//!
//! [CANTON-NOTE: SEMANTICS] Canton interprets all commands of a submission into one transaction whose roots are the commands' nodes (a
//! `CreateAndExerciseCommand` gives two) and `NextGenTransactionTreeFactory.createRootViews` makes one root view per root, in one request.
//! The ids of the contracts are promised before the request is built: each root view has its own plan (`ExercisePlan::draw_roots`), and the
//! build checks that it derives the ids that were promised.
use super::{open_instance, stored_from, CreatedByExercise, Node, SharedNode, TreeEntry, TreeNode};
use crate::submit::{
    plan_created, plan_root_created, Built, ExercisePlan, Os, Peer, StoredContract,
};
use crate::value_forms::lf_form;
use crate::view_tree::{Action, KeyUse, NewContract, Transaction};
use lf_eval::typed_json::Types;
use lf_eval::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::Verdict;

/// An exercise at the root of a transaction (the arguments of [`Node::prepare_exercise_with_options`]).
pub struct ExerciseRoot<'a> {
    pub contract_id_hex: &'a str,
    pub choice: &'a str,
    pub argument: &'a Value,
    pub actors: &'a [String],
    /// The root choice's own observers (`ExerciseNode.choiceObservers`).
    pub observers: &'a [String],
    pub entries: &'a [TreeEntry<'a>],
    pub root_interface_id: Option<&'a str>,
    pub root_by_key: bool,
    pub root_package_id: Option<&'a str>,
}

/// A root of a transaction: what one command made.
pub enum RootCommand<'a> {
    Create(CreatedByExercise<'a>),
    Exercise(ExerciseRoot<'a>),
}

/// A transaction of several roots submitted through a [`SharedNode`], how long its caller waits for the verdict, and its tag.
pub struct TransactionCommand<'a> {
    pub package_name: &'a str,
    pub roots: &'a [RootCommand<'a>],
    pub command_id: &'a str,
    pub act_as: &'a [String],
    /// One plan per root, the ones the ids of its contracts were promised from.
    pub plans: &'a [ExercisePlan],
    /// The contracts created by earlier roots of the transaction, as their ids were promised: a later root may use them.
    pub created_before: &'a [StoredContract],
    pub disclosed_instances: &'a [(String, Vec<u8>)],
    pub timeout: Duration,
    pub tag: &'a str,
}

/// The action nodes of a transaction assembled root by root, and what its request needs to know about them.
#[derive(Default)]
pub(super) struct Assembly {
    nodes: Vec<Action>,
    roots: Vec<usize>,
    keys: Vec<(usize, KeyUse)>,
    parties: Vec<String>,
    used_packages: BTreeSet<String>,
    /// The ids the engine gave the contracts the transaction creates and their action node index.
    expected: Vec<(String, usize)>,
    /// The contracts the transaction consumes.
    consumed: Vec<String>,
}

impl Node {
    /// The contracts disclosed to a command, by id, each checked to be the instance its id names.
    pub(super) fn disclosed_contracts(
        &self,
        disclosed_instances: &[(String, Vec<u8>)],
    ) -> Result<BTreeMap<String, StoredContract>, String> {
        let mut disclosed = BTreeMap::new();
        for (cid, bytes) in disclosed_instances {
            let opened = open_instance(&self.runtime.engine, bytes)?;
            if &opened.contract_id != cid {
                return Err(format!(
                    "disclosed contract id {cid} mismatches decoded {}",
                    opened.contract_id
                ));
            }
            disclosed.insert(opened.contract_id.clone(), stored_from(&opened, bytes));
        }
        Ok(disclosed)
    }

    /// Adds an exercise root and the nodes below it (`root.entries`); `extra` are contracts this node does not hold that the tree may use.
    /// Returns whether the root exercise consumes its contract.
    pub(super) fn add_exercise_root(
        &self,
        assembly: &mut Assembly,
        package_name: &str,
        root: &ExerciseRoot<'_>,
        extra: &BTreeMap<String, StoredContract>,
    ) -> Result<bool, String> {
        let Assembly {
            nodes,
            roots,
            keys: tx_keys,
            parties,
            used_packages,
            expected,
            consumed,
        } = assembly;
        // [CANTON-NOTE: SEMANTICS] Contracts created earlier within the same exercise (e.g. CIP-0112 TestTokenV2
        // `tryUseAccountAuthorityForTIA'` fetching `pendingInstrCid` right after creating it) are valid targets for
        // later Fetch/Exercise/Lookup nodes (`NextGenTransactionTreeFactory.scala:719-725` `createdInSameViewOrSubviews`).
        let mut created_in_root: BTreeMap<
            String,
            (StoredContract, Option<crate::view_tree::KeyUse>),
        > = BTreeMap::new();
        let stored = self
            .contracts
            .get(root.contract_id_hex)
            .cloned()
            .or_else(|| extra.get(root.contract_id_hex).cloned())
            .ok_or_else(|| {
                format!(
                    "the contract {} is not one this node created",
                    root.contract_id_hex
                )
            })?;
        let template = format!("{}:{}", stored.module.join("."), stored.name.join("."));
        let exec_pkg = root.root_package_id.unwrap_or(&stored.package_id);
        used_packages.insert(stored.package_id.clone());
        used_packages.insert(exec_pkg.to_string());
        let (arg, consuming) = {
            let types = Types::new(&self.world);
            let choice_types = match root.root_interface_id {
                Some(iface_full) => {
                    let (iface_pkg, iface_local) = iface_full
                        .split_once(':')
                        .ok_or_else(|| format!("interface id {iface_full} lacks package id"))?;
                    used_packages.insert(iface_pkg.to_string());
                    types.interface_choice(iface_pkg, iface_local, root.choice)?
                }
                None => types.choice(exec_pkg, &template, root.choice)?,
            };
            let lf = lf_form(&types, &choice_types.argument, root.argument)?;
            (lf, choice_types.consuming)
        };
        // [CANTON-NOTE: SEMANTICS] Every exercise and fetch of a keyed contract states the contract's key in its view's `resolved_keys`,
        // by id as well as by key (`NextGenTransactionTreeFactory`: `suffixedNode.keyOpt` of each core node); a use by id resolves it to no
        // contract (`LfTransactionUtil.queriedContractIds`). Measured (S-G11-001): without it p1 rebuilt a JSON API `Probe` with one more
        // resolved key than it received and rejected it (`LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK`, `ViewReconstructionError`).
        let key_of_use = |this: &Self, contract: &StoredContract, by_key: bool| {
            this.contract_key_use(contract, package_name).map(|k| {
                k.map(|mut k| {
                    if !by_key {
                        k.contract_id = None;
                    }
                    k
                })
            })
        };
        let key_of_cached = |mut k: crate::view_tree::KeyUse, by_key: bool| {
            if !by_key {
                k.contract_id = None;
            }
            k
        };
        let resolve_created_or_stored = |this: &Self,
                                         extra: &BTreeMap<String, StoredContract>,
                                         created: &BTreeMap<
            String,
            (StoredContract, Option<crate::view_tree::KeyUse>),
        >,
                                         id: &str|
         -> Result<
            (StoredContract, Option<Option<crate::view_tree::KeyUse>>),
            String,
        > {
            if let Some(c) = this.contracts.get(id).or_else(|| extra.get(id)) {
                return Ok((c.clone(), None));
            }
            if let Some((c, k)) = created.get(id) {
                return Ok((c.clone(), Some(k.clone())));
            }
            Err(format!("the contract {id} is not one this node created"))
        };
        let base = nodes.len();
        if let Some(key_use) = key_of_use(self, &stored, root.root_by_key)? {
            tx_keys.push((base, key_use));
        }
        if consuming {
            consumed.push(stored.contract_id_hex.clone());
        }
        let mut exercise_contract = stored.clone();
        exercise_contract.package_id = exec_pkg.to_string();
        roots.push(base);
        nodes.push(Action::Exercise {
            contract: exercise_contract,
            choice: root.choice.to_string(),
            argument: Some(arg),
            consuming,
            actors: root.actors.to_vec(),
            // [CANTON-NOTE: SEMANTICS] Choice observers are informees of the exercise (`Node.informeesOfNode`); leaving them out
            // made the view's informees differ from what a receiver's replay gives (`InformeesDiffer`, AUDIT U-50 2026-11-24).
            choice_observers: root.observers.to_vec(),
            children: Vec::new(),
            interface_id: root.root_interface_id.map(String::from),
        });
        let mut open: Vec<usize> = vec![base];
        parties.extend(stored.stakeholders.iter().cloned());
        parties.extend(root.actors.iter().cloned());
        parties.extend(root.observers.iter().cloned());
        for entry in root.entries {
            open.truncate(entry.depth);
            let parent = *open
                .last()
                .ok_or_else(|| "a node below the root has a depth of at least 1".to_string())?;
            let at = nodes.len();
            let action = match &entry.node {
                TreeNode::Exercise {
                    contract_id,
                    choice: child_choice,
                    argument: child_arg,
                    consuming,
                    actors,
                    observers,
                    interface_id,
                    by_key,
                } => {
                    let (contract, cached_key) =
                        resolve_created_or_stored(self, extra, &created_in_root, contract_id)?;
                    used_packages.insert(contract.package_id.clone());
                    parties.extend(contract.stakeholders.iter().cloned());
                    parties.extend(actors.iter().cloned());
                    parties.extend(observers.iter().cloned());
                    let encoded_arg = match (child_arg, interface_id) {
                        (Some(val), Some(iface_full)) if !child_choice.is_empty() => {
                            let (iface_pkg, iface_local) =
                                iface_full.split_once(':').ok_or_else(|| {
                                    format!("interface id {iface_full} lacks package id")
                                })?;
                            used_packages.insert(iface_pkg.to_string());
                            let types = Types::new(&self.world);
                            let ct =
                                types.interface_choice(iface_pkg, iface_local, child_choice)?;
                            Some(lf_form(&types, &ct.argument, val)?)
                        }
                        (Some(val), None) if !child_choice.is_empty() => {
                            let child_tmpl = format!(
                                "{}:{}",
                                contract.module.join("."),
                                contract.name.join(".")
                            );
                            let types = Types::new(&self.world);
                            let ct =
                                types.choice(&contract.package_id, &child_tmpl, child_choice)?;
                            Some(lf_form(&types, &ct.argument, val)?)
                        }
                        _ => None,
                    };
                    if let Some(iface_pkg) = interface_id.and_then(|s| s.split(':').next()) {
                        used_packages.insert(iface_pkg.to_string());
                    }
                    let key_use = match cached_key {
                        Some(maybe_k) => maybe_k.map(|k| key_of_cached(k, *by_key)),
                        None => key_of_use(self, &contract, *by_key)?,
                    };
                    if let Some(key_use) = key_use {
                        tx_keys.push((at, key_use));
                    }
                    if *consuming {
                        consumed.push(contract.contract_id_hex.clone());
                    }
                    Action::Exercise {
                        contract,
                        choice: (*child_choice).to_string(),
                        argument: encoded_arg,
                        consuming: *consuming,
                        actors: actors.clone(),
                        choice_observers: observers.clone(),
                        children: Vec::new(),
                        interface_id: interface_id.map(String::from),
                    }
                }
                TreeNode::Fetch {
                    contract_id,
                    actors,
                    interface_id,
                    by_key,
                } => {
                    let (contract, cached_key) =
                        resolve_created_or_stored(self, extra, &created_in_root, contract_id)?;
                    used_packages.insert(contract.package_id.clone());
                    parties.extend(contract.stakeholders.iter().cloned());
                    parties.extend(actors.iter().cloned());
                    if let Some(iface_pkg) = interface_id.and_then(|s| s.split(':').next()) {
                        used_packages.insert(iface_pkg.to_string());
                    }
                    let key_use = match cached_key {
                        Some(maybe_k) => maybe_k.map(|k| key_of_cached(k, *by_key)),
                        None => key_of_use(self, &contract, *by_key)?,
                    };
                    if let Some(key_use) = key_use {
                        tx_keys.push((at, key_use));
                    }
                    Action::Fetch {
                        contract,
                        actors: actors.clone(),
                        interface_id: interface_id.map(String::from),
                    }
                }
                TreeNode::Lookup {
                    template,
                    key,
                    contract_ids,
                } => {
                    let key_use = self.describe_key(
                        template,
                        key,
                        contract_ids.first().map(|s| (*s).to_string()),
                        package_name,
                    )?;
                    used_packages.insert(key_use.package_id.clone());
                    parties.extend(key_use.maintainers.iter().cloned());
                    let mut found = Vec::with_capacity(contract_ids.len());
                    for cid in contract_ids {
                        let (c, _) = resolve_created_or_stored(self, extra, &created_in_root, cid)?;
                        parties.extend(c.stakeholders.iter().cloned());
                        found.push(c);
                    }
                    Action::Lookup(key_use, found)
                }
                TreeNode::Rollback => Action::Rollback {
                    children: Vec::new(),
                },
                TreeNode::Create(c) => {
                    let (action, stakeholders) =
                        self.create_action(c, package_name, used_packages)?;
                    if let Action::Create(ref nc) = action {
                        let cached_key = nc.key.as_ref().map(|nk| crate::view_tree::KeyUse {
                            package_name: nc.package_name.clone(),
                            package_id: nc.package_id.clone(),
                            module: nc.module.clone(),
                            name: nc.name.clone(),
                            value: nk.value.clone(),
                            hash_value: nk.hash_value.clone(),
                            maintainers: nk.maintainers.clone(),
                            contract_id: Some(c.expected_id.to_string()),
                        });
                        created_in_root.insert(
                            c.expected_id.to_string(),
                            (
                                StoredContract {
                                    contract_id_hex: c.expected_id.to_string(),
                                    instance: Vec::new(),
                                    package_id: nc.package_id.clone(),
                                    module: nc.module.clone(),
                                    name: nc.name.clone(),
                                    signatories: nc.signatories.clone(),
                                    stakeholders: nc.stakeholders.clone(),
                                },
                                cached_key,
                            ),
                        );
                    }
                    parties.extend(stakeholders);
                    expected.push((c.expected_id.to_string(), at));
                    action
                }
            };
            match &mut nodes[parent] {
                Action::Exercise { children, .. } | Action::Rollback { children } => {
                    children.push(at)
                }
                _ => return Err("a node below a node that is not an exercise".into()),
            }
            let is_exercise = matches!(action, Action::Exercise { .. } | Action::Rollback { .. });
            nodes.push(action);
            if is_exercise {
                open.push(at);
            }
        }
        Ok(consuming)
    }

    /// Adds a create root (a `CreateCommand`, or the create of a `CreateAndExerciseCommand`).
    fn add_create_root(
        &self,
        assembly: &mut Assembly,
        package_name: &str,
        create: &CreatedByExercise<'_>,
    ) -> Result<(), String> {
        let (action, stakeholders) =
            self.create_action(create, package_name, &mut assembly.used_packages)?;
        if let Action::Create(c) = &action {
            self.check_submitters(&c.signatories)?;
        }
        assembly.parties.extend(stakeholders);
        let root_node = assembly.nodes.len();
        assembly
            .expected
            .push((create.expected_id.to_string(), root_node));
        assembly.roots.push(root_node);
        assembly.nodes.push(action);
        Ok(())
    }

    /// The create node of `c`, and its stakeholders.
    fn create_action(
        &self,
        c: &CreatedByExercise<'_>,
        package_name: &str,
        used_packages: &mut BTreeSet<String>,
    ) -> Result<(Action, Vec<String>), String> {
        let d = self.describe(c.template, c.payload)?;
        used_packages.insert(d.package_id.clone());
        let pkg_name = self
            .package_name_of(&d.package_id)
            .unwrap_or(package_name)
            .to_string();
        let stakeholders = d.stakeholders.clone();
        Ok((
            Action::Create(NewContract {
                package_name: pkg_name,
                package_id: d.package_id,
                module: d.module,
                name: d.name,
                arg: d.arg,
                hash_arg: d.hash_arg,
                signatories: d.signatories,
                stakeholders: d.stakeholders,
                key: d.key,
            }),
            stakeholders,
        ))
    }

    /// Builds the request of an assembled transaction, sent for `act_as` as `command_id`, returning any
    /// subview-derived contract ID remappings (`want -> made`). `plans` as in [`build_planned`].
    /// Builds the request of `assembly` without sending it and without checking the ids it gives the contracts it creates against the
    /// engine's: the built request, the engine's ids with their create nodes, and whether the tree has subviews.
    pub(super) fn build_assembly_unchecked(
        &mut self,
        assembly: Assembly,
        act_as: &[String],
        command_id: &str,
        plans: &[ExercisePlan],
        submission: &crate::submit::Submission,
    ) -> Result<(Built, Vec<(String, usize)>, bool), String> {
        let Assembly {
            nodes,
            roots,
            keys,
            mut parties,
            used_packages,
            expected,
            consumed: _,
        } = assembly;
        // who hosts whom: the participants that host each party of the tree, and the keys to encrypt for
        parties.sort();
        parties.dedup();
        let mut hosting: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut peers: Vec<Peer> = vec![self.me()];
        for party in &parties {
            let found = self.peers_of_party(party)?;
            hosting.insert(
                party.clone(),
                found.iter().map(|p| p.member.clone()).collect(),
            );
            for peer in found {
                if !peers.iter().any(|p| p.member == peer.member) {
                    peers.push(peer);
                }
            }
        }
        let me = self.identity.member();
        let admin = self.identity.uid();
        hosting.insert(admin.clone(), BTreeSet::from([me]));
        let at = match plans.first() {
            Some(plan) => plan.now,
            None => self.now()?,
        };
        for pkg_id in &used_packages {
            self.check_peers_vetted(pkg_id, &peers, at)?;
        }
        let lookup = |party: &str| hosting.get(party).cloned().unwrap_or_default();
        let mut tx = Transaction {
            nodes,
            roots,
            keys,
            temp_ids: Default::default(),
            package_preference: Default::default(),
            ledger_time: None,
        };
        let has_sub = {
            let views = crate::view_tree::decompose(&tx, &admin, &lookup);
            crate::view_tree::has_subview(&views)
        };
        if has_sub {
            for (want, create_node) in &expected {
                tx.temp_ids.insert(want.clone(), *create_node);
            }
        }
        let built = crate::view_tree::build_planned_as(
            &self.context(),
            &tx,
            &peers,
            &lookup,
            &crate::view_tree::RequestSpec {
                act_as,
                command_id,
                now: at,
                plan: plans,
                submission,
            },
            &mut Os,
        )?;
        Ok((built, expected, has_sub))
    }

    pub(super) fn build_assembly_with_remap(
        &mut self,
        assembly: Assembly,
        act_as: &[String],
        command_id: &str,
        plans: &[ExercisePlan],
        submission: &crate::submit::Submission,
    ) -> Result<(Built, BTreeMap<String, String>), String> {
        let (built, expected, has_sub) =
            self.build_assembly_unchecked(assembly, act_as, command_id, plans, submission)?;
        if built.created.len() != expected.len() {
            return Err(format!(
                "the request creates {} contracts, the engine created {}",
                built.created.len(),
                expected.len()
            ));
        }
        let mut remapped = BTreeMap::new();
        if has_sub {
            for (want, create_node) in &expected {
                let Some(pos) = built.created_nodes.iter().position(|n| n == create_node) else {
                    return Err(format!(
                        "created node {create_node} missing in built request"
                    ));
                };
                let made_id = &built.created[pos].contract_id_hex;
                if made_id != want {
                    remapped.insert(want.clone(), made_id.clone());
                }
            }
        } else {
            for (made, (want, _)) in built.created.iter().zip(&expected) {
                if made.contract_id_hex != *want {
                    return Err(format!(
                        "the request would create {} where the engine used {want}",
                        made.contract_id_hex
                    ));
                }
            }
        }
        Ok((built, remapped))
    }

    /// The plans of a request of `roots` roots, drawn now (see [`ExercisePlan::draw_roots`]).
    pub fn plan_roots(&mut self, roots: usize) -> Result<Vec<ExercisePlan>, String> {
        let now = self.current_time()?;
        Ok(ExercisePlan::draw_roots(&mut Os, now, roots))
    }

    /// The contract that `plan`'s root creates (`path` `None`), or that the create at `index`/`path` below `plan`'s root exercise creates
    /// (see [`Node::promise_created_at`]): its id is promised to the engine before the request is built.
    pub fn promise_in_root(
        &self,
        package_name: &str,
        plan: &ExercisePlan,
        below: Option<(usize, &[i32])>,
        template: &str,
        payload: &Value,
    ) -> Result<StoredContract, String> {
        let d = self.describe(template, payload)?;
        let pkg_name = self.package_name_of(&d.package_id).unwrap_or(package_name);
        match below {
            None => plan_root_created(&self.context(), plan, &d.in_view_at(pkg_name, &[])),
            Some((index, path)) => {
                plan_created(&self.context(), plan, index, &d.in_view_at(pkg_name, path))
            }
        }
    }

    #[cfg(test)]
    fn prepare_transaction(
        &mut self,
        command: &TransactionCommand<'_>,
    ) -> Result<(Built, Vec<String>), String> {
        let (built, consumed, _) = self.prepare_transaction_with_remap(command)?;
        Ok((built, consumed))
    }

    fn prepare_transaction_with_remap(
        &mut self,
        command: &TransactionCommand<'_>,
    ) -> Result<(Built, Vec<String>, BTreeMap<String, String>), String> {
        let mut extra = self.disclosed_contracts(command.disclosed_instances)?;
        for c in command.created_before {
            extra.insert(c.contract_id_hex.clone(), c.clone());
        }
        let mut assembly = Assembly::default();
        // [CANTON-NOTE: SEMANTICS] R-13b: SubmitterMetadata.act_as carries the request's actAs
        // (preserving non-signatory co-submitters) rather than reconstructing actAs from root
        // signatories/actors, and check_submitters validates every party in actAs.
        let act_as_set: BTreeSet<String> = command.act_as.iter().cloned().collect();
        if act_as_set.is_empty() {
            return Err("transaction command requires at least one actAs party".to_string());
        }
        let act_as: Vec<String> = act_as_set.iter().cloned().collect();
        self.check_submitters(&act_as)?;
        for root in command.roots {
            match root {
                RootCommand::Create(create) => {
                    self.add_create_root(&mut assembly, command.package_name, create)?;
                    if let Some(Action::Create(c)) = assembly.nodes.last() {
                        if let Some(missing) = c
                            .signatories
                            .iter()
                            .find(|s| !act_as_set.contains(s.as_str()))
                        {
                            return Err(format!(
                                "create signatory {missing} is not in command actAs"
                            ));
                        }
                    }
                }
                RootCommand::Exercise(exercise) => {
                    self.check_submitters(exercise.actors)?;
                    if let Some(missing) = exercise
                        .actors
                        .iter()
                        .find(|a| !act_as_set.contains(a.as_str()))
                    {
                        return Err(format!("exercise actor {missing} is not in command actAs"));
                    }
                    self.add_exercise_root(&mut assembly, command.package_name, exercise, &extra)?;
                }
            }
        }
        let consumed = assembly.consumed.clone();
        let (built, remapped) = self.build_assembly_with_remap(
            assembly,
            &act_as,
            command.command_id,
            command.plans,
            &crate::submit::Submission::default(),
        )?;
        Ok((built, consumed, remapped))
    }
}

impl SharedNode {
    /// Submits a transaction of several roots and waits for the verdict; when it is approved the node holds what it created and forgets what
    /// it consumed (a contract an earlier root created and a later one consumed included).
    pub fn submit_transaction_command(
        &self,
        command: TransactionCommand<'_>,
    ) -> Result<(Verdict, Vec<String>), String> {
        let (built, consumed, remapped) = self.with(|n| {
            let (built, consumed, remapped) = n.prepare_transaction_with_remap(&command)?;
            n.send_tagged(&built.message_id, built.request.clone(), command.tag)?;
            Ok::<_, String>((built, consumed, remapped))
        })??;
        let root_hash = built.root_hash.clone();
        Self::clear_approved_root_hash();
        Self::clear_remapped_cids();
        let (verdict, notes) = self.wait(&built.message_id, command.timeout)?;
        if verdict == Verdict::Approved {
            Self::note_approved_root_hash(root_hash);
            Self::note_remapped_cids(remapped.clone());
            self.with(|n| {
                for c in built.created {
                    n.remember(c);
                }
                for id in &consumed {
                    let forget_id = remapped.get(id).map(String::as_str).unwrap_or(id);
                    n.forget(forget_id);
                }
            })?;
        }
        self.note_awaited(command.command_id, &built.message_id)?;
        Ok((verdict, notes))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse_dar_package_names, Board, CreatedByExercise};
    use super::*;
    use crate::participant_runtime::{Config, Runtime};
    use crate::sequencer_connect::{SequencerConnect, Token};
    use crate::sequencer_time::TimeKeeper;
    use crate::topology_wire::ParticipantIdentity;
    use crate::view_acs::Timeouts;
    use crate::view_conformance::Engine;
    use crate::view_receive::{decrypt_views, revealed_submitter_metadata};
    use lf_eval::World;
    use std::path::Path;
    use std::time::Instant;

    #[test]
    fn r13b_prepare_transaction_preserves_request_act_as_in_submitter_metadata() {
        let dar = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let identity = ParticipantIdentity::generate("r13b-unit");
        let alice = format!("alice::{}", identity.namespace());
        let extra = format!("extra::{}", identity.namespace());
        let physical = "sync::1220aa".to_string();
        let engine = Engine::load(&dar).expect("load sample dar");
        let world = World::open(&dar).expect("open sample world");
        let boot_package_ids: BTreeSet<String> = world.package_ids().into_iter().collect();
        let mut package_names_by_id = BTreeMap::new();
        parse_dar_package_names(&dar, &mut package_names_by_id).expect("parse package names");
        let config = Config {
            member: identity.member(),
            encryption_fingerprint: identity.encryption_fingerprint(),
            encryption_secret: *identity.encryption_secret(),
            hosted_parties: vec![alice.clone(), extra.clone()],
            timeouts: Timeouts::default(),
            submitter_keys: Vec::new(),
            mediator_keys: Vec::new(),
            peer_encryption_keys: Default::default(),
            physical_synchronizer_id: physical.clone(),
            follow_topology: false,
            topology_change_delay_micros: 250_000,
        };
        let runtime = Runtime::open_in(config, engine, None, 0).expect("open runtime");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind dummy port");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let client =
            SequencerConnect::connect(&format!("http://127.0.0.1:{port}")).expect("lazy connect");
        let token = Token {
            token: vec![1],
            expires_at_seconds: i64::MAX,
        };
        let fp = identity.encryption_fingerprint();
        let secret = *identity.encryption_secret();
        let mut node = Node {
            runtime,
            last_notes: Vec::new(),
            identity,
            client,
            token,
            physical,
            mediator_group: 0,
            user_id: "u-r13b".to_string(),
            world,
            vetted_package_ids: boot_package_ids,
            package_names_by_id,
            contracts: BTreeMap::new(),
            unassigned: BTreeMap::new(),
            store: None,
            directory: BTreeMap::new(),
            board: std::sync::Arc::new(Board::default()),
            most_in_flight: 0,
            remote: Vec::new(),
            late: Vec::new(),
            clock: TimeKeeper::new(Instant::now(), 0),
        };
        let plans = ExercisePlan::draw_roots(&mut Os, 1_700_000_000_000_000, 1);
        let payload = Value::Record {
            tycon: Some("AssetHolding:AssetHolding".into()),
            fields: vec![
                ("bank".into(), Value::Party(alice.clone())),
                ("owner".into(), Value::Party(alice.clone())),
                ("auditor".into(), Value::Party(alice.clone())),
                ("assetSymbol".into(), Value::Text("USD".into())),
                (
                    "amount".into(),
                    Value::Numeric {
                        coeff: 1_005_000_000_000,
                        scale: 10,
                    },
                ),
            ],
        };
        let promised = node
            .promise_in_root(
                "sample-contract",
                &plans[0],
                None,
                "AssetHolding:AssetHolding",
                &payload,
            )
            .expect("promise contract id");
        let roots = [RootCommand::Create(CreatedByExercise {
            template: "AssetHolding:AssetHolding",
            payload: &payload,
            expected_id: &promised.contract_id_hex,
        })];

        // Preserves non-signatory co-submitter `extra` in `SubmitterMetadata.act_as`.
        let req_act_as = vec![extra.clone(), alice.clone(), extra.clone()];
        let (built, _) = node
            .prepare_transaction(&TransactionCommand {
                package_name: "sample-contract",
                roots: &roots,
                command_id: "cmd-r13b",
                act_as: &req_act_as,
                plans: &plans,
                created_before: &[],
                disclosed_instances: &[],
                timeout: Duration::from_secs(5),
                tag: "",
            })
            .expect("prepare_transaction with non-signatory co-submitter succeeds");
        let mut expected_act_as = vec![alice, extra.clone()];
        expected_act_as.sort();
        let submitter_act_as = built
            .envelopes
            .iter()
            .find_map(|(_, env)| {
                let views = decrypt_views(env, &fp, &secret).ok()?;
                views
                    .view_trees
                    .iter()
                    .filter_map(|vt| vt.tree.as_ref())
                    .find_map(|tree| revealed_submitter_metadata(tree).ok())
                    .map(|meta| meta.act_as)
            })
            .expect("SubmitterMetadata present in built envelopes");
        assert_eq!(submitter_act_as, expected_act_as);

        // Negative control 1: empty `act_as` is rejected.
        let empty_err = match node.prepare_transaction(&TransactionCommand {
            package_name: "sample-contract",
            roots: &roots,
            command_id: "cmd-r13b-empty",
            act_as: &[],
            plans: &plans,
            created_before: &[],
            disclosed_instances: &[],
            timeout: Duration::from_secs(5),
            tag: "",
        }) {
            Ok(_) => panic!("empty act_as must fail"),
            Err(e) => e,
        };
        assert!(empty_err.contains("actAs"), "{empty_err}");

        // Negative control 2: `act_as` omitting root signatory `alice` is rejected.
        let missing_auth_err = match node.prepare_transaction(&TransactionCommand {
            package_name: "sample-contract",
            roots: &roots,
            command_id: "cmd-r13b-missing-auth",
            act_as: std::slice::from_ref(&extra),
            plans: &plans,
            created_before: &[],
            disclosed_instances: &[],
            timeout: Duration::from_secs(5),
            tag: "",
        }) {
            Ok(_) => panic!("missing root signatory in act_as must fail"),
            Err(e) => e,
        };
        assert!(missing_auth_err.contains("signatory"), "{missing_auth_err}");
    }
}
