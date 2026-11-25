//! A transaction tree, decomposed into views and built into one confirmation request (G8 P1).
//!
//! A port of three Canton sources, kept in their structure so a reader can lay them side by side:
//! - `TransactionViewDecompositionFactory` (decomposition: which action nodes share a view, who is an informee, which quorums a view has),
//! - `Node.scala` (`informeesOfNode`) and `LfTransactionUtil` (`signatoriesOrMaintainers`, `actingParties`, `usedContractId`),
//! - `NextGenTransactionTreeFactory.createTransactionView` / `createViewParticipantData` (salts, contract creation inside a view, core
//!   inputs, created core, the action description of the root node, subviews).
//!
//! The wire encodings (Merkle tree, light tree, encryption, envelopes) are the ones `submit` already builds and the official participant
//! accepted.
//!
//! [CANTON-NOTE: LIMITATION] Any number of roots; create, exercise (by id, by key, through an interface), fetch, `lookupByKey` and rollback
//! nodes ([`Action`]). A contract created in the transaction is named in later arguments through [`Transaction::temp_ids`] (S-SPL-018).
//! The recipients of a view's message are a path of groups from the root view down to it (`sw::compressed_batch_paths`). A subview's
//! root exercise must carry its chosen value (`argument`): a request without it is refused.
use crate::contract_id as ci;
use crate::contract_wire::LfValue;
use crate::merkle_wire as mw;
use crate::submit::{Context, StoredContract};
use std::collections::{BTreeMap, BTreeSet};

mod build;
mod run;

pub use build::{build_planned, build_planned_as, build_transaction, RequestSpec};

/// A contract a node creates (its arguments in both protocol forms, see [`crate::value_forms::forms`]).
#[derive(Clone)]
pub struct NewContract {
    pub package_name: String,
    pub package_id: String,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub arg: LfValue,
    pub hash_arg: ci::HashValue,
    pub signatories: Vec<String>,
    pub stakeholders: Vec<String>,
    /// `None` for a template without a key.
    pub key: Option<crate::submit::NewKey>,
}

/// An action node of the transaction (`LfActionNode`).
#[derive(Clone)]
pub enum Action {
    Create(NewContract),
    Exercise {
        contract: StoredContract,
        choice: String,
        /// The chosen value; `None` when it is not known, which a node that becomes the root of a subview cannot be.
        argument: Option<LfValue>,
        consuming: bool,
        actors: Vec<String>,
        choice_observers: Vec<String>,
        /// The interface the choice is exercised through, as `<package id>:<module>:<interface>`.
        interface_id: Option<String>,
        /// Indices into [`Transaction::nodes`], in order. Every child counts for the numbering of node seeds (a fetch too).
        children: Vec<usize>,
    },
    Fetch {
        contract: StoredContract,
        actors: Vec<String>,
        /// The interface the contract is fetched through (`fetchFromInterface`), as `<package id>:<module>:<interface>`.
        interface_id: Option<String>,
    },
    /// `lookupByKey`: asks what a key resolves to. The node names no contract; its maintainers are its informees and its quorum, and the
    /// answer is stated in the view's resolved keys (S-SPL-023).
    /// The contract the key resolved to, when there is one: it is an input of the view (`Failed to find key resolution contract` otherwise).
    ///
    /// [CANTON-NOTE: SEMANTICS] Canton 3.7.2 has one key-query node, `Node.QueryByKey` (`result: Vector[ContractId]`): `lookupByKey` finds
    /// at most one contract and `lookupNByKey n` at most `n`. Every contract found is an input of the view and is listed, in order, in the
    /// key's resolution (UNRESOLVED U-21).
    Lookup(KeyUse, Vec<StoredContract>),
    /// A caught exception's rolled-back consequences (`try ... catch`). It has no informees and no view of its own: the views are those of
    /// its children (`TransactionViewDecompositionFactory` enters and leaves a rollback scope), and it takes **no** seed index
    /// (`PartialTransaction.rollbackTry` hands the action-child counter back to the parent). S-SPL-024.
    Rollback {
        children: Vec<usize>,
    },
}

/// A node that reaches its contract **by key** (`fetchByKey`, `exercise by key`) or looks a key up: what the key resolved to.
#[derive(Clone)]
pub struct KeyUse {
    pub package_name: String,
    /// The template the key belongs to (the node's contract's, or the one a `lookupByKey` asks about).
    pub package_id: String,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub value: LfValue,
    pub hash_value: ci::HashValue,
    pub maintainers: Vec<String>,
    /// The contract the key resolved to; `None` when nothing holds the key.
    pub contract_id: Option<String>,
}

#[derive(Clone)]
pub struct Transaction {
    pub nodes: Vec<Action>,
    pub roots: Vec<usize>,
    /// Contract ids that stand for a contract **this transaction creates**, in the arguments of its exercises (an engine's temporary ids such as
    /// `#1`): the temporary id and the index of the create node. [`build_transaction`] builds twice: the first build learns the ids of the
    /// created contracts, the second states them in the arguments (S-SPL-018).
    pub temp_ids: BTreeMap<String, usize>,
    /// By node index: the package ids the package **names** the interpretation of that exercise resolved stand for, stated in its action
    /// description (only the view of the command whose body resolved them: the other views are rebuilt without). Empty when the
    /// code resolves no name (measured: the official participant rebuilds such a view with none, and says `UnresolvedPackageName` for one that
    /// resolves a name while the view has none, S-SPL-018).
    pub package_preference: BTreeMap<usize, Vec<String>>,
    /// The ledger time of the transaction when it is not the sequencer's time `now` (a replay of a recorded network moves its own clock; the
    /// synchronizer's `ledgerTimeRecordTimeTolerance` has to allow the difference). Contract ids, creation times and the participant metadata use
    /// it; the maximum sequencing time and the topology time stay the sequencer's.
    pub ledger_time: Option<i64>,
    /// The key resolutions of the nodes (node index, what its key resolved to): a view states those of the nodes of its own core in its
    /// `resolved_keys` (S-SPL-014).
    pub keys: Vec<(usize, KeyUse)>,
}

fn set(parties: &[String]) -> BTreeSet<String> {
    parties.iter().cloned().collect()
}

/// `Node.informeesOfNode`.
fn informees_of_node(node: &Action) -> BTreeSet<String> {
    match node {
        Action::Create(c) => set(&c.stakeholders),
        Action::Fetch {
            contract, actors, ..
        } => &set(&contract.signatories) | &set(actors),
        Action::Lookup(k, _) => set(&k.maintainers),
        Action::Rollback { .. } => BTreeSet::new(),
        Action::Exercise {
            contract,
            consuming,
            actors,
            choice_observers,
            ..
        } => {
            let base = if *consuming {
                set(&contract.stakeholders)
            } else {
                set(&contract.signatories)
            };
            &(&base | &set(actors)) | &set(choice_observers)
        }
    }
}

/// `LfTransactionUtil.signatoriesOrMaintainers`.
fn signatories_of(node: &Action) -> BTreeSet<String> {
    match node {
        Action::Create(c) => set(&c.signatories),
        Action::Lookup(k, _) => set(&k.maintainers),
        Action::Rollback { .. } => BTreeSet::new(),
        Action::Fetch { contract, .. } | Action::Exercise { contract, .. } => {
            set(&contract.signatories)
        }
    }
}

/// `LfTransactionUtil.actingParties`.
fn acting_parties_of(node: &Action) -> BTreeSet<String> {
    match node {
        Action::Create(_) | Action::Lookup(..) | Action::Rollback { .. } => BTreeSet::new(),
        Action::Fetch { actors, .. } | Action::Exercise { actors, .. } => set(actors),
    }
}

fn children_of(node: &Action) -> &[usize] {
    match node {
        Action::Exercise { children, .. } | Action::Rollback { children } => children,
        _ => &[],
    }
}

/// `ActionNodeInfo`: the informees of a node, the quorum its confirming parties form, and the participants that host an informee.
struct Info {
    informees: BTreeSet<String>,
    quorum: BTreeSet<String>,
    participants: BTreeSet<String>,
}

/// `TransactionViewDecompositionFactory.informeesParticipantsAndThreshold`: the confirming parties of a node are the submitting admin party
/// (at a root only), the signatories of the node's contract and the acting parties; the informees are those and `informeesOfNode`.
fn info_of(node: &Action, admin: Option<&str>, hosting: &dyn Fn(&str) -> BTreeSet<String>) -> Info {
    let mut quorum = &signatories_of(node) | &acting_parties_of(node);
    if let Some(admin) = admin {
        quorum.insert(admin.to_string());
    }
    let informees = &informees_of_node(node) | &quorum;
    let participants = informees.iter().flat_map(|p| hosting(p)).collect();
    Info {
        informees,
        quorum,
        participants,
    }
}

/// `TransactionViewDecomposition`: a node of the view's own core (`SameView`) or a subview (`NewView`).
pub enum Tail {
    Same(usize),
    New(Box<NewView>),
}

pub struct NewView {
    pub node: usize,
    pub informees: BTreeSet<String>,
    /// The quorums of the view: its root node's first, then those of the nodes in its core, without duplicates.
    pub quorums: Vec<BTreeSet<String>>,
    pub tail: Vec<Tail>,
    /// The view's root node is inside a rollback (`rollbackContext.inRollback`): the view states `rolled_back` (S-SPL-025).
    pub in_rollback: bool,
}

#[derive(Default)]
struct ChildState {
    views: Vec<Tail>,
    informees: BTreeSet<String>,
    quorums: Vec<BTreeSet<String>>,
}

/// Topology-dependent view decomposition node shared between outbound view splitting ([`decompose`]) and inbound replay informee
/// verification (`view_informees::replayed_core_informees`, `TransactionViewDecompositionFactory.scala:131, 402-413`).
pub(crate) struct DecompNode {
    pub informees: BTreeSet<String>,
    pub participants: BTreeSet<String>,
    pub children: Vec<usize>,
    pub is_rollback: bool,
}

/// Outcome of classifying child actions against the parent view's participants.
pub(crate) enum DecompChild {
    Same(usize),
    NewSubview { node: usize, in_rollback: bool },
}

/// `[CANTON-NOTE: SEMANTICS]` `TransactionViewDecompositionFactory.scala:131, 195-230, 402-413`:
/// keeps child actions whose informee hosts are a subset of `root_participants` in the same view core and splits any others into a
/// `NewSubview` (transparently tracking rollback nesting).
pub(crate) fn collect_view_children(
    nodes: &[DecompNode],
    children: &[usize],
    root_participants: &BTreeSet<String>,
    rollback_depth: usize,
    out: &mut Vec<DecompChild>,
) {
    for &child in children {
        let entry = &nodes[child];
        if entry.is_rollback {
            collect_view_children(
                nodes,
                &entry.children,
                root_participants,
                rollback_depth + 1,
                out,
            );
        } else if entry.participants.is_subset(root_participants) {
            out.push(DecompChild::Same(child));
            collect_view_children(
                nodes,
                &entry.children,
                root_participants,
                rollback_depth,
                out,
            );
        } else {
            out.push(DecompChild::NewSubview {
                node: child,
                in_rollback: rollback_depth > 0,
            });
        }
    }
}

/// Computes the exact core informees of `root` (itself plus all `Same` descendants) over a `DecompNode` forest.
pub(crate) fn core_informees_of_root(nodes: &[DecompNode], root: usize) -> BTreeSet<String> {
    let mut out = nodes[root].informees.clone();
    let mut classified = Vec::new();
    collect_view_children(
        nodes,
        &nodes[root].children,
        &nodes[root].participants,
        0,
        &mut classified,
    );
    for item in classified {
        if let DecompChild::Same(idx) = item {
            out.extend(nodes[idx].informees.iter().cloned());
        }
    }
    out
}

struct Builder {
    infos: BTreeMap<usize, Info>,
    decomp: Vec<DecompNode>,
}

impl Builder {
    /// `buildNewView`.
    fn new_view(&self, node: usize, in_rollback: bool) -> NewView {
        let info = &self.infos[&node];
        let mut classified = Vec::new();
        collect_view_children(
            &self.decomp,
            &self.decomp[node].children,
            &self.decomp[node].participants,
            usize::from(in_rollback),
            &mut classified,
        );
        let mut child = ChildState::default();
        for item in classified {
            match item {
                DecompChild::Same(idx) => {
                    let cinfo = &self.infos[&idx];
                    child.views.push(Tail::Same(idx));
                    child.informees.extend(cinfo.informees.iter().cloned());
                    child.quorums.push(cinfo.quorum.clone());
                }
                DecompChild::NewSubview {
                    node: sub,
                    in_rollback: sub_rb,
                } => {
                    child
                        .views
                        .push(Tail::New(Box::new(self.new_view(sub, sub_rb))));
                }
            }
        }
        let mut quorums = vec![info.quorum.clone()];
        for q in child.quorums {
            if !quorums.contains(&q) {
                quorums.push(q);
            }
        }
        NewView {
            node,
            informees: &info.informees | &child.informees,
            quorums,
            tail: child.views,
            in_rollback,
        }
    }
}

/// `TransactionViewDecompositionFactory.fromTransaction`: the root views of the transaction.
pub fn decompose(
    tx: &Transaction,
    admin: &str,
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
) -> Vec<NewView> {
    let mut infos = BTreeMap::new();
    let mut decomp = Vec::with_capacity(tx.nodes.len());
    for (i, node) in tx.nodes.iter().enumerate() {
        let admin = tx.roots.contains(&i).then_some(admin);
        let info = info_of(node, admin, hosting);
        decomp.push(DecompNode {
            informees: info.informees.clone(),
            participants: info.participants.clone(),
            children: children_of(node).to_vec(),
            is_rollback: matches!(node, Action::Rollback { .. }),
        });
        infos.insert(i, info);
    }
    let builder = Builder { infos, decomp };
    tx.roots
        .iter()
        .map(|r| builder.new_view(*r, false))
        .collect()
}

fn view_has_subview(view: &NewView) -> bool {
    view.tail.iter().any(|item| match item {
        Tail::Same(_) => false,
        Tail::New(_) => true,
    })
}

/// Returns `true` when any decomposed view contains at least one child subview (`Tail::New`).
pub fn has_subview(views: &[NewView]) -> bool {
    views.iter().any(view_has_subview)
}

/// `MerkleSeq.indicesFromSeq(n)`: the position of each of `n` elements in the seq, the lowest layer's step first.
pub fn seq_indices(n: usize) -> Vec<Vec<bool>> {
    let mut layer: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    let mut paths: Vec<Vec<bool>> = vec![Vec::new(); n];
    while layer.len() > 1 {
        let mut next = Vec::new();
        for pair in layer.chunks(2) {
            if let [left, right] = pair {
                for i in left {
                    paths[*i].push(false);
                }
                for i in right {
                    paths[*i].push(true);
                }
                next.push([left.clone(), right.clone()].concat());
            } else {
                next.push(pair[0].clone());
            }
        }
        layer = next;
    }
    paths
}

/// A view as built: its trees, its position and what its message needs.
struct BuiltView {
    key: [u8; 16],
    full: mw::Tree,
    informee: mw::Tree,
    cd: mw::LeafNode,
    pd: mw::LeafNode,
    children: Vec<BuiltView>,
    /// Contract IDs created anywhere in this view's non-rolled-back subtree.
    created_ids: BTreeSet<String>,
    /// The members that host an informee of the view.
    members: BTreeSet<String>,
    /// The view's `resolved_keys` (its own nodes' and its subviews'), which its parent takes over.
    resolved: Vec<canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers>,
}

struct Run<'a, 'c> {
    ctx: &'a Context<'c>,
    tx: &'a Transaction,
    now: i64,
    uuid: String,
    seeds: BTreeMap<usize, [u8; 32]>,
    hosting: &'a dyn Fn(&str) -> BTreeSet<String>,
    created: Vec<StoredContract>,
    created_nodes: Vec<usize>,
    /// The participant-data salt of the root view being built, when the ids of its creates were promised before the request was built.
    root_salt: Option<[u8; 32]>,
}

/// The positions of the views of a request in the order [`build_transaction`] addresses them, for a test that answers for each.
pub fn view_positions(
    tx: &Transaction,
    admin: &str,
    hosting: &dyn Fn(&str) -> BTreeSet<String>,
) -> Vec<(Vec<Vec<bool>>, BTreeSet<String>)> {
    fn go(
        nv: &NewView,
        position: Vec<Vec<bool>>,
        out: &mut Vec<(Vec<Vec<bool>>, BTreeSet<String>)>,
    ) {
        out.push((
            position.clone(),
            nv.quorums.iter().flatten().cloned().collect(),
        ));
        let children: Vec<&NewView> = nv
            .tail
            .iter()
            .filter_map(|t| match t {
                Tail::New(v) => Some(&**v),
                Tail::Same(_) => None,
            })
            .collect();
        for (c, idx) in children.iter().zip(seq_indices(children.len())) {
            let mut p = vec![idx];
            p.extend(position.iter().cloned());
            go(c, p, out);
        }
    }
    let views = decompose(tx, admin, hosting);
    let mut out = Vec::new();
    for (v, p) in views.iter().zip(seq_indices(views.len())) {
        go(v, vec![p], &mut out);
    }
    out
}

#[cfg(test)]
mod tests;
