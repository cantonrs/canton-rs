//! Daml-LF General Transaction Tree, Authorization, Contract Key, and Rollback.
//!
//! Enforces:
//! - Hierarchical transaction tree with Create, Exercise, Fetch, LookupByKey, Rollback nodes (REQ-TX-SEMANTICS-001)
//! - Rollback node semantics with nested effect isolation (REQ-LEDGER-ROLLBACK-001, AT-L07)
//! - Cryptographic ContractId derivation and authentication (AT-T01)
//! - Contract key uniqueness and double-spend rejection (AT-L06, AT-T02)
//! - Signatory and controller authorization checking (AT-U03)
//! - Witness and stakeholder visibility calculation (AT-L08)

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub type NodeId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContractId(pub String);

impl ContractId {
    /// Computes canonical authenticated Daml Contract ID (AT-T01).
    pub fn derive(
        package_id: &str,
        template_name: &str,
        seed: &[u8],
        payload_bytes: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"daml-contract-id-v1:");
        hasher.update(package_id.as_bytes());
        hasher.update(b":");
        hasher.update(template_name.as_bytes());
        hasher.update(b":");
        hasher.update(seed);
        hasher.update(b":");
        hasher.update(payload_bytes);
        let digest = hasher.finalize();
        Self(format!("00{}", hex::encode(digest)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Create {
        contract_id: ContractId,
        template_id: String,
        payload: Vec<u8>,
        signatories: HashSet<String>,
        observers: HashSet<String>,
        key: Option<String>,
    },
    Exercise {
        contract_id: ContractId,
        choice: String,
        acting_parties: HashSet<String>,
        consuming: bool,
        children: Vec<NodeId>,
    },
    Fetch {
        contract_id: ContractId,
        template_id: String,
        stakeholders: HashSet<String>,
    },
    LookupByKey {
        template_id: String,
        key: String,
        found: Option<ContractId>,
    },
    Rollback {
        children: Vec<NodeId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    MissingSignatory { required: String },
    MissingController { required: String },
    ContractAlreadyConsumed(ContractId),
    ContractNotFound(ContractId),
    DuplicateContractKey(String),
    RollbackError(String),
}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignatory { required } => {
                write!(f, "missing required signatory: {required}")
            }
            Self::MissingController { required } => {
                write!(f, "missing required controller: {required}")
            }
            Self::ContractAlreadyConsumed(cid) => {
                write!(f, "contract {:?} already consumed (double spend)", cid)
            }
            Self::ContractNotFound(cid) => write!(f, "contract {:?} not found in active set", cid),
            Self::DuplicateContractKey(k) => write!(f, "duplicate contract key: {k}"),
            Self::RollbackError(msg) => write!(f, "transaction rolled back: {msg}"),
        }
    }
}

impl std::error::Error for TxError {}

/// General Update Transaction Tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionTree {
    pub roots: Vec<NodeId>,
    pub nodes: HashMap<NodeId, Node>,
    next_node_id: NodeId,
}

impl TransactionTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// The parts of the tree, for serialization (roots, nodes, next node id).
    pub fn parts(&self) -> (&[NodeId], &HashMap<NodeId, Node>, NodeId) {
        (&self.roots, &self.nodes, self.next_node_id)
    }

    /// Rebuilds a tree from the parts [`TransactionTree::parts`] returned.
    pub fn from_parts(
        roots: Vec<NodeId>,
        nodes: HashMap<NodeId, Node>,
        next_node_id: NodeId,
    ) -> Self {
        Self {
            roots,
            nodes,
            next_node_id,
        }
    }

    pub fn allocate_node_id(&mut self) -> NodeId {
        let id = self.next_node_id;
        self.next_node_id += 1;
        id
    }

    pub fn insert_node(&mut self, node: Node, is_root: bool) -> NodeId {
        let id = self.allocate_node_id();
        if is_root {
            self.roots.push(id);
        }
        self.nodes.insert(id, node);
        id
    }

    /// Computes stakeholders (signatories union observers) of a node.
    pub fn stakeholders(&self, node_id: NodeId) -> HashSet<String> {
        match self.nodes.get(&node_id) {
            Some(Node::Create {
                signatories,
                observers,
                ..
            }) => {
                let mut set = signatories.clone();
                set.extend(observers.clone());
                set
            }
            Some(Node::Fetch { stakeholders, .. }) => stakeholders.clone(),
            _ => HashSet::new(),
        }
    }

    /// Computes informees / witness parties of a node (AT-L08).
    pub fn witnesses(&self, node_id: NodeId) -> HashSet<String> {
        match self.nodes.get(&node_id) {
            Some(Node::Create {
                signatories,
                observers,
                ..
            }) => {
                let mut set = signatories.clone();
                set.extend(observers.clone());
                set
            }
            Some(Node::Exercise { acting_parties, .. }) => acting_parties.clone(),
            Some(Node::Fetch { stakeholders, .. }) => stakeholders.clone(),
            _ => HashSet::new(),
        }
    }
}

/// Represents an active contract in the Active Contract Set (ACS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveContract {
    pub template_id: String,
    pub payload: Vec<u8>,
    pub stakeholders: HashSet<String>,
    pub key: Option<String>,
}

/// One change to the active set, kept so that it can be reverted: the previous value of the entry (`None`: it was absent).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Undo {
    Contract(ContractId, Option<ActiveContract>),
    Key(String, Option<ContractId>),
}

/// Active Contract Set (ACS) and Key Index with Rollback Support.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveLedgerState {
    pub active_contracts: HashMap<ContractId, ActiveContract>,
    pub keys: HashMap<String, ContractId>,
    /// While `Some`, the changes of every applied transaction are kept so that a batch of them can be reverted together
    /// (`begin_batch`, `rollback_batch`, `end_batch`).
    batch: Option<Vec<Undo>>,
}

impl ActiveLedgerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a transaction tree to the state, supporting rollback frames (AT-L07).
    pub fn apply_transaction(
        &mut self,
        tx: &TransactionTree,
        act_as: &HashSet<String>,
    ) -> Result<(), TxError> {
        // [CANTON-NOTE: SEMANTICS] The whole transaction is atomic: on a failure every change it made is undone. The undo log
        // replaces the copy of the whole state this used to take for every transaction (and for every rollback frame), which
        // made each command cost O(size of the active contract set) and a long ledger quadratic to build or replay.
        let recording = self.batch.is_some();
        let mut undo = self.batch.take().unwrap_or_default();
        let mark = undo.len();
        let result = self.apply_nodes(&tx.roots, tx, act_as, &mut undo);
        if result.is_err() {
            self.undo_to(&mut undo, mark);
        }
        if recording {
            self.batch = Some(undo); // a successful transaction stays revertable with the rest of its batch
        }
        result
    }

    /// Starts keeping the changes of the transactions applied from now on.
    pub fn begin_batch(&mut self) {
        self.batch = Some(Vec::new());
    }

    /// Reverts everything applied since `begin_batch` and stops recording.
    pub fn rollback_batch(&mut self) {
        if let Some(mut undo) = self.batch.take() {
            self.undo_to(&mut undo, 0);
        }
    }

    /// Keeps what was applied since `begin_batch` and stops recording.
    pub fn end_batch(&mut self) {
        self.batch = None;
    }

    /// Reverts the changes recorded in `undo` after position `mark`, newest first.
    fn undo_to(&mut self, undo: &mut Vec<Undo>, mark: usize) {
        while undo.len() > mark {
            match undo.pop() {
                Some(Undo::Contract(id, None)) => {
                    self.active_contracts.remove(&id);
                }
                Some(Undo::Contract(id, Some(old))) => {
                    self.active_contracts.insert(id, old);
                }
                Some(Undo::Key(k, None)) => {
                    self.keys.remove(&k);
                }
                Some(Undo::Key(k, Some(old))) => {
                    self.keys.insert(k, old);
                }
                None => break,
            }
        }
    }

    fn apply_nodes(
        &mut self,
        node_ids: &[NodeId],
        tx: &TransactionTree,
        act_as: &HashSet<String>,
        undo: &mut Vec<Undo>,
    ) -> Result<(), TxError> {
        for &nid in node_ids {
            let Some(node) = tx.nodes.get(&nid) else {
                continue;
            };
            match node {
                Node::Create {
                    contract_id,
                    template_id,
                    payload,
                    signatories,
                    observers,
                    key,
                } => {
                    // Signatory authorization check (AT-U03)
                    for sig in signatories {
                        if !act_as.contains(sig) {
                            return Err(TxError::MissingSignatory {
                                required: sig.clone(),
                            });
                        }
                    }

                    // Key uniqueness check (AT-L06)
                    if let Some(k) = key {
                        if self.keys.contains_key(k) {
                            return Err(TxError::DuplicateContractKey(k.clone()));
                        }
                        let old = self.keys.insert(k.clone(), contract_id.clone());
                        undo.push(Undo::Key(k.clone(), old));
                    }

                    let mut stakeholders = signatories.clone();
                    stakeholders.extend(observers.clone());
                    let old = self.active_contracts.insert(
                        contract_id.clone(),
                        ActiveContract {
                            template_id: template_id.clone(),
                            payload: payload.clone(),
                            stakeholders,
                            key: key.clone(),
                        },
                    );
                    undo.push(Undo::Contract(contract_id.clone(), old));
                }
                Node::Exercise {
                    contract_id,
                    acting_parties,
                    consuming,
                    children,
                    ..
                } => {
                    // Controller authorization check (AT-U03)
                    for ctrl in acting_parties {
                        if !act_as.contains(ctrl) {
                            return Err(TxError::MissingController {
                                required: ctrl.clone(),
                            });
                        }
                    }

                    // Contract existence check (AT-T02 double spend check)
                    let ac = self
                        .active_contracts
                        .get(contract_id)
                        .cloned()
                        .ok_or_else(|| TxError::ContractAlreadyConsumed(contract_id.clone()))?;

                    if *consuming {
                        let old = self.active_contracts.remove(contract_id);
                        undo.push(Undo::Contract(contract_id.clone(), old));
                        if let Some(ref k) = ac.key {
                            let old = self.keys.remove(k);
                            undo.push(Undo::Key(k.clone(), old));
                        }
                    }

                    // In Daml transaction semantics, consequences of an exercise inherit authority
                    // from the acting parties (controllers) AND the signatories/stakeholders of the target contract.
                    let mut child_act_as = act_as.clone();
                    child_act_as.extend(ac.stakeholders);

                    // Apply child effects
                    self.apply_nodes(children, tx, &child_act_as, undo)?;
                }
                Node::Fetch { contract_id, .. } => {
                    if !self.active_contracts.contains_key(contract_id) {
                        return Err(TxError::ContractNotFound(contract_id.clone()));
                    }
                }
                Node::LookupByKey {
                    template_id: _,
                    key,
                    found,
                } => {
                    let actual = self.keys.get(key);
                    if actual != found.as_ref() {
                        return Err(TxError::RollbackError("key lookup mismatch".into()));
                    }
                }
                Node::Rollback { children } => {
                    // Isolated rollback frame: inner failures are caught, and on exit,
                    // all mutations performed by children are completely reverted from the active ledger state (AT-L07).
                    let mark = undo.len();
                    let _ = self.apply_nodes(children, tx, act_as, undo);
                    self.undo_to(undo, mark);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_t01_contract_id_derivation() {
        let cid1 = ContractId::derive("pkg1", "TemplateA", b"seed1", b"payload1");
        let cid2 = ContractId::derive("pkg1", "TemplateA", b"seed1", b"payload1");
        let cid3 = ContractId::derive("pkg1", "TemplateA", b"seed2", b"payload1");

        assert_eq!(cid1, cid2);
        assert_ne!(cid1, cid3);
        assert!(cid1.0.starts_with("00"));
        assert_eq!(cid1.0.len(), 66); // "00" + 64 hex chars
    }

    #[test]
    fn test_at_u03_authorization_signatory_check() {
        let mut state = ActiveLedgerState::new();
        let mut tx = TransactionTree::new();

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());
        sigs.insert("Bank".into());

        let cid = ContractId::derive("pkg1", "Asset", b"1", b"data");
        tx.insert_node(
            Node::Create {
                contract_id: cid,
                template_id: "Asset".into(),
                payload: vec![1, 2, 3],
                signatories: sigs,
                observers: HashSet::new(),
                key: None,
            },
            true,
        );

        // ActAs only Alice -> fails because Bank signatory missing
        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());
        let res = state.apply_transaction(&tx, &act_as);
        assert_eq!(
            res,
            Err(TxError::MissingSignatory {
                required: "Bank".into()
            })
        );

        // ActAs Alice + Bank -> succeeds
        act_as.insert("Bank".into());
        assert!(state.apply_transaction(&tx, &act_as).is_ok());
    }

    fn create_tx(id: &[u8], key: Option<&str>, sig: &str) -> TransactionTree {
        let mut tx = TransactionTree::new();
        let mut sigs = HashSet::new();
        sigs.insert(sig.to_string());
        tx.insert_node(
            Node::Create {
                contract_id: ContractId::derive("p", "T", id, b""),
                template_id: "T".into(),
                payload: id.to_vec(),
                signatories: sigs,
                observers: HashSet::new(),
                key: key.map(String::from),
            },
            true,
        );
        tx
    }

    /// [CANTON-NOTE: INVARIANT] A batch of transactions is reverted together, and a transaction that fails inside a batch
    /// reverts only itself (the undo log replaced the copy of the whole state taken per transaction).
    #[test]
    fn batch_rollback_reverts_every_applied_transaction() {
        let act_as: HashSet<String> = ["Alice".to_string()].into();
        let mut state = ActiveLedgerState::new();
        state
            .apply_transaction(&create_tx(b"0", Some("k0"), "Alice"), &act_as)
            .unwrap();
        let before = state.clone();

        state.begin_batch();
        state
            .apply_transaction(&create_tx(b"1", Some("k1"), "Alice"), &act_as)
            .unwrap();
        // fails (duplicate key) after a successful transaction of the same batch: only itself is reverted
        let dup = state.apply_transaction(&create_tx(b"2", Some("k1"), "Alice"), &act_as);
        assert!(matches!(dup, Err(TxError::DuplicateContractKey(_))));
        assert_eq!(state.active_contracts.len(), 2);
        assert!(state.keys.contains_key("k1"));
        state.rollback_batch();
        assert_eq!(state, before);

        // a batch that is ended keeps its changes, and later transactions are not recorded
        state.begin_batch();
        state
            .apply_transaction(&create_tx(b"3", None, "Alice"), &act_as)
            .unwrap();
        state.end_batch();
        assert_eq!(state.active_contracts.len(), 2);
        state.rollback_batch(); // nothing recorded any more
        assert_eq!(state.active_contracts.len(), 2);
    }

    #[test]
    fn test_at_l06_duplicate_key_rejection() {
        let mut state = ActiveLedgerState::new();
        let mut tx = TransactionTree::new();

        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        let cid1 = ContractId::derive("p", "T", b"1", b"");
        tx.insert_node(
            Node::Create {
                contract_id: cid1,
                template_id: "T".into(),
                payload: vec![],
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: Some("alice-account".into()),
            },
            true,
        );

        state.apply_transaction(&tx, &act_as).unwrap();

        // Second create with duplicate key MUST FAIL (AT-L06)
        let mut tx2 = TransactionTree::new();
        let cid2 = ContractId::derive("p", "T", b"2", b"");
        tx2.insert_node(
            Node::Create {
                contract_id: cid2,
                template_id: "T".into(),
                payload: vec![],
                signatories: sigs,
                observers: HashSet::new(),
                key: Some("alice-account".into()),
            },
            true,
        );

        let res = state.apply_transaction(&tx2, &act_as);
        assert_eq!(
            res,
            Err(TxError::DuplicateContractKey("alice-account".into()))
        );
    }

    #[test]
    fn test_at_l07_rollback_node_semantics() {
        let mut state = ActiveLedgerState::new();
        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        let mut tx = TransactionTree::new();
        // Root 1: Valid create
        let cid1 = ContractId::derive("p", "T", b"1", b"");
        tx.insert_node(
            Node::Create {
                contract_id: cid1.clone(),
                template_id: "T".into(),
                payload: vec![],
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: None,
            },
            true,
        );

        // Child node of rollback: will fail authorization
        let cid_fail = ContractId::derive("p", "T", b"fail", b"");
        let mut bad_sigs = HashSet::new();
        bad_sigs.insert("Bob".into()); // Bob is not in act_as!
        let child_id = tx.insert_node(
            Node::Create {
                contract_id: cid_fail.clone(),
                template_id: "T".into(),
                payload: vec![],
                signatories: bad_sigs,
                observers: HashSet::new(),
                key: None,
            },
            false,
        );

        // Root 2: Rollback node containing child_id
        tx.insert_node(
            Node::Rollback {
                children: vec![child_id],
            },
            true,
        );

        // Entire transaction succeeds; cid1 is created, but rollback child is discarded cleanly
        assert!(state.apply_transaction(&tx, &act_as).is_ok());
        assert!(state.active_contracts.contains_key(&cid1));
        assert!(!state.active_contracts.contains_key(&cid_fail));
    }

    #[test]
    fn test_at_l06_key_recreation_after_consumption() {
        let mut state = ActiveLedgerState::new();
        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        // 1. Create contract with key
        let mut tx1 = TransactionTree::new();
        let cid1 = ContractId::derive("pkg1", "Asset", b"1", b"");
        tx1.insert_node(
            Node::Create {
                contract_id: cid1.clone(),
                template_id: "Asset".into(),
                payload: vec![],
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: Some("alice-account".into()),
            },
            true,
        );
        state.apply_transaction(&tx1, &act_as).unwrap();
        assert_eq!(state.keys.get("alice-account"), Some(&cid1));

        // 2. Consume contract 1
        let mut tx2 = TransactionTree::new();
        tx2.insert_node(
            Node::Exercise {
                contract_id: cid1,
                choice: "Archive".into(),
                acting_parties: sigs.clone(),
                consuming: true,
                children: vec![],
            },
            true,
        );
        state.apply_transaction(&tx2, &act_as).unwrap();
        assert_eq!(state.keys.get("alice-account"), None);

        // 3. Create contract 2 with the SAME key must now succeed!
        let mut tx3 = TransactionTree::new();
        let cid2 = ContractId::derive("pkg1", "Asset", b"2", b"");
        tx3.insert_node(
            Node::Create {
                contract_id: cid2.clone(),
                template_id: "Asset".into(),
                payload: vec![],
                signatories: sigs,
                observers: HashSet::new(),
                key: Some("alice-account".into()),
            },
            true,
        );
        assert!(state.apply_transaction(&tx3, &act_as).is_ok());
        assert_eq!(state.keys.get("alice-account"), Some(&cid2));
    }

    #[test]
    fn test_at_l07_rollback_valid_children_are_reverted() {
        let mut state = ActiveLedgerState::new();
        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        let mut tx = TransactionTree::new();
        let cid_valid = ContractId::derive("pkg1", "Asset", b"valid", b"");
        let child_id = tx.insert_node(
            Node::Create {
                contract_id: cid_valid.clone(),
                template_id: "Asset".into(),
                payload: vec![],
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: Some("alice-temporary-key".into()),
            },
            false,
        );

        tx.insert_node(
            Node::Rollback {
                children: vec![child_id],
            },
            true,
        );

        // Transaction commits, but children inside Rollback must NOT leak into active state!
        assert!(state.apply_transaction(&tx, &act_as).is_ok());
        assert!(!state.active_contracts.contains_key(&cid_valid));
        assert!(!state.keys.contains_key("alice-temporary-key"));
    }

    #[test]
    fn test_at_l07_rollback_consuming_is_reverted() {
        let mut state = ActiveLedgerState::new();
        let mut act_as = HashSet::new();
        act_as.insert("Alice".into());

        let mut sigs = HashSet::new();
        sigs.insert("Alice".into());

        // Create a contract outside rollback
        let mut tx1 = TransactionTree::new();
        let cid = ContractId::derive("pkg1", "Asset", b"orig", b"");
        tx1.insert_node(
            Node::Create {
                contract_id: cid.clone(),
                template_id: "Asset".into(),
                payload: vec![],
                signatories: sigs.clone(),
                observers: HashSet::new(),
                key: Some("orig-key".into()),
            },
            true,
        );
        state.apply_transaction(&tx1, &act_as).unwrap();

        // Transaction 2 tries to consume cid inside a rollback node
        let mut tx2 = TransactionTree::new();
        let child_id = tx2.insert_node(
            Node::Exercise {
                contract_id: cid.clone(),
                choice: "Archive".into(),
                acting_parties: sigs,
                consuming: true,
                children: vec![],
            },
            false,
        );
        tx2.insert_node(
            Node::Rollback {
                children: vec![child_id],
            },
            true,
        );

        assert!(state.apply_transaction(&tx2, &act_as).is_ok());
        // cid must STILL be active and its key must STILL be registered!
        assert!(state.active_contracts.contains_key(&cid));
        assert_eq!(state.keys.get("orig-key"), Some(&cid));
    }
}
