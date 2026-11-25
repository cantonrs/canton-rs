//! A participant on several synchronizers (G7 B1, S-NET-040 part 7): one identity, one [`Node`] per synchronizer, and the reassignment of a
//! contract between them.
//!
//! [CANTON-NOTE: SEMANTICS] A Canton participant is one uid and one key set; it connects to each synchronizer on its own (its own sequencer
//! connection, its own sequenced events and contract set per synchronizer). A contract is active on one synchronizer at a time; an
//! unassignment is submitted on its source and the assignment on the target (`UnassignmentProcessingSteps`, `AssignmentProcessingSteps`).
//! The reassigning participants are the participants that host a stakeholder on **both** synchronizers
//! (`ReassigningParticipantsComputation`).
//!
//! [CANTON-NOTE: LIMITATION] One contract per reassignment; transactions are submitted on the synchronizer the caller names (no automatic
//! choice of synchronizer, no automatic reassignment before a transaction).
use crate::node::{Node, ReassignmentDone};
use crate::state_store::{FileStore, StateStore};
use crate::topology_wire::ParticipantIdentity;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// One participant identity with a node on each synchronizer.
pub struct MultiNode {
    pub nodes: Vec<Node>,
}

/// The logical synchronizer id of a physical one (`name::namespace::37-0` -> `name::namespace`); a logical id is returned as is.
pub fn logical(synchronizer: &str) -> String {
    match synchronizer.matches("::").count() {
        2 => synchronizer
            .rsplit_once("::")
            .map(|x| x.0.to_string())
            .unwrap_or_default(),
        _ => synchronizer.to_string(),
    }
}

impl MultiNode {
    /// Joins every synchronizer of `urls` with one identity named `name`. With `state_dir`, the identity is kept in `state_dir/identity`
    /// (a restart is the same participant) and each node's state in `state_dir/sync-<i>`.
    pub fn connect_in(
        urls: &[&str],
        name: &str,
        dar: &Path,
        state_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let root = match state_dir {
            Some(dir) => Some(FileStore::new(dir)? as Arc<dyn StateStore>),
            None => None,
        };
        Self::connect_with(urls, name, dar, root, |i| match state_dir {
            Some(dir) => Ok(Some(
                FileStore::new(&dir.join(format!("sync-{i}")))? as Arc<dyn StateStore>
            )),
            None => Ok(None),
        })
    }

    /// The same with any kind of store: `root` keeps the identity, `node_store(i)` is the state of the node on synchronizer `i`.
    /// [CANTON-NOTE: WHY] The identity must be shared by all nodes (one participant, several synchronizers) while each node's state is its
    /// own, whatever the backing is (a directory, or PostgreSQL state names `<name>`, `<name>-sync-<i>`, S-LOCAL-012).
    pub fn connect_with(
        urls: &[&str],
        name: &str,
        dar: &Path,
        root: Option<Arc<dyn StateStore>>,
        node_store: impl Fn(usize) -> Result<Option<Arc<dyn StateStore>>, String>,
    ) -> Result<Self, String> {
        let (text, restored) = match &root {
            Some(store) => match store.read("identity")? {
                Some(t) => (t, true),
                None => {
                    let t = ParticipantIdentity::generate(name).to_text();
                    store.create_new("identity", &t)?;
                    (t, false)
                }
            },
            None => (ParticipantIdentity::generate(name).to_text(), false),
        };
        // one reassignment store for the participant, whichever synchronizer an unassignment was seen on (U-60)
        let unassignments = crate::participant_runtime::SharedUnassignments::default();
        let mut nodes = Vec::new();
        for (i, url) in urls.iter().enumerate() {
            let identity = ParticipantIdentity::from_text(&text)
                .ok_or("the participant's identity cannot be read")?;
            // `connect_as` publishes the vetting of the boot packages (U-61)
            let mut node = Node::connect_as(identity, restored, url, dar, node_store(i)?)?;
            node.share_unassignments(unassignments.clone());
            nodes.push(node);
        }
        Ok(MultiNode { nodes })
    }

    /// The node of `synchronizer` (logical or physical id).
    pub fn index_of(&self, synchronizer: &str) -> Option<usize> {
        let wanted = logical(synchronizer);
        self.nodes
            .iter()
            .position(|n| logical(n.physical_synchronizer_id()) == wanted)
    }

    /// The synchronizer a contract is active on (as this participant knows it).
    pub fn locate(&self, contract_id_hex: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.is_active(contract_id_hex))
    }

    /// The participants that host one of `parties` on both `from` and `to` (sorted uids).
    pub fn reassigning_participants(
        &self,
        from: usize,
        to: usize,
        parties: &[String],
    ) -> Vec<String> {
        let a = self.nodes[from].hosting_participants(parties);
        let b = self.nodes[to].hosting_participants(parties);
        a.intersection(&b).cloned().collect()
    }

    fn index(&self, synchronizer: &str) -> Result<usize, String> {
        self.index_of(synchronizer)
            .ok_or_else(|| format!("this participant is not connected to {synchronizer}"))
    }

    /// Unassigns `contract_id_hex` from `source` to `target` as `submitter` and waits for the verdict.
    pub fn unassign(
        &mut self,
        contract_id_hex: &str,
        source: &str,
        target: &str,
        submitter: &str,
        command_id: &str,
        timeout: Duration,
    ) -> Result<ReassignmentDone, String> {
        let (from, to) = (self.index(source)?, self.index(target)?);
        if from == to {
            return Err("the source and the target are the same synchronizer".into());
        }
        let instance = self.nodes[from]
            .instance_bytes(contract_id_hex)
            .ok_or_else(|| format!("this participant has no instance of {contract_id_hex}"))?;
        let parties = crate::reassignment_submit::contract_parties(&instance)?;
        let reassigning = self.reassigning_participants(from, to, &parties.stakeholders);
        let target_physical = self.nodes[to].physical_synchronizer_id().to_string();
        let target_time = self.nodes[to].current_time()?;
        let done = self.nodes[from].unassign(
            contract_id_hex,
            &target_physical,
            target_time,
            submitter,
            command_id,
            &reassigning,
            timeout,
        )?;
        if done.verdict == crate::node::Verdict::Approved {
            if let Some(stored) = self.nodes[from]
                .stored_unassignment(&done.reassignment_id)
                .cloned()
            {
                self.nodes[to]
                    .remember_stored_unassignment(done.reassignment_id.clone(), stored)?;
            }
        }
        Ok(done)
    }

    /// Assigns on `target` the unassignment `unassigned` from `source`, as `submitter`, and waits for the verdict.
    pub fn assign(
        &mut self,
        unassigned: &ReassignmentDone,
        source: &str,
        target: &str,
        submitter: &str,
        command_id: &str,
        timeout: Duration,
    ) -> Result<ReassignmentDone, String> {
        let (from, to) = (self.index(source)?, self.index(target)?);
        let parties = crate::reassignment_submit::contract_parties(&unassigned.instance)?;
        let reassigning = self.reassigning_participants(from, to, &parties.stakeholders);
        let source_physical = self.nodes[from].physical_synchronizer_id().to_string();
        self.nodes[to].assign(
            unassigned,
            &source_physical,
            submitter,
            command_id,
            &reassigning,
            timeout,
        )
    }
}
