//! The commands of one submission committed as one transaction (P-8): while a batch is open on a thread, each command's commit is kept
//! instead of being judged, the ids of the contracts are promised from the batch's plans, and the batch is judged once, after its last
//! command, by [`ExecutionService::finish_protocol_batch`]. A failure leaves the rollback of the submission (`v2_atomic`) to undo it all.
use super::{ApiError, Arc, ExecutionService, NewContract, ProtocolCommitter, TransactionCommit};

struct Batch {
    id: u64,
    commits: Vec<TransactionCommit>,
    /// The scan history of the commits, written once the batch is approved: `(input, update id, workflow id)`.
    history: Vec<(crate::history::HistoryInput, String, String)>,
    /// Participant-estimated X-Ray records queued while the batch waits for synchronizer verdict.
    xray: Vec<crate::observability::XRayNodeRecord>,
}

thread_local! {
    static BATCH: std::cell::RefCell<Option<Batch>> = const { std::cell::RefCell::new(None) };
}

/// An open batch; dropping it without [`ExecutionService::finish_protocol_batch`] abandons it.
pub(crate) struct BatchGuard {
    committer: Arc<dyn ProtocolCommitter>,
    id: u64,
    finished: bool,
}

impl Drop for BatchGuard {
    fn drop(&mut self) {
        if !self.finished {
            BATCH.with(|b| b.borrow_mut().take());
            self.committer.abort_transaction(self.id);
        }
    }
}

impl ExecutionService {
    /// Opens a batch for a submission whose commands make `roots` roots, when a committer judges them and there is more than one root.
    pub(crate) fn begin_protocol_batch(
        &self,
        roots: usize,
    ) -> Result<Option<BatchGuard>, ApiError> {
        if roots < 2 || super::is_v2_prepare_dry_run() {
            return Ok(None);
        }
        let Some(committer) = self.committer.read().ok().and_then(|c| c.clone()) else {
            return Ok(None);
        };
        let Some(id) = committer.begin_transaction(roots) else {
            return Ok(None);
        };
        let id = id?;
        BATCH.with(|b| {
            *b.borrow_mut() = Some(Batch {
                id,
                commits: Vec::new(),
                history: Vec::new(),
                xray: Vec::new(),
            })
        });
        Ok(Some(BatchGuard {
            committer,
            id,
            finished: false,
        }))
    }

    /// Judges the open batch as one transaction; on approval writes the scan history its commands kept back.
    pub(crate) fn finish_protocol_batch(&self, mut guard: BatchGuard) -> Result<(), ApiError> {
        let batch = BATCH
            .with(|b| b.borrow_mut().take())
            .ok_or_else(|| ApiError::Ledger("the batch of this submission is gone".into()))?;
        guard.finished = true;
        if let Err(err) = guard.committer.commit_transaction(batch.id, &batch.commits) {
            super::clear_protocol_update_id();
            return Err(err);
        }
        for record in batch.xray {
            self.observability.record_xray(record);
        }
        let recorder = self.recorder.read().ok().and_then(|r| r.clone());
        if let Some(recorder) = recorder {
            for (input, update_id, workflow_id) in &batch.history {
                if let Err(e) = recorder.record(input, update_id, workflow_id) {
                    crate::diag::diag_eprintln!("scan history: {update_id} not recorded: {e}");
                }
            }
        }
        Ok(())
    }
}

/// The id of a contract the engine creates: promised from the open batch's plan of the root the next commit makes, else as
/// [`ProtocolCommitter::allocate_contract_id`] gives it.
pub(super) fn allocate(
    committer: &dyn ProtocolCommitter,
    new: &NewContract<'_>,
    session: &mut Option<u64>,
) -> Option<String> {
    let open = BATCH.with(|b| b.borrow().as_ref().map(|b| (b.id, b.commits.len())));
    match open {
        Some((id, root)) => committer.allocate_in_transaction(id, root, new),
        None => committer.allocate_contract_id(new, session),
    }
}

/// Keeps `commit` in the open batch; `false` when no batch is open.
pub(super) fn keep(commit: &TransactionCommit) -> bool {
    BATCH.with(|b| match b.borrow_mut().as_mut() {
        Some(batch) => {
            batch.commits.push(commit.clone());
            true
        }
        None => false,
    })
}

/// Keeps a commit's scan history in the open batch; `false` when no batch is open.
pub(super) fn keep_history(
    input: &crate::history::HistoryInput,
    update_id: &str,
    workflow_id: &str,
) -> bool {
    BATCH.with(|b| match b.borrow_mut().as_mut() {
        Some(batch) => {
            batch.history.push((
                input.clone(),
                update_id.to_string(),
                workflow_id.to_string(),
            ));
            true
        }
        None => false,
    })
}

/// Defers an X-Ray record until the open batch receives synchronizer commit verdict; `false` when no batch is open.
pub(super) fn keep_xray(record: &crate::observability::XRayNodeRecord) -> bool {
    BATCH.with(|b| match b.borrow_mut().as_mut() {
        Some(batch) => {
            batch.xray.push(record.clone());
            true
        }
        None => false,
    })
}
