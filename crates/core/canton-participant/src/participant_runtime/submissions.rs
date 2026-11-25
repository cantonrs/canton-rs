//! Replay detection of this participant's own requests (P-3): Canton's `SubmissionTracker` and its `SubmissionTrackerStore`.
//!
//! [CANTON-NOTE: SEMANTICS] A request whose submitter metadata names this participant is fresh iff it is sequenced by its max sequencing time
//! and it is the first request with its root hash (`SubmissionTrackerImpl.provideSubmissionData`: `amSubmitter && requestId <=
//! maxSequencingTime`, then `store.registerFreshRequest`). Otherwise the submitting participant answers every view malformed
//! (`TransactionProcessingSteps.checkReplayedTransaction`: "View %s belongs to a replayed transaction",
//! `LocalRejectError.MalformedRejects.MalformedRequest`). Other participants do not check it (`replayCheckResult = if (amSubmitter) ...`).
//!
//! What is kept (`submissions.journal`, one `<root hash hex> <request id> <max sequencing time>` line a fresh request) is written before the
//! answer, and a request read again after a restart or a rewind finds its own line: it stays fresh (the store's idempotence).
use super::Runtime;
use crate::state_store::StateStore;
use crate::view_receive::{decrypt_views, revealed_submitter_metadata};
use std::collections::BTreeMap;
use std::sync::Arc;

const JOURNAL: &str = "submissions.journal";

/// The fresh requests of this participant whose max sequencing time has not passed, by root hash: (request id, max sequencing time).
#[derive(Default)]
pub(super) struct Submissions {
    store: Option<Arc<dyn StateStore>>,
    fresh: BTreeMap<Vec<u8>, (i64, i64)>,
}

impl Submissions {
    /// What `store` keeps, without the requests whose max sequencing time is before `cursor` (no request with their root hash can be timely).
    pub(super) fn open(store: Option<Arc<dyn StateStore>>, cursor: i64) -> Result<Self, String> {
        let Some(kept) = &store else {
            return Ok(Self::default());
        };
        let journal = kept.read(JOURNAL)?.unwrap_or_default();
        let fresh: BTreeMap<Vec<u8>, (i64, i64)> = journal
            .lines()
            .filter_map(parse)
            .filter(|(_, (_, max))| *max >= cursor)
            .collect();
        if fresh.len() < journal.lines().count() {
            let text: String = fresh.iter().map(|(h, v)| record(h, *v) + "\n").collect();
            kept.write(JOURNAL, &text)?;
        }
        Ok(Submissions { store, fresh })
    }

    /// Whether the request at `request` with `root_hash` is fresh and timely; a fresh one is registered.
    fn register(
        &mut self,
        root_hash: &[u8],
        request: i64,
        max_sequencing_time: i64,
    ) -> Result<bool, String> {
        if request > max_sequencing_time {
            return Ok(false);
        }
        if let Some((first, _)) = self.fresh.get(root_hash) {
            return Ok(*first == request);
        }
        if let Some(store) = &self.store {
            store.append(JOURNAL, &record(root_hash, (request, max_sequencing_time)))?;
        }
        self.fresh
            .insert(root_hash.to_vec(), (request, max_sequencing_time));
        Ok(true)
    }

    /// Forgets the requests whose max sequencing time is before `now`.
    pub(super) fn forget(&mut self, now: i64) {
        self.fresh.retain(|_, (_, max)| *max >= now);
    }
}

fn record(root_hash: &[u8], (request, max): (i64, i64)) -> String {
    format!("{}\t{request}\t{max}", hex::encode(root_hash))
}

fn parse(line: &str) -> Option<(Vec<u8>, (i64, i64))> {
    let mut fields = line.trim_end().split('\t');
    let hash = hex::decode(fields.next()?).ok()?;
    let request = fields.next()?.parse().ok()?;
    let max = fields.next()?.parse().ok()?;
    fields.next().is_none().then_some((hash, (request, max)))
}

impl Runtime {
    /// Why this participant answers the request malformed as a replay of its own submission, if it does (see the module documentation).
    pub(super) fn replayed(
        &mut self,
        request_time: i64,
        root_hash: &[u8],
        view_envelopes: &[&[u8]],
    ) -> Result<Option<String>, String> {
        let uid = self.config.member.trim_start_matches("PAR::");
        let submitter = view_envelopes.iter().find_map(|envelope| {
            decrypt_views(
                envelope,
                &self.config.encryption_fingerprint,
                &self.config.encryption_secret,
            )
            .ok()?
            .view_trees
            .iter()
            .filter_map(|t| t.tree.as_ref())
            .find_map(|t| revealed_submitter_metadata(t).ok())
        });
        let Some(submitter) = submitter.filter(|m| m.submitting_participant_uid == uid) else {
            return Ok(None);
        };
        let fresh =
            self.submissions
                .register(root_hash, request_time, submitter.max_sequencing_time)?;
        Ok((!fresh).then(|| {
            "LOCAL_VERDICT_MALFORMED_REQUEST: the views belong to a replayed transaction"
                .to_string()
        }))
    }
}
