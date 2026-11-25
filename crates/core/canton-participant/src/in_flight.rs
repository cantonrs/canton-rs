//! The submissions of this participant that are in flight, and their fate as the synchronizer's time decides it (P-7, P-13).
//!
//! [CANTON-NOTE: SEMANTICS] Canton's `InFlightSubmissionTracker` and `ProtocolProcessor`, read as a specification:
//! - A submission is registered (and kept, `InFlightSubmissionStore.register`) **before** it is sent.
//! - Until it is sequenced, it is in flight until the synchronizer's time passes its max sequencing time; then it is rejected with
//!   `NOT_SEQUENCED_TIMEOUT` (`pullTimelyRejectEvent`, `TransactionSubmissionTrackingData.TimeoutCause`).
//! - A deliver error rejects it with the sequencer's status (`observeDeliverError`).
//! - Once sequenced, its request is decided by the mediator's verdict, or times out when the decision time passes without one
//!   (`handleTimeout`, `LocalRejectError.TimeRejects.LocalTimeout`: `LOCAL_VERDICT_TIMEOUT`).
//! - Nothing here looks at a wall clock: how long a caller waits is not the submission's fate (`SubmissionTracker.timedOut` answers the
//!   caller with `REQUEST_TIME_OUT` and leaves the command in flight).
//!
//! The table is changed only while an event is handled (`Runtime::handle`), before the cursor moves past that event, so a restart neither
//! loses a receipt or a verdict nor sees one twice. What it keeps (`in-flight.journal`, one record a line):
//! - `S <message id> <max sequencing time> <tag>`: registered, before it is sent,
//! - `Q <message id> <request id>`: sequenced,
//! - `V <message id> <1|0> <request id|-> <notes>`: its fate, for nobody waiting on it yet,
//! - `D <message id>`: done (its fate went to whoever waits for it, or the submission was never sent).
//!
//! The tag and the notes are hex: the caller's tag says what the submission was for (who to tell about its fate after a restart).
use crate::node::{Verdict, REJECTION_CONTEXT_NOTE, REJECTION_NOTE};
use crate::participant_runtime::Step;
use crate::state_store::StateStore;
use crate::view_acs::Timeouts;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The store key of the in-flight table.
pub const JOURNAL: &str = "in-flight.journal";

/// The status of a submission that was not sequenced by its max sequencing time (`SubmissionErrors.TimeoutError`, category
/// `ContentionOnSharedResources`: gRPC `ABORTED`), as a [`REJECTION_NOTE`] carries it.
pub const NOT_SEQUENCED_TIMEOUT: &str = "10:NOT_SEQUENCED_TIMEOUT(2,0): Transaction was not sequenced within the pre-defined max sequencing time and has therefore timed out";

/// The status of a sequenced request whose decision time passed without a verdict (`LocalRejectError.TimeRejects.LocalTimeout`), as a
/// [`REJECTION_NOTE`] carries it. The trailing space is Canton's (`_causePrefix` with no details).
pub const LOCAL_VERDICT_TIMEOUT: &str =
    "10:LOCAL_VERDICT_TIMEOUT(2,0): Rejected transaction due to a participant determined timeout ";

/// A submission whose fate is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub message_id: String,
    /// What the submitter said the submission is for (see [`InFlight::register`]).
    pub tag: String,
    /// The request's sequencing time, when it was sequenced.
    pub request_id: Option<i64>,
    pub verdict: Verdict,
    /// Why it was rejected (a [`REJECTION_NOTE`]), and what the runtime set aside while it was in flight.
    pub notes: Vec<String>,
    /// Whether a caller still waited for it when its fate became known (it was then not kept for later).
    pub awaited: bool,
}

#[derive(Debug)]
struct Entry {
    max_sequencing_time: i64,
    tag: String,
    request_id: Option<i64>,
    notes: Vec<String>,
    /// A caller waits for the fate (in memory only: after a restart nobody does).
    awaited: bool,
}

/// The submissions in flight, and the fates nobody has taken yet.
#[derive(Default)]
pub struct InFlight {
    entries: BTreeMap<String, Entry>,
    settled: BTreeMap<String, Settled>,
    store: Option<Arc<dyn StateStore>>,
    /// Whether the fate of an awaited submission is kept (`V`) until it is taken, as an unawaited one is (see
    /// [`InFlight::keep_awaited_until_taken`]).
    hold_awaited: bool,
}

impl InFlight {
    /// The table kept under [`JOURNAL`] of `store` (in memory when `None`), as the journal left it. The journal is rewritten without what is
    /// done.
    pub fn open(store: Option<Arc<dyn StateStore>>) -> Result<Self, String> {
        let mut table = InFlight {
            store,
            ..Default::default()
        };
        let Some(store) = table.store.clone() else {
            return Ok(table);
        };
        let text = store.read(JOURNAL)?.unwrap_or_default();
        let mut done = 0usize;
        for line in text.split_inclusive('\n') {
            // [CANTON-NOTE: INVARIANT] A record the process died writing has no newline: it never happened (a registration that was not
            // kept was not sent either).
            let Some(line) = line.strip_suffix('\n') else {
                break;
            };
            match line.split('\t').collect::<Vec<_>>().as_slice() {
                ["S", id, max, tag] => {
                    if let (Ok(max), Some(tag)) = (max.parse(), unhex(tag)) {
                        table.entries.insert(id.to_string(), Entry::new(max, tag));
                    }
                }
                ["Q", id, request] => {
                    if let (Some(e), Ok(r)) = (table.entries.get_mut(*id), request.parse()) {
                        e.request_id = Some(r);
                    }
                }
                ["V", id, approved, request, notes] => {
                    if let Some(e) = table.entries.remove(*id) {
                        table.settled.insert(
                            id.to_string(),
                            Settled {
                                message_id: id.to_string(),
                                tag: e.tag,
                                request_id: request.parse().ok(),
                                verdict: verdict_of(*approved == "1"),
                                notes: notes.split(',').filter_map(unhex).collect(),
                                awaited: false,
                            },
                        );
                    }
                }
                ["D", id] => {
                    table.entries.remove(*id);
                    table.settled.remove(*id);
                    done += 1;
                }
                _ => {}
            }
        }
        if done > 0 || !text.is_empty() && !text.ends_with('\n') {
            store.write(JOURNAL, &table.records())?;
        }
        Ok(table)
    }

    /// What the journal must hold for the table as it is now.
    fn records(&self) -> String {
        let mut text = String::new();
        for (id, e) in &self.entries {
            text.push_str(&format!(
                "S\t{id}\t{}\t{}\n",
                e.max_sequencing_time,
                hex::encode(&e.tag)
            ));
            if let Some(r) = e.request_id {
                text.push_str(&format!("Q\t{id}\t{r}\n"));
            }
        }
        for s in self.settled.values() {
            text.push_str(&format!("{}\n", fate_record(s)));
        }
        text
    }

    fn write(&self, record: &str) -> Result<(), String> {
        match &self.store {
            Some(store) => store.append(JOURNAL, record),
            None => Ok(()),
        }
    }

    /// Registers `message_id` as sent with `max_sequencing_time` (the synchronizer's time after which it can no longer be sequenced), a caller
    /// waiting for it. Kept before it is sent: a registration that is never sent is rejected once that time has passed, as Canton does.
    pub fn register(
        &mut self,
        message_id: &str,
        max_sequencing_time: i64,
        tag: &str,
    ) -> Result<(), String> {
        if message_id.contains(['\t', '\n']) || self.entries.contains_key(message_id) {
            return Err(format!(
                "the submission {message_id:?} cannot be tracked in flight"
            ));
        }
        self.write(&format!(
            "S\t{message_id}\t{max_sequencing_time}\t{}",
            hex::encode(tag)
        ))?;
        let mut entry = Entry::new(max_sequencing_time, tag.to_string());
        entry.awaited = true;
        self.entries.insert(message_id.to_string(), entry);
        Ok(())
    }

    /// From now on the fate of an awaited submission is kept like an unawaited one until [`InFlight::take_settled`] marks it done, instead of
    /// being done as soon as the waiter gets it.
    ///
    /// [CANTON-NOTE: WHY] P-13: the waiter (the JSON API's command service) records the fate after the runtime decided it. A crash between the
    /// two lost the completion and the transaction; held, the fate is handed over again after the restart (`settled_unawaited`), and the
    /// taker's record of it makes the second hand-over a no-op (`protocol_late::settle` finds the completion).
    pub fn keep_awaited_until_taken(&mut self) {
        self.hold_awaited = true;
    }

    /// Forgets a registration whose submission was not sent after all.
    pub fn cancel(&mut self, message_id: &str) -> Result<(), String> {
        if self.entries.remove(message_id).is_some() {
            self.write(&format!("D\t{message_id}"))?;
        }
        Ok(())
    }

    /// Nobody waits for `message_id` any more: its fate is kept for [`InFlight::take_settled`]. `false` when it is not in flight.
    pub fn stop_awaiting(&mut self, message_id: &str) -> bool {
        match self.entries.get_mut(message_id) {
            Some(e) => {
                e.awaited = false;
                true
            }
            None => false,
        }
    }

    /// The fates kept for nobody (after a restart, or after the caller stopped waiting), oldest submission first.
    pub fn settled_unawaited(&self) -> Vec<Settled> {
        self.settled
            .values()
            .filter(|s| !s.awaited)
            .cloned()
            .collect()
    }

    /// The kept fate of `message_id` was handed over: it is done.
    pub fn take_settled(&mut self, message_id: &str) -> Result<(), String> {
        if self.settled.remove(message_id).is_some() {
            self.write(&format!("D\t{message_id}"))?;
        }
        Ok(())
    }

    /// How many submissions are in flight.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The earliest time of the synchronizer the participant has to observe to learn a fate that no event may bring (a time proof is asked
    /// for it, see `sequencer_time`): past the max sequencing time of a submission not sequenced yet, the decision time of a request.
    pub fn wanted_time(&self, timeouts: &Timeouts) -> Option<i64> {
        self.entries
            .values()
            .map(|e| match e.request_id {
                Some(r) => timeouts.decision_time(r),
                None => e.max_sequencing_time.saturating_add(1),
            })
            .min()
    }

    /// What the event handled at `now` (its step so far) decides about the submissions in flight. Kept before the cursor moves past the
    /// event. Returns the submissions whose fate it decided.
    pub fn observe(
        &mut self,
        step: &Step,
        now: i64,
        timeouts: &Timeouts,
    ) -> Result<Vec<Settled>, String> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen = step.notes.clone();
        for answer in &step.to_send {
            seen.push(format!(
                "answered {} with {:?}",
                answer.request_time,
                answer
                    .decisions
                    .iter()
                    .map(|d| &d.outcome)
                    .collect::<Vec<_>>()
            ));
        }
        for e in self.entries.values_mut() {
            e.notes.extend(seen.iter().cloned());
        }
        for (id, at) in &step.own_requests {
            if let Some(e) = self.entries.get_mut(id) {
                if e.request_id.is_none() {
                    if let Some(store) = &self.store {
                        store.append(JOURNAL, &format!("Q\t{id}\t{at}"))?;
                    }
                    e.request_id = Some(*at);
                }
            }
        }
        // why the mediator rejected a request (the refusing participant's error): the status the submission fails with
        for (request, code, message) in &step.rejections {
            self.note_request(*request, format!("{REJECTION_NOTE}{code}:{message}"));
        }
        for (request, json) in &step.rejection_contexts {
            self.note_request(*request, format!("{REJECTION_CONTEXT_NOTE}{json}"));
        }
        let mut decided: Vec<(String, Verdict, Option<String>)> = Vec::new();
        for (id, code, message) in &step.deliver_errors {
            if self.entries.contains_key(id) {
                decided.push((
                    id.clone(),
                    Verdict::Rejected,
                    Some(format!("{REJECTION_NOTE}{code}:{message}")),
                ));
            }
        }
        // a verdict on a request kept in flight, or on one this participant rejected itself and so never kept
        for (request, approved) in step.verdicts.iter().chain(&step.unresolved_verdicts) {
            if let Some(id) = self.message_of(*request) {
                decided.push((id, verdict_of(*approved), None));
            }
        }
        // [CANTON-NOTE: SEMANTICS] After the event's verdicts: a verdict sequenced at the decision time itself still counts (`resultTs <=
        // decisionTime`); a submission can still be sequenced at its max sequencing time.
        for (id, e) in &self.entries {
            if decided.iter().any(|(d, _, _)| d == id) {
                continue;
            }
            let timed_out = match e.request_id {
                Some(r) => (timeouts.decision_time(r) <= now).then_some(LOCAL_VERDICT_TIMEOUT),
                None => (e.max_sequencing_time < now).then_some(NOT_SEQUENCED_TIMEOUT),
            };
            if let Some(status) = timed_out {
                decided.push((
                    id.clone(),
                    Verdict::Rejected,
                    Some(format!("{REJECTION_NOTE}{status}")),
                ));
            }
        }
        let mut out = Vec::new();
        for (id, verdict, note) in decided {
            let Some(mut e) = self.entries.remove(&id) else {
                continue;
            };
            e.notes.extend(note);
            let settled = Settled {
                message_id: id.clone(),
                tag: e.tag,
                request_id: e.request_id,
                verdict,
                notes: e.notes,
                awaited: e.awaited,
            };
            if settled.awaited && !self.hold_awaited {
                self.write(&format!("D\t{id}"))?;
            } else {
                self.write(&fate_record(&settled))?;
                self.settled.insert(id, settled.clone());
            }
            out.push(settled);
        }
        Ok(out)
    }

    fn message_of(&self, request: i64) -> Option<String> {
        self.entries
            .iter()
            .find(|(_, e)| e.request_id == Some(request))
            .map(|(id, _)| id.clone())
    }

    fn note_request(&mut self, request: i64, note: String) {
        for e in self.entries.values_mut() {
            if e.request_id == Some(request) {
                e.notes.push(note.clone());
            }
        }
    }
}

impl Entry {
    fn new(max_sequencing_time: i64, tag: String) -> Self {
        Entry {
            max_sequencing_time,
            tag,
            request_id: None,
            notes: Vec::new(),
            awaited: false,
        }
    }
}

fn verdict_of(approved: bool) -> Verdict {
    if approved {
        Verdict::Approved
    } else {
        Verdict::Rejected
    }
}

/// The `V` record of a fate. Only the notes the status is read from are kept (what the runtime set aside is for a caller that waits).
fn fate_record(s: &Settled) -> String {
    let notes: Vec<String> = s
        .notes
        .iter()
        .filter(|n| n.starts_with(REJECTION_NOTE) || n.starts_with(REJECTION_CONTEXT_NOTE))
        .map(hex::encode)
        .collect();
    format!(
        "V\t{}\t{}\t{}\t{}",
        s.message_id,
        u8::from(s.verdict == Verdict::Approved),
        s.request_id.map_or("-".to_string(), |r| r.to_string()),
        notes.join(",")
    )
}

fn unhex(text: &str) -> Option<String> {
    String::from_utf8(hex::decode(text).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::FileStore;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("in-flight-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn timeouts() -> Timeouts {
        Timeouts {
            confirmation_response_micros: 10,
            mediator_reaction_micros: 10,
        }
    }

    fn sequenced(id: &str, at: i64) -> Step {
        Step {
            own_requests: vec![(id.to_string(), at)],
            ..Default::default()
        }
    }

    fn verdict(request: i64, approved: bool) -> Step {
        Step {
            verdicts: vec![(request, approved)],
            ..Default::default()
        }
    }

    fn status(s: &Settled) -> Option<&str> {
        s.notes.iter().find_map(|n| n.strip_prefix(REJECTION_NOTE))
    }

    /// P-13: with the fates of awaited submissions held until taken, a crash after the fate is known but before whoever waited recorded it
    /// hands the fate over again after the restart; once taken it is not.
    #[test]
    fn a_held_awaited_fate_survives_a_restart_until_it_is_taken() {
        let dir = temp_dir("held");
        let store = || Some(FileStore::new(&dir).unwrap() as Arc<dyn StateStore>);
        let mut table = InFlight::open(store()).unwrap();
        table.keep_awaited_until_taken();
        table.register("m", 100, "tag").unwrap();
        table.observe(&sequenced("m", 50), 50, &timeouts()).unwrap();
        let fates = table.observe(&verdict(50, true), 60, &timeouts()).unwrap();
        assert!(fates[0].awaited, "the waiter gets it");
        assert!(
            table.settled_unawaited().is_empty(),
            "not handed over twice while running"
        );
        drop(table);
        let mut table = InFlight::open(store()).unwrap();
        let again = table.settled_unawaited();
        assert_eq!(again.len(), 1, "handed over again after the restart");
        assert_eq!(
            (again[0].verdict, again[0].request_id),
            (Verdict::Approved, Some(50))
        );
        table.take_settled("m").unwrap();
        drop(table);
        assert!(InFlight::open(store())
            .unwrap()
            .settled_unawaited()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_submission_not_sequenced_by_its_max_sequencing_time_is_rejected_once_the_time_is_past_it()
    {
        let mut table = InFlight::open(None).unwrap();
        table.register("m", 100, "").unwrap();
        assert!(table
            .observe(&Step::default(), 100, &timeouts())
            .unwrap()
            .is_empty());
        let fates = table.observe(&Step::default(), 101, &timeouts()).unwrap();
        assert_eq!(fates.len(), 1);
        assert_eq!(fates[0].verdict, Verdict::Rejected);
        assert_eq!(status(&fates[0]), Some(NOT_SEQUENCED_TIMEOUT));
        assert!(table.is_empty());
    }

    #[test]
    fn a_sequenced_submission_is_decided_by_its_verdict_or_times_out_at_its_decision_time() {
        let mut table = InFlight::open(None).unwrap();
        table.register("approved", 100, "").unwrap();
        table.register("silent", 100, "").unwrap();
        table
            .observe(&sequenced("approved", 50), 50, &timeouts())
            .unwrap();
        table
            .observe(&sequenced("silent", 60), 60, &timeouts())
            .unwrap();
        // the max sequencing time passing changes nothing for a sequenced request
        assert!(table
            .observe(&Step::default(), 69, &timeouts())
            .unwrap()
            .is_empty());
        let fates = table.observe(&verdict(50, true), 70, &timeouts()).unwrap();
        assert_eq!(fates.len(), 1);
        assert_eq!(
            (
                fates[0].message_id.as_str(),
                fates[0].verdict,
                fates[0].request_id
            ),
            ("approved", Verdict::Approved, Some(50))
        );
        let fates = table.observe(&Step::default(), 80, &timeouts()).unwrap();
        assert_eq!(fates.len(), 1);
        assert_eq!(status(&fates[0]), Some(LOCAL_VERDICT_TIMEOUT));
    }

    #[test]
    fn a_verdict_at_the_decision_time_is_taken_before_the_timeout() {
        let mut table = InFlight::open(None).unwrap();
        table.register("m", 100, "").unwrap();
        table.observe(&sequenced("m", 50), 50, &timeouts()).unwrap();
        let fates = table.observe(&verdict(50, true), 70, &timeouts()).unwrap();
        assert_eq!(fates[0].verdict, Verdict::Approved);
    }

    #[test]
    fn a_deliver_error_rejects_with_the_sequencer_status() {
        let mut table = InFlight::open(None).unwrap();
        table.register("m", 100, "").unwrap();
        let step = Step {
            deliver_errors: vec![("m".into(), 9, "SEQUENCER_X(9,0): no".into())],
            ..Default::default()
        };
        let fates = table.observe(&step, 10, &timeouts()).unwrap();
        assert_eq!(status(&fates[0]), Some("9:SEQUENCER_X(9,0): no"));
    }

    #[test]
    fn the_table_and_the_fates_nobody_took_survive_a_restart() {
        let dir = temp_dir("restart");
        let store = || Some(FileStore::new(&dir).unwrap() as Arc<dyn StateStore>);
        let mut table = InFlight::open(store()).unwrap();
        table.register("taken", 100, "a").unwrap();
        table.register("left", 100, "b").unwrap();
        table.register("open", 100, "c\tline").unwrap();
        table
            .observe(&sequenced("left", 40), 40, &timeouts())
            .unwrap();
        table
            .observe(&sequenced("open", 45), 45, &timeouts())
            .unwrap();
        assert!(table.stop_awaiting("left"));
        table
            .observe(
                &Step {
                    rejections: vec![(40, 5, "LOCAL_VERDICT_X(11,0): gone".into())],
                    verdicts: vec![(40, false)],
                    ..Default::default()
                },
                50,
                &timeouts(),
            )
            .unwrap();
        drop(table);

        let mut again = InFlight::open(store()).unwrap();
        // the caller that waited is gone: the open submission is nobody's, and still decided by the synchronizer's time
        let kept = again.settled_unawaited();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].message_id, "left");
        assert_eq!(kept[0].tag, "b");
        assert_eq!(status(&kept[0]), Some("5:LOCAL_VERDICT_X(11,0): gone"));
        assert_eq!(again.len(), 2, "taken and open are in flight");
        let fates = again.observe(&verdict(45, true), 60, &timeouts()).unwrap();
        assert_eq!(fates[0].message_id, "open");
        assert_eq!(fates[0].tag, "c\tline");
        assert!(!fates[0].awaited);
        again.take_settled("left").unwrap();
        drop(again);

        let last = InFlight::open(store()).unwrap();
        let kept: Vec<String> = last
            .settled_unawaited()
            .into_iter()
            .map(|s| s.message_id)
            .collect();
        assert_eq!(kept, vec!["open".to_string()]);
        assert_eq!(last.len(), 1, "taken is still in flight");
        assert_eq!(
            last.wanted_time(&timeouts()),
            Some(101),
            "past its max sequencing time"
        );
    }

    #[test]
    fn a_registration_the_process_died_writing_never_happened() {
        let dir = temp_dir("torn");
        let store = FileStore::new(&dir).unwrap() as Arc<dyn StateStore>;
        store.append(JOURNAL, "S\tkept\t100\t").unwrap();
        store.write(JOURNAL, "S\tkept\t100\t\nS\thalf\t1").unwrap();
        let table = InFlight::open(Some(Arc::clone(&store))).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(
            store.read(JOURNAL).unwrap().unwrap(),
            "S\tkept\t100\t\n",
            "the torn record is cut"
        );
    }
}
