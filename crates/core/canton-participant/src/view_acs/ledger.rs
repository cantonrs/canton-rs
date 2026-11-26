use super::{
    decode_kind, join_creates, join_instances, kind_code, split_counters, split_creates,
    split_instances, split_list, Applied, Conflict, Effects, Journal, Ledger,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

impl Ledger {
    /// A contract set that lives only in memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// A contract set backed by the journal at `path`: created if it is not there, replayed if it is. A trailing record that is
    /// incomplete is cut off.
    pub fn open(path: &Path) -> Result<Self, String> {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let key = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("a journal path names a file")?;
        Self::open_in(crate::state_store::FileStore::new(dir)?, key)
    }

    /// A contract set backed by the journal under `key` of `store`: created if there is none, replayed if there is. A trailing record that is
    /// incomplete is cut off.
    pub fn open_in(
        store: std::sync::Arc<dyn crate::state_store::StateStore>,
        key: &str,
    ) -> Result<Self, String> {
        let text = store.read(key)?.unwrap_or_default();
        let mut ledger = Ledger::new();
        let mut good = 0usize;
        for line in text.split_inclusive('\n') {
            if !line.ends_with('\n') {
                break; // the process died while writing this record
            }
            let fields: Vec<&str> = line.trim_end_matches('\n').split('\t').collect();
            match fields.as_slice() {
                ["I", id, template] => {
                    ledger.active.insert(id.to_string(), template.to_string());
                }
                ["B", request, consumes, creates, ..] if fields.len() <= 6 => {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    let decision_time = fields
                        .get(4)
                        .and_then(|t| t.parse::<i64>().ok())
                        .unwrap_or(i64::MAX);
                    ledger.apply_begin(
                        request,
                        Effects {
                            consumes: split_list(consumes),
                            creates: split_creates(creates),
                            instances: split_instances(fields.get(5).copied()),
                            remote_events: Vec::new(),
                        },
                        decision_time,
                    );
                }
                ["BX", request, consumes, creates, decision_time, instances, kind, leaving, counters] =>
                {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    let kind = decode_kind(kind)
                        .ok_or_else(|| format!("unknown reassignment kind {kind:?}"))?;
                    ledger.apply_begin(
                        request,
                        Effects {
                            consumes: split_list(consumes),
                            creates: split_creates(creates),
                            instances: split_instances(Some(instances)),
                            remote_events: Vec::new(),
                        },
                        decision_time.parse().unwrap_or(i64::MAX),
                    );
                    ledger.reassigning.insert(
                        request,
                        (kind, split_list(leaving), split_counters(counters)),
                    );
                }
                ["F", request, consumes, creates, decision_time, ..] if fields.len() <= 6 => {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    ledger.apply_keep_refused(
                        request,
                        Effects {
                            consumes: split_list(consumes),
                            creates: split_creates(creates),
                            instances: split_instances(fields.get(5).copied()),
                            remote_events: Vec::new(),
                        },
                        decision_time.parse().unwrap_or(i64::MAX),
                    );
                }
                ["FX", request, consumes, creates, decision_time, instances, kind, leaving, counters] =>
                {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    let kind = decode_kind(kind)
                        .ok_or_else(|| format!("unknown reassignment kind {kind:?}"))?;
                    ledger.apply_keep_refused(
                        request,
                        Effects {
                            consumes: split_list(consumes),
                            creates: split_creates(creates),
                            instances: split_instances(Some(instances)),
                            remote_events: Vec::new(),
                        },
                        decision_time.parse().unwrap_or(i64::MAX),
                    );
                    ledger.reassigning.insert(
                        request,
                        (kind, split_list(leaving), split_counters(counters)),
                    );
                }
                ["X", request, kind, leaving, counters] => {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    let kind = if *kind == "U" {
                        crate::reassignment_wire::Kind::Unassignment
                    } else {
                        crate::reassignment_wire::Kind::Assignment
                    };
                    ledger.reassigning.insert(
                        request,
                        (kind, split_list(leaving), split_counters(counters)),
                    );
                }
                ["P", id] => {
                    ledger.active.remove(*id);
                    ledger.untrack_active_key(id);
                }
                ["A", request] => {
                    ledger
                        .answered
                        .insert(request.parse().map_err(|_| "a request id".to_string())?);
                }
                ["R", request, approved] => {
                    let request: i64 = request.parse().map_err(|_| "a request id".to_string())?;
                    ledger.apply_resolve(request, *approved == "1");
                    if let Some(applied) = ledger.applied.take() {
                        for id in &applied.consumed {
                            ledger.replayed_instances.remove(id);
                        }
                        ledger.replayed_instances.extend(applied.created);
                    }
                }
                _ => {
                    return Err(format!(
                        "the journal has a record that is not understood: {line:?}"
                    ))
                }
            }
            good += line.len();
        }
        if good < text.len() {
            // cut the incomplete tail so that the next record starts on its own line
            store.write(key, &text[..good])?;
        }
        ledger.journal = Some(Journal {
            store,
            key: key.to_string(),
        });
        Ok(ledger)
    }

    /// Writes `record` to the journal (if there is one) and makes it durable.
    fn write_ahead(&mut self, record: &str) -> Result<(), Conflict> {
        if let Some(journal) = self.journal.as_ref() {
            journal
                .store
                .append(&journal.key, record.trim_end_matches('\n'))
                .map_err(Conflict::Journal)?;
        }
        Ok(())
    }

    /// Whether this participant has already dealt with the request: begun it, had it decided, or answered it.
    pub fn knows_request(&self, request: i64) -> bool {
        self.pending.contains_key(&request)
            || self.refused.contains_key(&request)
            || self.decided.contains(&request)
            || self.answered.contains(&request)
    }

    /// Records, **before** the answer is sent, that the request is answered (`Ok(false)` if it was already). A participant that
    /// restarts and reads the request's event again then does not answer twice. If it dies between this record and the sending, the
    /// answer is lost and the mediator times the request out: the safe way to fail (an answer is at most once, never twice).
    pub fn mark_answered(&mut self, request: i64) -> Result<bool, Conflict> {
        if self.answered.contains(&request) {
            return Ok(false);
        }
        self.write_ahead(&format!("A\t{request}\n"))?;
        self.answered.insert(request);
        Ok(true)
    }

    pub fn is_active(&self, id: &str) -> bool {
        self.active.contains_key(id)
    }

    pub fn archived_by(&self, id: &str) -> Option<i64> {
        self.archived.get(id).copied()
    }

    pub fn active_ids(&self) -> Vec<String> {
        self.active.keys().cloned().collect()
    }

    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// The earliest request still waiting for its verdict (locked here or refused here), if any.
    pub fn earliest_in_flight(&self) -> Option<i64> {
        let locked = self.pending.keys().next().copied();
        let refused = self.refused.keys().next().copied();
        locked.into_iter().chain(refused).min()
    }

    /// Records a contract that is active from the start (an ACS import). The caller has authenticated it.
    pub fn import(&mut self, id: &str, template: &str) -> Result<(), Conflict> {
        if self.active.contains_key(id)
            || self.archived.contains_key(id)
            || self.created_by.contains_key(id)
        {
            return Err(Conflict::ContractAlreadyExists(id.to_string()));
        }
        self.write_ahead(&format!("I\t{id}\t{template}\n"))?;
        self.active.insert(id.to_string(), template.to_string());
        Ok(())
    }

    /// The request in flight that consumes `id`, if any.
    pub fn locked_by(&self, id: &str) -> Option<i64> {
        self.consumed_by.get(id).copied()
    }

    /// Removes an active contract without a transaction (a repair purge). A purged contract can be imported again.
    pub fn purge(&mut self, id: &str) -> Result<(), Conflict> {
        if let Some(&by_request) = self.consumed_by.get(id) {
            return Err(Conflict::LockedContract {
                id: id.to_string(),
                by_request,
            });
        }
        if !self.active.contains_key(id) {
            return Err(Conflict::UnknownContract(id.to_string()));
        }
        self.write_ahead(&format!("P\t{id}\n"))?;
        self.active.remove(id);
        self.untrack_active_key(id);
        Ok(())
    }

    /// Checks `effects` against the contract set and, if they are consistent, locks what they touch until the verdict (without a
    /// time limit: see [`Ledger::begin_until`]).
    pub fn begin(&mut self, request: i64, effects: Effects) -> Result<(), Conflict> {
        self.begin_until(request, effects, i64::MAX)
    }

    /// Like [`Ledger::begin`], and the request is **rejected** by [`Ledger::expire`] if its verdict is not in by `decision_time`.
    pub fn begin_until(
        &mut self,
        request: i64,
        effects: Effects,
        decision_time: i64,
    ) -> Result<(), Conflict> {
        self.begin_using(request, effects, &[], decision_time)
    }

    /// Like [`Ledger::begin_until`], and the contracts in `uses` (fetched or exercised without being consumed) must be active and not locked
    /// by another request; they are not locked by this one.
    ///
    /// [CANTON-NOTE: SEMANTICS] `UsedAndCreated.activenessSet`: `checkActive` holds every input contract of a view with a hosted informee
    /// stakeholder, `lock` only the consumed ones. A contract another request in flight archives or creates fails the check as locked
    /// (`LockableStates.checkAndLock`).
    fn validate_begin(
        &self,
        request: i64,
        effects: &Effects,
        uses: &[String],
    ) -> Result<(), Conflict> {
        if self.decided.contains(&request) {
            return Err(Conflict::RequestAlreadyDecided(request));
        }
        if self.pending.contains_key(&request) {
            return Err(Conflict::RequestAlreadyInFlight(request));
        }
        // [CANTON-NOTE: SEMANTICS] `ExtractUsedAndCreated.usedAndCreatedContracts`: the contracts created in the same transaction are
        // removed from the activeness check, and one created and consumed by it is transient (see `Ledger::apply_resolve_effects`).
        let created = effects.created_ids();
        for id in effects.consumes.iter().filter(|id| !created.contains(id)) {
            if let Some(by) = self.archived.get(id) {
                return Err(Conflict::ArchivedContract {
                    id: id.clone(),
                    by_request: *by,
                });
            }
            if let Some(by) = self.consumed_by.get(id) {
                return Err(Conflict::LockedContract {
                    id: id.clone(),
                    by_request: *by,
                });
            }
            if !self.active.contains_key(id) {
                return Err(Conflict::UnknownContract(id.clone()));
            }
        }
        for id in uses.iter().filter(|id| !created.contains(id)) {
            if let Some(by) = self.archived.get(id) {
                return Err(Conflict::ArchivedContract {
                    id: id.clone(),
                    by_request: *by,
                });
            }
            if let Some(by) = self.consumed_by.get(id).or_else(|| self.created_by.get(id)) {
                return Err(Conflict::LockedContract {
                    id: id.clone(),
                    by_request: *by,
                });
            }
            if !self.active.contains_key(id) {
                return Err(Conflict::UnknownContract(id.clone()));
            }
        }
        // [CANTON-NOTE: SEMANTICS] R-15 / `TransactionConfirmationResponsesFactory.scala:83-128`:
        // an already committed create (`active`/`archived`) is `ContractAlreadyExists`
        // (`LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS`, `isMalformed = true`), whereas a create
        // colliding only with an unresolved in-flight create (`created_by`) is `LockedContract`
        // (`LOCAL_VERDICT_LOCKED_CONTRACTS`, `isMalformed = false`).
        for (id, _) in &effects.creates {
            if self.active.contains_key(id) || self.archived.contains_key(id) {
                return Err(Conflict::ContractAlreadyExists(id.clone()));
            }
            if let Some(by) = self.created_by.get(id) {
                return Err(Conflict::LockedContract {
                    id: id.clone(),
                    by_request: *by,
                });
            }
        }
        Ok(())
    }

    pub fn begin_using(
        &mut self,
        request: i64,
        effects: Effects,
        uses: &[String],
        decision_time: i64,
    ) -> Result<(), Conflict> {
        self.validate_begin(request, &effects, uses)?;
        self.write_ahead(&format!(
            "B\t{request}\t{}\t{}\t{decision_time}\t{}\n",
            effects.consumes.join(","),
            join_creates(&effects.creates),
            join_instances(&effects.instances)
        ))?;
        self.apply_begin(request, effects, decision_time);
        Ok(())
    }

    /// Keeps the `effects` of the views of `request` this participant refused although they conform, to apply if the mediator approves the
    /// request anyway. Nothing is locked or checked against the contract set; a request begun as well applies both on approval.
    ///
    /// [CANTON-NOTE: SEMANTICS] `ProtocolProcessor` warns "Mediator approved a request that has been locally rejected" and commits:
    /// `TransactionProcessingSteps` applies the commit set of an approved request whatever this participant answered, and leaves out only
    /// what failed model conformance (`ErrorWithSubTransaction`: the valid subtransaction is committed, nothing when there is none).
    pub fn keep_refused(
        &mut self,
        request: i64,
        effects: Effects,
        decision_time: i64,
    ) -> Result<(), Conflict> {
        if self.decided.contains(&request) {
            return Err(Conflict::RequestAlreadyDecided(request));
        }
        if self.refused.contains_key(&request) {
            return Err(Conflict::RequestAlreadyInFlight(request));
        }
        self.write_ahead(&format!(
            "F\t{request}\t{}\t{}\t{decision_time}\t{}\n",
            effects.consumes.join(","),
            join_creates(&effects.creates),
            join_instances(&effects.instances)
        ))?;
        self.apply_keep_refused(request, effects, decision_time);
        Ok(())
    }

    fn apply_keep_refused(&mut self, request: i64, effects: Effects, decision_time: i64) {
        self.decision_times.entry(request).or_insert(decision_time);
        self.refused.insert(request, effects);
    }

    /// Whether `request` waits for its verdict with views this participant refused (see [`Ledger::keep_refused`]).
    pub fn refused_here(&self, request: i64) -> bool {
        self.refused.contains_key(&request)
    }

    /// Rejects every request in flight whose decision time is `now` or earlier (its verdict never came in time), frees what it
    /// locked, and returns those requests. A participant calls this with the sequencing time of each event it processes: the
    /// decision time passing without a verdict means the request is treated as rejected.
    pub fn expire(&mut self, now: i64) -> Result<Vec<i64>, Conflict> {
        let due: Vec<i64> = self
            .decision_times
            .iter()
            .filter(|(request, time)| {
                **time <= now
                    && (self.pending.contains_key(request) || self.refused.contains_key(request))
            })
            .map(|(request, _)| *request)
            .collect();
        for request in &due {
            self.resolve(*request, false)?;
        }
        Ok(due)
    }

    fn apply_begin(&mut self, request: i64, effects: Effects, decision_time: i64) {
        self.decision_times.insert(request, decision_time);
        for id in &effects.consumes {
            self.consumed_by.insert(id.clone(), request);
        }
        for (id, _) in &effects.creates {
            self.created_by.insert(id.clone(), request);
        }
        self.pending.insert(request, effects);
    }

    /// Applies the verdict of an in-flight request: on approval the contract set changes, otherwise the locks are released.
    /// Returns `Ok(false)` if no such request is in flight (a verdict for a request never begun, or decided already: it is ignored).
    pub fn resolve(&mut self, request: i64, approved: bool) -> Result<bool, Conflict> {
        if !self.pending.contains_key(&request) && !self.refused.contains_key(&request) {
            return Ok(false);
        }
        self.write_ahead(&format!("R\t{request}\t{}\n", u8::from(approved)))?;
        Ok(self.apply_resolve(request, approved))
    }

    fn apply_resolve(&mut self, request: i64, approved: bool) -> bool {
        let reassignment = self.reassigning.remove(&request);
        let resolved = self.apply_resolve_effects(request, approved);
        if let (true, true, Some((kind, leaving, counters))) = (resolved, approved, reassignment) {
            if let Some(applied) = self.applied.as_mut() {
                applied.reassignment = Some((kind, counters.clone()));
            }
            // every contract of the request has a counter: an arriving one is no longer "unassigned" here
            for (id, counter) in counters {
                self.unassigned.remove(&id);
                self.counters.insert(id, counter);
            }
            // [CANTON-NOTE: SEMANTICS] an unassigned contract is not archived: it is no longer active **here**
            for id in leaving {
                self.archived.remove(&id);
                self.unassigned.insert(id, request);
            }
        }
        resolved
    }

    /// Begins a reassignment request: an unassignment takes `leaving` off this synchronizer, an assignment brings `arriving` (id, template,
    /// serialized instance) onto it; `counters` are the reassignment counters the request sets. Locked like a transaction until the verdict.
    pub fn begin_reassignment(
        &mut self,
        request: i64,
        kind: crate::reassignment_wire::Kind,
        leaving: Vec<String>,
        arriving: Vec<(String, String, Vec<u8>)>,
        counters: Vec<(String, i64)>,
        decision_time: i64,
    ) -> Result<(), Conflict> {
        let effects = Self::reassignment_effects(&leaving, arriving);
        self.validate_begin(request, &effects, &[])?;
        let line = Self::format_reassignment_record(
            "BX",
            request,
            &effects,
            decision_time,
            kind,
            &leaving,
            &counters,
        );
        self.write_ahead(&line)?;
        self.apply_begin(request, effects, decision_time);
        self.reassigning.insert(request, (kind, leaving, counters));
        Ok(())
    }

    /// Keeps an approved-by-mediator reassignment whose Phase 3 activeness check conflicted or failed local rejection so Phase 7 still
    /// commits (`ReassignmentProcessingSteps.scala` `alarmIfActivenessCheckFailed` + commit set application).
    pub fn keep_refused_reassignment(
        &mut self,
        request: i64,
        kind: crate::reassignment_wire::Kind,
        leaving: Vec<String>,
        arriving: Vec<(String, String, Vec<u8>)>,
        counters: Vec<(String, i64)>,
        decision_time: i64,
    ) -> Result<(), Conflict> {
        if self.decided.contains(&request) {
            return Err(Conflict::RequestAlreadyDecided(request));
        }
        if self.refused.contains_key(&request) {
            return Err(Conflict::RequestAlreadyInFlight(request));
        }
        let effects = Self::reassignment_effects(&leaving, arriving);
        let line = Self::format_reassignment_record(
            "FX",
            request,
            &effects,
            decision_time,
            kind,
            &leaving,
            &counters,
        );
        self.write_ahead(&line)?;
        self.apply_keep_refused(request, effects, decision_time);
        self.reassigning.insert(request, (kind, leaving, counters));
        Ok(())
    }

    fn format_reassignment_record(
        tag: &str,
        request: i64,
        effects: &Effects,
        decision_time: i64,
        kind: crate::reassignment_wire::Kind,
        leaving: &[String],
        counters: &[(String, i64)],
    ) -> String {
        let joined_counters = counters
            .iter()
            .map(|(id, n)| format!("{id}={n}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{tag}\t{request}\t{}\t{}\t{decision_time}\t{}\t{}\t{}\t{joined_counters}\n",
            effects.consumes.join(","),
            join_creates(&effects.creates),
            join_instances(&effects.instances),
            kind_code(kind),
            leaving.join(","),
        )
    }

    fn reassignment_effects(
        leaving: &[String],
        arriving: Vec<(String, String, Vec<u8>)>,
    ) -> Effects {
        Effects {
            consumes: leaving.to_vec(),
            creates: arriving
                .iter()
                .map(|(id, t, _)| (id.clone(), t.clone()))
                .collect(),
            instances: arriving.into_iter().map(|(_, _, i)| i).collect(),
            remote_events: Vec::new(),
        }
    }

    /// The approved unassignment that took `id` off this synchronizer (while it has not come back).
    pub fn unassigned_by(&self, id: &str) -> Option<i64> {
        self.unassigned.get(id).copied()
    }

    /// The reassignment counter of `id` as this participant knows it (0 for a contract no reassignment touched).
    pub fn counter_of(&self, id: &str) -> i64 {
        self.counters.get(id).copied().unwrap_or(0)
    }

    fn apply_resolve_effects(&mut self, request: i64, approved: bool) -> bool {
        let locked = self.pending.remove(&request);
        let refused = self.refused.remove(&request);
        if locked.is_none() && refused.is_none() {
            return false;
        }
        self.decided.insert(request);
        self.decision_times.remove(&request);
        let locked = locked.unwrap_or_default();
        for id in &locked.consumes {
            self.consumed_by.remove(id);
        }
        for (id, _) in &locked.creates {
            self.created_by.remove(id);
        }
        if approved {
            let mut applied = Applied {
                request_id: request,
                consumed: Vec::new(),
                created: Vec::new(),
                reassignment: None,
                root_hash: Vec::new(),
                remote_events: Vec::new(),
            };
            let all: Vec<Effects> = std::iter::once(locked).chain(refused).collect();
            // a transient contract is archived without ever being active, and is neither created nor consumed in what was applied
            let consumed: BTreeSet<&String> = all.iter().flat_map(|e| &e.consumes).collect();
            let created: BTreeSet<&String> = all.iter().flat_map(|e| e.created_ids()).collect();
            for effects in &all {
                for (i, (id, template)) in effects.creates.iter().enumerate() {
                    if consumed.contains(id) {
                        continue;
                    }
                    if let Some(instance) = effects.instances.get(i) {
                        self.track_active_instance(id, instance);
                        applied.created.push((id.clone(), instance.clone()));
                    }
                    self.active.insert(id.clone(), template.clone());
                }
                for id in &effects.consumes {
                    self.active.remove(id);
                    self.untrack_active_key(id);
                    self.archived.insert(id.clone(), request);
                    if !created.contains(id) {
                        applied.consumed.push(id.clone());
                    }
                }
                applied
                    .remote_events
                    .extend(effects.remote_events.iter().cloned());
            }
            self.applied = Some(applied);
        }
        true
    }

    fn track_active_instance(&mut self, id: &str, instance: &[u8]) {
        use canton_proto::com::digitalasset::daml::lf::transaction::{
            FatContractInstance, Versioned,
        };
        use prost::Message;
        let Ok(v) = Versioned::decode(instance) else {
            return;
        };
        let Ok(fci) = FatContractInstance::decode(v.payload.as_slice()) else {
            return;
        };
        let Some(key) = fci.contract_key_with_maintainers.as_ref() else {
            return;
        };
        if key.hash.is_empty() {
            return;
        }
        let stakeholders = crate::view_conformance::stated_stakeholders(&fci);
        self.active_keys
            .entry(key.hash.clone())
            .or_default()
            .insert(id.to_string(), stakeholders);
        self.contract_key_hash
            .insert(id.to_string(), key.hash.clone());
    }

    pub(super) fn untrack_active_key(&mut self, id: &str) {
        if let Some(hash) = self.contract_key_hash.remove(id) {
            if let Some(entries) = self.active_keys.get_mut(&hash) {
                entries.remove(id);
                if entries.is_empty() {
                    self.active_keys.remove(&hash);
                }
            }
        }
    }

    /// Active contracts currently in this ledger whose `FatContractInstance` carried `key_hash`, as `(contract_id, stakeholders)` pairs (U-21).
    pub fn active_contracts_for_key(&self, key_hash: &[u8]) -> Vec<(String, BTreeSet<String>)> {
        self.active_keys
            .get(key_hash)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(id, _)| self.active.contains_key(*id))
                    .map(|(id, s)| (id.clone(), s.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The instances of the contracts the journal's replay left active (taken: a second call gives nothing): what an opening that lost them
    /// elsewhere takes them back from.
    pub fn take_replayed_instances(&mut self) -> BTreeMap<String, Vec<u8>> {
        let mut kept = std::mem::take(&mut self.replayed_instances);
        kept.retain(|id, _| self.active.contains_key(id));
        kept
    }

    /// What the last approved resolution changed (taken: a second call gives `None` until the next approval).
    pub fn take_applied(&mut self) -> Option<Applied> {
        self.applied.take()
    }

    /// Whether `id` is currently tracked as active, archived, or locked in flight in this ACS.
    pub fn knows_contract(&self, id: &str) -> bool {
        self.active.contains_key(id)
            || self.archived.contains_key(id)
            || self.consumed_by.contains_key(id)
    }
}
