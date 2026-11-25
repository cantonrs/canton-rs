//! `CantonExEx` — Privacy-Scoped In-Process Execution Extensions (`reth` ExEx model adapted to
//! Canton 3.7.2 Sub-transaction Privacy).
//!
//! [CANTON-NOTE: INVARIANT]
//! 1. Zero hot-path overhead when no ExEx is registered (`active_count.load(Ordering::Relaxed) == 0`).
//! 2. Non-blocking `try_send` delivery: slow extensions increment `dropped_notifications` and NEVER
//!    stall ledger commit or BFT ordering threads.
//! 3. Sub-transaction Privacy enforcement:
//!    - `ExExPartyScope::Parties(allowlist)` strips every contract event whose stakeholders/witnesses
//!      do not intersect `allowlist`, and drops the notification altogether if zero visible events remain.
//!    - `ExExPartyScope::ZeroPayloadMetadata` redacts `create_arguments` (`None`) on every event while
//!      retaining `payload_sha256` and `payload_bytes`, preserving a strict zero-knowledge boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::v2_commands::StoredUpdate;

/// Visibility & privacy boundary enforced by the node BEFORE handing events to an ExEx.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "parties", rename_all = "snake_case")]
pub enum ExExPartyScope {
    /// Participant operator scope: receives all events visible to this participant node.
    AllParticipantVisible,
    /// Strict party allowlist: receives ONLY events where at least one stakeholder/witness is in the set.
    Parties(BTreeSet<String>),
    /// Combined allowlist + zero-payload metadata: receives only events visible to the allowlisted parties
    /// with all `create_arguments` stripped (`None`).
    PartiesZeroPayload(BTreeSet<String>),
    /// Zero-payload metadata scope: receives event headers, template IDs, byte sizes, and keyed payload digests
    /// with `create_arguments` unconditionally stripped (`None`).
    ZeroPayloadMetadata,
}

impl ExExPartyScope {
    /// Human-readable summary label for `/_exex` telemetry and `daemon top`.
    pub fn summary_label(&self) -> String {
        let format_parties = |prefix: &str, ps: &BTreeSet<String>| {
            let joined: Vec<&str> = ps.iter().map(String::as_str).take(3).collect();
            if ps.len() > 3 {
                format!("{prefix}({}+{})", joined.join(","), ps.len() - 3)
            } else {
                format!("{prefix}({})", joined.join(","))
            }
        };
        match self {
            Self::AllParticipantVisible => "all_participant_visible".to_string(),
            Self::Parties(ps) => format_parties("parties", ps),
            Self::PartiesZeroPayload(ps) => format_parties("parties_zero_payload", ps),
            Self::ZeroPayloadMetadata => "zero_payload_metadata".to_string(),
        }
    }
}

/// Shared participant-side transaction/commit digest used for ExEx `root_hash` and X-Ray participant estimates.
pub fn participant_tx_digest(update_id: &str, offset: u64, event_contract_ids: &[&str]) -> String {
    let mut hasher = Sha256::new();
    if !update_id.is_empty() {
        hasher.update(update_id.as_bytes());
    }
    if offset > 0 {
        hasher.update(offset.to_be_bytes());
    }
    for cid in event_contract_ids {
        hasher.update(cid.as_bytes());
    }
    let full_hex = hex::encode(hasher.finalize());
    format!("1220{}", &full_hex[..24])
}

/// Single contract lifecycle event delivered inside an [`ExExNotification::Committed`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExExContractEvent {
    Created {
        contract_id: String,
        package_id: String,
        template_id: String,
        stakeholders: BTreeSet<String>,
        witnesses: BTreeSet<String>,
        payload_bytes: usize,
        payload_sha256: String,
        /// `None` when running under [`ExExPartyScope::ZeroPayloadMetadata`].
        create_arguments: Option<serde_json::Value>,
    },
    Archived {
        contract_id: String,
        package_id: String,
        template_id: String,
        choice_name: Option<String>,
        consuming: bool,
        stakeholders: BTreeSet<String>,
        witnesses: BTreeSet<String>,
    },
}

impl ExExContractEvent {
    fn is_visible_to(&self, allowed: &BTreeSet<String>) -> bool {
        let (stakeholders, witnesses) = match self {
            Self::Created {
                stakeholders,
                witnesses,
                ..
            }
            | Self::Archived {
                stakeholders,
                witnesses,
                ..
            } => (stakeholders, witnesses),
        };
        stakeholders.iter().any(|p| allowed.contains(p))
            || witnesses.iter().any(|p| allowed.contains(p))
    }

    fn strip_payload(&mut self) {
        if let Self::Created {
            create_arguments, ..
        } = self
        {
            *create_arguments = None;
        }
    }
}

/// Real-time post-commit / post-prune notification pushed to in-process extensions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "notification", rename_all = "snake_case")]
pub enum ExExNotification {
    Committed {
        #[serde(default)]
        seq: u64,
        #[serde(default)]
        dropped_since_last: u64,
        offset: u64,
        update_id: String,
        command_id: String,
        synchronizer_id: String,
        effective_at: String,
        committed_at_micros: i64,
        root_hash: String,
        events: Vec<ExExContractEvent>,
    },
    PrunedUpTo {
        offset: u64,
    },
}

/// Zero-payload telemetry snapshot for a single registered [`CantonExEx`] subscriber.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExExSubscriberStats {
    pub name: String,
    pub scope: String,
    pub delivered_notifications: u64,
    pub filtered_out_events: u64,
    pub dropped_notifications: u64,
    #[serde(default)]
    pub write_errors: u64,
    pub connected: bool,
}

struct RegisteredExEx {
    name: String,
    scope: ExExPartyScope,
    sender: mpsc::SyncSender<ExExNotification>,
    delivered: Arc<AtomicU64>,
    filtered_out: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    write_errors: Arc<AtomicU64>,
    connected: Arc<AtomicBool>,
    next_seq: AtomicU64,
    pending_dropped: Arc<AtomicU64>,
}

/// Thread-safe, lock-free-gated registry of in-process [`CantonExEx`] subscribers.
pub struct ExExHub {
    active_count: AtomicUsize,
    subscribers: Mutex<Vec<RegisteredExEx>>,
    payload_hmac_key: hmac::Key,
}

impl ExExHub {
    /// Creates an empty extension hub with zero hot-path overhead and a per-instance CSPRNG HMAC key.
    /// Fails closed if the OS CSPRNG fails rather than deriving a predictable fallback key.
    pub fn try_new() -> Result<Self, String> {
        let rng = SystemRandom::new();
        Self::try_new_with_rng(|buf| {
            rng.fill(buf)
                .map_err(|_| "system CSPRNG failed to generate 32-byte ExEx HMAC key")
        })
    }

    /// Creates an empty extension hub using a caller-supplied entropy fill closure.
    pub fn try_new_with_rng<E: std::fmt::Display>(
        fill_key: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, String> {
        let mut raw_key = [0u8; 32];
        fill_key(&mut raw_key).map_err(|e| format!("cannot initialize ExEx HMAC key: {e}"))?;
        Ok(Self {
            active_count: AtomicUsize::new(0),
            subscribers: Mutex::new(Vec::new()),
            payload_hmac_key: hmac::Key::new(hmac::HMAC_SHA256, &raw_key),
        })
    }

    /// Fast relaxed check used by commit paths to skip notification construction when idle.
    #[inline]
    pub fn has_subscribers(&self) -> bool {
        self.active_count.load(Ordering::Relaxed) > 0
    }

    fn register_channel_with_seq(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        capacity: usize,
        initial_seq: u64,
    ) -> (
        mpsc::Receiver<ExExNotification>,
        Arc<AtomicU64>,
        Arc<AtomicBool>,
    ) {
        let cap = capacity.max(1);
        let (tx, rx) = mpsc::sync_channel(cap);
        let write_errors = Arc::new(AtomicU64::new(0));
        let connected = Arc::new(AtomicBool::new(true));
        let entry = RegisteredExEx {
            name: name.into(),
            scope,
            sender: tx,
            delivered: Arc::new(AtomicU64::new(initial_seq)),
            filtered_out: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            write_errors: Arc::clone(&write_errors),
            connected: Arc::clone(&connected),
            next_seq: AtomicU64::new(initial_seq),
            pending_dropped: Arc::new(AtomicU64::new(0)),
        };
        let mut guard = self
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.push(entry);
        self.active_count.store(guard.len(), Ordering::SeqCst);
        (rx, write_errors, connected)
    }

    fn register_channel_internal(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        capacity: usize,
    ) -> (
        mpsc::Receiver<ExExNotification>,
        Arc<AtomicU64>,
        Arc<AtomicBool>,
    ) {
        self.register_channel_with_seq(name, scope, capacity, 0)
    }

    /// Registers an in-process bounded channel extension (`capacity` >= 1).
    pub fn register_channel(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        capacity: usize,
    ) -> mpsc::Receiver<ExExNotification> {
        self.register_channel_internal(name, scope, capacity).0
    }

    fn open_jsonl_file(target: &Path) -> Result<std::fs::File, String> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(target)
            .map_err(|e| format!("cannot open ExEx JSONL output {}: {e}", target.display()))
    }

    fn write_jsonl_notif(
        file: &mut std::fs::File,
        notif: &ExExNotification,
        write_errors: &AtomicU64,
    ) {
        match serde_json::to_string(notif) {
            Ok(line) => {
                if writeln!(file, "{line}").is_err() || file.flush().is_err() {
                    write_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                write_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Installs a background dedicated-OS-thread JSONL file sink ExEx (`--exex-jsonl`, `0o600` on Unix).
    pub fn register_jsonl_file_sink(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        path: &Path,
        capacity: usize,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create ExEx parent dir {}: {e}", parent.display()))?;
        }
        // Verify we can open the file upfront before spawning background writer.
        let mut file = Self::open_jsonl_file(path)?;

        let (rx, write_errors, connected) = self.register_channel_internal(name, scope, capacity);
        std::thread::spawn(move || {
            while let Ok(notif) = rx.recv() {
                Self::write_jsonl_notif(&mut file, &notif, &write_errors);
            }
            connected.store(false, Ordering::Relaxed);
        });
        Ok(())
    }

    /// Registers a JSONL ExEx file sink with optional atomic backfill snapshot (`--exex-from-offset`), releasing
    /// `commit_publish_lock` BEFORE opening/writing on a dedicated OS writer thread.
    ///
    /// [CANTON-NOTE: WHY] Holding `commit_publish_lock` across `OpenOptions::open` (e.g. a slow mount or FIFO) or
    /// blocking `SyncSender::send` during backfill would stall commits and violate non-blocking async/worker rules;
    /// we snapshot historical updates in memory under the brief lock and stream both backfill and live events on the OS writer thread.
    pub(crate) fn register_jsonl_file_sink_with_backfill(
        &self,
        name: impl Into<String>,
        scope: ExExPartyScope,
        path: &Path,
        capacity: usize,
        from_offset: Option<u64>,
        state: &crate::v2::V2State,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create ExEx parent dir {}: {e}", parent.display()))?;
        }
        let is_fifo = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_fifo())
            }
            #[cfg(not(unix))]
            {
                false
            }
        };
        // Pre-open regular/non-FIFO paths synchronously BEFORE acquiring `commit_publish_lock` so
        // directory/permission errors fail startup loudly while FIFOs still defer open to the OS thread.
        let preopened = if is_fifo {
            None
        } else {
            Some(Self::open_jsonl_file(path)?)
        };
        let target: PathBuf = path.to_path_buf();
        let (backfill, rx, write_errors, connected) = {
            let _publish_guard = state
                .commit_publish_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let backfill = match from_offset {
                Some(from) => {
                    let sync_id = state.synchronizer_id();
                    let updates = state.updates();
                    self.backfill_stored_updates(&sync_id, &updates, from, &scope)
                }
                None => Vec::new(),
            };
            let initial_seq = u64::try_from(backfill.len()).unwrap_or(0);
            let (rx, write_errors, connected) =
                self.register_channel_with_seq(name, scope, capacity, initial_seq);
            (backfill, rx, write_errors, connected)
        };
        std::thread::spawn(move || {
            let mut file = match preopened {
                Some(file) => file,
                None => match Self::open_jsonl_file(&target) {
                    Ok(file) => file,
                    Err(_) => {
                        write_errors.fetch_add(1, Ordering::Relaxed);
                        connected.store(false, Ordering::Relaxed);
                        return;
                    }
                },
            };
            for notif in &backfill {
                Self::write_jsonl_notif(&mut file, notif, &write_errors);
            }
            while let Ok(notif) = rx.recv() {
                Self::write_jsonl_notif(&mut file, &notif, &write_errors);
            }
            connected.store(false, Ordering::Relaxed);
        });
        Ok(())
    }

    /// Computes keyed HMAC-SHA256 hex digest for canonical contract payload bytes.
    #[cfg(test)]
    pub(crate) fn keyed_payload_digest(&self, canonical_bytes: &[u8]) -> String {
        hex::encode(hmac::sign(&self.payload_hmac_key, canonical_bytes).as_ref())
    }

    /// Converts and publishes a committed `StoredUpdate` to all active extensions with privacy scoping.
    pub(crate) fn publish_stored_update(&self, synchronizer_id: &str, update: &StoredUpdate) {
        if update.topology.is_some() || !self.has_subscribers() {
            return;
        }
        let base_notif = build_notification_from_stored_update(
            synchronizer_id,
            update,
            Some(&self.payload_hmac_key),
        );
        self.dispatch_notification_with_act_as(&base_notif, Some(&update.act_as));
    }

    /// Replays historical updates (`offset >= from_offset`) to a list of notifications filtered by `scope`.
    pub(crate) fn backfill_stored_updates(
        &self,
        synchronizer_id: &str,
        updates: &[StoredUpdate],
        from_offset: u64,
        scope: &ExExPartyScope,
    ) -> Vec<ExExNotification> {
        let mut out = Vec::new();
        for u in updates {
            if u.offset < from_offset || u.topology.is_some() {
                continue;
            }
            let base = build_notification_from_stored_update(
                synchronizer_id,
                u,
                Some(&self.payload_hmac_key),
            );
            if let Some((mut scoped, _filtered)) = apply_scope(&base, scope, Some(&u.act_as)) {
                if let ExExNotification::Committed { seq, .. } = &mut scoped {
                    *seq = (out.len() + 1) as u64;
                }
                out.push(scoped);
            }
        }
        out
    }

    /// Replays historical updates directly through live registered subscribers (`offset >= from_offset`) with blocking backpressure.
    #[cfg(test)]
    pub(crate) fn replay_updates_to_subscribers(
        &self,
        synchronizer_id: &str,
        updates: &[StoredUpdate],
        from_offset: u64,
    ) {
        if !self.has_subscribers() {
            return;
        }
        for u in updates {
            if u.offset >= from_offset && u.topology.is_none() {
                let base_notif = build_notification_from_stored_update(
                    synchronizer_id,
                    u,
                    Some(&self.payload_hmac_key),
                );
                self.dispatch_notification_blocking_with_act_as(&base_notif, Some(&u.act_as));
            }
        }
    }

    /// Broadcasts a `PrunedUpTo` watermark event to all registered extensions.
    pub fn notify_pruned(&self, offset: u64) {
        if !self.has_subscribers() {
            return;
        }
        self.dispatch_notification(&ExExNotification::PrunedUpTo { offset });
    }

    /// Dispatches an [`ExExNotification`] non-blockingly (`try_send`), pruning disconnected receivers.
    pub fn dispatch_notification(&self, base: &ExExNotification) {
        self.dispatch_notification_with_act_as(base, None);
    }

    fn dispatch_notification_with_act_as(
        &self,
        base: &ExExNotification,
        update_act_as: Option<&[String]>,
    ) {
        let mut guard = self
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|sub| {
            let Some((mut scoped, filtered_cnt)) = apply_scope(base, &sub.scope, update_act_as)
            else {
                return true;
            };
            if filtered_cnt > 0 {
                sub.filtered_out
                    .fetch_add(filtered_cnt as u64, Ordering::Relaxed);
            }
            if let ExExNotification::Committed {
                seq,
                dropped_since_last,
                ..
            } = &mut scoped
            {
                *seq = sub.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                *dropped_since_last = sub.pending_dropped.load(Ordering::Relaxed);
            }
            match sub.sender.try_send(scoped) {
                Ok(()) => {
                    sub.delivered.fetch_add(1, Ordering::Relaxed);
                    sub.pending_dropped.store(0, Ordering::Relaxed);
                    true
                }
                Err(mpsc::TrySendError::Full(_)) => {
                    sub.dropped.fetch_add(1, Ordering::Relaxed);
                    sub.pending_dropped.fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    sub.connected.store(false, Ordering::Relaxed);
                    false
                }
            }
        });
        self.active_count.store(guard.len(), Ordering::SeqCst);
    }

    #[cfg(test)]
    fn dispatch_notification_blocking_with_act_as(
        &self,
        base: &ExExNotification,
        update_act_as: Option<&[String]>,
    ) {
        // [CANTON-NOTE: INVARIANT] Collect cloned senders under `self.subscribers` and drop the lock BEFORE calling blocking `send()` so subscribers calling `stats()` never deadlock.
        let targets = {
            let guard = self
                .subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut queued = Vec::with_capacity(guard.len());
            for sub in &*guard {
                let Some((mut scoped, filtered_cnt)) = apply_scope(base, &sub.scope, update_act_as)
                else {
                    continue;
                };
                if filtered_cnt > 0 {
                    sub.filtered_out
                        .fetch_add(filtered_cnt as u64, Ordering::Relaxed);
                }
                if let ExExNotification::Committed {
                    seq,
                    dropped_since_last,
                    ..
                } = &mut scoped
                {
                    *seq = sub.next_seq.fetch_add(1, Ordering::Relaxed) + 1;
                    *dropped_since_last = sub.pending_dropped.load(Ordering::Relaxed);
                }
                queued.push((
                    sub.sender.clone(),
                    scoped,
                    Arc::clone(&sub.delivered),
                    Arc::clone(&sub.pending_dropped),
                    Arc::clone(&sub.connected),
                ));
            }
            queued
        };
        let mut any_disconnected = false;
        for (sender, scoped, delivered, pending_dropped, connected) in targets {
            match sender.send(scoped) {
                Ok(()) => {
                    delivered.fetch_add(1, Ordering::Relaxed);
                    pending_dropped.store(0, Ordering::Relaxed);
                }
                Err(_) => {
                    connected.store(false, Ordering::Relaxed);
                    any_disconnected = true;
                }
            }
        }
        if any_disconnected {
            let mut guard = self
                .subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.retain(|s| s.connected.load(Ordering::Relaxed));
            self.active_count.store(guard.len(), Ordering::SeqCst);
        }
    }

    /// Returns zero-payload telemetry snapshot across all registered extensions.
    pub fn stats(&self) -> Vec<ExExSubscriberStats> {
        let guard = self
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .iter()
            .map(|s| ExExSubscriberStats {
                name: s.name.clone(),
                scope: s.scope.summary_label(),
                delivered_notifications: s.delivered.load(Ordering::Relaxed),
                filtered_out_events: s.filtered_out.load(Ordering::Relaxed),
                dropped_notifications: s.dropped.load(Ordering::Relaxed),
                write_errors: s.write_errors.load(Ordering::Relaxed),
                connected: s.connected.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Serializes `/_exex` telemetry JSON response.
    pub fn telemetry_json(&self) -> serde_json::Value {
        let items = self.stats();
        let active_extensions = items.iter().filter(|i| i.connected).count();
        let total_delivered: u64 = items.iter().map(|i| i.delivered_notifications).sum();
        let total_filtered: u64 = items.iter().map(|i| i.filtered_out_events).sum();
        let total_dropped: u64 = items.iter().map(|i| i.dropped_notifications).sum();
        serde_json::json!({
            "active_extensions": active_extensions,
            "total_delivered_notifications": total_delivered,
            "total_filtered_out_events": total_filtered,
            "total_dropped_notifications": total_dropped,
            "extensions": items,
        })
    }
}

fn filter_command_id(
    command_id: &str,
    allowed: &BTreeSet<String>,
    update_act_as: Option<&[String]>,
) -> String {
    match update_act_as {
        Some(act_as) if act_as.iter().any(|p| allowed.contains(p)) => command_id.to_string(),
        None if command_id.is_empty() => String::new(),
        Some(_) | None => String::new(),
    }
}

fn apply_scope(
    base: &ExExNotification,
    scope: &ExExPartyScope,
    update_act_as: Option<&[String]>,
) -> Option<(ExExNotification, usize)> {
    match base {
        ExExNotification::PrunedUpTo { offset } => {
            Some((ExExNotification::PrunedUpTo { offset: *offset }, 0))
        }
        ExExNotification::Committed {
            seq,
            dropped_since_last,
            offset,
            update_id,
            command_id,
            synchronizer_id,
            effective_at,
            committed_at_micros,
            root_hash,
            events,
        } => match scope {
            ExExPartyScope::AllParticipantVisible => Some((base.clone(), 0)),
            ExExPartyScope::ZeroPayloadMetadata => {
                let mut stripped = events.clone();
                for ev in &mut stripped {
                    ev.strip_payload();
                }
                Some((
                    ExExNotification::Committed {
                        seq: *seq,
                        dropped_since_last: *dropped_since_last,
                        offset: *offset,
                        update_id: update_id.clone(),
                        command_id: command_id.clone(),
                        synchronizer_id: synchronizer_id.clone(),
                        effective_at: effective_at.clone(),
                        committed_at_micros: *committed_at_micros,
                        root_hash: root_hash.clone(),
                        events: stripped,
                    },
                    0,
                ))
            }
            ExExPartyScope::Parties(allowed) => {
                let before = events.len();
                let visible: Vec<ExExContractEvent> = events
                    .iter()
                    .filter(|ev| ev.is_visible_to(allowed))
                    .cloned()
                    .collect();
                let filtered = before.saturating_sub(visible.len());
                if visible.is_empty() {
                    return None;
                }
                Some((
                    ExExNotification::Committed {
                        seq: *seq,
                        dropped_since_last: *dropped_since_last,
                        offset: *offset,
                        update_id: update_id.clone(),
                        command_id: filter_command_id(command_id, allowed, update_act_as),
                        synchronizer_id: synchronizer_id.clone(),
                        effective_at: effective_at.clone(),
                        committed_at_micros: *committed_at_micros,
                        root_hash: root_hash.clone(),
                        events: visible,
                    },
                    filtered,
                ))
            }
            ExExPartyScope::PartiesZeroPayload(allowed) => {
                let before = events.len();
                let mut visible: Vec<ExExContractEvent> = events
                    .iter()
                    .filter(|ev| ev.is_visible_to(allowed))
                    .cloned()
                    .collect();
                let filtered = before.saturating_sub(visible.len());
                if visible.is_empty() {
                    return None;
                }
                for ev in &mut visible {
                    ev.strip_payload();
                }
                Some((
                    ExExNotification::Committed {
                        seq: *seq,
                        dropped_since_last: *dropped_since_last,
                        offset: *offset,
                        update_id: update_id.clone(),
                        command_id: filter_command_id(command_id, allowed, update_act_as),
                        synchronizer_id: synchronizer_id.clone(),
                        effective_at: effective_at.clone(),
                        committed_at_micros: *committed_at_micros,
                        root_hash: root_hash.clone(),
                        events: visible,
                    },
                    filtered,
                ))
            }
        },
    }
}

fn build_notification_from_stored_update(
    default_sync: &str,
    u: &StoredUpdate,
    hmac_key: Option<&hmac::Key>,
) -> ExExNotification {
    let synchronizer_id = u
        .official
        .as_ref()
        .map_or_else(|| default_sync.to_string(), |m| m.synchronizer_id.clone());

    let mut cids: Vec<&str> = Vec::with_capacity(u.events.len());
    let mut events = Vec::with_capacity(u.events.len());
    for ev in &u.events {
        let c = &ev.contract;
        cids.push(c.contract_id.as_str());
        let stakeholders: BTreeSet<String> = c
            .signatories
            .iter()
            .chain(c.observers.iter())
            .cloned()
            .collect();
        let mut witnesses: BTreeSet<String> = c.witness_parties.iter().cloned().collect();
        for s in &stakeholders {
            witnesses.insert(s.clone());
        }
        let template_id = format!(
            "{}:{}:{}",
            c.package_id, c.template_id.module_name, c.template_id.entity_name
        );

        if ev.created {
            let canonical_bytes = canonical_value_bytes(&c.json_payload);
            let payload_sha256 = match hmac_key {
                Some(key) => hex::encode(hmac::sign(key, &canonical_bytes).as_ref()),
                None => {
                    let mut ph = Sha256::new();
                    ph.update(&canonical_bytes);
                    hex::encode(ph.finalize())
                }
            };
            events.push(ExExContractEvent::Created {
                contract_id: c.contract_id.clone(),
                package_id: c.package_id.clone(),
                template_id,
                stakeholders,
                witnesses,
                payload_bytes: canonical_bytes.len(),
                payload_sha256,
                create_arguments: Some(c.json_payload.clone()),
            });
        } else {
            let (choice_name, consuming) = match &ev.exercise {
                Some(ex) => (Some(ex.choice.clone()), ex.consuming),
                None => (None, true),
            };
            if let Some(ex) = &ev.exercise {
                for obs in &ex.choice_observers {
                    witnesses.insert(obs.clone());
                }
            }
            events.push(ExExContractEvent::Archived {
                contract_id: c.contract_id.clone(),
                package_id: c.package_id.clone(),
                template_id,
                choice_name,
                consuming,
                stakeholders,
                witnesses,
            });
        }
    }

    let root_hash = participant_tx_digest(&u.update_id, u.offset, &cids);

    ExExNotification::Committed {
        seq: 0,
        dropped_since_last: 0,
        offset: u.offset,
        update_id: u.update_id.clone(),
        command_id: u.command_id.clone(),
        synchronizer_id,
        effective_at: u.effective_at.clone(),
        committed_at_micros: u.at_micros,
        root_hash,
        events,
    }
}

fn canonical_value_bytes(val: &serde_json::Value) -> Vec<u8> {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.as_str(), v);
            }
            let mut out = Vec::from(b"{".as_slice());
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                if let Ok(kb) = serde_json::to_vec(k) {
                    out.extend_from_slice(&kb);
                }
                out.push(b':');
                out.extend_from_slice(&canonical_value_bytes(v));
            }
            out.push(b'}');
            out
        }
        serde_json::Value::Array(arr) => {
            let mut out = Vec::from(b"[".as_slice());
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&canonical_value_bytes(v));
            }
            out.push(b']');
            out
        }
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_notif() -> ExExNotification {
        let mut alice_only = BTreeSet::new();
        alice_only.insert("Alice::1220aa".to_string());

        let mut bob_only = BTreeSet::new();
        bob_only.insert("Bob::1220bb".to_string());

        ExExNotification::Committed {
            seq: 0,
            dropped_since_last: 0,
            offset: 7,
            update_id: "u-7".to_string(),
            command_id: "cmd-7".to_string(),
            synchronizer_id: "sync-1".to_string(),
            effective_at: "2026-11-19T00:00:00Z".to_string(),
            committed_at_micros: 1_700_000_007_000,
            root_hash: "1220abcdef1234567890abcd".to_string(),
            events: vec![
                ExExContractEvent::Created {
                    contract_id: "00aa".to_string(),
                    package_id: "pkg1".to_string(),
                    template_id: "pkg1:Asset:Holding".to_string(),
                    stakeholders: alice_only.clone(),
                    witnesses: alice_only,
                    payload_bytes: 42,
                    payload_sha256: "deadbeef".to_string(),
                    create_arguments: Some(serde_json::json!({ "secretAmount": "999999" })),
                },
                ExExContractEvent::Created {
                    contract_id: "00bb".to_string(),
                    package_id: "pkg1".to_string(),
                    template_id: "pkg1:Asset:Holding".to_string(),
                    stakeholders: bob_only.clone(),
                    witnesses: bob_only,
                    payload_bytes: 38,
                    payload_sha256: "cafebabe".to_string(),
                    create_arguments: Some(serde_json::json!({ "bobSecret": "777" })),
                },
            ],
        }
    }

    #[test]
    fn enforces_party_scoping_zero_payload_and_drop_first_non_blocking_delivery() {
        let hub = ExExHub::try_new().expect("exex hub");
        assert!(!hub.has_subscribers());

        let mut alice_set = BTreeSet::new();
        alice_set.insert("Alice::1220aa".to_string());

        let mut eve_set = BTreeSet::new();
        eve_set.insert("Eve::1220ee".to_string());

        let rx_alice = hub.register_channel("alice-fds", ExExPartyScope::Parties(alice_set), 4);
        let rx_eve = hub.register_channel("eve-spy", ExExPartyScope::Parties(eve_set), 4);
        let rx_zero = hub.register_channel("audit-meta", ExExPartyScope::ZeroPayloadMetadata, 1);

        assert!(hub.has_subscribers());
        hub.dispatch_notification(&sample_notif());

        // Alice receives ONLY her contract (00aa); Bob's secret contract (00bb) is stripped!
        let alice_msg = rx_alice.try_recv().expect("alice notification");
        let raw_alice = serde_json::to_string(&alice_msg).expect("json");
        assert!(raw_alice.contains("secretAmount"));
        assert!(!raw_alice.contains("bobSecret"));

        // Negative control 1: Unauthorized party Eve receives NOTHING!
        assert!(rx_eve.try_recv().is_err());

        // Negative control 2: ZeroPayloadMetadata receives headers & SHA-256 but ZERO business arguments!
        let zero_msg = rx_zero.try_recv().expect("zero-payload notification");
        let raw_zero = serde_json::to_string(&zero_msg).expect("json");
        assert!(raw_zero.contains("deadbeef"));
        assert!(!raw_zero.contains("secretAmount"));
        assert!(!raw_zero.contains("bobSecret"));

        // Drop-first non-blocking check: fill rx_zero (cap=1) and send again without draining; must NOT block!
        hub.dispatch_notification(&sample_notif());
        hub.dispatch_notification(&sample_notif());
        let stats = hub.stats();
        let zero_stat = stats
            .iter()
            .find(|s| s.name == "audit-meta")
            .expect("audit-meta stat");
        assert!(zero_stat.dropped_notifications >= 1);
    }

    #[test]
    fn enforces_hmac_digests_combined_scope_command_id_redaction_seq_and_file_perms() {
        let mut alice_set = BTreeSet::new();
        alice_set.insert("Alice::1220aa".to_string());
        let mut bob_set = BTreeSet::new();
        bob_set.insert("Bob::1220bb".to_string());

        let update = StoredUpdate {
            update_id: "u-9".to_string(),
            offset: 9,
            command_id: "secret-cmd-bob".to_string(),
            effective_at: "2026-11-19T00:00:00Z".to_string(),
            events: vec![crate::v2_commands::Ev {
                contract: crate::service::GenericContract {
                    contract_id: "00ab".to_string(),
                    package_id: "pkg1".to_string(),
                    template_id: crate::TemplateId::new("pkg1", "Asset", "Holding"),
                    payload_value: lf_eval::Value::Unit,
                    json_payload: serde_json::json!({"amount": "10"}),
                    signatories: vec!["Bob::1220bb".to_string()],
                    observers: vec!["Alice::1220aa".to_string()],
                    witness_parties: vec!["Alice::1220aa".to_string(), "Bob::1220bb".to_string()],
                    active: true,
                    key_value: None,
                    created_at_micros: 0,
                    created_event_blob: String::new(),
                    contract_key_hash: String::new(),
                    key_maintainers: Vec::new(),
                    creation_seq: 1,
                },
                created: true,
                node: 0,
                exercise: None,
            }],
            at_micros: 1_700_000_009_000,
            external_transaction_hash: None,
            reassignment: None,
            topology: None,
            official: None,
            trace_parent: None,
            act_as: vec!["Bob::1220bb".to_string()],
        };

        // Per-instance HMAC produces distinct payload digests across hubs for the same payload.
        let hub1 = ExExHub::try_new().expect("hub1");
        let hub2 = ExExHub::try_new().expect("hub2");
        let d1 = hub1.keyed_payload_digest(br#"{"amount":"10"}"#);
        let d2 = hub2.keyed_payload_digest(br#"{"amount":"10"}"#);
        assert_ne!(d1, d2);

        // PartiesZeroPayload strips arguments AND masks non-submitter command_id.
        let rx_alice_zero = hub1.register_channel(
            "alice-zero",
            ExExPartyScope::PartiesZeroPayload(alice_set),
            1,
        );
        let rx_bob = hub1.register_channel("bob", ExExPartyScope::Parties(bob_set), 4);
        hub1.publish_stored_update("sync-1", &update);

        match rx_alice_zero.try_recv().expect("alice-zero msg") {
            ExExNotification::Committed {
                seq,
                dropped_since_last,
                command_id,
                events,
                ..
            } => {
                assert_eq!(seq, 1);
                assert_eq!(dropped_since_last, 0);
                assert_eq!(
                    command_id, "",
                    "non-submitter observer must not see command_id"
                );
                assert!(matches!(
                    events.as_slice(),
                    [ExExContractEvent::Created {
                        create_arguments: None,
                        ..
                    }]
                ));
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Bob IS in update.act_as so Bob keeps command_id.
        match rx_bob.try_recv().expect("bob msg") {
            ExExNotification::Committed { command_id, .. } => {
                assert_eq!(command_id, "secret-cmd-bob");
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Fill capacity=1 channel for alice-zero and drop once, then drain and receive next -> dropped_since_last == 1.
        hub1.publish_stored_update("sync-1", &update);
        hub1.publish_stored_update("sync-1", &update);
        assert!(rx_alice_zero.try_recv().is_ok());
        hub1.publish_stored_update("sync-1", &update);
        match rx_alice_zero.try_recv().expect("next after drop") {
            ExExNotification::Committed {
                seq,
                dropped_since_last,
                ..
            } => {
                assert_eq!(seq, 4);
                assert_eq!(dropped_since_last, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // JSONL sink uses 0o600 permissions on Unix and resets `connected` when hub drops receiver.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = std::env::temp_dir().join(format!("crs-exex-perm-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let out = dir.join("exex.jsonl");
            hub1.register_jsonl_file_sink("sink", ExExPartyScope::ZeroPayloadMetadata, &out, 4)
                .expect("sink");
            let mode = std::fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn replays_2000_updates_over_1024_capacity_channel_without_dropping() {
        let hub = ExExHub::try_new().expect("exex hub");
        let rx = hub.register_channel("replay-sink", ExExPartyScope::ZeroPayloadMetadata, 1024);

        let updates: Vec<StoredUpdate> = (1..=2000_u64)
            .map(|off| StoredUpdate {
                update_id: format!("u-{off}"),
                offset: off,
                command_id: format!("cmd-{off}"),
                effective_at: "2026-11-22T00:00:00Z".to_string(),
                events: Vec::new(),
                at_micros: 1_700_000_000_000 + off as i64,
                external_transaction_hash: None,
                reassignment: None,
                topology: None,
                official: None,
                trace_parent: None,
                act_as: vec!["Alice::1220aa".to_string()],
            })
            .collect();

        let consumer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(15));
            let mut got = Vec::new();
            while let Ok(notif) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                if let ExExNotification::Committed { seq, offset, .. } = notif {
                    got.push((seq, offset));
                    if got.len() == 2000 {
                        break;
                    }
                }
            }
            got
        });

        hub.replay_updates_to_subscribers("sync-1", &updates, 1);
        let received = consumer.join().expect("consumer thread join");
        let stats = hub.stats();
        let st = stats
            .iter()
            .find(|s| s.name == "replay-sink")
            .expect("replay-sink stat");
        assert_eq!(
            received.len(),
            2000,
            "replay over bounded 1024 channel must backpressure instead of dropping: received={}, dropped={}",
            received.len(),
            st.dropped_notifications
        );
        assert_eq!(st.dropped_notifications, 0);
        assert_eq!(
            received.first().copied(),
            Some((1, 1)),
            "first replayed item must be (seq=1, offset=1)"
        );
        assert_eq!(
            received.last().copied(),
            Some((2000, 2000)),
            "last replayed item must be (seq=2000, offset=2000)"
        );
    }

    #[test]
    fn fails_closed_on_csprng_error_and_prunes_disconnected_replay_subscriber() {
        let err = match ExExHub::try_new_with_rng(|_| Err("injected csprng error")) {
            Ok(_) => panic!("failing CSPRNG must prevent ExExHub construction"),
            Err(e) => e,
        };
        assert!(err.contains("cannot initialize ExEx HMAC key"), "{err}");

        let svc_err = match crate::service::ExecutionService::try_new_with_exex_rng(|_| {
            Err("injected csprng error")
        }) {
            Ok(_) => panic!("failing CSPRNG must prevent ExecutionService startup"),
            Err(e) => e,
        };
        assert!(
            svc_err.contains("cannot initialize ExEx HMAC key"),
            "{svc_err}"
        );

        // Disconnected receiver mid-replay returns promptly without stalling and unregisters itself.
        let hub = ExExHub::try_new().expect("positive control hub");
        let rx = hub.register_channel("drop-early", ExExPartyScope::ZeroPayloadMetadata, 1);
        assert!(hub.has_subscribers());
        let updates: Vec<StoredUpdate> = (1..=10_u64)
            .map(|off| StoredUpdate {
                update_id: format!("u-{off}"),
                offset: off,
                command_id: format!("cmd-{off}"),
                effective_at: "2026-11-22T00:00:00Z".to_string(),
                events: Vec::new(),
                at_micros: 1_700_000_000_000 + off as i64,
                external_transaction_hash: None,
                reassignment: None,
                topology: None,
                official: None,
                trace_parent: None,
                act_as: vec!["Alice::1220aa".to_string()],
            })
            .collect();
        let h = std::thread::spawn(move || {
            let _ = rx.recv();
            drop(rx);
        });
        hub.replay_updates_to_subscribers("sync-1", &updates, 1);
        let _ = h.join();
        assert!(
            !hub.has_subscribers(),
            "disconnected replay subscriber must be pruned promptly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn r13j_jsonl_backfill_does_not_hold_commit_publish_lock_across_blocking_io() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            serve: crate::cli::ServeArgs,
        }

        let dir = std::env::temp_dir().join(format!(
            "crs-exex-b1-lock-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let fifo = dir.join("blocked.fifo.jsonl");
        let mkfifo = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("invoke mkfifo");
        assert!(mkfifo.success(), "mkfifo failed: {mkfifo}");

        let probe_reached = Arc::new(AtomicBool::new(false));
        let probe_lock_free = Arc::new(AtomicBool::new(false));
        let pr = Arc::clone(&probe_reached);
        let pl = Arc::clone(&probe_lock_free);

        let mut args = TestCli::try_parse_from([
            "ledger-json-api",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--exex-jsonl",
            fifo.to_str().expect("utf8 path"),
            "--exex-from-offset",
            "0",
            "--admin-port",
            "0",
        ])
        .expect("parse ServeArgs")
        .serve;
        args.admin_server = Some(crate::cli::AdminServer(Arc::new(move |svc, _, _, _| {
            pl.store(
                svc.v2_state().commit_publish_lock.try_lock().is_ok(),
                Ordering::SeqCst,
            );
            pr.store(true, Ordering::SeqCst);
            Err("probe stop".into())
        })));

        let handle = std::thread::spawn(move || crate::cli::serve(args));
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1200);
        while std::time::Instant::now() < deadline && !probe_reached.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let reached_without_fifo_reader = probe_reached.load(Ordering::SeqCst);
        let lock_was_free = probe_lock_free.load(Ordering::SeqCst);

        // Always unblock the FIFO so the background thread/worker exits cleanly on drop.
        let drain = std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::open(&fifo) {
                let mut buf = Vec::new();
                let _ = std::io::Read::read_to_end(&mut f, &mut buf);
            }
        });
        let _ = handle.join();
        let _ = drain.join();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            reached_without_fifo_reader,
            "cli::serve blocked during ExEx JSONL open/backfill while holding commit_publish_lock"
        );
        assert!(
            lock_was_free,
            "commit_publish_lock must be released before opening/writing blocking ExEx JSONL I/O"
        );

        // Positive control: >1024 backfill updates drain completely to a regular JSONL file without blocking.
        let backfill_dir = std::env::temp_dir().join(format!(
            "crs-exex-backfill-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&backfill_dir);
        std::fs::create_dir_all(&backfill_dir).expect("mkdir");
        let out_file = backfill_dir.join("out.jsonl");
        let svc = Arc::new(crate::service::ExecutionService::try_new().expect("service"));
        let updates: Vec<StoredUpdate> = (1..=1500_u64)
            .map(|off| StoredUpdate {
                update_id: format!("u-{off}"),
                offset: off,
                command_id: format!("cmd-{off}"),
                effective_at: "2026-11-22T00:00:00Z".to_string(),
                events: Vec::new(),
                at_micros: 1_700_000_000_000 + off as i64,
                external_transaction_hash: None,
                reassignment: None,
                topology: None,
                official: None,
                trace_parent: None,
                act_as: vec!["Alice::1220aa".to_string()],
            })
            .collect();
        *svc.v2_state().updates.lock().unwrap() = updates;
        svc.exex()
            .register_jsonl_file_sink_with_backfill(
                "backfill-test",
                ExExPartyScope::ZeroPayloadMetadata,
                &out_file,
                4,
                Some(1),
                svc.v2_state(),
            )
            .expect("register backfill sink");
        let wait_end = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut lines = 0usize;
        while std::time::Instant::now() < wait_end {
            lines = std::fs::read_to_string(&out_file)
                .map(|s| s.lines().count())
                .unwrap_or(0);
            if lines == 1500 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = std::fs::remove_dir_all(&backfill_dir);
        assert_eq!(
            lines, 1500,
            "all 1500 historical updates must write to JSONL file on dedicated OS thread"
        );
    }

    #[test]
    fn exex_jsonl_non_fifo_open_error_fails_synchronously() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing_dir = dir.path().join("not-a-file");
        std::fs::create_dir_all(&existing_dir).expect("mkdir target");
        let svc = Arc::new(crate::service::ExecutionService::try_new().expect("service"));
        let res = svc.exex().register_jsonl_file_sink_with_backfill(
            "bad-dir",
            ExExPartyScope::ZeroPayloadMetadata,
            &existing_dir,
            4,
            None,
            svc.v2_state(),
        );
        assert!(
            res.is_err(),
            "register_jsonl_file_sink_with_backfill on an existing directory must fail synchronously, got {res:?}"
        );
    }
}
