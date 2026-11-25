//! A Splice application runtime that survives a restart and fences duplicate workers (G9/G8, AT-D10, S-STORE-020).
//!
//! [CANTON-NOTE: SEMANTICS] The runtime ([`SpliceAppRuntime`]) is deterministic given the sequence of calls made on it: its clock is a
//! logical one (`now_micros`, moved only by `advance_time`), contract and update ids come from counters, and nothing reads the wall clock or
//! a random source. So it is kept by **command sourcing**, as the JSON API is (S-STORE-004): every state-changing HTTP request, the bootstrap
//! and every automation tick that changed something is appended as one line to the journal key [`JOURNAL_KEY`] of a [`StateStore`]
//! (a directory or PostgreSQL) **before** its answer is returned, and a restart replays the journal in order.
//!
//! What this gives AT-D10 (a commit's answer is lost; the client and the automation worker both retry):
//! - a request whose line reached the store survives the crash, so the client's retry with the same `tracking_id` is answered from the
//!   restored tracking table (`200`, same contract id) and is not applied twice;
//! - a request whose line did not reach the store is gone after the crash, so the retry applies it once;
//! - the automation worker's tick after the restart sees the replayed state: a transfer it already settled is not settled again.
//!
//! Two workers on one state are refused at start: PostgreSQL by the session advisory lock [`PgStore`](crate::state_store) takes on the
//! state name (a dead process releases it with its connection), a directory by an exclusive OS lock on `splice.lock` held for the life of
//! the runtime.
//!
//! [CANTON-NOTE: LIMITATION] A state-changing call whose journal write fails leaves memory ahead of the store: the runtime stops taking
//! state changes (`503`) until it is restarted, as the JSON API does. Request headers are journaled as received (the Splice apps here use
//! `x-wallet-user`, not bearer tokens). The journal is not compacted.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};

use crate::scan_api::Response;
use crate::splice_apps::{
    handle_splice_http, AutomationTickReport, SpliceAppRuntime, SpliceBootstrapConfig,
};
use crate::splice_ledger_backend::ParticipantLedgerConfig;
use crate::state_store::StateStore;

/// The key of the journal inside the state store.
pub const JOURNAL_KEY: &str = "splice-journal";

/// The key storing off-chain tracking/secret metadata in participant-ledger mode.
pub const LEDGER_META_KEY: &str = "splice-ledger-meta";

/// What opening a persistent runtime did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceReplayReport {
    /// Journal entries replayed.
    pub replayed: usize,
    /// Whether this start bootstrapped a fresh state (nothing to replay and `bootstrap` was asked for).
    pub bootstrapped: bool,
}

/// A [`SpliceAppRuntime`] whose state-changing calls are journaled to a [`StateStore`].
pub struct PersistentSplice {
    runtime: Mutex<SpliceAppRuntime>,
    store: Arc<dyn StateStore>,
    /// Serializes a state-changing call with its journal write, so the journal order is the order the state changed in.
    write_lock: Mutex<()>,
    failed: AtomicBool,
    _dir_lock: Option<std::fs::File>,
}

fn is_mutating(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn is_scan_read(raw_path: &str) -> bool {
    let route = raw_path.split('?').next().unwrap_or(raw_path);
    route == "/api/scan" || route.starts_with("/api/scan/") || route.starts_with("/registry/")
}

fn acquire_dir_lock(dir_lock: Option<&Path>) -> Result<Option<std::fs::File>, String> {
    let Some(dir) = dir_lock else {
        return Ok(None);
    };
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join("splice.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!(
            "the Splice state in {} is being written by another worker",
            dir.display()
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("{}: {e}", path.display())),
    }
}

fn unavailable(why: &str) -> Response {
    Response {
        status: 503,
        content_type: "application/json",
        body: json!({ "error": why }).to_string(),
    }
}

impl PersistentSplice {
    /// Loads the DARs, takes the directory lock (when `dir_lock` is given), and rebuilds the state from the journal in `store`. A fresh
    /// store is bootstrapped when `bootstrap` is set (and that bootstrap is journaled like any other change).
    pub fn open(
        dar_dir: &Path,
        config: SpliceBootstrapConfig,
        store: Arc<dyn StateStore>,
        bootstrap: bool,
        dir_lock: Option<&Path>,
    ) -> Result<(Self, SpliceReplayReport), String> {
        let dir_lock = acquire_dir_lock(dir_lock)?;

        let runtime = SpliceAppRuntime::from_dar_dir(dar_dir, config)?;
        let this = Self {
            runtime: Mutex::new(runtime),
            store,
            write_lock: Mutex::new(()),
            failed: AtomicBool::new(false),
            _dir_lock: dir_lock,
        };
        let journal = this.store.read(JOURNAL_KEY)?.unwrap_or_default();
        let mut replayed = 0usize;
        for (i, line) in journal.lines().enumerate() {
            // a line without its newline is one the process died writing: it was never acknowledged
            if line.trim().is_empty() {
                continue;
            }
            let entry: Json = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) if i + 1 == journal.lines().count() && !journal.ends_with('\n') => break,
                Err(e) => return Err(format!("journal line {}: {e}", i + 1)),
            };
            this.replay_entry(i + 1, &entry)?;
            replayed += 1;
        }
        let mut bootstrapped = false;
        if replayed == 0 && bootstrap {
            this.bootstrap()?;
            bootstrapped = true;
        }
        Ok((
            this,
            SpliceReplayReport {
                replayed,
                bootstrapped,
            },
        ))
    }

    /// Connects to an external participant ledger, restores off-chain metadata from `splice-ledger-meta`,
    /// and idempotently bootstraps DSO contracts if requested and absent on the participant ledger.
    pub fn open_participant_ledger(
        dar_dir: &Path,
        config: SpliceBootstrapConfig,
        ledger_config: ParticipantLedgerConfig,
        store: Arc<dyn StateStore>,
        bootstrap: bool,
        dir_lock: Option<&Path>,
    ) -> Result<(Self, SpliceReplayReport), String> {
        let dir_lock = acquire_dir_lock(dir_lock)?;
        let mut runtime =
            SpliceAppRuntime::from_participant_ledger(dar_dir, config, ledger_config)?;
        let mut replayed = 0usize;
        if let Some(raw_meta) = store.read(LEDGER_META_KEY)? {
            if !raw_meta.trim().is_empty() {
                let meta: Json = serde_json::from_str(&raw_meta)
                    .map_err(|e| format!("invalid {LEDGER_META_KEY}: {e}"))?;
                runtime.import_offchain_state(&meta)?;
                replayed = 1;
            }
        }
        let this = Self {
            runtime: Mutex::new(runtime),
            store,
            write_lock: Mutex::new(()),
            failed: AtomicBool::new(false),
            _dir_lock: dir_lock,
        };
        let mut bootstrapped = false;
        if bootstrap {
            let out = this.bootstrap()?;
            bootstrapped = out["already_bootstrapped"].as_bool() == Some(false);
        }
        Ok((
            this,
            SpliceReplayReport {
                replayed,
                bootstrapped,
            },
        ))
    }

    fn replay_entry(&self, n: usize, entry: &Json) -> Result<(), String> {
        let mut rt = self
            .runtime
            .lock()
            .map_err(|_| "the Splice runtime lock is poisoned".to_string())?;
        match entry["k"].as_str() {
            Some("bootstrap") => {
                rt.bootstrap()
                    .map_err(|e| format!("replay of journal line {n} (bootstrap): {e}"))?;
            }
            Some("tick") => {
                rt.run_automation_tick()
                    .map_err(|e| format!("replay of journal line {n} (automation tick): {e}"))?;
            }
            Some("http") => {
                drop(rt);
                let method = entry["m"].as_str().unwrap_or("");
                let path = entry["p"].as_str().unwrap_or("");
                let headers: Vec<(String, String)> = entry["h"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| {
                                Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let body = hex::decode(entry["b"].as_str().unwrap_or(""))
                    .map_err(|e| format!("journal line {n}: body: {e}"))?;
                let logged = entry["s"].as_u64().unwrap_or(200) as u16;
                let resp = handle_splice_http(&self.runtime, method, path, &headers, &body);
                if (200..300).contains(&logged) && !(200..300).contains(&resp.status) {
                    return Err(format!(
                        "replay of journal line {n} ({method} {path}) answered {}: {}",
                        resp.status, resp.body
                    ));
                }
            }
            other => return Err(format!("journal line {n}: unknown entry kind {other:?}")),
        }
        Ok(())
    }

    fn journal(&self, entry: &Json) -> Result<(), String> {
        self.store.append(JOURNAL_KEY, &entry.to_string())
    }

    fn save_meta(&self, rt: &SpliceAppRuntime) -> Result<(), String> {
        self.store
            .write(LEDGER_META_KEY, &rt.export_offchain_state().to_string())
    }

    /// The runtime, for reads and for tests.
    pub fn runtime(&self) -> &Mutex<SpliceAppRuntime> {
        &self.runtime
    }

    /// Where the journal is kept, for messages.
    pub fn describe(&self) -> String {
        self.store.describe()
    }

    /// Bootstraps DSO rules, Amulet rules and the first rounds (idempotent); journaled when it changed something.
    pub fn bootstrap(&self) -> Result<Json, String> {
        let _w = self
            .write_lock
            .lock()
            .map_err(|_| "the journal lock is poisoned".to_string())?;
        if self.failed.load(Ordering::SeqCst) {
            return Err("an earlier journal write failed; restart to recover".into());
        }
        let mut rt = self
            .runtime
            .lock()
            .map_err(|_| "the Splice runtime lock is poisoned".to_string())?;
        if rt.is_participant_ledger() {
            let before = rt.offchain_fingerprint();
            let out = rt.bootstrap().map_err(|e| e.to_string())?;
            if rt.offchain_fingerprint() != before {
                if let Err(e) = self.save_meta(&rt) {
                    self.failed.store(true, Ordering::SeqCst);
                    return Err(format!("could not persist splice metadata: {e}"));
                }
            }
            return Ok(out);
        }
        let before = rt.state_fingerprint();
        let out = rt.bootstrap().map_err(|e| e.to_string())?;
        if rt.state_fingerprint() != before {
            if let Err(e) = self.journal(&json!({ "k": "bootstrap" })) {
                self.failed.store(true, Ordering::SeqCst);
                return Err(format!("could not journal the bootstrap: {e}"));
            }
        }
        Ok(out)
    }

    /// Runs one automation tick (settle accepted transfers, complete traffic purchases, expire offers, advance rounds, ...); journaled
    /// when it changed something.
    pub fn automation_tick(&self) -> Result<AutomationTickReport, String> {
        let _w = self
            .write_lock
            .lock()
            .map_err(|_| "the journal lock is poisoned".to_string())?;
        if self.failed.load(Ordering::SeqCst) {
            return Err("an earlier journal write failed; restart to recover".into());
        }
        let mut rt = self
            .runtime
            .lock()
            .map_err(|_| "the Splice runtime lock is poisoned".to_string())?;
        if rt.is_participant_ledger() {
            let before = rt.offchain_fingerprint();
            let report = rt.run_automation_tick().map_err(|e| e.to_string())?;
            if rt.offchain_fingerprint() != before {
                if let Err(e) = self.save_meta(&rt) {
                    self.failed.store(true, Ordering::SeqCst);
                    return Err(format!("could not persist splice metadata: {e}"));
                }
            }
            return Ok(report);
        }
        let before = rt.state_fingerprint();
        let report = rt.run_automation_tick().map_err(|e| e.to_string())?;
        if rt.state_fingerprint() != before {
            if let Err(e) = self.journal(&json!({ "k": "tick" })) {
                self.failed.store(true, Ordering::SeqCst);
                return Err(format!("could not journal the automation tick: {e}"));
            }
        }
        Ok(report)
    }

    /// Serves an HTTP request of any Splice app (`SV`, `Validator`, `Wallet`, `Automation`, `Scan`). A state-changing request is journaled
    /// before it is answered; if the journal write fails the answer is `503` and the runtime takes no further state change.
    pub fn handle_http(
        &self,
        method: &str,
        raw_path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Response {
        if !is_mutating(method) || is_scan_read(raw_path) {
            return handle_splice_http(&self.runtime, method, raw_path, headers, body);
        }
        let Ok(_w) = self.write_lock.lock() else {
            return unavailable("the journal lock is poisoned");
        };
        if self.failed.load(Ordering::SeqCst) {
            return unavailable("an earlier journal write failed; restart to recover");
        }
        let (is_ledger_mode, before_state, before_offchain) = match self.runtime.lock() {
            Ok(rt) => (
                rt.is_participant_ledger(),
                rt.state_fingerprint(),
                rt.offchain_fingerprint(),
            ),
            Err(_) => return unavailable("the Splice runtime lock is poisoned"),
        };
        let resp = handle_splice_http(&self.runtime, method, raw_path, headers, body);
        if is_ledger_mode {
            let (changed, meta_err) = match self.runtime.lock() {
                Ok(rt) => {
                    if rt.offchain_fingerprint() != before_offchain {
                        (true, self.save_meta(&rt).err())
                    } else {
                        (false, None)
                    }
                }
                Err(_) => return unavailable("the Splice runtime lock is poisoned"),
            };
            if changed {
                if let Some(e) = meta_err {
                    self.failed.store(true, Ordering::SeqCst);
                    return unavailable(&format!("could not persist splice metadata: {e}"));
                }
            }
            return resp;
        }
        let after = match self.runtime.lock() {
            Ok(rt) => rt.state_fingerprint(),
            Err(_) => return unavailable("the Splice runtime lock is poisoned"),
        };
        let succeeded = (200..300).contains(&resp.status);
        if !succeeded && after == before_state {
            return resp; // it left no trace
        }
        let entry = json!({
            "k": "http",
            "m": method,
            "p": raw_path,
            "h": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "b": hex::encode(body),
            "s": resp.status,
        });
        if let Err(e) = self.journal(&entry) {
            self.failed.store(true, Ordering::SeqCst);
            return unavailable(&format!("could not journal the request: {e}"));
        }
        resp
    }
}
