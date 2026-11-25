//! Persistence of the ledger service by request log (S-STORE-004).
//!
//! [CANTON-NOTE: SEMANTICS] The ledger state (parties, users, packages, contracts, offsets, dedup table, update stream) is
//! rebuilt on start by replaying every state-changing request, in its original order and at its original time
//! (`clock::with_fixed`): the ones that succeeded, and the failed ones that still left a trace (a rejected command draws a
//! contract id and records a completion, see `state_fingerprint`). A request is acknowledged only after its record is durable. State changes are
//! deterministic given the request sequence (party ids, contract ids and offsets come from counters, times from the fixed
//! clock), which the restart-equivalence tests check against an uninterrupted run.
//!
//! [CANTON-NOTE: LIMITATION] This is command sourcing, not a relational schema of contracts/events: the log grows with every
//! mutation (DAR uploads included), nothing is compacted, a failed request is assumed to leave no trace unless the
//! fingerprint moved (counters and completions; another kind of trace would be lost), and replay time grows with the log. Authorization is not replayed: the log holds
//! what the node accepted. Bearer tokens are never stored; the parties a v1 token granted are kept as `x-daml-act-as` /
//! `x-daml-read-as` instead.
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use lf_eval::durable::CrashPoint;
use lf_eval::recfile::RecordFile;
use sha2::{Digest, Sha256};

use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;

/// One state-changing request as the node served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRequest {
    /// The instant the request was served at (what `clock::now_micros` returned while it ran).
    pub at_micros: i64,
    pub method: String,
    pub path: String,
    /// The status the request was answered with. Replay requires a logged success to succeed again; a logged failure is replayed
    /// for its effects (the ids it drew, the completion it left) and may answer differently (an overlap that was "locked" live).
    pub status: u16,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

const FORMAT_V2: u8 = 2;

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = rest;
        Some(head)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?.to_vec()).ok()
    }
    fn pairs(&mut self) -> Option<Vec<(String, String)>> {
        let n = self.u32()?;
        (0..n)
            .map(|_| Some((self.string()?, self.string()?)))
            .collect()
    }
}

impl LoggedRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_V2];
        out.extend_from_slice(&self.at_micros.to_le_bytes());
        put(&mut out, self.method.as_bytes());
        put(&mut out, self.path.as_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        for pairs in [&self.query, &self.headers] {
            out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
            for (k, v) in pairs {
                put(&mut out, k.as_bytes());
                put(&mut out, v.as_bytes());
            }
        }
        put(&mut out, &self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        if r.take(1)? != [FORMAT_V2] {
            return None;
        }
        let at_micros = i64::from_le_bytes(r.take(8)?.try_into().ok()?);
        let (method, path) = (r.string()?, r.string()?);
        let status = u16::from_le_bytes(r.take(2)?.try_into().ok()?);
        let (query, headers) = (r.pairs()?, r.pairs()?);
        let body = r.bytes()?.to_vec();
        r.0.is_empty().then_some(Self {
            at_micros,
            method,
            path,
            status,
            query,
            headers,
            body,
        })
    }

    fn to_request(&self) -> HttpRequest {
        HttpRequest {
            method: self.method.clone(),
            path: self.path.clone(),
            query_params: self.query.iter().cloned().collect(),
            headers: self.headers.iter().cloned().collect(),
            body: self.body.clone(),
        }
    }
}

/// Where the logged requests live. A backend appends durably (returns only once the record survives a crash) and returns the
/// records it holds, in order, once, when the service starts.
/// A checkpoint snapshot of the service state at 1-based record sequence `seq` (`U-16`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSnapshot {
    pub seq: u64,
    pub payload: Vec<u8>,
}

/// Persistent backend for the JSON API request log.
pub trait RequestLog: Send {
    fn load(&mut self) -> io::Result<Vec<LoggedRequest>>;
    fn append(&mut self, rec: &LoggedRequest) -> io::Result<()>;
    fn load_snapshot(&mut self) -> io::Result<Option<LogSnapshot>> {
        Ok(None)
    }
    fn save_snapshot(&mut self, _snap: &LogSnapshot) -> io::Result<()> {
        Ok(())
    }
    fn load_after(&mut self, after_seq: u64) -> io::Result<Vec<LoggedRequest>> {
        Ok(self.load()?.into_iter().skip(after_seq as usize).collect())
    }
    fn compact_before(&mut self, _seq: u64) -> io::Result<()> {
        Ok(())
    }
    fn current_seq(&self) -> u64 {
        0
    }
}

const SNAPSHOT_MAGIC: &[u8; 8] = b"CSNP0001";

fn snapshot_sidecar_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".snapshot");
    PathBuf::from(os)
}

fn snapshot_digest(seq: u64, compacted_base: u64, payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SNAPSHOT_MAGIC);
    h.update(seq.to_le_bytes());
    h.update(compacted_base.to_le_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    h.finalize().into()
}

fn read_file_snapshot(path: &Path) -> Option<(u64, LogSnapshot)> {
    let raw = std::fs::read(path).ok()?;
    if raw.len() < 8 + 8 + 8 + 8 + 32 || &raw[..8] != SNAPSHOT_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let compacted_base = u64::from_le_bytes(raw[16..24].try_into().ok()?);
    let len = u64::from_le_bytes(raw[24..32].try_into().ok()?) as usize;
    let payload_end = 32usize.checked_add(len)?;
    if raw.len() != payload_end + 32 {
        return None;
    }
    let payload = raw[32..payload_end].to_vec();
    let expected = snapshot_digest(seq, compacted_base, &payload);
    if raw[payload_end..] != expected {
        return None;
    }
    Some((compacted_base, LogSnapshot { seq, payload }))
}

fn write_file_snapshot(path: &Path, compacted_base: u64, snap: &LogSnapshot) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;
    f.write_all(SNAPSHOT_MAGIC)?;
    f.write_all(&snap.seq.to_le_bytes())?;
    f.write_all(&compacted_base.to_le_bytes())?;
    f.write_all(&(snap.payload.len() as u64).to_le_bytes())?;
    f.write_all(&snap.payload)?;
    f.write_all(&snapshot_digest(snap.seq, compacted_base, &snap.payload))?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp_path, path)
}

/// The request log in one CRC-framed file (with optional atomic `.snapshot` checkpoint sidecar).
pub struct FileLog {
    path: PathBuf,
    snapshot_path: PathBuf,
    file: RecordFile,
    loaded: Vec<LoggedRequest>,
    compacted_base: u64,
    total_seq: u64,
    crash: Option<CrashPoint>,
}

impl FileLog {
    /// Opens (creating if needed) the file; a torn tail left by a crash is cut off.
    pub fn open(path: &Path) -> io::Result<Self> {
        let (file, records) = RecordFile::open(path)?;
        let snapshot_path = snapshot_sidecar_path(path);
        let compacted_base = read_file_snapshot(&snapshot_path)
            .map(|(base, _)| base)
            .unwrap_or(0);
        let loaded = records
            .iter()
            .map(|b| {
                LoggedRequest::decode(b).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "undecodable record in the request log",
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let total_seq = compacted_base + loaded.len() as u64;
        Ok(Self {
            path: path.to_path_buf(),
            snapshot_path,
            file,
            loaded,
            compacted_base,
            total_seq,
            crash: None,
        })
    }

    /// Test hook: the next `append` is interrupted at `point` (once).
    pub fn inject_crash(&mut self, point: CrashPoint) {
        self.crash = Some(point);
    }

    /// Test hook: how many bytes of the file are known to be on disk.
    pub fn synced_len(&self) -> u64 {
        self.file.synced_len()
    }

    /// Bytes `open` cut off a torn tail.
    pub fn truncated_bytes(&self) -> u64 {
        self.file.truncated_bytes
    }
}

impl RequestLog for FileLog {
    fn load(&mut self) -> io::Result<Vec<LoggedRequest>> {
        Ok(std::mem::take(&mut self.loaded))
    }

    fn append(&mut self, rec: &LoggedRequest) -> io::Result<()> {
        let crash = self.crash.take();
        self.file.append(&rec.encode(), crash)?;
        self.total_seq += 1;
        Ok(())
    }

    fn load_snapshot(&mut self) -> io::Result<Option<LogSnapshot>> {
        Ok(read_file_snapshot(&self.snapshot_path).map(|(_, snap)| snap))
    }

    fn save_snapshot(&mut self, snap: &LogSnapshot) -> io::Result<()> {
        write_file_snapshot(&self.snapshot_path, self.compacted_base, snap)
    }

    fn load_after(&mut self, after_seq: u64) -> io::Result<Vec<LoggedRequest>> {
        let skip = after_seq.saturating_sub(self.compacted_base) as usize;
        Ok(std::mem::take(&mut self.loaded)
            .into_iter()
            .skip(skip)
            .collect())
    }

    fn compact_before(&mut self, seq: u64) -> io::Result<()> {
        if seq <= self.compacted_base {
            return Ok(());
        }
        let Some((old_base, snap)) = read_file_snapshot(&self.snapshot_path) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot compact file log without a persisted snapshot",
            ));
        };
        if snap.seq < seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "snapshot seq {} precedes compaction boundary {seq}",
                    snap.seq
                ),
            ));
        }
        let (_, records) = RecordFile::open(&self.path)?;
        let drop_count = seq.saturating_sub(old_base) as usize;
        let tail = records.into_iter().skip(drop_count).collect::<Vec<_>>();
        let mut tmp_os = self.path.as_os_str().to_os_string();
        tmp_os.push(".compact.tmp");
        let tmp_path = PathBuf::from(tmp_os);
        let _ = std::fs::remove_file(&tmp_path);
        {
            let (mut tmp_file, _) = RecordFile::open(&tmp_path)?;
            for rec in &tail {
                tmp_file.append(rec, None)?;
            }
        }
        write_file_snapshot(&self.snapshot_path, seq, &snap)?;
        std::fs::rename(&tmp_path, &self.path)?;
        let (reopened, _) = RecordFile::open(&self.path)?;
        self.file = reopened;
        self.compacted_base = seq;
        self.total_seq = seq + tail.len() as u64;
        Ok(())
    }

    fn current_seq(&self) -> u64 {
        self.total_seq
    }
}

/// Whether a request changes ledger state and so belongs in the log.
///
/// A deny-list of the read-only endpoints that use POST, so a state-changing route added later is logged by default: logging
/// a read costs space, missing a write loses data. Streams (`/v2/updates`) must never be here: they would hold the log lock.
pub fn is_logged(req: &HttpRequest) -> bool {
    if !matches!(req.method.as_str(), "POST" | "PATCH" | "PUT" | "DELETE") {
        return false;
    }
    let path = req.path.trim_end_matches('/');
    // `prepare` is logged with `execute`: it keeps the prepared transaction `execute` takes and draws a submission number
    const READ_ONLY_PREFIXES: [&str; 12] = [
        "/v2/state/",
        "/v2/updates",
        "/v2/commands/completions",
        "/v2/commands/command-completions",
        "/v2/commands/completion-by-hash",
        "/v2/interactive-submission/preferred-package",
        "/v2/package-vetting/list",
        "/v2/dars/validate",
        "/v2/contracts/",
        "/v2/events/",
        "/v1/query",
        "/v1/contracts",
    ];
    !READ_ONLY_PREFIXES.iter().any(|p| path.starts_with(p))
}

fn log_form(req: &HttpRequest, at_micros: i64, status: u16) -> LoggedRequest {
    let mut query: Vec<_> = req.query_params.clone().into_iter().collect();
    query.sort();
    // the parties a v1 call acts as come from its headers or token; the token itself is a secret and stays out of the log
    let (act_as, read_as) = crate::http::extract_parties(req);
    let mut headers = Vec::new();
    if !act_as.is_empty() {
        headers.push(("x-daml-act-as".to_string(), act_as.join(",")));
    }
    if !read_as.is_empty() {
        headers.push(("x-daml-read-as".to_string(), read_as.join(",")));
    }
    if let Some(ct) = req.headers.get("content-type") {
        headers.push(("content-type".to_string(), ct.clone()));
    }
    LoggedRequest {
        at_micros,
        method: req.method.clone(),
        path: req.path.clone(),
        status,
        query,
        headers,
        body: req.body.clone(),
    }
}

/// Serves a state-changing request under the log lock: fixes the clock, runs it, and records it before answering.
///
/// The lock serializes the logged requests, so the log order is the order the state changed in (replay depends on it). The
/// arrival-stamp model of racing consumes (`ExecutionService::tick`) does not depend on real parallelism, so it still sees an
/// overlapping consume as locked.
pub(crate) fn dispatch_logged(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let slot = service.persist_slot();
    let Ok(mut guard) = slot.lock() else {
        return unavailable("the request log lock is poisoned");
    };
    let Some(log) = guard.as_mut() else {
        return crate::http::dispatch_checked(service, req);
    };
    // a request the authentication refuses changes nothing and must never reach the log (replay skips authentication)
    let filled = match crate::auth::admit(service, req) {
        Ok(filled) => filled,
        Err(denied) => return denied,
    };
    // replay skips authentication: the log keeps the request with the user id the token filled in
    let req = filled.as_ref().unwrap_or(req);
    if service.persist_failed.load(Ordering::SeqCst) {
        return unavailable("an earlier write to the request log failed; restart to recover");
    }
    let at = crate::clock::real_micros();
    let before = service.state_fingerprint();
    let resp = crate::clock::with_fixed(at, || crate::http::route_request(service, req));
    let succeeded = (200..300).contains(&resp.status);
    if !succeeded && service.state_fingerprint() == before {
        return resp; // it left no trace
    }
    if let Err(e) = log.append(&log_form(req, at, resp.status)) {
        // the state already changed in memory but is not durable: stop taking writes, a restart replays what is on disk
        service.persist_failed.store(true, Ordering::SeqCst);
        return unavailable(&format!("could not persist the request: {e}"));
    }
    let every = service.snapshot_every.load(Ordering::SeqCst);
    let seq = log.current_seq();
    if every > 0 && seq > 0 && seq % every == 0 {
        if let Ok(payload) = crate::snapshot::encode_checkpoint(service) {
            let _ = log.save_snapshot(&LogSnapshot { seq, payload });
        }
    }
    resp
}

fn unavailable(why: &str) -> HttpResponse {
    HttpResponse::error_json(503, why)
}

thread_local! {
    static REPLAYING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the current thread is replaying the request log. A request that depended on a setting or on the time (a prune is
/// refused while the offset is younger than the deduplication window) was accepted once; replay must not judge it again by
/// what the configuration says now.
pub(crate) fn is_replaying() -> bool {
    REPLAYING.with(std::cell::Cell::get)
}

/// What starting from a store did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    pub replayed: usize,
    /// How long the replay took (microseconds), so a slow start is visible instead of a mystery.
    pub micros: u128,
    /// Sequence covered by restored checkpoint snapshot (`0` when rebuilt strictly from the log).
    pub snapshot_seq: u64,
}

impl ExecutionService {
    /// Rebuilds the state from `log` (using any valid checkpoint snapshot + tail replay), then keeps the log to record
    /// every later state-changing request.
    pub fn attach_store(&self, mut log: Box<dyn RequestLog>) -> Result<ReplayReport, String> {
        let started = std::time::Instant::now();
        struct Replaying;
        impl Replaying {
            fn start() -> Self {
                REPLAYING.with(|r| r.set(true));
                Self
            }
        }
        impl Drop for Replaying {
            fn drop(&mut self) {
                REPLAYING.with(|r| r.set(false));
            }
        }
        let replaying = Replaying::start();

        let (snapshot_seq, records) = match log.load_snapshot() {
            Ok(Some(snap)) if crate::snapshot::restore_checkpoint(self, &snap.payload).is_ok() => {
                let tail = log
                    .load_after(snap.seq)
                    .map_err(|e| format!("cannot read the request log tail: {e}"))?;
                (snap.seq, tail)
            }
            _ => {
                let all = log
                    .load()
                    .map_err(|e| format!("cannot read the request log: {e}"))?;
                (0, all)
            }
        };

        for (i, rec) in records.iter().enumerate() {
            let req = rec.to_request();
            let resp =
                crate::clock::with_fixed(rec.at_micros, || crate::http::route_request(self, &req));
            if (200..300).contains(&rec.status) && !(200..300).contains(&resp.status) {
                return Err(format!(
                    "replay of record {i} ({} {}) answered {}: {}",
                    rec.method,
                    rec.path,
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                ));
            }
        }
        drop(replaying);
        let mut slot = self
            .persist_slot()
            .lock()
            .map_err(|_| "the request log lock is poisoned".to_string())?;
        *slot = Some(log);
        Ok(ReplayReport {
            replayed: records.len(),
            micros: started.elapsed().as_micros(),
            snapshot_seq,
        })
    }

    /// Saves a checkpoint snapshot of the current ledger state at `log.current_seq()` (`U-16`).
    pub fn checkpoint_store(&self) -> Result<Option<u64>, String> {
        let mut guard = self
            .persist_slot()
            .lock()
            .map_err(|_| "the request log lock is poisoned".to_string())?;
        let Some(log) = guard.as_mut() else {
            return Ok(None);
        };
        let seq = log.current_seq();
        let payload = crate::snapshot::encode_checkpoint(self)?;
        log.save_snapshot(&LogSnapshot { seq, payload })
            .map_err(|e| format!("failed to save snapshot: {e}"))?;
        Ok(Some(seq))
    }

    /// Saves a fresh snapshot checkpoint and truncates log records up to that sequence (`U-16`).
    pub fn compact_store(&self) -> Result<Option<u64>, String> {
        let mut guard = self
            .persist_slot()
            .lock()
            .map_err(|_| "the request log lock is poisoned".to_string())?;
        let Some(log) = guard.as_mut() else {
            return Ok(None);
        };
        let seq = log.current_seq();
        let payload = crate::snapshot::encode_checkpoint(self)?;
        log.save_snapshot(&LogSnapshot { seq, payload })
            .map_err(|e| format!("failed to save snapshot before compaction: {e}"))?;
        log.compact_before(seq)
            .map_err(|e| format!("failed to compact log up to seq {seq}: {e}"))?;
        Ok(Some(seq))
    }

    pub(crate) fn has_store(&self) -> bool {
        self.persist_slot().lock().is_ok_and(|g| g.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LoggedRequest {
        LoggedRequest {
            at_micros: 1_700_000_000_123_456,
            method: "POST".into(),
            path: "/v2/parties".into(),
            status: 200,
            query: vec![("a".into(), "b".into())],
            headers: vec![("x-daml-act-as".into(), "alice".into())],
            body: b"{\"partyIdHint\":\"x\"}".to_vec(),
        }
    }

    #[test]
    fn record_round_trips() {
        let r = sample();
        assert_eq!(LoggedRequest::decode(&r.encode()), Some(r));
    }

    #[test]
    fn decode_rejects_garbage_and_trailing_bytes() {
        let mut bytes = sample().encode();
        assert!(LoggedRequest::decode(&bytes[..bytes.len() - 1]).is_none());
        bytes.push(0);
        assert!(LoggedRequest::decode(&bytes).is_none());
        assert!(LoggedRequest::decode(&[]).is_none());
        assert!(LoggedRequest::decode(&[9, 0, 0]).is_none());
    }

    #[test]
    fn only_state_changing_requests_are_logged() {
        let req = |m: &str, p: &str| HttpRequest {
            method: m.into(),
            path: p.into(),
            query_params: Default::default(),
            headers: Default::default(),
            body: vec![],
        };
        assert!(is_logged(&req("POST", "/v2/parties")));
        assert!(is_logged(&req("POST", "/v2/dars")));
        assert!(is_logged(&req("POST", "/v2/commands/submit-and-wait")));
        assert!(is_logged(&req("POST", "/v2/commands/async/submit")));
        assert!(is_logged(&req("PATCH", "/v2/users/alice")));
        assert!(is_logged(&req("POST", "/v1/create")));
        assert!(!is_logged(&req("GET", "/v2/parties")));
        assert!(!is_logged(&req("POST", "/v2/state/active-contracts")));
        assert!(!is_logged(&req("POST", "/v2/updates")));
        assert!(!is_logged(&req("POST", "/v2/dars/validate")));
        assert!(!is_logged(&req("POST", "/v1/query")));
    }

    #[test]
    fn file_log_snapshot_and_compaction_rebuild_identical_ledger() {
        let dir = std::env::temp_dir().join(format!(
            "canton-rs-file-snap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requests.log");
        let dar_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let dar = std::fs::read(&dar_path).unwrap();

        let svc = ExecutionService::new();
        let log = FileLog::open(&path).unwrap();
        svc.attach_store(Box::new(log)).unwrap();

        let post = |p: &str, body: Vec<u8>, ct: &str| {
            let mut headers = std::collections::HashMap::new();
            headers.insert("content-type".to_string(), ct.to_string());
            let r = crate::http::dispatch_request(
                &svc,
                &HttpRequest {
                    method: "POST".into(),
                    path: p.into(),
                    query_params: Default::default(),
                    headers,
                    body,
                },
            );
            assert_eq!(
                r.status,
                200,
                "POST {p}: {}",
                String::from_utf8_lossy(&r.body)
            );
            serde_json::from_slice::<serde_json::Value>(&r.body).unwrap_or(serde_json::Value::Null)
        };

        post("/v2/dars", dar, "application/octet-stream");
        let alice = post(
            "/v2/parties",
            br#"{"partyIdHint":"alice","identityProviderId":""}"#.to_vec(),
            "application/json",
        )["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();
        let bob = post(
            "/v2/parties",
            br#"{"partyIdHint":"bob","identityProviderId":""}"#.to_vec(),
            "application/json",
        )["partyDetails"]["party"]
            .as_str()
            .unwrap()
            .to_string();

        for i in 0..4 {
            let body = serde_json::json!({
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": alice, "owner": alice, "auditor": bob,
                            "assetSymbol": format!("USD{i}"), "amount": format!("{}.0", i + 1)
                        }
                    }
                }],
                "commandId": format!("cmd-{i}"),
                "userId": "participant_admin",
                "actAs": [alice]
            });
            post(
                "/v2/commands/submit-and-wait",
                serde_json::to_vec(&body).unwrap(),
                "application/json",
            );
        }

        // Checkpoint at seq 7 (1 dar + 2 parties + 4 creates)
        let snap_seq = svc.checkpoint_store().unwrap().unwrap();
        assert_eq!(snap_seq, 7);

        // Append 2 more creates in tail after checkpoint
        for i in 4..6 {
            let body = serde_json::json!({
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#sample-contract:AssetHolding:AssetHolding",
                        "createArguments": {
                            "bank": alice, "owner": alice, "auditor": bob,
                            "assetSymbol": format!("USD{i}"), "amount": format!("{}.0", i + 1)
                        }
                    }
                }],
                "commandId": format!("cmd-{i}"),
                "userId": "participant_admin",
                "actAs": [alice]
            });
            post(
                "/v2/commands/submit-and-wait",
                serde_json::to_vec(&body).unwrap(),
                "application/json",
            );
        }
        let expected_end = svc.v2_state().ledger_end.load(Ordering::SeqCst);
        let expected_acs = svc.v2_active_contracts().len();
        assert_eq!(expected_acs, 6);
        drop(svc);

        // Restart 1: loads snapshot(seq=7) + replays only 2 tail requests
        let restored1 = ExecutionService::new();
        let report1 = restored1
            .attach_store(Box::new(FileLog::open(&path).unwrap()))
            .unwrap();
        assert_eq!(report1.snapshot_seq, 7);
        assert_eq!(report1.replayed, 2);
        assert_eq!(
            restored1.v2_state().ledger_end.load(Ordering::SeqCst),
            expected_end
        );
        assert_eq!(restored1.v2_active_contracts().len(), 6);

        // Compact up to seq 9, then append 1 more create and restart again
        assert_eq!(restored1.compact_store().unwrap(), Some(9));
        let body = serde_json::json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": alice, "owner": alice, "auditor": bob,
                        "assetSymbol": "EUR0", "amount": "10.0"
                    }
                }
            }],
            "commandId": "cmd-tail",
            "userId": "participant_admin",
            "actAs": [alice]
        });
        let r = crate::http::dispatch_request(
            &restored1,
            &HttpRequest {
                method: "POST".into(),
                path: "/v2/commands/submit-and-wait".into(),
                query_params: Default::default(),
                headers: [("content-type".to_string(), "application/json".to_string())]
                    .into_iter()
                    .collect(),
                body: serde_json::to_vec(&body).unwrap(),
            },
        );
        assert_eq!(r.status, 200);
        let final_end = restored1.v2_state().ledger_end.load(Ordering::SeqCst);
        drop(restored1);

        let restored2 = ExecutionService::new();
        let report2 = restored2
            .attach_store(Box::new(FileLog::open(&path).unwrap()))
            .unwrap();
        assert_eq!(report2.snapshot_seq, 9);
        assert_eq!(report2.replayed, 1);
        assert_eq!(
            restored2.v2_state().ledger_end.load(Ordering::SeqCst),
            final_end
        );
        assert_eq!(restored2.v2_active_contracts().len(), 7);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
