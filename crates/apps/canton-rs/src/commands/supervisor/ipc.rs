//! Unix domain socket NDJSON IPC (`<state-dir>/daemon.sock`, `0o600` permissions).
//!
//! [CANTON-NOTE: WHY] macOS limits `sockaddr_un.sun_path` to 104 bytes (`sizeof(sun_path) - 1`).
//! When `<state-dir>/daemon.sock` exceeds 92 bytes (common in deep `/tmp` or CI test dirs), we
//! bind a short socket path inside a private `0o700` directory `/tmp/crs-<hash>/d.sock` and expose a symlink at `<state-dir>/daemon.sock`.

use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::log_rotate::LogLevel;
use super::{ClusterSnapshot, ExExNodeSummary, NodeInspection, XRayTraceEvent};

/// Default Unix domain socket filename inside `state_dir`.
pub const DAEMON_SOCKET_FILE: &str = "daemon.sock";
const MAX_DIRECT_SOCK_PATH: usize = 92;
const LAST_ACTIVE_STATE_DIR_FILE: &str = "canton-rs-last-state-dir";
const MAX_IPC_LINE_BYTES: u64 = 16 * 1024 * 1024;
static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// NDJSON request envelope sent by `daemon` CLI subcommands, TUI, and `console attach/exec`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    GetSnapshot,
    GetExex,
    Inspect {
        node: String,
    },
    TraceXray {
        root_hash: String,
    },
    RunScenario {
        spec: super::scenario::ScenarioSpec,
    },
    SubscribeXray {
        #[serde(default)]
        rate_limit_per_sec: Option<u32>,
    },
    SubscribeSnapshots {
        #[serde(default)]
        interval_ms: Option<u64>,
    },
    SubscribeLogs {
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        min_level: Option<String>,
        #[serde(default)]
        tail: Option<usize>,
    },
    StopNodes {
        targets: Vec<String>,
    },
    StartNodes {
        targets: Vec<String>,
    },
    Restart {
        #[serde(default)]
        target: Option<String>,
    },
    TriggerPing,
    Down {
        #[serde(default)]
        timeout_secs: Option<u64>,
        #[serde(default)]
        clean_files: Option<bool>,
        #[serde(default)]
        stream_progress: bool,
    },
}

/// Started slot acknowledgement returned by `start_nodes`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartedNodeInfo {
    pub node: String,
    pub pid: u32,
}

/// One-shot NDJSON response returned for unary IPC commands.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpcResponse {
    Snapshot {
        ok: bool,
        snapshot: ClusterSnapshot,
    },
    Inspection {
        ok: bool,
        inspection: Box<NodeInspection>,
    },
    Trace {
        ok: bool,
        trace: XRayTraceEvent,
    },
    StoppedNodes {
        ok: bool,
        stopped: Vec<String>,
    },
    StartedNodes {
        ok: bool,
        started: Vec<StartedNodeInfo>,
    },
    Restarted {
        ok: bool,
        restarted: Vec<String>,
    },
    Ping {
        ok: bool,
        rtt_ms: f64,
        detail: String,
    },
    DownAck {
        ok: bool,
        stopped: usize,
    },
    Exex {
        ok: bool,
        nodes: Vec<ExExNodeSummary>,
    },
    ScenarioReport {
        ok: bool,
        report: super::scenario::ScenarioRunReport,
    },
    Error {
        ok: bool,
        error: String,
    },
}

impl IpcResponse {
    /// Constructs a canonical JSON error response.
    pub fn err(msg: impl Into<String>) -> Self {
        Self::Error {
            ok: false,
            error: msg.into(),
        }
    }
}

/// Structured real-time teardown milestone emitted during `canton-rs daemon down`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum DownProgressEvent {
    Started {
        stack_name: String,
        synchronizer: String,
        storage_mode: String,
        state_dir: String,
        timeout_secs: u64,
        clean_files: bool,
        order: Vec<String>,
    },
    StoppingSlot {
        step: usize,
        total: usize,
        name: String,
        role: String,
        pid: u32,
        ports: String,
        timeout_secs: u64,
    },
    SlotStopped {
        step: usize,
        total: usize,
        name: String,
        role: String,
        pid: u32,
        elapsed_ms: u64,
        forced_kill: bool,
    },
    SlotSkipped {
        step: usize,
        total: usize,
        name: String,
        role: String,
    },
    CleaningFiles {
        state_dir: String,
        clean_files: bool,
        removed_entries: usize,
        /// Why `--clean-files` left the directory alone (not the supervisor's, or it holds the working/home directory).
        #[serde(default)]
        refused: Option<String>,
    },
    Completed {
        stopped: usize,
        elapsed_ms: u64,
        clean_files: bool,
    },
}

/// Streaming NDJSON event pushed over `subscribe_*` and `down` progress connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcStreamEvent {
    Snapshot {
        data: ClusterSnapshot,
    },
    Xray {
        data: XRayTraceEvent,
    },
    Log {
        ts: u64,
        node: String,
        level: LogLevel,
        line: String,
    },
    DownProgress {
        data: DownProgressEvent,
    },
}

/// Cleanup guard that removes `<state_dir>/daemon.sock`, its fallback socket, and any fallback directory on drop.
pub struct IpcSocketCleanup {
    pub logical_path: PathBuf,
    pub bound_path: PathBuf,
    fallback_dir: Option<PathBuf>,
}

impl Drop for IpcSocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.logical_path);
        if self.bound_path != self.logical_path {
            let _ = std::fs::remove_file(&self.bound_path);
        }
        if let Some(dir) = &self.fallback_dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Bound Unix listener together with cleanup metadata for symlink fallback sockets.
pub struct BoundIpcListener {
    pub listener: tokio::net::UnixListener,
    cleanup: IpcSocketCleanup,
}

impl BoundIpcListener {
    /// Splits the bound listener from its socket cleanup guard so teardown can retain the
    /// socket file until all child slots and manifests finish shutting down.
    pub fn into_parts(self) -> (tokio::net::UnixListener, IpcSocketCleanup) {
        (self.listener, self.cleanup)
    }
}

/// Returns `<state_dir>/daemon.sock`.
pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DAEMON_SOCKET_FILE)
}

/// Resolves `state_dir` for client commands (`top`, `ps`, `stop`, `start`, `down`, `console attach`):
/// when `state_dir` is the default `canton-rs-state` and its `daemon.sock` does not exist, falls back
/// to the most recently started supervisor's `state_dir` if its socket is still present.
pub fn resolve_client_state_dir(state_dir: &Path) -> PathBuf {
    let direct = socket_path(state_dir);
    if direct.exists() || direct.symlink_metadata().is_ok() {
        return state_dir.to_path_buf();
    }
    if state_dir == Path::new("canton-rs-state") {
        let marker = std::env::temp_dir().join(LAST_ACTIVE_STATE_DIR_FILE);
        if let Ok(saved) = std::fs::read_to_string(marker) {
            let candidate = PathBuf::from(saved.trim());
            let sock = socket_path(&candidate);
            if sock.exists() || sock.symlink_metadata().is_ok() {
                return candidate;
            }
        }
    }
    state_dir.to_path_buf()
}

/// Binds `<state_dir>/daemon.sock` with mode `0600` (and `/tmp` symlink fallback if path > 92B).
pub fn bind_socket(state_dir: &Path) -> io::Result<BoundIpcListener> {
    std::fs::create_dir_all(state_dir)?;
    let logical_path = socket_path(state_dir);
    let _ = std::fs::remove_file(&logical_path);

    let canonical_dir =
        std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    let _ = write_replacing(
        &std::env::temp_dir().join(LAST_ACTIVE_STATE_DIR_FILE),
        canonical_dir.to_string_lossy().as_bytes(),
    );
    let candidate = canonical_dir.join(DAEMON_SOCKET_FILE);
    let (bound_path, fallback_dir) = if candidate.as_os_str().len() <= MAX_DIRECT_SOCK_PATH {
        (candidate, None)
    } else {
        let mut h = Sha256::new();
        h.update(candidate.as_os_str().to_string_lossy().as_bytes());
        let tag = hex::encode(&h.finalize()[..8]);
        let fb_dir = std::env::temp_dir().join(format!("crs-{}", &tag[..12]));
        #[cfg(unix)]
        {
            match std::fs::symlink_metadata(&fb_dir) {
                Ok(meta) => {
                    if meta.file_type().is_symlink()
                        || !meta.is_dir()
                        || (meta.permissions().mode() & 0o077) != 0
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "unsafe fallback IPC socket directory at {}",
                                fb_dir.display()
                            ),
                        ));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let mut builder = std::fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&fb_dir)?;
                    std::fs::set_permissions(&fb_dir, std::fs::Permissions::from_mode(0o700))?;
                }
                Err(e) => return Err(e),
            }
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&fb_dir)?;
        let short = fb_dir.join("d.sock");
        let _ = std::fs::remove_file(&short);
        (short, Some(fb_dir))
    };

    let listener = tokio::net::UnixListener::bind(&bound_path)?;
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&bound_path, perms)?;
        if bound_path != logical_path {
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&bound_path, &logical_path);
        }
    }

    Ok(BoundIpcListener {
        listener,
        cleanup: IpcSocketCleanup {
            logical_path,
            bound_path,
            fallback_dir,
        },
    })
}

/// Writes `bytes` to a fresh sibling file and renames it over `path`, so a symlink planted at `path` in a shared directory is
/// replaced rather than followed.
fn write_replacing(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{seq}", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Checks synchronously whether an active supervisor daemon responds on `<state_dir>/daemon.sock`.
pub fn probe_daemon_alive(state_dir: &Path) -> bool {
    let sock = socket_path(state_dir);
    if !sock.exists() && sock.symlink_metadata().is_err() {
        return false;
    }
    matches!(
        call_unary(state_dir, &IpcRequest::GetSnapshot),
        Ok(IpcResponse::Snapshot { ok: true, .. })
    )
}

/// Classifies unary IPC errors so callers only fall back locally when the daemon was never reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcCallError {
    Unreachable(String),
    PostSend(String),
}

impl std::fmt::Display for IpcCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(msg) | Self::PostSend(msg) => f.write_str(msg),
        }
    }
}

/// Sends a unary request to `<state_dir>/daemon.sock` and reads one NDJSON line response.
pub fn call_unary(state_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, String> {
    call_unary_with_timeout(state_dir, req, None)
}

/// Sends a unary request to `<state_dir>/daemon.sock` with an optional read timeout and a `16 MiB` response line cap.
pub fn call_unary_with_timeout(
    state_dir: &Path,
    req: &IpcRequest,
    read_timeout: Option<Duration>,
) -> Result<IpcResponse, String> {
    call_unary_typed(state_dir, req, read_timeout).map_err(|e| e.to_string())
}

/// Sends a unary request to `<state_dir>/daemon.sock` while distinguishing connect-time unreachability from post-connect errors.
pub fn call_unary_typed(
    state_dir: &Path,
    req: &IpcRequest,
    read_timeout: Option<Duration>,
) -> Result<IpcResponse, IpcCallError> {
    let eff_dir = resolve_client_state_dir(state_dir);
    let sock = socket_path(&eff_dir);
    let mut stream = connect_unix_typed(&sock)?;
    stream
        .set_read_timeout(read_timeout)
        .map_err(|e| IpcCallError::PostSend(format!("failed to configure IPC timeout: {e}")))?;
    let line = serde_json::to_string(req).map_err(|e| IpcCallError::PostSend(e.to_string()))?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| IpcCallError::PostSend(format!("failed to send IPC command: {e}")))?;
    stream
        .flush()
        .map_err(|e| IpcCallError::PostSend(format!("failed to flush IPC socket: {e}")))?;

    let mut reader = BufReader::new(stream.take(MAX_IPC_LINE_BYTES + 1));
    let mut resp_line = String::new();
    let n = read_stream_line(
        &mut reader,
        &mut resp_line,
        "waiting for IPC response",
        read_timeout,
    )
    .map_err(IpcCallError::PostSend)?;
    if n == 0 {
        return Err(IpcCallError::PostSend(
            "supervisor daemon closed IPC socket without a response".to_string(),
        ));
    }
    if n as u64 > MAX_IPC_LINE_BYTES {
        return Err(IpcCallError::PostSend(format!(
            "supervisor IPC response exceeded {} byte limit",
            MAX_IPC_LINE_BYTES
        )));
    }
    let resp: IpcResponse = serde_json::from_str(&resp_line)
        .map_err(|e| IpcCallError::PostSend(format!("invalid IPC JSON: {e}")))?;
    if let IpcResponse::Error { ok: false, error } = resp {
        return Err(IpcCallError::PostSend(error));
    }
    Ok(resp)
}

/// Opens a streaming NDJSON subscription over `<state_dir>/daemon.sock`.
pub fn open_stream(
    state_dir: &Path,
    req: &IpcRequest,
    read_timeout: Option<Duration>,
) -> Result<BufReader<UnixStream>, String> {
    let eff_dir = resolve_client_state_dir(state_dir);
    let sock = socket_path(&eff_dir);
    let mut stream = connect_unix(&sock)?;
    stream
        .set_read_timeout(read_timeout)
        .map_err(|e| format!("failed to configure stream timeout: {e}"))?;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| format!("failed to start IPC stream: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("failed to flush IPC stream: {e}"))?;
    Ok(BufReader::new(stream))
}

/// Formats an IPC stream read/timeout error consistently, mapping `TimedOut`/`WouldBlock` to `"timed out"`.
pub fn format_ipc_io_error(
    context: &str,
    read_timeout: Option<Duration>,
    err: &io::Error,
) -> String {
    if matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        if let Some(limit) = read_timeout {
            return format!(
                "supervisor daemon IPC timed out {context} after {}ms: {err}",
                limit.as_millis()
            );
        }
        return format!("supervisor daemon IPC timed out {context}: {err}");
    }
    format!("failed to read IPC ({context}): {err}")
}

/// Reads one NDJSON line from an IPC stream reader with consistent timeout error formatting.
pub fn read_stream_line<R: BufRead>(
    reader: &mut R,
    buf: &mut String,
    context: &str,
    read_timeout: Option<Duration>,
) -> Result<usize, String> {
    reader
        .read_line(buf)
        .map_err(|e| format_ipc_io_error(context, read_timeout, &e))
}

#[cfg(unix)]
fn connect_unix(sock: &Path) -> Result<UnixStream, String> {
    connect_unix_typed(sock).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn connect_unix_typed(sock: &Path) -> Result<UnixStream, IpcCallError> {
    let resolved = std::fs::read_link(sock).unwrap_or_else(|_| sock.to_path_buf());
    let stream = UnixStream::connect(&resolved).map_err(|e| {
        let msg = format!(
            "no running canton-rs supervisor found at {} ({e}); start one with 'canton-rs daemon up'",
            sock.display()
        );
        if matches!(
            e.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        ) {
            IpcCallError::Unreachable(msg)
        } else {
            IpcCallError::PostSend(msg)
        }
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The last-state-dir note in the shared temp directory replaces a symlink planted there instead of writing through it.
    #[cfg(unix)]
    #[test]
    fn last_state_dir_note_does_not_follow_a_symlink() {
        let dir = std::env::temp_dir().join(format!("canton-ipc-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"precious").expect("write");
        let note = dir.join("note");
        std::os::unix::fs::symlink(&victim, &note).expect("symlink");
        write_replacing(&note, b"/state").expect("write note");
        assert_eq!(std::fs::read(&victim).expect("read"), b"precious");
        assert_eq!(std::fs::read(&note).expect("read"), b"/state");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trips_ipc_request_and_response_json() {
        let req = IpcRequest::SubscribeLogs {
            node: Some("participant1".into()),
            min_level: Some("INFO".into()),
            tail: Some(100),
        };
        let wire = serde_json::to_string(&req).expect("serialize request");
        assert!(wire.contains("\"cmd\":\"subscribe_logs\""));
        let decoded: IpcRequest = serde_json::from_str(&wire).expect("deserialize request");
        assert!(matches!(decoded, IpcRequest::SubscribeLogs { .. }));

        let ping_json = r#"{"ok":true,"rtt_ms":2.8,"detail":"participant1 -> participant1"}"#;
        let parsed: IpcResponse = serde_json::from_str(ping_json).expect("parse ping");
        assert!(matches!(parsed, IpcResponse::Ping { ok: true, .. }));

        let legacy_down = r#"{"cmd":"down","timeout_secs":5}"#;
        let parsed_down: IpcRequest = serde_json::from_str(legacy_down).expect("parse legacy down");
        assert!(matches!(
            parsed_down,
            IpcRequest::Down {
                timeout_secs: Some(5),
                clean_files: None,
                stream_progress: false,
            }
        ));

        let prog = IpcStreamEvent::DownProgress {
            data: DownProgressEvent::SlotStopped {
                step: 1,
                total: 3,
                name: "participant1".into(),
                role: "participant".into(),
                pid: 4242,
                elapsed_ms: 145,
                forced_kill: false,
            },
        };
        let prog_wire = serde_json::to_string(&prog).expect("serialize down progress");
        let parsed_prog: IpcStreamEvent =
            serde_json::from_str(&prog_wire).expect("deserialize down progress");
        assert!(matches!(
            parsed_prog,
            IpcStreamEvent::DownProgress {
                data: DownProgressEvent::SlotStopped {
                    step: 1,
                    total: 3,
                    forced_kill: false,
                    ..
                }
            }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn long_state_dir_uses_private_0700_fallback_dir_and_cleans_up() {
        let deep = std::env::temp_dir()
            .join(format!("canton-deep-ipc-test-{}", std::process::id()))
            .join("very_long_segment_1234567890_1234567890_1234567890")
            .join("another_long_segment_1234567890_1234567890");
        let _ = std::fs::remove_dir_all(&deep);
        let bound = bind_socket(&deep).expect("bind deep socket");
        let fb_dir = bound
            .cleanup
            .fallback_dir
            .clone()
            .expect("long path must use fallback dir");
        assert!(fb_dir.exists(), "fallback dir must exist while live");
        let dir_mode = std::fs::metadata(&fb_dir)
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "fallback dir must have private 0700 mode");
        let sock_mode = std::fs::metadata(&bound.cleanup.bound_path)
            .expect("sock meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600, "socket inside fallback dir must be 0600");
        assert!(bound.cleanup.logical_path.symlink_metadata().is_ok());

        drop(bound);
        assert!(
            !fb_dir.exists(),
            "dropping BoundIpcListener must remove empty fallback dir: {}",
            fb_dir.display()
        );
        let root_tmp = deep.parent().and_then(Path::parent).expect("root test dir");
        let _ = std::fs::remove_dir_all(root_tmp);
    }

    #[cfg(unix)]
    #[test]
    fn read_stream_line_maps_socket_timeout_to_timed_out_error() {
        let (client, server) = UnixStream::pair().expect("unix stream pair");
        let timeout = Duration::from_millis(25);
        client.set_read_timeout(Some(timeout)).expect("set timeout");
        let mut reader = BufReader::new(client);
        let mut buf = String::new();
        let err = read_stream_line(
            &mut reader,
            &mut buf,
            "reading supervisor down progress",
            Some(timeout),
        )
        .expect_err("silent peer must time out with mapped error");
        drop(server);
        assert!(
            err.contains("timed out"),
            "expected 'timed out' in error message, got: {err}"
        );
    }
}
