//! OS child process lifecycle, orphan prevention (`PR_SET_PDEATHSIG` + `daemon.pids.json`),
//! Self-Reexec detachment (`-d`), and reverse-order graceful shutdown (`SIGTERM` -> `SIGKILL`).

use std::collections::BTreeMap;
use std::io;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::now_unix_secs;
use super::proc_sampler::pid_matches_expected;

/// Alias re-exported for caller closures so `audit-native.py` tracks spawn factories in one file.
pub type ChildCmd = Command;

/// Filename storing active supervisor-managed PIDs inside `state_dir`.
pub const PID_MANIFEST_FILE: &str = "daemon.pids.json";

/// Monitored child process guard guaranteeing graceful `SIGTERM` -> `SIGKILL` stop on `Drop`.
pub struct ManagedProc {
    pub role: String,
    pub child: Child,
}

impl Drop for ManagedProc {
    fn drop(&mut self) {
        graceful_stop_child(&mut self.child, Duration::from_secs(5));
    }
}

/// Persisted child PID entry for crash/SIGKILL orphan cleanup without PID reuse mistakes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidEntry {
    pub slot_id: usize,
    pub role: String,
    pub name: String,
    pub pid: u32,
    pub started_at_unix: u64,
    pub exe: String,
}

/// Atomic manifest of active supervised child PIDs (`<state-dir>/daemon.pids.json`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidManifest {
    pub entries: Vec<PidEntry>,
}

impl PidManifest {
    /// Reads `<state_dir>/daemon.pids.json`, returning empty if missing or corrupt.
    pub fn load(state_dir: &Path) -> Self {
        let path = state_dir.join(PID_MANIFEST_FILE);
        let Ok(raw) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    /// Atomically persists the PID manifest via temporary sibling file + `rename`.
    pub fn save_atomic(&self, state_dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(state_dir)?;
        let target = state_dir.join(PID_MANIFEST_FILE);
        let tmp = state_dir.join(format!("{PID_MANIFEST_FILE}.tmp.{}", std::process::id()));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }

    /// Removes the PID manifest file on clean `daemon down`.
    pub fn remove(state_dir: &Path) {
        let _ = std::fs::remove_file(state_dir.join(PID_MANIFEST_FILE));
    }
}

/// Cleans up leftover orphan children from an abrupt supervisor termination (`kill -9`)
/// ONLY when PID identity (binary path + start window) matches the recorded manifest entry.
pub fn cleanup_stale_pids(state_dir: &Path, expected_exe: &Path, grace: Duration) -> Vec<u32> {
    let manifest = PidManifest::load(state_dir);
    let mut killed = Vec::new();
    for entry in manifest.entries {
        if entry.pid == 0 || entry.pid == std::process::id() {
            continue;
        }
        let recorded_exe = Path::new(&entry.exe);
        let matches = pid_matches_expected(entry.pid, recorded_exe, entry.started_at_unix)
            || pid_matches_expected(entry.pid, expected_exe, entry.started_at_unix);
        if matches && kill_pid_graceful(entry.pid, grace) {
            killed.push(entry.pid);
        }
    }
    PidManifest::remove(state_dir);
    killed
}

/// Builds a child `Command` referencing `exe` with extra env vars and optional Linux `PR_SET_PDEATHSIG`.
fn build_command(
    exe: &Path,
    args: &[String],
    extra_env: &BTreeMap<String, String>,
    pdeathsig: bool,
    detach_setsid: bool,
) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    if pdeathsig || detach_setsid {
        // SAFETY: `pre_exec` itself is the sole unsafe call in this block; helpers inside delegate cleanly.
        unsafe {
            cmd.pre_exec(move || {
                if detach_setsid {
                    enable_setsid();
                }
                if pdeathsig {
                    enable_pdeathsig();
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (pdeathsig, detach_setsid);
    cmd
}

#[cfg(unix)]
fn enable_setsid() {
    // SAFETY: `libc::setsid()` is async-signal-safe between `fork` and `exec`.
    unsafe {
        let _ = libc::setsid();
    }
}

#[cfg(target_os = "linux")]
fn enable_pdeathsig() {
    // SAFETY: `prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0)` is async-signal-safe with integer arguments.
    unsafe {
        let _ = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_pdeathsig() {}

/// Creates a `Command` targeting `exe` with Linux `PR_SET_PDEATHSIG(SIGTERM)` orphan protection.
pub fn exe_command(exe: &Path) -> Command {
    let mut cmd = Command::new(exe);
    #[cfg(unix)]
    // SAFETY: `pre_exec` configures `PR_SET_PDEATHSIG` cleanly before `exec`.
    unsafe {
        cmd.pre_exec(|| {
            enable_pdeathsig();
            Ok(())
        });
    }
    cmd
}

/// Runs a prepared `Command` synchronously with `stdin = null`, returning `stdout` on success.
pub fn run_command_to_end(command: &mut Command, what: &str) -> Result<String, String> {
    let out = command
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {what}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{what} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Spawns `exe` as a managed child process with `PR_SET_PDEATHSIG(SIGTERM)` on Linux.
pub fn spawn_managed_with_exe(
    exe: &Path,
    args: &[String],
    extra_env: &BTreeMap<String, String>,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, String> {
    let mut cmd = build_command(exe, args, extra_env, true, false);
    if !extra_env.contains_key("CANTON_RS_PG_URL") {
        // [CANTON-NOTE: INVARIANT] Clear standalone JSON API's `CANTON_RS_PG_URL` from inherited env so
        // multi-participant daemon stacks using `CANTON_RS_STATE_PG_URL` + `--state-name` do not collide on `ledger="default"`.
        cmd.env_remove("CANTON_RS_PG_URL");
    }
    cmd.stdin(Stdio::null()).stdout(stdout).stderr(stderr);
    spawn_on_spawner_thread(cmd).map_err(|e| format!("cannot start {}: {e}", exe.display()))
}

type SpawnJob = (Command, std::sync::mpsc::Sender<io::Result<Child>>);

/// Forks `cmd` on one thread that lives as long as the supervisor.
///
/// [CANTON-NOTE: WHY] Linux delivers `PR_SET_PDEATHSIG` when the *thread* that forked the child exits, not the process. A child forked
/// from a Tokio blocking-pool thread got SIGTERM once that thread idled out (10 s), killing a healthy node.
fn spawn_on_spawner_thread(cmd: Command) -> io::Result<Child> {
    static SPAWNER: std::sync::OnceLock<Option<std::sync::mpsc::Sender<SpawnJob>>> =
        std::sync::OnceLock::new();
    let spawner = SPAWNER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<SpawnJob>();
        std::thread::Builder::new()
            .name("canton-rs-spawner".into())
            .spawn(move || {
                for (mut cmd, reply) in rx {
                    let _ = reply.send(cmd.spawn());
                }
            })
            .ok()
            .map(|_| tx)
    });
    let Some(spawner) = spawner else {
        return Err(io::Error::other("the child spawner thread could not start"));
    };
    let (reply_tx, reply_rx) = std::sync::mpsc::channel();
    spawner
        .send((cmd, reply_tx))
        .map_err(|_| io::Error::other("the child spawner thread is gone"))?;
    reply_rx
        .recv()
        .map_err(|_| io::Error::other("the child spawner thread dropped the request"))?
}

/// Spawns `std::env::current_exe()` with the given arguments and env overrides.
pub fn spawn_current_exe(
    args: &[String],
    extra_env: &BTreeMap<String, String>,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate canton-rs: {e}"))?;
    spawn_managed_with_exe(&exe, args, extra_env, stdout, stderr)
}

/// Spawns the detached `-d` background supervisor worker via Self-Reexec (`setsid` in new session).
///
/// [CANTON-NOTE: WHY] macOS threads + `fork()` without `exec()` crash in CoreFoundation/libdispatch;
/// Self-Reexec immediately calls `execve` inside the new child so the daemon worker starts clean.
pub fn spawn_detached_worker(
    args: &[String],
    extra_env: &BTreeMap<String, String>,
    stdout: Stdio,
    stderr: Stdio,
) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate canton-rs: {e}"))?;
    let mut cmd = build_command(&exe, args, extra_env, false, true);
    cmd.stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| format!("cannot start detached supervisor {}: {e}", exe.display()))
}

/// Returns current executable path.
pub fn current_exe_path() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("cannot locate canton-rs: {e}"))
}

/// Result of stopping a supervised child process with `SIGTERM` grace before `SIGKILL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopChildOutcome {
    AlreadyExited,
    TerminatedGracefully { elapsed_ms: u64 },
    KilledAfterTimeout { elapsed_ms: u64 },
}

/// Sends `SIGTERM` to a `Child`, waits up to `grace`, then `SIGKILL`s if needed, returning timing/signal details.
pub fn graceful_stop_child_report(child: &mut Child, grace: Duration) -> StopChildOutcome {
    if let Ok(Some(_)) = child.try_wait() {
        return StopChildOutcome::AlreadyExited;
    }
    let started = Instant::now();
    let pid = child.id();
    send_signal_unix(pid, libc::SIGTERM);
    let deadline = started + grace;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                return StopChildOutcome::TerminatedGracefully {
                    elapsed_ms: started.elapsed().as_millis() as u64,
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    StopChildOutcome::KilledAfterTimeout {
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

/// Sends `SIGTERM` to a `Child`, waits up to `grace` via `try_wait`, then `SIGKILL`s if needed.
pub fn graceful_stop_child(child: &mut Child, grace: Duration) {
    let _ = graceful_stop_child_report(child, grace);
}

/// Sends `SIGTERM` to an arbitrary PID and waits up to `grace` before escalating to `SIGKILL`.
/// Returns `true` if the signal was accepted for a live process.
pub fn kill_pid_graceful(pid: u32, grace: Duration) -> bool {
    if !send_signal_unix(pid, libc::SIGTERM) {
        return false;
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !is_pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    send_signal_unix(pid, libc::SIGKILL);
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < kill_deadline && is_pid_alive(pid) {
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// Checks whether a PID currently exists on Unix via `kill(pid, 0)`.
#[cfg(unix)]
pub fn is_pid_alive(pid: u32) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    if raw_pid <= 0 {
        return false;
    }
    // SAFETY: `kill(pid, 0)` performs existence/permission probing without delivering a signal.
    let rc = unsafe { libc::kill(raw_pid, 0) };
    if rc == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
pub fn is_pid_alive(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
pub fn send_signal_unix(pid: u32, sig: libc::c_int) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    if raw_pid <= 0 {
        return false;
    }
    // SAFETY: `libc::kill` delivers `sig` to the verified positive process id.
    unsafe { libc::kill(raw_pid, sig) == 0 }
}

#[cfg(not(unix))]
pub fn send_signal_unix(_pid: u32, _sig: i32) -> bool {
    false
}

/// Polls loopback TCP port until accepting connections or `timeout` elapses.
pub fn wait_listening(port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("port {port} did not accept connections"))
}

/// Helper to construct a `PidEntry` stamped with the current Unix second.
pub fn make_pid_entry(slot_id: usize, role: &str, name: &str, pid: u32, exe: &Path) -> PidEntry {
    PidEntry {
        slot_id,
        role: role.to_string(),
        name: name.to_string(),
        pid,
        started_at_unix: now_unix_secs(),
        exe: exe.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(name: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("canton-sup-proc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("create test dir");
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A child spawned from a thread that then exits keeps running (on Linux `PR_SET_PDEATHSIG` fires when the forking thread exits).
    #[test]
    fn managed_child_outlives_the_thread_that_asked_for_it() {
        let child = std::thread::spawn(|| {
            spawn_managed_with_exe(
                Path::new("/bin/sleep"),
                &["30".to_string()],
                &BTreeMap::new(),
                Stdio::null(),
                Stdio::null(),
            )
        })
        .join()
        .expect("spawning thread")
        .expect("sleep starts");
        let mut proc = ManagedProc {
            role: "test".into(),
            child,
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            matches!(proc.child.try_wait(), Ok(None)),
            "child must survive its requesting thread"
        );
        graceful_stop_child(&mut proc.child, Duration::from_secs(2));
    }

    #[test]
    fn pid_manifest_round_trip_and_mismatch_refusal() {
        let dir = TestDir::new("manifest");
        let self_pid = std::process::id();
        let entry = PidEntry {
            slot_id: 0,
            role: "participant".to_string(),
            name: "p1".to_string(),
            pid: 999_999_999, // non-existent PID
            started_at_unix: now_unix_secs(),
            exe: "/nonexistent/other-binary".to_string(),
        };
        let mut manifest = PidManifest {
            entries: vec![entry],
        };
        // Negative control: even if a live PID were listed with mismatched binary name, cleanup must NOT kill it.
        manifest.entries.push(PidEntry {
            slot_id: 1,
            role: "sequencer".to_string(),
            name: "seq1".to_string(),
            pid: self_pid,
            started_at_unix: now_unix_secs(),
            exe: "/nonexistent/different-bin".to_string(),
        });
        manifest.save_atomic(dir.path()).expect("save manifest");
        let loaded = PidManifest::load(dir.path());
        assert_eq!(loaded.entries.len(), 2);

        let killed = cleanup_stale_pids(
            dir.path(),
            Path::new("/nonexistent/different-bin"),
            Duration::from_millis(50),
        );
        assert!(killed.is_empty(), "must refuse mismatched binary identity");
        assert!(!dir.path().join(PID_MANIFEST_FILE).exists());
    }
}
