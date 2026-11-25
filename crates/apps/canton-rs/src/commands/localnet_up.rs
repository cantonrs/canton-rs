//! `canton-rs localnet up`: a LocalNet of **real processes** (G11, S-LOCAL-003). One synchronizer (`canton-rs sequencer run`, the mediator inside
//! it) and N participants (`canton-rs participant run --sequencer`), each its own OS process of this one executable with a JSON API of its own.
//! The scenario then runs through those APIs only: alice (on the first participant) creates a contract that bob (on the second) observes, bob's
//! API must show it, alice settles it, and bob's API must drop it. Each step is reported with what was observed; the run passes only if every
//! step did. `localnet start` is the same command.
//!
//! [CANTON-NOTE: SEMANTICS] The processes are children of this one, started from this executable's own path (`std::env::current_exe`): no
//! helper binary, no interpreter, no JVM. They are stopped when this command ends, whatever the outcome, a stop signal included; each role's
//! output is kept in the LocalNet's private state directory and the end of each log is printed when the LocalNet fails.
use clap::Args;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use super::exit_code::{exit_with_message, EXIT_PREFLIGHT};
use super::port_plan::plan_localnet_ports;
use super::supervisor::doctor::checks::{
    check_d1_port_range, check_d2_protected_ports, check_d3_ports_in_use,
};
use super::supervisor::doctor::plan::PortEntry;
use super::supervisor::doctor::{CheckStatus, DoctorHost, DoctorPlan};
use super::supervisor::process::{
    exe_command, run_command_to_end as run_to_end, send_signal_unix, ChildCmd, ManagedProc as Proc,
};
use super::supervisor::status::{
    remove_localnet_status_file, write_localnet_status_file, LocalnetEndpointEntry,
    LocalnetStatusFile,
};

#[derive(Args, Debug)]
pub struct LocalnetUpArgs {
    /// Number of participants (at least two for the scenario).
    #[arg(short, long, alias = "nodes", default_value_t = 2)]
    pub participants: usize,

    /// Number of synchronizers (sequencer + mediator each). With two or more, every participant is connected to all of them and the scenario
    /// reassigns a contract from the first to the second.
    #[arg(long, default_value_t = 1)]
    pub synchronizers: usize,

    /// The DAR every participant runs.
    #[arg(long, default_value = "contracts/target/sample-contract.dar")]
    pub dar: String,

    /// Keep the LocalNet running after the scenario until this command is stopped.
    #[arg(long, alias = "foreground", default_value_t = false)]
    pub keep: bool,

    /// Run the mediator inside the sequencer process (the shortcut) instead of as a process of its own.
    #[arg(long, default_value_t = false)]
    pub embedded_mediator: bool,

    /// Leave out the scan app (by default a `canton-rs scan serve` process answers the Splice scan update history of the first participant).
    #[arg(long, default_value_t = false)]
    pub no_scan: bool,

    /// Leave out the Splice apps (by default a `canton-rs splice serve` process runs the SV, validator, wallet and automation APIs on the
    /// official Splice 0.10.1 DARs of `--splice-dar-dir`).
    #[arg(long, default_value_t = false)]
    pub no_splice: bool,

    /// The directory of the official Splice DARs the Splice apps run.
    #[arg(long, default_value = "tests/oracle/splice-dars")]
    pub splice_dar_dir: String,

    /// Keep the state of the sequencer, the mediator and the participants in this PostgreSQL database (a libpq-style URL; prefer the
    /// environment variable, the URL is handed to the processes in their environment, not on their command line).
    #[arg(long, env = "CANTON_RS_LOCALNET_PG_URL")]
    pub pg_url: Option<String>,

    /// With `--pg-url`: the prefix of the roles' state names in the database (`<prefix>-seq`, `<prefix>-p1`, ...).
    #[arg(long, default_value = "localnet")]
    pub pg_name: String,

    /// Deterministic fixed port base (`π_B(ℓ) = B + δ(ℓ)`); prefights D1–D3 before creating state or spawning (`S-DX-002`).
    #[arg(long)]
    pub port_base: Option<u16>,

    /// State directory for logs and `localnet-status.json` metadata (defaults to a private temp dir).
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

/// `eprintln!` that cannot fail: a closed stderr (the caller stopped reading) must not end the thread that stops the LocalNet.
macro_rules! say {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// The processes of one LocalNet and its private state directory (the mediators' keys, the scan history, each role's log in `logs/`).
/// [`Net::stop`] stops the processes, last started first, and only then removes the directory; it runs on every way out of [`run`],
/// a stop signal included.
struct Net {
    state: PathBuf,
    remove_dir_on_stop: bool,
    procs: Mutex<Running>,
}

#[derive(Default)]
struct Running {
    procs: Vec<Proc>,
    stopped: bool,
}

impl Net {
    fn new(explicit_state_dir: Option<&Path>) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let (state, remove_dir_on_stop) = match explicit_state_dir {
            None => {
                let dir = std::env::temp_dir().join(format!(
                    "localnet-{}-{:016x}",
                    std::process::id(),
                    rand::random::<u64>()
                ));
                // `create`, not `create_all`: a directory someone else made under that name is refused, not reused
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| {
                        format!("cannot create the state directory {}: {e}", dir.display())
                    })?;
                (dir, true)
            }
            Some(dir) => {
                let existed = dir.exists();
                if !existed {
                    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            format!("cannot create parent directory {}: {e}", parent.display())
                        })?;
                    }
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(dir)
                        .map_err(|e| {
                            format!("cannot create the state directory {}: {e}", dir.display())
                        })?;
                }
                (dir.to_path_buf(), !existed)
            }
        };
        std::fs::create_dir_all(state.join("logs")).map_err(|e| e.to_string())?;
        Ok(Self {
            state,
            remove_dir_on_stop,
            procs: Mutex::new(Running::default()),
        })
    }

    fn running(&self) -> std::sync::MutexGuard<'_, Running> {
        self.procs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keeps `proc` to be stopped with the rest; one started after [`Net::stop`] is stopped at once.
    fn add(&self, proc: Proc) {
        let mut running = self.running();
        if running.stopped {
            drop(running);
            drop(proc);
        } else {
            running.procs.push(proc);
        }
    }

    fn stop(&self) {
        remove_localnet_status_file(&self.state);
        let procs = {
            let mut running = self.running();
            running.stopped = true;
            std::mem::take(&mut running.procs)
        };
        // all of them asked at once, so one slow to stop does not leave the others running for its grace time
        for proc in &procs {
            send_signal_unix(proc.child.id(), libc::SIGTERM);
        }
        for proc in procs.into_iter().rev() {
            drop(proc);
        }
        if self.remove_dir_on_stop {
            let _ = std::fs::remove_dir_all(&self.state);
        }
    }

    fn logs(&self) -> PathBuf {
        self.state.join("logs")
    }

    /// The log file of a role (`logs/<name>.log`).
    fn log(&self, name: &str) -> Result<File, String> {
        File::create(self.logs().join(format!("{name}.log")))
            .map_err(|e| format!("cannot create the log of {name}: {e}"))
    }

    /// Both output streams of a role into its log file.
    fn logged(&self, name: &str) -> Result<(Stdio, Stdio), String> {
        let out = self.log(name)?;
        let err = out.try_clone().map_err(|e| e.to_string())?;
        Ok((out.into(), err.into()))
    }

    /// The end of each role's log, for a LocalNet that failed.
    fn print_log_tails(&self) {
        let Ok(dir) = std::fs::read_dir(self.logs()) else {
            return;
        };
        let mut paths: Vec<PathBuf> = dir.filter_map(|e| Some(e.ok()?.path())).collect();
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let lines: Vec<&str> = text.lines().collect();
            let tail = &lines[lines.len().saturating_sub(20)..];
            say!("--- {} (last {} lines) ---", path.display(), tail.len());
            for line in tail {
                say!("{line}");
            }
        }
    }
}

/// Stops the LocalNet and ends this process on SIGTERM or SIGINT, whenever it comes: a process ended by a signal runs no destructors, and
/// on macOS nothing else stops the children. The handlers are installed before this returns, so before any child is started.
fn stop_on_signal(net: Arc<Net>, kept: Arc<AtomicBool>) -> Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let (mut term, mut int) = runtime
        .block_on(async {
            Ok::<_, std::io::Error>((
                signal(SignalKind::terminate())?,
                signal(SignalKind::interrupt())?,
            ))
        })
        .map_err(|e| format!("cannot handle stop signals: {e}"))?;
    std::thread::spawn(move || {
        runtime.block_on(async {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        });
        say!("stopping the LocalNet");
        net.stop();
        std::process::exit(if kept.load(Ordering::SeqCst) { 0 } else { 130 });
    });
    Ok(())
}

/// Copies a child's stdout into its log, line by line, and sends the first line starting with `ready` (then keeps reading: a child whose
/// stdout pipe is closed dies on its next line, broken pipe).
fn watch_stdout(out: ChildStdout, mut log: File, ready: &'static str) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for raw in BufReader::new(out).split(b'\n').map_while(Result::ok) {
            let line = String::from_utf8_lossy(&raw);
            let _ = writeln!(log, "{line}");
            if line.starts_with(ready) {
                let _ = tx.send(line.into_owned());
            }
        }
    });
    rx
}

enum ReservedPort {
    Ephemeral(Option<(u16, std::net::TcpListener)>),
    Fixed(Option<u16>),
}

impl ReservedPort {
    fn alloc() -> Result<Self, String> {
        let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = l.local_addr().map_err(|e| e.to_string())?.port();
        Ok(Self::Ephemeral(Some((port, l))))
    }

    fn fixed(port: u16) -> Self {
        Self::Fixed(Some(port))
    }

    fn port(&self) -> u16 {
        match self {
            Self::Ephemeral(inner) => inner.as_ref().map_or(0, |(p, _)| *p),
            Self::Fixed(inner) => inner.unwrap_or(0),
        }
    }

    fn release(&mut self) -> u16 {
        match self {
            Self::Ephemeral(inner) => inner.take().map_or(0, |(p, _)| p),
            Self::Fixed(inner) => inner.take().unwrap_or(0),
        }
    }
}

struct ReservedSyncPorts {
    seq: ReservedPort,
    admin: ReservedPort,
    mediator: Option<ReservedPort>,
}

struct FixedLocalnetPorts {
    syncs: Vec<(u16, u16, Option<u16>)>,
    participants: Vec<u16>,
    scan: Option<u16>,
    splice: Option<u16>,
}

/// One HTTP/1.1 request over a fresh connection (no client library: the LocalNet's own APIs are all that is asked).
fn http(port: u16, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect {port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (head, rest) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("no status line")?;
    // `Connection: close`: the body is what is left, either plain or chunked
    let body_text = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut out = String::new();
        let mut cursor = rest;
        while let Some((size_line, after)) = cursor.split_once("\r\n") {
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 || after.len() < size {
                break;
            }
            out.push_str(&after[..size]);
            cursor = after[size..].trim_start_matches("\r\n");
        }
        out
    } else {
        rest.to_string()
    };
    Ok((
        status,
        serde_json::from_str(&body_text).unwrap_or(Value::String(body_text)),
    ))
}

fn wait_until(what: &str, limit: Duration, mut ok: impl FnMut() -> bool) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    while !ok() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}"));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Ok(())
}

fn wildcard(party: &str) -> Value {
    json!({party: {"cumulative": [{"identifierFilter": {"WildcardFilter": {"value": {"includeCreatedEventBlob": false}}}}]}})
}

/// Whether `party`'s API at `port` shows the active contract `id`.
fn shows(port: u16, party: &str, id: &str) -> bool {
    let Ok((200, end)) = http(port, "GET", "/v2/state/ledger-end", None) else {
        return false;
    };
    let body = json!({"eventFormat": {"filtersByParty": wildcard(party), "verbose": true}, "activeAtOffset": end["offset"]});
    match http(port, "POST", "/v2/state/active-contracts", Some(&body)) {
        Ok((200, Value::Array(entries))) => entries.iter().any(|e| {
            e.pointer("/contractEntry/JsActiveContract/createdEvent/contractId")
                .and_then(Value::as_str)
                == Some(id)
        }),
        _ => false,
    }
}

fn submit(port: u16, party: &str, command_id: &str, command: Value) -> Result<Value, String> {
    let body = json!({
        "commands": {"commands": [command], "commandId": command_id, "actAs": [party], "userId": "participant_admin"},
        "transactionFormat": {"eventFormat": {"filtersByParty": wildcard(party), "verbose": true},
                              "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}
    });
    match http(
        port,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        Some(&body),
    )? {
        (200, v) => Ok(v),
        (status, v) => Err(format!("{command_id} answered {status}: {v}")),
    }
}

struct Report {
    steps: Vec<Value>,
}

impl Report {
    fn ok(&mut self, step: &str, detail: Value) {
        say!("  ok    {step}");
        self.steps
            .push(json!({"step": step, "ok": true, "detail": detail}));
    }
    fn failed(&mut self, step: &str, why: &str) {
        say!("  FAIL  {step}: {why}");
        self.steps
            .push(json!({"step": step, "ok": false, "detail": why}));
    }
}

fn validate_args(args: &LocalnetUpArgs) -> Result<(), String> {
    if args.participants < 2 {
        return Err("the scenario needs at least two participants".into());
    }
    if args.synchronizers < 1 || args.synchronizers > 26 {
        return Err("--synchronizers must be between 1 and 26".into());
    }
    if !std::path::Path::new(&args.dar).exists() {
        return Err(format!("the DAR {} does not exist", args.dar));
    }
    if !args.no_splice && !std::path::Path::new(&args.splice_dar_dir).is_dir() {
        return Err(format!(
            "the Splice DAR directory {} is missing (give --splice-dar-dir, or --no-splice)",
            args.splice_dar_dir
        ));
    }
    Ok(())
}

fn find_resolved_port(ports: &[PortEntry], label: &str) -> Result<u16, String> {
    ports
        .iter()
        .find(|entry| entry.label == label)
        .and_then(|entry| entry.resolved)
        .ok_or_else(|| format!("missing resolved fixed port for {label}"))
}

fn preflight_localnet_port_base(
    args: &LocalnetUpArgs,
    base: u16,
) -> Result<FixedLocalnetPorts, String> {
    let ports = plan_localnet_ports(
        base,
        args.synchronizers,
        args.participants,
        args.embedded_mediator,
        args.no_scan,
        args.no_splice,
    )
    .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;

    let plan = DoctorPlan {
        state_dir: args
            .state_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("localnet")),
        state_dir_is_default: false,
        ports,
        pg_urls: Vec::new(),
        dar_files: Vec::new(),
        dar_dirs: Vec::new(),
        metrics_port: None,
    };
    let mut host = DoctorHost::live();
    host.skip_ipc_probe = true;
    let checks = [
        check_d1_port_range(&plan),
        check_d2_protected_ports(&plan),
        check_d3_ports_in_use(&plan, &host),
    ];
    let failed: Vec<String> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .map(|c| format!("[{}] {}", c.id, c.message))
        .collect();
    if !failed.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "localnet --port-base {base} preflight failed before spawn: {}",
                failed.join("; ")
            ),
        ));
    }

    let mut syncs = Vec::with_capacity(args.synchronizers);
    for i in 1..=args.synchronizers {
        let seq = find_resolved_port(&plan.ports, &format!("s{i}.public"))?;
        let adm = find_resolved_port(&plan.ports, &format!("s{i}.admin"))?;
        let med = if args.embedded_mediator {
            None
        } else {
            Some(find_resolved_port(&plan.ports, &format!("m{i}.admin"))?)
        };
        syncs.push((seq, adm, med));
    }
    let mut participants = Vec::with_capacity(args.participants);
    for i in 1..=args.participants {
        participants.push(find_resolved_port(&plan.ports, &format!("p{i}.json"))?);
    }
    let scan = if args.no_scan {
        None
    } else {
        Some(find_resolved_port(&plan.ports, "scan.http")?)
    };
    let splice = if args.no_splice {
        None
    } else {
        Some(find_resolved_port(&plan.ports, "splice.http")?)
    };
    Ok(FixedLocalnetPorts {
        syncs,
        participants,
        scan,
        splice,
    })
}

pub fn run(args: &LocalnetUpArgs) -> Result<(), String> {
    validate_args(args)?;
    let fixed_ports = match args.port_base {
        Some(base) => Some(preflight_localnet_port_base(args, base)?),
        None => None,
    };
    let net = Arc::new(Net::new(args.state_dir.as_deref())?);
    let kept = Arc::new(AtomicBool::new(false));
    if let Err(e) = stop_on_signal(Arc::clone(&net), Arc::clone(&kept)) {
        net.stop();
        return Err(e);
    }
    let result = up(args, &net, &kept, fixed_ports);
    if result.is_err() {
        net.print_log_tails();
    }
    net.stop();
    result
}

fn up(
    args: &LocalnetUpArgs,
    net: &Net,
    kept: &AtomicBool,
    fixed_ports: Option<FixedLocalnetPorts>,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut report = Report { steps: Vec::new() };

    // Reserve ephemeral sockets up front (Mode 0) or bind deterministic fixed ports after D1-D3 preflight (`S-DX-002`).
    let (mut reserved_syncs, reserved_participants, mut reserved_scan, mut reserved_splice) =
        match fixed_ports {
            Some(fixed) => (
                fixed
                    .syncs
                    .into_iter()
                    .map(|(seq, adm, med)| ReservedSyncPorts {
                        seq: ReservedPort::fixed(seq),
                        admin: ReservedPort::fixed(adm),
                        mediator: med.map(ReservedPort::fixed),
                    })
                    .collect::<Vec<_>>(),
                fixed
                    .participants
                    .into_iter()
                    .map(ReservedPort::fixed)
                    .collect::<Vec<_>>(),
                fixed.scan.map(ReservedPort::fixed),
                fixed.splice.map(ReservedPort::fixed),
            ),
            None => {
                let mut syncs = Vec::with_capacity(args.synchronizers);
                for _ in 0..args.synchronizers {
                    syncs.push(ReservedSyncPorts {
                        seq: ReservedPort::alloc()?,
                        admin: ReservedPort::alloc()?,
                        mediator: (!args.embedded_mediator)
                            .then(ReservedPort::alloc)
                            .transpose()?,
                    });
                }
                let mut parts = Vec::with_capacity(args.participants);
                for _ in 0..args.participants {
                    parts.push(ReservedPort::alloc()?);
                }
                let scan = (!args.no_scan).then(ReservedPort::alloc).transpose()?;
                let splice = (!args.no_splice).then(ReservedPort::alloc).transpose()?;
                (syncs, parts, scan, splice)
            }
        };

    // the synchronizers: a sequencer process each, and a mediator of its own (S-LOCAL-012: more than one, so a contract can be reassigned)
    let mut seq_ports = Vec::new();
    let mut sync_infos = Vec::with_capacity(reserved_syncs.len());
    for (index, sync_ports) in reserved_syncs.drain(..).enumerate() {
        let info = start_synchronizer(&exe, args, net, index, sync_ports, &mut report)?;
        seq_ports.push(info.0);
        sync_infos.push(info);
    }
    let seq_port = seq_ports[0];

    // the participants, each with its JSON API; the first one writes the scan history (S-SPL-011)
    let scan_history = net.state.join("scan-history.jsonl");
    let mut api_ports = Vec::new();
    for (i, mut reserved) in reserved_participants.into_iter().enumerate() {
        let port = reserved.port();
        let mut command = exe_command(&exe);
        if let Some(pg) = &args.pg_url {
            command.env("CANTON_RS_STATE_PG_URL", pg);
        }
        if i == 0 && !args.no_scan {
            command
                .arg("participant")
                .arg("run")
                .arg("--scan-history")
                .arg(&scan_history);
        } else {
            command.args(["participant", "run"]);
        }
        let child = command
            .args(["--port"])
            .arg(port.to_string())
            .arg("--sequencer")
            .arg(format!("http://127.0.0.1:{seq_port}"))
            .args(also_sequencers(&seq_ports))
            .args(["--dar", &args.dar, "--participant-id"])
            .arg(format!("p{}", i + 1))
            .args(match &args.pg_url {
                Some(_) => vec![
                    "--state-name".to_string(),
                    format!("{}-p{}", args.pg_name, i + 1),
                ],
                None => Vec::new(),
            });
        let (out, err) = net.logged(&format!("participant-p{}", i + 1))?;
        let port = reserved.release();
        let child = child
            .stdout(out)
            .stderr(err)
            .spawn()
            .map_err(|e| format!("cannot start participant {}: {e}", i + 1))?;
        net.add(Proc {
            role: format!("participant p{}", i + 1),
            child,
        });
        api_ports.push(port);
    }
    for (i, port) in api_ports.iter().enumerate() {
        let port = *port;
        wait_until(
            &format!("participant p{}'s API", i + 1),
            Duration::from_secs(60),
            || matches!(http(port, "GET", "/livez", None), Ok((200, _))),
        )?;
    }
    report.ok(
        "participants_ready",
        json!({"api_ports": api_ports, "storage": if args.pg_url.is_some() { "postgresql" } else { "memory" }}),
    );

    // the scan app: its own process, reading what the first participant writes
    let mut scan_port = None;
    if let Some(mut reserved) = reserved_scan.take() {
        let port = reserved.release();
        let log = net.log("scan")?;
        let mut scan = exe_command(&exe)
            .args(["scan", "serve", "--history"])
            .arg(&scan_history)
            .args(["--dar", &args.dar, "--port"])
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(log.try_clone().map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("cannot start the scan app: {e}"))?;
        let out = scan.stdout.take().ok_or("no scan output")?;
        net.add(Proc {
            role: "scan".into(),
            child: scan,
        });
        let line = watch_stdout(out, log, "SCAN listening")
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "the scan app did not say it is listening".to_string())?;
        report.ok("scan_ready", json!({"port": port, "line": line}));
        scan_port = Some(port);
    }

    // the Splice apps: their own process, on the official DARs (S-SPL-034, S-LOCAL-010)
    let mut splice_port = None;
    if let Some(mut reserved) = reserved_splice.take() {
        if !std::path::Path::new(&args.splice_dar_dir).is_dir() {
            return Err(format!(
                "the Splice DAR directory {} is missing (give --splice-dar-dir, or --no-splice)",
                args.splice_dar_dir
            ));
        }
        let port = reserved.release();
        let (out, err) = net.logged("splice")?;
        let splice = exe_command(&exe)
            .args([
                "splice",
                "serve",
                "--dar-dir",
                &args.splice_dar_dir,
                "--port",
            ])
            .arg(port.to_string())
            .stdout(out)
            .stderr(err)
            .spawn()
            .map_err(|e| format!("cannot start the Splice apps: {e}"))?;
        net.add(Proc {
            role: "splice apps".into(),
            child: splice,
        });
        wait_listening(port, Duration::from_secs(60))
            .map_err(|_| format!("the Splice apps did not listen on {port}"))?;
        report.ok("splice_ready", json!({"port": port}));
        splice_port = Some(port);
    }

    let mut endpoint_entries = Vec::new();
    let mut endpoints_json: BTreeMap<String, String> = BTreeMap::new();
    let mut record_endpoint = |label: String, port: u16, role: &str| {
        let url = format!("http://127.0.0.1:{port}");
        endpoints_json.insert(label.clone(), url.clone());
        endpoint_entries.push(LocalnetEndpointEntry {
            label,
            url,
            role: role.to_string(),
        });
    };
    for (idx, (seq_p, adm_p, med_p)) in sync_infos.iter().enumerate() {
        let n = idx + 1;
        record_endpoint(format!("s{n}.public"), *seq_p, "sequencer_public");
        record_endpoint(format!("s{n}.admin"), *adm_p, "sequencer_admin");
        if let Some(mp) = med_p {
            record_endpoint(format!("m{n}.admin"), *mp, "mediator_admin");
        }
    }
    for (idx, port) in api_ports.iter().enumerate() {
        record_endpoint(format!("p{}.json", idx + 1), *port, "participant_json");
    }
    if let Some(port) = scan_port {
        record_endpoint("scan.http".to_string(), port, "scan_http");
    }
    if let Some(port) = splice_port {
        record_endpoint("splice.http".to_string(), port, "splice_http");
    }
    write_localnet_status_file(
        &net.state,
        &LocalnetStatusFile {
            pid: std::process::id(),
            instance: None,
            endpoints: endpoint_entries,
        },
    )?;

    let mut scenario = scenario(&api_ports, scan_port, args.synchronizers > 1, &mut report);
    if scenario.is_ok() {
        if let Some(port) = splice_port {
            scenario = splice_scenario(port, &mut report);
        }
    }
    if let Err(why) = &scenario {
        report.failed("scenario", why);
    }
    let pass = scenario.is_ok() && report.steps.iter().all(|s| s["ok"] == json!(true));
    let processes: Vec<Value> = net
        .running()
        .procs
        .iter()
        .map(|p| json!({"role": p.role, "pid": p.child.id(), "executable": exe.display().to_string()}))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"pass": pass, "endpoints": endpoints_json, "processes": processes, "steps": report.steps})
        )
        .map_err(|e| e.to_string())?
    );
    if pass && args.keep {
        kept.store(true, Ordering::SeqCst);
        say!(
            "LocalNet is up; participants' JSON APIs: {api_ports:?}. Stop this command to stop it. Role logs in {}",
            net.logs().display()
        );
        // the stop signal's handler (`stop_on_signal`) stops the LocalNet and ends the process
        loop {
            std::thread::park();
        }
    }
    if pass {
        Ok(())
    } else {
        Err("the LocalNet scenario failed".into())
    }
}

/// Starts synchronizer number `index` (0 is the first): the sequencer process, and unless `--embedded-mediator` a mediator process that joins it
/// after genesis. Returns the sequencer's port. The first synchronizer keeps the step names of a one-synchronizer LocalNet; later ones add
/// `_b`, `_c` ... so a report says which synchronizer each step is about.
fn start_synchronizer(
    exe: &Path,
    args: &LocalnetUpArgs,
    net: &Net,
    index: usize,
    mut ports: ReservedSyncPorts,
    report: &mut Report,
) -> Result<(u16, u16, Option<u16>), String> {
    let state = net.state.as_path();
    // [CANTON-NOTE: WHY] The first synchronizer keeps the names a one-synchronizer LocalNet always had (existing state, scripts and the
    // restart test rely on them); the others get a letter.
    let letter = (b'a' + index as u8) as char;
    let (suffix, dir) = if index == 0 {
        (String::new(), state.to_path_buf())
    } else {
        (format!("-{letter}"), state.join(format!("sync-{letter}")))
    };
    let step = |name: &str| {
        if index == 0 {
            name.to_string()
        } else {
            format!("{name}_{letter}")
        }
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let seq_port = ports.seq.release();
    // [CANTON-NOTE: SEMANTICS] As the official sequencer, the topology administration has a port of its own; `add-mediator` is sent there.
    let admin_port = ports.admin.release();
    let mut sequencer_command = exe_command(exe);
    sequencer_command
        .args(["sequencer", "run", "--bind", "127.0.0.1", "--port"])
        .arg(seq_port.to_string())
        .args(["--name", &format!("localnet{suffix}")])
        .env(
            "CANTON_RS_SEQUENCER_ADMIN_BIND",
            format!("127.0.0.1:{admin_port}"),
        );
    if let Some(pg) = &args.pg_url {
        // the synchronizer's state in PostgreSQL (S-LOCAL-007)
        sequencer_command
            .args(["--state-name", &format!("{}-seq{suffix}", args.pg_name)])
            .env("CANTON_RS_STATE_PG_URL", pg);
    } else if !args.embedded_mediator {
        // [CANTON-NOTE: WHY] Kept in a directory of its own (not shared with the mediator, S-LOCAL-011): the sequencer restarts with the
        // mediator it onboarded.
        let own = dir.join("sequencer");
        std::fs::create_dir_all(&own).map_err(|e| e.to_string())?;
        sequencer_command.arg("--state-dir").arg(&own);
    }
    let log = net.log(&format!("sequencer{suffix}"))?;
    let mut sequencer = sequencer_command
        .stdout(Stdio::piped())
        .stderr(log.try_clone().map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("cannot start the sequencer: {e}"))?;
    let stdout = sequencer.stdout.take().ok_or("no sequencer output")?;
    net.add(Proc {
        role: format!(
            "{}{}",
            if args.embedded_mediator {
                "sequencer+mediator"
            } else {
                "sequencer"
            },
            if index == 0 {
                String::new()
            } else {
                format!(" {letter}")
            }
        ),
        child: sequencer,
    });
    let ready = watch_stdout(stdout, log, "READY sequencer=")
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| "the sequencer did not say it is ready".to_string())?;
    // [CANTON-NOTE: WHY] `READY sequencer=` says the keys are ready, and comes before the server binds its port: a mediator started on the
    // line alone was refused (`Connection refused`) whenever it was faster than the bind, which made `localnet up` fail now and then.
    wait_listening(seq_port, Duration::from_secs(30))
        .map_err(|_| format!("the sequencer did not listen on {seq_port}"))?;
    wait_listening(admin_port, Duration::from_secs(30))
        .map_err(|_| format!("the sequencer's admin port {admin_port} did not listen"))?;
    report.ok(
        &step("sequencer_ready"),
        json!({"port": seq_port, "admin_port": admin_port, "line": ready}),
    );

    let mut mediator_port_opt = None;
    if !args.embedded_mediator {
        // [CANTON-NOTE: SEMANTICS] The mediator joins as the official one is onboarded after genesis (S-LOCAL-011): it makes its own identity
        // in its own state, the operator loads its onboarding transactions and names it the only mediator of group 0 (the synchronizer's
        // own mediator steps down), and it runs with nothing of the sequencer's.
        let own_state = |command: &mut ChildCmd| match &args.pg_url {
            Some(pg) => {
                command
                    .args([
                        "--state-name",
                        &format!("{}-mediator{suffix}", args.pg_name),
                    ])
                    .env("CANTON_RS_STATE_PG_URL", pg);
            }
            None => {
                command.arg("--state-dir").arg(dir.join("mediator"));
            }
        };
        let onboarding = dir.join("mediator-onboarding.txt");
        let mut init = exe_command(exe);
        init.args([
            "mediator",
            "init",
            "--name",
            &format!("localnet-mediator{suffix}"),
        ]);
        own_state(&mut init);
        let mediator_id = run_to_end(&mut init, "mediator init")?;
        let mut print = exe_command(exe);
        print
            .args(["mediator", "onboarding", "--out"])
            .arg(&onboarding);
        own_state(&mut print);
        run_to_end(&mut print, "mediator onboarding")?;
        let added = run_to_end(
            exe_command(exe)
                .args([
                    "sequencer",
                    "add-mediator",
                    "--group",
                    "0",
                    "--replace",
                    "--sequencer-url",
                ])
                .arg(format!("http://127.0.0.1:{seq_port}"))
                .arg("--admin-url")
                .arg(format!("http://127.0.0.1:{admin_port}"))
                .arg("--onboarding")
                .arg(&onboarding),
            "sequencer add-mediator",
        )?;
        report.ok(
            &step("mediator_onboarded"),
            json!({"mediator": mediator_id.trim(), "authorized": added.trim()}),
        );
        // its status port, for `localnet status` (S-LOCAL-010)
        let mediator_port = ports
            .mediator
            .as_mut()
            .ok_or("missing reserved mediator port")?
            .release();
        let mut mediator_command = exe_command(exe);
        mediator_command.args(["mediator", "run"]);
        own_state(&mut mediator_command);
        let log = net.log(&format!("mediator{suffix}"))?;
        let mut mediator = mediator_command
            .arg("--sequencer-url")
            .arg(format!("http://127.0.0.1:{seq_port}"))
            .arg("--port")
            .arg(mediator_port.to_string())
            .stdout(Stdio::piped())
            .stderr(log.try_clone().map_err(|e| e.to_string())?)
            .spawn()
            .map_err(|e| format!("cannot start the mediator: {e}"))?;
        let out = mediator.stdout.take().ok_or("no mediator output")?;
        net.add(Proc {
            role: if index == 0 {
                "mediator".into()
            } else {
                format!("mediator {letter}")
            },
            child: mediator,
        });
        let line = watch_stdout(out, log, "READY mediator=")
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "the mediator did not say it is ready".to_string())?;
        mediator_port_opt = Some(mediator_port);
        report.ok(
            &step("mediator_ready"),
            json!({"line": line, "port": mediator_port}),
        );
    }
    Ok((seq_port, admin_port, mediator_port_opt))
}

/// alice on the first participant, bob on the second: a contract alice creates with bob as observer is shown by bob's API, and is gone from it
/// after alice settles.
/// The Splice apps through their HTTP API: the DSO is there (bootstrapping again changes nothing), and the validator's wallet taps 10 Amulet,
/// which is then one of its amulets and one more active contract.
fn splice_scenario(port: u16, report: &mut Report) -> Result<(), String> {
    let active = || -> Result<u64, String> {
        match http(port, "GET", "/status", None)? {
            (200, v) => Ok(v["active_contracts"].as_u64().unwrap_or(0)),
            (s, v) => Err(format!("the Splice apps' status answered {s}: {v}")),
        }
    };
    match http(port, "POST", "/v0/admin/bootstrap", Some(&json!({})))? {
        (200, _) => {}
        (s, v) => return Err(format!("bootstrapping the DSO answered {s}: {v}")),
    }
    let before = active()?;
    let amulet = match http(
        port,
        "POST",
        "/v0/wallet/tap",
        Some(&json!({"amount": "10.0"})),
    )? {
        (200, v) => v["contract_id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| format!("the tap named no contract: {v}"))?,
        (s, v) => return Err(format!("the tap answered {s}: {v}")),
    };
    let after = active()?;
    let listed = match http(port, "GET", "/v0/wallet/amulets", None)? {
        (200, v) => v.to_string().contains(&amulet),
        (s, v) => return Err(format!("listing the amulets answered {s}: {v}")),
    };
    if after <= before || !listed {
        return Err(format!(
            "after the tap: {after} active contracts (before {before}), the new amulet listed: {listed}"
        ));
    }
    report.ok(
        "splice_tap",
        json!({"amulet": amulet, "active_contracts_before": before, "active_contracts_after": after}),
    );
    Ok(())
}

fn scenario(
    api: &[u16],
    scan: Option<u16>,
    reassign: bool,
    report: &mut Report,
) -> Result<(), String> {
    let (p1, p2) = (api[0], api[1]);
    let allocate = |port: u16, hint: &str| -> Result<String, String> {
        let body = json!({"partyIdHint": hint, "identityProviderId": ""});
        match http(port, "POST", "/v2/parties", Some(&body))? {
            (200, v) => v
                .pointer("/partyDetails/party")
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| format!("no party in {v}")),
            (s, v) => Err(format!("allocating {hint} answered {s}: {v}")),
        }
    };
    let alice = allocate(p1, "alice")?;
    let bob = allocate(p2, "bob")?;
    report.ok("parties_allocated", json!({"alice": alice, "bob": bob}));

    let template = "#sample-contract:AssetHolding:AssetHolding";
    let created = submit(
        p1,
        &alice,
        "localnet-create",
        json!({"CreateCommand": {"templateId": template, "createArguments": {
            "bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "USD", "amount": "42.0"}}}),
    )?;
    let id = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no created contract in {created}"))?
        .to_string();
    report.ok("created_on_p1", json!({"contractId": id}));
    wait_until(
        "bob's API to show the contract",
        Duration::from_secs(20),
        || shows(p2, &bob, &id),
    )?;
    report.ok("visible_on_p2", json!({"party": bob}));
    submit(
        p1,
        &alice,
        "localnet-settle",
        json!({"ExerciseCommand": {"templateId": template, "contractId": id, "choice": "Settle", "choiceArgument": {}}}),
    )?;
    report.ok("settled_on_p1", json!({}));
    wait_until(
        "bob's API to drop the contract",
        Duration::from_secs(20),
        || !shows(p2, &bob, &id),
    )?;
    report.ok("gone_on_p2", json!({"party": bob}));
    if let Some(scan) = scan {
        // the scan app, a process of its own, has what p1 committed: the create, then the settle, as scan update items
        let mut updates = Vec::new();
        wait_until(
            "the scan app to show both commits",
            Duration::from_secs(20),
            || {
                let Ok((200, page)) = http(
                    scan,
                    "POST",
                    "/api/scan/v2/updates",
                    Some(&json!({"page_size": 10})),
                ) else {
                    return false;
                };
                updates = page["transactions"].as_array().cloned().unwrap_or_default();
                updates.len() >= 2
            },
        )?;
        let root = |u: &Value| {
            u["events_by_id"][u["root_event_ids"][0].as_str().unwrap_or_default()].clone()
        };
        let (first, second) = (root(&updates[0]), root(&updates[1]));
        if first["event_type"] != "created_event" || first["contract_id"] != json!(id) {
            return Err(format!(
                "the scan's first update is not the create of {id}: {first}"
            ));
        }
        if second["event_type"] != "exercised_event" || second["choice"] != "Settle" {
            return Err(format!(
                "the scan's second update is not the Settle: {second}"
            ));
        }
        report.ok(
            "scan_shows_p1_commits",
            json!({"updates": updates.len(), "contractId": id}),
        );
    }
    if reassign {
        reassign_scenario(p1, &alice, &bob, template, report)?;
    }
    Ok(())
}

/// With two synchronizers: a contract alice creates (on the first synchronizer, bob as observer) is unassigned to the second and assigned
/// there through p1's JSON API. Both participants take part (bob's p2 confirms on both synchronizers); afterwards p1's ACS shows the contract on
/// the second synchronizer with reassignment counter 1, and the same API refuses to unassign it from the first again.
fn reassign_scenario(
    p1: u16,
    alice: &str,
    bob: &str,
    template: &str,
    report: &mut Report,
) -> Result<(), String> {
    let (status, synchronizers) = http(p1, "GET", "/v2/state/connected-synchronizers", None)?;
    let id_of = |alias: &str| -> Result<String, String> {
        synchronizers["connectedSynchronizers"]
            .as_array()
            .and_then(|l| l.iter().find(|s| s["synchronizerAlias"] == json!(alias)))
            .and_then(|s| s["synchronizerId"].as_str())
            .map(String::from)
            .ok_or_else(|| format!("p1 is not connected to {alias} ({status}: {synchronizers})"))
    };
    let (sync_a, sync_b) = (id_of("syncA")?, id_of("syncB")?);
    let created = submit(
        p1,
        alice,
        "localnet-reassign-create",
        json!({"CreateCommand": {"templateId": template, "createArguments": {
            "bank": alice, "owner": alice, "auditor": bob, "assetSymbol": "EUR", "amount": "7.0"}}}),
    )?;
    let id = created
        .pointer("/transaction/events/0/CreatedEvent/contractId")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no created contract in {created}"))?
        .to_string();
    let format = json!({"filtersByParty": {alice: {}}, "verbose": false});
    let reassign = |command_id: &str, command: Value| -> Result<Value, String> {
        let body = json!({"reassignmentCommands": {"submitter": alice, "commandId": command_id,
            "userId": "participant_admin", "commands": [{"command": command}]}, "eventFormat": format});
        match http(
            p1,
            "POST",
            "/v2/commands/submit-and-wait-for-reassignment",
            Some(&body),
        )? {
            (200, v) => Ok(v),
            (s, v) => Err(format!("{command_id} answered {s}: {v}")),
        }
    };
    let unassigned = reassign(
        "localnet-unassign",
        json!({"UnassignCommand": {"value": {"contractId": id, "source": sync_a, "target": sync_b}}}),
    )?;
    let reassignment_id = unassigned
        .pointer("/reassignment/events/0/JsUnassignedEvent/value/reassignmentId")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no reassignment id in {unassigned}"))?
        .to_string();
    reassign(
        "localnet-assign",
        json!({"AssignCommand": {"value": {"reassignmentId": reassignment_id, "source": sync_a, "target": sync_b}}}),
    )?;
    let (_, end) = http(p1, "GET", "/v2/state/ledger-end", None)?;
    let acs_body = json!({"eventFormat": {"filtersByParty": wildcard(alice), "verbose": false}, "activeAtOffset": end["offset"]});
    let (_, acs) = http(p1, "POST", "/v2/state/active-contracts", Some(&acs_body))?;
    let entry = acs
        .as_array()
        .and_then(|l| {
            l.iter().find(|e| {
                e.pointer("/contractEntry/JsActiveContract/createdEvent/contractId")
                    .and_then(Value::as_str)
                    == Some(id.as_str())
            })
        })
        .map(|e| e["contractEntry"]["JsActiveContract"].clone())
        .ok_or_else(|| format!("{id} is in no ACS after the assign: {acs}"))?;
    if entry["synchronizerId"] != json!(sync_b) || entry["reassignmentCounter"] != json!(1) {
        return Err(format!(
            "after the assign the contract should be on {sync_b} with counter 1: {entry}"
        ));
    }
    // it has left the first synchronizer for good: unassigning from there again is refused
    let again = http(
        p1,
        "POST",
        "/v2/commands/submit-and-wait-for-reassignment",
        Some(
            &json!({"reassignmentCommands": {"submitter": alice, "commandId": "localnet-unassign-again",
            "userId": "participant_admin", "commands": [{"command": {"UnassignCommand": {"value":
                {"contractId": id, "source": sync_a, "target": sync_b}}}}]}, "eventFormat": format}),
        ),
    )?;
    if again.0 == 200 {
        return Err(
            "unassigning the moved contract from the first synchronizer was accepted".into(),
        );
    }
    report.ok(
        "reassigned_a_to_b",
        json!({"contractId": id, "reassignmentId": reassignment_id, "synchronizer": sync_b,
               "reassignmentCounter": 1, "second_unassign_status": again.0}),
    );
    Ok(())
}

/// With more than one synchronizer: the first is `syncA` and the others `--also-sequencer syncB=<url>` ... (the aliases the JSON API shows).
fn also_sequencers(ports: &[u16]) -> Vec<String> {
    if ports.len() < 2 {
        return Vec::new();
    }
    let mut out = vec!["--sequencer-alias".to_string(), "syncA".to_string()];
    for (i, port) in ports.iter().enumerate().skip(1) {
        out.push("--also-sequencer".into());
        out.push(format!(
            "sync{}=http://127.0.0.1:{port}",
            (b'A' + i as u8) as char
        ));
    }
    out
}

/// Waits until something accepts connections on the local `port`.
fn wait_listening(port: u16, within: Duration) -> Result<(), ()> {
    let until = std::time::Instant::now() + within;
    while std::time::Instant::now() < until {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(())
}
