//! Individual preflight checks `D1..D10` for `canton-rs daemon doctor` and `daemon up`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use canton_participant::pgconn::{connect as pg_connect, PgTarget};
use canton_participant::storage::check_postgres_version;

use super::super::ipc::{call_unary_with_timeout, socket_path, IpcRequest, IpcResponse};
use super::super::mask_secret_url;
use super::plan::DoctorPlan;
use super::{CheckStatus, DoctorCheck};

/// Protected hub host ports that `S-DX` commands must never occupy (`Axiom A3`).
pub const PROTECTED_HUB_PORTS: [u16; 5] = [3080, 3901, 6432, 6501, 6502];
/// Hard disk-space failure threshold for D6 (`2 GiB`).
pub const DISK_FAIL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Disk-space warning threshold for D6 (`10 GiB`).
pub const DISK_WARN_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Warning threshold for Cargo `target/` size (`10 GiB`, D7).
pub const TARGET_WARN_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Result of probing PostgreSQL for D8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PgProbeResult {
    Ok,
    VersionMismatch(String),
    Unreachable(String),
}

/// Host inspection environment used by `D1..D10` (defaults to real OS probes via [`DoctorHost::live`]).
#[derive(Clone)]
pub struct DoctorHost {
    pub test_mode: bool,
    pub target_dir: PathBuf,
    pub disk_avail_override: Option<u64>,
    pub target_bytes_override: Option<u64>,
    pub hub_containers_override: Option<Vec<String>>,
    pub pg_probe_override: Option<PgProbeResult>,
    pub skip_ipc_probe: bool,
    pub ports_probe: fn(&[u16]) -> BTreeSet<u16>,
}

impl DoctorHost {
    /// Constructs a live host inspector using real OS, socket, filesystem, PG, and Docker queries.
    pub fn live() -> Self {
        let test_mode = matches!(
            std::env::var("CANTON_RS_TEST_MODE").as_deref(),
            Ok("1" | "true" | "TRUE" | "yes")
        );
        Self {
            test_mode,
            target_dir: PathBuf::from("target"),
            disk_avail_override: None,
            target_bytes_override: None,
            hub_containers_override: None,
            pg_probe_override: None,
            skip_ipc_probe: false,
            ports_probe: detect_listening_ports,
        }
    }
}

/// Parses macOS `netstat -an` output and returns loopback/wildcard TCP `LISTEN` ports.
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "macOS netstat parser exercised directly in unit tests"
    )
)]
pub(crate) fn parse_macos_netstat_listen_ports(raw: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in raw.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 || !cols[0].starts_with("tcp") || cols[5] != "LISTEN" {
            continue;
        }
        let Some((host, port_str)) = cols[3].rsplit_once('.') else {
            continue;
        };
        if !matches!(host, "*" | "127.0.0.1" | "0.0.0.0" | "::1" | "::") {
            continue;
        }
        if let Ok(port) = port_str.parse::<u16>() {
            ports.insert(port);
        }
    }
    ports
}

/// Parses macOS `lsof -nP -iTCP -sTCP:LISTEN` output and returns loopback/wildcard listening ports.
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "macOS lsof parser exercised directly in unit tests"
    )
)]
pub(crate) fn parse_macos_lsof_listen_ports(raw: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in raw.lines() {
        let Some(before) = line.trim_end().strip_suffix(" (LISTEN)") else {
            continue;
        };
        let Some(endpoint) = before.split_whitespace().last() else {
            continue;
        };
        let Some((host, port_str)) = endpoint.rsplit_once(':') else {
            continue;
        };
        if !matches!(
            host,
            "*" | "127.0.0.1" | "0.0.0.0" | "[::1]" | "[::]" | "::1" | "::"
        ) {
            continue;
        }
        if let Ok(port) = port_str.parse::<u16>() {
            ports.insert(port);
        }
    }
    ports
}

/// Parses Linux `/proc/net/tcp` or `/proc/net/tcp6` output and returns loopback/wildcard `TCP_LISTEN` (`0A`) ports.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "Linux procfs parser exercised directly in unit tests"
    )
)]
pub(crate) fn parse_linux_proc_net_tcp(raw: &str, ipv6: bool) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in raw.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[3] != "0A" {
            continue;
        }
        let Some((hex_ip, hex_port)) = cols[1].split_once(':') else {
            continue;
        };
        let ip_upper = hex_ip.to_ascii_uppercase();
        let relevant_ip = if ipv6 {
            matches!(
                ip_upper.as_str(),
                "00000000000000000000000000000000"
                    | "00000000000000000000000001000000"
                    | "00000000000000000000000000000001"
                    | "0000000000000000FFFF00000100007F"
                    | "0000000000000000FFFF00007F000001"
            )
        } else {
            matches!(ip_upper.as_str(), "00000000" | "0100007F" | "7F000001")
        };
        if !relevant_ip {
            continue;
        }
        if let Ok(port) = u16::from_str_radix(hex_port, 16) {
            ports.insert(port);
        }
    }
    ports
}

#[cfg(target_os = "macos")]
fn read_os_listening_tcp_ports() -> Option<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    let mut observed_any = false;

    let lsof_bin = if Path::new("/usr/sbin/lsof").is_file() {
        "/usr/sbin/lsof"
    } else {
        "lsof"
    };
    if let Ok(out) = Command::new(lsof_bin)
        .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
        .output()
    {
        if out.status.success() && !out.stdout.is_empty() {
            ports.extend(parse_macos_lsof_listen_ports(&String::from_utf8_lossy(
                &out.stdout,
            )));
            observed_any = true;
        }
    }

    // Union with `netstat -an` so root-owned system listeners outside current UID stay covered too.
    let netstat_bin = if Path::new("/usr/sbin/netstat").is_file() {
        "/usr/sbin/netstat"
    } else {
        "netstat"
    };
    if let Ok(out) = Command::new(netstat_bin).arg("-an").output() {
        if out.status.success() && !out.stdout.is_empty() {
            ports.extend(parse_macos_netstat_listen_ports(&String::from_utf8_lossy(
                &out.stdout,
            )));
            observed_any = true;
        }
    }

    observed_any.then_some(ports)
}

#[cfg(target_os = "linux")]
fn read_os_listening_tcp_ports() -> Option<BTreeSet<u16>> {
    let mut ports = BTreeSet::new();
    let mut read_any = false;
    if let Ok(v4) = std::fs::read_to_string("/proc/net/tcp") {
        ports.extend(parse_linux_proc_net_tcp(&v4, false));
        read_any = true;
    }
    if let Ok(v6) = std::fs::read_to_string("/proc/net/tcp6") {
        ports.extend(parse_linux_proc_net_tcp(&v6, true));
        read_any = true;
    }
    read_any.then_some(ports)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_os_listening_tcp_ports() -> Option<BTreeSet<u16>> {
    None
}

/// Reads the OS TCP listen socket table to detect already-occupied ports without binding or handshaking.
///
/// [CANTON-NOTE: INVARIANT] Never probe via `TcpListener::bind`, which momentarily occupies the
/// port, violates `D-A1` purity, and induces `EADDRINUSE` races on unrelated listeners. Reading the
/// kernel socket table also avoids TCP `TIME_WAIT` side effects under concurrent test traffic.
pub fn detect_listening_ports(ports: &[u16]) -> BTreeSet<u16> {
    if ports.is_empty() {
        return BTreeSet::new();
    }
    let wanted: BTreeSet<u16> = ports.iter().copied().collect();
    if let Some(table) = read_os_listening_tcp_ports() {
        return wanted.into_iter().filter(|p| table.contains(p)).collect();
    }
    wanted
        .into_iter()
        .filter(|&port| {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
        })
        .collect()
}

/// Runs all checks `D1..D10` in strict order without short-circuiting.
pub fn run_all_checks(plan: &DoctorPlan, host: &DoctorHost) -> Vec<DoctorCheck> {
    vec![
        check_d1_port_range(plan),
        check_d2_protected_ports(plan),
        check_d3_ports_in_use(plan, host),
        check_d4_internal_collisions(plan),
        check_d5_state_dir(plan, host),
        check_d6_disk_space(plan, host),
        check_d7_target_size(host),
        check_d8_postgres(plan, host),
        check_d9_dars(plan),
        check_d10_hub_containers(host),
    ]
}

/// D1: verifies every planned port falls inside `1024..=65535` with no `u16` addition overflow.
pub fn check_d1_port_range(plan: &DoctorPlan) -> DoctorCheck {
    let mut problems = Vec::new();
    for entry in &plan.ports {
        match entry.resolved {
            None => problems.push(format!(
                "port overflow for {} ({} + {} > 65535)",
                entry.label, entry.base, entry.offset
            )),
            Some(p) if p < 1024 => problems.push(format!(
                "privileged port {} for {} (< 1024)",
                p, entry.label
            )),
            Some(_) => {}
        }
    }
    if problems.is_empty() {
        DoctorCheck {
            id: "D1".to_string(),
            status: CheckStatus::Ok,
            message: format!(
                "all {} planned port(s) within 1024..=65535",
                plan.ports.len()
            ),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "D1".to_string(),
            status: CheckStatus::Fail,
            message: problems.join("; "),
            fix: Some(
                "Adjust ports or --port-offset so every port satisfies 1024 <= base + offset <= 65535"
                    .to_string(),
            ),
        }
    }
}

/// D2: rejects any planned port colliding with protected hub ports `{3080, 3901, 6432, 6501, 6502}`.
pub fn check_d2_protected_ports(plan: &DoctorPlan) -> DoctorCheck {
    let mut hits = Vec::new();
    for entry in &plan.ports {
        if let Some(p) = entry.resolved {
            if PROTECTED_HUB_PORTS.contains(&p) {
                hits.push(format!("{p} ({})", entry.label));
            }
        }
    }
    if hits.is_empty() {
        DoctorCheck {
            id: "D2".to_string(),
            status: CheckStatus::Ok,
            message: "no protected hub ports in plan".to_string(),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "D2".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "planned port(s) overlap protected hub ports: {}",
                hits.join(", ")
            ),
            fix: Some(
                "Pass --port-offset <N> to avoid hub ports 3080, 3901, 6432, 6501, 6502"
                    .to_string(),
            ),
        }
    }
}

fn probe_running_instance_ports(plan: &DoctorPlan) -> Option<BTreeSet<u16>> {
    let sock = socket_path(&plan.state_dir);
    if !sock.exists() && sock.symlink_metadata().is_err() {
        return None;
    }
    let resp = call_unary_with_timeout(
        &plan.state_dir,
        &IpcRequest::GetSnapshot,
        Some(Duration::from_secs(2)),
    )
    .ok()?;
    let IpcResponse::Snapshot { ok: true, snapshot } = resp else {
        return None;
    };
    let mut owned: BTreeSet<u16> = BTreeSet::new();
    for node in &snapshot.nodes {
        for p in node.ports.all_ports() {
            owned.insert(p);
        }
    }
    if let Some(mp) = plan.metrics_port {
        owned.insert(mp);
    }
    Some(owned)
}

/// D3: detects ports already occupied by external listeners while recognizing this instance's own running ports.
pub fn check_d3_ports_in_use(plan: &DoctorPlan, host: &DoctorHost) -> DoctorCheck {
    let owned_ports = if host.skip_ipc_probe {
        None
    } else {
        probe_running_instance_ports(plan)
    };

    let mut checked: BTreeMap<u16, String> = BTreeMap::new();
    for entry in &plan.ports {
        if let Some(p) = entry.resolved {
            if owned_ports.as_ref().is_some_and(|owned| owned.contains(&p)) {
                continue;
            }
            checked.entry(p).or_insert_with(|| entry.label.clone());
        }
    }

    let candidate_ports: Vec<u16> = checked.keys().copied().collect();
    let in_use = (host.ports_probe)(&candidate_ports);
    let conflicts: Vec<String> = checked
        .iter()
        .filter(|(port, _)| in_use.contains(port))
        .map(|(port, label)| format!("port {port} ({label}) is already in use"))
        .collect();

    if !conflicts.is_empty() {
        return DoctorCheck {
            id: "D3".to_string(),
            status: CheckStatus::Fail,
            message: conflicts.join("; "),
            fix: Some(
                "Stop the listener using the conflicting port(s) or pass --port-offset <N>"
                    .to_string(),
            ),
        };
    }

    if owned_ports.is_some() {
        DoctorCheck {
            id: "D3".to_string(),
            status: CheckStatus::Running,
            message: format!(
                "instance is already running at {}",
                plan.state_dir.display()
            ),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "D3".to_string(),
            status: CheckStatus::Ok,
            message: format!("all {} distinct planned port(s) are free", checked.len()),
            fix: None,
        }
    }
}

/// D4: detects duplicate port assignments across distinct logical slots inside the manifest.
pub fn check_d4_internal_collisions(plan: &DoctorPlan) -> DoctorCheck {
    let mut seen: BTreeMap<u16, &str> = BTreeMap::new();
    let mut collisions = Vec::new();
    for entry in &plan.ports {
        let Some(port) = entry.resolved else {
            continue;
        };
        if let Some(first_label) = seen.get(&port) {
            collisions.push(format!(
                "port collision on {port}: '{first_label}' and '{}'",
                entry.label
            ));
        } else {
            seen.insert(port, entry.label.as_str());
        }
    }
    if collisions.is_empty() {
        DoctorCheck {
            id: "D4".to_string(),
            status: CheckStatus::Ok,
            message: "no internal manifest port collisions".to_string(),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "D4".to_string(),
            status: CheckStatus::Fail,
            message: collisions.join("; "),
            fix: Some("Assign distinct ports to each service endpoint in the manifest".to_string()),
        }
    }
}

#[cfg(unix)]
fn is_dir_writable(dir: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Ok(meta) = std::fs::metadata(dir) else {
        return false;
    };
    if !meta.is_dir() || meta.permissions().readonly() {
        return false;
    }
    let Ok(c_path) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a NUL-terminated path buffer valid for the duration of this call.
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
}

#[cfg(not(unix))]
fn is_dir_writable(dir: &Path) -> bool {
    std::fs::metadata(dir).is_ok_and(|m| m.is_dir() && !m.permissions().readonly())
}

fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let mut cur = path.to_path_buf();
    loop {
        if cur.exists() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// D5: checks state directory writability, test-mode protection of `canton-rs-state`, and registry version match without writing to disk.
pub fn check_d5_state_dir(plan: &DoctorPlan, host: &DoctorHost) -> DoctorCheck {
    if host.test_mode && plan.state_dir_is_default {
        return DoctorCheck {
            id: "D5".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "default protected state directory '{}' cannot be used in test mode",
                plan.state_dir.display()
            ),
            fix: Some("Pass --state-dir \"$(mktemp -d)\"".to_string()),
        };
    }

    let check_target = if plan.state_dir.exists() {
        Some(plan.state_dir.clone())
    } else {
        let abs = if plan.state_dir.is_relative() {
            std::env::current_dir()
                .map(|cwd| cwd.join(&plan.state_dir))
                .unwrap_or_else(|_| plan.state_dir.clone())
        } else {
            plan.state_dir.clone()
        };
        abs.parent().and_then(nearest_existing_path)
    };

    let Some(target) = check_target else {
        return DoctorCheck {
            id: "D5".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "state directory '{}' has no existing parent directory",
                plan.state_dir.display()
            ),
            fix: Some("Pass an existing writable parent path via --state-dir <path>".to_string()),
        };
    };

    if !is_dir_writable(&target) {
        return DoctorCheck {
            id: "D5".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "state directory '{}' is not writable",
                plan.state_dir.display()
            ),
            fix: Some("Fix directory permissions or choose another --state-dir <path>".to_string()),
        };
    }

    let registry = plan.state_dir.join("instance.json");
    if registry.is_file() {
        if let Ok(raw) = std::fs::read_to_string(&registry) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                    let current = env!("CARGO_PKG_VERSION");
                    if ver != current {
                        return DoctorCheck {
                            id: "D5".to_string(),
                            status: CheckStatus::Warn,
                            message: format!(
                                "existing registry version '{ver}' differs from canton-rs '{current}'"
                            ),
                            fix: Some(
                                "Inspect or remove stale state directory before starting"
                                    .to_string(),
                            ),
                        };
                    }
                }
            }
        }
    }

    DoctorCheck {
        id: "D5".to_string(),
        status: CheckStatus::Ok,
        message: "state directory is writable".to_string(),
        fix: None,
    }
}

#[cfg(unix)]
fn query_available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let abs = if path.is_relative() {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    let target = nearest_existing_path(&abs)?;
    let c_path = CString::new(target.as_os_str().as_bytes()).ok()?;
    let mut buf = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c_path` is a valid NUL-terminated path and `buf` is a writable `statvfs` buffer.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: `statvfs` returned 0, guaranteeing `buf` was initialized by the kernel.
    let stat = unsafe { buf.assume_init() };
    Some(u64::from(stat.f_bavail).saturating_mul(stat.f_frsize))
}

#[cfg(not(unix))]
fn query_available_bytes(_path: &Path) -> Option<u64> {
    None
}

/// D6: verifies available filesystem space (`< 2 GiB` Fail, `< 10 GiB` Warn, `>= 10 GiB` Ok).
pub fn check_d6_disk_space(plan: &DoctorPlan, host: &DoctorHost) -> DoctorCheck {
    let avail = host
        .disk_avail_override
        .or_else(|| query_available_bytes(&plan.state_dir));

    match avail {
        Some(bytes) if bytes < DISK_FAIL_BYTES => DoctorCheck {
            id: "D6".to_string(),
            status: CheckStatus::Fail,
            message: "insufficient free disk space (< 2 GiB available)".to_string(),
            fix: Some("Free disk space (e.g. run: rm -rf target/debug)".to_string()),
        },
        Some(bytes) if bytes < DISK_WARN_BYTES => DoctorCheck {
            id: "D6".to_string(),
            status: CheckStatus::Warn,
            message: "low free disk space (< 10 GiB available)".to_string(),
            fix: Some("Free disk space (e.g. run: rm -rf target/debug)".to_string()),
        },
        Some(_) => DoctorCheck {
            id: "D6".to_string(),
            status: CheckStatus::Ok,
            message: "sufficient disk space (>= 10 GiB available)".to_string(),
            fix: None,
        },
        None => DoctorCheck {
            id: "D6".to_string(),
            status: CheckStatus::Ok,
            message: "disk space check skipped on non-POSIX host".to_string(),
            fix: None,
        },
    }
}

fn dir_size_capped(root: &Path, limit: u64) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total = total.saturating_add(meta.len());
                    if total > limit {
                        return total;
                    }
                }
            }
        }
    }
    total
}

/// D7: warns when Cargo `target/` exceeds `10 GiB`.
pub fn check_d7_target_size(host: &DoctorHost) -> DoctorCheck {
    let bytes = host.target_bytes_override.unwrap_or_else(|| {
        if host.target_dir.exists() {
            dir_size_capped(&host.target_dir, TARGET_WARN_BYTES)
        } else {
            0
        }
    });
    if bytes > TARGET_WARN_BYTES {
        DoctorCheck {
            id: "D7".to_string(),
            status: CheckStatus::Warn,
            message: "target directory exceeds 10 GiB (> 10 GiB threshold)".to_string(),
            fix: Some(
                "Verify 'pgrep -fl \"cargo |rustc\"' is empty, then run: rm -rf target/debug"
                    .to_string(),
            ),
        }
    } else {
        DoctorCheck {
            id: "D7".to_string(),
            status: CheckStatus::Ok,
            message: "target directory size within limit (<= 10 GiB)".to_string(),
            fix: None,
        }
    }
}

fn probe_postgres_live(url: &str) -> PgProbeResult {
    let target = match PgTarget::from_url_or_jdbc(url, None, None, None) {
        Ok(t) => t,
        Err(e) => return PgProbeResult::Unreachable(format!("{}: {e}", mask_secret_url(url))),
    };
    let mut client = match pg_connect(&target) {
        Ok(c) => c,
        Err(e) => {
            return PgProbeResult::Unreachable(format!(
                "cannot connect to {}: {e}",
                mask_secret_url(url)
            ))
        }
    };
    let version: String = match client.query_one("SHOW server_version", &[]) {
        Ok(row) => row.get(0),
        Err(e) => {
            return PgProbeResult::Unreachable(format!(
                "failed to query PostgreSQL version on {}: {e}",
                mask_secret_url(url)
            ))
        }
    };
    match check_postgres_version(&version, false) {
        Ok(Some(note)) => PgProbeResult::VersionMismatch(note),
        Ok(None) => PgProbeResult::Ok,
        Err(e) => PgProbeResult::VersionMismatch(e),
    }
}

/// D8: verifies PostgreSQL reachability and server version when `--pg-url` or Postgres storage is configured.
pub fn check_d8_postgres(plan: &DoctorPlan, host: &DoctorHost) -> DoctorCheck {
    if plan.pg_urls.is_empty() {
        return DoctorCheck {
            id: "D8".to_string(),
            status: CheckStatus::Ok,
            message: "PostgreSQL not requested".to_string(),
            fix: None,
        };
    }

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for url in &plan.pg_urls {
        let res = match &host.pg_probe_override {
            Some(ov) => ov.clone(),
            None => probe_postgres_live(url),
        };
        match res {
            PgProbeResult::Ok => {}
            PgProbeResult::VersionMismatch(note) => warnings.push(note),
            PgProbeResult::Unreachable(err) => errors.push(err),
        }
    }

    if !errors.is_empty() {
        DoctorCheck {
            id: "D8".to_string(),
            status: CheckStatus::Fail,
            message: errors.join("; "),
            fix: Some("Verify PostgreSQL is running and --pg-url is reachable".to_string()),
        }
    } else if !warnings.is_empty() {
        DoctorCheck {
            id: "D8".to_string(),
            status: CheckStatus::Warn,
            message: warnings.join("; "),
            fix: Some("Use PostgreSQL 14..18 matching the Canton 3.7.2 test baseline".to_string()),
        }
    } else {
        DoctorCheck {
            id: "D8".to_string(),
            status: CheckStatus::Ok,
            message: format!("verified {} PostgreSQL connection(s)", plan.pg_urls.len()),
            fix: None,
        }
    }
}

/// D9: validates existence and archive integrity of configured DAR files without mutating disk.
pub fn check_d9_dars(plan: &DoctorPlan) -> DoctorCheck {
    let mut dar_paths: BTreeSet<PathBuf> = plan.dar_files.iter().cloned().collect();
    let mut errors = Vec::new();

    for dir in &plan.dar_dirs {
        if !dir.is_dir() {
            errors.push(format!("DAR directory missing: {}", dir.display()));
            continue;
        }
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("dar") {
                        dar_paths.insert(p);
                    }
                }
            }
            Err(e) => errors.push(format!("cannot read DAR directory {}: {e}", dir.display())),
        }
    }

    if dar_paths.is_empty() && errors.is_empty() {
        return DoctorCheck {
            id: "D9".to_string(),
            status: CheckStatus::Ok,
            message: "no DAR files configured".to_string(),
            fix: None,
        };
    }

    let checked_count = dar_paths.len();
    for path in &dar_paths {
        if !path.is_file() {
            errors.push(format!("missing DAR file: {}", path.display()));
            continue;
        }
        if let Err(e) = lf_archive::load_dar_file_allow_dev(path) {
            errors.push(format!("invalid DAR {}: {e}", path.display()));
        }
    }

    if errors.is_empty() {
        DoctorCheck {
            id: "D9".to_string(),
            status: CheckStatus::Ok,
            message: format!("verified {checked_count} DAR archive(s)"),
            fix: None,
        }
    } else {
        DoctorCheck {
            id: "D9".to_string(),
            status: CheckStatus::Fail,
            message: errors.join("; "),
            fix: Some(
                "Verify DAR paths exist and rebuild invalid archives with daml build".to_string(),
            ),
        }
    }
}

fn detect_running_hub_containers() -> Vec<String> {
    let Ok(out) = Command::new("docker")
        .args([
            "ps",
            "--filter",
            "name=^/hub-canton$",
            "--filter",
            "name=^/hub-postgres$",
            "--filter",
            "status=running",
            "--format",
            "{{.Names}}",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let mut found: BTreeSet<String> = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line.trim();
        if matches!(name, "hub-canton" | "hub-postgres") {
            found.insert(name.to_string());
        }
    }
    found.into_iter().collect()
}

/// D10: read-only check for running `hub-canton` / `hub-postgres` Docker containers (never mutates them).
pub fn check_d10_hub_containers(host: &DoctorHost) -> DoctorCheck {
    let mut running: BTreeSet<String> = host
        .hub_containers_override
        .clone()
        .unwrap_or_else(detect_running_hub_containers)
        .into_iter()
        .collect();
    running.retain(|n| !n.trim().is_empty());

    if running.is_empty() {
        DoctorCheck {
            id: "D10".to_string(),
            status: CheckStatus::Ok,
            message: "no running hub containers detected".to_string(),
            fix: None,
        }
    } else {
        let names: Vec<String> = running.into_iter().collect();
        DoctorCheck {
            id: "D10".to_string(),
            status: CheckStatus::Warn,
            message: format!(
                "hub container(s) running: {}; leaving untouched",
                names.join(", ")
            ),
            fix: Some(
                "Keep --port-offset set to avoid hub ports 3080, 3901, 6432, 6501, 6502"
                    .to_string(),
            ),
        }
    }
}
