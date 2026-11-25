//! Lightweight OS process resource sampler (`OsProcSampler`) and host process scanner.
//!
//! [CANTON-NOTE: INVARIANT] Uses only `libc` kernel queries (macOS `proc_pidinfo` / `sysctl`) and
//! Linux `/proc` file reads—zero external `ps` child spawns and zero new C dependencies.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::commands::supervisor::{sanitize_argv, NodePorts, ProcResources, UnmanagedProcess};

/// Process identity snapshot used for PID reuse protection (`daemon.pids.json`) and `--scan-host`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcIdentity {
    pub pid: u32,
    pub exe_path: Option<PathBuf>,
    pub started_at_unix_secs: Option<u64>,
    pub argv: Vec<String>,
}

struct PrevCpuSample {
    cpu_ns: u64,
    sampled_at: Instant,
}

/// Stateful per-PID sampler computing CPU percentage deltas, RSS/VMS memory, threads, and FDs.
pub struct OsProcSampler {
    prev_cpu: HashMap<u32, PrevCpuSample>,
    jvm_pid: Option<u32>,
    jvm_next_scan: Option<Instant>,
}

impl Default for OsProcSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl OsProcSampler {
    /// Creates a new sampler with an empty CPU delta baseline.
    pub fn new() -> Self {
        Self {
            prev_cpu: HashMap::new(),
            jvm_pid: None,
            jvm_next_scan: None,
        }
    }

    /// Samples resource usage for a managed PID, returning `ProcResources::default()` if exited.
    pub fn sample_pid(&mut self, pid: u32) -> ProcResources {
        let Some(raw) = sample_raw_pid(pid) else {
            self.prev_cpu.remove(&pid);
            return ProcResources::default();
        };
        let now = Instant::now();
        let cpu_percent = match self.prev_cpu.get(&pid) {
            Some(prev) => {
                let wall_ns = now.duration_since(prev.sampled_at).as_nanos() as f64;
                let cpu_delta_ns = raw.cpu_ns.saturating_sub(prev.cpu_ns) as f64;
                if wall_ns > 0.0 {
                    ((cpu_delta_ns / wall_ns) * 100.0).clamp(0.0, 6400.0)
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        self.prev_cpu.insert(
            pid,
            PrevCpuSample {
                cpu_ns: raw.cpu_ns,
                sampled_at: now,
            },
        );
        ProcResources {
            cpu_percent,
            rss_bytes: raw.rss_bytes,
            vms_bytes: raw.vms_bytes,
            thread_count: raw.thread_count,
            open_fds: raw.open_fds,
        }
    }

    /// Drops cached CPU deltas for a stopped/exited PID.
    pub fn forget_pid(&mut self, pid: u32) {
        self.prev_cpu.remove(&pid);
    }
}

struct RawProcSample {
    cpu_ns: u64,
    rss_bytes: u64,
    vms_bytes: u64,
    thread_count: u32,
    open_fds: u32,
}

/// Inspects an arbitrary OS PID's executable path, start timestamp, and sanitized argv.
pub fn inspect_pid_identity(pid: u32) -> Option<ProcIdentity> {
    inspect_pid_identity_os(pid)
}

/// Checks whether a live PID matches an expected binary path and optional approximate start time.
pub fn pid_matches_expected(pid: u32, expected_exe: &Path, started_at_unix: u64) -> bool {
    let Some(id) = inspect_pid_identity(pid) else {
        return false;
    };
    let Some(actual_exe) = &id.exe_path else {
        return false;
    };
    let same_bin = actual_exe == expected_exe
        || actual_exe
            .file_name()
            .zip(expected_exe.file_name())
            .is_some_and(|(a, b)| a == b);
    if !same_bin {
        return false;
    }
    if let Some(actual_start) = id.started_at_unix_secs {
        // Allow up to 120s clock/rounding tolerance across fork/exec vs manifest write.
        if actual_start.abs_diff(started_at_unix) > 120 {
            return false;
        }
    }
    true
}

/// Scans host processes belonging to `canton-rs` excluding the caller and known managed PIDs.
pub fn scan_host_canton_processes(
    managed_pids: &[u32],
    sampler: &mut OsProcSampler,
) -> Vec<UnmanagedProcess> {
    let self_pid = std::process::id();
    let mut results = Vec::new();
    for pid in list_all_pids() {
        if pid == 0 || pid == self_pid || managed_pids.contains(&pid) {
            continue;
        }
        let Some(identity) = inspect_pid_identity(pid) else {
            continue;
        };
        if !is_canton_rs_process(&identity) {
            continue;
        }
        let role_hint = infer_role_hint(&identity.argv);
        let ports = parse_ports_from_argv(&identity.argv);
        let sanitized = sanitize_argv(&identity.argv);
        let resources = sampler.sample_pid(pid);
        results.push(UnmanagedProcess {
            pid,
            role_hint,
            ports: ports.all_ports(),
            sanitized_cmdline: sanitized.join(" "),
            resources,
        });
    }
    results.sort_by_key(|p| p.pid);
    results
}

/// How long a scan that found no JVM Canton process is trusted before the host is scanned again.
const JVM_RESCAN_INTERVAL: Duration = Duration::from_secs(60);

/// Attempts to locate a JVM Canton process RSS if `--shadow-verify` runs alongside a JVM node.
pub fn detect_jvm_canton_rss(sampler: &mut OsProcSampler) -> Option<u64> {
    if let Some(pid) = sampler.jvm_pid {
        if inspect_pid_identity(pid).is_some_and(|id| is_jvm_canton(&id)) {
            let rss = sampler.sample_pid(pid).rss_bytes;
            if rss > 0 {
                return Some(rss);
            }
        }
        sampler.jvm_pid = None;
    }
    let now = Instant::now();
    if sampler.jvm_next_scan.is_some_and(|at| now < at) {
        return None;
    }
    sampler.jvm_next_scan = Some(now + JVM_RESCAN_INTERVAL);
    let self_pid = std::process::id();
    for pid in list_all_pids() {
        if pid == self_pid {
            continue;
        }
        let Some(id) = inspect_pid_identity(pid) else {
            continue;
        };
        if is_jvm_canton(&id) {
            let res = sampler.sample_pid(pid);
            if res.rss_bytes > 0 {
                sampler.jvm_pid = Some(pid);
                return Some(res.rss_bytes);
            }
        }
    }
    None
}

fn is_jvm_canton(id: &ProcIdentity) -> bool {
    let basename = |p: &Path| p.file_name().and_then(|n| n.to_str()).map(str::to_owned);
    let exe = id
        .exe_path
        .as_deref()
        .and_then(basename)
        .or_else(|| id.argv.first().map(Path::new).and_then(basename));
    let is_java = exe.is_some_and(|n| n == "java" || n == "java.exe");
    // Canton runs as `java ... com.digitalasset.canton.Canton*App` or `java -jar .../canton-*.jar`.
    let runs_canton = id.argv.iter().any(|a| {
        a.contains("com.digitalasset.canton.")
            || Path::new(a)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("canton") && n.ends_with(".jar"))
    });
    is_java && runs_canton
}

fn is_canton_rs_process(identity: &ProcIdentity) -> bool {
    let exe_matches = identity
        .exe_path
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("canton-rs"));
    if exe_matches {
        // Ignore short-lived read-only inspection queries like `daemon ps --scan-host`.
        if identity
            .argv
            .iter()
            .any(|a| a == "ps" || a == "status" || a == "stats" || a == "top")
        {
            return false;
        }
        return true;
    }
    identity.argv.first().is_some_and(|a| {
        Path::new(a)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("canton-rs"))
    })
}

fn infer_role_hint(argv: &[String]) -> String {
    let joined: Vec<&str> = argv.iter().skip(1).take(2).map(String::as_str).collect();
    if joined.is_empty() {
        "canton-rs".to_string()
    } else {
        joined.join(" ")
    }
}

fn parse_ports_from_argv(argv: &[String]) -> NodePorts {
    let mut ports = NodePorts::default();
    let flag_map: BTreeMap<&str, usize> = BTreeMap::from([
        ("--port", 0),
        ("-p", 0),
        ("--http-port", 0),
        ("--grpc-port", 1),
        ("--admin-port", 2),
        ("--metrics-port", 3),
        ("--public-api", 4),
    ]);
    let mut iter = argv.iter().peekable();
    while let Some(arg) = iter.next() {
        let (flag, val) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (arg.as_str(), iter.peek().map(|s| s.as_str())),
        };
        let Some(&kind) = flag_map.get(flag) else {
            continue;
        };
        let Some(raw) = val else {
            continue;
        };
        let parsed = raw
            .rsplit(':')
            .next()
            .and_then(|tail| tail.parse::<u16>().ok());
        if let Some(p) = parsed {
            match kind {
                0 => ports.http_json = Some(p),
                1 => ports.grpc_ledger = Some(p),
                2 => ports.admin = Some(p),
                3 => ports.metrics = Some(p),
                _ => ports.public = Some(p),
            }
        }
    }
    ports
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn mach_timebase_info(info: *mut MachTimebase) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn sample_raw_pid(pid: u32) -> Option<RawProcSample> {
    let mut task_info = libc::proc_taskinfo {
        pti_virtual_size: 0,
        pti_resident_size: 0,
        pti_total_user: 0,
        pti_total_system: 0,
        pti_threads_user: 0,
        pti_threads_system: 0,
        pti_policy: 0,
        pti_faults: 0,
        pti_pageins: 0,
        pti_cow_faults: 0,
        pti_messages_sent: 0,
        pti_messages_received: 0,
        pti_syscalls_mach: 0,
        pti_syscalls_unix: 0,
        pti_csw: 0,
        pti_threadnum: 0,
        pti_numrunning: 0,
        pti_priority: 0,
    };
    let info_size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    let info_ptr = (&mut task_info as *mut libc::proc_taskinfo).cast::<libc::c_void>();
    // SAFETY: `task_info` is a stack-allocated `proc_taskinfo` initialized with valid `info_size`.
    let ret =
        unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDTASKINFO, 0, info_ptr, info_size) };
    if ret <= 0 {
        return None;
    }

    let mut tb = MachTimebase { numer: 1, denom: 1 };
    // SAFETY: `tb` is a valid stack `MachTimebase` out-pointer populated by macOS libSystem.
    unsafe {
        mach_timebase_info(&mut tb);
    }
    let ticks = task_info
        .pti_total_user
        .saturating_add(task_info.pti_total_system);
    let cpu_ns = if tb.denom == 0 {
        ticks
    } else {
        ticks.saturating_mul(u64::from(tb.numer)) / u64::from(tb.denom)
    };

    let open_fds = macos_open_fds(pid as i32);

    Some(RawProcSample {
        cpu_ns,
        rss_bytes: task_info.pti_resident_size,
        vms_bytes: task_info.pti_virtual_size,
        thread_count: u32::try_from(task_info.pti_threadnum).unwrap_or(0),
        open_fds,
    })
}

/// Upper bound on FD entries read per sample (8 MiB of `proc_fdinfo`).
#[cfg(target_os = "macos")]
const MAX_FD_ENTRIES: usize = 1 << 20;

#[cfg(target_os = "macos")]
fn macos_open_fds(pid: i32) -> u32 {
    let entry = std::mem::size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer with size 0 asks the kernel for the byte size of the FD table.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let Ok(need) = usize::try_from(need) else {
        return 0;
    };
    if need == 0 {
        return 0;
    }
    // Headroom covers descriptors opened between the two calls.
    let cap = (need / entry).saturating_add(64).min(MAX_FD_ENTRIES);
    let mut buf = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        cap
    ];
    let bytes = libc::c_int::try_from(cap * entry).unwrap_or(libc::c_int::MAX);
    let ptr = buf.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `buf` holds `cap` entries, which is at least `bytes` writable bytes.
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, ptr, bytes) };
    usize::try_from(got).map_or(0, |n| u32::try_from(n / entry).unwrap_or(u32::MAX))
}

#[cfg(target_os = "macos")]
fn inspect_pid_identity_os(pid: u32) -> Option<ProcIdentity> {
    let mut path_buf = vec![0u8; 4096];
    let path_ptr = path_buf.as_mut_ptr().cast::<libc::c_void>();
    let path_cap = path_buf.len() as u32;
    // SAFETY: `path_buf` has `path_cap` writable bytes for `proc_pidpath`.
    let path_len = unsafe { libc::proc_pidpath(pid as i32, path_ptr, path_cap) };
    let exe_path = if path_len > 0 {
        let end = (path_len as usize).min(path_buf.len());
        Some(PathBuf::from(
            String::from_utf8_lossy(&path_buf[..end]).into_owned(),
        ))
    } else {
        None
    };

    let mut bsd: libc::proc_bsdinfo = zeroed_bsdinfo();
    let bsd_size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let bsd_ptr = (&mut bsd as *mut libc::proc_bsdinfo).cast::<libc::c_void>();
    // SAFETY: `bsd` is initialized stack storage sized `bsd_size` for `PROC_PIDTBSDINFO`.
    let bsd_ret =
        unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0, bsd_ptr, bsd_size) };
    let started_at_unix_secs = if bsd_ret > 0 {
        Some(bsd.pbi_start_tvsec)
    } else {
        None
    };

    let argv = macos_procargs2(pid).unwrap_or_default();
    if exe_path.is_none() && bsd_ret <= 0 && argv.is_empty() {
        return None;
    }
    Some(ProcIdentity {
        pid,
        exe_path,
        started_at_unix_secs,
        argv,
    })
}

#[cfg(target_os = "macos")]
fn zeroed_bsdinfo() -> libc::proc_bsdinfo {
    // SAFETY: `proc_bsdinfo` is a plain-old-data C struct of integers and `c_char` arrays.
    unsafe { std::mem::zeroed() }
}

#[cfg(target_os = "macos")]
fn macos_procargs2(pid: u32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;
    // SAFETY: First `sysctl` queries buffer length with null oldp pointer.
    let q = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if q != 0 || !(8..=1024 * 1024).contains(&size) {
        return None;
    }
    let mut buf = vec![0u8; size];
    let buf_ptr = buf.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `buf` is allocated with `size` writable bytes returned by the first `sysctl` call.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf_ptr,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if !(0..=1024).contains(&argc) {
        return None;
    }
    let mut idx = 4usize;
    let slice = &buf[..size.min(buf.len())];
    // Skip exec_path terminated by NUL
    while idx < slice.len() && slice[idx] != 0 {
        idx += 1;
    }
    // Skip trailing NUL padding after exec_path
    while idx < slice.len() && slice[idx] == 0 {
        idx += 1;
    }
    let mut args = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        if idx >= slice.len() {
            break;
        }
        let start = idx;
        while idx < slice.len() && slice[idx] != 0 {
            idx += 1;
        }
        args.push(String::from_utf8_lossy(&slice[start..idx]).into_owned());
        idx += 1;
    }
    Some(args)
}

#[cfg(target_os = "macos")]
fn list_all_pids() -> Vec<u32> {
    // SAFETY: Passing null/0 queries the approximate number of PIDs on macOS.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Vec::new();
    }
    let cap = (count as usize).saturating_add(64);
    let mut pids = vec![0i32; cap];
    let bytes = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
    let ptr = pids.as_mut_ptr().cast::<libc::c_void>();
    // SAFETY: `pids` is allocated for `bytes` writable bytes of `pid_t`.
    let n = unsafe { libc::proc_listallpids(ptr, bytes) };
    if n <= 0 {
        return Vec::new();
    }
    pids.into_iter()
        .take(n as usize)
        .filter(|p| *p > 0)
        .map(|p| p as u32)
        .collect()
}

#[cfg(target_os = "linux")]
fn sample_raw_pid(pid: u32) -> Option<RawProcSample> {
    let stat_text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat_text.rfind(')')?;
    let after = stat_text.get(rparen + 2..)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // Fields after `(comm) state`: index 11 is utime, 12 is stime, 17 is num_threads.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let thread_count: u32 = fields.get(17).and_then(|s| s.parse().ok()).unwrap_or(1);

    // SAFETY: `sysconf(_SC_CLK_TCK)` is a thread-safe POSIX query with no pointer arguments.
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let ticks_per_sec = u64::try_from(clk_tck).unwrap_or(100).max(1);
    let cpu_ns = (utime.saturating_add(stime)).saturating_mul(1_000_000_000) / ticks_per_sec;

    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let mut statm_parts = statm.split_whitespace();
    let vms_pages: u64 = statm_parts.next()?.parse().ok()?;
    let rss_pages: u64 = statm_parts.next()?.parse().ok()?;
    // SAFETY: `sysconf(_SC_PAGESIZE)` is a thread-safe POSIX query with no pointer arguments.
    let page_raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = u64::try_from(page_raw).unwrap_or(4096).max(512);

    let open_fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|it| u32::try_from(it.count()).unwrap_or(u32::MAX))
        .unwrap_or(0);

    Some(RawProcSample {
        cpu_ns,
        rss_bytes: rss_pages.saturating_mul(page_size),
        vms_bytes: vms_pages.saturating_mul(page_size),
        thread_count,
        open_fds,
    })
}

#[cfg(target_os = "linux")]
fn inspect_pid_identity_os(pid: u32) -> Option<ProcIdentity> {
    let dir = PathBuf::from(format!("/proc/{pid}"));
    if !dir.exists() {
        return None;
    }
    let exe_path = std::fs::read_link(dir.join("exe")).ok();
    let cmd_bytes = std::fs::read(dir.join("cmdline")).unwrap_or_default();
    let argv: Vec<String> = cmd_bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let started_at_unix_secs = linux_proc_start_secs(pid);
    Some(ProcIdentity {
        pid,
        exe_path,
        started_at_unix_secs,
        argv,
    })
}

#[cfg(target_os = "linux")]
fn linux_proc_start_secs(pid: u32) -> Option<u64> {
    let stat_text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat_text.rfind(')')?;
    let fields: Vec<&str> = stat_text.get(rparen + 2..)?.split_whitespace().collect();
    let start_ticks: u64 = fields.get(19)?.parse().ok()?;
    // SAFETY: `sysconf(_SC_CLK_TCK)` is a pure POSIX integer configuration query.
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = u64::try_from(clk_tck).unwrap_or(100).max(1);
    let stat_global = std::fs::read_to_string("/proc/stat").ok()?;
    let btime = stat_global
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|s| s.trim().parse::<u64>().ok())?;
    Some(btime.saturating_add(start_ticks / hz))
}

#[cfg(target_os = "linux")]
fn list_all_pids() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample_raw_pid(_pid: u32) -> Option<RawProcSample> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn inspect_pid_identity_os(_pid: u32) -> Option<ProcIdentity> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn list_all_pids() -> Vec<u32> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_current_process_resources() {
        let mut sampler = OsProcSampler::new();
        let pid = std::process::id();
        let first = sampler.sample_pid(pid);
        assert!(
            first.rss_bytes > 0,
            "expected non-zero RSS for current process"
        );
        assert!(first.vms_bytes >= first.rss_bytes);
        assert!(first.thread_count >= 1);
        std::thread::sleep(std::time::Duration::from_millis(15));
        let second = sampler.sample_pid(pid);
        assert!(second.rss_bytes > 0);
        assert!(second.cpu_percent >= 0.0);
    }

    fn identity(exe: &str, argv: &[&str]) -> ProcIdentity {
        ProcIdentity {
            pid: 7,
            exe_path: Some(PathBuf::from(exe)),
            started_at_unix_secs: None,
            argv: argv.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn jvm_baseline_matches_only_a_java_process_running_canton() {
        let jvm = identity(
            "/usr/lib/jvm/bin/java",
            &[
                "java",
                "-jar",
                "/opt/canton/lib/canton-open-source-3.7.2.jar",
                "daemon",
            ],
        );
        assert!(is_jvm_canton(&jvm));
        let rust_node = identity(
            "/work/target/debug/canton-rs",
            &[
                "/work/target/debug/canton-rs",
                "participant",
                "--state-dir",
                "/tmp/canton",
            ],
        );
        assert!(
            !is_jvm_canton(&rust_node),
            "a canton-rs node is not the JVM baseline"
        );
        let other_java = identity("/usr/bin/java", &["java", "-jar", "kafka.jar"]);
        assert!(!is_jvm_canton(&other_java));
        let pager = identity("/usr/bin/less", &["less", "canton.log"]);
        assert!(!is_jvm_canton(&pager));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn open_fd_count_is_not_capped_at_the_first_buffer() {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` is a valid out-pointer for `getrlimit`.
        let got = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        assert_eq!(got, 0);
        if lim.rlim_cur < 1024 {
            lim.rlim_cur = lim.rlim_max.min(4096);
            // SAFETY: `lim` holds a soft limit no larger than the hard limit.
            let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
            assert_eq!(set, 0);
        }
        let files: Vec<std::fs::File> = (0..400)
            .map(|_| std::fs::File::open("/dev/null").expect("open /dev/null"))
            .collect();
        let res = OsProcSampler::new().sample_pid(std::process::id());
        assert!(
            res.open_fds >= 400,
            "sampled {} open fds with {} held open",
            res.open_fds,
            files.len()
        );
    }

    #[test]
    fn inspects_current_pid_identity_and_masks_unmanaged_scan() {
        let pid = std::process::id();
        let id = inspect_pid_identity(pid).expect("identity of self");
        assert_eq!(id.pid, pid);
        assert!(id.exe_path.is_some());

        let current_exe = std::env::current_exe().expect("current_exe");
        assert!(pid_matches_expected(
            pid,
            &current_exe,
            id.started_at_unix_secs
                .unwrap_or_else(super::super::now_unix_secs)
        ));
        assert!(!pid_matches_expected(
            pid,
            Path::new("/nonexistent/other-binary"),
            0
        ));
    }
}
