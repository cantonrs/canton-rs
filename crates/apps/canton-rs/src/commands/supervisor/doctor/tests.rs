use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::checks::{
    check_d10_hub_containers, check_d1_port_range, check_d2_protected_ports, check_d3_ports_in_use,
    check_d4_internal_collisions, check_d5_state_dir, check_d6_disk_space, check_d7_target_size,
    check_d8_postgres, check_d9_dars, detect_listening_ports, parse_linux_proc_net_tcp,
    parse_macos_lsof_listen_ports, parse_macos_netstat_listen_ports, DoctorHost, PgProbeResult,
    DISK_FAIL_BYTES, DISK_WARN_BYTES, PROTECTED_HUB_PORTS, TARGET_WARN_BYTES,
};
use super::plan::{resolve_doctor_plan, shift_port, DoctorPlan, PortEntry};
use super::{compute_exit_code, render_json, render_text, run_doctor, CheckStatus, DoctorReport};
use crate::commands::exit_code::{EXIT_OK, EXIT_PREFLIGHT};
use crate::commands::supervisor::cli::UpArgs;
use crate::commands::supervisor::{
    DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES, DEFAULT_TRACE_RATE_LIMIT,
};
use ledger_json_api::canton_log::LogEncoder;

fn sample_plan(ports: Vec<(u16, Option<u16>)>, state_dir: PathBuf) -> DoctorPlan {
    DoctorPlan {
        state_dir,
        state_dir_is_default: false,
        ports: ports
            .into_iter()
            .enumerate()
            .map(|(i, (base, resolved))| PortEntry {
                label: format!("svc{i}.public"),
                owner: format!("svc{i}"),
                base,
                offset: 0,
                resolved,
            })
            .collect(),
        pg_urls: Vec::new(),
        dar_files: Vec::new(),
        dar_dirs: Vec::new(),
        metrics_port: None,
    }
}

fn default_test_up_args(
    file: Option<PathBuf>,
    config: Option<PathBuf>,
    state_dir: PathBuf,
) -> UpArgs {
    UpArgs {
        file,
        config,
        bootstrap: None,
        detach: false,
        name: None,
        state_dir: Some(state_dir),
        official_pg_addr: None,
        conf_auth_cert: None,
        dar: None,
        state_in_files: false,
        port_offset: None,
        same_identity: false,
        official_write: false,
        strict_config: false,
        log_encoder: LogEncoder::Text,
        log_level: None,
        log_diagnostics: None,
        suppress_idle_polls: None,
        no_restart: false,
        metrics_port: Some(0),
        metrics_bind: "127.0.0.1".into(),
        observability: false,
        dev_auth: false,
        bind: "127.0.0.1".into(),
        log_max_bytes: DEFAULT_LOG_MAX_BYTES,
        log_max_files: DEFAULT_LOG_MAX_FILES,
        xray: false,
        trace_rate_limit: DEFAULT_TRACE_RATE_LIMIT,
        shadow_verify: false,
        shadow_jvm_url: None,
        profile: Vec::new(),
        group: Vec::new(),
        token_env: None,
        token_file: None,
        pg_url: None,
        worker: false,
    }
}

#[test]
fn d1_detects_overflow_and_privileged_without_panicking() {
    assert_eq!(shift_port(60000, 6000), None);
    assert_eq!(shift_port(40000, 7000), Some(47000));

    let mut plan = sample_plan(vec![(60000, None), (80, Some(80))], PathBuf::from("/tmp"));
    plan.ports[0].offset = 6000;
    let c = check_d1_port_range(&plan);
    assert_eq!(c.id, "D1");
    assert_eq!(c.status, CheckStatus::Fail);
    assert!(
        c.message.contains("65535"),
        "expected overflow msg: {}",
        c.message
    );
    assert!(
        c.message.contains("80"),
        "expected privileged msg: {}",
        c.message
    );
    assert!(c.fix.is_some());
}

#[test]
fn d2_rejects_all_protected_hub_ports() {
    for &p in &PROTECTED_HUB_PORTS {
        let plan = sample_plan(vec![(p, Some(p))], PathBuf::from("/tmp"));
        let c = check_d2_protected_ports(&plan);
        assert_eq!(c.status, CheckStatus::Fail, "port {p} must fail D2");
        assert!(c.message.contains(&p.to_string()), "{}", c.message);
    }
}

#[test]
fn d4_detects_internal_collisions() {
    let plan = sample_plan(
        vec![(7575, Some(7575)), (7575, Some(7575))],
        PathBuf::from("/tmp"),
    );
    let c = check_d4_internal_collisions(&plan);
    assert_eq!(c.status, CheckStatus::Fail);
    assert!(c.message.contains("7575"), "{}", c.message);
}

#[test]
fn d5_checks_writability_test_mode_default_and_registry_without_mutating_disk() {
    let dir = std::env::temp_dir().join(format!("crs-doc-d5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let nonexistent = dir.join("missing-subdir");

    let mut plan = sample_plan(vec![], nonexistent);
    plan.state_dir_is_default = false;
    let mut host = DoctorHost::live();
    host.test_mode = true;

    let c_ok = check_d5_state_dir(&plan, &host);
    assert_eq!(c_ok.status, CheckStatus::Ok, "{}", c_ok.message);
    assert!(
        !dir.exists(),
        "D5 must never create directories on disk (D-A1)"
    );

    let mut default_plan = sample_plan(vec![], PathBuf::from("canton-rs-state"));
    default_plan.state_dir_is_default = true;
    let c_default = check_d5_state_dir(&default_plan, &host);
    assert_eq!(c_default.status, CheckStatus::Fail, "{}", c_default.message);

    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join("instance.json"),
        r#"{"name":"x","version":"0.0.1-old"}"#,
    )
    .expect("write registry");
    let reg_plan = sample_plan(vec![], dir.clone());
    let c_warn = check_d5_state_dir(&reg_plan, &host);
    assert_eq!(c_warn.status, CheckStatus::Warn, "{}", c_warn.message);

    let file_as_dir = dir.join("not-a-dir");
    std::fs::write(&file_as_dir, b"x").expect("write file");
    let bad_plan = sample_plan(vec![], file_as_dir);
    let c_bad = check_d5_state_dir(&bad_plan, &host);
    assert_eq!(c_bad.status, CheckStatus::Fail, "{}", c_bad.message);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn d6_d7_d8_d9_d10_thresholds_and_errors_behave_per_spec() {
    let plan = sample_plan(vec![], PathBuf::from("/tmp"));

    let mut host = DoctorHost::live();
    host.disk_avail_override = Some(DISK_FAIL_BYTES - 1);
    assert_eq!(check_d6_disk_space(&plan, &host).status, CheckStatus::Fail);

    host.disk_avail_override = Some(DISK_WARN_BYTES - 1);
    assert_eq!(check_d6_disk_space(&plan, &host).status, CheckStatus::Warn);

    host.disk_avail_override = Some(DISK_WARN_BYTES + 1);
    assert_eq!(check_d6_disk_space(&plan, &host).status, CheckStatus::Ok);

    host.target_bytes_override = Some(TARGET_WARN_BYTES + 1);
    assert_eq!(check_d7_target_size(&host).status, CheckStatus::Warn);
    host.target_bytes_override = Some(1024);
    assert_eq!(check_d7_target_size(&host).status, CheckStatus::Ok);

    let mut pg_plan = plan.clone();
    pg_plan
        .pg_urls
        .push("postgres://user:secret@127.0.0.1:59999/db".into());
    host.pg_probe_override = Some(PgProbeResult::VersionMismatch(
        "Expected Postgres version 14..18".into(),
    ));
    assert_eq!(check_d8_postgres(&pg_plan, &host).status, CheckStatus::Warn);

    host.pg_probe_override = Some(PgProbeResult::Unreachable("conn refused".into()));
    assert_eq!(check_d8_postgres(&pg_plan, &host).status, CheckStatus::Fail);

    let mut dar_plan = plan.clone();
    dar_plan
        .dar_files
        .push(PathBuf::from("/nonexistent/missing-model.dar"));
    let d9_fail = check_d9_dars(&dar_plan);
    assert_eq!(d9_fail.status, CheckStatus::Fail);

    let real_dar =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar");
    if real_dar.exists() {
        let mut ok_dar_plan = plan;
        ok_dar_plan.dar_files.push(real_dar);
        assert_eq!(check_d9_dars(&ok_dar_plan).status, CheckStatus::Ok);
    }

    host.hub_containers_override = Some(vec!["hub-postgres".into()]);
    let d10 = check_d10_hub_containers(&host);
    assert_eq!(d10.status, CheckStatus::Warn);
    assert!(d10.message.contains("hub-postgres"));
}

#[test]
fn doctor_report_monotone_exit_and_json_isomorphism() {
    let mut host = DoctorHost::live();
    host.disk_avail_override = Some(DISK_WARN_BYTES + 100);
    host.target_bytes_override = Some(0);
    host.hub_containers_override = Some(Vec::new());
    host.skip_ipc_probe = true;

    let plan_ok = sample_plan(vec![], PathBuf::from("/tmp"));
    let report = run_doctor(&plan_ok, &host);
    assert_eq!(report.exit_code, EXIT_OK);
    assert_eq!(report.checks.len(), 10);

    // D-A4: JSON parse(render(R)) == R, and text renders the exact same checks.
    let json = render_json(&report).expect("render json");
    let decoded: DoctorReport = serde_json::from_str(&json).expect("decode json");
    assert_eq!(decoded, report);
    let text = render_text(&report);
    assert!(text.contains("[D1 ] ok"));
    assert!(text.contains("[D10] ok"));

    // D-A2 monotonicity: adding a Fail check never lowers exit code.
    let mut with_fail = report.checks.clone();
    with_fail.push(super::DoctorCheck {
        id: "D_EXTRA".into(),
        status: CheckStatus::Fail,
        message: "injected failure".into(),
        fix: Some("fix".into()),
    });
    assert!(compute_exit_code(&report.checks) <= compute_exit_code(&with_fail));
    assert_eq!(compute_exit_code(&with_fail), EXIT_PREFLIGHT);
}

#[test]
fn hocon_doctor_plan_never_creates_state_dir() {
    let dir = std::env::temp_dir().join(format!("crs-doc-hocon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let conf = dir.join("canton.conf");
    std::fs::write(
        &conf,
        r#"canton {
  sequencers.s1 { public-api.port = 5018, admin-api.port = 5019 }
  mediators.m1 { admin-api.port = 5027 }
  participants.p1 { http-ledger-api.port = 7575, ledger-api.port = 7576, admin-api.port = 7577 }
}"#,
    )
    .expect("write conf");

    let ghost_state = dir.join("ghost-state-never-created");
    let mut up = default_test_up_args(None, Some(conf), ghost_state.clone());
    up.port_offset = Some(40000);
    let plan = resolve_doctor_plan(&up, None).expect("resolve hocon plan");
    assert!(
        !ghost_state.exists(),
        "Hocon doctor plan must be pure (D-A1)"
    );
    assert!(plan
        .ports
        .iter()
        .any(|p| p.label == "s1.public" && p.resolved == Some(45018)));
    assert!(plan
        .ports
        .iter()
        .any(|p| p.label == "p1.json" && p.resolved == Some(47575)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn live_os_socket_table_detects_bound_loopback_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let detected = detect_listening_ports(&[port]);
    assert!(
        detected.contains(&port),
        "detect_listening_ports must detect bound listener on 127.0.0.1:{port}, got {detected:?}"
    );
}

#[test]
fn parses_macos_netstat_and_linux_proc_net_listen_tables() {
    let mac_out = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  127.0.0.1.54105        *.*                    LISTEN
tcp46      0      0  *.8000                 *.*                    LISTEN
tcp6       0      0  ::1.54281              *.*                    LISTEN
tcp4       0      0  127.0.0.1.54105        127.0.0.1.60001        ESTABLISHED
tcp4       0      0  192.168.1.10.9999      *.*                    LISTEN
";
    let mac_ports = parse_macos_netstat_listen_ports(mac_out);
    assert!(mac_ports.contains(&54105));
    assert!(mac_ports.contains(&8000));
    assert!(mac_ports.contains(&54281));
    assert!(!mac_ports.contains(&60001));
    assert!(!mac_ports.contains(&9999));

    let proc_v4 = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1D97 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345
   1: 00000000:1920 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346
   2: 0100007F:1D98 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000        0 12347
";
    let v4_ports = parse_linux_proc_net_tcp(proc_v4, false);
    assert!(v4_ports.contains(&0x1D97)); // 7575
    assert!(v4_ports.contains(&0x1920)); // 6432
    assert!(!v4_ports.contains(&0x1D98)); // ESTABLISHED (01) ignored

    let proc_v6 = "\
   0: 00000000000000000000000001000000:139A 00000000000000000000000000000000:0000 0A 00000000:00000000
";
    let v6_ports = parse_linux_proc_net_tcp(proc_v6, true);
    assert!(v6_ports.contains(&0x139A)); // 5018

    let lsof_out = "\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
agy         198 kwon   10u  IPv4 0x145e18d73ffcf1e      0t0  TCP 127.0.0.1:58692 (LISTEN)
kiri      14818 kwon   15u  IPv4 0x6238431559fda145     0t0  TCP *:6432 (LISTEN)
My App    99999 kwon   11u  IPv6 0xd6b959562508be4e     0t0  TCP [::1]:7575 (LISTEN)
remote    88888 kwon   12u  IPv4 0x1111                 0t0  TCP 192.168.1.10:9999 (LISTEN)
";
    let lsof_ports = parse_macos_lsof_listen_ports(lsof_out);
    assert!(lsof_ports.contains(&58692));
    assert!(lsof_ports.contains(&6432));
    assert!(lsof_ports.contains(&7575));
    assert!(!lsof_ports.contains(&9999));
}

#[test]
fn sdx001_d05_d3_non_binding_race() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};

    if let Ok(csv) = std::env::var("CANTON_RS_D05_OBSERVER_PORTS") {
        let ports: Vec<u16> = csv
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_watch = Arc::clone(&stop);
        let stdin_watcher = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut buf);
            stop_watch.store(true, Ordering::Relaxed);
        });

        println!("D05_OBSERVER_READY");
        let _ = std::io::stdout().flush();

        let mut hits = 0usize;
        while !stop.load(Ordering::Relaxed) {
            for &port in &ports {
                match TcpListener::bind(("127.0.0.1", port)) {
                    Ok(listener) => {
                        drop(listener);
                        std::thread::yield_now();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                        hits += 1;
                    }
                    Err(_) => {}
                }
            }
        }
        let _ = stdin_watcher.join();
        println!("D05_OBSERVER_HITS={hits}");
        let _ = std::io::stdout().flush();
        return;
    }

    // Allocate 4 distinct free ports OUTSIDE macOS ephemeral range (49152..65535) so concurrent
    // tests calling `bind("127.0.0.1:0")` cannot touch these test ports.
    let mut ports = Vec::with_capacity(4);
    for cand in 39100..39900 {
        if PROTECTED_HUB_PORTS.contains(&cand) {
            continue;
        }
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", cand)) {
            drop(listener);
            ports.push(cand);
            if ports.len() == 4 {
                break;
            }
        }
    }
    assert_eq!(
        ports.len(),
        4,
        "failed to allocate 4 free ports in 39100..39900"
    );

    let csv = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .args([
            "commands::supervisor::doctor::tests::sdx001_d05_d3_non_binding_race",
            "--exact",
            "--nocapture",
        ])
        .env("CANTON_RS_D05_OBSERVER_PORTS", csv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn observer process");

    let mut stdin = child.stdin.take();
    let stdout = child.stdout.take().expect("observer stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut ready = false;
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line.contains("D05_OBSERVER_READY") {
            ready = true;
            break;
        }
        line.clear();
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("observer child exited before D05_OBSERVER_READY");
    }

    let plan = sample_plan(
        ports.into_iter().map(|p| (p, Some(p))).collect(),
        PathBuf::from("/tmp"),
    );
    let mut host = DoctorHost::live();
    host.skip_ipc_probe = true;
    host.ports_probe = detect_listening_ports;

    let start = std::time::Instant::now();
    let mut iters = 0usize;
    while iters < 10 || start.elapsed() < std::time::Duration::from_millis(200) {
        let _ = check_d3_ports_in_use(&plan, &host);
        iters += 1;
    }

    drop(stdin.take());
    let mut hits: Option<usize> = None;
    let mut tail = String::new();
    while {
        line.clear();
        reader.read_line(&mut line).unwrap_or(0) > 0
    } {
        tail.push_str(&line);
        if let Some(rest) = line.trim().strip_prefix("D05_OBSERVER_HITS=") {
            hits = rest.parse::<usize>().ok();
        }
    }
    let status = child.wait().expect("wait observer child");
    assert!(
        status.success(),
        "observer process failed: {status}, output={tail}"
    );
    let hits =
        hits.unwrap_or_else(|| panic!("missing D05_OBSERVER_HITS in observer output: {tail}"));

    assert_eq!(
        hits, 0,
        "D3 port probe must never bind() sockets and cause AddrInUse races (observed {hits} AddrInUse hits across {iters} checks)"
    );
}
