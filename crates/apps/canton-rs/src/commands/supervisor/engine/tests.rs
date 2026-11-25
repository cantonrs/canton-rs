use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, watch};

use super::super::now_unix_secs;
use super::lifecycle::{for_each_line_lossy, mark_slot_boot_failed, process_backoff_respawns};
use super::ops::{cleanup_local_state_files, mark_state_dir_if_empty, STATE_DIR_MARKER};
use super::*;

fn test_ctx(spec: DaemonSpec) -> Arc<EngineContext> {
    let (exit_tx, _exit_rx) = mpsc::unbounded_channel();
    let (snapshot_tx, _) = broadcast::channel(8);
    let (shutdown_tx, _) = watch::channel(false);
    let slots: Vec<SlotRuntime> = spec
        .services
        .iter()
        .cloned()
        .map(SlotRuntime::new)
        .collect();
    Arc::new(EngineContext {
        spec,
        exe_path: std::path::PathBuf::from("canton-rs"),
        storage_mode: "files".to_string(),
        slots: Mutex::new(slots),
        booting_pids: Mutex::new(BTreeMap::new()),
        log_hub: LogHub::new(),
        wiretap: WiretapHub::new(10),
        exporter: ExporterState::default(),
        last_ping: Mutex::new(None),
        shadow_verify: Mutex::new(None),
        remote_nodes_cache: RwLock::new(Vec::new()),
        latest_snapshot: RwLock::new(None),
        snapshot_tx,
        exit_tx,
        shutting_down: AtomicBool::new(false),
        shutdown_tx,
        shutdown_opts: Mutex::new(None),
    })
}

/// A failed Ping exports `canton_rs_last_ping_ok 0` and no round-trip time: the elapsed time of a failure is not an RTT.
#[test]
fn failed_ping_is_exported_as_failure_without_rtt() {
    let parsed = super::super::manifest::parse_yaml_manifest_str(
        "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
        Path::new("."),
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(spec) = parsed else {
        panic!("expected ModeA");
    };
    let ctx = test_ctx(spec);
    *ctx.last_ping.lock().expect("ping") = Some(PingStatus {
        ok: false,
        rtt_ms: 30_000.0,
        detail: "p1 -> p2: UNAUTHENTICATED".into(),
        checked_at_unix_ms: 0,
    });
    let text =
        super::super::metrics::render_prometheus_metrics(&ctx.build_snapshot(), &BTreeMap::new());
    assert!(
        !text.contains("canton_rs_last_ping_rtt_seconds{"),
        "a failure has no RTT sample: {text}"
    );
    assert!(text.contains("canton_rs_last_ping_ok{"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("canton_rs_last_ping_ok{") && l.ends_with(" 0")),
        "{text}"
    );
}

/// A PID entry keeps the child's start time across later manifest syncs, so orphan cleanup after a supervisor crash still matches it.
#[test]
fn pid_manifest_keeps_the_child_start_time_across_syncs() {
    let dir = std::env::temp_dir().join(format!("canton-pidsync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let parsed = super::super::manifest::parse_yaml_manifest_str(
        "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
        &dir,
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
        panic!("expected ModeA");
    };
    spec.state_dir = dir.clone();
    let ctx = test_ctx(spec);
    {
        let mut slots = ctx.slots.lock().expect("slots");
        slots[0].pid = Some(4242);
        slots[0].pid_started_unix = Some(now_unix_secs());
    }
    ctx.sync_pid_manifest();
    let first = PidManifest::load(&dir).entries[0].started_at_unix;
    std::thread::sleep(Duration::from_millis(1100));
    ctx.sync_pid_manifest();
    let second = PidManifest::load(&dir).entries[0].started_at_unix;
    assert_eq!(
        first, second,
        "a later sync must not restamp the start time"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn backoff_scales_exponentially_and_caps_at_30s() {
    for f in 1..=8 {
        let ms = compute_backoff_ms(f, 0);
        let expected_base = match f {
            1 => 1000,
            2 => 2000,
            3 => 4000,
            4 => 8000,
            5 => 16000,
            _ => 30000,
        };
        let lo = (expected_base * 90) / 100;
        let hi = (expected_base * 110) / 100;
        assert!(
            (lo..=hi).contains(&ms),
            "failure {f}: {ms}ms outside 10% band around {expected_base}ms"
        );
    }
}

/// Stays alive without printing a ready line: the child a slow respawn waits on (the test binary runs it with `--ignored`).
#[test]
#[ignore = "child process helper for the respawn test"]
fn sleeper_child_helper() {
    std::thread::sleep(Duration::from_secs(30));
}

/// A slow respawn does not hold the supervisor loop: the tick returns at once, and a shutdown stops the respawn and its child.
#[tokio::test(flavor = "multi_thread")]
async fn backoff_respawn_does_not_block_the_main_loop() {
    let dir = std::env::temp_dir().join(format!("canton-respawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let parsed = super::super::manifest::parse_yaml_manifest_str(
        "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
        &dir,
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
        panic!("expected ModeA");
    };
    spec.state_dir = dir.clone();
    spec.services[0].argv = vec![
        "--exact".into(),
        "commands::supervisor::engine::tests::sleeper_child_helper".into(),
        "--ignored".into(),
    ];
    spec.services[0].env.clear();
    spec.services[0].ready_line_prefix = Some("NEVER-READY".into());
    let ctx = test_ctx(spec);
    {
        let mut slots = ctx.slots.lock().expect("slots");
        slots[0].state = NodeLifecycleState::BackoffWait;
        slots[0].backoff_until_ms = Some(0);
    }
    let started = Instant::now();
    let mut respawns = tokio::task::JoinSet::new();
    process_backoff_respawns(&ctx, &mut respawns);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the tick waited {:?} on a respawn",
        started.elapsed()
    );
    assert_eq!(respawns.len(), 1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    ctx.shutting_down.store(true, Ordering::SeqCst);
    let finished = tokio::time::timeout(Duration::from_secs(5), respawns.join_next()).await;
    assert!(finished.is_ok(), "a shutdown ends the in-flight respawn");
    let slots = ctx.slots.lock().expect("slots");
    assert!(slots[0].pid.is_none(), "the cancelled child is not kept");
    drop(slots);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A line that is not UTF-8 is logged lossily and reading goes on, so the child's pipe never fills up.
#[test]
fn pipe_reader_keeps_reading_past_a_line_that_is_not_utf8() {
    let mut lines = Vec::new();
    for_each_line_lossy(&b"first\n\xff\xfe bad\r\nlast\n"[..], |l| lines.push(l));
    assert_eq!(lines, vec!["first", "\u{fffd}\u{fffd} bad", "last"]);
}

/// `down --clean-files` leaves a directory alone unless the supervisor marked it as its own state directory.
#[test]
fn clean_files_refuses_a_directory_the_supervisor_did_not_mark() {
    let dir = std::env::temp_dir().join(format!("canton-clean-unmarked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join("precious.txt"), b"keep").expect("write");

    let err = cleanup_local_state_files(&dir).expect_err("unmarked dir refused");
    assert!(err.contains(STATE_DIR_MARKER), "{err}");
    assert!(
        dir.join("precious.txt").exists(),
        "an unmarked directory must not be emptied"
    );
    mark_state_dir_if_empty(&dir);
    assert!(
        !dir.join(STATE_DIR_MARKER).exists(),
        "non-empty directory must not be marked retroactively"
    );

    let fresh = std::env::temp_dir().join(format!("canton-clean-fresh-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&fresh);
    std::fs::create_dir_all(&fresh).expect("mkdir fresh");
    mark_state_dir_if_empty(&fresh);
    std::fs::create_dir_all(fresh.join("logs")).expect("mkdir logs");
    std::fs::write(fresh.join("logs/supervisor.log"), b"log").expect("write log");
    cleanup_local_state_files(&fresh).expect("empty dir marked before logs/ is cleanable");
    assert!(std::fs::read_dir(&fresh).expect("readdir").next().is_none());

    let _ = std::fs::remove_dir_all(&fresh);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cleanup_local_state_files_preserves_nothing_local_and_never_touches_external() {
    let dir = std::env::temp_dir().join(format!("canton-clean-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("logs")).expect("mkdir");
    std::fs::write(dir.join("logs/p1.log"), b"hi").expect("write");
    std::fs::write(dir.join("daemon.pids.json"), b"{}").expect("write");
    std::fs::write(dir.join(STATE_DIR_MARKER), b"").expect("write");

    cleanup_local_state_files(&dir).expect("marked dir is cleaned");
    assert!(std::fs::read_dir(&dir).expect("readdir").next().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mark_slot_boot_failed_transitions_bootstrapping_to_backoff_or_failed() {
    let dir = std::env::temp_dir().join(format!("canton-bootfail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let parsed = super::super::manifest::parse_yaml_manifest_str(
        r#"
name: boot-test
state_dir: ./state
services:
  seq1:
    role: sequencer
    ports: ["5018:public"]
    restart: unless-stopped
  med1:
    role: mediator
    ports: ["5017:admin"]
    depends_on: [seq1]
    restart: no
"#,
        &dir,
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
        panic!("expected ModeA");
    };
    spec.state_dir = dir.clone();

    let ctx = test_ctx(spec);

    // Slot 0 (`unless-stopped`): boot failure must enter `BackoffWait`, never stay stuck in `Bootstrapping`.
    mark_slot_boot_failed(&ctx, 0, 0, "sequencer port busy");
    // Negative control: Slot 1 (`restart: no`): boot failure must enter `Failed` with no backoff scheduled.
    mark_slot_boot_failed(&ctx, 1, 0, "connection refused");

    let guard = ctx.slots.lock().expect("lock slots");
    assert_eq!(guard[0].state, NodeLifecycleState::BackoffWait);
    assert!(guard[0].backoff_until_ms.is_some());
    assert_eq!(guard[0].consecutive_failures, 1);

    assert_eq!(guard[1].state, NodeLifecycleState::Failed);
    assert!(guard[1].backoff_until_ms.is_none());
    drop(guard);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn commit_started_slot_ignores_stale_generation_and_stops_orphan() {
    let dir = std::env::temp_dir().join(format!("canton-r13i-commit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let parsed = super::super::manifest::parse_yaml_manifest_str(
        "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
        &dir,
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
        panic!("expected ModeA");
    };
    spec.state_dir = dir.clone();
    let ctx = test_ctx(spec);

    // (a) Superseded start generation: Stop bumped slot.generation to 2 while start_gen was 1.
    {
        let mut slots = ctx.slots.lock().expect("slots");
        slots[0].state = NodeLifecycleState::Stopped;
        slots[0].generation = 2;
    }
    let orphan_child = std::process::Command::new("sleep")
        .arg("15")
        .spawn()
        .expect("spawn orphan sleep");
    let orphan_pid = orphan_child.id();
    let orphan_arc = Arc::new(Mutex::new(Some(orphan_child)));
    let res = super::lifecycle::commit_started_slot(
        &ctx,
        0,
        1,
        (
            orphan_pid,
            Arc::clone(&orphan_arc),
            1,
            "5018:public".into(),
            0,
        ),
    )
    .await;
    assert!(res.is_err(), "stale start_gen must be refused: {res:?}");
    assert!(
        orphan_arc.lock().expect("child lock").is_none(),
        "orphan child handle must be consumed and stopped"
    );
    {
        let slots = ctx.slots.lock().expect("slots");
        assert_eq!(slots[0].state, NodeLifecycleState::Stopped);
        assert!(slots[0].pid.is_none());
    }

    // (b) Positive control: matching generation transitions Bootstrapping -> Online.
    {
        let mut slots = ctx.slots.lock().expect("slots");
        slots[0].state = NodeLifecycleState::Bootstrapping;
        slots[0].generation = 3;
    }
    let live_child = std::process::Command::new("sleep")
        .arg("15")
        .spawn()
        .expect("spawn live sleep");
    let live_pid = live_child.id();
    let live_arc = Arc::new(Mutex::new(Some(live_child)));
    let ok_res = super::lifecycle::commit_started_slot(
        &ctx,
        0,
        3,
        (live_pid, Arc::clone(&live_arc), 3, "5018:public".into(), 0),
    )
    .await;
    assert!(
        ok_res.is_ok(),
        "matching generation must commit Online: {ok_res:?}"
    );
    {
        let mut slots = ctx.slots.lock().expect("slots");
        assert_eq!(slots[0].state, NodeLifecycleState::Online);
        assert_eq!(slots[0].pid, Some(live_pid));
        if let Some(ch_arc) = slots[0].child.take() {
            if let Ok(mut g) = ch_arc.lock() {
                if let Some(mut c) = g.take() {
                    super::super::process::graceful_stop_child(&mut c, Duration::from_secs(1));
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "child process helper for stop_during_restart_leaves_slot_stopped"]
fn delayed_ready_child_helper() {
    std::thread::sleep(Duration::from_millis(350));
    println!("READY seq1");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::thread::sleep(Duration::from_secs(3));
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_during_restart_leaves_slot_stopped() {
    let dir = std::env::temp_dir().join(format!("canton-r13i-stop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let parsed = super::super::manifest::parse_yaml_manifest_str(
        "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
        &dir,
        &std::collections::BTreeMap::new(),
        None,
    )
    .expect("parse yaml");
    let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
        panic!("expected ModeA");
    };
    spec.state_dir = dir.clone();
    spec.services[0].argv = vec![
        "--exact".into(),
        "commands::supervisor::engine::tests::delayed_ready_child_helper".into(),
        "--ignored".into(),
        "--nocapture".into(),
    ];
    spec.services[0].env.clear();
    spec.services[0].ports = super::super::NodePorts::default();
    spec.services[0].readiness_url = None;
    spec.services[0].health_url = None;
    spec.services[0].status_url = None;
    spec.services[0].metrics_url = None;
    spec.services[0].xray_url = None;
    spec.services[0].ready_line_prefix = Some("READY ".into());

    let ctx = test_ctx(spec);
    let start_ctx = Arc::clone(&ctx);
    let start_handle =
        tokio::spawn(async move { super::lifecycle::start_single_slot(&start_ctx, 0).await });

    // Wait until slot enters Bootstrapping and child is actively booting before calling stop
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let is_booting = ctx
            .slots
            .lock()
            .expect("slots")
            .first()
            .is_some_and(|s| s.state == NodeLifecycleState::Bootstrapping);
        if is_booting {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "slot never entered Bootstrapping"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(60)).await;

    super::ops::stop_slots_by_indices(&ctx, &[0], 2).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), start_handle)
        .await
        .expect("start_single_slot must finish promptly");

    let (final_state, final_pid, leaked_child) = {
        let mut slots = ctx.slots.lock().expect("slots");
        (slots[0].state, slots[0].pid, slots[0].child.take())
    };
    if let Some(child_arc) = leaked_child {
        if let Ok(mut g) = child_arc.lock() {
            if let Some(mut c) = g.take() {
                super::super::process::graceful_stop_child(&mut c, Duration::from_secs(1));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        final_state,
        NodeLifecycleState::Stopped,
        "stop issued during restart must not be overwritten with Online"
    );
    assert!(
        final_pid.is_none(),
        "stopped slot must not retain leaked PID {final_pid:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn shadow_verify_tick_preserves_mismatch_forwards_token_and_omits_unknown_gauges() {
    use std::io::{Read, Write};

    let dir = std::env::temp_dir().join(format!("canton-r8-tick-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let tok_file = dir.join("p1.tok");
    std::fs::write(&tok_file, "secret-tok\n").expect("write token");

    let serve_authed = |max_reqs: usize,
                        status: &'static str,
                        body: &'static str|
     -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            for _ in 0..max_reqs {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let ok_auth = head.lines().any(|l| {
                    l.trim()
                        .eq_ignore_ascii_case("Authorization: Bearer secret-tok")
                });
                let (st, b) = if head.starts_with("GET /readyz") {
                    ("200 OK", r#"{"status":"SERVING"}"#)
                } else if ok_auth {
                    (status, body)
                } else {
                    ("401 Unauthorized", "unauthorized")
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {st}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                );
                let _ = stream.flush();
            }
        });
        (port, h)
    };

    let prep_tick = |jvm_status: &'static str, jvm_body: &'static str| {
        let (rust_port, h_rust) = serve_authed(
            2,
            "200 OK",
            r#"{"ledger_end":100,"active_contracts":2,"hosted_parties":2,"loaded_dars":1}"#,
        );
        let (jvm_port, h_jvm) = serve_authed(1, jvm_status, jvm_body);

        let parsed = super::super::manifest::parse_yaml_manifest_str(
            "services:\n  p1:\n    role: participant\n    ports: [\"7575:json-api\"]\n",
            &dir,
            &std::collections::BTreeMap::new(),
            None,
        )
        .expect("parse yaml");
        let super::super::manifest::ParsedYamlManifest::ModeA(mut spec) = parsed else {
            panic!("expected ModeA");
        };
        spec.state_dir = dir.clone();
        spec.shadow_verify = true;
        spec.shadow_jvm_url = Some(format!("http://127.0.0.1:{jvm_port}"));
        spec.services[0].readiness_url = Some(format!("http://127.0.0.1:{rust_port}/readyz"));
        spec.services[0].status_url = Some(format!("http://127.0.0.1:{rust_port}/_telemetry"));
        spec.services[0].xray_url = None;
        spec.services[0].metrics_url = None;
        spec.services[0].token = Some(super::super::TokenSource::File(tok_file.clone()));

        let ctx = test_ctx(spec);
        {
            let mut slots = ctx.slots.lock().expect("slots");
            slots[0].pid = Some(std::process::id());
            slots[0].state = NodeLifecycleState::Online;
        }
        (ctx, h_rust, h_jvm)
    };

    // (a) Mismatch preserved + bearer token forwarded
    let (ctx_a, h_rust_a, h_jvm_a) = prep_tick("200 OK", r#"{"offset":50}"#);
    let _ =
        super::ops::sample_and_poll_tick(&ctx_a, super::super::proc_sampler::OsProcSampler::new())
            .await;
    let _ = (h_rust_a.join(), h_jvm_a.join());
    let sv_a = ctx_a
        .shadow_verify
        .lock()
        .expect("shadow_verify")
        .clone()
        .expect("shadow_verify populated");
    assert_eq!(
        sv_a.verified_tx_total,
        Some(50),
        "must preserve min(rust=100, jvm=50)"
    );
    assert_eq!(
        sv_a.mismatch_total,
        Some(50),
        "must report mismatch abs_diff(100, 50)"
    );
    assert_eq!(sv_a.match_ratio_percent, Some(50.0));

    // (b) JVM 500 -> unknown (None) and Prometheus omits sample lines
    let (ctx_b, h_rust_b, h_jvm_b) = prep_tick("500 Internal Server Error", "oops");
    let _ =
        super::ops::sample_and_poll_tick(&ctx_b, super::super::proc_sampler::OsProcSampler::new())
            .await;
    let _ = (h_rust_b.join(), h_jvm_b.join());
    let sv_b = ctx_b
        .shadow_verify
        .lock()
        .expect("shadow_verify")
        .clone()
        .expect("shadow_verify populated");
    assert_eq!(
        sv_b.verified_tx_total, None,
        "JVM 500 must yield unknown verified_tx_total"
    );
    assert_eq!(
        sv_b.mismatch_total, None,
        "JVM 500 must yield unknown mismatch_total"
    );
    assert_eq!(sv_b.match_ratio_percent, None);
    let prom_b =
        super::super::metrics::render_prometheus_metrics(&ctx_b.build_snapshot(), &BTreeMap::new());
    assert!(
        !prom_b.contains("canton_rs_shadow_verified_tx_total{"),
        "unknown shadow_verify must omit verified gauge sample: {prom_b}"
    );
    assert!(
        !prom_b.contains("canton_rs_shadow_mismatch_total{"),
        "unknown shadow_verify must omit mismatch gauge sample: {prom_b}"
    );

    // (c) Positive control: JVM=100, Rust=100 -> verified=Some(100), mismatch=Some(0), ratio=Some(100.0)
    let (ctx_c, h_rust_c, h_jvm_c) = prep_tick("200 OK", r#"{"offset":100}"#);
    let _ =
        super::ops::sample_and_poll_tick(&ctx_c, super::super::proc_sampler::OsProcSampler::new())
            .await;
    let _ = (h_rust_c.join(), h_jvm_c.join());
    let sv_c = ctx_c
        .shadow_verify
        .lock()
        .expect("shadow_verify")
        .clone()
        .expect("shadow_verify populated");
    assert_eq!(sv_c.verified_tx_total, Some(100));
    assert_eq!(sv_c.mismatch_total, Some(0));
    assert_eq!(sv_c.match_ratio_percent, Some(100.0));

    let _ = std::fs::remove_dir_all(&dir);
}
