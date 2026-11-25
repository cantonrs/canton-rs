//! The dashboard must keep rendering while the daemon, a node, or the archive is slow.

use std::collections::VecDeque;
use std::io::{self, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use ratatui_core::backend::TestBackend;
use ratatui_core::terminal::Terminal;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

use super::super::ipc::{bind_socket, IpcRequest, IpcResponse};
use super::super::{
    ClusterSnapshot, DomainMetrics, NodeLifecycleState, NodePorts, NodeRole, NodeSnapshot,
    ProcResources, QuorumVerdictState, RestartPolicy, XRayTraceEvent,
};
use super::backend::Key;
use super::render::render_dashboard;
use super::state::{
    handle_key, pump_lines, DashboardState, IpcThreadSlot, WorkspaceTab, MAX_TUI_IPC_THREADS,
};

fn participant(http_port: Option<u16>) -> NodeSnapshot {
    NodeSnapshot {
        slot_id: 0,
        role: NodeRole::Participant,
        name: "participant1".into(),
        group: None,
        synchronizer_domain: None,
        host_label: None,
        pid: Some(4242),
        ports: NodePorts {
            http_json: http_port,
            ..Default::default()
        },
        state: NodeLifecycleState::Online,
        restart_policy: RestartPolicy::UnlessStopped,
        restarts_total: 0,
        consecutive_failures: 0,
        uptime_secs: 5,
        stopped_at_unix_ms: None,
        last_exit_reason: None,
        resources: ProcResources::default(),
        history_60s: vec![],
        domain: DomainMetrics::Participant {
            ledger_end_offset: 3,
            active_contracts: 1,
            hosted_parties: 1,
            loaded_dars: 1,
            ready: true,
            ready_reason: "SERVING".into(),
            api_requests_total: 0,
        },
    }
}

fn snapshot(nodes: Vec<NodeSnapshot>) -> ClusterSnapshot {
    ClusterSnapshot {
        stack_name: "slow".into(),
        synchronizer: "sync".into(),
        storage_mode: "memory".into(),
        collected_at_unix_ms: 0,
        total_cpu_percent: 0.0,
        total_rss_bytes: 0,
        last_ping: None,
        shadow_verify: None,
        wiretap_dropped_events: 0,
        scenarios: vec![],
        metrics_port: None,
        metrics_bind: None,
        nodes,
    }
}

/// A daemon socket that answers every request only after `delay`.
struct SlowDaemon {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    state_dir: PathBuf,
}

impl SlowDaemon {
    fn start(tag: &str, delay: Duration, snap: ClusterSnapshot) -> Self {
        let state_dir = std::env::temp_dir().join(format!("crs-tui-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");
        let (listener, cleanup) =
            rt.block_on(async { bind_socket(&state_dir).expect("bind").into_parts() });
        let done = Arc::new(AtomicBool::new(false));
        let done_srv = Arc::clone(&done);
        let thread = std::thread::spawn(move || {
            let _cleanup = cleanup;
            rt.block_on(async move {
                while !done_srv.load(Ordering::Relaxed) {
                    let Ok(Ok((stream, _))) =
                        tokio::time::timeout(Duration::from_millis(40), listener.accept()).await
                    else {
                        continue;
                    };
                    let snap = snap.clone();
                    tokio::spawn(async move {
                        let (r, mut w) = stream.into_split();
                        let mut lines = TokioBufReader::new(r).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            tokio::time::sleep(delay).await;
                            let resp = match serde_json::from_str::<IpcRequest>(&line) {
                                Ok(IpcRequest::TriggerPing) => IpcResponse::Ping {
                                    ok: true,
                                    rtt_ms: 1.5,
                                    detail: "p1 -> p1".into(),
                                },
                                Ok(IpcRequest::GetSnapshot) => IpcResponse::Snapshot {
                                    ok: true,
                                    snapshot: snap.clone(),
                                },
                                _ => IpcResponse::err("unsupported in mock"),
                            };
                            let out = serde_json::to_string(&resp).expect("serialize");
                            let _ = w.write_all(format!("{out}\n").as_bytes()).await;
                        }
                    });
                }
            });
        });
        Self {
            done,
            thread: Some(thread),
            state_dir,
        }
    }

    fn dir(&self) -> &Path {
        &self.state_dir
    }
}

impl Drop for SlowDaemon {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

#[test]
fn ping_returns_to_the_render_loop_before_the_daemon_answers() {
    let daemon = SlowDaemon::start("ping", Duration::from_millis(1500), snapshot(vec![]));
    let mut app = DashboardState::new(daemon.dir().to_path_buf(), snapshot(vec![]));
    let (tx, rx) = mpsc::channel();
    let mut xray_guard = None;

    let started = Instant::now();
    handle_key(daemon.dir(), &mut app, Key::Char('p'), &tx, &mut xray_guard).expect("p");
    let blocked = started.elapsed();
    assert!(
        blocked < Duration::from_millis(500),
        "the key handler blocked the render loop for {blocked:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
            app.apply_event(ev);
        }
        if app
            .status_banner
            .as_ref()
            .is_some_and(|(b, _)| b.starts_with("Ping OK"))
        {
            return;
        }
    }
    panic!(
        "the ping result never reached the dashboard: {:?}",
        app.status_banner
    );
}

#[test]
fn exex_and_cold_tab_does_not_wait_for_a_silent_node() {
    let silent = TcpListener::bind("127.0.0.1:0").expect("bind silent node");
    let port = silent.local_addr().expect("addr").port();
    let state_dir = std::env::temp_dir().join(format!("crs-tui-cold-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let snap = snapshot(vec![participant(Some(port)), participant(Some(port))]);
    let mut app = DashboardState::new(state_dir.clone(), snap);
    let (tx, rx) = mpsc::channel();
    let mut xray_guard = None;

    let started = Instant::now();
    handle_key(&state_dir, &mut app, Key::Char('c'), &tx, &mut xray_guard).expect("c");
    let blocked = started.elapsed();
    assert!(
        blocked < Duration::from_millis(200),
        "opening [c] blocked the render loop for {blocked:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while app.exex_cold_cache.is_none() && Instant::now() < deadline {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100)) {
            app.apply_event(ev);
        }
    }
    let (nodes, cold) = app.exex_cold_cache.as_ref().expect("summary arrives");
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().all(|n| !n.reachable));
    assert_eq!(cold.archive_dir, state_dir.join("cold-archive"));
    drop(silent);
    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn xray_detail_labels_participant_estimates() {
    let mut app = DashboardState::new(PathBuf::from("/nonexistent"), snapshot(vec![]));
    app.push_xray(XRayTraceEvent {
        root_hash: "1220feed".into(),
        started_at_unix_ms: 0,
        submitter_participant: "p1".into(),
        package_id: "pkg".into(),
        template_qualified_name: None,
        daml_eval_us: 10,
        blinded_view_count: 1,
        sealed_envelope_bytes: 256,
        traffic_cost_bytes: 256,
        recipient_member_count: 2,
        bft_block_height: None,
        bft_order_latency_ms: None,
        mediator_verdict: QuorumVerdictState::Approved,
        total_latency_ms: 3.0,
        views: vec![],
    });
    app.active_tab = WorkspaceTab::Xray;
    let mut terminal = Terminal::new(TestBackend::new(160, 40)).expect("terminal");
    terminal
        .draw(|f| render_dashboard(f, &mut app))
        .expect("draw");
    let text: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(
        text.contains("participant estimate"),
        "X-Ray shows digest, envelope and recipients as if Canton measured them"
    );
}

/// Serves scripted chunks, with a read timeout between some of them.
struct ScriptedReader(VecDeque<Option<&'static [u8]>>);

impl Read for ScriptedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(None) => Err(io::Error::new(io::ErrorKind::TimedOut, "slow daemon")),
            Some(Some(chunk)) => {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.0.push_front(Some(&chunk[n..]));
                }
                Ok(n)
            }
        }
    }
}

#[test]
fn a_line_split_by_a_read_timeout_is_delivered_whole() {
    let script: VecDeque<Option<&'static [u8]>> = VecDeque::from([
        Some(&b"{\"event\":\"snap"[..]),
        None,
        Some(&"shot\",\"note\":\"caf\u{e9}".as_bytes()[..18]),
        None,
        Some(&"shot\",\"note\":\"caf\u{e9}\"}\n".as_bytes()[18..]),
        Some(&b"{\"event\":\"next\"}\n"[..]),
    ]);
    let mut reader = BufReader::with_capacity(8, ScriptedReader(script));
    let stop = AtomicBool::new(false);
    let mut lines = Vec::new();
    pump_lines(&mut reader, &stop, |l| lines.push(l.to_string()));
    assert_eq!(
        lines,
        vec![
            "{\"event\":\"snapshot\",\"note\":\"caf\u{e9}\"}\n".to_string(),
            "{\"event\":\"next\"}\n".to_string(),
        ]
    );
}

#[test]
fn tui_ipc_thread_pool_caps_concurrent_spawns_and_recovers_on_drop() {
    let app = DashboardState::new(PathBuf::from("/nonexistent"), snapshot(vec![]));
    let mut held = Vec::new();
    for _ in 0..MAX_TUI_IPC_THREADS {
        let g = IpcThreadSlot::try_acquire(&app.ipc_inflight)
            .expect("slot below MAX_TUI_IPC_THREADS must succeed");
        held.push(g);
    }
    assert_eq!(app.ipc_inflight.load(Ordering::SeqCst), MAX_TUI_IPC_THREADS);
    assert!(
        IpcThreadSlot::try_acquire(&app.ipc_inflight).is_none(),
        "9th concurrent TUI IPC thread must be refused cleanly"
    );

    drop(held.pop());
    let regained = IpcThreadSlot::try_acquire(&app.ipc_inflight)
        .expect("slot must recover immediately once a guard drops");
    assert_eq!(app.ipc_inflight.load(Ordering::SeqCst), MAX_TUI_IPC_THREADS);
    drop(regained);
    drop(held);
    assert_eq!(app.ipc_inflight.load(Ordering::SeqCst), 0);
}

#[test]
fn fetch_initial_snapshot_times_out_within_budget() {
    use std::os::unix::net::UnixListener;

    let dir = std::env::temp_dir().join(format!("canton-tui-fetch-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("daemon.sock");
    let listener = UnixListener::bind(&sock).expect("bind silent sock");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking silent listener");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let srv = std::thread::spawn(move || {
        let mut conns = Vec::new();
        while !stop_srv.load(Ordering::Relaxed) {
            if let Ok((stream, _)) = listener.accept() {
                conns.push(stream);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    let started = Instant::now();
    let err = super::fetch_initial_snapshot(&dir, Duration::from_millis(200))
        .expect_err("silent daemon socket must time out instead of blocking");
    let elapsed = started.elapsed();

    stop.store(true, Ordering::Relaxed);
    let _ = srv.join();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        elapsed < Duration::from_secs(2),
        "fetch_initial_snapshot took {elapsed:?} instead of ~200ms timeout"
    );
    assert!(
        err.contains("timed out"),
        "expected explicit timeout error, got: {err}"
    );
}
