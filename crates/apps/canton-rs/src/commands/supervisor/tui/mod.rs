//! Theme-safe interactive `ratatui` terminal dashboard (`canton-rs daemon top` / `daemon tui`).
//!
//! Layout benchmarks `lazydocker` × `btop` × `k9s`: slim left `[1] Services` navigation sidebar
//! synchronized with a right-hand `[2] Workspace` (`Overview`, `Live Logs`, `Protocol X-Ray`,
//! `Inspect`), zero hardcoded row/selection backgrounds, and CJK-safe cursor resync.

pub mod backend;
pub mod groups;
pub mod render;
pub mod state;
pub mod theme;
pub mod views;

#[cfg(test)]
mod async_tests;

use std::io::{self, IsTerminal};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crossterm::cursor::Show;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use ratatui_core::terminal::Terminal;

use super::ipc::{call_unary_with_timeout, resolve_client_state_dir, IpcRequest, IpcResponse};

use backend::{read_key_timeout, CrosstermBackend, TerminalGuard};
use render::render_dashboard;
use state::{handle_key, DashboardState, UiEvent, XraySubscriptionGuard};

const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn fetch_initial_snapshot(
    state_dir: &Path,
    timeout: Duration,
) -> Result<super::ClusterSnapshot, String> {
    match call_unary_with_timeout(state_dir, &IpcRequest::GetSnapshot, Some(timeout))? {
        IpcResponse::Snapshot { snapshot, .. } => Ok(snapshot),
        _ => Err("unexpected IPC response for get_snapshot".to_string()),
    }
}

/// Runs the interactive `canton-rs daemon top` TUI against `<state_dir>/daemon.sock`.
///
/// Enforces non-TTY defense (`exit 2`) before raw mode and installs a panic hook + RAII guard
/// to guarantee clean terminal restoration.
pub fn run_top(state_dir: &Path) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        eprintln!(
            "canton-rs daemon top requires an interactive TTY; use 'canton-rs daemon ps' instead"
        );
        std::process::exit(2);
    }

    let eff_state_dir = resolve_client_state_dir(state_dir);
    let initial = fetch_initial_snapshot(&eff_state_dir, INITIAL_SNAPSHOT_TIMEOUT)?;

    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        orig_hook(info);
    }));

    let _guard =
        TerminalGuard::enter().map_err(|e| format!("failed to enter raw TUI mode: {e}"))?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("failed to create ratatui Terminal: {e}"))?;
    terminal.clear().map_err(|e| e.to_string())?;

    let (ev_tx, ev_rx) = mpsc::channel::<UiEvent>();
    let stop_all = Arc::new(AtomicBool::new(false));
    state::spawn_snapshot_thread(eff_state_dir.clone(), ev_tx.clone(), Arc::clone(&stop_all));
    state::spawn_log_thread(eff_state_dir.clone(), ev_tx.clone(), Arc::clone(&stop_all));

    let mut xray_guard: Option<XraySubscriptionGuard> = None;
    let mut app = DashboardState::new(eff_state_dir.clone(), initial);

    loop {
        while let Ok(ev) = ev_rx.try_recv() {
            app.apply_event(ev);
        }
        if let Some((_, ts)) = &app.status_banner {
            if ts.elapsed() > Duration::from_secs(4) {
                app.status_banner = None;
            }
        }

        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .map_err(|e| e.to_string())?;

        let Some(key) = read_key_timeout(120) else {
            continue;
        };

        if handle_key(&eff_state_dir, &mut app, key, &ev_tx, &mut xray_guard)? {
            break;
        }
    }

    drop(xray_guard);
    stop_all.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::ipc::{bind_socket, IpcRequest, IpcResponse, StartedNodeInfo};
    use super::super::log_rotate::LogLevel;
    use super::super::{
        BlindedViewQuorum, ClusterSnapshot, DomainMetrics, InformeeVote, NodeInspection,
        NodeLifecycleState, NodePorts, NodeRole, NodeSnapshot, ProcResources, QuorumVerdictState,
        ResourceSample, RestartPolicy, VoteStatus, XRayTraceEvent,
    };
    use super::backend::{decode_key_bytes, Key};
    use super::state::{ConfirmAction, LogLineItem, LogScope, PanelFocus, WorkspaceTab};
    use super::*;
    use ratatui_core::backend::{Backend, TestBackend};
    use ratatui_core::buffer::{Buffer, Cell};
    use ratatui_core::style::{Color, Modifier, Style};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

    fn wait_for_ui<F: Fn(&DashboardState) -> bool>(
        app: &mut DashboardState,
        rx: &mpsc::Receiver<UiEvent>,
        pred: F,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !pred(app) && std::time::Instant::now() < deadline {
            if let Ok(ev) = rx.recv_timeout(Duration::from_millis(50)) {
                app.apply_event(ev);
            }
        }
    }

    fn buf_text(buf: &Buffer) -> String {
        buf.content().iter().map(|c| c.symbol()).collect()
    }

    fn find_row_y(buf: &Buffer, needle: &str) -> Option<u16> {
        let w = buf.area.width;
        let h = buf.area.height;
        for y in 0..h {
            let mut row = String::with_capacity(w as usize);
            for x in 0..w {
                if let Some(cell) = buf.cell((x, y)) {
                    row.push_str(cell.symbol());
                }
            }
            if row.contains(needle) {
                return Some(y);
            }
        }
        None
    }

    fn mk_node(
        slot_id: usize,
        name: &str,
        role: NodeRole,
        state: NodeLifecycleState,
    ) -> NodeSnapshot {
        let pid = if matches!(
            state,
            NodeLifecycleState::Stopped | NodeLifecycleState::Failed
        ) {
            None
        } else {
            Some(1000 + slot_id as u32)
        };
        let domain = match role {
            NodeRole::Sequencer => DomainMetrics::Sequencer {
                head_offset: 12,
                connected_members: 3,
                bft_quorum_peers: Some((4, 4)),
            },
            NodeRole::Mediator => DomainMetrics::Mediator {
                group_id: 0,
                verdicts_approved: 8,
                verdicts_rejected: 0,
                pending_quorums: 0,
            },
            NodeRole::Participant => DomainMetrics::Participant {
                ledger_end_offset: 42,
                active_contracts: 7,
                hosted_parties: 2,
                loaded_dars: 1,
                ready: pid.is_some(),
                ready_reason: "SERVING".into(),
                api_requests_total: 15,
            },
            NodeRole::Splice | NodeRole::Scan => DomainMetrics::Splice {
                open_round: Some(3),
                scan_updates_total: 25,
                ledger_backend_connected: pid.is_some(),
            },
            NodeRole::Pqs => DomainMetrics::Pqs {
                watermark_offset: 42,
                active_contracts: 7,
                connected: pid.is_some(),
            },
        };
        NodeSnapshot {
            slot_id,
            role,
            name: name.to_string(),
            group: None,
            synchronizer_domain: None,
            host_label: None,
            pid,
            ports: NodePorts {
                public: Some(5000 + slot_id as u16),
                ..Default::default()
            },
            state,
            restart_policy: RestartPolicy::UnlessStopped,
            restarts_total: 0,
            consecutive_failures: 0,
            uptime_secs: if pid.is_some() { 120 } else { 0 },
            stopped_at_unix_ms: None,
            last_exit_reason: if state == NodeLifecycleState::Stopped {
                Some("stopped".into())
            } else {
                None
            },
            resources: ProcResources {
                cpu_percent: if pid.is_some() { 1.8 } else { 0.0 },
                rss_bytes: if pid.is_some() { 32 * 1024 * 1024 } else { 0 },
                vms_bytes: 96 * 1024 * 1024,
                thread_count: 6,
                open_fds: 20,
            },
            history_60s: vec![ResourceSample {
                ts_unix_ms: 1_700_000_000_000,
                cpu_percent: 1.8,
                rss_bytes: 32 * 1024 * 1024,
            }],
            domain,
        }
    }

    fn mk_snapshot(nodes: Vec<NodeSnapshot>) -> ClusterSnapshot {
        ClusterSnapshot {
            stack_name: "ux-stack".into(),
            synchronizer: "dev-sync".into(),
            storage_mode: "postgres".into(),
            collected_at_unix_ms: 1_700_000_000_000,
            total_cpu_percent: 3.6,
            total_rss_bytes: 96 * 1024 * 1024,
            last_ping: None,
            shadow_verify: None,
            wiretap_dropped_events: 0,
            scenarios: Vec::new(),
            metrics_port: None,
            metrics_bind: None,
            nodes,
        }
    }

    #[test]
    fn theme_safe_palette_uses_reset_and_reverse_without_hardcoded_row_bg_or_dark_gray() {
        let snap = mk_snapshot(vec![
            mk_node(
                0,
                "sequencer1",
                NodeRole::Sequencer,
                NodeLifecycleState::Online,
            ),
            mk_node(
                1,
                "mediator1",
                NodeRole::Mediator,
                NodeLifecycleState::Stopped,
            ),
            mk_node(
                2,
                "participant1",
                NodeRole::Participant,
                NodeLifecycleState::Bootstrapping,
            ),
            mk_node(
                3,
                "participant2",
                NodeRole::Participant,
                NodeLifecycleState::Degraded,
            ),
            mk_node(4, "scan1", NodeRole::Scan, NodeLifecycleState::BackoffWait),
            mk_node(
                5,
                "splice-app",
                NodeRole::Splice,
                NodeLifecycleState::Failed,
            ),
        ]);
        let mut app = DashboardState::new(PathBuf::from("/tmp/theme-test"), snap);
        let backend = TestBackend::new(130, 34);
        let mut terminal = Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw dashboard");
        let buf = terminal.backend().buffer();
        let text = buf_text(buf);

        assert!(text.contains("canton-rs daemon top"));
        assert!(text.contains("sequencer1"));
        assert!(text.contains("mediator1"));
        assert!(text.contains("Stopped"));
        assert!(text.contains("▶ "));

        // Every cell must keep background Color::Reset (no hardcoded Blue/Gray/DarkGray/Black bg).
        for cell in buf.content() {
            assert_eq!(
                cell.bg,
                Color::Reset,
                "unexpected hardcoded cell background {:?} on glyph {:?}",
                cell.bg,
                cell.symbol()
            );
            if cell.symbol() != " " {
                assert!(
                    !matches!(cell.fg, Color::DarkGray | Color::Black),
                    "unreadable foreground {:?} on glyph {:?}",
                    cell.fg,
                    cell.symbol()
                );
            }
        }

        // Focused selected row ("sequencer1") must have REVERSED | BOLD with fg=Reset across entire row.
        let seq_y = find_row_y(buf, "▶ ● sequencer1")
            .or_else(|| find_row_y(buf, "sequencer1"))
            .expect("sequencer1 row present");
        for check_x in [6u16, 25u16, 38u16] {
            let seq_cell = buf
                .cell((check_x, seq_y))
                .expect("cell in selected sequencer1 row");
            assert!(
                seq_cell.modifier.contains(Modifier::REVERSED)
                    && seq_cell.modifier.contains(Modifier::BOLD),
                "selected service row cell x={check_x} must render with REVERSED | BOLD, got {:?}",
                seq_cell.modifier
            );
            assert_eq!(seq_cell.fg, Color::Reset);
            assert_eq!(seq_cell.bg, Color::Reset);
        }

        // Also verify compact 80x24 terminal layout renders cleanly without panicking.
        let mut small_term = Terminal::new(TestBackend::new(80, 24)).expect("small test terminal");
        small_term
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw 80x24 dashboard");
        let small_text = buf_text(small_term.backend().buffer());
        assert!(small_text.contains("sequencer1"));
        assert!(small_text.contains("mediator1"));

        // Stopped row ("mediator1") must render text in Color::Reset so it never hides on any bg.
        let med_y =
            find_row_y(buf, "mediator1").expect("stopped mediator1 row must remain visible");
        let mut found_med_char = false;
        for x in 1..38 {
            if let Some(cell) = buf.cell((x, med_y)) {
                if cell.symbol() == "m" {
                    assert_eq!(cell.fg, Color::Reset);
                    assert_eq!(cell.bg, Color::Reset);
                    found_med_char = true;
                    break;
                }
            }
        }
        assert!(found_med_char, "mediator1 text cell not found in sidebar");
    }

    #[test]
    fn stop_and_start_over_live_unix_ipc_preserves_service_row_and_updates_context_bar() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");

        let state_dir = std::env::temp_dir().join(format!("crs-tui-ipc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);

        let nodes = Arc::new(Mutex::new(vec![
            mk_node(
                0,
                "sequencer1",
                NodeRole::Sequencer,
                NodeLifecycleState::Online,
            ),
            mk_node(
                1,
                "mediator1",
                NodeRole::Mediator,
                NodeLifecycleState::Online,
            ),
        ]));
        let nodes_srv = Arc::clone(&nodes);

        let (bound_listener, cleanup) = rt.block_on(async {
            bind_socket(&state_dir)
                .expect("bind test unix socket")
                .into_parts()
        });

        let server_done = Arc::new(AtomicBool::new(false));
        let server_done_srv = Arc::clone(&server_done);
        let srv_handle = std::thread::spawn(move || {
            rt.block_on(async move {
                while !server_done_srv.load(Ordering::Relaxed) {
                    let accept_res =
                        tokio::time::timeout(Duration::from_millis(40), bound_listener.accept())
                            .await;
                    let Ok(Ok((stream, _))) = accept_res else {
                        continue;
                    };
                    let (r, mut w) = stream.into_split();
                    let mut lines = TokioBufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let Ok(req) = serde_json::from_str::<IpcRequest>(&line) else {
                            continue;
                        };
                        let resp = match req {
                            IpcRequest::GetSnapshot => {
                                let guard = nodes_srv.lock().expect("nodes lock");
                                IpcResponse::Snapshot {
                                    ok: true,
                                    snapshot: mk_snapshot(guard.clone()),
                                }
                            }
                            IpcRequest::StopNodes { targets } => {
                                let mut guard = nodes_srv.lock().expect("nodes lock");
                                for n in guard.iter_mut() {
                                    if targets.contains(&n.name) {
                                        n.state = NodeLifecycleState::Stopped;
                                        n.pid = None;
                                    }
                                }
                                IpcResponse::StoppedNodes {
                                    ok: true,
                                    stopped: targets,
                                }
                            }
                            IpcRequest::StartNodes { targets } => {
                                let mut guard = nodes_srv.lock().expect("nodes lock");
                                let mut started = Vec::new();
                                for n in guard.iter_mut() {
                                    if targets.contains(&n.name) {
                                        n.state = NodeLifecycleState::Online;
                                        n.pid = Some(2001);
                                        started.push(StartedNodeInfo {
                                            node: n.name.clone(),
                                            pid: 2001,
                                        });
                                    }
                                }
                                IpcResponse::StartedNodes { ok: true, started }
                            }
                            IpcRequest::GetExex => IpcResponse::Exex {
                                ok: true,
                                nodes: Vec::new(),
                            },
                            _ => IpcResponse::err("unsupported in mock".to_string()),
                        };
                        let out = serde_json::to_string(&resp).expect("serialize resp");
                        let _ = w.write_all(format!("{out}\n").as_bytes()).await;
                        let _ = w.flush().await;
                    }
                }
            });
        });

        let initial = mk_snapshot(nodes.lock().expect("nodes lock").clone());
        let mut app = DashboardState::new(state_dir.clone(), initial);
        let (tx, rx) = mpsc::channel();
        let mut xray_guard = None;
        let backend = TestBackend::new(130, 34);
        let mut terminal = Terminal::new(backend).expect("test terminal");

        // Down selects mediator1 (Online -> footer shows Stop mediator1).
        handle_key(&state_dir, &mut app, Key::Down, &tx, &mut xray_guard).expect("down");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw 1");
        assert!(buf_text(terminal.backend().buffer()).contains("Stop mediator1"));

        // Stop mediator1 via 's' -> confirm 'y'.
        handle_key(&state_dir, &mut app, Key::Char('s'), &tx, &mut xray_guard).expect("s stop");
        assert!(matches!(app.confirm_modal, Some(ConfirmAction::Stop(_))));
        handle_key(&state_dir, &mut app, Key::Char('y'), &tx, &mut xray_guard).expect("y confirm");
        wait_for_ui(&mut app, &rx, |a| {
            a.selected_node()
                .is_some_and(|n| n.state == NodeLifecycleState::Stopped)
        });

        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw stopped");
        let stopped_buf = terminal.backend().buffer();
        let stopped_text = buf_text(stopped_buf);
        assert!(stopped_text.contains("mediator1"));
        assert!(stopped_text.contains("Stopped"));
        assert!(stopped_text.contains("Start mediator1"));
        let med_y = find_row_y(stopped_buf, "▶ ■").expect("stopped row keeps ▶ ■ prefix");
        assert!(
            stopped_buf
                .cell((6, med_y))
                .expect("selected cell")
                .modifier
                .contains(Modifier::REVERSED),
            "stopped row must remain highlighted with REVERSED"
        );

        // Press 's' again while Stopped -> starts immediately without modal.
        handle_key(&state_dir, &mut app, Key::Char('s'), &tx, &mut xray_guard).expect("s start");
        assert!(app.confirm_modal.is_none());
        wait_for_ui(&mut app, &rx, |a| {
            a.selected_node()
                .is_some_and(|n| n.state == NodeLifecycleState::Online)
        });
        assert_eq!(
            app.selected_node().expect("node").state,
            NodeLifecycleState::Online
        );

        server_done.store(true, Ordering::SeqCst);
        let _ = srv_handle.join();
        drop(cleanup);
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn workspace_tabs_log_scope_zoom_inspect_and_help_modal_flow() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt");
        let state_dir = std::env::temp_dir().join(format!("crs-tui-tab-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state_dir);

        let (bound_listener, cleanup) = rt.block_on(async {
            bind_socket(&state_dir)
                .expect("bind inspect mock sock")
                .into_parts()
        });
        let server_done = Arc::new(AtomicBool::new(false));
        let server_done_srv = Arc::clone(&server_done);
        let srv_handle = std::thread::spawn(move || {
            rt.block_on(async move {
                while !server_done_srv.load(Ordering::Relaxed) {
                    let accept_res =
                        tokio::time::timeout(Duration::from_millis(40), bound_listener.accept())
                            .await;
                    let Ok(Ok((stream, _))) = accept_res else {
                        continue;
                    };
                    let (r, mut w) = stream.into_split();
                    let mut lines = TokioBufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let Ok(req) = serde_json::from_str::<IpcRequest>(&line) else {
                            continue;
                        };
                        let resp = match req {
                            IpcRequest::Inspect { node } => IpcResponse::Inspection {
                                ok: true,
                                inspection: Box::new(NodeInspection {
                                    role: NodeRole::Sequencer,
                                    name: node,
                                    pid: Some(1000),
                                    state: NodeLifecycleState::Online,
                                    config_path: None,
                                    bootstrap_path: None,
                                    state_dir: "/tmp/mock".into(),
                                    log_file_path: "/tmp/mock/sequencer1.log".into(),
                                    log_file_bytes: 2048,
                                    log_generations: 1,
                                    log_encoder: "text".into(),
                                    port_offset: 0,
                                    sanitized_argv: vec!["canton-rs".into(), "sequencer".into()],
                                    config_applied_count: 3,
                                    config_not_applied_keys: vec![],
                                    storage_summary: "files".into(),
                                    same_identity: false,
                                    official_write: false,
                                    auth_mode: "none".into(),
                                    node_uid: Some("seq::1220abcd".into()),
                                    physical_synchronizer_id: Some("sync::1220".into()),
                                    protocol_version: Some("33".into()),
                                    loaded_dars: vec![],
                                    hosted_parties: vec![],
                                    user_count: None,
                                    ports: NodePorts::default(),
                                    restarts_total: 0,
                                    last_exit_at_unix_ms: None,
                                    last_exit_reason: None,
                                }),
                            },
                            IpcRequest::GetExex => IpcResponse::Exex {
                                ok: true,
                                nodes: Vec::new(),
                            },
                            _ => IpcResponse::err("unsupported in mock".to_string()),
                        };
                        let out = serde_json::to_string(&resp).expect("serialize inspect");
                        let _ = w.write_all(format!("{out}\n").as_bytes()).await;
                        let _ = w.flush().await;
                    }
                }
            });
        });

        let snap = mk_snapshot(vec![
            mk_node(
                0,
                "sequencer1",
                NodeRole::Sequencer,
                NodeLifecycleState::Online,
            ),
            mk_node(
                1,
                "mediator1",
                NodeRole::Mediator,
                NodeLifecycleState::Online,
            ),
        ]);
        let mut app = DashboardState::new(state_dir.clone(), snap);
        app.push_log(LogLineItem {
            node: "sequencer1".into(),
            level: LogLevel::Info,
            line: "SEQ_ONLY_LINE".into(),
        });
        app.push_log(LogLineItem {
            node: "mediator1".into(),
            level: LogLevel::Info,
            line: "MED_ONLY_LINE".into(),
        });

        let (tx, rx) = mpsc::channel();
        let mut xray_guard = None;
        let backend = TestBackend::new(130, 34);
        let mut terminal = Terminal::new(backend).expect("test terminal");

        // Default LogScope::SelectedNode filters to sequencer1 only.
        assert_eq!(app.log_scope, LogScope::SelectedNode);
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw 0");
        let ov0 = buf_text(terminal.backend().buffer());
        assert!(ov0.contains("SEQ_ONLY_LINE"));
        assert!(!ov0.contains("MED_ONLY_LINE"));

        // Press 'a' -> toggles LogScope::AllNodes so both log lines appear.
        handle_key(&state_dir, &mut app, Key::Char('a'), &tx, &mut xray_guard).expect("a");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw all logs");
        let ov_all = buf_text(terminal.backend().buffer());
        assert!(ov_all.contains("SEQ_ONLY_LINE"));
        assert!(ov_all.contains("MED_ONLY_LINE"));

        // Press 'i' -> opens Inspect tab inside Workspace and fetches NodeInspection via IPC.
        handle_key(&state_dir, &mut app, Key::Char('i'), &tx, &mut xray_guard).expect("i");
        assert_eq!(app.active_tab, WorkspaceTab::Inspect);
        wait_for_ui(&mut app, &rx, |a| a.inspect_cache.is_some());
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw inspect");
        assert!(buf_text(terminal.backend().buffer()).contains("seq::1220abcd"));

        // Press 'c' -> opens ExEx & Cold Archive tab with theme-safe Color::Reset cells.
        handle_key(&state_dir, &mut app, Key::Char('c'), &tx, &mut xray_guard).expect("c");
        assert_eq!(app.active_tab, WorkspaceTab::ExexCold);
        wait_for_ui(&mut app, &rx, |a| a.exex_cold_cache.is_some());
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw exex & cold");
        let exex_text = buf_text(terminal.backend().buffer());
        assert!(exex_text.contains("CantonExEx"));
        assert!(exex_text.contains("Cold Archive Tier"));
        for cell in terminal.backend().buffer().content() {
            assert_eq!(cell.bg, Color::Reset);
        }

        // Press 'z' -> zooms Workspace fullscreen (sidebar hidden), then 'z' restores sidebar.
        handle_key(&state_dir, &mut app, Key::Char('z'), &tx, &mut xray_guard).expect("z on");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw zoom");
        assert!(!buf_text(terminal.backend().buffer()).contains("Cluster & Quick Status"));
        handle_key(&state_dir, &mut app, Key::Char('z'), &tx, &mut xray_guard).expect("z off");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw unzoom");
        assert!(buf_text(terminal.backend().buffer()).contains("Cluster & Quick Status"));

        // Press '?' -> opens Help modal; Esc closes Help without quitting.
        handle_key(&state_dir, &mut app, Key::Char('?'), &tx, &mut xray_guard).expect("help");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw help");
        assert!(buf_text(terminal.backend().buffer()).contains("Navigation & Focus"));
        let quit = handle_key(&state_dir, &mut app, Key::Esc, &tx, &mut xray_guard).expect("esc");
        assert!(!quit);
        assert!(!app.help_modal);

        server_done.store(true, Ordering::SeqCst);
        let _ = srv_handle.join();
        drop(cleanup);
        let _ = std::fs::remove_dir_all(&state_dir);
    }

    #[test]
    fn xray_tab_root_hash_reverse_highlight_navigation_modal_and_focus_switch() {
        let snap = mk_snapshot(vec![mk_node(
            0,
            "participant1",
            NodeRole::Participant,
            NodeLifecycleState::Online,
        )]);
        let mut app = DashboardState::new(PathBuf::from("/tmp/xray"), snap);
        app.push_xray(XRayTraceEvent {
            root_hash: "1220aaaa1111aaaa1111".into(),
            started_at_unix_ms: 1_700_000_001_000,
            submitter_participant: "participant1".into(),
            package_id: "pkg1".into(),
            template_qualified_name: Some("Mod:FirstAsset".into()),
            daml_eval_us: 100,
            blinded_view_count: 1,
            sealed_envelope_bytes: 512,
            traffic_cost_bytes: 512,
            recipient_member_count: 2,
            bft_block_height: None,
            bft_order_latency_ms: None,
            mediator_verdict: QuorumVerdictState::Approved,
            total_latency_ms: 5.0,
            views: vec![BlindedViewQuorum {
                view_hash: "0xview1".into(),
                threshold: 1,
                informees: vec![InformeeVote {
                    party_id: "Alice::ns".into(),
                    vote: VoteStatus::Approved { latency_ms: 1.2 },
                }],
            }],
        });
        app.push_xray(XRayTraceEvent {
            root_hash: "1220bbbb2222bbbb2222".into(),
            started_at_unix_ms: 1_700_000_002_000,
            submitter_participant: "participant1".into(),
            package_id: "pkg2".into(),
            template_qualified_name: Some("Mod:SecondAsset".into()),
            daml_eval_us: 250,
            blinded_view_count: 2,
            sealed_envelope_bytes: 1024,
            traffic_cost_bytes: 1024,
            recipient_member_count: 3,
            bft_block_height: Some(42),
            bft_order_latency_ms: Some(1.5),
            mediator_verdict: QuorumVerdictState::Approved,
            total_latency_ms: 9.5,
            views: vec![],
        });

        let (tx, _rx) = mpsc::channel();
        let mut xray_guard = None;
        let backend = TestBackend::new(130, 34);
        let mut terminal = Terminal::new(backend).expect("test terminal");

        // Switch to X-Ray via 'x': Workspace gets focus so newest RootHash is reverse-highlighted.
        handle_key(
            Path::new("/tmp/xray"),
            &mut app,
            Key::Char('x'),
            &tx,
            &mut xray_guard,
        )
        .expect("x key");
        assert_eq!(app.active_tab, WorkspaceTab::Xray);
        assert_eq!(app.focus, PanelFocus::Workspace);

        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw xray 0");
        let b0 = terminal.backend().buffer();
        let t0 = buf_text(b0);
        assert!(t0.contains("RootHash (participant estimate): 1220bbbb2222bbbb2222"));
        assert!(t0.contains("ZERO-KNOWLEDGE BOUNDARY: SEALED"));

        let trace_y = find_row_y(b0, "1220bbbb2222bbbb").expect("newest trace row visible");
        let trace_cell = b0
            .cell((50, trace_y))
            .expect("cell in selected RootHash row");
        assert!(
            trace_cell.modifier.contains(Modifier::REVERSED),
            "focused X-Ray row must be reverse-highlighted"
        );
        assert_eq!(trace_cell.bg, Color::Reset);

        // Unfocused sidebar row uses '▸' without REVERSED.
        let svc_y = find_row_y(b0, "▸ ● participant1").expect("unfocused sidebar marker");
        let svc_cell = b0.cell((6, svc_y)).expect("unfocused sidebar cell");
        assert!(!svc_cell.modifier.contains(Modifier::REVERSED));

        // Press Down -> moves to older trace (1220aaaa1111) and updates 4-Hop detail panel.
        handle_key(
            Path::new("/tmp/xray"),
            &mut app,
            Key::Down,
            &tx,
            &mut xray_guard,
        )
        .expect("down");
        assert_eq!(app.xray_selected_idx, 1);
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw xray 1");
        let t1 = buf_text(terminal.backend().buffer());
        assert!(t1.contains("RootHash (participant estimate): 1220aaaa1111aaaa1111"));
        assert!(t1.contains("Alice::ns"));

        // Enter opens full X-Ray trace modal; Esc closes it; Tab returns focus to Services.
        handle_key(
            Path::new("/tmp/xray"),
            &mut app,
            Key::Enter,
            &tx,
            &mut xray_guard,
        )
        .expect("enter");
        assert!(app.xray_modal.is_some());
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw modal");
        assert!(buf_text(terminal.backend().buffer()).contains("Protocol X-Ray Trace Detail"));

        handle_key(
            Path::new("/tmp/xray"),
            &mut app,
            Key::Esc,
            &tx,
            &mut xray_guard,
        )
        .expect("esc");
        assert!(app.xray_modal.is_none());
        handle_key(
            Path::new("/tmp/xray"),
            &mut app,
            Key::Tab,
            &tx,
            &mut xray_guard,
        )
        .expect("tab");
        assert_eq!(app.focus, PanelFocus::Services);

        drop(xray_guard);
    }

    #[test]
    fn crossterm_backend_emits_reverse_sgr_and_unicode_cursor_resync() {
        let mut out: Vec<u8> = Vec::new();
        {
            let mut backend = CrosstermBackend::new(&mut out);
            let mut c0 = Cell::new("●");
            c0.set_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED));
            let c1 = Cell::new("A");
            backend
                .draw([(0u16, 0u16, &c0), (1u16, 0u16, &c1)].into_iter())
                .expect("draw cells");
            backend.flush().expect("flush");
        }
        let ansi = String::from_utf8_lossy(&out);
        assert!(ansi.contains("\x1b[7m"), "missing ANSI Reverse in {ansi:?}");
        assert!(ansi.contains("\x1b[1m"), "missing ANSI Bold in {ansi:?}");
        assert!(
            !ansi.contains("\x1b[48;5;4m"),
            "must not emit hardcoded DarkBlue bg: {ansi:?}"
        );
        // After non-ASCII '●' at (0,0), backend must emit MoveTo(1,0) == CSI 1;2H before 'A'.
        assert!(
            ansi.contains("\x1b[1;2H"),
            "missing MoveTo cursor resync after Unicode glyph in {ansi:?}"
        );

        assert_eq!(decode_key_bytes(b"\x1b[5~"), Some(Key::PageUp));
        assert_eq!(decode_key_bytes(b"\x1b[6~"), Some(Key::PageDown));
        assert_eq!(decode_key_bytes(b"\x1b[H"), Some(Key::Home));
        assert_eq!(decode_key_bytes(b"\x1b[F"), Some(Key::End));
        assert_eq!(decode_key_bytes(b"\x1b[Z"), Some(Key::BackTab));
    }

    #[test]
    fn collapsible_group_tree_bulk_chaos_and_scenario_lab_modal_preserve_theme_safety() {
        let mut n0 = mk_node(
            0,
            "seq-core",
            NodeRole::Sequencer,
            NodeLifecycleState::Online,
        );
        n0.group = Some("sync-core".into());
        n0.synchronizer_domain = Some("krw-sync".into());
        let mut n1 = mk_node(
            1,
            "med-core",
            NodeRole::Mediator,
            NodeLifecycleState::Online,
        );
        n1.group = Some("sync-core".into());
        n1.synchronizer_domain = Some("krw-sync".into());
        let mut n2 = mk_node(
            2,
            "p-bank-a",
            NodeRole::Participant,
            NodeLifecycleState::Online,
        );
        n2.group = Some("bank-a".into());
        n2.synchronizer_domain = Some("krw-sync".into());
        let mut n3 = mk_node(
            3,
            "p-sec-b",
            NodeRole::Participant,
            NodeLifecycleState::Online,
        );
        n3.group = Some("sec-b".into());
        n3.synchronizer_domain = Some("usd-sync".into());

        let snap = mk_snapshot(vec![n0, n1, n2, n3]);
        let sd = PathBuf::from("/tmp/crs-group-tree-test");
        let mut app = DashboardState::new(sd.clone(), snap);
        assert_eq!(app.group_by, groups::GroupByMode::Group);

        let mut terminal = Terminal::new(TestBackend::new(132, 34)).expect("test terminal");
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw grouped dashboard");
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("[sync-core]"));
        assert!(text.contains("2/2 Up"));
        assert!(text.contains("[bank-a]"));
        assert!(text.contains("p-bank-a"));

        let (ev_tx, _ev_rx) = mpsc::channel();
        let mut xray_guard = None;

        // Pressing Space on `[sync-core]` folds its children (`seq-core` hidden from sidebar, shown in Group Overview summary).
        handle_key(&sd, &mut app, Key::Char(' '), &ev_tx, &mut xray_guard).expect("fold");
        assert!(
            !app.sidebar_entries()
                .iter()
                .any(|e| matches!(e, groups::SidebarEntry::Service { node_idx: 0, .. })),
            "folded group must omit seq-core from sidebar entries"
        );
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw folded");
        let folded_text = buf_text(terminal.backend().buffer());
        assert!(folded_text.contains("[sync-core]"));
        assert!(folded_text.contains("Collapsed: Yes"));
        assert!(folded_text.contains("p-bank-a"));

        // Pressing `s` on a group header opens bulk `@sync-core` Stop confirmation!
        handle_key(&sd, &mut app, Key::Char('s'), &ev_tx, &mut xray_guard).expect("bulk stop");
        assert!(matches!(
            &app.confirm_modal,
            Some(ConfirmAction::Stop(sel)) if sel == "@sync-core"
        ));
        handle_key(&sd, &mut app, Key::Esc, &ev_tx, &mut xray_guard).expect("cancel modal");
        assert!(app.confirm_modal.is_none());

        // Pressing `g` cycles Group-By to `SyncDomain` (`[krw-sync]`, `[usd-sync]`).
        handle_key(&sd, &mut app, Key::Char('g'), &ev_tx, &mut xray_guard).expect("cycle group");
        assert_eq!(app.group_by, groups::GroupByMode::Synchronizer);
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw sync domain");
        let dom_text = buf_text(terminal.backend().buffer());
        assert!(dom_text.contains("[krw-sync]"));
        assert!(dom_text.contains("[usd-sync]"));

        // Pressing `t` opens the Scenario & Load Lab modal with built-in privacy audit scenario
        // while keeping 100% Color::Reset cell backgrounds.
        handle_key(&sd, &mut app, Key::Char('t'), &ev_tx, &mut xray_guard).expect("open lab");
        assert!(app.scenario_modal.open);
        terminal
            .draw(|f| render_dashboard(f, &mut app))
            .expect("draw scenario modal");
        let lab_buf = terminal.backend().buffer();
        let lab_text = buf_text(lab_buf);
        assert!(lab_text.contains("Scenario & Load Lab"));
        assert!(lab_text.contains("privacy-isolation-audit"));
        for cell in lab_buf.content() {
            assert_eq!(cell.bg, Color::Reset);
        }
    }
}
