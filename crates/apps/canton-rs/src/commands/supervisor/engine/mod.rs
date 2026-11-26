//! Built-in supervisor runtime engine: permanent slot registry, dependency-ordered startup,
//! instant child exit monitoring, exponential backoff, 1-second snapshot loop, IPC dispatch,
//! and reverse-order graceful shutdown (`daemon.pids.json` + `SizeRotatingWriter`).

mod ipc_server;
mod lifecycle;
mod ops;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};

use self::ipc_server::handle_ipc_client;
use self::lifecycle::{
    handle_unexpected_or_expected_exit, process_backoff_respawns, start_all_initial_slots,
};
pub(crate) use self::ops::mark_state_dir_if_empty;
use self::ops::{run_ping_for_ctx, sample_and_poll_tick, shutdown_all_slots};
use super::ipc::{bind_socket, socket_path, DownProgressEvent};
use super::log_rotate::{LogHub, LogLevel};
use super::metrics::{spawn_metrics_server, ExporterState};
use super::proc_sampler::OsProcSampler;
use super::process::{cleanup_stale_pids, current_exe_path, make_pid_entry, PidEntry, PidManifest};
use super::wiretap::WiretapHub;
use super::{
    now_unix_ms, ClusterSnapshot, DaemonServiceSpec, DaemonSpec, DomainMetrics, NodeLifecycleState,
    NodeRole, NodeSnapshot, PingStatus, ProcResources, ResourceSample, ShadowVerifySummary,
};

pub(super) const MAX_HISTORY_SAMPLES: usize = 300;
pub(super) const SNAPSHOT_BROADCAST_CAP: usize = 32;
pub const READY_HANDSHAKE_FILE: &str = "daemon.ready.json";

/// Handshake payload written by `--daemon-supervisor-worker` for the `-d` spawning CLI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerReadyAck {
    pub ok: bool,
    pub stack_name: String,
    pub synchronizer: String,
    pub error: Option<String>,
    pub nodes: Vec<WorkerReadyNode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerReadyNode {
    pub slot_id: usize,
    pub name: String,
    pub role: NodeRole,
    pub summary: String,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug)]
pub(super) struct ChildExitNotice {
    pub(super) slot_id: usize,
    pub(super) generation: u64,
    pub(super) exit_desc: String,
    pub(super) exit_clean: bool,
}

pub(super) struct SlotRuntime {
    pub(super) spec: DaemonServiceSpec,
    pub(super) generation: u64,
    pub(super) pid: Option<u32>,
    pub(super) child: Option<Arc<Mutex<Option<Child>>>>,
    pub(super) state: NodeLifecycleState,
    pub(super) auto_restart_paused: bool,
    pub(super) stopping_intentionally: bool,
    pub(super) restarts_total: u64,
    pub(super) consecutive_failures: u32,
    pub(super) backoff_until_ms: Option<u64>,
    pub(super) pid_started_at: Option<Instant>,
    /// Unix second the current child was forked; the PID manifest keeps it so orphan cleanup can match the process later.
    pub(super) pid_started_unix: Option<u64>,
    pub(super) online_since: Option<Instant>,
    pub(super) stopped_at_unix_ms: Option<u64>,
    pub(super) last_exit_at_unix_ms: Option<u64>,
    pub(super) last_exit_reason: Option<String>,
    pub(super) resources: ProcResources,
    pub(super) history: VecDeque<ResourceSample>,
    pub(super) domain: DomainMetrics,
    pub(super) last_xray_ms: u64,
}

impl SlotRuntime {
    pub(super) fn new(spec: DaemonServiceSpec) -> Self {
        let domain = default_domain_for_role(spec.role);
        Self {
            spec,
            generation: 0,
            pid: None,
            child: None,
            state: NodeLifecycleState::Bootstrapping,
            auto_restart_paused: false,
            stopping_intentionally: false,
            restarts_total: 0,
            consecutive_failures: 0,
            backoff_until_ms: None,
            pid_started_at: None,
            pid_started_unix: None,
            online_since: None,
            stopped_at_unix_ms: None,
            last_exit_at_unix_ms: None,
            last_exit_reason: None,
            resources: ProcResources::default(),
            history: VecDeque::with_capacity(MAX_HISTORY_SAMPLES),
            domain,
            last_xray_ms: 0,
        }
    }

    pub(super) fn uptime_secs(&self) -> u64 {
        match (self.pid, self.pid_started_at) {
            (Some(_), Some(t)) => t.elapsed().as_secs(),
            _ => 0,
        }
    }

    pub(super) fn snapshot(&self) -> NodeSnapshot {
        let history_start = self.history.len().saturating_sub(60);
        NodeSnapshot {
            slot_id: self.spec.slot_id,
            role: self.spec.role,
            name: self.spec.name.clone(),
            group: self.spec.group.clone(),
            synchronizer_domain: self.spec.synchronizer_domain.clone(),
            host_label: None,
            pid: self.pid,
            ports: self.spec.ports.clone(),
            state: self.state,
            restart_policy: self.spec.restart,
            restarts_total: self.restarts_total,
            consecutive_failures: self.consecutive_failures,
            uptime_secs: self.uptime_secs(),
            stopped_at_unix_ms: self.stopped_at_unix_ms,
            last_exit_reason: self.last_exit_reason.clone(),
            resources: self.resources,
            history_60s: self.history.iter().skip(history_start).cloned().collect(),
            domain: self.domain.clone(),
        }
    }
}

fn default_domain_for_role(role: NodeRole) -> DomainMetrics {
    match role {
        NodeRole::Sequencer => DomainMetrics::Sequencer {
            head_offset: 0,
            connected_members: 0,
            bft_quorum_peers: None,
        },
        NodeRole::Mediator => DomainMetrics::Mediator {
            group_id: 0,
            verdicts_approved: 0,
            verdicts_rejected: 0,
            pending_quorums: 0,
        },
        NodeRole::Participant => DomainMetrics::Participant {
            ledger_end_offset: 0,
            active_contracts: 0,
            hosted_parties: 0,
            loaded_dars: 0,
            ready: false,
            ready_reason: "bootstrapping".to_string(),
            api_requests_total: 0,
        },
        NodeRole::Splice | NodeRole::Scan => DomainMetrics::Splice {
            open_round: None,
            scan_updates_total: 0,
            ledger_backend_connected: false,
        },
        NodeRole::Pqs => DomainMetrics::Pqs {
            watermark_offset: 0,
            active_contracts: 0,
            connected: false,
        },
    }
}

/// Computes exponential backoff duration with deterministic ±10% jitter:
/// `1s -> 2s -> 4s -> 8s -> 16s -> capped 30s`.
pub fn compute_backoff_ms(consecutive_failures: u32, slot_id: usize) -> u64 {
    let shift = consecutive_failures.saturating_sub(1).min(5);
    let base_ms = 1000u64.saturating_mul(1u64 << shift).min(30_000);
    // Deterministic pseudo-jitter in [-10%, +10%] derived from slot_id + wall millis.
    let salt = ((now_unix_ms() ^ (slot_id as u64 * 7919)) % 21) as i64 - 10;
    let delta = ((base_ms as i64) * salt) / 100;
    (base_ms as i64 + delta).max(200) as u64
}

pub(super) struct ShutdownSignal {
    pub(super) timeout_secs: u64,
    pub(super) clean_files: bool,
    pub(super) progress_tx: Option<mpsc::UnboundedSender<DownProgressEvent>>,
    pub(super) flush_done_rx: Option<tokio::sync::oneshot::Receiver<()>>,
}

/// Live coordinator shared between the supervisor main loop and IPC client handlers.
pub struct EngineContext {
    pub(super) spec: DaemonSpec,
    pub(super) exe_path: PathBuf,
    pub(super) storage_mode: String,
    pub(super) slots: Mutex<Vec<SlotRuntime>>,
    pub(super) booting_pids: Mutex<BTreeMap<usize, PidEntry>>,
    pub(super) log_hub: LogHub,
    pub(super) wiretap: WiretapHub,
    pub(super) exporter: ExporterState,
    pub(super) last_ping: Mutex<Option<PingStatus>>,
    pub(super) shadow_verify: Mutex<Option<ShadowVerifySummary>>,
    pub(super) remote_nodes_cache: RwLock<Vec<NodeSnapshot>>,
    pub(super) latest_snapshot: RwLock<Option<ClusterSnapshot>>,
    pub(super) snapshot_tx: broadcast::Sender<ClusterSnapshot>,
    pub(super) exit_tx: mpsc::UnboundedSender<ChildExitNotice>,
    pub(super) shutting_down: AtomicBool,
    pub(super) shutdown_tx: watch::Sender<bool>,
    pub(super) shutdown_opts: Mutex<Option<ShutdownSignal>>,
}

impl EngineContext {
    pub(super) fn sync_pid_manifest(&self) {
        let mut entries = Vec::new();
        let mut seen_slots = Vec::new();
        if let Ok(slots) = self.slots.lock() {
            for s in slots.iter() {
                if let Some(pid) = s.pid {
                    let mut entry = make_pid_entry(
                        s.spec.slot_id,
                        s.spec.role.as_str(),
                        &s.spec.name,
                        pid,
                        &self.exe_path,
                    );
                    if let Some(started) = s.pid_started_unix {
                        entry.started_at_unix = started;
                    }
                    seen_slots.push(s.spec.slot_id);
                    entries.push(entry);
                }
            }
        }
        if let Ok(booting) = self.booting_pids.lock() {
            for (&slot_id, entry) in booting.iter() {
                if !seen_slots.contains(&slot_id) {
                    entries.push(entry.clone());
                }
            }
        }
        let manifest = PidManifest { entries };
        let _ = manifest.save_atomic(&self.spec.state_dir);
    }

    pub(super) fn build_snapshot(&self) -> ClusterSnapshot {
        let mut nodes: Vec<NodeSnapshot> = self
            .slots
            .lock()
            .map(|slots| slots.iter().map(SlotRuntime::snapshot).collect())
            .unwrap_or_default();
        if let Ok(remote) = self.remote_nodes_cache.read() {
            nodes.extend(remote.iter().cloned());
        }
        let total_cpu_percent = nodes.iter().map(|n| n.resources.cpu_percent).sum();
        let total_rss_bytes = nodes.iter().map(|n| n.resources.rss_bytes).sum();
        let last_ping = self.last_ping.lock().ok().and_then(|g| g.clone());
        let shadow_verify = self.shadow_verify.lock().ok().and_then(|g| g.clone());

        ClusterSnapshot {
            stack_name: self.spec.name.clone(),
            synchronizer: self.spec.synchronizer.clone(),
            storage_mode: self.storage_mode.clone(),
            collected_at_unix_ms: now_unix_ms(),
            total_cpu_percent,
            total_rss_bytes,
            last_ping,
            shadow_verify,
            wiretap_dropped_events: self.wiretap.dropped_total(),
            scenarios: self.spec.scenarios.clone(),
            metrics_port: self.spec.metrics_port,
            metrics_bind: Some(self.spec.metrics_bind.clone()),
            nodes,
        }
    }

    pub(super) fn update_and_broadcast_snapshot(&self) {
        let snap = self.build_snapshot();
        if let Ok(mut g) = self.latest_snapshot.write() {
            *g = Some(snap.clone());
        }
        if let Ok(mut g) = self.exporter.snapshot.write() {
            *g = Some(snap.clone());
        }
        let _ = self.snapshot_tx.send(snap);
    }

    /// Resolves user target tokens (service name, `@group` / `group:<name>` / `sync:<domain>` /
    /// `role:<role>` group selector, slot ID integer, or OS PID) to slot indices.
    pub(super) fn resolve_target_indices(&self, targets: &[String]) -> Result<Vec<usize>, String> {
        let slots = self
            .slots
            .lock()
            .map_err(|_| "supervisor slot registry poisoned".to_string())?;
        if targets.is_empty() || (targets.len() == 1 && targets[0] == "all") {
            return Ok((0..slots.len()).collect());
        }
        let mut indices = Vec::new();
        for t in targets {
            if let Some(grp) = t
                .strip_prefix('@')
                .or_else(|| t.strip_prefix("group:"))
                .or_else(|| t.strip_prefix("cell:"))
            {
                let mut matched = false;
                for (pos, s) in slots.iter().enumerate() {
                    let eff_grp = s.spec.group.as_deref().unwrap_or("default");
                    if eff_grp == grp {
                        matched = true;
                        if !indices.contains(&pos) {
                            indices.push(pos);
                        }
                    }
                }
                if matched {
                    continue;
                }
                return Err(format!("unknown group/cell '{grp}'"));
            }
            if let Some(sync_dom) = t.strip_prefix("sync:") {
                let mut matched = false;
                for (pos, s) in slots.iter().enumerate() {
                    let eff_sync = s
                        .spec
                        .synchronizer_domain
                        .as_deref()
                        .unwrap_or(&self.spec.synchronizer);
                    if eff_sync == sync_dom {
                        matched = true;
                        if !indices.contains(&pos) {
                            indices.push(pos);
                        }
                    }
                }
                if matched {
                    continue;
                }
                return Err(format!("unknown synchronizer domain '{sync_dom}'"));
            }
            if let Some(role_name) = t.strip_prefix("role:") {
                let mut matched = false;
                for (pos, s) in slots.iter().enumerate() {
                    if s.spec.role.as_str() == role_name {
                        matched = true;
                        if !indices.contains(&pos) {
                            indices.push(pos);
                        }
                    }
                }
                if matched {
                    continue;
                }
                return Err(format!("unknown role '{role_name}'"));
            }
            if let Some(pos) = slots.iter().position(|s| s.spec.name == *t) {
                if !indices.contains(&pos) {
                    indices.push(pos);
                }
                continue;
            }
            if let Ok(num) = t.parse::<u32>() {
                if let Some(pos) = slots
                    .iter()
                    .position(|s| s.spec.slot_id == num as usize || s.pid == Some(num))
                {
                    if !indices.contains(&pos) {
                        indices.push(pos);
                    }
                    continue;
                }
            }
            return Err(format!("unknown service, @group, slot ID, or PID '{t}'"));
        }
        Ok(indices)
    }
}

/// Runs the supervisor engine until interrupted (`SIGINT`/`SIGTERM`) or `daemon down`.
pub fn run_supervisor(mut spec: DaemonSpec, ready_ack_mode: bool) -> Result<(), String> {
    std::fs::create_dir_all(&spec.state_dir)
        .map_err(|e| format!("cannot create state_dir {}: {e}", spec.state_dir.display()))?;
    mark_state_dir_if_empty(&spec.state_dir);
    super::topology::materialize_declarative_bft_genesis(&mut spec)?;
    let exe_path = current_exe_path()?;

    // Clean up any leftover orphans left by an earlier SIGKILL crash using PID+exe identity check.
    let stale = cleanup_stale_pids(&spec.state_dir, &exe_path, Duration::from_secs(3));
    if !stale.is_empty() && !spec.foreground_legacy_banner {
        eprintln!(
            "Cleaned up {} orphaned canton-rs process(es) from prior run: {stale:?}",
            stale.len()
        );
    }

    let storage_mode = classify_storage_mode(&spec.services);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build supervisor tokio runtime: {e}"))?;

    runtime.block_on(async move {
        let (exit_tx, mut exit_rx) = mpsc::unbounded_channel::<ChildExitNotice>();
        let (snapshot_tx, _) = broadcast::channel::<ClusterSnapshot>(SNAPSHOT_BROADCAST_CAP);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let wiretap = WiretapHub::new(spec.trace_rate_limit_per_sec);
        let log_hub = LogHub::with_capacity(spec.logging.ring_buffer_lines);

        let slots: Vec<SlotRuntime> = spec
            .services
            .iter()
            .cloned()
            .map(SlotRuntime::new)
            .collect();
        let ctx = Arc::new(EngineContext {
            spec: spec.clone(),
            exe_path,
            storage_mode,
            slots: Mutex::new(slots),
            booting_pids: Mutex::new(BTreeMap::new()),
            log_hub,
            wiretap,
            exporter: ExporterState::default(),
            last_ping: Mutex::new(None),
            shadow_verify: Mutex::new(None),
            remote_nodes_cache: RwLock::new(Vec::new()),
            latest_snapshot: RwLock::new(None),
            snapshot_tx,
            exit_tx,
            shutting_down: AtomicBool::new(false),
            shutdown_tx: shutdown_tx.clone(),
            shutdown_opts: Mutex::new(None),
        });

        // Start optional supervisor Prometheus /metrics server (`--metrics-port`).
        let metrics_shutdown = Arc::new(AtomicBool::new(false));
        let metrics_handle = if let Some(mport) = spec.metrics_port {
            Some(spawn_metrics_server(
                &spec.metrics_bind,
                mport,
                ctx.exporter.clone(),
                Arc::clone(&metrics_shutdown),
            )?)
        } else {
            None
        };

        // Bind `<state_dir>/daemon.sock` (0600) before worker ready ack so CLI/TUI/console attach at once.
        let (ipc_listener, ipc_cleanup) = bind_socket(&spec.state_dir)
            .map_err(|e| {
                format!(
                    "cannot bind IPC socket {}: {e}",
                    socket_path(&spec.state_dir).display()
                )
            })?
            .into_parts();

        let ipc_ctx = Arc::clone(&ctx);
        let mut ipc_stop_rx = shutdown_rx.clone();
        let ipc_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = ipc_stop_rx.wait_for(|&stop| stop) => break,
                    accept_res = ipc_listener.accept() => {
                        match accept_res {
                            Ok((stream, _)) => {
                                let conn_ctx = Arc::clone(&ipc_ctx);
                                tokio::spawn(async move {
                                    handle_ipc_client(conn_ctx, stream).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        let mut term_sig =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| e.to_string())?;
        let mut int_sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|e| e.to_string())?;

        // Dependency-ordered startup of all initial slots (interruptible on SIGTERM/SIGINT).
        let mut ready_nodes = Vec::with_capacity(spec.services.len());
        let startup_result = tokio::select! {
            biased;
            _ = int_sig.recv() => {
                ctx.shutting_down.store(true, Ordering::SeqCst);
                shutdown_tx.send_replace(true);
                Err("supervisor received SIGINT during startup".to_string())
            }
            _ = term_sig.recv() => {
                ctx.shutting_down.store(true, Ordering::SeqCst);
                shutdown_tx.send_replace(true);
                Err("supervisor received SIGTERM during startup".to_string())
            }
            res = start_all_initial_slots(&ctx, &mut ready_nodes) => res,
        };

        if let Err(err) = startup_result {
            // [CANTON-NOTE: INVARIANT] Roll back every already-started upstream slot (e.g. sequencer1,
            // mediator1), close IPC and metrics listeners, and unlink `daemon.sock` BEFORE writing the
            // failure `WorkerReadyAck` so detached `daemon up -d` never returns while stray nodes live (M-001).
            ctx.shutting_down.store(true, Ordering::SeqCst);
            shutdown_tx.send_replace(true);
            shutdown_all_slots(&ctx, spec.shutdown_timeout_secs, false, None).await;
            metrics_shutdown.store(true, Ordering::SeqCst);
            let _ = ipc_task.await;
            drop(ipc_cleanup);
            if let Some(h) = metrics_handle {
                let _ = h.join();
            }
            if ready_ack_mode {
                write_ready_ack(
                    &spec.state_dir,
                    &WorkerReadyAck {
                        ok: false,
                        stack_name: spec.name.clone(),
                        synchronizer: spec.synchronizer.clone(),
                        error: Some(err.clone()),
                        nodes: ready_nodes,
                    },
                );
            }
            return Err(err);
        }

        // Perform initial bootstrap ping check if configured.
        if !spec.ping_participants.is_empty() {
            let ctx_ping = Arc::clone(&ctx);
            let ping = tokio::task::spawn_blocking(move || run_ping_for_ctx(&ctx_ping))
                .await
                .map_err(|e| e.to_string())?;
            if !ping.ok && spec.foreground_legacy_banner {
                shutdown_all_slots(&ctx, spec.shutdown_timeout_secs, false, None).await;
                shutdown_tx.send_replace(true);
                metrics_shutdown.store(true, Ordering::SeqCst);
                let _ = ipc_task.await;
                if let Some(h) = metrics_handle {
                    let _ = h.join();
                }
                return Err(format!("bootstrap health.ping failed: {}", ping.detail));
            }
            if ping.ok && spec.foreground_legacy_banner {
                ledger_json_api::canton_log::emit(
                    parse_log_encoder(&spec.log_encoder),
                    "INFO",
                    "canton-rs.daemon",
                    "ping",
                    &format!(" Ping succeeded in {:.0} ms ({})", ping.rtt_ms, ping.detail),
                );
            }
            if let Ok(mut lp) = ctx.last_ping.lock() {
                *lp = Some(ping);
            }
        }

        ctx.update_and_broadcast_snapshot();

        if spec.observability {
            if let Some(mport) = spec.metrics_port {
                let (shared_root, inst_name) = super::observability::resolve_instance_target_scope(
                    &spec.state_dir,
                    &spec.name,
                );
                let scrape_addr =
                    super::observability::metrics_scrape_address(&spec.metrics_bind, mport);
                if let Err(err) = super::observability::write_prometheus_targets(
                    &spec.state_dir,
                    shared_root.as_deref(),
                    &inst_name,
                    &spec.synchronizer,
                    &scrape_addr,
                ) {
                    ctx.shutting_down.store(true, Ordering::SeqCst);
                    shutdown_tx.send_replace(true);
                    shutdown_all_slots(&ctx, spec.shutdown_timeout_secs, false, None).await;
                    metrics_shutdown.store(true, Ordering::SeqCst);
                    let _ = ipc_task.await;
                    drop(ipc_cleanup);
                    if let Some(h) = metrics_handle {
                        let _ = h.join();
                    }
                    if ready_ack_mode {
                        write_ready_ack(
                            &spec.state_dir,
                            &WorkerReadyAck {
                                ok: false,
                                stack_name: spec.name.clone(),
                                synchronizer: spec.synchronizer.clone(),
                                error: Some(err.clone()),
                                nodes: ready_nodes,
                            },
                        );
                    }
                    return Err(err);
                }
            }
        }

        if ready_ack_mode {
            write_ready_ack(
                &spec.state_dir,
                &WorkerReadyAck {
                    ok: true,
                    stack_name: spec.name.clone(),
                    synchronizer: spec.synchronizer.clone(),
                    error: None,
                    nodes: ready_nodes,
                },
            );
        } else if spec.foreground_legacy_banner {
            // Preserve exact legacy banner expected by existing scripts (`verify-daemon-persistence.sh`, etc.).
            let count = spec.services.len();
            let role_names: Vec<String> = spec
                .services
                .iter()
                .map(|s| format!("{} {}", s.role.as_str(), s.name))
                .collect();
            ledger_json_api::canton_log::emit(
                parse_log_encoder(&spec.log_encoder),
                "INFO",
                "canton-rs.daemon",
                "",
                &format!(
                    "READY canton-rs daemon: synchronizer {}, {} process(es)",
                    spec.synchronizer, count
                ),
            );
            ledger_json_api::canton_log::emit(
                parse_log_encoder(&spec.log_encoder),
                "INFO",
                "canton-rs.daemon",
                "",
                &format!(" Processes: {}", role_names.join(", ")),
            );
        }

        // Main supervisor monitoring loop (1s cadence + instant child exit + signal/down handling).
        let mut sampler = OsProcSampler::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut sup_stop_rx = shutdown_rx;
        let mut respawns = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = sup_stop_rx.wait_for(|&stop| stop) => {
                    break;
                }
                _ = int_sig.recv() => {
                    ctx.shutting_down.store(true, Ordering::SeqCst);
                    shutdown_tx.send_replace(true);
                    break;
                }
                _ = term_sig.recv() => {
                    ctx.shutting_down.store(true, Ordering::SeqCst);
                    shutdown_tx.send_replace(true);
                    break;
                }
                Some(notice) = exit_rx.recv() => {
                    handle_unexpected_or_expected_exit(&ctx, notice, &mut sampler);
                    ctx.update_and_broadcast_snapshot();
                }
                Some(_) = respawns.join_next(), if !respawns.is_empty() => {}
                _ = tick.tick() => {
                    process_backoff_respawns(&ctx, &mut respawns);
                    sampler = sample_and_poll_tick(&ctx, sampler).await;
                    ctx.update_and_broadcast_snapshot();
                }
            }
        }

        // In-flight respawns see the flag, stop their child and return; wait for them so none outlives the shutdown.
        ctx.shutting_down.store(true, Ordering::SeqCst);
        let respawn_deadline = Duration::from_secs(spec.shutdown_timeout_secs.max(5));
        let _ = tokio::time::timeout(respawn_deadline, async {
            while respawns.join_next().await.is_some() {}
        })
        .await;

        let down_opts = ctx.shutdown_opts.lock().ok().and_then(|mut g| g.take());
        let (timeout_secs, clean_files, progress_tx, flush_done_rx) = match down_opts {
            Some(o) => (
                o.timeout_secs,
                o.clean_files,
                o.progress_tx,
                o.flush_done_rx,
            ),
            None => (spec.shutdown_timeout_secs, false, None, None),
        };

        shutdown_all_slots(&ctx, timeout_secs, clean_files, progress_tx).await;
        if let Some(rx) = flush_done_rx {
            // Let the active `Down` stream client flush `Completed` before dropping `_ipc_cleanup`.
            let _ = tokio::time::timeout(Duration::from_secs(2), rx).await;
        }
        metrics_shutdown.store(true, Ordering::SeqCst);
        let _ = ipc_task.await;
        if let Some(h) = metrics_handle {
            let _ = h.join();
        }
        Ok(())
    })
}

fn classify_storage_mode(services: &[DaemonServiceSpec]) -> String {
    let mut has_pg = false;
    let mut has_files = false;
    for s in services {
        match &s.storage {
            super::StorageSpec::Postgres { .. } => has_pg = true,
            super::StorageSpec::Files => has_files = true,
            super::StorageSpec::Memory => {}
        }
    }
    match (has_pg, has_files) {
        (true, true) => "hybrid".to_string(),
        (true, false) => "postgres".to_string(),
        (false, _) => "files".to_string(),
    }
}

pub(super) fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.windows(2)
        .find_map(|w| (w[0] == flag).then(|| w[1].clone()))
}

pub(super) fn tail_summary(hub: &LogHub, node: &str) -> String {
    let lines = hub.tail(Some(node), LogLevel::Debug, 4);
    if lines.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = lines.into_iter().map(|e| e.line).collect();
        format!(" | log tail: {}", joined.join(" / "))
    }
}

pub(super) fn write_ready_ack(state_dir: &Path, ack: &WorkerReadyAck) {
    let path = state_dir.join(READY_HANDSHAKE_FILE);
    let tmp = state_dir.join(format!("{READY_HANDSHAKE_FILE}.tmp"));
    if let Ok(json) = serde_json::to_string_pretty(ack) {
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(tmp, path);
        }
    }
}

pub(super) fn parse_log_encoder(s: &str) -> ledger_json_api::canton_log::LogEncoder {
    match s.to_ascii_lowercase().as_str() {
        "plain" => ledger_json_api::canton_log::LogEncoder::Plain,
        "json" => ledger_json_api::canton_log::LogEncoder::Json,
        _ => ledger_json_api::canton_log::LogEncoder::Text,
    }
}

/// Spawns detached `--daemon-supervisor-worker` and waits for `daemon.ready.json` handshake.
pub fn spawn_detached_and_wait(
    state_dir: &Path,
    worker_args: &[String],
    timeout_secs: u64,
) -> Result<WorkerReadyAck, String> {
    if super::ipc::probe_daemon_alive(state_dir) {
        return Err(format!(
            "supervisor already running at {} (stop it first with 'canton-rs daemon down --state-dir {}')",
            socket_path(state_dir).display(),
            state_dir.display()
        ));
    }
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("cannot create {}: {e}", state_dir.display()))?;
    mark_state_dir_if_empty(state_dir);
    let ack_path = state_dir.join(READY_HANDSHAKE_FILE);
    let _ = std::fs::remove_file(&ack_path);

    let logs_dir = state_dir.join("logs");
    std::fs::create_dir_all(&logs_dir).map_err(|e| e.to_string())?;
    let sup_log_path = logs_dir.join("supervisor.log");
    let sup_out = File::create(&sup_log_path).map_err(|e| e.to_string())?;
    let sup_err = sup_out.try_clone().map_err(|e| e.to_string())?;

    let mut worker = super::process::spawn_detached_worker(
        worker_args,
        &BTreeMap::new(),
        Stdio::from(sup_out),
        Stdio::from(sup_err),
    )?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(30));
    while Instant::now() < deadline {
        if ack_path.exists() {
            if let Ok(raw) = std::fs::read_to_string(&ack_path) {
                if let Ok(ack) = serde_json::from_str::<WorkerReadyAck>(&raw) {
                    if ack.ok {
                        return Ok(ack);
                    }
                    // Wait briefly for the detached worker process to finish exiting after rollback
                    // so callers immediately observe 0 stray processes on `daemon up -d` failure.
                    let exit_deadline = Instant::now() + Duration::from_secs(5);
                    while Instant::now() < exit_deadline {
                        if matches!(worker.try_wait(), Ok(Some(_))) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    let msg = ack
                        .error
                        .unwrap_or_else(|| "supervisor worker startup failed".to_string());
                    return Err(msg);
                }
            }
        }
        if let Ok(Some(status)) = worker.try_wait() {
            let tail = std::fs::read_to_string(&sup_log_path).unwrap_or_default();
            return Err(format!(
                "supervisor worker exited prematurely ({status}): {}",
                tail.lines()
                    .rev()
                    .take(6)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    let pid = worker.id();
    super::process::kill_pid_graceful(pid, Duration::from_secs(5));
    let _ = worker.kill();
    let _ = worker.try_wait();
    if let Ok(exe) = std::env::current_exe() {
        let _ = super::process::cleanup_stale_pids(state_dir, &exe, Duration::from_secs(3));
    }
    Err(format!(
        "timed out waiting for detached supervisor worker after {timeout_secs}s (see {})",
        sup_log_path.display()
    ))
}
