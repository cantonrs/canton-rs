use std::io::BufReader;
use std::process::{Child, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::log_rotate::{LogHub, SizeRotatingWriter};
use super::super::probe::{probe_http_ok_bearer, upload_extra_dar};
use super::super::proc_sampler::OsProcSampler;
use super::super::process::{
    graceful_stop_child, make_pid_entry, run_command_to_end, spawn_current_exe, wait_listening,
};
use super::super::{
    now_unix_ms, now_unix_secs, DaemonServiceSpec, NodeLifecycleState, NodeRole, ProcResources,
    RestartPolicy,
};
use super::{
    arg_value, compute_backoff_ms, parse_log_encoder, tail_summary, ChildExitNotice, EngineContext,
    WorkerReadyNode,
};

pub(super) async fn start_all_initial_slots(
    ctx: &Arc<EngineContext>,
    ready_nodes: &mut Vec<WorkerReadyNode>,
) -> Result<(), String> {
    let count = ctx.slots.lock().map(|s| s.len()).unwrap_or(0);
    for idx in 0..count {
        let started = Instant::now();
        let summary = start_single_slot(ctx, idx).await?;
        let (name, role) = ctx
            .slots
            .lock()
            .ok()
            .and_then(|s| s.get(idx).map(|r| (r.spec.name.clone(), r.spec.role)))
            .unwrap_or_else(|| (format!("slot-{idx}"), NodeRole::Participant));
        ready_nodes.push(WorkerReadyNode {
            slot_id: idx,
            name,
            role,
            summary,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }
    Ok(())
}

fn slot_superseded(ctx: &Arc<EngineContext>, idx: usize, expected_gen: u64) -> bool {
    if ctx.shutting_down.load(Ordering::SeqCst) {
        return true;
    }
    ctx.slots
        .lock()
        .ok()
        .and_then(|slots| slots.get(idx).map(|s| s.generation != expected_gen))
        .unwrap_or(true)
}

/// Spawns one slot synchronously in background threadpool and awaits readiness/port check.
pub(super) async fn start_single_slot(
    ctx: &Arc<EngineContext>,
    idx: usize,
) -> Result<String, String> {
    start_single_slot_for_generation(ctx, idx, None).await
}

pub(super) async fn start_single_slot_for_generation(
    ctx: &Arc<EngineContext>,
    idx: usize,
    expected_gen: Option<u64>,
) -> Result<String, String> {
    let (spec, is_respawn, start_gen) = {
        let mut slots = ctx
            .slots
            .lock()
            .map_err(|_| "slots lock poisoned".to_string())?;
        let slot = slots.get_mut(idx).ok_or("slot out of range")?;
        if let Some(eg) = expected_gen {
            if slot.generation != eg {
                return Ok(String::new());
            }
        } else {
            slot.generation = slot.generation.saturating_add(1);
        }
        let start_gen = slot.generation;
        slot.auto_restart_paused = false;
        slot.stopping_intentionally = false;
        slot.backoff_until_ms = None;
        slot.state = NodeLifecycleState::Bootstrapping;
        (slot.spec.clone(), slot.restarts_total > 0, start_gen)
    };

    let ctx_clone = Arc::clone(ctx);
    let spawn_outcome = match tokio::task::spawn_blocking(move || {
        spawn_slot_blocking(&ctx_clone, idx, &spec, is_respawn, start_gen)
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            mark_slot_boot_failed(ctx, idx, start_gen, &err);
            return Err(err);
        }
        Err(join_err) => {
            let err = format!("slot {idx} task failed: {join_err}");
            mark_slot_boot_failed(ctx, idx, start_gen, &err);
            return Err(err);
        }
    };

    commit_started_slot(ctx, idx, start_gen, spawn_outcome).await
}

/// Commits a started child process into `slots[idx]` only if `slot.generation == start_gen` and shutdown has not started.
pub(super) async fn commit_started_slot(
    ctx: &Arc<EngineContext>,
    idx: usize,
    start_gen: u64,
    outcome: SpawnSlotOutcome,
) -> Result<String, String> {
    let (pid, child_arc, gen_num, summary, started_unix) = outcome;
    let committed = {
        let mut slots = ctx
            .slots
            .lock()
            .map_err(|_| "slots lock poisoned".to_string())?;
        match slots.get_mut(idx) {
            Some(slot)
                if !ctx.shutting_down.load(Ordering::SeqCst) && slot.generation == start_gen =>
            {
                slot.pid = Some(pid);
                slot.child = Some(Arc::clone(&child_arc));
                slot.generation = gen_num;
                slot.state = NodeLifecycleState::Online;
                slot.pid_started_at = Some(Instant::now());
                slot.pid_started_unix = Some(started_unix);
                slot.online_since = Some(Instant::now());
                slot.stopped_at_unix_ms = None;
                true
            }
            _ => false,
        }
    };
    if let Ok(mut booting) = ctx.booting_pids.lock() {
        booting.remove(&idx);
    }
    if !committed {
        ctx.sync_pid_manifest();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(mut g) = child_arc.lock() {
                if let Some(mut c) = g.take() {
                    graceful_stop_child(&mut c, Duration::from_secs(2));
                }
            }
        })
        .await;
        return Err(format!(
            "slot {idx} start superseded or stopped during startup"
        ));
    }
    ctx.sync_pid_manifest();
    Ok(summary)
}

/// Transitions a slot out of `Bootstrapping` when `start_single_slot` fails so a slot whose
/// dependency (e.g. `sequencer1`) is temporarily offline enters `BackoffWait` and retries
/// automatically instead of remaining permanently wedged in `Bootstrapping`.
pub(super) fn mark_slot_boot_failed(
    ctx: &Arc<EngineContext>,
    idx: usize,
    start_gen: u64,
    err: &str,
) {
    if let Ok(mut slots) = ctx.slots.lock() {
        if let Some(slot) = slots.get_mut(idx) {
            if slot.generation != start_gen {
                return;
            }
            slot.generation = slot.generation.saturating_add(1);
            slot.pid = None;
            slot.child = None;
            slot.online_since = None;
            slot.resources = ProcResources::default();
            slot.last_exit_at_unix_ms = Some(now_unix_ms());
            slot.last_exit_reason = Some(err.to_string());

            let max_hit = ctx
                .spec
                .max_restarts
                .is_some_and(|max| slot.restarts_total >= max);
            let policy_no = ctx.spec.no_restart
                || slot.spec.restart == RestartPolicy::No
                || slot.auto_restart_paused
                || max_hit;
            if policy_no {
                slot.backoff_until_ms = None;
                slot.state = NodeLifecycleState::Failed;
            } else {
                slot.consecutive_failures = slot.consecutive_failures.saturating_add(1);
                let delay_ms = compute_backoff_ms(slot.consecutive_failures, idx);
                slot.backoff_until_ms = Some(now_unix_ms().saturating_add(delay_ms));
                slot.state = NodeLifecycleState::BackoffWait;
            }
        }
    }
    if let Ok(mut booting) = ctx.booting_pids.lock() {
        booting.remove(&idx);
    }
    ctx.sync_pid_manifest();
}

pub(super) type SpawnSlotOutcome = (u32, Arc<Mutex<Option<Child>>>, u64, String, u64);

fn spawn_slot_blocking(
    ctx: &Arc<EngineContext>,
    idx: usize,
    svc: &DaemonServiceSpec,
    is_respawn: bool,
    start_gen: u64,
) -> Result<SpawnSlotOutcome, String> {
    if svc.role == NodeRole::Mediator && svc.config_path.is_none() {
        ensure_mode_a_mediator_onboarded(ctx, idx, svc, is_respawn)?;
    }

    // [CANTON-NOTE: WHY] Read PQS token_env lazily at child spawn time so manifest parsing succeeds before the env var exists and rotations take effect on restart.
    let mut spawn_env = svc.env.clone();
    if svc.role == NodeRole::Pqs {
        if let Some(super::super::TokenSource::Env(var)) = &svc.token {
            let value = std::env::var(var)
                .map_err(|_| format!("pqs service '{}': token_env {var} is not set", svc.name))?;
            spawn_env.insert("CANTON_RS_PQS_TOKEN".into(), value);
        }
    }
    let mut child = spawn_current_exe(&svc.argv, &spawn_env, Stdio::piped(), Stdio::piped())?;
    let started_unix = now_unix_secs();
    let pid = child.id();
    {
        let mut entry = make_pid_entry(idx, svc.role.as_str(), &svc.name, pid, &ctx.exe_path);
        entry.started_at_unix = started_unix;
        if let Ok(mut booting) = ctx.booting_pids.lock() {
            booting.insert(idx, entry);
        }
        ctx.sync_pid_manifest();
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let writer = Arc::new(Mutex::new(
        SizeRotatingWriter::open(
            &ctx.spec.state_dir,
            &svc.name,
            ctx.spec.log_max_bytes,
            ctx.spec.log_max_files,
        )
        .map_err(|e| format!("cannot open rotated log for {}: {e}", svc.name))?,
    ));

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<String>();
    let ready_prefix = svc.ready_line_prefix.clone();
    let forward = ctx.spec.foreground_legacy_banner && ctx.spec.log_encoder != "text";
    let node_log_policy = ctx.spec.logging.resolve_for_node(&svc.name);

    if let Some(out) = stdout {
        spawn_pipe_reader(
            out,
            PipeReaderSpec {
                node_name: svc.name.clone(),
                file_writer: Arc::clone(&writer),
                log_hub: ctx.log_hub.clone(),
                ready_prefix,
                ready_tx: Some(ready_tx),
                forward_to_stdout: forward,
                line_gate: super::super::log_policy::NodeLineGate::new(node_log_policy.clone()),
            },
        );
    }
    if let Some(err) = stderr {
        spawn_pipe_reader(
            err,
            PipeReaderSpec {
                node_name: svc.name.clone(),
                file_writer: writer,
                log_hub: ctx.log_hub.clone(),
                ready_prefix: None,
                ready_tx: None,
                forward_to_stdout: forward,
                line_gate: super::super::log_policy::NodeLineGate::new(node_log_policy),
            },
        );
    }

    let gen_num = start_gen;
    let mut child = child;
    if slot_superseded(ctx, idx, start_gen) {
        graceful_stop_child(&mut child, Duration::from_secs(2));
        return Err(format!(
            "service '{}' start cancelled: slot superseded before tracking child",
            svc.name
        ));
    }

    let child_arc = Arc::new(Mutex::new(Some(child)));
    let watcher_child = Arc::clone(&child_arc);
    let watcher_tx = ctx.exit_tx.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(80));
        let done = {
            let Ok(mut g) = watcher_child.lock() else {
                break;
            };
            match g.as_mut() {
                Some(c) => match c.try_wait() {
                    Ok(Some(status)) => {
                        let clean = status.success();
                        Some((format!("{status}"), clean))
                    }
                    Ok(None) => None,
                    Err(e) => Some((format!("wait error: {e}"), false)),
                },
                None => break,
            }
        };
        if let Some((exit_desc, exit_clean)) = done {
            let _ = watcher_tx.send(ChildExitNotice {
                slot_id: idx,
                generation: gen_num,
                exit_desc,
                exit_clean,
            });
            break;
        }
    });

    // Wait for READY stdout banner (if defined) and listening TCP ports.
    let timeout = Duration::from_secs(ctx.spec.wait_for_deps_secs.max(10));
    let mut ready_line: Option<String> = None;
    let stopping = || slot_superseded(ctx, idx, start_gen);
    if svc.ready_line_prefix.is_some() {
        let deadline = Instant::now() + timeout;
        let mut got = Err(std::sync::mpsc::RecvTimeoutError::Timeout);
        while Instant::now() < deadline && !stopping() {
            got = ready_rx.recv_timeout(Duration::from_millis(200));
            if !matches!(got, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                break;
            }
        }
        match got {
            Ok(line) => ready_line = Some(line),
            Err(_) => {
                if let Ok(mut g) = child_arc.lock() {
                    if let Some(mut c) = g.take() {
                        graceful_stop_child(&mut c, Duration::from_secs(2));
                    }
                }
                let tail = tail_summary(&ctx.log_hub, &svc.name);
                return Err(format!(
                    "service '{}' did not report ready within {}s{}",
                    svc.name,
                    timeout.as_secs(),
                    tail
                ));
            }
        }
    } else {
        // Brief check that process did not crash immediately before port probe.
        std::thread::sleep(Duration::from_millis(120));
        if let Ok(mut g) = child_arc.lock() {
            if let Some(c) = g.as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    return Err(format!(
                        "service '{}' exited immediately ({status}){}",
                        svc.name,
                        tail_summary(&ctx.log_hub, &svc.name)
                    ));
                }
            }
        }
    }

    let primary_port = svc
        .ports
        .http_json
        .or(svc.ports.public)
        .or(svc.ports.grpc_ledger)
        .or(svc.ports.admin);
    if let Some(p) = primary_port {
        let deadline = Instant::now() + timeout;
        let mut listening = false;
        while Instant::now() < deadline && !stopping() {
            if wait_listening(p, Duration::from_millis(200)).is_ok() {
                listening = true;
                break;
            }
        }
        if !listening {
            if let Ok(mut g) = child_arc.lock() {
                if let Some(mut c) = g.take() {
                    graceful_stop_child(&mut c, Duration::from_secs(2));
                }
            }
            return Err(format!(
                "service '{}' did not listen on port {p}{}",
                svc.name,
                tail_summary(&ctx.log_hub, &svc.name)
            ));
        }
    }

    // [CANTON-NOTE: INVARIANT] `ledger-json-api` binds `TcpListener` before finishing DAR vetting,
    // synchronizer onboarding, and Admin API startup, so TCP connect succeeds before `run_server` calls
    // `accept()`. Poll the HTTP `/readyz` (or `/livez`) gate here so downstream dependents wait cleanly.
    if let Some(check_url) = svc.readiness_url.as_deref().or(svc.health_url.as_deref()) {
        let deadline = Instant::now() + timeout;
        let mut ready = false;
        while Instant::now() < deadline && !stopping() {
            if let Ok(mut g) = child_arc.lock() {
                if let Some(c) = g.as_mut() {
                    if let Ok(Some(status)) = c.try_wait() {
                        return Err(format!(
                            "service '{}' exited while waiting for readiness ({status}){}",
                            svc.name,
                            tail_summary(&ctx.log_hub, &svc.name)
                        ));
                    }
                }
            }
            let svc_token = svc.token.as_ref().and_then(super::super::TokenSource::read);
            if probe_http_ok_bearer(check_url, Duration::from_millis(1500), svc_token.as_deref()) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            if let Ok(mut g) = child_arc.lock() {
                if let Some(mut c) = g.take() {
                    graceful_stop_child(&mut c, Duration::from_secs(2));
                }
            }
            return Err(format!(
                "service '{}' failed readiness check at {check_url} within {}s{}",
                svc.name,
                timeout.as_secs(),
                tail_summary(&ctx.log_hub, &svc.name)
            ));
        }
    }

    // Upload any additional DARs listed in Mode A manifest once participant JSON API accepts traffic.
    if svc.role == NodeRole::Participant && svc.dars.len() > 1 {
        if let Some(http_port) = svc.ports.http_json {
            let svc_token = svc.token.as_ref().and_then(super::super::TokenSource::read);
            for extra_dar in &svc.dars[1..] {
                upload_extra_dar(http_port, extra_dar, svc_token.as_deref())?;
            }
        }
    }

    if stopping() {
        if let Ok(mut g) = child_arc.lock() {
            if let Some(mut c) = g.take() {
                graceful_stop_child(&mut c, Duration::from_secs(2));
            }
        }
        return Err(format!(
            "service '{}' start cancelled: the supervisor is shutting down",
            svc.name
        ));
    }

    if ctx.spec.foreground_legacy_banner && !is_respawn {
        emit_legacy_node_ready(ctx, svc, ready_line.as_deref());
    }

    Ok((pid, child_arc, gen_num, svc.ports.summary(), started_unix))
}

fn emit_legacy_node_ready(
    ctx: &Arc<EngineContext>,
    svc: &DaemonServiceSpec,
    ready_line: Option<&str>,
) {
    let enc = parse_log_encoder(&ctx.spec.log_encoder);
    let context = format!("{}={}", svc.role.as_str(), svc.name);
    let line_str = ready_line.unwrap_or("READY");
    let msg = match svc.role {
        NodeRole::Sequencer => format!(
            " Sequencer {}: {} ({}, {})",
            svc.name,
            line_str,
            svc.ports.summary(),
            svc.storage.masked_summary()
        ),
        NodeRole::Mediator => format!(
            " Mediator {}: {} ({})",
            svc.name,
            line_str,
            svc.storage.masked_summary()
        ),
        NodeRole::Participant => format!(
            " Participant {}: {} ({}, synchronizer {})",
            svc.name,
            if svc.ports.http_json.is_some() {
                "JSON API"
            } else {
                "gRPC/Admin API"
            },
            svc.ports.summary(),
            ctx.spec.synchronizer
        ),
        NodeRole::Splice | NodeRole::Scan | NodeRole::Pqs => {
            format!(
                " {} {}: {}",
                svc.role.as_str(),
                svc.name,
                svc.ports.summary()
            )
        }
    };
    ledger_json_api::canton_log::emit(enc, "INFO", "canton-rs.daemon", &context, &msg);
}

fn ensure_mode_a_mediator_onboarded(
    ctx: &Arc<EngineContext>,
    idx: usize,
    svc: &DaemonServiceSpec,
    is_respawn: bool,
) -> Result<(), String> {
    // [CANTON-NOTE: INVARIANT] Declarative BFT clusters (`bft_group`) already include mediator
    // identities inside `bft-<sync>-genesis.tx`, so dynamic `add-mediator` must not run again.
    if svc.bft_peer_count.is_some() {
        return Ok(());
    }
    let onboarding = ctx
        .spec
        .state_dir
        .join(format!("{}-onboarding.txt", svc.name));
    if is_respawn && onboarding.exists() {
        return Ok(());
    }
    let Some(seq_url) = arg_value(&svc.argv, "--sequencer-url") else {
        return Ok(());
    };
    // Support Multi-Synchronizer Mode A manifests: pass `--replace` for the FIRST mediator
    // onboarding onto each distinct `--sequencer-url`.
    let is_first_mediator = ctx
        .spec
        .services
        .iter()
        .find(|s| {
            s.role == NodeRole::Mediator
                && arg_value(&s.argv, "--sequencer-url").as_deref() == Some(seq_url.as_str())
        })
        .is_some_and(|first| first.slot_id == idx);
    if let Some(port) = seq_url
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
    {
        wait_listening(port, Duration::from_secs(30))?;
    }
    std::fs::create_dir_all(&ctx.spec.state_dir).map_err(|e| e.to_string())?;
    let exe = &ctx.exe_path;

    let mut init_args = vec![
        "mediator".to_string(),
        "init".to_string(),
        "--name".to_string(),
        svc.name.clone(),
    ];
    let mut print_args = vec![
        "mediator".to_string(),
        "onboarding".to_string(),
        "--out".to_string(),
        onboarding.display().to_string(),
    ];
    if let Some(sd) = arg_value(&svc.argv, "--state-dir") {
        init_args.extend(["--state-dir".into(), sd.clone()]);
        print_args.extend(["--state-dir".into(), sd]);
    } else if let Some(sn) = arg_value(&svc.argv, "--state-name") {
        init_args.extend(["--state-name".into(), sn.clone()]);
        print_args.extend(["--state-name".into(), sn]);
    }

    let mut init_cmd = super::super::process::exe_command(exe);
    init_cmd.args(&init_args).envs(&svc.env);
    run_command_to_end(&mut init_cmd, "mediator init")?;

    let mut print_cmd = super::super::process::exe_command(exe);
    print_cmd.args(&print_args).envs(&svc.env);
    run_command_to_end(&mut print_cmd, "mediator onboarding")?;

    let mut add_cmd = super::super::process::exe_command(exe);
    add_cmd.args(["sequencer", "add-mediator", "--group", "0"]);
    if is_first_mediator {
        add_cmd.arg("--replace");
    }
    add_cmd.args([
        "--sequencer-url",
        &url_or(&seq_url),
        "--onboarding",
        &onboarding.display().to_string(),
    ]);
    // a sequencer with an admin port serves its topology administration there only
    let admin_bind = ctx
        .spec
        .services
        .iter()
        .filter(|s| s.role == NodeRole::Sequencer)
        .find(|s| arg_value(&s.argv, "--port").is_some_and(|p| seq_url.ends_with(&format!(":{p}"))))
        .and_then(|s| {
            s.env
                .get("CANTON_RS_SEQUENCER_ADMIN_BIND")
                .cloned()
                .or_else(|| arg_value(&s.argv, "--admin-bind"))
        });
    if let Some(bind) = admin_bind {
        add_cmd.args(["--admin-url", &format!("http://{bind}")]);
    }
    run_command_to_end(&mut add_cmd, "sequencer add-mediator")?;
    Ok(())
}

fn url_or(seq_url: &str) -> String {
    seq_url.to_string()
}

struct PipeReaderSpec {
    node_name: String,
    file_writer: Arc<Mutex<SizeRotatingWriter>>,
    log_hub: LogHub,
    ready_prefix: Option<String>,
    ready_tx: Option<std::sync::mpsc::Sender<String>>,
    forward_to_stdout: bool,
    line_gate: super::super::log_policy::NodeLineGate,
}

fn spawn_pipe_reader<R: std::io::Read + Send + 'static>(reader: R, mut spec: PipeReaderSpec) {
    std::thread::spawn(move || {
        for_each_line_lossy(BufReader::new(reader), |line| {
            // [CANTON-NOTE: INVARIANT] Detect `READY` handshake lines before applying `NodeLineGate`
            // so strict log thresholds (`warn`/`error`/`off`) never block node readiness.
            if let Some(prefix) = &spec.ready_prefix {
                if line.starts_with(prefix) {
                    if let Some(tx) = spec.ready_tx.take() {
                        let _ = tx.send(line.clone());
                    }
                }
            }
            for accepted in spec.line_gate.accept_now(&line) {
                if spec.forward_to_stdout {
                    println!("{accepted}");
                }
                if let Ok(mut w) = spec.file_writer.lock() {
                    let _ = w.write_line(&accepted);
                }
                spec.log_hub.push(&spec.node_name, &accepted);
            }
        });
    });
}

/// Calls `on_line` for every line of `reader` until end of file or a read error, decoding non-UTF-8 bytes lossily.
///
/// [CANTON-NOTE: DEFENSIVE] Stopping at the first non-UTF-8 line left the pipe undrained: the child then blocked on a full pipe
/// or died of EPIPE.
pub(super) fn for_each_line_lossy<R: std::io::BufRead>(
    mut reader: R,
    mut on_line: impl FnMut(String),
) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return,
            Ok(_) => {
                while matches!(buf.last(), Some(b'\n' | b'\r')) {
                    buf.pop();
                }
                on_line(String::from_utf8_lossy(&buf).into_owned());
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

pub(super) fn handle_unexpected_or_expected_exit(
    ctx: &Arc<EngineContext>,
    notice: ChildExitNotice,
    sampler: &mut OsProcSampler,
) {
    let Ok(mut slots) = ctx.slots.lock() else {
        return;
    };
    let Some(slot) = slots.get_mut(notice.slot_id) else {
        return;
    };
    if slot.generation != notice.generation {
        return;
    }
    if let Some(old_pid) = slot.pid.take() {
        sampler.forget_pid(old_pid);
    }
    slot.child = None;
    slot.online_since = None;
    slot.resources = ProcResources::default();
    slot.last_exit_at_unix_ms = Some(now_unix_ms());
    slot.last_exit_reason = Some(notice.exit_desc.clone());

    if slot.stopping_intentionally {
        slot.stopping_intentionally = false;
        slot.state = NodeLifecycleState::Stopped;
        slot.stopped_at_unix_ms = Some(now_unix_ms());
        drop(slots);
        ctx.sync_pid_manifest();
        return;
    }

    ctx.log_hub.push(
        &slot.spec.name,
        &format!(
            "ERROR supervised child exited unexpectedly ({})",
            notice.exit_desc
        ),
    );

    let max_hit = ctx
        .spec
        .max_restarts
        .is_some_and(|max| slot.restarts_total >= max);
    let policy_no = ctx.spec.no_restart
        || slot.spec.restart == RestartPolicy::No
        || (slot.spec.restart == RestartPolicy::OnFailure && notice.exit_clean);

    if policy_no || max_hit || slot.auto_restart_paused {
        slot.state = if notice.exit_clean && slot.spec.restart == RestartPolicy::OnFailure {
            slot.stopped_at_unix_ms = Some(now_unix_ms());
            NodeLifecycleState::Stopped
        } else {
            NodeLifecycleState::Failed
        };
    } else {
        slot.consecutive_failures = slot.consecutive_failures.saturating_add(1);
        let delay_ms = compute_backoff_ms(slot.consecutive_failures, slot.spec.slot_id);
        slot.backoff_until_ms = Some(now_unix_ms().saturating_add(delay_ms));
        slot.state = NodeLifecycleState::BackoffWait;
    }
    drop(slots);
    ctx.sync_pid_manifest();
}

/// Starts the respawn of every slot whose backoff ran out, each as its own task in `respawns`, so the main loop keeps handling signals,
/// `down` and child exits while a node boots.
pub(super) fn process_backoff_respawns(
    ctx: &Arc<EngineContext>,
    respawns: &mut tokio::task::JoinSet<()>,
) {
    let now = now_unix_ms();
    let due: Vec<(usize, u64)> = {
        let Ok(mut slots) = ctx.slots.lock() else {
            return;
        };
        slots
            .iter_mut()
            .filter(|s| {
                s.state == NodeLifecycleState::BackoffWait
                    && !s.auto_restart_paused
                    && s.backoff_until_ms.is_some_and(|t| now >= t)
            })
            .map(|s| {
                // Leaves `BackoffWait` now so the next tick does not start a second respawn of the same slot.
                s.state = NodeLifecycleState::Bootstrapping;
                s.restarts_total = s.restarts_total.saturating_add(1);
                s.generation = s.generation.saturating_add(1);
                (s.spec.slot_id, s.generation)
            })
            .collect()
    };

    for (idx, expected_gen) in due {
        let ctx = Arc::clone(ctx);
        respawns.spawn(async move {
            if let Err(err) = start_single_slot_for_generation(&ctx, idx, Some(expected_gen)).await
            {
                ctx.log_hub.push(
                    "supervisor",
                    &format!("WARN slot {idx} restart attempt failed: {err}"),
                );
            }
        });
    }
}
