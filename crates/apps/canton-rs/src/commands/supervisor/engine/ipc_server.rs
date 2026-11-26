use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::sync::{broadcast, mpsc};

use super::super::ipc::{
    DownProgressEvent, IpcRequest, IpcResponse, IpcStreamEvent, StartedNodeInfo,
};
use super::super::log_rotate::{inspect_log_file, LogLevel};
use super::super::probe::{collect_domain_inspection, http_request_bearer, poll_slot};
use super::super::{
    now_unix_ms, sanitize_argv, DaemonServiceSpec, ExExNodeSummary, NodeInspection,
    NodeLifecycleState, NodeRole, PingStatus, XRayTraceEvent,
};
use super::lifecycle::start_single_slot;
use super::ops::{run_ping_for_ctx, stop_slots_by_indices};
use super::{EngineContext, ShutdownSignal};

/// The most bytes read from one IPC connection (its request line and the end-of-stream wait of a subscription).
const MAX_IPC_REQUEST_BYTES: u64 = 1 << 20;

pub(super) async fn handle_ipc_client(ctx: Arc<EngineContext>, stream: tokio::net::UnixStream) {
    let (reader, mut writer) = stream.into_split();
    // A request is one JSON line; the cap keeps a client from making the supervisor buffer without bound.
    let reader = tokio::io::AsyncReadExt::take(reader, MAX_IPC_REQUEST_BYTES);
    let mut lines = AsyncBufReader::new(reader).lines();
    let Ok(Some(line)) = lines.next_line().await else {
        return;
    };
    let req: IpcRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let _ = write_json_line(
                &mut writer,
                &IpcResponse::err(format!("bad IPC request: {e}")),
            )
            .await;
            return;
        }
    };

    match req {
        IpcRequest::GetSnapshot => {
            let snap = ctx.build_snapshot();
            let _ = write_json_line(
                &mut writer,
                &IpcResponse::Snapshot {
                    ok: true,
                    snapshot: snap,
                },
            )
            .await;
        }
        IpcRequest::GetExex => {
            let targets: Vec<(String, u16, bool, Option<String>)> = ctx
                .slots
                .lock()
                .map(|slots| {
                    slots
                        .iter()
                        .filter_map(|s| {
                            let port = s.spec.ports.http_json?;
                            Some((
                                s.spec.name.clone(),
                                port,
                                s.state == NodeLifecycleState::Online,
                                s.spec
                                    .token
                                    .as_ref()
                                    .and_then(super::super::TokenSource::read),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let nodes = tokio::task::spawn_blocking(move || {
                targets
                    .into_iter()
                    .map(|(node_name, port, online, token)| {
                        let mut reachable = false;
                        let mut active_subscribers = 0u64;
                        let mut subscriber_lines = Vec::new();
                        if online {
                            let url = format!("http://127.0.0.1:{port}/_exex");
                            if let Ok((200, body)) = http_request_bearer(
                                &url,
                                "GET",
                                None,
                                None,
                                Duration::from_millis(350),
                                token.as_deref(),
                            ) {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                                    reachable = true;
                                    active_subscribers = val["active_extensions"]
                                        .as_u64()
                                        .or_else(|| val["active_subscribers"].as_u64())
                                        .unwrap_or(0);
                                    if let Some(arr) = val["extensions"]
                                        .as_array()
                                        .or_else(|| val["subscribers"].as_array())
                                    {
                                        for sub in arr {
                                            let name = sub["name"].as_str().unwrap_or("exex");
                                            let deliv = sub["delivered_notifications"]
                                                .as_u64()
                                                .or_else(|| sub["delivered"].as_u64())
                                                .unwrap_or(0);
                                            let filt = sub["filtered_out_events"]
                                                .as_u64()
                                                .or_else(|| sub["filtered_out"].as_u64())
                                                .unwrap_or(0);
                                            let drop_cnt = sub["dropped_notifications"]
                                                .as_u64()
                                                .or_else(|| sub["dropped_backpressure"].as_u64())
                                                .unwrap_or(0);
                                            let errs = sub["write_errors"].as_u64().unwrap_or(0);
                                            let err_suffix = if errs > 0 {
                                                format!(", write_errors={errs}")
                                            } else {
                                                String::new()
                                            };
                                            subscriber_lines.push(format!(
                                                "{name}: delivered={deliv}, privacy_filtered={filt}, dropped={drop_cnt}{err_suffix}"
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        ExExNodeSummary {
                            node_name,
                            port,
                            reachable,
                            active_subscribers,
                            subscriber_lines,
                        }
                    })
                    .collect()
            })
            .await
            .unwrap_or_default();
            let _ = write_json_line(&mut writer, &IpcResponse::Exex { ok: true, nodes }).await;
        }
        IpcRequest::Inspect { node } => {
            let resp = build_inspection(&ctx, &node).await;
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::TraceXray { root_hash } => {
            let trace = find_trace_on_hub_or_nodes(&ctx, &root_hash).await;
            let resp = match trace {
                Ok(t) => IpcResponse::Trace { ok: true, trace: t },
                Err(e) => IpcResponse::err(e),
            };
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::RunScenario { spec } => {
            let snap = ctx.build_snapshot();
            let sd = ctx.spec.state_dir.clone();
            let auth_map: BTreeMap<String, super::super::scenario::ScenarioNodeAuth> = ctx
                .slots
                .lock()
                .map(|slots| {
                    slots
                        .iter()
                        .filter_map(|s| {
                            let src = s.spec.token.as_ref()?;
                            let tok = src.read()?;
                            let is_dev_auto_signed =
                                matches!(src, super::super::TokenSource::DevJwt { .. });
                            Some((
                                s.spec.name.clone(),
                                super::super::scenario::ScenarioNodeAuth {
                                    token: tok,
                                    is_dev_auto_signed,
                                },
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let resp = tokio::task::spawn_blocking(move || {
                let report = super::super::scenario::execute_scenario_with_auth(
                    Some(&sd),
                    &snap,
                    &spec,
                    &auth_map,
                );
                IpcResponse::ScenarioReport {
                    ok: report.ok,
                    report,
                }
            })
            .await
            .unwrap_or_else(|e| IpcResponse::err(e.to_string()));
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::StopNodes { targets } => {
            let resp = match ctx.resolve_target_indices(&targets) {
                Ok(idxs) => {
                    let stopped =
                        stop_slots_by_indices(&ctx, &idxs, ctx.spec.shutdown_timeout_secs).await;
                    ctx.update_and_broadcast_snapshot();
                    IpcResponse::StoppedNodes { ok: true, stopped }
                }
                Err(e) => IpcResponse::err(e),
            };
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::StartNodes { targets } => {
            let resp = match ctx.resolve_target_indices(&targets) {
                Ok(idxs) => {
                    let mut started = Vec::new();
                    let mut failure = None;
                    for idx in idxs {
                        match start_single_slot(&ctx, idx).await {
                            Ok(_) => {
                                if let Ok(slots) = ctx.slots.lock() {
                                    if let Some(s) = slots.get(idx) {
                                        started.push(StartedNodeInfo {
                                            node: s.spec.name.clone(),
                                            pid: s.pid.unwrap_or(0),
                                        });
                                    }
                                }
                            }
                            Err(e) => {
                                if failure.is_none() {
                                    failure = Some(e);
                                }
                            }
                        }
                    }
                    ctx.update_and_broadcast_snapshot();
                    match failure {
                        Some(err) => IpcResponse::err(err),
                        None => IpcResponse::StartedNodes { ok: true, started },
                    }
                }
                Err(e) => IpcResponse::err(e),
            };
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::Restart { target } => {
            let list = target.map_or_else(Vec::new, |t| vec![t]);
            let resp = match ctx.resolve_target_indices(&list) {
                Ok(idxs) => {
                    let rev: Vec<usize> = idxs.iter().copied().rev().collect();
                    let _ = stop_slots_by_indices(&ctx, &rev, ctx.spec.shutdown_timeout_secs).await;
                    let mut restarted = Vec::new();
                    let mut failure = None;
                    for idx in idxs {
                        if let Ok(mut slots) = ctx.slots.lock() {
                            if let Some(s) = slots.get_mut(idx) {
                                s.restarts_total = s.restarts_total.saturating_add(1);
                                s.consecutive_failures = 0;
                            }
                        }
                        if let Err(e) = start_single_slot(&ctx, idx).await {
                            failure = Some(e);
                            break;
                        }
                        if let Ok(slots) = ctx.slots.lock() {
                            if let Some(s) = slots.get(idx) {
                                restarted.push(s.spec.name.clone());
                            }
                        }
                    }
                    ctx.update_and_broadcast_snapshot();
                    match failure {
                        Some(e) => IpcResponse::err(e),
                        None => IpcResponse::Restarted {
                            ok: true,
                            restarted,
                        },
                    }
                }
                Err(e) => IpcResponse::err(e),
            };
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::TriggerPing => {
            let ctx_ping = Arc::clone(&ctx);
            let status = tokio::task::spawn_blocking(move || run_ping_for_ctx(&ctx_ping))
                .await
                .unwrap_or_else(|e| PingStatus {
                    ok: false,
                    rtt_ms: 0.0,
                    detail: e.to_string(),
                    checked_at_unix_ms: now_unix_ms(),
                });
            if let Ok(mut lp) = ctx.last_ping.lock() {
                *lp = Some(status.clone());
            }
            ctx.update_and_broadcast_snapshot();
            let resp = if status.ok {
                IpcResponse::Ping {
                    ok: true,
                    rtt_ms: status.rtt_ms,
                    detail: status.detail,
                }
            } else {
                IpcResponse::err(format!("{} (rtt {:.2} ms)", status.detail, status.rtt_ms))
            };
            let _ = write_json_line(&mut writer, &resp).await;
        }
        IpcRequest::Down {
            timeout_secs,
            clean_files,
            stream_progress,
        } => {
            if ctx.shutting_down.swap(true, Ordering::SeqCst) {
                let _ = write_json_line(
                    &mut writer,
                    &IpcResponse::err("supervisor shutdown already in progress"),
                )
                .await;
                return;
            }
            let timeout = timeout_secs.unwrap_or(ctx.spec.shutdown_timeout_secs);
            let clean = clean_files.unwrap_or(false);
            if stream_progress {
                let (prog_tx, mut prog_rx) = mpsc::unbounded_channel::<DownProgressEvent>();
                let (flush_tx, flush_rx) = tokio::sync::oneshot::channel::<()>();
                if let Ok(mut opts) = ctx.shutdown_opts.lock() {
                    *opts = Some(ShutdownSignal {
                        timeout_secs: timeout,
                        clean_files: clean,
                        progress_tx: Some(prog_tx),
                        flush_done_rx: Some(flush_rx),
                    });
                }
                ctx.shutdown_tx.send_replace(true);
                while let Some(ev) = prog_rx.recv().await {
                    if write_json_line(&mut writer, &IpcStreamEvent::DownProgress { data: ev })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = writer.shutdown().await;
                let _ = flush_tx.send(());
            } else {
                let stopped = ctx.slots.lock().map(|s| s.len()).unwrap_or(0);
                if let Ok(mut opts) = ctx.shutdown_opts.lock() {
                    *opts = Some(ShutdownSignal {
                        timeout_secs: timeout,
                        clean_files: clean,
                        progress_tx: None,
                        flush_done_rx: None,
                    });
                }
                let _ =
                    write_json_line(&mut writer, &IpcResponse::DownAck { ok: true, stopped }).await;
                ctx.shutdown_tx.send_replace(true);
            }
        }
        IpcRequest::SubscribeSnapshots { interval_ms } => {
            let _ = write_json_line(
                &mut writer,
                &IpcStreamEvent::Snapshot {
                    data: ctx.build_snapshot(),
                },
            )
            .await;
            let mut rx = ctx.snapshot_tx.subscribe();
            let min_gap = Duration::from_millis(interval_ms.unwrap_or(1000).max(200));
            let mut last_sent = Instant::now();
            loop {
                match rx.recv().await {
                    Ok(snap) => {
                        if last_sent.elapsed() >= min_gap {
                            last_sent = Instant::now();
                            if write_json_line(
                                &mut writer,
                                &IpcStreamEvent::Snapshot { data: snap },
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        IpcRequest::SubscribeLogs {
            node,
            min_level,
            tail,
        } => {
            let level = min_level
                .as_deref()
                .map_or(LogLevel::Info, LogLevel::parse_filter);
            let history = ctx
                .log_hub
                .tail(node.as_deref(), level, tail.unwrap_or(100));
            for ev in history {
                if write_json_line(
                    &mut writer,
                    &IpcStreamEvent::Log {
                        ts: ev.ts_unix_ms,
                        node: ev.node,
                        level: ev.level,
                        line: ev.line,
                    },
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            let mut rx = ctx.log_hub.subscribe();
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if ev.level < level {
                            continue;
                        }
                        if node.as_deref().is_some_and(|n| n != ev.node) {
                            continue;
                        }
                        if write_json_line(
                            &mut writer,
                            &IpcStreamEvent::Log {
                                ts: ev.ts_unix_ms,
                                node: ev.node,
                                level: ev.level,
                                line: ev.line,
                            },
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        IpcRequest::SubscribeXray { rate_limit_per_sec } => {
            if let Some(cap) = rate_limit_per_sec {
                ctx.wiretap.set_rate_limit(cap);
            }
            let mut sub = ctx.wiretap.subscribe();
            backfill_recent_xray_from_nodes(&ctx).await;
            for existing in ctx.wiretap.recent(64) {
                if write_json_line(&mut writer, &IpcStreamEvent::Xray { data: existing })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            loop {
                tokio::select! {
                    eof_res = lines.next_line() => {
                        match eof_res {
                            Ok(None) | Err(_) => break,
                            Ok(Some(_)) => continue,
                        }
                    }
                    recv_res = sub.receiver.recv() => {
                        match recv_res {
                            Ok(ev) => {
                                if write_json_line(&mut writer, &IpcStreamEvent::Xray { data: ev })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        }
    }
}

async fn write_json_line<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> std::io::Result<()> {
    let json = serde_json::to_string(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writer.write_all(format!("{json}\n").as_bytes()).await?;
    writer.flush().await
}

async fn build_inspection(ctx: &Arc<EngineContext>, target: &str) -> IpcResponse {
    let idx = match ctx.resolve_target_indices(&[target.to_string()]) {
        Ok(idxs) if !idxs.is_empty() => idxs[0],
        Ok(_) => return IpcResponse::err(format!("service '{target}' not found")),
        Err(e) => return IpcResponse::err(e),
    };
    let (svc, pid, state, restarts, last_exit_at, last_exit_reason) = {
        let Ok(slots) = ctx.slots.lock() else {
            return IpcResponse::err("supervisor lock poisoned");
        };
        let s = &slots[idx];
        (
            s.spec.clone(),
            s.pid,
            s.state,
            s.restarts_total,
            s.last_exit_at_unix_ms,
            s.last_exit_reason.clone(),
        )
    };
    let (log_path, log_bytes, log_gens) =
        inspect_log_file(&ctx.spec.state_dir, &svc.name, ctx.spec.log_max_files);
    let domain = if pid.is_some() {
        let svc_probe = svc.clone();
        tokio::task::spawn_blocking(move || collect_domain_inspection(&svc_probe))
            .await
            .unwrap_or_default()
    } else {
        Default::default()
    };

    IpcResponse::Inspection {
        ok: true,
        inspection: Box::new(NodeInspection {
            role: svc.role,
            name: svc.name.clone(),
            pid,
            state,
            config_path: svc
                .config_path
                .as_ref()
                .or(ctx.spec.canton_conf.as_ref())
                .or(ctx.spec.manifest_path.as_ref())
                .map(|p| p.display().to_string()),
            bootstrap_path: svc
                .bootstrap_path
                .as_ref()
                .or(ctx.spec.bootstrap.as_ref())
                .map(|p| p.display().to_string()),
            state_dir: svc.state_dir.display().to_string(),
            log_file_path: log_path.display().to_string(),
            log_file_bytes: log_bytes,
            log_generations: log_gens,
            log_encoder: ctx.spec.log_encoder.clone(),
            port_offset: svc.port_offset,
            sanitized_argv: sanitize_argv(&svc.argv),
            config_applied_count: svc.config_applied_count,
            config_not_applied_keys: svc.config_not_applied_keys.clone(),
            storage_summary: svc.storage.masked_summary(),
            same_identity: svc.same_identity,
            official_write: svc.official_write,
            auth_mode: svc.auth_mode.clone(),
            node_uid: domain.node_uid,
            physical_synchronizer_id: domain.physical_synchronizer_id,
            protocol_version: domain.protocol_version,
            loaded_dars: domain.loaded_dars,
            hosted_parties: domain.hosted_parties,
            user_count: domain.user_count,
            ports: svc.ports,
            restarts_total: restarts,
            last_exit_at_unix_ms: last_exit_at,
            last_exit_reason,
        }),
    }
}

async fn backfill_recent_xray_from_nodes(ctx: &Arc<EngineContext>) {
    let svcs: Vec<DaemonServiceSpec> = ctx
        .slots
        .lock()
        .map(|s| {
            s.iter()
                .filter(|n| n.pid.is_some() && n.spec.role == NodeRole::Participant)
                .map(|n| n.spec.clone())
                .collect()
        })
        .unwrap_or_default();
    if svcs.is_empty() {
        return;
    }
    let collected = tokio::task::spawn_blocking(move || {
        let mut all = Vec::new();
        for svc in svcs {
            let res = poll_slot(&svc, 0, true, None);
            all.extend(res.xray_events);
        }
        all
    })
    .await
    .unwrap_or_default();
    for ev in collected {
        ctx.wiretap.record_trace(ev);
    }
}

async fn find_trace_on_hub_or_nodes(
    ctx: &Arc<EngineContext>,
    root_hash: &str,
) -> Result<XRayTraceEvent, String> {
    if let Some(found) = ctx.wiretap.lookup(root_hash) {
        return Ok(found);
    }
    let svcs: Vec<DaemonServiceSpec> = ctx
        .slots
        .lock()
        .map(|s| {
            s.iter()
                .filter(|n| n.pid.is_some())
                .map(|n| n.spec.clone())
                .collect()
        })
        .unwrap_or_default();
    let needle = root_hash.trim().to_string();
    let wants_latest = needle.is_empty() || needle.eq_ignore_ascii_case("latest");
    let polled = tokio::task::spawn_blocking(move || {
        for svc in svcs {
            if svc.role == NodeRole::Participant {
                let res = poll_slot(&svc, 0, true, None);
                let found = if wants_latest {
                    res.xray_events.into_iter().next_back()
                } else {
                    res.xray_events
                        .into_iter()
                        .rev()
                        .find(|t| t.root_hash == needle || t.root_hash.starts_with(&needle))
                };
                if found.is_some() {
                    return found;
                }
            }
        }
        None
    })
    .await
    .map_err(|e| e.to_string())?;

    if let Some(found) = polled {
        ctx.wiretap.record_trace(found.clone());
        return Ok(found);
    }
    Err(format!(
        "no Zero-Payload X-Ray trace found for '{root_hash}'"
    ))
}
