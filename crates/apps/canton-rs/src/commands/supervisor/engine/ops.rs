use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::super::ipc::{DownProgressEvent, DAEMON_SOCKET_FILE};
use super::super::metrics::NodeApiTelemetry;
use super::super::probe::{collect_shadow_verify, execute_cluster_ping, poll_slot, PingEndpoint};
use super::super::proc_sampler::OsProcSampler;
use super::super::process::{graceful_stop_child_report, PidManifest, StopChildOutcome};
use super::super::wiretap::WIRE_TAP_ACTIVE;
use super::super::{
    now_unix_ms, DaemonServiceSpec, DomainMetrics, NodeLifecycleState, NodeRole, PingStatus,
    ProcResources, ResourceSample,
};
use super::{EngineContext, MAX_HISTORY_SAMPLES, READY_HANDSHAKE_FILE};

pub(super) async fn sample_and_poll_tick(
    ctx: &Arc<EngineContext>,
    mut sampler: OsProcSampler,
) -> OsProcSampler {
    let targets: Vec<(usize, Option<u32>, DaemonServiceSpec, u64)> = {
        let Ok(mut slots) = ctx.slots.lock() else {
            return sampler;
        };
        slots
            .iter_mut()
            .map(|s| {
                if s.state == NodeLifecycleState::Online
                    && s.online_since
                        .is_some_and(|since| since.elapsed() >= Duration::from_secs(60))
                {
                    s.consecutive_failures = 0;
                }
                (s.spec.slot_id, s.pid, s.spec.clone(), s.last_xray_ms)
            })
            .collect()
    };

    let collect_xray = WIRE_TAP_ACTIVE.load(Ordering::Relaxed);
    let shadow_verify_enabled = ctx.spec.shadow_verify;
    let shadow_jvm_url = ctx.spec.shadow_jvm_url.clone();
    let remote_clusters = ctx.spec.remote_clusters.clone();
    let local_slot_count = targets.len();
    let prev_tel = ctx
        .exporter
        .api_telemetry
        .read()
        .ok()
        .map(|g| g.clone())
        .unwrap_or_default();

    let (returned_sampler, sampled_rows, new_telemetry, shadow_opt, remote_nodes) =
        tokio::task::spawn_blocking(move || {
            let mut rows = Vec::with_capacity(targets.len());
            let mut tel_map: BTreeMap<String, NodeApiTelemetry> = BTreeMap::new();
            let mut bft_height_hint = None;
            let mut rust_ledger_end = None;
            let mut shadow_token = None;

            for (slot_id, pid_opt, svc, last_xray_ms) in targets {
                let Some(pid) = pid_opt else {
                    continue;
                };
                let res = sampler.sample_pid(pid);
                let poll = poll_slot(&svc, last_xray_ms, collect_xray, bft_height_hint);
                match &poll.domain {
                    DomainMetrics::Sequencer { head_offset, .. } => {
                        bft_height_hint = Some(*head_offset);
                    }
                    // the ledger end is known only when the status poll answered (it also yields the telemetry)
                    DomainMetrics::Participant {
                        ledger_end_offset, ..
                    } if rust_ledger_end.is_none() && poll.api_telemetry.is_some() => {
                        rust_ledger_end = Some(*ledger_end_offset);
                        shadow_token = svc.token.as_ref().and_then(super::super::TokenSource::read);
                    }
                    _ => {}
                }
                if let Some(tel) = &poll.api_telemetry {
                    tel_map.insert(svc.name.clone(), tel.clone());
                }
                rows.push((slot_id, res, poll));
            }

            let sv = if shadow_verify_enabled {
                let effective_tel = if tel_map.is_empty() {
                    &prev_tel
                } else {
                    &tel_map
                };
                Some(collect_shadow_verify(
                    rust_ledger_end,
                    shadow_jvm_url.as_deref(),
                    shadow_token.as_deref(),
                    effective_tel,
                    &mut sampler,
                ))
            } else {
                None
            };
            let remote = if remote_clusters.is_empty() {
                Vec::new()
            } else {
                super::super::topology::poll_remote_clusters(&remote_clusters, local_slot_count)
            };
            (sampler, rows, tel_map, sv, remote)
        })
        .await
        .unwrap_or_else(|_| {
            (
                OsProcSampler::new(),
                Vec::new(),
                BTreeMap::new(),
                None,
                Vec::new(),
            )
        });

    if !ctx.spec.remote_clusters.is_empty() {
        if let Ok(mut g) = ctx.remote_nodes_cache.write() {
            *g = remote_nodes;
        }
    }

    let ts = now_unix_ms();
    if let Ok(mut slots) = ctx.slots.lock() {
        for (slot_id, res, poll) in sampled_rows {
            let Some(slot) = slots.get_mut(slot_id) else {
                continue;
            };
            if slot.pid.is_none() {
                continue;
            }
            slot.resources = res;
            if slot.history.len() >= MAX_HISTORY_SAMPLES {
                slot.history.pop_front();
            }
            slot.history.push_back(ResourceSample {
                ts_unix_ms: ts,
                cpu_percent: res.cpu_percent,
                rss_bytes: res.rss_bytes,
            });
            slot.domain = poll.domain;
            if poll.max_xray_ms > slot.last_xray_ms {
                slot.last_xray_ms = poll.max_xray_ms;
            }
            for ev in poll.xray_events {
                ctx.wiretap.record_trace(ev);
            }
            let limit_exceeded = slot
                .spec
                .limits
                .and_then(|lim| lim.max_rss_mb)
                .is_some_and(|max_mb| res.rss_bytes > max_mb.saturating_mul(1024 * 1024));
            if limit_exceeded {
                ctx.log_hub.push(
                    &slot.spec.name,
                    &format!(
                        "WARN resource guard: RSS {} exceeds configured max_rss_mb limit",
                        super::super::format_bytes(res.rss_bytes)
                    ),
                );
            }
            let next_state = if poll.ready && !limit_exceeded {
                if slot.online_since.is_none() {
                    slot.online_since = Some(Instant::now());
                }
                NodeLifecycleState::Online
            } else {
                slot.online_since = None;
                NodeLifecycleState::Degraded
            };
            if !slot.stopping_intentionally && slot.state != NodeLifecycleState::Stopped {
                slot.state = next_state;
            }
        }
    }

    if !new_telemetry.is_empty() {
        if let Ok(mut g) = ctx.exporter.api_telemetry.write() {
            *g = new_telemetry;
        }
    }
    if let Some(sv) = shadow_opt {
        // [CANTON-NOTE: INVARIANT] Keep collect_shadow_verify's exact min/mismatch/unknown result without synthetic clamping.
        if let Ok(mut g) = ctx.shadow_verify.lock() {
            *g = Some(sv);
        }
    }

    returned_sampler
}

pub(super) async fn stop_slots_by_indices(
    ctx: &Arc<EngineContext>,
    indices: &[usize],
    timeout_secs: u64,
) -> Vec<String> {
    stop_slots_with_progress(ctx, indices, timeout_secs, None).await
}

pub(super) async fn stop_slots_with_progress(
    ctx: &Arc<EngineContext>,
    indices: &[usize],
    timeout_secs: u64,
    progress_tx: Option<&mpsc::UnboundedSender<DownProgressEvent>>,
) -> Vec<String> {
    let mut stopped_names = Vec::new();
    let total = indices.len();
    let grace = Duration::from_secs(timeout_secs.max(1));

    for (step_idx, &idx) in indices.iter().enumerate() {
        let step = step_idx + 1;
        let prep = {
            let Ok(mut slots) = ctx.slots.lock() else {
                break;
            };
            slots.get_mut(idx).map(|slot| {
                // [CANTON-NOTE: INVARIANT] Advance generation so any in-flight start/respawn for this slot cannot overwrite Stopped with Online (R-13i).
                slot.generation = slot.generation.saturating_add(1);
                let stop_gen = slot.generation;
                slot.auto_restart_paused = true;
                slot.stopping_intentionally = true;
                slot.backoff_until_ms = None;
                slot.online_since = None;
                let pid = slot.pid;
                let name = slot.spec.name.clone();
                let role = slot.spec.role.as_str().to_string();
                let ports = slot.spec.ports.summary();
                let child = slot.child.take();
                if child.is_none() {
                    slot.state = NodeLifecycleState::Stopped;
                    slot.pid = None;
                    slot.stopped_at_unix_ms = Some(now_unix_ms());
                    slot.stopping_intentionally = false;
                }
                (name, role, pid, ports, child, stop_gen)
            })
        };

        let Some((name, role, pid_opt, ports, child_opt, stop_gen)) = prep else {
            continue;
        };

        if let Some(child_arc) = child_opt {
            let pid_num = pid_opt.unwrap_or(0);
            if let Some(tx) = progress_tx {
                let _ = tx.send(DownProgressEvent::StoppingSlot {
                    step,
                    total,
                    name: name.clone(),
                    role: role.clone(),
                    pid: pid_num,
                    ports,
                    timeout_secs,
                });
            }
            let outcome = tokio::task::spawn_blocking(move || {
                if let Ok(mut g) = child_arc.lock() {
                    if let Some(mut child) = g.take() {
                        return graceful_stop_child_report(&mut child, grace);
                    }
                }
                StopChildOutcome::AlreadyExited
            })
            .await
            .unwrap_or(StopChildOutcome::AlreadyExited);

            if let Ok(mut slots) = ctx.slots.lock() {
                if let Some(slot) = slots.get_mut(idx) {
                    if slot.generation == stop_gen {
                        slot.pid = None;
                        slot.resources = ProcResources::default();
                        slot.state = NodeLifecycleState::Stopped;
                        slot.stopped_at_unix_ms = Some(now_unix_ms());
                        slot.stopping_intentionally = false;
                    }
                }
            }
            ctx.sync_pid_manifest();
            if let Some(tx) = progress_tx {
                let (elapsed_ms, forced_kill) = match outcome {
                    StopChildOutcome::AlreadyExited => (0, false),
                    StopChildOutcome::TerminatedGracefully { elapsed_ms } => (elapsed_ms, false),
                    StopChildOutcome::KilledAfterTimeout { elapsed_ms } => (elapsed_ms, true),
                };
                let _ = tx.send(DownProgressEvent::SlotStopped {
                    step,
                    total,
                    name: name.clone(),
                    role,
                    pid: pid_num,
                    elapsed_ms,
                    forced_kill,
                });
            }
        } else {
            ctx.sync_pid_manifest();
            if let Some(tx) = progress_tx {
                let _ = tx.send(DownProgressEvent::SlotSkipped {
                    step,
                    total,
                    name: name.clone(),
                    role,
                });
            }
        }
        stopped_names.push(name);
    }

    stopped_names
}

pub(super) async fn shutdown_all_slots(
    ctx: &Arc<EngineContext>,
    timeout_secs: u64,
    clean_files: bool,
    progress_tx: Option<mpsc::UnboundedSender<DownProgressEvent>>,
) -> usize {
    let started = Instant::now();
    let (rev_indices, order): (Vec<usize>, Vec<String>) = ctx
        .slots
        .lock()
        .map(|s| {
            let idxs: Vec<usize> = (0..s.len()).rev().collect();
            let names: Vec<String> = idxs.iter().map(|&i| s[i].spec.name.clone()).collect();
            (idxs, names)
        })
        .unwrap_or_default();

    if let Some(tx) = &progress_tx {
        let _ = tx.send(DownProgressEvent::Started {
            stack_name: ctx.spec.name.clone(),
            synchronizer: ctx.spec.synchronizer.clone(),
            storage_mode: ctx.storage_mode.clone(),
            state_dir: ctx.spec.state_dir.display().to_string(),
            timeout_secs,
            clean_files,
            order,
        });
    }

    let stopped =
        stop_slots_with_progress(ctx, &rev_indices, timeout_secs, progress_tx.as_ref()).await;
    let remaining_booting: Vec<super::super::process::PidEntry> = ctx
        .booting_pids
        .lock()
        .map(|mut map| {
            let drained = std::mem::take(&mut *map);
            drained.into_values().collect()
        })
        .unwrap_or_default();
    if !remaining_booting.is_empty() {
        let grace = Duration::from_secs(timeout_secs.clamp(1, 5));
        let _ = tokio::task::spawn_blocking(move || {
            for entry in remaining_booting {
                super::super::process::kill_pid_graceful(entry.pid, grace);
            }
        })
        .await;
    }
    PidManifest::remove(&ctx.spec.state_dir);
    let _ = std::fs::remove_file(ctx.spec.state_dir.join(READY_HANDSHAKE_FILE));
    let (removed_entries, refused) = if clean_files {
        match cleanup_local_state_files(&ctx.spec.state_dir) {
            Ok(n) => (n, None),
            Err(why) => (0, Some(why)),
        }
    } else {
        (0, None)
    };
    if let Some(tx) = &progress_tx {
        let _ = tx.send(DownProgressEvent::CleaningFiles {
            state_dir: ctx.spec.state_dir.display().to_string(),
            clean_files,
            removed_entries,
            refused,
        });
        let _ = tx.send(DownProgressEvent::Completed {
            stopped: stopped.len(),
            elapsed_ms: started.elapsed().as_millis() as u64,
            clean_files,
        });
    }
    stopped.len()
}

/// Cleans ONLY local files/sockets/logs inside `state_dir` on `daemon down --clean-files`.
///
/// [CANTON-NOTE: INVARIANT] PostgreSQL tables (`canton_rs_state` or official tables) are NEVER dropped.
pub fn cleanup_local_state_files(state_dir: &Path) -> Result<usize, String> {
    check_cleanable_state_dir(state_dir)?;
    let Ok(entries) = std::fs::read_dir(state_dir) else {
        return Ok(0);
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let p = entry.path();
        // Keep `daemon.sock` until `IpcSocketCleanup` drops at `run_supervisor` exit.
        if p.file_name().and_then(|n| n.to_str()) == Some(DAEMON_SOCKET_FILE) {
            continue;
        }
        let ok = if p.is_dir() {
            std::fs::remove_dir_all(&p).is_ok()
        } else {
            std::fs::remove_file(&p).is_ok()
        };
        if ok {
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}

/// Marker file the supervisor writes into a state directory it created (or found empty); `--clean-files` empties only marked directories.
pub const STATE_DIR_MARKER: &str = ".canton-rs-state-dir";

/// Marks `state_dir` as the supervisor's own when it is empty (just created), so `--clean-files` may later empty it.
pub(crate) fn mark_state_dir_if_empty(state_dir: &Path) {
    let empty = std::fs::read_dir(state_dir).is_ok_and(|mut e| e.next().is_none());
    if empty {
        let _ = std::fs::write(
            state_dir.join(STATE_DIR_MARKER),
            b"canton-rs supervisor state directory\n",
        );
    }
}

/// Refuses to empty a directory the supervisor did not mark, or one that holds the working directory or the home directory.
fn check_cleanable_state_dir(state_dir: &Path) -> Result<(), String> {
    let canonical = std::fs::canonicalize(state_dir)
        .map_err(|e| format!("cannot resolve state_dir {}: {e}", state_dir.display()))?;
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|d| std::fs::canonicalize(d).ok());
    let home = std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok());
    let holds_cwd = cwd.is_some_and(|c| c.starts_with(&canonical));
    let holds_home = home.is_some_and(|h| h.starts_with(&canonical));
    if canonical.parent().is_none() || holds_cwd || holds_home {
        return Err(format!(
            "refusing to empty {}: it is or contains the working or home directory",
            canonical.display()
        ));
    }
    if !canonical.join(STATE_DIR_MARKER).is_file() {
        return Err(format!(
            "refusing to empty {}: no {STATE_DIR_MARKER} marker (the supervisor did not create it); remove it by hand",
            canonical.display()
        ));
    }
    Ok(())
}

pub(super) fn run_ping_for_ctx(ctx: &Arc<EngineContext>) -> PingStatus {
    let (ping_pairs, fallback) = {
        let Ok(slots) = ctx.slots.lock() else {
            return PingStatus {
                ok: false,
                rtt_ms: 0.0,
                detail: "slot registry poisoned".to_string(),
                checked_at_unix_ms: now_unix_ms(),
            };
        };
        let endpoint = |name: &str| {
            slots
                .iter()
                .find(|s| s.spec.name == name && s.state != NodeLifecycleState::Stopped)
                .and_then(|s| {
                    s.spec.ports.admin.map(|admin_port| PingEndpoint {
                        name: name.to_string(),
                        admin_port,
                        token: s
                            .spec
                            .token
                            .as_ref()
                            .and_then(super::super::TokenSource::read),
                    })
                })
        };
        let mut pairs = Vec::new();
        for (from, to) in &ctx.spec.ping_participants {
            if let (Some(f), Some(t)) = (endpoint(from), endpoint(to)) {
                pairs.push((f, t));
            }
        }
        let participants: Vec<(String, Option<u16>)> = slots
            .iter()
            .filter(|s| {
                s.spec.role == NodeRole::Participant && s.state != NodeLifecycleState::Stopped
            })
            .map(|s| (s.spec.name.clone(), s.spec.ports.http_json))
            .collect();
        (pairs, participants)
    };
    execute_cluster_ping(&ping_pairs, &fallback)
}
