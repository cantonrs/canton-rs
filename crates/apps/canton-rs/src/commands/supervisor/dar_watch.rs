//! Debounced hot-watch and multi-participant DAR upload/vetting (`canton-rs daemon dar watch`, `S-DX-006`).
//!
//! [CANTON-NOTE: INVARIANT] Before sending any `POST /v2/packages` request to participants,
//! every modified DAR is parsed (`check_dar_for_upload`) and validated against the previously
//! uploaded version via `check_upgrade` (`R-A5`: failed parse or upgrade check leaves every
//! participant's package store unchanged and keeps the watcher running).

use std::collections::HashSet;
use std::fs;
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use lf_archive::LoadedDar;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use crate::commands::dar::check_upgrade_refs;
use crate::commands::exit_code::{exit_with_message, EXIT_PREFLIGHT};
use crate::commands::json_http;

use super::cli::{DaemonDarAction, DaemonDarCliArgs, DaemonDarWatchArgs};
use super::query::{parse_http_url, wait_shutdown_signal, EndpointTarget};

const POLL_INTERVAL_MS: u64 = 50;

/// Dispatches `canton-rs daemon dar <action>`.
pub fn cmd_daemon_dar(args: DaemonDarCliArgs) -> Result<(), String> {
    match args.action {
        DaemonDarAction::Watch(watch_args) => execute_dar_watch(&watch_args),
    }
}

fn execute_dar_watch(args: &DaemonDarWatchArgs) -> Result<(), String> {
    let endpoints = resolve_participant_endpoints(args.name.as_deref(), args.state_dir.as_deref())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
    rt.block_on(run_dar_watch_loop(args, &endpoints))
}

/// Discovers every participant JSON API endpoint registered under the target supervisor instance (`BTreeMap`-ordered).
fn resolve_participant_endpoints(
    name: Option<&str>,
    state_dir: Option<&Path>,
) -> Result<Vec<(String, EndpointTarget)>, String> {
    let dir = super::registry::resolve_target_state_dir(name, state_dir)
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let report = super::status::collect_daemon_status(&dir)
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let mut participants = Vec::new();
    for (label, ep) in &report.endpoints {
        if label.ends_with(".json") || label.ends_with("_json") {
            participants.push((label.clone(), parse_http_url(&ep.url)?));
        }
    }
    if participants.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("no Ledger JSON API endpoints found under {}", dir.display()),
        ));
    }
    Ok(participants)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

fn read_file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = fs::metadata(path).ok()?;
    meta.is_file().then(|| FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn emit_line(line: &str) -> Result<(), String> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{line}").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}

fn check_upgrade_against_prev(
    prev: Option<&LoadedDar>,
    candidate: &LoadedDar,
) -> Result<(), String> {
    match prev {
        Some(prior) => check_upgrade_refs(&[prior, candidate]),
        None => check_upgrade_refs(&[candidate]),
    }
}

fn participant_has_package(ep: &EndpointTarget, pkg_id: &str) -> Result<bool, String> {
    let (status, resp) = json_http::call(&ep.host, ep.port, "GET", "/v2/packages", None)?;
    if status != 200 {
        return Err(format!(
            "GET {}/v2/packages returned HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    }
    Ok(resp
        .get("packageIds")
        .and_then(Json::as_array)
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(pkg_id))))
}

fn participant_has_vetted_package(ep: &EndpointTarget, pkg_id: &str) -> Result<bool, String> {
    if !participant_has_package(ep, pkg_id)? {
        return Ok(false);
    }

    let req = json!({ "packageMetadataFilter": { "packageIds": [pkg_id] } });
    let (v_status, v_resp) = json_http::call_json(
        &ep.host,
        ep.port,
        "POST",
        "/v2/package-vetting/list",
        Some(&req),
    )?;
    if v_status != 200 {
        return Err(format!(
            "POST {}/v2/package-vetting/list returned HTTP {v_status}: {}",
            ep.base_url,
            json_http::error_cause(&v_resp)
        ));
    }
    let vetted = v_resp
        .get("vettedPackages")
        .and_then(Json::as_array)
        .is_some_and(|groups| {
            groups.iter().any(|group| {
                group
                    .get("packages")
                    .and_then(Json::as_array)
                    .is_some_and(|pkgs| {
                        pkgs.iter()
                            .any(|pkg| pkg.get("packageId").and_then(Json::as_str) == Some(pkg_id))
                    })
            })
        });
    Ok(vetted)
}

fn upload_and_vet_one(
    label: &str,
    ep: &EndpointTarget,
    bytes: &[u8],
    main_pkg_id: &str,
) -> Result<(), String> {
    let (status, resp) = json_http::call(
        &ep.host,
        ep.port,
        "POST",
        "/v2/packages",
        Some((bytes, "application/octet-stream")),
    )?;
    if status >= 300 {
        return Err(format!(
            "participant {label} ({}) rejected upload with HTTP {status}: {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    }
    if !participant_has_vetted_package(ep, main_pkg_id)? {
        return Err(format!(
            "participant {label} did not report package {main_pkg_id} as vetted after upload"
        ));
    }
    Ok(())
}

fn upload_and_vet_all(
    endpoints: &[(String, EndpointTarget)],
    bytes: &[u8],
    main_pkg_id: &str,
) -> Result<(), String> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = endpoints
            .iter()
            .map(|(label, ep)| {
                scope.spawn(move || upload_and_vet_one(label, ep, bytes, main_pkg_id))
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .map_err(|_| "participant upload worker thread panicked".to_string())??;
        }
        Ok(())
    })
}

async fn upload_with_timeout(
    endpoints: &[(String, EndpointTarget)],
    bytes: Vec<u8>,
    main_pkg_id: &str,
    timeout: Duration,
) -> Result<(), String> {
    let eps = endpoints.to_vec();
    let pkg_id = main_pkg_id.to_string();
    let handle = tokio::task::spawn_blocking(move || upload_and_vet_all(&eps, &bytes, &pkg_id));
    match tokio::time::timeout(timeout, handle).await {
        Ok(Ok(res)) => res,
        Ok(Err(join_err)) => Err(format!("upload worker failed: {join_err}")),
        Err(_) => Err(format!(
            "upload timed out after {}ms across {} participant(s)",
            timeout.as_millis(),
            endpoints.len()
        )),
    }
}

async fn process_candidate(
    path: &Path,
    endpoints: &[(String, EndpointTarget)],
    prev_dar: &mut Option<LoadedDar>,
    last_sha256: &mut Option<String>,
    is_initial: bool,
    timeout: Duration,
) -> Result<(), String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            emit_line(&format!("rejected: read error: {e}"))?;
            return Ok(());
        }
    };
    let digest = sha256_hex(&bytes);
    if last_sha256.as_deref() == Some(digest.as_str()) {
        return Ok(());
    }
    *last_sha256 = Some(digest);

    let loaded = match lf_archive::parse_loaded_dar_allow_dev(Cursor::new(&bytes)) {
        Ok(l) => l,
        Err(e) => {
            emit_line(&format!("rejected: parse error: {e}"))?;
            return Ok(());
        }
    };
    if let Err(e) = lf_archive::check_dar_for_upload(&loaded, &HashSet::new()) {
        emit_line(&format!("rejected: parse error: {e}"))?;
        return Ok(());
    }

    let main_pkg_id = loaded.archive.main_package_id.clone();

    // If the DAR on disk at startup is already loaded across every participant
    // (either via startup `--dar` or an earlier upload), adopt it as the upgrade
    // baseline without emitting a duplicate upload.
    if is_initial {
        let eps = endpoints.to_vec();
        let pkg = main_pkg_id.clone();
        let already_synced = tokio::task::spawn_blocking(move || -> bool {
            eps.iter()
                .all(|(_, ep)| participant_has_package(ep, &pkg).unwrap_or(false))
        })
        .await
        .unwrap_or(false);
        if already_synced {
            *prev_dar = Some(loaded);
            return Ok(());
        }
    }

    if let Err(e) = check_upgrade_against_prev(prev_dar.as_ref(), &loaded) {
        emit_line(&format!("rejected: {e}"))?;
        return Ok(());
    }

    match upload_with_timeout(endpoints, bytes, &main_pkg_id, timeout).await {
        Ok(()) => {
            *prev_dar = Some(loaded);
            emit_line(&format!("uploaded {main_pkg_id}"))?;
        }
        Err(e) => {
            emit_line(&format!("rejected: {e}"))?;
        }
    }
    Ok(())
}

async fn run_dar_watch_loop(
    args: &DaemonDarWatchArgs,
    endpoints: &[(String, EndpointTarget)],
) -> Result<(), String> {
    let debounce = Duration::from_millis(args.debounce_ms);
    let timeout = Duration::from_secs(args.timeout_secs.max(1));
    let mut prev_dar: Option<LoadedDar> = None;
    let mut last_sha256: Option<String> = None;
    let mut last_stamp = read_file_stamp(&args.path);
    let mut pending_since: Option<Instant> = None;

    if last_stamp.is_some() {
        process_candidate(
            &args.path,
            endpoints,
            &mut prev_dar,
            &mut last_sha256,
            true,
            timeout,
        )
        .await?;
    }

    {
        let mut stderr = io::stderr().lock();
        let _ = writeln!(
            stderr,
            "watching {} ({} participant(s), debounce={}ms)",
            args.path.display(),
            endpoints.len(),
            args.debounce_ms
        );
        let _ = stderr.flush();
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(POLL_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = wait_shutdown_signal() => {
                return Ok(());
            }
            _ = ticker.tick() => {
                let current_stamp = read_file_stamp(&args.path);
                if current_stamp != last_stamp {
                    last_stamp = current_stamp.clone();
                    if current_stamp.is_some() {
                        pending_since = Some(Instant::now());
                    } else {
                        pending_since = None;
                        last_sha256 = None;
                    }
                    continue;
                }
                if let Some(started_at) = pending_since {
                    if started_at.elapsed() >= debounce && last_stamp.is_some() {
                        pending_since = None;
                        process_candidate(
                            &args.path,
                            endpoints,
                            &mut prev_dar,
                            &mut last_sha256,
                            false,
                            timeout,
                        )
                        .await?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_dar(name: &str) -> LoadedDar {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/fixtures")
            .join(name)
            .join("target/sdx006-pkg.dar");
        lf_archive::load_dar_file_allow_dev(path).expect("load fixture")
    }

    #[test]
    fn upgrade_gate_allows_v2_and_blocks_v3_before_upload() {
        let v1 = fixture_dar("sdx006-v1");
        let v2 = fixture_dar("sdx006-v2");
        let v3 = fixture_dar("sdx006-v3-dropfield");

        assert!(check_upgrade_against_prev(Some(&v1), &v2).is_ok());
        let err = check_upgrade_against_prev(Some(&v2), &v3).expect_err("incompatible v3");
        assert!(err.contains("NOT_VALID_UPGRADE_PACKAGE"), "err={err}");
    }
}
