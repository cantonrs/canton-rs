//! Lightweight loopback HTTP telemetry, readiness, X-Ray, inspection, and `--shadow-verify` probers.
//!
//! [CANTON-NOTE: WHY] Uses raw `TcpStream` HTTP/1.1 with bounded connect/read timeouts inside
//! `spawn_blocking` so supervisor tick latency stays deterministic with zero extra HTTP client crates.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::metrics::{ApiHistogram, NodeApiTelemetry};
use super::proc_sampler::{detect_jvm_canton_rss, OsProcSampler};
use super::wiretap::assemble_xray_trace;
use super::{
    now_unix_ms, DaemonServiceSpec, DarSummary, DomainMetrics, NodeRole, PingStatus,
    ShadowVerifySummary, XRayTraceEvent,
};

const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);

/// Returns `true` when `GET url` (with optional bearer token) responds with HTTP `200` within `per_try_timeout`.
pub fn probe_http_ok_bearer(url: &str, per_try_timeout: Duration, token: Option<&str>) -> bool {
    matches!(
        http_request_bearer(url, "GET", None, None, per_try_timeout, token),
        Ok((200, _))
    )
}

/// Parsed result of polling one managed node's HTTP status/telemetry/readiness endpoints.
pub struct NodePollResult {
    pub ready: bool,
    pub domain: DomainMetrics,
    pub api_telemetry: Option<NodeApiTelemetry>,
    pub xray_events: Vec<XRayTraceEvent>,
    pub max_xray_ms: u64,
}

/// Extracted domain layer fields returned for on-demand `NodeInspection`.
#[derive(Default)]
pub struct DomainInspectionData {
    pub node_uid: Option<String>,
    pub physical_synchronizer_id: Option<String>,
    pub protocol_version: Option<String>,
    pub loaded_dars: Vec<DarSummary>,
    pub hosted_parties: Vec<String>,
    pub user_count: Option<u64>,
}

/// Performs one synchronous HTTP/1.1 request against `http://host:port/path` with `PROBE_TIMEOUT`.
pub fn http_request(
    url: &str,
    method: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    http_request_bearer(url, method, body, content_type, timeout, None)
}

/// `GET url` with the node's bearer token when it has one.
fn authed_get(url: &str, token: Option<&str>) -> Result<(u16, String), String> {
    http_request_bearer(url, "GET", None, None, PROBE_TIMEOUT, token)
}

/// [`http_request`] with `Authorization: Bearer <token>` when `token` is given.
pub fn http_request_bearer(
    url: &str,
    method: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
    timeout: Duration,
    token: Option<&str>,
) -> Result<(u16, String), String> {
    let (status, body_bytes) =
        http_request_bearer_bytes(url, method, body, content_type, timeout, token)?;
    Ok((status, String::from_utf8_lossy(&body_bytes).into_owned()))
}

/// Like [`http_request_bearer`], preserving raw binary response bytes (e.g. DALF protobuf payloads).
pub fn http_request_bearer_bytes(
    url: &str,
    method: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
    timeout: Duration,
    token: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    if let Some(t) = token {
        if t.as_bytes().iter().any(|&b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err("bearer token contains forbidden CR/LF/NUL control characters".to_string());
        }
    }
    let (host, port, path) = parse_http_url(url)?;
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("invalid probe address {host}:{port}: {e}"))?;
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = body.unwrap_or(&[]);
    let ctype_hdr = content_type
        .map(|ct| format!("Content-Type: {ct}\r\n"))
        .unwrap_or_default();
    let auth_hdr = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth_hdr}{ctype_hdr}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write header to {addr}: {e}"))?;
    if !payload.is_empty() {
        stream
            .write_all(payload)
            .map_err(|e| format!("write body to {addr}: {e}"))?;
    }
    let _ = stream.flush();

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read response from {addr}: {e}"))?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("malformed HTTP response from {addr}"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("missing HTTP status from {addr}"))?;
    let body_bytes = decode_chunked_if_needed(&head, &raw[split + 4..]);
    Ok((status, body_bytes))
}

fn decode_chunked_if_needed(head: &str, body: &[u8]) -> Vec<u8> {
    if !head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return body.to_vec();
    }
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        let len_hex = String::from_utf8_lossy(&rest[..pos]);
        let size =
            usize::from_str_radix(len_hex.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        rest = &rest[pos + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
    out
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let no_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// URLs are supported for local probing: {url}"))?;
    let (host_port, rest) = match no_scheme.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (no_scheme, "/".to_string()),
    };
    let (host, port_str) = host_port
        .rsplit_once(':')
        .ok_or_else(|| format!("URL missing port: {url}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port in URL: {url}"))?;
    Ok((host.to_string(), port, rest))
}

/// Polls readiness, domain metrics, API telemetry, and new X-Ray traces for one running node slot.
pub fn poll_slot(
    svc: &DaemonServiceSpec,
    last_xray_ms: u64,
    collect_xray: bool,
    bft_height_hint: Option<u64>,
) -> NodePollResult {
    match svc.role {
        NodeRole::Participant => poll_participant(svc, last_xray_ms, collect_xray, bft_height_hint),
        NodeRole::Sequencer => poll_sequencer(svc),
        NodeRole::Mediator => poll_mediator(svc),
        NodeRole::Splice | NodeRole::Scan => poll_splice_or_scan(svc),
        NodeRole::Pqs => NodePollResult {
            ready: true,
            domain: DomainMetrics::Pqs {
                watermark_offset: 0,
                active_contracts: 0,
                connected: true,
            },
            api_telemetry: None,
            xray_events: Vec::new(),
            max_xray_ms: last_xray_ms,
        },
    }
}

fn poll_participant(
    svc: &DaemonServiceSpec,
    last_xray_ms: u64,
    collect_xray: bool,
    bft_height_hint: Option<u64>,
) -> NodePollResult {
    let token = svc.token.as_ref().and_then(super::TokenSource::read);
    let token = token.as_deref();
    let mut ready = false;
    let mut ready_reason = "port not listening".to_string();

    if let Some(url) = &svc.readiness_url {
        match authed_get(url, token) {
            Ok((200, _)) => {
                ready = true;
                ready_reason = "SERVING".to_string();
            }
            Ok((code, body)) => {
                ready = false;
                ready_reason = format!("HTTP {code}: {}", body.trim());
            }
            Err(err) => {
                ready = false;
                ready_reason = err;
            }
        }
    } else if svc.ports.all_ports().iter().any(|p| tcp_open(*p)) {
        ready = true;
        ready_reason = "listening".to_string();
    }

    let mut ledger_end_offset = 0;
    let mut active_contracts = 0;
    let mut hosted_parties = 0;
    let mut loaded_dars = 0;
    let mut api_requests_total = 0;
    let mut api_telemetry = None;

    if let Some(url) = &svc.status_url {
        if let Ok((200, body)) = authed_get(url, token) {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                ledger_end_offset = v["ledger_end"].as_u64().unwrap_or(0);
                active_contracts = v["active_contracts"].as_u64().unwrap_or(0);
                hosted_parties = v["hosted_parties"].as_u64().unwrap_or(0);
                loaded_dars = v["loaded_dars"].as_u64().unwrap_or(0);
                let parsed = parse_api_telemetry(&v);
                api_requests_total = parsed.requests_total.values().sum();
                api_telemetry = Some(parsed);
            }
        }
    }

    let mut xray_events = Vec::new();
    let mut max_xray_ms = last_xray_ms;
    if collect_xray {
        if let Some(base) = &svc.xray_url {
            let query_url = if last_xray_ms > 0 {
                format!("{base}?since_ms={}", last_xray_ms.saturating_add(1))
            } else {
                base.clone()
            };
            if let Ok((200, body)) = authed_get(&query_url, token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if let Some(arr) = v["traces"].as_array() {
                        for item in arr {
                            if let Some(trace) =
                                assemble_xray_trace(item, bft_height_hint, None, None, None)
                            {
                                max_xray_ms = max_xray_ms.max(trace.started_at_unix_ms);
                                xray_events.push(trace);
                            }
                        }
                    }
                }
            }
        }
    }

    NodePollResult {
        ready,
        domain: DomainMetrics::Participant {
            ledger_end_offset,
            active_contracts,
            hosted_parties,
            loaded_dars,
            ready,
            ready_reason,
            api_requests_total,
        },
        api_telemetry,
        xray_events,
        max_xray_ms,
    }
}

fn poll_sequencer(svc: &DaemonServiceSpec) -> NodePollResult {
    let mut head_offset = 0;
    let mut connected_members = 0;
    let manifest_peers = svc.bft_peer_count.map(|n| (n as u32, n as u32));
    let mut bft_quorum_peers = None;
    let mut ready = false;

    // [CANTON-NOTE: DEFENSIVE] Peers stay unknown unless the sequencer answered: the manifest's n would show a full quorum for a node
    // that does not respond.
    if let Some(url) = &svc.status_url {
        if let Ok((200, body)) = http_request(url, "GET", None, None, PROBE_TIMEOUT) {
            ready = true;
            bft_quorum_peers = manifest_peers;
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                head_offset = v["head_offset"].as_u64().unwrap_or(0);
                connected_members = v["connected_members"].as_u64().unwrap_or(0);
                if let Some(pair) = v["bft_quorum_peers"].as_array() {
                    if let (Some(c), Some(t)) = (
                        pair.first().and_then(Value::as_u64),
                        pair.get(1).and_then(Value::as_u64),
                    ) {
                        bft_quorum_peers = Some((c as u32, t as u32));
                    }
                }
            }
        }
    } else if svc.ports.public.is_some_and(tcp_open) {
        ready = true;
    }

    NodePollResult {
        ready,
        domain: DomainMetrics::Sequencer {
            head_offset,
            connected_members,
            bft_quorum_peers,
        },
        api_telemetry: None,
        xray_events: Vec::new(),
        max_xray_ms: 0,
    }
}

fn poll_mediator(svc: &DaemonServiceSpec) -> NodePollResult {
    let mut verdicts_approved = 0;
    let mut verdicts_rejected = 0;
    let mut pending_quorums = 0;
    let mut group_id = 0;

    let mut ready = if let Some(url) = &svc.readiness_url {
        matches!(
            http_request(url, "GET", None, None, PROBE_TIMEOUT),
            Ok((200, _))
        )
    } else {
        true
    };

    if let Some(url) = &svc.status_url {
        if let Ok((200, body)) = http_request(url, "GET", None, None, PROBE_TIMEOUT) {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                group_id = v["group"].as_u64().unwrap_or(0) as u32;
                verdicts_approved = v["verdicts_approved"].as_u64().unwrap_or(0);
                verdicts_rejected = v["verdicts_rejected"].as_u64().unwrap_or(0);
                pending_quorums = v["pending_quorums"].as_u64().unwrap_or(0);
                if v["connected"].as_bool() == Some(false) {
                    ready = false;
                }
            }
        }
    }

    NodePollResult {
        ready,
        domain: DomainMetrics::Mediator {
            group_id,
            verdicts_approved,
            verdicts_rejected,
            pending_quorums,
        },
        api_telemetry: None,
        xray_events: Vec::new(),
        max_xray_ms: 0,
    }
}

fn poll_splice_or_scan(svc: &DaemonServiceSpec) -> NodePollResult {
    let mut ready = false;
    let mut open_round = None;
    let mut scan_updates_total = 0;
    let mut ledger_backend_connected = false;

    if let Some(url) = &svc.readiness_url {
        if matches!(
            http_request(url, "GET", None, None, PROBE_TIMEOUT),
            Ok((200, _))
        ) {
            ready = true;
            ledger_backend_connected = true;
        }
    } else if svc.ports.http_json.is_some_and(tcp_open) {
        ready = true;
        ledger_backend_connected = true;
    }

    if let Some(url) = &svc.status_url {
        if let Ok((200, body)) = http_request(url, "GET", None, None, PROBE_TIMEOUT) {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                open_round = v["open_round"].as_u64();
                scan_updates_total = v["updates"].as_u64().unwrap_or(0);
                if let Some(conn) = v["ledger_backend_connected"].as_bool() {
                    ledger_backend_connected = conn;
                }
            }
        }
    }

    NodePollResult {
        ready,
        domain: DomainMetrics::Splice {
            open_round,
            scan_updates_total,
            ledger_backend_connected,
        },
        api_telemetry: None,
        xray_events: Vec::new(),
        max_xray_ms: 0,
    }
}

fn parse_api_telemetry(v: &Value) -> NodeApiTelemetry {
    let mut tel = NodeApiTelemetry::default();
    if let Some(arr) = v["requests_total"].as_array() {
        for item in arr {
            if let (Some(proto), Some(meth), Some(status), Some(count)) = (
                item["protocol"].as_str(),
                item["method"].as_str(),
                item["status"].as_u64().and_then(|s| u16::try_from(s).ok()),
                item["count"].as_u64(),
            ) {
                tel.requests_total
                    .insert((proto.to_string(), meth.to_string(), status), count);
            }
        }
    }
    if let Some(arr) = v["durations"].as_array() {
        for item in arr {
            if let (Some(proto), Some(meth)) = (item["protocol"].as_str(), item["method"].as_str())
            {
                let mut counts = [0u64; 10];
                if let Some(buckets) = item["bucket_counts"].as_array() {
                    for (i, slot) in counts.iter_mut().enumerate() {
                        *slot = buckets.get(i).and_then(Value::as_u64).unwrap_or(0);
                    }
                }
                tel.durations.insert(
                    (proto.to_string(), meth.to_string()),
                    ApiHistogram {
                        bucket_counts: counts,
                        total_count: item["total_count"].as_u64().unwrap_or(0),
                        total_sum_secs: item["total_sum_secs"].as_f64().unwrap_or(0.0),
                    },
                );
            }
        }
    }
    tel
}

/// Checks if a local loopback TCP port accepts connections within a brief 150ms probe.
pub fn tcp_open(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
}

/// Queries non-payload domain inspection fields (`uid`, `synchronizer`, `version`, DARs, parties, user count).
pub fn collect_domain_inspection(svc: &DaemonServiceSpec) -> DomainInspectionData {
    let mut out = DomainInspectionData::default();
    match svc.role {
        NodeRole::Participant => {
            let Some(http_port) = svc.ports.http_json else {
                return out;
            };
            let base = format!("http://127.0.0.1:{http_port}");
            let token = svc.token.as_ref().and_then(super::TokenSource::read);
            let token = token.as_deref();
            if let Ok((200, body)) = authed_get(&format!("{base}/v2/version"), token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    out.protocol_version = v["version"].as_str().map(String::from);
                }
            }
            if let Ok((200, body)) =
                authed_get(&format!("{base}/v2/state/connected-synchronizers"), token)
            {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if let Some(first) = v["connectedSynchronizers"]
                        .as_array()
                        .and_then(|a| a.first())
                    {
                        out.physical_synchronizer_id = first["synchronizerId"]
                            .as_str()
                            .or_else(|| first["physicalSynchronizerId"].as_str())
                            .map(String::from);
                    }
                }
            }
            if let Ok((200, body)) = authed_get(&format!("{base}/v2/packages"), token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if let Some(ids) = v["packageIds"].as_array() {
                        for id in ids.iter().filter_map(Value::as_str) {
                            out.loaded_dars.push(DarSummary {
                                name: svc
                                    .dars
                                    .first()
                                    .and_then(|p| p.file_name())
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("loaded")
                                    .to_string(),
                                version: None,
                                main_package_id: id.to_string(),
                                vetted: true,
                            });
                        }
                    }
                }
            }
            if let Ok((200, body)) = authed_get(&format!("{base}/v2/parties"), token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if let Some(details) = v["partyDetails"].as_array() {
                        out.hosted_parties = details
                            .iter()
                            .filter_map(|p| p["party"].as_str().map(String::from))
                            .collect();
                    }
                }
            }
            if let Ok((200, body)) = authed_get(&format!("{base}/v2/users"), token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    out.user_count = v["users"].as_array().map(|u| u.len() as u64);
                }
            }
            if let Ok((200, body)) = authed_get(&format!("{base}/_telemetry"), token) {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    out.node_uid = v["participant_id"].as_str().map(String::from);
                    if out.physical_synchronizer_id.is_none() {
                        out.physical_synchronizer_id =
                            v["synchronizer_id"].as_str().map(String::from);
                    }
                }
            }
        }
        NodeRole::Sequencer | NodeRole::Mediator => {
            if let Some(url) = &svc.status_url {
                if let Ok((200, body)) = http_request(url, "GET", None, None, PROBE_TIMEOUT) {
                    if let Ok(v) = serde_json::from_str::<Value>(&body) {
                        out.node_uid = v["sequencer_uid"]
                            .as_str()
                            .or_else(|| v["member"].as_str())
                            .map(String::from);
                        out.physical_synchronizer_id =
                            v["physical_synchronizer_id"].as_str().map(String::from);
                    }
                }
            }
        }
        NodeRole::Splice | NodeRole::Scan | NodeRole::Pqs => {}
    }
    out
}

/// Uploads additional Mode A DARs via `POST /v2/packages` after the primary DAR loads.
pub fn upload_extra_dar(
    http_port: u16,
    dar_path: &std::path::Path,
    token: Option<&str>,
) -> Result<(), String> {
    let bytes = std::fs::read(dar_path)
        .map_err(|e| format!("cannot read DAR {}: {e}", dar_path.display()))?;
    let url = format!("http://127.0.0.1:{http_port}/v2/packages");
    let (status, body) = http_request_bearer(
        &url,
        "POST",
        Some(&bytes),
        Some("application/octet-stream"),
        Duration::from_secs(15),
        token,
    )?;
    if status >= 300 {
        return Err(format!(
            "POST /v2/packages for {} answered HTTP {status}: {body}",
            dar_path.display()
        ));
    }
    Ok(())
}

/// One side of a `PingService/Ping`: a participant's Admin API port and the token the supervisor sends it.
pub struct PingEndpoint {
    pub name: String,
    pub admin_port: u16,
    pub token: Option<String>,
}

/// Runs an immediate end-to-end health ping (`PingService/Ping` when admin ports exist, else `/readyz`).
pub fn execute_cluster_ping(
    ping_pairs: &[(PingEndpoint, PingEndpoint)],
    fallback_participants: &[(String, Option<u16>)],
) -> PingStatus {
    if let Some((from, to)) = ping_pairs.first() {
        let (from_name, to_name) = (&from.name, &to.name);
        let started = Instant::now();
        return match crate::commands::daemon::run_admin_ping(from, to) {
            Ok(rtt) => PingStatus {
                ok: true,
                rtt_ms: rtt as f64,
                detail: format!("{from_name} -> {to_name}"),
                checked_at_unix_ms: now_unix_ms(),
            },
            Err(err) => PingStatus {
                ok: false,
                rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                detail: format!("{from_name} -> {to_name}: {err}"),
                checked_at_unix_ms: now_unix_ms(),
            },
        };
    }

    if let Some((name, Some(http_port))) = fallback_participants.first() {
        let started = Instant::now();
        let url = format!("http://127.0.0.1:{http_port}/readyz");
        return match http_request(&url, "GET", None, None, PROBE_TIMEOUT) {
            Ok((200, _)) => PingStatus {
                ok: true,
                rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                detail: format!("{name} /readyz"),
                checked_at_unix_ms: now_unix_ms(),
            },
            Ok((status, body)) => PingStatus {
                ok: false,
                rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                detail: format!("{name} /readyz HTTP {status}: {}", body.trim()),
                checked_at_unix_ms: now_unix_ms(),
            },
            Err(e) => PingStatus {
                ok: false,
                rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                detail: format!("{name} /readyz: {e}"),
                checked_at_unix_ms: now_unix_ms(),
            },
        };
    }

    PingStatus {
        ok: true,
        rtt_ms: 0.0,
        detail: "no participant HTTP/Admin endpoint registered".to_string(),
        checked_at_unix_ms: now_unix_ms(),
    }
}

/// Evaluates Shadow-Mode Dual Verifier state against an official JVM participant endpoint.
pub fn collect_shadow_verify(
    rust_ledger_end: Option<u64>,
    jvm_url: Option<&str>,
    jvm_token: Option<&str>,
    api_telemetry: &BTreeMap<String, NodeApiTelemetry>,
    sampler: &mut OsProcSampler,
) -> ShadowVerifySummary {
    let mut verified_tx_total = None;
    let mut mismatch_total = None;
    let mut match_ratio_percent = None;

    // [CANTON-NOTE: LIMITATION] Compares ledger-end offsets only, not root hashes or ACS contents.
    if let (Some(url), Some(rust_offset)) = (jvm_url, rust_ledger_end) {
        let trimmed = url.trim_end_matches('/');
        if let Ok((200, body)) = http_request_bearer(
            &format!("{trimmed}/v2/state/ledger-end"),
            "GET",
            None,
            None,
            PROBE_TIMEOUT,
            jvm_token,
        ) {
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                if let Some(jvm_offset) = v["offset"].as_u64() {
                    let verified = rust_offset.min(jvm_offset);
                    let mismatch = rust_offset.abs_diff(jvm_offset);
                    let total = verified.saturating_add(mismatch);
                    let ratio = if total == 0 {
                        100.0
                    } else {
                        (verified as f64 / total as f64) * 100.0
                    };
                    verified_tx_total = Some(verified);
                    mismatch_total = Some(mismatch);
                    match_ratio_percent = Some(ratio);
                }
            }
        }
    }

    let canton_rs_p99_ms = estimate_p99_ms(api_telemetry);
    let baseline_jvm_rss_bytes = detect_jvm_canton_rss(sampler);

    ShadowVerifySummary {
        verified_tx_total,
        mismatch_total,
        match_ratio_percent,
        baseline_jvm_rss_bytes,
        canton_rs_p99_ms,
    }
}

fn estimate_p99_ms(telemetry: &BTreeMap<String, NodeApiTelemetry>) -> f64 {
    let mut combined = [0u64; 10];
    let mut total = 0u64;
    for tel in telemetry.values() {
        for hist in tel.durations.values() {
            total = total.saturating_add(hist.total_count);
            for (i, c) in hist.bucket_counts.iter().enumerate() {
                combined[i] = combined[i].saturating_add(*c);
            }
        }
    }
    if total == 0 {
        return 0.0;
    }
    let threshold = ((total as f64) * 0.99).ceil() as u64;
    for (i, &le) in super::metrics::API_LATENCY_BUCKETS.iter().enumerate() {
        if combined[i] >= threshold {
            return le * 1000.0;
        }
    }
    5000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers `GET /v2/state/ledger-end` with `offset` on each of `n` connections.
    fn jvm_ledger_end(offset: u64, n: usize) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            for _ in 0..n {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);
                    let body = format!(r#"{{"offset":{offset}}}"#);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), h)
    }

    fn sequencer_spec(status_url: &str, bft_peer_count: Option<usize>) -> DaemonServiceSpec {
        let parsed = super::super::manifest::parse_yaml_manifest_str(
            "services:\n  seq1:\n    role: sequencer\n    ports: [\"5018:public\"]\n",
            std::path::Path::new("."),
            &BTreeMap::new(),
            None,
        )
        .expect("parse");
        let super::super::manifest::ParsedYamlManifest::ModeA(spec) = parsed else {
            panic!("expected ModeA");
        };
        let mut svc = spec.services[0].clone();
        svc.status_url = Some(status_url.to_string());
        svc.bft_peer_count = bft_peer_count;
        svc
    }

    /// The participant poll sends the manifest's token (read from its file on each poll), so a node with auth on still reports its
    /// ledger end; without the token the node answers 401 and nothing is read.
    #[test]
    fn participant_poll_sends_the_manifest_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let (status, body) = if head.contains("Authorization: Bearer abc\r\n") {
                    ("200 OK", r#"{"ledger_end":9}"#)
                } else {
                    ("401 Unauthorized", "{}")
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let dir = std::env::temp_dir().join(format!("canton-probe-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let token_file = dir.join("token");
        std::fs::write(&token_file, "abc\n").expect("write");
        let mut svc = sequencer_spec(&format!("http://127.0.0.1:{port}/_telemetry"), None);
        svc.role = NodeRole::Participant;
        svc.readiness_url = None;
        svc.xray_url = None;
        let ledger_end =
            |svc: &DaemonServiceSpec| match poll_participant(svc, 0, false, None).domain {
                DomainMetrics::Participant {
                    ledger_end_offset, ..
                } => ledger_end_offset,
                _ => u64::MAX,
            };
        assert_eq!(
            ledger_end(&svc),
            0,
            "negative control: no token, nothing read"
        );
        svc.token = Some(super::super::TokenSource::File(token_file));
        assert_eq!(ledger_end(&svc), 9);
        let _ = h.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sequencer whose status cannot be read reports its BFT peers as unknown, not the manifest's full quorum.
    #[test]
    fn unreachable_sequencer_status_leaves_bft_peers_unknown() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let svc = sequencer_spec(&format!("http://127.0.0.1:{port}/status"), Some(4));
        let poll = poll_sequencer(&svc);
        let DomainMetrics::Sequencer {
            bft_quorum_peers, ..
        } = poll.domain
        else {
            panic!("sequencer metrics");
        };
        assert!(!poll.ready);
        assert_eq!(bft_quorum_peers, None, "unknown, not (4, 4)");
    }

    /// Shadow-verify compares the Rust participant's ledger end with the JVM's; with no Rust offset known it leaves the comparison
    /// unknown (`None`) instead of reporting a fake `0` mismatch.
    #[test]
    fn shadow_verify_compares_the_rust_participant_ledger_end() {
        let mut sampler = OsProcSampler::new();
        let (url, h) = jvm_ledger_end(7, 2);
        let unknown = collect_shadow_verify(None, Some(&url), None, &BTreeMap::new(), &mut sampler);
        assert_eq!(unknown.verified_tx_total, None);
        assert_eq!(
            unknown.mismatch_total, None,
            "no Rust offset leaves mismatch unknown instead of reporting 0"
        );
        let same = collect_shadow_verify(Some(7), Some(&url), None, &BTreeMap::new(), &mut sampler);
        assert_eq!(
            (same.verified_tx_total, same.mismatch_total),
            (Some(7), Some(0))
        );
        let behind =
            collect_shadow_verify(Some(4), Some(&url), None, &BTreeMap::new(), &mut sampler);
        assert_eq!(behind.mismatch_total, Some(3));
        let _ = h.join();

        let err = http_request_bearer(
            "http://127.0.0.1:1/readyz",
            "GET",
            None,
            None,
            PROBE_TIMEOUT,
            Some("bad\r\ntoken"),
        )
        .expect_err("bearer token with CRLF must be refused before connecting");
        assert!(err.contains("CR/LF/NUL"), "{err}");
    }

    #[test]
    fn probes_loopback_http_server_cleanly() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let body = r#"{"status":"ok"}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let (code, body) = http_request(
            &format!("http://127.0.0.1:{port}/livez"),
            "GET",
            None,
            None,
            Duration::from_secs(2),
        )
        .expect("probe ok");
        assert_eq!(code, 200);
        assert!(body.contains("ok"));
        let _ = h.join();
    }
}
