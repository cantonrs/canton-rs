//! Pure-Rust Prometheus 0.0.4 exporter, `daemon stats` table formatter, and `daemon ps --report` Markdown generator.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    format_bytes, format_uptime, ClusterSnapshot, DomainMetrics, NodeLifecycleState, NodeSnapshot,
};

/// Histogram bucket upper bounds for `canton_rs_api_request_duration_seconds`.
pub const API_LATENCY_BUCKETS: [f64; 10] =
    [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// All lifecycle state labels emitted by `canton_rs_node_state_info`.
const ALL_STATES: [&str; 6] = [
    "online",
    "bootstrapping",
    "degraded",
    "backoff",
    "stopped",
    "failed",
];

/// Scraped Tier-1 API counter/histogram series from an individual participant or gRPC node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeApiTelemetry {
    pub requests_total: BTreeMap<(String, String, u16), u64>,
    pub durations: BTreeMap<(String, String), ApiHistogram>,
}

/// Cumulative latency histogram matching [`API_LATENCY_BUCKETS`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApiHistogram {
    pub bucket_counts: [u64; 10],
    pub total_count: u64,
    pub total_sum_secs: f64,
}

/// Escapes a Prometheus label value per the text exposition format (`\\`, `\"`, `\n`).
pub fn escape_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Renders the complete Prometheus `0.0.4` cluster exposition containing all 26 metrics.
pub fn render_prometheus_metrics(
    snapshot: &ClusterSnapshot,
    api_telemetry: &BTreeMap<String, NodeApiTelemetry>,
) -> String {
    let mut out = String::with_capacity(8192);
    let sync = escape_label(&snapshot.synchronizer);

    // 1. canton_rs_node_up
    push_header(
        &mut out,
        "canton_rs_node_up",
        "gauge",
        "Node liveness and /readyz availability (1 = Online, 0 = Degraded/Down)",
    );
    for node in &snapshot.nodes {
        let val = u8::from(node.state == NodeLifecycleState::Online);
        let grp = escape_label(node.group.as_deref().unwrap_or("default"));
        out.push_str(&format!(
            "canton_rs_node_up{{synchronizer=\"{sync}\",group=\"{grp}\",role=\"{}\",node=\"{}\"}} {val}\n",
            escape_label(node.role.as_str()),
            escape_label(&node.name),
        ));
    }

    // 2. canton_rs_node_state_info
    push_header(
        &mut out,
        "canton_rs_node_state_info",
        "gauge",
        "One-hot lifecycle state of each supervised slot",
    );
    for node in &snapshot.nodes {
        let cur = node.state.prometheus_state();
        let grp = escape_label(node.group.as_deref().unwrap_or("default"));
        let role = escape_label(node.role.as_str());
        let name = escape_label(&node.name);
        for st in ALL_STATES {
            let v = u8::from(st == cur);
            out.push_str(&format!(
                "canton_rs_node_state_info{{synchronizer=\"{sync}\",group=\"{grp}\",role=\"{role}\",node=\"{name}\",state=\"{st}\"}} {v}\n"
            ));
        }
    }

    // 3..8. Node restarts, CPU, RSS, VMS, open FDs, uptime
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_restarts_total",
        "counter",
        "Total supervisor restarts recorded for this slot",
        |n| format!("{}", n.restarts_total),
    );
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_cpu_usage_ratio",
        "gauge",
        "Process CPU usage ratio (1.0 = 100% of one core)",
        |n| format!("{:.6}", n.resources.cpu_percent / 100.0),
    );
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_memory_rss_bytes",
        "gauge",
        "Process physical resident set size (RSS) in bytes",
        |n| format!("{}", n.resources.rss_bytes),
    );
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_memory_vms_bytes",
        "gauge",
        "Process virtual memory size (VMS) in bytes",
        |n| format!("{}", n.resources.vms_bytes),
    );
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_open_fds",
        "gauge",
        "Open file descriptor count of the managed process",
        |n| format!("{}", n.resources.open_fds),
    );
    emit_node_gauge(
        &mut out,
        snapshot,
        "canton_rs_node_uptime_seconds",
        "gauge",
        "Continuous uptime in seconds for the current child PID",
        |n| format!("{}", n.uptime_secs),
    );

    // 9. Cluster RSS total
    push_header(
        &mut out,
        "canton_rs_cluster_memory_rss_bytes_total",
        "gauge",
        "Sum of RSS bytes across all managed Canton nodes in the stack",
    );
    out.push_str(&format!(
        "canton_rs_cluster_memory_rss_bytes_total{{synchronizer=\"{sync}\"}} {}\n",
        snapshot.total_rss_bytes
    ));

    // 10. Last ping RTT
    push_header(
        &mut out,
        "canton_rs_last_ping_rtt_seconds",
        "gauge",
        "Last recorded health ping round-trip time in seconds",
    );
    if let Some(ping) = snapshot.last_ping.as_ref().filter(|p| p.ok) {
        out.push_str(&format!(
            "canton_rs_last_ping_rtt_seconds{{synchronizer=\"{sync}\"}} {:.6}\n",
            ping.rtt_ms / 1000.0
        ));
    }
    push_header(
        &mut out,
        "canton_rs_last_ping_ok",
        "gauge",
        "Whether the last health ping succeeded (1) or failed (0)",
    );
    if let Some(ping) = &snapshot.last_ping {
        out.push_str(&format!(
            "canton_rs_last_ping_ok{{synchronizer=\"{sync}\"}} {}\n",
            u8::from(ping.ok)
        ));
    }

    // 11..14. Participant metrics
    let participants: Vec<&NodeSnapshot> = snapshot
        .nodes
        .iter()
        .filter(|n| matches!(n.domain, DomainMetrics::Participant { .. }))
        .collect();
    push_header(
        &mut out,
        "canton_rs_ledger_end_offset",
        "gauge",
        "Participant ledger end offset",
    );
    for n in &participants {
        if let DomainMetrics::Participant {
            ledger_end_offset, ..
        } = &n.domain
        {
            let grp = escape_label(n.group.as_deref().unwrap_or("default"));
            out.push_str(&format!(
                "canton_rs_ledger_end_offset{{synchronizer=\"{sync}\",group=\"{grp}\",node=\"{}\"}} {ledger_end_offset}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_acs_active_contracts",
        "gauge",
        "Participant active contract set (ACS) count",
    );
    for n in &participants {
        if let DomainMetrics::Participant {
            active_contracts, ..
        } = &n.domain
        {
            let grp = escape_label(n.group.as_deref().unwrap_or("default"));
            out.push_str(&format!(
                "canton_rs_acs_active_contracts{{synchronizer=\"{sync}\",group=\"{grp}\",node=\"{}\"}} {active_contracts}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_hosted_parties",
        "gauge",
        "Participant hosted party count",
    );
    for n in &participants {
        if let DomainMetrics::Participant { hosted_parties, .. } = &n.domain {
            let grp = escape_label(n.group.as_deref().unwrap_or("default"));
            out.push_str(&format!(
                "canton_rs_hosted_parties{{synchronizer=\"{sync}\",group=\"{grp}\",node=\"{}\"}} {hosted_parties}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_loaded_dars",
        "gauge",
        "Participant loaded DAR archive count",
    );
    for n in &participants {
        if let DomainMetrics::Participant { loaded_dars, .. } = &n.domain {
            let grp = escape_label(n.group.as_deref().unwrap_or("default"));
            out.push_str(&format!(
                "canton_rs_loaded_dars{{synchronizer=\"{sync}\",group=\"{grp}\",node=\"{}\"}} {loaded_dars}\n",
                escape_label(&n.name)
            ));
        }
    }

    // 15..16. API requests & duration histogram
    push_header(
        &mut out,
        "canton_rs_api_requests_total",
        "counter",
        "Ledger API HTTP/gRPC requests handled per node, method, and status",
    );
    for (node, tel) in api_telemetry {
        let node_lbl = escape_label(node);
        for ((protocol, method, status), count) in &tel.requests_total {
            out.push_str(&format!(
                "canton_rs_api_requests_total{{node=\"{node_lbl}\",protocol=\"{}\",method=\"{}\",status=\"{status}\"}} {count}\n",
                escape_label(protocol),
                escape_label(method),
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_api_request_duration_seconds",
        "histogram",
        "Ledger API HTTP/gRPC request processing latency distribution",
    );
    for (node, tel) in api_telemetry {
        let node_lbl = escape_label(node);
        for ((protocol, method), hist) in &tel.durations {
            let p_lbl = escape_label(protocol);
            let m_lbl = escape_label(method);
            for (idx, le) in API_LATENCY_BUCKETS.iter().enumerate() {
                let c = hist.bucket_counts[idx];
                out.push_str(&format!(
                    "canton_rs_api_request_duration_seconds_bucket{{node=\"{node_lbl}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\",le=\"{le}\"}} {c}\n"
                ));
            }
            out.push_str(&format!(
                "canton_rs_api_request_duration_seconds_bucket{{node=\"{node_lbl}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\",le=\"+Inf\"}} {}\n",
                hist.total_count
            ));
            out.push_str(&format!(
                "canton_rs_api_request_duration_seconds_sum{{node=\"{node_lbl}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\"}} {:.6}\n",
                hist.total_sum_secs
            ));
            out.push_str(&format!(
                "canton_rs_api_request_duration_seconds_count{{node=\"{node_lbl}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\"}} {}\n",
                hist.total_count
            ));
        }
    }

    // 17..19. Sequencer metrics
    let sequencers: Vec<&NodeSnapshot> = snapshot
        .nodes
        .iter()
        .filter(|n| matches!(n.domain, DomainMetrics::Sequencer { .. }))
        .collect();
    push_header(
        &mut out,
        "canton_rs_sequencer_head_offset",
        "gauge",
        "Sequencer current sequencing head offset",
    );
    for n in &sequencers {
        if let DomainMetrics::Sequencer { head_offset, .. } = &n.domain {
            out.push_str(&format!(
                "canton_rs_sequencer_head_offset{{synchronizer=\"{sync}\",node=\"{}\"}} {head_offset}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_sequencer_connected_members",
        "gauge",
        "Members registered with the sequencer (not live connections)",
    );
    for n in &sequencers {
        if let DomainMetrics::Sequencer {
            connected_members, ..
        } = &n.domain
        {
            out.push_str(&format!(
                "canton_rs_sequencer_connected_members{{synchronizer=\"{sync}\",node=\"{}\"}} {connected_members}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_bft_quorum_peers",
        "gauge",
        "Active peers connected in BFT consensus quorum",
    );
    for n in &sequencers {
        if let DomainMetrics::Sequencer {
            bft_quorum_peers, ..
        } = &n.domain
        {
            let peers = bft_quorum_peers
                .map(|(connected, _)| connected)
                .unwrap_or(0);
            out.push_str(&format!(
                "canton_rs_bft_quorum_peers{{synchronizer=\"{sync}\",node=\"{}\"}} {peers}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_bft_configured_peers",
        "gauge",
        "BFT peers configured for this sequencer's ordering cluster (n in n = 3f + 1)",
    );
    for n in &sequencers {
        if let DomainMetrics::Sequencer {
            bft_quorum_peers: Some((_, configured)),
            ..
        } = &n.domain
        {
            out.push_str(&format!(
                "canton_rs_bft_configured_peers{{synchronizer=\"{sync}\",node=\"{}\"}} {configured}\n",
                escape_label(&n.name)
            ));
        }
    }

    // 20..21. Mediator metrics
    let mediators: Vec<&NodeSnapshot> = snapshot
        .nodes
        .iter()
        .filter(|n| matches!(n.domain, DomainMetrics::Mediator { .. }))
        .collect();
    push_header(
        &mut out,
        "canton_rs_mediator_verdicts_total",
        "counter",
        "Cumulative mediator 2PC verdicts by decision (approve/reject)",
    );
    for n in &mediators {
        if let DomainMetrics::Mediator {
            verdicts_approved,
            verdicts_rejected,
            ..
        } = &n.domain
        {
            let lbl = escape_label(&n.name);
            out.push_str(&format!(
                "canton_rs_mediator_verdicts_total{{synchronizer=\"{sync}\",node=\"{lbl}\",verdict=\"approve\"}} {verdicts_approved}\n"
            ));
            out.push_str(&format!(
                "canton_rs_mediator_verdicts_total{{synchronizer=\"{sync}\",node=\"{lbl}\",verdict=\"reject\"}} {verdicts_rejected}\n"
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_mediator_pending_quorums",
        "gauge",
        "In-flight 2PC confirmation transactions awaiting mediator quorum",
    );
    for n in &mediators {
        if let DomainMetrics::Mediator {
            pending_quorums, ..
        } = &n.domain
        {
            out.push_str(&format!(
                "canton_rs_mediator_pending_quorums{{synchronizer=\"{sync}\",node=\"{}\"}} {pending_quorums}\n",
                escape_label(&n.name)
            ));
        }
    }

    // 22. Wiretap drops
    push_header(
        &mut out,
        "canton_rs_xray_dropped_events_total",
        "counter",
        "Cumulative X-Ray wiretap events dropped by non-blocking try_send",
    );
    out.push_str(&format!(
        "canton_rs_xray_dropped_events_total{{synchronizer=\"{sync}\"}} {}\n",
        snapshot.wiretap_dropped_events
    ));

    // 23..24. Shadow verify metrics: one cluster-wide value that can go down between scrapes.
    let shadow = snapshot.shadow_verify.as_ref();
    push_header(
        &mut out,
        "canton_rs_shadow_verified_tx_total",
        "gauge",
        "Ledger offsets the Rust participant and the official JVM participant both reached",
    );
    if let Some(verified) = shadow.and_then(|sv| sv.verified_tx_total) {
        out.push_str(&format!(
            "canton_rs_shadow_verified_tx_total{{synchronizer=\"{sync}\"}} {verified}\n"
        ));
    }
    push_header(
        &mut out,
        "canton_rs_shadow_mismatch_total",
        "gauge",
        "Ledger end offset gap between the Rust participant and the official JVM participant",
    );
    if let Some(mismatch) = shadow.and_then(|sv| sv.mismatch_total) {
        out.push_str(&format!(
            "canton_rs_shadow_mismatch_total{{synchronizer=\"{sync}\"}} {mismatch}\n"
        ));
    }

    // 25..26. Splice / Scan metrics
    let splices: Vec<&NodeSnapshot> = snapshot
        .nodes
        .iter()
        .filter(|n| matches!(n.domain, DomainMetrics::Splice { .. }))
        .collect();
    push_header(
        &mut out,
        "canton_rs_splice_open_round",
        "gauge",
        "Current OpenMiningRound number observed by Splice",
    );
    for n in &splices {
        if let DomainMetrics::Splice {
            open_round: Some(round),
            ..
        } = &n.domain
        {
            out.push_str(&format!(
                "canton_rs_splice_open_round{{node=\"{}\"}} {round}\n",
                escape_label(&n.name)
            ));
        }
    }
    push_header(
        &mut out,
        "canton_rs_scan_updates_ingested_total",
        "counter",
        "Cumulative ledger updates ingested by Scan / Splice apps",
    );
    for n in &splices {
        if let DomainMetrics::Splice {
            scan_updates_total, ..
        } = &n.domain
        {
            out.push_str(&format!(
                "canton_rs_scan_updates_ingested_total{{node=\"{}\"}} {scan_updates_total}\n",
                escape_label(&n.name)
            ));
        }
    }

    super::observability::append_official_metric_aliases(&mut out, snapshot);
    out
}

fn push_header(out: &mut String, name: &str, kind: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
}

fn emit_node_gauge<F>(
    out: &mut String,
    snapshot: &ClusterSnapshot,
    metric: &str,
    kind: &str,
    help: &str,
    value_fn: F,
) where
    F: Fn(&NodeSnapshot) -> String,
{
    push_header(out, metric, kind, help);
    let sync = escape_label(&snapshot.synchronizer);
    // [CANTON-NOTE: SEMANTICS] Every node-scoped OpenMetrics series carries `group="<cell>"`
    // (falling back to `"default"` when ungrouped) so Prometheus/Grafana can stack RSS, CPU,
    // liveness, and ACS privacy bars per institutional cell without label-cardinality gaps.
    for node in &snapshot.nodes {
        let val = value_fn(node);
        let grp = escape_label(node.group.as_deref().unwrap_or("default"));
        out.push_str(&format!(
            "{metric}{{synchronizer=\"{sync}\",group=\"{grp}\",role=\"{}\",node=\"{}\"}} {val}\n",
            escape_label(node.role.as_str()),
            escape_label(&node.name),
        ));
    }
}

/// Shared state exported by the background cluster Prometheus HTTP endpoint.
#[derive(Clone, Default)]
pub struct ExporterState {
    pub snapshot: Arc<RwLock<Option<ClusterSnapshot>>>,
    pub api_telemetry: Arc<RwLock<BTreeMap<String, NodeApiTelemetry>>>,
}

/// One response from a [`serve_tiny_http`] handler.
pub struct TinyResponse {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: String,
}

impl TinyResponse {
    fn text(status: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into(),
        }
    }
}

/// Connections served at once; further ones are closed unanswered.
const MAX_CONCURRENT_CONNECTIONS: usize = 32;
/// Shorter than the supervisor probe timeout (2.5 s) so a stuck client never outlives a probe.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECTION_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves `GET <path>` on `listener`, one thread per connection, until `shutdown` is set.
///
/// Shared by the supervisor exporter and the mediator health port.
pub fn serve_tiny_http<H>(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    handler: H,
) -> Result<std::thread::JoinHandle<()>, String>
where
    H: Fn(&str) -> TinyResponse + Send + Sync + 'static,
{
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("cannot configure HTTP listener: {e}"))?;
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    Ok(std::thread::spawn(move || {
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
                        active.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                    let slot = ActiveConnection(Arc::clone(&active));
                    let handler = Arc::clone(&handler);
                    // A failed spawn drops the closure, and with it `slot`.
                    let _ = std::thread::Builder::new()
                        .name("tiny-http-conn".into())
                        .spawn(move || {
                            let _slot = slot;
                            serve_connection(stream, handler.as_ref());
                        });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                // [CANTON-NOTE: DEFENSIVE] EMFILE, ECONNABORTED and the like are transient; the
                // endpoint must outlive them rather than stop answering for the process lifetime.
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }))
}

fn serve_connection(mut stream: std::net::TcpStream, handler: &dyn Fn(&str) -> TinyResponse) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECTION_WRITE_TIMEOUT));
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    let resp = handler(path);
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        resp.content_type,
        resp.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(resp.body.as_bytes());
    let _ = stream.flush();
}

/// Binds `--metrics-bind:metrics-port` and serves `/metrics`, `/livez`, `/readyz` until stopped.
pub fn spawn_metrics_server(
    bind: &str,
    port: u16,
    state: ExporterState,
    shutdown: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let addr: SocketAddr = format!("{bind}:{port}")
        .parse()
        .map_err(|e| format!("invalid metrics bind address {bind}:{port}: {e}"))?;
    let listener = TcpListener::bind(addr)
        .map_err(|e| format!("cannot bind supervisor metrics on {addr}: {e}"))?;
    serve_tiny_http(listener, shutdown, move |path| {
        exporter_response(&state, path)
    })
}

fn exporter_response(state: &ExporterState, path: &str) -> TinyResponse {
    let snapshot = || {
        state
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    match path {
        "/livez" => TinyResponse::text("200 OK", "ok\n"),
        "/readyz" => match snapshot() {
            Some(s)
                if !s.nodes.is_empty()
                    && s.nodes.iter().all(|node| {
                        node.state == NodeLifecycleState::Online
                            || node.state == NodeLifecycleState::Stopped
                    }) =>
            {
                TinyResponse::text("200 OK", "[+] supervisor ok\nreadyz check passed\n")
            }
            Some(_) => TinyResponse::text(
                "503 Service Unavailable",
                "[-] one or more supervised nodes are degraded or bootstrapping\n",
            ),
            None => TinyResponse::text(
                "503 Service Unavailable",
                "[-] cluster snapshot not yet initialized\n",
            ),
        },
        "/metrics" => {
            let tel = state
                .api_telemetry
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            TinyResponse {
                status: "200 OK",
                content_type: "text/plain; version=0.0.4; charset=utf-8",
                body: snapshot()
                    .map(|s| render_prometheus_metrics(&s, &tel))
                    .unwrap_or_default(),
            }
        }
        "/snapshot" => TinyResponse {
            status: "200 OK",
            content_type: "application/json",
            body: snapshot()
                .and_then(|s| serde_json::to_string_pretty(&s).ok())
                .unwrap_or_else(|| "null".to_string()),
        },
        _ => TinyResponse::text("404 Not Found", "not found\n"),
    }
}

/// Formats `canton-rs daemon stats` resource table aligned to `02-metrics-prometheus-and-tui.md` §1.3.
pub fn render_stats_table(snapshot: &ClusterSnapshot) -> String {
    let mut lines = Vec::with_capacity(snapshot.nodes.len() + 2);
    lines.push(format!(
        "{:<3} {:<16} {:<7} {:<7} {:<16} {:<11} {:<5} {:<8} {:<10} {}",
        "ID",
        "NAME",
        "PID",
        "CPU %",
        "MEM USAGE (RSS)",
        "MEM (VMS)",
        "FDS",
        "THREADS",
        "UPTIME",
        "RESTARTS"
    ));
    for n in &snapshot.nodes {
        let pid = n.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
        let (cpu, rss, vms, fds, threads, uptime) = if n.pid.is_some() {
            (
                format!("{:.2}%", n.resources.cpu_percent),
                format_bytes(n.resources.rss_bytes),
                format_bytes(n.resources.vms_bytes),
                n.resources.open_fds.to_string(),
                n.resources.thread_count.to_string(),
                format_uptime(n.uptime_secs),
            )
        } else {
            (
                "--".into(),
                "--".into(),
                "--".into(),
                "-".into(),
                "-".into(),
                if n.state == NodeLifecycleState::Stopped {
                    "Exited".into()
                } else {
                    n.state.display_label().into()
                },
            )
        };
        lines.push(format!(
            "{:<3} {:<16} {:<7} {:<7} {:<16} {:<11} {:<5} {:<8} {:<10} {}",
            n.slot_id, n.name, pid, cpu, rss, vms, fds, threads, uptime, n.restarts_total
        ));
    }
    lines.join("\n")
}

/// Generates Markdown footprint report (`daemon ps --report` and TUI `[e]` export) with zero secrets.
pub fn render_markdown_report(snapshot: &ClusterSnapshot) -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let cpus = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    let up_count = snapshot
        .nodes
        .iter()
        .filter(|n| n.state == NodeLifecycleState::Online)
        .count();
    let mut out = String::new();
    out.push_str(&format!(
        "# canton-rs Cluster Footprint Report ({})\n\n",
        snapshot.stack_name
    ));
    out.push_str(&format!(
        "- **Host**: `{os}/{arch}` ({cpus} logical CPUs)\n"
    ));
    out.push_str(&format!(
        "- **Synchronizer**: `{}` (`{}` storage)\n",
        snapshot.synchronizer, snapshot.storage_mode
    ));
    out.push_str(&format!(
        "- **Availability**: {up_count}/{} Up | **Total RSS**: {} | **Total CPU**: {:.2}%\n",
        snapshot.nodes.len(),
        format_bytes(snapshot.total_rss_bytes),
        snapshot.total_cpu_percent
    ));
    if let Some(ping) = &snapshot.last_ping {
        out.push_str(&format!(
            "- **Health Ping**: {} ({:.2} ms — {})\n",
            if ping.ok { "OK" } else { "FAIL" },
            ping.rtt_ms,
            ping.detail
        ));
    }
    if let Some(sv) = &snapshot.shadow_verify {
        let rss_suffix = sv
            .baseline_jvm_rss_bytes
            .map(|r| format!(", JVM baseline RSS={}", format_bytes(r)))
            .unwrap_or_default();
        match (
            sv.verified_tx_total,
            sv.mismatch_total,
            sv.match_ratio_percent,
        ) {
            (Some(v), Some(m), Some(r)) => out.push_str(&format!(
                "- **Shadow Verify**: {}/{} matched ({:.2}%), mismatches={}, p99={:.2}ms{}\n",
                v,
                v.saturating_add(m),
                r,
                m,
                sv.canton_rs_p99_ms,
                rss_suffix
            )),
            _ => out.push_str(&format!(
                "- **Shadow Verify**: unknown (JVM/Rust ledger-end unavailable), p99={:.2}ms{}\n",
                sv.canton_rs_p99_ms, rss_suffix
            )),
        }
    }
    out.push_str(
        "\n| Slot | Name | Role | PID | State | CPU % | RSS | FDs | Restarts | Domain Summary |\n",
    );
    out.push_str("|---|---|---|---|---|---:|---:|---:|---:|---|\n");
    for n in &snapshot.nodes {
        let domain_summary = match &n.domain {
            DomainMetrics::Participant {
                ledger_end_offset,
                active_contracts,
                hosted_parties,
                loaded_dars,
                ready,
                ..
            } => format!(
                "offset={ledger_end_offset}, acs={active_contracts}, parties={hosted_parties}, dars={loaded_dars}, ready={ready}"
            ),
            DomainMetrics::Sequencer {
                head_offset,
                connected_members,
                bft_quorum_peers,
            } => format!(
                "head={head_offset}, members={connected_members}, bft={bft_quorum_peers:?}"
            ),
            DomainMetrics::Mediator {
                group_id,
                verdicts_approved,
                verdicts_rejected,
                pending_quorums,
            } => format!(
                "group={group_id}, approved={verdicts_approved}, rejected={verdicts_rejected}, pending={pending_quorums}"
            ),
            DomainMetrics::Splice {
                open_round,
                scan_updates_total,
                ledger_backend_connected,
            } => format!(
                "open_round={open_round:?}, updates={scan_updates_total}, ledger_connected={ledger_backend_connected}"
            ),
            DomainMetrics::Pqs {
                watermark_offset,
                active_contracts,
                connected,
            } => format!(
                "watermark={watermark_offset}, active={active_contracts}, connected={connected}"
            ),
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.2}% | {} | {} | {} | {} |\n",
            n.slot_id,
            n.name,
            n.role,
            n.pid.map_or_else(|| "-".into(), |p| p.to_string()),
            n.state.display_label(),
            n.resources.cpu_percent,
            format_bytes(n.resources.rss_bytes),
            n.resources.open_fds,
            n.restarts_total,
            domain_summary
        ));
    }
    out
}

#[cfg(test)]
#[path = "monitoring_kit_tests.rs"]
mod monitoring_kit_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::supervisor::{
        NodePorts, PingStatus, ProcResources, RestartPolicy, ShadowVerifySummary,
    };

    #[test]
    fn renders_all_26_prometheus_metric_families_cleanly() {
        let snap = ClusterSnapshot {
            stack_name: "test-stack".into(),
            synchronizer: "sync\"0\\a".into(),
            storage_mode: "postgres".into(),
            collected_at_unix_ms: 1_700_000_000_000,
            total_cpu_percent: 3.0,
            total_rss_bytes: 100_000,
            last_ping: Some(PingStatus {
                ok: true,
                rtt_ms: 2.5,
                detail: "p1 -> p1".into(),
                checked_at_unix_ms: 1_700_000_000_000,
            }),
            shadow_verify: Some(ShadowVerifySummary {
                verified_tx_total: Some(42),
                mismatch_total: Some(0),
                match_ratio_percent: Some(100.0),
                baseline_jvm_rss_bytes: Some(1_000_000_000),
                canton_rs_p99_ms: 4.2,
            }),
            wiretap_dropped_events: 1,
            scenarios: vec![],
            metrics_port: None,
            metrics_bind: None,
            nodes: vec![
                NodeSnapshot {
                    slot_id: 0,
                    role: super::super::NodeRole::Sequencer,
                    name: "seq1".into(),
                    group: None,
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(100),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 60,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Sequencer {
                        head_offset: 10,
                        connected_members: 3,
                        bft_quorum_peers: Some((4, 4)),
                    },
                },
                NodeSnapshot {
                    slot_id: 1,
                    role: super::super::NodeRole::Mediator,
                    name: "med1".into(),
                    group: None,
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(101),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 59,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Mediator {
                        group_id: 0,
                        verdicts_approved: 12,
                        verdicts_rejected: 1,
                        pending_quorums: 2,
                    },
                },
                NodeSnapshot {
                    slot_id: 2,
                    role: super::super::NodeRole::Participant,
                    name: "p1".into(),
                    group: Some("bank-\"a".into()),
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(102),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 1,
                    consecutive_failures: 0,
                    uptime_secs: 58,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Participant {
                        ledger_end_offset: 10,
                        active_contracts: 5,
                        hosted_parties: 2,
                        loaded_dars: 1,
                        ready: true,
                        ready_reason: "ok".into(),
                        api_requests_total: 9,
                    },
                },
                NodeSnapshot {
                    slot_id: 3,
                    role: super::super::NodeRole::Splice,
                    name: "splice1".into(),
                    group: None,
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(103),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 57,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Splice {
                        open_round: Some(4),
                        scan_updates_total: 7,
                        ledger_backend_connected: true,
                    },
                },
            ],
        };

        let mut tel = BTreeMap::new();
        let hist = ApiHistogram {
            bucket_counts: [1; 10],
            total_count: 1,
            total_sum_secs: 0.002,
        };
        tel.insert(
            "p1".to_string(),
            NodeApiTelemetry {
                requests_total: BTreeMap::from([(
                    (
                        "http".to_string(),
                        "POST /v2/commands/submit-and-wait".to_string(),
                        200,
                    ),
                    9,
                )]),
                durations: BTreeMap::from([(
                    (
                        "http".to_string(),
                        "POST /v2/commands/submit-and-wait".to_string(),
                    ),
                    hist,
                )]),
            },
        );

        let txt = render_prometheus_metrics(&snap, &tel);
        let expected_families = [
            "canton_rs_node_up",
            "canton_rs_node_state_info",
            "canton_rs_node_restarts_total",
            "canton_rs_node_cpu_usage_ratio",
            "canton_rs_node_memory_rss_bytes",
            "canton_rs_node_memory_vms_bytes",
            "canton_rs_node_open_fds",
            "canton_rs_node_uptime_seconds",
            "canton_rs_cluster_memory_rss_bytes_total",
            "canton_rs_last_ping_rtt_seconds",
            "canton_rs_ledger_end_offset",
            "canton_rs_acs_active_contracts",
            "canton_rs_hosted_parties",
            "canton_rs_loaded_dars",
            "canton_rs_api_requests_total",
            "canton_rs_api_request_duration_seconds",
            "canton_rs_sequencer_head_offset",
            "canton_rs_sequencer_connected_members",
            "canton_rs_bft_quorum_peers",
            "canton_rs_mediator_verdicts_total",
            "canton_rs_mediator_pending_quorums",
            "canton_rs_xray_dropped_events_total",
            "canton_rs_shadow_verified_tx_total",
            "canton_rs_shadow_mismatch_total",
            "canton_rs_splice_open_round",
            "canton_rs_scan_updates_ingested_total",
        ];
        for fam in expected_families {
            let hdr = format!("# TYPE {fam} ");
            assert_eq!(
                txt.matches(&hdr).count(),
                1,
                "metric family {fam} missing or duplicated header"
            );
        }
        assert!(txt.contains("synchronizer=\"sync\\\"0\\\\a\""));
        assert!(txt.contains("group=\"default\",role=\"mediator\",node=\"med1\""));
        assert!(txt.contains("group=\"bank-\\\"a\",role=\"participant\",node=\"p1\""));
        assert!(txt.contains("canton_rs_acs_active_contracts{synchronizer=\"sync\\\"0\\\\a\",group=\"bank-\\\"a\",node=\"p1\"} 5"));
        assert!(!txt.contains("group=\"bank-\"a\""));
    }

    fn snapshot_with(
        nodes: Vec<NodeSnapshot>,
        shadow: Option<ShadowVerifySummary>,
    ) -> ClusterSnapshot {
        ClusterSnapshot {
            stack_name: "s".into(),
            synchronizer: "sync".into(),
            storage_mode: "memory".into(),
            collected_at_unix_ms: 0,
            total_cpu_percent: 0.0,
            total_rss_bytes: 0,
            last_ping: None,
            shadow_verify: shadow,
            wiretap_dropped_events: 0,
            scenarios: vec![],
            metrics_port: None,
            metrics_bind: None,
            nodes,
        }
    }

    fn node(name: &str, role: super::super::NodeRole, domain: DomainMetrics) -> NodeSnapshot {
        NodeSnapshot {
            slot_id: 0,
            role,
            name: name.into(),
            group: None,
            synchronizer_domain: None,
            host_label: None,
            pid: Some(1),
            ports: NodePorts::default(),
            state: NodeLifecycleState::Online,
            restart_policy: RestartPolicy::UnlessStopped,
            restarts_total: 0,
            consecutive_failures: 0,
            uptime_secs: 0,
            stopped_at_unix_ms: None,
            last_exit_reason: None,
            resources: ProcResources::default(),
            history_60s: vec![],
            domain,
        }
    }

    fn participant(name: &str) -> NodeSnapshot {
        node(
            name,
            super::super::NodeRole::Participant,
            DomainMetrics::Participant {
                ledger_end_offset: 1,
                active_contracts: 0,
                hosted_parties: 0,
                loaded_dars: 0,
                ready: true,
                ready_reason: "ok".into(),
                api_requests_total: 0,
            },
        )
    }

    #[test]
    fn shadow_verify_series_are_cluster_scoped_gauges() {
        let shadow = ShadowVerifySummary {
            verified_tx_total: Some(5),
            mismatch_total: Some(2),
            match_ratio_percent: Some(71.0),
            baseline_jvm_rss_bytes: None,
            canton_rs_p99_ms: 0.0,
        };
        let snap = snapshot_with(vec![participant("p1"), participant("p2")], Some(shadow));
        let txt = render_prometheus_metrics(&snap, &BTreeMap::new());
        // The value can go down between scrapes, so a counter type would make rate() lie.
        assert!(txt.contains("# TYPE canton_rs_shadow_mismatch_total gauge"));
        assert!(txt.contains("# TYPE canton_rs_shadow_verified_tx_total gauge"));
        let lines: Vec<&str> = txt
            .lines()
            .filter(|l| l.starts_with("canton_rs_shadow_mismatch_total{"))
            .collect();
        assert_eq!(
            lines,
            vec!["canton_rs_shadow_mismatch_total{synchronizer=\"sync\"} 2"]
        );

        let unknown = ShadowVerifySummary {
            verified_tx_total: None,
            mismatch_total: None,
            match_ratio_percent: None,
            baseline_jvm_rss_bytes: None,
            canton_rs_p99_ms: 0.0,
        };
        let unknown_txt = render_prometheus_metrics(
            &snapshot_with(vec![participant("p1")], Some(unknown)),
            &BTreeMap::new(),
        );
        assert!(!unknown_txt.contains("canton_rs_shadow_mismatch_total{"));
        assert!(!unknown_txt.contains("canton_rs_shadow_verified_tx_total{"));
    }

    #[test]
    fn bft_quorum_exports_the_configured_peer_count() {
        let seq = node(
            "seq1",
            super::super::NodeRole::Sequencer,
            DomainMetrics::Sequencer {
                head_offset: 0,
                connected_members: 2,
                bft_quorum_peers: Some((5, 7)),
            },
        );
        let txt = render_prometheus_metrics(&snapshot_with(vec![seq], None), &BTreeMap::new());
        assert!(txt.contains("canton_rs_bft_quorum_peers{synchronizer=\"sync\",node=\"seq1\"} 5"));
        assert!(
            txt.contains("canton_rs_bft_configured_peers{synchronizer=\"sync\",node=\"seq1\"} 7")
        );
    }

    fn free_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        l.local_addr().expect("addr").port()
    }

    fn get(port: u16, path: &str) -> String {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn a_silent_client_does_not_stall_the_metrics_endpoint() {
        let port = free_port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = spawn_metrics_server(
            "127.0.0.1",
            port,
            ExporterState::default(),
            Arc::clone(&shutdown),
        )
        .expect("spawn exporter");
        let _silent = std::net::TcpStream::connect(("127.0.0.1", port)).expect("silent client");
        std::thread::sleep(Duration::from_millis(100));
        let started = std::time::Instant::now();
        let resp = get(port, "/livez");
        let elapsed = started.elapsed();
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "unexpected response {resp:?}"
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "/livez waited {elapsed:?} behind a client that sent nothing"
        );
        shutdown.store(true, Ordering::SeqCst);
        let _ = handle.join();
    }
}
