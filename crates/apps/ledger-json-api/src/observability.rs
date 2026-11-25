//! Node-level observability: API request counters/histograms, Prometheus `GET /metrics`,
//! readiness checks, and Zero-Payload 4-Hop X-Ray metadata (`GET /_xray`).
//!
//! [CANTON-NOTE: INVARIANT] Zero Daml contract payloads, arguments, or ciphertexts are stored
//! inside `XRayNodeRecord`, enforcing the compile-time zero-knowledge boundary.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::service::ExecutionService;

/// Maximum number of recent Zero-Payload X-Ray records retained per participant.
const MAX_XRAY_RECORDS: usize = 256;

/// Histogram bucket upper bounds (seconds) matching supervisor Prometheus exposition.
pub const LATENCY_BUCKETS: [f64; 10] = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The header the gRPC server puts on the JSON requests it makes of a call: such a request is counted as the gRPC call, not as HTTP.
pub const VIA_GRPC_HEADER: &str = "x-canton-rs-via-grpc";

/// Zero-Payload X-Ray metadata record emitted per transaction commit attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XRayNodeRecord {
    pub root_hash: String,
    pub started_at_unix_ms: u64,
    pub submitter_participant: String,
    pub package_id: String,
    pub template_qualified_name: Option<String>,
    pub daml_eval_us: u64,
    pub blinded_view_count: u32,
    pub sealed_envelope_bytes: u64,
    pub traffic_cost_bytes: u64,
    pub recipient_member_count: u32,
    pub verdict: String,
    pub total_latency_ms: f64,
    pub views: Vec<XRayViewRecord>,
    /// True when sizes/hashes are estimated locally by the participant rather than synchronizer envelopes.
    #[serde(default)]
    pub is_participant_estimate: bool,
}

/// Blinded sub-transaction view summary without payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XRayViewRecord {
    pub view_hash: String,
    pub threshold: u32,
    pub approved_parties: Vec<String>,
    pub latency_ms: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LatencyHist {
    pub bucket_counts: [u64; 10],
    pub total_count: u64,
    pub total_sum_secs: f64,
}

#[derive(Default)]
struct MetricsInner {
    requests_total: BTreeMap<(String, String, u16), u64>,
    durations: BTreeMap<(String, String), LatencyHist>,
}

/// Per-node runtime observability container attached to [`ExecutionService`].
#[derive(Default)]
pub struct ObservabilityState {
    metrics: RwLock<MetricsInner>,
    xray_buffer: Mutex<VecDeque<XRayNodeRecord>>,
    pub wiretap_active: AtomicBool,
    active_ws_subscriptions: AtomicUsize,
}

impl ObservabilityState {
    /// Enables or disables Zero-Payload X-Ray capture.
    pub fn set_wiretap_active(&self, active: bool) {
        self.wiretap_active.store(active, Ordering::Relaxed);
    }

    /// Increments the active WebSocket subscription gauge (`S-DX-005`).
    pub fn inc_ws_subscriptions(&self) {
        self.active_ws_subscriptions.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrements the active WebSocket subscription gauge (`S-DX-005`), saturating at `0`.
    pub fn dec_ws_subscriptions(&self) {
        let _ =
            self.active_ws_subscriptions
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                    Some(v.saturating_sub(1))
                });
    }

    /// Returns the number of active WebSocket streaming subscriptions (`S-DX-005`).
    pub fn active_ws_subscriptions(&self) -> usize {
        self.active_ws_subscriptions.load(Ordering::SeqCst)
    }

    /// Normalizes HTTP verbs and paths against a strict allowlist to keep Prometheus label cardinality bounded.
    pub fn normalize_method(method: &str, path: &str) -> String {
        let verb = match method {
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => method,
            _ => "OTHER",
        };
        let clean = path.split('?').next().unwrap_or(path).trim_end_matches('/');
        let base = if clean.is_empty() || clean == "/" {
            "/"
        } else if clean.starts_with("/v2/packages/") {
            if clean.ends_with("/status") {
                "/v2/packages/:id/status"
            } else {
                "/v2/packages/:id"
            }
        } else if clean.starts_with("/v2/users/") {
            if clean.ends_with("/rights") {
                "/v2/users/:id/rights"
            } else if clean.ends_with("/identity-provider-id") {
                "/v2/users/:id/identity-provider-id"
            } else {
                "/v2/users/:id"
            }
        } else if clean.starts_with("/v2/idps/") {
            "/v2/idps/:id"
        } else if clean == "/v2/parties/participant-id"
            || clean == "/v2/parties/external/generate-topology"
            || clean == "/v2/parties/external/allocate"
        {
            clean
        } else if clean.starts_with("/v2/parties/") {
            "/v2/parties/:id"
        } else if clean.starts_with("/v2/updates/transaction-by-id/") {
            "/v2/updates/transaction-by-id/:id"
        } else if clean.starts_with("/v2/updates/transaction-tree-by-id/") {
            "/v2/updates/transaction-tree-by-id/:id"
        } else if clean.starts_with("/v2/updates/update-by-id/") {
            "/v2/updates/update-by-id/:id"
        } else if clean.starts_with("/v2/updates/transaction-by-offset/") {
            "/v2/updates/transaction-by-offset/:offset"
        } else if clean.starts_with("/v2/updates/transaction-tree-by-offset/") {
            "/v2/updates/transaction-tree-by-offset/:offset"
        } else if clean.starts_with("/v2/events/events-by-contract-id/") {
            "/v2/events/events-by-contract-id/:id"
        } else if clean.starts_with("/v2/jose/jwks/synchronizer/")
            || clean.starts_with("/v2/jose/jwks/")
        {
            "/v2/jose/jwks/:id"
        } else if clean.starts_with("/v2/traffic/accounts/") {
            "/v2/traffic/accounts/:id"
        } else if clean.starts_with("/v2/interactive-submission/") {
            match clean {
                "/v2/interactive-submission/prepare"
                | "/v2/interactive-submission/execute"
                | "/v2/interactive-submission/executeAndWait"
                | "/v2/interactive-submission/executeAndWaitForTransaction"
                | "/v2/interactive-submission/preferred-packages"
                | "/v2/interactive-submission/preferred-package-version" => clean,
                _ => "/v2/interactive-submission/:op",
            }
        } else {
            match clean {
                "/livez"
                | "/readyz"
                | "/healthz"
                | "/health"
                | "/metrics"
                | "/_telemetry"
                | "/_quiesce"
                | "/_quiesce/pause"
                | "/_quiesce/resume"
                | "/_resume"
                | "/_xray"
                | "/_exex"
                | "/docs/openapi"
                | "/docs/asyncapi"
                | "/unauthorized"
                | "/v1/version"
                | "/v1/packages"
                | "/v1/create"
                | "/v1/exercise"
                | "/v1/contracts"
                | "/v1/query"
                | "/v1/command/submit-and-wait"
                | "/v2/version"
                | "/v2/state/ledger-end"
                | "/v2/state/connected-synchronizers"
                | "/v2/state/latest-pruned-offsets"
                | "/v2/state/active-contracts"
                | "/v2/state/active-contracts-page"
                | "/v2/state/convert-record-time-to-offset"
                | "/v2/state/acs"
                | "/v2/admin/prune"
                | "/v2/prune"
                | "/v2/idps"
                | "/v2/packages"
                | "/v2/dars"
                | "/v2/dars/validate"
                | "/v2/parties"
                | "/v2/users"
                | "/v2/authenticated-user"
                | "/v2/package-vetting"
                | "/v2/package-vetting/update"
                | "/v2/package-vetting/list"
                | "/v2/commands/submit-and-wait"
                | "/v2/commands/submit-and-wait-for-transaction"
                | "/v2/commands/submit-and-wait-for-transaction-tree"
                | "/v2/commands/submit-and-wait-for-reassignment"
                | "/v2/commands/async/submit"
                | "/v2/commands/async/submit-reassignment"
                | "/v2/commands/completions"
                | "/v2/commands/command-completions"
                | "/v2/commands/completion-by-hash"
                | "/v2/command/submit-and-wait"
                | "/v2/updates"
                | "/v2/updates/flats"
                | "/v2/updates/trees"
                | "/v2/updates/get-updates-page"
                | "/v2/updates/update-by-id"
                | "/v2/updates/update-by-offset"
                | "/v2/updates/update-by-hash"
                | "/v2/updates/transaction-by-id"
                | "/v2/updates/transaction-by-offset"
                | "/v2/contracts/contract-by-id"
                | "/v2/events/events-by-contract-id"
                | "/v2/completions"
                | "/v2/traffic/accounts"
                | "/v2/traffic/prune"
                | "/v2/traffic/events/prune" => clean,
                _ => "/other",
            }
        };
        format!("{verb} {base}")
    }

    /// Records one completed API request (`protocol` is `"http"` or `"grpc"`; for gRPC `status` is the status code).
    pub fn record_request(&self, protocol: &str, method: &str, status: u16, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        let Ok(mut guard) = self.metrics.write() else {
            return;
        };
        *guard
            .requests_total
            .entry((protocol.to_string(), method.to_string(), status))
            .or_insert(0) += 1;
        let hist = guard
            .durations
            .entry((protocol.to_string(), method.to_string()))
            .or_default();
        hist.total_count = hist.total_count.saturating_add(1);
        hist.total_sum_secs += secs;
        for (idx, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                hist.bucket_counts[idx] = hist.bucket_counts[idx].saturating_add(1);
            }
        }
    }

    /// Pushes a Zero-Payload X-Ray record when `wiretap_active` is enabled without blocking transaction commit threads.
    pub fn record_xray(&self, record: XRayNodeRecord) {
        if !self.wiretap_active.load(Ordering::Relaxed) {
            return;
        }
        let Ok(mut guard) = self.xray_buffer.try_lock() else {
            return;
        };
        if guard.len() >= MAX_XRAY_RECORDS {
            guard.pop_front();
        }
        guard.push_back(record);
    }

    /// Returns recent X-Ray records optionally filtered by `root_hash` or `since_ms`.
    pub fn snapshot_xray(&self, root_hash: Option<&str>, since_ms: u64) -> Vec<XRayNodeRecord> {
        let Ok(guard) = self.xray_buffer.lock() else {
            return Vec::new();
        };
        guard
            .iter()
            .filter(|r| {
                r.started_at_unix_ms >= since_ms
                    && root_hash.is_none_or(|needle| r.root_hash.contains(needle))
            })
            .cloned()
            .collect()
    }

    /// Exports API counters/histograms as JSON for `daemon` aggregation (`GET /_telemetry`).
    pub fn telemetry_json(&self, service: &ExecutionService) -> Value {
        let state = service.v2_state();
        let ledger_end = state.ledger_end.load(Ordering::Relaxed);
        let active_contracts = service.active_contract_count();
        let hosted_parties = state.parties.lock().map(|p| p.len() as u64).unwrap_or(0);
        let loaded_dars = service.package_ids().len() as u64;
        let (ready, ready_reason) = match service.check_ready() {
            Ok(()) => (true, "SERVING".to_string()),
            Err(why) => (false, why),
        };
        let (requests_total, durations) = match self.metrics.read() {
            Ok(g) => {
                let reqs: Vec<Value> = g
                    .requests_total
                    .iter()
                    .map(|((proto, meth, status), count)| {
                        json!({ "protocol": proto, "method": meth, "status": status, "count": count })
                    })
                    .collect();
                let durs: Vec<Value> = g
                    .durations
                    .iter()
                    .map(|((proto, meth), hist)| {
                        json!({
                            "protocol": proto,
                            "method": meth,
                            "bucket_counts": hist.bucket_counts,
                            "total_count": hist.total_count,
                            "total_sum_secs": hist.total_sum_secs,
                        })
                    })
                    .collect();
                (reqs, durs)
            }
            Err(_) => (Vec::new(), Vec::new()),
        };

        json!({
            "participant_id": state.participant_id(),
            "synchronizer_id": state.synchronizer_id(),
            "ledger_end": ledger_end,
            "active_contracts": active_contracts,
            "hosted_parties": hosted_parties,
            "loaded_dars": loaded_dars,
            "ready": ready,
            "ready_reason": ready_reason,
            "quiesced": service.is_quiesced(),
            "in_flight": service.total_in_flight(),
            "requests_total": requests_total,
            "durations": durations,
        })
    }

    /// Renders Tier-1 Prometheus 0.0.4 metrics directly from this node (`GET /metrics`).
    pub fn render_prometheus(&self, service: &ExecutionService) -> String {
        let state = service.v2_state();
        let node = escape_label(&state.participant_id());
        let sync = escape_label(&state.synchronizer_id());
        let up = u8::from(service.check_ready().is_ok());
        let ledger_end = state.ledger_end.load(Ordering::Relaxed);
        let active_contracts = service.active_contract_count();
        let hosted_parties = state.parties.lock().map(|p| p.len() as u64).unwrap_or(0);
        let loaded_dars = service.package_ids().len() as u64;

        let mut out = String::with_capacity(2048);
        out.push_str("# HELP canton_rs_node_up Participant /readyz status (1 = ready, 0 = not ready)\n# TYPE canton_rs_node_up gauge\n");
        out.push_str(&format!(
            "canton_rs_node_up{{synchronizer=\"{sync}\",role=\"participant\",node=\"{node}\"}} {up}\n"
        ));
        out.push_str("# HELP canton_rs_ledger_end_offset Current participant ledger end offset\n# TYPE canton_rs_ledger_end_offset gauge\n");
        out.push_str(&format!(
            "canton_rs_ledger_end_offset{{synchronizer=\"{sync}\",node=\"{node}\"}} {ledger_end}\n"
        ));
        out.push_str("# HELP canton_rs_acs_active_contracts Participant active contract count\n# TYPE canton_rs_acs_active_contracts gauge\n");
        out.push_str(&format!(
            "canton_rs_acs_active_contracts{{synchronizer=\"{sync}\",node=\"{node}\"}} {active_contracts}\n"
        ));
        out.push_str("# HELP canton_rs_hosted_parties Hosted party count\n# TYPE canton_rs_hosted_parties gauge\n");
        out.push_str(&format!(
            "canton_rs_hosted_parties{{synchronizer=\"{sync}\",node=\"{node}\"}} {hosted_parties}\n"
        ));
        out.push_str("# HELP canton_rs_loaded_dars Loaded DAR package count\n# TYPE canton_rs_loaded_dars gauge\n");
        out.push_str(&format!(
            "canton_rs_loaded_dars{{synchronizer=\"{sync}\",node=\"{node}\"}} {loaded_dars}\n"
        ));
        let active_ws = self.active_ws_subscriptions();
        out.push_str("# HELP canton_rs_active_subscriptions Active streaming subscriptions on this node\n# TYPE canton_rs_active_subscriptions gauge\n");
        out.push_str(&format!(
            "canton_rs_active_subscriptions{{synchronizer=\"{sync}\",node=\"{node}\",transport=\"ws\"}} {active_ws}\n"
        ));

        if let Ok(guard) = self.metrics.read() {
            out.push_str("# HELP canton_rs_api_requests_total Ledger API requests handled\n# TYPE canton_rs_api_requests_total counter\n");
            for ((proto, meth, status), count) in &guard.requests_total {
                out.push_str(&format!(
                    "canton_rs_api_requests_total{{node=\"{node}\",protocol=\"{}\",method=\"{}\",status=\"{status}\"}} {count}\n",
                    escape_label(proto),
                    escape_label(meth),
                ));
            }
            out.push_str("# HELP canton_rs_api_request_duration_seconds Ledger API latency distribution\n# TYPE canton_rs_api_request_duration_seconds histogram\n");
            for ((proto, meth), hist) in &guard.durations {
                let p_lbl = escape_label(proto);
                let m_lbl = escape_label(meth);
                for (idx, le) in LATENCY_BUCKETS.iter().enumerate() {
                    out.push_str(&format!(
                        "canton_rs_api_request_duration_seconds_bucket{{node=\"{node}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\",le=\"{le}\"}} {}\n",
                        hist.bucket_counts[idx]
                    ));
                }
                out.push_str(&format!(
                    "canton_rs_api_request_duration_seconds_bucket{{node=\"{node}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\",le=\"+Inf\"}} {}\n",
                    hist.total_count
                ));
                out.push_str(&format!(
                    "canton_rs_api_request_duration_seconds_sum{{node=\"{node}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\"}} {:.6}\n",
                    hist.total_sum_secs
                ));
                out.push_str(&format!(
                    "canton_rs_api_request_duration_seconds_count{{node=\"{node}\",protocol=\"{p_lbl}\",method=\"{m_lbl}\"}} {}\n",
                    hist.total_count
                ));
            }
            crate::metrics_compat::render(&mut out, up, &guard.requests_total, &guard.durations);
        }
        out
    }
}

/// Returns current wall-clock Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn escape_label(raw: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_and_zero_payload_xray_render_cleanly() {
        let svc = ExecutionService::new();
        svc.observability.record_request(
            "http",
            &ObservabilityState::normalize_method("GET", "/v2/users/alice"),
            200,
            Duration::from_millis(3),
        );
        svc.observability.record_xray(XRayNodeRecord {
            root_hash: "1220dropped".into(),
            started_at_unix_ms: now_unix_ms(),
            submitter_participant: "participant1".into(),
            package_id: "8f3ac102".into(),
            template_qualified_name: Some("Asset:Holding".into()),
            daml_eval_us: 250,
            blinded_view_count: 1,
            sealed_envelope_bytes: 512,
            traffic_cost_bytes: 512,
            recipient_member_count: 2,
            verdict: "approved".into(),
            total_latency_ms: 4.1,
            views: vec![],
            is_participant_estimate: true,
        });
        assert!(
            svc.observability.snapshot_xray(None, 0).is_empty(),
            "record_xray must stay zero-overhead when wiretap_active is false"
        );
        svc.observability.set_wiretap_active(true);
        svc.observability.record_xray(XRayNodeRecord {
            root_hash: "1220deadbeef".into(),
            started_at_unix_ms: now_unix_ms(),
            submitter_participant: "participant1".into(),
            package_id: "8f3ac102".into(),
            template_qualified_name: Some("Asset:Holding".into()),
            daml_eval_us: 250,
            blinded_view_count: 1,
            sealed_envelope_bytes: 512,
            traffic_cost_bytes: 512,
            recipient_member_count: 2,
            verdict: "approved".into(),
            total_latency_ms: 4.1,
            views: vec![],
            is_participant_estimate: true,
        });
        let prom = svc.observability.render_prometheus(&svc);
        assert!(prom.contains("canton_rs_node_up"));
        assert!(prom.contains("method=\"GET /v2/users/:id\""));
        assert!(prom.contains("canton_rs_api_request_duration_seconds_bucket"));

        let xray = svc.observability.snapshot_xray(Some("1220dead"), 0);
        assert_eq!(xray.len(), 1);
        assert!(xray[0].is_participant_estimate);
        let serialized = serde_json::to_string(&xray).expect("json");
        assert!(!serialized.contains("create_arguments"));
    }

    #[test]
    fn unknown_and_unauthorized_routes_keep_prometheus_cardinality_bounded() {
        let svc = ExecutionService::new();
        for i in 0..10_000 {
            let m = ObservabilityState::normalize_method("GET", &format!("/random/probe/{i}"));
            svc.observability
                .record_request("http", &m, 404, Duration::from_micros(50));
        }
        svc.observability.record_request(
            "http",
            &ObservabilityState::normalize_method("WEIRD\nVERB", "/secret/path"),
            401,
            Duration::from_micros(10),
        );
        let prom = svc.observability.render_prometheus(&svc);
        let request_series: Vec<&str> = prom
            .lines()
            .filter(|l| {
                l.starts_with("canton_rs_api_requests_total{")
                    || l.starts_with("daml_http_requests_total{")
            })
            .collect();
        assert_eq!(request_series.len(), 4, "got: {request_series:#?}");
        assert!(prom.contains("path=\"/other\""), "{prom}");
        assert!(!prom.contains("/random/probe/"), "{prom}");
        assert!(!prom.contains("/secret/path"), "{prom}");
    }
}
