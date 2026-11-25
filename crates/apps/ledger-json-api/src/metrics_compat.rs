//! The node's request metrics under the names Canton exports them with, so that a dashboard made for a Canton participant reads this node.
//!
//! [CANTON-NOTE: SEMANTICS] Canton's metrics reference (`docs-open/.../participant/reference/metrics.rst`): `daml_health_status{component}`,
//! `daml_grpc_server_handled_total{grpc_service_name, grpc_method_name, grpc_code}`, `daml_grpc_server_duration_seconds`,
//! `daml_http_requests_total{http_verb, path, http_status}` and `daml_http_requests_duration_seconds`, each with the `service` label
//! (`participant` for gRPC, `json_api` for HTTP).
use crate::observability::LatencyHist;
use std::collections::BTreeMap;

/// The name of a gRPC status code as Canton's `grpc_code` label writes it.
fn grpc_code(code: u16) -> &'static str {
    const NAMES: [&str; 17] = [
        "OK",
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNIMPLEMENTED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
        "UNAUTHENTICATED",
    ];
    NAMES.get(usize::from(code)).copied().unwrap_or("UNKNOWN")
}

/// The labels that name a request's call (`POST /v2/parties` for HTTP, `<service>/<method>` for gRPC), and its `service` label.
fn labels(protocol: &str, method: &str) -> Option<(String, &'static str)> {
    match protocol {
        "http" => {
            let (verb, path) = method.split_once(' ')?;
            Some((
                format!("http_verb=\"{}\",path=\"{}\"", escape(verb), escape(path)),
                "json_api",
            ))
        }
        "grpc" => {
            let (service, name) = method.rsplit_once('/')?;
            Some((
                format!(
                    "grpc_service_name=\"{}\",grpc_method_name=\"{}\"",
                    escape(service),
                    escape(name)
                ),
                "participant",
            ))
        }
        _ => None,
    }
}

fn escape(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Appends the Canton-named series of the counted requests (`protocol`, `method`, `status`) and their latencies to `out`.
pub(crate) fn render(
    out: &mut String,
    up: u8,
    requests: &BTreeMap<(String, String, u16), u64>,
    durations: &BTreeMap<(String, String), LatencyHist>,
) {
    out.push_str(
        "# HELP daml_health_status The status of the component\n# TYPE daml_health_status gauge\n",
    );
    out.push_str(&format!(
        "daml_health_status{{component=\"participant\"}} {up}\n"
    ));
    for (protocol, total, outcome) in [
        ("http", "daml_http_requests_total", "http_status"),
        ("grpc", "daml_grpc_server_handled_total", "grpc_code"),
    ] {
        out.push_str(&format!("# TYPE {total} counter\n"));
        for ((p, method, status), count) in requests {
            let Some((call, service)) = (p == protocol).then(|| labels(p, method)).flatten() else {
                continue;
            };
            let value = if protocol == "grpc" {
                grpc_code(*status).to_string()
            } else {
                status.to_string()
            };
            out.push_str(&format!(
                "{total}{{{call},{outcome}=\"{value}\",service=\"{service}\"}} {count}\n"
            ));
        }
    }
    for (protocol, histogram) in [
        ("http", "daml_http_requests_duration_seconds"),
        ("grpc", "daml_grpc_server_duration_seconds"),
    ] {
        out.push_str(&format!("# TYPE {histogram} histogram\n"));
        for ((p, method), hist) in durations {
            let Some((call, service)) = (p == protocol).then(|| labels(p, method)).flatten() else {
                continue;
            };
            let labels = format!("{call},service=\"{service}\"");
            for (bound, count) in crate::observability::LATENCY_BUCKETS
                .iter()
                .zip(hist.bucket_counts)
            {
                out.push_str(&format!(
                    "{histogram}_bucket{{{labels},le=\"{bound}\"}} {count}\n"
                ));
            }
            out.push_str(&format!(
                "{histogram}_bucket{{{labels},le=\"+Inf\"}} {}\n",
                hist.total_count
            ));
            out.push_str(&format!(
                "{histogram}_sum{{{labels}}} {:.6}\n",
                hist.total_sum_secs
            ));
            out.push_str(&format!(
                "{histogram}_count{{{labels}}} {}\n",
                hist.total_count
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_shown_under_cantons_names() {
        let mut requests = BTreeMap::new();
        requests.insert(("http".to_string(), "POST /v2/parties".to_string(), 200), 2);
        requests.insert(
            (
                "grpc".to_string(),
                "com.daml.ledger.api.v2.StateService/GetLedgerEnd".to_string(),
                3,
            ),
            1,
        );
        let mut durations = BTreeMap::new();
        durations.insert(
            ("http".to_string(), "POST /v2/parties".to_string()),
            LatencyHist {
                bucket_counts: [0, 1, 2, 2, 2, 2, 2, 2, 2, 2],
                total_count: 2,
                total_sum_secs: 0.012,
            },
        );
        let mut out = String::new();
        render(&mut out, 1, &requests, &durations);
        assert!(
            out.contains("daml_health_status{component=\"participant\"} 1\n"),
            "{out}"
        );
        assert!(out.contains(
            "daml_http_requests_total{http_verb=\"POST\",path=\"/v2/parties\",http_status=\"200\",service=\"json_api\"} 2\n"
        ), "{out}");
        assert!(out.contains(
            "daml_grpc_server_handled_total{grpc_service_name=\"com.daml.ledger.api.v2.StateService\",grpc_method_name=\"GetLedgerEnd\",grpc_code=\"INVALID_ARGUMENT\",service=\"participant\"} 1\n"
        ), "{out}");
        assert!(out.contains(
            "daml_http_requests_duration_seconds_bucket{http_verb=\"POST\",path=\"/v2/parties\",service=\"json_api\",le=\"0.005\"} 1\n"
        ), "{out}");
        assert!(out.contains(
            "daml_http_requests_duration_seconds_count{http_verb=\"POST\",path=\"/v2/parties\",service=\"json_api\"} 2\n"
        ), "{out}");
        assert!(
            out.contains("# TYPE daml_grpc_server_handled_total counter\n"),
            "{out}"
        );
    }
}
