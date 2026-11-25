//! Pins `deploy/monitoring/` to what the supervisor exporter actually emits.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use yaml_rust2::{Yaml, YamlLoader};

use super::super::{
    ClusterSnapshot, DomainMetrics, NodeLifecycleState, NodePorts, NodeRole, NodeSnapshot,
    PingStatus, ProcResources, RestartPolicy, ShadowVerifySummary,
};
use super::{render_prometheus_metrics, ApiHistogram, NodeApiTelemetry};

fn kit(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../deploy/monitoring")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn yaml(rel: &str) -> Yaml {
    YamlLoader::load_from_str(&kit(rel))
        .unwrap_or_else(|e| panic!("{rel} is not YAML: {e}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{rel} is empty"))
}

fn node(slot_id: usize, role: NodeRole, name: &str, domain: DomainMetrics) -> NodeSnapshot {
    NodeSnapshot {
        slot_id,
        role,
        name: name.into(),
        group: Some("bank-a".into()),
        synchronizer_domain: None,
        host_label: None,
        pid: Some(100),
        ports: NodePorts::default(),
        state: NodeLifecycleState::Online,
        restart_policy: RestartPolicy::UnlessStopped,
        restarts_total: 0,
        consecutive_failures: 0,
        uptime_secs: 1,
        stopped_at_unix_ms: None,
        last_exit_reason: None,
        resources: ProcResources::default(),
        history_60s: vec![],
        domain,
    }
}

/// A cluster with every role so every family has at least one series.
fn full_exposition() -> String {
    let snap = ClusterSnapshot {
        stack_name: "kit".into(),
        synchronizer: "sync".into(),
        storage_mode: "memory".into(),
        collected_at_unix_ms: 0,
        total_cpu_percent: 0.0,
        total_rss_bytes: 1,
        last_ping: Some(PingStatus {
            ok: true,
            rtt_ms: 1.0,
            detail: "ok".into(),
            checked_at_unix_ms: 0,
        }),
        shadow_verify: Some(ShadowVerifySummary {
            verified_tx_total: Some(1),
            mismatch_total: Some(0),
            match_ratio_percent: Some(100.0),
            baseline_jvm_rss_bytes: None,
            canton_rs_p99_ms: 0.0,
        }),
        wiretap_dropped_events: 0,
        scenarios: vec![],
        metrics_port: None,
        metrics_bind: None,
        nodes: vec![
            node(
                0,
                NodeRole::Sequencer,
                "seq1",
                DomainMetrics::Sequencer {
                    head_offset: 1,
                    connected_members: 3,
                    bft_quorum_peers: Some((4, 4)),
                },
            ),
            node(
                1,
                NodeRole::Mediator,
                "med1",
                DomainMetrics::Mediator {
                    group_id: 0,
                    verdicts_approved: 1,
                    verdicts_rejected: 0,
                    pending_quorums: 0,
                },
            ),
            node(
                2,
                NodeRole::Participant,
                "p1",
                DomainMetrics::Participant {
                    ledger_end_offset: 1,
                    active_contracts: 1,
                    hosted_parties: 1,
                    loaded_dars: 1,
                    ready: true,
                    ready_reason: "ok".into(),
                    api_requests_total: 1,
                },
            ),
            node(
                3,
                NodeRole::Splice,
                "splice1",
                DomainMetrics::Splice {
                    open_round: Some(1),
                    scan_updates_total: 1,
                    ledger_backend_connected: true,
                },
            ),
        ],
    };
    let tel = BTreeMap::from([(
        "p1".to_string(),
        NodeApiTelemetry {
            requests_total: BTreeMap::from([(("http".into(), "GET /v2/version".into(), 200), 1)]),
            durations: BTreeMap::from([(
                ("http".into(), "GET /v2/version".into()),
                ApiHistogram {
                    bucket_counts: [1; 10],
                    total_count: 1,
                    total_sum_secs: 0.001,
                },
            )]),
        },
    )]);
    render_prometheus_metrics(&snap, &tel)
}

fn metric_names(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find("canton_rs_") {
        let tail = &rest[at..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        out.insert(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

fn dashboard_exprs() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for file in [
        "grafana/dashboards/canton-rs-overview.json",
        "grafana/dashboards/canton-rs-consensus-and-shadow.json",
    ] {
        let doc: serde_json::Value =
            serde_json::from_str(&kit(file)).unwrap_or_else(|e| panic!("{file} is not JSON: {e}"));
        for panel in doc["panels"].as_array().expect("panels") {
            let title = panel["title"].as_str().unwrap_or_default().to_string();
            for t in panel["targets"].as_array().into_iter().flatten() {
                out.push((
                    title.clone(),
                    t["expr"].as_str().unwrap_or_default().to_string(),
                ));
            }
        }
    }
    out
}

fn alert_rules() -> BTreeMap<String, String> {
    let doc = yaml("prometheus/alerts.yml");
    let mut out = BTreeMap::new();
    for group in doc["groups"].as_vec().expect("groups") {
        for rule in group["rules"].as_vec().expect("rules") {
            out.insert(
                rule["alert"].as_str().expect("alert name").to_string(),
                rule["expr"].as_str().expect("expr").to_string(),
            );
        }
    }
    out
}

#[test]
fn every_metric_the_kit_queries_is_exported() {
    let exposition = full_exposition();
    let exported: BTreeSet<String> = exposition
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split(['{', ' ']).next())
        .map(String::from)
        .collect();
    let mut queried = BTreeSet::new();
    for (_, expr) in dashboard_exprs() {
        queried.extend(metric_names(&expr));
    }
    for expr in alert_rules().values() {
        queried.extend(metric_names(expr));
    }
    let missing: Vec<&String> = queried.difference(&exported).collect();
    assert!(
        missing.is_empty(),
        "queried but never exported: {missing:?}"
    );
}

#[test]
fn alerts_ignore_stopped_nodes_and_derive_the_bft_quorum() {
    let rules = alert_rules();
    let down = &rules["CantonRsNodeDown"];
    assert!(
        down.contains("state=\"stopped\""),
        "a node stopped on purpose must not page: {down}"
    );
    let bft = &rules["CantonRsBftQuorumDegraded"];
    assert!(
        bft.contains("canton_rs_bft_configured_peers"),
        "the quorum must come from the configured peer count: {bft}"
    );
}

#[test]
fn no_panel_calls_registered_members_connected() {
    for (title, expr) in dashboard_exprs() {
        if expr.contains("canton_rs_sequencer_connected_members") {
            assert!(
                !title.contains("Connected"),
                "the series counts registered members, not connections: {title}"
            );
        }
    }
}

#[test]
fn the_lab_stack_listens_on_loopback_without_anonymous_or_lifecycle_access() {
    let compose = yaml("docker-compose.yml");
    for svc in ["prometheus", "grafana"] {
        let s = &compose["services"][svc];
        for port in s["ports"].as_vec().expect("ports") {
            let p = port.as_str().expect("port string");
            assert!(
                p.starts_with("127.0.0.1:"),
                "{svc} publishes {p} beyond loopback"
            );
        }
        for arg in s["command"].as_vec().into_iter().flatten() {
            assert_ne!(
                arg.as_str(),
                Some("--web.enable-lifecycle"),
                "{svc} allows remote /-/quit"
            );
        }
        for env in s["environment"].as_vec().into_iter().flatten() {
            let e = env.as_str().unwrap_or_default();
            assert!(
                !e.contains(":-canton-rs}"),
                "{svc} ships a default password: {e}"
            );
            if e.starts_with("GF_AUTH_ANONYMOUS_ENABLED=") {
                assert!(
                    e.ends_with(":-false}"),
                    "anonymous Grafana must default off: {e}"
                );
            }
        }
    }
    let env_example = kit(".env.example");
    assert!(!env_example.contains("GRAFANA_ADMIN_PASSWORD=canton-rs"));
}

#[test]
fn example_manifests_bind_metrics_to_loopback() {
    for case in [
        "case1-dvp-multicell.yaml",
        "case2-bft-chaos.yaml",
        "case3-multidomain-bridge.yaml",
        "case4-org-production-shadow.yaml",
    ] {
        let doc = yaml(&format!("examples/{case}"));
        assert_eq!(doc["metrics_bind"].as_str(), Some("127.0.0.1"), "{case}");
    }
}

#[test]
fn the_demo_runner_keeps_docker_credentials_out_of_a_fixed_tmp_path() {
    let script = kit("run-demo.sh");
    assert!(!script.contains("/tmp/crs-docker-public-cfg"));
    assert!(script.contains("mktemp -d"));
}
