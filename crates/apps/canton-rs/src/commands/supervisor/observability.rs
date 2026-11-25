//! Prometheus `file_sd_configs` target management and Canton 3.7.2 metric aliases (`S-DX-010`).

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::metrics::escape_label;
use super::{ClusterSnapshot, DomainMetrics};

/// Single Prometheus `file_sd_configs` target group written to `targets.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrometheusTargetGroup {
    pub targets: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// Per-instance `file_sd` target path (`dir(I)/prometheus/targets.json`).
pub fn local_targets_path(state_dir: &Path) -> PathBuf {
    state_dir.join("prometheus").join("targets.json")
}

/// Shared `file_sd` target path (`<root>/prometheus/targets/<name>.json`).
pub fn shared_targets_path(root: &Path, instance_name: &str) -> Result<PathBuf, String> {
    super::registry::validate_instance_name(instance_name)?;
    Ok(root
        .join("prometheus")
        .join("targets")
        .join(format!("{instance_name}.json")))
}

/// Derives `(shared_root, instance_name)` when `state_dir` resides under `<root>/instances/<name>`.
pub fn resolve_instance_target_scope(
    state_dir: &Path,
    fallback_name: &str,
) -> (Option<PathBuf>, String) {
    let dir_name = state_dir.file_name().and_then(|s| s.to_str());
    let instances_parent = state_dir.parent();
    let is_instances_dir =
        instances_parent.and_then(|p| p.file_name().and_then(|s| s.to_str())) == Some("instances");
    let root = instances_parent.and_then(Path::parent);
    if let (Some(name), true, Some(root_dir)) = (dir_name, is_instances_dir, root) {
        if super::registry::validate_instance_name(name).is_ok() {
            return (Some(root_dir.to_path_buf()), name.to_string());
        }
    }
    (None, fallback_name.to_string())
}

/// Normalizes supervisor `metrics_bind` and `metrics_port` into a concrete Prometheus scrape address.
pub fn metrics_scrape_address(bind: &str, port: u16) -> String {
    let host = bind.trim();
    let eff = match host {
        "" | "0.0.0.0" => "127.0.0.1",
        "::" | "[::]" => "::1",
        other => other.trim_start_matches('[').trim_end_matches(']'),
    };
    if eff.contains(':') {
        format!("[{eff}]:{port}")
    } else {
        format!("{eff}:{port}")
    }
}

/// Atomically writes `dir(I)/prometheus/targets.json` and, for named instances, `<root>/prometheus/targets/<name>.json`.
pub fn write_prometheus_targets(
    state_dir: &Path,
    shared_root: Option<&Path>,
    instance_name: &str,
    synchronizer: &str,
    metrics_addr: &str,
) -> Result<(PathBuf, Option<PathBuf>), String> {
    let mut labels = BTreeMap::new();
    labels.insert("instance".to_string(), instance_name.to_string());
    labels.insert("synchronizer".to_string(), synchronizer.to_string());
    let payload = vec![PrometheusTargetGroup {
        targets: vec![metrics_addr.to_string()],
        labels,
    }];
    let encoded = serde_json::to_vec_pretty(&payload)
        .map_err(|e| format!("serialize prometheus targets: {e}"))?;

    let local_path = local_targets_path(state_dir);
    write_file_0644_atomic(&local_path, &encoded)?;

    let shared_path = match shared_root {
        Some(root) => {
            let p = shared_targets_path(root, instance_name)?;
            write_file_0644_atomic(&p, &encoded)?;
            Some(p)
        }
        None => None,
    };
    Ok((local_path, shared_path))
}

/// Removes `<root>/prometheus/targets/<instance_name>.json` safely (refuses symlinks).
pub fn remove_shared_target(root: &Path, instance_name: &str) -> Result<Option<PathBuf>, String> {
    let path = shared_targets_path(root, instance_name)?;
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || meta.is_dir() {
                return Err(format!(
                    "refusing non-regular prometheus target path {}",
                    path.display()
                ));
            }
            fs::remove_file(&path)
                .map_err(|e| format!("remove prometheus target {}: {e}", path.display()))?;
            Ok(Some(path))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "inspect prometheus target {}: {err}",
            path.display()
        )),
    }
}

/// Appends Canton 3.7.2 official metric aliases with verified unit/semantics/label parity (`M-A2`, `M-A3`).
///
/// [CANTON-NOTE: SEMANTICS] Only `daml_mediator_outstanding_requests`,
/// `daml_sequencer_bftordering_p2p_connections_connected`, and
/// `daml_sequencer_bftordering_topology_validators` are emitted here because they match the
/// corresponding `canton_rs_*` gauges in unit (`1`), Prometheus type (`gauge`), and `{synchronizer, node}`
/// labels 1:1 against Canton 3.7.2 Scala definitions.
pub fn append_official_metric_aliases(out: &mut String, snapshot: &ClusterSnapshot) {
    let sync = escape_label(&snapshot.synchronizer);

    // 1. daml_mediator_outstanding_requests <- canton_rs_mediator_pending_quorums
    out.push_str(
        "# HELP daml_mediator_outstanding_requests Number of currently open requests registered with the mediator (alias of canton_rs_mediator_pending_quorums)\n\
         # TYPE daml_mediator_outstanding_requests gauge\n",
    );
    for n in &snapshot.nodes {
        if let DomainMetrics::Mediator {
            pending_quorums, ..
        } = &n.domain
        {
            out.push_str(&format!(
                "daml_mediator_outstanding_requests{{synchronizer=\"{sync}\",node=\"{}\"}} {pending_quorums}\n",
                escape_label(&n.name),
            ));
        }
    }

    // 2. daml_sequencer_bftordering_p2p_connections_connected <- canton_rs_bft_quorum_peers
    out.push_str(
        "# HELP daml_sequencer_bftordering_p2p_connections_connected Number of connected BFT P2P endpoints (alias of canton_rs_bft_quorum_peers)\n\
         # TYPE daml_sequencer_bftordering_p2p_connections_connected gauge\n",
    );
    for n in &snapshot.nodes {
        if let DomainMetrics::Sequencer {
            bft_quorum_peers, ..
        } = &n.domain
        {
            let connected = bft_quorum_peers.map_or(0, |(c, _)| c);
            out.push_str(&format!(
                "daml_sequencer_bftordering_p2p_connections_connected{{synchronizer=\"{sync}\",node=\"{}\"}} {connected}\n",
                escape_label(&n.name),
            ));
        }
    }

    // 3. daml_sequencer_bftordering_topology_validators <- canton_rs_bft_configured_peers
    out.push_str(
        "# HELP daml_sequencer_bftordering_topology_validators Number of configured BFT validators in ordering topology (alias of canton_rs_bft_configured_peers)\n\
         # TYPE daml_sequencer_bftordering_topology_validators gauge\n",
    );
    for n in &snapshot.nodes {
        if let DomainMetrics::Sequencer {
            bft_quorum_peers: Some((_, configured)),
            ..
        } = &n.domain
        {
            out.push_str(&format!(
                "daml_sequencer_bftordering_topology_validators{{synchronizer=\"{sync}\",node=\"{}\"}} {configured}\n",
                escape_label(&n.name),
            ));
        }
    }
}

fn write_file_0644_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod 0644 {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::supervisor::metrics::render_prometheus_metrics;
    use crate::commands::supervisor::{
        NodeLifecycleState, NodePorts, NodeRole, NodeSnapshot, ProcResources, RestartPolicy,
    };

    #[test]
    fn resolves_named_instance_target_scope_and_roundtrips_target_files() {
        let tmp = std::env::temp_dir().join(format!("sdx010-obs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        let state_dir = tmp.join("instances").join("obs-a");
        fs::create_dir_all(&state_dir).expect("mkdir");

        let (shared_root, inst_name) = resolve_instance_target_scope(&state_dir, "ignored");
        assert_eq!(shared_root.as_deref(), Some(tmp.as_path()));
        assert_eq!(inst_name, "obs-a");

        let addr = metrics_scrape_address("0.0.0.0", 9564);
        assert_eq!(addr, "127.0.0.1:9564");

        let (local, shared) = write_prometheus_targets(
            &state_dir,
            shared_root.as_deref(),
            &inst_name,
            "sync-a",
            &addr,
        )
        .expect("write targets");
        assert!(local.is_file());
        let shared = shared.expect("shared path");
        assert!(shared.is_file());

        let parsed: Vec<PrometheusTargetGroup> =
            serde_json::from_str(&fs::read_to_string(&shared).expect("read")).expect("json");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].targets, vec!["127.0.0.1:9564"]);
        assert_eq!(
            parsed[0].labels.get("instance").map(String::as_str),
            Some("obs-a")
        );

        let removed = remove_shared_target(&tmp, "obs-a").expect("remove");
        assert_eq!(removed.as_deref(), Some(shared.as_path()));
        assert!(!shared.exists());
        assert_eq!(
            remove_shared_target(&tmp, "obs-a").expect("idempotent"),
            None
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn official_aliases_preserve_exact_values_and_labels() {
        let snap = ClusterSnapshot {
            stack_name: "obs".into(),
            synchronizer: "sync-alias".into(),
            storage_mode: "files".into(),
            collected_at_unix_ms: 0,
            total_cpu_percent: 0.0,
            total_rss_bytes: 0,
            last_ping: None,
            shadow_verify: None,
            wiretap_dropped_events: 0,
            scenarios: vec![],
            metrics_port: Some(9464),
            metrics_bind: Some("127.0.0.1".into()),
            nodes: vec![
                NodeSnapshot {
                    slot_id: 0,
                    role: NodeRole::Sequencer,
                    name: "s1".into(),
                    group: None,
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(1),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 5,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Sequencer {
                        head_offset: 3,
                        connected_members: 2,
                        bft_quorum_peers: Some((3, 4)),
                    },
                },
                NodeSnapshot {
                    slot_id: 1,
                    role: NodeRole::Mediator,
                    name: "m1".into(),
                    group: None,
                    synchronizer_domain: None,
                    host_label: None,
                    pid: Some(2),
                    ports: NodePorts::default(),
                    state: NodeLifecycleState::Online,
                    restart_policy: RestartPolicy::UnlessStopped,
                    restarts_total: 0,
                    consecutive_failures: 0,
                    uptime_secs: 5,
                    stopped_at_unix_ms: None,
                    last_exit_reason: None,
                    resources: ProcResources::default(),
                    history_60s: vec![],
                    domain: DomainMetrics::Mediator {
                        group_id: 0,
                        verdicts_approved: 1,
                        verdicts_rejected: 0,
                        pending_quorums: 7,
                    },
                },
            ],
        };
        let txt = render_prometheus_metrics(&snap, &BTreeMap::new());
        assert!(txt.contains(
            "daml_mediator_outstanding_requests{synchronizer=\"sync-alias\",node=\"m1\"} 7"
        ));
        assert!(txt.contains(
            "canton_rs_mediator_pending_quorums{synchronizer=\"sync-alias\",node=\"m1\"} 7"
        ));
        assert!(txt.contains("daml_sequencer_bftordering_p2p_connections_connected{synchronizer=\"sync-alias\",node=\"s1\"} 3"));
        assert!(
            txt.contains("canton_rs_bft_quorum_peers{synchronizer=\"sync-alias\",node=\"s1\"} 3")
        );
        assert!(txt.contains("daml_sequencer_bftordering_topology_validators{synchronizer=\"sync-alias\",node=\"s1\"} 4"));
        assert!(txt
            .contains("canton_rs_bft_configured_peers{synchronizer=\"sync-alias\",node=\"s1\"} 4"));
    }
}
