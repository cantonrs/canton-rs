//! Machine-readable endpoint status (`canton-rs daemon status`) and shell environment exports
//! (`canton-rs daemon env`) (`S-DX-002`).
//!
//! [CANTON-NOTE: INVARIANT] `DaemonStatusReport::endpoints` uses [`BTreeMap`] so JSON keys, text
//! lines, and `export` lines always emit in deterministic lexicographic label order (`A1`, `P-A6`).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use canton_sequencer_server::health::health_check_response::ServingStatus;
use canton_sequencer_server::health::health_client::HealthClient;
use canton_sequencer_server::health::HealthCheckRequest;
use serde::{Deserialize, Serialize};
use tonic::transport::Endpoint;

use super::cli::DEFAULT_STATE_DIR;
use super::ipc::{call_unary, resolve_client_state_dir, socket_path, IpcRequest, IpcResponse};
use super::probe::http_request;
use super::process::is_pid_alive;
use super::{ClusterSnapshot, NodeLifecycleState, NodeRole};

/// Versioned schema identifier emitted by `canton-rs daemon status --format json`.
pub const STATUS_JSON_SCHEMA: &str = "canton-rs.status/1";

/// Metadata filename written by an active `canton-rs localnet up` coordinator inside its state dir.
pub const LOCALNET_STATUS_FILE: &str = "localnet-status.json";

const LAST_LOCALNET_STATE_DIR_FILE: &str = "canton-rs-last-localnet-state-dir";
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Reachability + lifecycle state for one exposed endpoint (`P-A4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointState {
    Up,
    Down,
    Starting,
    Failed,
}

impl EndpointState {
    /// Lowercase text representation matching serialized JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Starting => "starting",
            Self::Failed => "failed",
        }
    }
}

/// One serialized endpoint record inside [`DaemonStatusReport`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointStatus {
    pub url: String,
    pub state: EndpointState,
}

/// Canonical `canton-rs.status/1` report shared between JSON, text, and `daemon env` (`A1`, `P-A4`..`P-A6`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatusReport {
    pub schema: String,
    pub instance: Option<String>,
    pub state_dir: String,
    pub endpoints: BTreeMap<String, EndpointStatus>,
    pub version: String,
}

/// Persisted endpoint entry published by `localnet up` while child processes are alive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalnetEndpointEntry {
    pub label: String,
    pub url: String,
    pub role: String,
}

/// Sidecar file `<state-dir>/localnet-status.json` read when no `daemon.sock` is active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalnetStatusFile {
    pub pid: u32,
    pub instance: Option<String>,
    pub endpoints: Vec<LocalnetEndpointEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointProbeKind {
    HttpHealth { path: &'static str },
    GrpcHealth,
    TcpConnect,
}

#[derive(Clone, Debug)]
struct PlannedEndpointProbe {
    label: String,
    url: String,
    kind: EndpointProbeKind,
    lifecycle: Option<NodeLifecycleState>,
}

#[derive(Deserialize)]
struct InstanceStub {
    name: Option<String>,
}

fn read_instance_name(state_dir: &Path) -> Option<String> {
    let raw = fs::read_to_string(state_dir.join("instance.json")).ok()?;
    let parsed: InstanceStub = serde_json::from_str(&raw).ok()?;
    parsed.name.filter(|n| !n.trim().is_empty())
}

fn absolute_dir_string(dir: &Path) -> String {
    let resolved = fs::canonicalize(dir).unwrap_or_else(|_| {
        if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(dir))
                .unwrap_or_else(|_| dir.to_path_buf())
        }
    });
    resolved.display().to_string()
}

fn connect_host(bind: Option<&str>) -> &str {
    match bind.map(str::trim) {
        None | Some("" | "0.0.0.0") => "127.0.0.1",
        Some("::" | "[::]") => "[::1]",
        Some(other) => other,
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("missing parent directory for {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("status"),
        std::process::id()
    ));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("open {}: {e}", tmp.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename {} -> {}: {e}", tmp.display(), path.display())
    })
}

/// Atomically writes `<state-dir>/localnet-status.json` (`0o600`) and updates the default lookup marker.
pub fn write_localnet_status_file(
    state_dir: &Path,
    status: &LocalnetStatusFile,
) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(status).map_err(|e| e.to_string())?;
    let path = state_dir.join(LOCALNET_STATUS_FILE);
    write_private_atomic(&path, &payload)?;
    let abs = absolute_dir_string(state_dir);
    let marker = std::env::temp_dir().join(LAST_LOCALNET_STATE_DIR_FILE);
    let _ = write_private_atomic(&marker, abs.as_bytes());
    Ok(())
}

/// Removes `<state-dir>/localnet-status.json` and clears the lookup marker if it still names `state_dir`.
pub fn remove_localnet_status_file(state_dir: &Path) {
    let _ = fs::remove_file(state_dir.join(LOCALNET_STATUS_FILE));
    let marker = std::env::temp_dir().join(LAST_LOCALNET_STATE_DIR_FILE);
    if let Ok(saved) = fs::read_to_string(&marker) {
        if saved.trim() == absolute_dir_string(state_dir) {
            let _ = fs::remove_file(&marker);
        }
    }
}

fn read_live_localnet_file(state_dir: &Path) -> Result<Option<LocalnetStatusFile>, String> {
    let path = state_dir.join(LOCALNET_STATUS_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parsed: LocalnetStatusFile =
        serde_json::from_str(&raw).map_err(|e| format!("invalid {}: {e}", path.display()))?;
    if !is_pid_alive(parsed.pid) {
        return Ok(None);
    }
    Ok(Some(parsed))
}

fn endpoint_kind_for_localnet_role(role: &str) -> EndpointProbeKind {
    match role {
        "sequencer_public" | "sequencer_admin" => EndpointProbeKind::GrpcHealth,
        "mediator_admin" => EndpointProbeKind::HttpHealth { path: "/status" },
        "participant_json" => EndpointProbeKind::HttpHealth { path: "/readyz" },
        "scan_http" => EndpointProbeKind::HttpHealth {
            path: "/api/scan/v0/dso-party-id",
        },
        _ => EndpointProbeKind::HttpHealth { path: "/livez" },
    }
}

fn endpoints_from_snapshot(snapshot: &ClusterSnapshot) -> Vec<PlannedEndpointProbe> {
    let mut out = Vec::new();
    for node in &snapshot.nodes {
        let life = Some(node.state);
        match node.role {
            NodeRole::Sequencer => {
                if let Some(p) = node.ports.public {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.public", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::GrpcHealth,
                        lifecycle: life,
                    });
                }
                if let Some(p) = node.ports.admin {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.admin", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::GrpcHealth,
                        lifecycle: life,
                    });
                }
                if let Some(p) = node.ports.p2p {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.p2p", node.name),
                        url: format!("tcp://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::TcpConnect,
                        lifecycle: life,
                    });
                }
                if let Some(mp) = node
                    .ports
                    .metrics
                    .filter(|p| node.ports.public != Some(*p) && node.ports.admin != Some(*p))
                {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.metrics", node.name),
                        url: format!("http://127.0.0.1:{mp}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/livez" },
                        lifecycle: life,
                    });
                }
            }
            NodeRole::Mediator => {
                if let Some(p) = node.ports.admin {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.admin", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/status" },
                        lifecycle: life,
                    });
                }
                if let Some(mp) = node.ports.metrics.filter(|p| node.ports.admin != Some(*p)) {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.metrics", node.name),
                        url: format!("http://127.0.0.1:{mp}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/livez" },
                        lifecycle: life,
                    });
                }
            }
            NodeRole::Participant => {
                if let Some(p) = node.ports.http_json {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.json", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/readyz" },
                        lifecycle: life,
                    });
                }
                if let Some(p) = node.ports.grpc_ledger {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.grpc", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::GrpcHealth,
                        lifecycle: life,
                    });
                }
                if let Some(p) = node.ports.admin {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.admin", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::GrpcHealth,
                        lifecycle: life,
                    });
                }
                if let Some(mp) = node.ports.metrics.filter(|p| {
                    node.ports.http_json != Some(*p)
                        && node.ports.grpc_ledger != Some(*p)
                        && node.ports.admin != Some(*p)
                }) {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.metrics", node.name),
                        url: format!("http://127.0.0.1:{mp}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/livez" },
                        lifecycle: life,
                    });
                }
            }
            NodeRole::Scan => {
                if let Some(p) = node.ports.http_json {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.http", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::HttpHealth {
                            path: "/api/scan/v0/dso-party-id",
                        },
                        lifecycle: life,
                    });
                }
            }
            NodeRole::Splice | NodeRole::Pqs => {
                if let Some(p) = node.ports.http_json {
                    out.push(PlannedEndpointProbe {
                        label: format!("{}.http", node.name),
                        url: format!("http://127.0.0.1:{p}"),
                        kind: EndpointProbeKind::HttpHealth { path: "/livez" },
                        lifecycle: life,
                    });
                }
            }
        }
    }
    if let Some(mp) = snapshot.metrics_port.filter(|&p| p != 0) {
        let host = connect_host(snapshot.metrics_bind.as_deref());
        out.push(PlannedEndpointProbe {
            label: "metrics".to_string(),
            url: format!("http://{host}:{mp}"),
            kind: EndpointProbeKind::HttpHealth { path: "/livez" },
            lifecycle: Some(NodeLifecycleState::Online),
        });
    }
    out
}

async fn probe_grpc_health(url: &str) -> bool {
    let Ok(endpoint) = Endpoint::from_shared(url.to_string()) else {
        return false;
    };
    let endpoint = endpoint
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT);
    let Ok(channel) = endpoint.connect().await else {
        return false;
    };
    let mut client = HealthClient::new(channel);
    let req = tonic::Request::new(HealthCheckRequest {
        service: String::new(),
    });
    match client.check(req).await {
        Ok(resp) => resp.into_inner().status == ServingStatus::Serving as i32,
        Err(_) => false,
    }
}

fn probe_tcp_connect(url: &str) -> bool {
    let host_port = url
        .strip_prefix("tcp://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let Ok(addr) = host_port.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

async fn probe_single_endpoint(spec: PlannedEndpointProbe) -> (String, EndpointStatus) {
    let ok = match spec.kind {
        EndpointProbeKind::HttpHealth { path } => {
            let full = format!("{}{path}", spec.url);
            tokio::task::spawn_blocking(move || {
                matches!(
                    http_request(&full, "GET", None, None, PROBE_TIMEOUT),
                    Ok((code, _)) if (200..300).contains(&code)
                )
            })
            .await
            .unwrap_or(false)
        }
        EndpointProbeKind::GrpcHealth => probe_grpc_health(&spec.url).await,
        EndpointProbeKind::TcpConnect => {
            let target = spec.url.clone();
            tokio::task::spawn_blocking(move || probe_tcp_connect(&target))
                .await
                .unwrap_or(false)
        }
    };
    let state = resolve_endpoint_state(ok, spec.lifecycle);
    (
        spec.label,
        EndpointStatus {
            url: spec.url,
            state,
        },
    )
}

/// Maps real probe success and optional node lifecycle into [`EndpointState`] (`P-A4`).
///
/// [CANTON-NOTE: INVARIANT] `state == EndpointState::Up` holds if and only if the live probe succeeds.
pub const fn resolve_endpoint_state(
    probe_ok: bool,
    lifecycle: Option<NodeLifecycleState>,
) -> EndpointState {
    if probe_ok {
        return EndpointState::Up;
    }
    match lifecycle {
        Some(NodeLifecycleState::Bootstrapping | NodeLifecycleState::BackoffWait) => {
            EndpointState::Starting
        }
        Some(NodeLifecycleState::Failed) => EndpointState::Failed,
        _ => EndpointState::Down,
    }
}

fn probe_all_endpoints(
    specs: Vec<PlannedEndpointProbe>,
) -> Result<BTreeMap<String, EndpointStatus>, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build probe runtime: {e}"))?;
    Ok(rt.block_on(async move {
        let mut join_set = tokio::task::JoinSet::new();
        for spec in specs {
            join_set.spawn(probe_single_endpoint(spec));
        }
        let mut out = BTreeMap::new();
        while let Some(joined) = join_set.join_next().await {
            if let Ok((label, status)) = joined {
                out.insert(label, status);
            }
        }
        out
    }))
}

fn resolve_target_dir(
    state_dir: &Path,
) -> Result<(PathBuf, Option<ClusterSnapshot>, Option<LocalnetStatusFile>), String> {
    let resolved = resolve_client_state_dir(state_dir);
    let sock = socket_path(&resolved);
    if sock.exists() || sock.symlink_metadata().is_ok() {
        if let Ok(IpcResponse::Snapshot { ok: true, snapshot }) =
            call_unary(&resolved, &IpcRequest::GetSnapshot)
        {
            return Ok((resolved, Some(snapshot), None));
        }
    }

    if let Some(local) = read_live_localnet_file(&resolved)? {
        return Ok((resolved, None, Some(local)));
    }

    if state_dir == Path::new(DEFAULT_STATE_DIR) {
        let marker = std::env::temp_dir().join(LAST_LOCALNET_STATE_DIR_FILE);
        if let Ok(saved) = fs::read_to_string(&marker) {
            let candidate = PathBuf::from(saved.trim());
            if let Some(local) = read_live_localnet_file(&candidate)? {
                return Ok((candidate, None, Some(local)));
            }
        }
    }

    Err(format!(
        "no running canton-rs daemon or localnet found at {}",
        state_dir.display()
    ))
}

/// Probes live supervisor or `localnet up` endpoints and returns a [`DaemonStatusReport`].
pub fn collect_daemon_status(state_dir: &Path) -> Result<DaemonStatusReport, String> {
    let (target_dir, snap_opt, local_opt) = resolve_target_dir(state_dir)?;
    let (instance, planned) = match (snap_opt, local_opt) {
        (Some(snapshot), _) => {
            let inst = read_instance_name(&target_dir);
            let specs = endpoints_from_snapshot(&snapshot);
            (inst, specs)
        }
        (None, Some(local)) => {
            let inst = local.instance.or_else(|| read_instance_name(&target_dir));
            let specs = local
                .endpoints
                .into_iter()
                .map(|ep| PlannedEndpointProbe {
                    kind: endpoint_kind_for_localnet_role(&ep.role),
                    label: ep.label,
                    url: ep.url,
                    lifecycle: None,
                })
                .collect();
            (inst, specs)
        }
        (None, None) => {
            return Err(format!(
                "no running canton-rs daemon or localnet found at {}",
                target_dir.display()
            ));
        }
    };

    let endpoints = probe_all_endpoints(planned)?;
    Ok(DaemonStatusReport {
        schema: STATUS_JSON_SCHEMA.to_string(),
        instance,
        state_dir: absolute_dir_string(&target_dir),
        endpoints,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Renders [`DaemonStatusReport`] as deterministic pretty JSON (`P-A6`).
pub fn render_status_json(report: &DaemonStatusReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}

/// Renders human-readable status lines from the exact same [`DaemonStatusReport`].
pub fn render_status_text(report: &DaemonStatusReport) -> String {
    let mut out = String::new();
    let inst = report.instance.as_deref().unwrap_or("-");
    out.push_str(&format!(
        "canton-rs daemon status (schema={}, version={}, instance={}, state_dir={})\n",
        report.schema, report.version, inst, report.state_dir
    ));
    if report.endpoints.is_empty() {
        out.push_str("  (no endpoints registered)\n");
    } else {
        for (label, ep) in &report.endpoints {
            out.push_str(&format!(
                "  {:<16} {:<9} {}\n",
                label,
                ep.state.as_str(),
                ep.url
            ));
        }
    }
    out
}

/// Maps endpoint label `ℓ` to `CANTON_RS_<UPPER>_URL` (e.g. `p1.json` -> `CANTON_RS_P1_JSON_URL`).
pub fn label_to_env_var(label: &str) -> String {
    let mut normalized = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
        } else {
            normalized.push('_');
        }
    }
    format!("CANTON_RS_{normalized}_URL")
}

fn is_safe_env_url(url: &str) -> bool {
    !url.is_empty()
        && !url.bytes().any(|b| {
            b.is_ascii_control()
                || matches!(
                    b,
                    b' ' | b'\t'
                        | b'\''
                        | b'"'
                        | b'$'
                        | b'`'
                        | b';'
                        | b'|'
                        | b'&'
                        | b'\\'
                        | b'('
                        | b')'
                        | b'<'
                        | b'>'
                )
        })
}

/// Renders POSIX shell `export` assignments matching [`DaemonStatusReport::endpoints`] (`P-A5`).
pub fn render_env_exports(report: &DaemonStatusReport) -> Result<String, String> {
    let mut out = String::new();
    for (label, ep) in &report.endpoints {
        if !is_safe_env_url(&ep.url) {
            return Err(format!(
                "unsafe characters in endpoint URL for {label}: {}",
                ep.url
            ));
        }
        let var = label_to_env_var(label);
        out.push_str(&format!("export {var}={}\n", ep.url));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        label_to_env_var, render_env_exports, render_status_json, render_status_text,
        resolve_endpoint_state, DaemonStatusReport, EndpointState, EndpointStatus,
        STATUS_JSON_SCHEMA,
    };
    use crate::commands::supervisor::NodeLifecycleState;

    fn sample_report() -> DaemonStatusReport {
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            "s1.public".to_string(),
            EndpointStatus {
                url: "http://127.0.0.1:47000".to_string(),
                state: EndpointState::Up,
            },
        );
        endpoints.insert(
            "p1.json".to_string(),
            EndpointStatus {
                url: "http://127.0.0.1:47100".to_string(),
                state: EndpointState::Up,
            },
        );
        endpoints.insert(
            "m1.admin".to_string(),
            EndpointStatus {
                url: "http://127.0.0.1:47002".to_string(),
                state: EndpointState::Down,
            },
        );
        DaemonStatusReport {
            schema: STATUS_JSON_SCHEMA.to_string(),
            instance: Some("dev-alpha".to_string()),
            state_dir: "/tmp/crs-dev-alpha".to_string(),
            endpoints,
            version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn status_json_roundtrip_and_key_order_isomorphic() {
        let report = sample_report();
        let json = render_status_json(&report).expect("render status json");
        let reparsed: DaemonStatusReport = serde_json::from_str(&json).expect("reparse json");
        assert_eq!(reparsed, report);

        let m1_pos = json.find("\"m1.admin\"").expect("m1.admin present");
        let p1_pos = json.find("\"p1.json\"").expect("p1.json present");
        let s1_pos = json.find("\"s1.public\"").expect("s1.public present");
        assert!(m1_pos < p1_pos && p1_pos < s1_pos);

        let text = render_status_text(&report);
        assert!(text.contains("dev-alpha"));
        assert!(text.contains("p1.json"));
    }

    #[test]
    fn env_var_mapping_and_export_rendering() {
        assert_eq!(label_to_env_var("p1.json"), "CANTON_RS_P1_JSON_URL");
        assert_eq!(label_to_env_var("s1.public"), "CANTON_RS_S1_PUBLIC_URL");
        assert_eq!(label_to_env_var("scan.http"), "CANTON_RS_SCAN_HTTP_URL");
        assert_eq!(
            label_to_env_var("splice-app.http"),
            "CANTON_RS_SPLICE_APP_HTTP_URL"
        );

        let report = sample_report();
        let exports = render_env_exports(&report).expect("render env exports");
        assert_eq!(
            exports,
            "export CANTON_RS_M1_ADMIN_URL=http://127.0.0.1:47002\n\
export CANTON_RS_P1_JSON_URL=http://127.0.0.1:47100\n\
export CANTON_RS_S1_PUBLIC_URL=http://127.0.0.1:47000\n"
        );

        let mut unsafe_report = sample_report();
        unsafe_report.endpoints.insert(
            "p1.json".into(),
            EndpointStatus {
                url: "http://127.0.0.1:47100;id".into(),
                state: EndpointState::Up,
            },
        );
        assert!(render_env_exports(&unsafe_report).is_err());
    }

    #[test]
    fn endpoint_state_reflects_probe_and_lifecycle() {
        assert_eq!(
            resolve_endpoint_state(true, Some(NodeLifecycleState::Bootstrapping)),
            EndpointState::Up
        );
        assert_eq!(
            resolve_endpoint_state(false, Some(NodeLifecycleState::Bootstrapping)),
            EndpointState::Starting
        );
        assert_eq!(
            resolve_endpoint_state(false, Some(NodeLifecycleState::BackoffWait)),
            EndpointState::Starting
        );
        assert_eq!(
            resolve_endpoint_state(false, Some(NodeLifecycleState::Failed)),
            EndpointState::Failed
        );
        assert_eq!(
            resolve_endpoint_state(false, Some(NodeLifecycleState::Stopped)),
            EndpointState::Down
        );
        assert_eq!(resolve_endpoint_state(false, None), EndpointState::Down);
    }
}
