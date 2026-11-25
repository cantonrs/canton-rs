//! Built-in multi-node process supervisor domain models, normalization spec, and secret-masking helpers.
//!
//! [CANTON-NOTE: INVARIANT] This module is the Single Source of Truth shared by the background supervisor
//! engine, `daemon ps`/`stats`/`inspect`, Prometheus `/metrics`, the Zero-Payload X-Ray wiretap, the
//! `ratatui` TUI (`daemon top`), and `console attach`/`exec`.

pub mod cli;
pub mod creds;
pub mod dar_watch;
pub mod doctor;
pub mod engine;
pub mod ipc;
pub mod log_policy;
pub mod log_rotate;
pub mod manifest;
pub mod metrics;
pub mod observability;
pub mod probe;
pub mod proc_sampler;
pub mod process;
pub mod projection;
pub mod query;
pub mod registry;
pub mod scenario;
pub mod service_unit;
pub mod snapshot;
pub mod status;
pub mod topology;
pub mod tui;
pub mod wiretap;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default per-log-file byte limit before newline-boundary rotation (50 MiB).
pub const DEFAULT_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;
/// Default number of rotated log generations (`.log.1` .. `.log.5`).
pub const DEFAULT_LOG_MAX_FILES: usize = 5;
/// Default supervisor Prometheus exporter port.
pub const DEFAULT_METRICS_PORT: u16 = 9464;
/// Default Zero-Payload Wiretap event emission cap per second.
pub const DEFAULT_TRACE_RATE_LIMIT: u32 = 100;
/// Default graceful shutdown window (`SIGTERM` -> `SIGKILL`).
pub const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 10;

/// Returns current wall-clock time in Unix milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Returns current wall-clock time in Unix seconds.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cluster-wide observation snapshot updated on a 1-second cadence by the supervisor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterSnapshot {
    pub stack_name: String,
    pub synchronizer: String,
    /// Storage mode summary: `"postgres"` | `"files"` | `"hybrid"`.
    pub storage_mode: String,
    pub collected_at_unix_ms: u64,
    pub total_cpu_percent: f64,
    pub total_rss_bytes: u64,
    pub last_ping: Option<PingStatus>,
    /// Populated when `--shadow-verify` / `shadow_verify: true` is active.
    pub shadow_verify: Option<ShadowVerifySummary>,
    /// Cumulative number of wiretap events dropped via non-blocking `try_send`.
    pub wiretap_dropped_events: u64,
    #[serde(default)]
    pub scenarios: Vec<scenario::ScenarioSpec>,
    #[serde(default)]
    pub metrics_port: Option<u16>,
    #[serde(default)]
    pub metrics_bind: Option<String>,
    pub nodes: Vec<NodeSnapshot>,
}

/// Result of a cluster end-to-end health ping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingStatus {
    pub ok: bool,
    pub rtt_ms: f64,
    pub detail: String,
    pub checked_at_unix_ms: u64,
}

/// Logical Canton / Splice role managed inside a permanent supervisor slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Sequencer,
    Mediator,
    Participant,
    Splice,
    Scan,
    Pqs,
}

impl NodeRole {
    /// Canonical lowercase label string used in CLI tables, IPC, and Prometheus labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Mediator => "mediator",
            Self::Participant => "participant",
            Self::Splice => "splice",
            Self::Scan => "scan",
            Self::Pqs => "pqs",
        }
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of a supervisor slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    Online,
    Bootstrapping,
    Degraded,
    BackoffWait,
    Stopped,
    Failed,
}

impl NodeLifecycleState {
    /// Stable Prometheus one-hot state label (`online`, `bootstrapping`, `degraded`, `backoff`, `stopped`, `failed`).
    pub const fn prometheus_state(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Bootstrapping => "bootstrapping",
            Self::Degraded => "degraded",
            Self::BackoffWait => "backoff",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// Human-readable status column text for CLI and TUI tables.
    pub const fn display_label(self) -> &'static str {
        match self {
            Self::Online => "Up (healthy)",
            Self::Bootstrapping => "Bootstrapping",
            Self::Degraded => "Degraded",
            Self::BackoffWait => "BackoffWait",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }
}

/// Automatic restart policy for a managed service slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    UnlessStopped,
    Always,
    OnFailure,
    No,
}

impl RestartPolicy {
    /// Canonical YAML/CLI representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnlessStopped => "unless-stopped",
            Self::Always => "always",
            Self::OnFailure => "on-failure",
            Self::No => "no",
        }
    }
}

/// Network port bindings assigned to a node slot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePorts {
    pub public: Option<u16>,
    pub http_json: Option<u16>,
    pub grpc_ledger: Option<u16>,
    pub admin: Option<u16>,
    pub metrics: Option<u16>,
    pub p2p: Option<u16>,
}

impl NodePorts {
    /// Formats exposed ports concisely for `daemon ps` and TUI detail panes.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = self.public {
            parts.push(format!("{p}->public"));
        }
        if let Some(p) = self.http_json {
            parts.push(format!("{p}->json"));
        }
        if let Some(p) = self.grpc_ledger {
            parts.push(format!("{p}->grpc"));
        }
        if let Some(p) = self.admin {
            parts.push(format!("{p}->admin"));
        }
        if let Some(p) = self.p2p {
            parts.push(format!("{p}->p2p"));
        }
        if let Some(p) = self.metrics.filter(|mp| {
            self.public != Some(*mp) && self.http_json != Some(*mp) && self.admin != Some(*mp)
        }) {
            parts.push(format!("{p}->metrics"));
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// Returns distinct configured TCP listener ports in this struct.
    ///
    /// [CANTON-NOTE: INVARIANT] Participants and mediators serve `/metrics` on their primary
    /// `http_json` or `admin` HTTP listener rather than binding a second TCP socket, so shared
    /// `metrics` ports must not be emitted twice during port-collision checks.
    pub fn all_ports(&self) -> Vec<u16> {
        let primary = [
            self.public,
            self.http_json,
            self.grpc_ledger,
            self.admin,
            self.p2p,
        ];
        let dedicated_metrics = self
            .metrics
            .filter(|mp| !primary.iter().flatten().any(|p| p == mp));
        primary
            .into_iter()
            .chain(std::iter::once(dedicated_metrics))
            .flatten()
            .collect()
    }
}

/// Point-in-time OS resource metrics collected by `OsProcSampler`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ProcResources {
    /// CPU usage percentage over the last sampling window (`100.0` = 1 core 100%).
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub vms_bytes: u64,
    pub thread_count: u32,
    pub open_fds: u32,
}

/// Compact 24-byte sample stored in each node's 300-second history ring buffer for Sparklines.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ResourceSample {
    pub ts_unix_ms: u64,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
}

/// Role-specific domain telemetry aggregated into `ClusterSnapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DomainMetrics {
    Participant {
        ledger_end_offset: u64,
        active_contracts: u64,
        hosted_parties: u64,
        loaded_dars: u64,
        ready: bool,
        ready_reason: String,
        #[serde(default)]
        api_requests_total: u64,
    },
    Sequencer {
        head_offset: u64,
        connected_members: u64,
        bft_quorum_peers: Option<(u32, u32)>,
    },
    Mediator {
        group_id: u32,
        verdicts_approved: u64,
        verdicts_rejected: u64,
        #[serde(default)]
        pending_quorums: u64,
    },
    Splice {
        open_round: Option<u64>,
        scan_updates_total: u64,
        ledger_backend_connected: bool,
    },
    Pqs {
        watermark_offset: u64,
        active_contracts: u64,
        connected: bool,
    },
}

/// Observed state for one permanent slot inside `ClusterSnapshot`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub slot_id: usize,
    pub role: NodeRole,
    pub name: String,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub synchronizer_domain: Option<String>,
    #[serde(default)]
    pub host_label: Option<String>,
    pub pid: Option<u32>,
    pub ports: NodePorts,
    pub state: NodeLifecycleState,
    pub restart_policy: RestartPolicy,
    pub restarts_total: u64,
    pub consecutive_failures: u32,
    pub uptime_secs: u64,
    pub stopped_at_unix_ms: Option<u64>,
    pub last_exit_reason: Option<String>,
    pub resources: ProcResources,
    pub history_60s: Vec<ResourceSample>,
    pub domain: DomainMetrics,
}

/// On-demand snapshot of `GET /_exex` subscriber telemetry on one participant node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExExNodeSummary {
    pub node_name: String,
    pub port: u16,
    pub reachable: bool,
    pub active_subscribers: u64,
    pub subscriber_lines: Vec<String>,
}

/// DAR summary returned as part of `NodeInspection`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DarSummary {
    pub name: String,
    pub version: Option<String>,
    pub main_package_id: String,
    pub vetted: bool,
}

/// On-demand 4-layer detail inspection for `daemon inspect <node>` and TUI `[i]`/`[Enter]`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInspection {
    pub role: NodeRole,
    pub name: String,
    pub pid: Option<u32>,
    pub state: NodeLifecycleState,
    // 1. Paths & configuration
    pub config_path: Option<String>,
    pub bootstrap_path: Option<String>,
    pub state_dir: String,
    pub log_file_path: String,
    pub log_file_bytes: u64,
    pub log_generations: usize,
    pub log_encoder: String,
    pub port_offset: u16,
    pub sanitized_argv: Vec<String>,
    pub config_applied_count: usize,
    pub config_not_applied_keys: Vec<String>,
    // 2. Storage & auth (secrets strictly masked)
    pub storage_summary: String,
    pub same_identity: bool,
    pub official_write: bool,
    pub auth_mode: String,
    // 3. Canton domain state (zero contract payloads)
    pub node_uid: Option<String>,
    pub physical_synchronizer_id: Option<String>,
    pub protocol_version: Option<String>,
    pub loaded_dars: Vec<DarSummary>,
    pub hosted_parties: Vec<String>,
    pub user_count: Option<u64>,
    // 4. Ports & fault history
    pub ports: NodePorts,
    pub restarts_total: u64,
    pub last_exit_at_unix_ms: Option<u64>,
    pub last_exit_reason: Option<String>,
}

/// Outcome state for a 2PC Mediator verdict in X-Ray traces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumVerdictState {
    Pending,
    Approved,
    Rejected,
    TimedOut,
}

impl QuorumVerdictState {
    /// Returns true if this trace represents an anomaly (`Rejected` or `TimedOut`).
    pub const fn is_anomaly(self) -> bool {
        matches!(self, Self::Rejected | Self::TimedOut)
    }
}

/// Per-informee quorum vote inside a blinded view.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VoteStatus {
    Approved { latency_ms: f64 },
    Rejected { code: String },
    Pending { elapsed_ms: f64 },
}

/// Informee confirmation record inside a blinded view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InformeeVote {
    pub party_id: String,
    pub vote: VoteStatus,
}

/// Quorum state for one blinded sub-transaction view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedViewQuorum {
    pub view_hash: String,
    pub threshold: u32,
    pub informees: Vec<InformeeVote>,
}

/// Zero-Payload 4-Hop Protocol X-Ray trace event.
///
/// [CANTON-NOTE: INVARIANT] Zero contract payload bytes (`create_arguments`, `choice_argument`, `Value`,
/// or raw ciphertexts) exist anywhere in this struct, enforcing a compile-time zero-knowledge boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XRayTraceEvent {
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
    pub bft_block_height: Option<u64>,
    pub bft_order_latency_ms: Option<f64>,
    pub mediator_verdict: QuorumVerdictState,
    pub total_latency_ms: f64,
    pub views: Vec<BlindedViewQuorum>,
}

/// Shadow-Mode Dual Verifier comparison summary (`--shadow-verify`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShadowVerifySummary {
    pub verified_tx_total: Option<u64>,
    pub mismatch_total: Option<u64>,
    pub match_ratio_percent: Option<f64>,
    pub baseline_jvm_rss_bytes: Option<u64>,
    pub canton_rs_p99_ms: f64,
}

/// Non-managed `canton-rs` process discovered on the host by `daemon ps --scan-host`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnmanagedProcess {
    pub pid: u32,
    pub role_hint: String,
    pub ports: Vec<u16>,
    pub sanitized_cmdline: String,
    pub resources: ProcResources,
}

/// Normalized storage declaration for a supervised service slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageSpec {
    #[default]
    Files,
    Postgres {
        url: String,
        #[serde(default)]
        name: Option<String>,
    },
    Memory,
}

impl StorageSpec {
    /// Returns a credential-masked description safe for `NodeInspection` and `daemon config`.
    pub fn masked_summary(&self) -> String {
        match self {
            Self::Files => "files".to_string(),
            Self::Memory => "memory".to_string(),
            Self::Postgres { url, name } => {
                let masked = mask_secret_url(url);
                match name {
                    Some(n) => format!("{masked} (state={n})"),
                    None => masked,
                }
            }
        }
    }
}

/// Normalized definition of one permanently indexed supervisor service slot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonServiceSpec {
    pub slot_id: usize,
    pub name: String,
    pub role: NodeRole,
    pub ports: NodePorts,
    pub restart: RestartPolicy,
    pub depends_on: Vec<String>,
    pub dars: Vec<PathBuf>,
    pub dar_dir: Option<PathBuf>,
    pub ledger_of: Option<String>,
    pub ledger_url: Option<String>,
    pub automation_interval_ms: Option<u64>,
    pub storage: StorageSpec,
    /// Pre-built CLI arguments passed to `canton-rs` when spawning this role.
    pub argv: Vec<String>,
    /// Extra environment variables (masked before display in `inspect`).
    pub env: BTreeMap<String, String>,
    pub health_url: Option<String>,
    pub readiness_url: Option<String>,
    pub status_url: Option<String>,
    pub metrics_url: Option<String>,
    pub xray_url: Option<String>,
    /// Explicit per-service YAML `xray: <bool>` setting so CLI `--xray` respects `xray: false`.
    #[serde(default)]
    pub xray_override: Option<bool>,
    pub state_dir: PathBuf,
    pub auth_mode: String,
    pub config_path: Option<PathBuf>,
    pub bootstrap_path: Option<PathBuf>,
    pub port_offset: u16,
    pub same_identity: bool,
    pub official_write: bool,
    pub config_applied_count: usize,
    pub config_not_applied_keys: Vec<String>,
    pub ready_line_prefix: Option<String>,
    pub bft_peer_count: Option<usize>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub synchronizer_domain: Option<String>,
    #[serde(default)]
    pub also_synchronizers: Vec<String>,
    #[serde(default)]
    pub limits: Option<topology::ResourceLimits>,
    /// Where the supervisor reads the bearer token it sends to this node (probes, polling, Ping); a `pqs` slot also hands it to the
    /// sync it runs.
    #[serde(default)]
    pub token: Option<TokenSource>,
    /// Resolved host bind address configured for this service slot (`127.0.0.1` unless overridden).
    #[serde(default)]
    pub bind_host: Option<String>,
}

/// Where a bearer token is read from. It is read again on every use, so a token renewed in place is picked up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    /// The supervisor's environment variable of this name.
    Env(String),
    /// A file holding the token (surrounding whitespace ignored).
    File(PathBuf),
    /// Mint short-lived dev-auth HS256 bearer tokens in memory from `dev-jwt.key` and `participant-id` (`S-DX-007`).
    DevJwt {
        key_file: PathBuf,
        participant_id_file: PathBuf,
    },
}

impl TokenSource {
    /// The current token, or `None` when the variable is unset or the file unreadable or empty.
    pub fn read(&self) -> Option<String> {
        let raw = match self {
            Self::Env(name) => std::env::var(name).ok()?,
            Self::File(path) => std::fs::read_to_string(path).ok()?,
            Self::DevJwt {
                key_file,
                participant_id_file,
            } => return creds::mint_supervisor_probe_token(key_file, participant_id_file),
        };
        let token = raw.trim();
        (!token.is_empty()).then(|| token.to_string())
    }
}

/// Normalized supervisor stack specification parsed from `canton-daemon.yaml` or legacy `daemon -c`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonSpec {
    pub name: String,
    pub synchronizer: String,
    pub state_dir: PathBuf,
    pub metrics_port: Option<u16>,
    pub metrics_bind: String,
    pub log_encoder: String,
    pub log_max_bytes: u64,
    pub log_max_files: usize,
    #[serde(default)]
    pub logging: log_policy::LogPolicy,
    pub trace_rate_limit_per_sec: u32,
    #[serde(default)]
    pub xray: bool,
    pub no_restart: bool,
    pub max_restarts: Option<u64>,
    pub shadow_verify: bool,
    pub shadow_jvm_url: Option<String>,
    pub foreground_legacy_banner: bool,
    pub shutdown_timeout_secs: u64,
    pub manifest_path: Option<PathBuf>,
    pub canton_conf: Option<PathBuf>,
    pub bootstrap: Option<PathBuf>,
    pub port_offset: u16,
    pub same_identity: bool,
    pub official_write: bool,
    pub official_pg_addr: Option<String>,
    pub auth_cert: Option<PathBuf>,
    pub strict_config: bool,
    pub wait_for_deps_secs: u64,
    #[serde(default)]
    pub cells: BTreeMap<String, topology::CellSpec>,
    #[serde(default)]
    pub remote_clusters: Vec<topology::RemoteClusterSpec>,
    #[serde(default)]
    pub scenarios: Vec<scenario::ScenarioSpec>,
    pub services: Vec<DaemonServiceSpec>,
    /// Initial `HealthPing` verification targets (`(from_participant, to_participant)`) derived from `bootstrap.sc` or manifest.
    pub ping_participants: Vec<(String, String)>,
    /// Whether loopback-only `--dev-auth` HS256 JWT enforcement is active (`S-DX-007`).
    #[serde(default)]
    pub dev_auth: bool,
    /// Whether `--observability` writes Prometheus `file_sd` target JSON files (`S-DX-010`).
    #[serde(default)]
    pub observability: bool,
    /// Distinct host/interface bind addresses collected across the stack (`S-DX-007`).
    #[serde(default)]
    pub bind_addresses: Vec<String>,
}

/// Masks passwords inside database/HTTP URLs (`scheme://user:secret@host/db` -> `scheme://user:****@host/db`).
pub fn mask_secret_url(input: &str) -> String {
    let Some((scheme_user, host_and_rest)) = input.split_once('@') else {
        return mask_libpq_kv(input);
    };
    if let Some((prefix, _secret)) = scheme_user.rsplit_once(':') {
        if prefix.contains("://") {
            return format!("{prefix}:****@{host_and_rest}");
        }
    }
    input.to_string()
}

fn mask_libpq_kv(input: &str) -> String {
    if !input.contains("password=") && !input.contains("Password=") {
        return input.to_string();
    }
    input
        .split_whitespace()
        .map(|part| {
            if let Some((k, _)) = part.split_once('=') {
                if k.eq_ignore_ascii_case("password") {
                    return format!("{k}=****");
                }
            }
            part.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Sanitizes command-line arguments so secrets (`--jwt-hmac-secret`, `--pg-url`, URLs with passwords)
/// are replaced with `****` before leaving the process boundary.
pub fn sanitize_argv(argv: &[String]) -> Vec<String> {
    let secret_flags = [
        "--jwt-hmac-secret",
        "--state-pg-url",
        "--official-pg-url",
        "--pg-url",
        "--ord-pg-url",
        "--password",
    ];
    let mut out = Vec::with_capacity(argv.len());
    let mut mask_next = false;
    for arg in argv {
        if mask_next {
            out.push(if arg.contains("://") || arg.contains("password=") {
                mask_secret_url(arg)
            } else {
                "****".to_string()
            });
            mask_next = false;
            continue;
        }
        if secret_flags.iter().any(|f| arg == f) {
            out.push(arg.clone());
            mask_next = true;
            continue;
        }
        if let Some((flag, val)) = arg.split_once('=') {
            if secret_flags.contains(&flag) {
                let masked = if val.contains("://") || val.contains("password=") {
                    mask_secret_url(val)
                } else {
                    "****".to_string()
                };
                out.push(format!("{flag}={masked}"));
                continue;
            }
        }
        out.push(mask_secret_url(arg));
    }
    out
}

/// Formats bytes into compact human-readable KiB/MiB/GiB units.
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// Formats uptime seconds compactly (`2h 14m`, `45s`, etc.).
pub fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m {}s", secs % 60);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h {}m", mins % 60);
    }
    let days = hours / 24;
    format!("{days}d {}h", hours % 24)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_urls_and_secret_argv_flags() {
        let masked = mask_secret_url("postgres://canton:supersecret@127.0.0.1:6432/hub");
        assert_eq!(masked, "postgres://canton:****@127.0.0.1:6432/hub");
        assert!(!masked.contains("supersecret"));

        let kv = mask_secret_url("host=127.0.0.1 user=canton password=topsecret dbname=hub");
        assert_eq!(kv, "host=127.0.0.1 user=canton password=**** dbname=hub");
        assert!(!kv.contains("topsecret"));

        let argv = vec![
            "json-api".to_string(),
            "--jwt-hmac-secret".to_string(),
            "my-hmac-key".to_string(),
            "--state-pg-url=postgresql://u:pw123@localhost:5432/db".to_string(),
            "--port".to_string(),
            "7575".to_string(),
        ];
        let clean = sanitize_argv(&argv);
        let joined = clean.join(" ");
        assert!(!joined.contains("my-hmac-key"));
        assert!(!joined.contains("pw123"));
        assert!(joined.contains("****"));
        assert!(joined.contains("--port 7575"));
    }

    #[test]
    fn xray_event_serializes_with_zero_payload_fields() {
        let event = XRayTraceEvent {
            root_hash: "12207f83b165".to_string(),
            started_at_unix_ms: 1_700_000_000_000,
            submitter_participant: "participant1".to_string(),
            package_id: "8f3ac102".to_string(),
            template_qualified_name: Some("Asset:Holding".to_string()),
            daml_eval_us: 380,
            blinded_view_count: 2,
            sealed_envelope_bytes: 1420,
            traffic_cost_bytes: 1420,
            recipient_member_count: 3,
            bft_block_height: Some(1483),
            bft_order_latency_ms: Some(3.2),
            mediator_verdict: QuorumVerdictState::Approved,
            total_latency_ms: 11.4,
            views: vec![BlindedViewQuorum {
                view_hash: "0x9a4c".to_string(),
                threshold: 1,
                informees: vec![InformeeVote {
                    party_id: "Alice::1220ab".to_string(),
                    vote: VoteStatus::Approved { latency_ms: 1.1 },
                }],
            }],
        };
        let json = serde_json::to_string(&event).expect("serialize XRayTraceEvent");
        assert!(!json.contains("create_arguments"));
        assert!(!json.contains("choice_argument"));
        assert!(!json.contains("ciphertext"));
        assert!(json.contains("12207f83b165"));
    }

    #[test]
    fn shared_metrics_port_is_deduplicated_while_distinct_ports_preserved() {
        let shared = NodePorts {
            public: None,
            http_json: Some(6575),
            grpc_ledger: Some(6501),
            admin: Some(6502),
            metrics: Some(6575),
            p2p: None,
        };
        assert_eq!(shared.all_ports(), vec![6575, 6501, 6502]);
        assert_eq!(shared.summary(), "6575->json, 6501->grpc, 6502->admin");

        let dedicated = NodePorts {
            public: Some(5018),
            metrics: Some(5019),
            ..NodePorts::default()
        };
        assert_eq!(dedicated.all_ports(), vec![5018, 5019]);
        assert_eq!(dedicated.summary(), "5018->public, 5019->metrics");

        // Negative control: distinct protocol endpoints colliding on the same port remain duplicated so collision checks reject them.
        let colliding = NodePorts {
            http_json: Some(6575),
            admin: Some(6575),
            ..NodePorts::default()
        };
        assert_eq!(colliding.all_ports(), vec![6575, 6575]);
    }
}
