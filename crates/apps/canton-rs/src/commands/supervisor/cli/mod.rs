//! Supervisor CLI subcommands (`canton-rs daemon <up|down|ps|stop|start|restart|logs|stats|top|inspect|init|config|install-service|attach|exec>`)
//! and terminal output formatters.

mod lifecycle;
mod observe;
#[cfg(test)]
mod tests;

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use ledger_json_api::canton_log::LogEncoder;

pub(crate) use self::lifecycle::cmd_down_with_writer;
use self::lifecycle::{cmd_doctor, cmd_down, cmd_remove, cmd_restart, cmd_start, cmd_stop, cmd_up};
use self::observe::{
    cmd_config, cmd_env, cmd_init, cmd_inspect, cmd_install_service, cmd_list, cmd_logs, cmd_ps,
    cmd_stats, cmd_status,
};

use super::tui::run_top;
use super::{
    DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES, DEFAULT_SHUTDOWN_TIMEOUT_SECS,
    DEFAULT_TRACE_RATE_LIMIT,
};

/// Default state directory shared across `daemon` supervisor subcommands.
pub const DEFAULT_STATE_DIR: &str = "canton-rs-state";

/// Supervisor subcommands nested cleanly under `canton-rs daemon`.
#[derive(Subcommand, Debug, Clone)]
pub enum DaemonAction {
    /// Start multi-node stack (`canton-daemon.yaml` or `-c canton.conf`) in dependency order.
    #[command(visible_alias = "start-stack")]
    Up(Box<UpArgs>),
    /// Gracefully stop all managed slots in reverse dependency order and exit supervisor daemon.
    #[command(visible_alias = "kill")]
    Down(DownArgs),
    /// Show managed slots and optional unmanaged host `canton-rs` processes.
    #[command(visible_alias = "ls")]
    Ps(PsArgs),
    /// List all registered named supervisor instances (`<root>/instances/*`) (`S-DX-003`).
    List(ListArgs),
    /// Remove a named supervisor instance and its local files / PostgreSQL schemas (`S-DX-003`).
    Remove(RemoveArgs),
    /// Show canonical endpoint status (`canton-rs.status/1`) for managed daemon or active LocalNet (`S-DX-002`).
    Status(StatusArgs),
    /// Export shell environment variables (`CANTON_RS_<LABEL>_URL=<url>`) matching `daemon status` (`S-DX-002`).
    Env(EnvArgs),
    /// Stop specific managed service slot(s) by name, slot ID, or PID (preserves slot & pauses auto-restart).
    Stop(SlotTargetsArgs),
    /// Start/resume stopped service slot(s) or bring stack up.
    Start(StartOrUpArgs),
    /// Gracefully restart specific service (or all services when omitted).
    #[command(visible_alias = "reload")]
    Restart(RestartArgs),
    /// Stream or tail multiplexed node logs with color alignment and level filtering.
    Logs(LogsArgs),
    /// Live resource table (CPU%, RSS, VMS, FDs, threads, uptime, restarts).
    Stats(StatsArgs),
    /// Launch full-screen interactive master-detail `ratatui` cluster & X-Ray dashboard (`q` detaches).
    #[command(visible_aliases = ["tui", "monit"])]
    Top(StateDirArg),
    /// Detailed 4-layer node inspection (masked secrets) or Root Hash Zero-Payload X-Ray trace.
    #[command(visible_aliases = ["describe", "show"])]
    Inspect(InspectArgs),
    /// Generate starter `canton-daemon.yaml` (default, localnet template, or wrapping `canton.conf`).
    Init(InitArgs),
    /// Expand `.env`, verify ports & configuration coverage, and print masked normalized config.
    Config(ConfigCheckArgs),
    /// Generate OS boot service definition (`systemd` `.service` / `launchd` `.plist`); the init system restarts the supervisor, the supervisor its nodes.
    InstallService(InstallServiceCliArgs),
    /// Check ports, hub conflicts, state dir, disk space, PostgreSQL, and DARs without mutating the host (`S-DX-001`).
    Doctor(Box<DoctorArgs>),
    /// Query or stream participant active contracts (`ls`, `watch`) (`S-DX-005`).
    Contracts(ContractsCliArgs),
    /// List, replay, or oracle-diff participant transactions (`ls`, `replay`, `diff`) (`S-DX-005`).
    Tx(TxCliArgs),
    /// Watch and hot-upload validated DAR archives to all participants (`watch`) (`S-DX-006`).
    Dar(DaemonDarCliArgs),
    /// Quiesce cluster, capture consistent Files/PG snapshot bundle (`S-DX-004`).
    Snapshot(DaemonSnapshotArgs),
    /// Verify integrity/version and restore snapshot bundle (`S-DX-004`).
    Restore(DaemonRestoreArgs),
    /// Issue a loopback-only development HS256 JWT credential for a participant (`S-DX-007`).
    Creds(DaemonCredsArgs),
    /// Execute or list declarative enterprise verification & load scenarios (`list`, `run`).
    #[command(visible_alias = "lab")]
    Scenario(super::scenario::ScenarioCliArgs),
    /// Convenience alias for `canton-rs console attach` against running supervisor.
    #[command(visible_alias = "console")]
    Attach(crate::commands::console::AttachArgs),
    /// Convenience alias for `canton-rs console exec '<expr>'` against running supervisor.
    Exec(crate::commands::console::ExecArgs),
}

/// Flags for `canton-rs daemon up`.
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
    /// Declarative YAML stack manifest (`canton-daemon.yaml`).
    #[arg(short = 'f', long = "file", conflicts_with = "config")]
    pub file: Option<PathBuf>,
    /// Legacy/Mode-B HOCON configuration file (`canton.conf`).
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    /// Bootstrap script (`bootstrap.sc`) paired with `-c`.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,
    /// Run supervisor in background via macOS-safe Self-Reexec detachment.
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,
    /// Registered instance name (`<root>/instances/<name>`) (`S-DX-003`).
    #[arg(long)]
    pub name: Option<String>,
    /// Directory storing PIDs, `daemon.sock`, rotated logs, and file-mode node state.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Override database host:port from `canton.conf`.
    #[arg(long, hide = true)]
    pub official_pg_addr: Option<String>,
    /// JWT RSA/EC certificate override for `-c`.
    #[arg(long)]
    pub conf_auth_cert: Option<PathBuf>,
    /// Default DAR path when not specified in official DB or YAML.
    #[arg(long)]
    pub dar: Option<PathBuf>,
    /// Keep node state in files under `--state-dir` instead of PostgreSQL.
    #[arg(long)]
    pub state_in_files: bool,
    /// Shift all configured ports by `offset` (`GUIDE-run-beside-hub.ko.md`).
    #[arg(long)]
    pub port_offset: Option<u16>,
    /// Adopt participant/mediator keys from official database (`common_crypto_private_keys`).
    #[arg(long, hide = true)]
    pub same_identity: bool,
    /// Write admin changes back to official DB tables (`--official-write`).
    #[arg(long, hide = true)]
    pub official_write: bool,
    /// Refuse startup if `canton.conf` contains unapplied keys.
    #[arg(long)]
    pub strict_config: bool,
    /// Canton log encoder (`text`, `plain`, `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub log_encoder: LogEncoder,
    /// Minimum supervisor log filter level (`debug`, `info`, `warn`, `error`, `off`).
    #[arg(long)]
    pub log_level: Option<String>,
    /// Crate-internal diagnostic mode (`normal`, `all`, `off`).
    #[arg(long)]
    pub log_diagnostics: Option<String>,
    /// Override idle `Subscribe`/`GetTime` poll log suppression (`true` or `false`).
    #[arg(long)]
    pub suppress_idle_polls: Option<bool>,
    /// Disable automatic crash restarts (`systemd` / CI use).
    #[arg(long)]
    pub no_restart: bool,
    /// Prometheus cluster exporter port (`0` disables; defaults to manifest or `9464`).
    #[arg(long)]
    pub metrics_port: Option<u16>,
    /// Prometheus cluster exporter bind host.
    #[arg(long, default_value = "127.0.0.1")]
    pub metrics_bind: String,
    /// Write Prometheus `file_sd_configs` target JSON files for instance discovery (`S-DX-010`).
    #[arg(long)]
    pub observability: bool,
    /// Enable loopback-only development HS256 JWT authentication using `dev-jwt.key` (`S-DX-007`).
    #[arg(long)]
    pub dev_auth: bool,
    /// Override listener bind host across supervised services (`127.0.0.1`, `::1`, or `0.0.0.0`; `S-DX-007`).
    #[arg(long, visible_alias = "host", default_value = "127.0.0.1")]
    pub bind: String,
    /// Rotated log max bytes per file before newline rollover.
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_BYTES)]
    pub log_max_bytes: u64,
    /// Number of rotated log generations to keep.
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_FILES)]
    pub log_max_files: usize,
    /// Enable Zero-Payload X-Ray (`--xray` and `/_xray`) on spawned participants.
    #[arg(long)]
    pub xray: bool,
    /// Zero-Payload X-Ray emission cap per second.
    #[arg(long, default_value_t = DEFAULT_TRACE_RATE_LIMIT)]
    pub trace_rate_limit: u32,
    /// Enable read-only JVM Root Hash / ACS / RSS comparison (`--shadow-verify`).
    #[arg(long)]
    pub shadow_verify: bool,
    /// Optional official JVM JSON API URL (`http://127.0.0.1:7575`) for `--shadow-verify`.
    #[arg(long)]
    pub shadow_jvm_url: Option<String>,
    /// Start only services matching these profile tag(s) (comma-separated, plus transitive `depends_on`).
    #[arg(long, value_delimiter = ',')]
    pub profile: Vec<String>,
    /// Start only services belonging to these group/cell name(s) (comma-separated, plus transitive `depends_on`).
    #[arg(long, visible_alias = "cell", value_delimiter = ',')]
    pub group: Vec<String>,
    /// Environment variable supplying a bearer token for participant probes and Ping (`-c`).
    #[arg(long)]
    pub token_env: Option<String>,
    /// File supplying a bearer token for participant probes and Ping (`-c`).
    #[arg(long, conflicts_with = "token_env")]
    pub token_file: Option<PathBuf>,
    /// Optional PostgreSQL connection URL verified during preflight doctor checks (`--pg-url`).
    #[arg(long)]
    pub pg_url: Option<String>,
    /// Internal flag used by Self-Reexec background worker.
    #[arg(long = "daemon-supervisor-worker", hide = true)]
    pub worker: bool,
}

/// Output format for `canton-rs daemon doctor`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoctorFormatArg {
    Text,
    Json,
}

/// Flags for `canton-rs daemon doctor` (mirrors `daemon up` inputs + `--format`).
#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Declarative YAML stack manifest (`canton-daemon.yaml`).
    #[arg(short = 'f', long = "file", conflicts_with = "config")]
    pub file: Option<PathBuf>,
    /// Legacy/Mode-B HOCON configuration file (`canton.conf`).
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    /// Bootstrap script (`bootstrap.sc`) paired with `-c`.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,
    /// Registered instance name (`<root>/instances/<name>`) (`S-DX-003`).
    #[arg(long)]
    pub name: Option<String>,
    /// Directory storing PIDs, `daemon.sock`, rotated logs, and file-mode node state.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Default DAR path when not specified in official DB or YAML.
    #[arg(long)]
    pub dar: Option<PathBuf>,
    /// Keep node state in files under `--state-dir` instead of PostgreSQL.
    #[arg(long)]
    pub state_in_files: bool,
    /// Shift all configured ports by `offset` (`D1` checked without wrapping).
    #[arg(long, default_value_t = 0)]
    pub port_offset: u16,
    /// Prometheus cluster exporter port (`0` disables; defaults to manifest or `9464`).
    #[arg(long)]
    pub metrics_port: Option<u16>,
    /// Optional PostgreSQL connection URL verified by D8 (`--pg-url`).
    #[arg(long)]
    pub pg_url: Option<String>,
    /// Inspect only services matching these profile tag(s) (comma-separated, plus transitive `depends_on`).
    #[arg(long, value_delimiter = ',')]
    pub profile: Vec<String>,
    /// Inspect only services belonging to these group/cell name(s) (comma-separated, plus transitive `depends_on`).
    #[arg(long, visible_alias = "cell", value_delimiter = ',')]
    pub group: Vec<String>,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: DoctorFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct DownArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_TIMEOUT_SECS)]
    pub timeout_secs: u64,
    /// Remove local state files, sockets, and logs under `--state-dir` (never touches PostgreSQL).
    #[arg(long)]
    pub clean_files: bool,
    /// Print detailed per-service PID/signal/timing/cleanup diagnostics while stopping.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

#[derive(Args, Debug, Clone)]
pub struct PsArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Include manually `Stopped` and `Failed` permanent slots.
    #[arg(short = 'a', long = "all")]
    pub all: bool,
    /// Scan host process table for standalone unmanaged `canton-rs` processes (pure OS APIs).
    #[arg(long)]
    pub scan_host: bool,
    /// Output machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Output Markdown footprint summary table (`02` §5.1).
    #[arg(long)]
    pub report: bool,
}

/// Output format for `canton-rs daemon status`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusFormatArg {
    Text,
    Json,
}

#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct EnvArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct RemoveArgs {
    /// Registered instance name to delete (`<root>/instances/<name>`).
    #[arg(long)]
    pub name: String,
    /// Print filesystem paths and PostgreSQL targets without deleting anything.
    #[arg(long)]
    pub dry_run: bool,
    /// Stop and remove a running instance without an interactive TTY confirmation prompt.
    #[arg(long)]
    pub force: bool,
    /// PostgreSQL URL override for cleaning `<name>-*` schemas/rows.
    #[arg(long)]
    pub pg_url: Option<String>,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct SlotTargetsArgs {
    #[arg(required = true)]
    pub targets: Vec<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct StartOrUpArgs {
    /// Service names or slot IDs to resume; omit when pairing with `-f`/`-c`/`-d` to start stack.
    pub targets: Vec<String>,
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct RestartArgs {
    pub target: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct LogsArgs {
    pub node: Option<String>,
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,
    #[arg(long, default_value_t = 100)]
    pub tail: usize,
    #[arg(long, default_value = "INFO")]
    pub level: String,
    #[arg(long)]
    pub grep: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct StatsArgs {
    #[arg(long)]
    pub no_stream: bool,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct StateDirArg {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Service name, slot ID, or PID (omit when querying `--trace`).
    pub node: Option<String>,
    /// Query Zero-Payload 4-Hop Protocol X-Ray trace by Root Hash (or `latest`).
    #[arg(long)]
    pub trace: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum TemplateArg {
    Default,
    Localnet,
    EnterpriseDvp,
    BftCluster,
    MultiDomain,
    OrgProduction,
}

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    #[arg(long, value_enum, default_value = "default")]
    pub template: TemplateArg,
    #[arg(long)]
    pub from_canton_conf: Option<PathBuf>,
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,
    #[arg(short = 'o', long = "output", default_value = "canton-daemon.yaml")]
    pub output: PathBuf,
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigCheckArgs {
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub port_offset: u16,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ServiceFormatArg {
    Auto,
    Systemd,
    Launchd,
}

#[derive(Args, Debug, Clone)]
pub struct InstallServiceCliArgs {
    #[arg(long, default_value = "daemon")]
    pub name: String,
    #[arg(long)]
    pub system: bool,
    #[arg(long)]
    pub user: bool,
    #[arg(long, value_enum, default_value = "auto")]
    pub format: ServiceFormatArg,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub apply: bool,
}

/// CLI entrypoint for `canton-rs daemon contracts <ls|watch>` (`S-DX-005`).
#[derive(Args, Debug, Clone)]
pub struct ContractsCliArgs {
    #[command(subcommand)]
    pub action: ContractsAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ContractsAction {
    /// List active contracts visible to `--party` at `--at` (defaults to current ledger end).
    Ls(ContractsLsArgs),
    /// Stream active contract creates (`+`) and archives (`-`) for `--party` over WebSocket.
    Watch(ContractsWatchArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ContractsLsArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub participant: Option<String>,
    #[arg(long)]
    pub party: String,
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub at: Option<u64>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct ContractsWatchArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub participant: Option<String>,
    #[arg(long)]
    pub party: String,
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub from: Option<u64>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

/// CLI entrypoint for `canton-rs daemon tx <ls|replay|diff>` (`S-DX-005`).
#[derive(Args, Debug, Clone)]
pub struct TxCliArgs {
    #[command(subcommand)]
    pub action: TxAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TxAction {
    /// List updates in `(from, to]` visible to `--party`.
    Ls(TxLsArgs),
    /// Replay one update's party-scoped `LEDGER_EFFECTS` event tree (`--id`).
    Replay(TxReplayArgs),
    /// Normalize and semantically diff two `ScenarioCapture` JSON files (`exit 3` on diff).
    Diff(TxDiffArgs),
}

#[derive(Args, Debug, Clone)]
pub struct TxLsArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub participant: Option<String>,
    #[arg(long)]
    pub party: String,
    #[arg(long)]
    pub template: Option<String>,
    #[arg(long)]
    pub from: Option<u64>,
    #[arg(long)]
    pub to: Option<u64>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct TxReplayArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub participant: Option<String>,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    pub party: String,
    #[arg(long = "interface")]
    pub interface: Vec<String>,
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

#[derive(Args, Debug, Clone)]
pub struct TxDiffArgs {
    pub left: PathBuf,
    pub right: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

/// CLI arguments for `canton-rs daemon dar` (`S-DX-006`).
#[derive(Args, Debug, Clone)]
pub struct DaemonDarCliArgs {
    #[command(subcommand)]
    pub action: DaemonDarAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DaemonDarAction {
    /// Debounce file changes, run `check-upgrade`, and upload/vet on every participant (`S-DX-006`).
    Watch(DaemonDarWatchArgs),
}

#[derive(Args, Debug, Clone)]
pub struct DaemonDarWatchArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 500)]
    pub debounce_ms: u64,
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,
    pub path: PathBuf,
}

/// CLI arguments for `canton-rs daemon snapshot` (`S-DX-004`).
#[derive(Args, Debug, Clone)]
pub struct DaemonSnapshotArgs {
    /// Registered instance name (`<root>/instances/<name>`).
    #[arg(long)]
    pub name: Option<String>,
    /// Explicit supervisor state directory.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Output `.tar` snapshot bundle path (mode `0600`).
    #[arg(long)]
    pub out: PathBuf,
    /// Maximum seconds to wait for in-flight requests to drain after `/_quiesce/pause`.
    #[arg(long, default_value_t = super::snapshot::DEFAULT_QUIESCE_TIMEOUT_SECS)]
    pub quiesce_timeout_secs: u64,
    /// Graceful shutdown wait timeout (`SIGTERM` -> `SIGKILL`).
    #[arg(long, default_value_t = DEFAULT_SHUTDOWN_TIMEOUT_SECS)]
    pub shutdown_timeout_secs: u64,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

/// CLI arguments for `canton-rs daemon restore` (`S-DX-004`).
#[derive(Args, Debug, Clone)]
pub struct DaemonRestoreArgs {
    /// Target registered instance name (`<root>/instances/<name>`).
    #[arg(long)]
    pub name: String,
    /// Explicit target supervisor state directory.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Source `.tar` snapshot bundle path.
    #[arg(long)]
    pub from: PathBuf,
    /// Stop and overwrite a running target instance.
    #[arg(long)]
    pub force: bool,
    /// Explicit port offset override when restoring as a new instance.
    #[arg(long)]
    pub port_offset: Option<u16>,
    /// PostgreSQL URL override for Postgres-mode restore.
    #[arg(long)]
    pub pg_url: Option<String>,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

/// CLI arguments for `canton-rs daemon creds` (`S-DX-007`).
#[derive(Args, Debug, Clone)]
pub struct DaemonCredsArgs {
    /// Registered instance name (`<root>/instances/<name>`).
    #[arg(long)]
    pub name: Option<String>,
    /// Explicit supervisor state directory.
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Target participant service name (defaults to first participant in the stack).
    #[arg(long)]
    pub participant: Option<String>,
    /// Subject (`sub`) user ID recorded in the issued JWT (`participant_admin` by default).
    #[arg(long, default_value = "participant_admin")]
    pub user: String,
    /// Optional party identifier to include and authorize (`CanActAs` + `CanReadAs`) on the live participant.
    #[arg(long)]
    pub party: Option<String>,
    /// Token lifetime duration (e.g. `1s`, `15m`, `1h`; max `24h`).
    #[arg(long, default_value = "1h")]
    pub ttl: String,
    /// Output format (`text` or `json`).
    #[arg(long, value_enum, default_value = "text")]
    pub format: StatusFormatArg,
}

/// Dispatches `canton-rs daemon <action>`.
pub fn execute_action(action: DaemonAction) -> Result<(), String> {
    match action {
        DaemonAction::Up(args) => cmd_up(*args),
        DaemonAction::Down(args) => cmd_down(args),
        DaemonAction::Ps(args) => cmd_ps(args),
        DaemonAction::List(args) => cmd_list(args),
        DaemonAction::Remove(args) => cmd_remove(args),
        DaemonAction::Status(args) => cmd_status(args),
        DaemonAction::Env(args) => cmd_env(args),
        DaemonAction::Stop(args) => cmd_stop(args),
        DaemonAction::Start(args) => cmd_start(args),
        DaemonAction::Restart(args) => cmd_restart(args),
        DaemonAction::Logs(args) => cmd_logs(args),
        DaemonAction::Stats(args) => cmd_stats(args),
        DaemonAction::Top(args) => {
            let state_dir = super::registry::resolve_target_state_dir(
                args.name.as_deref(),
                args.state_dir.as_deref(),
            )?;
            run_top(&state_dir)
        }
        DaemonAction::Inspect(args) => cmd_inspect(args),
        DaemonAction::Init(args) => cmd_init(args),
        DaemonAction::Config(args) => cmd_config(args),
        DaemonAction::InstallService(args) => cmd_install_service(args),
        DaemonAction::Doctor(args) => cmd_doctor(*args),
        DaemonAction::Contracts(args) => super::query::cmd_contracts(args),
        DaemonAction::Tx(args) => super::query::cmd_tx(args),
        DaemonAction::Dar(args) => super::dar_watch::cmd_daemon_dar(args),
        DaemonAction::Snapshot(args) => super::snapshot::cmd_daemon_snapshot(args),
        DaemonAction::Restore(args) => super::snapshot::cmd_daemon_restore(args),
        DaemonAction::Creds(args) => super::creds::cmd_daemon_creds(args),
        DaemonAction::Scenario(args) => super::scenario::cmd_scenario(args),
        DaemonAction::Attach(args) => crate::commands::console::execute_attach(args),
        DaemonAction::Exec(args) => crate::commands::console::execute_exec(args),
    }
}
