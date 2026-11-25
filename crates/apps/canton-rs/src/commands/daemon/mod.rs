//! `canton-rs daemon -c canton.conf [--bootstrap bootstrap.sc]`: the nodes of an official `canton.conf` as Rust processes (U-47), the way
//! `canton daemon -c canton.conf --bootstrap bootstrap.sc` starts them in one JVM.
//!
//! [CANTON-NOTE: SEMANTICS] What the configuration names is started, each node a process of this executable: every sequencer (`sequencer run` on its
//! `public-api` port), every mediator (`mediator run`, its `admin-api` port as the status port, onboarded to the synchronizer's sequencer as
//! `localnet up` does), and every participant (a `json-api` process with its protocol node behind it, on its `http-ledger-api` port, with the
//! official database of its storage block read for its parties, users, DARs and contracts). The bootstrap script is read, not run: the
//! statements of the script of the hub (`list_connected`, `bootstrap.synchronizer`, `connect_local`) say the synchronizer's name and which node
//! connects to which sequencer; any other call is an error, never skipped.
//!
//! [CANTON-NOTE: SEMANTICS] The state of each sequencer, mediator and participant is in the database of its own `storage` block (`hub_sequencer`,
//! `hub_mediator`, `hub_participant`), in the one table `canton_rs_state` beside the official tables, which the Rust nodes leave alone (the
//! participant's are only read). A restart finds the keys, members, events and contracts there; `--state-in-files` keeps them in `--state-dir`
//! instead. The participant process serves the JSON API (`http-ledger-api` port) and the gRPC Ledger API (`ledger-api` port) from one service.
//!
//! [CANTON-NOTE: LIMITATION] The Rust nodes do not take over an official sequencer's or mediator's tables, so the synchronizer is a new one with the
//! name the script gives.

pub(crate) mod bootstrap;
mod official;
mod spec;
#[cfg(test)]
mod tests;

pub(crate) use official::run_admin_ping;
pub(crate) use spec::build_daemon_spec;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use canton_participant::hocon::Hocon;
use clap::Args;

use ledger_json_api::canton_log::LogEncoder;

use super::supervisor::cli::{execute_action, DaemonAction};
use super::supervisor::engine::run_supervisor;
use super::supervisor::{
    StorageSpec, DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES, DEFAULT_TRACE_RATE_LIMIT,
};

#[derive(Args, Debug, Clone)]
pub struct DaemonArgs {
    /// Supervisor subcommand (`up`, `down`, `ps`, `stop`, `start`, `restart`, `logs`, `stats`, `top`, `inspect`, `init`, `config`, `install-service`, `attach`, `exec`).
    #[command(subcommand)]
    pub action: Option<DaemonAction>,
    /// The Canton configuration file to start the nodes of (HOCON).
    #[arg(short = 'c', long = "config", env = "CANTON_RS_CANTON_CONF")]
    pub config: Option<PathBuf>,
    /// The bootstrap script (`--bootstrap`): read for the synchronizer's name and the connections, see the module documentation.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,
    /// Where the nodes keep their state (default: `canton-rs-state` in the current directory).
    #[arg(long, default_value = "canton-rs-state")]
    pub state_dir: PathBuf,
    /// Reach the configured participant database at this `host:port` instead of the configured one (see `json-api --official-pg-addr`).
    #[arg(long, hide = true)]
    pub official_pg_addr: Option<String>,
    /// The certificate file of a `jwt-rs-256-crt` auth service on this host (see `json-api --conf-auth-cert`).
    #[arg(long)]
    pub conf_auth_cert: Option<PathBuf>,
    /// The DAR the participants run when the configuration names no database to take them from.
    #[arg(long)]
    pub dar: Option<PathBuf>,
    /// Keep the nodes' state in files under `--state-dir` even when the configuration gives them a PostgreSQL database (by default each sequencer,
    /// mediator and participant keeps its state in the database of its own `storage` block, in the table `canton_rs_state`).
    #[arg(long)]
    pub state_in_files: bool,
    /// Added to every port of the configuration (the sequencer's public API, the mediator's status port, the participant's JSON API and gRPC Ledger API),
    /// so the daemon runs beside the node the configuration was written for (a backend routes to either; the data stays the same).
    #[arg(long, default_value_t = 0)]
    pub port_offset: u16,
    /// Start each participant with the identity (the namespace, signing, sequencer-authentication and encryption keys) of the participant of the same name in its
    /// database, so it hosts the parties the database's participant hosts (`Issuer::<namespace>`) and signs for them with the same namespace key. Reads private keys
    /// (never printed) from `common_crypto_private_keys`; refused when they are wrapped. An internal option.
    #[arg(long, hide = true)]
    pub same_identity: bool,
    /// How the daemon writes its lines: `text` (its own plain lines, the default), or `plain` / `json`, the two encoders of a Canton node's log (the time, thread,
    /// level, logger name with the node's context, and for `json` the same field names).
    #[arg(long, value_enum, default_value = "text")]
    pub log_encoder: LogEncoder,
    /// Refuse to start when the configuration sets a key canton-rs does not apply (the keys the start-up summary lists as `not applied`), instead of
    /// starting without it. By default such keys are only reported, so a configuration written for the JVM node (e.g. a BFT sequencer type) still starts.
    #[arg(long)]
    pub strict_config: bool,
    /// Accepted so a JVM node's command line works as it is (`--no-tty --log-profile container --log-file-appender off`): the daemon writes to the console only.
    #[arg(long, hide = true)]
    pub no_tty: bool,
    #[arg(long, hide = true)]
    pub log_profile: Option<String>,
    #[arg(long, hide = true)]
    pub log_file_appender: Option<String>,
    /// Let the participants write their administration state (users, party records, identity providers, uploaded DARs) to the official tables of their
    /// database as well (see `json-api --official-write`).
    #[arg(long, hide = true)]
    pub official_write: bool,
    /// Disable automatic backoff restart on child failure (`Daemon` fails fast so container orchestrators can restart it).
    #[arg(long)]
    pub no_restart: bool,
    /// Bind supervisor Prometheus HTTP exporter (`GET /metrics`, `GET /healthz`, `GET /readyz`, `GET /snapshot`).
    #[arg(long)]
    pub metrics_port: Option<u16>,
    /// Bind address for supervisor Prometheus exporter (`--metrics-port`).
    #[arg(long, default_value = "127.0.0.1")]
    pub metrics_bind: String,
    /// Enable non-mutating Shadow-Mode Dual Verifier beside a reference JVM Canton node.
    #[arg(long)]
    pub shadow_verify: bool,
    /// Base URL of reference JVM participant JSON API for `--shadow-verify` comparison.
    #[arg(long)]
    pub shadow_jvm_url: Option<String>,
    /// Enable Zero-Payload X-Ray (`--xray` and `/_xray`) on spawned participants.
    #[arg(long)]
    pub xray: bool,
    /// Maximum Zero-Payload X-Ray trace events emitted per second.
    #[arg(long, default_value_t = DEFAULT_TRACE_RATE_LIMIT)]
    pub trace_rate_limit: u32,
    /// Per-node log file size limit before newline-boundary rotation.
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_BYTES)]
    pub log_max_bytes: u64,
    /// Number of rotated log generations to keep per node.
    #[arg(long, default_value_t = DEFAULT_LOG_MAX_FILES)]
    pub log_max_files: usize,
    /// Environment variable supplying a bearer token for participant probes and Ping (mode `-c`).
    #[arg(long)]
    pub token_env: Option<String>,
    /// File supplying a bearer token for participant probes and Ping (mode `-c`).
    #[arg(long, conflicts_with = "token_env")]
    pub token_file: Option<PathBuf>,
    /// Internal hidden flag for macOS-safe Self-Reexec detached background supervisor worker.
    #[arg(long = "daemon-supervisor-worker", hide = true)]
    pub worker: bool,
}

/// Where a node keeps its state.
pub(super) enum Backend {
    /// A directory of the daemon.
    Files(PathBuf),
    /// The PostgreSQL database of the node's `storage` block, as the state `name`.
    Database { url: String, name: String },
}

impl Backend {
    /// The state the node `kind`/`node` of the configuration keeps: its database when the storage block is PostgreSQL (unless `--state-in-files`).
    ///
    /// [CANTON-NOTE: SEMANTICS] The daemon of the official node keeps the three databases of a hub (`hub_sequencer`, `hub_mediator`, `hub_participant`).
    /// The Rust nodes keep their state in the one table `canton_rs_state` of the same databases, beside the official tables, which they leave alone
    /// (the participant's are read, read-only, for its parties, users, DARs and contracts). A restart finds its keys, members and events there.
    pub(super) fn of(
        config_path: &Path,
        args: &DaemonArgs,
        state: &Path,
        kind: &str,
        node: &str,
    ) -> Result<Self, String> {
        if !args.state_in_files {
            if let Some(target) = ledger_json_api::canton_conf::node_database(
                config_path,
                kind,
                node,
                args.official_pg_addr.as_deref(),
            )? {
                return Ok(Self::Database {
                    url: ledger_json_api::canton_conf::pg_url(&target),
                    name: node.to_string(),
                });
            }
        }
        let dir = state.join(node);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(Self::Files(dir))
    }

    /// Gives a node's CLI args and env its state: `--state-dir` for file storage, or `CANTON_RS_STATE_PG_URL` + `--state-name` for PostgreSQL.
    pub(super) fn give_args_env(&self, argv: &mut Vec<String>, env: &mut BTreeMap<String, String>) {
        match self {
            Self::Files(dir) => {
                argv.push("--state-dir".into());
                argv.push(dir.display().to_string());
            }
            Self::Database { url, name } => {
                env.insert("CANTON_RS_STATE_PG_URL".into(), url.clone());
                argv.push("--state-name".into());
                argv.push(name.clone());
            }
        }
    }

    pub(super) fn to_storage_spec(&self) -> StorageSpec {
        match self {
            Self::Files(_) => StorageSpec::Files,
            Self::Database { url, name } => StorageSpec::Postgres {
                url: url.clone(),
                name: Some(name.clone()),
            },
        }
    }

    pub(super) fn node_state_dir(&self, root_state: &Path, node: &str) -> PathBuf {
        match self {
            Self::Files(dir) => dir.clone(),
            Self::Database { .. } => root_state.join(node),
        }
    }
}

/// How much of a configuration the daemon applies: `(applied, harmless, not applied)` counts and the paths of the keys not applied.
///
/// [CANTON-NOTE: SEMANTICS] A key of a node (`canton.<kind>.<name>.<key>`) is **applied** when it is one the daemon reads (the storage block, the addresses
/// and ports of the APIs, the Ledger API's auth services); a connection-pool setting (`storage.parameters`) changes nothing a client sees, so it is **ignored
/// without effect**; every other key is **not applied**, said out loud at the start: a configuration that sets something this program does not do is never read
/// as one that is followed. (The reading of the keys themselves refuses what it cannot follow, e.g. an auth service of another type.)
pub fn configuration_coverage(conf: &Hocon) -> (usize, usize, Vec<String>) {
    use ledger_json_api::canton_conf::{
        is_under, APPLIED_NODE_KEYS as APPLIED, HARMLESS_NODE_KEYS as HARMLESS,
    };
    const GLOBAL_APPLIED: [&str; 1] = ["canton.monitoring.metrics"];
    const PARTICIPANT_ONLY: [&str; 4] = [
        "admin-api.auth-services",
        "admin-api.admin-token-config",
        "ledger-api",
        "http-ledger-api",
    ];
    let under = is_under;
    let Some(canton) = conf.get("canton") else {
        return (0, 0, Vec::new());
    };
    let (mut applied, mut harmless, mut not_applied) = (0, 0, Vec::new());
    for path in canton.leaf_paths("canton") {
        if under(&path, &GLOBAL_APPLIED) {
            applied += 1;
            continue;
        }
        let parts: Vec<&str> = path.splitn(4, '.').collect();
        let rest = match parts.as_slice() {
            ["canton", "sequencers" | "mediators" | "participants", _, rest] => Some(*rest),
            _ => None,
        };
        // [CANTON-NOTE: SEMANTICS] `sequencer.type = BFT` alone (no peer network under `sequencer`) is a Canton sequencer ordering by itself: with the one
        // sequencer this daemon starts, a client sees the same order and offsets as from this program's sequencer, so the key changes nothing it sees. A BFT
        // sequencer with `sequencer.config.initial-network` is validated by `bft_network`: supported BFT keys count as applied, whereas TLS, disabled endpoint
        // auth, invalid durations, or unknown keys stay in `not_applied`.
        let lone_bft = parts.as_slice()
            == [
                "canton",
                "sequencers",
                parts.get(2).copied().unwrap_or(""),
                "sequencer.type",
            ]
            && matches!(conf.get(&path), Some(Hocon::Str(t)) if t.eq_ignore_ascii_case("BFT"))
            && canton
                .leaf_paths("canton")
                .iter()
                .filter(|q| q.starts_with(&format!("canton.sequencers.{}.sequencer.", parts[2])))
                .count()
                == 1;
        let is_bft_leaf = match parts.as_slice() {
            ["canton", "sequencers", name, r]
                if *r == "sequencer.type" || r.starts_with("sequencer.") =>
            {
                !lone_bft
                    && super::bft_config::bft_network(conf, name).is_ok()
                    && super::bft_config::bft_applied_leaf(r)
            }
            _ => false,
        };
        // [CANTON-NOTE: LIMITATION] The participant's API keys (Ledger API, HTTP API, Admin API auth) are applied by the JSON API; a
        // sequencer or mediator started here has no auth services or token config, so those keys are not applied for it.
        // Likewise, `daemon` always binds node listeners to `127.0.0.1`, so non-loopback `*.address` settings are reported as not applied.
        let participant_only = matches!(parts.get(1), Some(&"sequencers" | &"mediators"))
            && rest.is_some_and(|r| under(r, &PARTICIPANT_ONLY));
        const ADDRESS_KEYS: [&str; 4] = [
            "public-api.address",
            "admin-api.address",
            "ledger-api.address",
            "http-ledger-api.address",
        ];
        let is_address_leaf = rest.is_some_and(|r| ADDRESS_KEYS.contains(&r));
        match rest {
            _ if lone_bft => harmless += 1,
            _ if is_bft_leaf => applied += 1,
            _ if participant_only => not_applied.push(path),
            _ if is_address_leaf => {
                let text = conf.get(&path).and_then(Hocon::text);
                if matches!(text.as_deref(), Some("127.0.0.1" | "localhost" | "::1")) {
                    applied += 1;
                } else {
                    not_applied.push(path);
                }
            }
            Some(r) if under(r, &APPLIED) => applied += 1,
            Some(r) if under(r, &HARMLESS) => harmless += 1,
            _ => not_applied.push(path),
        }
    }
    (applied, harmless, not_applied)
}

/// Refuses a `--port-offset` that would push any configured port past 65535 (it would wrap or be dropped).
pub(super) fn check_port_offset(conf: &Hocon, offset: u16) -> Result<(), String> {
    let Some(canton) = conf.get("canton") else {
        return Ok(());
    };
    for path in canton.leaf_paths("canton") {
        if !path.ends_with(".port") {
            continue;
        }
        if let Some(port) = conf.get(&path).and_then(Hocon::as_u16) {
            if super::supervisor::doctor::shift_port(port, offset).is_none() {
                return Err(format!(
                    "{path} = {port} + port offset {offset} overflows u16"
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn log_encoder_str(enc: LogEncoder) -> &'static str {
    match enc {
        LogEncoder::Text => "text",
        LogEncoder::Plain => "plain",
        LogEncoder::Json => "json",
    }
}

pub(super) fn node_unapplied_keys(not_applied: &[String], kind: &str, node: &str) -> Vec<String> {
    let prefix = format!("canton.{kind}.{node}.");
    not_applied
        .iter()
        .filter(|k| {
            k.starts_with(&prefix)
                || !k.starts_with("canton.sequencers.")
                    && !k.starts_with("canton.mediators.")
                    && !k.starts_with("canton.participants.")
        })
        .cloned()
        .collect()
}

pub(super) fn participant_auth_mode(
    conf: &Hocon,
    participant: &str,
    conf_auth_cert: Option<&Path>,
) -> String {
    if let Some(cert) = conf_auth_cert {
        return format!("jwt-rs-256-crt ({})", cert.display());
    }
    match conf.get(&format!(
        "canton.participants.{participant}.ledger-api.auth-services"
    )) {
        Some(Hocon::Array(items)) if !items.is_empty() => {
            let kinds: Vec<String> = items
                .iter()
                .filter_map(|i| i.get("type").and_then(Hocon::text))
                .collect();
            if kinds.is_empty() {
                "configured".to_string()
            } else {
                kinds.join(", ")
            }
        }
        _ => "open".to_string(),
    }
}

/// Entrypoint for `canton-rs daemon ...`: dispatches nested supervisor subcommands or legacy `-c canton.conf`.
pub fn run(args: &DaemonArgs) -> Result<(), String> {
    if let Some(action) = &args.action {
        return execute_action(action.clone());
    }
    let mut spec = build_daemon_spec(args, None)?;
    spec.foreground_legacy_banner = !args.worker;
    run_supervisor(spec, args.worker)
}
