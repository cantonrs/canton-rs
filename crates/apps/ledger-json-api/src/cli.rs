use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::http::run_server;
use crate::service::ExecutionService;

/// How long a command waits for its fate before the caller is answered `REQUEST_TIME_OUT`: the command service's default tracking timeout
/// (`CommandServiceConfig.DefaultDefaultTrackingTimeout`, 5 minutes). The command stays in flight after it.
#[cfg(feature = "protocol")]
const COMMAND_TRACKING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The options of the JSON API server (the same for `ledger-json-api` and `canton-rs json-api`).
#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// Bind address
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port
    #[arg(short, long, default_value_t = 7575)]
    pub port: u16,

    /// Require JWT bearer tokens signed with this HMAC-SHA256 secret (the `unsafe-jwt-hmac-256` auth service)
    #[arg(long, group = "jwt_auth")]
    pub jwt_hmac_secret: Option<String>,

    /// Read the HMAC-SHA256 secret from a private file (`0600`) so the secret never appears in `argv` or logs (`S-DX-007`)
    #[arg(long, group = "jwt_auth", conflicts_with_all = ["jwt_hmac_secret", "auth_cert"])]
    pub jwt_hmac_secret_file: Option<std::path::PathBuf>,

    /// Start on the database of an official Canton 3.7.2 participant (a libpq or JDBC PostgreSQL URL; prefer `CANTON_RS_OFFICIAL_PG_URL`, the URL holds
    /// a password): the parties of its topology and their metadata are read, read-only, and are this API's parties, so `GET /v2/parties` lists what the
    /// official participant lists (U-47). Nothing is written to that database.
    #[cfg(feature = "protocol")]
    #[arg(
        long,
        env = "CANTON_RS_OFFICIAL_PG_URL",
        hide_env_values = true,
        hide = true
    )]
    pub official_pg_url: Option<String>,

    /// A Canton configuration file (`canton.conf`, HOCON) of the Canton (JVM) participant this API runs beside: its storage block names the
    /// database the API reads its parties, contracts and history from, and its `http-ledger-api` port is the port with
    /// `--conf-port`. Environment substitutions (`${NAME}`) are read from the environment; what the reader does not know (`include`) is an error.
    #[cfg(feature = "protocol")]
    #[arg(long, env = "CANTON_RS_CANTON_CONF")]
    pub canton_conf: Option<std::path::PathBuf>,

    /// With `--canton-conf`: the participant of the file (default: the only one).
    #[cfg(feature = "protocol")]
    #[arg(long, requires = "canton_conf")]
    pub conf_participant: Option<String>,

    /// With `--canton-conf`: reach the configured database at this `host:port` instead of the configured one (the configuration names the database as
    /// the node's container sees it, `hub-postgres:5432`; from the host it is published elsewhere).
    #[cfg(feature = "protocol")]
    #[arg(long, requires = "canton_conf", hide = true)]
    pub official_pg_addr: Option<String>,

    /// With `--canton-conf`: the certificate file of its `jwt-rs-256-crt` auth service on this host (the configuration names it as the node's container
    /// sees it, `/hub/auth/jwt.crt`). Without the option the configured path is tried; a configuration with that service and no readable certificate
    /// is an error, never an open server.
    #[cfg(feature = "protocol")]
    #[arg(long, requires = "canton_conf")]
    pub conf_auth_cert: Option<std::path::PathBuf>,

    /// With `--canton-conf`: listen on the configured `http-ledger-api` port instead of `--port`.
    #[cfg(feature = "protocol")]
    #[arg(long, requires = "canton_conf")]
    pub conf_port: bool,

    /// With `--conf-port` and `--with-grpc`: added to the configured ports (the Ledger API's and the JSON API's), so a Rust node can run beside the node of
    /// the configuration it was taken from.
    #[arg(long, default_value_t = 0)]
    #[cfg_attr(feature = "protocol", arg(requires = "canton_conf"))]
    pub conf_port_offset: u16,

    /// Require RS256 bearer tokens checked against this certificate (PEM), the `jwt-rs-256-crt` auth service without a Canton configuration
    /// (what the supervisor passes for a manifest's `auth_cert`). An unreadable certificate is an error, never an open server.
    #[arg(long, group = "jwt_auth", conflicts_with = "jwt_hmac_secret")]
    pub auth_cert: Option<std::path::PathBuf>,

    /// With `--jwt-hmac-secret`, `--jwt-hmac-secret-file`, or `--auth-cert`: the audience a token has to name in `aud` (the official LocalNet's `target-audience`, audience-based tokens such as
    /// the Wallet SDK's `self_signed` ones); without it tokens are scope-based (`daml_ledger_api`).
    #[arg(long, requires = "jwt_auth")]
    pub jwt_audience: Option<String>,

    /// Bind `aud` requirement dynamically to this participant's finalized `participantId` (`S-DX-007` dev auth).
    #[arg(long, requires = "jwt_auth", conflicts_with = "jwt_audience")]
    pub jwt_audience_self: bool,

    /// Internal path where the participant writes its finalized `participantId` after synchronizer/store setup.
    #[arg(long, hide = true)]
    pub participant_id_file: Option<std::path::PathBuf>,

    /// With `--jwt-hmac-secret` or `--auth-cert`: the longest remaining lifetime a token may have, in seconds (Canton's `max-token-life`; the sandbox this was measured
    /// on allows 300, the official LocalNet's `unsafe` auth has no limit and the Wallet SDK's self-signed tokens last an hour).
    #[arg(long, requires = "jwt_auth")]
    pub jwt_max_lifetime_seconds: Option<i64>,

    /// Enable `/v2/traffic/*` enforcement routes (disabled by default in sandbox mode to match Canton 3.7.2).
    #[arg(long)]
    pub traffic_enforcement: bool,

    /// Maximum elements returned by HTTP blocking list endpoints (`413 JSON_API_MAXIMUM_LIST_ELEMENTS_NUMBER_REACHED` when exceeded; overrides `http-list-max-elements-limit` from `--canton-conf`).
    #[arg(long)]
    pub http_list_max_elements_limit: Option<usize>,

    /// Optional path to DAR file to load at startup
    #[arg(long)]
    pub dar: Option<PathBuf>,

    /// Keep the ledger (parties, users, packages, commands) in this request-log file and rebuild it from there on start
    #[arg(long)]
    pub store: Option<PathBuf>,

    /// Keep the ledger in PostgreSQL instead (a libpq-style URL; prefer the environment variable, a command line is visible to
    /// other users of the machine)
    #[arg(long, env = "CANTON_RS_PG_URL", conflicts_with = "store")]
    pub pg_url: Option<String>,

    /// The maximum deduplication duration in seconds: an offset younger than this cannot be pruned (Canton's default: 168 hours)
    #[arg(long)]
    pub max_dedup_seconds: Option<u64>,

    /// The name of the ledger inside the database (one writer per name)
    #[arg(long, default_value = "default")]
    pub ledger: String,

    /// Save a checkpoint snapshot every N logged requests (`0` disables auto-checkpointing; `CANTON_RS_SNAPSHOT_EVERY`)
    #[arg(long, env = "CANTON_RS_SNAPSHOT_EVERY", default_value_t = 0)]
    pub snapshot_every: u64,

    /// Put a Rust participant behind the API: register with the synchronizer whose sequencer is at this URL and let it judge every
    /// transaction (views, sequencer, mediator) before it is applied. Needs `--dar` and the `protocol` feature.
    #[cfg(feature = "protocol")]
    #[arg(long)]
    pub sequencer: Option<String>,

    /// More synchronizers for the same participant, each `<alias>=<sequencer url>` (repeatable): one identity, a connection per
    /// synchronizer, and `submit-and-wait-for-reassignment` between them (S-NET-040). The synchronizer of `--sequencer` is `--sequencer-alias`
    /// and takes the transactions. Not with `--state-pg-url`.
    #[cfg(feature = "protocol")]
    #[arg(long = "also-sequencer", value_name = "ALIAS=URL")]
    pub also_sequencer: Vec<String>,

    /// The alias of the synchronizer of `--sequencer` when `--also-sequencer` is used
    #[cfg(feature = "protocol")]
    #[arg(long, default_value = "sync0")]
    pub sequencer_alias: String,

    /// The name of the participant started by `--sequencer`
    #[cfg(feature = "protocol")]
    #[arg(long, default_value = "participant")]
    pub participant_name: String,

    /// The package name of the DAR (what a contract's hash is computed with) when `--sequencer` is used;
    /// defaults to the loaded DAR's package name (`sample-contract` if unavailable).
    #[cfg(feature = "protocol")]
    #[arg(long)]
    pub package_name: Option<String>,

    /// Keep the participant started by `--sequencer` in this directory: its identity (keys), the contracts it can exercise, where it stopped
    /// reading and the topology it followed. Started again with the same directory it is the same participant and continues.
    #[cfg(feature = "protocol")]
    #[arg(long, conflicts_with = "state_pg_url")]
    pub state_dir: Option<PathBuf>,

    /// Keep the participant in PostgreSQL instead of a directory (a libpq-style URL; prefer the environment variable, a command line is visible
    /// to other users of the machine). One participant of a name runs at a time.
    #[cfg(feature = "protocol")]
    #[arg(long, env = "CANTON_RS_STATE_PG_URL")]
    pub state_pg_url: Option<String>,

    /// The name of the participant's state inside the database (default: the participant's name).
    #[cfg(feature = "protocol")]
    #[arg(long)]
    pub state_name: Option<String>,

    /// Writes every transaction this API commits to this file as a scan update item, one JSON object per line
    /// (`canton-rs scan serve --history <file>` answers from it).
    #[arg(long)]
    pub scan_history: Option<PathBuf>,

    /// The synchronizer id the scan history states for its updates.
    #[arg(long, default_value = "canton-rs::synchronizer")]
    pub scan_synchronizer_id: String,

    /// Stream privacy-scoped in-process `CantonExEx` post-commit notifications to this JSONL file without external gRPC polling.
    #[arg(long)]
    pub exex_jsonl: Option<PathBuf>,

    /// Restrict `--exex-jsonl` to events visible to these stakeholder/witness parties (repeatable; omit for participant-wide visibility).
    #[arg(long = "exex-party")]
    pub exex_parties: Vec<String>,

    /// Redact all contract create arguments in `--exex-jsonl` (`ZeroPayloadMetadata` or `PartiesZeroPayload` when paired with `--exex-party`).
    #[arg(long)]
    pub exex_zero_payload: bool,

    /// With `--exex-jsonl`: replay stored/adopted ledger updates from this inclusive offset before live streaming.
    #[arg(long, requires = "exex_jsonl")]
    pub exex_from_offset: Option<u64>,

    /// Enable Zero-Payload Protocol X-Ray trace capture (`GET /_xray`; off by default for zero hot-path overhead).
    #[arg(long)]
    pub xray: bool,

    /// Write what the Ledger API's administration changes (users with their rights and annotations, party records, identity providers, uploaded DARs) to the
    /// official tables of the database `--official-pg-url` / `--canton-conf` names, so the official participant or another Rust one started on it finds
    /// them. Without this the database is only read (U-47).
    #[arg(long, hide = true)]
    pub official_write: bool,

    /// With `--official-write`: also write the topology transaction of every party this participant starts to host into the topology store of these databases (a
    /// libpq URL each; the daemon gives those of the synchronizer's sequencer and mediator, whose topology the official participant's requests are judged by).
    /// `CANTON_RS_OFFICIAL_TOPOLOGY_URLS` (one URL per line) keeps the passwords out of the command line.
    #[arg(
        long,
        hide = true,
        env = "CANTON_RS_OFFICIAL_TOPOLOGY_URLS",
        hide_env_values = true,
        value_delimiter = '\n'
    )]
    pub official_topology_url: Vec<String>,

    /// How the server writes its request log: `text` (none, the default), or `plain` / `json`, the two encoders of a Canton node's log (see `canton_log`).
    #[arg(long, value_enum, default_value = "text")]
    pub log_encoder: crate::canton_log::LogEncoder,

    /// With a participant that has the identity of the database's participant (`daemon --same-identity`): host on the synchronizer joined every party of the
    /// database that its participant hosts (the parties of its namespace, `isLocal`), so their contracts can be exercised there. An internal option.
    #[arg(long, hide = true)]
    pub host_adopted_parties: bool,

    /// Also serve the gRPC Ledger API of this same service (the same ledger, parties, users and committer) on this port. With `--canton-conf` and
    /// `--conf-port` the configured `ledger-api` port is the default.
    #[arg(long)]
    pub grpc_port: Option<u16>,

    /// Also serve the participant's Admin API on this port (see `--with-admin-api`).
    #[arg(long)]
    pub admin_port: Option<u16>,

    /// Serve the participant's Admin API on the `admin-api` port of `--canton-conf`. [CANTON-NOTE: LIMITATION] The services of
    /// `ledger-grpc-api/src/admin_api` are answered (packages, ping, connectivity, status, inspection and repair, pruning, part of the
    /// topology manager); the others answer `UNIMPLEMENTED`. The port authenticates as the configuration's `admin-api.auth-services` and
    /// `admin-token-config` say (without auth services it takes every call, as Canton does); its TLS is not read. On the Ledger API port
    /// the same Admin services need an administrator's token when an auth service is on.
    #[arg(long)]
    #[cfg_attr(feature = "protocol", arg(requires = "canton_conf"))]
    pub with_admin_api: bool,

    /// Serve the gRPC Ledger API on the `ledger-api` port of `--canton-conf` (see `--grpc-port`).
    #[arg(long)]
    #[cfg_attr(feature = "protocol", arg(requires = "canton_conf"))]
    pub with_grpc: bool,

    /// What serves the gRPC Ledger API for the service when `--grpc-port` or `--with-grpc` is given: set by the program that links the gRPC server
    /// (`canton-rs`), not an option.
    #[arg(skip)]
    pub grpc_server: Option<GrpcServer>,

    /// What serves the Admin API (`--admin-port` / `--with-admin-api`), with the authentication of the configuration's `admin-api`.
    #[arg(skip)]
    pub admin_server: Option<AdminServer>,

    /// Optional CLI banner sink so binaries emit user-facing startup lines without `diag_println!` gating or raw library `println!`.
    #[arg(skip)]
    pub on_banner: Option<BannerSink>,

    /// Optional warning sink so binaries surface non-fatal startup warnings even when diagnostic logs are quiet (`4.8`).
    #[arg(skip)]
    pub on_warning: Option<BannerSink>,
}

/// Sink for user-facing CLI startup banner lines (wired by binary entrypoints).
#[derive(Clone)]
pub struct BannerSink(pub Arc<dyn Fn(&str) + Send + Sync>);

impl std::fmt::Debug for BannerSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BannerSink")
    }
}

fn emit_banner(sink: &Option<BannerSink>, line: impl std::fmt::Display) {
    let text = line.to_string();
    if let Some(sink) = sink {
        (sink.0)(&text);
    } else {
        crate::diag::diag_println!("{text}");
    }
}

#[cfg(feature = "protocol")]
fn emit_warning(sink: &Option<BannerSink>, line: impl std::fmt::Display) {
    let text = line.to_string();
    if let Some(sink) = sink {
        (sink.0)(&text);
    } else {
        crate::diag::diag_eprintln!("{text}");
    }
}

/// Starts the Admin API for a service on `host:port` in the background, with the port's authentication (see [`ServeArgs::admin_server`]).
#[derive(Clone)]
pub struct AdminServer(
    pub  Arc<
        dyn Fn(
                Arc<ExecutionService>,
                &str,
                u16,
                Option<crate::admin_api_auth::AdminApiAuth>,
            ) -> Result<(), String>
            + Send
            + Sync,
    >,
);

impl std::fmt::Debug for AdminServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminServer")
    }
}

/// Starts the gRPC Ledger API for a service on `host:port` in the background (see [`ServeArgs::grpc_server`]).
#[derive(Clone)]
pub struct GrpcServer(
    pub Arc<dyn Fn(Arc<ExecutionService>, &str, u16) -> Result<(), String> + Send + Sync>,
);

impl std::fmt::Debug for GrpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrpcServer")
    }
}

/// Serves the JSON API (and the Ledger API v2 over HTTP) until the process is stopped.
pub fn serve(args: ServeArgs) -> Result<(), String> {
    #[cfg(feature = "protocol")]
    let conf = match &args.canton_conf {
        Some(path) => Some(crate::canton_conf::read(
            path,
            args.conf_participant.as_deref(),
            args.official_pg_addr.as_deref(),
            args.conf_auth_cert.as_deref(),
        )?),
        None => None,
    };
    #[cfg(feature = "protocol")]
    let port = match (&conf, args.conf_port) {
        (Some(c), true) => {
            c.http_port.ok_or(
                "--conf-port: the participant of the configuration has no http-ledger-api port",
            )? + args.conf_port_offset
        }
        _ => args.port,
    };
    #[cfg(not(feature = "protocol"))]
    let port = args.port;
    let pending_hmac_file_secret = if let Some(ref key_path) = args.jwt_hmac_secret_file {
        if args.jwt_audience_self && !crate::auth::is_loopback_host(&args.host) {
            return Err(format!(
                "refusing dev HS256 JWT authentication on non-loopback host '{}'",
                args.host
            ));
        }
        let raw = std::fs::read_to_string(key_path).map_err(|e| {
            format!(
                "cannot read --jwt-hmac-secret-file {}: {e}",
                key_path.display()
            )
        })?;
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(format!(
                "empty secret in --jwt-hmac-secret-file {}",
                key_path.display()
            ));
        }
        Some(trimmed)
    } else {
        None
    };
    let addr = format!("{}:{port}", args.host);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;

    emit_banner(
        &args.on_banner,
        "============================================================",
    );
    emit_banner(
        &args.on_banner,
        " Daml Ledger API & JSON API Server (Canton-Rust v3.7.2)    ",
    );
    emit_banner(
        &args.on_banner,
        format_args!(" Listening on: http://{}", addr),
    );
    emit_banner(
        &args.on_banner,
        "------------------------------------------------------------",
    );
    emit_banner(&args.on_banner, " Supported Endpoints:");
    emit_banner(&args.on_banner, "   GET  /livez, /readyz");
    emit_banner(&args.on_banner, "   GET  /v1/version");
    emit_banner(&args.on_banner, "   GET  /v1/packages");
    emit_banner(&args.on_banner, "   POST /v1/create");
    emit_banner(&args.on_banner, "   POST /v1/exercise");
    emit_banner(&args.on_banner, "   GET  /v1/contracts");
    emit_banner(&args.on_banner, "   POST /v1/query");
    emit_banner(&args.on_banner, "   POST /v1/command/submit-and-wait");
    emit_banner(
        &args.on_banner,
        "============================================================",
    );

    let service = Arc::new(ExecutionService::try_new()?);
    let recorder = args.scan_history.as_ref().map(|path| {
        Arc::new(crate::history::UpdateRecorder::new(
            path,
            &args.scan_synchronizer_id,
            0,
        ))
    });
    if let Some(recorder) = &recorder {
        service.set_update_recorder(Arc::clone(recorder));
    }
    if let Some(secs) = args.max_dedup_seconds {
        service.set_max_dedup(std::time::Duration::from_secs(secs));
    }
    if args.snapshot_every > 0 {
        service.set_snapshot_every(args.snapshot_every);
    }
    if args.xray {
        service.observability.set_wiretap_active(true);
    }
    #[cfg(feature = "protocol")]
    let official_target = match (&args.official_pg_url, &conf) {
        (Some(url), _) => Some(
            canton_participant::pgconn::PgTarget::from_url_or_jdbc(url, None, None, None)
                .map_err(|e| format!("Cannot read --official-pg-url: {e}"))?,
        ),
        (None, Some(c)) => c.database.clone(),
        (None, None) => None,
    };
    #[cfg(feature = "protocol")]
    let mut official_write_targets: Option<(
        canton_participant::pgconn::PgTarget,
        Vec<canton_participant::pgconn::PgTarget>,
    )> = None;
    #[cfg(feature = "protocol")]
    let official_adopted = match official_target {
        Some(target) => {
            let populated = crate::official::has_official_database(&target)?;
            let adopted = if populated {
                Some(crate::official::adopt_official_database(&service, &target)?)
            } else if args.official_write {
                if !crate::official::has_official_schema(&target)? {
                    return Err(
                        "The official database has no Canton participant schema (lapi_parameters missing): run canton-rs db migrate --role participant first"
                            .into(),
                    );
                }
                None
            } else if args.official_pg_url.is_some() {
                // Keep read-only `--official-pg-url` failing loudly when `lapi_parameters` is unpopulated.
                Some(crate::official::adopt_official_database(&service, &target)?)
            } else {
                None
            };
            if args.official_write {
                let peers = args
                    .official_topology_url
                    .iter()
                    .map(|u| {
                        canton_participant::pgconn::PgTarget::from_url_or_jdbc(u, None, None, None)
                            .map_err(|e| format!("Cannot read --official-topology-url: {e}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                official_write_targets = Some((target, peers));
            }
            adopted
        }
        None if args.official_write => return Err(
            "--official-write needs the database to write to: --official-pg-url or --canton-conf"
                .into(),
        ),
        None => None,
    };

    #[cfg(feature = "protocol")]
    if let Some(ref c) = conf {
        if c.traffic_enforcement {
            service.set_traffic_enforcement(true);
        }
        if let Some(limit) = c.http_list_max_elements_limit {
            service.set_http_list_max_elements_limit(Some(limit));
        }
        if let Some(wait_ms) = c.http_list_wait_time_ms {
            service.set_http_list_wait_time_ms(Some(wait_ms));
        }
        if let Some(auth) = c.auth.clone() {
            service.set_auth(auth);
            emit_banner(
                &args.on_banner,
                format_args!(" JWT authentication: on ({})", c.auth_services.join(", ")),
            );
        }
    }
    if args.traffic_enforcement {
        service.set_traffic_enforcement(true);
    }
    if let Some(limit) = args.http_list_max_elements_limit {
        service.set_http_list_max_elements_limit(Some(limit));
    }

    let mut deferred_self_auth: Option<(crate::AuthConfig, &'static str)> = None;
    if let Some(secret) = &args.jwt_hmac_secret {
        let mut config = crate::AuthConfig::hmac(secret);
        if let Some(seconds) = args.jwt_max_lifetime_seconds {
            config.max_lifetime_secs = seconds;
        }
        if args.jwt_audience_self {
            deferred_self_auth = Some((config, " JWT authentication: on (HMAC-SHA256)"));
        } else {
            service.set_auth(match &args.jwt_audience {
                Some(audience) => config.with_audience(audience),
                None => config,
            });
            emit_banner(&args.on_banner, " JWT authentication: on (HMAC-SHA256)");
        }
    }
    if let Some(cert) = &args.auth_cert {
        let pem = std::fs::read_to_string(cert)
            .map_err(|e| format!("cannot read --auth-cert {}: {e}", cert.display()))?;
        let mut config = crate::AuthConfig::rs256_certificate(&pem)?;
        if let Some(seconds) = args.jwt_max_lifetime_seconds {
            config.max_lifetime_secs = seconds;
        }
        if args.jwt_audience_self {
            deferred_self_auth = Some((config, " JWT authentication: on (jwt-rs-256-crt)"));
        } else {
            service.set_auth(match &args.jwt_audience {
                Some(audience) => config.with_audience(audience),
                None => config,
            });
            emit_banner(&args.on_banner, " JWT authentication: on (jwt-rs-256-crt)");
        }
    }

    #[cfg(feature = "protocol")]
    let mut loaded_dar_package_name: Option<String> = None;
    if let Some(ref dar_path) = args.dar {
        match service.load_dar(dar_path) {
            Ok(info) => {
                #[cfg(feature = "protocol")]
                {
                    loaded_dar_package_name = info.package_name.clone();
                }
                emit_banner(
                    &args.on_banner,
                    format_args!(
                        " Loaded DAR: {} (main package: {})",
                        dar_path.display(),
                        info.main_package_id
                    ),
                );
                if let Some(ref name) = info.package_name {
                    emit_banner(
                        &args.on_banner,
                        format_args!(
                            " Package: {} (v{})",
                            name,
                            info.package_version.as_deref().unwrap_or("unknown")
                        ),
                    );
                }
                emit_banner(
                    &args.on_banner,
                    format_args!(" Total packages in DAR: {}", info.dalfs.len()),
                );
            }
            Err(e) => {
                return Err(format!(
                    "Failed to load DAR from {}: {}",
                    dar_path.display(),
                    e
                ));
            }
        }
    }

    #[cfg(feature = "protocol")]
    if let Some(url) = &args.sequencer {
        let effective_package_name = args
            .package_name
            .clone()
            .or(loaded_dar_package_name)
            .unwrap_or_else(|| "sample-contract".to_string());
        let dar_path = args
            .dar
            .as_ref()
            .ok_or("--sequencer needs --dar: the participant runs the package of the DAR")?;
        let store: Option<Arc<dyn canton_participant::state_store::StateStore>> =
            if let Some(dir) = &args.state_dir {
                Some(
                    canton_participant::state_store::FileStore::new(dir)
                        .map_err(|e| format!("Cannot open the state directory: {e}"))?,
                )
            } else if let Some(pg) = &args.state_pg_url {
                let name = args.state_name.as_deref().unwrap_or(&args.participant_name);
                Some(
                    canton_participant::state_store::PgStore::connect(pg, name).map_err(|e| {
                        format!("Cannot open the participant's state in PostgreSQL: {e}")
                    })?,
                )
            } else {
                None
            };
        if let Some(store) = &store {
            emit_banner(
                &args.on_banner,
                format_args!(" State: {}", store.describe()),
            );
        }
        let committer = if args.also_sequencer.is_empty() {
            let node = canton_participant::node::Node::connect_with(
                url,
                &args.participant_name,
                dar_path,
                store,
            )
            .map_err(|e| format!("Cannot join the synchronizer at {url}: {e}"))?;
            emit_banner(
                &args.on_banner,
                format_args!(
                    " Participant: {} on the synchronizer at {url}",
                    node.identity.member()
                ),
            );
            let committer = crate::protocol::NodeCommitter::new(
                node,
                &effective_package_name,
                std::time::Duration::from_secs(30),
            )
            .with_tracking_timeout(COMMAND_TRACKING_TIMEOUT);
            // an alias given with a single `--sequencer` names that synchronizer (the default stays unnamed)
            Arc::new(if args.sequencer_alias == "sync0" {
                committer
            } else {
                committer.with_alias(&args.sequencer_alias)
            })
        } else {
            // the nodes keep their state themselves: under the directory (`sync-<i>`, and the shared identity), or in PostgreSQL under
            // the state names `<name>` (identity) and `<name>-sync-<i>`
            drop(store);
            let mut aliases = vec![args.sequencer_alias.clone()];
            let mut urls = vec![url.as_str()];
            for entry in &args.also_sequencer {
                let (alias, other) = entry
                    .split_once('=')
                    .ok_or_else(|| format!("--also-sequencer takes <alias>=<url>, not {entry}"))?;
                aliases.push(alias.to_string());
                urls.push(other);
            }
            let multi = if let Some(pg) = &args.state_pg_url {
                let name = args.state_name.as_deref().unwrap_or(&args.participant_name);
                let open = |state_name: &str| {
                    canton_participant::state_store::PgStore::connect(pg, state_name)
                        .map(|s| s as Arc<dyn canton_participant::state_store::StateStore>)
                        .map_err(|e| {
                            format!("Cannot open the participant's state {state_name:?} in PostgreSQL: {e}")
                        })
                };
                canton_participant::multi_node::MultiNode::connect_with(
                    &urls,
                    &args.participant_name,
                    dar_path,
                    Some(open(name)?),
                    |i| open(&format!("{name}-sync-{i}")).map(Some),
                )
            } else {
                canton_participant::multi_node::MultiNode::connect_in(
                    &urls,
                    &args.participant_name,
                    dar_path,
                    args.state_dir.as_deref(),
                )
            }
            .map_err(|e| format!("Cannot join the synchronizers {urls:?}: {e}"))?;
            emit_banner(
                &args.on_banner,
                format_args!(
                    " Participant: {} on {} synchronizers {aliases:?}",
                    multi.nodes[0].identity.member(),
                    multi.nodes.len()
                ),
            );
            Arc::new(
                crate::protocol::NodeCommitter::new_multi(
                    aliases.into_iter().zip(multi.nodes).collect(),
                    &effective_package_name,
                    std::time::Duration::from_secs(30),
                )
                .with_tracking_timeout(COMMAND_TRACKING_TIMEOUT),
            )
        };
        // the updates and completions of this service are on the synchronizer it joined
        if let Some((_, id)) = crate::service::ProtocolCommitter::synchronizers(&*committer).first()
        {
            service.v2_state().set_synchronizer(id);
        }
        if !service
            .v2_state()
            .official_parties
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            if let Some(uid) = crate::service::ProtocolCommitter::participant_id(&*committer) {
                service.v2_state().set_participant_id(&uid);
            }
        }
        if args.host_adopted_parties {
            let state = service.v2_state();
            let own = state.participant_id();
            let namespace = own
                .split_once("::")
                .map(|(_, n)| n.to_string())
                .unwrap_or_default();
            let remote = state
                .remote_parties
                .lock()
                .map(|r| r.clone())
                .unwrap_or_default();
            let parties = state.parties.lock().map(|p| p.clone()).unwrap_or_default();
            let (mut hosted, mut failed) = (0, 0);
            for party in parties {
                let Some((hint, ns)) = party.split_once("::") else {
                    continue;
                };
                if party == own || remote.contains(&party) || ns != namespace {
                    continue;
                }
                match crate::service::ProtocolCommitter::allocate_party(&*committer, hint) {
                    Some(Ok(id)) if id == party => hosted += 1,
                    other => {
                        failed += 1;
                        emit_warning(
                            &args.on_warning,
                            format_args!(" Cannot host {party} on the synchronizer: {other:?}"),
                        );
                    }
                }
            }
            emit_banner(
                &args.on_banner,
                format_args!(
                    " Hosted {hosted} party(ies) of the database on the synchronizer ({failed} failed)"
                ),
            );
        }
        // Restore uploaded DARs and administration state FIRST so dynamically uploaded templates
        // are known to `Node` before hydrating persisted contracts.
        let (dars, admin) = committer.restore_admin_in(&service);
        if dars > 0 || admin {
            emit_banner(
                &args.on_banner,
                format_args!(" Restored {dars} uploaded DAR(s) and the administration state from the participant's state"),
            );
        }
        let pre_hydrate_ledger_end = service
            .v2_state()
            .ledger_end
            .load(std::sync::atomic::Ordering::SeqCst);
        // the contracts the participant kept are in this API's ACS from the first call
        match committer.show_known_contracts_in(&service) {
            Ok(0) => {}
            Ok(n) => emit_banner(
                &args.on_banner,
                format_args!(" Restored {n} contract(s) from the participant's state directory"),
            ),
            Err(e) => return Err(format!("Cannot restore the participant's contracts: {e}")),
        }
        // what the official database holds can be exercised on this participant's synchronizer: its packages are vetted there, its contracts held
        if let Some(adopted) = &official_adopted {
            let (vetted, held, problems) =
                committer.adopt_official(&adopted.dars, &adopted.instances);
            emit_banner(
                &args.on_banner,
                format_args!(
                    " Official database: {vetted} DARs vetted on the synchronizer, {held} contracts the participant can exercise, {} problems",
                    problems.len()
                ),
            );
            for p in problems.iter().take(3) {
                emit_warning(&args.on_warning, format_args!(" Official database: {p}"));
            }
        }
        service
            .v2_state()
            .ledger_end
            .store(pre_hydrate_ledger_end, std::sync::atomic::Ordering::SeqCst);
        // and the updates it committed before are in the update stream, the offsets going on where they stopped
        let kept = committer.keep_updates_in(&service);
        if kept > 0 {
            emit_banner(
                &args.on_banner,
                format_args!(" Restored {kept} update(s) from the participant's state directory"),
            );
        }
        // what other participants get approved for this participant's parties is shown AFTER journals and ledger_end are restored
        committer.show_remote_transactions_in(Arc::clone(&service));
        if let Some(recorder) = &recorder {
            committer.record_salts_in(Arc::clone(recorder));
        }
        let official_synchronizer = match official_write_targets.take() {
            Some((target, peers)) => {
                crate::official::enable_official_writes(&service, &target, &peers)?
            }
            None => None,
        };
        service.set_committer(committer);
        // with `--official-write` the API names the synchronizer of the official database (see `enable_official_writes`), after the committer's own
        if let Some(id) = &official_synchronizer {
            service.v2_state().set_synchronizer(id);
        }
    }
    #[cfg(feature = "protocol")]
    if let Some((target, peers)) = official_write_targets.take() {
        if let Some(id) = crate::official::enable_official_writes(&service, &target, &peers)? {
            service.v2_state().set_synchronizer(&id);
        }
    }

    let store: Option<(String, Box<dyn crate::store::RequestLog>)> = if let Some(path) = &args.store
    {
        let log = crate::store::FileLog::open(path)
            .map_err(|e| format!("Cannot open the store {}: {e}", path.display()))?;
        Some((path.display().to_string(), Box::new(log)))
    } else if let Some(url) = &args.pg_url {
        let log = crate::store_pg::PgLog::connect(url, &args.ledger)
            .map_err(|e| format!("Cannot open the PostgreSQL ledger {:?}: {e}", args.ledger))?;
        Some((
            format!("postgresql ledger {:?}", args.ledger),
            Box::new(log),
        ))
    } else {
        None
    };
    if let Some((name, log)) = store {
        match service.attach_store(log) {
            Ok(report) => emit_banner(
                &args.on_banner,
                format_args!(
                    " Store: {name} ({} requests replayed in {:.2} s)",
                    report.replayed,
                    report.micros as f64 / 1e6
                ),
            ),
            Err(e) => {
                return Err(format!("Cannot start from the store {name}: {e}"));
            }
        }
    }
    let final_participant_id = service.v2_state().participant_id();
    if let Some(ref pid_file) = args.participant_id_file {
        write_participant_id_file(pid_file, &final_participant_id)?;
    }
    if let Some(secret) = pending_hmac_file_secret {
        let mut config = crate::AuthConfig::hmac(&secret);
        config.max_lifetime_secs = args
            .jwt_max_lifetime_seconds
            .unwrap_or(if args.jwt_audience_self { 86_400 } else { 300 });
        let final_cfg = if args.jwt_audience_self {
            config.with_audience(&final_participant_id)
        } else if let Some(ref audience) = args.jwt_audience {
            config.with_audience(audience)
        } else {
            config
        };
        service.set_auth(final_cfg);
        let msg = if args.jwt_audience_self {
            " JWT authentication: on (dev HS256, loopback-only)"
        } else {
            " JWT authentication: on (HMAC-SHA256 file)"
        };
        emit_banner(&args.on_banner, msg);
    } else if let Some((cfg, msg)) = deferred_self_auth {
        service.set_auth(cfg.with_audience(&final_participant_id));
        emit_banner(&args.on_banner, msg);
    }

    if let Some(exex_path) = &args.exex_jsonl {
        let scope = match (args.exex_zero_payload, args.exex_parties.is_empty()) {
            (true, false) => crate::exex::ExExPartyScope::PartiesZeroPayload(
                args.exex_parties.iter().cloned().collect(),
            ),
            (true, true) => crate::exex::ExExPartyScope::ZeroPayloadMetadata,
            (false, false) => {
                crate::exex::ExExPartyScope::Parties(args.exex_parties.iter().cloned().collect())
            }
            (false, true) => crate::exex::ExExPartyScope::AllParticipantVisible,
        };
        let state = service.v2_state();
        service.exex().register_jsonl_file_sink_with_backfill(
            "cli-jsonl-exex",
            scope,
            exex_path,
            1024,
            args.exex_from_offset,
            state,
        )?;
    }

    // the gRPC Ledger API of the same service, beside the HTTP one
    #[cfg(feature = "protocol")]
    let grpc_port = args.grpc_port.or_else(|| {
        conf.as_ref()
            .filter(|_| args.with_grpc)
            .and_then(|c| c.ledger_port)
            .map(|p| p + args.conf_port_offset)
    });
    #[cfg(not(feature = "protocol"))]
    let grpc_port = args.grpc_port;
    if let Some(grpc_port) = grpc_port {
        let server = args
            .grpc_server
            .as_ref()
            .ok_or("this program has no gRPC Ledger API server to start (--grpc-port)")?;
        (server.0)(Arc::clone(&service), &args.host, grpc_port)?;
        emit_banner(
            &args.on_banner,
            format_args!(" Ledger API v2 gRPC on {}:{grpc_port}", args.host),
        );
    } else if args.with_grpc {
        return Err(
            "--with-grpc: the participant of the configuration has no ledger-api port".into(),
        );
    }

    // the Admin API: the same dynamic service answers the one method of it that this program has (the Ledger API methods answer there as well)
    #[cfg(feature = "protocol")]
    let admin_port = args.admin_port.or_else(|| {
        conf.as_ref()
            .filter(|_| args.with_admin_api)
            .and_then(|c| c.admin_port)
            .map(|p| p + args.conf_port_offset)
    });
    #[cfg(not(feature = "protocol"))]
    let admin_port = args.admin_port;
    if let Some(admin_port) = admin_port {
        let server = args
            .admin_server
            .as_ref()
            .ok_or("this program has no gRPC server to start the Admin API with (--admin-port)")?;
        #[cfg(feature = "protocol")]
        let admin_auth = conf.as_ref().and_then(|c| c.admin_auth.clone());
        #[cfg(not(feature = "protocol"))]
        let admin_auth = None;
        (server.0)(Arc::clone(&service), &args.host, admin_port, admin_auth)?;
        emit_banner(
            &args.on_banner,
            format_args!(
                " Admin API (GetId, PackageService, PingService) on {}:{admin_port}",
                args.host
            ),
        );
    } else if args.with_admin_api {
        return Err(
            "--with-admin-api: the participant of the configuration has no admin-api port".into(),
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    stop_on_signals(&shutdown)?;

    #[cfg(feature = "protocol")]
    let node = args.participant_name.clone();
    #[cfg(not(feature = "protocol"))]
    let node = "participant".to_string();
    crate::http::set_request_log(args.log_encoder, format!("participant={node}"));
    run_server(service, listener, shutdown).map_err(|e| e.to_string())
}

/// Sets `shutdown` on SIGTERM or SIGINT: the server stops accepting and lets the requests in flight finish (see `run_server`).
///
/// [CANTON-NOTE: SEMANTICS] A Canton node shuts down on these signals and drains within `ProcessingTimeouts.shutdownProcessing` (internal
/// review A-14). A second signal while the first is being handled ends the process at once, so an operator can still force it.
fn stop_on_signals(shutdown: &Arc<AtomicBool>) -> Result<(), String> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    for signal in [SIGTERM, SIGINT] {
        // registered first: a second signal arrives with `shutdown` already set and exits with the signal's conventional status
        signal_hook::flag::register_conditional_shutdown(
            signal,
            128 + signal,
            Arc::clone(shutdown),
        )
        .map_err(|e| format!("cannot install the handler of signal {signal}: {e}"))?;
        signal_hook::flag::register(signal, Arc::clone(shutdown))
            .map_err(|e| format!("cannot install the handler of signal {signal}: {e}"))?;
    }
    Ok(())
}

fn write_participant_id_file(path: &std::path::Path, participant_id: &str) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create parent dir for {}: {e}", path.display()))?;
    }
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("participant-id");
    let tmp = path.with_file_name(format!(".{fname}.tmp.{}", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("cannot open {}: {e}", tmp.display()))?;
    file.write_all(format!("{participant_id}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot install {}: {e}", path.display())
    })
}
