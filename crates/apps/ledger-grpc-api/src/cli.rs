//! The Ledger API v2 gRPC server as a command (`ledger-grpc-server`, and `canton-rs ledger-api`).
use std::{path::PathBuf, sync::Arc};

use ledger_json_api::{admin_api_auth::AdminApiAuth, cli::BannerSink, ExecutionService};

/// The options of the gRPC Ledger API server.
#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(short, long, default_value_t = 6865)]
    pub port: u16,
    /// Require JWT bearer tokens signed with this HMAC-SHA256 secret
    #[arg(long)]
    pub jwt_hmac_secret: Option<String>,
    /// Start on the database of an official Canton 3.7.2 participant (libpq or JDBC PostgreSQL URL; prefer `CANTON_RS_OFFICIAL_PG_URL`): its parties,
    /// users, DARs, active contracts and ledger end are read, read-only, and are this server's (U-47).
    #[cfg(feature = "official")]
    #[arg(
        long,
        env = "CANTON_RS_OFFICIAL_PG_URL",
        hide_env_values = true,
        hide = true
    )]
    pub official_pg_url: Option<String>,
    /// A Canton configuration file (`canton.conf`): its storage block names the database the API reads from, its `ledger-api` port is the
    /// port with `--conf-port`, and a `jwt-rs-256-crt` auth service turns RS256 token checks on.
    #[cfg(feature = "official")]
    #[arg(long, env = "CANTON_RS_CANTON_CONF")]
    pub canton_conf: Option<PathBuf>,
    /// With `--canton-conf`: the participant of the file (default: the only one).
    #[cfg(feature = "official")]
    #[arg(long, requires = "canton_conf")]
    pub conf_participant: Option<String>,
    /// With `--canton-conf`: reach the configured database at this `host:port` instead of the configured one.
    #[cfg(feature = "official")]
    #[arg(long, requires = "canton_conf", hide = true)]
    pub official_pg_addr: Option<String>,
    /// With `--canton-conf`: the certificate file of its `jwt-rs-256-crt` service on this host.
    #[cfg(feature = "official")]
    #[arg(long, requires = "canton_conf")]
    pub conf_auth_cert: Option<PathBuf>,
    /// With `--canton-conf`: listen on the configured `ledger-api` port instead of `--port`.
    #[cfg(feature = "official")]
    #[arg(long, requires = "canton_conf")]
    pub conf_port: bool,
    /// How the server writes its request log: `text` (none, the default), or `plain` / `json`, the two encoders of a Canton node's log.
    #[arg(long, value_enum, default_value = "text")]
    pub log_encoder: ledger_json_api::canton_log::LogEncoder,
    /// A DAR to load at startup
    #[arg(long)]
    pub dar: Option<PathBuf>,
    /// PEM certificate chain for serving Ledger API over TLS.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key (PKCS#8) matching `--tls-cert`.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
    /// Optional PEM client CA bundle requiring mutual TLS when set alongside `--tls-cert` and `--tls-key`.
    #[arg(long)]
    pub tls_client_ca: Option<PathBuf>,
}

/// Starts the gRPC Ledger API for an existing service on `host:port` in a thread of its own (no TLS), so a process that serves another API from the
/// same service (`canton-rs json-api --with-grpc`) answers both. The thread lives as long as the process. An error that stops the thread
/// after the start goes to `on_error`.
///
/// [CANTON-NOTE: WHY] Library crates print nothing themselves (`S-QUAL-003`); the binary passes a sink that writes to stderr, so a server
/// that stops in the background is still reported whatever `CANTON_RS_LOG` says.
pub fn serve_in_background(
    service: Arc<ExecutionService>,
    host: &str,
    port: u16,
    on_error: BannerSink,
) -> Result<(), String> {
    serve_on_in_background(service, host, port, None, on_error)
}

/// `admin` is `None` for the Ledger API port, the port's authentication for the Admin API port.
fn serve_on_in_background(
    service: Arc<ExecutionService>,
    host: &str,
    port: u16,
    admin: Option<Option<AdminApiAuth>>,
    on_error: BannerSink,
) -> Result<(), String> {
    let addr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("{host}:{port}: {e}"))?;
    // the port is checked here, in the caller's thread, so a port in use is an error of the start and not a thread that ends
    drop(std::net::TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?);
    std::thread::Builder::new()
        .name("ledger-api-grpc".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => return (on_error.0)(&format!("gRPC Ledger API: {e}")),
            };
            let served = match admin {
                None => runtime.block_on(crate::server::serve(service, addr)),
                Some(auth) => runtime.block_on(crate::server::serve_admin(service, addr, auth)),
            };
            if let Err(e) = served {
                (on_error.0)(&format!("gRPC Ledger API stopped: {e}"));
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Like [`serve_in_background`], for the participant Admin API endpoint: eagerly loads and vets the built-in ping DAR and
/// starts the Admin Ping Nanobot responder at startup.
pub fn serve_admin_in_background(
    service: Arc<ExecutionService>,
    host: &str,
    port: u16,
    auth: Option<AdminApiAuth>,
    on_error: BannerSink,
) -> Result<(), String> {
    if let Err(status) = crate::admin_api::ensure_ping_workflow(&service) {
        return Err(status.to_string());
    }
    serve_on_in_background(service, host, port, Some(auth), on_error)
}

/// Serves the Ledger API v2 over gRPC until the process is stopped. The startup lines go to `out` (the binary's stdout).
pub fn serve(args: ServeArgs, out: &dyn Fn(&str)) -> Result<(), String> {
    #[cfg(feature = "official")]
    let conf = match &args.canton_conf {
        Some(path) => Some(ledger_json_api::canton_conf::read(
            path,
            args.conf_participant.as_deref(),
            args.official_pg_addr.as_deref(),
            args.conf_auth_cert.as_deref(),
        )?),
        None => None,
    };
    #[cfg(feature = "official")]
    let port = match (&conf, args.conf_port) {
        (Some(c), true) => c
            .ledger_port
            .ok_or("--conf-port: the participant of the configuration has no ledger-api port")?,
        _ => args.port,
    };
    #[cfg(not(feature = "official"))]
    let port = args.port;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = std::fs::read_to_string(cert)
                .map_err(|e| format!("cannot read TLS certificate {}: {e}", cert.display()))?;
            let key_pem = std::fs::read_to_string(key)
                .map_err(|e| format!("cannot read TLS key {}: {e}", key.display()))?;
            let client_ca_pem = args
                .tls_client_ca
                .as_ref()
                .map(|ca| {
                    std::fs::read_to_string(ca)
                        .map_err(|e| format!("cannot read TLS client CA {}: {e}", ca.display()))
                })
                .transpose()?;
            Some(crate::server::TlsServerOptions {
                cert_pem,
                key_pem,
                client_ca_pem,
            })
        }
        (None, None) => {
            if args.tls_client_ca.is_some() {
                return Err("--tls-client-ca requires --tls-cert and --tls-key".into());
            }
            None
        }
        _ => return Err("--tls-cert and --tls-key must be provided together".into()),
    };
    let ledger = Arc::new(ExecutionService::try_new()?);
    if let Some(secret) = &args.jwt_hmac_secret {
        ledger.set_auth(ledger_json_api::AuthConfig::hmac(secret));
    }
    #[cfg(feature = "official")]
    {
        let target = match (&args.official_pg_url, &conf) {
            (Some(url), _) => Some(
                canton_participant::pgconn::PgTarget::from_url_or_jdbc(url, None, None, None)
                    .map_err(|e| format!("Cannot read --official-pg-url: {e}"))?,
            ),
            (None, Some(c)) => c.database.clone(),
            (None, None) => None,
        };
        if let Some(target) = target {
            ledger_json_api::official::adopt_official_database(&ledger, &target)?;
        }
        if let Some(auth) = conf.as_ref().and_then(|c| c.auth.clone()) {
            ledger.set_auth(auth);
            out("JWT authentication: on (RS256, the certificate of the configuration)");
        }
    }
    if let Some(dar) = &args.dar {
        ledger
            .load_dar(dar)
            .map_err(|e| format!("cannot load {}: {e}", dar.display()))?;
    }
    ledger_json_api::http::set_request_log(args.log_encoder, "participant=participant".to_string());
    let addr = format!("{}:{port}", args.host)
        .parse()
        .map_err(|e| format!("{}:{port}: {e}", args.host))?;
    out(&format!("Ledger API v2 gRPC on {addr}"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    match tls {
        Some(tls) => runtime.block_on(crate::server::serve_tls(ledger, addr, tls)),
        None => runtime.block_on(crate::server::serve(ledger, addr)),
    }
    .map_err(|e| e.to_string())
}
