//! A connection to the PostgreSQL server of a node's storage, with the TLS settings of the Canton storage config (`sslmode`,
//! `sslrootcert`) meaning what they mean to the official node's driver (G9, AT-D09).
//!
//! [CANTON-NOTE: SEMANTICS] Measured with the official 3.7.2 participant against a server with a test CA's certificate
//! (`scripts/oracle-db-tls.sh`, `tests/oracle/db-startup/tls.tsv`): `verify-full` checks the chain and the host name, `verify-ca` the chain
//! only, `require` encrypts and checks the chain when a root certificate is given, `disable` does not encrypt (a server that only takes TLS
//! refuses it). No setting turns a failed check into a connection.
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use postgres::{Client, NoTls};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslMode {
    Disable,
    Require,
    VerifyCa,
    VerifyFull,
}

impl SslMode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "disable" => Self::Disable,
            "require" => Self::Require,
            "verify-ca" => Self::VerifyCa,
            "verify-full" => Self::VerifyFull,
            _ => return None,
        })
    }
}

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct PgTarget {
    /// The server's name: what is resolved (unless `hostaddr` is given) and what its certificate has to name.
    pub host: String,
    pub hostaddr: Option<std::net::IpAddr>,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
    pub sslmode: SslMode,
    /// The CA certificates (PEM) the client trusts (`sslrootcert`).
    pub root_cert: Option<Vec<u8>>,
    /// The session's schema (`currentSchema`): where the history and the node's tables are.
    pub schema: Option<String>,
    /// The session's application name (`ApplicationName`).
    pub application_name: Option<String>,
    /// Optional SQL executed right after connecting (`connectionInitSql` in HikariCP / Canton storage config).
    pub connection_init_sql: Option<String>,
}

impl PgTarget {
    /// The target of a Canton storage `config` block: a JDBC `url` with `user`, `password` and driver `properties`, or a data source's
    /// `properties` (`serverName`, `portNumber`, `databaseName`, ...). `sslrootcert` is read from the file it names.
    ///
    /// [CANTON-NOTE: SEMANTICS] Measured on the official 3.7.2 participant (`scripts/oracle-db-jdbc.sh`, `tests/oracle/db-startup/jdbc.tsv`):
    /// the URL's database and its percent-decoded parameters win, properties fill what the URL leaves out. When the URL and the properties
    /// **disagree** the official node migrates the URL's database and schema and then fails on its own index (`INDEX_DB_SQL_NON_TRANSIENT_ERROR
    /// ... relation "lapi_parameters" does not exist`): such a config is refused here before anything is touched.
    pub fn from_canton_config(
        url: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        properties: &[(&str, &str)],
    ) -> Result<Self, String> {
        let prop = |k: &str| {
            properties
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        };
        let mut params: Vec<(String, String)> = Vec::new();
        let (host, port, database) = match url {
            Some(url) => {
                let rest = url
                    .strip_prefix("jdbc:postgresql://")
                    .ok_or_else(|| format!("not a PostgreSQL JDBC URL: {}", redact_url(url)))?;
                let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
                let (authority, path) = authority_path
                    .split_once('/')
                    .unwrap_or((authority_path, ""));
                let (url_user, url_pass, host_port) = match authority.rsplit_once('@') {
                    Some((creds, hp)) => match creds.split_once(':') {
                        Some((u, p)) => (Some(percent_decode(u)?), Some(percent_decode(p)?), hp),
                        None => (Some(percent_decode(creds)?), None, hp),
                    },
                    None => (None, None, authority),
                };
                if let Some(u) = url_user {
                    params.push(("user".into(), u));
                }
                if let Some(p) = url_pass {
                    params.push(("password".into(), p));
                }
                let (host, port) = match host_port.rsplit_once(':') {
                    Some((h, p)) => (
                        h.to_string(),
                        p.parse::<u16>().map_err(|_| format!("a port: {p}"))?,
                    ),
                    None => (host_port.to_string(), 5432),
                };
                for pair in query.split('&').filter(|p| !p.is_empty()) {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    params.push((percent_decode(k)?, percent_decode(v)?));
                }
                let database = percent_decode(path)?;
                // what the URL says, the properties may not say otherwise
                let mut said: Vec<(String, String)> = params.clone();
                said.push(("databaseName".into(), database.clone()));
                for (k, v) in &said {
                    if let Some(other) = prop(k) {
                        if &other != v {
                            if k.eq_ignore_ascii_case("password") {
                                return Err(
                                    "the JDBC URL and the data source properties disagree on password"
                                        .to_string(),
                                );
                            }
                            return Err(format!(
                                "the JDBC URL and the data source properties disagree on {k} ({v} and {other}): the official node migrates the one and indexes the other"
                            ));
                        }
                    }
                }
                (host, port, database)
            }
            None => (
                prop("serverName").ok_or("no serverName")?,
                prop("portNumber")
                    .map_or(Ok(5432), |p| p.parse().map_err(|_| format!("a port: {p}")))?,
                prop("databaseName").ok_or("no databaseName")?,
            ),
        };
        let get = |k: &str| {
            params
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .or_else(|| prop(k))
        };
        let sslmode = match get("sslmode") {
            None => SslMode::Disable,
            Some(m) => SslMode::parse(&m).ok_or_else(|| format!("an sslmode: {m}"))?,
        };
        let root_cert = match get("sslrootcert") {
            None => None,
            Some(path) => {
                Some(std::fs::read(&path).map_err(|e| format!("sslrootcert {path}: {e}"))?)
            }
        };
        Ok(Self {
            host,
            hostaddr: None,
            port,
            database,
            user: user
                .map(String::from)
                .or_else(|| get("user"))
                .unwrap_or_default(),
            password: password
                .map(String::from)
                .or_else(|| get("password"))
                .unwrap_or_default(),
            sslmode,
            root_cert,
            schema: get("currentSchema"),
            // [CANTON-NOTE: SEMANTICS] JDBC spells it `ApplicationName`, a libpq URL `application_name`; a libpq URL's was dropped, so the
            // session never carried the name its caller gave it (the state store tests find their own sessions by it)
            application_name: get("ApplicationName").or_else(|| get("application_name")),
            connection_init_sql: get("connectionInitSql"),
        })
    }

    /// Parses either a `jdbc:postgresql://...` URL or a standard `postgres[ql]://[user[:password]@]host[:port]/db?...` URL.
    pub fn from_url_or_jdbc(
        url: &str,
        user: Option<&str>,
        password: Option<&str>,
        connection_init_sql: Option<&str>,
    ) -> Result<Self, String> {
        let mut target = if url.starts_with("jdbc:postgresql://") {
            Self::from_canton_config(Some(url), user, password, &[])?
        } else if let Some(rest) = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
        {
            let (authority_path, query) = rest.split_once('?').unwrap_or((rest, ""));
            let (authority, path) = authority_path
                .split_once('/')
                .unwrap_or((authority_path, ""));
            let (url_user, url_pass, host_port) = match authority.rsplit_once('@') {
                Some((creds, hp)) => match creds.split_once(':') {
                    Some((u, p)) => (Some(percent_decode(u)?), Some(percent_decode(p)?), hp),
                    None => (Some(percent_decode(creds)?), None, hp),
                },
                None => (None, None, authority),
            };
            let jdbc = if query.is_empty() {
                format!("jdbc:postgresql://{host_port}/{path}")
            } else {
                format!("jdbc:postgresql://{host_port}/{path}?{query}")
            };
            let eff_user = user.map(String::from).or(url_user);
            let eff_pass = password.map(String::from).or(url_pass);
            Self::from_canton_config(Some(&jdbc), eff_user.as_deref(), eff_pass.as_deref(), &[])?
        } else {
            return Err(format!(
                "not a PostgreSQL JDBC or libpq URL: {}",
                redact_url(url)
            ));
        };
        if let Some(sql) = connection_init_sql {
            if !sql.trim().is_empty() {
                target.connection_init_sql = Some(sql.to_string());
            }
        }
        Ok(target)
    }
}

/// `url` with the password of its `user:password@` part and any `password=` parameter masked.
fn redact_url(url: &str) -> String {
    let (head, query) = url.split_once('?').unwrap_or((url, ""));
    let head = match head.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((creds, host)) => match creds.split_once(':') {
                Some((user, _)) => format!("{scheme}://{user}:***@{host}"),
                None => format!("{scheme}://{creds}@{host}"),
            },
            None => head.to_string(),
        },
        None => head.to_string(),
    };
    if query.is_empty() {
        return head;
    }
    let query: Vec<String> = query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if k.eq_ignore_ascii_case("password") => format!("{k}=***"),
            _ => kv.to_string(),
        })
        .collect();
    format!("{head}?{}", query.join("&"))
}

/// `%2D` -> `-`; a `%` that is not followed by two hex digits is refused.
fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .ok_or_else(|| "a broken percent escape in the URL credentials".to_string())?;
            out.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| "a broken percent escape in the URL credentials".to_string())?,
            );
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "URL credentials are not UTF-8 once decoded".to_string())
}

fn format_pg_error(err: &postgres::Error) -> String {
    let mut msg = err.to_string();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(err);
    while let Some(src) = cur {
        let s = src.to_string();
        if !msg.contains(&s) {
            msg.push_str(": ");
            msg.push_str(&s);
        }
        cur = src.source();
    }
    msg
}

/// Formats a comma-separated `currentSchema` value into a PostgreSQL `search_path` option string,
/// quoting any non-identifier schema name (such as hyphenated instance names like `inst-a-state`).
pub fn format_search_path(schema: &str) -> String {
    schema
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|part| {
            let already_quoted = part.starts_with('"') && part.ends_with('"') && part.len() >= 2;
            let safe_unquoted = part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if already_quoted || safe_unquoted {
                part.to_string()
            } else {
                let escaped = part.replace('"', "\"\"");
                format!("\"{escaped}\"")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Connects as `target` says; a refusal says why.
pub fn connect(target: &PgTarget) -> Result<Client, String> {
    let mut config = postgres::Config::new();
    config
        .host(&target.host)
        .port(target.port)
        .dbname(&target.database)
        .user(&target.user)
        .password(&target.password);
    if let Some(addr) = target.hostaddr {
        config.hostaddr(addr);
    }
    if let Some(name) = &target.application_name {
        config.application_name(name);
    }
    if let Some(schema) = &target.schema {
        let formatted = format_search_path(schema);
        if !formatted.is_empty() {
            config.options(&format!("-c search_path={formatted}"));
        }
    }
    let mut client = if target.sslmode == SslMode::Disable {
        config.ssl_mode(postgres::config::SslMode::Disable);
        config.connect(NoTls).map_err(|e| format_pg_error(&e))?
    } else {
        config.ssl_mode(postgres::config::SslMode::Require);
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(client_config(target)?);
        config.connect(tls).map_err(|e| format_pg_error(&e))?
    };
    if let Some(sql) = target
        .connection_init_sql
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        client.batch_execute(sql).map_err(|e| {
            let msg = e
                .as_db_error()
                .map_or_else(|| e.to_string(), |d| format!("ERROR: {}", d.message()));
            format!("Failed to initialize new connection: {msg}")
        })?;
    }
    Ok(client)
}

/// Connection retry schedule for database restarts and RDS writer DNS failovers (G9, AT-D09).
///
/// [CANTON-NOTE: SEMANTICS] Measured in `oracle-db-failover` (`tests/oracle/db-failover/outcome.tsv`): an official
/// Canton node survives a 20 s database outage and resumes answering within 12–14 s of DB restart without dropping the
/// process. Re-resolving hostnames on each attempt avoids pinned IP caching when RDS flips a writer CNAME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_elapsed: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub backoff_factor: u32,
}

impl RetryPolicy {
    pub fn canton_default() -> Self {
        Self {
            max_elapsed: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            backoff_factor: 2,
        }
    }

    pub fn from_env() -> Self {
        let mut policy = Self::canton_default();
        if let Some(secs) = std::env::var("CANTON_RS_STATE_PG_RETRY_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            policy.max_elapsed = Duration::from_secs(secs);
        }
        policy
    }

    pub fn next_backoff(&self, current: Duration) -> Duration {
        let factor = self.backoff_factor.max(1);
        current
            .saturating_mul(factor)
            .min(self.max_backoff)
            .max(self.initial_backoff)
    }
}

/// Performs a fresh DNS lookup for `(host, port)` without caching prior results across attempts.
pub fn resolve_fresh_hostaddrs(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {host}:{port}: {e}"))?;
    let mut ips = Vec::new();
    for addr in addrs {
        if !ips.contains(&addr.ip()) {
            ips.push(addr.ip());
        }
    }
    if ips.is_empty() {
        return Err(format!(
            "DNS resolution returned no addresses for {host}:{port}"
        ));
    }
    Ok(ips)
}

/// Classifies whether a PostgreSQL connection error should be retried (transient network, DNS, or DB recovery/restart)
/// or failed fast (TLS verification, bad credentials, invalid `connectionInitSql`, or missing database/role).
pub fn is_transient_connect_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    const FATAL_MARKERS: [&str; 10] = [
        "password authentication failed",
        "no pg_hba.conf entry",
        "failed to initialize new connection",
        "certificate",
        "not valid for name",
        "unknown issuer",
        "invalid dnsname",
        "sslmode",
        "does not exist",
        "permission denied",
    ];
    if FATAL_MARKERS.iter().any(|m| lower.contains(m)) {
        return false;
    }
    const TRANSIENT_MARKERS: [&str; 15] = [
        "connection refused",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "timed out",
        "timeout",
        "dns resolution",
        "failed to lookup",
        "could not translate host name",
        "network is unreachable",
        "57p01",
        "57p02",
        "57p03",
        "in recovery",
        "shutting down",
    ];
    TRANSIENT_MARKERS.iter().any(|m| lower.contains(m))
        || lower.contains("error connecting to server")
        || lower.contains("starting up")
        || lower.contains("terminating connection")
        || lower.contains("closed")
}

/// Connects to `target` with fresh per-attempt DNS resolution and exponential backoff under `policy`.
///
/// When `target.hostaddr` is `None`, `(target.host, target.port)` is resolved dynamically on every retry iteration while
/// `target.host` remains preserved for TLS certificate hostname verification (`verify-full`).
pub fn connect_with_retry(target: &PgTarget, policy: RetryPolicy) -> Result<Client, String> {
    let started = Instant::now();
    let mut pause = policy.initial_backoff;
    let mut last_err: Option<String> = None;

    loop {
        if target.hostaddr.is_some() {
            match connect(target) {
                Ok(client) => return Ok(client),
                Err(e) => {
                    if !is_transient_connect_error(&e) {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        } else {
            match resolve_fresh_hostaddrs(&target.host, target.port) {
                Ok(ips) => {
                    for ip in ips {
                        let mut attempt = target.clone();
                        attempt.hostaddr = Some(ip);
                        match connect(&attempt) {
                            Ok(client) => return Ok(client),
                            Err(e) => {
                                if !is_transient_connect_error(&e) {
                                    return Err(e);
                                }
                                last_err = Some(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let elapsed = started.elapsed();
        if elapsed >= policy.max_elapsed {
            return Err(last_err.unwrap_or_else(|| {
                format!(
                    "could not connect to {}:{} within {:?}",
                    target.host, target.port, policy.max_elapsed
                )
            }));
        }
        let sleep_for = pause.min(policy.max_elapsed.saturating_sub(elapsed));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }
        pause = policy.next_backoff(pause);
    }
}

fn client_config(target: &PgTarget) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(std::sync::Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let roots = match &target.root_cert {
        None => None,
        Some(pem) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem) {
                roots
                    .add(cert.map_err(|e| format!("the root certificate: {e}"))?)
                    .map_err(|e| format!("the root certificate: {e}"))?;
            }
            Some(Arc::new(roots))
        }
    };
    let verifier: Arc<dyn ServerCertVerifier> = match (target.sslmode, roots) {
        (SslMode::VerifyFull, Some(roots)) => {
            rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| e.to_string())?
        }
        (SslMode::VerifyCa, Some(roots)) => Arc::new(ChainOnly(
            rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| e.to_string())?,
        )),
        (SslMode::VerifyFull | SslMode::VerifyCa, None) => {
            return Err(format!(
                "sslmode {:?} needs a root certificate (sslrootcert)",
                target.sslmode
            ))
        }
        // [CANTON-NOTE: WHY] `require` encrypts without authenticating the server, with or without a root certificate, as the official
        // node's driver does (measured); the configuration says so, nothing here decides it
        (SslMode::Require, _) => Arc::new(EncryptOnly(provider)),
        (SslMode::Disable, _) => unreachable!("handled before"),
    };
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// `verify-ca`: the chain must lead to a trusted CA; the name the certificate is for is not looked at.
#[derive(Debug)]
struct ChainOnly(Arc<rustls::client::WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName))
            | Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// `require`: the handshake's signatures are checked, the certificate is not.
#[derive(Debug)]
struct EncryptOnly(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for EncryptOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn url_parse_errors_do_not_echo_the_password() {
        for url in [
            "mysql://admin:s3cret@db.example/x",
            "postgres://admin:s3cr%ZZet@db.example/x",
            "postgres://admin:s3cr%FFet@db.example/x",
            "jdbc:postgresql://admin:s3cret@db.example:badport/x",
        ] {
            let err = PgTarget::from_url_or_jdbc(url, None, None, None).expect_err(url);
            assert!(!err.contains("s3cr"), "{url} -> {err}");
        }
        let parsed = PgTarget::from_canton_config(
            Some("jdbc:postgresql://admin:s3cret@db.example/x"),
            None,
            None,
            &[],
        )
        .expect("missing port with userinfo parses cleanly");
        assert_eq!(parsed.host, "db.example");
        assert_eq!(parsed.port, 5432);
        assert_eq!(parsed.user, "admin");
        assert_eq!(parsed.password, "s3cret");

        let mismatch = PgTarget::from_canton_config(
            Some("jdbc:postgresql://db.example:5432/x?password=s3cret_a"),
            None,
            None,
            &[("password", "s3cret_b")],
        )
        .expect_err("conflicting password must be refused");
        assert!(!mismatch.contains("s3cret"), "{mismatch}");
    }

    #[test]
    fn retry_policy_backoff_doubles_and_caps() {
        let p = RetryPolicy::canton_default();
        assert_eq!(p.max_elapsed, Duration::from_secs(60));
        let d1 = p.next_backoff(p.initial_backoff);
        assert_eq!(d1, Duration::from_millis(200));
        let d_cap = p.next_backoff(Duration::from_secs(2));
        assert_eq!(d_cap, Duration::from_secs(2));
    }

    #[test]
    fn error_classifier_separates_transient_outage_from_fatal_config() {
        assert!(is_transient_connect_error(
            "error connecting to server: Connection refused (os error 61)"
        ));
        assert!(is_transient_connect_error(
            "db error: FATAL: the database system is in recovery mode (57P03)"
        ));
        assert!(is_transient_connect_error(
            "DNS resolution failed for db-writer.internal:5432"
        ));
        assert!(!is_transient_connect_error(
            "db error: FATAL: password authentication failed for user \"canton\""
        ));
        assert!(!is_transient_connect_error(
            "Failed to initialize new connection: ERROR: syntax error"
        ));
        assert!(!is_transient_connect_error(
            "invalid peer certificate: NotValidForName"
        ));
    }

    #[test]
    fn resolve_fresh_hostaddrs_resolves_localhost_without_caching_errors() {
        let ips = resolve_fresh_hostaddrs("localhost", 5432).expect("localhost resolves");
        assert!(!ips.is_empty());
        let literal = resolve_fresh_hostaddrs("127.0.0.1", 5432).expect("literal IP");
        assert_eq!(literal, vec![IpAddr::from([127, 0, 0, 1])]);
    }

    #[test]
    fn connect_with_retry_respects_deadline_on_refused_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let target = PgTarget::from_canton_config(
            Some(&format!("jdbc:postgresql://localhost:{port}/canton")),
            Some("canton"),
            Some("canton"),
            &[("sslmode", "disable")],
        )
        .unwrap();

        let t0 = Instant::now();
        let err = match connect_with_retry(
            &target,
            RetryPolicy {
                max_elapsed: Duration::from_millis(250),
                initial_backoff: Duration::from_millis(40),
                max_backoff: Duration::from_millis(100),
                backoff_factor: 2,
            },
        ) {
            Ok(_) => panic!("expected refused connection"),
            Err(e) => e,
        };
        assert!(is_transient_connect_error(&err), "unexpected err: {err}");
        assert!(
            t0.elapsed() >= Duration::from_millis(150),
            "expected retry window to elapse, got {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn format_search_path_quotes_hyphenated_identifiers() {
        assert_eq!(format_search_path("public"), "public");
        assert_eq!(format_search_path("inst-a-state"), "\"inst-a-state\"");
        assert_eq!(
            format_search_path("inst-a-state, public"),
            "\"inst-a-state\",public"
        );
        assert_eq!(
            format_search_path("\"already-quoted\""),
            "\"already-quoted\""
        );
    }
}
