//! What `--canton-conf` takes from an official participant's `canton.conf` (U-47): the database of its storage block, its `http-ledger-api` port,
//! and what its Ledger API authenticates with. The file is read with [`canton_participant::hocon`], which refuses what it does not know.
//!
//! [CANTON-NOTE: SEMANTICS] The configuration names the database as the *node's* process sees it (`serverName = "hub-postgres"` inside a container
//! network); a client on the host reaches it elsewhere, so `--official-pg-addr host:port` replaces the address and keeps the rest (database, user,
//! password, SSL mode). Nothing in the file is written back.
use std::path::Path;

use canton_participant::hocon::{parse_file, Hocon};
use canton_participant::pgconn::PgTarget;

/// The parts of a participant's configuration this server uses.
pub struct CantonConf {
    pub participant: String,
    /// The PostgreSQL database of its storage (`None` for another storage type: there is no database to read).
    pub database: Option<PgTarget>,
    pub http_port: Option<u16>,
    pub ledger_port: Option<u16>,
    /// The `admin-api` port of the participant: where its Admin API (`IdentityInitializationService.GetId`, the part this server answers) is served.
    pub admin_port: Option<u16>,
    /// The `type` of each of its Ledger API's `auth-services`.
    pub auth_services: Vec<String>,
    /// The authentication configuration parsed from `ledger-api.auth-services`, `max-token-life`, `jwt-timestamp-leeway`, and `jwks-cache-config`.
    pub auth: Option<crate::AuthConfig>,
    /// The Admin API port's authentication (`admin-api.auth-services`, `admin-token-config`); `None` when it has no auth services.
    pub admin_auth: Option<crate::admin_api_auth::AdminApiAuth>,
    /// Whether `http-ledger-api.traffic-enforcement` is enabled (`false` by default).
    pub traffic_enforcement: bool,
    /// Optional cap on HTTP blocking list results (`http-ledger-api.websocket-config.http-list-max-elements-limit`).
    pub http_list_max_elements_limit: Option<usize>,
    /// Optional idle wait timeout in milliseconds (`http-ledger-api.websocket-config.http-list-wait-time`).
    pub http_list_wait_time_ms: Option<u64>,
}

/// The keys of a node (`canton.<kind>.<name>.<key>`) this program reads and applies, with everything below them.
pub const APPLIED_NODE_KEYS: [&str; 20] = [
    "storage.type",
    "storage.config",
    "public-api.port",
    "public-api.address",
    "admin-api.port",
    "admin-api.address",
    "admin-api.auth-services",
    "admin-api.admin-token-config",
    "ledger-api.port",
    "ledger-api.address",
    "ledger-api.auth-services",
    "ledger-api.max-token-life",
    "ledger-api.jwt-timestamp-leeway",
    "ledger-api.jwks-cache-config",
    "http-ledger-api.port",
    "http-ledger-api.address",
    "http-ledger-api.traffic-enforcement",
    "http-ledger-api.websocket-config.http-list-max-elements-limit",
    "http-ledger-api.websocket-config.http-list-wait-time",
    "traffic-enforcement.enabled",
];

/// The keys of a node whose setting changes nothing a client sees (a connection pool).
pub const HARMLESS_NODE_KEYS: [&str; 1] = ["storage.parameters"];

/// Whether the key `key` (a path below a node) is one of `keys` or below one (`k.x`, `k[].x`).
pub fn is_under(key: &str, keys: &[&str]) -> bool {
    keys.iter().any(|k| {
        key == *k || key.starts_with(&format!("{k}.")) || key.starts_with(&format!("{k}["))
    })
}

/// The keys of participant `name` that this program does not apply (full paths). Among them are the transport limits
/// (`max-inbound-message-size`, `keep-alive-server`), `rate-limit` and `tls` of its APIs: the listeners use Canton's defaults.
pub fn unapplied_participant_keys(conf: &Hocon, name: &str) -> Vec<String> {
    let prefix = format!("canton.participants.{name}");
    let Some(node) = conf.get(&prefix) else {
        return Vec::new();
    };
    node.leaf_paths(&prefix)
        .into_iter()
        .filter(|path| {
            let key = path.strip_prefix(&format!("{prefix}.")).unwrap_or(path);
            !is_under(key, &APPLIED_NODE_KEYS) && !is_under(key, &HARMLESS_NODE_KEYS)
        })
        .collect()
}

/// Reads the configuration at `path` for `participant` (the only one when `None`) and prints what it says.
pub fn read(
    path: &Path,
    participant: Option<&str>,
    pg_addr: Option<&str>,
    auth_cert: Option<&Path>,
) -> Result<CantonConf, String> {
    read_inner(path, participant, pg_addr, auth_cert, true)
}

/// Only the database of the participant's storage (no authentication read, nothing printed): for a caller that needs the database and leaves the
/// Ledger API's auth service to the process that serves it.
pub fn database(
    path: &Path,
    participant: Option<&str>,
    pg_addr: Option<&str>,
) -> Result<Option<PgTarget>, String> {
    Ok(read_inner(path, participant, pg_addr, None, false)?.database)
}

/// The PostgreSQL database of the storage block of a node (`<prefix>.storage`), at `pg_addr` (`host:port`) instead of the configured host when given;
/// `None` for a node whose storage is not PostgreSQL.
fn storage_target(
    conf: &Hocon,
    prefix: &str,
    pg_addr: Option<&str>,
) -> Result<Option<PgTarget>, String> {
    let at = |tail: &str| conf.get(&format!("{prefix}.{tail}"));
    if at("storage.type").and_then(Hocon::text).as_deref() != Some("postgres") {
        return Ok(None);
    }
    let config = at("storage.config").ok_or("the storage has no config block")?;
    let properties = config
        .get("properties")
        .map(Hocon::scalars)
        .unwrap_or_default();
    let props: Vec<(&str, &str)> = properties
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let url = config.get("url").and_then(Hocon::text);
    let user = config.get("user").and_then(Hocon::text);
    let password = config.get("password").and_then(Hocon::text);
    let mut target =
        PgTarget::from_canton_config(url.as_deref(), user.as_deref(), password.as_deref(), &props)?;
    if let Some(addr) = pg_addr {
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or("--official-pg-addr is host:port")?;
        target.host = host.to_string();
        target.port = port
            .parse()
            .map_err(|_| format!("--official-pg-addr port: {port}"))?;
    }
    Ok(Some(target))
}

/// The database of the storage block of a sequencer, mediator or participant of the configuration (`kind` is `sequencers`, `mediators` or
/// `participants`), `None` when it is not PostgreSQL. The nodes a daemon starts keep their state there (U-47).
pub fn node_database(
    path: &Path,
    kind: &str,
    node: &str,
    pg_addr: Option<&str>,
) -> Result<Option<PgTarget>, String> {
    let conf = parse_file(path, &|name| std::env::var(name).ok())
        .map_err(|e| format!("Cannot read the configuration {}: {e}", path.display()))?;
    storage_target(&conf, &format!("canton.{kind}.{node}"), pg_addr)
}

/// A libpq URL (`postgres://user:password@host:port/database`) for a target, the user and password percent-encoded: what `--state-pg-url` takes.
pub fn pg_url(target: &PgTarget) -> String {
    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect()
    }
    format!(
        "postgres://{}:{}@{}:{}/{}",
        enc(&target.user),
        enc(&target.password),
        target.host,
        target.port,
        enc(&target.database)
    )
}

fn read_inner(
    path: &Path,
    participant: Option<&str>,
    pg_addr: Option<&str>,
    auth_cert: Option<&Path>,
    with_auth: bool,
) -> Result<CantonConf, String> {
    let conf = parse_file(path, &|name| std::env::var(name).ok())
        .map_err(|e| format!("Cannot read the configuration {}: {e}", path.display()))?;
    let participants = conf
        .get("canton.participants")
        .ok_or("the configuration has no canton.participants")?;
    let names = participants.keys();
    let name = match (participant, names.as_slice()) {
        (Some(n), _) if names.contains(&n) => n.to_string(),
        (Some(n), _) => {
            return Err(format!(
                "the configuration has no participant {n} (it has {})",
                names.join(", ")
            ))
        }
        (None, [only]) => only.to_string(),
        (None, _) => {
            return Err(format!(
                "the configuration has several participants ({}): name one with --conf-participant",
                names.join(", ")
            ))
        }
    };
    let at = |tail: &str| conf.get(&format!("canton.participants.{name}.{tail}"));
    let database = storage_target(&conf, &format!("canton.participants.{name}"), pg_addr)?;
    let auth_services = match at("ledger-api.auth-services") {
        Some(Hocon::Array(items)) => items
            .iter()
            .filter_map(|i| i.get("type").and_then(Hocon::text))
            .collect(),
        _ => Vec::new(),
    };
    // [CANTON-NOTE: SEMANTICS] A `jwt-rs-256-crt`, `jwt-es-256-crt`, `jwt-es-512-crt`, `unsafe-jwt-hmac-256`,
    // `jwt-jwks`, or `wildcard` auth service turns authentication on; unknown types are refused loudly.
    let traffic_enforcement = at("http-ledger-api.traffic-enforcement")
        .or_else(|| at("traffic-enforcement.enabled"))
        .and_then(Hocon::text)
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(false);
    let http_list_max_elements_limit =
        at("http-ledger-api.websocket-config.http-list-max-elements-limit")
            .map(|v| {
                let raw = v.text().ok_or(
                    "invalid http-ledger-api.websocket-config.http-list-max-elements-limit",
                )?;
                let n = raw.trim().parse::<i64>().map_err(|_| {
                    format!(
                "invalid http-ledger-api.websocket-config.http-list-max-elements-limit: {raw:?}"
            )
                })?;
                usize::try_from(n).map_err(|_| {
                    format!(
                "negative http-ledger-api.websocket-config.http-list-max-elements-limit: {raw:?}"
            )
                })
            })
            .transpose()?;
    let http_list_wait_time_ms = at("http-ledger-api.websocket-config.http-list-wait-time")
        .and_then(Hocon::text)
        .map(|s| parse_duration_millis(&s))
        .transpose()?;
    let (auth, admin_auth) = if with_auth {
        (
            parse_auth_services(&conf, &name, auth_cert)?,
            parse_admin_api_auth(&conf, &name, auth_cert)?,
        )
    } else {
        (None, None)
    };
    let (http_port, ledger_port) = (
        at("http-ledger-api.port").and_then(Hocon::as_u16),
        at("ledger-api.port").and_then(Hocon::as_u16),
    );
    let result = CantonConf {
        participant: name.clone(),
        database,
        http_port,
        ledger_port,
        admin_port: at("admin-api.port").and_then(Hocon::as_u16),
        auth_services,
        auth,
        admin_auth,
        traffic_enforcement,
        http_list_max_elements_limit,
        http_list_wait_time_ms,
    };
    if !with_auth {
        return Ok(result);
    }
    // [CANTON-NOTE: DEFENSIVE] A setting this program does not follow is said out loud, as the daemon says it (A-13).
    for key in unapplied_participant_keys(&conf, &name) {
        crate::diag::diag_eprintln!(
            " Canton configuration {}: {key} is not applied",
            path.display()
        );
    }
    crate::diag::diag_println!(
        " Canton configuration {}: participant {}, storage {}, ledger-api port {}, http-ledger-api port {}, auth {}",
        path.display(),
        result.participant,
        match &result.database {
            Some(d) => format!("postgres {}:{}/{}", d.host, d.port, d.database),
            None => at("storage.type")
                .and_then(Hocon::text)
                .unwrap_or_else(|| "none".into()),
        },
        result.ledger_port.map_or("-".to_string(), |p| p.to_string()),
        result.http_port.map_or("-".to_string(), |p| p.to_string()),
        if result.auth_services.is_empty() {
            "none".to_string()
        } else {
            result.auth_services.join(", ")
        }
    );
    Ok(result)
}

fn parse_duration_parts(raw: &str, bare_unit: &str) -> Result<(i64, String), String> {
    let s = raw.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Ok((n, bare_unit.to_string()));
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .ok_or_else(|| format!("invalid HOCON duration {raw:?}"))?;
    let num: i64 = s[..split]
        .trim()
        .parse()
        .map_err(|_| format!("invalid HOCON duration {raw:?}"))?;
    Ok((num, s[split..].trim().to_ascii_lowercase()))
}

fn parse_duration_secs(raw: &str) -> Result<i64, String> {
    let (num, unit) = parse_duration_parts(raw, "s")?;
    match unit.as_str() {
        "ns" | "nanos" | "nanoseconds" => Ok(0),
        "us" | "micros" | "microseconds" => Ok(0),
        "ms" | "millis" | "milliseconds" => Ok(if num <= 0 { 0 } else { (num + 999) / 1000 }),
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(num),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(num * 60),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(num * 3600),
        "d" | "day" | "days" => Ok(num * 86400),
        _ => Err(format!("unknown HOCON duration unit in {raw:?}")),
    }
}

fn parse_duration_millis(raw: &str) -> Result<u64, String> {
    let (num, unit) = parse_duration_parts(raw, "ms")?;
    if num < 0 {
        return Err(format!("negative HOCON duration {raw:?}"));
    }
    let millis: i64 = match unit.as_str() {
        "ns" | "nanos" | "nanoseconds" => num / 1_000_000,
        "us" | "micros" | "microseconds" => num / 1_000,
        "ms" | "millis" | "milliseconds" => num,
        "s" | "sec" | "secs" | "second" | "seconds" => num.saturating_mul(1_000),
        "m" | "min" | "mins" | "minute" | "minutes" => num.saturating_mul(60_000),
        "h" | "hr" | "hrs" | "hour" | "hours" => num.saturating_mul(3_600_000),
        "d" | "day" | "days" => num.saturating_mul(86_400_000),
        _ => return Err(format!("unknown HOCON duration unit in {raw:?}")),
    };
    u64::try_from(millis).map_err(|_| format!("invalid HOCON duration {raw:?}"))
}

fn parse_jwks_cache_config(conf: &Hocon, name: &str) -> crate::auth_jwks::JwksCacheConfig {
    let at = |tail: &str| conf.get(&format!("canton.participants.{name}.{tail}"));
    let mut cfg = crate::auth_jwks::JwksCacheConfig::default();
    if let Some(v) = at("ledger-api.jwks-cache-config.cache-max-size")
        .and_then(Hocon::text)
        .and_then(|s| s.parse::<usize>().ok())
    {
        cfg.cache_max_size = v.max(1);
    }
    if let Some(v) = at("ledger-api.jwks-cache-config.cache-max-age")
        .and_then(Hocon::text)
        .and_then(|s| parse_duration_secs(&s).ok())
    {
        cfg.cache_max_age_secs = u64::try_from(v.max(0)).unwrap_or(0);
    }
    if let Some(v) = at("ledger-api.jwks-cache-config.connection-timeout")
        .and_then(Hocon::text)
        .and_then(|s| parse_duration_secs(&s).ok())
    {
        cfg.connection_timeout_secs = u64::try_from(v.max(1)).unwrap_or(10);
    }
    if let Some(v) = at("ledger-api.jwks-cache-config.read-timeout")
        .and_then(Hocon::text)
        .and_then(|s| parse_duration_secs(&s).ok())
    {
        cfg.read_timeout_secs = u64::try_from(v.max(1)).unwrap_or(10);
    }
    cfg
}

fn parse_auth_services(
    conf: &Hocon,
    name: &str,
    auth_cert: Option<&Path>,
) -> Result<Option<crate::AuthConfig>, String> {
    let mut built: Vec<crate::AuthConfig> = parse_auth_list(conf, name, "ledger-api", auth_cert)?
        .into_iter()
        .map(|(cfg, _)| cfg)
        .collect();
    if built.len() <= 1 {
        Ok(built.pop())
    } else {
        Ok(Some(crate::AuthConfig::multi(built)))
    }
}

/// The authentication of the participant's `admin-api` (`None`: no `auth-services`, every call passes).
fn parse_admin_api_auth(
    conf: &Hocon,
    name: &str,
    auth_cert: Option<&Path>,
) -> Result<Option<crate::admin_api_auth::AdminApiAuth>, String> {
    let services = parse_auth_list(conf, name, "admin-api", auth_cert)?;
    if services.is_empty() {
        return Ok(None);
    }
    let at = |tail: &str| conf.get(&format!("canton.participants.{name}.admin-api.{tail}"));
    Ok(Some(crate::admin_api_auth::AdminApiAuth {
        services: services
            .into_iter()
            .map(
                |(verifier, privileged)| crate::admin_api_auth::AdminAuthService {
                    verifier,
                    privileged,
                },
            )
            .collect(),
        fixed_admin_token: at("admin-token-config.fixed-admin-token").and_then(Hocon::text),
        admin_claim: at("admin-token-config.admin-claim")
            .and_then(Hocon::text)
            .is_some_and(|s| s == "true"),
    }))
}

/// The `auth-services` of the participant's `api` block (`ledger-api` or `admin-api`), each with whether it is privileged (`privileged = true`
/// with a target audience or scope: `AuthServiceJWT.apply`).
fn parse_auth_list(
    conf: &Hocon,
    name: &str,
    api: &str,
    auth_cert: Option<&Path>,
) -> Result<Vec<(crate::AuthConfig, bool)>, String> {
    let at = |tail: &str| conf.get(&format!("canton.participants.{name}.{api}.{tail}"));
    let Some(Hocon::Array(items)) = at("auth-services") else {
        return Ok(Vec::new());
    };
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let max_life = at("max-token-life")
        .and_then(Hocon::text)
        .map(|s| parse_duration_secs(&s))
        .transpose()?;
    let default_leeway = at("jwt-timestamp-leeway.default")
        .and_then(Hocon::text)
        .map(|s| parse_duration_secs(&s))
        .transpose()?
        .unwrap_or(0);
    let iat_leeway = at("jwt-timestamp-leeway.issued-at")
        .and_then(Hocon::text)
        .map(|s| parse_duration_secs(&s))
        .transpose()?;
    let exp_leeway = at("jwt-timestamp-leeway.expires-at")
        .and_then(Hocon::text)
        .map(|s| parse_duration_secs(&s))
        .transpose()?;
    let jwks_cache = parse_jwks_cache_config(conf, name);

    let read_cert = |item: &Hocon, kind: &str| -> Result<String, String> {
        let configured = item.get("certificate").and_then(Hocon::text);
        let path = auth_cert
            .map(Path::to_path_buf)
            .or_else(|| configured.clone().map(std::path::PathBuf::from))
            .ok_or_else(|| format!("the {kind} service names no certificate"))?;
        std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "Cannot read the certificate {} of the {kind} service (the configuration names {}): {e}; give --conf-auth-cert",
                path.display(),
                configured.unwrap_or_default()
            )
        })
    };

    let mut built = Vec::with_capacity(items.len());
    for item in items {
        let kind = item.get("type").and_then(Hocon::text).unwrap_or_default();
        let mut cfg = match kind.as_str() {
            "unsafe-jwt-hmac-256" => {
                let secret = item
                    .get("secret")
                    .and_then(Hocon::text)
                    .filter(|s| !s.is_empty())
                    .ok_or("the unsafe-jwt-hmac-256 service names no secret")?;
                crate::AuthConfig::hmac(&secret)
            }
            "jwt-rs-256-crt" => crate::AuthConfig::rs256_certificate(&read_cert(item, &kind)?)?,
            "jwt-es-256-crt" => crate::AuthConfig::es256_certificate(&read_cert(item, &kind)?)?,
            "jwt-es-512-crt" => crate::AuthConfig::es512_certificate(&read_cert(item, &kind)?)?,
            "jwt-jwks" => {
                let url = item
                    .get("url")
                    .and_then(Hocon::text)
                    .filter(|s| !s.is_empty())
                    .ok_or("the jwt-jwks service names no url")?;
                crate::AuthConfig::jwks(&url, jwks_cache.clone())
            }
            "wildcard" => crate::AuthConfig::wildcard(),
            _ => {
                return Err(format!(
                    "the {api} of {name} has an auth service of type {kind}, which this server does not check"
                ));
            }
        };
        if item.get("users").is_some() {
            return Err(format!(
                "the {api} of {name} has an auth service with `users`, which this server does not check"
            ));
        }
        let audience = item.get("target-audience").and_then(Hocon::text);
        let scope = item.get("target-scope").and_then(Hocon::text);
        let privileged = item
            .get("privileged")
            .and_then(Hocon::text)
            .is_some_and(|s| s == "true")
            && (audience.is_some() || scope.is_some());
        if let Some(audience) = audience {
            cfg = cfg.with_audience(&audience);
        }
        if let Some(scope) = scope {
            cfg = cfg.with_target_scope(&scope);
        }
        if let Some(secs) = max_life {
            cfg.max_lifetime_secs = secs;
        }
        cfg = cfg.with_leeway_config(default_leeway, iat_leeway, exp_leeway);
        cfg = cfg.with_jwks_cache(jwks_cache.clone());
        built.push((cfg, privileged));
    }
    Ok(built)
}
