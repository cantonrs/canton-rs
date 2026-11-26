//! Development-only loopback HS256 JWT issuance and enforcement (`S-DX-007`).
//!
//! [CANTON-NOTE: INVARIANT] Development credentials are strictly restricted to instances whose
//! configured listening addresses are all loopback (`127.0.0.0/8`, `::1`, `localhost`). Any
//! non-loopback bind address disables dev auth mode (`J-A5`) and causes `daemon creds` to fail
//! closed with `exit = 2` (`EXIT_PREFLIGHT`). Raw key bytes from `dev-jwt.key` are never printed,
//! logged, placed on `argv`, or emitted in `status`/`inspect` outputs (`J-A6`).

use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use canton_participant::hocon::{parse_file as parse_hocon_file, Hocon};
use canton_participant::topology_wire::ParticipantIdentity;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Value as Json};

use super::cli::{DaemonCredsArgs, StatusFormatArg};
use super::ipc::{call_unary, resolve_client_state_dir, IpcRequest, IpcResponse};
use super::query::parse_http_url;
use super::registry::resolve_target_state_dir;
use super::snapshot::{atomic_write_0600, read_daemon_recipe, DaemonRecipe};
use super::status::{collect_daemon_status, EndpointState};
use super::{now_unix_secs, DaemonSpec};
use crate::commands::exit_code::{exit_with_message, EXIT_PREFLIGHT};
use crate::commands::json_http;

/// Filename storing the instance-wide 256-bit dev HS256 secret (`0600`).
pub const DEV_JWT_KEY_FILE: &str = "dev-jwt.key";
/// Per-participant file recording the finalized `participantId` (`PAR::<name>::<fp>`).
pub const PARTICIPANT_ID_FILE: &str = "participant-id";
/// Mandatory development warning included in both text and JSON `daemon creds` output.
pub const DEV_JWT_WARNING: &str = "개발용, 운영 사용 금지";
/// Maximum dev token TTL accepted by `daemon creds` (24 hours = `86400`s).
pub const DEV_JWT_MAX_TTL_SECS: i64 = 86_400;
/// Short-lived TTL for auto-signed management CLI dev JWTs (`M-002`).
pub const CLI_AUTO_DEV_JWT_TTL_SECS: i64 = 60;
/// JSON output schema version for `canton-rs daemon creds --format json`.
pub const DEV_CREDS_JSON_SCHEMA: &str = "canton-rs.dev-creds/1";

#[derive(Clone, Debug, Serialize)]
struct DevCredsReport {
    schema: String,
    warning: String,
    instance: String,
    participant: String,
    aud: String,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    party: Option<String>,
    scope: String,
    canton_rs_dev: bool,
    iat: i64,
    exp: i64,
    ttl_secs: i64,
    token: String,
}

/// Returns `true` iff `host` is a loopback address (`127.0.0.0/8`, `::1`, or `localhost`).
pub fn is_loopback_host(host: &str) -> bool {
    ledger_json_api::auth::is_loopback_host(host)
}

/// Extracts the host component from `<host>:<port>`, `[<ipv6>]:<port>`, or bare `<host>`.
pub fn extract_host_from_bind(bind_spec: &str) -> &str {
    let trimmed = bind_spec.trim();
    if let Some(after_open) = trimmed.strip_prefix('[') {
        if let Some((host, _rest)) = after_open.split_once(']') {
            return host.trim();
        }
        return after_open.trim();
    }
    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return host.trim();
        }
    }
    trimmed
}

/// Collects every listening host/bind address configured across `spec`.
pub fn collect_spec_bind_addresses(spec: &DaemonSpec) -> Vec<String> {
    let mut addrs = BTreeSet::new();
    let mut insert = |raw: &str| {
        let host = extract_host_from_bind(raw);
        if !host.is_empty() {
            addrs.insert(host.to_string());
        }
    };

    if spec.metrics_port.is_some_and(|p| p != 0) && !spec.metrics_bind.trim().is_empty() {
        insert(&spec.metrics_bind);
    }

    const BIND_FLAGS: [&str; 6] = [
        "--host",
        "--bind",
        "--public-bind",
        "--admin-bind",
        "--p2p-bind",
        "--metrics-bind",
    ];

    for svc in &spec.services {
        if let Some(ref host) = svc.bind_host {
            insert(host);
        } else {
            insert("127.0.0.1");
        }
        let mut i = 0usize;
        while i < svc.argv.len() {
            let arg = &svc.argv[i];
            if let Some((flag, val)) = arg.split_once('=') {
                if BIND_FLAGS.contains(&flag) {
                    insert(val);
                }
            } else if BIND_FLAGS.contains(&arg.as_str()) {
                if let Some(val) = svc.argv.get(i + 1) {
                    insert(val);
                    i += 1;
                }
            }
            i += 1;
        }
    }

    if let Some(ref conf_path) = spec.canton_conf {
        if let Ok(conf) = parse_hocon_file(conf_path, &|n| std::env::var(n).ok()) {
            collect_hocon_bind_addresses(&conf, &mut addrs);
        }
    }

    addrs.into_iter().collect()
}

fn collect_hocon_bind_addresses(conf: &Hocon, out: &mut BTreeSet<String>) {
    const KEYS: [&str; 4] = [
        "public-api.address",
        "admin-api.address",
        "ledger-api.address",
        "http-ledger-api.address",
    ];
    let Some(canton) = conf.get("canton") else {
        return;
    };
    for path in canton.leaf_paths("canton") {
        if KEYS.iter().any(|suffix| path.ends_with(suffix)) {
            if let Some(addr) = conf.get(&path).and_then(Hocon::text) {
                let host = extract_host_from_bind(&addr);
                if !host.is_empty() {
                    out.insert(host.to_string());
                }
            }
        }
    }
}

/// Returns all unique non-loopback addresses from `addrs`.
pub fn non_loopback_addresses(addrs: &[String]) -> Vec<String> {
    let mut bad = BTreeSet::new();
    for raw in addrs {
        let host = extract_host_from_bind(raw);
        if !is_loopback_host(host) {
            bad.insert(if host.is_empty() {
                "<empty>".to_string()
            } else {
                host.to_string()
            });
        }
    }
    bad.into_iter().collect()
}

/// Generates (on first boot) or validates/reuses `dir(I)/dev-jwt.key` with `0600` permissions.
pub fn ensure_dev_jwt_key(state_dir: &Path) -> Result<PathBuf, String> {
    let path = state_dir.join(DEV_JWT_KEY_FILE);
    if path.is_file() {
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read dev JWT key file {}: {e}", path.display()))?;
        if !raw.trim().is_empty() {
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot chmod 0600 {}: {e}", path.display()))?;
            return Ok(path);
        }
    }
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let hex_key = hex::encode(secret_bytes);
    atomic_write_0600(&path, format!("{hex_key}\n").as_bytes())?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot chmod 0600 {}: {e}", path.display()))?;
    Ok(path)
}

/// Reads the 256-bit dev secret from `dir(I)/dev-jwt.key` without exposing secret bytes in errors.
pub fn read_dev_jwt_key(state_dir: &Path) -> Result<String, String> {
    let path = state_dir.join(DEV_JWT_KEY_FILE);
    let raw = fs::read_to_string(&path).map_err(|e| {
        format!(
            "dev JWT key file {} is missing or unreadable (start instance on loopback first): {e}",
            path.display()
        )
    })?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err(format!("dev JWT key file {} is empty", path.display()));
    }
    Ok(key)
}

/// Parses `--ttl` (`<N>s`, `<N>m`, `<N>h`, `<N>d`, or `<N>` seconds) into positive seconds.
pub fn parse_ttl_secs(raw: &str) -> Result<i64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty --ttl value".to_string());
    }
    let (num_str, mult) = if let Some(v) = trimmed.strip_suffix('s') {
        (v, 1i64)
    } else if let Some(v) = trimmed.strip_suffix('m') {
        (v, 60i64)
    } else if let Some(v) = trimmed.strip_suffix('h') {
        (v, 3_600i64)
    } else if let Some(v) = trimmed.strip_suffix('d') {
        (v, 86_400i64)
    } else {
        (trimmed, 1i64)
    };
    let count: i64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid --ttl duration '{raw}' (expected e.g. 1s, 15m, 1h)"))?;
    if count <= 0 {
        return Err(format!("--ttl must be positive, got '{raw}'"));
    }
    let secs = count
        .checked_mul(mult)
        .ok_or_else(|| format!("--ttl '{raw}' overflows"))?;
    if secs > DEV_JWT_MAX_TTL_SECS {
        return Err(format!(
            "--ttl '{raw}' exceeds maximum dev lifetime ({DEV_JWT_MAX_TTL_SECS}s)"
        ));
    }
    Ok(secs)
}

/// Signs a development HS256 JWT targeting `participant_id` with `J-01..J-04` required claims.
pub fn sign_dev_jwt(
    secret: &str,
    participant_id: &str,
    user: &str,
    party: Option<&str>,
    ttl_secs: i64,
    now_secs: i64,
) -> (String, i64, i64) {
    let exp = now_secs.saturating_add(ttl_secs);
    let mut claims = json!({
        "aud": participant_id,
        "sub": user,
        "iat": now_secs,
        "exp": exp,
        "scope": "daml_ledger_api",
        "canton_rs_dev": true,
    });
    if let Some(p) = party.filter(|s| !s.trim().is_empty()) {
        claims["party"] = Json::String(p.to_string());
    }
    let token = ledger_json_api::auth::sign_token(secret, &claims);
    (token, now_secs, exp)
}

/// Mints a short-lived `participant_admin` bearer token in memory for supervisor internal probes.
pub fn mint_supervisor_probe_token(key_file: &Path, participant_id_file: &Path) -> Option<String> {
    let secret = fs::read_to_string(key_file).ok()?;
    let secret = secret.trim();
    if secret.is_empty() {
        return None;
    }
    let participant_id = read_participant_id_from_files(participant_id_file)?;
    let now = now_unix_secs() as i64;
    let (token, _, _) = sign_dev_jwt(secret, &participant_id, "participant_admin", None, 60, now);
    Some(token)
}

fn read_participant_id_from_files(participant_id_file: &Path) -> Option<String> {
    if let Ok(raw) = fs::read_to_string(participant_id_file) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let identity_file = participant_id_file.parent()?.join("identity");
    let raw = fs::read_to_string(identity_file).ok()?;
    ParticipantIdentity::from_text(&raw).map(|id| id.uid())
}

/// Resolves the target participant's canonical ID (`PAR::<name>::<fp>`).
pub fn resolve_participant_id(
    state_dir: &Path,
    svc_state_rel: &str,
    http_url: Option<&str>,
) -> Result<String, String> {
    let svc_dir = state_dir.join(svc_state_rel);
    if let Some(pid) = read_participant_id_from_files(&svc_dir.join(PARTICIPANT_ID_FILE)) {
        return Ok(pid);
    }
    if let Some(url) = http_url {
        if let Ok(target) = parse_http_url(url) {
            if let Ok((200, json)) = json_http::call(
                &target.host,
                target.port,
                "GET",
                "/v2/parties/participant-id",
                None,
            ) {
                if let Some(pid) = json["participantId"].as_str().filter(|s| !s.is_empty()) {
                    return Ok(pid.to_string());
                }
            }
        }
    }
    Err(format!(
        "cannot resolve participant ID under {} (start participant first)",
        svc_dir.display()
    ))
}

fn collect_recipe_bind_addresses(state_dir: &Path, recipe: &DaemonRecipe) -> Vec<String> {
    let mut set = BTreeSet::new();
    for addr in &recipe.bind_addresses {
        let h = extract_host_from_bind(addr);
        if !h.is_empty() {
            set.insert(h.to_string());
        }
    }
    if !recipe.bind.trim().is_empty() {
        set.insert(extract_host_from_bind(&recipe.bind).to_string());
    }
    if recipe.metrics_port.is_some_and(|p| p != 0) && !recipe.metrics_bind.trim().is_empty() {
        set.insert(extract_host_from_bind(&recipe.metrics_bind).to_string());
    }
    if let Ok(IpcResponse::Snapshot { snapshot, .. }) =
        call_unary(state_dir, &IpcRequest::GetSnapshot)
    {
        if snapshot.metrics_port.is_some_and(|p| p != 0) {
            if let Some(ref mb) = snapshot.metrics_bind {
                let h = extract_host_from_bind(mb);
                if !h.is_empty() {
                    set.insert(h.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

fn ensure_party_user_rights(
    http_url: &str,
    admin_token: &str,
    user: &str,
    party: Option<&str>,
) -> Result<(), String> {
    let target = parse_http_url(http_url)?;
    let encoded_user: String = user
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect();
    let get_path = format!("/v2/users/{encoded_user}");
    let (status, _) = json_http::call_with_token(
        &target.host,
        target.port,
        "GET",
        &get_path,
        None,
        Some(admin_token),
    )?;
    let rights: Vec<Json> = party
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            vec![
                json!({ "kind": { "CanActAs": { "value": { "party": p } } } }),
                json!({ "kind": { "CanReadAs": { "value": { "party": p } } } }),
            ]
        })
        .unwrap_or_default();

    if status == 404 {
        let create_body = json!({
            "user": {
                "id": user,
                "primaryParty": party.unwrap_or(""),
            },
            "rights": rights,
        });
        let raw = create_body.to_string();
        let (st, body) = json_http::call_with_token(
            &target.host,
            target.port,
            "POST",
            "/v2/users",
            Some((raw.as_bytes(), "application/json")),
            Some(admin_token),
        )?;
        if st >= 300 {
            return Err(format!(
                "POST /v2/users for '{user}' returned HTTP {st}: {}",
                json_http::error_cause(&body)
            ));
        }
    } else if status == 200 && !rights.is_empty() {
        let grant_body = json!({
            "userId": user,
            "rights": rights,
        });
        let raw = grant_body.to_string();
        let grant_path = format!("/v2/users/{encoded_user}/rights");
        let (st, body) = json_http::call_with_token(
            &target.host,
            target.port,
            "POST",
            &grant_path,
            Some((raw.as_bytes(), "application/json")),
            Some(admin_token),
        )?;
        if st >= 300 {
            return Err(format!(
                "POST {grant_path} returned HTTP {st}: {}",
                json_http::error_cause(&body)
            ));
        }
    }
    Ok(())
}

/// Development JWT pair (`user_token` for the requested user, `admin_token` for `participant_admin`).
pub(crate) struct DevAuthTokens {
    pub user_token: String,
    pub admin_token: String,
}

/// Explicit bearer token flags shared by management CLI subcommands (`M-002`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ExplicitTokenArgs<'a> {
    pub token_env: Option<&'a str>,
    pub token_file: Option<&'a Path>,
}

/// Resolved bearer token for a management CLI call, tracking whether it was auto-signed via `--dev-auth`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedCliAuth {
    pub token: String,
    pub is_dev_auto_signed: bool,
}

/// Connection parameters used to resolve explicit or loopback dev-JWT auth for management CLIs (`M-002`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct CliAuthTarget<'a> {
    pub url: Option<&'a str>,
    pub name: Option<&'a str>,
    pub state_dir: Option<&'a Path>,
    pub participant: Option<&'a str>,
    pub target_host: &'a str,
    pub target_base_url: &'a str,
    pub explicit: ExplicitTokenArgs<'a>,
}

fn validate_bearer_token(raw: &str, origin: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("{origin} is empty"),
        ));
    }
    if trimmed
        .as_bytes()
        .iter()
        .any(|&b| matches!(b, b'\r' | b'\n' | 0))
    {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("{origin} contains forbidden CR/LF/NUL control characters"),
        ));
    }
    Ok(trimmed.to_string())
}

/// Reads an explicit bearer token from `--token-env` or `--token-file`, failing closed on missing/empty inputs.
pub(crate) fn resolve_explicit_token(
    args: &ExplicitTokenArgs<'_>,
) -> Result<Option<String>, String> {
    match (args.token_env, args.token_file) {
        (Some(_), Some(_)) => Err(exit_with_message(
            EXIT_PREFLIGHT,
            "give either '--token-env' or '--token-file', not both",
        )),
        (Some(var), None) => {
            let val = std::env::var(var).map_err(|_| {
                exit_with_message(
                    EXIT_PREFLIGHT,
                    format!("environment variable '{var}' for --token-env is not set"),
                )
            })?;
            validate_bearer_token(&val, &format!("--token-env {var}")).map(Some)
        }
        (None, Some(path)) => {
            let raw = fs::read_to_string(path).map_err(|e| {
                exit_with_message(
                    EXIT_PREFLIGHT,
                    format!("cannot read --token-file '{}': {e}", path.display()),
                )
            })?;
            validate_bearer_token(&raw, &format!("--token-file '{}'", path.display())).map(Some)
        }
        (None, None) => Ok(None),
    }
}

/// Extracts the unverified `sub` claim from a JWT string when present (used to align request `userId`).
pub(crate) fn jwt_subject_unverified(token: &str) -> Option<String> {
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = decode_base64url_no_pad(payload_b64)?;
    let claims: Json = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("sub")
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

fn decode_base64url_no_pad(input: &str) -> Option<Vec<u8>> {
    let val = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None,
        }
    };
    let trimmed = input.trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut idx = 0usize;
    while idx < bytes.len() {
        let rem = bytes.len() - idx;
        if rem == 1 {
            return None;
        }
        let a = u32::from(val(bytes[idx])?);
        let b = u32::from(val(bytes[idx + 1])?);
        out.push(((a << 2) | (b >> 4)) as u8);
        if rem >= 3 {
            let c = u32::from(val(bytes[idx + 2])?);
            out.push((((b & 0x0f) << 4) | (c >> 2)) as u8);
            if rem >= 4 {
                let d = u32::from(val(bytes[idx + 3])?);
                out.push((((c & 0x03) << 6) | d) as u8);
            }
        }
        idx += 4;
    }
    Some(out)
}

/// Grants `CanActAs`/`CanReadAs` (for `party`) and/or `CanReadAsAnyParty` on `participant_admin`
/// using an auto-signed `--dev-auth` admin JWT.
pub(crate) fn ensure_dev_admin_rights(
    http_url: &str,
    admin_token: &str,
    party: Option<&str>,
    read_any_party: bool,
) -> Result<(), String> {
    let mut rights: Vec<Json> = Vec::new();
    if let Some(p) = party.map(str::trim).filter(|s| !s.is_empty()) {
        rights.push(json!({ "kind": { "CanActAs": { "value": { "party": p } } } }));
        rights.push(json!({ "kind": { "CanReadAs": { "value": { "party": p } } } }));
    }
    if read_any_party {
        rights.push(json!({ "kind": { "CanReadAsAnyParty": { "value": {} } } }));
    }
    if rights.is_empty() {
        return Ok(());
    }
    let target = parse_http_url(http_url)?;
    let grant_body = json!({
        "userId": "participant_admin",
        "rights": rights,
    });
    let raw = grant_body.to_string();
    let (st, body) = json_http::call_with_token(
        &target.host,
        target.port,
        "POST",
        "/v2/users/participant_admin/rights",
        Some((raw.as_bytes(), "application/json")),
        Some(admin_token),
    )?;
    if st >= 300 {
        return Err(format!(
            "POST /v2/users/participant_admin/rights returned HTTP {st}: {}",
            json_http::error_cause(&body)
        ));
    }
    Ok(())
}

/// Signs a short-lived `S-DX-007` dev JWT from `dir/dev-jwt.key` when dev-auth is configured.
pub(crate) fn resolve_dev_auth_token_for_dir(
    dir: &Path,
    participant: Option<&str>,
    user: &str,
    live_http_url: Option<&str>,
    ttl_secs: i64,
) -> Result<Option<DevAuthTokens>, String> {
    let key_path = dir.join(DEV_JWT_KEY_FILE);
    if !key_path.is_file() {
        return Ok(None);
    }
    let recipe = read_daemon_recipe(dir)?;
    let addrs = collect_recipe_bind_addresses(dir, &recipe);
    let bad = non_loopback_addresses(&addrs);
    if !bad.is_empty() {
        return Err(format!(
            "refusing to use dev JWT: instance '{}' listens on non-loopback address(es): {}",
            recipe.instance_name,
            bad.join(", ")
        ));
    }
    let secret = read_dev_jwt_key(dir)?;
    let participants: Vec<_> = recipe
        .services
        .iter()
        .filter(|s| s.role == "participant")
        .collect();
    if participants.is_empty() {
        return Err(format!(
            "instance '{}' defines no participant services",
            recipe.instance_name
        ));
    }
    let target_svc = if let Some(wanted) = participant {
        participants
            .iter()
            .copied()
            .find(|s| s.name == wanted)
            .ok_or_else(|| {
                format!(
                    "participant '{wanted}' not found in instance '{}'",
                    recipe.instance_name
                )
            })?
    } else {
        participants[0]
    };
    let participant_id = resolve_participant_id(dir, &target_svc.state_dir_rel, live_http_url)?;
    let now = now_unix_secs() as i64;
    let (user_token, _, _) = sign_dev_jwt(&secret, &participant_id, user, None, ttl_secs, now);
    let admin_token = if user == "participant_admin" {
        user_token.clone()
    } else {
        let (tok, _, _) = sign_dev_jwt(
            &secret,
            &participant_id,
            "participant_admin",
            None,
            ttl_secs,
            now,
        );
        tok
    };
    Ok(Some(DevAuthTokens {
        user_token,
        admin_token,
    }))
}

/// Resolves bearer auth for management CLIs (`M-002`):
/// 1. Explicit `--token-env` / `--token-file` always takes precedence (never auto-signs).
/// 2. Non-loopback target hosts NEVER auto-sign `dev-jwt.key`.
/// 3. Explicit `--url` without `--name`/`--state-dir` never reads unrelated default `dev-jwt.key`.
/// 4. Otherwise auto-signs a short-lived (`60s`) `participant_admin` HS256 JWT when `<state_dir>/dev-jwt.key` exists.
pub(crate) fn resolve_cli_auth(
    target: &CliAuthTarget<'_>,
) -> Result<Option<ResolvedCliAuth>, String> {
    if let Some(tok) = resolve_explicit_token(&target.explicit)? {
        return Ok(Some(ResolvedCliAuth {
            token: tok,
            is_dev_auto_signed: false,
        }));
    }
    // [CANTON-NOTE: INVARIANT] Never auto-sign dev-jwt.key for any non-loopback target host,
    // even when --state-dir or a local instance directory contains dev-jwt.key (M-002 / S-DX-007).
    if !is_loopback_host(target.target_host) {
        return Ok(None);
    }
    if target.url.is_some() && target.name.is_none() && target.state_dir.is_none() {
        return Ok(None);
    }
    let raw_dir = resolve_target_state_dir(target.name, target.state_dir)?;
    let eff_dir = if target.name.is_none() && target.state_dir.is_none() {
        resolve_client_state_dir(&raw_dir)
    } else {
        raw_dir
    };
    let tokens = resolve_dev_auth_token_for_dir(
        &eff_dir,
        target.participant,
        "participant_admin",
        Some(target.target_base_url),
        CLI_AUTO_DEV_JWT_TTL_SECS,
    )
    .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    Ok(tokens.map(|t| ResolvedCliAuth {
        token: t.admin_token,
        is_dev_auto_signed: true,
    }))
}

/// Signs a short-lived `S-DX-007` dev JWT for `state_dir` when dev-auth is configured (`dev-jwt.key` present).
pub(crate) fn resolve_dev_auth_token(
    name: Option<&str>,
    state_dir: Option<&Path>,
    participant: Option<&str>,
    user: &str,
    live_http_url: Option<&str>,
) -> Result<Option<DevAuthTokens>, String> {
    let raw_dir = resolve_target_state_dir(name, state_dir)?;
    let dir = if name.is_none() && state_dir.is_none() {
        resolve_client_state_dir(&raw_dir)
    } else {
        raw_dir
    };
    resolve_dev_auth_token_for_dir(&dir, participant, user, live_http_url, 300)
}

pub fn cmd_daemon_creds(args: DaemonCredsArgs) -> Result<(), String> {
    let state_dir = resolve_target_state_dir(args.name.as_deref(), args.state_dir.as_deref())
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let recipe =
        read_daemon_recipe(&state_dir).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;

    let addrs = collect_recipe_bind_addresses(&state_dir, &recipe);
    let bad = non_loopback_addresses(&addrs);
    if !bad.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "refusing to issue dev JWT: instance '{}' listens on non-loopback address(es): {}",
                recipe.instance_name,
                bad.join(", ")
            ),
        ));
    }

    let ttl_secs = parse_ttl_secs(&args.ttl).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let user = args.user.trim();
    if user.is_empty() {
        return Err(exit_with_message(EXIT_PREFLIGHT, "--user cannot be empty"));
    }

    let secret = read_dev_jwt_key(&state_dir).map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;

    let participants: Vec<_> = recipe
        .services
        .iter()
        .filter(|s| s.role == "participant")
        .collect();
    if participants.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "instance '{}' defines no participant services",
                recipe.instance_name
            ),
        ));
    }
    let target_svc = if let Some(ref wanted) = args.participant {
        participants
            .iter()
            .copied()
            .find(|s| &s.name == wanted)
            .ok_or_else(|| {
                exit_with_message(
                    EXIT_PREFLIGHT,
                    format!(
                        "participant '{wanted}' not found in instance '{}'",
                        recipe.instance_name
                    ),
                )
            })?
    } else {
        participants[0]
    };

    let live_http_url = collect_daemon_status(&state_dir).ok().and_then(|report| {
        report
            .endpoints
            .get(&format!("{}.json", target_svc.name))
            .filter(|ep| ep.state == EndpointState::Up)
            .map(|ep| ep.url.clone())
    });

    let participant_id = resolve_participant_id(
        &state_dir,
        &target_svc.state_dir_rel,
        live_http_url.as_deref(),
    )
    .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;

    let now = now_unix_secs() as i64;
    if let Some(ref url) = live_http_url {
        if user != "participant_admin" || args.party.is_some() {
            let (admin_tok, _, _) =
                sign_dev_jwt(&secret, &participant_id, "participant_admin", None, 60, now);
            ensure_party_user_rights(url, &admin_tok, user, args.party.as_deref())
                .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
        }
    }

    let (token, iat, exp) = sign_dev_jwt(
        &secret,
        &participant_id,
        user,
        args.party.as_deref(),
        ttl_secs,
        now,
    );

    let report = DevCredsReport {
        schema: DEV_CREDS_JSON_SCHEMA.to_string(),
        warning: format!("{DEV_JWT_WARNING} (development only — do NOT use in production)"),
        instance: recipe.instance_name.clone(),
        participant: target_svc.name.clone(),
        aud: participant_id,
        sub: user.to_string(),
        party: args.party.clone(),
        scope: "daml_ledger_api".to_string(),
        canton_rs_dev: true,
        iat,
        exp,
        ttl_secs,
        token,
    };

    match args.format {
        StatusFormatArg::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            println!("WARNING: {}", report.warning);
            println!("instance:    {}", report.instance);
            println!("participant: {} (aud={})", report.participant, report.aud);
            println!("sub:         {}", report.sub);
            if let Some(ref p) = report.party {
                println!("party:       {p}");
            }
            println!("exp:         {} (ttl={}s)", report.exp, report.ttl_secs);
            println!("token:       {}", report.token);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_json_api::auth::{verify_hmac_claims, AuthConfig};

    #[test]
    fn loopback_host_classification() {
        for ok in [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "[::1]",
            "localhost",
            "LOCALHOST",
            " 127.0.0.1 ",
        ] {
            assert!(is_loopback_host(ok), "expected loopback for {ok:?}");
        }
        for bad in [
            "0.0.0.0",
            "::",
            "[::]",
            "192.168.1.5",
            "10.0.0.1",
            "fe80::1",
            "example.com",
            "",
            "   ",
        ] {
            assert!(!is_loopback_host(bad), "expected non-loopback for {bad:?}");
        }
        assert_eq!(extract_host_from_bind("[::1]:5018"), "::1");
        assert_eq!(extract_host_from_bind("0.0.0.0:7575"), "0.0.0.0");
        assert_eq!(
            non_loopback_addresses(&["127.0.0.1".into(), "0.0.0.0:7575".into()]),
            vec!["0.0.0.0".to_string()]
        );
    }

    #[test]
    fn ttl_parsing_and_bounds() {
        assert_eq!(parse_ttl_secs("1s"), Ok(1));
        assert_eq!(parse_ttl_secs("5m"), Ok(300));
        assert_eq!(parse_ttl_secs("1h"), Ok(3600));
        assert_eq!(parse_ttl_secs("24h"), Ok(86_400));
        assert_eq!(parse_ttl_secs("1d"), Ok(86_400));
        assert_eq!(parse_ttl_secs("42"), Ok(42));

        assert!(parse_ttl_secs("").is_err());
        assert!(parse_ttl_secs("0s").is_err());
        assert!(parse_ttl_secs("-5s").is_err());
        assert!(parse_ttl_secs("25h").is_err());
        assert!(parse_ttl_secs("abc").is_err());
    }

    #[test]
    fn dev_jwt_key_generation_permissions_and_stability() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let root = std::env::temp_dir().join(format!("crs-dev-jwt-key-test-{nanos}"));
        let dir_a = root.join("a");
        let dir_b = root.join("b");
        fs::create_dir_all(&dir_a).expect("mkdir a");
        fs::create_dir_all(&dir_b).expect("mkdir b");

        let p1 = ensure_dev_jwt_key(&dir_a).expect("key a");
        #[cfg(unix)]
        {
            let mode = fs::metadata(&p1).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let s1 = read_dev_jwt_key(&dir_a).expect("read a");
        assert_eq!(s1.len(), 64);
        assert!(s1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

        // Idempotent across restarts
        let _p1_again = ensure_dev_jwt_key(&dir_a).expect("key a reuse");
        assert_eq!(read_dev_jwt_key(&dir_a).expect("read a2"), s1);

        // Distinct across instances
        let _p2 = ensure_dev_jwt_key(&dir_b).expect("key b");
        assert_ne!(read_dev_jwt_key(&dir_b).expect("read b"), s1);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn dev_jwt_axioms_j_a1_through_j_a4() {
        let now = now_unix_secs() as i64;
        let pid_a = "PAR::p1::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let pid_b = "PAR::p1::1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let secret_a = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret_b = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let mut cfg_a = AuthConfig::hmac(secret_a).with_audience(pid_a);
        cfg_a.max_lifetime_secs = DEV_JWT_MAX_TTL_SECS;
        let mut cfg_b_same_secret = AuthConfig::hmac(secret_a).with_audience(pid_b);
        cfg_b_same_secret.max_lifetime_secs = DEV_JWT_MAX_TTL_SECS;
        let mut cfg_b_diff_secret = AuthConfig::hmac(secret_b).with_audience(pid_b);
        cfg_b_diff_secret.max_lifetime_secs = DEV_JWT_MAX_TTL_SECS;

        // J-A1: valid token succeeds with required claims
        let (tok, iat, exp) = sign_dev_jwt(secret_a, pid_a, "participant_admin", None, 300, now);
        assert_eq!(exp, iat + 300);
        let claims = verify_hmac_claims(&cfg_a, &tok).expect("J-A1 verify");
        assert_eq!(claims["aud"], pid_a);
        assert_eq!(claims["sub"], "participant_admin");
        assert_eq!(claims["scope"], "daml_ledger_api");
        assert_eq!(claims["canton_rs_dev"], true);
        assert!(DEV_JWT_WARNING.contains("개발용, 운영 사용 금지"));

        // J-A2: wrong instance rejected both with different secret AND same secret / different aud
        assert_eq!(verify_hmac_claims(&cfg_b_diff_secret, &tok), Err(401));
        assert_eq!(verify_hmac_claims(&cfg_b_same_secret, &tok), Err(401));

        // J-A3: expired token (now >= exp) rejected
        let (expired_tok, _, _) =
            sign_dev_jwt(secret_a, pid_a, "participant_admin", None, 1, now - 2);
        assert_eq!(verify_hmac_claims(&cfg_a, &expired_tok), Err(401));

        // J-A4: payload tamper and signature tamper both rejected
        let mut parts: Vec<String> = tok.split('.').map(String::from).collect();
        let mutated_payload = json!({
            "aud": pid_a,
            "sub": "other_user",
            "iat": iat,
            "exp": exp,
            "scope": "daml_ledger_api",
            "canton_rs_dev": true,
        })
        .to_string();
        parts[1] = base64url_no_pad(mutated_payload.as_bytes());
        assert_eq!(verify_hmac_claims(&cfg_a, &parts.join(".")), Err(401));

        let mut sig_tampered: Vec<String> = tok.split('.').map(String::from).collect();
        let mut sig_bytes = sig_tampered[2].as_bytes().to_vec();
        sig_bytes[0] = if sig_bytes[0] == b'A' { b'B' } else { b'A' };
        sig_tampered[2] = String::from_utf8(sig_bytes).expect("ascii");
        assert_eq!(
            verify_hmac_claims(&cfg_a, &sig_tampered.join(".")),
            Err(401)
        );
    }

    #[test]
    fn cli_auth_loopback_auto_sign_explicit_override_and_non_loopback_guard() {
        use super::super::snapshot::{DaemonRecipe, SnapshotServiceInfo, RECIPE_FILE};

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let root = std::env::temp_dir().join(format!("crs-m002-cli-auth-{nanos}"));
        let svc_dir = root.join("participant1");
        fs::create_dir_all(&svc_dir).expect("mkdir svc");

        let _ = ensure_dev_jwt_key(&root).expect("write dev-jwt.key");
        let secret = read_dev_jwt_key(&root).expect("read secret");
        let pid = "PAR::participant1::1220cccccccccccccccccccccccccccccccc";
        fs::write(svc_dir.join(PARTICIPANT_ID_FILE), format!("{pid}\n")).expect("write pid");

        let recipe = DaemonRecipe {
            schema: "canton-rs.daemon-recipe/1".to_string(),
            mode: "mode_a".to_string(),
            manifest_file: "manifest.yaml".to_string(),
            canton_conf_file: None,
            bootstrap_file: None,
            launch_cwd: root.clone(),
            instance_name: "m002-unit".to_string(),
            port_offset: 0,
            pg_url: None,
            pg_schema: None,
            state_in_files: true,
            metrics_port: None,
            metrics_bind: "127.0.0.1".to_string(),
            profile: Vec::new(),
            group: Vec::new(),
            dar: None,
            xray: false,
            no_restart: false,
            strict_config: false,
            same_identity: false,
            official_write: false,
            official_pg_addr: None,
            conf_auth_cert: None,
            token_env: None,
            token_file: None,
            log_encoder: "text".to_string(),
            dev_auth: true,
            observability: false,
            bind: "127.0.0.1".to_string(),
            bind_addresses: vec!["127.0.0.1".to_string()],
            services: vec![SnapshotServiceInfo {
                name: "participant1".to_string(),
                role: "participant".to_string(),
                state_dir_rel: "participant1".to_string(),
                storage_kind: "files".to_string(),
                state_name: None,
                has_bft_group: false,
                synchronizer: "sync".to_string(),
            }],
        };
        let recipe_bytes = serde_json::to_vec_pretty(&recipe).expect("ser recipe");
        fs::write(root.join(RECIPE_FILE), recipe_bytes).expect("write recipe");

        // 1. Loopback target with state_dir auto-signs a short-lived 60s participant_admin JWT.
        let auto = resolve_cli_auth(&CliAuthTarget {
            url: None,
            name: None,
            state_dir: Some(&root),
            participant: Some("participant1"),
            target_host: "127.0.0.1",
            target_base_url: "http://127.0.0.1:7575",
            explicit: ExplicitTokenArgs::default(),
        })
        .expect("loopback auto-sign ok")
        .expect("should produce auto-signed token");
        assert!(auto.is_dev_auto_signed);
        assert_eq!(
            jwt_subject_unverified(&auto.token).as_deref(),
            Some("participant_admin")
        );
        let mut cfg = AuthConfig::hmac(&secret).with_audience(pid);
        cfg.max_lifetime_secs = DEV_JWT_MAX_TTL_SECS;
        let claims = verify_hmac_claims(&cfg, &auto.token).expect("valid HS256 JWT");
        assert_eq!(claims["sub"], "participant_admin");
        assert_eq!(
            claims["exp"].as_i64().unwrap_or(0) - claims["iat"].as_i64().unwrap_or(0),
            CLI_AUTO_DEV_JWT_TTL_SECS
        );

        // 2. Negative control: non-loopback --url NEVER auto-signs, even when state_dir has dev-jwt.key!
        for remote in [
            ("192.168.1.50", "http://192.168.1.50:7575"),
            ("example.com", "http://example.com:7575"),
            ("10.0.0.9", "http://10.0.0.9:7575"),
        ] {
            let res = resolve_cli_auth(&CliAuthTarget {
                url: Some(remote.1),
                name: None,
                state_dir: Some(&root),
                participant: Some("participant1"),
                target_host: remote.0,
                target_base_url: remote.1,
                explicit: ExplicitTokenArgs::default(),
            })
            .expect("non-loopback returns Ok(None)");
            assert!(
                res.is_none(),
                "must NEVER auto-sign dev-jwt.key for non-loopback target {}",
                remote.1
            );
        }

        // 3. Explicit --url on loopback without --name/--state-dir does not auto-sign.
        let bare_url = resolve_cli_auth(&CliAuthTarget {
            url: Some("http://127.0.0.1:7575"),
            name: None,
            state_dir: None,
            participant: None,
            target_host: "127.0.0.1",
            target_base_url: "http://127.0.0.1:7575",
            explicit: ExplicitTokenArgs::default(),
        })
        .expect("bare loopback url ok");
        assert!(bare_url.is_none());

        // 4. Explicit --token-file overrides auto-signing (and works for non-loopback too).
        let tok_file = root.join("explicit.tok");
        fs::write(&tok_file, "  explicit-file-token  \n").expect("write token file");
        let from_file = resolve_cli_auth(&CliAuthTarget {
            url: Some("http://example.com:7575"),
            name: None,
            state_dir: Some(&root),
            participant: Some("participant1"),
            target_host: "example.com",
            target_base_url: "http://example.com:7575",
            explicit: ExplicitTokenArgs {
                token_env: None,
                token_file: Some(&tok_file),
            },
        })
        .expect("token_file ok")
        .expect("explicit token present");
        assert_eq!(from_file.token, "explicit-file-token");
        assert!(!from_file.is_dev_auto_signed);

        // 5. Explicit --token-env overrides auto-signing, and unset env var fails closed.
        let env_key = format!("CANTON_RS_M002_TEST_TOK_{nanos}");
        std::env::set_var(&env_key, "explicit-env-token");
        let from_env = resolve_cli_auth(&CliAuthTarget {
            url: None,
            name: None,
            state_dir: Some(&root),
            participant: Some("participant1"),
            target_host: "127.0.0.1",
            target_base_url: "http://127.0.0.1:7575",
            explicit: ExplicitTokenArgs {
                token_env: Some(&env_key),
                token_file: None,
            },
        })
        .expect("token_env ok")
        .expect("explicit env token");
        std::env::remove_var(&env_key);
        assert_eq!(from_env.token, "explicit-env-token");
        assert!(!from_env.is_dev_auto_signed);

        let missing_env = resolve_explicit_token(&ExplicitTokenArgs {
            token_env: Some("CANTON_RS_M002_UNSET_VAR_XYZ"),
            token_file: None,
        });
        assert!(missing_env.is_err(), "unset --token-env must fail closed");

        let _ = fs::remove_dir_all(&root);
    }

    fn base64url_no_pad(data: &[u8]) -> String {
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            out.push(B64[(n >> 18) as usize & 63] as char);
            out.push(B64[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(B64[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(B64[n as usize & 63] as char);
            }
        }
        out
    }
}
