//! S-API-015: JWT authentication and the rights-based authorization of the Ledger API (HMAC-SHA256 tokens, the
//! `unsafe-jwt-hmac-256` auth service of Canton), checked against a Canton 3.7.2 sandbox started with that service.
//!
//! [CANTON-NOTE: SEMANTICS] A token is accepted when its signature verifies (HS256 with the shared secret), it has an `exp` in
//! the future that is at most the maximum lifetime away (the sandbox default is 5 minutes), a `sub`, and the Ledger API scope
//! `daml_ledger_api`. Failing any of that is `401` / gRPC `UNAUTHENTICATED`. A valid token whose user does not exist, or whose
//! user lacks the right a call needs, is `403` / `PERMISSION_DENIED`; both carry Canton's generic "security-sensitive" error
//! body (nothing reveals why). The rights are the user's rights from the user store: `ParticipantAdmin` for management calls,
//! `CanActAs` for the parties a command acts as, `CanReadAs`/`CanActAs`/`CanReadAsAnyParty` for the parties a read names.
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use crate::auth_jwks::{
    parse_certificate_pem, verify_jwt_signature, CertKind, JwksCache, JwksCacheConfig, VerifiedKey,
};
use crate::http::{HttpRequest, HttpResponse};
use crate::service::ExecutionService;

#[derive(Clone, Debug)]
pub(crate) enum AuthMode {
    Legacy,
    Key(VerifiedKey),
    Jwks { url: String },
    Wildcard,
    Multi(Vec<AuthConfig>),
}

/// How a token is checked: the HMAC secret, certificate/JWKS key source, and claim bounds.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub secret: Vec<u8>,
    pub max_lifetime_secs: i64,
    /// `target-audience`: when set, a token must name it in `aud` (audience-based tokens); when not, tokens are scope-based.
    pub audience: Option<String>,
    /// `jwt-timestamp-leeway.default`: seconds of clock skew tolerated for `exp`, `nbf` and `iat`.
    pub leeway_secs: i64,
    /// The RSA public key (DER `RSAPublicKey`) of the certificate of a `jwt-rs-256-crt` auth service: tokens are then RS256, not HS256.
    pub rsa_public_key: Option<Vec<u8>>,
    /// `target-scope`: overrides the required `scope` entry when `audience` is unset (default: `"daml_ledger_api"`).
    pub target_scope: Option<String>,
    /// Optional per-claim clock-skew override for `iat` (`jwt-timestamp-leeway.issued-at`).
    pub issued_at_leeway_secs: Option<i64>,
    /// Optional per-claim clock-skew override for `exp` (`jwt-timestamp-leeway.expires-at`).
    pub expires_at_leeway_secs: Option<i64>,
    pub(crate) jwks_cache: JwksCache,
    pub(crate) mode: AuthMode,
}

impl AuthConfig {
    pub fn hmac(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(JwksCacheConfig::default()),
            mode: AuthMode::Legacy,
        }
    }

    /// An auth service that checks RS256 tokens against the certificate `pem` (`jwt-rs-256-crt`: `auth-services = [{ type = jwt-rs-256-crt,
    /// certificate = ... }]` of a participant's Ledger API). [CANTON-NOTE: SEMANTICS] The lifetime limit stays the node's default of 300 seconds
    /// (measured on the 3.7.2 hub: `exp` 299 and 300 seconds ahead are accepted, 301 is not; a token without `exp`, with a past `exp` or with a future
    /// `nbf` is refused, and an `iat` does not extend the limit).
    pub fn rs256_certificate(pem: &str) -> Result<Self, String> {
        Ok(Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: Some(rsa_public_key_of_certificate(pem)?),
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(JwksCacheConfig::default()),
            mode: AuthMode::Legacy,
        })
    }

    /// An auth service that checks ES256 tokens against a P-256 X.509 PEM certificate (`jwt-es-256-crt`).
    pub fn es256_certificate(pem: &str) -> Result<Self, String> {
        let key = parse_certificate_pem(pem, CertKind::Es256)?;
        Ok(Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(JwksCacheConfig::default()),
            mode: AuthMode::Key(key),
        })
    }

    /// An auth service that checks ES512 tokens against a P-521 X.509 PEM certificate (`jwt-es-512-crt`).
    pub fn es512_certificate(pem: &str) -> Result<Self, String> {
        let key = parse_certificate_pem(pem, CertKind::Es512)?;
        Ok(Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(JwksCacheConfig::default()),
            mode: AuthMode::Key(key),
        })
    }

    /// An auth service that fetches signing keys from a JWKS endpoint (`jwt-jwks`).
    pub fn jwks(url: &str, cache_config: JwksCacheConfig) -> Self {
        Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(cache_config),
            mode: AuthMode::Jwks {
                url: url.to_string(),
            },
        }
    }

    /// Canton `AuthServiceWildcard`: grants participant-admin and wildcard party access without requiring a JWT.
    pub fn wildcard() -> Self {
        Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: JwksCache::new(JwksCacheConfig::default()),
            mode: AuthMode::Wildcard,
        }
    }

    /// Combines multiple configured `auth-services` entries; succeeds if any validator accepts the token.
    pub fn multi(configs: Vec<AuthConfig>) -> Self {
        let cache = configs
            .first()
            .map(|c| c.jwks_cache.clone())
            .unwrap_or_else(|| JwksCache::new(JwksCacheConfig::default()));
        Self {
            secret: Vec::new(),
            max_lifetime_secs: 300,
            audience: None,
            leeway_secs: 0,
            rsa_public_key: None,
            target_scope: None,
            issued_at_leeway_secs: None,
            expires_at_leeway_secs: None,
            jwks_cache: cache,
            mode: AuthMode::Multi(configs),
        }
    }

    /// Requires audience-based tokens whose `aud` contains `audience`.
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_string());
        self
    }

    /// Requires scope-based tokens whose `scope` contains `scope` (when `audience` is unset).
    pub fn with_target_scope(mut self, scope: &str) -> Self {
        self.target_scope = Some(scope.to_string());
        self
    }

    /// Tolerates `secs` of clock skew on `exp`, `nbf` and `iat`.
    pub fn with_leeway(mut self, secs: i64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Configures `jwt-timestamp-leeway` default plus optional `iat`/`exp` overrides.
    pub fn with_leeway_config(
        mut self,
        default_secs: i64,
        issued_at_secs: Option<i64>,
        expires_at_secs: Option<i64>,
    ) -> Self {
        self.leeway_secs = default_secs;
        self.issued_at_leeway_secs = issued_at_secs;
        self.expires_at_leeway_secs = expires_at_secs;
        self
    }

    /// Overrides the JWKS cache settings (used for both static `jwt-jwks` and dynamic `/v2/idps` issuers).
    pub fn with_jwks_cache(mut self, cache_config: JwksCacheConfig) -> Self {
        self.jwks_cache = JwksCache::new(cache_config);
        self
    }
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK, 0);
    let (mut inner, mut outer) = (Sha256::new(), Sha256::new());
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<_>>());
    inner.update(data);
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>());
    outer.update(inner.finalize());
    outer.finalize().to_vec()
}

pub(crate) fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base64url_encode(data: &[u8]) -> String {
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

/// The DER `RSAPublicKey` inside the PEM certificate `pem`: the `subjectPublicKey` of its `SubjectPublicKeyInfo` (read with a minimal DER walk:
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial, signature, issuer, validity, subject, subjectPublicKeyInfo, .. } .. }`).
pub fn rsa_public_key_of_certificate(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    let der = base64_decode(&body).ok_or("the certificate is not PEM (base64)")?;
    /// `(tag, content, rest)` of the DER element at the start of `bytes`.
    fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let tag = *bytes.first()?;
        let first = *bytes.get(1)?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            let len = bytes
                .get(2..2 + n)?
                .iter()
                .fold(0usize, |a, b| (a << 8) | usize::from(*b));
            (len, 2 + n)
        };
        Some((
            tag,
            bytes.get(header..header + len)?,
            bytes.get(header + len..)?,
        ))
    }
    let bad = || "the certificate is not a DER X.509 certificate".to_string();
    let (_, certificate, _) = element(&der).ok_or_else(bad)?;
    let (_, tbs, _) = element(certificate).ok_or_else(bad)?;
    let mut rest = tbs;
    let (tag, _, after) = element(rest).ok_or_else(bad)?;
    if tag == 0xa0 {
        rest = after; // the explicit version
    }
    // serial, signature algorithm, issuer, validity, subject: five elements, then the SubjectPublicKeyInfo
    for _ in 0..5 {
        rest = element(rest).ok_or_else(bad)?.2;
    }
    let (_, spki, _) = element(rest).ok_or_else(bad)?;
    let (_, _algorithm, key_part) = element(spki).ok_or_else(bad)?;
    let (_, bits, _) = element(key_part).ok_or_else(bad)?;
    // the first byte of a BIT STRING counts its unused bits (0 for a key)
    bits.get(1..).map(<[u8]>::to_vec).ok_or_else(bad)
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|c| *c != b'=') {
        let v = B64.iter().position(|x| *x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A signed HS256 token for `claims` (for tests and tools; the server only verifies).
pub fn sign_token(secret: &str, claims: &Json) -> String {
    let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = base64url_encode(claims.to_string().as_bytes());
    let signature = base64url_encode(&hmac_sha256(
        secret.as_bytes(),
        format!("{header}.{payload}").as_bytes(),
    ));
    format!("{header}.{payload}.{signature}")
}

fn now() -> i64 {
    crate::clock::now_secs() as i64
}

/// What an accepted token says about its caller.
pub struct Principal {
    pub user_id: String,
    pub admin: bool,
    act_as: Vec<String>,
    read_as: Vec<String>,
    exec_as: Vec<String>,
    read_any: bool,
    exec_any: bool,
    any_party: bool,
}

impl Principal {
    fn can_read(&self, party: &str) -> bool {
        self.any_party
            || self.read_any
            || self.read_as.iter().any(|p| p == party)
            || self.act_as.iter().any(|p| p == party)
    }

    fn can_act(&self, party: &str) -> bool {
        self.any_party || self.act_as.iter().any(|p| p == party)
    }

    fn can_execute(&self, party: &str) -> bool {
        self.any_party
            || self.exec_any
            || self.can_act(party)
            || self.exec_as.iter().any(|p| p == party)
    }

    /// The user a user token resolved to; a wildcard token has none (Canton's `Claims.Wildcard`).
    fn token_user(&self) -> Option<crate::auth_user::TokenUser<'_>> {
        (!self.any_party).then_some(crate::auth_user::TokenUser {
            user_id: &self.user_id,
            reads_any_party: self.read_any,
        })
    }
}

/// The generic body Canton answers an authentication (401, gRPC 16) or permission (403, gRPC 7) failure with.
pub fn security_error(status: u16) -> HttpResponse {
    let grpc = if status == 401 { 16 } else { 7 };
    HttpResponse::json(
        status,
        &json!({
            "code": "NA",
            "cause": "A security-sensitive error has been received",
            "correlationId": "00000000000000000000000000000000",
            "traceId": "00000000000000000000000000000000",
            "context": {},
            "resources": [],
            "errorCategory": -1,
            "grpcCodeValue": grpc,
            "retryInfo": null,
            "definiteAnswer": null
        }),
    )
}

fn bearer_token(req: &HttpRequest) -> Option<String> {
    if let Some((_, header)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
    {
        if let Some(tok) = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        {
            let tok = tok.trim();
            if !tok.is_empty() {
                return Some(tok.to_string());
            }
        }
    }
    if let Some((_, proto)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-protocol"))
    {
        for item in proto.split(',') {
            if let Some(tok) = item.trim().strip_prefix("jwt.token.") {
                let tok = tok.trim();
                if !tok.is_empty() {
                    return Some(tok.to_string());
                }
            }
        }
    }
    None
}

fn validate_claims(
    claims: &Json,
    max_lifetime_secs: i64,
    leeway_secs: i64,
    issued_at_leeway_secs: Option<i64>,
    expires_at_leeway_secs: Option<i64>,
    audience: Option<&str>,
    target_scope: Option<&str>,
) -> Result<(), u16> {
    let exp = claims["exp"].as_i64().ok_or(401u16)?;
    let t = now();
    let exp_leeway = expires_at_leeway_secs.unwrap_or(leeway_secs);
    let nbf_leeway = leeway_secs;
    let iat_leeway = issued_at_leeway_secs.unwrap_or(leeway_secs);
    // [CANTON-NOTE: SEMANTICS] Measured on the node (AT-R02, leeway 10): an `exp` up to the leeway in the past, an `nbf` and an
    // `iat` up to the leeway in the future are accepted; 30 seconds off is not. The maximum lifetime is checked on `exp` as before.
    let remaining = exp - t;
    if remaining <= -exp_leeway || remaining > max_lifetime_secs {
        return Err(401);
    }
    if let Some(v) = claims.get("nbf").and_then(Json::as_i64) {
        if v - t > nbf_leeway {
            return Err(401);
        }
    }
    if let Some(v) = claims.get("iat").and_then(Json::as_i64) {
        if v - t > iat_leeway {
            return Err(401);
        }
    }
    if claims["sub"].as_str().is_none_or(str::is_empty) {
        return Err(401);
    }
    if let Some(want) = audience {
        // audience-based tokens: `aud` is a string or a list and must contain the configured audience exactly (case
        // sensitive, a missing, empty or other audience is refused; a `scope` next to it is ignored). Measured on the node.
        let hit = match &claims["aud"] {
            Json::String(a) => a == want,
            Json::Array(a) => a.iter().any(|x| x.as_str() == Some(want)),
            _ => false,
        };
        return if hit { Ok(()) } else { Err(401) };
    }
    // the scope-based token format; an audience-based token is not accepted for this participant (measured: 403)
    let expected_scope = target_scope.unwrap_or("daml_ledger_api");
    let scoped = claims["scope"]
        .as_str()
        .is_some_and(|s| s.split(' ').any(|x| x == expected_scope));
    if !scoped {
        return Err(if claims.get("aud").is_some() {
            403
        } else {
            401
        });
    }
    Ok(())
}

pub(crate) struct VerifiedAuth {
    claims: Json,
    matched_idp: Option<String>,
    pub(crate) is_wildcard: bool,
}

/// Returns `true` iff `host` is a loopback address (`127.0.0.0/8`, `::1`, or `localhost`).
///
/// [CANTON-NOTE: INVARIANT] Any unspecified (`0.0.0.0`, `::`), LAN, or arbitrary hostname returns
/// `false` so dev HS256 authentication and credential issuance fail closed on non-loopback binds (`S-DX-007`, `J-A5`).
pub fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim();
    let stripped = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return false;
    }
    if stripped.eq_ignore_ascii_case("localhost") {
        return true;
    }
    stripped
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        })
}

/// Verifies a bearer token (without its `Bearer ` prefix) against `cfg` and returns decoded claims.
pub fn verify_hmac_claims(cfg: &AuthConfig, raw_token: &str) -> Result<Json, u16> {
    verify_static(cfg, Some(raw_token)).map(|v| v.claims)
}

/// Verifies a bearer token (without its `Bearer ` prefix) against one auth service configuration, without the participant's identity
/// providers: what the Admin API's `auth-services` check (`crate::admin_api_auth`).
pub(crate) fn verify_token(cfg: &AuthConfig, raw_token: Option<&str>) -> Result<VerifiedAuth, u16> {
    verify_static(cfg, raw_token)
}

/// The bearer token of a request, verified; `Err(401)` when it is missing or invalid.
#[cfg(test)]
fn verify(cfg: &AuthConfig, req: &HttpRequest) -> Result<Json, u16> {
    verify_with_state(cfg, req, None).map(|v| v.claims)
}

fn verify_with_state(
    cfg: &AuthConfig,
    req: &HttpRequest,
    state: Option<&crate::v2::V2State>,
) -> Result<VerifiedAuth, u16> {
    if matches!(cfg.mode, AuthMode::Wildcard) {
        return Ok(VerifiedAuth {
            claims: json!({ "sub": "participant_admin" }),
            matched_idp: None,
            is_wildcard: true,
        });
    }
    let raw_token = bearer_token(req);
    if let (Some(tok), Some(st)) = (raw_token.as_deref(), state) {
        if let Some(res) = try_verify_dynamic_idp(cfg, tok, st) {
            return res;
        }
    }
    verify_static(cfg, raw_token.as_deref())
}

fn split_jwt(token: &str) -> Result<(&str, &str, Json, Json, Vec<u8>), u16> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(401);
    };
    let header: Json =
        serde_json::from_slice(&base64url_decode(h).ok_or(401u16)?).map_err(|_| 401u16)?;
    let claims: Json =
        serde_json::from_slice(&base64url_decode(p).ok_or(401u16)?).map_err(|_| 401u16)?;
    let sig = base64url_decode(s).ok_or(401u16)?;
    Ok((h, p, header, claims, sig))
}

fn try_verify_dynamic_idp(
    cfg: &AuthConfig,
    token: &str,
    state: &crate::v2::V2State,
) -> Option<Result<VerifiedAuth, u16>> {
    let Ok((h, p, header, claims, signature)) = split_jwt(token) else {
        return None;
    };
    let issuer = claims.get("iss").and_then(Json::as_str).unwrap_or("");
    let idp = crate::v2_idps::idp_for_issuer(state, issuer)?;
    if idp.deactivated {
        return Some(Err(401));
    }
    let Some(alg) = header.get("alg").and_then(Json::as_str) else {
        return Some(Err(401));
    };
    let Some(kid) = header
        .get("kid")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Some(Err(401));
    };
    let Ok(key) = cfg.jwks_cache.resolve_key(&idp.jwks_url, kid) else {
        return Some(Err(401));
    };
    let signing_input = format!("{h}.{p}");
    if !verify_jwt_signature(&key, alg, signing_input.as_bytes(), &signature) {
        return Some(Err(401));
    }
    let aud = if !idp.audience.is_empty() {
        Some(idp.audience.as_str())
    } else {
        cfg.audience.as_deref()
    };
    match validate_claims(
        &claims,
        cfg.max_lifetime_secs,
        cfg.leeway_secs,
        cfg.issued_at_leeway_secs,
        cfg.expires_at_leeway_secs,
        aud,
        cfg.target_scope.as_deref(),
    ) {
        Ok(()) => Some(Ok(VerifiedAuth {
            claims,
            matched_idp: Some(idp.id),
            is_wildcard: false,
        })),
        Err(status) => Some(Err(status)),
    }
}

fn verify_static(cfg: &AuthConfig, raw_token: Option<&str>) -> Result<VerifiedAuth, u16> {
    if let AuthMode::Multi(configs) = &cfg.mode {
        if raw_token.is_none() && configs.iter().any(|c| matches!(c.mode, AuthMode::Wildcard)) {
            return Ok(VerifiedAuth {
                claims: json!({ "sub": "participant_admin" }),
                matched_idp: None,
                is_wildcard: true,
            });
        }
        let mut saw_403 = false;
        for sub in configs {
            if matches!(sub.mode, AuthMode::Wildcard) {
                continue;
            }
            match verify_static(sub, raw_token) {
                Ok(ok) => return Ok(ok),
                Err(403) => saw_403 = true,
                Err(_) => {}
            }
        }
        return Err(if saw_403 { 403 } else { 401 });
    }
    if matches!(cfg.mode, AuthMode::Wildcard) {
        return Ok(VerifiedAuth {
            claims: json!({ "sub": "participant_admin" }),
            matched_idp: None,
            is_wildcard: true,
        });
    }
    let token = raw_token.ok_or(401u16)?;
    let (h, p, header, claims, signature) = split_jwt(token)?;
    let signing_input = format!("{h}.{p}");
    let alg = header["alg"].as_str();
    match (&cfg.mode, alg, &cfg.rsa_public_key) {
        // [CANTON-NOTE: SEMANTICS] Each configured service validates its exact algorithm family; tokens cannot choose a weaker verifier.
        (AuthMode::Legacy, Some("RS256"), Some(key)) => {
            let public_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                key,
            );
            public_key
                .verify(signing_input.as_bytes(), &signature)
                .map_err(|_| 401u16)?;
        }
        (AuthMode::Legacy, Some("HS256"), None) if !cfg.secret.is_empty() => {
            // `ring::hmac::verify` compares in constant time
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &cfg.secret);
            ring::hmac::verify(&key, signing_input.as_bytes(), &signature).map_err(|_| 401u16)?;
        }
        (AuthMode::Key(key), Some(alg_s), _) => {
            if !verify_jwt_signature(key, alg_s, signing_input.as_bytes(), &signature) {
                return Err(401);
            }
        }
        (AuthMode::Jwks { url }, Some(alg_s), _) => {
            let kid = header["kid"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or(401u16)?;
            let key = cfg.jwks_cache.resolve_key(url, kid).map_err(|_| 401u16)?;
            if !verify_jwt_signature(&key, alg_s, signing_input.as_bytes(), &signature) {
                return Err(401);
            }
        }
        _ => return Err(401),
    }
    validate_claims(
        &claims,
        cfg.max_lifetime_secs,
        cfg.leeway_secs,
        cfg.issued_at_leeway_secs,
        cfg.expires_at_leeway_secs,
        cfg.audience.as_deref(),
        cfg.target_scope.as_deref(),
    )?;
    Ok(VerifiedAuth {
        claims,
        matched_idp: None,
        is_wildcard: false,
    })
}

/// The `sub` of the bearer token of a request (the user it authenticates as), read without checking the signature: the checks of this module have
/// run before a handler asks. `None` without a bearer token.
pub(crate) fn token_subject(req: &HttpRequest) -> Option<String> {
    token_claims(req)?["sub"].as_str().map(String::from)
}

/// The claims of the bearer token of a request, read without checking the signature (see [`token_subject`]).
pub(crate) fn token_claims(req: &HttpRequest) -> Option<Json> {
    let token = bearer_token(req)?;
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&base64url_decode(payload)?).ok()
}

fn principal(
    service: &ExecutionService,
    claims: &Json,
    matched_idp: Option<&str>,
    is_wildcard: bool,
) -> Option<Principal> {
    if is_wildcard {
        return Some(Principal {
            user_id: claims["sub"]
                .as_str()
                .unwrap_or("participant_admin")
                .to_string(),
            admin: true,
            act_as: Vec::new(),
            read_as: Vec::new(),
            exec_as: Vec::new(),
            read_any: true,
            exec_any: true,
            any_party: true,
        });
    }
    let user_id = claims["sub"].as_str()?.to_string();
    let (user_idp, active) = service.v2_state().user_idp_and_active(&user_id)?;
    if !active {
        return None;
    }
    if let Some(idp_id) = matched_idp {
        if user_idp != idp_id {
            return None;
        }
    }
    let rights = service.v2_state().user_rights(&user_id)?;
    let (mut admin, mut act_as, mut read_as, mut exec_as, mut read_any, mut exec_any) =
        (false, vec![], vec![], vec![], false, false);
    for r in rights {
        let party = |k: &str| {
            r.pointer(&format!("/{k}/value/party"))
                .and_then(Json::as_str)
                .map(String::from)
        };
        if r.get("ParticipantAdmin").is_some() {
            admin = true;
        }
        if r.get("CanReadAsAnyParty").is_some() {
            read_any = true;
        }
        if r.get("CanExecuteAsAnyParty").is_some() {
            exec_any = true;
        }
        act_as.extend(party("CanActAs"));
        read_as.extend(party("CanReadAs"));
        exec_as.extend(party("CanExecuteAs"));
    }
    Some(Principal {
        user_id,
        admin,
        act_as,
        read_as,
        exec_as,
        read_any,
        exec_any,
        any_party: false,
    })
}

fn json_body(req: &HttpRequest) -> Json {
    serde_json::from_slice(&req.body).unwrap_or(Json::Null)
}

fn strings(v: Option<&Json>) -> Vec<String> {
    v.and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn filter_parties(v: Option<&Json>) -> Option<Vec<String>> {
    v.and_then(|f| f.get("filtersByParty"))
        .and_then(Json::as_object)
        .map(|m| m.keys().cloned().collect())
}

/// The parties a read call names, `None` when it names none (it then reads as any party).
fn read_parties(path: &str, body: &Json) -> Option<Vec<String>> {
    if path.starts_with("/v2/commands/") {
        let p = strings(body.get("parties"));
        return (!p.is_empty()).then_some(p);
    }
    if path == "/v2/contracts/contract-by-id" {
        let p = strings(body.get("queryingParties"));
        return (!p.is_empty()).then_some(p);
    }
    if path == "/v2/updates/transaction-by-id" || path == "/v2/updates/transaction-by-offset" {
        let p = strings(body.get("requestingParties"));
        if !p.is_empty() {
            return Some(p);
        }
        return filter_parties(body.pointer("/transactionFormat/eventFormat"))
            .or_else(|| filter_parties(body.get("eventFormat")));
    }
    filter_parties(body.get("eventFormat"))
        .or_else(|| filter_parties(body.pointer("/updateFormat/includeTransactions/eventFormat")))
        .or_else(|| {
            filter_parties(
                body.pointer("/filter/filtersByParty")
                    .map(|_| &body["filter"]),
            )
        })
        .or_else(
            || match crate::v2_topology_events::parse_topology_filter(body) {
                Ok(crate::v2_topology_events::TopologyFilter::Parties(p)) => Some(p),
                Ok(
                    crate::v2_topology_events::TopologyFilter::AllParties
                    | crate::v2_topology_events::TopologyFilter::None,
                )
                | Err(_) => None,
            },
        )
}

fn topology_filter_readable(p: &Principal, body: &Json) -> bool {
    match crate::v2_topology_events::parse_topology_filter(body) {
        Ok(crate::v2_topology_events::TopologyFilter::None) => true,
        Ok(crate::v2_topology_events::TopologyFilter::AllParties) => p.any_party || p.read_any,
        Ok(crate::v2_topology_events::TopologyFilter::Parties(parties)) => {
            parties.iter().all(|party| p.can_read(party))
        }
        Err(_) => true,
    }
}

/// The values a command carries for the ledger (a Daml record may have a field of any name): never read as a filter.
const COMMAND_VALUES: [&str; 4] = [
    "createArguments",
    "choiceArgument",
    "contractKey",
    "disclosedContracts",
];

/// Whether a body has a `filtersForAnyParty` filter at any depth: the same walk `v2::expand_any_party` makes when it turns the filter into
/// one entry per known party.
fn asks_any_party(v: &Json) -> bool {
    match v {
        Json::Object(map) => {
            map.contains_key("filtersForAnyParty") || map.values().any(asks_any_party)
        }
        Json::Array(items) => items.iter().any(asks_any_party),
        _ => false,
    }
}

/// The parties every `filtersByParty` of a body names, wherever it sits outside the commands' own values.
fn filter_parties_anywhere<'a>(v: &'a Json, out: &mut Vec<&'a str>) {
    match v {
        Json::Object(map) => {
            for (key, value) in map {
                if key == "filtersByParty" {
                    if let Some(by_party) = value.as_object() {
                        out.extend(by_party.keys().map(String::as_str));
                    }
                } else if !COMMAND_VALUES.contains(&key.as_str()) {
                    filter_parties_anywhere(value, out);
                }
            }
        }
        Json::Array(items) => items.iter().for_each(|x| filter_parties_anywhere(x, out)),
        _ => {}
    }
}

/// Whether `p` may read as every party the filters of a body ask for.
///
/// [CANTON-NOTE: SEMANTICS] `RequiredClaims.scala` (ledger-api-core, 3.7.2): a `ReadAs` claim for every key of `filtersByParty`, and
/// `ReadAsAnyParty` whenever `filtersForAnyParty` is set; the two are checked together, so an empty or readable `filtersByParty` next
/// to an any-party filter does not stand in for the right to read as any party. The same claims guard the format of a submission that
/// returns its transaction (`CommandServiceAuthorization`, `InteractiveSubmissionServiceAuthorization`).
///
/// [CANTON-NOTE: DEFENSIVE] The routes read their filter from different places of the body (`eventFormat`, `filter`,
/// `updateFormat.includeTransactions.eventFormat`, `transactionFormat.eventFormat`). Every filter of the body is checked, not the one
/// place a route is expected to read: a filter that is not looked at here must never be the one that is served.
fn filters_readable(p: &Principal, body: &Json) -> bool {
    let mut parties = Vec::new();
    filter_parties_anywhere(body, &mut parties);
    parties.iter().all(|party| p.can_read(party))
        && (p.any_party || p.read_any || !asks_any_party(body))
        && topology_filter_readable(p, body)
}

/// Whether `p` may read what a read call asks for: the parties the call names its own way (see [`read_parties`]; a call that names
/// none reads as any party) and every filter of its body.
fn may_read(p: &Principal, path: &str, body: &Json) -> bool {
    let named = match read_parties(path, body) {
        Some(parties) => parties.iter().all(|x| p.can_read(x)),
        None => p.read_any,
    };
    named && filters_readable(p, body)
}

fn is_ws_upgrade(req: &HttpRequest) -> bool {
    req.headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"))
}

fn ws_channels(path: &str) -> bool {
    matches!(
        path,
        "/v2/updates"
            | "/v2/updates/flats"
            | "/v2/updates/trees"
            | "/v2/state/active-contracts"
            | "/v2/commands/completions"
            | "/v2/commands/command-completions"
    )
}

fn query_parties(req: &HttpRequest) -> Option<Vec<String>> {
    let raw = req.query_params.get("parties")?;
    let list: Vec<String> = raw
        .split(['\x1f', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Whether the principal may make the call (the authorization half; the token is already accepted).
fn allowed(p: &Principal, req: &HttpRequest) -> bool {
    if p.any_party {
        return true;
    }
    let (method, path) = (req.method.as_str(), req.path.trim_end_matches('/'));
    let public = [
        "/v2/version",
        "/v2/state/ledger-end",
        "/v2/state/connected-synchronizers",
        "/v2/state/latest-pruned-offsets",
        "/v2/state/convert-record-time-to-offset",
        "/v2/parties/participant-id",
        "/v2/packages",
        "/v2/package-vetting",
        "/v2/package-vetting/list",
        "/v2/interactive-submission/preferred-package-version",
        "/v2/authenticated-user",
        "/docs/openapi",
        "/docs/asyncapi",
    ];
    if method == "GET"
        && (public.contains(&path)
            || path.starts_with("/v2/packages/")
            || path.starts_with("/v2/jose/jwks/synchronizer/"))
    {
        return true;
    }
    if method == "GET" && is_ws_upgrade(req) && ws_channels(path) {
        return true;
    }
    if method == "POST"
        && matches!(
            path,
            "/v2/package-vetting/list"
                | "/v2/interactive-submission/preferred-packages"
                | "/v2/interactive-submission/preferred-package-version"
        )
    {
        return true;
    }
    if method == "GET"
        && (path.starts_with("/v2/updates/transaction-tree-by-id/")
            || path.starts_with("/v2/updates/transaction-tree-by-offset/"))
    {
        return match query_parties(req) {
            Some(parties) => parties.iter().all(|x| p.can_read(x)),
            None => p.read_any,
        };
    }
    if method == "GET" && path.starts_with("/v2/traffic/accounts/") {
        let acct = crate::v2::percent_decode(&path["/v2/traffic/accounts/".len()..]);
        return p.admin || p.can_execute(&acct);
    }
    // a user reads its own record and rights; any other user is an administrator's
    if method == "GET" && path.starts_with("/v2/users/") {
        let rest = &path["/v2/users/".len()..];
        let id = rest.strip_suffix("/rights").unwrap_or(rest);
        return p.admin || crate::v2::percent_decode(id) == p.user_id;
    }
    if method == "GET"
        && path.starts_with("/v2/parties/")
        && !path.starts_with("/v2/parties/external/")
        && !path.ends_with("participant-id")
    {
        return p.admin || p.can_read(&crate::v2::percent_decode(&path["/v2/parties/".len()..]));
    }
    let body = json_body(req);
    // a submission or an execution that returns its transaction reads it as the parties of its format
    if !filters_readable(p, &body) {
        return false;
    }
    if path.starts_with("/v2/commands/submit") || path == "/v2/commands/async/submit" {
        let commands = body
            .get("commands")
            .filter(|c| c.is_object())
            .unwrap_or(&body);
        let (act, read) = (
            strings(commands.get("actAs")),
            strings(commands.get("readAs")),
        );
        return !act.is_empty()
            && act.iter().all(|a| p.can_act(a))
            && read.iter().all(|r| p.can_read(r));
    }
    if path == "/v2/commands/async/submit-reassignment"
        || path == "/v2/commands/submit-and-wait-for-reassignment"
    {
        let inner = body
            .get("reassignmentCommands")
            .filter(|c| c.is_object())
            .unwrap_or(&body);
        let submitter = inner.get("submitter").and_then(Json::as_str).unwrap_or("");
        return !submitter.is_empty() && p.can_act(submitter);
    }
    if path == "/v2/interactive-submission/prepare" {
        let (act, read) = (strings(body.get("actAs")), strings(body.get("readAs")));
        return !act.is_empty()
            && act.iter().all(|a| p.can_execute(a))
            && read.iter().all(|r| p.can_read(r));
    }
    if path.starts_with("/v2/interactive-submission/execute") {
        // [CANTON-NOTE: SEMANTICS] `InteractiveSubmissionServiceAuthorization.getExecuteSubmissionClaims` (Canton 3.7.2): the right
        // to execute as every `actAs` party of the prepared transaction itself. A body without a readable prepared transaction names
        // no party; the handler then refuses it as malformed, for any user with some right to act or execute.
        return match crate::v2_interactive::prepared_act_as(&body) {
            Some(act_as) => !act_as.is_empty() && act_as.iter().all(|a| p.can_execute(a)),
            None => p.admin || p.exec_any || !p.exec_as.is_empty() || !p.act_as.is_empty(),
        };
    }
    let reads = [
        "/v2/state/active-contracts",
        "/v2/state/active-contracts-page",
        "/v2/updates",
        "/v2/updates/flats",
        "/v2/updates/trees",
        "/v2/updates/get-updates-page",
        "/v2/updates/update-by-id",
        "/v2/updates/update-by-offset",
        "/v2/updates/update-by-hash",
        "/v2/updates/transaction-by-id",
        "/v2/updates/transaction-by-offset",
        "/v2/events/events-by-contract-id",
        "/v2/contracts/contract-by-id",
        "/v2/commands/completions",
        "/v2/commands/command-completions",
    ];
    if method == "POST" && reads.contains(&path) {
        return may_read(p, path, &body);
    }
    p.admin
}

/// Checks permission of the initial JSON message received on a WebSocket subscription channel: `Ok(Some(_))` is the message
/// with the token's user filled into an empty `userId` (the completion channel, [`crate::auth_user`]).
pub(crate) fn check_ws_payload(
    service: &ExecutionService,
    req: &HttpRequest,
    frame_body: &[u8],
) -> Result<Option<Vec<u8>>, HttpResponse> {
    let Some(cfg) = service.auth_config() else {
        return Ok(None);
    };
    let verified =
        verify_with_state(&cfg, req, Some(service.v2_state())).map_err(security_error)?;
    let p = principal(
        service,
        &verified.claims,
        verified.matched_idp.as_deref(),
        verified.is_wildcard,
    )
    .ok_or_else(|| security_error(403))?;
    let Some(user) = p.token_user() else {
        return Ok(None);
    };
    let body: Json = serde_json::from_slice(frame_body).unwrap_or(Json::Null);
    let path = req.path.trim_end_matches('/');
    if !may_read(&p, path, &body) {
        return Err(security_error(403));
    }
    let frame = HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: frame_body.to_vec(),
    };
    Ok(crate::auth_user::match_user_id(&frame, &user)?.map(|filled| filled.body))
}

/// The authentication and authorization step of a request: `None` when the call may proceed (also when no authentication is
/// configured), else the error response.
pub fn check(service: &ExecutionService, req: &HttpRequest) -> Option<HttpResponse> {
    admit(service, req).err()
}

/// [`check`], and the request as the call proceeds with: `Ok(Some(_))` when the token's user filled an empty `userId`
/// ([`crate::auth_user`]).
pub(crate) fn admit(
    service: &ExecutionService,
    req: &HttpRequest,
) -> Result<Option<HttpRequest>, HttpResponse> {
    let Some(cfg) = service.auth_config() else {
        return Ok(None);
    };
    let path = req.path.trim_end_matches('/');
    if path == "/livez"
        || path == "/readyz"
        || path == "/healthz"
        || path == "/health"
        || (req.method == "GET"
            && (path == "/docs/openapi"
                || path == "/docs/asyncapi"
                || path.starts_with("/v2/jose/jwks/synchronizer/")))
    {
        return Ok(None);
    }
    let verified =
        verify_with_state(&cfg, req, Some(service.v2_state())).map_err(security_error)?;
    let p = principal(
        service,
        &verified.claims,
        verified.matched_idp.as_deref(),
        verified.is_wildcard,
    )
    .ok_or_else(|| security_error(403))?;
    if !req.body.is_empty() {
        if let Ok(body) = serde_json::from_slice::<Json>(&req.body) {
            if let Err(msg) = crate::v2_topology_events::parse_topology_filter(&body) {
                return Err(crate::v2_commands::bad_body(msg));
            }
        }
    }
    if !allowed(&p, req) {
        return Err(security_error(403));
    }
    match p.token_user() {
        Some(user) => crate::auth_user::match_user_id(req, &user),
        None => Ok(None),
    }
}

/// The authentication and authorization step of a call to the participant's Admin API (gRPC, no HTTP path of its own): `None` when
/// the call may proceed (also when no authentication is configured), else the error response.
///
/// [CANTON-NOTE: DEFENSIVE] A Canton node serves the Admin API on a port of its own with its own `auth-services`
/// (`AdminServerConfig`). This server answers the Admin services on the Ledger API's listener, so with an auth service configured
/// an administration call needs the token of a participant administrator: otherwise repair, package and topology calls would be
/// reachable around the Ledger API's authentication.
pub fn check_admin(
    service: &ExecutionService,
    authorization: Option<&str>,
) -> Option<HttpResponse> {
    let cfg = service.auth_config()?;
    let req = HttpRequest {
        method: "POST".into(),
        path: "/admin-api".into(),
        query_params: Default::default(),
        headers: authorization
            .map(|a| ("authorization".to_string(), a.to_string()))
            .into_iter()
            .collect(),
        body: Vec::new(),
    };
    let verified = match verify_with_state(&cfg, &req, Some(service.v2_state())) {
        Ok(v) => v,
        Err(status) => return Some(security_error(status)),
    };
    let Some(p) = principal(
        service,
        &verified.claims,
        verified.matched_idp.as_deref(),
        verified.is_wildcard,
    ) else {
        return Some(security_error(403));
    };
    (!p.admin).then(|| security_error(403))
}

#[cfg(test)]
mod rs256_tests {
    use super::*;

    /// A self-signed certificate (`openssl req -x509 -newkey rsa:2048`) and a token its key signed (`sub` participant_admin, scope `daml_ledger_api`,
    /// `exp` in 2100): the shape of a `jwt-rs-256-crt` setup.
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIICsDCCAZgCCQDpQrqwUAmYpDANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5j
YW50b24tcnMtdGVzdDAgFw0yNjExMTcwNjQ4NDlaGA8yMTI2MTAyNDA2NDg0OVow
GTEXMBUGA1UEAwwOY2FudG9uLXJzLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC1q5hPZbc11hj3UPT00CZKxLmoc9Au9kI+Xbc2NARgQxXjtH4a
xVCdziZ4kG4F/8kJKrl1hTr7B29QEIQHmfV4HAlt/0y9mnNV7kD0ErgUqQTQt/f5
jdpQOkixhU75XMP+GTe4DrNY2LN6mqivFXCd+BZihxUqV2dGKZ/Culyq+z0MIc6k
wYTw+whZOeiCHmALkx4gwSPHnGX0XeSa27OQdnPIYDAHi8fEoKeU95PlxiUSDWl5
gTRUH92enkCWaR6eXiBLzS88TLE2+pPFqRMceG3kW0O2D5xjvyOiwIrxuTuKpEeM
qgtzrACu0YIXkJMwqUIX/IUPJX1EgN2EsX8pAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAKzC62rilMGW3yJ5QF84e3riy/BNBPc4DSluFEJwNSvtXD5Aie2Y9Roh+NLg
jYKShRjHrPwT/3HMcLPPZZr42Y2KmT7PCj9jaFujZ8xesu+T9xaMwWAysFPesDan
Oz7BbZw3QX/bVa9b46ZrumV4ANSePrgaxXdUIy0sF+SbXC/qXgDBDKR1SggsHVch
RxkBljLeqEGwmQkHPXFAgfYw0ktNgetCqJprHnXM3Uhg0XWZK0lBFn/LXqwebCQ5
hZyJb3y4ivdZ8afUcf/DSFV8pD2L+RqN1ZNfVFIynqb4T5zU0pXWgBNc4NgMys/q
RI22yzlf9ZQv4h66MyBh3wrBm5w=
-----END CERTIFICATE-----\n";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwYXJ0aWNpcGFudF9hZG1pbiIsInNjb3BlIjoiZGFtbF9sZWRnZXJfYXBpIiwiZXhwIjo0MTAyNDQ0ODAwfQ.o7cDaD63QYE5RqWXCp8l8jvrk9i_EgYDw4o6D2iIQn2JpFZ0oyKMQfhsc_LNIZreohz3Wd1Lv720s_9QVrmGWaSqvxG-c3ZZnWvN5xq7bk7ioCLAG9UW0CsPE1J61vDP5zAZD-hEV-q9SwmuaN4E5J8IZrjxia73ZODhF8LCdJZyIzkZN_QwBcwtSd-Gr3mQv-aELxw1wWW623mm2rsk19zL7axu0jPREDmGGvpH9jdYKkr3yUTdh3YmDw8XGZDjojRvIWspR_NfHhO4NQ-9mohA9n60DYep5-H3h59wyWyH8XW1LN7gfEDAH_A5HJHPB-dMPNTyW_vFYSiGL4yWCw";

    fn request(token: &str) -> HttpRequest {
        let mut req = HttpRequest {
            method: "GET".into(),
            path: "/v2/version".into(),
            query_params: Default::default(),
            headers: Default::default(),
            body: Vec::new(),
        };
        req.headers
            .insert("authorization".into(), format!("Bearer {token}"));
        req
    }

    #[test]
    fn a_token_signed_by_the_key_of_the_certificate_is_accepted() {
        let mut cfg = AuthConfig::rs256_certificate(CERT).expect("the certificate is read");
        // the embedded token lives until 2100: its lifetime is allowed here (the default limit is tested below)
        cfg.max_lifetime_secs = i64::MAX / 4;
        let claims = verify(&cfg, &request(TOKEN)).expect("the token verifies");
        assert_eq!(claims["sub"], "participant_admin");
    }

    #[test]
    fn the_default_lifetime_limit_is_the_nodes_300_seconds() {
        let cfg = AuthConfig::rs256_certificate(CERT).unwrap();
        assert_eq!(cfg.max_lifetime_secs, 300);
        // the token of the test expires in 2100: far beyond the limit
        assert!(verify(&cfg, &request(TOKEN)).is_err());
    }

    #[test]
    fn a_changed_token_and_an_hmac_token_are_refused() {
        let mut cfg = AuthConfig::rs256_certificate(CERT).unwrap();
        cfg.max_lifetime_secs = i64::MAX / 4;
        // one character of the payload changed: the signature no longer fits
        let mut parts: Vec<String> = TOKEN.split('.').map(String::from).collect();
        parts[1] = base64url_encode(
            br#"{"sub":"someone_else","scope":"daml_ledger_api","exp":4102444800}"#,
        );
        assert!(verify(&cfg, &request(&parts.join("."))).is_err());
        // an HS256 token must not be accepted by a certificate-based service, whatever secret it names
        let hs = sign_token(
            "unsafe",
            &json!({"sub": "x", "scope": "daml_ledger_api", "exp": 4102444800i64}),
        );
        assert!(verify(&cfg, &request(&hs)).is_err());
        // and an RS256 token is refused by a secret-based service
        assert!(verify(&AuthConfig::hmac("unsafe"), &request(TOKEN)).is_err());
    }

    #[test]
    fn observability_endpoints_require_admin_jwt_while_health_stays_public() {
        let svc = ExecutionService::new();
        let mut cfg = AuthConfig::hmac("secret-for-obs-test");
        cfg.max_lifetime_secs = i64::MAX / 4;
        svc.set_auth(cfg);
        let admin_tok = sign_token(
            "secret-for-obs-test",
            &json!({"sub": "participant_admin", "scope": "daml_ledger_api", "exp": 4102444800i64}),
        );
        let user_tok = sign_token(
            "secret-for-obs-test",
            &json!({"sub": "alice-user", "scope": "daml_ledger_api", "exp": 4102444800i64}),
        );
        // Provision non-admin user so JWT claims resolve to a valid non-admin principal (`403` vs admin `200`).
        let mut create_user = HttpRequest::json_post(
            "/v2/users",
            &json!({ "user": { "id": "alice-user", "primaryParty": "" }, "rights": [] }),
        );
        create_user
            .headers
            .insert("authorization".into(), format!("Bearer {admin_tok}"));
        assert_eq!(
            crate::http::dispatch_request(&svc, &create_user).status,
            200
        );
        let mk_req = |method: &str, path: &str, tok: Option<&str>| {
            let mut req = HttpRequest {
                method: method.into(),
                path: path.into(),
                query_params: Default::default(),
                headers: Default::default(),
                body: Vec::new(),
            };
            if let Some(t) = tok {
                req.headers
                    .insert("authorization".into(), format!("Bearer {t}"));
            }
            req
        };
        assert_eq!(
            crate::http::dispatch_request(&svc, &mk_req("GET", "/livez", None)).status,
            200
        );
        assert_eq!(
            crate::http::dispatch_request(&svc, &mk_req("GET", "/readyz", None)).status,
            200
        );
        for ep in ["/metrics", "/_telemetry", "/_xray", "/_exex"] {
            assert_eq!(
                crate::http::dispatch_request(&svc, &mk_req("GET", ep, None)).status,
                401,
                "{ep} without token"
            );
            assert_eq!(
                crate::http::dispatch_request(&svc, &mk_req("GET", ep, Some(&user_tok))).status,
                403,
                "{ep} with non-admin token"
            );
            assert_eq!(
                crate::http::dispatch_request(&svc, &mk_req("GET", ep, Some(&admin_tok))).status,
                200,
                "{ep} with admin token"
            );
        }
        assert_eq!(
            crate::http::dispatch_request(&svc, &mk_req("POST", "/_xray", Some(&user_tok))).status,
            403
        );
    }
}
