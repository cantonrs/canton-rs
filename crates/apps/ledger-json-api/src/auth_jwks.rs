//! JWKS HTTP/HTTPS key-set caching, X.509 SPKI parsing (RS256/ES256/ES384/ES512), NIST P-521 ECDSA
//! verification, and external-party JWK serialization (`U-47`, `S-API-029`).

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use canton_algo::signing::{KeySpec, PublicKey};
use num_bigint::BigUint;
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use rustls_pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha512};

const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_CURVE_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_CURVE_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_CURVE_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// Certificate algorithm expectation for PEM certificate auth services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertKind {
    Rs256,
    Es256,
    Es512,
}

/// Verified public key material usable for JWT signature checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    EcP256(Vec<u8>),
    EcP384(Vec<u8>),
    EcP521 { x: Vec<u8>, y: Vec<u8> },
}

/// Canton `jwks-cache-config` tuning for JWKS fetches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwksCacheConfig {
    pub cache_max_size: usize,
    pub cache_max_age_secs: u64,
    pub connection_timeout_secs: u64,
    pub read_timeout_secs: u64,
}

impl Default for JwksCacheConfig {
    fn default() -> Self {
        Self {
            cache_max_size: 1000,
            cache_max_age_secs: 600,
            connection_timeout_secs: 10,
            read_timeout_secs: 10,
        }
    }
}

#[derive(Clone)]
struct CachedJwks {
    fetched_at: Instant,
    keys: BTreeMap<String, VerifiedKey>,
}

/// Thread-safe JWKS cache keyed by JWKS URL (`kid` required on tokens).
#[derive(Clone)]
pub struct JwksCache {
    pub config: JwksCacheConfig,
    entries: Arc<Mutex<HashMap<String, CachedJwks>>>,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("config", &self.config)
            .finish()
    }
}

impl JwksCache {
    pub fn new(config: JwksCacheConfig) -> Self {
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolves key `kid` from cache or fetches/refreshes `url` when stale or missing.
    pub fn resolve_key(&self, url: &str, kid: &str) -> Result<VerifiedKey, String> {
        if kid.is_empty() {
            return Err("JWKS verification requires a non-empty kid header".into());
        }
        let now = Instant::now();
        let max_age = Duration::from_secs(self.config.cache_max_age_secs);
        if let Ok(guard) = self.entries.lock() {
            if let Some(cached) = guard.get(url) {
                if now.duration_since(cached.fetched_at) < max_age {
                    if let Some(key) = cached.keys.get(kid) {
                        return Ok(key.clone());
                    }
                }
            }
        }
        let fetched = fetch_jwks(url, &self.config)?;
        let out = fetched
            .get(kid)
            .cloned()
            .ok_or_else(|| format!("JWKS at {url} does not contain key id {kid:?}"))?;
        if let Ok(mut guard) = self.entries.lock() {
            if !guard.contains_key(url) && guard.len() >= self.config.cache_max_size.max(1) {
                if let Some(oldest) = guard
                    .iter()
                    .min_by_key(|(_, v)| v.fetched_at)
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&oldest);
                }
            }
            guard.insert(
                url.to_string(),
                CachedJwks {
                    fetched_at: Instant::now(),
                    keys: fetched,
                },
            );
        }
        Ok(out)
    }
}

/// Decodes unpadded (or padded) URL-safe base64.
pub(crate) fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut padded = s.replace('-', "+").replace('_', "/");
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    crate::v2::unbase64(&padded).ok_or_else(|| "invalid base64url encoding".into())
}

/// Encodes unpadded URL-safe base64.
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    crate::v2::base64(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Parses an X.509 PEM certificate and extracts a verified public key matching `expected`.
pub fn parse_certificate_pem(pem: &str, expected: CertKind) -> Result<VerifiedKey, String> {
    let certs = decode_pem_blocks(pem, "CERTIFICATE");
    let der = certs
        .into_iter()
        .next()
        .ok_or_else(|| "certificate PEM contains no CERTIFICATE block".to_string())?;
    let spki = extract_cert_spki(&der)?;
    let key = parse_spki_key(&spki)?;
    match (expected, &key) {
        (CertKind::Rs256, VerifiedKey::Rsa { .. })
        | (CertKind::Es256, VerifiedKey::EcP256(_))
        | (CertKind::Es512, VerifiedKey::EcP521 { .. }) => Ok(key),
        (CertKind::Rs256, _) => Err("certificate does not carry an RSA public key".into()),
        (CertKind::Es256, _) => Err("certificate does not carry an EC P-256 public key".into()),
        (CertKind::Es512, _) => Err("certificate does not carry an EC P-521 public key".into()),
    }
}

/// Verifies a JWT signature against `key` for JWS algorithm `alg`.
pub fn verify_jwt_signature(
    key: &VerifiedKey,
    alg: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> bool {
    match (key, alg) {
        (VerifiedKey::Rsa { n, e }, "RS256") => RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input, signature)
        .is_ok(),
        (VerifiedKey::Rsa { n, e }, "RS384") => RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(&RSA_PKCS1_2048_8192_SHA384, signing_input, signature)
        .is_ok(),
        (VerifiedKey::Rsa { n, e }, "RS512") => RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(&RSA_PKCS1_2048_8192_SHA512, signing_input, signature)
        .is_ok(),
        (VerifiedKey::EcP256(point), "ES256") => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point.as_slice())
                .verify(signing_input, signature)
                .is_ok()
        }
        (VerifiedKey::EcP384(point), "ES384") => {
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, point.as_slice())
                .verify(signing_input, signature)
                .is_ok()
        }
        (VerifiedKey::EcP521 { x, y }, "ES512") => verify_es512(x, y, signing_input, signature),
        _ => false,
    }
}

/// Serializes a registered external-party Canton signing public key into RFC 7517 JWK JSON.
pub fn public_key_to_jwk(pk: &PublicKey) -> Result<Json, String> {
    let spki = parse_spki_raw(&pk.key)?;
    match pk.key_spec {
        KeySpec::EcCurve25519 => {
            if spki.oid != OID_ED25519 || spki.bits.len() != 32 {
                return Err("unexpected Ed25519 SPKI payload".into());
            }
            Ok(json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": pk.id,
                "x": base64url_encode(&spki.bits),
            }))
        }
        KeySpec::EcP256 | KeySpec::EcP384 | KeySpec::EcSecp256k1 => {
            let (crv, coord_len) = match pk.key_spec {
                KeySpec::EcP256 => ("P-256", 32usize),
                KeySpec::EcP384 => ("P-384", 48usize),
                KeySpec::EcSecp256k1 => ("secp256k1", 32usize),
                _ => unreachable!(),
            };
            let uncompressed = spki.bits;
            if uncompressed.first() != Some(&0x04) || uncompressed.len() != 1 + 2 * coord_len {
                return Err(format!("expected uncompressed {crv} EC point in SPKI"));
            }
            let x = &uncompressed[1..1 + coord_len];
            let y = &uncompressed[1 + coord_len..];
            Ok(json!({
                "kty": "EC",
                "crv": crv,
                "use": "sig",
                "kid": pk.id,
                "x": base64url_encode(x),
                "y": base64url_encode(y),
            }))
        }
        other => Err(format!(
            "key spec {} has no JWK representation",
            other.name()
        )),
    }
}

// ---------------------------------------------------------------------------
// JWKS HTTP / HTTPS / file client + JWK parsing
// ---------------------------------------------------------------------------

fn fetch_jwks(url: &str, cfg: &JwksCacheConfig) -> Result<BTreeMap<String, VerifiedKey>, String> {
    let body = if let Some(path) = url.strip_prefix("file://") {
        std::fs::read(path).map_err(|e| format!("reading JWKS file {path}: {e}"))?
    } else {
        http_get_url(
            url,
            Duration::from_secs(cfg.connection_timeout_secs.max(1)),
            Duration::from_secs(cfg.read_timeout_secs.max(1)),
        )?
    };
    parse_jwks_json(&body)
}

pub(crate) fn parse_jwks_json(body: &[u8]) -> Result<BTreeMap<String, VerifiedKey>, String> {
    let val: Json = serde_json::from_slice(body).map_err(|e| format!("invalid JWKS JSON: {e}"))?;
    let keys = val
        .get("keys")
        .and_then(Json::as_array)
        .ok_or_else(|| "JWKS JSON has no 'keys' array".to_string())?;
    let mut out = BTreeMap::new();
    for entry in keys {
        if let Some(u) = entry.get("use").and_then(Json::as_str) {
            if u != "sig" {
                continue;
            }
        }
        let Some(kid) = entry
            .get("kid")
            .and_then(Json::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        if let Ok(key) = parse_jwk_entry(entry) {
            out.insert(kid.to_string(), key);
        }
    }
    Ok(out)
}

fn parse_jwk_entry(entry: &Json) -> Result<VerifiedKey, String> {
    // Prefer X.509 cert chain `x5c[0]` if present alongside `kty` when RSA modulus omitted.
    if let Some(kty) = entry.get("kty").and_then(Json::as_str) {
        match kty {
            "RSA" => {
                if let (Some(n_s), Some(e_s)) = (
                    entry.get("n").and_then(Json::as_str),
                    entry.get("e").and_then(Json::as_str),
                ) {
                    let n = trim_leading_zeros(&base64url_decode(n_s)?).to_vec();
                    let e = trim_leading_zeros(&base64url_decode(e_s)?).to_vec();
                    if n.is_empty() || e.is_empty() {
                        return Err("empty RSA modulus or exponent in JWK".into());
                    }
                    return Ok(VerifiedKey::Rsa { n, e });
                }
            }
            "EC" => {
                let crv = entry
                    .get("crv")
                    .and_then(Json::as_str)
                    .ok_or_else(|| "EC JWK missing crv".to_string())?;
                let x_s = entry
                    .get("x")
                    .and_then(Json::as_str)
                    .ok_or_else(|| "EC JWK missing x".to_string())?;
                let y_s = entry
                    .get("y")
                    .and_then(Json::as_str)
                    .ok_or_else(|| "EC JWK missing y".to_string())?;
                let x = base64url_decode(x_s)?;
                let y = base64url_decode(y_s)?;
                return ec_from_coords(crv, &x, &y);
            }
            other => return Err(format!("unsupported JWK kty {other}")),
        }
    }
    if let Some(first_cert_b64) = entry
        .get("x5c")
        .and_then(Json::as_array)
        .and_then(|arr| arr.first())
        .and_then(Json::as_str)
    {
        let cleaned: String = first_cert_b64
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = crate::v2::unbase64(&cleaned).ok_or_else(|| "invalid x5c base64".to_string())?;
        let spki = extract_cert_spki(&der)?;
        return parse_spki_key(&spki);
    }
    Err("JWK entry has neither usable parameters nor x5c certificate".into())
}

fn ec_from_coords(crv: &str, x: &[u8], y: &[u8]) -> Result<VerifiedKey, String> {
    let coord_len = match crv {
        "P-256" => 32usize,
        "P-384" => 48usize,
        "P-521" => 66usize,
        other => return Err(format!("unsupported EC JWK curve {other}")),
    };
    let xp = pad_big_endian(x, coord_len)?;
    let yp = pad_big_endian(y, coord_len)?;
    Ok(match crv {
        "P-256" => {
            let mut pt = Vec::with_capacity(1 + 64);
            pt.push(0x04);
            pt.extend_from_slice(&xp);
            pt.extend_from_slice(&yp);
            VerifiedKey::EcP256(pt)
        }
        "P-384" => {
            let mut pt = Vec::with_capacity(1 + 96);
            pt.push(0x04);
            pt.extend_from_slice(&xp);
            pt.extend_from_slice(&yp);
            VerifiedKey::EcP384(pt)
        }
        "P-521" => VerifiedKey::EcP521 { x: xp, y: yp },
        _ => unreachable!(),
    })
}

fn pad_big_endian(bytes: &[u8], len: usize) -> Result<Vec<u8>, String> {
    let trimmed = trim_leading_zeros(bytes);
    if trimmed.len() > len {
        return Err(format!(
            "coordinate byte length {} exceeds {len}",
            trimmed.len()
        ));
    }
    let mut out = vec![0u8; len];
    out[len - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

fn http_get_url(
    url: &str,
    conn_timeout: Duration,
    read_timeout: Duration,
) -> Result<Vec<u8>, String> {
    let (is_https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("unsupported JWKS URL scheme: {url}"));
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, if is_https { 443 } else { 80 })?;
    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving JWKS host {host}:{port}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {host}:{port}"));
    }
    let mut last_err = String::new();
    let mut tcp_opt = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, conn_timeout) {
            Ok(s) => {
                tcp_opt = Some(s);
                break;
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    let tcp = tcp_opt.ok_or_else(|| format!("connecting to JWKS {host}:{port}: {last_err}"))?;
    let _ = tcp.set_read_timeout(Some(read_timeout));
    let _ = tcp.set_write_timeout(Some(conn_timeout));

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    let raw_resp = if is_https {
        let cfg = build_https_client_config()?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid HTTPS server name {host:?}: {e}"))?;
        let conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| format!("TLS handshake setup failed: {e}"))?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(req.as_bytes())
            .map_err(|e| format!("writing JWKS HTTPS request: {e}"))?;
        let mut buf = Vec::new();
        read_to_end_allowing_close_notify(&mut tls, &mut buf)?;
        buf
    } else {
        let mut s = tcp;
        s.write_all(req.as_bytes())
            .map_err(|e| format!("writing JWKS HTTP request: {e}"))?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)
            .map_err(|e| format!("reading JWKS HTTP response: {e}"))?;
        buf
    };
    parse_http_response_body(&raw_resp)
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("malformed IPv6 authority {authority:?}"))?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in {authority:?}"))?
        } else {
            default_port
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("invalid port in {authority:?}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((authority.to_string(), default_port)),
    }
}

fn read_to_end_allowing_close_notify<R: Read>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            // Servers sometimes drop TCP FIN without TLS close_notify; accept if body already complete.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !out.is_empty() => {
                return Ok(());
            }
            Err(e) => return Err(format!("reading JWKS TLS response: {e}")),
        }
    }
}

fn build_https_client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    let mut loaded = 0usize;
    let candidates: Vec<String> = [
        std::env::var("CANTON_RS_JWKS_CA_FILE").ok(),
        std::env::var("SSL_CERT_FILE").ok(),
        Some("/etc/ssl/certs/ca-certificates.crt".to_string()),
        Some("/etc/pki/tls/certs/ca-bundle.crt".to_string()),
        Some("/etc/ssl/cert.pem".to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    for path in candidates {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for der in decode_pem_blocks(&text, "CERTIFICATE") {
            if roots.add(CertificateDer::from(der)).is_ok() {
                loaded += 1;
            }
        }
        if loaded > 0 {
            break;
        }
    }
    if loaded == 0 {
        return Err(
            "no trusted CA certificates found for HTTPS JWKS (set CANTON_RS_JWKS_CA_FILE or SSL_CERT_FILE)"
                .into(),
        );
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol config error: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

fn parse_http_response_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response from JWKS endpoint".to_string())?;
    let head = std::str::from_utf8(&raw[..split])
        .map_err(|_| "non-UTF8 HTTP headers from JWKS endpoint".to_string())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed HTTP status line: {status_line:?}"))?;
    if status_code != 200 {
        return Err(format!("JWKS endpoint returned HTTP {status_code}"));
    }
    let mut is_chunked = false;
    let mut content_len: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            } else if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse::<usize>().ok();
            }
        }
    }
    let body = &raw[split + 4..];
    if is_chunked {
        decode_chunked_body(body)
    } else if let Some(n) = content_len {
        if body.len() < n {
            return Err("truncated JWKS response body".into());
        }
        Ok(body[..n].to_vec())
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let crlf = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed HTTP chunk header".to_string())?;
        let size_hex = std::str::from_utf8(&body[..crlf])
            .map_err(|_| "invalid HTTP chunk size".to_string())?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid HTTP chunk size {size_hex:?}"))?;
        body = &body[crlf + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("truncated HTTP chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

// ---------------------------------------------------------------------------
// Minimal DER / X.509 / SPKI parser
// ---------------------------------------------------------------------------

struct ParsedSpki {
    oid: Vec<u8>,
    params_oid: Option<Vec<u8>>,
    bits: Vec<u8>,
}

fn decode_pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(s) = rest.find(&begin) {
        let after_begin = &rest[s + begin.len()..];
        let Some(e) = after_begin.find(&end) else {
            break;
        };
        let b64: String = after_begin[..e]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if let Some(bytes) = crate::v2::unbase64(&b64) {
            out.push(bytes);
        }
        rest = &after_begin[e + end.len()..];
    }
    out
}

fn read_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let &tag = data
        .first()
        .ok_or_else(|| "unexpected end of DER".to_string())?;
    let &len_b = data
        .get(1)
        .ok_or_else(|| "unexpected end of DER length".to_string())?;
    let (len, hdr) = if len_b < 0x80 {
        (len_b as usize, 2usize)
    } else {
        let n = (len_b & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err("unsupported DER length".into());
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (l, 2 + n)
    };
    if data.len() < hdr + len {
        return Err("truncated DER element".into());
    }
    Ok((tag, &data[hdr..hdr + len], &data[hdr + len..]))
}

fn extract_cert_spki(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (tag, cert_seq, _) = read_tlv(cert_der)?;
    if tag != 0x30 {
        return Err("X.509 certificate is not a DER SEQUENCE".into());
    }
    let (tbs_tag, mut tbs, _) = read_tlv(cert_seq)?;
    if tbs_tag != 0x30 {
        return Err("X.509 tbsCertificate is not a DER SEQUENCE".into());
    }
    // Skip optional EXPLICIT [0] version.
    if tbs.first() == Some(&0xa0) {
        let (_, _, rest) = read_tlv(tbs)?;
        tbs = rest;
    }
    // Skip serialNumber, signature, issuer, validity, subject (5 fields).
    for _ in 0..5 {
        let (_, _, rest) = read_tlv(tbs)?;
        tbs = rest;
    }
    let (spki_tag, spki_body, _) = read_tlv(tbs)?;
    if spki_tag != 0x30 {
        return Err("X.509 subjectPublicKeyInfo is not a DER SEQUENCE".into());
    }
    // Reconstruct raw SPKI SEQUENCE slice from prefix before `spki_body`.
    let consumed = tbs.len() - spki_body.len();
    let mut spki = Vec::with_capacity(consumed + spki_body.len());
    spki.extend_from_slice(&tbs[..consumed + spki_body.len()]);
    Ok(spki)
}

fn parse_spki_raw(spki_der: &[u8]) -> Result<ParsedSpki, String> {
    let (tag, inner, _) = read_tlv(spki_der)?;
    if tag != 0x30 {
        return Err("SubjectPublicKeyInfo is not a DER SEQUENCE".into());
    }
    let (alg_tag, alg_seq, rest) = read_tlv(inner)?;
    if alg_tag != 0x30 {
        return Err("SPKI AlgorithmIdentifier is not a DER SEQUENCE".into());
    }
    let (oid_tag, oid_bytes, alg_rest) = read_tlv(alg_seq)?;
    if oid_tag != 0x06 {
        return Err("SPKI AlgorithmIdentifier missing OID".into());
    }
    let params_oid = if !alg_rest.is_empty() {
        let (ptag, pbody, _) = read_tlv(alg_rest)?;
        if ptag == 0x06 {
            Some(pbody.to_vec())
        } else {
            None
        }
    } else {
        None
    };
    let (bit_tag, bit_body, _) = read_tlv(rest)?;
    if bit_tag != 0x03 || bit_body.is_empty() || bit_body[0] != 0x00 {
        return Err("SPKI missing valid BIT STRING public key".into());
    }
    Ok(ParsedSpki {
        oid: oid_bytes.to_vec(),
        params_oid,
        bits: bit_body[1..].to_vec(),
    })
}

fn parse_spki_key(spki_der: &[u8]) -> Result<VerifiedKey, String> {
    let spki = parse_spki_raw(spki_der)?;
    if spki.oid == OID_RSA_ENCRYPTION {
        let (seq_tag, mut body, _) = read_tlv(&spki.bits)?;
        if seq_tag != 0x30 {
            return Err("RSA public key BIT STRING is not a DER SEQUENCE".into());
        }
        let (nt, nb, rest) = read_tlv(body)?;
        body = rest;
        let (et, eb, _) = read_tlv(body)?;
        if nt != 0x02 || et != 0x02 {
            return Err("RSA public key missing INTEGER modulus/exponent".into());
        }
        return Ok(VerifiedKey::Rsa {
            n: trim_leading_zeros(nb).to_vec(),
            e: trim_leading_zeros(eb).to_vec(),
        });
    }
    if spki.oid == OID_EC_PUBLIC_KEY {
        let Some(curve) = spki.params_oid.as_deref() else {
            return Err("EC public key missing namedCurve parameter OID".into());
        };
        if curve == OID_CURVE_P256 {
            if spki.bits.first() != Some(&0x04) || spki.bits.len() != 65 {
                return Err("expected uncompressed EC P-256 public point".into());
            }
            return Ok(VerifiedKey::EcP256(spki.bits));
        }
        if curve == OID_CURVE_P384 {
            if spki.bits.first() != Some(&0x04) || spki.bits.len() != 97 {
                return Err("expected uncompressed EC P-384 public point".into());
            }
            return Ok(VerifiedKey::EcP384(spki.bits));
        }
        if curve == OID_CURVE_P521 {
            if spki.bits.first() != Some(&0x04) || spki.bits.len() != 133 {
                return Err("expected uncompressed EC P-521 public point".into());
            }
            return Ok(VerifiedKey::EcP521 {
                x: spki.bits[1..67].to_vec(),
                y: spki.bits[67..133].to_vec(),
            });
        }
        return Err("unsupported EC curve OID in SPKI".into());
    }
    Err("unsupported public key algorithm OID in SPKI".into())
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let idx = bytes.iter().take_while(|b| **b == 0).count();
    &bytes[idx..]
}

// ---------------------------------------------------------------------------
// NIST P-521 ECDSA verification (ES512 / SHA-512)
// ---------------------------------------------------------------------------

struct P521Params {
    p: BigUint,
    n: BigUint,
    a: BigUint,
    b: BigUint,
    gx: BigUint,
    gy: BigUint,
}

fn p521_params() -> P521Params {
    // p = 2^521 - 1
    let mut p_bytes = vec![0xffu8; 66];
    p_bytes[0] = 0x01;
    let p = BigUint::from_bytes_be(&p_bytes);
    let a = &p - 3u32;
    let b = BigUint::from_bytes_be(&[
        0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6,
        0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91,
        0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0,
        0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45,
        0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00,
    ]);
    let n = BigUint::from_bytes_be(&[
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ]);
    let gx = BigUint::from_bytes_be(&[
        0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e, 0xcb, 0x66, 0x23,
        0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60,
        0x6b, 0x4d, 0x3d, 0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1,
        0x27, 0xa2, 0xff, 0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e,
        0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66,
    ]);
    let gy = BigUint::from_bytes_be(&[
        0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c,
        0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17,
        0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50, 0xb9,
        0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe,
        0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50,
    ]);
    P521Params { p, n, a, b, gx, gy }
}

#[derive(Clone)]
struct JacPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    inf: bool,
}

impl JacPoint {
    fn infinity() -> Self {
        Self {
            x: BigUint::ZERO,
            y: BigUint::ZERO,
            z: BigUint::ZERO,
            inf: true,
        }
    }

    fn from_affine(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            z: BigUint::from(1u32),
            inf: false,
        }
    }
}

fn mod_sub(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    let a = a % m;
    let b = b % m;
    if a >= b {
        a - b
    } else {
        m + a - b
    }
}

fn mod_half(a: &BigUint, p: &BigUint) -> BigUint {
    let a = a % p;
    if a.bit(0) {
        (a + p) >> 1
    } else {
        a >> 1
    }
}

fn p521_double(pt: &JacPoint, p: &BigUint) -> JacPoint {
    if pt.inf || pt.y == BigUint::ZERO {
        return JacPoint::infinity();
    }
    let z2 = (&pt.z * &pt.z) % p;
    let t2 = mod_sub(&pt.x, &z2, p);
    let t1 = (&pt.x + &z2) % p;
    let m = (3u32 * ((t2 * t1) % p)) % p;

    let two_y = (2u32 * &pt.y) % p;
    let z3 = (&two_y * &pt.z) % p;
    let four_y2 = (&two_y * &two_y) % p;
    let s = (&four_y2 * &pt.x) % p;
    let sixteen_y4 = (&four_y2 * &four_y2) % p;
    let t = mod_half(&sixteen_y4, p);

    let m2 = (&m * &m) % p;
    let two_s = (2u32 * &s) % p;
    let x3 = mod_sub(&m2, &two_s, p);
    let s_minus_x3 = mod_sub(&s, &x3, p);
    let y3 = mod_sub(&((&m * &s_minus_x3) % p), &t, p);
    JacPoint {
        x: x3,
        y: y3,
        z: z3,
        inf: false,
    }
}

fn p521_add(p1: &JacPoint, p2: &JacPoint, p: &BigUint) -> JacPoint {
    if p1.inf {
        return p2.clone();
    }
    if p2.inf {
        return p1.clone();
    }
    let z1z1 = (&p1.z * &p1.z) % p;
    let z2z2 = (&p2.z * &p2.z) % p;
    let u1 = (&p1.x * &z2z2) % p;
    let u2 = (&p2.x * &z1z1) % p;
    let z1_3 = (&z1z1 * &p1.z) % p;
    let z2_3 = (&z2z2 * &p2.z) % p;
    let s1 = (&p1.y * &z2_3) % p;
    let s2 = (&p2.y * &z1_3) % p;

    let h = mod_sub(&u2, &u1, p);
    let r = mod_sub(&s2, &s1, p);
    if h == BigUint::ZERO {
        return if r == BigUint::ZERO {
            p521_double(p1, p)
        } else {
            JacPoint::infinity()
        };
    }
    let h2 = (&h * &h) % p;
    let h3 = (&h2 * &h) % p;
    let v = (&u1 * &h2) % p;
    let r2 = (&r * &r) % p;
    let two_v = (2u32 * &v) % p;
    let x3 = mod_sub(&mod_sub(&r2, &h3, p), &two_v, p);
    let v_minus_x3 = mod_sub(&v, &x3, p);
    let y3 = mod_sub(&((&r * &v_minus_x3) % p), &((&s1 * &h3) % p), p);
    let z3 = (((&p1.z * &p2.z) % p) * &h) % p;
    JacPoint {
        x: x3,
        y: y3,
        z: z3,
        inf: false,
    }
}

fn p521_scalar_mul(base: &JacPoint, scalar: &BigUint, p: &BigUint) -> JacPoint {
    let mut acc = JacPoint::infinity();
    for bit in (0..scalar.bits()).rev() {
        acc = p521_double(&acc, p);
        if scalar.bit(bit) {
            acc = p521_add(&acc, base, p);
        }
    }
    acc
}

fn verify_es512(qx_bytes: &[u8], qy_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 132 {
        return false;
    }
    let c = p521_params();
    let qx = BigUint::from_bytes_be(qx_bytes);
    let qy = BigUint::from_bytes_be(qy_bytes);
    if qx >= c.p || qy >= c.p || (qx == BigUint::ZERO && qy == BigUint::ZERO) {
        return false;
    }
    // Check Q on curve: y^2 == x^3 + a*x + b (mod p).
    let lhs = (&qy * &qy) % &c.p;
    let x2 = (&qx * &qx) % &c.p;
    let x3 = (&x2 * &qx) % &c.p;
    let ax = (&c.a * &qx) % &c.p;
    let rhs = (x3 + ax + &c.b) % &c.p;
    if lhs != rhs {
        return false;
    }
    let r = BigUint::from_bytes_be(&sig[..66]);
    let s = BigUint::from_bytes_be(&sig[66..]);
    if r == BigUint::ZERO || s == BigUint::ZERO || r >= c.n || s >= c.n {
        return false;
    }
    let digest = Sha512::digest(msg);
    // SHA-512 produces 512 bits (< 521 bits of P-521 order n), so no right-shift per FIPS 186-4.
    let z = BigUint::from_bytes_be(&digest) % &c.n;
    let w = s.modpow(&(&c.n - 2u32), &c.n);
    let u1 = (&z * &w) % &c.n;
    let u2 = (&r * &w) % &c.n;

    let g = JacPoint::from_affine(c.gx, c.gy);
    let q = JacPoint::from_affine(qx, qy);
    let r_pt = p521_add(
        &p521_scalar_mul(&g, &u1, &c.p),
        &p521_scalar_mul(&q, &u2, &c.p),
        &c.p,
    );
    if r_pt.inf || r_pt.z == BigUint::ZERO {
        return false;
    }
    let z2 = (&r_pt.z * &r_pt.z) % &c.p;
    let z2_inv = z2.modpow(&(&c.p - 2u32), &c.p);
    let rx = (r_pt.x * z2_inv) % &c.p;
    (rx % &c.n) == r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn es512_verifies_valid_p521_signature_and_rejects_tampered() {
        // Test vector generated over NIST P-521 / SHA-512 (JWS IEEE-P1363 format):
        // Verify with private scalar d = 7: Q = 7*G; compute k = 11 -> (r, s) for msg = "hdr.pay".
        let c = p521_params();
        let g = JacPoint::from_affine(c.gx.clone(), c.gy.clone());
        let d = BigUint::from(7u32);
        let q_jac = p521_scalar_mul(&g, &d, &c.p);
        let z_inv = q_jac.z.modpow(&(&c.p - 2u32), &c.p);
        let z2_inv = (&z_inv * &z_inv) % &c.p;
        let z3_inv = (&z2_inv * &z_inv) % &c.p;
        let qx = (&q_jac.x * &z2_inv) % &c.p;
        let qy = (&q_jac.y * &z3_inv) % &c.p;
        let qx_bytes = pad_big_endian(&qx.to_bytes_be(), 66).unwrap();
        let qy_bytes = pad_big_endian(&qy.to_bytes_be(), 66).unwrap();

        let msg = b"eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiJ1MSJ9";
        let z = BigUint::from_bytes_be(&Sha512::digest(msg)) % &c.n;
        let k = BigUint::from(11u32);
        let k_jac = p521_scalar_mul(&g, &k, &c.p);
        let kz2 = (&k_jac.z * &k_jac.z) % &c.p;
        let rx = (&k_jac.x * kz2.modpow(&(&c.p - 2u32), &c.p)) % &c.p;
        let r = rx % &c.n;
        let k_inv = k.modpow(&(&c.n - 2u32), &c.n);
        let s = (k_inv * ((z + &r * &d) % &c.n)) % &c.n;
        let mut sig = pad_big_endian(&r.to_bytes_be(), 66).unwrap();
        sig.extend_from_slice(&pad_big_endian(&s.to_bytes_be(), 66).unwrap());

        let key = VerifiedKey::EcP521 {
            x: qx_bytes,
            y: qy_bytes,
        };
        assert!(verify_jwt_signature(&key, "ES512", msg, &sig));
        assert!(!verify_jwt_signature(&key, "ES256", msg, &sig));
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(!verify_jwt_signature(&key, "ES512", msg, &bad_sig));
    }

    #[test]
    fn jwks_cache_requires_kid_and_refreshes_on_miss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let c = p521_params();
        let gx_b64 = base64url_encode(&pad_big_endian(&c.gx.to_bytes_be(), 66).unwrap());
        let gy_b64 = base64url_encode(&pad_big_endian(&c.gy.to_bytes_be(), 66).unwrap());
        let body1 = serde_json::to_vec(&json!({
            "keys": [{ "kty": "EC", "crv": "P-521", "kid": "k1", "use": "sig", "x": gx_b64, "y": gy_b64 }]
        }))
        .unwrap();
        let body2 = serde_json::to_vec(&json!({
            "keys": [{ "kty": "EC", "crv": "P-521", "kid": "k2", "use": "sig", "x": gx_b64, "y": gy_b64 }]
        }))
        .unwrap();

        let h = std::thread::spawn(move || {
            for (i, b) in [body1, body2].into_iter().enumerate() {
                let (mut s, _) = listener.accept().unwrap();
                let mut req_buf = [0u8; 512];
                let _ = s.read(&mut req_buf);
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                );
                let _ = s.write_all(hdr.as_bytes());
                let _ = s.write_all(&b);
                if i == 1 {
                    break;
                }
            }
        });

        let cache = JwksCache::new(JwksCacheConfig::default());
        let url = format!("http://127.0.0.1:{port}/.well-known/jwks.json");
        assert!(cache.resolve_key(&url, "").is_err());
        assert!(matches!(
            cache.resolve_key(&url, "k1"),
            Ok(VerifiedKey::EcP521 { .. })
        ));
        // Cache hit does not hit server again for k1:
        assert!(cache.resolve_key(&url, "k1").is_ok());
        // Unknown kid triggers refresh -> gets k2:
        assert!(cache.resolve_key(&url, "k2").is_ok());
        h.join().unwrap();
    }
}
