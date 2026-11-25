//! A plain HTTP/1.1 client for a participant's JSON Ledger API, shared by `canton-rs script --ledger-host`, `canton-rs console`, `pqs` and
//! `localnet status`.
//!
//! [CANTON-NOTE: LIMITATION] Plain HTTP only (no TLS; `https://` is not supported), one connection per call; a bearer token is optional
//! ([`call_with_token`]).
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::Value as Json;

const MAX_HTTP_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// One request. `body` is sent with `content_type`; the answer is the status and the body read as JSON (a body that is not JSON comes
/// back as a JSON string, an empty one as `null`).
pub fn call(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&[u8], &str)>,
) -> Result<(u16, Json), String> {
    call_with_token(host, port, method, path, body, None)
}

/// [`call`] with an `Authorization: Bearer <token>` header (a participant that checks JWTs, `canton-rs json-api --jwt-hmac-secret`).
pub fn call_with_token(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<(&[u8], &str)>,
    token: Option<&str>,
) -> Result<(u16, Json), String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("cannot reach the JSON Ledger API at {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    let (payload, content_type): (&[u8], &str) = body.unwrap_or((b"", "application/json"));
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: {content_type}\r\nAccept: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(payload))
        .map_err(|e| format!("{method} {path}: {e}"))?;
    let mut raw = Vec::new();
    stream
        .take(MAX_HTTP_RESPONSE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("{method} {path}: {e}"))?;
    if raw.len() as u64 > MAX_HTTP_RESPONSE_BYTES {
        return Err(format!(
            "{method} {path}: HTTP response exceeded {MAX_HTTP_RESPONSE_BYTES} byte limit"
        ));
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("{method} {path}: no HTTP header in the answer"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body_bytes = raw[split + 4..].to_vec();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("{method} {path}: bad status line"))?;
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        body_bytes = dechunk(&body_bytes);
    }
    let json = if body_bytes.is_empty() {
        Json::Null
    } else {
        serde_json::from_slice(&body_bytes)
            .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(&body_bytes).to_string()))
    };
    Ok((status, json))
}

/// [`call`] with a JSON body.
pub fn call_json(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&Json>,
) -> Result<(u16, Json), String> {
    let text = body.map(|b| b.to_string());
    call(
        host,
        port,
        method,
        path,
        text.as_deref().map(|t| (t.as_bytes(), "application/json")),
    )
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let Some(eol) = body[at..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_text = String::from_utf8_lossy(&body[at..at + eol]).to_string();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        at += eol + 2;
        if size == 0 || at + size > body.len() {
            break;
        }
        out.extend_from_slice(&body[at..at + size]);
        at += size + 2;
    }
    out
}

/// The `code: cause` of a Ledger API error answer, or the whole body.
pub fn error_cause(body: &Json) -> String {
    match body {
        Json::Object(o) => match (o.get("code"), o.get("cause")) {
            (Some(code), Some(cause)) => format!(
                "{}: {}",
                code.as_str().unwrap_or_default(),
                cause.as_str().unwrap_or_default()
            ),
            _ => body.to_string(),
        },
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_responses_exceeding_max_byte_cap() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let h = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                let chunk = vec![b'a'; 1024 * 1024];
                for _ in 0..66 {
                    if s.write_all(&chunk).is_err() {
                        break;
                    }
                }
            }
        });
        let err = call("127.0.0.1", port, "GET", "/huge", None)
            .expect_err("66 MiB body must trip 64 MiB cap");
        assert!(err.contains("byte limit"), "got: {err}");
        let _ = h.join();
    }
}
