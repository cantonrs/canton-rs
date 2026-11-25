//! RFC 6455 WebSocket server for Canton JSON Ledger API v2 AsyncAPI streaming channels:
//! `/v2/updates`, `/v2/updates/flats`, `/v2/updates/trees`, `/v2/state/active-contracts`,
//! `/v2/commands/completions`, `/v2/commands/command-completions`.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use serde_json::{json, Value as Json};

use crate::http::{write_http_response, HttpRequest, HttpResponse};
use crate::service::ExecutionService;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// RAII tracker decremented when a WebSocket streaming connection closes or disconnects (`S-DX-005`).
struct WsSubscriptionGuard<'a>(&'a ExecutionService);

impl<'a> WsSubscriptionGuard<'a> {
    fn new(service: &'a ExecutionService) -> Self {
        service.observability.inc_ws_subscriptions();
        Self(service)
    }
}

impl Drop for WsSubscriptionGuard<'_> {
    fn drop(&mut self) {
        self.0.observability.dec_ws_subscriptions();
    }
}

/// Returns `true` when `req` is an HTTP/1.1 WebSocket upgrade handshake.
pub fn is_websocket_upgrade(req: &HttpRequest) -> bool {
    let has_upgrade = req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"));
    let has_key = req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("sec-websocket-key") && !v.trim().is_empty());
    has_upgrade && has_key
}

fn is_supported_channel(path: &str) -> bool {
    matches!(
        path.trim_end_matches('/'),
        "/v2/updates"
            | "/v2/updates/flats"
            | "/v2/updates/trees"
            | "/v2/state/active-contracts"
            | "/v2/commands/completions"
            | "/v2/commands/command-completions"
    )
}

/// Computes `Sec-WebSocket-Accept` for a client `Sec-WebSocket-Key`.
pub fn accept_key(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_GUID.len());
    input.extend_from_slice(client_key.trim().as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    crate::v2::base64(hash.as_ref())
}

/// Handles a WebSocket upgrade request on the accepted TCP stream, preserving buffered bytes.
pub fn handle_connection(
    service: Arc<ExecutionService>,
    mut reader: BufReader<TcpStream>,
    peer: SocketAddr,
    req: HttpRequest,
    shutdown: Arc<AtomicBool>,
) {
    let path = req.path.trim_end_matches('/').to_string();
    crate::http::log_request(&req, &peer.to_string(), None);

    if !is_supported_channel(&path) {
        let resp = HttpResponse::json(
            404,
            &json!({
                "errors": [format!("HttpMethod(GET), uri: http://localhost{}", req.path)],
                "status": 404,
                "ledgerApiError": null
            }),
        );
        crate::http::log_request(&req, &peer.to_string(), Some(resp.status));
        let _ = write_http_response(reader.get_mut(), &resp);
        return;
    }

    if let Some(denied) = crate::auth::check(&service, &req) {
        crate::http::log_request(&req, &peer.to_string(), Some(denied.status));
        let _ = write_http_response(reader.get_mut(), &denied);
        return;
    }

    let Some(ws_key) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
        .map(|(_, v)| v.trim().to_string())
    else {
        let resp = HttpResponse::error_json(400, "Missing Sec-WebSocket-Key header");
        let _ = write_http_response(reader.get_mut(), &resp);
        return;
    };

    let wants_daml_proto = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-protocol"))
        .is_some_and(|(_, v)| {
            v.split(',')
                .any(|p| p.trim() == "daml.ws.auth" || p.trim().starts_with("jwt.token."))
        });

    let mut handshake = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n",
        accept_key(&ws_key)
    );
    if wants_daml_proto {
        handshake.push_str("Sec-WebSocket-Protocol: daml.ws.auth\r\n");
    }
    handshake.push_str("\r\n");
    if reader.get_mut().write_all(handshake.as_bytes()).is_err()
        || reader.get_mut().flush().is_err()
    {
        return;
    }
    crate::http::log_request(&req, &peer.to_string(), Some(101));
    let _sub_guard = WsSubscriptionGuard::new(&service);

    let _ = reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(200)));

    let initial_payload = match read_next_message(&mut reader, &shutdown) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            let _ = write_close_frame(reader.get_mut(), 1000, "normal closure");
            return;
        }
        Err(_) => {
            let _ = write_close_frame(reader.get_mut(), 1002, "protocol error");
            return;
        }
    };

    let initial_payload = match crate::auth::check_ws_payload(&service, &req, &initial_payload) {
        Ok(filled) => filled.unwrap_or(initial_payload),
        Err(denied) => {
            let _ = write_text_frame(reader.get_mut(), &denied.body);
            let _ = write_close_frame(reader.get_mut(), 1000, "permission denied");
            return;
        }
    };

    let Ok(initial_json) = serde_json::from_slice::<Json>(&initial_payload) else {
        let err = crate::v2_commands::bad_body("Invalid value for: body".into());
        let _ = write_text_frame(reader.get_mut(), &err.body);
        let _ = write_close_frame(reader.get_mut(), 1000, "invalid request");
        return;
    };

    if path == "/v2/state/active-contracts" {
        serve_acs(&service, &mut reader, &req, initial_payload);
        return;
    }

    serve_offset_stream(&service, &mut reader, &req, &path, &initial_json, &shutdown);
}

fn build_sub_request(template: &HttpRequest, path: &str, body: Vec<u8>) -> HttpRequest {
    let mut sub = template.clone();
    sub.method = "POST".to_string();
    sub.path = path.to_string();
    sub.body = body;
    sub
}

fn dispatch_snapshot_route(
    service: &ExecutionService,
    path: &str,
    req: &HttpRequest,
) -> HttpResponse {
    let effective = crate::v2::expand_any_party(service.v2_state(), req);
    let r = effective.as_ref().unwrap_or(req);
    crate::v2_updates::with_unbounded_stream_list(|| match path {
        "/v2/updates" => crate::v2_updates::updates(service, r),
        "/v2/updates/flats" => crate::v2_updates::updates_with_default_shape(service, r, false),
        "/v2/updates/trees" => crate::v2_updates::updates_with_default_shape(service, r, true),
        "/v2/state/active-contracts" => crate::v2_commands::active_contracts(service, r),
        "/v2/commands/completions" => crate::v2_completions::completions(service, r, true),
        "/v2/commands/command-completions" => crate::v2_completions::completions(service, r, false),
        _ => HttpResponse::error_json(404, "unknown channel"),
    })
}

fn serve_acs(
    service: &ExecutionService,
    reader: &mut BufReader<TcpStream>,
    req: &HttpRequest,
    payload: Vec<u8>,
) {
    let sub_req = build_sub_request(req, "/v2/state/active-contracts", payload);
    let resp = dispatch_snapshot_route(service, "/v2/state/active-contracts", &sub_req);
    if send_response_frames(reader.get_mut(), &resp).is_ok() {
        let _ = write_close_frame(reader.get_mut(), 1000, "complete");
    }
}

fn serve_offset_stream(
    service: &ExecutionService,
    reader: &mut BufReader<TcpStream>,
    req: &HttpRequest,
    path: &str,
    initial_json: &Json,
    shutdown: &AtomicBool,
) {
    let begin = initial_json
        .get("beginExclusive")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
        .unwrap_or(0);
    let end_inclusive = initial_json
        .get("endInclusive")
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));

    let current_end = service.v2_state().ledger_end.load(Ordering::SeqCst);
    let first_req_json = if end_inclusive.is_none() {
        let mut copy = initial_json.clone();
        if let Some(obj) = copy.as_object_mut() {
            obj.insert("endInclusive".into(), json!(current_end));
        }
        copy
    } else {
        initial_json.clone()
    };
    let first_body = serde_json::to_vec(&first_req_json).unwrap_or_default();
    let first_sub = build_sub_request(req, path, first_body);
    let first_resp = dispatch_snapshot_route(service, path, &first_sub);
    if first_resp.status != 200 {
        let _ = write_text_frame(reader.get_mut(), &first_resp.body);
        let _ = write_close_frame(reader.get_mut(), 1000, "error");
        return;
    }
    if send_response_frames(reader.get_mut(), &first_resp).is_err() {
        return;
    }
    let mut cursor = end_inclusive.unwrap_or(current_end);
    if let Some(limit) = end_inclusive {
        if cursor >= limit {
            let _ = write_close_frame(reader.get_mut(), 1000, "complete");
            return;
        }
    }
    let _ = begin;

    let mut auth = crate::auth_stream::StreamAuthorization::capture_request(service, req);
    let end_with = |reader: &mut BufReader<TcpStream>, refusal: HttpResponse| {
        let _ = write_text_frame(reader.get_mut(), &refusal.body);
        let _ = write_close_frame(reader.get_mut(), 1000, "error");
    };
    // Live-tailing loop until `shutdown` or client disconnect/close.
    while !shutdown.load(Ordering::SeqCst) {
        if let Err(refusal) = auth.periodic(service) {
            end_with(reader, refusal);
            return;
        }
        match poll_control_frame(reader) {
            Ok(PollControl::Closed) | Err(_) => return,
            Ok(PollControl::Continue) => {}
        }
        let next_end = service.v2_state().ledger_end.load(Ordering::SeqCst);
        if next_end > cursor {
            let mut next_json = initial_json.clone();
            if let Some(obj) = next_json.as_object_mut() {
                obj.insert("beginExclusive".into(), json!(cursor));
                obj.insert("endInclusive".into(), json!(next_end));
            }
            let body = serde_json::to_vec(&next_json).unwrap_or_default();
            let sub = build_sub_request(req, path, body);
            let resp = dispatch_snapshot_route(service, path, &sub);
            if resp.status != 200 {
                let _ = write_text_frame(reader.get_mut(), &resp.body);
                let _ = write_close_frame(reader.get_mut(), 1000, "error");
                return;
            }
            // Suppress initial offsetCheckpoint when no new completion actually landed above `cursor`.
            let items = extract_array_items(&resp.body);
            let mut sent_any = false;
            for item in &items {
                let is_ckpt_only = item
                    .pointer("/completionResponse/OffsetCheckpoint")
                    .is_some();
                if is_ckpt_only && !path.starts_with("/v2/commands/") {
                    continue;
                }
                if let Err(refusal) = auth.before_element() {
                    end_with(reader, refusal);
                    return;
                }
                let raw = serde_json::to_vec(item).unwrap_or_default();
                if write_text_frame(reader.get_mut(), &raw).is_err() {
                    return;
                }
                sent_any = true;
            }
            let _ = sent_any;
            cursor = next_end;
        } else {
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    let _ = write_close_frame(reader.get_mut(), 1001, "shutdown");
}

fn extract_array_items(body: &[u8]) -> Vec<Json> {
    match serde_json::from_slice::<Json>(body) {
        Ok(Json::Array(arr)) => arr,
        Ok(other) => vec![other],
        Err(_) => Vec::new(),
    }
}

fn send_response_frames(stream: &mut TcpStream, resp: &HttpResponse) -> std::io::Result<()> {
    if resp.status != 200 {
        write_text_frame(stream, &resp.body)?;
        return Ok(());
    }
    for item in extract_array_items(&resp.body) {
        let bytes = serde_json::to_vec(&item).unwrap_or_default();
        write_text_frame(stream, &bytes)?;
    }
    Ok(())
}

enum PollControl {
    Continue,
    Closed,
}

enum Frame {
    Data {
        fin: bool,
        opcode: u8,
        payload: Vec<u8>,
    },
    Ping(Vec<u8>),
    Pong,
    Close,
}

fn poll_control_frame(reader: &mut BufReader<TcpStream>) -> std::io::Result<PollControl> {
    match read_frame(reader) {
        Ok(Some(Frame::Ping(data))) => {
            write_raw_frame(reader.get_mut(), 0x8a, &data)?;
            Ok(PollControl::Continue)
        }
        Ok(Some(Frame::Close)) => {
            let _ = write_close_frame(reader.get_mut(), 1000, "bye");
            Ok(PollControl::Closed)
        }
        Ok(Some(_)) => Ok(PollControl::Continue),
        Ok(None) => Ok(PollControl::Closed),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(PollControl::Continue)
        }
        Err(_) => Ok(PollControl::Closed),
    }
}

fn read_next_message(
    reader: &mut BufReader<TcpStream>,
    shutdown: &AtomicBool,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut acc = Vec::new();
    let mut expecting_cont = false;
    while !shutdown.load(Ordering::SeqCst) {
        match read_frame(reader) {
            Ok(Some(Frame::Ping(data))) => {
                write_raw_frame(reader.get_mut(), 0x8a, &data)?;
            }
            Ok(Some(Frame::Pong)) => {}
            Ok(Some(Frame::Close)) => return Ok(None),
            Ok(Some(Frame::Data {
                fin,
                opcode,
                payload,
            })) => {
                if opcode == 0x01 || opcode == 0x02 {
                    if expecting_cont {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "unexpected new data frame during fragmented message",
                        ));
                    }
                    acc.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(acc));
                    }
                    expecting_cont = true;
                } else if opcode == 0x00 && expecting_cont {
                    if acc.len() + payload.len() > MAX_FRAME_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "fragmented frame exceeds max size",
                        ));
                    }
                    acc.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(acc));
                    }
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid WebSocket opcode sequence",
                    ));
                }
            }
            Ok(None) => return Ok(None),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn read_frame(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<Frame>> {
    let mut hdr = [0u8; 2];
    match reader.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
    let len7 = (hdr[1] & 0x7f) as u64;
    let payload_len = match len7 {
        126 => {
            let mut ext = [0u8; 2];
            reader.read_exact(&mut ext)?;
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext)?;
            let n = u64::from_be_bytes(ext);
            usize::try_from(n).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "frame length overflow")
            })?
        }
        n => n as usize,
    };
    if payload_len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WebSocket frame too large",
        ));
    }
    let mut mask = [0u8; 4];
    if masked {
        reader.read_exact(&mut mask)?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload)?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some(match opcode {
        0x08 => Frame::Close,
        0x09 => Frame::Ping(payload),
        0x0a => Frame::Pong,
        _ => Frame::Data {
            fin,
            opcode,
            payload,
        },
    }))
}

/// Writes an unmasked RFC 6455 text frame to `stream`.
pub fn write_text_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    write_raw_frame(stream, 0x81, payload)
}

/// Writes an unmasked RFC 6455 close frame to `stream`.
pub fn write_close_frame(stream: &mut TcpStream, code: u16, reason: &str) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(2 + reason.len());
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(reason.as_bytes());
    write_raw_frame(stream, 0x88, &buf)
}

fn write_raw_frame(stream: &mut TcpStream, first_byte: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = Vec::with_capacity(10);
    hdr.push(first_byte);
    let len = payload.len();
    if len < 126 {
        hdr.push(len as u8);
    } else if len <= 0xffff {
        hdr.push(126);
        hdr.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        hdr.push(127);
        hdr.extend_from_slice(&(len as u64).to_be_bytes());
    }
    stream.write_all(&hdr)?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    stream.flush()
}
