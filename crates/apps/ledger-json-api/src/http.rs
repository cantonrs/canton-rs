use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub use crate::http_limits::HttpLimits;
use crate::http_limits::{ConnectionGate, Deadline, ReadError};
use crate::models::json_api::{
    CreateRequest, ExerciseRequest, JsonApiErrorResponse, QueryContractsRequest,
};
use crate::models::ledger_api::SubmitAndWaitRequest;
use crate::service::ExecutionService;

/// Raw HTTP Request structure.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Builds an in-memory `POST` JSON request for embedded [`CantonNodeBuilder`](crate::CantonNodeBuilder) calls.
    pub fn json_post(path: &str, body_json: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(body_json).unwrap_or_default();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            method: "POST".to_string(),
            path: path.to_string(),
            query_params: HashMap::new(),
            headers,
            body,
        }
    }
}

/// Raw HTTP Response structure.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body_json: &serde_json::Value) -> Self {
        let body = serde_json::to_vec(body_json).unwrap_or_default();
        let status_text = match status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            413 => "Payload Too Large",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
        }
        .to_string();

        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("Content-Length".into(), body.len().to_string());
        headers.insert("Connection".into(), "close".into());

        Self {
            status,
            status_text,
            headers,
            body,
        }
    }

    pub fn ok_json<T: serde::Serialize>(val: &T) -> Self {
        let json_val = serde_json::to_value(val).unwrap_or(serde_json::Value::Null);
        Self::json(200, &json_val)
    }

    pub fn error_json(status: u16, err_msg: impl Into<String>) -> Self {
        let err_response = JsonApiErrorResponse::new(status, err_msg);
        let json_val = serde_json::to_value(&err_response).unwrap_or(serde_json::Value::Null);
        Self::json(status, &json_val)
    }
}

/// Parse comma-separated list of parties from header or query param.
fn parse_party_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Extract act_as and read_as parties from headers (supporting Daml JWT and raw auth).
pub(crate) fn extract_parties(req: &HttpRequest) -> (Vec<String>, Vec<String>) {
    let mut act_as = Vec::new();
    let mut read_as = Vec::new();
    if let Some(hdr) = req.headers.get("x-daml-act-as") {
        act_as.extend(parse_party_list(hdr));
    }
    if let Some(hdr) = req.headers.get("x-daml-read-as") {
        read_as.extend(parse_party_list(hdr));
    }
    if let Some(party_param) = req.query_params.get("party") {
        read_as.extend(parse_party_list(party_param));
    }
    if let Some(auth_hdr) = req.headers.get("authorization") {
        let token = auth_hdr.strip_prefix("Bearer ").unwrap_or(auth_hdr);
        if let Ok(claims) = crate::ledger_v2::JwtClaims::parse_bearer_token(token) {
            act_as.extend(claims.act_as);
            read_as.extend(claims.read_as);
        } else {
            act_as.extend(parse_party_list(token));
        }
    }
    (act_as, read_as)
}

/// Returns `true` for Ledger API write/command endpoints blocked while quiesced for snapshotting.
fn is_command_or_write_path(method: &str, path: &str) -> bool {
    let clean = path.trim_end_matches('/');
    match method {
        "POST" => {
            clean.starts_with("/v2/commands/submit")
                || clean == "/v2/commands/async/submit"
                || clean == "/v2/commands/async/submit-reassignment"
                || clean.starts_with("/v2/interactive-submission/execute")
                || clean == "/v1/create"
                || clean == "/v1/exercise"
                || clean == "/v1/command/submit-and-wait"
                || clean == "/v2/command/submit-and-wait"
                || clean == "/v2/dars"
                || clean == "/v2/packages"
                || clean == "/v2/package-vetting/update"
                || clean == "/v2/admin/prune"
                || clean == "/v2/parties"
                || clean == "/v2/parties/external/allocate"
                || clean == "/v2/users"
                || (clean.starts_with("/v2/users/") && clean.ends_with("/rights"))
                || clean == "/v2/idps"
        }
        "PATCH" | "DELETE" => {
            clean.starts_with("/v2/parties/")
                || clean.starts_with("/v2/users/")
                || clean.starts_with("/v2/idps/")
        }
        _ => false,
    }
}

/// Dispatch and execute an HTTP request against the ExecutionService.
///
/// With a store attached (`ExecutionService::attach_store`) a state-changing request is served under the log lock and
/// recorded before the answer goes out (S-STORE-004); every other request is served as before.
pub fn dispatch_request(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    let _write_guard = if is_command_or_write_path(&req.method, &req.path) {
        match service.try_enter_write() {
            Ok(guard) => Some(guard),
            Err(()) => {
                return HttpResponse::json(
                    503,
                    &serde_json::json!({
                        "code": "NODE_QUIESCED",
                        "cause": "Participant is quiesced for snapshot",
                        "errorCategory": 9,
                    }),
                );
            }
        }
    } else {
        None
    };
    let started = std::time::Instant::now();
    let resp = if crate::store::is_logged(req) && service.has_store() {
        crate::store::dispatch_logged(service, req)
    } else {
        dispatch_checked(service, req)
    };
    if !req
        .headers
        .contains_key(crate::observability::VIA_GRPC_HEADER)
    {
        let method = if resp.status == 401 || resp.status == 403 {
            crate::observability::ObservabilityState::normalize_method(&req.method, "/unauthorized")
        } else {
            crate::observability::ObservabilityState::normalize_method(&req.method, &req.path)
        };
        service
            .observability
            .record_request("http", &method, resp.status, started.elapsed());
    }
    resp
}

/// Authentication, then routing.
pub(crate) fn dispatch_checked(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    // [CANTON-NOTE: SEMANTICS] authentication and rights come first, for every endpoint but the health checks
    match crate::auth::admit(service, req) {
        Ok(None) => route_request(service, req),
        Ok(Some(filled)) => route_request(service, &filled),
        Err(denied) => denied,
    }
}

/// Routing without authentication for internal Admin workflows (`PingService`), bypassing HTTP JWT checks.
pub fn route_internal(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    route_request(service, req)
}

/// Routing without authentication: what replay of the request log runs (the requests were accepted when first served).
pub(crate) fn route_request(service: &ExecutionService, req: &HttpRequest) -> HttpResponse {
    // S-API-001: the Canton-shaped v2 endpoints (and the plain-text health checks) come first
    if let Some(resp) = crate::v2::route(service, req) {
        return resp;
    }
    let clean_path = req.path.trim_end_matches('/');

    match (req.method.as_str(), clean_path) {
        ("GET", "/livez") => HttpResponse::json(200, &serde_json::json!({ "status": "pass" })),
        ("GET", "/readyz") => match service.check_ready() {
            Ok(()) => HttpResponse::json(200, &serde_json::json!({ "status": "pass" })),
            Err(why) => {
                HttpResponse::json(503, &serde_json::json!({ "status": "fail", "reason": why }))
            }
        },
        ("GET", "/v1/version") | ("GET", "/v2/version") => HttpResponse::json(
            200,
            &serde_json::json!({
                "version": "3.7.2",
                "features": {
                    "daml-lf": ["2.1", "2.2", "2.3", "2.4"],
                    "json-api": ["v1", "v2"],
                    "grpc-ledger-api": "v2"
                }
            }),
        ),
        ("GET", "/v1/packages") | ("GET", "/v2/packages") => {
            HttpResponse::ok_json(&service.packages_response())
        }
        ("POST", "/v1/create") => {
            let body_str = match std::str::from_utf8(&req.body) {
                Ok(s) => s,
                Err(_) => return HttpResponse::error_json(400, "Invalid UTF-8 body"),
            };

            let create_req: CreateRequest = match serde_json::from_str(body_str) {
                Ok(r) => r,
                Err(e) => return HttpResponse::error_json(400, format!("Malformed JSON: {e}")),
            };

            let (act_as, _) = extract_parties(req);

            match service.json_create(&act_as, create_req) {
                Ok(resp) => HttpResponse::ok_json(&resp),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("POST", "/v1/exercise") => {
            let body_str = match std::str::from_utf8(&req.body) {
                Ok(s) => s,
                Err(_) => return HttpResponse::error_json(400, "Invalid UTF-8 body"),
            };

            let exercise_req: ExerciseRequest = match serde_json::from_str(body_str) {
                Ok(r) => r,
                Err(e) => return HttpResponse::error_json(400, format!("Malformed JSON: {e}")),
            };

            let (act_as, _) = extract_parties(req);

            match service.json_exercise(&act_as, exercise_req) {
                Ok(resp) => HttpResponse::ok_json(&resp),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("GET", "/v1/contracts") => {
            let (_, read_as) = extract_parties(req);

            match service.json_contracts(&read_as, None) {
                Ok(resp) => HttpResponse::ok_json(&resp),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("POST", "/v1/query") | ("POST", "/v1/contracts") => {
            let (_, read_as) = extract_parties(req);

            let query_req: Option<QueryContractsRequest> = if !req.body.is_empty() {
                serde_json::from_slice(&req.body).ok()
            } else {
                None
            };

            match service.json_contracts(&read_as, query_req) {
                Ok(resp) => HttpResponse::ok_json(&resp),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("POST", "/v1/command/submit-and-wait") | ("POST", "/v2/command/submit-and-wait") => {
            let mut submit_req: SubmitAndWaitRequest = match serde_json::from_slice(&req.body) {
                Ok(r) => r,
                Err(e) => return HttpResponse::error_json(400, format!("Malformed JSON: {e}")),
            };

            // If act_as is empty in request, populate from JWT / headers
            if submit_req.commands.act_as.is_empty() {
                let (act_as, read_as) = extract_parties(req);
                submit_req.commands.act_as = act_as;
                if submit_req.commands.read_as.is_empty() {
                    submit_req.commands.read_as = read_as;
                }
            }

            match service.submit_and_wait(submit_req) {
                Ok(tree) => HttpResponse::ok_json(&tree),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("GET", "/v2/updates") => {
            let begin = req
                .query_params
                .get("begin")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let end = req
                .query_params
                .get("end")
                .and_then(|s| s.parse::<u64>().ok());
            let (_, read_as) = extract_parties(req);

            let updates = service.get_updates(begin, end, &read_as);
            HttpResponse::ok_json(&updates)
        }
        ("GET", "/v2/state/acs") => {
            let (_, read_as) = extract_parties(req);
            match service.get_active_contracts(&read_as) {
                Ok(resp) => HttpResponse::ok_json(&resp),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        ("GET", "/v2/completions") => {
            let app_id = req
                .query_params
                .get("applicationId")
                .or_else(|| req.query_params.get("app_id"))
                .map(|s| s.as_str())
                .unwrap_or("default");
            let offset = req
                .query_params
                .get("offset")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            let completions = service.get_completions(app_id, offset);
            HttpResponse::ok_json(&completions)
        }
        ("POST", "/v2/prune") => {
            #[derive(serde::Deserialize)]
            struct PruneReq {
                #[serde(alias = "pruneUpTo")]
                prune_up_to: u64,
            }
            let prune_req: PruneReq = match serde_json::from_slice(&req.body) {
                Ok(r) => r,
                Err(e) => return HttpResponse::error_json(400, format!("Malformed JSON: {e}")),
            };

            match service.prune_stream(prune_req.prune_up_to) {
                Ok(pruned) => HttpResponse::ok_json(&serde_json::json!({
                    "status": "success",
                    "pruned_events": pruned
                })),
                Err(err) => HttpResponse::error_json(err.status_code(), err.to_string()),
            }
        }
        _ => HttpResponse::error_json(
            404,
            format!("Endpoint not found: {} {}", req.method, req.path),
        ),
    }
}

/// Parse incoming HTTP request from a stream.
pub fn parse_http_stream(stream: &mut TcpStream) -> Result<HttpRequest, std::io::Error> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream);
    parse_http_buffered(&mut reader)
}

/// Parses an HTTP request while retaining the caller's [`BufReader`] (used by WebSocket upgrades), within the default [`HttpLimits`].
pub(crate) fn parse_http_buffered<R: Read>(
    reader: &mut BufReader<R>,
) -> Result<HttpRequest, std::io::Error> {
    parse_within(reader, &Deadline::starting_now(HttpLimits::default())).map_err(ReadError::into_io)
}

/// Parses an HTTP request within `deadline`'s time and size limits: a body longer than allowed is refused from its `Content-Length`,
/// before any of it is read or the request is authenticated.
fn parse_within<R: Read>(
    reader: &mut BufReader<R>,
    deadline: &Deadline,
) -> Result<HttpRequest, ReadError> {
    let request_line = deadline.read_line(reader)?;
    if request_line.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Client closed connection",
        )
        .into());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Malformed request line").into(),
        );
    }

    let method = parts[0].to_uppercase();
    let full_path = parts[1].to_string();

    let (path, query_params) = if let Some((p, q)) = full_path.split_once('?') {
        let mut params: HashMap<String, String> = HashMap::new();
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                let val = crate::v2::percent_decode(v);
                params
                    .entry(k.to_string())
                    .and_modify(|existing| {
                        existing.push('\x1f');
                        existing.push_str(&val);
                    })
                    .or_insert(val);
            } else if !kv.is_empty() {
                params.entry(kv.to_string()).or_default();
            }
        }
        (p.to_string(), params)
    } else {
        (full_path, HashMap::new())
    };

    let mut headers = HashMap::new();
    let mut content_length: usize = 0;

    for count in 0.. {
        let line = deadline.read_line(reader)?;
        if line.is_empty() || line == "\r\n" || line == "\n" {
            break;
        }
        if count >= deadline.limits.max_headers {
            return Err(deadline.too_many_headers());
        }

        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse::<usize>().unwrap_or(0);
            }
            if key == crate::observability::VIA_GRPC_HEADER
                || key == crate::trace_context::GENERATED_HEADER
            {
                // [CANTON-NOTE: DEFENSIVE] Internal request-origin markers are injected only
                // in-process (`ledger-grpc-api` via `dispatch_request` and `run_server_with`);
                // strip client-supplied copies on external wire ingress.
                continue;
            }
            headers.insert(key, val);
        }
    }

    deadline.admit_body(content_length)?;
    let body = deadline.read_body(reader, content_length)?;

    Ok(HttpRequest {
        method,
        path,
        query_params,
        headers,
        body,
    })
}

/// Write HTTP response to a stream.
pub fn write_http_response(
    stream: &mut TcpStream,
    response: &HttpResponse,
) -> Result<(), std::io::Error> {
    let mut header_bytes = Vec::new();
    write!(
        header_bytes,
        "HTTP/1.1 {} {}\r\n",
        response.status, response.status_text
    )?;

    for (k, v) in &response.headers {
        write!(header_bytes, "{}: {}\r\n", k, v)?;
    }
    write!(header_bytes, "\r\n")?;

    stream.write_all(&header_bytes)?;
    stream.write_all(&response.body)?;
    stream.flush()?;
    Ok(())
}

/// Run HTTP server synchronously until shutdown is signalled.
/// How and in whose name the server logs its requests (set once at start; `text` logs none).
static REQUEST_LOG: std::sync::OnceLock<(crate::canton_log::LogEncoder, String)> =
    std::sync::OnceLock::new();

pub fn set_request_log(encoder: crate::canton_log::LogEncoder, context: String) {
    let _ = REQUEST_LOG.set((encoder, context));
}

/// A random lowercase hex string of `len` digits (trace and span ids), from the process's randomly seeded hasher: no dependency is needed for an id.
fn random_hex(len: usize) -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    while out.len() < len {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(crate::clock::now_micros() as u128);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out.truncate(len);
    out
}

/// The `traceparent` the lines of one call are written with: the one the caller sent, or (when the request log is on) a new one, so the line that says
/// the call was received and the line that ends it share one trace as they do in a Canton node's log.
pub fn call_traceparent(given: Option<&str>) -> Option<String> {
    match (given, REQUEST_LOG.get()) {
        (Some(t), _) => Some(t.to_string()),
        (None, Some((encoder, _))) if *encoder != crate::canton_log::LogEncoder::Text => {
            Some(format!("00-{}-{}-01", random_hex(32), random_hex(16)))
        }
        _ => None,
    }
}

/// Logs a call and its answer in the form of a Canton node's request log (`ApiRequestLogger`): `span_name` is the call (`POST /v2/updates`,
/// `com.daml.ledger.api.v2.UpdateService/GetUpdates`), `peer` who made it (`http:/127.0.0.1:5000`, `grpc:/172.24.0.4:59484`), the trace comes from the
/// call's `traceparent` (`00-<trace-id>-<parent span id>-<flags>`), or is new, and `outcome` is `None` for the line that says the call was received and
/// the end of the answer for the other.
pub fn log_call(span_name: &str, peer: &str, traceparent: Option<&str>, outcome: Option<&str>) {
    let Some((encoder, context)) = REQUEST_LOG.get() else {
        return;
    };
    if *encoder == crate::canton_log::LogEncoder::Text {
        return;
    }
    let parts: Vec<&str> = traceparent.map_or(Vec::new(), |t| t.split('-').collect());
    let (trace_id, parent_id) = match parts.as_slice() {
        [_, trace, parent, ..] if trace.len() == 32 && parent.len() == 16 => {
            ((*trace).to_string(), (*parent).to_string())
        }
        _ => (random_hex(32), random_hex(16)),
    };
    // both lines of a call carry one span: it is derived from the call's traceparent (see `call_traceparent`)
    let span_id = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        traceparent.hash(&mut h);
        span_name.hash(&mut h);
        peer.hash(&mut h);
        format!("{:016x}", h.finish())
    };
    let message = match outcome {
        None => format!("Request {span_name} by {peer}: received"),
        Some(end) => format!("Request {span_name} by {peer}: {end}"),
    };
    crate::diag::diag_println!(
        "{}",
        crate::canton_log::Line {
            micros: crate::clock::now_micros(),
            thread: "canton-env-ec",
            level: "DEBUG",
            logger: "c.d.c.l.a.ApiRequestLogger",
            context,
            trace: Some(crate::canton_log::Trace {
                trace_id: &trace_id,
                span_id: &span_id,
                parent_span_id: &parent_id,
                span_name,
            }),
            message: &message,
        }
        .render(*encoder)
    );
}

pub(crate) fn log_request(req: &HttpRequest, peer: &str, status: Option<u16>) {
    let traceparent = req
        .headers
        .get("traceparent")
        .or_else(|| req.headers.get("Traceparent"));
    log_call(
        &format!("{} {}", req.method, req.path),
        &format!("http:/{peer}"),
        traceparent.map(String::as_str),
        status
            .map(|code| format!("sending response (status {code})"))
            .as_deref(),
    );
}

pub fn run_server(
    service: Arc<ExecutionService>,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    run_server_with(service, listener, shutdown, HttpLimits::default())
}

/// [`run_server`] with explicit [`HttpLimits`].
pub fn run_server_with(
    service: Arc<ExecutionService>,
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    limits: HttpLimits,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let gate = Arc::new(ConnectionGate::default());

    while !shutdown.load(Ordering::SeqCst) {
        // past the limit, connections wait in the accept queue until one closes (as Pekko's `max-connections` does)
        let Some(slot) = gate.try_enter(limits.max_connections) else {
            thread::sleep(Duration::from_millis(10));
            continue;
        };
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                // The listener is non-blocking, and on some platforms (macOS) an accepted socket inherits that. The
                // handler reads the request synchronously, so a request whose bytes had not arrived yet failed with
                // `WouldBlock`, was dropped without a response and made `test_full_http_end_to_end_server` flaky
                // under load. A bounded read timeout keeps a silent client from holding the thread forever.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                let s = Arc::clone(&service);
                let conn_shutdown = Arc::clone(&shutdown);
                // stamp the arrival here, before the request is read: two requests that reach the listener together overlap
                let arrival = s.tick();
                thread::spawn(move || {
                    let _slot = slot;
                    crate::service::set_arrival(arrival);
                    let _ = stream
                        .set_read_timeout(Some(limits.request_timeout.min(Duration::from_secs(5))));
                    let _ = stream.set_write_timeout(Some(limits.request_timeout));
                    let mut reader = BufReader::new(stream);
                    let parsed = parse_within(&mut reader, &Deadline::starting_now(limits));
                    if let Err(ReadError::Refused { status, message }) = &parsed {
                        let mut resp = HttpResponse::json(*status, &serde_json::json!({}));
                        resp.body = message.clone().into_bytes();
                        resp.headers
                            .insert("Content-Type".into(), "text/plain; charset=UTF-8".into());
                        resp.headers
                            .insert("Content-Length".into(), resp.body.len().to_string());
                        resp.headers.insert("Connection".into(), "close".into());
                        let _ = write_http_response(reader.get_mut(), &resp);
                    }
                    if let Ok(mut req) = parsed {
                        let peer = peer_addr.to_string();
                        // one trace for the two lines of the call (a `traceparent` the client sent is kept)
                        let given = req
                            .headers
                            .get("traceparent")
                            .or_else(|| req.headers.get("Traceparent"))
                            .cloned();
                        if let Some(t) = call_traceparent(given.as_deref()) {
                            if given.is_none() {
                                req.headers.insert(
                                    crate::trace_context::GENERATED_HEADER.to_string(),
                                    "1".to_string(),
                                );
                            }
                            req.headers.insert("traceparent".to_string(), t);
                        }
                        if crate::ws::is_websocket_upgrade(&req) {
                            crate::ws::handle_connection(s, reader, peer_addr, req, conn_shutdown);
                            return;
                        }
                        log_request(&req, &peer, None);
                        let resp = dispatch_request(&s, &req);
                        log_request(&req, &peer, Some(resp.status));
                        let _ = write_http_response(reader.get_mut(), &resp);
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                crate::diag::diag_eprintln!("Accept error: {e}");
            }
        }
    }

    // stopped: no new connection is accepted, the ones in flight are answered first
    gate.drain(limits.shutdown_grace);
    Ok(())
}

/// Helper for tests: binds to 127.0.0.1:0 and starts server in background thread.
pub fn start_test_server(service: Arc<ExecutionService>) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    thread::spawn(move || {
        let _ = run_server(service, listener, shutdown_clone);
    });

    (port, shutdown)
}
