//! The limits of the JSON API's HTTP listener (internal review A-10): what a client can make the server allocate or hold before it is
//! authenticated. Canton's JSON API (Pekko HTTP) refuses a body over `max-inbound-message-size` (10 MiB) from its `Content-Length`
//! with 413, bounds open connections (`max-connections`, 1024) and times requests out (`request-timeout`, 20 s).
#![allow(clippy::unwrap_used, reason = "integration test")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ledger_json_api::http::{run_server_with, start_test_server, HttpLimits};
use ledger_json_api::{AuthConfig, ExecutionService};

fn read_status(stream: &mut TcpStream, within: Duration) -> Option<String> {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0u8; 256];
    let mut out = Vec::new();
    while !out.windows(2).any(|w| w == b"\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    let text = String::from_utf8_lossy(&out).to_string();
    text.lines().next().map(str::to_string)
}

fn limited_server(limits: HttpLimits) -> u16 {
    let service = Arc::new(ExecutionService::new());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn(move || run_server_with(service, listener, stop, limits));
    port
}

#[test]
fn a_body_over_the_limit_is_refused_from_its_length_before_authentication() {
    let service = Arc::new(ExecutionService::new());
    service.set_auth(AuthConfig::hmac("secret"));
    let (port, _stop) = start_test_server(service);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    // no body follows and no token is sent: the answer comes from the length alone
    write!(
        stream,
        "POST /v2/commands/submit-and-wait HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        10 * 1024 * 1024 + 1
    )
    .unwrap();
    assert_eq!(
        read_status(&mut stream, Duration::from_secs(3)).as_deref(),
        Some("HTTP/1.1 413 Payload Too Large")
    );
}

#[test]
fn a_body_at_the_limit_is_read() {
    let (port, _stop) = start_test_server(Arc::new(ExecutionService::new()));
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let body = vec![b' '; 10 * 1024 * 1024];
    write!(
        stream,
        "POST /v2/commands/submit-and-wait HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
    let status = read_status(&mut stream, Duration::from_secs(10)).unwrap();
    assert!(!status.contains("413"), "{status}");
}

#[test]
fn a_request_whose_head_trickles_in_is_cut_off_at_the_deadline() {
    let port = limited_server(HttpLimits {
        request_timeout: Duration::from_millis(800),
        ..HttpLimits::default()
    });
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let started = Instant::now();
    stream.write_all(b"GET /livez HTTP/1.1\r\n").unwrap();
    // one header byte every 300 ms: no single read waits long, the request as a whole does
    let mut closed = false;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(300));
        if stream.write_all(b"X").is_err() {
            closed = true;
            break;
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        let mut buf = [0u8; 64];
        if stream.read(&mut buf).is_ok() {
            closed = true;
            break;
        }
    }
    assert!(
        closed,
        "the server still waits for the head after {:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn connections_past_the_limit_wait_until_one_closes() {
    let port = limited_server(HttpLimits {
        max_connections: 2,
        ..HttpLimits::default()
    });
    let idle: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let mut third = TcpStream::connect(("127.0.0.1", port)).unwrap();
    third
        .write_all(b"GET /livez HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    assert_eq!(read_status(&mut third, Duration::from_millis(500)), None);
    drop(idle);
    let status = read_status(&mut third, Duration::from_secs(5)).unwrap();
    assert!(status.starts_with("HTTP/1.1 "), "{status}");
}

/// When the shutdown flag is set the server stops accepting and returns only once the requests in flight are answered (Canton's
/// `ProcessingTimeouts.shutdownProcessing`, 60 s, bounds the wait).
#[test]
fn shutdown_waits_for_the_requests_in_flight() {
    let service = Arc::new(ExecutionService::new());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let serving = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || run_server_with(service, listener, stop, HttpLimits::default()))
    };
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.write_all(b"GET /livez HTTP/1.1\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !serving.is_finished(),
        "the server returned with a request in flight"
    );
    stream.write_all(b"Host: x\r\n\r\n").unwrap();
    assert_eq!(
        read_status(&mut stream, Duration::from_secs(5)).as_deref(),
        Some("HTTP/1.1 200 OK")
    );
    let started = Instant::now();
    while !serving.is_finished() && started.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(serving.is_finished(), "the server returns once drained");
}

/// R-13h: external HTTP requests strip `x-canton-rs-via-grpc` and `x-canton-rs-generated-traceparent` so external clients
/// cannot evade HTTP metrics or suppress their own `traceparent`, while in-process gRPC calls still set `via-grpc`.
#[test]
fn r13h_external_http_strips_internal_headers() {
    use std::collections::HashMap;
    use std::path::Path;

    use ledger_json_api::{dispatch_request, HttpRequest};
    use serde_json::{json, Value};

    const TRACE: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const EMPTY: &str = "00-00000000000000000000000000000000-0000000000000000-00";

    let service = Arc::new(ExecutionService::new());
    let dar = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    let up = dispatch_request(
        &service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/dars".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: dar,
        },
    );
    assert_eq!(up.status, 200);
    let alloc = dispatch_request(
        &service,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/parties".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: br#"{"partyIdHint":"alice","identityProviderId":""}"#.to_vec(),
        },
    );
    assert_eq!(alloc.status, 200);
    let alloc_json: Value = serde_json::from_slice(&alloc.body).unwrap();
    let alice = alloc_json["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();

    let (port, stop) = start_test_server(Arc::clone(&service));

    let send_http =
        |method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]| -> (u16, Value) {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n",
                body.len()
            );
            for (k, v) in headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            let mut raw = Vec::new();
            let _ = stream.read_to_end(&mut raw);
            let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let status_line = std::str::from_utf8(&raw[..split])
                .unwrap()
                .lines()
                .next()
                .unwrap();
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            let json: Value = serde_json::from_slice(&raw[split + 4..]).unwrap_or(Value::Null);
            (status, json)
        };

    // 1. Attempt to spoof `x-canton-rs-via-grpc` on an external TCP HTTP GET /v2/version.
    let (st_ver, _) = send_http("GET", "/v2/version", &[("X-Canton-Rs-Via-Grpc", "1")], b"");
    assert_eq!(st_ver, 200);
    let tele = service.observability.telemetry_json(&service);
    let http_ver_count: u64 = tele["requests_total"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["protocol"] == "http" && e["method"] == "GET /v2/version")
        .filter_map(|e| e["count"].as_u64())
        .sum();
    assert_eq!(
        http_ver_count, 1,
        "external HTTP request must not evade HTTP counter with spoofed via-grpc header: {tele}"
    );

    // 2. Attempt to spoof `x-canton-rs-generated-traceparent` alongside a caller traceparent.
    let cmd_body = json!({ "commands": {
        "commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": &alice, "owner": &alice, "auditor": &alice, "assetSymbol": "USD", "amount": "1.0"}
        }}],
        "userId": "u-r13h",
        "commandId": "cmd-r13h-spoof",
        "actAs": [&alice]
    }})
    .to_string();
    let (st_cmd, body_cmd) = send_http(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        &[
            ("Content-Type", "application/json"),
            ("traceparent", TRACE),
            ("X-Canton-Rs-Generated-Traceparent", "1"),
        ],
        cmd_body.as_bytes(),
    );
    assert_eq!(st_cmd, 200, "{body_cmd}");
    assert_eq!(
        body_cmd["transaction"]["traceContext"]["traceparent"], TRACE,
        "external HTTP request must keep caller traceparent even when spoofing generated header: {body_cmd}"
    );

    // Positive control A: external HTTP with NO traceparent still records EMPTY trace.
    let plain_body = json!({ "commands": {
        "commands": [{"CreateCommand": {
            "templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": &alice, "owner": &alice, "auditor": &alice, "assetSymbol": "USD", "amount": "2.0"}
        }}],
        "userId": "u-r13h",
        "commandId": "cmd-r13h-plain",
        "actAs": [&alice]
    }})
    .to_string();
    let (st_plain, body_plain) = send_http(
        "POST",
        "/v2/commands/submit-and-wait-for-transaction",
        &[("Content-Type", "application/json")],
        plain_body.as_bytes(),
    );
    assert_eq!(st_plain, 200, "{body_plain}");
    assert_eq!(
        body_plain["transaction"]["traceContext"]["traceparent"],
        EMPTY
    );

    // Positive control B: in-process dispatch with VIA_GRPC_HEADER still does not increment http GET /v2/version count.
    let mut grpc_headers = HashMap::new();
    grpc_headers.insert("x-canton-rs-via-grpc".to_string(), "1".to_string());
    let inproc = dispatch_request(
        &service,
        &HttpRequest {
            method: "GET".into(),
            path: "/v2/version".into(),
            query_params: HashMap::new(),
            headers: grpc_headers,
            body: Vec::new(),
        },
    );
    assert_eq!(inproc.status, 200);
    let tele_after = service.observability.telemetry_json(&service);
    let http_ver_after: u64 = tele_after["requests_total"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["protocol"] == "http" && e["method"] == "GET /v2/version")
        .filter_map(|e| e["count"].as_u64())
        .sum();
    assert_eq!(http_ver_after, 1);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
}
