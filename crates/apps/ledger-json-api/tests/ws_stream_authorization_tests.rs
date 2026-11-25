//! An open WebSocket stream re-checks its token before each element and ends once it expired (`UserBasedOngoingAuthorization`,
//! Canton 3.7.2: `ACCESS_TOKEN_EXPIRED`).
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use ledger_json_api::{
    auth::sign_token, dispatch_request, http::start_test_server, AuthConfig, ExecutionService,
    HttpRequest,
};
use serde_json::{json, Value};

const SECRET: &str = "ws-secret";

fn token(sub: &str, lifetime: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sign_token(
        SECRET,
        &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now + lifetime }),
    )
}

fn call(svc: &ExecutionService, path: &str, body: Vec<u8>, bearer: &str) -> Value {
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: [("authorization".to_string(), format!("Bearer {bearer}"))].into(),
            body,
        },
    );
    assert!(
        resp.status < 300,
        "{path}: {}",
        String::from_utf8_lossy(&resp.body)
    );
    serde_json::from_slice(&resp.body).unwrap_or(Value::Null)
}

fn send_masked_text(stream: &mut TcpStream, msg: &str) {
    let payload = msg.as_bytes();
    let mut frame = vec![0x81u8];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    stream.write_all(&frame).unwrap();
}

fn read_frame(reader: &mut BufReader<TcpStream>) -> (u8, Vec<u8>) {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).unwrap();
    let len = match hdr[1] & 0x7f {
        126 => {
            let mut ext = [0u8; 2];
            reader.read_exact(&mut ext).unwrap();
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext).unwrap();
            u64::from_be_bytes(ext) as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).unwrap();
    (hdr[0] & 0x0f, payload)
}

#[test]
fn a_websocket_stream_ends_at_its_first_element_after_the_token_expired() {
    let svc = Arc::new(ExecutionService::new());
    svc.set_auth(AuthConfig::hmac(SECRET));
    let admin = token("participant_admin", 120);
    let dar = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar"),
    )
    .unwrap();
    call(&svc, "/v2/dars", dar, &admin);
    let alice = call(
        &svc,
        "/v2/parties",
        json!({"partyIdHint": "alice", "identityProviderId": ""})
            .to_string()
            .into_bytes(),
        &admin,
    )["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &svc,
        "/v2/users",
        json!({"user": {"id": "alice_user"}, "rights": [{"kind": {"CanActAs": {"value": {"party": &alice}}}}]})
            .to_string()
            .into_bytes(),
        &admin,
    );
    let (port, _shutdown) = start_test_server(Arc::clone(&svc));
    let short = token("alice_user", 2);
    let mut ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        ws,
        "GET /v2/updates HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: daml.ws.auth, jwt.token.{short}\r\n\r\n"
    )
    .unwrap();
    let mut reader = BufReader::new(ws);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
    }
    send_masked_text(
        reader.get_mut(),
        &json!({"beginExclusive": 0, "updateFormat": {"includeTransactions": {
            "eventFormat": {"filtersByParty": {&alice: {}}}, "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"}}})
        .to_string(),
    );
    std::thread::sleep(Duration::from_secs(3));
    call(
        &svc,
        "/v2/commands/submit-and-wait",
        json!({"commands": [{"CreateCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding",
            "createArguments": {"bank": &alice, "owner": &alice, "auditor": &alice, "amount": "1.0", "assetSymbol": "USD"}}}],
            "commandId": "after-expiry", "actAs": [&alice], "userId": "alice_user"})
        .to_string()
        .into_bytes(),
        &token("alice_user", 120),
    );
    let (opcode, payload) = read_frame(&mut reader);
    assert_eq!(opcode, 0x01, "a text frame");
    let body: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(body["code"], "ACCESS_TOKEN_EXPIRED", "{body}");
    assert_eq!(body["grpcCodeValue"], 10);
    assert_eq!(read_frame(&mut reader).0, 0x08, "then the close frame");
}
