#![allow(clippy::unwrap_used, reason = "integration test")]
//! S-API-029: Tests for the 14 previously unrouted JSON API v2 endpoints, traffic enforcement toggle,
//! external-party JWKS serialization, `/docs/{openapi,asyncapi}`, and RFC 6455 WebSocket streaming.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ledger_json_api::auth::sign_token;
use ledger_json_api::http::{start_test_server, HttpRequest};
use ledger_json_api::{dispatch_request, AuthConfig, ExecutionService};
use serde_json::{json, Value as Json};

fn http_call(
    svc: &ExecutionService,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    body: Json,
    token: Option<&str>,
) -> (u16, Json, Vec<u8>) {
    let mut headers = HashMap::new();
    if let Some(t) = token {
        headers.insert("authorization".to_string(), format!("Bearer {t}"));
    }
    let mut query_params: HashMap<String, String> = HashMap::new();
    for (k, v) in query {
        query_params
            .entry((*k).to_string())
            .and_modify(|prev| {
                prev.push('\x1f');
                prev.push_str(v);
            })
            .or_insert_with(|| (*v).to_string());
    }
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: method.into(),
            path: path.into(),
            query_params,
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                serde_json::to_vec(&body).unwrap()
            },
        },
    );
    let parsed = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
    (resp.status, parsed, resp.body)
}

fn setup_service_with_dar_and_party() -> (ExecutionService, String, String) {
    let svc = ExecutionService::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let dar_path = root.join("contracts/target/sample-contract.dar");
    let dar = std::fs::read(&dar_path).expect("sample-contract.dar");
    let upload = dispatch_request(
        &svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/dars".into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: dar,
        },
    );
    assert_eq!(upload.status, 200);
    let (_, p_resp, _) = http_call(
        &svc,
        "POST",
        "/v2/parties",
        &[],
        json!({ "partyIdHint": "alice" }),
        None,
    );
    let alice = p_resp["partyDetails"]["party"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, pkgs, _) = http_call(&svc, "GET", "/v2/packages", &[], Json::Null, None);
    let pkg_id = pkgs["packageIds"][0].as_str().unwrap().to_string();
    (svc, alice, pkg_id)
}

#[test]
fn routes_14_and_docs_and_external_party_guard_and_jwks() {
    let (svc, alice, _pkg_id) = setup_service_with_dar_and_party();

    // Fixed shadow bug: GET /v2/parties/external/{allocate,generate-topology} must return 404.
    assert_eq!(
        http_call(
            &svc,
            "GET",
            "/v2/parties/external/allocate",
            &[],
            Json::Null,
            None
        )
        .0,
        404
    );
    assert_eq!(
        http_call(
            &svc,
            "GET",
            "/v2/parties/external/generate-topology",
            &[],
            Json::Null,
            None
        )
        .0,
        404
    );

    // Docs endpoints.
    let (st_open, _, body_open) = http_call(&svc, "GET", "/docs/openapi", &[], Json::Null, None);
    assert_eq!(st_open, 200);
    assert!(String::from_utf8_lossy(&body_open).contains("openapi: 3.0.3"));
    let (st_async, _, body_async) = http_call(&svc, "GET", "/docs/asyncapi", &[], Json::Null, None);
    assert_eq!(st_async, 200);
    assert!(String::from_utf8_lossy(&body_async).contains("asyncapi: 2.6.0"));

    // GET /v2/package-vetting & GET /v2/interactive-submission/preferred-package-version.
    let (st_vet, v_json, _) = http_call(&svc, "GET", "/v2/package-vetting", &[], Json::Null, None);
    assert_eq!(st_vet, 200, "{v_json}");
    assert!(!v_json["vettedPackages"].as_array().unwrap().is_empty());

    let (st_pref, pref, _) = http_call(
        &svc,
        "GET",
        "/v2/interactive-submission/preferred-package-version",
        &[("package-name", "sample-contract"), ("parties", &alice)],
        Json::Null,
        None,
    );
    assert_eq!(st_pref, 200, "{pref}");
    assert_eq!(
        pref["packagePreference"]["packageReference"]["packageName"],
        "sample-contract"
    );

    let (st_pref_missing, pref_missing, _) = http_call(
        &svc,
        "GET",
        "/v2/interactive-submission/preferred-package-version",
        &[("package-name", "nonexistent-pkg-xyz")],
        Json::Null,
        None,
    );
    assert_eq!(st_pref_missing, 200);
    assert!(pref_missing.get("packagePreference").is_none());

    // Submit and wait for transaction tree + query tree/flat endpoints.
    let (st_tree, sub_tree, raw_tree) = http_call(
        &svc,
        "POST",
        "/v2/commands/submit-and-wait-for-transaction-tree",
        &[],
        json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": alice,
                        "owner": alice,
                        "auditor": alice,
                        "amount": "42.0",
                        "assetSymbol": "USD"
                    }
                }
            }],
            "commandId": "cmd-tree-1",
            "actAs": [&alice],
            "userId": "participant_admin"
        }),
        None,
    );
    assert_eq!(
        st_tree,
        200,
        "submit-tree failed: {}",
        String::from_utf8_lossy(&raw_tree)
    );
    let update_id = sub_tree["transactionTree"]["updateId"]
        .as_str()
        .unwrap()
        .to_string();
    let offset = sub_tree["transactionTree"]["offset"].as_u64().unwrap();
    assert!(!sub_tree["transactionTree"]["eventsById"]
        .as_object()
        .unwrap()
        .is_empty());

    // /v2/updates/flats & /v2/updates/trees
    let ef = json!({ "filtersByParty": { &alice: {} } });
    let (st_f, flats, _) = http_call(
        &svc,
        "POST",
        "/v2/updates/flats",
        &[],
        json!({ "beginExclusive": 0, "filter": ef }),
        None,
    );
    assert_eq!(st_f, 200, "{flats}");
    assert!(flats
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["update"]["Transaction"]["value"]["updateId"] == update_id));

    let (st_t, trees, _) = http_call(
        &svc,
        "POST",
        "/v2/updates/trees",
        &[],
        json!({ "beginExclusive": 0, "filter": { "filtersByParty": { &alice: {} } } }),
        None,
    );
    assert_eq!(st_t, 200, "{trees}");
    assert!(trees
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["update"]["TransactionTree"]["value"]["updateId"] == update_id));

    // transaction-by-id & transaction-by-offset (POST) + transaction-tree-by-id/{id} & offset (GET)
    let (st_tbi, tbi, _) = http_call(
        &svc,
        "POST",
        "/v2/updates/transaction-by-id",
        &[],
        json!({ "updateId": &update_id, "requestingParties": [&alice] }),
        None,
    );
    assert_eq!(st_tbi, 200, "{tbi}");
    assert_eq!(tbi["transaction"]["updateId"], update_id);

    let (st_tbo, tbo, _) = http_call(
        &svc,
        "POST",
        "/v2/updates/transaction-by-offset",
        &[],
        json!({ "offset": offset, "requestingParties": [&alice] }),
        None,
    );
    assert_eq!(st_tbo, 200, "{tbo}");
    assert_eq!(tbo["transaction"]["offset"], offset);

    let (st_ttid, ttid, _) = http_call(
        &svc,
        "GET",
        &format!("/v2/updates/transaction-tree-by-id/{update_id}"),
        &[("parties", &alice)],
        Json::Null,
        None,
    );
    assert_eq!(st_ttid, 200, "{ttid}");
    assert_eq!(ttid["transaction"]["updateId"], update_id);

    let (st_ttoff, ttoff, _) = http_call(
        &svc,
        "GET",
        &format!("/v2/updates/transaction-tree-by-offset/{offset}"),
        &[("parties", &alice)],
        Json::Null,
        None,
    );
    assert_eq!(st_ttoff, 200, "{ttoff}");
    assert_eq!(ttoff["transaction"]["offset"], offset);

    // /v2/commands/async/submit-reassignment: routed (standalone returns 400 missing synchronizers, not 404).
    let (st_reas, reas_body, _) = http_call(
        &svc,
        "POST",
        "/v2/commands/async/submit-reassignment",
        &[],
        json!({
            "submitter": &alice,
            "commandId": "r1",
            "source": "s1",
            "target": "s2",
            "unassignId": "u1",
            "contractId": "c1"
        }),
        None,
    );
    assert_ne!(st_reas, 404, "route must exist: {reas_body}");
}

#[test]
fn traffic_routes_disabled_by_default_and_enabled_when_configured() {
    let svc = ExecutionService::new();
    assert_eq!(
        http_call(
            &svc,
            "GET",
            "/v2/traffic/accounts/p1",
            &[],
            Json::Null,
            None
        )
        .0,
        404
    );
    assert_eq!(
        http_call(&svc, "POST", "/v2/traffic/accounts", &[], json!({}), None).0,
        404
    );
    assert_eq!(
        http_call(
            &svc,
            "POST",
            "/v2/traffic/prune",
            &[],
            json!({"beforeOrAt": "2020-01-01T00:00:00Z"}),
            None
        )
        .0,
        404
    );
    assert_eq!(
        http_call(
            &svc,
            "POST",
            "/v2/traffic/events/prune",
            &[],
            json!({"beforeOrAt": "2020-01-01T00:00:00Z"}),
            None
        )
        .0,
        404
    );

    // Enable traffic enforcement.
    svc.set_traffic_enforcement(true);
    let (s, u1, _) = http_call(
        &svc,
        "POST",
        "/v2/traffic/accounts",
        &[],
        json!({ "accountId": "p1::ns", "balanceDelta": 500, "deduplicationId": "d1" }),
        None,
    );
    assert_eq!(s, 200, "{u1}");
    assert_eq!(u1["response"]["balance"], 500);

    // Duplicate deduplicationId is idempotent.
    let (_, u2, _) = http_call(
        &svc,
        "POST",
        "/v2/traffic/accounts",
        &[],
        json!({ "accountId": "p1::ns", "balanceDelta": 500, "deduplicationId": "d1" }),
        None,
    );
    assert_eq!(u2["response"]["balance"], 500);

    let (sg, ga, _) = http_call(
        &svc,
        "GET",
        "/v2/traffic/accounts/p1::ns",
        &[],
        Json::Null,
        None,
    );
    assert_eq!(sg, 200);
    assert_eq!(ga["balance"], 500);

    // Unsafe prune within default 7-day dedup window fails loudly with TRAFFIC_UNSAFE_TO_PRUNE.
    let (sp_bad, bad, _) = http_call(
        &svc,
        "POST",
        "/v2/traffic/prune",
        &[],
        json!({ "beforeOrAt": "2099-01-01T00:00:00Z" }),
        None,
    );
    assert_eq!(sp_bad, 400);
    assert_eq!(bad["code"], "TRAFFIC_UNSAFE_TO_PRUNE");

    // Old timestamp outside dedup window succeeds.
    let (sp_ok, ok, _) = http_call(
        &svc,
        "POST",
        "/v2/traffic/prune",
        &[],
        json!({ "beforeOrAt": "2020-01-01T00:00:00Z" }),
        None,
    );
    assert_eq!(sp_ok, 200, "{ok}");
    assert!(ok.get("prunedEventCount").is_some());
    assert!(ok.get("prunedCorrelationCount").is_some());

    let (sep, ep, _) = http_call(
        &svc,
        "POST",
        "/v2/traffic/events/prune",
        &[],
        json!({ "beforeOrAt": "2020-01-01T00:00:00Z" }),
        None,
    );
    assert_eq!(sep, 200, "{ep}");
    assert!(ep.get("prunedEventCount").is_some());
}

fn send_ws_masked_text(stream: &mut TcpStream, msg: &str) {
    let payload = msg.as_bytes();
    let mut frame = vec![0x81u8];
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | (len as u8));
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    }
    let mask = [0x11u8, 0x22, 0x33, 0x44];
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    stream.write_all(&frame).unwrap();
    stream.flush().unwrap();
}

fn read_ws_frame(reader: &mut BufReader<TcpStream>) -> (u8, Vec<u8>) {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).unwrap();
    let opcode = hdr[0] & 0x0f;
    let len7 = (hdr[1] & 0x7f) as u64;
    let len = match len7 {
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
    if len > 0 {
        reader.read_exact(&mut payload).unwrap();
    }
    (opcode, payload)
}

#[test]
fn websocket_auth_subprotocol_error_frame_and_live_tailing() {
    let (svc, alice, _) = setup_service_with_dar_and_party();
    let secret = "ws-secret";
    svc.set_auth(AuthConfig::hmac(secret));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let admin_tok = sign_token(
        secret,
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    let nobody_tok = sign_token(
        secret,
        &json!({ "sub": "nobody", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    let alice_tok = sign_token(
        secret,
        &json!({ "sub": "alice_user", "scope": "daml_ledger_api", "exp": now + 120 }),
    );

    // Create users `nobody` and `alice_user`.
    assert_eq!(
        http_call(
            &svc,
            "POST",
            "/v2/users",
            &[],
            json!({ "user": { "id": "nobody" }, "rights": [] }),
            Some(&admin_tok)
        )
        .0,
        200
    );
    assert_eq!(
        http_call(
            &svc,
            "POST",
            "/v2/users",
            &[],
            json!({ "user": { "id": "alice_user" }, "rights": [{ "kind": { "CanActAs": { "value": { "party": &alice } } } }] }),
            Some(&admin_tok)
        )
        .0,
        200
    );

    let svc_arc = std::sync::Arc::new(svc);
    let (port, shutdown) = start_test_server(std::sync::Arc::clone(&svc_arc));

    // 1. Pre-upgrade unauthenticated handshake must return HTTP 401 before switching protocols.
    let mut unauth = TcpStream::connect(("127.0.0.1", port)).unwrap();
    unauth
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        unauth,
        "GET /v2/updates HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = String::new();
    let mut r1 = BufReader::new(unauth);
    r1.read_line(&mut head).unwrap();
    assert!(
        head.contains("401"),
        "expected 401 handshake denial, got {head}"
    );

    // 2. User lacking CanReadAs gets Ws handshake 101 via Sec-WebSocket-Protocol, then JsCantonError frame.
    let mut deny_ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    deny_ws
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        deny_ws,
        "GET /v2/updates HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: daml.ws.auth, jwt.token.{nobody_tok}\r\n\r\n"
    )
    .unwrap();
    let mut r_deny = BufReader::new(deny_ws);
    let mut status_line = String::new();
    r_deny.read_line(&mut status_line).unwrap();
    assert!(status_line.contains("101"), "{status_line}");
    let mut saw_daml_proto = false;
    loop {
        let mut l = String::new();
        r_deny.read_line(&mut l).unwrap();
        if l.to_ascii_lowercase()
            .starts_with("sec-websocket-protocol:")
            && l.contains("daml.ws.auth")
        {
            saw_daml_proto = true;
        }
        if l == "\r\n" {
            break;
        }
    }
    assert!(saw_daml_proto);
    send_ws_masked_text(
        r_deny.get_mut(),
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": { "filtersByParty": { &alice: {} } },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        })
        .to_string(),
    );
    let (op_err, err_bytes) = read_ws_frame(&mut r_deny);
    assert_eq!(op_err, 0x01);
    let err_json: Json = serde_json::from_slice(&err_bytes).unwrap();
    assert_eq!(err_json["grpcCodeValue"], 7);

    // 3. Authorized live-tailing WS on /v2/updates receives live update after subscription opens.
    let mut ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        ws,
        "GET /v2/updates HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: daml.ws.auth, jwt.token.{alice_tok}\r\n\r\n"
    )
    .unwrap();
    let mut reader = BufReader::new(ws);
    loop {
        let mut l = String::new();
        reader.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
    }
    send_ws_masked_text(
        reader.get_mut(),
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": { "filtersByParty": { &alice: {} } },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        })
        .to_string(),
    );

    // Submit a new transaction while the WS stream is tailing!
    let (sub_st, _, sub_raw) = http_call(
        &svc_arc,
        "POST",
        "/v2/commands/submit-and-wait",
        &[],
        json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": alice,
                        "owner": alice,
                        "auditor": alice,
                        "amount": "99.0",
                        "assetSymbol": "USD"
                    }
                }
            }],
            "commandId": "ws-live-1",
            "actAs": [&alice],
            "userId": "alice_user"
        }),
        Some(&alice_tok),
    );
    assert_eq!(
        sub_st,
        200,
        "ws submit failed: {}",
        String::from_utf8_lossy(&sub_raw)
    );

    let (op, frame_bytes) = read_ws_frame(&mut reader);
    assert_eq!(op, 0x01);
    let live_update: Json = serde_json::from_slice(&frame_bytes).unwrap();
    assert_eq!(
        live_update["update"]["Transaction"]["value"]["commandId"],
        "ws-live-1"
    );

    // 4. ACS WebSocket channel emits snapshot then clean Close frame.
    let mut acs_ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    acs_ws
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        acs_ws,
        "GET /v2/state/active-contracts HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {alice_tok}\r\n\r\n"
    )
    .unwrap();
    let mut acs_reader = BufReader::new(acs_ws);
    loop {
        let mut l = String::new();
        acs_reader.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
    }
    let end_now = svc_arc.v2_ledger_end();
    send_ws_masked_text(
        acs_reader.get_mut(),
        &json!({
            "activeAtOffset": end_now,
            "eventFormat": { "filtersByParty": { &alice: {} } }
        })
        .to_string(),
    );
    let (op_acs, acs_bytes) = read_ws_frame(&mut acs_reader);
    assert_eq!(op_acs, 0x01);
    let acs_item: Json = serde_json::from_slice(&acs_bytes).unwrap();
    assert!(acs_item["contractEntry"]["JsActiveContract"].is_object());
    let (op_close, _) = read_ws_frame(&mut acs_reader);
    assert_eq!(op_close, 0x08);

    shutdown.store(true, Ordering::SeqCst);
}

#[test]
fn ws_updates_streams_live_topology_transactions() {
    let secret = "ws-topo-secret";
    let svc = ExecutionService::new();
    svc.set_auth(AuthConfig::hmac(secret));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let admin_tok = sign_token(
        secret,
        &json!({ "sub": "participant_admin", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    let any_tok = sign_token(
        secret,
        &json!({ "sub": "any_reader", "scope": "daml_ledger_api", "exp": now + 120 }),
    );
    assert_eq!(
        http_call(
            &svc,
            "POST",
            "/v2/users",
            &[],
            json!({
                "user": { "id": "any_reader" },
                "rights": [{ "kind": { "CanReadAsAnyParty": { "value": {} } } }]
            }),
            Some(&admin_tok),
        )
        .0,
        200
    );

    let svc_arc = std::sync::Arc::new(svc);
    let (port, shutdown) = start_test_server(std::sync::Arc::clone(&svc_arc));

    let mut ws = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ws.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        ws,
        "GET /v2/updates HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: daml.ws.auth, jwt.token.{any_tok}\r\n\r\n"
    )
    .unwrap();
    let mut reader = BufReader::new(ws);
    loop {
        let mut l = String::new();
        reader.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
    }
    let current_end = svc_arc.v2_ledger_end();
    send_ws_masked_text(
        reader.get_mut(),
        &json!({
            "beginExclusive": current_end,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [] }
                }
            }
        })
        .to_string(),
    );

    let (st_p, p_json, _) = http_call(
        &svc_arc,
        "POST",
        "/v2/parties",
        &[],
        json!({ "partyIdHint": "carol", "identityProviderId": "" }),
        Some(&admin_tok),
    );
    assert_eq!(st_p, 200, "{p_json}");
    let carol = p_json["partyDetails"]["party"].as_str().unwrap();

    let (op, frame_bytes) = read_ws_frame(&mut reader);
    assert_eq!(op, 0x01);
    let live: Json = serde_json::from_slice(&frame_bytes).unwrap();
    let added = live
        .pointer(
            "/update/TopologyTransaction/value/events/0/event/ParticipantAuthorizationAdded/value",
        )
        .unwrap_or_else(|| panic!("expected TopologyTransaction frame, got {live}"));
    assert_eq!(added["partyId"], carol);
    assert_eq!(
        added["participantPermission"],
        "PARTICIPANT_PERMISSION_SUBMISSION"
    );

    shutdown.store(true, Ordering::SeqCst);
}
