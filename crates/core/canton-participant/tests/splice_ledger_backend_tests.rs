//! S-SPL-037: unit and mock-Ledger-API integration tests for [`ParticipantLedgerClient`].

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use canton_participant::scan_api::{DsoInfoConfig, UpdateHistory};
use canton_participant::splice_apps::{SpliceAppRuntime, SpliceBootstrapConfig};
use canton_participant::splice_ledger_backend::{
    sign_hs256_jwt, ParticipantLedgerClient, ParticipantLedgerConfig,
};
use lf_eval::fat_contract::{
    decode_strict_base64, encode_auth_data_v30, encode_base64, encode_fat_contract,
    FatContractInput,
};
use lf_eval::typed_json::{format_timestamp_micros, Types};
use lf_eval::World;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

fn splice_dar_paths() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/splice-dars");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("splice-dars dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "dar"))
        .collect();
    paths.sort();
    paths
}

fn load_splice_world(paths: &[PathBuf]) -> World {
    let mut w = World::open(&paths[0]).expect("open first dar");
    for p in &paths[1..] {
        w.add_dar(p).expect("add dar");
    }
    w
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let mut padded = s.replace('-', "+").replace('_', "/");
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    decode_strict_base64(&padded).expect("valid base64url")
}

#[test]
fn hs256_jwt_signing_and_admin_vs_user_token_routing() {
    let tok = sign_hs256_jwt("unsafe", "ledger-api-user", "https://canton.network.global");
    let parts: Vec<&str> = tok.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: Json = serde_json::from_slice(&b64url_decode(parts[0])).expect("jwt header");
    assert_eq!(header, json!({ "alg": "HS256", "typ": "JWT" }));
    let claims: Json = serde_json::from_slice(&b64url_decode(parts[1])).expect("jwt claims");
    assert_eq!(claims["sub"], json!("ledger-api-user"));
    assert_eq!(claims["aud"], json!("https://canton.network.global"));
    assert!(claims["exp"].as_u64().unwrap_or(0) > 0);

    // Check explicit admin_token vs user_token routing via mock server connect_and_setup
    let dars = splice_dar_paths();
    let world = load_splice_world(&dars);
    let captured_auth: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_auth_srv = Arc::clone(&captured_auth);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while !stop_srv.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = stream.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let clen: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + clen {
                        break;
                    }
                }
            }
            let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let first = head.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");
            let auth = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("authorization")
                        .then(|| v.trim().to_string())
                })
                .unwrap_or_default();
            captured_auth_srv
                .lock()
                .unwrap()
                .push((format!("{method} {path}"), auth));

            let body_bytes = &buf[pos + 4..];
            let req_json: Json = serde_json::from_slice(body_bytes).unwrap_or(Json::Null);
            let resp = match (method, path) {
                ("GET", "/v2/version") => json!({ "version": "3.7.2" }),
                ("GET", "/v2/state/connected-synchronizers") => {
                    json!({ "connectedSynchronizers": [{ "synchronizerId": "sync::1220aa" }] })
                }
                ("GET", "/v2/parties/participant-id") => {
                    json!({ "participantId": "PAR::mock::1220aa" })
                }
                ("POST", "/v2/dars") => json!({}),
                ("GET", "/v2/parties") => json!({ "partyDetails": [] }),
                ("POST", "/v2/parties") => {
                    let hint = req_json["partyIdHint"].as_str().unwrap_or("p");
                    json!({ "partyDetails": { "party": format!("{hint}::122011"), "isLocal": true } })
                }
                ("POST", "/v2/users") => json!({}),
                ("GET", "/v2/state/ledger-end") => json!({ "offset": 0 }),
                _ => json!({}),
            };
            let out = resp.to_string();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                out.len(),
                out
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });

    let cfg = ParticipantLedgerConfig {
        host: "127.0.0.1".into(),
        port,
        admin_token: Some("admin-tok-xyz".into()),
        user_id: "splice-user".into(),
        user_token: Some("user-tok-abc".into()),
        auth_unsafe_secret: None,
        jwt_audience: "https://canton.network.global".into(),
        synchronizer_id: None,
        scan_history_path: None,
    };
    let client = ParticipantLedgerClient::connect_and_setup(
        cfg,
        &dars,
        &world,
        &SpliceBootstrapConfig::default(),
    )
    .expect("connect_and_setup");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = handle.join();

    assert_eq!(client.synchronizer_id(), "sync::1220aa");
    assert_eq!(client.participant_id(), "PAR::mock::1220aa");
    assert_eq!(client.dso_party(), "DSO::122011");

    let recorded = captured_auth.lock().unwrap();
    assert!(recorded
        .iter()
        .any(|(r, a)| r == "POST /v2/dars" && a == "Bearer admin-tok-xyz"));
    assert!(recorded
        .iter()
        .any(|(r, a)| r == "POST /v2/parties" && a == "Bearer admin-tok-xyz"));
    assert!(recorded
        .iter()
        .any(|(r, a)| r == "GET /v2/state/ledger-end" && a == "Bearer user-tok-abc"));
}

#[test]
fn sync_to_ledger_end_builds_scan_history_extracts_salts_and_discloses_reference_contracts() {
    let dars = splice_dar_paths();
    let world = load_splice_world(&dars);
    let types = Types::new(&world);

    // Run a real in-process bootstrap first only to grab authentic bootstrapped Splice contract payloads/V12 blobs!
    let dar_dir = dars[0].parent().unwrap();
    let mut sample_rt =
        SpliceAppRuntime::from_dar_dir(dar_dir, SpliceBootstrapConfig::default()).unwrap();
    sample_rt.bootstrap().unwrap();

    let dso = sample_rt.config().dso_party.clone();
    let sv = sample_rt.config().sv_party.clone();
    let validator = sample_rt.config().validator_party.clone();
    let dso_rules = sample_rt
        .find_contracts("Splice.DsoRules:DsoRules")
        .into_iter()
        .next()
        .unwrap()
        .clone();
    let open_round = sample_rt
        .find_contracts("Splice.Round:OpenMiningRound")
        .into_iter()
        .next()
        .unwrap()
        .clone();

    let encode_blob = |c: &lf_eval::Contract| -> (Json, String) {
        let pkg_name = types.package_name(&c.package_id).unwrap();
        let (mod_n, ent_n) = c.template_id.split_once(':').unwrap();
        let tpl_ty = types.template(&c.package_id, &c.template_id).unwrap();
        let lapi_arg = types
            .encode_ledger_api_omitting_nulls(&tpl_ty, &c.payload)
            .unwrap();
        let salt: [u8; 32] = Sha256::digest(c.contract_id.as_bytes()).into();
        let bytes = encode_fat_contract(
            &world,
            &FatContractInput {
                contract_id: &c.contract_id,
                package_id: &c.package_id,
                package_name: &pkg_name,
                module_name: mod_n,
                entity_name: ent_n,
                payload: &c.payload,
                signatories: &c.signatories,
                observers: &c.observers,
                created_at_micros: 1_794_620_100_000_000,
                salt: &salt,
                key: c.key.as_ref(),
                key_maintainers: &[],
                key_hash: None,
            },
        )
        .unwrap();
        let _auth_v30 = encode_auth_data_v30(&salt);
        (lapi_arg, encode_base64(&bytes))
    };

    let (dso_rules_arg, dso_rules_blob) = encode_blob(&dso_rules);
    let (round_arg, round_blob) = encode_blob(&open_round);
    let ts = format_timestamp_micros(1_794_620_100_000_000);

    let updates_payload = Arc::new(json!([
        {
            "update": {
                "Transaction": {
                    "value": {
                        "updateId": "12200000000000000000000000000000000000000000000000000000000000000001",
                        "commandId": "boot",
                        "workflowId": "dso-bootstrap",
                        "effectiveAt": ts,
                        "recordTime": ts,
                        "offset": 1,
                        "synchronizerId": "sync::1220mock",
                        "events": [
                            {
                                "CreatedEvent": {
                                    "offset": 1,
                                    "nodeId": 0,
                                    "contractId": dso_rules.contract_id,
                                    "templateId": format!("{}:{}", dso_rules.package_id, dso_rules.template_id),
                                    "packageName": types.package_name(&dso_rules.package_id).unwrap(),
                                    "createArgument": dso_rules_arg,
                                    "createdAt": ts,
                                    "signatories": dso_rules.signatories,
                                    "observers": dso_rules.observers,
                                    "witnessParties": [dso],
                                    "createdEventBlob": dso_rules_blob,
                                    "acsDelta": true
                                }
                            },
                            {
                                "CreatedEvent": {
                                    "offset": 1,
                                    "nodeId": 1,
                                    "contractId": open_round.contract_id,
                                    "templateId": format!("{}:{}", open_round.package_id, open_round.template_id),
                                    "packageName": types.package_name(&open_round.package_id).unwrap(),
                                    "createArgument": round_arg,
                                    "createdAt": ts,
                                    "signatories": open_round.signatories,
                                    "observers": open_round.observers,
                                    "witnessParties": [dso],
                                    "createdEventBlob": round_blob,
                                    "acsDelta": true
                                }
                            }
                        ]
                    }
                }
            }
        }
    ]));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let upd_clone = Arc::clone(&updates_payload);
    let parties_json = Arc::new(json!({
        "partyDetails": [
            { "party": dso, "isLocal": true },
            { "party": sv, "isLocal": true },
            { "party": validator, "isLocal": true }
        ]
    }));
    let pj_clone = Arc::clone(&parties_json);
    let ledger_end = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let le_clone = Arc::clone(&ledger_end);
    let seen_dars: Arc<Mutex<HashMap<String, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let sd_clone = Arc::clone(&seen_dars);

    let handle = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while !stop_srv.load(std::sync::atomic::Ordering::SeqCst) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = stream.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let clen: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + clen {
                        break;
                    }
                }
            }
            let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let first = head.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");

            let resp = match (method, path) {
                ("GET", "/v2/version") => json!({ "version": "3.7.2" }),
                ("GET", "/v2/state/connected-synchronizers") => {
                    json!({ "connectedSynchronizers": [{ "synchronizerId": "sync::1220mock" }] })
                }
                ("GET", "/v2/parties/participant-id") => {
                    json!({ "participantId": "PAR::mock::1220aa" })
                }
                ("POST", "/v2/dars") => {
                    let mut guard = sd_clone.lock().unwrap();
                    let n = guard.entry("dars".into()).or_insert(0);
                    *n += 1;
                    json!({})
                }
                ("GET", "/v2/parties") => (*pj_clone).clone(),
                ("POST", "/v2/users") => json!({}),
                ("GET", "/v2/state/ledger-end") => {
                    json!({ "offset": le_clone.load(std::sync::atomic::Ordering::SeqCst) })
                }
                ("POST", "/v2/updates") => (*upd_clone).clone(),
                _ => json!({}),
            };
            let out = resp.to_string();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                out.len(),
                out
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });

    let cfg = ParticipantLedgerConfig {
        host: "127.0.0.1".into(),
        port,
        admin_token: None,
        user_id: "ledger-api-user".into(),
        user_token: None,
        auth_unsafe_secret: Some("unsafe".into()),
        jwt_audience: "https://canton.network.global".into(),
        synchronizer_id: None,
        scan_history_path: None,
    };
    let client = ParticipantLedgerClient::connect_and_setup(
        cfg,
        &dars,
        &world,
        &SpliceBootstrapConfig::default(),
    )
    .expect("connect_and_setup");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = handle.join();

    // Adopted DSO/SV parties from existing DsoRules
    assert_eq!(client.dso_party(), dso);
    assert_eq!(client.sv_party(), sv);
    assert_eq!(client.last_synced_offset(), 1);
    assert_eq!(client.active_contracts().len(), 2);
    assert!(client
        .authentication_data()
        .contains_key(&dso_rules.contract_id));
    assert!(client
        .authentication_data()
        .contains_key(&open_round.contract_id));

    // Scan UpdateHistory can immediately serve /api/scan/v0/dso-party-id using synced updates + salts!
    let history = UpdateHistory::new(client.updates().to_vec())
        .with_contracts(vec![world], client.authentication_data().clone())
        .expect("with_contracts")
        .with_dso_info(DsoInfoConfig {
            sv_user: "ledger-api-user".into(),
            sv_party: Some(sv),
            initial_round: "0".into(),
        });
    let dso_resp = history.handle("GET", "/api/scan/v0/dso-party-id", "");
    assert_eq!(dso_resp.status, 200);
    let parsed_dso: Json = serde_json::from_str(&dso_resp.body).unwrap();
    assert_eq!(parsed_dso["dso_party_id"], json!(dso));

    // build_disclosed_contracts automatically attaches DsoRules + OpenMiningRound blobs
    let disclosed = client.build_disclosed_contracts(None, &json!({}));
    assert_eq!(disclosed.len(), 2);
    assert!(disclosed
        .iter()
        .any(|d| d["contractId"] == dso_rules.contract_id));
    assert!(disclosed
        .iter()
        .any(|d| d["contractId"] == open_round.contract_id));
}
