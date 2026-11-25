#![allow(clippy::unwrap_used, reason = "integration test")]
//! A-8: Streaming and pointwise `TopologyTransaction` updates (`UpdateFormat.includeTopologyEvents`),
//! party-authorization diffs (`admin_state::add_topology_txs`), external party allocation, snapshot persistence,
//! and authorization (`ReadAs(p)` per named party; `ReadAsAnyParty` when `parties` is empty).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use canton_proto::com::digitalasset::canton::crypto::v30::{
    Signature, SignatureFormat, SigningAlgorithmSpec,
};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    enums::{ParticipantPermission, TopologyChangeOp},
    party_to_participant::HostingParticipant,
    topology_mapping::Mapping,
    PartyToParticipant, SignedTopologyTransaction, TopologyMapping, TopologyTransaction,
};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use ledger_json_api::admin_state::{
    add_topology_txs, authorize_party_to_participant_in_store, topology_party_mappings,
};
use ledger_json_api::auth::sign_token;
use ledger_json_api::store::FileLog;
use ledger_json_api::{dispatch_request, AuthConfig, ExecutionService, HttpRequest};
use prost::Message as _;
use serde_json::{json, Value as Json};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_decode(text: &str) -> Vec<u8> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        buf = (buf << 6) | B64.iter().position(|b| *b == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn post(svc: &ExecutionService, path: &str, body: &Json, token: Option<&str>) -> (u16, Json) {
    let mut headers = HashMap::new();
    if let Some(tok) = token {
        headers.insert("authorization".to_string(), format!("Bearer {tok}"));
    }
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers,
            body: serde_json::to_vec(body).unwrap(),
        },
    );
    let parsed = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
    (resp.status, parsed)
}

fn upload_sample_dar(svc: &ExecutionService, token: Option<&str>) {
    let dar_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("contracts/target/sample-contract.dar");
    let mut headers = HashMap::new();
    if let Some(tok) = token {
        headers.insert("authorization".to_string(), format!("Bearer {tok}"));
    }
    let resp = dispatch_request(
        svc,
        &HttpRequest {
            method: "POST".into(),
            path: "/v2/dars".into(),
            query_params: HashMap::new(),
            headers,
            body: std::fs::read(&dar_path).expect("read sample-contract.dar"),
        },
    );
    assert_eq!(resp.status, 200);
}

fn allocate_party(svc: &ExecutionService, hint: &str, token: Option<&str>) -> String {
    let (status, resp) = post(
        svc,
        "/v2/parties",
        &json!({ "partyIdHint": hint, "identityProviderId": "" }),
        token,
    );
    assert_eq!(status, 200, "allocate {hint}: {resp}");
    resp["partyDetails"]["party"].as_str().unwrap().to_string()
}

fn create_holding(svc: &ExecutionService, party: &str, cmd_id: &str) {
    let (status, resp) = post(
        svc,
        "/v2/commands/submit-and-wait",
        &json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": party,
                        "owner": party,
                        "auditor": party,
                        "assetSymbol": "USD",
                        "amount": "10.0"
                    }
                }
            }],
            "commandId": cmd_id,
            "actAs": [party],
            "userId": "participant_admin"
        }),
        None,
    );
    assert_eq!(status, 200, "submit-and-wait: {resp}");
}

fn encoded_party_to_participant_tx(
    party: &str,
    hosting: &[(&str, i32)],
    serial: u32,
    op: TopologyChangeOp,
) -> Vec<u8> {
    let ptp = PartyToParticipant {
        party: party.to_string(),
        threshold: 1,
        participants: hosting
            .iter()
            .map(|(uid, permission)| HostingParticipant {
                participant_uid: (*uid).to_string(),
                permission: *permission,
                onboarding: None,
            })
            .collect(),
        party_signing_keys: None,
    };
    let tx = TopologyTransaction {
        operation: op as i32,
        serial,
        mapping: Some(TopologyMapping {
            mapping: Some(Mapping::PartyToParticipant(ptp)),
        }),
    };
    let signed = SignedTopologyTransaction {
        transaction: tx.encode_to_vec(),
        signatures: vec![Signature {
            format: SignatureFormat::Raw as i32,
            signature: vec![0; 64],
            signed_by: "testkey".into(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        }],
        proposal: false,
        multi_transaction_signatures: Vec::new(),
    };
    signed.encode_to_vec()
}

#[test]
fn updates_page_pointwise_and_external_party_emit_filtered_topology_transactions() {
    let svc = ExecutionService::new();
    upload_sample_dar(&svc, None);
    let alice = allocate_party(&svc, "alice", None);
    let bob = allocate_party(&svc, "bob", None);
    create_holding(&svc, &alice, "topo-create-1");

    // 1. Without includeTopologyEvents: only Daml Transaction is returned, zero TopologyTransactions.
    let (st, no_topo) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": { "filtersByParty": { &alice: {} } },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        }),
        None,
    );
    assert_eq!(st, 200, "{no_topo}");
    let no_topo_arr = no_topo.as_array().unwrap();
    assert_eq!(no_topo_arr.len(), 1);
    assert!(no_topo_arr[0].pointer("/update/Transaction").is_some());

    // 2. Topology-only updateFormat with parties: [] returns both alice and bob, and omits Daml Transaction.
    let all_topo_format = json!({
        "includeTopologyEvents": {
            "includeParticipantAuthorizationEvents": { "parties": [] }
        }
    });
    let (st, all_topo) = post(
        &svc,
        "/v2/updates",
        &json!({ "beginExclusive": 0, "updateFormat": &all_topo_format }),
        None,
    );
    assert_eq!(st, 200, "{all_topo}");
    let all_arr = all_topo.as_array().unwrap();
    assert_eq!(all_arr.len(), 2, "expected 2 topology updates: {all_topo}");
    let mut seen_parties = BTreeSet::new();
    for item in all_arr {
        assert!(item.pointer("/update/Transaction").is_none(), "{item}");
        let v = item.pointer("/update/TopologyTransaction/value").unwrap();
        let evs = v["events"].as_array().unwrap();
        assert_eq!(evs.len(), 1);
        let added = evs[0]
            .pointer("/event/ParticipantAuthorizationAdded/value")
            .unwrap();
        assert_eq!(
            added["participantPermission"],
            "PARTICIPANT_PERMISSION_SUBMISSION"
        );
        assert!(!added["participantId"].as_str().unwrap().is_empty());
        seen_parties.insert(added["partyId"].as_str().unwrap().to_string());
    }
    assert_eq!(seen_parties, BTreeSet::from([alice.clone(), bob.clone()]));

    // 3. Party-specific filter includes only alice.
    let alice_topo_format = json!({
        "includeTopologyEvents": {
            "includeParticipantAuthorizationEvents": { "parties": [&alice] }
        }
    });
    let (st, alice_only) = post(
        &svc,
        "/v2/updates",
        &json!({ "beginExclusive": 0, "updateFormat": &alice_topo_format }),
        None,
    );
    assert_eq!(st, 200);
    let alice_arr = alice_only.as_array().unwrap();
    assert_eq!(alice_arr.len(), 1);
    let alice_topo_val = alice_arr[0]
        .pointer("/update/TopologyTransaction/value")
        .unwrap();
    assert_eq!(
        alice_topo_val["events"][0]["event"]["ParticipantAuthorizationAdded"]["value"]["partyId"],
        alice
    );
    let alice_offset = alice_topo_val["offset"].as_u64().unwrap();
    let alice_update_id = alice_topo_val["updateId"].as_str().unwrap().to_string();

    // 4. get-updates-page (ascending with pagination AND descendingOrder: true).
    let (st_p1, page1) = post(
        &svc,
        "/v2/updates/get-updates-page",
        &json!({ "beginExclusive": 0, "maxPageSize": 1, "updateFormat": &all_topo_format }),
        None,
    );
    assert_eq!(st_p1, 200, "{page1}");
    assert_eq!(page1["updates"].as_array().unwrap().len(), 1);
    let next_token = page1["nextPageToken"].as_str().unwrap();
    let (st_p2, page2) = post(
        &svc,
        "/v2/updates/get-updates-page",
        &json!({
            "beginExclusive": 0,
            "maxPageSize": 1,
            "pageToken": next_token,
            "updateFormat": &all_topo_format
        }),
        None,
    );
    assert_eq!(st_p2, 200, "{page2}");
    assert_eq!(page2["updates"].as_array().unwrap().len(), 1);
    let p1_off = page1["updates"][0]["update"]["TopologyTransaction"]["value"]["offset"]
        .as_u64()
        .unwrap();
    let p2_off = page2["updates"][0]["update"]["TopologyTransaction"]["value"]["offset"]
        .as_u64()
        .unwrap();
    assert!(
        p2_off > p1_off,
        "ascending page order: {p1_off} vs {p2_off}"
    );

    let (st_desc, desc_page) = post(
        &svc,
        "/v2/updates/get-updates-page",
        &json!({
            "beginExclusive": 0,
            "maxPageSize": 10,
            "descendingOrder": true,
            "updateFormat": &all_topo_format
        }),
        None,
    );
    assert_eq!(st_desc, 200, "{desc_page}");
    let desc_updates = desc_page["updates"].as_array().unwrap();
    assert_eq!(desc_updates.len(), 2);
    assert_eq!(
        desc_updates[0]["update"]["TopologyTransaction"]["value"]["offset"].as_u64(),
        Some(p2_off)
    );
    assert_eq!(
        desc_updates[1]["update"]["TopologyTransaction"]["value"]["offset"].as_u64(),
        Some(p1_off)
    );

    // 5. Pointwise lookup by offset and by id + filtering out returns 404 UPDATE_NOT_FOUND.
    let (st_by_off, by_off) = post(
        &svc,
        "/v2/updates/update-by-offset",
        &json!({ "offset": alice_offset, "updateFormat": &alice_topo_format }),
        None,
    );
    assert_eq!(st_by_off, 200, "{by_off}");
    assert_eq!(
        by_off["update"]["TopologyTransaction"]["value"]["updateId"],
        alice_update_id
    );

    let (st_by_id, by_id) = post(
        &svc,
        "/v2/updates/update-by-id",
        &json!({ "updateId": &alice_update_id, "updateFormat": &alice_topo_format }),
        None,
    );
    assert_eq!(st_by_id, 200, "{by_id}");
    assert_eq!(
        by_id["update"]["TopologyTransaction"]["value"]["offset"],
        alice_offset
    );

    let (st_hidden, hidden) = post(
        &svc,
        "/v2/updates/update-by-id",
        &json!({
            "updateId": &alice_update_id,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&bob] }
                }
            }
        }),
        None,
    );
    assert_eq!(st_hidden, 404, "{hidden}");
    assert_eq!(hidden["code"], "UPDATE_NOT_FOUND");

    let (st_omitted, _) = post(
        &svc,
        "/v2/updates/update-by-offset",
        &json!({
            "offset": alice_offset,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": { "filtersByParty": { &alice: {} } },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        }),
        None,
    );
    assert_eq!(st_omitted, 404);

    // 6. External party allocation emits ParticipantAuthorizationAdded with CONFIRMATION permission.
    let (_, sync_resp, sync_body) = {
        let r = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: "/v2/state/connected-synchronizers".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        let j: Json = serde_json::from_slice(&r.body).unwrap();
        (r.status, j, r.body)
    };
    let sync_id = sync_resp["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap_or_else(|| panic!("sync_id: {}", String::from_utf8_lossy(&sync_body)))
        .to_string();
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let spki = sk.verifying_key().to_public_key_der().unwrap();
    let (st_gen, topo_gen) = post(
        &svc,
        "/v2/parties/external/generate-topology",
        &json!({
            "synchronizer": &sync_id,
            "partyHint": "extparty",
            "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": base64_encode(spki.as_bytes()),
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
            }
        }),
        None,
    );
    assert_eq!(st_gen, 200, "{topo_gen}");
    let ext_party = topo_gen["partyId"].as_str().unwrap().to_string();
    let fp = topo_gen["publicKeyFingerprint"].as_str().unwrap();
    let multi_hash = base64_decode(topo_gen["multiHash"].as_str().unwrap());
    let mut payload = Vec::new();
    if multi_hash.len() == 32 {
        payload.extend([0x12, 0x20]);
    }
    payload.extend(multi_hash);
    let sig_json = json!({
        "format": "SIGNATURE_FORMAT_CONCAT",
        "signature": base64_encode(&sk.sign(&payload).to_bytes()),
        "signedBy": fp,
        "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    });
    let (st_alloc, alloc_resp) = post(
        &svc,
        "/v2/parties/external/allocate",
        &json!({
            "synchronizer": &sync_id,
            "onboardingTransactions": [{ "transaction": topo_gen["topologyTransactions"][0], "signatures": [] }],
            "multiHashSignatures": [sig_json]
        }),
        None,
    );
    assert_eq!(st_alloc, 200, "{alloc_resp}");
    let (st_ext, ext_updates) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&ext_party] }
                }
            }
        }),
        None,
    );
    assert_eq!(st_ext, 200, "{ext_updates}");
    let ext_arr = ext_updates.as_array().unwrap();
    assert_eq!(ext_arr.len(), 1);
    assert_eq!(
        ext_arr[0]["update"]["TopologyTransaction"]["value"]["events"][0]["event"]
            ["ParticipantAuthorizationAdded"]["value"]["participantPermission"],
        "PARTICIPANT_PERMISSION_CONFIRMATION"
    );
}

#[test]
fn admin_topology_tx_diffs_emit_added_changed_and_revoked_and_survive_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("topo.log");

    let svc = ExecutionService::new();
    svc.attach_store(Box::new(FileLog::open(&log_path).unwrap()))
        .unwrap();

    let party = "charlie::1220cc";
    let p_a = "PAR::pa::122011";
    let p_b = "PAR::pb::122022";

    // Initial hosting on p_a (Confirmation) -> Added(2)
    let tx1 = encoded_party_to_participant_tx(
        party,
        &[(p_a, ParticipantPermission::Confirmation as i32)],
        1,
        TopologyChangeOp::AddReplace,
    );
    add_topology_txs(&svc, "sync", vec![tx1]).unwrap();

    // Update hosting on p_a to Submission and add p_b (Observation) -> Changed(1) + Added(3)
    let tx2 = encoded_party_to_participant_tx(
        party,
        &[
            (p_a, ParticipantPermission::Submission as i32),
            (p_b, ParticipantPermission::Observation as i32),
        ],
        2,
        TopologyChangeOp::AddReplace,
    );
    add_topology_txs(&svc, "sync", vec![tx2]).unwrap();

    // Revoke party hosting (Remove) -> Revoked for both p_a and p_b (without participantPermission)
    let tx3 = encoded_party_to_participant_tx(
        party,
        &[(p_a, ParticipantPermission::Submission as i32)],
        3,
        TopologyChangeOp::Remove,
    );
    add_topology_txs(&svc, "sync", vec![tx3]).unwrap();

    let query = json!({
        "beginExclusive": 0,
        "updateFormat": {
            "includeTopologyEvents": {
                "includeParticipantAuthorizationEvents": { "parties": [party] }
            }
        }
    });
    let (st, updates) = post(&svc, "/v2/updates", &query, None);
    assert_eq!(st, 200, "{updates}");
    let arr = updates.as_array().unwrap();
    assert_eq!(arr.len(), 3, "{updates}");
    assert_eq!(
        arr[0]["update"]["TopologyTransaction"]["value"]["events"][0]["event"]
            ["ParticipantAuthorizationAdded"]["value"]["participantPermission"],
        "PARTICIPANT_PERMISSION_CONFIRMATION"
    );
    let evs2 = arr[1]["update"]["TopologyTransaction"]["value"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(evs2.len(), 2);
    assert_eq!(
        evs2[0]["event"]["ParticipantAuthorizationChanged"]["value"]["participantPermission"],
        "PARTICIPANT_PERMISSION_SUBMISSION"
    );
    assert_eq!(
        evs2[1]["event"]["ParticipantAuthorizationAdded"]["value"]["participantPermission"],
        "PARTICIPANT_PERMISSION_OBSERVATION"
    );
    let evs3 = arr[2]["update"]["TopologyTransaction"]["value"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(evs3.len(), 2);
    for ev in evs3 {
        let rev = &ev["event"]["ParticipantAuthorizationRevoked"]["value"];
        assert!(rev.is_object(), "{ev}");
        assert!(
            rev.get("participantPermission").is_none(),
            "Revoked has no participantPermission: {rev}"
        );
    }

    // Save snapshot checkpoint, compact log, reopen fresh ExecutionService from snapshot.
    svc.compact_store().unwrap();
    drop(svc);

    let restored = ExecutionService::new();
    restored
        .attach_store(Box::new(FileLog::open(&log_path).unwrap()))
        .unwrap();
    let (st_restored, restored_updates) = post(&restored, "/v2/updates", &query, None);
    assert_eq!(st_restored, 200);
    assert_eq!(restored_updates, updates);
}

#[test]
fn topology_event_filters_enforce_read_as_and_read_as_any_party() {
    let secret = "topo-auth-secret";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tok = |sub: &str| {
        sign_token(
            secret,
            &json!({ "sub": sub, "scope": "daml_ledger_api", "exp": now + 120 }),
        )
    };
    let svc = ExecutionService::new();
    svc.set_auth(AuthConfig::hmac(secret));
    let admin = tok("participant_admin");
    let alice = allocate_party(&svc, "alice", Some(&admin));
    let bob = allocate_party(&svc, "bob", Some(&admin));

    for (id, rights) in [
        (
            "alice_reader",
            vec![json!({"kind": {"CanReadAs": {"value": {"party": &alice}}}})],
        ),
        (
            "any_reader",
            vec![json!({"kind": {"CanReadAsAnyParty": {"value": {}}}})],
        ),
    ] {
        let (st, resp) = post(
            &svc,
            "/v2/users",
            &json!({ "user": { "id": id }, "rights": rights }),
            Some(&admin),
        );
        assert_eq!(st, 200, "create user {id}: {resp}");
    }

    let alice_tok = tok("alice_reader");
    let any_tok = tok("any_reader");

    // 1. Named party alice succeeds for alice_reader.
    let (st_ok, _) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&alice] }
                }
            }
        }),
        Some(&alice_tok),
    );
    assert_eq!(st_ok, 200);

    // 2. Named party bob fails (403) for alice_reader.
    let (st_bob, body_bob) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [&bob] }
                }
            }
        }),
        Some(&alice_tok),
    );
    assert_eq!((st_bob, &body_bob["grpcCodeValue"]), (403, &json!(7)));

    // 3. Wildcard empty `parties` requires ReadAsAnyParty -> 403 for alice_reader (alone OR alongside readable transactions).
    for format in [
        json!({
            "includeTopologyEvents": {
                "includeParticipantAuthorizationEvents": { "parties": [] }
            }
        }),
        json!({
            "includeTransactions": {
                "eventFormat": { "filtersByParty": { &alice: {} } },
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            },
            "includeTopologyEvents": {
                "includeParticipantAuthorizationEvents": { "parties": [] }
            }
        }),
    ] {
        let (st_wild, body_wild) = post(
            &svc,
            "/v2/updates",
            &json!({ "beginExclusive": 0, "updateFormat": format }),
            Some(&alice_tok),
        );
        assert_eq!((st_wild, &body_wild["grpcCodeValue"]), (403, &json!(7)));
    }

    // 4. CanReadAsAnyParty user succeeds on wildcard `parties: []`.
    let (st_any, body_any) = post(
        &svc,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTopologyEvents": {
                    "includeParticipantAuthorizationEvents": { "parties": [] }
                }
            }
        }),
        Some(&any_tok),
    );
    assert_eq!(st_any, 200, "{body_any}");
    assert_eq!(body_any.as_array().unwrap().len(), 2);
}

/// R-13f: non-string elements in `includeParticipantAuthorizationEvents.parties` (or wrong field types) must fail with HTTP 400
/// instead of silently dropping invalid items and widening to `AllParties`.
#[test]
fn r13f_non_string_parties_in_topology_filter_returns_400() {
    let svc = ExecutionService::new();
    let alice = allocate_party(&svc, "alice", None);
    let _bob = allocate_party(&svc, "bob", None);

    for bad_pa in [
        json!({ "parties": [&alice, 123] }),
        json!({ "parties": [123] }),
        json!({ "parties": "alice" }),
        json!(123),
    ] {
        for (path, req_body) in [
            (
                "/v2/updates",
                json!({
                    "beginExclusive": 0,
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": bad_pa
                        }
                    }
                }),
            ),
            (
                "/v2/updates/get-updates-page",
                json!({
                    "beginOffsetExclusive": 0,
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": bad_pa
                        }
                    }
                }),
            ),
            (
                "/v2/updates/update-by-offset",
                json!({
                    "offset": 1,
                    "updateFormat": {
                        "includeTopologyEvents": {
                            "includeParticipantAuthorizationEvents": bad_pa
                        }
                    }
                }),
            ),
        ] {
            let (st, resp) = post(&svc, path, &req_body, None);
            assert_eq!(
                st, 400,
                "{path} must reject invalid topology filter {bad_pa}: {resp}"
            );
        }
    }

    // Positive controls: omitted `parties`, `parties: []`, and valid `parties: [alice]` succeed.
    for good_pa in [
        json!({}),
        json!({ "parties": [] }),
        json!({ "parties": [&alice] }),
    ] {
        let (st, resp) = post(
            &svc,
            "/v2/updates",
            &json!({
                "beginExclusive": 0,
                "updateFormat": {
                    "includeTopologyEvents": {
                        "includeParticipantAuthorizationEvents": good_pa
                    }
                }
            }),
            None,
        );
        assert_eq!(st, 200, "valid topology filter {good_pa} failed: {resp}");
    }
}

/// R-7: topology events must come only from non-proposal fully signed synchronizer-store diffs (not proposals, Authorized store,
/// or duplicates), handle `Onboarding` + `PAR::` normalization (`TopologyTransactionDiff.scala:48-74`), emit all `canHost` hosts
/// on external allocation, and never leak into ExEx `backfill_stored_updates` / `replay_updates_to_subscribers`.
#[test]
fn r7_topology_events_require_effective_non_proposal_synchronizer_txs_and_skip_exex() {
    use canton_proto::com::digitalasset::canton::protocol::v30::party_to_participant::hosting_participant::Onboarding;
    use ledger_json_api::exex::ExExPartyScope;

    let svc = ExecutionService::new();
    let sync = "mysync::12207ba0";
    let fetch_topo = |party: Option<&str>| -> Vec<Json> {
        let pa = match party {
            Some(p) => json!({ "parties": [p] }),
            None => json!({ "parties": [] }),
        };
        let (st, resp) = post(
            &svc,
            "/v2/updates",
            &json!({
                "beginExclusive": 0,
                "updateFormat": {
                    "includeTopologyEvents": {
                        "includeParticipantAuthorizationEvents": pa
                    }
                }
            }),
            None,
        );
        assert_eq!(st, 200, "{resp}");
        resp.as_array().unwrap().clone()
    };
    let build_tx = |party: &str,
                    hosting: &[(&str, i32, bool)],
                    serial: u32,
                    op: TopologyChangeOp,
                    proposal: bool,
                    signed: bool| {
        let ptp = PartyToParticipant {
            party: party.to_string(),
            threshold: 1,
            participants: hosting
                .iter()
                .map(|(uid, permission, is_onboarding)| HostingParticipant {
                    participant_uid: (*uid).to_string(),
                    permission: *permission,
                    onboarding: is_onboarding.then_some(Onboarding {}),
                })
                .collect(),
            party_signing_keys: None,
        };
        let tx = TopologyTransaction {
            operation: op as i32,
            serial,
            mapping: Some(TopologyMapping {
                mapping: Some(Mapping::PartyToParticipant(ptp)),
            }),
        };
        let sigs = if signed {
            vec![Signature {
                format: SignatureFormat::Raw as i32,
                signature: vec![0; 64],
                signed_by: "testkey".into(),
                signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
                signature_delegation: None,
            }]
        } else {
            Vec::new()
        };
        SignedTopologyTransaction {
            transaction: tx.encode_to_vec(),
            signatures: sigs,
            proposal,
            multi_transaction_signatures: Vec::new(),
        }
        .encode_to_vec()
    };

    // 1. Proposals and unsigned txs on synchronizer store must emit 0 events.
    let prop_tx = build_tx(
        "prop::1220aa",
        &[(
            "p1::122011",
            ParticipantPermission::Confirmation as i32,
            false,
        )],
        1,
        TopologyChangeOp::AddReplace,
        true,
        true,
    );
    add_topology_txs(&svc, sync, vec![prop_tx]).unwrap();
    assert!(
        fetch_topo(None).is_empty(),
        "proposal topology tx must emit 0 events"
    );

    let unsigned_tx = build_tx(
        "unsigned::1220aa",
        &[(
            "p1::122011",
            ParticipantPermission::Confirmation as i32,
            false,
        )],
        1,
        TopologyChangeOp::AddReplace,
        false,
        false,
    );
    add_topology_txs(&svc, sync, vec![unsigned_tx]).unwrap();
    assert!(
        fetch_topo(None).is_empty(),
        "unsigned topology tx must emit 0 events"
    );

    // 2. Authorized store must NOT directly emit Ledger API events.
    let auth_tx = build_tx(
        "authonly::1220aa",
        &[(
            "p1::122011",
            ParticipantPermission::Submission as i32,
            false,
        )],
        1,
        TopologyChangeOp::AddReplace,
        false,
        true,
    );
    add_topology_txs(&svc, "Authorized", vec![auth_tx]).unwrap();
    assert!(
        fetch_topo(None).is_empty(),
        "Authorized store add_topology_txs must emit 0 Ledger API events"
    );

    // 3. Synchronizer store effective tx normalizes `PAR::` to bare UID and deduplicates repeats.
    let eff_tx = build_tx(
        "bare::1220bb",
        &[(
            "PAR::p1::122011",
            ParticipantPermission::Submission as i32,
            false,
        )],
        1,
        TopologyChangeOp::AddReplace,
        false,
        true,
    );
    add_topology_txs(&svc, sync, vec![eff_tx.clone(), eff_tx]).unwrap();
    let bare_updates = fetch_topo(Some("bare::1220bb"));
    assert_eq!(bare_updates.len(), 1, "{bare_updates:?}");
    assert_eq!(
        bare_updates[0]["update"]["TopologyTransaction"]["value"]["synchronizerId"],
        sync
    );
    assert_eq!(
        bare_updates[0]["update"]["TopologyTransaction"]["value"]["events"][0]["event"]
            ["ParticipantAuthorizationAdded"]["value"]["participantId"],
        "p1::122011"
    );

    // 4. Onboarding -> Active with permission upgrade emits Added + Changed per TopologyTransactionDiff.scala:51-68.
    let onb_tx = build_tx(
        "onb::1220cc",
        &[(
            "p1::122011",
            ParticipantPermission::Confirmation as i32,
            true,
        )],
        1,
        TopologyChangeOp::AddReplace,
        false,
        true,
    );
    add_topology_txs(&svc, sync, vec![onb_tx]).unwrap();
    let onb_updates = fetch_topo(Some("onb::1220cc"));
    assert_eq!(onb_updates.len(), 1, "{onb_updates:?}");
    assert_eq!(
        onb_updates[0]["update"]["TopologyTransaction"]["value"]["events"][0]["event"]
            ["ParticipantAuthorizationOnboarding"]["value"]["participantPermission"],
        "PARTICIPANT_PERMISSION_CONFIRMATION"
    );
    let act_tx = build_tx(
        "onb::1220cc",
        &[(
            "p1::122011",
            ParticipantPermission::Submission as i32,
            false,
        )],
        2,
        TopologyChangeOp::AddReplace,
        false,
        true,
    );
    add_topology_txs(&svc, sync, vec![act_tx]).unwrap();
    let onb_after = fetch_topo(Some("onb::1220cc"));
    assert_eq!(onb_after.len(), 2, "{onb_after:?}");
    let evs = onb_after[1]["update"]["TopologyTransaction"]["value"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(
        evs.len(),
        2,
        "Onboarding->Active with perm change emits Added + Changed: {evs:?}"
    );
    assert!(evs[0]["event"]["ParticipantAuthorizationAdded"].is_object());
    assert!(evs[1]["event"]["ParticipantAuthorizationChanged"].is_object());

    // 5. External party allocation with multi-host PartyToParticipant emits events for all canHost hosts (bare UIDs).
    let (st_sync, sync_resp) = {
        let r = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: "/v2/state/connected-synchronizers".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        (r.status, serde_json::from_slice::<Json>(&r.body).unwrap())
    };
    assert_eq!(st_sync, 200);
    let live_sync = sync_resp["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let spki = sk.verifying_key().to_public_key_der().unwrap();
    let (st_gen, topo_gen) = post(
        &svc,
        "/v2/parties/external/generate-topology",
        &json!({
            "synchronizer": &live_sync,
            "partyHint": "multiext",
            "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": base64_encode(spki.as_bytes()),
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
            },
            "otherConfirmingParticipantUids": ["PAR::p2::122022"],
            "observingParticipantUids": ["p3::122033"]
        }),
        None,
    );
    assert_eq!(st_gen, 200, "{topo_gen}");
    let ext_party = topo_gen["partyId"].as_str().unwrap().to_string();
    let fp = topo_gen["publicKeyFingerprint"].as_str().unwrap();
    let multi_hash = base64_decode(topo_gen["multiHash"].as_str().unwrap());
    let mut payload = Vec::new();
    if multi_hash.len() == 32 {
        payload.extend([0x12, 0x20]);
    }
    payload.extend(multi_hash);
    let sig_json = json!({
        "format": "SIGNATURE_FORMAT_CONCAT",
        "signature": base64_encode(&sk.sign(&payload).to_bytes()),
        "signedBy": fp,
        "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    });
    let (st_alloc, alloc_resp) = post(
        &svc,
        "/v2/parties/external/allocate",
        &json!({
            "synchronizer": &live_sync,
            "onboardingTransactions": [{ "transaction": topo_gen["topologyTransactions"][0], "signatures": [] }],
            "multiHashSignatures": [sig_json]
        }),
        None,
    );
    assert_eq!(st_alloc, 200, "{alloc_resp}");
    let ext_updates = fetch_topo(Some(&ext_party));
    assert_eq!(ext_updates.len(), 1, "{ext_updates:?}");
    let ext_evs = ext_updates[0]["update"]["TopologyTransaction"]["value"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(
        ext_evs.len(),
        3,
        "external multi-host allocation must emit all 3 canHost hosts: {ext_evs:?}"
    );
    let mut pids: Vec<&str> = ext_evs
        .iter()
        .map(|e| {
            e["event"]["ParticipantAuthorizationAdded"]["value"]["participantId"]
                .as_str()
                .unwrap()
        })
        .collect();
    pids.sort();
    assert!(
        pids.contains(&"p2::122022") && pids.contains(&"p3::122033"),
        "expected bare UIDs for all hosts: {pids:?}"
    );
    assert!(pids.iter().all(|p| !p.starts_with("PAR::")), "{pids:?}");

    // 6. ExEx backfill_stored_updates with AllParticipantVisible must skip TopologyTransaction updates.
    upload_sample_dar(&svc, None);
    let local_p = allocate_party(&svc, "localp", None);
    create_holding(&svc, &local_p, "r7-exex-cmd");
    let backfilled = svc.backfill_exex_from(0, &ExExPartyScope::AllParticipantVisible);
    assert_eq!(
        backfilled.len(),
        1,
        "ExEx backfill must skip topology updates and only yield the 1 contract transaction: {backfilled:?}"
    );
}

#[test]
fn r7_authorized_store_not_in_sync_party_mappings() {
    let svc = ExecutionService::new();
    let (staged_party, _raw) = authorize_party_to_participant_in_store(
        &svc,
        "staged-only",
        None,
        false,
        Some("Authorized"),
    )
    .expect("authorize into Authorized store");
    let mappings = topology_party_mappings(&svc);
    assert!(
        !mappings.iter().any(|(party, _, _)| party == &staged_party),
        "Authorized-store staging must NOT appear in live Synchronizer topology_party_mappings: {mappings:?}"
    );
}

#[test]
fn r7_multihost_authorize_enforces_must_fully_authorize_and_proposals_do_not_host() {
    use ledger_json_api::admin_state::{
        authorize_party_to_participant_spec, topology_party_mappings_in_store, PartyAuthorizeSpec,
    };

    let svc = ExecutionService::new();
    let own_uid = svc.participant_id();
    let remote_uid = "PAR::remote-p2::122022222222";

    // (a) `must_fully_authorize = true` with a remote hosting participant must fail loudly (9) with zero state changes.
    let err = authorize_party_to_participant_spec(
        &svc,
        PartyAuthorizeSpec {
            party: "multihost",
            participants: vec![(own_uid.clone(), 1, false), (remote_uid.into(), 2, false)],
            threshold: 2,
            serial: 1,
            operation: TopologyChangeOp::AddReplace as i32,
            signed_by: Vec::new(),
            must_fully_authorize: true,
            apply_to_synchronizer: true,
            synchronizer_id: Some("mysync::1220sync"),
        },
    )
    .expect_err("missing remote participant signature must fail when must_fully_authorize=true");
    assert_eq!(err.0, 9, "{err:?}");
    assert!(err.1.contains("NOT_FULLY_AUTHORIZED"), "{err:?}");

    let hosted_parties = || -> Vec<String> {
        let r = dispatch_request(
            &svc,
            &HttpRequest {
                method: "GET".into(),
                path: "/v2/parties".into(),
                query_params: HashMap::new(),
                headers: HashMap::new(),
                body: Vec::new(),
            },
        );
        assert_eq!(r.status, 200);
        let body: Json = serde_json::from_slice(&r.body).unwrap();
        body["partyDetails"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["party"].as_str().map(str::to_string))
            .collect()
    };
    let topo_updates = || -> Vec<Json> {
        let (st, body) = post(
            &svc,
            "/v2/updates",
            &json!({
                "beginExclusive": 0,
                "updateFormat": {
                    "includeTopologyEvents": {
                        "includeParticipantAuthorizationEvents": {}
                    }
                }
            }),
            None,
        );
        assert_eq!(st, 200, "{body}");
        body.as_array().cloned().unwrap_or_default()
    };
    assert!(
        !hosted_parties()
            .into_iter()
            .any(|p| p.starts_with("multihost::")),
        "failed must_fully_authorize must not host party"
    );
    assert!(topo_updates().is_empty(), "{:?}", topo_updates());

    // (b) `must_fully_authorize = false` stores as proposal, does NOT host in `/v2/parties`, does NOT appear
    // in live effective `topology_party_mappings`, emits 0 events, and IS visible when querying proposals=true.
    let (party_id, raw_tx) = authorize_party_to_participant_spec(
        &svc,
        PartyAuthorizeSpec {
            party: "multihost",
            participants: vec![(own_uid, 1, false), (remote_uid.into(), 2, false)],
            threshold: 2,
            serial: 1,
            operation: TopologyChangeOp::AddReplace as i32,
            signed_by: Vec::new(),
            must_fully_authorize: false,
            apply_to_synchronizer: true,
            synchronizer_id: Some("mysync::1220sync"),
        },
    )
    .expect("must_fully_authorize=false stores proposal");
    let decoded = SignedTopologyTransaction::decode(raw_tx.as_slice()).expect("decode signed");
    assert!(
        decoded.proposal,
        "multi-host tx without peer sig must be marked proposal"
    );
    assert!(
        !hosted_parties().into_iter().any(|p| p == party_id),
        "partial proposal must NOT host party in /v2/parties"
    );
    let live = topology_party_mappings(&svc);
    assert!(
        !live.iter().any(|(p, _, _)| p == &party_id),
        "partial proposal must NOT appear in live effective mappings: {live:?}"
    );
    assert!(
        topo_updates().is_empty(),
        "partial proposal must emit 0 Ledger API TopologyTransaction events"
    );
    let proposals = topology_party_mappings_in_store(&svc, Some("mysync::1220sync"), true)
        .expect("proposals query");
    assert_eq!(
        proposals.iter().filter(|(p, _, _)| p == &party_id).count(),
        2,
        "proposals query must surface both hosting entries of stored proposal: {proposals:?}"
    );
}
