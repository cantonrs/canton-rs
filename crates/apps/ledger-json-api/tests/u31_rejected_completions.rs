//! U-31 (S-API-025): synchronizer-rejected command completions.
//!
//! Pre-submission failures (missing fields, unknown templates, Daml-LF interpretation failures)
//! never create completions or advance `ledger_end`. Once a submission reaches the synchronizer and
//! receives a synchronizer rejection (`ApiError::SynchronizerRejected`), ACS mutations roll back,
//! no transaction update is emitted, `ledger_end` advances with a non-zero `status` `Completion`
//! (`updateId == ""`), async `/v2/commands/submit` and `/v2/interactive-submission/execute` still
//! answer `200 {}`, and rejected attempts do not poison command deduplication.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use ledger_json_api::service::{ApiError, ExecutionService, ProtocolCommitter, TransactionCommit};
use ledger_json_api::{dispatch_request, HttpRequest};
use lf_eval::engine::NewContract;
use serde_json::{json, Value as Json};

fn sample_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

#[derive(Default)]
struct RejectingCommitter {
    next_cid: AtomicUsize,
    next_rejection: Mutex<Option<ApiError>>,
}

impl RejectingCommitter {
    fn set_rejection(&self, err: Option<ApiError>) {
        *self.next_rejection.lock().expect("rejection lock") = err;
    }
}

impl ProtocolCommitter for RejectingCommitter {
    fn allocate_contract_id(
        &self,
        _new: &NewContract<'_>,
        _session: &mut Option<u64>,
    ) -> Option<String> {
        let n = self.next_cid.fetch_add(1, Ordering::SeqCst) + 1;
        Some(format!("00{:064x}", n))
    }

    fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
        if let Some(err) = self
            .next_rejection
            .lock()
            .expect("rejection lock")
            .as_ref()
            .map(clone_api_err)
        {
            return Err(err);
        }
        Ok(())
    }
}

fn clone_api_err(err: &ApiError) -> ApiError {
    match err {
        ApiError::SynchronizerRejected {
            code,
            cause,
            grpc_code,
            http_status,
            category,
            details,
        } => ApiError::SynchronizerRejected {
            code: code.clone(),
            cause: cause.clone(),
            grpc_code: *grpc_code,
            http_status: *http_status,
            category: *category,
            details: details.clone(),
        },
        other => ApiError::Ledger(other.to_string()),
    }
}

fn post(service: &ExecutionService, path: &str, body: &Json) -> (u16, Json) {
    let req = HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: body.to_string().into_bytes(),
    };
    let resp = dispatch_request(service, &req);
    let parsed = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(&resp.body).into_owned()));
    (resp.status, parsed)
}

fn get(service: &ExecutionService, path: &str) -> (u16, Json) {
    let req = HttpRequest {
        method: "GET".into(),
        path: path.into(),
        query_params: Default::default(),
        headers: Default::default(),
        body: Vec::new(),
    };
    let resp = dispatch_request(service, &req);
    let parsed = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Json::String(String::from_utf8_lossy(&resp.body).into_owned()));
    (resp.status, parsed)
}

fn b64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(text: &str) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.trim_end_matches('=').bytes() {
        let Some(v) = B64.iter().position(|b| *b == c) else {
            continue;
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

fn setup_service() -> (ExecutionService, Arc<RejectingCommitter>, String) {
    let service = ExecutionService::new();
    service.load_dar(&sample_dar()).expect("load sample dar");
    let committer = Arc::new(RejectingCommitter::default());
    service.set_committer(Arc::clone(&committer) as Arc<_>);
    let (st, p) = post(&service, "/v2/parties", &json!({ "partyIdHint": "alice" }));
    assert_eq!(st, 200, "{p}");
    let alice = p["partyDetails"]["party"].as_str().unwrap().to_string();
    (service, committer, alice)
}

fn create_cmd(party: &str, command_id: &str, amount: &str) -> Json {
    json!({
        "commands": [{
            "CreateCommand": {
                "templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {
                    "bank": party,
                    "owner": party,
                    "auditor": party,
                    "assetSymbol": "USD",
                    "amount": amount
                }
            }
        }],
        "userId": "u-u31",
        "commandId": command_id,
        "actAs": [party]
    })
}

#[test]
fn sync_rejected_submit_and_wait_and_async_record_rejected_completion_and_allow_retry() {
    let (service, committer, alice) = setup_service();

    let base_end = get(&service, "/v2/state/ledger-end").1["offset"]
        .as_u64()
        .unwrap();
    // 1. Accepted baseline create -> base_end + 1.
    let (st, ok_resp) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &create_cmd(&alice, "cmd-ok", "10.0"),
    );
    assert_eq!(st, 200, "{ok_resp}");
    assert_eq!(ok_resp["completionOffset"], base_end + 1);
    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        base_end + 1
    );

    // 2. Synchronizer rejects synchronously with LOCAL_VERDICT_INACTIVE_CONTRACTS (404 / gRPC 5 / cat 11).
    committer.set_rejection(Some(ApiError::SynchronizerRejected {
        code: "LOCAL_VERDICT_INACTIVE_CONTRACTS".into(),
        cause: "Rejected transaction is referring to inactive contracts".into(),
        grpc_code: 5,
        http_status: 404,
        category: 11,
        details: None,
    }));
    let (st, err_resp) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &create_cmd(&alice, "cmd-retryable", "25.0"),
    );
    assert_eq!(st, 404, "{err_resp}");
    assert_eq!(err_resp["code"], "LOCAL_VERDICT_INACTIVE_CONTRACTS");
    assert_eq!(err_resp["grpcCodeValue"], 5);
    assert_eq!(err_resp["errorCategory"], 11);

    // ledger_end advanced to base_end + 2, no new update recorded, ACS still has 1 contract.
    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        base_end + 2
    );
    let (_, updates) = post(
        &service,
        "/v2/updates",
        &json!({
            "beginExclusive": 0,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": { "filtersByParty": { (alice.clone()): {} } },
                    "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
                }
            }
        }),
    );
    let initial_updates = updates.as_array().unwrap().len();
    assert_eq!(initial_updates, 1, "{updates}");
    let acs = service.get_active_contracts(&[]).unwrap();
    assert_eq!(acs.active_contracts.len(), 1);

    // Rejected completion appears on both /v2/commands/completions and /v2/commands/command-completions.
    let (st, comps) = post(
        &service,
        "/v2/commands/completions",
        &json!({ "userId": "u-u31", "parties": [alice], "beginExclusive": base_end + 1 }),
    );
    assert_eq!(st, 200, "{comps}");
    let items = comps.as_array().unwrap();
    assert_eq!(items.len(), 1, "{comps}");
    let comp = &items[0]["completionResponse"]["Completion"]["value"];
    assert_eq!(comp["commandId"], "cmd-retryable");
    assert_eq!(comp["offset"], base_end + 2);
    assert_eq!(comp["updateId"], "");
    assert_eq!(comp["status"]["code"], 5);
    assert!(
        comp["status"]["message"]
            .as_str()
            .unwrap()
            .starts_with("LOCAL_VERDICT_INACTIVE_CONTRACTS(11,0): "),
        "{comp}"
    );

    // 3. Asynchronous /v2/commands/async/submit returns 200 {} even when synchronizer rejects, recording base_end + 3.
    committer.set_rejection(Some(ApiError::SynchronizerRejected {
        code: "MEDIATOR_SAYS_TX_TIMED_OUT".into(),
        cause: "no verdict within timeout".into(),
        grpc_code: 10,
        http_status: 409,
        category: 2,
        details: None,
    }));
    let (st, async_resp) = post(
        &service,
        "/v2/commands/async/submit",
        &create_cmd(&alice, "cmd-async-timeout", "30.0"),
    );
    assert_eq!(st, 200, "{async_resp}");
    assert_eq!(async_resp, json!({}));
    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        base_end + 3
    );

    // 3b. Synchronous /v2/commands/submit-and-wait-for-transaction (wrapped `{ "commands": ... }`) also records rejected completion.
    committer.set_rejection(Some(ApiError::SynchronizerRejected {
        code: "LOCAL_VERDICT_LOCKED_CONTRACTS".into(),
        cause: "contract is locked".into(),
        grpc_code: 10,
        http_status: 409,
        category: 2,
        details: None,
    }));
    let (st, tx_err_resp) = post(
        &service,
        "/v2/commands/submit-and-wait-for-transaction",
        &json!({ "commands": create_cmd(&alice, "cmd-wait-tx-locked", "31.0") }),
    );
    assert_eq!(st, 409, "{tx_err_resp}");
    assert_eq!(tx_err_resp["code"], "LOCAL_VERDICT_LOCKED_CONTRACTS");
    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        base_end + 4
    );

    let (st, cmd_comps) = post(
        &service,
        "/v2/commands/command-completions",
        &json!({ "parties": [alice], "beginExclusive": base_end + 2 }),
    );
    assert_eq!(st, 200, "{cmd_comps}");
    let items = cmd_comps.as_array().unwrap();
    assert_eq!(items.len(), 2, "{cmd_comps}");
    let c3 = &items[0]["completionResponse"]["Completion"]["value"];
    assert_eq!(c3["commandId"], "cmd-async-timeout");
    assert_eq!(c3["offset"], base_end + 3);
    assert_eq!(c3["updateId"], "");
    assert_eq!(c3["status"]["code"], 10);
    assert!(
        c3["status"]["message"]
            .as_str()
            .unwrap()
            .starts_with("MEDIATOR_SAYS_TX_TIMED_OUT(2,0): "),
        "{c3}"
    );
    let c4 = &items[1]["completionResponse"]["Completion"]["value"];
    assert_eq!(c4["commandId"], "cmd-wait-tx-locked");
    assert_eq!(c4["offset"], base_end + 4);
    assert_eq!(c4["updateId"], "");

    // 4. Retry with the SAME commandId ("cmd-retryable") succeeds when synchronizer approves; then another retry is deduplicated.
    committer.set_rejection(None);
    let (st, retry_resp) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &create_cmd(&alice, "cmd-retryable", "25.0"),
    );
    assert_eq!(st, 200, "{retry_resp}");
    assert_eq!(retry_resp["completionOffset"], base_end + 5);

    let (st, dup_resp) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &create_cmd(&alice, "cmd-retryable", "25.0"),
    );
    assert_eq!(st, 409, "{dup_resp}");
    assert_eq!(dup_resp["code"], "DUPLICATE_COMMAND");

    // 5. Negative controls: pre-submission failures must NOT advance ledger_end or emit completions.
    let end_before_neg = get(&service, "/v2/state/ledger-end").1["offset"]
        .as_u64()
        .unwrap();
    let (st, _) = post(&service, "/v2/commands/submit-and-wait", &json!({}));
    assert_eq!(st, 400);
    let (st, _) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &json!({
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:NoSuchTemplate",
                    "createArguments": {}
                }
            }],
            "userId": "u-u31",
            "commandId": "neg-tmpl",
            "actAs": [alice]
        }),
    );
    assert_eq!(st, 404);
    let (st, _) = post(
        &service,
        "/v2/commands/submit-and-wait",
        &create_cmd(&alice, "neg-ensure", "-5.0"),
    );
    assert_eq!(st, 400);
    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        end_before_neg
    );
}

#[test]
fn interactive_execute_rejected_records_completion_by_hash_and_retry_keeps_history() {
    let (service, committer, _alice) = setup_service();
    let sync_id = get(&service, "/v2/state/connected-synchronizers").1["connectedSynchronizers"][0]
        ["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();

    let mut sk_bytes = [0u8; 32];
    sk_bytes[0] = 42;
    let sk = SigningKey::from_bytes(&sk_bytes);
    let spki = sk.verifying_key().to_public_key_der().unwrap();

    let (st, gen) = post(
        &service,
        "/v2/parties/external/generate-topology",
        &json!({
            "synchronizer": sync_id,
            "partyHint": "ext_u31",
            "publicKey": {
                "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                "keyData": b64_encode(spki.as_bytes()),
                "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
            }
        }),
    );
    assert_eq!(st, 200, "{gen}");
    let party_id = gen["partyId"].as_str().unwrap().to_string();
    let fp = gen["publicKeyFingerprint"].as_str().unwrap().to_string();
    let topo0 = gen["topologyTransactions"][0].as_str().unwrap().to_string();
    let multi_hash = gen["multiHash"].as_str().unwrap().to_string();
    let sig_mh = sk.sign(&b64_decode(&multi_hash));
    let (st, alloc) = post(
        &service,
        "/v2/parties/external/allocate",
        &json!({
            "synchronizer": sync_id,
            "onboardingTransactions": [{ "transaction": topo0, "signatures": [] }],
            "multiHashSignatures": [{
                "format": "SIGNATURE_FORMAT_CONCAT",
                "signature": b64_encode(&sig_mh.to_bytes()),
                "signedBy": fp,
                "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
            }]
        }),
    );
    assert_eq!(st, 200, "{alloc}");

    let (st, prep) = post(
        &service,
        "/v2/interactive-submission/prepare",
        &json!({
            "commandId": "ext-u31-cmd",
            "userId": "u-ext",
            "actAs": [party_id],
            "synchronizerId": sync_id,
            "packageIdSelectionPreference": [],
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": party_id,
                        "owner": party_id,
                        "auditor": party_id,
                        "assetSymbol": "USD",
                        "amount": "99.0"
                    }
                }
            }]
        }),
    );
    assert_eq!(st, 200, "{prep}");
    let prep_tx = prep["preparedTransaction"].as_str().unwrap().to_string();
    let prep_hash = prep["preparedTransactionHash"]
        .as_str()
        .unwrap()
        .to_string();
    let sig = sk.sign(&b64_decode(&prep_hash));
    let exec_body = json!({
        "preparedTransaction": prep_tx,
        "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2",
        "deduplicationPeriod": { "Empty": {} },
        "submissionId": "sub-ext-u31",
        "partySignatures": {
            "signatures": [{
                "party": party_id,
                "signatures": [{
                    "format": "SIGNATURE_FORMAT_CONCAT",
                    "signature": b64_encode(&sig.to_bytes()),
                    "signedBy": fp,
                    "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
                }]
            }]
        }
    });

    // 1. Synchronous interactive rejection with conformance check (HTTP 400, gRPC 3, cat 5).
    committer.set_rejection(Some(ApiError::SynchronizerRejected {
        code: "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK".into(),
        cause: "Rejected transaction due to a failed model conformance check".into(),
        grpc_code: 3,
        http_status: 400,
        category: 5,
        details: None,
    }));
    let (st, r1) = post(
        &service,
        "/v2/interactive-submission/executeAndWait",
        &exec_body,
    );
    assert_eq!(st, 400, "{r1}");
    assert_eq!(
        r1["code"], "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK",
        "{r1}"
    );

    let (st, by_hash1) = post(
        &service,
        "/v2/commands/completion-by-hash",
        &json!({ "transactionHash": prep_hash, "parties": [party_id] }),
    );
    assert_eq!(st, 200, "{by_hash1}");
    assert!(by_hash1["acceptedCompletion"].is_null(), "{by_hash1}");
    let rej1 = by_hash1["lastRejectedCompletions"].as_array().unwrap();
    assert_eq!(rej1.len(), 1);
    assert_eq!(rej1[0]["status"]["code"], 3);
    assert_eq!(rej1[0]["updateId"], "");
    assert_eq!(rej1[0]["transactionHash"], prep_hash);

    // 2. Async interactive /execute returns 200 {} on synchronizer rejection.
    committer.set_rejection(Some(ApiError::SynchronizerRejected {
        code: "LOCAL_VERDICT_LOCKED_CONTRACTS".into(),
        cause: "Local verdict: contract is locked".into(),
        grpc_code: 10,
        http_status: 409,
        category: 2,
        details: None,
    }));
    let (st, r2) = post(&service, "/v2/interactive-submission/execute", &exec_body);
    assert_eq!(st, 200, "{r2}");
    assert_eq!(r2, json!({}));

    let (st, by_hash2) = post(
        &service,
        "/v2/commands/completion-by-hash",
        &json!({ "transactionHash": prep_hash, "parties": [party_id] }),
    );
    assert_eq!(st, 200, "{by_hash2}");
    assert!(by_hash2["acceptedCompletion"].is_null());
    let rej2 = by_hash2["lastRejectedCompletions"].as_array().unwrap();
    assert_eq!(rej2.len(), 2);
    assert!(rej2[0]["offset"].as_u64().unwrap() > rej2[1]["offset"].as_u64().unwrap());
    assert_eq!(rej2[0]["status"]["code"], 10);
    assert_eq!(rej2[1]["status"]["code"], 3);

    // 3. Re-prepare (because prepare cache entry was consumed) and retry under same commandId, or reuse prep_tx via re-execute.
    committer.set_rejection(None);
    let (st, r3) = post(
        &service,
        "/v2/interactive-submission/executeAndWait",
        &exec_body,
    );
    assert_eq!(st, 200, "{r3}");
    let (st, by_hash3) = post(
        &service,
        "/v2/commands/completion-by-hash",
        &json!({ "transactionHash": prep_hash, "parties": [party_id] }),
    );
    assert_eq!(st, 200, "{by_hash3}");
    assert_eq!(by_hash3["acceptedCompletion"]["status"]["code"], 0);
    assert_ne!(by_hash3["acceptedCompletion"]["updateId"], "");
    assert_eq!(
        by_hash3["lastRejectedCompletions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// Every `actAs` party of an executed transaction has to have signed it, and its signatures are checked against the signing keys the
/// party registered (`InteractiveSubmission.verifySignatures`, Canton 3.7.2): a party hosted here without external signing keys is
/// not a way around the signature.
#[test]
fn interactive_execute_refuses_an_act_as_party_that_is_not_externally_signed() {
    let (service, _committer, alice) = setup_service();
    let sync_id = get(&service, "/v2/state/connected-synchronizers").1["connectedSynchronizers"][0]
        ["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, prep) = post(
        &service,
        "/v2/interactive-submission/prepare",
        &json!({
            "commandId": "local-act-as",
            "userId": "u-local",
            "actAs": [alice],
            "synchronizerId": sync_id,
            "packageIdSelectionPreference": [],
            "commands": [{
                "CreateCommand": {
                    "templateId": "#sample-contract:AssetHolding:AssetHolding",
                    "createArguments": {
                        "bank": alice,
                        "owner": alice,
                        "auditor": alice,
                        "assetSymbol": "USD",
                        "amount": "1.0"
                    }
                }
            }]
        }),
    );
    assert_eq!(st, 200, "{prep}");
    let prepared = prep["preparedTransaction"].as_str().unwrap().to_string();
    let hash = b64_decode(prep["preparedTransactionHash"].as_str().unwrap());
    let end_before = get(&service, "/v2/state/ledger-end").1["offset"].clone();

    let unsigned = json!({
        "preparedTransaction": prepared,
        "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2",
        "deduplicationPeriod": { "Empty": {} },
        "submissionId": "sub-local-unsigned",
        "partySignatures": { "signatures": [] }
    });
    let (st, r) = post(
        &service,
        "/v2/interactive-submission/executeAndWait",
        &unsigned,
    );
    assert_eq!(st, 400, "{r}");
    assert_eq!(r["code"], "FAILED_TO_EXECUTE_TRANSACTION", "{r}");
    assert_eq!(
        r["cause"],
        format!(
            "The participant failed to execute the transaction: The following actAs parties did not provide an external signature: {alice}"
        ),
        "{r}"
    );

    // a signature by a key the party never registered: the party has no signing keys at all
    let stranger = SigningKey::from_bytes(&[7u8; 32]);
    let signed_by_a_stranger = json!({
        "preparedTransaction": prepared,
        "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2",
        "deduplicationPeriod": { "Empty": {} },
        "submissionId": "sub-local-stranger",
        "partySignatures": {
            "signatures": [{
                "party": alice,
                "signatures": [{
                    "format": "SIGNATURE_FORMAT_CONCAT",
                    "signature": b64_encode(&stranger.sign(&hash).to_bytes()),
                    "signedBy": "1220".to_string() + &"ab".repeat(32),
                    "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
                }]
            }]
        }
    });
    let (st, r) = post(
        &service,
        "/v2/interactive-submission/executeAndWait",
        &signed_by_a_stranger,
    );
    assert_eq!(st, 400, "{r}");
    assert_eq!(r["code"], "FAILED_TO_EXECUTE_TRANSACTION", "{r}");
    assert!(
        r["cause"]
            .as_str()
            .unwrap()
            .contains("Could not find party signing keys for alice::"),
        "{r}"
    );

    assert_eq!(
        get(&service, "/v2/state/ledger-end").1["offset"],
        end_before,
        "nothing was committed"
    );
}
