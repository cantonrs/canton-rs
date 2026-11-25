//! An interactive submission (`prepare`, then `execute` with the external party's signature) is in the request log, so the
//! transaction it committed is there again after a restart.
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;

use common::{call, dar_bytes, post};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use ledger_json_api::store::FileLog;
use ledger_json_api::ExecutionService;
use serde_json::{json, Value};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
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

fn unbase64(text: &str) -> Vec<u8> {
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

/// A signature over a prepared transaction's hash: the raw 32 bytes, as the official participant verifies it (the multihash form is for
/// onboarding only: U-56 review R1-F3).
fn sign_transaction_hash(sk: &SigningKey, fingerprint: &str, digest_b64: &str) -> Value {
    let digest = unbase64(digest_b64);
    assert_eq!(digest.len(), 32, "a prepared transaction hash is 32 bytes");
    json!({
        "format": "SIGNATURE_FORMAT_CONCAT",
        "signature": base64(&sk.sign(&digest).to_bytes()),
        "signedBy": fingerprint,
        "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    })
}

/// A signature over the multihash of `digest_b64` (`0x12 0x20` and the SHA-256 digest; a multihash is signed as it is).
fn sign(sk: &SigningKey, fingerprint: &str, digest_b64: &str) -> Value {
    let digest = unbase64(digest_b64);
    let mut payload = Vec::new();
    if digest.len() == 32 {
        payload.extend([0x12, 0x20]);
    }
    payload.extend(digest);
    json!({
        "format": "SIGNATURE_FORMAT_CONCAT",
        "signature": base64(&sk.sign(&payload).to_bytes()),
        "signedBy": fingerprint,
        "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
    })
}

fn open(path: &std::path::Path) -> ExecutionService {
    let svc = ExecutionService::new();
    svc.attach_store(Box::new(FileLog::open(path).unwrap()))
        .unwrap();
    svc
}

fn holdings(svc: &ExecutionService, party: &str) -> usize {
    let (_, end) = call(svc, "GET", "/v2/state/ledger-end", vec![]);
    let (s, acs) = post(
        svc,
        "/v2/state/active-contracts",
        json!({"eventFormat": {"filtersByParty": {party: {}}}, "activeAtOffset": end["offset"]}),
    );
    assert_eq!(s, 200, "{acs}");
    acs.as_array().unwrap().len()
}

#[test]
fn an_executed_interactive_submission_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.log");
    let svc = open(&path);
    assert_eq!(call(&svc, "POST", "/v2/dars", dar_bytes()).0, 200);
    let (_, sync) = call(&svc, "GET", "/v2/state/connected-synchronizers", vec![]);
    let sync = sync["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let spki = sk.verifying_key().to_public_key_der().unwrap();
    let (s, topology) = post(
        &svc,
        "/v2/parties/external/generate-topology",
        json!({"synchronizer": &sync, "partyHint": "ext", "publicKey": {
            "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
            "keyData": base64(spki.as_bytes()), "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"}}),
    );
    assert_eq!(s, 200, "{topology}");
    let party = topology["partyId"].as_str().unwrap().to_string();
    let fingerprint = topology["publicKeyFingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, b) = post(
        &svc,
        "/v2/parties/external/allocate",
        json!({"synchronizer": &sync,
            "onboardingTransactions": [{"transaction": topology["topologyTransactions"][0], "signatures": []}],
            "multiHashSignatures": [sign(&sk, &fingerprint, topology["multiHash"].as_str().unwrap())]}),
    );
    assert_eq!(s, 200, "{b}");
    let (s, prepared) = post(
        &svc,
        "/v2/interactive-submission/prepare",
        json!({"userId": "participant_admin", "commandId": "ext-create", "actAs": [&party], "synchronizerId": &sync,
            "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": &party, "owner": &party, "auditor": &party, "assetSymbol": "USD", "amount": "1.0"}}}]}),
    );
    assert_eq!(s, 200, "{prepared}");
    let (s, b) = post(
        &svc,
        "/v2/interactive-submission/executeAndWait",
        json!({"userId": "participant_admin", "submissionId": "ext-1",
            "preparedTransaction": prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": &party,
                "signatures": [sign_transaction_hash(&sk, &fingerprint, prepared["preparedTransactionHash"].as_str().unwrap())]}]},
            "deduplicationPeriod": {"Empty": {}},
            "hashingSchemeVersion": prepared["hashingSchemeVersion"]}),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(holdings(&svc, &party), 1);
    drop(svc);
    let restarted = open(&path);
    assert_eq!(
        holdings(&restarted, &party),
        1,
        "the executed transaction after a restart"
    );
}
