//! `execute` checks an external party's signatures against the signing keys the synchronizer's topology has for it
//! (`InteractiveSubmission.verifySignatures`, Canton 3.7.2), not only against the keys this server recorded when it allocated the party.
#![allow(clippy::unwrap_used, reason = "integration test")]
mod common;

use std::sync::{Arc, Mutex};

use canton_proto::com::digitalasset::canton::crypto::v30::SigningPublicKey;
use common::{call, dar_bytes, post};
use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
use ledger_json_api::service::{ApiError, ExecutionService, ProtocolCommitter, TransactionCommit};
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
            out.push(if i <= chunk.len() {
                B64[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
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

fn spki(sk: &SigningKey) -> Vec<u8> {
    sk.verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// A synchronizer whose topology holds the party's keys as `keys` says; it accepts every transaction.
#[derive(Default)]
struct Topology {
    keys: Mutex<Option<(String, Vec<SigningPublicKey>)>>,
}

impl ProtocolCommitter for Topology {
    fn commit(&self, _commit: &TransactionCommit) -> Result<(), ApiError> {
        Ok(())
    }

    fn party_signing_keys(&self, party: &str) -> Option<(u32, Vec<SigningPublicKey>)> {
        let keys = self.keys.lock().unwrap();
        keys.as_ref()
            .filter(|(p, _)| p == party)
            .map(|(_, k)| (1, k.clone()))
    }
}

struct Ledger {
    svc: ExecutionService,
    sync: String,
    party: String,
}

/// An external party allocated with `allocated`'s key, then `rotated`'s key in force in the topology; with the fingerprints of both.
fn ledger(
    allocated: &SigningKey,
    rotated: &SigningKey,
    topology: &Arc<Topology>,
) -> (Ledger, String, String) {
    let svc = ExecutionService::new();
    assert_eq!(call(&svc, "POST", "/v2/dars", dar_bytes()).0, 200);
    let (_, sync) = call(&svc, "GET", "/v2/state/connected-synchronizers", vec![]);
    let sync = sync["connectedSynchronizers"][0]["synchronizerId"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, topo) = post(
        &svc,
        "/v2/parties/external/generate-topology",
        json!({"synchronizer": &sync, "partyHint": "ext", "publicKey": {
            "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
            "keyData": base64(&spki(allocated)), "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"}}),
    );
    assert_eq!(s, 200, "{topo}");
    let party = topo["partyId"].as_str().unwrap().to_string();
    let fp = topo["publicKeyFingerprint"].as_str().unwrap().to_string();
    let (s, b) = post(
        &svc,
        "/v2/parties/external/allocate",
        json!({"synchronizer": &sync,
            "onboardingTransactions": [{"transaction": topo["topologyTransactions"][0], "signatures": []}],
            "multiHashSignatures": [sign(allocated, &fp, topo["multiHash"].as_str().unwrap())]}),
    );
    assert_eq!(s, 200, "{b}");
    // the fingerprint of the rotated key, as generate-topology computes one
    let (_, other) = post(
        &svc,
        "/v2/parties/external/generate-topology",
        json!({"synchronizer": &sync, "partyHint": "probe", "publicKey": {
            "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
            "keyData": base64(&spki(rotated)), "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"}}),
    );
    let rotated_fp = other["publicKeyFingerprint"].as_str().unwrap().to_string();
    *topology.keys.lock().unwrap() = Some((
        party.clone(),
        vec![SigningPublicKey {
            format: 4,
            public_key: spki(rotated),
            usage: vec![4],
            key_spec: 1,
            ..Default::default()
        }],
    ));
    svc.set_committer(Arc::clone(topology) as Arc<dyn ProtocolCommitter>);
    (Ledger { svc, sync, party }, fp, rotated_fp)
}

fn execute(l: &Ledger, command_id: &str, sk: &SigningKey, fp: &str) -> (u16, Value) {
    let (s, prepared) = post(
        &l.svc,
        "/v2/interactive-submission/prepare",
        json!({"userId": "participant_admin", "commandId": command_id, "actAs": [&l.party], "synchronizerId": &l.sync,
            "packageIdSelectionPreference": [],
            "commands": [{"CreateCommand": {"templateId": "#sample-contract:AssetHolding:AssetHolding",
                "createArguments": {"bank": &l.party, "owner": &l.party, "auditor": &l.party, "assetSymbol": "USD", "amount": "1.0"}}}]}),
    );
    assert_eq!(s, 200, "{prepared}");
    post(
        &l.svc,
        "/v2/interactive-submission/executeAndWait",
        json!({"userId": "participant_admin", "submissionId": command_id,
            "preparedTransaction": prepared["preparedTransaction"],
            "partySignatures": {"signatures": [{"party": &l.party,
                "signatures": [sign_transaction_hash(sk, fp, prepared["preparedTransactionHash"].as_str().unwrap())]}]},
            "deduplicationPeriod": {"Empty": {}},
            "hashingSchemeVersion": prepared["hashingSchemeVersion"]}),
    )
}

#[test]
fn the_keys_in_the_topology_decide_and_the_key_recorded_at_allocation_no_longer_does() {
    let (allocated, rotated) = (
        SigningKey::from_bytes(&[3u8; 32]),
        SigningKey::from_bytes(&[9u8; 32]),
    );
    let topology = Arc::new(Topology::default());
    let (l, allocated_fp, rotated_fp) = ledger(&allocated, &rotated, &topology);
    let (s, b) = execute(&l, "by-rotated-key", &rotated, &rotated_fp);
    assert_eq!(s, 200, "signed with the key the topology names: {b}");
    let (s, b) = execute(&l, "by-allocated-key", &allocated, &allocated_fp);
    assert_eq!(
        s, 400,
        "signed with the key the topology no longer names: {b}"
    );
}
