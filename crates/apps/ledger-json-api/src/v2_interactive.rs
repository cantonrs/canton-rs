//! Interactive submission v2 (`/v2/parties/external/{generate-topology,allocate}` and
//! `/v2/interactive-submission/{prepare,execute,executeAndWait,executeAndWaitForTransaction}`),
//! matching Canton 3.7.2 V2/V3 deterministic hashing and external signature verification (`S-API-024`, `U-13(ii)`).

use canton_algo::hash::sha256_with_purpose;
use canton_algo::signing::PublicKey;
use canton_proto::com::daml::ledger::api::v2::interactive::HashingSchemeVersion;
use serde_json::json;

use crate::service::{GenericContract, TransactionCommit};
use crate::v2_commands::{canton_error, Ev, Kind};
use crate::HttpResponse;

mod execute;
mod external_party;
mod prepare;
mod values;

pub use execute::execute;
pub(crate) use execute::prepared_act_as;
pub use external_party::{allocate_external_party, generate_topology};
pub use prepare::prepare;

const HASH_PURPOSE_TOPOLOGY_TX_SIG: i32 = 11;
const PROTO_VERSION_TOPOLOGY_V31: i32 = 31;

/// Registered external party state kept on [`crate::v2::V2State`].
#[derive(Clone, Debug)]
pub struct ExternalPartyInfo {
    pub party_id: String,
    pub fingerprint: String,
    pub keys: Vec<PublicKey>,
    pub threshold: u32,
    pub synchronizer_id: String,
}

/// Prepared submission cached in [`crate::v2::V2State`] keyed by `(synchronizer_id, hash_bytes)`.
#[derive(Clone)]
pub struct CachedPrepared {
    pub commits: Vec<TransactionCommit>,
    pub disclosed: Vec<GenericContract>,
    pub read_as: Vec<String>,
    pub required_active_inputs: Vec<String>,
    pub(crate) events: Vec<Ev>,
    pub max_record_time_micros: Option<i64>,
    pub has_disclosed_inputs: bool,
}

fn fail_prepare(cause: impl std::fmt::Display) -> HttpResponse {
    canton_error(
        Kind::RequestCorrelated,
        400,
        "FAILED_TO_PREPARE_TRANSACTION",
        format!("The participant failed to prepare the transaction: {cause}"),
        8,
        3,
        json!([]),
    )
}

fn fail_execute(cause: impl std::fmt::Display) -> HttpResponse {
    canton_error(
        Kind::RequestCorrelated,
        400,
        "FAILED_TO_EXECUTE_TRANSACTION",
        format!("The participant failed to execute the transaction: {cause}"),
        8,
        3,
        json!([]),
    )
}

fn invalid_arg(cause: impl std::fmt::Display) -> HttpResponse {
    canton_error(
        Kind::RequestCorrelated,
        400,
        "INVALID_ARGUMENT",
        format!("The submitted request has invalid arguments: {cause}"),
        8,
        3,
        json!([]),
    )
}

fn fail_max_record_time(record_time: &str, max_record_time: &str) -> HttpResponse {
    canton_error(
        Kind::Ctx {
            submission: true,
            definite: false,
            field: None,
            retry: Some("1 second"),
        },
        409,
        "LOCAL_VERDICT_MAX_RECORD_TIME_EXCEEDED",
        format!(
            "Rejected transaction as record time exceeds the maximum record time: \
             recordTime={record_time}, maxRecordTime={max_record_time}"
        ),
        2,
        10,
        json!([]),
    )
}

fn party_abbrev(party: &str) -> String {
    match party.split_once("::") {
        Some((hint, fp)) if fp.len() > 12 => format!("{hint}::{}...", &fp[..12]),
        _ => party.to_string(),
    }
}

fn logical_synchronizer(sync_id: &str) -> &str {
    // Strip optional physical suffix `::<serial>` when the logical id already contains `::<fp>`.
    if let Some((prefix, _tail)) = sync_id.rsplit_once("::") {
        if prefix.contains("::") {
            return prefix;
        }
    }
    sync_id
}

fn synchronizer_matches(expected: &str, supplied: &str) -> bool {
    logical_synchronizer(expected) == logical_synchronizer(supplied)
}

fn multihash_34(digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.push(0x12);
    out.push(0x20);
    out.extend_from_slice(digest);
    out
}

/// Computes the 34-byte multihash (`0x1220...`) of one `UntypedVersionedMessage`-wrapped topology transaction.
pub fn compute_topology_tx_hash_34(raw_versioned_tx: &[u8]) -> Vec<u8> {
    multihash_34(&sha256_with_purpose(
        HASH_PURPOSE_TOPOLOGY_TX_SIG,
        raw_versioned_tx,
    ))
}

/// Computes Canton's `MultiTransactionSignature.computeCombinedHash` (HashPurpose 55) as a 34-byte multihash.
pub fn compute_multi_hash_34(tx_hashes_34: &[Vec<u8>]) -> Vec<u8> {
    // [CANTON-NOTE: DEFENSIVE] the hasher only refuses input after it finished, which this one does not
    canton_algo::hash::multi_topology_transaction_hash(tx_hashes_34).unwrap_or_default()
}

fn hashing_scheme_name(s: HashingSchemeVersion) -> &'static str {
    match s {
        HashingSchemeVersion::V2 => "HASHING_SCHEME_VERSION_V2",
        HashingSchemeVersion::V3 => "HASHING_SCHEME_VERSION_V3",
        HashingSchemeVersion::V4 => "HASHING_SCHEME_VERSION_V4",
        HashingSchemeVersion::Unspecified => "HASHING_SCHEME_VERSION_UNSPECIFIED",
    }
}

#[cfg(test)]
mod tests {
    use super::execute::commit_from_prepared;
    use super::*;
    use crate::dispatch_request;
    use crate::service::ExecutionService;
    use crate::v2::base64;
    use crate::HttpRequest;
    use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::node::VersionedNode;
    use canton_proto::com::daml::ledger::api::v2::interactive::daml_transaction::Node as DamTxNode;
    use canton_proto::com::daml::ledger::api::v2::interactive::metadata::input_contract;
    use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1;
    use canton_proto::com::daml::ledger::api::v2::interactive::transaction::v1::node::NodeType;
    use canton_proto::com::daml::ledger::api::v2::interactive::DamlTransaction;
    use canton_proto::com::daml::ledger::api::v2::interactive::PreparedTransaction;
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    use lf_eval::fat_contract::decode_strict_base64;
    use prost::Message;
    use serde_json::Value as Json;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn matrix() -> Json {
        let raw = include_str!(
            "../../../../tests/oracle/interactive-prepare/canton-3.7.2-interactive-matrix.json"
        );
        serde_json::from_str(raw).expect("interactive matrix json")
    }

    fn http_post(service: &ExecutionService, path: &str, body: &Json) -> (u16, Json) {
        let req = HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: serde_json::to_vec(body).unwrap(),
        };
        let resp = dispatch_request(service, &req);
        let j = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
        (resp.status, j)
    }

    fn http_get(service: &ExecutionService, path: &str) -> (u16, Json) {
        let req = HttpRequest {
            method: "GET".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let resp = dispatch_request(service, &req);
        let j = serde_json::from_slice(&resp.body).unwrap_or(Json::Null);
        (resp.status, j)
    }

    fn load_oracle_dars(service: &ExecutionService) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        service
            .load_dar(&root.join("tests/oracle/tx-corpus/tx-corpus.dar"))
            .expect("tx-corpus.dar");
        service
            .load_dar(&root.join("tests/oracle/key-diff/key-diff.dar"))
            .expect("key-diff.dar");
    }

    fn setup_oracle_service() -> (ExecutionService, Json) {
        let m = matrix();
        let service = ExecutionService::new();
        service
            .v2_state()
            .set_synchronizer_id_for_test(m["synchronizerId"].as_str().unwrap());
        load_oracle_dars(&service);
        (service, m)
    }

    fn sign_hash(sk: &SigningKey, fingerprint: &str, digest_b64: &str) -> Json {
        let bytes = decode_strict_base64(digest_b64).expect("hash b64");
        let payload = if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            multihash_34(&arr)
        } else {
            bytes
        };
        let sig = sk.sign(&payload);
        json!({
            "format": "SIGNATURE_FORMAT_CONCAT",
            "signature": base64(&sig.to_bytes()),
            "signedBy": fingerprint,
            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
        })
    }

    /// A party's signature over a prepared transaction's hash: the raw 32 bytes, as the official participant verifies it (a signature
    /// over the multihash form, which onboarding uses, is refused: U-56 review R1-F3).
    fn sign_transaction_hash(sk: &SigningKey, fingerprint: &str, digest_b64: &str) -> Json {
        let bytes = decode_strict_base64(digest_b64).expect("hash b64");
        assert_eq!(bytes.len(), 32, "a prepared transaction hash is 32 bytes");
        json!({
            "format": "SIGNATURE_FORMAT_CONCAT",
            "signature": base64(&sk.sign(&bytes).to_bytes()),
            "signedBy": fingerprint,
            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519"
        })
    }

    #[test]
    fn oracle_onboarding_topology_and_replay_execute_and_hash_queries() {
        let (service, m) = setup_oracle_service();
        let onb = &m["externalPartyOnboarding"];

        // 1. Multi-hash of Canton's exact topologyTransactions[0] matches byte-for-byte
        let oracle_tx0 = decode_strict_base64(
            onb["generateResponse"]["topologyTransactions"][0]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let oracle_mh = compute_multi_hash_34(&[compute_topology_tx_hash_34(&oracle_tx0)]);
        assert_eq!(
            base64(&oracle_mh),
            onb["generateResponse"]["multiHash"].as_str().unwrap()
        );

        // 2. generate-topology returns exact partyId & publicKeyFingerprint
        let (st, gen_resp) = http_post(
            &service,
            "/v2/parties/external/generate-topology",
            &onb["generateRequest"],
        );
        assert_eq!(st, 200, "generate-topology: {gen_resp}");
        assert_eq!(gen_resp["partyId"], onb["generateResponse"]["partyId"]);
        assert_eq!(
            gen_resp["publicKeyFingerprint"],
            onb["generateResponse"]["publicKeyFingerprint"]
        );

        // 3. allocate-external-party verifies Canton's real Ed25519 multiHashSignature
        let (st, alloc_resp) = http_post(
            &service,
            "/v2/parties/external/allocate",
            &onb["allocateRequest"],
        );
        assert_eq!(st, 200, "allocate: {alloc_resp}");
        assert_eq!(alloc_resp["partyId"], onb["allocateResponse"]["partyId"]);

        let (st, parties) = http_get(&service, "/v2/parties");
        assert_eq!(st, 200);
        let party_id = alloc_resp["partyId"].as_str().unwrap();
        assert!(parties["partyDetails"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["party"] == party_id && p["isLocal"] == true));

        // 4. Replay unmodified Canton-prepared Note Create & ExecuteAndWaitForTransaction
        let c1 = &m["cases"]["v2CreateNoteAndExecuteTx"];
        let (st, exec_tx_resp) = http_post(
            &service,
            "/v2/interactive-submission/executeAndWaitForTransaction",
            &c1["executeRequest"],
        );
        assert_eq!(st, 200, "replay create execute: {exec_tx_resp}");
        let oracle_tx = &c1["executeResponse"]["transaction"];
        let got_tx = &exec_tx_resp["transaction"];
        assert_eq!(
            got_tx["externalTransactionHash"],
            oracle_tx["externalTransactionHash"]
        );
        assert_eq!(got_tx["transactionHash"], oracle_tx["transactionHash"]);
        assert_eq!(got_tx["commandId"], oracle_tx["commandId"]);
        let got_cid = got_tx["events"][0]["CreatedEvent"]["contractId"]
            .as_str()
            .unwrap();
        let oracle_cid = oracle_tx["events"][0]["CreatedEvent"]["contractId"]
            .as_str()
            .unwrap();
        assert_eq!(got_cid.len(), 66);
        // Canton suffixes the 66-hex discriminator with `ca121220...` at synchronizer execution time
        assert!(
            oracle_cid.starts_with(got_cid),
            "discriminator mismatch: got={got_cid} oracle={oracle_cid}"
        );
        assert_eq!(
            got_tx["events"][0]["CreatedEvent"]["createArgument"],
            oracle_tx["events"][0]["CreatedEvent"]["createArgument"]
        );

        // 5. Replay unmodified Canton-prepared Exercise Bump & ExecuteAndWait.
        // Seed the Canton-suffixed input contract (`oracle_cid`) from c2.metadata.input_contracts[0]
        // so the unmodified Canton-signed PreparedTransaction can consume `oracle_cid`.
        let c2 = &m["cases"]["v2ExerciseBumpAndExecuteWait"];
        let c2_pt = PreparedTransaction::decode(
            decode_strict_base64(
                c2["prepareResponse"]["preparedTransaction"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        let seed_create = match &c2_pt.metadata.as_ref().unwrap().input_contracts[0].contract {
            Some(input_contract::Contract::V1(c)) => c.clone(),
            _ => panic!("expected V1 input contract"),
        };
        let seed_pt = PreparedTransaction {
            transaction: Some(DamlTransaction {
                version: "2.1".into(),
                roots: vec!["0".into()],
                nodes: vec![DamTxNode {
                    node_id: "0".into(),
                    versioned_node: Some(VersionedNode::V1(v1::Node {
                        node_type: Some(NodeType::Create(seed_create)),
                    })),
                }],
                node_seeds: Vec::new(),
            }),
            metadata: Some({
                let mut md = c2_pt.metadata.unwrap();
                md.input_contracts.clear();
                md
            }),
        };
        let seed_plan = commit_from_prepared(&service, &seed_pt).expect("seed suffixed note");
        service
            .commit_prepared_transaction(seed_plan.commits, &[], Vec::new(), Vec::new())
            .expect("commit suffixed note");

        let (st, wait_resp) = http_post(
            &service,
            "/v2/interactive-submission/executeAndWait",
            &c2["executeRequest"],
        );
        assert_eq!(st, 200, "replay bump executeAndWait: {wait_resp}");
        assert!(wait_resp["updateId"].as_str().unwrap().starts_with("1220"));
        assert!(wait_resp["completionOffset"].as_u64().unwrap() >= 2);

        // 6. Query completion-by-hash & update-by-hash (positive + missing hash 400)
        let note_hash_b64 = c1["prepareResponse"]["preparedTransactionHash"]
            .as_str()
            .unwrap();
        let (st, comp_resp) = http_post(
            &service,
            "/v2/commands/completion-by-hash",
            &json!({ "transactionHash": note_hash_b64, "parties": [party_id] }),
        );
        assert_eq!(st, 200, "completion-by-hash: {comp_resp}");
        assert_eq!(
            comp_resp["acceptedCompletion"]["transactionHash"],
            note_hash_b64
        );
        assert_eq!(comp_resp["lastRejectedCompletions"], json!([]));

        let (st, upd_resp) = http_post(
            &service,
            "/v2/updates/update-by-hash",
            &json!({
                "transactionHash": note_hash_b64,
                "updateFormat": {
                    "includeTransactions": {
                        "eventFormat": { "filtersByParty": { (party_id): {} } },
                        "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                    }
                }
            }),
        );
        assert_eq!(st, 200, "update-by-hash: {upd_resp}");
        assert_eq!(
            upd_resp["update"]["Transaction"]["value"]["externalTransactionHash"],
            oracle_tx["externalTransactionHash"]
        );

        let (st, miss_resp) = http_post(&service, "/v2/updates/update-by-hash", &json!({}));
        assert_eq!(st, 400);
        assert_eq!(miss_resp["code"], "MISSING_FIELD");
    }

    #[test]
    fn negative_oracle_controls_rejected_with_canton_codes() {
        let (service, m) = setup_oracle_service();
        let (st, _) = http_post(
            &service,
            "/v2/parties/external/allocate",
            &m["externalPartyOnboarding"]["allocateRequest"],
        );
        assert_eq!(st, 200);
        let party_id = m["externalPartyOnboarding"]["allocateResponse"]["partyId"]
            .as_str()
            .unwrap();

        // Multi-root execution rejected
        let rb_exec = json!({
            "userId": "participant_admin",
            "preparedTransaction": m["cases"]["v3RollbackNonConsuming"]["prepareResponse"]["preparedTransaction"],
            "partySignatures": { "signatures": [] },
            "deduplicationPeriod": { "Empty": {} },
            "submissionId": "neg-multiroot",
            "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
        });
        let (st, resp) = http_post(&service, "/v2/interactive-submission/execute", &rb_exec);
        assert_eq!(st, 400, "multi-root: {resp}");
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");
        assert!(resp["cause"]
            .as_str()
            .unwrap()
            .contains("Transaction with multiple root nodes are not supported"));

        // Expired maxRecordTime rejected with 409 LOCAL_VERDICT_MAX_RECORD_TIME_EXCEEDED
        let mut expired_req = m["cases"]["v2CreateNoteAndExecuteTx"]["executeRequest"].clone();
        // Prepare local expired tx or execute using expired preparedTransaction with matching key
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 7;
        let sk = SigningKey::from_bytes(&sk_bytes);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let sync = m["synchronizerId"].as_str().unwrap();
        let (st, gen_r) = http_post(
            &service,
            "/v2/parties/external/generate-topology",
            &json!({
                "synchronizer": sync,
                "partyHint": "exp_alice",
                "publicKey": {
                    "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                    "keyData": base64(spki.as_bytes()),
                    "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
                }
            }),
        );
        assert_eq!(st, 200);
        let exp_party = gen_r["partyId"].as_str().unwrap();
        let exp_fp = gen_r["publicKeyFingerprint"].as_str().unwrap();
        let (st, _) = http_post(
            &service,
            "/v2/parties/external/allocate",
            &json!({
                "synchronizer": sync,
                "onboardingTransactions": [{
                    "transaction": gen_r["topologyTransactions"][0],
                    "signatures": []
                }],
                "multiHashSignatures": [sign_hash(&sk, exp_fp, gen_r["multiHash"].as_str().unwrap())]
            }),
        );
        assert_eq!(st, 200);
        let (st, prep_exp) = http_post(
            &service,
            "/v2/interactive-submission/prepare",
            &json!({
                "userId": "participant_admin",
                "commandId": "exp-cmd",
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#tx-corpus:TxNote:Note",
                        "createArguments": {
                            "author": exp_party,
                            "watchers": [],
                            "text": "expired",
                            "n": "1"
                        }
                    }
                }],
                "actAs": [exp_party],
                "synchronizerId": sync,
                "packageIdSelectionPreference": [],
                "maxRecordTime": "2020-01-01T00:00:00Z",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        );
        assert_eq!(st, 200);
        let (st, resp) = http_post(
            &service,
            "/v2/interactive-submission/execute",
            &json!({
                "userId": "participant_admin",
                "preparedTransaction": prep_exp["preparedTransaction"],
                "partySignatures": {
                    "signatures": [{
                        "party": exp_party,
                        "signatures": [sign_transaction_hash(&sk, exp_fp, prep_exp["preparedTransactionHash"].as_str().unwrap())]
                    }]
                },
                "deduplicationPeriod": { "Empty": {} },
                "submissionId": "sub-exp",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        );
        assert_eq!(st, 409, "expired maxRecordTime: {resp}");
        assert_eq!(resp["code"], "LOCAL_VERDICT_MAX_RECORD_TIME_EXCEEDED");

        // Missing party signature rejected
        expired_req["partySignatures"] = json!({ "signatures": [] });
        let (st, resp) = http_post(&service, "/v2/interactive-submission/execute", &expired_req);
        assert_eq!(st, 400);
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");
        assert!(resp["cause"].as_str().unwrap().contains(&format!(
            "did not provide an external signature: {party_id}"
        )));

        // Bad signature rejected
        let mut bad_sig_req = m["cases"]["v2CreateNoteAndExecuteTx"]["executeRequest"].clone();
        bad_sig_req["partySignatures"]["signatures"][0]["signatures"][0]["signature"] =
            json!(base64(&[0u8; 64]));
        let (st, resp) = http_post(&service, "/v2/interactive-submission/execute", &bad_sig_req);
        assert_eq!(st, 400);
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");
        assert!(resp["cause"]
            .as_str()
            .unwrap()
            .contains("Received 0 valid signatures from distinct keys (1 invalid)"));

        // Unknown signedBy rejected
        let mut unk_req = m["cases"]["v2CreateNoteAndExecuteTx"]["executeRequest"].clone();
        unk_req["partySignatures"]["signatures"][0]["signatures"][0]["signedBy"] =
            json!("12200000000000000000000000000000000000000000000000000000000000000000");
        let (st, resp) = http_post(&service, "/v2/interactive-submission/execute", &unk_req);
        assert_eq!(st, 400);
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");

        // Wrong hashingSchemeVersion rejected
        let mut wrong_scheme = m["cases"]["v2CreateNoteAndExecuteTx"]["executeRequest"].clone();
        wrong_scheme["hashingSchemeVersion"] = json!("HASHING_SCHEME_VERSION_V3");
        let (st, resp) = http_post(
            &service,
            "/v2/interactive-submission/execute",
            &wrong_scheme,
        );
        assert_eq!(st, 400);
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");

        // Tampered preparedTransaction rejected
        let mut tampered_tx = PreparedTransaction::decode(
            decode_strict_base64(
                m["cases"]["v2CreateNoteAndExecuteTx"]["prepareResponse"]["preparedTransaction"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
        if let Some(meta) = tampered_tx.metadata.as_mut() {
            meta.mediator_group = 99;
        }
        let mut tamp_req = m["cases"]["v2CreateNoteAndExecuteTx"]["executeRequest"].clone();
        tamp_req["preparedTransaction"] = json!(base64(&tampered_tx.encode_to_vec()));
        let (st, resp) = http_post(&service, "/v2/interactive-submission/execute", &tamp_req);
        assert_eq!(st, 400);
        assert_eq!(resp["code"], "FAILED_TO_EXECUTE_TRANSACTION");
    }

    #[test]
    fn local_prepare_dry_run_and_v2_v3_keyed_end_to_end() {
        let (service, m) = setup_oracle_service();
        let sync = m["synchronizerId"].as_str().unwrap();

        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = 42;
        let sk = SigningKey::from_bytes(&sk_bytes);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let (st, gen_r) = http_post(
            &service,
            "/v2/parties/external/generate-topology",
            &json!({
                "synchronizer": sync,
                "partyHint": "loc_alice",
                "publicKey": {
                    "format": "CRYPTO_KEY_FORMAT_DER_X509_SUBJECT_PUBLIC_KEY_INFO",
                    "keyData": base64(spki.as_bytes()),
                    "keySpec": "SIGNING_KEY_SPEC_EC_CURVE25519"
                }
            }),
        );
        assert_eq!(st, 200);
        let party = gen_r["partyId"].as_str().unwrap();
        let fp = gen_r["publicKeyFingerprint"].as_str().unwrap();
        let (st, _) = http_post(
            &service,
            "/v2/parties/external/allocate",
            &json!({
                "synchronizer": sync,
                "onboardingTransactions": [{
                    "transaction": gen_r["topologyTransactions"][0],
                    "signatures": []
                }],
                "multiHashSignatures": [sign_hash(&sk, fp, gen_r["multiHash"].as_str().unwrap())]
            }),
        );
        assert_eq!(st, 200);

        // V2 rejects keyed template
        let (st, v2_key_err) = http_post(
            &service,
            "/v2/interactive-submission/prepare",
            &json!({
                "userId": "participant_admin",
                "commandId": "v2-keyed",
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#key-diff:Keys:Item",
                        "createArguments": { "owner": party, "label": "k1", "note": "n1" }
                    }
                }],
                "actAs": [party],
                "synchronizerId": sync,
                "packageIdSelectionPreference": [],
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V2"
            }),
        );
        assert_eq!(st, 400, "v2 keyed should fail: {v2_key_err}");
        assert_eq!(v2_key_err["code"], "FAILED_TO_PREPARE_TRANSACTION");
        assert!(
            v2_key_err["cause"]
                .as_str()
                .unwrap()
                .contains("Use hashing scheme V3 or higher")
                || v2_key_err["cause"]
                    .as_str()
                    .unwrap()
                    .contains("Please use hashing scheme V3 or higher.")
        );

        // V3 succeeds for keyed template with ZERO side effects on ledger
        let end_before = service.v2_state().ledger_end.load(Ordering::SeqCst);
        let (st, prep) = http_post(
            &service,
            "/v2/interactive-submission/prepare",
            &json!({
                "userId": "participant_admin",
                "commandId": "v3-keyed-create",
                "commands": [{
                    "CreateCommand": {
                        "templateId": "#key-diff:Keys:Item",
                        "createArguments": { "owner": party, "label": "k1", "note": "n1" }
                    }
                }],
                "actAs": [party],
                "synchronizerId": sync,
                "packageIdSelectionPreference": [],
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        );
        assert_eq!(st, 200, "v3 prepare: {prep}");
        assert_eq!(
            service.v2_state().ledger_end.load(Ordering::SeqCst),
            end_before
        );
        assert!(service.v2_active_contracts().is_empty());

        let (st, exec_r) = http_post(
            &service,
            "/v2/interactive-submission/executeAndWaitForTransaction",
            &json!({
                "userId": "participant_admin",
                "preparedTransaction": prep["preparedTransaction"],
                "partySignatures": {
                    "signatures": [{
                        "party": party,
                        "signatures": [sign_transaction_hash(&sk, fp, prep["preparedTransactionHash"].as_str().unwrap())]
                    }]
                },
                "deduplicationPeriod": { "Empty": {} },
                "submissionId": "sub-v3-keyed-1",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        );
        assert_eq!(st, 200, "v3 execute: {exec_r}");
        assert_eq!(service.v2_active_contracts().len(), 1);

        // Duplicate command rejected with 409 DUPLICATE_COMMAND
        let (st, dup_r) = http_post(
            &service,
            "/v2/interactive-submission/execute",
            &json!({
                "userId": "participant_admin",
                "preparedTransaction": prep["preparedTransaction"],
                "partySignatures": {
                    "signatures": [{
                        "party": party,
                        "signatures": [sign_transaction_hash(&sk, fp, prep["preparedTransactionHash"].as_str().unwrap())]
                    }]
                },
                "deduplicationPeriod": { "Empty": {} },
                "submissionId": "sub-v3-keyed-dup",
                "hashingSchemeVersion": "HASHING_SCHEME_VERSION_V3"
            }),
        );
        assert_eq!(st, 409, "dup: {dup_r}");
        assert_eq!(dup_r["code"], "DUPLICATE_COMMAND");
    }
}
