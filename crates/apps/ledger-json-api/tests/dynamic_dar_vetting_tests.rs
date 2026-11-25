//! S-SPL-030: dynamic multi-DAR upload (`POST /v2/packages`) and signed `VettedPackages`
//! topology broadcast across two Rust participants on a Rust synchronizer. No JVM.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
#![cfg(feature = "protocol")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use canton_participant::node::Node;
use ledger_json_api::models::json_api::*;
use ledger_json_api::models::ledger_api::*;
use ledger_json_api::protocol::NodeCommitter;
use ledger_json_api::service::ExecutionService;
use ledger_json_api::{dispatch_request, HttpRequest, HttpResponse};
use serde_json::json;

fn sample_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/target/sample-contract.dar")
}

fn tree_dar() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/fixtures/tree/target/tree-view.dar")
}

fn synchronizer() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = canton_sequencer_server::new_synchronizer_with_groups("vetsync", "vs1", 1);
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(canton_sequencer_server::serve(address, config))
            .unwrap();
    });
    for _ in 0..50 {
        if std::net::TcpStream::connect(address).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    format!("http://{address}")
}

fn participant(url: &str, name: &str) -> Arc<ExecutionService> {
    let node = Node::connect(url, name, &sample_dar()).expect("join synchronizer");
    let service = Arc::new(ExecutionService::new());
    service.load_dar(&sample_dar()).expect("load boot DAR");
    let committer = Arc::new(NodeCommitter::new(
        node,
        "sample-contract",
        Duration::from_secs(30),
    ));
    committer.show_remote_transactions_in(Arc::clone(&service));
    service.set_committer(committer);
    service
}

fn post(service: &ExecutionService, path: &str, body: Vec<u8>) -> HttpResponse {
    dispatch_request(
        service,
        &HttpRequest {
            method: "POST".into(),
            path: path.into(),
            query_params: HashMap::new(),
            headers: HashMap::new(),
            body,
        },
    )
}

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ok() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn corrupt_dar_upload_returns_400_negative_control() {
    let url = synchronizer();
    let alpha = participant(&url, "alpha");
    let resp = post(&alpha, "/v2/packages", b"not-a-valid-dar".to_vec());
    assert_eq!(resp.status, 400, "{}", String::from_utf8_lossy(&resp.body));
    let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(body["code"], json!("INVALID_DAR"));
}

#[test]
fn dynamic_dar_upload_vets_topology_and_enables_cross_participant_execution() {
    let url = synchronizer();
    let alpha = participant(&url, "alpha");
    let beta = participant(&url, "beta");
    let alice = alpha.protocol_party("alice").unwrap().unwrap();
    let bob = beta.protocol_party("bob").unwrap().unwrap();

    let tree_bytes = std::fs::read(tree_dar()).unwrap();
    let tree_archive = lf_archive::parse_dar_file(tree_dar()).unwrap();
    let tree_pkg_id = tree_archive.main_package_id;

    // Upload tree-view.dar to alpha only via HTTP POST /v2/packages
    let upload_alpha = post(&alpha, "/v2/packages", tree_bytes.clone());
    assert_eq!(
        upload_alpha.status,
        200,
        "alpha DAR upload failed: {}",
        String::from_utf8_lossy(&upload_alpha.body)
    );

    // Alpha's package vetting list includes tree_pkg_id with bumped serial
    let vetting = post(&alpha, "/v2/package-vetting/list", b"{}".to_vec());
    assert_eq!(vetting.status, 200);
    let vetting_json: serde_json::Value = serde_json::from_slice(&vetting.body).unwrap();
    let vetted_ids: Vec<&str> = vetting_json["vettedPackages"][0]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["packageId"].as_str())
        .collect();
    assert!(
        vetted_ids.contains(&tree_pkg_id.as_str()),
        "tree-view package missing from vetted list: {vetting_json}"
    );
    assert!(
        vetting_json["vettedPackages"][0]["topologySerial"]
            .as_u64()
            .unwrap()
            >= 2
    );

    // Creating a contract shared with beta fails before beta vets the package
    let err = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&tree_pkg_id, "Tree", "Held"),
                payload: json!({ "r": alice, "a": bob }),
                meta: None,
            },
        )
        .expect_err("unvetted peer beta must cause refusal");
    let msg = err.to_string();
    assert!(
        msg.contains("PACKAGE_NOT_VETTED_BY_RECIPIENTS"),
        "expected PACKAGE_NOT_VETTED_BY_RECIPIENTS, got: {msg}"
    );

    // Now upload tree-view.dar to beta via HTTP POST /v2/packages
    let upload_beta = post(&beta, "/v2/packages", tree_bytes);
    assert_eq!(
        upload_beta.status,
        200,
        "beta DAR upload failed: {}",
        String::from_utf8_lossy(&upload_beta.body)
    );

    // Cross-participant create of Tree:Held now succeeds and shows up on beta
    std::thread::sleep(Duration::from_millis(50));
    let held_id = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::new(&tree_pkg_id, "Tree", "Held"),
                payload: json!({ "r": alice, "a": bob }),
                meta: None,
            },
        )
        .expect("create succeeds once both peers vetted tree-view.dar")
        .result
        .contract_id;

    eventually("beta never saw Tree:Held", || {
        beta.get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .iter()
            .any(|c| c.contract_id == held_id)
    });

    // Bob exercises consuming choice Touch on Tree:Held, creating Tree:Receipt on both peers
    beta.json_exercise(
        std::slice::from_ref(&bob),
        ExerciseRequest {
            template_id: TemplateId::new(&tree_pkg_id, "Tree", "Held"),
            contract_id: held_id.clone(),
            choice: "Touch".into(),
            argument: json!({}),
            meta: None,
        },
    )
    .expect("bob exercises Tree:Held.Touch");

    eventually("alpha never saw Tree:Receipt or archival of Held", || {
        let active = alpha.get_active_contracts(&[]).unwrap().active_contracts;
        !active.iter().any(|c| c.contract_id == held_id)
            && active
                .iter()
                .any(|c| c.template_id.entity_name == "Receipt")
    });
    eventually("beta never saw Tree:Receipt", || {
        beta.get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .iter()
            .any(|c| c.template_id.entity_name == "Receipt")
    });

    // Boot DAR templates (sample-contract AssetHolding) continue working seamlessly
    let holding_id = alpha
        .json_create(
            std::slice::from_ref(&alice),
            CreateRequest {
                template_id: TemplateId::asset_holding(),
                payload: json!({
                    "bank": alice,
                    "owner": alice,
                    "auditor": bob,
                    "assetSymbol": "USD",
                    "amount": "15.0"
                }),
                meta: None,
            },
        )
        .expect("boot DAR AssetHolding create still succeeds")
        .result
        .contract_id;

    eventually("beta never saw boot DAR AssetHolding", || {
        beta.get_active_contracts(&[])
            .unwrap()
            .active_contracts
            .iter()
            .any(|c| c.contract_id == holding_id)
    });
}
