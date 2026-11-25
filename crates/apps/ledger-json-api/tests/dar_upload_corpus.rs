//! S-LF-014: every DAR of `tests/oracle/dar-input` uploaded to the Rust server must get the answer the Canton 3.7.2 upload
//! endpoint gave (`expected.jsonl`): the same HTTP status and the same error code, and for an accepted DAR a 200.
mod common;

use std::path::Path;

use common::call;
use ledger_json_api::ExecutionService;

#[test]
fn the_upload_endpoint_answers_like_the_node_for_every_dar_input_case() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/dar-input");
    let recorded: Vec<serde_json::Value> = std::fs::read_to_string(root.join("expected.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        recorded.len() >= 50,
        "the recording shrank: {}",
        recorded.len()
    );
    let mut differing = Vec::new();
    for d in &recorded {
        let id = d["id"].as_str().unwrap();
        let Ok(bytes) = std::fs::read(root.join("dars").join(format!("{id}.dar"))) else {
            continue;
        };
        let svc = ExecutionService::new();
        let (status, body) = call(&svc, "POST", "/v2/dars", bytes);
        let want_status = d["status"].as_u64().unwrap() as u16;
        let want_code = d["code"].as_str().unwrap_or("");
        let got_code = body["code"].as_str().unwrap_or("");
        if status != want_status || got_code != want_code {
            differing.push(format!(
                "{id}: node {want_status} {want_code:?}, rust {status} {got_code:?}"
            ));
        }
    }
    // Four DARs the node accepts are refused here on purpose: the loader's defenses (path traversal in an entry name, an
    // entry above the size ceiling) are stricter than the node's. Nothing else may differ, and these must still differ (so the
    // list cannot silently go stale).
    const STRICTER: [&str; 4] = [
        "a01-big-entry",
        "a02-absolute",
        "a02-dotdot-extra",
        "a02-dotdot-inner",
    ];
    let ids: Vec<&str> = differing
        .iter()
        .map(|d| d.split(':').next().unwrap())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        STRICTER,
        "the upload endpoint differs from the node on other cases:\n  {}",
        differing.join("\n  ")
    );
    for d in &differing {
        assert!(d.contains("node 200") && d.contains("rust 400"), "{d}");
    }
}
