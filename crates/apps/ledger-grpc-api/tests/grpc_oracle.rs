//! S-API-013: the gRPC server's answers against what the Canton 3.7.2 sandbox answered on its gRPC port
//! (`tests/oracle/grpc-api/expected.jsonl`, recorded by `scripts/verify-grpc-api.sh`), without Docker.
use std::{path::PathBuf, sync::Arc};

use ledger_grpc_api::oracle::{compare, parse_requests, replay};
use ledger_json_api::ExecutionService;
use serde_json::Value;

fn dir() -> PathBuf {
    std::env::var("GRPC_API_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/grpc-api")
        })
}

#[test]
fn grpc_responses_agree_with_the_recorded_canton_sandbox() {
    let tsv = std::fs::read_to_string(dir().join("requests.tsv")).expect("requests.tsv");
    let expected: Vec<Value> = std::fs::read_to_string(dir().join("expected.jsonl"))
        .expect("expected.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let got = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(ledger_grpc_api::server::serve_listener(
            Arc::new(ExecutionService::new()),
            listener,
        ));
        let out = replay(&addr.to_string(), &tsv, &Default::default()).await;
        server.abort();
        out
    });
    let specs = parse_requests(&tsv);
    let mut problems = Vec::new();
    let mut agreed = 0;
    for (spec, got) in specs.iter().zip(&got) {
        let Some(want) = expected.iter().find(|e| e["id"] == spec.id.as_str()) else {
            problems.push(format!("{}: not recorded", spec.id));
            continue;
        };
        let diffs = compare(want, got, &spec.exact);
        if diffs.is_empty() {
            agreed += 1;
        } else {
            problems.push(format!("  {} {}: {}", spec.id, spec.path, diffs.join("; ")));
        }
    }
    println!(
        "grpc-api: {agreed} of {} responses agree with the recorded Canton sandbox",
        specs.len()
    );
    assert!(
        problems.is_empty(),
        "MISMATCH against the recorded Canton responses:\n{}",
        problems.join("\n")
    );
}
