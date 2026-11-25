//! S-API-001: the JSON API v2 responses of this crate against the ones recorded from a real Canton 3.7.2 sandbox.
//!
//! Docker-free. `tests/oracle/json-api/expected.jsonl` holds what the Canton sandbox answered to `requests.tsv` (regenerated
//! by `scripts/verify-json-api.sh --update`). The same requests are replayed here against the Rust server and every response
//! must agree: equal HTTP status, and either equal text or the same JSON *shape* (object keys and value types, recursively; an
//! array is compared through its first element and an empty array matches any array) plus equal values at the JSON pointers
//! of the request's `exact` column. Identifiers that differ between runs (party hashes, trace ids, offsets) are covered by
//! the shape rule. The same rule is implemented in `scripts/json_api_oracle.py`, which checks the JVM against the recording.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ledger_json_api::{start_test_server, ExecutionService};
use serde_json::Value;

fn dir() -> PathBuf {
    // JSON_API_DIR lets the selftest of scripts/verify-json-api.sh point the test at a tampered recording
    std::env::var_os("JSON_API_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/json-api")
        })
}

struct Request {
    id: String,
    method: String,
    path: String,
    body: Option<String>,
    exact: Vec<String>,
    bind: Option<String>,
}

fn requests(dir: &Path) -> Vec<Request> {
    std::fs::read_to_string(dir.join("requests.tsv"))
        .expect("requests.tsv")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            Request {
                id: c[0].to_string(),
                method: c[1].to_string(),
                path: c[2].to_string(),
                body: (c[3] != "-").then(|| c[3].to_string()),
                exact: if c[4] == "-" {
                    vec![]
                } else {
                    c[4].split(',').map(String::from).collect()
                },
                bind: (c[5] != "-").then(|| c[5].to_string()),
            }
        })
        .collect()
}

fn recorded(dir: &Path) -> HashMap<String, (u16, Value)> {
    std::fs::read_to_string(dir.join("expected.jsonl"))
        .expect("expected.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            (
                v["id"].as_str().unwrap().to_string(),
                (v["status"].as_u64().unwrap() as u16, v["body"].clone()),
            )
        })
        .collect()
}

/// A JSON pointer where the part `#` is the length of the array reached so far (the same rule as `scripts/json_api_oracle.py`).
fn pointer(v: &Value, ptr: &str) -> Option<Value> {
    let mut cur = v.clone();
    for part in ptr.split('/').filter(|p| !p.is_empty()) {
        cur = match (&cur, part) {
            (Value::Array(a), "#") => Value::from(a.len()),
            (Value::Object(m), k) => m.get(k)?.clone(),
            (Value::Array(a), k) => a.get(k.parse::<usize>().ok()?)?.clone(),
            _ => return None,
        };
    }
    Some(cur)
}

/// The shape of a JSON value: objects keep their keys, scalars become their type name, an array becomes `["array", first]`.
fn shape(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), shape(x))).collect()),
        Value::Array(a) => {
            let mut out = vec![Value::String("array".into())];
            if let Some(first) = a.first() {
                out.push(shape(first));
            }
            Value::Array(out)
        }
        Value::Bool(_) => "bool".into(),
        Value::Number(_) => "number".into(),
        Value::Null => "null".into(),
        Value::String(_) => "string".into(),
    }
}

fn shapes_agree(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == 1 || y.len() == 1 || shapes_agree(&x[1], &y[1])
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| shapes_agree(v, w)))
        }
        _ => a == b,
    }
}

/// One call; a body with `Content-Type: application/octet-stream` is returned as its length, SHA-256 and the
/// `Canton-Package-Hash` header (the same recording `scripts/json_api_oracle.py` makes), any other body as text.
fn call(port: u16, method: &str, path: &str, body: &[u8], content_type: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let payload = raw[split..].to_vec();
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let header = |name: &str| {
        head.lines()
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim().to_string())
    };
    if header("content-type").is_some_and(|c| c.starts_with("application/octet-stream")) {
        let hex = lf_archive::compute_sha256(&payload);
        let rec = serde_json::json!({
            "_binary": { "length": payload.len(), "sha256": hex },
            "_headers": { "canton-package-hash": header("canton-package-hash").unwrap_or_default() }
        });
        return (status, rec.to_string());
    }
    (status, String::from_utf8_lossy(&payload).into_owned())
}

/// The request body: `{name}` is replaced as is, the JSON string "@end" by the bound number, `@file:<path>` is a binary body.
fn fill_body(body: &str, bound: &HashMap<String, String>) -> (Vec<u8>, &'static str) {
    if let Some(file) = body.strip_prefix("@file:") {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(file);
        return (
            std::fs::read(path).expect("binary body"),
            "application/octet-stream",
        );
    }
    let mut out = body.to_string();
    for (name, val) in bound {
        // `{name!flip}` / `{name!flipNN}`: the bound value with one character changed in the middle / NN percent into it (a
        // tampered copy, AT-C06)
        if !val.is_empty() {
            for pct in [50usize, 10, 20, 30, 40, 60, 70, 75, 80, 90, 95] {
                let pos = val.len() * pct / 100;
                let mut chars: Vec<char> = val.chars().collect();
                chars[pos] = if chars[pos] != 'A' { 'A' } else { 'B' };
                let tampered: String = chars.into_iter().collect();
                let tag = if pct == 50 {
                    format!("{{{name}!flip}}")
                } else {
                    format!("{{{name}!flip{pct}}}")
                };
                out = out.replace(&tag, &tampered);
            }
        }
        out = out.replace(&format!("{{{name}}}"), val);
    }
    for (name, val) in bound {
        out = out.replace(&format!("\"@{name}\""), val);
    }
    (out.into_bytes(), "application/json")
}

/// The participant emits `OffsetCheckpoint` items on a timer into update and completion streams; they show up in some runs
/// and not in others, so the oracle leaves them out of every array (the same rule as `scripts/json_api_oracle.py`).
fn drop_checkpoints(body: Value) -> Value {
    let Value::Array(items) = body else {
        return body;
    };
    Value::Array(
        items
            .into_iter()
            .filter(|x| {
                x.pointer("/update/OffsetCheckpoint").is_none()
                    && x.pointer("/completionResponse/OffsetCheckpoint").is_none()
            })
            .collect(),
    )
}

fn encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

#[test]
fn v2_responses_agree_with_the_recorded_canton_sandbox() {
    run_corpus(&dir(), || Arc::new(ExecutionService::new()), None);
}

/// S-STORE-007 (U-17): participant pruning, against what a Canton 3.7.2 Community sandbox (max deduplication duration 10 s)
/// answered to the steps of `tests/oracle/prune/requests.tsv`. A `CONSOLE prune N` step is the admin route here, a `SLEEP`
/// moves the service clock (no waiting).
#[test]
fn pruning_agrees_with_the_recorded_canton_sandbox() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/prune");
    run_corpus(
        &corpus,
        || {
            let svc = ExecutionService::new();
            svc.set_max_dedup(std::time::Duration::from_secs(10));
            Arc::new(svc)
        },
        None,
    );
}

/// Runs the whole corpus against the services `make` returns. With `restart_every = Some(n)` the service is dropped and `make`
/// builds a new one after every n requests: for a persistent store (S-STORE-005) the answers must still agree with the node's,
/// so a restart is invisible to a client.
pub fn run_corpus(
    dir: &Path,
    mut make: impl FnMut() -> Arc<ExecutionService>,
    restart_every: Option<usize>,
) {
    let (mut port, mut stop) = start_test_server(make());
    let expected = recorded(dir);
    let mut bound: HashMap<String, String> = HashMap::new();
    let (mut agreed, mut problems) = (0, Vec::new());
    let mut causes: HashMap<String, String> = HashMap::new();
    for (i, r) in requests(dir).into_iter().enumerate() {
        if restart_every.is_some_and(|n| i > 0 && i % n == 0) {
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            // the accept loop polls every 10 ms; wait until it let go of the old service (and so of the database connection)
            std::thread::sleep(std::time::Duration::from_millis(300));
            (port, stop) = start_test_server(make());
        }
        let mut path = r.path.clone();
        for (name, val) in &bound {
            path = path.replace(&format!("{{{name}}}"), &encode(val));
        }
        let (body, ctype) = r
            .body
            .as_deref()
            .map_or((Vec::new(), "application/json"), |b| fill_body(b, &bound));
        let (status, raw) = match r.method.as_str() {
            // the clock moves instead of the test waiting
            "SLEEP" => {
                ledger_json_api::clock::advance(path.parse::<i64>().expect("seconds") * 1_000_000);
                (200, "{}".to_string())
            }
            // the participant console's `prune(offset)`: the admin route here
            "CONSOLE" => {
                let offset = String::from_utf8(body.clone()).unwrap();
                let req = format!("{{\"pruneUpTo\":{offset}}}");
                call(
                    port,
                    "POST",
                    "/v2/admin/prune",
                    req.as_bytes(),
                    "application/json",
                )
            }
            _ => call(port, &r.method, &path, &body, ctype),
        };
        let (want_status, want_body) = expected
            .get(&r.id)
            .unwrap_or_else(|| panic!("{}: not recorded", r.id));
        let got: Value =
            serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({ "_text": raw }));
        let got = drop_checkpoints(got);
        if let Some(c) = got.get("cause").and_then(Value::as_str) {
            causes.insert(r.id.clone(), c.to_string());
        }
        if let (Some(bind), 200) = (&r.bind, status) {
            for one in bind.split(';') {
                let (name, ptr) = one.split_once('=').unwrap();
                match pointer(&got, ptr) {
                    Some(Value::String(v)) => bound.insert(name.to_string(), v.clone()),
                    Some(Value::Number(n)) => bound.insert(name.to_string(), n.to_string()),
                    _ => None,
                };
            }
        }
        let mut diffs = Vec::new();
        if status != *want_status {
            diffs.push(format!("status {want_status} (Canton) vs {status}"));
        } else if want_body.get("_text").is_some() || got.get("_text").is_some() {
            if want_body != &got {
                diffs.push(format!("text {want_body} vs {got}"));
            }
        } else if !shapes_agree(&shape(want_body), &shape(&got)) {
            diffs.push(format!("shape {} vs {}", shape(want_body), shape(&got)));
        } else {
            for ptr in &r.exact {
                // `/pointer~A|B`: an answer the node gives differently as time passes (U-17, U-19); the recording and this
                // server must each give one of the listed values
                if let Some((ptr, allowed)) = ptr.split_once('~') {
                    let allowed: Vec<&str> = allowed.split('|').collect();
                    for (who, body) in [("Canton", want_body), ("this server", &got)] {
                        let have = pointer(body, ptr).map(|v| match v {
                            Value::String(s) => s,
                            other => other.to_string(),
                        });
                        if !have.as_deref().is_some_and(|h| allowed.contains(&h)) {
                            diffs.push(format!(
                                "{who} answered {have:?} at {ptr}, not one of {allowed:?}"
                            ));
                        }
                    }
                    continue;
                }
                // `/pointer=name`: the value must equal the offset bound as `name` in THIS run (offsets differ from the node's)
                if let Some((ptr, name)) = ptr.split_once('=') {
                    let have = pointer(&got, ptr).map(|v| match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    });
                    if have.as_deref() != bound.get(name).map(String::as_str) {
                        diffs.push(format!(
                            "value at {ptr} is {have:?}, not {name}={:?}",
                            bound.get(name)
                        ));
                    }
                    continue;
                }
                if pointer(want_body, ptr) != pointer(&got, ptr) {
                    diffs.push(format!(
                        "value at {ptr}: {:?} vs {:?}",
                        pointer(want_body, ptr),
                        pointer(&got, ptr)
                    ));
                }
            }
        }
        if diffs.is_empty() {
            agreed += 1;
        } else {
            problems.push(format!(
                "{} {} {}: {}",
                r.id,
                r.method,
                r.path,
                diffs.join("; ")
            ));
        }
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    // [CANTON-NOTE: INVARIANT] AT-U04: a contract the actor cannot see (uu02), one that was archived (uu06) and an archived one
    // asked by an outsider (uu07) are all answered with the SAME text, so an answer never tells "exists but hidden" from
    // "gone". Checked on the recording (the node) and on this run (Rust).
    let same = ["uu02", "uu06", "uu07"];
    let node: Vec<String> = same
        .iter()
        .filter_map(|id| expected.get(*id))
        .filter_map(|(_, b)| b.get("cause").and_then(Value::as_str).map(str::to_string))
        .collect();
    if node.len() == same.len() && node.windows(2).any(|w| w[0] != w[1]) {
        problems.push(format!(
            "the recorded node answers differ between hidden/archived contracts: {node:?}"
        ));
    }
    let rust: Vec<&String> = same.iter().filter_map(|id| causes.get(*id)).collect();
    if rust.len() == same.len() && rust.windows(2).any(|w| w[0] != w[1]) {
        problems.push(format!(
            "Rust tells a hidden contract from an archived one: {rust:?}"
        ));
    }
    assert!(
        problems.is_empty(),
        "MISMATCH against the recorded Canton responses:\n  {}",
        problems.join("\n  ")
    );
    eprintln!("json-api-v2: {agreed} responses agree with the recorded Canton sandbox");
}

/// S-STORE-005: the same corpus with the ledger in PostgreSQL and a restart of the service every `RESTART_EVERY` requests.
#[cfg(feature = "pg-tests")]
#[test]
fn v2_responses_agree_with_the_node_across_restarts_on_postgres() {
    use ledger_json_api::store_pg::PgLog;
    let url = std::env::var("CANTON_RS_PG_URL")
        .expect("CANTON_RS_PG_URL must point at a PostgreSQL server");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ledger = format!("corpus-{}-{nanos}", std::process::id());
    let restarts = std::cell::Cell::new(0usize);
    run_corpus(
        &dir(),
        || {
            let svc = ExecutionService::new();
            let log = PgLog::connect(&url, &ledger).expect("connect");
            let report = svc.attach_store(Box::new(log)).expect("attach store");
            restarts.set(restarts.get() + 1);
            eprintln!(
                "service #{}: {} requests replayed",
                restarts.get(),
                report.replayed
            );
            Arc::new(svc)
        },
        Some(7),
    );
    assert!(
        restarts.get() > 5,
        "the corpus must have restarted the service several times"
    );
}
