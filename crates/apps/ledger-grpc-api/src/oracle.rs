//! The gRPC oracle: replays `tests/oracle/grpc-api/requests.tsv` against a Ledger API v2 gRPC endpoint (a reference Canton
//! sandbox, or this server) and records `{id, method, path, status, body}` lines, the same shape `scripts/json_api_oracle.py`
//! compares. The comparison rule is the JSON API oracle's: the same status, the same JSON shape, and equal values at the
//! JSON pointers of the `exact` column.
//!
//! A response message is recorded as protobuf JSON with every field written (default values included). An error is recorded as
//! `{"code": <Canton error code>, "message": <cause>}`, parsed from the status message `CODE(category,correlation): cause`;
//! the gRPC code is the `status`.
use std::collections::HashMap;

use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::{json, Value as Json};
use tonic::Request;

use crate::dynamic::DynCodec;

const PACKAGE: &str = "com.daml.ledger.api.v2.";

pub struct Spec {
    pub id: String,
    /// The token (by name) the request is sent with: `GRPC:<name>` in the method column; none for plain `GRPC`.
    pub token: Option<String>,
    pub path: String,
    pub body: String,
    pub exact: Vec<String>,
    pub bind: Option<String>,
}

pub fn parse_requests(tsv: &str) -> Vec<Spec> {
    tsv.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            Spec {
                id: c[0].to_string(),
                token: c[1].strip_prefix("GRPC:").map(String::from),
                path: c[2].to_string(),
                body: c[3].to_string(),
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

/// A JSON pointer where the part `#` is the length of the array reached so far.
pub fn pointer(v: &Json, ptr: &str) -> Option<Json> {
    let mut cur = v.clone();
    for part in ptr.split('/').filter(|p| !p.is_empty()) {
        cur = match (&cur, part) {
            (Json::Array(a), "#") => Json::from(a.len()),
            (Json::Object(m), k) => m.get(k)?.clone(),
            (Json::Array(a), k) => a.get(k.parse::<usize>().ok()?)?.clone(),
            _ => return None,
        };
    }
    Some(cur)
}

fn shape(v: &Json) -> Json {
    match v {
        Json::Object(m) => Json::Object(m.iter().map(|(k, x)| (k.clone(), shape(x))).collect()),
        Json::Array(a) => {
            let mut out = vec![Json::String("array".into())];
            if let Some(first) = a.first() {
                out.push(shape(first));
            }
            Json::Array(out)
        }
        Json::Bool(_) => "bool".into(),
        Json::Number(_) => "number".into(),
        Json::Null => "null".into(),
        Json::String(_) => "string".into(),
    }
}

fn shapes_agree(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Array(x), Json::Array(y)) => {
            x.len() == 1 || y.len() == 1 || shapes_agree(&x[1], &y[1])
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| shapes_agree(v, w)))
        }
        _ => a == b,
    }
}

/// The differences between a recorded and a fresh response, empty when they agree.
pub fn compare(want: &Json, got: &Json, exact: &[String]) -> Vec<String> {
    let mut diffs = Vec::new();
    if want["status"] != got["status"] {
        diffs.push(format!(
            "status {} (reference) vs {}",
            want["status"], got["status"]
        ));
    } else if !shapes_agree(&shape(&want["body"]), &shape(&got["body"])) {
        diffs.push(format!(
            "shape {} vs {}",
            shape(&want["body"]),
            shape(&got["body"])
        ));
    } else {
        for ptr in exact {
            let (a, b) = (pointer(&want["body"], ptr), pointer(&got["body"], ptr));
            if a != b {
                diffs.push(format!("value at {ptr}: {a:?} vs {b:?}"));
            }
        }
    }
    diffs
}

fn fill(body: &str, bound: &HashMap<String, String>) -> String {
    let mut out = body.to_string();
    for (name, val) in bound {
        out = out.replace(&format!("{{{name}}}"), val);
        out = out.replace(&format!("\"@{name}\""), val);
    }
    out
}

/// `"@file64:<path>"` in a request body is the base64 of that file (a path relative to the repository root).
fn files(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some(i) = rest.find("\"@file64:") {
        out.push_str(&rest[..i]);
        let after = &rest[i + "\"@file64:".len()..];
        let end = after.find('"').expect("closing quote");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(&after[..end]);
        out.push('"');
        out.push_str(&base64(&std::fs::read(path).expect("file64")));
        out.push('"');
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn base64(data: &[u8]) -> String {
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

fn with_token(
    msg: DynamicMessage,
    name: &Option<String>,
    tokens: &HashMap<String, String>,
) -> Request<DynamicMessage> {
    let mut request = Request::new(msg);
    if let Some(token) = name.as_ref().and_then(|n| tokens.get(n)) {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata"),
        );
    }
    request
}

fn error_body(msg: &str) -> Json {
    // `CODE(category,correlation): cause`
    if let Some((head, cause)) = msg.split_once("): ") {
        if let Some((code, _)) = head.split_once('(') {
            if !code.is_empty() && code.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                return json!({ "code": code, "message": cause });
            }
        }
    }
    json!({ "code": "", "message": msg })
}

/// Replays every request against `endpoint` (`host:port`) and returns the records, in order. `tokens` maps the token names
/// of the request file to bearer tokens.
pub async fn replay(endpoint: &str, tsv: &str, tokens: &HashMap<String, String>) -> Vec<Json> {
    let pool = DescriptorPool::decode(canton_proto::FILE_DESCRIPTOR_SET).expect("descriptor set");
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{endpoint}"))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let opts = SerializeOptions::new()
        .skip_default_fields(false)
        .stringify_64_bit_integers(false);
    let mut bound: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for spec in parse_requests(tsv) {
        let (svc, name) = spec.path.split_once('/').expect("Service/Method");
        let method = pool
            .get_service_by_name(&format!("{PACKAGE}{svc}"))
            .and_then(|s| s.methods().find(|m| m.name() == name))
            .unwrap_or_else(|| panic!("unknown method {}", spec.path));
        let json: Json =
            serde_json::from_str(&files(&fill(&spec.body, &bound))).expect("request json");
        let request = DynamicMessage::deserialize(method.input(), json).expect("request message");
        let mut grpc = tonic::client::Grpc::new(channel.clone());
        grpc.ready().await.expect("ready");
        let path =
            http::uri::PathAndQuery::try_from(format!("/{PACKAGE}{}/{}", svc, name)).expect("path");
        let codec = DynCodec::new(method.output());
        let result: Result<Vec<DynamicMessage>, tonic::Status> = if method.is_server_streaming() {
            match grpc
                .server_streaming(Request::new(request), path, codec)
                .await
            {
                Ok(resp) => {
                    let mut stream = resp.into_inner();
                    let mut items = Vec::new();
                    loop {
                        // a stream that stays open (a reference server waits for new items) ends when it has been
                        // idle for a while, like the JSON API's `stream_idle_timeout_ms`
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(2500),
                            stream.message(),
                        )
                        .await
                        {
                            Ok(Ok(Some(m))) => items.push(m),
                            Ok(Ok(None)) | Err(_) => break Ok(items),
                            Ok(Err(e)) => break Err(e),
                        }
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            grpc.unary(with_token(request, &spec.token, tokens), path, codec)
                .await
                .map(|r| vec![r.into_inner()])
        };
        let (status, body) = match result {
            Ok(items) => {
                let rendered: Vec<Json> = items
                    .iter()
                    .map(|m| {
                        m.serialize_with_options(serde_json::value::Serializer, &opts)
                            .unwrap_or(Json::Null)
                    })
                    // the participant emits `OffsetCheckpoint` items on a timer into update and completion streams; they
                    // come and go between runs, so they are left out (the same rule as the JSON API oracle)
                    .filter(|j| {
                        j.pointer("/update/offsetCheckpoint")
                            .is_none_or(Json::is_null)
                            && j.pointer("/completionResponse/offsetCheckpoint")
                                .is_none_or(Json::is_null)
                    })
                    .collect();
                (
                    0,
                    if method.is_server_streaming() {
                        Json::Array(rendered)
                    } else {
                        rendered.into_iter().next().unwrap_or(Json::Null)
                    },
                )
            }
            Err(e) => (e.code() as i32, error_body(e.message())),
        };
        if let (Some(bind), 0) = (&spec.bind, status) {
            for one in bind.split(';') {
                let (n, ptr) = one.split_once('=').expect("name=pointer");
                match pointer(&body, ptr) {
                    Some(Json::String(v)) => bound.insert(n.to_string(), v),
                    Some(Json::Number(v)) => bound.insert(n.to_string(), v.to_string()),
                    _ => None,
                };
            }
        }
        out.push(json!({ "id": spec.id, "method": "GRPC", "path": spec.path, "status": status, "body": body }));
    }
    out
}
