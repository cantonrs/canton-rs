//! AI coding agent `.dar` verification MCP server (`canton-rs dpm mcp`): line-delimited JSON-RPC 2.0
//! over stdio, no network listener, read-only tools.
//!
//! [CANTON-NOTE: DEFENSIVE] The client is an agent that may be prompt-injected, so every client-supplied
//! path must resolve under the server root, request lines and pack files are size-capped, and fuzz
//! sizes are bounded by `MAX_FUZZ_SEEDS` / `MAX_FUZZ_STEPS`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use serde_json::{json, Value as Json};

use super::dpm_vision::{
    audit_dar_privacy, check_dar_like_upload, fuzz_dar_authorization, parse_signer_trust,
    read_and_verify_pack,
};

/// Largest JSON-RPC request line the server reads.
const MAX_REQUEST_LINE_BYTES: u64 = 1 << 20;

#[derive(Args, Debug)]
pub struct McpDarArgs {
    /// Optional default `.dar` path used when an MCP tool call omits `dar_path`.
    #[arg(long)]
    pub dar: Option<PathBuf>,

    /// Directory client-supplied paths must resolve under (default: the current directory).
    #[arg(long)]
    pub root: Option<PathBuf>,
}

/// Server-side configuration shared by every request.
pub struct McpContext {
    /// Operator-configured default DAR; trusted, so it is not confined to `root`.
    pub default_dar: Option<PathBuf>,
    /// Canonical directory that client-supplied paths must resolve under.
    pub root: PathBuf,
}

impl McpContext {
    pub fn new(default_dar: Option<PathBuf>, root: &Path) -> Result<Self, String> {
        let root = root
            .canonicalize()
            .map_err(|e| format!("invalid MCP root '{}': {e}", root.display()))?;
        Ok(Self { default_dar, root })
    }

    /// Resolves a client-supplied path. Missing and outside paths get the same error, so a client
    /// cannot probe for files outside the root.
    fn resolve_client_path(&self, raw: &str) -> Result<PathBuf, String> {
        let refused = || {
            format!(
                "'{raw}' is not a readable file under the MCP root {}",
                self.root.display()
            )
        };
        let joined = self.root.join(raw);
        let resolved = joined.canonicalize().map_err(|_| refused())?;
        if resolved.starts_with(&self.root) && resolved.is_file() {
            Ok(resolved)
        } else {
            Err(refused())
        }
    }

    fn dar_path(&self, args: Option<&Json>) -> Result<PathBuf, String> {
        if let Some(p) = args.and_then(|a| a.get("dar_path")).and_then(Json::as_str) {
            return self.resolve_client_path(p);
        }
        self.default_dar.clone().ok_or_else(|| {
            "missing required 'dar_path' argument (and no --dar default configured)".to_string()
        })
    }
}

/// Runs the Model Context Protocol (`2024-11-05`) JSON-RPC 2.0 server over stdio.
pub fn execute_mcp_server(args: McpDarArgs) -> Result<(), String> {
    let root = match args.root {
        Some(r) => r,
        None => std::env::current_dir().map_err(|e| e.to_string())?,
    };
    let ctx = McpContext::new(args.dar, &root)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    run_mcp_loop(&mut reader, &mut writer, &ctx)
}

enum RequestLine {
    Eof,
    Line(String),
    TooLong,
}

fn read_request_line<R: BufRead>(reader: &mut R) -> Result<RequestLine, String> {
    let mut buf = Vec::new();
    let n = reader
        .by_ref()
        .take(MAX_REQUEST_LINE_BYTES + 1)
        .read_until(b'\n', &mut buf)
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(RequestLine::Eof);
    }
    if buf.len() as u64 > MAX_REQUEST_LINE_BYTES && buf.last() != Some(&b'\n') {
        reader.skip_until(b'\n').map_err(|e| e.to_string())?;
        return Ok(RequestLine::TooLong);
    }
    Ok(RequestLine::Line(
        String::from_utf8_lossy(&buf).into_owned(),
    ))
}

fn write_frame<W: Write>(writer: &mut W, frame: &Json) -> Result<(), String> {
    writeln!(writer, "{frame}").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())
}

/// Testable line-delimited JSON-RPC 2.0 MCP loop supporting `initialize`, `ping`, `tools/list`, and `tools/call`.
pub fn run_mcp_loop<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    ctx: &McpContext,
) -> Result<(), String> {
    loop {
        let line = match read_request_line(reader)? {
            RequestLine::Eof => break,
            RequestLine::TooLong => {
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32600, "message": format!("request line exceeds {MAX_REQUEST_LINE_BYTES} bytes") }
                });
                write_frame(writer, &resp)?;
                continue;
            }
            RequestLine::Line(line) => line,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Json = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                write_frame(writer, &err_resp)?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(Json::as_str).unwrap_or("");
        // JSON-RPC notifications (no `id`, e.g. `notifications/initialized`) produce no response frame.
        if id.is_none() || method.starts_with("notifications/") {
            continue;
        }

        let resp = handle_mcp_request(id.unwrap_or(Json::Null), method, req.get("params"), ctx);
        write_frame(writer, &resp)?;
    }
    Ok(())
}

fn handle_mcp_request(id: Json, method: &str, params: Option<&Json>, ctx: &McpContext) -> Json {
    match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "canton-rs-dpm-verifier-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {
                        "name": "inspect_dar_surface",
                        "description": "Inspect compiled Daml-LF 2 DAR package ID, modules, templates, signatories, observers, and choices, plus whether the upload checks (manifest, dependencies, LF typecheck) accept it.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "dar_path": { "type": "string" } }
                        }
                    },
                    {
                        "name": "audit_dar_privacy",
                        "description": "Static signatory/controller coverage and observer broadcast audit; refuses a DAR the upload checks would refuse.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "dar_path": { "type": "string" } }
                        }
                    },
                    {
                        "name": "fuzz_dar_authorization",
                        "description": "Run deterministic in-memory multi-party authorization and stakeholder-isolation fuzzing against a DAR. Verdict is PASS, FAIL, or INCONCLUSIVE.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "dar_path": { "type": "string" },
                                "seeds": { "type": "integer", "maximum": super::dpm_vision::MAX_FUZZ_SEEDS },
                                "steps": { "type": "integer", "maximum": super::dpm_vision::MAX_FUZZ_STEPS }
                            }
                        }
                    },
                    {
                        "name": "verify_audit_capsule",
                        "description": "Offline-verify a Selective Audit Capsule (.audit-pack) Merkle proof and Ed25519 signature. Without expected_signer_key_hex only integrity is checked, not who signed.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "pack_path": { "type": "string" },
                                "expected_signer_key_hex": { "type": "string" }
                            },
                            "required": ["pack_path"]
                        }
                    }
                ]
            }
        }),
        "tools/call" => {
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(Json::as_str)
                .unwrap_or("");
            let args = params.and_then(|p| p.get("arguments"));
            let (text, is_error) = match dispatch_mcp_tool(name, args, ctx) {
                Ok(val) => match serde_json::to_string_pretty(&val) {
                    Ok(text) => (text, false),
                    Err(e) => (e.to_string(), true),
                },
                Err(err_msg) => (err_msg, true),
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": is_error
                }
            })
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    }
}

fn size_arg(args: Option<&Json>, key: &str, default: usize) -> Result<usize, String> {
    match args.and_then(|a| a.get(key)) {
        None => Ok(default),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("'{key}' must be a non-negative integer")),
    }
}

fn dispatch_mcp_tool(name: &str, args: Option<&Json>, ctx: &McpContext) -> Result<Json, String> {
    match name {
        "inspect_dar_surface" => {
            let path = ctx.dar_path(args)?;
            let archive = lf_archive::parse_dar_file(&path).map_err(|e| e.to_string())?;
            let upload_check = match check_dar_like_upload(&path) {
                Ok(()) => "accepted".to_string(),
                Err(e) => format!("refused: {e}"),
            };
            let mut summary_map = BTreeMap::new();
            summary_map.insert("main_package_id", json!(archive.main_package_id));
            summary_map.insert("lf_version", json!(archive.lf_version));
            summary_map.insert("modules", json!(archive.modules));
            summary_map.insert("module_surfaces", json!(archive.module_surfaces));
            summary_map.insert("upload_check", json!(upload_check));
            serde_json::to_value(summary_map).map_err(|e| e.to_string())
        }
        "audit_dar_privacy" => {
            let path = ctx.dar_path(args)?;
            let rep = audit_dar_privacy(&path)?;
            serde_json::to_value(rep).map_err(|e| e.to_string())
        }
        "fuzz_dar_authorization" => {
            let path = ctx.dar_path(args)?;
            let seeds = size_arg(args, "seeds", 2)?;
            let steps = size_arg(args, "steps", 6)?;
            let rep = fuzz_dar_authorization(&path, 0xCA47_0425_2026_0001, seeds, steps)?;
            serde_json::to_value(rep).map_err(|e| e.to_string())
        }
        "verify_audit_capsule" => {
            let raw = args
                .and_then(|a| a.get("pack_path"))
                .and_then(Json::as_str)
                .ok_or_else(|| "missing 'pack_path' argument".to_string())?;
            let pack_path = ctx.resolve_client_path(raw)?;
            let expected = args
                .and_then(|a| a.get("expected_signer_key_hex"))
                .and_then(Json::as_str);
            let trust = parse_signer_trust(expected)?;
            let verified = read_and_verify_pack(&pack_path, trust)?;
            serde_json::to_value(verified).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown MCP tool '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::commands::dpm_vision::DarFuzzReport;

    fn repo_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(rel)
    }

    fn ctx(default_dar: Option<&str>) -> McpContext {
        McpContext::new(default_dar.map(repo_path), &repo_path("")).expect("mcp root")
    }

    fn mcp_frames(requests: &str, ctx: &McpContext) -> Vec<Json> {
        let mut reader = Cursor::new(requests.as_bytes().to_vec());
        let mut output = Vec::new();
        run_mcp_loop(&mut reader, &mut output, ctx).expect("mcp loop");
        String::from_utf8(output)
            .expect("utf8")
            .lines()
            .map(|l| serde_json::from_str(l).expect("frame json"))
            .collect()
    }

    #[test]
    fn mcp_survives_oversized_fuzz_request() {
        let frames = mcp_frames(
            concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fuzz_dar_authorization","arguments":{"seeds":4611686018427387904,"steps":1}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
                "\n"
            ),
            &ctx(Some("contracts/target/sample-contract.dar")),
        );
        assert_eq!(frames.len(), 2, "server must answer both requests");
        assert_eq!(frames[0]["result"]["isError"], true);
        assert_eq!(frames[1]["id"], 2);
    }

    #[test]
    fn mcp_answers_an_oversized_request_line_and_keeps_serving() {
        let mut requests = String::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping","pad":""#);
        requests.push_str(&"x".repeat(MAX_REQUEST_LINE_BYTES as usize + 10));
        requests.push_str("\"}\n");
        requests.push_str(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
        requests.push('\n');
        let frames = mcp_frames(&requests, &ctx(None));
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["error"]["code"], -32600);
        assert_eq!(frames[1]["id"], 2);
    }

    #[test]
    fn mcp_dar_tools_refuse_what_the_upload_path_refuses() {
        let frames = mcp_frames(
            concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_dar_privacy","arguments":{}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_dar_surface","arguments":{}}}"#,
                "\n"
            ),
            &ctx(Some("tests/e2e/fixtures/valid_lf22.dar")),
        );
        assert_eq!(frames[0]["result"]["isError"], true, "got {}", frames[0]);
        let surface = frames[1]["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        assert!(
            surface.contains("\"upload_check\": \"refused"),
            "got {surface}"
        );
    }

    #[test]
    fn mcp_refuses_paths_outside_its_root_without_revealing_existence() {
        let frames = mcp_frames(
            concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"inspect_dar_surface","arguments":{"dar_path":"/etc/hosts"}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_dar_surface","arguments":{"dar_path":"/no/such/file.dar"}}}"#,
                "\n",
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_dar_surface","arguments":{"dar_path":"contracts/target/sample-contract.dar"}}}"#,
                "\n"
            ),
            &ctx(None),
        );
        let a = frames[0]["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        let b = frames[1]["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        assert!(a.contains("under the MCP root"), "got: {a}");
        assert_eq!(
            a.replace("/etc/hosts", ""),
            b.replace("/no/such/file.dar", "")
        );
        assert_eq!(
            frames[2]["result"]["isError"], false,
            "a path under the root is served"
        );
    }

    #[test]
    fn mcp_loop_serves_sample_dar_end_to_end() {
        let requests = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"audit_dar_privacy","arguments":{}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fuzz_dar_authorization","arguments":{"seeds":1,"steps":3}}}"#,
            "\n"
        );
        let frames = mcp_frames(requests, &ctx(Some("contracts/target/sample-contract.dar")));
        assert_eq!(frames.len(), 4, "a notification produces no frame");
        assert_eq!(
            frames[0]["result"]["serverInfo"]["name"],
            "canton-rs-dpm-verifier-mcp"
        );
        assert!(frames[1].to_string().contains("fuzz_dar_authorization"));
        assert_eq!(frames[2]["result"]["isError"], false);
        let inner_txt = frames[3]["result"]["content"][0]["text"]
            .as_str()
            .expect("mcp content text");
        let inner_fuzz: DarFuzzReport = serde_json::from_str(inner_txt).expect("DarFuzzReport");
        assert_eq!(inner_fuzz.verdict, "PASS", "{}", inner_fuzz.verdict_reason);
        assert_eq!(inner_fuzz.stakeholder_isolation_violations, 0);
    }
}
