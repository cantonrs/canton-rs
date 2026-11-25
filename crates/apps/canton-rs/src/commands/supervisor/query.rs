//! Participant Ledger API query/watch/replay and projection-diff commands (`S-DX-005`).
//!
//! Covers:
//! - `canton-rs daemon contracts ls|watch`
//! - `canton-rs daemon tx ls|replay|diff`

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value as Json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::commands::exit_code::{exit_with_message, EXIT_MISMATCH, EXIT_PREFLIGHT};
use crate::commands::json_http;

use super::cli::{
    ContractsAction, ContractsCliArgs, ContractsLsArgs, ContractsWatchArgs, StatusFormatArg,
    TxAction, TxCliArgs, TxDiffArgs, TxLsArgs, TxReplayArgs,
};
use super::projection::{
    check_witness_invariants, diff_captures, normalize_capture, DiffEntry, ScenarioCapture,
};

const MAX_WS_FRAME_BYTES: usize = 16 * 1024 * 1024;
const WS_CLOSE_DRAIN_MS: u64 = 200;
static WS_NONCE: AtomicU64 = AtomicU64::new(1);

/// Resolved HTTP/1.1 Ledger JSON API host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointTarget {
    pub host: String,
    pub port: u16,
    pub base_url: String,
}

/// Validated template filter specification (`#<package-name>:<Module>:<Entity>` or `<package-id>:<Module>:<Entity>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateFilterSpec {
    ByPkgName {
        pkg_name: String,
        module_entity: String,
    },
    ByPkgId {
        pkg_id: String,
        module_entity: String,
    },
}

impl TemplateFilterSpec {
    /// Parses `#<pkg-name>:<Module>:<Entity>` or `<pkg-id>:<Module>:<Entity>`, failing with `EXIT_PREFLIGHT`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let fail = || {
            exit_with_message(
                EXIT_PREFLIGHT,
                format!(
                    "invalid --template '{raw}': expected '#<package-name>:<Module>:<Entity>' or '<package-id>:<Module>:<Entity>'"
                ),
            )
        };
        if raw.trim().is_empty() || raw.chars().any(char::is_whitespace) {
            return Err(fail());
        }
        if let Some(rest) = raw.strip_prefix('#') {
            let (pkg_name, local) = rest.split_once(':').ok_or_else(fail)?;
            let (module_name, entity_name) = local.split_once(':').ok_or_else(fail)?;
            if pkg_name.is_empty()
                || pkg_name.contains('#')
                || module_name.is_empty()
                || entity_name.is_empty()
                || entity_name.contains(':')
            {
                return Err(fail());
            }
            return Ok(Self::ByPkgName {
                pkg_name: pkg_name.to_string(),
                module_entity: format!("{module_name}:{entity_name}"),
            });
        }
        let (pkg_id, local) = raw.split_once(':').ok_or_else(fail)?;
        let (module_name, entity_name) = local.split_once(':').ok_or_else(fail)?;
        if pkg_id.is_empty()
            || pkg_id.contains('#')
            || module_name.is_empty()
            || entity_name.is_empty()
            || entity_name.contains(':')
        {
            return Err(fail());
        }
        Ok(Self::ByPkgId {
            pkg_id: pkg_id.to_string(),
            module_entity: format!("{module_name}:{entity_name}"),
        })
    }

    /// Wire `TemplateFilter` identifier when expressed as package name (`#<pkg>:<Mod>:<Ent>`).
    fn wire_template_id(&self) -> Option<String> {
        match self {
            Self::ByPkgName {
                pkg_name,
                module_entity,
            } => Some(format!("#{pkg_name}:{module_entity}")),
            Self::ByPkgId { .. } => None,
        }
    }

    /// Client-side check supporting both package-name and package-id filters.
    pub fn matches_event(&self, ev_body: &Json) -> bool {
        let Some((ev_pkg_id, ev_local)) = parse_event_template_id(ev_body.get("templateId")) else {
            return false;
        };
        let ev_pkg_name = ev_body
            .get("packageName")
            .and_then(Json::as_str)
            .unwrap_or_default();
        match self {
            Self::ByPkgName {
                pkg_name,
                module_entity,
            } => ev_local == *module_entity && ev_pkg_name == *pkg_name,
            Self::ByPkgId {
                pkg_id,
                module_entity,
            } => ev_local == *module_entity && ev_pkg_id == *pkg_id,
        }
    }
}

fn parse_event_template_id(val: Option<&Json>) -> Option<(String, String)> {
    let v = val?;
    if let Some(s) = v.as_str() {
        let (pkg, rest) = s.split_once(':')?;
        return (!pkg.is_empty() && rest.contains(':'))
            .then(|| (pkg.to_string(), rest.to_string()));
    }
    let obj = v.as_object()?;
    let pkg = obj.get("packageId").and_then(Json::as_str)?;
    let module = obj.get("moduleName").and_then(Json::as_str)?;
    let entity = obj.get("entityName").and_then(Json::as_str)?;
    Some((pkg.to_string(), format!("{module}:{entity}")))
}

fn canonical_template_string(val: Option<&Json>) -> String {
    match parse_event_template_id(val) {
        Some((pkg, local)) => format!("{pkg}:{local}"),
        None => val
            .and_then(Json::as_str)
            .unwrap_or("<unknown>")
            .to_string(),
    }
}

/// Parses `http://host:port` (plain HTTP only), rejecting invalid URLs with `EXIT_PREFLIGHT`.
pub fn parse_http_url(raw: &str) -> Result<EndpointTarget, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
        exit_with_message(
            EXIT_PREFLIGHT,
            format!("unsupported Ledger JSON API URL '{raw}': expected 'http://<host>:<port>'"),
        )
    })?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("invalid URL '{raw}': empty host"),
        ));
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (h, after) = bracketed.split_once(']').ok_or_else(|| {
            exit_with_message(EXIT_PREFLIGHT, format!("invalid IPv6 host in '{raw}'"))
        })?;
        let p = match after.strip_prefix(':') {
            Some(ps) => ps.parse::<u16>().map_err(|_| {
                exit_with_message(EXIT_PREFLIGHT, format!("invalid port in '{raw}'"))
            })?,
            None if after.is_empty() => 80,
            None => {
                return Err(exit_with_message(
                    EXIT_PREFLIGHT,
                    format!("invalid authority in '{raw}'"),
                ));
            }
        };
        (h.to_string(), p)
    } else if let Some((h, ps)) = authority.rsplit_once(':') {
        let p = ps
            .parse::<u16>()
            .map_err(|_| exit_with_message(EXIT_PREFLIGHT, format!("invalid port in '{raw}'")))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), 80)
    };
    if host.is_empty() {
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!("invalid URL '{raw}': empty host"),
        ));
    }
    Ok(EndpointTarget {
        host: host.clone(),
        port,
        base_url: format!("http://{host}:{port}"),
    })
}

pub(crate) fn resolve_endpoint(
    url: Option<&str>,
    name: Option<&str>,
    state_dir: Option<&Path>,
    participant: Option<&str>,
) -> Result<EndpointTarget, String> {
    if let Some(u) = url {
        return parse_http_url(u);
    }
    let dir = super::registry::resolve_target_state_dir(name, state_dir)
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let report = super::status::collect_daemon_status(&dir)
        .map_err(|e| exit_with_message(EXIT_PREFLIGHT, e))?;
    let found = if let Some(p) = participant {
        report
            .endpoints
            .get(&format!("{p}.json"))
            .or_else(|| report.endpoints.get(p))
            .or_else(|| report.endpoints.get(&format!("{p}_json")))
    } else {
        report
            .endpoints
            .iter()
            .find(|(k, _)| k.ends_with(".json") || k.ends_with("_json"))
            .map(|(_, v)| v)
    };
    let Some(ep) = found else {
        let target = participant.unwrap_or("<default participant>");
        return Err(exit_with_message(
            EXIT_PREFLIGHT,
            format!(
                "no Ledger JSON API endpoint found for {target} under {}",
                dir.display()
            ),
        ));
    };
    parse_http_url(&ep.url)
}

fn build_event_format(
    party: &str,
    template: Option<&TemplateFilterSpec>,
    interfaces: &[String],
) -> Json {
    let mut cumulative = Vec::new();
    match template.and_then(TemplateFilterSpec::wire_template_id) {
        Some(wire_id) => {
            cumulative.push(json!({
                "identifierFilter": {
                    "TemplateFilter": {
                        "value": {
                            "templateId": wire_id,
                            "includeCreatedEventBlob": false
                        }
                    }
                }
            }));
        }
        None => {
            cumulative.push(json!({
                "identifierFilter": {
                    "WildcardFilter": {
                        "value": {
                            "includeCreatedEventBlob": false
                        }
                    }
                }
            }));
        }
    }
    for iface in interfaces {
        cumulative.push(json!({
            "identifierFilter": {
                "InterfaceFilter": {
                    "value": {
                        "interfaceId": iface,
                        "includeInterfaceView": true,
                        "includeCreatedEventBlob": false
                    }
                }
            }
        }));
    }
    json!({
        "filtersByParty": {
            party: {
                "cumulative": cumulative
            }
        },
        "verbose": false
    })
}

fn parse_u64_json(v: Option<&Json>) -> Option<u64> {
    v.and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse::<u64>().ok()))
}

fn fetch_ledger_end(ep: &EndpointTarget) -> Result<u64, String> {
    let (status, resp) = json_http::call(&ep.host, ep.port, "GET", "/v2/state/ledger-end", None)?;
    if status != 200 {
        return Err(format!(
            "GET {}/v2/state/ledger-end failed ({status}): {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    }
    parse_u64_json(resp.get("offset"))
        .ok_or_else(|| format!("missing `offset` in /v2/state/ledger-end response: {resp}"))
}

/// Dispatches `canton-rs daemon contracts <action>`.
pub fn cmd_contracts(args: ContractsCliArgs) -> Result<(), String> {
    match args.action {
        ContractsAction::Ls(a) => cmd_contracts_ls(a),
        ContractsAction::Watch(a) => cmd_contracts_watch(a),
    }
}

/// Dispatches `canton-rs daemon tx <action>`.
pub fn cmd_tx(args: TxCliArgs) -> Result<(), String> {
    match args.action {
        TxAction::Ls(a) => cmd_tx_ls(a),
        TxAction::Replay(a) => cmd_tx_replay(a),
        TxAction::Diff(a) => cmd_tx_diff(a),
    }
}

fn cmd_contracts_ls(args: ContractsLsArgs) -> Result<(), String> {
    let ep = resolve_endpoint(
        args.url.as_deref(),
        args.name.as_deref(),
        args.state_dir.as_deref(),
        args.participant.as_deref(),
    )?;
    let tpl_filter = args
        .template
        .as_deref()
        .map(TemplateFilterSpec::parse)
        .transpose()?;
    let active_at = match args.at {
        Some(off) => off,
        None => fetch_ledger_end(&ep)?,
    };

    let req = json!({
        "eventFormat": build_event_format(&args.party, tpl_filter.as_ref(), &[]),
        "activeAtOffset": active_at,
    });
    let (status, resp) = json_http::call_json(
        &ep.host,
        ep.port,
        "POST",
        "/v2/state/active-contracts",
        Some(&req),
    )?;
    if status != 200 {
        return Err(format!(
            "POST {}/v2/state/active-contracts failed ({status}): {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    }

    let items = resp
        .as_array()
        .or_else(|| resp.get("activeContracts").and_then(Json::as_array))
        .ok_or_else(|| format!("unexpected /v2/state/active-contracts payload: {resp}"))?;

    let mut rows: Vec<Json> = Vec::new();
    for entry in items {
        let Some(active) = entry
            .pointer("/contractEntry/JsActiveContract")
            .or_else(|| entry.get("JsActiveContract"))
        else {
            continue;
        };
        let Some(ce) = active.get("createdEvent") else {
            continue;
        };
        if let Some(ref flt) = tpl_filter {
            if !flt.matches_event(ce) {
                continue;
            }
        }
        let cid = ce
            .get("contractId")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string();
        let template_id = canonical_template_string(ce.get("templateId"));
        let created_offset = parse_u64_json(ce.get("offset")).unwrap_or(0);
        rows.push(json!({
            "contractId": cid,
            "templateId": template_id,
            "packageName": ce.get("packageName").and_then(Json::as_str).unwrap_or_default(),
            "createdAtOffset": created_offset,
            "signatories": ce.get("signatories").cloned().unwrap_or_else(|| json!([])),
            "observers": ce.get("observers").cloned().unwrap_or_else(|| json!([])),
            "createArgument": ce.get("createArgument").cloned().unwrap_or(Json::Null),
            "synchronizerId": active.get("synchronizerId").cloned().unwrap_or(Json::Null),
        }));
    }
    rows.sort_by(|a, b| {
        let ca = a.get("contractId").and_then(Json::as_str).unwrap_or("");
        let cb = b.get("contractId").and_then(Json::as_str).unwrap_or("");
        ca.cmp(cb)
    });

    match args.format {
        StatusFormatArg::Json => {
            let doc = json!({
                "party": args.party,
                "activeAtOffset": active_at,
                "contracts": rows,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            for r in &rows {
                let cid = r["contractId"].as_str().unwrap_or("");
                let tpl = r["templateId"].as_str().unwrap_or("");
                let off = r["createdAtOffset"].as_u64().unwrap_or(0);
                let sigs = &r["signatories"];
                let obs = &r["observers"];
                let payload = &r["createArgument"];
                println!("{cid}\t{tpl}\toffset={off}\tsignatories={sigs}\tobservers={obs}\tpayload={payload}");
            }
        }
    }
    Ok(())
}

fn cmd_contracts_watch(args: ContractsWatchArgs) -> Result<(), String> {
    let ep = resolve_endpoint(
        args.url.as_deref(),
        args.name.as_deref(),
        args.state_dir.as_deref(),
        args.participant.as_deref(),
    )?;
    let tpl_filter = args
        .template
        .as_deref()
        .map(TemplateFilterSpec::parse)
        .transpose()?;
    let start_offset = match args.from {
        Some(off) => off,
        None => fetch_ledger_end(&ep)?,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(watch_updates_ws(
        &ep,
        &args.party,
        tpl_filter.as_ref(),
        start_offset,
        args.format,
    ))
}

fn ws_handshake_key() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = u128::from(WS_NONCE.fetch_add(1, Ordering::Relaxed));
    let pid = u128::from(std::process::id());
    let mix = nanos ^ (seq << 32) ^ (pid << 64);
    encode_base64(&mix.to_le_bytes())
}

fn ws_mask_key() -> [u8; 4] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let seq = WS_NONCE.fetch_add(1, Ordering::Relaxed) as u32;
    (nanos ^ seq.rotate_left(13) ^ std::process::id()).to_le_bytes()
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

enum WsFrame {
    Text { fin: bool, payload: Vec<u8> },
    Cont { fin: bool, payload: Vec<u8> },
    Ping(Vec<u8>),
    Pong,
    Close,
}

struct WsClient {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl WsClient {
    async fn connect(host: &str, port: u16, path: &str) -> Result<Self, String> {
        let mut stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| format!("cannot connect WebSocket to {host}:{port}: {e}"))?;
        let key = ws_handshake_key();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("WebSocket handshake write error: {e}"))?;
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 2048];
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos;
            }
            if buf.len() > 32 * 1024 {
                return Err("WebSocket handshake headers too large".to_string());
            }
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| format!("WebSocket handshake read error: {e}"))?;
            if n == 0 {
                return Err("WebSocket closed before 101 Switching Protocols".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..header_end]);
        let status_code = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        if status_code != "101" {
            return Err(format!(
                "WebSocket upgrade rejected (HTTP {status_code}): {}",
                head.lines().next().unwrap_or("")
            ));
        }
        let leftover = buf.split_off(header_end + 4);
        Ok(Self {
            stream,
            buf: leftover,
        })
    }

    async fn read_exact(&mut self, len: usize) -> io::Result<Option<Vec<u8>>> {
        while self.buf.len() < len {
            let mut tmp = [0u8; 4096];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated WebSocket frame",
                    ))
                };
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        let rest = self.buf.split_off(len);
        let taken = std::mem::replace(&mut self.buf, rest);
        Ok(Some(taken))
    }

    async fn read_frame(&mut self) -> io::Result<Option<WsFrame>> {
        let Some(head) = self.read_exact(2).await? else {
            return Ok(None);
        };
        let fin = (head[0] & 0x80) != 0;
        let opcode = head[0] & 0x0f;
        let masked = (head[1] & 0x80) != 0;
        let len7 = head[1] & 0x7f;
        let len = match len7 {
            0..=125 => usize::from(len7),
            126 => {
                let ext = self.read_exact(2).await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated len16")
                })?;
                usize::from(u16::from_be_bytes([ext[0], ext[1]]))
            }
            _ => {
                let ext = self.read_exact(8).await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "truncated len64")
                })?;
                let raw = u64::from_be_bytes([
                    ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
                ]);
                usize::try_from(raw).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "WebSocket frame too large")
                })?
            }
        };
        if len > MAX_WS_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket payload exceeded max frame size",
            ));
        }
        let mask = if masked {
            let m = self
                .read_exact(4)
                .await?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated mask"))?;
            Some([m[0], m[1], m[2], m[3]])
        } else {
            None
        };
        let mut payload = if len == 0 {
            Vec::new()
        } else {
            self.read_exact(len)
                .await?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated payload"))?
        };
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        let frame = match opcode {
            0x01 | 0x02 => WsFrame::Text { fin, payload },
            0x00 => WsFrame::Cont { fin, payload },
            0x08 => WsFrame::Close,
            0x09 => WsFrame::Ping(payload),
            0x0a => WsFrame::Pong,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported WebSocket opcode {opcode:#x}"),
                ));
            }
        };
        Ok(Some(frame))
    }

    async fn read_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut acc = Vec::new();
        let mut in_fragment = false;
        loop {
            match self.read_frame().await? {
                None | Some(WsFrame::Close) => return Ok(None),
                Some(WsFrame::Pong) => {}
                Some(WsFrame::Ping(data)) => {
                    self.write_masked_frame(0x8a, &data).await?;
                }
                Some(WsFrame::Text { fin, payload }) => {
                    if in_fragment {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected data frame while fragmented",
                        ));
                    }
                    acc.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(acc));
                    }
                    in_fragment = true;
                }
                Some(WsFrame::Cont { fin, payload }) => {
                    if !in_fragment || acc.len() + payload.len() > MAX_WS_FRAME_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid WebSocket continuation frame",
                        ));
                    }
                    acc.extend_from_slice(&payload);
                    if fin {
                        return Ok(Some(acc));
                    }
                }
            }
        }
    }

    async fn write_masked_frame(&mut self, first_byte: u8, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(first_byte);
        if payload.len() < 126 {
            out.push(0x80 | (payload.len() as u8));
        } else if payload.len() <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        let mask = ws_mask_key();
        out.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
        self.stream.write_all(&out).await?;
        self.stream.flush().await
    }

    async fn close_and_drain(mut self) {
        let mut close_payload = Vec::with_capacity(5);
        close_payload.extend_from_slice(&1000u16.to_be_bytes());
        close_payload.extend_from_slice(b"bye");
        let _ = self.write_masked_frame(0x88, &close_payload).await;
        let _ = tokio::time::timeout(Duration::from_millis(WS_CLOSE_DRAIN_MS), async {
            while let Ok(Some(frame)) = self.read_frame().await {
                if matches!(frame, WsFrame::Close) {
                    break;
                }
            }
        })
        .await;
        let _ = self.stream.shutdown().await;
    }
}

pub(super) async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn watch_updates_ws(
    ep: &EndpointTarget,
    party: &str,
    tpl_filter: Option<&TemplateFilterSpec>,
    start_offset: u64,
    format: StatusFormatArg,
) -> Result<(), String> {
    let mut ws = WsClient::connect(&ep.host, ep.port, "/v2/updates").await?;
    let init_req = json!({
        "beginExclusive": start_offset,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": build_event_format(party, tpl_filter, &[]),
                "transactionShape": "TRANSACTION_SHAPE_ACS_DELTA"
            }
        }
    });
    let init_bytes = serde_json::to_vec(&init_req).map_err(|e| e.to_string())?;
    ws.write_masked_frame(0x81, &init_bytes)
        .await
        .map_err(|e| format!("failed to send watch subscription frame: {e}"))?;

    loop {
        tokio::select! {
            _ = wait_shutdown_signal() => {
                ws.close_and_drain().await;
                return Ok(());
            }
            msg = ws.read_message() => {
                match msg {
                    Ok(Some(bytes)) => {
                        if bytes.is_empty() {
                            continue;
                        }
                        let msg_json: Json = serde_json::from_slice(&bytes)
                            .map_err(|e| format!("invalid JSON frame on /v2/updates: {e}"))?;
                        if let Some(err_code) = msg_json.get("code").and_then(Json::as_str) {
                            let cause = msg_json.get("cause").and_then(Json::as_str).unwrap_or("");
                            ws.close_and_drain().await;
                            return Err(format!("stream error {err_code}: {cause}"));
                        }
                        emit_watch_update(&msg_json, tpl_filter, format)?;
                    }
                    Ok(None) => {
                        let _ = ws.stream.shutdown().await;
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = ws.stream.shutdown().await;
                        return Err(format!("WebSocket read error: {e}"));
                    }
                }
            }
        }
    }
}

fn emit_watch_update(
    update_json: &Json,
    tpl_filter: Option<&TemplateFilterSpec>,
    format: StatusFormatArg,
) -> Result<(), String> {
    let Some(events) = update_json
        .pointer("/update/Transaction/value/events")
        .or_else(|| update_json.pointer("/transaction/events"))
        .and_then(Json::as_array)
    else {
        return Ok(());
    };
    let mut stdout = io::stdout().lock();
    for ev in events {
        if let Some(ce) = ev.get("CreatedEvent") {
            if let Some(flt) = tpl_filter {
                if !flt.matches_event(ce) {
                    continue;
                }
            }
            let cid = ce.get("contractId").and_then(Json::as_str).unwrap_or("");
            let tpl = canonical_template_string(ce.get("templateId"));
            let off = parse_u64_json(ce.get("offset")).unwrap_or(0);
            match format {
                StatusFormatArg::Text => {
                    writeln!(
                        stdout,
                        "+ {cid} {tpl} offset={off} signatories={} observers={}",
                        ce.get("signatories").unwrap_or(&json!([])),
                        ce.get("observers").unwrap_or(&json!([]))
                    )
                    .map_err(|e| e.to_string())?;
                }
                StatusFormatArg::Json => {
                    let row = json!({
                        "op": "+",
                        "contractId": cid,
                        "templateId": tpl,
                        "offset": off,
                        "createdEvent": ce,
                    });
                    writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string(&row).map_err(|e| e.to_string())?
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        } else if let Some(ae) = ev.get("ArchivedEvent") {
            if let Some(flt) = tpl_filter {
                if !flt.matches_event(ae) {
                    continue;
                }
            }
            let cid = ae.get("contractId").and_then(Json::as_str).unwrap_or("");
            let tpl = canonical_template_string(ae.get("templateId"));
            let off = parse_u64_json(ae.get("offset")).unwrap_or(0);
            match format {
                StatusFormatArg::Text => {
                    writeln!(stdout, "- {cid} {tpl} offset={off}").map_err(|e| e.to_string())?;
                }
                StatusFormatArg::Json => {
                    let row = json!({
                        "op": "-",
                        "contractId": cid,
                        "templateId": tpl,
                        "offset": off,
                        "archivedEvent": ae,
                    });
                    writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string(&row).map_err(|e| e.to_string())?
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    stdout.flush().map_err(|e| e.to_string())
}

fn event_inner_and_kind(ev: &Json) -> Option<(&'static str, &Json)> {
    if let Some(ce) = ev.get("CreatedEvent") {
        Some(("CreatedEvent", ce))
    } else if let Some(ee) = ev.get("ExercisedEvent") {
        Some(("ExercisedEvent", ee))
    } else if let Some(ae) = ev.get("ArchivedEvent") {
        Some(("ArchivedEvent", ae))
    } else {
        None
    }
}

fn cmd_tx_ls(args: TxLsArgs) -> Result<(), String> {
    let ep = resolve_endpoint(
        args.url.as_deref(),
        args.name.as_deref(),
        args.state_dir.as_deref(),
        args.participant.as_deref(),
    )?;
    let tpl_filter = args
        .template
        .as_deref()
        .map(TemplateFilterSpec::parse)
        .transpose()?;
    let end_off = match args.to {
        Some(off) => off,
        None => fetch_ledger_end(&ep)?,
    };
    let begin_off = args.from.unwrap_or(0);

    let mut rows: Vec<Json> = Vec::new();
    if begin_off < end_off {
        let req = json!({
            "beginExclusive": begin_off,
            "endInclusive": end_off,
            "updateFormat": {
                "includeTransactions": {
                    "eventFormat": build_event_format(&args.party, tpl_filter.as_ref(), &[]),
                    "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
                }
            }
        });
        let (status, resp) =
            json_http::call_json(&ep.host, ep.port, "POST", "/v2/updates", Some(&req))?;
        if status != 200 {
            return Err(format!(
                "POST {}/v2/updates failed ({status}): {}",
                ep.base_url,
                json_http::error_cause(&resp)
            ));
        }
        let items = resp
            .as_array()
            .ok_or_else(|| format!("expected array from /v2/updates, got {resp}"))?;
        for item in items {
            let Some(tx) = item
                .pointer("/update/Transaction/value")
                .or_else(|| item.get("transaction"))
            else {
                continue;
            };
            let Some(events) = tx.get("events").and_then(Json::as_array) else {
                continue;
            };
            let mut matched = 0usize;
            let mut templates = BTreeSet::new();
            for ev in events {
                let Some((_, body)) = event_inner_and_kind(ev) else {
                    continue;
                };
                if let Some(ref flt) = tpl_filter {
                    if !flt.matches_event(body) {
                        continue;
                    }
                }
                matched += 1;
                templates.insert(canonical_template_string(body.get("templateId")));
            }
            if matched == 0 {
                continue;
            }
            rows.push(json!({
                "offset": parse_u64_json(tx.get("offset")).unwrap_or(0),
                "updateId": tx.get("updateId").and_then(Json::as_str).unwrap_or_default(),
                "commandId": tx.get("commandId").and_then(Json::as_str).unwrap_or_default(),
                "eventCount": matched,
                "templates": templates.into_iter().collect::<Vec<_>>(),
            }));
        }
    }

    match args.format {
        StatusFormatArg::Json => {
            let doc = json!({
                "party": args.party,
                "from": begin_off,
                "to": end_off,
                "updates": rows,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            for r in &rows {
                let off = r["offset"].as_u64().unwrap_or(0);
                let uid = r["updateId"].as_str().unwrap_or("");
                let cid = r["commandId"].as_str().unwrap_or("");
                let cnt = r["eventCount"].as_u64().unwrap_or(0);
                let tpls = &r["templates"];
                println!("{off}\t{uid}\tcommand={cid}\tevents={cnt}\ttemplates={tpls}");
            }
        }
    }
    Ok(())
}

fn render_replay_tree(events: &[Json]) {
    let mut stack: Vec<u64> = Vec::new();
    for ev in events {
        let Some((kind, body)) = event_inner_and_kind(ev) else {
            continue;
        };
        let node_id = parse_u64_json(body.get("nodeId")).unwrap_or(0);
        while let Some(&last_desc) = stack.last() {
            if node_id <= last_desc {
                break;
            }
            stack.pop();
        }
        let indent = "  ".repeat(stack.len());
        let cid = body
            .get("contractId")
            .and_then(Json::as_str)
            .unwrap_or_default();
        let tpl = canonical_template_string(body.get("templateId"));
        match kind {
            "CreatedEvent" => {
                println!(
                    "{indent}+ Created node={node_id} cid={cid} template={tpl} witnesses={}",
                    body.get("witnessParties").unwrap_or(&json!([]))
                );
            }
            "ExercisedEvent" => {
                let choice = body.get("choice").and_then(Json::as_str).unwrap_or("");
                let consuming = body
                    .get("consuming")
                    .and_then(Json::as_bool)
                    .unwrap_or(false);
                println!(
                    "{indent}> Exercised node={node_id} choice={choice} consuming={consuming} cid={cid} template={tpl} witnesses={}",
                    body.get("witnessParties").unwrap_or(&json!([]))
                );
                let last_desc = parse_u64_json(body.get("lastDescendantNodeId")).unwrap_or(node_id);
                if last_desc > node_id {
                    stack.push(last_desc);
                }
            }
            _ => {
                println!(
                    "{indent}- Archived node={node_id} cid={cid} template={tpl} witnesses={}",
                    body.get("witnessParties").unwrap_or(&json!([]))
                );
            }
        }
    }
}

fn cmd_tx_replay(args: TxReplayArgs) -> Result<(), String> {
    let ep = resolve_endpoint(
        args.url.as_deref(),
        args.name.as_deref(),
        args.state_dir.as_deref(),
        args.participant.as_deref(),
    )?;
    let req = json!({
        "updateId": args.id,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": build_event_format(&args.party, None, &args.interface),
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS"
            }
        }
    });
    let (status, resp) = json_http::call_json(
        &ep.host,
        ep.port,
        "POST",
        "/v2/updates/update-by-id",
        Some(&req),
    )?;
    let doc = if status == 404 {
        json!({
            "visible": false,
            "party": args.party,
            "updateId": args.id,
            "update": Json::Null,
            "events": [],
        })
    } else if status == 200 {
        let tx = resp
            .pointer("/update/Transaction/value")
            .or_else(|| resp.get("transaction"))
            .cloned()
            .unwrap_or(Json::Null);
        let events = tx
            .get("events")
            .and_then(Json::as_array)
            .cloned()
            .unwrap_or_default();
        json!({
            "visible": !events.is_empty(),
            "party": args.party,
            "updateId": args.id,
            "update": tx,
            "events": events,
        })
    } else {
        return Err(format!(
            "POST {}/v2/updates/update-by-id failed ({status}): {}",
            ep.base_url,
            json_http::error_cause(&resp)
        ));
    };

    match args.format {
        StatusFormatArg::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            if doc.get("visible").and_then(Json::as_bool) != Some(true) {
                println!("update {} not visible to party {}", args.id, args.party);
            } else if let Some(events) = doc.get("events").and_then(Json::as_array) {
                render_replay_tree(events);
            }
        }
    }
    Ok(())
}

fn read_capture_file(path: &Path, label: &str) -> Result<ScenarioCapture, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        exit_with_message(
            EXIT_PREFLIGHT,
            format!("cannot read {label} capture {}: {e}", path.display()),
        )
    })?;
    serde_json::from_str::<ScenarioCapture>(&raw).map_err(|e| {
        exit_with_message(
            EXIT_PREFLIGHT,
            format!("invalid {label} capture JSON {}: {e}", path.display()),
        )
    })
}

fn cmd_tx_diff(args: TxDiffArgs) -> Result<(), String> {
    let left = read_capture_file(&args.left, "left")?;
    let right = read_capture_file(&args.right, "right")?;

    let l_norm = normalize_capture(&left)?;
    let r_norm = normalize_capture(&right)?;
    let mut witness_violations = check_witness_invariants(&l_norm);
    witness_violations.extend(
        check_witness_invariants(&r_norm)
            .into_iter()
            .map(|v| format!("right: {v}")),
    );
    let diffs: Vec<DiffEntry> = diff_captures(&left, &right)?;

    let ok = diffs.is_empty() && witness_violations.is_empty();
    match args.format {
        StatusFormatArg::Json => {
            let doc = json!({
                "scenario": left.scenario,
                "equal": ok,
                "diffs": diffs,
                "witnessViolations": witness_violations,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
            );
        }
        StatusFormatArg::Text => {
            if ok {
                println!(
                    "PASS projection diff clean for scenario '{}' ({} steps)",
                    left.scenario,
                    l_norm.steps.len()
                );
            } else {
                for v in &witness_violations {
                    println!("WITNESS {v}");
                }
                for d in &diffs {
                    println!(
                        "DIFF step={} party={} path={} left={} right={}",
                        d.step, d.party, d.path, d.left, d.right
                    );
                }
            }
        }
    }

    if !ok {
        return Err(exit_with_message(
            EXIT_MISMATCH,
            format!(
                "projection mismatch for '{}': {} diff(s), {} witness violation(s)",
                left.scenario,
                diffs.len(),
                witness_violations.len()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_and_rejects_invalid_template_filters() {
        assert_eq!(
            TemplateFilterSpec::parse("#events-oracle:Events:Box").expect("pkg name"),
            TemplateFilterSpec::ByPkgName {
                pkg_name: "events-oracle".into(),
                module_entity: "Events:Box".into(),
            }
        );
        assert_eq!(
            TemplateFilterSpec::parse("deadbeef:Splice.Amulet:Amulet").expect("pkg id"),
            TemplateFilterSpec::ByPkgId {
                pkg_id: "deadbeef".into(),
                module_entity: "Splice.Amulet:Amulet".into(),
            }
        );
        for bad in [
            "",
            "#:Events:Box",
            "pkg:Events",
            "pkg:Events:",
            "a b:E:B",
            "#a:b:c:d",
        ] {
            assert!(
                TemplateFilterSpec::parse(bad).is_err(),
                "expected err for {bad}"
            );
        }
    }

    #[test]
    fn parses_http_endpoints_and_rejects_https() {
        let ep = parse_http_url("http://127.0.0.1:7575/").expect("valid http");
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 7575);
        assert!(parse_http_url("https://127.0.0.1:7575").is_err());
        assert!(parse_http_url("http://").is_err());
    }
}
