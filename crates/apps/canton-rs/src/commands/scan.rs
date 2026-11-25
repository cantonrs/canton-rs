//! The scan app's HTTP API (G8, S-SPL-005): `canton-rs scan serve` answers the update history requests of the Splice scan app over a history
//! file, as the official Splice 0.10.1 scan app answers them (`canton_participant::scan_api`).
//!
//! The history is a file: the updates as the official scan prints them (`{"transactions": [...]}` or an array), or the JSON lines a node writes
//! with `--scan-history` (S-SPL-007). The file is re-read when it changes.
//!
//! [CANTON-NOTE: LIMITATION] Only the update history endpoints exist.
use canton_participant::scan_api::UpdateHistory;
use clap::{Args, Subcommand};
use ledger_json_api::http::{parse_http_stream, write_http_response};
use ledger_json_api::HttpResponse;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub action: ScanAction,
}

#[derive(Subcommand, Debug)]
pub enum ScanAction {
    /// Serve `/api/scan/v2/updates` and `/api/scan/v2/updates/{id}` until stopped.
    Serve(ScanServeArgs),
}

#[derive(Args, Debug)]
pub struct ScanServeArgs {
    /// The update history to answer from: a JSON file with `{"transactions": [...]}` or a plain array of updates.
    #[arg(long)]
    pub history: String,
    /// A DAR of the packages the history's contracts are of (repeat for several): the contract endpoints (`/v0/amulet-rules`, ...) encode
    /// the contracts' blobs on them. Without a DAR only the update endpoints are served.
    #[arg(long = "dar")]
    pub dars: Vec<String>,
    /// The contract salts the blobs need: a JSON object from contract id (hex) to the contract's `authentication_data` (hex), or the lines a
    /// node writes (`--scan-history <file>` makes `<file>.auth`, which is read when this option is left out and the file exists).
    #[arg(long)]
    pub contract_auth: Option<String>,
    /// `GET /v0/dso` states the scan app's SV user, SV party (default: the first SV of the DsoRules) and the first round.
    #[arg(long, default_value = "ledger-api-user")]
    pub sv_user: String,
    #[arg(long)]
    pub sv_party: Option<String>,
    #[arg(long, default_value = "0")]
    pub initial_round: String,
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// The port to listen on (the official scan app listens on 5012 inside LocalNet).
    #[arg(long, default_value_t = 5012)]
    pub port: u16,
}

/// The updates a history file holds: a JSON document (`{"transactions": [...]}` or an array), or JSON lines as a node writes them
/// (`--scan-history`, one update per line). A last line that is cut off (a writer is mid-write) is left out.
fn load(
    path: &str,
    dars: &[String],
    auth: Option<&str>,
    dso: &canton_participant::scan_api::DsoInfoConfig,
) -> Result<UpdateHistory, String> {
    // a node that has committed nothing yet has written no file: an empty history
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {path}: {e}")),
    };
    let updates: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(json) => {
            let updates = match json.get("transactions") {
                Some(t) => t.clone(),
                None => json,
            };
            updates
                .as_array()
                .ok_or_else(|| format!("{path} holds no array of updates"))?
                .clone()
        }
        Err(_) => text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect(),
    };
    let history = UpdateHistory::new(updates);
    if dars.is_empty() {
        return Ok(history);
    }
    let worlds = dars
        .iter()
        .map(|d| {
            lf_eval::World::open(std::path::Path::new(d))
                .map_err(|e| format!("cannot load {d}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut salts = HashMap::new();
    if let Some(auth) = auth {
        // a node that has not created a contract yet has written no file: no salts
        let text = std::fs::read_to_string(auth).unwrap_or_default();
        // a JSON object (contract id to salt), or the JSON lines a node writes next to its history
        let map: HashMap<String, String> = match serde_json::from_str(&text) {
            Ok(map) => map,
            Err(_) => text
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter_map(|l| {
                    Some((
                        l["contract_id"].as_str()?.to_string(),
                        l["authentication_data"].as_str()?.to_string(),
                    ))
                })
                .collect(),
        };
        for (id, hex) in map {
            let bytes = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| format!("the salt of {id} is not hex"))?;
            salts.insert(id, bytes);
        }
    }
    Ok(history
        .with_contracts(worlds, salts)?
        .with_dso_info(dso.clone()))
}

/// The history file and what was read from it last: a request re-reads the file when its size or modification time changed, so a node that
/// keeps appending to it is answered from the current history.
struct Source {
    path: String,
    dars: Vec<String>,
    auth: Option<String>,
    dso: canton_participant::scan_api::DsoInfoConfig,
    loaded: Mutex<(Stamp, Arc<UpdateHistory>)>,
}

impl Source {
    fn open(
        path: &str,
        dars: &[String],
        auth: Option<&str>,
        dso: canton_participant::scan_api::DsoInfoConfig,
    ) -> Result<Self, String> {
        let history = load(path, dars, auth, &dso)?;
        Ok(Self {
            path: path.to_string(),
            dars: dars.to_vec(),
            auth: auth.map(String::from),
            dso,
            loaded: Mutex::new((stamp(path, auth), Arc::new(history))),
        })
    }

    fn current(&self) -> Arc<UpdateHistory> {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        let now = stamp(&self.path, self.auth.as_deref());
        if now != loaded.0 {
            // a file that cannot be read right now keeps the history that was
            if let Ok(history) = load(&self.path, &self.dars, self.auth.as_deref(), &self.dso) {
                *loaded = (now, Arc::new(history));
            }
        }
        Arc::clone(&loaded.1)
    }
}

type Stamp = (
    Option<(std::time::SystemTime, u64)>,
    Option<(std::time::SystemTime, u64)>,
);

/// Size and modification time of the history file and of the salts file.
fn stamp(path: &str, auth: Option<&str>) -> Stamp {
    let one = |p: &str| {
        let meta = std::fs::metadata(p).ok()?;
        Some((meta.modified().ok()?, meta.len()))
    };
    (one(path), auth.and_then(one))
}

pub fn execute_scan(args: ScanArgs) -> Result<(), String> {
    match args.action {
        ScanAction::Serve(a) => serve(a),
    }
}

fn serve(args: ScanServeArgs) -> Result<(), String> {
    // the salts a node writes next to its history are read when the option is left out (the file may not exist yet)
    let auth = Some(
        args.contract_auth
            .clone()
            .unwrap_or_else(|| format!("{}.auth", args.history)),
    );
    let dso = canton_participant::scan_api::DsoInfoConfig {
        sv_user: args.sv_user.clone(),
        sv_party: args.sv_party.clone(),
        initial_round: args.initial_round.clone(),
    };
    let source = Arc::new(Source::open(
        &args.history,
        &args.dars,
        auth.as_deref(),
        dso,
    )?);
    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    println!(
        "SCAN listening on {}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let source = Arc::clone(&source);
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
            let Ok(request) = parse_http_stream(&mut stream) else {
                return;
            };
            let body = String::from_utf8_lossy(&request.body).to_string();
            let answer = source
                .current()
                .handle(&request.method, &request.path, &body);
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), answer.content_type.to_string());
            headers.insert("Content-Length".to_string(), answer.body.len().to_string());
            headers.insert("Connection".to_string(), "close".to_string());
            let response = HttpResponse {
                status: answer.status,
                status_text: String::new(),
                headers,
                body: answer.body.into_bytes(),
            };
            let _ = write_http_response(&mut stream, &response);
        });
    }
    Ok(())
}
