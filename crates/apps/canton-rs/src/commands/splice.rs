//! Splice Native Services CLI subcommand (`canton-rs splice`) (Stage 12 / Gate G8).

use std::collections::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use canton_participant::{
    handle_splice_http, Fingerprint, GovernanceAction, Namespace, ParticipantLedgerConfig, PartyId,
    SpliceAppRuntime, SpliceBootstrapConfig, SpliceServiceHost,
};
use clap::{Args, Subcommand};
use ledger_json_api::http::{parse_http_stream, write_http_response, HttpResponse};

#[derive(Args, Debug)]
pub struct SpliceArgs {
    #[command(subcommand)]
    pub action: Option<SpliceAction>,

    /// Path to Daml DAR archive to load natively without recompilation.
    #[arg(long)]
    pub dar: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SpliceAction {
    /// Start and verify the native Splice Host (SV, Validator, Wallet, Scan).
    Run(SpliceRunArgs),
    /// Query status, thresholds, and current mining round of the Splice DSO.
    Status(SpliceStatusArgs),
    /// Execute a full Splice governance, wallet transfer, automation, and scan workflow.
    Workflow(SpliceWorkflowArgs),
    /// Serve the DAR-backed Splice 0.10.1 App Services HTTP API (SV, Validator, Wallet, Automation, Scan).
    Serve(SpliceServeArgs),
    /// Execute an end-to-end Splice 0.10.1 App Services & Automation workflow against official DARs.
    AppWorkflow(SpliceAppWorkflowArgs),
    /// Run the Splice DSO bootstrap as Ledger API commands on a participant's JSON API, so the Splice contracts live in that participant's ledger (U-25).
    BootstrapLedger(super::splice_ledger::SpliceBootstrapLedgerArgs),
}

#[derive(Args, Debug)]
pub struct SpliceRunArgs {
    /// Number of Super Validators in the DSO cluster.
    #[arg(long, default_value_t = 4)]
    pub sv_count: usize,

    /// Path to Daml DAR archive to load natively.
    #[arg(long)]
    pub dar: Option<String>,
}

#[derive(Args, Debug)]
pub struct SpliceStatusArgs {
    /// Number of Super Validators in the DSO cluster.
    #[arg(long, default_value_t = 4)]
    pub sv_count: usize,
}

#[derive(Args, Debug)]
pub struct SpliceWorkflowArgs {
    /// Path to Daml DAR archive to execute natively.
    #[arg(long, default_value = "contracts/target/sample-contract.dar")]
    pub dar: String,

    /// Number of Super Validators in the DSO cluster.
    #[arg(long, default_value_t = 4)]
    pub sv_count: usize,
}

#[derive(Args, Debug)]
pub struct SpliceServeArgs {
    /// Directory containing the official Splice DAR archives (e.g. tests/oracle/splice-dars).
    #[arg(long, default_value = "tests/oracle/splice-dars")]
    pub dar_dir: PathBuf,

    /// Host interface to bind the HTTP server to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind the HTTP server to.
    #[arg(long, default_value_t = 5020)]
    pub port: u16,

    /// Immediately bootstrap DsoRules, AmuletRules, and initial mining rounds on startup.
    #[arg(long, default_value_t = true)]
    pub bootstrap: bool,

    /// Background automation tick interval in milliseconds (0 disables automatic timer thread).
    #[arg(long, default_value_t = 0)]
    pub automation_interval_ms: u64,

    /// Require a bearer token on the wallet routes, signed HS256 with this secret (the official LocalNet's "unsafe" HMAC auth,
    /// `SPLICE_APP_UI_UNSAFE_SECRET`). Without it the wallet routes take the caller from the request and require nothing.
    #[arg(long, env = "CANTON_RS_SPLICE_AUTH_UNSAFE_SECRET")]
    pub auth_unsafe_secret: Option<String>,

    /// Keep the Splice apps' state (a journal of every state-changing call) in this directory and rebuild it from there on start.
    /// A second worker on the same directory is refused.
    #[arg(long, conflicts_with = "state_pg_url")]
    pub state_dir: Option<PathBuf>,

    /// Keep the state in PostgreSQL instead (a libpq-style URL; prefer the environment variable). A second worker on the same
    /// state name is refused by a session advisory lock.
    #[arg(long, env = "CANTON_RS_SPLICE_STATE_PG_URL")]
    pub state_pg_url: Option<String>,

    /// The name of the Splice state inside the database (one worker per name).
    #[arg(long, default_value = "splice")]
    pub state_name: String,

    /// Connect to an external participant JSON Ledger API v2 host instead of running the in-process engine.
    #[arg(long, env = "CANTON_RS_SPLICE_LEDGER_HOST")]
    pub ledger_host: Option<String>,

    /// Port of the external participant JSON Ledger API v2 server (active when `--ledger-host` is set).
    #[arg(long, env = "CANTON_RS_SPLICE_LEDGER_PORT", default_value_t = 7575)]
    pub ledger_port: u16,

    /// ParticipantAdmin Bearer token for DAR upload, party allocation, and user rights provisioning.
    #[arg(long, env = "CANTON_RS_LEDGER_TOKEN")]
    pub ledger_admin_token: Option<String>,

    /// User ID (`sub`) used when reading/submitting ledger commands on the external participant.
    #[arg(long, default_value = "ledger-api-user")]
    pub ledger_user: String,

    /// Bearer token for `--ledger-user` (falls back to `--ledger-admin-token` when omitted).
    #[arg(long, env = "CANTON_RS_LEDGER_USER_TOKEN")]
    pub ledger_user_token: Option<String>,

    /// Local/DevNet HS256 secret used to self-sign Admin (`participant_admin`) and User JWTs automatically.
    #[arg(long)]
    pub ledger_auth_unsafe_secret: Option<String>,

    /// Target synchronizer ID on the external participant (auto-detected if omitted).
    #[arg(long)]
    pub synchronizer_id: Option<String>,

    /// Optional participant `--scan-history` JSONL path to merge `.auth` contract salts from.
    #[arg(long)]
    pub scan_history: Option<PathBuf>,

    /// Override `round_tick_duration` in milliseconds when bootstrapping a fresh DSO.
    #[arg(long)]
    pub round_tick_duration_ms: Option<u64>,
}

#[derive(Args, Debug)]
pub struct SpliceAppWorkflowArgs {
    /// Directory containing the official Splice DAR archives (e.g. tests/oracle/splice-dars).
    #[arg(long, default_value = "tests/oracle/splice-dars")]
    pub dar_dir: PathBuf,
}

fn build_host(sv_count: usize) -> Result<(SpliceServiceHost, Vec<PartyId>), String> {
    let ns = Namespace::new(Fingerprint::new(
        "1220abcd00001111222233334444555566667777888899990000111122223333",
    ));
    let dso = PartyId::new("DSO", ns.clone());
    let mut svs = Vec::new();
    for i in 1..=sv_count {
        svs.push(PartyId::new(format!("SV{i}"), ns.clone()));
    }
    let host = SpliceServiceHost::new(dso, svs.clone()).map_err(|e| e.to_string())?;
    Ok((host, svs))
}

pub fn execute_splice(args: SpliceArgs) -> Result<(), String> {
    match args.action {
        None => {
            let (mut host, _) = build_host(4)?;
            if let Some(dar) = &args.dar {
                let pkg_id = host.load_native_dar(dar).map_err(|e| e.to_string())?;
                println!("Loaded Native DAR Package ID: {}", pkg_id);
            }
            println!("Canton Splice Native Services Host (Stage 12 / Gate G8)");
            println!("Roles: SV, Validator, Wallet, Scan");
            println!("Status: READY");
            Ok(())
        }
        Some(SpliceAction::Run(run_args)) => {
            let (mut host, _) = build_host(run_args.sv_count)?;
            let mut loaded_pkg = String::from("none");
            if let Some(dar) = &run_args.dar {
                loaded_pkg = host.load_native_dar(dar).map_err(|e| e.to_string())?;
            }
            let gov_thresh = host
                .current_governance_threshold()
                .map_err(|e| e.to_string())?;
            let bft_thresh = host.current_f_plus_one_threshold();

            println!("============================================================");
            println!(" Canton Splice Native Service Host (Pure Rust Release 2021)");
            println!("============================================================");
            println!(" DSO Party:            {}", host.dso_party);
            println!(" Super Validators:     {}", run_args.sv_count);
            println!(" Governance Threshold: {}", gov_thresh);
            println!(" Scan BFT (f+1):       {}", bft_thresh);
            println!(" Active Mining Round:  {}", host.current_round.round_number);
            println!(" Native DAR Package:   {}", loaded_pkg);
            println!(" Splice Host Status:   ONLINE (Ready)");
            println!("============================================================");
            Ok(())
        }
        Some(SpliceAction::Status(s_args)) => {
            let (host, _) = build_host(s_args.sv_count)?;
            let gov_thresh = host
                .current_governance_threshold()
                .map_err(|e| e.to_string())?;
            let bft_thresh = host.current_f_plus_one_threshold();
            println!("Splice Service Status: ONLINE");
            println!("Super Validators:      {}", s_args.sv_count);
            println!("Governance Threshold:  {}", gov_thresh);
            println!("Scan BFT Quorum (f+1): {}", bft_thresh);
            println!("Mining Round:          {}", host.current_round.round_number);
            Ok(())
        }
        Some(SpliceAction::Workflow(w_args)) => {
            let (mut host, svs) = build_host(w_args.sv_count)?;
            let pkg_id = host
                .load_native_dar(&w_args.dar)
                .map_err(|e| e.to_string())?;

            let ns = svs[0].namespace.clone();
            let validator1 = PartyId::new("Validator1", ns.clone());
            let alice = PartyId::new("Alice", ns.clone());
            let bob = PartyId::new("Bob", ns);

            host.onboard_validator(validator1.clone());

            // 1. Governance vote to advance round to 2
            host.create_governance_proposal(
                "prop-r2",
                svs[0].clone(),
                GovernanceAction::AdvanceMiningRound { next_round: 2 },
            )
            .map_err(|e| e.to_string())?;
            for sv in svs.iter().skip(1) {
                let p = host
                    .cast_governance_vote("prop-r2", sv.clone(), true)
                    .map_err(|e| e.to_string())?;
                if p.executed {
                    break;
                }
            }

            // 2. Validator reward automation job
            host.run_reward_collection_job("job-val1-r2", validator1.clone(), 500, false)
                .map_err(|e| e.to_string())?;

            // 3. Wallet tap and transfer
            host.wallet_tap("tap-alice-1", alice.clone(), 10_000)
                .map_err(|e| e.to_string())?;
            let xfer = host
                .wallet_transfer("xfer-alice-bob-1", alice.clone(), bob.clone(), 2_500)
                .map_err(|e| e.to_string())?;

            // 4. Scan pagination query
            let scan_page = host
                .scan_transactions(None, 10)
                .map_err(|e| e.to_string())?;

            println!("============================================================");
            println!(" Splice Native DAR Execution & Workflow Complete (Stage 12)");
            println!("============================================================");
            println!(" Native DAR Package:   {}", pkg_id);
            println!(" Current Mining Round: {}", host.current_round.round_number);
            println!(
                " Validator1 Balance:   {} tenths",
                host.wallet_balance(&validator1)
            );
            println!(
                " Alice Balance:        {} tenths",
                host.wallet_balance(&alice)
            );
            println!(
                " Bob Balance:          {} tenths",
                host.wallet_balance(&bob)
            );
            println!(" Transfer Fee Paid:    {} tenths", xfer.fee_tenths);
            println!(" Scan Total Tx Count:  {}", scan_page.total_count);
            println!(" Workflow Status:      SUCCESS");
            println!("============================================================");
            Ok(())
        }
        Some(SpliceAction::Serve(args)) => execute_serve(args),
        Some(SpliceAction::AppWorkflow(args)) => execute_app_workflow(args),
        Some(SpliceAction::BootstrapLedger(args)) => {
            super::splice_ledger::execute_bootstrap_ledger(args)
        }
    }
}

fn status_text_for(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

/// The runtime `splice serve` answers from: in memory, or journaled to a state store (S-STORE-020).
enum Served {
    Memory(Arc<Mutex<SpliceAppRuntime>>),
    Persistent(Arc<canton_participant::splice_persist::PersistentSplice>),
}

impl Served {
    fn handle(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> canton_participant::scan_api::Response {
        match self {
            Served::Memory(rt) => handle_splice_http(rt, method, path, headers, body),
            Served::Persistent(p) => p.handle_http(method, path, headers, body),
        }
    }

    fn tick(&self) {
        match self {
            Served::Memory(rt) => {
                if let Ok(mut guard) = rt.lock() {
                    let _ = guard.run_automation_tick();
                }
            }
            Served::Persistent(p) => {
                let _ = p.automation_tick();
            }
        }
    }
}

fn execute_serve(args: SpliceServeArgs) -> Result<(), String> {
    let store: Option<(
        Arc<dyn canton_participant::state_store::StateStore>,
        Option<PathBuf>,
    )> = if let Some(dir) = &args.state_dir {
        Some((
            canton_participant::state_store::FileStore::new(dir)?,
            Some(dir.clone()),
        ))
    } else if let Some(url) = &args.state_pg_url {
        Some((
            canton_participant::state_store::PgStore::connect(url, &args.state_name)
                .map_err(|e| format!("Cannot open the Splice state in PostgreSQL: {e}"))?,
            None,
        ))
    } else {
        None
    };
    let mut boot_cfg = SpliceBootstrapConfig::default();
    if let Some(ms) = args.round_tick_duration_ms {
        boot_cfg.round_tick_duration_micros = (ms as i64).saturating_mul(1_000).max(1_000);
    }
    boot_cfg.scan_url = format!("http://{}:{}", args.host, args.port);

    let ledger_cfg = args
        .ledger_host
        .as_ref()
        .map(|host| ParticipantLedgerConfig {
            host: host.clone(),
            port: args.ledger_port,
            admin_token: args.ledger_admin_token.clone(),
            user_id: args.ledger_user.clone(),
            user_token: args.ledger_user_token.clone(),
            auth_unsafe_secret: args.ledger_auth_unsafe_secret.clone(),
            synchronizer_id: args.synchronizer_id.clone(),
            scan_history_path: args.scan_history.clone(),
            ..ParticipantLedgerConfig::default()
        });

    let served = match (ledger_cfg, store) {
        (Some(lcfg), Some((store, dir_lock))) => {
            let (app, report) =
                canton_participant::splice_persist::PersistentSplice::open_participant_ledger(
                    &args.dar_dir,
                    boot_cfg,
                    lcfg,
                    store,
                    args.bootstrap,
                    dir_lock.as_deref(),
                )?;
            println!(
                "SPLICE LEDGER {}:{}, STATE {} ({} meta entries loaded{})",
                args.ledger_host.as_deref().unwrap_or_default(),
                args.ledger_port,
                app.describe(),
                report.replayed,
                if report.bootstrapped {
                    ", bootstrapped"
                } else {
                    ""
                }
            );
            Served::Persistent(Arc::new(app))
        }
        (Some(lcfg), None) => {
            let mut runtime =
                SpliceAppRuntime::from_participant_ledger(&args.dar_dir, boot_cfg, lcfg)?;
            if args.bootstrap {
                runtime.bootstrap().map_err(|e| e.to_string())?;
            }
            Served::Memory(Arc::new(Mutex::new(runtime)))
        }
        (None, Some((store, dir_lock))) => {
            let (app, report) = canton_participant::splice_persist::PersistentSplice::open(
                &args.dar_dir,
                boot_cfg,
                store,
                args.bootstrap,
                dir_lock.as_deref(),
            )?;
            println!(
                "SPLICE STATE {} ({} journal entries replayed{})",
                app.describe(),
                report.replayed,
                if report.bootstrapped {
                    ", bootstrapped"
                } else {
                    ""
                }
            );
            Served::Persistent(Arc::new(app))
        }
        (None, None) => {
            let mut runtime = SpliceAppRuntime::from_dar_dir(&args.dar_dir, boot_cfg)?;
            if args.bootstrap {
                runtime.bootstrap().map_err(|e| e.to_string())?;
            }
            Served::Memory(Arc::new(Mutex::new(runtime)))
        }
    };
    let served = Arc::new(served);

    if args.automation_interval_ms > 0 {
        let auto = Arc::clone(&served);
        let interval = Duration::from_millis(args.automation_interval_ms);
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            auto.tick();
        });
    }

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    println!(
        "SPLICE APPS listening on {}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let secret = Arc::new(args.auth_unsafe_secret);
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let served = Arc::clone(&served);
        let secret = Arc::clone(&secret);
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let Ok(request) = parse_http_stream(&mut stream) else {
                return;
            };
            let raw_path = if request.query_params.is_empty() {
                request.path.clone()
            } else {
                let qs: Vec<String> = request
                    .query_params
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                format!("{}?{}", request.path, qs.join("&"))
            };
            let req_headers: Vec<(String, String)> = request
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let host = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let mut headers = HashMap::new();
            let answer = match wallet_auth_refusal(secret.as_deref(), &request.path, &req_headers) {
                Some(why) => {
                    headers.insert(
                        "WWW-Authenticate".to_string(),
                        "Bearer realm=\"splice wallet realm\"".to_string(),
                    );
                    canton_participant::scan_api::Response {
                        status: 401,
                        content_type: "text/plain; charset=UTF-8",
                        body: why.to_string(),
                    }
                }
                None => official_not_found(
                    served.handle(&request.method, &raw_path, &req_headers, &request.body),
                    &host,
                    &raw_path,
                ),
            };
            headers.insert("Content-Type".to_string(), answer.content_type.to_string());
            headers.insert("Content-Length".to_string(), answer.body.len().to_string());
            headers.insert("Connection".to_string(), "close".to_string());
            let response = HttpResponse {
                status: answer.status,
                status_text: status_text_for(answer.status).to_string(),
                headers,
                body: answer.body.into_bytes(),
            };
            let _ = write_http_response(&mut stream, &response);
        });
    }
    Ok(())
}

/// Why the wallet routes refuse a request with `secret` configured, as the official validator app words it (its HTTP server's rejection,
/// `text/plain`, with `WWW-Authenticate: Bearer realm="splice wallet realm"`), or `None` when the request may go on.
///
/// [CANTON-NOTE: SEMANTICS] Measured on the official Splice 0.10.1 LocalNet (S-G11-001, A5): a wallet call without a token is `401 The
/// resource requires authentication, which was not supplied with the request`, one whose HS256 signature does not verify with the secret
/// is `401 The supplied authentication is invalid`. The token's subject is the wallet user.
fn wallet_auth_refusal(
    secret: Option<&str>,
    path: &str,
    headers: &[(String, String)],
) -> Option<&'static str> {
    let secret = secret?;
    if !path.contains("/v0/wallet/") {
        return None;
    }
    let Some(token) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .and_then(|(_, v)| v.trim().strip_prefix("Bearer ").map(str::trim))
    else {
        return Some(
            "The resource requires authentication, which was not supplied with the request",
        );
    };
    if hs256_verifies(secret.as_bytes(), token) {
        None
    } else {
        Some("The supplied authentication is invalid")
    }
}

/// Whether `token` is a JWT whose HS256 signature verifies with `secret` and whose `exp` (if any) is in the future.
fn hs256_verifies(secret: &[u8], token: &str) -> bool {
    use hmac::{Hmac, Mac};
    let parts: Vec<&str> = token.split('.').collect();
    let [head, body, signature] = parts.as_slice() else {
        return false;
    };
    let (Some(head_json), Some(body_json), Some(signature)) =
        (base64url(head), base64url(body), base64url(signature))
    else {
        return false;
    };
    let alg = serde_json::from_slice::<serde_json::Value>(&head_json)
        .ok()
        .and_then(|h| h.get("alg").and_then(|a| a.as_str()).map(String::from));
    if alg.as_deref() != Some("HS256") {
        return false;
    }
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(format!("{head}.{body}").as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return false;
    }
    let exp = serde_json::from_slice::<serde_json::Value>(&body_json)
        .ok()
        .and_then(|b| b.get("exp").and_then(|e| e.as_i64()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    exp.is_none_or(|exp| exp > now)
}

/// Unpadded base64url.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A route nobody serves answers as the official app's HTTP server does: `404 {"error": "The requested resource could not be found:
/// <the request's URL>"}` (measured, S-G11-001 A5).
fn official_not_found(
    answer: canton_participant::scan_api::Response,
    host: &str,
    raw_path: &str,
) -> canton_participant::scan_api::Response {
    let unrouted = answer.status == 404
        && serde_json::from_str::<serde_json::Value>(&answer.body)
            .ok()
            .and_then(|b| b.get("error").and_then(|e| e.as_str()).map(String::from))
            .is_some_and(|e| e.starts_with("no route for "));
    if !unrouted {
        return answer;
    }
    canton_participant::scan_api::Response {
        status: 404,
        content_type: "application/json",
        body: serde_json::json!({
            "error": format!("The requested resource could not be found: http://{host}{raw_path}")
        })
        .to_string(),
    }
}

fn execute_app_workflow(args: SpliceAppWorkflowArgs) -> Result<(), String> {
    let mut rt = SpliceAppRuntime::from_dar_dir(&args.dar_dir, SpliceBootstrapConfig::default())?;
    let boot = rt.bootstrap().map_err(|e| e.to_string())?;

    // 1. Secret-gated validator onboarding
    let secret = rt
        .prepare_validator_onboarding(3600, Some("partner-val".into()), None)
        .map_err(|e| e.to_string())?;
    let partner_party =
        "partner-val::1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let partner_license = rt
        .onboard_validator(partner_party, &secret, "0.10.1", "ops@example.com")
        .map_err(|e| e.to_string())?;

    // 2. User onboarding & preapproval
    let alice = rt.register_user("alice", None).map_err(|e| e.to_string())?;
    let bob = rt.register_user("bob", None).map_err(|e| e.to_string())?;
    let preapproval_cid = rt
        .create_transfer_preapproval(&bob, None, 3_600_000_000)
        .map_err(|e| e.to_string())?;

    // 3. Tap + P2P TransferOffer + Automation settlement
    let _tap = rt.tap("alice", "5000.0").map_err(|e| e.to_string())?;
    let expires_at = rt.now_micros() + 3_600_000_000;
    let offer_cid = rt
        .create_transfer_offer(
            "alice",
            "bob",
            "125.0",
            "invoice-1",
            expires_at,
            "wf-xfer-1",
        )
        .map_err(|e| e.to_string())?;
    let _accepted_cid = rt
        .accept_transfer_offer("bob", &offer_cid)
        .map_err(|e| e.to_string())?;

    // 4. BuyTrafficRequest + Automation settlement
    let _traffic_req = rt
        .create_buy_traffic_request(
            "alice",
            partner_party,
            None,
            0,
            1_000_000,
            expires_at,
            "wf-traffic-1",
        )
        .map_err(|e| e.to_string())?;

    let tick1 = rt.run_automation_tick().map_err(|e| e.to_string())?;
    if !tick1.errors.is_empty()
        || tick1.transfers_completed != 1
        || tick1.traffic_requests_completed != 1
    {
        return Err(format!("automation tick 1 incomplete: {tick1:?}"));
    }
    let xfer_status = rt
        .transfer_offer_status("wf-xfer-1")
        .map_err(|e| e.to_string())?;
    let traffic_status = rt
        .buy_traffic_status("wf-traffic-1")
        .map_err(|e| e.to_string())?;

    // 5. SV governance vote + time advance + round advance
    let vote_req = rt
        .request_vote(
            None,
            serde_json::json!({
                "tag": "ARC_DsoRules",
                "value": {
                    "dsoAction": {
                        "tag": "SRARC_GrantFeaturedAppRight",
                        "value": { "provider": alice }
                    }
                }
            }),
            "https://example.org/proposal",
            "Feature Alice wallet app",
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
    let round_duration = rt.config().round_tick_duration_micros;
    rt.advance_time(round_duration + 1_000)
        .map_err(|e| e.to_string())?;
    let tick2 = rt.run_automation_tick().map_err(|e| e.to_string())?;

    // 6. Verify Scan endpoints reflect live DAR state
    let scan = rt.scan_history()?;
    let dso_resp = scan.handle("GET", "/api/scan/v0/dso", "");
    let updates_resp = scan.handle("POST", "/api/scan/v2/updates", r#"{"page_size": 100}"#);
    let alice_bal = rt.get_balance(&alice).map_err(|e| e.to_string())?;
    let bob_bal = rt.get_balance(&bob).map_err(|e| e.to_string())?;

    let summary = serde_json::json!({
        "status": "ok",
        "bootstrap": boot,
        "partner_validator_license": partner_license,
        "alice_party": alice,
        "bob_party": bob,
        "transfer_preapproval": preapproval_cid,
        "transfer_offer_status": xfer_status,
        "buy_traffic_status": traffic_status,
        "vote_request": vote_req,
        "automation_tick_1": tick1,
        "automation_tick_2": tick2,
        "alice_balance": alice_bal,
        "bob_balance": bob_bal,
        "scan_dso_status": dso_resp.status,
        "scan_updates_status": updates_resp.status,
        "total_updates": rt.updates().len(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).unwrap_or_default()
    );
    Ok(())
}
