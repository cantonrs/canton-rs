//! Canton Mediator node subcommand.

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct MediatorArgs {
    #[command(subcommand)]
    pub action: Option<MediatorAction>,

    /// Synchronizer/domain identifier.
    #[arg(long, default_value = "da::default")]
    pub synchronizer_id: String,

    /// Bind port for mediator consensus service.
    #[arg(short, long, default_value_t = 5012)]
    pub port: u16,
}

#[derive(Subcommand, Debug)]
pub enum MediatorAction {
    /// Start and run the standalone Canton Mediator node.
    Run(MediatorRunArgs),
    /// Query the health status of the Mediator node.
    Status(MediatorStatusArgs),
    /// Query the BFT consensus ordering status of the Mediator cluster.
    ConsensusStatus(MediatorConsensusStatusArgs),
    /// Make the mediator's own identity (its namespace, signing and sequencer authentication keys) in its own state, once.
    Init(MediatorInitArgs),
    /// Print what the synchronizer's operator has to authorize for this mediator and write its onboarding transactions to a file.
    Onboarding(MediatorOnboardingArgs),
}

/// Where a mediator keeps its own state: a directory, or a state in PostgreSQL.
#[derive(Args, Debug)]
pub struct MediatorStateArgs {
    /// The mediator's own state directory.
    #[arg(long, conflicts_with = "state_pg_url")]
    pub state_dir: Option<std::path::PathBuf>,

    /// The mediator's own state in PostgreSQL instead (prefer the environment variable).
    #[arg(long, env = "CANTON_RS_STATE_PG_URL")]
    pub state_pg_url: Option<String>,

    /// The name of the mediator's state inside the database.
    #[arg(long, default_value = "mediator")]
    pub state_name: String,
}

impl MediatorStateArgs {
    fn open(
        &self,
    ) -> Result<std::sync::Arc<dyn canton_participant::state_store::StateStore>, String> {
        match (&self.state_dir, &self.state_pg_url) {
            (Some(dir), _) => {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                Ok(canton_participant::state_store::FileStore::new(dir)?)
            }
            (None, Some(url)) => Ok(canton_participant::state_store::PgStore::connect_unlocked(
                url,
                &self.state_name,
            )?),
            (None, None) => Err("give the mediator's --state-dir or --state-pg-url".into()),
        }
    }
}

#[derive(Args, Debug)]
pub struct MediatorInitArgs {
    #[command(flatten)]
    pub state: MediatorStateArgs,

    /// The mediator's name: its member id is `MED::<name>::<fingerprint of its namespace key>`.
    #[arg(long, default_value = "mediator1")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct MediatorOnboardingArgs {
    #[command(flatten)]
    pub state: MediatorStateArgs,

    /// Where to write the onboarding transactions (one hex-encoded `SignedTopologyTransaction` per line).
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
pub struct MediatorRunArgs {
    /// Bind address of the health endpoint.
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,

    /// Serve a health endpoint on this port (`GET /livez`, `/readyz`, `/status`); none when left out.
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Synchronizer/domain identifier.
    #[arg(long, default_value = "da::default")]
    pub synchronizer_id: String,

    /// Mediator member identifier.
    #[arg(long, default_value = "MED::mediator1::ns1")]
    pub mediator_id: String,

    /// Sequencer connection endpoint URL.
    #[arg(long, default_value = "http://127.0.0.1:5018")]
    pub sequencer_url: String,

    /// Storage backend engine (memory or postgres connection string).
    #[arg(long, default_value = "memory")]
    pub storage: String,

    /// Optional path to Canton HOCON/YAML configuration file.
    #[arg(short, long)]
    pub config: Option<String>,

    /// Run mediator server process in background daemon mode.
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// Serve as the mediator **process** of the synchronizer whose sequencer is at `--sequencer-url`: join it as a member and judge the
    /// requests addressed to its group. A directory with the mediator's own identity (`mediator init`) is the mediator's alone: it joins as the
    /// member the synchronizer's operator authorized (`mediator onboarding`, `sequencer add-mediator`). Otherwise the directory is the Rust
    /// sequencer's state directory (where the key of the synchronizer's own mediator is kept) and the sequencer has to run with
    /// `RUST_SEQUENCER_EXTERNAL_MEDIATOR=1`.
    #[arg(long)]
    pub state_dir: Option<std::path::PathBuf>,

    /// The mediator group this mediator serves (`MGR::<group>`), with `--state-dir` or `--state-pg-url`.
    #[arg(long, default_value_t = 0)]
    pub group: u32,

    /// Serve as the mediator process with the synchronizer's state in PostgreSQL (the sequencer's `--state-pg-url`): the keys are read from the
    /// sequencer's state `--state-name` (read only), the mediator keeps its own in the state `<state-name>-mediator-<group>`.
    #[arg(long, env = "CANTON_RS_STATE_PG_URL", conflicts_with = "state_dir")]
    pub state_pg_url: Option<String>,

    /// The name of the sequencer's state inside the database.
    #[arg(long, default_value = "sequencer")]
    pub state_name: String,
}

#[derive(Args, Debug)]
pub struct MediatorStatusArgs {
    /// The status port of a running mediator process (`mediator run --port`).
    #[arg(short, long, default_value_t = 5012)]
    pub port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(long, default_value = "da::default")]
    pub synchronizer_id: String,
}

#[derive(Args, Debug)]
pub struct MediatorConsensusStatusArgs {
    #[arg(short, long, default_value_t = 5012)]
    pub port: u16,

    #[arg(long, default_value = "da::default")]
    pub synchronizer_id: String,
}

pub fn execute_mediator(args: MediatorArgs) -> Result<(), String> {
    match args.action {
        None => {
            // no status is claimed here: `mediator run` serves, `mediator status` asks a running one
            println!("Canton Mediator Node: `canton-rs mediator run` serves one, `canton-rs mediator status` asks a running one");
            Ok(())
        }
        Some(MediatorAction::Init(args)) => {
            let store = args.state.open()?;
            let identity = canton_sequencer_server::mediator_identity::MediatorIdentity::load_or_create(
                store.as_ref(),
                &args.name,
            )?;
            println!("MEDIATOR {}", identity.member());
            Ok(())
        }
        Some(MediatorAction::Onboarding(args)) => {
            let store = args.state.open()?;
            let identity = canton_sequencer_server::mediator_identity::MediatorIdentity::load(store.as_ref())?
                .ok_or("no mediator identity here: `canton-rs mediator init` makes one")?;
            let transactions = identity.onboarding_transactions();
            if let Some(out) = &args.out {
                std::fs::write(out, canton_sequencer_server::mediator_identity::onboarding_file(&transactions))
                    .map_err(|e| format!("{}: {e}", out.display()))?;
            }
            println!("Mediator:         {}", identity.member());
            println!("Namespace key:    {}", identity.namespace());
            println!("Signing key:      {} (signing, proof-of-ownership)", identity.signing_key.fingerprint);
            println!("Sequencer auth:   {} (sequencer-auth, proof-of-ownership)", identity.sequencer_auth_key.fingerprint);
            println!("The synchronizer's owners have to:");
            println!("  1. load its {} onboarding transactions into the synchronizer's store (NamespaceDelegation of {}, OwnerToKeyMapping of {}){}",
                transactions.len(), identity.namespace(), identity.member(),
                args.out.as_ref().map(|o| format!(", written to {}", o.display())).unwrap_or_default());
            println!("  2. authorize a MediatorSynchronizerState that names {} in a mediator group", identity.uid());
            println!("  e.g. canton-rs sequencer add-mediator --sequencer-url <url> --onboarding <file> --group 0");
            Ok(())
        }
        Some(MediatorAction::Run(run_args))
            if run_args.state_dir.is_some() || run_args.state_pg_url.is_some() =>
        {
            let own: Option<std::sync::Arc<dyn canton_participant::state_store::StateStore>> =
                match (&run_args.state_dir, &run_args.state_pg_url) {
                    (Some(dir), _) => {
                        let store: std::sync::Arc<dyn canton_participant::state_store::StateStore> =
                            canton_participant::state_store::FileStore::new(dir)?;
                        canton_sequencer_server::mediator_identity::MediatorIdentity::load(store.as_ref())?
                            .map(|_| store)
                    }
                    (None, Some(url)) => {
                        // looked at without the lock first: the state named may be the sequencer's, which the sequencer holds
                        let probe = canton_participant::state_store::PgStore::connect_unlocked(url, &run_args.state_name)?;
                        match canton_sequencer_server::mediator_identity::MediatorIdentity::load(probe.as_ref())? {
                            Some(_) => Some(canton_participant::state_store::PgStore::connect(url, &run_args.state_name)?
                                as std::sync::Arc<dyn canton_participant::state_store::StateStore>),
                            None => None,
                        }
                    }
                    _ => None,
                };
            let process = if let Some(own) = own {
                canton_sequencer_server::mediator_node::start_own(&run_args.sequencer_url, own)?
            } else if let Some(dir) = run_args.state_dir.as_ref() {
                canton_sequencer_server::mediator_node::start(
                    &run_args.sequencer_url,
                    dir,
                    run_args.group,
                )?
            } else {
                let url = run_args.state_pg_url.as_ref().expect("checked above");
                let keys = canton_participant::state_store::PgStore::connect_unlocked(
                    url,
                    &run_args.state_name,
                )?;
                let own = canton_participant::state_store::PgStore::connect(
                    url,
                    &format!("{}-mediator-{}", run_args.state_name, run_args.group),
                )?;
                canton_sequencer_server::mediator_node::start_with(
                    &run_args.sequencer_url,
                    keys.as_ref(),
                    own,
                    run_args.group,
                )?
            };
            if let Some(port) = run_args.port {
                serve_health(
                    &run_args.bind,
                    port,
                    process.member.to_string(),
                    process.group,
                    std::sync::Arc::clone(&process.telemetry),
                )?;
            }
            println!("READY mediator={}", process.member);
            // [CANTON-NOTE: WHY] Wait for the signal rather than sleep: a process ended by SIGTERM runs no destructors, so the loop would be
            // abandoned mid-step instead of stopped.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                use tokio::signal::unix::{signal, SignalKind};
                let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
                let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
                tokio::select! {
                    _ = term.recv() => {}
                    _ = int.recv() => {}
                }
                Ok::<(), String>(())
            })?;
            drop(process);
            Ok(())
        }
        // [CANTON-NOTE: WHY] Without a synchronizer to join this used to print an "ONLINE (Ready)" banner and exit, serving nothing.
        Some(MediatorAction::Run(_)) => Err(
            "`mediator run` serves as the mediator process of a synchronizer: give --sequencer-url and the sequencer's \
             --state-dir (the sequencer runs with RUST_SEQUENCER_EXTERNAL_MEDIATOR=1) or --state-pg-url"
                .into(),
        ),
        // [CANTON-NOTE: WHY] These used to print fixed values (ONLINE, 0 pending, a leader named MED::mediator1::ns1, quorum 2/3) for any port.
        Some(MediatorAction::Status(status_args)) => {
            let (status, body) = super::json_http::call_json(
                &status_args.host,
                status_args.port,
                "GET",
                "/status",
                None,
            )
            .map_err(|e| format!("no mediator answers at {}:{}: {e}", status_args.host, status_args.port))?;
            if status != 200 {
                return Err(format!("the mediator at {}:{} answered {status}", status_args.host, status_args.port));
            }
            println!("Mediator Node Status: ONLINE");
            println!("Member:               {}", body["member"].as_str().unwrap_or_default());
            println!("Group:                MGR::{}", body["group"]);
            Ok(())
        }
        Some(MediatorAction::ConsensusStatus(_)) => Err(
            "a Rust mediator process runs no BFT consensus of its own: the synchronizer's ordering is the sequencer's (`canton-rs sequencer run`)"
                .into(),
        ),
    }
}

/// The health and observability endpoint of a mediator process:
/// - `GET /livez` answers 200 whenever the listener accepts connections;
/// - `GET /readyz` answers 200 when connected to the sequencer, else 503 Service Unavailable;
/// - `GET /status` returns member/group/verdict/pending JSON;
/// - `GET /metrics` exposes Prometheus 0.0.4 counters & gauges.
fn serve_health(
    bind: &str,
    port: u16,
    member: String,
    group: u32,
    telemetry: std::sync::Arc<canton_sequencer_server::mediator_node::MediatorTelemetry>,
) -> Result<(), String> {
    use super::supervisor::metrics::{serve_tiny_http, TinyResponse};
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = std::net::TcpListener::bind((bind, port))
        .map_err(|e| format!("cannot listen on {bind}:{port}: {e}"))?;
    let quiesced = std::sync::Arc::new(AtomicBool::new(false));
    let json = |status: &'static str, body: String| TinyResponse {
        status,
        content_type: "application/json",
        body,
    };
    serve_tiny_http(
        listener,
        std::sync::Arc::new(AtomicBool::new(false)),
        move |path| {
            let connected = telemetry.connected.load(Ordering::Relaxed);
            let approved = telemetry.verdicts_approved.load(Ordering::Relaxed);
            let rejected = telemetry.verdicts_rejected.load(Ordering::Relaxed);
            let pending = telemetry.pending_quorums.load(Ordering::Relaxed);
            let last_error = telemetry.last_error.lock().ok().and_then(|g| g.clone());
            match path {
                "/_quiesce/pause" | "/_quiesce_pause" => {
                    quiesced.store(true, Ordering::SeqCst);
                    json(
                        "200 OK",
                        serde_json::json!({ "quiesced": true, "in_flight": pending }).to_string(),
                    )
                }
                "/_quiesce/resume" | "/_resume" => {
                    quiesced.store(false, Ordering::SeqCst);
                    json(
                        "200 OK",
                        serde_json::json!({ "quiesced": false, "in_flight": pending }).to_string(),
                    )
                }
                "/_quiesce" => json(
                    "200 OK",
                    serde_json::json!({
                        "quiesced": quiesced.load(Ordering::SeqCst),
                        "in_flight": pending
                    })
                    .to_string(),
                ),
                "/livez" => json("200 OK", "{}".to_string()),
                "/readyz" if connected => json("200 OK", r#"{"status":"ok"}"#.to_string()),
                "/readyz" => json(
                    "503 Service Unavailable",
                    serde_json::json!({
                        "status": "not_ready",
                        "reason": last_error.unwrap_or_else(|| "sequencer link disconnected".to_string())
                    })
                    .to_string(),
                ),
                "/status" => json(
                    "200 OK",
                    serde_json::json!({
                        "member": member,
                        "group": group,
                        "connected": connected,
                        "verdicts_approved": approved,
                        "verdicts_rejected": rejected,
                        "pending_quorums": pending,
                        "last_error": last_error,
                    })
                    .to_string(),
                ),
                "/metrics" => {
                    let up = u8::from(connected);
                    let m = super::supervisor::metrics::escape_label(&member);
                    TinyResponse {
                        status: "200 OK",
                        content_type: "text/plain; version=0.0.4; charset=utf-8",
                        body: format!(
                            "# HELP canton_rs_node_up Mediator /readyz readiness state\n\
                             # TYPE canton_rs_node_up gauge\n\
                             canton_rs_node_up{{synchronizer=\"default\",role=\"mediator\",node=\"{m}\"}} {up}\n\
                             # HELP canton_rs_mediator_verdicts_total Cumulative mediator verdicts\n\
                             # TYPE canton_rs_mediator_verdicts_total counter\n\
                             canton_rs_mediator_verdicts_total{{synchronizer=\"default\",node=\"{m}\",verdict=\"approve\"}} {approved}\n\
                             canton_rs_mediator_verdicts_total{{synchronizer=\"default\",node=\"{m}\",verdict=\"reject\"}} {rejected}\n\
                             # HELP canton_rs_mediator_pending_quorums Pending 2PC mediator quorums\n\
                             # TYPE canton_rs_mediator_pending_quorums gauge\n\
                             canton_rs_mediator_pending_quorums{{synchronizer=\"default\",node=\"{m}\"}} {pending}\n"
                        ),
                    }
                }
                _ => json("404 Not Found", "{}".to_string()),
            }
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    #[test]
    fn readyz_answers_while_another_client_stays_silent() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let telemetry = std::sync::Arc::new(
            canton_sequencer_server::mediator_node::MediatorTelemetry::default(),
        );
        super::serve_health("127.0.0.1", port, "MED::m1".into(), 0, telemetry).expect("serve");
        let _silent = std::net::TcpStream::connect(("127.0.0.1", port)).expect("silent");
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        s.write_all(b"GET /readyz HTTP/1.1\r\n\r\n").expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 503"), "unexpected {out:?}");
        let waited = started.elapsed();
        // The supervisor probe gives up after 2.5 s.
        assert!(
            waited < Duration::from_millis(800),
            "/readyz waited {waited:?}"
        );
    }
}
