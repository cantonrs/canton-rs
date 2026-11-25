//! Participant node CLI subcommand implementation (Stage 08 / Stage 15).
//!
//! [CANTON-NOTE: WHY] The in-memory `participant reassign` command is gone (S-NET-040): reassignment is done by the real protocol
//! (`reassignment_wire`, `reassignment_receive`, `reassignment_submit`), checked by `scripts/verify-rust-reassignment.sh`.

use std::path::Path;

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct ParticipantArgs {
    #[command(subcommand)]
    pub action: Option<ParticipantAction>,

    /// Path to node configuration file.
    #[arg(short, long)]
    pub config: Option<String>,

    /// Path to Daml DAR archive to pre-load.
    #[arg(long)]
    pub dar: Option<String>,

    /// Bind port for Ledger API.
    #[arg(short, long, default_value_t = 5011)]
    pub port: u16,
}

#[derive(Subcommand, Debug)]
pub enum ParticipantAction {
    /// Start and run the Canton Participant node.
    Run(Box<ParticipantRunArgs>),
    /// Query status, loaded packages, and connected synchronizer domains of the Participant node.
    Status(ParticipantStatusArgs),
}

#[derive(Args, Debug)]
pub struct ParticipantRunArgs {
    /// Participant identifier.
    #[arg(long, default_value = "participant1")]
    pub participant_id: String,

    /// Primary synchronizer domain identifier.
    #[arg(long, default_value = "da::default")]
    pub domain_id: String,

    /// Bind port for Ledger API.
    #[arg(short, long, default_value_t = 5011)]
    pub port: u16,

    /// Optional DAR archive to load on startup.
    #[arg(long)]
    pub dar: Option<String>,

    /// Join the synchronizer whose sequencer is at this URL and serve the Ledger API (JSON API v2 over HTTP) on `--port` with this participant
    /// behind it: every transaction is judged by the protocol (views, sequencer, mediator) before it is applied. Needs `--dar`.
    #[arg(long)]
    pub sequencer: Option<String>,

    /// More synchronizers for the same participant, each `<alias>=<sequencer url>` (repeatable; reassignment between them, S-NET-040).
    #[arg(long = "also-sequencer", value_name = "ALIAS=URL")]
    pub also_sequencer: Vec<String>,

    /// The alias of the synchronizer of `--sequencer` when `--also-sequencer` is used.
    #[arg(long, default_value = "sync0")]
    pub sequencer_alias: String,

    /// The package name of the DAR (what a contract's hash is computed with), for `--sequencer`;
    /// defaults to the loaded DAR's package name.
    #[arg(long)]
    pub package_name: Option<String>,

    /// With `--sequencer`: keep the participant in this directory (its identity, contracts and where it stopped reading); started again with the
    /// same directory it is the same participant and continues.
    #[arg(long, conflicts_with = "state_pg_url")]
    pub state_dir: Option<std::path::PathBuf>,

    /// With `--sequencer`: keep the participant in PostgreSQL instead (a libpq-style URL; prefer the environment variable `CANTON_RS_STATE_PG_URL`).
    #[arg(long, env = "CANTON_RS_STATE_PG_URL")]
    pub state_pg_url: Option<String>,

    /// The name of the participant's state inside the database (default: `--participant-id`).
    #[arg(long)]
    pub state_name: Option<String>,

    /// Writes every transaction this participant commits to this file as a scan update item (`canton-rs scan serve --history <file>`).
    #[arg(long)]
    pub scan_history: Option<std::path::PathBuf>,

    /// Optional JSONL output sink for in-process `CantonExEx` post-commit execution extension notifications.
    #[arg(long)]
    pub exex_jsonl: Option<std::path::PathBuf>,

    /// Optional repeatable party filter scoping `--exex-jsonl` exclusively to authorized stakeholder events.
    #[arg(long = "exex-party")]
    pub exex_parties: Vec<String>,

    /// Redact contract payload arguments in `--exex-jsonl` (`ZeroPayloadMetadata` mode).
    #[arg(long, default_value_t = false)]
    pub exex_zero_payload: bool,
}

#[derive(Args, Debug)]
pub struct ParticipantStatusArgs {
    #[arg(short, long, default_value_t = 5011)]
    pub port: u16,

    #[arg(long, default_value = "participant1")]
    pub participant_id: String,
}

pub fn execute_participant(args: ParticipantArgs) -> Result<(), String> {
    match args.action {
        None => {
            println!("Canton Participant Node (Stage 08/11/15)");
            println!("Ledger API Port: {}", args.port);
            if let Some(dar) = &args.dar {
                let archive = lf_archive::parse_dar_file(Path::new(dar))
                    .map_err(|e| format!("Failed to load DAR '{dar}': {e}"))?;
                println!("Pre-loading DAR: {}", dar);
                println!("Main Package ID: {}", archive.main_package_id);
                println!("DALF Count:      {}", archive.dalfs.len());
            }
            println!("Nothing is running: `participant run --sequencer <url> --dar <dar>` starts a participant.");
            Ok(())
        }
        Some(ParticipantAction::Run(run_args)) if run_args.sequencer.is_some() => {
            // [CANTON-NOTE: SEMANTICS] A participant that serves: it registers with the synchronizer, hosts the parties its clients allocate and
            // answers the Ledger API until the process is stopped. The earlier `run` below only printed a status and exited.
            let dar = run_args
                .dar
                .as_ref()
                .ok_or("--sequencer needs --dar: the participant runs the package of the DAR")?;
            ledger_json_api::cli::serve(ledger_json_api::cli::ServeArgs {
                host: "127.0.0.1".into(),
                port: run_args.port,
                jwt_hmac_secret: None,
                jwt_hmac_secret_file: None,
                auth_cert: None,
                jwt_audience: None,
                jwt_audience_self: false,
                participant_id_file: None,
                jwt_max_lifetime_seconds: None,
                traffic_enforcement: false,
                http_list_max_elements_limit: None,
                official_pg_url: None,
                canton_conf: None,
                conf_participant: None,
                official_pg_addr: None,
                conf_port: false,
                conf_port_offset: 0,
                conf_auth_cert: None,
                dar: Some(std::path::PathBuf::from(dar)),
                store: None,
                pg_url: None,
                max_dedup_seconds: None,
                ledger: "default".into(),
                snapshot_every: 0,
                sequencer: run_args.sequencer.clone(),
                also_sequencer: run_args.also_sequencer.clone(),
                sequencer_alias: run_args.sequencer_alias.clone(),
                participant_name: run_args.participant_id.clone(),
                package_name: run_args.package_name.clone(),
                state_dir: run_args.state_dir.clone(),
                state_pg_url: run_args.state_pg_url.clone(),
                state_name: run_args.state_name.clone(),
                scan_history: run_args.scan_history.clone(),
                scan_synchronizer_id: "canton-rs::synchronizer".into(),
                official_write: false,
                official_topology_url: Vec::new(),
                log_encoder: ledger_json_api::canton_log::LogEncoder::Text,
                host_adopted_parties: false,
                grpc_port: None,
                with_grpc: false,
                admin_port: None,
                with_admin_api: false,
                grpc_server: None,
                admin_server: None,
                exex_jsonl: run_args.exex_jsonl.clone(),
                exex_parties: run_args.exex_parties.clone(),
                exex_zero_payload: run_args.exex_zero_payload,
                exex_from_offset: None,
                xray: false,
                on_banner: Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
                    |line| println!("{line}"),
                ))),
                on_warning: Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
                    |line| eprintln!("{line}"),
                ))),
            })
        }
        // [CANTON-NOTE: WHY] A participant is one that joined a synchronizer. The earlier `run` without `--sequencer` made a key from the
        // participant's name (an in-memory model), printed an "ONLINE (Ready)" banner and exited without serving anything.
        Some(ParticipantAction::Run(_)) => Err(
            "participant run needs --sequencer <url> (and --dar): the participant joins that synchronizer and serves the Ledger API"
                .into(),
        ),
        Some(ParticipantAction::Status(status_args)) => {
            let (host, port) = ("127.0.0.1", status_args.port);
            // `/v2/version` is answered without a token
            let (status, _) = super::json_http::call_json(host, port, "GET", "/v2/version", None)
                .map_err(|e| format!("no participant answers at {host}:{port}: {e}"))?;
            if status != 200 {
                return Err(format!("the participant at {host}:{port} answered {status}"));
            }
            println!("Participant Node Status: ONLINE");
            println!("Ledger API Port:         {port}");
            // what the participant itself reports; one that asks for a token answers neither without it, and nothing is made up for it
            match super::json_http::call_json(host, port, "GET", "/v2/parties/participant-id", None) {
                Ok((200, body)) => println!(
                    "Participant ID:          {}",
                    body["participantId"].as_str().unwrap_or_default()
                ),
                _ => println!("Participant ID:          (not reported without a token)"),
            }
            match super::json_http::call_json(
                host,
                port,
                "GET",
                "/v2/state/connected-synchronizers",
                None,
            ) {
                Ok((200, body)) => {
                    let connected: Vec<&str> = body["connectedSynchronizers"]
                        .as_array()
                        .map(|list| {
                            list.iter()
                                .filter_map(|s| s["synchronizerId"].as_str())
                                .collect()
                        })
                        .unwrap_or_default();
                    println!("Connected Synchronizers: [{}]", connected.join(", "));
                }
                _ => println!("Connected Synchronizers: (not reported without a token)"),
            }
            Ok(())
        }
    }
}
