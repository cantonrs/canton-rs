//! Unified Canton & Daml Ecosystem Single Executable Binary (`canton-rs`).

use clap::{Parser, Subcommand};

mod commands;
mod runtime_audit;

use commands::console::{execute_console, ConsoleArgs};
use commands::dar::{execute_dar, DarArgs};
use commands::db::{execute_db, DbArgs};
use commands::dpm::{execute_dpm, DpmArgs};
use commands::localnet::{execute_localnet, LocalnetArgs};
use commands::mediator::{execute_mediator, MediatorArgs};
use commands::participant::{execute_participant, ParticipantArgs};
use commands::pqs::{execute_pqs, PqsArgs};
use commands::scan::{execute_scan, ScanArgs};
use commands::script::{execute_script, ScriptArgs};
use commands::sequencer::{execute_sequencer, SequencerArgs};
use commands::splice::{execute_splice, SpliceArgs};

#[derive(Parser, Debug)]
#[command(
    name = "canton-rs",
    author = "Canton Rust Team",
    version,
    about = "Unified Pure Rust Canton & Daml Ecosystem CLI",
    long_about = "Single binary release for Canton distributed ledger, protocol sequencers, mediators, participant nodes, Splice native host, PostgreSQL Flyway DB takeover, DPM, Daml Script, and LocalNet."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Canton Sequencer node service and protocol transport (Stage 09).
    Sequencer(SequencerArgs),

    /// Canton Participant node service, topology, ACS commitment, and cross-domain reassignment (Stage 08/11/15).
    Participant(ParticipantArgs),

    /// Canton Mediator node service, view quorums, and BFT consensus (Stage 10/15).
    Mediator(MediatorArgs),

    /// Native Splice Service Host (SV, Validator, Wallet, Scan) & DAR execution (Stage 12).
    Splice(SpliceArgs),

    /// The Splice scan app's update history API over a history file (G8).
    Scan(ScanArgs),

    /// Pure Rust Participant Query Store (PQS) PostgreSQL projection and query commands.
    Pqs(PqsArgs),

    /// PostgreSQL Storage Engine, Flyway checksum/history compatibility, and DB Takeover (Stage 13).
    Db(DbArgs),

    /// Daml Package Manager (DPM), DAR inspector/validator, and language codegen (Stage 14).
    Dpm(DpmArgs),

    /// Checks on DAR files: `check-upgrade`, `inspect`, and `diff`.
    Dar(DarArgs),

    /// Starts the nodes of a canton.conf (the file a Canton JVM node starts from) as Rust processes, bootstrapped as the script says (U-47).
    Daemon(Box<commands::daemon::DaemonArgs>),

    /// Pure Rust Daml Script runner over compiled DAR archives (Stage 14).
    Script(ScriptArgs),

    /// In-process multi-node cluster supervisor & Zero-JVM runtime auditor (Stage 15).
    Localnet(LocalnetArgs),

    /// Interactive Canton administration console REPL and DSL evaluator (Stage 14/15).
    Console(ConsoleArgs),

    /// The JSON API (and the Ledger API v2 over HTTP) server, until stopped (G11).
    JsonApi(Box<ledger_json_api::cli::ServeArgs>),

    /// The Ledger API v2 gRPC server, until stopped (G11).
    LedgerApi(ledger_grpc_api::cli::ServeArgs),

    /// CIP-0112 Token Standard V2 CLI (`S-DX-008`).
    Token(Box<commands::token::TokenArgs>),
}

/// A sink that writes each line to stderr: how this binary shows what its library crates report (they print nothing themselves).
fn stderr_sink() -> ledger_json_api::cli::BannerSink {
    ledger_json_api::cli::BannerSink(std::sync::Arc::new(|line| eprintln!("{line}")))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Sequencer(args) => execute_sequencer(args),
        Commands::Participant(args) => execute_participant(args),
        Commands::Mediator(args) => execute_mediator(args),
        Commands::Splice(args) => execute_splice(args),
        Commands::Scan(args) => execute_scan(args),
        Commands::Pqs(args) => execute_pqs(args),
        Commands::Db(args) => execute_db(args),
        Commands::Dpm(args) => execute_dpm(args),
        Commands::Dar(args) => execute_dar(args),
        Commands::Daemon(args) => commands::daemon::run(&args),
        Commands::Script(args) => execute_script(args),
        Commands::Localnet(args) => execute_localnet(args),
        Commands::Console(args) => execute_console(args),
        Commands::JsonApi(mut args) => {
            // `--with-grpc` / `--grpc-port` / `--with-admin-api` / `--admin-port`: this program links the gRPC Ledger and Admin API servers
            args.grpc_server = Some(ledger_json_api::cli::GrpcServer(std::sync::Arc::new(
                |service, host, port| {
                    ledger_grpc_api::cli::serve_in_background(service, host, port, stderr_sink())
                },
            )));
            args.admin_server = Some(ledger_json_api::cli::AdminServer(std::sync::Arc::new(
                |service, host, port, auth| {
                    ledger_grpc_api::cli::serve_admin_in_background(
                        service,
                        host,
                        port,
                        auth,
                        stderr_sink(),
                    )
                },
            )));
            args.on_banner = Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
                |line| println!("{line}"),
            )));
            args.on_warning = Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
                |line| eprintln!("{line}"),
            )));
            ledger_json_api::cli::serve(*args)
        }
        Commands::LedgerApi(args) => ledger_grpc_api::cli::serve(args, &|line| println!("{line}")),
        Commands::Token(args) => commands::token::execute_token(*args),
    };

    if let Err(e) = result {
        let (code, msg) = commands::exit_code::decode_exit(&e);
        if let Some(m) = msg {
            eprintln!("Error executing command: {m}");
        }
        std::process::exit(code);
    }

    Ok(())
}
