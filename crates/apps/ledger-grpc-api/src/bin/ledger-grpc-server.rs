//! `ledger-grpc-server`: the Ledger API v2 gRPC server on its own, with an optional DAR to load.
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "ledger-grpc-server",
    about = "Ledger API v2 over gRPC for canton-rust"
)]
struct Cli {
    #[command(flatten)]
    serve: ledger_grpc_api::cli::ServeArgs,
}

fn main() {
    if let Err(why) = ledger_grpc_api::cli::serve(Cli::parse().serve, &|line| println!("{line}")) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
