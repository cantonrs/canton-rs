use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "ledger-json-api",
    about = "Daml Ledger API & JSON API Server for Canton-Rust"
)]
struct Cli {
    #[command(flatten)]
    serve: ledger_json_api::cli::ServeArgs,
}

fn main() {
    let mut args = Cli::parse().serve;
    args.on_banner = Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
        |line| println!("{line}"),
    )));
    args.on_warning = Some(ledger_json_api::cli::BannerSink(std::sync::Arc::new(
        |line| eprintln!("{line}"),
    )));
    if let Err(why) = ledger_json_api::cli::serve(args) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
