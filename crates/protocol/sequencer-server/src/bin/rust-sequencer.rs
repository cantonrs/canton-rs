//! `rust-sequencer <address> [name] [state dir]`: serves the sequencer's connect API (G6, S-NET-037) until it is killed. The same server is
//! `canton-rs sequencer run` (G11); the code is [`canton_sequencer_server::cli::run`].
fn main() {
    let address: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:15993".to_string())
        .parse()
        .expect("an address such as 0.0.0.0:15993");
    let name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "rustsync".to_string());
    let state_dir = std::env::args().nth(3).map(std::path::PathBuf::from);
    if let Err(why) =
        canton_sequencer_server::cli::run(address, &name, state_dir, &|line| println!("{line}"))
    {
        eprintln!("the server stopped: {why}");
        std::process::exit(1);
    }
}
