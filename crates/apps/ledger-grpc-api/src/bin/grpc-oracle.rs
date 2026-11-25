//! `grpc-oracle <host:port> <requests.tsv>`: replays the requests over gRPC and prints the records as JSON lines.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 && args.len() != 4 {
        eprintln!("usage: grpc-oracle <host:port> <requests.tsv> [tokens.json]");
        std::process::exit(64);
    }
    let tsv = std::fs::read_to_string(&args[2]).expect("requests.tsv");
    // a map of token name to bearer token (the verify script writes it with the reference server's clock)
    let tokens: std::collections::HashMap<String, String> = args
        .get(3)
        .map(|p| {
            serde_json::from_str(&std::fs::read_to_string(p).expect("tokens.json"))
                .expect("tokens json")
        })
        .unwrap_or_default();
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    for record in rt.block_on(ledger_grpc_api::oracle::replay(&args[1], &tsv, &tokens)) {
        println!("{}", serde_json::to_string(&record).expect("json"));
    }
}
