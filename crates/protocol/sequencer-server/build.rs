//! Generates the gRPC health service (`grpc.health.v1`), which a participant's connection pool calls (`Health/Watch`) before it asks
//! the sequencer anything. The proto is the one in the official Canton 3.7.2 jar (`jar-classes/grpc/health/v1/health.proto`), copied
//! byte for byte to `proto/` (SHA-256 in `proto/SOURCES.tsv`), not part of the vendored `canton-proto` protos (those are the release's
//! protobuf folder only).
fn main() {
    println!("cargo:rerun-if-changed=proto");
    let proto = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"),
    )
    .join("proto");
    let fds = protox::compile(["grpc/health/v1/health.proto"], [&proto])
        .expect("protox compiles the health proto");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(false)
        .compile_fds(fds)
        .expect("tonic-prost-build generates the health service");
}
