//! Compiles every vendored .proto file (no external `protoc`: the pure-Rust `protox` parser is used)
//! and generates Rust code with prost, plus tonic stubs when the `grpc` feature is on.
//! The vendored files are byte copies of the pinned Canton 3.7.2 release; see scripts/vendor-protos.sh.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn collect(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read proto dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect(&p, base, out);
        } else if p.extension().is_some_and(|e| e == "proto") {
            out.push(p.strip_prefix(base).expect("under base").to_path_buf());
        }
    }
}

fn main() {
    let proto_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir")).join("proto");
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=build.rs");

    let mut files = Vec::new();
    collect(&proto_dir, &proto_dir, &mut files);
    assert!(
        !files.is_empty(),
        "no .proto files under {}",
        proto_dir.display()
    );

    let fds = protox::compile(&files, [&proto_dir])
        .expect("protox failed to compile the vendored protos");

    // The descriptor set of every vendored file, for dynamic (reflection) users such as the gRPC bridge and its oracle.
    {
        use prost::Message;
        let out = PathBuf::from(env::var("OUT_DIR").expect("out dir")).join("canton_fds.bin");
        fs::write(out, fds.encode_to_vec()).expect("write descriptor set");
    }

    let mut config = prost_build::Config::new();
    config.include_file("canton_proto_all.rs");
    // `prost::Name` on every message: the depth bound (`src/depth.rs`) finds a message's schema by its full name.
    config.enable_type_names();

    #[cfg(feature = "grpc")]
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        // Generated clients must not reference tonic::transport; this crate depends on tonic without it.
        .build_transport(false)
        // Every generated service and client decodes through the nesting bound (`src/depth.rs`).
        .codec_path("crate::depth::BoundedCodec")
        .compile_fds_with_config(fds, config)
        .expect("tonic-prost-build failed");

    #[cfg(not(feature = "grpc"))]
    config.compile_fds(fds).expect("prost-build failed");
}
