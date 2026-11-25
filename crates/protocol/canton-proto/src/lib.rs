//! Rust types generated from the official Canton 3.7.2 `.proto` files.
//!
//! Nothing here is hand-written. The `.proto` sources under `proto/` are byte copies of the pinned 3.7.2
//! release (`scripts/vendor-protos.sh --check` proves it) and are compiled by `build.rs`. Module paths follow
//! the protobuf package names, for example `com::digitalasset::daml::lf::archive::ArchivePayload` and
//! `com::daml::ledger::api::v2::...`. With the `grpc` feature the tonic client and server stubs are generated too.
//!
//! Decoding limit: prost stops at nesting depth 100. Real Daml-LF packages (for example `daml-prim`) nest deeper,
//! so the default build fails closed with `RecursionLimitReached` on them. The `no-recursion-limit` feature lifts
//! the limit; a caller that decodes untrusted bytes bounds the depth with [`depth`], which the generated gRPC
//! services and clients do.
//!
//! This crate provides message types and (optionally) service stubs only. It contains no server, client
//! behaviour, or protocol logic.
#![allow(clippy::all)]
#![allow(rustdoc::all)]
#![allow(missing_docs)]

include!(concat!(env!("OUT_DIR"), "/canton_proto_all.rs"));

pub mod depth;

/// The protobuf `FileDescriptorSet` of every vendored `.proto` file (for reflection-based users).
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/canton_fds.bin"));
