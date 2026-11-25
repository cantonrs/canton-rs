//! The transport limits of the sequencer's gRPC listeners, with Canton's defaults.
//!
//! [CANTON-NOTE: SEMANTICS] The public API takes messages up to the synchronizer's `max_request_size` (`DynamicGrpcServer`:
//! `maxInboundMessageSize(serverConfig.overrideMaxRequestSize.getOrElse(maxRequestSize.value))`, 10 MiB by default), the admin API up to
//! `ServerConfig.defaultMaxInboundMessageSize` (10 MiB). Both keep connections alive as `BasicKeepAliveServerConfig` (a ping after 40 s
//! of silence, 20 s to answer it) and allow `defaultMaxConcurrentCallsPerConnection` (100000) calls and `defaultMaxInboundMetadataSize`
//! (8 KiB) of headers per call.
//!
//! [CANTON-NOTE: LIMITATION] The bound is fixed at the default `max_request_size`: Canton rebuilds its public server when the parameter
//! changes; here a synchronizer that raised it past 10 MiB has larger requests refused by the transport (OUT_OF_RANGE).
use std::time::Duration;

/// The largest request message a listener reads.
pub const MAX_INBOUND_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// A server builder with Canton's transport limits (the message size is per service: see [`MAX_INBOUND_MESSAGE_SIZE`]).
pub fn server() -> tonic::transport::Server {
    tonic::transport::Server::builder()
        .max_concurrent_streams(100_000)
        .http2_max_header_list_size(8 * 1024)
        .http2_keepalive_interval(Some(Duration::from_secs(40)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
}
