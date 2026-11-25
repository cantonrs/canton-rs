//! The transport limits of the node's two gRPC listeners, with Canton's defaults.
//!
//! [CANTON-NOTE: SEMANTICS] `ServerConfig` (`base/.../config/ServerConfig.scala`): `defaultMaxInboundMessageSize` 10 MiB,
//! `defaultMaxInboundMetadataSize` 8 KiB, `defaultMaxConcurrentCallsPerConnection` 100000; the Ledger API keeps the connection alive with
//! `LedgerApiKeepAliveServerConfig` (a ping after 10 minutes of silence, 20 s to answer it), the Admin API with
//! `BasicKeepAliveServerConfig` (40 s, 20 s).
//!
//! [CANTON-NOTE: LIMITATION] No `permitKeepAliveTime` (the most frequent ping a client may send; Canton: 10 s on the Ledger API, 20 s on the
//! Admin API, never without calls): neither tonic 0.14, hyper's HTTP/2 server nor h2 0.4 police the client's pings, so no
//! `ENHANCE_YOUR_CALM` "too_many_pings" GOAWAY is sent.
use std::time::Duration;

use crate::server::Listener;

/// The limits of one gRPC listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcLimits {
    /// The largest request message (`max-inbound-message-size`).
    pub max_inbound_message_size: usize,
    /// The largest header list of a call (`max-inbound-metadata-size`).
    pub max_inbound_metadata_size: u32,
    /// The most calls open at once on one connection (`max-concurrent-calls-per-connection`).
    pub max_concurrent_calls_per_connection: u32,
    /// How long a connection may be silent before the server pings it (`keep-alive-server.time`).
    pub keepalive_time: Duration,
    /// How long the server waits for the ping's answer before it closes the connection (`keep-alive-server.timeout`).
    pub keepalive_timeout: Duration,
}

impl GrpcLimits {
    /// `ledger-api` of a participant.
    pub const LEDGER_API: Self = Self {
        max_inbound_message_size: 10 * 1024 * 1024,
        max_inbound_metadata_size: 8 * 1024,
        max_concurrent_calls_per_connection: 100_000,
        keepalive_time: Duration::from_secs(10 * 60),
        keepalive_timeout: Duration::from_secs(20),
    };

    /// `admin-api` of a node.
    pub const ADMIN_API: Self = Self {
        keepalive_time: Duration::from_secs(40),
        ..Self::LEDGER_API
    };

    /// The defaults of the listener.
    pub const fn of(listener: Listener) -> Self {
        match listener {
            Listener::LedgerApi => Self::LEDGER_API,
            Listener::AdminApi => Self::ADMIN_API,
        }
    }

    /// A server builder with these limits (the message size is the service's: [`crate::server::GrpcService`] applies it).
    pub fn server(&self) -> tonic::transport::Server {
        tonic::transport::Server::builder()
            .max_concurrent_streams(self.max_concurrent_calls_per_connection)
            .http2_max_header_list_size(self.max_inbound_metadata_size)
            .http2_keepalive_interval(Some(self.keepalive_time))
            .http2_keepalive_timeout(Some(self.keepalive_timeout))
    }
}

/// The answer to a request message over `limit` bytes as grpc-java gives it, in place of tonic's.
///
/// [CANTON-NOTE: SEMANTICS] grpc-java's `MessageDeframer` refuses the frame with RESOURCE_EXHAUSTED "gRPC message exceeds maximum size
/// <limit>: <length>" (Canton's `InvalidRequestSequencerIntegrationTest`); tonic's decoder answers OUT_OF_RANGE "Error, decoded message length
/// too large: found <length> bytes, the limit is: <limit> bytes", as a trailers-only response.
pub(crate) fn as_resource_exhausted(
    mut response: http::Response<tonic::body::Body>,
    limit: usize,
) -> http::Response<tonic::body::Body> {
    let Some(status) = tonic::Status::from_header_map(response.headers()) else {
        return response;
    };
    if status.code() != tonic::Code::OutOfRange {
        return response;
    }
    let Some(length) = status
        .message()
        .strip_prefix("Error, decoded message length too large: found ")
        .and_then(|rest| rest.split(' ').next())
    else {
        return response;
    };
    let refused = tonic::Status::resource_exhausted(format!(
        "gRPC message exceeds maximum size {limit}: {length}"
    ));
    let headers = response.headers_mut();
    headers.remove("grpc-message");
    headers.remove("grpc-status-details-bin");
    if refused.add_header(headers).is_err() {
        return tonic::Status::internal("the refusal of an oversized message").into_http();
    }
    response
}
