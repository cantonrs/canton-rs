// [CANTON-NOTE: STYLE] Wire builders take the parts of one Canton message as separate arguments and a few long tuple types are named once; neither is
// clearer behind a parameter struct or an alias, so these two lints are allowed in this crate.
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    reason = "wire builders pass individual fields and protocol state uses tuple types"
)]

pub mod admin_api_auth;
pub mod admin_state;
pub mod auth;
pub mod auth_jwks;
pub mod auth_stream;
mod auth_user;
#[cfg(feature = "protocol")]
pub mod canton_conf;
pub mod canton_log;
pub mod cli;
pub mod clock;
pub mod cost_estimation;
mod dedup;
pub(crate) mod diag;
pub mod exex;
mod external_keys;
pub mod history;
pub mod http;
mod http_limits;
pub mod ledger_v2;
mod metrics_compat;
pub mod models;
pub mod node_builder;
pub mod observability;
#[cfg(feature = "protocol")]
pub mod official;
#[cfg(feature = "protocol")]
pub mod official_events;
pub mod payload_schema;
mod prepared_cache;
#[cfg(feature = "protocol")]
pub mod protocol;
#[cfg(feature = "protocol")]
mod protocol_late;
pub mod service;
pub mod snapshot;
#[cfg(feature = "protocol")]
pub mod status_details;
pub mod store;
pub mod store_pg;
mod trace_context;
pub mod v2;
pub mod v2_commands;
pub mod v2_completions;
pub mod v2_idps;
pub mod v2_interactive;
pub mod v2_misc;
pub mod v2_packages;
pub mod v2_parties;
pub mod v2_prune;
pub mod v2_queries;
pub mod v2_reassign;
pub(crate) mod v2_topology_events;
pub mod v2_traffic;
pub mod v2_updates;
pub mod v2_users;
pub mod ws;

pub use auth::AuthConfig;
pub use exex::{ExExContractEvent, ExExHub, ExExNotification, ExExPartyScope, ExExSubscriberStats};
pub use http::{
    dispatch_request, route_internal, run_server, start_test_server, HttpRequest, HttpResponse,
};
pub use ledger_v2::{
    CommandCompletion, CompletionStreamResponse, DedupEntry, DeduplicationStore, JwtClaims,
};
pub use models::*;
pub use node_builder::{CantonEmbeddedNode, CantonNodeBuilder};
pub use service::{ApiError, DarPackageInfo, ExecutionService, PackagesResponse};
