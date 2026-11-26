//! Native Canton participant: protocol runtime, topology state, ACS commitments, storage and the Splice services.

// [CANTON-NOTE: STYLE] The protocol builders take the many wire parts of one Canton message as separate arguments, and the gRPC
// stream types are long tuples named once; neither is clearer behind a parameter struct or an alias, so these two lints are allowed.
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    reason = "protocol builders accept individual Canton message fields and complex stream tuple types"
)]

#[cfg(feature = "sequencer-grpc")]
pub mod acs_commitment;
#[cfg(feature = "sequencer-grpc")]
pub mod acs_commitment_runtime;
pub mod audit_capsule;
pub mod cold_archive;
#[cfg(feature = "sequencer-grpc")]
pub mod confirmation_wire;
pub mod contract_id;
#[cfg(feature = "sequencer-grpc")]
pub mod contract_wire;
#[cfg(feature = "sequencer-grpc")]
pub mod crypto_handshake;
#[cfg(feature = "sequencer-grpc")]
pub(crate) mod diag;
#[cfg(feature = "postgres")]
mod embedded_migrations;
#[cfg(feature = "sequencer-grpc")]
pub mod external_hash;
pub mod hocon;
#[cfg(feature = "sequencer-grpc")]
pub mod in_flight;
pub mod lthash;
#[cfg(feature = "sequencer-grpc")]
pub mod merkle_wire;
#[cfg(feature = "postgres")]
pub mod migrate;
#[cfg(feature = "sequencer-grpc")]
pub mod multi_node;
#[cfg(feature = "sequencer-grpc")]
pub mod node;
pub mod official_prune;
#[cfg(all(feature = "postgres", feature = "sequencer-grpc"))]
pub mod official_state;
#[cfg(feature = "sequencer-grpc")]
pub mod participant_runtime;
#[cfg(feature = "postgres")]
pub mod pgconn;
#[cfg(feature = "postgres")]
pub mod pqs_index;
#[cfg(feature = "sequencer-grpc")]
pub mod reassignment_receive;
#[cfg(feature = "sequencer-grpc")]
pub mod reassignment_submit;
#[cfg(feature = "sequencer-grpc")]
pub mod reassignment_wire;
#[cfg(feature = "sequencer-grpc")]
pub mod root_hash_messages;
#[cfg(feature = "sequencer-grpc")]
pub mod routing;
pub mod scan_api;
#[cfg(feature = "sequencer-grpc")]
pub mod sequenced_event_validation;
#[cfg(feature = "sequencer-grpc")]
pub mod sequencer_connect;
#[cfg(feature = "sequencer-grpc")]
pub mod sequencer_time;
#[cfg(feature = "sequencer-grpc")]
pub mod sequencing_wire;
pub mod splice;
pub mod splice_apps;
pub mod splice_ledger_backend;
pub mod splice_persist;
pub mod state_store;
pub mod storage;
#[cfg(feature = "sequencer-grpc")]
pub mod submit;
#[cfg(feature = "postgres")]
pub mod takeover;
pub mod topology;
#[cfg(feature = "sequencer-grpc")]
pub mod topology_state;
#[cfg(feature = "sequencer-grpc")]
#[expect(
    clippy::allow_attributes_without_reason,
    reason = "topology_wire.rs is a frozen wire-format reference module"
)]
pub mod topology_wire;
#[cfg(feature = "sequencer-grpc")]
pub mod value_forms;
#[cfg(feature = "sequencer-grpc")]
pub mod view_acs;
#[cfg(feature = "sequencer-grpc")]
pub mod view_conformance;
#[cfg(feature = "sequencer-grpc")]
pub mod view_crypto;
#[cfg(feature = "sequencer-grpc")]
pub mod view_decision;
#[cfg(feature = "sequencer-grpc")]
pub mod view_informees;
#[cfg(feature = "sequencer-grpc")]
pub mod view_message;
#[cfg(feature = "sequencer-grpc")]
pub mod view_receive;
#[cfg(feature = "sequencer-grpc")]
pub mod view_tree;
#[cfg(feature = "sequencer-grpc")]
pub mod view_validation;
#[cfg(feature = "sequencer-grpc")]
pub mod view_vetting;

pub use splice::{
    AmuletEntry, AutomationJobState, GovernanceAction, GovernanceProposal, MiningRoundState,
    ScanPage, ScanTransactionRecord, SpliceError, SpliceServiceHost, SvScanObservation,
};
pub use splice_apps::{
    dso_bootstrap_payload, handle_splice_http, AutomationTickReport, SpliceAppError,
    SpliceAppRuntime, SpliceBootstrapConfig,
};
pub use splice_ledger_backend::{
    sign_hs256_jwt, LedgerSubmitOutcome, ParticipantLedgerClient, ParticipantLedgerConfig,
};
pub use storage::{compute_flyway_checksum, db_lock_id, flyway_file_checksum, lock_counters};
pub use topology::{Fingerprint, Namespace, PartyId};
