//! Participant Admin API gRPC handlers (`PackageService`, `PingService`, `SynchronizerConnectivityService`,
//! `StatusService`, `ParticipantStatusService`, `ParticipantInspectionService`, `ParticipantRepairService`,
//! and Participant `TopologyManager{Read,Write}Service`).

mod connectivity;
mod inspection_repair;
mod packages;
mod ping_bong;
mod pruning;
mod topology_status;

use std::sync::Arc;

use ledger_json_api::ExecutionService;
use prost::Message as _;
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::{Code, Status};

pub use connectivity::handle_connectivity_method;
pub use inspection_repair::{
    handle_repair_client_streaming, handle_repair_method, handle_repair_server_streaming,
};
pub use packages::handle_package_method;
pub use ping_bong::{ensure_ping_workflow, handle_ping, BUILTIN_PING_DAR};
pub use pruning::handle_pruning_method;
pub use topology_status::{
    handle_identity_method, handle_participant_status_method, handle_status_method,
    handle_status_server_streaming, handle_topology_read_method,
    handle_topology_read_server_streaming, handle_topology_write_client_streaming,
    handle_topology_write_method,
};

pub(crate) fn decode_typed<T: prost::Message + Default>(msg: &DynamicMessage) -> Result<T, Status> {
    T::decode(msg.encode_to_vec().as_slice())
        .map_err(|e| Status::invalid_argument(format!("invalid request: {e}")))
}

pub(crate) fn encode_typed<T: prost::Message>(
    method: &MethodDescriptor,
    msg: &T,
) -> Result<DynamicMessage, Status> {
    DynamicMessage::decode(method.output(), msg.encode_to_vec().as_slice())
        .map_err(|e| Status::internal(format!("response conversion: {e}")))
}

pub(crate) fn map_admin_err((code, msg): (i32, String)) -> Status {
    Status::new(Code::from_i32(code), msg)
}

/// Dispatches unary Participant/Topology/Health Admin gRPC methods.
pub fn handle_admin_unary(
    ledger: &Arc<ExecutionService>,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    started_at: std::time::Instant,
    authorization: Option<&str>,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    let svc = method.parent_service().full_name();
    match svc {
        "com.digitalasset.canton.admin.participant.v30.PackageService" => {
            handle_package_method(ledger, method, request)
        }
        "com.digitalasset.canton.admin.participant.v30.PruningService" => {
            handle_pruning_method(ledger, method, request, authorization)
        }
        "com.digitalasset.canton.admin.participant.v30.SynchronizerConnectivityService" => {
            handle_connectivity_method(ledger, method, request)
        }
        "com.digitalasset.canton.admin.participant.v30.ParticipantInspectionService"
        | "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService" => {
            handle_repair_method(ledger, method, request)
        }
        "com.digitalasset.canton.topology.admin.v30.IdentityInitializationService" => {
            handle_identity_method(ledger, method, request)
        }
        "com.digitalasset.canton.admin.participant.v30.ParticipantStatusService" => {
            handle_participant_status_method(ledger, method, request, started_at)
        }
        "com.digitalasset.canton.admin.health.v30.StatusService" => {
            handle_status_method(ledger, method, request)
        }
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService" => {
            handle_topology_read_method(ledger, method, request)
        }
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService" => {
            handle_topology_write_method(ledger, method, request)
        }
        _ => None,
    }
}

/// Dispatches server-streaming Participant/Topology/Health Admin gRPC methods.
pub fn handle_admin_server_streaming(
    ledger: &Arc<ExecutionService>,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    started_at: std::time::Instant,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    match method.parent_service().full_name() {
        "com.digitalasset.canton.admin.health.v30.StatusService" => {
            handle_status_server_streaming(ledger, method, request, started_at)
        }
        "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService" => {
            handle_repair_server_streaming(ledger, method, request)
        }
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerReadService" => {
            handle_topology_read_server_streaming(ledger, method, request)
        }
        _ => None,
    }
}

/// Dispatches client-streaming Participant/Topology Admin gRPC methods (`ImportAcs`, `ImportTopologySnapshot*`).
pub fn handle_admin_client_streaming(
    ledger: &Arc<ExecutionService>,
    method: &MethodDescriptor,
    requests: Vec<DynamicMessage>,
) -> Option<Result<DynamicMessage, Status>> {
    match method.parent_service().full_name() {
        "com.digitalasset.canton.admin.participant.v30.ParticipantRepairService" => {
            handle_repair_client_streaming(ledger, method, requests)
        }
        "com.digitalasset.canton.topology.admin.v30.TopologyManagerWriteService" => {
            handle_topology_write_client_streaming(ledger, method, requests)
        }
        _ => None,
    }
}
