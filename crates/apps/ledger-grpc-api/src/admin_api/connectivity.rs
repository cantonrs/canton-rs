//! `com.digitalasset.canton.admin.participant.v30.SynchronizerConnectivityService` gRPC handlers.

use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use canton_proto::com::digitalasset::canton::admin::sequencer::v30 as s30;
use ledger_json_api::{
    admin_state::{
        connect_sync, disconnect_all_syncs, disconnect_sync, get_sync_id, list_connected_syncs,
        list_registered_syncs, modify_sync, reconnect_all_syncs, reconnect_sync, register_sync,
    },
    v2::RegisteredSync,
    ExecutionService,
};
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::Status;

use super::{decode_typed, encode_typed, map_admin_err};

fn endpoints_from_config(cfg: &p30::SynchronizerConnectionConfig) -> Vec<String> {
    cfg.sequencer_connections
        .as_ref()
        .map(|sc| {
            sc.sequencer_connections
                .iter()
                .flat_map(|c| match &c.r#type {
                    Some(s30::sequencer_connection::Type::Grpc(g)) => g.connections.clone(),
                    None => Vec::new(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn to_registered(cfg: Option<p30::SynchronizerConnectionConfig>) -> Result<RegisteredSync, Status> {
    let Some(cfg) = cfg else {
        return Err(Status::invalid_argument(
            "PROTO_DESERIALIZATION_ERROR: missing config",
        ));
    };
    let endpoints = endpoints_from_config(&cfg);
    Ok(RegisteredSync {
        alias: cfg.synchronizer_alias,
        synchronizer_id: String::new(),
        physical_synchronizer_id: cfg.physical_synchronizer_id,
        sequencer_endpoints: endpoints,
        manual_connect: cfg.manual_connect,
        priority: cfg.priority,
        connected: false,
        handshake_only: false,
    })
}

fn to_proto_config(reg: &RegisteredSync) -> p30::SynchronizerConnectionConfig {
    let conn = if reg.sequencer_endpoints.is_empty() {
        Vec::new()
    } else {
        let transport_security = reg
            .sequencer_endpoints
            .iter()
            .any(|e| e.starts_with("https://"));
        vec![s30::SequencerConnection {
            alias: reg.alias.clone(),
            sequencer_id: None,
            r#type: Some(s30::sequencer_connection::Type::Grpc(
                s30::sequencer_connection::Grpc {
                    connections: reg.sequencer_endpoints.clone(),
                    transport_security,
                    custom_trust_certificates: None,
                },
            )),
        }]
    };
    p30::SynchronizerConnectionConfig {
        synchronizer_alias: reg.alias.clone(),
        sequencer_connections: Some(s30::SequencerConnections {
            sequencer_connections: conn,
            sequencer_trust_threshold: 1,
            submission_request_amplification: None,
            sequencer_liveness_margin: 0,
            sequencer_connection_pool_delays: None,
            subscription_liveness_limits: None,
        }),
        manual_connect: reg.manual_connect,
        physical_synchronizer_id: reg.physical_synchronizer_id.clone(),
        priority: reg.priority,
        initial_retry_delay: None,
        max_retry_delay: None,
        time_tracker: None,
        initialize_from_trusted_synchronizer: false,
    }
}

/// Dispatches all unary methods of `SynchronizerConnectivityService`.
pub fn handle_connectivity_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    match method.name() {
        "ListConnectedSynchronizers" => Some((|| {
            let connected = list_connected_syncs(ledger)
                .into_iter()
                .map(|s| p30::list_connected_synchronizers_response::Result {
                    synchronizer_alias: s.alias,
                    synchronizer_id: s.synchronizer_id,
                    physical_synchronizer_id: s.physical_synchronizer_id,
                    healthy: true,
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::ListConnectedSynchronizersResponse {
                    connected_synchronizers: connected,
                },
            )?])
        })()),
        "ListRegisteredSynchronizers" => Some((|| {
            let _req: p30::ListRegisteredSynchronizersRequest = decode_typed(request)?;
            let results = list_registered_syncs(ledger)
                .into_iter()
                .map(|s| p30::list_registered_synchronizers_response::Result {
                    config: Some(to_proto_config(&s)),
                    connected: s.connected,
                    physical_synchronizer_id: (!s.physical_synchronizer_id.is_empty())
                        .then_some(s.physical_synchronizer_id),
                    status: p30::list_registered_synchronizers_response::Status::Active as i32,
                    synchronizer_predecessor: None,
                })
                .collect();
            Ok(vec![encode_typed(
                method,
                &p30::ListRegisteredSynchronizersResponse { results },
            )?])
        })()),
        "RegisterSynchronizer" => Some((|| {
            let req: p30::RegisterSynchronizerRequest = decode_typed(request)?;
            let mut reg = to_registered(req.config)?;
            let handshake = req.synchronizer_connection
                == p30::register_synchronizer_request::SynchronizerConnection::Handshake as i32;
            reg.handshake_only = handshake;
            let validate_ep = req.sequencer_connection_validation
                == s30::SequencerConnectionValidation::All as i32
                || req.sequencer_connection_validation
                    == s30::SequencerConnectionValidation::Active as i32
                || handshake;
            register_sync(ledger, reg, validate_ep).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::RegisterSynchronizerResponse {},
            )?])
        })()),
        "ModifySynchronizer" => Some((|| {
            let req: p30::ModifySynchronizerRequest = decode_typed(request)?;
            let reg = to_registered(req.new_config)?;
            modify_sync(ledger, req.physical_synchronizer_id.as_deref(), reg)
                .map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ModifySynchronizerResponse {},
            )?])
        })()),
        "ConnectSynchronizer" => Some((|| {
            let req: p30::ConnectSynchronizerRequest = decode_typed(request)?;
            let reg = to_registered(req.config)?;
            let connected_successfully = connect_sync(ledger, reg).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ConnectSynchronizerResponse {
                    connected_successfully,
                },
            )?])
        })()),
        "DisconnectSynchronizer" => Some((|| {
            let req: p30::DisconnectSynchronizerRequest = decode_typed(request)?;
            disconnect_sync(ledger, &req.synchronizer_alias).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::DisconnectSynchronizerResponse {},
            )?])
        })()),
        "DisconnectAllSynchronizers" => Some((|| {
            let _req: p30::DisconnectAllSynchronizersRequest = decode_typed(request)?;
            disconnect_all_syncs(ledger).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::DisconnectAllSynchronizersResponse {},
            )?])
        })()),
        "ReconnectSynchronizer" => Some((|| {
            let req: p30::ReconnectSynchronizerRequest = decode_typed(request)?;
            let connected_successfully =
                reconnect_sync(ledger, &req.synchronizer_alias).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ReconnectSynchronizerResponse {
                    connected_successfully,
                },
            )?])
        })()),
        "ReconnectSynchronizers" => Some((|| {
            let req: p30::ReconnectSynchronizersRequest = decode_typed(request)?;
            reconnect_all_syncs(ledger, req.ignore_failures).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::ReconnectSynchronizersResponse {},
            )?])
        })()),
        "Logout" => Some((|| {
            let req: p30::LogoutRequest = decode_typed(request)?;
            disconnect_sync(ledger, &req.synchronizer_alias).map_err(map_admin_err)?;
            Ok(vec![encode_typed(method, &p30::LogoutResponse {})?])
        })()),
        "GetSynchronizerId" => Some((|| {
            let req: p30::GetSynchronizerIdRequest = decode_typed(request)?;
            let (synchronizer_id, physical_synchronizer_id) =
                get_sync_id(ledger, &req.synchronizer_alias).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &p30::GetSynchronizerIdResponse {
                    synchronizer_id,
                    physical_synchronizer_id,
                },
            )?])
        })()),
        _ => None,
    }
}
