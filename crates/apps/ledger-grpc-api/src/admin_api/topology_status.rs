//! `StatusService`, `ParticipantStatusService`, `IdentityInitializationService`,
//! and Participant `TopologyManagerReadService` / `TopologyManagerWriteService` gRPC handlers.

use std::time::Instant;

use canton_proto::com::digitalasset::canton::admin::health::v30 as h30;
use canton_proto::com::digitalasset::canton::admin::participant::v30 as p30;
use canton_proto::com::digitalasset::canton::crypto::v30 as c30;
use canton_proto::com::digitalasset::canton::protocol::v30 as proto30;
use canton_proto::com::digitalasset::canton::topology::admin::v30 as t30;
use ledger_json_api::{
    admin_state::{
        add_topology_txs_in_store, authorize_party_to_participant_spec, authorize_vetted_packages,
        extra_topology_txs, health_dump_json, import_topology_txs, set_log_level,
        topology_party_mappings, topology_party_mappings_in_store, topology_vetted_packages,
        PartyAuthorizeSpec,
    },
    ExecutionService,
};
use prost::Message as _;
use prost_reflect::{DynamicMessage, MethodDescriptor};
use tonic::Status;

use super::{decode_typed, encode_typed, map_admin_err};

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Builds a standard uncompressed (STORED, method 0) ZIP archive holding a single file.
fn build_single_file_zip(filename: &str, data: &[u8]) -> Vec<u8> {
    let name_bytes = filename.as_bytes();
    let crc = crc32(data);
    let size = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let name_len = u16::try_from(name_bytes.len()).unwrap_or(u16::MAX);

    let mut out = Vec::with_capacity(128 + name_bytes.len() * 2 + data.len());
    // Local file header
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);

    let cd_offset = u32::try_from(out.len()).unwrap_or(u32::MAX);
    // Central directory header
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes()); // version made by
    out.extend_from_slice(&20u16.to_le_bytes()); // version needed
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
    out.extend_from_slice(&0u16.to_le_bytes()); // mod time
    out.extend_from_slice(&0u16.to_le_bytes()); // mod date
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // extra len
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    out.extend_from_slice(name_bytes);

    let cd_size = u32::try_from(out.len())
        .unwrap_or(u32::MAX)
        .saturating_sub(cd_offset);
    // End of central directory
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
    out.extend_from_slice(&1u16.to_le_bytes()); // entries on disk
    out.extend_from_slice(&1u16.to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

fn common_status(
    ledger: &ExecutionService,
    started_at: Instant,
    sync_filter: Option<&str>,
) -> h30::Status {
    let elapsed = started_at.elapsed();
    let uid = ledger.participant_id();
    let mut components = vec![h30::ComponentStatus {
        name: "ledger-api-server".to_string(),
        labels: Default::default(),
        status: Some(h30::component_status::Status::Ok(
            h30::component_status::StatusData {
                description: Some("serving".to_string()),
            },
        )),
    }];
    for (alias, sid) in ledger.connected_synchronizers() {
        if let Some(f) = sync_filter {
            if sid != f && !sid.starts_with(f) {
                continue;
            }
        }
        let mut labels = std::collections::HashMap::new();
        labels.insert("synchronizer".to_string(), sid);
        labels.insert("alias".to_string(), alias);
        components.push(h30::ComponentStatus {
            name: "sequencer-client".to_string(),
            labels,
            status: Some(h30::component_status::Status::Ok(
                h30::component_status::StatusData {
                    description: Some("connected".to_string()),
                },
            )),
        });
    }
    let pending = u32::try_from(ledger.pending_topology_changes()).unwrap_or(u32::MAX);
    h30::Status {
        uid,
        uptime: Some(prost_reflect::prost_types::Duration {
            seconds: elapsed.as_secs() as i64,
            nanos: elapsed.subsec_nanos() as i32,
        }),
        ports: ledger.admin_ports().into_iter().collect(),
        active: true,
        topology_queues: Some(h30::TopologyQueueStatus {
            manager: 0,
            dispatcher: 0,
            clients: pending,
        }),
        components,
        version: "3.7.2".to_string(),
    }
}

/// Handles `IdentityInitializationService/GetId`.
pub fn handle_identity_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    _request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "GetId" {
        return None;
    }
    let id = ledger.participant_id();
    Some(
        encode_typed(
            method,
            &t30::GetIdResponse {
                initialized: !id.is_empty(),
                unique_identifier: id,
            },
        )
        .map(|msg| vec![msg]),
    )
}

/// Handles `ParticipantStatusService/ParticipantStatus`.
pub fn handle_participant_status_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    started_at: Instant,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "ParticipantStatus" {
        return None;
    }
    Some((|| {
        let req: p30::ParticipantStatusRequest = decode_typed(request)?;
        let sync_filter = req.synchronizer_id.and_then(|s| match s.kind {
            Some(t30::synchronizer::Kind::Id(id)) => Some(id),
            Some(t30::synchronizer::Kind::PhysicalId(pid)) => Some(pid),
            None => None,
        });
        let synchronizers = ledger
            .connected_synchronizers()
            .into_iter()
            .filter(|(_, sid)| {
                sync_filter
                    .as_deref()
                    .is_none_or(|f| sid == f || sid.starts_with(f))
            })
            .map(|(_, id)| p30::ConnectedSynchronizer {
                physical_synchronizer_id: id,
                health: p30::connected_synchronizer::Health::Healthy as i32,
            })
            .collect();
        let status = common_status(ledger, started_at, sync_filter.as_deref());
        let resp = p30::ParticipantStatusResponse {
            kind: Some(p30::participant_status_response::Kind::Status(
                p30::participant_status_response::ParticipantStatusResponseStatus {
                    common_status: Some(status),
                    connected_synchronizers: synchronizers,
                    active: true,
                    supported_protocol_versions: vec![37],
                },
            )),
        };
        Ok(vec![encode_typed(method, &resp)?])
    })())
}

/// Handles unary `com.digitalasset.canton.admin.health.v30.StatusService` RPCs (`SetLogLevel`).
pub fn handle_status_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "SetLogLevel" {
        return None;
    }
    Some((|| {
        let req: h30::SetLogLevelRequest = decode_typed(request)?;
        set_log_level(ledger, &req.level).map_err(map_admin_err)?;
        Ok(vec![encode_typed(method, &h30::SetLogLevelResponse {})?])
    })())
}

/// Handles server-streaming `StatusService/HealthDump`.
pub fn handle_status_server_streaming(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
    started_at: Instant,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "HealthDump" {
        return None;
    }
    Some((|| {
        let req: h30::HealthDumpRequest = decode_typed(request)?;
        let _ = started_at;
        let json_bytes = health_dump_json(ledger);
        let zip_bytes = build_single_file_zip("canton-rs-health-dump.json", &json_bytes);
        let chunk_size = req.chunk_size.unwrap_or(65_536).max(1) as usize;
        let mut out = Vec::new();
        for chunk in zip_bytes.chunks(chunk_size) {
            out.push(encode_typed(
                method,
                &h30::HealthDumpResponse {
                    chunk: chunk.to_vec(),
                },
            )?);
        }
        Ok(out)
    })())
}

fn is_synchronizer_store(store: Option<&t30::StoreId>) -> bool {
    matches!(
        store.and_then(|s| s.store.as_ref()),
        Some(t30::store_id::Store::Synchronizer(s)) if s.kind.is_some()
    )
}

fn store_id_to_label(store: Option<&t30::StoreId>) -> String {
    match store.and_then(|s| s.store.as_ref()) {
        Some(t30::store_id::Store::Authorized(_)) => "Authorized".to_string(),
        Some(t30::store_id::Store::Synchronizer(s)) => match &s.kind {
            Some(t30::synchronizer::Kind::Id(id)) => id.clone(),
            Some(t30::synchronizer::Kind::PhysicalId(pid)) => pid.clone(),
            None => "Authorized".to_string(),
        },
        Some(t30::store_id::Store::Temporary(t)) => t.name.clone(),
        None => "Authorized".to_string(),
    }
}

fn base_result(serial: i32, signed_by: &str) -> t30::BaseResult {
    t30::BaseResult {
        store: Some(t30::StoreId {
            store: Some(t30::store_id::Store::Authorized(
                t30::store_id::Authorized {},
            )),
        }),
        sequenced: None,
        valid_from: None,
        valid_until: None,
        operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
        transaction_hash: Vec::new(),
        serial,
        signed_by_fingerprints: if signed_by.is_empty() {
            Vec::new()
        } else {
            vec![signed_by.to_string()]
        },
    }
}

#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf fields for wire compatibility"
)]
fn collect_topology_items(
    ledger: &ExecutionService,
    include: &[String],
    filter_ns: &str,
) -> Vec<t30::topology_transactions::Item> {
    let uid = ledger.participant_id();
    let fp = uid.split("::").nth(1).unwrap_or("").to_string();
    let matches_ns = filter_ns.is_empty() || filter_ns == fp;
    let want = |code: &str| include.is_empty() || include.iter().any(|c| c == code);
    let mut items = Vec::new();

    if matches_ns && want("PTP") {
        let extra = extra_topology_txs(ledger, None);
        for (party, part_uid, perm) in topology_party_mappings(ledger) {
            let (_, bytes) = authorize_party_noop_bytes(&party, &part_uid, perm as i32);
            if extra.iter().any(|raw| {
                proto30::SignedTopologyTransaction::decode(raw.as_slice())
                    .ok()
                    .and_then(|s| proto30::TopologyTransaction::decode(s.transaction.as_slice()).ok())
                    .and_then(|t| t.mapping.and_then(|m| m.mapping))
                    .is_some_and(|m| matches!(m, proto30::topology_mapping::Mapping::PartyToParticipant(p) if p.party == party))
            }) {
                continue;
            }
            items.push(t30::topology_transactions::Item {
                sequenced: None,
                valid_from: None,
                valid_until: None,
                transaction: bytes,
                rejection_reason: None,
            });
        }
    }
    if matches_ns && want("VTP") {
        let (part_uid, _, serial, pkgs) = topology_vetted_packages(ledger);
        let mapping = proto30::VettedPackages {
            participant_uid: part_uid,
            package_ids: Vec::new(),
            packages: pkgs
                .into_iter()
                .map(|(id, _, _)| proto30::vetted_packages::VettedPackage {
                    package_id: id,
                    valid_from_inclusive: None,
                    valid_until_exclusive: None,
                })
                .collect(),
        };
        let tx = proto30::TopologyTransaction {
            operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
            serial: serial as u32,
            mapping: Some(proto30::TopologyMapping {
                mapping: Some(proto30::topology_mapping::Mapping::VettedPackages(mapping)),
            }),
        };
        let signed = proto30::SignedTopologyTransaction {
            transaction: tx.encode_to_vec(),
            signatures: Vec::new(),
            proposal: false,
            multi_transaction_signatures: Vec::new(),
        };
        items.push(t30::topology_transactions::Item {
            sequenced: None,
            valid_from: None,
            valid_until: None,
            transaction: signed.encode_to_vec(),
            rejection_reason: None,
        });
    }
    for raw in extra_topology_txs(ledger, None) {
        items.push(t30::topology_transactions::Item {
            sequenced: None,
            valid_from: None,
            valid_until: None,
            transaction: raw,
            rejection_reason: None,
        });
    }
    items
}

fn authorize_party_noop_bytes(party: &str, uid: &str, perm: i32) -> ((), Vec<u8>) {
    let mapping = proto30::PartyToParticipant {
        party: party.to_string(),
        threshold: 1,
        participants: vec![proto30::party_to_participant::HostingParticipant {
            participant_uid: uid.to_string(),
            permission: perm,
            onboarding: None,
        }],
        party_signing_keys: None,
    };
    let tx = proto30::TopologyTransaction {
        operation: proto30::enums::TopologyChangeOp::AddReplace as i32,
        serial: 1,
        mapping: Some(proto30::TopologyMapping {
            mapping: Some(proto30::topology_mapping::Mapping::PartyToParticipant(
                mapping,
            )),
        }),
    };
    let signed = proto30::SignedTopologyTransaction {
        transaction: tx.encode_to_vec(),
        signatures: Vec::new(),
        proposal: false,
        multi_transaction_signatures: Vec::new(),
    };
    ((), signed.encode_to_vec())
}

/// Handles unary Participant `TopologyManagerReadService` RPCs.
#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf fields for wire compatibility"
)]
pub fn handle_topology_read_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    let uid = ledger.participant_id();
    let fp = uid.split("::").nth(1).unwrap_or("").to_string();
    match method.name() {
        "ListAvailableStores" => Some((|| {
            let mut store_ids = vec![t30::StoreId {
                store: Some(t30::store_id::Store::Authorized(
                    t30::store_id::Authorized {},
                )),
            }];
            for (_, sid) in ledger.connected_synchronizers() {
                store_ids.push(t30::StoreId {
                    store: Some(t30::store_id::Store::Synchronizer(t30::Synchronizer {
                        kind: Some(t30::synchronizer::Kind::PhysicalId(sid)),
                    })),
                });
            }
            Ok(vec![encode_typed(
                method,
                &t30::ListAvailableStoresResponse { store_ids },
            )?])
        })()),
        "ListPartyToParticipant" => Some((|| {
            let req: t30::ListPartyToParticipantRequest = decode_typed(request)?;
            let proposals_only = req.base_query.as_ref().is_some_and(|q| q.proposals);
            let store_filter = req
                .base_query
                .as_ref()
                .and_then(|q| q.store.as_ref())
                .and_then(|s| s.store.as_ref())
                .map(|store| match store {
                    t30::store_id::Store::Authorized(_) => "Authorized".to_string(),
                    t30::store_id::Store::Synchronizer(sync) => match &sync.kind {
                        Some(t30::synchronizer::Kind::Id(id)) => id.clone(),
                        Some(t30::synchronizer::Kind::PhysicalId(pid)) => pid.clone(),
                        None => String::new(),
                    },
                    t30::store_id::Store::Temporary(t) => t.name.clone(),
                })
                .filter(|s| !s.is_empty());
            let mappings =
                topology_party_mappings_in_store(ledger, store_filter.as_deref(), proposals_only)
                    .map_err(map_admin_err)?;
            let results = mappings
                .into_iter()
                .filter(|(party, p_uid, _)| {
                    (req.filter_party.is_empty() || party.starts_with(&req.filter_party))
                        && (req.filter_participant.is_empty()
                            || p_uid.starts_with(&req.filter_participant))
                })
                .map(
                    |(party, p_uid, perm)| t30::list_party_to_participant_response::Result {
                        context: Some(base_result(1, &fp)),
                        item: Some(t30::list_party_to_participant_response::result::Item::V30(
                            proto30::PartyToParticipant {
                                party,
                                threshold: 1,
                                participants: vec![
                                    proto30::party_to_participant::HostingParticipant {
                                        participant_uid: p_uid,
                                        permission: perm as i32,
                                        onboarding: None,
                                    },
                                ],
                                party_signing_keys: None,
                            },
                        )),
                    },
                )
                .collect();
            Ok(vec![encode_typed(
                method,
                &t30::ListPartyToParticipantResponse { results },
            )?])
        })()),
        "ListVettedPackages" => Some((|| {
            let req: t30::ListVettedPackagesRequest = decode_typed(request)?;
            let (part_uid, _, serial, pkgs) = topology_vetted_packages(ledger);
            let mut results = Vec::new();
            if req.filter_participant.is_empty() || part_uid.starts_with(&req.filter_participant) {
                results.push(t30::list_vetted_packages_response::Result {
                    context: Some(base_result(serial as i32, &fp)),
                    item: Some(proto30::VettedPackages {
                        participant_uid: part_uid,
                        package_ids: Vec::new(),
                        packages: pkgs
                            .into_iter()
                            .map(|(id, _, _)| proto30::vetted_packages::VettedPackage {
                                package_id: id,
                                valid_from_inclusive: None,
                                valid_until_exclusive: None,
                            })
                            .collect(),
                    }),
                });
            }
            Ok(vec![encode_typed(
                method,
                &t30::ListVettedPackagesResponse { results },
            )?])
        })()),
        "ListNamespaceDelegation" => Some((|| {
            let req: t30::ListNamespaceDelegationRequest = decode_typed(request)?;
            let mut results = Vec::new();
            if (req.filter_namespace.is_empty() || fp.starts_with(&req.filter_namespace))
                && (req.filter_target_key_fingerprint.is_empty()
                    || fp.starts_with(&req.filter_target_key_fingerprint))
            {
                results.push(t30::list_namespace_delegation_response::Result {
                    context: Some(base_result(1, &fp)),
                    item: Some(t30::list_namespace_delegation_response::result::Item::V30(
                        proto30::NamespaceDelegation {
                            namespace: fp.clone(),
                            target_key: Some(c30::SigningPublicKey {
                                format: c30::CryptoKeyFormat::DerX509SubjectPublicKeyInfo as i32,
                                public_key: Vec::new(),
                                scheme: c30::SigningKeyScheme::Ed25519 as i32,
                                usage: vec![c30::SigningKeyUsage::Namespace as i32],
                                key_spec: c30::SigningKeySpec::EcCurve25519 as i32,
                            }),
                            is_root_delegation: true,
                            restriction: None,
                        },
                    )),
                });
            }
            Ok(vec![encode_typed(
                method,
                &t30::ListNamespaceDelegationResponse { results },
            )?])
        })()),
        "ListOwnerToKeyMapping" => Some((|| {
            let req: t30::ListOwnerToKeyMappingRequest = decode_typed(request)?;
            let member = format!("PAR::{uid}");
            let mut results = Vec::new();
            if req.filter_key_owner_uid.is_empty() || member.contains(&req.filter_key_owner_uid) {
                results.push(t30::list_owner_to_key_mapping_response::Result {
                    context: Some(base_result(1, &fp)),
                    item: Some(t30::list_owner_to_key_mapping_response::result::Item::V30(
                        proto30::OwnerToKeyMapping {
                            member,
                            public_keys: Vec::new(),
                        },
                    )),
                });
            }
            Ok(vec![encode_typed(
                method,
                &t30::ListOwnerToKeyMappingResponse { results },
            )?])
        })()),
        "ListSynchronizerTrustCertificate" => Some((|| {
            let req: t30::ListSynchronizerTrustCertificateRequest = decode_typed(request)?;
            let results = ledger
                .connected_synchronizers()
                .into_iter()
                .filter(|(_, _)| req.filter_uid.is_empty() || uid.starts_with(&req.filter_uid))
                .map(
                    |(_, sid)| t30::list_synchronizer_trust_certificate_response::Result {
                        context: Some(base_result(1, &fp)),
                        item: Some(proto30::SynchronizerTrustCertificate {
                            participant_uid: uid.clone(),
                            synchronizer_id: sid,
                            feature_flags: Vec::new(),
                        }),
                    },
                )
                .collect();
            Ok(vec![encode_typed(
                method,
                &t30::ListSynchronizerTrustCertificateResponse { results },
            )?])
        })()),
        "ListAllV2" => Some((|| {
            let req: t30::ListAllV2Request = decode_typed(request)?;
            let items =
                collect_topology_items(ledger, &req.include_mappings, &req.filter_namespace);
            Ok(vec![encode_typed(
                method,
                &t30::ListAllV2Response {
                    result: Some(t30::TopologyTransactions { items }),
                },
            )?])
        })()),
        _ => None,
    }
}

/// Handles server-streaming `TopologyManagerReadService/ExportTopologySnapshotV2`.
pub fn handle_topology_read_server_streaming(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    if method.name() != "ExportTopologySnapshotV2" && method.name() != "ExportTopologySnapshot" {
        return None;
    }
    Some((|| {
        let (filter_ns, is_v2) = if method.name() == "ExportTopologySnapshotV2" {
            let req: t30::ExportTopologySnapshotV2Request = decode_typed(request)?;
            (req.filter_namespace, true)
        } else {
            let req: t30::ExportTopologySnapshotRequest = decode_typed(request)?;
            (req.filter_namespace, false)
        };
        let items = collect_topology_items(ledger, &[], &filter_ns);
        let bytes = t30::TopologyTransactions { items }.encode_to_vec();
        let mut out = Vec::new();
        for chunk in bytes.chunks(65_536) {
            if is_v2 {
                out.push(encode_typed(
                    method,
                    &t30::ExportTopologySnapshotV2Response {
                        chunk: chunk.to_vec(),
                    },
                )?);
            } else {
                out.push(encode_typed(
                    method,
                    &t30::ExportTopologySnapshotResponse {
                        chunk: chunk.to_vec(),
                    },
                )?);
            }
        }
        if out.is_empty() {
            if is_v2 {
                out.push(encode_typed(
                    method,
                    &t30::ExportTopologySnapshotV2Response { chunk: Vec::new() },
                )?);
            } else {
                out.push(encode_typed(
                    method,
                    &t30::ExportTopologySnapshotResponse { chunk: Vec::new() },
                )?);
            }
        }
        Ok(out)
    })())
}

/// Handles unary `TopologyManagerWriteService` RPCs (`Authorize`, `AddTransactions`).
#[allow(
    deprecated,
    reason = "populates legacy/deprecated Canton protobuf fields for wire compatibility"
)]
pub fn handle_topology_write_method(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    request: &DynamicMessage,
) -> Option<Result<Vec<DynamicMessage>, Status>> {
    match method.name() {
        "Authorize" => Some((|| {
            let req: t30::AuthorizeRequest = decode_typed(request)?;
            let Some(t30::authorize_request::Type::Proposal(proposal)) = req.r#type else {
                return Err(Status::invalid_argument(
                    "Authorize requires a proposal mapping",
                ));
            };
            let serial_opt = (proposal.serial > 0).then_some(proposal.serial);
            let is_sync_store = is_synchronizer_store(req.store.as_ref());
            let sync_label = is_sync_store.then(|| store_id_to_label(req.store.as_ref()));
            // [CANTON-NOTE: SEMANTICS] `TopologyAdministrationGroup.scala:2488-2501`: `mustFullyAuthorize`
            // defaults to false in Canton console; self-hosted local participant authorizations still take effect
            // immediately on a synchronizer store and must keep `/v2/parties` and Ledger API topology events in sync.
            let signed_bytes = match proposal.mapping {
                Some(t30::authorize_request::proposal::Mapping::V30(m)) => match m.mapping {
                    Some(proto30::topology_mapping::Mapping::PartyToParticipant(p)) => {
                        let participants = p
                            .participants
                            .into_iter()
                            .map(|hp| (hp.participant_uid, hp.permission, hp.onboarding.is_some()))
                            .collect();
                        let (_, bytes) = authorize_party_to_participant_spec(
                            ledger,
                            PartyAuthorizeSpec {
                                party: &p.party,
                                participants,
                                threshold: p.threshold,
                                serial: proposal.serial,
                                operation: proposal.change,
                                signed_by: req.signed_by.clone(),
                                must_fully_authorize: req.must_fully_authorize,
                                apply_to_synchronizer: is_sync_store,
                                synchronizer_id: sync_label.as_deref(),
                            },
                        )
                        .map_err(map_admin_err)?;
                        bytes
                    }
                    Some(proto30::topology_mapping::Mapping::VettedPackages(vp)) => {
                        let mut pkg_ids: Vec<String> = vp
                            .packages
                            .into_iter()
                            .map(|p| p.package_id)
                            .collect();
                        for id in vp.package_ids {
                            if !pkg_ids.contains(&id) {
                                pkg_ids.push(id);
                            }
                        }
                        authorize_vetted_packages(ledger, &pkg_ids, serial_opt)
                            .map_err(map_admin_err)?
                    }
                    _ => {
                        return Err(Status::invalid_argument(
                            "Unsupported v30 topology mapping in Authorize",
                        ))
                    }
                },
                Some(t30::authorize_request::proposal::Mapping::V31(m)) => match m.mapping {
                    Some(canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping::PartyToParticipant(p)) => {
                        const STATE_ONBOARDING: i32 = 3;
                        let participants = p
                            .participants
                            .into_iter()
                            .map(|hp| {
                                (
                                    hp.participant_uid,
                                    hp.permission,
                                    hp.state == STATE_ONBOARDING,
                                )
                            })
                            .collect();
                        let (_, bytes) = authorize_party_to_participant_spec(
                            ledger,
                            PartyAuthorizeSpec {
                                party: &p.party,
                                participants,
                                threshold: p.threshold,
                                serial: proposal.serial,
                                operation: proposal.change,
                                signed_by: req.signed_by.clone(),
                                must_fully_authorize: req.must_fully_authorize,
                                apply_to_synchronizer: is_sync_store,
                                synchronizer_id: sync_label.as_deref(),
                            },
                        )
                        .map_err(map_admin_err)?;
                        bytes
                    }
                    Some(canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping::VettedPackages(vp)) => {
                        let mut pkg_ids: Vec<String> = vp
                            .packages
                            .into_iter()
                            .map(|p| p.package_id)
                            .collect();
                        for id in vp.package_ids {
                            if !pkg_ids.contains(&id) {
                                pkg_ids.push(id);
                            }
                        }
                        authorize_vetted_packages(ledger, &pkg_ids, serial_opt)
                            .map_err(map_admin_err)?
                    }
                    _ => {
                        return Err(Status::invalid_argument(
                            "Unsupported v31 topology mapping in Authorize",
                        ))
                    }
                },
                None => {
                    return Err(Status::invalid_argument(
                        "Authorize proposal is missing mapping",
                    ))
                }
            };
            let signed_tx = proto30::SignedTopologyTransaction::decode(signed_bytes.as_slice())
                .map_err(|e| Status::internal(format!("decode signed tx: {e}")))?;
            Ok(vec![encode_typed(
                method,
                &t30::AuthorizeResponse {
                    transaction: Some(signed_tx),
                },
            )?])
        })()),
        "AddTransactions" => Some((|| {
            let req: t30::AddTransactionsRequest = decode_typed(request)?;
            let label = store_id_to_label(req.store.as_ref());
            let sync_store = is_synchronizer_store(req.store.as_ref());
            let raw: Vec<Vec<u8>> = req
                .transactions
                .into_iter()
                .map(|t| t.encode_to_vec())
                .collect();
            add_topology_txs_in_store(ledger, &label, sync_store, raw).map_err(map_admin_err)?;
            Ok(vec![encode_typed(
                method,
                &t30::AddTransactionsResponse {},
            )?])
        })()),
        _ => None,
    }
}

/// Handles client-streaming `TopologyManagerWriteService/ImportTopologySnapshot{,V2}`.
pub fn handle_topology_write_client_streaming(
    ledger: &ExecutionService,
    method: &MethodDescriptor,
    requests: Vec<DynamicMessage>,
) -> Option<Result<DynamicMessage, Status>> {
    match method.name() {
        "ImportTopologySnapshotV2" => Some((|| {
            if requests.is_empty() {
                return Err(Status::invalid_argument("empty topology snapshot stream"));
            }
            let first: t30::ImportTopologySnapshotV2Request = decode_typed(&requests[0])?;
            let label = store_id_to_label(first.store.as_ref());
            let mut buf = first.topology_snapshot;
            for msg in requests.into_iter().skip(1) {
                let r: t30::ImportTopologySnapshotV2Request = decode_typed(&msg)?;
                buf.extend_from_slice(&r.topology_snapshot);
            }
            let txs = t30::TopologyTransactions::decode(buf.as_slice()).map_err(|e| {
                Status::invalid_argument(format!("invalid TopologyTransactions: {e}"))
            })?;
            let raw: Vec<Vec<u8>> = txs.items.into_iter().map(|i| i.transaction).collect();
            import_topology_txs(ledger, &label, raw).map_err(map_admin_err)?;
            encode_typed(method, &t30::ImportTopologySnapshotV2Response {})
        })()),
        "ImportTopologySnapshot" => Some((|| {
            if requests.is_empty() {
                return Err(Status::invalid_argument("empty topology snapshot stream"));
            }
            let first: t30::ImportTopologySnapshotRequest = decode_typed(&requests[0])?;
            let label = store_id_to_label(first.store.as_ref());
            let mut buf = first.topology_snapshot;
            for msg in requests.into_iter().skip(1) {
                let r: t30::ImportTopologySnapshotRequest = decode_typed(&msg)?;
                buf.extend_from_slice(&r.topology_snapshot);
            }
            let txs = t30::TopologyTransactions::decode(buf.as_slice()).map_err(|e| {
                Status::invalid_argument(format!("invalid TopologyTransactions: {e}"))
            })?;
            let raw: Vec<Vec<u8>> = txs.items.into_iter().map(|i| i.transaction).collect();
            import_topology_txs(ledger, &label, raw).map_err(map_admin_err)?;
            encode_typed(method, &t30::ImportTopologySnapshotResponse {})
        })()),
        _ => None,
    }
}
