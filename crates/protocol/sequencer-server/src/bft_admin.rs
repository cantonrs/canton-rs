//! gRPC BFT Sequencer Administration & Pruning Administration services (`SequencerBftAdministrationService`,
//! `SequencerBftPruningAdministrationService`).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use canton_proto::com::digitalasset::canton::admin::pruning::v30 as pruning_v30;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30 as admin_v30;
use canton_proto::com::digitalasset::canton::synchronizer::sequencing::sequencer::bftordering::v31 as bft_v31;
use tonic::{Request, Response, Status};

use crate::bft_p2p::{BftPeerConfig, BftPeerManager, Consensus, PeerConnState};
use crate::ord_store::{OrdPruningSchedule, OrdPruningStatus, OrdStore};

const DEFAULT_MIN_BLOCKS_TO_KEEP: i32 = 100;

/// Implements `com.digitalasset.canton.sequencer.admin.v30.SequencerBftAdministrationService`.
#[derive(Clone)]
pub struct BftAdminService {
    peer_manager: Arc<BftPeerManager>,
    consensus: Arc<Consensus>,
    epoch_length: i64,
}

impl BftAdminService {
    pub fn new(
        peer_manager: Arc<BftPeerManager>,
        consensus: Arc<Consensus>,
        epoch_length: i64,
    ) -> Self {
        Self {
            peer_manager,
            consensus,
            epoch_length: epoch_length.max(1),
        }
    }
}

#[tonic::async_trait]
impl admin_v30::sequencer_bft_administration_service_server::SequencerBftAdministrationService
    for BftAdminService
{
    async fn add_peer_endpoint(
        &self,
        request: Request<admin_v30::AddPeerEndpointRequest>,
    ) -> Result<Response<admin_v30::AddPeerEndpointResponse>, Status> {
        let Some(ep) = request.into_inner().endpoint else {
            return Ok(Response::new(admin_v30::AddPeerEndpointResponse {
                added: false,
            }));
        };
        let cfg = BftPeerConfig::from_proto(&ep).map_err(Status::invalid_argument)?;
        let added = self
            .peer_manager
            .add_endpoint(cfg)
            .map_err(Status::internal)?;
        Ok(Response::new(admin_v30::AddPeerEndpointResponse { added }))
    }

    async fn remove_peer_endpoint(
        &self,
        request: Request<admin_v30::RemovePeerEndpointRequest>,
    ) -> Result<Response<admin_v30::RemovePeerEndpointResponse>, Status> {
        let Some(id) = request.into_inner().endpoint_id else {
            return Ok(Response::new(admin_v30::RemovePeerEndpointResponse {
                removed: false,
            }));
        };
        if id.address.is_empty() || id.port == 0 || id.port > u32::from(u16::MAX) {
            return Err(Status::invalid_argument("invalid peer endpoint id"));
        }
        let removed = self
            .peer_manager
            .remove_endpoint(&id.address, id.port, id.tls)
            .map_err(Status::internal)?;
        Ok(Response::new(admin_v30::RemovePeerEndpointResponse {
            removed,
        }))
    }

    async fn list_configured_endpoints(
        &self,
        _request: Request<admin_v30::ListConfiguredEndpointsRequest>,
    ) -> Result<Response<admin_v30::ListConfiguredEndpointsResponse>, Status> {
        let endpoints = self
            .peer_manager
            .list_configured_endpoints()
            .into_iter()
            .map(|(cfg, seq_id)| cfg.to_proto(seq_id))
            .collect();
        Ok(Response::new(admin_v30::ListConfiguredEndpointsResponse {
            endpoints,
        }))
    }

    async fn get_peer_network_status(
        &self,
        request: Request<admin_v30::GetPeerNetworkStatusRequest>,
    ) -> Result<Response<admin_v30::GetPeerNetworkStatusResponse>, Status> {
        let req_ids = request.into_inner().endpoint_ids;
        let filter_keys: Vec<(String, u32, bool)> = req_ids
            .iter()
            .map(|id| (id.address.clone(), id.port, id.tls))
            .collect();
        let filter_opt = (!filter_keys.is_empty()).then_some(filter_keys.as_slice());
        let (views, incoming) = self.peer_manager.network_status(filter_opt);

        let mut statuses = Vec::with_capacity(views.len() + incoming.len());
        let mut seen = std::collections::BTreeSet::new();
        for view in views {
            seen.insert((view.address.clone(), view.port, view.tls));
            let health_status = match view.state {
                PeerConnState::Disconnected => {
                    admin_v30::peer_endpoint_health_status::Status::Disconnected(
                        admin_v30::peer_endpoint_health_status::Disconnected {},
                    )
                }
                PeerConnState::Unauthenticated => {
                    admin_v30::peer_endpoint_health_status::Status::Unauthenticated(
                        admin_v30::peer_endpoint_health_status::Unauthenticated {},
                    )
                }
                PeerConnState::Authenticated(sequencer_id) => {
                    admin_v30::peer_endpoint_health_status::Status::Authenticated(
                        admin_v30::Authenticated { sequencer_id },
                    )
                }
            };
            statuses.push(admin_v30::PeerConnectionStatus {
                status: Some(
                    admin_v30::peer_connection_status::Status::PeerEndpointStatus(
                        admin_v30::PeerEndpointStatus {
                            endpoint_id: Some(admin_v30::PeerEndpointId {
                                address: view.address,
                                port: view.port,
                                tls: view.tls,
                            }),
                            is_outgoing_connection: view.is_outgoing,
                            health: Some(admin_v30::PeerEndpointHealth {
                                status: Some(admin_v30::PeerEndpointHealthStatus {
                                    status: Some(health_status),
                                }),
                                description: view.description,
                            }),
                        },
                    ),
                ),
            });
        }
        for key in filter_keys {
            if !seen.contains(&key) {
                statuses.push(admin_v30::PeerConnectionStatus {
                    status: Some(
                        admin_v30::peer_connection_status::Status::PeerEndpointStatus(
                            admin_v30::PeerEndpointStatus {
                                endpoint_id: Some(admin_v30::PeerEndpointId {
                                    address: key.0,
                                    port: key.1,
                                    tls: key.2,
                                }),
                                is_outgoing_connection: false,
                                health: Some(admin_v30::PeerEndpointHealth {
                                    status: Some(admin_v30::PeerEndpointHealthStatus {
                                        status: Some(
                                            admin_v30::peer_endpoint_health_status::Status::UnknownEndpoint(
                                                admin_v30::peer_endpoint_health_status::UnknownEndpoint {},
                                            ),
                                        ),
                                    }),
                                    description: None,
                                }),
                            },
                        ),
                    ),
                });
            }
        }
        for sequencer_id in incoming {
            statuses.push(admin_v30::PeerConnectionStatus {
                status: Some(
                    admin_v30::peer_connection_status::Status::PeerIncomingConnection(
                        admin_v30::Authenticated { sequencer_id },
                    ),
                ),
            });
        }
        Ok(Response::new(admin_v30::GetPeerNetworkStatusResponse {
            statuses,
        }))
    }

    async fn get_write_readiness(
        &self,
        _request: Request<admin_v30::GetWriteReadinessRequest>,
    ) -> Result<Response<admin_v30::GetWriteReadinessResponse>, Status> {
        let (_, nodes, _, _) = self.consensus.ordering_topology();
        let weak_quorum = canton_bft_orderer::topology::weak_quorum_size(nodes.len().max(1));
        let required_other_peers = weak_quorum.saturating_sub(1) as i32;
        let authenticated = self.peer_manager.authenticated_peers_count() as i32;
        let p2p = Some(admin_v30::get_write_readiness_response::P2p {
            authenticated_peers_count: authenticated,
            required_quorum: required_other_peers,
        });
        let readiness = if authenticated >= required_other_peers {
            admin_v30::get_write_readiness_response::Readiness::Ready(
                admin_v30::get_write_readiness_response::Ready { p2p },
            )
        } else {
            admin_v30::get_write_readiness_response::Readiness::P2pNotReady(
                admin_v30::get_write_readiness_response::P2pNotReady { p2p },
            )
        };
        Ok(Response::new(admin_v30::GetWriteReadinessResponse {
            readiness: Some(readiness),
        }))
    }

    async fn get_ordering_topology(
        &self,
        _request: Request<admin_v30::GetOrderingTopologyRequest>,
    ) -> Result<Response<admin_v30::GetOrderingTopologyResponse>, Status> {
        let (current_epoch, sequencer_ids, leader_sequencer_ids, blacklisted_sequencer_ids) =
            self.consensus.ordering_topology();
        let params = bft_v31::DynamicSequencingParametersPayload {
            pbft_view_change_timeout: Some(prost_types::Duration {
                seconds: 1,
                nanos: 0,
            }),
            segment_length: self.epoch_length,
            blacklist_leader_selection_policy: Some(bft_v31::BlacklistLeaderSelectionPolicy {
                how_long_to_blacklist: Some(
                    bft_v31::blacklist_leader_selection_policy::HowLongToBlacklist::HowLongLinear(
                        bft_v31::HowLongLinear {
                            maximum_epoch_length_blacklisted: Some(250),
                        },
                    ),
                ),
                how_many_can_we_blacklist: Some(
                    bft_v31::blacklist_leader_selection_policy::HowManyCanWeBlacklist::HowManyNumFaultsTolerated(
                        bft_v31::HowManyNumFaultsTolerated {},
                    ),
                ),
            }),
            max_requests_in_batch: 16,
            max_batches_per_proposal: 16,
            pbft_view_change_timeout_step: None,
            pbft_view_change_timeout_upper_bound: None,
            stricter_detection_of_requests_potentially_changing_ordering_topology: false,
        };
        Ok(Response::new(admin_v30::GetOrderingTopologyResponse {
            current_epoch,
            sequencer_ids,
            leader_sequencer_ids,
            blacklisted_sequencer_ids,
            dynamic_sequencing_parameters: Some(
                admin_v30::get_ordering_topology_response::DynamicSequencingParameters::DynamicSequencingParametersPayload31(
                    params,
                ),
            ),
        }))
    }

    async fn set_performance_metrics_enabled(
        &self,
        request: Request<admin_v30::SetPerformanceMetricsEnabledRequest>,
    ) -> Result<Response<admin_v30::SetPerformanceMetricsEnabledResponse>, Status> {
        self.consensus
            .set_performance_metrics_enabled(request.into_inner().enabled);
        Ok(Response::new(
            admin_v30::SetPerformanceMetricsEnabledResponse {},
        ))
    }
}

struct PruningState {
    ord_store: Option<Arc<OrdStore>>,
    consensus: Option<Arc<Consensus>>,
    in_memory_schedule: Mutex<Option<OrdPruningSchedule>>,
    scheduler_stop: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

/// Implements `com.digitalasset.canton.sequencer.admin.v30.SequencerBftPruningAdministrationService`.
#[derive(Clone)]
pub struct BftPruningAdminService {
    inner: Arc<PruningState>,
}

impl BftPruningAdminService {
    pub fn new(ord_store: Option<Arc<OrdStore>>, consensus: Option<Arc<Consensus>>) -> Self {
        Self {
            inner: Arc::new(PruningState {
                ord_store,
                consensus,
                in_memory_schedule: Mutex::new(None),
                scheduler_stop: Mutex::new(None),
            }),
        }
    }

    fn save_schedule(&self, sched: &OrdPruningSchedule) -> Result<(), Status> {
        if let Some(store) = &self.inner.ord_store {
            store
                .set_bft_schedule(sched.clone())
                .map_err(Status::internal)?;
        } else if let Ok(mut guard) = self.inner.in_memory_schedule.lock() {
            *guard = Some(sched.clone());
        }
        self.restart_background_scheduler(Some(sched.clone()));
        Ok(())
    }

    fn load_schedule(&self) -> Result<Option<OrdPruningSchedule>, Status> {
        if let Some(store) = &self.inner.ord_store {
            store.get_bft_schedule().map_err(Status::internal)
        } else {
            Ok(self
                .inner
                .in_memory_schedule
                .lock()
                .ok()
                .and_then(|g| g.clone()))
        }
    }

    fn restart_background_scheduler(&self, schedule: Option<OrdPruningSchedule>) {
        if let Ok(mut stop_guard) = self.inner.scheduler_stop.lock() {
            if let Some(old) = stop_guard.take() {
                old.notify_waiters();
            }
            if let Some(sched) = schedule {
                let stop = Arc::new(tokio::sync::Notify::new());
                *stop_guard = Some(Arc::clone(&stop));
                let inner = Arc::clone(&self.inner);
                let interval = Duration::from_secs(
                    u64::try_from(sched.max_duration_secs).unwrap_or(60).max(1),
                );
                tokio::spawn(async move {
                    let retention_micros = sched.retention_secs.saturating_mul(1_000_000);
                    loop {
                        tokio::select! {
                            _ = tokio::time::sleep(interval) => {
                                if let Some(store) = &inner.ord_store {
                                    let _ = store.prune(retention_micros, sched.min_blocks_to_keep);
                                }
                            }
                            _ = stop.notified() => break,
                        }
                    }
                });
            }
        }
    }
}

fn positive_secs(name: &str, dur: Option<prost_types::Duration>) -> Result<i64, Status> {
    let d = dur.ok_or_else(|| Status::invalid_argument(format!("{name} must be set")))?;
    if d.seconds <= 0 && d.nanos <= 0 {
        return Err(Status::invalid_argument(format!("{name} must be positive")));
    }
    if d.seconds < 0 || d.nanos < 0 {
        return Err(Status::invalid_argument(format!(
            "{name} cannot be negative"
        )));
    }
    Ok(d.seconds.max(1))
}

fn positive_micros(name: &str, dur: Option<prost_types::Duration>) -> Result<i64, Status> {
    let d = dur.ok_or_else(|| Status::invalid_argument(format!("{name} must be set")))?;
    if d.seconds < 0 || d.nanos < 0 || (d.seconds == 0 && d.nanos == 0) {
        return Err(Status::invalid_argument(format!("{name} must be positive")));
    }
    Ok(d.seconds
        .saturating_mul(1_000_000)
        .saturating_add(i64::from(d.nanos / 1_000)))
}

fn validate_pruning_schedule(
    ps: Option<pruning_v30::PruningSchedule>,
    min_blocks_to_keep: i32,
) -> Result<OrdPruningSchedule, Status> {
    let s = ps.ok_or_else(|| Status::invalid_argument("schedule must be set"))?;
    if s.cron.trim().is_empty() {
        return Err(Status::invalid_argument("cron expression cannot be empty"));
    }
    if min_blocks_to_keep < 0 {
        return Err(Status::invalid_argument(
            "min_blocks_to_keep cannot be negative",
        ));
    }
    Ok(OrdPruningSchedule {
        cron: s.cron,
        max_duration_secs: positive_secs("max_duration", s.max_duration)?,
        retention_secs: positive_secs("retention", s.retention)?,
        min_blocks_to_keep,
    })
}

fn schedule_to_proto(s: &OrdPruningSchedule) -> pruning_v30::PruningSchedule {
    pruning_v30::PruningSchedule {
        cron: s.cron.clone(),
        max_duration: Some(prost_types::Duration {
            seconds: s.max_duration_secs,
            nanos: 0,
        }),
        retention: Some(prost_types::Duration {
            seconds: s.retention_secs,
            nanos: 0,
        }),
    }
}

fn bft_schedule_to_proto(s: &OrdPruningSchedule) -> admin_v30::BftOrdererPruningSchedule {
    admin_v30::BftOrdererPruningSchedule {
        schedule: Some(schedule_to_proto(s)),
        min_blocks_to_keep: s.min_blocks_to_keep,
    }
}

fn micros_to_timestamp(micros: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: micros.div_euclid(1_000_000),
        nanos: (micros.rem_euclid(1_000_000) * 1_000) as i32,
    }
}

#[tonic::async_trait]
impl
    admin_v30::sequencer_bft_pruning_administration_service_server::SequencerBftPruningAdministrationService
    for BftPruningAdminService
{
    async fn bft_pruning_status(
        &self,
        _request: Request<admin_v30::BftPruningStatusRequest>,
    ) -> Result<Response<admin_v30::BftPruningStatusResponse>, Status> {
        let st = if let Some(store) = &self.inner.ord_store {
            store.pruning_status().map_err(Status::internal)?
        } else if let Some(c) = &self.inner.consensus {
            let (ep, blk, ts) = c.latest_output_info();
            OrdPruningStatus {
                latest_block_epoch: ep,
                latest_block: blk,
                latest_block_ts_micros: ts,
                lower_bound_epoch: 0,
                lower_bound_block: 0,
            }
        } else {
            OrdPruningStatus::default()
        };
        Ok(Response::new(admin_v30::BftPruningStatusResponse {
            latest_block_epoch: st.latest_block_epoch,
            latest_block: st.latest_block,
            latest_block_timestamp: Some(micros_to_timestamp(
                st.latest_block_ts_micros.unwrap_or(0),
            )),
            lower_bound_epoch: st.lower_bound_epoch,
            lower_bound_block: st.lower_bound_block,
        }))
    }

    async fn bft_prune(
        &self,
        request: Request<admin_v30::BftPruneRequest>,
    ) -> Result<Response<admin_v30::BftPruneResponse>, Status> {
        let req = request.into_inner();
        if req.min_blocks_to_keep < 0 {
            return Err(Status::invalid_argument(
                "min_blocks_to_keep cannot be negative",
            ));
        }
        let retention_micros = positive_micros("retention", req.retention)?;
        let message = if let Some(store) = &self.inner.ord_store {
            store
                .prune(retention_micros, req.min_blocks_to_keep)
                .map_err(Status::internal)?
        } else {
            "No persistent BFT DB configured; in-memory pruning is a no-op".to_string()
        };
        Ok(Response::new(admin_v30::BftPruneResponse { message }))
    }

    async fn set_schedule(
        &self,
        request: Request<pruning_v30::SetScheduleRequest>,
    ) -> Result<Response<pruning_v30::SetScheduleResponse>, Status> {
        let sched =
            validate_pruning_schedule(request.into_inner().schedule, DEFAULT_MIN_BLOCKS_TO_KEEP)?;
        self.save_schedule(&sched)?;
        Ok(Response::new(pruning_v30::SetScheduleResponse {}))
    }

    async fn set_bft_schedule(
        &self,
        request: Request<admin_v30::SetBftScheduleRequest>,
    ) -> Result<Response<admin_v30::SetBftScheduleResponse>, Status> {
        let bft = request
            .into_inner()
            .schedule
            .ok_or_else(|| Status::invalid_argument("bft_orderer_schedule must be set"))?;
        let sched = validate_pruning_schedule(bft.schedule, bft.min_blocks_to_keep)?;
        self.save_schedule(&sched)?;
        Ok(Response::new(admin_v30::SetBftScheduleResponse {}))
    }

    async fn set_cron(
        &self,
        request: Request<pruning_v30::SetCronRequest>,
    ) -> Result<Response<pruning_v30::SetCronResponse>, Status> {
        let cron = request.into_inner().cron;
        if cron.trim().is_empty() {
            return Err(Status::invalid_argument("cron expression cannot be empty"));
        }
        if let Some(store) = &self.inner.ord_store {
            store
                .update_cron(cron)
                .map_err(Status::invalid_argument)?;
        } else {
            let mut guard = self
                .inner
                .in_memory_schedule
                .lock()
                .map_err(|e| Status::internal(e.to_string()))?;
            let s = guard
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("No pruning schedule configured"))?;
            s.cron = cron;
        }
        Ok(Response::new(pruning_v30::SetCronResponse {}))
    }

    async fn set_max_duration(
        &self,
        request: Request<pruning_v30::SetMaxDurationRequest>,
    ) -> Result<Response<pruning_v30::SetMaxDurationResponse>, Status> {
        let secs = positive_secs("max_duration", request.into_inner().max_duration)?;
        if let Some(store) = &self.inner.ord_store {
            store
                .update_max_duration(secs)
                .map_err(Status::invalid_argument)?;
        } else {
            let mut guard = self
                .inner
                .in_memory_schedule
                .lock()
                .map_err(|e| Status::internal(e.to_string()))?;
            let s = guard
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("No pruning schedule configured"))?;
            s.max_duration_secs = secs;
        }
        let updated = self.load_schedule()?;
        self.restart_background_scheduler(updated);
        Ok(Response::new(pruning_v30::SetMaxDurationResponse {}))
    }

    async fn set_retention(
        &self,
        request: Request<pruning_v30::SetRetentionRequest>,
    ) -> Result<Response<pruning_v30::SetRetentionResponse>, Status> {
        let secs = positive_secs("retention", request.into_inner().retention)?;
        if let Some(store) = &self.inner.ord_store {
            store
                .update_retention(secs)
                .map_err(Status::invalid_argument)?;
        } else {
            let mut guard = self
                .inner
                .in_memory_schedule
                .lock()
                .map_err(|e| Status::internal(e.to_string()))?;
            let s = guard
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("No pruning schedule configured"))?;
            s.retention_secs = secs;
        }
        let updated = self.load_schedule()?;
        self.restart_background_scheduler(updated);
        Ok(Response::new(pruning_v30::SetRetentionResponse {}))
    }

    async fn clear_schedule(
        &self,
        _request: Request<pruning_v30::ClearScheduleRequest>,
    ) -> Result<Response<pruning_v30::ClearScheduleResponse>, Status> {
        if let Some(store) = &self.inner.ord_store {
            store.clear_schedule().map_err(Status::internal)?;
        } else if let Ok(mut guard) = self.inner.in_memory_schedule.lock() {
            *guard = None;
        }
        self.restart_background_scheduler(None);
        Ok(Response::new(pruning_v30::ClearScheduleResponse {}))
    }

    async fn get_schedule(
        &self,
        _request: Request<pruning_v30::GetScheduleRequest>,
    ) -> Result<Response<pruning_v30::GetScheduleResponse>, Status> {
        let schedule = self.load_schedule()?.map(|s| schedule_to_proto(&s));
        Ok(Response::new(pruning_v30::GetScheduleResponse { schedule }))
    }

    async fn get_bft_schedule(
        &self,
        _request: Request<admin_v30::GetBftScheduleRequest>,
    ) -> Result<Response<admin_v30::GetBftScheduleResponse>, Status> {
        let schedule = self.load_schedule()?.map(|s| bft_schedule_to_proto(&s));
        Ok(Response::new(admin_v30::GetBftScheduleResponse {
            schedule,
        }))
    }

    async fn set_min_blocks_to_keep(
        &self,
        request: Request<admin_v30::SetMinBlocksToKeepRequest>,
    ) -> Result<Response<admin_v30::SetMinBlocksToKeepResponse>, Status> {
        let min_blocks = request.into_inner().min_blocks_to_keep;
        if min_blocks < 0 {
            return Err(Status::invalid_argument(
                "min_blocks_to_keep cannot be negative",
            ));
        }
        if let Some(store) = &self.inner.ord_store {
            store
                .update_min_blocks_to_keep(min_blocks)
                .map_err(Status::invalid_argument)?;
        } else {
            let mut guard = self
                .inner
                .in_memory_schedule
                .lock()
                .map_err(|e| Status::internal(e.to_string()))?;
            let s = guard
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("No pruning schedule configured"))?;
            s.min_blocks_to_keep = min_blocks;
        }
        let updated = self.load_schedule()?;
        self.restart_background_scheduler(updated);
        Ok(Response::new(admin_v30::SetMinBlocksToKeepResponse {}))
    }
}
