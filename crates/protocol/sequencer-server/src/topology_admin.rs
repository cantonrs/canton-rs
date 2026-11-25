//! The topology administration a synchronizer's operator uses to onboard a mediator after genesis (B2, S-LOCAL-011): Canton's
//! `TopologyManagerWriteService` (`AddTransactions`, `Authorize`) and `TopologyManagerReadService` (`ListMediatorSynchronizerState`), served
//! by the Rust sequencer for its synchronizer's store. These are the calls the official console makes for `mediators.groups.propose_new_group`
//! and `propose_delta`: `topology.transactions.load(<the mediator's onboarding transactions>, <synchronizer>, ForceFlag.AlienMember)`, then
//! `topology.mediators.list` and `topology.mediators.propose` (see `crate::mediator_identity` for what was measured on the official node).
//!
//! [CANTON-NOTE: SEMANTICS] The transactions an operator loads are sequenced to every member as one topology broadcast and kept when they are
//! authorized; a mediator group change is signed by the synchronizer's owners (the keys the sequencer holds) and sequenced as a broadcast of
//! its own. The sequencer makes the mediators the topology names members ([`crate::sequencing::Sequencer::follow_mediators`]).
//!
//! [CANTON-NOTE: LIMITATION] Only the synchronizer's own store is served, only a mediator group change is authorized (`AddReplace`), and a
//! loaded transaction is validated as it is sequenced (an unauthorized one is broadcast and then not kept, where the official node refuses
//! it before broadcasting). The service is on the sequencer's public port, as its other administration services are here: whoever reaches
//! the port can have the owners' keys sign a mediator group change. Every other call answers `UNIMPLEMENTED`.
use crate::sequencing::Sequencer;
use crate::SynchronizerConfig;
use admin::topology_manager_read_service_server::TopologyManagerReadService;
use admin::topology_manager_write_service_server::TopologyManagerWriteService;
use canton_participant::topology_state::Outcome;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::protocol::{v30, v31};
use canton_proto::com::digitalasset::canton::topology::admin::v30 as admin;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

#[derive(Clone)]
pub struct TopologyAdmin {
    config: SynchronizerConfig,
    sequencer: Sequencer,
}

impl TopologyAdmin {
    pub fn new(config: SynchronizerConfig, sequencer: Sequencer) -> Self {
        Self { config, sequencer }
    }

    /// Refuses a store that is not this synchronizer's.
    fn check_store(&self, store: Option<&admin::StoreId>) -> Result<(), Status> {
        use admin::store_id::Store;
        use admin::synchronizer::Kind;
        let ours = match store.and_then(|s| s.store.as_ref()) {
            Some(Store::Synchronizer(admin::Synchronizer {
                kind: Some(Kind::Id(id)),
            })) => *id == self.config.synchronizer_uid(),
            Some(Store::Synchronizer(admin::Synchronizer {
                kind: Some(Kind::PhysicalId(id)),
            })) => *id == self.config.physical_synchronizer_id(),
            _ => false,
        };
        if ours {
            Ok(())
        } else {
            Err(Status::invalid_argument(format!(
                "the Rust sequencer serves only the store of its synchronizer {}",
                self.config.synchronizer_uid()
            )))
        }
    }
}

fn not_served<T>(what: &str) -> Result<Response<T>, Status> {
    Err(Status::unimplemented(format!(
        "{what} is not served by the Rust sequencer"
    )))
}

fn timestamp(micros: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: micros.div_euclid(1_000_000),
        nanos: (micros.rem_euclid(1_000_000) * 1_000) as i32,
    }
}

/// The mediator group change a proposal carries, whatever the version of its mapping.
fn mediator_state_of(
    proposal: &admin::authorize_request::Proposal,
) -> Option<v30::MediatorSynchronizerState> {
    use admin::authorize_request::proposal::Mapping as Versioned;
    match proposal.mapping.as_ref()? {
        Versioned::V31(v31::TopologyMapping {
            mapping: Some(v31::topology_mapping::Mapping::MediatorSynchronizerState(m)),
        }) => Some(m.clone()),
        Versioned::V30(v30::TopologyMapping {
            mapping: Some(v30::topology_mapping::Mapping::MediatorSynchronizerState(m)),
        }) => Some(m.clone()),
        _ => None,
    }
}

/// Asked to wait for the change to take effect: the topology change delay, and a little more.
async fn wait_until_effective(wait: bool) {
    if wait {
        tokio::time::sleep(std::time::Duration::from_micros(
            crate::synchronizer_state::TOPOLOGY_CHANGE_DELAY_MICROS as u64 + 100_000,
        ))
        .await;
    }
}

/// Refused unless every outcome put its transaction in force.
fn all_in_force(outcomes: &[Outcome]) -> Result<(), Status> {
    let refused: Vec<&str> = outcomes
        .iter()
        .filter(|o| !o.is_in_force())
        .map(|o| o.note())
        .collect();
    if refused.is_empty() {
        Ok(())
    } else {
        Err(Status::failed_precondition(format!(
            "TOPOLOGY_TRANSACTION_NOT_AUTHORIZED: {}",
            refused.join("; ")
        )))
    }
}

#[tonic::async_trait]
impl TopologyManagerWriteService for TopologyAdmin {
    async fn add_transactions(
        &self,
        request: Request<admin::AddTransactionsRequest>,
    ) -> Result<Response<admin::AddTransactionsResponse>, Status> {
        let request = request.into_inner();
        self.check_store(request.store.as_ref())?;
        crate::diag::diag_eprintln!(
            "RPC AddTransactions {} transaction(s)",
            request.transactions.len()
        );
        if request.transactions.is_empty() {
            return Ok(Response::new(admin::AddTransactionsResponse {}));
        }
        if self.sequencer.has_orderer() {
            self.sequencer
                .order_topology_broadcast(&request.transactions)
                .await?;
        } else {
            all_in_force(
                &self
                    .sequencer
                    .sequence_topology_outcomes(&request.transactions),
            )?;
        }
        wait_until_effective(request.wait_to_become_effective.is_some()).await;
        Ok(Response::new(admin::AddTransactionsResponse {}))
    }

    async fn authorize(
        &self,
        request: Request<admin::AuthorizeRequest>,
    ) -> Result<Response<admin::AuthorizeResponse>, Status> {
        let request = request.into_inner();
        self.check_store(request.store.as_ref())?;
        let Some(admin::authorize_request::Type::Proposal(proposal)) = request.r#type else {
            return not_served("authorizing a transaction by its hash");
        };
        let Some(state) = mediator_state_of(&proposal) else {
            return not_served("authorizing anything but a mediator group change");
        };
        if proposal.change != v30::enums::TopologyChangeOp::AddReplace as i32 {
            return not_served("removing a mediator group");
        }
        if state.synchronizer_id != self.config.synchronizer_uid() {
            return Err(Status::invalid_argument(format!(
                "a mediator group of {} on the synchronizer {}",
                state.synchronizer_id,
                self.config.synchronizer_uid()
            )));
        }
        let store = self.sequencer.store();
        // the serial: the one asked for, else the next one of the group
        let serial = if proposal.serial > 0 {
            proposal.serial
        } else {
            store
                .mediator_states()
                .iter()
                .find(|(_, stored)| mediator_group_index(&stored.signed) == Some(state.group))
                .map_or(1, |(g, _)| g.serial + 1)
        };
        let bytes = tw::mediator_synchronizer_state_at(
            &state.synchronizer_id,
            state.group,
            state.threshold,
            &state.active,
            &state.observers,
            serial,
        );
        let signed = crate::synchronizer_state::signed_by_owners(&self.config.keys, bytes);
        crate::diag::diag_eprintln!(
            "RPC Authorize mediator group {} serial {serial} active {:?}",
            state.group,
            state.active
        );
        if self.sequencer.has_orderer() {
            self.sequencer
                .order_topology_broadcast(std::slice::from_ref(&signed))
                .await?;
        } else {
            all_in_force(
                &self
                    .sequencer
                    .sequence_topology_outcomes(std::slice::from_ref(&signed)),
            )?;
        }
        wait_until_effective(request.wait_to_become_effective.is_some()).await;
        Ok(Response::new(admin::AuthorizeResponse {
            transaction: Some(signed),
        }))
    }

    async fn import_topology_snapshot(
        &self,
        _request: Request<tonic::Streaming<admin::ImportTopologySnapshotRequest>>,
    ) -> Result<Response<admin::ImportTopologySnapshotResponse>, Status> {
        not_served("import_topology_snapshot")
    }
    async fn import_topology_snapshot_v2(
        &self,
        _request: Request<tonic::Streaming<admin::ImportTopologySnapshotV2Request>>,
    ) -> Result<Response<admin::ImportTopologySnapshotV2Response>, Status> {
        not_served("import_topology_snapshot_v2")
    }
    async fn sign_transactions(
        &self,
        _request: Request<admin::SignTransactionsRequest>,
    ) -> Result<Response<admin::SignTransactionsResponse>, Status> {
        not_served("sign_transactions")
    }
    async fn generate_transactions(
        &self,
        _request: Request<admin::GenerateTransactionsRequest>,
    ) -> Result<Response<admin::GenerateTransactionsResponse>, Status> {
        not_served("generate_transactions")
    }
    async fn create_temporary_topology_store(
        &self,
        _request: Request<admin::CreateTemporaryTopologyStoreRequest>,
    ) -> Result<Response<admin::CreateTemporaryTopologyStoreResponse>, Status> {
        not_served("create_temporary_topology_store")
    }
    async fn drop_temporary_topology_store(
        &self,
        _request: Request<admin::DropTemporaryTopologyStoreRequest>,
    ) -> Result<Response<admin::DropTemporaryTopologyStoreResponse>, Status> {
        not_served("drop_temporary_topology_store")
    }
}

/// The group of a stored `MediatorSynchronizerState`.
fn mediator_group_index(signed: &v30::SignedTopologyTransaction) -> Option<u32> {
    let entries =
        canton_participant::topology_state::decode(&[(0, tw::stored_form(signed))]).ok()?;
    match entries[0].tx.mapping.as_ref()?.mapping.as_ref()? {
        v31::topology_mapping::Mapping::MediatorSynchronizerState(m) => Some(m.group),
        _ => None,
    }
}

#[tonic::async_trait]
impl TopologyManagerReadService for TopologyAdmin {
    async fn list_mediator_synchronizer_state(
        &self,
        request: Request<admin::ListMediatorSynchronizerStateRequest>,
    ) -> Result<Response<admin::ListMediatorSynchronizerStateResponse>, Status> {
        let request = request.into_inner();
        let query = request.base_query.unwrap_or_default();
        self.check_store(query.store.as_ref())?;
        if query.proposals {
            return Ok(Response::new(Default::default()));
        }
        let results = self
            .sequencer
            .store()
            .mediator_states()
            .into_iter()
            .filter_map(|(group, stored)| {
                let index = mediator_group_index(&stored.signed)?;
                let synchronizer_id = self.config.synchronizer_uid();
                if !synchronizer_id.starts_with(&request.filter_synchronizer_id) {
                    return None;
                }
                Some(admin::list_mediator_synchronizer_state_response::Result {
                    context: Some(admin::BaseResult {
                        store: query.store.clone(),
                        sequenced: Some(timestamp(stored.sequenced_micros)),
                        valid_from: Some(timestamp(stored.valid_from_micros)),
                        valid_until: None,
                        operation: v30::enums::TopologyChangeOp::AddReplace as i32,
                        transaction_hash: tw::transaction_hash(&stored.signed.transaction),
                        serial: group.serial as i32,
                        signed_by_fingerprints: stored
                            .signed
                            .signatures
                            .iter()
                            .map(|s| s.signed_by.clone())
                            .collect(),
                    }),
                    item: Some(v30::MediatorSynchronizerState {
                        synchronizer_id,
                        group: index,
                        threshold: group.threshold,
                        active: group.active,
                        observers: group.observers,
                    }),
                })
            })
            .collect();
        Ok(Response::new(
            admin::ListMediatorSynchronizerStateResponse { results },
        ))
    }

    type GenesisStateStream =
        Pin<Box<dyn Stream<Item = Result<admin::GenesisStateResponse, Status>> + Send>>;
    type GenesisStateV2Stream =
        Pin<Box<dyn Stream<Item = Result<admin::GenesisStateV2Response, Status>> + Send>>;
    type ExportTopologySnapshotStream =
        Pin<Box<dyn Stream<Item = Result<admin::ExportTopologySnapshotResponse, Status>> + Send>>;
    type ExportTopologySnapshotV2Stream =
        Pin<Box<dyn Stream<Item = Result<admin::ExportTopologySnapshotV2Response, Status>> + Send>>;
    type SequencerLsuStateStream =
        Pin<Box<dyn Stream<Item = Result<admin::SequencerLsuStateResponse, Status>> + Send>>;
    async fn list_namespace_delegation(
        &self,
        _request: Request<admin::ListNamespaceDelegationRequest>,
    ) -> Result<Response<admin::ListNamespaceDelegationResponse>, Status> {
        not_served("list_namespace_delegation")
    }
    async fn list_decentralized_namespace_definition(
        &self,
        _request: Request<admin::ListDecentralizedNamespaceDefinitionRequest>,
    ) -> Result<Response<admin::ListDecentralizedNamespaceDefinitionResponse>, Status> {
        not_served("list_decentralized_namespace_definition")
    }
    async fn list_owner_to_key_mapping(
        &self,
        _request: Request<admin::ListOwnerToKeyMappingRequest>,
    ) -> Result<Response<admin::ListOwnerToKeyMappingResponse>, Status> {
        not_served("list_owner_to_key_mapping")
    }
    async fn list_party_to_key_mapping(
        &self,
        _request: Request<admin::ListPartyToKeyMappingRequest>,
    ) -> Result<Response<admin::ListPartyToKeyMappingResponse>, Status> {
        not_served("list_party_to_key_mapping")
    }
    async fn list_synchronizer_trust_certificate(
        &self,
        _request: Request<admin::ListSynchronizerTrustCertificateRequest>,
    ) -> Result<Response<admin::ListSynchronizerTrustCertificateResponse>, Status> {
        not_served("list_synchronizer_trust_certificate")
    }
    async fn list_participant_synchronizer_permission(
        &self,
        _request: Request<admin::ListParticipantSynchronizerPermissionRequest>,
    ) -> Result<Response<admin::ListParticipantSynchronizerPermissionResponse>, Status> {
        not_served("list_participant_synchronizer_permission")
    }
    async fn list_party_hosting_limits(
        &self,
        _request: Request<admin::ListPartyHostingLimitsRequest>,
    ) -> Result<Response<admin::ListPartyHostingLimitsResponse>, Status> {
        not_served("list_party_hosting_limits")
    }
    async fn list_vetted_packages(
        &self,
        _request: Request<admin::ListVettedPackagesRequest>,
    ) -> Result<Response<admin::ListVettedPackagesResponse>, Status> {
        not_served("list_vetted_packages")
    }
    async fn list_party_to_participant(
        &self,
        _request: Request<admin::ListPartyToParticipantRequest>,
    ) -> Result<Response<admin::ListPartyToParticipantResponse>, Status> {
        not_served("list_party_to_participant")
    }
    async fn list_synchronizer_parameters_state(
        &self,
        _request: Request<admin::ListSynchronizerParametersStateRequest>,
    ) -> Result<Response<admin::ListSynchronizerParametersStateResponse>, Status> {
        not_served("list_synchronizer_parameters_state")
    }
    async fn list_sequencing_parameters_state(
        &self,
        _request: Request<admin::ListSequencingParametersStateRequest>,
    ) -> Result<Response<admin::ListSequencingParametersStateResponse>, Status> {
        not_served("list_sequencing_parameters_state")
    }
    async fn list_sequencer_synchronizer_state(
        &self,
        _request: Request<admin::ListSequencerSynchronizerStateRequest>,
    ) -> Result<Response<admin::ListSequencerSynchronizerStateResponse>, Status> {
        not_served("list_sequencer_synchronizer_state")
    }
    async fn list_lsu_announcement(
        &self,
        _request: Request<admin::ListLsuAnnouncementRequest>,
    ) -> Result<Response<admin::ListLsuAnnouncementResponse>, Status> {
        not_served("list_lsu_announcement")
    }
    async fn list_lsu_sequencer_connection_successor(
        &self,
        _request: Request<admin::ListLsuSequencerConnectionSuccessorRequest>,
    ) -> Result<Response<admin::ListLsuSequencerConnectionSuccessorResponse>, Status> {
        not_served("list_lsu_sequencer_connection_successor")
    }
    async fn list_available_stores(
        &self,
        _request: Request<admin::ListAvailableStoresRequest>,
    ) -> Result<Response<admin::ListAvailableStoresResponse>, Status> {
        not_served("list_available_stores")
    }
    async fn list_all(
        &self,
        _request: Request<admin::ListAllRequest>,
    ) -> Result<Response<admin::ListAllResponse>, Status> {
        not_served("list_all")
    }
    async fn list_all_v2(
        &self,
        _request: Request<admin::ListAllV2Request>,
    ) -> Result<Response<admin::ListAllV2Response>, Status> {
        not_served("list_all_v2")
    }
    async fn export_topology_snapshot(
        &self,
        _request: Request<admin::ExportTopologySnapshotRequest>,
    ) -> Result<Response<Self::ExportTopologySnapshotStream>, Status> {
        not_served("export_topology_snapshot")
    }
    async fn export_topology_snapshot_v2(
        &self,
        _request: Request<admin::ExportTopologySnapshotV2Request>,
    ) -> Result<Response<Self::ExportTopologySnapshotV2Stream>, Status> {
        not_served("export_topology_snapshot_v2")
    }
    async fn genesis_state(
        &self,
        _request: Request<admin::GenesisStateRequest>,
    ) -> Result<Response<Self::GenesisStateStream>, Status> {
        not_served("genesis_state")
    }
    async fn genesis_state_v2(
        &self,
        _request: Request<admin::GenesisStateV2Request>,
    ) -> Result<Response<Self::GenesisStateV2Stream>, Status> {
        not_served("genesis_state_v2")
    }
    async fn sequencer_lsu_state(
        &self,
        _request: Request<admin::SequencerLsuStateRequest>,
    ) -> Result<Response<Self::SequencerLsuStateStream>, Status> {
        not_served("sequencer_lsu_state")
    }
    async fn generate_onboarding_topology_transactions(
        &self,
        _request: Request<admin::GenerateOnboardingTopologyTransactionsRequest>,
    ) -> Result<Response<admin::GenerateOnboardingTopologyTransactionsResponse>, Status> {
        not_served("generate_onboarding_topology_transactions")
    }
}

/// What [`onboard_mediator`] did: the mediator group as it now stands, signed.
pub struct Onboarded {
    pub group: u32,
    pub serial: u32,
    pub active: Vec<String>,
    pub transaction: v30::SignedTopologyTransaction,
}

/// The operator's side of a mediator's onboarding, against the topology administration of a synchronizer's sequencer at `admin_url` (the
/// Rust sequencer's public port, or an official sequencer's admin API): what the console's `mediators.groups.propose_delta` does. The
/// mediator's onboarding `transactions` are loaded into the store of `physical_synchronizer_id` (with `ForceFlag.AlienMember`), the
/// group's current state is read, and a new state naming `mediator_uid` is authorized: added to the active mediators, or the only one when
/// `replace` (a group that does not exist yet starts with it, threshold 1).
pub fn onboard_mediator(
    admin_url: &str,
    physical_synchronizer_id: &str,
    transactions: Vec<v30::SignedTopologyTransaction>,
    mediator_uid: &str,
    group: u32,
    replace: bool,
) -> Result<Onboarded, String> {
    use admin::topology_manager_read_service_client::TopologyManagerReadServiceClient;
    use admin::topology_manager_write_service_client::TopologyManagerWriteServiceClient;
    let logical = physical_synchronizer_id
        .rsplit_once("::")
        .map(|(l, _)| l.to_string())
        .ok_or_else(|| format!("{physical_synchronizer_id} is no physical synchronizer id"))?;
    let store = admin::StoreId {
        store: Some(admin::store_id::Store::Synchronizer(admin::Synchronizer {
            kind: Some(admin::synchronizer::Kind::PhysicalId(
                physical_synchronizer_id.to_string(),
            )),
        })),
    };
    let wait = Some(prost_types::Duration {
        seconds: 30,
        nanos: 0,
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let channel = tonic::transport::Channel::from_shared(admin_url.to_string())
            .map_err(|e| e.to_string())?
            .connect()
            .await
            .map_err(|e| format!("{admin_url}: {e}"))?;
        let mut write = TopologyManagerWriteServiceClient::new(channel.clone());
        let mut read = TopologyManagerReadServiceClient::new(channel);
        let current = read
            .list_mediator_synchronizer_state(admin::ListMediatorSynchronizerStateRequest {
                base_query: Some(admin::BaseQuery {
                    store: Some(store.clone()),
                    proposals: false,
                    operation: 0,
                    filter_signed_key: String::new(),
                    protocol_version: None,
                    client_version: None,
                    time_query: Some(admin::base_query::TimeQuery::HeadState(())),
                }),
                filter_synchronizer_id: logical.clone(),
            })
            .await
            .map_err(|e| format!("reading the mediator groups: {}", e.message()))?
            .into_inner()
            .results
            .into_iter()
            .filter(|r| r.item.as_ref().is_some_and(|i| i.group == group))
            .max_by_key(|r| r.context.as_ref().map_or(0, |c| c.serial));
        // [CANTON-NOTE: SEMANTICS] A mediator the group already names is onboarded: a restart of the daemon asks again and changes nothing (the
        // transactions of its identity are in the store, the state names it), where loading them a second time is refused as not authorized.
        if let Some(r) = &current {
            let item = r.item.clone().unwrap_or_default();
            let already = item.active.iter().any(|m| m == mediator_uid)
                && (!replace || item.active.len() == 1);
            if already {
                return Ok(Onboarded {
                    group,
                    serial: r.context.as_ref().map_or(0, |c| c.serial) as u32,
                    active: item.active,
                    transaction: v30::SignedTopologyTransaction::default(),
                });
            }
        }
        write
            .add_transactions(admin::AddTransactionsRequest {
                transactions,
                force_changes: vec![admin::ForceFlag::AlienMember as i32],
                store: Some(store.clone()),
                wait_to_become_effective: wait,
            })
            .await
            .map_err(|e| format!("loading the mediator's identity: {}", e.message()))?;
        let (serial, threshold, mut active, observers) = match &current {
            Some(r) => {
                let item = r.item.clone().unwrap_or_default();
                let serial = r.context.as_ref().map_or(0, |c| c.serial) as u32;
                (
                    serial + 1,
                    item.threshold.max(1),
                    item.active,
                    item.observers,
                )
            }
            None => (1, 1, Vec::new(), Vec::new()),
        };
        if replace {
            active.clear();
        }
        if !active.iter().any(|m| m == mediator_uid) {
            active.push(mediator_uid.to_string());
        }
        let state = v30::MediatorSynchronizerState {
            synchronizer_id: logical.clone(),
            group,
            threshold: if replace { 1 } else { threshold },
            active: active.clone(),
            observers,
        };
        let answer = write
            .authorize(admin::AuthorizeRequest {
                r#type: Some(admin::authorize_request::Type::Proposal(
                    admin::authorize_request::Proposal {
                        change: v30::enums::TopologyChangeOp::AddReplace as i32,
                        serial,
                        mapping: Some(admin::authorize_request::proposal::Mapping::V31(
                            v31::TopologyMapping {
                                mapping: Some(
                                    v31::topology_mapping::Mapping::MediatorSynchronizerState(
                                        state,
                                    ),
                                ),
                            },
                        )),
                        protocol_version: None,
                    },
                )),
                must_fully_authorize: true,
                force_changes: Vec::new(),
                signed_by: Vec::new(),
                store: Some(store),
                wait_to_become_effective: wait,
            })
            .await
            .map_err(|e| format!("authorizing the mediator group: {}", e.message()))?
            .into_inner();
        Ok(Onboarded {
            group,
            serial,
            active,
            transaction: answer.transaction.unwrap_or_default(),
        })
    })
}

/// What `onboard_sequencer` did.
#[derive(Debug)]
pub struct OnboardedSequencer {
    pub serial: u32,
    pub active: Vec<String>,
}

/// The owners' side of a sequencer's onboarding (U-49 B2a), against the topology administration of the synchronizer's existing sequencers (`admin_urls`, one per
/// owner of the synchronizer's namespace, the first also the one the sequencer's identity is loaded through): what the console's
/// `sequencers.propose_delta` does on each owner. The new sequencer's onboarding `transactions` are loaded into the store of `physical_synchronizer_id` (with
/// `ForceFlag.AlienMember`), the `SequencerSynchronizerState` in force is read, and a new state naming `sequencer_uid` (a uid, `name::fingerprint`) is proposed
/// to **each** admin API, which signs it with that node's namespace key; the synchronizer's decentralized namespace takes it into force when enough owners
/// have signed. The state is read again until it names the sequencer (or `timeout` passes).
pub fn onboard_sequencer(
    admin_urls: &[String],
    physical_synchronizer_id: &str,
    transactions: Vec<v30::SignedTopologyTransaction>,
    sequencer_uid: &str,
    timeout: std::time::Duration,
) -> Result<OnboardedSequencer, String> {
    use admin::topology_manager_read_service_client::TopologyManagerReadServiceClient;
    use admin::topology_manager_write_service_client::TopologyManagerWriteServiceClient;
    let first = admin_urls
        .first()
        .ok_or("no admin API to onboard through")?;
    let logical = physical_synchronizer_id
        .rsplit_once("::")
        .map(|(l, _)| l.to_string())
        .ok_or_else(|| format!("{physical_synchronizer_id} is no physical synchronizer id"))?;
    let store = admin::StoreId {
        store: Some(admin::store_id::Store::Synchronizer(admin::Synchronizer {
            kind: Some(admin::synchronizer::Kind::PhysicalId(
                physical_synchronizer_id.to_string(),
            )),
        })),
    };
    let wait = Some(prost_types::Duration {
        seconds: 30,
        nanos: 0,
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let connect = |url: String| async move {
            tonic::transport::Channel::from_shared(url.clone())
                .map_err(|e| e.to_string())?
                .connect()
                .await
                .map_err(|e| format!("{url}: {e}"))
        };
        let current_of = |channel: tonic::transport::Channel, store: admin::StoreId, logical: String| async move {
            let mut read = TopologyManagerReadServiceClient::new(channel);
            let results = read
                .list_sequencer_synchronizer_state(admin::ListSequencerSynchronizerStateRequest {
                    base_query: Some(admin::BaseQuery {
                        store: Some(store),
                        proposals: false,
                        operation: 0,
                        filter_signed_key: String::new(),
                        protocol_version: None,
                        client_version: None,
                        time_query: Some(admin::base_query::TimeQuery::HeadState(())),
                    }),
                    filter_synchronizer_id: logical,
                })
                .await
                .map_err(|e| format!("reading the sequencer state: {}", e.message()))?
                .into_inner()
                .results;
            Ok::<_, String>(
                results
                    .into_iter()
                    .max_by_key(|r| r.context.as_ref().map_or(0, |c| c.serial)),
            )
        };
        let first_channel = connect(first.clone()).await?;
        let current = current_of(first_channel.clone(), store.clone(), logical.clone()).await?;
        let (serial, threshold, mut active, observers) = match &current {
            Some(r) => {
                let item = r.item.clone().unwrap_or_default();
                let serial = r.context.as_ref().map_or(0, |c| c.serial) as u32;
                (serial + 1, item.threshold.max(1), item.active, item.observers)
            }
            None => (1, 1, Vec::new(), Vec::new()),
        };
        if active.iter().any(|m| m == sequencer_uid) {
            return Ok(OnboardedSequencer {
                serial: serial.saturating_sub(1),
                active,
            });
        }
        let mut write = TopologyManagerWriteServiceClient::new(first_channel.clone());
        write
            .add_transactions(admin::AddTransactionsRequest {
                transactions,
                force_changes: vec![admin::ForceFlag::AlienMember as i32],
                store: Some(store.clone()),
                wait_to_become_effective: wait,
            })
            .await
            .map_err(|e| format!("loading the sequencer's identity: {}", e.message()))?;
        active.push(sequencer_uid.to_string());
        let state = v30::SequencerSynchronizerState {
            synchronizer_id: logical.clone(),
            threshold,
            active: active.clone(),
            observers,
        };
        for url in admin_urls {
            let mut write = TopologyManagerWriteServiceClient::new(connect(url.clone()).await?);
            write
                .authorize(admin::AuthorizeRequest {
                    r#type: Some(admin::authorize_request::Type::Proposal(
                        admin::authorize_request::Proposal {
                            change: v30::enums::TopologyChangeOp::AddReplace as i32,
                            serial,
                            mapping: Some(admin::authorize_request::proposal::Mapping::V31(
                                v31::TopologyMapping {
                                    mapping: Some(
                                        v31::topology_mapping::Mapping::SequencerSynchronizerState(
                                            state.clone(),
                                        ),
                                    ),
                                },
                            )),
                            protocol_version: None,
                        },
                    )),
                    // the other owners' signatures come from their own admin APIs
                    must_fully_authorize: false,
                    force_changes: Vec::new(),
                    signed_by: Vec::new(),
                    store: Some(store.clone()),
                    wait_to_become_effective: None,
                })
                .await
                .map_err(|e| format!("proposing the sequencer state through {url}: {}", e.message()))?;
        }
        // in force when the state names the sequencer
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let now_in_force =
                current_of(first_channel.clone(), store.clone(), logical.clone()).await?;
            if let Some(r) = now_in_force {
                let item = r.item.unwrap_or_default();
                if item.active.iter().any(|m| m == sequencer_uid) {
                    return Ok(OnboardedSequencer {
                        serial: r.context.as_ref().map_or(serial as i32, |c| c.serial) as u32,
                        active: item.active,
                    });
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "the sequencer state does not name {sequencer_uid} yet: the owners' signatures may be missing (proposed through {} admin API(s))",
                    admin_urls.len()
                ));
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}

/// Loads topology transactions into the store of the synchronizer `physical_synchronizer_id` through the admin API at `admin_url` (the transactions of a member
/// the synchronizer's owners do not know, with `ForceFlag.AlienMember`), waiting until they are in force.
pub fn load_transactions(
    admin_url: &str,
    physical_synchronizer_id: &str,
    transactions: Vec<v30::SignedTopologyTransaction>,
) -> Result<(), String> {
    use admin::topology_manager_write_service_client::TopologyManagerWriteServiceClient;
    let store = admin::StoreId {
        store: Some(admin::store_id::Store::Synchronizer(admin::Synchronizer {
            kind: Some(admin::synchronizer::Kind::PhysicalId(
                physical_synchronizer_id.to_string(),
            )),
        })),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let channel = tonic::transport::Channel::from_shared(admin_url.to_string())
            .map_err(|e| e.to_string())?
            .connect()
            .await
            .map_err(|e| format!("{admin_url}: {e}"))?;
        TopologyManagerWriteServiceClient::new(channel)
            .add_transactions(admin::AddTransactionsRequest {
                transactions,
                force_changes: vec![admin::ForceFlag::AlienMember as i32],
                store: Some(store),
                wait_to_become_effective: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
            })
            .await
            .map_err(|e| format!("loading the transactions: {}", e.message()))?;
        Ok(())
    })
}
