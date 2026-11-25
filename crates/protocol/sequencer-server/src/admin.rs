//! The sequencer's administration API, as far as the acceptance tests need it (G6, S-NET-038 part 5): traffic purchases and the traffic
//! control state.
//!
//! [CANTON-NOTE: SEMANTICS] Measured on the official 3.7.2 sandbox (traffic control is **off** in it; `ORACLE_TRAFFIC` lines of
//! `the_official_sequencer_answers_traffic_purchases_for_registered_and_unregistered_members`): **every** `SetTrafficPurchased` is refused with
//! `NOT_FOUND` `TRAFFIC_CONTROL_DISABLED(11,...)`: `TrafficControlDisabled`, whatever the member (registered or not) and whatever the serial
//! (a first one, a duplicate, a lower one). Nothing is credited, so there is no balance to double. The traffic state of a **registered**
//! member is all zeros with the time at the beginning of time, and an unregistered member is **not in the answer**.
//!
//! With traffic control **on** (the dynamic parameters' `traffic_control`, S-NET-038 part 13) a purchase sets the member's extra traffic and
//! the state is the member's real one (see [`crate::traffic`]); a member that is not registered yet may be sold traffic (pre-purchase,
//! protocol version 37).
use crate::onboarding::Registry;
use canton_proto::com::digitalasset::canton::protocol::v30::TrafficState;
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    sequencer_administration_service_server::SequencerAdministrationService, DisableMemberRequest,
    DisableMemberResponse, GenerateAuthenticationTokenRequest, GenerateAuthenticationTokenResponse,
    GetLsuTrafficControlStateRequest, GetLsuTrafficControlStateResponse, GetThroughputCapRequest,
    GetThroughputCapResponse, OnboardingStateV2Request, OnboardingStateV2Response,
    PerformLsuSequencingTestRequest, PerformLsuSequencingTestResponse, PruningStatusRequest,
    PruningStatusResponse, SetLsuTrafficControlStateRequest, SetLsuTrafficControlStateResponse,
    SetThroughputCapRequest, SetThroughputCapResponse, SetTrafficPurchasedRequest,
    SetTrafficPurchasedResponse, SnapshotRequest, SnapshotResponse, TrafficControlStateRequest,
    TrafficControlStateResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct AdminService {
    registry: Arc<Registry>,
    sequencer: crate::sequencing::Sequencer,
}

impl AdminService {
    pub fn new(registry: Arc<Registry>, sequencer: crate::sequencing::Sequencer) -> Self {
        Self {
            registry,
            sequencer,
        }
    }
}

fn not_served<T>(what: &str) -> Result<Response<T>, Status> {
    Err(Status::unimplemented(format!(
        "{what} is not served by the Rust sequencer"
    )))
}

#[tonic::async_trait]
impl SequencerAdministrationService for AdminService {
    async fn get_lsu_traffic_control_state(
        &self,
        _request: Request<GetLsuTrafficControlStateRequest>,
    ) -> Result<Response<GetLsuTrafficControlStateResponse>, Status> {
        not_served("the traffic state at an upgrade")
    }

    async fn set_lsu_traffic_control_state(
        &self,
        _request: Request<SetLsuTrafficControlStateRequest>,
    ) -> Result<Response<SetLsuTrafficControlStateResponse>, Status> {
        not_served("setting the traffic state at an upgrade")
    }

    async fn set_throughput_cap(
        &self,
        _request: Request<SetThroughputCapRequest>,
    ) -> Result<Response<SetThroughputCapResponse>, Status> {
        not_served("the throughput cap")
    }

    async fn get_throughput_cap(
        &self,
        _request: Request<GetThroughputCapRequest>,
    ) -> Result<Response<GetThroughputCapResponse>, Status> {
        not_served("the throughput cap")
    }

    async fn snapshot(
        &self,
        _request: Request<SnapshotRequest>,
    ) -> Result<Response<SnapshotResponse>, Status> {
        not_served("the sequencer snapshot")
    }

    type OnboardingStateV2Stream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<OnboardingStateV2Response, Status>> + Send>,
    >;

    async fn onboarding_state_v2(
        &self,
        _request: Request<OnboardingStateV2Request>,
    ) -> Result<Response<Self::OnboardingStateV2Stream>, Status> {
        Err(Status::unimplemented(
            "the onboarding state of a new sequencer is not served by the Rust sequencer",
        ))
    }

    async fn disable_member(
        &self,
        _request: Request<DisableMemberRequest>,
    ) -> Result<Response<DisableMemberResponse>, Status> {
        not_served("disabling a member")
    }

    async fn generate_authentication_token(
        &self,
        _request: Request<GenerateAuthenticationTokenRequest>,
    ) -> Result<Response<GenerateAuthenticationTokenResponse>, Status> {
        not_served("generating an authentication token")
    }

    async fn perform_lsu_sequencing_test(
        &self,
        _request: Request<PerformLsuSequencingTestRequest>,
    ) -> Result<Response<PerformLsuSequencingTestResponse>, Status> {
        not_served("the upgrade sequencing test")
    }

    async fn pruning_status(
        &self,
        _request: Request<PruningStatusRequest>,
    ) -> Result<Response<PruningStatusResponse>, Status> {
        crate::diag::diag_eprintln!("RPC PruningStatus");
        Ok(Response::new(PruningStatusResponse {
            pruning_status: Some(self.sequencer.pruning_status()),
        }))
    }

    async fn traffic_control_state(
        &self,
        request: Request<TrafficControlStateRequest>,
    ) -> Result<Response<TrafficControlStateResponse>, Status> {
        crate::diag::diag_eprintln!("RPC TrafficControlState");
        let asked = request.into_inner().members;
        let members = self.registry.members();
        let wanted: Vec<String> = if asked.is_empty() {
            members
        } else {
            asked.into_iter().filter(|m| members.contains(m)).collect()
        };
        let beginning_of_time = crate::synchronizer_state::BEGINNING_OF_TIME_MICROS;
        Ok(Response::new(TrafficControlStateResponse {
            traffic_states: wanted
                .into_iter()
                .map(|m| {
                    let state = self.sequencer.traffic_state(&m);
                    (
                        m,
                        state.unwrap_or(TrafficState {
                            extra_traffic_purchased: 0,
                            extra_traffic_consumed: 0,
                            base_traffic_remainder: 0,
                            last_consumed_cost: 0,
                            timestamp: beginning_of_time,
                            serial: None,
                        }),
                    )
                })
                .collect(),
        }))
    }

    async fn set_traffic_purchased(
        &self,
        request: Request<SetTrafficPurchasedRequest>,
    ) -> Result<Response<SetTrafficPurchasedResponse>, Status> {
        let asked = request.into_inner();
        crate::diag::diag_eprintln!(
            "RPC SetTrafficPurchased member={} serial={}",
            asked.member,
            asked.serial
        );
        self.sequencer.purchase_traffic(
            &asked.member,
            asked.serial,
            asked.total_traffic_purchased.max(0) as u64,
        )?;
        Ok(Response::new(SetTrafficPurchasedResponse {}))
    }
}
