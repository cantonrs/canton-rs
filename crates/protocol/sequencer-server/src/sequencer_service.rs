//! The sequencer's authenticated API (`SequencerService`): what a participant calls once it holds a token.
//!
//! Served here: `GetTime`, `GetTrafficStateForMember`, `SendAsync`, `Subscribe`, `AcknowledgeSigned` and the topology download. Every
//! call first goes through [`Authentication::authenticated_member`]: the `memberid` header has to be the member the `authtoken-bin`
//! token was given to.
use crate::auth::Authentication;
use crate::synchronizer_state::TopologyStore;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::protocol::v30::TrafficState;
use canton_proto::com::digitalasset::canton::sequencer::api::v30::sequencer_service_server::SequencerService;
use canton_proto::com::digitalasset::canton::sequencer::api::v30::{
    AcknowledgeSignedRequest, AcknowledgeSignedResponse, DownloadTopologyStateForInitHashRequest,
    DownloadTopologyStateForInitHashResponse, DownloadTopologyStateForInitRequest,
    DownloadTopologyStateForInitResponse, GetTimeRequest, GetTimeResponse,
    GetTrafficStateForMemberRequest, GetTrafficStateForMemberResponse, SendAsyncRequest,
    SendAsyncResponse, SubscriptionRequest, SubscriptionResponse,
};
use canton_proto::com::digitalasset::canton::topology::admin::v30::{
    topology_transactions::Item, TopologyTransactions,
};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

pub struct SequencerServiceImpl {
    authentication: Authentication,
    store: std::sync::Arc<TopologyStore>,
    sequencer: Sequencer,
}

impl SequencerServiceImpl {
    pub fn new(
        authentication: Authentication,
        store: std::sync::Arc<TopologyStore>,
        sequencer: Sequencer,
    ) -> Self {
        Self {
            authentication,
            store,
            sequencer,
        }
    }
}

use crate::sequencing::Sequencer;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl SequencerService for SequencerServiceImpl {
    async fn get_time(
        &self,
        request: Request<GetTimeRequest>,
    ) -> Result<Response<GetTimeResponse>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        crate::diag::diag_poll_eprintln!("RPC GetTime member={member}");
        Ok(Response::new(GetTimeResponse {
            sequencing_timestamp: self.sequencer.current_time(),
        }))
    }

    async fn get_traffic_state_for_member(
        &self,
        request: Request<GetTrafficStateForMemberRequest>,
    ) -> Result<Response<GetTrafficStateForMemberResponse>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        let asked = request.into_inner();
        crate::diag::diag_eprintln!(
            "RPC GetTrafficStateForMember member={member} of={}",
            asked.member
        );
        // [CANTON-NOTE: SEMANTICS] Measured on the official sequencer (traffic control off): a member may ask for its own state only
        // (another member's is `PERMISSION_DENIED`), and the answer at the asked time is all zeros with no serial.
        if asked.member != member {
            return Err(Status::permission_denied(format!(
                "Authenticated member {member} just tried to use sequencer on behalf of {} without permission",
                asked.member
            )));
        }
        // with traffic control on: the member's state now (S-NET-038 part 13)
        Ok(Response::new(GetTrafficStateForMemberResponse {
            traffic_state: Some(
                self.sequencer
                    .traffic_state(&member)
                    .unwrap_or(TrafficState {
                        extra_traffic_purchased: 0,
                        extra_traffic_consumed: 0,
                        base_traffic_remainder: 0,
                        last_consumed_cost: 0,
                        timestamp: asked.timestamp,
                        serial: None,
                    }),
            ),
        }))
    }

    async fn send_async(
        &self,
        request: Request<SendAsyncRequest>,
    ) -> Result<Response<SendAsyncResponse>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        crate::diag::diag_eprintln!("RPC SendAsync member={member}");
        let _guard = self.sequencer.try_enter_submission()?;
        self.sequencer
            .submit(&member, &request.into_inner().signed_submission_request)?;
        Ok(Response::new(SendAsyncResponse {}))
    }

    type SubscribeStream = BoxStream<SubscriptionResponse>;

    async fn subscribe(
        &self,
        request: Request<SubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (member, expires_at) = self.authentication.authenticated_member_until(&request)?;
        let asked = request.into_inner();
        crate::diag::diag_poll_eprintln!(
            "RPC Subscribe member={member} from={:?}",
            asked.timestamp
        );
        if asked.member != member {
            return Err(Status::permission_denied(format!(
                "Authenticated member {member} just tried to use sequencer on behalf of {} without permission",
                asked.member
            )));
        }
        Ok(Response::new(Box::pin(self.sequencer.subscribe_until(
            member,
            asked.timestamp,
            Some(expires_at),
        ))))
    }

    async fn acknowledge_signed(
        &self,
        request: Request<AcknowledgeSignedRequest>,
    ) -> Result<Response<AcknowledgeSignedResponse>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        crate::diag::diag_eprintln!("RPC AcknowledgeSigned member={member}");
        self.sequencer
            .acknowledge(&member, &request.into_inner().signed_acknowledge_request)?;
        Ok(Response::new(AcknowledgeSignedResponse {}))
    }

    type DownloadTopologyStateForInitStream = BoxStream<DownloadTopologyStateForInitResponse>;

    async fn download_topology_state_for_init(
        &self,
        request: Request<DownloadTopologyStateForInitRequest>,
    ) -> Result<Response<Self::DownloadTopologyStateForInitStream>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        crate::diag::diag_eprintln!("RPC DownloadTopologyStateForInit member={member}");
        let timestamp = |micros: i64| prost_types::Timestamp {
            seconds: micros.div_euclid(1_000_000),
            nanos: (micros.rem_euclid(1_000_000) * 1000) as i32,
        };
        let items: Vec<Item> = self
            .store
            .snapshot()
            .iter()
            .map(|e| Item {
                sequenced: Some(timestamp(e.sequenced_micros)),
                valid_from: Some(timestamp(e.valid_from_micros)),
                valid_until: None,
                transaction: tw::stored_form(&e.signed),
                rejection_reason: None,
            })
            .collect();
        let response = DownloadTopologyStateForInitResponse {
            topology_transactions: Some(TopologyTransactions { items }),
        };
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(response)]))))
    }

    async fn download_topology_state_for_init_hash(
        &self,
        request: Request<DownloadTopologyStateForInitHashRequest>,
    ) -> Result<Response<DownloadTopologyStateForInitHashResponse>, Status> {
        let member = self.authentication.authenticated_member(&request)?;
        crate::diag::diag_eprintln!("RPC DownloadTopologyStateForInitHash member={member}");
        Ok(Response::new(DownloadTopologyStateForInitHashResponse {
            topology_state_hash: self.store.hash(),
        }))
    }
}
