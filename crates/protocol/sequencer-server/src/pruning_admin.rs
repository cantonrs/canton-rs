//! The pruning administration services of the admin port: the sequencer's (`SequencerPruningAdministrationService`) and the one of the
//! mediators inside it (`MediatorAdministrationService`).
//!
//! [CANTON-NOTE: SEMANTICS] Read from 3.7.2 `GrpcSequencerPruningAdministrationService`, `BlockSequencer`, `GrpcMediatorAdministrationService`
//! and `Mediator`: a block sequencer prunes (`UnsafePruningPoint`: `FAILED_PRECONDITION`) but has no pruning scheduler and does not find pruning
//! timestamps (`UNIMPLEMENTED`); a mediator prunes (`NoDataAvailableForPruning`: `FAILED_PRECONDITION`, `CannotPruneAtTimestamp`:
//! `INVALID_ARGUMENT`) and finds the request time of its `index`-th finalized response (1-based).
//! [CANTON-NOTE: LIMITATION] The mediators' pruning schedule (`SetSchedule`, `SetCron`, ..., `GetSchedule`, `ClearSchedule`) is not served: a
//! schedule would need a cron runner here. A mediator that runs as a process of its own has no admin port.
use crate::sequencing::{MediatorPruneRefused, Sequencer};
use canton_proto::com::digitalasset::canton::admin::pruning::v30::{
    ClearScheduleRequest, ClearScheduleResponse, FindPruningTimestampRequest,
    FindPruningTimestampResponse, GetScheduleRequest, GetScheduleResponse, SetCronRequest,
    SetCronResponse, SetMaxDurationRequest, SetMaxDurationResponse, SetRetentionRequest,
    SetRetentionResponse, SetScheduleRequest, SetScheduleResponse,
};
use canton_proto::com::digitalasset::canton::mediator::admin::v30::{
    mediator_administration_service_server::MediatorAdministrationService, mediator_pruning,
};
use canton_proto::com::digitalasset::canton::sequencer::admin::v30::{
    sequencer_pruning_administration_service_server::SequencerPruningAdministrationService,
    PruneRequest, PruneResponse,
};
use tonic::{Request, Response, Status};

/// `CantonTimestamp.fromProtoTimestamp` of the required `timestamp` field, in microseconds.
fn requested(timestamp: Option<prost_types::Timestamp>) -> Result<i64, Status> {
    let t = timestamp.ok_or_else(|| Status::invalid_argument("FieldNotSet(timestamp)"))?;
    Ok(t.seconds * 1_000_000 + i64::from(t.nanos) / 1000)
}

fn timestamp(micros: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: micros.div_euclid(1_000_000),
        nanos: (micros.rem_euclid(1_000_000) * 1000) as i32,
    }
}

/// Runs the blocking `work` (it rewrites the journal) off the async workers.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| Status::internal(format!("pruning stopped: {e}")))
}

pub struct SequencerPruning {
    sequencer: Sequencer,
}

impl SequencerPruning {
    pub fn new(sequencer: Sequencer) -> Self {
        Self { sequencer }
    }
}

/// `PruningError.ScheduledPruningNotSupported`.
fn no_scheduler<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented(
        "This sequencer does not support scheduled pruning",
    ))
}

#[tonic::async_trait]
impl SequencerPruningAdministrationService for SequencerPruning {
    async fn prune(
        &self,
        request: Request<PruneRequest>,
    ) -> Result<Response<PruneResponse>, Status> {
        let at = requested(request.into_inner().timestamp)?;
        crate::diag::diag_eprintln!("RPC Prune sequencer at {at}");
        let sequencer = self.sequencer.clone();
        let details = blocking(move || sequencer.prune(at))
            .await?
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(PruneResponse { details }))
    }

    async fn set_schedule(
        &self,
        _request: Request<SetScheduleRequest>,
    ) -> Result<Response<SetScheduleResponse>, Status> {
        no_scheduler()
    }

    async fn set_cron(
        &self,
        _request: Request<SetCronRequest>,
    ) -> Result<Response<SetCronResponse>, Status> {
        no_scheduler()
    }

    async fn set_max_duration(
        &self,
        _request: Request<SetMaxDurationRequest>,
    ) -> Result<Response<SetMaxDurationResponse>, Status> {
        no_scheduler()
    }

    async fn set_retention(
        &self,
        _request: Request<SetRetentionRequest>,
    ) -> Result<Response<SetRetentionResponse>, Status> {
        no_scheduler()
    }

    async fn clear_schedule(
        &self,
        _request: Request<ClearScheduleRequest>,
    ) -> Result<Response<ClearScheduleResponse>, Status> {
        no_scheduler()
    }

    async fn get_schedule(
        &self,
        _request: Request<GetScheduleRequest>,
    ) -> Result<Response<GetScheduleResponse>, Status> {
        no_scheduler()
    }

    async fn find_pruning_timestamp(
        &self,
        request: Request<FindPruningTimestampRequest>,
    ) -> Result<Response<FindPruningTimestampResponse>, Status> {
        let index = request.into_inner().index;
        if index < 1 {
            return Err(Status::invalid_argument(format!(
                "Received the non-positive value {index}"
            )));
        }
        // `PruningError.NotSupported`
        Err(Status::unimplemented(
            "This sequencer does not support pruning",
        ))
    }
}

pub struct MediatorPruning {
    sequencer: Sequencer,
}

impl MediatorPruning {
    pub fn new(sequencer: Sequencer) -> Self {
        Self { sequencer }
    }
}

/// A mediator pruning schedule needs a scheduler to run it, which the mediators inside the sequencer do not have.
fn no_mediator_scheduler<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented(
        "scheduled pruning is not served by the Rust mediator",
    ))
}

#[tonic::async_trait]
impl MediatorAdministrationService for MediatorPruning {
    async fn prune(
        &self,
        request: Request<mediator_pruning::PruneRequest>,
    ) -> Result<Response<mediator_pruning::PruneResponse>, Status> {
        let at = requested(request.into_inner().timestamp)?;
        match self.sequencer.prune_mediators(at) {
            Ok(pruned) => {
                crate::diag::diag_eprintln!(
                    "RPC Prune mediator at {at}: {pruned} finalized response(s)"
                );
                Ok(Response::new(mediator_pruning::PruneResponse {}))
            }
            Err(why @ MediatorPruneRefused::NoData) => {
                Err(Status::failed_precondition(why.message()))
            }
            Err(why @ MediatorPruneRefused::TooLate { .. }) => {
                Err(Status::invalid_argument(why.message()))
            }
        }
    }

    async fn set_schedule(
        &self,
        _request: Request<SetScheduleRequest>,
    ) -> Result<Response<SetScheduleResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn set_cron(
        &self,
        _request: Request<SetCronRequest>,
    ) -> Result<Response<SetCronResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn set_max_duration(
        &self,
        _request: Request<SetMaxDurationRequest>,
    ) -> Result<Response<SetMaxDurationResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn set_retention(
        &self,
        _request: Request<SetRetentionRequest>,
    ) -> Result<Response<SetRetentionResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn clear_schedule(
        &self,
        _request: Request<ClearScheduleRequest>,
    ) -> Result<Response<ClearScheduleResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn get_schedule(
        &self,
        _request: Request<GetScheduleRequest>,
    ) -> Result<Response<GetScheduleResponse>, Status> {
        no_mediator_scheduler()
    }

    async fn find_pruning_timestamp(
        &self,
        request: Request<FindPruningTimestampRequest>,
    ) -> Result<Response<FindPruningTimestampResponse>, Status> {
        // a 1-based index, the store's skip is 0-based
        let skip = usize::try_from(i64::from(request.into_inner().index) - 1)
            .map_err(|_| Status::invalid_argument("The index must be at least 1"))?;
        Ok(Response::new(FindPruningTimestampResponse {
            timestamp: self
                .sequencer
                .mediator_pruning_timestamp(skip)
                .map(timestamp),
        }))
    }
}
