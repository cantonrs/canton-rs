//! The rate of a participant's confirmation requests (`GrpcSequencerService.checkRate`).
//!
//! [CANTON-NOTE: SEMANTICS] A request is a confirmation request when a participant sends it to participants and mediators only
//! (`SubmissionRequestType.submissionRequestType`). Its sender's rate is bounded by the synchronizer's
//! `participant_synchronizer_limits.confirmation_requests_max_rate` (`DynamicSynchronizerParameters.defaultConfirmationRequestsMaxRate`,
//! 1000000/s), with bursts of `max-confirmation-requests-burst-factor` (`SequencerNodeParameterConfig`, 0.5) times the rate, by Canton's
//! `RateLimiter`: the approved tasks drain at the rate, and a request is approved while fewer than the burst are outstanding. A refused
//! request is `SequencerErrors.Overloaded`.
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use tonic::Status;

use crate::submission::Submission;

/// Canton's `maxConfirmationRequestsBurstFactor` default.
pub const BURST_FACTOR: f64 = 0.5;

/// Canton's `defaultConfirmationRequestsMaxRate`.
pub const DEFAULT_MAX_RATE: u32 = 1_000_000;

/// One participant's `RateLimiter` state.
#[derive(Debug, Clone, Copy)]
struct Limiter {
    rate: u32,
    last: Option<Instant>,
    approved: f64,
}

impl Limiter {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            last: None,
            approved: 0.0,
        }
    }

    fn check_and_update(&mut self, now: Instant) -> bool {
        let rate = f64::from(self.rate);
        let drained = match self.last {
            Some(last) => (self.approved - rate * now.duration_since(last).as_secs_f64()).max(0.0),
            None => 0.0,
        };
        self.last = Some(now);
        if drained < BURST_FACTOR * rate {
            self.approved = drained + 1.0;
            true
        } else {
            self.approved = drained;
            false
        }
    }
}

/// The limiters of every participant that sent a confirmation request.
#[derive(Debug, Default)]
pub struct ConfirmationRates {
    limiters: Mutex<BTreeMap<String, Limiter>>,
}

impl ConfirmationRates {
    /// Refuses `submission` when it is a participant's confirmation request past `rate` per second.
    pub(crate) fn check(&self, submission: &Submission, rate: u32) -> Result<(), Status> {
        if !is_confirmation_request(submission) {
            return Ok(());
        }
        // [CANTON-NOTE: DEFENSIVE] The limiters are counters: a poisoned lock keeps them.
        let mut limiters = self
            .limiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let limiter = limiters
            .entry(submission.sender.clone())
            .or_insert_with(|| Limiter::new(rate));
        // a changed rate starts a new limiter (`getOrUpdateRateLimiter`)
        if limiter.rate != rate {
            *limiter = Limiter::new(rate);
        }
        if limiter.check_and_update(Instant::now()) {
            Ok(())
        } else {
            Err(crate::sequencing::overloaded(format!(
                "Submission rate exceeds rate limit of {rate}/s."
            )))
        }
    }
}

fn is_confirmation_request(submission: &Submission) -> bool {
    if !submission.sender.starts_with("PAR::") {
        return false;
    }
    let addresses = submission.addresses();
    let participants = addresses.iter().any(|a| a.starts_with("PAR::"));
    let mediators = addresses
        .iter()
        .any(|a| a.starts_with("MED::") || a.starts_with("MGR::"));
    let others = addresses
        .iter()
        .any(|a| !(a.starts_with("PAR::") || a.starts_with("MED::") || a.starts_with("MGR::")));
    participants && mediators && !others
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_up_to_half_the_rate_then_the_rate() {
        let start = Instant::now();
        let mut limiter = Limiter::new(10);
        let approved = (0..10).filter(|_| limiter.check_and_update(start)).count();
        assert_eq!(approved, 5, "a burst of 0.5 x 10");
        // 150 ms drain 1.5 of the 5 outstanding: 3.5 and 4.5 are under the burst, 5.5 is not
        let later = start + std::time::Duration::from_millis(150);
        let approved = (0..10).filter(|_| limiter.check_and_update(later)).count();
        assert_eq!(approved, 2);
    }

    #[test]
    fn a_rate_of_zero_refuses_everything() {
        assert!(!Limiter::new(0).check_and_update(Instant::now()));
    }
}
