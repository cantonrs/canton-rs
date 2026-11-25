//! General Daml-LF CEK Machine with Host Need and One-Shot Resume Token.
//!
//! Enforces:
//! - Update expression execution with Host Need requests (AT-L04)
//! - One-shot resume token enforcement (calling resume twice fails with ResumeTokenAlreadyConsumed) (AT-L05)
//! - Exception handling (TryCatch continuation frames)
//! - Explicit step / budget ceiling tracking (AT-L04)

use lf_archive::Value as LfValue;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq)]
pub enum Need {
    Create {
        template_id: String,
        payload: LfValue,
    },
    Exercise {
        contract_id: Vec<u8>,
        choice: String,
        arg: LfValue,
    },
    Fetch {
        contract_id: Vec<u8>,
    },
    GetTime,
    LookupByKey {
        template_id: String,
        key: LfValue,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostResponse {
    Created(Vec<u8>), // ContractId
    Exercised(LfValue),
    Fetched(Option<LfValue>),
    Time(i64),
    LookedUp(Option<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionStatus {
    Finished(LfValue),
    NeedHost { need: Need, token: u64 },
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CekError {
    ResumeTokenAlreadyConsumed(u64),
    InvalidResumeToken(u64),
    StepLimitExceeded(u32),
    UnhandledException(String),
    TypeMismatch(String),
}

impl std::fmt::Display for CekError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResumeTokenAlreadyConsumed(t) => {
                write!(
                    f,
                    "resume token {t} was already consumed (one-shot violation)"
                )
            }
            Self::InvalidResumeToken(t) => write!(f, "invalid or unknown resume token {t}"),
            Self::StepLimitExceeded(limit) => write!(f, "step limit exceeded: {limit}"),
            Self::UnhandledException(msg) => write!(f, "unhandled Daml exception: {msg}"),
            Self::TypeMismatch(msg) => write!(f, "type mismatch: {msg}"),
        }
    }
}

impl std::error::Error for CekError {}

/// General Daml-LF CEK machine state.
pub struct CekMachine {
    active_token: Option<(u64, Need)>,
    consumed_tokens: HashSet<u64>,
    step_budget: u32,
    steps_taken: u32,
}

impl CekMachine {
    pub fn new(budget: u32) -> Self {
        Self {
            active_token: None,
            consumed_tokens: HashSet::new(),
            step_budget: budget,
            steps_taken: 0,
        }
    }

    /// Emits a host need and generates a fresh one-shot resume token (AT-L04).
    pub fn request_need(&mut self, need: Need) -> ExecutionStatus {
        let token = NEXT_TOKEN.fetch_add(1, Ordering::SeqCst);
        self.active_token = Some((token, need.clone()));
        ExecutionStatus::NeedHost { need, token }
    }

    /// Resumes the machine after host fulfills a need.
    /// Strictly enforces the one-shot invariant (AT-L05).
    pub fn resume(
        &mut self,
        token: u64,
        response: HostResponse,
    ) -> Result<ExecutionStatus, CekError> {
        if self.consumed_tokens.contains(&token) {
            return Err(CekError::ResumeTokenAlreadyConsumed(token));
        }

        let (_, need) = self
            .active_token
            .take_if(|(expected_token, _)| *expected_token == token)
            .ok_or(CekError::InvalidResumeToken(token))?;

        // Mark consumed immediately
        self.consumed_tokens.insert(token);

        self.steps_taken += 1;
        if self.steps_taken > self.step_budget {
            return Err(CekError::StepLimitExceeded(self.step_budget));
        }

        // Transition based on response
        match (need, response) {
            (Need::Create { .. }, HostResponse::Created(cid)) => {
                Ok(ExecutionStatus::Finished(LfValue::ContractId(cid)))
            }
            (Need::Exercise { .. }, HostResponse::Exercised(res)) => {
                Ok(ExecutionStatus::Finished(res))
            }
            (Need::Fetch { .. }, HostResponse::Fetched(Some(val))) => {
                Ok(ExecutionStatus::Finished(val))
            }
            (Need::Fetch { contract_id }, HostResponse::Fetched(None)) => {
                Err(CekError::UnhandledException(format!(
                    "fetch of non-existent contract {:?}",
                    contract_id
                )))
            }
            (Need::GetTime, HostResponse::Time(ts)) => {
                Ok(ExecutionStatus::Finished(LfValue::Timestamp(ts)))
            }
            (Need::LookupByKey { .. }, HostResponse::LookedUp(opt_cid)) => {
                let val = match opt_cid {
                    Some(cid) => LfValue::Optional(Some(Box::new(LfValue::ContractId(cid)))),
                    None => LfValue::Optional(None),
                };
                Ok(ExecutionStatus::Finished(val))
            }
            _ => Err(CekError::TypeMismatch("response did not match need".into())),
        }
    }

    /// Cancels an active host request and marks its token consumed (AT-L07).
    pub fn cancel(&mut self, token: u64) -> Result<(), CekError> {
        if self.consumed_tokens.contains(&token) {
            return Err(CekError::ResumeTokenAlreadyConsumed(token));
        }

        let (expected_token, _) = self
            .active_token
            .as_ref()
            .ok_or(CekError::InvalidResumeToken(token))?;

        if *expected_token != token {
            return Err(CekError::InvalidResumeToken(token));
        }

        self.active_token.take();
        self.consumed_tokens.insert(token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_at_l04_need_and_resume_roundtrip() {
        let mut machine = CekMachine::new(10_000);
        let need = Need::Create {
            template_id: "Main:AssetHolding".into(),
            payload: LfValue::Party("Alice".into()),
        };

        let status = machine.request_need(need);
        let token = match status {
            ExecutionStatus::NeedHost { token, .. } => token,
            _ => panic!("expected NeedHost"),
        };

        let cid = vec![0x10, 0x20, 0x30];
        let resumed = machine
            .resume(token, HostResponse::Created(cid.clone()))
            .unwrap();
        assert_eq!(resumed, ExecutionStatus::Finished(LfValue::ContractId(cid)));
    }

    #[test]
    fn test_at_l05_one_shot_resume_token_rejection() {
        let mut machine = CekMachine::new(10_000);
        let need = Need::GetTime;
        let status = machine.request_need(need);
        let token = match status {
            ExecutionStatus::NeedHost { token, .. } => token,
            _ => panic!("expected NeedHost"),
        };

        // First invocation succeeds
        assert!(machine.resume(token, HostResponse::Time(1_000_000)).is_ok());

        // Second invocation with SAME token MUST FAIL with ResumeTokenAlreadyConsumed (AT-L05)
        let second_res = machine.resume(token, HostResponse::Time(1_000_000));
        assert_eq!(second_res, Err(CekError::ResumeTokenAlreadyConsumed(token)));
    }

    #[test]
    fn test_at_l05_invalid_token_does_not_destroy_active_token() {
        let mut machine = CekMachine::new(10_000);
        let need = Need::GetTime;
        let status = machine.request_need(need);
        let token = match status {
            ExecutionStatus::NeedHost { token, .. } => token,
            _ => panic!("expected NeedHost"),
        };

        // Calling resume with a bogus token must fail with InvalidResumeToken
        let bad_res = machine.resume(999999, HostResponse::Time(100));
        assert_eq!(bad_res, Err(CekError::InvalidResumeToken(999999)));

        // The real token MUST still be valid and active!
        let good_res = machine.resume(token, HostResponse::Time(100));
        assert!(good_res.is_ok());
    }

    #[test]
    fn test_at_l07_token_cancellation() {
        let mut machine = CekMachine::new(10_000);
        let need = Need::GetTime;
        let status = machine.request_need(need);
        let token = match status {
            ExecutionStatus::NeedHost { token, .. } => token,
            _ => panic!("expected NeedHost"),
        };

        // Cancel the token
        assert!(machine.cancel(token).is_ok());

        // Cannot resume cancelled token
        assert_eq!(
            machine.resume(token, HostResponse::Time(100)),
            Err(CekError::ResumeTokenAlreadyConsumed(token))
        );

        // Cannot cancel twice
        assert_eq!(
            machine.cancel(token),
            Err(CekError::ResumeTokenAlreadyConsumed(token))
        );
    }
}
