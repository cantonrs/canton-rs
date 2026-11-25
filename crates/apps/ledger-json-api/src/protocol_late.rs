//! What the service records when the fate of one of its protocol submissions comes after the wait for it ended, or after a restart (P-7).
//!
//! [CANTON-NOTE: SEMANTICS] The command service answered the caller `REQUEST_TIME_OUT` and left the command in flight
//! (`SubmissionTracker.timedOut`); its fate is still published: an approval as the transaction and an accepted completion, anything else as
//! a rejected completion with the participant's status (`NOT_SEQUENCED_TIMEOUT`, `LOCAL_VERDICT_TIMEOUT`, or the verdict's). Each fate is
//! recorded once: one handed over again after a restart finds its completion and records nothing more.
use crate::service::{CommandIdentity, ExecutionService, RemoteApplied};
use crate::v2_commands::Ev;
use canton_participant::node::{LateFate, Verdict};
use std::sync::atomic::Ordering;

/// Records `fate` in `service`. `applied` is the fate's transaction as the service shows a transaction of another participant (see
/// `NodeCommitter::show_remote_transactions_in`).
pub(crate) fn settle(
    service: &ExecutionService,
    fate: LateFate,
    applied: Option<RemoteApplied>,
) -> Result<(), String> {
    let settled = fate.settled;
    let created: Vec<String> = applied
        .as_ref()
        .map(|a| a.created.iter().map(|c| c.contract_id.clone()).collect())
        .unwrap_or_default();
    let consumed: Vec<String> = applied
        .as_ref()
        .map(|a| a.consumed.clone())
        .unwrap_or_default();
    // the consumed contracts as the service showed them, before the transaction archives them
    let archived: Vec<Ev> = consumed
        .iter()
        .filter_map(|id| service.v2_contract(id))
        .map(|contract| Ev {
            contract,
            created: false,
            node: 0,
            exercise: None,
        })
        .collect();
    let root_update_id = applied
        .as_ref()
        .and_then(|a| a.root_hash.as_deref())
        .filter(|h| !h.is_empty())
        .map(hex::encode);
    let is_local_approved_cmd = serde_json::from_str::<CommandIdentity>(&settled.tag).is_ok()
        && settled.verdict == Verdict::Approved;
    if let Some(applied) = applied {
        let res = if is_local_approved_cmd {
            service.apply_remote_without_v2(applied)
        } else {
            service.apply_remote(applied)
        };
        if let Err(e) = res {
            return Err(format!(
                "the transaction of the submission {} could not be shown: {e}",
                settled.message_id
            ));
        }
    }
    let Ok(command) = serde_json::from_str::<CommandIdentity>(&settled.tag) else {
        // a submission that was not a command of this service (a reassignment, a test's): its transaction is all there is to show
        return Ok(());
    };
    let state = service.v2_state();
    // [CANTON-NOTE: DEFENSIVE] The client's submission id, or the submission's message id: the same each time the fate is handed over.
    let submission_id = if command.submission_id.is_empty() {
        settled.message_id.clone()
    } else {
        command.submission_id.clone()
    };
    let recorded = state.completions().iter().any(|c| {
        c.command_id == command.command_id
            && c.user_id == command.user_id
            && c.submission_id == submission_id
    });
    if recorded {
        let mut act_sorted = command.act_as;
        act_sorted.sort();
        crate::dedup::release(state, &(command.user_id, command.command_id, act_sorted));
        return Ok(());
    }
    match settled.verdict {
        Verdict::Approved => {
            let mut events: Vec<Ev> = archived;
            events.extend(created.iter().filter_map(|id| service.v2_contract(id)).map(
                |contract| Ev {
                    contract,
                    created: true,
                    node: 0,
                    exercise: None,
                },
            ));
            for (node, event) in events.iter_mut().enumerate() {
                event.node = node as u64;
            }
            if let Some(uid) = root_update_id {
                crate::service::set_protocol_update_id(uid);
            }
            let resp = crate::v2_commands::finish_with_hash(
                service,
                &command.command_id,
                &command.act_as,
                events,
                false,
                state,
                (command.user_id.clone(), submission_id.clone()),
                None,
                None,
            );
            if resp.status >= 500 {
                return Err(format!(
                    "late approved command {} failed to persist journal (status {})",
                    command.command_id, resp.status
                ));
            }
            let mut act_sorted = command.act_as.clone();
            act_sorted.sort();
            let key = (command.user_id, command.command_id, act_sorted);
            crate::dedup::record(
                service,
                key.clone(),
                state.ledger_end.load(Ordering::SeqCst),
                submission_id,
            );
            crate::dedup::release(state, &key);
        }
        Verdict::Rejected => {
            let error = crate::protocol::sync_rejected("command", &settled.notes);
            let (grpc_code, details) = match &error {
                crate::ApiError::SynchronizerRejected {
                    grpc_code, details, ..
                } => (*grpc_code, details.clone()),
                _ => (2, None),
            };
            if !crate::v2_commands::record_rejected_completion(
                state,
                &command.command_id,
                &command.user_id,
                &submission_id,
                &command.act_as,
                None,
                grpc_code,
                error.to_string(),
                details,
            ) {
                return Err(format!(
                    "late rejected command {} failed to persist completion journal",
                    command.command_id
                ));
            }
            let mut act_sorted = command.act_as;
            act_sorted.sort();
            crate::dedup::release(state, &(command.user_id, command.command_id, act_sorted));
        }
    }
    Ok(())
}
