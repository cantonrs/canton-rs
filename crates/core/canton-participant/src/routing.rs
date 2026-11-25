//! Whether this participant may submit for the parties of a command on its synchronizer, checked before a request is built or sent.
//!
//! [CANTON-NOTE: SEMANTICS] Port of `AdmissibleSynchronizersComputation.ensureSynchronizerSuitability` for the one synchronizer a node is
//! connected to. A synchronizer is suitable when every submitter is hosted by the local participant with **submission** permission and a
//! hosting threshold of 1; otherwise routing refuses the command with `NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT`, or with
//! `DECENTRALIZED_PARTY_CANNOT_SUBMIT` when the threshold is the only reason. The receiving side checks the same hosting
//! ([`crate::view_validation::check_authorization`], `TopologySnapshot.canNotSubmit`).

use crate::view_validation::HostsOf;
use std::collections::BTreeSet;

/// `ParticipantPermission.PARTICIPANT_PERMISSION_SUBMISSION` (topology.proto).
pub const SUBMISSION: i32 = 1;

/// The prefix of a refusal by routing: `refused by routing: <gRPC code>:<CODE>(<category>,0): <cause>`, the shape of
/// [`crate::node::REJECTION_NOTE`]'s status so the API layer reads both the same way.
pub const ROUTING_REFUSAL: &str = "refused by routing: ";

/// Refuses `act_as` unless every party is hosted by `me` (a participant uid) with submission permission and a threshold of 1.
pub fn check_submitters(act_as: &[String], me: &str, hosts_of: &HostsOf<'_>) -> Result<(), String> {
    let submitters: BTreeSet<&str> = act_as.iter().map(String::as_str).collect();
    let mut unknown = Vec::new();
    let mut without_permission = Vec::new();
    let mut decentralized = Vec::new();
    for party in &submitters {
        let hosting = hosts_of(party);
        let mine = hosting.as_ref().and_then(|(_, hosts)| {
            hosts
                .iter()
                .find(|(uid, _)| uid == me)
                .map(|(_, permission)| *permission)
        });
        match (hosting.as_ref(), mine) {
            (_, None) => unknown.push(*party),
            (Some((threshold, hosts)), Some(_))
                if *threshold > 1 && hosts.iter().any(|(_, p)| *p == SUBMISSION) =>
            {
                decentralized.push(*party)
            }
            (_, Some(permission)) if permission != SUBMISSION => without_permission.push(*party),
            _ => {}
        }
    }
    if unknown.is_empty() && without_permission.is_empty() {
        if decentralized.is_empty() {
            return Ok(());
        }
        return Err(format!(
            "{ROUTING_REFUSAL}9:DECENTRALIZED_PARTY_CANNOT_SUBMIT(9,0): Submission is not supported for parties that are hosted with \
             Submission permission and have a confirmation threshold greater than 1: {}.",
            decentralized.join(", ")
        ));
    }
    let cause = if submitters.len() == 1 {
        "This participant cannot submit as the given submitter on any connected synchronizer"
    } else {
        "Not connected to a synchronizer on which this participant can submit for all submitters"
    };
    Err(format!(
        "{ROUTING_REFUSAL}5:NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT(11,0): {cause}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(party: &str) -> Option<(u32, Vec<(String, i32)>)> {
        match party {
            "own" => Some((1, vec![("me".into(), SUBMISSION)])),
            "confirming" => Some((1, vec![("me".into(), 2), ("other".into(), SUBMISSION)])),
            "elsewhere" => Some((1, vec![("other".into(), SUBMISSION)])),
            "decentralized" => Some((2, vec![("me".into(), SUBMISSION), ("other".into(), 2)])),
            _ => None,
        }
    }

    fn check(parties: &[&str]) -> Result<(), String> {
        let act_as: Vec<String> = parties.iter().map(|p| p.to_string()).collect();
        check_submitters(&act_as, "me", &table)
    }

    #[test]
    fn a_party_hosted_here_with_submission_permission_may_submit() {
        assert_eq!(check(&["own"]), Ok(()));
    }

    #[test]
    fn a_party_hosted_elsewhere_or_unknown_is_refused() {
        for party in ["elsewhere", "nobody", "confirming"] {
            let error = check(&[party]).expect_err(party);
            assert!(
                error.starts_with(ROUTING_REFUSAL)
                    && error.contains("5:NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT(11,0): This participant cannot submit as the given submitter"),
                "{error}"
            );
        }
        let error = check(&["own", "elsewhere"]).expect_err("two submitters");
        assert!(error.ends_with("Not connected to a synchronizer on which this participant can submit for all submitters"), "{error}");
    }

    #[test]
    fn a_threshold_above_one_alone_is_a_decentralized_party() {
        let error = check(&["own", "decentralized"]).expect_err("threshold 2");
        assert!(
            error.contains("9:DECENTRALIZED_PARTY_CANNOT_SUBMIT(9,0)")
                && error.ends_with(": decentralized."),
            "{error}"
        );
        let error = check(&["decentralized", "elsewhere"]).expect_err("also unknown");
        assert!(
            error.contains("NO_SYNCHRONIZER_ON_WHICH_ALL_SUBMITTERS_CAN_SUBMIT"),
            "{error}"
        );
    }
}
