//! The checks of a confirmation request that read more than the request itself: its sequencing time (`TimeValidator`) and the
//! synchronizer's topology at that time (`AuthorizationValidator`), and the checks of a verdict against the request it is about
//! (`ProtocolProcessor`'s result checks). Pure: what the runtime knows goes in, a refusal or nothing comes out.
use crate::routing::SUBMISSION;
use crate::topology_state::{iso_utc, MediatorGroup};
use crate::view_acs::Verdict;
use crate::view_receive::RevealedView;
use canton_algo::signing::PublicKey;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::DynamicSynchronizerParameters;
use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
use canton_proto::com::digitalasset::canton::protocol::v32::SubmitterMetadata;
use std::collections::{BTreeMap, BTreeSet};

/// How far a request's ledger time and preparation time may be from its sequencing time (microseconds).
///
/// [CANTON-NOTE: SEMANTICS] The dynamic synchronizer parameters `ledgerTimeRecordTimeTolerance` and `preparationTimeRecordTimeTolerance`;
/// a parameter that is not set takes Canton's default, as `findDynamicSynchronizerParametersOrDefault` does (60 s and 24 h,
/// `DynamicSynchronizerParameters.defaultLedgerTimeRecordTimeTolerance` / `defaultPreparationTimeRecordTimeTolerance`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeTolerances {
    pub ledger_time_record_time_micros: i64,
    pub preparation_time_record_time_micros: i64,
}

impl Default for TimeTolerances {
    fn default() -> Self {
        TimeTolerances {
            ledger_time_record_time_micros: 60_000_000,
            preparation_time_record_time_micros: 24 * 3_600_000_000,
        }
    }
}

impl TimeTolerances {
    /// The tolerances `parameters` set, each falling back to its default.
    pub fn of(parameters: &DynamicSynchronizerParameters) -> Self {
        let micros = |d: &Option<prost_types::Duration>| {
            d.as_ref()
                .map(|d| d.seconds * 1_000_000 + i64::from(d.nanos) / 1_000)
        };
        let defaults = TimeTolerances::default();
        TimeTolerances {
            ledger_time_record_time_micros: micros(&parameters.ledger_time_record_time_tolerance)
                .unwrap_or(defaults.ledger_time_record_time_micros),
            preparation_time_record_time_micros: micros(
                &parameters.preparation_time_record_time_tolerance,
            )
            .unwrap_or(defaults.preparation_time_record_time_micros),
        }
    }
}

/// The times of a request, all in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTimes {
    /// The request's sequencing time (Canton's record time for the request).
    pub record_time: i64,
    pub ledger_time: i64,
    pub preparation_time: i64,
    /// The latest record time an external signer allowed (`ExternalAuthorization.max_record_time`).
    pub max_record_time: Option<i64>,
}

/// Why a request's times refuse it: the reason of a local **rejection** (not a malformed request), which names Canton's error id.
///
/// [CANTON-NOTE: SEMANTICS] `TimeValidator.checkTimestamps`: the ledger time first, then the preparation time, then (externally signed
/// submissions only) the maximum record time; each bound is inclusive. `TransactionConfirmationResponsesFactory` turns a failure into
/// `LocalRejectError.TimeRejects.{LedgerTime, PreparationTime, MaxRecordTimeExceeded}` for every view.
pub fn check_times(times: &RequestTimes, tolerances: TimeTolerances) -> Result<(), String> {
    let RequestTimes {
        record_time,
        ledger_time,
        preparation_time,
        max_record_time,
    } = *times;
    let outside = |time: i64, tolerance: i64| {
        time < record_time.saturating_sub(tolerance) || time > record_time.saturating_add(tolerance)
    };
    if outside(ledger_time, tolerances.ledger_time_record_time_micros) {
        return Err(format!(
            "LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND: Rejected transaction as delta of the ledger time and the record time exceed the time \
             tolerance ledgerTime={}, recordTime={}, maxDelta={}us",
            iso_utc(ledger_time),
            iso_utc(record_time),
            tolerances.ledger_time_record_time_micros
        ));
    }
    if outside(
        preparation_time,
        tolerances.preparation_time_record_time_micros,
    ) {
        return Err(format!(
            "LOCAL_VERDICT_PREPARATION_TIME_OUT_OF_BOUND: Rejected transaction as delta of the preparation time and the record time exceed \
             the time tolerance preparationTime={}, recordTime={}, maxDelta={}us",
            iso_utc(preparation_time),
            iso_utc(record_time),
            tolerances.preparation_time_record_time_micros
        ));
    }
    match max_record_time {
        Some(max) if record_time > max => Err(format!(
            "LOCAL_VERDICT_MAX_RECORD_TIME_EXCEEDED: Rejected transaction as record time exceeds the maximum record time: recordTime={}, \
             maxRecordTime={}",
            iso_utc(record_time),
            iso_utc(max)
        )),
        _ => Ok(()),
    }
}

/// For a party: the hosting threshold and the participants (uids) that host it with their permission, as the topology in force at the
/// request's time says (`Tracker::hosts_of`); `None` for a party no mapping names.
pub type HostsOf<'a> = dyn Fn(&str) -> Option<(u32, Vec<(String, i32)>)> + 'a;

/// The parties that authorize a view's root action: the signatories of a create (of its first created contract), the actors of an
/// exercise or a fetch (`ViewParticipantData.rootAction.authorizers`).
pub fn root_action_authorizers(view: &RevealedView) -> Result<BTreeSet<String>, String> {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use prost::Message;
    let data = &view.participant_data;
    match data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => {
            let first = data
                .created_core
                .first()
                .ok_or("a create view without a created contract")?;
            let versioned =
                Versioned::decode(first.contract.as_slice()).map_err(|e| e.to_string())?;
            let fci = FatContractInstance::decode(versioned.payload.as_slice())
                .map_err(|e| e.to_string())?;
            Ok(crate::view_conformance::stated_signatories(&fci))
        }
        Some(Description::Exercise(e)) => Ok(e.actors.iter().cloned().collect()),
        Some(Description::Fetch(f)) => Ok(f.actors.iter().cloned().collect()),
        None => Err("a view without an action description".into()),
    }
}

/// Whether `view` is a root view of what this participant sees: a view whose parent is not among the `revealed` ones.
pub fn is_root_of_revealed(view: &RevealedView, revealed: &[RevealedView]) -> bool {
    match view.position.get(1..) {
        Some(parent) if !parent.is_empty() => !revealed.iter().any(|v| v.position == parent),
        _ => true,
    }
}

/// What the authorization check of a root view reads besides the view.
pub struct Authorization<'a> {
    /// The submitter metadata when the view's tree reveals it (a top-level view), `None` when it is blinded.
    pub submitter: Option<&'a SubmitterMetadata>,
    /// This participant's uid.
    pub me: &'a str,
    /// The hosting in force when the topology is followed, `None` for a runtime configured by hand.
    pub hosts_of: Option<&'a HostsOf<'a>>,
    /// The parties this participant hosts with permission to confirm (what a runtime configured by hand knows of the hosting).
    pub hosted_parties: &'a [String],
    /// Whether the submitter metadata's external authorization was verified (`crate::external_hash::verify`): the parties' signatures over
    /// the hash recomputed from the root view.
    pub external_verified: bool,
}

/// Whether the root action of a root view this participant sees is authorized; the reason of a **malformed** view if not.
///
/// [CANTON-NOTE: SEMANTICS] `AuthorizationValidator.checkAuthorization`, answered as `LocalRejectError.MalformedRejects.MalformedRequest`:
/// - submitter metadata revealed (a top-level view): the authorizers are among `act_as`; then, unless the submission is externally
///   signed, every `act_as` party is hosted by the submitting participant with **submission** permission and a hosting threshold of 1
///   (`TopologySnapshot.canNotSubmit`; an externally signed submission was authenticated by its parties' signatures instead);
/// - blinded (a root view below a view this participant does not see): no authorizer is hosted here, else this participant would have
///   received the parent view (`checkAuthorizersAreNotHosted`).
///
/// [CANTON-NOTE: LIMITATION] A runtime configured by hand has no hosting table: it checks the authorizers against `act_as`, skips the
/// submitting participant's permission, and knows of its own hosting only the parties it confirms for (`hosted_parties`).
pub fn check_authorization(view: &RevealedView, a: &Authorization) -> Result<(), String> {
    let malformed = |details: String| {
        format!(
            "LOCAL_VERDICT_MALFORMED_REQUEST: a view that is not correctly authorized: {details}"
        )
    };
    let authorizers = root_action_authorizers(view).map_err(malformed)?;
    let Some(submitter) = a.submitter else {
        let hosted_here: Vec<&String> = authorizers
            .iter()
            .filter(|party| match a.hosts_of {
                Some(hosts_of) => hosts_of(party)
                    .is_some_and(|(_, hosts)| hosts.iter().any(|(uid, _)| uid == a.me)),
                None => a.hosted_parties.contains(party),
            })
            .collect();
        return if hosted_here.is_empty() {
            Ok(())
        } else {
            Err(malformed(format!(
                "Missing authorization for {hosted_here:?}, {:?}.",
                view.position
            )))
        };
    };
    let act_as: BTreeSet<&String> = submitter.act_as.iter().collect();
    let not_covered: Vec<&String> = authorizers.iter().filter(|p| !act_as.contains(p)).collect();
    if !not_covered.is_empty() {
        return Err(malformed(format!(
            "Missing authorization for {not_covered:?} through the submitting parties."
        )));
    }
    // [CANTON-NOTE: SEMANTICS] An externally signed submission is authenticated by its parties' signatures over the transaction hash
    // recomputed from the root view (`AuthenticationValidator.verifyExternalPartySignature`, here `crate::external_hash::verify`), not by
    // the submitting participant's permission. A claim that was not verified never skips the permission check (U-56: an empty external
    // authorization used to).
    if submitter.external_authorization.is_some() {
        return if a.external_verified {
            Ok(())
        } else {
            Err(malformed(
                "Failed to compute externally signed hash: the external authorization was not verified".to_string(),
            ))
        };
    }
    let Some(hosts_of) = a.hosts_of else {
        return Ok(());
    };
    let submitting = &submitter.submitting_participant_uid;
    let cannot_submit: Vec<&String> = act_as
        .into_iter()
        .filter(|party| {
            !hosts_of(party).is_some_and(|(threshold, hosts)| {
                threshold <= 1
                    && hosts
                        .iter()
                        .any(|(uid, permission)| uid == submitting && *permission == SUBMISSION)
            })
        })
        .collect();
    if cannot_submit.is_empty() {
        Ok(())
    } else {
        Err(malformed(format!(
            "The submitting participant {submitting} is not authorized to submit on behalf of the submitting parties {cannot_submit:?}."
        )))
    }
}

/// What a participant keeps of a request it answered, to check the verdict about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFacts {
    /// The root hash the request's root hash message announced.
    pub root_hash: Vec<u8>,
    /// The mediator group the request's common metadata names (`None`: the request could not be read, or it is a reassignment).
    pub mediator_group: Option<u32>,
    /// The time by which the verdict has to be sequenced.
    pub decision_time: i64,
}

impl RequestFacts {
    /// The line that records the facts of `request` (tab-separated: request, root hash in hex, group or `-`, decision time).
    pub fn record(&self, request: i64) -> String {
        let group = self
            .mediator_group
            .map_or_else(|| "-".to_string(), |g| g.to_string());
        format!(
            "{request}\t{}\t{group}\t{}",
            hex::encode(&self.root_hash),
            self.decision_time
        )
    }

    /// The request and its facts from a line [`RequestFacts::record`] wrote; `None` for a line that is not one.
    pub fn parse(line: &str) -> Option<(i64, RequestFacts)> {
        let mut fields = line.trim_end().split('\t');
        let request = fields.next()?.parse().ok()?;
        let root_hash = hex::decode(fields.next()?).ok()?;
        let mediator_group = match fields.next()? {
            "-" => None,
            group => Some(group.parse().ok()?),
        };
        let decision_time = fields.next()?.parse().ok()?;
        fields.next().is_none().then_some((
            request,
            RequestFacts {
                root_hash,
                mediator_group,
                decision_time,
            },
        ))
    }
}

/// Whose signatures make a verdict the mediator's.
pub enum MediatorTrust<'a> {
    /// The topology is followed: the mediator groups in force and the signing keys of a member (`MED::<uid>`).
    Topology {
        groups: &'a BTreeMap<u32, MediatorGroup>,
        keys_of: &'a dyn Fn(&str) -> Option<Vec<PublicKey>>,
    },
    /// Configured by hand: the mediator's keys, any one of which signs.
    Configured(&'a [PublicKey]),
}

/// A verdict as it arrived: decoded, with the hash its signatures cover, the signatures, and the event's sequencing time.
pub struct ReceivedVerdict<'a> {
    pub verdict: &'a Verdict,
    pub signed_hash: &'a [u8],
    pub signatures: &'a [Signature],
    pub sequenced_at: i64,
}

/// Whether a verdict may resolve the request it names; why not, if not (the verdict is then set aside).
///
/// [CANTON-NOTE: SEMANTICS] `ProtocolProcessor.processResultInternal`: the result is sequenced after the request and not after its
/// decision time, its signatures are the request's mediator group's (`verifyMediatorSignatures(snapshot, pendingRequestData.mediator.group)`:
/// the group's threshold of distinct active mediators) and its root hash is the pending request's.
///
/// [CANTON-NOTE: SEMANTICS] The mediator groups and keys are the ones in force at the verdict's sequencing time (`filterInvalidSignature`:
/// `crypto.awaitSnapshot(resultTs)`), with the group index the request named.
///
/// [CANTON-NOTE: LIMITATION] What a request whose facts are unknown (`facts` `None`: this participant never answered it) can be checked by:
/// only the signatures, by any group in force. Such a verdict resolves nothing in the contract set.
pub fn check_verdict(
    received: &ReceivedVerdict,
    facts: Option<&RequestFacts>,
    trust: &MediatorTrust,
) -> Result<(), String> {
    let verdict = received.verdict;
    if let Some(facts) = facts {
        if received.sequenced_at <= verdict.request_id {
            return Err(format!(
                "it is sequenced at {}, not after the request",
                received.sequenced_at
            ));
        }
        if received.sequenced_at > facts.decision_time {
            return Err(format!(
                "it is sequenced at {}, after the decision time {}",
                iso_utc(received.sequenced_at),
                iso_utc(facts.decision_time)
            ));
        }
        if verdict.root_hash != facts.root_hash {
            return Err("its root hash is not the request's".into());
        }
    }
    match trust {
        MediatorTrust::Configured(keys) => {
            if crate::view_acs::mediator_signed_at(
                received.signatures,
                received.signed_hash,
                keys,
                &received.verdict.physical_synchronizer_id,
                received.sequenced_at,
            ) {
                Ok(())
            } else {
                Err("it is not signed by the mediator".into())
            }
        }
        MediatorTrust::Topology { groups, keys_of } => {
            let named = facts.and_then(|f| f.mediator_group);
            let candidates: Vec<&MediatorGroup> = match named {
                Some(group) => groups.get(&group).into_iter().collect(),
                None => groups.values().collect(),
            };
            if candidates
                .iter()
                .any(|group| signed_by_group(group, keys_of, received))
            {
                Ok(())
            } else {
                Err(match named {
                    Some(group) => format!(
                        "it is not signed by the threshold of the active mediators of group {group}"
                    ),
                    None => "it is not signed by the threshold of any mediator group".into(),
                })
            }
        }
    }
}

/// Why a mediator's timeout verdict sequenced at `sequenced_at` comes too early, if it does: not after the participant response deadline of
/// its request (`TimeoutResultTooEarly`, "Received mediator timeout message at ... before response deadline").
///
/// [CANTON-NOTE: SEMANTICS] Canton tells a timeout by its error code id (`isTimeoutDeterminedByMediator`: `MEDIATOR_SAYS_TX_TIMED_OUT`); the
/// status message starts with that id.
pub fn check_timeout_not_early(
    verdict: &Verdict,
    sequenced_at: i64,
    response_deadline: i64,
) -> Result<(), String> {
    let timeout = matches!(
        verdict.kind,
        crate::view_acs::VerdictKind::MediatorReject { .. }
    ) && verdict.reason.starts_with("MEDIATOR_SAYS_TX_TIMED_OUT");
    if timeout && sequenced_at <= response_deadline {
        return Err(format!(
            "it is a timeout sequenced at {}, before the response deadline {}",
            iso_utc(sequenced_at),
            iso_utc(response_deadline)
        ));
    }
    Ok(())
}

/// Whether `group` is active (`threshold >= 1`) and `group.threshold` distinct active mediators each made one of the signatures.
fn signed_by_group(
    group: &MediatorGroup,
    keys_of: &dyn Fn(&str) -> Option<Vec<PublicKey>>,
    received: &ReceivedVerdict,
) -> bool {
    if !group.is_active() {
        return false;
    }
    let unique_active: std::collections::BTreeSet<&str> =
        group.active.iter().map(String::as_str).collect();
    let signers = unique_active
        .into_iter()
        .filter(|uid| {
            let keys = keys_of(&format!("MED::{uid}")).unwrap_or_default();
            crate::view_acs::mediator_signed_at(
                received.signatures,
                received.signed_hash,
                &keys,
                &received.verdict.physical_synchronizer_id,
                received.sequenced_at,
            )
        })
        .count();
    signers >= usize::try_from(group.threshold).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: i64 = 1_000_000_000_000;

    fn times(ledger: i64, preparation: i64, max: Option<i64>) -> RequestTimes {
        RequestTimes {
            record_time: RECORD,
            ledger_time: ledger,
            preparation_time: preparation,
            max_record_time: max,
        }
    }

    fn refusal(t: RequestTimes) -> String {
        check_times(&t, TimeTolerances::default()).unwrap_err()
    }

    #[test]
    fn the_bounds_of_the_ledger_time_are_inclusive() {
        let tolerance = TimeTolerances::default().ledger_time_record_time_micros;
        for ledger in [RECORD - tolerance, RECORD, RECORD + tolerance] {
            assert_eq!(
                check_times(&times(ledger, RECORD, None), TimeTolerances::default()),
                Ok(())
            );
        }
        for ledger in [RECORD - tolerance - 1, RECORD + tolerance + 1] {
            assert!(refusal(times(ledger, RECORD, None))
                .starts_with("LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"));
        }
    }

    #[test]
    fn the_preparation_time_is_checked_after_the_ledger_time() {
        let day = TimeTolerances::default().preparation_time_record_time_micros;
        assert!(refusal(times(RECORD, RECORD - day - 1, None))
            .starts_with("LOCAL_VERDICT_PREPARATION_TIME_OUT_OF_BOUND"));
        assert!(refusal(times(RECORD + day, RECORD + day + 1, None))
            .starts_with("LOCAL_VERDICT_LEDGER_TIME_OUT_OF_BOUND"));
        assert_eq!(
            check_times(
                &times(RECORD, RECORD + day, None),
                TimeTolerances::default()
            ),
            Ok(())
        );
    }

    #[test]
    fn an_external_signers_maximum_record_time_is_a_bound_too() {
        assert!(refusal(times(RECORD, RECORD, Some(RECORD - 1)))
            .starts_with("LOCAL_VERDICT_MAX_RECORD_TIME_EXCEEDED"));
        assert_eq!(
            check_times(
                &times(RECORD, RECORD, Some(RECORD)),
                TimeTolerances::default()
            ),
            Ok(())
        );
    }

    #[test]
    fn the_tolerances_follow_the_parameters_and_default_when_unset() {
        let mut parameters = crate::topology_wire::default_dynamic_parameters();
        parameters.ledger_time_record_time_tolerance = Some(prost_types::Duration {
            seconds: 5,
            nanos: 0,
        });
        parameters.preparation_time_record_time_tolerance = None;
        let tolerances = TimeTolerances::of(&parameters);
        assert_eq!(tolerances.ledger_time_record_time_micros, 5_000_000);
        assert_eq!(
            tolerances.preparation_time_record_time_micros,
            TimeTolerances::default().preparation_time_record_time_micros
        );
        assert!(check_times(&times(RECORD + 5_000_001, RECORD, None), tolerances).is_err());
    }

    fn exercise_view(actors: &[&str], position: Vec<Vec<bool>>) -> RevealedView {
        use canton_proto::com::digitalasset::canton::protocol::v30::action_description::ExerciseActionDescription;
        use canton_proto::com::digitalasset::canton::protocol::v31::ActionDescription;
        let participant_data =
            canton_proto::com::digitalasset::canton::protocol::v32::ViewParticipantData {
                action_description: Some(ActionDescription {
                    description: Some(Description::Exercise(ExerciseActionDescription {
                        actors: actors.iter().map(|a| a.to_string()).collect(),
                        ..Default::default()
                    })),
                }),
                ..Default::default()
            };
        RevealedView {
            view_hash: vec![],
            common_data: Default::default(),
            participant_data,
            position,
            has_subviews: false,
        }
    }

    fn submitter(act_as: &[&str], participant: &str) -> SubmitterMetadata {
        SubmitterMetadata {
            act_as: act_as.iter().map(|a| a.to_string()).collect(),
            submitting_participant_uid: participant.into(),
            ..Default::default()
        }
    }

    /// alice is hosted by p1 to submit, bob by p2 (this participant) to confirm.
    fn hosting(party: &str) -> Option<(u32, Vec<(String, i32)>)> {
        match party {
            "alice" => Some((1, vec![("p1".into(), 1)])),
            "bob" => Some((1, vec![("p2".into(), 2)])),
            _ => None,
        }
    }

    fn check(
        view: &RevealedView,
        submitter: Option<&SubmitterMetadata>,
        followed: bool,
    ) -> Result<(), String> {
        let hosts_of: &HostsOf = &hosting;
        check_authorization(
            view,
            &Authorization {
                submitter,
                me: "p2",
                hosts_of: followed.then_some(hosts_of),
                hosted_parties: &["bob".to_string()],
                external_verified: false,
            },
        )
    }

    #[test]
    fn a_top_level_view_needs_its_actors_among_the_submitting_parties_hosted_to_submit() {
        let view = exercise_view(&["alice"], vec![vec![]]);
        assert_eq!(
            check(&view, Some(&submitter(&["alice"], "p1")), true),
            Ok(())
        );
        assert!(check(&view, Some(&submitter(&["bob"], "p1")), true)
            .unwrap_err()
            .contains("through the submitting parties"));
        // p2 does not host alice at all; bob is hosted by p2 only to confirm; an unknown party is hosted nowhere
        for (act_as, by) in [
            (&["alice"][..], "p2"),
            (&["alice", "bob"][..], "p2"),
            (&["alice", "carol"][..], "p1"),
        ] {
            assert!(
                check(&view, Some(&submitter(act_as, by)), true)
                    .unwrap_err()
                    .contains("is not authorized to submit"),
                "{act_as:?} by {by}"
            );
        }
    }

    #[test]
    fn an_external_authorization_skips_the_submission_permission_only_once_verified() {
        // an empty external authorization, as a submitting participant without the parties' keys could forge it
        let view = exercise_view(&["carol"], vec![vec![]]);
        let mut external = submitter(&["carol"], "p1");
        external.external_authorization = Some(Default::default());
        let hosts_of: &HostsOf = &hosting;
        let with = |verified: bool| {
            check_authorization(
                &view,
                &Authorization {
                    submitter: Some(&external),
                    me: "p2",
                    hosts_of: Some(hosts_of),
                    hosted_parties: &[],
                    external_verified: verified,
                },
            )
        };
        assert!(with(false)
            .unwrap_err()
            .contains("Failed to compute externally signed hash"));
        assert_eq!(with(true), Ok(()));
        // control: the same submission without the claim is checked for the permission
        assert!(check(&view, Some(&submitter(&["carol"], "p1")), true)
            .unwrap_err()
            .contains("is not authorized to submit"));
    }

    #[test]
    fn a_runtime_configured_by_hand_checks_the_submitting_parties_but_not_the_permission() {
        let view = exercise_view(&["alice"], vec![vec![]]);
        assert_eq!(
            check(&view, Some(&submitter(&["alice"], "p2")), false),
            Ok(())
        );
        assert!(check(&view, Some(&submitter(&["bob"], "p2")), false).is_err());
    }

    #[test]
    fn a_root_view_below_an_unseen_parent_may_not_have_an_authorizer_hosted_here() {
        let below = exercise_view(&["bob"], vec![vec![], vec![]]);
        for followed in [true, false] {
            assert!(check(&below, None, followed)
                .unwrap_err()
                .contains("Missing authorization for [\"bob\"]"));
        }
        assert_eq!(
            check(&exercise_view(&["alice"], vec![vec![], vec![]]), None, true),
            Ok(())
        );
    }

    #[test]
    fn only_a_view_whose_parent_is_not_revealed_is_a_root() {
        let parent = exercise_view(&["alice"], vec![vec![]]);
        let child = exercise_view(&["bob"], vec![vec![false], vec![]]);
        let revealed = [parent.clone(), child.clone()];
        assert!(is_root_of_revealed(&parent, &revealed));
        assert!(!is_root_of_revealed(&child, &revealed));
        assert!(is_root_of_revealed(&child, std::slice::from_ref(&child)));
    }

    #[test]
    fn the_facts_of_a_request_read_back_as_they_were_recorded() {
        for group in [Some(3), None] {
            let facts = RequestFacts {
                root_hash: vec![0x12, 0x20, 7],
                mediator_group: group,
                decision_time: 42,
            };
            assert_eq!(RequestFacts::parse(&facts.record(9)), Some((9, facts)));
        }
        assert_eq!(RequestFacts::parse("9\tzz\t0\t42"), None);
        assert_eq!(RequestFacts::parse("9\t12\t0\t42\textra"), None);
    }
}
