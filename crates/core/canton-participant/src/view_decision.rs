//! What a receiving participant answers to a confirmation request (G5 5.6m, S-NET-021): approve, reject, or "I cannot read this".
//!
//! [CANTON-NOTE: SEMANTICS] The decision follows the order in which a participant can know things:
//! 1. The request has to be **readable**: the view decrypts with this participant's key, the tree's hashes add up to the root hash
//!    the sender announced, the view is one the message lists, and the signature of the submitting participant the request names (for
//!    a top-level view) holds. If any of it fails the answer is **malformed** (no confirming parties, no view position): the participant
//!    cannot say anything about the content, and the mediator treats the whole request as malformed. A root view whose action is not
//!    authorized (`view_validation::check_authorization`) is malformed too.
//! 2. The view has to **conform**: the engine reproduces what it claims (`view_conformance`). A view that does not conform is
//!    **malformed** (`LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK`, `LocalRejectError.MalformedRejects.ModelConformance`), answered for
//!    that view's position.
//!    A request whose ledger or preparation time is too far from its sequencing time is **rejected** in every view
//!    (`view_validation::check_times`).
//! 3. The view must be **consistent with the contract set** (`view_acs`): it may not consume a contract that is not active, is
//!    archived, or is locked by another request in flight, nor create one that exists. A conflict is a **rejection** too. Only a view
//!    that passed all three is **approved**, and only then are its contracts locked (a refused request locks nothing).
//!
//! The answer is given for the parties the participant **confirms** in the view (the informees it hosts that carry weight in a
//! quorum); a participant that confirms nothing in the view has nothing to answer.
//!
//! A request can reveal several views to a participant (sibling subviews, or a root and the views below it): the answer is **one
//! decision per revealed view**, sent in one confirmation response message. The contracts of the views the participant approves are
//! locked together under the one request (`Ledger` knows requests, not views); if the lock conflicts, every approved view is
//! rejected for it.
//!
//! [CANTON-NOTE: LIMITATION] Create, exercise and fetch views only; a view rooted in any other action is refused as nonconforming.
use crate::confirmation_wire::Outcome;
use crate::view_acs::{effects_of, Effects, Ledger};
use crate::view_conformance::{
    check_discriminators_at, check_exercise_view_with_events, check_fetch_view, check_quorums,
    check_view, Engine, Nonconformance,
};
use crate::view_informees::{check_informees, single_node_informees, CoreInformees};
use crate::view_receive::{
    check_views, decrypt_views, revealed_common_metadata, revealed_participant_metadata,
    revealed_submitter_metadata, ReceiveError, RevealedView,
};
use crate::view_validation::{
    check_authorization, check_times, is_root_of_revealed, Authorization, HostsOf, RequestTimes,
    TimeTolerances,
};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;

/// What this participant is: its encryption key, its engine, and the parties it hosts.
pub struct Participant<'a> {
    pub encryption_fingerprint: &'a str,
    pub encryption_secret: &'a [u8; 32],
    pub engine: &'a Engine,
    /// The parties this participant hosts with permission to confirm.
    pub hosted_parties: &'a [String],
    /// Whether a signature over a root hash is the submitting participant's: the participant (uid) the submitter metadata names, `None`
    /// when the tree has the submitter metadata blinded.
    pub verify_submitter: &'a dyn Fn(Option<&str>, &Signature, &[u8]) -> bool,
    /// How far the request's ledger and preparation times may be from its sequencing time.
    pub time_tolerances: TimeTolerances,
    /// This participant's uid (`name::namespace`).
    pub uid: &'a str,
    /// Who hosts a party, when the topology is followed (`None`: configured by hand, see [`check_authorization`]).
    pub hosts_of: Option<&'a HostsOf<'a>>,
    /// The signing keys of a party, when the topology is followed: what an external authorization is verified against (`None`: an
    /// externally signed request is refused).
    pub party_keys: Option<&'a crate::external_hash::PartyKeys<'a>>,
    /// The packages a participant vets, when the topology is followed: what the package vetting of the parties that see the view is
    /// checked against (`None`: configured by hand, nothing is checked).
    pub vetted_at: Option<&'a crate::view_vetting::VettedAt<'a>>,
}

/// A confirmation request as it was delivered.
pub struct Request<'a> {
    /// The request's sequencing time (the request id).
    pub request_time: i64,
    /// The envelope content of the encrypted view message.
    pub view_envelope: &'a [u8],
    /// The root hash the root hash message of the same event announced.
    pub announced_root_hash: &'a [u8],
    /// The time by which the verdict has to be in; the request is rejected by `Ledger::expire` if it is not. `None`: no limit.
    pub decision_time: Option<i64>,
}

/// What to answer for the first revealed view of `request` (see [`decide_all_envelopes`]). The caller has checked the event's root hash
/// message, so the mediator group the views declare is not compared with it here.
pub fn decide(participant: &Participant, ledger: &mut Ledger, request: &Request) -> Decision {
    match decide_all_envelopes(
        participant,
        ledger,
        request.request_time,
        request.decision_time,
        request.announced_root_hash,
        None,
        &[request.view_envelope],
    ) {
        Ok(mut decisions) if !decisions.is_empty() => decisions.remove(0),
        Ok(_) => malformed("no revealed view"),
        Err(why) => malformed(why),
    }
}

/// The answer, and what it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    /// The position of the view the answer is for (empty for a malformed request).
    pub view_position: Vec<Vec<bool>>,
    /// The parties the answer is for.
    pub confirming_parties: Vec<String>,
}

// [CANTON-NOTE: SEMANTICS] R-15 / `ProcessingSteps.scala:696`, `AuthenticationValidator.scala:234-244`,
// `TransactionConfirmationResponsesFactory.scala:185-193`: wrong view signatures emit
// `LOCAL_VERDICT_MALFORMED_REQUEST`, whereas decryption/deserialization/hash errors emit
// `LOCAL_VERDICT_MALFORMED_PAYLOAD`.
fn malformed(why: impl std::fmt::Debug) -> Decision {
    Decision {
        outcome: Outcome::Malformed(format!("LOCAL_VERDICT_MALFORMED_PAYLOAD: {why:?}")),
        view_position: Vec::new(),
        confirming_parties: Vec::new(),
    }
}

fn malformed_receive(err: ReceiveError) -> Decision {
    match err {
        ReceiveError::BadSignature => Decision {
            outcome: Outcome::Malformed(
                "LOCAL_VERDICT_MALFORMED_REQUEST: a view that is not correctly authenticated: BadSignature"
                    .into(),
            ),
            view_position: Vec::new(),
            confirming_parties: Vec::new(),
        },
        other => malformed(other),
    }
}

/// The informees of `view` that carry weight in a quorum, and that `hosted` contains.
fn confirmed_by(view: &RevealedView, hosted: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for quorum in &view.common_data.quorums {
        for member in &quorum.party_index_and_weight {
            if member.weight <= 0 {
                continue;
            }
            if let Some(party) = view.common_data.informees.get(member.index as usize) {
                if hosted.contains(party) && !out.contains(party) {
                    out.push(party.clone());
                }
            }
        }
    }
    out
}

/// What the checks found about one view, before anything is locked.
struct Checked<'v> {
    view: &'v RevealedView,
    confirming: Vec<String>,
    /// What the view does when it conforms (Canton's model conformance), or why it does not.
    conforming: Result<Effects, String>,
    /// The answer before the contract set is consulted: `Ok` to approve, else the refusal (a rejection or a malformed view).
    verdict: Result<(), Outcome>,
}

/// Decides what to answer across all encrypted view envelopes of one confirmation request (when subviews have distinct recipient sets
/// and therefore arrive in separate envelopes of the same delivered event), locking combined effects once under `request_time`: one
/// decision per revealed view (at least one).
///
/// `Err` when the request is not processed at all (nothing is answered or locked): the views declare another mediator group than
/// `mediator_group`, the one the root hash message is sent to (`None`: the caller does not check it).
pub fn decide_all_envelopes(
    participant: &Participant,
    ledger: &mut Ledger,
    request_time: i64,
    decision_time: Option<i64>,
    announced_root_hash: &[u8],
    mediator_group: Option<u32>,
    view_envelopes: &[&[u8]],
) -> Result<Vec<Decision>, String> {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        CommonMetadata, GenTransactionTree,
    };

    let mut entries: Vec<(RevealedView, GenTransactionTree, CommonMetadata)> = Vec::new();
    for env in view_envelopes {
        let views = match decrypt_views(
            env,
            participant.encryption_fingerprint,
            participant.encryption_secret,
        ) {
            Ok(v) => v,
            Err(e) => return Ok(vec![malformed_receive(e)]),
        };
        // [CANTON-NOTE: SEMANTICS] The signature is verified with the keys of the participant the submitter metadata names
        // (`AuthenticationValidator.verifyParticipantSignature` with `submitterMetadata.submittingParticipant`); the trees of one message share
        // one root hash, so one submitter metadata.
        let submitting = views
            .view_trees
            .iter()
            .filter_map(|t| t.tree.as_ref())
            .find_map(|t| revealed_submitter_metadata(t).ok())
            .map(|m| m.submitting_participant_uid);
        let env_revealed = match check_views(&views, announced_root_hash, |s, r| {
            (participant.verify_submitter)(submitting.as_deref(), s, r)
        }) {
            Ok(v) => v,
            Err(e) => return Ok(vec![malformed_receive(e)]),
        };
        if env_revealed.is_empty() {
            return Ok(vec![malformed("no revealed view")]);
        }
        let Some(tree) = views
            .view_trees
            .first()
            .and_then(|t| t.tree.as_ref())
            .cloned()
        else {
            return Ok(vec![malformed("no tree")]);
        };
        let common = match revealed_common_metadata(&tree) {
            Ok(c) => c,
            Err(e) => return Ok(vec![malformed(e)]),
        };
        for rv in env_revealed {
            if !entries
                .iter()
                .any(|(existing, _, _)| existing.view_hash == rv.view_hash)
            {
                entries.push((rv, tree.clone(), common.clone()));
            }
        }
    }
    if entries.is_empty() {
        return Ok(vec![malformed("no revealed view")]);
    }
    // [CANTON-NOTE: SEMANTICS] `ProtocolProcessor`: "Mediator ... declared in views is not the recipient ... of the root hash message". The
    // submitting participant is then malicious; the request is not processed and waits for its verdict or its decision time.
    // All views with the root hash share one common metadata, so the first one tells.
    if let (Some((_, _, common)), Some(expected)) = (entries.first(), mediator_group) {
        if u32::try_from(common.mediator_group).ok() != Some(expected) {
            return Err(format!(
                "Mediator group {} declared in views is not the recipient MGR::{expected} of the root hash message",
                common.mediator_group
            ));
        }
    }
    let all_revealed: Vec<RevealedView> = entries.iter().map(|(rv, _, _)| rv.clone()).collect();
    let times = request_times(entries.iter().map(|(_, tree, _)| tree), request_time)
        .map(|t| check_times(&t, participant.time_tolerances));
    let all_trees: Vec<&GenTransactionTree> = entries.iter().map(|(_, tree, _)| tree).collect();
    let checked: Vec<Checked> = entries
        .iter()
        .map(|(view, tree, common)| {
            let conforming = check_one(participant, view, &all_revealed, tree, common, ledger);
            let verdict = authorize(participant, view, &all_revealed, tree, &all_trees)
                .map_err(Outcome::Malformed)
                .and_then(|()| {
                    conforming
                        .as_ref()
                        .map(|_| ())
                        .map_err(|why| Outcome::Malformed(why.clone()))
                })
                // [CANTON-NOTE: SEMANTICS] A time rejection is a local rejection of every view; a view that does not conform is refused
                // for that first (Canton's model conformance failure is malformed, which outranks a rejection).
                .and_then(|()| match &times {
                    Some(Err(why)) => Err(Outcome::Reject(why.clone())),
                    _ => Ok(()),
                });
            Checked {
                view,
                confirming: confirmed_by(view, participant.hosted_parties),
                conforming,
                verdict,
            }
        })
        .collect();
    // one lock for the request: the effects of every view that passed, together
    let approved: Vec<&Checked> = checked.iter().filter(|c| c.verdict.is_ok()).collect();
    let conflict = if approved.is_empty() {
        None
    } else {
        let effects = combined_effects(participant, ledger, &approved, &all_revealed);
        let uses = match used_contracts(participant, &checked, &effects) {
            Ok(uses) => uses,
            Err(why) => return Ok(vec![malformed(&why)]),
        };
        ledger
            .begin_using(
                request_time,
                effects,
                &uses,
                decision_time.unwrap_or(i64::MAX),
            )
            .err()
    };
    // what an approving verdict commits beyond what is locked: the conforming views this participant refused
    let refused: Vec<&Checked> = checked
        .iter()
        .filter(|c| (c.verdict.is_err() || conflict.is_some()) && family_conforms(c.view, &checked))
        .collect();
    if !refused.is_empty() {
        let effects = combined_effects(participant, ledger, &refused, &all_revealed);
        if let Err(conflict) =
            ledger.keep_refused(request_time, effects, decision_time.unwrap_or(i64::MAX))
        {
            return Err(format!("the request cannot be kept: {conflict:?}"));
        }
    }
    let decisions = checked
        .into_iter()
        .map(|c| Decision {
            outcome: match (&c.verdict, &conflict) {
                (Err(refusal), _) => refusal.clone(),
                // [CANTON-NOTE: SEMANTICS] R-15 / `TransactionConfirmationResponsesFactory.scala:83-128`,
                // `LocalRejectError.scala:285-294`: committed duplicate creates are `Malformed`
                // (`LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS`), while locked inputs/creates are
                // `Reject` (`LOCAL_VERDICT_LOCKED_CONTRACTS`) and inactive inputs are `Reject`
                // (`LOCAL_VERDICT_INACTIVE_CONTRACTS`).
                (Ok(()), Some(conflict)) => match conflict {
                    crate::view_acs::Conflict::ContractAlreadyExists(_) => Outcome::Malformed(
                        format!(
                            "LOCAL_VERDICT_CREATES_EXISTING_CONTRACTS: conflict with the contract set: {conflict:?}"
                        ),
                    ),
                    crate::view_acs::Conflict::LockedContract { .. } => Outcome::Reject(format!(
                        "LOCAL_VERDICT_LOCKED_CONTRACTS: conflict with the contract set: {conflict:?}"
                    )),
                    _ => Outcome::Reject(format!(
                        "LOCAL_VERDICT_INACTIVE_CONTRACTS: conflict with the contract set: {conflict:?}"
                    )),
                },
                (Ok(()), None) => Outcome::Approve,
            },
            view_position: c.view.position.clone(),
            confirming_parties: c.confirming,
        })
        .collect();
    Ok(decisions)
}

/// Whether the effects of `view` are committed when the mediator approves: it conforms, and so does every view of the family of its root among
/// the revealed views (Canton's valid subtransaction is made of whole root views whose reinterpretation succeeds).
fn family_conforms(view: &RevealedView, checked: &[Checked]) -> bool {
    let root = checked
        .iter()
        .map(|c| c.view)
        .filter(|r| view.position.ends_with(&r.position))
        .min_by_key(|r| r.position.len())
        .unwrap_or(view);
    checked
        .iter()
        .filter(|c| c.view.position.ends_with(&root.position))
        .all(|c| c.conforming.is_ok())
}

/// The input contracts of the views that are used without being consumed (fetched, or exercised by a non-consuming choice) and that this
/// participant must know to be active: a stakeholder that is an informee of the view is hosted here, and the request neither creates nor
/// consumes it.
///
/// [CANTON-NOTE: SEMANTICS] `ExtractUsedAndCreated.inputContractPrep`: `contractIdsOfHostedInformeeStakeholder`; a contract only the
/// other participants' parties are stakeholders of is not checked (this participant need not know it).
fn used_contracts(
    participant: &Participant,
    checked: &[Checked],
    effects: &Effects,
) -> Result<Vec<String>, String> {
    use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
    use prost::Message;
    let created: Vec<&String> = checked
        .iter()
        .filter_map(|c| c.conforming.as_ref().ok())
        .flat_map(|e| e.creates.iter().map(|(id, _)| id))
        .collect();
    let mut uses = Vec::new();
    for c in checked {
        if c.conforming.is_err() {
            continue;
        }
        let informees = &c.view.common_data.informees;
        for input in c
            .view
            .participant_data
            .core_inputs
            .iter()
            .filter(|i| !i.consumed)
        {
            let versioned = Versioned::decode(input.contract.as_slice())
                .map_err(|e| format!("a non-consumed core input does not decode: {e}"))?;
            let fci = FatContractInstance::decode(versioned.payload.as_slice())
                .map_err(|e| format!("a non-consumed core input contract does not decode: {e}"))?;
            let id = hex::encode(&fci.contract_id);
            let maintainers = fci
                .contract_key_with_maintainers
                .as_ref()
                .map(|k| k.maintainers.as_slice())
                .unwrap_or(&[]);
            let hosted_informee_stakeholder = fci
                .non_maintainer_signatories
                .iter()
                .chain(&fci.non_signatory_stakeholders)
                .chain(maintainers)
                .any(|p| informees.contains(p) && participant.hosted_parties.contains(p));
            if hosted_informee_stakeholder
                && !created.contains(&&id)
                && !effects.consumes.contains(&id)
                && !uses.contains(&id)
            {
                uses.push(id);
            }
        }
    }
    Ok(uses)
}

/// Pre-order key for [`RevealedView::position`] (reverses both nesting order and path-to-root segments).
fn view_preorder_key(position: &[Vec<bool>]) -> Vec<Vec<bool>> {
    position
        .iter()
        .rev()
        .map(|seg| seg.iter().rev().copied().collect())
        .collect()
}

/// The effects of `views` together (each one conforms).
///
/// A consumed input contract whose stakeholders include no party hosted here and whose id this participant never tracked is an explicitly
/// disclosed foreign contract (its authenticity was verified in `check_one`; the stakeholder participant checks and archives it).
fn combined_effects(
    participant: &Participant,
    ledger: &Ledger,
    views: &[&Checked],
    revealed: &[RevealedView],
) -> Effects {
    let consumed_has_hosted_stakeholder = |view: &RevealedView, cid: &str| -> bool {
        use canton_proto::com::digitalasset::daml::lf::transaction::{
            FatContractInstance, Versioned,
        };
        use prost::Message;
        if participant.hosted_parties.is_empty() {
            return true;
        }
        for input in &view.participant_data.core_inputs {
            let Ok(v) = Versioned::decode(input.contract.as_slice()) else {
                continue;
            };
            let Ok(fci) = FatContractInstance::decode(v.payload.as_slice()) else {
                continue;
            };
            if hex::encode(&fci.contract_id) != cid {
                continue;
            }
            let maintainers = fci
                .contract_key_with_maintainers
                .as_ref()
                .map(|k| k.maintainers.as_slice())
                .unwrap_or(&[]);
            return fci
                .non_maintainer_signatories
                .iter()
                .chain(&fci.non_signatory_stakeholders)
                .chain(maintainers)
                .any(|p| participant.hosted_parties.contains(p));
        }
        true
    };
    let mut ordered: Vec<&Checked> = views.to_vec();
    ordered.sort_by_cached_key(|c| view_preorder_key(&c.view.position));
    let mut all = Effects::default();
    for c in &ordered {
        let Ok(e) = &c.conforming else {
            continue;
        };
        for id in &e.consumes {
            let require_local =
                ledger.knows_contract(id) || consumed_has_hosted_stakeholder(c.view, id);
            if require_local && !all.consumes.contains(id) {
                all.consumes.push(id.clone());
            }
        }
        all.creates.extend(e.creates.iter().cloned());
        all.instances.extend(e.instances.iter().cloned());
        // Root-of-revealed views already replay their whole revealed subview subtree; emitting only
        // root-of-revealed views in pre-order preserves tree structure without duplicating subviews.
        if is_root_of_revealed(c.view, revealed) {
            all.remote_events.extend(e.remote_events.iter().cloned());
        }
    }
    all
}

/// The authorization of `view` when it is a root of what this participant sees (a view below a revealed one is authorized by its parent's
/// action, which the conformance check replays).
fn authorize(
    participant: &Participant,
    view: &RevealedView,
    revealed: &[RevealedView],
    tree: &canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
    trees: &[&canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree],
) -> Result<(), String> {
    if !is_root_of_revealed(view, revealed) {
        return Ok(());
    }
    // a top-level view's tree reveals the submitter metadata; a subview's recipient gets it blinded
    let submitter = (view.position.len() == 1)
        .then(|| revealed_submitter_metadata(tree).ok())
        .flatten();
    let external_verified = match submitter.as_ref() {
        Some(s) if s.external_authorization.is_some() => {
            let verified = match participant.party_keys {
                Some(keys) => crate::external_hash::verify_in(participant.engine, tree, revealed, keys),
                None => Err("this participant does not follow the topology: no party keys to verify against".into()),
            };
            external_trees::capture(tree, trees, &verified);
            verified.map_err(|cause| {
                format!(
                    "LOCAL_VERDICT_MALFORMED_REQUEST: a view that is not correctly authenticated: {:?} has an invalid signature: {cause}",
                    view.position
                )
            })?;
            true
        }
        _ => false,
    };
    check_authorization(
        view,
        &Authorization {
            submitter: submitter.as_ref(),
            me: participant.uid,
            hosts_of: participant.hosts_of,
            hosted_parties: participant.hosted_parties,
            external_verified,
        },
    )
}

/// The times of the request the trees belong to (they share one root hash, so one participant metadata), `None` when no tree reveals
/// the participant metadata (the conformance check refuses such a view, see [`check_one`]).
fn request_times<'t>(
    trees: impl Iterator<
            Item = &'t canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
        > + Clone,
    record_time: i64,
) -> Option<RequestTimes> {
    let metadata = trees
        .clone()
        .find_map(|tree| revealed_participant_metadata(tree).ok())?;
    let max_record_time = trees
        .filter_map(|tree| revealed_submitter_metadata(tree).ok())
        .find_map(|s| s.external_authorization.and_then(|e| e.max_record_time));
    Some(RequestTimes {
        record_time,
        ledger_time: metadata.ledger_time,
        preparation_time: metadata.preparation_time,
        max_record_time,
    })
}

/// Whether one revealed view conforms (the engine reproduces it, its discriminators and quorums are right) and what it would lock.
fn check_one(
    participant: &Participant,
    view: &RevealedView,
    revealed: &[RevealedView],
    tree: &canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
    common: &canton_proto::com::digitalasset::canton::protocol::v30::CommonMetadata,
    ledger: &Ledger,
) -> Result<Effects, String> {
    // the choice code the engine replays may read the ledger time (`getTime`): it is the request's, which the participant metadata carries
    if let Ok(metadata) = revealed_participant_metadata(tree) {
        participant.engine.set_ledger_time(metadata.ledger_time);
    }
    // where the creates of an exercise sit in its tree, from the replay (see `check_discriminators_at`), and the informees its nodes give
    let mut positions: Option<Vec<Vec<usize>>> = None;
    let mut core = CoreInformees::Unknown;
    let mut exercise_events: Vec<crate::view_acs::RemoteEvent> = Vec::new();
    let mut party_packages = crate::view_vetting::PartyPackages::new();
    let mut exhaustive_keys = Vec::new();
    let conformance: Result<(), Nonconformance> = match view
        .participant_data
        .action_description
        .as_ref()
        .and_then(|a| a.description.as_ref())
    {
        Some(Description::Create(_)) => check_view(participant.engine, view, common).map(|_| ()),
        Some(Description::Exercise(_)) => {
            let subviews: Vec<&RevealedView> = revealed
                .iter()
                .filter(|other| {
                    other.position.len() > view.position.len()
                        && other.position.ends_with(&view.position)
                })
                .collect();
            let root_admin = (view.position.len() == 1)
                .then(|| {
                    revealed_submitter_metadata(tree)
                        .ok()
                        .map(|s| s.submitting_participant_uid)
                })
                .flatten();
            check_exercise_view_with_events(
                participant.engine,
                view,
                &subviews,
                common,
                root_admin.as_deref(),
                participant.hosts_of,
            )
            .map(|(conforming, placed, informees, events)| {
                party_packages = conforming.party_packages;
                exhaustive_keys = conforming.exhaustive_keys;
                positions = Some(placed);
                core = informees;
                exercise_events = events;
            })
        }
        Some(Description::Fetch(_)) => check_fetch_view(participant.engine, view).map(|_| ()),
        _ => Err(Nonconformance::Unsupported(
            "an action other than a create, an exercise or a fetch".into(),
        )),
    };
    // the discriminators need the preparation time, which the participant metadata (revealed to a participant that gets the view)
    // carries; a tree that hides it cannot be checked
    let conformance = conformance.and_then(|()| {
        let participant_metadata = revealed_participant_metadata(tree)
            .map_err(|e| Nonconformance::Malformed(format!("{e:?}")))?;
        check_discriminators_at(
            view,
            participant_metadata.preparation_time,
            positions.as_deref(),
        )?;
        if matches!(core, CoreInformees::Unknown) {
            core = single_node_informees(view)?;
        }
        // a create or a fetch view (an exercise's replay gave its own)
        if positions.is_none() {
            party_packages = crate::view_vetting::single_node_party_packages(view)?;
        }
        // a subview's recipient does not see the submitter metadata (blinded): its quorums have no admin party (measured, S-NET-035)
        if view.position.len() > 1 {
            check_informees(view, &core, None)?;
            return check_quorums(view, None);
        }
        let submitter = revealed_submitter_metadata(tree)
            .map_err(|e| Nonconformance::Malformed(format!("{e:?}")))?;
        check_informees(view, &core, Some(&submitter.submitting_participant_uid))?;
        check_quorums(view, Some(&submitter.submitting_participant_uid))
    });
    if let Err(n) = conformance {
        return Err(format!(
            "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: model conformance: {n:?}"
        ));
    }
    // [CANTON-NOTE: SEMANTICS] U-21: an exhaustive key query (`Node.QueryByKey.exhaustive`: `found.len() < limit`) must include
    // every active visible contract with that key known to this participant's ACS (unless consumed earlier in the same view).
    for q in &exhaustive_keys {
        for (cid, stakeholders) in ledger.active_contracts_for_key(&q.key_hash) {
            if q.stated_ids.contains(&cid) || q.consumed_before.contains(&cid) {
                continue;
            }
            let visible = stakeholders.iter().any(|p| q.submitters.contains(p));
            if visible {
                return Err(format!(
                    "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: model conformance: KeyDiffers(\"exhaustive key query of {} omitted active contract {cid}\")",
                    q.template_id
                ));
            }
        }
    }
    // [CANTON-NOTE: SEMANTICS] U-62 / `ModelConformanceChecker.checkTxPackageVetting`: every participant hosting a party that sees a node of
    // the reinterpreted view must vet the node's packages at the ledger time, this participant included; else `UnvettedPackages`.
    if let (Some(hosts_of), Some(vetted_at)) = (participant.hosts_of, participant.vetted_at) {
        let ledger_time = revealed_participant_metadata(tree)
            .map_err(|e| {
                format!("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: model conformance: {e:?}")
            })?
            .ledger_time;
        crate::view_vetting::check_vetted(&party_packages, hosts_of, vetted_at, ledger_time)?;
    }
    let mut effects =
        effects_of(view).ok_or_else(|| "the contracts of the view do not decode".to_string())?;
    if !exercise_events.is_empty() && !view.participant_data.rolled_back {
        effects.remote_events = exercise_events;
    }
    Ok(effects)
}

/// The trees of externally signed requests this process received, kept only while a test asks for them (U-56): the test vectors the
/// recomputation of the externally signed hash is developed against.
///
/// [CANTON-NOTE: WHY] The official participant recomputes the hash the external parties signed from the re-interpreted root view
/// (`AuthenticationValidator`). A tree an official participant sent, with the hash its signer signed, is the oracle that recomputation
/// must meet; capturing it once lets the recomputation be checked without a running synchronizer.
pub mod external_trees {
    use std::sync::Mutex;

    /// The trees of a kept request (each `GenTransactionTree` encoded, the root view's first) and what verifying its external
    /// authorization came to.
    pub type Captured = (Vec<Vec<u8>>, Result<(), String>);

    /// `None` while nobody asked: nothing is kept.
    static CAPTURED: Mutex<Option<Vec<Captured>>> = Mutex::new(None);

    /// Starts keeping the trees of externally signed requests (forgets those kept before).
    pub fn start() {
        *CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Vec::new());
    }

    /// The trees kept since [`start`] with their verification outcomes, and stops keeping.
    pub fn take() -> Vec<Captured> {
        CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .unwrap_or_default()
    }

    /// How many trees were kept since [`start`].
    pub fn len() -> usize {
        CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, Vec::len)
    }

    pub(super) fn capture(
        tree: &canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree,
        trees: &[&canton_proto::com::digitalasset::canton::protocol::v30::GenTransactionTree],
        verified: &Result<(), String>,
    ) {
        if let Some(kept) = CAPTURED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            let encoded = std::iter::once(tree)
                .chain(trees.iter().copied().filter(|t| *t != tree))
                .map(prost::Message::encode_to_vec)
                .collect();
            kept.push((encoded, verified.clone()));
        }
    }
}
