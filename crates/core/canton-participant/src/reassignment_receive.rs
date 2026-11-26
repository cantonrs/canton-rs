//! What a participant does with an unassignment or assignment request it receives (G7 B1, S-NET-040 part 3): decrypt the reassignment
//! view, check that it is the tree the submitting participant signed and the mediator was announced, and decide for the parties it hosts.
//!
//! [CANTON-NOTE: SEMANTICS] Read from `UnassignmentProcessingSteps`/`AssignmentProcessingSteps` and `ReassignmentValidation`:
//! - The request's view comes in the same `EncryptedMultipleViewsMessage` as a transaction's, with `view_type` `Unassignment` (2) or
//!   `Assignment` (3); its one tree is the **full** `ReassignmentViewTree` (versioned 30), not a light transaction view tree.
//! - The tree's recomputed root hash must be the root hash message's of the same event and the submitting participant's signature must
//!   cover it (else the request is malformed).
//! - The request must be for this synchronizer: the source of an unassignment, the target of an assignment.
//! - A participant answers for the **confirming parties** it hosts: the signatories and the submitting participant's admin party
//!   (`ReassignmentCommonData.confirmingParties`). The answer is for the view at the root position (`ViewPosition.root`, empty).
//! - An unassignment takes its contracts off this synchronizer when approved; an assignment brings them in with the counter it carries.
//!
//! - The stakeholders the view declares are the contracts' (`ReassignmentValidation.checkStakeholders`, else malformed), the submitter is one
//!   of them and is hosted on the submitting participant (`checkSubmitter`, else rejected with `REASSIGNMENT_VALIDATION_FAILED`).
//!
//! [CANTON-NOTE: LIMITATION] Not done here: checking on unassignment that every stakeholder is hosted on the **target** synchronizer
//! (because this participant follows one synchronizer per runtime). A runtime configured by hand (no hosting table) skips hosting and vetting checks.
//! `StoredUnassignment` is persisted to the runtime journal (`stored-unassignments.journal`) across restarts, and the runtimes of one
//! participant share what they hold (`participant_runtime::SharedUnassignments`, U-60): a reassigning participant judges an assignment by
//! the unassignment its runtime on the source synchronizer saw approved, whoever submitted it. A runtime that shares with none (or whose
//! participant never saw the unassignment) answers `LocalAbstain` with `UnassignmentDataNotFound`, as the official participant does.
use crate::reassignment_wire::{read_tree, Kind, ReadCommon};
use crate::topology_wire::unversioned;
use crate::view_crypto::{aes_gcm_decrypt, ecies_decrypt};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    blindable_node::BlindedOrNot, ReassignmentViewTree, ViewType,
};
use canton_proto::com::digitalasset::canton::protocol::v31::{AssignmentView, UnassignmentView};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    encrypted_multiple_views_message::UncompressedViewTrees, envelope_content::SomeEnvelopeContent,
    EnvelopeContent,
};
use prost::Message;

/// One contract a reassignment moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The contract id as hex.
    pub contract_id: String,
    pub template: String,
    pub source_validation_package_id: String,
    pub target_validation_package_id: String,
    /// The reassignment counter the request carries (already incremented by the unassignment).
    pub counter: i64,
    /// The serialized contract instance (`ContractInstance.encoded`).
    pub instance: Vec<u8>,
}

/// One contract captured in an approved [`StoredUnassignment`] for cross-checking a later assignment (`AssignmentValidation.scala`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredReassignedContract {
    pub contract_id: String,
    pub counter: i64,
    pub source_validation_package_id: String,
    pub target_validation_package_id: String,
    pub instance: Vec<u8>,
}

/// Summary of an approved unassignment stored locally for cross-checking a later assignment (`AssignmentValidation.scala:266-310`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredUnassignment {
    /// Target logical synchronizer id (`name::namespace`), mirroring Canton's per-target `ReassignmentStore`
    /// (`ReassignmentCoordination.scala:294-307`, U-60 C1). Legacy pre-C1 journal entries without this field deserialize as empty and fail closed.
    #[serde(default)]
    pub target_synchronizer: String,
    pub contracts: Vec<StoredReassignedContract>,
    pub stakeholders: std::collections::BTreeSet<String>,
    pub reassigning_participants: std::collections::BTreeSet<String>,
    pub unassignment_ts: i64,
}

/// Result of looking up a reassignment id in the target synchronizer's reassignment store (`AssignmentValidation.scala:74-105`, U-60 C1/C3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReassignmentLookup<'a> {
    /// No unassignment data is known for this `(target_synchronizer, reassignment_id)` (`UnknownReassignmentId` -> `LocalAbstain`).
    #[default]
    Missing,
    /// An approved unassignment targeting this synchronizer is stored and has not yet completed.
    Stored(&'a StoredUnassignment),
    /// The assignment for this reassignment id has already completed on this synchronizer (`ReassignmentCompleted` -> `AssignmentCompleted` reject).
    Completed,
}

/// Result of deciding a reassignment request along with whether common Phase 7 preconditions held and whether this participant is reassigning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecideOutcome {
    pub decision: crate::view_decision::Decision,
    pub phase7_valid: bool,
    pub is_reassigning: bool,
}

/// Optional validation context provided by [`crate::participant_runtime::Runtime`] for reassignment checks (`P-14`).
#[derive(Default)]
pub struct ReassignmentContext<'a> {
    /// This participant's uid (`name::namespace`), used to abstain when it is not a reassigning participant.
    pub own_uid: Option<&'a str>,
    pub engine: Option<&'a crate::view_conformance::Engine>,
    pub hosts_of: Option<&'a crate::view_validation::HostsOf<'a>>,
    /// Active vetted package IDs for a participant uid (`None` when vetting state is not tracked for that host).
    pub vetted_of: Option<&'a dyn Fn(&str) -> Option<std::collections::BTreeSet<String>>>,
    /// Target-scoped lookup result for an assignment's reassignment id (U-60 C1/C3).
    pub reassignment_lookup: ReassignmentLookup<'a>,
}

/// A decrypted reassignment request, with what its revealed view says.
#[derive(Debug, Clone)]
pub struct Received {
    pub common: ReadCommon,
    pub signature: Option<Signature>,
    pub contracts: Vec<Moved>,
    /// The target synchronizer of an unassignment (physical id).
    pub target: Option<String>,
    /// The reassignment id an assignment names (hex string form).
    pub reassignment_id: Option<String>,
}

/// The view type of an envelope that is an encrypted view message (`None` for anything else).
pub fn view_type_of(envelope_content: &[u8]) -> Option<ViewType> {
    let (inner, _) = unversioned(envelope_content)?;
    match canton_proto::depth::decode::<EnvelopeContent>(inner.as_slice())
        .ok()?
        .some_envelope_content?
    {
        SomeEnvelopeContent::EncryptedMultipleViewsMessage(m) => {
            ViewType::try_from(m.view_type).ok()
        }
        _ => None,
    }
}

/// Decrypts an envelope that holds a reassignment's encrypted view. `None` if the envelope is not one (a transaction's view, anything
/// else); `Some(Err)` if it is one this participant should read but cannot.
pub fn decrypt(
    envelope_content: &[u8],
    encryption_fingerprint: &str,
    encryption_secret: &[u8; 32],
) -> Option<Result<Received, String>> {
    let (inner, _) = unversioned(envelope_content)?;
    let Some(SomeEnvelopeContent::EncryptedMultipleViewsMessage(message)) =
        canton_proto::depth::decode::<EnvelopeContent>(inner.as_slice())
            .ok()?
            .some_envelope_content
    else {
        return None;
    };
    let kind = match ViewType::try_from(message.view_type).ok()? {
        ViewType::Unassignment => Kind::Unassignment,
        ViewType::Assignment => Kind::Assignment,
        _ => return None,
    };
    let entry = message
        .session_key_lookup
        .iter()
        .find(|e| e.fingerprint == encryption_fingerprint)?;
    Some((|| {
        let randomness: [u8; 16] = ecies_decrypt(encryption_secret, &entry.ciphertext)
            .and_then(|r| r.try_into().ok())
            .ok_or("the session key does not decrypt")?;
        let compressed = aes_gcm_decrypt(&randomness, &message.compressed_view_trees)
            .ok_or("the view does not decrypt")?;
        let uncompressed = crate::sequencing_wire::decompress(&compressed)
            .ok_or("the view does not decompress")?;
        let trees = canton_proto::depth::decode::<UncompressedViewTrees>(uncompressed.as_slice())
            .map_err(|e| format!("UncompressedViewTrees: {e}"))?;
        let [bytes] = trees.view_trees.as_slice() else {
            return Err(format!(
                "a reassignment request has one view tree, not {}",
                trees.view_trees.len()
            ));
        };
        let (data, _) = unversioned(bytes).ok_or("an unversioned reassignment tree")?;
        let tree = canton_proto::depth::decode::<ReassignmentViewTree>(data.as_slice())
            .map_err(|e| format!("ReassignmentViewTree: {e}"))?;
        read_received(kind, &tree, message.submitting_participant_signature)
    })())
}

/// Reads a full reassignment tree: the common data, the root hash and the revealed view.
pub fn read_received(
    kind: Kind,
    tree: &ReassignmentViewTree,
    signature: Option<Signature>,
) -> Result<Received, String> {
    let common = read_tree(kind, tree)?;
    let Some(BlindedOrNot::Unblinded(view)) = tree
        .participant_data
        .as_ref()
        .and_then(|n| n.blinded_or_not.as_ref())
    else {
        return Err("the reassignment view is blinded".into());
    };
    let (data, _) = unversioned(view).ok_or("an unversioned reassignment view")?;
    let (contracts, target, reassignment_id) = match kind {
        Kind::Unassignment => {
            let v = UnassignmentView::decode(data.as_slice()).map_err(|e| e.to_string())?;
            (v.contracts, Some(v.target_physical_synchronizer_id), None)
        }
        Kind::Assignment => {
            let v = AssignmentView::decode(data.as_slice()).map_err(|e| e.to_string())?;
            (v.contracts, None, v.reassignment_id.map(|r| r.id))
        }
    };
    let contracts = contracts
        .into_iter()
        .map(|c| {
            let (contract_id, template) = crate::view_acs::contract_of(&c.contract)
                .ok_or("a reassigned contract instance cannot be read")?;
            Ok(Moved {
                contract_id,
                template,
                source_validation_package_id: c.source_validation_package_id,
                target_validation_package_id: c.target_validation_package_id,
                counter: c.reassignment_counter,
                instance: c.contract,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Received {
        common,
        signature,
        contracts,
        target,
        reassignment_id,
    })
}

/// This participant's answer to a reassignment request it was shown (`decision.confirming_parties` empty on malformed; `Outcome::Abstain`
/// when this participant is not a reassigning participant per `ReassignmentProcessingSteps`), and what it locks if approved.
///
/// `[CANTON-NOTE: SEMANTICS]` Follows `ReassignmentProcessingSteps.scala:468-525` (`responsesForWellformedPayloads`),
/// `UnassignmentValidation.scala:43-80, 141-181`, and `AssignmentValidation.scala:67-120, 161, 203-280`:
/// - Non-reassigning participants still track common validation validity (`phase7_valid`) so approved requests commit in Phase 7 even after
///   `LocalAbstain`, without writing local unassignment store entries (`R-2`).
/// - Contract authentication uses `source/target_validation_package_id`; PV <= 36 skips package vetting (`R-6a`); PV >= 37 fails closed on
///   hosts missing `VettedPackages` (`R-6b`); known local package & validity window are checked at request time (`R-6d`).
/// - Missing stored unassignment on an assignment returns `LocalAbstain` (`UnassignmentDataNotFound`) for reassigning participants (`R-6e`).
pub fn decide(
    received: &Result<Received, String>,
    announced_root_hash: &[u8],
    physical_synchronizer_id: &str,
    hosted_parties: &[String],
    verify_submitter: &dyn Fn(&Signature, &[u8]) -> bool,
    ledger: &crate::view_acs::Ledger,
    ctx: &ReassignmentContext<'_>,
) -> crate::view_decision::Decision {
    decide_with_phase7(
        received,
        announced_root_hash,
        physical_synchronizer_id,
        hosted_parties,
        verify_submitter,
        ledger,
        ctx,
    )
    .decision
}

/// Decides a reassignment request and returns Phase 7 eligibility (`phase7_valid`) and reassigning role (`is_reassigning`).
pub fn decide_with_phase7(
    received: &Result<Received, String>,
    announced_root_hash: &[u8],
    physical_synchronizer_id: &str,
    hosted_parties: &[String],
    verify_submitter: &dyn Fn(&Signature, &[u8]) -> bool,
    ledger: &crate::view_acs::Ledger,
    ctx: &ReassignmentContext<'_>,
) -> DecideOutcome {
    use crate::confirmation_wire::Outcome;
    let answer = |outcome: Outcome, parties: Vec<String>| crate::view_decision::Decision {
        outcome,
        view_position: Vec::new(),
        confirming_parties: parties,
    };
    let malformed = |why: String| DecideOutcome {
        decision: answer(Outcome::Malformed(why), Vec::new()),
        phase7_valid: false,
        is_reassigning: false,
    };
    let r = match received {
        Ok(r) => r,
        Err(why) => return malformed(why.clone()),
    };
    if r.common.root_hash != announced_root_hash {
        return malformed("the reassignment tree's root hash is not the announced one".into());
    }
    if !r
        .signature
        .as_ref()
        .is_some_and(|s| verify_submitter(s, &r.common.root_hash))
    {
        return malformed("the submitting participant's signature does not verify".into());
    }
    if r.common.synchronizer != physical_synchronizer_id {
        return malformed(format!(
            "the request is for {}, not for this synchronizer",
            r.common.synchronizer
        ));
    }
    let parties: Vec<String> = r
        .common
        .confirming_parties()
        .into_iter()
        .filter(|p| hosted_parties.contains(p))
        .collect();
    // [CANTON-NOTE: SEMANTICS] `ReassignmentCommonData.isReassigningParticipant`: a participant is reassigning only when
    // explicitly named in `reassigning_participant_uids`; an empty list is never treated as reassigning (fail-closed audit A1).
    let is_reassigning = ctx.own_uid.is_none_or(|me| {
        r.common
            .reassigning_participant_uids
            .iter()
            .any(|u| u == me)
    });
    let auth_res = check_contracts_authentic(r, ctx.engine);
    let stakeholders_res = check_stakeholders(r);
    let vetting_res = check_packages_vetted(r, ctx.engine, ctx.hosts_of, ctx.vetted_of);
    let submitter_res = check_submitter(&r.common, ctx.hosts_of);
    let stakeholders_hosted_res = check_stakeholders_hosted(r, ctx.hosts_of);
    let rid_res = check_reassignment_id(r);
    // [CANTON-NOTE: SEMANTICS] `ReassignmentProcessingSteps.scala:614-649` (`checkPhase7Validations`):
    // Phase 7 checks ONLY common validation errors (model conformance, signature/auth, submitter, stakeholder hosting, reassignment id),
    // NOT Phase 3 activeness conflicts and NOT `ReassigningParticipantValidationResult` (e.g. stored unassignment mismatch).
    let phase7_valid = auth_res.is_ok()
        && stakeholders_res.is_ok()
        && vetting_res.is_ok()
        && submitter_res.is_ok()
        && stakeholders_hosted_res.is_ok()
        && rid_res.is_ok();

    // [CANTON-NOTE: SEMANTICS] `ReassignmentProcessingSteps.scala:468-483`: non-reassigning participants respond `LocalAbstain`
    // immediately in Phase 3 while still keeping `phase7_valid` (including `submitter_res`) so an approved verdict commits only when valid.
    if !is_reassigning {
        return DecideOutcome {
            decision: answer(
                Outcome::Abstain("The participant is not a reassigning participant".into()),
                parties,
            ),
            phase7_valid,
            is_reassigning: false,
        };
    }

    // [CANTON-NOTE: SEMANTICS] `ReassignmentProcessingSteps.scala:530-564`, `AssignmentValidation.scala:74-105`: Phase 3 rejection priority
    // order for reassigning participants is: model conformance (Malformed) -> completed assignment (`AssignmentCompleted`, LocalReject) ->
    // activeness conflict (LocalReject) -> submitter check (LocalReject) -> stakeholder hosting check (LocalReject) -> reassignment id check
    // (LocalReject) -> stored unassignment mismatch (LocalReject) -> missing stored unassignment (`UnassignmentDataNotFound`, LocalAbstain).
    // Every `LocalReject` outranks `LocalAbstain`.
    if let Err(why) = auth_res {
        return malformed(why);
    }
    if let Err(why) = stakeholders_res {
        return malformed(why);
    }
    if let Err(why) = vetting_res {
        return malformed(why);
    }
    if r.common.kind == Kind::Assignment
        && matches!(ctx.reassignment_lookup, ReassignmentLookup::Completed)
    {
        // [CANTON-NOTE: SEMANTICS] `AssignmentValidation.scala:86-89`: once an assignment completes on this target synchronizer, any
        // subsequent assignment with the same reassignment id is rejected with `AssignmentCompleted`, even if the contract has since left
        // or been archived on this synchronizer (U-60 C3).
        return DecideOutcome {
            decision: answer(
                Outcome::Reject(format!(
                    "REASSIGNMENT_VALIDATION_FAILED: AssignmentCompleted: Cannot assign `{}`: assignment has been completed",
                    r.reassignment_id.as_deref().unwrap_or("")
                )),
                parties,
            ),
            phase7_valid,
            is_reassigning: true,
        };
    }
    for c in &r.contracts {
        let id = &c.contract_id;
        let problem = match r.common.kind {
            Kind::Unassignment if ledger.knows_contract(id) && !ledger.is_active(id) => Some(
                format!("the contract {id} is not active on this synchronizer"),
            ),
            Kind::Unassignment
                if ledger.is_active(id) && c.counter != ledger.counter_of(id) + 1 =>
            {
                Some(format!(
                    "the reassignment counter of {id} is {}, not {}",
                    c.counter,
                    ledger.counter_of(id) + 1
                ))
            }
            Kind::Assignment if ledger.is_active(id) => Some(format!(
                "the contract {id} is already active on this synchronizer"
            )),
            _ => None,
        };
        if let Some(why) = problem {
            return DecideOutcome {
                decision: answer(Outcome::Reject(why), parties),
                phase7_valid,
                is_reassigning: true,
            };
        }
    }
    if let Err(why) = submitter_res {
        return DecideOutcome {
            decision: answer(Outcome::Reject(why), parties),
            phase7_valid: false,
            is_reassigning: true,
        };
    }
    if let Err(why) = stakeholders_hosted_res {
        return DecideOutcome {
            decision: answer(Outcome::Reject(why), parties),
            phase7_valid: false,
            is_reassigning: true,
        };
    }
    if let Err(why) = rid_res {
        return DecideOutcome {
            decision: answer(Outcome::Reject(why), parties),
            phase7_valid: false,
            is_reassigning: true,
        };
    }
    if r.common.kind == Kind::Assignment {
        match (ctx.own_uid, ctx.reassignment_lookup) {
            (_, ReassignmentLookup::Stored(u)) => {
                if let Err(why) = check_stored_unassignment(r, u) {
                    return DecideOutcome {
                        decision: answer(Outcome::Reject(why), parties),
                        phase7_valid,
                        is_reassigning: true,
                    };
                }
            }
            (Some(_), ReassignmentLookup::Missing) => {
                // [CANTON-NOTE: SEMANTICS] `AssignmentValidation.scala:98-103`, `AssignmentValidationResult.scala:198-201`:
                // missing unassignment data causes a reassigning participant to respond `LocalAbstain` (`UnassignmentDataNotFound`).
                return DecideOutcome {
                    decision: answer(
                        Outcome::Abstain(format!(
                            "UnassignmentDataNotFound: no stored unassignment for {}",
                            r.reassignment_id.as_deref().unwrap_or("")
                        )),
                        parties,
                    ),
                    phase7_valid,
                    is_reassigning: true,
                };
            }
            (None, ReassignmentLookup::Missing) | (_, ReassignmentLookup::Completed) => {}
        }
    }
    DecideOutcome {
        decision: answer(Outcome::Approve, parties),
        phase7_valid,
        is_reassigning: true,
    }
}

/// `[CANTON-NOTE: SEMANTICS]` `ReassignmentValidation.scala` (`authenticateContractsAgainstSource/Target`):
/// authenticates each contract against `engine` using the declared validation package id.
fn check_contracts_authentic(
    r: &Received,
    engine: Option<&crate::view_conformance::Engine>,
) -> Result<(), String> {
    let Some(engine) = engine else {
        return Ok(());
    };
    for c in &r.contracts {
        let validation_pkg = match r.common.kind {
            Kind::Unassignment => &c.source_validation_package_id,
            Kind::Assignment => &c.target_validation_package_id,
        };
        let validation_pkg = (!validation_pkg.is_empty()).then_some(validation_pkg.as_str());
        let (recomputed_id, _) = crate::view_conformance::authenticate_instance_with_package(
            engine,
            &c.instance,
            validation_pkg,
        )
        .map_err(|e| {
            format!(
                "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: contract authentication failed for {}: {e:?}",
                c.contract_id
            )
        })?;
        if recomputed_id != c.contract_id {
            return Err(format!(
                "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: contract id mismatch ({recomputed_id} != {})",
                c.contract_id
            ));
        }
    }
    Ok(())
}

/// `[CANTON-NOTE: SEMANTICS]` `UnassignmentValidation.scala:169`, `AssignmentValidation.scala:209`,
/// `BaseTopologySnapshot.scala:132-157`: skip package vetting for `PV <= 36`, verify main validation packages locally and fail-closed
/// across all stakeholder hosts (including validity window via `vetted_of`) for `PV >= 37`. Dependency packages are NOT vetted-checked
/// (`NextGenTransactionTreeFactoryTest.scala:567-577`).
fn check_packages_vetted(
    r: &Received,
    engine: Option<&crate::view_conformance::Engine>,
    hosts_of: Option<&crate::view_validation::HostsOf>,
    vetted_of: Option<&dyn Fn(&str) -> Option<std::collections::BTreeSet<String>>>,
) -> Result<(), String> {
    let enforce = crate::topology_state::Psid::parse(&r.common.synchronizer)
        .ok()
        .is_none_or(|p| p.protocol_version > 36);
    if !enforce {
        return Ok(());
    }
    for c in &r.contracts {
        let declared = match r.common.kind {
            Kind::Unassignment => &c.source_validation_package_id,
            Kind::Assignment => &c.target_validation_package_id,
        };
        let fallback_pkg;
        let pkg_id = if declared.is_empty() {
            fallback_pkg = crate::reassignment_submit::contract_parties(&c.instance)?.package_id;
            &fallback_pkg
        } else {
            declared
        };
        if let Some(engine) = engine {
            if !engine.knows_package(pkg_id) {
                return Err(format!(
                    "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: PackageIdUnknownOrUnvetted: package {pkg_id} is not known locally"
                ));
            }
        }
        let (Some(hosts_of), Some(vetted_of)) = (hosts_of, vetted_of) else {
            continue;
        };
        for stakeholder in &r.common.stakeholders {
            let Some((_, hosts)) = hosts_of(stakeholder) else {
                continue;
            };
            for (host_uid, _) in hosts {
                match vetted_of(&host_uid) {
                    Some(vetted) if vetted.contains(pkg_id) => {}
                    _ => {
                        return Err(format!(
                            "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: PackageIdUnknownOrUnvetted: package {pkg_id} is not vetted on PAR::{host_uid} for stakeholder {stakeholder}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// `[CANTON-NOTE: SEMANTICS]` Every stakeholder of a reassigned contract must have at least one active host on this
/// synchronizer when topology is followed (fail-closed audit A6).
fn check_stakeholders_hosted(
    r: &Received,
    hosts_of: Option<&crate::view_validation::HostsOf>,
) -> Result<(), String> {
    let Some(hosts_of) = hosts_of else {
        return Ok(());
    };
    for stakeholder in &r.common.stakeholders {
        let hosted = hosts_of(stakeholder).is_some_and(|(_, hosts)| !hosts.is_empty());
        if !hosted {
            return Err(format!(
                "REASSIGNMENT_VALIDATION_FAILED: StakeholderNotHosted: stakeholder {stakeholder} has no active hosts on {}",
                r.common.synchronizer
            ));
        }
    }
    Ok(())
}

/// `[CANTON-NOTE: SEMANTICS]` `AssignmentValidation.scala:259-264`, `AssignmentViewTree.scala:500-508`:
/// validates that an assignment's declared `reassignment_id` matches the hash over logical synchronizers, `unassignment_ts`, and contract counters.
fn check_reassignment_id(r: &Received) -> Result<(), String> {
    if r.common.kind != Kind::Assignment {
        return Ok(());
    }
    let (Some(src), Some(ts)) = (&r.common.source_synchronizer, r.common.unassignment_ts) else {
        return Err(
            "REASSIGNMENT_VALIDATION_FAILED: InconsistentReassignmentId: missing source synchronizer or unassignment timestamp"
                .into(),
        );
    };
    fn logical(psid: &str) -> &str {
        psid.rsplit_once("::").map_or(psid, |(l, _)| l)
    }
    let pairs: Vec<(&str, i64)> = r
        .contracts
        .iter()
        .map(|c| (c.contract_id.as_str(), c.counter))
        .collect();
    let expected = crate::reassignment_wire::reassignment_id(
        logical(src),
        logical(&r.common.synchronizer),
        ts,
        &pairs,
    );
    if r.reassignment_id.as_deref() != Some(expected.as_str()) {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: InconsistentReassignmentId: expected {expected}, got {:?}",
            r.reassignment_id
        ));
    }
    Ok(())
}

/// Verifies an assignment matches all unassignment facts recorded earlier on the source synchronizer (`AssignmentValidation.scala:266-310`).
fn check_stored_unassignment(r: &Received, u: &StoredUnassignment) -> Result<(), String> {
    let normalize = |c: &StoredReassignedContract| {
        (
            c.contract_id.clone(),
            c.counter,
            c.source_validation_package_id.clone(),
            c.target_validation_package_id.clone(),
            c.instance.clone(),
        )
    };
    let mut got_contracts: Vec<_> = r
        .contracts
        .iter()
        .map(|c| {
            (
                c.contract_id.clone(),
                c.counter,
                c.source_validation_package_id.clone(),
                c.target_validation_package_id.clone(),
                c.instance.clone(),
            )
        })
        .collect();
    got_contracts.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut want_contracts: Vec<_> = u.contracts.iter().map(normalize).collect();
    want_contracts.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let got_stakeholders: std::collections::BTreeSet<String> =
        r.common.stakeholders.iter().cloned().collect();
    let got_reassigning: std::collections::BTreeSet<String> = r
        .common
        .reassigning_participant_uids
        .iter()
        .cloned()
        .collect();
    let rid = r.reassignment_id.as_deref().unwrap_or("");
    let target_logical = crate::multi_node::logical(&r.common.synchronizer);
    if u.target_synchronizer.is_empty()
        || crate::multi_node::logical(&u.target_synchronizer) != target_logical
    {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: assignment {rid} target synchronizer {target_logical} does not match stored {:?}",
            u.target_synchronizer
        ));
    }
    if got_contracts != want_contracts {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: assignment {rid} contracts do not match stored unassignment"
        ));
    }
    if got_stakeholders != u.stakeholders {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: assignment {rid} stakeholders do not match stored unassignment"
        ));
    }
    if got_reassigning != u.reassigning_participants {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: assignment {rid} reassigning participants do not match stored unassignment"
        ));
    }
    if r.common.unassignment_ts != Some(u.unassignment_ts) {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: assignment {rid} unassignment_ts {:?} does not match stored {}",
            r.common.unassignment_ts, u.unassignment_ts
        ));
    }
    Ok(())
}

/// Why a readable request is not processed at all: its common data declares another mediator group than `mediator_group`, the one its root
/// hash message is sent to (`ProtocolProcessor`: "Mediator ... declared in views is not the recipient ... of the root hash message").
pub fn other_mediator(received: &Result<Received, String>, mediator_group: u32) -> Option<String> {
    let declared = received.as_ref().ok()?.common.mediator_group;
    (u32::try_from(declared).ok() != Some(mediator_group)).then(|| {
        format!(
            "Mediator group {declared} declared in the reassignment is not the recipient MGR::{mediator_group} of the root hash message"
        )
    })
}

/// `ReassignmentValidation.checkStakeholders`: the view's stakeholders are those of its contracts.
fn check_stakeholders(r: &Received) -> Result<(), String> {
    let mut of_contracts = std::collections::BTreeSet::new();
    for c in &r.contracts {
        of_contracts
            .extend(crate::reassignment_submit::contract_parties(&c.instance)?.stakeholders);
    }
    let declared: std::collections::BTreeSet<String> =
        r.common.stakeholders.iter().cloned().collect();
    if declared == of_contracts {
        return Ok(());
    }
    Err(format!(
        "LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK: stakeholders mismatch. Expected {of_contracts:?}, found {declared:?}"
    ))
}

/// `ReassignmentValidation.checkSubmitter`: the submitter is a stakeholder and is hosted (with any permission) on the submitting participant.
fn check_submitter(
    common: &ReadCommon,
    hosts_of: Option<&crate::view_validation::HostsOf>,
) -> Result<(), String> {
    let (submitter, participant) = (&common.submitter, &common.submitting_participant_uid);
    if !common.stakeholders.contains(submitter) {
        return Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: submitter `{submitter}` is not a stakeholder"
        ));
    }
    let Some(hosts_of) = hosts_of else {
        return Ok(());
    };
    let hosted = hosts_of(submitter)
        .is_some_and(|(_, hosts)| hosts.iter().any(|(host, _)| host == participant));
    if hosted {
        Ok(())
    } else {
        Err(format!(
            "REASSIGNMENT_VALIDATION_FAILED: {submitter} is not hosted on PAR::{participant}"
        ))
    }
}

/// (leaving, arriving as (id, template, serialized instance), counters).
pub type Locks = (
    Vec<String>,
    Vec<(String, String, Vec<u8>)>,
    Vec<(String, i64)>,
);

/// What an approved request locks: (leaving, arriving, counters) for [`crate::view_acs::Ledger::begin_reassignment`]. An unassignment
/// only takes away what this participant has active.
pub fn effects(r: &Received, ledger: &crate::view_acs::Ledger) -> Locks {
    let counters = r
        .contracts
        .iter()
        .map(|c| (c.contract_id.clone(), c.counter))
        .collect();
    match r.common.kind {
        Kind::Unassignment => (
            r.contracts
                .iter()
                .filter(|c| ledger.is_active(&c.contract_id))
                .map(|c| c.contract_id.clone())
                .collect(),
            Vec::new(),
            counters,
        ),
        Kind::Assignment => (
            Vec::new(),
            r.contracts
                .iter()
                .map(|c| {
                    (
                        c.contract_id.clone(),
                        c.template.clone(),
                        c.instance.clone(),
                    )
                })
                .collect(),
            counters,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_assignment(source: Option<&str>, ts: Option<i64>) -> Received {
        Received {
            common: ReadCommon {
                kind: Kind::Assignment,
                synchronizer: "sync-b::1220bb::37-0".into(),
                source_synchronizer: source.map(str::to_string),
                unassignment_ts: ts,
                mediator_group: 0,
                submitter: "alice::1220aa".into(),
                submitting_participant_uid: "p1::1220aa".into(),
                stakeholders: vec!["alice::1220aa".into()],
                signatories: vec!["alice::1220aa".into()],
                reassigning_participant_uids: vec!["p1::1220aa".into()],
                root_hash: vec![1; 32],
            },
            contracts: Vec::new(),
            target: None,
            reassignment_id: Some("00".into()),
            signature: None,
        }
    }

    /// Fail-closed audit A2: an Assignment missing `source_synchronizer` or `unassignment_ts` must fail `check_reassignment_id`
    /// rather than silently returning `Ok(())`.
    #[test]
    fn check_reassignment_id_refuses_assignment_without_source_or_timestamp() {
        let missing_src = minimal_assignment(None, Some(100));
        let err_src = check_reassignment_id(&missing_src).expect_err("missing source must fail");
        assert!(err_src.contains("InconsistentReassignmentId"), "{err_src}");

        let missing_ts = minimal_assignment(Some("sync-a::1220aa::37-0"), None);
        let err_ts = check_reassignment_id(&missing_ts).expect_err("missing ts must fail");
        assert!(err_ts.contains("InconsistentReassignmentId"), "{err_ts}");
    }
}
