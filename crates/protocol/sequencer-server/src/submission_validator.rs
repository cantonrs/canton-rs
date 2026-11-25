//! The checks a submission passes, as a function of the submission, its sequencing time and what the sequencer knows at that time
//! (`SubmissionRequestValidator.performIndependentValidations`). `SendAsync` runs a subset at the estimated sequencing time before it
//! answers; once the orderer gave the submission its time, every sequencer runs all of them at that time, so they all decide alike.
//!
//! [CANTON-NOTE: SEMANTICS] The order and the outcome of each check after ordering, read from 3.7.2:
//! - the sender is not registered, its signature does not verify, or the sequencing time is past the maximum sequencing time: the request
//!   is **dropped** (`SubmissionOutcome.Discard`: no event, not even for the sender: "the client will not expect a receipt AFTER max
//!   sequencing time");
//! - more than one mediator group (`checkToAtMostOneMediator`) or an envelope signature that is not the sender's
//!   (`checkClosedEnvelopesSignatures`): `SEQUENCER_SUBMISSION_REQUEST_MALFORMED_REJECTED` with the step's name (protocol version 37);
//! - a member recipient that is not registered (`SequencerErrors.UnknownRecipients`), a mediator group that does not exist, an aggregation
//!   rule the sender may not use: an error event for the sender alone (`SubmissionOutcome.Reject`).
//!
//! [CANTON-NOTE: LIMITATION] The members and their keys are the [`Registry`] as the ordered submissions before this one left it (it changes
//! when a topology broadcast is sequenced, not when the change takes effect after the topology change delay): every sequencer that orders
//! the same submissions has the same registry, but the keys are not the ones of the snapshot at the sequencing time.
use crate::aggregation::{Group, RuleTopology};
use crate::onboarding::Registry;
use crate::submission::{refused, Submission};
use crate::synchronizer_state::TopologyStore;
use canton_algo::signing::PublicKey;
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_state::iso_utc;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use tonic::Status;

/// What the sequencer knows at a sequencing time.
pub(crate) struct Snapshot<'a> {
    pub(crate) at: i64,
    /// The physical synchronizer id (what a session-key delegation is bound to, as its logical id).
    pub(crate) physical: &'a str,
    pub(crate) registry: &'a Registry,
    pub(crate) store: &'a TopologyStore,
    /// This sequencer's own member, a recipient even when the registry does not list it.
    pub(crate) self_member: Option<&'a str>,
    /// Whether the mediator group with this index serves requests at `at`.
    pub(crate) serves_group: &'a dyn Fn(&str) -> bool,
}

/// Which checks run: the ones `SendAsync` answers, or all of them once the submission has its time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    SendAsync,
    Sequenced,
}

/// Why a submission does not pass.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Invalid {
    /// The request names another sender than the authenticated (or ordering) member.
    NotTheSender {
        member: String,
    },
    SenderUnknown,
    Signature,
    MaxSequencingTime,
    SeveralMediatorGroups,
    UnknownRecipients(Vec<String>),
    EnvelopeSignature,
    MissingMediatorGroups(Vec<String>),
    AggregationRule(String),
}

/// What a submission that passes needs further on.
pub(crate) struct Valid {
    /// How many senders complete its aggregation, when it carries an aggregation rule.
    pub(crate) aggregation_threshold: Option<usize>,
}

/// Checks `submission`, sent (or ordered) as `member`, at `snapshot.at`.
pub(crate) fn validate(
    submission: &Submission,
    member: &str,
    snapshot: &Snapshot,
    scope: Scope,
) -> Result<Valid, Invalid> {
    let registered = authenticate(submission, member, snapshot)?;
    let late = submission.max_sequencing_time < snapshot.at;
    if scope == Scope::Sequenced && late {
        return Err(Invalid::MaxSequencingTime);
    }
    let addresses = submission.addresses();
    if addresses.iter().filter(|a| a.starts_with("MGR::")).count() > 1 {
        return Err(Invalid::SeveralMediatorGroups);
    }
    let unknown: Vec<String> = addresses
        .iter()
        .filter(|a| is_member(a))
        .filter(|a| !snapshot.registry.is_registered(a) && snapshot.self_member != Some(**a))
        .map(|a| a.to_string())
        .collect();
    if !unknown.is_empty() {
        return Err(Invalid::UnknownRecipients(unknown));
    }
    if scope == Scope::SendAsync {
        // [CANTON-NOTE: SEMANTICS] `BlockSequencer.validateMaxSequencingTime`: refused at once when already past at the estimated time
        return if late {
            Err(Invalid::MaxSequencingTime)
        } else {
            Ok(Valid {
                aggregation_threshold: None,
            })
        };
    }
    for envelope in &submission.envelopes {
        let hash = envelope_hash(&envelope.content);
        if !envelope
            .signatures
            .iter()
            .all(|s| verifies_at(&registered.signing_keys, s, &hash, snapshot))
        {
            return Err(Invalid::EnvelopeSignature);
        }
    }
    let missing: Vec<String> = addresses
        .iter()
        .filter_map(|a| a.strip_prefix("MGR::"))
        .filter(|group| !(snapshot.serves_group)(group))
        .map(str::to_string)
        .collect();
    if !missing.is_empty() {
        return Err(Invalid::MissingMediatorGroups(missing));
    }
    let aggregation_threshold = match &submission.aggregation_rule {
        None => None,
        Some(rule) => {
            let mediator_groups = snapshot.store.mediator_groups_at(snapshot.at);
            let sequencer_group = snapshot.store.sequencer_group_at(snapshot.at);
            let topology = RuleTopology {
                mediator_groups: &mediator_groups,
                sequencer_group: sequencer_group.as_ref().map(|(threshold, active)| Group {
                    threshold: *threshold,
                    active,
                }),
            };
            Some(
                crate::aggregation::threshold(rule, member, &topology)
                    .map_err(Invalid::AggregationRule)?,
            )
        }
    };
    Ok(Valid {
        aggregation_threshold,
    })
}

/// The submission names `member` as its sender, `member` is registered and the submission is signed by one of its keys
/// (`SubmissionRequestValidator.checkSignatureOnSubmissionRequest`). Returns what `member` registered.
pub(crate) fn authenticate(
    submission: &Submission,
    member: &str,
    snapshot: &Snapshot,
) -> Result<crate::onboarding::Registered, Invalid> {
    if submission.sender != member {
        return Err(Invalid::NotTheSender {
            member: member.to_string(),
        });
    }
    // [CANTON-NOTE: SEMANTICS] A sequencer is a member of the synchronizer whether or not it ever connected here: the topology's key
    // mapping is what its own submissions (a traffic purchase) are checked against (`MemberValidator.isMemberRegisteredAt`).
    let registered = snapshot
        .registry
        .get(member)
        .or_else(|| {
            let keys = member
                .starts_with("SEQ::")
                .then(|| snapshot.store.signing_keys_of(member))
                .flatten()?;
            Some(crate::onboarding::Registered {
                member: member.to_string(),
                signing_keys: keys,
                authentication_keys: Vec::new(),
                encryption_keys: Vec::new(),
            })
        })
        .ok_or(Invalid::SenderUnknown)?;
    let hash = sw::submission_hash(&submission.content);
    if !submission
        .signatures
        .iter()
        .any(|s| verifies_at(&registered.signing_keys, s, &hash, snapshot))
    {
        return Err(Invalid::Signature);
    }
    Ok(registered)
}

impl Invalid {
    /// The answer of `SendAsync` (the texts are the official sequencer's, measured against 3.7.2, S-NET-038 part 3).
    pub(crate) fn send_async_status(
        &self,
        submission: &Submission,
        member: &str,
        at: i64,
    ) -> Status {
        let (id, sender) = (&submission.message_id, &submission.sender);
        match self {
            Invalid::NotTheSender { member } => refused(
                id,
                sender,
                &format!(
                    "{sender} is not authorized to send: Authenticated member {member} just tried to use sequencer on behalf of {sender} without permission"
                ),
            ),
            Invalid::SenderUnknown => refused(id, sender, &format!("{member} is not registered")),
            Invalid::Signature => Status::failed_precondition(format!(
                "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Sequencer could not verify client's signature on [SubmissionRequest] with sequencer's current snapshot at {}. Error: SignatureWithWrongKey(the signature is not by a key of {member} that may sign protocol messages)",
                iso_utc(at)
            )),
            Invalid::MaxSequencingTime => Status::aborted(format!(
                "MAX_SEQUENCING_TIME_EXCEEDED(2,0): The sequencer time [{}] has exceeded the max-sequencing-time of the send request [{}]: Estimation for message id {id}",
                iso_utc(at),
                iso_utc(submission.max_sequencing_time)
            )),
            Invalid::SeveralMediatorGroups => {
                refused(id, sender, "Batch contains multiple mediators as recipients.")
            }
            Invalid::UnknownRecipients(names) => Status::failed_precondition(format!(
                "SEQUENCER_UNKNOWN_RECIPIENTS(9,0): Unknown recipients: {}",
                names.join(", ")
            )),
            other => match other.sequenced() {
                Some((_, message)) => Status::failed_precondition(message),
                None => refused(id, sender, "invalid"),
            },
        }
    }

    /// What the sender is told once the submission has its time: `None` drops it (`SubmissionOutcome.Discard`), else the gRPC code and
    /// the message of its error event (`SubmissionOutcome.Reject`).
    pub(crate) fn sequenced(&self) -> Option<(i32, String)> {
        let malformed_rejected = |step: &str| {
            Some((
                3,
                format!("SEQUENCER_SUBMISSION_REQUEST_MALFORMED_REJECTED: {step}"),
            ))
        };
        match self {
            Invalid::NotTheSender { .. }
            | Invalid::SenderUnknown
            | Invalid::Signature
            | Invalid::MaxSequencingTime => None,
            Invalid::SeveralMediatorGroups => malformed_rejected("checkToAtMostOneMediator"),
            Invalid::EnvelopeSignature => malformed_rejected("checkClosedEnvelopesSignatures"),
            Invalid::UnknownRecipients(names) => Some((
                9,
                format!(
                    "SEQUENCER_UNKNOWN_RECIPIENTS: Unknown recipients: {}",
                    names.join(", ")
                ),
            )),
            Invalid::MissingMediatorGroups(groups) => Some((
                9,
                format!(
                    "SEQUENCER_SUBMISSION_REQUEST_REFUSED: The following mediator groups do not exist List({})",
                    groups.join(", ")
                ),
            )),
            Invalid::AggregationRule(why) => malformed_rejected(&format!(
                "Validation of aggregation rule: {why}"
            )),
        }
    }
}

/// An address that names one member (`MemberRecipient`), not a group.
fn is_member(address: &str) -> bool {
    ["PAR::", "MED::", "SEQ::"]
        .iter()
        .any(|kind| address.starts_with(kind))
}

/// What a signed protocol message's signature is over: the multihash of `HashPurpose.SignedProtocolMessageSignature` (38) of the envelope's
/// content (`ClosedEnvelope.verifySignatures`).
fn envelope_hash(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&canton_algo::hash::sha256_with_purpose(38, content));
    out
}

/// [`verifies`] at `snapshot`'s time: a session key that one of `keys` delegated to signs as well.
pub(crate) fn verifies_at(
    keys: &[PublicKey],
    signature: &Signature,
    hash: &[u8],
    snapshot: &Snapshot<'_>,
) -> bool {
    verifies_on(keys, signature, hash, snapshot.physical, snapshot.at)
}

/// Whether the protocol `signature` over `hash` is by one of the member's `keys` or a session key one of them delegated to, at
/// `at_micros` on the synchronizer `physical`.
pub(crate) fn verifies_on(
    keys: &[PublicKey],
    signature: &Signature,
    hash: &[u8],
    physical: &str,
    at_micros: i64,
) -> bool {
    use canton_algo::member_signature::{
        logical_synchronizer_id, protocol_only, verify_by_keys_at, DelegationScope,
    };
    let scope = DelegationScope {
        synchronizer_id: logical_synchronizer_id(physical),
        at_micros,
    };
    verify_by_keys_at(keys, hash, signature, &protocol_only(), &scope).is_ok()
}
