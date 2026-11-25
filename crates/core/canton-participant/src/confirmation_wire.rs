//! The messages of the transaction protocol's first phase: what a submitting participant sends to the mediator (G5 5.6c, S-NET-007).
//!
//! [CANTON-NOTE: SEMANTICS]
//! - A protocol message travels as `EnvelopeContent { some_envelope_content }`, wrapped as `UntypedVersionedMessage` with
//!   **version 32**, and that is the `content` of an unsigned envelope.
//! - The **`InformeeMessage`** carries the full informee tree and the submitting participant's signature over the tree's
//!   *root hash* (the multihash bytes themselves, no extra hash purpose); it is addressed to the mediator group (`MGR::<n>`).
//! - Each informee participant gets a **`RootHashMessage`** (root hash, physical synchronizer id, view type, the topology time
//!   the submission used, optional payload) addressed to the *pair* `{MGR::<n>, <participant>}`: the mediator checks that every
//!   such group has exactly two members, one of them the mediator group, one a participant.
//!
//! [CANTON-NOTE: LIMITATION] No encrypted view message is built (the participant side comes later); only what the mediator reads.
use crate::merkle_wire::{full_informee_tree, GenTree};
use crate::topology_wire::{versioned, Ed25519Key};
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    InformeeMessage, RootHashMessage, ViewType,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    envelope_content::SomeEnvelopeContent, EnvelopeContent,
};
use prost::Message;

/// The version of `EnvelopeContent` (protocol version 37).
pub const ENVELOPE_CONTENT_VERSION: i32 = 32;

/// The recipient string of a mediator group.
pub fn mediator_group(group: u32) -> String {
    format!("MGR::{group}")
}

/// The envelope content of a signed informee message: the tree and the signature over its root hash.
pub fn informee_message(tree: &GenTree, key: &Ed25519Key) -> Vec<u8> {
    informee_message_signed_over(tree, key, &tree.root_hash)
}

/// Like [`informee_message`], but the signature covers `signed` instead of the root hash (to show the mediator checks it).
pub fn informee_message_signed_over(tree: &GenTree, key: &Ed25519Key, signed: &[u8]) -> Vec<u8> {
    versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::InformeeMessage(InformeeMessage {
                full_informee_tree: Some(full_informee_tree(tree)),
                submitting_participant_signature: Some(key.sign_bytes(signed)),
            })),
        }
        .encode_to_vec(),
        ENVELOPE_CONTENT_VERSION,
    )
}

/// The envelope content of a root hash message for a transaction view tree.
pub fn root_hash_message(
    root_hash: &[u8],
    physical_synchronizer_id: &str,
    submission_topology_time_micros: i64,
) -> Vec<u8> {
    root_hash_message_of_type(
        ViewType::Transaction,
        root_hash,
        physical_synchronizer_id,
        submission_topology_time_micros,
    )
}

/// A `RootHashMessage` of a request of `view_type` (a reassignment's names `Unassignment` or `Assignment`; the payload is empty).
pub fn root_hash_message_of_type(
    view_type: ViewType,
    root_hash: &[u8],
    physical_synchronizer_id: &str,
    submission_topology_time_micros: i64,
) -> Vec<u8> {
    versioned(
        EnvelopeContent {
            some_envelope_content: Some(SomeEnvelopeContent::RootHashMessage(RootHashMessage {
                root_hash: root_hash.to_vec(),
                physical_synchronizer_id: physical_synchronizer_id.to_string(),
                view_type: view_type as i32,
                submission_topology_time: submission_topology_time_micros,
                payload: Vec::new(),
            })),
        }
        .encode_to_vec(),
        ENVELOPE_CONTENT_VERSION,
    )
}

/// `HashPurpose.SignedProtocolMessageSignature`.
const PURPOSE_SIGNED_PROTOCOL_MESSAGE: i32 = 38;
/// The version of `TypedSignedProtocolMessageContent` and `ConfirmationResponses` (both v30).
const SIGNED_MESSAGE_VERSION: i32 = 30;

/// What a participant answers for one view of a confirmation request.
pub struct ViewResponse<'a> {
    /// The view's position in the informee tree (one element per level; each the directions from leaf to root).
    pub view_position: &'a [Vec<bool>],
    pub outcome: Outcome,
    /// The parties this participant answers for (empty for a malformed request).
    pub confirming_parties: &'a [String],
}

/// What the participant says about a view.
///
/// [CANTON-NOTE: SEMANTICS] Four local verdicts (`LocalVerdict.VerdictCode`): **approve** (`Status { code: 0 }`); **reject**: the
/// participant understood the request and refuses it, with a reason (a `Status` whose message the mediator carries into the
/// verdict); **malformed**: the participant cannot even read it (it does not decrypt, the hashes do not add up), or the view breaks a rule
/// of the protocol (its authorization, its model conformance); **abstain**: a participant that is not reassigning in a reassignment request
/// and abstains for its hosted parties (`LocalAbstainError.CannotPerformAllValidations`). A malformed answer has **no confirming parties**
/// (the invariant of `ConfirmationResponse`); it has the view position of the view it is about, and none when it is about the whole request
/// (`ViewResponse` with an empty position). The mediator counts it as a rejection by every confirming party the sender hosts in that view,
/// or in every view (`ResponseAggregator.validateResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Approve,
    Reject(String),
    Malformed(String),
    Abstain(String),
}

/// A signed `ConfirmationResponses`: the content of an envelope and the signature that goes with it.
///
/// [CANTON-NOTE: SEMANTICS] Read from `AbstractMessageProcessor.signResponses`, `SignedProtocolMessage` and
/// `ClosedUncompressedEnvelope`:
/// - The response is the v30 `ConfirmationResponses` message (versioned, 30), put in the `confirmation_responses` arm of a
///   `TypedSignedProtocolMessageContent` (versioned, 30); **those bytes are the envelope's content**.
/// - The signature is of the multihash of `HashPurpose.SignedProtocolMessageSignature` (38) over those bytes, made with a key
///   usable for the `protocol` usage, and travels in the **envelope's** `signatures` (not inside the content).
/// - `request_id` is the sequencing time of the confirmation request (microseconds); `root_hash` its tree's root hash; the
///   `sender` is the participant member (`PAR::name::namespace`). An approval's reason is `Status { code: 0 }`.
/// - The envelope goes to the mediator group; it has to be sequenced before the request time plus the response timeout.
pub fn confirmation_responses(
    request_id_micros: i64,
    root_hash: &[u8],
    physical_synchronizer_id: &str,
    sender_member: &str,
    responses: &[ViewResponse],
    key: &Ed25519Key,
) -> (Vec<u8>, Vec<Signature>) {
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        local_verdict::VerdictCode,
        typed_signed_protocol_message_content::SomeSignedProtocolMessage, ConfirmationResponse,
        ConfirmationResponses, LocalVerdict, MerkleSeqIndex, TypedSignedProtocolMessageContent,
        ViewPosition,
    };
    use canton_proto::google::rpc::Status;
    let message = ConfirmationResponses {
        request_id: request_id_micros,
        root_hash: root_hash.to_vec(),
        physical_synchronizer_id: physical_synchronizer_id.to_string(),
        sender: sender_member.to_string(),
        responses: responses
            .iter()
            .map(|r| {
                let (code, status_code, reason) = match &r.outcome {
                    Outcome::Approve => (VerdictCode::LocalApprove, 0, String::new()),
                    // FAILED_PRECONDITION (9) for a refusal/abstain, INVALID_ARGUMENT (3) for what cannot be read
                    Outcome::Reject(why) => (VerdictCode::LocalReject, 9, why.clone()),
                    Outcome::Malformed(why) => (VerdictCode::LocalMalformed, 3, why.clone()),
                    Outcome::Abstain(why) => (VerdictCode::LocalAbstain, 9, why.clone()),
                };
                let malformed = matches!(r.outcome, Outcome::Malformed(_));
                ConfirmationResponse {
                    local_verdict: Some(LocalVerdict {
                        code: code as i32,
                        reason: Some(Status {
                            code: status_code,
                            message: reason,
                            details: Vec::new(),
                        }),
                    }),
                    confirming_parties: if malformed {
                        Vec::new()
                    } else {
                        r.confirming_parties.to_vec()
                    },
                    view_position: (!malformed || !r.view_position.is_empty()).then(|| {
                        ViewPosition {
                            position: r
                                .view_position
                                .iter()
                                .map(|index| MerkleSeqIndex {
                                    is_right: index.clone(),
                                })
                                .collect(),
                        }
                    }),
                }
            })
            .collect(),
    };
    let typed = TypedSignedProtocolMessageContent {
        some_signed_protocol_message: Some(SomeSignedProtocolMessage::ConfirmationResponses(
            versioned(message.encode_to_vec(), SIGNED_MESSAGE_VERSION),
        )),
    };
    let content = versioned(typed.encode_to_vec(), SIGNED_MESSAGE_VERSION);
    let mut hash = vec![0x12, 0x20];
    hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(
        PURPOSE_SIGNED_PROTOCOL_MESSAGE,
        &content,
    ));
    let signature = key.sign_bytes(&hash);
    (content, vec![signature])
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_proto::com::digitalasset::canton::protocol::v30::{
        typed_signed_protocol_message_content::SomeSignedProtocolMessage, ConfirmationResponses,
        TypedSignedProtocolMessageContent,
    };

    fn sent(position: &[Vec<bool>]) -> ConfirmationResponses {
        let key = Ed25519Key::from_seed([7; 32]);
        let responses = [ViewResponse {
            view_position: position,
            outcome: Outcome::Malformed("LOCAL_VERDICT_FAILED_MODEL_CONFORMANCE_CHECK".into()),
            confirming_parties: &["alice::1220aa".to_string()],
        }];
        let (content, _) = confirmation_responses(
            1,
            &[7],
            "sync::1220aa::37-0",
            "PAR::p::1220aa",
            &responses,
            &key,
        );
        let (typed, _) = crate::topology_wire::unversioned(&content).unwrap();
        let typed = TypedSignedProtocolMessageContent::decode(typed.as_slice()).unwrap();
        let Some(SomeSignedProtocolMessage::ConfirmationResponses(bytes)) =
            typed.some_signed_protocol_message
        else {
            panic!("confirmation responses")
        };
        let (message, _) = crate::topology_wire::unversioned(&bytes).unwrap();
        ConfirmationResponses::decode(message.as_slice()).unwrap()
    }

    /// A malformed view keeps its position and names no party; a malformed request names neither (`ConfirmationResponse` invariants).
    #[test]
    fn a_malformed_view_is_answered_for_its_position_without_parties() {
        let view = sent(&[vec![true]]);
        assert!(view.responses[0].confirming_parties.is_empty());
        assert_eq!(
            view.responses[0]
                .view_position
                .as_ref()
                .map(|p| p.position.len()),
            Some(1)
        );
        let request = sent(&[]);
        assert!(request.responses[0].view_position.is_none());
    }

    #[test]
    fn an_abstain_answer_keeps_view_position_and_confirming_parties() {
        use canton_proto::com::digitalasset::canton::protocol::v30::{
            local_verdict::VerdictCode,
            typed_signed_protocol_message_content::SomeSignedProtocolMessage,
            ConfirmationResponses, TypedSignedProtocolMessageContent,
        };
        let key = Ed25519Key::from_seed([8; 32]);
        let party = "alice::1220aa".to_string();
        let responses = [ViewResponse {
            view_position: &[vec![false]],
            outcome: Outcome::Abstain("not a reassigning participant".into()),
            confirming_parties: std::slice::from_ref(&party),
        }];
        let (content, _) = confirmation_responses(
            1,
            &[9],
            "sync::1220aa::37-0",
            "PAR::p::1220aa",
            &responses,
            &key,
        );
        let (typed, _) = crate::topology_wire::unversioned(&content).unwrap();
        let typed = TypedSignedProtocolMessageContent::decode(typed.as_slice()).unwrap();
        let Some(SomeSignedProtocolMessage::ConfirmationResponses(bytes)) =
            typed.some_signed_protocol_message
        else {
            panic!("confirmation responses")
        };
        let (message, _) = crate::topology_wire::unversioned(&bytes).unwrap();
        let decoded = ConfirmationResponses::decode(message.as_slice()).unwrap();
        assert_eq!(
            decoded.responses[0].local_verdict.as_ref().map(|v| v.code),
            Some(VerdictCode::LocalAbstain as i32)
        );
        assert_eq!(decoded.responses[0].confirming_parties, vec![party]);
        assert!(decoded.responses[0].view_position.is_some());
    }
}
