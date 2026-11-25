//! Submission requests and sequenced events as they go over the wire (G5 5.5, S-NET-004).
//!
//! Generated messages (`canton-proto`) plus the rules the `.proto` files do not state, read from the Canton 3.7.2 sources:
//!
//! [CANTON-NOTE: SEMANTICS]
//! - For protocol version 37 a `SubmissionRequest` is the **v33** message wrapped in `UntypedVersionedMessage` with version 33;
//!   the `SequencedEvent` is the **v32** message (version 32); `SignedContent` is v30 (version 30).
//! - A batch is **Zstd**-compressed twice over: the recipients (`DecompressedRecipients`) as one block and each envelope
//!   (`EnvelopeWithoutRecipients`) on its own.
//! - The sender signs the multihash of `HashPurpose.SubmissionRequestSignature` (35) over the *versioned* request bytes with a
//!   key whose usage includes `protocol`; the signed request is `SignedContent { content, signatures }`, again versioned (30).
//!
//! [CANTON-NOTE: LIMITATION] The submission requests built here carry no aggregation rule and no topology timestamp (not part of the
//! v33 request).
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    Recipients, RecipientsTree, SequencingSubmissionCost, SignedContent,
};
use canton_proto::com::digitalasset::canton::protocol::v31::EnvelopeWithoutRecipients;
use canton_proto::com::digitalasset::canton::protocol::v32::{
    compressed_batch::DecompressedRecipients, CompressedBatch, SequencedEvent,
};
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use prost::Message;

use crate::topology_wire::{unversioned, versioned, Ed25519Key};

/// `HashPurpose.SubmissionRequestSignature`.
const PURPOSE_SUBMISSION_REQUEST_SIGNATURE: i32 = 35;
pub const SUBMISSION_REQUEST_VERSION: i32 = 33;
pub const SEQUENCED_EVENT_VERSION: i32 = 32;
pub const SIGNED_CONTENT_VERSION: i32 = 30;

/// Zstd with the content size in the frame header: the sequencer sizes its decompression buffer from it (the streaming
/// `encode_all` leaves it out and the sequencer refuses the request: "Destination buffer is too small", measured).
///
/// [CANTON-NOTE: SEMANTICS] Level 5, as Canton compresses (`ByteStringUtil.DefaultZstdCompressionLevel`, `Zstd.compress(bytes, 5)`): a participant that reads the
/// same event from two sequencers compares the compressed bytes, so a sequencer that compressed at another level hands out an event the others do not.
fn compress(bytes: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(bytes, 5).expect("zstd compression of an in-memory buffer")
}

/// The bound of [`decompress`]: Canton's `MaxBytesToDecompress.HardcodedDefault` (10 MiB), what it applies to each envelope when it has no
/// topology snapshot to read `max_request_size` from.
///
/// [CANTON-NOTE: LIMITATION] Canton bounds a delivered batch by the dynamic `max_request_size` in force (`SequencedEventValidator`); the
/// readers here do not follow the parameters, so a synchronizer that raised `max_request_size` past 10 MiB delivers envelopes they refuse.
pub const MAX_DECOMPRESSED_BYTES: usize = 10 * 1024 * 1024;

/// Why a Zstd block was not decompressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressError {
    /// The output would be longer than the bound: decoding stopped there.
    TooLarge,
    /// Not a Zstd block.
    Invalid,
}

/// Decompresses a Zstd block into at most `limit` bytes, stopping as soon as the output passes it (`ByteStringUtil.decompress` with
/// `MaxBytesToDecompress`): a few bytes on the wire can claim gigabytes.
pub fn decompress_within(bytes: &[u8], limit: usize) -> Result<Vec<u8>, DecompressError> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|_| DecompressError::Invalid)?;
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| DecompressError::Invalid)?;
    if out.len() > limit {
        return Err(DecompressError::TooLarge);
    }
    Ok(out)
}

/// Decompresses a Zstd block (what the sequencer put in a delivered batch), bounded by [`MAX_DECOMPRESSED_BYTES`].
pub fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
    decompress_within(bytes, MAX_DECOMPRESSED_BYTES).ok()
}

/// A batch of envelopes (`(recipient member, opaque content)`), each to one recipient.
pub fn compressed_batch(envelopes: &[(String, Vec<u8>)]) -> CompressedBatch {
    let grouped: Vec<(Vec<String>, Vec<u8>)> = envelopes
        .iter()
        .map(|(member, content)| (vec![member.clone()], content.clone()))
        .collect();
    compressed_batch_to_groups(&grouped)
}

/// A batch of envelopes (`(recipient group, content)`): each envelope goes to **all** the recipients of its group at once
/// (one `RecipientsTree` node holding the whole group, as the transaction protocol addresses a root hash message to
/// the mediator group together with one participant).
pub fn compressed_batch_to_groups(envelopes: &[(Vec<String>, Vec<u8>)]) -> CompressedBatch {
    let with_signatures: Vec<(Vec<String>, Vec<u8>, Vec<Signature>)> = envelopes
        .iter()
        .map(|(group, content)| (group.clone(), content.clone(), Vec::new()))
        .collect();
    compressed_batch_signed(&with_signatures)
}

/// Like [`compressed_batch_to_groups`], but each envelope carries signatures.
///
/// [CANTON-NOTE: SEMANTICS] An envelope without signatures holds an `EnvelopeContent`; one **with** signatures holds the
/// `TypedSignedProtocolMessageContent` of a signed protocol message (e.g. `ConfirmationResponses`) and the signatures are the
/// message's (`ClosedUncompressedEnvelope.toOpenEnvelope`).
pub fn compressed_batch_signed(
    envelopes: &[(Vec<String>, Vec<u8>, Vec<Signature>)],
) -> CompressedBatch {
    let recipients = DecompressedRecipients {
        recipients: envelopes
            .iter()
            .map(|(group, _, _)| Recipients {
                recipients_tree: vec![RecipientsTree {
                    recipients: group.clone(),
                    children: Vec::new(),
                }],
            })
            .collect(),
    };
    CompressedBatch {
        compressed_recipients: compress(&recipients.encode_to_vec()),
        compressed_envelopes: envelopes
            .iter()
            .map(|(_, content, signatures)| {
                compress(
                    &EnvelopeWithoutRecipients {
                        content: content.clone(),
                        signatures: signatures.clone(),
                    }
                    .encode_to_vec(),
                )
            })
            .collect(),
    }
}

/// An envelope addressed to a list of recipient trees: the trees (each one group of addresses), the content and the signatures.
pub type TreeEnvelope = (Vec<Vec<String>>, Vec<u8>, Vec<Signature>);

/// Like [`compressed_batch_trees`], preserving arbitrary multi-level [`RecipientsTree`] paths for each envelope.
pub fn compressed_batch_recipient_trees(
    envelopes: &[(Vec<RecipientsTree>, Vec<u8>, Vec<Signature>)],
) -> CompressedBatch {
    let recipients = DecompressedRecipients {
        recipients: envelopes
            .iter()
            .map(|(trees, _, _)| Recipients {
                recipients_tree: trees.clone(),
            })
            .collect(),
    };
    CompressedBatch {
        compressed_recipients: compress(&recipients.encode_to_vec()),
        compressed_envelopes: envelopes
            .iter()
            .map(|(_, content, signatures)| {
                compress(
                    &EnvelopeWithoutRecipients {
                        content: content.clone(),
                        signatures: signatures.clone(),
                    }
                    .encode_to_vec(),
                )
            })
            .collect(),
    }
}

/// Like [`compressed_batch_signed`], but each envelope is addressed to a **list of recipient trees** (each tree one group): an envelope
/// that goes to several groups at once, as the root hash message does when a request has several informee participants (one tree
/// `{mediator group, participant}` for each; measured on the JVM participant's request).
pub fn compressed_batch_trees(envelopes: &[TreeEnvelope]) -> CompressedBatch {
    let recipients = DecompressedRecipients {
        recipients: envelopes
            .iter()
            .map(|(trees, _, _)| Recipients {
                recipients_tree: trees
                    .iter()
                    .map(|group| RecipientsTree {
                        recipients: group.clone(),
                        children: Vec::new(),
                    })
                    .collect(),
            })
            .collect(),
    };
    CompressedBatch {
        compressed_recipients: compress(&recipients.encode_to_vec()),
        compressed_envelopes: envelopes
            .iter()
            .map(|(_, content, signatures)| {
                compress(
                    &EnvelopeWithoutRecipients {
                        content: content.clone(),
                        signatures: signatures.clone(),
                    }
                    .encode_to_vec(),
                )
            })
            .collect(),
    }
}

/// An envelope addressed to a **path** of recipient groups, outermost first: one `RecipientsTree` whose node holds the first group and
/// whose single child holds the next, and so on. A path of one group is the same as [`compressed_batch_to_groups`].
///
/// [CANTON-NOTE: SEMANTICS] The message of a subview goes to the groups of every view from the root down to it (`Witnesses.toRecipients`:
/// one level per view, each the participants of that view's informees). A participant that received an ancestor view and gets a subview
/// whose recipients have no group for that ancestor discards the ancestor (`RecipientsValidator.checkRecipientsPath`: "no recipients group
/// for ...", reported as `WrongRecipients`; measured, S-G11-001).
/// The recipients tree of a path of groups: the first group at the top, each next one the only child of the one before.
pub fn path_tree(path: &[Vec<String>]) -> RecipientsTree {
    RecipientsTree {
        recipients: path.first().cloned().unwrap_or_default(),
        children: if path.len() > 1 {
            vec![path_tree(&path[1..])]
        } else {
            Vec::new()
        },
    }
}

/// A submission request whose envelopes are each addressed to their own recipient trees (`Recipients`): several groups at once for the
/// root hash message, a path for a view message (U-57).
pub fn submission_request_with_trees(
    sender: &str,
    message_id: &str,
    envelopes: &[(Vec<RecipientsTree>, Vec<u8>)],
    max_sequencing_time_micros: i64,
) -> Vec<u8> {
    let with_signatures: Vec<(Vec<RecipientsTree>, Vec<u8>, Vec<Signature>)> = envelopes
        .iter()
        .map(|(trees, content)| (trees.clone(), content.clone(), Vec::new()))
        .collect();
    versioned(
        SubmissionRequest {
            sender: sender.to_string(),
            message_id: message_id.to_string(),
            batch: Some(compressed_batch_recipient_trees(&with_signatures)),
            max_sequencing_time: max_sequencing_time_micros,
            aggregation_rule: None,
            submission_cost: None,
        }
        .encode_to_vec(),
        SUBMISSION_REQUEST_VERSION,
    )
}

pub fn compressed_batch_paths(envelopes: &[(Vec<Vec<String>>, Vec<u8>)]) -> CompressedBatch {
    let tree = path_tree;
    let recipients = DecompressedRecipients {
        recipients: envelopes
            .iter()
            .map(|(path, _)| Recipients {
                recipients_tree: vec![tree(path)],
            })
            .collect(),
    };
    CompressedBatch {
        compressed_recipients: compress(&recipients.encode_to_vec()),
        compressed_envelopes: envelopes
            .iter()
            .map(|(_, content)| {
                compress(
                    &EnvelopeWithoutRecipients {
                        content: content.clone(),
                        signatures: Vec::new(),
                    }
                    .encode_to_vec(),
                )
            })
            .collect(),
    }
}

/// Like [`submission_request_to_groups`], each envelope addressed to a path of groups (see [`compressed_batch_paths`]).
pub fn submission_request_to_paths(
    sender: &str,
    message_id: &str,
    envelopes: &[(Vec<Vec<String>>, Vec<u8>)],
    max_sequencing_time_micros: i64,
) -> Vec<u8> {
    versioned(
        SubmissionRequest {
            sender: sender.to_string(),
            message_id: message_id.to_string(),
            batch: Some(compressed_batch_paths(envelopes)),
            max_sequencing_time: max_sequencing_time_micros,
            aggregation_rule: None,
            submission_cost: None,
        }
        .encode_to_vec(),
        SUBMISSION_REQUEST_VERSION,
    )
}

/// The versioned bytes of a submission request.
pub fn submission_request(
    sender: &str,
    message_id: &str,
    envelopes: &[(String, Vec<u8>)],
    max_sequencing_time_micros: i64,
) -> Vec<u8> {
    submission_request_costed(
        sender,
        message_id,
        envelopes,
        max_sequencing_time_micros,
        None,
    )
}

/// Like [`submission_request`], with the traffic cost the sender computed (what a sequencer with traffic control on checks).
pub fn submission_request_costed(
    sender: &str,
    message_id: &str,
    envelopes: &[(String, Vec<u8>)],
    max_sequencing_time_micros: i64,
    cost: Option<i64>,
) -> Vec<u8> {
    versioned(
        SubmissionRequest {
            sender: sender.to_string(),
            message_id: message_id.to_string(),
            batch: Some(compressed_batch(envelopes)),
            max_sequencing_time: max_sequencing_time_micros,
            aggregation_rule: None,
            submission_cost: cost.map(|cost| SequencingSubmissionCost { cost }),
        }
        .encode_to_vec(),
        SUBMISSION_REQUEST_VERSION,
    )
}

/// Like [`submission_request`], but each envelope is addressed to a whole group of recipients.
pub fn submission_request_to_groups(
    sender: &str,
    message_id: &str,
    envelopes: &[(Vec<String>, Vec<u8>)],
    max_sequencing_time_micros: i64,
) -> Vec<u8> {
    versioned(
        SubmissionRequest {
            sender: sender.to_string(),
            message_id: message_id.to_string(),
            batch: Some(compressed_batch_to_groups(envelopes)),
            max_sequencing_time: max_sequencing_time_micros,
            aggregation_rule: None,
            submission_cost: None,
        }
        .encode_to_vec(),
        SUBMISSION_REQUEST_VERSION,
    )
}

/// Like [`submission_request_to_groups`], with signed envelopes (see [`compressed_batch_signed`]).
pub fn submission_request_signed(
    sender: &str,
    message_id: &str,
    envelopes: &[(Vec<String>, Vec<u8>, Vec<Signature>)],
    max_sequencing_time_micros: i64,
) -> Vec<u8> {
    versioned(
        SubmissionRequest {
            sender: sender.to_string(),
            message_id: message_id.to_string(),
            batch: Some(compressed_batch_signed(envelopes)),
            max_sequencing_time: max_sequencing_time_micros,
            aggregation_rule: None,
            submission_cost: None,
        }
        .encode_to_vec(),
        SUBMISSION_REQUEST_VERSION,
    )
}

/// What the sender signs for a submission request.
pub fn submission_hash(request_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&canton_algo::hash::sha256_with_purpose(
        PURPOSE_SUBMISSION_REQUEST_SIGNATURE,
        request_bytes,
    ));
    out
}

/// The `SendAsyncRequest.signed_submission_request` bytes: the request signed by `key`.
pub fn signed_submission_request(request_bytes: Vec<u8>, key: &Ed25519Key) -> Vec<u8> {
    let signature = key.sign_bytes(&submission_hash(&request_bytes));
    versioned(
        SignedContent {
            content: Some(request_bytes),
            signatures: vec![signature],
            timestamp_of_signing_key: None,
        }
        .encode_to_vec(),
        SIGNED_CONTENT_VERSION,
    )
}

/// The envelopes of a signed submission request (what [`signed_submission_request`] makes) as a sequencer prices them: each envelope's
/// content size and every address of its recipient trees, once. `None` when it does not decode.
///
/// [CANTON-NOTE: SEMANTICS] `EventCostCalculator` prices the uncompressed content of an envelope (`ClosedUncompressedEnvelope.bytes`),
/// not its signatures, and counts `recipients.allRecipients`: every address of every tree level.
pub fn submission_envelopes(
    signed_request: &[u8],
) -> Option<Vec<(usize, std::collections::BTreeSet<String>)>> {
    fn all(tree: &RecipientsTree, into: &mut std::collections::BTreeSet<String>) {
        into.extend(tree.recipients.iter().cloned());
        for child in &tree.children {
            all(child, into);
        }
    }
    let (signed, _) = unversioned(signed_request)?;
    let content = SignedContent::decode(signed.as_slice()).ok()?.content?;
    let (request, _) = unversioned(&content)?;
    let batch = SubmissionRequest::decode(request.as_slice()).ok()?.batch?;
    let recipients = decompress(&batch.compressed_recipients)
        .and_then(|b| canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok())?;
    if recipients.recipients.len() != batch.compressed_envelopes.len() {
        return None;
    }
    recipients
        .recipients
        .iter()
        .zip(&batch.compressed_envelopes)
        .map(|(r, compressed)| {
            let envelope =
                EnvelopeWithoutRecipients::decode(decompress(compressed)?.as_slice()).ok()?;
            let mut addresses = std::collections::BTreeSet::new();
            for tree in &r.recipients_tree {
                all(tree, &mut addresses);
            }
            Some((envelope.content.len(), addresses))
        })
        .collect()
}

/// `signed_request` with its traffic cost set to `cost` and signed again by `key` (the cost is part of what the sender signs). `None` when
/// it does not decode.
pub fn with_submission_cost(signed_request: &[u8], cost: i64, key: &Ed25519Key) -> Option<Vec<u8>> {
    let (signed, _) = unversioned(signed_request)?;
    let content = SignedContent::decode(signed.as_slice()).ok()?.content?;
    let (request, version) = unversioned(&content)?;
    let mut request = SubmissionRequest::decode(request.as_slice()).ok()?;
    request.submission_cost = Some(SequencingSubmissionCost { cost });
    Some(signed_submission_request(
        versioned(request.encode_to_vec(), version),
        key,
    ))
}

/// The `max_sequencing_time` of a signed submission request (what [`signed_submission_request`] makes), or `None` when it does not decode.
pub fn max_sequencing_time_of(signed_request: &[u8]) -> Option<i64> {
    let (signed, _) = unversioned(signed_request)?;
    let content = SignedContent::decode(signed.as_slice()).ok()?.content?;
    let (request, _) = unversioned(&content)?;
    Some(
        SubmissionRequest::decode(request.as_slice())
            .ok()?
            .max_sequencing_time,
    )
}

/// The prefix of a time proof's message id (`TimeProof.timeEventMessageIdPrefix`).
pub const TIME_PROOF_PREFIX: &str = "tick-";

/// A time proof request (`TimeProof.sendRequest`): an empty batch the sequencer delivers back to `sender` only, signed by `key`. The event it
/// becomes tells the sender the synchronizer's time when nothing else is sequenced.
pub fn signed_time_proof_request(
    sender: &str,
    message_id: &str,
    max_sequencing_time_micros: i64,
    key: &Ed25519Key,
) -> Vec<u8> {
    signed_submission_request(
        submission_request_to_groups(sender, message_id, &[], max_sequencing_time_micros),
        key,
    )
}

/// The hash an acknowledgement is signed over (`HashPurpose.AcknowledgementSignature`, 36) as a multihash.
pub fn acknowledgement_hash(request_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&canton_algo::hash::sha256_with_purpose(36, request_bytes));
    out
}

/// `SignedContent[AcknowledgeRequest]` (versioned): `member` tells the sequencer it has read every event up to `timestamp_micros` and will not
/// read them again.
pub fn signed_acknowledge_request(
    member: &str,
    timestamp_micros: i64,
    key: &Ed25519Key,
) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::sequencer::api::v30::AcknowledgeRequest;
    let request = versioned(
        AcknowledgeRequest {
            member: member.to_string(),
            timestamp: timestamp_micros,
        }
        .encode_to_vec(),
        // [CANTON-NOTE: SEMANTICS] the acknowledge request is a versioned wrapper of proto version 30 (the submission request's is 33)
        30,
    );
    let signature = key.sign_bytes(&acknowledgement_hash(&request));
    versioned(
        SignedContent {
            content: Some(request),
            signatures: vec![signature],
            timestamp_of_signing_key: None,
        }
        .encode_to_vec(),
        SIGNED_CONTENT_VERSION,
    )
}

/// A delivered event: what the sequencer sent to a subscriber, decoded.
#[derive(Debug, Clone)]
pub struct Delivered {
    pub timestamp_micros: i64,
    pub previous_timestamp_micros: Option<i64>,
    pub physical_synchronizer_id: String,
    pub message_id: Option<String>,
    /// The envelopes' contents, decompressed (empty for an event that carries none).
    pub envelopes: Vec<Vec<u8>>,
    /// The recipients of each envelope, as the members the sequencer wrote.
    pub recipients: Vec<Vec<String>>,
    /// The signatures each envelope carries (a signed protocol message, e.g. the mediator's confirmation result, has them).
    pub envelope_signatures: Vec<Vec<Signature>>,
    /// The signatures on the event (the sequencer's).
    pub signatures: Vec<Signature>,
    /// A rejection the sequencer recorded instead of a delivery, written `<gRPC code>: <message>` (see [`Delivered::deliver_error`]).
    pub error: Option<String>,
    /// The versioned `SequencedEvent` bytes: what the sequencer's signature covers (see [`event_hash`]).
    pub event_bytes: Vec<u8>,
    /// `SignedContent.timestamp_of_signing_key`, which a sequenced event must not set.
    pub timestamp_of_signing_key_micros: Option<i64>,
}

/// What an event that carries a message id tells its sender about its submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt<'a> {
    /// The submission with this message id is sequenced at the event's timestamp.
    Sequenced(&'a str),
    /// The sequencer refused the submission with this message id (a deliver error): its gRPC code and message.
    Refused(&'a str, i32, &'a str),
}

impl Delivered {
    /// The receipt of the sender's own submission (`None` for an event about someone else's).
    ///
    /// [CANTON-NOTE: SEMANTICS] A deliver error is not a sequenced submission (`MessageDispatcher.observeSequencing` skips it), and one that
    /// refuses an aggregated submission already sent is no failure of it (`InFlightSubmissionTracker.observeDeliverError`).
    pub fn receipt(&self) -> Option<Receipt<'_>> {
        let message_id = self.message_id.as_deref()?;
        let Some(error) = self.error.as_deref() else {
            return Some(Receipt::Sequenced(message_id));
        };
        let (code, message) = error.split_once(": ")?;
        (!message.starts_with("SEQUENCER_AGGREGATE_SUBMISSION_ALREADY_SENT"))
            .then_some(Receipt::Refused(message_id, code.parse().ok()?, message))
    }
}

/// What the sequencer signs for an event: the multihash of `HashPurpose.SequencedEventSignature` (1) over the versioned event.
pub fn event_hash(event_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&canton_algo::hash::sha256_with_purpose(1, event_bytes));
    out
}

/// The `signed_sequenced_event` bytes of a `SubscriptionResponse`: `event`, versioned, signed by the sequencer's `key` (what
/// [`decode_delivered`] reads back).
pub fn signed_sequenced_event(event: &SequencedEvent, key: &Ed25519Key) -> Vec<u8> {
    let event_bytes = versioned(event.encode_to_vec(), SEQUENCED_EVENT_VERSION);
    let signature = key.sign_bytes(&event_hash(&event_bytes));
    versioned(
        SignedContent {
            content: Some(event_bytes),
            signatures: vec![signature],
            timestamp_of_signing_key: None,
        }
        .encode_to_vec(),
        SIGNED_CONTENT_VERSION,
    )
}

/// Decodes the `signed_sequenced_event` bytes of a `SubscriptionResponse`.
///
/// [CANTON-NOTE: SEMANTICS] All or nothing, as `SequencedEvent.fromProtoV30` and `SequencedEvent.decompress`: an event whose recipients or one
/// of whose envelopes do not decompress or decode is not an event (`DecompressionFailed`), rather than an event with that envelope left out.
pub fn decode_delivered(bytes: &[u8]) -> Option<Delivered> {
    let (data, version) = unversioned(bytes)?;
    if version != SIGNED_CONTENT_VERSION {
        return None;
    }
    let signed = SignedContent::decode(data.as_slice()).ok()?;
    // `SignedContent.fromProtoV30` requires a signature (`parseRequiredNonEmpty`)
    if signed.signatures.is_empty() {
        return None;
    }
    let content = signed.content?;
    let (event_bytes, event_version) = unversioned(&content)?;
    if event_version != SEQUENCED_EVENT_VERSION {
        return None;
    }
    let event = SequencedEvent::decode(event_bytes.as_slice()).ok()?;
    let batch = event.batch.unwrap_or_default();
    let recipients = if batch.compressed_recipients.is_empty() {
        Vec::new()
    } else {
        canton_proto::depth::decode::<DecompressedRecipients>(
            decompress(&batch.compressed_recipients)?.as_slice(),
        )
        .ok()?
        .recipients
        .into_iter()
        .map(|r| {
            r.recipients_tree
                .into_iter()
                .flat_map(|t| t.recipients)
                .collect()
        })
        .collect()
    };
    let decoded = batch
        .compressed_envelopes
        .iter()
        .map(|e| EnvelopeWithoutRecipients::decode(decompress(e)?.as_slice()).ok())
        .collect::<Option<Vec<_>>>()?;
    let envelope_signatures = decoded.iter().map(|e| e.signatures.clone()).collect();
    let envelopes = decoded.into_iter().map(|e| e.content).collect();
    Some(Delivered {
        timestamp_micros: event.timestamp,
        previous_timestamp_micros: event.previous_timestamp,
        physical_synchronizer_id: event.physical_synchronizer_id,
        message_id: event.message_id,
        envelopes,
        recipients,
        envelope_signatures,
        signatures: signed.signatures,
        error: event
            .deliver_error_reason
            .map(|s| format!("{}: {}", s.code, s.message)),
        event_bytes: content,
        timestamp_of_signing_key_micros: signed.timestamp_of_signing_key,
    })
}

/// The recipient trees of each envelope of a delivered event, **not flattened**: for each envelope, each tree as the list of the addresses it
/// names. A mediator that is not told who sent a message needs the trees to tell a request (the informee message alone to the group) from the
/// root hash messages (to the group and one participant).
pub fn decode_recipient_trees(bytes: &[u8]) -> Option<Vec<Vec<Vec<String>>>> {
    let (data, version) = unversioned(bytes)?;
    if version != SIGNED_CONTENT_VERSION {
        return None;
    }
    let signed = SignedContent::decode(data.as_slice()).ok()?;
    let (event_bytes, _) = unversioned(&signed.content?)?;
    let event = SequencedEvent::decode(event_bytes.as_slice()).ok()?;
    let batch = event.batch.unwrap_or_default();
    let decompressed = decompress(&batch.compressed_recipients)
        .and_then(|b| canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok())?;
    Some(
        decompressed
            .recipients
            .into_iter()
            .map(|r| {
                r.recipients_tree
                    .into_iter()
                    .map(|t| t.recipients)
                    .collect()
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_paid_request_keeps_its_envelopes_and_carries_the_cost_signed_again() {
        let key = Ed25519Key::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]));
        let envelopes = vec![
            (vec!["MGR::0".to_string()], vec![1u8; 950]),
            (
                vec!["MGR::0".to_string(), "PAR::a::1".to_string()],
                vec![2u8; 139],
            ),
        ];
        let signed = signed_submission_request(
            submission_request_to_groups("PAR::me::1", "m-1", &envelopes, 42),
            &key,
        );
        let read = submission_envelopes(&signed).expect("decodes");
        assert_eq!(
            read.iter().map(|(s, a)| (*s, a.len())).collect::<Vec<_>>(),
            vec![(950, 1), (139, 2)]
        );
        let paid = with_submission_cost(&signed, 3061, &key).expect("decodes");
        let (outer, _) = unversioned(&paid).unwrap();
        let content = SignedContent::decode(outer.as_slice()).unwrap();
        let (request, _) = unversioned(content.content.as_ref().unwrap()).unwrap();
        let request = SubmissionRequest::decode(request.as_slice()).unwrap();
        assert_eq!(request.submission_cost.map(|c| c.cost), Some(3061));
        assert_eq!(max_sequencing_time_of(&paid), Some(42));
        // the signature is over the paid request, not the unpaid one
        assert_ne!(
            content.signatures,
            SignedContent::decode(unversioned(&signed).unwrap().0.as_slice())
                .unwrap()
                .signatures
        );
        assert_eq!(submission_envelopes(&paid), Some(read));
    }

    #[test]
    fn a_block_that_decompresses_past_the_bound_is_not_read() {
        // 11 MiB of zeros are a few hundred bytes on the wire
        let bomb = compress(&vec![0u8; 11 * 1024 * 1024]);
        assert!(bomb.len() < 4096, "{}", bomb.len());
        assert_eq!(decompress(&bomb), None, "past the 10 MiB bound");
        // control: a block within the bound reads back
        let small = vec![7u8; 1024];
        assert_eq!(decompress(&compress(&small)), Some(small));
    }

    #[test]
    fn a_bounded_decompression_takes_exactly_the_limit_and_tells_too_large_from_invalid() {
        let block = compress(&[5u8; 1000]);
        assert_eq!(decompress_within(&block, 1000), Ok(vec![5u8; 1000]));
        assert_eq!(
            decompress_within(&block, 999),
            Err(DecompressError::TooLarge)
        );
        assert_eq!(
            decompress_within(b"not zstd", 1000),
            Err(DecompressError::Invalid)
        );
    }
}
