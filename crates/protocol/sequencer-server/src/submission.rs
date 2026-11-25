//! A signed submission request as the sequencer reads it (`SignedContent[SubmissionRequest]` with its batch decompressed), and what the
//! ordering layer reads of one without the sequencer's state (who sent it, its priority in a block, whether it may change the ordering
//! topology).
use canton_participant::sequencing_wire as sw;
use canton_participant::topology_wire as tw;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    AggregationRule, RecipientsTree, SignedContent,
};
use canton_proto::com::digitalasset::canton::protocol::v31::EnvelopeWithoutRecipients;
use canton_proto::com::digitalasset::canton::protocol::v32::compressed_batch::DecompressedRecipients;
use canton_proto::com::digitalasset::canton::protocol::v33::SubmissionRequest;
use prost::Message;
use std::collections::BTreeSet;
use tonic::Status;

/// The most recipients one tree of a batch may name (`max_recipients_per_recipients_tree_level` of the synchronizer's limits).
const MAX_RECIPIENTS_PER_TREE: usize = 10_000;

/// The longest message id a submission may carry (`MessageId` is a `String73`).
const MAX_MESSAGE_ID_LENGTH: usize = 73;

/// A submission request, decoded and with its batch decompressed within the `max_request_size` in force.
pub(crate) struct Submission {
    /// The versioned `SubmissionRequest` bytes: what the sender signed.
    pub(crate) content: Vec<u8>,
    pub(crate) signatures: Vec<Signature>,
    pub(crate) sender: String,
    pub(crate) message_id: String,
    pub(crate) max_sequencing_time: i64,
    pub(crate) aggregation_rule: Option<AggregationRule>,
    /// The cost the sender says the submission has (traffic control).
    pub(crate) submitted_cost: Option<u64>,
    /// Each envelope's `Recipients` as encoded (what the aggregation id hashes).
    pub(crate) recipient_protos: Vec<Vec<u8>>,
    /// Each envelope's recipient trees.
    pub(crate) trees: Vec<Vec<RecipientsTree>>,
    /// Each envelope's trees, each flattened to the addresses it names.
    pub(crate) recipients: Vec<Vec<Vec<String>>>,
    pub(crate) envelopes: Vec<EnvelopeWithoutRecipients>,
}

impl Submission {
    /// Decodes `signed_request` (the `SendAsyncRequest.signed_submission_request` bytes); the envelopes together may decompress to at most
    /// `max_request_size` bytes.
    ///
    /// [CANTON-NOTE: SEMANTICS] `GrpcSequencerService` deserializes the request with `MaxBytesToDecompress(maxRequestSize)`: the recipients
    /// block is bounded on its own, the envelopes together share one budget (`DecompressionPolicy.Cumulative`, protocol version 36 on), and
    /// decoding stops once a budget is spent, so a small request cannot claim gigabytes. After ordering, the budget is the one in force at
    /// the sequencing time (`BlockChunkProcessor.addSnapshotsAndValidateSubmissions`).
    pub(crate) fn parse(signed_request: &[u8], max_request_size: usize) -> Result<Self, Status> {
        // the request could not be read: the official sequencer cannot name its id or sender
        let bad = |detail: &str| malformed("", "", detail);
        let (data, version) = tw::unversioned(signed_request)
            .ok_or_else(|| bad("BufferException(not a versioned message)"))?;
        if version != sw::SIGNED_CONTENT_VERSION {
            return Err(bad(&format!(
                "OtherError(Unable to find deserializer for version ProtoVersion({version}) and message SignedContent. This indicates that the node is trying to parse a message with a proto version that is not supported anymore.)"
            )));
        }
        let signed = SignedContent::decode(data.as_slice())
            .map_err(|e| bad(&format!("BufferException({e})")))?;
        let content = signed
            .content
            .ok_or_else(|| bad("ValueConversionError(SignedContent.content,missing)"))?;
        let (request_bytes, request_version) = tw::unversioned(&content)
            .ok_or_else(|| bad("BufferException(not a versioned message)"))?;
        if request_version != sw::SUBMISSION_REQUEST_VERSION {
            return Err(bad(&format!(
                "OtherError(Unable to find deserializer for version ProtoVersion({request_version}) and message SubmissionRequest.)"
            )));
        }
        let request = SubmissionRequest::decode(request_bytes.as_slice())
            .map_err(|e| bad(&format!("BufferException({e})")))?;
        // [CANTON-NOTE: SEMANTICS] A message id is a `String73` (`MessageId`): longer, and the request does not deserialize, so the official
        // sequencer names neither id nor sender (`GrpcSequencerService.requestDeserializationError`). The length is the Java string's (UTF-16
        // code units); the text is `LengthLimitedString`'s, measured on the JVM sequencer (S-LOCAL-011).
        let id_length = request.message_id.encode_utf16().count();
        if id_length > MAX_MESSAGE_ID_LENGTH {
            return Err(bad(&format!(
                "InvariantViolation(Some(message_id),The given message_id has a maximum length of {MAX_MESSAGE_ID_LENGTH} but a message_id of length {id_length} ('{}') was given)",
                request.message_id
            )));
        }
        let (id, sender) = (request.message_id.clone(), request.sender.clone());
        let batch = request.batch.unwrap_or_default();
        let decompressed_recipients =
            sw::decompress_within(&batch.compressed_recipients, max_request_size)
                .ok()
                .and_then(|b| {
                    canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok()
                })
                .unwrap_or_default();
        let recipient_protos: Vec<Vec<u8>> = decompressed_recipients
            .recipients
            .iter()
            .map(|r| r.encode_to_vec())
            .collect();
        let trees: Vec<Vec<RecipientsTree>> = decompressed_recipients
            .recipients
            .into_iter()
            .map(|r| r.recipients_tree)
            .collect();
        for tree in trees.iter().flatten() {
            validate_tree(tree).map_err(|msg| bad(&msg))?;
        }
        // [CANTON-NOTE: SEMANTICS] An envelope goes to every member named anywhere in a tree (`Recipients.allRecipients`), while each
        // recipient receives the filtered tree hierarchy computed by `RecipientsTree.forMember`.
        let recipients: Vec<Vec<Vec<String>>> = trees
            .iter()
            .map(|trees| {
                trees
                    .iter()
                    .map(|tree| {
                        let mut out = Vec::new();
                        flatten_tree_members(tree, &mut out);
                        out
                    })
                    .collect()
            })
            .collect();
        let mut budget = max_request_size;
        let mut envelopes: Vec<EnvelopeWithoutRecipients> = Vec::new();
        for compressed in &batch.compressed_envelopes {
            match sw::decompress_within(compressed, budget) {
                Ok(bytes) => {
                    budget -= bytes.len();
                    if let Ok(envelope) = EnvelopeWithoutRecipients::decode(bytes.as_slice()) {
                        envelopes.push(envelope);
                    }
                }
                Err(sw::DecompressError::TooLarge) => {
                    return Err(malformed(
                        &id,
                        &sender,
                        &format!(
                            "Batch contains envelope with max bytes exceeded. The limit is {max_request_size} bytes."
                        ),
                    ));
                }
                Err(sw::DecompressError::Invalid) => {}
            }
        }
        if envelopes.len() != recipients.len()
            || envelopes.len() != batch.compressed_envelopes.len()
        {
            return Err(bad("the envelopes and their recipients do not match"));
        }
        Ok(Self {
            content,
            signatures: signed.signatures,
            sender,
            message_id: id,
            max_sequencing_time: request.max_sequencing_time,
            aggregation_rule: request.aggregation_rule,
            submitted_cost: request.submission_cost.map(|c| c.cost.max(0) as u64),
            recipient_protos,
            trees,
            recipients,
            envelopes,
        })
    }

    /// Every address the batch names (members and groups).
    pub(crate) fn addresses(&self) -> BTreeSet<&str> {
        self.recipients
            .iter()
            .flatten()
            .flatten()
            .map(String::as_str)
            .collect()
    }

    pub(crate) fn addresses_mediator(&self) -> bool {
        self.addresses().iter().any(|a| a.starts_with("MGR::"))
    }

    pub(crate) fn sends_to_all(&self) -> bool {
        self.addresses().contains(tw::ALL_MEMBERS)
    }
}

fn validate_tree(tree: &RecipientsTree) -> Result<(), String> {
    if tree.recipients.is_empty() {
        return Err(
            "ValueConversionError(RecipientsTree.recipients,RecipientsTree.recipients must be non-empty)"
                .to_string(),
        );
    }
    if tree.recipients.len() > MAX_RECIPIENTS_PER_TREE {
        return Err(format!(
            "InvariantViolation(Some(RecipientsTreeProto.recipients),repeated field has {} elements, exceeding the maximum of {MAX_RECIPIENTS_PER_TREE})",
            tree.recipients.len()
        ));
    }
    for child in &tree.children {
        validate_tree(child)?;
    }
    Ok(())
}

/// Evaluates Canton `RecipientsTree.forMember` over a list of trees: returns each outermost subtree whose root names `member`
/// (or a group resolving to `member`), keeping descendant levels intact, or descends into children otherwise.
pub(crate) fn trees_for_member(
    trees: &[RecipientsTree],
    member: &str,
    resolve: &dyn Fn(&str) -> Vec<String>,
) -> Vec<RecipientsTree> {
    let mut out = Vec::new();
    for tree in trees {
        if tree
            .recipients
            .iter()
            .any(|a| resolve(a).iter().any(|x| x == member))
        {
            out.push(tree.clone());
        } else {
            out.extend(trees_for_member(&tree.children, member, resolve));
        }
    }
    out
}

pub(crate) fn flatten_tree_members(tree: &RecipientsTree, out: &mut Vec<String>) {
    for r in &tree.recipients {
        if !out.contains(r) {
            out.push(r.clone());
        }
    }
    for child in &tree.children {
        flatten_tree_members(child, out);
    }
}

/// `INVALID_ARGUMENT`: the request is malformed (the official sequencer's `SEQUENCER_SUBMISSION_REQUEST_MALFORMED` alarm).
pub(crate) fn malformed(id: &str, sender: &str, detail: &str) -> Status {
    Status::invalid_argument(format!(
        "SEQUENCER_SUBMISSION_REQUEST_MALFORMED(5,0): Send request [{id}] from sender [{sender}] is malformed. Discarding request. {detail}"
    ))
}

/// `FAILED_PRECONDITION`: the sequencer refuses the request (`SEQUENCER_SUBMISSION_REQUEST_REFUSED`).
pub(crate) fn refused(id: &str, sender: &str, why: &str) -> Status {
    Status::failed_precondition(format!(
        "SEQUENCER_SUBMISSION_REQUEST_REFUSED(9,0): Request '{id}' from '{sender}' refused: {why}"
    ))
}

/// The submission request inside a signed one, if the bytes are one.
fn request_of(signed_request: &[u8]) -> Option<SubmissionRequest> {
    let (data, version) = tw::unversioned(signed_request)?;
    if version != sw::SIGNED_CONTENT_VERSION {
        return None;
    }
    let signed = SignedContent::decode(data.as_slice()).ok()?;
    let (request_bytes, request_version) = tw::unversioned(&signed.content?)?;
    if request_version != sw::SUBMISSION_REQUEST_VERSION {
        return None;
    }
    SubmissionRequest::decode(request_bytes.as_slice()).ok()
}

/// Reads who sent a signed submission and the id the sender gave it (`SubmissionRequest.sender`, `.message_id`): what an ordering request of the BFT orderer
/// carries (`BftBlockOrderer.send`: the payload is `signedSubmissionRequest.toByteString`). `None` if the bytes are not a signed submission.
pub fn read_submission(signed_request: &[u8]) -> Option<(String, String)> {
    let request = request_of(signed_request)?;
    Some((request.sender, request.message_id))
}

/// The priority `BlockReorderer` gives a signed submission in its block (`SubmissionRequestType.submissionRequestType`: the sender and the kinds of recipients decide):
/// verdict 0, confirmation response 1, confirmation request 2, commitment 3, topology transaction 4, time proof 5, top-up 6; a type the official nodes do not expect is 0.
/// `None` if the bytes are not a signed submission.
pub fn submission_priority(signed_request: &[u8]) -> Option<u8> {
    let request = request_of(signed_request)?;
    let batch = request.batch?;
    let recipients = sw::decompress(&batch.compressed_recipients)
        .and_then(|b| canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok())?;
    let mut all = Vec::new();
    for r in &recipients.recipients {
        for tree in &r.recipients_tree {
            flatten_tree_members(tree, &mut all);
        }
    }
    let (mut participants, mut mediators, mut sequencers, mut broadcast) =
        (false, false, false, false);
    for a in &all {
        if a.starts_with("PAR::") {
            participants = true;
        } else if a.starts_with("MED::") || a.starts_with("MGR::") {
            mediators = true;
        } else if a.starts_with("SEQ::") || a.starts_with("SOS") {
            sequencers = true;
        } else if a.starts_with("ALL") {
            broadcast = true;
        }
    }
    let sender = &request.sender;
    let (par, med, seq) = (
        sender.starts_with("PAR::"),
        sender.starts_with("MED::"),
        sender.starts_with("SEQ::"),
    );
    Some(
        match (
            par,
            med,
            seq,
            participants,
            mediators,
            sequencers,
            broadcast,
        ) {
            (true, _, _, false, true, false, false) => 1,
            (true, _, _, true, true, false, false) => 2,
            (_, true, _, true, false, false, false) => 0,
            (true, _, _, true, false, false, false) => 3,
            (_, _, true, true, false, true, false)
            | (_, _, true, false, true, true, false)
            | (_, _, true, false, false, true, false) => 6,
            (_, _, true, false, true, false, false) => 5,
            (_, _, _, false, false, false, true) => 4,
            (_, _, _, false, false, false, false) => 5,
            _ => 0,
        },
    )
}

/// Returns `true` when `signed_request` may change the ordering topology (`OutputModule.DefaultRequestInspector.mayChangeOrderingTopology`).
///
/// [CANTON-NOTE: SEMANTICS] A request is checked for an `AllMembersOfSynchronizer` (`ALL`) recipient; when `stricter` is true
/// (`stricterDetectionOfRequestsPotentiallyChangingOrderingTopology`), only broadcasts containing `OwnerToKeyMapping` for a sequencer
/// (`SEQ::...`), `SequencerSynchronizerState`, `DynamicSequencingParametersState`, or `SynchronizerParametersState` count.
pub fn may_change_ordering_topology(signed_request: &[u8], stricter: bool) -> bool {
    use canton_participant::topology_state::{broadcast_transactions, decode};
    use canton_proto::com::digitalasset::canton::protocol::v31::topology_mapping::Mapping;

    let Some(batch) = request_of(signed_request).and_then(|r| r.batch) else {
        return false;
    };
    fn has_all(tree: &RecipientsTree) -> bool {
        tree.recipients.iter().any(|r| r == tw::ALL_MEMBERS) || tree.children.iter().any(has_all)
    }
    let sends_to_all = sw::decompress(&batch.compressed_recipients)
        .and_then(|b| canton_proto::depth::decode::<DecompressedRecipients>(b.as_slice()).ok())
        .is_some_and(|d| {
            d.recipients
                .iter()
                .any(|r| r.recipients_tree.iter().any(has_all))
        });
    if !sends_to_all {
        return false;
    }
    if !stricter {
        return true;
    }
    for compressed in &batch.compressed_envelopes {
        let Some(raw_env) = sw::decompress(compressed) else {
            continue;
        };
        let Ok(env) = EnvelopeWithoutRecipients::decode(raw_env.as_slice()) else {
            continue;
        };
        let Some(txs) = broadcast_transactions(&env.content) else {
            continue;
        };
        let numbered: Vec<(i64, Vec<u8>)> = txs
            .into_iter()
            .enumerate()
            .map(|(i, s)| (i as i64, s))
            .collect();
        let Ok(entries) = decode(&numbered) else {
            continue;
        };
        for entry in entries {
            let Some(m) = entry.tx.mapping.and_then(|tm| tm.mapping) else {
                continue;
            };
            match m {
                Mapping::OwnerToKeyMapping(o) if o.member.starts_with("SEQ::") => return true,
                Mapping::SequencerSynchronizerState(_)
                | Mapping::SequencingDynamicParametersState(_)
                | Mapping::SynchronizerParametersState(_) => return true,
                _ => {}
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trees_for_member_keeps_ancestor_subtree_and_prunes_disjoint_ancestors() {
        let subview = RecipientsTree {
            recipients: vec!["PAR::p2::1220bb".into()],
            children: Vec::new(),
        };
        let root = RecipientsTree {
            recipients: vec!["PAR::p1::1220aa".into()],
            children: vec![subview.clone()],
        };
        let resolve = |a: &str| vec![a.to_string()];
        let for_p1 = trees_for_member(std::slice::from_ref(&root), "PAR::p1::1220aa", &resolve);
        assert_eq!(for_p1, vec![root]);
        let for_p2 = trees_for_member(&for_p1, "PAR::p2::1220bb", &resolve);
        assert_eq!(for_p2, vec![subview]);
    }
}
