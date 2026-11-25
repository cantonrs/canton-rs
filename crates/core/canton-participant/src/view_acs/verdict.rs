use super::{Effects, RemoteEvent};
use crate::topology_wire::unversioned;
use crate::view_receive::RevealedView;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    typed_signed_protocol_message_content::SomeSignedProtocolMessage, verdict::SomeVerdict,
    ConfirmationResultMessage, TypedSignedProtocolMessageContent,
};
use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
use prost::Message;

/// The contract id (hex) and template of a serialized contract instance.
pub(crate) fn contract_of(bytes: &[u8]) -> Option<(String, String)> {
    let versioned = Versioned::decode(bytes).ok()?;
    let fci = FatContractInstance::decode(versioned.payload.as_slice()).ok()?;
    let template = fci.template_id?;
    Some((
        hex::encode(fci.contract_id),
        format!(
            "{}:{}",
            template.module_name.join("."),
            template.name.join(".")
        ),
    ))
}

/// What a validated view does to the contract set: the input contracts it consumes and the contracts created in its core.
pub fn effects_of(view: &RevealedView) -> Option<Effects> {
    use canton_proto::com::digitalasset::canton::protocol::v31::action_description::Description;
    let is_root_create = matches!(
        view.participant_data
            .action_description
            .as_ref()
            .and_then(|a| a.description.as_ref()),
        Some(Description::Create(_))
    );
    let mut effects = Effects::default();
    for input in &view.participant_data.core_inputs {
        let id = contract_of(&input.contract)?.0;
        if input.consumed {
            effects.consumes.push(id);
        }
    }
    for created in &view.participant_data.created_core {
        // [CANTON-NOTE: SEMANTICS] A contract the view creates and consumes again in its core is transient
        // (`ExtractUsedAndCreated.transientContracts`): it never becomes active.
        if created.consumed_in_core {
            continue;
        }
        let info = contract_of(&created.contract)?;
        if is_root_create {
            effects.remote_events.push(RemoteEvent::Create {
                depth: 0,
                contract_id: info.0.clone(),
                instance: created.contract.clone(),
            });
        }
        effects.creates.push(info);
        effects.instances.push(created.contract.clone());
    }
    // [CANTON-NOTE: SEMANTICS] A contract created in a descendant subview and consumed by this view's
    // core is listed in `created_in_subview_archived_in_core`; adding it to `effects.consumes` lets
    // `apply_resolve_effects` cancel the subview creation so transient cross-view contracts never
    // become active.
    for id in &view.participant_data.created_in_subview_archived_in_core {
        effects.consumes.push(id.clone());
    }
    if view.participant_data.rolled_back {
        return Some(Effects::default());
    }
    Some(effects)
}

/// Who refused a request, if anybody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictKind {
    Approve,
    /// A participant refused it (some participant's `LocalReject` or `LocalMalformed`).
    ParticipantReject,
    /// The mediator refused it itself: a confirming party did not answer in time (`MEDIATOR_SAYS_TX_TIMED_OUT`), the request was
    /// malformed, or a response did not fit.
    MediatorReject {
        malformed: bool,
    },
}

/// A mediator's verdict on a request, as a participant receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub request_id: i64,
    pub root_hash: Vec<u8>,
    pub approved: bool,
    pub kind: VerdictKind,
    /// Why it was rejected (the `Status` message; empty for an approval): the mediator's for a `MediatorReject`, the first refusing
    /// participant's `LocalReject` for a `ParticipantReject`.
    pub reason: String,
    /// The gRPC code of that `Status` (0 for an approval).
    pub reason_code: i32,
    /// What the refusing participant's `RejectionReason` adds to its error, as a JSON object (empty for an approval and a mediator's
    /// refusal): `parties` (the confirming parties it answered for), `reported_by` (its participant id) and `metadata` (the `ErrorInfo`
    /// of its error). The official participant puts `confirming_parties` and `reported_by_participant_id` into the error it reports
    /// (`Verdict.ParticipantReject.keyErrorDetails`).
    pub reject_context: String,
    pub physical_synchronizer_id: String,
}

/// The `metadata` of the `google.rpc.ErrorInfo` among the details of an error status (what the error's context was).
fn error_info_metadata(details: &[prost_types::Any]) -> std::collections::BTreeMap<String, String> {
    fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
        let (mut value, mut shift) = (0u64, 0);
        while let Some(b) = bytes.get(*at) {
            *at += 1;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
        None
    }
    /// The length-delimited fields `(number, bytes)` of a protobuf message.
    fn fields(bytes: &[u8]) -> Vec<(u64, &[u8])> {
        let (mut out, mut at) = (Vec::new(), 0);
        while at < bytes.len() {
            let Some(key) = varint(bytes, &mut at) else {
                break;
            };
            match key & 7 {
                0 => {
                    if varint(bytes, &mut at).is_none() {
                        break;
                    }
                }
                2 => {
                    let Some(len) = varint(bytes, &mut at) else {
                        break;
                    };
                    let end = at + len as usize;
                    let Some(body) = bytes.get(at..end) else {
                        break;
                    };
                    out.push((key >> 3, body));
                    at = end;
                }
                _ => break,
            }
        }
        out
    }
    let mut metadata = std::collections::BTreeMap::new();
    for any in details {
        if !any.type_url.ends_with("google.rpc.ErrorInfo") {
            continue;
        }
        for (number, entry) in fields(&any.value) {
            if number != 3 {
                continue; // field 3 of ErrorInfo: the map<string, string> metadata, one entry per message
            }
            let (mut key, mut value) = (String::new(), String::new());
            for (n, text) in fields(entry) {
                match n {
                    1 => key = String::from_utf8_lossy(text).into_owned(),
                    2 => value = String::from_utf8_lossy(text).into_owned(),
                    _ => {}
                }
            }
            metadata.insert(key, value);
        }
    }
    metadata
}

/// Decodes the content of an envelope that holds a signed `ConfirmationResultMessage`.
///
/// [CANTON-NOTE: SEMANTICS] The mediator sends the verdict as a **signed protocol message**: the envelope's content is a
/// `TypedSignedProtocolMessageContent` (versioned, 30) whose `confirmation_result` holds the versioned `ConfirmationResultMessage`;
/// the envelope's signature is the mediator's, over the multihash of `HashPurpose.SignedProtocolMessageSignature` (38) of that
/// content. Returns the verdict and the hash the signature covers.
pub fn decode_verdict(envelope_content: &[u8]) -> Option<(Verdict, Vec<u8>)> {
    let (typed_bytes, _) = unversioned(envelope_content)?;
    let typed = TypedSignedProtocolMessageContent::decode(typed_bytes.as_slice()).ok()?;
    let Some(SomeSignedProtocolMessage::ConfirmationResult(result_bytes)) =
        typed.some_signed_protocol_message
    else {
        return None;
    };
    let (data, _) = unversioned(&result_bytes)?;
    let message = ConfirmationResultMessage::decode(data.as_slice()).ok()?;
    let mut reject_context = String::new();
    let (kind, reason, reason_code) = match message.verdict.and_then(|v| v.some_verdict) {
        Some(SomeVerdict::Approve(_)) => (VerdictKind::Approve, String::new(), 0),
        Some(SomeVerdict::MediatorReject(m)) => {
            let status = m.reason.unwrap_or_default();
            (
                VerdictKind::MediatorReject {
                    malformed: m.is_malformed,
                },
                status.message,
                status.code,
            )
        }
        // [CANTON-NOTE: SEMANTICS] A participant's refusal travels in the verdict: each `RejectionReason` holds the refusing participant's
        // `LocalVerdict`, whose `reason` is the error it reported (e.g. `LOCAL_VERDICT_INACTIVE_CONTRACTS(11,…): Rejected transaction is
        // referring to inactive contracts `). The submitting participant reports that error for the command (measured on the official
        // participant: p1's completion for a command p2 vetoed carries p2's error, S-G11-001 / U-31).
        Some(SomeVerdict::ParticipantReject(p)) => {
            let first = p.reasons.into_iter().find(|r| r.reject.is_some());
            let status = first
                .as_ref()
                .and_then(|r| r.reject.as_ref().and_then(|v| v.reason.clone()))
                .unwrap_or_default();
            if let Some(reason) = &first {
                reject_context = serde_json::json!({
                    "parties": reason.parties,
                    "reported_by": reason.participant_id,
                    "metadata": error_info_metadata(&status.details),
                })
                .to_string();
            }
            (VerdictKind::ParticipantReject, status.message, status.code)
        }
        None => (VerdictKind::ParticipantReject, String::new(), 0),
    };
    let approved = kind == VerdictKind::Approve;
    let mut signed_hash = vec![0x12, 0x20];
    signed_hash.extend_from_slice(&canton_algo::hash::sha256_with_purpose(
        38,
        envelope_content,
    ));
    Some((
        Verdict {
            request_id: message.request_id,
            root_hash: message.root_hash,
            approved,
            kind,
            reason,
            reason_code,
            reject_context,
            physical_synchronizer_id: message.physical_synchronizer_id,
        },
        signed_hash,
    ))
}

/// [`mediator_signed`] at the topology snapshot of `at_micros` on the synchronizer `physical`: a session key that one of
/// `mediator_keys` delegated to signs as well.
pub fn mediator_signed_at(
    signatures: &[Signature],
    signed_hash: &[u8],
    mediator_keys: &[canton_algo::signing::PublicKey],
    physical: &str,
    at_micros: i64,
) -> bool {
    signatures.iter().any(|s| {
        crate::sequenced_event_validation::verifies_at(
            mediator_keys,
            s,
            signed_hash,
            physical,
            at_micros,
        )
    })
}

/// Whether one of `signatures` is the mediator's over `signed_hash` (made by one of `mediator_keys`).
pub fn mediator_signed(
    signatures: &[Signature],
    signed_hash: &[u8],
    mediator_keys: &[canton_algo::signing::PublicKey],
) -> bool {
    signatures
        .iter()
        .any(|s| crate::sequenced_event_validation::verifies(mediator_keys, s, signed_hash))
}
