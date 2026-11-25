//! A participant that **submits** an unassignment or an assignment (G7 B1, S-NET-040 parts 4 and 6): the request the official participant builds in
//! `UnassignmentProcessingSteps.createSubmission`, from a contract this participant has.
//!
//! [CANTON-NOTE: SEMANTICS] Read from `UnassignmentProcessingSteps`, `UnassignmentRequest` and `ReassignmentSubmitterMetadata`:
//! - The tree is `UnassignmentCommonData` (source synchronizer, stakeholders and signatories of the contract, the reassigning participants,
//!   a fresh uuid, the source mediator group, the submitter metadata) and `UnassignmentView` (target synchronizer, the target's time,
//!   the contract with its counter **incremented**). Salts are fresh.
//! - The submitting participant signs the tree's root hash; the batch is the mediator message (the tree with the view blinded) to the
//!   mediator group alone, the encrypted view (`view_type` `Unassignment`, the full tree) to every recipient participant, and a
//!   `RootHashMessage` (`view_type` `Unassignment`, empty payload) to {mediator group, participant} for each recipient.
//! - The stakeholders of a contract are its signatories and its other stakeholders (`FatContractInstance`); the validation package of the
//!   source and the target is the template's package.
//!
//! [CANTON-NOTE: LIMITATION] One contract per request; the reassigning participants and the recipients are given by the caller (the
//! participants hosting a stakeholder on both synchronizers); the submission topology time is the source sequencer's time when built.
use crate::confirmation_wire::{
    mediator_group, root_hash_message_of_type, ENVELOPE_CONTENT_VERSION,
};
use crate::merkle_wire::Tree;
use crate::reassignment_wire as rw;
use crate::submit::{Peer, Randomness};
use crate::topology_wire::{versioned, ParticipantIdentity};
use crate::view_message as vm;
use canton_proto::com::digitalasset::canton::protocol::v30::ViewType;
use canton_proto::com::digitalasset::canton::protocol::v32::{
    envelope_content::SomeEnvelopeContent, EnvelopeContent,
};
use canton_proto::com::digitalasset::daml::lf::transaction::{FatContractInstance, Versioned};
use prost::Message;

/// What a contract instance says about who must see and who must authorize its reassignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractParties {
    pub contract_id: String,
    pub package_id: String,
    pub signatories: Vec<String>,
    pub stakeholders: Vec<String>,
}

/// Reads the parties and the template package of a serialized contract instance (`ContractInstance.encoded`).
pub fn contract_parties(instance: &[u8]) -> Result<ContractParties, String> {
    let versioned = Versioned::decode(instance).map_err(|e| e.to_string())?;
    let fci =
        FatContractInstance::decode(versioned.payload.as_slice()).map_err(|e| e.to_string())?;
    let mut signatories = fci.non_maintainer_signatories.clone();
    if let Some(k) = &fci.contract_key_with_maintainers {
        signatories.extend(k.maintainers.iter().cloned());
    }
    signatories.sort();
    signatories.dedup();
    let mut stakeholders = signatories.clone();
    stakeholders.extend(fci.non_signatory_stakeholders.iter().cloned());
    stakeholders.sort();
    stakeholders.dedup();
    Ok(ContractParties {
        contract_id: hex::encode(&fci.contract_id),
        package_id: fci.template_id.map(|t| t.package_id).unwrap_or_default(),
        signatories,
        stakeholders,
    })
}

/// An unassignment to submit.
pub struct Unassignment<'a> {
    /// The source and target physical synchronizer ids.
    pub source: &'a str,
    pub target: &'a str,
    /// The target synchronizer's time the request is based on (microseconds).
    pub target_time_micros: i64,
    /// The serialized contract instance and its **current** counter (the request carries the next one).
    pub instance: &'a [u8],
    pub current_counter: i64,
    pub submitter: &'a str,
    pub command_id: &'a str,
    pub user_id: &'a str,
    /// The participants that host a stakeholder on both synchronizers (uids, this one included).
    pub reassigning_participant_uids: &'a [String],
    /// The participants that get the view (with their encryption keys; this one included).
    pub recipients: &'a [Peer],
    /// The source sequencer's time, for the root hash messages' submission topology time.
    pub now_micros: i64,
}

/// A built unassignment: the batch to send and the tree's root hash.
pub struct Built {
    pub message_id: String,
    /// Each envelope with the recipient groups it is addressed to (one group for the mediator message and the view, one group per
    /// recipient participant for the root hash message).
    pub envelopes: Vec<(Vec<Vec<String>>, Vec<u8>)>,
    pub root_hash: Vec<u8>,
    pub uuid: String,
}

impl Built {
    /// The submission request of this batch from `sender`, sequenced before `max_sequencing_time_micros`, unsigned.
    pub fn submission_request(&self, sender: &str, max_sequencing_time_micros: i64) -> Vec<u8> {
        let trees: Vec<(
            Vec<canton_proto::com::digitalasset::canton::protocol::v30::RecipientsTree>,
            Vec<u8>,
        )> = self
            .envelopes
            .iter()
            .map(|(groups, content)| {
                (
                    groups
                        .iter()
                        .map(|g| crate::sequencing_wire::path_tree(std::slice::from_ref(g)))
                        .collect(),
                    content.clone(),
                )
            })
            .collect();
        crate::sequencing_wire::submission_request_with_trees(
            sender,
            &self.message_id,
            &trees,
            max_sequencing_time_micros,
        )
    }
}

fn uuid_v4(bytes: &[u8; 32]) -> String {
    let mut b: [u8; 16] = bytes[..16]
        .try_into()
        .expect("32-byte input always has a 16-byte prefix");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Builds the batch of an unassignment request (see the module's description).
pub fn unassignment(
    identity: &ParticipantIdentity,
    u: &Unassignment,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    let parties = contract_parties(u.instance)?;
    let uid = identity.uid();
    let uuid = uuid_v4(&random.fresh("uuid"));
    let stakeholders: Vec<&str> = parties.stakeholders.iter().map(String::as_str).collect();
    let signatories: Vec<&str> = parties.signatories.iter().map(String::as_str).collect();
    let reassigning: Vec<&str> = u
        .reassigning_participant_uids
        .iter()
        .map(String::as_str)
        .collect();
    let common = rw::unassignment_common_data(
        u.source,
        &rw::CommonParts {
            stakeholders: &stakeholders,
            signatories: &signatories,
            reassigning_participant_uids: &reassigning,
            uuid: &uuid,
            mediator_group: 0,
            submitter: rw::Submitter {
                submitter: u.submitter,
                submitting_participant_uid: &uid,
                command_id: u.command_id,
                submission_id: None,
                user_id: u.user_id,
                workflow_id: None,
            },
        },
        &random.fresh("common-salt"),
    );
    let view = rw::unassignment_view(
        u.target,
        u.target_time_micros,
        &[rw::Reassigned {
            contract_id: &parties.contract_id,
            encoded: u.instance,
            source_validation_package_id: &parties.package_id,
            target_validation_package_id: &parties.package_id,
            counter: u.current_counter + 1,
        }],
        &random.fresh("view-salt"),
    );
    let tree = rw::view_tree(&common, &Tree::leaf(&view));
    Ok(batch(
        identity,
        rw::Kind::Unassignment,
        &tree,
        u.recipients,
        u.source,
        u.now_micros,
        uuid,
        random,
    ))
}

/// The batch of a reassignment request over `tree`, sequenced on `synchronizer` (the source of an unassignment, the target of an
/// assignment): the mediator message to the mediator group, the encrypted view to the recipients, and one root hash message envelope to
/// every recipient, each in its own group with the mediator group.
#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn batch(
    identity: &ParticipantIdentity,
    kind: rw::Kind,
    tree: &rw::ViewTree,
    recipients_of_view: &[Peer],
    synchronizer: &str,
    now_micros: i64,
    uuid: String,
    random: &mut dyn Randomness,
) -> Built {
    let signature = identity.signing_key.sign_bytes(&tree.root_hash);
    let mediator = mediator_group(0);
    let (view_type, content, prefix) = match kind {
        rw::Kind::Unassignment => (
            ViewType::Unassignment,
            SomeEnvelopeContent::UnassignmentMediatorMessage(rw::unassignment_mediator_message(
                tree,
                signature.clone(),
            )),
            "unassign",
        ),
        rw::Kind::Assignment => (
            ViewType::Assignment,
            SomeEnvelopeContent::AssignmentMediatorMessage(rw::assignment_mediator_message(
                tree,
                signature.clone(),
            )),
            "assign",
        ),
    };
    let mediator_message = versioned(
        EnvelopeContent {
            some_envelope_content: Some(content),
        }
        .encode_to_vec(),
        ENVELOPE_CONTENT_VERSION,
    );
    let recipients: Vec<vm::Recipient> = recipients_of_view
        .iter()
        .map(|peer| vm::Recipient {
            encryption_spki: &peer.encryption_spki,
            fingerprint: &peer.fingerprint,
            ecies_iv: random.fresh("ecies-iv")[..16]
                .try_into()
                .expect("SeededRandom::fresh always yields 32 bytes"),
            ecies_ephemeral_scalar: random.fresh("ecies-eph"),
        })
        .collect();
    let randomness: [u8; 16] = random.fresh("randomness")[..16]
        .try_into()
        .expect("SeededRandom::fresh always yields 32 bytes");
    let gcm_iv: [u8; 12] = random.fresh("gcm-iv")[..12]
        .try_into()
        .expect("SeededRandom::fresh always yields 32 bytes");
    let encrypted = vm::encrypted_view_message_of_type(
        view_type,
        &tree.bytes(),
        &tree.view_hash,
        &randomness,
        &gcm_iv,
        &recipients,
        synchronizer,
        Some(signature),
    );
    let root_hash_message =
        root_hash_message_of_type(view_type, &tree.root_hash, synchronizer, now_micros);
    let mut envelopes = vec![(vec![vec![mediator.clone()]], mediator_message)];
    envelopes.push((
        vec![recipients_of_view
            .iter()
            .map(|p| p.member.clone())
            .collect()],
        encrypted,
    ));
    // [CANTON-NOTE: SEMANTICS] one root hash message envelope, one recipient group `{mediator group, participant}` per recipient
    // (`UnassignmentProcessingSteps.scala:337`, `AssignmentProcessingSteps.scala:245`: `Recipients.recipientGroups`; U-57 review R1-F1: it
    // used to be one envelope per recipient, as the transaction path was before U-57)
    envelopes.push((
        recipients_of_view
            .iter()
            .map(|peer| vec![mediator.clone(), peer.member.clone()])
            .collect(),
        root_hash_message,
    ));
    Built {
        message_id: format!(
            "{prefix}-{}",
            hex::encode(&random.fresh("message-id")[..12])
        ),
        envelopes,
        root_hash: tree.root_hash.clone(),
        uuid,
    }
}

/// An assignment to submit: the completion of an unassignment this participant knows.
pub struct Assignment<'a> {
    pub source: &'a str,
    pub target: &'a str,
    /// The unassignment's sequencing time (its request id, the record time of the unassigned event).
    pub unassignment_time_micros: i64,
    /// The reassignment id (hex string form) of the unassignment.
    pub reassignment_id: &'a str,
    /// The serialized contract instance and the counter the unassignment carried (the assignment keeps it).
    pub instance: &'a [u8],
    pub counter: i64,
    pub submitter: &'a str,
    pub command_id: &'a str,
    pub user_id: &'a str,
    pub reassigning_participant_uids: &'a [String],
    pub recipients: &'a [Peer],
    /// The target sequencer's time, for the root hash messages' submission topology time.
    pub now_micros: i64,
}

/// Builds the batch of an assignment request, sequenced on the target synchronizer.
///
/// [CANTON-NOTE: SEMANTICS] `AssignmentProcessingSteps.createSubmission`: `AssignmentCommonData` names both synchronizers and the
/// unassignment's time, `AssignmentView` the reassignment id and the contracts with the unassignment's counter; the rest is as for an
/// unassignment, on the target synchronizer, with `view_type` `Assignment`.
pub fn assignment(
    identity: &ParticipantIdentity,
    a: &Assignment,
    random: &mut dyn Randomness,
) -> Result<Built, String> {
    let parties = contract_parties(a.instance)?;
    let uid = identity.uid();
    let uuid = uuid_v4(&random.fresh("uuid"));
    let stakeholders: Vec<&str> = parties.stakeholders.iter().map(String::as_str).collect();
    let signatories: Vec<&str> = parties.signatories.iter().map(String::as_str).collect();
    let reassigning: Vec<&str> = a
        .reassigning_participant_uids
        .iter()
        .map(String::as_str)
        .collect();
    let common = rw::assignment_common_data(
        a.source,
        a.target,
        a.unassignment_time_micros,
        &rw::CommonParts {
            stakeholders: &stakeholders,
            signatories: &signatories,
            reassigning_participant_uids: &reassigning,
            uuid: &uuid,
            mediator_group: 0,
            submitter: rw::Submitter {
                submitter: a.submitter,
                submitting_participant_uid: &uid,
                command_id: a.command_id,
                submission_id: None,
                user_id: a.user_id,
                workflow_id: None,
            },
        },
        &random.fresh("common-salt"),
    );
    let view = rw::assignment_view(
        a.reassignment_id,
        &[rw::Reassigned {
            contract_id: &parties.contract_id,
            encoded: a.instance,
            source_validation_package_id: &parties.package_id,
            target_validation_package_id: &parties.package_id,
            counter: a.counter,
        }],
        &random.fresh("view-salt"),
    );
    let tree = rw::view_tree(&common, &Tree::leaf(&view));
    Ok(batch(
        identity,
        rw::Kind::Assignment,
        &tree,
        a.recipients,
        a.target,
        a.now_micros,
        uuid,
        random,
    ))
}
