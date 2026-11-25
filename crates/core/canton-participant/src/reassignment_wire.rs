//! The Merkle nodes of the Canton reassignment protocol (unassignment and assignment), serialized and hashed the way the
//! node does (G7 B1, S-NET-040).
//!
//! An unassignment (on the source synchronizer) and an assignment (on the target synchronizer) are each sent as a
//! `ReassignmentViewTree` with exactly two children: the common data (for the mediator and the participants) and the view
//! (for the participants only). `tests/reassignment_wire.rs` compares every node with the one the node's Scala classes build
//! (`scripts/verify-reassignment-wire.sh`).
//!
//! [CANTON-NOTE: SEMANTICS]
//! - The leaves are hashed like the transaction protocol's (see `merkle_wire`): `HashPurpose` 24 `UnassignmentCommonData`,
//!   25 `UnassignmentView`, 26 `AssignmentCommonData`, 27 `AssignmentView`, over the salt and the versioned bytes.
//! - The common data are v30 messages; the views are **v31** messages under protocol version 37 (`v31.ActiveContract` carries
//!   the source and target validation package ids; v30 derived them from the template id).
//! - The tree's root hash is an inner node (`HashPurpose` 3) over the common data's hash and the view's hash. The tree's
//!   proto carries the common data as plain versioned **bytes** (it can never be blinded) and the view as a `BlindableNode`.
//! - The mediator gets the same tree with the view blinded (`UnassignmentMediatorMessage`/`AssignmentMediatorMessage`,
//!   unversioned tree proto plus the submitting participant's signature over the root hash).
//! - `ReassignmentId` (`HashPurpose` 57, SHA-256) covers the *logical* source and target synchronizer ids, the unassignment's
//!   sequencing time and every (contract id, reassignment counter) sorted by contract id; its string form is the hex of a
//!   version byte `00` followed by the multihash.
//! - The reassignment counter in an unassignment is already the incremented one (`counter + 1`); the assignment carries the
//!   same counter.
//!
//! [CANTON-NOTE: WHY] Scala writes `Set`s (stakeholders, reassigning participants) in its own iteration order; the receiver
//! hashes the bytes it received, so any order is accepted. Rust writes them sorted.
use crate::merkle_wire::{inner_hash, wire_salt, LeafNode, Tree};
use crate::topology_wire::versioned;
use canton_algo::hash::PurposeHash;
use canton_proto::com::digitalasset::canton::crypto::v30::Signature;
use canton_proto::com::digitalasset::canton::protocol::v30::{
    AssignmentCommonData, AssignmentMediatorMessage, ReassignmentId, ReassignmentSubmitterMetadata,
    ReassignmentViewTree, Stakeholders, UnassignmentCommonData, UnassignmentMediatorMessage,
};
use canton_proto::com::digitalasset::canton::protocol::v31::{
    ActiveContract, AssignmentView, UnassignmentView,
};
use prost::Message;

const PURPOSE_UNASSIGNMENT_COMMON_DATA: i32 = 24;
const PURPOSE_UNASSIGNMENT_VIEW: i32 = 25;
const PURPOSE_ASSIGNMENT_COMMON_DATA: i32 = 26;
const PURPOSE_ASSIGNMENT_VIEW: i32 = 27;
const PURPOSE_REASSIGNMENT_ID: i32 = 57;
/// The version of the common data messages and of the view tree.
pub const COMMON_DATA_VERSION: i32 = 30;
/// The version of the view messages under protocol version 37.
pub const VIEW_VERSION: i32 = 31;
/// The version byte of a `ReassignmentId.V0`.
const REASSIGNMENT_ID_V0: u8 = 0x00;

/// Who submitted the reassignment (`ReassignmentSubmitterMetadata`); absent optional fields are written as empty strings.
#[derive(Debug, Clone)]
pub struct Submitter<'a> {
    pub submitter: &'a str,
    pub submitting_participant_uid: &'a str,
    pub command_id: &'a str,
    pub submission_id: Option<&'a str>,
    pub user_id: &'a str,
    pub workflow_id: Option<&'a str>,
}

impl Submitter<'_> {
    pub fn proto(&self) -> ReassignmentSubmitterMetadata {
        ReassignmentSubmitterMetadata {
            submitter: self.submitter.to_string(),
            submitting_participant_uid: self.submitting_participant_uid.to_string(),
            command_id: self.command_id.to_string(),
            submission_id: self.submission_id.unwrap_or_default().to_string(),
            user_id: self.user_id.to_string(),
            workflow_id: self.workflow_id.unwrap_or_default().to_string(),
        }
    }
}

/// A contract being reassigned: its serialized instance (`ContractInstance.encoded`) and its new reassignment counter.
#[derive(Debug, Clone)]
pub struct Reassigned<'a> {
    pub contract_id: &'a str,
    pub encoded: &'a [u8],
    pub source_validation_package_id: &'a str,
    pub target_validation_package_id: &'a str,
    pub counter: i64,
}

impl Reassigned<'_> {
    fn proto(&self) -> ActiveContract {
        ActiveContract {
            contract: self.encoded.to_vec(),
            source_validation_package_id: self.source_validation_package_id.to_string(),
            target_validation_package_id: self.target_validation_package_id.to_string(),
            reassignment_counter: self.counter,
        }
    }
}

fn sorted(items: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    v.sort();
    v.dedup();
    v
}

fn stakeholders(all: &[&str], signatories: &[&str]) -> Stakeholders {
    Stakeholders {
        all: sorted(all),
        signatories: sorted(signatories),
    }
}

/// The parts both common data carry.
#[derive(Debug, Clone)]
pub struct CommonParts<'a> {
    pub stakeholders: &'a [&'a str],
    pub signatories: &'a [&'a str],
    pub reassigning_participant_uids: &'a [&'a str],
    pub uuid: &'a str,
    pub mediator_group: i32,
    pub submitter: Submitter<'a>,
}

/// `UnassignmentCommonData`: the source synchronizer and what the mediator of the source synchronizer needs.
pub fn unassignment_common_data(source_psid: &str, parts: &CommonParts, salt: &[u8]) -> LeafNode {
    let proto = UnassignmentCommonData {
        salt: Some(wire_salt(salt)),
        source_physical_synchronizer_id: source_psid.to_string(),
        stakeholders: Some(stakeholders(parts.stakeholders, parts.signatories)),
        reassigning_participant_uids: sorted(parts.reassigning_participant_uids),
        uuid: parts.uuid.to_string(),
        source_mediator_group: parts.mediator_group,
        submitter_metadata: Some(parts.submitter.proto()),
    };
    LeafNode::with_version(
        proto.encode_to_vec(),
        salt,
        PURPOSE_UNASSIGNMENT_COMMON_DATA,
        COMMON_DATA_VERSION,
    )
}

/// `UnassignmentView`: the target synchronizer, the target topology time the submitter used, and the contracts.
pub fn unassignment_view(
    target_psid: &str,
    target_timestamp_micros: i64,
    contracts: &[Reassigned],
    salt: &[u8],
) -> LeafNode {
    let proto = UnassignmentView {
        salt: Some(wire_salt(salt)),
        target_physical_synchronizer_id: target_psid.to_string(),
        target_timestamp: target_timestamp_micros,
        contracts: contracts.iter().map(Reassigned::proto).collect(),
    };
    LeafNode::with_version(
        proto.encode_to_vec(),
        salt,
        PURPOSE_UNASSIGNMENT_VIEW,
        VIEW_VERSION,
    )
}

/// `AssignmentCommonData`: both synchronizers, the unassignment's time and what the target mediator needs.
pub fn assignment_common_data(
    source_psid: &str,
    target_psid: &str,
    unassignment_ts_micros: i64,
    parts: &CommonParts,
    salt: &[u8],
) -> LeafNode {
    let proto = AssignmentCommonData {
        salt: Some(wire_salt(salt)),
        source_physical_synchronizer_id: source_psid.to_string(),
        target_physical_synchronizer_id: target_psid.to_string(),
        unassignment_ts: Some(prost_types::Timestamp {
            seconds: unassignment_ts_micros.div_euclid(1_000_000),
            nanos: (unassignment_ts_micros.rem_euclid(1_000_000) * 1000) as i32,
        }),
        stakeholders: Some(stakeholders(parts.stakeholders, parts.signatories)),
        uuid: parts.uuid.to_string(),
        target_mediator_group: parts.mediator_group,
        submitter_metadata: Some(parts.submitter.proto()),
        reassigning_participant_uids: sorted(parts.reassigning_participant_uids),
    };
    LeafNode::with_version(
        proto.encode_to_vec(),
        salt,
        PURPOSE_ASSIGNMENT_COMMON_DATA,
        COMMON_DATA_VERSION,
    )
}

/// `AssignmentView`: the reassignment id (hex string form) and the contracts.
pub fn assignment_view(reassignment_id: &str, contracts: &[Reassigned], salt: &[u8]) -> LeafNode {
    let proto = AssignmentView {
        salt: Some(wire_salt(salt)),
        contracts: contracts.iter().map(Reassigned::proto).collect(),
        reassignment_id: Some(ReassignmentId {
            id: reassignment_id.to_string(),
        }),
    };
    LeafNode::with_version(
        proto.encode_to_vec(),
        salt,
        PURPOSE_ASSIGNMENT_VIEW,
        VIEW_VERSION,
    )
}

/// A reassignment view tree: the common data and the view (revealed or blinded).
#[derive(Debug, Clone)]
pub struct ViewTree {
    pub proto: ReassignmentViewTree,
    pub root_hash: Vec<u8>,
    pub view_hash: Vec<u8>,
}

impl ViewTree {
    /// The versioned bytes (what `FullUnassignmentTree.toByteString` / `FullAssignmentTree.toByteString` give).
    pub fn bytes(&self) -> Vec<u8> {
        versioned(self.proto.encode_to_vec(), COMMON_DATA_VERSION)
    }

    /// The same tree with the view blinded: what the mediator receives.
    pub fn blinded_for_mediator(&self) -> ViewTree {
        let mut proto = self.proto.clone();
        proto.participant_data = Some(Tree::blinded(self.view_hash.clone()).node);
        ViewTree {
            proto,
            root_hash: self.root_hash.clone(),
            view_hash: self.view_hash.clone(),
        }
    }
}

/// Builds a `ReassignmentViewTree` over a common data leaf and a view.
pub fn view_tree(common: &LeafNode, view: &Tree) -> ViewTree {
    let common_hash = common.root_hash();
    ViewTree {
        proto: ReassignmentViewTree {
            common_data: common.bytes.clone(),
            participant_data: Some(view.node.clone()),
        },
        root_hash: inner_hash(&[&common_hash, &view.hash]),
        view_hash: view.hash.clone(),
    }
}

/// The mediator message of an unassignment: the blinded tree and the submitting participant's signature.
pub fn unassignment_mediator_message(
    tree: &ViewTree,
    signature: Signature,
) -> UnassignmentMediatorMessage {
    UnassignmentMediatorMessage {
        tree: Some(tree.blinded_for_mediator().proto),
        submitting_participant_signature: Some(signature),
    }
}

/// The mediator message of an assignment: the blinded tree and the submitting participant's signature.
pub fn assignment_mediator_message(
    tree: &ViewTree,
    signature: Signature,
) -> AssignmentMediatorMessage {
    AssignmentMediatorMessage {
        tree: Some(tree.blinded_for_mediator().proto),
        submitting_participant_signature: Some(signature),
    }
}

/// `ReassignmentId.V0` in its string form (hex of `00` + multihash): the logical synchronizer ids, the unassignment's
/// sequencing time (microseconds) and each contract's id and reassignment counter, sorted by contract id.
pub fn reassignment_id(
    source_synchronizer: &str,
    target_synchronizer: &str,
    unassignment_ts_micros: i64,
    contracts: &[(&str, i64)],
) -> String {
    let mut sorted: Vec<(&str, i64)> = contracts.to_vec();
    // [CANTON-NOTE: SEMANTICS] Scala sorts by `coid` (a `String`): UTF-16 order, the same as byte order for hex ids.
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut h = PurposeHash::new(PURPOSE_REASSIGNMENT_ID);
    h.add_string(source_synchronizer).expect("open");
    h.add_string(target_synchronizer).expect("open");
    h.add_long(unassignment_ts_micros).expect("open");
    for (cid, counter) in sorted {
        h.add_string(cid).expect("open");
        h.add_long(counter).expect("open");
    }
    let mut out = vec![REASSIGNMENT_ID_V0, 0x12, 0x20];
    out.extend_from_slice(&h.finish().expect("open"));
    hex::encode(out)
}

/// Which half of a reassignment a tree is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Unassignment,
    Assignment,
}

impl Kind {
    fn purposes(self) -> (i32, i32) {
        match self {
            Kind::Unassignment => (PURPOSE_UNASSIGNMENT_COMMON_DATA, PURPOSE_UNASSIGNMENT_VIEW),
            Kind::Assignment => (PURPOSE_ASSIGNMENT_COMMON_DATA, PURPOSE_ASSIGNMENT_VIEW),
        }
    }
}

/// What a received reassignment tree says to everyone who may read its common data (the mediator included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCommon {
    pub kind: Kind,
    /// The tree's root hash, recomputed from the bytes received.
    pub root_hash: Vec<u8>,
    pub stakeholders: Vec<String>,
    pub signatories: Vec<String>,
    pub submitter: String,
    pub submitting_participant_uid: String,
    pub reassigning_participant_uids: Vec<String>,
    /// The source mediator group of an unassignment, the target one of an assignment.
    pub mediator_group: i32,
    /// The physical synchronizer the request is sequenced on (the source of an unassignment, the target of an assignment).
    pub synchronizer: String,
    /// For `Kind::Assignment`, the source physical synchronizer id named in `AssignmentCommonData`.
    pub source_synchronizer: Option<String>,
    /// For `Kind::Assignment`, the unassignment sequencing timestamp named in `AssignmentCommonData` (microseconds).
    pub unassignment_ts: Option<i64>,
}

impl ReadCommon {
    /// `ReassignmentCommonData.confirmingParties`: the signatories and the submitting participant's admin party (named by the participant's
    /// uid).
    ///
    /// [CANTON-NOTE: SEMANTICS] `ReassignmentMediatorMessage.informeesAndConfirmationParamsByViewPosition`: one view at the root position,
    /// each confirming party with weight 1, the other stakeholders with weight 0, and a threshold of the number of confirming parties
    /// (all of them have to confirm).
    pub fn confirming_parties(&self) -> Vec<String> {
        let mut out = self.signatories.clone();
        out.push(self.submitting_participant_uid.clone());
        out.sort();
        out.dedup();
        out
    }

    /// The stakeholders that are not confirming parties (weight 0).
    pub fn non_confirming_parties(&self) -> Vec<String> {
        let confirming = self.confirming_parties();
        let mut out: Vec<String> = self
            .stakeholders
            .iter()
            .filter(|s| !confirming.contains(s))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

fn salt_of(salt: &Option<canton_proto::com::digitalasset::canton::crypto::v30::Salt>) -> Vec<u8> {
    salt.as_ref().map(|s| s.salt.clone()).unwrap_or_default()
}

fn leaf_hash(purpose: i32, salt: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut h = PurposeHash::new(purpose);
    h.add_byte_string(salt).expect("open");
    h.add_byte_string(bytes).expect("open");
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&h.finish().expect("open"));
    out
}

/// Reads a received `ReassignmentViewTree` of `kind`: its common data, and the root hash recomputed from the bytes as received (the view
/// either blinded - the mediator's copy - or revealed).
pub fn read_tree(kind: Kind, tree: &ReassignmentViewTree) -> Result<ReadCommon, String> {
    use canton_proto::com::digitalasset::canton::protocol::v30::blindable_node::BlindedOrNot;
    let (common_purpose, view_purpose) = kind.purposes();
    let (data, _) = crate::topology_wire::unversioned(&tree.common_data)
        .ok_or("the common data is not a versioned message")?;
    let read = match kind {
        Kind::Unassignment => {
            let c = UnassignmentCommonData::decode(data.as_slice()).map_err(|e| e.to_string())?;
            let s = c.stakeholders.unwrap_or_default();
            let m = c.submitter_metadata.unwrap_or_default();
            (
                salt_of(&c.salt),
                ReadCommon {
                    kind,
                    root_hash: Vec::new(),
                    stakeholders: s.all,
                    signatories: s.signatories,
                    submitter: m.submitter,
                    submitting_participant_uid: m.submitting_participant_uid,
                    reassigning_participant_uids: c.reassigning_participant_uids,
                    mediator_group: c.source_mediator_group,
                    synchronizer: c.source_physical_synchronizer_id,
                    source_synchronizer: None,
                    unassignment_ts: None,
                },
            )
        }
        Kind::Assignment => {
            let c = AssignmentCommonData::decode(data.as_slice()).map_err(|e| e.to_string())?;
            let s = c.stakeholders.unwrap_or_default();
            let m = c.submitter_metadata.unwrap_or_default();
            let unassignment_ts = c.unassignment_ts.as_ref().map(|ts| {
                ts.seconds
                    .saturating_mul(1_000_000)
                    .saturating_add(i64::from(ts.nanos) / 1_000)
            });
            (
                salt_of(&c.salt),
                ReadCommon {
                    kind,
                    root_hash: Vec::new(),
                    stakeholders: s.all,
                    signatories: s.signatories,
                    submitter: m.submitter,
                    submitting_participant_uid: m.submitting_participant_uid,
                    reassigning_participant_uids: c.reassigning_participant_uids,
                    mediator_group: c.target_mediator_group,
                    synchronizer: c.target_physical_synchronizer_id,
                    source_synchronizer: Some(c.source_physical_synchronizer_id),
                    unassignment_ts,
                },
            )
        }
    };
    let (common_salt, mut common) = read;
    let common_hash = leaf_hash(common_purpose, &common_salt, &tree.common_data);
    let view_hash = match tree
        .participant_data
        .as_ref()
        .and_then(|n| n.blinded_or_not.as_ref())
        .ok_or("the tree has no view")?
    {
        BlindedOrNot::BlindedHash(h) => h.clone(),
        BlindedOrNot::Unblinded(bytes) => {
            let (data, _) = crate::topology_wire::unversioned(bytes)
                .ok_or("the view is not a versioned message")?;
            let salt = match kind {
                Kind::Unassignment => salt_of(
                    &UnassignmentView::decode(data.as_slice())
                        .map_err(|e| e.to_string())?
                        .salt,
                ),
                Kind::Assignment => salt_of(
                    &AssignmentView::decode(data.as_slice())
                        .map_err(|e| e.to_string())?
                        .salt,
                ),
            };
            leaf_hash(view_purpose, &salt, bytes)
        }
    };
    common.root_hash = inner_hash(&[&common_hash, &view_hash]);
    Ok(common)
}
