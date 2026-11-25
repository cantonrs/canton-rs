//! The Merkle-tree nodes of the Canton transaction protocol, serialized and hashed the way the node does (G5 5.6, S-NET-005).
//!
//! A transaction is sent as a `GenTransactionTree`: a tree of *nodes* whose hashes the mediator and the participants check.
//! This module builds the **leaf nodes** (`CommonMetadata`, `ParticipantMetadata`, `ViewCommonData`) and their root hashes.
//! `tests/merkle_views.rs` rebuilds the same nodes in the node's console (Scala) and compares bytes and hashes.
//!
//! [CANTON-NOTE: SEMANTICS]
//! - A node is serialized as `UntypedVersionedMessage { data = <proto bytes>, version = 30 }`; that wrapped form is what the
//!   Scala code calls `getCryptographicEvidence`, and it is what the leaf hash covers.
//! - The **leaf hash** is the multihash (`1220` + SHA-256) of `HashPurpose.<node kind>` over `addByteString(salt.forHashing)`
//!   then `addByteString(versioned bytes)`; `addByteString` is a 4-byte big-endian length followed by the bytes.
//! - `Salt.forHashing` is the raw salt bytes (32 for HMAC-SHA256); the *wire* salt is `Salt { hmac = SHA256, salt }`.
//! - `ViewCommonData.informees` are written in the order given; each quorum names its confirmers by **index** into it.
//!
//! - An **inner node** (`ViewNode`, `MerkleSeqElement` branch/singleton, `GenTransactionTree`) hashes
//!   `HashPurpose.MerkleTreeInnerNode` (3) over `addInt(number of subtrees)` then each subtree's multihash **without** a length
//!   prefix. A blinded node is only its hash (`blinded_hash`); an unblinded one carries its versioned bytes (`unblinded`).
//! - A `MerkleSeq` wraps every element in a *singleton* and pairs them left to right layer by layer (`mkTree`): three
//!   elements give `Branch(Branch(a, b), c)`. Each element is itself versioned bytes (`MerkleSeqElement`, version 30).
//! - `SubmitterMetadata` is the one leaf that is a **v32** message (node version 32, purpose 5).
//! - A full informee tree is a `GenTransactionTree` with the participant metadata and every `ViewParticipantData` blinded.
//!
//! - `ViewParticipantData` (the participant-side part of a view) is a **v32** message (node version 32, purpose 9); the
//!   action description inside is the v31 one, the created contract the v31 `CreatedContract` (no `rolled_back`; the view has one).
//!
//! [CANTON-NOTE: LIMITATION] Only a root *create* and a root *exercise* (of one input contract, no subviews) are built; fetches,
//! keys and rollbacks are not.
//! External authorization is not supported.
use crate::topology_wire::versioned;
use canton_algo::hash::PurposeHash;
use canton_proto::com::digitalasset::canton::crypto::v30::{salt, HmacAlgorithm, Salt};
use canton_proto::com::digitalasset::canton::protocol::v30::{
    action_description::{
        CreateActionDescription, ExerciseActionDescription, FetchActionDescription,
    },
    blindable_node::BlindedOrNot,
    deduplication_period, BlindableNode, CommonMetadata, DeduplicationPeriod, FullInformeeTree,
    GenTransactionTree, InputContract, MerkleSeq, MerkleSeqElement, ParticipantMetadata,
    PartyIndexAndWeight, Quorum, ViewCommonData, ViewNode,
};
use canton_proto::com::digitalasset::canton::protocol::v31::{
    action_description::Description, ActionDescription, CreatedContract,
};
use canton_proto::com::digitalasset::canton::protocol::v32::{
    SubmitterMetadata, ViewParticipantData,
};
use prost::Message;

/// The version of the `CommonMetadata`/`ParticipantMetadata`/`ViewCommonData` messages (protocol version 37).
pub const NODE_VERSION: i32 = 30;
/// `HashPurpose.CommonMetadata`, `ParticipantMetadata`, `ViewCommonData` (see `canton-algo` purposes).
const PURPOSE_INNER_NODE: i32 = 3;
const PURPOSE_SUBMITTER_METADATA: i32 = 5;
const PURPOSE_VIEW_PARTICIPANT_DATA: i32 = 9;
/// The version of `ViewParticipantData` (a v32 message).
pub const VIEW_PARTICIPANT_DATA_VERSION: i32 = 32;
/// The version of `SubmitterMetadata` (a v32 message).
pub const SUBMITTER_METADATA_VERSION: i32 = 32;
const PURPOSE_COMMON_METADATA: i32 = 6;
const PURPOSE_PARTICIPANT_METADATA: i32 = 7;
const PURPOSE_VIEW_COMMON_DATA: i32 = 8;

/// The wire form of an HMAC-SHA256 salt.
pub fn wire_salt(bytes: &[u8]) -> Salt {
    Salt {
        algorithm: Some(salt::Algorithm::Hmac(HmacAlgorithm::HmacSha256 as i32)),
        salt: bytes.to_vec(),
    }
}

/// A node ready to be sent: its versioned bytes and the salt that goes into its hash.
#[derive(Debug, Clone)]
pub struct LeafNode {
    /// `UntypedVersionedMessage` bytes (the node's "cryptographic evidence").
    pub bytes: Vec<u8>,
    pub salt: Vec<u8>,
    purpose: i32,
}

impl LeafNode {
    fn new(proto: Vec<u8>, salt: &[u8], purpose: i32) -> Self {
        Self::with_version(proto, salt, purpose, NODE_VERSION)
    }

    pub(crate) fn with_version(proto: Vec<u8>, salt: &[u8], purpose: i32, version: i32) -> Self {
        LeafNode {
            bytes: versioned(proto, version),
            salt: salt.to_vec(),
            purpose,
        }
    }

    /// The root hash of the leaf, as the multihash bytes (`1220` + digest).
    pub fn root_hash(&self) -> Vec<u8> {
        let mut h = PurposeHash::new(self.purpose);
        h.add_byte_string(&self.salt).expect("open");
        h.add_byte_string(&self.bytes).expect("open");
        let mut out = vec![0x12, 0x20];
        out.extend_from_slice(&h.finish().expect("open"));
        out
    }
}

/// `CommonMetadata`: the synchronizer, the mediator group and the request's uuid.
pub fn common_metadata(
    physical_synchronizer_id: &str,
    mediator_group: i32,
    salt: &[u8],
    uuid: &str,
) -> LeafNode {
    LeafNode::new(
        CommonMetadata {
            salt: Some(wire_salt(salt)),
            physical_synchronizer_id: physical_synchronizer_id.to_string(),
            uuid: uuid.to_string(),
            mediator_group,
        }
        .encode_to_vec(),
        salt,
        PURPOSE_COMMON_METADATA,
    )
}

/// `ParticipantMetadata`: ledger time and preparation time (microseconds) and the optional workflow id (empty when absent).
pub fn participant_metadata(
    ledger_time_micros: i64,
    preparation_time_micros: i64,
    workflow_id: Option<&str>,
    salt: &[u8],
) -> LeafNode {
    LeafNode::new(
        ParticipantMetadata {
            salt: Some(wire_salt(salt)),
            ledger_time: ledger_time_micros,
            preparation_time: preparation_time_micros,
            workflow_id: workflow_id.unwrap_or("").to_string(),
        }
        .encode_to_vec(),
        salt,
        PURPOSE_PARTICIPANT_METADATA,
    )
}

/// One quorum: confirming parties with their weights, and the threshold the weights must reach.
pub struct QuorumSpec<'a> {
    pub confirmers: Vec<(&'a str, i32)>,
    pub threshold: i32,
}

/// `ViewCommonData`: the informees (in this order) and the quorums that name confirmers by index.
pub fn view_common_data(informees: &[&str], quorums: &[QuorumSpec], salt: &[u8]) -> LeafNode {
    let quorums = quorums
        .iter()
        .map(|q| Quorum {
            party_index_and_weight: q
                .confirmers
                .iter()
                .map(|(party, weight)| PartyIndexAndWeight {
                    index: informees
                        .iter()
                        .position(|p| p == party)
                        .expect("a confirmer is an informee") as i32,
                    weight: *weight,
                })
                .collect(),
            threshold: q.threshold,
        })
        .collect();
    LeafNode::new(
        ViewCommonData {
            salt: Some(wire_salt(salt)),
            informees: informees.iter().map(|s| s.to_string()).collect(),
            quorums,
        }
        .encode_to_vec(),
        salt,
        PURPOSE_VIEW_COMMON_DATA,
    )
}

/// The submitter of a transaction: who acts, under which user and command id, and until when it may be sequenced.
pub struct SubmitterInfo<'a> {
    pub act_as: Vec<&'a str>,
    pub user_id: &'a str,
    pub command_id: &'a str,
    /// The participant's unique identifier (`name::fingerprint`, without the `PAR::` prefix).
    pub submitting_participant_uid: &'a str,
    pub submission_id: Option<&'a str>,
    /// The deduplication period as a duration (seconds, nanos).
    pub dedup_duration: (i64, i32),
    pub max_sequencing_time_micros: i64,
}

/// `SubmitterMetadata` (v32), of a classic submission (no external authorization).
pub fn submitter_metadata(info: &SubmitterInfo, salt: &[u8]) -> LeafNode {
    submitter_metadata_with(info, salt, None)
}

/// `SubmitterMetadata` (v32) carrying the external parties' authorization of an externally signed submission (U-56).
pub fn submitter_metadata_with(
    info: &SubmitterInfo,
    salt: &[u8],
    external_authorization: Option<
        &canton_proto::com::digitalasset::canton::protocol::v32::ExternalAuthorization,
    >,
) -> LeafNode {
    LeafNode::with_version(
        SubmitterMetadata {
            salt: Some(wire_salt(salt)),
            act_as: info.act_as.iter().map(|s| s.to_string()).collect(),
            user_id: info.user_id.to_string(),
            command_id: info.command_id.to_string(),
            submitting_participant_uid: info.submitting_participant_uid.to_string(),
            submission_id: info.submission_id.unwrap_or("").to_string(),
            dedup_period: Some(DeduplicationPeriod {
                period: Some(deduplication_period::Period::Duration(
                    prost_types::Duration {
                        seconds: info.dedup_duration.0,
                        nanos: info.dedup_duration.1,
                    },
                )),
            }),
            max_sequencing_time: info.max_sequencing_time_micros,
            external_authorization: external_authorization.cloned(),
        }
        .encode_to_vec(),
        salt,
        PURPOSE_SUBMITTER_METADATA,
        SUBMITTER_METADATA_VERSION,
    )
}

/// A node as it sits in its parent: its hash, and the `BlindableNode` that carries it (the bytes, or only the hash).
#[derive(Debug, Clone)]
pub struct Tree {
    pub hash: Vec<u8>,
    pub node: BlindableNode,
}

impl Tree {
    /// A node whose content is revealed.
    pub fn unblinded(bytes: Vec<u8>, hash: Vec<u8>) -> Self {
        Tree {
            hash,
            node: BlindableNode {
                blinded_or_not: Some(BlindedOrNot::Unblinded(bytes)),
            },
        }
    }

    /// A node that is only known by its hash.
    pub fn blinded(hash: Vec<u8>) -> Self {
        Tree {
            node: BlindableNode {
                blinded_or_not: Some(BlindedOrNot::BlindedHash(hash.clone())),
            },
            hash,
        }
    }

    pub fn leaf(node: &LeafNode) -> Self {
        Tree::unblinded(node.bytes.clone(), node.root_hash())
    }
}

/// The hash of an inner node over its subtrees' hashes.
pub fn inner_hash(children: &[&[u8]]) -> Vec<u8> {
    let mut h = PurposeHash::new(PURPOSE_INNER_NODE);
    h.add_int(children.len() as i32).expect("open");
    for c in children {
        h.add_without_length_prefix(c).expect("open");
    }
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&h.finish().expect("open"));
    out
}

/// A `MerkleSeq`: the proto and the root hash (none when empty).
#[derive(Debug, Clone, Default)]
pub struct Seq {
    pub proto: MerkleSeq,
    pub root_hash: Option<Vec<u8>>,
}

fn element(first: Option<&Tree>, second: Option<&Tree>, data: Option<&Tree>) -> Tree {
    let children: Vec<&[u8]> = [first, second, data]
        .iter()
        .flatten()
        .map(|t| t.hash.as_slice())
        .collect();
    let hash = inner_hash(&children);
    let bytes = versioned(
        MerkleSeqElement {
            first: first.map(|t| t.node.clone()),
            second: second.map(|t| t.node.clone()),
            data: data.map(|t| t.node.clone()),
        }
        .encode_to_vec(),
        NODE_VERSION,
    );
    Tree::unblinded(bytes, hash)
}

/// `MerkleSeq.fromSeq`: every element in a singleton, paired left to right layer by layer.
pub fn merkle_seq(elements: &[Tree]) -> Seq {
    if elements.is_empty() {
        return Seq::default();
    }
    let mut layer: Vec<Tree> = elements
        .iter()
        .map(|e| element(None, None, Some(e)))
        .collect();
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|c| match c {
                [a, b] => element(Some(a), Some(b), None),
                [a] => a.clone(),
                _ => unreachable!("chunks of two"),
            })
            .collect();
    }
    let root = layer.remove(0);
    Seq {
        root_hash: Some(root.hash),
        proto: MerkleSeq {
            root_or_empty: Some(root.node),
        },
    }
}

/// A `MerkleSeq` whose root is blinded: only its root hash is revealed (`MerkleSeq.isFullyBlinded`).
pub fn blinded_seq(root_hash: &[u8]) -> Seq {
    Seq {
        root_hash: Some(root_hash.to_vec()),
        proto: MerkleSeq {
            root_or_empty: Some(Tree::blinded(root_hash.to_vec()).node),
        },
    }
}

/// A `ViewNode` (`TransactionView`): common data, participant data and the subviews.
pub fn view_node(common: &Tree, participant: &Tree, subviews: &Seq) -> Tree {
    let mut children: Vec<&[u8]> = vec![&common.hash, &participant.hash];
    if let Some(h) = &subviews.root_hash {
        children.push(h);
    }
    let hash = inner_hash(&children);
    let bytes = versioned(
        ViewNode {
            view_common_data: Some(common.node.clone()),
            view_participant_data: Some(participant.node.clone()),
            subviews: Some(subviews.proto.clone()),
        }
        .encode_to_vec(),
        NODE_VERSION,
    );
    Tree::unblinded(bytes, hash)
}

/// A `GenTransactionTree` and its root hash (what the submitting participant signs and the mediator checks).
#[derive(Debug, Clone)]
pub struct GenTree {
    pub proto: GenTransactionTree,
    pub root_hash: Vec<u8>,
}

pub fn gen_transaction_tree(
    submitter: &Tree,
    common: &Tree,
    participant: &Tree,
    root_views: &Seq,
) -> GenTree {
    let mut children: Vec<&[u8]> = vec![&submitter.hash, &common.hash, &participant.hash];
    if let Some(h) = &root_views.root_hash {
        children.push(h);
    }
    GenTree {
        root_hash: inner_hash(&children),
        proto: GenTransactionTree {
            submitter_metadata: Some(submitter.node.clone()),
            common_metadata: Some(common.node.clone()),
            participant_metadata: Some(participant.node.clone()),
            root_views: Some(root_views.proto.clone()),
        },
    }
}

/// The `FullInformeeTree` message around a tree.
pub fn full_informee_tree(tree: &GenTree) -> FullInformeeTree {
    FullInformeeTree {
        tree: Some(tree.proto.clone()),
    }
}

/// `ViewParticipantData` of a view whose root action **creates** one contract (no inputs, no subview effects).
///
/// `contract` is the serialized instance (`contract_wire::ContractInstance::encode`), `contract_id_hex` its id as the node
/// prints it (hex of the id bytes) and `node_seed` the 32-byte seed of the create node.
pub fn view_participant_data_create(
    contract: &[u8],
    contract_id_hex: &str,
    node_seed: &[u8],
    salt: &[u8],
) -> LeafNode {
    view_participant_data_create_with_keys(contract, contract_id_hex, node_seed, salt, Vec::new())
}

/// Like `view_participant_data_create`, for a contract with a key: `resolved_keys` lists that key with its maintainers and no contract id
/// (nothing held the key; measured on views p1 made, U-21).
pub fn view_participant_data_create_with_keys(
    contract: &[u8],
    contract_id_hex: &str,
    node_seed: &[u8],
    salt: &[u8],
    resolved_keys: Vec<
        canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers,
    >,
) -> LeafNode {
    LeafNode::with_version(
        ViewParticipantData {
            salt: Some(wire_salt(salt)),
            core_inputs: Vec::new(),
            created_core: vec![CreatedContract {
                contract: contract.to_vec(),
                consumed_in_core: false,
            }],
            created_in_subview_archived_in_core: Vec::new(),
            resolved_keys,
            action_description: Some(ActionDescription {
                description: Some(Description::Create(CreateActionDescription {
                    contract_id: contract_id_hex.to_string(),
                    node_seed: node_seed.to_vec(),
                })),
            }),
            external_call_results: Vec::new(),
            rolled_back: false,
        }
        .encode_to_vec(),
        salt,
        PURPOSE_VIEW_PARTICIPANT_DATA,
        VIEW_PARTICIPANT_DATA_VERSION,
    )
}

/// What a root **exercise** view says about the exercise.
pub struct ExerciseSpec<'a> {
    /// The id of the exercised contract, as the node prints it (hex of the id bytes).
    pub contract_id_hex: &'a str,
    /// `<package id>:<module>:<template>`.
    pub template_id: &'a str,
    pub choice: &'a str,
    /// The chosen value as a **versioned** value (`Versioned { version, payload }`), unlike a contract's bare `create_arg`.
    pub chosen_value: &'a [u8],
    pub actors: &'a [&'a str],
    pub node_seed: &'a [u8],
    /// The interface the choice is exercised through, as `<package id>:<module>:<interface>` (`None` for a choice of the template).
    pub interface_id: Option<&'a str>,
    /// The packages a package **name** in the choice's code resolves in (`ExerciseActionDescription.package_preference`): the official participant
    /// says `UnresolvedPackageName` for a body that calls another package by name when it is missing (measured on Splice's `AmuletRules_Mint`).
    pub package_preference: &'a [String],
}

/// `ViewParticipantData` of a view whose root action **exercises** a contract: the contract is the view's one core input
/// (`consumed` says whether the choice consumes it) and `created` are the contracts the exercise creates in this view (serialized
/// instances, each with whether the same view consumes it).
///
/// [CANTON-NOTE: SEMANTICS] Measured on an exercise p1 submitted (`Settle`): the input is the **full instance** exactly as it was
/// created (so the receiver can check its authentication data), `by_key`, `failed`, `interface_id`, `package_preference`,
/// `resolved_keys` and the rollback flag are all empty/false, and the node seed is any 32 bytes (it only matters for the contracts
/// the exercise creates).
pub fn view_participant_data_exercise(
    input_contract: &[u8],
    consumed: bool,
    created: &[(&[u8], bool)],
    exercise: &ExerciseSpec,
    salt: &[u8],
) -> LeafNode {
    view_participant_data_exercise_with_keys(
        input_contract,
        consumed,
        created,
        exercise,
        salt,
        Vec::new(),
    )
}

/// Like `view_participant_data_exercise`, with the view's `resolved_keys` (the keys the exercise's contracts hold).
pub fn view_participant_data_exercise_with_keys(
    input_contract: &[u8],
    consumed: bool,
    created: &[(&[u8], bool)],
    exercise: &ExerciseSpec,
    salt: &[u8],
    resolved_keys: Vec<
        canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers,
    >,
) -> LeafNode {
    view_participant_data_exercise_tree(
        &[(input_contract, consumed)],
        created,
        exercise,
        salt,
        resolved_keys,
    )
}

/// `ViewParticipantData` of a view whose root action exercises a contract and whose **subtree** (children in the same view) reads or
/// consumes further contracts: `inputs` are all the contracts the view's core uses, the exercised one first, each with whether the view
/// consumes it.
///
/// [CANTON-NOTE: LIMITATION] The order of `inputs` is the order of the serialized `core_inputs`; whether a participant requires a canonical
/// order (by contract id) is not known, the caller passes them as the subtree meets them.
pub fn view_participant_data_exercise_tree(
    inputs: &[(&[u8], bool)],
    created: &[(&[u8], bool)],
    exercise: &ExerciseSpec,
    salt: &[u8],
    resolved_keys: Vec<
        canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers,
    >,
) -> LeafNode {
    LeafNode::with_version(
        ViewParticipantData {
            salt: Some(wire_salt(salt)),
            core_inputs: inputs
                .iter()
                .map(|(contract, consumed)| InputContract {
                    contract: contract.to_vec(),
                    consumed: *consumed,
                })
                .collect(),
            created_core: created
                .iter()
                .map(|(contract, consumed_in_core)| CreatedContract {
                    contract: contract.to_vec(),
                    consumed_in_core: *consumed_in_core,
                })
                .collect(),
            created_in_subview_archived_in_core: Vec::new(),
            resolved_keys,
            action_description: Some(ActionDescription {
                description: Some(Description::Exercise(ExerciseActionDescription {
                    input_contract_id: exercise.contract_id_hex.to_string(),
                    choice: exercise.choice.to_string(),
                    chosen_value: exercise.chosen_value.to_vec(),
                    actors: exercise.actors.iter().map(|a| a.to_string()).collect(),
                    by_key: false,
                    node_seed: exercise.node_seed.to_vec(),
                    failed: false,
                    interface_id: None,
                    template_id: exercise.template_id.to_string(),
                    package_preference: Vec::new(),
                })),
            }),
            external_call_results: Vec::new(),
            rolled_back: false,
        }
        .encode_to_vec(),
        salt,
        PURPOSE_VIEW_PARTICIPANT_DATA,
        VIEW_PARTICIPANT_DATA_VERSION,
    )
}

/// `ViewParticipantData` of any view: its core inputs (each with whether the core consumes it), the contracts its core creates (each with
/// whether the core consumes it), the contracts a subview created and the core archived, and the action of its root node.
///
/// Source: `NextGenTransactionTreeFactory.createViewParticipantData`.
pub fn view_participant_data_of(
    inputs: &[(&[u8], bool)],
    created: &[(&[u8], bool)],
    created_in_subview_archived_in_core: Vec<String>,
    resolved_keys: Vec<
        canton_proto::com::digitalasset::canton::protocol::v31::view_participant_data::KeyResolutionWithMaintainers,
    >,
    description: Description,
    salt: &[u8],
    rolled_back: bool,
) -> LeafNode {
    LeafNode::with_version(
        ViewParticipantData {
            salt: Some(wire_salt(salt)),
            core_inputs: inputs
                .iter()
                .map(|(contract, consumed)| InputContract {
                    contract: contract.to_vec(),
                    consumed: *consumed,
                })
                .collect(),
            created_core: created
                .iter()
                .map(|(contract, consumed_in_core)| CreatedContract {
                    contract: contract.to_vec(),
                    consumed_in_core: *consumed_in_core,
                })
                .collect(),
            created_in_subview_archived_in_core,
            resolved_keys,
            action_description: Some(ActionDescription {
                description: Some(description),
            }),
            external_call_results: Vec::new(),
            rolled_back,
        }
        .encode_to_vec(),
        salt,
        PURPOSE_VIEW_PARTICIPANT_DATA,
        VIEW_PARTICIPANT_DATA_VERSION,
    )
}

/// The action description of a root **create** node.
pub fn create_description(contract_id_hex: &str, node_seed: &[u8]) -> Description {
    Description::Create(CreateActionDescription {
        contract_id: contract_id_hex.to_string(),
        node_seed: node_seed.to_vec(),
    })
}

/// The action description of a root **exercise** node.
pub fn exercise_description(exercise: &ExerciseSpec) -> Description {
    exercise_description_with_by_key(exercise, false)
}

/// Like [`exercise_description`], explicitly setting `by_key` when the target was reached by key.
pub fn exercise_description_with_by_key(exercise: &ExerciseSpec, by_key: bool) -> Description {
    Description::Exercise(ExerciseActionDescription {
        input_contract_id: exercise.contract_id_hex.to_string(),
        choice: exercise.choice.to_string(),
        chosen_value: exercise.chosen_value.to_vec(),
        actors: exercise.actors.iter().map(|a| a.to_string()).collect(),
        by_key,
        node_seed: exercise.node_seed.to_vec(),
        failed: false,
        interface_id: exercise.interface_id.map(String::from),
        template_id: exercise.template_id.to_string(),
        package_preference: exercise.package_preference.to_vec(),
    })
}

/// The action description of a root **fetch** node (no key, no interface).
pub fn fetch_description(
    contract_id_hex: &str,
    actors: &[&str],
    template_id: &str,
    interface_id: Option<&str>,
) -> Description {
    fetch_description_with_by_key(contract_id_hex, actors, template_id, interface_id, false)
}

/// Like [`fetch_description`], explicitly setting `by_key` when fetched by key.
pub fn fetch_description_with_by_key(
    contract_id_hex: &str,
    actors: &[&str],
    template_id: &str,
    interface_id: Option<&str>,
    by_key: bool,
) -> Description {
    Description::Fetch(FetchActionDescription {
        input_contract_id: contract_id_hex.to_string(),
        actors: actors.iter().map(|a| a.to_string()).collect(),
        by_key,
        template_id: template_id.to_string(),
        interface_id: interface_id.map(String::from),
    })
}
