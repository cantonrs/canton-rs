//! Deterministic Canton 3.7.2 `PreparedTransaction` hashing (`HashPurpose.PreparedSubmission = 48`,
//! `HashingSchemeVersion.V2` / `V3`) over protobuf `com.daml.ledger.api.v2.interactive.PreparedTransaction`
//! (`U-13(ii)`, `AT-C01`).
//!
//! References in Canton 3.7.2 (`references/canton-3.7.2-src`):
//! - `protocol/hash/TransactionHash.scala`
//! - `protocol/hash/VersionedTransactionHasher.scala`
//! - `protocol/hash/NodeHashBuilderCommon.scala`, `v2/NodeHashBuilder.scala`, `v3/NodeHashBuilder.scala`
//! - `protocol/hash/LfValueHashBuilder.scala`
//! - `protocol/hash/v2/TransactionMetadataHasher.scala`, `v3/TransactionMetadataHasher.scala`
//! - `crypto/InteractiveSubmission.scala`

use std::collections::{BTreeSet, HashMap, HashSet};

use canton_proto::com::daml::ledger::api::v2::{
    self as lapi,
    interactive::{
        daml_transaction::node::VersionedNode,
        metadata::{self, input_contract},
        transaction::v1::{self, node::NodeType},
        DamlTransaction, GlobalKeyWithMaintainers, HashingSchemeVersion, Metadata,
        PreparedTransaction,
    },
};
use prost::Message;
use sha2::{Digest, Sha256};

/// Canton `HashPurpose.PreparedSubmission` ID.
pub const PREPARED_SUBMISSION_PURPOSE: i32 = 48;

const NODE_ENCODING_V1: u8 = 0x01;
const METADATA_ENCODING_V1: u8 = 0x01;
const MAX_RECURSION_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedHashError {
    Decode(String),
    UnsupportedHashingScheme(i32),
    UnsupportedSerializationVersion {
        scheme: &'static str,
        version: String,
    },
    MissingField(&'static str),
    MissingNode(String),
    MissingNodeSeed {
        node_kind: &'static str,
        node_id: String,
    },
    CycleDetected(String),
    DepthExceeded,
    InvalidContractId(String),
    InvalidHexHash(String),
    InvalidNumeric(String),
    InvalidIdentifier(String),
}

impl std::fmt::Display for PreparedHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(msg) => write!(f, "failed to decode PreparedTransaction protobuf: {msg}"),
            Self::UnsupportedHashingScheme(v) => {
                write!(f, "unsupported hashing scheme version: {v}")
            }
            Self::UnsupportedSerializationVersion { scheme, version } => write!(
                f,
                "unsupported serialization version '{version}' for hashing scheme {scheme}"
            ),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::MissingNode(id) => write!(f, "missing node '{id}' in transaction"),
            Self::MissingNodeSeed { node_kind, node_id } => {
                write!(f, "missing node seed for {node_kind} node '{node_id}'")
            }
            Self::CycleDetected(id) => write!(f, "cycle detected at node '{id}'"),
            Self::DepthExceeded => write!(f, "maximum node/value nesting depth exceeded"),
            Self::InvalidContractId(cid) => write!(f, "invalid hex contract id '{cid}'"),
            Self::InvalidHexHash(msg) => write!(f, "invalid hash bytes: {msg}"),
            Self::InvalidNumeric(s) => write!(f, "invalid numeric string '{s}'"),
            Self::InvalidIdentifier(msg) => write!(f, "invalid identifier: {msg}"),
        }
    }
}

impl std::error::Error for PreparedHashError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SerializationVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    VDev = i32::MAX as isize,
}

impl SerializationVersion {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "2.1" => Some(Self::V1),
            "2" => Some(Self::V2),
            "3" => Some(Self::V3),
            "dev" => Some(Self::VDev),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    V2,
    V3,
}

impl Scheme {
    fn parse(version: HashingSchemeVersion) -> Result<Self, PreparedHashError> {
        match version {
            HashingSchemeVersion::V2 => Ok(Self::V2),
            HashingSchemeVersion::V3 => Ok(Self::V3),
            other => Err(PreparedHashError::UnsupportedHashingScheme(other as i32)),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::V2 => "V2",
            Self::V3 => "V3",
        }
    }

    fn version_byte(self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    fn max_serialization_version(self) -> SerializationVersion {
        match self {
            Self::V2 => SerializationVersion::V1,
            Self::V3 => SerializationVersion::V2,
        }
    }

    fn check_version(self, raw: &str) -> Result<SerializationVersion, PreparedHashError> {
        let Some(parsed) = SerializationVersion::parse(raw) else {
            return Err(PreparedHashError::UnsupportedSerializationVersion {
                scheme: self.name(),
                version: raw.to_string(),
            });
        };
        if parsed > self.max_serialization_version() {
            return Err(PreparedHashError::UnsupportedSerializationVersion {
                scheme: self.name(),
                version: raw.to_string(),
            });
        }
        Ok(parsed)
    }
}

/// Encode raw protobuf bytes and compute the Canton `preparedTransactionHash` (32 bytes).
pub fn hash_prepared_transaction_bytes(
    bytes: &[u8],
    scheme: HashingSchemeVersion,
) -> Result<[u8; 32], PreparedHashError> {
    let tx =
        PreparedTransaction::decode(bytes).map_err(|e| PreparedHashError::Decode(e.to_string()))?;
    hash_prepared_transaction(&tx, scheme)
}

/// Compute the deterministic 32-byte `preparedTransactionHash` for a `PreparedTransaction`.
pub fn hash_prepared_transaction(
    prepared: &PreparedTransaction,
    scheme: HashingSchemeVersion,
) -> Result<[u8; 32], PreparedHashError> {
    let scheme = Scheme::parse(scheme)?;
    let tx = prepared
        .transaction
        .as_ref()
        .ok_or(PreparedHashError::MissingField(
            "PreparedTransaction.transaction",
        ))?;
    let meta = prepared
        .metadata
        .as_ref()
        .ok_or(PreparedHashError::MissingField(
            "PreparedTransaction.metadata",
        ))?;

    let tx_hash = hash_versioned_transaction(scheme, tx)?;
    let meta_hash = hash_metadata(scheme, meta)?;

    let mut out = HashWriter::new_with_purpose(PREPARED_SUBMISSION_PURPOSE);
    out.add_byte(scheme.version_byte());
    out.add_hash(&tx_hash);
    out.add_hash(&meta_hash);
    Ok(out.finish())
}

fn hash_versioned_transaction(
    scheme: Scheme,
    tx: &DamlTransaction,
) -> Result<[u8; 32], PreparedHashError> {
    scheme.check_version(&tx.version)?;
    let mut nodes: HashMap<&str, &v1::Node> = HashMap::with_capacity(tx.nodes.len());
    for node in &tx.nodes {
        let Some(VersionedNode::V1(inner)) = &node.versioned_node else {
            return Err(PreparedHashError::MissingField("Node.versioned_node.v1"));
        };
        nodes.insert(node.node_id.as_str(), inner);
    }
    let mut seeds: HashMap<i32, &[u8]> = HashMap::with_capacity(tx.node_seeds.len());
    for ns in &tx.node_seeds {
        seeds.insert(ns.node_id, ns.seed.as_slice());
    }

    let mut w = HashWriter::new_with_purpose(PREPARED_SUBMISSION_PURPOSE);
    w.add_string(&tx.version);
    w.add_int(tx.roots.len() as i32);
    let mut active = HashSet::new();
    for root in &tx.roots {
        let h = hash_node(scheme, root, &nodes, &seeds, true, &mut active, 0)?;
        w.add_hash(&h);
    }
    Ok(w.finish())
}

fn lookup_seed<'a>(node_id: &str, seeds: &'a HashMap<i32, &'a [u8]>) -> Option<&'a [u8]> {
    node_id
        .trim()
        .parse::<i32>()
        .ok()
        .and_then(|id| seeds.get(&id).copied())
}

fn hash_node(
    scheme: Scheme,
    node_id: &str,
    nodes: &HashMap<&str, &v1::Node>,
    seeds: &HashMap<i32, &[u8]>,
    enforce_create_seed: bool,
    active: &mut HashSet<String>,
    depth: usize,
) -> Result<[u8; 32], PreparedHashError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(PreparedHashError::DepthExceeded);
    }
    if !active.insert(node_id.to_string()) {
        return Err(PreparedHashError::CycleDetected(node_id.to_string()));
    }
    let res = (|| {
        let node = nodes
            .get(node_id)
            .ok_or_else(|| PreparedHashError::MissingNode(node_id.to_string()))?;
        let Some(node_type) = &node.node_type else {
            return Err(PreparedHashError::MissingField("Node.node_type"));
        };
        match node_type {
            NodeType::Create(c) => {
                let seed = lookup_seed(node_id, seeds);
                if enforce_create_seed && seed.is_none() {
                    return Err(PreparedHashError::MissingNodeSeed {
                        node_kind: "Create",
                        node_id: node_id.to_string(),
                    });
                }
                hash_create_node(scheme, c, seed)
            }
            NodeType::Fetch(f) => hash_fetch_node(scheme, f),
            NodeType::Exercise(ex) => {
                let seed = lookup_seed(node_id, seeds).ok_or_else(|| {
                    PreparedHashError::MissingNodeSeed {
                        node_kind: "Exercise",
                        node_id: node_id.to_string(),
                    }
                })?;
                hash_exercise_node(
                    scheme,
                    ex,
                    seed,
                    nodes,
                    seeds,
                    enforce_create_seed,
                    active,
                    depth,
                )
            }
            NodeType::Rollback(rb) => {
                let mut w = HashWriter::new_without_purpose();
                if scheme == Scheme::V2 {
                    w.add_byte(NODE_ENCODING_V1);
                }
                w.add_byte(3); // NodeTag.Rollback
                w.add_int(rb.children.len() as i32);
                for child_id in &rb.children {
                    let child_hash = hash_node(
                        scheme,
                        child_id,
                        nodes,
                        seeds,
                        enforce_create_seed,
                        active,
                        depth + 1,
                    )?;
                    w.add_hash(&child_hash);
                }
                Ok(w.finish())
            }
            NodeType::QueryByKey(q) => {
                if scheme == Scheme::V2 {
                    return Err(PreparedHashError::UnsupportedSerializationVersion {
                        scheme: scheme.name(),
                        version: q.lf_version.clone(),
                    });
                }
                scheme.check_version(&q.lf_version)?;
                let tpl = q
                    .template_id
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("QueryByKey.template_id"))?;
                let key = q
                    .key
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("QueryByKey.key"))?;
                let mut w = HashWriter::new_without_purpose();
                w.add_string(&q.lf_version);
                w.add_byte(4); // NodeTag.QueryByKey
                w.add_string(&q.package_name);
                add_identifier(&mut w, tpl)?;
                w.add_bool(q.exhaustive);
                add_global_key_with_maintainers(&mut w, key)?;
                w.add_int(q.result.len() as i32);
                for cid in &q.result {
                    add_cid(&mut w, cid)?;
                }
                Ok(w.finish())
            }
        }
    })();
    active.remove(node_id);
    res
}

fn hash_create_node(
    scheme: Scheme,
    c: &v1::Create,
    seed: Option<&[u8]>,
) -> Result<[u8; 32], PreparedHashError> {
    scheme.check_version(&c.lf_version)?;
    let tpl = c
        .template_id
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Create.template_id"))?;
    let arg = c
        .argument
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Create.argument"))?;
    let mut w = HashWriter::new_without_purpose();
    if scheme == Scheme::V2 {
        w.add_byte(NODE_ENCODING_V1);
    }
    w.add_string(&c.lf_version);
    w.add_byte(0); // NodeTag.Create
    w.add_optional(seed, add_lf_hash_bytes)?;
    add_cid(&mut w, &c.contract_id)?;
    w.add_string(&c.package_name);
    add_identifier(&mut w, tpl)?;
    add_typed_value(&mut w, arg, 0)?;
    w.add_string_set(&c.signatories);
    w.add_string_set(&c.stakeholders);
    if scheme == Scheme::V3 {
        w.add_optional(c.key.as_ref(), add_global_key_with_maintainers)?;
    }
    Ok(w.finish())
}

fn hash_fetch_node(scheme: Scheme, f: &v1::Fetch) -> Result<[u8; 32], PreparedHashError> {
    scheme.check_version(&f.lf_version)?;
    let tpl = f
        .template_id
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Fetch.template_id"))?;
    let mut w = HashWriter::new_without_purpose();
    if scheme == Scheme::V2 {
        w.add_byte(NODE_ENCODING_V1);
    }
    w.add_string(&f.lf_version);
    w.add_byte(2); // NodeTag.Fetch
    add_cid(&mut w, &f.contract_id)?;
    w.add_string(&f.package_name);
    add_identifier(&mut w, tpl)?;
    w.add_string_set(&f.signatories);
    w.add_string_set(&f.stakeholders);
    w.add_optional(f.interface_id.as_ref(), add_identifier)?;
    w.add_string_set(&f.acting_parties);
    if scheme == Scheme::V3 {
        w.add_bool(f.by_key);
        w.add_optional(f.key.as_ref(), add_global_key_with_maintainers)?;
    }
    Ok(w.finish())
}

#[allow(
    clippy::too_many_arguments,
    reason = "wire builders and state handlers pass explicit field arguments directly"
)]
fn hash_exercise_node(
    scheme: Scheme,
    ex: &v1::Exercise,
    seed: &[u8],
    nodes: &HashMap<&str, &v1::Node>,
    seeds: &HashMap<i32, &[u8]>,
    enforce_create_seed: bool,
    active: &mut HashSet<String>,
    depth: usize,
) -> Result<[u8; 32], PreparedHashError> {
    scheme.check_version(&ex.lf_version)?;
    let tpl = ex
        .template_id
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Exercise.template_id"))?;
    let chosen_value = ex
        .chosen_value
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Exercise.chosen_value"))?;
    let mut w = HashWriter::new_without_purpose();
    if scheme == Scheme::V2 {
        w.add_byte(NODE_ENCODING_V1);
    }
    w.add_string(&ex.lf_version);
    w.add_byte(1); // NodeTag.Exercise
    add_lf_hash_bytes(&mut w, seed)?;
    add_cid(&mut w, &ex.contract_id)?;
    w.add_string(&ex.package_name);
    add_identifier(&mut w, tpl)?;
    w.add_string_set(&ex.signatories);
    w.add_string_set(&ex.stakeholders);
    w.add_string_set(&ex.acting_parties);
    w.add_optional(ex.interface_id.as_ref(), add_identifier)?;
    w.add_string(&ex.choice_id);
    add_typed_value(&mut w, chosen_value, 0)?;
    w.add_bool(ex.consuming);
    w.add_optional(ex.exercise_result.as_ref(), |w, v| add_typed_value(w, v, 0))?;
    w.add_string_set(&ex.choice_observers);
    if scheme == Scheme::V3 {
        w.add_bool(ex.by_key);
        w.add_optional(ex.key.as_ref(), |w, k| {
            add_global_key_with_maintainers(w, k)
        })?;
    }
    w.add_int(ex.children.len() as i32);
    for child_id in &ex.children {
        let child_hash = hash_node(
            scheme,
            child_id,
            nodes,
            seeds,
            enforce_create_seed,
            active,
            depth + 1,
        )?;
        w.add_hash(&child_hash);
    }
    Ok(w.finish())
}

fn hash_metadata(scheme: Scheme, meta: &Metadata) -> Result<[u8; 32], PreparedHashError> {
    let sub = meta
        .submitter_info
        .as_ref()
        .ok_or(PreparedHashError::MissingField("Metadata.submitter_info"))?;

    let mut w = HashWriter::new_with_purpose(PREPARED_SUBMISSION_PURPOSE);
    if scheme == Scheme::V2 {
        w.add_byte(METADATA_ENCODING_V1);
    }
    w.add_string_set(&sub.act_as);
    w.add_string(&sub.command_id);
    w.add_string(&meta.transaction_uuid);
    w.add_int(meta.mediator_group as i32);
    w.add_string(&meta.synchronizer_id);
    w.add_optional(meta.min_ledger_effective_time, |w, t| {
        w.add_long(t as i64);
        Ok(())
    })?;
    w.add_optional(meta.max_ledger_effective_time, |w, t| {
        w.add_long(t as i64);
        Ok(())
    })?;
    w.add_long(meta.preparation_time as i64);

    // InteractiveSubmission.TransactionMetadataForHashing sorts disclosedContracts by LfContractId.coid.
    let mut inputs: Vec<(&metadata::InputContract, &v1::Create)> =
        Vec::with_capacity(meta.input_contracts.len());
    for ic in &meta.input_contracts {
        let Some(input_contract::Contract::V1(c)) = &ic.contract else {
            return Err(PreparedHashError::MissingField("InputContract.contract.v1"));
        };
        inputs.push((ic, c));
    }
    inputs.sort_by(|(_, a), (_, b)| cmp_utf16(&a.contract_id, &b.contract_id));

    w.add_int(inputs.len() as i32);
    for (ic, create) in inputs {
        w.add_long(ic.created_at as i64);
        let create_hash = hash_create_node(scheme, create, None)?;
        w.add_hash(&create_hash);
    }

    if scheme == Scheme::V3 {
        w.add_optional(meta.max_record_time, |w, t| {
            w.add_long(t as i64);
            Ok(())
        })?;
    }
    Ok(w.finish())
}

fn add_lf_hash_bytes(w: &mut HashWriter, seed: &[u8]) -> Result<(), PreparedHashError> {
    if seed.len() != 32 {
        return Err(PreparedHashError::InvalidHexHash(format!(
            "expected 32-byte LfHash seed, got {} bytes",
            seed.len()
        )));
    }
    w.add_raw(seed);
    Ok(())
}

fn add_cid(w: &mut HashWriter, cid: &str) -> Result<(), PreparedHashError> {
    let raw =
        hex::decode(cid).map_err(|_| PreparedHashError::InvalidContractId(cid.to_string()))?;
    w.add_byte_string(&raw);
    Ok(())
}

fn add_identifier(w: &mut HashWriter, id: &lapi::Identifier) -> Result<(), PreparedHashError> {
    if id.module_name.is_empty() || id.entity_name.is_empty() {
        return Err(PreparedHashError::InvalidIdentifier(format!(
            "{}:{}:{}",
            id.package_id, id.module_name, id.entity_name
        )));
    }
    w.add_string(&id.package_id);
    add_dotted_name(w, &id.module_name)?;
    add_dotted_name(w, &id.entity_name)?;
    Ok(())
}

fn add_dotted_name(w: &mut HashWriter, dotted: &str) -> Result<(), PreparedHashError> {
    let segs: Vec<&str> = dotted.split('.').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return Err(PreparedHashError::InvalidIdentifier(dotted.to_string()));
    }
    w.add_int(segs.len() as i32);
    for seg in segs {
        w.add_string(seg);
    }
    Ok(())
}

fn add_global_key_with_maintainers(
    w: &mut HashWriter,
    gkm: &GlobalKeyWithMaintainers,
) -> Result<(), PreparedHashError> {
    let gk = gkm.key.as_ref().ok_or(PreparedHashError::MissingField(
        "GlobalKeyWithMaintainers.key",
    ))?;
    let tpl = gk
        .template_id
        .as_ref()
        .ok_or(PreparedHashError::MissingField("GlobalKey.template_id"))?;
    let val = gk
        .key
        .as_ref()
        .ok_or(PreparedHashError::MissingField("GlobalKey.key"))?;
    w.add_string(&gk.package_name);
    add_identifier(w, tpl)?;
    add_typed_value(w, val, 0)?;
    add_lf_hash_bytes(w, &gk.hash)?;
    w.add_string_set(&gkm.maintainers);
    Ok(())
}

fn add_typed_value(
    w: &mut HashWriter,
    val: &lapi::Value,
    depth: usize,
) -> Result<(), PreparedHashError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(PreparedHashError::DepthExceeded);
    }
    let Some(sum) = &val.sum else {
        return Err(PreparedHashError::MissingField("Value.sum"));
    };
    use lapi::value::Sum;
    match sum {
        Sum::Unit(()) => {
            w.add_byte(0);
        }
        Sum::Bool(b) => {
            w.add_byte(1);
            w.add_bool(*b);
        }
        Sum::Int64(n) => {
            w.add_byte(2);
            w.add_long(*n);
        }
        Sum::Numeric(s) => {
            w.add_byte(3);
            let canonical = canonicalize_numeric(s)?;
            w.add_string(&canonical);
        }
        Sum::Timestamp(ts) => {
            w.add_byte(4);
            w.add_long(*ts);
        }
        Sum::Date(d) => {
            w.add_byte(5);
            w.add_int(*d);
        }
        Sum::Party(p) => {
            w.add_byte(6);
            w.add_string(p);
        }
        Sum::Text(t) => {
            w.add_byte(7);
            w.add_string(t);
        }
        Sum::ContractId(cid) => {
            w.add_byte(8);
            add_cid(w, cid)?;
        }
        Sum::Optional(opt) => {
            w.add_byte(9);
            w.add_optional(opt.value.as_deref(), |w, inner| {
                add_typed_value(w, inner, depth + 1)
            })?;
        }
        Sum::List(list) => {
            w.add_byte(10);
            w.add_int(list.elements.len() as i32);
            for elem in &list.elements {
                add_typed_value(w, elem, depth + 1)?;
            }
        }
        Sum::TextMap(tm) => {
            w.add_byte(11);
            // `FrontStackMap.from` sorts and deduplicates entries by UTF-16 string key (last wins).
            let mut entries: HashMap<&str, &lapi::Value> = HashMap::with_capacity(tm.entries.len());
            for e in &tm.entries {
                let v = e
                    .value
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("TextMap.Entry.value"))?;
                entries.insert(e.key.as_str(), v);
            }
            let mut sorted: Vec<(&str, &lapi::Value)> = entries.into_iter().collect();
            sorted.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
            w.add_int(sorted.len() as i32);
            for (k, v) in sorted {
                w.add_string(k);
                add_typed_value(w, v, depth + 1)?;
            }
        }
        Sum::Record(rec) => {
            w.add_byte(12);
            w.add_optional(rec.record_id.as_ref(), add_identifier)?;
            w.add_int(rec.fields.len() as i32);
            for field in &rec.fields {
                let label = if field.label.is_empty() {
                    None
                } else {
                    Some(field.label.as_str())
                };
                w.add_optional(label, |w, l| {
                    w.add_string(l);
                    Ok(())
                })?;
                let v = field
                    .value
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("RecordField.value"))?;
                add_typed_value(w, v, depth + 1)?;
            }
        }
        Sum::Variant(var) => {
            w.add_byte(13);
            w.add_optional(var.variant_id.as_ref(), add_identifier)?;
            w.add_string(&var.constructor);
            let v = var
                .value
                .as_deref()
                .ok_or(PreparedHashError::MissingField("Variant.value"))?;
            add_typed_value(w, v, depth + 1)?;
        }
        Sum::Enum(en) => {
            w.add_byte(14);
            w.add_optional(en.enum_id.as_ref(), add_identifier)?;
            w.add_string(&en.constructor);
        }
        Sum::GenMap(gm) => {
            w.add_byte(15);
            w.add_int(gm.entries.len() as i32);
            for entry in &gm.entries {
                let k = entry
                    .key
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("GenMap.Entry.key"))?;
                let v = entry
                    .value
                    .as_ref()
                    .ok_or(PreparedHashError::MissingField("GenMap.Entry.value"))?;
                add_typed_value(w, k, depth + 1)?;
                add_typed_value(w, v, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// Canonicalize a Daml `Numeric` string matching `Numeric.fromString` + `Numeric.toString`.
/// Preserves the fractional scale (`"1.5000000000"` stays `"1.5000000000"`) while trimming
/// redundant leading integer zeros and normalizing zero-scale integers (`"5"` / `"-0."` -> `"5."` / `"0."`).
fn canonicalize_numeric(raw: &str) -> Result<String, PreparedHashError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(PreparedHashError::InvalidNumeric(raw.to_string()));
    }
    let (neg, unsigned) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    let (int_raw, dec_raw) = match unsigned.split_once('.') {
        Some((i, d)) => (i, d),
        None => (unsigned, ""),
    };
    if int_raw.is_empty()
        || !int_raw.bytes().all(|b| b.is_ascii_digit())
        || !dec_raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PreparedHashError::InvalidNumeric(raw.to_string()));
    }
    let int_trimmed = int_raw.trim_start_matches('0');
    let int_part = if int_trimmed.is_empty() {
        "0"
    } else {
        int_trimmed
    };
    let scale = dec_raw.len();
    let precision = if int_part == "0" {
        scale
    } else {
        int_part.len() + scale
    };
    if scale > 37 || precision > 38 {
        return Err(PreparedHashError::InvalidNumeric(raw.to_string()));
    }
    let is_zero = int_part == "0" && dec_raw.bytes().all(|b| b == b'0');
    let sign = if neg && !is_zero { "-" } else { "" };
    Ok(format!("{sign}{int_part}.{dec_raw}"))
}

#[derive(Eq, PartialEq)]
struct Utf16Str<'a>(&'a str);

impl Ord for Utf16Str<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        cmp_utf16(self.0, other.0)
    }
}

impl PartialOrd for Utf16Str<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

struct HashWriter {
    digest: Sha256,
}

impl HashWriter {
    fn new_without_purpose() -> Self {
        Self {
            digest: Sha256::new(),
        }
    }

    fn new_with_purpose(purpose_id: i32) -> Self {
        let mut w = Self::new_without_purpose();
        w.add_int(purpose_id);
        w
    }

    fn add_raw(&mut self, bytes: &[u8]) {
        self.digest.update(bytes);
    }

    fn add_byte(&mut self, b: u8) {
        self.digest.update([b]);
    }

    fn add_bool(&mut self, b: bool) {
        self.add_byte(if b { 1 } else { 0 });
    }

    fn add_int(&mut self, n: i32) {
        self.digest.update(n.to_be_bytes());
    }

    fn add_long(&mut self, n: i64) {
        self.digest.update(n.to_be_bytes());
    }

    fn add_byte_string(&mut self, bytes: &[u8]) {
        self.add_int(bytes.len() as i32);
        self.digest.update(bytes);
    }

    fn add_string(&mut self, s: &str) {
        self.add_byte_string(s.as_bytes());
    }

    fn add_hash(&mut self, hash: &[u8; 32]) {
        self.digest.update(hash);
    }

    fn add_string_set(&mut self, items: &[String]) {
        let sorted: BTreeSet<Utf16Str<'_>> = items.iter().map(|s| Utf16Str(s.as_str())).collect();
        self.add_int(sorted.len() as i32);
        for item in sorted {
            self.add_string(item.0);
        }
    }

    fn add_optional<T>(
        &mut self,
        opt: Option<T>,
        f: impl FnOnce(&mut Self, T) -> Result<(), PreparedHashError>,
    ) -> Result<(), PreparedHashError> {
        match opt {
            None => {
                self.add_byte(0);
                Ok(())
            }
            Some(v) => {
                self.add_byte(1);
                f(self, v)
            }
        }
    }

    fn finish(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}

/// Standard base64 encoder with `=` padding (reused by JSON API tests and HTTP responses).
pub fn encode_base64(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Strict standard base64 decoder.
pub fn decode_base64(input: &str) -> Result<Vec<u8>, PreparedHashError> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = input.trim();
    if !s.len().is_multiple_of(4) {
        return Err(PreparedHashError::Decode("invalid base64 length".into()));
    }
    let mut out = Vec::with_capacity((s.len() / 4) * 3);
    for chunk in s.as_bytes().chunks(4) {
        let pad = chunk.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 {
            return Err(PreparedHashError::Decode("invalid base64 padding".into()));
        }
        let mut vals = [0u32; 4];
        for (i, &b) in chunk.iter().enumerate() {
            if i >= 4 - pad {
                if b != b'=' {
                    return Err(PreparedHashError::Decode("non-trailing '='".into()));
                }
                vals[i] = 0;
            } else {
                vals[i] = B64
                    .iter()
                    .position(|&x| x == b)
                    .ok_or_else(|| PreparedHashError::Decode("invalid base64 byte".into()))?
                    as u32;
            }
        }
        let word = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((word >> 16) as u8);
        if pad < 2 {
            out.push((word >> 8) as u8);
        }
        if pad < 1 {
            out.push(word as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_json_string(json_text: &str, key: &str) -> String {
        let needle = format!("\"{key}\": \"");
        let start = json_text
            .find(&needle)
            .unwrap_or_else(|| panic!("missing key {key} in fixture"))
            + needle.len();
        let end = json_text[start..]
            .find('"')
            .expect("unterminated json string")
            + start;
        json_text[start..end].to_string()
    }

    #[test]
    fn prepared_create_prober_matches_canton_v2_oracle_and_rejects_tampers() {
        let fixture = include_str!(
            "../../../../tests/oracle/interactive-prepare/prepared-create-prober.json"
        );
        let tx_b64 = extract_json_string(fixture, "preparedTransaction");
        let expected_hash_b64 = extract_json_string(fixture, "preparedTransactionHash");

        let raw = decode_base64(&tx_b64).expect("base64 preparedTransaction");
        let computed =
            hash_prepared_transaction_bytes(&raw, HashingSchemeVersion::V2).expect("v2 hash");
        assert_eq!(encode_base64(&computed), expected_hash_b64);

        // Negative control 1: mutating a single field inside Create.argument changes hash.
        let mut prepared = PreparedTransaction::decode(raw.as_slice()).unwrap();
        let original = prepared.clone();
        if let Some(tx) = prepared.transaction.as_mut() {
            if let Some(VersionedNode::V1(node)) = tx.nodes[0].versioned_node.as_mut() {
                if let Some(NodeType::Create(c)) = node.node_type.as_mut() {
                    if let Some(lapi::value::Sum::Record(r)) =
                        c.argument.as_mut().and_then(|v| v.sum.as_mut())
                    {
                        r.fields[0].value = Some(lapi::Value {
                            sum: Some(lapi::value::Sum::Party("tampered::1220abcd".into())),
                        });
                    }
                }
            }
        }
        let mutated_arg = hash_prepared_transaction(&prepared, HashingSchemeVersion::V2).unwrap();
        assert_ne!(mutated_arg, computed);

        // Negative control 2: mutating metadata command_id changes hash.
        prepared = original.clone();
        prepared
            .metadata
            .as_mut()
            .unwrap()
            .submitter_info
            .as_mut()
            .unwrap()
            .command_id
            .push_str("-tamper");
        let mutated_cmd = hash_prepared_transaction(&prepared, HashingSchemeVersion::V2).unwrap();
        assert_ne!(mutated_cmd, computed);

        // Negative control 3: mutating node_seed changes hash.
        prepared = original.clone();
        prepared.transaction.as_mut().unwrap().node_seeds[0].seed[0] ^= 0xff;
        let mutated_seed = hash_prepared_transaction(&prepared, HashingSchemeVersion::V2).unwrap();
        assert_ne!(mutated_seed, computed);

        // Negative control 4: V2 rejects LF serialization version "2" (contract keys) while V3 hashes it.
        prepared = original;
        prepared.transaction.as_mut().unwrap().version = "2".into();
        let err = hash_prepared_transaction(&prepared, HashingSchemeVersion::V2).unwrap_err();
        assert!(matches!(
            err,
            PreparedHashError::UnsupportedSerializationVersion { scheme: "V2", .. }
        ));
        assert!(hash_prepared_transaction(&prepared, HashingSchemeVersion::V3).is_ok());

        // Negative control 5: hashing the same tx under V3 gives a different digest than V2.
        let mut prepared_v2_1 = PreparedTransaction::decode(raw.as_slice()).unwrap();
        let h_v3 = hash_prepared_transaction(&prepared_v2_1, HashingSchemeVersion::V3).unwrap();
        assert_ne!(h_v3, computed);

        // Negative control 6: V3 includes max_record_time in metadata hash.
        prepared_v2_1.metadata.as_mut().unwrap().max_record_time = Some(123_456_789);
        let h_v3_mrt = hash_prepared_transaction(&prepared_v2_1, HashingSchemeVersion::V3).unwrap();
        assert_ne!(h_v3_mrt, h_v3);
    }

    #[test]
    fn numeric_canonicalization_matches_lf_to_string() {
        assert_eq!(
            canonicalize_numeric("1.5000000000").unwrap(),
            "1.5000000000"
        );
        assert_eq!(canonicalize_numeric("5").unwrap(), "5.");
        assert_eq!(canonicalize_numeric("-0.0").unwrap(), "0.0");
        assert_eq!(canonicalize_numeric("+0042.10").unwrap(), "42.10");
        assert!(canonicalize_numeric("abc").is_err());
    }

    fn extract_case_block<'a>(json_text: &'a str, case_name: &str) -> &'a str {
        let marker = format!("\"{case_name}\": {{");
        let start = json_text
            .find(&marker)
            .unwrap_or_else(|| panic!("missing case {case_name} in fixture"));
        &json_text[start..]
    }

    #[test]
    fn canton_372_interactive_matrix_v2_and_v3_hashes_match_oracle() {
        let fixture = include_str!(
            "../../../../tests/oracle/interactive-prepare/canton-3.7.2-interactive-matrix.json"
        );
        let cases = [
            ("v2CreateNoteAndExecuteTx", HashingSchemeVersion::V2),
            ("v2ExerciseBumpAndExecuteWait", HashingSchemeVersion::V2),
            ("v2RbEnsure", HashingSchemeVersion::V2),
            ("v2DisclosedInputContract", HashingSchemeVersion::V2),
            ("v3CreateNoteWithMaxRecordTime", HashingSchemeVersion::V3),
            ("v3RollbackNonConsuming", HashingSchemeVersion::V3),
            ("v3CreateKeyedItem", HashingSchemeVersion::V3),
            ("v3ExpiredMaxRecordTime", HashingSchemeVersion::V3),
            ("v2MaxRecordTime", HashingSchemeVersion::V2),
        ];
        for (name, scheme) in cases {
            let block = extract_case_block(fixture, name);
            let tx_b64 = extract_json_string(block, "preparedTransaction");
            let expected_hash_b64 = extract_json_string(block, "preparedTransactionHash");
            let scheme_str = extract_json_string(block, "hashingSchemeVersion");
            let expected_scheme = match scheme {
                HashingSchemeVersion::V2 => "HASHING_SCHEME_VERSION_V2",
                HashingSchemeVersion::V3 => "HASHING_SCHEME_VERSION_V3",
                HashingSchemeVersion::Unspecified | HashingSchemeVersion::V4 => unreachable!(),
            };
            assert_eq!(scheme_str, expected_scheme, "case {name} scheme mismatch");

            let raw = decode_base64(&tx_b64).expect("base64 preparedTransaction");
            let computed =
                hash_prepared_transaction_bytes(&raw, scheme).expect("prepared hash compute");
            assert_eq!(
                encode_base64(&computed),
                expected_hash_b64,
                "case {name} digest mismatch"
            );
        }

        // Negative control A: mutating metadata input_contracts alters V2 disclosed-contract hash.
        let disclosed_raw = decode_base64(&extract_json_string(
            extract_case_block(fixture, "v2DisclosedInputContract"),
            "preparedTransaction",
        ))
        .unwrap();
        let disclosed_base =
            hash_prepared_transaction_bytes(&disclosed_raw, HashingSchemeVersion::V2).unwrap();
        let mut disclosed = PreparedTransaction::decode(disclosed_raw.as_slice()).unwrap();
        let inputs = &mut disclosed.metadata.as_mut().unwrap().input_contracts;
        assert!(
            !inputs.is_empty(),
            "expected input_contracts in v2DisclosedInputContract"
        );
        inputs[0].created_at += 1;
        assert_ne!(
            hash_prepared_transaction(&disclosed, HashingSchemeVersion::V2).unwrap(),
            disclosed_base
        );

        // Negative control B: mutating Rollback children alters V3 rollback hash.
        let rollback_raw = decode_base64(&extract_json_string(
            extract_case_block(fixture, "v3RollbackNonConsuming"),
            "preparedTransaction",
        ))
        .unwrap();
        let rollback_base =
            hash_prepared_transaction_bytes(&rollback_raw, HashingSchemeVersion::V3).unwrap();
        let mut rollback_tx = PreparedTransaction::decode(rollback_raw.as_slice()).unwrap();
        let mut touched_rollback = false;
        if let Some(tx) = rollback_tx.transaction.as_mut() {
            for node in &mut tx.nodes {
                if let Some(VersionedNode::V1(v1)) = node.versioned_node.as_mut() {
                    if let Some(NodeType::Rollback(rb)) = v1.node_type.as_mut() {
                        let first = rb.children.first().cloned().expect("rollback child");
                        rb.children.push(first);
                        touched_rollback = true;
                        break;
                    }
                }
            }
        }
        assert!(
            touched_rollback,
            "expected Rollback node in v3RollbackNonConsuming"
        );
        assert_ne!(
            hash_prepared_transaction(&rollback_tx, HashingSchemeVersion::V3).unwrap(),
            rollback_base
        );

        // Negative control C: mutating global_key_mapping alters V3 keyed hash.
        let keyed_raw = decode_base64(&extract_json_string(
            extract_case_block(fixture, "v3CreateKeyedItem"),
            "preparedTransaction",
        ))
        .unwrap();
        let keyed_base =
            hash_prepared_transaction_bytes(&keyed_raw, HashingSchemeVersion::V3).unwrap();
        let mut keyed_tx = PreparedTransaction::decode(keyed_raw.as_slice()).unwrap();
        if let Some(tx) = keyed_tx.transaction.as_mut() {
            for node in &mut tx.nodes {
                if let Some(VersionedNode::V1(v1)) = node.versioned_node.as_mut() {
                    if let Some(NodeType::Create(c)) = v1.node_type.as_mut() {
                        if let Some(k) = c.key.as_mut() {
                            k.maintainers.push("extra::1220deadbeef".into());
                        }
                    }
                }
            }
        }
        assert_ne!(
            hash_prepared_transaction(&keyed_tx, HashingSchemeVersion::V3).unwrap(),
            keyed_base
        );
        let mut keyed_hash_mut = PreparedTransaction::decode(keyed_raw.as_slice()).unwrap();
        let mut mutated_key_hash = false;
        if let Some(tx) = keyed_hash_mut.transaction.as_mut() {
            for node in &mut tx.nodes {
                if let Some(VersionedNode::V1(v1)) = node.versioned_node.as_mut() {
                    if let Some(NodeType::Create(c)) = v1.node_type.as_mut() {
                        if let Some(k) = c.key.as_mut().and_then(|gkm| gkm.key.as_mut()) {
                            k.hash[0] ^= 0xff;
                            mutated_key_hash = true;
                        }
                    }
                }
            }
        }
        assert!(mutated_key_hash, "expected GlobalKey on Create.key");
        assert_ne!(
            hash_prepared_transaction(&keyed_hash_mut, HashingSchemeVersion::V3).unwrap(),
            keyed_base
        );
        // Hashing V3 keyed LF V2 tx under V2 scheme is rejected just as Canton 3.7.2 does.
        assert!(matches!(
            hash_prepared_transaction_bytes(&keyed_raw, HashingSchemeVersion::V2),
            Err(PreparedHashError::UnsupportedSerializationVersion { scheme: "V2", .. })
        ));

        // Negative control D: V2 ignores max_record_time while V3 commits max_record_time.
        let v2_mrt_raw = decode_base64(&extract_json_string(
            extract_case_block(fixture, "v2MaxRecordTime"),
            "preparedTransaction",
        ))
        .unwrap();
        let v2_mrt_base =
            hash_prepared_transaction_bytes(&v2_mrt_raw, HashingSchemeVersion::V2).unwrap();
        let mut v2_mrt_tx = PreparedTransaction::decode(v2_mrt_raw.as_slice()).unwrap();
        let meta = v2_mrt_tx.metadata.as_mut().unwrap();
        assert!(meta.max_record_time.is_some());
        meta.max_record_time = meta.max_record_time.map(|t| t + 5_000_000);
        assert_eq!(
            hash_prepared_transaction(&v2_mrt_tx, HashingSchemeVersion::V2).unwrap(),
            v2_mrt_base
        );

        let v3_mrt_raw = decode_base64(&extract_json_string(
            extract_case_block(fixture, "v3CreateNoteWithMaxRecordTime"),
            "preparedTransaction",
        ))
        .unwrap();
        let v3_mrt_base =
            hash_prepared_transaction_bytes(&v3_mrt_raw, HashingSchemeVersion::V3).unwrap();
        let mut v3_mrt_tx = PreparedTransaction::decode(v3_mrt_raw.as_slice()).unwrap();
        let meta3 = v3_mrt_tx.metadata.as_mut().unwrap();
        meta3.max_record_time = meta3.max_record_time.map(|t| t + 5_000_000);
        assert_ne!(
            hash_prepared_transaction(&v3_mrt_tx, HashingSchemeVersion::V3).unwrap(),
            v3_mrt_base
        );
    }
}
