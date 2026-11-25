//! Serializable snapshot representations (`*Repr`) and key spec encodings.

use std::collections::{BTreeMap, HashMap};

use canton_algo::signing::{KeyFormat, KeySpec, Usage};
use lf_eval::tx_model::NodeId;
use lf_eval::{BigNumericValue, List, Value};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::models::ledger_api::{TemplateId, TransactionTree};
use crate::service::{DarPackageInfo, GenericContract};
use crate::v2::PartyMeta;
use crate::v2_idps::IdpRec;
use crate::v2_packages::PackageRec;
use crate::v2_users::UserRec;

#[derive(Serialize, Deserialize)]
pub(super) enum ValueRepr {
    Int64(i64),
    Numeric {
        coeff: i128,
        scale: u8,
    },
    BigNumeric {
        coeff_le: Vec<u8>,
        scale: i32,
    },
    Text(String),
    Party(String),
    ContractId(String),
    Bool(bool),
    Unit,
    List(Vec<ValueRepr>),
    Optional(Option<Box<ValueRepr>>),
    Record {
        tycon: Option<String>,
        fields: Vec<(String, ValueRepr)>,
    },
    Variant {
        tycon: Option<String>,
        constructor: String,
        value: Box<ValueRepr>,
    },
    Enum {
        tycon: Option<String>,
        constructor: String,
    },
    Struct(Vec<(String, ValueRepr)>),
    AnyException {
        tycon: String,
        payload: Box<ValueRepr>,
    },
    Any {
        key: String,
        payload: Box<ValueRepr>,
    },
    TypeRep {
        key: String,
        tycon: Option<String>,
    },
    Map(Vec<(ValueRepr, ValueRepr)>),
    Iface {
        package_id: String,
        template: String,
        payload: Box<ValueRepr>,
    },
}

impl ValueRepr {
    pub(super) fn from_value(v: &Value) -> Result<Self, String> {
        Ok(match v {
            Value::Int64(n) => Self::Int64(*n),
            Value::Numeric { coeff, scale } => Self::Numeric {
                coeff: *coeff,
                scale: *scale,
            },
            Value::BigNumeric(bn) => {
                let (coeff_le, scale) = bn.to_signed_bytes_le();
                Self::BigNumeric { coeff_le, scale }
            }
            Value::Text(s) => Self::Text(s.clone()),
            Value::Party(p) => Self::Party(p.clone()),
            Value::ContractId(c) => Self::ContractId(c.clone()),
            Value::Bool(b) => Self::Bool(*b),
            Value::Unit => Self::Unit,
            Value::List(l) => Self::List(
                l.iter()
                    .map(Self::from_value)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Value::Optional(o) => Self::Optional(
                o.as_deref()
                    .map(Self::from_value)
                    .transpose()?
                    .map(Box::new),
            ),
            Value::Record { tycon, fields } => Self::Record {
                tycon: tycon.clone(),
                fields: fields
                    .iter()
                    .map(|(k, val)| Ok((k.clone(), Self::from_value(val)?)))
                    .collect::<Result<Vec<_>, String>>()?,
            },
            Value::Variant {
                tycon,
                constructor,
                value,
                ..
            } => Self::Variant {
                tycon: tycon.clone(),
                constructor: constructor.clone(),
                value: Box::new(Self::from_value(value)?),
            },
            Value::Enum {
                tycon, constructor, ..
            } => Self::Enum {
                tycon: tycon.clone(),
                constructor: constructor.clone(),
            },
            Value::Struct(fields) => Self::Struct(
                fields
                    .iter()
                    .map(|(k, val)| Ok((k.clone(), Self::from_value(val)?)))
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            Value::AnyException { tycon, payload } => Self::AnyException {
                tycon: tycon.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::Any { key, payload } => Self::Any {
                key: key.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::TypeRep { key, tycon } => Self::TypeRep {
                key: key.clone(),
                tycon: tycon.clone(),
            },
            Value::Map(entries) => Self::Map(
                entries
                    .iter()
                    .map(|(k, val)| Ok((Self::from_value(k)?, Self::from_value(val)?)))
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            Value::Iface {
                package_id,
                template,
                payload,
            } => Self::Iface {
                package_id: package_id.clone(),
                template: template.clone(),
                payload: Box::new(Self::from_value(payload)?),
            },
            Value::Partial { .. }
            | Value::Closure { .. }
            | Value::TyClosure { .. }
            | Value::Action { .. }
            | Value::KeyFn { .. }
            | Value::KeyAction { .. } => {
                return Err("cannot snapshot unevaluated closure or action value".into());
            }
        })
    }

    pub(super) fn into_value(self) -> Result<Value, String> {
        Ok(match self {
            Self::Int64(n) => Value::Int64(n),
            Self::Numeric { coeff, scale } => Value::Numeric { coeff, scale },
            Self::BigNumeric { coeff_le, scale } => {
                let bn = BigNumericValue::from_signed_bytes_le(&coeff_le, scale)
                    .map_err(|e| format!("invalid BigNumeric in snapshot: {e}"))?;
                Value::BigNumeric(bn)
            }
            Self::Text(s) => Value::Text(s),
            Self::Party(p) => Value::Party(p),
            Self::ContractId(c) => Value::ContractId(c),
            Self::Bool(b) => Value::Bool(b),
            Self::Unit => Value::Unit,
            Self::List(items) => {
                let vals = items
                    .into_iter()
                    .map(Self::into_value)
                    .collect::<Result<Vec<_>, _>>()?;
                Value::List(List::new().prepend_all(vals))
            }
            Self::Optional(o) => {
                Value::Optional(o.map(|v| v.into_value().map(Box::new)).transpose()?)
            }
            Self::Record { tycon, fields } => Value::Record {
                tycon,
                fields: fields
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.into_value()?)))
                    .collect::<Result<Vec<_>, String>>()?,
            },
            Self::Variant {
                tycon,
                constructor,
                value,
            } => Value::Variant {
                tycon,
                constructor,
                rank: lf_eval::CtorRank::default(),
                value: Box::new(value.into_value()?),
            },
            Self::Enum { tycon, constructor } => Value::Enum {
                tycon,
                constructor,
                rank: lf_eval::CtorRank::default(),
            },
            Self::Struct(fields) => Value::Struct(
                fields
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.into_value()?)))
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            Self::AnyException { tycon, payload } => Value::AnyException {
                tycon,
                payload: Box::new(payload.into_value()?),
            },
            Self::Any { key, payload } => Value::Any {
                key,
                payload: Box::new(payload.into_value()?),
            },
            Self::TypeRep { key, tycon } => Value::TypeRep { key, tycon },
            Self::Map(entries) => Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| Ok((k.into_value()?, v.into_value()?)))
                    .collect::<Result<Vec<_>, String>>()?,
            ),
            Self::Iface {
                package_id,
                template,
                payload,
            } => Value::Iface {
                package_id,
                template,
                payload: Box::new(payload.into_value()?),
            },
        })
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct HoldingRepr {
    pub(super) bank: String,
    pub(super) owner: String,
    pub(super) auditor: String,
    pub(super) symbol: String,
    pub(super) tenths: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct SingleContractLedgerRepr {
    pub(super) contracts: Vec<Option<HoldingRepr>>,
    pub(super) contract_ids: Vec<String>,
    pub(super) submission_count: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) enum TxNodeRepr {
    Create {
        contract_id: String,
        template_id: String,
        payload: Vec<u8>,
        signatories: Vec<String>,
        observers: Vec<String>,
        key: Option<String>,
    },
    Exercise {
        contract_id: String,
        choice: String,
        acting_parties: Vec<String>,
        consuming: bool,
        children: Vec<NodeId>,
    },
    Fetch {
        contract_id: String,
        template_id: String,
        stakeholders: Vec<String>,
    },
    LookupByKey {
        template_id: String,
        key: String,
        found: Option<String>,
    },
    Rollback {
        children: Vec<NodeId>,
    },
}

#[derive(Serialize, Deserialize)]
pub(super) struct LfTxTreeRepr {
    pub(super) roots: Vec<NodeId>,
    pub(super) nodes: Vec<(NodeId, TxNodeRepr)>,
    pub(super) next_node_id: NodeId,
}

#[derive(Serialize, Deserialize)]
pub(super) struct TxActiveContractRepr {
    pub(super) template_id: String,
    pub(super) payload: Vec<u8>,
    pub(super) stakeholders: Vec<String>,
    pub(super) key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ActiveStateRepr {
    pub(super) active_contracts: Vec<(String, TxActiveContractRepr)>,
    pub(super) keys: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct JournalEntryRepr {
    pub(super) offset: u64,
    pub(super) tx: LfTxTreeRepr,
    pub(super) act_as: Vec<String>,
    pub(super) timestamp_micros: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct LedgerJournalRepr {
    pub(super) entries: Vec<JournalEntryRepr>,
    pub(super) next_offset: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct DedupEntryRepr {
    pub(super) submission_time: u64,
    pub(super) expiry_time: u64,
    pub(super) offset: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct GenericContractRepr {
    contract_id: String,
    package_id: String,
    template_id: TemplateId,
    payload_value: ValueRepr,
    json_payload: Json,
    signatories: Vec<String>,
    observers: Vec<String>,
    witness_parties: Vec<String>,
    active: bool,
    key_value: Option<ValueRepr>,
    created_at_micros: i64,
    created_event_blob: String,
    contract_key_hash: String,
    key_maintainers: Vec<String>,
    creation_seq: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ExInfoRepr {
    pub(super) choice: String,
    pub(super) argument: Json,
    pub(super) argument_value: Option<ValueRepr>,
    pub(super) acting: Vec<String>,
    pub(super) consuming: bool,
    pub(super) result: Json,
    pub(super) result_value: Option<ValueRepr>,
    pub(super) last_descendant: u64,
    #[serde(default)]
    pub(super) interface_id: Option<String>,
    #[serde(default)]
    pub(super) choice_observers: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct EvRepr {
    pub(super) contract: GenericContractRepr,
    pub(super) created: bool,
    pub(super) node: u64,
    pub(super) exercise: Option<ExInfoRepr>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StoredUpdateRepr {
    pub(super) update_id: String,
    pub(super) offset: u64,
    pub(super) command_id: String,
    pub(super) effective_at: String,
    pub(super) events: Vec<EvRepr>,
    pub(super) at_micros: i64,
    pub(super) external_transaction_hash: Option<String>,
    /// Set for a reassignment update (no events); absent in snapshots written before reassignments were kept.
    #[serde(default)]
    pub(super) reassignment: Option<ReassignmentRepr>,
    /// Set for a topology transaction update (no events); absent in older snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) topology: Option<crate::v2_topology_events::StoredTopologyTransaction>,
    /// The submission's W3C `traceparent`; absent before it was kept, and when the command named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) trace_parent: Option<String>,
    /// Submitters (`actAs`) of the local command, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) act_as: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ReassignmentRepr {
    unassign: bool,
    reassignment_id: String,
    contract_id: String,
    source: String,
    target: String,
    counter: i64,
    record_time_micros: i64,
    submitter: String,
    witnesses: Vec<String>,
}

impl ReassignmentRepr {
    pub(super) fn from_stored(r: &crate::v2_reassign::StoredReassignment) -> Self {
        Self {
            unassign: r.unassign,
            reassignment_id: r.outcome.reassignment_id.clone(),
            contract_id: r.outcome.contract_id.clone(),
            source: r.outcome.source.clone(),
            target: r.outcome.target.clone(),
            counter: r.outcome.counter,
            record_time_micros: r.outcome.record_time_micros,
            submitter: r.submitter.clone(),
            witnesses: r.witnesses.clone(),
        }
    }

    pub(super) fn into_stored(self) -> crate::v2_reassign::StoredReassignment {
        crate::v2_reassign::StoredReassignment {
            unassign: self.unassign,
            outcome: crate::service::ReassignOutcome {
                reassignment_id: self.reassignment_id,
                contract_id: self.contract_id,
                source: self.source,
                target: self.target,
                counter: self.counter,
                record_time_micros: self.record_time_micros,
            },
            submitter: self.submitter,
            witnesses: self.witnesses,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct CompletionRepr {
    pub(super) offset: u64,
    pub(super) update_id: String,
    pub(super) command_id: String,
    pub(super) user_id: String,
    pub(super) submission_id: String,
    pub(super) act_as: Vec<String>,
    pub(super) record_time: String,
    pub(super) transaction_hash: Option<String>,
    pub(super) status_code: i32,
    pub(super) status_message: String,
    #[serde(default)]
    pub(super) refusal: Option<String>,
    /// The submission's W3C `traceparent`; absent before it was kept, and when the command named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) trace_parent: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct PublicKeyRepr {
    pub(super) key_spec: u8,
    pub(super) format: u8,
    pub(super) usage: Vec<u8>,
    pub(super) key: Vec<u8>,
    pub(super) id: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ExternalPartyRepr {
    pub(super) party_id: String,
    pub(super) fingerprint: String,
    pub(super) keys: Vec<PublicKeyRepr>,
    pub(super) threshold: u32,
    pub(super) synchronizer_id: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct V2StateRepr {
    pub(super) participant: String,
    pub(super) parties: Vec<String>,
    pub(super) ledger_end: u64,
    pub(super) updates: Vec<StoredUpdateRepr>,
    pub(super) packages: BTreeMap<String, PackageRec>,
    pub(super) party_meta: PartyMeta,
    pub(super) completions: Vec<CompletionRepr>,
    pub(super) dedup: Vec<((String, String, Vec<String>), (u64, i64, String))>,
    pub(super) vetting_serial: u64,
    pub(super) idps: BTreeMap<String, IdpRec>,
    pub(super) users: BTreeMap<String, UserRec>,
    pub(super) submission_seq: u64,
    pub(super) pruned_up_to: u64,
    pub(super) max_dedup_micros: i64,
    pub(super) acs_safe_to_prune_micros: Option<i64>,
    pub(super) external_parties: HashMap<String, ExternalPartyRepr>,
    pub(super) synchronizer: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ExecutionCheckpointRepr {
    pub(super) format_version: u32,
    pub(super) ledger: SingleContractLedgerRepr,
    pub(super) active_state: ActiveStateRepr,
    pub(super) journal: LedgerJournalRepr,
    pub(super) dedup_store: Vec<((String, String), DedupEntryRepr)>,
    pub(super) update_stream: Vec<TransactionTree>,
    pub(super) offset_counter: u64,
    pub(super) event_counter: u64,
    pub(super) contract_counter: u64,
    pub(super) dar_info: Option<DarPackageInfo>,
    pub(super) package_names: Vec<(String, String, String)>,
    pub(super) dar_blobs: Vec<Vec<u8>>,
    pub(super) clock: u64,
    pub(super) consumed_at: HashMap<String, u64>,
    pub(super) generic_contracts: HashMap<String, GenericContractRepr>,
    pub(super) creation_seq_counter: u64,
    pub(super) v2: V2StateRepr,
}

impl GenericContractRepr {
    pub(super) fn from_contract(c: &GenericContract) -> Result<Self, String> {
        let GenericContract {
            contract_id,
            package_id,
            template_id,
            payload_value,
            json_payload,
            signatories,
            observers,
            witness_parties,
            active,
            key_value,
            created_at_micros,
            created_event_blob,
            contract_key_hash,
            key_maintainers,
            creation_seq,
        } = c;
        Ok(Self {
            contract_id: contract_id.clone(),
            package_id: package_id.clone(),
            template_id: template_id.clone(),
            payload_value: ValueRepr::from_value(payload_value)?,
            json_payload: json_payload.clone(),
            signatories: signatories.clone(),
            observers: observers.clone(),
            witness_parties: witness_parties.clone(),
            active: *active,
            key_value: key_value.as_ref().map(ValueRepr::from_value).transpose()?,
            created_at_micros: *created_at_micros,
            created_event_blob: created_event_blob.clone(),
            contract_key_hash: contract_key_hash.clone(),
            key_maintainers: key_maintainers.clone(),
            creation_seq: *creation_seq,
        })
    }

    pub(super) fn into_contract(self) -> Result<GenericContract, String> {
        Ok(GenericContract {
            contract_id: self.contract_id,
            package_id: self.package_id,
            template_id: self.template_id,
            payload_value: self.payload_value.into_value()?,
            json_payload: self.json_payload,
            signatories: self.signatories,
            observers: self.observers,
            witness_parties: self.witness_parties,
            active: self.active,
            key_value: self.key_value.map(ValueRepr::into_value).transpose()?,
            created_at_micros: self.created_at_micros,
            created_event_blob: self.created_event_blob,
            contract_key_hash: self.contract_key_hash,
            key_maintainers: self.key_maintainers,
            creation_seq: self.creation_seq,
        })
    }
}

pub(super) fn encode_key_spec(s: KeySpec) -> u8 {
    match s {
        KeySpec::EcCurve25519 => 1,
        KeySpec::EcP256 => 2,
        KeySpec::EcP384 => 3,
        KeySpec::EcSecp256k1 => 4,
        KeySpec::MlDsa65 => 5,
    }
}

pub(super) fn decode_key_spec(v: u8) -> Result<KeySpec, String> {
    match v {
        1 => Ok(KeySpec::EcCurve25519),
        2 => Ok(KeySpec::EcP256),
        3 => Ok(KeySpec::EcP384),
        4 => Ok(KeySpec::EcSecp256k1),
        5 => Ok(KeySpec::MlDsa65),
        other => Err(format!("unknown KeySpec tag {other}")),
    }
}

pub(super) fn encode_key_format(f: KeyFormat) -> u8 {
    match f {
        KeyFormat::Der => 1,
        KeyFormat::Raw => 2,
        KeyFormat::DerX509Spki => 3,
        KeyFormat::DerPkcs8Pki => 4,
        KeyFormat::Symbolic => 5,
    }
}

pub(super) fn decode_key_format(v: u8) -> Result<KeyFormat, String> {
    match v {
        1 => Ok(KeyFormat::Der),
        2 => Ok(KeyFormat::Raw),
        3 => Ok(KeyFormat::DerX509Spki),
        4 => Ok(KeyFormat::DerPkcs8Pki),
        5 => Ok(KeyFormat::Symbolic),
        other => Err(format!("unknown KeyFormat tag {other}")),
    }
}

pub(super) fn encode_usage(u: Usage) -> u8 {
    match u {
        Usage::Namespace => 1,
        Usage::SequencerAuthentication => 2,
        Usage::Protocol => 3,
        Usage::ProofOfOwnership => 4,
    }
}

pub(super) fn decode_usage(v: u8) -> Result<Usage, String> {
    match v {
        1 => Ok(Usage::Namespace),
        2 => Ok(Usage::SequencerAuthentication),
        3 => Ok(Usage::Protocol),
        4 => Ok(Usage::ProofOfOwnership),
        other => Err(format!("unknown Usage tag {other}")),
    }
}
