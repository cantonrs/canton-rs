//! A contract instance as the transaction protocol serializes it: the Daml-LF `FatContractInstance` (G5 5.6d, S-NET-008).
//!
//! [CANTON-NOTE: SEMANTICS] Read from `ContractInstanceCoder`/`ValueCoder` of the Canton 3.7.2 sources:
//! - The instance is a `FatContractInstance` message wrapped in `Versioned { version = "2.1", payload }`: the serialization version
//!   of a contract **without a key** is V1, which the coder writes as "2.1" (`SerializationVersion.assign(hasKey)`: V2, written "2", only with a key).
//! - `create_arg` is the **bare `Value` message** (no version of its own); a record is a list of fields **without labels**.
//! - `non_maintainer_signatories` and `non_signatory_stakeholders` are the sorted differences (signatories minus the key
//!   maintainers, stakeholders minus the signatories); `created_at` is the ledger time in microseconds (`sfixed64`).
//! - `package_version` (field 9) is not written by this coder.
//!
//! [CANTON-NOTE: LIMITATION] No contract key, and only unit/bool/int64/text/party/list/record values.
use canton_proto::com::digitalasset::daml::lf::transaction::{
    FatContractInstance, KeyWithMaintainers, Versioned,
};
use canton_proto::com::digitalasset::daml::lf::value::{
    value::{self, Sum},
    Identifier, Value,
};
use prost::Message;
use std::collections::BTreeSet;

/// The serialization version string of protocol version 37's contracts.
pub const SERIALIZATION_VERSION: &str = "2.1";

/// A Daml-LF value (the subset the tests need).
#[derive(Debug, Clone, PartialEq)]
pub enum LfValue {
    Unit,
    Bool(bool),
    Int64(i64),
    Text(String),
    Party(String),
    /// A contract id as the hex of its bytes (a choice argument that names a contract).
    ContractId(String),
    /// The text of the number **at the full scale of its type** (`Numeric 10`: `100.5000000000`, `-3.2500000000`), as the LF coder
    /// writes it (measured: the coder does not strip trailing zeros).
    Numeric(String),
    List(Vec<LfValue>),
    /// Fields in declaration order; the labels are not serialized.
    Record(Vec<LfValue>),
    /// Days since the epoch.
    Date(i32),
    /// Microseconds since the epoch.
    Timestamp(i64),
    Optional(Option<Box<LfValue>>),
    /// The constructor's name and its value (no variant id is serialized).
    Variant(String, Box<LfValue>),
    Enum(String),
    /// Entries in the map's order (sorted by key).
    TextMap(Vec<(String, LfValue)>),
    GenMap(Vec<(LfValue, LfValue)>),
}

impl LfValue {
    fn to_proto(&self) -> Value {
        let sum = match self {
            LfValue::Unit => Sum::Unit(()),
            LfValue::Bool(b) => Sum::Bool(*b),
            LfValue::Int64(i) => Sum::Int64(*i),
            LfValue::Text(t) => Sum::Text(t.clone()),
            LfValue::Party(p) => Sum::Party(p.clone()),
            LfValue::ContractId(id) => {
                Sum::ContractId(hex::decode(id).expect("a contract id is hex"))
            }
            LfValue::Numeric(n) => Sum::Numeric(n.clone()),
            LfValue::List(items) => Sum::List(value::List {
                elements: items.iter().map(LfValue::to_proto).collect(),
            }),
            // [CANTON-NOTE: SEMANTICS] A record is written without its trailing `None` fields (measured on the official scan's contract blobs,
            // S-SPL-008), so a contract of an older template version keeps its serialization.
            LfValue::Record(fields) => {
                let kept = fields
                    .iter()
                    .rposition(|f| !matches!(f, LfValue::Optional(None)))
                    .map_or(0, |i| i + 1);
                Sum::Record(value::Record {
                    fields: fields[..kept]
                        .iter()
                        .map(|f| value::record::Field {
                            value: Some(f.to_proto()),
                        })
                        .collect(),
                })
            }
            LfValue::Date(days) => Sum::Date(*days),
            LfValue::Timestamp(micros) => Sum::Timestamp(*micros),
            LfValue::Optional(inner) => Sum::Optional(Box::new(value::Optional {
                value: inner.as_ref().map(|v| Box::new(v.to_proto())),
            })),
            LfValue::Variant(constructor, inner) => Sum::Variant(Box::new(value::Variant {
                constructor: constructor.clone(),
                value: Some(Box::new(inner.to_proto())),
            })),
            LfValue::Enum(constructor) => Sum::Enum(value::Enum {
                value: constructor.clone(),
            }),
            LfValue::TextMap(entries) => Sum::TextMap(value::TextMap {
                entries: entries
                    .iter()
                    .map(|(k, v)| value::text_map::Entry {
                        key: k.clone(),
                        value: Some(v.to_proto()),
                    })
                    .collect(),
            }),
            LfValue::GenMap(entries) => Sum::Map(value::Map {
                entries: entries
                    .iter()
                    .map(|(k, v)| value::map::Entry {
                        key: Some(k.to_proto()),
                        value: Some(v.to_proto()),
                    })
                    .collect(),
            }),
        };
        Value { sum: Some(sum) }
    }

    /// The bare `Value` message bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }
}

/// The key of a contract: its value, its maintainers and the hash of the key (`contract_id::lf_contract_key_hash`).
pub struct ContractKey {
    pub value: LfValue,
    pub maintainers: Vec<String>,
    pub hash: [u8; 32],
}

/// A created contract, with everything the instance carries.
pub struct ContractInstance {
    /// The contract id bytes (`00` + discriminator + suffix for a V1 id).
    pub contract_id: Vec<u8>,
    pub package_name: String,
    pub package_id: String,
    pub module: Vec<String>,
    pub name: Vec<String>,
    pub arg: LfValue,
    pub signatories: BTreeSet<String>,
    pub stakeholders: BTreeSet<String>,
    pub created_at_micros: i64,
    pub authentication_data: Vec<u8>,
    /// `None` for a template without a key.
    pub key: Option<ContractKey>,
}

impl ContractInstance {
    /// The serialized, versioned instance (what `CreatedContract.contract` carries).
    pub fn encode(&self) -> Vec<u8> {
        let inner = FatContractInstance {
            contract_id: self.contract_id.clone(),
            package_name: self.package_name.clone(),
            package_version: Vec::new(),
            template_id: Some(Identifier {
                package_id: self.package_id.clone(),
                module_name: self.module.clone(),
                name: self.name.clone(),
            }),
            create_arg: self.arg.encode(),
            // [CANTON-NOTE: SEMANTICS] the signatories are split: the key maintainers are stated with the key, the others as
            // `non_maintainer_signatories` (all of them when there is no key)
            non_maintainer_signatories: self
                .signatories
                .iter()
                .filter(|s| !self.key.as_ref().is_some_and(|k| k.maintainers.contains(s)))
                .cloned()
                .collect(),
            non_signatory_stakeholders: self
                .stakeholders
                .difference(&self.signatories)
                .cloned()
                .collect(),
            created_at: self.created_at_micros,
            authentication_data: self.authentication_data.clone(),
            // the key value is encoded like the arguments (a bare `Value` message), the maintainers sorted
            contract_key_with_maintainers: self.key.as_ref().map(|k| {
                let mut maintainers = k.maintainers.clone();
                maintainers.sort();
                KeyWithMaintainers {
                    key: k.value.encode(),
                    maintainers,
                    hash: k.hash.to_vec(),
                }
            }),
        };
        // [CANTON-NOTE: SEMANTICS] A contract with a key is serialization version `2` (Daml-LF 2.3): the key hash field of
        // `KeyWithMaintainers` exists only from that version, and p1 refuses it inside a version `2.1` instance
        // ("unexpected hash field in KeyWithMaintainers for version V1"). A contract without a key stays `2.1`.
        let version = if self.key.is_some() {
            "2"
        } else {
            SERIALIZATION_VERSION
        };
        Versioned {
            version: version.to_string(),
            payload: inner.encode_to_vec(),
        }
        .encode_to_vec()
    }
}

/// The `authentication_data` of a V1 contract (`ContractAuthenticationDataV1.toLfBytes`): the contract salt, as a
/// `ContractAuthenticationData` message (v30) wrapped in `UntypedVersionedMessage` with version 30.
pub fn authentication_data(contract_salt: &[u8]) -> Vec<u8> {
    use canton_proto::com::digitalasset::canton::protocol::v30::ContractAuthenticationData;
    crate::topology_wire::versioned(
        ContractAuthenticationData {
            contract_salt: Some(crate::merkle_wire::wire_salt(contract_salt)),
        }
        .encode_to_vec(),
        30,
    )
}

/// The `authentication_data` (the contract salt message) of a serialized contract instance (`ContractInstance::encode`): what a scan's
/// `created_event_blob` carries besides the contract (S-SPL-010).
pub fn authentication_data_of(instance: &[u8]) -> Result<Vec<u8>, String> {
    Ok(instance_facts(instance)?.0)
}

/// Returns whether an encoded `Versioned(FatContractInstance)` carries a contract key (`Some(has_key)`),
/// or `None` if `instance` does not decode as a `FatContractInstance`.
pub fn instance_has_key(instance: &[u8]) -> Option<bool> {
    let versioned = Versioned::decode(instance).ok()?;
    let fat = FatContractInstance::decode(versioned.payload.as_slice()).ok()?;
    Some(fat.contract_key_with_maintainers.is_some())
}

/// The package name of an encoded `Versioned(FatContractInstance)`, or `None` if it does not decode as one.
pub fn instance_package_name(instance: &[u8]) -> Option<String> {
    let versioned = Versioned::decode(instance).ok()?;
    let fat = FatContractInstance::decode(versioned.payload.as_slice()).ok()?;
    Some(fat.package_name)
}

/// The salt message and the creation time (microseconds) of a serialized contract instance.
pub fn instance_facts(instance: &[u8]) -> Result<(Vec<u8>, i64), String> {
    let versioned = Versioned::decode(instance).map_err(|e| e.to_string())?;
    let fat =
        FatContractInstance::decode(versioned.payload.as_slice()).map_err(|e| e.to_string())?;
    Ok((fat.authentication_data, fat.created_at))
}

#[cfg(test)]
mod authentication_tests {
    use super::*;

    #[test]
    fn the_salt_of_an_encoded_instance_is_read_back() {
        let instance = ContractInstance {
            contract_id: vec![0, 1, 2],
            package_name: "p".into(),
            package_id: "pid".into(),
            module: vec!["M".into()],
            name: vec!["T".into()],
            arg: LfValue::Unit,
            signatories: BTreeSet::from(["alice".to_string()]),
            stakeholders: BTreeSet::from(["alice".to_string()]),
            created_at_micros: 7,
            authentication_data: authentication_data(&[9u8; 32]),
            key: None,
        };
        assert_eq!(
            authentication_data_of(&instance.encode()).unwrap(),
            authentication_data(&[9u8; 32])
        );
    }
}
