//! Canton contract ids of version V1 (suffix `ca12`): the contract salt, the LF contract hash and the Unicum (G5 5.6d-2, S-NET-009).
//!
//! [CANTON-NOTE: SEMANTICS] Read from `ContractSalt.createV1`, `UnicumGenerator`, `CantonContractIdVersion` and the LF
//! `SValueHash` of the Canton 3.7.2 sources; every function here is compared byte for byte with the node's own classes in
//! `tests/contract_ids.rs`:
//! - A contract id is `00` + the 32-byte discriminator + the suffix; the suffix is the version prefix `ca12` followed by the
//!   multihash (`1220` + SHA-256) of the **Unicum**. Version `ca12` means the contract is hashed in the *typed normal form*.
//! - The contract salt is `HMAC-SHA256(key = salt of the view participant data, message = createIndex ++ viewPosition ++
//!   uuid ++ synchronizerId ++ mediator)` with Canton's `DeterministicEncoding` (ints big endian, strings and byte strings
//!   prefixed by their length as an int).
//! - The Unicum is the Canton hash of purpose 29 over: the contract salt (no prefix), the creation time as an instant
//!   (`i64` seconds + `i32` nanos, no prefix), the signatories, the non-signatory stakeholders, the key hash (absent: one
//!   zero byte) and the maintainers (absent: a byte string holding one zero byte), then the 32-byte contract hash.
//! - The contract hash is the LF `SValueHash.hashContractInstance`: SHA-256 over `03 05`, the package *name*, the qualified
//!   name of the template and the value in its typed normal form (record fields carry their labels, trailing `None` fields
//!   are dropped, a record ends with `ff`).
//!
//! [CANTON-NOTE: LIMITATION] No contract key, no numeric, text map, generic map, variant, enum or contract-id values (their
//! hash rules are read but not exercised against the node); the labels and the template's qualified name come from the
//! caller, not from the package.
use canton_algo::hash::PurposeHash;
use sha2::{Digest, Sha256};

/// `HashPurpose.Unicum`.
const PURPOSE_UNICUM: i32 = 29;
/// The version prefix of `AuthenticatedContractIdVersionV12`.
pub const VERSION_PREFIX_V12: [u8; 2] = [0xca, 0x12];

/// HMAC-SHA256 (RFC 2104); `key` is at most one block (64 bytes), as the node insists.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 64, "an HMAC secret is at most one block");
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// `DeterministicEncoding.encodeInt`.
fn encode_int(value: i32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// `DeterministicEncoding.encodeString`: the length as an int, then the UTF-8 bytes.
fn encode_string(value: &str) -> Vec<u8> {
    let mut out = encode_int(value.len() as i32);
    out.extend_from_slice(value.as_bytes());
    out
}

/// A path element of a view position: the directions from the leaf to the root of the Merkle sequence (`true` = right).
pub type MerkleSeqIndex = Vec<bool>;

/// `ViewPosition.encodeDeterministically`: the elements as a sequence, each a sequence of one byte per direction.
pub fn encode_view_position(position: &[MerkleSeqIndex]) -> Vec<u8> {
    let mut out = encode_int(position.len() as i32);
    for index in position {
        out.extend(encode_int(index.len() as i32));
        out.extend(index.iter().map(|right| u8::from(*right)));
    }
    out
}

/// What makes a contract id unique (the arguments of `ContractSalt.createV1`).
pub struct SaltInputs<'a> {
    /// The salt of the view participant data of the view whose core creates the contract.
    pub view_participant_data_salt: &'a [u8],
    pub create_index: i32,
    pub view_position: &'a [MerkleSeqIndex],
    pub transaction_uuid: &'a str,
    pub synchronizer_id: &'a str,
    /// `MediatorGroupRecipient.toProtoPrimitive`, e.g. `MGR::0`.
    pub mediator: &'a str,
}

/// `ContractSalt.createV1`.
pub fn contract_salt(inputs: &SaltInputs) -> [u8; 32] {
    let mut message = encode_int(inputs.create_index);
    message.extend(encode_view_position(inputs.view_position));
    message.extend(encode_string(inputs.transaction_uuid));
    message.extend(encode_string(inputs.synchronizer_id));
    message.extend(encode_string(inputs.mediator));
    hmac_sha256(inputs.view_participant_data_salt, &message)
}

/// LF `Hash.deriveTransactionSeed`: `HMAC(key = submission seed, participant id ++ preparation time)`.
///
/// [CANTON-NOTE: SEMANTICS] The LF `hMacBuilder` is HMAC-SHA256 keyed with the 32 bytes of the seed hash; its data is added
/// with the LF primitives (strings with an int length prefix, longs and ints big endian).
pub fn derive_transaction_seed(
    submission_seed: &[u8; 32],
    participant_id: &str,
    preparation_time_micros: i64,
) -> [u8; 32] {
    let mut message = encode_string(participant_id);
    message.extend(preparation_time_micros.to_be_bytes());
    hmac_sha256(submission_seed, &message)
}

/// LF `Hash.deriveNodeSeed`: `HMAC(key = parent seed, child index)`. A root node's parent is the transaction seed.
pub fn derive_node_seed(parent_seed: &[u8; 32], child_index: i32) -> [u8; 32] {
    hmac_sha256(parent_seed, &child_index.to_be_bytes())
}

/// LF `Hash.deriveContractDiscriminator`: `HMAC(key = node seed, submission time ++ the set of parties)`; the parties are
/// the stakeholders of the contract (sorted as `addStringSet` does, by UTF-16 code units).
pub fn derive_contract_discriminator(
    node_seed: &[u8; 32],
    submission_time_micros: i64,
    parties: &[String],
) -> [u8; 32] {
    let mut sorted: Vec<&String> = parties.iter().collect();
    sorted.sort_by_key(|p| p.encode_utf16().collect::<Vec<u16>>());
    sorted.dedup();
    let mut message = submission_time_micros.to_be_bytes().to_vec();
    message.extend(encode_int(sorted.len() as i32));
    for party in sorted {
        message.extend(encode_string(party));
    }
    hmac_sha256(node_seed, &message)
}

/// A Daml-LF value in the form the typed normal form hashes (`SValue`).
#[derive(Debug, Clone, PartialEq)]
pub enum HashValue {
    Unit,
    Bool(bool),
    Int64(i64),
    Text(String),
    Party(String),
    /// A numeric by its unscaled integer value (the number times 10^scale), e.g. `100.5` of scale 10 is `1005000000000`.
    Numeric(i128),
    /// Days since the epoch.
    Date(i32),
    /// Microseconds since the epoch.
    Timestamp(i64),
    Optional(Option<Box<HashValue>>),
    List(Vec<HashValue>),
    /// A contract id by its bytes (`ContractId.toBytes`: the hex of a V1 id decoded).
    ContractId(Vec<u8>),
    /// A variant constructor with its **rank** (its index among the type's constructors).
    Variant {
        module: Vec<String>,
        name: Vec<String>,
        constructor: String,
        rank: i32,
        value: Box<HashValue>,
    },
    Enum {
        module: Vec<String>,
        name: Vec<String>,
        constructor: String,
        rank: i32,
    },
    /// Entries in the map's order (sorted by key).
    TextMap(Vec<(String, HashValue)>),
    GenMap(Vec<(HashValue, HashValue)>),
    /// The qualified name (module segments, name segments) and the labelled fields in declaration order.
    Record {
        module: Vec<String>,
        name: Vec<String>,
        fields: Vec<(String, HashValue)>,
    },
}

/// `BigInteger.toByteArray`: the minimal big-endian two's-complement bytes of `v`.
fn big_integer_bytes(v: i128) -> Vec<u8> {
    let all = v.to_be_bytes();
    let mut start = 0;
    // drop leading bytes that only repeat the sign of the next byte
    while start < all.len() - 1 {
        let (b, next) = (all[start], all[start + 1]);
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    all[start..].to_vec()
}

/// A hash builder with the LF `Builder` primitives (`addInt`/`addLong`/`addString` and the like; ints big endian).
struct LfBuilder(Sha256);

impl LfBuilder {
    fn byte(&mut self, b: u8) -> &mut Self {
        self.0.update([b]);
        self
    }
    fn int(&mut self, v: i32) -> &mut Self {
        self.0.update(v.to_be_bytes());
        self
    }
    fn long(&mut self, v: i64) -> &mut Self {
        self.0.update(v.to_be_bytes());
        self
    }
    fn string(&mut self, s: &str) -> &mut Self {
        self.int(s.len() as i32);
        self.0.update(s.as_bytes());
        self
    }
    fn segments(&mut self, segments: &[String]) -> &mut Self {
        self.int(segments.len() as i32);
        for s in segments {
            self.string(s);
        }
        self
    }
    fn qualified_name(&mut self, module: &[String], name: &[String]) -> &mut Self {
        self.segments(module).segments(name)
    }

    fn value(&mut self, value: &HashValue) -> &mut Self {
        match value {
            HashValue::Int64(v) => self.byte(0).long(*v),
            HashValue::Text(s) => self.byte(2).string(s),
            HashValue::Timestamp(v) => self.byte(3).long(*v),
            // `addNumeric`: the bytes of the unscaled `BigInteger` (minimal two's complement), with a length prefix
            HashValue::Numeric(v) => {
                self.byte(1);
                let bytes = big_integer_bytes(*v);
                self.int(bytes.len() as i32);
                self.0.update(&bytes);
                self
            }
            HashValue::Party(s) => self.byte(4).string(s),
            HashValue::Bool(b) => self.byte(5).byte(u8::from(*b)),
            HashValue::Unit => self.byte(6),
            HashValue::Date(days) => self.byte(7).int(*days),
            HashValue::Record {
                module,
                name,
                fields,
            } => {
                self.byte(8).qualified_name(module, name);
                // [CANTON-NOTE: SEMANTICS] Trailing `None` fields are not part of the hash, so that a template that
                // gained an optional field at its end (an upgrade) keeps the hashes of its old contracts.
                let trailing_nones = fields
                    .iter()
                    .rev()
                    .take_while(|(_, v)| matches!(v, HashValue::Optional(None)))
                    .count();
                for (label, v) in &fields[..fields.len() - trailing_nones] {
                    self.string(label).value(v);
                }
                self.byte(0xff)
            }
            HashValue::List(items) => {
                self.byte(11).int(items.len() as i32);
                for item in items {
                    self.value(item);
                }
                self
            }
            // `addCid`: the tag 15 and the id's bytes, length-prefixed
            HashValue::ContractId(bytes) => {
                self.byte(15).int(bytes.len() as i32);
                self.0.update(bytes);
                self
            }
            HashValue::Variant {
                module,
                name,
                constructor,
                rank,
                value,
            } => self
                .byte(9)
                .qualified_name(module, name)
                .string(constructor)
                .int(*rank)
                .value(value),
            HashValue::Enum {
                module,
                name,
                constructor,
                rank,
            } => self
                .byte(10)
                .qualified_name(module, name)
                .string(constructor)
                .int(*rank),
            HashValue::TextMap(entries) => {
                self.byte(13).int(entries.len() as i32);
                for (k, v) in entries {
                    self.string(k).value(v);
                }
                self
            }
            HashValue::GenMap(entries) => {
                self.byte(14).int(entries.len() as i32);
                for (k, v) in entries {
                    self.value(k).value(v);
                }
                self
            }
            HashValue::Optional(None) => self.byte(12).byte(0),
            HashValue::Optional(Some(v)) => self.byte(12).byte(1).value(v),
        }
    }
}

/// `SValueHash.hashContractInstance`: the hash of a contract (its package name, the qualified name of its template and its
/// argument, which must be a record).
pub fn lf_contract_hash(
    package_name: &str,
    template_module: &[String],
    template_name: &[String],
    argument: &HashValue,
) -> [u8; 32] {
    let mut b = LfBuilder(Sha256::new());
    // version `TypedNormalForm` = 3, purpose `ThinContractInstance` = 5
    b.byte(3)
        .byte(5)
        .string(package_name)
        .qualified_name(template_module, template_name)
        .value(argument);
    b.0.finalize().into()
}

/// `SValueHash.hashContractKey`: the hash of a contract key (the package name, the qualified name of its template and the key value).
///
/// [CANTON-NOTE: SEMANTICS] The purpose is `NextGenContractKey` (9), the same builder version (`TypedNormalForm` = 3) as the contract hash,
/// then the byte 1 (the key hash version), the package name, the template's qualified name and the key as a typed value. The Unicum of a
/// keyed contract commits to this hash, and a view's resolved key states it (`GlobalKey.hash`).
pub fn lf_contract_key_hash(
    package_name: &str,
    template_module: &[String],
    template_name: &[String],
    key: &HashValue,
) -> [u8; 32] {
    let mut b = LfBuilder(Sha256::new());
    b.byte(3)
        .byte(9)
        .byte(1)
        .string(package_name)
        .qualified_name(template_module, template_name)
        .value(key);
    b.0.finalize().into()
}

/// The key of a contract the Unicum commits to: the hash of the key and its maintainers.
pub struct KeyInputs<'a> {
    pub hash: &'a [u8; 32],
    pub maintainers: &'a [String],
}

/// What the Unicum commits to besides the salt.
pub struct UnicumInputs<'a> {
    pub created_at_micros: i64,
    pub signatories: &'a [String],
    pub stakeholders: &'a [String],
    /// `None` for a contract of a template without a key.
    pub key: Option<KeyInputs<'a>>,
    pub contract_hash: &'a [u8; 32],
}

/// `DeterministicEncoding.encodeSeqWith(sorted parties)(encodeParty)`.
fn encode_parties(parties: &[&String]) -> Vec<u8> {
    let mut sorted: Vec<&&String> = parties.iter().collect();
    // Scala sorts strings by UTF-16 code units
    sorted.sort_by_key(|s| s.encode_utf16().collect::<Vec<u16>>());
    let mut out = encode_int(sorted.len() as i32);
    for party in sorted {
        out.extend(encode_string(party));
    }
    out
}

/// `UnicumGenerator.computeUnicumHash`.
///
/// [CANTON-NOTE: SEMANTICS] The key part is `encodeOptionWith(key hash)` added without a length prefix, then `encodeOptionWith(maintainers)`
/// added as a byte string; `Some` is the byte 1 followed by the payload, `None` the byte 0 alone.
pub fn unicum(salt: &[u8; 32], inputs: &UnicumInputs) -> [u8; 32] {
    let non_signatory_stakeholders: Vec<&String> = inputs
        .stakeholders
        .iter()
        .filter(|s| !inputs.signatories.contains(s))
        .collect();
    let signatories: Vec<&String> = inputs.signatories.iter().collect();
    let micros = inputs.created_at_micros;
    let mut h = PurposeHash::new(PURPOSE_UNICUM);
    let infallible = "an open hash builder takes data";
    h.add_without_length_prefix(salt).expect(infallible);
    // `Instant`: seconds as a long, nanoseconds as an int
    h.add_without_length_prefix(&micros.div_euclid(1_000_000).to_be_bytes())
        .expect(infallible);
    h.add_without_length_prefix(&(micros.rem_euclid(1_000_000) as i32 * 1000).to_be_bytes())
        .expect(infallible);
    h.add_byte_string(&encode_parties(&signatories))
        .expect(infallible);
    h.add_byte_string(&encode_parties(&non_signatory_stakeholders))
        .expect(infallible);
    match &inputs.key {
        None => {
            h.add_without_length_prefix(&[0]).expect(infallible);
            h.add_byte_string(&[0]).expect(infallible);
        }
        Some(key) => {
            let mut hash = vec![1u8];
            hash.extend_from_slice(key.hash);
            h.add_without_length_prefix(&hash).expect(infallible);
            let maintainers: Vec<&String> = key.maintainers.iter().collect();
            let mut encoded = vec![1u8];
            encoded.extend(encode_parties(&maintainers));
            h.add_byte_string(&encoded).expect(infallible);
        }
    }
    h.add_without_length_prefix(inputs.contract_hash)
        .expect(infallible);
    h.finish().expect(infallible)
}

/// The suffix of a V1 contract id: the version prefix and the multihash of the Unicum.
pub fn contract_id_suffix(unicum: &[u8; 32]) -> Vec<u8> {
    let mut out = VERSION_PREFIX_V12.to_vec();
    out.extend_from_slice(&[0x12, 0x20]);
    out.extend_from_slice(unicum);
    out
}

/// A V1 contract id as the string of the ledger: `00`, the discriminator and the suffix, in hex.
pub fn contract_id(discriminator: &[u8; 32], unicum: &[u8; 32]) -> String {
    format!(
        "00{}{}",
        hex::encode(discriminator),
        hex::encode(contract_id_suffix(unicum))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_integer_bytes_are_minimal_twos_complement() {
        assert_eq!(big_integer_bytes(0), vec![0x00]);
        assert_eq!(big_integer_bytes(127), vec![0x7f]);
        assert_eq!(big_integer_bytes(128), vec![0x00, 0x80]);
        assert_eq!(big_integer_bytes(-1), vec![0xff]);
        assert_eq!(big_integer_bytes(-128), vec![0x80]);
        assert_eq!(big_integer_bytes(-129), vec![0xff, 0x7f]);
        assert_eq!(
            big_integer_bytes(1_000_000_000_000),
            // the top bit of 0xe8 is set, so the sign needs a leading zero byte
            vec![0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn suffix_has_version_prefix_and_multihash() {
        let suffix = contract_id_suffix(&[7; 32]);
        assert_eq!(&suffix[..4], &[0xca, 0x12, 0x12, 0x20]);
        assert_eq!(suffix.len(), 36);
    }

    #[test]
    fn trailing_nones_do_not_change_the_hash() {
        let record = |fields: Vec<(String, HashValue)>| HashValue::Record {
            module: vec!["Main".into()],
            name: vec!["Holding".into()],
            fields,
        };
        let base = vec![("owner".to_string(), HashValue::Party("alice".into()))];
        let mut longer = base.clone();
        longer.push(("note".to_string(), HashValue::Optional(None)));
        let m = vec!["Main".to_string()];
        let n = vec!["Holding".to_string()];
        assert_eq!(
            lf_contract_hash("pkg", &m, &n, &record(base)),
            lf_contract_hash("pkg", &m, &n, &record(longer))
        );
    }
}

#[cfg(test)]
mod key_hash_tests {
    use super::*;

    /// The key `(erin, "entry")` of `Keyed:Registry` (package name `keyed-vault`), and the hash p1 stated for it in a view's `resolved_keys`
    /// (U-21, measured on Canton 3.7.2): the Rust hash has to be those 32 bytes.
    #[test]
    fn the_contract_key_hash_equals_the_one_a_participant_stated() {
        let key = HashValue::Record {
            module: vec!["DA".into(), "Types".into()],
            name: vec!["Tuple2".into()],
            fields: vec![
                (
                    "_1".into(),
                    HashValue::Party(
                        "erin::12200d26de5fc316a0dc543c8ce7392e9a18ce22b04cdb64844193df8cb8538a2e23".into(),
                    ),
                ),
                ("_2".into(), HashValue::Text("entry".into())),
            ],
        };
        let hash =
            lf_contract_key_hash("keyed-vault", &["Keyed".into()], &["Registry".into()], &key);
        let stated: [u8; 32] = [
            215, 23, 204, 137, 37, 125, 207, 117, 137, 103, 235, 214, 96, 42, 216, 239, 55, 95, 28,
            168, 140, 39, 245, 93, 255, 140, 134, 69, 145, 163, 174, 44,
        ];
        assert_eq!(hex::encode(hash), hex::encode(stated));
    }
}
