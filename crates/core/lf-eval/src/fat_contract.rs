//! Canton 3.7.2 `Versioned(FatContractInstance)` codec, `SValueHash` (TypedNormalForm),
//! V12 `Unicum` (HashPurpose 29) computation, and two-stage explicit-disclosure validation.
//!
//! References in `references/canton-3.7.2-src`:
//! - `ContractInstanceCoder.scala` / `transaction.proto` (`Versioned`, `FatContractInstance`, `KeyWithMaintainers`)
//! - `ValueCoder.scala` / `value.proto`
//! - `SValueHash.scala` / `Hash.scala` (`TypedNormalForm = 3`, `ThinContractInstance = 5`, `NextGenContractKey = 9`)
//! - `UnicumGenerator.scala` / `CantonContractIdVersion.scala` / `ContractValidator.scala` / `ContractAuthenticationData.scala`

use std::collections::BTreeSet;

use crate::typed_json::{wire_field, wire_tag, wire_varint, Types};
use crate::{values_equal, Value, World};

mod hash;
mod untyped_value;

pub use hash::{compute_contract_hash, compute_key_hash, compute_unicum};

use untyped_value::{check_strict_party_order, validate_untyped_value_proto};

const MAX_NESTING: usize = 100;
const MIN_DATE_DAYS: i32 = -719_162; // 0001-01-01
const MAX_DATE_DAYS: i32 = 2_932_896; // 9999-12-31
const MIN_TIMESTAMP_MICROS: i64 = -62_135_596_800_000_000; // 0001-01-01T00:00:00Z
const MAX_TIMESTAMP_MICROS: i64 = 253_402_300_799_999_999; // 9999-12-31T23:59:59.999999Z
const TYPED_NORMAL_FORM_VERSION: u8 = 3;
const PURPOSE_THIN_CONTRACT_INSTANCE: u8 = 5;
const PURPOSE_NEXT_GEN_CONTRACT_KEY: u8 = 9;
const HASH_PURPOSE_UNICUM: i32 = 29;
const V12_SUFFIX_PREFIX: [u8; 4] = [0xca, 0x12, 0x12, 0x20];

const TAG_INT64: u8 = 0;
const TAG_NUMERIC: u8 = 1;
const TAG_TEXT: u8 = 2;
const TAG_TIMESTAMP: u8 = 3;
const TAG_PARTY: u8 = 4;
const TAG_BOOL: u8 = 5;
const TAG_UNIT: u8 = 6;
const TAG_DATE: u8 = 7;
const TAG_RECORD: u8 = 8;
const TAG_VARIANT: u8 = 9;
const TAG_ENUM: u8 = 10;
const TAG_LIST: u8 = 11;
const TAG_OPTIONAL: u8 = 12;
const TAG_TEXT_MAP: u8 = 13;
const TAG_GEN_MAP: u8 = 14;
const TAG_CONTRACT_ID: u8 = 15;
const END_OF_RECORD: u8 = 0xff;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthError(pub String);

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawKeyWithMaintainers {
    pub key_bytes: Vec<u8>,
    pub maintainers: Vec<String>,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawFatContract {
    pub version: String,
    pub contract_id: String,
    pub package_name: String,
    pub package_id: String,
    pub module_name: String,
    pub entity_name: String,
    pub create_arg_bytes: Vec<u8>,
    pub non_maintainer_signatories: Vec<String>,
    pub non_signatory_stakeholders: Vec<String>,
    pub created_at_micros: i64,
    pub authentication_data: Vec<u8>,
    pub key: Option<RawKeyWithMaintainers>,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedFatContract {
    pub contract_id: String,
    pub package_id: String,
    pub package_name: String,
    pub module_name: String,
    pub entity_name: String,
    pub payload: Value,
    pub signatories: Vec<String>,
    pub observers: Vec<String>,
    pub created_at_micros: i64,
    pub salt: [u8; 32],
    pub key: Option<Value>,
    pub key_maintainers: Vec<String>,
    pub key_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct FatContractInput<'a> {
    pub contract_id: &'a str,
    pub package_id: &'a str,
    pub package_name: &'a str,
    pub module_name: &'a str,
    pub entity_name: &'a str,
    pub payload: &'a Value,
    pub signatories: &'a [String],
    pub observers: &'a [String],
    pub created_at_micros: i64,
    pub salt: &'a [u8; 32],
    pub key: Option<&'a Value>,
    pub key_maintainers: &'a [String],
    pub key_hash: Option<&'a [u8; 32]>,
}

/// Standard Base64 encoding with `=` padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Strict canonical standard Base64 decoder (no whitespace, exact padding, zeroed unused pad bits).
pub fn decode_strict_base64(input: &str) -> Result<Vec<u8>, DecodeError> {
    let err = |msg: &str| DecodeError(format!("DecodeError(invalid base64: {msg})"));
    if input.is_empty() || !input.is_ascii() || !input.len().is_multiple_of(4) {
        return Err(err("invalid length or encoding"));
    }
    let b = input.as_bytes();
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let chunks = b.len() / 4;
    for (idx, quad) in b.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == chunks;
        let pad = match (quad[2], quad[3]) {
            (b'=', b'=') if is_last => 2,
            (c2, b'=') if is_last && c2 != b'=' => 1,
            (c2, c3) if c2 != b'=' && c3 != b'=' => 0,
            _ => return Err(err("misplaced padding")),
        };
        let v0 = val(quad[0]).ok_or_else(|| err("invalid character"))?;
        let v1 = val(quad[1]).ok_or_else(|| err("invalid character"))?;
        out.push((v0 << 2) | (v1 >> 4));
        match pad {
            2 => {
                if (v1 & 0x0f) != 0 {
                    return Err(err("non-canonical trailing bits in == padding"));
                }
            }
            1 => {
                let v2 = val(quad[2]).ok_or_else(|| err("invalid character"))?;
                if (v2 & 0x03) != 0 {
                    return Err(err("non-canonical trailing bits in = padding"));
                }
                out.push((v1 << 4) | (v2 >> 2));
            }
            _ => {
                let v2 = val(quad[2]).ok_or_else(|| err("invalid character"))?;
                let v3 = val(quad[3]).ok_or_else(|| err("invalid character"))?;
                out.push((v1 << 4) | (v2 >> 2));
                out.push((v2 << 6) | v3);
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum WireVal<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
}

fn parse_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    let mut out = 0u64;
    let mut shift = 0u32;
    let start = *pos;
    loop {
        let &byte = bytes
            .get(*pos)
            .ok_or_else(|| DecodeError("DecodeError(truncated varint)".into()))?;
        let count = *pos - start;
        if count >= 10 || (count == 9 && byte > 1) {
            return Err(DecodeError("DecodeError(varint overflow)".into()));
        }
        *pos += 1;
        out |= u64::from(byte & 0x7f) << shift;
        if (byte & 0x80) == 0 {
            if count > 0 && byte == 0 {
                return Err(DecodeError("DecodeError(non-minimal varint)".into()));
            }
            return Ok(out);
        }
        shift += 7;
    }
}

fn parse_proto_fields(bytes: &[u8]) -> Result<Vec<(u32, WireVal<'_>)>, DecodeError> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < bytes.len() {
        let tag = parse_varint(bytes, &mut pos)?;
        let field = u32::try_from(tag >> 3)
            .ok()
            .filter(|&f| f != 0)
            .ok_or_else(|| DecodeError("DecodeError(invalid protobuf field number)".into()))?;
        let wire_type = (tag & 0x07) as u8;
        let val = match wire_type {
            0 => WireVal::Varint(parse_varint(bytes, &mut pos)?),
            1 => {
                let slice = bytes
                    .get(pos..pos + 8)
                    .ok_or_else(|| DecodeError("DecodeError(truncated fixed64)".into()))?;
                pos += 8;
                WireVal::Fixed64(slice.try_into().expect("8 bytes"))
            }
            2 => {
                let len = usize::try_from(parse_varint(bytes, &mut pos)?)
                    .map_err(|_| DecodeError("DecodeError(length overflow)".into()))?;
                let slice = bytes.get(pos..pos + len).ok_or_else(|| {
                    DecodeError("DecodeError(truncated length-delimited field)".into())
                })?;
                pos += len;
                WireVal::Bytes(slice)
            }
            _ => {
                return Err(DecodeError(format!(
                    "DecodeError(unsupported wire type {wire_type})"
                )))
            }
        };
        out.push((field, val));
    }
    Ok(out)
}

fn expect_utf8(bytes: &[u8], what: &str) -> Result<String, DecodeError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| DecodeError(format!("DecodeError({what} is not valid UTF-8)")))
}

fn wire_bytes_field(out: &mut Vec<u8>, field: u32, payload: &[u8]) {
    wire_field(out, field, payload);
}

fn wire_fixed64_field(out: &mut Vec<u8>, field: u32, v: i64) {
    wire_tag(out, field, 1);
    out.extend_from_slice(&v.to_le_bytes());
}

fn wire_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    wire_tag(out, field, 0);
    wire_varint(out, v);
}

pub fn is_valid_party(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b' '))
}

pub fn is_valid_package_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub fn is_valid_package_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b' '))
}

fn is_valid_lf_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1000
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$'))
        && !s.as_bytes()[0].is_ascii_digit()
}

fn is_valid_v1_contract_id_bytes(bytes: &[u8]) -> bool {
    // V1 contract id: 0x00 (1) + discriminator (32) + suffix (1..=94 bytes, total <= 127).
    bytes.first() == Some(&0x00) && bytes.len() >= 34 && bytes.len() <= 127
}

fn encode_identifier(package_id: &str, module_name: &str, entity_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire_bytes_field(&mut out, 1, package_id.as_bytes());
    for seg in module_name.split('.') {
        wire_bytes_field(&mut out, 2, seg.as_bytes());
    }
    for seg in entity_name.split('.') {
        wire_bytes_field(&mut out, 3, seg.as_bytes());
    }
    out
}

fn parse_identifier(bytes: &[u8]) -> Result<(String, String, String), DecodeError> {
    let mut pkg_id = None;
    let mut mod_segs = Vec::new();
    let mut name_segs = Vec::new();
    for (f, v) in parse_proto_fields(bytes)? {
        let WireVal::Bytes(b) = v else {
            return Err(DecodeError(
                "DecodeError(invalid Identifier wire type)".into(),
            ));
        };
        let s = expect_utf8(b, "identifier")?;
        match f {
            1 if pkg_id.is_none() => pkg_id = Some(s),
            2 => mod_segs.push(s),
            3 => name_segs.push(s),
            _ => {
                return Err(DecodeError(
                    "DecodeError(unknown/duplicate Identifier field)".into(),
                ))
            }
        }
    }
    let Some(pkg_id) = pkg_id else {
        return Err(DecodeError(
            "DecodeError(missing Identifier.package_id)".into(),
        ));
    };
    if !is_valid_package_id(&pkg_id) || mod_segs.is_empty() || name_segs.is_empty() {
        return Err(DecodeError("DecodeError(invalid Identifier)".into()));
    }
    for seg in mod_segs.iter().chain(&name_segs) {
        if !is_valid_lf_name(seg) {
            return Err(DecodeError(format!(
                "DecodeError(invalid Identifier segment '{seg}')"
            )));
        }
    }
    Ok((pkg_id, mod_segs.join("."), name_segs.join(".")))
}

fn parse_key_with_maintainers(
    bytes: &[u8],
    version: &str,
) -> Result<RawKeyWithMaintainers, DecodeError> {
    let mut key_bytes = None;
    let mut maintainers = Vec::new();
    let mut hash = None;
    for (f, v) in parse_proto_fields(bytes)? {
        let WireVal::Bytes(b) = v else {
            return Err(DecodeError(
                "DecodeError(invalid KeyWithMaintainers wire type)".into(),
            ));
        };
        match f {
            1 if key_bytes.is_none() => key_bytes = Some(validate_untyped_value_proto(b, 0)?),
            2 => maintainers.push(expect_utf8(b, "maintainer")?),
            3 if hash.is_none() => hash = Some(b.to_vec()),
            _ => {
                return Err(DecodeError(
                    "DecodeError(invalid KeyWithMaintainers field)".into(),
                ))
            }
        }
    }
    let Some(key_bytes) = key_bytes else {
        return Err(DecodeError(
            "DecodeError(missing KeyWithMaintainers.key)".into(),
        ));
    };
    if maintainers.is_empty() {
        return Err(DecodeError("DecodeError(key without maintainers)".into()));
    }
    check_strict_party_order(&maintainers, "maintainers")?;
    let hash = match (version, hash) {
        ("2", Some(h)) if h.len() == 32 => h,
        _ => {
            return Err(DecodeError(
                "DecodeError(KeyWithMaintainers.hash mismatch for version)".into(),
            ))
        }
    };
    Ok(RawKeyWithMaintainers {
        key_bytes,
        maintainers,
        hash,
    })
}

pub fn encode_raw_fat_contract(raw: &RawFatContract) -> Result<Vec<u8>, String> {
    let cid_bytes = hex::decode(&raw.contract_id).map_err(|e| format!("invalid cid hex: {e}"))?;
    let mut inner = Vec::new();
    wire_bytes_field(&mut inner, 1, &cid_bytes);
    wire_bytes_field(&mut inner, 2, raw.package_name.as_bytes());
    let id_bytes = encode_identifier(&raw.package_id, &raw.module_name, &raw.entity_name);
    wire_bytes_field(&mut inner, 3, &id_bytes);
    wire_bytes_field(&mut inner, 4, &raw.create_arg_bytes);
    for s in &raw.non_maintainer_signatories {
        wire_bytes_field(&mut inner, 5, s.as_bytes());
    }
    for s in &raw.non_signatory_stakeholders {
        wire_bytes_field(&mut inner, 6, s.as_bytes());
    }
    wire_fixed64_field(&mut inner, 7, raw.created_at_micros);
    wire_bytes_field(&mut inner, 8, &raw.authentication_data);
    if let Some(kwm) = &raw.key {
        let mut kb = Vec::new();
        wire_bytes_field(&mut kb, 1, &kwm.key_bytes);
        for m in &kwm.maintainers {
            wire_bytes_field(&mut kb, 2, m.as_bytes());
        }
        if !kwm.hash.is_empty() {
            wire_bytes_field(&mut kb, 3, &kwm.hash);
        }
        wire_bytes_field(&mut inner, 1001, &kb);
    }
    let mut versioned = Vec::new();
    wire_bytes_field(&mut versioned, 1, raw.version.as_bytes());
    wire_bytes_field(&mut versioned, 2, &inner);
    Ok(versioned)
}

/// Decodes a Canton `Versioned(FatContractInstance)` without accessing a `World` (Stage 1).
pub fn decode_fat_contract_blob(blob: &[u8]) -> Result<RawFatContract, DecodeError> {
    let mut version = None;
    let mut payload = None;
    for (f, v) in parse_proto_fields(blob)? {
        let WireVal::Bytes(b) = v else {
            return Err(DecodeError(
                "DecodeError(invalid Versioned wire type)".into(),
            ));
        };
        match f {
            1 if version.is_none() => version = Some(expect_utf8(b, "version")?),
            2 if payload.is_none() => payload = Some(b),
            _ => {
                return Err(DecodeError(
                    "DecodeError(unknown/duplicate Versioned field)".into(),
                ))
            }
        }
    }
    let (Some(version), Some(payload)) = (version, payload) else {
        return Err(DecodeError(
            "DecodeError(incomplete Versioned message)".into(),
        ));
    };
    if version != "2.1" && version != "2" {
        return Err(DecodeError(format!(
            "DecodeError(unsupported serialization version '{version}')"
        )));
    }

    let mut cid_bytes = None;
    let mut pkg_name = None;
    let mut template_id = None;
    let mut create_arg_bytes = None;
    let mut non_maint_sigs = Vec::new();
    let mut non_sig_stakeholders = Vec::new();
    let mut created_at_micros = None;
    let mut auth_data = None;
    let mut key_bytes_raw = None;

    for (f, v) in parse_proto_fields(payload)? {
        match (f, v) {
            (1, WireVal::Bytes(b)) if cid_bytes.is_none() => cid_bytes = Some(b),
            (2, WireVal::Bytes(b)) if pkg_name.is_none() => {
                pkg_name = Some(expect_utf8(b, "package_name")?)
            }
            (3, WireVal::Bytes(b)) if template_id.is_none() => {
                template_id = Some(parse_identifier(b)?)
            }
            (4, WireVal::Bytes(b)) if create_arg_bytes.is_none() => {
                create_arg_bytes = Some(validate_untyped_value_proto(b, 0)?)
            }
            (5, WireVal::Bytes(b)) => {
                non_maint_sigs.push(expect_utf8(b, "non_maintainer_signatories")?)
            }
            (6, WireVal::Bytes(b)) => {
                non_sig_stakeholders.push(expect_utf8(b, "non_signatory_stakeholders")?)
            }
            (7, WireVal::Fixed64(le)) if created_at_micros.is_none() => {
                created_at_micros = Some(i64::from_le_bytes(le))
            }
            (8, WireVal::Bytes(b)) if auth_data.is_none() => auth_data = Some(b.to_vec()),
            (1001, WireVal::Bytes(b)) if key_bytes_raw.is_none() => key_bytes_raw = Some(b),
            _ => {
                return Err(DecodeError(format!(
                    "DecodeError(unknown or duplicate FatContractInstance field {f})"
                )))
            }
        }
    }

    let (
        Some(cid_bytes),
        Some(package_name),
        Some((package_id, module_name, entity_name)),
        Some(create_arg_bytes),
        Some(created_at_micros),
        Some(authentication_data),
    ) = (
        cid_bytes,
        pkg_name,
        template_id,
        create_arg_bytes,
        created_at_micros,
        auth_data,
    )
    else {
        return Err(DecodeError(
            "DecodeError(missing required FatContractInstance field)".into(),
        ));
    };

    if !is_valid_v1_contract_id_bytes(cid_bytes) {
        return Err(DecodeError("DecodeError(invalid contract_id bytes)".into()));
    }
    if !is_valid_package_name(&package_name) {
        return Err(DecodeError(format!(
            "DecodeError(invalid package_name '{package_name}')"
        )));
    }
    if !(MIN_TIMESTAMP_MICROS..=MAX_TIMESTAMP_MICROS).contains(&created_at_micros) {
        return Err(DecodeError(
            "DecodeError(created_at out of timestamp range)".into(),
        ));
    }
    check_strict_party_order(&non_maint_sigs, "non_maintainer_signatories")?;
    check_strict_party_order(&non_sig_stakeholders, "non_signatory_stakeholders")?;

    let key = match (version.as_str(), key_bytes_raw) {
        ("2.1", None) => None,
        ("2", Some(kb)) => Some(parse_key_with_maintainers(kb, &version)?),
        _ => {
            return Err(DecodeError(format!(
                "DecodeError(key presence invalid for serialization version '{version}')"
            )))
        }
    };

    let maintainers: BTreeSet<&str> = key
        .as_ref()
        .map(|k| k.maintainers.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let mut signatories: BTreeSet<&str> = maintainers.clone();
    for s in &non_maint_sigs {
        if !signatories.insert(s.as_str()) {
            return Err(DecodeError(format!(
                "DecodeError(party '{s}' is declared as maintainer and nonMaintainerSignatory)"
            )));
        }
    }
    if signatories.is_empty() {
        return Err(DecodeError(
            "DecodeError(maintainers or non_maintainer_signatories should be non empty)".into(),
        ));
    }
    for s in &non_sig_stakeholders {
        if signatories.contains(s.as_str()) {
            return Err(DecodeError(format!(
                "DecodeError(party '{s}' is declared as signatory and nonSignatoryStakeholder)"
            )));
        }
    }

    let raw = RawFatContract {
        version,
        contract_id: hex::encode(cid_bytes),
        package_name,
        package_id,
        module_name,
        entity_name,
        create_arg_bytes,
        non_maintainer_signatories: non_maint_sigs,
        non_signatory_stakeholders: non_sig_stakeholders,
        created_at_micros,
        authentication_data,
        key,
    };
    let canonical = encode_raw_fat_contract(&raw)
        .map_err(|e| DecodeError(format!("DecodeError(canonical re-encode failed: {e})")))?;
    if canonical != blob {
        return Err(DecodeError(
            "DecodeError(non-canonical FatContractInstance protobuf)".into(),
        ));
    }
    Ok(raw)
}

pub fn encode_auth_data_v30(salt: &[u8; 32]) -> Vec<u8> {
    let mut salt_msg = Vec::new();
    wire_varint_field(&mut salt_msg, 1, 1); // HMAC_ALGORITHM_HMAC_SHA256 = 1
    wire_bytes_field(&mut salt_msg, 2, salt);
    let mut auth_msg = Vec::new();
    wire_bytes_field(&mut auth_msg, 1, &salt_msg);
    let mut wrapped = Vec::new();
    wire_bytes_field(&mut wrapped, 1, &auth_msg);
    wire_varint_field(&mut wrapped, 2, 30);
    wrapped
}

pub fn decode_auth_data_v30(bytes: &[u8]) -> Result<[u8; 32], AuthError> {
    let err = |msg: &str| AuthError(format!("Failed to decode canton metadata: {msg}"));
    let mut data = None;
    let mut version = None;
    for (f, v) in parse_proto_fields(bytes).map_err(|e| err(&e.0))? {
        match (f, v) {
            (1, WireVal::Bytes(b)) if data.is_none() => data = Some(b),
            (2, WireVal::Varint(ver)) if version.is_none() => version = Some(ver),
            _ => return Err(err("unexpected UntypedVersionedMessage field")),
        }
    }
    if version != Some(30) {
        return Err(err("ContractAuthenticationData version is not 30"));
    }
    let Some(data) = data else {
        return Err(err("missing ContractAuthenticationData data"));
    };
    let mut salt_msg_bytes = None;
    for (f, v) in parse_proto_fields(data).map_err(|e| err(&e.0))? {
        match (f, v) {
            (1, WireVal::Bytes(b)) if salt_msg_bytes.is_none() => salt_msg_bytes = Some(b),
            _ => return Err(err("unexpected v30.ContractAuthenticationData field")),
        }
    }
    let Some(salt_msg_bytes) = salt_msg_bytes else {
        return Err(err("missing contract_salt"));
    };
    let mut hmac_algo = None;
    let mut salt_bytes = None;
    for (f, v) in parse_proto_fields(salt_msg_bytes).map_err(|e| err(&e.0))? {
        match (f, v) {
            (1, WireVal::Varint(a)) if hmac_algo.is_none() => hmac_algo = Some(a),
            (2, WireVal::Bytes(s)) if salt_bytes.is_none() => salt_bytes = Some(s),
            _ => return Err(err("unexpected v30.Salt field")),
        }
    }
    if hmac_algo != Some(1) {
        return Err(err("unsupported salt HMAC algorithm"));
    }
    let salt: [u8; 32] = salt_bytes
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| err("invalid salt length (expected 32 bytes)"))?;
    if encode_auth_data_v30(&salt) != bytes {
        return Err(err("non-canonical ContractAuthenticationData"));
    }
    Ok(salt)
}

/// Formats a Canton V12 contract ID: `00<disc:64>ca121220<unicum:64>`.
pub fn format_v12_contract_id(disc: &[u8; 32], unicum: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(69);
    bytes.push(0x00);
    bytes.extend_from_slice(disc);
    bytes.extend_from_slice(&V12_SUFFIX_PREFIX);
    bytes.extend_from_slice(unicum);
    hex::encode(bytes)
}

/// Encodes a contract into canonical Canton 3.7.2 `Versioned(FatContractInstance)` bytes.
pub fn encode_fat_contract(world: &World, input: &FatContractInput<'_>) -> Result<Vec<u8>, String> {
    let types = Types::new(world);
    let local_template = format!("{}:{}", input.module_name, input.entity_name);
    let tpl_ty = types.template(input.package_id, &local_template)?;
    let create_arg_bytes = types.to_wire(&tpl_ty, input.payload)?;

    let sig_set: BTreeSet<String> = input.signatories.iter().cloned().collect();
    let mut non_sig_stakeholders: BTreeSet<String> = input
        .observers
        .iter()
        .filter(|o| !sig_set.contains(*o))
        .cloned()
        .collect();
    // Invariant: stakeholders = signatories | non_signatory_stakeholders.
    non_sig_stakeholders.retain(|o| !sig_set.contains(o));

    let (version, key, non_maintainer_signatories) = match (input.key, input.key_hash) {
        (Some(key_val), Some(kh)) => {
            let key_ty = types
                .template_key_type(input.package_id, &local_template)?
                .ok_or_else(|| format!("template {local_template} has no key"))?;
            let key_bytes = types.to_wire(&key_ty, key_val)?;
            let maint_set: BTreeSet<String> = input.key_maintainers.iter().cloned().collect();
            let non_maint_sigs: Vec<String> = sig_set.difference(&maint_set).cloned().collect();
            let kwm = RawKeyWithMaintainers {
                key_bytes,
                maintainers: maint_set.into_iter().collect(),
                hash: kh.to_vec(),
            };
            ("2".to_string(), Some(kwm), non_maint_sigs)
        }
        (None, None) => ("2.1".to_string(), None, sig_set.iter().cloned().collect()),
        _ => {
            return Err(
                "contract key value and key_hash must both be present or both absent".into(),
            )
        }
    };

    let raw = RawFatContract {
        version,
        contract_id: input.contract_id.to_string(),
        package_name: input.package_name.to_string(),
        package_id: input.package_id.to_string(),
        module_name: input.module_name.to_string(),
        entity_name: input.entity_name.to_string(),
        create_arg_bytes,
        non_maintainer_signatories,
        non_signatory_stakeholders: non_sig_stakeholders.into_iter().collect(),
        created_at_micros: input.created_at_micros,
        authentication_data: encode_auth_data_v30(input.salt),
        key,
    };
    encode_raw_fat_contract(&raw)
}

/// Validates and authenticates a decoded `RawFatContract` against `World` (Stage 2).
pub fn authenticate_fat_contract(
    world: &World,
    raw: &RawFatContract,
) -> Result<AuthenticatedFatContract, AuthError> {
    let fail = |msg: String| AuthError(format!("failed to authenticate contract: {msg}"));

    let cid_bytes = hex::decode(&raw.contract_id).map_err(|e| fail(format!("cid hex: {e}")))?;
    if cid_bytes.len() != 69 || cid_bytes[0] != 0x00 || cid_bytes[33..37] != V12_SUFFIX_PREFIX {
        return Err(fail(
            "unsupported or malformed Canton V12 contract id".into(),
        ));
    }
    let cid_unicum: [u8; 32] = cid_bytes[37..69].try_into().expect("32 bytes");

    let salt = decode_auth_data_v30(&raw.authentication_data)?;

    let types = Types::new(world);
    let pkg_name = types.package_name(&raw.package_id).map_err(&fail)?;
    if pkg_name != raw.package_name {
        return Err(fail(format!(
            "package name mismatch: expected '{pkg_name}', got '{}'",
            raw.package_name
        )));
    }
    let local_template = format!("{}:{}", raw.module_name, raw.entity_name);
    let tpl_ty = types
        .template(&raw.package_id, &local_template)
        .map_err(&fail)?;
    let payload = types
        .from_wire(&tpl_ty, &raw.create_arg_bytes)
        .map_err(|e| fail(format!("create_arg decode: {e}")))?;
    let reencoded_arg = types
        .to_wire(&tpl_ty, &payload)
        .map_err(|e| fail(format!("create_arg reencode: {e}")))?;
    if reencoded_arg != raw.create_arg_bytes {
        return Err(fail("create_arg is non-canonical for template type".into()));
    }

    let key_ty_opt = types
        .template_key_type(&raw.package_id, &local_template)
        .map_err(&fail)?;
    let (key_val, key_maintainers, key_hash) = match (key_ty_opt, &raw.key) {
        (Some(key_ty), Some(raw_key)) => {
            let kv = types
                .from_wire(&key_ty, &raw_key.key_bytes)
                .map_err(|e| fail(format!("contract key decode: {e}")))?;
            let reencoded_k = types
                .to_wire(&key_ty, &kv)
                .map_err(|e| fail(format!("contract key reencode: {e}")))?;
            if reencoded_k != raw_key.key_bytes {
                return Err(fail("contract key is non-canonical".into()));
            }
            let expected_kh = compute_key_hash(&types, &pkg_name, &local_template, &key_ty, &kv)
                .map_err(&fail)?;
            if raw_key.hash.as_slice() != expected_kh.as_slice() {
                return Err(fail("contract key hash mismatch".into()));
            }
            (Some(kv), raw_key.maintainers.clone(), Some(expected_kh))
        }
        (None, None) => (None, Vec::new(), None),
        _ => {
            return Err(fail(
                "contract key presence does not match template declaration".into(),
            ))
        }
    };

    // Template metadata verification (precondition, signatories, observers, key & maintainers).
    let ensure_ok = world
        .eval_template_precond_in(
            &raw.package_id,
            &raw.module_name,
            &raw.entity_name,
            &payload,
        )
        .map_err(|e| fail(format!("ensure check failed: {e}")))?;
    if !ensure_ok {
        return Err(fail("template ensure precondition returned false".into()));
    }

    let eval_sigs = world
        .eval_template_signatories_in(
            &raw.package_id,
            &raw.module_name,
            &raw.entity_name,
            &payload,
        )
        .map_err(|e| fail(format!("signatories evaluation: {e}")))?;
    let expected_sigs: BTreeSet<String> = eval_sigs.into_iter().collect();
    if expected_sigs.is_empty() || !expected_sigs.iter().all(|p| is_valid_party(p)) {
        return Err(fail("invalid template signatories".into()));
    }

    let eval_obs = world
        .eval_template_observers_in(
            &raw.package_id,
            &raw.module_name,
            &raw.entity_name,
            &payload,
        )
        .map_err(|e| fail(format!("observers evaluation: {e}")))?;
    let mut expected_non_sig_obs: BTreeSet<String> = eval_obs.into_iter().collect();
    if !expected_non_sig_obs.iter().all(|p| is_valid_party(p)) {
        return Err(fail("invalid template observers".into()));
    }
    expected_non_sig_obs.retain(|p| !expected_sigs.contains(p));

    if let Some(kv) = &key_val {
        let Some((expected_k, expected_maint)) = world
            .eval_template_key_in(
                &raw.package_id,
                &raw.module_name,
                &raw.entity_name,
                &payload,
            )
            .map_err(|e| fail(format!("template key evaluation: {e}")))?
        else {
            return Err(fail("template key evaluation returned None".into()));
        };
        if !values_equal(kv, &expected_k).map_err(|e| fail(format!("key compare: {e}")))? {
            return Err(fail(
                "declared contract key differs from template key expression".into(),
            ));
        }
        let expected_maint_set: BTreeSet<String> = expected_maint.into_iter().collect();
        if expected_maint_set.is_empty() || !expected_maint_set.is_subset(&expected_sigs) {
            return Err(fail(
                "maintainers invalid or not subset of signatories".into(),
            ));
        }
        let expected_maint_vec: Vec<String> = expected_maint_set.iter().cloned().collect();
        if key_maintainers != expected_maint_vec {
            return Err(fail("contract key maintainers mismatch".into()));
        }
        let expected_non_maint_sigs: Vec<String> = expected_sigs
            .difference(&expected_maint_set)
            .cloned()
            .collect();
        if raw.non_maintainer_signatories != expected_non_maint_sigs {
            return Err(fail("non_maintainer_signatories mismatch".into()));
        }
    } else {
        let expected_sigs_vec: Vec<String> = expected_sigs.iter().cloned().collect();
        if raw.non_maintainer_signatories != expected_sigs_vec {
            return Err(fail("signatories mismatch".into()));
        }
    }

    let expected_obs_vec: Vec<String> = expected_non_sig_obs.into_iter().collect();
    if raw.non_signatory_stakeholders != expected_obs_vec {
        return Err(fail("non_signatory_stakeholders mismatch".into()));
    }

    let contract_hash =
        compute_contract_hash(&types, &pkg_name, &local_template, &tpl_ty, &payload)
            .map_err(&fail)?;
    let sigs_vec: Vec<String> = expected_sigs.into_iter().collect();
    let expected_unicum = compute_unicum(
        &salt,
        raw.created_at_micros,
        &sigs_vec,
        &expected_obs_vec,
        key_hash.as_ref(),
        &key_maintainers,
        &contract_hash,
    );
    if expected_unicum != cid_unicum {
        return Err(fail("contract id unicum mismatch".into()));
    }

    Ok(AuthenticatedFatContract {
        contract_id: raw.contract_id.clone(),
        package_id: raw.package_id.clone(),
        package_name: raw.package_name.clone(),
        module_name: raw.module_name.clone(),
        entity_name: raw.entity_name.clone(),
        payload,
        signatories: sigs_vec,
        observers: expected_obs_vec,
        created_at_micros: raw.created_at_micros,
        salt,
        key: key_val,
        key_maintainers,
        key_hash,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value as Json;

    use super::*;

    fn root_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    fn expected_jsonl_created_event(
        entity_suffix: &str,
        require_blob: bool,
    ) -> Option<(String, String, String, Json)> {
        let raw = std::fs::read_to_string(root_dir().join("tests/oracle/json-api/expected.jsonl"))
            .ok()?;
        raw.lines()
            .filter(|l| l.contains(entity_suffix))
            .find_map(|l| {
                let row: Json = serde_json::from_str(l).ok()?;
                let body = row.get("body")?;
                let mut stack = vec![body];
                while let Some(v) = stack.pop() {
                    match v {
                        Json::Object(map) => {
                            for key in ["CreatedEvent", "createdEvent"] {
                                if let Some(ce) = map.get(key) {
                                    let matches_tpl = ce["templateId"]
                                        .as_str()
                                        .is_some_and(|t| t.ends_with(&format!(":{entity_suffix}")));
                                    let blob = ce["createdEventBlob"].as_str().unwrap_or("");
                                    if matches_tpl && (!require_blob || !blob.is_empty()) {
                                        return Some((
                                            ce["contractId"].as_str()?.to_string(),
                                            blob.to_string(),
                                            ce["contractKeyHash"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_string(),
                                            ce.clone(),
                                        ));
                                    }
                                }
                            }
                            for child in map.values() {
                                stack.push(child);
                            }
                        }
                        Json::Array(arr) => stack.extend(arr),
                        _ => {}
                    }
                }
                None
            })
    }

    #[test]
    fn real_canton_offer_and_asset_holding_blobs_round_trip_and_authenticate() {
        let disc_dar = root_dir().join("tests/oracle/disclosure/disc-1.0.0.dar");
        let disc_world = World::open(&disc_dar).unwrap();
        let (offer_cid, offer_b64, _, _) =
            expected_jsonl_created_event("Main:Offer", true).expect("Offer blob in expected.jsonl");
        let offer_bytes = decode_strict_base64(&offer_b64).unwrap();
        let raw = decode_fat_contract_blob(&offer_bytes).unwrap();
        assert_eq!(raw.contract_id, offer_cid);
        let auth = authenticate_fat_contract(&disc_world, &raw).unwrap();
        let reencoded = encode_fat_contract(
            &disc_world,
            &FatContractInput {
                contract_id: &auth.contract_id,
                package_id: &auth.package_id,
                package_name: &auth.package_name,
                module_name: &auth.module_name,
                entity_name: &auth.entity_name,
                payload: &auth.payload,
                signatories: &auth.signatories,
                observers: &auth.observers,
                created_at_micros: auth.created_at_micros,
                salt: &auth.salt,
                key: auth.key.as_ref(),
                key_maintainers: &auth.key_maintainers,
                key_hash: auth.key_hash.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(
            reencoded, offer_bytes,
            "Offer blob must match Canton 3.7.2 bit-for-bit"
        );

        let sample_dar = root_dir().join("contracts/target/sample-contract.dar");
        let (ah_cid, ah_b64, _, _) =
            expected_jsonl_created_event("AssetHolding:AssetHolding", true)
                .expect("AssetHolding blob in expected.jsonl");
        let ah_world = World::open(&sample_dar).unwrap();
        let ah_bytes = decode_strict_base64(&ah_b64).unwrap();
        let ah_raw = decode_fat_contract_blob(&ah_bytes).unwrap();
        assert_eq!(ah_raw.contract_id, ah_cid);
        let ah_auth = authenticate_fat_contract(&ah_world, &ah_raw).unwrap();
        let ah_reencoded = encode_fat_contract(
            &ah_world,
            &FatContractInput {
                contract_id: &ah_auth.contract_id,
                package_id: &ah_auth.package_id,
                package_name: &ah_auth.package_name,
                module_name: &ah_auth.module_name,
                entity_name: &ah_auth.entity_name,
                payload: &ah_auth.payload,
                signatories: &ah_auth.signatories,
                observers: &ah_auth.observers,
                created_at_micros: ah_auth.created_at_micros,
                salt: &ah_auth.salt,
                key: ah_auth.key.as_ref(),
                key_maintainers: &ah_auth.key_maintainers,
                key_hash: ah_auth.key_hash.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(
            ah_reencoded, ah_bytes,
            "AssetHolding blob (Numeric 10 = 15.0000000000) must match Canton 3.7.2 bit-for-bit"
        );
    }

    #[test]
    fn real_canton_key_hash_matches_and_keyed_round_trips_and_tamper_fails() {
        let key_dar = root_dir().join("tests/oracle/key-diff/key-diff.dar");
        let world = World::open(&key_dar).unwrap();
        let types = Types::new(&world);
        let pkg_id = &world.main_package_id;
        let pkg_name = types.package_name(pkg_id).unwrap();

        // Cross-check Canton 3.7.2 golden contractKeyHash on Keys:Item:
        let (_, _, expected_kh_b64, ce) = expected_jsonl_created_event("Keys:Item", false)
            .expect("Keys:Item row in expected.jsonl");
        let owner = ce["createArgument"]["owner"].as_str().unwrap().to_string();
        let label = ce["createArgument"]["label"].as_str().unwrap().to_string();
        let note = ce["createArgument"]["note"].as_str().unwrap().to_string();
        let key_ty = types
            .template_key_type(pkg_id, "Keys:Item")
            .unwrap()
            .expect("Keys:Item has a contract key");
        let tpl_ty = types.template(pkg_id, "Keys:Item").unwrap();
        let key_val = Value::Record {
            tycon: None,
            fields: vec![
                ("_1".into(), Value::Party(owner.clone())),
                ("_2".into(), Value::Text(label.clone())),
            ],
        };
        let key_hash = compute_key_hash(&types, &pkg_name, "Keys:Item", &key_ty, &key_val).unwrap();
        assert!(!expected_kh_b64.is_empty());
        assert_eq!(encode_base64(&key_hash), expected_kh_b64);

        // Synthetic keyed V12 round-trip and Stage 2 tamper failure:
        let payload = Value::Record {
            tycon: None,
            fields: vec![
                ("owner".into(), Value::Party(owner.clone())),
                ("label".into(), Value::Text(label)),
                ("note".into(), Value::Text(note)),
            ],
        };
        let signatories = vec![owner.clone()];
        let observers: Vec<String> = vec![];
        let maintainers = vec![owner];
        let created_at_micros = 1_762_955_032_416_621_i64;
        let salt = [0x42u8; 32];
        let disc = [0x11u8; 32];
        let contract_hash =
            compute_contract_hash(&types, &pkg_name, "Keys:Item", &tpl_ty, &payload).unwrap();
        let unicum = compute_unicum(
            &salt,
            created_at_micros,
            &signatories,
            &observers,
            Some(&key_hash),
            &maintainers,
            &contract_hash,
        );
        let cid = format_v12_contract_id(&disc, &unicum);
        let blob_bytes = encode_fat_contract(
            &world,
            &FatContractInput {
                contract_id: &cid,
                package_id: pkg_id,
                package_name: &pkg_name,
                module_name: "Keys",
                entity_name: "Item",
                payload: &payload,
                signatories: &signatories,
                observers: &observers,
                created_at_micros,
                salt: &salt,
                key: Some(&key_val),
                key_maintainers: &maintainers,
                key_hash: Some(&key_hash),
            },
        )
        .unwrap();
        let raw = decode_fat_contract_blob(&blob_bytes).unwrap();
        assert_eq!(raw.version, "2");
        assert_eq!(raw.contract_id, cid);
        let auth = authenticate_fat_contract(&world, &raw).unwrap();
        assert_eq!(auth.key_hash, Some(key_hash));
        let reencoded = encode_fat_contract(
            &world,
            &FatContractInput {
                contract_id: &auth.contract_id,
                package_id: &auth.package_id,
                package_name: &auth.package_name,
                module_name: &auth.module_name,
                entity_name: &auth.entity_name,
                payload: &auth.payload,
                signatories: &auth.signatories,
                observers: &auth.observers,
                created_at_micros: auth.created_at_micros,
                salt: &auth.salt,
                key: auth.key.as_ref(),
                key_maintainers: &auth.key_maintainers,
                key_hash: auth.key_hash.as_ref(),
            },
        )
        .unwrap();
        assert_eq!(reencoded, blob_bytes);

        // Non-canonical base64 padding bit rejection:
        let b64 = encode_base64(b"hi"); // "aGk="
        let bad_b64 = "aGl="; // trailing pad bits non-zero
        assert!(decode_strict_base64(&b64).is_ok());
        assert!(decode_strict_base64(bad_b64).is_err());

        // Overlong varint rejection:
        assert!(parse_proto_fields(&[0x08, 0x81, 0x00]).is_err());

        // Forged payload under same contractId & salt must fail Stage 2 authentication:
        let mut forged = auth.payload;
        if let Value::Record { fields, .. } = &mut forged {
            for (n, v) in fields {
                if n == "note" {
                    *v = Value::Text("tampered".into());
                }
            }
        }
        let mut forged_raw = raw;
        forged_raw.create_arg_bytes = types.to_wire(&tpl_ty, &forged).unwrap();
        let err = authenticate_fat_contract(&world, &forged_raw).unwrap_err();
        assert!(err.0.contains("failed to authenticate contract"));
    }

    #[test]
    fn offer_stage1_flip_vs_stage2_forged_payload() {
        let disc_dar = root_dir().join("tests/oracle/disclosure/disc-1.0.0.dar");
        let disc_world = World::open(&disc_dar).unwrap();
        let (_, offer_b64, _, _) =
            expected_jsonl_created_event("Main:Offer", true).expect("Offer blob in expected.jsonl");

        // Stage 1: 50% base64 char flip (like `{b3!flip}` in dx03) fails decode_fat_contract_blob
        let mut chars: Vec<char> = offer_b64.chars().collect();
        let pos = chars.len() / 2;
        chars[pos] = if chars[pos] != 'A' { 'A' } else { 'B' };
        let flipped_b64: String = chars.into_iter().collect();
        let stage1_res =
            decode_strict_base64(&flipped_b64).and_then(|b| decode_fat_contract_blob(&b));
        assert!(
            stage1_res.is_err(),
            "flipped Offer blob must fail Stage 1 decode"
        );

        // Stage 2: canonical Offer blob with modified price under same contractId & salt
        let offer_bytes = decode_strict_base64(&offer_b64).unwrap();
        let raw = decode_fat_contract_blob(&offer_bytes).unwrap();
        let auth = authenticate_fat_contract(&disc_world, &raw).unwrap();
        let mut forged_payload = auth.payload.clone();
        if let Value::Record { fields, .. } = &mut forged_payload {
            for (n, v) in fields {
                if n == "price" {
                    *v = Value::Int64(999);
                }
            }
        }
        let forged_blob = encode_fat_contract(
            &disc_world,
            &FatContractInput {
                contract_id: &auth.contract_id,
                package_id: &auth.package_id,
                package_name: &auth.package_name,
                module_name: &auth.module_name,
                entity_name: &auth.entity_name,
                payload: &forged_payload,
                signatories: &auth.signatories,
                observers: &auth.observers,
                created_at_micros: auth.created_at_micros,
                salt: &auth.salt,
                key: None,
                key_maintainers: &[],
                key_hash: None,
            },
        )
        .unwrap();
        let decoded_forged = decode_fat_contract_blob(&forged_blob)
            .expect("syntactically valid forged Offer blob must pass Stage 1 decode");
        let auth_err = authenticate_fat_contract(&disc_world, &decoded_forged)
            .expect_err("forged Offer blob under original contractId & salt must fail Stage 2");
        assert!(auth_err.0.contains("failed to authenticate contract"));
    }
}
