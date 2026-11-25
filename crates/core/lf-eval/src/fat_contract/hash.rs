//! Contract and key hashing (`compute_contract_hash`, `compute_key_hash`) and contract id suffixes (`compute_unicum`).

use sha2::{Digest, Sha256};

use crate::typed_json::{LfType, Types};
use crate::Value;

use super::{
    END_OF_RECORD, HASH_PURPOSE_UNICUM, PURPOSE_NEXT_GEN_CONTRACT_KEY,
    PURPOSE_THIN_CONTRACT_INSTANCE, TAG_BOOL, TAG_CONTRACT_ID, TAG_DATE, TAG_ENUM, TAG_GEN_MAP,
    TAG_INT64, TAG_LIST, TAG_NUMERIC, TAG_OPTIONAL, TAG_PARTY, TAG_RECORD, TAG_TEXT, TAG_TEXT_MAP,
    TAG_TIMESTAMP, TAG_UNIT, TAG_VARIANT, TYPED_NORMAL_FORM_VERSION,
};

fn big_int_to_java_bytes(n: i128) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let raw = n.to_be_bytes();
    if n > 0 {
        let start = raw.iter().position(|&b| b != 0).unwrap_or(15);
        let mut out = Vec::with_capacity(16 - start + 1);
        if (raw[start] & 0x80) != 0 {
            out.push(0);
        }
        out.extend_from_slice(&raw[start..]);
        out
    } else {
        let mut start = 0;
        while start + 1 < 16 && raw[start] == 0xff && (raw[start + 1] & 0x80) != 0 {
            start += 1;
        }
        raw[start..].to_vec()
    }
}

fn rescale_exact(coeff: i128, from_scale: u8, to_scale: u8) -> Result<i128, String> {
    if from_scale == to_scale {
        return Ok(coeff);
    }
    if from_scale < to_scale {
        let factor = 10i128
            .checked_pow(u32::from(to_scale - from_scale))
            .ok_or_else(|| "numeric scale overflow".to_string())?;
        coeff
            .checked_mul(factor)
            .ok_or_else(|| "numeric scale overflow".to_string())
    } else {
        let factor = 10i128
            .checked_pow(u32::from(from_scale - to_scale))
            .ok_or_else(|| "numeric scale overflow".to_string())?;
        if coeff % factor != 0 {
            return Err("numeric loses non-zero fractional digits".to_string());
        }
        Ok(coeff / factor)
    }
}

fn hash_bytes(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as i32).to_be_bytes());
    h.update(bytes);
}

fn hash_str(h: &mut Sha256, s: &str) {
    hash_bytes(h, s.as_bytes());
}

fn hash_dotted_name(h: &mut Sha256, dotted: &str) {
    let segs: Vec<&str> = dotted.split('.').collect();
    h.update((segs.len() as i32).to_be_bytes());
    for seg in segs {
        hash_str(h, seg);
    }
}

fn hash_qualified_name(h: &mut Sha256, module: &str, name: &str) {
    hash_dotted_name(h, module);
    hash_dotted_name(h, name);
}

fn hash_typed_svalue(
    h: &mut Sha256,
    types: &Types<'_>,
    ty: &LfType,
    val: &Value,
    allow_cid: bool,
) -> Result<(), String> {
    match (ty, val) {
        (LfType::Unit, Value::Unit) => h.update([TAG_UNIT]),
        (LfType::Bool, Value::Bool(b)) => {
            h.update([TAG_BOOL, if *b { 1 } else { 0 }]);
        }
        (LfType::Int64, Value::Int64(v)) => {
            h.update([TAG_INT64]);
            h.update(v.to_be_bytes());
        }
        (LfType::Date, Value::Int64(days)) => {
            h.update([TAG_DATE]);
            h.update((*days as i32).to_be_bytes());
        }
        (LfType::Timestamp, Value::Int64(micros)) => {
            h.update([TAG_TIMESTAMP]);
            h.update(micros.to_be_bytes());
        }
        (LfType::Numeric(target_scale), Value::Numeric { coeff, scale }) => {
            let unscaled = match target_scale {
                Some(s) => rescale_exact(*coeff, *scale, *s)?,
                None => *coeff,
            };
            h.update([TAG_NUMERIC]);
            hash_bytes(h, &big_int_to_java_bytes(unscaled));
        }
        (LfType::Party, Value::Party(p)) => {
            h.update([TAG_PARTY]);
            hash_str(h, p);
        }
        (LfType::Text, Value::Text(t)) => {
            h.update([TAG_TEXT]);
            hash_str(h, t);
        }
        (LfType::ContractId, Value::ContractId(cid)) => {
            if !allow_cid {
                return Err("Contract IDs are not supported in contract keys.".to_string());
            }
            let bytes = hex::decode(cid).map_err(|e| format!("invalid contract id {cid}: {e}"))?;
            h.update([TAG_CONTRACT_ID]);
            hash_bytes(h, &bytes);
        }
        (LfType::Optional(inner_ty), Value::Optional(opt)) => {
            h.update([TAG_OPTIONAL]);
            match opt {
                None => h.update([0]),
                Some(v) => {
                    h.update([1]);
                    hash_typed_svalue(h, types, inner_ty, v, allow_cid)?;
                }
            }
        }
        (LfType::List(inner_ty), Value::List(items)) => {
            h.update([TAG_LIST]);
            h.update((items.len() as i32).to_be_bytes());
            for item in items.iter() {
                hash_typed_svalue(h, types, inner_ty, item, allow_cid)?;
            }
        }
        (LfType::TextMap(val_ty), Value::Map(entries)) => {
            h.update([TAG_TEXT_MAP]);
            let mut sorted: Vec<(&str, &Value)> = entries
                .iter()
                .map(|(k, v)| match k {
                    Value::Text(s) => Ok((s.as_str(), v)),
                    _ => Err("non-text key in TextMap".to_string()),
                })
                .collect::<Result<_, _>>()?;
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            h.update((sorted.len() as i32).to_be_bytes());
            for (k, v) in sorted {
                hash_str(h, k);
                hash_typed_svalue(h, types, val_ty, v, allow_cid)?;
            }
        }
        (LfType::GenMap(key_ty, val_ty), Value::Map(entries)) => {
            h.update([TAG_GEN_MAP]);
            h.update((entries.len() as i32).to_be_bytes());
            for (k, v) in entries {
                hash_typed_svalue(h, types, key_ty, k, allow_cid)?;
                hash_typed_svalue(h, types, val_ty, v, allow_cid)?;
            }
        }
        (LfType::Con { module, name, .. }, Value::Record { fields, .. }) => {
            h.update([TAG_RECORD]);
            hash_qualified_name(h, module, name);
            let field_defs = types.record_fields(ty)?;
            if field_defs.len() != fields.len() {
                return Err(format!(
                    "record {module}:{name} field count mismatch: expected {}, got {}",
                    field_defs.len(),
                    fields.len()
                ));
            }
            let ordered: Vec<(&str, &LfType, &Value)> = field_defs
                .iter()
                .map(|(fname, fty)| {
                    let v = fields
                        .iter()
                        .find(|(n, _)| n == fname)
                        .map(|(_, v)| v)
                        .ok_or_else(|| format!("missing field {fname} on {module}:{name}"))?;
                    Ok((fname.as_str(), fty, v))
                })
                .collect::<Result<_, String>>()?;
            let trailing_nones = ordered
                .iter()
                .rev()
                .take_while(|(_, _, v)| matches!(v, Value::Optional(None)))
                .count();
            let keep = ordered.len() - trailing_nones;
            for (fname, fty, fval) in &ordered[..keep] {
                hash_str(h, fname);
                hash_typed_svalue(h, types, fty, fval, allow_cid)?;
            }
            h.update([END_OF_RECORD]);
        }
        (
            LfType::Con { module, name, .. },
            Value::Variant {
                constructor, value, ..
            },
        ) => {
            h.update([TAG_VARIANT]);
            hash_qualified_name(h, module, name);
            let ctors = types.constructors(ty)?;
            let (rank, (_, arg_ty)) = ctors
                .iter()
                .enumerate()
                .find(|(_, (c, _))| c == constructor)
                .ok_or_else(|| {
                    format!("unknown variant constructor {constructor} on {module}:{name}")
                })?;
            hash_str(h, constructor);
            h.update((rank as i32).to_be_bytes());
            hash_typed_svalue(h, types, arg_ty, value, allow_cid)?;
        }
        (LfType::Con { module, name, .. }, Value::Enum { constructor, .. }) => {
            h.update([TAG_ENUM]);
            hash_qualified_name(h, module, name);
            let ctors = types.constructors(ty)?;
            let rank = ctors
                .iter()
                .position(|(c, _)| c == constructor)
                .ok_or_else(|| {
                    format!("unknown enum constructor {constructor} on {module}:{name}")
                })?;
            hash_str(h, constructor);
            h.update((rank as i32).to_be_bytes());
        }
        _ => {
            return Err(format!(
                "type/value mismatch in SValueHash: {ty:?} vs {val:?}"
            ))
        }
    }
    Ok(())
}

/// Computes Canton 3.7.2 `SValueHash.assertHashContractInstance` (`[3, 5]`).
pub fn compute_contract_hash(
    types: &Types<'_>,
    package_name: &str,
    template_id: &str,
    template_ty: &LfType,
    payload: &Value,
) -> Result<[u8; 32], String> {
    let (module, name) = template_id
        .split_once(':')
        .ok_or_else(|| format!("expected Module:Name template id, got {template_id}"))?;
    let mut h = Sha256::new();
    h.update([TYPED_NORMAL_FORM_VERSION, PURPOSE_THIN_CONTRACT_INSTANCE]);
    hash_str(&mut h, package_name);
    hash_qualified_name(&mut h, module, name);
    hash_typed_svalue(&mut h, types, template_ty, payload, true)?;
    Ok(h.finalize().into())
}

/// Computes Canton 3.7.2 `SValueHash.assertHashContractKey` (`[3, 9, 1]`).
pub fn compute_key_hash(
    types: &Types<'_>,
    package_name: &str,
    template_id: &str,
    key_ty: &LfType,
    key: &Value,
) -> Result<[u8; 32], String> {
    let (module, name) = template_id
        .split_once(':')
        .ok_or_else(|| format!("expected Module:Name template id, got {template_id}"))?;
    let mut h = Sha256::new();
    h.update([TYPED_NORMAL_FORM_VERSION, PURPOSE_NEXT_GEN_CONTRACT_KEY, 1]);
    hash_str(&mut h, package_name);
    hash_qualified_name(&mut h, module, name);
    hash_typed_svalue(&mut h, types, key_ty, key, false)?;
    Ok(h.finalize().into())
}

fn encode_party_seq(parties: &[String]) -> Vec<u8> {
    let mut sorted: Vec<&str> = parties.iter().map(String::as_str).collect();
    sorted.sort();
    sorted.dedup();
    let mut out = Vec::new();
    out.extend_from_slice(&(sorted.len() as i32).to_be_bytes());
    for p in sorted {
        out.extend_from_slice(&(p.len() as i32).to_be_bytes());
        out.extend_from_slice(p.as_bytes());
    }
    out
}

/// Computes Canton 3.7.2 `UnicumGenerator.computeUnicumHash` (HashPurpose::Unicum = 29).
pub fn compute_unicum(
    salt: &[u8; 32],
    created_at_micros: i64,
    signatories: &[String],
    non_sig_stakeholders: &[String],
    key_hash: Option<&[u8; 32]>,
    maintainers: &[String],
    contract_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HASH_PURPOSE_UNICUM.to_be_bytes());
    h.update(salt);

    let secs = created_at_micros.div_euclid(1_000_000);
    let nanos = (created_at_micros.rem_euclid(1_000_000) * 1_000) as i32;
    h.update(secs.to_be_bytes());
    h.update(nanos.to_be_bytes());

    let sig_seq = encode_party_seq(signatories);
    hash_bytes(&mut h, &sig_seq);

    let obs_seq = encode_party_seq(non_sig_stakeholders);
    hash_bytes(&mut h, &obs_seq);

    // Contract key hash: encodeOptionWith(_.bytes) WITHOUT outer length prefix
    match key_hash {
        Some(kh) => {
            h.update([1]);
            h.update(kh);
        }
        None => h.update([0]),
    }

    // Maintainers: addByteString(encodeOptionWith(maintainers)(encodeSeqWith))
    match key_hash {
        Some(_) => {
            let m_seq = encode_party_seq(maintainers);
            let mut opt = Vec::with_capacity(1 + m_seq.len());
            opt.push(1);
            opt.extend_from_slice(&m_seq);
            hash_bytes(&mut h, &opt);
        }
        None => hash_bytes(&mut h, &[0]),
    }

    // Contract hash (32 raw bytes, without length prefix)
    h.update(contract_hash);
    h.finalize().into()
}
