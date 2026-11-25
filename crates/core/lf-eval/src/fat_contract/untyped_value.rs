//! Strict validation of untyped `Value` protos inside a fat contract.

use super::{
    expect_utf8, is_valid_lf_name, is_valid_party, is_valid_v1_contract_id_bytes,
    parse_proto_fields, wire_bytes_field, wire_fixed64_field, wire_varint_field, DecodeError,
    WireVal, MAX_DATE_DAYS, MAX_NESTING, MAX_TIMESTAMP_MICROS, MIN_DATE_DAYS, MIN_TIMESTAMP_MICROS,
};

fn is_valid_untyped_numeric_str(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    let Some((whole, frac)) = (match body.split_once('.') {
        Some((w, f)) => (!f.is_empty()).then_some((w, f)),
        None => Some((body, "")),
    }) else {
        return false;
    };
    !whole.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && frac.bytes().all(|b| b.is_ascii_digit())
        && (whole == "0" || !whole.starts_with('0'))
        && whole.len() + frac.len() <= 38
        && frac.len() <= 37
}

pub(super) fn check_strict_party_order(list: &[String], label: &str) -> Result<(), DecodeError> {
    for p in list {
        if !is_valid_party(p) {
            return Err(DecodeError(format!(
                "DecodeError(invalid party '{p}' in {label})"
            )));
        }
    }
    for w in list.windows(2) {
        if w[0] >= w[1] {
            return Err(DecodeError(format!(
                "DecodeError(non-strictly-ordered parties in {label}: '{}' vs '{}')",
                w[0], w[1]
            )));
        }
    }
    Ok(())
}

/// Validates an untyped protobuf `lf.value.Value` for canonical structure, bounds, and party/text syntax.
pub(super) fn validate_untyped_value_proto(
    bytes: &[u8],
    depth: usize,
) -> Result<Vec<u8>, DecodeError> {
    if depth > MAX_NESTING {
        return Err(DecodeError(
            "DecodeError(value nesting exceeds limit)".into(),
        ));
    }
    let fields = parse_proto_fields(bytes)?;
    if fields.len() != 1 {
        return Err(DecodeError(
            "DecodeError(proto Value must have exactly one variant field)".into(),
        ));
    }
    let mut canon = Vec::with_capacity(bytes.len());
    match fields[0] {
        (1, WireVal::Bytes(empty)) => {
            if !empty.is_empty() {
                return Err(DecodeError("DecodeError(Unit must be empty)".into()));
            }
            wire_bytes_field(&mut canon, 1, &[]);
        }
        (2, WireVal::Varint(b)) => {
            if b > 1 {
                return Err(DecodeError("DecodeError(invalid bool varint)".into()));
            }
            wire_varint_field(&mut canon, 2, b);
        }
        (3, WireVal::Varint(zz)) => {
            wire_varint_field(&mut canon, 3, zz);
        }
        (4, WireVal::Varint(raw)) => {
            let days = raw as u32 as i32;
            if i64::from(days) as u64 != raw || !(MIN_DATE_DAYS..=MAX_DATE_DAYS).contains(&days) {
                return Err(DecodeError("DecodeError(date out of range)".into()));
            }
            wire_varint_field(&mut canon, 4, raw);
        }
        (5, WireVal::Fixed64(le)) => {
            let micros = i64::from_le_bytes(le);
            if !(MIN_TIMESTAMP_MICROS..=MAX_TIMESTAMP_MICROS).contains(&micros) {
                return Err(DecodeError("DecodeError(timestamp out of range)".into()));
            }
            wire_fixed64_field(&mut canon, 5, micros);
        }
        (6, WireVal::Bytes(b)) => {
            let s = expect_utf8(b, "numeric")?;
            if !is_valid_untyped_numeric_str(&s) {
                return Err(DecodeError(format!("DecodeError(invalid numeric '{s}')")));
            }
            wire_bytes_field(&mut canon, 6, s.as_bytes());
        }
        (7, WireVal::Bytes(b)) => {
            let p = expect_utf8(b, "party")?;
            if !is_valid_party(&p) {
                return Err(DecodeError(format!("DecodeError(invalid party '{p}')")));
            }
            wire_bytes_field(&mut canon, 7, p.as_bytes());
        }
        (8, WireVal::Bytes(b)) => {
            let t = expect_utf8(b, "text")?;
            if t.contains('\0') {
                return Err(DecodeError(
                    "DecodeError(text contains null character)".into(),
                ));
            }
            wire_bytes_field(&mut canon, 8, t.as_bytes());
        }
        (9, WireVal::Bytes(b)) => {
            if !is_valid_v1_contract_id_bytes(b) {
                return Err(DecodeError("DecodeError(invalid contract id bytes)".into()));
            }
            wire_bytes_field(&mut canon, 9, b);
        }
        (10, WireVal::Bytes(b)) => {
            let opt_fields = parse_proto_fields(b)?;
            let mut inner = Vec::new();
            let mut seen = false;
            for (f, v) in opt_fields {
                if f != 1 || seen {
                    return Err(DecodeError("DecodeError(invalid Optional proto)".into()));
                }
                seen = true;
                let WireVal::Bytes(val_b) = v else {
                    return Err(DecodeError("DecodeError(Optional.value wire type)".into()));
                };
                let c = validate_untyped_value_proto(val_b, depth + 1)?;
                wire_bytes_field(&mut inner, 1, &c);
            }
            wire_bytes_field(&mut canon, 10, &inner);
        }
        (11, WireVal::Bytes(b)) => {
            let mut inner = Vec::new();
            for (f, v) in parse_proto_fields(b)? {
                let (1, WireVal::Bytes(elem)) = (f, v) else {
                    return Err(DecodeError("DecodeError(invalid List proto)".into()));
                };
                let c = validate_untyped_value_proto(elem, depth + 1)?;
                wire_bytes_field(&mut inner, 1, &c);
            }
            wire_bytes_field(&mut canon, 11, &inner);
        }
        (12, WireVal::Bytes(b)) => {
            let mut inner = Vec::new();
            for (f, v) in parse_proto_fields(b)? {
                let (1, WireVal::Bytes(entry_b)) = (f, v) else {
                    return Err(DecodeError("DecodeError(invalid GenMap proto)".into()));
                };
                let mut key_b = None;
                let mut val_b = None;
                for (ef, ev) in parse_proto_fields(entry_b)? {
                    match (ef, ev) {
                        (1, WireVal::Bytes(kb)) if key_b.is_none() => {
                            key_b = Some(validate_untyped_value_proto(kb, depth + 1)?);
                        }
                        (2, WireVal::Bytes(vb)) if val_b.is_none() => {
                            val_b = Some(validate_untyped_value_proto(vb, depth + 1)?);
                        }
                        _ => return Err(DecodeError("DecodeError(invalid GenMap Entry)".into())),
                    }
                }
                let (Some(k), Some(v)) = (key_b, val_b) else {
                    return Err(DecodeError("DecodeError(incomplete GenMap Entry)".into()));
                };
                let mut entry = Vec::new();
                wire_bytes_field(&mut entry, 1, &k);
                wire_bytes_field(&mut entry, 2, &v);
                wire_bytes_field(&mut inner, 1, &entry);
            }
            wire_bytes_field(&mut canon, 12, &inner);
        }
        (13, WireVal::Bytes(b)) => {
            let mut inner = Vec::new();
            for (f, v) in parse_proto_fields(b)? {
                let (1, WireVal::Bytes(fld_b)) = (f, v) else {
                    return Err(DecodeError("DecodeError(invalid Record proto)".into()));
                };
                let mut val_b = None;
                for (ff, fv) in parse_proto_fields(fld_b)? {
                    let (1, WireVal::Bytes(vb)) = (ff, fv) else {
                        return Err(DecodeError(
                            "DecodeError(invalid Record.Field proto)".into(),
                        ));
                    };
                    if val_b.is_some() {
                        return Err(DecodeError(
                            "DecodeError(duplicate Record.Field.value)".into(),
                        ));
                    }
                    val_b = Some(validate_untyped_value_proto(vb, depth + 1)?);
                }
                let Some(vb) = val_b else {
                    return Err(DecodeError(
                        "DecodeError(missing Record.Field.value)".into(),
                    ));
                };
                let mut fld = Vec::new();
                wire_bytes_field(&mut fld, 1, &vb);
                wire_bytes_field(&mut inner, 1, &fld);
            }
            wire_bytes_field(&mut canon, 13, &inner);
        }
        (14, WireVal::Bytes(b)) => {
            let mut con = None;
            let mut val_b = None;
            for (f, v) in parse_proto_fields(b)? {
                match (f, v) {
                    (1, WireVal::Bytes(cb)) if con.is_none() => {
                        let s = expect_utf8(cb, "variant constructor")?;
                        if !is_valid_lf_name(&s) {
                            return Err(DecodeError(
                                "DecodeError(invalid variant constructor)".into(),
                            ));
                        }
                        con = Some(s);
                    }
                    (2, WireVal::Bytes(vb)) if val_b.is_none() => {
                        val_b = Some(validate_untyped_value_proto(vb, depth + 1)?);
                    }
                    _ => return Err(DecodeError("DecodeError(invalid Variant proto)".into())),
                }
            }
            let (Some(con), Some(vb)) = (con, val_b) else {
                return Err(DecodeError("DecodeError(incomplete Variant proto)".into()));
            };
            let mut inner = Vec::new();
            wire_bytes_field(&mut inner, 1, con.as_bytes());
            wire_bytes_field(&mut inner, 2, &vb);
            wire_bytes_field(&mut canon, 14, &inner);
        }
        (15, WireVal::Bytes(b)) => {
            let mut con = None;
            for (f, v) in parse_proto_fields(b)? {
                let (1, WireVal::Bytes(cb)) = (f, v) else {
                    return Err(DecodeError("DecodeError(invalid Enum proto)".into()));
                };
                if con.is_some() {
                    return Err(DecodeError("DecodeError(duplicate Enum.value)".into()));
                }
                let s = expect_utf8(cb, "enum constructor")?;
                if !is_valid_lf_name(&s) {
                    return Err(DecodeError("DecodeError(invalid enum constructor)".into()));
                }
                con = Some(s);
            }
            let Some(con) = con else {
                return Err(DecodeError("DecodeError(missing Enum.value)".into()));
            };
            let mut inner = Vec::new();
            wire_bytes_field(&mut inner, 1, con.as_bytes());
            wire_bytes_field(&mut canon, 15, &inner);
        }
        (16, WireVal::Bytes(b)) => {
            let mut inner = Vec::new();
            let mut prev_key: Option<String> = None;
            for (f, v) in parse_proto_fields(b)? {
                let (1, WireVal::Bytes(entry_b)) = (f, v) else {
                    return Err(DecodeError("DecodeError(invalid TextMap proto)".into()));
                };
                let mut key = None;
                let mut val_b = None;
                for (ef, ev) in parse_proto_fields(entry_b)? {
                    match (ef, ev) {
                        (1, WireVal::Bytes(kb)) if key.is_none() => {
                            let s = expect_utf8(kb, "text map key")?;
                            if s.contains('\0') {
                                return Err(DecodeError("DecodeError(text contains null)".into()));
                            }
                            key = Some(s);
                        }
                        (2, WireVal::Bytes(vb)) if val_b.is_none() => {
                            val_b = Some(validate_untyped_value_proto(vb, depth + 1)?);
                        }
                        _ => return Err(DecodeError("DecodeError(invalid TextMap Entry)".into())),
                    }
                }
                let (Some(k), Some(vb)) = (key, val_b) else {
                    return Err(DecodeError("DecodeError(incomplete TextMap Entry)".into()));
                };
                if let Some(prev) = &prev_key {
                    if *prev >= k {
                        return Err(DecodeError(
                            "DecodeError(unsorted or duplicate TextMap key)".into(),
                        ));
                    }
                }
                prev_key = Some(k.clone());
                let mut entry = Vec::new();
                wire_bytes_field(&mut entry, 1, k.as_bytes());
                wire_bytes_field(&mut entry, 2, &vb);
                wire_bytes_field(&mut inner, 1, &entry);
            }
            wire_bytes_field(&mut canon, 16, &inner);
        }
        _ => {
            return Err(DecodeError(
                "DecodeError(unknown or invalid Value field)".into(),
            ))
        }
    }
    if canon != bytes {
        return Err(DecodeError(
            "DecodeError(non-canonical Value protobuf)".into(),
        ));
    }
    Ok(canon)
}
