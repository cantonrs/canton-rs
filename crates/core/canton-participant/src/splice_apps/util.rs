//! Small helpers of the Splice app runtime: decimals, parties, error mapping, DAR loading and scan auth files.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lf_eval::typed_json::numeric;
use lf_eval::{ExecError, World};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use super::{SpliceAppError, DEFAULT_INITIAL_TIME_MICROS, SCALE_10};

pub(super) fn map_exec_error(err: ExecError) -> SpliceAppError {
    match &err {
        ExecError::ContractNotFound(_) => SpliceAppError::NotFound(err.to_string()),
        ExecError::ContractNotActive(_) => SpliceAppError::Conflict(err.to_string()),
        ExecError::Unauthorized { .. } => SpliceAppError::Unauthorized(err.to_string()),
        _ => SpliceAppError::BadRequest(err.to_string()),
    }
}

pub(super) fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub(super) fn deterministic_party(hint: &str) -> String {
    if hint.contains("::") {
        hint.to_string()
    } else {
        format!(
            "{hint}::1220{}",
            sha256_hex(&format!("canton-party:{hint}"))
        )
    }
}

pub(super) fn dedup_actors<'a>(actors: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for &a in actors {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

pub(super) fn normalize_decimal_10(input: &str) -> Result<String, SpliceAppError> {
    let (coeff, scale) = numeric(input, 10)
        // the official app's OpenAPI decoder words it so (measured, S-G11-001 A5)
        .ok_or_else(|| {
            SpliceAppError::BadRequest(format!(
                "Failed to decode: Invalid Decimal string \"{input}\", as it does not match \"-?\\d{{1,28}}(\\.\\d{{1,10}})?\""
            ))
        })?;
    let factor = 10i128.pow(u32::from(10u8.saturating_sub(scale)));
    let scaled = coeff
        .checked_mul(factor)
        .ok_or_else(|| SpliceAppError::BadRequest("decimal overflow".into()))?;
    if scaled <= 0 {
        return Err(SpliceAppError::BadRequest(
            "amount must be strictly positive".into(),
        ));
    }
    Ok(format_decimal_10(scaled))
}

pub(super) fn format_decimal_10(scaled: i128) -> String {
    let sign = if scaled < 0 { "-" } else { "" };
    let abs = scaled.abs();
    let whole = abs / SCALE_10;
    let frac = abs % SCALE_10;
    format!("{sign}{whole}.{frac:010}")
}

pub(super) fn amulet_value_and_fee(amulet: &Json, current_round: i64) -> (i128, i128) {
    let init = amulet["amount"]["initialAmount"]
        .as_str()
        .and_then(|s| numeric(s, 10))
        .map(|(c, _)| c)
        .unwrap_or(0);
    let created_round = amulet["amount"]["createdAt"]["number"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(current_round);
    let rate = amulet["amount"]["ratePerRound"]["rate"]
        .as_str()
        .and_then(|s| numeric(s, 10))
        .map(|(c, _)| c)
        .unwrap_or(0);
    let elapsed = (current_round - created_round).max(0) as i128;
    let fee = elapsed.saturating_mul(rate).min(init.max(0));
    (init, fee)
}

pub(super) fn last_recorded_or(v: Option<i64>) -> Option<i64> {
    v
}

pub(super) fn event_touches_party(ev: &Json, party: &str) -> bool {
    let in_list = |arr: &Json| {
        arr.as_array()
            .map(|items| items.iter().any(|x| x.as_str() == Some(party)))
            .unwrap_or(false)
    };
    in_list(&ev["signatories"])
        || in_list(&ev["observers"])
        || in_list(&ev["acting_parties"])
        || ev["create_arguments"]["owner"].as_str() == Some(party)
        || ev["choice_argument"]["receiver"].as_str() == Some(party)
        || ev["choice_argument"]["transfer"]["sender"].as_str() == Some(party)
}

pub(super) fn load_dar_dir(dar_dir: &Path) -> Result<(Vec<PathBuf>, World), String> {
    let mut dar_paths: Vec<PathBuf> = std::fs::read_dir(dar_dir)
        .map_err(|e| format!("cannot read DAR dir {}: {e}", dar_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("dar"))
        .collect();
    dar_paths.sort();
    if dar_paths.is_empty() {
        return Err(format!("no .dar files found in {}", dar_dir.display()));
    }

    let mut world = World::open(&dar_paths[0])
        .map_err(|e| format!("cannot open {}: {e}", dar_paths[0].display()))?;
    for extra in &dar_paths[1..] {
        world
            .add_dar(extra)
            .map_err(|e| format!("cannot add DAR {}: {e}", extra.display()))?;
    }
    Ok((dar_paths, world))
}

pub(super) fn wall_clock_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(DEFAULT_INITIAL_TIME_MICROS)
}

pub(super) fn merge_scan_auth_file(
    path: &Path,
    auth_out: &mut HashMap<String, Vec<u8>>,
) -> Result<(), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let map: HashMap<String, String> = match serde_json::from_str(&text) {
        Ok(map) => map,
        Err(_) => text
            .lines()
            .filter_map(|l| serde_json::from_str::<Json>(l).ok())
            .filter_map(|l| {
                Some((
                    l["contract_id"].as_str()?.to_string(),
                    l["authentication_data"].as_str()?.to_string(),
                ))
            })
            .collect(),
    };
    for (id, hex_str) in map {
        if auth_out.contains_key(&id) {
            continue;
        }
        let bytes = hex::decode(hex_str.trim())
            .map_err(|_| format!("invalid hex salt for {id} in {}", path.display()))?;
        auth_out.insert(id, bytes);
    }
    Ok(())
}
