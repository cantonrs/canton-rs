//! S-TX-001 (part 2): the Splice execution scenarios against the recorded JVM answers, without Docker.
//!
//! `tests/oracle/splice-diff/<group>/expected.jsonl` holds what `daml script --ide-ledger` (Canton 3.7.2 toolchain)
//! printed for every scenario of `scripts/gen-splice-diff.py`; `scripts/verify-splice-diff.sh` checks that the file is
//! still what the JVM prints. This test runs the same scenarios with the Rust engine (`splice-diff` binary) on the
//! pinned Splice DARs (LF 2.3 for amulet and wallet, LF 2.1 for validator-lifecycle) and requires the same step
//! outcomes, the messages of failed steps (U-6: an uncaught Daml exception or FailureStatus, `failure:<errorId>|<message>`)
//! and observed active contracts (numeric cells compared as decimals).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::{fs, path::PathBuf, process::Command};

use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn norm_cell(v: &str) -> String {
    let numeric = !v.is_empty()
        && v.trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
        && v.matches('.').count() <= 1
        && v.chars().any(|c| c.is_ascii_digit());
    if !numeric || !v.contains('.') {
        return v.to_string();
    }
    let t = v.trim_end_matches('0').trim_end_matches('.');
    if t.is_empty() || t == "-" {
        "0".to_string()
    } else {
        t.to_string()
    }
}

/// Environment differences that carry no meaning (the same rule as `scripts/compare-splice-diff.py`): the IDE ledger's
/// party ids end in `-<8 hex digits>` and print contract ids as `<contract-id>`; the Rust ledger names parties plainly
/// and numbers contracts `#n`.
fn norm_detail(text: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // `-` + 8 lowercase hex digits + a word boundary, right after a letter or digit
        if chars[i] == '-'
            && i > 0
            && chars[i - 1].is_ascii_alphanumeric()
            && i + 9 <= chars.len()
            && chars[i + 1..i + 9]
                .iter()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(c))
            && chars
                .get(i + 9)
                .is_none_or(|c| !c.is_ascii_alphanumeric() && *c != '_')
        {
            i += 9;
            continue;
        }
        if chars[i] == '#' && chars.get(i + 1).is_some_and(char::is_ascii_digit) {
            out.push_str("<contract-id>");
            i += 1;
            while chars.get(i).is_some_and(char::is_ascii_digit) {
                i += 1;
            }
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn normalize(mut scenario: Value) -> Value {
    if let Some(details) = scenario["details"].as_array_mut() {
        for d in details {
            *d = Value::String(norm_detail(d.as_str().unwrap_or("")));
        }
    }
    if let Some(acs) = scenario["acs"].as_object_mut() {
        for rows in acs.values_mut() {
            let mut normalized: Vec<String> = rows
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|row| {
                            let cells: std::collections::BTreeMap<String, String> = row
                                .as_object()
                                .unwrap()
                                .iter()
                                .map(|(k, v)| (k.clone(), norm_cell(v.as_str().unwrap_or(""))))
                                .collect();
                            serde_json::to_string(&cells).unwrap()
                        })
                        .collect()
                })
                .unwrap_or_default();
            normalized.sort();
            *rows = Value::Array(normalized.into_iter().map(Value::String).collect());
        }
    }
    scenario
}

fn run_group(group: &str) -> usize {
    let dir = root().join("tests/oracle/splice-diff").join(group);
    let spec: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("scenarios.json")).unwrap()).unwrap();
    let dar = root()
        .join("tests/oracle/splice-dars")
        .join(spec["dar"].as_str().unwrap());
    let out = Command::new(env!("CARGO_BIN_EXE_splice-diff"))
        .arg(&dar)
        .arg(dir.join("scenarios.json"))
        .output()
        .expect("run splice-diff");
    assert!(
        out.status.success(),
        "{group}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rust: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let jvm: Vec<Value> = fs::read_to_string(dir.join("expected.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rust.len(), jvm.len(), "{group}: scenario count");
    let mut by_name = std::collections::BTreeMap::new();
    for r in rust {
        by_name.insert(r["name"].as_str().unwrap().to_string(), normalize(r));
    }
    for j in &jvm {
        let name = j["name"].as_str().unwrap();
        let r = by_name
            .get(name)
            .unwrap_or_else(|| panic!("{group}: Rust has no scenario {name}"));
        assert_eq!(&r["steps"], &j["steps"], "{group}/{name}: step outcomes");
        assert_eq!(
            &r["details"],
            &normalize(j.clone())["details"],
            "{group}/{name}: messages of failed steps"
        );
        assert_eq!(
            &r["acs"],
            &normalize(j.clone())["acs"],
            "{group}/{name}: observed contracts"
        );
    }
    jvm.len()
}

#[test]
fn splice_amulet_scenarios_match_the_recorded_jvm_answers() {
    assert!(run_group("amulet") >= 930);
}

#[test]
fn splice_wallet_scenarios_match_the_recorded_jvm_answers() {
    assert!(run_group("wallet") >= 35);
}

#[test]
fn splice_validator_lifecycle_scenarios_match_the_recorded_jvm_answers() {
    assert!(run_group("lifecycle") >= 15);
}

#[test]
fn splice_dso_governance_scenarios_match_the_recorded_jvm_answers() {
    assert!(run_group("dso") >= 100);
}
