//! Locked wire measurement for choice bodies in the four pinned Splice DARs.
//!
//! Recorded when `Expr` was a hand-written message without field 44: an LF 2.3 choice `update` then decoded
//! with `sum == None`, although the bytes say that field is one varint indexing `Package` field 7. Since
//! S-PROTO-002 `lf-archive` uses the types generated from the official 3.7.2 protos, where field 44 is
//! `Expr.interned_expr` and field 7 is `Package.interned_exprs`. The numbers stay comparable:
//! - `sum_some` counts choices whose update is an *inline* expression (a `Sum` other than `InternedExpr`),
//!   `sum_none` the others (interned or empty), exactly as when field 44 was unknown;
//! - `KNOWN_PACKAGE_FIELDS` and `KNOWN_TEMPLATE_FIELDS` are the fields the hand-written module declared, so the
//!   "unknown" columns keep their meaning;
//! - `field7_undecoded` lists the fields of interned expressions that did not decode to a `Sum`. The hand-written
//!   `Expr` left two of them undecoded in the amulet DAR (fields 33 and 34); the official one decodes all of them,
//!   so that cell is now `-`.
//!
//! The measurement does not add fields to any type.

#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_archive::proto::daml_lf::archive_payload::Sum;
use lf_archive::proto::daml_lf::{Archive, ArchivePayload};
use lf_archive::proto::daml_lf_2::{expr::Sum as ExprSum, Expr};
use lf_archive::Manifest;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

const KNOWN_PACKAGE_FIELDS: &[u32] = &[1, 2, 3, 4, 5];
const KNOWN_TEMPLATE_FIELDS: &[u32] = &[1, 2, 3, 4, 6, 7];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        if buf.is_empty() {
            return None;
        }
        let byte = buf[0];
        *buf = &buf[1..];
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

struct WireField<'a> {
    field: u32,
    wire: u32,
    payload: Option<&'a [u8]>,
    varint: Option<u64>,
}

fn take_field<'a>(buf: &mut &'a [u8]) -> Option<WireField<'a>> {
    let key = read_varint(buf)?;
    let field = (key >> 3) as u32;
    let wire = (key & 7) as u32;
    if field == 0 {
        return None;
    }
    match wire {
        0 => Some(WireField {
            field,
            wire,
            payload: None,
            varint: Some(read_varint(buf)?),
        }),
        1 => {
            if buf.len() < 8 {
                return None;
            }
            *buf = &buf[8..];
            Some(WireField {
                field,
                wire,
                payload: None,
                varint: None,
            })
        }
        2 => {
            let len = read_varint(buf)? as usize;
            if buf.len() < len {
                return None;
            }
            let payload = &buf[..len];
            *buf = &buf[len..];
            Some(WireField {
                field,
                wire,
                payload: Some(payload),
                varint: None,
            })
        }
        5 => {
            if buf.len() < 4 {
                return None;
            }
            *buf = &buf[4..];
            Some(WireField {
                field,
                wire,
                payload: None,
                varint: None,
            })
        }
        _ => None,
    }
}

fn foreach_field(mut bytes: &[u8], mut visit: impl FnMut(u32, u32, Option<&[u8]>, Option<u64>)) {
    while !bytes.is_empty() {
        let item = take_field(&mut bytes).expect("DAR protobuf field");
        visit(item.field, item.wire, item.payload, item.varint);
    }
}

fn main_package_bytes(dar_name: &str) -> (String, String, Vec<u8>) {
    let path = repo_root().join("tests/oracle/splice-dars").join(dar_name);
    let mut file_bytes = Vec::new();
    File::open(&path)
        .unwrap_or_else(|err| panic!("open {dar_name}: {err}"))
        .read_to_end(&mut file_bytes)
        .expect("read dar");
    let sha = hex::encode(Sha256::digest(&file_bytes));
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(file_bytes))
        .unwrap_or_else(|err| panic!("zip {dar_name}: {err}"));
    let mut manifest_bytes = Vec::new();
    zip.by_name("META-INF/MANIFEST.MF")
        .expect("manifest")
        .read_to_end(&mut manifest_bytes)
        .expect("read manifest");
    let manifest = Manifest::parse(&manifest_bytes).expect("parse manifest");
    let mut dalf = Vec::new();
    zip.by_name(&manifest.main_dalf)
        .unwrap_or_else(|err| panic!("main dalf {}: {err}", manifest.main_dalf))
        .read_to_end(&mut dalf)
        .expect("read dalf");
    let archive = Archive::decode(dalf.as_slice()).expect("archive envelope");
    let payload = ArchivePayload::decode(archive.payload.as_slice()).expect("archive payload");
    let bytes = match payload.sum {
        Some(Sum::DamlLf2(bytes)) => bytes,
        other => panic!("{dar_name} main payload is {other:?}"),
    };
    (sha, format!("2.{}", payload.minor), bytes)
}

struct Measured {
    sha256: String,
    lf: String,
    choices: u64,
    update_fields: String,
    sum_some: u64,
    sum_none: u64,
    indexes_in_field7: u64,
    target_sum_some: u64,
    package_unknown: String,
    template_unknown: String,
    field7_undecoded: String,
}

fn hist_outside(hist: &BTreeMap<(u32, u32), u64>, known: &[u32]) -> String {
    let text = hist
        .iter()
        .filter(|((field, _), _)| !known.contains(field))
        .map(|((field, wire), count)| format!("{field}/{wire}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    if text.is_empty() {
        "-".to_string()
    } else {
        text
    }
}

fn hist_all(hist: &BTreeMap<(u32, u32), u64>) -> String {
    let text = hist
        .iter()
        .map(|((field, wire), count)| format!("{field}/{wire}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    if text.is_empty() {
        "-".to_string()
    } else {
        text
    }
}

fn measure(dar_name: &str) -> Measured {
    let (sha256, lf, bytes) = main_package_bytes(dar_name);
    let mut package_fields = BTreeMap::new();
    let mut template_fields = BTreeMap::new();
    let mut update_fields = BTreeMap::new();
    let mut field7_none_fields = BTreeMap::new();
    let mut field7_payloads = Vec::new();
    let mut update_indexes = Vec::new();
    let mut choices = 0u64;
    let mut sum_some = 0u64;
    let mut sum_none = 0u64;

    foreach_field(&bytes, |field, wire, payload, _| {
        *package_fields.entry((field, wire)).or_default() += 1;
        if field == 7 {
            if let Some(payload) = payload {
                match Expr::decode(payload) {
                    Ok(expr) if expr.sum.is_some() => {}
                    _ => foreach_field(payload, |field, wire, _, _| {
                        *field7_none_fields.entry((field, wire)).or_default() += 1;
                    }),
                }
                field7_payloads.push(payload.to_vec());
            }
        }
        if field != 1 {
            return;
        }
        let Some(module) = payload else {
            return;
        };
        foreach_field(module, |field, _, payload, _| {
            if field != 6 {
                return;
            }
            let Some(template) = payload else {
                return;
            };
            foreach_field(template, |field, wire, payload, _| {
                *template_fields.entry((field, wire)).or_default() += 1;
                if field != 6 {
                    return;
                }
                let Some(choice) = payload else {
                    return;
                };
                choices += 1;
                foreach_field(choice, |field, _, payload, _| {
                    if field != 9 {
                        return;
                    }
                    let Some(update) = payload else {
                        return;
                    };
                    match Expr::decode(update) {
                        Ok(expr) if matches!(&expr.sum, Some(sum) if !matches!(sum, ExprSum::InternedExpr(_))) => {
                            sum_some += 1
                        }
                        _ => sum_none += 1,
                    }
                    foreach_field(update, |field, wire, _, varint| {
                        *update_fields.entry((field, wire)).or_default() += 1;
                        if wire == 0 && field == 44 {
                            if let Some(value) = varint {
                                update_indexes.push(value);
                            }
                        }
                    });
                });
            });
        });
    });

    let mut indexes_in_field7 = 0u64;
    let mut target_sum_some = 0u64;
    for idx in update_indexes {
        if idx < field7_payloads.len() as u64 {
            indexes_in_field7 += 1;
            if matches!(
                Expr::decode(field7_payloads[idx as usize].as_slice()),
                Ok(expr) if expr.sum.is_some()
            ) {
                target_sum_some += 1;
            }
        }
    }

    Measured {
        sha256,
        lf,
        choices,
        update_fields: hist_all(&update_fields),
        sum_some,
        sum_none,
        indexes_in_field7,
        target_sum_some,
        package_unknown: hist_outside(&package_fields, KNOWN_PACKAGE_FIELDS),
        template_unknown: hist_outside(&template_fields, KNOWN_TEMPLATE_FIELDS),
        field7_undecoded: hist_all(&field7_none_fields),
    }
}

fn expected_rows() -> Vec<Vec<String>> {
    let path = repo_root().join("tests/oracle/splice-dars/lf23-choice-update-wire.tsv");
    let text = std::fs::read_to_string(&path).expect("read wire tsv");
    text.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

#[test]
fn splice_choice_update_wire_matches_locked_tsv() {
    for row in expected_rows() {
        assert_eq!(row.len(), 12, "wire tsv row width: {row:?}");
        let measured = measure(&row[0]);
        let actual = [
            row[0].as_str(),
            measured.sha256.as_str(),
            measured.lf.as_str(),
            &measured.choices.to_string(),
            measured.update_fields.as_str(),
            &measured.sum_some.to_string(),
            &measured.sum_none.to_string(),
            &measured.indexes_in_field7.to_string(),
            &measured.target_sum_some.to_string(),
            measured.package_unknown.as_str(),
            measured.template_unknown.as_str(),
            measured.field7_undecoded.as_str(),
        ];
        let expected: Vec<&str> = row.iter().map(String::as_str).collect();
        assert_eq!(actual.as_slice(), expected.as_slice(), "{}", row[0]);
    }
}
