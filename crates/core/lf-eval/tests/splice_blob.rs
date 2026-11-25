//! G8 (S-SPL-008): the contracts the official Splice 0.10.1 scan app returns carry a `created_event_blob`, the serialized contract instance
//! (`tests/oracle/splice-replay/blobs.jsonl`, recorded from the LocalNet's scan endpoints). The argument inside it, rebuilt by Rust from the
//! contract's JSON payload on the official DARs (`Types::decode` then `Types::to_wire`), is byte for byte the official one, and so is the whole
//! blob rebuilt from the instance's id, template, parties, creation time and contract salt (`scan_update::created_event_blob`).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::typed_json::Types;
use lf_eval::World;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The fields of a protobuf message: (field number, wire type, payload) with the payload of a varint as its little-endian bytes.
fn fields(mut b: &[u8]) -> Vec<(u32, u8, Vec<u8>)> {
    let varint = |b: &mut &[u8]| {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let c = b[0];
            *b = &b[1..];
            v |= u64::from(c & 0x7f) << shift;
            shift += 7;
            if c < 0x80 {
                return v;
            }
        }
    };
    let mut out = Vec::new();
    while !b.is_empty() {
        let key = varint(&mut b);
        let (field, wire) = ((key >> 3) as u32, (key & 7) as u8);
        let payload = match wire {
            0 => varint(&mut b).to_le_bytes().to_vec(),
            1 => {
                let (p, rest) = b.split_at(8);
                b = rest;
                p.to_vec()
            }
            2 => {
                let len = varint(&mut b) as usize;
                let (p, rest) = b.split_at(len);
                b = rest;
                p.to_vec()
            }
            other => panic!("wire type {other}"),
        };
        out.push((field, wire, payload));
    }
    out
}

fn field(b: &[u8], number: u32) -> Vec<u8> {
    fields(b)
        .into_iter()
        .find(|(n, _, _)| *n == number)
        .map(|(_, _, p)| p)
        .unwrap_or_default()
}

fn worlds() -> Vec<World> {
    [
        "splice-amulet-0.1.25.dar",
        "splice-dso-governance-0.1.31.dar",
        "splice-validator-lifecycle-0.1.7.dar",
        "splice-wallet-0.1.26.dar",
    ]
    .iter()
    .map(|d| World::open(&root().join("tests/oracle/splice-dars").join(d)).unwrap())
    .collect()
}

#[test]
fn every_official_blob_is_rebuilt_byte_for_byte() {
    let worlds = worlds();
    let text =
        std::fs::read_to_string(root().join("tests/oracle/splice-replay/blobs.jsonl")).unwrap();
    let mut checked = 0;
    let mut unresolved = Vec::new();
    for line in text.lines() {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        let c = &record["contract"];
        let (package, template) = c["template_id"].as_str().unwrap().split_once(':').unwrap();
        let blob = lf_blob(c["created_event_blob"].as_str().unwrap());
        let versioned = fields(&blob);
        let instance = &versioned.iter().find(|(n, _, _)| *n == 2).unwrap().2;
        let official_arg = field(instance, 4);
        // the world that has the package
        let mut rebuilt = None;
        for world in &worlds {
            let types = Types::new(world);
            let Ok(ty) = types.template(package, template) else {
                continue;
            };
            let value = types
                .decode(&ty, &c["payload"])
                .unwrap_or_else(|e| panic!("{template}: {e}"));
            let arg = types
                .to_wire(&ty, &value)
                .unwrap_or_else(|e| panic!("{template}: {e}"));
            // the inverse: the official bytes read back as a value write the same bytes (`Types::from_wire`)
            let read_back = types
                .from_wire(&ty, &official_arg)
                .unwrap_or_else(|e| panic!("{template}: from_wire: {e}"));
            assert!(
                types.to_wire(&ty, &read_back).unwrap() == official_arg,
                "{template}: from_wire then to_wire does not give the official bytes back"
            );
            // the whole blob: what an update history gives (id, template, parties, creation time) and the contract salt of the creating node
            let strings = |n: u32| -> Vec<String> {
                fields(instance)
                    .into_iter()
                    .filter(|(f, _, _)| *f == n)
                    .map(|(_, _, p)| String::from_utf8(p).unwrap())
                    .collect()
            };
            let created_at = i64::from_le_bytes(field(instance, 7).try_into().unwrap());
            assert_eq!(
                lf_eval::typed_json::format_timestamp_micros(created_at),
                c["created_at"].as_str().unwrap(),
                "{template}: created_at"
            );
            let package_name = types.package_name(package).unwrap();
            let full =
                lf_eval::scan_update::created_event_blob(&lf_eval::scan_update::BlobContract {
                    contract_id: c["contract_id"].as_str().unwrap(),
                    package_id: package,
                    package_name: &package_name,
                    template_id: template,
                    create_arg: &arg,
                    signatories: &strings(5),
                    observers: &strings(6),
                    created_at_micros: created_at,
                    authentication_data: &field(instance, 8),
                })
                .unwrap();
            assert!(
                full == blob,
                "{template} {}: blob of {} bytes, official {}",
                c["contract_id"],
                full.len(),
                blob.len()
            );
            rebuilt = Some(arg);
            break;
        }
        match rebuilt {
            None => unresolved.push(format!("{template} in {package}")),
            Some(bytes) => {
                assert!(
                    bytes == official_arg,
                    "{template} {}: {} bytes, official {}",
                    c["contract_id"],
                    bytes.len(),
                    official_arg.len()
                );
                checked += 1;
            }
        }
    }
    assert!(
        unresolved.is_empty(),
        "package not in the DARs: {unresolved:?}"
    );
    assert!(checked >= 14, "{checked} blobs checked");
}

fn lf_blob(base64: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in base64.bytes().filter(|c| *c != b'=') {
        acc = acc << 6 | ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}
