//! U-13 (part i): the wire form of the `Signature` message, replayed against canton-algo.
//!
//! The recording (`tests/oracle/canton-crypto/expected.tsv`, `sgp` lines, made by `scripts/verify-canton-crypto.sh --update`)
//! holds what a Canton 3.7.2 node answered, through its console, to `Signature.fromProtoV30` on hand-built bytes of a
//! `v30.Signature` (field order reversed or interleaved, repeated scalars and embedded messages, unknown fields of every wire
//! type, known fields with the wrong wire type, non-canonical and over-long varints, a bad UTF-8 `signed_by`, truncation,
//! groups, a session-key delegation with boundary timestamps and durations) and on the same message inside the
//! `UntypedVersionedMessage` wrapper (`Signature.fromTrustedByteString`). Every line carries its input, so the same test runs
//! on the recording and on a fresh node run.
//!
//! [CANTON-NOTE: ORACLE] The oracle is ScalaPB's parser plus the node's own `fromProtoV30`, not the proto definition: prost
//! would refuse a known field with the wrong wire type that the node skips, so the Rust side reads these bytes with the
//! protobuf-java-compatible reader of `canton_algo::signing::parse_signature`.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use canton_algo::signing::{parse_signature, parse_versioned_signature};

fn file() -> String {
    let path = std::env::var("CANTON_CRYPTO_FILE").unwrap_or_else(|_| {
        format!(
            "{}/../../../tests/oracle/canton-crypto/expected.tsv",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn lines_of(kind: &str) -> Vec<Vec<String>> {
    file()
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect::<Vec<_>>())
        .filter(|f| f.first().map(String::as_str) == Some(kind))
        .collect()
}

/// Compares one failure with the node's. `class` is the node's error class.
fn check_error(
    name: &str,
    outcome: &str,
    class: &str,
    got_class: &str,
    thrown: bool,
) -> Result<(), String> {
    let want_thrown = outcome == "THROW";
    if want_thrown != thrown || class != got_class {
        return Err(format!(
            "{name}: the node says {outcome}/{class}, this implementation says {got_class} (thrown: {thrown})"
        ));
    }
    Ok(())
}

fn check_sgp(f: &[String]) -> Result<(), String> {
    let [_, name, mode, input, outcome, class, detail] = f else {
        return Err(format!("malformed sgp line: {f:?}"));
    };
    let wire = hex::decode(input).unwrap();
    let parsed = if mode == "w" {
        parse_versioned_signature(&wire)
    } else {
        parse_signature(&wire)
    };
    match (outcome.as_str(), parsed) {
        ("OK", Ok(s)) => {
            if &s.describe() != detail {
                return Err(format!(
                    "{name}: the node reads `{detail}`, this implementation `{}`",
                    s.describe()
                ));
            }
            Ok(())
        }
        ("OK", Err(e)) => Err(format!(
            "{name}: the node accepts, this implementation says {e:?}"
        )),
        (_, Ok(s)) => Err(format!(
            "{name}: the node says {outcome}/{class}, this implementation accepts {s:?}"
        )),
        (_, Err(e)) => check_error(name, outcome, class, e.class(), e.is_thrown()),
    }
}

#[test]
fn signature_wire_forms_are_read_like_the_node() {
    let lines = lines_of("sgp");
    let mut accepted = 0;
    let mut thrown = 0;
    for f in &lines {
        check_sgp(f).unwrap_or_else(|e| panic!("{e}"));
        accepted += usize::from(f[4] == "OK");
        thrown += usize::from(f[4] == "THROW");
    }
    assert!(lines.len() >= 130, "{} sgp cases", lines.len());
    assert!(accepted >= 60, "{accepted} accepted");
    assert!(thrown >= 20, "{thrown} thrown");
    // facts that make this matrix more than a list of numbers (each is a line of the recording)
    let outcome = |n: &str| {
        lines
            .iter()
            .find(|f| f[1] == n)
            .unwrap_or_else(|| panic!("{n} missing"))[4]
            .clone()
    };
    for ok in [
        "Ed25519/reversed",
        "Ed25519/unknownGroup",
        "Ed25519/formatVarintTooBig",
        "Ed25519/signatureAsVarint", // a known field with the wrong wire type is skipped, not an error
        "Ed25519/delegation-splitInTwo",
    ] {
        assert_eq!(outcome(ok), "OK", "{ok}");
    }
    for refused in [
        "Ed25519/unknownGroupUnterminated",
        "Ed25519/signedByInvalidUtf8",
        "Ed25519/tagZero",
    ] {
        assert_eq!(outcome(refused), "THROW", "{refused}");
    }
}

/// A checker that cannot fail proves nothing: change a recorded reading and the checker must say so.
#[test]
fn the_checker_detects_a_wrong_reading() {
    let sgp = lines_of("sgp");
    let ok = sgp.iter().find(|f| f[1] == "Ed25519/canonical").unwrap();
    assert!(check_sgp(ok).is_ok());
    let mut tampered = ok.clone();
    tampered[6] = tampered[6].replacen('3', "2", 1);
    assert!(
        check_sgp(&tampered).is_err(),
        "a different reading of the same bytes"
    );
    let mut flipped = ok.clone();
    flipped[4] = "ERR".into();
    assert!(
        check_sgp(&flipped).is_err(),
        "an accepted message recorded as refused"
    );
}
