//! G10 AT-K06: the Rust Daml Script host against what `daml script --ide-ledger` printed for the same DAR
//! (tests/oracle/script-host/outputs.tsv, recorded from the official runner).
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use lf_eval::script::{ScriptError, ScriptHost};
use lf_eval::{Value, World};
use std::path::Path;

fn json(v: &Value) -> String {
    match v {
        Value::Int64(n) => n.to_string(),
        Value::Optional(None) => "null".to_string(),
        Value::Optional(Some(inner)) => json(inner),
        Value::List(items) => format!("[{}]", items.iter().map(json).collect::<Vec<_>>().join(",")),
        Value::Party(p) | Value::Text(p) | Value::ContractId(p) => {
            serde_json::to_string(p).unwrap()
        }
        Value::Record { fields, .. } => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(n, v)| format!("\"{n}\":{}", json(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Bool(b) => b.to_string(),
        other => format!("{other:?}"),
    }
}

/// A `Time` is an `Int64` of microseconds at runtime; the official runner prints it as `YYYY-MM-DDTHH:MM:SSZ` (whole seconds only here).
fn iso(micros: i64) -> String {
    let (days, secs) = (
        micros.div_euclid(86_400_000_000),
        micros.rem_euclid(86_400_000_000) / 1_000_000,
    );
    // civil date from days since the epoch (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// `json`, with every `Int64` read as a `Time`.
fn json_times(v: &Value) -> String {
    match v {
        Value::Int64(n) => format!("\"{}\"", iso(*n)),
        Value::Record { fields, .. } => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(n, v)| format!("\"{n}\":{}", json_times(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => json(other),
    }
}

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/oracle/script-host")
}

#[test]
fn scripts_end_with_what_the_official_runner_printed() {
    let world = World::open(&root().join("script-host.dar")).unwrap();
    let recorded = std::fs::read_to_string(root().join("outputs.tsv")).unwrap();
    let mut checked = 0;
    for line in recorded
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (name, official) = line.split_once('\t').unwrap();
        // every script runs on a fresh ledger: the party suffixes are the IDE ledger's, counted from its start
        let ours = ScriptHost::new(&world).run("Scripts", name).unwrap();
        // the scripts that return a `Time` are the ones whose official output has a time in it
        let shown = if name.contains("Clock") || name.contains("Read") {
            json_times(&ours)
        } else {
            json(&ours)
        };
        // compared as JSON values: the recording escapes non-ASCII (`\u00e9`), serde writes it as is
        let parse = |s: &str| {
            serde_json::from_str::<serde_json::Value>(s)
                .unwrap_or(serde_json::Value::String(s.to_string()))
        };
        assert_eq!(parse(&shown), parse(official), "script {name}");
        checked += 1;
    }
    assert!(checked >= 3);
}

#[test]
fn a_question_the_host_does_not_answer_stops_the_run() {
    let world = World::open(&root().join("script-host.dar")).unwrap();
    // a question this host does not serve: the run stops and names it, it does not make up an answer
    match ScriptHost::new(&world).run("Scripts", "asksAnUnservedQuestion") {
        Err(ScriptError::Unsupported(command)) => assert_eq!(command, "Secp256k1GenerateKeyPair"),
        other => panic!("{other:?}"),
    }
    // a script that does not exist is an evaluation error, not an empty result
    assert!(matches!(
        ScriptHost::new(&world).run("Scripts", "noSuchScript"),
        Err(ScriptError::Eval(_))
    ));
}

#[test]
fn what_the_official_runner_refuses_the_host_refuses_with_its_message() {
    let world = World::open(&root().join("script-host.dar")).unwrap();
    let recorded = std::fs::read_to_string(root().join("failures.tsv")).unwrap();
    let mut checked = 0;
    for line in recorded
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (name, official) = line.split_once('\t').unwrap();
        // the official line is `<exception class>: <message>`; the message is what the host must give. It may end in the name
        // of a Java class of the runner (`...RunnerException`), which has no meaning here: only what comes before it is compared
        let message = official.split_once(": ").unwrap().1;
        let message = message.split("com.digitalasset").next().unwrap();
        match ScriptHost::new(&world).run("Scripts", name) {
            Err(ScriptError::Eval(ours)) => assert!(
                ours.starts_with(message),
                "script {name}: {ours:?} does not start with {message:?}"
            ),
            other => panic!("script {name}: {other:?}"),
        }
        checked += 1;
    }
    assert!(checked >= 5);
}
