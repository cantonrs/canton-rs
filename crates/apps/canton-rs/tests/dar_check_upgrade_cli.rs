//! `canton-rs dar check-upgrade <old.dar> <new.dar>`: the participant's upgrade checks on two DARs.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::path::PathBuf;
use std::process::{Command, Output};

fn run(dars: &[&str]) -> Output {
    let mut bin = std::env::current_exe().unwrap();
    bin.pop();
    if bin.ends_with("deps") {
        bin.pop();
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    Command::new(bin.join("canton-rs"))
        .args(["dar", "check-upgrade"])
        .args(dars.iter().map(|d| root.join(d)))
        .output()
        .unwrap()
}

#[test]
fn the_fixture_v2_passes_against_v1_in_either_order() {
    for pair in [
        [
            "tests/oracle/upgrade/upg-1.0.0.dar",
            "tests/oracle/upgrade/upg-2.0.0.dar",
        ],
        [
            "tests/oracle/upgrade/upg-2.0.0.dar",
            "tests/oracle/upgrade/upg-1.0.0.dar",
        ],
    ] {
        let out = run(&pair);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{pair:?}: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("Upgrade checks passed"), "{stdout}");
    }
}

#[test]
fn an_unreadable_dar_fails() {
    let out = run(&[
        "tests/oracle/upgrade/upg-1.0.0.dar",
        "tests/oracle/upgrade/v1/daml.yaml",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("daml.yaml"));
}
