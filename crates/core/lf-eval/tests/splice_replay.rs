//! G8: the transactions the official Splice 0.10.1 apps committed on their LocalNet (`tests/oracle/splice-replay/updates.json`, the scan
//! app's update history recorded by `scripts/verify-splice-replay.sh --update`), re-executed by the Rust engine on the official
//! `splice-dso-governance` DAR, give the official event trees; and a changed official value is found.
#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn replay(updates: &Path) -> (bool, Vec<serde_json::Value>) {
    let out = Command::new(env!("CARGO_BIN_EXE_splice-replay"))
        .arg(root().join("tests/oracle/splice-dars/splice-dso-governance-0.1.31.dar"))
        .arg(updates)
        .output()
        .expect("splice-replay runs");
    let lines = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect();
    (out.status.success(), lines)
}

#[test]
fn the_official_splice_transactions_replay_to_the_official_trees() {
    let (ok, lines) = replay(&root().join("tests/oracle/splice-replay/updates.json"));
    let summary = lines.last().expect("a summary");
    assert!(
        ok,
        "{:?}",
        lines
            .iter()
            .filter(|l| l["outcome"].as_str().is_some_and(|o| o != "same"))
            .collect::<Vec<_>>()
    );
    assert_eq!(summary["differs"], 0);
    assert_eq!(summary["skipped"], 0);
    assert!(summary["same"].as_u64().unwrap() >= 30, "{summary}");
    assert!(
        summary["events_compared"].as_u64().unwrap() >= 150,
        "{summary}"
    );
    // S-SPL-006: what the engine ran, written as a scan writes an update, is the official update item: every one of the transactions
    assert_eq!(summary["rendered_same"], summary["same"], "{summary}");
    assert_eq!(summary["rendered_differs"], 0, "{summary}");
    assert_eq!(summary["not_rendered"], 0, "{summary}");
    // what the history is about: the network's bootstrap, validators joining, the faucet, a traffic purchase, a transfer
    let roots: Vec<&str> = lines
        .iter()
        .flat_map(|l| l["roots"].as_array().into_iter().flatten())
        .filter_map(|r| r.as_str())
        .collect();
    for choice in [
        "DsoBootstrap_Bootstrap",
        "DsoRules_OnboardValidator",
        "AmuletRules_DevNet_Tap",
        "AmuletRules_BuyMemberTraffic",
        "AmuletRules_Transfer",
        "DsoRules_ReceiveSvRewardCoupon",
    ] {
        assert!(roots.contains(&choice), "the history has no {choice}");
    }
}

#[test]
fn a_changed_official_value_is_found() {
    let text =
        std::fs::read_to_string(root().join("tests/oracle/splice-replay/updates.json")).unwrap();
    let mut history: serde_json::Value = serde_json::from_str(&text).unwrap();
    // the result of the first faucet tap names another round
    let mut changed = false;
    for tx in history["transactions"].as_array_mut().unwrap() {
        for event in tx["events_by_id"].as_object_mut().unwrap().values_mut() {
            if !changed && event["choice"] == "AmuletRules_DevNet_Tap" {
                event["exercise_result"]["amuletSum"]["round"]["number"] = "77".into();
                changed = true;
            }
        }
    }
    assert!(changed);
    let path =
        std::env::temp_dir().join(format!("splice-replay-changed-{}.json", std::process::id()));
    std::fs::write(&path, history.to_string()).unwrap();
    let (ok, lines) = replay(&path);
    let _ = std::fs::remove_file(&path);
    assert!(!ok, "a changed result must fail the replay");
    let found = lines.iter().filter_map(|l| l["outcome"].as_str()).any(|o| {
        o.contains("the result of AmuletRules_DevNet_Tap differs at result.amuletSum.round.number")
    });
    assert!(found, "{lines:?}");
}

/// The rendering compares what the replay does not: a detail only the update item carries (here a package name) is found.
#[test]
fn a_changed_detail_of_the_update_item_is_found() {
    let text =
        std::fs::read_to_string(root().join("tests/oracle/splice-replay/updates.json")).unwrap();
    let mut history: serde_json::Value = serde_json::from_str(&text).unwrap();
    let tx = &mut history["transactions"].as_array_mut().unwrap()[0];
    let event = tx["events_by_id"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .find(|e| e["event_type"] == "created_event")
        .unwrap();
    event["package_name"] = "another-package".into();
    let path =
        std::env::temp_dir().join(format!("splice-render-changed-{}.json", std::process::id()));
    std::fs::write(&path, history.to_string()).unwrap();
    let (_, lines) = replay(&path);
    let _ = std::fs::remove_file(&path);
    let summary = lines.last().expect("a summary");
    assert_eq!(summary["rendered_differs"], 1, "{summary}");
    assert_eq!(
        summary["differs"], 0,
        "the replay itself does not look at the package name"
    );
}
