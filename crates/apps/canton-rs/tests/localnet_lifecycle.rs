#![allow(clippy::unwrap_used, reason = "integration test")]
//! `canton-rs localnet`: what a user sees when a LocalNet is stopped, fails or is started from outside the repository.
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("canton-rs")
}

fn sample_dar() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/target/sample-contract.dar")
        .canonicalize()
        .unwrap()
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn children_of(pid: u32) -> Vec<u32> {
    let out = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect()
}

/// Reads the localnet's stderr until a line containing `marker`, returning that line.
fn wait_for_line(child: &mut Child, marker: &str) -> String {
    let err = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let wanted = marker.to_string();
    // keeps reading after the marker: a closed pipe would fail the localnet's next line
    std::thread::spawn(move || {
        let mut seen = String::new();
        let mut sent = false;
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if !sent && line.contains(&wanted) {
                sent = true;
                let _ = tx.send(Ok(line.clone()));
            }
            seen.push_str(&line);
            seen.push('\n');
        }
        if !sent {
            let _ = tx.send(Err(seen));
        }
    });
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(line)) => line,
        Ok(Err(seen)) => panic!("the localnet ended before {marker:?}:\n{seen}"),
        Err(_) => panic!("no {marker:?} within 120 s"),
    }
}

fn stop_and_check_children_gone(mut child: Child, kids: &[u32]) {
    assert!(!kids.is_empty(), "the localnet started no processes");
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    let _ = child.wait();
    let deadline = Instant::now() + Duration::from_secs(15);
    while kids.iter().any(|k| alive(*k)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let left: Vec<_> = kids.iter().filter(|k| alive(**k)).collect();
    for k in &left {
        let _ = Command::new("kill")
            .args(["-KILL", &k.to_string()])
            .status();
    }
    assert!(
        left.is_empty(),
        "processes left running after SIGTERM: {left:?}"
    );
}

/// SIGTERM while the scenario is still running stops every process the LocalNet started.
#[test]
fn a_localnet_stopped_during_its_scenario_leaves_no_process() {
    let mut child = Command::new(bin())
        .args(["localnet", "up", "--no-splice", "--no-scan", "--dar"])
        .arg(sample_dar())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_line(&mut child, "participants_ready");
    let kids = children_of(child.id());
    stop_and_check_children_gone(child, &kids);
}

/// `localnet start` takes the options of `up`, works outside the repository, keeps each role's log in a private state directory, runs the
/// sequencer with an admin port, and removes the directory after the processes are stopped.
#[test]
fn a_kept_localnet_started_outside_the_repository_logs_each_role_and_cleans_up() {
    let outside = std::env::temp_dir();
    let mut child = Command::new(bin())
        .current_dir(&outside)
        .args([
            "localnet",
            "start",
            "--nodes",
            "2",
            "--no-splice",
            "--no-scan",
            "--foreground",
            "--dar",
        ])
        .arg(sample_dar())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let up = wait_for_line(&mut child, "LocalNet is up");
    let logs = PathBuf::from(
        up.split("logs in ")
            .nth(1)
            .unwrap_or_else(|| panic!("no log directory named in {up:?}"))
            .trim(),
    );
    let state = logs.parent().unwrap().to_path_buf();
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode,
        0o700,
        "the state directory {} is not private",
        state.display()
    );
    for role in ["sequencer", "mediator", "participant-p1", "participant-p2"] {
        let log = logs.join(format!("{role}.log"));
        assert!(
            Path::new(&log).is_file(),
            "no log for {role} at {}",
            log.display()
        );
    }
    let sequencer_log = std::fs::read_to_string(logs.join("sequencer.log")).unwrap();
    assert!(
        sequencer_log.contains("READY sequencer="),
        "the sequencer log misses its output: {sequencer_log}"
    );
    assert!(
        !sequencer_log.contains("served on the public port"),
        "the sequencer serves its administration on the public port: {sequencer_log}"
    );
    let kids = children_of(child.id());
    stop_and_check_children_gone(child, &kids);
    assert!(
        !state.exists(),
        "the state directory {} was left behind",
        state.display()
    );
}

/// Without a subcommand `localnet` starts nothing and prints no made-up topology.
#[test]
fn bare_localnet_prints_no_topology() {
    let out = Command::new(bin()).arg("localnet").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains("Cluster Topology"), "{text}");
    assert!(text.contains("localnet up"), "{text}");
}
