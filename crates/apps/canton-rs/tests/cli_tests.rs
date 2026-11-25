#![allow(clippy::unwrap_used, reason = "integration test helper")]
use std::path::PathBuf;
use std::process::Command;

fn get_bin_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("canton-rs");
    path
}

fn sample_dar_path() -> String {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../../../contracts/target/sample-contract.dar")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn test_cli_help() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .arg("--help")
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Single binary release for Canton distributed ledger"));
    assert!(stdout.contains("sequencer"));
    assert!(stdout.contains("participant"));
    assert!(stdout.contains("mediator"));
    assert!(stdout.contains("splice"));
    assert!(stdout.contains("db"));
    assert!(stdout.contains("dpm"));
    assert!(stdout.contains("script"));
    assert!(stdout.contains("localnet"));
    assert!(stdout.contains("console"));
}

#[test]
fn test_cli_sequencer_help() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["sequencer", "--help"])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("prune"));
}

// One server-binding CLI test at a time so ephemeral `free_port` picks are never stolen by sibling tests.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status();
            let _ = child.wait();
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `canton-rs sequencer run` serves the real API: a client connects, gets the synchronizer's identity, and the server stops on SIGTERM.
#[test]
fn test_cli_sequencer_run_serves_and_status_asks_it() {
    let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = get_bin_path();
    let port = free_port();
    let mut server = ChildGuard(Some(
        Command::new(&bin)
            .args([
                "sequencer",
                "run",
                "--port",
                &port.to_string(),
                "--name",
                "clisync",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the server starts"),
    ));
    let mut up = false;
    let mut early_exit = None;
    for _ in 0..100 {
        if let Ok(Some(st)) = server.0.as_mut().unwrap().try_wait() {
            early_exit = Some(st);
            break;
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !up {
        let out = server.0.take().unwrap().wait_with_output().ok();
        let err = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        panic!("the server did not listen on {port} (exit={early_exit:?}): {err}");
    }
    let status = Command::new(&bin)
        .args(["sequencer", "status", "--port", &port.to_string()])
        .output()
        .expect("status runs");
    let text = String::from_utf8_lossy(&status.stdout).to_string();
    assert!(
        status.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(text.contains("sequencer-public-api"), "{text}");
    assert!(text.contains("Synchronizer ID: clisync::1220"), "{text}");
    assert!(text.contains("::37-0"), "{text}");
    // stopped as a service is: SIGTERM
    let mut child = server.0.take().unwrap();
    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let exit = child.wait().unwrap();
    assert!(
        exit.success(),
        "a stop request ends the server cleanly: {exit:?}"
    );
}

/// `localnet status` asks every synchronizer's sequencer it is given: a LocalNet of `--synchronizers 2` has two, and the second one that
/// answers nothing is OFFLINE while the first is still ONLINE (not "nothing is online").
#[test]
fn test_cli_localnet_status_asks_a_second_sequencer() {
    let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = get_bin_path();
    let l1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let first = l1.local_addr().unwrap().port();
    let second = l2.local_addr().unwrap().port();
    drop(l1);
    drop(l2);
    let mut server = ChildGuard(Some(
        Command::new(&bin)
            .args([
                "sequencer",
                "run",
                "--port",
                &first.to_string(),
                "--name",
                "statussync",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the server starts"),
    ));
    let mut up = false;
    let mut early_exit = None;
    for _ in 0..100 {
        if let Ok(Some(st)) = server.0.as_mut().unwrap().try_wait() {
            early_exit = Some(st);
            break;
        }
        if std::net::TcpStream::connect(("127.0.0.1", first)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !up {
        let out = server.0.take().unwrap().wait_with_output().ok();
        let err = out
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
            .unwrap_or_default();
        panic!("the first sequencer did not listen on {first} (exit={early_exit:?}): {err}");
    }
    let status = Command::new(&bin)
        .args([
            "localnet",
            "--sequencer-port",
            &first.to_string(),
            "--also-sequencer-port",
            &second.to_string(),
            "status",
        ])
        .output()
        .expect("status runs");
    let text = String::from_utf8_lossy(&status.stdout).to_string();
    drop(server);
    assert!(
        status.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(text.contains("Sequencer:   ONLINE"), "{text}");
    assert!(
        text.contains("Sequencer 2:  OFFLINE") || text.contains("Sequencer 2: OFFLINE"),
        "{text}"
    );
}

/// What answers nothing is not reported ONLINE.
#[test]
fn test_cli_sequencer_status_of_nothing_is_an_error() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["sequencer", "status", "--port", &free_port().to_string()])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("no sequencer answers"), "{text}");
    assert!(!text.contains("ONLINE"), "{text}");
}

#[test]
fn test_cli_sequencer_prune_says_it_is_not_served() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["sequencer", "prune", "--before-or-at", "1000000"])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not prune on request"));
}

#[test]
fn test_cli_stubs() {
    let bin = get_bin_path();

    // Participant
    let p_out = Command::new(&bin).arg("participant").output().unwrap();
    assert!(p_out.status.success());
    assert!(String::from_utf8_lossy(&p_out.stdout).contains("Canton Participant Node"));

    // Mediator
    let m_out = Command::new(&bin).arg("mediator").output().unwrap();
    assert!(m_out.status.success());
    assert!(String::from_utf8_lossy(&m_out.stdout).contains("Canton Mediator Node"));

    // LocalNet
    let l_out = Command::new(&bin).arg("localnet").output().unwrap();
    assert!(l_out.status.success());
    assert!(String::from_utf8_lossy(&l_out.stdout).contains("LocalNet Supervisor"));
    assert!(!String::from_utf8_lossy(&l_out.stdout).contains("READY"));

    // Console: without statements to run it says so (S-TOOLS-001; it used to print a banner and succeed)
    let c_out = Command::new(&bin).arg("console").output().unwrap();
    assert!(!c_out.status.success());
    assert!(String::from_utf8_lossy(&c_out.stderr).contains("give statements to run"));
}

#[test]
fn test_cli_mediator_run_dry() {
    // S-LOCAL-009: without a synchronizer to join, `mediator run` refuses; it used to print an "ONLINE (Ready)" banner and serve nothing
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["mediator", "run", "--bind", "127.0.0.1", "--port", "5012"])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--state-dir"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ONLINE"));
}

#[test]
fn test_cli_mediator_status() {
    // S-LOCAL-009: `mediator status` asks a running mediator process; nothing answers here, so it says so (it used to print ONLINE for any
    // port). A live mediator is asked in scripts/verify-mediator.sh.
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["mediator", "status", "--port", "1"])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no mediator answers at 127.0.0.1:1"));
}

#[test]
fn test_cli_mediator_consensus_status() {
    // a Rust mediator process has no consensus of its own: the command says so instead of printing a made-up leader and quorum
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["mediator", "consensus-status", "--port", "5012"])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("runs no BFT consensus of its own"));
}

/// S-TOOLS-001: the console answers from a node or says it cannot; it no longer prints fixed text (`mediator.health.status` used to report
/// an ONLINE mediator nobody asked). Served commands against a live participant are checked by scripts/verify-console.sh.
#[test]
fn test_cli_console_eval_commands() {
    let bin = get_bin_path();
    let run = |statements: &str| {
        Command::new(&bin)
            .args([
                "console",
                "--participant",
                "participant1=127.0.0.1:1",
                "--eval",
                statements,
            ])
            .output()
            .expect("canton-rs console")
    };
    // a node the console was not given is no value
    let unknown = run("mediator.health.status");
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("not found: value mediator"));
    // a 3.7.2 command it does not serve, and a path that is no 3.7.2 command
    let unserved = run("participant1.topology.party_to_participant_mappings.list(\"x\")");
    assert!(String::from_utf8_lossy(&unserved.stderr)
        .contains("is a Canton 3.7.2 console command this console does not serve"));
    let invented = run("participant1.domains.list_connected()");
    assert!(
        String::from_utf8_lossy(&invented.stderr).contains("is not a Canton 3.7.2 console command")
    );
    // a served command asks the node: nothing listens at port 1
    let unreachable = run("println(participant1.ledger_api.state.end())");
    assert!(!unreachable.status.success());
    assert!(
        String::from_utf8_lossy(&unreachable.stderr).contains("cannot reach the JSON Ledger API")
    );
    // values and variables need no node
    let local = run("val x = \"abc\"; println(x.length)");
    assert!(local.status.success());
    assert_eq!(String::from_utf8_lossy(&local.stdout).trim(), "3");
}

#[test]
fn test_cli_splice_workflow_stage12() {
    let bin = get_bin_path();
    let dar = sample_dar_path();
    let out = Command::new(&bin)
        .args(["splice", "workflow", "--dar", &dar, "--sv-count", "4"])
        .output()
        .expect("splice workflow");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"));
    assert!(stdout.contains("Current Mining Round: 2"));
    assert!(stdout.contains("Workflow Status:      SUCCESS"));
}

#[test]
fn test_cli_db_migrate_and_takeover_stage13() {
    let bin = get_bin_path();

    // Checksum works offline and matches Java java.util.zip.CRC32
    let sum_out = Command::new(&bin)
        .args(["db", "checksum", "--sql", "SELECT 1;\n"])
        .output()
        .expect("db checksum");
    assert!(sum_out.status.success());
    assert!(String::from_utf8_lossy(&sum_out.stdout).contains("Flyway CRC32 Checksum:"));

    // Real DB subcommands must NOT pretend to be ONLINE when no PostgreSQL listens
    let unused_url = format!(
        "jdbc:postgresql://127.0.0.1:{}/canton?currentSchema=public",
        free_port()
    );
    for args in [
        vec!["db", "status", "--jdbc-url", &unused_url],
        vec![
            "db",
            "migrate",
            "--jdbc-url",
            &unused_url,
            "--migrate-and-start",
        ],
        vec!["db", "takeover", "--jdbc-url", &unused_url],
    ] {
        let out = Command::new(&bin).args(&args).output().expect("db cmd");
        assert!(!out.status.success(), "{args:?} must fail without PG");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!combined.contains("ONLINE"), "{args:?}: {combined}");
    }
}

#[test]
fn test_cli_dpm_and_script_stage14() {
    let bin = get_bin_path();
    let dar = sample_dar_path();

    let inspect_out = Command::new(&bin)
        .args(["dpm", "inspect-dar", "--summary", &dar])
        .output()
        .expect("dpm inspect-dar");
    assert!(inspect_out.status.success());
    let stdout1 = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(stdout1.contains("0fe75100f5ff666fed86ea5f6a324d7e4bb853e9889c413833a2921c2dcdd4a2"));
    assert!(stdout1.contains("Modules: [AssetHolding]"));

    let val_out = Command::new(&bin)
        .args(["dpm", "validate-dar", &dar])
        .output()
        .expect("dpm validate-dar");
    assert!(val_out.status.success());
    assert!(String::from_utf8_lossy(&val_out.stdout).contains("DAR Validation Status: VALID"));

    let codegen_out = Command::new(&bin)
        .args(["dpm", "codegen", &dar, "--lang", "rust"])
        .output()
        .expect("dpm codegen");
    assert!(codegen_out.status.success());
    assert!(String::from_utf8_lossy(&codegen_out.stdout).contains("pub struct AssetHolding"));

    // S-SCRIPT-002: the runner runs only what the DAR defines. `splitOk` used to "succeed" from a hard-coded model; the sample DAR has
    // no such script, so it is refused now.
    let missing = Command::new(&bin)
        .args([
            "script",
            "--dar",
            &dar,
            "--script-name",
            "AssetHolding:splitOk",
            "--ide-ledger",
        ])
        .output()
        .expect("script runner");
    assert!(
        !missing.status.success(),
        "a script the DAR lacks is refused"
    );
    // a script of the Daml Script host's fixture prints what the official runner printed (tests/oracle/script-host/outputs.tsv)
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/oracle/script-host/script-host.dar");
    let out_file =
        std::env::temp_dir().join(format!("canton-rs-script-{}.json", std::process::id()));
    let script_out = Command::new(&bin)
        .args([
            "script",
            "--dar",
            fixture.to_str().unwrap(),
            "--script-name",
            "Scripts:keys",
            "--ide-ledger",
            "--output-file",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("script runner");
    assert!(
        script_out.status.success(),
        "{}",
        String::from_utf8_lossy(&script_out.stderr)
    );
    let written = std::fs::read_to_string(&out_file).unwrap();
    let _ = std::fs::remove_file(&out_file);
    assert_eq!(written, r#"{"_1":6,"_2":null,"_3":-1}"#);
    // neither --ide-ledger nor a ledger to run against
    let no_ledger = Command::new(&bin)
        .args([
            "script",
            "--dar",
            fixture.to_str().unwrap(),
            "--script-name",
            "Scripts:keys",
        ])
        .output()
        .expect("script runner");
    assert!(!no_ledger.status.success());
}

#[test]
fn test_cli_localnet_start_and_audit_stage15() {
    let bin = get_bin_path();
    let dar = sample_dar_path();

    // S-LOCAL-010: `localnet start` starts real processes (it used to run an in-process model) and runs the scenario through their APIs
    let start_out = Command::new(&bin)
        .args(["localnet", "start", "--nodes", "2", "--dar", &dar])
        // the Splice apps' DARs are found from the repository's root
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .output()
        .expect("localnet start");
    let stdout1 = String::from_utf8_lossy(&start_out.stdout);
    assert!(
        start_out.status.success(),
        "{stdout1}{}",
        String::from_utf8_lossy(&start_out.stderr)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout1).expect("a JSON report");
    assert_eq!(report["pass"], serde_json::json!(true));
    let roles: Vec<&str> = report["processes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["role"].as_str().unwrap())
        .collect();
    assert_eq!(
        roles,
        [
            "sequencer",
            "mediator",
            "participant p1",
            "participant p2",
            "scan",
            "splice apps"
        ]
    );
    assert!(!stdout1.contains("MODEL RUN"));

    let audit_out = Command::new(&bin)
        .args(["localnet", "audit"])
        .output()
        .expect("localnet audit");
    assert!(audit_out.status.success());
    let stdout2 = String::from_utf8_lossy(&audit_out.stdout);
    assert!(
        stdout2.contains("links /usr/lib/libSystem.B.dylib: system")
            || stdout2.contains("links libc.so"),
        "{stdout2}"
    );
    assert!(
        stdout2.contains("Linked libraries: all system libraries"),
        "{stdout2}"
    );
    assert!(
        stdout2.contains("Not measured here"),
        "what it does not measure is said: {stdout2}"
    );
    assert!(
        !stdout2.contains("PASS (100% Pure Rust"),
        "no claim beyond the measure: {stdout2}"
    );
}

/// Starts `canton-rs <args>` (with a free port), waits until it listens, runs `check` and stops it with SIGTERM.
fn serving(args: &[&str], check: impl FnOnce(u16)) {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let bin = get_bin_path();
    let port = free_port();
    let mut argv: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    argv.extend(["--port".to_string(), port.to_string()]);
    let mut child = ChildGuard(Some(
        Command::new(&bin)
            .args(&argv)
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("the server starts"),
    ));
    let mut up = false;
    for _ in 0..100 {
        if let Ok(Some(_)) = child.0.as_mut().unwrap().try_wait() {
            break;
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if up {
        check(port);
    }
    drop(child);
    assert!(up, "`canton-rs {}` listens on {port}", args.join(" "));
}

/// The JSON API in the one executable answers its health and version endpoints over HTTP.
#[test]
fn test_cli_json_api_serves_http() {
    serving(&["json-api"], |port| {
        use std::io::{Read, Write};
        for (path, wanted) in [
            ("/livez", "200"),
            ("/readyz", "200"),
            ("/v1/version", "200"),
        ] {
            // [CANTON-NOTE: TEST] retried: under a parallel run the port `free_port` picked can be taken by another test's server for a moment
            let mut stream = (0..50)
                .find_map(|_| {
                    std::net::TcpStream::connect(("127.0.0.1", port))
                        .map_err(|_| std::thread::sleep(std::time::Duration::from_millis(100)))
                        .ok()
                })
                .expect("the JSON API accepts a connection");
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut answer = String::new();
            stream.read_to_string(&mut answer).unwrap();
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {wanted}")),
                "{path}: {answer}"
            );
        }
    });
}

/// `json-api --auth-cert` (what the supervisor passes for a manifest's `auth_cert`) refuses a request without a token and takes one the
/// certificate's key signed.
#[test]
fn test_cli_json_api_auth_cert_requires_a_token() {
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIICsDCCAZgCCQDpQrqwUAmYpDANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5j
YW50b24tcnMtdGVzdDAgFw0yNjExMTcwNjQ4NDlaGA8yMTI2MTAyNDA2NDg0OVow
GTEXMBUGA1UEAwwOY2FudG9uLXJzLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC1q5hPZbc11hj3UPT00CZKxLmoc9Au9kI+Xbc2NARgQxXjtH4a
xVCdziZ4kG4F/8kJKrl1hTr7B29QEIQHmfV4HAlt/0y9mnNV7kD0ErgUqQTQt/f5
jdpQOkixhU75XMP+GTe4DrNY2LN6mqivFXCd+BZihxUqV2dGKZ/Culyq+z0MIc6k
wYTw+whZOeiCHmALkx4gwSPHnGX0XeSa27OQdnPIYDAHi8fEoKeU95PlxiUSDWl5
gTRUH92enkCWaR6eXiBLzS88TLE2+pPFqRMceG3kW0O2D5xjvyOiwIrxuTuKpEeM
qgtzrACu0YIXkJMwqUIX/IUPJX1EgN2EsX8pAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAKzC62rilMGW3yJ5QF84e3riy/BNBPc4DSluFEJwNSvtXD5Aie2Y9Roh+NLg
jYKShRjHrPwT/3HMcLPPZZr42Y2KmT7PCj9jaFujZ8xesu+T9xaMwWAysFPesDan
Oz7BbZw3QX/bVa9b46ZrumV4ANSePrgaxXdUIy0sF+SbXC/qXgDBDKR1SggsHVch
RxkBljLeqEGwmQkHPXFAgfYw0ktNgetCqJprHnXM3Uhg0XWZK0lBFn/LXqwebCQ5
hZyJb3y4ivdZ8afUcf/DSFV8pD2L+RqN1ZNfVFIynqb4T5zU0pXWgBNc4NgMys/q
RI22yzlf9ZQv4h66MyBh3wrBm5w=
-----END CERTIFICATE-----\n";
    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwYXJ0aWNpcGFudF9hZG1pbiIsInNjb3BlIjoiZGFtbF9sZWRnZXJfYXBpIiwiZXhwIjo0MTAyNDQ0ODAwfQ.o7cDaD63QYE5RqWXCp8l8jvrk9i_EgYDw4o6D2iIQn2JpFZ0oyKMQfhsc_LNIZreohz3Wd1Lv720s_9QVrmGWaSqvxG-c3ZZnWvN5xq7bk7ioCLAG9UW0CsPE1J61vDP5zAZD-hEV-q9SwmuaN4E5J8IZrjxia73ZODhF8LCdJZyIzkZN_QwBcwtSd-Gr3mQv-aELxw1wWW623mm2rsk19zL7axu0jPREDmGGvpH9jdYKkr3yUTdh3YmDw8XGZDjojRvIWspR_NfHhO4NQ-9mohA9n60DYep5-H3h59wyWyH8XW1LN7gfEDAH_A5HJHPB-dMPNTyW_vFYSiGL4yWCw";
    let dir = std::env::temp_dir().join(format!("canton-rs-auth-cert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("jwt.crt");
    std::fs::write(&cert, CERT).unwrap();
    let cert_arg = cert.display().to_string();
    let send_req = |port: u16, token: Option<&str>| -> String {
        use std::io::{Read, Write};
        let mut stream = (0..50)
            .find_map(|_| {
                std::net::TcpStream::connect(("127.0.0.1", port))
                    .map_err(|_| std::thread::sleep(std::time::Duration::from_millis(100)))
                    .ok()
            })
            .expect("the JSON API accepts a connection");
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "GET /v2/parties HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n"
        )
        .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        answer
    };
    serving(&["json-api", "--auth-cert", &cert_arg], |port| {
        let answer = send_req(port, Some(TOKEN));
        assert!(
            answer.starts_with("HTTP/1.1 401"),
            "default max-token-life should reject far-future exp token: {answer}"
        );
    });
    serving(
        &[
            "json-api",
            "--auth-cert",
            &cert_arg,
            "--jwt-max-lifetime-seconds",
            "3000000000",
        ],
        |port| {
            for (token, wanted) in [(None, "401"), (Some(TOKEN), "200")] {
                let answer = send_req(port, token);
                assert!(
                    answer.starts_with(&format!("HTTP/1.1 {wanted}")),
                    "token {}: {answer}",
                    token.is_some()
                );
            }
        },
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The gRPC Ledger API in the one executable answers an HTTP/2 connection (what a gRPC client opens).
#[test]
fn test_cli_ledger_api_serves_http2() {
    serving(&["ledger-api"], |port| {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        // the HTTP/2 client preface and an empty SETTINGS frame: a server that speaks HTTP/2 answers with its own SETTINGS frame
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        stream.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
        let mut frame = [0u8; 9];
        stream
            .read_exact(&mut frame)
            .expect("a frame from the server");
        assert_eq!(
            frame[3], 4,
            "the server's first frame is SETTINGS: {frame:?}"
        );
    });
}

/// `participant status` asks the participant that listens on the port; where nothing answers it says so (it used to print ONLINE and a
/// made-up synchronizer for any port).
#[test]
fn test_cli_participant_status_asks_the_participant() {
    let bin = get_bin_path();
    let port = free_port();
    let output = Command::new(&bin)
        .args(["participant", "status", "--port", &port.to_string()])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("no participant answers at 127.0.0.1:{port}")),
        "{stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ONLINE"));
}

/// Without a synchronizer to join, `participant run` refuses: it used to make a key from the participant's name, print an
/// "ONLINE (Ready)" banner and exit without serving anything.
#[test]
fn test_cli_participant_run_needs_a_synchronizer() {
    let bin = get_bin_path();
    let output = Command::new(&bin)
        .args(["participant", "run", "--port", &free_port().to_string()])
        .output()
        .expect("failed to execute process");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--sequencer"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("ONLINE"));
}

#[test]
fn jwt_rs256_banner_line_is_emitted_even_when_diagnostics_are_off() {
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIICsDCCAZgCCQDpQrqwUAmYpDANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5j
YW50b24tcnMtdGVzdDAgFw0yNjExMTcwNjQ4NDlaGA8yMTI2MTAyNDA2NDg0OVow
GTEXMBUGA1UEAwwOY2FudG9uLXJzLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC1q5hPZbc11hj3UPT00CZKxLmoc9Au9kI+Xbc2NARgQxXjtH4a
xVCdziZ4kG4F/8kJKrl1hTr7B29QEIQHmfV4HAlt/0y9mnNV7kD0ErgUqQTQt/f5
jdpQOkixhU75XMP+GTe4DrNY2LN6mqivFXCd+BZihxUqV2dGKZ/Culyq+z0MIc6k
wYTw+whZOeiCHmALkx4gwSPHnGX0XeSa27OQdnPIYDAHi8fEoKeU95PlxiUSDWl5
gTRUH92enkCWaR6eXiBLzS88TLE2+pPFqRMceG3kW0O2D5xjvyOiwIrxuTuKpEeM
qgtzrACu0YIXkJMwqUIX/IUPJX1EgN2EsX8pAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAKzC62rilMGW3yJ5QF84e3riy/BNBPc4DSluFEJwNSvtXD5Aie2Y9Roh+NLg
jYKShRjHrPwT/3HMcLPPZZr42Y2KmT7PCj9jaFujZ8xesu+T9xaMwWAysFPesDan
Oz7BbZw3QX/bVa9b46ZrumV4ANSePrgaxXdUIy0sF+SbXC/qXgDBDKR1SggsHVch
RxkBljLeqEGwmQkHPXFAgfYw0ktNgetCqJprHnXM3Uhg0XWZK0lBFn/LXqwebCQ5
hZyJb3y4ivdZ8afUcf/DSFV8pD2L+RqN1ZNfVFIynqb4T5zU0pXWgBNc4NgMys/q
RI22yzlf9ZQv4h66MyBh3wrBm5w=
-----END CERTIFICATE-----\n";
    let dir = std::env::temp_dir().join(format!("canton-rs-jwt-banner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let cert = dir.join("jwt.crt");
    std::fs::write(&cert, CERT).expect("write cert");
    let missing_dar = dir.join("missing.dar");

    let bin = get_bin_path();
    let out = Command::new(&bin)
        .env("CANTON_RS_LOG", "off")
        .args([
            "json-api",
            "--auth-cert",
            cert.to_str().expect("utf8 cert path"),
            "--dar",
            missing_dar.to_str().expect("utf8 dar path"),
        ])
        .output()
        .expect("spawn canton-rs json-api");
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("missing.dar"),
        "expected failure only after RS256 auth config setup at missing DAR load; stderr={stderr:?}"
    );
    assert!(
        stdout.contains("JWT authentication: on (jwt-rs-256-crt)"),
        "expected RS256 JWT banner on stdout with CANTON_RS_LOG=off; stdout={stdout:?}, stderr={stderr:?}"
    );
}

#[test]
fn initial_snapshot_times_out_against_unresponsive_daemon() {
    use std::os::unix::net::UnixListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    let dir =
        std::env::temp_dir().join(format!("canton-rs-tui-init-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("daemon.sock");
    let listener = UnixListener::bind(&sock).expect("bind silent daemon.sock");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking silent listener");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let held = std::thread::spawn(move || {
        let mut streams = Vec::new();
        while !stop_srv.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                streams.push(s);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    });

    let bin = get_bin_path();
    let mut child = Command::new("script")
        .args([
            "-q",
            "/dev/null",
            bin.to_str().expect("utf8 bin"),
            "daemon",
            "top",
            "--state-dir",
            dir.to_str().expect("utf8 dir"),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon top under PTY");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    let mut exited = None;
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            exited = Some(status);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if exited.is_none() {
        let _ = child.kill();
    }
    let out = child.wait_with_output().expect("wait_with_output");
    stop.store(true, Ordering::Relaxed);
    let _ = held.join();
    let _ = std::fs::remove_dir_all(&dir);

    let status = exited.expect(
        "daemon top initial GetSnapshot hung > 12s against unresponsive daemon instead of timing out",
    );
    assert!(
        !status.success(),
        "timed-out daemon top must exit non-zero, got {status}"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("timed out")
            || combined.contains("timeout")
            || combined.contains("daemon"),
        "expected timeout/daemon error message on initial snapshot timeout, got: {combined}"
    );
}
