//! A participant's JSON API stops on SIGTERM (internal review A-14): it stops accepting, lets the requests in flight finish within the
//! grace period, and exits with status 0 with what it recorded on disk, so the next start sees it.
#![allow(clippy::unwrap_used, reason = "integration test")]
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("canton-rs");
    path
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(store: &std::path::Path, port: u16) -> Child {
    let mut child = Command::new(bin())
        .args(["json-api", "--port", &port.to_string(), "--store"])
        .arg(store)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the JSON API does not listen on {port}");
}

fn http(port: u16, method: &str, path: &str, body: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

fn terminate(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if started.elapsed() > within {
            let _ = child.kill();
            let _ = child.wait();
            panic!("still running {within:?} after SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn sigterm_stops_the_json_api_cleanly_and_keeps_what_it_recorded() {
    let dir = std::env::temp_dir().join(format!("srv7-a14-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("ledger.log");

    let port = free_port();
    let mut child = start(&store, port);
    let created = http(
        port,
        "POST",
        "/v2/parties",
        r#"{"partyIdHint":"sigterm","identityProviderId":""}"#,
    );
    assert!(created.starts_with("HTTP/1.1 200"), "{created}");
    let status = terminate(&mut child, Duration::from_secs(10));
    assert!(
        status.success(),
        "the process exits with 0 on SIGTERM: {status:?}"
    );

    let port = free_port();
    let mut again = start(&store, port);
    let parties = http(port, "GET", "/v2/parties", "");
    assert!(parties.contains("sigterm::"), "{parties}");
    assert!(terminate(&mut again, Duration::from_secs(10)).success());
    let _ = std::fs::remove_dir_all(&dir);
}
