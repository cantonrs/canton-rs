//! Integration tests for S-DX-010 Observability (`M-01` .. `M-04`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

const PROM_IMAGE: &str = "prom/prometheus:v2.54.1";
static SEQ: AtomicUsize = AtomicUsize::new(1);

fn canton_rs_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_canton-rs"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

static PORT_CURSOR: AtomicUsize = AtomicUsize::new(0);

fn free_port() -> u16 {
    let base = 31000 + ((std::process::id() as usize) % 500) * 20;
    for _ in 0..14000 {
        let step = PORT_CURSOR.fetch_add(1, Ordering::SeqCst);
        let candidate = (31000 + ((base - 31000 + step) % 14000)) as u16;
        if [3080, 3901, 6432, 6501, 6502].contains(&candidate) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
    panic!("no free TCP port available in 31000..=45000");
}

fn free_stack_ports() -> [u16; 5] {
    let mut ports = BTreeSet::new();
    while ports.len() < 5 {
        ports.insert(free_port());
    }
    let vec: Vec<u16> = ports.into_iter().collect();
    [vec[0], vec[1], vec[2], vec[3], vec[4]]
}

#[derive(Clone, Debug)]
struct StackSpec {
    name: String,
    synchronizer: String,
    s1_pub: u16,
    s1_adm: u16,
    m1_adm: u16,
    p1_json: u16,
    metrics_port: u16,
}

impl StackSpec {
    fn alloc(name: &str, synchronizer: &str) -> Self {
        let [s1_pub, s1_adm, m1_adm, p1_json, metrics_port] = free_stack_ports();
        Self {
            name: name.to_string(),
            synchronizer: synchronizer.to_string(),
            s1_pub,
            s1_adm,
            m1_adm,
            p1_json,
            metrics_port,
        }
    }
}

struct TestEnv {
    base_dir: PathBuf,
    xdg_state_home: PathBuf,
    containers: Vec<String>,
    instances: Vec<String>,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let base_dir =
            PathBuf::from("/tmp").join(format!("sdx010-{tag}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&base_dir);
        let xdg_state_home = base_dir.join("xdg");
        fs::create_dir_all(&xdg_state_home).expect("mkdir xdg");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o755));
            let _ = fs::set_permissions(&xdg_state_home, fs::Permissions::from_mode(0o755));
        }
        Self {
            base_dir,
            xdg_state_home,
            containers: Vec::new(),
            instances: Vec::new(),
        }
    }

    fn root(&self) -> PathBuf {
        self.xdg_state_home.join("canton-rs")
    }

    fn run_cli(&self, args: &[&str]) -> Output {
        Command::new(canton_rs_bin())
            .args(args)
            .env("XDG_STATE_HOME", &self.xdg_state_home)
            .output()
            .expect("spawn canton-rs")
    }

    fn write_manifest(&self, spec: &StackSpec) -> PathBuf {
        let path = self.base_dir.join(format!("{}.yaml", spec.name));
        let state = self.base_dir.join(format!("{}-local-state", spec.name));
        let dar = repo_root().join("contracts/target/sample-contract.dar");
        let yaml = format!(
            "name: {}\nsynchronizer: {}\nstate_dir: {}\nmetrics_port: {}\nservices:\n  s1:\n    role: sequencer\n    ports: [\"{}:public\", \"{}:admin\"]\n    restart: no\n  m1:\n    role: mediator\n    ports: [\"{}:admin\"]\n    depends_on: [s1]\n    restart: no\n  p1:\n    role: participant\n    ports: [\"{}:json-api\"]\n    dars: [\"{}\"]\n    depends_on: [s1, m1]\n    restart: no\n",
            spec.name,
            spec.synchronizer,
            state.display(),
            spec.metrics_port,
            spec.s1_pub,
            spec.s1_adm,
            spec.m1_adm,
            spec.p1_json,
            dar.display(),
        );
        fs::write(&path, yaml).expect("write manifest");
        path
    }

    fn start_observability_instance(&mut self, spec: &StackSpec) {
        let manifest = self.write_manifest(spec);
        let manifest_s = manifest.display().to_string();
        let mp_s = spec.metrics_port.to_string();
        let out = self.run_cli(&[
            "daemon",
            "up",
            "--name",
            &spec.name,
            "-f",
            &manifest_s,
            "--state-in-files",
            "--port-offset",
            "0",
            "--metrics-port",
            &mp_s,
            "--observability",
            "-d",
        ]);
        assert!(
            out.status.success(),
            "daemon up {} failed:\nstdout:\n{}\nstderr:\n{}",
            spec.name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        self.instances.push(spec.name.clone());
    }

    fn start_prometheus(&mut self) -> u16 {
        let targets_dir = self.root().join("prometheus").join("targets");
        fs::create_dir_all(&targets_dir).expect("mkdir targets");
        let prom_dir = self.base_dir.join("prom-conf");
        fs::create_dir_all(&prom_dir).expect("mkdir prom-conf");
        let cfg_path = prom_dir.join("prometheus.yml");
        let cfg = "\
global:
  scrape_interval: 1s
  evaluation_interval: 1s

scrape_configs:
  - job_name: canton-rs
    file_sd_configs:
      - files:
          - /etc/prometheus/targets/*.json
        refresh_interval: 250ms
    relabel_configs:
      - source_labels: [__address__]
        regex: '127\\.0\\.0\\.1:(.*)'
        target_label: __address__
        replacement: 'host.docker.internal:$1'
";
        fs::write(&cfg_path, cfg).expect("write prometheus.yml");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&prom_dir, fs::Permissions::from_mode(0o755));
            let _ = fs::set_permissions(&cfg_path, fs::Permissions::from_mode(0o644));
        }

        let prom_port = free_port();
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let cname = format!("sdx010-prom-{}-{id}", std::process::id());
        let port_bind = format!("127.0.0.1:{prom_port}:9090");
        let cfg_mount = format!("{}:/etc/prometheus/prometheus.yml:ro", cfg_path.display());
        let targets_mount = format!("{}:/etc/prometheus/targets:ro", targets_dir.display());
        let out = Command::new("docker")
            .args([
                "run",
                "--pull=never",
                "-d",
                "--name",
                &cname,
                "--add-host=host.docker.internal:host-gateway",
                "-p",
                &port_bind,
                "-v",
                &cfg_mount,
                "-v",
                &targets_mount,
                PROM_IMAGE,
                "--config.file=/etc/prometheus/prometheus.yml",
                "--web.listen-address=0.0.0.0:9090",
            ])
            .output()
            .expect("spawn docker run prometheus");
        assert!(
            out.status.success(),
            "docker run prometheus failed (ensure {PROM_IMAGE} exists locally):\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        self.containers.push(cname);

        wait_until("prometheus ready", Duration::from_secs(20), || {
            let (status, _) = http_request("127.0.0.1", prom_port, "GET", "/-/ready", None).ok()?;
            (status == 200).then_some(())
        });
        prom_port
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for cname in self.containers.drain(..) {
            let _ = Command::new("docker").args(["rm", "-fv", &cname]).output();
        }
        for name in std::mem::take(&mut self.instances) {
            let _ = self.run_cli(&["daemon", "remove", "--name", &name, "--force"]);
        }
        let _ = fs::remove_dir_all(&self.base_dir);
    }
}

fn wait_until<T, F>(label: &str, timeout: Duration, mut f: F) -> T
where
    F: FnMut() -> Option<T>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {label} after {}s",
            timeout.as_secs()
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn http_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let payload = body.unwrap_or("");
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("\r\n");
    req.push_str(payload);
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (hdr, rest) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response".to_string())?;
    let status = hdr
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("missing status code in: {hdr}"))?;
    let is_chunked = hdr.lines().any(|l| {
        l.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    });
    let body_str = if is_chunked {
        decode_chunked(rest)?
    } else {
        rest.to_string()
    };
    Ok((status, body_str))
}

fn decode_chunked(input: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = input;
    loop {
        let Some((len_line, after)) = rest.split_once("\r\n") else {
            return Err("truncated chunked body".into());
        };
        let hex_len = len_line.split(';').next().unwrap_or("").trim();
        let len = usize::from_str_radix(hex_len, 16)
            .map_err(|e| format!("bad chunk size '{hex_len}': {e}"))?;
        if len == 0 {
            break;
        }
        if after.len() < len {
            return Err("short chunk payload".into());
        }
        out.push_str(&after[..len]);
        rest = after[len..].strip_prefix("\r\n").unwrap_or(&after[len..]);
    }
    Ok(out)
}

fn url_encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 2);
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn prom_targets(prom_port: u16) -> Option<Vec<Value>> {
    let (status, body) =
        http_request("127.0.0.1", prom_port, "GET", "/api/v1/targets", None).ok()?;
    if status != 200 {
        return None;
    }
    let json: Value = serde_json::from_str(&body).ok()?;
    json["data"]["activeTargets"].as_array().cloned()
}

fn prom_instant_query(prom_port: u16, expr: &str) -> Result<Vec<Value>, String> {
    let path = format!("/api/v1/query?query={}", url_encode_component(expr));
    let (status, body) = http_request("127.0.0.1", prom_port, "GET", &path, None)?;
    if status != 200 {
        return Err(format!("PromQL '{expr}' HTTP {status}: {body}"));
    }
    let json: Value = serde_json::from_str(&body).map_err(|e| format!("parse PromQL json: {e}"))?;
    if json["status"].as_str() != Some("success") {
        return Err(format!("PromQL '{expr}' status != success: {body}"));
    }
    Ok(json["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

#[test]
fn sdx_010_m01_prometheus_scrapes_up() {
    let mut env = TestEnv::new("m01");
    let prom_port = env.start_prometheus();
    let s1 = StackSpec::alloc("obs1", "sync-m01");
    env.start_observability_instance(&s1);

    let local_targets = env.root().join("instances/obs1/prometheus/targets.json");
    let shared_target = env.root().join("prometheus/targets/obs1.json");
    assert!(
        local_targets.is_file(),
        "missing {}",
        local_targets.display()
    );
    assert!(
        shared_target.is_file(),
        "missing {}",
        shared_target.display()
    );

    let targets = wait_until("Prometheus target obs1 up", Duration::from_secs(15), || {
        let active = prom_targets(prom_port)?;
        let hit = active.iter().find(|t| {
            t["labels"]["instance"].as_str() == Some("obs1") && t["health"].as_str() == Some("up")
        })?;
        Some(hit.clone())
    });
    assert_eq!(targets["labels"]["synchronizer"].as_str(), Some("sync-m01"));
    println!("M-01_OK instance=obs1 health=up");
}

#[test]
fn sdx_010_m02_dashboard_panels_all_return_values() {
    let mut env = TestEnv::new("m02");
    let prom_port = env.start_prometheus();
    let s1 = StackSpec::alloc("obs-dash", "sync-m02");
    env.start_observability_instance(&s1);

    wait_until("obs-dash target up", Duration::from_secs(15), || {
        let active = prom_targets(prom_port)?;
        active.into_iter().find(|t| {
            t["labels"]["instance"].as_str() == Some("obs-dash")
                && t["health"].as_str() == Some("up")
        })
    });

    // Generate participant API requests across multiple 1s supervisor polls & Prometheus scrapes
    // so histogram buckets increment over >1 scrape window (yielding finite rate/quantile values).
    for step in 0..4 {
        let _ = http_request("127.0.0.1", s1.p1_json, "GET", "/v2/state/ledger-end", None);
        let _ = http_request(
            "127.0.0.1",
            s1.p1_json,
            "POST",
            "/v2/parties",
            Some(&format!(
                r#"{{"partyIdHint":"DashParty{step}","identityProviderId":""}}"#
            )),
        );
        std::thread::sleep(Duration::from_millis(1200));
    }

    let dash_path = repo_root().join("examples/grafana/canton-rs.json");
    let dash_raw = fs::read_to_string(&dash_path).expect("read grafana dashboard json");
    let dash: Value = serde_json::from_str(&dash_raw).expect("parse dashboard json");
    let panels = dash["panels"].as_array().expect("dashboard panels array");
    assert!(!panels.is_empty(), "dashboard has 0 panels");

    for panel in panels {
        let title = panel["title"].as_str().unwrap_or("<untitled>");
        let targets = panel["targets"].as_array().expect("panel targets");
        assert!(!targets.is_empty(), "panel '{title}' has no targets");
        for tgt in targets {
            let expr = tgt["expr"].as_str().expect("target expr");
            let series = wait_until(
                &format!("non-empty finite result for panel '{title}'"),
                Duration::from_secs(12),
                || {
                    let res = prom_instant_query(prom_port, expr).ok()?;
                    if res.is_empty() {
                        return None;
                    }
                    let all_finite = res.iter().all(|item| {
                        item["value"][1]
                            .as_str()
                            .and_then(|s| s.parse::<f64>().ok())
                            .is_some_and(f64::is_finite)
                    });
                    all_finite.then_some(res)
                },
            );
            println!(
                "M-02_PANEL title=\"{title}\" series={} expr=\"{expr}\"",
                series.len()
            );
        }
    }
}

#[test]
fn sdx_010_m03_two_instances_remove_updates_targets_within_5s() {
    let mut env = TestEnv::new("m03");
    let prom_port = env.start_prometheus();
    let sa = StackSpec::alloc("obs-a", "sync-a");
    let sb = StackSpec::alloc("obs-b", "sync-b");
    env.start_observability_instance(&sa);
    env.start_observability_instance(&sb);

    wait_until("2 active up targets", Duration::from_secs(15), || {
        let active = prom_targets(prom_port)?;
        let up_names: BTreeSet<String> = active
            .iter()
            .filter(|t| t["health"].as_str() == Some("up"))
            .filter_map(|t| t["labels"]["instance"].as_str().map(String::from))
            .collect();
        (up_names.len() == 2 && up_names.contains("obs-a") && up_names.contains("obs-b"))
            .then_some(up_names)
    });

    // Step away from the 5s internal scrape.Manager reload boundary observed at target-up.
    std::thread::sleep(Duration::from_millis(1500));

    let remove_start = Instant::now();
    let rm_out = env.run_cli(&["daemon", "remove", "--name", "obs-b", "--force"]);
    let remove_ms = remove_start.elapsed().as_millis();
    assert!(
        rm_out.status.success(),
        "daemon remove obs-b failed:\n{}",
        String::from_utf8_lossy(&rm_out.stderr)
    );
    env.instances.retain(|n| n != "obs-b");

    // M-A1 allows up to 5s target reflection lag once `obs-b` is removed (`daemon remove` completes).
    let sync_start = Instant::now();
    wait_until(
        "Prometheus drops obs-b leaving only obs-a",
        Duration::from_secs(5),
        || {
            let active = prom_targets(prom_port)?;
            if active.len() != 1 {
                return None;
            }
            let only = &active[0];
            (only["labels"]["instance"].as_str() == Some("obs-a")
                && only["health"].as_str() == Some("up"))
            .then_some(())
        },
    );
    let sync_elapsed = sync_start.elapsed();
    assert!(
        sync_elapsed <= Duration::from_secs(5),
        "target removal reflection took {:?} > 5s (remove_ms={remove_ms})",
        sync_elapsed
    );

    let obs_b_target = env.root().join("prometheus/targets/obs-b.json");
    assert!(
        !obs_b_target.exists(),
        "shared target {} must be deleted by daemon remove",
        obs_b_target.display()
    );
    println!(
        "M-03_OK remaining=obs-a remove_ms={remove_ms} prom_sync_ms={}",
        sync_elapsed.as_millis()
    );
}

#[test]
fn sdx_010_m04_official_aliases_match_exact_value_and_labels() {
    let mut env = TestEnv::new("m04");
    let prom_port = env.start_prometheus();
    let s1 = StackSpec::alloc("obs-alias", "sync-m04");
    env.start_observability_instance(&s1);

    let pairs = [
        (
            "canton_rs_mediator_pending_quorums",
            "daml_mediator_outstanding_requests",
        ),
        (
            "canton_rs_bft_quorum_peers",
            "daml_sequencer_bftordering_p2p_connections_connected",
        ),
    ];

    let extract_series = |res: &[Value]| -> BTreeMap<(String, String), String> {
        let mut out = BTreeMap::new();
        for item in res {
            let sync = item["metric"]["synchronizer"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let node = item["metric"]["node"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let val = item["value"][1].as_str().unwrap_or_default().to_string();
            out.insert((sync, node), val);
        }
        out
    };

    wait_until(
        "alias pairs scraped by Prometheus",
        Duration::from_secs(15),
        || {
            for (rs_name, off_name) in &pairs {
                let rs_res = prom_instant_query(prom_port, rs_name).ok()?;
                let off_res = prom_instant_query(prom_port, off_name).ok()?;
                if rs_res.is_empty() || off_res.is_empty() {
                    return None;
                }
            }
            Some(())
        },
    );

    for (rs_name, off_name) in &pairs {
        let rs_map = extract_series(&prom_instant_query(prom_port, rs_name).expect("rs query"));
        let off_map = extract_series(&prom_instant_query(prom_port, off_name).expect("off query"));
        assert!(!rs_map.is_empty(), "{rs_name} empty in Prometheus");
        assert_eq!(
            rs_map, off_map,
            "mismatch between {rs_name} and {off_name}: left={rs_map:?} right={off_map:?}"
        );
        println!(
            "M-04_ALIAS_OK {rs_name} == {off_name} series={}",
            rs_map.len()
        );
    }

    // Verify mapped count against direct /metrics exposition as well.
    let (code, body) =
        http_request("127.0.0.1", s1.metrics_port, "GET", "/metrics", None).expect("get /metrics");
    assert_eq!(code, 200);
    assert!(
        body.contains("daml_mediator_outstanding_requests{synchronizer=\"sync-m04\",node=\"m1\"}")
    );
    assert!(body.contains("daml_sequencer_bftordering_p2p_connections_connected{synchronizer=\"sync-m04\",node=\"s1\"}"));
}
