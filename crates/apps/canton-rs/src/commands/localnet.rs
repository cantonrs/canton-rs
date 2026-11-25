//! The LocalNet commands (`canton-rs localnet`) (Gate G11).
//!
//! - `localnet up` (and `localnet start`, the same): a LocalNet of real processes of this one executable, a synchronizer (sequencer and
//!   mediator), participants with their JSON APIs and the scan app, with the scenario run through their APIs ([`super::localnet_up`]).
//! - `localnet status`: asks each role at the port it is given and says what answered.
//! - `localnet audit`: the libraries a binary links.
//!
//! [CANTON-NOTE: WHY] `localnet start` used to run an in-process **model** of a cluster (structs called in sequence, "Pairwise ACS Commit:
//! MATCHED", "Cross-Domain Reassign: COMPLETED") inside this one process, no socket opened. It now starts the real processes (S-LOCAL-010).

use std::path::Path;

use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct LocalnetArgs {
    #[command(subcommand)]
    pub action: Option<LocalnetAction>,

    /// Path to Daml DAR archive to deploy onto localnet.
    #[arg(long)]
    pub dar: Option<String>,

    /// The port `localnet status` asks for the sequencer.
    #[arg(long, default_value_t = 5018)]
    pub sequencer_port: u16,

    /// The port of a further synchronizer's sequencer `localnet status` asks (repeat for several: `localnet up --synchronizers N` starts N).
    #[arg(long = "also-sequencer-port")]
    pub also_sequencer_ports: Vec<u16>,

    /// The status port of the mediator process `localnet status` asks (`mediator run --port`).
    #[arg(long)]
    pub mediator_port: Option<u16>,

    /// A JSON Ledger API port of a participant `localnet status` asks (repeat for several).
    #[arg(long = "json-api-port")]
    pub json_api_ports: Vec<u16>,

    /// The port of the scan app `localnet status` asks (`scan serve --port`).
    #[arg(long)]
    pub scan_port: Option<u16>,

    /// The port of the Splice apps `localnet status` asks (`splice serve --port`).
    #[arg(long)]
    pub splice_port: Option<u16>,
}

#[derive(Subcommand, Debug)]
pub enum LocalnetAction {
    /// The same as `up` (`--nodes` is `--participants`, `--foreground` is `--keep`).
    Start(super::localnet_up::LocalnetUpArgs),
    /// Start a LocalNet of real processes (a synchronizer and N participants, each its own process with a JSON API) and run the scenario
    /// through their APIs.
    Up(super::localnet_up::LocalnetUpArgs),
    /// Query status of all LocalNet cluster roles and runtime boundary audit.
    Status,
    /// Audit the libraries a binary links (this executable unless `--binary` names another). The rest of the native audit (process spawns,
    /// native code, the roles the one executable serves) is `scripts/audit-native.py`.
    Audit(LocalnetAuditArgs),
}

#[derive(Args, Debug)]
pub struct LocalnetAuditArgs {
    /// The binary to audit.
    #[arg(long)]
    pub binary: Option<std::path::PathBuf>,
}

pub fn execute_localnet(args: LocalnetArgs) -> Result<(), String> {
    match args.action {
        None => {
            println!("Canton Full Rust LocalNet Supervisor: nothing started");
            if let Some(dar) = &args.dar {
                let archive = lf_archive::parse_dar_file(Path::new(dar))
                    .map_err(|e| format!("Failed to load DAR '{dar}': {e}"))?;
                println!("Deployment DAR:   {}", dar);
                println!("Main Package ID:  {}", archive.main_package_id);
            }
            println!("`localnet up` starts a LocalNet of real processes; `localnet status` asks a running one");
            Ok(())
        }
        Some(LocalnetAction::Start(up)) => super::localnet_up::run(&up),
        Some(LocalnetAction::Up(up)) => super::localnet_up::run(&up),
        Some(LocalnetAction::Status) => {
            // every line is what an answer said; a role nothing answers for is OFFLINE, a role this executable does not serve is said so
            let mut online = 0;
            // the first synchronizer's sequencer, then the ones `--also-sequencer-port` names (a LocalNet of `--synchronizers N` has N)
            let sequencer_ports: Vec<u16> = std::iter::once(args.sequencer_port)
                .chain(args.also_sequencer_ports.iter().copied())
                .collect();
            for (index, port) in sequencer_ports.iter().enumerate() {
                let url = format!("http://127.0.0.1:{port}");
                let role = if index == 0 {
                    "Sequencer:".to_string()
                } else {
                    format!("Sequencer {}:", index + 1)
                };
                match canton_participant::sequencer_connect::SequencerConnect::connect(&url)
                    .and_then(|mut c| c.synchronizer_id())
                {
                    Ok(id) => {
                        online += 1;
                        println!(
                            "{role:<12} ONLINE at {url} ({})",
                            id.physical_synchronizer_id
                        );
                    }
                    Err(e) => println!("{role:<12} OFFLINE at {url} ({e})"),
                }
            }
            // the HTTP roles: what a GET at the role's own path answered (`localnet up` prints the ports it chose)
            let mut probe = |role: &str, port: Option<u16>, path: &str| match port {
                None => println!("{role:<12} not asked (give its port)"),
                Some(port) => {
                    match super::json_http::call_json("127.0.0.1", port, "GET", path, None) {
                        Ok((status, body)) if (200..300).contains(&status) => {
                            online += 1;
                            let detail = body
                                .get("member")
                                .or_else(|| body.get("version"))
                                .map(|v| format!(" ({})", v.as_str().unwrap_or_default()))
                                .unwrap_or_default();
                            println!("{role:<12} ONLINE at 127.0.0.1:{port}{detail}");
                        }
                        Ok((status, _)) => {
                            println!("{role:<12} answers {status} at 127.0.0.1:{port} {path}")
                        }
                        Err(e) => println!("{role:<12} OFFLINE at 127.0.0.1:{port} ({e})"),
                    }
                }
            };
            probe("Mediator:", args.mediator_port, "/status");
            if args.json_api_ports.is_empty() {
                probe("JSON API:", None, "");
            }
            for port in &args.json_api_ports {
                probe("JSON API:", Some(*port), "/v2/version");
            }
            probe("Scan:", args.scan_port, "/api/scan/v0/dso-party-id");
            probe("Splice apps:", args.splice_port, "/livez");
            if online == 0 {
                return Err("nothing is online".into());
            }
            Ok(())
        }
        Some(LocalnetAction::Audit(audit)) => {
            let exe_path = match audit.binary {
                Some(path) => path,
                None => std::env::current_exe().map_err(|e| e.to_string())?,
            };
            let report = crate::runtime_audit::audit_binary(&exe_path)?;
            println!("Audit of {}", exe_path.display());
            for lib in &report.libraries {
                println!(
                    "  links {lib}: {}",
                    if report.foreign.contains(lib) {
                        "FOREIGN"
                    } else {
                        "system"
                    }
                );
            }
            println!(
                "  JVM processes on this host: {} (informational)",
                report.jvm_processes
            );
            println!("  Not measured here: child processes it spawns, native code built into it, the roles it serves.");
            println!("  Those are measured by scripts/audit-native.py (`make audit-native`), which also tests that it can fail.");
            if report.foreign.is_empty() {
                println!("Linked libraries: all system libraries");
                Ok(())
            } else {
                Err(format!(
                    "links foreign libraries: {}",
                    report.foreign.join(", ")
                ))
            }
        }
    }
}
