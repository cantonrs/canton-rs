//! Pure, side-effect-free execution plan (`π(I)`, storage targets, DARs) shared by `daemon doctor` and `daemon up`.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use canton_participant::hocon::{parse_file, Hocon};

use super::super::super::bft_config::bft_network;
use super::super::super::daemon::bootstrap::parse_bootstrap;
use super::super::cli::{UpArgs, DEFAULT_STATE_DIR};
use super::super::manifest::{
    parse_yaml_for_doctor, plan_raw_service_ports, resolve_mode_a_metrics_port,
    ModeBManifestConfig, RawServiceDecl,
};
use super::super::topology::{filter_raw_services, CellSpec};
use super::super::{StorageSpec, DEFAULT_METRICS_PORT};

/// Shifts a configured port by `offset` without wrapping (`D1` invariant).
///
/// [CANTON-NOTE: INVARIANT] Uses `checked_add` (never `wrapping_add`) so `base + offset > 65535`
/// fails preflight check D1 cleanly instead of wrapping silently into a lower port range.
#[inline]
pub fn shift_port(base: u16, offset: u16) -> Option<u16> {
    base.checked_add(offset)
}

/// One resolved port entry `ℓ -> π(I)(ℓ)` retained even when `base + offset` overflows `u16`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortEntry {
    pub label: String,
    pub owner: String,
    pub base: u16,
    pub offset: u16,
    pub resolved: Option<u16>,
}

/// Complete side-effect-free resource plan inspected by `D1..D10` before `daemon up` spawns nodes.
#[derive(Clone, Debug)]
pub struct DoctorPlan {
    pub state_dir: PathBuf,
    pub state_dir_is_default: bool,
    pub ports: Vec<PortEntry>,
    pub pg_urls: Vec<String>,
    pub dar_files: Vec<PathBuf>,
    pub dar_dirs: Vec<PathBuf>,
    pub metrics_port: Option<u16>,
}

fn is_default_canton_rs_state(path: &Path) -> bool {
    path == Path::new(DEFAULT_STATE_DIR)
        || path.file_name().and_then(|n| n.to_str()) == Some(DEFAULT_STATE_DIR)
}

/// Computes the pure `(π(I), state_dir, PG, DAR)` plan from the exact CLI arguments used by `daemon up`.
///
/// [CANTON-NOTE: INVARIANT] Never creates directories, writes genesis files, or binds sockets (`D-A1`).
pub fn resolve_doctor_plan(args: &UpArgs, cli_pg_url: Option<&str>) -> Result<DoctorPlan, String> {
    let manifest_path = match (&args.file, &args.config) {
        (Some(f), _) => Some(f.clone()),
        (None, Some(_)) => None,
        (None, None) => {
            let default_yaml = PathBuf::from("canton-daemon.yaml");
            if default_yaml.exists() {
                Some(default_yaml)
            } else {
                return Err(
                    "give '-f canton-daemon.yaml' or '-c canton.conf' (or generate one with 'canton-rs daemon init')"
                        .to_string(),
                );
            }
        }
    };

    let mut ports: Vec<PortEntry> = Vec::new();
    let mut pg_set: BTreeSet<String> = BTreeSet::new();
    let mut dar_file_set: BTreeSet<PathBuf> = BTreeSet::new();
    let mut dar_dir_set: BTreeSet<PathBuf> = BTreeSet::new();

    if let Some(url) = cli_pg_url.filter(|s| !s.trim().is_empty()) {
        pg_set.insert(url.to_string());
    }
    if let Some(dar) = &args.dar {
        dar_file_set.insert(dar.clone());
    }

    let (state_dir, state_dir_is_default, eff_metrics_port) = if let Some(yaml_path) = manifest_path
    {
        let raw = parse_yaml_for_doctor(&yaml_path)?;
        if let Some(mode_b) = raw.mode_b {
            let eff_offset = args
                .port_offset
                .filter(|&o| o != 0)
                .unwrap_or(mode_b.port_offset);
            let state_dir = args
                .state_dir
                .clone()
                .unwrap_or_else(|| mode_b.state_dir.clone());
            let is_default = (args.state_dir.is_none() && raw.state_dir_omitted)
                || is_default_canton_rs_state(&state_dir);
            let eff_metrics = normalize_metrics(args.metrics_port.or(mode_b.metrics_port));
            collect_hocon_plan(
                args,
                Some(&mode_b),
                eff_offset,
                eff_metrics,
                &mut ports,
                &mut pg_set,
                &mut dar_file_set,
                &mut dar_dir_set,
            )?;
            (state_dir, is_default, eff_metrics)
        } else {
            let eff_offset = args
                .port_offset
                .filter(|&o| o != 0)
                .unwrap_or(raw.port_offset);
            let state_dir = args.state_dir.clone().unwrap_or(raw.state_dir);
            let is_default = (args.state_dir.is_none() && raw.state_dir_omitted)
                || is_default_canton_rs_state(&state_dir);
            let filtered = filter_raw_services(&raw.extra_services, &args.profile, &args.group)?;
            collect_mode_a_ports(&filtered, &raw.cells, eff_offset, &mut ports)?;
            for svc in &filtered {
                collect_raw_service_assets(
                    svc,
                    args.state_in_files,
                    &mut pg_set,
                    &mut dar_file_set,
                    &mut dar_dir_set,
                );
            }
            let eff_metrics = match resolve_mode_a_metrics_port(
                raw.metrics_port,
                args.metrics_port,
                eff_offset,
            ) {
                Some(Some(mp)) => {
                    let base = if args.metrics_port.is_none() && eff_offset != 0 {
                        raw.metrics_port.unwrap_or(DEFAULT_METRICS_PORT)
                    } else {
                        mp
                    };
                    let applied_offset = if args.metrics_port.is_none() {
                        eff_offset
                    } else {
                        0
                    };
                    ports.push(PortEntry {
                        label: "supervisor.metrics".to_string(),
                        owner: "supervisor".to_string(),
                        base,
                        offset: applied_offset,
                        resolved: Some(mp),
                    });
                    Some(mp)
                }
                Some(None) => None,
                None => {
                    let base = raw.metrics_port.unwrap_or(DEFAULT_METRICS_PORT);
                    ports.push(PortEntry {
                        label: "supervisor.metrics".to_string(),
                        owner: "supervisor".to_string(),
                        base,
                        offset: eff_offset,
                        resolved: None,
                    });
                    None
                }
            };
            (state_dir, is_default, eff_metrics)
        }
    } else {
        let state_dir = args
            .state_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
        let is_default = args.state_dir.is_none() || is_default_canton_rs_state(&state_dir);
        let eff_metrics = normalize_metrics(args.metrics_port);
        collect_hocon_plan(
            args,
            None,
            args.port_offset.unwrap_or(0),
            eff_metrics,
            &mut ports,
            &mut pg_set,
            &mut dar_file_set,
            &mut dar_dir_set,
        )?;
        (state_dir, is_default, eff_metrics)
    };

    ports.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then_with(|| a.owner.cmp(&b.owner))
            .then_with(|| a.base.cmp(&b.base))
    });

    Ok(DoctorPlan {
        state_dir,
        state_dir_is_default,
        ports,
        pg_urls: pg_set.into_iter().collect(),
        dar_files: dar_file_set.into_iter().collect(),
        dar_dirs: dar_dir_set.into_iter().collect(),
        metrics_port: eff_metrics_port,
    })
}

fn normalize_metrics(raw: Option<u16>) -> Option<u16> {
    match raw {
        Some(0) | None => None,
        Some(p) => Some(p),
    }
}

fn collect_mode_a_ports(
    services: &[RawServiceDecl],
    cells: &std::collections::BTreeMap<String, CellSpec>,
    offset: u16,
    out: &mut Vec<PortEntry>,
) -> Result<(), String> {
    let mut cell_slot_counts: std::collections::BTreeMap<String, u16> =
        std::collections::BTreeMap::new();
    for raw in services {
        // Assign group indices even if caller calls `plan_raw_service_ports` on subsets cleanly.
        let idx_in_cell = if let Some(g) = &raw.group {
            let entry = cell_slot_counts.entry(g.clone()).or_insert(0);
            let cur = *entry;
            *entry = entry.saturating_add(1);
            cur
        } else {
            0
        };
        let (_ports, slots) = plan_raw_service_ports(raw, cells, idx_in_cell, offset)?;
        for s in slots {
            out.push(PortEntry {
                label: s.label,
                owner: raw.name.clone(),
                base: s.base,
                offset,
                resolved: s.resolved,
            });
        }
    }
    Ok(())
}

fn collect_raw_service_assets(
    svc: &RawServiceDecl,
    state_in_files: bool,
    pg_set: &mut BTreeSet<String>,
    dar_files: &mut BTreeSet<PathBuf>,
    dar_dirs: &mut BTreeSet<PathBuf>,
) {
    if !state_in_files {
        if let StorageSpec::Postgres { url, .. } = &svc.storage {
            if !url.trim().is_empty() {
                pg_set.insert(url.clone());
            }
        }
    }
    for d in &svc.dars {
        dar_files.insert(d.clone());
    }
    if let Some(dir) = &svc.dar_dir {
        dar_dirs.insert(dir.clone());
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal read-only HOCON collector sharing mutable accumulator sets"
)]
fn collect_hocon_plan(
    args: &UpArgs,
    mode_b: Option<&ModeBManifestConfig>,
    offset: u16,
    eff_metrics: Option<u16>,
    ports: &mut Vec<PortEntry>,
    pg_set: &mut BTreeSet<String>,
    dar_files: &mut BTreeSet<PathBuf>,
    dar_dirs: &mut BTreeSet<PathBuf>,
) -> Result<(), String> {
    let config_path = args
        .config
        .as_ref()
        .or_else(|| mode_b.map(|m| &m.canton_conf))
        .ok_or_else(|| {
            "give '-f canton-daemon.yaml' or '-c canton.conf' (or generate one with 'canton-rs daemon init')"
                .to_string()
        })?;

    if let Some(d) = args
        .dar
        .as_ref()
        .or_else(|| mode_b.and_then(|m| m.dar.as_ref()))
    {
        dar_files.insert(d.clone());
    }

    let conf = parse_file(config_path, &|n| std::env::var(n).ok())
        .map_err(|e| format!("Cannot read {}: {e}", config_path.display()))?;

    let names = |kind: &str| -> Vec<String> {
        conf.get(&format!("canton.{kind}"))
            .map(|h| h.keys().into_iter().map(String::from).collect())
            .unwrap_or_default()
    };
    let sequencers = names("sequencers");
    let mediators = names("mediators");
    let participants = names("participants");
    let all_nodes: Vec<&str> = sequencers
        .iter()
        .chain(&mediators)
        .chain(&participants)
        .map(String::as_str)
        .collect();

    let bootstrap_path = args
        .bootstrap
        .as_ref()
        .or_else(|| mode_b.and_then(|m| m.bootstrap.as_ref()));
    let connected_participants: Option<HashSet<String>> = match bootstrap_path {
        Some(path) => {
            let script = std::fs::read_to_string(path)
                .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
            let parsed = parse_bootstrap(&script, &all_nodes)?;
            Some(parsed.connections.into_iter().map(|(n, _, _)| n).collect())
        }
        None => None,
    };

    let push_hocon_port =
        |kind: &str, node: &str, tail: &str, label_kind: &str, out: &mut Vec<PortEntry>| {
            if let Some(base) = conf
                .get(&format!("canton.{kind}.{node}.{tail}"))
                .and_then(Hocon::as_u16)
            {
                out.push(PortEntry {
                    label: format!("{node}.{label_kind}"),
                    owner: node.to_string(),
                    base,
                    offset,
                    resolved: shift_port(base, offset),
                });
            }
        };

    for seq in &sequencers {
        push_hocon_port("sequencers", seq, "public-api.port", "public", ports);
        let adm = conf
            .get(&format!("canton.sequencers.{seq}.admin-api.port"))
            .and_then(Hocon::as_u16);
        let met = conf
            .get(&format!("canton.sequencers.{seq}.metrics.port"))
            .and_then(Hocon::as_u16);
        if let Some(a) = adm {
            ports.push(PortEntry {
                label: format!("{seq}.admin"),
                owner: seq.clone(),
                base: a,
                offset,
                resolved: shift_port(a, offset),
            });
        }
        if let Some(m) = met {
            if Some(m) != adm {
                ports.push(PortEntry {
                    label: format!("{seq}.metrics"),
                    owner: seq.clone(),
                    base: m,
                    offset,
                    resolved: shift_port(m, offset),
                });
            }
        }
        if sequencers.len() > 1
            || conf
                .get(&format!("canton.sequencers.{seq}.sequencer.config"))
                .is_some()
        {
            if let Ok(net) = bft_network(&conf, seq) {
                if let Some((_, p_str)) = net.bind.rsplit_once(':') {
                    if let Ok(p2p_base) = p_str.parse::<u16>() {
                        ports.push(PortEntry {
                            label: format!("{seq}.p2p"),
                            owner: seq.clone(),
                            base: p2p_base,
                            offset,
                            resolved: shift_port(p2p_base, offset),
                        });
                    }
                }
            }
        }
    }

    for med in &mediators {
        if let Some(base) = conf
            .get(&format!("canton.mediators.{med}.admin-api.port"))
            .and_then(Hocon::as_u16)
        {
            if base != 0 {
                ports.push(PortEntry {
                    label: format!("{med}.admin"),
                    owner: med.clone(),
                    base,
                    offset,
                    resolved: shift_port(base, offset),
                });
            }
        }
    }

    for part in &participants {
        if let Some(ref connected) = connected_participants {
            if !connected.contains(part) {
                continue;
            }
        }
        push_hocon_port("participants", part, "http-ledger-api.port", "json", ports);
        push_hocon_port("participants", part, "ledger-api.port", "grpc", ports);
        push_hocon_port("participants", part, "admin-api.port", "admin", ports);
    }

    if let Some(mb) = mode_b {
        if !mb.extra_services.is_empty() {
            let extra = if args.profile.is_empty() && args.group.is_empty() {
                mb.extra_services.clone()
            } else {
                filter_raw_services(&mb.extra_services, &args.profile, &args.group)?
            };
            collect_mode_a_ports(&extra, &mb.cells, 0, ports)?;
            let state_in_files = args.state_in_files || mb.state_in_files;
            for svc in &extra {
                collect_raw_service_assets(svc, state_in_files, pg_set, dar_files, dar_dirs);
            }
        }
    }

    if let Some(mp) = eff_metrics {
        ports.push(PortEntry {
            label: "supervisor.metrics".to_string(),
            owner: "supervisor".to_string(),
            base: mp,
            offset: 0,
            resolved: Some(mp),
        });
    }

    Ok(())
}
