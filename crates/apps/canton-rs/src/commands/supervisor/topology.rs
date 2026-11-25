//! Declarative enterprise topology primitives: logical Cell/Group isolation (`cells:`),
//! multi-synchronizer domain routing (`synchronizers:`), declarative BFT sequencer clusters
//! (`bft_group:`), OS resource guardrails (`limits:`), remote daemon federation (`clusters:`),
//! and turnkey enterprise starter templates (`enterprise-dvp`, `bft-cluster`, `multi-domain`,
//! `org-production`).
//!
//! [CANTON-NOTE: INVARIANT] Every primitive in this module operates strictly at the supervisor
//! process-orchestration layer outside Canton 3.7.2 protocol crates (`lf-eval`, `canton-participant`,
//! `wire`, `sequencer`, `mediator`, `bft-orderer`), preserving 1:1 wire, hash, and DB compatibility.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use canton_participant::state_store::FileStore;
use serde::{Deserialize, Serialize};
use yaml_rust2::Yaml;

use super::probe::http_request;
use super::{ClusterSnapshot, DaemonServiceSpec, DaemonSpec, NodePorts, NodeRole, StorageSpec};

/// Isolation policy applied to a logical `cell` (`cells.<name>.isolation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CellIsolation {
    /// Enforces isolated state subtrees (`<state_dir>/cells/<cell>/<service>`) and rejects
    /// cross-cell sharing of PostgreSQL `(url, state_name)` or JWT `auth_cert` files.
    #[default]
    Strict,
    /// Visual/operational grouping without cross-cell storage/auth rejection.
    Shared,
}

impl CellIsolation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Shared => "shared",
        }
    }
}

/// Logical institution or deployment tier boundary declared under top-level `cells:`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CellSpec {
    pub name: String,
    #[serde(default)]
    pub isolation: CellIsolation,
    #[serde(default)]
    pub base_port: Option<u16>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub synchronizer: Option<String>,
}

/// Optional per-service or per-cell OS resource guardrails monitored by the supervisor sampler.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    /// Maximum resident memory in MiB before the slot is flagged degraded (or restarted if `restart_on_exceed` is set).
    #[serde(default)]
    pub max_rss_mb: Option<u64>,
    /// CPU warning threshold (`100.0` = 1 full core).
    #[serde(default)]
    pub cpu_warn_percent: Option<f64>,
    /// Restart the child process automatically when `max_rss_mb` is exceeded.
    #[serde(default)]
    pub restart_on_exceed: bool,
}

/// Remote `canton-rs daemon` supervisor endpoint federated into `ClusterSnapshot` (`clusters:`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClusterSpec {
    pub name: String,
    /// Base URL of the remote supervisor exporter (e.g. `http://10.0.1.12:9464`).
    pub snapshot_url: String,
}

/// Declarative synchronizer domain metadata declared under top-level `synchronizers:`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizerDomainSpec {
    pub alias: String,
    /// Optional external/remote sequencer URL (used in Single-Org Production stacks when the
    /// synchronizer is hosted by an external consortium or JVM Canton cluster).
    #[serde(default)]
    pub external_sequencer_url: Option<String>,
    /// Optional BFT threshold override when multiple local sequencers form a BFT group.
    #[serde(default)]
    pub bft_threshold: Option<i32>,
}

/// Parses optional top-level `cells:` mapping from `canton-daemon.yaml`.
pub fn parse_cells_yaml(doc: &Yaml) -> Result<BTreeMap<String, CellSpec>, String> {
    let raw = &doc["cells"];
    if raw.is_badvalue() || raw.is_null() {
        return Ok(BTreeMap::new());
    }
    let Some(map) = raw.as_hash() else {
        return Err("'cells' must be a mapping of <cell_name>: { ... }".to_string());
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let name = k
            .as_str()
            .ok_or_else(|| "cell key under 'cells' must be a string".to_string())?
            .trim()
            .to_string();
        if name.is_empty() {
            return Err("cell name under 'cells' cannot be empty".to_string());
        }
        let isolation = match v["isolation"].as_str().map(str::trim) {
            None | Some("strict") => CellIsolation::Strict,
            Some("shared") | Some("soft") => CellIsolation::Shared,
            Some(other) => {
                return Err(format!(
                    "cell '{name}' unsupported isolation '{other}' (expected strict|shared)"
                ))
            }
        };
        let base_port = match v["base_port"].as_i64() {
            Some(n) => Some(
                u16::try_from(n)
                    .map_err(|_| format!("cell '{name}' base_port {n} out of u16 range"))?,
            ),
            None => None,
        };
        let description = v["description"].as_str().map(String::from);
        let synchronizer = v["synchronizer"].as_str().map(String::from);
        out.insert(
            name.clone(),
            CellSpec {
                name,
                isolation,
                base_port,
                description,
                synchronizer,
            },
        );
    }
    Ok(out)
}

/// Parses optional top-level `synchronizers:` mapping from `canton-daemon.yaml`.
pub fn parse_synchronizers_yaml(
    doc: &Yaml,
) -> Result<BTreeMap<String, SynchronizerDomainSpec>, String> {
    let raw = &doc["synchronizers"];
    if raw.is_badvalue() || raw.is_null() {
        return Ok(BTreeMap::new());
    }
    let Some(map) = raw.as_hash() else {
        return Err("'synchronizers' must be a mapping of <alias>: { ... }".to_string());
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let alias = k
            .as_str()
            .ok_or_else(|| "synchronizer alias key must be a string".to_string())?
            .trim()
            .to_string();
        if alias.is_empty() {
            return Err("synchronizer alias cannot be empty".to_string());
        }
        let external_sequencer_url = v["sequencer_url"]
            .as_str()
            .or_else(|| v["external_sequencer_url"].as_str())
            .map(String::from);
        let bft_threshold = v["bft_threshold"]
            .as_i64()
            .and_then(|n| i32::try_from(n).ok());
        out.insert(
            alias.clone(),
            SynchronizerDomainSpec {
                alias,
                external_sequencer_url,
                bft_threshold,
            },
        );
    }
    Ok(out)
}

/// Parses optional top-level `clusters:` list/mapping for multi-host supervisor federation.
pub fn parse_remote_clusters_yaml(doc: &Yaml) -> Result<Vec<RemoteClusterSpec>, String> {
    let raw = &doc["clusters"];
    if raw.is_badvalue() || raw.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    if let Some(map) = raw.as_hash() {
        for (k, v) in map {
            let name = k
                .as_str()
                .ok_or_else(|| "cluster key under 'clusters' must be a string".to_string())?
                .trim()
                .to_string();
            let raw_url = v
                .as_str()
                .or_else(|| v["url"].as_str())
                .or_else(|| v["snapshot_url"].as_str())
                .ok_or_else(|| format!("cluster '{name}' requires 'url'"))?;
            out.push(RemoteClusterSpec {
                name,
                snapshot_url: normalize_snapshot_url(raw_url),
            });
        }
        return Ok(out);
    }
    if let Some(items) = raw.as_vec() {
        for item in items {
            let name = item["name"]
                .as_str()
                .ok_or_else(|| "entry in 'clusters' list requires 'name'".to_string())?
                .to_string();
            let raw_url = item["url"]
                .as_str()
                .or_else(|| item["snapshot_url"].as_str())
                .ok_or_else(|| format!("cluster '{name}' requires 'url'"))?;
            out.push(RemoteClusterSpec {
                name,
                snapshot_url: normalize_snapshot_url(raw_url),
            });
        }
        return Ok(out);
    }
    Err("'clusters' must be a mapping or list".to_string())
}

fn normalize_snapshot_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    if with_scheme.ends_with("/snapshot") {
        with_scheme
    } else {
        format!("{with_scheme}/snapshot")
    }
}

/// Parses optional `limits:` block on a service declaration.
pub fn parse_limits_yaml(v: &Yaml, service: &str) -> Result<Option<ResourceLimits>, String> {
    let lim = &v["limits"];
    if lim.is_badvalue() || lim.is_null() {
        return Ok(None);
    }
    if !matches!(lim, Yaml::Hash(_)) {
        return Err(format!("service '{service}' 'limits' must be a mapping"));
    }
    let max_rss_mb = match lim["max_rss_mb"]
        .as_i64()
        .or_else(|| lim["max_memory_mb"].as_i64())
    {
        Some(n) if n > 0 => Some(u64::try_from(n).unwrap_or(0)),
        Some(n) => {
            return Err(format!(
                "service '{service}' limits.max_rss_mb must be positive (got {n})"
            ))
        }
        None => None,
    };
    let cpu_warn_percent = lim["cpu_warn_percent"]
        .as_f64()
        .or_else(|| lim["cpu_warn_percent"].as_i64().map(|n| n as f64));
    let restart_on_exceed = lim["restart_on_exceed"].as_bool().unwrap_or(false);
    if max_rss_mb.is_none() && cpu_warn_percent.is_none() {
        return Ok(None);
    }
    Ok(Some(ResourceLimits {
        max_rss_mb,
        cpu_warn_percent,
        restart_on_exceed,
    }))
}

/// Assigns deterministic ports for services inside cells that define `base_port` when explicit
/// ports were omitted in `canton-daemon.yaml`.
pub fn assign_cell_base_ports(
    cells: &BTreeMap<String, CellSpec>,
    group_opt: Option<&str>,
    role: NodeRole,
    slot_offset_in_cell: u16,
    ports: &mut NodePorts,
) -> Result<(), String> {
    let Some(cell_name) = group_opt else {
        return Ok(());
    };
    let Some(cell) = cells.get(cell_name) else {
        return Ok(());
    };
    let Some(base) = cell.base_port else {
        return Ok(());
    };
    if !ports.all_ports().is_empty() {
        return Ok(());
    }
    let stride = slot_offset_in_cell
        .checked_mul(10)
        .ok_or_else(|| format!("cell '{cell_name}' port stride overflow"))?;
    let slot_base = base
        .checked_add(stride)
        .ok_or_else(|| format!("cell '{cell_name}' base_port {base} overflow"))?;
    match role {
        NodeRole::Sequencer => {
            ports.public = Some(slot_base);
            ports.metrics = Some(slot_base.saturating_add(1));
        }
        NodeRole::Mediator => {
            ports.admin = Some(slot_base);
        }
        NodeRole::Participant => {
            ports.http_json = Some(slot_base);
            ports.admin = Some(slot_base.saturating_add(1));
        }
        NodeRole::Splice | NodeRole::Scan | NodeRole::Pqs => {
            ports.http_json = Some(slot_base);
        }
    }
    Ok(())
}

/// Enforces `CellIsolation::Strict` boundaries across all resolved service slots.
///
/// [CANTON-NOTE: INVARIANT] Two distinct cells marked `isolation: strict` may never share the
/// exact same PostgreSQL `(url, state_name)` tuple, the same filesystem `state_dir`, or the same
/// JWT certificate path (`auth_mode` with file path), preventing accidental cross-institution
/// ledger/key contamination in multi-cell topologies.
pub fn validate_cell_isolation(
    cells: &BTreeMap<String, CellSpec>,
    services: &[DaemonServiceSpec],
) -> Result<(), String> {
    let mut pg_owners: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut dir_owners: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut cert_owners: BTreeMap<String, String> = BTreeMap::new();

    for svc in services {
        let Some(cell_name) = svc.group.as_deref() else {
            continue;
        };
        let is_strict = cells
            .get(cell_name)
            .is_none_or(|c| c.isolation == CellIsolation::Strict);
        if !is_strict {
            continue;
        }

        if let Some(prev_cell) = dir_owners.get(&svc.state_dir) {
            if prev_cell != cell_name {
                return Err(format!(
                    "strict cell isolation violation: state_dir '{}' shared between cell '{prev_cell}' and cell '{cell_name}'",
                    svc.state_dir.display()
                ));
            }
        } else {
            dir_owners.insert(svc.state_dir.clone(), cell_name.to_string());
        }

        if let StorageSpec::Postgres { url, name } = &svc.storage {
            let eff_name = name.clone().unwrap_or_else(|| "default".to_string());
            let key = (url.clone(), eff_name.clone());
            if let Some(prev_cell) = pg_owners.get(&key) {
                if prev_cell != cell_name {
                    return Err(format!(
                        "strict cell isolation violation: PostgreSQL state '{}' on '{}' is shared between cell '{prev_cell}' and cell '{cell_name}' (set distinct DB/state names or isolation: shared)",
                        eff_name,
                        super::mask_secret_url(url),
                    ));
                }
            } else {
                pg_owners.insert(key, cell_name.to_string());
            }
        }

        if svc.auth_mode.starts_with("jwt-rs-256-crt (") {
            if let Some(prev_cell) = cert_owners.get(&svc.auth_mode) {
                if prev_cell != cell_name {
                    return Err(format!(
                        "strict cell isolation violation: {} shared between cell '{prev_cell}' and cell '{cell_name}'",
                        svc.auth_mode
                    ));
                }
            } else {
                cert_owners.insert(svc.auth_mode.clone(), cell_name.to_string());
            }
        }
    }
    Ok(())
}

struct FilterServiceRow<'a> {
    name: &'a str,
    profiles: &'a [String],
    group: Option<&'a str>,
    depends_on: &'a [String],
}

fn select_filtered_service_names(
    items: &[FilterServiceRow<'_>],
    profiles: &[String],
    groups: &[String],
) -> Result<BTreeSet<String>, String> {
    if profiles.is_empty() && groups.is_empty() {
        return Ok(items.iter().map(|r| r.name.to_string()).collect());
    }
    let prof_set: BTreeSet<&str> = profiles.iter().map(String::as_str).collect();
    let grp_set: BTreeSet<&str> = groups.iter().map(|g| g.trim_start_matches('@')).collect();

    let mut keep_names: BTreeSet<String> = BTreeSet::new();
    for row in items {
        let prof_match =
            prof_set.is_empty() || row.profiles.iter().any(|p| prof_set.contains(p.as_str()));
        let grp_match = grp_set.is_empty() || row.group.is_some_and(|g| grp_set.contains(g));
        if prof_match && grp_match {
            keep_names.insert(row.name.to_string());
        }
    }
    if keep_names.is_empty() {
        return Err(format!(
            "no services matched requested filters (profiles={profiles:?}, groups={groups:?})"
        ));
    }

    // Pull in transitive local `depends_on` prerequisites so selected cells always boot cleanly.
    let mut changed = true;
    while changed {
        changed = false;
        for row in items {
            if keep_names.contains(row.name) {
                for dep in row.depends_on {
                    if keep_names.insert(dep.clone()) {
                        changed = true;
                    }
                }
            }
        }
    }
    Ok(keep_names)
}

/// Filters raw manifest service declarations by `--profile` or `--group` CLI selectors,
/// retaining transitive `depends_on` prerequisites cleanly for preflight `doctor`.
pub(crate) fn filter_raw_services(
    services: &[super::manifest::RawServiceDecl],
    profiles: &[String],
    groups: &[String],
) -> Result<Vec<super::manifest::RawServiceDecl>, String> {
    if profiles.is_empty() && groups.is_empty() {
        return Ok(services.to_vec());
    }
    let rows: Vec<FilterServiceRow<'_>> = services
        .iter()
        .map(|s| FilterServiceRow {
            name: s.name.as_str(),
            profiles: s.profiles.as_slice(),
            group: s.group.as_deref(),
            depends_on: s.depends_on.as_slice(),
        })
        .collect();
    let keep_names = select_filtered_service_names(&rows, profiles, groups)?;
    Ok(services
        .iter()
        .filter(|s| keep_names.contains(&s.name))
        .cloned()
        .collect())
}

/// Filters a resolved `DaemonSpec`'s services by `--profile` or `--group` CLI selectors,
/// automatically retaining transitive `depends_on` prerequisites that exist in the manifest.
pub fn filter_spec_services(
    spec: &mut DaemonSpec,
    profiles: &[String],
    groups: &[String],
) -> Result<(), String> {
    if profiles.is_empty() && groups.is_empty() {
        return Ok(());
    }
    let rows: Vec<FilterServiceRow<'_>> = spec
        .services
        .iter()
        .map(|s| FilterServiceRow {
            name: s.name.as_str(),
            profiles: s.profiles.as_slice(),
            group: s.group.as_deref(),
            depends_on: s.depends_on.as_slice(),
        })
        .collect();
    let keep_names = select_filtered_service_names(&rows, profiles, groups)?;

    spec.services.retain(|s| keep_names.contains(&s.name));
    for (idx, svc) in spec.services.iter_mut().enumerate() {
        svc.slot_id = idx;
    }
    Ok(())
}

/// Materializes cryptographic identities and `bft-<sync>-genesis.tx` files on disk right before
/// `run_supervisor` spawns any declarative Mode A BFT sequencer cluster (`bft_group`).
///
/// [CANTON-NOTE: SEMANTICS] Keeping genesis materialization here (at runtime startup rather than
/// YAML parse time) guarantees `canton-rs daemon config` stays pure and side-effect-free while
/// `canton-rs daemon up` boots genuine Canton 3.7.2 BFT consensus (`sequencer run-bft`) identically
/// to `daemon.rs` Mode B.
pub fn materialize_declarative_bft_genesis(spec: &mut DaemonSpec) -> Result<(), String> {
    // Group BFT sequencers by their synchronizer domain.
    let mut bft_domains: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (idx, svc) in spec.services.iter().enumerate() {
        if svc.role == NodeRole::Sequencer
            && svc.config_path.is_none()
            && svc.argv.get(1).is_some_and(|sub| sub == "run-bft")
        {
            let sync = svc
                .synchronizer_domain
                .clone()
                .unwrap_or_else(|| spec.synchronizer.clone());
            bft_domains.entry(sync).or_default().push(idx);
        }
    }

    for (sync_name, seq_indices) in bft_domains {
        if seq_indices.is_empty() {
            continue;
        }
        let mut seq_identities = Vec::with_capacity(seq_indices.len());
        let mut owners = Vec::with_capacity(seq_indices.len());
        for &s_idx in &seq_indices {
            let svc = &spec.services[s_idx];
            let store = FileStore::new(&svc.state_dir)?;
            let id =
                canton_sequencer_server::sequencer_identity::SequencerIdentity::load_or_create_in(
                    store.as_ref(),
                    &svc.name,
                )?;
            owners.push(svc.name.clone());
            seq_identities.push(id);
        }

        let med_indices: Vec<usize> = spec
            .services
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.role == NodeRole::Mediator
                    && s.config_path.is_none()
                    && s.synchronizer_domain
                        .as_deref()
                        .unwrap_or(&spec.synchronizer)
                        == sync_name
            })
            .map(|(i, _)| i)
            .collect();

        let mut med_identities = Vec::with_capacity(med_indices.len());
        for &m_idx in &med_indices {
            let svc = &spec.services[m_idx];
            let store = FileStore::new(&svc.state_dir)?;
            let id = canton_sequencer_server::mediator_identity::MediatorIdentity::load_or_create(
                store.as_ref(),
                &svc.name,
            )?;
            med_identities.push(id);
        }

        let seq_refs: Vec<_> = seq_identities.iter().collect();
        let med_refs: Vec<_> = med_identities.iter().collect();
        // BFT quorum fault tolerance: 3f + 1 => threshold = N - f (e.g. 4 nodes -> f=1 -> threshold 3; 1..3 nodes -> threshold N).
        let n = seq_indices.len();
        let f = n.saturating_sub(1) / 3;
        let default_threshold = i32::try_from(n.saturating_sub(f).max(1)).unwrap_or(1);

        let (namespace, genesis_txs) =
            canton_sequencer_server::synchronizer_state::build_bft_genesis(
                &sync_name,
                &seq_refs,
                &med_refs,
                &owners,
                default_threshold,
            )?;

        std::fs::create_dir_all(&spec.state_dir).map_err(|e| e.to_string())?;
        let genesis_path = spec.state_dir.join(format!("bft-{sync_name}-genesis.tx"));
        std::fs::write(
            &genesis_path,
            canton_sequencer_server::mediator_identity::onboarding_file(&genesis_txs),
        )
        .map_err(|e| format!("{}: {e}", genesis_path.display()))?;

        // Patch computed `--namespace` and `--genesis-file` placeholders in each BFT sequencer's argv.
        for &s_idx in &seq_indices {
            let argv = &mut spec.services[s_idx].argv;
            set_flag_value(argv, "--namespace", &namespace);
            set_flag_value(argv, "--genesis-file", &genesis_path.display().to_string());
        }
        // Mark companion mediators as genesis-onboarded so dynamic `add-mediator` is skipped.
        let peer_cnt = Some(seq_indices.len());
        for &m_idx in &med_indices {
            spec.services[m_idx].bft_peer_count = peer_cnt;
        }
    }

    Ok(())
}

fn set_flag_value(argv: &mut Vec<String>, flag: &str, value: &str) {
    for idx in 0..argv.len() {
        if argv[idx] == flag {
            if let Some(slot) = argv.get_mut(idx + 1) {
                *slot = value.to_string();
                return;
            }
        }
    }
    argv.push(flag.to_string());
    argv.push(value.to_string());
}

/// Polls remote `canton-rs daemon` supervisor `/snapshot` HTTP endpoints (`clusters:`) with bounded
/// timeout and tags imported `NodeSnapshot`s with `host_label = Some(cluster.name)`.
pub fn poll_remote_clusters(
    clusters: &[RemoteClusterSpec],
    base_slot_id: usize,
) -> Vec<super::NodeSnapshot> {
    let mut imported = Vec::new();
    let mut next_slot = base_slot_id;
    for cluster in clusters {
        if let Ok((200, body)) = http_request(
            &cluster.snapshot_url,
            "GET",
            None,
            None,
            Duration::from_millis(450),
        ) {
            if let Ok(remote_snap) = serde_json::from_str::<ClusterSnapshot>(&body) {
                for mut node in remote_snap.nodes {
                    if node.host_label.is_none() {
                        node.host_label = Some(cluster.name.clone());
                    }
                    if node.group.is_none() {
                        node.group = Some(format!("host:{}", cluster.name));
                    }
                    node.slot_id = next_slot;
                    next_slot += 1;
                    imported.push(node);
                }
            }
        }
    }
    imported
}

/// Renders starter YAML manifests for enterprise multi-cell simulation labs and single-org stacks.
pub fn render_enterprise_template_yaml(kind: EnterpriseTemplateKind) -> String {
    match kind {
        EnterpriseTemplateKind::EnterpriseDvp => String::from(
            r#"# canton-daemon.yaml — Enterprise Multi-Institution Bond DvP & Sub-Transaction Privacy Lab
# [Control Assumption: Multi-Org Local Sandbox — 100% controlled on 1 host to prove Canton 3.7.2 privacy]
name: enterprise-dvp-lab
synchronizer: krw-repo-sync
state_dir: ./canton-rs-state
metrics_port: 9464

cells:
  sync-core:
    isolation: strict
    description: "Consortium Synchronizer (Sequencer + Blinded 2PC Mediator)"
  bank-a:
    isolation: strict
    description: "Buyer Institution — Commercial Bank A (Cash Leg)"
  sec-b:
    isolation: strict
    description: "Seller Institution — Securities Firm B (KTB Bond Leg)"
  bank-c:
    isolation: strict
    description: "Uninvolved Third-Party Bank C (0-Byte Zero-Knowledge Witness)"
  fss-audit:
    isolation: strict
    description: "Financial Supervisory Observer Node"

services:
  seq-core:
    role: sequencer
    group: sync-core
    profiles: [core, all]
    ports: ["5018:public", "5019:metrics"]
    restart: unless-stopped

  med-core:
    role: mediator
    group: sync-core
    profiles: [core, all]
    ports: ["5017:admin"]
    depends_on: [seq-core]
    restart: unless-stopped

  p-bank-a:
    role: participant
    group: bank-a
    profiles: [core, bank-a, all]
    ports: ["7575:json-api", "7576:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    limits:
      max_rss_mb: 1024
    depends_on: [seq-core, med-core]
    restart: unless-stopped

  p-sec-b:
    role: participant
    group: sec-b
    profiles: [core, sec-b, all]
    ports: ["7585:json-api", "7586:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    limits:
      max_rss_mb: 1024
    depends_on: [seq-core, med-core]
    restart: unless-stopped

  p-bank-c:
    role: participant
    group: bank-c
    profiles: [witness, all]
    ports: ["7595:json-api", "7596:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-core, med-core]
    restart: unless-stopped

  p-fss-audit:
    role: participant
    group: fss-audit
    profiles: [audit, all]
    ports: ["7605:json-api", "7606:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-core, med-core]
    restart: unless-stopped

scenarios:
  dvp-privacy-proof:
    description: "Onboard BankA & SecB, commit asset contract, and prove BankC sees 0 active contracts"
    steps:
      - action: health_ping
      - action: allocate_party
        node: p-bank-a
        party_hint: BankA
      - action: allocate_party
        node: p-sec-b
        party_hint: SecB
      - action: allocate_party
        node: p-bank-c
        party_hint: BankC
      - action: submit_create
        node: p-bank-a
        party_hint: BankA
      - action: assert_acs_visibility
        informee_node: p-bank-a
        informee_party_hint: BankA
        witness_node: p-bank-c
        witness_party_hint: BankC
"#,
        ),
        EnterpriseTemplateKind::BftCluster => String::from(
            r#"# canton-daemon.yaml — 4-Node BFT Consensus Cluster & Fault-Injection Chaos Lab (3f+1, Quorum = 3/4)
# [Try stopping @bft-spare or seq-bft-4 in `daemon top` with `s`: 3/4 quorum continues with zero downtime]
name: bft-chaos-lab
synchronizer: bft-sync
state_dir: ./canton-rs-state
metrics_port: 9464

cells:
  bft-quorum-core:
    isolation: strict
    description: "Primary 3 BFT Sequencers + Blinded Mediator"
  bft-spare:
    isolation: strict
    description: "4th BFT Sequencer (Fault-Injection Target: f=1 tolerable)"
  institutions:
    isolation: strict
    description: "Trading Participants Connected to BFT Synchronizer"

services:
  seq-bft-1:
    role: sequencer
    group: bft-quorum-core
    bft_group: core-bft
    ports: ["5118:public", "5119:metrics", "5120:p2p"]
    restart: unless-stopped

  seq-bft-2:
    role: sequencer
    group: bft-quorum-core
    bft_group: core-bft
    ports: ["5128:public", "5129:metrics", "5130:p2p"]
    restart: unless-stopped

  seq-bft-3:
    role: sequencer
    group: bft-quorum-core
    bft_group: core-bft
    ports: ["5138:public", "5139:metrics", "5140:p2p"]
    restart: unless-stopped

  seq-bft-4:
    role: sequencer
    group: bft-spare
    bft_group: core-bft
    ports: ["5148:public", "5149:metrics", "5150:p2p"]
    restart: unless-stopped

  med-bft-1:
    role: mediator
    group: bft-quorum-core
    ports: ["5117:admin"]
    depends_on: [seq-bft-1, seq-bft-2, seq-bft-3, seq-bft-4]
    restart: unless-stopped

  p-institution-1:
    role: participant
    group: institutions
    ports: ["7615:json-api", "7616:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-bft-1, med-bft-1]
    restart: unless-stopped

  p-institution-2:
    role: participant
    group: institutions
    ports: ["7625:json-api", "7626:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-bft-2, med-bft-1]
    restart: unless-stopped

scenarios:
  bft-quorum-burst:
    description: "Verify BFT readiness and execute 5 sequential ledger commits across BFT consensus"
    steps:
      - action: health_ping
      - action: allocate_party
        node: p-institution-1
        party_hint: InstAlpha
      - action: burst_creates
        node: p-institution-1
        party_hint: InstAlpha
        count: 5
"#,
        ),
        EnterpriseTemplateKind::MultiDomain => String::from(
            r#"# canton-daemon.yaml — Multi-Synchronizer Cross-Domain Bridge Topology (krw-sync <-> usd-sync)
name: multi-domain-lab
synchronizer: krw-sync
state_dir: ./canton-rs-state
metrics_port: 9464

synchronizers:
  krw-sync: {}
  usd-sync: {}

cells:
  domain-krw:
    isolation: strict
    description: "Domestic KRW Cash Synchronizer"
  domain-usd:
    isolation: strict
    description: "Global USD Treasury Synchronizer"
  global-dealer:
    isolation: strict
    description: "Bridge Dealer Participant Connected to Both Synchronizers"

services:
  seq-krw:
    role: sequencer
    group: domain-krw
    synchronizer: krw-sync
    ports: ["5218:public", "5219:metrics"]
    restart: unless-stopped

  med-krw:
    role: mediator
    group: domain-krw
    synchronizer: krw-sync
    ports: ["5217:admin"]
    depends_on: [seq-krw]
    restart: unless-stopped

  seq-usd:
    role: sequencer
    group: domain-usd
    synchronizer: usd-sync
    ports: ["5318:public", "5319:metrics"]
    restart: unless-stopped

  med-usd:
    role: mediator
    group: domain-usd
    synchronizer: usd-sync
    ports: ["5317:admin"]
    depends_on: [seq-usd]
    restart: unless-stopped

  p-dealer-bridge:
    role: participant
    group: global-dealer
    synchronizer: krw-sync
    also_synchronizers: [usd-sync]
    ports: ["7715:json-api", "7716:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-krw, med-krw, seq-usd, med-usd]
    restart: unless-stopped

  p-domestic-bank:
    role: participant
    group: domain-krw
    synchronizer: krw-sync
    ports: ["7725:json-api", "7726:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-krw, med-krw]
    restart: unless-stopped

  p-global-fund:
    role: participant
    group: domain-usd
    synchronizer: usd-sync
    ports: ["7735:json-api", "7736:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [seq-usd, med-usd]
    restart: unless-stopped
"#,
        ),
        EnterpriseTemplateKind::OrgProduction => String::from(
            r#"# canton-daemon.yaml — Single-Institution Multi-Tier Production Stack
# [Control Assumption: Real Enterprise Production — You ONLY run & control your own institution's
#  nodes inside your VPC/firewall, connecting over 1:1 Canton 3.7.2 wire protocol to an external
#  consortium or Scala JVM Canton sequencer URL.]
name: bank-a-prod-stack
synchronizer: ${CONSORTIUM_SYNC_ALIAS:-global-sync}
state_dir: ./canton-rs-state
metrics_port: 9464

synchronizers:
  ${CONSORTIUM_SYNC_ALIAS:-global-sync}:
    sequencer_url: ${CONSORTIUM_SEQUENCER_URL:-http://127.0.0.1:5018}

cells:
  core-ledger:
    isolation: strict
    description: "Internal Department Participants (Treasury & Custody)"
  app-and-read-tier:
    isolation: shared
    description: "Splice Validator Automation & Scan Read Cache"

services:
  p-treasury:
    role: participant
    group: core-ledger
    profiles: [core, treasury]
    ports: ["7575:json-api", "7501:grpc", "7502:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    limits:
      max_rss_mb: 2048
      cpu_warn_percent: 250.0
    restart: unless-stopped

  p-custody:
    role: participant
    group: core-ledger
    profiles: [core, custody]
    ports: ["7585:json-api", "7511:grpc", "7512:admin"]
    dars: ["./contracts/target/sample-contract.dar"]
    limits:
      max_rss_mb: 2048
    restart: unless-stopped

  scan-cache:
    role: scan
    group: app-and-read-tier
    profiles: [apps]
    ports: ["5012:http"]
    dars: ["./contracts/target/sample-contract.dar"]
    depends_on: [p-treasury]
    restart: unless-stopped

  splice-validator:
    role: splice
    group: app-and-read-tier
    profiles: [apps]
    ports: ["5020:http"]
    dar_dir: ./tests/oracle/splice-dars
    ledger_of: p-treasury
    automation_interval_ms: 1000
    depends_on: [p-treasury]
    restart: unless-stopped
"#,
        ),
    }
}

/// Enterprise template variants beyond `default` and `localnet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterpriseTemplateKind {
    EnterpriseDvp,
    BftCluster,
    MultiDomain,
    OrgProduction,
}
