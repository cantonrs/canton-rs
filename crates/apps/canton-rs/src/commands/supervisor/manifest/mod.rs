//! Declarative stack manifest (`canton-daemon.yaml` Mode A & Mode B), `.env` loader,
//! `${VAR:-default}` substitution, template generator (`daemon init`), and preflight validation (`daemon config`).

mod resolve;
mod templates;
#[cfg(test)]
mod tests;

pub use resolve::check_port_collisions;
pub(crate) use resolve::{
    append_mode_b_extra_services, connect_host_for_bind, format_bind_host_port,
    plan_raw_service_ports,
};
pub use templates::{format_masked_config_summary, render_init_yaml, InitTemplate};

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use yaml_rust2::{Yaml, YamlLoader};

use self::resolve::{append_resolved_services, topo_sort_services, ResolveServicesContext};
use super::log_policy::{
    merge_node_override, parse_logging_yaml, parse_service_logging_yaml, LogPolicy, NodeLogOverride,
};
use super::scenario::{parse_scenarios_yaml, ScenarioSpec};
use super::topology::{
    parse_cells_yaml, parse_limits_yaml, parse_remote_clusters_yaml, parse_synchronizers_yaml,
    validate_cell_isolation, CellSpec, RemoteClusterSpec, ResourceLimits, SynchronizerDomainSpec,
};
use super::{
    DaemonSpec, NodePorts, NodeRole, RestartPolicy, StorageSpec, DEFAULT_METRICS_PORT,
    DEFAULT_SHUTDOWN_TIMEOUT_SECS, DEFAULT_TRACE_RATE_LIMIT,
};

/// Mode B parameters parsed from `canton-daemon.yaml` when `canton_conf` is set.
#[derive(Clone, Debug)]
pub struct ModeBManifestConfig {
    pub name: String,
    pub state_dir: PathBuf,
    pub metrics_port: Option<u16>,
    pub metrics_bind: String,
    pub log_encoder: String,
    pub log_max_bytes: u64,
    pub log_max_files: usize,
    pub logging: LogPolicy,
    pub trace_rate_limit_per_sec: u32,
    pub xray: bool,
    pub no_restart: bool,
    pub max_restarts: Option<u64>,
    pub shadow_verify: bool,
    pub shadow_jvm_url: Option<String>,
    pub canton_conf: PathBuf,
    pub bootstrap: Option<PathBuf>,
    pub port_offset: u16,
    pub same_identity: bool,
    pub official_write: bool,
    pub official_pg_addr: Option<String>,
    pub auth_cert: Option<PathBuf>,
    /// The token the supervisor sends to the configuration's participants (`token_env` / `token_file`).
    pub token: Option<super::TokenSource>,
    pub state_in_files: bool,
    pub strict_config: bool,
    pub dar: Option<PathBuf>,
    pub cells: BTreeMap<String, CellSpec>,
    pub remote_clusters: Vec<RemoteClusterSpec>,
    pub scenarios: Vec<ScenarioSpec>,
    pub extra_services: Vec<RawServiceDecl>,
}

/// Raw parsed YAML entry before topological resolution into [`DaemonServiceSpec`].
#[derive(Clone, Debug)]
pub struct RawServiceDecl {
    pub name: String,
    pub role: NodeRole,
    pub group: Option<String>,
    pub profiles: Vec<String>,
    pub synchronizer: Option<String>,
    pub also_synchronizers: Vec<String>,
    pub sequencer_url: Option<String>,
    pub bft_group: Option<String>,
    pub limits: Option<ResourceLimits>,
    pub ports: NodePorts,
    pub restart: RestartPolicy,
    pub depends_on: Vec<String>,
    pub dars: Vec<PathBuf>,
    pub dar_dir: Option<PathBuf>,
    pub ledger_of: Option<String>,
    pub ledger_url: Option<String>,
    pub automation_interval_ms: Option<u64>,
    pub history: Option<PathBuf>,
    pub storage: StorageSpec,
    pub auth_cert: Option<PathBuf>,
    pub token: Option<super::TokenSource>,
    pub extra_env: BTreeMap<String, String>,
    pub logging: Option<NodeLogOverride>,
    pub xray: Option<bool>,
    pub bind_host: Option<String>,
}

/// Parsed YAML document either purely declarative (`ModeA`) or wrapping `canton.conf` (`ModeB`).
#[derive(Clone, Debug)]
pub enum ParsedYamlManifest {
    ModeA(DaemonSpec),
    ModeB(ModeBManifestConfig),
}

/// Pure read-only YAML parse result used by `daemon doctor` before port shifting or collision rejection.
#[derive(Clone, Debug)]
pub(crate) struct RawDoctorYaml {
    pub(crate) state_dir: PathBuf,
    pub(crate) state_dir_omitted: bool,
    pub(crate) metrics_port: Option<u16>,
    pub(crate) port_offset: u16,
    pub(crate) mode_b: Option<ModeBManifestConfig>,
    pub(crate) cells: BTreeMap<String, CellSpec>,
    pub(crate) extra_services: Vec<RawServiceDecl>,
}

struct ParsedYamlHeader {
    name: String,
    synchronizer: String,
    state_dir: PathBuf,
    state_dir_omitted: bool,
    metrics_port: Option<u16>,
    metrics_bind: String,
    log_encoder: String,
    log_max_bytes: u64,
    log_max_files: usize,
    logging: LogPolicy,
    trace_rate_limit_per_sec: u32,
    xray: bool,
    no_restart: bool,
    max_restarts: Option<u64>,
    shadow_verify: bool,
    shadow_jvm_url: Option<String>,
    shutdown_timeout_secs: u64,
    port_offset: u16,
    cells: BTreeMap<String, CellSpec>,
    synchronizers: BTreeMap<String, SynchronizerDomainSpec>,
    remote_clusters: Vec<RemoteClusterSpec>,
    scenarios: Vec<ScenarioSpec>,
    extra_services: Vec<RawServiceDecl>,
    mode_b: Option<ModeBManifestConfig>,
    bind_host: Option<String>,
}

/// Loads `KEY=VALUE` pairs from `.env` in `dir` (ignoring blanks and `#` comments).
pub fn load_dotenv(dir: &Path) -> BTreeMap<String, String> {
    let path = dir.join(".env");
    let Ok(raw) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    parse_dotenv_str(&raw)
}

/// Parses `.env` content lines cleanly into a deterministic `BTreeMap`.
pub fn parse_dotenv_str(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        let Some((key, val)) = body.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut v = val.trim().to_string();
        if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v = v[1..v.len() - 1].to_string();
        }
        map.insert(key.to_string(), v);
    }
    map
}

/// Expands `${VAR}` and `${VAR:-default}` across a YAML string using process env then `.env`.
pub fn expand_env_vars(raw: &str, dotenv: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err("unclosed '${...}' variable reference in manifest".to_string());
        };
        let expr = &after[..end];
        let (var_name, default_val) = match expr.split_once(":-") {
            Some((k, d)) => (k.trim(), Some(d)),
            None => (expr.trim(), None),
        };
        if let Some(val) = std::env::var(var_name)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| dotenv.get(var_name).cloned().filter(|v| !v.is_empty()))
        {
            out.push_str(&val);
        } else if let Some(def) = default_val {
            out.push_str(def);
        } else {
            return Err(format!(
                "environment variable '{var_name}' referenced in manifest is not set (add to .env or export it)"
            ));
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Pure helper resolving supervisor `metrics_port` identically across `doctor` and `up` (`ModeA`).
pub(crate) fn resolve_mode_a_metrics_port(
    yaml_metrics_port: Option<u16>,
    cli_metrics_port: Option<u16>,
    eff_port_offset: u16,
) -> Option<Option<u16>> {
    match cli_metrics_port {
        Some(0) => Some(None),
        Some(mp) => Some(Some(mp)),
        None => match yaml_metrics_port {
            None => Some(None),
            Some(mp) if eff_port_offset != 0 => {
                super::doctor::shift_port(mp, eff_port_offset).map(Some)
            }
            Some(mp) => Some(Some(mp)),
        },
    }
}

/// Reads and parses a `canton-daemon.yaml` file cleanly without running `resolve` or side effects.
pub(crate) fn parse_yaml_for_doctor(path: &Path) -> Result<RawDoctorYaml, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read manifest {}: {e}", path.display()))?;
    let base_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dotenv = load_dotenv(base_dir);
    let hdr = parse_yaml_document_header(&raw, base_dir, &dotenv)?;
    Ok(RawDoctorYaml {
        state_dir: hdr.state_dir,
        state_dir_omitted: hdr.state_dir_omitted,
        metrics_port: hdr.metrics_port,
        port_offset: hdr.port_offset,
        mode_b: hdr.mode_b,
        cells: hdr.cells,
        extra_services: hdr.extra_services,
    })
}

/// Loads `.env`, substitutes `${VAR:-default}`, and parses `canton-daemon.yaml`.
pub fn load_yaml_manifest(path: &Path) -> Result<ParsedYamlManifest, String> {
    load_yaml_manifest_with_options(path, 0, None)
}

/// Loads `.env` and parses `canton-daemon.yaml`, applying CLI `--port-offset` and `--metrics-port`.
pub fn load_yaml_manifest_with_options(
    path: &Path,
    cli_port_offset: u16,
    cli_metrics_port: Option<u16>,
) -> Result<ParsedYamlManifest, String> {
    load_yaml_manifest_with_options_and_pg(path, cli_port_offset, cli_metrics_port, None, false)
}

/// Loads `.env` and parses `canton-daemon.yaml` with optional CLI `--pg-url` schema override.
pub fn load_yaml_manifest_with_options_and_pg(
    path: &Path,
    cli_port_offset: u16,
    cli_metrics_port: Option<u16>,
    pg_override_url: Option<&str>,
    state_in_files: bool,
) -> Result<ParsedYamlManifest, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read manifest {}: {e}", path.display()))?;
    let base_dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dotenv = load_dotenv(base_dir);
    parse_yaml_manifest_str_with_options_and_pg(
        &raw,
        base_dir,
        &dotenv,
        Some(path.to_path_buf()),
        cli_port_offset,
        cli_metrics_port,
        pg_override_url,
        state_in_files,
    )
}

/// Parses manifest YAML text with explicit `.env` bindings and base directory resolution.
#[cfg(test)]
pub fn parse_yaml_manifest_str(
    raw: &str,
    base_dir: &Path,
    dotenv: &BTreeMap<String, String>,
    manifest_path: Option<PathBuf>,
) -> Result<ParsedYamlManifest, String> {
    parse_yaml_manifest_str_with_options(raw, base_dir, dotenv, manifest_path, 0, None)
}

fn parse_yaml_document_header(
    raw: &str,
    base_dir: &Path,
    dotenv: &BTreeMap<String, String>,
) -> Result<ParsedYamlHeader, String> {
    let expanded = expand_env_vars(raw, dotenv)?;
    let docs = YamlLoader::load_from_str(&expanded)
        .map_err(|e| format!("invalid YAML syntax in manifest: {e}"))?;
    let doc = docs
        .first()
        .ok_or_else(|| "manifest YAML document is empty".to_string())?;
    if !matches!(doc, Yaml::Hash(_)) {
        return Err("manifest root must be a YAML mapping".to_string());
    }

    let name = yaml_str(doc, "name").unwrap_or_else(|| "canton-stack".to_string());
    let synchronizer = yaml_str(doc, "synchronizer").unwrap_or_else(|| "canton-sync".to_string());
    let yaml_state = yaml_str(doc, "state_dir");
    let state_dir_omitted = yaml_state.is_none();
    let state_dir = resolve_rel(
        base_dir,
        &yaml_state.unwrap_or_else(|| "canton-rs-state".to_string()),
    );
    let metrics_port = match yaml_opt_u16(doc, "metrics_port")? {
        Some(0) => None,
        Some(p) => Some(p),
        None => Some(DEFAULT_METRICS_PORT),
    };
    let metrics_bind = yaml_str(doc, "metrics_bind").unwrap_or_else(|| "127.0.0.1".to_string());
    let mut logging = parse_logging_yaml(doc)?;
    let trace_rate_limit_per_sec = yaml_opt_u64(doc, "trace_rate_limit")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(DEFAULT_TRACE_RATE_LIMIT);
    let no_restart = yaml_bool(doc, "no_restart").unwrap_or(false);
    let max_restarts = yaml_opt_u64(doc, "max_restarts");
    let shadow_verify = yaml_bool(doc, "shadow_verify").unwrap_or(false);
    let shadow_jvm_url = yaml_str(doc, "shadow_jvm_url");
    let xray = yaml_bool(doc, "xray").unwrap_or(false);
    let bind_host = yaml_str(doc, "bind").or_else(|| yaml_str(doc, "host"));
    let shutdown_timeout_secs =
        yaml_opt_u64(doc, "shutdown_timeout_secs").unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_SECS);
    let port_offset = yaml_opt_u16(doc, "port_offset")?.unwrap_or(0);
    let cells = parse_cells_yaml(doc)?;
    let synchronizers = parse_synchronizers_yaml(doc)?;
    let remote_clusters = parse_remote_clusters_yaml(doc)?;
    let scenarios = parse_scenarios_yaml(doc)?;

    let extra_services = parse_services_map(doc, base_dir)?;
    for svc_decl in &extra_services {
        if let Some(svc_log) = &svc_decl.logging {
            merge_node_override(&mut logging.nodes, &svc_decl.name, svc_log.clone());
        }
    }
    let log_encoder = logging.encoder.clone();
    let log_max_bytes = logging.max_bytes;
    let log_max_files = logging.max_files;

    let mode_b = if let Some(conf_raw) = yaml_str(doc, "canton_conf") {
        let canton_conf = resolve_rel_existing(base_dir, &conf_raw);
        let bootstrap = yaml_str(doc, "bootstrap").map(|p| resolve_rel_existing(base_dir, &p));
        let same_identity = yaml_bool(doc, "same_identity").unwrap_or(false);
        let official_write = yaml_bool(doc, "official_write").unwrap_or(false);
        let official_pg_addr = yaml_str(doc, "official_pg_addr");
        let auth_cert = yaml_str(doc, "auth_cert").map(|p| resolve_rel_existing(base_dir, &p));
        let token = parse_token_source(doc, base_dir, "the manifest")?;
        let state_in_files = yaml_bool(doc, "state_in_files").unwrap_or(false);
        let strict_config = yaml_bool(doc, "strict_config").unwrap_or(false);
        let dar = yaml_str(doc, "dar").map(|p| resolve_rel_existing(base_dir, &p));
        Some(ModeBManifestConfig {
            name: name.clone(),
            state_dir: state_dir.clone(),
            metrics_port,
            metrics_bind: metrics_bind.clone(),
            log_encoder: log_encoder.clone(),
            log_max_bytes,
            log_max_files,
            logging: logging.clone(),
            trace_rate_limit_per_sec,
            xray,
            no_restart,
            max_restarts,
            shadow_verify,
            shadow_jvm_url: shadow_jvm_url.clone(),
            canton_conf,
            bootstrap,
            port_offset,
            same_identity,
            official_write,
            official_pg_addr,
            auth_cert,
            token,
            state_in_files,
            strict_config,
            dar,
            cells: cells.clone(),
            remote_clusters: remote_clusters.clone(),
            scenarios: scenarios.clone(),
            extra_services: extra_services.clone(),
        })
    } else {
        None
    };

    Ok(ParsedYamlHeader {
        name,
        synchronizer,
        state_dir,
        state_dir_omitted,
        metrics_port,
        metrics_bind,
        log_encoder,
        log_max_bytes,
        log_max_files,
        logging,
        trace_rate_limit_per_sec,
        xray,
        no_restart,
        max_restarts,
        shadow_verify,
        shadow_jvm_url,
        shutdown_timeout_secs,
        port_offset,
        cells,
        synchronizers,
        remote_clusters,
        scenarios,
        extra_services,
        mode_b,
        bind_host,
    })
}

/// Parses manifest YAML text with explicit `.env`, base directory, and CLI port overrides.
#[cfg(test)]
pub fn parse_yaml_manifest_str_with_options(
    raw: &str,
    base_dir: &Path,
    dotenv: &BTreeMap<String, String>,
    manifest_path: Option<PathBuf>,
    cli_port_offset: u16,
    cli_metrics_port: Option<u16>,
) -> Result<ParsedYamlManifest, String> {
    parse_yaml_manifest_str_with_options_and_pg(
        raw,
        base_dir,
        dotenv,
        manifest_path,
        cli_port_offset,
        cli_metrics_port,
        None,
        false,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal YAML parser bridge mirrors public option entry point"
)]
fn parse_yaml_manifest_str_with_options_and_pg(
    raw: &str,
    base_dir: &Path,
    dotenv: &BTreeMap<String, String>,
    manifest_path: Option<PathBuf>,
    cli_port_offset: u16,
    cli_metrics_port: Option<u16>,
    pg_override_url: Option<&str>,
    state_in_files: bool,
) -> Result<ParsedYamlManifest, String> {
    let mut hdr = parse_yaml_document_header(raw, base_dir, dotenv)?;
    if let Some(mode_b) = hdr.mode_b {
        return Ok(ParsedYamlManifest::ModeB(mode_b));
    }

    if hdr.extra_services.is_empty() {
        return Err("Mode A manifest must define at least one entry under 'services:' (or set 'canton_conf:')".to_string());
    }

    if let Some(pg_url) = pg_override_url.filter(|_| !state_in_files) {
        for svc in &mut hdr.extra_services {
            let eligible = matches!(
                svc.role,
                NodeRole::Sequencer | NodeRole::Mediator | NodeRole::Participant | NodeRole::Pqs
            ) && svc.bft_group.is_none();
            if eligible && matches!(svc.storage, StorageSpec::Files) {
                svc.storage = StorageSpec::Postgres {
                    url: pg_url.to_string(),
                    name: None,
                };
            }
        }
    }

    let eff_port_offset = if cli_port_offset != 0 {
        cli_port_offset
    } else {
        hdr.port_offset
    };
    let eff_metrics_port =
        resolve_mode_a_metrics_port(hdr.metrics_port, cli_metrics_port, eff_port_offset)
            .ok_or_else(|| {
                format!(
                    "metrics_port {} + port_offset {eff_port_offset} overflows u16",
                    hdr.metrics_port.unwrap_or(0)
                )
            })?;

    let ordered = topo_sort_services(hdr.extra_services, &BTreeSet::new())?;
    let mut services = Vec::with_capacity(ordered.len());
    let resolve_ctx = ResolveServicesContext {
        root_state_dir: &hdr.state_dir,
        default_synchronizer: &hdr.synchronizer,
        synchronizers: &hdr.synchronizers,
        cells: &hdr.cells,
        log_encoder: &hdr.log_encoder,
        global_no_restart: hdr.no_restart,
        xray: hdr.xray,
        port_offset: eff_port_offset,
        default_bind: hdr.bind_host.as_deref(),
    };
    append_resolved_services(&mut services, ordered, &resolve_ctx)?;
    for s in &mut services {
        hdr.logging.apply_child_env(&s.name, &mut s.env);
    }
    check_port_collisions(&services)?;
    validate_cell_isolation(&hdr.cells, &services)?;

    let mut spec = DaemonSpec {
        name: hdr.name,
        synchronizer: hdr.synchronizer,
        state_dir: hdr.state_dir,
        metrics_port: eff_metrics_port,
        metrics_bind: hdr.metrics_bind,
        log_encoder: hdr.log_encoder,
        log_max_bytes: hdr.log_max_bytes,
        log_max_files: hdr.log_max_files,
        logging: hdr.logging,
        trace_rate_limit_per_sec: hdr.trace_rate_limit_per_sec,
        xray: hdr.xray,
        no_restart: hdr.no_restart,
        max_restarts: hdr.max_restarts,
        shadow_verify: hdr.shadow_verify,
        shadow_jvm_url: hdr.shadow_jvm_url,
        foreground_legacy_banner: false,
        shutdown_timeout_secs: hdr.shutdown_timeout_secs,
        manifest_path,
        canton_conf: None,
        bootstrap: None,
        port_offset: eff_port_offset,
        same_identity: false,
        official_write: false,
        official_pg_addr: None,
        auth_cert: None,
        strict_config: false,
        wait_for_deps_secs: 60,
        cells: hdr.cells,
        remote_clusters: hdr.remote_clusters,
        scenarios: hdr.scenarios,
        services,
        ping_participants: Vec::new(),
        dev_auth: false,
        observability: false,
        bind_addresses: Vec::new(),
    };
    spec.bind_addresses = super::creds::collect_spec_bind_addresses(&spec);
    Ok(ParsedYamlManifest::ModeA(spec))
}

fn parse_services_map(doc: &Yaml, base_dir: &Path) -> Result<Vec<RawServiceDecl>, String> {
    let services_yaml = &doc["services"];
    if services_yaml.is_badvalue() || services_yaml.is_null() {
        return Ok(Vec::new());
    }
    let Some(map) = services_yaml.as_hash() else {
        return Err("'services' must be a mapping of <service_name>: { ... }".to_string());
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let name = k
            .as_str()
            .ok_or_else(|| "service key in 'services' must be a string".to_string())?
            .to_string();
        let role = match yaml_str(v, "role")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "sequencer" => NodeRole::Sequencer,
            "mediator" => NodeRole::Mediator,
            "participant" => NodeRole::Participant,
            "splice" => NodeRole::Splice,
            "scan" => NodeRole::Scan,
            "pqs" => NodeRole::Pqs,
            other => {
                return Err(format!(
                    "service '{name}' has unsupported role '{other}' (expected sequencer|mediator|participant|splice|scan|pqs)"
                ))
            }
        };
        let group = yaml_str(v, "group")
            .or_else(|| yaml_str(v, "cell"))
            .or_else(|| yaml_str(v, "org"));
        let profiles = yaml_string_list(v, "profiles");
        let synchronizer = yaml_str(v, "synchronizer");
        let also_synchronizers = yaml_string_list(v, "also_synchronizers");
        let sequencer_url = yaml_str(v, "sequencer_url");
        let bft_group = yaml_str(v, "bft_group");
        let limits = parse_limits_yaml(v, &name)?;
        let ports = parse_ports(v, &name)?;
        let restart = parse_restart(yaml_str(v, "restart").as_deref())?;
        let depends_on = yaml_string_list(v, "depends_on");
        let dars = yaml_string_list(v, "dars")
            .into_iter()
            .map(|p| resolve_rel_existing(base_dir, &p))
            .collect();
        let dar_dir = yaml_str(v, "dar_dir").map(|p| resolve_rel_existing(base_dir, &p));
        let ledger_of = yaml_str(v, "ledger_of");
        let ledger_url = yaml_str(v, "ledger_url");
        let automation_interval_ms = yaml_opt_u64(v, "automation_interval_ms");
        let history = yaml_str(v, "history").map(|p| resolve_rel_existing(base_dir, &p));
        let auth_cert = yaml_str(v, "auth_cert").map(|p| resolve_rel_existing(base_dir, &p));
        let token = parse_token_source(v, base_dir, &format!("service '{name}'"))?;
        let storage = parse_storage(v, &name)?;
        let extra_env = parse_env_map(&v["env"]);
        let logging = parse_service_logging_yaml(v, &name)?;
        let xray = yaml_bool(v, "xray");
        let bind_host = yaml_str(v, "bind").or_else(|| yaml_str(v, "host"));

        out.push(RawServiceDecl {
            name,
            role,
            group,
            profiles,
            synchronizer,
            also_synchronizers,
            sequencer_url,
            bft_group,
            limits,
            ports,
            restart,
            depends_on,
            dars,
            dar_dir,
            ledger_of,
            ledger_url,
            automation_interval_ms,
            history,
            storage,
            auth_cert,
            token,
            extra_env,
            logging,
            xray,
            bind_host,
        });
    }
    Ok(out)
}

/// `token_env: NAME` or `token_file: path` of a manifest entry.
fn parse_token_source(
    v: &Yaml,
    base_dir: &Path,
    what: &str,
) -> Result<Option<super::TokenSource>, String> {
    match (yaml_str(v, "token_env"), yaml_str(v, "token_file")) {
        (Some(_), Some(_)) => Err(format!(
            "{what}: give either 'token_env' or 'token_file', not both"
        )),
        (Some(var), None) => Ok(Some(super::TokenSource::Env(var))),
        (None, Some(path)) => Ok(Some(super::TokenSource::File(resolve_rel_existing(
            base_dir, &path,
        )))),
        (None, None) => Ok(None),
    }
}

fn parse_ports(v: &Yaml, service: &str) -> Result<NodePorts, String> {
    let mut ports = NodePorts::default();
    let arr = &v["ports"];
    if arr.is_badvalue() || arr.is_null() {
        return Ok(ports);
    }
    let Some(items) = arr.as_vec() else {
        return Err(format!("service '{service}' 'ports' must be a list"));
    };
    for item in items {
        if let Some(num) = item.as_i64() {
            let port = u16::try_from(num)
                .map_err(|_| format!("service '{service}' invalid port {num}"))?;
            ports.public = ports.public.or(Some(port));
            continue;
        }
        let spec = item
            .as_str()
            .ok_or_else(|| format!("service '{service}' port entry must be string or integer"))?;
        let (port_str, label) = spec
            .split_once(':')
            .ok_or_else(|| format!("service '{service}' port '{spec}' must be '<port>:<kind>'"))?;
        let port: u16 = port_str
            .trim()
            .parse()
            .map_err(|_| format!("service '{service}' invalid port '{port_str}'"))?;
        match label.trim().to_ascii_lowercase().as_str() {
            "public" | "public-api" => ports.public = Some(port),
            "json" | "json-api" | "http" | "http-ledger-api" => ports.http_json = Some(port),
            "grpc" | "ledger" | "ledger-api" => ports.grpc_ledger = Some(port),
            "admin" | "admin-api" | "status" => ports.admin = Some(port),
            "metrics" => ports.metrics = Some(port),
            "p2p" => ports.p2p = Some(port),
            other => {
                return Err(format!(
                    "service '{service}' unknown port kind '{other}' in '{spec}'"
                ))
            }
        }
    }
    Ok(ports)
}

fn parse_restart(raw: Option<&str>) -> Result<RestartPolicy, String> {
    match raw.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        None | Some("unless-stopped") => Ok(RestartPolicy::UnlessStopped),
        Some("always") => Ok(RestartPolicy::Always),
        Some("on-failure") => Ok(RestartPolicy::OnFailure),
        Some("no") | Some("never") => Ok(RestartPolicy::No),
        Some(other) => Err(format!("unsupported restart policy '{other}'")),
    }
}

fn parse_storage(v: &Yaml, service: &str) -> Result<StorageSpec, String> {
    let st = &v["storage"];
    if st.is_badvalue() || st.is_null() {
        return Ok(StorageSpec::Files);
    }
    match yaml_str(st, "type")
        .unwrap_or_else(|| "files".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "files" | "file" => Ok(StorageSpec::Files),
        "memory" | "mem" => Ok(StorageSpec::Memory),
        "postgres" | "postgresql" | "pg" => {
            let url = yaml_str(st, "url").ok_or_else(|| {
                format!("service '{service}' uses postgres storage without 'url'")
            })?;
            let name = yaml_str(st, "name");
            Ok(StorageSpec::Postgres { url, name })
        }
        other => Err(format!(
            "service '{service}' unsupported storage.type '{other}'"
        )),
    }
}

fn parse_env_map(yaml: &Yaml) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(hash) = yaml.as_hash() {
        for (k, v) in hash {
            if let Some(ks) = k.as_str() {
                if let Some(vs) = v.as_str() {
                    out.insert(ks.to_string(), vs.to_string());
                } else if let Some(n) = v.as_i64() {
                    out.insert(ks.to_string(), n.to_string());
                } else if let Some(b) = v.as_bool() {
                    out.insert(ks.to_string(), b.to_string());
                }
            }
        }
    }
    out
}

pub(super) fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let host_port = stripped.split('/').next()?;
    let (h, p) = host_port.rsplit_once(':')?;
    let port = p.parse::<u16>().ok()?;
    Some((h.to_string(), port))
}

fn resolve_rel(base_dir: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Resolves an input file/dir relative to `base_dir`, falling back to the process working directory
/// when the manifest itself lives in `/tmp` or another folder outside the workspace root.
fn resolve_rel_existing(base_dir: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let candidate = base_dir.join(p);
    if candidate.exists() {
        return candidate;
    }
    if p.exists() {
        if let Ok(cwd) = std::env::current_dir() {
            return cwd.join(p);
        }
    }
    candidate
}

fn yaml_str(doc: &Yaml, key: &str) -> Option<String> {
    let v = &doc[key];
    v.as_str().map(String::from)
}

fn yaml_bool(doc: &Yaml, key: &str) -> Option<bool> {
    doc[key].as_bool()
}

fn yaml_opt_u64(doc: &Yaml, key: &str) -> Option<u64> {
    doc[key].as_i64().and_then(|n| u64::try_from(n).ok())
}

fn yaml_opt_u16(doc: &Yaml, key: &str) -> Result<Option<u16>, String> {
    let v = &doc[key];
    if v.is_badvalue() || v.is_null() {
        return Ok(None);
    }
    let Some(n) = v.as_i64() else {
        return Err(format!("field '{key}' must be an integer port"));
    };
    u16::try_from(n)
        .map(Some)
        .map_err(|_| format!("field '{key}' port {n} out of u16 range"))
}

fn yaml_string_list(doc: &Yaml, key: &str) -> Vec<String> {
    doc[key]
        .as_vec()
        .map(|items| {
            items
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}
