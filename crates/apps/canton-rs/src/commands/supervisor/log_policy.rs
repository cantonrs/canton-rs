//! Declarative supervisor logging policy (`logging:` in `canton-daemon.yaml`), per-node overrides,
//! byte-size parser, and line-level spam/dedupe/rate-limit gate (`NodeLineGate`).
//!
//! [CANTON-NOTE: INVARIANT] `NodeLineGate` runs strictly AFTER startup `ready_line_prefix` detection
//! in `engine::spawn_pipe_reader`, so setting `level: error` or `level: off` never blocks node boot
//! handshakes (`READY sequencer=...`, `READY mediator=...`, `SCAN listening`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use yaml_rust2::Yaml;

use super::log_rotate::{detect_log_level, LogLevel};
use super::{now_unix_ms, DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES};

/// Default per-node in-memory ring buffer line capacity for `daemon logs` and `daemon top`.
pub const DEFAULT_RING_BUFFER_LINES: usize = 1000;

/// Minimum log level threshold configured in `logging.level` or per-node overrides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFilterLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl LogFilterLevel {
    /// Parses a YAML/CLI level string (`debug|info|warn|error|off`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "debug" | "trace" | "all" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" | "err" => Ok(Self::Error),
            "off" | "none" | "silent" => Ok(Self::Off),
            other => Err(format!(
                "unsupported logging level '{other}' (expected debug|info|warn|error|off)"
            )),
        }
    }

    /// Canonical lowercase representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Off => "off",
        }
    }

    /// Returns whether a detected [`LogLevel`] passes this filter threshold.
    pub const fn allows(self, event_level: LogLevel) -> bool {
        match self {
            Self::Debug => true,
            Self::Info => matches!(
                event_level,
                LogLevel::Info | LogLevel::Warn | LogLevel::Error
            ),
            Self::Warn => matches!(event_level, LogLevel::Warn | LogLevel::Error),
            Self::Error => matches!(event_level, LogLevel::Error),
            Self::Off => false,
        }
    }
}

/// Crate-internal diagnostic verbosity mode mapped onto child `CANTON_RS_LOG`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticsMode {
    /// Emits state/submission/topology diagnostics while suppressing 15ms idle `Subscribe`/`GetTime` polls at source.
    #[default]
    Normal,
    /// Emits every low-level diagnostic line including raw HTTP/2 `PATH` and idle `Subscribe`/`GetTime` polls.
    All,
    /// Disables all crate-internal `diag_eprintln!` / `diag_println!` output.
    Off,
}

impl DiagnosticsMode {
    /// Parses `normal | all | off` (plus common aliases `quiet-polls`, `debug`, `false`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "normal" | "quiet" | "quiet-polls" | "no-polls" | "info" => Ok(Self::Normal),
            "all" | "full" | "debug" | "trace" | "verbose" | "true" => Ok(Self::All),
            "off" | "none" | "false" | "0" => Ok(Self::Off),
            other => Err(format!(
                "unsupported logging.diagnostics '{other}' (expected normal|all|off)"
            )),
        }
    }

    /// Canonical lowercase representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::All => "all",
            Self::Off => "off",
        }
    }

    /// Environment variable value passed as `CANTON_RS_LOG` to supervised child processes.
    pub const fn canton_rs_log_env(self, suppress_idle_polls: bool) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Normal => "normal",
            Self::All => {
                if suppress_idle_polls {
                    "normal"
                } else {
                    "all"
                }
            }
        }
    }
}

/// Per-node logging overrides declared under `logging.nodes.<name>` or `services.<name>.logging`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLogOverride {
    pub level: Option<LogFilterLevel>,
    pub diagnostics: Option<DiagnosticsMode>,
    pub suppress_idle_polls: Option<bool>,
    pub suppress_health_probes: Option<bool>,
    pub dedupe_window_ms: Option<u64>,
    pub rate_limit_per_sec: Option<u32>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

/// Cluster-wide supervisor logging policy (`logging:` block in `canton-daemon.yaml`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPolicy {
    pub level: LogFilterLevel,
    pub encoder: String,
    pub diagnostics: DiagnosticsMode,
    pub suppress_idle_polls: bool,
    pub suppress_health_probes: bool,
    pub dedupe_window_ms: u64,
    pub rate_limit_per_sec: u32,
    pub max_bytes: u64,
    pub max_files: usize,
    pub ring_buffer_lines: usize,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeLogOverride>,
}

impl Default for LogPolicy {
    /// Legacy CLI (`canton-rs daemon -c canton.conf`) default: unfiltered `All`/`Debug` so existing
    /// oracle harnesses see identical raw lines unless YAML `logging:` or CLI flags opt in.
    fn default() -> Self {
        Self {
            level: LogFilterLevel::Debug,
            encoder: "text".to_string(),
            diagnostics: DiagnosticsMode::All,
            suppress_idle_polls: false,
            suppress_health_probes: false,
            dedupe_window_ms: 0,
            rate_limit_per_sec: 0,
            max_bytes: DEFAULT_LOG_MAX_BYTES,
            max_files: DEFAULT_LOG_MAX_FILES,
            ring_buffer_lines: DEFAULT_RING_BUFFER_LINES,
            exclude_patterns: Vec::new(),
            nodes: BTreeMap::new(),
        }
    }
}

impl LogPolicy {
    /// Sensible production/TUI defaults for declarative `canton-daemon.yaml` stacks:
    /// `level: info`, `diagnostics: normal`, and idle poll / health probe spam suppressed.
    pub fn yaml_default() -> Self {
        Self {
            level: LogFilterLevel::Info,
            encoder: "text".to_string(),
            diagnostics: DiagnosticsMode::Normal,
            suppress_idle_polls: true,
            suppress_health_probes: true,
            dedupe_window_ms: 0,
            rate_limit_per_sec: 0,
            max_bytes: DEFAULT_LOG_MAX_BYTES,
            max_files: DEFAULT_LOG_MAX_FILES,
            ring_buffer_lines: DEFAULT_RING_BUFFER_LINES,
            exclude_patterns: Vec::new(),
            nodes: BTreeMap::new(),
        }
    }

    /// Resolves the effective logging policy for `node_name`.
    pub fn resolve_for_node(&self, node_name: &str) -> ResolvedNodeLogPolicy {
        let ov = self.nodes.get(node_name);
        let mut patterns = self.exclude_patterns.clone();
        if let Some(o) = ov {
            for p in &o.exclude_patterns {
                if !patterns.contains(p) {
                    patterns.push(p.clone());
                }
            }
        }
        ResolvedNodeLogPolicy {
            level: ov.and_then(|o| o.level).unwrap_or(self.level),
            diagnostics: ov.and_then(|o| o.diagnostics).unwrap_or(self.diagnostics),
            suppress_idle_polls: ov
                .and_then(|o| o.suppress_idle_polls)
                .unwrap_or(self.suppress_idle_polls),
            suppress_health_probes: ov
                .and_then(|o| o.suppress_health_probes)
                .unwrap_or(self.suppress_health_probes),
            dedupe_window_ms: ov
                .and_then(|o| o.dedupe_window_ms)
                .unwrap_or(self.dedupe_window_ms),
            rate_limit_per_sec: ov
                .and_then(|o| o.rate_limit_per_sec)
                .unwrap_or(self.rate_limit_per_sec),
            exclude_patterns: patterns,
        }
    }

    /// Injects `CANTON_RS_LOG` into `env` for `node_name` unless already explicitly set in `service.env`.
    pub fn apply_child_env(&self, node_name: &str, env: &mut BTreeMap<String, String>) {
        if env.contains_key("CANTON_RS_LOG") {
            return;
        }
        let resolved = self.resolve_for_node(node_name);
        // Only inject `CANTON_RS_LOG` when diagnostics is not unrestricted `All`, preserving unset default otherwise.
        let val = resolved
            .diagnostics
            .canton_rs_log_env(resolved.suppress_idle_polls);
        if val != "all" {
            env.insert("CANTON_RS_LOG".to_string(), val.to_string());
        }
    }

    /// Concise human-readable summary for `canton-rs daemon config`.
    pub fn summary(&self) -> String {
        format!(
            "level={}, encoder={}, diagnostics={}, suppress_idle_polls={}, suppress_health_probes={}, dedupe_ms={}, rate_limit={}/s, max_bytes={}, max_files={}, ring_lines={}",
            self.level.as_str(),
            self.encoder,
            self.diagnostics.as_str(),
            self.suppress_idle_polls,
            self.suppress_health_probes,
            self.dedupe_window_ms,
            self.rate_limit_per_sec,
            self.max_bytes,
            self.max_files,
            self.ring_buffer_lines,
        )
    }
}

/// Effective per-node filter parameters resolved from [`LogPolicy`] + [`NodeLogOverride`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNodeLogPolicy {
    pub level: LogFilterLevel,
    pub diagnostics: DiagnosticsMode,
    pub suppress_idle_polls: bool,
    pub suppress_health_probes: bool,
    pub dedupe_window_ms: u64,
    pub rate_limit_per_sec: u32,
    pub exclude_patterns: Vec<String>,
}

/// Stateful per-pipe line filter handling idle-poll/probe suppression, level gating,
/// consecutive duplicate collapsing, and per-second burst rate limiting.
pub struct NodeLineGate {
    policy: ResolvedNodeLogPolicy,
    last_line: Option<String>,
    last_line_ms: u64,
    repeat_count: u64,
    window_sec: u64,
    emitted_in_sec: u32,
    dropped_in_sec: u64,
}

impl NodeLineGate {
    /// Creates a new line gate for a single stdout or stderr reader thread.
    pub fn new(policy: ResolvedNodeLogPolicy) -> Self {
        Self {
            policy,
            last_line: None,
            last_line_ms: 0,
            repeat_count: 0,
            window_sec: 0,
            emitted_in_sec: 0,
            dropped_in_sec: 0,
        }
    }

    /// Evaluates one raw line at `now_ms`, returning 0..=3 lines to emit to file + `LogHub`.
    pub fn accept(&mut self, line: &str, now_ms: u64) -> Vec<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        if self.policy.level == LogFilterLevel::Off {
            return Vec::new();
        }
        if self.policy.suppress_idle_polls && is_idle_poll_line(trimmed) {
            return Vec::new();
        }
        if self.policy.suppress_health_probes && is_health_probe_line(trimmed) {
            return Vec::new();
        }
        if self
            .policy
            .exclude_patterns
            .iter()
            .any(|pat| !pat.is_empty() && line.contains(pat.as_str()))
        {
            return Vec::new();
        }

        let detected = classify_line_level(trimmed);
        if !self.policy.level.allows(detected) {
            return Vec::new();
        }

        let mut out = Vec::new();

        // Consecutive duplicate suppression within `dedupe_window_ms`.
        if self.policy.dedupe_window_ms > 0 {
            if self.last_line.as_deref() == Some(line)
                && now_ms.saturating_sub(self.last_line_ms) <= self.policy.dedupe_window_ms
            {
                self.repeat_count = self.repeat_count.saturating_add(1);
                return out;
            }
            if self.repeat_count > 0 {
                out.push(format!(
                    "INFO [log-policy] previous message repeated {} more time(s)",
                    self.repeat_count
                ));
                self.repeat_count = 0;
            }
            self.last_line = Some(line.to_string());
            self.last_line_ms = now_ms;
        }

        // Per-second burst rate limiting (`0` = unlimited).
        if self.policy.rate_limit_per_sec > 0 {
            let sec = now_ms / 1000;
            if sec != self.window_sec {
                if self.dropped_in_sec > 0 {
                    out.push(format!(
                        "WARN [log-policy] suppressed {} log line(s) exceeding rate_limit_per_sec={}",
                        self.dropped_in_sec, self.policy.rate_limit_per_sec
                    ));
                    self.dropped_in_sec = 0;
                }
                self.window_sec = sec;
                self.emitted_in_sec = 0;
            }
            if self.emitted_in_sec >= self.policy.rate_limit_per_sec {
                self.dropped_in_sec = self.dropped_in_sec.saturating_add(1);
                return out;
            }
            self.emitted_in_sec = self.emitted_in_sec.saturating_add(1);
        }

        out.push(line.to_string());
        out
    }

    /// Evaluates one raw line using the current wall-clock timestamp.
    pub fn accept_now(&mut self, line: &str) -> Vec<String> {
        self.accept(line, now_unix_ms())
    }
}

fn classify_line_level(trimmed: &str) -> LogLevel {
    if is_idle_poll_line(trimmed) {
        return LogLevel::Debug;
    }
    detect_log_level(trimmed)
}

/// Identifies high-frequency sequencer idle-polling trace lines (`Subscribe` and `GetTime`).
pub fn is_idle_poll_line(trimmed: &str) -> bool {
    trimmed.starts_with("RPC Subscribe ")
        || trimmed.starts_with("RPC GetTime ")
        || (trimmed.starts_with("PATH /")
            && (trimmed.contains("SequencerService/Subscribe ")
                || trimmed.ends_with("SequencerService/Subscribe")
                || trimmed.contains("SequencerService/GetTime ")
                || trimmed.ends_with("SequencerService/GetTime")))
}

/// Identifies supervisor/monitoring HTTP readiness, liveness, metrics, and telemetry probe lines.
pub fn is_health_probe_line(trimmed: &str) -> bool {
    if !(trimmed.contains("Request GET ") || trimmed.starts_with("PATH /")) {
        return false;
    }
    [
        "/livez",
        "/readyz",
        "/metrics",
        "/status",
        "/_telemetry",
        "/_xray",
    ]
    .iter()
    .any(|p| trimmed.contains(p))
}

/// Parses human-readable byte sizes (`"50MB"`, `"20MiB"`, `"512KB"`, `"1GB"`) or raw integers.
pub fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("byte size cannot be empty".to_string());
    }
    if let Ok(bytes) = s.parse::<u64>() {
        return Ok(bytes);
    }
    let split_idx = s
        .find(|c: char| !c.is_ascii_digit() && c != '_')
        .unwrap_or(s.len());
    let num_part = s[..split_idx].replace('_', "");
    let unit_part = s[split_idx..].trim().to_ascii_lowercase();
    let num: u64 = num_part
        .parse()
        .map_err(|_| format!("invalid byte size '{raw}'"))?;
    let mult: u64 = match unit_part.as_str() {
        "b" | "" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1_024,
        "m" | "mb" => 1_000_000,
        "mib" => 1_024 * 1_024,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1_024 * 1_024 * 1_024,
        _ => {
            return Err(format!(
            "unsupported byte size unit '{unit_part}' in '{raw}' (expected B|KB|KiB|MB|MiB|GB|GiB)"
        ))
        }
    };
    num.checked_mul(mult)
        .ok_or_else(|| format!("byte size '{raw}' overflows u64"))
}

/// Parses root `logging:` YAML block merged on top of legacy root `log_encoder` / `log_max_bytes` / `log_max_files`.
pub fn parse_logging_yaml(doc: &Yaml) -> Result<LogPolicy, String> {
    let mut policy = LogPolicy::yaml_default();

    // Legacy top-level flat keys remain supported as base defaults before `logging:` overrides.
    if let Some(enc) = doc["log_encoder"].as_str() {
        validate_encoder(enc)?;
        policy.encoder = enc.trim().to_ascii_lowercase();
    }
    if let Some(bytes) = parse_yaml_bytes(&doc["log_max_bytes"], "log_max_bytes")? {
        policy.max_bytes = bytes;
    }
    if let Some(files) = parse_yaml_usize(&doc["log_max_files"], "log_max_files")? {
        policy.max_files = files.max(1);
    }

    let blk = &doc["logging"];
    if blk.is_badvalue() || blk.is_null() {
        return Ok(policy);
    }
    if !matches!(blk, Yaml::Hash(_)) {
        return Err("'logging' must be a YAML mapping".to_string());
    }

    if let Some(lvl) = blk["level"].as_str() {
        policy.level = LogFilterLevel::parse(lvl)?;
    }
    if let Some(enc) = blk["encoder"].as_str() {
        validate_encoder(enc)?;
        policy.encoder = enc.trim().to_ascii_lowercase();
    }
    if let Some(diag) = blk["diagnostics"].as_str() {
        policy.diagnostics = DiagnosticsMode::parse(diag)?;
    } else if let Some(b) = blk["diagnostics"].as_bool() {
        policy.diagnostics = if b {
            DiagnosticsMode::Normal
        } else {
            DiagnosticsMode::Off
        };
    }
    if let Some(v) = blk["suppress_idle_polls"].as_bool() {
        policy.suppress_idle_polls = v;
    }
    if let Some(v) = blk["suppress_health_probes"].as_bool() {
        policy.suppress_health_probes = v;
    }
    if let Some(ms) = parse_yaml_u64(&blk["dedupe_window_ms"], "logging.dedupe_window_ms")? {
        policy.dedupe_window_ms = ms;
    }
    if let Some(rl) = parse_yaml_u64(&blk["rate_limit_per_sec"], "logging.rate_limit_per_sec")? {
        policy.rate_limit_per_sec = u32::try_from(rl)
            .map_err(|_| format!("logging.rate_limit_per_sec {rl} exceeds u32::MAX"))?;
    }
    if let Some(bytes) = parse_yaml_bytes(&blk["max_bytes"], "logging.max_bytes")? {
        policy.max_bytes = bytes;
    }
    if let Some(files) = parse_yaml_usize(&blk["max_files"], "logging.max_files")? {
        policy.max_files = files.max(1);
    }
    if let Some(ring) = parse_yaml_usize(&blk["ring_buffer_lines"], "logging.ring_buffer_lines")? {
        policy.ring_buffer_lines = ring.max(50);
    }
    policy.exclude_patterns = parse_string_vec(&blk["exclude_patterns"]);

    let nodes_blk = &blk["nodes"];
    if !nodes_blk.is_badvalue() && !nodes_blk.is_null() {
        let Some(map) = nodes_blk.as_hash() else {
            return Err("'logging.nodes' must be a mapping of <service_name>: { ... }".to_string());
        };
        for (k, v) in map {
            let name = k.as_str().ok_or_else(|| {
                "key in 'logging.nodes' must be a service name string".to_string()
            })?;
            let ov = parse_node_override_yaml(v, &format!("logging.nodes.{name}"))?;
            policy.nodes.insert(name.to_string(), ov);
        }
    }

    Ok(policy)
}

/// Parses an optional per-service `logging:` mapping under `services.<name>.logging`.
pub fn parse_service_logging_yaml(
    service_yaml: &Yaml,
    service_name: &str,
) -> Result<Option<NodeLogOverride>, String> {
    let blk = &service_yaml["logging"];
    if blk.is_badvalue() || blk.is_null() {
        return Ok(None);
    }
    let ov = parse_node_override_yaml(blk, &format!("services.{service_name}.logging"))?;
    Ok(Some(ov))
}

/// Merges a `services.<name>.logging` override on top of any `logging.nodes.<name>` entry.
pub fn merge_node_override(
    target: &mut BTreeMap<String, NodeLogOverride>,
    name: &str,
    svc_ov: NodeLogOverride,
) {
    let entry = target.entry(name.to_string()).or_default();
    if svc_ov.level.is_some() {
        entry.level = svc_ov.level;
    }
    if svc_ov.diagnostics.is_some() {
        entry.diagnostics = svc_ov.diagnostics;
    }
    if svc_ov.suppress_idle_polls.is_some() {
        entry.suppress_idle_polls = svc_ov.suppress_idle_polls;
    }
    if svc_ov.suppress_health_probes.is_some() {
        entry.suppress_health_probes = svc_ov.suppress_health_probes;
    }
    if svc_ov.dedupe_window_ms.is_some() {
        entry.dedupe_window_ms = svc_ov.dedupe_window_ms;
    }
    if svc_ov.rate_limit_per_sec.is_some() {
        entry.rate_limit_per_sec = svc_ov.rate_limit_per_sec;
    }
    for pat in svc_ov.exclude_patterns {
        if !entry.exclude_patterns.contains(&pat) {
            entry.exclude_patterns.push(pat);
        }
    }
}

fn parse_node_override_yaml(blk: &Yaml, ctx: &str) -> Result<NodeLogOverride, String> {
    if !matches!(blk, Yaml::Hash(_)) {
        return Err(format!("'{ctx}' must be a YAML mapping"));
    }
    let level = match blk["level"].as_str() {
        Some(s) => Some(LogFilterLevel::parse(s)?),
        None => None,
    };
    let diagnostics = if let Some(s) = blk["diagnostics"].as_str() {
        Some(DiagnosticsMode::parse(s)?)
    } else {
        blk["diagnostics"].as_bool().map(|b| {
            if b {
                DiagnosticsMode::Normal
            } else {
                DiagnosticsMode::Off
            }
        })
    };
    let suppress_idle_polls = blk["suppress_idle_polls"].as_bool();
    let suppress_health_probes = blk["suppress_health_probes"].as_bool();
    let dedupe_window_ms =
        parse_yaml_u64(&blk["dedupe_window_ms"], &format!("{ctx}.dedupe_window_ms"))?;
    let rate_limit_per_sec = match parse_yaml_u64(
        &blk["rate_limit_per_sec"],
        &format!("{ctx}.rate_limit_per_sec"),
    )? {
        Some(v) => Some(
            u32::try_from(v)
                .map_err(|_| format!("{ctx}.rate_limit_per_sec {v} exceeds u32::MAX"))?,
        ),
        None => None,
    };
    let exclude_patterns = parse_string_vec(&blk["exclude_patterns"]);
    Ok(NodeLogOverride {
        level,
        diagnostics,
        suppress_idle_polls,
        suppress_health_probes,
        dedupe_window_ms,
        rate_limit_per_sec,
        exclude_patterns,
    })
}

fn validate_encoder(raw: &str) -> Result<(), String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "text" | "plain" | "json" => Ok(()),
        other => Err(format!(
            "unsupported log encoder '{other}' (expected text|plain|json)"
        )),
    }
}

fn parse_yaml_bytes(v: &Yaml, field: &str) -> Result<Option<u64>, String> {
    if v.is_badvalue() || v.is_null() {
        return Ok(None);
    }
    if let Some(n) = v.as_i64() {
        let u = u64::try_from(n).map_err(|_| format!("{field} must be non-negative"))?;
        return Ok(Some(u));
    }
    if let Some(s) = v.as_str() {
        return parse_byte_size(s).map(Some);
    }
    Err(format!(
        "{field} must be an integer or size string (e.g. \"50MB\")"
    ))
}

fn parse_yaml_u64(v: &Yaml, field: &str) -> Result<Option<u64>, String> {
    if v.is_badvalue() || v.is_null() {
        return Ok(None);
    }
    if let Some(n) = v.as_i64() {
        return u64::try_from(n)
            .map(Some)
            .map_err(|_| format!("{field} must be non-negative"));
    }
    if let Some(s) = v.as_str() {
        return s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("invalid integer for {field}: '{s}'"));
    }
    Err(format!("{field} must be a non-negative integer"))
}

fn parse_yaml_usize(v: &Yaml, field: &str) -> Result<Option<usize>, String> {
    match parse_yaml_u64(v, field)? {
        Some(n) => usize::try_from(n)
            .map(Some)
            .map_err(|_| format!("{field} overflows usize")),
        None => Ok(None),
    }
}

fn parse_string_vec(v: &Yaml) -> Vec<String> {
    v.as_vec()
        .map(|items| {
            items
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use yaml_rust2::YamlLoader;

    use super::*;

    #[test]
    fn parses_byte_sizes_and_rejects_invalid_units_negative_control() {
        assert_eq!(parse_byte_size("1024"), Ok(1024));
        assert_eq!(parse_byte_size("50MB"), Ok(50_000_000));
        assert_eq!(parse_byte_size("20MiB"), Ok(20 * 1024 * 1024));
        assert_eq!(parse_byte_size("512KB"), Ok(512_000));
        assert_eq!(parse_byte_size("1GiB"), Ok(1024 * 1024 * 1024));
        assert!(parse_byte_size("99TB").is_err());
        assert!(parse_byte_size("").is_err());
    }

    #[test]
    fn suppresses_idle_subscribe_polls_while_preserving_submissions_and_dedupe_rate_limits() {
        let yaml = r#"
logging:
  level: info
  encoder: plain
  diagnostics: normal
  suppress_idle_polls: true
  suppress_health_probes: true
  dedupe_window_ms: 1000
  rate_limit_per_sec: 3
  max_bytes: "25MiB"
  max_files: 7
  ring_buffer_lines: 2000
  exclude_patterns: ["noisy-debug-token"]
  nodes:
    sequencer1:
      level: info
      diagnostics: normal
"#;
        let docs = YamlLoader::load_from_str(yaml).expect("load yaml");
        let policy = parse_logging_yaml(&docs[0]).expect("parse logging block");
        assert_eq!(policy.encoder, "plain");
        assert_eq!(policy.max_bytes, 25 * 1024 * 1024);
        assert_eq!(policy.max_files, 7);
        assert_eq!(policy.ring_buffer_lines, 2000);

        let mut env = BTreeMap::new();
        policy.apply_child_env("sequencer1", &mut env);
        assert_eq!(env.get("CANTON_RS_LOG").map(String::as_str), Some("normal"));

        let mut gate = NodeLineGate::new(policy.resolve_for_node("sequencer1"));
        // Idle Subscribe / GetTime spam must be suppressed completely.
        assert!(gate
            .accept(
                "PATH /com.digitalasset.canton.sequencer.api.v30.SequencerService/Subscribe at 1780",
                1000
            )
            .is_empty());
        assert!(gate
            .accept(
                "RPC Subscribe member=PAR::participant1::1220ab from=Some(1)",
                1015
            )
            .is_empty());
        assert!(gate.accept("Request GET /readyz -> 200", 1020).is_empty());
        assert!(gate
            .accept("INFO internal noisy-debug-token payload", 1030)
            .is_empty());

        // Real submission RPCs and errors must pass through, with dedupe collapsing within 1000ms.
        assert_eq!(
            gate.accept("RPC SendAsync member=PAR::participant1::1220ab", 1050),
            vec!["RPC SendAsync member=PAR::participant1::1220ab"]
        );
        assert!(gate
            .accept("RPC SendAsync member=PAR::participant1::1220ab", 1200)
            .is_empty());
        let flushed = gate.accept("WARN connection retry", 1300);
        assert_eq!(flushed.len(), 2);
        assert!(flushed[0].contains("repeated 1 more time(s)"));
        assert_eq!(flushed[1], "WARN connection retry");

        // Rate limit (3 lines in second `1`): 3rd distinct line passes, 4th drops, next second flushes summary.
        assert_eq!(gate.accept("INFO third line", 1400).len(), 1);
        assert!(gate.accept("INFO fourth line dropped", 1500).is_empty());
        let next_sec = gate.accept("INFO new second line", 2100);
        assert_eq!(next_sec.len(), 2);
        assert!(next_sec[0].contains("suppressed 1 log line(s)"));
        assert_eq!(next_sec[1], "INFO new second line");
    }
}
