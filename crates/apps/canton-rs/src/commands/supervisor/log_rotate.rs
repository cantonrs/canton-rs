//! Line-boundary size-based log rotation (`SizeRotatingWriter`) and multiplexed in-memory log hub.
//!
//! [CANTON-NOTE: INVARIANT] Rotation happens strictly AFTER writing a `\n` newline terminator,
//! guaranteeing that `--log-encoder json` records never split mid-line across `.log` and `.log.1`.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::now_unix_ms;

/// Per-node in-memory log ring-buffer capacity (1,000 recent lines).
const MAX_RING_LINES_PER_NODE: usize = 1000;
/// Broadcast channel capacity for live `daemon logs -f` and TUI subscribers.
const BROADCAST_CAPACITY: usize = 512;

/// Parsed log severity level for multiplexed log filtering (`1-4` in TUI, `--level` in `daemon logs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// Parses case-insensitive level strings or numbers (`all`/`debug`, `info`, `warn`, `error`).
    pub fn parse_filter(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" | "err" | "4" => Self::Error,
            "warn" | "warning" | "3" => Self::Warn,
            "debug" | "all" | "1" => Self::Debug,
            _ => Self::Info,
        }
    }

    /// Canonical uppercase tag displayed in terminal and TUI log views.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

/// One log line emitted by a supervised node or by the supervisor itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEvent {
    pub ts_unix_ms: u64,
    pub node: String,
    pub level: LogLevel,
    pub line: String,
}

/// Newline-safe size-rotating file writer for one managed node (`<state-dir>/logs/<node>.log`).
pub struct SizeRotatingWriter {
    active_path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    written_bytes: u64,
    writer: BufWriter<File>,
}

impl SizeRotatingWriter {
    /// Opens `<state_dir>/logs/<node>.log` for append (resuming accurate byte count) and creates
    /// `<state_dir>/<node>.log` symlink for compatibility with existing single-file scripts.
    pub fn open(
        state_dir: &Path,
        node: &str,
        max_bytes: u64,
        max_files: usize,
    ) -> io::Result<Self> {
        let logs_dir = state_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)?;
        let active_path = logs_dir.join(format!("{node}.log"));
        let compat_link = state_dir.join(format!("{node}.log"));
        ensure_compat_symlink(&active_path, &compat_link);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active_path)?;
        let written_bytes = file.metadata()?.len();
        Ok(Self {
            active_path,
            max_bytes: max_bytes.max(1024),
            max_files: max_files.max(1),
            written_bytes,
            writer: BufWriter::new(file),
        })
    }

    /// Writes `line` terminated by `\n` and rotates ONLY after the newline is flushed when size >= `max_bytes`.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let clean = line.trim_end_matches(['\r', '\n']);
        self.writer.write_all(clean.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.written_bytes = self
            .written_bytes
            .saturating_add(u64::try_from(clean.len() + 1).unwrap_or(u64::MAX));
        if self.written_bytes >= self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    /// Returns the active log file path.
    #[cfg(test)]
    pub fn active_path(&self) -> &Path {
        &self.active_path
    }

    /// Returns current active log file size and number of existing log files (active + rotated).
    #[cfg(test)]
    pub fn stats(&self) -> (u64, usize) {
        let mut generations = usize::from(self.active_path.exists());
        for idx in 1..=self.max_files {
            if rotated_path(&self.active_path, idx).exists() {
                generations += 1;
            }
        }
        (self.written_bytes, generations)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        let oldest = rotated_path(&self.active_path, self.max_files);
        if oldest.exists() {
            let _ = std::fs::remove_file(&oldest);
        }
        for idx in (1..self.max_files).rev() {
            let src = rotated_path(&self.active_path, idx);
            let dst = rotated_path(&self.active_path, idx + 1);
            if src.exists() {
                std::fs::rename(&src, &dst)?;
            }
        }
        if self.active_path.exists() {
            std::fs::rename(&self.active_path, rotated_path(&self.active_path, 1))?;
        }
        let fresh = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.active_path)?;
        self.writer = BufWriter::new(fresh);
        self.written_bytes = 0;
        Ok(())
    }
}

fn rotated_path(active: &Path, generation: usize) -> PathBuf {
    PathBuf::from(format!("{}.{generation}", active.display()))
}

#[cfg(unix)]
fn ensure_compat_symlink(target: &Path, link_path: &Path) {
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        return;
    }
    let rel_target = target
        .file_name()
        .map(|name| Path::new("logs").join(name))
        .unwrap_or_else(|| target.to_path_buf());
    let _ = std::os::unix::fs::symlink(rel_target, link_path);
}

#[cfg(not(unix))]
fn ensure_compat_symlink(_target: &Path, _link_path: &Path) {}

/// Shared ring buffer and live broadcast hub for node logs across `daemon logs` and `daemon top`.
#[derive(Clone)]
pub struct LogHub {
    ring_capacity: usize,
    rings: Arc<Mutex<BTreeMap<String, VecDeque<LogEvent>>>>,
    sender: broadcast::Sender<LogEvent>,
}

impl Default for LogHub {
    fn default() -> Self {
        Self::new()
    }
}

impl LogHub {
    /// Creates an empty log hub with the default 1,000-line per-node ring capacity.
    pub fn new() -> Self {
        Self::with_capacity(MAX_RING_LINES_PER_NODE)
    }

    /// Creates an empty log hub with an explicit per-node ring capacity.
    pub fn with_capacity(ring_capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            ring_capacity: ring_capacity.max(50),
            rings: Arc::new(Mutex::new(BTreeMap::new())),
            sender,
        }
    }

    /// Records a raw output line, detects severity (`JSON "level"` or text heuristic), appends to the
    /// bounded per-node ring buffer, and notifies live subscribers without blocking.
    pub fn push(&self, node: &str, raw_line: &str) {
        let clean = raw_line.trim_end_matches(['\r', '\n']).to_string();
        let event = LogEvent {
            ts_unix_ms: now_unix_ms(),
            node: node.to_string(),
            level: detect_log_level(&clean),
            line: clean,
        };
        if let Ok(mut guard) = self.rings.lock() {
            let ring = guard.entry(node.to_string()).or_default();
            while ring.len() >= self.ring_capacity {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }
        let _ = self.sender.send(event);
    }

    /// Returns the last `tail` lines across either one node or all nodes merged chronologically.
    pub fn tail(&self, node: Option<&str>, min_level: LogLevel, tail: usize) -> Vec<LogEvent> {
        let Ok(guard) = self.rings.lock() else {
            return Vec::new();
        };
        let mut collected: Vec<LogEvent> = match node {
            Some(target) => guard
                .get(target)
                .map(|q| q.iter().filter(|e| e.level >= min_level).cloned().collect())
                .unwrap_or_default(),
            None => {
                let mut all: Vec<LogEvent> = guard
                    .values()
                    .flat_map(|q| q.iter())
                    .filter(|e| e.level >= min_level)
                    .cloned()
                    .collect();
                all.sort_by_key(|e| e.ts_unix_ms);
                all
            }
        };
        if collected.len() > tail {
            collected.drain(..collected.len() - tail);
        }
        collected
    }

    /// Subscribes to live log events as they arrive.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.sender.subscribe()
    }
}

/// Counts active log file size and rotated generation files for `NodeInspection`.
pub fn inspect_log_file(state_dir: &Path, node: &str, max_files: usize) -> (PathBuf, u64, usize) {
    let active = state_dir.join("logs").join(format!("{node}.log"));
    let bytes = std::fs::metadata(&active).map(|m| m.len()).unwrap_or(0);
    let mut gens = usize::from(active.exists());
    for idx in 1..=max_files {
        if rotated_path(&active, idx).exists() {
            gens += 1;
        }
    }
    (active, bytes, gens)
}

/// Extracts log level from Canton JSON log lines or standard text log markers.
pub fn detect_log_level(line: &str) -> LogLevel {
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) =
            serde_json::from_str::<serde_json::Value>(trimmed)
        {
            if let Some(level) = map.get("level").and_then(serde_json::Value::as_str) {
                return LogLevel::parse_filter(level);
            }
        }
    }
    let upper = line.to_ascii_uppercase();
    if upper.contains(" ERROR ")
        || upper.starts_with("ERROR")
        || upper.contains("\"LEVEL\":\"ERROR\"")
    {
        LogLevel::Error
    } else if upper.contains(" WARN ")
        || upper.starts_with("WARN")
        || upper.contains("\"LEVEL\":\"WARN\"")
    {
        LogLevel::Warn
    } else if upper.contains(" DEBUG ") || upper.starts_with("DEBUG") {
        LogLevel::Debug
    } else {
        LogLevel::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new(name: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("canton-sup-rot-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("create test dir");
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rotation_never_splits_json_lines() {
        let dir = TestDir::new("rotate");
        let mut writer = SizeRotatingWriter::open(dir.path(), "participant1", 1024, 3)
            .expect("open SizeRotatingWriter");

        // Write 30 JSON lines (~90 bytes each) to trigger multiple rotations at 1024 B threshold.
        for i in 0..30 {
            let line = format!(
                r#"{{"ts":"2026-11-19T00:00:00Z","level":"INFO","seq":{i},"msg":"transaction committed offset={i:04}"}}"#
            );
            writer.write_line(&line).expect("write json line");
        }

        let (_, gens) = writer.stats();
        assert!(
            (2..=4).contains(&gens),
            "unexpected generation count {gens}"
        );
        assert!(!rotated_path(writer.active_path(), 4).exists());

        // Verify every line in every generation parses as complete valid JSON.
        let mut files = vec![writer.active_path().to_path_buf()];
        for i in 1..=3 {
            let p = rotated_path(writer.active_path(), i);
            if p.exists() {
                files.push(p);
            }
        }
        for file in files {
            let content = std::fs::read_to_string(&file).expect("read rotated file");
            for raw_line in content.lines() {
                let parsed: serde_json::Value = serde_json::from_str(raw_line)
                    .expect("JSON line must stay intact across rotation");
                assert!(parsed.get("seq").is_some());
            }
        }
        assert!(dir.path().join("participant1.log").exists());
    }

    #[test]
    fn log_hub_tails_and_filters_levels() {
        let hub = LogHub::new();
        hub.push("p1", "2026-11-19 DEBUG detail");
        hub.push("p1", r#"{"level":"INFO","message":"boot ok"}"#);
        hub.push("p1", "2026-11-19 WARN slow query");
        hub.push("p2", "ERROR fatal crash");

        let p1_warns = hub.tail(Some("p1"), LogLevel::Warn, 10);
        assert_eq!(p1_warns.len(), 1);
        assert_eq!(p1_warns[0].level, LogLevel::Warn);

        let all_err = hub.tail(None, LogLevel::Error, 10);
        assert_eq!(all_err.len(), 1);
        assert_eq!(all_err[0].node, "p2");
    }
}
