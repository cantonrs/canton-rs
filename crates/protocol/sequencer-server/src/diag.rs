//! Centralized diagnostic log sink for `canton-sequencer-server`.
//!
//! Preserves exact default `stderr` output (relied upon by oracle harnesses) unless
//! `CANTON_RS_LOG` is explicitly set:
//! - `off` | `0` | `false` | `warn` | `error`: disables all diagnostic lines.
//! - `normal` | `info` | `quiet-polls` | `no-polls`: keeps state/submission RPC diagnostics while
//!   suppressing high-frequency idle `Subscribe` / `GetTime` poll lines at the source.
//! - `all` | `debug` | `trace` | `1` | `true` (or unset): emits all diagnostic lines.

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiagLevel {
    Off,
    Normal,
    All,
}

fn level() -> DiagLevel {
    static LEVEL: OnceLock<DiagLevel> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        std::env::var("CANTON_RS_LOG").map_or(DiagLevel::All, |v| {
            match v.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" | "warn" | "error" | "none" => DiagLevel::Off,
                "normal" | "info" | "quiet-polls" | "no-polls" => DiagLevel::Normal,
                _ => DiagLevel::All,
            }
        })
    })
}

/// Returns whether domain diagnostic output is enabled (`CANTON_RS_LOG` gate).
pub(crate) fn enabled() -> bool {
    level() != DiagLevel::Off
}

/// Returns whether high-frequency polling RPC diagnostics (`Subscribe`, `GetTime`) are enabled.
pub(crate) fn poll_enabled() -> bool {
    level() == DiagLevel::All
}

/// Emits a formatted diagnostic line to `stderr` when diagnostics are enabled.
pub(crate) fn emit_stderr(args: std::fmt::Arguments<'_>) {
    if enabled() {
        eprintln!("{args}");
    }
}

/// Emits a high-frequency polling diagnostic line only when `CANTON_RS_LOG` is `all`/unset.
pub(crate) fn emit_poll_stderr(args: std::fmt::Arguments<'_>) {
    if poll_enabled() {
        eprintln!("{args}");
    }
}

macro_rules! diag_eprintln {
    () => {
        $crate::diag::emit_stderr(format_args!(""))
    };
    ($($arg:tt)+) => {
        $crate::diag::emit_stderr(format_args!($($arg)+))
    };
}

macro_rules! diag_poll_eprintln {
    ($($arg:tt)+) => {
        $crate::diag::emit_poll_stderr(format_args!($($arg)+))
    };
}

pub(crate) use {diag_eprintln, diag_poll_eprintln};
