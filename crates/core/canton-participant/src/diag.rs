//! Centralized diagnostic log sink for `canton-participant`.
//!
//! Preserves exact default `stderr` diagnostic output unless `CANTON_RS_LOG` is
//! explicitly set to `off`, `0`, or `false`.

use std::sync::OnceLock;

/// Returns whether domain diagnostic output is enabled (`CANTON_RS_LOG` gate).
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CANTON_RS_LOG").map_or(true, |v| {
            let trimmed = v.trim();
            !trimmed.eq_ignore_ascii_case("off")
                && trimmed != "0"
                && !trimmed.eq_ignore_ascii_case("false")
        })
    })
}

/// Emits a formatted diagnostic line to `stderr` when diagnostics are enabled.
pub(crate) fn emit_stderr(args: std::fmt::Arguments<'_>) {
    if enabled() {
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

pub(crate) use diag_eprintln;
