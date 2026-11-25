//! Theme-safe color palette and selection styles for `canton-rs daemon top`.
//!
//! [CANTON-NOTE: INVARIANT] Never hardcode `Color::Blue`, `Color::Gray`, `Color::DarkGray`, or
//! `Color::Black` in cell foregrounds or backgrounds. Primary text uses `Color::Reset` (the
//! user terminal's native foreground/background), status colors are restricted to a single prefix
//! glyph on unselected rows, and active row highlights use `Modifier::REVERSED | Modifier::BOLD`
//! so every row stays crisp across dark, light, navy, and Solarized themes.

use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::text::Span;

use super::super::log_rotate::LogLevel;
use super::super::{NodeLifecycleState, QuorumVerdictState};

/// Native terminal foreground and background without hardcoded color overrides.
pub fn normal_text_style() -> Style {
    Style::default().fg(Color::Reset).bg(Color::Reset)
}

/// High-contrast solid selection bar for the currently focused interactive table.
pub fn focused_selected_style() -> Style {
    Style::default()
        .fg(Color::Reset)
        .bg(Color::Reset)
        .add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

/// Subtle cursor indicator when another panel owns keyboard focus.
pub fn unfocused_selected_style() -> Style {
    Style::default()
        .fg(Color::Reset)
        .bg(Color::Reset)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Emphasizes the active panel border (`LightCyan` + `BOLD`) versus passive borders (`Reset`).
pub fn panel_border_style(focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Reset)
    }
}

/// Active workspace tab highlight using theme-independent reverse video.
pub fn active_tab_style() -> Style {
    Style::default()
        .fg(Color::Reset)
        .bg(Color::Reset)
        .add_modifier(Modifier::REVERSED | Modifier::BOLD)
}

/// Inactive workspace tab text in native terminal foreground.
pub fn inactive_tab_style() -> Style {
    normal_text_style()
}

/// Renders a single-glyph indicator (`●`, `■`, `▲`, `↻`, `✖`, `◐`).
///
/// Inside a focused selected row, the foreground remains `Color::Reset` so the reverse-video
/// highlight bar stays completely uniform from edge to edge.
pub fn glyph_span(
    glyph: &'static str,
    color: Color,
    row_is_focused_selected: bool,
) -> Span<'static> {
    if row_is_focused_selected {
        Span::styled(glyph, normal_text_style())
    } else {
        Span::styled(
            glyph,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )
    }
}

/// Returns `(glyph, short_label, semantic_glyph_color)` for a managed node lifecycle state.
pub const fn node_status_badge(state: NodeLifecycleState) -> (&'static str, &'static str, Color) {
    match state {
        NodeLifecycleState::Online => ("●", "Online", Color::LightGreen),
        NodeLifecycleState::Bootstrapping => ("◐", "Booting", Color::LightCyan),
        NodeLifecycleState::Degraded => ("▲", "Degraded", Color::LightYellow),
        NodeLifecycleState::BackoffWait => ("↻", "Backoff", Color::LightYellow),
        NodeLifecycleState::Stopped => ("■", "Stopped", Color::LightYellow),
        NodeLifecycleState::Failed => ("✖", "Failed", Color::LightRed),
    }
}

/// Returns `(glyph, uppercase_verdict, semantic_glyph_color)` for a 2PC Mediator verdict.
pub const fn verdict_badge(verdict: QuorumVerdictState) -> (&'static str, &'static str, Color) {
    match verdict {
        QuorumVerdictState::Approved => ("●", "APPROVED", Color::LightGreen),
        QuorumVerdictState::Pending => ("◐", "PENDING", Color::LightYellow),
        QuorumVerdictState::Rejected => ("✖", "REJECTED", Color::LightRed),
        QuorumVerdictState::TimedOut => ("▲", "TIMED_OUT", Color::LightRed),
    }
}

/// Severity tag style for log lines (`[ERROR]`, `[WARN]`, `[INFO]`, `[DEBUG]`); log bodies use `Reset`.
pub fn log_level_tag_style(level: LogLevel) -> Style {
    match level {
        LogLevel::Error => Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
        LogLevel::Warn => Style::default()
            .fg(Color::LightYellow)
            .add_modifier(Modifier::BOLD),
        LogLevel::Info => Style::default().fg(Color::LightCyan),
        LogLevel::Debug => Style::default()
            .fg(Color::Reset)
            .add_modifier(Modifier::DIM),
    }
}
