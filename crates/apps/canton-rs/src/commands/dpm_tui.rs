//! Interactive theme-safe `ratatui` DAR Surface, Privacy Audit & Live Fuzzer TUI (`canton-rs dpm tui` / `dpm top`).
//!
//! [CANTON-NOTE: INVARIANT] Reuses `supervisor::tui::backend` (`CrosstermBackend`) and
//! `supervisor::tui::theme` (`Color::Reset` + `Modifier::REVERSED | Modifier::BOLD`) so every row,
//! badge, and modal stays crisp on dark, light, Solarized, and monochrome terminals.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use clap::Args;
use crossterm::cursor::Show;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use lf_archive::{DarArchive, TemplateSurface};
use ratatui_core::layout::{Constraint, Direction, Layout, Rect};
use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::terminal::{Frame, Terminal};
use ratatui_core::text::{Line, Span};
use ratatui_widgets::block::Block;
use ratatui_widgets::borders::Borders;
use ratatui_widgets::clear::Clear;
use ratatui_widgets::paragraph::{Paragraph, Wrap};
use ratatui_widgets::table::{Row, Table, TableState};

use super::dpm_vision::{
    audit_dar_privacy, fuzz_dar_authorization, DarFuzzReport, DarPrivacyAuditReport,
};
use super::supervisor::tui::backend::{read_key_timeout, CrosstermBackend, Key, TerminalGuard};
use super::supervisor::tui::theme::{
    active_tab_style, focused_selected_style, glyph_span, inactive_tab_style, normal_text_style,
    panel_border_style,
};

#[derive(Args, Debug)]
pub struct DpmTuiArgs {
    /// Path to the compiled `.dar` archive to inspect and fuzz interactively.
    #[arg(default_value = "contracts/target/sample-contract.dar")]
    pub dar_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpmTuiTab {
    Surface,
    PrivacyAudit,
    LiveFuzzer,
}

impl DpmTuiTab {
    pub const ALL: [Self; 3] = [Self::Surface, Self::PrivacyAudit, Self::LiveFuzzer];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Surface => "[1] Templates & Choices",
            Self::PrivacyAudit => "[2] Privacy & Auth Audit",
            Self::LiveFuzzer => "[3] Interactive Fuzzer",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Self::Surface => 0,
            Self::PrivacyAudit => 1,
            Self::LiveFuzzer => 2,
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

#[derive(Clone, Debug)]
pub struct FlatTemplateRow {
    pub module_name: String,
    pub surface: TemplateSurface,
}

/// A fuzz campaign running off the UI thread.
struct FuzzJob {
    seed: u64,
    rx: mpsc::Receiver<Result<DarFuzzReport, String>>,
}

/// Testable state model for `canton-rs dpm tui`.
pub struct DpmTuiState {
    pub dar_path: PathBuf,
    pub archive: DarArchive,
    pub templates: Vec<FlatTemplateRow>,
    pub audit: DarPrivacyAuditReport,
    pub fuzz: Option<DarFuzzReport>,
    /// Last fuzz failure, kept until a later run succeeds.
    pub fuzz_error: Option<String>,
    fuzz_job: Option<FuzzJob>,
    pub next_fuzz_seed: u64,
    pub tab: DpmTuiTab,
    pub tpl_idx: usize,
    pub tpl_state: TableState,
    pub finding_idx: usize,
    pub finding_state: TableState,
    pub help_modal: bool,
    pub banner: Option<(String, Instant)>,
}

impl DpmTuiState {
    pub fn load(dar_path: &Path) -> Result<Self, String> {
        let archive = lf_archive::parse_dar_file(dar_path)
            .map_err(|e| format!("failed to parse '{}': {e}", dar_path.display()))?;
        let audit = audit_dar_privacy(dar_path)?;

        let mut templates = Vec::new();
        for m in &archive.module_surfaces {
            for t in &m.templates {
                templates.push(FlatTemplateRow {
                    module_name: m.name.clone(),
                    surface: t.clone(),
                });
            }
        }
        let mut tpl_state = TableState::default();
        if !templates.is_empty() {
            tpl_state.select(Some(0));
        }
        let mut finding_state = TableState::default();
        if !audit.findings.is_empty() {
            finding_state.select(Some(0));
        }

        let mut state = Self {
            dar_path: dar_path.to_path_buf(),
            archive,
            templates,
            audit,
            fuzz: None,
            fuzz_error: None,
            fuzz_job: None,
            next_fuzz_seed: 0xCA47_0425_2026_0010,
            tab: DpmTuiTab::Surface,
            tpl_idx: 0,
            tpl_state,
            finding_idx: 0,
            finding_state,
            help_modal: false,
            banner: None,
        };
        state.start_fuzz(0xCA47_0425_2026_0001, 2, 4);
        Ok(state)
    }

    pub fn fuzz_running(&self) -> bool {
        self.fuzz_job.is_some()
    }

    fn start_fuzz(&mut self, seed: u64, seeds: usize, steps: usize) {
        let (tx, rx) = mpsc::channel();
        let dar_path = self.dar_path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(fuzz_dar_authorization(&dar_path, seed, seeds, steps));
        });
        self.fuzz_job = Some(FuzzJob { seed, rx });
    }

    /// Applies a finished background fuzz run, if any. Called once per UI tick.
    pub fn poll_fuzz(&mut self) {
        let Some(job) = &self.fuzz_job else {
            return;
        };
        let seed = job.seed;
        let result = match job.rx.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("fuzz worker exited without a result".to_string())
            }
        };
        self.fuzz_job = None;
        match result {
            Ok(rep) => {
                self.set_banner(format!(
                    "Fuzz seed {seed:#x}: {} ({}/{} attempts blocked by authorization)",
                    rep.verdict,
                    rep.unauthorized_attempts_rejected,
                    rep.unauthorized_attempts_total
                ));
                self.fuzz = Some(rep);
                self.fuzz_error = None;
            }
            Err(e) => {
                self.set_banner(format!("Fuzz execution failed: {e}"));
                self.fuzz_error = Some(e);
            }
        }
    }

    pub fn set_banner(&mut self, msg: impl Into<String>) {
        self.banner = Some((msg.into(), Instant::now()));
    }

    pub fn move_selection(&mut self, delta: isize) {
        match self.tab {
            DpmTuiTab::Surface => {
                let len = self.templates.len();
                if len == 0 {
                    return;
                }
                let next = (self.tpl_idx as isize + delta).clamp(0, len as isize - 1) as usize;
                self.tpl_idx = next;
                self.tpl_state.select(Some(next));
            }
            DpmTuiTab::PrivacyAudit => {
                let len = self.audit.findings.len();
                if len == 0 {
                    return;
                }
                let next = (self.finding_idx as isize + delta).clamp(0, len as isize - 1) as usize;
                self.finding_idx = next;
                self.finding_state.select(Some(next));
            }
            DpmTuiTab::LiveFuzzer => {}
        }
    }

    pub fn trigger_live_fuzz(&mut self) {
        self.tab = DpmTuiTab::LiveFuzzer;
        if self.fuzz_running() {
            self.set_banner("A fuzz campaign is already running");
            return;
        }
        let seed = self.next_fuzz_seed;
        self.next_fuzz_seed = self.next_fuzz_seed.wrapping_add(4);
        self.start_fuzz(seed, 4, 6);
        self.set_banner(format!("Fuzz seed {seed:#x}: running in the background"));
    }
}

pub fn execute_dpm_tui(args: DpmTuiArgs) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        eprintln!(
            "canton-rs dpm tui requires an interactive TTY; use 'canton-rs dpm inspect-dar' or 'dpm fuzz' instead"
        );
        std::process::exit(2);
    }

    let mut app = DpmTuiState::load(&args.dar_path)?;

    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
        orig_hook(info);
    }));

    let _guard =
        TerminalGuard::enter().map_err(|e| format!("failed to enter raw TUI mode: {e}"))?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("failed to create Terminal: {e}"))?;
    terminal.clear().map_err(|e| e.to_string())?;

    loop {
        app.poll_fuzz();
        if let Some((_, ts)) = &app.banner {
            if ts.elapsed() > Duration::from_secs(4) {
                app.banner = None;
            }
        }
        terminal
            .draw(|f| render_dpm_tui(f, &mut app))
            .map_err(|e| e.to_string())?;

        let Some(key) = read_key_timeout(150) else {
            continue;
        };
        if handle_dpm_key(&mut app, key) {
            break;
        }
    }
    Ok(())
}

pub fn handle_dpm_key(app: &mut DpmTuiState, key: Key) -> bool {
    if matches!(key, Key::CtrlC) {
        return true;
    }
    if app.help_modal {
        if matches!(
            key,
            Key::Esc | Key::Enter | Key::Char('q') | Key::Char('?') | Key::Char('h')
        ) {
            app.help_modal = false;
        }
        return false;
    }

    match key {
        Key::Char('q') | Key::Esc => return true,
        Key::Char('?') | Key::Char('h') => app.help_modal = true,
        Key::Tab | Key::Right => app.tab = app.tab.next(),
        Key::BackTab | Key::Left => app.tab = app.tab.prev(),
        Key::Char('1') => app.tab = DpmTuiTab::Surface,
        Key::Char('2') => app.tab = DpmTuiTab::PrivacyAudit,
        Key::Char('3') => app.tab = DpmTuiTab::LiveFuzzer,
        Key::Up | Key::Char('k') => app.move_selection(-1),
        Key::Down | Key::Char('j') => app.move_selection(1),
        Key::PageUp => app.move_selection(-8),
        Key::PageDown => app.move_selection(8),
        Key::Char('f') => app.trigger_live_fuzz(),
        _ => {}
    }
    false
}

pub fn render_dpm_tui(frame: &mut Frame<'_>, app: &mut DpmTuiState) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let short_pkg: String = app.archive.main_package_id.chars().take(16).collect();
    let banner_str = app
        .banner
        .as_ref()
        .map(|(m, _)| format!(" | {m}"))
        .unwrap_or_default();
    let header_line = Line::from(vec![
        Span::styled(
            " canton-rs dpm tui ",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "{} | pkg:{short_pkg}.. | LF {} | Templates: {} | Audit: {}{banner_str}",
                app.dar_path.display(),
                app.archive.lf_version,
                app.templates.len(),
                app.audit.status,
            ),
            normal_text_style(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(header_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(normal_text_style()),
        ),
        outer[0],
    );

    let mut tab_spans: Vec<Span<'static>> = Vec::new();
    for (idx, t) in DpmTuiTab::ALL.iter().enumerate() {
        if idx > 0 {
            tab_spans.push(Span::styled("   ", normal_text_style()));
        }
        let st = if *t == app.tab {
            active_tab_style()
        } else {
            inactive_tab_style()
        };
        tab_spans.push(Span::styled(format!(" {} ", t.label()), st));
    }
    frame.render_widget(Paragraph::new(Line::from(tab_spans)), outer[1]);

    match app.tab {
        DpmTuiTab::Surface => render_surface_tab(frame, outer[2], app),
        DpmTuiTab::PrivacyAudit => render_privacy_tab(frame, outer[2], app),
        DpmTuiTab::LiveFuzzer => render_fuzzer_tab(frame, outer[2], app),
    }

    let footer = Line::from(Span::styled(
        " [↑/↓] Select  [1-3/Tab] Switch Tab  [f] Run Multi-Party Fuzzer  [?] Help  [q] Quit ",
        normal_text_style().add_modifier(Modifier::REVERSED),
    ));
    frame.render_widget(Paragraph::new(footer), outer[3]);

    if app.help_modal {
        render_dpm_help_modal(frame);
    }
}

fn render_surface_tab(frame: &mut Frame<'_>, area: Rect, app: &mut DpmTuiState) {
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let header = Row::new(["", "MODULE", "TEMPLATE", "SIGS", "CHOICES"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));

    let selected = app.tpl_idx;
    let rows: Vec<Row<'static>> = app
        .templates
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let is_sel = idx == selected;
            let cursor = if is_sel { "▶ " } else { "  " };
            let s = normal_text_style();
            let choice_cnt = item
                .surface
                .choices
                .iter()
                .filter(|c| c.name != "Archive")
                .count();
            Row::new(vec![
                Line::from(Span::styled(cursor, s)),
                Line::from(Span::styled(item.module_name.clone(), s)),
                Line::from(Span::styled(item.surface.name.clone(), s)),
                Line::from(Span::styled(item.surface.signatories.len().to_string(), s)),
                Line::from(Span::styled(choice_cnt.to_string(), s)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Length(16),
        Constraint::Min(18),
        Constraint::Length(5),
        Constraint::Length(7),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(format!(
                    " Daml-LF Templates ({} · ACTIVE) ",
                    app.templates.len()
                ))
                .borders(Borders::ALL)
                .border_style(panel_border_style(true)),
        )
        .row_highlight_style(focused_selected_style());

    frame.render_stateful_widget(table, split[0], &mut app.tpl_state);

    let detail = if let Some(item) = app.templates.get(app.tpl_idx) {
        let t = &item.surface;
        let mut fields_str = String::new();
        for f in &t.fields {
            fields_str.push_str(&format!("  • {}: {}\n", f.name, f.type_str));
        }
        let mut choices_str = String::new();
        for c in &t.choices {
            let mode = if c.consuming {
                "consuming"
            } else {
                "nonconsuming"
            };
            let ctrls = if c.controllers.is_empty() {
                "(dynamic)".to_string()
            } else {
                c.controllers.join(", ")
            };
            choices_str.push_str(&format!(
                "  • {} [{}] ctrl=[{}] -> {}\n",
                c.name, mode, ctrls, c.return_type_str
            ));
        }
        format!(
            "Template     : {}:{}\n\
             Signatories  : [{}]\n\
             Observers    : [{}]\n\
             Ensure Guard : {}\n\n\
             Record Fields ({})\n\
             ──────────────────\n\
             {}\n\
             Choices ({})\n\
             ────────────\n\
             {}",
            item.module_name,
            t.name,
            t.signatories.join(", "),
            t.observers.join(", "),
            if t.ensure.present {
                format!("present ({}B LF)", t.ensure.bytes_len)
            } else {
                "none".to_string()
            },
            t.fields.len(),
            fields_str,
            t.choices.len(),
            choices_str,
        )
    } else {
        String::from("No templates found in DAR archive.")
    };

    frame.render_widget(
        Paragraph::new(detail)
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Stakeholders, Fields & Choice Controllers ")
                    .borders(Borders::ALL)
                    .border_style(normal_text_style()),
            )
            .wrap(Wrap { trim: false }),
        split[1],
    );
}

fn render_privacy_tab(frame: &mut Frame<'_>, area: Rect, app: &mut DpmTuiState) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(6)])
        .split(area);

    let summary = format!(
        "Main Package ID (SHA-256) : {}\n\
         Verified DALF Packages    : {} (Daml-LF {})\n\
         Audited Surface           : {} template(s), {} non-Archive choice(s)\n\
         Security & Privacy Status : {} ({} finding(s))",
        app.audit.main_package_id,
        app.audit.dalf_packages_verified,
        app.audit.lf_version,
        app.audit.templates_count,
        app.audit.choices_count,
        app.audit.status,
        app.audit.findings.len(),
    );
    frame.render_widget(
        Paragraph::new(summary).style(normal_text_style()).block(
            Block::default()
                .title(" Static Cryptographic & Sub-Transaction Privacy Summary ")
                .borders(Borders::ALL)
                .border_style(normal_text_style()),
        ),
        split[0],
    );

    if app.audit.findings.is_empty() {
        frame.render_widget(
            Paragraph::new("Zero static privacy or authorization warnings found.")
                .style(normal_text_style())
                .block(
                    Block::default()
                        .title(" Findings (0) ")
                        .borders(Borders::ALL)
                        .border_style(panel_border_style(true)),
                ),
            split[1],
        );
        return;
    }

    let header = Row::new(["", "SEVERITY", "CODE", "TARGET", "DETAIL"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));

    let selected = app.finding_idx;
    let rows: Vec<Row<'static>> = app
        .audit
        .findings
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            let is_sel = idx == selected;
            let cursor = if is_sel { "▶ " } else { "  " };
            let (glyph, col) = match f.severity.as_str() {
                "CRITICAL" | "HIGH" => ("✖", Color::LightRed),
                "WARN" => ("▲", Color::LightYellow),
                _ => ("●", Color::LightCyan),
            };
            let s = normal_text_style();
            Row::new(vec![
                Line::from(vec![
                    Span::styled(cursor, s),
                    glyph_span(glyph, col, is_sel),
                ]),
                Line::from(Span::styled(f.severity.clone(), s)),
                Line::from(Span::styled(f.code.clone(), s)),
                Line::from(Span::styled(f.target.clone(), s)),
                Line::from(Span::styled(f.detail.clone(), s)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Length(9),
        Constraint::Length(28),
        Constraint::Length(26),
        Constraint::Min(24),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(format!(
                    " Privacy & Authorization Findings ({} · ACTIVE) ",
                    app.audit.findings.len()
                ))
                .borders(Borders::ALL)
                .border_style(panel_border_style(true)),
        )
        .row_highlight_style(focused_selected_style());

    frame.render_stateful_widget(table, split[1], &mut app.finding_state);
}

fn render_fuzzer_tab(frame: &mut Frame<'_>, area: Rect, app: &DpmTuiState) {
    let body = match &app.fuzz {
        Some(rep) => {
            let mut seed_lines = String::new();
            for tr in &rep.seed_traces {
                seed_lines.push_str(&format!(
                    "  • seed {:#018x} | creates_ok={} | choices_ok={} | creates_blocked_by_auth={} | choices_blocked_by_auth={} | violations={}\n",
                    tr.seed,
                    tr.authorized_creates_ok,
                    tr.authorized_choices_exercised,
                    tr.unauthorized_creates_rejected,
                    tr.unauthorized_choices_rejected,
                    tr.invariant_violations,
                ));
            }
            format!(
                "Security Verdict                : {}\n\
                 Campaigns Executed              : {} seeds × {} steps\n\
                 Authorized Creates Committed    : {}\n\
                 Authorized Choices Exercised    : {}\n\
                 Verdict Reason                  : {}\n\
                 Blocked by Authorization        : {} / {} attempts\n\
                 Rejected for Other Reasons      : {} (not counted as blocked) {:?}\n\
                 Ledger API Isolation Checks     : {}\n\
                 Stakeholder Isolation Leaks     : {}\n\
                 Authorization Bypasses          : {}\n\n\
                 Deterministic Seed Traces (In-Memory CantonNodeBuilder + lf-eval)\n\
                 ─────────────────────────────────────────────────────────────────\n\
                 {}\n\
                 Press [f] to run a fresh 4-seed × 6-step multi-party fuzz campaign!",
                rep.verdict,
                rep.seeds_executed,
                rep.steps_per_seed,
                rep.authorized_creates_ok,
                rep.authorized_choices_exercised,
                rep.verdict_reason,
                rep.unauthorized_attempts_rejected,
                rep.unauthorized_attempts_total,
                rep.unauthorized_attempts_inconclusive,
                rep.inconclusive_rejection_codes,
                rep.isolation_checks,
                rep.stakeholder_isolation_violations,
                rep.authorization_bypasses,
                seed_lines,
            )
        }
        None => match &app.fuzz_error {
            Some(e) => format!("Fuzz execution failed: {e}\n\nPress [f] to retry."),
            None if app.fuzz_running() => {
                String::from("Fuzz campaign running in the background...")
            }
            None => String::from(
                "Press [f] to execute deterministic multi-party authorization fuzzing.",
            ),
        },
    };
    let body = if app.fuzz_running() && app.fuzz.is_some() {
        format!("[a new fuzz campaign is running in the background]\n\n{body}")
    } else {
        body
    };

    frame.render_widget(
        Paragraph::new(body)
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Multi-Party Authorization & Stakeholder-Isolation Fuzzer ")
                    .borders(Borders::ALL)
                    .border_style(panel_border_style(true)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_dpm_help_modal(frame: &mut Frame<'_>) {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(14.min(frame.area().height)),
            Constraint::Fill(1),
        ])
        .split(frame.area());
    let area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(15),
            Constraint::Percentage(70),
            Constraint::Percentage(15),
        ])
        .split(v[1])[1];

    frame.render_widget(Clear, area);
    let help = "\
Navigation & Tabs
  ↑ / ↓ or j / k   Select template or privacy finding (theme-safe reverse-video bar)
  1 / 2 / 3        Jump to Surface / Privacy Audit / Interactive Fuzzer
  Tab / ← / →      Cycle tabs

Security Verification
  f                Run fresh deterministic 4-seed × 6-step multi-party fuzz campaign
  ? or h           Toggle this help modal
  q or Esc         Exit TUI";
    frame.render_widget(
        Paragraph::new(help).style(normal_text_style()).block(
            Block::default()
                .title(" canton-rs dpm tui — Keyboard Shortcuts ")
                .borders(Borders::ALL)
                .border_style(panel_border_style(true)),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui_core::backend::TestBackend;

    #[test]
    fn renders_all_dpm_tui_tabs_and_runs_fuzzer_with_reset_bg() {
        let dar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/target/sample-contract.dar");
        let mut app = DpmTuiState::load(&dar).expect("load sample dar into dpm tui");
        let backend = TestBackend::new(124, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");

        let started = Instant::now();
        while app.fuzz_running() {
            assert!(
                started.elapsed() < Duration::from_secs(300),
                "startup fuzz never finished"
            );
            std::thread::sleep(Duration::from_millis(20));
            app.poll_fuzz();
        }
        assert!(
            app.fuzz.is_some(),
            "startup fuzz result: {:?}",
            app.fuzz_error
        );

        // [f] returns at once and leaves the campaign running off the UI thread.
        assert!(!handle_dpm_key(&mut app, Key::Char('f')));
        assert_eq!(app.tab, DpmTuiTab::LiveFuzzer);
        assert!(app.fuzz_running(), "fuzz must not run on the UI thread");

        for tab in DpmTuiTab::ALL {
            app.tab = tab;
            terminal
                .draw(|f| render_dpm_tui(f, &mut app))
                .expect("draw dpm tab");
            for cell in terminal.backend().buffer().content() {
                assert_eq!(
                    cell.bg,
                    Color::Reset,
                    "dpm tui must never emit hardcoded background colors"
                );
            }
        }
    }
}
