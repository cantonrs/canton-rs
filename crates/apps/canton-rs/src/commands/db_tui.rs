//! Interactive theme-safe `ratatui` Storage, Cold Archive & Staged Replay TUI (`canton-rs db tui` / `db top`).
//!
//! [CANTON-NOTE: INVARIANT] Reuses `supervisor::tui::backend` (`CrosstermBackend` + CJK-safe cursor
//! resync) and `supervisor::tui::theme` (`Color::Reset` + `Modifier::REVERSED | Modifier::BOLD`) so
//! every table row and tab stays crisp on dark, light, Solarized, and monochrome terminals.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use canton_participant::cold_archive::{
    staged_replay_dir_streaming, verify_archive_dir_streaming, ArchiveVerifyReport,
    ColdArchiveSegmentMeta, StagedReplayReport, StorageOverviewStats,
};
use crossterm::cursor::Show;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use ratatui_core::layout::{Constraint, Direction, Layout, Rect};
use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::terminal::{Frame, Terminal};
use ratatui_core::text::{Line, Span};
use ratatui_widgets::block::Block;
use ratatui_widgets::borders::Borders;
use ratatui_widgets::clear::Clear;
use ratatui_widgets::paragraph::{Paragraph, Wrap};
use ratatui_widgets::table::{Row, Table, TableState};

use super::supervisor::format_bytes;
use super::supervisor::tui::backend::{read_key_timeout, CrosstermBackend, Key, TerminalGuard};
use super::supervisor::tui::theme::{
    active_tab_style, focused_selected_style, glyph_span, inactive_tab_style, normal_text_style,
    panel_border_style,
};

/// Active tab inside `canton-rs db tui`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbTuiTab {
    Tables,
    ColdSegments,
    StagedReplay,
}

impl DbTuiTab {
    pub const ALL: [Self; 3] = [Self::Tables, Self::ColdSegments, Self::StagedReplay];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Tables => "[1] PG Tables & Headroom",
            Self::ColdSegments => "[2] Cold Archive Segments",
            Self::StagedReplay => "[3] 4-Stage Replay",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Self::Tables => 0,
            Self::ColdSegments => 1,
            Self::StagedReplay => 2,
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Result of a cold-archive job run off the UI thread.
// [CANTON-NOTE: WHY] Verifying or replaying a large segment set reads every segment from disk; running it inside the
// key handler froze the whole TUI (no redraw, no Ctrl+C) until it finished (UNRESOLVED U-55).
pub enum ArchiveJob {
    Verify(Result<(ArchiveVerifyReport, Vec<ColdArchiveSegmentMeta>), String>),
    Replay(Result<StagedReplayReport, String>),
}

/// Testable state model for `canton-rs db tui`.
pub struct DbTuiState {
    pub source_label: String,
    pub archive_dir: Option<PathBuf>,
    pub tab: DbTuiTab,
    pub stats: StorageOverviewStats,
    pub segments: Vec<ColdArchiveSegmentMeta>,
    pub replay_report: Option<StagedReplayReport>,
    pub table_idx: usize,
    pub table_state: TableState,
    pub seg_idx: usize,
    pub seg_state: TableState,
    pub detail_modal: Option<(String, String, u16)>,
    pub help_modal: bool,
    pub banner: Option<(String, Instant)>,
    /// The running background job, if any; at most one runs at a time.
    pub pending_job: Option<Receiver<ArchiveJob>>,
}

impl DbTuiState {
    pub fn new(
        source_label: String,
        archive_dir: Option<PathBuf>,
        stats: StorageOverviewStats,
        segments: Vec<ColdArchiveSegmentMeta>,
        replay_report: Option<StagedReplayReport>,
    ) -> Self {
        let mut table_state = TableState::default();
        if !stats.tables.is_empty() {
            table_state.select(Some(0));
        }
        let mut seg_state = TableState::default();
        if !segments.is_empty() {
            seg_state.select(Some(0));
        }
        let initial_tab = if stats.tables.is_empty() && !segments.is_empty() {
            DbTuiTab::ColdSegments
        } else {
            DbTuiTab::Tables
        };
        Self {
            source_label,
            archive_dir,
            tab: initial_tab,
            stats,
            segments,
            replay_report,
            table_idx: 0,
            table_state,
            seg_idx: 0,
            seg_state,
            detail_modal: None,
            help_modal: false,
            banner: None,
            pending_job: None,
        }
    }

    pub fn set_banner(&mut self, msg: impl Into<String>) {
        self.banner = Some((msg.into(), Instant::now()));
    }

    pub fn move_selection(&mut self, delta: isize) {
        match self.tab {
            DbTuiTab::Tables => {
                let len = self.stats.tables.len();
                if len == 0 {
                    return;
                }
                let next = (self.table_idx as isize + delta).clamp(0, len as isize - 1) as usize;
                self.table_idx = next;
                self.table_state.select(Some(next));
            }
            DbTuiTab::ColdSegments => {
                let len = self.segments.len();
                if len == 0 {
                    return;
                }
                let next = (self.seg_idx as isize + delta).clamp(0, len as isize - 1) as usize;
                self.seg_idx = next;
                self.seg_state.select(Some(next));
            }
            DbTuiTab::StagedReplay => {}
        }
    }

    /// Starts chain verification. Without an archive directory it checks the in-memory segments at once; otherwise the
    /// directory is verified on a background thread and the result is applied by [`Self::poll_job`].
    pub fn start_verify(&mut self) {
        let Some(dir) = self.archive_dir.clone() else {
            let valid = !self.segments.is_empty() && self.segments.iter().all(|s| s.integrity_ok);
            self.stats.cold_chain_valid = valid;
            self.set_banner(if valid {
                format!(
                    "Verified {} in-memory segment(s) — SHA-256 chain OK",
                    self.segments.len()
                )
            } else {
                "Chain verification FAILED (no archive directory)".to_string()
            });
            return;
        };
        self.spawn_job("Verifying archive chain…", move || {
            ArchiveJob::Verify(verify_archive_dir_streaming(&dir, None).map_err(|e| e.to_string()))
        });
    }

    /// Starts the 4-stage replay on a background thread; the result is applied by [`Self::poll_job`].
    pub fn start_replay(&mut self) {
        let Some(dir) = self.archive_dir.clone() else {
            self.set_banner("No cold archive directory loaded to replay");
            return;
        };
        if self.segments.is_empty() {
            self.set_banner("No cold archive segments loaded to replay");
            return;
        }
        self.spawn_job("Replaying cold archive…", move || {
            ArchiveJob::Replay(staged_replay_dir_streaming(&dir, None).map_err(|e| e.to_string()))
        });
    }

    fn spawn_job(&mut self, running: &str, job: impl FnOnce() -> ArchiveJob + Send + 'static) {
        if self.pending_job.is_some() {
            self.set_banner("A verify/replay job is already running");
            return;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            // A closed receiver only means the TUI exited first; the result is no longer needed.
            let _ = tx.send(job());
        });
        self.pending_job = Some(rx);
        self.set_banner(running);
    }

    /// Applies the background job's result once it is ready; call it on every UI tick.
    pub fn poll_job(&mut self) {
        let Some(rx) = self.pending_job.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(job) => {
                self.pending_job = None;
                self.apply_job(job);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pending_job = None;
                self.set_banner("Background job ended without a result");
            }
        }
    }

    /// Applies a finished job to the state (split from [`Self::poll_job`] so tests need no thread).
    pub fn apply_job(&mut self, job: ArchiveJob) {
        match job {
            ArchiveJob::Verify(Ok((rep, metas))) => {
                self.segments = metas;
                if self.seg_idx >= self.segments.len() {
                    self.seg_idx = 0;
                    self.seg_state
                        .select((!self.segments.is_empty()).then_some(0));
                }
                self.stats.cold_chain_valid = true;
                self.stats.cold_segments_count = rep.segments_verified;
                self.stats.cold_events_count = rep.total_events;
                self.stats.cold_max_offset = rep.max_offset;
                self.set_banner(format!(
                    "Verified {} segment(s), {} signed, {} events — SHA-256 chain OK",
                    rep.segments_verified, rep.signed_segments, rep.total_events
                ));
            }
            ArchiveJob::Verify(Err(e)) => {
                self.stats.cold_chain_valid = false;
                self.set_banner(format!("Chain verification FAILED: {e}"));
            }
            ArchiveJob::Replay(Ok(rep)) => {
                let acs = rep.active_contracts_count;
                let off = rep.up_to_offset;
                let status = if rep.is_partial {
                    format!("PARTIAL from #{}", rep.from_offset)
                } else {
                    "complete".to_string()
                };
                self.replay_report = Some(rep);
                self.tab = DbTuiTab::StagedReplay;
                self.set_banner(format!(
                    "4-Stage Replay ({status}) up to offset #{off} ({acs} active contracts)"
                ));
            }
            ArchiveJob::Replay(Err(e)) => {
                self.set_banner(format!("Replay failed: {e}"));
            }
        }
    }

    pub fn open_selected_detail(&mut self) {
        match self.tab {
            DbTuiTab::Tables => {
                if let Some(t) = self.stats.tables.get(self.table_idx) {
                    let body = format!(
                        "Table Name : {}\n\
                         Category   : {}\n\
                         Approx Rows: {}\n\
                         Disk Size  : {} ({} bytes)\n\
                         Ledger End : #{}\n\
                         Pruned UpTo: #{}\n\n\
                         [Esc / Enter] Close",
                        t.table_name,
                        t.category,
                        t.row_count,
                        format_bytes(t.total_bytes),
                        t.total_bytes,
                        self.stats.ledger_end,
                        self.stats.pruned_up_to,
                    );
                    self.detail_modal = Some((format!(" Table: {} ", t.table_name), body, 0));
                }
            }
            DbTuiTab::ColdSegments => {
                if let Some(s) = self.segments.get(self.seg_idx) {
                    let valid = s.integrity_ok;
                    let body = format!(
                        "Segment Range : [{} ..= {}] ({} event(s))\n\
                         Synchronizer  : {}\n\
                         Participant   : {}\n\
                         Integrity     : {}\n\
                         Segment SHA256: {}\n\
                         Prev SHA256   : {}\n\
                         ACS Root Hash : {}\n\
                         Signer PubKey : {}\n\
                         Ed25519 Sig   : {}\n\n\
                         [Esc / Enter] Close   [↑/↓] Scroll",
                        s.from_offset,
                        s.to_offset,
                        s.events_count,
                        s.synchronizer_id,
                        s.participant_id,
                        if valid {
                            "● VERIFIED"
                        } else {
                            "✖ CORRUPTED"
                        },
                        s.segment_sha256,
                        s.prev_segment_sha256.as_deref().unwrap_or("(GENESIS)"),
                        s.acs_state_root_sha256,
                        s.signer_public_key_hex.as_deref().unwrap_or("(unsigned)"),
                        s.ed25519_signature_hex.as_deref().unwrap_or("(unsigned)"),
                    );
                    self.detail_modal = Some((
                        format!(" Cold Segment [{}..={}] ", s.from_offset, s.to_offset),
                        body,
                        0,
                    ));
                }
            }
            DbTuiTab::StagedReplay => {}
        }
    }
}

/// Launches the interactive `canton-rs db tui` full-screen inspector.
pub fn run_db_tui(
    source_label: String,
    archive_dir: Option<&Path>,
    stats: StorageOverviewStats,
    segments: Vec<ColdArchiveSegmentMeta>,
    initial_replay: Option<StagedReplayReport>,
) -> Result<(), String> {
    if !io::stdout().is_terminal() {
        eprintln!("canton-rs db tui requires an interactive TTY; use 'canton-rs db stats' instead");
        std::process::exit(2);
    }

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

    let mut app = DbTuiState::new(
        source_label,
        archive_dir.map(Path::to_path_buf),
        stats,
        segments,
        initial_replay,
    );

    loop {
        app.poll_job();
        if let Some((_, ts)) = &app.banner {
            // The "running" banner stays until the background job reports back.
            if app.pending_job.is_none() && ts.elapsed() > Duration::from_secs(4) {
                app.banner = None;
            }
        }
        terminal
            .draw(|f| render_db_tui(f, &mut app))
            .map_err(|e| e.to_string())?;

        let Some(key) = read_key_timeout(150) else {
            continue;
        };
        if handle_db_key(&mut app, key) {
            break;
        }
    }
    Ok(())
}

/// Processes a single key event; returns `true` when the user exits (`q` / `Ctrl+C`).
pub fn handle_db_key(app: &mut DbTuiState, key: Key) -> bool {
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
    if let Some((_, _, ref mut scroll)) = app.detail_modal {
        match key {
            Key::Esc | Key::Enter | Key::Char('q') => app.detail_modal = None,
            Key::Up | Key::Char('k') => *scroll = scroll.saturating_sub(1),
            Key::Down | Key::Char('j') => *scroll = scroll.saturating_add(1),
            _ => {}
        }
        return false;
    }

    match key {
        Key::Char('q') | Key::Esc => return true,
        Key::Char('?') | Key::Char('h') => app.help_modal = true,
        Key::Tab | Key::Right => app.tab = app.tab.next(),
        Key::BackTab | Key::Left => app.tab = app.tab.prev(),
        Key::Char('1') => app.tab = DbTuiTab::Tables,
        Key::Char('2') => app.tab = DbTuiTab::ColdSegments,
        Key::Char('3') => app.tab = DbTuiTab::StagedReplay,
        Key::Up | Key::Char('k') => app.move_selection(-1),
        Key::Down | Key::Char('j') => app.move_selection(1),
        Key::PageUp => app.move_selection(-8),
        Key::PageDown => app.move_selection(8),
        Key::Enter | Key::Char('i') => app.open_selected_detail(),
        Key::Char('v') => app.start_verify(),
        Key::Char('r') => app.start_replay(),
        _ => {}
    }
    false
}

/// Renders the complete theme-safe `canton-rs db tui` frame.
pub fn render_db_tui(frame: &mut Frame<'_>, app: &mut DbTuiState) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let chain_badge = if app.stats.cold_chain_valid {
        "Chain: ● OK"
    } else {
        "Chain: ✖ INVALID"
    };
    let banner_str = app
        .banner
        .as_ref()
        .map(|(m, _)| format!(" | {m}"))
        .unwrap_or_default();
    let header_line = Line::from(vec![
        Span::styled(
            " canton-rs db tui ",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "{} | End: #{} | Pruned: #{} | DB: {} | Cold Segs: {} ({chain_badge}){banner_str}",
                app.source_label,
                app.stats.ledger_end,
                app.stats.pruned_up_to,
                format_bytes(app.stats.total_db_bytes),
                app.segments.len(),
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
    for (idx, t) in DbTuiTab::ALL.iter().enumerate() {
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
        DbTuiTab::Tables => render_tables_tab(frame, outer[2], app),
        DbTuiTab::ColdSegments => render_segments_tab(frame, outer[2], app),
        DbTuiTab::StagedReplay => render_replay_tab(frame, outer[2], app),
    }

    let footer = Line::from(Span::styled(
        " [↑/↓] Select  [1-3/Tab] Switch Tab  [Enter/i] Detail  [v] Verify Chain  [r] Staged Replay  [?] Help  [q] Quit ",
        normal_text_style().add_modifier(Modifier::REVERSED),
    ));
    frame.render_widget(Paragraph::new(footer), outer[3]);

    if app.help_modal {
        render_db_help_modal(frame);
    } else if let Some((title, body, scroll)) = &app.detail_modal {
        let area = centered_rect(80, 18, frame.area());
        frame.render_widget(Clear, area);
        let block = Block::default()
            .title(title.clone())
            .borders(Borders::ALL)
            .border_style(panel_border_style(true));
        frame.render_widget(
            Paragraph::new(body.clone())
                .style(normal_text_style())
                .block(block)
                .scroll((*scroll, 0))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

fn render_tables_tab(frame: &mut Frame<'_>, area: Rect, app: &mut DbTuiState) {
    if app.stats.tables.is_empty() {
        let msg = format!(
            "No PostgreSQL connection provided (offline cold-archive mode).\n\
             Cold Archive Segments loaded: {} ({} total events).\n\
             Press [2] or [Tab] to inspect Cold Archive Segments, or [r] to run 4-Stage Replay.",
            app.segments.len(),
            app.stats.cold_events_count
        );
        frame.render_widget(
            Paragraph::new(msg)
                .style(normal_text_style())
                .block(
                    Block::default()
                        .title(" PostgreSQL Storage Tables ")
                        .borders(Borders::ALL)
                        .border_style(panel_border_style(true)),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }

    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
        .split(area);

    let header = Row::new(["", "CATEGORY", "TABLE NAME", "ROWS", "DISK SIZE"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));

    let selected = app.table_idx;
    let rows: Vec<Row<'static>> = app
        .stats
        .tables
        .iter()
        .enumerate()
        .map(|(idx, t)| {
            let is_sel = idx == selected;
            let cursor = if is_sel { "▶ " } else { "  " };
            let s = normal_text_style();
            Row::new(vec![
                Line::from(Span::styled(cursor, s)),
                Line::from(Span::styled(t.category.clone(), s)),
                Line::from(Span::styled(t.table_name.clone(), s)),
                Line::from(Span::styled(t.row_count.to_string(), s)),
                Line::from(Span::styled(format_bytes(t.total_bytes), s)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(2),
        Constraint::Length(14),
        Constraint::Min(24),
        Constraint::Length(10),
        Constraint::Length(11),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(format!(
                    " PostgreSQL Tables ({} · ACTIVE) ",
                    app.stats.tables.len()
                ))
                .borders(Borders::ALL)
                .border_style(panel_border_style(true)),
        )
        .row_highlight_style(focused_selected_style());

    frame.render_stateful_widget(table, split[0], &mut app.table_state);

    let summary = format!(
        "Ledger End Offset    : #{}\n\
         Pruned Up To Offset  : #{}\n\
         Prunable Activations : {} row(s)\n\
         Prunable Deactivations: {} row(s)\n\
         Total Relation Bytes : {}\n\n\
         Cold Archive Tier\n\
         ─────────────────\n\
         Segments Stored      : {}\n\
         Archived Events      : {}\n\
         Max Archived Offset  : {:?}\n\
         Hash-Chain Status    : {}\n\n\
         Tip: Run 'canton-rs db archive --prune-after-archive'\n\
         to export cold segments before physical PG pruning.",
        app.stats.ledger_end,
        app.stats.pruned_up_to,
        app.stats.prunable_activations,
        app.stats.prunable_deactivations,
        format_bytes(app.stats.total_db_bytes),
        app.stats.cold_segments_count,
        app.stats.cold_events_count,
        app.stats.cold_max_offset,
        if app.stats.cold_chain_valid {
            "VERIFIED"
        } else {
            "BROKEN / UNVERIFIED"
        },
    );
    frame.render_widget(
        Paragraph::new(summary)
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Pruning & Cold-Tier Summary ")
                    .borders(Borders::ALL)
                    .border_style(normal_text_style()),
            )
            .wrap(Wrap { trim: false }),
        split[1],
    );
}

fn render_segments_tab(frame: &mut Frame<'_>, area: Rect, app: &mut DbTuiState) {
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(area);

    if app.segments.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "No '.crs-seg.json' segments found in --archive-dir.\n\
                 Create segments via:\n\
                 canton-rs db archive --archive-dir ./cold-archive --up-to-offset 100",
            )
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Cold Archive Segments (0) ")
                    .borders(Borders::ALL)
                    .border_style(panel_border_style(true)),
            )
            .wrap(Wrap { trim: false }),
            split[0],
        );
        frame.render_widget(
            Paragraph::new("Select a segment to inspect its SHA-256 chain & Ed25519 signature.")
                .style(normal_text_style())
                .block(
                    Block::default()
                        .title(" Segment Cryptographic Proof ")
                        .borders(Borders::ALL)
                        .border_style(normal_text_style()),
                ),
            split[1],
        );
        return;
    }

    let header = Row::new(["", "OFFSETS", "EVENTS", "SIG", "SEGMENT SHA-256"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));

    let selected = app.seg_idx;
    let rows: Vec<Row<'static>> = app
        .segments
        .iter()
        .enumerate()
        .map(|(idx, seg)| {
            let is_sel = idx == selected;
            let cursor = if is_sel { "▶ " } else { "  " };
            let ok = seg.integrity_ok;
            let (glyph, gcol) = if ok {
                ("●", Color::LightGreen)
            } else {
                ("✖", Color::LightRed)
            };
            let s = normal_text_style();
            let short_sha: String = seg.segment_sha256.chars().take(16).collect();
            let signed = if seg.ed25519_signature_hex.is_some() {
                "Ed25519"
            } else {
                "SHA256"
            };
            Row::new(vec![
                Line::from(vec![
                    Span::styled(cursor, s),
                    glyph_span(glyph, gcol, is_sel),
                ]),
                Line::from(Span::styled(
                    format!("{}..={}", seg.from_offset, seg.to_offset),
                    s,
                )),
                Line::from(Span::styled(seg.events_count.to_string(), s)),
                Line::from(Span::styled(signed, s)),
                Line::from(Span::styled(short_sha, s)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Length(14),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Min(16),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(format!(
                    " Cold Archive Segments ({} · ACTIVE) ",
                    app.segments.len()
                ))
                .borders(Borders::ALL)
                .border_style(panel_border_style(true)),
        )
        .row_highlight_style(focused_selected_style());

    frame.render_stateful_widget(table, split[0], &mut app.seg_state);

    let detail = if let Some(seg) = app.segments.get(app.seg_idx) {
        let valid = seg.integrity_ok;
        let signed = seg.ed25519_signature_hex.is_some();
        format!(
            "Offset Window : #{} ..= #{}\n\
             Synchronizer  : {}\n\
             Participant   : {}\n\
             Events        : {}\n\
             Integrity     : {}\n\
             Segment Hash  : {}\n\
             Prev Hash     : {}\n\
             ACS Root      : {}\n\
             Signer PubKey : {}\n\n\
             [v] Verify Full Chain   [r] Run 4-Stage Replay\n\
             [Enter] Full Signature Modal",
            seg.from_offset,
            seg.to_offset,
            seg.synchronizer_id,
            seg.participant_id,
            seg.events_count,
            if !valid {
                "CORRUPTED"
            } else if signed {
                "VERIFIED (SHA-256 + Ed25519)"
            } else {
                "VERIFIED (SHA-256 integrity only, unsigned)"
            },
            &seg.segment_sha256[..seg.segment_sha256.len().min(32)],
            seg.prev_segment_sha256
                .as_deref()
                .map(|h| &h[..h.len().min(32)])
                .unwrap_or("(GENESIS)"),
            &seg.acs_state_root_sha256[..seg.acs_state_root_sha256.len().min(32)],
            seg.signer_public_key_hex
                .as_deref()
                .map(|h| &h[..h.len().min(32)])
                .unwrap_or("(none)"),
        )
    } else {
        String::from("No segment selected.")
    };

    frame.render_widget(
        Paragraph::new(detail)
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Segment Cryptographic Proof ")
                    .borders(Borders::ALL)
                    .border_style(normal_text_style()),
            )
            .wrap(Wrap { trim: false }),
        split[1],
    );
}

fn render_replay_tab(frame: &mut Frame<'_>, area: Rect, app: &DbTuiState) {
    let body = match &app.replay_report {
        Some(rep) => {
            let mut stage_lines = String::new();
            for st in &rep.stages {
                stage_lines.push_str(&format!(
                    "  • {:<28} {:>7} us   ({} items)\n",
                    st.stage, st.elapsed_us, st.items_processed
                ));
            }
            let mut tmpl_lines = String::new();
            for (tmpl, cnt) in &rep.template_histogram {
                tmpl_lines.push_str(&format!("  • {tmpl}: {cnt} event(s)\n"));
            }
            if tmpl_lines.is_empty() {
                tmpl_lines.push_str("  (no template events)\n");
            }
            let scope_line = if rep.is_partial {
                format!("PARTIAL (from offset #{}; earlier contracts missing)", rep.from_offset)
            } else {
                format!("COMPLETE (from offset #{})", rep.from_offset)
            };
            format!(
                "Replay Scope           : {}\n\
                 Replayed Segments      : {}\n\
                 Replayed Events        : {} (up to offset #{})\n\
                 Active Contracts (ACS) : {}\n\
                 ACS State SHA-256      : {} (self-hash)\n\n\
                 Pipeline Stage Timings (4-Stage Deterministic Sync)\n\
                 ───────────────────────────────────────────────────\n\
                 {}\n\
                 Template Surface Histogram\n\
                 ──────────────────────────\n\
                 {}\n\
                 Press [r] to re-execute deterministic 4-stage replay.",
                scope_line,
                rep.replayed_segments,
                rep.replayed_events,
                rep.up_to_offset,
                rep.active_contracts_count,
                rep.acs_commitment_sha256,
                stage_lines,
                tmpl_lines,
            )
        }
        None => String::from(
            "No replay executed yet.\n\
             Load cold archive segments (--archive-dir) and press [r] to run 4-stage deterministic replay.",
        ),
    };

    frame.render_widget(
        Paragraph::new(body)
            .style(normal_text_style())
            .block(
                Block::default()
                    .title(" Deterministic 4-Stage Cold Archive Replay ")
                    .borders(Borders::ALL)
                    .border_style(panel_border_style(true)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_db_help_modal(frame: &mut Frame<'_>) {
    let area = centered_rect(72, 16, frame.area());
    frame.render_widget(Clear, area);
    let help = "\
Navigation & Tabs
  ↑ / ↓ or j / k   Move row selection (theme-safe reverse-video bar)
  1 / 2 / 3        Jump to PG Tables / Cold Segments / 4-Stage Replay
  Tab / ← / →      Cycle tabs
  Enter or i       Open full cryptographic / table detail modal

Verification & Replay
  v                Reload & verify SHA-256 hash chain + Ed25519 signatures
  r                Execute 4-stage deterministic ACS catch-up replay
  ? or h           Toggle this help modal
  q or Esc         Exit TUI";
    let block = Block::default()
        .title(" canton-rs db tui — Keyboard Shortcuts ")
        .borders(Borders::ALL)
        .border_style(panel_border_style(true));
    frame.render_widget(
        Paragraph::new(help).style(normal_text_style()).block(block),
        area,
    );
}

fn centered_rect(percent_w: u16, height: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height.min(area.height)),
            Constraint::Fill(1),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_w) / 2),
            Constraint::Percentage(percent_w),
            Constraint::Percentage((100 - percent_w) / 2),
        ])
        .split(v[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_participant::cold_archive::{
        build_cold_segment, hash_payload_json, staged_replay, BuildSegmentSpec, ColdArchiveEvent,
        ColdArchiveEventKind, ColdArchiveSourceKind, StorageTableStat,
    };
    use ratatui_core::backend::TestBackend;
    use std::collections::BTreeSet;

    #[test]
    fn renders_all_three_db_tui_tabs_without_hardcoded_backgrounds() {
        let seg = build_cold_segment(BuildSegmentSpec {
            synchronizer_id: "sync-1",
            participant_id: "p1",
            source_kind: Some(ColdArchiveSourceKind::Jsonl),
            from_offset: 1,
            to_offset: 2,
            prev_segment_sha256: None,
            events: vec![ColdArchiveEvent {
                offset: 1,
                update_id: "u1".into(),
                synchronizer_id: "sync-1".into(),
                record_time_micros: 1_000,
                kind: ColdArchiveEventKind::Activate,
                contract_id: "00aa".into(),
                template_id: "Asset:Holding".into(),
                stakeholders: BTreeSet::from(["Alice".to_string()]),
                payload_json: None,
                payload_sha256: hash_payload_json(None),
            }],
            signing_key_bytes: Some(&[5u8; 32]),
        })
        .expect("segment");

        let stats = StorageOverviewStats {
            ledger_end: 10,
            pruned_up_to: 2,
            prunable_activations: 1,
            prunable_deactivations: 1,
            total_db_bytes: 65536,
            tables: vec![StorageTableStat {
                category: "Ledger API".into(),
                table_name: "lapi_events_activate_contract".into(),
                row_count: 42,
                total_bytes: 32768,
            }],
            cold_segments_count: 1,
            cold_events_count: 1,
            cold_max_offset: Some(2),
            cold_chain_valid: true,
        };

        let meta = ColdArchiveSegmentMeta::from_segment(&seg, true);
        let replay = staged_replay(std::slice::from_ref(&seg), None).ok();
        let mut app = DbTuiState::new(
            "127.0.0.1:5432/canton".into(),
            None,
            stats,
            vec![meta],
            replay,
        );
        let backend = TestBackend::new(124, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");

        for tab in DbTuiTab::ALL {
            app.tab = tab;
            terminal
                .draw(|f| render_db_tui(f, &mut app))
                .expect("draw tab");
            let buf = terminal.backend().buffer();
            for cell in buf.content() {
                assert_eq!(
                    cell.bg,
                    Color::Reset,
                    "db tui must remain 100% theme-safe (Color::Reset bg)"
                );
            }
        }
    }

    fn empty_stats() -> StorageOverviewStats {
        StorageOverviewStats {
            ledger_end: 0,
            pruned_up_to: 0,
            prunable_activations: 0,
            prunable_deactivations: 0,
            total_db_bytes: 0,
            tables: Vec::new(),
            cold_segments_count: 0,
            cold_events_count: 0,
            cold_max_offset: None,
            cold_chain_valid: true,
        }
    }

    fn wait_for_job(app: &mut DbTuiState) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while app.pending_job.is_some() {
            assert!(
                Instant::now() < deadline,
                "background job never reported back"
            );
            std::thread::sleep(Duration::from_millis(5));
            app.poll_job();
        }
    }

    #[test]
    fn verify_key_returns_before_the_archive_job_finishes_and_applies_its_result_later() {
        let missing =
            std::env::temp_dir().join(format!("db-tui-u55-missing-{}", std::process::id()));
        let mut app = DbTuiState::new("x".into(), Some(missing), empty_stats(), Vec::new(), None);

        assert!(!handle_db_key(&mut app, Key::Char('v')));
        assert!(
            app.pending_job.is_some(),
            "'v' must hand the verification to a background job"
        );
        assert!(app
            .banner
            .as_ref()
            .is_some_and(|(m, _)| m.starts_with("Verifying")));

        wait_for_job(&mut app);
        let (msg, _) = app.banner.as_ref().expect("result banner");
        assert!(
            msg.starts_with("Verified") || msg.starts_with("Chain verification FAILED"),
            "the job's result must replace the running banner, got: {msg}"
        );
    }

    #[test]
    fn a_second_job_is_refused_while_one_is_running() {
        let mut app = DbTuiState::new("x".into(), None, empty_stats(), Vec::new(), None);
        let (release, gate) = mpsc::channel::<()>();
        app.spawn_job("Replaying cold archive…", move || {
            let _ = gate.recv();
            ArchiveJob::Replay(Err("stopped by the test".into()))
        });
        app.archive_dir = Some(std::env::temp_dir());

        assert!(!handle_db_key(&mut app, Key::Char('v')));
        assert!(app
            .banner
            .as_ref()
            .is_some_and(|(m, _)| m.contains("already running")));

        release.send(()).expect("release the job");
        wait_for_job(&mut app);
        assert!(app
            .banner
            .as_ref()
            .is_some_and(|(m, _)| m == "Replay failed: stopped by the test"));
    }
}
