//! Specialized Protocol X-Ray, 4-layer NodeInspection, and interactive modal views.

use ratatui_core::layout::{Constraint, Direction, Layout, Rect};
use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::terminal::Frame;
use ratatui_core::text::{Line, Span};
use ratatui_widgets::block::Block;
use ratatui_widgets::borders::Borders;
use ratatui_widgets::clear::Clear;
use ratatui_widgets::paragraph::{Paragraph, Wrap};
use ratatui_widgets::table::{Row, Table};

use super::super::{format_bytes, NodeInspection, VoteStatus, XRayTraceEvent};
use super::state::{ConfirmAction, DashboardState, PanelFocus};
use super::theme::{
    focused_selected_style, glyph_span, normal_text_style, panel_border_style,
    unfocused_selected_style, verdict_badge,
};

/// Renders the interactive `RootHash` trace table and 4-Hop 2PC quorum detail workspace tab.
pub fn render_xray_tab(frame: &mut Frame<'_>, area: Rect, app: &mut DashboardState) {
    let is_focused = app.focus == PanelFocus::Workspace;
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);

    let trace_count = app.xray_traces.len();
    let active_tag = if is_focused { " · ACTIVE" } else { "" };
    let list_title = format!(
        " X-Ray Traces ({trace_count}{active_tag}) — ↑/↓ select RootHash, Enter full modal "
    );

    if trace_count == 0 {
        let empty = Paragraph::new(
            "Waiting for blinded transaction metadata (backfilling recent participant traces)...\n\
             Submit a Daml tx to see 4-Hop pipeline; zero contract arguments leave ZERO-KNOWLEDGE BOUNDARY.",
        )
        .style(normal_text_style())
        .block(
            Block::default()
                .title(list_title)
                .borders(Borders::ALL)
                .border_style(panel_border_style(is_focused)),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(empty, split[0]);
    } else {
        let max_idx = trace_count - 1;
        if app.xray_selected_idx > max_idx {
            app.xray_selected_idx = max_idx;
        }
        app.xray_table_state.select(Some(app.xray_selected_idx));

        let header = Row::new(["", "ROOT HASH", "SUBMITTER", "TEMPLATE", "MS", "VERDICT"])
            .style(normal_text_style().add_modifier(Modifier::BOLD));

        let selected_idx = app.xray_selected_idx;
        let rows: Vec<Row<'static>> = app
            .xray_traces
            .iter()
            .rev()
            .enumerate()
            .map(|(idx, t)| {
                let (glyph, verdict_label, glyph_color) = verdict_badge(t.mediator_verdict);
                let is_selected = idx == selected_idx;
                let solid_selected = is_focused && is_selected;
                let cursor = if !is_selected {
                    "  "
                } else if is_focused {
                    "▶ "
                } else {
                    "▸ "
                };
                let short_hash: String = t.root_hash.chars().take(16).collect();
                let tmpl = t
                    .template_qualified_name
                    .as_deref()
                    .map(|s| s.rsplit(':').next().unwrap_or(s))
                    .unwrap_or("-");
                let cell_style = normal_text_style();
                Row::new(vec![
                    Line::from(vec![
                        Span::styled(cursor, cell_style),
                        glyph_span(glyph, glyph_color, solid_selected),
                    ]),
                    Line::from(Span::styled(short_hash, cell_style)),
                    Line::from(Span::styled(t.submitter_participant.clone(), cell_style)),
                    Line::from(Span::styled(tmpl.to_string(), cell_style)),
                    Line::from(Span::styled(
                        format!("{:.1}", t.total_latency_ms),
                        cell_style,
                    )),
                    Line::from(Span::styled(verdict_label, cell_style)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(3),
            Constraint::Length(17),
            Constraint::Length(13),
            Constraint::Min(14),
            Constraint::Length(7),
            Constraint::Fill(1),
        ];
        let highlight_style = if is_focused {
            focused_selected_style()
        } else {
            unfocused_selected_style()
        };

        let table = Table::new(rows, widths)
            .header(header)
            .column_spacing(1)
            .block(
                Block::default()
                    .title(list_title)
                    .borders(Borders::ALL)
                    .border_style(panel_border_style(is_focused)),
            )
            .row_highlight_style(highlight_style);

        frame.render_stateful_widget(table, split[0], &mut app.xray_table_state);
    }

    render_xray_4hop_detail(frame, split[1], app);
}

fn render_xray_4hop_detail(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let detail_block = Block::default()
        .title(format!(
            " 4-Hop Detail (dropped: {}) [ZERO-KNOWLEDGE BOUNDARY: SEALED] ",
            app.snapshot.wiretap_dropped_events
        ))
        .borders(Borders::ALL)
        .border_style(panel_border_style(false));

    let Some(trace) = app.selected_xray_trace() else {
        frame.render_widget(
            Paragraph::new("Select a RootHash above to inspect its 4-Hop 2PC quorum pipeline.")
                .style(normal_text_style())
                .block(detail_block)
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    let (glyph, verdict_label, glyph_color) = verdict_badge(trace.mediator_verdict);
    let mut lines: Vec<Line<'_>> = vec![
        Line::from(vec![
            Span::styled(
                format!(
                    "RootHash (participant estimate): {} | Total: {:.2}ms | Verdict: ",
                    trace.root_hash, trace.total_latency_ms
                ),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
            glyph_span(glyph, glyph_color, false),
            Span::styled(
                format!(" {verdict_label}"),
                normal_text_style().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!(
                "[1. Participant] {} | pkg: {} | tmpl: {} | eval: {}us | {} view(s)",
                trace.submitter_participant,
                trace.package_id,
                trace.template_qualified_name.as_deref().unwrap_or("-"),
                trace.daml_eval_us,
                trace.blinded_view_count,
            ),
            normal_text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "[2. Sequencer]   envelope: [SEALED {} B, participant estimate] | traffic: -{} B | recipients: {} (est.)",
                trace.sealed_envelope_bytes, trace.traffic_cost_bytes, trace.recipient_member_count,
            ),
            normal_text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "[3. BFT Orderer] block: {} | order_finality: {}",
                trace
                    .bft_block_height
                    .map_or_else(|| "single-node".into(), |h| format!("#{h}")),
                trace
                    .bft_order_latency_ms
                    .map_or_else(|| "-".into(), |ms| format!("{ms:.2}ms")),
            ),
            normal_text_style(),
        )),
    ];

    if trace.views.is_empty() {
        lines.push(Line::from(Span::styled(
            "[4. Mediator 2PC] (no sub-transaction informee views recorded)",
            normal_text_style(),
        )));
    } else {
        for (idx, view) in trace.views.iter().enumerate() {
            let votes: Vec<String> = view
                .informees
                .iter()
                .map(|inf| match &inf.vote {
                    VoteStatus::Approved { latency_ms } => {
                        format!("{} (Approve {:.1}ms)", inf.party_id, latency_ms)
                    }
                    VoteStatus::Rejected { code } => format!("{} (Reject: {})", inf.party_id, code),
                    VoteStatus::Pending { elapsed_ms } => {
                        format!("{} (Pending {:.0}ms)", inf.party_id, elapsed_ms)
                    }
                })
                .collect();
            let prefix = if idx == 0 {
                "[4. Mediator 2PC]"
            } else {
                "                 "
            };
            lines.push(Line::from(Span::styled(
                format!(
                    "{prefix} View #{} ({}) [thr={}]: {}",
                    idx + 1,
                    view.view_hash,
                    view.threshold,
                    votes.join(", ")
                ),
                normal_text_style(),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Renders the masked 4-layer `NodeInspection` view for the selected sidebar service.
pub fn render_inspect_tab(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let selected_name = app.selected_node().map(|n| n.name.as_str()).unwrap_or("-");
    let matching_insp = app
        .inspect_cache
        .as_ref()
        .filter(|insp| insp.name == selected_name);

    let Some(insp) = matching_insp else {
        frame.render_widget(
            Paragraph::new(format!(
                "No cached 4-layer inspection for '{selected_name}'.\n\
                 Press [i] or [Enter] to fetch live NodeInspection via daemon IPC."
            ))
            .style(normal_text_style())
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    let body = format_inspection_body(insp);
    frame.render_widget(
        Paragraph::new(body)
            .style(normal_text_style())
            .scroll((app.inspect_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Renders the `[c] ExEx & Cold` tab showing live `CantonExEx` (`GET /_exex`) subscribers and
/// immutable Cold Archive SHA-256/Ed25519 segment status.
pub fn render_exex_cold_tab(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let body = match &app.exex_cold_cache {
        Some((exex_nodes, cold)) => {
            let mut exex_text = String::new();
            if exex_nodes.is_empty() {
                exex_text.push_str(
                    "  (no participant HTTP JSON ports configured in this cluster manifest)\n",
                );
            } else {
                for node in exex_nodes {
                    let status = if node.reachable { "ONLINE" } else { "OFFLINE" };
                    exex_text.push_str(&format!(
                        "  • {} (127.0.0.1:{}/_exex · {status}) — {} active ExEx subscriber(s)\n",
                        node.node_name, node.port, node.active_subscribers
                    ));
                    if node.subscriber_lines.is_empty() {
                        exex_text.push_str(
                            "      0% idle overhead (attach via --exex-jsonl / CantonNodeBuilder::install_exex)\n",
                        );
                    } else {
                        for line in &node.subscriber_lines {
                            exex_text.push_str(&format!("      - {line}\n"));
                        }
                    }
                }
            }

            let chain_state = if cold.segments_count == 0 {
                "EMPTY (no .crs-seg.json files yet)"
            } else if cold.chain_valid {
                "VERIFIED (SHA-256 hash chain + Ed25519 intact)"
            } else {
                "CORRUPTED / INVALID"
            };
            format!(
                "CantonExEx — Privacy-Scoped In-Process Execution Extensions\n\
                 ───────────────────────────────────────────────────────────\n\
                 {}\n\
                 Cold Archive Tier — Pre-Prune Immutable Segments (.crs-seg.json)\n\
                 ────────────────────────────────────────────────────────────────\n\
                   Archive Directory   : {}\n\
                   Segments Verified   : {} ({} Ed25519-signed)\n\
                   Archived Events     : {} (max offset: {:?})\n\
                   Chain Integrity     : {}\n\
                   Head Segment SHA256 : {}\n\n\
                 Standalone Inspectors : 'canton-rs db tui --archive-dir <DIR>' | 'canton-rs dpm tui <DAR>'\n\
                 [c] Refresh ExEx & Cold Archive   [Tab/2 + ↑/↓] Scroll",
                exex_text,
                cold.archive_dir.display(),
                cold.segments_count,
                cold.signed_count,
                cold.events_count,
                cold.max_offset,
                chain_state,
                cold.head_sha256.as_deref().unwrap_or("-"),
            )
        }
        None => String::from(
            "Press [c] to query live CantonExEx (/_exex) endpoints and Cold Archive chain status.",
        ),
    };

    frame.render_widget(
        Paragraph::new(body)
            .style(normal_text_style())
            .scroll((app.exex_cold_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn format_inspection_body(insp: &NodeInspection) -> String {
    format!(
        "Node         : {} ({}) | PID: {:?} | State: {}\n\
         Config       : {}\n\
         Bootstrap    : {}\n\
         State Dir    : {}\n\
         Log File     : {} ({}, {} gen, encoder={})\n\
         PortOffset   : {} | Argv: {}\n\
         Config Check : {} applied | not_applied: {}\n\
         Storage      : {} (same_identity={}, official_write={})\n\
         Auth Mode    : {}\n\
         Node UID     : {}\n\
         Sync ID      : {} (protocol={})\n\
         DARs ({})    : {}\n\
         Parties ({}) : {}\n\
         Users        : {:?}\n\
         Ports        : {}\n\
         Faults       : restarts={}, last_exit_reason={}\n\
         \n[Tab/2 + ↑/↓] Scroll   [i] Refresh",
        insp.name,
        insp.role,
        insp.pid,
        insp.state.display_label(),
        insp.config_path.as_deref().unwrap_or("-"),
        insp.bootstrap_path.as_deref().unwrap_or("-"),
        insp.state_dir,
        insp.log_file_path,
        format_bytes(insp.log_file_bytes),
        insp.log_generations,
        insp.log_encoder,
        insp.port_offset,
        insp.sanitized_argv.join(" "),
        insp.config_applied_count,
        if insp.config_not_applied_keys.is_empty() {
            "-".to_string()
        } else {
            insp.config_not_applied_keys.join(", ")
        },
        insp.storage_summary,
        insp.same_identity,
        insp.official_write,
        insp.auth_mode,
        insp.node_uid.as_deref().unwrap_or("-"),
        insp.physical_synchronizer_id.as_deref().unwrap_or("-"),
        insp.protocol_version.as_deref().unwrap_or("-"),
        insp.loaded_dars.len(),
        insp.loaded_dars
            .iter()
            .map(|d| d.main_package_id.chars().take(12).collect::<String>())
            .collect::<Vec<_>>()
            .join(", "),
        insp.hosted_parties.len(),
        insp.hosted_parties.join(", "),
        insp.user_count,
        insp.ports.summary(),
        insp.restarts_total,
        insp.last_exit_reason.as_deref().unwrap_or("-"),
    )
}

/// Renders the scrollable full-detail modal for a selected Protocol X-Ray trace.
pub fn render_xray_modal(frame: &mut Frame<'_>, trace: &XRayTraceEvent, scroll: u16) {
    let area = centered_rect(84, 21, frame.area());
    frame.render_widget(Clear, area);
    let mut views_text = String::new();
    for v in &trace.views {
        let votes: Vec<String> = v
            .informees
            .iter()
            .map(|inf| match &inf.vote {
                VoteStatus::Approved { latency_ms } => {
                    format!("{} -> Approve ({latency_ms:.2}ms)", inf.party_id)
                }
                VoteStatus::Rejected { code } => format!("{} -> Reject ({code})", inf.party_id),
                VoteStatus::Pending { elapsed_ms } => {
                    format!("{} -> Pending ({elapsed_ms:.0}ms)", inf.party_id)
                }
            })
            .collect();
        views_text.push_str(&format!(
            "  - {} (threshold={}): {}\n",
            v.view_hash,
            v.threshold,
            votes.join(", ")
        ));
    }
    if views_text.is_empty() {
        views_text.push_str("  (no informee views recorded)\n");
    }
    let body = format!(
        "Boundary    : ZERO-KNOWLEDGE BOUNDARY: SEALED (0 bytes contract payload)\n\
         RootHash    : {} (participant estimate)\n\
         Verdict     : {:?} | Total Latency: {:.2} ms\n\
         \n\
         [1. Participant]\n\
           Submitter : {}\n\
           Package   : {}\n\
           Template  : {}\n\
           Daml Eval : {} us | Blinded Views: {}\n\
         \n\
         [2. Sequencer]\n\
           Envelope  : [SEALED {} B, participant estimate] | Traffic Cost: -{} B | Recipients: {} (est.)\n\
         \n\
         [3. BFT Orderer]\n\
           Block     : {} | Finality: {}\n\
         \n\
         [4. Mediator 2PC Quorum Tree]\n\
         {}\n\
         [Esc / Enter / i] Close   [↑/↓] Scroll",
        trace.root_hash,
        trace.mediator_verdict,
        trace.total_latency_ms,
        trace.submitter_participant,
        trace.package_id,
        trace.template_qualified_name.as_deref().unwrap_or("-"),
        trace.daml_eval_us,
        trace.blinded_view_count,
        trace.sealed_envelope_bytes,
        trace.traffic_cost_bytes,
        trace.recipient_member_count,
        trace
            .bft_block_height
            .map_or_else(|| "single-node".into(), |h| format!("#{h}")),
        trace
            .bft_order_latency_ms
            .map_or_else(|| "-".into(), |ms| format!("{ms:.2} ms")),
        views_text,
    );
    let block = Block::default()
        .title(" Protocol X-Ray Trace Detail [ZERO-KNOWLEDGE BOUNDARY: SEALED] ")
        .borders(Borders::ALL)
        .border_style(panel_border_style(true));
    frame.render_widget(
        Paragraph::new(body)
            .style(normal_text_style())
            .block(block)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Renders the confirmation prompt modal before Stop or Restart operations.
pub fn render_confirm_modal(frame: &mut Frame<'_>, action: &ConfirmAction) {
    let prompt = match action {
        ConfirmAction::Stop(n) => format!("Stop service '{n}'? Auto-restart will pause. [y/N]"),
        ConfirmAction::Restart(n) => format!("Restart service '{n}' now? [y/N]"),
    };
    let area = centered_rect(56, 5, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Confirm Action ")
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(
        Paragraph::new(prompt)
            .style(normal_text_style())
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Renders the keyboard shortcuts reference overlay (`?`).
pub fn render_help_modal(frame: &mut Frame<'_>) {
    let area = centered_rect(76, 20, frame.area());
    frame.render_widget(Clear, area);
    let help = "\
Navigation & Focus
  ↑/↓, j/k, PgUp/PgDn   Move selection / scroll active workspace view
  Home / End            Jump to first or last item / top or bottom of logs
  Tab / ← → / 1, 2      Switch keyboard focus between [1] Services and [2] Workspace

Workspace Tabs & Layout
  o / l / x / i / c     Overview / Logs / Protocol X-Ray (2PC) / Inspect / ExEx & Cold
  [ / ]                 Cycle workspace tabs left / right
  z                     Toggle full-screen Zoom on [2] Workspace
  Enter                 Inspect selected service (or open full modal in X-Ray)

Service Control, Group Chaos & Scenario Lab
  g / Space             Cycle Group-By (Cell -> SyncDomain -> Role -> Host -> Flat) / Fold group
  s / r                 Start/Stop slot or @group (confirm on Stop) / Restart slot or @group
  t                     Open Scenario & Load Lab (onboard parties, submit Daml tx, prove privacy)
  a / v / /             Toggle log scope (Node/Group vs All) / Level / Search
  p / e                 Run E2E Ping / Export footprint-report.md
  ? / Esc / q           Toggle help / Back out one layer / Detach TUI (daemon stays up)";

    let block = Block::default()
        .title(" canton-rs daemon top — Shortcuts ([Esc / ? / q] Close) ")
        .borders(Borders::ALL)
        .border_style(panel_border_style(true));
    frame.render_widget(
        Paragraph::new(help)
            .style(normal_text_style())
            .block(block)
            .wrap(Wrap { trim: false }),
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
