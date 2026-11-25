//! Theme-safe `lazydocker` × `btop` × `k9s` master-detail multi-tab UI renderer.

use ratatui_core::layout::{Constraint, Direction, Layout, Rect};
use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::terminal::Frame;
use ratatui_core::text::{Line, Span};
use ratatui_widgets::block::Block;
use ratatui_widgets::borders::Borders;
use ratatui_widgets::paragraph::Paragraph;
use ratatui_widgets::sparkline::Sparkline;
use ratatui_widgets::table::{Row, Table};

use super::super::{format_bytes, format_uptime, DomainMetrics, NodeLifecycleState, NodeSnapshot};
use super::groups::{
    render_scenario_modal, render_selected_group_overview, GroupByMode, SidebarEntry,
};
use super::state::{DashboardState, LogLineItem, LogScope, PanelFocus, WorkspaceTab};
use super::theme::{
    active_tab_style, focused_selected_style, glyph_span, inactive_tab_style, log_level_tag_style,
    node_status_badge, normal_text_style, panel_border_style, unfocused_selected_style,
};
use super::views::{
    render_confirm_modal, render_exex_cold_tab, render_help_modal, render_inspect_tab,
    render_xray_modal, render_xray_tab,
};

/// Renders the entire `canton-rs daemon top` dashboard plus active modal overlays.
pub fn render_dashboard(frame: &mut Frame<'_>, app: &mut DashboardState) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_header(frame, outer[0], app);

    if app.zoom_workspace {
        render_workspace(frame, outer[1], app);
    } else {
        let sidebar_w =
            (((outer[1].width as u32 * 32) / 100).clamp(30, 42) as u16).min(outer[1].width / 2);
        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(sidebar_w), Constraint::Min(1)])
            .split(outer[1]);
        render_sidebar(frame, body[0], app);
        render_workspace(frame, body[1], app);
    }

    render_footer(frame, outer[2], app);

    if app.help_modal {
        render_help_modal(frame);
    } else if app.scenario_modal.open {
        render_scenario_modal(frame, &app.scenario_modal);
    } else if let Some((trace, scroll)) = &app.xray_modal {
        render_xray_modal(frame, trace, *scroll);
    } else if let Some(action) = &app.confirm_modal {
        render_confirm_modal(frame, action);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let up = app
        .snapshot
        .nodes
        .iter()
        .filter(|n| n.state == NodeLifecycleState::Online)
        .count();
    let total = app.snapshot.nodes.len();
    let ping = app
        .snapshot
        .last_ping
        .as_ref()
        .map_or_else(|| "-".into(), |p| format!("{:.1}ms", p.rtt_ms));
    let shadow = app
        .snapshot
        .shadow_verify
        .as_ref()
        .map(|sv| match sv.match_ratio_percent {
            Some(pct) => format!(" | Shadow: {pct:.2}% Match"),
            None => " | Shadow: unknown".to_string(),
        })
        .unwrap_or_default();

    let mut spans = vec![
        Span::styled(
            " canton-rs daemon top ",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "sync: {} ({}) | {up}/{total} Up | CPU: {:.1}% | RSS: {} | Ping: {ping}{shadow}",
                app.snapshot.synchronizer,
                app.snapshot.storage_mode,
                app.snapshot.total_cpu_percent,
                format_bytes(app.snapshot.total_rss_bytes),
            ),
            normal_text_style(),
        ),
    ];

    if let Some((msg, _)) = &app.status_banner {
        spans.push(Span::styled(" | ", normal_text_style()));
        spans.push(Span::styled(
            msg.clone(),
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(normal_text_style());
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn render_sidebar(frame: &mut Frame<'_>, area: Rect, app: &mut DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(area);

    render_services_sidebar(frame, chunks[0], app);
    render_cluster_status_card(frame, chunks[1], app);
}

fn render_services_sidebar(frame: &mut Frame<'_>, area: Rect, app: &mut DashboardState) {
    let is_focused = app.focus == PanelFocus::Services;
    let header = Row::new(["", "SERVICE", "STATE", "MEM"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));

    let selected_idx = app.selected_idx;
    let entries = app.sidebar_entries();
    let rows: Vec<Row<'_>> = entries
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| {
            let is_selected = idx == selected_idx;
            let solid_selected = is_focused && is_selected;
            let cursor = if !is_selected {
                "  "
            } else if is_focused {
                "▶ "
            } else {
                "▸ "
            };
            let cell_style = normal_text_style();
            match entry {
                SidebarEntry::GroupHeader(grp) => {
                    let fold = if grp.collapsed { "▶" } else { "▼" };
                    let hdr_style = cell_style.add_modifier(Modifier::BOLD);
                    let mem = if grp.online_count > 0 {
                        format_bytes(grp.total_rss_bytes)
                    } else {
                        "-".to_string()
                    };
                    Row::new(vec![
                        Line::from(vec![
                            Span::styled(cursor, cell_style),
                            Span::styled(fold, hdr_style),
                        ]),
                        Line::from(Span::styled(format!("[{}]", grp.key), hdr_style)),
                        Line::from(Span::styled(
                            format!("{}/{} Up", grp.online_count, grp.total_count),
                            hdr_style,
                        )),
                        Line::from(Span::styled(mem, hdr_style)),
                    ])
                }
                SidebarEntry::Service { node_idx, indented } => {
                    let n = &app.snapshot.nodes[node_idx];
                    let (glyph, label, glyph_color) = node_status_badge(n.state);
                    let mem = if n.pid.is_some() {
                        format_bytes(n.resources.rss_bytes)
                    } else {
                        "-".to_string()
                    };
                    let name_text = if indented {
                        format!(" {}", n.name)
                    } else {
                        n.name.clone()
                    };
                    let prefix_line = Line::from(vec![
                        Span::styled(cursor, cell_style),
                        glyph_span(glyph, glyph_color, solid_selected),
                    ]);
                    Row::new(vec![
                        prefix_line,
                        Line::from(Span::styled(name_text, cell_style)),
                        Line::from(Span::styled(label, cell_style)),
                        Line::from(Span::styled(mem, cell_style)),
                    ])
                }
            }
        })
        .collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Length(8),
        Constraint::Fill(1),
    ];

    let title = match (is_focused, app.group_by) {
        (true, GroupByMode::Flat) => " [1] Services [ACTIVE] (↑/↓ · g group) ".to_string(),
        (false, GroupByMode::Flat) => " [1] Services (Tab/1 · g group) ".to_string(),
        (true, mode) => format!(" [1] Services · {} [ACTIVE] (g/Space) ", mode.label()),
        (false, mode) => format!(" [1] Services · {} (Tab/1) ", mode.label()),
    };
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
                .title(title)
                .borders(Borders::ALL)
                .border_style(panel_border_style(is_focused)),
        )
        .row_highlight_style(highlight_style);

    frame.render_stateful_widget(table, area, &mut app.services_table_state);
}

fn render_cluster_status_card(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let up = app
        .snapshot
        .nodes
        .iter()
        .filter(|n| n.state == NodeLifecycleState::Online)
        .count();
    let stopped = app
        .snapshot
        .nodes
        .iter()
        .filter(|n| n.state == NodeLifecycleState::Stopped)
        .count();
    let total = app.snapshot.nodes.len();

    let wiretap_line = if app.active_tab == WorkspaceTab::Xray {
        Line::from(vec![
            Span::styled("Wiretap : ", normal_text_style()),
            Span::styled(
                format!("LIVE (dropped: {})", app.snapshot.wiretap_dropped_events),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(Span::styled(
            "Wiretap : IDLE (0% overhead)",
            normal_text_style(),
        ))
    };

    let scope_name = match app.log_scope {
        LogScope::AllNodes => "All",
        LogScope::SelectedNode => app.selected_node().map_or("-", |n| n.name.as_str()),
    };

    let mut lines = vec![
        Line::from(Span::styled(
            format!("Nodes   : {up}/{total} Up · {stopped} Stopped"),
            normal_text_style(),
        )),
        wiretap_line,
        Line::from(Span::styled(
            format!("Logs    : {scope_name} · {}+", app.log_level.as_str()),
            normal_text_style(),
        )),
    ];

    if app.recent_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "• Press [?] for shortcuts",
            normal_text_style(),
        )));
    } else {
        for ev in app.recent_events.iter().rev().take(2) {
            lines.push(Line::from(Span::styled(
                format!("• {ev}"),
                normal_text_style(),
            )));
        }
    }

    let block = Block::default()
        .title(" Cluster & Quick Status ")
        .borders(Borders::ALL)
        .border_style(panel_border_style(false));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_workspace(frame: &mut Frame<'_>, area: Rect, app: &mut DashboardState) {
    let is_focused = app.focus == PanelFocus::Workspace;
    let zoom_tag = if app.zoom_workspace { " [ZOOM]" } else { "" };
    let title = if is_focused {
        format!(" [2] Workspace [ACTIVE]{zoom_tag} ([/] tabs · z zoom) ")
    } else {
        format!(" [2] Workspace{zoom_tag} (Tab/2 focus · [/] tabs) ")
    };

    let outer_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(panel_border_style(is_focused));
    let inner = outer_block.inner(area);
    frame.render_widget(outer_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(6)])
        .split(inner);

    render_workspace_tabs(frame, chunks[0], app.active_tab);

    match app.active_tab {
        WorkspaceTab::Overview => render_overview_tab(frame, chunks[1], app),
        WorkspaceTab::Logs => render_logs_tab(frame, chunks[1], app),
        WorkspaceTab::Xray => render_xray_tab(frame, chunks[1], app),
        WorkspaceTab::Inspect => render_inspect_tab(frame, chunks[1], app),
        WorkspaceTab::ExexCold => render_exex_cold_tab(frame, chunks[1], app),
    }
}

fn render_workspace_tabs(frame: &mut Frame<'_>, area: Rect, active_tab: WorkspaceTab) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let mut tab_spans: Vec<Span<'_>> = Vec::with_capacity(WorkspaceTab::ALL.len() * 2);
    for (idx, tab) in WorkspaceTab::ALL.iter().enumerate() {
        if idx > 0 {
            tab_spans.push(Span::styled("  │  ", normal_text_style()));
        }
        let style = if *tab == active_tab {
            active_tab_style()
        } else {
            inactive_tab_style()
        };
        tab_spans.push(Span::styled(format!(" {} ", tab.label()), style));
    }

    frame.render_widget(Paragraph::new(Line::from(tab_spans)), rows[0]);
    let rule = "─".repeat(rows[1].width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(rule, normal_text_style())),
        rows[1],
    );
}

fn render_overview_tab(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(4)])
        .split(area);

    if let Some(grp) = app.selected_group() {
        render_selected_group_overview(frame, chunks[0], app.group_by, &grp);
    } else {
        render_selected_node_overview(frame, chunks[0], app.selected_node());
    }
    render_overview_log_tail(frame, chunks[1], app);
}

fn render_selected_node_overview(frame: &mut Frame<'_>, area: Rect, node: Option<&NodeSnapshot>) {
    let Some(node) = node else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No managed services in stack",
                normal_text_style(),
            )),
            area,
        );
        return;
    };

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    let (glyph, state_label, glyph_color) = node_status_badge(node.state);
    let pid_str = node.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
    let up_str = if node.pid.is_some() {
        format_uptime(node.uptime_secs)
    } else {
        "-".to_string()
    };
    let exit_note = node
        .last_exit_reason
        .as_deref()
        .map(|r| format!(" | Exit: {r}"))
        .unwrap_or_default();

    let (domain_1, domain_2) = format_domain_summary(&node.domain);
    let info_lines = vec![
        Line::from(vec![
            glyph_span(glyph, glyph_color, false),
            Span::styled(
                format!(
                    " {} ({}) | PID: {pid_str} | State: {state_label} | Uptime: {up_str}",
                    node.name,
                    node.role.as_str(),
                ),
                normal_text_style().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!("Endpoints : {}", node.ports.summary()),
            normal_text_style(),
        )),
        Line::from(Span::styled(
            format!(
                "Resources : CPU {:.1}% | RSS {} | FDs {} | Threads {} | Restarts {}{}",
                node.resources.cpu_percent,
                format_bytes(node.resources.rss_bytes),
                node.resources.open_fds,
                node.resources.thread_count,
                node.restarts_total,
                exit_note,
            ),
            normal_text_style(),
        )),
        Line::from(Span::styled(domain_1, normal_text_style())),
        Line::from(Span::styled(domain_2, normal_text_style())),
    ];
    frame.render_widget(Paragraph::new(info_lines), sections[0]);

    let spark_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(sections[1]);

    let cpu_series: Vec<u64> = node
        .history_60s
        .iter()
        .map(|s| (s.cpu_percent * 10.0) as u64)
        .collect();
    let rss_series: Vec<u64> = node
        .history_60s
        .iter()
        .map(|s| s.rss_bytes / (1024 * 1024))
        .collect();

    frame.render_widget(
        Sparkline::default()
            .data(&cpu_series)
            .block(
                Block::default()
                    .title(format!(" CPU (60s): {:.1}% ", node.resources.cpu_percent))
                    .border_style(normal_text_style()),
            )
            .style(Style::default().fg(Color::LightCyan)),
        spark_cols[0],
    );
    frame.render_widget(
        Sparkline::default()
            .data(&rss_series)
            .block(
                Block::default()
                    .title(format!(
                        " RSS (60s): {} ",
                        format_bytes(node.resources.rss_bytes)
                    ))
                    .border_style(normal_text_style()),
            )
            .style(Style::default().fg(Color::LightGreen)),
        spark_cols[1],
    );

    let sep = "─".repeat(sections[2].width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(sep, normal_text_style())),
        sections[2],
    );
}

fn format_domain_summary(domain: &DomainMetrics) -> (String, String) {
    match domain {
        DomainMetrics::Participant {
            ledger_end_offset,
            active_contracts,
            hosted_parties,
            loaded_dars,
            ready,
            ..
        } => (
            format!("Ledger    : offset #{ledger_end_offset} | ACS: {active_contracts}"),
            format!("Domain    : {hosted_parties} parties | {loaded_dars} DARs | ready={ready}"),
        ),
        DomainMetrics::Sequencer {
            head_offset,
            connected_members,
            bft_quorum_peers,
        } => (
            format!("Sequencer : head #{head_offset} | members: {connected_members}"),
            format!("BFT Quorum: {bft_quorum_peers:?}"),
        ),
        DomainMetrics::Mediator {
            group_id,
            verdicts_approved,
            verdicts_rejected,
            pending_quorums,
        } => (
            format!("Mediator  : group={group_id} | pending={pending_quorums}"),
            format!("Verdicts  : approved={verdicts_approved}, rejected={verdicts_rejected}"),
        ),
        DomainMetrics::Splice {
            open_round,
            scan_updates_total,
            ledger_backend_connected,
        } => (
            format!("Splice    : open_round={open_round:?} | updates={scan_updates_total}"),
            format!("Backend   : ledger_connected={ledger_backend_connected}"),
        ),
        DomainMetrics::Pqs {
            watermark_offset,
            active_contracts,
            connected,
        } => (
            format!(
                "PQS Index : watermark #{watermark_offset} | active_contracts={active_contracts}"
            ),
            format!("Backend   : postgres_connected={connected}"),
        ),
    }
}

fn render_overview_log_tail(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);

    let grp_opt = app.selected_group();
    let scope_name: String = match app.log_scope {
        LogScope::AllNodes => "All".to_string(),
        LogScope::SelectedNode => match &grp_opt {
            Some(g) => format!("Group:{}", g.key),
            None => app
                .selected_node()
                .map_or_else(|| "-".to_string(), |n| n.name.clone()),
        },
    };
    let status = if app.log_paused { "PAUSED" } else { "LIVE" };
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "Live Tail ({scope_name}) | {}+ | {status}   ([a] scope  [l] full logs)",
                app.log_level.as_str(),
            ),
            normal_text_style().add_modifier(Modifier::BOLD),
        )),
        chunks[0],
    );

    let visible_rows = chunks[1].height as usize;
    let lines = build_visible_log_lines(app, visible_rows);
    frame.render_widget(Paragraph::new(lines), chunks[1]);
}

fn render_logs_tab(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(2)])
        .split(area);

    let filtered = app.filtered_logs();
    let grp_opt = app.selected_group();
    let scope_name: String = match app.log_scope {
        LogScope::AllNodes => "All".to_string(),
        LogScope::SelectedNode => match &grp_opt {
            Some(g) => format!("Group:{}", g.key),
            None => app
                .selected_node()
                .map_or_else(|| "-".to_string(), |n| n.name.clone()),
        },
    };
    let status = if app.log_paused { "PAUSED" } else { "LIVE" };
    let search = if app.search_mode {
        format!("/{}|", app.search_query)
    } else if !app.search_query.is_empty() {
        format!("/{}", app.search_query)
    } else {
        "none".to_string()
    };

    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "Scope: {scope_name} | Level: {}+ | {status} | Filter: {search} | Lines: {}  ([a] [v] [/] [Space])",
                app.log_level.as_str(),
                filtered.len(),
            ),
            normal_text_style().add_modifier(Modifier::BOLD),
        )),
        chunks[0],
    );

    let visible_rows = chunks[1].height as usize;
    let lines = format_sliced_logs(
        &filtered,
        visible_rows,
        app.log_scroll_from_bottom,
        &app.search_query,
    );
    frame.render_widget(Paragraph::new(lines), chunks[1]);
}

fn build_visible_log_lines(app: &DashboardState, visible_rows: usize) -> Vec<Line<'static>> {
    let filtered = app.filtered_logs();
    format_sliced_logs(
        &filtered,
        visible_rows,
        app.log_scroll_from_bottom,
        &app.search_query,
    )
}

fn format_sliced_logs(
    filtered: &[&LogLineItem],
    visible_rows: usize,
    scroll_from_bottom: usize,
    search_query: &str,
) -> Vec<Line<'static>> {
    if visible_rows == 0 || filtered.is_empty() {
        return vec![Line::from(Span::styled(
            "(no matching log lines yet)",
            normal_text_style(),
        ))];
    }
    let end = filtered.len().saturating_sub(scroll_from_bottom);
    let start = end.saturating_sub(visible_rows);
    filtered[start..end]
        .iter()
        .map(|item| format_log_line(item, search_query))
        .collect()
}

fn format_log_line(item: &LogLineItem, search_query: &str) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{:<12} ", item.node), normal_text_style()),
        Span::styled(
            format!("[{:<5}] ", item.level.as_str()),
            log_level_tag_style(item.level),
        ),
    ];

    if search_query.is_empty() {
        spans.push(Span::styled(item.line.clone(), normal_text_style()));
    } else {
        append_search_highlighted_spans(&mut spans, &item.line, search_query);
    }
    Line::from(spans)
}

fn append_search_highlighted_spans(spans: &mut Vec<Span<'static>>, line: &str, query: &str) {
    let line_lc = line.to_ascii_lowercase();
    let query_lc = query.to_ascii_lowercase();
    if query_lc.is_empty() {
        spans.push(Span::styled(line.to_string(), normal_text_style()));
        return;
    }
    let mut cursor = 0;
    while let Some(rel) = line_lc[cursor..].find(&query_lc) {
        let start = cursor + rel;
        let end = start + query_lc.len();
        if start > cursor && line.is_char_boundary(start) {
            spans.push(Span::styled(
                line[cursor..start].to_string(),
                normal_text_style(),
            ));
        }
        if line.is_char_boundary(start) && line.is_char_boundary(end) {
            spans.push(Span::styled(
                line[start..end].to_string(),
                active_tab_style(),
            ));
            cursor = end;
        } else {
            break;
        }
    }
    if cursor < line.len() {
        spans.push(Span::styled(
            line[cursor..].to_string(),
            normal_text_style(),
        ));
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &DashboardState) {
    let line_text = if app.help_modal {
        " [?/Esc/Enter/q] Close Help ".to_string()
    } else if app.scenario_modal.open {
        " [↑/↓] Select Scenario   [Enter] Run Live Scenario   [t/Esc/q] Close Lab ".to_string()
    } else if app.confirm_modal.is_some() {
        " [y/Enter] Confirm Action   [Any other key] Cancel ".to_string()
    } else if app.xray_modal.is_some() {
        " [↑/↓/PgUp/PgDn] Scroll Detail   [Esc/Enter/q] Close ".to_string()
    } else if app.search_mode {
        format!(
            " Search: {}_   [Enter] Apply   [Backspace] Delete   [Esc] Clear ",
            app.search_query
        )
    } else {
        let s_label = if let Some(grp) = app.selected_group() {
            if grp.online_count == 0 {
                format!("Start {}", grp.selector)
            } else {
                format!("Stop {}", grp.selector)
            }
        } else {
            match app.selected_node() {
                Some(n)
                    if matches!(
                        n.state,
                        NodeLifecycleState::Stopped | NodeLifecycleState::Failed
                    ) =>
                {
                    format!("Start {}", n.name)
                }
                Some(n) => format!("Stop {}", n.name),
                None => "Start/Stop".to_string(),
            }
        };
        match app.focus {
            PanelFocus::Services => format!(
                " [↑/↓] Select  [g] Group  [Space] Fold  [s] {s_label}  [r] Restart  [t] Lab  [o/l/x/i/c] Tabs  [?] Help  [q] Quit "
            ),
            PanelFocus::Workspace => match app.active_tab {
                WorkspaceTab::Overview => {
                    " [↑/↓] Scroll Tail  [Tab/←] Services  [a] Scope  [v] Level  [l/x/i] Tabs  [z] Zoom  [?] Help  [q] Quit ".to_string()
                }
                WorkspaceTab::Logs => {
                    " [↑/↓/PgUp] Scroll  [Tab/←] Services  [a] Scope  [v] Level  [/] Search  [Space] Pause  [z] Zoom  [?] Help ".to_string()
                }
                WorkspaceTab::Xray => {
                    " [↑/↓] RootHash  [Enter] Full Detail  [Tab/←] Services  [x/o] Exit X-Ray  [z] Zoom  [?] Help  [q] Quit ".to_string()
                }
                WorkspaceTab::Inspect => {
                    " [↑/↓/PgUp] Scroll  [Tab/←] Services  [o/l/x/c] Tabs  [z] Zoom  [?] Help  [q] Quit ".to_string()
                }
                WorkspaceTab::ExexCold => {
                    " [c] Refresh ExEx & Cold  [↑/↓] Scroll  [Tab/←] Services  [o/l/x/i] Tabs  [z] Zoom  [?] Help  [q] Quit ".to_string()
                }
            },
        }
    };

    frame.render_widget(
        Paragraph::new(Span::styled(line_text, normal_text_style())),
        area,
    );
}
