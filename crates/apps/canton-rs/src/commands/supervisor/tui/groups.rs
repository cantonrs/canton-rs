//! Collapsible multi-cell / domain / role / host sidebar tree builder and interactive `[t]`
//! Scenario & Load Lab modal for `canton-rs daemon top`.
//!
//! [CANTON-NOTE: INVARIANT] All widgets in this module strictly obey the theme-safe palette
//! (`Color::Reset` backgrounds + `Modifier::REVERSED | BOLD` selection) so light, dark, and
//! solarized terminals render with zero contrast loss.

use std::collections::BTreeSet;

use ratatui_core::layout::{Constraint, Direction, Layout, Rect};
use ratatui_core::style::{Color, Modifier, Style};
use ratatui_core::terminal::Frame;
use ratatui_core::text::{Line, Span};
use ratatui_widgets::block::Block;
use ratatui_widgets::borders::Borders;
use ratatui_widgets::clear::Clear;
use ratatui_widgets::paragraph::{Paragraph, Wrap};
use ratatui_widgets::table::{Row, Table, TableState};

use super::super::scenario::{ScenarioRunReport, ScenarioSpec};
use super::super::{format_bytes, ClusterSnapshot, NodeLifecycleState, NodeSnapshot};
use super::theme::{focused_selected_style, normal_text_style, panel_border_style};

/// Grouping dimension used by the left `[1] Services` tree (`g` key cycles modes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupByMode {
    Flat,
    Group,
    Synchronizer,
    Role,
    Host,
}

impl GroupByMode {
    /// Chooses `Group` automatically whenever any slot carries `group: Some(...)`, otherwise `Flat`.
    pub fn initial_for(nodes: &[NodeSnapshot]) -> Self {
        if nodes.iter().any(|n| n.group.is_some()) {
            Self::Group
        } else {
            Self::Flat
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Flat => "Flat",
            Self::Group => "Cell/Group",
            Self::Synchronizer => "SyncDomain",
            Self::Role => "Role",
            Self::Host => "Host",
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Flat => Self::Group,
            Self::Group => Self::Synchronizer,
            Self::Synchronizer => Self::Role,
            Self::Role => Self::Host,
            Self::Host => Self::Flat,
        }
    }
}

/// Aggregated metrics and bulk IPC target selector for one collapsible group row.
#[derive(Clone, Debug)]
pub struct SidebarGroupSummary {
    pub key: String,
    /// Target token accepted by `StopNodes` / `StartNodes` / `Restart` (`@bank-a`, `sync:krw`, `role:sequencer`).
    pub selector: String,
    pub collapsed: bool,
    pub online_count: usize,
    pub total_count: usize,
    pub total_cpu_percent: f64,
    pub total_rss_bytes: u64,
    pub node_names: Vec<String>,
}

/// One visible row in `[1] Services` (either a collapsible group header or a service slot).
#[derive(Clone, Debug)]
pub enum SidebarEntry {
    GroupHeader(SidebarGroupSummary),
    Service { node_idx: usize, indented: bool },
}

/// Builds the ordered list of visible rows in `[1] Services`, preserving first-seen topological
/// group order while respecting `collapsed_keys`.
pub fn build_sidebar_entries(
    snapshot: &ClusterSnapshot,
    mode: GroupByMode,
    collapsed_keys: &BTreeSet<String>,
) -> Vec<SidebarEntry> {
    if mode == GroupByMode::Flat {
        return (0..snapshot.nodes.len())
            .map(|node_idx| SidebarEntry::Service {
                node_idx,
                indented: false,
            })
            .collect();
    }

    // Preserve first-seen topological group order rather than alphabetical reshuffling.
    let mut group_order: Vec<(String, String, Vec<usize>)> = Vec::new();
    for (idx, n) in snapshot.nodes.iter().enumerate() {
        let (key, selector) = match mode {
            GroupByMode::Flat => unreachable!(),
            GroupByMode::Group => {
                let g = n.group.as_deref().unwrap_or("default");
                (g.to_string(), format!("@{g}"))
            }
            GroupByMode::Synchronizer => {
                let s = n
                    .synchronizer_domain
                    .as_deref()
                    .unwrap_or(snapshot.synchronizer.as_str());
                (s.to_string(), format!("sync:{s}"))
            }
            GroupByMode::Role => {
                let r = n.role.as_str();
                (r.to_string(), format!("role:{r}"))
            }
            GroupByMode::Host => {
                let h = n.host_label.as_deref().unwrap_or("local");
                let sel = if h == "local" {
                    "all".to_string()
                } else {
                    format!("@host:{h}")
                };
                (h.to_string(), sel)
            }
        };
        if let Some(bucket) = group_order.iter_mut().find(|(k, _, _)| k == &key) {
            bucket.2.push(idx);
        } else {
            group_order.push((key, selector, vec![idx]));
        }
    }

    let mut out = Vec::with_capacity(snapshot.nodes.len() + group_order.len());
    for (key, selector, indices) in group_order {
        let collapsed = collapsed_keys.contains(&key);
        let mut online_count = 0usize;
        let mut total_cpu_percent = 0.0f64;
        let mut total_rss_bytes = 0u64;
        let mut node_names = Vec::with_capacity(indices.len());
        for &ni in &indices {
            let node = &snapshot.nodes[ni];
            if node.state == NodeLifecycleState::Online {
                online_count += 1;
            }
            total_cpu_percent += node.resources.cpu_percent;
            total_rss_bytes = total_rss_bytes.saturating_add(node.resources.rss_bytes);
            node_names.push(node.name.clone());
        }
        out.push(SidebarEntry::GroupHeader(SidebarGroupSummary {
            key,
            selector,
            collapsed,
            online_count,
            total_count: indices.len(),
            total_cpu_percent,
            total_rss_bytes,
            node_names,
        }));
        if !collapsed {
            for ni in indices {
                out.push(SidebarEntry::Service {
                    node_idx: ni,
                    indented: true,
                });
            }
        }
    }
    out
}

/// Interactive state for the `[t]` Scenario & Load Lab modal.
#[derive(Clone, Debug, Default)]
pub struct ScenarioModalState {
    pub open: bool,
    pub scenarios: Vec<ScenarioSpec>,
    pub selected_idx: usize,
    pub running_name: Option<String>,
    pub last_report: Option<ScenarioRunReport>,
}

impl ScenarioModalState {
    pub fn move_selection(&mut self, delta: isize) {
        if self.scenarios.is_empty() {
            self.selected_idx = 0;
            return;
        }
        let max_idx = self.scenarios.len() as isize - 1;
        self.selected_idx = (self.selected_idx as isize + delta).clamp(0, max_idx) as usize;
    }

    pub fn selected(&self) -> Option<&ScenarioSpec> {
        self.scenarios.get(self.selected_idx)
    }
}

/// Renders theOverview top card when a `GroupHeader` row is highlighted in `[1] Services`.
pub fn render_selected_group_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    mode: GroupByMode,
    grp: &SidebarGroupSummary,
) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(1)])
        .split(area);

    let health_badge = if grp.online_count == grp.total_count && grp.total_count > 0 {
        ("●", Color::LightGreen, "Healthy")
    } else if grp.online_count == 0 {
        ("○", Color::Reset, "Stopped")
    } else {
        ("◐", Color::LightYellow, "Partial / Degraded")
    };

    let members_preview = if grp.node_names.len() <= 6 {
        grp.node_names.join(", ")
    } else {
        format!(
            "{}, +{} more",
            grp.node_names[..6].join(", "),
            grp.node_names.len() - 6
        )
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(health_badge.0, Style::default().fg(health_badge.1)),
            Span::styled(
                format!(
                    " [{}] ({}) | {}/{} Online ({}) | Bulk Target: {}",
                    grp.key,
                    mode.label(),
                    grp.online_count,
                    grp.total_count,
                    health_badge.2,
                    grp.selector
                ),
                normal_text_style().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!(
                "Aggregate : CPU {:.1}% | Total RSS {} | Collapsed: {}",
                grp.total_cpu_percent,
                format_bytes(grp.total_rss_bytes),
                if grp.collapsed { "Yes" } else { "No" }
            ),
            normal_text_style(),
        )),
        Line::from(Span::styled(
            format!("Members   : {members_preview}"),
            normal_text_style(),
        )),
        Line::from(Span::styled(
            "Chaos/Ops : [Space] Collapse/Expand   [s] Bulk Stop/Start Group   [r] Bulk Restart Group",
            normal_text_style(),
        )),
        Line::from(Span::styled(
            "Grouping  : [g] Cycle Group-By (Cell/Group -> SyncDomain -> Role -> Host -> Flat)   [t] Scenario Lab",
            normal_text_style(),
        )),
    ];

    frame.render_widget(Paragraph::new(lines), sections[0]);
    let sep = "─".repeat(sections[1].width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(sep, normal_text_style())),
        sections[1],
    );
}

/// Renders the `[t]` Scenario & Load Lab overlay modal.
pub fn render_scenario_modal(frame: &mut Frame<'_>, modal: &ScenarioModalState) {
    let area = centered_modal_rect(82, 22, frame.area());
    frame.render_widget(Clear, area);

    let title = match &modal.running_name {
        Some(run_name) => {
            format!(" [t] Scenario & Load Lab — RUNNING '{run_name}'... ([Esc] Close) ")
        }
        None => " [t] Scenario & Load Lab — [↑/↓] Select · [Enter] Run Live · [Esc/t] Close "
            .to_string(),
    };
    let outer = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(panel_border_style(true));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(6)])
        .split(inner);

    let header = Row::new(["", "SCENARIO", "SRC", "STEPS", "DESCRIPTION"])
        .style(normal_text_style().add_modifier(Modifier::BOLD));
    let rows: Vec<Row<'static>> = modal
        .scenarios
        .iter()
        .enumerate()
        .map(|(idx, sc)| {
            let cursor = if idx == modal.selected_idx {
                "▶ "
            } else {
                "  "
            };
            let src = if sc.builtin { "auto" } else { "yaml" };
            let st = normal_text_style();
            Row::new(vec![
                Line::from(Span::styled(cursor, st)),
                Line::from(Span::styled(sc.name.clone(), st)),
                Line::from(Span::styled(src, st)),
                Line::from(Span::styled(sc.steps.len().to_string(), st)),
                Line::from(Span::styled(sc.description.clone(), st)),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(2),
        Constraint::Length(24),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Fill(1),
    ];
    let mut tstate = TableState::default();
    if !modal.scenarios.is_empty() {
        tstate.select(Some(modal.selected_idx));
    }
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(focused_selected_style());
    frame.render_stateful_widget(table, chunks[0], &mut tstate);

    let mut report_lines = Vec::new();
    let sep = "─".repeat(chunks[1].width as usize);
    report_lines.push(Line::from(Span::styled(sep, normal_text_style())));
    if let Some(running) = &modal.running_name {
        report_lines.push(Line::from(Span::styled(
            format!(
                "Executing '{running}' against live HTTP v2 participants... (4-Hop X-Ray traces will populate automatically)"
            ),
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        )));
    } else if let Some(rep) = &modal.last_report {
        let badge_style = if rep.ok {
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
        };
        report_lines.push(Line::from(vec![
            Span::styled(if rep.ok { "PASS " } else { "FAIL " }, badge_style),
            Span::styled(
                format!("{} ({:.1} ms total)", rep.scenario, rep.total_elapsed_ms),
                normal_text_style().add_modifier(Modifier::BOLD),
            ),
        ]));
        for st in &rep.steps {
            let mark = if st.ok { "[OK] " } else { "[ERR]" };
            report_lines.push(Line::from(Span::styled(
                format!(
                    "  {mark} #{:<2} {:<22} ({:>5.1}ms) {}",
                    st.index, st.action, st.elapsed_ms, st.summary
                ),
                normal_text_style(),
            )));
        }
    } else {
        report_lines.push(Line::from(Span::styled(
            "Press [Enter] to run the highlighted scenario against the live stack (allocates parties, submits Daml contracts, and verifies privacy).",
            normal_text_style(),
        )));
    }

    frame.render_widget(
        Paragraph::new(report_lines).wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn centered_modal_rect(percent_w: u16, height: u16, area: Rect) -> Rect {
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
