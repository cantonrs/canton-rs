//! Dashboard state machine, IPC subscription threads, and keyboard command handler.

use std::collections::{BTreeSet, VecDeque};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use ratatui_widgets::table::TableState;

use super::super::ipc::{
    call_unary_with_timeout, open_stream, IpcRequest, IpcResponse, IpcStreamEvent,
};
use super::super::log_rotate::LogLevel;
use super::super::metrics::render_markdown_report;
use super::super::scenario::{
    available_scenarios_for_nodes, failed_scenario_report, run_scenario_via_ipc_or_local,
    ScenarioRunReport,
};
use super::super::{
    ClusterSnapshot, NodeInspection, NodeLifecycleState, NodeSnapshot, XRayTraceEvent,
};
use super::backend::Key;
use super::groups::{
    build_sidebar_entries, GroupByMode, ScenarioModalState, SidebarEntry, SidebarGroupSummary,
};

pub const MAX_UI_LOGS: usize = 500;
pub const MAX_UI_XRAY: usize = 64;
const MAX_RECENT_EVENTS: usize = 6;
pub(super) const MAX_TUI_IPC_THREADS: usize = 8;

pub(super) struct IpcThreadSlot(Arc<AtomicUsize>);

impl IpcThreadSlot {
    pub(super) fn try_acquire(counter: &Arc<AtomicUsize>) -> Option<Self> {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
                (cur < MAX_TUI_IPC_THREADS).then_some(cur + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(counter)))
    }
}

impl Drop for IpcThreadSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Which top-level panel owns `↑`/`↓`, `PgUp`/`PgDn`, and `Enter` keyboard navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelFocus {
    Services,
    Workspace,
}

/// Active tab inside `[2] Workspace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceTab {
    Overview,
    Logs,
    Xray,
    Inspect,
    ExexCold,
}

impl WorkspaceTab {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Logs,
        Self::Xray,
        Self::Inspect,
        Self::ExexCold,
    ];

    /// Compact tab header label shown in the workspace tab bar.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "[o] Overview",
            Self::Logs => "[l] Live Logs",
            Self::Xray => "[x] Protocol X-Ray (2PC)",
            Self::Inspect => "[i] Inspect",
            Self::ExexCold => "[c] ExEx & Cold",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Logs => 1,
            Self::Xray => 2,
            Self::Inspect => 3,
            Self::ExexCold => 4,
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// On-demand snapshot of `GET /_exex` subscriber telemetry on one participant node.
pub use super::super::ExExNodeSummary;

/// On-demand Cold Archive chain summary displayed in `[c] ExEx & Cold`.
#[derive(Clone, Debug)]
pub struct ColdArchiveTabSummary {
    pub archive_dir: PathBuf,
    pub segments_count: usize,
    pub signed_count: usize,
    pub events_count: usize,
    pub max_offset: Option<i64>,
    pub chain_valid: bool,
    pub head_sha256: Option<String>,
}

/// Whether log views follow the selected left-hand node or multiplex the entire stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogScope {
    SelectedNode,
    AllNodes,
}

/// Single buffered log entry displayed in Overview live tail and Live Logs tab.
#[derive(Clone, Debug)]
pub struct LogLineItem {
    pub node: String,
    pub level: LogLevel,
    pub line: String,
}

/// Destructive/state-mutating action awaiting `[y/Enter]` confirmation.
#[derive(Clone, Debug)]
pub enum ConfirmAction {
    Stop(String),
    Restart(String),
}

/// Asynchronous UI update pushed by IPC background listener threads.
pub enum UiEvent {
    Snapshot(ClusterSnapshot),
    Log(LogLineItem),
    Xray(XRayTraceEvent),
    ScenarioDone(ScenarioRunReport),
    /// Outcome of a start/stop/restart/ping request run off the render thread.
    Action {
        banner: String,
        recent: Option<String>,
        snapshot: Option<Box<ClusterSnapshot>>,
    },
    Inspection {
        node: String,
        result: Result<Box<NodeInspection>, String>,
        report_error: bool,
    },
    ExexCold(Vec<ExExNodeSummary>, ColdArchiveTabSummary),
}

/// RAII stop guard ensuring background X-Ray wiretap subscriptions cease on drop or tab exit.
///
/// [CANTON-NOTE: INVARIANT] Zero wiretap overhead when `WorkspaceTab::Xray` is inactive: dropping
/// this guard sets `AtomicBool(true)` so `spawn_xray_thread` disconnects cleanly.
pub struct XraySubscriptionGuard {
    stop: Arc<AtomicBool>,
}

impl XraySubscriptionGuard {
    fn spawn(state_dir: &Path, ev_tx: &mpsc::Sender<UiEvent>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        spawn_xray_thread(state_dir.to_path_buf(), ev_tx.clone(), Arc::clone(&stop));
        Self { stop }
    }
}

impl Drop for XraySubscriptionGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Interactive dashboard state (publicly testable via `ratatui_core::backend::TestBackend`).
pub struct DashboardState {
    pub state_dir: PathBuf,
    pub snapshot: ClusterSnapshot,
    pub focus: PanelFocus,
    pub active_tab: WorkspaceTab,
    pub zoom_workspace: bool,
    pub selected_idx: usize,
    pub services_table_state: TableState,
    pub xray_selected_idx: usize,
    pub xray_table_state: TableState,
    pub xray_traces: VecDeque<XRayTraceEvent>,
    pub logs: VecDeque<LogLineItem>,
    pub log_scope: LogScope,
    pub log_level: LogLevel,
    pub log_paused: bool,
    pub log_scroll_from_bottom: usize,
    pub inspect_cache: Option<NodeInspection>,
    pub inspect_scroll: u16,
    pub exex_cold_cache: Option<(Vec<ExExNodeSummary>, ColdArchiveTabSummary)>,
    pub exex_cold_scroll: u16,
    pub exex_cold_loading: bool,
    pub search_mode: bool,
    pub search_query: String,
    pub confirm_modal: Option<ConfirmAction>,
    pub xray_modal: Option<(XRayTraceEvent, u16)>,
    pub help_modal: bool,
    pub group_by: GroupByMode,
    pub collapsed_groups: BTreeSet<String>,
    pub scenario_modal: ScenarioModalState,
    pub status_banner: Option<(String, Instant)>,
    pub recent_events: VecDeque<String>,
    pub(crate) ipc_inflight: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
enum SelectionAnchor {
    Node(String),
    Group(String),
}

impl DashboardState {
    /// Initializes dashboard state from the first cluster snapshot.
    pub fn new(state_dir: PathBuf, snapshot: ClusterSnapshot) -> Self {
        let group_by = GroupByMode::initial_for(&snapshot.nodes);
        let collapsed_groups = BTreeSet::new();
        let entries = build_sidebar_entries(&snapshot, group_by, &collapsed_groups);
        let mut services_table_state = TableState::default();
        if !entries.is_empty() {
            services_table_state.select(Some(0));
        }
        Self {
            state_dir,
            snapshot,
            focus: PanelFocus::Services,
            active_tab: WorkspaceTab::Overview,
            zoom_workspace: false,
            selected_idx: 0,
            services_table_state,
            xray_selected_idx: 0,
            xray_table_state: TableState::default(),
            xray_traces: VecDeque::with_capacity(MAX_UI_XRAY),
            logs: VecDeque::with_capacity(MAX_UI_LOGS),
            log_scope: LogScope::SelectedNode,
            log_level: LogLevel::Info,
            log_paused: false,
            log_scroll_from_bottom: 0,
            inspect_cache: None,
            inspect_scroll: 0,
            exex_cold_cache: None,
            exex_cold_scroll: 0,
            exex_cold_loading: false,
            search_mode: false,
            search_query: String::new(),
            confirm_modal: None,
            xray_modal: None,
            help_modal: false,
            group_by,
            collapsed_groups,
            scenario_modal: ScenarioModalState::default(),
            status_banner: None,
            recent_events: VecDeque::with_capacity(MAX_RECENT_EVENTS),
            ipc_inflight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Applies one update posted by a background thread.
    pub fn apply_event(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::Snapshot(snap) => self.apply_snapshot(snap),
            UiEvent::Log(line) => self.push_log(line),
            UiEvent::Xray(trace) => self.push_xray(trace),
            UiEvent::ScenarioDone(rep) => self.finish_scenario(rep),
            UiEvent::Action {
                banner,
                recent,
                snapshot,
            } => {
                if let Some(snap) = snapshot {
                    self.apply_snapshot(*snap);
                }
                self.set_banner(banner);
                if let Some(r) = recent {
                    self.push_recent_event(r);
                }
            }
            UiEvent::Inspection {
                node,
                result,
                report_error,
            } => self.apply_inspection(node, result, report_error),
            UiEvent::ExexCold(nodes, cold) => {
                self.exex_cold_cache = Some((nodes, cold));
                self.exex_cold_scroll = 0;
                self.exex_cold_loading = false;
            }
        }
    }

    /// Builds visible rows in `[1] Services` according to `group_by` and `collapsed_groups`.
    pub fn sidebar_entries(&self) -> Vec<SidebarEntry> {
        build_sidebar_entries(&self.snapshot, self.group_by, &self.collapsed_groups)
    }

    /// Returns the currently highlighted sidebar entry (group header or service slot).
    pub fn selected_entry(&self) -> Option<SidebarEntry> {
        self.sidebar_entries().into_iter().nth(self.selected_idx)
    }

    /// Returns the currently highlighted group summary when the cursor rests on a group header.
    pub fn selected_group(&self) -> Option<SidebarGroupSummary> {
        match self.selected_entry()? {
            SidebarEntry::GroupHeader(grp) => Some(grp),
            SidebarEntry::Service { .. } => None,
        }
    }

    /// Returns the currently highlighted node slot in `[1] Services`.
    pub fn selected_node(&self) -> Option<&NodeSnapshot> {
        match self.selected_entry()? {
            SidebarEntry::Service { node_idx, .. } => self.snapshot.nodes.get(node_idx),
            SidebarEntry::GroupHeader(_) => None,
        }
    }

    fn current_anchor(&self) -> Option<SelectionAnchor> {
        match self.selected_entry()? {
            SidebarEntry::Service { node_idx, .. } => self
                .snapshot
                .nodes
                .get(node_idx)
                .map(|n| SelectionAnchor::Node(n.name.clone())),
            SidebarEntry::GroupHeader(g) => Some(SelectionAnchor::Group(g.key)),
        }
    }

    fn restore_anchor(&mut self, anchor: Option<SelectionAnchor>) {
        let entries = self.sidebar_entries();
        if entries.is_empty() {
            self.selected_idx = 0;
            self.services_table_state.select(None);
            return;
        }
        if let Some(anc) = anchor {
            let found = entries.iter().position(|e| match (&anc, e) {
                (SelectionAnchor::Node(name), SidebarEntry::Service { node_idx, .. }) => self
                    .snapshot
                    .nodes
                    .get(*node_idx)
                    .is_some_and(|n| &n.name == name),
                (SelectionAnchor::Group(key), SidebarEntry::GroupHeader(g)) => &g.key == key,
                _ => false,
            });
            if let Some(pos) = found {
                self.selected_idx = pos;
            }
        }
        let max_idx = entries.len() - 1;
        if self.selected_idx > max_idx {
            self.selected_idx = max_idx;
        }
        self.services_table_state.select(Some(self.selected_idx));
    }

    /// Cycles `[1] Services` grouping mode (`g` key) while keeping selection valid.
    pub fn cycle_group_by(&mut self) {
        let anchor = self.current_anchor();
        self.group_by = self.group_by.next();
        self.restore_anchor(anchor);
        self.set_banner(format!(
            "Services grouped by: {} ([Space] fold/unfold group, [s/r] bulk group control)",
            self.group_by.label()
        ));
    }

    /// Toggles collapse/expand state of a group header row.
    pub fn toggle_group_collapse(&mut self, key: &str) {
        if !self.collapsed_groups.remove(key) {
            self.collapsed_groups.insert(key.to_string());
        }
        self.restore_anchor(Some(SelectionAnchor::Group(key.to_string())));
    }

    /// Opens the interactive `[t]` Scenario & Load Lab modal.
    pub fn open_scenario_modal(&mut self) {
        self.scenario_modal.scenarios =
            available_scenarios_for_nodes(&self.snapshot.scenarios, &self.snapshot.nodes);
        if self.scenario_modal.selected_idx >= self.scenario_modal.scenarios.len() {
            self.scenario_modal.selected_idx = 0;
        }
        self.scenario_modal.open = true;
    }

    /// Records the finished `ScenarioRunReport` from the background worker thread.
    pub fn finish_scenario(&mut self, report: ScenarioRunReport) {
        let status = if report.ok { "PASS" } else { "FAIL" };
        self.push_recent_event(format!("Scenario {} {status}", report.scenario));
        self.set_banner(format!(
            "Scenario '{}' {} ({:.1} ms)",
            report.scenario, status, report.total_elapsed_ms
        ));
        self.scenario_modal.running_name = None;
        self.scenario_modal.last_report = Some(report);
    }

    /// Returns X-Ray traces ordered newest-first for interactive table selection.
    pub fn xray_newest_first(&self) -> Vec<&XRayTraceEvent> {
        self.xray_traces.iter().rev().collect()
    }

    /// Returns the currently highlighted X-Ray trace matching `xray_selected_idx`.
    pub fn selected_xray_trace(&self) -> Option<&XRayTraceEvent> {
        let list = self.xray_newest_first();
        list.get(self.xray_selected_idx).copied()
    }

    /// Buffers a new log line unless live tailing is paused.
    pub fn push_log(&mut self, item: LogLineItem) {
        if self.log_paused {
            return;
        }
        if self.logs.len() >= MAX_UI_LOGS {
            self.logs.pop_front();
        }
        self.logs.push_back(item);
    }

    /// Upserts an X-Ray trace by `root_hash` while preserving valid selection bounds.
    pub fn push_xray(&mut self, trace: XRayTraceEvent) {
        if let Some(pos) = self
            .xray_traces
            .iter()
            .position(|t| t.root_hash == trace.root_hash)
        {
            self.xray_traces[pos] = trace;
        } else {
            if self.xray_traces.len() >= MAX_UI_XRAY {
                self.xray_traces.pop_front();
            }
            self.xray_traces.push_back(trace);
        }
        if !self.xray_traces.is_empty() {
            let max_idx = self.xray_traces.len().saturating_sub(1);
            if self.xray_selected_idx > max_idx {
                self.xray_selected_idx = max_idx;
            }
            self.xray_table_state.select(Some(self.xray_selected_idx));
        }
    }

    /// Updates `snapshot` while keeping the cursor anchored to the previously selected service or group.
    pub fn apply_snapshot(&mut self, snap: ClusterSnapshot) {
        let anchor = self.current_anchor();
        self.snapshot = snap;
        self.restore_anchor(anchor);
    }

    /// Records a concise operational event shown in the lower-left status card.
    pub fn push_recent_event(&mut self, msg: impl Into<String>) {
        if self.recent_events.len() >= MAX_RECENT_EVENTS {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(msg.into());
    }

    /// Displays a transient notice banner in the top header.
    pub fn set_banner(&mut self, msg: impl Into<String>) {
        self.status_banner = Some((msg.into(), Instant::now()));
    }

    /// Returns filtered log references honoring scope (`SelectedNode`/Group/`AllNodes`), level, and search.
    pub fn filtered_logs(&self) -> Vec<&LogLineItem> {
        let selected_grp = self.selected_group();
        let selected_name = self.selected_node().map(|n| n.name.clone());
        let query_lc = self.search_query.to_ascii_lowercase();
        self.logs
            .iter()
            .filter(|l| l.level >= self.log_level)
            .filter(|l| {
                if self.log_scope == LogScope::AllNodes {
                    true
                } else if let Some(grp) = &selected_grp {
                    grp.node_names.iter().any(|name| name == &l.node)
                } else {
                    selected_name.as_deref().is_none_or(|name| l.node == name)
                }
            })
            .filter(|l| query_lc.is_empty() || l.line.to_ascii_lowercase().contains(&query_lc))
            .collect()
    }

    /// Moves the active table/scroll position by `delta` rows.
    pub fn move_selection(&mut self, delta: isize) {
        match self.focus {
            PanelFocus::Services => {
                let count = self.sidebar_entries().len();
                if count == 0 {
                    self.selected_idx = 0;
                    self.services_table_state.select(None);
                    return;
                }
                let next =
                    (self.selected_idx as isize + delta).clamp(0, count as isize - 1) as usize;
                if next != self.selected_idx {
                    self.selected_idx = next;
                    self.log_scroll_from_bottom = 0;
                    self.inspect_scroll = 0;
                    if let Some(insp) = &self.inspect_cache {
                        if self.selected_node().is_some_and(|n| n.name != insp.name) {
                            self.inspect_cache = None;
                        }
                    }
                }
                self.services_table_state.select(Some(self.selected_idx));
            }
            PanelFocus::Workspace => match self.active_tab {
                WorkspaceTab::Xray => {
                    let count = self.xray_traces.len();
                    if count == 0 {
                        self.xray_selected_idx = 0;
                        self.xray_table_state.select(None);
                        return;
                    }
                    let next = (self.xray_selected_idx as isize + delta)
                        .clamp(0, count as isize - 1) as usize;
                    self.xray_selected_idx = next;
                    self.xray_table_state.select(Some(next));
                }
                WorkspaceTab::Logs | WorkspaceTab::Overview => {
                    let total = self.filtered_logs().len();
                    let next = if delta < 0 {
                        // Moving Up scrolls backward into older logs (`log_scroll_from_bottom` increases).
                        self.log_scroll_from_bottom
                            .saturating_add(delta.unsigned_abs())
                    } else {
                        self.log_scroll_from_bottom.saturating_sub(delta as usize)
                    };
                    self.log_scroll_from_bottom = next.min(total.saturating_sub(1));
                }
                WorkspaceTab::Inspect => {
                    self.inspect_scroll = if delta >= 0 {
                        self.inspect_scroll.saturating_add(delta as u16)
                    } else {
                        self.inspect_scroll
                            .saturating_sub(delta.unsigned_abs() as u16)
                    };
                }
                WorkspaceTab::ExexCold => {
                    self.exex_cold_scroll = if delta >= 0 {
                        self.exex_cold_scroll.saturating_add(delta as u16)
                    } else {
                        self.exex_cold_scroll
                            .saturating_sub(delta.unsigned_abs() as u16)
                    };
                }
            },
        }
    }

    fn jump_edge(&mut self, to_start: bool) {
        match self.focus {
            PanelFocus::Services => {
                let entries = self.sidebar_entries();
                if entries.is_empty() {
                    return;
                }
                let target = if to_start { 0 } else { entries.len() - 1 };
                if target != self.selected_idx {
                    self.selected_idx = target;
                    self.log_scroll_from_bottom = 0;
                    self.inspect_scroll = 0;
                }
                self.services_table_state.select(Some(target));
            }
            PanelFocus::Workspace => match self.active_tab {
                WorkspaceTab::Xray => {
                    if self.xray_traces.is_empty() {
                        return;
                    }
                    let target = if to_start {
                        0
                    } else {
                        self.xray_traces.len() - 1
                    };
                    self.xray_selected_idx = target;
                    self.xray_table_state.select(Some(target));
                }
                WorkspaceTab::Logs | WorkspaceTab::Overview => {
                    if to_start {
                        self.log_scroll_from_bottom = self.filtered_logs().len().saturating_sub(1);
                    } else {
                        self.log_scroll_from_bottom = 0;
                    }
                }
                WorkspaceTab::Inspect => {
                    self.inspect_scroll = if to_start { 0 } else { u16::MAX / 2 };
                }
                WorkspaceTab::ExexCold => {
                    self.exex_cold_scroll = if to_start { 0 } else { u16::MAX / 2 };
                }
            },
        }
    }

    /// Starts a background query of `GET /_exex` and the Cold Archive; the result arrives as [`UiEvent::ExexCold`].
    pub fn refresh_exex_and_cold(&mut self, tx: &mpsc::Sender<UiEvent>) {
        if self.exex_cold_loading {
            return;
        }
        let Some(slot_guard) = IpcThreadSlot::try_acquire(&self.ipc_inflight) else {
            self.set_banner("Too many IPC requests in flight; wait for pending action");
            return;
        };
        self.exex_cold_loading = true;
        let nodes = self.snapshot.nodes.clone();
        let state_dir = self.state_dir.clone();
        let archive_dir = self.state_dir.join("cold-archive");
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _slot_guard = slot_guard;
            let (exex, cold) = collect_exex_and_cold(&state_dir, &nodes, archive_dir);
            let _ = tx.send(UiEvent::ExexCold(exex, cold));
        });
    }

    /// Asks the daemon for the selected node's inspection off the render thread.
    fn fetch_selected_inspection(
        &mut self,
        state_dir: &Path,
        tx: &mpsc::Sender<UiEvent>,
        report_error: bool,
    ) {
        let Some(name) = self.selected_node().map(|n| n.name.clone()) else {
            self.inspect_cache = None;
            return;
        };
        let Some(slot_guard) = IpcThreadSlot::try_acquire(&self.ipc_inflight) else {
            if report_error {
                self.set_banner("Too many IPC requests in flight; wait for pending action");
            }
            return;
        };
        let dir = state_dir.to_path_buf();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _slot_guard = slot_guard;
            let result = match call_unary_with_timeout(
                &dir,
                &IpcRequest::Inspect { node: name.clone() },
                Some(Duration::from_secs(5)),
            ) {
                Ok(IpcResponse::Inspection { inspection, .. }) => Ok(inspection),
                Ok(_) => Err("Unexpected inspect response".to_string()),
                Err(e) => Err(e),
            };
            let _ = tx.send(UiEvent::Inspection {
                node: name,
                result,
                report_error,
            });
        });
    }

    fn apply_inspection(
        &mut self,
        name: String,
        result: Result<Box<NodeInspection>, String>,
        report_error: bool,
    ) {
        let still_selected = self.selected_node().is_some_and(|n| n.name == name);
        match result {
            Ok(inspection) if still_selected => {
                self.inspect_cache = Some(*inspection);
                self.inspect_scroll = 0;
            }
            Ok(_) => {}
            Err(e) => {
                if self
                    .inspect_cache
                    .as_ref()
                    .is_some_and(|insp| insp.name != name)
                {
                    self.inspect_cache = None;
                }
                if report_error {
                    self.set_banner(format!("Inspect failed for {name}: {e}"));
                }
            }
        }
    }
}

/// Queries each online local participant's `/_exex` via authenticated supervisor IPC and verifies the Cold Archive chain in `archive_dir`.
fn collect_exex_and_cold(
    state_dir: &Path,
    nodes: &[NodeSnapshot],
    archive_dir: PathBuf,
) -> (Vec<ExExNodeSummary>, ColdArchiveTabSummary) {
    let exex_nodes = match call_unary_with_timeout(
        state_dir,
        &IpcRequest::GetExex,
        Some(Duration::from_secs(3)),
    ) {
        Ok(IpcResponse::Exex { nodes, .. }) => nodes,
        _ => nodes
            .iter()
            .filter_map(|n| {
                n.ports.http_json.map(|port| ExExNodeSummary {
                    node_name: n.name.clone(),
                    port,
                    reachable: false,
                    active_subscribers: 0,
                    subscriber_lines: Vec::new(),
                })
            })
            .collect(),
    };

    let chosen_dir = archive_dir;
    let cold_summary =
        match canton_participant::cold_archive::verify_archive_dir_streaming(&chosen_dir, None) {
            Ok((rep, _)) => ColdArchiveTabSummary {
                archive_dir: chosen_dir,
                segments_count: rep.segments_verified,
                signed_count: rep.signed_segments,
                events_count: rep.total_events,
                max_offset: rep.max_offset,
                chain_valid: true,
                head_sha256: rep.head_segment_sha256,
            },
            Err(_) => {
                let mut tmp = canton_participant::cold_archive::StorageOverviewStats::default();
                canton_participant::cold_archive::populate_cold_stats_from_dir(
                    &chosen_dir,
                    &mut tmp,
                );
                ColdArchiveTabSummary {
                    archive_dir: chosen_dir,
                    segments_count: tmp.cold_segments_count,
                    signed_count: 0,
                    events_count: tmp.cold_events_count,
                    max_offset: tmp.cold_max_offset,
                    chain_valid: false,
                    head_sha256: None,
                }
            }
        };

    (exex_nodes, cold_summary)
}

/// Synchronizes background X-Ray wiretap stream with `WorkspaceTab::Xray`.
pub fn sync_wiretap_subscription(
    state_dir: &Path,
    app: &DashboardState,
    ev_tx: &mpsc::Sender<UiEvent>,
    xray_guard: &mut Option<XraySubscriptionGuard>,
) {
    if app.active_tab == WorkspaceTab::Xray {
        if xray_guard.is_none() {
            *xray_guard = Some(XraySubscriptionGuard::spawn(state_dir, ev_tx));
        }
    } else if xray_guard.take().is_some() {
        // Guard drop signals `AtomicBool(true)` to stop the stream and restore 0% hot-path overhead.
    }
}

/// Applies one decoded terminal key event and returns `Ok(true)` when the user detaches TUI.
pub fn handle_key(
    state_dir: &Path,
    app: &mut DashboardState,
    key: Key,
    ev_tx: &mpsc::Sender<UiEvent>,
    xray_guard: &mut Option<XraySubscriptionGuard>,
) -> Result<bool, String> {
    if matches!(key, Key::CtrlC) {
        return Ok(true);
    }

    if app.help_modal {
        if matches!(key, Key::Esc | Key::Enter | Key::Char('?') | Key::Char('q')) {
            app.help_modal = false;
        }
        return Ok(false);
    }

    if app.scenario_modal.open {
        match key {
            Key::Esc | Key::Char('t') | Key::Char('q') => {
                app.scenario_modal.open = false;
            }
            Key::Up | Key::Char('k') => app.scenario_modal.move_selection(-1),
            Key::Down | Key::Char('j') => app.scenario_modal.move_selection(1),
            Key::Enter if app.scenario_modal.running_name.is_none() => {
                if let Some(spec) = app.scenario_modal.selected().cloned() {
                    let Some(slot_guard) = IpcThreadSlot::try_acquire(&app.ipc_inflight) else {
                        app.set_banner("Too many IPC requests in flight; wait for pending action");
                        return Ok(false);
                    };
                    app.scenario_modal.running_name = Some(spec.name.clone());
                    let sd = state_dir.to_path_buf();
                    let snap = app.snapshot.clone();
                    let tx = ev_tx.clone();
                    std::thread::spawn(move || {
                        let _slot_guard = slot_guard;
                        let rep = run_scenario_via_ipc_or_local(
                            &sd,
                            &snap,
                            &spec,
                            Duration::from_secs(120),
                        )
                        .unwrap_or_else(|err| failed_scenario_report(&spec, err));
                        let _ = tx.send(UiEvent::ScenarioDone(rep));
                    });
                }
            }
            _ => {}
        }
        return Ok(false);
    }

    if let Some(action) = app.confirm_modal.clone() {
        handle_confirm_key(state_dir, app, action, &key, ev_tx);
        return Ok(false);
    }

    if let Some((ref mut _trace, ref mut scroll)) = app.xray_modal {
        match key {
            Key::Esc | Key::Enter | Key::Char('i') | Key::Char('q') => {
                app.xray_modal = None;
            }
            Key::Down | Key::Char('j') => *scroll = scroll.saturating_add(1),
            Key::Up | Key::Char('k') => *scroll = scroll.saturating_sub(1),
            Key::PageDown => *scroll = scroll.saturating_add(6),
            Key::PageUp => *scroll = scroll.saturating_sub(6),
            _ => {}
        }
        return Ok(false);
    }

    if app.search_mode {
        match key {
            Key::Esc => {
                app.search_query.clear();
                app.search_mode = false;
                app.log_scroll_from_bottom = 0;
            }
            Key::Enter => {
                app.search_mode = false;
            }
            Key::Backspace => {
                app.search_query.pop();
                app.log_scroll_from_bottom = 0;
            }
            Key::Char(c) => {
                app.search_query.push(c);
                app.log_scroll_from_bottom = 0;
            }
            _ => {}
        }
        return Ok(false);
    }

    match key {
        Key::Char('q') => return Ok(true),
        Key::Char('?') => app.help_modal = true,
        Key::Esc => {
            if app.zoom_workspace {
                app.zoom_workspace = false;
            } else if !app.search_query.is_empty() {
                app.search_query.clear();
                app.log_scroll_from_bottom = 0;
            } else if app.active_tab != WorkspaceTab::Overview {
                switch_workspace_tab(state_dir, app, WorkspaceTab::Overview, ev_tx, xray_guard);
                app.focus = PanelFocus::Services;
            } else {
                app.focus = PanelFocus::Services;
            }
        }
        Key::Tab | Key::BackTab => {
            if app.zoom_workspace && app.focus == PanelFocus::Workspace {
                app.zoom_workspace = false;
                app.focus = PanelFocus::Services;
            } else {
                app.focus = match app.focus {
                    PanelFocus::Services => PanelFocus::Workspace,
                    PanelFocus::Workspace => PanelFocus::Services,
                };
            }
        }
        Key::Left | Key::Char('1') => {
            app.zoom_workspace = false;
            app.focus = PanelFocus::Services;
        }
        Key::Right | Key::Char('2') => {
            app.focus = PanelFocus::Workspace;
        }
        Key::Up | Key::Char('k') => {
            app.move_selection(-1);
            if app.focus == PanelFocus::Services && app.active_tab == WorkspaceTab::Inspect {
                app.fetch_selected_inspection(state_dir, ev_tx, false);
            }
        }
        Key::Down | Key::Char('j') => {
            app.move_selection(1);
            if app.focus == PanelFocus::Services && app.active_tab == WorkspaceTab::Inspect {
                app.fetch_selected_inspection(state_dir, ev_tx, false);
            }
        }
        Key::PageUp => app.move_selection(-5),
        Key::PageDown => app.move_selection(5),
        Key::Home => app.jump_edge(true),
        Key::End => app.jump_edge(false),
        Key::Char('o') => {
            switch_workspace_tab(state_dir, app, WorkspaceTab::Overview, ev_tx, xray_guard);
        }
        Key::Char('l') => {
            switch_workspace_tab(state_dir, app, WorkspaceTab::Logs, ev_tx, xray_guard);
        }
        Key::Char('x') => {
            if app.active_tab == WorkspaceTab::Xray {
                switch_workspace_tab(state_dir, app, WorkspaceTab::Overview, ev_tx, xray_guard);
                app.focus = PanelFocus::Services;
                app.set_banner("Protocol X-Ray wiretap OFF (0% hot-path overhead)");
            } else {
                switch_workspace_tab(state_dir, app, WorkspaceTab::Xray, ev_tx, xray_guard);
                app.focus = PanelFocus::Workspace;
                app.set_banner(
                    "Protocol X-Ray ON (↑/↓ select RootHash, Enter full detail, Tab focus)",
                );
            }
        }
        Key::Char('i') => {
            switch_workspace_tab(state_dir, app, WorkspaceTab::Inspect, ev_tx, xray_guard);
        }
        Key::Char('c') => {
            switch_workspace_tab(state_dir, app, WorkspaceTab::ExexCold, ev_tx, xray_guard);
            app.set_banner("Refreshed CantonExEx (/_exex) & Cold Archive chain status");
        }
        Key::Char('[') => {
            let prev = app.active_tab.prev();
            switch_workspace_tab(state_dir, app, prev, ev_tx, xray_guard);
        }
        Key::Char(']') => {
            let next = app.active_tab.next();
            switch_workspace_tab(state_dir, app, next, ev_tx, xray_guard);
        }
        Key::Enter => {
            if app.focus == PanelFocus::Services {
                if let Some(grp) = app.selected_group() {
                    app.toggle_group_collapse(&grp.key);
                    return Ok(false);
                }
            }
            if app.focus == PanelFocus::Workspace && app.active_tab == WorkspaceTab::Xray {
                if let Some(trace) = app.selected_xray_trace().cloned() {
                    app.xray_modal = Some((trace, 0));
                } else {
                    app.set_banner("No X-Ray trace selected yet (submit a transaction to capture)");
                }
            } else {
                switch_workspace_tab(state_dir, app, WorkspaceTab::Inspect, ev_tx, xray_guard);
                app.focus = PanelFocus::Workspace;
            }
        }
        Key::Char('g') => {
            app.cycle_group_by();
        }
        Key::Char('t') => {
            app.open_scenario_modal();
        }
        Key::Char('z') => {
            app.zoom_workspace = !app.zoom_workspace;
            if app.zoom_workspace {
                app.focus = PanelFocus::Workspace;
            }
        }
        Key::Char('a') => {
            app.log_scope = match app.log_scope {
                LogScope::SelectedNode => LogScope::AllNodes,
                LogScope::AllNodes => LogScope::SelectedNode,
            };
            app.log_scroll_from_bottom = 0;
            let scope_desc = match app.log_scope {
                LogScope::AllNodes => "All services".to_string(),
                LogScope::SelectedNode => app
                    .selected_node()
                    .map_or_else(|| "selected".to_string(), |n| n.name.clone()),
            };
            app.set_banner(format!("Log scope: {scope_desc}"));
        }
        Key::Char('v') => {
            app.log_level = match app.log_level {
                LogLevel::Debug => LogLevel::Info,
                LogLevel::Info => LogLevel::Warn,
                LogLevel::Warn => LogLevel::Error,
                LogLevel::Error => LogLevel::Debug,
            };
            app.log_scroll_from_bottom = 0;
            app.set_banner(format!("Log level: {}+", app.log_level.as_str()));
        }
        Key::Char('/') => {
            if matches!(
                app.active_tab,
                WorkspaceTab::Xray | WorkspaceTab::Inspect | WorkspaceTab::ExexCold
            ) {
                switch_workspace_tab(state_dir, app, WorkspaceTab::Logs, ev_tx, xray_guard);
            }
            app.search_mode = true;
            app.search_query.clear();
        }
        Key::Char(' ') => {
            if app.focus == PanelFocus::Services {
                if let Some(grp) = app.selected_group() {
                    app.toggle_group_collapse(&grp.key);
                } else {
                    app.log_paused = !app.log_paused;
                }
            } else {
                app.log_paused = !app.log_paused;
            }
        }
        Key::Char('s') => {
            if let Some(grp) = app.selected_group() {
                let selector = grp.selector.clone();
                if grp.online_count == 0 {
                    app.set_banner(format!("Starting group {selector}..."));
                    spawn_unary_action(
                        app,
                        state_dir,
                        ev_tx,
                        IpcRequest::StartNodes {
                            targets: vec![selector.clone()],
                        },
                        format!("Started group {selector}"),
                        format!("Started {selector}"),
                        "Group start error",
                    );
                } else {
                    app.confirm_modal = Some(ConfirmAction::Stop(selector));
                }
            } else if let Some(node) = app.selected_node() {
                let name = node.name.clone();
                if matches!(
                    node.state,
                    NodeLifecycleState::Stopped | NodeLifecycleState::Failed
                ) {
                    app.set_banner(format!("Starting {name}..."));
                    spawn_unary_action(
                        app,
                        state_dir,
                        ev_tx,
                        IpcRequest::StartNodes {
                            targets: vec![name.clone()],
                        },
                        format!("Started {name}"),
                        format!("Started {name}"),
                        "Start error",
                    );
                } else {
                    app.confirm_modal = Some(ConfirmAction::Stop(name));
                }
            }
        }
        Key::Char('r') => {
            if let Some(grp) = app.selected_group() {
                app.confirm_modal = Some(ConfirmAction::Restart(grp.selector));
            } else if let Some(node) = app.selected_node() {
                app.confirm_modal = Some(ConfirmAction::Restart(node.name.clone()));
            }
        }
        Key::Char('p') => {
            app.set_banner("Pinging...");
            spawn_ping_action(app, state_dir, ev_tx);
        }
        Key::Char('e') => {
            let md = render_markdown_report(&app.snapshot);
            let out_path = app.state_dir.join("footprint-report.md");
            match std::fs::write(&out_path, md) {
                Ok(()) => {
                    app.set_banner(format!("Exported report to {}", out_path.display()));
                    app.push_recent_event("Exported footprint-report.md");
                }
                Err(e) => app.set_banner(format!("Export failed: {e}")),
            }
        }
        _ => {}
    }

    Ok(false)
}

fn switch_workspace_tab(
    state_dir: &Path,
    app: &mut DashboardState,
    tab: WorkspaceTab,
    ev_tx: &mpsc::Sender<UiEvent>,
    xray_guard: &mut Option<XraySubscriptionGuard>,
) {
    app.active_tab = tab;
    sync_wiretap_subscription(state_dir, app, ev_tx, xray_guard);
    if tab == WorkspaceTab::Inspect {
        app.fetch_selected_inspection(state_dir, ev_tx, true);
    } else if tab == WorkspaceTab::Xray {
        app.focus = PanelFocus::Workspace;
    } else if tab == WorkspaceTab::ExexCold {
        app.refresh_exex_and_cold(ev_tx);
    }
}

/// Runs a unary daemon IPC command off the render thread and posts its outcome as [`UiEvent::Action`].
fn spawn_unary_action(
    app: &mut DashboardState,
    state_dir: &Path,
    ev_tx: &mpsc::Sender<UiEvent>,
    req: IpcRequest,
    ok_banner: String,
    ok_recent: String,
    err_prefix: &'static str,
) {
    let Some(slot_guard) = IpcThreadSlot::try_acquire(&app.ipc_inflight) else {
        app.set_banner("Too many IPC requests in flight; wait for pending action");
        return;
    };
    let req_timeout = match &req {
        IpcRequest::StopNodes { .. } | IpcRequest::Restart { .. } => Duration::from_secs(45),
        _ => Duration::from_secs(15),
    };
    let dir = state_dir.to_path_buf();
    let tx = ev_tx.clone();
    std::thread::spawn(move || {
        let _slot_guard = slot_guard;
        let ev = match call_unary_with_timeout(&dir, &req, Some(req_timeout)) {
            Ok(_) => {
                let snapshot = match call_unary_with_timeout(
                    &dir,
                    &IpcRequest::GetSnapshot,
                    Some(Duration::from_secs(5)),
                ) {
                    Ok(IpcResponse::Snapshot { snapshot, .. }) => Some(Box::new(snapshot)),
                    _ => None,
                };
                UiEvent::Action {
                    banner: ok_banner,
                    recent: Some(ok_recent),
                    snapshot,
                }
            }
            Err(e) => UiEvent::Action {
                banner: format!("{err_prefix}: {e}"),
                recent: None,
                snapshot: None,
            },
        };
        let _ = tx.send(ev);
    });
}

/// Runs `TriggerPing` off the render thread and posts the RTT banner as [`UiEvent::Action`].
fn spawn_ping_action(app: &mut DashboardState, state_dir: &Path, ev_tx: &mpsc::Sender<UiEvent>) {
    let Some(slot_guard) = IpcThreadSlot::try_acquire(&app.ipc_inflight) else {
        app.set_banner("Too many IPC requests in flight; wait for pending action");
        return;
    };
    let dir = state_dir.to_path_buf();
    let tx = ev_tx.clone();
    std::thread::spawn(move || {
        let _slot_guard = slot_guard;
        let ev = match call_unary_with_timeout(
            &dir,
            &IpcRequest::TriggerPing,
            Some(Duration::from_secs(45)),
        ) {
            Ok(IpcResponse::Ping { rtt_ms, detail, .. }) => {
                let snapshot = match call_unary_with_timeout(
                    &dir,
                    &IpcRequest::GetSnapshot,
                    Some(Duration::from_secs(5)),
                ) {
                    Ok(IpcResponse::Snapshot { snapshot, .. }) => Some(Box::new(snapshot)),
                    _ => None,
                };
                UiEvent::Action {
                    banner: format!("Ping OK ({rtt_ms:.2} ms: {detail})"),
                    recent: Some(format!("Ping {rtt_ms:.1}ms")),
                    snapshot,
                }
            }
            Ok(_) => return,
            Err(e) => UiEvent::Action {
                banner: format!("Ping failed: {e}"),
                recent: None,
                snapshot: None,
            },
        };
        let _ = tx.send(ev);
    });
}

fn handle_confirm_key(
    state_dir: &Path,
    app: &mut DashboardState,
    action: ConfirmAction,
    key: &Key,
    ev_tx: &mpsc::Sender<UiEvent>,
) {
    match key {
        Key::Char('y') | Key::Char('Y') | Key::Enter => {
            app.confirm_modal = None;
            match action {
                ConfirmAction::Stop(name) => {
                    app.set_banner(format!("Stopping {name}..."));
                    spawn_unary_action(
                        app,
                        state_dir,
                        ev_tx,
                        IpcRequest::StopNodes {
                            targets: vec![name.clone()],
                        },
                        format!("Stopped {name} (auto-restart paused)"),
                        format!("Stopped {name}"),
                        "Stop error",
                    );
                }
                ConfirmAction::Restart(name) => {
                    app.set_banner(format!("Restarting {name}..."));
                    spawn_unary_action(
                        app,
                        state_dir,
                        ev_tx,
                        IpcRequest::Restart {
                            target: Some(name.clone()),
                        },
                        format!("Restarted {name}"),
                        format!("Restarted {name}"),
                        "Restart error",
                    );
                }
            }
        }
        _ => {
            app.confirm_modal = None;
            app.set_banner("Action cancelled");
        }
    }
}

fn spawn_ipc_stream_thread<F>(
    state_dir: PathBuf,
    req: IpcRequest,
    read_timeout: Duration,
    tx: mpsc::Sender<UiEvent>,
    stop: Arc<AtomicBool>,
    map_event: F,
) where
    F: Fn(IpcStreamEvent) -> Option<UiEvent> + Send + 'static,
{
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let Ok(mut reader) = open_stream(&state_dir, &req, Some(read_timeout)) else {
                std::thread::sleep(Duration::from_millis(400));
                continue;
            };
            pump_lines(&mut reader, &stop, |raw| {
                if let Ok(stream_ev) = serde_json::from_str::<IpcStreamEvent>(raw) {
                    if let Some(ui_ev) = map_event(stream_ev) {
                        let _ = tx.send(ui_ev);
                    }
                }
            });
        }
    });
}

/// Feeds each complete NDJSON line to `on_line` until EOF, a hard read error, or `stop`.
///
/// Preserves partial bytes (including split multi-byte UTF-8 sequences) across read timeouts.
pub(crate) fn pump_lines<R: BufRead>(
    reader: &mut R,
    stop: &AtomicBool,
    mut on_line: impl FnMut(&str),
) {
    let mut buf = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => {
                if !buf.is_empty() {
                    let line = String::from_utf8_lossy(&buf);
                    on_line(&line);
                    buf.clear();
                }
                break;
            }
            Ok(_) => {
                if buf.ends_with(b"\n") {
                    let line = String::from_utf8_lossy(&buf);
                    on_line(&line);
                    buf.clear();
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Spawns the 1-second snapshot stream listener over `daemon.sock`.
pub fn spawn_snapshot_thread(state_dir: PathBuf, tx: mpsc::Sender<UiEvent>, stop: Arc<AtomicBool>) {
    spawn_ipc_stream_thread(
        state_dir,
        IpcRequest::SubscribeSnapshots {
            interval_ms: Some(1000),
        },
        Duration::from_millis(600),
        tx,
        stop,
        |ev| match ev {
            IpcStreamEvent::Snapshot { data } => Some(UiEvent::Snapshot(data)),
            _ => None,
        },
    );
}

/// Spawns the live multiplexed log tail thread over `daemon.sock`.
pub fn spawn_log_thread(state_dir: PathBuf, tx: mpsc::Sender<UiEvent>, stop: Arc<AtomicBool>) {
    spawn_ipc_stream_thread(
        state_dir,
        IpcRequest::SubscribeLogs {
            node: None,
            min_level: Some("DEBUG".to_string()),
            tail: Some(150),
        },
        Duration::from_millis(600),
        tx,
        stop,
        |ev| match ev {
            IpcStreamEvent::Log {
                node, level, line, ..
            } => Some(UiEvent::Log(LogLineItem { node, level, line })),
            _ => None,
        },
    );
}

fn spawn_xray_thread(state_dir: PathBuf, tx: mpsc::Sender<UiEvent>, stop: Arc<AtomicBool>) {
    spawn_ipc_stream_thread(
        state_dir,
        IpcRequest::SubscribeXray {
            rate_limit_per_sec: Some(100),
        },
        Duration::from_millis(400),
        tx,
        stop,
        |ev| match ev {
            IpcStreamEvent::Xray { data } => Some(UiEvent::Xray(data)),
            _ => None,
        },
    );
}
