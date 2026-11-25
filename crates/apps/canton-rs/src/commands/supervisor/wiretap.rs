//! Production-safe Zero-Payload Wiretap (`DiagnosticEvent`) and 4-Hop Protocol X-Ray coordinator.
//!
//! [CANTON-NOTE: INVARIANT] Overhead is zero when inactive (`WIRE_TAP_ACTIVE == false` checked via a
//! single `Relaxed` load), publication is strictly non-blocking (`try_send` drop-first), and no contract
//! payload bytes exist anywhere in `XRayTraceEvent`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use super::{
    now_unix_ms, now_unix_secs, BlindedViewQuorum, InformeeVote, QuorumVerdictState, VoteStatus,
    XRayTraceEvent, DEFAULT_TRACE_RATE_LIMIT,
};

/// Global lock-free gate: hot protocol/participant paths skip wiretap assembly unless active.
pub static WIRE_TAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Live subscriptions across all hubs; `WIRE_TAP_ACTIVE` is only written while this is held,
/// so a late "last one out" store can never close the gate under a fresh subscriber.
static GATE_SUBSCRIBERS: Mutex<usize> = Mutex::new(0);

fn adjust_gate(open: bool) {
    let mut n = GATE_SUBSCRIBERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *n = if open {
        n.saturating_add(1)
    } else {
        n.saturating_sub(1)
    };
    WIRE_TAP_ACTIVE.store(*n > 0, Ordering::SeqCst);
}

const MAX_STORED_TRACES: usize = 512;
const BROADCAST_CAP: usize = 256;

/// RAII subscription guard keeping `WIRE_TAP_ACTIVE` enabled only while consumers listen.
pub struct WiretapSubscription {
    pub receiver: broadcast::Receiver<XRayTraceEvent>,
    hub: Arc<WiretapInner>,
}

impl Drop for WiretapSubscription {
    fn drop(&mut self) {
        self.hub.subscribers.fetch_sub(1, Ordering::SeqCst);
        adjust_gate(false);
    }
}

struct RateWindow {
    sec: u64,
    emitted_normal: u32,
    emitted_anomaly: u32,
}

struct WiretapInner {
    subscribers: AtomicUsize,
    dropped_events: AtomicU64,
    rate_limit_per_sec: AtomicU32,
    rate_window: Mutex<RateWindow>,
    recent: Mutex<VecDeque<XRayTraceEvent>>,
    sender: broadcast::Sender<XRayTraceEvent>,
}

/// Thread-safe Zero-Payload X-Ray wiretap hub owned by the supervisor engine.
#[derive(Clone)]
pub struct WiretapHub {
    inner: Arc<WiretapInner>,
}

impl Default for WiretapHub {
    fn default() -> Self {
        Self::new(DEFAULT_TRACE_RATE_LIMIT)
    }
}

impl WiretapHub {
    /// Creates a hub capped at `rate_limit_per_sec` normal trace emissions per second.
    pub fn new(rate_limit_per_sec: u32) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            inner: Arc::new(WiretapInner {
                subscribers: AtomicUsize::new(0),
                dropped_events: AtomicU64::new(0),
                rate_limit_per_sec: AtomicU32::new(rate_limit_per_sec.max(1)),
                rate_window: Mutex::new(RateWindow {
                    sec: 0,
                    emitted_normal: 0,
                    emitted_anomaly: 0,
                }),
                recent: Mutex::new(VecDeque::with_capacity(MAX_STORED_TRACES)),
                sender,
            }),
        }
    }

    /// Updates the `--trace-rate-limit` ceiling dynamically.
    pub fn set_rate_limit(&self, per_sec: u32) {
        self.inner
            .rate_limit_per_sec
            .store(per_sec.max(1), Ordering::Relaxed);
    }

    /// Activates the wiretap gate and returns an RAII stream subscription.
    pub fn subscribe(&self) -> WiretapSubscription {
        self.inner.subscribers.fetch_add(1, Ordering::SeqCst);
        adjust_gate(true);
        WiretapSubscription {
            receiver: self.inner.sender.subscribe(),
            hub: Arc::clone(&self.inner),
        }
    }

    /// Returns cumulative number of events dropped by rate limiting or slow subscribers.
    pub fn dropped_total(&self) -> u64 {
        self.inner.dropped_events.load(Ordering::Relaxed)
    }

    /// Publishes an `XRayTraceEvent` non-blockingly (`try_lock` / drop-first).
    pub fn record_trace(&self, event: XRayTraceEvent) {
        if let Ok(mut guard) = self.inner.recent.try_lock() {
            if let Some(pos) = guard.iter().position(|t| t.root_hash == event.root_hash) {
                guard[pos] = event.clone();
            } else {
                if guard.len() >= MAX_STORED_TRACES {
                    guard.pop_front();
                }
                guard.push_back(event.clone());
            }
        } else {
            self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
        }

        if self.inner.subscribers.load(Ordering::Relaxed) == 0 {
            return;
        }
        if !self.allow_rate(&event) {
            self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.inner.sender.send(event).is_err() {
            self.inner.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn allow_rate(&self, event: &XRayTraceEvent) -> bool {
        let cap = self.inner.rate_limit_per_sec.load(Ordering::Relaxed);
        let now = now_unix_secs();
        let Ok(mut win) = self.inner.rate_window.try_lock() else {
            return false;
        };
        if win.sec != now {
            win.sec = now;
            win.emitted_normal = 0;
            win.emitted_anomaly = 0;
        }
        if event.mediator_verdict.is_anomaly() {
            // Rejections and timeouts get their own budget so normal traffic cannot crowd them out.
            if win.emitted_anomaly >= cap {
                return false;
            }
            win.emitted_anomaly += 1;
            return true;
        }
        if win.emitted_normal >= cap {
            return false;
        }
        win.emitted_normal += 1;
        true
    }

    /// Looks up a trace by exact or prefix `root_hash` (or returns latest trace if `"latest"`).
    pub fn lookup(&self, root_hash: &str) -> Option<XRayTraceEvent> {
        let guard = self.inner.recent.lock().ok()?;
        let needle = root_hash.trim();
        if needle.is_empty() || needle.eq_ignore_ascii_case("latest") {
            return guard.back().cloned();
        }
        guard
            .iter()
            .rev()
            .find(|t| t.root_hash == needle || t.root_hash.starts_with(needle))
            .cloned()
    }

    /// Lists up to `limit` most recent stored traces (newest last).
    pub fn recent(&self, limit: usize) -> Vec<XRayTraceEvent> {
        let Ok(guard) = self.inner.recent.lock() else {
            return Vec::new();
        };
        let skip = guard.len().saturating_sub(limit);
        guard.iter().skip(skip).cloned().collect()
    }
}

/// Converts a participant `GET /_xray` JSON entry + cluster hop context into a Zero-Payload `XRayTraceEvent`.
pub fn assemble_xray_trace(
    raw: &serde_json::Value,
    bft_height: Option<u64>,
    bft_latency_ms: Option<f64>,
    envelope_scale: Option<u64>,
    recipient_override: Option<u32>,
) -> Option<XRayTraceEvent> {
    let root_hash = raw.get("root_hash")?.as_str()?.to_string();
    let started_at_unix_ms = raw
        .get("started_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(now_unix_ms);
    let submitter_participant = raw
        .get("submitter_participant")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("participant")
        .to_string();
    let package_id = raw
        .get("package_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let template_qualified_name = raw
        .get("template_qualified_name")
        .and_then(serde_json::Value::as_str)
        .map(String::from);
    let daml_eval_us = raw
        .get("daml_eval_us")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let blinded_view_count = raw
        .get("blinded_view_count")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1);
    let sealed_envelope_bytes = raw
        .get("sealed_envelope_bytes")
        .and_then(serde_json::Value::as_u64)
        .or(envelope_scale)
        .unwrap_or(256);
    let traffic_cost_bytes = raw
        .get("traffic_cost_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(sealed_envelope_bytes);
    let recipient_member_count = recipient_override.unwrap_or_else(|| {
        raw.get("recipient_member_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1)
    });
    let mediator_verdict = match raw
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("pending")
    {
        "approved" => QuorumVerdictState::Approved,
        "rejected" => QuorumVerdictState::Rejected,
        "timed_out" => QuorumVerdictState::TimedOut,
        _ => QuorumVerdictState::Pending,
    };
    let total_latency_ms = raw
        .get("total_latency_ms")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);

    let views = raw
        .get("views")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let view_hash = v.get("view_hash")?.as_str()?.to_string();
                    let threshold = v
                        .get("threshold")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or(1);
                    let latency = v
                        .get("latency_ms")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(total_latency_ms);
                    let informees = v
                        .get("approved_parties")
                        .and_then(serde_json::Value::as_array)
                        .map(|parties| {
                            parties
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .map(|party| InformeeVote {
                                    party_id: party.to_string(),
                                    vote: match mediator_verdict {
                                        QuorumVerdictState::Approved => VoteStatus::Approved {
                                            latency_ms: latency,
                                        },
                                        QuorumVerdictState::Rejected => VoteStatus::Rejected {
                                            code: "MEDIATOR_REJECTED".to_string(),
                                        },
                                        _ => VoteStatus::Pending {
                                            elapsed_ms: latency,
                                        },
                                    },
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(BlindedViewQuorum {
                        view_hash,
                        threshold,
                        informees,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(XRayTraceEvent {
        root_hash,
        started_at_unix_ms,
        submitter_participant,
        package_id,
        template_qualified_name,
        daml_eval_us,
        blinded_view_count,
        sealed_envelope_bytes,
        traffic_cost_bytes,
        recipient_member_count,
        bft_block_height: bft_height,
        bft_order_latency_ms: bft_latency_ms,
        mediator_verdict,
        total_latency_ms,
        views,
    })
}

/// Formats one `XRayTraceEvent` in readable CLI detail for `canton-rs daemon inspect --trace`.
pub fn render_trace_text(trace: &XRayTraceEvent) -> String {
    let verdict_tag = match trace.mediator_verdict {
        QuorumVerdictState::Approved => "APPROVED",
        QuorumVerdictState::Rejected => "REJECTED",
        QuorumVerdictState::TimedOut => "TIMED_OUT",
        QuorumVerdictState::Pending => "PENDING_QUORUM",
    };
    let mut lines = vec![
        format!(
            "Protocol X-Ray Trace [ZERO-KNOWLEDGE BOUNDARY: SEALED]\nRootHash : {}\nTotal    : {:.2} ms | Verdict: {verdict_tag}",
            trace.root_hash, trace.total_latency_ms
        ),
        format!(
            "  [1. Participant]  {} | pkg: {} | tmpl: {} | eval: {} us | {} blinded view(s)",
            trace.submitter_participant,
            trace.package_id,
            trace.template_qualified_name.as_deref().unwrap_or("-"),
            trace.daml_eval_us,
            trace.blinded_view_count
        ),
        format!(
            "  [2. Sequencer]    envelope: [SEALED {} B] | traffic: -{} B | recipients: {} member(s)",
            trace.sealed_envelope_bytes, trace.traffic_cost_bytes, trace.recipient_member_count
        ),
        format!(
            "  [3. BFT Orderer]  block: {} | finality: {}",
            trace
                .bft_block_height
                .map_or_else(|| "single-node".into(), |h| format!("#{h}")),
            trace
                .bft_order_latency_ms
                .map_or_else(|| "-".into(), |ms| format!("{ms:.2} ms"))
        ),
    ];
    for view in &trace.views {
        let votes: BTreeMap<&str, String> = view
            .informees
            .iter()
            .map(|inf| {
                let s = match &inf.vote {
                    VoteStatus::Approved { latency_ms } => format!("Approve ({latency_ms:.1}ms)"),
                    VoteStatus::Rejected { code } => format!("Reject ({code})"),
                    VoteStatus::Pending { elapsed_ms } => format!("Pending ({elapsed_ms:.0}ms)"),
                };
                (inf.party_id.as_str(), s)
            })
            .collect();
        let joined: Vec<String> = votes
            .into_iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        lines.push(format!(
            "  [4. Mediator 2PC] {} (threshold={}) -> {}",
            view.view_hash,
            view.threshold,
            joined.join(", ")
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that assert the process-wide gate closes must not overlap.
    static GATE_TESTS: Mutex<()> = Mutex::new(());

    fn sample_trace(hash: &str, verdict: QuorumVerdictState) -> XRayTraceEvent {
        XRayTraceEvent {
            root_hash: hash.to_string(),
            started_at_unix_ms: now_unix_ms(),
            submitter_participant: "p1".to_string(),
            package_id: "pkg1".to_string(),
            template_qualified_name: Some("Asset:Holding".to_string()),
            daml_eval_us: 120,
            blinded_view_count: 1,
            sealed_envelope_bytes: 512,
            traffic_cost_bytes: 512,
            recipient_member_count: 2,
            bft_block_height: Some(10),
            bft_order_latency_ms: Some(2.1),
            mediator_verdict: verdict,
            total_latency_ms: 4.5,
            views: vec![],
        }
    }

    #[test]
    fn wiretap_gate_and_rate_limiter_prioritize_anomalies() {
        let _serial = GATE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hub = WiretapHub::new(2);
        {
            let mut sub = hub.subscribe();
            assert!(WIRE_TAP_ACTIVE.load(Ordering::SeqCst));
            hub.record_trace(sample_trace("1220a", QuorumVerdictState::Approved));
            hub.record_trace(sample_trace("1220b", QuorumVerdictState::Approved));
            // 3rd normal trace in the same second is rate-limited/dropped.
            hub.record_trace(sample_trace("1220c", QuorumVerdictState::Approved));
            // Anomaly trace must still pass priority gate!
            hub.record_trace(sample_trace("1220d", QuorumVerdictState::Rejected));

            assert_eq!(hub.dropped_total(), 1);
            assert!(hub.lookup("1220b").is_some());
            let mut got = Vec::new();
            while let Ok(ev) = sub.receiver.try_recv() {
                got.push(ev.root_hash);
            }
            assert_eq!(got, vec!["1220a", "1220b", "1220d"]);
        }
        assert!(!WIRE_TAP_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn anomaly_traces_have_their_own_bounded_budget() {
        let _serial = GATE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hub = WiretapHub::new(3);
        let mut sub = hub.subscribe();
        for i in 0..50 {
            hub.record_trace(sample_trace(
                &format!("1220r{i}"),
                QuorumVerdictState::Rejected,
            ));
        }
        let mut delivered = 0;
        while sub.receiver.try_recv().is_ok() {
            delivered += 1;
        }
        // A second boundary between sends may open one more window.
        assert!(
            (3..=6).contains(&delivered),
            "{delivered} anomaly traces delivered with a limit of 3 per second"
        );
    }

    #[test]
    fn the_gate_stays_open_while_any_subscriber_listens() {
        let _serial = GATE_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hub = WiretapHub::new(10);
        let closed_while_held = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let hub = hub.clone();
                let closed = Arc::clone(&closed_while_held);
                std::thread::spawn(move || {
                    for _ in 0..20_000 {
                        let sub = hub.subscribe();
                        if !WIRE_TAP_ACTIVE.load(Ordering::SeqCst) {
                            closed.fetch_add(1, Ordering::SeqCst);
                        }
                        drop(sub);
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().expect("worker");
        }
        let held = hub.subscribe();
        assert!(WIRE_TAP_ACTIVE.load(Ordering::SeqCst));
        drop(held);
        assert_eq!(
            closed_while_held.load(Ordering::SeqCst),
            0,
            "the gate read closed while the reader held a subscription"
        );
    }
}
