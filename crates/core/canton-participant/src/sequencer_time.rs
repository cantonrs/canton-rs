//! When a participant asks the sequencer for the time, and when it acknowledges what it has read.
//!
//! [CANTON-NOTE: SEMANTICS] `SynchronizerTimeTracker` and `PeriodicAcknowledgements`, read as a specification:
//! - A participant that waits for the synchronizer's time to pass a point (a max sequencing time, a decision time) and sees no event asks
//!   for a **time proof**: an empty batch to itself, whose event carries the synchronizer's time (`TimeProof.sendRequest`). It asks once its
//!   own clock is `observationLatency` (250 ms) past that point and nothing was received for `patienceDuration` (500 ms); one request is
//!   outstanding at a time and is asked again after `maxSequencingDelay` (10 s) without an answer (`TimeProofRequestSubmitter`).
//! - It acknowledges the timestamp of the last event it handled cleanly at the start and then every `acknowledgementInterval` (1 min),
//!   when that changed and the subscription is healthy.
//!
//! [CANTON-NOTE: LIMITATION] The host clock is compared with the synchronizer's times as Canton does (it assumes they are roughly in step);
//! the decisions are checked whenever the node reads the stream, not on a timer of their own.
use std::time::{Duration, Instant};

/// `SynchronizerTimeTrackerConfig.observationLatency`.
pub const OBSERVATION_LATENCY: Duration = Duration::from_millis(250);
/// `SynchronizerTimeTrackerConfig.patienceDuration`.
pub const PATIENCE: Duration = Duration::from_millis(500);
/// `TimeProofRequestConfig.maxSequencingDelay`: how long a time proof request may go unanswered before it is sent again.
pub const MAX_SEQUENCING_DELAY: Duration = Duration::from_secs(10);
/// `TimeProofRequestConfig.requestTimeout`: the max sequencing time of a time proof request, from now.
pub const TIME_PROOF_EXPIRY_MICROS: i64 = 120_000_000;
/// `SequencerClientConfig.acknowledgementInterval`.
pub const ACKNOWLEDGEMENT_INTERVAL: Duration = Duration::from_secs(60);

/// What the participant knows of the synchronizer's clock and its own requests for it.
#[derive(Debug)]
pub struct TimeKeeper {
    /// When the last event was received (the host's clock), and the cursor it moved to.
    last_received: Instant,
    last_cursor: i64,
    /// When the time proof that is still unanswered was asked for.
    proof_asked: Option<Instant>,
    /// The timestamp acknowledged last, and when the next acknowledgement is due.
    acknowledged: Option<i64>,
    next_acknowledgement: Instant,
}

impl TimeKeeper {
    /// A participant that starts now at `cursor`: its first acknowledgement is due at once.
    pub fn new(now: Instant, cursor: i64) -> Self {
        TimeKeeper {
            last_received: now,
            last_cursor: cursor,
            proof_asked: None,
            acknowledged: None,
            next_acknowledgement: now,
        }
    }

    /// The cursor is now `cursor`: an event that moved it is an observed time, and it answers the time proof asked for.
    pub fn observed(&mut self, now: Instant, cursor: i64) {
        if cursor > self.last_cursor {
            self.last_cursor = cursor;
            self.last_received = now;
            self.proof_asked = None;
        }
    }

    /// Whether to ask for a time proof now: the participant waits to observe `wanted` (a time of the synchronizer, see
    /// `InFlight::wanted_time`), has observed up to `cursor`, and its own clock reads `wall_micros`. Records the request when it says yes.
    pub fn ask_for_time(
        &mut self,
        now: Instant,
        wall_micros: i64,
        cursor: i64,
        wanted: Option<i64>,
    ) -> bool {
        let Some(wanted) = wanted.filter(|w| *w > cursor) else {
            self.proof_asked = None;
            return false;
        };
        let latency = i64::try_from(OBSERVATION_LATENCY.as_micros()).unwrap_or(i64::MAX);
        let due = wall_micros >= wanted.saturating_add(latency)
            && now.saturating_duration_since(self.last_received) >= PATIENCE
            && self
                .proof_asked
                .is_none_or(|at| now.saturating_duration_since(at) >= MAX_SEQUENCING_DELAY);
        if due {
            self.proof_asked = Some(now);
        }
        due
    }

    /// The timestamp to acknowledge now, if one is due: `cursor` when it changed since the last acknowledgement and the subscription is
    /// `healthy`. Records it as acknowledged when it says one.
    pub fn acknowledgement(&mut self, now: Instant, cursor: i64, healthy: bool) -> Option<i64> {
        if now < self.next_acknowledgement {
            return None;
        }
        self.next_acknowledgement = now + ACKNOWLEDGEMENT_INTERVAL;
        if !healthy || self.acknowledged == Some(cursor) {
            return None;
        }
        self.acknowledged = Some(cursor);
        Some(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i64 = 1_000_000;

    #[test]
    fn a_time_proof_is_asked_for_once_the_wanted_time_is_past_on_the_host_clock_and_nothing_came() {
        let start = Instant::now();
        let mut keeper = TimeKeeper::new(start, 0);
        let wanted = Some(10 * SECOND);
        assert!(
            !keeper.ask_for_time(start + PATIENCE, 10 * SECOND, 0, wanted),
            "not before the observation latency"
        );
        assert!(keeper.ask_for_time(start + PATIENCE, 10 * SECOND + 250_000, 0, wanted));
        assert!(
            !keeper.ask_for_time(start + Duration::from_secs(5), 11 * SECOND, 0, wanted),
            "one request is outstanding"
        );
        assert!(
            keeper.ask_for_time(start + Duration::from_secs(11), 12 * SECOND, 0, wanted),
            "asked again after the max sequencing delay"
        );
    }

    #[test]
    fn no_time_proof_while_events_come_or_when_nothing_is_awaited() {
        let start = Instant::now();
        let mut keeper = TimeKeeper::new(start, 0);
        let later = start + Duration::from_secs(3);
        keeper.observed(later, 5 * SECOND);
        assert!(
            !keeper.ask_for_time(
                later + Duration::from_millis(100),
                20 * SECOND,
                5 * SECOND,
                Some(10 * SECOND)
            ),
            "an event came within the patience"
        );
        assert!(!keeper.ask_for_time(later + PATIENCE, 20 * SECOND, 5 * SECOND, None));
        assert!(
            !keeper.ask_for_time(
                later + PATIENCE,
                20 * SECOND,
                10 * SECOND,
                Some(10 * SECOND)
            ),
            "the wanted time is observed already"
        );
    }

    #[test]
    fn the_cursor_is_acknowledged_at_the_start_and_then_each_interval_when_it_changed() {
        let start = Instant::now();
        let mut keeper = TimeKeeper::new(start, 7);
        assert_eq!(keeper.acknowledgement(start, 7, true), Some(7));
        assert_eq!(
            keeper.acknowledgement(start + Duration::from_secs(1), 9, true),
            None
        );
        let next = start + ACKNOWLEDGEMENT_INTERVAL;
        assert_eq!(keeper.acknowledgement(next, 7, true), None, "unchanged");
        let after = next + ACKNOWLEDGEMENT_INTERVAL;
        assert_eq!(keeper.acknowledgement(after, 9, false), None, "unhealthy");
        assert_eq!(
            keeper.acknowledgement(after + ACKNOWLEDGEMENT_INTERVAL, 9, true),
            Some(9)
        );
    }
}
