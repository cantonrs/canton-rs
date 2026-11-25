//! The time the mediators inside the sequencer may take as passed.
//!
//! [CANTON-NOTE: SEMANTICS] A mediator times a request out at the first sequencing time it observes after the request's deadline, and it
//! observes the times in order: every event before that time was handled first (`MediatorEventsProcessor`). The mediators inside the
//! sequencer are shown a submission after the lock that gave it its timestamp is released, while the expiry timer reads the sequencer's
//! clock on a task of its own. The timer may therefore take a time as passed only up to the first submission addressed to a mediator group
//! that is sequenced and not yet shown to the mediators: an answer sequenced before the deadline is never beaten by the time-out.
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The timestamps of the submissions addressed to a mediator group that are sequenced and not yet shown to the mediators.
#[derive(Default)]
pub(crate) struct MediatorClock {
    unshown: Mutex<BTreeMap<i64, usize>>,
}

/// A submission sequenced at a timestamp and not yet shown to the mediators; dropping it marks it shown.
pub(crate) struct Unshown<'a> {
    clock: &'a MediatorClock,
    timestamp: i64,
}

impl Drop for Unshown<'_> {
    fn drop(&mut self) {
        let mut unshown = self
            .clock
            .unshown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = unshown.get_mut(&self.timestamp) {
            *count -= 1;
            if *count == 0 {
                unshown.remove(&self.timestamp);
            }
        }
    }
}

impl MediatorClock {
    /// A submission addressed to a mediator group was sequenced at `timestamp`. Called while the events are locked, where the timestamp is
    /// given; the mediators are shown it before the returned value is dropped.
    pub(crate) fn sequenced(&self, timestamp: i64) -> Unshown<'_> {
        *self
            .unshown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(timestamp)
            .or_default() += 1;
        Unshown {
            clock: self,
            timestamp,
        }
    }

    /// The time the mediators may take as passed when the sequencer's clock reads `now` (read while the events are locked): `now`, or the
    /// first submission they have not been shown yet, which times out what is due before it when it is shown.
    pub(crate) fn passed(&self, now: i64) -> i64 {
        self.unshown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .next()
            .map_or(now, |first| now.min(*first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_time_passed_stops_at_a_submission_the_mediators_have_not_been_shown() {
        let clock = MediatorClock::default();
        assert_eq!(clock.passed(100), 100);
        let answer = clock.sequenced(40);
        let same_time = clock.sequenced(40);
        let later = clock.sequenced(70);
        assert_eq!(clock.passed(100), 40, "not past an answer still in flight");
        drop(answer);
        assert_eq!(
            clock.passed(100),
            40,
            "another one at that time is in flight"
        );
        drop(same_time);
        assert_eq!(clock.passed(100), 70);
        drop(later);
        assert_eq!(clock.passed(100), 100);
        assert_eq!(clock.passed(30), 30, "never past the clock");
    }
}
