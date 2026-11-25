//! The wall clock of the service, with a per-thread override (S-STORE-004).
//!
//! [CANTON-NOTE: SEMANTICS] A ledger that is rebuilt by replaying its request log (`store.rs`) must see, while a request is
//! replayed, the time at which the request was first served: record times, dedup periods and offsets of the rebuilt state
//! have to equal the original ones. Every place that reads the time goes through this module. While a request is served
//! under a persistent store, the time is fixed to one instant for the whole request, in the live run and in the replay alike,
//! so the two runs cannot differ by the microseconds a request takes.
use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static FIXED: Cell<Option<i64>> = const { Cell::new(None) };
}

/// Microseconds the clock has been moved forward by `advance` (a simulation hook: tests let time pass without sleeping).
static SKEW: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// Moves the service clock forward. Only simulations and tests call this; it is process-wide and never goes back.
pub fn advance(micros: i64) {
    SKEW.fetch_add(micros.max(0), std::sync::atomic::Ordering::SeqCst);
}

/// The system clock in microseconds since the epoch, ignoring any override (but not `advance`).
pub fn real_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
        + SKEW.load(std::sync::atomic::Ordering::SeqCst)
}

/// The current time in microseconds: the fixed instant while a request is served under a store, else the system clock.
pub fn now_micros() -> i64 {
    FIXED.with(Cell::get).unwrap_or_else(real_micros)
}

/// The current time in whole seconds (see `now_micros`).
pub fn now_secs() -> u64 {
    (now_micros() / 1_000_000).max(0) as u64
}

/// Runs `f` with the clock fixed at `micros`, restoring the previous setting afterwards (also when `f` unwinds).
pub fn with_fixed<R>(micros: i64, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<i64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FIXED.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(FIXED.with(|c| c.replace(Some(micros))));
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_overrides_and_restores() {
        let outer = with_fixed(5_000_000, || {
            assert_eq!(now_micros(), 5_000_000);
            assert_eq!(now_secs(), 5);
            with_fixed(7_000_000, now_micros)
        });
        assert_eq!(outer, 7_000_000);
        assert!(now_micros() > 1_000_000_000_000_000); // the real clock again
    }
}
