//! Time source for the UI, replaceable in tests.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Monotonic and wall-clock time.
pub trait UiClock {
    /// Monotonic time since the clock started.
    fn now(&self) -> Duration;
    /// Seconds since the Unix epoch.
    fn unix_secs(&self) -> u64;
}

/// The real clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemUiClock {
    start: Instant,
}

impl SystemUiClock {
    pub fn new() -> Self {
        SystemUiClock {
            start: Instant::now(),
        }
    }
}

impl Default for SystemUiClock {
    fn default() -> Self {
        Self::new()
    }
}

impl UiClock for SystemUiClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }

    fn unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

#[derive(Debug, Default)]
struct Inner {
    now: Duration,
    unix: u64,
}

/// A clock that only moves when told to. Clones share the same time.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    inner: Arc<Mutex<Inner>>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Move both the monotonic and the wall clock forward without sleeping.
    pub fn advance(&self, by: Duration) {
        let mut g = self.guard();
        g.now = g.now.saturating_add(by);
        g.unix = g.unix.saturating_add(by.as_secs());
    }

    pub fn set_unix(&self, secs: u64) {
        self.guard().unix = secs;
    }
}

impl UiClock for ManualClock {
    fn now(&self) -> Duration {
        self.guard().now
    }

    fn unix_secs(&self) -> u64 {
        self.guard().unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_without_sleeping() {
        let c = ManualClock::new();
        let shared = c.clone();
        c.set_unix(1_000);
        assert_eq!(c.now(), Duration::ZERO);
        shared.advance(Duration::from_secs(3600));
        assert_eq!(c.now(), Duration::from_secs(3600));
        assert_eq!(c.unix_secs(), 4_600);
    }

    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemUiClock::new();
        let a = c.now();
        assert!(c.now() >= a);
        assert!(c.unix_secs() > 1_600_000_000);
    }
}
