//! Idle timer (REQ-LOCK-002, REQ-LOCK-005, REQ-LOCK-006).

use std::time::Duration;

/// Monotonic idle deadline bookkeeping. Times are `UiClock::now()` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleTimer {
    pub timeout: Duration,
    pub last_activity: Duration,
}

impl IdleTimer {
    pub fn new(timeout: Duration, now: Duration) -> Self {
        IdleTimer {
            timeout,
            last_activity: now,
        }
    }

    /// Record activity at `now`.
    pub fn touch(&mut self, now: Duration) {
        self.last_activity = now;
    }

    /// True once `timeout` has elapsed since the last activity. A clock that
    /// went backwards never expires the timer.
    pub fn expired(&self, now: Duration) -> bool {
        now.saturating_sub(self.last_activity) >= self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn expires_at_timeout_and_touch_resets() {
        let mut t = IdleTimer::new(s(300), s(10));
        assert!(!t.expired(s(309)));
        assert!(t.expired(s(310)));
        t.touch(s(309));
        assert!(!t.expired(s(500)));
        assert!(t.expired(s(609)));
    }

    #[test]
    fn set_timeout_applies_to_existing_activity() {
        let mut t = IdleTimer::new(s(300), s(0));
        assert!(!t.expired(s(100)));
        t.set_timeout(s(60));
        assert!(t.expired(s(100)));
    }

    #[test]
    fn backwards_clock_does_not_expire() {
        let t = IdleTimer::new(s(10), s(100));
        assert!(!t.expired(s(5)));
    }
}
