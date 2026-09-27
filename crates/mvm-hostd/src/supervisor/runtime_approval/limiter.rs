//! How many prompts one VM may raise.
//!
//! A workload that can trigger an `ask` can trigger thousands, and a person
//! answering them is the resource being spent. Past the limit, a question is
//! denied without being put to anyone, and the denial is recorded.

use std::collections::VecDeque;
use std::time::Duration;

/// At most `max` prompts in any `window`, measured on a millisecond clock.
#[derive(Debug)]
pub(super) struct PromptLimiter {
    max: usize,
    window_ms: u64,
    recent: VecDeque<u64>,
}

impl PromptLimiter {
    pub(super) fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            recent: VecDeque::with_capacity(max),
        }
    }

    /// Take a slot at `now_ms`, or `false` when the window is full.
    pub(super) fn try_take(&mut self, now_ms: u64) -> bool {
        while self
            .recent
            .front()
            .is_some_and(|&at| now_ms.saturating_sub(at) >= self.window_ms)
        {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.max {
            return false;
        }
        self.recent.push_back(now_ms);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_admits_max_then_refuses_until_it_slides() {
        let mut limiter = PromptLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.try_take(0));
        assert!(limiter.try_take(1_000));
        assert!(limiter.try_take(2_000));
        assert!(!limiter.try_take(3_000), "a fourth inside the window");
        assert!(!limiter.try_take(59_999));
        assert!(limiter.try_take(60_000), "the first slot has aged out");
        assert!(!limiter.try_take(60_001));
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        assert!(!PromptLimiter::new(0, Duration::from_secs(1)).try_take(0));
    }
}
