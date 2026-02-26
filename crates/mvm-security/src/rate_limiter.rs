use std::collections::VecDeque;
use std::time::{Duration, Instant};

use mvm_core::security::RateLimitPolicy;

/// Outcome of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Frame is allowed through.
    Allowed,
    /// Frame exceeds the per-second limit.
    ExceededPerSecond,
    /// Frame exceeds the per-minute limit.
    ExceededPerMinute,
}

/// Sliding-window rate limiter for vsock frames.
///
/// Tracks frame timestamps in two sliding windows (1-second and 1-minute)
/// and rejects frames that exceed the configured limits. This is a pure
/// data structure with no async runtime dependency — callers drive it
/// by calling `check_and_record()` on each incoming frame.
///
/// Unlimited (0) values in the policy disable that specific window.
pub struct RateLimiter {
    /// Timestamps of frames within the last second.
    second_window: VecDeque<Instant>,
    /// Timestamps of frames within the last minute.
    minute_window: VecDeque<Instant>,
    /// Maximum frames per second (0 = unlimited).
    fps_limit: u32,
    /// Maximum frames per minute (0 = unlimited).
    fpm_limit: u32,
    /// Total frames allowed through.
    pub allowed_count: u64,
    /// Total frames rejected.
    pub rejected_count: u64,
}

impl RateLimiter {
    /// Create a new rate limiter from a policy.
    pub fn new(policy: &RateLimitPolicy) -> Self {
        Self {
            second_window: VecDeque::new(),
            minute_window: VecDeque::new(),
            fps_limit: policy.frames_per_second,
            fpm_limit: policy.frames_per_minute,
            allowed_count: 0,
            rejected_count: 0,
        }
    }

    /// Check whether a frame at the current instant is allowed, and if so,
    /// record it in the sliding windows.
    ///
    /// Returns `Allowed` if the frame passes both windows, or the specific
    /// exceeded limit otherwise.
    pub fn check_and_record(&mut self) -> RateLimitResult {
        self.check_and_record_at(Instant::now())
    }

    /// Check and record at a specific instant (for testing).
    pub fn check_and_record_at(&mut self, now: Instant) -> RateLimitResult {
        self.expire_old(now);

        // Check per-second limit first (tighter window).
        if self.fps_limit > 0 && self.second_window.len() >= self.fps_limit as usize {
            self.rejected_count += 1;
            return RateLimitResult::ExceededPerSecond;
        }

        // Check per-minute limit.
        if self.fpm_limit > 0 && self.minute_window.len() >= self.fpm_limit as usize {
            self.rejected_count += 1;
            return RateLimitResult::ExceededPerMinute;
        }

        // Allowed — record the frame.
        self.second_window.push_back(now);
        self.minute_window.push_back(now);
        self.allowed_count += 1;

        RateLimitResult::Allowed
    }

    /// Remove expired entries from both windows.
    fn expire_old(&mut self, now: Instant) {
        let one_second_ago = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        let one_minute_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);

        while let Some(&front) = self.second_window.front() {
            if front <= one_second_ago {
                self.second_window.pop_front();
            } else {
                break;
            }
        }

        while let Some(&front) = self.minute_window.front() {
            if front <= one_minute_ago {
                self.minute_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Current count of frames in the per-second window.
    pub fn current_fps(&self) -> usize {
        self.second_window.len()
    }

    /// Current count of frames in the per-minute window.
    pub fn current_fpm(&self) -> usize {
        self.minute_window.len()
    }

    /// Whether rate limiting is effectively disabled (both limits are 0).
    pub fn is_unlimited(&self) -> bool {
        self.fps_limit == 0 && self.fpm_limit == 0
    }

    /// Reset all state (windows and counters).
    pub fn reset(&mut self) {
        self.second_window.clear();
        self.minute_window.clear();
        self.allowed_count = 0;
        self.rejected_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(fps: u32, fpm: u32) -> RateLimitPolicy {
        RateLimitPolicy {
            frames_per_second: fps,
            frames_per_minute: fpm,
        }
    }

    #[test]
    fn test_allows_within_limits() {
        let mut rl = RateLimiter::new(&policy(10, 100));
        let now = Instant::now();

        for i in 0..10 {
            let result = rl.check_and_record_at(now + Duration::from_millis(i * 50));
            assert_eq!(
                result,
                RateLimitResult::Allowed,
                "frame {i} should be allowed"
            );
        }
        assert_eq!(rl.allowed_count, 10);
        assert_eq!(rl.rejected_count, 0);
    }

    #[test]
    fn test_exceeds_per_second() {
        let mut rl = RateLimiter::new(&policy(5, 0));
        let now = Instant::now();

        // Fill the per-second window.
        for i in 0..5 {
            let result = rl.check_and_record_at(now + Duration::from_millis(i * 10));
            assert_eq!(result, RateLimitResult::Allowed);
        }

        // 6th frame within the same second should be rejected.
        let result = rl.check_and_record_at(now + Duration::from_millis(100));
        assert_eq!(result, RateLimitResult::ExceededPerSecond);
        assert_eq!(rl.rejected_count, 1);
    }

    #[test]
    fn test_exceeds_per_minute() {
        let mut rl = RateLimiter::new(&policy(0, 5));
        let now = Instant::now();

        // Fill the per-minute window (spread across seconds to avoid FPS limit).
        for i in 0..5 {
            let result = rl.check_and_record_at(now + Duration::from_secs(i));
            assert_eq!(result, RateLimitResult::Allowed);
        }

        // 6th frame within the same minute should be rejected.
        let result = rl.check_and_record_at(now + Duration::from_secs(10));
        assert_eq!(result, RateLimitResult::ExceededPerMinute);
        assert_eq!(rl.rejected_count, 1);
    }

    #[test]
    fn test_window_expiry_allows_after_cooldown() {
        let mut rl = RateLimiter::new(&policy(3, 0));
        let now = Instant::now();

        // Fill the per-second window.
        for i in 0..3 {
            let result = rl.check_and_record_at(now + Duration::from_millis(i * 100));
            assert_eq!(result, RateLimitResult::Allowed);
        }

        // Blocked at t+300ms.
        let result = rl.check_and_record_at(now + Duration::from_millis(300));
        assert_eq!(result, RateLimitResult::ExceededPerSecond);

        // After 1 second, old entries expire and new frames are allowed.
        let result = rl.check_and_record_at(now + Duration::from_millis(1100));
        assert_eq!(result, RateLimitResult::Allowed);
    }

    #[test]
    fn test_minute_window_expiry() {
        let mut rl = RateLimiter::new(&policy(0, 3));
        let now = Instant::now();

        for i in 0..3 {
            let result = rl.check_and_record_at(now + Duration::from_secs(i));
            assert_eq!(result, RateLimitResult::Allowed);
        }

        // Blocked at t+30s.
        let result = rl.check_and_record_at(now + Duration::from_secs(30));
        assert_eq!(result, RateLimitResult::ExceededPerMinute);

        // After 61 seconds from the first frame, it expires.
        let result = rl.check_and_record_at(now + Duration::from_secs(61));
        assert_eq!(result, RateLimitResult::Allowed);
    }

    #[test]
    fn test_unlimited_allows_everything() {
        let mut rl = RateLimiter::new(&policy(0, 0));
        let now = Instant::now();

        assert!(rl.is_unlimited());

        for i in 0..1000 {
            let result = rl.check_and_record_at(now + Duration::from_micros(i));
            assert_eq!(result, RateLimitResult::Allowed);
        }
        assert_eq!(rl.allowed_count, 1000);
        assert_eq!(rl.rejected_count, 0);
    }

    #[test]
    fn test_per_second_checked_before_per_minute() {
        // Both limits set: FPS should trigger first when burst arrives.
        let mut rl = RateLimiter::new(&policy(3, 100));
        let now = Instant::now();

        for i in 0..3 {
            rl.check_and_record_at(now + Duration::from_millis(i * 10));
        }

        let result = rl.check_and_record_at(now + Duration::from_millis(50));
        assert_eq!(result, RateLimitResult::ExceededPerSecond);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut rl = RateLimiter::new(&policy(5, 100));
        let now = Instant::now();

        for i in 0..5 {
            rl.check_and_record_at(now + Duration::from_millis(i * 10));
        }

        assert_eq!(rl.allowed_count, 5);
        assert_eq!(rl.current_fps(), 5);

        rl.reset();

        assert_eq!(rl.allowed_count, 0);
        assert_eq!(rl.rejected_count, 0);
        assert_eq!(rl.current_fps(), 0);
        assert_eq!(rl.current_fpm(), 0);
    }

    #[test]
    fn test_current_fps_fpm_counters() {
        let mut rl = RateLimiter::new(&policy(100, 1000));
        let now = Instant::now();

        for i in 0..10 {
            rl.check_and_record_at(now + Duration::from_millis(i * 50));
        }

        assert_eq!(rl.current_fps(), 10);
        assert_eq!(rl.current_fpm(), 10);

        // After 1.5 seconds (all 10 originals at t+0..t+450 are >1s old), per-second
        // window clears but per-minute retains.
        for i in 0..5 {
            rl.check_and_record_at(now + Duration::from_millis(1500 + i * 50));
        }

        assert_eq!(rl.current_fps(), 5);
        assert_eq!(rl.current_fpm(), 15);
    }

    #[test]
    fn test_default_policy_limits() {
        let rl = RateLimiter::new(&RateLimitPolicy::default());
        assert!(!rl.is_unlimited());
        assert_eq!(rl.current_fps(), 0);
        assert_eq!(rl.current_fpm(), 0);
    }

    #[test]
    fn test_sustained_rate_within_limit() {
        // 10 fps limit, send exactly 10 per second for 3 seconds.
        let mut rl = RateLimiter::new(&policy(10, 0));
        let start = Instant::now();
        let mut allowed = 0u64;

        for second in 0..3u64 {
            for frame in 0..10u64 {
                let t = start + Duration::from_millis(second * 1000 + frame * 100);
                if rl.check_and_record_at(t) == RateLimitResult::Allowed {
                    allowed += 1;
                }
            }
        }

        assert_eq!(allowed, 30);
    }
}
