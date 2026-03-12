use std::thread;
use std::time::Duration;

use anyhow::Result;
use tracing::warn;

/// Retry a fallible operation with exponential backoff.
///
/// - `max_attempts`: Total attempts (including the first).
/// - `base_delay`: Delay after first failure, doubled on each subsequent failure.
/// - `label`: Description for log messages.
/// - `f`: The closure to retry.
pub fn retry<F, T>(max_attempts: u32, base_delay: Duration, label: &str, f: F) -> Result<T>
where
    F: Fn() -> Result<T>,
{
    let mut last_err = None;
    let mut delay = base_delay;

    for attempt in 1..=max_attempts {
        match f() {
            Ok(val) => return Ok(val),
            Err(e) => {
                if attempt < max_attempts {
                    warn!(
                        attempt,
                        max_attempts,
                        delay_ms = delay.as_millis() as u64,
                        error = %e,
                        "{} failed, retrying",
                        label,
                    );
                    thread::sleep(delay);
                    delay *= 2;
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.expect("retry loop must have recorded at least one error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn test_retry_succeeds_first_try() {
        let result = retry(3, Duration::from_millis(1), "test", || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_retry_succeeds_after_failures() {
        let count = Cell::new(0);
        let result = retry(3, Duration::from_millis(1), "test", || {
            let c = count.get() + 1;
            count.set(c);
            if c < 3 {
                anyhow::bail!("not yet");
            }
            Ok(c)
        });
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_retry_exhausts_all_attempts() {
        let count = Cell::new(0);
        let result: Result<i32> = retry(3, Duration::from_millis(1), "test", || {
            count.set(count.get() + 1);
            anyhow::bail!("always fails");
        });
        assert!(result.is_err());
        assert_eq!(count.get(), 3);
    }

    #[test]
    fn test_retry_single_attempt() {
        let result: Result<i32> = retry(1, Duration::from_millis(1), "test", || {
            anyhow::bail!("fail");
        });
        assert!(result.is_err());
    }
}
