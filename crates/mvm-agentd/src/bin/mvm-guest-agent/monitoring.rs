//! System monitoring: load-average sampling and the background busy/idle loop.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::globals::{HOT_BUSY_THRESHOLD_BITS, HOT_SAMPLE_INTERVAL_SECS};
use crate::state::AgentState;

/// Read 1-minute load average from /proc/loadavg.
fn sample_load() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

/// Format current UTC time as ISO 8601.
pub(crate) fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Convert epoch seconds to UTC date/time components.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Days since 1970-01-01 to (year, month, day).
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    )
}

/// Background monitoring loop — samples /proc/loadavg at the configured interval.
///
/// Reads `HOT_BUSY_THRESHOLD_BITS` and `HOT_SAMPLE_INTERVAL_SECS`
/// on every iteration so a SIGHUP-driven reload picks up on the next
/// sample without restarting the loop.
pub(crate) fn monitoring_loop(state: Arc<Mutex<AgentState>>) {
    loop {
        let load = sample_load();
        let busy_threshold = f64::from_bits(HOT_BUSY_THRESHOLD_BITS.load(Ordering::Acquire));
        if let Ok(mut s) = state.lock() {
            if load >= busy_threshold {
                s.status = "busy".to_string();
                s.last_busy_at = Some(utc_now());
            } else {
                s.status = "idle".to_string();
            }
        }
        let interval_secs = HOT_SAMPLE_INTERVAL_SECS.load(Ordering::Acquire).max(1); // never sleep 0 — busy-spin would peg a CPU
        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}
