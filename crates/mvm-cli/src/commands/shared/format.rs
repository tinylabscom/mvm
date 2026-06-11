//! Pure formatters — no I/O, no allocation outside the returned string.

pub fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Human-readable age from a whole-second duration: `45s`, `12m`, `3h`,
/// `9d`. Coarse by design — cache/blob ages (`cache info` / `doctor`)
/// want a glanceable single unit, not compound or sub-second precision.
pub fn human_age_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_age_picks_the_right_coarse_unit() {
        assert_eq!(human_age_secs(0), "0s");
        assert_eq!(human_age_secs(45), "45s");
        assert_eq!(human_age_secs(59), "59s");
        assert_eq!(human_age_secs(60), "1m");
        assert_eq!(human_age_secs(3599), "59m");
        assert_eq!(human_age_secs(3600), "1h");
        assert_eq!(human_age_secs(86_399), "23h");
        assert_eq!(human_age_secs(86_400), "1d");
        assert_eq!(human_age_secs(9 * 86_400), "9d");
    }
}
