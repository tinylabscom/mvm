//! Pure formatters — no I/O, no allocation outside the returned string.

pub(crate) use mvm_client::cli_image::human_bytes;

/// Human-readable age from a whole-second duration: `45s`, `12m`, `3h`,
/// `9d`. Coarse by design — cache/blob ages (`cache info` / `doctor`)
/// want a glanceable single unit, not compound or sub-second precision.
pub(crate) fn human_age_secs(secs: u64) -> String {
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
