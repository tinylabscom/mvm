//! `xtask check-deny-ignore-expiry`
//!
//! `deny.toml` keeps its advisory ignore list empty by policy. An exception
//! is allowed only when it carries its own end date and a tracking issue, so
//! a suppression cannot outlive the reason it was granted. Every `ignore`
//! entry must be a table whose `reason` names `expires YYYY-MM-DD` and a
//! `#<issue>`, and the gate fails once the system date is past that day.

use anyhow::{Context, Result, bail};
use regex::Regex;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const DENY_FILE: &str = "deny.toml";

/// A calendar day; the derived order is chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Day {
    year: i64,
    month: u32,
    day: u32,
}

impl Day {
    /// `None` unless the day exists on the proleptic Gregorian calendar.
    fn new(year: i64, month: u32, day: u32) -> Option<Self> {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let last = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        (1..=last)
            .contains(&day)
            .then_some(Self { year, month, day })
    }

    /// The UTC day containing `secs` since the Unix epoch.
    fn from_unix_secs(secs: u64) -> Self {
        // Days-to-civil conversion over 400-year eras.
        let z = i64::try_from(secs / 86_400).expect("a day count fits i64") + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).expect("day of month");
        let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).expect("month");
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self { year, month, day }
    }
}

/// Every problem with the `ignore` list of `deny_toml`, judged on `today`.
fn findings(deny_toml: &str, today: Day) -> Result<Vec<String>> {
    let doc: toml::Table = deny_toml.parse().context("parsing deny.toml")?;
    let ignore = doc
        .get("advisories")
        .and_then(|a| a.get("ignore"))
        .and_then(toml::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let expires = Regex::new(r"expires (\d{4})-(\d{2})-(\d{2})\b").expect("static regex");
    let issue = Regex::new(r"#\d+\b").expect("static regex");

    let mut out = Vec::new();
    for entry in ignore {
        let id = entry
            .get("id")
            .and_then(toml::Value::as_str)
            .or_else(|| entry.as_str())
            .unwrap_or("<unnamed entry>");
        let reason = entry
            .get("reason")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if !issue.is_match(reason) {
            out.push(format!(
                "{id}: reason names no tracking issue (`#<number>`)"
            ));
        }
        let Some(caps) = expires.captures(reason) else {
            out.push(format!("{id}: reason has no `expires YYYY-MM-DD`"));
            continue;
        };
        let part = |i: usize| caps[i].parse::<i64>().expect("digits");
        let valid = u32::try_from(part(2))
            .ok()
            .zip(u32::try_from(part(3)).ok())
            .and_then(|(m, d)| Day::new(part(1), m, d));
        match valid {
            None => out.push(format!("{id}: `{}` is not a calendar date", &caps[0])),
            Some(day) if today > day => out.push(format!(
                "{id}: expired {}-{:02}-{:02}; fix the advisory or remove the ignore",
                day.year, day.month, day.day
            )),
            Some(_) => {}
        }
    }
    Ok(out)
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(DENY_FILE);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let problems = findings(&text, Day::from_unix_secs(secs))?;
    if !problems.is_empty() {
        bail!(
            "check-deny-ignore-expiry: {} problem(s) in {DENY_FILE}:\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }
    eprintln!("check-deny-ignore-expiry: clean");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: fn(i64, u32, u32) -> Day = |y, m, d| Day::new(y, m, d).expect("valid day");

    fn deny(reason: &str) -> String {
        format!(
            "[advisories]\nignore = [{{ id = \"RUSTSEC-2026-0543\", reason = \"{reason}\" }}]\n"
        )
    }

    const GOOD: &str = "unmaintained, expires 2026-12-31, tracked in #5673";

    #[test]
    fn a_future_expiry_passes() {
        assert!(findings(&deny(GOOD), D(2026, 11, 17)).unwrap().is_empty());
    }

    #[test]
    fn the_expiry_day_itself_passes() {
        assert!(findings(&deny(GOOD), D(2026, 12, 31)).unwrap().is_empty());
    }

    #[test]
    fn the_day_after_fails() {
        let f = findings(&deny(GOOD), D(2027, 1, 1)).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("expired 2026-12-31"), "{f:?}");
    }

    #[test]
    fn a_missing_expiry_fails() {
        let f = findings(&deny("unmaintained, tracked in #5673"), D(2026, 11, 17)).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("no `expires"), "{f:?}");
    }

    #[test]
    fn a_missing_issue_fails() {
        let f = findings(&deny("unmaintained, expires 2026-12-31"), D(2026, 11, 17)).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("no tracking issue"), "{f:?}");
    }

    #[test]
    fn an_empty_ignore_list_passes() {
        let empty = "[advisories]\nignore = []\n";
        assert!(findings(empty, D(2030, 1, 1)).unwrap().is_empty());
        assert!(findings("", D(2030, 1, 1)).unwrap().is_empty());
    }

    #[test]
    fn each_entry_is_checked() {
        let two = "[advisories]\nignore = [\n\
            { id = \"A\", reason = \"expires 2026-12-31 #1\" },\n\
            { id = \"B\", reason = \"expires 2026-11-01 #2\" },\n\
            \"C\",\n]\n";
        let f = findings(two, D(2026, 11, 17)).unwrap();
        assert!(f.iter().any(|m| m.starts_with("B: expired")), "{f:?}");
        assert!(f.iter().any(|m| m.starts_with("C: ")), "{f:?}");
        assert!(!f.iter().any(|m| m.starts_with("A: ")), "{f:?}");
    }

    #[test]
    fn a_malformed_date_fails() {
        for bad in ["2026-13-01", "2026-02-30", "2026-00-10", "2027-02-29"] {
            let f = findings(&deny(&format!("expires {bad} #1")), D(2026, 1, 1)).unwrap();
            assert_eq!(f.len(), 1, "{bad}: {f:?}");
            assert!(f[0].contains("not a calendar date"), "{bad}: {f:?}");
        }
        assert!(Day::new(2028, 2, 29).is_some());
    }

    #[test]
    fn unix_seconds_convert_at_the_edges() {
        assert_eq!(Day::from_unix_secs(0), D(1970, 1, 1));
        assert_eq!(Day::from_unix_secs(86_399), D(1970, 1, 1));
        assert_eq!(Day::from_unix_secs(86_400), D(1970, 1, 2));
        assert_eq!(Day::from_unix_secs(951_782_400), D(2000, 2, 29));
        assert_eq!(Day::from_unix_secs(1_709_164_800), D(2024, 2, 29));
        assert_eq!(Day::from_unix_secs(1_709_251_200), D(2024, 3, 1));
        assert_eq!(Day::from_unix_secs(1_795_000_000), D(2026, 11, 18));
        assert_eq!(Day::from_unix_secs(4_102_444_799), D(2099, 12, 31));
    }

    #[test]
    fn the_repository_deny_toml_passes_today() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join(DENY_FILE)).unwrap();
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let f = findings(&text, Day::from_unix_secs(secs)).unwrap();
        assert!(f.is_empty(), "{f:?}");
    }
}
