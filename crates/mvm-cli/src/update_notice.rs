//! Ambient "an update is available" notice for interactive use.
//!
//! `mvmctl env update` is the explicit check-and-install flow; this module adds
//! the passive half: once per day, on an interactive terminal, after the
//! user's command has fully settled, check the GitHub releases API and print
//! one stderr line if a newer release exists. The check never changes the
//! command's result, never writes to stdout (piped output stays clean), and
//! is silent on any failure — offline is not an error condition.
//!
//! Deliberate boundaries:
//! - at most one network call per 24 h per machine, remembered in
//!   `$MVM_HOME/update-check.json`;
//! - skipped when stderr is not a terminal, when `CI` is set, or when
//!   `MVM_NO_UPDATE_CHECK` is present (opt out);
//! - a failed check records nothing, so the next run tries again — but only
//!   after the command path finishes, so a slow or absent network adds no
//!   latency to what the user asked for.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How often an interactive session re-checks the releases API.
const CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

/// Opt-out: any value suppresses the notice for the process.
pub(crate) const OPT_OUT_ENV: &str = "MVM_NO_UPDATE_CHECK";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct UpdateCheckState {
    checked_at_unix: u64,
    latest_tag: String,
}

fn state_path() -> std::path::PathBuf {
    std::path::Path::new(&mvm_core::config::mvm_home()).join("update-check.json")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether a state recorded at `checked_at` is fresh enough to skip the call.
fn is_fresh(checked_at_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(checked_at_unix) < CHECK_INTERVAL.as_secs()
}

/// The one line an interactive user sees. `None` when there is nothing to say.
fn notice_line(latest_tag: &str, current: &str) -> Option<String> {
    use crate::update::UpdateAction;
    match crate::update::decide_update(latest_tag.trim_start_matches('v'), current, false) {
        UpdateAction::Install => Some(format!(
            "mvmctl {latest} is available (running {current}) — run `mvmctl env update` to upgrade",
            latest = latest_tag,
        )),
        UpdateAction::UpToDate | UpdateAction::RefuseDowngrade => None,
    }
}

fn read_state(path: &Path) -> Option<UpdateCheckState> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn write_state(path: &Path, latest_tag: &str) {
    let state = UpdateCheckState {
        checked_at_unix: now_unix(),
        latest_tag: latest_tag.to_string(),
    };
    if let Ok(body) = serde_json::to_string(&state)
        && std::fs::write(path, body).is_err()
    {
        // Best effort: a lost record only means the next session re-checks.
    }
}

/// True when this process looks like a human at a terminal rather than a
/// pipe, a CI job, or an explicit opt-out.
fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
        && std::env::var_os("CI").is_none()
        && std::env::var_os(OPT_OUT_ENV).is_none()
}

/// Run the ambient notice. Called once after the command result settles;
/// everything inside is best-effort and never propagates.
pub(crate) fn maybe_notify() {
    if !interactive() {
        return;
    }
    let path = state_path();
    let now = now_unix();
    if read_state(&path).is_some_and(|state| is_fresh(state.checked_at_unix, now)) {
        return;
    }
    let latest_tag = match crate::update::fetch_latest_version() {
        Ok(tag) => tag,
        Err(_) => return,
    };
    write_state(&path, &latest_tag);
    if let Some(line) = notice_line(&latest_tag, crate::update::current_version()) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_younger_than_a_day_is_fresh() {
        let now = 1_000_000u64;
        assert!(is_fresh(now - 60, now));
        assert!(is_fresh(now - CHECK_INTERVAL.as_secs() + 1, now));
        assert!(!is_fresh(now - CHECK_INTERVAL.as_secs(), now));
        assert!(!is_fresh(now - CHECK_INTERVAL.as_secs() - 60, now));
    }

    #[test]
    fn state_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update-check.json");
        assert!(read_state(&path).is_none());
        write_state(&path, "v9.9.9");
        let state = read_state(&path).expect("the state parses back");
        assert_eq!(state.latest_tag, "v9.9.9");
        assert!(is_fresh(state.checked_at_unix, now_unix()));
    }

    #[test]
    fn only_a_newer_release_produces_a_line() {
        assert_eq!(
            notice_line("v9.9.9", "0.18.3").as_deref(),
            Some(
                "mvmctl v9.9.9 is available (running 0.18.3) — run `mvmctl env update` to upgrade"
            )
        );
        assert!(notice_line("v0.18.3", "0.18.3").is_none());
        assert!(notice_line("v0.18.2", "0.18.3").is_none());
    }
}
