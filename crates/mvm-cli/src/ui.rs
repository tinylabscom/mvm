//! CLI-side surface for `[mvm]` chrome. Every helper is a thin
//! delegation to [`mvm::ui`] so the verbosity gate (info/success/step/
//! progress are opt-in; errors/warnings/banners/status/prompts always
//! print) lives in exactly one place. Only [`format_timed`] /
//! [`timed_step`] are CLI-local, and `timed_step` routes through the
//! gated [`info`] so it follows the same toggle.

use indicatif::ProgressBar;

// ---------------------------------------------------------------------------
// Message helpers (delegate to mvm::ui)
// ---------------------------------------------------------------------------

/// Print a progress / chatter message that's only useful when
/// troubleshooting. Opt-in: shown when `--verbose`/`--debug` is passed
/// or `RUST_LOG` is set.
pub fn progress(msg: &str) {
    mvm::ui::progress(msg);
}

/// Print an informational message: `[mvm]` message. Opt-in chatter.
pub fn info(msg: &str) {
    mvm::ui::info(msg);
}

/// Print a success message: `[mvm]` message (in green). Opt-in chatter.
pub fn success(msg: &str) {
    mvm::ui::success(msg);
}

/// Print an error message: `[mvm]` message (in red). Always printed.
pub fn error(msg: &str) {
    mvm::ui::error(msg);
}

/// Print a warning message: `[mvm]` message (in yellow). Always printed.
pub fn warn(msg: &str) {
    mvm::ui::warn(msg);
}

/// Print an always-on liveness/notice line: `[mvm]` message. Unlike [`info`],
/// this is *not* gated on verbosity — it's for the rare case where a periodic
/// line is the only signal a long, silent blocking step is alive (the Stage 0
/// builder-image build), so it must show even in the default quiet mode.
pub fn notice(msg: &str) {
    mvm::ui::notice(msg);
}

/// Print a numbered step: `[mvm]` Step n/total: message. Opt-in chatter.
pub fn step(n: u32, total: u32, msg: &str) {
    mvm::ui::step(n, total, msg);
}

/// Format a completed timed step's message: `<label> … <secs>s`.
/// Pure (testable); [`timed_step`] routes it through [`info`].
pub fn format_timed(label: &str, elapsed: std::time::Duration) -> String {
    format!("{label} … {:.1}s", elapsed.as_secs_f64())
}

/// Print a completed timed step: `[mvm] <label> … <secs>s`. Used for
/// Stage 0 per-step progress so the user's perceived speed matches the
/// actual per-step wall-clock. Opt-in chatter (routes through [`info`]).
pub fn timed_step(label: &str, elapsed: std::time::Duration) {
    info(&format_timed(label, elapsed));
}

/// Format a liveness heartbeat for a long, silent blocking step: `<activity>
/// still running — <secs>s elapsed …`. The Stage 0 builder-image build runs
/// `nix` inside the guest with no host-visible output until it completes, so a
/// periodic line is the only way to distinguish "working" from "hung". Pure
/// (testable); the ticker routes it through [`notice`] — an always-on liveness
/// signal, not gated chatter, since it's the *only* feedback during the block.
pub fn format_heartbeat(activity: &str, elapsed: std::time::Duration) -> String {
    format!(
        "{activity} still running — {}s elapsed (the in-guest nix build is silent until it finishes; this is normal, not a hang)",
        elapsed.as_secs()
    )
}

// ---------------------------------------------------------------------------
// Banner / status / prompts / spinners (always printed; delegate)
// ---------------------------------------------------------------------------

/// Print a green bold banner box. Always printed (carries actionable
/// command results like the guest IP and next-step verbs).
pub fn banner(lines: &[&str]) {
    mvm::ui::banner(lines);
}

/// Print the status header.
pub fn status_header() {
    mvm::ui::status_header();
}

/// Print a status line with a bold label and a colored value.
pub fn status_line(label: &str, value: &str) {
    mvm::ui::status_line(label, value);
}

/// Show an interactive confirmation prompt. Returns true if confirmed.
pub fn confirm(msg: &str) -> bool {
    mvm::ui::confirm(msg)
}

/// Create and start a spinner with the given message.
/// Call `.finish_with_message()` or `.finish_and_clear()` when done.
pub fn spinner(msg: &str) -> ProgressBar {
    mvm::ui::spinner(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timed_renders_label_and_one_decimal_second() {
        assert_eq!(
            format_timed(
                "Fetching Stage 0 bootstrap assets",
                std::time::Duration::from_millis(400)
            ),
            "Fetching Stage 0 bootstrap assets … 0.4s"
        );
        assert_eq!(
            format_timed("nix build", std::time::Duration::from_millis(12_345)),
            "nix build … 12.3s"
        );
    }

    #[test]
    fn format_heartbeat_names_activity_whole_seconds_and_reassures() {
        let line = format_heartbeat("Builder VM image build", std::time::Duration::from_secs(40));
        assert!(line.starts_with("Builder VM image build still running — 40s elapsed"));
        // Reassurance text is the whole point — it must say silence is expected.
        assert!(line.contains("not a hang"));
        // Whole seconds, no fractional noise.
        assert!(!line.contains("40.0"));
    }
}
