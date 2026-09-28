//! CLI-side surface for `[mvm]` chrome. Every helper is a thin
//! delegation to [`mvm_runtime::ui`] so the verbosity gate (info/success/step/
//! progress are opt-in; errors/warnings/banners/status/prompts always
//! print) lives in exactly one place. Only [`format_timed`] /
//! [`timed_step`] are CLI-local, and `timed_step` routes through the
//! gated [`info`] so it follows the same toggle.

pub type Spinner = mvm_runtime::ui::Spinner;

// ---------------------------------------------------------------------------
// Message helpers (delegate to mvm_runtime::ui)
// ---------------------------------------------------------------------------

/// Print a progress / chatter message that's only useful when
/// troubleshooting. Opt-in: shown when `--verbose`/`--debug` is passed
/// or `RUST_LOG` is set.
pub fn progress(msg: &str) {
    mvm_runtime::ui::progress(msg);
}

/// Print an informational message: `[mvm]` message. Opt-in chatter.
pub fn info(msg: &str) {
    mvm_runtime::ui::info(msg);
}

/// Print a success message: `[mvm]` message (in green). Opt-in chatter.
pub fn success(msg: &str) {
    mvm_runtime::ui::success(msg);
}

/// Print an error message: `[mvm]` message (in red). Always printed.
pub fn error(msg: &str) {
    mvm_runtime::ui::error(msg);
}

/// Print a warning message: `[mvm]` message (in yellow). Always printed.
pub fn warn(msg: &str) {
    mvm_runtime::ui::warn(msg);
}

/// Print an always-on notice line: `[mvm]` message. Unlike [`info`], this is
/// *not* gated on verbosity. For a phase that takes a while, prefer
/// [`mvm_runtime::ui::activity::start`], which also keeps a live line going.
pub fn notice(msg: &str) {
    mvm_runtime::ui::notice(msg);
}

/// Print a numbered step: `[mvm]` Step n/total: message. Opt-in chatter.
pub fn step(n: u32, total: u32, msg: &str) {
    mvm_runtime::ui::step(n, total, msg);
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

// ---------------------------------------------------------------------------
// Banner / status / prompts / spinners (always printed; delegate)
// ---------------------------------------------------------------------------

/// Print a green bold banner box. Always printed (carries actionable
/// command results like the guest IP and next-step verbs).
pub fn banner(lines: &[&str]) {
    mvm_runtime::ui::banner(lines);
}

/// Print the status header.
pub fn status_header() {
    mvm_runtime::ui::status_header();
}

/// Print a status line with a bold label and a colored value.
pub fn status_line(label: &str, value: &str) {
    mvm_runtime::ui::status_line(label, value);
}

/// Show an interactive confirmation prompt. Returns true if confirmed.
pub fn confirm(msg: &str) -> bool {
    mvm_runtime::ui::confirm(msg)
}

/// Show an interactive free-form prompt and return the entered line.
pub fn prompt_text(msg: &str) -> std::io::Result<String> {
    mvm_runtime::ui::prompt_text(msg)
}

/// Show an interactive secret prompt with terminal echo disabled while the
/// user types.
pub fn prompt_secret(msg: &str) -> std::io::Result<String> {
    mvm_runtime::ui::prompt_secret(msg)
}

/// Create and start a spinner with the given message.
/// Call `.finish_with_message()` or `.finish_and_clear()` when done.
pub fn spinner(msg: &str) -> mvm_runtime::ui::Spinner {
    mvm_runtime::ui::spinner(msg)
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
}
