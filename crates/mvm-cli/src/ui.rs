use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

// ---------------------------------------------------------------------------
// Verbosity (CLI-side mirror of mvm::ui)
// ---------------------------------------------------------------------------

/// Print a progress / chatter message that's only useful when troubleshooting.
/// Suppressed by default; shown when `--verbose`/`--debug` is passed or
/// `RUST_LOG` is set. Delegates to [`mvm::ui::progress`] so both
/// crates honor the same toggle.
pub fn progress(msg: &str) {
    mvm::ui::progress(msg);
}

// ---------------------------------------------------------------------------
// Colored message helpers
// ---------------------------------------------------------------------------

fn prefix() -> String {
    "[mvm]".bold().cyan().to_string()
}

/// Print an informational message: [mvm] message
pub fn info(msg: &str) {
    if mvm::ui::is_chrome_routed_to_stderr() {
        eprintln!("{} {}", prefix(), msg);
    } else {
        println!("{} {}", prefix(), msg);
    }
}

/// Print a success message: [mvm] message (in green)
pub fn success(msg: &str) {
    if mvm::ui::is_chrome_routed_to_stderr() {
        eprintln!("{} {}", prefix(), msg.green());
    } else {
        println!("{} {}", prefix(), msg.green());
    }
}

/// Print an error message: [mvm] ERROR: message (in red)
pub fn error(msg: &str) {
    eprintln!("{} {}", "[mvm]".bold().red(), msg.red());
}

/// Print a warning message: [mvm] message (in yellow)
pub fn warn(msg: &str) {
    if mvm::ui::is_chrome_routed_to_stderr() {
        eprintln!("{} {}", prefix(), msg.yellow());
    } else {
        println!("{} {}", prefix(), msg.yellow());
    }
}

/// Format a completed timed step's message: `<label> … <secs>s`.
/// Pure (testable); [`timed_step`] routes it through [`info`].
pub fn format_timed(label: &str, elapsed: std::time::Duration) -> String {
    format!("{label} … {:.1}s", elapsed.as_secs_f64())
}

/// Print a completed timed step: `[mvm] <label> … <secs>s`. Used for
/// Stage 0 per-step progress (Plan 93 Phase 3) so the user's perceived
/// speed matches the actual per-step wall-clock.
pub fn timed_step(label: &str, elapsed: std::time::Duration) {
    info(&format_timed(label, elapsed));
}

/// Print a numbered step: [mvm] Step n/total: message
pub fn step(n: u32, total: u32, msg: &str) {
    let formatted = format!(
        "\n{} {} {}",
        prefix(),
        format!("Step {}/{}:", n, total).bold().yellow(),
        msg,
    );
    if mvm::ui::is_chrome_routed_to_stderr() {
        eprintln!("{formatted}");
    } else {
        println!("{formatted}");
    }
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/// Print a green bold banner box.
pub fn banner(lines: &[&str]) {
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0) + 4;
    let rule = "=".repeat(width);

    println!();
    println!("{}", rule.bold().green());
    for line in lines {
        let pad = width - line.len() - 4;
        println!(
            "{}",
            format!("  {}{}  ", line, " ".repeat(pad)).bold().green()
        );
    }
    println!("{}", rule.bold().green());
    println!();
}

// ---------------------------------------------------------------------------
// Status table
// ---------------------------------------------------------------------------

/// Print the status header.
pub fn status_header() {
    println!("{}", "mvmctl status".bold());
    println!("{}", "-------------".dimmed());
}

/// Print a status line with a bold label and a colored value.
/// Recognized values: "Running", "Stopped", "Not running", etc.
pub fn status_line(label: &str, value: &str) {
    let colored_value = if value.starts_with("Running") {
        value.green().to_string()
    } else if value == "Stopped" {
        value.yellow().to_string()
    } else if value.starts_with("Not ") || value == "-" {
        value.dimmed().to_string()
    } else if value.starts_with("Starting") {
        value.yellow().to_string()
    } else {
        value.to_string()
    };

    println!("{} {}", format!("{:<14}", label).bold(), colored_value);
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Show an interactive confirmation prompt. Returns true if confirmed.
pub fn confirm(msg: &str) -> bool {
    inquire::Confirm::new(msg)
        .with_default(false)
        .prompt()
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Spinners
// ---------------------------------------------------------------------------

/// Create and start a spinner with the given message.
/// Call `.finish_with_message()` or `.finish_and_clear()` when done.
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.cyan} {msg}")
            .expect("invalid spinner template"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
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
