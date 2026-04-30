use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Verbosity
// ---------------------------------------------------------------------------

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable verbose `[mvm]` chatter (info/success/warn/step). Errors are
/// always printed regardless. Called once at CLI startup based on
/// `--verbose`/`--debug` or the presence of `RUST_LOG`.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether `[mvm]` chatter is currently enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Colored message helpers
// ---------------------------------------------------------------------------

fn prefix() -> String {
    "[mvm]".bold().cyan().to_string()
}

/// Print an informational message: [mvm] message
pub fn info(msg: &str) {
    println!("{} {}", prefix(), msg);
}

/// Print a success message: [mvm] message (in green)
pub fn success(msg: &str) {
    println!("{} {}", prefix(), msg.green());
}

/// Print an error message: [mvm] ERROR: message (in red).
pub fn error(msg: &str) {
    eprintln!("{} {}", "[mvm]".bold().red(), msg.red());
}

/// Print a warning message: [mvm] message (in yellow)
pub fn warn(msg: &str) {
    println!("{} {}", prefix(), msg.yellow());
}

/// Print a numbered step: [mvm] Step n/total: message
pub fn step(n: u32, total: u32, msg: &str) {
    println!(
        "\n{} {} {}",
        prefix(),
        format!("Step {}/{}:", n, total).bold().yellow(),
        msg,
    );
}

/// Print a progress / chatter message that's only useful when
/// troubleshooting (e.g. "auto-starting dev VM…"). Suppressed by default;
/// shown when `--verbose`/`--debug` is passed or `RUST_LOG` is set.
pub fn progress(msg: &str) {
    if !is_verbose() {
        return;
    }
    println!("{} {}", prefix(), msg);
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
