//! Verification tests for production code quality rules.
//!
//! These tests grep the source tree to enforce coding standards
//! established in AGENTS.md and Sprint 16.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Scan Rust source files for `.unwrap()` calls in production code.
///
/// Production code = everything before the `#[cfg(test)]` marker in each file,
/// and excluding `tests/` directories and test infrastructure files.
///
/// This enforces the AGENTS.md rule: never use `.unwrap()` in production code.
#[test]
fn no_unwrap_in_production_code() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates");

    // Use grep to find .unwrap() in .rs files, excluding test directories.
    let output = Command::new("grep")
        .args([
            "-rn",
            r"\.unwrap()",
            "--include=*.rs",
            "--exclude-dir=tests",
            "--exclude-dir=.build",
        ])
        .arg(crates_dir.to_str().expect("crates dir must be UTF-8"))
        .output()
        .expect("grep must be available");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Build a cache of test-block start lines per file.
    // In this codebase, `#[cfg(test)]` always appears once per file,
    // marking the start of the test module at the bottom.
    let mut test_start_cache: HashMap<String, Option<usize>> = HashMap::new();

    let violations: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            // Skip test infrastructure files
            if line.contains("shell_mock.rs")
                || line.contains("shell/mock.rs")
                || line.contains("/tests/")
            {
                return false;
            }

            // Parse content portion and skip doc comments and regular comments
            let parts_peek: Vec<&str> = line.splitn(3, ':').collect();
            if parts_peek.len() >= 3 {
                let content = parts_peek[2].trim();
                if content.starts_with("///") || content.starts_with("//") {
                    return false;
                }
            }

            // Parse "path:line_num:content"
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                return false;
            }
            let file_path = parts[0];
            let line_num: usize = match parts[1].parse() {
                Ok(n) => n,
                Err(_) => return false,
            };

            // Find where #[cfg(test)] starts in this file
            let test_start = test_start_cache
                .entry(file_path.to_string())
                .or_insert_with(|| find_cfg_test_line(file_path));

            // If the unwrap is after #[cfg(test)], it's test code — skip it.
            if let Some(start) = test_start
                && line_num >= *start
            {
                return false;
            }

            true
        })
        .collect();

    if !violations.is_empty() {
        let mut msg = String::from("Found .unwrap() in production code (violates AGENTS.md):\n\n");
        for v in &violations {
            msg.push_str("  ");
            msg.push_str(v);
            msg.push('\n');
        }
        msg.push_str("\nReplace with .expect(\"descriptive message\") or proper error handling.");
        panic!("{}", msg);
    }
}

/// Ensure no user-facing strings reference the old binary name `mvm` as a CLI command.
///
/// Internal identifiers are fine: Lima VM name `mvm`, bridge `br-mvm`, paths `/var/lib/mvm/`,
/// crate names `mvm-core`, log prefixes `[mvm]`, RUST_LOG filter `mvm=info`, etc.
/// Only CLI command suggestions like "Run 'mvm setup'" should use `mvmctl`.
#[test]
fn no_stale_binary_name_in_user_facing_strings() {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("crates");

    // Patterns that indicate user-facing CLI command references using old name.
    // These are strings where 'mvm' is used as a command the user should type.
    let patterns = [
        r"Run 'mvm ",
        r"Use 'mvm ",
        r#""mvm run"#,
        r#""mvm stop"#,
        r#""mvm start"#,
        r#""mvm setup"#,
        r#""mvm dev"#,
        r#""mvm shell"#,
        r#""mvm status"#,
        r#""mvm bootstrap"#,
        r#""mvm up"#,
        r#""mvm pool "#,
        r#""mvm agent "#,
        r"Run with: mvm ",
    ];

    let output = Command::new("grep")
        .args([
            "-rn",
            "--include=*.rs",
            "--exclude-dir=tests",
            "--exclude-dir=.build",
        ])
        .arg(
            patterns
                .iter()
                .map(|p| format!("-e{}", p))
                .collect::<Vec<_>>()
                .first()
                .expect("at least one pattern"),
        )
        .args(
            patterns
                .iter()
                .skip(1)
                .flat_map(|p| ["-e", p])
                .collect::<Vec<&str>>(),
        )
        .arg(crates_dir.to_str().expect("crates dir must be UTF-8"))
        .output()
        .expect("grep must be available");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let violations: Vec<&str> = stdout
        .lines()
        .filter(|line| {
            // Skip test code and comments
            if line.contains("/tests/")
                || line.contains("shell_mock.rs")
                || line.contains("shell/mock.rs")
            {
                return false;
            }
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let content = parts[2].trim();
                if content.starts_with("///") || content.starts_with("//") {
                    return false;
                }
            }

            // Skip test blocks
            if parts.len() >= 2 {
                let file_path = parts[0];
                let line_num: usize = match parts[1].parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                if let Some(start) = find_cfg_test_line(file_path) {
                    if line_num >= start {
                        return false;
                    }
                }
            }
            true
        })
        .collect();

    if !violations.is_empty() {
        let mut msg = String::from(
            "Found stale 'mvm' binary name in user-facing strings (should be 'mvmctl'):\n\n",
        );
        for v in &violations {
            msg.push_str("  ");
            msg.push_str(v);
            msg.push('\n');
        }
        msg.push_str("\nReplace 'mvm <command>' with 'mvmctl <command>' in user-facing messages.");
        panic!("{}", msg);
    }
}

/// Find the line number of `#[cfg(test)]` in a file, if present.
fn find_cfg_test_line(path: &str) -> Option<usize> {
    let content = std::fs::read_to_string(path).ok()?;
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" || trimmed == "#![cfg(test)]" {
            return Some(i + 1); // 1-indexed
        }
    }
    None
}
