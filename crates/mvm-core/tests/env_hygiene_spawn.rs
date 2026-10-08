//! A helper started through any of the filter's seams does not inherit a
//! denied variable from the process that starts it.
//!
//! The variables have to be in a real parent's environment for this to test
//! anything, and a test must not mutate its own process environment, so the
//! test re-runs its own binary with the variables set. That child plays the
//! `mvmctl` role: it starts `/usr/bin/env` once through each seam and prints
//! what each helper actually received.

use std::process::Command;

use mvm_core::env_hygiene::{EnvReadmit, filtered_env, helper_command, helper_command_with};

const PROBE: &str = "MVM_ENV_HYGIENE_SPAWN_PROBE";
const TEST_NAME: &str = "a_helper_does_not_inherit_denied_variables";
const SECTION: &str = "--- seam ";

/// Each seam's name and the variables it deliberately keeps.
const SEAMS: [(&str, &[&str]); 3] = [
    ("helper_command", &[]),
    ("helper_command_with", &["PYTHONPATH"]),
    ("filtered_env", &[]),
];

const DENIED: [&str; 6] = [
    "BASH_ENV",
    "LD_PRELOAD",
    "PERL5DB",
    "OP_SESSION_probe",
    "PYTHONPATH",
    "BASH_FUNC_probe%%",
];

fn print_helper_env(seam: &str, mut helper: Command) {
    let output = helper.output().expect("run /usr/bin/env as the helper");
    println!("{SECTION}{seam}");
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

fn run_as_parent() {
    print_helper_env("helper_command", helper_command("/usr/bin/env"));
    let readmit = EnvReadmit::from_names(["PYTHONPATH"]).expect("exact name");
    print_helper_env(
        "helper_command_with",
        helper_command_with("/usr/bin/env", &readmit),
    );
    // The environment a direct `exec` is handed, delivered as a whole.
    let mut exec = Command::new("/usr/bin/env");
    exec.env_clear().envs(filtered_env(&EnvReadmit::none()));
    print_helper_env("filtered_env", exec);
}

/// The lines each seam's helper printed, keyed by seam.
fn sections(stdout: &str) -> Vec<(&str, Vec<&str>)> {
    let mut sections: Vec<(&str, Vec<&str>)> = Vec::new();
    for line in stdout.lines() {
        if let Some((_, seam)) = line.split_once(SECTION) {
            sections.push((seam, Vec::new()));
        } else if let Some((_, lines)) = sections.last_mut() {
            lines.push(line);
        }
    }
    sections
}

#[test]
fn the_first_seam_is_found_after_the_test_harness_prefix() {
    let stdout = "test a_helper_does_not_inherit_denied_variables ... --- seam helper_command\nA=1\n--- seam filtered_env\nB=2\n";
    assert_eq!(
        sections(stdout),
        vec![
            ("helper_command", vec!["A=1"]),
            ("filtered_env", vec!["B=2"])
        ]
    );
}

#[test]
fn a_helper_does_not_inherit_denied_variables() {
    if std::env::var_os(PROBE).is_some() {
        run_as_parent();
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test binary path"))
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env(PROBE, "1")
        .env("BASH_ENV", "/nonexistent/rc")
        // Empty, so the loader of every dynamically linked program on the way
        // has nothing to preload or complain about.
        .env("LD_PRELOAD", "")
        .env("PERL5DB", "BEGIN { die }")
        .env("OP_SESSION_probe", "session-value")
        .env("PYTHONPATH", "/probe/lib")
        .env("BASH_FUNC_probe%%", "() { :; }")
        .env("MVM_ENV_HYGIENE_KEPT", "kept")
        .output()
        .expect("re-run the test binary as the parent");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(
        !stdout.contains("session-value"),
        "the session token's value reached a helper"
    );

    let sections = sections(&stdout);
    let seams: Vec<&str> = sections.iter().map(|(seam, _)| *seam).collect();
    assert_eq!(seams, SEAMS.map(|(seam, _)| seam), "{stdout}");
    for ((seam, lines), (_, kept)) in sections.iter().zip(SEAMS) {
        assert!(
            lines.contains(&"MVM_ENV_HYGIENE_KEPT=kept"),
            "{seam}: an ordinary variable is inherited: {lines:?}"
        );
        for denied in DENIED {
            let reached = lines
                .iter()
                .any(|line| line.starts_with(&format!("{denied}=")));
            assert_eq!(
                reached,
                kept.contains(&denied),
                "{seam}: {denied} reached the helper: {reached}: {lines:?}"
            );
        }
    }
}
