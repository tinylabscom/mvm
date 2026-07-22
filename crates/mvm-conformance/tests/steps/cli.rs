//! Steps that drive the built `mvmctl` binary as a subprocess and assert on
//! its exit code / stdout. Covers the CLI-surface suite; scenarios that need
//! a running microVM call through `mvm-client` instead as those suites land.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;
use cucumber::{then, when};

use crate::world::CliWorld;

#[when(expr = "I run mvmctl with {string}")]
fn run_mvmctl(world: &mut CliWorld, args: String) {
    #[allow(deprecated)] // matches crates/mvm-cli/tests/cli.rs's use of this API
    let mut cmd = Command::cargo_bin("mvmctl").unwrap_or_else(|e| {
        panic!("mvmctl binary not found ({e}) — run `cargo build --bin mvmctl` before `just bdd`")
    });
    let output = cmd
        .args(args.split_whitespace())
        .output()
        .expect("failed to spawn mvmctl");
    world.last_run = Some(output);
}

#[then(expr = "the command exits with code {int}")]
fn exits_with_code(world: &mut CliWorld, code: i64) {
    let output = world.last_output();
    assert_eq!(
        output.status.code(),
        Some(code as i32),
        "unexpected exit code; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[then(expr = "the help output lists the {string} verb")]
fn help_lists_verb(world: &mut CliWorld, verb: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let listed = stdout
        .lines()
        .any(|line| line.trim_start().starts_with(verb.as_str()));
    assert!(
        listed,
        "expected top-level verb {verb:?} in `mvmctl --help` output:\n{stdout}"
    );
}

#[then(expr = "the output contains {string}")]
fn output_contains(world: &mut CliWorld, needle: String) {
    let output = world.last_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(needle.as_str()),
        "expected stdout to contain {needle:?}; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
