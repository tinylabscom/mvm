//! Steps for the Claude Code example workbench (`examples/claude-code/`).
//!
//! The interactive profile's posture — default-deny egress answered as
//! policy, an allow-listed host admitted at the gate, a sized workspace disk
//! surviving stop/start, and a console attach counting as guest activity —
//! is only observable against a real boot, so every step here targets the
//! live home the other live CLI steps share.
//!
//! The egress probes deliberately speak raw HTTP `CONNECT` to the guest's
//! loopback egress proxy over bash's `/dev/tcp`, because the example image
//! carries no curl: its closure is the pinned Claude Code binary, bash, and
//! busybox. The proxy's first response line is the whole assertion — `403
//! Forbidden` is the policy-refusal shape (immediate, from the gate), `200
//! Connection established` means the host-side endpoint admitted the
//! connect and reached the real upstream. Nothing here performs an API
//! call, so the scenario needs no Anthropic credential.

use std::path::PathBuf;
use std::process::Output;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;

use crate::steps::cli::{mvmctl_command, selected_live_home, workspace_root};
use crate::world::CliWorld;

/// Run `mvmctl` with `args` against the scenario's live home, from the
/// workspace root so `--flake examples/claude-code` resolves as a reader's
/// own invocation would.
fn run_workbench_mvmctl<I, S>(world: &mut CliWorld, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let home = selected_live_home(world);
    let output = mvmctl_command()
        .current_dir(workspace_root())
        .args(args)
        .isolated_home(&home)
        .output()
        .expect("failed to spawn mvmctl for the claude-code workbench");
    world.last_live_home = Some(home);
    output
}

/// Remove a leftover workspace image so the persistence assertion cannot be
/// satisfied by a marker some earlier run wrote.
///
/// The path is feature text, so it is constrained to `/tmp/` — a step that
/// deletes whatever a feature file names is a foot-gun the constraint keeps
/// pointed at scratch space only.
#[given(expr = "a fresh claude-code workspace image at {string}")]
fn fresh_workspace_image(_world: &mut CliWorld, path: String) {
    let path = PathBuf::from(path);
    assert!(
        path.starts_with("/tmp/"),
        "the workspace image must live under /tmp/, got {}",
        path.display()
    );
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("removing stale workspace image {}: {error}", path.display()),
    }
}

/// Run one bash command inside the workbench guest via `machine exec`.
///
/// bash rather than `/bin/sh` (busybox ash) because the egress probe needs
/// bash's `/dev/tcp`; the example's default profile ships `bashInteractive`
/// on `/usr/local/bin`, which is on the guest agent's default PATH.
#[when(expr = "I execute workbench command {string} in machine {string}")]
fn execute_workbench_command(world: &mut CliWorld, script: String, machine: String) {
    let output = run_workbench_mvmctl(
        world,
        ["machine", "exec", &machine, "--", "bash", "-c", &script],
    );
    world.last_run = Some(output);
}

/// Speak one HTTP `CONNECT` to the guest's loopback egress proxy and print
/// the proxy's first response line, which the scenario then asserts on.
///
/// `read -t 30` bounds the wait so a gate that hangs fails the step as a
/// timeout instead of hanging the suite; the refusal being *immediate* is
/// asserted by the 403 arriving inside that window from a probe that never
/// retried.
#[when(expr = "I probe the egress gate of workbench machine {string} for {string}")]
fn probe_egress_gate(world: &mut CliWorld, machine: String, host: String) {
    assert!(
        host.contains(':') && !host.contains('\'') && !host.contains(' '),
        "the probe target must be a bare host:port token, got {host:?}"
    );
    let proxy = mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN;
    let (proxy_host, proxy_port) = proxy
        .split_once(':')
        .expect("DEFAULT_EGRESS_PROXY_LISTEN is host:port");
    let script = format!(
        "exec 3<>/dev/tcp/{proxy_host}/{proxy_port} || {{ echo bdd-no-proxy-listener; exit 1; }}; \
         printf 'CONNECT {host} HTTP/1.1\\r\\nHost: {host}\\r\\n\\r\\n' >&3; \
         IFS= read -r -t 30 line <&3 || {{ echo bdd-proxy-read-timeout; exit 1; }}; \
         printf '%s\\n' \"$line\""
    );
    let output = run_workbench_mvmctl(
        world,
        ["machine", "exec", &machine, "--", "bash", "-c", &script],
    );
    world.last_run = Some(output);
}

/// The `last_active` stamp the name registry holds for `machine` in the
/// scenario's live home, read through the registry's own loader.
///
/// The registry path helpers are ambient (`MVM_HOME`), so the read runs
/// under a scoped env override — safe because the BDD runner executes
/// scenarios sequentially.
fn workbench_last_active(world: &mut CliWorld, machine: &str) -> Option<String> {
    let home = selected_live_home(world);
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", &home);
    let path = mvm_runtime::vm::name_registry::registry_path();
    let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).ok()?;
    registry
        .lookup(machine)
        .and_then(|reg| reg.last_active.clone())
}

/// Attach to the guest through the console verb's one-shot form, recording
/// the activity stamp beforehand so the refresh is observable.
///
/// One-shot (`--command`) rather than the interactive PTY loop: the PTY form
/// blocks on a terminal this harness does not have, while both forms share
/// the accessible-gate check and the `touch_activity` call this scenario is
/// after.
#[when(expr = "I attach a one-shot console command to machine {string}")]
fn attach_one_shot_console(world: &mut CliWorld, machine: String) {
    world.workbench_last_active_before = Some(workbench_last_active(world, &machine));
    let output = run_workbench_mvmctl(world, ["machine", "console", &machine, "--command", "true"]);
    world.last_run = Some(output);
    world.workbench_machine = Some(machine);
}

/// The attach must have moved the registry's `last_active` stamp — the input
/// the reaper's idle logic keys off (`idle_elapsed` prefers `last_active`).
/// The idle reaper itself runs in no local `mvmctl` process, so the wiring
/// from the console verb into its input is the live-observable half; the
/// "recent activity is not idle" half is unit-tested beside the reaper.
#[then(expr = "the console attach refreshed the workbench activity marker")]
fn console_attach_refreshed_activity(world: &mut CliWorld) {
    let machine = world
        .workbench_machine
        .clone()
        .expect("the console attach step must run first");
    let before = world
        .workbench_last_active_before
        .clone()
        .expect("the console attach step must run first");
    let after = workbench_last_active(world, &machine);
    assert!(
        after.is_some(),
        "the console attach left no last_active stamp on {machine:?} \
         (before: {before:?})"
    );
    assert_ne!(
        after, before,
        "the console attach did not refresh {machine:?}'s last_active stamp"
    );
}
