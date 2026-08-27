//! The documented machine lifecycle, driven against one real guest.
//!
//! Most of the `machine` verb surface is documented but proven only by the
//! `parse` tier, for one structural reason: each verb needs a machine that is
//! already running, and a scenario that boots its own guest pays minutes for
//! a single assertion. So `machine cp`, `machine pause`, `machine fs ls` and
//! two dozen siblings were verified to the depth of "clap accepts these
//! arguments" — which cannot see a verb that parses and then refuses, the
//! shape `machine forward` had already decayed into.
//!
//! This module boots one guest for the whole feature and lets every scenario
//! drive it. The machine is process-global rather than per-scenario because
//! cucumber's `World` is rebuilt for each scenario; the runner pins
//! `max_concurrent_scenarios(1)`, so sharing it is sequential by construction.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::OnceLock;

use cucumber::{given, then, when};

use crate::world::CliWorld;
use mvm_conformance::IsolatedHome;

/// Name of the guest every journey scenario operates. Fixed rather than
/// generated: a leaked machine from an aborted run is then findable by name
/// and reclaimed by the next run's teardown, instead of accumulating.
const JOURNEY_MACHINE: &str = "bdd-journey";

/// The home the journey machine lives in, booted once per process.
///
/// `MVM_E2E_HOME` points this at an artifact-warm home. A fresh tempdir would
/// re-acquire the kernel, overlay and initramfs before the first boot, which
/// reads as a launch timeout rather than as a cold cache.
fn journey_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        std::env::var_os("MVM_E2E_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let dir = std::env::temp_dir().join("mvm-journey-home");
                std::fs::create_dir_all(&dir).expect("create journey MVM_HOME");
                dir
            })
    })
}

/// Run `mvmctl` against the journey home, from the workspace root so relative
/// paths in a documented example resolve as they would for a reader.
pub(crate) fn run_in_journey_home<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    crate::steps::cli::mvmctl_command()
        .current_dir(crate::steps::cli::workspace_root())
        .args(args)
        .isolated_home(journey_home())
        .output()
        .expect("failed to spawn mvmctl against the journey home")
}

/// Boot the journey guest, once per process.
///
/// Returns the boot output so the first caller can assert on it; later callers
/// observe the same stored result. A failed boot is not retried — a second
/// attempt against a half-created machine reports a name collision, which
/// buries the real error under a misleading one.
fn ensure_journey_machine() -> &'static Result<(), String> {
    static BOOTED: OnceLock<Result<(), String>> = OnceLock::new();
    BOOTED.get_or_init(|| {
        // Reclaim a machine leaked by an aborted earlier run before creating.
        let _ = run_in_journey_home(["machine", "stop", JOURNEY_MACHINE, "--yes"]);
        let _ = run_in_journey_home(["machine", "rm", JOURNEY_MACHINE, "--yes"]);

        // `nginx` rather than a bare `alpine`: every verb below needs a guest
        // that is still up when it runs. An image with no long-running process
        // boots, finds nothing to run and exits, and the state directory is
        // gone by the next scenario — which then reports "never booted" and
        // reads as a broken verb rather than a finished guest.
        let create = run_in_journey_home([
            "machine",
            "create",
            JOURNEY_MACHINE,
            "--image",
            "nginx",
            "--cpus",
            "2",
            "--memory",
            "512M",
        ]);
        if !create.status.success() {
            return Err(format!(
                "machine create failed: {}",
                String::from_utf8_lossy(&create.stderr).trim()
            ));
        }

        let start = run_in_journey_home(["machine", "start", JOURNEY_MACHINE]);
        if !start.status.success() {
            return Err(format!(
                "machine start failed: {}",
                String::from_utf8_lossy(&start.stderr).trim()
            ));
        }

        // Exit 0 from `start` is not the same as a guest that is up. Confirm
        // the state directory the runtime verbs resolve against actually
        // exists, so a guest that booted and exited is reported here — once,
        // naming the boot — rather than as one cryptic failure per verb.
        let state_dir = journey_home().join("vms").join(JOURNEY_MACHINE);
        if !state_dir.exists() {
            return Err(format!(
                "machine start exited 0 but {} does not exist — the guest is \
                 not running. An image with no long-running process boots and \
                 exits immediately.",
                state_dir.display()
            ));
        }
        Ok(())
    })
}

#[given(expr = "the journey machine is running")]
fn journey_machine_is_running(world: &mut CliWorld) {
    match ensure_journey_machine() {
        Ok(()) => {}
        Err(problem) => panic!("the journey guest could not be booted: {problem}"),
    }
    world.journey_machine = Some(JOURNEY_MACHINE.to_string());
}

/// Drive a documented command against the running journey machine.
///
/// `{machine}` in the argument string is substituted with the journey guest's
/// name, so the feature file reads like the documentation it mirrors while
/// still operating the one guest this feature booted.
#[when(expr = "I run mvmctl against the journey machine with {string}")]
fn run_against_journey_machine(world: &mut CliWorld, args: String) {
    let name = world
        .journey_machine
        .clone()
        .expect("the journey machine step must run first");
    let rendered = args.replace("{machine}", &name);
    world.last_run = Some(run_in_journey_home(rendered.split_whitespace()));
}

/// Stage a host-side file the documented example copies into the guest.
#[given(expr = "a host file {string} exists")]
fn a_host_file_exists(_world: &mut CliWorld, relative: String) {
    let path = crate::steps::cli::workspace_root().join(&relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create host fixture parent");
    }
    std::fs::write(&path, b"{\"journey\":true}\n").expect("write host fixture");
}

#[then(expr = "the journey machine is still running")]
fn journey_machine_still_running(world: &mut CliWorld) {
    let name = world
        .journey_machine
        .clone()
        .expect("the journey machine step must run first");
    // A verb that leaves the guest dead breaks every scenario after it, and
    // the failure surfaces on the *next* scenario rather than the one that
    // caused it. Check here so the blame lands on the right verb.
    let output = run_in_journey_home(["machine", "inspect", &name]);
    assert!(
        output.status.success(),
        "the journey guest is no longer inspectable after this scenario: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

#[then(expr = "the journey machine is torn down")]
fn journey_machine_torn_down(world: &mut CliWorld) {
    let name = world
        .journey_machine
        .clone()
        .expect("the journey machine step must run first");
    let stop = run_in_journey_home(["machine", "stop", &name, "--yes"]);
    assert!(
        stop.status.success(),
        "machine stop failed: {}",
        String::from_utf8_lossy(&stop.stderr).trim()
    );
    let remove = run_in_journey_home(["machine", "rm", &name, "--yes"]);
    assert!(
        remove.status.success(),
        "machine rm failed: {}",
        String::from_utf8_lossy(&remove.stderr).trim()
    );
}
