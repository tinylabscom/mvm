//! Steps for `features/suites/s40_mission_demo/mission_demo.feature`.
//!
//! The demo is a test in `mvm-hostd`; these steps run it once and read its
//! output, so the scenarios cannot drift from the script they describe.

use std::process::Command;

use cucumber::{then, when};

use crate::world::CliWorld;

#[when("the scripted mission demo runs")]
fn run_demo(world: &mut CliWorld) {
    let output = Command::new("cargo")
        .args(["test", "-p", "mvm-hostd", "--test", "mission_demo"])
        .args(["--", "--nocapture"])
        .current_dir(crate::steps::cli::workspace_root())
        .env_remove("RUSTFLAGS")
        .output()
        .expect("spawn `cargo test` for the mission demo");
    world.last_run = Some(output);
}

fn stdout(world: &CliWorld) -> String {
    let run = world.last_run.as_ref().expect("the demo ran");
    String::from_utf8_lossy(&run.stdout).into_owned()
}

#[then("the demo passes")]
fn demo_passes(world: &mut CliWorld) {
    let run = world.last_run.as_ref().expect("the demo ran");
    assert!(
        run.status.success(),
        "mission demo failed:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[then(
    "the evidence timeline lists, in order, launch, the denials, quarantine, replacement and relaunch"
)]
fn timeline_order(world: &mut CliWorld) {
    let out = stdout(world);
    let timeline = out
        .split("--- evidence timeline")
        .nth(1)
        .expect("the demo prints its timeline");
    let mut at = 0;
    for event in [
        "plan.launched",
        "plan.admission_refused",
        "workload.quarantined",
        "workload.replaced",
        "plan.launched",
    ] {
        let found = timeline[at..]
            .find(event)
            .unwrap_or_else(|| panic!("`{event}` missing or out of order in:\n{timeline}"));
        at += found + event.len();
    }
}

#[then("the demo output says the mailbox is local-only and the VMs are simulated")]
fn says_simulated(world: &mut CliWorld) {
    let out = stdout(world);
    assert!(
        out.contains("simulated: mailbox delivery") && out.contains("VMs"),
        "the demo must disclose what it simulates:\n{out}"
    );
}
