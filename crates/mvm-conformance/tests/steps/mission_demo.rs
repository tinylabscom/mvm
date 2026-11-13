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

#[when("the production mailbox helper witness runs")]
fn run_production_mailbox_helper(world: &mut CliWorld) {
    let output = Command::new("cargo")
        .args([
            "test",
            "-p",
            "mvm-hostd",
            "--lib",
            "mailbox_process::tests::production_helper_requires_retained_custody_and_returns_signed_local_receipt",
            "--",
            "--exact",
        ])
        .current_dir(crate::steps::cli::workspace_root())
        .env_remove("RUSTFLAGS")
        .output()
        .expect("spawn the production mailbox helper test");
    world.last_run = Some(output);
}

#[then("the production mailbox helper witness passes")]
fn production_mailbox_helper_passes(world: &mut CliWorld) {
    let run = world.last_run.as_ref().expect("the witness ran");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success()
            && stdout.contains(
                "production_helper_requires_retained_custody_and_returns_signed_local_receipt"
            )
            && stdout.contains("1 passed; 0 failed"),
        "production mailbox helper witness failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&run.stderr)
    );
}

#[when("the booted local-durable mailbox witness runs")]
fn run_booted_local_mailbox(world: &mut CliWorld) {
    let root = crate::steps::cli::workspace_root();
    let home = tempfile::tempdir().expect("isolated live mailbox home");
    crate::steps::live_home::prepare_live_home(home.path());
    let output = Command::new("bash")
        .arg("scripts/mailbox-local-live-witness.sh")
        .current_dir(root)
        .env("MVM_HOME", home.path())
        .env(
            crate::steps::live_home::RUNTIME_ACQUIRE_MODE_ENV,
            crate::steps::live_home::RUNTIME_ACQUIRE_MODE,
        )
        .env(
            "MVMCTL",
            std::env::var_os("CARGO_BIN_EXE_mvmctl")
                .expect("the live lane built mvmctl before running scenarios"),
        )
        .output()
        .expect("spawn the booted-guest mailbox witness");
    world.last_run = Some(output);
}

#[then("the booted local-durable mailbox witness passes")]
fn booted_local_mailbox_passes(world: &mut CliWorld) {
    let run = world.last_run.as_ref().expect("the witness ran");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success()
            && stdout.contains("booted guest: verified V2 acceptance and signed Receive/ACK")
            && stdout.contains("booted guest: missing retention refused before helper readiness")
            && stdout.contains("booted guest: retained journal survived the VM stop")
            && stdout.contains("WITNESS_RESULT=pass"),
        "booted mailbox witness failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&run.stderr)
    );
}

#[then("the production helper recovers the signed ACK and same-ID retry")]
fn production_helper_recovers_ack(world: &mut CliWorld) {
    run_production_mailbox_helper(world);
    production_mailbox_helper_passes(world);
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

#[then("the demo output says the nodes and VMs are simulated and the mailbox is not cross-host")]
fn says_simulated(world: &mut CliWorld) {
    let out = stdout(world);
    assert!(
        out.contains(
            "simulated: the three nodes are simulated nodes in one test process; their VMs are gated and audited but none boots here; node-to-node mailbox delivery is a local Unix socket or a loopback TCP transport (no Iroh, no cross-host transport); the booted-guest mailbox path is wired through the backend capability on Firecracker and HVF and live-witnessed by separate manual runs, not CI lanes: many messages per VM on Firecracker, HVF re-witness pending, see Demo status in specs/contracts/host-interface-distributed-execution.md"
        ),
        "the demo must disclose what it simulates:\n{out}"
    );
}

#[then("the cross-node delivery test ran and passed")]
fn cross_node_delivery(world: &mut CliWorld) {
    let out = stdout(world);
    assert!(
        out.contains("two_nodes_deliver_over_a_loopback_tcp_peer_transport ... ok"),
        "the TCP delivery test must run:\n{out}"
    );
}
