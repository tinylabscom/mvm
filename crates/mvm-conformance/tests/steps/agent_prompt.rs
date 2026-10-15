//! Live witness for the agent prompt transport and its replay.
//!
//! One machine runs `examples/agent-prompt`, whose agent answers each prompt
//! with a turn count it keeps in guest memory-backed `/tmp`. Two prompts are
//! recorded against it, the session is replayed onto a fork of its base
//! checkpoint, and a third prompt to the fork must come back as turn three:
//! a replay that delivered nothing, or delivered onto the wrong state, answers
//! with a different turn. That third prompt is recorded and step-checkpointed
//! under the fork's own session, which is replayed onto a second fork, so a
//! fork's state and devices survive being snapshotted and restored again.

use cucumber::{given, then, when};
use mvm_conformance::prompt_fixture::{
    AGENT_MACHINE, PROMPT_MACHINES, clear_stale_prompt_sessions,
};

use crate::steps::machine_journey::{journey_home, run_in_journey_home};
use crate::world::CliWorld;

fn reclaim(name: &str) {
    let _ = run_in_journey_home(["machine", "stop", name, "--yes"]);
    let _ = run_in_journey_home(["machine", "rm", name, "--yes"]);
}

/// Forks first, so no parent is removed while a fork restored from it runs.
fn reclaim_prompt_machines() {
    for name in PROMPT_MACHINES.into_iter().rev() {
        reclaim(name);
    }
}

#[given(expr = "the prompt agent machine is running")]
fn prompt_agent_machine_is_running(_world: &mut CliWorld) {
    reclaim_prompt_machines();
    // A previous run can leave either timeline behind. Never adopt a fork's
    // history under a new workload identity.
    clear_stale_prompt_sessions(journey_home()).expect("remove stale prompt sessions");
    let run = run_in_journey_home([
        "machine",
        "run",
        "--flake",
        "examples/agent-prompt",
        "--name",
        AGENT_MACHINE,
        "-d",
    ]);
    assert!(
        run.status.success(),
        "booting the prompt agent failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[when(expr = "I run mvmctl against the prompt agent with {string}")]
fn run_against_prompt_agent(world: &mut CliWorld, args: String) {
    world.last_run = Some(run_in_journey_home(args.split_whitespace()));
}

#[then(expr = "the prompt agent machines are removed")]
fn prompt_agent_machines_are_removed(_world: &mut CliWorld) {
    reclaim_prompt_machines();
    clear_stale_prompt_sessions(journey_home()).expect("remove completed prompt sessions");
}

/// Both streams of the last run, as one string.
fn combined_output(world: &CliWorld) -> String {
    let output = world.last_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Status lines go to whichever stream the CLI's chrome uses, so this reads
/// both; the agent's own answers are asserted on stdout with
/// `the output contains`.
#[then(expr = "the prompt agent reports {string}")]
fn prompt_agent_reports(world: &mut CliWorld, needle: String) {
    let combined = combined_output(world);
    assert!(
        combined.contains(needle.as_str()),
        "expected {needle:?} in the output:\n{combined}"
    );
}

/// A prompt whose step checkpoint failed still exits 0, because the agent
/// answered; the warning is the only sign the session can no longer be
/// replayed past it. Asserting its absence at the prompt names the failure
/// and its reason here, instead of at the replay that cannot find a resume
/// point.
#[then(expr = "the prompt agent does not report {string}")]
fn prompt_agent_does_not_report(world: &mut CliWorld, needle: String) {
    let combined = combined_output(world);
    assert!(
        !combined.contains(needle.as_str()),
        "unexpected {needle:?} in the output:\n{combined}"
    );
}
