//! Live witness for the agent prompt transport and its replay.
//!
//! One machine runs `examples/agent-prompt`, whose agent answers each prompt
//! with a turn count it keeps in guest memory-backed `/tmp`. Two prompts are
//! recorded against it, the session is replayed onto a fork of its base
//! checkpoint, and a third prompt to the fork must come back as turn three:
//! a replay that delivered nothing, or delivered onto the wrong state, answers
//! with a different turn.

use cucumber::{given, then, when};

use crate::steps::machine_journey::{journey_home, run_in_journey_home};
use crate::world::CliWorld;

/// The machine the prompts are recorded against.
const AGENT_MACHINE: &str = "bdd-prompt";
/// The fork the recorded prompts are replayed onto.
const REPLAY_MACHINE: &str = "bdd-prompt-replay";

fn reclaim(name: &str) {
    let _ = run_in_journey_home(["machine", "stop", name, "--yes"]);
    let _ = run_in_journey_home(["machine", "rm", name, "--yes"]);
}

#[given(expr = "the prompt agent machine is running")]
fn prompt_agent_machine_is_running(_world: &mut CliWorld) {
    reclaim(REPLAY_MACHINE);
    reclaim(AGENT_MACHINE);
    // A session left by an earlier run would put its prompts on this run's
    // timeline. Sessions have no delete verb, so the record goes with its
    // directory.
    let stale = journey_home().join("agent-sessions").join(AGENT_MACHINE);
    if stale.exists() {
        std::fs::remove_dir_all(&stale).expect("remove the previous run's agent session");
    }
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
    reclaim(REPLAY_MACHINE);
    reclaim(AGENT_MACHINE);
}

/// Status lines go to whichever stream the CLI's chrome uses, so this reads
/// both; the agent's own answers are asserted on stdout with
/// `the output contains`.
#[then(expr = "the prompt agent reports {string}")]
fn prompt_agent_reports(world: &mut CliWorld, needle: String) {
    let output = world.last_output();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(needle.as_str()),
        "expected {needle:?} in the output:\n{combined}"
    );
}
