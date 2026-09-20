//! Live witness for the published agent-workload example.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::OnceLock;

use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;

use crate::world::CliWorld;

const SMOKE_SECRET: &str = "agent-workload-smoke";

fn agent_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        std::env::var_os("MVM_E2E_HOME")
            .or_else(|| std::env::var_os("MVM_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let path = std::env::temp_dir().join("mvm-agent-workload-home");
                std::fs::create_dir_all(&path).expect("create agent workload MVM_HOME");
                path
            })
    })
}

fn run_agent_command<I, S>(args: I, stdin: Option<&[u8]>) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut command = crate::steps::cli::mvmctl_command();
    command
        .current_dir(crate::steps::cli::workspace_root())
        .args(args)
        .isolated_home(agent_home());

    let Some(input) = stdin else {
        return command.output().expect("run agent-workload mvmctl command");
    };

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-workload mvmctl command");
    child
        .stdin
        .take()
        .expect("piped stdin must exist")
        .write_all(input)
        .expect("write agent-workload command stdin");
    child
        .wait_with_output()
        .expect("wait for agent-workload mvmctl command")
}

#[given(expr = "the agent workload smoke secret is stored")]
fn store_agent_workload_smoke_secret(_world: &mut CliWorld) {
    let _ = run_agent_command(["secret", "rm", SMOKE_SECRET], None);
    let output = run_agent_command(
        [
            "secret",
            "set",
            SMOKE_SECRET,
            "--provider",
            "anthropic",
            "--value",
            "-",
        ],
        Some(b"not-a-real-key"),
    );
    assert!(
        output.status.success(),
        "storing the smoke secret failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[when(expr = "I run the agent workload example with {string}")]
fn run_agent_workload_example(world: &mut CliWorld, args: String) {
    world.last_run = Some(run_agent_command(
        mvm_conformance::doc_examples::tokenize(&args),
        Some(b""),
    ));
}

#[when(expr = "I verify the agent workload audit chain")]
fn verify_agent_workload_audit_chain(world: &mut CliWorld) {
    world.last_run = Some(run_agent_command(["trust", "audit", "verify"], None));
}

#[then(expr = "the agent workload smoke secret is removed with {string}")]
fn remove_agent_workload_smoke_secret(_world: &mut CliWorld, args: String) {
    let output = run_agent_command(mvm_conformance::doc_examples::tokenize(&args), None);
    assert!(
        output.status.success(),
        "removing the smoke secret failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
