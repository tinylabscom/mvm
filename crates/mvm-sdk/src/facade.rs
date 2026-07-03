//! A subprocess-backed `MvmClient`: the SDK drives machine lifecycle through the
//! `mvmctl machine` CLI, behind the shared facade trait. The process boundary is
//! deliberate — linking the in-process backend here would form a dependency
//! cycle (sdk -> mvm-client[local] -> mvm-backend -> mvm-build -> sdk). `run`
//! waits on the admitted-boot library seam so it never boots a workload that
//! skipped signed-plan admission.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use async_trait::async_trait;
use mvm_client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus,
};
use mvm_client::{MvmClient, MvmError, Result};

use crate::machine::{Machine, MachineError, MachineLs};

/// Env var overriding the `mvmctl` binary path (shared with `machine.rs`).
const MVM_CLI_BIN_ENV: &str = "MVM_CLI_BIN";

/// Surface a `machine.rs` builder error (empty name, etc.) as a backend error.
fn machine_err(e: MachineError) -> MvmError {
    MvmError::Backend {
        reason: e.to_string(),
    }
}

// The `machine` subcommand argv is built in exactly one place — the pure
// `machine.rs` builders, which the cross-language conformance harness pins to
// `sdks/machine-fixtures/*.argv`. The facade delegates to them rather than
// hand-rolling a second copy, so it can never drift from the CLI contract.

fn list_args() -> Result<Vec<String>> {
    MachineLs::builder()
        .json(true)
        .machine_args()
        .map_err(machine_err)
}

fn stop_args(id: &MachineId) -> Result<Vec<String>> {
    Machine::named(&id.0)
        .and_then(|m| m.stop().machine_args())
        .map_err(machine_err)
}

fn logs_args(id: &MachineId, opts: &LogOpts) -> Result<Vec<String>> {
    let mut builder = Machine::named(&id.0).map_err(machine_err)?.logs();
    if opts.follow {
        builder = builder.follow(true);
    }
    if let Some(lines) = opts.tail_lines {
        builder = builder.lines(lines);
    }
    builder.machine_args().map_err(machine_err)
}

fn exec_args(id: &MachineId, command: Vec<String>) -> Result<Vec<String>> {
    Machine::named(&id.0)
        .map_err(machine_err)?
        .exec(command)
        .machine_args()
        .map_err(machine_err)
}

/// Drives machine lifecycle by shelling `mvmctl machine`. Construct with
/// [`SubprocessBackend::from_env`] (respects `MVM_CLI_BIN`) or
/// [`SubprocessBackend::new`].
pub struct SubprocessBackend {
    cli_bin: PathBuf,
}

impl SubprocessBackend {
    pub fn new(cli_bin: impl Into<PathBuf>) -> Self {
        Self {
            cli_bin: cli_bin.into(),
        }
    }

    pub fn from_env() -> Self {
        let bin = std::env::var_os(MVM_CLI_BIN_ENV).unwrap_or_else(|| OsString::from("mvmctl"));
        Self::new(bin)
    }

    fn bin(&self) -> &Path {
        &self.cli_bin
    }

    /// Run `mvmctl machine <args>` and return stdout, or a `Backend` error
    /// carrying stderr on non-zero exit. Synchronous `Command` (a short-lived
    /// CLI call), mirroring the sibling `machine.rs`.
    fn run_cli(&self, args: &[String]) -> Result<Vec<u8>> {
        let out = self.capture(args)?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(exit_to_error(
                out.status.code().unwrap_or(-1),
                &String::from_utf8_lossy(&out.stderr),
            ))
        }
    }

    /// Spawn `mvmctl machine <args>` and return the raw `Output` (caller decides
    /// how to interpret the exit code).
    fn capture(&self, args: &[String]) -> Result<std::process::Output> {
        Command::new(self.bin())
            .arg("machine")
            .args(args)
            .output()
            .map_err(|e| MvmError::Backend {
                reason: format!("spawn mvmctl: {e}"),
            })
    }
}

impl Default for SubprocessBackend {
    fn default() -> Self {
        Self::from_env()
    }
}

fn exit_to_error(code: i32, stderr: &str) -> MvmError {
    MvmError::Backend {
        reason: format!("`mvmctl machine` exited {code}: {}", stderr.trim()),
    }
}

/// One item of `mvmctl machine ls --json`. That output is the persisted spec;
/// only `name` is load-bearing here, and it carries no runtime status.
#[derive(serde::Deserialize)]
struct MachineListItem {
    name: String,
}

fn parse_machine_list(bytes: &[u8]) -> Result<Vec<MachineState>> {
    let items: Vec<MachineListItem> =
        serde_json::from_slice(bytes).map_err(|e| MvmError::Backend {
            reason: format!("parsing `machine ls --json`: {e}"),
        })?;
    Ok(items
        .into_iter()
        .map(|it| MachineState {
            id: MachineId(it.name.clone()),
            name: it.name,
            // `machine ls --json` lists persisted specs and carries no runtime
            // status, so this reports Stopped. That is the documented gap vs
            // LocalBackend (which queries live state); a status-aware listing
            // closes it.
            status: MachineStatus::Stopped,
        })
        .collect())
}

#[async_trait]
impl MvmClient for SubprocessBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let stdout = self.run_cli(&list_args()?)?;
        let machines = parse_machine_list(&stdout)?;
        Ok(machines.into_iter().filter(|m| filter.matches(m)).collect())
    }

    async fn run_machine(&self, _spec: MachineSpec) -> Result<MachineState> {
        Err(MvmError::Backend {
            reason: "local run requires the admitted-boot library seam (signed-plan admission)"
                .into(),
        })
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        self.run_cli(&stop_args(id)?).map(|_| ())
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        self.run_cli(&logs_args(id, &opts)?)
    }

    async fn exec_machine(&self, id: &MachineId, command: Vec<String>) -> Result<ExecResult> {
        // A non-zero exit is a valid result (the command failed), not a spawn
        // error, so this captures the full Output rather than going through
        // `run_cli`.
        let out = self.capture(&exec_args(id, command)?)?;
        Ok(ExecResult {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_nonzero_exit_to_backend_error() {
        assert!(matches!(exit_to_error(2, "boom"), MvmError::Backend { .. }));
    }

    #[test]
    fn parses_machine_ls_json_into_states() {
        // Extra fields (image/status) are ignored; only `name` is needed.
        let json = br#"[{"name":"web","image":"x"},{"name":"api"}]"#;
        let states = parse_machine_list(json).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].id, MachineId("web".into()));
        assert_eq!(states[0].name, "web");
    }

    #[tokio::test]
    async fn run_refuses_pending_admitted_boot() {
        let be = SubprocessBackend::new("mvmctl");
        let spec = MachineSpec {
            name: "w".into(),
            image: "i".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
        };
        assert!(matches!(
            be.run_machine(spec).await,
            Err(MvmError::Backend { .. })
        ));
    }

    /// Read a shared machine-verb fixture (mirrors the conformance harness).
    fn fixture(name: &str) -> Vec<String> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../sdks/machine-fixtures")
                .join(format!("{name}.argv")),
        )
        .expect("read shared machine fixture")
        .lines()
        .map(str::to_string)
        .collect()
    }

    // The facade builds argv only through the conformed `machine.rs` builders,
    // so its argv is pinned to the same shared fixtures the CLI/Python/TS/Rust
    // harness enforces.

    #[test]
    fn list_argv_matches_shared_fixture() {
        assert_eq!(list_args().unwrap(), fixture("ls"));
    }

    #[test]
    fn stop_argv_matches_shared_fixture() {
        // Positional name — the bug the harness caught, now inherited-correct.
        assert_eq!(
            stop_args(&MachineId("web".into())).unwrap(),
            fixture("stop")
        );
    }

    #[test]
    fn logs_argv_matches_shared_fixture() {
        let opts = LogOpts {
            follow: true,
            tail_lines: Some(100),
        };
        assert_eq!(
            logs_args(&MachineId("web".into()), &opts).unwrap(),
            fixture("logs")
        );
    }

    #[test]
    fn exec_argv_delegates_to_the_conformed_builder() {
        // The facade's exec carries no `--force` (the trait exposes none), so it
        // maps to the fixture minus that flag — proving it is the same conformed
        // builder, not a hand-rolled second copy.
        let id = MachineId("web".into());
        let cmd = vec!["sh".to_string(), "-lc".to_string(), "echo ok".to_string()];
        assert_eq!(
            exec_args(&id, cmd).unwrap(),
            vec!["exec", "--name", "web", "--", "sh", "-lc", "echo ok"]
        );
    }
}
