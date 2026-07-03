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

/// Env var overriding the `mvmctl` binary path (shared with `machine.rs`).
const MVM_CLI_BIN_ENV: &str = "MVM_CLI_BIN";

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
    fn run_cli(&self, args: &[&str]) -> Result<Vec<u8>> {
        let out = Command::new(self.bin())
            .arg("machine")
            .args(args)
            .output()
            .map_err(|e| MvmError::Backend {
                reason: format!("spawn mvmctl: {e}"),
            })?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(exit_to_error(
                out.status.code().unwrap_or(-1),
                &String::from_utf8_lossy(&out.stderr),
            ))
        }
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

/// One item of `mvmctl machine ls --json`: the persisted spec, of which `name`
/// and the live `status` label are load-bearing here (other fields ignored).
/// `status` is `#[serde(default)]` so an older CLI without the field degrades
/// to `Stopped` rather than failing the parse.
#[derive(serde::Deserialize)]
struct MachineListItem {
    name: String,
    #[serde(default)]
    status: Option<String>,
}

/// Map the CLI's `ls --json` status label to a facade [`MachineStatus`].
fn status_from_label(label: Option<&str>) -> MachineStatus {
    match label {
        Some("running") => MachineStatus::Running,
        Some("starting") => MachineStatus::Starting,
        Some("failed") => MachineStatus::Failed,
        // `stopped`, absent (older CLI), or anything unrecognized → stopped.
        _ => MachineStatus::Stopped,
    }
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
            status: status_from_label(it.status.as_deref()),
            name: it.name,
        })
        .collect())
}

#[async_trait]
impl MvmClient for SubprocessBackend {
    async fn list_machines(&self, filter: MachineFilter) -> Result<Vec<MachineState>> {
        let stdout = self.run_cli(&["ls", "--json"])?;
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
        self.run_cli(&["stop", id.0.as_str()]).map(|_| ())
    }

    async fn machine_logs(&self, id: &MachineId, opts: LogOpts) -> Result<Vec<u8>> {
        let lines = opts.tail_lines.map(|n| n.to_string());
        let mut args: Vec<&str> = vec!["logs", id.0.as_str()];
        if let Some(ref n) = lines {
            args.push("--lines");
            args.push(n.as_str());
        }
        self.run_cli(&args)
    }

    async fn exec_machine(&self, id: &MachineId, command: Vec<String>) -> Result<ExecResult> {
        // `mvmctl machine exec --name <id> -- <command...>`. A non-zero exit is a
        // valid result (the command failed), not a spawn error, so this captures
        // the full Output rather than going through `run_cli`.
        let mut args: Vec<String> = vec!["exec".into(), "--name".into(), id.0.clone(), "--".into()];
        args.extend(command);
        let out = std::process::Command::new(self.bin())
            .arg("machine")
            .args(&args)
            .output()
            .map_err(|e| MvmError::Backend {
                reason: format!("spawn mvmctl: {e}"),
            })?;
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
    fn parses_machine_ls_json_with_live_status() {
        // Unknown fields (image) ignored; `status` maps to the facade status.
        let json =
            br#"[{"name":"web","image":"x","status":"running"},{"name":"api","status":"stopped"}]"#;
        let states = parse_machine_list(json).unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].id, MachineId("web".into()));
        assert_eq!(states[0].status, MachineStatus::Running);
        assert_eq!(states[1].status, MachineStatus::Stopped);
    }

    #[test]
    fn missing_status_degrades_to_stopped() {
        // An older CLI without the `status` field must not fail the parse.
        let json = br#"[{"name":"web"}]"#;
        let states = parse_machine_list(json).unwrap();
        assert_eq!(states[0].status, MachineStatus::Stopped);
    }

    #[test]
    fn status_label_mapping_is_total() {
        assert_eq!(status_from_label(Some("running")), MachineStatus::Running);
        assert_eq!(status_from_label(Some("starting")), MachineStatus::Starting);
        assert_eq!(status_from_label(Some("failed")), MachineStatus::Failed);
        assert_eq!(status_from_label(Some("stopped")), MachineStatus::Stopped);
        assert_eq!(status_from_label(Some("weird")), MachineStatus::Stopped);
        assert_eq!(status_from_label(None), MachineStatus::Stopped);
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
}
