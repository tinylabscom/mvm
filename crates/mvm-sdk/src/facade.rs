//! A subprocess-backed `MvmClient`: the SDK drives machine lifecycle through the
//! `mvmctl machine` CLI, behind the shared facade trait. The process boundary is
//! deliberate — linking the in-process backend here would form a dependency
//! cycle (sdk -> mvm-client::LocalBackend -> mvm-backend -> mvm-build -> sdk).
//!
//! `run` shells `mvmctl machine run --up-json`, which performs the full OCI
//! pull + rootfs materialize + signed-plan admission (claim 8) + boot and prints
//! the vm_id envelope this facade parses. The facade never re-implements (or
//! bypasses) admission — the CLI is the one admitted-boot path.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use async_trait::async_trait;
use mvm_core::client::dto::{
    ExecResult, LogOpts, MachineFilter, MachineId, MachineSpec, MachineState, MachineStatus,
    ReconfigureRequest,
};
use mvm_core::client::{MvmClient, MvmError, Result};

use crate::machine::{Machine, MachineCreate, MachineError, MachineLs};

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
// `tests/machine-fixtures/*.argv`. The facade delegates to them rather than
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

/// Build the argv for a persistent, admitted boot: `machine run --image … --name …
/// --up-json`. `--up-json` makes the run detached + persistent (so the machine is
/// afterward listable/stoppable) and prints the vm_id envelope. This is a
/// facade-internal invocation — not one of the cross-language `machine` verbs the
/// conformance harness pins — so it is built here rather than via a shared builder.
fn run_args(spec: &MachineSpec) -> Result<Vec<String>> {
    if spec.name.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "name must not be empty".into(),
        });
    }
    if spec.image.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "image must not be empty".into(),
        });
    }
    let mut args = vec![
        "run".to_string(),
        "--image".to_string(),
        spec.image.clone(),
        "--name".to_string(),
        spec.name.clone(),
        "--cpus".to_string(),
        spec.cpus.to_string(),
        "--memory".to_string(),
        format!("{}M", spec.memory_mib),
    ];
    for (k, v) in &spec.env {
        args.push("--env".to_string());
        args.push(format!("{k}={v}"));
    }
    args.push("--up-json".to_string());
    Ok(args)
}

/// Build the argv for `machine create --name … --image …` — persists the spec
/// without booting. Uses the shared builder so it can't drift from the CLI.
fn create_args(spec: &MachineSpec) -> Result<Vec<String>> {
    if spec.name.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "name must not be empty".into(),
        });
    }
    if spec.image.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "image must not be empty".into(),
        });
    }
    MachineCreate::builder(&spec.name)
        .image(&spec.image)
        .cpus(spec.cpus as u16)
        .memory(format!("{}M", spec.memory_mib))
        .machine_args()
        .map_err(machine_err)
}

fn start_args(id: &MachineId) -> Result<Vec<String>> {
    Machine::named(&id.0)
        .map_err(machine_err)?
        .start()
        .machine_args()
        .map_err(machine_err)
}

fn rm_args(id: &MachineId) -> Result<Vec<String>> {
    Machine::named(&id.0)
        .map_err(machine_err)?
        .rm()
        // Non-interactive: the facade never prompts.
        .yes(true)
        .machine_args()
        .map_err(machine_err)
}

/// The `machine run --up-json` boot envelope. The CLI prints it as the sole
/// stdout line once the machine has booted; only `vm_id` is load-bearing here.
#[derive(serde::Deserialize)]
struct UpJsonEnvelope {
    vm_id: String,
}

fn parse_up_json(bytes: &[u8]) -> Result<MachineId> {
    // Defensive: take the last non-empty stdout line, so any leading chatter a
    // future CLI build might emit doesn't break the parse.
    let text = String::from_utf8_lossy(bytes);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let envelope: UpJsonEnvelope = serde_json::from_str(line).map_err(|e| MvmError::Backend {
        reason: format!("parsing `machine run --up-json` envelope: {e}"),
    })?;
    Ok(MachineId(envelope.vm_id))
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
            ..Default::default()
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

    async fn inspect_machine(&self, id: &MachineId) -> Result<MachineState> {
        // The facade's MachineState is the live runtime state, which
        // `machine ls` reports; `machine inspect` dumps the persisted spec.
        let stdout = self.run_cli(&list_args()?)?;
        parse_machine_list(&stdout)?
            .into_iter()
            .find(|m| m.id == *id)
            .ok_or_else(|| MvmError::NotFound { id: id.0.clone() })
    }

    async fn create_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        // `machine create` persists the spec without booting → stopped.
        let name = spec.name.clone();
        self.run_cli(&create_args(&spec)?)?;
        Ok(MachineState {
            id: MachineId(name.clone()),
            name,
            status: MachineStatus::Stopped,
            ..Default::default()
        })
    }

    async fn run_machine(&self, spec: MachineSpec) -> Result<MachineState> {
        // `machine run` does the full OCI pull + rootfs materialize + signed-plan
        // admission (claim 8) + boot; `--up-json` boots it detached and prints the
        // vm_id envelope. Shelling it keeps the CLI as the one admitted-boot path.
        let stdout = self.run_cli(&run_args(&spec)?)?;
        let id = parse_up_json(&stdout)?;
        Ok(MachineState {
            name: id.0.clone(),
            id,
            status: MachineStatus::Running,
            ..Default::default()
        })
    }

    async fn start_machine(&self, id: &MachineId) -> Result<MachineState> {
        self.run_cli(&start_args(id)?)?;
        Ok(MachineState {
            id: id.clone(),
            name: id.0.clone(),
            status: MachineStatus::Running,
            ..Default::default()
        })
    }

    async fn stop_machine(&self, id: &MachineId) -> Result<()> {
        self.run_cli(&stop_args(id)?).map(|_| ())
    }

    async fn remove_machine(&self, id: &MachineId) -> Result<()> {
        self.run_cli(&rm_args(id)?).map(|_| ())
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

    async fn reconfigure_machine(
        &self,
        _id: &MachineId,
        _cfg: ReconfigureRequest,
    ) -> Result<MachineState> {
        // Reconfigure patches a persisted machine record and relaunches it —
        // state this subprocess courier doesn't own. Drive it through the CLI
        // (`mvmctl machine reconfigure`) or `LocalBackend` directly.
        Err(MvmError::Backend {
            reason: "reconfigure is not supported via the subprocess facade; \
                     use `mvmctl machine reconfigure` or LocalBackend"
                .into(),
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

    #[test]
    fn run_args_builds_persistent_up_json_invocation() {
        let spec = MachineSpec {
            name: "web".into(),
            image: "alpine:latest".into(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("MODE".into(), "test".into())],
        };
        assert_eq!(
            run_args(&spec).unwrap(),
            vec![
                "run",
                "--image",
                "alpine:latest",
                "--name",
                "web",
                "--cpus",
                "2",
                "--memory",
                "512M",
                "--env",
                "MODE=test",
                "--up-json",
            ]
        );
    }

    #[test]
    fn create_start_rm_args_build_the_machine_verbs() {
        // Matches the shared `create-image.argv` conformance fixture, so the
        // client's create argv is drift-locked against the CLI + every SDK.
        let spec = MachineSpec {
            name: "web".into(),
            image: "alpine:3.20".into(),
            cpus: 2,
            memory_mib: 512,
            env: vec![],
        };
        assert_eq!(
            create_args(&spec).unwrap(),
            vec![
                "create",
                "--name",
                "web",
                "--image",
                "alpine:3.20",
                "--cpus",
                "2",
                "--memory",
                "512M",
            ]
        );

        let id = MachineId("db".into());
        assert_eq!(start_args(&id).unwrap(), vec!["start", "db"]);
        // rm is non-interactive (--yes) so the facade never blocks on a prompt.
        let rm = rm_args(&id).unwrap();
        assert_eq!(rm[0], "rm");
        assert!(rm.iter().any(|a| a == "db"));
        assert!(rm.iter().any(|a| a == "--yes"));
    }

    #[test]
    fn create_args_reject_empty_name_and_image() {
        let bad = MachineSpec {
            name: String::new(),
            image: "img".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
        };
        assert!(create_args(&bad).is_err());
    }

    #[test]
    fn run_args_rejects_empty_name_and_image() {
        let base = MachineSpec {
            name: "web".into(),
            image: "alpine".into(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
        };
        assert!(matches!(
            run_args(&MachineSpec {
                name: String::new(),
                ..base.clone()
            }),
            Err(MvmError::InvalidSpec { .. })
        ));
        assert!(matches!(
            run_args(&MachineSpec {
                image: String::new(),
                ..base
            }),
            Err(MvmError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn parse_up_json_extracts_vm_id_ignoring_leading_lines() {
        let out = b"some progress chatter\n{\"schema_version\":1,\"vm_id\":\"web\",\"build_mode\":\"prod\"}\n";
        assert_eq!(parse_up_json(out).unwrap(), MachineId("web".into()));
    }

    #[test]
    fn parse_up_json_surfaces_malformed_envelope() {
        assert!(matches!(
            parse_up_json(b"not json"),
            Err(MvmError::Backend { .. })
        ));
    }

    /// End-to-end shell path: a fake `mvmctl` that prints the boot envelope makes
    /// `run_machine` return a Running machine — proving the argv + parse + state
    /// mapping wire together (the real boot is the CLI's own tested concern).
    #[cfg(unix)]
    #[tokio::test]
    async fn run_boots_via_fake_mvmctl_and_returns_running() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-mvmctl");
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(
            f,
            "#!/bin/sh\necho '{{\"schema_version\":1,\"vm_id\":\"web\",\"build_mode\":\"prod\"}}'"
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let be = SubprocessBackend::new(&script);
        let state = be
            .run_machine(MachineSpec {
                name: "web".into(),
                image: "alpine:latest".into(),
                cpus: 1,
                memory_mib: 128,
                env: vec![],
            })
            .await
            .expect("run boots");
        assert_eq!(state.id, MachineId("web".into()));
        assert_eq!(state.name, "web");
        assert_eq!(state.status, MachineStatus::Running);
    }

    /// Read a shared machine-verb fixture (mirrors the conformance harness).
    fn fixture(name: &str) -> Vec<String> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/machine-fixtures")
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
            vec!["exec", "web", "--", "sh", "-lc", "echo ok"]
        );
    }
}
