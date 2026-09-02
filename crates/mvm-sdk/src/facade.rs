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
    PauseOpts, PauseOutcome, ReconfigureRequest, ResumeOpts, ResumeOutcome,
};
use mvm_core::client::{BackendCapabilityReport, MvmClient, MvmError, Result};

use crate::machine::{Machine, MachineCreate, MachineError, MachineLs};

// The name is owned by `crate::env`; this used to be a second copy that
// happened to agree, which is precisely why nothing could detect drift.
use crate::env::MVM_CLI_BIN_ENV;

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
//
// The workload's permission set is the one thing those builders do not model:
// they describe the cross-language `machine` verb surface, and a `Grants` is
// not part of it. [`grant_argv`] appends it, emitting only flags the CLI
// already parses — so the exception is where that argv is assembled, never
// what it says.

/// A permission set encoded for the command line, plus anything that has to
/// outlive the subprocess.
///
/// The temp file is held rather than returned as a path because `--grants-file`
/// is read by the child: dropping the handle before the spawn would hand the
/// CLI a path that no longer exists.
struct GrantArgv {
    args: Vec<String>,
    /// Present only when a dimension had no faithful flag.
    grants_file: Option<tempfile::NamedTempFile>,
}

/// Encode `grants` as `mvmctl` flags.
///
/// Three dimensions have a flag that means exactly them, and those are emitted
/// directly: a CPU share as `--cpu-limit <millicores>`, a bounded wall clock as
/// `--timeout <secs>`, and each granted destination as `--allow-host
/// <host>:<port>`, which is the spelling the CLI's own `--allow-host` parser
/// turns back into an egress grant.
///
/// Three cannot be said in flags at all, and each is written verbatim to a
/// `--grants-file` instead of being flattened into something close:
///
/// - A **fuel** budget is an instruction count; `--cpu-limit` is millicores.
///   There is no conversion between them, so there is nothing to emit.
/// - An **`Unbounded`** wall clock is not the same as omitting `--timeout`.
///   Omitting it leaves the dimension unspecified, which a host with a
///   `max_wall_clock_secs` ceiling admits; an explicit `Unbounded` is refused
///   by that same ceiling. Emitting nothing would turn a refusal into a boot.
/// - An **empty** allow-list is an explicit "no destinations", which zero
///   `--allow-host` flags would record as "no egress grant". Both deny all
///   traffic, so nothing opens either way, but only one of them is what the
///   caller declared, and the signed plan should say which.
///
/// An egress host containing a colon takes the same route: `--allow-host`
/// splits on the last one, so such a value would be parsed back as a different
/// host and port than it went in as.
fn grant_argv(grants: Option<&mvm_contract::grants::Grants>) -> Result<GrantArgv> {
    use mvm_contract::grants::{CpuGrant, WallClockGrant};

    let Some(grants) = grants else {
        return Ok(GrantArgv {
            args: Vec::new(),
            grants_file: None,
        });
    };

    let mut args = Vec::new();
    let mut needs_file = false;

    match grants.cpu {
        None => {}
        Some(CpuGrant::Share { millicores }) => {
            args.push("--cpu-limit".to_string());
            args.push(millicores.to_string());
        }
        Some(CpuGrant::Fuel { .. }) => needs_file = true,
    }

    match grants.wall_clock {
        None => {}
        Some(WallClockGrant::Secs { secs }) => {
            args.push("--timeout".to_string());
            args.push(secs.get().to_string());
        }
        Some(WallClockGrant::Unbounded) => needs_file = true,
    }

    if let Some(egress) = grants.egress.as_ref() {
        if egress.allow.is_empty() || egress.allow.iter().any(|hp| hp.host.contains(':')) {
            needs_file = true;
        } else {
            for hp in &egress.allow {
                args.push("--allow-host".to_string());
                args.push(format!("{}:{}", hp.host, hp.port));
            }
        }
    }

    if !needs_file {
        return Ok(GrantArgv {
            args,
            grants_file: None,
        });
    }

    // One encoding or the other, never a mix: the file already carries every
    // dimension, and adding flags beside it would be two statements of one
    // decision that a precedence rule then has to reconcile.
    let file = write_grants_file(grants)?;
    Ok(GrantArgv {
        args: vec![
            "--grants-file".to_string(),
            file.path().to_string_lossy().into_owned(),
        ],
        grants_file: Some(file),
    })
}

/// Serialize `grants` to a temp file in the exact shape `--grants-file` parses.
fn write_grants_file(grants: &mvm_contract::grants::Grants) -> Result<tempfile::NamedTempFile> {
    let backend_err = |reason: String| MvmError::Backend { reason };
    let json = serde_json::to_vec(grants)
        .map_err(|e| backend_err(format!("serializing grants for --grants-file: {e}")))?;
    let mut file = tempfile::Builder::new()
        .prefix("mvm-grants-")
        .suffix(".json")
        .tempfile()
        .map_err(|e| backend_err(format!("creating a temp file for --grants-file: {e}")))?;
    {
        use std::io::Write as _;
        file.write_all(&json)
            .and_then(|()| file.flush())
            .map_err(|e| backend_err(format!("writing --grants-file: {e}")))?;
    }
    Ok(file)
}

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
fn run_args(spec: &MachineSpec) -> Result<GrantArgv> {
    if spec.name.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "name must not be empty".into(),
        });
    }
    let mut args = vec![
        "run".to_string(),
        "--image".to_string(),
        // The written form of the declaration — the same token a user would
        // have typed, so the argv the CLI sees matches what the caller wrote.
        spec.image.to_string(),
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
    let mut grants = grant_argv(spec.grants.as_ref())?;
    args.append(&mut grants.args);
    args.push("--up-json".to_string());
    Ok(GrantArgv {
        args,
        grants_file: grants.grants_file,
    })
}

/// Build the argv for `machine create <name> --image …` — persists the spec
/// without booting. Uses the shared builder so it can't drift from the CLI.
fn create_args(spec: &MachineSpec) -> Result<GrantArgv> {
    if spec.name.is_empty() {
        return Err(MvmError::InvalidSpec {
            reason: "name must not be empty".into(),
        });
    }
    let mut args = MachineCreate::builder(&spec.name)
        .image(spec.image.to_string())
        .cpus(spec.cpus as u16)
        .memory(format!("{}M", spec.memory_mib))
        .machine_args()
        .map_err(machine_err)?;
    let mut grants = grant_argv(spec.grants.as_ref())?;
    args.append(&mut grants.args);
    Ok(GrantArgv {
        args,
        grants_file: grants.grants_file,
    })
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
    /// Refused, explicitly.
    ///
    /// This facade's entire surface is `mvmctl machine` argv, and that surface
    /// carries no capability query to shell out to. The report is a backend
    /// object describing itself — its `kind()` plus its own `VmCapabilities` —
    /// and neither is derivable from a subprocess that answers only about
    /// machines.
    ///
    /// Reconstructing one from a backend name would mean a second copy of the
    /// capability matrix living in a crate that cannot see the backends, and a
    /// stale copy of that table is worse than no answer at all: a consumer
    /// would plan around a capability the backend no longer has. So this
    /// refuses by type, and the two clients that hold a real backend —
    /// `mvm_client::LocalBackend` and `GatewayBackend` — answer it.
    async fn backend_capabilities(&self) -> Result<BackendCapabilityReport> {
        Err(MvmError::Unavailable {
            reason: "the mvmctl subprocess facade exposes no capability query; use \
                     mvm_client::LocalBackend for an in-process backend, or GatewayBackend \
                     for a remote one"
                .to_string(),
        })
    }

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
        // `invocation` is held across the call: when the grants needed a
        // `--grants-file`, dropping it first would delete the file the child
        // is about to read.
        let invocation = create_args(&spec)?;
        self.run_cli(&invocation.args)?;
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
        // Held across the call for the same reason as `create_machine`: a
        // `--grants-file` path must still exist when the child opens it.
        let invocation = run_args(&spec)?;
        let stdout = self.run_cli(&invocation.args)?;
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

    async fn pause_machine(&self, _id: &MachineId, _opts: PauseOpts) -> Result<PauseOutcome> {
        // Instance-snapshot pause is not one of the conformed `machine` verbs
        // this courier drives (it seals a host-local snapshot). Drive it through
        // the CLI (`mvmctl machine pause`) or `LocalBackend` directly.
        Err(MvmError::Backend {
            reason: "pause is not supported via the subprocess facade; \
                     use `mvmctl machine pause` or LocalBackend"
                .into(),
        })
    }

    async fn resume_machine(&self, _id: &MachineId, _opts: ResumeOpts) -> Result<ResumeOutcome> {
        // Symmetric with `pause_machine`.
        Err(MvmError::Backend {
            reason: "resume is not supported via the subprocess facade; \
                     use `mvmctl machine resume` or LocalBackend"
                .into(),
        })
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

    async fn set_ttl(&self, _id: &MachineId, _expires_at: Option<String>) -> Result<()> {
        // TTL lives in the host name registry, which this courier doesn't own.
        Err(MvmError::Backend {
            reason: "set-ttl is not supported via the subprocess facade; \
                     use `mvmctl set-ttl` or LocalBackend"
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

    #[tokio::test]
    async fn pause_and_resume_are_fail_closed_via_subprocess() {
        // The subprocess courier does not drive snapshot pause/resume; both must
        // refuse with a typed error (no `mvmctl` is spawned).
        let be = SubprocessBackend::new("/nonexistent/mvmctl");
        let id = MachineId("web".into());
        assert!(matches!(
            be.pause_machine(&id, PauseOpts::default()).await,
            Err(MvmError::Backend { .. })
        ));
        assert!(matches!(
            be.resume_machine(&id, ResumeOpts::default()).await,
            Err(MvmError::Backend { .. })
        ));
    }

    #[test]
    fn run_args_builds_persistent_up_json_invocation() {
        let spec = MachineSpec {
            name: "web".into(),
            image: "alpine:latest".parse().unwrap(),
            cpus: 2,
            memory_mib: 512,
            env: vec![("MODE".into(), "test".into())],
            grants: None,
            assurance_campaign: None,
        };
        assert_eq!(
            run_args(&spec).unwrap().args,
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
            image: "alpine:3.20".parse().unwrap(),
            cpus: 2,
            memory_mib: 512,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        assert_eq!(
            create_args(&spec).unwrap().args,
            vec![
                "create",
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
    fn create_args_rejects_an_empty_name() {
        // The companion empty-image guard is gone: the spec's image is a parsed
        // declaration, so an empty one never gets this far to be checked.
        let bad = MachineSpec {
            name: String::new(),
            image: "img".parse().unwrap(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        assert!(create_args(&bad).is_err());
    }

    #[test]
    fn run_args_rejects_an_empty_name() {
        let base = MachineSpec {
            name: "web".into(),
            image: "alpine".parse().unwrap(),
            cpus: 1,
            memory_mib: 64,
            env: vec![],
            grants: None,
            assurance_campaign: None,
        };
        assert!(matches!(
            run_args(&MachineSpec {
                name: String::new(),
                ..base.clone()
            }),
            Err(MvmError::InvalidSpec { .. })
        ));
        // An empty image has no `MachineSpec` to be checked in: it is refused
        // where the declaration is parsed, not where the argv is assembled.
        assert!(
            "".parse::<mvm_core::rootfs_source::RootfsSource>().is_err(),
            "an empty declaration must not parse"
        );
        drop(base);
    }

    // ── Grants on the argv ────────────────────────────────────────────
    //
    // This is the impl every language SDK goes through, so a grant dropped
    // here is a grant no Python or TypeScript caller can express at all.

    #[test]
    fn a_cpu_and_egress_grant_reach_the_run_argv() {
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .cpus(2)
            .memory_mib(512)
            .cpu_millicores(1500)
            .wall_clock_secs(std::num::NonZeroU32::new(600).unwrap())
            .allow_egress("api.example.com", 443)
            .allow_egress("db.internal", 5432)
            .build();
        let invocation = run_args(&spec).unwrap();
        assert_eq!(
            invocation.args,
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
                "--cpu-limit",
                "1500",
                "--timeout",
                "600",
                "--allow-host",
                "api.example.com:443",
                "--allow-host",
                "db.internal:5432",
                "--up-json",
            ]
        );
        assert!(
            invocation.grants_file.is_none(),
            "every dimension had a flag; no file should have been written"
        );
    }

    #[test]
    fn a_cpu_and_egress_grant_reach_the_create_argv() {
        let spec = MachineSpec::builder("web", "alpine:3.20")
            .expect("declared image parses")
            .cpus(2)
            .memory_mib(512)
            .cpu_millicores(1500)
            .allow_egress("api.example.com", 443)
            .build();
        assert_eq!(
            create_args(&spec).unwrap().args,
            vec![
                "create",
                "web",
                "--image",
                "alpine:3.20",
                "--cpus",
                "2",
                "--memory",
                "512M",
                "--cpu-limit",
                "1500",
                "--allow-host",
                "api.example.com:443",
            ]
        );
    }

    #[test]
    fn a_spec_that_grants_nothing_emits_the_argv_it_always_did() {
        // The pre-grant baseline: no flags appear for a spec with no grants,
        // so the conformance-pinned argv is unchanged.
        let spec = MachineSpec::builder("web", "alpine:3.20")
            .expect("declared image parses")
            .cpus(2)
            .memory_mib(512)
            .build();
        assert!(
            !create_args(&spec)
                .unwrap()
                .args
                .iter()
                .any(|a| a.starts_with("--cpu-limit")
                    || a.starts_with("--allow-host")
                    || a.starts_with("--grants-file"))
        );
    }

    #[test]
    fn the_emitted_flags_parse_back_to_the_grant_that_produced_them() {
        // The encoding contract. What the SDK emits and what the CLI parses are
        // two halves of one agreement, and a mismatch between them is a
        // silently dropped grant wearing a different hat. Asserted against the
        // CLI's own spellings: `--cpu-limit` is millicores, `--timeout` is
        // seconds, and `--allow-host HOST:PORT` is the egress grant.
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .cpu_millicores(1500)
            .wall_clock_secs(std::num::NonZeroU32::new(600).unwrap())
            .allow_egress("api.example.com", 443)
            .build();
        let args = run_args(&spec).unwrap().args;

        let flag_value = |flag: &str| -> Option<String> {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        assert_eq!(flag_value("--cpu-limit").as_deref(), Some("1500"));
        assert_eq!(flag_value("--timeout").as_deref(), Some("600"));

        // Every `--allow-host` value must be the `HOST:PORT` form the CLI
        // parser splits on its last colon, and must round-trip.
        let hosts: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| i > &0 && args[i - 1] == "--allow-host")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(hosts.len(), 1);
        let (host, port) = hosts[0].rsplit_once(':').expect("HOST:PORT");
        assert_eq!(host, "api.example.com");
        assert_eq!(port.parse::<u16>().unwrap(), 443);
    }

    #[test]
    fn a_grant_no_flag_can_say_goes_to_a_grants_file_verbatim() {
        // Fuel is an instruction count and `--cpu-limit` is millicores; there
        // is no conversion, so flattening one into the other would be a
        // different grant. The file carries it unchanged.
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .cpu_fuel(100_000)
            .allow_egress("api.example.com", 443)
            .build();
        let invocation = run_args(&spec).unwrap();
        let file = invocation
            .grants_file
            .as_ref()
            .expect("an inexpressible dimension must produce a file");

        // One encoding, not a mix: no per-dimension flags beside the file.
        assert!(!invocation.args.iter().any(|a| a == "--cpu-limit"));
        assert!(!invocation.args.iter().any(|a| a == "--allow-host"));
        let idx = invocation
            .args
            .iter()
            .position(|a| a == "--grants-file")
            .expect("--grants-file emitted");
        assert_eq!(
            &invocation.args[idx + 1],
            &file.path().display().to_string()
        );

        // And what it holds is exactly the grant, parseable by the same
        // `deny_unknown_fields` type the CLI reads.
        let written: mvm_contract::grants::Grants =
            serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
        assert_eq!(written, spec.grants.unwrap());
    }

    #[test]
    fn an_unbounded_wall_clock_is_never_encoded_as_an_absent_timeout() {
        // Omitting `--timeout` means "unspecified", which a host with a
        // wall-clock ceiling admits; an explicit `Unbounded` is refused by that
        // same ceiling. Dropping it would turn a refusal into a boot.
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .grants(mvm_contract::grants::Grants {
                wall_clock: Some(mvm_contract::grants::WallClockGrant::Unbounded),
                ..Default::default()
            })
            .build();
        let invocation = run_args(&spec).unwrap();
        assert!(invocation.grants_file.is_some());
        assert!(invocation.args.iter().any(|a| a == "--grants-file"));
    }

    #[test]
    fn an_explicitly_empty_allow_list_is_not_encoded_as_no_grant_at_all() {
        // Both deny every destination, so nothing opens either way — but only
        // one of them is what the caller declared, and the plan records which.
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .grants(mvm_contract::grants::Grants {
                egress: Some(mvm_contract::grants::EgressGrant { allow: vec![] }),
                ..Default::default()
            })
            .build();
        let invocation = run_args(&spec).unwrap();
        assert!(
            invocation.grants_file.is_some(),
            "an empty allow-list must survive as an empty allow-list"
        );
    }

    #[test]
    fn a_host_carrying_a_colon_is_not_emitted_as_an_allow_host_flag() {
        // `--allow-host` splits on the last colon, so this would come back as a
        // different host and port than it went in as.
        let spec = MachineSpec::builder("web", "alpine:latest")
            .expect("declared image parses")
            .allow_egress("::1", 443)
            .build();
        let invocation = run_args(&spec).unwrap();
        assert!(invocation.grants_file.is_some());
        assert!(!invocation.args.iter().any(|a| a == "--allow-host"));
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
                image: "alpine:latest".parse().unwrap(),
                cpus: 1,
                memory_mib: 128,
                env: vec![],
                grants: None,
                assurance_campaign: None,
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
