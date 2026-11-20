//! Building and dispatching the guest command: the wrapper script, the
//! healthcheck IR, transient naming and console decisions, snapshot
//! eligibility, and the run/capture entry points over the launch orchestrator.
//!
//! Split out of `exec.rs`: these functions are the request-shaping half of a
//! transient run, independent of the launch-resolution machinery.

use anyhow::{Context as _, Result};
use mvm_client::entrypoint::SessionAdmit;
use mvm_core::vm_backend::SnapshotCapability;
use mvm_vmm::host::shell::shell_quote;

use super::either::Either;
use super::{ExecRequest, ExecTarget, ImageSource, run_inner};
use crate::commands::DirShareSpec;

/// Build the IR healthcheck from the CLI flags. A shell command string becomes
/// an exec argv the guest agent runs (`/bin/sh -lc <cmd>`). `None` command ⇒ no
/// healthcheck (a plain task).
pub fn build_healthcheck(
    cmd: Option<&str>,
    interval_secs: u32,
    timeout_secs: u32,
    retries: u32,
    start_period_secs: u32,
) -> Option<mvm_contract::ir::HealthCheck> {
    let cmd = cmd?;
    Some(mvm_contract::ir::HealthCheck {
        command: vec!["/bin/sh".into(), "-lc".into(), cmd.to_string()],
        interval_secs,
        timeout_secs,
        retries,
        start_period_secs,
    })
}

pub(crate) fn quote_argv_for_exec(argv: &[String]) -> String {
    let quoted: Vec<String> = argv.iter().map(|a| shell_quote(a)).collect();
    format!("exec {}", quoted.join(" "))
}

/// Build the wrapper script that runs inside the guest:
///   1. exports launch-plan-derived env vars (when target is LaunchPlan)
///   2. exports CLI `--env` vars (CLI overrides launch-plan)
///   3. cds into `working_dir` (when target is LaunchPlan and it's set)
///   4. execs the resolved command
///
/// Host-directory snapshots are attached and mounted by the guest activation
/// path. The command wrapper must not contain a second mount implementation.
///
/// Env precedence (lowest → highest): launch-plan app.env → launch-plan
/// entrypoint.env → CLI `--env`. The first two are merged in
/// `parse_launch_plan`; CLI wins by being emitted last.
pub fn build_guest_wrapper(req: &ExecRequest) -> String {
    let mut script = String::from("set -e\n");
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target {
        for (k, v) in &entrypoint.env {
            script.push_str(&format!("export {k}={}\n", shell_quote(v)));
        }
    }
    for (k, v) in &req.env {
        script.push_str(&format!("export {k}={}\n", shell_quote(v)));
    }
    // After the caller's exports, so the network utility wins over the image's
    // ping: a NIC-less guest's own copy fails at `socket()`.
    script.push_str(&format!(
        "export PATH={}:\"$PATH\"\n",
        shell_quote(mvm_core::guest_netd::NETWORK_UTILITIES_BIN),
    ));
    if let ExecTarget::LaunchPlan { entrypoint } = &req.target
        && let Some(wd) = &entrypoint.working_dir
    {
        script.push_str(&format!("cd {}\n", shell_quote(wd)));
    }
    script.push_str(&req.target_command());
    script.push('\n');
    script
}

/// Generate a transient VM name for an exec invocation.
pub fn transient_vm_name() -> String {
    mvm_core::naming::generate_machine_name()
}

/// Whether a transient run should pre-open interactive console data sockets.
///
/// `true` only when the caller requested a PTY (`pty`) AND the image is not
/// sealed (`image_sealed == false`). A verity-backed OCI/dev image may still be
/// interactive, so sealing/accessibility must follow the image sidecar rather
/// than the presence of verity sidecars alone.
pub fn transient_run_dev_console(pty: bool, image_sealed: bool) -> bool {
    pty && !image_sealed
}

/// Remove the transient VM's host state dir (`~/.mvm/vms/<name>`) once the VM
/// is stopped. Host-side
/// `std::fs` — never `run_in_vm`, which targets a path *inside* the guest and
/// (on macOS) would wake a builder VM to `rm` a path that isn't there, leaking
/// the real host dir. Runs for every transient run: the backend writes
/// `hvf.pid` / `console.log` here regardless, so a plain OCI launch created
/// the dir and must clean it up too. Best-effort — teardown must
/// never fail on a cleanup error.
pub(crate) fn remove_transient_state_dir(staging_dir: &str) {
    match std::fs::remove_dir_all(staging_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::debug!(error = %e, dir = staging_dir, "transient state dir cleanup failed");
            // Firecracker is launched under sudo, so its console/hypervisor
            // logs, API socket, and vsock UDS are root-owned. A normal
            // `remove_dir_all` cannot delete them; fall back to the same
            // privilege level on Linux. On other platforms the leak is logged
            // and left for the next convergence pass / manual cleanup.
            #[cfg(target_os = "linux")]
            {
                // Argv, not a shell: no shell startup file runs, and the
                // helper seam strips what the child would otherwise inherit.
                match mvm_runtime::shell::run_host("sudo", &["rm", "-rf", "--", staging_dir]) {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => {
                        tracing::debug!(
                            status = ?output.status,
                            stderr = %String::from_utf8_lossy(&output.stderr),
                            dir = staging_dir,
                            "privileged transient state dir cleanup failed"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, dir = staging_dir, "privileged transient state dir cleanup command failed");
                    }
                }
            }
        }
    }
}

/// Decide whether snapshot restore is safe for this request.
///
/// Only enabled for the trivial case: a registered template (so the image
/// has a snapshot at all), no live directory shares (so the device layout
/// matches the snapshot's recorded layout), and a backend that advertises
/// snapshot support.
pub fn snapshot_eligible(
    image: &ImageSource,
    dir_shares: &[DirShareSpec],
    snap_present: bool,
    snapshot_capability: SnapshotCapability,
) -> bool {
    if snapshot_capability == SnapshotCapability::Unsupported
        || !snap_present
        || !dir_shares.is_empty()
    {
        return false;
    }
    matches!(image, ImageSource::Template(_))
}

/// Captured stdout/stderr/exit-code from a one-shot exec.
///
/// `run_captured` returns this instead of streaming guest output to the
/// CLI's terminal, so a caller can inspect the run's output as data.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub phase_timing: Option<crate::commands::vm::phase_timing::RunPhaseTimingReport>,
}

/// Run the request and capture stdout/stderr instead of streaming.
///
/// Same orchestration as [`run`]: boot a transient microVM, dispatch
/// the command via the guest agent's `Exec` over vsock, tear down.
/// The only difference is what happens with the guest's stdout/stderr
/// — captured into the returned [`ExecOutput`] instead of inherited
/// to the parent process's terminal.
///
/// Used where a caller needs the output as data; the CLI's interactive
/// `mvmctl exec` keeps using [`run`] (streaming) so human ergonomics
/// don't regress. `posture`, when supplied, receives the resolved boot
/// posture so the command layer can chain-audit it (`plan.boot_posture`).
pub fn run_captured(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: Option<&PostureSink>,
) -> Result<ExecOutput> {
    run_captured_started(
        req,
        admit.map(super::LaunchAdmit::Session),
        None,
        posture,
        std::time::Instant::now(),
    )
}

pub(crate) fn run_captured_started(
    req: ExecRequest,
    admit: Option<super::LaunchAdmit<'_>>,
    audit_owner: Option<&std::cell::RefCell<Option<mvm_client::admission::CliAdmission>>>,
    posture: Option<&PostureSink>,
    startup_started: std::time::Instant,
) -> Result<ExecOutput> {
    run_inner(
        req,
        /* capture = */ true,
        admit,
        audit_owner,
        posture,
        startup_started,
    )
    .and_then(|either| {
        either
            .right()
            .context("capture mode did not return captured output")
    })
}

/// Run the request: boot, run, tear down.
///
/// Returns the guest command's exit code. On orchestrator failure (boot,
/// agent unreachable, vsock error), returns an error; the VM is torn down
/// best-effort before returning. `posture`, when supplied, receives the
/// resolved boot posture so the command layer can chain-audit it
/// (`plan.boot_posture`).
pub fn run(
    req: ExecRequest,
    admit: Option<&SessionAdmit<'_>>,
    posture: Option<&PostureSink>,
) -> Result<i32> {
    run_started(
        req,
        admit.map(super::LaunchAdmit::Session),
        None,
        posture,
        std::time::Instant::now(),
    )
}

pub(crate) fn run_started(
    req: ExecRequest,
    admit: Option<super::LaunchAdmit<'_>>,
    audit_owner: Option<&std::cell::RefCell<Option<mvm_client::admission::CliAdmission>>>,
    posture: Option<&PostureSink>,
    startup_started: std::time::Instant,
) -> Result<i32> {
    run_inner(
        req,
        /* capture = */ false,
        admit,
        audit_owner,
        posture,
        startup_started,
    )
    .and_then(|either| {
        either
            .left()
            .context("streaming mode did not return an exit code")
    })
}

pub(crate) fn reported_exit_code(
    outcome: &Result<(Either<i32, ExecOutput>, Option<std::time::Instant>)>,
) -> Option<i32> {
    match outcome {
        Ok((Either::Left(code), _)) => Some(*code),
        Ok((Either::Right(output), _)) => Some(output.exit_code),
        Err(_) => None,
    }
}

/// Side channel by which [`run_inner`] reports the resolved boot posture (which
/// rootfs strategy the run-path tier gate selected) back to the command layer,
/// which records it on the chain-signed admission log (`plan.boot_posture`).
/// The command layer reads it after the run returns. `None` means the caller
/// does not audit posture (session boots, which never reach virtiofs).
pub type PostureSink = std::cell::Cell<mvm_client::admission::BootPosture>;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::exec::load_launch_plan;

    #[test]
    fn transient_audit_uses_only_a_reported_exit_code() {
        let direct = Ok((Either::Left(7), None));
        assert_eq!(reported_exit_code(&direct), Some(7));

        let captured = Ok((
            Either::Right(ExecOutput {
                exit_code: 9,
                stdout: String::new(),
                stderr: String::new(),
                phase_timing: None,
            }),
            None,
        ));
        assert_eq!(reported_exit_code(&captured), Some(9));

        let failed: Result<(Either<i32, ExecOutput>, Option<std::time::Instant>)> =
            Err(anyhow::anyhow!("dispatch failed"));
        assert_eq!(reported_exit_code(&failed), None);
    }

    #[test]
    fn build_healthcheck_wraps_shell_command() {
        let hc = build_healthcheck(Some("curl -fsS localhost/health"), 10, 5, 3, 0)
            .expect("Some when a command is given");
        assert_eq!(
            hc.command,
            vec!["/bin/sh", "-lc", "curl -fsS localhost/health"]
        );
        assert_eq!(hc.interval_secs, 10);
        assert_eq!(build_healthcheck(None, 30, 5, 3, 0), None);
    }

    #[test]
    fn target_command_inline_quotes_each_arg() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["uname".into(), "-a".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        assert_eq!(req.target_command(), "exec 'uname' '-a'");
    }

    #[test]
    fn build_guest_wrapper_no_extras() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("exec 'true'"));
        assert!(!script.contains("mount"));
        // The network utility PATH is always emitted; no caller export joins it.
        assert_eq!(script.matches("export ").count(), 1);
        assert!(script.contains(mvm_core::guest_netd::NETWORK_UTILITIES_BIN));
    }

    /// The image's own `ping` fails at `socket()` in a NIC-less guest, so the
    /// network utility has to win even when the caller sets `PATH` itself.
    #[test]
    fn build_guest_wrapper_network_path_outranks_a_caller_supplied_path() {
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("PATH".into(), "/usr/bin".into())],
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        let caller = script.find("export PATH='/usr/bin'").expect("caller PATH");
        let utility = script
            .find(mvm_core::guest_netd::NETWORK_UTILITIES_BIN)
            .expect("network utility PATH");
        assert!(
            utility > caller,
            "network utility PATH must come last to win; got:\n{script}"
        );
        // Composed against $PATH rather than replacing it, so the caller's
        // entry survives behind ours.
        assert!(script.contains(":\"$PATH\""), "got:\n{script}");
    }

    #[test]
    fn transient_vm_name_format() {
        let n = transient_vm_name();
        mvm_core::naming::validate_vm_name(&n)
            .unwrap_or_else(|e| panic!("transient name {n:?} invalid: {e}"));
        assert_eq!(n.split('-').count(), 3);
        assert!(!n.contains(' '));
        assert!(!n.contains('/'));
    }

    // -- launch.json parser --

    #[test]
    fn build_guest_wrapper_launch_plan_emits_cd_and_env() {
        let entrypoint = load_launch_plan(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/launch-plan/workload.json"),
        )
        .unwrap();
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            // Live shares are attached by the guest activation path.
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: vec![("CLI_OVER".to_string(), "wins".to_string())],
            target: ExecTarget::LaunchPlan { entrypoint },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        // Env from entrypoint exported.
        assert!(script.contains("export PORT='8080'"));
        assert!(script.contains("export LOG='info'"));
        // CLI env exported AFTER entrypoint env, so it wins on conflict.
        let cli_pos = script
            .find("export CLI_OVER='wins'")
            .expect("CLI env exported");
        let port_pos = script.find("export PORT='8080'").expect("port exported");
        assert!(
            cli_pos > port_pos,
            "CLI env must appear after launch-plan env"
        );
        // cd into working_dir before exec.
        assert!(script.contains("cd '/app'"));
        let cd_pos = script.find("cd '/app'").unwrap();
        let exec_pos = script.find("exec 'python' 'main.py'").unwrap();
        assert!(cd_pos < exec_pos, "cd must precede the final exec");
    }

    #[test]
    fn build_guest_wrapper_inline_target_unchanged() {
        // Sanity: inline target wrapper still does not emit cd or extra env blocks.
        let req = ExecRequest {
            name: None,
            warm_pool_size: 0,
            standby_refill: None,
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            dir_shares: Vec::new(),
            disk_volumes: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: Some(30),
            pty: false,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            assets: Vec::new(),
            stdin: Vec::new(),
            healthcheck: None,
            hypervisor: None,
            gpu: false,
            gpu_device: None,
            sdk_host_services: Vec::new(),
            declared_libc: mvm_contract::guest_libc::GuestLibc::Unknown,
        };
        let script = build_guest_wrapper(&req);
        assert!(!script.contains("cd "));
        assert_eq!(script.matches("export ").count(), 1);
        assert!(script.contains(mvm_core::guest_netd::NETWORK_UTILITIES_BIN));
        assert!(script.contains("exec 'true'"));
    }

    fn template(name: &str) -> ImageSource {
        ImageSource::Template(name.into())
    }

    #[test]
    fn snapshot_eligible_true_for_template_no_extras_with_snapshot() {
        assert!(snapshot_eligible(
            &template("t"),
            &[],
            true,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn snapshot_eligible_false_when_backend_lacks_support() {
        assert!(!snapshot_eligible(
            &template("t"),
            &[],
            true,
            SnapshotCapability::Unsupported
        ));
    }

    #[test]
    fn snapshot_eligible_false_when_no_snapshot_present() {
        assert!(!snapshot_eligible(
            &template("t"),
            &[],
            false,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn snapshot_eligible_false_with_directory_shares() {
        // A live share changes the device layout; snapshot would fail.
        assert!(!snapshot_eligible(
            &template("t"),
            &[DirShareSpec {
                host_dir: "/h".into(),
                guest_mount: "/g".into(),
                read_only: true,
                include: Vec::new(),
                exclude: Vec::new(),
            }],
            true,
            SnapshotCapability::LiveMemory
        ));
    }

    #[test]
    fn interactive_transient_run_sets_dev_console_when_not_sealed() {
        // PTY-mode run against a non-sealed image must pre-open console sockets
        // so the hvf backend can host-dial the guest's data port.
        assert!(transient_run_dev_console(true, false));
    }

    #[test]
    fn non_interactive_transient_run_leaves_dev_console_unset() {
        // A non-PTY run never needs the interactive console data sockets.
        assert!(!transient_run_dev_console(false, false));
    }

    #[test]
    fn interactive_sealed_run_leaves_dev_console_unset() {
        // A sealed image has no interactive agent; pre-opening sockets is
        // wasteful. enforce_accessible_gate refuses the attach separately.
        assert!(!transient_run_dev_console(true, true));
    }

    #[test]
    fn non_interactive_sealed_run_leaves_dev_console_unset() {
        assert!(!transient_run_dev_console(false, true));
    }

    #[test]
    fn interactive_verity_backed_oci_run_still_arms_dev_console() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"x").unwrap();
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(dir.path().join("rootfs.roothash"), b"roothash").unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run("oci:test", false, true)
            .write_to_dir(dir.path())
            .unwrap();

        let image_sealed = crate::commands::vm::image_is_sealed(&rootfs);
        assert!(
            transient_run_dev_console(true, image_sealed),
            "verity-backed accessible OCI images must keep the interactive console armed"
        );
    }

    #[test]
    fn remove_transient_state_dir_removes_the_host_dir() {
        // Every transient run creates its state dir
        // when the backend writes hvf.pid / console.log there, so teardown must
        // remove it host-side — not via run_in_vm, which targets the guest.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("vms").join("throwaway-vm");
        std::fs::create_dir_all(&dir).expect("create state dir");
        std::fs::write(dir.join("hvf.pid"), b"1234").expect("write pid file");
        assert!(dir.exists());

        remove_transient_state_dir(&dir.to_string_lossy());

        assert!(!dir.exists(), "the host state dir must be removed");
    }

    #[test]
    fn remove_transient_state_dir_is_a_noop_on_a_missing_dir() {
        // Best-effort: an already-gone dir (or a boot that never created one) is
        // a clean no-op, never a panic.
        remove_transient_state_dir("/nonexistent/mvm/vms/never-created");
    }
}
