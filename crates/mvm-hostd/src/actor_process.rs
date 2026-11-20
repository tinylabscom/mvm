//! Private bootstrap transport for the independently owned actor controller.

use std::io::{self, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_core::net::actor_session::ActorDeadlineStream;
use mvm_core::net::session::{read_json_frame, write_json_frame};
use mvm_vmm::host::aux_bin::{self, AuxBin};
use serde::{Deserialize, Serialize};

/// Bounds all root plans and exact templates together before deserialization.
pub const MAX_BOOTSTRAP_BYTES: usize = 4 * 1024 * 1024;
const MAX_READY_BYTES: usize = 4096;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// Host-local acknowledgement of actual parent admission and controller activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorLaunch {
    pub machine: String,
    pub plan_id: String,
    pub controller_pid: u32,
}

/// Launch a separately owned controller through the verified host-helper resolver.
///
/// This path is explicit: ordinary workload launches never call it or allocate
/// actor state. Unsupported native ownership refuses before spawning anything.
pub fn launch(bootstrap: &crate::actor_bootstrap::ActorBootstrap) -> Result<ActorLaunch> {
    let (launch, mut child) = launch_controller(bootstrap, Stdio::null())?;
    // A library caller may remain alive after launch. Reap its child on exit;
    // dropping the CLI itself does not terminate the independent controller.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(launch)
}

/// Live validation retains the actual controller child instead of polling a PID.
///
/// Uses the identical manifest preflight, executable verification and bootstrap
/// handshake as ordinary launch. The caller must wait and reap this child without
/// killing it: after submission, the controller owns cleanup of possible effects,
/// including when startup or terminal cleanup remains unknown.
/// Controller diagnostics inherit stderr for this explicit live-validation path.
#[cfg(feature = "hvf-live-validation")]
pub fn launch_retained(
    bootstrap: &crate::actor_bootstrap::ActorBootstrap,
) -> Result<(ActorLaunch, Child)> {
    launch_controller(bootstrap, Stdio::inherit())
}

fn launch_controller(
    bootstrap: &crate::actor_bootstrap::ActorBootstrap,
    stderr: Stdio,
) -> Result<(ActorLaunch, Child)> {
    bootstrap.validate()?;
    crate::actor_bootstrap::require_host_budget(
        &mvm_core::user_config::load_strict(None)?,
        bootstrap.host_budget,
    )?;
    mvm_runtime::actor_teardown::supports_actor_backend(
        &mvm_runtime::AnyBackend::from_hypervisor("hvf"),
    )?;
    let binary = prepare_helpers(aux_bin::resolve_verified)?;
    spawn(&binary, bootstrap, stderr)
}

pub(crate) const HOLDER_SPEC: AuxBin<'static> =
    AuxBin::new("mvm-actor-holder", "MVM_ACTOR_HOLDER_PATH", "mvm-hostd");

fn prepare_helpers(
    mut resolve: impl FnMut(&AuxBin<'_>) -> Result<std::path::PathBuf>,
) -> Result<std::path::PathBuf> {
    let spec = AuxBin::new(
        "mvm-actor-controller",
        "MVM_ACTOR_CONTROLLER_PATH",
        "mvm-hostd",
    )
    .with_companions(&[
        "mvm-actor-holder",
        "mvm-mailbox",
        "mvm-broker",
        "mvm-network-endpoint",
        "mvm-audit-signer",
        "mvm-host-signer",
        "mvm-signer-helper",
    ]);
    let binary = resolve(&spec)?;
    // Building companions does not probe them. Prepare the companions whose
    // launch contract requires a probe before the private bootstrap deadline.
    // Mailbox, broker and audit signer instead consume stdin configuration.
    for spec in [
        HOLDER_SPEC,
        AuxBin::new(
            "mvm-network-endpoint",
            "MVM_SUBSTITUTION_ENDPOINT_PATH",
            "mvm-hostd",
        ),
    ] {
        resolve(&spec)?;
    }
    // Sign last: a companion's stale-contract recovery may relink package bins.
    resolve(
        &AuxBin::new("mvm-hvf-supervisor", "MVM_HVF_SUPERVISOR_PATH", "mvm-hostd")
            .signed_with(mvm_vmm::host::codesign::RequiredEntitlement::Hypervisor),
    )?;
    Ok(binary)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BootstrapReply {
    Started { launch: ActorLaunch },
    Refused,
    Unknown,
}

/// Retains the child until commit, or waits for owned cleanup after submission.
struct PendingController {
    child: Option<Child>,
    submitted: bool,
}

impl Drop for PendingController {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if self.submitted {
                // Closing the uncommitted bootstrap requests owned cleanup.
                // This controller may already own native and helper effects.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            } else {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn spawn(
    binary: &Path,
    bootstrap: &crate::actor_bootstrap::ActorBootstrap,
    stderr: Stdio,
) -> Result<(ActorLaunch, Child)> {
    // Check the complete serialized size before creating any host process.
    ensure!(
        serde_json::to_vec(bootstrap)?.len() <= MAX_BOOTSTRAP_BYTES,
        "actor bootstrap exceeds bound"
    );
    let (client, child_socket) = UnixStream::pair()?;
    let mut client = ActorDeadlineStream::new(client, Instant::now() + BOOTSTRAP_TIMEOUT)?;
    let stdin: OwnedFd = child_socket.into();
    let mut command = mvm_core::env_hygiene::helper_command(binary);
    command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::null())
        .stderr(stderr);
    // SAFETY: setsid is async-signal-safe and captures no state or allocator.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut pending = PendingController {
        child: Some(spawn_command(command)?),
        submitted: false,
    };
    // A partial write is also uncertain submission. The receiver owns proving
    // that its bounded bootstrap did not reach dispatch, never this launcher.
    pending.submitted = true;
    write_json_frame(&mut client, bootstrap, MAX_BOOTSTRAP_BYTES)?;
    let reply: BootstrapReply = read_json_frame(&mut client, MAX_READY_BYTES)?;
    let launch = match reply {
        BootstrapReply::Started { launch } => launch,
        BootstrapReply::Refused => anyhow::bail!("actor controller refused bootstrap"),
        BootstrapReply::Unknown => anyhow::bail!(
            "actor controller startup outcome is unknown; retained state must be reconciled"
        ),
    };
    let child = pending
        .child
        .as_ref()
        .context("missing actor controller owner")?;
    ensure!(
        launch.controller_pid == child.id(),
        "actor controller identity mismatch"
    );
    ensure!(
        launch.machine == bootstrap.parent.workload.0
            && launch.plan_id == bootstrap.parent.plan_id.0,
        "actor controller returned another parent admission"
    );
    client.write_all(&[1])?;
    let child = pending
        .child
        .take()
        .context("missing actor controller owner")?;
    Ok((launch, child))
}

fn spawn_command(mut command: std::process::Command) -> Result<Child> {
    // Command owns the supplied stdin socket even after spawn. Do not retain
    // that peer in the launcher: it would hide controller exit from the reader.
    command.spawn().context("spawning actor controller")
}

pub(crate) fn receive<T: serde::de::DeserializeOwned>(stream: &mut impl io::Read) -> Result<T> {
    Ok(read_json_frame(stream, MAX_BOOTSTRAP_BYTES)?)
}

pub(crate) fn reply(stream: &mut impl io::Write, reply: &BootstrapReply) -> Result<()> {
    Ok(write_json_frame(stream, reply, MAX_READY_BYTES)?)
}

pub(crate) fn await_commit(stream: &mut impl io::Read) -> Result<()> {
    let mut commit = [0u8; 1];
    stream.read_exact(&mut commit)?;
    ensure!(commit == [1], "actor bootstrap was not committed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_probes_each_native_launch_spec_before_bootstrap() {
        let mut prepared = Vec::new();
        let binary = prepare_helpers(|spec| {
            prepared.push((spec.bin.to_owned(), spec.env_var.to_owned()));
            Ok(std::path::PathBuf::from(spec.bin))
        })
        .unwrap();
        assert_eq!(binary, Path::new("mvm-actor-controller"));
        assert_eq!(
            prepared
                .iter()
                .map(|(bin, _)| bin.as_str())
                .collect::<Vec<_>>(),
            [
                "mvm-actor-controller",
                "mvm-actor-holder",
                "mvm-network-endpoint",
                "mvm-hvf-supervisor",
            ]
        );
        assert_eq!(prepared[1].1, HOLDER_SPEC.env_var);
        assert_eq!(prepared[2].1, "MVM_SUBSTITUTION_ENDPOINT_PATH");
    }

    #[test]
    fn preparation_failure_stops_before_remaining_helpers_or_bootstrap() {
        let mut count = 0;
        let result = prepare_helpers(|spec| {
            count += 1;
            anyhow::ensure!(spec.bin != HOLDER_SPEC.bin, "holder contract mismatch");
            Ok(std::path::PathBuf::from(spec.bin))
        });
        assert!(result.is_err());
        assert_eq!(count, 2);
    }

    #[test]
    fn exited_controller_closes_private_channel_without_waiting_for_deadline() {
        use std::io::Read as _;
        let (mut client, socket) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut command = std::process::Command::new("/usr/bin/true");
        command.stdin(Stdio::from(OwnedFd::from(socket)));
        let mut child = spawn_command(command).unwrap();
        assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn oversized_bootstrap_refuses_before_body_allocation() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(receive::<serde_json::Value>(&mut receiver).is_err());
    }

    #[test]
    fn readiness_is_one_bounded_frame_not_process_exit() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let launch = ActorLaunch {
            machine: "parent".into(),
            plan_id: "sha256:0123456789abcdef".into(),
            controller_pid: 42,
        };
        reply(
            &mut sender,
            &BootstrapReply::Started {
                launch: launch.clone(),
            },
        )
        .unwrap();
        let decoded: BootstrapReply = read_json_frame(&mut receiver, MAX_READY_BYTES).unwrap();
        assert!(matches!(decoded, BootstrapReply::Started { launch: actual } if actual == launch));
        // sender is still alive: returning ready does not wait for controller EOF.
        assert!(sender.peer_addr().is_ok());
    }

    #[test]
    fn readiness_rejects_unknown_authority_fields() {
        assert!(serde_json::from_str::<BootstrapReply>(
            r#"{"status":"started","launch":{"machine":"p","plan_id":"x","controller_pid":1},"admitted":true}"#
        ).is_err());
    }

    #[test]
    fn started_without_commit_is_cancellation_not_dispatch_permission() {
        let (mut client, mut controller) = UnixStream::pair().unwrap();
        reply(
            &mut controller,
            &BootstrapReply::Started {
                launch: ActorLaunch {
                    machine: "parent".into(),
                    plan_id: "plan".into(),
                    controller_pid: 1,
                },
            },
        )
        .unwrap();
        let _: BootstrapReply = read_json_frame(&mut client, MAX_READY_BYTES).unwrap();
        drop(client);
        assert!(await_commit(&mut controller).is_err());
        assert!(await_commit(&mut &b"\0"[..]).is_err());
        await_commit(&mut &b"\x01"[..]).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn uncertain_submission_retains_controller_until_owned_cleanup_exits() {
        let (writer, reader) = UnixStream::pair().unwrap();
        let child = std::process::Command::new("/bin/cat")
            .stdin(Stdio::from(OwnedFd::from(reader)))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let event =
            mvm_vmm::host::process_exit::ProcessExitObserver::arm(child.id().try_into().unwrap())
                .unwrap();
        drop(PendingController {
            child: Some(child),
            submitted: true,
        });
        assert_eq!(
            event
                .wait_event(Instant::now() + Duration::from_millis(20))
                .unwrap(),
            mvm_vmm::host::process_exit::ProcessExitWait::TimedOut,
            "partial write, timeout and Unknown must not kill a submitted controller"
        );
        drop(writer);
        assert_eq!(
            event
                .wait_event(Instant::now() + Duration::from_secs(1))
                .unwrap(),
            mvm_vmm::host::process_exit::ProcessExitWait::Exited
        );
    }

    #[test]
    fn bootstrap_socket_deadline_refuses_an_incomplete_frame() {
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(&4u32.to_be_bytes()).unwrap();
        let mut receiver =
            ActorDeadlineStream::new(receiver, Instant::now() + Duration::from_millis(20)).unwrap();
        assert!(receive::<serde_json::Value>(&mut receiver).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn failed_bootstrap_reaps_the_original_process() {
        let (_writer, reader) = UnixStream::pair().unwrap();
        let child = std::process::Command::new("/bin/cat")
            .stdin(Stdio::from(OwnedFd::from(reader)))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let event =
            mvm_vmm::host::process_exit::ProcessExitObserver::arm(child.id().try_into().unwrap())
                .unwrap();
        let pending = PendingController {
            child: Some(child),
            submitted: false,
        };
        drop(pending);
        assert_eq!(
            event
                .wait_event(Instant::now() + Duration::from_secs(1))
                .unwrap(),
            mvm_vmm::host::process_exit::ProcessExitWait::Exited
        );
    }
}
