//! The guest mailbox as its own host process.
//!
//! A granted launch serves the guest's mailbox port from a separate process,
//! not from the supervisor and not from the confined egress endpoint. That
//! keeps mailbox material out of the egress endpoint, and it keeps the host
//! signing seed out of this process: the launcher derives the keys for this one
//! mailbox ([`derive_launch_keys`]) and hands over only those, as JSON on
//! stdin. Nothing secret travels in argv or the environment.
//!
//! The process lives as long as its launcher or its VM does, the rule the
//! per-VM egress endpoint's keeper applies.
//!
//! Only a Firecracker guest is wired: its vsock mux is a fixed path reached by
//! the `CONNECT` handshake. The other backends bridge a host-dialed port only
//! when the VM spec declares it, and no workload spec declares the mailbox
//! port, so there is no socket to dial and no process is started for them.

use std::io::{Error, ErrorKind, Result, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use mvm_contract::protocol::mailbox::{MAILBOX_PORT, MailboxGrant};
use mvm_core::plan::ExecutionPlan;
use mvm_core::vm_backend::BackendKind;
use mvm_vmm::host::aux_bin::AuxBin;

use crate::mailbox_launch::{DerivedMailboxKeys, ServePaths, derive_launch_keys, serve_derived};
use crate::mailbox_service::MailboxLimits;
use crate::vm_lifetime::{endpoint_needed, launcher_is_alive};

/// The helper binary this module spawns.
pub const MAILBOX_BIN: &str = "mvm-mailbox";
/// Path-override variable for the helper binary.
pub const MAILBOX_BIN_ENV: &str = "MVM_MAILBOX_PATH";
/// Where the process's pid is recorded, beside the VM.
pub const MAILBOX_PID_FILE: &str = "mailbox.pid";
const MAILBOX_SOCKET: &str = "mailbox.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const LIMITS: MailboxLimits = MailboxLimits {
    max_depth: 64,
    max_frame_bytes: 64 * 1024,
};

/// What the process reads on stdin. `deny_unknown_fields`, so a field a newer
/// launcher adds fails closed here.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxProcessConfig {
    pub grant: MailboxGrant,
    pub keys: DerivedMailboxKeys,
    pub socket: PathBuf,
    pub guest_port: PathBuf,
    pub firecracker_mux: PathBuf,
    /// The VM whose lifetime bounds this process.
    pub vm_state_dir: PathBuf,
}

/// Parse the stdin config.
pub fn parse(raw: &[u8]) -> serde_json::Result<MailboxProcessConfig> {
    serde_json::from_slice(raw)
}

/// Serve until neither the launcher nor the VM is left; the exit code.
pub fn serve(config: MailboxProcessConfig) -> i32 {
    // SAFETY: `getppid` is async-signal-safe and infallible.
    let launcher = unsafe { libc::getppid() };
    let MailboxProcessConfig {
        grant,
        keys,
        socket,
        guest_port,
        firecracker_mux,
        vm_state_dir,
    } = config;
    let _serving = serve_derived(
        grant,
        keys,
        ServePaths {
            socket,
            guest_port,
            firecracker_mux,
        },
        LIMITS,
    );
    while endpoint_needed(launcher_is_alive(launcher), vm_is_alive(&vm_state_dir)) {
        std::thread::sleep(POLL_INTERVAL);
    }
    0
}

fn vm_is_alive(state_dir: &Path) -> bool {
    mvm_vmm::host::process_liveness::state_dir_has_live_process(state_dir)
}

/// Whether a launch on `backend` can reach the guest's mailbox port.
pub fn backend_is_wired(backend: BackendKind) -> bool {
    backend == BackendKind::Firecracker
}

/// The process config for `grant` on the VM at `state_dir`, with keys derived
/// from the host key directory `keys_dir`.
pub fn build_config(
    keys_dir: &Path,
    grant: &MailboxGrant,
    state_dir: &Path,
) -> Result<MailboxProcessConfig> {
    Ok(MailboxProcessConfig {
        grant: *grant,
        keys: derive_launch_keys(keys_dir, grant)?,
        socket: mvm_core::config::vm_socket_dir_at(state_dir).join(MAILBOX_SOCKET),
        guest_port: mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, MAILBOX_PORT),
        firecracker_mux: PathBuf::from(mvm_agentd::vsock::vsock_uds_path(
            &state_dir.to_string_lossy(),
        )),
        vm_state_dir: state_dir.to_path_buf(),
    })
}

/// The command that starts the process: no arguments, a scrubbed environment,
/// its own process group, config over a pipe.
fn command(bin: &Path) -> Command {
    let mut cmd = mvm_core::env_hygiene::helper_command(bin);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    cmd
}

/// Start the mailbox process for a launched VM when `plan` grants a mailbox
/// and `backend` is wired; its pid, or `None` when nothing was started.
pub fn spawn_for_launch(
    plan: &ExecutionPlan,
    backend: BackendKind,
    vm_name: &str,
) -> Result<Option<u32>> {
    let Some(grant) = &plan.mailbox else {
        return Ok(None);
    };
    if !backend_is_wired(backend) {
        tracing::warn!(
            vm = vm_name,
            ?backend,
            "the plan grants a mailbox but this backend does not reach the guest's mailbox port; none is served"
        );
        return Ok(None);
    }
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let config = build_config(&mvm_core::config::mvm_keys_dir(), grant, &state_dir)?;
    let bin = mvm_vmm::host::broker_services_spawn::resolve_subprocess_bin_to_spawn(&AuxBin::new(
        MAILBOX_BIN,
        MAILBOX_BIN_ENV,
        "mvm-hostd",
    ))
    .map_err(|e| Error::new(ErrorKind::NotFound, format!("{e:#}")))?;
    let mut child = command(&bin).spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or_else(|| Error::other("mvm-mailbox stdin was not piped"))
        .and_then(|mut stdin| stdin.write_all(&serde_json::to_vec(&config)?));
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    std::fs::write(state_dir.join(MAILBOX_PID_FILE), child.id().to_string())?;
    Ok(Some(child.id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};

    fn keys_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        dir
    }

    fn grant(dir: &Path) -> MailboxGrant {
        let mailbox = MailboxId::from_bytes([4; 32]);
        MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(dir, &mailbox)
                .unwrap()
                .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
        }
    }

    #[test]
    fn an_ungranted_plan_spawns_nothing() {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(plan.mailbox.is_none());
        let started = spawn_for_launch(&plan, BackendKind::Firecracker, "no-such-vm").unwrap();
        assert_eq!(started, None);
    }

    #[test]
    fn only_firecracker_is_wired() {
        assert!(backend_is_wired(BackendKind::Firecracker));
        assert!(
            ![BackendKind::Hvf, BackendKind::Libkrun, BackendKind::Qemu]
                .iter()
                .any(|b| backend_is_wired(*b))
        );
    }

    #[test]
    fn a_granted_plan_on_an_unwired_backend_spawns_nothing() {
        let dir = keys_dir();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant(dir.path()));
        assert_eq!(
            spawn_for_launch(&plan, BackendKind::Hvf, "no-such-vm").unwrap(),
            None
        );
    }

    #[test]
    fn the_config_refuses_unknown_fields() {
        let dir = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let config = build_config(dir.path(), &grant(dir.path()), state.path()).unwrap();
        let mut value = serde_json::to_value(&config).unwrap();
        assert!(parse(value.to_string().as_bytes()).is_ok());
        value["seed"] = serde_json::json!("00");
        assert!(parse(value.to_string().as_bytes()).is_err());
    }

    #[test]
    fn the_config_carries_no_seed_and_the_command_carries_no_argv_or_env_secret() {
        let dir = keys_dir();
        let seed = std::fs::read(dir.path().join("host-signer.ed25519")).unwrap();
        let state = tempfile::tempdir().unwrap();
        let config = build_config(dir.path(), &grant(dir.path()), state.path()).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains(&hex::encode(&seed)));
        assert!(
            !json.contains(
                serde_json::to_string(&seed)
                    .unwrap()
                    .trim_matches(['[', ']'])
            ),
            "seed bytes in the config"
        );
        let cmd = command(Path::new("/bin/true"));
        assert_eq!(cmd.get_args().count(), 0);
        for (_, value) in cmd.get_envs() {
            let value = value
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default();
            assert!(!value.contains(&hex::encode(&seed)));
        }
    }
}
