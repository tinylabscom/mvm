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
//! per-VM egress endpoint's keeper applies, and it also stops when the VM's
//! state directory is gone. The stop path reaps it by its pid file with the
//! VM's other helpers.
//!
//! Whether a backend can serve one is the backend's own declaration
//! (`VmCapabilities::guest_mailbox`). A granted plan puts a host-dialed
//! `Mailbox` port in the workload's standing vsock channels; a backend that
//! bridges it to a per-port socket, or reaches the guest through its vsock mux,
//! declares the capability. A grant on one that does not refuses the launch
//! rather than boot a guest that asserts a mailbox nobody serves.

use std::io::{Error, ErrorKind, Result, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use mvm_contract::protocol::mailbox::{MAILBOX_PORT, MailboxGrant};
use mvm_core::plan::ExecutionPlan;
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::aux_bin::AuxBin;

use crate::mailbox_launch::{
    DerivedMailboxKeys, LAUNCH_LIMITS, ServePaths, derive_launch_keys, serve_derived,
};
use crate::vm_lifetime::{endpoint_needed, launcher_is_alive};

/// The helper binary this module spawns.
pub const MAILBOX_BIN: &str = "mvm-mailbox";
/// Path-override variable for the helper binary.
pub const MAILBOX_BIN_ENV: &str = "MVM_MAILBOX_PATH";
/// Where the process's pid is recorded, beside the VM.
pub use mvm_vmm::host::vm_helpers::MAILBOX_PID_FILE;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

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
        LAUNCH_LIMITS,
    );
    while vm_state_dir.exists()
        && endpoint_needed(launcher_is_alive(launcher), vm_is_alive(&vm_state_dir))
    {
        std::thread::sleep(POLL_INTERVAL);
    }
    0
}

fn vm_is_alive(state_dir: &Path) -> bool {
    mvm_vmm::host::process_liveness::state_dir_has_live_process(state_dir)
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
        socket: mvm_core::config::vm_mailbox_socket_at(state_dir),
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

/// Refuse a launch whose plan grants a mailbox on a backend that cannot reach
/// the guest's mailbox port. The guest would be told to serve a port nobody
/// dials, so the launch fails instead.
fn require_wired(plan: &ExecutionPlan, backend: &AnyBackend) -> Result<()> {
    if plan.mailbox.is_some() && !backend.capabilities().guest_mailbox {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "the plan grants a mailbox, which the {:?} backend cannot serve",
                backend.kind()
            ),
        ));
    }
    Ok(())
}

/// The plan `config` boots under, when it grants a mailbox. Read the way the
/// guest's `mvm.mailbox=1` cmdline token reads it, so the two cannot disagree.
fn granted_plan(config: &VmStartConfig) -> Option<ExecutionPlan> {
    mvm_core::plan::plan_from_admitted_json(config.plan_json.as_deref()?)
        .ok()
        .filter(|plan| plan.mailbox.is_some())
}

/// Refuse, before the VM boots, a config whose guest would be told to serve a
/// mailbox this backend cannot.
pub fn require_servable(config: &VmStartConfig, backend: &AnyBackend) -> anyhow::Result<()> {
    match granted_plan(config) {
        Some(plan) => Ok(require_wired(&plan, backend)?),
        None => Ok(()),
    }
}

/// Serve the mailbox `config` grants, now that its VM `id` is up on `backend`.
/// The cmdline token and this process come from the same plan, so a guest
/// asserts a mailbox exactly when one is served. A grant that cannot be served
/// stops the VM and fails the launch.
pub fn serve_started(
    backend: &AnyBackend,
    id: &VmId,
    config: &VmStartConfig,
) -> anyhow::Result<()> {
    serve_started_with(backend, id, config, spawn_for_launch)
}

fn serve_started_with(
    backend: &AnyBackend,
    id: &VmId,
    config: &VmStartConfig,
    spawn: impl FnOnce(&ExecutionPlan, &AnyBackend, &str) -> Result<Option<u32>>,
) -> anyhow::Result<()> {
    let Some(plan) = granted_plan(config) else {
        return Ok(());
    };
    if let Err(error) = spawn(&plan, backend, &id.0) {
        if let Err(stop) = backend.stop(id) {
            tracing::warn!(vm = %id.0, error = %stop, "stopping a VM whose mailbox could not be served failed");
        }
        return Err(
            anyhow::Error::new(error).context("the granted guest mailbox could not be served")
        );
    }
    Ok(())
}

/// Start the mailbox process for a launched VM when `plan` grants a mailbox
/// and `backend` declares the capability; its pid, or `None` when nothing was started.
pub fn spawn_for_launch(
    plan: &ExecutionPlan,
    backend: &AnyBackend,
    vm_name: &str,
) -> Result<Option<u32>> {
    let Some(grant) = &plan.mailbox else {
        return Ok(None);
    };
    require_wired(plan, backend)?;
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
        let started = spawn_for_launch(&plan, &backend_named("firecracker"), "no-such-vm").unwrap();
        assert_eq!(started, None);
    }

    fn backend_named(name: &str) -> AnyBackend {
        AnyBackend::from_hypervisor(name)
    }

    #[test]
    fn a_granted_plan_on_an_unwired_backend_is_refused() {
        let dir = keys_dir();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant(dir.path()));
        let error = spawn_for_launch(&plan, &backend_named("libkrun"), "no-such-vm").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
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

    fn config_for(grant: Option<MailboxGrant>) -> VmStartConfig {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = grant;
        VmStartConfig {
            name: "vm-under-test".into(),
            plan_json: Some(serde_json::to_string(&plan).unwrap()),
            ..Default::default()
        }
    }

    type Spawns = std::cell::RefCell<Vec<String>>;

    fn serve_with(
        config: &VmStartConfig,
        spawns: &Spawns,
        outcome: Result<Option<u32>>,
    ) -> anyhow::Result<()> {
        let backend = AnyBackend::from_hypervisor("firecracker");
        serve_started_with(
            &backend,
            &VmId("vm-under-test".into()),
            config,
            |_, _, name| {
                spawns.borrow_mut().push(name.to_string());
                outcome
            },
        )
    }

    /// The guest's token and the host process come from one plan: a granted
    /// config has both, an ungranted one neither.
    #[test]
    fn the_token_and_the_host_process_come_together() {
        let dir = keys_dir();
        let token = |c: &VmStartConfig| mvm_vmm::host::egress_bridge::mailbox_cmdline_token(c);
        let spawns = Spawns::default();

        let granted = config_for(Some(grant(dir.path())));
        assert!(token(&granted).is_some());
        serve_with(&granted, &spawns, Ok(Some(7))).unwrap();
        assert_eq!(*spawns.borrow(), ["vm-under-test"]);

        let ungranted = config_for(None);
        let none = Spawns::default();
        assert!(token(&ungranted).is_none());
        serve_with(&ungranted, &none, Ok(Some(7))).unwrap();
        assert!(none.borrow().is_empty());
        assert!(VmStartConfig::default().plan_json.is_none());
        serve_with(&VmStartConfig::default(), &none, Ok(None)).unwrap();
        assert!(none.borrow().is_empty());
    }

    /// An idle process with nothing dialing it still exits once its VM's state
    /// directory is gone, however long the dial loop has been running.
    #[test]
    fn the_process_exits_when_the_state_dir_disappears() {
        let dir = keys_dir();
        let grant = grant(dir.path());
        let state = tempfile::tempdir().unwrap();
        let state_path = state.path().to_path_buf();
        let config = MailboxProcessConfig {
            keys: derive_launch_keys(dir.path(), &grant).unwrap(),
            grant,
            socket: dir.path().join("mailbox.sock"),
            guest_port: dir.path().join("absent-port"),
            firecracker_mux: dir.path().join("absent-mux"),
            vm_state_dir: state_path,
        };
        let serving = std::thread::spawn(move || serve(config));
        drop(state);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !serving.is_finished() {
            assert!(std::time::Instant::now() < deadline, "process did not exit");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(serving.join().unwrap(), 0);
    }

    #[test]
    fn a_grant_that_cannot_be_served_fails_the_launch() {
        let dir = keys_dir();
        let granted = config_for(Some(grant(dir.path())));
        let error = serve_with(
            &granted,
            &Spawns::default(),
            Err(Error::other("no mvm-mailbox")),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("no mvm-mailbox"), "{error:#}");
    }

    #[test]
    fn a_grant_on_an_unwired_backend_is_refused_before_boot() {
        let dir = keys_dir();
        let granted = config_for(Some(grant(dir.path())));
        for name in ["firecracker", "hvf"] {
            let backend = backend_named(name);
            assert!(backend.capabilities().guest_mailbox, "{name}");
            assert!(require_servable(&granted, &backend).is_ok(), "{name}");
        }
        for name in ["libkrun", "qemu", "wasm"] {
            let backend = backend_named(name);
            assert!(!backend.capabilities().guest_mailbox, "{name}");
            assert!(require_servable(&granted, &backend).is_err(), "{name}");
            assert!(
                require_servable(&config_for(None), &backend).is_ok(),
                "{name}"
            );
        }
    }
}
