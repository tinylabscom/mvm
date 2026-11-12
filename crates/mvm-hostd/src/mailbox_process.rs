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
//!
//! Admitted Dev launches retain the ephemeral Send queue. Production requires
//! an explicit signed retention window, verified guest boot, and retained
//! custody before binding a receipt-bearing local journal and guest reader.
//! The same-host anchor authorizes `AcceptedLocalDurable`, never the stronger
//! whole-host rollback-resistant `AcceptedDurable` claim.

use std::io::{Error, ErrorKind, Result, Write as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use mvm_contract::protocol::mailbox::{MAILBOX_PORT, MailboxGrant};
use mvm_core::mailbox::journal::{FileJournalAnchor, JournalError, JournalLimits, MailboxJournal};
use mvm_core::plan::{ExecutionPlan, Variant};
use mvm_core::vm_backend::{HostDialRoute, VmId, VmStartConfig};
use mvm_runtime::backend::AnyBackend;
use mvm_vmm::host::aux_bin::AuxBin;
use mvm_vmm::host::flowmux_identity::{MAILBOX_READER_BOOT_FILE, MailboxReaderBootBinding};

use crate::mailbox_custody::RetainedMailboxKeys;
use crate::mailbox_launch::{DerivedMailboxKeys, LAUNCH_LIMITS, derive_launch_keys};
use crate::mailbox_service::MailboxService;
use crate::mailbox_service::durable::DurableMailboxService;
use crate::plan_admission::{MailboxLaunchPosture, MailboxPostureHandoff};
use crate::vm_lifetime::{endpoint_needed, launcher_is_alive};

mod reader;

/// The helper binary this module spawns.
pub const MAILBOX_BIN: &str = "mvm-mailbox";
/// Path-override variable for the helper binary.
pub const MAILBOX_BIN_ENV: &str = "MVM_MAILBOX_PATH";
/// Where the process's pid is recorded, beside the VM.
pub use mvm_vmm::host::vm_helpers::MAILBOX_PID_FILE;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_MARKER: &[u8; 6] = b"READY\n";
const MAX_HELPER_PLAN_BYTES: u64 = 1024 * 1024;
const LOCAL_JOURNAL_LIMITS: JournalLimits = JournalLimits {
    max_records: 10_000,
    max_bytes: 64 * 1024 * 1024,
};

/// What the process reads on stdin. `deny_unknown_fields`, so a field a newer
/// launcher adds fails closed here.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxProcessConfig {
    pub grant: MailboxGrant,
    pub keys: DerivedMailboxKeys,
    /// Absolute host key directory from the launcher; helper environment is empty.
    pub keys_dir: PathBuf,
    pub socket: PathBuf,
    pub guest_route: HostDialRoute,
    /// Absent on an old or unauthenticated restart: fail closed, never default Dev.
    pub posture: Option<MailboxPostureHandoff>,
    /// Public ACK key and boot identity pinned to the admitted cold plan.
    /// Absent on a warm child until it rekeys and enrolls.
    pub reader_boot: Option<MailboxReaderBootBinding>,
    /// The VM whose lifetime bounds this process.
    pub vm_state_dir: PathBuf,
}

/// Parse the stdin config.
pub fn parse(raw: &[u8]) -> serde_json::Result<MailboxProcessConfig> {
    serde_json::from_slice(raw)
}

fn load_admitted_plan(state_dir: &Path) -> Result<ExecutionPlan> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state_dir.join("plan.json"))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_HELPER_PLAN_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "mailbox helper plan is not a bounded single-link regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_HELPER_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_HELPER_PLAN_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "mailbox helper plan is oversized",
        ));
    }
    mvm_core::plan::plan_from_admitted_json(
        std::str::from_utf8(&bytes).map_err(|error| Error::new(ErrorKind::InvalidData, error))?,
    )
    .map_err(|error| Error::new(ErrorKind::InvalidData, error))
}

/// Serve until neither the launcher nor the VM is left; the exit code.
pub fn serve(config: MailboxProcessConfig) -> i32 {
    match serve_verified(config) {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(%error, "mailbox service failed closed");
            1
        }
    }
}

fn serve_verified(config: MailboxProcessConfig) -> Result<()> {
    // SAFETY: `getppid` is async-signal-safe and infallible.
    let launcher = unsafe { libc::getppid() };
    let MailboxProcessConfig {
        grant,
        keys,
        keys_dir,
        socket,
        guest_route,
        posture,
        reader_boot,
        vm_state_dir,
    } = config;
    let posture = posture.ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "mailbox helper has no admitted posture",
        )
    })?;
    let plan = load_admitted_plan(&vm_state_dir)?;
    let vm_name = vm_state_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "mailbox VM identity is invalid"))?;
    if reader_boot != load_reader_boot_for_plan(&vm_state_dir, &plan)? {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "mailbox reader boot changed since the admitted helper handoff",
        ));
    }
    posture
        .verify(
            &plan,
            vm_name,
            reader_boot.as_ref().map(|binding| binding.boot),
        )
        .map_err(Error::other)?;
    if plan.mailbox != Some(grant) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "mailbox helper grant does not match its admitted plan",
        ));
    }
    if posture.variant() == Variant::Prod {
        return serve_local(
            launcher,
            &plan,
            MailboxProcessConfig {
                grant,
                keys,
                keys_dir,
                socket,
                guest_route,
                posture: Some(posture),
                reader_boot,
                vm_state_dir,
            },
        );
    }
    if posture.variant() != Variant::Dev {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "invalid mailbox posture",
        ));
    }
    let (policy, sealer) = keys.trust();
    let sealer = sealer.with_grant(&grant)?;
    let service = MailboxService::bind_live(&socket, LAUNCH_LIMITS, policy.with_grant(&grant)?)?;
    std::io::stdout().write_all(READY_MARKER)?;
    let mut sealer = sealer;
    while vm_state_dir.exists()
        && endpoint_needed(launcher_is_alive(launcher), vm_is_alive(&vm_state_dir))
    {
        if service
            .serve_guest_route(&guest_route, &mut sealer)
            .is_err()
        {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    Ok(())
}

fn serve_local(
    launcher: libc::pid_t,
    plan: &ExecutionPlan,
    config: MailboxProcessConfig,
) -> Result<()> {
    let MailboxProcessConfig {
        grant,
        keys,
        keys_dir,
        socket,
        guest_route,
        posture,
        reader_boot,
        vm_state_dir,
    } = config;
    let posture = posture.ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "production mailbox has no admitted posture",
        )
    })?;
    let vm_name = vm_state_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "mailbox VM identity is invalid"))?;
    if !keys_dir.is_absolute() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "mailbox custody directory must be absolute",
        ));
    }
    let binding = reader_boot.as_ref().ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "production mailbox requires a verified guest reader boot",
        )
    })?;
    let retention = grant.retention.ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "production mailbox has no signed retention",
        )
    })?;
    let (initial_policy, _) = keys.trust();
    let address = mvm_contract::protocol::mailbox::MailboxAddress {
        tenant: initial_policy.context.expected_tenant,
        authorization_domain: initial_policy.context.expected_authorization_domain,
        mailbox: grant.mailbox,
        recipient: initial_policy.context.expected_recipient,
    };
    let retained = RetainedMailboxKeys::open_existing(
        &keys_dir,
        plan,
        vm_name,
        &posture,
        Some(binding.boot),
        address,
    )
    .map_err(Error::other)?;
    if retained.retention().map_err(Error::other)? != retention {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "local mailbox retention differs from signed custody",
        ));
    }
    let paths = retained.storage_paths(&keys_dir).map_err(Error::other)?;
    let derived = keys.with_retained(&retained)?;
    let (signer, _, _) = derived.durable_material();
    let (policy, sealer) = derived.trust();
    let mut sealer = sealer.with_grant(&grant)?;
    mvm_core::private_fs::ensure_private_dir(&paths.source_intents).map_err(Error::other)?;
    sealer.intent_dir = Some(paths.source_intents);
    let anchor = FileJournalAnchor::open(&paths.anchor, address, retained.anchor_key())
        .map_err(Error::other)?;
    let journal = MailboxJournal::open_local_with_custody(
        &paths.journal,
        retained.history_reference(),
        signer.verifying_key(),
        LOCAL_JOURNAL_LIMITS,
        &retained,
        &anchor,
        retention,
    )
    .map_err(Error::other)?;
    let reader = reader::load_or_enroll(
        &vm_state_dir,
        &grant,
        binding.clone(),
        &sealer.capability,
        &signer,
    )?;
    let service = DurableMailboxService::bind_local(
        &socket,
        LAUNCH_LIMITS,
        policy.with_grant(&grant)?,
        signer,
        journal,
        anchor,
    )?;
    service.install_guest_reader(reader)?;
    std::io::stdout().write_all(READY_MARKER)?;
    while vm_state_dir.exists()
        && endpoint_needed(launcher_is_alive(launcher), vm_is_alive(&vm_state_dir))
    {
        if service.serve_guest(&guest_route, &mut sealer).is_err() {
            std::thread::sleep(POLL_INTERVAL);
        }
        match service.maintain_local() {
            Ok(()) | Err(JournalError::MaintenancePending) => {}
            Err(error) => return Err(Error::other(error)),
        }
    }
    Ok(())
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
    backend: &AnyBackend,
) -> Result<MailboxProcessConfig> {
    Ok(MailboxProcessConfig {
        grant: *grant,
        keys: derive_launch_keys(keys_dir, grant)?,
        keys_dir: keys_dir.to_path_buf(),
        socket: mvm_core::config::vm_mailbox_socket_at(state_dir),
        guest_route: backend
            .host_dial_route(state_dir, MAILBOX_PORT)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "backend cannot dial the guest mailbox port",
                )
            })?,
        posture: None,
        reader_boot: None,
        vm_state_dir: state_dir.to_path_buf(),
    })
}

fn load_reader_boot_for_plan(
    state_dir: &Path,
    plan: &ExecutionPlan,
) -> Result<Option<MailboxReaderBootBinding>> {
    use base64::Engine as _;
    let path = state_dir.join(MAILBOX_READER_BOOT_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "mailbox reader boot binding is not a regular file",
            ));
        }
        Ok(_) => {}
    }
    let binding = MailboxReaderBootBinding::load(state_dir).map_err(Error::other)?;
    binding.check_plan(plan).map_err(|_| {
        Error::new(
            ErrorKind::PermissionDenied,
            "mailbox reader boot binding does not match the admitted plan",
        )
    })?;
    let identity = mvm_vmm::host::flowmux_identity::load_inheritable_identity(state_dir)
        .map_err(Error::other)?
        .ok_or_else(|| Error::new(ErrorKind::PermissionDenied, "guest identity is absent"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(identity.guest_verifying_key_base64)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "guest identity encoding is invalid"))?;
    if bytes != binding.guest_identity_key {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "mailbox ACK key belongs to a different guest boot identity",
        ));
    }
    Ok(Some(binding))
}

/// The command that starts the process: no arguments, an empty environment,
/// its own process group, config over a pipe. The process parses guest bytes
/// and holds derived keys, and reads no variable, so it is given none.
fn command(bin: &Path) -> Command {
    let mut cmd = mvm_core::env_hygiene::helper_command(bin);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    cmd
}

fn wait_ready(mut stdout: impl std::io::Read + Send + 'static, timeout: Duration) -> Result<()> {
    let (tx, rx) = sync_channel(1);
    std::thread::spawn(move || {
        let mut marker = [0u8; READY_MARKER.len()];
        let outcome = stdout.read_exact(&mut marker).map(|()| marker);
        let _ = tx.send(outcome);
    });
    let marker = rx
        .recv_timeout(timeout)
        .map_err(|_| Error::new(ErrorKind::TimedOut, "mailbox helper readiness timed out"))??;
    if &marker != READY_MARKER {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "mailbox helper sent an invalid readiness marker",
        ));
    }
    Ok(())
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
pub fn require_servable(
    config: &VmStartConfig,
    backend: &AnyBackend,
    posture: Option<&MailboxLaunchPosture>,
) -> anyhow::Result<()> {
    match granted_plan(config) {
        Some(plan) => {
            let posture = posture.ok_or_else(|| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    "mailbox launch has no admitted posture",
                )
            })?;
            posture.verify(&plan, &config.name)?;
            if posture.variant() == Variant::Prod
                && plan.mailbox.is_some_and(|grant| grant.retention.is_none())
            {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "production mailbox requires signed retention",
                )
                .into());
            }
            Ok(require_wired(&plan, backend)?)
        }
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
    posture: Option<&MailboxLaunchPosture>,
) -> anyhow::Result<()> {
    serve_started_with(backend, id, config, posture, spawn_for_launch)
}

fn serve_started_with(
    backend: &AnyBackend,
    id: &VmId,
    config: &VmStartConfig,
    posture: Option<&MailboxLaunchPosture>,
    spawn: impl FnOnce(
        &ExecutionPlan,
        &AnyBackend,
        &str,
        Option<&MailboxLaunchPosture>,
    ) -> Result<Option<u32>>,
) -> anyhow::Result<()> {
    let Some(plan) = granted_plan(config) else {
        return Ok(());
    };
    let outcome = (|| -> anyhow::Result<()> {
        require_servable(config, backend, posture)?;
        spawn(&plan, backend, &id.0, posture)?;
        Ok(())
    })();
    if let Err(error) = outcome {
        if let Err(stop) = backend.stop(id) {
            tracing::warn!(vm = %id.0, error = %stop, "stopping a VM whose mailbox could not be served failed");
        }
        return Err(error.context("the granted guest mailbox could not be served"));
    }
    Ok(())
}

/// Start the mailbox process for a launched VM when `plan` grants a mailbox
/// and `backend` declares the capability; its pid, or `None` when nothing was started.
pub fn spawn_for_launch(
    plan: &ExecutionPlan,
    backend: &AnyBackend,
    vm_name: &str,
    posture: Option<&MailboxLaunchPosture>,
) -> Result<Option<u32>> {
    let Some(grant) = &plan.mailbox else {
        return Ok(None);
    };
    let posture = posture.ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            "mailbox launch has no admitted posture",
        )
    })?;
    posture.verify(plan, vm_name).map_err(Error::other)?;
    if posture.variant() == Variant::Prod && grant.retention.is_none() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "production mailbox requires signed retention",
        ));
    }
    require_wired(plan, backend)?;
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let mut config = build_config(
        &mvm_core::config::mvm_keys_dir(),
        grant,
        &state_dir,
        backend,
    )?;
    config.reader_boot = load_reader_boot_for_plan(&state_dir, plan)?;
    if posture.variant() == Variant::Prod {
        let binding = config.reader_boot.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::PermissionDenied,
                "production mailbox requires guest boot binding",
            )
        })?;
        let (policy, _) = config.keys.trust();
        let address = mvm_contract::protocol::mailbox::MailboxAddress {
            tenant: policy.context.expected_tenant,
            authorization_domain: policy.context.expected_authorization_domain,
            mailbox: grant.mailbox,
            recipient: policy.context.expected_recipient,
        };
        RetainedMailboxKeys::provision_or_open(
            &config.keys_dir,
            plan,
            vm_name,
            posture,
            Some(binding.boot),
            address,
        )
        .map_err(Error::other)?;
    }
    config.posture = Some(posture.handoff(config.reader_boot.as_ref().map(|binding| binding.boot)));
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
    let ready = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("mvm-mailbox stdout was not piped"))
        .and_then(|stdout| wait_ready(stdout, READY_TIMEOUT));
    if let Err(error) = ready {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if let Err(error) = std::fs::write(state_dir.join(MAILBOX_PID_FILE), child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(Some(child.id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::mailbox::{ExecutionEpoch, MailboxId};

    #[test]
    fn helper_readiness_requires_the_exact_marker_before_launch_succeeds() {
        let timeout = Duration::from_millis(100);
        assert!(wait_ready(std::io::Cursor::new(*READY_MARKER), timeout).is_ok());
        assert_eq!(
            wait_ready(std::io::Cursor::new(*b"WRONG\n"), timeout)
                .expect_err("wrong marker")
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            wait_ready(std::io::Cursor::new(Vec::<u8>::new()), timeout)
                .expect_err("helper exited")
                .kind(),
            ErrorKind::UnexpectedEof
        );
        let (blocked, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            wait_ready(blocked, Duration::from_millis(1))
                .expect_err("silent helper cannot hang the launch")
                .kind(),
            ErrorKind::TimedOut
        );
        drop(peer);
    }

    fn keys_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
        dir
    }

    fn accept_guest(listener: &std::os::unix::net::UnixListener) -> std::os::unix::net::UnixStream {
        use std::os::fd::AsRawFd as _;
        let mut ready = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `ready` is a live pollfd for this owned listener, valid for one entry.
        let result = unsafe { libc::poll(&mut ready, 1, 10_000) };
        assert_eq!(result, 1, "helper did not dial before the guest deadline");
        assert_ne!(
            ready.revents & libc::POLLIN,
            0,
            "guest port was not readable"
        );
        let (stream, _) = listener.accept().expect("helper dialed guest port");
        stream
            .set_nonblocking(false)
            .expect("blocking guest exchange");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("bounded guest read");
        stream
    }

    fn grant(dir: &Path) -> MailboxGrant {
        let mailbox = MailboxId::from_bytes([4; 32]);
        MailboxGrant {
            mailbox,
            authority_key: crate::mailbox_launch::authority_key_for(dir, &mailbox)
                .unwrap()
                .to_bytes(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            report: None,
            retention: None,
        }
    }

    #[test]
    fn an_ungranted_plan_spawns_nothing() {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        assert!(plan.mailbox.is_none());
        let started =
            spawn_for_launch(&plan, &backend_named("firecracker"), "no-such-vm", None).unwrap();
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
        plan.image.name = "no-such-vm".into();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Dev);
        let error = spawn_for_launch(
            &plan,
            &backend_named("libkrun"),
            "no-such-vm",
            Some(&posture),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn the_config_refuses_unknown_fields() {
        let dir = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let config = build_config(
            dir.path(),
            &grant(dir.path()),
            state.path(),
            &backend_named("hvf"),
        )
        .unwrap();
        let mut value = serde_json::to_value(&config).unwrap();
        assert!(parse(value.to_string().as_bytes()).is_ok());
        value["seed"] = serde_json::json!("00");
        assert!(parse(value.to_string().as_bytes()).is_err());
    }

    #[test]
    fn mailbox_process_dials_only_the_route_declared_by_its_backend() {
        let dir = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let grant = grant(dir.path());
        for (backend, expected_mux) in [("hvf", false), ("firecracker", true)] {
            let backend = backend_named(backend);
            let config = build_config(dir.path(), &grant, state.path(), &backend).unwrap();
            assert_eq!(
                matches!(config.guest_route, HostDialRoute::Mux(_)),
                expected_mux
            );
            assert_eq!(
                config.guest_route,
                backend.host_dial_route(state.path(), MAILBOX_PORT).unwrap()
            );
        }
        assert_eq!(
            build_config(dir.path(), &grant, state.path(), &backend_named("libkrun"),)
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn guest_reader_boot_must_match_the_admitted_plan_and_pinned_guest_identity() {
        use base64::Engine as _;
        use mvm_vmm::host::flowmux_identity::{
            InheritableIdentity, MAILBOX_READER_BOOT_FILE, MailboxAckKeyMaterial,
        };
        let keys = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let guest = ed25519_dalek::SigningKey::from_bytes(&[66; 32]);
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant(keys.path()));
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let ack = MailboxAckKeyMaterial::mint().unwrap();
        let binding = MailboxReaderBootBinding::mint(
            &plan,
            guest.verifying_key(),
            ack.verifying_key().to_bytes(),
        )
        .unwrap();
        binding.persist(state.path()).unwrap();
        InheritableIdentity {
            session_id: "guest-current".into(),
            guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
                .encode(guest.verifying_key().as_bytes()),
        }
        .persist(state.path())
        .unwrap();
        assert_eq!(
            load_reader_boot_for_plan(state.path(), &plan).unwrap(),
            Some(binding.clone())
        );
        let mut tampered = plan.clone();
        tampered.audit_labels.insert("changed".into(), "yes".into());
        assert!(
            load_reader_boot_for_plan(state.path(), &tampered).is_err(),
            "a changed plan body cannot reuse its old content address"
        );
        let mut stale = plan.clone();
        stale.nonce = mvm_core::plan::Nonce::from_bytes([99; 16]);
        assert!(load_reader_boot_for_plan(state.path(), &stale).is_err());
        InheritableIdentity {
            session_id: "guest-other".into(),
            guest_verifying_key_base64: base64::engine::general_purpose::STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[67; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
        }
        .persist(state.path())
        .unwrap();
        assert!(load_reader_boot_for_plan(state.path(), &plan).is_err());
        std::fs::remove_file(state.path().join(MAILBOX_READER_BOOT_FILE)).unwrap();
        let outside = state.path().join("outside");
        std::fs::write(&outside, serde_json::to_vec(&binding).unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, state.path().join(MAILBOX_READER_BOOT_FILE)).unwrap();
        assert!(load_reader_boot_for_plan(state.path(), &plan).is_err());
    }

    #[test]
    fn the_config_carries_no_seed_and_the_command_carries_no_argv_or_env_secret() {
        let dir = keys_dir();
        let seed = std::fs::read(dir.path().join("host-signer.ed25519")).unwrap();
        let state = tempfile::tempdir().unwrap();
        let config = build_config(
            dir.path(),
            &grant(dir.path()),
            state.path(),
            &backend_named("firecracker"),
        )
        .unwrap();
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
        // Cleared, not filtered: whatever the parent holds is not inherited,
        // and the builder sets nothing back.
        assert_eq!(cmd.get_envs().count(), 0, "no variable is passed");
        let out = command(Path::new("/usr/bin/env"))
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        assert!(out.stdout.is_empty(), "the child's environ is empty");
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
        plan.image.name = "vm-under-test".into();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        VmStartConfig {
            name: "vm-under-test".into(),
            plan_json: Some(serde_json::to_string(&plan).unwrap()),
            ..Default::default()
        }
    }

    type Spawns = std::cell::RefCell<Vec<String>>;

    fn posture_for(config: &VmStartConfig, variant: Variant) -> Option<MailboxLaunchPosture> {
        granted_plan(config).map(|plan| MailboxLaunchPosture::for_test(&plan, variant))
    }

    fn serve_with(
        config: &VmStartConfig,
        spawns: &Spawns,
        outcome: Result<Option<u32>>,
    ) -> anyhow::Result<()> {
        let backend = AnyBackend::from_hypervisor("firecracker");
        let posture = posture_for(config, Variant::Dev);
        serve_started_with(
            &backend,
            &VmId("vm-under-test".into()),
            config,
            posture.as_ref(),
            |_, _, name, _| {
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
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.image.name = state_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        std::fs::write(
            state_path.join("plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        let config = MailboxProcessConfig {
            keys: derive_launch_keys(dir.path(), &grant).unwrap(),
            keys_dir: dir.path().to_path_buf(),
            grant,
            socket: dir.path().join("mailbox.sock"),
            guest_route: HostDialRoute::PortSocket(dir.path().join("absent-port")),
            posture: Some(MailboxLaunchPosture::for_test(&plan, Variant::Dev).handoff(None)),
            reader_boot: None,
            vm_state_dir: state_path,
        };
        let socket = config.socket.clone();
        let serving = std::thread::spawn(move || serve(config));
        let started = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !socket.exists() {
            assert!(std::time::Instant::now() < started, "mailbox never bound");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        drop(state);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !serving.is_finished() {
            assert!(std::time::Instant::now() < deadline, "process did not exit");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(serving.join().unwrap(), 0);
    }

    #[test]
    fn dev_send_stays_live_without_a_false_durable_receipt() {
        use mvm_contract::protocol::mailbox::PrincipalId;
        use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage};
        let keys = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let grant = grant(keys.path());
        let vm_name = state
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.image.name = vm_name;
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        std::fs::write(
            state.path().join("plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();

        let guest_port = keys.path().join("guest-port.sock");
        let listener = std::os::unix::net::UnixListener::bind(&guest_port).unwrap();
        let outbox = keys.path().join("outbox");
        mvm_agentd::mailbox_outbox::write_outbox(
            &outbox,
            &OutboxMessage::new(
                PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
                b"ephemeral dev send".to_vec(),
            ),
        )
        .unwrap();
        let socket = keys.path().join("mailbox.sock");
        let config = MailboxProcessConfig {
            keys: derive_launch_keys(keys.path(), &grant).unwrap(),
            keys_dir: keys.path().to_path_buf(),
            grant,
            socket: socket.clone(),
            guest_route: HostDialRoute::PortSocket(guest_port),
            posture: Some(MailboxLaunchPosture::for_test(&plan, Variant::Dev).handoff(None)),
            reader_boot: None,
            vm_state_dir: state.path().to_path_buf(),
        };
        let helper = std::thread::spawn(move || serve(config));
        let ready = std::time::Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < ready,
                "dev mailbox did not bind"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let guest = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            mvm_agentd::mailbox_outbox::wait_and_forward_outbox(&mut stream, &outbox).unwrap();
            let (mut reader, _) = listener.accept().unwrap();
            reader
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            mvm_core::mailbox::reader_wire::write_request(
                &mut reader,
                &mvm_core::mailbox::reader_wire::ReaderRequest::Receive,
            )
            .unwrap();
            assert_eq!(
                mvm_core::mailbox::reader_wire::read_response(&mut reader),
                Ok(mvm_core::mailbox::reader_wire::ReaderResponse::Refused {
                    reason: mvm_core::mailbox::frame::Refusal::Unavailable
                }),
                "ephemeral Send cannot grant a guest Receive lease"
            );
        });
        guest.join().unwrap();
        assert_eq!(
            crate::mailbox_service::recv(&socket).unwrap().message,
            Some(hex::encode(b"ephemeral dev send"))
        );
        assert!(!state.path().join("mailbox-journal").exists());
        assert!(!state.path().join("mailbox-anchor").exists());
        drop(state);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !helper.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "ephemeral helper did not stop"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(helper.join().unwrap(), 0);
    }

    #[test]
    fn production_helper_requires_retained_custody_and_returns_signed_local_receipt() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::mailbox::{DeliveryOutcome, PrincipalId};
        use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage};

        let home = tempfile::tempdir_in("/tmp").expect("isolated host home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let keys_dir = mvm_core::config::mvm_keys_dir();
        crate::audit::host_keypair::load_or_init_at(&keys_dir).expect("host signer");
        let state = tempfile::tempdir_in("/tmp").expect("VM state");
        let mut grant = grant(&keys_dir);
        grant.retention = Some(
            mvm_contract::protocol::mailbox::MailboxRetentionPolicy::new(10_000)
                .expect("signed retention"),
        );
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.image.name = state
            .path()
            .file_name()
            .expect("VM name")
            .to_string_lossy()
            .into_owned();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        std::fs::write(
            state.path().join("plan.json"),
            serde_json::to_vec(&plan).expect("plan"),
        )
        .expect("admitted plan");
        let binding = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[45; 32]).verifying_key(),
            SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes(),
        )
        .expect("cold boot identity");
        binding.persist(state.path()).expect("persist guest boot");
        {
            use base64::Engine as _;
            mvm_vmm::host::flowmux_identity::InheritableIdentity {
                session_id: "production-guest".into(),
                guest_verifying_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(SigningKey::from_bytes(&[45; 32]).verifying_key().as_bytes()),
            }
            .persist(state.path())
            .expect("persist pinned guest identity");
        }
        let posture = MailboxLaunchPosture::for_test(&plan, Variant::Prod);
        let keys = derive_launch_keys(&keys_dir, &grant).expect("derived mailbox keys");
        let (policy, _) = keys.trust();
        let address = mvm_contract::protocol::mailbox::MailboxAddress {
            tenant: policy.context.expected_tenant,
            authorization_domain: policy.context.expected_authorization_domain,
            mailbox: grant.mailbox,
            recipient: policy.context.expected_recipient,
        };
        let retained = RetainedMailboxKeys::provision_or_open(
            &keys_dir,
            &plan,
            &plan.image.name,
            &posture,
            Some(binding.boot),
            address,
        )
        .expect("signed custody");
        let paths = retained.storage_paths(&keys_dir).expect("persistent paths");
        let guest_port = home.path().join("guest-port.sock");
        let listener = std::sync::Arc::new(
            std::os::unix::net::UnixListener::bind(&guest_port).expect("guest port"),
        );
        listener
            .set_nonblocking(true)
            .expect("bounded guest accept");
        let socket = home.path().join("mailbox.sock");
        let restart_keys = keys.clone();
        let restart_binding = binding.clone();
        let wrong_keys = MailboxProcessConfig {
            keys: keys.clone(),
            keys_dir: home.path().join("missing-keys"),
            grant,
            socket: socket.clone(),
            guest_route: HostDialRoute::PortSocket(guest_port.clone()),
            posture: Some(posture.handoff(Some(binding.boot))),
            reader_boot: Some(binding.clone()),
            vm_state_dir: state.path().to_path_buf(),
        };
        assert!(
            serve_verified(wrong_keys).is_err(),
            "the helper must load exact retained custody, not use its launch keys alone"
        );
        assert!(!socket.exists(), "failed custody cannot bind a listener");
        let config = MailboxProcessConfig {
            keys,
            keys_dir: keys_dir.clone(),
            grant,
            socket: socket.clone(),
            guest_route: HostDialRoute::PortSocket(guest_port.clone()),
            posture: Some(posture.handoff(Some(binding.boot))),
            reader_boot: Some(binding),
            vm_state_dir: state.path().to_path_buf(),
        };
        let (stopped_tx, stopped_rx) = sync_channel(1);
        let helper = std::thread::spawn(move || {
            let outcome = serve_verified(config);
            let _ = stopped_tx.send(());
            outcome
        });
        let outbox = home.path().join("outbox");
        let message = OutboxMessage::new(
            PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
            b"local report".to_vec(),
        );
        mvm_agentd::mailbox_outbox::write_outbox(&outbox, &message).expect("outbox");
        let retry_outbox = outbox.clone();
        let send_listener = std::sync::Arc::clone(&listener);
        let guest = std::thread::spawn(move || {
            let mut stream = accept_guest(&send_listener);
            mvm_agentd::mailbox_outbox::forward_local_outbox(
                &mut stream,
                &outbox,
                &ed25519_dalek::VerifyingKey::from_bytes(&grant.authority_key).expect("authority"),
                grant.mailbox,
                grant.epoch,
            )
            .expect("verified signed local receipt")
        });
        let accepted = match guest.join() {
            Ok(accepted) => accepted,
            Err(panic) => {
                if helper.is_finished() {
                    panic!(
                        "production helper failed: {:?}",
                        helper.join().expect("helper task")
                    );
                }
                std::panic::resume_unwind(panic);
            }
        };
        assert_eq!(
            accepted.receipt.outcome,
            DeliveryOutcome::AcceptedLocalDurable
        );
        assert!(paths.journal.is_dir(), "history survives outside VM state");
        assert!(paths.anchor.is_file(), "anchor committed before receipt");

        use mvm_contract::protocol::mailbox::{
            DeliveryAckNonce, MailboxDeliveryAck, ProtocolVersion, SignatureAlgorithm,
        };
        use mvm_core::mailbox::reader::{sign_delivery_ack, sign_reader_possession};
        use mvm_core::mailbox::reader_wire::{
            ReaderRequest, ReaderResponse, read_response, write_request,
        };
        let ack_key = SigningKey::from_bytes(&[44; 32]);
        let mut receiving = accept_guest(&listener);
        write_request(&mut receiving, &ReaderRequest::Receive).expect("request Receive");
        let ReaderResponse::Challenge {
            enrollment,
            challenge,
            ..
        } = read_response(&mut receiving).expect("reader challenge")
        else {
            panic!("guest did not receive a boot-bound challenge");
        };
        let signature = sign_reader_possession(&enrollment, &challenge, &ack_key)
            .expect("guest possession proof");
        write_request(
            &mut receiving,
            &ReaderRequest::Possession {
                signature: signature.to_vec(),
            },
        )
        .expect("answer challenge");
        let ReaderResponse::Delivery { lease, payload, .. } =
            read_response(&mut receiving).expect("leased delivery")
        else {
            panic!("guest did not receive a durable lease");
        };
        assert_eq!(payload, b"local report");
        drop(receiving);

        let now: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis()
            .try_into()
            .expect("bounded time");
        let signed_ack = sign_delivery_ack(
            MailboxDeliveryAck {
                protocol_version: ProtocolVersion::V1,
                signature_algorithm: SignatureAlgorithm::ED25519,
                lease: *lease,
                ack_nonce: DeliveryAckNonce::from_bytes([66; 16]),
                acknowledged_at_unix_ms: now,
            },
            &ack_key,
        )
        .expect("signed guest ACK");
        let mut forged = signed_ack.clone();
        forged.signature[0] ^= 1;
        let mut rejecting = accept_guest(&listener);
        write_request(
            &mut rejecting,
            &ReaderRequest::Ack {
                signed: Box::new(forged),
            },
        )
        .expect("forged guest ACK request");
        assert_eq!(
            read_response(&mut rejecting),
            Ok(ReaderResponse::Refused {
                reason: mvm_core::mailbox::frame::Refusal::NotAuthorized
            }),
            "a forged guest signature must not complete the lease"
        );
        drop(rejecting);
        let mut acknowledging = accept_guest(&listener);
        write_request(
            &mut acknowledging,
            &ReaderRequest::Ack {
                signed: Box::new(signed_ack.clone()),
            },
        )
        .expect("guest ACK");
        assert_eq!(
            read_response(&mut acknowledging),
            Ok(ReaderResponse::Acknowledged {
                ack: Box::new(signed_ack)
            }),
            "only the guest's exact signed ACK may complete the lease"
        );
        drop(acknowledging);
        drop(listener);
        let state_path = state.path().to_path_buf();
        let parked = home.path().join("paused-vm-state");
        std::fs::rename(&state_path, &parked).expect("stop helper without losing VM state");
        stopped_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("helper stopped after VM state moved");
        helper.join().expect("helper task").expect("clean stop");
        std::fs::rename(&parked, &state_path).expect("restore same VM identity");
        let anchor = FileJournalAnchor::open(&paths.anchor, address, retained.anchor_key())
            .expect("held local anchor");
        let mut journal = MailboxJournal::open_local_with_custody(
            &paths.journal,
            retained.history_reference(),
            ed25519_dalek::VerifyingKey::from_bytes(&grant.authority_key).expect("authority"),
            LOCAL_JOURNAL_LIMITS,
            &retained,
            &anchor,
            grant.retention.expect("signed retention"),
        )
        .expect("recover signed guest ACK");
        journal
            .compact_local(now, &restart_keys.durable_material().0, &anchor)
            .expect("checkpoint ACK before helper restart");
        drop(journal);
        drop(anchor);

        std::fs::remove_file(&guest_port).expect("release old guest socket");
        let listener = std::sync::Arc::new(
            std::os::unix::net::UnixListener::bind(&guest_port).expect("restart guest port"),
        );
        listener
            .set_nonblocking(true)
            .expect("bounded guest accept");
        let config = MailboxProcessConfig {
            keys: restart_keys,
            keys_dir: keys_dir.clone(),
            grant,
            socket,
            guest_route: HostDialRoute::PortSocket(guest_port),
            posture: Some(posture.handoff(Some(restart_binding.boot))),
            reader_boot: Some(restart_binding),
            vm_state_dir: state_path,
        };
        let (restarted_tx, restarted_rx) = sync_channel(1);
        let restarted = std::thread::spawn(move || {
            let outcome = serve_verified(config);
            let _ = restarted_tx.send(());
            outcome
        });
        mvm_agentd::mailbox_outbox::write_outbox(&retry_outbox, &message)
            .expect("replay same operation");
        let retry_listener = std::sync::Arc::clone(&listener);
        let retry = std::thread::spawn(move || {
            let mut stream = accept_guest(&retry_listener);
            mvm_agentd::mailbox_outbox::forward_local_outbox(
                &mut stream,
                &retry_outbox,
                &ed25519_dalek::VerifyingKey::from_bytes(&grant.authority_key).expect("authority"),
                grant.mailbox,
                grant.epoch,
            )
            .expect("recover exact signed receipt")
        })
        .join()
        .expect("retry guest");
        assert_eq!(retry, accepted, "checkpoint retained exact acceptance");
        let mut receiving = accept_guest(&listener);
        write_request(&mut receiving, &ReaderRequest::Receive).expect("Receive after restart");
        let ReaderResponse::Challenge {
            enrollment,
            challenge,
            ..
        } = read_response(&mut receiving).expect("restart challenge")
        else {
            panic!("guest reader enrollment was not restored");
        };
        let signature = sign_reader_possession(&enrollment, &challenge, &ack_key)
            .expect("same guest boot possession");
        write_request(
            &mut receiving,
            &ReaderRequest::Possession {
                signature: signature.to_vec(),
            },
        )
        .expect("answer restart challenge");
        assert_eq!(
            read_response(&mut receiving),
            Ok(ReaderResponse::Empty),
            "signed ACK must remain terminal after checkpoint and restart"
        );
        drop(receiving);
        drop(listener);
        drop(state);
        restarted_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("restarted helper stopped after VM teardown");
        restarted
            .join()
            .expect("restarted helper task")
            .expect("clean stop");
        assert!(
            paths.journal.is_dir(),
            "VM teardown cannot erase accepted history"
        );
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
        let posture = posture_for(&granted, Variant::Dev);
        for name in ["firecracker", "hvf"] {
            let backend = backend_named(name);
            assert!(backend.capabilities().guest_mailbox, "{name}");
            assert!(
                require_servable(&granted, &backend, posture.as_ref()).is_ok(),
                "{name}"
            );
        }
        for name in ["libkrun", "qemu", "wasm"] {
            let backend = backend_named(name);
            assert!(!backend.capabilities().guest_mailbox, "{name}");
            assert!(
                require_servable(&granted, &backend, posture.as_ref()).is_err(),
                "{name}"
            );
            assert!(
                require_servable(&config_for(None), &backend, None).is_ok(),
                "{name}"
            );
        }
    }

    #[test]
    fn mailbox_never_defaults_missing_or_production_posture_to_dev() {
        let dir = keys_dir();
        let config = config_for(Some(grant(dir.path())));
        let backend = backend_named("firecracker");
        assert!(require_servable(&config, &backend, None).is_err());
        let prod = posture_for(&config, Variant::Prod);
        assert!(require_servable(&config, &backend, prod.as_ref()).is_err());
        let dev = posture_for(&config, Variant::Dev);
        assert!(require_servable(&config, &backend, dev.as_ref()).is_ok());

        let mut retained = grant(dir.path());
        retained.retention = Some(
            mvm_contract::protocol::mailbox::MailboxRetentionPolicy::new(10_000)
                .expect("finite signed window"),
        );
        let prod_config = config_for(Some(retained));
        let prod = posture_for(&prod_config, Variant::Prod);
        assert!(
            require_servable(&prod_config, &backend, prod.as_ref()).is_ok(),
            "a verified production grant with explicit retention may reach the helper"
        );
        let unwired = backend_named("wasm");
        assert!(
            require_servable(&prod_config, &unwired, prod.as_ref()).is_err(),
            "a signed window cannot make an unwired backend serve"
        );

        let mut forged = serde_json::to_value(dev.unwrap().handoff(None)).unwrap();
        forged["plan_id"] = serde_json::json!("sha256:wrong");
        let forged: MailboxPostureHandoff = serde_json::from_value(forged).unwrap();
        let plan = granted_plan(&config).unwrap();
        assert!(forged.verify(&plan, &config.name, None).is_err());
        let stale_boot = posture_for(&config, Variant::Dev).unwrap().handoff(Some(
            mvm_contract::protocol::mailbox::BootId::from_bytes([8; 32]),
        ));
        assert!(stale_boot.verify(&plan, &config.name, None).is_err());
    }

    #[test]
    fn helper_restart_without_admitted_posture_refuses_before_binding() {
        let dir = keys_dir();
        let state = tempfile::tempdir().unwrap();
        let grant = grant(dir.path());
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(grant);
        plan.image.name = state
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        std::fs::write(
            state.path().join("plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        let config = MailboxProcessConfig {
            keys: derive_launch_keys(dir.path(), &grant).unwrap(),
            keys_dir: dir.path().to_path_buf(),
            grant,
            socket: dir.path().join("mailbox.sock"),
            guest_route: HostDialRoute::PortSocket(dir.path().join("absent-port")),
            posture: None,
            reader_boot: None,
            vm_state_dir: state.path().to_path_buf(),
        };
        assert_eq!(serve(config), 1);
        assert!(!dir.path().join("mailbox.sock").exists());
    }

    #[test]
    fn production_helper_without_guest_boot_refuses_before_custody_or_binding() {
        let keys = keys_dir();
        let mut grant = grant(keys.path());
        grant.retention = Some(
            mvm_contract::protocol::mailbox::MailboxRetentionPolicy::new(10_000)
                .expect("signed window"),
        );
        let start = config_for(Some(grant));
        let plan = granted_plan(&start).expect("admitted plan");
        let state = tempfile::tempdir_in("/tmp").expect("VM state root");
        let vm_state_dir = state.path().join("vm-under-test");
        std::fs::create_dir(&vm_state_dir).expect("VM state");
        std::fs::write(
            vm_state_dir.join("plan.json"),
            start.plan_json.expect("plan JSON"),
        )
        .expect("persist admitted plan");
        let socket = state.path().join("mailbox.sock");
        let config = MailboxProcessConfig {
            grant,
            keys: derive_launch_keys(keys.path(), &grant).expect("mailbox keys"),
            keys_dir: keys.path().to_path_buf(),
            socket: socket.clone(),
            guest_route: HostDialRoute::PortSocket(state.path().join("guest-port.sock")),
            posture: Some(MailboxLaunchPosture::for_test(&plan, Variant::Prod).handoff(None)),
            reader_boot: None,
            vm_state_dir,
        };
        let error = serve_verified(config).expect_err("no signed guest boot");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        assert!(
            !socket.exists(),
            "a refused helper cannot publish a listener"
        );
    }

    #[test]
    fn helper_refuses_oversized_or_symlinked_plan_state() {
        let state = tempfile::tempdir().unwrap();
        let path = state.path().join("plan.json");
        std::fs::write(&path, vec![b' '; MAX_HELPER_PLAN_BYTES as usize + 1]).unwrap();
        assert_eq!(
            load_admitted_plan(state.path()).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(state.path().join("missing"), &path).unwrap();
        assert!(load_admitted_plan(state.path()).is_err());
    }
}
