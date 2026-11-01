//! Original native launch, authenticated stream, and stop custody.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use super::{
    ConnectedInstance, HandoffConfig, HvfInstance, HvfRunningVm, HvfSupervisorConfig,
    OwnedInstance, SupervisorLaunchPolicy, VmId, VmmSpec, boot_retaining_child,
};

pub(super) struct BootInputFiles<'a> {
    pub(super) kernel: Option<&'a mvm_vmm::host::restore_image::VerifiedRestoreFile>,
    pub(super) images: Option<&'a mvm_vmm::host::boot_images::FrozenBootImageBytes>,
    pub(super) writable: Option<&'a mvm_vmm::driver::prepared_disks::PreparedWritableDisks>,
}

impl BootInputFiles<'_> {
    pub(super) fn project(&self, spec: &VmmSpec, cfg: &mut HvfSupervisorConfig) -> Result<()> {
        use std::os::fd::AsRawFd;
        cfg.kernel_fd = self.kernel.map(|kernel| kernel.file().as_raw_fd());
        cfg.boot_image_fds = self.images.map(|images| {
            use mvm_core::registry_pack_boot::BootImageAsset as Role;
            mvm_vmm::host::hvf_supervisor::BootImageFds {
                rootfs: images.file(Role::Rootfs).as_raw_fd(),
                verity: images.file(Role::Verity).as_raw_fd(),
                metadata: images.file(Role::Metadata).as_raw_fd(),
                root_hash: images.file(Role::RootHash).as_raw_fd(),
            }
        });
        if let Some(images) = self.images {
            anyhow::ensure!(
                cfg.kernel_fd.is_some() && cfg.caller_registration.is_some(),
                "frozen images require the original kernel and caller registration"
            );
            let claims = cfg.boot_image_claims().map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                claims.root_hash() == images.root_hash(),
                "projected command differs from original frozen image hash"
            );
        }
        if let Some(writable) = self.writable {
            let mut ordered = spec.blocks.iter().collect::<Vec<_>>();
            ordered.sort_by_key(|block| block.slot);
            cfg.writable_disk_fds = writable
                .iter()
                .map(|(slot, image)| {
                    let disk = ordered
                        .iter()
                        .position(|block| block.slot == slot)
                        .context("prepared writable slot missing from HVF spec")?;
                    Ok(mvm_vmm::host::hvf_supervisor::HvfWritableDiskFds {
                        disk,
                        backing: image.backing().as_raw_fd(),
                        sidecar: image.sidecar().as_raw_fd(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        }
        Ok(())
    }

    pub(super) fn inheritance_vector(cfg: &HvfSupervisorConfig) -> Result<Vec<i32>> {
        let mut inherited = cfg.kernel_fd.into_iter().collect::<Vec<_>>();
        if let Some(images) = cfg.boot_image_fds {
            inherited.extend(images.descriptors());
        }
        for disk in &cfg.writable_disk_fds {
            inherited.extend([disk.backing, disk.sidecar]);
        }
        anyhow::ensure!(
            inherited.iter().all(|fd| *fd > 2)
                && inherited
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == inherited.len(),
            "native boot descriptors must be distinct original files"
        );
        Ok(inherited)
    }
}

pub(super) fn boot_with_custody(
    spec: &VmmSpec,
    handoff: Option<&HandoffConfig>,
    exclusive_image_lock: Option<&Path>,
    policy: SupervisorLaunchPolicy,
    files: BootInputFiles<'_>,
) -> std::result::Result<HvfRunningVm, ColdHvfBootFailure> {
    let mut child = None;
    let mut rollback = None;
    boot_retaining_child(
        spec,
        handoff,
        exclusive_image_lock,
        &mut child,
        &mut rollback,
        &policy,
        files,
    )
    .map_err(|error| {
        let outcome = match (child, rollback) {
            (Some(child), None) => FailedLaunchOutcome::Unconfirmed {
                child,
                vm_name: spec.name.clone(),
            },
            (None, Some(proof)) => FailedLaunchOutcome::ConfirmedRollback(proof),
            (None, None) => FailedLaunchOutcome::NeverLaunched,
            (Some(child), Some(_)) => FailedLaunchOutcome::Unconfirmed {
                child,
                vm_name: spec.name.clone(),
            },
        };
        ColdHvfBootFailure {
            error: Some(error),
            custody: Some(Box::new(std::sync::Mutex::new(FailedLaunchCustody {
                outcome,
                supporting: Vec::new(),
            }))),
        }
    })
}

pub(super) fn failed_owned_boot(
    original: anyhow::Error,
    pending: &mut Option<std::process::Child>,
    vm: &str,
    rollback: &mut Option<mvm_vmm::host::hvf_stop::ConfirmedExit>,
) -> anyhow::Error {
    let Some(child) = pending.as_mut() else {
        return original.context("owned supervisor handle unavailable");
    };
    if matches!(child.try_wait(), Ok(Some(_))) {
        return original.context("owned supervisor exited; runtime evidence retained");
    }
    let cleanup = ConnectedInstance::connect_owned(vm, child.id())
        .and_then(ConnectedInstance::stop)
        .and_then(|proof| {
            proof.verify_current()?;
            child.wait()?;
            Ok(proof)
        });
    match cleanup {
        Ok(proof) => {
            *rollback = Some(proof);
            drop(pending.take());
            original.context("owned HVF rollback confirmed; runtime evidence retained")
        }
        Err(error) => {
            original.context(error.context("safe HVF rollback unconfirmed; custody retained"))
        }
    }
}

pub(super) fn require_cold_config(config: &HvfSupervisorConfig) -> Result<()> {
    anyhow::ensure!(
        config.restore_ram.is_none()
            && config.restore_frame.is_none()
            && config.restore_fds.is_none()
            && config.handoff_socket.is_none()
            && config.handoff_root.is_none()
            && config.handoff_verify_key.is_none()
            && config.builder_egress_endpoint.is_none()
            && !config.trusted_builder_egress
            && config.exclusive_image_lock.is_none()
            && config.writable_disk_fds.is_empty()
            && config.builder_control_sockets.is_empty(),
        "cold HVF channel refuses restore, fork, handoff and builder configurations"
    );
    let hostname = format!("mvm.hostname={}", config.vm_name);
    anyhow::ensure!(
        config.cmdline.as_deref().is_some_and(|cmdline| {
            cmdline
                .split_whitespace()
                .filter(|token| token.starts_with("mvm.hostname="))
                .eq([hostname.as_str()])
        }),
        "cold HVF channel refuses identity-free factory-parent boot configuration"
    );
    anyhow::ensure!(cfg!(target_os = "macos"), "cold HVF custody requires macOS");
    Ok(())
}

/// A failed fresh launch keeps the exact child, including on rollback
/// uncertainty. This is not a channel and cannot authenticate guest RPCs.
#[must_use = "retain failed native launch custody until stop is confirmed"]
pub struct ColdHvfBootFailure {
    error: Option<anyhow::Error>,
    custody: Option<Box<std::sync::Mutex<FailedLaunchCustody>>>,
}

enum FailedLaunchOutcome {
    NeverLaunched,
    ConfirmedRollback(mvm_vmm::host::hvf_stop::ConfirmedExit),
    Unconfirmed {
        child: std::process::Child,
        vm_name: String,
    },
}

struct FailedLaunchCustody {
    outcome: FailedLaunchOutcome,
    // Runtime guards can travel inside legacy anyhow errors without an upward
    // dependency. The mutex makes Send-only guard aggregates safe to carry in
    // an Error; they are never exposed as generation authority.
    supporting: Vec<Box<dyn Send>>,
}

impl std::fmt::Debug for ColdHvfBootFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdHvfBootFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ColdHvfBootFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.error(), f)
    }
}

impl std::error::Error for ColdHvfBootFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error().as_ref())
    }
}

impl ColdHvfBootFailure {
    pub fn error(&self) -> &anyhow::Error {
        self.error
            .as_ref()
            .expect("failed launch error is present until consumed")
    }

    fn custody_mut(&mut self) -> &mut FailedLaunchCustody {
        self.custody
            .as_mut()
            .expect("failed launch custody remains present")
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Preserve supporting guards through legacy error boundaries. Dropping
    /// this error retains the entire aggregate only for unconfirmed launches.
    pub fn retain_support(mut self, support: impl Send + 'static) -> Self {
        self.custody_mut().supporting.push(Box::new(support));
        self
    }

    /// Text-only conversion is permitted only when no child was launched or
    /// an actual authenticated rollback proof was retained after reaping.
    pub fn into_released_error(mut self) -> std::result::Result<anyhow::Error, Self> {
        match self.custody_mut().outcome {
            FailedLaunchOutcome::NeverLaunched | FailedLaunchOutcome::ConfirmedRollback(_) => {
                Ok(self
                    .error
                    .take()
                    .expect("failed launch error not consumed twice"))
            }
            FailedLaunchOutcome::Unconfirmed { .. } => Err(self),
        }
    }

    pub fn retry_stop(&mut self) -> Result<()> {
        let custody = self.custody_mut();
        let (child, vm_name) = match &mut custody.outcome {
            FailedLaunchOutcome::NeverLaunched => return Ok(()),
            FailedLaunchOutcome::ConfirmedRollback(proof) => return proof.verify_current(),
            FailedLaunchOutcome::Unconfirmed { child, vm_name } => (child, vm_name),
        };
        anyhow::ensure!(
            child.try_wait()?.is_none(),
            "failed native launch exited before authenticated adoption; retain uncertain custody"
        );
        let proof = ConnectedInstance::connect_owned(vm_name, child.id())?.stop()?;
        proof.verify_current()?;
        child.wait()?;
        custody.outcome = FailedLaunchOutcome::ConfirmedRollback(proof);
        Ok(())
    }

    /// Borrow only the actual authenticated rollback outcome already held.
    pub fn confirmed_exit(&mut self) -> Option<&mvm_vmm::host::hvf_stop::ConfirmedExit> {
        match &self.custody_mut().outcome {
            FailedLaunchOutcome::ConfirmedRollback(proof) => Some(proof),
            FailedLaunchOutcome::NeverLaunched | FailedLaunchOutcome::Unconfirmed { .. } => None,
        }
    }
}

impl Drop for ColdHvfBootFailure {
    fn drop(&mut self) {
        if let Some(mut custody) = self.custody.take() {
            let state = custody
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(state.outcome, FailedLaunchOutcome::Unconfirmed { .. }) {
                std::mem::forget(custody);
            }
        }
    }
}

#[derive(PartialEq)]
enum ColdChannelState {
    Unopened,
    Authenticated,
    Uncertain,
    Stopped,
}

/// Opaque transport/generation custody, never workload admission. Only the
/// concrete fresh driver can construct this owner; attach cannot promote one.
#[must_use = "retain the native owner and session on stop uncertainty"]
pub struct ColdHvfOwner {
    custody: Option<ColdNativeCustody>,
}

/// Concrete cold-native resource custody, without admission or warm authority.
pub type RetainedHvfLaunch = ColdHvfOwner;

struct ColdNativeCustody {
    vm: HvfRunningVm,
    bridge: ColdBridge,
}

struct ColdBridge {
    state: ColdChannelState,
    stream: Option<std::os::unix::net::UnixStream>,
    session: Option<mvm_agentd::vsock::AuthenticatedSession>,
    first_guest_key: Option<ed25519_dalek::VerifyingKey>,
}

impl ColdBridge {
    const fn unopened() -> Self {
        Self {
            state: ColdChannelState::Unopened,
            stream: None,
            session: None,
            first_guest_key: None,
        }
    }
}

impl ColdHvfOwner {
    pub(super) fn from_fresh(vm: HvfRunningVm) -> Self {
        Self {
            custody: Some(ColdNativeCustody {
                vm,
                bridge: ColdBridge::unopened(),
            }),
        }
    }

    pub fn instance(&self) -> Result<&HvfInstance> {
        Ok(self.inner().owned()?.instance())
    }

    fn inner(&self) -> &ColdNativeCustody {
        self.custody
            .as_ref()
            .expect("native owner custody remains present")
    }

    fn inner_mut(&mut self) -> &mut ColdNativeCustody {
        self.custody
            .as_mut()
            .expect("native owner custody remains present")
    }

    pub fn id(&self) -> &VmId {
        &self.inner().vm.id
    }

    pub fn open(&mut self) -> Result<()> {
        self.inner_mut().open()
    }

    pub fn validate_live(&self) -> Result<()> {
        let custody = self.inner();
        anyhow::ensure!(
            custody.bridge.state == ColdChannelState::Authenticated,
            "native authenticated session is not usable"
        );
        custody.owned()?.validate_agent_bridge(
            custody
                .bridge
                .stream
                .as_ref()
                .context("retained native stream missing")?,
        )
    }

    pub fn call_unary(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
    ) -> Result<mvm_agentd::vsock::GuestResponse> {
        self.inner_mut().call_unary(request)
    }

    pub fn exec(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
        on_event: impl FnMut(&mvm_agentd::vsock::ExecEvent),
    ) -> Result<mvm_agentd::vsock::ExecEvent> {
        self.inner_mut().exec(request, on_event)
    }

    pub fn entrypoint(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
        on_event: impl FnMut(&mvm_agentd::vsock::EntrypointEvent),
    ) -> Result<mvm_agentd::vsock::EntrypointEvent> {
        self.inner_mut().entrypoint(request, on_event)
    }

    pub fn stop(&mut self) -> Result<()> {
        self.stop_confirmed().map(|_| ())
    }

    /// An actual terminal proof from the original retained instance.
    pub fn stop_confirmed(&mut self) -> Result<mvm_vmm::host::hvf_stop::ConfirmedExit> {
        self.inner_mut().stop_confirmed()
    }
}

impl Drop for ColdHvfOwner {
    fn drop(&mut self) {
        if let Some(custody) = self.custody.take()
            && custody.vm.owned.is_some()
            && custody.bridge.state != ColdChannelState::Stopped
        {
            // Abandonment is not exit proof or recovery. Keep the original
            // owner to retry; Drop must not discard its native/session handles.
            std::mem::forget(custody);
        }
    }
}

impl ColdNativeCustody {
    fn owned(&self) -> Result<&OwnedInstance> {
        self.vm
            .owned
            .as_ref()
            .context("reattached HVF handle has no original child")
    }

    /// The sole connection attempt. Even a failed handshake retains its stream
    /// and disables retry; there is no name-based reconnect path.
    pub fn open(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.bridge.state == ColdChannelState::Unopened,
            "cold HVF channel cannot reconnect"
        );
        self.bridge.state = ColdChannelState::Uncertain;
        self.vm
            .owned
            .as_ref()
            .context("reattached HVF handle has no original child")?
            .open_agent_bridge(&self.vm.agent_socket, &mut self.bridge.stream)
            .context("open the original native agent bridge")?;
        let ColdBridge {
            stream,
            session,
            first_guest_key,
            ..
        } = &mut self.bridge;
        let stream = stream.as_mut().context("native bridge missing")?;
        stream.set_read_timeout(Some(mvm_agentd::vsock::COLD_GUEST_AGENT_READY_BUDGET))?;
        stream.set_write_timeout(Some(mvm_agentd::vsock::COLD_GUEST_AGENT_READY_BUDGET))?;
        mvm_agentd::vsock::run_with_stream_deadline(
            stream,
            Instant::now()
                .checked_add(mvm_agentd::vsock::COLD_GUEST_AGENT_READY_BUDGET)
                .context("cold guest handshake deadline overflow")?,
            |stream| {
                let (authenticated, key) =
                    mvm_agentd::vsock::open_peer_authenticated_session(stream)?;
                // Store a completed handshake before the deadline helper's
                // final check: even a late completion must retain its first
                // real key and session on the uncertainty path.
                *session = Some(authenticated);
                *first_guest_key = Some(key);
                Ok(())
            },
        )
        .context("authenticate the guest on the original native bridge")?;
        self.owned()?.validate_agent_bridge(
            self.bridge
                .stream
                .as_ref()
                .context("native bridge missing")?,
        )?;
        self.bridge.state = ColdChannelState::Authenticated;
        Ok(())
    }

    fn begin_request(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.bridge.state == ColdChannelState::Authenticated,
            "cold HVF session is not usable"
        );
        self.bridge.state = ColdChannelState::Uncertain;
        self.bridge
            .first_guest_key
            .as_ref()
            .context("first authenticated guest key missing")?;
        self.owned()?.validate_agent_bridge(
            self.bridge
                .stream
                .as_ref()
                .context("native bridge missing")?,
        )
    }

    fn finish_request(&mut self) -> Result<()> {
        self.owned()?.validate_agent_bridge(
            self.bridge
                .stream
                .as_ref()
                .context("native bridge missing")?,
        )?;
        self.bridge.state = ColdChannelState::Authenticated;
        Ok(())
    }

    /// Protected activation or flush on the retained session; response
    /// contracts are checked before the caller can interpret an ACK.
    pub fn call_unary(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
    ) -> Result<mvm_agentd::vsock::GuestResponse> {
        use mvm_agentd::vsock::GuestRequest;
        anyhow::ensure!(
            matches!(
                request,
                GuestRequest::ActivateEnvironment(_) | GuestRequest::SyncFilesystems
            ),
            "cold HVF unary request outside activation/flush"
        );
        self.begin_request()?;
        let stream = self
            .bridge
            .stream
            .as_mut()
            .context("native bridge missing")?;
        let session = self
            .bridge
            .session
            .as_mut()
            .context("guest session missing")?;
        stream.set_read_timeout(None)?;
        let response = mvm_agentd::vsock::run_with_stream_deadline(
            stream,
            Instant::now()
                .checked_add(std::time::Duration::from_secs(30))
                .context("cold guest unary deadline overflow")?,
            |stream| {
                session.write(stream, request)?;
                Ok(mvm_agentd::vsock::check_response(
                    request,
                    session.read(stream)?,
                )?)
            },
        )?;
        self.finish_request()?;
        Ok(response)
    }

    pub fn exec(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
        on_event: impl FnMut(&mvm_agentd::vsock::ExecEvent),
    ) -> Result<mvm_agentd::vsock::ExecEvent> {
        let mvm_agentd::vsock::GuestRequest::Exec {
            timeout_secs: Some(seconds),
            ..
        } = request
        else {
            bail!("cold native Exec requires an explicit execution deadline");
        };
        anyhow::ensure!(*seconds > 0, "cold native Exec deadline must be positive");
        let budget = std::time::Duration::from_secs(*seconds)
            .checked_add(std::time::Duration::from_secs(5))
            .context("cold Exec deadline overflow")?;
        let deadline = Instant::now()
            .checked_add(budget)
            .context("cold Exec deadline overflow")?;
        self.begin_request()?;
        let stream = self
            .bridge
            .stream
            .as_mut()
            .context("native bridge missing")?;
        let session = self
            .bridge
            .session
            .as_mut()
            .context("guest session missing")?;
        stream.set_read_timeout(None)?;
        let result = mvm_agentd::vsock::run_with_stream_deadline(stream, deadline, |stream| {
            mvm_agentd::vsock::send_exec_on_authenticated_session(
                stream, session, request, on_event,
            )
        })?;
        self.finish_request()?;
        Ok(result)
    }

    fn entrypoint(
        &mut self,
        request: &mvm_agentd::vsock::GuestRequest,
        on_event: impl FnMut(&mvm_agentd::vsock::EntrypointEvent),
    ) -> Result<mvm_agentd::vsock::EntrypointEvent> {
        use mvm_agentd::vsock::GuestRequest;
        let seconds = match request {
            GuestRequest::RunEntrypoint {
                timeout_secs,
                stream_input: false,
                ..
            }
            | GuestRequest::AgentPrompt { timeout_secs, .. } => *timeout_secs,
            _ => bail!("cold native entrypoint requires a one-shot original entrypoint verb"),
        };
        anyhow::ensure!(seconds > 0, "cold entrypoint deadline must be positive");
        let budget = std::time::Duration::from_secs(seconds)
            .checked_add(std::time::Duration::from_secs(5))
            .context("cold entrypoint deadline overflow")?;
        let deadline = Instant::now()
            .checked_add(budget)
            .context("cold entrypoint deadline overflow")?;
        self.begin_request()?;
        let stream = self
            .bridge
            .stream
            .as_mut()
            .context("native bridge missing")?;
        let session = self
            .bridge
            .session
            .as_mut()
            .context("guest session missing")?;
        // One overall deadline closes the exact socket on expiry. No
        // timeout-and-continue can consume a partially read protected frame.
        stream.set_read_timeout(None)?;
        let terminal = mvm_agentd::vsock::run_with_stream_deadline(stream, deadline, |stream| {
            mvm_agentd::vsock::send_entrypoint_on_authenticated_session(
                stream, session, request, on_event,
            )
        })?;
        self.finish_request()?;
        Ok(terminal)
    }

    /// On any error all native, stream and key custody stays in `self`.
    fn stop_confirmed(&mut self) -> Result<mvm_vmm::host::hvf_stop::ConfirmedExit> {
        let proof = self.owned()?.stop()?;
        proof.verify_current()?;
        self.bridge.state = ColdChannelState::Stopped;
        self.bridge.stream = None;
        self.bridge.session = None;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{sample_paths, spec_with};
    use super::super::{KernelImage, PID_FILE_NAME, relay_supervisor_config};
    use super::*;
    use std::io::Read;

    #[test]
    fn prelaunch_failure_releases_support_and_survives_legacy_anyhow_boundary() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let failure = ColdHvfBootFailure {
            error: Some(anyhow::anyhow!("prelaunch refusal")),
            custody: Some(Box::new(std::sync::Mutex::new(FailedLaunchCustody {
                outcome: FailedLaunchOutcome::NeverLaunched,
                supporting: Vec::new(),
            }))),
        }
        .retain_support(Guard(Arc::clone(&drops)));
        let legacy = anyhow::Error::new(failure).context("legacy caller");
        let failure = legacy.downcast::<ColdHvfBootFailure>().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(failure.into_released_error().is_ok());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cold_config_refuses_restore_handoff_and_identity_free_parent() {
        let spec = spec_with(KernelImage::Path("/test-kernel".into()), vec![], vec![]);
        let paths = sample_paths();
        let mut config = relay_supervisor_config(&spec, &paths).unwrap();
        config.restore_ram = Some("/test-ram".into());
        assert!(
            require_cold_config(&config)
                .unwrap_err()
                .to_string()
                .contains("restore")
        );
        config.restore_ram = None;
        config.restore_frame = Some("/test-frame".into());
        assert!(
            require_cold_config(&config)
                .unwrap_err()
                .to_string()
                .contains("restore")
        );
        config.restore_frame = None;
        config.handoff_socket = Some("/test-handoff.sock".into());
        assert!(
            require_cold_config(&config)
                .unwrap_err()
                .to_string()
                .contains("handoff")
        );
        config.handoff_socket = None;
        config.cmdline = Some("init=/init".into());
        assert!(
            require_cold_config(&config)
                .unwrap_err()
                .to_string()
                .contains("factory-parent")
        );
        config.cmdline = Some(format!("init=/init mvm.hostname={}", config.vm_name));
        #[cfg(target_os = "macos")]
        assert!(require_cold_config(&config).is_ok());
    }

    #[test]
    fn attached_handle_refuses_cold_open_and_stop_without_losing_retained_stream() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let directory = tempfile::tempdir().unwrap();
        // Mirrors the actual attach representation, deliberately owned: None.
        // This is a refusal test, not a fabricated native positive witness.
        let mut owner = ColdHvfOwner {
            custody: Some(ColdNativeCustody {
                vm: HvfRunningVm {
                    id: VmId("attached-only".into()),
                    state_dir: directory.path().into(),
                    pid_file: directory.path().join(PID_FILE_NAME),
                    agent_socket: directory.path().join("absent-agent.sock"),
                    instance: HvfInstance {
                        vm_id: "attached-only".into(),
                        boot_nonce: [0; 32],
                    },
                    owned: None,
                },
                bridge: ColdBridge::unopened(),
            }),
        };
        assert!(
            owner
                .open()
                .unwrap_err()
                .to_string()
                .contains("original child")
        );
        assert!(owner.inner().bridge.state == ColdChannelState::Uncertain);
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let fd = stream.as_raw_fd();
        owner.inner_mut().bridge.stream = Some(stream);
        assert!(owner.stop().is_err());
        assert_eq!(
            owner.inner().bridge.stream.as_ref().unwrap().as_raw_fd(),
            fd
        );
        assert!(owner.inner().bridge.state == ColdChannelState::Uncertain);
        assert!(owner.open().unwrap_err().to_string().contains("reconnect"));
        drop(owner);
        // No native child existed in this refusal fixture, so ordinary RAII
        // must release its socket rather than conservatively abandoning it.
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
}
