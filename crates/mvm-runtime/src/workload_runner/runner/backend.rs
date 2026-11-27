//! `VmBackend` and workload-role implementations for [`super::WorkloadRunner`].

use super::*;
use std::time::Instant;

/// A VM state directory belongs to a booted VM when it holds its console log or
/// the pid file its supervisor wrote. A machine whose console is not captured
/// (a named HVF machine) has only the pid file, and must still be listed.
fn has_vm_marker(state_dir: &std::path::Path) -> bool {
    state_dir.join("console.log").exists()
        || mvm_vmm::host::process_liveness::PID_FILE_NAMES
            .iter()
            .any(|name| state_dir.join(name).exists())
}

impl<S: NetworkEndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    WorkloadRunner<mvm_vmm::driver::hvf::HvfDriver, S, B>
{
    /// Preserve native launch failures and this exact runtime lease before any
    /// compatibility conversion to the string-only standby error.
    pub fn spawn_standby_captured_owned(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> Result<StandbyHandle> {
        self.spawn_standby_captured(ctx, spec).map_err(Into::into)
    }

    /// Prepare lower transport custody, not an admission capability. No native
    /// launch occurs until the returned owner's `activate` method is called.
    /// Client integration must still pair its original opaque admission.
    pub fn prepare_cold_hvf_channel(
        &self,
        config: &VmStartConfig,
        images: mvm_vmm::host::boot_images::FrozenBootImageBytes,
    ) -> Result<ColdHvfChannel> {
        self.prepare_cold_hvf_channel_verified(config, images, None)
    }

    /// Bind launch-owned release bytes before handing control to native HVF.
    pub fn prepare_cold_hvf_channel_verified(
        &self,
        config: &VmStartConfig,
        images: mvm_vmm::host::boot_images::FrozenBootImageBytes,
        release: Option<&mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    ) -> Result<ColdHvfChannel> {
        cold_hvf_channel::require_cold_start_config(config)?;
        anyhow::ensure!(
            config.roothash.as_deref() == Some(images.root_hash()),
            "original frozen root hash differs from the final config"
        );
        self.require_caller_registration_shape(config)?;
        let lifecycle = crate::runtime_evidence::RuntimeLifecycleLease::acquire(&config.name)?;
        let config = match release {
            Some(release) => lifecycle.bind_verified_release(config, release)?,
            None => lifecycle.bind(config)?,
        };
        let launch =
            crate::kernel_custody::KernelBoundLaunch::bind(config, self.driver.kind(), &lifecycle)?;
        let config = launch.config();
        cold_hvf_channel::require_cold_start_config(config)?;
        ClaimGuards::new(&self.spawner)
            .admit_overlay_contract(std::path::Path::new(&config.rootfs_path))?;
        refuse_rootfs_needing_journal_replay(&config.rootfs_path)?;
        let state_dir = vm_state_dir(&config.name);
        let decoded = decode_plan_secrets_from_state(&state_dir)?;
        let default_redaction = RedactionPolicy::default();
        let (secrets, redaction, tenant) = match &decoded {
            Some((secrets, redaction, tenant)) => (secrets.as_slice(), redaction, tenant.as_str()),
            None => (
                &[][..],
                &default_redaction,
                config.tenant_id.as_deref().unwrap_or("local"),
            ),
        };
        let inputs = WorkloadLaunchInputs {
            config,
            tenant,
            secrets,
            redaction,
            network_policy: &config.network_policy,
            cmdline: cmdline::runner_cmdline(config, &state_dir, |has_disk| {
                self.driver.workload_base_bootargs(has_disk)
            }),
        };
        let prepared = self.prepare_workload_boot(&inputs)?;
        let (broker, _) = self.register_workload_broker(config, &prepared.socks)?;
        Ok(ColdHvfChannel::new(cold_hvf_channel::ColdHvfPreparation {
            launch,
            images,
            _lifecycle: lifecycle,
            prepared,
            _broker: broker,
            streamer: Arc::clone(&self.console_streamer),
            redaction: redaction.clone(),
        }))
    }
}

/// Refuse a rootfs whose ext4 journal still needs replay, without touching it.
///
/// The rootfs is attached to the guest read-only, so the guest kernel cannot
/// replay a dirty journal and would fail the mount. The host must not replay it
/// either: the image was hashed when the launch was admitted and is shared by
/// every launch that names it (the cached default image, a template revision),
/// so repairing it here rewrites bytes the signed plan already recorded and
/// changes the shared image under every later launch. A dirty journal is a
/// defect in whatever produced the image, and it is reported as one before boot.
///
/// An image that cannot be read is left to the VMM, whose own open reports it.
fn refuse_rootfs_needing_journal_replay(rootfs_path: &str) -> Result<()> {
    use mvm_fs::ext4::journal_state::{JournalState, read_journal_state};

    if rootfs_path.is_empty() {
        return Ok(());
    }
    match read_journal_state(std::path::Path::new(rootfs_path)) {
        Ok(JournalState::NeedsRecovery) => anyhow::bail!(
            "refusing to boot {rootfs_path}: its ext4 journal needs replay, and the guest \
             mounts the rootfs from a read-only device. mvm does not repair an admitted \
             image in place; rebuild or re-fetch the image"
        ),
        Ok(JournalState::Clean | JournalState::NotExt4) => Ok(()),
        Err(e) => {
            tracing::debug!(error = %e, rootfs = %rootfs_path, "could not read the rootfs superblock");
            Ok(())
        }
    }
}

impl<D: VmmDriver + 'static, S: NetworkEndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    WorkloadRunner<D, S, B>
{
    /// Stop a VM and expose timings for each runner-owned teardown phase.
    pub fn stop_with_timing(&self, id: &VmId) -> Result<StopTiming> {
        self.terminate_with_timing(id, true, None)
    }

    /// Stop only the authenticated instance named by an automatic recovery request.
    pub fn stop_hvf_instance(
        &self,
        expected: &mvm_core::protocol::hvf_control::HvfInstance,
    ) -> Result<StopTiming> {
        self.terminate_with_timing(&VmId(expected.vm_id.clone()), true, Some(expected))
    }

    /// Abort a launch that never reached readiness, without asking the guest
    /// to flush or otherwise cooperate.
    pub fn abort_start_with_timing(&self, id: &VmId) -> Result<StopTiming> {
        self.terminate_with_timing(id, false, None)
    }

    fn terminate_with_timing(
        &self,
        id: &VmId,
        prepare_guest: bool,
        expected: Option<&mvm_core::protocol::hvf_control::HvfInstance>,
    ) -> Result<StopTiming> {
        mvm_core::naming::validate_vm_name(&id.0)?;
        let lifecycle = crate::runtime_evidence::RuntimeLifecycleLease::acquire(&id.0)?;
        // Measurement is diagnostic, never permission to terminate or delete.
        // Keep the lifecycle lease even if retention accounting fails.
        lifecycle.report_retained_best_effort();
        let total_started = Instant::now();
        let attach_started = Instant::now();
        let vm = match self.driver.attach(id) {
            Ok(vm) => vm,
            Err(err) => {
                if expected.is_none() {
                    self.console_streamer.stop(&id.0);
                }
                return Err(err);
            }
        };
        let attach = attach_started.elapsed();

        if let Some(expected) = expected {
            require_restart_instance(vm.as_ref(), expected)?;
        }

        let endpoint_started = Instant::now();
        let state_dir = vm_state_dir(&id.0);
        mvm_vmm::host::vm_helpers::reap_vm_host_helpers(&state_dir, &id.0);
        let endpoint_reaping = endpoint_started.elapsed();

        let kill_started = Instant::now();
        let kill_result = (|| {
            if prepare_guest {
                vm.prepare_stop()?;
            }
            vm.terminate_with_kernel_exit()
        })();
        let driver_detail = match &kill_result {
            Ok(detail) => detail.timing,
            Err(_) => None,
        };
        let driver_kill = kill_started.elapsed();

        let console_started = Instant::now();
        self.console_streamer.stop(&id.0);
        let console_cleanup = console_started.elapsed();
        let stopped = kill_result?;
        // The boot this record named has ended; a later boot of the same
        // machine must not inherit its unit.
        if let Err(e) = mvm_core::spawn_scope::clear_placement_owner(&state_dir) {
            tracing::warn!(vm = %id.0, error = %e, "clearing the placement owner after stop");
        }
        if crate::kernel_custody::has_retained_kernel(&lifecycle)? {
            #[cfg(unix)]
            {
                match stopped.hvf_exit.as_ref() {
                    Some(proof) => {
                        crate::kernel_custody::release_after_confirmed_exit(&lifecycle, proof)?
                    }
                    None => crate::kernel_custody::release_after_process_exit(&lifecycle)
                        .context("kernel generation retained: backend did not provide instance-bound exit evidence")?,
                }
            }
            #[cfg(not(unix))]
            anyhow::bail!("kernel generation retained: lifetime release unsupported");
        }
        lifecycle.release_installed_bundle_after_stop(&id.0)?;

        // A resident-handoff claim runs the child out of the consumed standby
        // parent's state dir. The handoff resumed the parent's own supervisor
        // process under the child name, so the HVF `ConfirmedExit` proof above
        // is also the parent's bounded confirmed exit: the parent dir's
        // descriptors are closed and both the dir and the pool record the claim
        // left behind can go. Best-effort — a cleanup failure never turns a
        // confirmed stop into a failure.
        #[cfg(unix)]
        warm_claim::cleanup_consumed_resident_parent(&state_dir, stopped.hvf_exit.is_some());

        // A preloaded-child claim adopted the pool's paused child and consumed
        // its standby parent. The adopted child is its own VMM process, so a
        // stop that reached this point already holds the driver's bounded
        // confirmed-exit evidence — for backends without an authenticated exit
        // proof (every preloading backend today), the successful terminate
        // above is that evidence. Remove what the claim left behind,
        // best-effort like the resident cleanup.
        #[cfg(unix)]
        warm_claim::cleanup_consumed_preloaded_parent(
            &state_dir,
            stopped.hvf_exit.is_some()
                || self.driver.kind() != mvm_core::vm_backend::BackendKind::Hvf,
        );

        let timing = StopTiming {
            attach,
            endpoint_reaping,
            driver_kill,
            console_cleanup,
            total: total_started.elapsed(),
            driver_detail,
        };
        // Callers that only want the stop (and `stop_transient`, which
        // reaches teardown through here) record one opaque total at most.
        // Logging the breakdown on every stop keeps the bulk of a teardown
        // attributable without asking each caller to carry the numbers.
        tracing::debug!(
            vm = %id.0,
            attach_ms = timing.attach.as_secs_f64() * 1000.0,
            endpoint_reaping_ms = timing.endpoint_reaping.as_secs_f64() * 1000.0,
            driver_kill_ms = timing.driver_kill.as_secs_f64() * 1000.0,
            console_cleanup_ms = timing.console_cleanup.as_secs_f64() * 1000.0,
            total_ms = timing.total.as_secs_f64() * 1000.0,
            "stop: teardown breakdown"
        );
        Ok(timing)
    }
}

fn require_restart_instance(
    vm: &dyn RunningVm,
    expected: &mvm_core::protocol::hvf_control::HvfInstance,
) -> Result<()> {
    #[cfg(unix)]
    {
        anyhow::ensure!(
            vm.authenticated_hvf_instance()?.as_ref() == Some(expected),
            "health restart cancelled: workload instance changed or cannot be authenticated"
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (vm, expected);
        anyhow::bail!("health restart cancelled: instance-bound control is unavailable")
    }
}

#[cfg(all(test, unix))]
mod restart_instance_tests {
    use super::*;
    use mvm_core::protocol::hvf_control::HvfInstance;

    struct IdentityOnlyVm {
        id: VmId,
        instance: Option<HvfInstance>,
    }

    impl RunningVm for IdentityOnlyVm {
        fn id(&self) -> &VmId {
            &self.id
        }
        fn authenticated_hvf_instance(&self) -> Result<Option<HvfInstance>> {
            Ok(self.instance.clone())
        }
        fn wait(&self) -> Result<VmExitStatus> {
            panic!("identity check must not wait")
        }
        fn kill(&self) -> Result<()> {
            panic!("identity check must not kill")
        }
        fn pause(&self) -> Result<()> {
            panic!("identity check must not pause")
        }
        fn resume(&self) -> Result<()> {
            panic!("identity check must not resume")
        }
        fn status(&self) -> Result<VmStatus> {
            panic!("status is not authenticated identity")
        }
        fn vsock_connect(&self, _: u32) -> Result<Box<dyn mvm_vmm::driver::DuplexStream>> {
            panic!("identity check must not enter the guest")
        }
    }

    #[test]
    fn conditional_stop_requires_the_entire_authenticated_instance_before_effects() {
        let expected = HvfInstance {
            vm_id: "health-vm".into(),
            boot_nonce: [1; 32],
        };
        for observed in [
            None,
            Some(HvfInstance {
                vm_id: "successor".into(),
                ..expected.clone()
            }),
            Some(HvfInstance {
                boot_nonce: [2; 32],
                ..expected.clone()
            }),
        ] {
            let vm = IdentityOnlyVm {
                id: VmId(expected.vm_id.clone()),
                instance: observed,
            };
            assert!(require_restart_instance(&vm, &expected).is_err());
        }
        let vm = IdentityOnlyVm {
            id: VmId(expected.vm_id.clone()),
            instance: Some(expected.clone()),
        };
        require_restart_instance(&vm, &expected).expect("same authenticated instance");
    }
}

/// The runner is the workload backend: lifecycle operations run through the
/// `VmmDriver` seam rather than being copied into each backend. State is
/// disk-backed under the per-VM `vm_state_dir`, so a stateless CLI invocation
/// reconstructs a handle by id.
impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Start through this concrete runner with original writable-image custody.
    pub fn start_custodied(
        &self,
        config: &VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    ) -> Result<VmId> {
        self.start_custodied_verified_release(config, images, None)
    }

    /// Transfer a launch's verified release bytes to the lifecycle binder.
    pub fn start_custodied_verified_release(
        &self,
        config: &VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        release: Option<&mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    ) -> Result<VmId> {
        self.start_retaining_vm(config, images, release)
            .map(|vm| vm.id().clone())
    }

    /// Keep the original native owner instead of reducing a successful launch to its name.
    pub(crate) fn start_retaining_vm(
        &self,
        config: &VmStartConfig,
        images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        release: Option<&mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    ) -> Result<Box<dyn RunningVm>> {
        let _activation_barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // A cold boot's rootfs *is* its image, so the gate reads the dir it
        // already boots from.
        ClaimGuards::new(&self.spawner)
            .admit_overlay_contract(std::path::Path::new(&config.rootfs_path))?;
        refuse_rootfs_needing_journal_replay(&config.rootfs_path)?;

        let default_redaction = RedactionPolicy::default();
        let decoded = decode_plan_secrets_from_state(&state_dir)?;
        let (secrets, redaction, tenant): (&[SecretBinding], &RedactionPolicy, &str) =
            match &decoded {
                Some((s, r, t)) => (s.as_slice(), r, t.as_str()),
                None => (
                    &[],
                    &default_redaction,
                    config.tenant_id.as_deref().unwrap_or("local"),
                ),
            };

        let cmdline = cmdline::runner_cmdline(config, &state_dir, |has_disk| {
            self.driver.workload_base_bootargs(has_disk)
        });
        if let Some(problem) = cmdline::cmdline_overflow(&cmdline) {
            anyhow::bail!("refusing to start VM {}: {problem}", config.name);
        }
        tracing::debug!(vm = %config.name, %cmdline, "assembled workload kernel cmdline");

        let inputs = WorkloadLaunchInputs {
            config,
            tenant,
            secrets,
            redaction,
            network_policy: &config.network_policy,
            cmdline,
        };
        self.start_workload_custodied_with_release(&inputs, images, release)
    }

    pub(super) fn start_workload_custodied_with_release(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
        release: Option<&mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    ) -> Result<Box<dyn RunningVm>> {
        self.require_caller_registration_shape(inputs.config)?;
        let lifecycle =
            crate::runtime_evidence::RuntimeLifecycleLease::acquire(&inputs.config.name)?;
        anyhow::ensure!(
            !crate::kernel_custody::has_retained_kernel(&lifecycle)?,
            "canonical kernel lifetime for this VM is still unresolved"
        );
        let bound_config = match release {
            Some(release) => lifecycle.bind_verified_release(inputs.config, release)?,
            None => lifecycle.bind(inputs.config)?,
        };
        let kernel_binding = crate::kernel_custody::KernelBoundLaunch::bind(
            bound_config,
            self.driver.kind(),
            &lifecycle,
        )?;
        let bound_config = kernel_binding.config();
        let bound_cmdline = if bound_config.runtime_release_proof.is_some()
            || bound_config.unsigned_runtime_development
        {
            cmdline::runner_cmdline(
                bound_config,
                &vm_state_dir(&bound_config.name),
                |has_disk| self.driver.workload_base_bootargs(has_disk),
            )
        } else {
            inputs.cmdline.clone()
        };
        let inputs = &WorkloadLaunchInputs {
            config: bound_config,
            tenant: inputs.tenant,
            secrets: inputs.secrets,
            redaction: inputs.redaction,
            network_policy: inputs.network_policy,
            cmdline: bound_cmdline,
        };
        let result =
            self.boot_bound_workload_guarded(inputs, Some(&kernel_binding), writable_images);
        result.map_err(|error| {
            cold_hvf_channel::retain_boot_error(error, (lifecycle, kernel_binding))
        })
    }
}

impl<D: VmmDriver + 'static, S: NetworkEndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    VmBackend for WorkloadRunner<D, S, B>
{
    fn name(&self) -> &str {
        self.driver.name()
    }

    fn kind(&self) -> BackendKind {
        self.driver.kind()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.driver.capabilities()
    }

    fn supports_resident_handoff(&self) -> bool {
        self.driver.supports_resident_handoff()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.driver.security_profile()
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.driver.guest_channel_info(id)
    }

    fn host_dial_route(&self, state_dir: &std::path::Path, port: u32) -> Option<HostDialRoute> {
        self.driver.host_dial_route(state_dir, port)
    }

    fn is_available(&self) -> Result<bool> {
        self.driver.is_available()
    }

    /// Report what actually bounded this VM, by reading the live control.
    ///
    /// Overridden for every workload backend, because the trait default answers
    /// `Declared` for everything — which on a genuinely bounded boot is a false
    /// statement about the run, and exactly the overstatement this seam exists
    /// to prevent. The tier comes from resolving the scope the VMM was born into
    /// and reading its `cpu.max`, never from the spawn having succeeded.
    ///
    /// The requested grants are deliberately unused: what was *asked for* is
    /// already on the signed plan, and deriving a tier from the request is how a
    /// report ends up describing an intention rather than a fact.
    fn apply_grants(
        &self,
        id: &VmId,
        _grants: &mvm_contract::grants::Grants,
    ) -> Result<mvm_contract::protocol::resource_controls::EnforcedGrants> {
        Ok(mvm_core::spawn_scope::enforced_grants_for_vm(
            &vm_state_dir(&id.0),
        ))
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        self.start_custodied(config, Vec::new())
    }

    fn host_process_id(&self, id: &VmId) -> Result<Option<u32>> {
        Ok(self.driver.attach(id)?.host_process_id())
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        self.driver.attach(id)?.wait()
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        self.stop_with_timing(id).map(|_| ())
    }

    fn abort_start(&self, id: &VmId) -> Result<()> {
        self.abort_start_with_timing(id).map(|_| ())
    }

    fn stop_all(&self) -> Result<()> {
        for vm in self.list()? {
            let _ = self.stop(&vm.id);
        }
        Ok(())
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        self.driver.attach(id)?.pause()
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        let _activation_barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
        self.driver.attach(id)?.resume()
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.driver.attach(id)?.status()
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        let log = vm_state_dir(&id.0).join("console.log");
        std::fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = vms_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("listing VM state in {}", root.display()))?;
            if !has_vm_marker(&entry.path()) {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 VM state entry in {}", root.display()))?;
            let id = VmId(name.clone());
            // A machine whose state cannot be probed is reported, never
            // presumed stopped and never allowed to hide the others. Callers
            // that need proof of quiescence refuse on a failed row.
            let status = self.status(&id).unwrap_or_else(|error| VmStatus::Failed {
                reason: format!("state unreadable: {error:#}"),
            });
            vms.push(VmInfo {
                id,
                name,
                status,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            });
        }
        Ok(vms)
    }

    fn install(&self) -> Result<()> {
        Ok(())
    }
}

impl<D: VmmDriver + 'static, S: NetworkEndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    WorkloadBackend for WorkloadRunner<D, S, B>
{
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        EgressSubstitutionTransport::VsockUdsChannel
    }
}

#[cfg(test)]
mod tests {
    use super::refuse_rootfs_needing_journal_replay;

    /// A formatted ext4 image, with the journal-recovery flag set on request.
    fn ext4_image(dir: &std::path::Path, needs_recovery: bool) -> String {
        let path = dir.join("rootfs.ext4");
        let mut image = std::fs::File::create_new(&path).unwrap();
        let size = 8 * 1024 * 1024;
        image.set_len(size).unwrap();
        mvm_fs::ext4::mkfs::format_empty_ext4(&mut image, size).unwrap();
        drop(image);
        if needs_recovery {
            let mut bytes = std::fs::read(&path).unwrap();
            // s_feature_incompat, EXT4_FEATURE_INCOMPAT_RECOVER.
            bytes[1024 + 0x60] |= 0x4;
            std::fs::write(&path, bytes).unwrap();
        }
        path.display().to_string()
    }

    #[test]
    fn a_clean_rootfs_is_admitted_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = ext4_image(dir.path(), false);
        let before = std::fs::read(&rootfs).unwrap();

        refuse_rootfs_needing_journal_replay(&rootfs).expect("a clean journal boots");

        assert_eq!(std::fs::read(&rootfs).unwrap(), before);
    }

    #[test]
    fn a_rootfs_needing_journal_replay_is_refused_by_name_and_left_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = ext4_image(dir.path(), true);
        let before = std::fs::read(&rootfs).unwrap();

        let err = refuse_rootfs_needing_journal_replay(&rootfs)
            .expect_err("a dirty journal cannot be mounted from a read-only device");

        let message = err.to_string();
        assert!(message.contains(&rootfs), "names the image: {message}");
        assert!(message.contains("journal needs replay"), "{message}");
        assert_eq!(
            std::fs::read(&rootfs).unwrap(),
            before,
            "the refusal must not repair the image it refuses"
        );
    }

    #[test]
    fn a_diskless_boot_or_an_unreadable_image_is_left_to_the_vmm() {
        refuse_rootfs_needing_journal_replay("").expect("an initramfs-only boot has no rootfs");
        refuse_rootfs_needing_journal_replay("/nonexistent/rootfs.ext4")
            .expect("the VMM's own open reports a missing image");
        let dir = tempfile::tempdir().unwrap();
        let not_ext4 = dir.path().join("rootfs.img");
        std::fs::write(&not_ext4, b"rootfs").unwrap();
        refuse_rootfs_needing_journal_replay(&not_ext4.display().to_string())
            .expect("a non-ext4 image carries no journal to replay");
    }
}
