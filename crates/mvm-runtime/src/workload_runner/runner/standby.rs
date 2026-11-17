//! Standby creation: boot a factory parent, capture it, and release it.

use super::*;

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Boot a standby parent, capture its whole live state, and release it.
    ///
    /// The parent's boot inputs are derived here, from the launch it will
    /// serve, through the same mappers `start_workload` uses — a factory parent
    /// boots the device model and boot-shape cmdline a workload boots, minus
    /// the claim-time hostname and host channels a workload is entitled to and
    /// it is not. That is not a
    /// nicety: a child is restored out of the parent's saved memory and
    /// inherits both, so a parent assembled by a second recipe hands every
    /// child whatever that recipe got wrong.
    ///
    /// The driver boots those inputs and supplies the backend-specific control;
    /// capturing a live VM's memory is backend-agnostic, so it lives here rather
    /// than in any one driver. The captured checkpoint is what a later claim
    /// verifies content and lineage against.
    ///
    /// A factory parent gets no substitution endpoint and no broker: those are
    /// workload-only steps (`ClaimGuards::spawn_endpoint`, `BrokerRegistrar`,
    /// both reached from `start_workload` and neither reachable from here), and
    /// [`factory_parent_config`] drops every field that could carry workload
    /// authority into the parent's launch config in the first place.
    pub fn spawn_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError>
    where
        D: 'static,
    {
        let _activation_barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()
                .map_err(|error| StandbyError::SpawnFailed(format!("{error:#}")))?;
        let launch = ctx.launch.ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no launch config to mirror: a warm parent boots the same \
                 device model and boot-shape kernel cmdline a workload does, so it cannot be assembled \
                 without the launch it will serve",
                spec.id
            ))
        })?;
        let started = Instant::now();
        let parent_config = factory_parent_config(launch, spec)?;
        let lifecycle = crate::runtime_evidence::RuntimeLifecycleLease::acquire(&spec.id)
            .map_err(|e| StandbyError::SpawnFailed(format!("lock runtime lifecycle: {e:#}")))?;
        warm_claim::record_standby_phase(started, "lease", "acquired");
        let parent_config = lifecycle.bind(&parent_config).map_err(|e| {
            StandbyError::SpawnFailed(format!("bind standby runtime artifacts: {e:#}"))
        })?;
        warm_claim::record_standby_phase(started, "lease", "bound");
        let result = match (&self.driver as &dyn std::any::Any)
            .downcast_ref::<mvm_backends::driver::hvf::HvfDriver>()
        {
            Some(driver) => {
                self.spawn_bound_standby_captured_using(ctx, spec, &parent_config, |request| {
                    driver.spawn_standby_parent_owned(request)
                })
            }
            None => self
                .spawn_bound_standby_captured(ctx, spec, &parent_config)
                .map_err(anyhow::Error::new),
        };
        result.map_err(|error| {
            cold_hvf_channel::standby_compatibility_error(cold_hvf_channel::retain_boot_error(
                error,
                (lifecycle, parent_config),
            ))
        })
    }

    /// Maps an already-bound parent while its caller holds the lifecycle lease.
    pub(super) fn spawn_bound_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
        parent_config: &VmStartConfig,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        self.spawn_bound_standby_captured_using(ctx, spec, parent_config, |request| {
            self.driver
                .spawn_standby_parent(request)
                .map_err(anyhow::Error::new)
        })
        .map_err(cold_hvf_channel::standby_compatibility_error)
    }

    fn spawn_bound_standby_captured_using(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
        parent_config: &VmStartConfig,
        launch: impl FnOnce(&StandbyParentSpawn<'_>) -> Result<StandbyHandle>,
    ) -> Result<StandbyHandle> {
        let started = Instant::now();
        let state_dir = PathBuf::from(&spec.vm_state_dir);

        // Written before boot, exactly as `start` does for a workload, so a
        // capture against this parent resolves its rootfs and boot contract the
        // same way every runner-launched VM's does.
        crate::base::runtime_meta::record_from_start_config(
            &spec.id,
            StartMode::Detached,
            parent_config,
        )
        .map_err(|e| {
            StandbyError::SpawnFailed(format!(
                "recording standby parent '{}' runtime metadata: {e:#}",
                spec.id
            ))
        })?;

        let slots = self.driver.late_volume_slots();
        mvm_vmm::host::late_volumes::ensure_placeholders(&state_dir, slots).map_err(|e| {
            StandbyError::SpawnFailed(format!(
                "creating standby '{}' late-volume placeholders: {e:#}",
                spec.id
            ))
        })?;
        let mut boot = slotted_factory_parent_spec(
            parent_config,
            &state_dir,
            |has_disk| self.driver.workload_base_bootargs(has_disk),
            slots,
        );
        let identity = spawner::prepare_standby_identity(&self.spawner, spec)?;
        spawner::assert_standby_telemetry(&state_dir, &mut boot.cmdline);
        // The same truncation refusal a workload boot gets, for the same reason
        // and then some: a child inherits its parent's cmdline out of restored
        // memory rather than deriving its own, so a parent whose trailing tokens
        // the kernel silently dropped hands that loss to every child it produces.
        if let Some(problem) = cmdline::cmdline_overflow(&boot.cmdline) {
            return Err(StandbyError::SpawnFailed(format!(
                "refusing to boot standby parent '{}': {problem}",
                spec.id
            ))
            .into());
        }
        let boot = mvm_vmm::host::spec_map::with_identity_drive(boot, identity.as_deref());
        warm_claim::record_standby_phase(started, "boot", "spec_ready");
        let mut handle = launch(&StandbyParentSpawn { spec, boot: &boot })?;
        warm_claim::record_standby_phase(started, "boot", "parent_booted");

        // The universal initramfs waits in a fail-closed pre-activation state.
        // Capturing it there would make every restored child refuse PostRestore
        // and fall back to a cold boot. The parent shares only its rootfs device
        // and verity environment; factory_parent_config has already removed all
        // workload identity, secrets, plan, and grant authority.
        if crate::microvm::booted_with_universal_initramfs(parent_config) {
            let parent = self.driver.attach(&VmId(spec.id.clone())).map_err(|e| {
                StandbyError::SpawnFailed(format!(
                    "attach standby parent '{}' for activation: {e:#}",
                    spec.id
                ))
            })?;
            crate::microvm::activate_workload(parent.as_ref(), parent_config).map_err(|e| {
                StandbyError::SpawnFailed(format!(
                    "activate standby parent '{}' before capture: {e:#}",
                    spec.id
                ))
            })?;
        }
        warm_claim::record_standby_phase(started, "boot", "parent_activated");

        let control = self.driver.vm_full_control(&spec.id).ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "backend cannot capture a warm parent's memory for standby '{}'",
                spec.id
            ))
        })?;
        let retain_parent = control.retain_paused_after_capture();
        let snapshots = FsSnapshotStore::new(mvm_core::config::snapshots_dir())
            .map_err(|e| StandbyError::SpawnFailed(format!("open snapshot store: {e:#}")))?;

        let capture_params = CaptureVmFullParams {
            id: CheckpointId::new(format!("standby-{}", spec.id)),
            vm_name: spec.id.clone(),
            supervisor_config_digest: String::new(),
            runtime_overlay_version: None,
            runtime_launch_binding: crate::base::runtime_meta::read(&spec.id)
                .map_err(|e| {
                    StandbyError::SpawnFailed(format!("read bound standby runtime metadata: {e:#}"))
                })?
                .and_then(|meta| meta.runtime_launch_binding),
            // Firecracker keeps no supervisor-config blob; its presence is
            // what marks a checkpoint as originating from a backend that does.
            supervisor_config_src: control.supervisor_config_path().map_err(|e| {
                StandbyError::SpawnFailed(format!("resolve standby supervisor config: {e:#}"))
            })?,
            tag: None,
            created_unix: mvm_core::time::now_unix_secs(),
            retain_paused: true,
            // A decision, not an omission. A factory parent holds no plan and
            // no tenant by construction — `factory_parent_config` drops
            // `plan_json` and `cpu_grant` precisely so a parent cannot carry a
            // grant admitted for some other workload, and one parent serves
            // every later claim against this pool. Sealing the mirrored
            // launch's grant here would bind all of them to whichever workload
            // happened to provision the pool.
            //
            // Sealing nothing is not the same as checking nothing: the claim
            // path still compares, and an absent parent grant is deny-all
            // egress, so a claimed child asking to reach anywhere is refused.
            // It leaves CPU and wall clock unbounded by the *parent*; those are
            // bounded for a warm child by the host ceiling its own plan was
            // admitted against, never by this record.
            grants: None,
            // A factory parent has no workspace: it is booted before any
            // workload, with no user volume attached.
            parent: None,
            session: None,
            workspace_volumes: Vec::new(),
            key_domain: mvm_core::checkpoint::CheckpointKeyDomain::host(),
        };
        let trusted_backend = if cfg!(all(feature = "trusted-apfs", target_os = "macos"))
            && trusted_snapshot_opted_in(
                std::env::var("MVM_HVF_ENABLE_TRUSTED_SNAPSHOT")
                    .ok()
                    .as_deref(),
            ) {
            Some(
                mvm_fs::trusted_snapshot::platform_backend(snapshots.root()).map_err(|e| {
                    StandbyError::SpawnFailed(format!("open trusted snapshot backend: {e:#}"))
                })?,
            )
        } else {
            None
        };
        let captured = if let Some(backend) = trusted_backend.as_deref() {
            capture_vm_full_to_trusted_snapshot_backend(
                ctx.checkpoints,
                capture_params,
                control.as_ref(),
                backend,
            )
        } else {
            capture_vm_full_into_snapshot_store(
                ctx.checkpoints,
                capture_params,
                control.as_ref(),
                &snapshots,
            )
        };

        warm_claim::record_standby_phase(started, "capture", "captured");

        // Saved-state backends release the source after capture because the
        // checkpoint is their claim resource. The HVF live-handoff backend
        // deliberately retains its paused supervisor: the checkpoint is an
        // integrity witness, while the resident parent remains the sole owner
        // of the HVF machine and its interrupt-controller state. A failed
        // capture never leaves that source resident.
        if captured.is_err() || !retain_parent {
            self.force_stop(&spec.id, "captured standby parent");
        }

        warm_claim::record_standby_phase(started, "capture", "source_released");
        let meta = captured
            .map_err(|e| StandbyError::SpawnFailed(format!("capture standby parent: {e:#}")))?;

        // Saved-state backends have no live process after capture and use pid=0
        // as their persisted sentinel. A retained HVF parent keeps its real pid
        // so claims can verify and address the resident supervisor.
        if !retain_parent {
            handle.pid = 0;
        }
        handle.parent_checkpoint = Some(meta.id.as_str().to_string());
        Ok(handle)
    }

    /// Force-stop a VM the warm-pool path is done with, naming its `role` for the
    /// log. Failure is logged, never propagated: the callers are already on their
    /// way out (a captured parent, a refused child) and have nothing better to do
    /// about it, but a VM that outlives its owner must stay visible.
    pub(super) fn force_stop(&self, vm_name: &str, role: &str) {
        let _ = self.checked_force_stop(vm_name, role);
    }

    /// Stop a warm-pool VM without treating an unavailable handle as confirmed exit.
    pub(super) fn checked_force_stop(&self, vm_name: &str, role: &str) -> Result<()> {
        let id = VmId(vm_name.to_string());
        self.driver
            .attach(&id)
            .and_then(|vm| vm.kill())
            .inspect_err(|e| {
                tracing::warn!(
                    vm = vm_name,
                    role,
                    error = %e,
                    "stopping a warm-pool VM failed; it may still be running"
                );
            })
    }
}
