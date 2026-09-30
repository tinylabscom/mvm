//! `VmBackend` and workload-role implementations for [`super::WorkloadRunner`].

use super::*;
use std::time::Instant;

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
        let total_started = Instant::now();
        let attach_started = Instant::now();
        let vm = match self.driver.attach(id) {
            Ok(vm) => vm,
            Err(err) => {
                self.console_streamer.stop(&id.0);
                return Err(err);
            }
        };
        let attach = attach_started.elapsed();

        let endpoint_started = Instant::now();
        let state_dir = vm_state_dir(&id.0);
        reap_network_endpoint(&state_dir, &id.0);
        mvm_vmm::host::gpu_endpoint_spawn::reap_gpu_endpoint(&state_dir);
        mvm_vmm::host::broker_services_spawn::reap_broker_services(&state_dir);
        mvm_vmm::host::host_agent_spawn::reap_host_agent_services_from_state(&state_dir, &id.0);
        let endpoint_reaping = endpoint_started.elapsed();

        let kill_started = Instant::now();
        let kill_result = vm.kill_with_timing();
        let driver_detail = match &kill_result {
            Ok(detail) => *detail,
            Err(_) => None,
        };
        let driver_kill = kill_started.elapsed();

        let console_started = Instant::now();
        self.console_streamer.stop(&id.0);
        let console_cleanup = console_started.elapsed();
        kill_result?;

        Ok(StopTiming {
            attach,
            endpoint_reaping,
            driver_kill,
            console_cleanup,
            total: total_started.elapsed(),
            driver_detail,
        })
    }
}

/// The runner is the workload backend: lifecycle operations run through the
/// `VmmDriver` seam rather than being copied into each backend. State is
/// disk-backed under the per-VM `vm_state_dir`, so a stateless CLI invocation
/// reconstructs a handle by id.
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
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // A cold boot's rootfs *is* its image, so the gate reads the dir it
        // already boots from.
        ClaimGuards::new(&self.spawner)
            .admit_overlay_contract(std::path::Path::new(&config.rootfs_path))?;
        refuse_rootfs_needing_journal_replay(&config.rootfs_path)?;
        crate::base::runtime_meta::record_from_start_config(
            &config.name,
            StartMode::Detached,
            config,
        )?;

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
        match self.start_workload(&inputs) {
            Ok(_vm) => Ok(VmId(config.name.clone())),
            Err(e) => Err(e),
        }
    }

    fn host_process_id(&self, id: &VmId) -> Result<Option<u32>> {
        Ok(self.driver.attach(id)?.host_process_id())
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        self.driver.attach(id)?.wait()
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let timing = self.stop_with_timing(id)?;
        // `stop_transient` reaches teardown through here, and the launch sample
        // records only the one opaque total for it. The breakdown is computed on
        // every stop regardless, so dropping it left the majority of a teardown
        // unattributable while the numbers already existed.
        tracing::debug!(
            vm = %id.0,
            attach_ms = timing.attach.as_secs_f64() * 1000.0,
            endpoint_reaping_ms = timing.endpoint_reaping.as_secs_f64() * 1000.0,
            driver_kill_ms = timing.driver_kill.as_secs_f64() * 1000.0,
            console_cleanup_ms = timing.console_cleanup.as_secs_f64() * 1000.0,
            total_ms = timing.total.as_secs_f64() * 1000.0,
            "stop: teardown breakdown"
        );
        Ok(())
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
        for entry in entries.flatten() {
            if !entry.path().join("console.log").exists() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let id = VmId(name.clone());
            let status = self.status(&id).unwrap_or(VmStatus::Stopped);
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
