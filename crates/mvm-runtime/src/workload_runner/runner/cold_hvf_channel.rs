//! Lower cold-native transport custody. This is deliberately not an admission
//! permit and cannot be promoted from an arbitrary running VM or public claim.

use super::*;
use mvm_agentd::vsock::{ExecEvent, GuestRequest, GuestResponse};
use mvm_backends::driver::hvf::{ColdHvfBootFailure, ColdHvfOwner, HvfDriver};

/// Legacy anyhow callers still carry the actual typed native failure. Add
/// their supporting guards before any outer caller can drop or format it.
pub(super) fn retain_boot_error(
    error: anyhow::Error,
    support: impl Send + 'static,
) -> anyhow::Error {
    match error.downcast::<ColdHvfBootFailure>() {
        Ok(failure) => anyhow::Error::new(failure.retain_support(support)),
        Err(error) => error,
    }
}

pub(super) fn standby_compatibility_error(error: anyhow::Error) -> StandbyError {
    match error.downcast::<StandbyError>() {
        Ok(error) => error,
        // Unconfirmed typed native custody is retained by its own Drop. This
        // old string-only compatibility return is not a recoverable owner.
        Err(error) => StandbyError::SpawnFailed(format!("{error:#}")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DispatchLane {
    Exec,
    Entrypoint,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CompletionBarrier {
    FilesystemsSynced,
    EntrypointTerminalNoWriteback,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Prepared,
    Activated,
    Dispatched(DispatchLane),
    Finalized(CompletionBarrier),
    Uncertain,
}

pub(super) struct ColdHvfPreparation {
    pub(super) launch: crate::kernel_custody::KernelBoundLaunch,
    pub(super) images: mvm_vmm::host::boot_images::FrozenBootImageBytes,
    pub(super) _lifecycle: crate::runtime_evidence::RuntimeLifecycleLease,
    pub(super) prepared: PreparedWorkloadBoot,
    pub(super) _broker: BrokerGuard,
    pub(super) streamer: Arc<dyn ConsoleStreamer>,
    pub(super) redaction: RedactionPolicy,
}

struct Custody {
    preparation: ColdHvfPreparation,
    native: Option<ColdHvfOwner>,
    failed_boot: Option<ColdHvfBootFailure>,
    native_exit: Option<mvm_vmm::host::hvf_stop::ConfirmedExit>,
    entrypoint_terminal: Option<mvm_agentd::vsock::EntrypointEvent>,
    phase: Phase,
    support: Vec<Box<dyn Send>>,
}

impl Custody {
    fn cleanup_pending(&self) -> Result<bool> {
        cleanup_evidence_pending(
            crate::kernel_custody::has_retained_kernel(&self.preparation._lifecycle),
            self.preparation
                .launch
                .config()
                .canonical_kernel
                .as_ref()
                .map(|kernel| path_entry_exists(kernel.generation_dir()))
                .unwrap_or(Ok(false)),
        )
    }

    fn rollback_cleanup_pending(&mut self) -> bool {
        self.failed_boot
            .as_mut()
            .and_then(ColdHvfBootFailure::confirmed_exit)
            .is_some()
            && cleanup_record_unresolved(self.cleanup_pending())
    }
}

/// Non-Clone, non-serializable lower owner. `activate` establishes the native
/// bridge, retains its guest key and requires its protected activation ACK.
/// Every operational error leaves all custody in this object for `stop`.
///
/// Dropping an uncertain live owner deliberately retains its owned resources
/// until process exit rather than reaping helpers or releasing runtime paths
/// under a potentially live native generation. Keep the owner to retry stop.
#[must_use = "keep cold native custody until authenticated stop succeeds"]
pub struct ColdHvfChannel {
    custody: Option<Custody>,
}

/// Owning runtime return, not a VM-id DTO or admission permit.
pub type OwnedRuntimeLaunch = ColdHvfChannel;

/// Actual original exit after a storage barrier and required kernel cleanup.
/// Neither a caller result nor a deserialized status can construct this.
pub struct NativeCompletion {
    _exit: mvm_vmm::host::hvf_stop::ConfirmedExit,
    _barrier: CompletionBarrier,
    terminal: mvm_agentd::vsock::EntrypointEvent,
}

impl NativeCompletion {
    pub fn terminal(&self) -> &mvm_agentd::vsock::EntrypointEvent {
        &self.terminal
    }
}

impl ColdHvfChannel {
    pub(super) fn new(preparation: ColdHvfPreparation) -> Self {
        Self {
            custody: Some(Custody {
                preparation,
                native: None,
                failed_boot: None,
                native_exit: None,
                entrypoint_terminal: None,
                phase: Phase::Prepared,
                support: Vec::new(),
            }),
        }
    }

    fn custody(&mut self) -> Result<&mut Custody> {
        self.custody
            .as_mut()
            .context("cold native owner already stopped")
    }

    /// Keep actual higher-layer resources with this native lifetime. This is
    /// storage only, never a transfer to the VMM or a grant of admission.
    pub fn retain_support(&mut self, support: impl Send + 'static) -> Result<()> {
        self.custody()?.support.push(Box::new(support));
        Ok(())
    }

    pub fn vm_id(&self) -> Result<&VmId> {
        self.custody
            .as_ref()
            .and_then(|custody| custody.native.as_ref())
            .map(ColdHvfOwner::id)
            .context("native instance not running")
    }

    pub fn config(&self) -> Result<&VmStartConfig> {
        self.custody
            .as_ref()
            .map(|custody| custody.preparation.launch.config())
            .context("runtime custody already released")
    }

    pub fn validate_live(&self) -> Result<()> {
        let custody = self
            .custody
            .as_ref()
            .context("runtime custody already released")?;
        anyhow::ensure!(
            matches!(
                custody.phase,
                Phase::Activated | Phase::Dispatched(_) | Phase::Finalized(_)
            ),
            "retained session has no completed activation ACK"
        );
        custody
            .native
            .as_ref()
            .context("original native instance missing")?
            .validate_live()
    }

    /// Consume only a preparation that never acquired native custody, or whose
    /// failed boot already retained an actual confirmed rollback outcome.
    /// A live/uncertain owner is returned intact; this performs no stop.
    pub fn release_if_child_free(mut self) -> std::result::Result<(), Box<Self>> {
        let Some(custody) = self.custody.as_mut() else {
            return Ok(());
        };
        let mut disposition = if custody.native.is_some() {
            Abandonment::MayOwnNativeChild
        } else if custody.rollback_cleanup_pending() {
            Abandonment::TerminalCleanupUnconfirmed
        } else {
            Abandonment::NoNativeChild
        };
        if matches!(disposition, Abandonment::NoNativeChild)
            && let Some(failure) = custody.failed_boot.take()
            && let Err(failure) = failure.into_released_error()
        {
            custody.failed_boot = Some(failure);
            disposition = Abandonment::MayOwnNativeChild;
        }
        if try_release_custody(&mut self.custody, disposition).is_err() {
            return Err(Box::new(self));
        }
        Ok(())
    }

    pub fn activate(&mut self) -> Result<()> {
        let custody = self.custody()?;
        anyhow::ensure!(
            custody.phase == Phase::Prepared,
            "cold activation cannot be retried"
        );
        custody.phase = Phase::Uncertain;
        let preparation = &mut custody.preparation;
        let config = preparation.launch.config();
        anyhow::ensure!(
            config.roothash.as_deref() == Some(preparation.images.root_hash()),
            "activation root hash differs from retained image facts"
        );
        project_frozen_image_selectors(
            &mut preparation.prepared.spec.cmdline,
            preparation.images.root_hash(),
        )?;
        preparation.launch.before_boot(&preparation.prepared.spec)?;
        let capture = ConsoleCapture {
            vm_name: &config.name,
            supervisor_owned: true,
            console_log: &preparation.prepared.socks.console_log,
            display_socket: preparation.prepared.socks.display.as_deref(),
            redaction: &preparation.redaction,
            retention: plan_stream_retention(config.plan_json.as_deref()),
        };
        let boot = console_boot::boot_while_starting_console(
            || {
                Ok(HvfDriver::new().boot_cold_owned_verified(
                    &preparation.prepared.spec,
                    preparation.launch.verified_kernel(),
                    Some(&preparation.images),
                ))
            },
            || preparation.streamer.start(&capture),
            || {},
        )?;
        match boot {
            Ok(native) => custody.native = Some(native),
            Err(failure) => {
                // Keep the real primary error and any actual rollback proof
                // for kernel cleanup. Neither is replaced by a text summary.
                custody.failed_boot = Some(failure);
                anyhow::bail!("cold native boot failed; original launch custody retained");
            }
        }
        let native = custody.native.as_mut().context("native owner missing")?;
        preparation.launch.observe_instance(native.instance()?)?;
        native.open()?;
        durability::wait_for_owned_activation(config)?;
        crate::microvm::activation::activate_cold_hvf(native, config)?;
        if let Some(mut trace) = preparation.prepared.trace.take() {
            trace.mark("owned_channel_activated");
            trace.write_to(&vm_state_dir(&config.name));
        }
        custody.phase = Phase::Activated;
        Ok(())
    }

    /// One Exec after the actual same-session activation ACK. This transport
    /// operation does not supply admission authority or bypass guest grants.
    pub fn exec(
        &mut self,
        command: &str,
        stdin: Option<String>,
        timeout_secs: Option<u64>,
        on_event: impl FnMut(&ExecEvent),
    ) -> Result<ExecEvent> {
        let custody = self.custody()?;
        anyhow::ensure!(
            custody.phase == Phase::Activated,
            "cold Exec requires activation ACK"
        );
        custody.phase = Phase::Uncertain;
        let request = GuestRequest::Exec {
            command: command.to_owned(),
            stdin,
            timeout_secs,
        };
        let terminal = custody
            .native
            .as_mut()
            .context("native owner missing")?
            .exec(&request, on_event)?;
        custody.phase = Phase::Dispatched(DispatchLane::Exec);
        Ok(terminal)
    }

    /// Exactly one original signed entrypoint verb, not an Exec substitution.
    /// This lower transport operation carries no admission authority.
    pub fn entrypoint(
        &mut self,
        request: &GuestRequest,
        on_event: impl FnMut(&mvm_agentd::vsock::EntrypointEvent),
    ) -> Result<mvm_agentd::vsock::EntrypointEvent> {
        let custody = self.custody()?;
        anyhow::ensure!(
            custody.phase == Phase::Activated,
            "entrypoint requires activation ACK"
        );
        anyhow::ensure!(
            matches!(
                request,
                GuestRequest::RunEntrypoint {
                    stream_input: false,
                    ..
                } | GuestRequest::AgentPrompt { .. }
            ),
            "entrypoint requires an original one-shot entrypoint request"
        );
        custody.phase = Phase::Uncertain;
        let terminal = custody
            .native
            .as_mut()
            .context("native owner missing")?
            .entrypoint(request, on_event)?;
        custody.entrypoint_terminal = Some(terminal.clone());
        custody.phase = Phase::Dispatched(DispatchLane::Entrypoint);
        Ok(terminal)
    }

    pub fn flush(&mut self) -> Result<()> {
        let custody = self.custody()?;
        anyhow::ensure!(
            matches!(custody.phase, Phase::Dispatched(_)),
            "cold flush requires a terminal dispatch"
        );
        custody.phase = Phase::Uncertain;
        let response = custody
            .native
            .as_mut()
            .context("native owner missing")?
            .call_unary(&GuestRequest::SyncFilesystems)?;
        anyhow::ensure!(
            matches!(response, GuestResponse::FilesystemsSynced),
            "guest flush not acknowledged"
        );
        custody.phase = Phase::Finalized(CompletionBarrier::FilesystemsSynced);
        Ok(())
    }

    /// Storage finalization only: no guest RPC and no admission authority.
    /// The original authenticated terminal follows every streamed frame on the
    /// retained session. Host capture flushing is not part of this proof.
    pub fn finalize_readonly_entrypoint(&mut self) -> Result<()> {
        let custody = self.custody()?;
        require_entrypoint_terminal(custody.phase, custody.entrypoint_terminal.as_ref())?;
        let preparation = &custody.preparation;
        let config = preparation.launch.config();
        require_no_writeback_substrate(config, &preparation.prepared.spec)?;
        anyhow::ensure!(
            config.roothash.as_deref() == Some(preparation.images.root_hash()),
            "entrypoint completion root hash differs from retained frozen image facts"
        );
        custody
            .native
            .as_ref()
            .context("original native owner missing")?
            .validate_live()?;
        custody.phase = Phase::Finalized(CompletionBarrier::EntrypointTerminalNoWriteback);
        Ok(())
    }

    /// The original owner supplies stop/exit/finalization proof. On error the
    /// native stream, session, first guest key and runtime lease remain held.
    pub fn stop(&mut self) -> Result<()> {
        self.stop_retaining_evidence().map(|_| ())
    }

    pub fn complete(&mut self) -> Result<NativeCompletion> {
        let custody = self
            .custody
            .as_ref()
            .context("native completion already consumed")?;
        let barrier = require_completion_barrier(custody.phase)?;
        anyhow::ensure!(custody.native.is_some(), "original native owner missing");
        let terminal = custody
            .entrypoint_terminal
            .clone()
            .context("native completion has no original entrypoint terminal")?;
        let proof = self
            .stop_retaining_evidence()?
            .context("native completion has no original exit proof")?;
        Ok(NativeCompletion {
            _exit: proof,
            _barrier: barrier,
            terminal,
        })
    }

    fn stop_retaining_evidence(
        &mut self,
    ) -> Result<Option<mvm_vmm::host::hvf_stop::ConfirmedExit>> {
        let Some(custody) = self.custody.as_mut() else {
            // Only a prior proven stop (or consumed child-free preparation)
            // removes this private aggregate. Never reconstruct an instance.
            return Ok(None);
        };
        if let Some(native) = custody.native.as_mut() {
            stop_original_once(&mut custody.native_exit, || native.stop_confirmed())?;
        }
        if let Some(failed) = custody.failed_boot.as_mut() {
            failed.retry_stop()?;
        }
        if crate::kernel_custody::has_retained_kernel(&custody.preparation._lifecycle)? {
            let proof = custody
                .native_exit
                .as_ref()
                .or_else(|| {
                    custody
                        .failed_boot
                        .as_mut()
                        .and_then(ColdHvfBootFailure::confirmed_exit)
                })
                .context("canonical kernel cleanup requires retained original exit proof")?;
            custody
                .preparation
                .launch
                .observe_instance(proof.instance())?;
            crate::kernel_custody::release_after_confirmed_exit(
                &custody.preparation._lifecycle,
                proof,
            )?;
        }
        anyhow::ensure!(
            !custody.cleanup_pending()?,
            "original canonical cleanup remains; retain exit proof and cleanup custody"
        );
        custody
            .preparation
            .streamer
            .stop(&custody.preparation.launch.config().name);
        let proof = custody.native_exit.take();
        // Only now may RAII guards reap supporting services and release the
        // lifecycle lease. No native stop is reconstructed from the VM name.
        release_terminal_custody(&mut self.custody);
        Ok(proof)
    }
}

fn require_entrypoint_terminal(
    phase: Phase,
    terminal: Option<&mvm_agentd::vsock::EntrypointEvent>,
) -> Result<()> {
    anyhow::ensure!(
        phase == Phase::Dispatched(DispatchLane::Entrypoint)
            && terminal.is_some_and(mvm_agentd::vsock::EntrypointEvent::is_terminal),
        "readonly entrypoint finalization requires the original authenticated entrypoint terminal"
    );
    Ok(())
}

fn require_completion_barrier(phase: Phase) -> Result<CompletionBarrier> {
    match phase {
        Phase::Finalized(barrier) => Ok(barrier),
        _ => anyhow::bail!("native completion requires a retained storage completion barrier"),
    }
}

fn require_no_writeback_substrate(
    config: &VmStartConfig,
    spec: &mvm_vmm::driver::spec::VmmSpec,
) -> Result<()> {
    require_unmounted_substrate(config, &spec.shares)?;
    require_readonly_blocks(config, &spec.blocks)
}

fn require_unmounted_substrate(
    config: &VmStartConfig,
    shares: &[mvm_vmm::driver::spec::VirtioFsShare],
) -> Result<()> {
    anyhow::ensure!(
        config.volumes.is_empty() && shares.is_empty(),
        "readonly entrypoint completion refuses volumes and host shares"
    );
    Ok(())
}

fn require_readonly_blocks(
    config: &VmStartConfig,
    blocks: &[mvm_vmm::driver::spec::BlockDev],
) -> Result<()> {
    anyhow::ensure!(
        blocks.iter().all(|block| block.read_only),
        "readonly entrypoint completion refuses writable blocks"
    );
    for (slot, source) in [
        (0, Some(config.rootfs_path.as_str())),
        (1, config.verity_path.as_deref()),
    ] {
        let source = source.context("readonly entrypoint completion requires root and verity")?;
        let mut matching = blocks.iter().filter(|block| block.slot == slot);
        anyhow::ensure!(
            matching.next().is_some_and(|block| {
                block.read_only && !block.ephemeral && block.source == std::path::Path::new(source)
            }) && matching.next().is_none(),
            "readonly entrypoint completion requires the original fixed readonly root and verity"
        );
    }
    Ok(())
}

/// Bind physical boot selectors to the held frozen images before spawning.
/// Conflicts and overflow leave the original command line unchanged.
fn project_frozen_image_selectors(cmdline: &mut String, root_hash: &str) -> Result<()> {
    let mut projected = cmdline.clone();
    for (key, expected) in [
        ("mvm.roothash", root_hash),
        ("mvm.data", "/dev/vda"),
        ("mvm.hash", "/dev/vdb"),
    ] {
        let mut values = cmdline
            .split_ascii_whitespace()
            .filter_map(|token| token.split_once('='))
            .filter_map(|(name, value)| (name == key).then_some(value));
        match (values.next(), values.next()) {
            (None, None) => {
                projected.push(' ');
                projected.push_str(key);
                projected.push('=');
                projected.push_str(expected);
            }
            (Some(value), None) if value == expected => {}
            _ => anyhow::bail!("physical boot image selector differs from original frozen images"),
        }
    }
    if let Some(error) = cmdline::cmdline_overflow(&projected) {
        anyhow::bail!("{error}");
    }
    *cmdline = projected;
    Ok(())
}

impl Drop for ColdHvfChannel {
    fn drop(&mut self) {
        if let Some(mut custody) = self.custody.take() {
            // An attempted start is not evidence that a child ever existed.
            // Only a genuine adopted owner or the typed, child-retaining boot
            // failure requires conservative abandonment.
            let abandonment = if custody.native.is_some() {
                Abandonment::MayOwnNativeChild
            } else if custody.rollback_cleanup_pending() {
                Abandonment::TerminalCleanupUnconfirmed
            } else if let Some(failure) = custody.failed_boot.take() {
                match failure.into_released_error() {
                    Ok(_) => Abandonment::NoNativeChild,
                    Err(failure) => {
                        custody.failed_boot = Some(failure);
                        Abandonment::MayOwnNativeChild
                    }
                }
            } else {
                Abandonment::NoNativeChild
            };
            abandon_custody(custody, abandonment);
        }
    }
}

/// This fallback prevents premature cleanup, not lossless recovery. Retrying
/// stop requires keeping the original owner; exiting the launcher is never
/// evidence that its detached native VM stopped.
enum Abandonment {
    NoNativeChild,
    MayOwnNativeChild,
    TerminalCleanupUnconfirmed,
}

fn abandon_custody<T>(custody: T, abandonment: Abandonment) {
    match abandonment {
        Abandonment::NoNativeChild => drop(custody),
        Abandonment::MayOwnNativeChild | Abandonment::TerminalCleanupUnconfirmed => {
            std::mem::forget(custody);
        }
    }
}

fn cleanup_record_unresolved(check: Result<bool>) -> bool {
    check.unwrap_or(true)
}

fn path_entry_exists(path: &std::path::Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_evidence_pending(index: Result<bool>, generation: Result<bool>) -> Result<bool> {
    // Neither absent index nor absent generation is an exit proof. These
    // observations only bound release AFTER the original proof is retained.
    Ok(index? || generation?)
}

fn stop_original_once<T>(exit: &mut Option<T>, stop: impl FnOnce() -> Result<T>) -> Result<()> {
    if exit.is_none() {
        *exit = Some(stop()?);
    }
    Ok(())
}

fn try_release_custody<T>(custody: &mut Option<T>, disposition: Abandonment) -> Result<(), ()> {
    match disposition {
        Abandonment::NoNativeChild => {
            release_terminal_custody(custody);
            Ok(())
        }
        Abandonment::MayOwnNativeChild | Abandonment::TerminalCleanupUnconfirmed => Err(()),
    }
}

// Called only after retained native stop proof (or when no native child ever
// existed). Taking the whole aggregate prevents double-release of its guards.
fn release_terminal_custody<T>(custody: &mut Option<T>) {
    drop(custody.take());
}

pub(super) fn require_cold_start_config(config: &VmStartConfig) -> Result<()> {
    anyhow::ensure!(
        config.warm_pool_size == 0,
        "cold HVF channel refuses warm launch configuration"
    );
    anyhow::ensure!(
        crate::microvm::booted_with_universal_initramfs(config),
        "cold HVF channel requires explicit universal-initramfs activation"
    );
    anyhow::ensure!(cfg!(target_os = "macos"), "cold HVF channel requires macOS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    #[test]
    fn readonly_entrypoint_requires_original_terminal_lane_and_storage_barrier() {
        let terminal = mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 };
        let output = mvm_agentd::vsock::EntrypointEvent::Stdout { chunk: vec![] };
        for phase in [
            Phase::Prepared,
            Phase::Activated,
            Phase::Dispatched(DispatchLane::Exec),
            Phase::Uncertain,
        ] {
            assert!(require_entrypoint_terminal(phase, Some(&terminal)).is_err());
            assert!(require_completion_barrier(phase).is_err());
        }
        let dispatched = Phase::Dispatched(DispatchLane::Entrypoint);
        assert!(require_entrypoint_terminal(dispatched, None).is_err());
        assert!(require_entrypoint_terminal(dispatched, Some(&output)).is_err());
        assert!(require_entrypoint_terminal(dispatched, Some(&terminal)).is_ok());
        assert!(require_completion_barrier(dispatched).is_err());
        for barrier in [
            CompletionBarrier::FilesystemsSynced,
            CompletionBarrier::EntrypointTerminalNoWriteback,
        ] {
            let phase = Phase::Finalized(barrier);
            assert_eq!(require_completion_barrier(phase).unwrap(), barrier);
            assert!(require_entrypoint_terminal(phase, Some(&terminal)).is_err());
        }
        let mut empty = ColdHvfChannel { custody: None };
        assert!(empty.complete().is_err());
        assert!(empty.finalize_readonly_entrypoint().is_err());
    }

    #[test]
    fn readonly_entrypoint_rejects_writable_or_replaced_physical_blocks() {
        use mvm_vmm::driver::spec::BlockDev;
        let config = VmStartConfig {
            rootfs_path: "/root.ext4".into(),
            verity_path: Some("/root.verity".into()),
            ..VmStartConfig::default()
        };
        let blocks = vec![
            BlockDev {
                source: "/root.ext4".into(),
                read_only: true,
                ephemeral: false,
                slot: 0,
            },
            BlockDev {
                source: "/root.verity".into(),
                read_only: true,
                ephemeral: false,
                slot: 1,
            },
        ];
        assert!(require_readonly_blocks(&config, &blocks).is_ok());
        for index in 0..2 {
            let mut changed = blocks.clone();
            changed[index].read_only = false;
            assert!(require_readonly_blocks(&config, &changed).is_err());
            let mut changed = blocks.clone();
            changed[index].ephemeral = true;
            assert!(require_readonly_blocks(&config, &changed).is_err());
            let mut changed = blocks.clone();
            changed[index].source = "/other".into();
            assert!(require_readonly_blocks(&config, &changed).is_err());
            let mut changed = blocks.clone();
            changed[index].slot = 2;
            assert!(require_readonly_blocks(&config, &changed).is_err());
        }
        let mut changed = blocks.clone();
        changed.push(BlockDev {
            source: "/volume".into(),
            read_only: false,
            ephemeral: true,
            slot: 2,
        });
        assert!(require_readonly_blocks(&config, &changed).is_err());
        assert!(require_readonly_blocks(&config, &blocks[..1]).is_err());
        let mut changed = blocks.clone();
        changed.push(blocks[0].clone());
        assert!(require_readonly_blocks(&config, &changed).is_err());
        let mut missing_verity = config.clone();
        missing_verity.verity_path = None;
        assert!(require_readonly_blocks(&missing_verity, &blocks).is_err());
    }

    #[test]
    fn readonly_entrypoint_rejects_config_volumes_and_even_readonly_host_shares() {
        let mut config = VmStartConfig::default();
        assert!(require_unmounted_substrate(&config, &[]).is_ok());
        let shares = [mvm_vmm::driver::spec::VirtioFsShare {
            tag: "host".into(),
            host_path: "/host".into(),
            read_only: true,
            dax: false,
        }];
        assert!(require_unmounted_substrate(&config, &shares).is_err());
        config.volumes.push(mvm_core::vm_backend::VmVolume {
            read_only: true,
            ..Default::default()
        });
        assert!(require_unmounted_substrate(&config, &[]).is_err());
    }

    #[test]
    fn frozen_physical_selectors_extend_without_overriding_claims() {
        let hash = "a".repeat(64);
        let original = "console=hvc0 mvm.hostname=image-selector-unit mvm.require_grant=1";
        let mut cmdline = original.to_owned();
        project_frozen_image_selectors(&mut cmdline, &hash).unwrap();
        assert!(cmdline.starts_with(original));
        assert!(cmdline.contains(&format!("mvm.roothash={hash}")));
        assert!(cmdline.contains("mvm.data=/dev/vda mvm.hash=/dev/vdb"));
        let projected = cmdline.clone();
        project_frozen_image_selectors(&mut cmdline, &hash).unwrap();
        assert_eq!(cmdline, projected);
        for suffix in [
            " mvm.roothash=wrong",
            " mvm.data=/dev/vdc",
            " mvm.hash=/dev/vda",
            " mvm.data=/dev/vda mvm.data=/dev/vda",
            " mvm.hash=/dev/vdb mvm.hash=/dev/vdb",
        ] {
            let mut cmdline = format!("{original}{suffix}");
            let held = cmdline.clone();
            assert!(project_frozen_image_selectors(&mut cmdline, &hash).is_err());
            assert_eq!(cmdline, held);
        }
        let mut overflow = "x".repeat(2047);
        let held = overflow.clone();
        assert!(project_frozen_image_selectors(&mut overflow, &hash).is_err());
        assert_eq!(overflow, held);
    }

    #[test]
    fn missing_index_with_remaining_generation_retains_release_and_drop_groups() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let index = directory.path().join("absent-index");
        let generation = directory.path().join("original-generation");
        std::fs::create_dir(&generation).unwrap();
        let pending = || {
            cleanup_record_unresolved(cleanup_evidence_pending(
                path_entry_exists(&index),
                path_entry_exists(&generation),
            ))
        };
        assert!(pending());
        let release_drops = Arc::new(AtomicUsize::new(0));
        let mut group = Some(Guard(Arc::clone(&release_drops)));
        assert!(try_release_custody(&mut group, Abandonment::TerminalCleanupUnconfirmed,).is_err());
        assert!(group.is_some());
        assert_eq!(release_drops.load(Ordering::SeqCst), 0);
        let abandon_drops = Arc::new(AtomicUsize::new(0));
        assert!(pending());
        abandon_custody(
            Guard(Arc::clone(&abandon_drops)),
            Abandonment::TerminalCleanupUnconfirmed,
        );
        assert_eq!(abandon_drops.load(Ordering::SeqCst), 0);
        assert!(generation.is_dir());
        assert!(!index.exists());
        // Same production release/Drop policy with real record mechanics,
        // not an instantiated ConfirmedRollback/ConfirmedExit or native VM.
        drop(group);
        assert_eq!(release_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exited_cleanup_retry_does_not_dispatch_stop_again_without_faking_exit() {
        let mut marker = None;
        let mut stops = 0;
        stop_original_once(&mut marker, || {
            stops += 1;
            Ok(())
        })
        .unwrap();
        let cleanup: Result<()> = Err(anyhow::anyhow!("local cleanup failure"));
        assert!(cleanup.is_err());
        stop_original_once(&mut marker, || -> Result<()> {
            panic!("cached outcome must prevent another stop")
        })
        .unwrap();
        assert_eq!(stops, 1);
        // Unit marker exercises actual cache policy, not native exit evidence.
        // NativeCompletion still requires the original opaque driver proof.
    }

    #[test]
    fn consuming_release_retains_original_group_for_pending_or_unreadable_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let record = directory.path().join("pending");
        std::fs::write(&record, b"pending native lifetime").unwrap();
        let checks = [
            std::fs::symlink_metadata(&record)
                .map(|_| true)
                .map_err(anyhow::Error::from),
            std::fs::symlink_metadata(record.join("not-a-directory"))
                .map(|_| true)
                .map_err(anyhow::Error::from),
        ];
        for check in checks {
            assert!(cleanup_record_unresolved(check));
            let (stream, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_millis(10)))
                .unwrap();
            let mut original = Some(stream);
            assert!(
                try_release_custody(&mut original, Abandonment::TerminalCleanupUnconfirmed,)
                    .is_err()
            );
            assert!(original.is_some());
            assert!(
                peer.read(&mut [0]).is_err(),
                "original stream must remain held"
            );
            // Policy only; no native exit proof is constructed. Production
            // consults the record only after borrowing the opaque proof.
            try_release_custody(&mut original, Abandonment::NoNativeChild).unwrap();
            assert!(original.is_none());
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn callback_stop_then_retry_accepts_private_empty_custody_without_native_proof() {
        // Pure empty-state coverage, not a fabricated ConfirmedExit. The
        // running production path empties custody only after original stop.
        let mut channel = ColdHvfChannel { custody: None };
        let rollback: Result<()> = channel.stop();
        rollback.unwrap();
        channel.stop().unwrap();
        assert!(channel.custody.is_none());
    }

    #[test]
    fn custody_drop_policy_releases_once_or_retains_without_fabricating_exit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct DropCounter(Arc<AtomicUsize>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let prechild = Arc::new(AtomicUsize::new(0));
        abandon_custody(
            DropCounter(Arc::clone(&prechild)),
            Abandonment::NoNativeChild,
        );
        assert_eq!(prechild.load(Ordering::SeqCst), 1);

        let terminal_release = Arc::new(AtomicUsize::new(0));
        let mut aggregate = Some(DropCounter(Arc::clone(&terminal_release)));
        // This tests release accounting only. Native proof is not fabricated;
        // the production call is reachable only after retained stop succeeds.
        release_terminal_custody(&mut aggregate);
        release_terminal_custody(&mut aggregate);
        assert_eq!(terminal_release.load(Ordering::SeqCst), 1);

        let uncertain = Arc::new(AtomicUsize::new(0));
        abandon_custody(
            DropCounter(Arc::clone(&uncertain)),
            Abandonment::MayOwnNativeChild,
        );
        assert_eq!(uncertain.load(Ordering::SeqCst), 0);

        let pending_cleanup = Arc::new(AtomicUsize::new(0));
        abandon_custody(
            DropCounter(Arc::clone(&pending_cleanup)),
            Abandonment::TerminalCleanupUnconfirmed,
        );
        assert_eq!(pending_cleanup.load(Ordering::SeqCst), 0);
        // Policy branch only: this does not construct a native exit proof.
    }

    #[test]
    fn prepared_drop_releases_real_socket_custody() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        abandon_custody(stream, Abandonment::NoNativeChild);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn uncertain_abandonment_keeps_socket_and_lock_guards_not_exit_proof() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("custody.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.lock().unwrap();
        let observer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        // The production fallback is tested with real OS resources, not a
        // fabricated native VM, OwnedInstance or activation witness.
        abandon_custody((file, stream), Abandonment::MayOwnNativeChild);
        assert!(observer.try_lock().is_err());
        let error = peer.read(&mut [0]).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn warm_configuration_is_rejected_before_any_native_boot() {
        let config = VmStartConfig {
            warm_pool_size: 1,
            ..VmStartConfig::default()
        };
        let error = require_cold_start_config(&config).unwrap_err();
        assert!(error.to_string().contains("warm launch"));
    }
}
