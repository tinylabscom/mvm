//! Booting and tearing down the microVM an entrypoint call runs in.
//!
//! A transient call boots, dispatches once and tears down; a session boots
//! once and keeps the VM for many calls. Both boot here, and both boot only
//! under an admitted plan: the admission callback runs once the rootfs,
//! kernel and VM name are known, and its signed plan is what the backend
//! starts from, so the host spawns the substitution endpoint and the egress
//! gate for this VM before a byte of it runs.
//!
//! These boots take no host-directory shares. A session attaches whatever it
//! needs when it is created, never per call.

use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmId, VmStartConfig};
use mvm_runtime::AnyBackend;

use crate::launch::runtime_source::{
    PairArtifactSource, SdkSidecarAttachment, attach_runtime_overlay_if_cached_version,
    attach_universal_initramfs_if_cached,
};

/// A booted microVM, named so it can be dispatched into and torn down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionVm {
    /// The name the backend started it under.
    pub vm_name: String,
}

/// What an admitted plan contributes to a VM's start config so the backend
/// spawns the substitution endpoint (the guest never holds a raw secret).
///
/// Strings rather than typed plan values so the boot carries no admission
/// types of its own. **Do not log `plan_json`**: the signed envelope carries
/// secret bindings.
pub struct SessionAuditSubstrate {
    /// The tenant the plan was admitted under.
    pub tenant_id: String,
    /// The signed plan, serialized.
    pub plan_json: String,
    /// The tenant policy bundle the plan resolved, serialized, when it has one.
    pub bundle_json: Option<String>,
    /// Config-drive files the plan's guest boot config needs.
    pub config_files: Vec<mvm_core::vm_backend::VmFile>,
}

/// Admission callback: given what the boot resolved, produce the substrate the
/// admitted plan contributes, or `None` when the caller admits nothing.
///
/// The kernel rides along for the same reason the rootfs does. A plan that
/// names the image but not the kernel pins what the workload *is* and nothing
/// about what confines it, so the callback cannot bind the environment it was
/// admitted onto unless it is told which kernel that is.
pub type SessionAdmit<'a> = dyn Fn(AdmitInputs<'_>) -> Result<Option<SessionAuditSubstrate>> + 'a;

/// What the launch resolution has established by the time admission runs.
///
/// A struct rather than a positional list because every field is something the
/// resolution *discovered* — the rootfs it materialized, the kernel it chose,
/// the name it generated, the sidecar variant that rootfs turned out to need.
#[derive(Debug, Clone, Copy)]
pub struct AdmitInputs<'a> {
    /// The materialized rootfs the workload will boot.
    pub rootfs: &'a std::path::Path,
    /// The kernel confining it, when the tier has one.
    pub kernel: Option<&'a std::path::Path>,
    /// The name this VM will be started under.
    pub vm_name: &'a str,
    /// The SDK sidecar this boot will attach, or `None`.
    ///
    /// Resolved once, after the rootfs exists — the guest's own recorded libc
    /// decides which variant it is — and handed to both halves from here, so
    /// the plan grant and the attached volume cannot describe different bytes.
    pub sdk_sidecar: Option<&'a SdkSidecarAttachment>,
    /// Declared asset bindings forwarded to admission for content identity
    /// hashing.
    pub assets: &'a [crate::admission::AssetSpec],
    /// Every volume this boot will attach, as the launch config already
    /// resolved them.
    ///
    /// Admission turns these into the plan's host-fs grants, so the signed
    /// plan names the same shares the backend is about to mount. Without it a
    /// mount reaches the guest under a plan that never admitted it, and the
    /// admitted-share check has nothing to compare it against.
    pub volumes: &'a [mvm_core::vm_backend::VmVolume],
    /// The cached archive of the installed bundle `rootfs` and `kernel` were
    /// resolved from, or `None` when they did not come from one.
    ///
    /// Admission pins it into the signed plan and refuses the boot when the
    /// archive, or the extracted files beside it, no longer match what the
    /// publisher signed.
    pub bundle_archive: Option<&'a std::path::Path>,
}

/// Identity policy for a session-style VM boot.
#[derive(Debug, Clone, Copy)]
pub enum SessionVmName<'a> {
    /// Preserve a user-visible persistent machine identity exactly.
    Exact(&'a str),
    /// Generate an internal collision-resistant name under this prefix.
    Prefixed(&'a str),
}

impl SessionVmName<'_> {
    pub(crate) fn resolve(self) -> String {
        match self {
            Self::Exact(name) => name.to_string(),
            Self::Prefixed(prefix) => {
                format!("{prefix}-{}", mvm_core::naming::generate_machine_name())
            }
        }
    }
}

/// One session-style boot: which built workload, under what name, how big, and
/// on which backend.
pub struct SessionBoot<'a> {
    slot: &'a str,
    vm_name: SessionVmName<'a>,
    cpus: u32,
    memory_mib: u32,
    network_policy: mvm_core::network_policy::NetworkPolicy,
    backend_name: Option<&'a str>,
}

impl<'a> SessionBoot<'a> {
    /// A boot of `slot` under `vm_name`, one vCPU and 256 MiB, deny-all egress,
    /// on the host's default backend until told otherwise.
    #[must_use]
    pub fn builder(slot: &'a str, vm_name: SessionVmName<'a>) -> SessionBootBuilder<'a> {
        SessionBootBuilder(Self {
            slot,
            vm_name,
            cpus: 1,
            memory_mib: 256,
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            backend_name: None,
        })
    }
}

/// Builder for [`SessionBoot`].
pub struct SessionBootBuilder<'a>(SessionBoot<'a>);

impl<'a> SessionBootBuilder<'a> {
    /// vCPUs for the VM.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.0.cpus = cpus;
        self
    }

    /// Guest memory in MiB.
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.0.memory_mib = memory_mib;
        self
    }

    /// The egress policy the VM's start config carries.
    #[must_use]
    pub fn network_policy(mut self, policy: mvm_core::network_policy::NetworkPolicy) -> Self {
        self.0.network_policy = policy;
        self
    }

    /// The backend to boot on; the host's default when never called.
    #[must_use]
    pub fn backend_name(mut self, backend_name: &'a str) -> Self {
        self.0.backend_name = Some(backend_name);
        self
    }

    /// The finished boot description.
    #[must_use]
    pub fn build(self) -> SessionBoot<'a> {
        self.0
    }
}

/// Resolve the backend a boot runs on: the named hypervisor, refused when this
/// host cannot select it, or the host's default.
///
/// # Errors
/// A hypervisor name this host cannot select.
pub fn resolve_backend(hypervisor: Option<&str>) -> Result<AnyBackend> {
    match hypervisor {
        Some(name) => {
            AnyBackend::require_hypervisor_selectable(name)?;
            Ok(AnyBackend::from_hypervisor(name))
        }
        None => Ok(AnyBackend::auto_select()),
    }
}

/// Boot a session microVM from a built workload slot, under the plan `admit`
/// produces.
///
/// `admit` must admit: a callback that returns `None` is refused before the
/// backend is touched, because a VM these calls dispatch into is one whose
/// egress and secrets the host has to be able to enforce. That is also why
/// there is no snapshot-resume here — a restored VM skips the endpoint spawn
/// an admitted plan exists to drive.
///
/// `pair` is where the runtime overlay comes from when a local image checkout
/// is selected; a caller that offers none gets the cached or published
/// overlay.
///
/// # Errors
/// An unknown slot, an admission refusal, a missing runtime overlay, or a
/// backend that would not start.
pub fn boot_session_vm(
    boot: SessionBoot<'_>,
    admit: &SessionAdmit<'_>,
    pair: Option<&mut PairArtifactSource<'_>>,
) -> Result<SessionVm> {
    let SessionBoot {
        slot,
        vm_name,
        cpus,
        memory_mib,
        network_policy,
        backend_name,
    } = boot;
    let (spec, vmlinux, initrd, rootfs, rev) =
        mvm_runtime::vm::template::lifecycle::template_artifacts_for_boot(slot)
            .with_context(|| format!("Loading template '{slot}'"))?;
    let bundle_archive = mvm_runtime::vm::template::lifecycle::installed_bundle_archive(slot)?;
    let backend = resolve_backend(backend_name)?;
    let vm_name = vm_name.resolve();
    let (verity_path, roothash) = mvm_runtime::microvm::probe_verity_sidecar(&rootfs);

    let mut start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs.clone(),
        kernel_path: Some(vmlinux),
        initrd_path: initrd,
        verity_path,
        roothash,
        revision_hash: rev,
        flake_ref: spec.flake_ref,
        profile: Some(spec.profile),
        cpus,
        memory_mib,
        // Session VMs are short-lived boots; balloon elasticity isn't useful
        // here, so leave commit at boot.
        mem_initial_mib: None,
        ports: vec![],
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        runner_dir: None,
        network_policy,
        ..Default::default()
    };

    // The runtime overlay is the single source of the guest agent and its
    // helpers here, as on the transient path; a missing required overlay is
    // built or acquired, never replaced by a copy baked into the rootfs.
    attach_runtime_overlay_if_cached_version(&mut start_config, backend.name(), None, pair)?;
    attach_universal_initramfs_if_cached(&mut start_config, backend.name())?;

    // Admission starts the plan and verb-grant validity windows. All boot
    // preparation therefore completes before this point, immediately before
    // the backend consumes the admitted start config.
    let substrate = admit(AdmitInputs {
        rootfs: std::path::Path::new(&rootfs),
        kernel: start_config
            .kernel_path
            .as_deref()
            .map(std::path::Path::new),
        vm_name: &vm_name,
        // An entrypoint VM binds no SDK host service.
        sdk_sidecar: None,
        // The function payload is admitted as the workload itself; there are
        // no standalone assets.
        assets: &[],
        volumes: &start_config.volumes,
        bundle_archive: bundle_archive.as_deref(),
    })?
    .context("refusing to boot an entrypoint VM without an admitted plan")?;
    start_config.tenant_id = Some(substrate.tenant_id);
    start_config.plan_json = Some(substrate.plan_json);
    start_config.bundle_json = substrate.bundle_json;
    start_config.config_files.extend(substrate.config_files);
    if mvm_runtime::catalog::descriptor(backend.kind()).is_workload {
        mvm_hostd::plan_admission::stash_plan_for_bridge(&start_config)
            .context("persisting admitted session plan before backend start")?;
    }

    tracing::info!(vm = %vm_name, slot, "booting session VM");
    let vm_id = backend
        .start(&start_config)
        .with_context(|| format!("starting session microVM '{vm_name}'"))?;
    // The budget gate this boot admitted under counts only what is recorded:
    // a session boot that skipped the charge would be invisible to every
    // later admission the way a CLI boot on the old tail was. Fatal, not
    // logged — a VM running without its charge recorded is the undercount
    // the budget exists to prevent, so the boot stops rather than stay up
    // uncounted. Session plans declare no resource grants, so the charge is
    // the configured memory and no CPU millicores.
    let charge = mvm_hostd::admission_budget::charge_for(
        u64::from(memory_mib),
        &mvm_contract::grants::Grants::default(),
    );
    if let Err(err) = mvm_hostd::admission_budget::record_charge(&vm_name, charge) {
        if let Err(stop_err) = backend.stop(&vm_id) {
            tracing::warn!(
                error = %stop_err,
                "stopping a session VM whose admitted charge could not be recorded;                  it may still be running",
            );
        }
        return Err(err).context("recording the session boot's admitted charge");
    }
    Ok(SessionVm { vm_name })
}

/// Tear down a session VM. Best-effort: a failure (already stopped, backend
/// mismatch) is logged rather than returned, because the reaper calls this
/// where nobody is waiting for an error.
pub fn tear_down_session_vm(vm: SessionVm) {
    if let Err(e) = stop_session_vm(&vm) {
        tracing::warn!(vm = %vm.vm_name, err = %e, "session VM teardown failed");
    }
}

/// Stop a session VM, reporting whether the stop took. A caller that records
/// the end of the VM's session needs to know: a VM that may still be running
/// is not one whose session can be sealed.
///
/// # Errors
/// The backend refused or failed the stop.
pub(crate) fn stop_session_vm(vm: &SessionVm) -> Result<()> {
    // The marker in the VM's state dir names the backend that actually
    // launched it. Falling back to the host default would send the stop to
    // the wrong VMM and leave the guest running.
    let backend = AnyBackend::for_started_vm(&vm.vm_name).unwrap_or_else(AnyBackend::auto_select);
    backend.stop(&VmId(vm.vm_name.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exact_session_vm_name_is_not_rewritten() {
        assert_eq!(SessionVmName::Exact("named-agent").resolve(), "named-agent");
    }

    #[test]
    fn a_prefixed_session_vm_name_keeps_its_prefix_and_differs_each_time() {
        let first = SessionVmName::Prefixed("invoke").resolve();
        let second = SessionVmName::Prefixed("invoke").resolve();
        assert!(first.starts_with("invoke-"), "{first}");
        assert_ne!(first, second, "a generated name must not repeat");
    }

    #[test]
    fn the_boot_builder_carries_every_setting() {
        let boot = SessionBoot::builder("slot", SessionVmName::Exact("vm"))
            .cpus(4)
            .memory_mib(1024)
            .backend_name("mock")
            .build();
        assert_eq!((boot.cpus, boot.memory_mib), (4, 1024));
        assert_eq!(boot.backend_name, Some("mock"));
        assert_eq!(
            boot.network_policy,
            mvm_core::network_policy::NetworkPolicy::deny_all()
        );
    }

    #[test]
    fn an_unselectable_hypervisor_is_refused() {
        assert!(resolve_backend(Some("docker")).is_err());
    }

    #[test]
    fn an_unknown_slot_is_refused_before_admission_runs() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        let admit = |_: AdmitInputs<'_>| -> Result<Option<SessionAuditSubstrate>> {
            panic!("admission must not run for a slot that does not exist")
        };
        let slot = "0".repeat(64);
        let error = boot_session_vm(
            SessionBoot::builder(&slot, SessionVmName::Prefixed("t")).build(),
            &admit,
            None,
        )
        .expect_err("an unknown slot has nothing to boot");
        assert!(
            format!("{error:#}").contains("Loading template"),
            "{error:#}"
        );
    }
}
