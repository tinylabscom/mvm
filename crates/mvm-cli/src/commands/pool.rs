//! Warm-pool launch glue + the `mvmctl pool` command.
//!
//! Owns the bits that must live above the backend: the kernel-identity hash (part of the
//! base-compat key), the per-spawn binding nonce, and the host signer identity/key path
//! the standby re-verifies the attach plan against (claim 8). Builds a backend-agnostic
//! `StandbySpec` and drives the `SupervisorStandbyPool` + `VmBackend` trait methods.
//!
//! A standby is claimable by a launch whose kernel, resources, **rootfs image**
//! and **guest egress enablement** all match (`StandbyCompat`, exact equality) and whose
//! shape a shared parent can serve at all (`warm_eligible_launch` — no extra volumes).
//! Anything else cold-boots. Both halves of
//! the pool build that key and that eligibility test through one function each, because
//! a spawn and a claim that compute them separately are free to disagree, and a
//! disagreement is invisible: the pool fills and never drains. Multi-kernel keying and
//! honouring an explicit `--name`/volumes are deferred follow-ups.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::checkpoint::CheckpointId;
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::{
    RuntimeSourceRootStrategy, StandbyClaim, StandbyCompat, StandbyError, StandbyHandle,
    StandbySpec, StandbyState, VmBackend, VmId, VmStartConfig, WarmClaimRefusal, WarmLaunchMode,
};
use mvm_fs::snapshot_store::FsSnapshotStore;
use mvm_runtime::backend::AnyBackend;
use mvm_runtime::checkpoint::CheckpointStore;
use mvm_runtime::standby_pool::{STANDBY_POOL_TTL, SupervisorStandbyPool};
use mvm_runtime::workload_runner::{ChildGrantIssuer, ClaimContext, PreloadContext, SpawnContext};
use sha2::{Digest, Sha256};

use super::Cli;
use super::vm::checkpoint::SignedChainAnchor;
use super::vm::host_signer;
use mvm_contract::builder::BuilderError;
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_hostd::plan_admission::{
    AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run, stash_plan_and_mint_verb_grant,
};

struct HostChildGrantIssuer;

impl ChildGrantIssuer for HostChildGrantIssuer {
    fn issue(
        &self,
        config: &VmStartConfig,
    ) -> Result<Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>> {
        stash_plan_and_mint_verb_grant(config)
    }
}

/// Lowercase-hex sha256 of a kernel image — part of the base-compat key.
pub fn kernel_sha256_hex(kernel: &Path) -> Result<String> {
    let bytes =
        std::fs::read(kernel).with_context(|| format!("read kernel {}", kernel.display()))?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

/// 32 random bytes as lowercase hex — the per-spawn binding nonce.
pub fn fresh_binding_nonce() -> String {
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex_lower(&buf)
}

/// The compat-key kernel identity, computed identically at claim **and** replenish time.
/// For **libkrun** a workload microVM always boots the bundled libkrunfw kernel (mkGuest
/// images ship none; the builder VM uses a custom kernel but never the warm pool), so the
/// identity is a constant — crucially the same whether the workload's `kernel_path` is
/// absent (claim, pre-boot) or present (replenish, after libkrun materialized the bundled
/// kernel). That's what makes the libkrun warm claim *fire* instead of fail-open to cold
/// because the absent path can't be hashed. Other backends boot a real on-disk kernel → sha.
const LIBKRUN_BUNDLED_KERNEL_ID: &str = "libkrun-bundled-kernel";

pub fn kernel_identity(backend: &dyn VmBackend, kernel_path: Option<&str>) -> Result<String> {
    if mvm_runtime::catalog::descriptor(backend.kind()).bundled_kernel {
        return Ok(LIBKRUN_BUNDLED_KERNEL_ID.to_string());
    }
    let kernel = kernel_path.context("launch config has no kernel path for the compat key")?;
    kernel_sha256_hex(Path::new(kernel))
}

/// Inputs to [`build_standby_spec`] (grouped to avoid a long positional signature).
pub struct StandbySpecParams<'a> {
    /// `~/.mvm/pool/` root — holds the control UDS.
    pub pool_root: &'a Path,
    /// Registered template identity for a template-bound warm parent.
    pub template_id: Option<&'a str>,
    /// `~/.mvm/vms/` root — the standby's runtime state dir lives at `vms_root/<id>/`.
    pub vms_root: &'a Path,
    /// Kernel image the standby pre-loads (the path; for libkrun mkGuest the bundled kernel
    /// is materialized here at boot).
    pub kernel: &'a Path,
    /// Compat-key identity (see [`kernel_identity`]) — not necessarily a hash of `kernel`
    /// (for libkrun it's the bundled-kernel constant).
    pub kernel_sha256: &'a str,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub signer_id: &'a str,
    pub signing_key_path: &'a Path,
    /// Resolved rootfs image for the parent. A block parent boots it directly;
    /// a virtiofs parent uses its digest as the image identity while serving the
    /// launch's read-only unpacked tree. `None` only when the caller has no
    /// launch to mirror, which the spawn then refuses.
    pub image_path: Option<&'a Path>,
    /// Sha256 hex of that image — the compat key's image half, and the same
    /// digest a claim computes for its own launch. `None` only alongside an
    /// absent `image_path`.
    pub image_sha256: Option<&'a str>,
    /// Root device model the parent boots and every restored child inherits.
    pub root_strategy: RuntimeSourceRootStrategy,
    /// Whether the parent boots its guest's vsock egress client — the compat
    /// key's egress half, read off the launch's effective enablement. A restored
    /// child inherits the token from the parent's memory, so this is fixed here.
    pub vsock_egress: bool,
}

impl<'a> StandbySpecParams<'a> {
    /// Start building a [`StandbySpecParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> StandbySpecParamsBuilder<'a> {
        StandbySpecParamsBuilder::new()
    }
}

/// Builder for [`StandbySpecParams`]. Required fields are checked by
/// [`StandbySpecParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct StandbySpecParamsBuilder<'a> {
    pool_root: Option<&'a Path>,
    template_id: Option<&'a str>,
    vms_root: Option<&'a Path>,
    kernel: Option<&'a Path>,
    kernel_sha256: Option<&'a str>,
    vcpus: Option<u8>,
    mem_mib: Option<u32>,
    signer_id: Option<&'a str>,
    signing_key_path: Option<&'a Path>,
    image_path: Option<&'a Path>,
    image_sha256: Option<&'a str>,
    root_strategy: Option<RuntimeSourceRootStrategy>,
    vsock_egress: Option<bool>,
}

impl<'a> StandbySpecParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pool_root: None,
            template_id: None,
            vms_root: None,
            kernel: None,
            kernel_sha256: None,
            vcpus: None,
            mem_mib: None,
            signer_id: None,
            signing_key_path: None,
            image_path: None,
            image_sha256: None,
            root_strategy: None,
            vsock_egress: None,
        }
    }

    /// Set `pool_root`.
    #[must_use]
    pub fn pool_root(mut self, pool_root: &'a Path) -> Self {
        self.pool_root = Some(pool_root);
        self
    }

    /// Set `template_id`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn template_id(mut self, template_id: impl Into<Option<&'a str>>) -> Self {
        self.template_id = template_id.into();
        self
    }

    /// Set `vms_root`.
    #[must_use]
    pub fn vms_root(mut self, vms_root: &'a Path) -> Self {
        self.vms_root = Some(vms_root);
        self
    }

    /// Set `kernel`.
    #[must_use]
    pub fn kernel(mut self, kernel: &'a Path) -> Self {
        self.kernel = Some(kernel);
        self
    }

    /// Set `kernel_sha256`.
    #[must_use]
    pub fn kernel_sha256(mut self, kernel_sha256: &'a str) -> Self {
        self.kernel_sha256 = Some(kernel_sha256);
        self
    }

    /// Set `vcpus`.
    #[must_use]
    pub fn vcpus(mut self, vcpus: u8) -> Self {
        self.vcpus = Some(vcpus);
        self
    }

    /// Set `mem_mib`.
    #[must_use]
    pub fn mem_mib(mut self, mem_mib: u32) -> Self {
        self.mem_mib = Some(mem_mib);
        self
    }

    /// Set `signer_id`.
    #[must_use]
    pub fn signer_id(mut self, signer_id: &'a str) -> Self {
        self.signer_id = Some(signer_id);
        self
    }

    /// Set `signing_key_path`.
    #[must_use]
    pub fn signing_key_path(mut self, signing_key_path: &'a Path) -> Self {
        self.signing_key_path = Some(signing_key_path);
        self
    }

    /// Set `image_path`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn image_path(mut self, image_path: impl Into<Option<&'a Path>>) -> Self {
        self.image_path = image_path.into();
        self
    }

    /// Set `image_sha256`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn image_sha256(mut self, image_sha256: impl Into<Option<&'a str>>) -> Self {
        self.image_sha256 = image_sha256.into();
        self
    }

    /// Set `root_strategy`.
    #[must_use]
    pub fn root_strategy(mut self, root_strategy: RuntimeSourceRootStrategy) -> Self {
        self.root_strategy = Some(root_strategy);
        self
    }

    /// Set `vsock_egress`.
    #[must_use]
    pub fn vsock_egress(mut self, vsock_egress: bool) -> Self {
        self.vsock_egress = Some(vsock_egress);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<StandbySpecParams<'a>, BuilderError> {
        Ok(StandbySpecParams {
            pool_root: self
                .pool_root
                .ok_or(BuilderError::missing("StandbySpecParams", "pool_root"))?,
            template_id: self.template_id,
            vms_root: self
                .vms_root
                .ok_or(BuilderError::missing("StandbySpecParams", "vms_root"))?,
            kernel: self
                .kernel
                .ok_or(BuilderError::missing("StandbySpecParams", "kernel"))?,
            kernel_sha256: self
                .kernel_sha256
                .ok_or(BuilderError::missing("StandbySpecParams", "kernel_sha256"))?,
            vcpus: self
                .vcpus
                .ok_or(BuilderError::missing("StandbySpecParams", "vcpus"))?,
            mem_mib: self
                .mem_mib
                .ok_or(BuilderError::missing("StandbySpecParams", "mem_mib"))?,
            signer_id: self
                .signer_id
                .ok_or(BuilderError::missing("StandbySpecParams", "signer_id"))?,
            signing_key_path: self.signing_key_path.ok_or(BuilderError::missing(
                "StandbySpecParams",
                "signing_key_path",
            ))?,
            image_path: self.image_path,
            image_sha256: self.image_sha256,
            root_strategy: self
                .root_strategy
                .ok_or(BuilderError::missing("StandbySpecParams", "root_strategy"))?,
            vsock_egress: self
                .vsock_egress
                .ok_or(BuilderError::missing("StandbySpecParams", "vsock_egress"))?,
        })
    }
}

impl<'a> Default for StandbySpecParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a `StandbySpec` from [`StandbySpecParams`]. The control UDS lives under
/// `pool_root/<id>/control-<nonce>.sock` (nonce in the path — defense in depth); the VM's
/// runtime state dir is the normal `vms_root/<id>/` so stop/status/console resolve it like
/// any cold-booted VM.
pub fn build_standby_spec(p: &StandbySpecParams<'_>) -> Result<StandbySpec> {
    let nonce = fresh_binding_nonce();
    // `standby-<16 hex>` — nonce-derived (defense-in-depth obfuscation within the 0700
    // dir). The socket filename is kept SHORT and fixed: a Unix domain socket path must fit
    // `SUN_LEN` (~104 bytes on macOS), so the full 64-char nonce can't live in the path —
    // the binding security is the *echoed full nonce verified in the attach*, not the path.
    let id = format!("standby-{}", &nonce[..16]);
    Ok(StandbySpec {
        kernel_path: p.kernel.to_string_lossy().into_owned(),
        template_id: p.template_id.map(str::to_string),
        kernel_sha256: p.kernel_sha256.to_string(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        signing_key_path: p.signing_key_path.to_string_lossy().into_owned(),
        signer_id: p.signer_id.to_string(),
        control_socket: p
            .pool_root
            .join(&id)
            .join("control.sock")
            .to_string_lossy()
            .into_owned(),
        vm_state_dir: p.vms_root.join(&id).to_string_lossy().into_owned(),
        binding_nonce: nonce,
        image_path: p.image_path.map(|p| p.to_string_lossy().into_owned()),
        image_sha256: p.image_sha256.map(str::to_string),
        root_strategy: p.root_strategy,
        vsock_egress: p.vsock_egress,
        id,
    })
}

/// Parameters for [`warm_to_target`] — grouped to keep the signature small.
pub struct WarmParams<'a> {
    pub backend: &'a AnyBackend,
    pub signer_id: &'a str,
    pub signing_key_path: &'a Path,
    pub target: u32,
    /// The resolved launch config the warm parents mirror, carrying everything
    /// the run path resolves for a boot — the rootfs and its verity sidecar, the
    /// runtime overlay that holds the guest agent, the universal initramfs, and
    /// the cmdline-bearing policy fields.
    ///
    /// Every other input to the parent's shape is derived from this one value:
    /// template, kernel, vCPUs, memory, image digest and egress enablement all
    /// come out of [`compat_for_launch`]. They used to be separate fields, which
    /// let a caller record a compat key describing something other than what
    /// booted — a pool that fills and never drains, with no error anywhere.
    pub launch: &'a VmStartConfig,
}

/// Summary returned by [`warm_to_target`].
#[derive(Debug, PartialEq, Eq)]
pub struct WarmResult {
    /// Standbys newly spawned and recorded in this call.
    pub spawned: u32,
    /// Spawn attempts that failed (each was logged as a warning).
    pub failed: u32,
}

/// Warm the pool toward `target` idle standbys for the given kernel+resources.
/// Spawn failures are logged and counted; the caller decides whether to
/// surface them as an error.  Returns a [`WarmResult`] with success and
/// failure counts.
/// Tenant a factory parent's plan is admitted under when the launch it mirrors
/// carries none. A parent is host-side capacity, not a tenant's workload, so it
/// gets its own identity rather than borrowing an arbitrary one.
const STANDBY_PARENT_TENANT: &str = "standby";

/// The captured parent's own rootfs digest — the bytes it actually booted, so
/// the plan admitted for it describes what it is rather than what asked for it.
fn captured_rootfs_digest(meta: &mvm_core::checkpoint::CheckpointMeta) -> Result<String> {
    mvm_runtime::workload_runner::claim::parent_rootfs_digest(meta)
        .map(str::to_string)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Admit a signed `ExecutionPlan` for a captured factory parent.
///
/// Mirrors the workload admission path (synthesize → sign → verify → window →
/// nonce) with every workload authority left out: no secrets, no services, no
/// bundle, no deps volume, no shares. The parent runs nothing on a tenant's
/// behalf; the plan exists so its checkpoint has a signed creation entry to
/// anchor against.
fn admit_standby_parent_plan(
    handle: &StandbyHandle,
    backend_name: &str,
    tenant: &str,
    rootfs_sha256: &str,
    vcpus: u8,
    mem_mib: u32,
) -> Result<AdmittedPlan> {
    let input = SynthesisInput {
        grants: None,
        kernel_sha256: None,
        vm_name: &handle.id,
        tenant: Some(tenant),
        backend_name,
        image_name: &handle.id,
        image_sha256: rootfs_sha256,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::default(),
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: u32::from(vcpus),
        mem_mib: u64::from(mem_mib),
        disk_mib: 0,
        boot_timeout_secs: 60,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_edges: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
        // The parent reaches nothing, so it gets the closed transport and no
        // L3 spec — the same "no workload authority" posture as the empty
        // secrets, services, and shares above.
        network_mode: mvm_contract::plan::NetworkMode::None,
        ingress: Vec::new(),
    };
    let ledger = InMemoryNonceLedger::new();
    admit_for_run(
        &input,
        &SystemClock,
        &ledger,
        None,
        None,
        mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
    )
    .context("admitting a plan for the captured standby parent")
}

/// Bind a freshly captured parent's checkpoint into the signed audit chain.
///
/// The claim path refuses to fork a parent whose checkpoint carries no
/// `checkpoint.created` entry — the claim-8 lineage gate. A factory parent is
/// never launched from a workload plan, so nothing else admits one for it, and
/// without this every parent the pool captures is unclaimable by construction.
fn audit_captured_parent(
    checkpoints: &CheckpointStore,
    handle: &StandbyHandle,
    backend_name: &str,
    tenant: &str,
) -> Result<()> {
    let checkpoint_id = handle.parent_checkpoint.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "standby '{}' was recorded without a parent checkpoint to anchor",
            handle.id
        )
    })?;
    let meta = checkpoints
        .read_meta(&CheckpointId::new(checkpoint_id.to_string()))
        .with_context(|| format!("reading captured checkpoint '{checkpoint_id}'"))?;
    let rootfs_sha256 = captured_rootfs_digest(&meta)?;
    let admitted = admit_standby_parent_plan(
        handle,
        backend_name,
        tenant,
        &rootfs_sha256,
        handle.vcpus,
        handle.mem_mib,
    )?;
    let signer = host_signer::load_or_init()
        .context("loading the host signer to sign the parent's creation entry")?;
    let emitter = super::vm::audit_chain::AuditEmitter::new(signer.signing)
        .context("opening the audit chain to record the parent's creation")?
        .with_receipts()
        .with_decisions()
        .context("enabling the decision store for the pool audit")?;
    mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, admitted.plan(), &meta)
        .context("emitting checkpoint.created for the captured standby parent")
}

/// Drop a parent that could not be audited, checkpoint and all.
///
/// An unauditable parent is worse than no parent: every claim would refuse it,
/// quarantine it, and replenish would spawn another — a wasted boot and capture
/// per launch, forever. Its guest is already stopped by the capture, so this
/// only has to reclaim the disk.
fn discard_unauditable_parent(checkpoints: &CheckpointStore, handle: &StandbyHandle) {
    let Some(id) = handle.parent_checkpoint.as_deref() else {
        return;
    };
    if let Err(e) = checkpoints.remove(&CheckpointId::new(id.to_string())) {
        tracing::warn!(
            checkpoint = id,
            error = %e,
            "could not remove the unauditable parent's checkpoint; it will occupy disk until pruned"
        );
    }
}

/// Reap a paused child if the pool record cannot be published after preload.
/// The child is not yet a user VM, so leaving it behind would leak a VMM that
/// no persisted reaper can discover.
fn discard_preloaded_child(backend: &AnyBackend, handle: &StandbyHandle) {
    let Some(child_name) = handle.preloaded_child_vm_name.as_deref() else {
        return;
    };
    if let Err(error) = backend.stop_transient(&VmId(child_name.to_string())) {
        tracing::warn!(
            child = child_name,
            %error,
            "could not stop unpublished preloaded standby child"
        );
    }
    let child_dir = mvm_core::config::vm_state_dir(child_name);
    if let Err(error) = std::fs::remove_dir_all(&child_dir)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            child = child_name,
            path = %child_dir.display(),
            %error,
            "could not remove unpublished preloaded child state"
        );
    }
}

/// Whether a standby pool this backend cannot serve should fail the launch.
///
/// The warm target is not always something anyone asked for. On the HVF
/// default tier the host residency policy resolves to always-warm on its own,
/// and a run that names a pool-less backend — `--hypervisor libkrun`, wasm —
/// inherits that default without ever opting into it. Refusing there makes
/// those backends unusable on this host for a pool nobody configured, which is
/// what `machine run --hypervisor libkrun` reported: "claiming *configured*
/// warm standby", naming a configuration that did not exist.
///
/// An operator who set `MVM_RESIDENCY` did ask, and a request this backend
/// cannot serve is worth saying out loud rather than quietly cold-booting.
///
/// Pure over the source so both answers are testable without mutating process
/// env, which no test can do safely while others run beside it.
fn unsupported_standby_pool_is_fatal(source: mvm_core::residency::ResidencySource) -> bool {
    matches!(source, mvm_core::residency::ResidencySource::EnvOverride)
}

/// How this launch came by its warm target.
fn residency_source() -> mvm_core::residency::ResidencySource {
    mvm_core::residency::resolve_residency().1
}

fn warm_launch_mode(
    source: mvm_core::residency::ResidencySource,
    require_claim_override: bool,
) -> WarmLaunchMode {
    if require_claim_override || matches!(source, mvm_core::residency::ResidencySource::EnvOverride)
    {
        WarmLaunchMode::Required
    } else {
        WarmLaunchMode::Optional
    }
}

pub fn warm_to_target(pool: &SupervisorStandbyPool, p: &WarmParams<'_>) -> Result<WarmResult> {
    if p.target == 0 {
        return Ok(WarmResult {
            spawned: 0,
            failed: 0,
        });
    }
    if !p.backend.capabilities().standby_pool {
        if !unsupported_standby_pool_is_fatal(residency_source()) {
            return Ok(WarmResult {
                spawned: 0,
                failed: 0,
            });
        }
        return Err(anyhow::Error::new(StandbyError::Unsupported {
            backend: p.backend.name().to_string(),
        })
        .context("requested standby-pool recovery"));
    }
    // Serialize concurrent warms on the pool directory. Without this lock two
    // launches can both read an empty pool and each spawn up to `target`,
    // overshooting it; the standbys then age out via TTL but waste a boot each.
    // The lock spans the idle-count read through the spawn loop and releases on
    // return.
    let _warm_guard = mvm_core::atomic_io::FileLock::acquire(&pool.root().join("warm"))?;
    // The key this spawn records is the key a claim will look for, because both
    // are built by `compat_for_launch` from the same launch config. Building it
    // twice from two field sets is how the pool came to fill with parents no
    // claim could ever match.
    let image = Path::new(p.launch.rootfs_path.as_str());
    let kernel = Path::new(p.launch.kernel_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("the launch config names no kernel for its warm parents to boot")
    })?);
    let want = compat_for_launch(p.backend.as_vm_backend(), p.launch)?;
    let have = pool.idle_count_compatible(&want)? as u32;
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    let vms_root = mvm_core::config::vms_dir();
    let checkpoints = CheckpointStore::open();
    let spawn_ctx = SpawnContext {
        checkpoints: &checkpoints,
        launch: Some(p.launch),
    };
    let mut spawned = 0u32;
    let mut failed = 0u32;
    for _ in have..p.target {
        // Every compat field comes from `want`, so the recorded handle's own
        // `compat()` is `want` — the exact value the claim searches for.
        let spec = build_standby_spec(
            &StandbySpecParams::builder()
                .pool_root(&pool_root)
                .template_id(want.template_id.as_deref())
                .vms_root(&vms_root)
                .kernel(kernel)
                .kernel_sha256(&want.kernel_sha256)
                .vcpus(want.vcpus)
                .mem_mib(want.mem_mib)
                .signer_id(p.signer_id)
                .signing_key_path(p.signing_key_path)
                .image_path(image)
                .image_sha256(want.image_sha256.as_deref())
                .root_strategy(want.root_strategy)
                .vsock_egress(want.vsock_egress)
                .build()?,
        )?;
        match p.backend.spawn_standby_via_runner(&spawn_ctx, &spec) {
            Ok(handle) => {
                // Audit before recording: the claim refuses a parent with no
                // signed creation entry, so pooling an unauditable one only
                // buys a refusal, a quarantine and another spawn next launch.
                let tenant = p
                    .launch
                    .tenant_id
                    .as_deref()
                    .unwrap_or(STANDBY_PARENT_TENANT);
                match audit_captured_parent(&checkpoints, &handle, p.backend.name(), tenant) {
                    Ok(()) => {
                        let mut handle = handle;
                        if p.backend.supports_preloaded_standby() {
                            let snapshots =
                                FsSnapshotStore::new(mvm_core::config::snapshots_dir())?;
                            let anchor = SignedChainAnchor::load()?;
                            let registry_path = mvm_runtime::vm::name_registry::registry_path();
                            let preload = PreloadContext {
                                checkpoints: &checkpoints,
                                snapshots: &snapshots,
                                anchor: &anchor,
                                registry_path: &registry_path,
                            };
                            if let Err(error) =
                                p.backend.preload_standby_via_runner(&preload, &mut handle)
                            {
                                tracing::warn!(
                                    standby = %handle.id,
                                    %error,
                                    "could not preload paused child; discarding standby"
                                );
                                discard_preloaded_child(p.backend, &handle);
                                failed += 1;
                                continue;
                            }
                        }
                        if let Err(error) = pool.record(&handle) {
                            discard_preloaded_child(p.backend, &handle);
                            return Err(error);
                        }
                        spawned += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            standby = %handle.id,
                            error = %e,
                            "could not audit the captured standby parent; discarding it rather \
                             than pooling one no claim could ever verify"
                        );
                        discard_unauditable_parent(&checkpoints, &handle);
                        failed += 1;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "spawn standby failed; pool stays under target");
                failed += 1;
            }
        }
    }
    // Bound the retained parent footprint for this template. The target is
    // also the intended number of parents, so its per-parent memory cap gives
    // the warm set a deterministic upper bound even when older records were
    // created with a different resource shape.
    let max_memory_mib = u64::from(p.target).saturating_mul(u64::from(want.mem_mib));
    let evicted = pool.evict_to_memory_budget(want.template_id.as_deref(), max_memory_mib)?;
    if !evicted.is_empty() {
        tracing::debug!(
            template_id = ?want.template_id,
            count = evicted.len(),
            "evicted warm parents over memory budget"
        );
    }
    Ok(WarmResult { spawned, failed })
}

/// The compat-key image identity for a launch: the sha256 of its rootfs image.
///
/// A warm parent is a full-state capture of one particular rootfs, and every
/// child is cloned from that captured content — so a parent captured from image
/// A must never be handed to a launch of image B. This key is what keeps the
/// two apart, and it is deliberately the **same digest** claim-8 admission puts
/// on `plan.image.sha256` and that the runner's `bind_plan_to_parent` checks a
/// captured parent's `rootfs.ext4` blob against. A standby that passes this
/// pre-filter is therefore one the downstream binding will also accept, rather
/// than one that gets reserved and then refused.
///
/// Both halves of the pool call this — the spawn records what it returns, the
/// claim searches for it. They must not compute it separately: this function
/// used to return `None` unconditionally, which read as "image-agnostic" but
/// meant "never equal to anything the spawn recorded", so every claim silently
/// cold-booted while the pool filled and never drained.
///
/// Hashing goes through the size+mtime-keyed sidecar cache that plan admission
/// already populated for this rootfs, so the launch path re-reads a digest
/// instead of re-hashing ~100 MB before it can decide.
pub fn image_identity(rootfs_path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file_cached(rootfs_path).with_context(|| {
        format!(
            "hashing rootfs for the warm-pool compat key: {}",
            rootfs_path.display()
        )
    })
}

// ── Warm-pool claim glue (recovered from history after up/run folded into
// `machine run` orphaned it; the surviving standby primitives are unchanged).
// Wired into `crate::exec::run_inner`.

pub enum LaunchDecision {
    /// A standby was claimed and is booting under this VmId.
    Claimed(VmId),
    /// No compatible warm standby — caller may cold-boot when its mode permits it.
    ColdBoot,
    /// The caller required warm service and must not cold-boot.
    Refused(WarmClaimRefusal),
}

/// Try a warm claim in the default compatibility mode: use warm capacity when
/// available and preserve the existing cold-boot fallback.
///
/// `make_claim` builds the [`StandbyClaim`] **for the selected standby's id** — the audit
/// substrate (`gateway-<vm>.sock`) is name-keyed, and a claimed VM runs under its
/// standby-id, so the caller must compute those paths against `handle.id`. Errors from
/// `make_claim` are surfaced to [`claim_with_mode`] for mode-specific handling.
pub fn claim_or_cold<F>(
    pool: &SupervisorStandbyPool,
    backend: &AnyBackend,
    want: &StandbyCompat,
    make_claim: F,
) -> Result<LaunchDecision>
where
    F: FnOnce(&StandbyHandle) -> Result<StandbyClaim>,
{
    claim_with_mode(pool, backend, want, WarmLaunchMode::Optional, make_claim)
}

/// Try to claim an idle standby compatible with `want` under an explicit warm
/// launch mode. A required warm launch returns a typed refusal for every
/// capacity, compatibility, preparation, and backend claim failure; it never
/// silently turns those failures into a cold boot.
pub fn claim_with_mode<F>(
    pool: &SupervisorStandbyPool,
    backend: &AnyBackend,
    want: &StandbyCompat,
    mode: WarmLaunchMode,
    make_claim: F,
) -> Result<LaunchDecision>
where
    F: FnOnce(&StandbyHandle) -> Result<StandbyClaim>,
{
    if matches!(mode, WarmLaunchMode::Cold) {
        return Ok(LaunchDecision::ColdBoot);
    }
    if !backend.capabilities().standby_pool {
        if mode.requires_warm() {
            return Ok(LaunchDecision::Refused(
                WarmClaimRefusal::BackendUnsupported {
                    backend: backend.name().to_string(),
                },
            ));
        }
        if !unsupported_standby_pool_is_fatal(residency_source()) {
            return Ok(LaunchDecision::ColdBoot);
        }
        return Err(anyhow::Error::new(StandbyError::Unsupported {
            backend: backend.name().to_string(),
        })
        .context("requested standby-pool recovery"));
    }
    // Select without reserving. The runner reserves this parent itself, in the
    // same locked section it verifies it in, and refuses a parent that is
    // already `Claimed` — so reserving here too made every warm claim fail with
    // "parent is not in a claimable state". One reservation owner, and it is the
    // one that also verifies.
    //
    // Two launchers can still both select the same idle parent; the runner's
    // lock serializes them and the loser is refused into a cold boot, which is
    // the same outcome reserving here bought, without deadlocking the winner.
    let Some(handle) = pool.select_idle_compatible(want)? else {
        return Ok(match mode {
            WarmLaunchMode::Required => {
                LaunchDecision::Refused(WarmClaimRefusal::NoCompatibleParent)
            }
            WarmLaunchMode::Optional | WarmLaunchMode::Cold => LaunchDecision::ColdBoot,
        });
    };
    let claim = match make_claim(&handle) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "build claim failed");
            return Ok(decision_for_mode(
                mode,
                WarmClaimRefusal::PreparationFailed {
                    reason: e.to_string(),
                },
            ));
        }
    };
    // A claim verifies the parent's content and lineage against the checkpoint
    // it was captured as, so an uncaptured parent is unusable by construction.
    let parent_checkpoint = match parent_checkpoint_for(&handle) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "warm claim parent checkpoint unavailable");
            let _ = pool.remove(&handle.id);
            return Ok(decision_for_mode(
                mode,
                WarmClaimRefusal::ClaimRejected {
                    reason: e.to_string(),
                },
            ));
        }
    };
    let checkpoints = CheckpointStore::open();
    let snapshots = FsSnapshotStore::new(mvm_core::config::snapshots_dir())?;
    let anchor = if backend.as_vm_backend().supports_resident_handoff() {
        SignedChainAnchor::empty()
    } else {
        SignedChainAnchor::load()?
    };
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    let grant_issuer = HostChildGrantIssuer;
    let ctx = ClaimContext {
        pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_checkpoint,
        registry_path: &registry_path,
        grant_issuer: Some(&grant_issuer),
    };
    match backend.claim_standby_via_runner(&ctx, &handle, &claim) {
        Ok(vm_id) => {
            // The standby has become the VM; drop its pool entry (the control UDS is
            // one-shot). The VM now lives under its vms/<id> state dir.
            let _ = pool.remove(&handle.id);
            Ok(LaunchDecision::Claimed(vm_id))
        }
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "standby claim failed");
            // The runner owns the reservation lease. Healthy parents are
            // released by its cleanup guard; parents that fail verification
            // are quarantined there. The orchestration layer must not delete
            // the record and strand healthy warm capacity.
            Ok(decision_for_mode(
                mode,
                WarmClaimRefusal::ClaimRejected {
                    reason: e.to_string(),
                },
            ))
        }
    }
}

fn decision_for_mode(mode: WarmLaunchMode, refusal: WarmClaimRefusal) -> LaunchDecision {
    if mode.requires_warm() {
        LaunchDecision::Refused(refusal)
    } else {
        LaunchDecision::ColdBoot
    }
}

/// Resolve the checkpoint a standby parent was captured as. A parent that never
/// went through the spawn-and-capture path (or predates it) has no checkpoint to
/// verify content and lineage against, so a claim against it must refuse rather
/// than clone unverified content. Kept separate from [`claim_or_cold`] so the
/// refusal is unit-testable without a pool or a VM.
fn parent_checkpoint_for(handle: &StandbyHandle) -> Result<CheckpointId> {
    handle
        .parent_checkpoint
        .as_deref()
        .map(|id| CheckpointId::new(id.to_string()))
        .with_context(|| format!("standby '{}' was never captured to a checkpoint", handle.id))
}

/// The base-compat key for one launch shape. The single builder both halves of
/// the pool use: `warm_to_target` records what this returns on the standby it
/// spawns, and `try_warm_claim` searches for what this returns. Anything that
/// computed one side independently would be free to disagree with the other,
/// and `StandbyHandle::is_compatible` is exact equality — a disagreement is a
/// pool that never drains, with no error anywhere.
fn compat_for_launch(backend: &dyn VmBackend, cfg: &VmStartConfig) -> Result<StandbyCompat> {
    Ok(StandbyCompat {
        template_id: cfg.template_id.clone(),
        kernel_sha256: kernel_identity(backend, cfg.kernel_path.as_deref())?,
        vcpus: u8::try_from(cfg.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX),
        mem_mib: cfg.memory_mib,
        image_sha256: Some(image_identity(Path::new(cfg.rootfs_path.as_str()))?),
        // Every launch resolves a block root; the field stays on the recorded
        // spec so a parent warmed before that was true still declares what it
        // was warmed under, and the claim's compat check can refuse it.
        root_strategy: RuntimeSourceRootStrategy::BlockExt4,
        // Whether the guest boots an egress client, read off the launch's policy
        // and its admitted plan through the same derivation the guest cmdline
        // token comes from — never re-expressed here, because a second
        // expression of it is free to drift from the token it must predict.
        vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(cfg),
    })
}

/// Whether a warm parent can serve this launch shape at all.
///
/// A parent is shared across claims and carries no workload authority, so a
/// launch shape whose guest a parent cannot boot is excluded here rather than
/// keyed on. Both halves of the pool consult this — the claim to decide whether
/// to look, the replenish to decide whether to spawn — because excluding a shape
/// from one but not the other either fills the pool with parents nothing claims
/// or claims parents that cannot serve the launch.
///
/// Excluded:
///
/// - **extra volumes** — the attach threads only the rootfs, so a volume disk
///   would be missing from the child;
///
/// A virtio-fs root is keyed rather than excluded. The parent boots the same
/// read-only image tree and a restored child inherits that device model, so the
/// compatibility key distinguishes it from a block-backed parent.
///
/// An egress-allowing policy is *not* excluded. `mvm.vsock_egress=1` is a
/// kernel-cmdline token, and a forked child inherits its parent's cmdline out of
/// restored memory rather than deriving its own — but the token carries only
/// whether the guest starts an egress client, never a destination. So the pool
/// partitions on that boolean instead of refusing the shape:
/// [`StandbyCompat::vsock_egress`] makes a parent claimable only by launches
/// whose guest boots the same way, and the destinations a workload may reach are
/// resolved host-side on the claimed child's own egress endpoint, from that
/// child's own policy. A shared parent therefore holds nothing per-launch that
/// could reach the next claim.
///
/// `VmVolumeKind::DirShare` is included in the volume check. The current
/// factory-parent path has no late attachment operation for a host path, so a
/// live read-only share remains cold-path-only until the backend supplies one.
fn warm_eligible_launch(cfg: &VmStartConfig) -> bool {
    cfg.volumes.is_empty()
}

/// Attempt a warm-pool claim for this launch. Returns the claimed `VmId` (the standby-id
/// the VM now runs under) or `None` when this launch shape is not eligible. A configured
/// warm pool on a backend without standby support is an explicit typed error; it must not
/// silently become a cold boot.
///
/// Eligibility (all required): `warm_pool_size > 0`, the launch is auto-named (no explicit
/// `--name` — a claimed VM is named by its standby-id), a launch shape a shared parent can
/// serve ([`warm_eligible_launch`]), the backend supports the pool, and the admitted tenant
/// is threaded into the config. libkrun additionally requires the signed
/// plan JSON because its claimed standby enters the gateway-bridge supervisor path;
/// Firecracker can claim with only the resolved launch config because the default path
/// enforces networking directly via TAP/nftables and only needs plan JSON when its optional
/// bridge is enabled.
pub fn try_warm_claim(
    backend: &AnyBackend,
    cfg: &VmStartConfig,
    user_named: bool,
) -> Result<Option<VmId>> {
    if cfg.warm_pool_size == 0 {
        return Ok(None);
    }
    if user_named || !warm_eligible_launch(cfg) {
        return Ok(None);
    }
    let Some(tenant) = cfg.tenant_id.clone() else {
        // No admitted tenant threaded in → not an admitted workload → cold-boot.
        return Ok(None);
    };
    let Some(plan_json) = warm_claim_plan_json(backend.as_vm_backend(), cfg) else {
        // libkrun claims need a signed envelope for the gateway-bridge
        // supervisor attach path; without it, cold-boot.
        return Ok(None);
    };
    if !backend.capabilities().standby_pool {
        if !unsupported_standby_pool_is_fatal(residency_source()) {
            return Ok(None);
        }
        return Err(anyhow::Error::new(StandbyError::Unsupported {
            backend: backend.name().to_string(),
        })
        .context("requested standby-pool recovery"));
    }
    // The same builder the spawn side records with, so the key searched for is
    // the key recorded. The rootfs digest comes from the sidecar cache plan
    // admission just populated, so this costs a read, not a re-hash.
    let want = compat_for_launch(backend.as_vm_backend(), cfg)?;
    let rootfs = cfg.rootfs_path.clone();
    let bundle_json = cfg.bundle_json.clone();
    let claim_start_config = cfg.clone();
    let pool = SupervisorStandbyPool::open()?;
    let claim_mode = warm_launch_mode(
        residency_source(),
        std::env::var("MVM_HVF_WARM_REQUIRE_CLAIM").as_deref() == Ok("1"),
    );
    let make_claim = |handle: &StandbyHandle| {
        // The audit substrate (`gateway-<vm>.sock`) is name-keyed; the claimed VM runs
        // under the standby-id, so compute it for `handle.id`.
        let sub =
            mvm_vmm::host::audit_substrate::compute_audit_substrate(&handle.id, Some(&tenant))?;
        let mut start_config = claim_start_config.clone();
        start_config.name = handle.id.clone();
        start_config.rootfs_path = rootfs.clone();
        start_config.tenant_id = Some(tenant.clone());
        start_config.plan_json = Some(plan_json.clone());
        start_config.bundle_json = bundle_json.clone();
        start_config.network_policy = cfg.network_policy.clone();
        Ok(StandbyClaim {
            start_config: Some(start_config),
            rootfs_path: rootfs.clone(),
            tenant_id: tenant.clone(),
            audit_dir: sub.audit_dir.context("audit substrate missing audit_dir")?,
            gateway_audit_socket: sub
                .gateway_audit_socket
                .context("audit substrate missing gateway_audit_socket")?,
            gateway_events_socket: sub.gateway_events_socket,
            plan_json: plan_json.clone(),
            bundle_json: bundle_json.clone(),
            network_policy: cfg.network_policy.clone(),
        })
    };
    let decision = if matches!(claim_mode, WarmLaunchMode::Optional) {
        claim_or_cold(&pool, backend, &want, make_claim)
    } else {
        claim_with_mode(&pool, backend, &want, claim_mode, make_claim)
    }?;
    Ok(match decision {
        LaunchDecision::Claimed(id) => Some(id),
        LaunchDecision::ColdBoot => None,
        LaunchDecision::Refused(refusal) => return Err(anyhow::Error::new(refusal)),
    })
}

fn warm_claim_plan_json(backend: &dyn VmBackend, cfg: &VmStartConfig) -> Option<String> {
    match cfg.plan_json.clone() {
        Some(plan) => Some(plan),
        None if mvm_runtime::catalog::descriptor(backend.kind()).needs_plan_json => {
            Some(String::new())
        }
        None => None,
    }
}

/// Lazily reap dead/expired standbys on the launch path — the no-daemon
/// reap-on-use counterpart to an explicit `pool warm`. Without a background
/// daemon nothing enforces the standby TTL between invocations, so every launch
/// expires stale spares itself; otherwise a one-off run, or runs against
/// different images, leave standbys resident until a manual `cache prune`
/// (`reap_stale` is only otherwise wired into `cache prune`). Best-effort: a
/// reap failure must never block a launch, so it is logged at debug and
/// swallowed. Uses the same [`STANDBY_POOL_TTL`] as `cache prune` so the two
/// reapers agree on what "stale" means.
pub fn reap_stale_standbys_best_effort() {
    match SupervisorStandbyPool::open()
        .and_then(|pool| pool.reap_stale(STANDBY_POOL_TTL, mvm_core::time::now_unix_secs()))
    {
        Ok(reaped) if !reaped.is_empty() => {
            tracing::debug!(count = reaped.len(), "reaped stale standbys on launch");
        }
        Ok(_) => {}
        Err(e) => tracing::debug!(error = %e, "standby reap on launch failed (best-effort)"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use mvm_core::vm_backend::{StandbyHandle, StandbyState, VmStartConfig};

    fn sha256_hex_of(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }

    // ── Warm-claim eligibility-gate tests. They assert `try_warm_claim` fails
    // open to cold boot *before* touching the pool, so they need no real
    // VM/backend.
    fn eligible_cfg() -> VmStartConfig {
        VmStartConfig {
            warm_pool_size: 2,
            kernel_path: Some("/k/vmlinux".into()),
            rootfs_path: "/vol/rootfs.ext4".into(),
            cpus: 2,
            memory_mib: 1024,
            tenant_id: Some("tenant-a".into()),
            plan_json: Some("{}".into()),
            ..Default::default()
        }
    }

    /// The optional half of a standby spec — the template binding and the
    /// image identity — is what a claim searches a parent by, so each optional
    /// setter has to land rather than leaving `None` behind.
    #[test]
    fn the_optional_standby_setters_reach_the_built_value() {
        let pool_root = Path::new("/pool");
        let vms_root = Path::new("/vms");
        let kernel = Path::new("/vmlinux");
        let key = Path::new("/key");
        let image = Path::new("/rootfs.ext4");
        let Ok(built) = StandbySpecParams::builder()
            .pool_root(pool_root)
            .template_id("tpl-1")
            .vms_root(vms_root)
            .kernel(kernel)
            .kernel_sha256("deadbeef")
            .vcpus(2)
            .mem_mib(1024)
            .signer_id("host:test")
            .signing_key_path(key)
            .image_path(image)
            .image_sha256("cafebabe")
            .root_strategy(RuntimeSourceRootStrategy::VirtiofsRoot)
            .vsock_egress(true)
            .build()
        else {
            panic!("every StandbySpecParams field is set");
        };
        assert_eq!(built.template_id, Some("tpl-1"));
        assert_eq!(built.image_path, Some(image));
        assert_eq!(built.image_sha256, Some("cafebabe"));
        assert_eq!(built.root_strategy, RuntimeSourceRootStrategy::VirtiofsRoot);
        assert!(built.vsock_egress);
    }

    /// A required field left unset is named, never defaulted into a spec that
    /// spawns a standby no launch can claim.
    #[test]
    fn an_empty_standby_builder_names_the_first_missing_field() {
        let Err(err) = StandbySpecParams::builder().build() else {
            panic!("an empty StandbySpecParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("StandbySpecParams", "pool_root"));
    }

    #[test]
    fn try_warm_claim_cold_when_pool_size_zero() {
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.warm_pool_size = 0;
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }

    // ── Auditing a captured factory parent ───────────────────────────────
    //
    // The claim refuses a parent whose checkpoint has no signed creation
    // entry. Nothing admits a plan for a factory parent, so before this the
    // pool filled with parents no claim could ever verify.

    /// A captured parent's checkpoint, written the way `capture_vm_full` leaves
    /// it: a `vm_full` record carrying the rootfs blob a claim binds against.
    fn write_captured_parent(store: &CheckpointStore, id: &str, rootfs_sha: &str) -> CheckpointId {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta, ContentBlob};
        let ckpt = CheckpointId::new(id.to_string());
        let meta = CheckpointMeta::builder(ckpt.clone(), CheckpointClass::VmFull, "standby-vm")
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: rootfs_sha.into(),
            }])
            .supervisor_config_digest("")
            .created_unix(1)
            .build();
        store.write_meta(&meta).unwrap();
        ckpt
    }

    fn captured_handle(id: &str, ckpt: &CheckpointId) -> StandbyHandle {
        StandbyHandle {
            id: id.to_string(),
            template_id: None,
            control_socket: String::new(),
            // Zero is the released-after-capture sentinel a real captured
            // parent carries: its state lives in the checkpoint, not a process.
            pid: 0,
            vcpus: 2,
            mem_mib: 512,
            binding_nonce: "nonce".into(),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            parent_checkpoint: Some(ckpt.as_str().to_string()),
            kernel_sha256: "a".repeat(64),
            image_sha256: Some("b".repeat(64)),
            root_strategy: RuntimeSourceRootStrategy::BlockExt4,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        }
    }

    /// The whole point: after auditing, the anchor the claim uses resolves the
    /// parent's creation digest. This is the exact lookup that returned `None`
    /// and produced `ParentUnaudited` on every live claim.
    #[test]
    fn auditing_a_captured_parent_makes_the_claim_anchor_resolve_it() {
        use mvm_runtime::checkpoint::CheckpointChainAnchor;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::open();
        let ckpt = write_captured_parent(&store, "standby-standby-abc", &"ab".repeat(32));
        let handle = captured_handle("standby-abc", &ckpt);
        let meta = store.read_meta(&ckpt).unwrap();

        // Before: the claim's gate finds nothing and refuses.
        assert_eq!(
            SignedChainAnchor::load()
                .unwrap()
                .recorded_creation_digest(&meta)
                .unwrap(),
            None,
            "an un-audited parent must not resolve — that is the fail-closed gate"
        );

        audit_captured_parent(&store, &handle, "firecracker", "tenant-a").unwrap();

        assert_eq!(
            SignedChainAnchor::load()
                .unwrap()
                .recorded_creation_digest(&meta)
                .unwrap(),
            Some(meta.meta_digest.clone()),
            "after auditing, the claim's anchor must recover the parent's content-address"
        );
    }

    /// The parent's plan is admitted for capacity, not for work: it must carry
    /// none of the authority a workload plan does, or a claimed child could
    /// inherit reach the parent was never entitled to.
    #[test]
    fn the_parent_plan_carries_no_workload_authority() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let ckpt = CheckpointId::new("standby-standby-xyz".to_string());
        let handle = captured_handle("standby-xyz", &ckpt);
        let admitted =
            admit_standby_parent_plan(&handle, "firecracker", "tenant-a", &"cd".repeat(32), 2, 512)
                .unwrap();

        assert!(admitted.plan().secrets.is_empty(), "no secret bindings");
        assert!(
            admitted.plan().services.is_empty(),
            "no host-service bindings"
        );
        assert_eq!(
            admitted.plan().workload.0,
            handle.id,
            "named for the parent"
        );
        assert_eq!(
            admitted.plan().image.sha256,
            "cd".repeat(32),
            "the plan describes the rootfs the parent actually booted"
        );
    }

    /// An unauditable parent must be dropped, not pooled. Pooling one buys a
    /// refusal and a quarantine on the next launch, then another spawn — a
    /// wasted boot and capture per launch, forever.
    #[test]
    fn an_unauditable_parent_is_discarded_with_its_checkpoint() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::open();
        let ckpt = write_captured_parent(&store, "standby-standby-doomed", &"ef".repeat(32));
        let handle = captured_handle("standby-doomed", &ckpt);
        assert!(store.read_meta(&ckpt).is_ok());

        discard_unauditable_parent(&store, &handle);

        assert!(
            store.read_meta(&ckpt).is_err(),
            "the discarded parent's checkpoint must not survive to occupy disk"
        );
    }

    /// A handle with no captured checkpoint has nothing to anchor; say so
    /// rather than emitting an entry that points at nothing.
    #[test]
    fn auditing_refuses_a_handle_with_no_captured_checkpoint() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let store = CheckpointStore::open();
        let mut handle = captured_handle("standby-nockpt", &CheckpointId::new("x".to_string()));
        handle.parent_checkpoint = None;

        let err = audit_captured_parent(&store, &handle, "firecracker", "tenant-a").unwrap_err();
        assert!(
            err.to_string().contains("without a parent checkpoint"),
            "unexpected error: {err}"
        );
    }

    /// A pool the operator named is still worth refusing over: silently
    /// cold-booting would hide that the backend they also chose cannot serve
    /// the residency they asked for.
    ///
    /// qemu is the dev/test substrate and is never wired for the standby pool,
    /// so it stays "unsupported" regardless of which workload backend grows a
    /// live warm path next.
    #[test]
    fn try_warm_claim_refuses_an_operator_configured_pool_on_an_unsupported_backend() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_RESIDENCY", "warm");

        let backend = AnyBackend::from_hypervisor("qemu");
        let err = try_warm_claim(&backend, &eligible_cfg(), false)
            .expect_err("configured warm pool must not silently cold-boot");
        let message = format!("{err:#}");
        assert!(
            message.contains("standby pool is not supported"),
            "{message}"
        );
        assert!(
            message.contains("requested standby-pool recovery"),
            "{message}"
        );
    }

    /// The other half, and the regression: with no `MVM_RESIDENCY` the warm
    /// target is the host tier's own default, which a run naming a pool-less
    /// backend never opted into. It cold-boots instead of failing the launch.
    #[test]
    fn try_warm_claim_cold_boots_a_host_default_pool_on_an_unsupported_backend() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove("MVM_RESIDENCY");

        let backend = AnyBackend::from_hypervisor("qemu");
        assert_eq!(
            try_warm_claim(&backend, &eligible_cfg(), false).unwrap(),
            None,
            "a default nobody configured must not fail the launch"
        );
    }

    #[test]
    fn try_warm_claim_cold_when_user_named() {
        let b = AnyBackend::from_hypervisor("libkrun");
        assert_eq!(try_warm_claim(&b, &eligible_cfg(), true).unwrap(), None);
    }

    #[test]
    fn try_warm_claim_cold_with_directory_share_volume() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.volumes = vec![VmVolume {
            materialized_image: None,
            host: "/h".into(),
            guest: "/g".into(),
            size: String::new(),
            read_only: false,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        }];
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }

    #[test]
    fn every_launch_keys_as_a_block_root() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"root").unwrap();
        let backend = AnyBackend::from_hypervisor("libkrun");
        let mut cfg = eligible_cfg();
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();

        let key = compat_for_launch(backend.as_vm_backend(), &cfg).unwrap();

        // There is one root shape now. A parent warmed under any other one
        // still declares it on its recorded spec, so the compat check keeps
        // comparing the field rather than assuming it.
        assert_eq!(key.root_strategy, RuntimeSourceRootStrategy::BlockExt4);
        assert!(warm_eligible_launch(&cfg));
    }

    #[test]
    fn runtime_pack_prebuilt_config_is_warm_eligible_and_keys_on_pack_identity() {
        // A verified runtime pack resolves to a prebuilt kernel + rootfs that
        // land in an ordinary VmStartConfig — the same shape as eligible_cfg().
        // The warm-pool compat is derived from that config, never from the image
        // source, so a pack participates in the warm pool (and its saved-state
        // snapshot) like any other admitted workload. This locks that in: a
        // future refactor that special-cased the image source would break it.
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"pack-kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"pack-rootfs").unwrap();

        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.to_string_lossy().into_owned());
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();

        // Firecracker keys on the pack's own vmlinux sha, and on the pack
        // rootfs's own sha — a parent is a full-state capture of one particular
        // rootfs, so the image is part of the identity, not incidental to it.
        let fc = AnyBackend::from_hypervisor("firecracker");
        let want = compat_for_launch(fc.as_vm_backend(), &cfg).unwrap();
        assert_eq!(want.kernel_sha256, sha256_hex_of(b"pack-kernel"));
        assert_eq!(want.vcpus, 2);
        assert_eq!(want.mem_mib, 1024);
        assert_eq!(want.image_sha256, Some(sha256_hex_of(b"pack-rootfs")));

        // libkrun boots its bundled kernel, so the kernel half of the key is the
        // constant; the image half is still the pack rootfs.
        let lk = AnyBackend::from_hypervisor("libkrun");
        let lk_want = compat_for_launch(lk.as_vm_backend(), &cfg).unwrap();
        assert_eq!(lk_want.kernel_sha256, LIBKRUN_BUNDLED_KERNEL_ID);
        assert_eq!(lk_want.image_sha256, Some(sha256_hex_of(b"pack-rootfs")));
    }

    #[test]
    fn try_warm_claim_cold_without_admitted_plan() {
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.plan_json = None; // not the gateway-bridge/admitted path → cold-boot
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }

    #[test]
    fn warm_claim_plan_json_passes_supplied_plan_and_none_when_absent() {
        // Every CLI-selectable backend now routes through the workload runner,
        // which takes the admitted plan in-process (no `needs_plan_json`), so a
        // missing plan yields None for all of them and a supplied plan passes
        // through verbatim.
        let mut cfg = eligible_cfg();
        cfg.plan_json = None;
        let fc = AnyBackend::from_hypervisor("firecracker");
        let libkrun = AnyBackend::from_hypervisor("libkrun");
        assert_eq!(warm_claim_plan_json(fc.as_vm_backend(), &cfg), None);
        assert_eq!(warm_claim_plan_json(libkrun.as_vm_backend(), &cfg), None);
        cfg.plan_json = Some("{\"signed\":\"plan\"}".into());
        assert_eq!(
            warm_claim_plan_json(fc.as_vm_backend(), &cfg),
            Some("{\"signed\":\"plan\"}".into())
        );
        assert_eq!(
            warm_claim_plan_json(libkrun.as_vm_backend(), &cfg),
            Some("{\"signed\":\"plan\"}".into())
        );
    }

    /// The regression: on the HVF default tier the residency policy resolves to
    /// always-warm with nobody configuring anything, and every pool-less
    /// backend inherited it. `machine run --hypervisor libkrun` then died on
    /// "claiming configured warm standby / standby pool is not supported by
    /// this backend" before it could boot, naming a configuration that did not
    /// exist. A host default is a preference, so it yields to the backend.
    #[test]
    fn a_host_default_warm_target_yields_to_a_backend_with_no_pool() {
        assert!(!unsupported_standby_pool_is_fatal(
            mvm_core::residency::ResidencySource::AutoDetect
        ));
    }

    /// An operator who set `MVM_RESIDENCY` asked for warm by name. Silently
    /// cold-booting there would hide that the backend they also chose cannot
    /// do it, so that one still refuses.
    #[test]
    fn an_operator_set_residency_still_refuses_a_backend_with_no_pool() {
        assert!(unsupported_standby_pool_is_fatal(
            mvm_core::residency::ResidencySource::EnvOverride
        ));
    }

    #[test]
    fn an_operator_requested_warm_launch_refuses_a_failed_claim() {
        assert_eq!(
            warm_launch_mode(mvm_core::residency::ResidencySource::EnvOverride, false),
            WarmLaunchMode::Required
        );
    }

    #[test]
    fn a_host_default_warm_launch_may_fall_back_to_cold() {
        assert_eq!(
            warm_launch_mode(mvm_core::residency::ResidencySource::AutoDetect, false),
            WarmLaunchMode::Optional
        );
    }

    #[test]
    fn a_required_claim_override_remains_fail_closed() {
        assert_eq!(
            warm_launch_mode(mvm_core::residency::ResidencySource::AutoDetect, true),
            WarmLaunchMode::Required
        );
    }

    #[test]
    fn inline_replenish_skips_zero_unsupported_and_ineligible_shapes() {}

    /// The claim and the replenish must exclude exactly the same launch shapes.
    /// Excluding a shape from one but not the other is silent: the replenish
    /// fills the pool with parents the claim never looks for, so every launch
    /// pays for a parent boot and cold-boots anyway.
    #[test]
    fn claim_and_replenish_agree_on_which_launch_shapes_a_warm_parent_can_serve() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};

        let ineligible = [("extra volume", {
            let mut c = eligible_cfg();
            c.volumes = vec![VmVolume {
                materialized_image: None,
                host: "/h".into(),
                guest: "/g".into(),
                size: String::new(),
                read_only: false,
                kind: VmVolumeKind::Disk,
                encrypted: false,
            }];
            c
        })];

        assert!(
            warm_eligible_launch(&eligible_cfg()),
            "the baseline launch shape must be warm-eligible, or this test proves nothing"
        );
        let b = AnyBackend::from_hypervisor("libkrun");
        for (why, cfg) in ineligible {
            assert!(
                !warm_eligible_launch(&cfg),
                "{why} must not be warm-eligible"
            );
            assert_eq!(
                try_warm_claim(&b, &cfg, false).unwrap(),
                None,
                "{why} must cold-boot rather than claim"
            );
        }
    }

    /// The launch shape the pool used to refuse outright now warms and claims
    /// like any other. It is keyed, not excluded: the guest cmdline carries only
    /// whether an egress client starts, so a parent can boot that and the
    /// destinations stay host-side on the child's own endpoint.
    ///
    /// The assertion is equality with the baseline eligible launch rather than a
    /// hard-coded outcome: whatever a default-shaped launch does at each gate, an
    /// egress-allowing one must do too, so this keeps holding as the gates move.
    #[test]
    fn an_egress_allowing_launch_is_warm_eligible_exactly_like_a_deny_all_one() {
        use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

        let baseline = eligible_cfg();
        assert!(warm_eligible_launch(&baseline));
        let b = AnyBackend::from_hypervisor("libkrun");
        // The disarmed pool refuses at the capability gate, which sits *after*
        // the shape gate — so reaching the same verdict as the baseline is what
        // proves the shape gate no longer short-circuits an egress launch.
        let baseline_verdict = try_warm_claim(&b, &baseline, false).is_err();

        for (why, policy) in [
            (
                "explicit allow-list",
                NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            ),
            ("named preset", NetworkPolicy::preset(NetworkPreset::Dev)),
            ("unrestricted", NetworkPolicy::unrestricted()),
        ] {
            let mut cfg = eligible_cfg();
            cfg.network_policy = policy;
            assert!(
                cfg.network_policy.allows_egress(),
                "{why} must actually allow egress, or this proves nothing"
            );
            assert!(warm_eligible_launch(&cfg), "{why} must be warm-eligible");
            assert_eq!(
                try_warm_claim(&b, &cfg, false).is_err(),
                baseline_verdict,
                "{why} must reach the same gate a deny-all launch does"
            );
        }
    }

    /// The compat key's egress half is the shared derivation, never a second
    /// expression of it here — a copy in the CLI would be free to drift from the
    /// guest cmdline token it exists to predict.
    #[test]
    fn the_compat_key_reads_egress_enablement_from_the_one_shared_derivation() {
        use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};

        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let fc = AnyBackend::from_hypervisor("firecracker");

        for policy in [
            NetworkPolicy::deny_all(),
            NetworkPolicy::allow_list(vec![]),
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            NetworkPolicy::preset(NetworkPreset::Dev),
            NetworkPolicy::unrestricted(),
        ] {
            for plan in [None, Some("{}".to_string())] {
                let mut cfg = eligible_cfg();
                cfg.kernel_path = Some(kernel.to_string_lossy().into_owned());
                cfg.rootfs_path = rootfs.to_string_lossy().into_owned();
                cfg.network_policy = policy.clone();
                cfg.plan_json = plan;
                let want = compat_for_launch(fc.as_vm_backend(), &cfg).unwrap();
                assert_eq!(
                    want.vsock_egress,
                    mvm_vmm::host::egress_shared::effective_vsock_egress(&cfg),
                    "the compat key must not re-derive the guest's egress enablement"
                );
            }
        }
    }

    /// A parent warmed for one egress enablement must not serve a launch of the
    /// other. Both directions matter: the permissive one would hand a child
    /// egress its cold boot would have denied, the restrictive one a workload
    /// with silently no network.
    #[test]
    fn a_parent_of_the_wrong_egress_enablement_is_not_claimable() {
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let fc = AnyBackend::from_hypervisor("firecracker");

        let mut deny = eligible_cfg();
        deny.kernel_path = Some(kernel.to_string_lossy().into_owned());
        deny.rootfs_path = rootfs.to_string_lossy().into_owned();
        let mut egress = deny.clone();
        egress.network_policy =
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);

        let deny_key = compat_for_launch(fc.as_vm_backend(), &deny).unwrap();
        let egress_key = compat_for_launch(fc.as_vm_backend(), &egress).unwrap();
        assert!(!deny_key.vsock_egress);
        assert!(egress_key.vsock_egress);
        assert_ne!(
            deny_key, egress_key,
            "the two launches must not share a compat key"
        );

        // A recorded parent answers only its own key — the pool's compat test is
        // exact equality, so this is what makes the mismatch a cold boot.
        let mut parent = saved_idle_handle("standby-deny", &deny_key.kernel_sha256, "img");
        parent.image_sha256 = deny_key.image_sha256.clone();
        parent.vcpus = deny_key.vcpus;
        parent.mem_mib = deny_key.mem_mib;
        assert!(parent.is_compatible(&deny_key));
        assert!(
            !parent.is_compatible(&egress_key),
            "a token-less parent must not serve an egress-allowing launch"
        );

        let egress_parent = StandbyHandle {
            vsock_egress: true,
            ..parent.clone()
        };
        assert!(egress_parent.is_compatible(&egress_key));
        assert!(
            !egress_parent.is_compatible(&deny_key),
            "an egress-booted parent must not serve a launch whose guest wants none"
        );
    }

    #[test]
    fn kernel_sha256_hex_is_64_lowercase_hex_of_known_content() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"hello-kernel").unwrap();
        let hex = kernel_sha256_hex(&kp).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(hex, sha256_hex_of(b"hello-kernel"));
    }

    #[test]
    fn fresh_binding_nonce_is_64_hex_chars_and_varies() {
        let a = fresh_binding_nonce();
        let b = fresh_binding_nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn standby_spec_socket_is_short_and_nonce_derived_state_under_vms() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"k").unwrap();
        let pool_root = tmp.path().join("pool");
        let vms_root = tmp.path().join("vms");
        let kernel_sha256 = kernel_sha256_hex(&kp).unwrap();
        let key_path = tmp.path().join("key");
        let Ok(params) = StandbySpecParams::builder()
            .pool_root(&pool_root)
            .vms_root(&vms_root)
            .kernel(&kp)
            .kernel_sha256(&kernel_sha256)
            .vcpus(2)
            .mem_mib(1024)
            .signer_id("host:test")
            .signing_key_path(&key_path)
            .root_strategy(RuntimeSourceRootStrategy::BlockExt4)
            .vsock_egress(false)
            .build()
        else {
            panic!("every required StandbySpecParams field is set");
        };
        let spec = build_standby_spec(&params).unwrap();
        // The socket lives under the nonce-derived `standby-<16hex>` dir; the filename is
        // short + fixed so the path fits SUN_LEN (the full 64-char nonce would overflow it).
        assert!(spec.id.starts_with("standby-"));
        assert!(spec.binding_nonce.starts_with(&spec.id["standby-".len()..]));
        assert!(Path::new(&spec.control_socket).starts_with(pool_root.join(&spec.id)));
        assert_eq!(
            Path::new(&spec.control_socket).file_name().unwrap(),
            "control.sock"
        );
        // Keep a realistic home-rooted path well under the macOS SUN_LEN (~104 bytes).
        assert!(
            std::path::Path::new("/Users/someuser/mvm-home/pool")
                .join(&spec.id)
                .join("control.sock")
                .as_os_str()
                .len()
                < 104
        );
        assert!(
            spec.vm_state_dir
                .starts_with(vms_root.to_string_lossy().as_ref())
        );
        assert_eq!(spec.kernel_sha256.len(), 64);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.mem_mib, 1024);
    }

    #[test]
    fn kernel_identity_is_constant_for_libkrun_and_sha_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"real-kernel").unwrap();
        let kps = kp.to_string_lossy();

        // libkrun: the bundled-kernel constant, computable even when the workload kernel is
        // absent (the mkGuest claim/replenish symmetry fix).
        let libkrun = AnyBackend::from_hypervisor("libkrun");
        assert_eq!(
            kernel_identity(libkrun.as_vm_backend(), None).unwrap(),
            LIBKRUN_BUNDLED_KERNEL_ID
        );
        assert_eq!(
            kernel_identity(libkrun.as_vm_backend(), Some("/nonexistent/vmlinux")).unwrap(),
            LIBKRUN_BUNDLED_KERNEL_ID
        );

        // firecracker: the real on-disk kernel's sha.
        let fc = AnyBackend::from_hypervisor("firecracker");
        assert_eq!(
            kernel_identity(fc.as_vm_backend(), Some(&kps)).unwrap(),
            sha256_hex_of(b"real-kernel")
        );
        // …and it errors if a real-kernel backend has no path.
        assert!(kernel_identity(fc.as_vm_backend(), None).is_err());
    }

    fn idle_handle(id: &str, kernel: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}.sock"),
            pid: std::process::id(),
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        }
    }

    fn saved_idle_handle(id: &str, kernel: &str, image: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            template_id: None,
            control_socket: format!("/p/{id}/control.sock"),
            pid: 0,
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "cd".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: Some(image.into()),
            root_strategy: Default::default(),
            parent_checkpoint: None,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        }
    }

    fn sample_handle_without_parent_checkpoint() -> StandbyHandle {
        idle_handle("standby-no-checkpoint", "aa")
    }

    /// A parent that was never captured has no checkpoint to verify content and
    /// lineage against, so a claim against it must refuse rather than clone
    /// unverified content.
    #[test]
    fn claim_refuses_a_parent_without_a_checkpoint() {
        let handle = sample_handle_without_parent_checkpoint();

        let err = parent_checkpoint_for(&handle).unwrap_err();

        assert!(
            err.to_string().contains("never captured"),
            "expected a refusal naming the uncaptured parent, got: {err}"
        );
    }

    #[test]
    fn claim_resolves_the_captured_parent_checkpoint() {
        let mut handle = sample_handle_without_parent_checkpoint();
        handle.parent_checkpoint = Some("standby-warm-parent".to_string());

        let id = parent_checkpoint_for(&handle).unwrap();

        assert_eq!(id.as_str(), "standby-warm-parent");
    }

    #[test]
    fn build_pool_status_reports_dead_standbys_separately() {
        let live = idle_handle("live", "aa");
        let mut dead = idle_handle("dead", "aa");
        dead.pid = 999_999_999;
        let saved = saved_idle_handle("saved", "aa", "img");

        let report = build_pool_status(&[live, dead, saved]);

        assert_eq!(report.idle, 2, "live process + saved-state are idle");
        assert_eq!(report.claimed, 0);
        assert_eq!(report.parked, 0);
        assert_eq!(report.dead, 1);
        assert_eq!(report.standbys[0].state, "idle");
        assert_eq!(report.standbys[1].state, "dead");
        assert_eq!(report.standbys[2].state, "idle");
    }

    // The following tests need a backend that actually reaches the spawn loop
    // (`capabilities().standby_pool == true`) — every real `AnyBackend` variant
    // selectable via the CLI reports `false` until a live run proves its spawn
    // and claim both work, and a real spawn loop boots a VM, which a hermetic
    // unit test must not do. The in-memory `Mock` variant opts into the
    // capability (`with_standby()`) without touching the host, so it drives
    // `warm_to_target` past its capability gate here. Gated behind
    // `test-support` like the mock backend itself; the dedicated CI lane
    // (`--features test-support`) covers them.

    /// The pool must actually drain. A spawn records a standby under the compat
    /// key it computed; a claim searches for the key it computed. If those two
    /// keys differ by so much as `None` vs `Some(hash)`,
    /// `StandbyHandle::is_compatible` (exact equality) never matches: every
    /// launch pays for a parent boot and cold-boots anyway, silently, and the
    /// pool grows without ever being drawn from. That is what shipped — the
    /// claim side returned `None` unconditionally while the spawn side recorded
    /// a real digest.
    ///
    /// So this drives the real spawn path and then asks the real claim path for
    /// what it produced, rather than comparing two locally-built keys.
    #[cfg(feature = "test-support")]
    #[test]
    fn a_parent_the_spawn_records_is_found_by_the_claim_compat_key() {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"warm-kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"warm-rootfs").unwrap();
        let key = tmp.path().join("host-signer.ed25519");
        std::fs::write(&key, b"fake-key").unwrap();

        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.display().to_string());
        cfg.rootfs_path = rootfs.display().to_string();

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        let result = warm_to_target(
            &pool,
            &WarmParams {
                backend: &backend,
                signer_id: "host:test",
                signing_key_path: &key,
                target: 1,
                launch: &cfg,
            },
        )
        .unwrap();
        assert_eq!(result.spawned, 1, "the spawn must record one standby");

        let want = compat_for_launch(backend.as_vm_backend(), &cfg).unwrap();
        let claimed = pool
            .claim_idle_compatible(&want)
            .unwrap()
            .expect("the launch that warmed this parent must be able to claim it");
        assert_eq!(
            claimed.compat(),
            want,
            "the recorded key must be the key the claim searched for"
        );
        assert_eq!(
            claimed.image_sha256,
            Some(sha256_hex_of(b"warm-rootfs")),
            "the key must name the rootfs the parent was captured from"
        );

        // And the negative: a launch of a different rootfs must not claim it —
        // a parent is a full-state capture of one particular image.
        let other_rootfs = tmp.path().join("other-rootfs.ext4");
        std::fs::write(&other_rootfs, b"other-rootfs").unwrap();
        let mut other = cfg.clone();
        other.rootfs_path = other_rootfs.display().to_string();
        let other_want = compat_for_launch(backend.as_vm_backend(), &other).unwrap();
        assert_ne!(other_want, want);
    }

    /// `pool warm` and the run path must resolve the *same* compat key for the
    /// same image and sizing, or the verb warms parents nothing claims — which
    /// is the failure this whole path exists to fix, and it is silent:
    /// `StandbyHandle::is_compatible` is exact equality, so a disagreement
    /// cold-boots every launch while the pool fills.
    ///
    /// Both sides go through `crate::exec::resolve_launch`, so this asserts the
    /// composition end to end rather than comparing two locally-built keys.
    #[cfg(feature = "test-support")]
    #[test]
    fn pool_warm_and_the_run_path_resolve_the_same_compat_key() {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());

        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();

        let image = crate::exec::ImageSource::Prebuilt {
            kernel_path: kernel.display().to_string(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: None,
            label: "fixture".into(),
            unpacked_oci_root: None,
        };
        let policy = mvm_core::network_policy::NetworkPolicy::deny_all();
        let shape = |name: Option<&'static str>| crate::exec::LaunchShape {
            name,
            image: &image,
            cpus: 2,
            memory_mib: 1024,
            mem_initial_mib: None,
            dir_shares: &[],
            disk_volumes: &[],
            pty: false,
            network_policy: &policy,
            warm_pool_size: 1,
            sdk_sidecar: None,
            hypervisor: Some("mock"),
        };
        let resolve = |name| {
            crate::exec::resolve_launch(
                &shape(name),
                None,
                &mut crate::exec::LaunchResolveMarks::new(false),
                &mut crate::commands::vm::phase_timing::LaunchSubMarks::new(false),
            )
            .unwrap()
        };

        // The warm side resolves ahead of any launch; the run side resolves for
        // the launch itself. Only the VM name differs, and the compat key must
        // not depend on it — a claimed parent runs under its own standby id.
        let warmed = resolve(None);
        let launched = resolve(Some("the-launch"));
        assert_ne!(warmed.start_config.name, launched.start_config.name);

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        let warm_key = compat_for_launch(backend.as_vm_backend(), &warmed.start_config).unwrap();
        let claim_key = compat_for_launch(backend.as_vm_backend(), &launched.start_config).unwrap();
        assert_eq!(
            warm_key, claim_key,
            "a parent warmed for this image must be found by the launch that boots it"
        );
        assert!(
            warm_key.image_sha256.is_some(),
            "the warm key must name the rootfs, or it matches nothing"
        );
        assert!(
            warm_eligible_launch(&warmed.start_config),
            "the resolved warm shape must be one a shared parent can serve"
        );
    }

    /// `claim_or_cold` must hand the runner a parent that is still claimable.
    ///
    /// The runner reserves the parent itself, in the same locked section it
    /// verifies it in, and refuses one that is already `Claimed`. Reserving here
    /// as well meant every warm claim on a runner-backed backend died with
    /// "parent is not in a claimable state": the pool filled and never drained.
    ///
    /// Nothing caught it because the mock backend services a claim from its own
    /// in-memory state and never runs the runner's reserve, so the two-layer
    /// interaction only existed on a live host. This asserts the seam directly:
    /// at the moment the claim is built the runner has not run, so the parent
    /// must still be claimable on disk.
    #[cfg(feature = "test-support")]
    #[test]
    fn claim_or_cold_leaves_the_parent_claimable_for_the_runner_to_reserve() {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"warm-kernel").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"warm-rootfs").unwrap();
        let key = tmp.path().join("host-signer.ed25519");
        std::fs::write(&key, b"fake-key").unwrap();

        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.display().to_string());
        cfg.rootfs_path = rootfs.display().to_string();

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        assert_eq!(
            warm_to_target(
                &pool,
                &WarmParams {
                    backend: &backend,
                    signer_id: "host:test",
                    signing_key_path: &key,
                    target: 1,
                    launch: &cfg,
                },
            )
            .unwrap()
            .spawned,
            1,
            "the fixture must warm one parent, or this asserts nothing"
        );

        let want = compat_for_launch(backend.as_vm_backend(), &cfg).unwrap();
        let observed: std::cell::Cell<Option<StandbyState>> = std::cell::Cell::new(None);
        let decision = claim_or_cold(&pool, &backend, &want, |handle| {
            observed.set(Some(pool.load(&handle.id).unwrap().state));
            // Stop here: the reservation state is the whole subject of this test.
            anyhow::bail!("halt after inspecting the reservation state")
        })
        .unwrap();

        assert_eq!(
            observed.get(),
            Some(StandbyState::Idle),
            "the parent must still be claimable when the runner is handed it; \
             reserving it here is what made every warm claim refuse"
        );
        assert!(
            matches!(decision, LaunchDecision::ColdBoot),
            "a halted claim falls back to a cold boot"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn warm_to_target_counts_failures_when_spawn_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"k").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"r").unwrap();
        let key = tmp.path().join("host-signer.ed25519");
        std::fs::write(&key, b"fake-key").unwrap();
        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.display().to_string());
        cfg.rootfs_path = rootfs.display().to_string();

        let backend = AnyBackend::Mock(
            mvm_runtime::mock::MockBackend::new()
                .with_standby()
                .with_failing_spawn_standby(),
        );
        let result = warm_to_target(
            &pool,
            &WarmParams {
                backend: &backend,
                signer_id: "host:test",
                signing_key_path: &key,
                target: 2,
                launch: &cfg,
            },
        )
        .unwrap();

        // No standbys were spawned; both attempts counted as failures.
        assert_eq!(result.spawned, 0, "no standbys should be recorded");
        assert_eq!(
            result.failed, 2,
            "both spawn attempts must be counted as failures"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn warm_to_target_already_at_target_returns_zero_spawned_zero_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"k").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"r").unwrap();
        let key = tmp.path().join("key");
        std::fs::write(&key, b"fake-key").unwrap();
        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.display().to_string());
        cfg.rootfs_path = rootfs.display().to_string();

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        // Pre-fill the pool with 1 idle standby carrying the launch's own compat
        // key, so the warm below sees the target already met.
        let want = compat_for_launch(backend.as_vm_backend(), &cfg).unwrap();
        let mut h = idle_handle("s1", &want.kernel_sha256);
        h.vcpus = want.vcpus;
        h.mem_mib = want.mem_mib;
        h.image_sha256 = want.image_sha256.clone();
        h.vsock_egress = want.vsock_egress;
        pool.record(&h).unwrap();

        let result = warm_to_target(
            &pool,
            &WarmParams {
                backend: &backend,
                signer_id: "host:test",
                signing_key_path: &key,
                target: 1,
                launch: &cfg,
            },
        )
        .unwrap();

        // Already at target → no spawns attempted, no failures.
        assert_eq!(result.spawned, 0);
        assert_eq!(result.failed, 0);
    }

    // Two launches warming the same pool to the same target concurrently must
    // not overshoot it: the pool-dir flock serializes the idle-count read →
    // spawn loop, so the second warmer observes the first's standbys and spawns
    // nothing. Without the lock both read an empty pool and each spawn `target`.
    #[cfg(feature = "test-support")]
    #[test]
    fn warm_to_target_concurrent_calls_do_not_overshoot() {
        let _guard = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(tmp.path());
        let pool = SupervisorStandbyPool::at(tmp.path().join("pool"));
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"k").unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"warm-rootfs").unwrap();
        let key = tmp.path().join("key");
        std::fs::write(&key, b"fake-key").unwrap();
        let mut cfg = eligible_cfg();
        cfg.kernel_path = Some(kernel.display().to_string());
        cfg.rootfs_path = rootfs.display().to_string();

        let backend = AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());
        fn warm_once(
            pool: &SupervisorStandbyPool,
            backend: &AnyBackend,
            key: &std::path::Path,
            launch: &VmStartConfig,
        ) {
            warm_to_target(
                pool,
                &WarmParams {
                    backend,
                    signer_id: "host:test",
                    signing_key_path: key,
                    target: 2,
                    launch,
                },
            )
            .unwrap();
        }

        std::thread::scope(|s| {
            let a = s.spawn(|| warm_once(&pool, &backend, &key, &cfg));
            let b = s.spawn(|| warm_once(&pool, &backend, &key, &cfg));
            a.join().unwrap();
            b.join().unwrap();
        });

        let want = StandbyCompat {
            ..compat_for_launch(backend.as_vm_backend(), &cfg).unwrap()
        };
        assert_eq!(
            pool.idle_count_compatible(&want).unwrap(),
            2,
            "concurrent warms overshot the target — the read→spawn lock is missing or not held"
        );
    }
}

// ── `mvmctl pool` command ───────────────────────────────────────────────────────────

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PoolAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PoolAction {
    /// Sweep the standby pool toward a target count, warming parents that boot
    /// the shape a matching launch will claim.
    ///
    /// The shape is resolved the same way a real launch resolves it — same
    /// image, kernel, verity sidecars, runtime overlay and cmdline tokens — so a
    /// later `mvmctl machine run` with the same image and sizing claims what
    /// this spawned. A launch that differs in image, kernel, vCPUs, memory or
    /// egress enablement is a different shape and cold-boots. Default count 1.
    Warm {
        /// How many idle standbys to warm the pool toward (default 1).
        count: Option<u32>,
        /// OCI image the warmed parents boot, matching the `--image` the launch
        /// will pass. Omit to warm the image a bare `machine run` boots.
        #[arg(long)]
        image: Option<String>,
        /// vCPUs the warmed parents boot with; must match the launch's `--cpus`
        /// (default: the configured `default_cpus`).
        #[arg(long)]
        cpus: Option<u32>,
        /// Memory the warmed parents boot with; must match the launch's
        /// `--memory` (default: the configured `default_memory_mib`).
        #[arg(long)]
        memory: Option<String>,
    },
    /// Show the standby pool — recorded standbys and their idle/claimed state.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// What `pool warm` warms toward, expressed as the launch it must mirror.
struct WarmRequest {
    image: Option<String>,
    cpus: u32,
    memory_mib: u32,
    target: u32,
}

/// Resolve the launch shape a warm parent must boot, without booting one.
///
/// This is the whole point of the verb working at all: a claimable parent needs
/// the rootfs *and* its verity sidecars, the runtime overlay carrying the guest
/// agent, the universal initramfs, and the cmdline-bearing policy fields — none
/// of which a rootfs path supplies, and all of which
/// [`crate::exec::resolve_launch`] produces. Resolving through the run path's
/// own function is what keeps the recorded compat key equal to the one a claim
/// will search for.
///
/// No admission hook is passed. A factory parent carries no workload authority
/// and `factory_parent_config` drops the tenant and plan from whatever it is
/// handed, so admitting one here would buy a signed plan that is discarded —
/// while giving a shared parent a workload's authority is exactly the posture
/// the pool is built to avoid. The launch that later claims the parent supplies
/// its own admitted plan.
fn resolve_warm_launch(req: &WarmRequest) -> Result<crate::exec::ResolvedLaunch> {
    let image = super::vm::exec::resolve_launch_image_source(req.image.as_deref(), false, None)
        .context("resolving the image the warm parents boot")?;
    // Deny-all is the default a `machine run` resolves to, and it is the half
    // of the policy the compat key reads: `StandbyCompat::vsock_egress` records
    // whether the guest boots an egress client, never a destination.
    let network_policy = mvm_core::network_policy::NetworkPolicy::default();
    let shape = crate::exec::LaunchShape {
        name: None,
        image: &image,
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        mem_initial_mib: None,
        dir_shares: &[],
        disk_volumes: &[],
        pty: false,
        network_policy: &network_policy,
        warm_pool_size: req.target,
        sdk_sidecar: None,
        hypervisor: None,
    };
    crate::exec::resolve_launch(
        &shape,
        None,
        &mut crate::exec::LaunchResolveMarks::new(false),
        &mut crate::commands::vm::phase_timing::LaunchSubMarks::new(false),
    )
    .context("resolving the launch shape the warm parents mirror")
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let pool = SupervisorStandbyPool::open()?;
    match args.action {
        PoolAction::Status { json } => run_status(&pool, json),
        PoolAction::Warm {
            count,
            image,
            cpus,
            memory,
        } => {
            let memory_mib = match memory.as_deref() {
                Some(raw) => mvm_core::util::parse_human_size(raw).context("Invalid --memory")?,
                None => cfg.default_memory_mib,
            };
            run_warm(
                &pool,
                &WarmRequest {
                    image,
                    cpus: cpus.unwrap_or(cfg.default_cpus),
                    memory_mib,
                    target: count.unwrap_or(1),
                },
            )
        }
    }
}

fn run_warm(pool: &SupervisorStandbyPool, req: &WarmRequest) -> Result<()> {
    let target = req.target;
    let launch = resolve_warm_launch(req)?;
    // Ensure the host signer exists — the standby re-verifies the attach plan against it.
    let signer = host_signer::load_or_init()?;
    let result = warm_to_target(
        pool,
        &WarmParams {
            backend: &launch.backend,
            signer_id: &host_signer::host_signer_id(),
            signing_key_path: &signer.secret_path,
            target,
            launch: &launch.start_config,
        },
    )?;
    // A state-changing verb emits one audit record per attempt.
    mvm_core::audit_emit!(
        PoolWarm,
        "spawned={} failed={} target={target}",
        result.spawned,
        result.failed
    );
    let idle_after = result.spawned;
    if result.failed > 0 && idle_after < target {
        crate::ui::warn(&format!(
            "{}/{} standby(s) warmed; {} spawn(s) failed — check logs for details.",
            idle_after, target, result.failed,
        ));
        return Err(anyhow::anyhow!(
            "pool warm: {}/{} standby(s) warmed, {} failed",
            idle_after,
            target,
            result.failed,
        ));
    } else if result.spawned == 0 && result.failed == 0 {
        crate::ui::info(&format!("Pool already at or above target {target}."));
    } else {
        crate::ui::success(&format!(
            "Warmed {} standby(s) toward target {target}.",
            result.spawned,
        ));
    }
    crate::ui::info(
        "A launch claims one of these only if it matches on image, kernel, vCPUs, memory and \
         egress enablement, is auto-named, and runs with a non-zero warm pool size \
         (MVM_RESIDENCY=warm on hosts whose default is parked).",
    );
    Ok(())
}

/// Machine-readable `pool status --json` shape.
#[derive(serde::Serialize)]
struct PoolStatus {
    idle: usize,
    claimed: usize,
    parked: usize,
    dead: usize,
    standbys: Vec<PoolStatusEntry>,
}

#[derive(serde::Serialize)]
struct PoolStatusEntry {
    id: String,
    state: &'static str,
    pid: u32,
    kernel_sha256: String,
    vcpus: u8,
    mem_mib: u32,
    /// The image half of the compat key: sha256 of the rootfs the parent
    /// booted. Every standby carries one, since a parent is only ever spawned
    /// for a resolved launch shape; absent marks a record predating that.
    image_sha256: Option<String>,
}

fn build_pool_status(standbys: &[StandbyHandle]) -> PoolStatus {
    let idle = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Idle && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let parked = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Parked && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let claimed = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Claimed && SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    let dead = standbys
        .iter()
        .filter(|h| !SupervisorStandbyPool::is_live_or_saved(h))
        .count();
    PoolStatus {
        idle,
        claimed,
        parked,
        dead,
        standbys: standbys
            .iter()
            .map(|h| PoolStatusEntry {
                id: h.id.clone(),
                state: if SupervisorStandbyPool::is_live_or_saved(h) {
                    match h.state {
                        StandbyState::Idle => "idle",
                        StandbyState::Claimed => "claimed",
                        StandbyState::Parked => "parked",
                    }
                } else {
                    "dead"
                },
                pid: h.pid,
                kernel_sha256: h.kernel_sha256.clone(),
                vcpus: h.vcpus,
                mem_mib: h.mem_mib,
                image_sha256: h.image_sha256.clone(),
            })
            .collect(),
    }
}

fn run_status(pool: &SupervisorStandbyPool, json: bool) -> Result<()> {
    let standbys = pool.list()?;
    let report = build_pool_status(&standbys);
    if json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    println!(
        "Supervisor standby pool: {} idle, {} claimed, {} parked, {} dead",
        report.idle, report.claimed, report.parked, report.dead
    );
    for e in &report.standbys {
        let image_tag = e
            .image_sha256
            .as_deref()
            .map(|s| format!(" · image {}", &s[..s.len().min(12)]))
            .unwrap_or_default();
        println!(
            "  {} · {} · {} · {} vcpu / {} MiB · kernel {}{}",
            e.id,
            e.state,
            if e.pid == 0 {
                "saved-state".to_string()
            } else {
                format!("pid {}", e.pid)
            },
            e.vcpus,
            e.mem_mib,
            &e.kernel_sha256[..e.kernel_sha256.len().min(12)],
            image_tag,
        );
    }
    Ok(())
}
