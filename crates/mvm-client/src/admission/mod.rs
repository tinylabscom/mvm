//! Signed `ExecutionPlan` admission for a boot — synthesize, sign, verify,
//! and audit-emit the plan right before a backend `start()`.
//!
//! Every boot path admits through here: the CLI's transient runs, entrypoints,
//! sessions, checkpoint forks and persistent starts, and the host library the
//! SDKs load. It lives in the client rather than the CLI so that one request is
//! admitted under one plan whoever makes it.
//!
//! The pieces a boot needs around admission itself sit in sibling modules and
//! are re-exported here: the guest boot-config attachments (host-signer
//! pubkey, security policy) in `boot_config`, the launch-outcome audit
//! records in `outcome`, and the boot-time share/kernel enforcement gates in
//! `enforce`.

use anyhow::{Context, Result, bail};

use mvm_core::deploy_record::{BootArtifactIdentity, read_deploy_record, verify_boot_artifact};
use mvm_core::plan::{StreamRetention, SynthesisInput, Variant};
pub use mvm_hostd::plan_admission::{
    AdmittedPlan, BundleAdmissionContext, BundleImageAdmissionContext, InMemoryNonceLedger,
    RunPosture, SystemClock, admit_for_run, populate_audit_substrate,
    stash_plan_and_mint_verb_grant, stash_plan_for_bridge,
};

use crate::admission::entrypoint_resolve::ResolvedEntrypoint;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::host_keypair::load_or_init_at;

use self::audit::{
    PolicyResolutionKind, build_default_audit_emitter, emit_bundle_environment_refused,
    emit_bundle_posture_refused, emit_policy_resolved,
};
use self::policy::{egress_destinations, generated_policy_ref};

pub mod agent_verbs;
mod audit;
mod boot_config;
mod bundle_binding;
pub mod bundle_environment;
pub mod bundle_posture;
pub mod bundle_resources;
mod cli_dispatch;
mod durability;
pub mod entrypoint_resolve;
pub mod instructions;
pub mod mailbox_grant;
mod outcome;
mod pinned_bundle;
pub mod policy;
pub mod run_grants;
pub mod run_network;
pub mod run_routes;
pub mod run_secrets;
pub mod secrets;

pub use boot_config::{
    SECURITY_POLICY_FILENAME, attach_guest_boot_config, attach_guest_boot_config_for_plan,
    attach_guest_security_policy_config, attach_host_signer_pubkey_config_for_plan,
    guest_profile_for_boot,
};
pub use bundle_binding::{BundlePin, InheritedBundle};
pub use cli_dispatch::{CliStartFailureKind, cli_start_failure_kind};
pub use durability::{
    admit_plan_for_boot_syncing_beside_boot,
    admit_plan_for_boot_with_verified_runtime_syncing_beside_boot,
};
pub use instructions::InstructionSources;
pub use outcome::{
    BootPosture, StartMode, emit_failed, emit_launched, record_uncertain_restore_stop,
};
pub(crate) use outcome::{record_boot, seal_recorded_failure};

/// A content-bound asset. Operator-declared files and internally selected
/// signed packs are recorded in the plan without sharing them with the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetSpec {
    /// An operator-declared host file or directory to hash.
    File {
        kind: mvm_contract::plan::AssetKind,
        host_path: String,
    },
    /// An internally selected signed pack; never accepted from `--asset`.
    RegistryPack(mvm_core::registry_pack::PackPin),
    /// The resident owner's exact project-policy generation and closure.
    /// Host admission revalidates it before signing; it is not a host file.
    CommittedPolicy(mvm_core::plan::AssetIdentity),
}

pub struct AdmitPlanForBootParams<'a> {
    /// What this launch took from its bundle's recorded sizing. Recorded in
    /// the `plan.admitted` labels, with the requested figure beside the applied
    /// one when a cap lowered it. `cpus` and `mem_mib` already hold the result.
    pub bundle_sizing: bundle_resources::AppliedSizing,
    /// Mailbox this launch grants, minted into the plan before signing.
    pub mailbox: Option<mvm_contract::protocol::mailbox::MailboxGrant>,
    pub tenant: &'a str,
    pub vm_name: &'a str,
    pub backend_name: &'a str,
    /// Local image checkout selected by the process entry point, if any.
    ///
    /// Admission consumes this captured value instead of rereading
    /// `MVM_IMAGES_DIR`. Besides making the authority explicit for library
    /// callers, that keeps one admission stable if unrelated code changes the
    /// process environment concurrently.
    pub configured_images_dir: Option<&'a std::path::Path>,
    pub rootfs_path: &'a std::path::Path,
    /// The kernel this launch will boot, pinned into the plan's
    /// `EnvironmentRef` and re-checked by the admitted-environment gate.
    ///
    /// `None` only for backends that carry their own kernel (libkrun's
    /// bundled image, the mock). For everything else this must be the same
    /// path handed to the backend: the image digest says what the workload
    /// *is* and says nothing about what confines it, so a plan that names the
    /// image but not the kernel admits a workload onto whatever kernel the
    /// host happened to have cached.
    pub kernel_path: Option<&'a std::path::Path>,
    /// Skip re-hashing `rootfs_path` and admit with this sha256 instead.
    /// Only sound when a fail-closed integrity check re-hashes the same
    /// bytes before boot (the checkpoint fork path: `verify_content`
    /// refuses a tampered blob before any supervisor spawns) — a
    /// mismatch then aborts the launch, never boots a mis-admitted image.
    pub precomputed_image_sha256: Option<String>,
    /// Optional deploy-record identity for the exact rootfs selected by this
    /// boot. When present, both labeled digests and the byte count are
    /// reverified before plan synthesis.
    pub boot_artifact_identity: Option<&'a BootArtifactIdentity>,
    /// The exact selected runtime, verified before it can contribute assurance.
    pub runtime_config: Option<&'a mvm_core::vm_backend::VmStartConfig>,
    pub cpus: u32,
    pub mem_mib: u64,
    /// The transport this launch gives the guest, recorded on the plan.
    ///
    /// Was hardcoded to `Default::default()` — `NetworkMode::None`, whose own
    /// doc reads "no guest NIC, no broker, the workload cannot reach the
    /// network" — while every ordinary launch derives `HostVsockProxy` and the
    /// host stands a broker up for it. The signed record said the workload had
    /// no path to the network while it was being given one.
    pub network_mode: mvm_contract::plan::NetworkMode,
    pub seccomp_tier: mvm_core::plan::PlanSeccompTier,
    pub secret_release: mvm_core::plan::SecretReleasePolicy,
    pub secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Opaque caller commitment copied into the plan and its audit entries.
    pub caller_commitment: Option<mvm_core::plan::CallerCommitment>,
    pub ledger: &'a InMemoryNonceLedger,
    /// Override for the host-signer keys directory. Production callers
    /// pass `None`, which resolves to `~/.mvm/keys/`; tests pass a
    /// tempdir so they don't write into the real user's home.
    pub keys_dir: Option<&'a std::path::Path>,
    /// Override for the audit-chain directory (`~/.mvm/audit/`).
    /// Tests inject a tempdir; production passes `None`.
    pub audit_dir: Option<&'a std::path::Path>,
    /// Optional path to a `.mvmpkg` bundle archive. When set, the
    /// archive is read + verified at admit time, the resulting
    /// `PlanArtifact` is embedded into the plan, and the supervisor's
    /// admit path re-verifies on every launch. Once the plan is
    /// admitted, the boot's root filesystem and kernel must be the
    /// ones the bundle signed, and an installed copy beside the archive
    /// must still match it; a mismatch is refused and recorded as
    /// `plan.failed`. Boots resolved from an installed bundle
    /// (`--manifest <bundle-sha256>`) set it to the registry archive.
    /// A child forked or restored from a parent whose plan pins a bundle
    /// inherits that pin ([`InheritedBundle`]): the archive is re-verified
    /// and must still be the bundle the parent was admitted under.
    pub bundle_pin: Option<BundlePin<'a>>,
    /// The signed security posture of the installed bundle this run boots,
    /// when it boots one. The launch may only narrow it: admission refuses a
    /// run whose network policy, host shares, or agent verbs ask for more,
    /// and records the refusal as `plan.failed`. A pinned bundle's own
    /// posture is checked the same way.
    pub bundle_posture: Option<mvm_core::plan::BundleSecurityPosture>,
    /// Optional deps-volume binding from the app-deps install pipeline.
    /// No boot path supplies one today. When `Some`, the
    /// synthesised `ExecutionPlan` carries `deps_volume = Some(...)`,
    /// and the supervisor's admission gate re-verifies
    /// the on-disk sealed volume before launch — claim 9.
    /// `None` preserves the claim-8 baseline (no deps gate).
    pub deps_volume: Option<mvm_core::plan::DepsVolumeBinding>,
    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`) baked
    /// into the signed plan + emitted to the chain-signed audit log
    /// (claim 1 / claim 8). Empty for the common no-volume case.
    pub shares: Vec<mvm_core::plan::HostShareGrant>,
    /// Declared `--asset KIND:HOST_PATH` bindings hashed into content
    /// identities at admission and recorded in the signed plan's
    /// `asset_identities` (with the environment, bundle, deps volume,
    /// digested shares, and the resolved network policy). Empty for runs
    /// that declare no assets.
    pub assets: Vec<AssetSpec>,
    /// Output grants recorded in the signed plan: which guest directories the
    /// workload may hand back, where they land on the host, and the bounds the
    /// collection enforces. Each must be backed by a writable disk in `shares`.
    pub outputs: Vec<mvm_core::plan::OutputGrant>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// Default (all-off) preserves the curated-only baseline.
    pub redaction: mvm_core::policy::RedactionPolicy,
    /// The resolved runtime egress policy (`--allow-host`,
    /// template default, or deny-all default). Its content digest is bound
    /// into the signed plan as a policy asset identity, and the per-VM egress
    /// gate enforces exactly this policy.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    /// Raw `--agent-verb` strings from the CLI. Empty ⇒ use the computed
    /// default. Validated inside `admit_plan_for_boot` via
    /// `parse_agent_verb_override`; any unknown/DevOnly verb is an error.
    pub agent_verb_override: Vec<String>,
    /// Host services this workload is authorized to call over the broker
    /// channel, baked into the signed plan. The broker's dispatch gate refuses
    /// anything absent from this set, and the launch path reads the same set to
    /// decide whether the optional glibc SDK sidecar must be attached. Empty
    /// (the common case) means the workload calls no host service.
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// Whether this launch arms the GPU remoting plane. Its shims dial the
    /// host GPU endpoint over vsock from inside the workload, so admission
    /// raises the seccomp tier to one that opens `AF_VSOCK` sockets.
    pub gpu: bool,
    /// True iff this run should receive an attenuated (ProdSafe-only) agent-verb
    /// grant. Set this with `grant_eligible(pty, has_ad_hoc_argv, is_dev_profile)`.
    /// Interactive / ad-hoc / dev runs must pass `false`: they issue DevOnly verbs
    /// (ConsoleOpen, Exec) that a ProdSafe grant would refuse.
    pub restrict_agent_verbs: bool,
    /// What the caller worked out this image will run.
    ///
    /// Feeds [`entrypoint_is_shell_shaped`], which refuses the workload input
    /// grant under a sealed production posture (`restrict_agent_verbs`) when
    /// the entrypoint looks like a shell.
    /// [`Unresolved`](ResolvedEntrypoint::Unresolved) refuses that grant too:
    /// a launch that cannot say what it runs has not established that what it
    /// runs is not a shell, and admitting on that basis would leave a control
    /// that reports present and never fires. Callers that never request the
    /// input grant may pass `Unresolved` freely — the check is reached only
    /// through the grant.
    pub entrypoint: ResolvedEntrypoint,
    /// What this workload is permitted to consume or reach, as resolved from
    /// the surfaces that may author one (CLI flags, a JSON grants file, the
    /// project manifest, the operator's host config). Baked into the signed
    /// plan and checked against the host's ceiling inside `admit_for_run`. Its
    /// egress dimension is already reflected in
    /// [`network_policy`](Self::network_policy), which the caller derived from
    /// the same resolution.
    ///
    /// `None` means no surface authored anything, which is the pre-grant
    /// baseline: no CPU cap, no wall-clock bound, deny-all egress.
    pub grants: Option<mvm_contract::grants::Grants>,
    /// The backend this run will actually boot on, when the caller has one in
    /// hand. Admission measures a declared grant against the mechanisms that
    /// tier really has; without it a sealed run refuses a grant whose
    /// enforceability nothing can confirm, and a dev run is warned. Taken from
    /// the backend object, never parsed from
    /// [`backend_name`](Self::backend_name) — a name is a label, and a grant
    /// checked against a label is checked against whatever the caller typed.
    pub backend_kind: Option<mvm_contract::protocol::vm_backend::BackendKind>,
    /// Where instruction-file provenance looks beyond `shares` and `assets`:
    /// the workload's own source directory, and an override for the user
    /// policy. Every instruction file the boot copies into the guest is
    /// verified against that policy before the boot is admitted.
    pub instructions: InstructionSources<'a>,
}

/// Shell basenames [`entrypoint_is_shell_shaped`] refuses on direct match.
/// A superset of `mvm_contract::entrypoint`'s own shell set: that helper
/// treats a bare `busybox` invocation (no applet argument) as safe, because
/// for the SDK-declaration gate it validates an applet name is what matters.
/// Here a bare `busybox` is itself the risk — invoked with no arguments it
/// drops into an interactive shell — so it is refused directly rather than
/// only when a shell applet is named.
const DIRECT_SHELL_BASENAMES: &[&str] =
    &["sh", "bash", "dash", "ash", "busybox", "zsh", "ksh", "fish"];

/// Last path segment of `program`. A local stand-in for
/// `std::path::Path::file_name()`: an entrypoint argv element is wire/JSON
/// data (a plain string), not a host filesystem path, and may use either
/// separator.
fn program_basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

/// Whether `argv`'s own program name is a direct shell match, reusing
/// `mvm_contract::entrypoint`'s argv/env/busybox-applet resolution for
/// everything except the bare-`busybox` case it deliberately excludes.
fn argv_is_shell(argv: &[String]) -> bool {
    argv.first()
        .is_some_and(|prog| DIRECT_SHELL_BASENAMES.contains(&program_basename(prog)))
        || mvm_contract::entrypoint::detect_shell_entrypoint_argv(argv).is_some()
}

/// Whether a resolved entrypoint is shell-shaped, per the design's rule for
/// refusing the workload input grant under a sealed production posture: its
/// own argv names a shell (directly, via `env`, or as a busybox applet, or
/// busybox itself), its script shebang names one, or the argv carries an
/// inline-command flag (`-c`) — the shape every "run this string"
/// invocation takes, and one a renamed or wrapped interpreter still has to
/// carry to accept an inline command.
///
/// This is a heuristic, not a proof. A wrapper script, a program that
/// `exec`s a shell, or an interpreter invoked under an unusual name defeats
/// it. What still holds is the signed grant itself: input only reaches a
/// program the admitted plan chose, never one input bytes select.
pub fn entrypoint_is_shell_shaped(argv: &[String], shebang: Option<&[u8]>) -> bool {
    argv_is_shell(argv)
        || argv.iter().skip(1).any(|arg| arg == "-c")
        || shebang
            .is_some_and(|bytes| mvm_contract::entrypoint::detect_shell_shebang(bytes).is_some())
}

/// Bundle of artifacts produced by a successful admission: the
/// admitted plan + the audit emitter wired against the host signer.
/// Callers thread this through `cmd_run` so the `plan.launched` and
/// `plan.failed` audit lines bind to the same plan_id.
///
/// Hand-written `Debug` (not derived) because `AuditEmitter` wraps a
/// `FileAuditSigner` whose internals hold an Ed25519 secret key. The
/// xtask `check-no-display-on-secret-types` lint would catch a
/// derived `Debug` that forwarded; the manual impl prints only the
/// plan_id + signer_id and elides the emitter's signing material.
pub struct AdmissionContext {
    pub admitted: AdmittedPlan,
    pub emitter: AuditEmitter,
    pub host_signer_public_path: std::path::PathBuf,
}

/// The admitted CLI run before it chooses warm claim or cold boot.
///
/// The authority cannot be cloned or built from signed-plan JSON. A cold
/// dispatch consumes it; a pool miss leaves it pending for the cold path.
pub enum CliAdmission {
    /// Host-prepared authority for the admitted CLI cold alternative.
    PreparedCold(Box<mvm_hostd::plan_admission::PreparedCliCold<CliColdContinuation>>),
    /// One-use authority before warm/cold selection.
    Pending(Box<PendingCliAdmission>),
    /// Dispatch spent the authority; only the audit continuation remains.
    Dispatched(Box<AuditContinuation>),
}

pub(crate) use cli_dispatch::FsQuickBootAdmission;
pub use cli_dispatch::prepare_cli_cold;

impl CliAdmission {
    /// The host cores admission placed this launch on, while the authority is
    /// still pending. A placed launch boots cold: neither a standby nor a
    /// snapshot restore is born inside a scope carrying the set.
    #[must_use]
    pub fn allowed_cpus(&self) -> Option<&mvm_contract::protocol::cpu_set::CpuSet> {
        match self {
            Self::PreparedCold(prepared) => prepared.allowed_cpus(),
            Self::Pending(pending) => pending.authority.allowed_cpus(),
            Self::Dispatched(_) => None,
        }
    }
}

/// Private fields keep the pending authority one-shot.
pub struct PendingCliAdmission {
    authority: AdmittedPlan,
    audit: AuditContinuation,
    source_rootfs: Option<std::path::PathBuf>,
    verified_runtime: Option<std::sync::Arc<mvm_runtime::runtime_evidence::VerifiedRuntimeSet>>,
}

/// Read-only CLI state retained inside the opaque host-prepared capability.
pub struct CliColdContinuation {
    host_budget: std::sync::Arc<mvm_hostd::admission_budget::HostBudgetPermit>,
    mailbox_posture: Option<mvm_hostd::plan_admission::MailboxLaunchPosture>,
    _built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

/// Source-specific lowering produced by the CLI admission callback.
pub struct CliColdAdmissionInput {
    admission: CliAdmission,
    built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
}

impl CliColdAdmissionInput {
    /// Move the temporary audit owner into host-prepared launch authority.
    #[must_use]
    pub fn new(
        admission: CliAdmission,
        built_runtime: Option<mvm_hostd::plan_admission::PreparedBuiltPackRuntime>,
    ) -> Self {
        Self {
            admission,
            built_runtime,
        }
    }
}

/// Actual admission plus its config projection before source-specific lowering.
pub struct CliColdAdmissionResult {
    /// Temporary owner installed before fallible post-admission lowering.
    pub admission: std::rc::Rc<std::cell::RefCell<Option<CliAdmission>>>,
    /// Read-only/config-drive projection applied only inside host preparation.
    pub substrate: crate::entrypoint::SessionAuditSubstrate,
}

/// Prepared CLI cold projection used for warm/template/cold selection.
pub struct PreparedCliCold {
    /// Opaque one-shot launch owner.
    pub admission: CliAdmission,
    /// Read-only projection of the exact host-prepared config.
    pub config: mvm_core::vm_backend::VmStartConfig,
    /// Existing admission budget hold used by the CLI dispatch accounting.
    pub host_budget: std::sync::Arc<mvm_hostd::admission_budget::HostBudgetPermit>,
    /// Existing mailbox posture used by explicit non-cold alternatives.
    pub mailbox_posture: Option<mvm_hostd::plan_admission::MailboxLaunchPosture>,
}

/// Read-only admitted plan and its original signer for post-run accounting.
pub struct AuditContinuation {
    plan: mvm_core::plan::ExecutionPlan,
    emitter: AuditEmitter,
}

// allow(secret-debug): only the plan id is shown; signing material is redacted.
impl std::fmt::Debug for AuditContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditContinuation")
            .field("plan_id", &self.plan.plan_id)
            .field("emitter", &"<redacted: FileAuditSigner>")
            .finish()
    }
}

impl AuditContinuation {
    /// The exact plan admitted for this run, not one decoded from boot JSON.
    #[must_use]
    pub fn plan(&self) -> &mvm_core::plan::ExecutionPlan {
        &self.plan
    }

    /// Record an unresolved host rollback without sealing a possibly live VM.
    pub fn record_uncertain_stop(&self, error: &anyhow::Error) {
        mvm_hostd::audit::unsealed::record_unsealed_end(
            Some((&self.emitter, &self.plan)),
            mvm_hostd::audit::unsealed::UnsealedEnd::new(
                &self.plan.workload.0,
                mvm_hostd::audit::unsealed::UnsealedReason::StopFailed,
            )
            .error(format!("{error:#}")),
        );
    }

    /// Record an output against an actual signed grant.
    ///
    /// # Errors
    /// Refuses an ungranted output or an audit-write failure.
    pub fn record_output(
        &self,
        record: &mvm_hostd::audit::output_audit::OutputRecord<'_>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.plan
                .outputs
                .iter()
                .any(|grant| grant.guest_path == record.guest_path),
            "the admitted plan carries no output grant for {}",
            record.guest_path
        );
        self.emitter.emit_outputs(&self.plan, record)
    }
}

// allow(secret-debug): hand-written Debug elides the AuditEmitter's
// underlying FileAuditSigner (Ed25519 secret key); prints plan_id +
// signer_id only.
impl std::fmt::Debug for AdmissionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionContext")
            .field("plan_id", self.admitted.plan_id())
            .field("signer_id", &self.admitted.signer_id())
            .field("emitter", &"<redacted: FileAuditSigner>")
            .finish()
    }
}

/// Run admission (`synthesize → sign → verify → check_window →
/// nonce`) right before a backend `start()`. Every path that boots an
/// admitted workload calls it: `mvmctl run`, `mvmctl machine run` and
/// `machine start`, and checkpoint forks.
///
/// There is no way to boot without it: this returns an admitted plan or an
/// error, never an unadmitted success.
///
/// The caller is expected to have already resolved the rootfs path on
/// disk (admission hashes it for the plan's `SignedImageRef`); on
/// first build the rootfs is the freshly-emitted Nix store path, on
/// snapshot restore it is the template's frozen rootfs, on
/// `MVM_DIRECT_BOOT` it is whatever the launchd agent staged.
///
/// Each `cmd_run` invocation owns its own [`InMemoryNonceLedger`] —
/// the only way `admit_for_run` can refuse for replay within one
/// process is the `--watch` loop (multiple admits over the lifetime
/// of one `cmd_run`), and that's the desired G4 behaviour.
///
/// On success, also constructs an [`AuditEmitter`] for the host
/// signer's key and emits the `plan.admitted` chain entry; subsequent
/// `plan.launched` / `plan.failed` events bind to the same plan_id.
///
/// The image name on the plan is the VM name (the workload identifier
/// the rest of the supervisor surface uses). Once `mvm-hostd` lifts
/// the supervisor in-process, the proper `mvm_core::crypto::image_verify`
/// signed-manifest path can replace this.
/// The policy variant an admission runs under. `restrict_agent_verbs` is this
/// codebase's sealed-production signal: a non-interactive, non-ad-hoc,
/// non-dev boot of a sealed image.
fn admission_variant(restrict_agent_verbs: bool) -> Variant {
    if restrict_agent_verbs {
        Variant::Prod
    } else {
        Variant::Dev
    }
}

fn enforce_image_source_admission(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    variant: Variant,
    configured_images_dir: Option<&std::path::Path>,
    rootfs_path: &std::path::Path,
) -> Result<()> {
    if !channel.permits_automatic_builds() {
        mvm_build::image_source::refuse_in_production(variant, configured_images_dir)?;
    }
    if let Some(tier) = mvm_build::image_source::recorded_tier_for(rootfs_path) {
        mvm_build::image_source::refuse_tier_in_production(variant, tier)?;
    }
    Ok(())
}

pub fn admit_plan_for_boot(p: AdmitPlanForBootParams<'_>) -> Result<AdmissionContext> {
    // Hashing a freshly built root filesystem for the plan reads every byte
    // of it; later boots are served from the digest cache and stay silent.
    let phase = mvm_runtime::ui::activity::start("Signing and admitting the execution plan");
    let admitted = admit_plan_for_boot_configured_ingress(p, Vec::new())?;
    phase.finish();
    Ok(admitted)
}

/// Admit a release launch using its checked whole-runtime selection.
pub fn admit_plan_for_boot_with_verified_runtime(
    p: AdmitPlanForBootParams<'_>,
    runtime: &mvm_runtime::runtime_evidence::VerifiedRuntimeSet,
) -> Result<AdmissionContext> {
    let phase = mvm_runtime::ui::activity::start("Signing and admitting the execution plan");
    let admitted =
        admit_plan_for_boot_configured_ingress_with_verified_runtime(p, Vec::new(), runtime)?;
    phase.finish();
    Ok(admitted)
}

/// Sign the verified retained release identity for a checkpoint fork.
pub fn admit_plan_for_boot_with_verified_retained(
    p: AdmitPlanForBootParams<'_>,
    retained: &mvm_runtime::checkpoint::VerifiedRetainedRuntime,
) -> Result<AdmissionContext> {
    let phase = mvm_runtime::ui::activity::start("Signing and admitting the execution plan");
    let (context, durability) = admit_with_runtime_evidence(
        p,
        Vec::new(),
        durability::AdmissionSync::Inline,
        None,
        Some(retained),
        None,
    )?;
    debug_assert!(
        durability.is_settled(),
        "a retained-runtime admission is durable before it returns"
    );
    phase.finish();
    Ok(context)
}

pub fn admit_plan_for_boot_configured_ingress(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
) -> Result<AdmissionContext> {
    let (context, durability) = admit(p, ingress, durability::AdmissionSync::Inline)?;
    debug_assert!(
        durability.is_settled(),
        "an inline admission is already durable"
    );
    Ok(context)
}

/// Keep a verified runtime beside the config through signed plan admission.
pub fn admit_plan_for_boot_configured_ingress_with_verified_runtime(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
    runtime: &mvm_runtime::runtime_evidence::VerifiedRuntimeSet,
) -> Result<AdmissionContext> {
    let (context, durability) = admit_with_runtime_evidence(
        p,
        ingress,
        durability::AdmissionSync::Inline,
        Some(runtime),
        None,
        None,
    )?;
    debug_assert!(
        durability.is_settled(),
        "an inline admission is already durable"
    );
    Ok(context)
}

fn admit(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
    sync: durability::AdmissionSync,
) -> Result<(
    AdmissionContext,
    mvm_core::admission_durability::AdmissionDurability,
)> {
    admit_with_runtime_evidence(p, ingress, sync, None, None, None)
}

pub(crate) fn admit_prepared_plan_for_boot(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
    prepared: &crate::image_cache::prepared::ValidatedPrepared,
    runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
) -> Result<AdmissionContext> {
    let (context, durability) = admit_with_runtime_evidence(
        p,
        ingress,
        durability::AdmissionSync::Inline,
        runtime,
        None,
        Some(prepared),
    )?;
    debug_assert!(durability.is_settled());
    Ok(context)
}

fn admit_with_runtime_evidence(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
    sync: durability::AdmissionSync,
    runtime: Option<&mvm_runtime::runtime_evidence::VerifiedRuntimeSet>,
    retained: Option<&mvm_runtime::checkpoint::VerifiedRetainedRuntime>,
    prepared: Option<&crate::image_cache::prepared::ValidatedPrepared>,
) -> Result<(
    AdmissionContext,
    mvm_core::admission_durability::AdmissionDurability,
)> {
    let prepared = prepared.map(|validated| &validated.selection);
    // A production boot runs only verified released images, for every
    // managed artifact it resolves. The tiers recorded with those images
    // decide (below): a local-dev managed image is refused however it was
    // selected, with the selector unset as surely as set. The selector
    // itself is refused here only on release-channel binaries: a release
    // binary refuses the variable at CLI entry before any verb runs, so a
    // production run cannot be steered by a local path, while a contributor
    // build is allowed to use the paired workflow for exactly this
    // development flow — a sealed workload the developer just built from
    // their own flake must boot.
    let variant = admission_variant(p.restrict_agent_verbs);
    enforce_image_source_admission(
        mvm_build::artifact_acquisition::compiled_channel(),
        variant,
        p.configured_images_dir,
        p.rootfs_path,
    )?;

    // Refuse before any hashing, bundle reads, or signing: a rejection here
    // must not have already spent the boot work it exists to avoid. Gated on
    // `restrict_agent_verbs` — the same "non-interactive, non-ad-hoc, non-dev,
    // sealed image" posture the ProdSafe verb attenuation uses — because that
    // is this codebase's existing "sealed production" signal, and the
    // shell-entrypoint refusal is scoped to exactly that tier. A dev,
    // interactive, or ad-hoc-argv run already carries a DevOnly Exec grant, so
    // refining its input grant would not close anything the Exec grant hasn't
    // already opened.
    if p.restrict_agent_verbs && mvm_contract::stream::input::grants_input_for(&p.services) {
        match &p.entrypoint {
            ResolvedEntrypoint::Known { argv, shebang } => {
                if entrypoint_is_shell_shaped(argv, shebang.as_deref()) {
                    anyhow::bail!(
                        "refusing the workload input grant: the resolved entrypoint {argv:?} is \
                         shell-shaped, and under a sealed production posture streaming stdin \
                         to a shell is interactive access wearing a different hat",
                    );
                }
            }
            // Fail closed. The alternative — admit and hope — is what leaves a
            // refusal that reports present and can never fire, which is worse
            // than no refusal at all because it is believed.
            ResolvedEntrypoint::Unresolved { because }
            | ResolvedEntrypoint::AdHocOverride { because } => anyhow::bail!(
                "refusing the workload input grant: this launch cannot say what the \
                 workload runs ({because}), so it cannot rule out a shell — and under \
                 a sealed production posture streaming stdin to a shell is interactive \
                 access wearing a different hat",
            ),
        }
    }

    let sibling_identity = if p.boot_artifact_identity.is_none() {
        sibling_deploy_boot_artifact(p.rootfs_path)?
    } else {
        None
    };
    let boot_artifact_identity = p.boot_artifact_identity.or(sibling_identity.as_ref());
    let attested_sha = boot_artifact_identity
        .map(|identity| {
            verify_boot_artifact(p.rootfs_path, identity).map_err(|error| {
                anyhow::anyhow!(
                    "verifying deploy-record boot artifact for {}: {error}",
                    p.rootfs_path.display()
                )
            })?;
            Ok::<String, anyhow::Error>(identity.sha256.clone())
        })
        .transpose()?;
    let t_admit_start = std::time::Instant::now();
    mvm_core::launch_trace::lap("admit_plan.setup_and_boot_artifact_identity");
    let sha = if let Some(expected) = prepared {
        let actual = mvm_core::crypto::image_verify::sha256_file(p.rootfs_path)?;
        if actual != expected.rootfs_sha256 || p.backend_name != expected.backend {
            return Err(mvm_core::prepared_image::PreparedImageError {
                kind: mvm_core::prepared_image::PreparedImageErrorKind::SelectionChanged,
                reference: expected.canonical_reference.clone(),
                detail: "prepared bytes or backend changed before admission".into(),
            }
            .into());
        }
        actual
    } else {
        resolve_image_sha256(p.rootfs_path, p.precomputed_image_sha256.or(attested_sha))?
    };
    mvm_core::launch_trace::lap("admit_plan.image_sha256");
    let t_sha = std::time::Instant::now();
    tracing::debug!(
        ms = (t_sha - t_admit_start).as_secs_f64() * 1000.0,
        "admit: image sha"
    );

    // Claim 9 — bundle pin (when supplied).
    //
    // Read the archive bytes, verify them against the local trust
    // store, then construct the `PlanArtifact` triple
    // (bundle_sha256 + manifest_sig + key_id). The supervisor's
    // admit path re-runs the same verifier against the on-disk
    // archive — defence in depth between CLI synth and backend
    // dispatch. Errors surface before admit so the user sees them
    // without a confusing post-sign rejection.
    let bundle_image_support = p
        .backend_kind
        .and_then(mvm_core::image_set::BackendImageSupport::for_backend);
    let bundle_host_protocols = mvm_build::stage0_kernel::current_image_set_protocol_support();
    let mut postures: Vec<mvm_core::plan::BundleSecurityPosture> =
        p.bundle_posture.into_iter().collect();
    let (
        bundle_pin,
        bundle_resolver,
        bundle_trust,
        bundle_has_embedded_images,
        pinned_bundle,
        pinned_bundle_origin,
        pinned_environment,
    ) = match p.bundle_pin {
        Some(pin) => {
            let prepared =
                pinned_bundle::prepare_pinned_bundle(pinned_bundle::PreparePinnedBundleParams {
                    pin,
                    keys_dir: p.keys_dir,
                    backend_kind: p.backend_kind,
                    image_support: bundle_image_support.as_ref(),
                    host_protocols: &bundle_host_protocols,
                })?;
            postures.extend(prepared.posture);
            let pinned_environment = prepared.environment;
            (
                Some(prepared.plan_pin),
                Some(prepared.resolver),
                Some(prepared.trust),
                prepared.has_embedded_images,
                Some(prepared.pinned),
                Some(prepared.origin),
                pinned_environment,
            )
        }
        None => (None, None, None, false, None, None, None),
    };

    // Pin the kernel alongside the image. Through the shared digest cache, the
    // same way `image_sha256` above is derived — a pin that re-read the whole
    // kernel would put a multi-MB read back on every launch to reproduce a
    // value the kernel's own cache check just computed from the same bytes.
    mvm_core::launch_trace::lap("admit_plan.bundle_prepare");
    let kernel_sha256 = p
        .kernel_path
        .map(|kernel| {
            mvm_core::crypto::image_verify::sha256_file_cached(kernel)
                .with_context(|| format!("hashing kernel at {} for the plan pin", kernel.display()))
        })
        .transpose()?;
    // A kernel the selected backend cannot load is refused here, before a plan
    // is signed for a boot that would only end in the VMM's own loader error.
    if let (Some(kind), Some(kernel)) = (p.backend_kind, p.kernel_path) {
        mvm_core::kernel_format::check_direct_boot_loadable(
            kind,
            mvm_core::arch::GuestArch::host(),
            kernel,
        )
        .with_context(|| format!("backend {} cannot boot this kernel", kind.as_str()))?;
    }

    mvm_core::launch_trace::lap("admit_plan.kernel_sha256_and_loadable");
    let generated_policy_ref = generated_policy_ref(p.tenant, p.vm_name, &p.network_policy)?;
    let generated_policy_ref = generated_policy_ref.as_deref();

    // Content-derived asset identities. Directory shares that don't carry a
    // digest yet are hashed here, at admission, so the signed plan records
    // what the granted tree actually was; enforcement re-hashes at attach
    // time and refuses drift (hostd `enforce_admitted_shares`). The path is
    // canonicalized first so a symlink alias (macOS `/tmp`) hashes the same
    // tree `hash_source` would refuse as a symlink root.
    let mut shares = p.shares.clone();
    let materialized_images = p
        .instructions
        .materialized_mounts
        .unwrap_or_default()
        .iter()
        .map(|mount| (mount.host_path.clone(), mount.image_path.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for grant in &mut shares {
        if grant.kind == mvm_core::plan::ShareKind::DirShare && grant.content_sha256.is_none() {
            if let Some(image) = materialized_images.get(std::path::Path::new(&grant.host_path)) {
                grant.content_sha256 = Some(
                    mvm_core::crypto::image_verify::sha256_file(image).with_context(|| {
                        format!(
                            "hashing frozen share image {} for its content identity",
                            image.display()
                        )
                    })?,
                );
                continue;
            }
            let resolved = std::fs::canonicalize(&grant.host_path)?;
            let digest = mvm_fs::hash::hash_source(&resolved).with_context(|| {
                format!(
                    "hashing admitted share {} for its content identity",
                    grant.host_path
                )
            })?;
            grant.content_sha256 = Some(digest);
        }
    }

    mvm_core::launch_trace::lap("admit_plan.share_hash");
    // Caller-declared files and selected signed packs are verified here,
    // before their identities enter the signed plan.
    let mut caller_assets = Vec::with_capacity(p.assets.len());
    for spec in &p.assets {
        match spec {
            AssetSpec::File { kind, host_path } => {
                let resolved = std::fs::canonicalize(host_path)?;
                let digest = mvm_fs::hash::hash_source(&resolved).with_context(|| {
                    format!(
                        "hashing declared {} asset {} for its content identity",
                        serde_json::to_string(kind).expect("asset kind serializes"),
                        host_path
                    )
                })?;
                let name = std::path::Path::new(host_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| host_path.clone());
                caller_assets.push(mvm_core::plan::AssetIdentity::new(*kind, name, digest)?);
            }
            AssetSpec::RegistryPack(pin) => {
                use mvm_core::registry_pack::AuthenticatedRegistryManifest as _;
                let lock = mvm_core::registry_pack_store::load_pack_lockfile(
                    &mvm_core::config::pack_lockfile_path(),
                )?;
                let publisher =
                    mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
                        &mvm_core::config::registry_pack_publisher_policy_path(),
                    )?
                    .policy;
                let (_, verified) =
                    mvm_core::registry_pack_store::open_installed_registry_manifest(
                        &mvm_core::config::registry_pack_cache_dir(),
                        &lock,
                        &publisher,
                        pin.reference(),
                    )?;
                anyhow::ensure!(
                    verified.manifest_sha256() == pin.manifest_sha256(),
                    "registry pack {} changed after source selection",
                    pin.reference()
                );
                caller_assets.push(mvm_core::plan::AssetIdentity::new(
                    mvm_core::plan::AssetKind::RegistryPack,
                    verified.reference().to_string(),
                    verified.manifest_sha256().as_str(),
                )?);
            }
            AssetSpec::CommittedPolicy(identity) => {
                anyhow::ensure!(
                    identity.kind == mvm_core::plan::AssetKind::Policy
                        && identity
                            .name
                            .starts_with(mvm_hostd::policy_generation::GENERATION_ASSET_PREFIX),
                    "invalid committed project-policy asset"
                );
                caller_assets.push(identity.clone());
            }
        }
    }

    // Instruction files the boot copies into the guest, verified against the
    // operator's provenance policy now — before signing — so a broken policy
    // or an unreadable input fails here. The verdicts are recorded, and the
    // policy enforced, once the plan exists to bind them to.
    let instruction_report =
        instructions::evaluate_and_harden(&mut shares, &p.assets, p.instructions)?;

    mvm_core::launch_trace::lap("admit_plan.asset_hash_and_instructions");
    // The resolved network policy's identity: the plan pins policies by
    // reference name, so the caller adds the resolved bytes' hash — an
    // operator comparing identities sees which exact policy content was
    // admitted, not just its name.
    let network_policy_digest = mvm_core::policy::network_policy::content_sha256(&p.network_policy);

    let seccomp_tier = mvm_core::plan::workload_seccomp_tier(
        p.seccomp_tier,
        &p.network_policy,
        &ingress,
        &p.services,
        p.gpu,
    );
    let mut bundle_audit_labels = p.bundle_sizing.audit_labels();
    if let Some(prepared) = prepared {
        bundle_audit_labels.extend(prepared.audit_labels());
    }
    if pinned_bundle_origin == Some(mvm_core::plan::bundle::BundleOrigin::LocalBuild) {
        bundle_audit_labels.insert("origin".to_string(), "local-build".to_string());
        bundle_audit_labels.insert(
            "bundle_sha256".to_string(),
            bundle_pin
                .as_ref()
                .expect("a classified bundle has a pin")
                .bundle_sha256
                .clone(),
        );
    }
    let input = SynthesisInput {
        mailbox: p
            .mailbox
            .map(|grant| mailbox_grant::at_workload_epoch(grant, p.vm_name))
            .transpose()?,
        outputs: p.outputs.clone(),
        // The resolved permission set rides into the plan body, so the ceiling
        // check below measures what the user actually asked for and the
        // signature covers it.
        grants: p.grants.clone(),
        stream_edges: Vec::new(),
        kernel_sha256: kernel_sha256.as_deref(),
        network_mode: p.network_mode,
        ingress,
        vm_name: p.vm_name,
        tenant: Some(p.tenant),
        backend_name: p.backend_name,
        image_name: p.vm_name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier,
        network_policy_ref: generated_policy_ref,
        fs_policy_ref: generated_policy_ref,
        egress_policy_ref: generated_policy_ref,
        secret_release: p.secret_release,
        secrets: p.secrets.clone(),
        audit_event_prefix: None,
        cpus: p.cpus,
        mem_mib: p.mem_mib,
        disk_mib: 0,
        boot_timeout_secs: 60,
        destroy_on_exit: true,
        bundle_pin: bundle_pin.clone(),
        deps_volume: p.deps_volume.clone(),
        shares: shares.clone(),
        assets: {
            let mut assets = caller_assets;
            let policy_name = generated_policy_ref
                .map(str::to_string)
                .unwrap_or_else(|| "network_policy".to_string());
            assets.push(mvm_core::plan::AssetIdentity::new(
                mvm_core::plan::AssetKind::Policy,
                policy_name,
                network_policy_digest.clone(),
            )?);
            assets
        },
        redaction: p.redaction.clone(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        caller_commitment: p.caller_commitment.clone(),
        audit_labels: bundle_audit_labels,
        agent_verbs: crate::admission::agent_verbs::parse_agent_verb_override(
            &p.agent_verb_override,
        )?
        .or_else(|| {
            crate::admission::agent_verbs::default_agent_verbs(
                p.restrict_agent_verbs,
                !p.shares.is_empty(),
                mvm_contract::stream::input::grants_input_for(&p.services),
            )
        }),
        services: p.services.clone(),
        extensions: Vec::new(),
        // Recorded, always, and not reachable from a flag. A caller who could
        // turn the transcript off from the command line would leave an absent
        // recording indistinguishable from a suppressed one; opting out is a
        // decision for whoever authors and signs the plan, and it lands in the
        // chain as `plan.admitted`'s retention label either way.
        stream_retention: StreamRetention::Persist,
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    };
    let admission_ctx = match (&bundle_resolver, &bundle_trust) {
        (Some(r), Some(t)) => Some(BundleAdmissionContext {
            resolver: r,
            trust: t,
            image: bundle_has_embedded_images.then(|| BundleImageAdmissionContext {
                arch: mvm_core::arch::GuestArch::host(),
                backend: bundle_image_support
                    .as_ref()
                    .expect("embedded image backend checked above"),
                host_protocols: &bundle_host_protocols,
            }),
        }),
        _ => None,
    };
    // The posture the grant gate reads. `restrict_agent_verbs` is this
    // codebase's sealed-production signal — the same one the input-grant
    // refusal above is scoped to — so a sealed boot refuses a grant nothing
    // can enforce, and a dev boot is told about it and proceeds.
    let variant = admission_variant(p.restrict_agent_verbs);
    mvm_core::launch_trace::lap("admit_plan.synthesis_inputs");
    let t_pre_sign = std::time::Instant::now();
    tracing::debug!(
        ms = (t_pre_sign - t_sha).as_secs_f64() * 1000.0,
        "admit: synthesis inputs"
    );
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        p.ledger,
        p.keys_dir,
        admission_ctx.as_ref(),
        crate::admission::run_grants::run_posture(variant, p.backend_kind, p.runtime_config)
            .with_verified_runtime(runtime)
            .with_verified_retained(retained),
    )
    .or_else(|err| -> Result<_> {
        if let Some(refused) =
            err.downcast_ref::<mvm_hostd::plan_admission::BundleEnvironmentRefused>()
        {
            let signer = match p.keys_dir {
                Some(dir) => load_or_init_at(dir),
                None => mvm_hostd::audit::host_keypair::load_or_init(),
            }
            .context("loading host signer for the environment refusal")?;
            let emitter = build_default_audit_emitter(signer.signing, p.audit_dir)
                .context("opening audit chain emitter for the environment refusal")?;
            emit_bundle_environment_refused(refused.plan(), &emitter, &err);
        }
        Err(err)
    })?;
    let t_signed = std::time::Instant::now();
    mvm_core::launch_trace::lap("admit_plan.replay_bundle_reverify_and_admit_tail");
    tracing::debug!(
        ms = (t_signed - t_pre_sign).as_secs_f64() * 1000.0,
        "admit: sign+verify"
    );
    // The plan was synthesized just now and nothing has been recorded for it
    // yet, so this is the one moment its session's first possible segment is
    // known without reading the chain. Sealing it later reads only that far.
    if let Some(dir) = p
        .audit_dir
        .map(std::path::Path::to_path_buf)
        .or_else(|| mvm_hostd::audit::emitter::default_audit_dir().ok())
    {
        mvm_hostd::audit::session::note_new_session(
            &dir,
            &admitted.plan().tenant.0,
            &admitted.plan_id().0,
        );
    }
    tracing::info!(
        plan_id = %admitted.plan_id().0,
        signer_id = %admitted.signer_id(),
        tenant = %p.tenant,
        workload = %p.vm_name,
        backend = %p.backend_name,
        image_sha256 = %sha,
        "plan admitted",
    );

    // Load the host signer's signing key for the audit chain. We
    // re-read it (rather than threading it out of `admit_for_run`)
    // because the key bytes are still on disk and the re-read is
    // cheap — keeps `admit_for_run`'s shape unchanged. Audit failures
    // here surface as `Err`; the caller decides whether one is fatal.
    let signer = match p.keys_dir {
        Some(dir) => load_or_init_at(dir),
        None => mvm_hostd::audit::host_keypair::load_or_init(),
    }
    .context("loading host signer for audit emitter")?;

    // A bundle's signed posture is a ceiling on this launch. The plan is
    // already admitted so the refusal binds to its id in the audit chain;
    // nothing has been recorded as admitted yet, and nothing boots.
    let posture_request = bundle_posture::PostureRequest {
        network_policy: &p.network_policy,
        shares: &shares,
        restrict_agent_verbs: p.restrict_agent_verbs,
    };
    let exceeded: Vec<_> = postures
        .iter()
        .flat_map(|posture| bundle_posture::posture_exceedances(posture, &posture_request))
        .collect();
    if !exceeded.is_empty() {
        let err = anyhow::anyhow!(bundle_posture::refusal_message(&exceeded));
        let emitter = build_default_audit_emitter(signer.signing.clone(), p.audit_dir)
            .context("opening audit chain emitter for the posture refusal")?;
        emit_bundle_posture_refused(admitted.plan(), &emitter, &err);
        return Err(err);
    }
    // The pinned bundle's signed environment, measured against what this
    // launch binds and runs. Refused and audited the same way as the posture.
    if let Some(environment) = &pinned_environment {
        let refused = bundle_environment::environment_refusals(
            environment,
            &bundle_environment::EnvironmentRequest {
                secrets: &p.secrets,
                entrypoint: &p.entrypoint,
                postures: &postures,
                network_policy: &p.network_policy,
            },
        );
        if !refused.is_empty() {
            let err = anyhow::anyhow!(bundle_environment::refusal_message(&refused));
            let emitter = build_default_audit_emitter(signer.signing.clone(), p.audit_dir)
                .context("opening audit chain emitter for the environment refusal")?;
            emit_bundle_environment_refused(admitted.plan(), &emitter, &err);
            return Err(err);
        }
    }
    let t_signer = std::time::Instant::now();
    mvm_core::launch_trace::lap("admit_plan.session_note_and_signer_reload");
    tracing::debug!(
        ms = (t_signer - t_signed).as_secs_f64() * 1000.0,
        "admit: load host signer"
    );

    let resolution = if generated_policy_ref.is_some() {
        PolicyResolutionKind::NetworkPolicy
    } else {
        PolicyResolutionKind::LocalDefault
    };
    let emitter = build_default_audit_emitter(signer.signing, p.audit_dir)
        .context("opening audit chain emitter")?
        .with_receipts();

    if let Some(report) = &instruction_report {
        instructions::record_and_enforce(&emitter, admitted.plan(), report)?;
    }

    // A sealed-production run that cannot record its admission does not boot.
    // The chain can prove nothing was altered among the entries it holds, but
    // an entry that was never written leaves no gap for it to find — so the
    // only moment this is catchable is right here. `restrict_agent_verbs` is
    // the same sealed-tier signal the shell-entrypoint refusal above keys on.
    let t_emitter = std::time::Instant::now();
    mvm_core::launch_trace::lap("admit_plan.policy_and_emitter");
    tracing::debug!(
        ms = (t_emitter - t_signer).as_secs_f64() * 1000.0,
        "admit: policy + emitter build"
    );
    // The admitted L7 egress boundary recorded in the chain-signed log so a
    // receipt can name the destinations without re-resolving policy refs.
    let egress_destinations = egress_destinations(&p.network_policy);

    // One batch, one fsync. Every admission-path entry has to be durable
    // before the same thing — this plan's workload running — and nothing
    // between them acts on the one before it, so syncing each separately
    // bought no ordering. The batch covers the admission record, its decision
    // record, the grant, the shares, the asset identities, the policy
    // resolution and the egress destinations: all entries that would
    // each trigger their own fsync share the single flush. A failed write
    // inside the batch is an error here; a failed sync is an error wherever
    // the caller waits for it, which is here unless it asked to sync beside
    // the boot.
    let record = || {
        mvm_hostd::audit::durability::record_admission(
            Some(&emitter),
            admitted.plan(),
            admitted.signer_id(),
            mvm_hostd::audit::durability::AuditDurability::for_sealed_production(
                p.restrict_agent_verbs,
            ),
        )?;
        if let Some(verbs) = admitted.plan().agent_verbs.as_ref()
            && let Err(e) = emitter.emit_grant_required(admitted.plan(), verbs)
        {
            tracing::warn!(error = %e, "audit emit_grant_required failed (non-fatal)");
        }
        // Claim 1 / claim 8 — record the admitted host-fs grants in the
        // chain-signed log (no-op when there are none).
        if let Err(e) = emitter.emit_shares_admitted(admitted.plan()) {
            tracing::warn!(error = %e, "audit emit_shares_admitted failed (non-fatal)");
        }
        // Record every bound asset's content-derived identity in the
        // chain-signed log alongside the grants (no-op when the plan
        // records none). An admitted asset without this record must not boot.
        emitter
            .emit_asset_identities(admitted.plan())
            .context("recording admitted asset identities in the audit chain")?;
        // Policy resolution and egress destinations are non-fatal records
        // that sit in the batch rather than syncing each on its own.
        // Folding them in saves two serial F_FULLFSYNCs (~15ms on
        // Apple silicon, ~84ms on KVM arrays) with no ordering loss.
        emit_policy_resolved(admitted.plan(), &emitter, resolution);
        if let Err(e) = emitter.emit_egress_destinations(admitted.plan(), &egress_destinations) {
            tracing::warn!(error = %e, "audit emit_egress_destinations failed (non-fatal)");
        }
        Ok(())
    };
    let durability = match sync {
        durability::AdmissionSync::Inline => {
            emitter.batched(record)?;
            mvm_core::admission_durability::AdmissionDurability::settled(Ok(()))
        }
        durability::AdmissionSync::BesideBoot => emitter.batched_sync_detached(record)?.1,
    };
    mvm_core::launch_trace::lap("admit_plan.audit_record");
    tracing::debug!(
        ms = t_emitter.elapsed().as_secs_f64() * 1000.0,
        ?sync,
        "admit: record_admission (batched fsync)"
    );

    let context = AdmissionContext {
        admitted,
        emitter,
        host_signer_public_path: signer.public_path,
    };

    // The archive verified before synthesis; what remains is whether this boot
    // runs it. Checked once the plan is admitted, so a refusal is recorded
    // against the plan that pinned the bundle.
    if let Some(pinned) = &pinned_bundle
        && let Err(err) = pinned.check_boot(bundle_binding::BootDigests {
            rootfs_sha256: &sha,
            kernel_sha256: kernel_sha256.as_deref(),
        })
    {
        emit_failed(&context, bundle_binding::BUNDLE_VERIFY_CLASS, &err);
        return Err(err);
    }

    Ok((context, durability))
}

/// Resolve a local deployment record only when it sits beside the exact
/// rootfs selected for boot. A record elsewhere is not an authority for this
/// path, and an invalid sibling record refuses admission rather than silently
/// falling back to an unrecorded boot.
fn sibling_deploy_boot_artifact(
    rootfs_path: &std::path::Path,
) -> Result<Option<BootArtifactIdentity>> {
    let Some(parent) = rootfs_path.parent() else {
        return Ok(None);
    };
    let record_path = parent.join("deploy.json");
    if !record_path.is_file() {
        return Ok(None);
    }
    let record = read_deploy_record(&record_path).with_context(|| {
        format!(
            "reading deployment attestation beside boot artifact {}",
            rootfs_path.display()
        )
    })?;
    Ok(Some(record.boot_artifact))
}

/// Resolve the image digest used by the signed plan, verifying any caller-
/// supplied digest against the exact rootfs bytes first.
///
/// The ordinary boot path uses the size/mtime cache because the rootfs is
/// immutable across repeated launches. A precomputed digest is different: it
/// is an external attestation claim, so it must be checked with an uncached
/// read before it can influence admission. A mismatch fails closed.
#[tracing::instrument(
    skip_all,
    fields(rootfs = %rootfs_path.display(), precomputed = precomputed.is_some())
)]
fn resolve_image_sha256(
    rootfs_path: &std::path::Path,
    precomputed: Option<String>,
) -> Result<String> {
    match precomputed {
        Some(expected) => {
            let actual =
                mvm_core::crypto::image_verify::sha256_file(rootfs_path).with_context(|| {
                    format!(
                        "verifying precomputed rootfs digest for {}",
                        rootfs_path.display()
                    )
                })?;
            if actual != expected {
                bail!(
                    "precomputed rootfs sha256 mismatch for {}: expected {}, got {}",
                    rootfs_path.display(),
                    expected,
                    actual
                );
            }
            Ok(actual)
        }
        None => {
            mvm_core::crypto::image_verify::sha256_file_cached(rootfs_path).with_context(|| {
                format!(
                    "hashing rootfs at {} for plan admission",
                    rootfs_path.display()
                )
            })
        }
    }
}

// ── admit_plan_for_boot tests ────────────────────────────
//
// These tests stay scoped to the helper rather than `cmd_run` itself
// because the dispatcher (`cmd_run`) calls into backends (libkrun, HVF,
// Firecracker) that need a live host environment. `admit_plan_for_boot`
// is the bridge between CLI args and admission, so verifying it
// in isolation covers the contract the dispatcher depends on without
// pulling in VMM selection + start dispatch.

#[cfg(test)]
pub(crate) mod admit_plan_tests {
    use super::*;
    use std::io::Write;

    pub(super) fn isolated_home() -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    pub(super) fn write_rootfs(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("rootfs.ext4");
        let mut f = std::fs::File::create(&path).expect("create rootfs");
        f.write_all(bytes).expect("write rootfs");
        path
    }

    #[test]
    fn precomputed_rootfs_digest_must_match_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(dir.path(), b"attested rootfs");
        let expected = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();

        assert_eq!(
            resolve_image_sha256(&rootfs, Some(expected.clone())).unwrap(),
            expected
        );
        let err = resolve_image_sha256(&rootfs, Some("0".repeat(64))).unwrap_err();
        assert!(
            err.to_string()
                .contains("precomputed rootfs sha256 mismatch")
        );
    }

    #[test]
    fn sibling_deploy_record_is_only_used_for_its_rootfs_directory() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(dir.path(), b"recorded rootfs");
        let boot_artifact = mvm_core::deploy_record::digest_boot_artifact(&rootfs).unwrap();
        let record = mvm_core::deploy_record::DeployRecord {
            schema_version: mvm_core::deploy_record::DEPLOY_RECORD_SCHEMA_VERSION,
            workload_id: "vm-test".to_string(),
            ir_hash: "ir-hash".to_string(),
            image: mvm_core::deploy_record::ArtifactDigests {
                blake3: "b".repeat(64),
                sha256: "a".repeat(64),
                size_bytes: 1,
            },
            boot_artifact: boot_artifact.clone(),
            environment: None,
            dependency_volume: None,
        };
        mvm_core::deploy_record::write_deploy_record(&record, &dir.path().join("deploy.json"))
            .unwrap();

        assert_eq!(
            sibling_deploy_boot_artifact(&rootfs).unwrap(),
            Some(boot_artifact)
        );
        let unrelated = dir.path().join("other").join("rootfs.ext4");
        assert!(sibling_deploy_boot_artifact(&unrelated).unwrap().is_none());
    }

    /// A minimal admission that really runs — signs, verifies, burns a nonce.
    /// Callers override only the fields their assertion is about.
    pub(crate) fn pinning_params<'a>(
        rootfs: &'a std::path::Path,
        ledger: &'a InMemoryNonceLedger,
    ) -> AdmitPlanForBootParams<'a> {
        AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            outputs: Vec::new(),
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-pinned",
            runtime_config: None,
            backend_name: "firecracker",
            configured_images_dir: None,
            rootfs_path: rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            ledger,
            keys_dir: None,
            audit_dir: None,
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        }
    }

    /// Admit a real libkrun plan and retain its signer and audit directories.
    /// Only where the production signer, chain and plan live is injected.
    pub(crate) fn admitted_libkrun(
        vm_name: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (AdmissionContext, tempfile::TempDir, tempfile::TempDir) {
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let rootfs_dir = tempfile::tempdir().expect("rootfs dir");
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs bytes").expect("write rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name,
            backend_name: "libkrun",
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            grants,
            // The gate measures a declared bound against a real tier's
            // mechanisms; admitting without one refuses rather than guessing.
            backend_kind: Some(mvm_core::protocol::vm_backend::BackendKind::Libkrun),
            entrypoint: ResolvedEntrypoint::unresolved("this test resolves no entrypoint"),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission succeeds");
        (ctx, keys_dir, audit_dir)
    }

    #[test]
    fn admission_binds_the_caller_commitment_into_the_plan() {
        let _home = isolated_home();
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = write_rootfs(dir.path(), b"committed rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let commitment = mvm_core::plan::CallerCommitment::from_bytes([0x33; 32]);
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.caller_commitment = Some(commitment.clone());

        let admitted = admit_plan_for_boot(params).expect("admission succeeds");
        assert_eq!(admitted.admitted.plan().caller_commitment, Some(commitment));
    }

    #[test]
    fn a_clamped_bundle_default_is_recorded_on_plan_admitted() {
        let _home = isolated_home();
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = write_rootfs(dir.path(), b"sized rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.mem_mib = 1024;
        params.bundle_sizing = bundle_resources::seed(
            bundle_resources::SizingDefaults {
                cpus: Some(2),
                memory_mib: Some(4096),
            },
            bundle_resources::NamedSizing::default(),
            Some(1024),
        );

        let admitted = admit_plan_for_boot(params).expect("admission succeeds");
        let labels = &admitted.admitted.plan().audit_labels;
        assert_eq!(labels["sizing_memory_requested_mib"], "4096");
        assert_eq!(labels["sizing_memory_mib"], "1024");
        assert_eq!(labels["sizing_clamped"], "true");
        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("chain");
        assert!(chain.contains("sizing_memory_requested_mib"), "{chain}");
    }

    #[test]
    fn a_launch_the_bundle_did_not_size_carries_no_sizing_labels() {
        let _home = isolated_home();
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = write_rootfs(dir.path(), b"unsized rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);

        let admitted = admit_plan_for_boot(params).expect("admission succeeds");
        assert!(
            !admitted
                .admitted
                .plan()
                .audit_labels
                .keys()
                .any(|key| key.starts_with("sizing_"))
        );
    }

    #[test]
    fn a_typed_memory_over_the_host_ceiling_is_still_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        let config = mvm_core::user_config::MvmConfig {
            max_memory_mib: Some(128),
            ..Default::default()
        };
        mvm_core::user_config::save(&config, None).expect("host config");
        let rootfs = write_rootfs(dir.path(), b"typed rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.mem_mib = 4096;

        let err = admit_plan_for_boot(params)
            .expect_err("a typed value over the ceiling is refused, not clamped");
        assert!(err.to_string().contains("memory_mib"), "{err:#}");
    }

    /// Admission that leaves its sync beside the boot still writes the whole
    /// admission before it returns; the handle it hands back is only the sync.
    #[test]
    fn a_beside_boot_admission_is_written_before_it_returns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        let rootfs = write_rootfs(dir.path(), b"beside-boot rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);

        let (context, durability) =
            admit_plan_for_boot_syncing_beside_boot(params).expect("admission succeeds");
        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).expect("chain");
        assert!(
            chain.contains("plan.admitted")
                && chain.contains(context.admitted.plan_id().0.as_str()),
            "the admission is on the chain before the sync is waited for: {chain}"
        );
        durability.wait().expect("the sync succeeds");
    }

    /// The host budget is a refusal, and refusals do not wait for a boot: a
    /// beside-boot admission over budget fails before it returns, so there is
    /// no config for a VMM to start from and nothing is recorded as admitted.
    #[test]
    fn a_beside_boot_admission_refuses_an_over_budget_boot_before_returning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        let config = mvm_core::user_config::MvmConfig {
            host_budget_memory_mib: Some(64),
            ..Default::default()
        };
        mvm_core::user_config::save(&config, None).expect("host config");
        let rootfs = write_rootfs(dir.path(), b"over-budget rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);

        let error = match admit_plan_for_boot_syncing_beside_boot(params) {
            Ok(_) => panic!("a 512 MiB boot must not fit a 64 MiB host budget"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("budget"),
            "the refusal names the budget: {error:#}"
        );
        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl")).unwrap_or_default();
        assert!(
            !chain.contains("plan.admitted"),
            "a refused boot is not recorded as admitted: {chain}"
        );
    }

    #[test]
    fn an_uninstalled_pack_image_is_refused_before_plan_signing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        let rootfs = write_rootfs(dir.path(), b"pack rootfs");
        let keys_dir = dir.path().join("keys");
        let ledger = InMemoryNonceLedger::new();
        let pin = mvm_core::registry_pack::PackPin::new(
            "runtime/absent@1.0.0".parse().expect("versioned reference"),
            mvm_core::packs::Sha256Hex::from_bytes(b"signed manifest"),
        )
        .expect("pin");
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.assets = vec![AssetSpec::RegistryPack(pin)];

        let error = admit_plan_for_boot(params).expect_err("uninstalled pack refused");
        assert!(format!("{error:#}").contains("not pinned"), "{error:#}");
        assert!(
            !keys_dir.exists(),
            "refusal must not initialize signer keys"
        );
    }

    #[test]
    fn asset_identity_audit_failure_refuses_admission_before_boot() {
        let _home = isolated_home();
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = write_rootfs(dir.path(), b"asset audit rootfs");
        let declared = dir.path().join("declared-input.txt");
        std::fs::write(&declared, b"bound asset").expect("declared asset");
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(audit_dir.join("local.jsonl"))
            .expect("block the chain file with a directory");
        let keys_dir = dir.path().join("keys");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.restrict_agent_verbs = false;
        params.assets = vec![AssetSpec::File {
            kind: mvm_core::plan::AssetKind::Dataset,
            host_path: declared.to_string_lossy().into_owned(),
        }];

        let error = admit_plan_for_boot(params).expect_err("asset identity must be audited");
        assert!(
            format!("{error:#}").contains("recording admitted asset identities"),
            "{error:#}"
        );
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn signed_pack_identity_is_in_admitted_plan_and_audit_chain() {
        use mvm_core::registry_pack::{
            PackAdoption, PackPin, RegistryPackPublisher, RegistryPackPublisherPolicy,
        };
        use mvm_core::registry_pack_store::{adopt_install_and_pin, save_publisher_policy};

        const MANIFEST: &[u8] =
            include_bytes!("../../tests/fixtures/signed-registry-python/manifest.json");
        const BUNDLE: &[u8] =
            include_bytes!("../../tests/fixtures/signed-registry-python/manifest.sigstore.json");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path().join("home"));
        let publisher = RegistryPackPublisher::new(
            "runtime",
            "https://token.actions.githubusercontent.com",
            vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/feat/3716-python-image-pack".to_string()],
        )
        .expect("fixture signer identity");
        let policy = RegistryPackPublisherPolicy::new(vec![publisher]).expect("publisher policy");
        save_publisher_policy(
            &mvm_core::config::registry_pack_publisher_policy_path(),
            &policy,
        )
        .expect("save fixture trust");
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/signed-registry-python/files");
        let staged = dir.path().join("staged-pack");
        for relative in [
            "pack/group.toml",
            "pack/image/mvm.toml",
            "pack/image/flake.nix",
            "pack/image/flake.lock",
        ] {
            let destination = staged.join(relative);
            std::fs::create_dir_all(destination.parent().expect("payload parent"))
                .expect("create payload directory");
            std::fs::copy(fixture.join(relative), destination).expect("stage signed payload");
        }
        let reference = "runtime/python@1.1.0".parse().expect("pack reference");
        adopt_install_and_pin(
            &PackAdoption {
                requested: &reference,
                manifest_bytes: MANIFEST,
                signature_bundle: BUNDLE,
                publisher_policy: &policy,
            },
            &staged,
            &mvm_core::config::registry_pack_cache_dir(),
            &mvm_core::config::pack_lockfile_path(),
        )
        .expect("install signed fixture pack");

        let digest = mvm_core::packs::Sha256Hex::from_bytes(MANIFEST);
        let pin = PackPin::new(reference.clone(), digest.clone()).expect("signed pack pin");
        let rootfs = write_rootfs(dir.path(), b"pack rootfs");
        let keys_dir = dir.path().join("keys");
        let audit_dir = dir.path().join("audit");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.keys_dir = Some(&keys_dir);
        params.audit_dir = Some(&audit_dir);
        params.assets = vec![AssetSpec::RegistryPack(pin)];
        params.backend_kind = Some(mvm_core::vm_backend::BackendKind::Firecracker);

        let admitted = admit_plan_for_boot(params).expect("signed pack admission");
        let asset = admitted
            .admitted
            .plan()
            .asset_identities
            .iter()
            .find(|asset| asset.kind == mvm_core::plan::AssetKind::RegistryPack)
            .expect("signed plan pins pack identity");
        assert_eq!(asset.name, reference.to_string());
        assert_eq!(asset.digest, digest.as_str());

        let mut substrate = crate::entrypoint::SessionAuditSubstrate {
            host_budget: admitted.admitted.host_budget_permit(),
            tenant_id: admitted.admitted.plan().tenant.0.clone(),
            plan_json: serde_json::to_string(admitted.admitted.signed()).unwrap(),
            audit_context: admitted.admitted.workload_audit_context(),
            mailbox_posture: admitted.admitted.mailbox_posture(),
            caller_registration: None,
            config_files: Vec::new(),
            read_only_materialized_images: vec!["admitted-image.ext4".into()],
            built_pack_check: admitted.admitted.built_pack_boot_check().unwrap(),
            durability: Some(
                mvm_core::admission_durability::AdmissionDurability::settled(Err(anyhow::anyhow!(
                    "audit sync refused"
                ))),
            ),
        };
        let check = substrate
            .built_pack_check
            .take()
            .expect("admitted pack check");
        let mut config = mvm_core::vm_backend::VmStartConfig::default();
        assert_eq!(substrate.apply_to(&mut config), vec!["admitted-image.ext4"]);
        assert!(
            check
                .prepare(&mut config, mvm_core::vm_backend::BackendKind::Firecracker)
                .unwrap()
                .is_none(),
            "a signed Source pack retains its existing non-built launch path"
        );
        assert!(
            config
                .admission_durability
                .as_ref()
                .unwrap()
                .wait()
                .is_err(),
            "carrying the image check must not drop a failed admission sync"
        );

        let chain = std::fs::read_to_string(audit_dir.join("local.jsonl"))
            .expect("read admitted audit chain");
        assert!(chain.contains("plan.asset_identities"), "{chain}");
        assert!(chain.contains("registry_pack"), "{chain}");
        assert!(chain.contains(digest.as_str()), "{chain}");
    }

    /// The image digest says what the workload *is* and nothing about what
    /// confines it, so a plan that names the image but not the kernel admits a
    /// workload onto whatever kernel the host happened to have cached. This is
    /// the assertion that would have caught `kernel_sha256: None` sitting on
    /// the CLI's only admission seam.
    #[test]
    fn the_booting_kernel_is_pinned_into_the_signed_plan() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let kernel = rootfs_dir.path().join("vmlinux");
        std::fs::write(&kernel, b"workload-kernel-bytes").unwrap();
        let expected = mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap();
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            outputs: Vec::new(),
            kernel_path: Some(kernel.as_path()),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        let environment = ctx
            .admitted
            .plan()
            .environment
            .as_ref()
            .expect("a launch that boots a kernel must pin it");
        assert_eq!(environment.kernel_sha256, expected);

        // And the pin is what the enforcement gate compares against, so the
        // kernel that was admitted is admitted onto itself rather than the pin
        // being a value nothing ever reads.
        mvm_hostd::plan_admission::enforce_admitted_environment(
            Some(kernel.as_path()),
            ctx.admitted.plan(),
        )
        .expect("the pinned kernel must pass its own gate");
    }

    /// QEMU's x86_64 loader refuses an uncompressed ELF with no PVH entry note,
    /// which is the vmlinux Firecracker boots. Admission has to refuse it by
    /// name rather than sign a plan for a boot QEMU will reject.
    #[test]
    fn qemu_admission_refuses_an_elf_kernel_qemu_cannot_load() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        // A little-endian ELF64 header with no program headers, so no notes.
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        let kernel = rootfs_dir.path().join("vmlinux");
        std::fs::write(&kernel, &elf).unwrap();

        let admit = |kind| {
            let ledger = InMemoryNonceLedger::new();
            admit_plan_for_boot(AdmitPlanForBootParams {
                bundle_sizing: Default::default(),
                mailbox: None,
                gpu: false,
                instructions: Default::default(),
                outputs: Vec::new(),
                kernel_path: Some(kernel.as_path()),
                keys_dir: Some(keys_dir.path()),
                audit_dir: Some(audit_dir.path()),
                backend_kind: Some(kind),
                ..pinning_params(&rootfs, &ledger)
            })
            .map(|_| ())
        };

        let on_qemu = admit(mvm_core::vm_backend::BackendKind::Qemu);
        if mvm_core::arch::GuestArch::host() == mvm_core::arch::GuestArch::X86_64 {
            let err = format!("{:#}", on_qemu.expect_err("qemu x86_64 must refuse"));
            assert!(err.contains("no PVH entry note"), "{err}");
            assert!(err.contains("CONFIG_PVH=y"), "{err}");
        } else {
            on_qemu.expect("the PVH rule binds only an x86_64 guest");
        }
        admit(mvm_core::vm_backend::BackendKind::Firecracker)
            .expect("Firecracker boots the same ELF without a PVH note");
    }

    /// A kernel swapped between admission and boot is refused. Same plan, same
    /// image, a different confinement — the substitution the pin exists to make
    /// visible.
    #[test]
    fn a_kernel_swapped_after_admission_is_refused() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let kernel = rootfs_dir.path().join("vmlinux");
        std::fs::write(&kernel, b"workload-kernel-bytes").unwrap();
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            outputs: Vec::new(),
            kernel_path: Some(kernel.as_path()),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        std::fs::write(&kernel, b"a-general-purpose-kernel-with-user-ns").unwrap();

        let err = mvm_hostd::plan_admission::enforce_admitted_environment(
            Some(kernel.as_path()),
            ctx.admitted.plan(),
        )
        .expect_err("a kernel swapped after admission must be refused");
        assert!(
            format!("{err:#}").contains("admitted-environment mismatch"),
            "error must name the mismatch, got: {err:#}"
        );
    }

    #[test]
    fn admits_real_rootfs_and_returns_plan_id() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let boot_artifact = mvm_core::deploy_record::digest_boot_artifact(&rootfs).unwrap();
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-happy",
            boot_artifact_identity: Some(&boot_artifact),
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Network,
            secret_release: mvm_core::plan::SecretReleasePolicy::PlanBound,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");
        assert!(!ctx.admitted.plan_id().0.is_empty());
        assert_eq!(ctx.admitted.plan().workload.0, "vm-happy");
        assert_eq!(ctx.admitted.plan().tenant.0, "local");
        assert_eq!(ctx.admitted.plan().resources.cpus, 2);
        assert_eq!(ctx.admitted.plan().resources.mem_mib, 512);
        assert_eq!(ctx.admitted.plan().image.sha256, boot_artifact.sha256);
        assert_eq!(
            ctx.admitted.plan().admission_profile.seccomp_tier,
            mvm_core::plan::PlanSeccompTier::Network
        );
        assert_eq!(
            ctx.admitted.plan().admission_profile.secret_release,
            mvm_core::plan::SecretReleasePolicy::PlanBound
        );

        // The `plan.admitted` audit line must be present in the
        // tenant's chain file already (admit_plan_for_boot emits
        // it inline before returning).
        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.admitted"));
        assert!(content.contains(&ctx.admitted.plan_id().0));
    }

    #[test]
    fn admission_failure_when_rootfs_missing() {
        let _home = isolated_home();
        // sha256_file fails when the file does not exist; the helper
        // must propagate the error with context naming the rootfs path.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();
        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-missing",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(std::path::Path::new("/nonexistent/rootfs.ext4"), &ledger)
        })
        .expect_err("missing rootfs must fail");
        assert!(
            err.chain().any(|e| e.to_string().contains("rootfs")),
            "error must name rootfs: {err}"
        );
    }

    /// The plan must record the transport the launch gives the guest.
    ///
    /// This was hardcoded to `NetworkMode::None` — "no guest NIC, no broker,
    /// the workload cannot reach the network" — for every admission, including
    /// the ordinary ones that derive `HostVsockProxy` and get a broker stood up
    /// for them. The value is inside the signature, so the record was
    /// confidently wrong rather than merely absent.
    /// The retired in-guest IP stack does not boot, and says why.
    ///
    /// The refusal is the thing that keeps the migration to a single
    /// networking path from ever running three live production paths at once,
    /// so it is asserted on the message an operator actually reads — naming
    /// both replacements — not merely on `is_err()`.
    #[test]
    fn a_launch_asking_for_the_retired_ip_stack_is_refused() {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_mode = mvm_contract::plan::NetworkMode::HostVsockProxy;
        let json = serde_json::to_string(&plan)
            .expect("plan serializes")
            .replace("host_vsock_proxy", "l3_vsock");
        let err = serde_json::from_str::<mvm_contract::plan::ExecutionPlan>(&json)
            .expect_err("the retired transport must not enter the admitted type");
        let msg = err.to_string();
        assert!(msg.contains("has been retired"), "{msg}");
        assert!(msg.contains("FlowMux loopback adapters"), "{msg}");
        assert!(msg.contains("typed connector"), "{msg}");
    }

    #[test]
    fn the_admitted_plan_records_the_transport_the_launch_derived() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"transport");

        for mode in [
            mvm_contract::plan::NetworkMode::HostVsockProxy,
            mvm_contract::plan::NetworkMode::None,
        ] {
            let ledger = InMemoryNonceLedger::new();
            let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
                bundle_sizing: Default::default(),
                mailbox: None,
                network_mode: mode,
                vm_name: "vm-transport",
                cpus: 1,
                mem_mib: 128,
                keys_dir: Some(keys_dir.path()),
                audit_dir: Some(audit_dir.path()),
                bundle_pin: None,
                bundle_posture: None,
                deps_volume: None,
                shares: Vec::new(),
                assets: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
                agent_verb_override: vec![],
                restrict_agent_verbs: false,
                entrypoint: crate::admission::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                    "test",
                ),
                ..pinning_params(&rootfs, &ledger)
            })
            .expect("admit");

            assert_eq!(
                ctx.admitted.plan().network_mode,
                mode,
                "the plan must record the mode the launch was admitted with"
            );
        }
    }

    #[test]
    fn two_admissions_in_same_run_produce_distinct_plan_ids() {
        let _home = isolated_home();
        // The shared ledger is the per-`cmd_run` replay-store. Two
        // admissions with different rootfs hashes (or even same hash —
        // synthesize_plan generates fresh nonces) must both succeed.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"first");
        let ledger = InMemoryNonceLedger::new();

        let a1 = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-1",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .unwrap();
        let a2 = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-2",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .unwrap();
        assert_ne!(a1.admitted.plan_id(), a2.admitted.plan_id());
        assert_ne!(a1.admitted.plan().nonce, a2.admitted.plan().nonce);
    }

    /// Admit a real plan whose chain is written to `audit_dir`. The signer,
    /// chain and plan are the production ones; only where they live is injected.
    pub(crate) fn admitted_into(
        keys_dir: &std::path::Path,
        audit_dir: &std::path::Path,
        vm_name: &str,
    ) -> AdmissionContext {
        let rootfs_dir = tempfile::tempdir().expect("rootfs dir");
        let rootfs = write_rootfs(rootfs_dir.path(), vm_name.as_bytes());
        let ledger = InMemoryNonceLedger::new();
        admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name,
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir),
            audit_dir: Some(audit_dir),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission")
    }

    #[test]
    fn cli_owner_retains_exact_admission_until_legacy_selection_finishes() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let context = admitted_into(keys_dir.path(), audit_dir.path(), "vm-cli-owner");
        let original_id = context.admitted.plan_id().clone();
        let original_nonce = context.admitted.plan().nonce.clone();
        let signed = serde_json::to_string(context.admitted.signed()).expect("signed envelope");
        let owner = CliAdmission::new(context);
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-cli-owner".into(),
            plan_json: Some(signed),
            ..Default::default()
        };
        owner
            .check_legacy_projection(&config)
            .expect("the three projected fields match the admitted owner");
        assert_eq!(owner.plan().plan_id, original_id);
        assert_eq!(owner.plan().nonce, original_nonce);
        let changed_name = mvm_core::vm_backend::VmStartConfig {
            name: "other-vm".into(),
            ..config.clone()
        };
        let identity_error = owner
            .check_legacy_projection(&changed_name)
            .expect_err("the admitted VM name cannot drift");
        assert!(
            identity_error.to_string().contains("identity differs"),
            "{identity_error:#}"
        );
        let changed = mvm_core::vm_backend::VmStartConfig {
            plan_json: Some("{}".into()),
            ..config
        };
        let error = owner
            .check_legacy_projection(&changed)
            .expect_err("JSON cannot replace the admitted authority");
        assert!(
            error.to_string().contains("projection differs"),
            "{error:#}"
        );
        let continuation = owner.finish_legacy();
        assert_eq!(continuation.plan().plan_id, original_id);
        assert_eq!(continuation.plan().nonce, original_nonce);
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("admission was recorded");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert!(!chain.contains("plan.launched"), "{chain}");
    }

    #[test]
    fn cli_cold_refuses_a_changed_source_projection_without_spending_authority() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let context = admitted_into(keys_dir.path(), audit_dir.path(), "vm-source-owner");
        let original_nonce = context.admitted.plan().nonce.clone();
        let signed = serde_json::to_string(context.admitted.signed()).expect("signed plan");
        let owner = CliAdmission::new_for_rootfs(context, std::path::Path::new("/admitted/rootfs"));
        let config = mvm_core::vm_backend::VmStartConfig {
            name: "vm-source-owner".into(),
            rootfs_path: "/substituted/rootfs".into(),
            plan_json: Some(signed),
            ..Default::default()
        };
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let (owner, result) = owner.start_cold(&backend, config, Vec::new());
        assert!(result.is_err(), "altered projection must not dispatch");
        assert_eq!(owner.plan().nonce, original_nonce);
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("admission record");
        assert_eq!(chain.matches("plan.admitted").count(), 1, "{chain}");
        assert!(!chain.contains("plan.launched"), "{chain}");
    }

    #[test]
    fn cli_cold_cannot_dispatch_a_legacy_owner_without_source_binding() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let context = admitted_into(keys_dir.path(), audit_dir.path(), "vm-no-source");
        let nonce = context.admitted.plan().nonce.clone();
        let owner = CliAdmission::new(context);
        let backend = mvm_runtime::AnyBackend::from_hypervisor("mock");
        let (owner, result) = owner.start_cold(&backend, Default::default(), Vec::new());
        assert!(result.is_err(), "a plan without its source cannot dispatch");
        assert_eq!(owner.plan().nonce, nonce);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn legacy_pending_cli_admission_cannot_enter_the_warm_claim_path() {
        let (_env, home) = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let rootfs = write_rootfs(home.path(), b"warm child image");
        let ledger = InMemoryNonceLedger::new();
        let context = admit_plan_for_boot(AdmitPlanForBootParams {
            vm_name: "warm-child",
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admit warm child");
        let owner = CliAdmission::new_for_rootfs(context, &rootfs);
        let pool = mvm_runtime::standby_pool::SupervisorStandbyPool::at(home.path().join("pool"));
        let checkpoints = mvm_runtime::checkpoint::CheckpointStore::at(home.path().join("checks"));
        let snapshots = mvm_fs::snapshot_store::FsSnapshotStore::new(home.path().join("snaps"))
            .expect("snapshot store");
        let anchor = crate::checkpoint::anchor::SignedChainAnchor::empty();
        let parent = mvm_core::checkpoint::CheckpointId::new("mock-parent");
        let registry_path = home.path().join("names.json");
        let claim_context = crate::ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent,
            registry_path: &registry_path,
            grant_issuer: None,
        };
        let handle = mvm_core::vm_backend::StandbyHandle {
            id: "mock-standby".into(),
            template_id: None,
            control_socket: String::new(),
            pid: 0,
            kernel_sha256: String::new(),
            vcpus: 2,
            mem_mib: 512,
            binding_nonce: String::new(),
            spawned_unix_secs: 0,
            state: mvm_core::vm_backend::StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        };
        let backend =
            mvm_runtime::AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby());

        let (owner, result) = owner.claim_prepared_warm(&backend, &claim_context, &handle);
        let error = result.expect_err("legacy pending admission cannot claim warm");
        assert!(
            error
                .to_string()
                .contains("requires host-prepared CLI cold authority"),
            "{error:#}"
        );
        assert!(matches!(owner, CliAdmission::Dispatched(_)));
    }

    /// Admit a warm child, quarantine its workload, then claim it on `mock`.
    #[cfg(feature = "test-support")]
    fn claim_warm_after_quarantine(
        mock: mvm_runtime::mock::MockBackend,
    ) -> anyhow::Result<crate::standby::OwnedWarmClaim> {
        let backend = mvm_runtime::AnyBackend::Mock(mock);
        let (_env, home) = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let runtime_dir = tempfile::tempdir().expect("runtime");
        let rootfs = write_rootfs(home.path(), b"warm child image");
        let ledger = InMemoryNonceLedger::new();
        let runtime = mvm_build::guest_runtime::evidence::verified_release_runtime_fixture(
            runtime_dir.path(),
            mvm_core::arch::GuestArch::host(),
            mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        );
        let release = std::sync::Arc::clone(&runtime.release);
        let workload = std::cell::RefCell::new(None);
        let prepared = crate::admission::prepare_cli_cold(
            &backend,
            mvm_core::vm_backend::VmStartConfig {
                name: "warm-child".into(),
                rootfs_path: rootfs.display().to_string(),
                ..Default::default()
            },
            |config| {
                config.runtime_release_proof = Some(release.proof().clone());
                config.runtime_overlay_path = Some(runtime.overlay.display().to_string());
                config.runtime_overlay_verity_path =
                    Some(runtime.overlay_verity.display().to_string());
                config.runtime_overlay_roothash = Some(runtime.overlay_roothash.clone());
                config.runtime_overlay_version = Some(release.proof().version.clone());
                config.initrd_path = Some(runtime.initramfs.display().to_string());
                Ok(Some(release))
            },
            |config, verified_runtime| {
                let verified_runtime =
                    verified_runtime.context("fixture must retain verified runtime")?;
                let (context, durability) =
                    admit_plan_for_boot_with_verified_runtime_syncing_beside_boot(
                        AdmitPlanForBootParams {
                            vm_name: "warm-child",
                            keys_dir: Some(keys_dir.path()),
                            audit_dir: Some(audit_dir.path()),
                            runtime_config: Some(config),
                            ..pinning_params(&rootfs, &ledger)
                        },
                        verified_runtime,
                    )?;
                config.admission_durability = Some(durability);
                config.plan_json = Some(serde_json::to_string(context.admitted.signed())?);
                *workload.borrow_mut() = Some(context.admitted.plan().workload.0.clone());
                Ok(crate::admission::CliColdAdmissionInput::new(
                    CliAdmission::new_for_rootfs(context, &rootfs),
                    None,
                ))
            },
        )
        .expect("prepare warm child");
        let store =
            mvm_hostd::policy_generation::workload_store::OwnedWorkloadStore::open(home.path())
                .expect("workload store");
        store
            .commit(
                &mvm_core::host_interface::workload::WorkloadChange::Quarantine {
                    workload: workload.borrow_mut().take().expect("admitted workload"),
                },
            )
            .expect("quarantine after admission");
        drop(store);
        let pool = mvm_runtime::standby_pool::SupervisorStandbyPool::at(home.path().join("pool"));
        let checkpoints = mvm_runtime::checkpoint::CheckpointStore::at(home.path().join("checks"));
        let snapshots = mvm_fs::snapshot_store::FsSnapshotStore::new(home.path().join("snaps"))
            .expect("snapshot store");
        let anchor = crate::checkpoint::anchor::SignedChainAnchor::empty();
        let parent = mvm_core::checkpoint::CheckpointId::new("mock-parent");
        let registry_path = home.path().join("names.json");
        let claim_context = crate::ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent,
            registry_path: &registry_path,
            grant_issuer: None,
        };
        let handle = mvm_core::vm_backend::StandbyHandle {
            id: "mock-standby".into(),
            template_id: None,
            control_socket: String::new(),
            pid: 0,
            kernel_sha256: String::new(),
            vcpus: 2,
            mem_mib: 512,
            binding_nonce: String::new(),
            spawned_unix_secs: 0,
            state: mvm_core::vm_backend::StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        };
        prepared
            .admission
            .claim_prepared_warm(&backend, &claim_context, &handle)
            .1
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn a_warm_child_contained_after_admission_is_stopped_before_custody() {
        let mock = mvm_runtime::mock::MockBackend::new().with_standby();
        let error = claim_warm_after_quarantine(mock.clone())
            .expect_err("a quarantined workload must not hand back a claimed child");
        assert!(
            format!("{error:#}").contains("no longer admits"),
            "{error:#}"
        );
        assert!(
            !matches!(
                error.downcast_ref::<mvm_hostd::plan_admission::CliStartFailure>(),
                Some(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(_))
            ),
            "{error:#}"
        );
        assert_eq!(mock.count(), 0, "the claimed child was stopped");
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn a_warm_child_that_cannot_be_stopped_is_reported_uncertain() {
        let mock = mvm_runtime::mock::MockBackend::new()
            .with_standby()
            .with_failing_stop();
        let error = claim_warm_after_quarantine(mock.clone())
            .expect_err("a quarantined workload must not hand back a claimed child");
        assert!(
            matches!(
                error.downcast_ref::<mvm_hostd::plan_admission::CliStartFailure>(),
                Some(mvm_hostd::plan_admission::CliStartFailure::UncertainStop(_))
            ),
            "{error:#}"
        );
        assert_eq!(
            mock.count(),
            1,
            "the child that would not stop is still live"
        );
    }

    #[test]
    fn record_boot_audits_the_root_strategy_label() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let ctx = admitted_into(keys_dir.path(), audit_dir.path(), "vm-boot-posture");

        record_boot(
            &ctx.emitter,
            ctx.admitted.plan(),
            "firecracker",
            "vm-boot-posture",
            BootPosture::block(),
        );

        let content = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("audit file exists");
        assert!(
            content.contains("plan.boot_posture"),
            "audit chain must include boot posture event: {content}"
        );
        assert!(
            content.contains("\"root_strategy\":\"block-ext4\""),
            "audit chain must carry the root_strategy label: {content}"
        );
    }

    /// A transient run that booted records `plan.launched` and its posture, and
    /// nothing that reads as a failure — the two outcomes share one helper, so
    /// each branch is pinned to the entries it alone writes.
    #[test]
    fn a_transient_run_that_booted_records_launched_and_posture() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let ctx = admitted_into(keys_dir.path(), audit_dir.path(), "vm-transient-ok");

        record_boot(
            &ctx.emitter,
            ctx.admitted.plan(),
            "firecracker",
            "vm-transient-ok",
            BootPosture {
                start: Some(StartMode::Warm),
                ..BootPosture::block()
            },
        );

        let content = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("audit file exists");
        assert!(content.contains("plan.launched"), "{content}");
        assert!(content.contains("plan.boot_posture"), "{content}");
        assert!(content.contains("plan.start_mode"), "{content}");
        assert!(content.contains("\"mode\":\"warm\""), "{content}");
        assert!(!content.contains("cold_reason"), "{content}");
        assert!(!content.contains("plan.failed"), "{content}");
    }

    /// A cold boot is declared on the chain with its reason, so the first run
    /// of an image can be told apart from a run that should have been warm.
    #[test]
    fn a_cold_transient_run_records_why_it_was_cold() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().expect("keys dir");
        let audit_dir = tempfile::tempdir().expect("audit dir");
        let ctx = admitted_into(keys_dir.path(), audit_dir.path(), "vm-transient-cold");

        record_boot(
            &ctx.emitter,
            ctx.admitted.plan(),
            "firecracker",
            "vm-transient-cold",
            BootPosture {
                start: Some(StartMode::Cold {
                    reason: "no_standby_ready",
                }),
                ..BootPosture::block()
            },
        );

        let content = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("audit file exists");
        assert!(content.contains("\"mode\":\"cold\""), "{content}");
        assert!(
            content.contains("\"cold_reason\":\"no_standby_ready\""),
            "{content}"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Policy resolution recorded at admission
    //
    // A deny-all launch ships `local-default` policy refs, so the
    // happy-path admission must succeed and emit `plan.policy_resolved`
    // with `resolution="local-default"`.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn admission_emits_policy_resolved_for_default_local_default_refs() {
        let _home = isolated_home();
        // The synthesized plan defaults to `local-default` on every
        // ref; validation succeeds without a bundle. The hook must
        // record that resolution without implying a live control.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"local-default-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-local-default",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.admitted"));
        assert!(
            content.contains("plan.policy_resolved"),
            "audit chain must include plan.policy_resolved: {content}"
        );
        assert!(
            content.contains("\"resolution\":\"local-default\""),
            "audit chain must record local-default policy resolution: {content}"
        );
        assert!(!content.contains("slots_mode"), "{content}");
        // Sanity: plan_id matches.
        assert!(content.contains(&ctx.admitted.plan_id().0));
    }

    #[test]
    fn admission_binds_an_allow_list_into_the_signed_plan() {
        let _home = isolated_home();
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"allow-list-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-allow-list",
            backend_name: "libkrun",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("93.184.216.34", 443)]),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        // Egress reaches the network through a loopback proxy the workload
        // dials, so the admitted tier has to grant sockets.
        assert_eq!(
            ctx.admitted.plan().admission_profile.seccomp_tier,
            mvm_core::plan::PlanSeccompTier::Network
        );
        assert_eq!(ctx.admitted.plan().audit_labels["seccomp_tier"], "network");
        assert_ne!(
            ctx.admitted.plan().network_policy.0,
            mvm_core::plan::DEFAULT_POLICY_REF
        );
        assert_eq!(
            ctx.admitted.plan().network_policy.0,
            ctx.admitted.plan().egress_policy.0
        );
        let policy_asset = ctx
            .admitted
            .plan()
            .asset_identities
            .iter()
            .find(|asset| asset.kind == mvm_core::plan::AssetKind::Policy)
            .expect("the signed plan binds the network policy as an asset");
        assert_eq!(policy_asset.name, ctx.admitted.plan().network_policy.0);
        assert_eq!(
            policy_asset.digest,
            mvm_core::policy::network_policy::content_sha256(&NetworkPolicy::allow_list(vec![
                HostPort::new("93.184.216.34", 443)
            ]))
        );

        let content =
            std::fs::read_to_string(audit_dir.path().join("local.jsonl")).expect("audit file");
        assert!(
            content.contains("\"resolution\":\"network-policy\""),
            "an egress grant must audit as a network-policy resolution: {content}"
        );
        assert!(!content.contains("slots_mode"), "{content}");
    }

    /// The admitted egress destinations reach the chain from the launch's own
    /// network policy: one sorted, de-duplicated `(host, port)` per allowed
    /// destination, on a plan whose refs are the generated label. Deny-all
    /// and unrestricted launches record no destination list.
    #[test]
    fn admission_records_allow_list_destinations_from_the_network_policy() {
        let _home = isolated_home();
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        let admit = |vm_name: &'static str, network_policy: NetworkPolicy| {
            let keys_dir = tempfile::tempdir().unwrap();
            let audit_dir = tempfile::tempdir().unwrap();
            let rootfs_dir = tempfile::tempdir().unwrap();
            let rootfs = write_rootfs(rootfs_dir.path(), vm_name.as_bytes());
            let ledger = InMemoryNonceLedger::new();
            let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
                bundle_sizing: Default::default(),
                mailbox: None,
                vm_name,
                cpus: 1,
                mem_mib: 128,
                keys_dir: Some(keys_dir.path()),
                audit_dir: Some(audit_dir.path()),
                network_policy,
                ..pinning_params(&rootfs, &ledger)
            })
            .expect("admission");
            let content = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
                .expect("the default chain holds every admission record");
            (ctx.admitted.plan().clone(), content)
        };

        let (plan, content) = admit(
            "vm-destinations",
            NetworkPolicy::allow_list(vec![
                HostPort::new("203.0.113.7", 8443),
                HostPort::new("93.184.216.34", 443),
                HostPort::new("203.0.113.7", 8443),
            ]),
        );
        let generated_ref = format!("{}:vm-destinations", plan.tenant.0);
        assert_eq!(plan.network_policy.0, generated_ref);
        assert_eq!(plan.egress_policy.0, generated_ref);
        assert_eq!(plan.fs_policy.0, generated_ref);
        let entry = content
            .lines()
            .find(|line| line.contains("\"plan.egress_destinations\""))
            .unwrap_or_else(|| panic!("no plan.egress_destinations entry: {content}"));
        for label in [
            "\"destination_count\":\"2\"",
            "\"destination_0_host\":\"203.0.113.7\"",
            "\"destination_0_port\":\"8443\"",
            "\"destination_1_host\":\"93.184.216.34\"",
            "\"destination_1_port\":\"443\"",
        ] {
            assert!(entry.contains(label), "missing {label}: {entry}");
        }

        let (plan, content) = admit("vm-deny-all", NetworkPolicy::deny_all());
        assert_eq!(plan.network_policy.0, mvm_core::plan::DEFAULT_POLICY_REF);
        assert!(content.contains("plan.admitted"), "{content}");
        assert!(!content.contains("plan.egress_destinations"), "{content}");

        let (plan, content) = admit("vm-open", NetworkPolicy::unrestricted());
        assert_eq!(plan.network_policy.0, format!("{}:vm-open", plan.tenant.0));
        assert!(!content.contains("plan.egress_destinations"), "{content}");

        // A preset's hosts are recorded as the preset expands them.
        let preset = mvm_core::network_policy::NetworkPreset::Agent;
        let (_, content) = admit("vm-preset", NetworkPolicy::preset(preset));
        let entry = content
            .lines()
            .find(|line| line.contains("\"plan.egress_destinations\""))
            .unwrap_or_else(|| panic!("no plan.egress_destinations entry: {content}"));
        let expected = self::policy::egress_destinations(&NetworkPolicy::preset(preset));
        assert!(!expected.is_empty());
        assert!(
            entry.contains(&format!("\"destination_count\":\"{}\"", expected.len())),
            "{entry}"
        );
        for (host, _) in &expected {
            assert!(
                entry.contains(&format!("\"{host}\"")),
                "missing {host}: {entry}"
            );
        }
    }

    /// A destination the egress gate could never pin is refused before the
    /// plan is signed, naming the entry, whatever source supplied it — not
    /// signed, audited as admitted, and then silently denied at the endpoint.
    #[test]
    fn admission_refuses_a_destination_the_gate_cannot_pin() {
        let _home = isolated_home();
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        for host in ["*.example.com", "10.0.0.0/8", "[::1]", "bad..name"] {
            let keys_dir = tempfile::tempdir().unwrap();
            let audit_dir = tempfile::tempdir().unwrap();
            let rootfs_dir = tempfile::tempdir().unwrap();
            let rootfs = write_rootfs(rootfs_dir.path(), b"unpinnable");
            let ledger = InMemoryNonceLedger::new();
            let err = admit_plan_for_boot(AdmitPlanForBootParams {
                bundle_sizing: Default::default(),
                mailbox: None,
                vm_name: "vm-unpinnable",
                cpus: 1,
                mem_mib: 128,
                keys_dir: Some(keys_dir.path()),
                audit_dir: Some(audit_dir.path()),
                network_policy: NetworkPolicy::allow_list(vec![
                    HostPort::new("api.github.com", 443),
                    HostPort::new(host, 443),
                ]),
                ..pinning_params(&rootfs, &ledger)
            })
            .err()
            .unwrap_or_else(|| panic!("{host} must be refused"));
            let msg = format!("{err:#}");
            assert!(msg.contains(host), "{host}: {msg}");
            assert!(
                !audit_dir.path().join("local.jsonl").exists(),
                "{host}: nothing is admitted or audited as admitted"
            );
        }
    }

    #[test]
    fn admission_binds_unrestricted_egress_into_the_signed_plan() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unrestricted-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-unrestricted",
            backend_name: "hvf",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::unrestricted(),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        assert_ne!(
            ctx.admitted.plan().network_policy.0,
            mvm_core::plan::DEFAULT_POLICY_REF
        );
        let policy_asset = ctx
            .admitted
            .plan()
            .asset_identities
            .iter()
            .find(|asset| asset.kind == mvm_core::plan::AssetKind::Policy)
            .expect("the signed plan binds the network policy as an asset");
        assert_eq!(
            policy_asset.digest,
            mvm_core::policy::network_policy::content_sha256(
                &mvm_core::network_policy::NetworkPolicy::unrestricted()
            )
        );
    }

    #[test]
    fn up_populates_agent_verbs_default_and_override() {
        use crate::admission::agent_verbs::{default_agent_verbs, parse_agent_verb_override};
        // Default path: sealed-prod, no shares → run-entrypoint present, mount-volume absent.
        let d = parse_agent_verb_override(&[])
            .unwrap()
            .or_else(|| default_agent_verbs(true, false, false))
            .unwrap();
        assert!(d.iter().any(|v| v.as_str() == "run-entrypoint"));
        assert!(!d.iter().any(|v| v.as_str() == "mount-volume"));
        // Override path: explicit set replaces the default.
        let o = parse_agent_verb_override(&["run-entrypoint".into()])
            .unwrap()
            .or_else(|| default_agent_verbs(true, false, false))
            .unwrap();
        assert_eq!(
            o.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            ["run-entrypoint"]
        );
        // Dev path: None (class-gate only).
        assert!(
            parse_agent_verb_override(&[])
                .unwrap()
                .or_else(|| default_agent_verbs(false, false, false))
                .is_none()
        );
    }

    // ──────────────────────────────────────────────────────────────
    // A sealed-production run refuses the input grant when the
    // entrypoint is shell-shaped. These three are what make the rule a
    // real gate rather than a blanket ban: a non-shell entrypoint keeps
    // its grant, a shell entrypoint keeps booting when nothing granted
    // it input in the first place, and only the intersection refuses.
    // ──────────────────────────────────────────────────────────────

    fn stream_grant_service() -> mvm_contract::protocol::broker::ServiceId {
        mvm_contract::protocol::broker::ServiceId::parse(
            mvm_contract::stream::input::INPUT_GRANT_SERVICE,
        )
        .expect("the input grant token is a valid service id")
    }

    /// Admission content-hashes directory shares, and only those.
    ///
    /// Two mutants survived on the guard: `==` swapped for `!=`, and `&&` for
    /// `||`. Both change *which* grants get a content identity written into the
    /// signed plan. A `Disk` share hashed here carries a digest that
    /// enforcement re-checks against a tree the grant never described; a
    /// `DirShare` skipped here reaches enforcement with nothing to re-check,
    /// which is the pinning that refuses a directory edited after admission.
    ///
    /// The discriminating fixture is a non-`DirShare` grant with no digest:
    /// under either mutant it acquires one, and under the real guard it does
    /// not.
    #[test]
    fn admission_hashes_directory_shares_and_leaves_disk_shares_alone() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let share_dir = tempfile::tempdir().unwrap();
        std::fs::write(share_dir.path().join("payload"), b"shared bytes").unwrap();
        let disk_image = rootfs_dir.path().join("vol.img");
        std::fs::write(&disk_image, b"disk bytes").unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"share-digest-payload");
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            outputs: Vec::new(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            shares: vec![
                mvm_core::plan::HostShareGrant {
                    tag: "dirvol".into(),
                    host_path: share_dir.path().to_string_lossy().into_owned(),
                    guest_path: "/data".into(),
                    kind: mvm_core::plan::ShareKind::DirShare,
                    read_only: true,
                    encrypted: false,
                    content_sha256: None,
                    include: Vec::new(),
                    exclude: Vec::new(),
                },
                mvm_core::plan::HostShareGrant {
                    tag: "diskvol".into(),
                    host_path: disk_image.to_string_lossy().into_owned(),
                    guest_path: "/disk".into(),
                    kind: mvm_core::plan::ShareKind::Disk,
                    read_only: true,
                    encrypted: false,
                    content_sha256: None,
                    include: Vec::new(),
                    exclude: Vec::new(),
                },
            ],
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission with a directory and a disk share");

        let shares = &ctx.admitted.plan().shares;
        let dir = shares
            .iter()
            .find(|g| g.tag == "dirvol")
            .expect("the directory share survives admission");
        let disk = shares
            .iter()
            .find(|g| g.tag == "diskvol")
            .expect("the disk share survives admission");

        assert!(
            dir.content_sha256.is_some(),
            "a directory share must carry the content identity enforcement re-checks"
        );
        assert!(
            disk.content_sha256.is_none(),
            "a disk share must not be hashed here; a digest it never described is \
             one enforcement would re-check against the wrong thing"
        );
    }

    #[test]
    fn a_non_shell_entrypoint_with_the_grant_is_admitted_under_prod() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"non-shell-entrypoint-payload");
        // A real directory the share digest can be hashed over — the shared
        // system /tmp carries entries no test (and on multi-user hosts, no
        // admission) can read.
        let share_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-non-shell-granted",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            shares: vec![mvm_core::plan::HostShareGrant {
                tag: "uvol0".into(),
                host_path: share_dir.path().to_string_lossy().into_owned(),
                guest_path: "/data".into(),
                kind: mvm_core::plan::ShareKind::DirShare,
                read_only: true,
                encrypted: false,
                content_sha256: None,
                include: Vec::new(),
                exclude: Vec::new(),
            }],
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec!["python".to_string(), "-m".to_string(), "app".to_string()],
                shebang: None,
            },
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a non-shell entrypoint must not be refused");

        assert!(!ctx.admitted.plan_id().0.is_empty());
        let verbs = ctx
            .admitted
            .plan()
            .agent_verbs
            .as_ref()
            .expect("restricted boots receive a default verb grant");
        assert!(verbs.iter().any(|verb| verb.as_str() == "mount-volume"));
    }

    #[test]
    fn a_shell_entrypoint_without_the_grant_is_admitted_output_streaming_is_unconditional() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"shell-entrypoint-no-grant-payload");
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-shell-ungranted",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(), // no host.stream.v1 grant
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a shell entrypoint must still boot when nothing granted it input");

        assert!(!ctx.admitted.plan_id().0.is_empty());
    }

    #[test]
    fn a_shell_entrypoint_with_the_grant_is_refused_and_names_the_reason() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"shell-entrypoint-granted-payload");
        let ledger = InMemoryNonceLedger::new();

        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-shell-granted",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
            ..pinning_params(&rootfs, &ledger)
        })
        .expect_err("a shell entrypoint carrying the grant must be refused");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("shell-shaped"),
            "the refusal must name the reason: {rendered}"
        );
    }

    #[test]
    fn an_ad_hoc_override_does_not_bypass_the_sealed_input_grant_gate() {
        let _home = isolated_home();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unit-only rootfs");
        let ledger = InMemoryNonceLedger::new();
        let mut params = pinning_params(&rootfs, &ledger);
        params.restrict_agent_verbs = true;
        params.services = vec![stream_grant_service()];
        params.entrypoint = ResolvedEntrypoint::ad_hoc_override();

        let err = admit_plan_for_boot(params)
            .expect_err("an explicit override is not evidence for a sealed input grant");
        assert!(
            format!("{err:#}").contains("cannot say what the workload runs"),
            "{err:#}"
        );
    }

    #[test]
    fn an_unresolved_entrypoint_with_the_grant_is_refused() {
        let _home = isolated_home();
        // The gate's fail-closed arm. Before it, every launch path passed an
        // empty argv and the shell refusal could never fire — a control that
        // reported present and was structurally dormant. An entrypoint nobody
        // resolved is one nobody checked, and the grant is refused on that
        // basis rather than on having found a shell.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unresolved-entrypoint-payload");
        let ledger = InMemoryNonceLedger::new();

        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-entrypoint-unknown",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            entrypoint: ResolvedEntrypoint::unresolved("this launch path resolves no entrypoint"),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect_err("an unresolved entrypoint carrying the grant must be refused");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("cannot say what the workload runs"),
            "the refusal must name what it could not establish: {rendered}"
        );
        assert!(
            rendered.contains("this launch path resolves no entrypoint"),
            "and must quote the resolver's own reason: {rendered}"
        );
    }

    #[test]
    fn an_unresolved_entrypoint_without_the_grant_still_boots() {
        let _home = isolated_home();
        // Every launch path that never asks for streamed stdin passes an
        // unresolved entrypoint, so the fail-closed arm above must be
        // reachable only through the grant — otherwise this would refuse to
        // boot most of the CLI.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unresolved-no-grant-payload");
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-entrypoint-unknown-ungranted",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this launch path resolves no entrypoint"),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("an unresolved entrypoint that asked for nothing must still boot");

        assert!(!ctx.admitted.plan_id().0.is_empty());
    }

    #[test]
    fn a_dev_profile_shell_entrypoint_with_the_grant_is_not_refused() {
        let _home = isolated_home();
        // The refusal is scoped to the sealed-production tier
        // (restrict_agent_verbs). A dev/interactive/ad-hoc run already carries
        // a DevOnly Exec grant, so it must not fire there — it would be a
        // no-op wearing a security label.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"dev-shell-entrypoint-payload");
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-dev-shell",
            cpus: 1,
            mem_mib: 128,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            ledger: &ledger,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: false,
            services: vec![stream_grant_service()],
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("dev-tier runs are out of the shell-entrypoint refusal's scope");

        assert!(!ctx.admitted.plan_id().0.is_empty());
    }

    /// Stage a default-image cache entry under a temporary MVM_HOME and point
    /// the rootfs at it, exactly as a no-image boot resolves it. `source` is
    /// the sidecar's recorded acquisition (what W5g stamps).
    fn staged_default_image(
        env: &mut mvm_core::util::test_env::TestEnv,
        source: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let variant = home.path().join("cache/default-microvm/prod");
        std::fs::create_dir_all(&variant).unwrap();
        let rootfs = write_rootfs(&variant, b"staged default image");
        std::fs::write(
            variant.join("mvm-meta.json"),
            format!(
                "{{\"name\": \"mvm-default-microvm\", \"accessible\": false, \"sealed\": true, \"entrypointKind\": \"command\", \"initSystem\": \"busybox\", \"expectedBootMs\": 300, \"agentBinary\": \"real\", \"rootlessEntrypoint\": true, \"hypervisor\": \"libkrun\", \"protocolVersion\": 2, \"generatorRev\": \"abc\", \"source\": \"{source}\" }}"
            ),
        )
        .unwrap();
        (home, rootfs)
    }

    /// The tier gate W5k adds: a locally built image already sitting in the
    /// managed cache is refused under production with the selector unset —
    /// "however it was selected" is the point of reading the recorded tier.
    #[test]
    fn a_production_admission_refuses_a_locally_built_image_in_the_cache() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let (_home, rootfs) = staged_default_image(&mut env, "local-pair");
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();

        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            restrict_agent_verbs: true,
            ..pinning_params(&rootfs, &ledger)
        })
        .expect_err("a sealed boot must refuse a locally built cached image");

        assert!(
            err.to_string().contains("production admission"),
            "unexpected refusal: {err:#}"
        );
        assert_eq!(
            std::fs::read_dir(keys_dir.path()).unwrap().count(),
            0,
            "the refusal must precede signing"
        );
    }

    /// The same locally built image under a development profile is admitted:
    /// the refusal is scoped to the production tier.
    #[test]
    fn a_development_admission_accepts_a_locally_built_image_in_the_cache() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let (_home, rootfs) = staged_default_image(&mut env, "local-pair");
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();

        admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            restrict_agent_verbs: false,
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a development boot is not refused for a local-dev image");
    }

    /// A fetched (published) image recorded in the cache verifies as the
    /// release tier and is admitted under production.
    #[test]
    fn a_production_admission_accepts_a_fetched_image_in_the_cache() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let (_home, rootfs) = staged_default_image(&mut env, "fetched");
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();

        admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            restrict_agent_verbs: true,
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a sealed boot admits an image the cache records as fetched");
    }

    #[test]
    fn parallel_admissions_keep_their_captured_image_source_contexts() {
        let _home = isolated_home();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"parallel admission image");
        let configured = std::path::Path::new("/nonexistent/mvm-images");

        std::thread::scope(|scope| {
            for index in 0..64 {
                let rootfs = rootfs.as_path();
                scope.spawn(move || {
                    let selected = (index % 2 == 0).then_some(configured);
                    let result = enforce_image_source_admission(
                        mvm_build::artifact_acquisition::DistributionChannel::Release,
                        Variant::Prod,
                        selected,
                        rootfs,
                    );
                    if selected.is_some() {
                        assert!(
                            result.is_err(),
                            "a release admission with a captured local selector must refuse"
                        );
                    } else {
                        result.expect(
                            "a parallel admission with no captured selector must stay independent",
                        );
                    }
                });
            }
        });
    }

    /// A contributor build's sealed boot is not refused by the selector
    /// alone: the paired workflow is how a developer boots a workload built
    /// from their own flake against images from a sibling checkout. The
    /// production gate keys on the tiers the managed artifacts record (the
    /// rootfs here is unmanaged, so nothing records a tier); the selector
    /// itself is refused only on release-channel binaries, which refuse it at
    /// CLI entry before any verb runs.
    #[cfg(not(feature = "release-channel"))]
    #[test]
    fn a_contributor_sealed_boot_with_a_configured_checkout_and_an_unmanaged_image_is_admitted() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"own-flake-sealed-workload");
        let ledger = InMemoryNonceLedger::new();

        admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            restrict_agent_verbs: true,
            configured_images_dir: Some(std::path::Path::new("/nonexistent/mvm-images")),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a contributor sealed boot admits its own-flake workload");
    }

    /// The same configuration leaves a development boot alone: the refusal is
    /// scoped to the production tier, not to the variable.
    #[test]
    fn a_development_admission_is_not_refused_for_a_configured_local_image_checkout() {
        let _home = isolated_home();
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"local-image-source-dev");
        let ledger = InMemoryNonceLedger::new();

        admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            gpu: false,
            instructions: Default::default(),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            restrict_agent_verbs: false,
            configured_images_dir: Some(std::path::Path::new("/nonexistent/mvm-images")),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("a development boot is not refused for a configured checkout");
    }
}

#[cfg(test)]
mod entrypoint_shape_tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn every_direct_shell_basename_is_shell_shaped() {
        for name in DIRECT_SHELL_BASENAMES {
            assert!(
                entrypoint_is_shell_shaped(&argv(&[name]), None),
                "{name} must be treated as a shell"
            );
            // A full path to the same program must match on basename alone.
            assert!(
                entrypoint_is_shell_shaped(&argv(&[&format!("/usr/local/bin/{name}")]), None),
                "a full path to {name} must be treated as a shell"
            );
        }
    }

    #[test]
    fn a_bare_busybox_invocation_is_shell_shaped_even_with_a_non_shell_applet() {
        // Unlike mvm_contract::entrypoint's SDK-declaration check (which lets
        // "busybox true" through because the named applet isn't a shell), the
        // admission gate treats busybox itself as the risk: invoked bare it
        // drops into an interactive shell, so any invocation is refused on
        // basename alone.
        assert!(entrypoint_is_shell_shaped(&argv(&["busybox"]), None));
        assert!(entrypoint_is_shell_shaped(
            &argv(&["busybox", "true"]),
            None
        ));
    }

    #[test]
    fn an_env_wrapped_shell_is_shell_shaped() {
        // Reused from mvm_contract::entrypoint::detect_shell_entrypoint_argv
        // rather than reimplemented: env indirection, -S/--split-string, and
        // env-assignment skipping all apply here for free.
        assert!(entrypoint_is_shell_shaped(
            &argv(&["/usr/bin/env", "bash", "-lc", "echo no"]),
            None
        ));
    }

    #[test]
    fn a_script_whose_shebang_names_a_shell_is_shell_shaped() {
        assert!(entrypoint_is_shell_shaped(
            &argv(&["./entrypoint.sh"]),
            Some(b"#!/bin/bash\necho hi\n"),
        ));
    }

    #[test]
    fn a_script_whose_shebang_names_a_non_shell_interpreter_is_not_shell_shaped() {
        assert!(!entrypoint_is_shell_shaped(
            &argv(&["./entrypoint.py"]),
            Some(b"#!/usr/bin/env python3\n"),
        ));
    }

    #[test]
    fn an_inline_command_flag_makes_any_interpreter_shell_shaped() {
        // Deliberately not restricted to programs already named as shells:
        // an inline-command flag is the shape every "run this string"
        // invocation takes, including a renamed or wrapped interpreter.
        assert!(entrypoint_is_shell_shaped(
            &argv(&["python", "-c", "print(1)"]),
            None
        ));
    }

    #[test]
    fn an_ordinary_argv_program_is_not_shell_shaped() {
        assert!(!entrypoint_is_shell_shaped(
            &argv(&["python", "-m", "app"]),
            None
        ));
    }

    #[test]
    fn an_empty_argv_is_not_shell_shaped() {
        assert!(!entrypoint_is_shell_shaped(&[], None));
    }
}

// ── the surfaces, end to end ─────────────────────────────
//
// Everything above proves a piece. These prove the whole path: a grant
// written in a project's manifest is resolved, checked against the host's
// ceiling, signed into the plan, and — for egress — becomes the policy the
// gate enforces. Asserting on the admitted `ExecutionPlan` rather than on an
// intermediate struct is the point; every previous version of this feature
// was correct in the middle and unreachable at the ends.

#[cfg(test)]
mod grant_surface_tests {
    use super::admit_plan_tests::pinning_params;
    use super::*;
    use crate::admission::run_grants::{GrantInputs, resolve_run_grants};
    use mvm_contract::grants::CpuGrant;
    use mvm_core::network_policy::HostPort;
    use mvm_core::user_config::MvmConfig;

    // `localhost` rather than a public name on purpose: admission lowers a
    // non-deny policy into a signed bundle and pins each allowed host to its
    // resolved addresses, so a name needing a real resolver would make these
    // tests depend on the network.
    const MANIFEST: &str = r#"
image = "alpine:3.20"
cpus = 4

[grants]
cpu_millicores = 1500
wall_clock_secs = 600
allow_hosts = ["localhost:8443"]
"#;

    fn manifest_grants(text: &str) -> mvm_contract::grants::Grants {
        mvm_core::manifest::Manifest::from_toml_str(text)
            .expect("the manifest parses")
            .machine_workflow()
            .expect("an image-backed manifest yields a machine workflow")
            .grants
    }

    fn write_rootfs(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("rootfs.ext4");
        std::fs::write(&path, b"grant rootfs").expect("write rootfs");
        path
    }

    /// Admission pins a directory share's content digest, and only where one
    /// is missing and the grant really is a directory.
    ///
    /// The pin is what makes claim 19's post-admission drift refusal possible:
    /// enforcement re-hashes at attach time and compares. If admission records
    /// no digest, there is nothing to compare against and the refusal cannot
    /// fire — it reports present and never bites, which is worse than no
    /// refusal because it is believed.
    ///
    /// Two mutants survived here and this covers both. Flipping `==` to `!=`
    /// hashes disks and skips directory shares, so exactly the grants the claim
    /// is about lose their pin. Relaxing `&&` to `||` re-hashes a share that
    /// already carries a digest, overwriting a caller-supplied identity with
    /// whatever the tree happens to be at admission — which turns a pin into a
    /// snapshot and admits the drift it exists to refuse.
    ///
    /// The existing witness, `admitted_share_digest_refuses_directory_changed_after_admission`,
    /// tests the enforcement side in mvm-hostd. It cannot see this: it is
    /// handed a plan that already carries a digest.
    #[test]
    fn admission_pins_a_directory_shares_digest_and_leaves_other_grants_alone() {
        let _env = mvm_core::util::test_env::TestEnv::new();
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("payload.txt"), b"admitted bytes").unwrap();
        let canonical = std::fs::canonicalize(shared.path()).unwrap();
        let expected = mvm_fs::hash::hash_source(&canonical).expect("the tree hashes");

        let disk_dir = tempfile::tempdir().unwrap();
        let disk = disk_dir.path().join("data.img");
        std::fs::write(&disk, b"disk bytes").unwrap();

        const ALREADY_PINNED: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";

        let share = |tag: &str, host: &std::path::Path, guest: &str, kind, digest: Option<&str>| {
            mvm_core::plan::HostShareGrant {
                tag: tag.to_string(),
                host_path: host.display().to_string(),
                guest_path: guest.to_string(),
                kind,
                read_only: false,
                encrypted: false,
                content_sha256: digest.map(str::to_string),
                include: Vec::new(),
                exclude: Vec::new(),
            }
        };

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path());
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-shares",
            cpus: 1,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            shares: vec![
                share(
                    "uvol0",
                    shared.path(),
                    "/work",
                    mvm_core::plan::ShareKind::DirShare,
                    None,
                ),
                share(
                    "uvol1",
                    shared.path(),
                    "/pinned",
                    mvm_core::plan::ShareKind::DirShare,
                    Some(ALREADY_PINNED),
                ),
                share(
                    "uvol2",
                    &disk,
                    "/data",
                    mvm_core::plan::ShareKind::Disk,
                    None,
                ),
            ],
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: false,
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        let shares = &ctx.admitted.plan().shares;
        let by_tag = |tag: &str| {
            shares
                .iter()
                .find(|s| s.tag == tag)
                .unwrap_or_else(|| panic!("the signed plan carries {tag}"))
        };

        assert_eq!(
            by_tag("uvol0").content_sha256.as_deref(),
            Some(expected.as_str()),
            "an unpinned directory share must be hashed at admission, or drift              enforcement has nothing to compare against"
        );
        assert_eq!(
            by_tag("uvol1").content_sha256.as_deref(),
            Some(ALREADY_PINNED),
            "a share that already carries a digest must keep it — re-hashing              would replace a pin with a snapshot of the tree at admission"
        );
        assert_eq!(
            by_tag("uvol2").content_sha256,
            None,
            "a disk is not a directory tree and must not be hashed as one"
        );
    }

    #[test]
    fn a_manifest_grant_reaches_the_signed_plan() {
        let _env = mvm_core::util::test_env::TestEnv::new();
        let declared = manifest_grants(MANIFEST);
        let config = MvmConfig::default();
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host: &[],
            peer: &[],
            net: false,
            network_preset: None,
            grants_file: None,
            manifest: Some(&declared),
            config: &config,
            ai: None,
        })
        .expect("the manifest's grants resolve");

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path());
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-granted",
            cpus: 4,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            // A dev posture: the grant is recorded and, on a tier without a
            // CPU mechanism, warned about rather than refused. The refusal
            // half is `plan_admission`'s to test; this one is about reach.
            restrict_agent_verbs: false,
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");

        let plan_grants = ctx
            .admitted
            .plan()
            .grants
            .as_ref()
            .expect("the signed plan carries the manifest's grants");
        assert_eq!(
            plan_grants.cpu,
            Some(CpuGrant::Share { millicores: 1500 }),
            "the manifest's CPU share must survive into the signed plan"
        );
        assert_eq!(
            plan_grants
                .egress
                .as_ref()
                .map(|egress| egress.allow.as_slice()),
            Some(&[HostPort::new("localhost", 8443)][..]),
            "the manifest's allow-list must survive into the signed plan"
        );
        assert_eq!(
            ctx.admitted.plan().resources.cpus,
            4,
            "the vCPU count is its own resource and is untouched by the CPU share"
        );
    }

    #[test]
    fn a_manifest_egress_grant_is_what_the_gate_enforces() {
        // The gate reads the resolved `NetworkPolicy`; the only thing allowed
        // to derive one from a grant is the projection. So the policy handed
        // to the launch must be exactly what the projection yields for the
        // grant the plan was signed over.
        let declared = manifest_grants(MANIFEST);
        let config = MvmConfig::default();
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host: &[],
            peer: &[],
            // `--net` would select the broad dev preset; the granted allow-list
            // is what wins.
            net: true,
            network_preset: None,
            grants_file: None,
            manifest: Some(&declared),
            config: &config,
            ai: None,
        })
        .expect("resolves");

        let plan_grants = resolved
            .plan_grants
            .as_ref()
            .expect("the manifest granted egress");
        assert_eq!(
            resolved.network_policy,
            mvm_contract::grants::projection::network_policy_from_grants(plan_grants),
            "the enforced policy must be the projection of the signed grant"
        );
        assert_eq!(
            resolved
                .network_policy
                .resolve_rules()
                .expect("an allow-list resolves to rules"),
            vec![HostPort::new("localhost", 8443)]
        );
        assert!(!resolved.network_policy.is_unrestricted());
    }

    #[test]
    fn a_grant_over_the_hosts_ceiling_is_refused_before_the_plan_is_signed() {
        // Admission reads the ceiling from host config, so the test has to be
        // a bounded host. The refusal must land before signing: a signed plan
        // we would have refused is indistinguishable downstream from one we
        // admitted.
        let home = tempfile::tempdir().expect("scratch mvm home");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        mvm_core::user_config::save(
            &MvmConfig {
                max_cpu_millicores: Some(1000),
                ..MvmConfig::default()
            },
            None,
        )
        .expect("writing the host config");

        let declared = manifest_grants(MANIFEST);
        let config = mvm_core::user_config::load(None);
        // The resolver refuses first and names the surface to go edit: with
        // four places a grant can come from, the dimension alone is not
        // actionable.
        let early = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host: &[],
            peer: &[],
            net: false,
            network_preset: None,
            grants_file: None,
            manifest: Some(&declared),
            config: &config,
            ai: None,
        })
        .expect_err("the resolver refuses a grant over this host's ceiling");
        let early = format!("{early:#}");
        assert!(early.contains("ceiling"), "got: {early}");
        assert!(
            early.contains("manifest"),
            "the refusal must name the surface that asked for it: {early}"
        );

        // Admission refuses independently, against host config it reads itself.
        // That is the authoritative check — resolve with an unbounded config so
        // the grant reaches it, and it must still refuse.
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host: &[],
            peer: &[],
            net: false,
            network_preset: None,
            grants_file: None,
            manifest: Some(&declared),
            config: &MvmConfig::default(),
            ai: None,
        })
        .expect("an unbounded config resolves the same grant");

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path());
        let ledger = InMemoryNonceLedger::new();
        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-over-ceiling",
            cpus: 4,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            restrict_agent_verbs: false,
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect_err("1500 millicores on a 1000-millicore host must be refused");
        assert!(
            format!("{err:#}").contains("ceiling"),
            "the refusal must name the ceiling, got: {err:#}"
        );
    }

    #[test]
    fn a_run_that_grants_nothing_still_admits_a_grant_free_plan() {
        let _env = mvm_core::util::test_env::TestEnv::new();
        // The pre-grant baseline has to stay byte-identical: an untouched
        // permission set must not become an empty-but-present one.
        let config = MvmConfig::default();
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host: &[],
            peer: &[],
            net: false,
            network_preset: None,
            grants_file: None,
            manifest: None,
            config: &config,
            ai: None,
        })
        .expect("resolves");
        assert_eq!(resolved.plan_grants, None);

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path());
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            bundle_sizing: Default::default(),
            mailbox: None,
            vm_name: "vm-ungranted",
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            bundle_pin: None,
            bundle_posture: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission");
        assert_eq!(ctx.admitted.plan().grants, None);
        assert_eq!(
            resolved.network_policy.resolve_rules().as_deref(),
            Some(&[][..]),
            "granting nothing still means deny-all"
        );
    }
}

#[cfg(test)]
#[path = "instruction_admission_tests.rs"]
mod instruction_admission_tests;

#[cfg(test)]
#[path = "bundle_admission_tests.rs"]
mod bundle_admission_tests;
