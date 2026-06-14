//! `mvmctl run` / `mvmctl up` / `mvmctl start` — boot a microVM from a flake or template.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::ui;

use mvm_backend::backend::AnyBackend;
use mvm_backend::{image, microvm};
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::naming::{validate_flake_ref, validate_template_name, validate_vm_name};
use mvm_core::user_config::MvmConfig;
use mvm_core::util::parse_human_size;
use mvm_core::vm_backend::VmId;

use super::super::env::dev_vz::ensure_default_microvm_image;
use super::Cli;
use super::audit_chain::{AuditEmitter, default_audit_dir};
use super::forward::forward_ports;
use super::host_signer::load_or_init_at;
use super::managed_secrets::lower_workload_secrets;
use super::plan_admission::{
    AdmittedPlan, BundleAdmissionContext, InMemoryNonceLedger, SystemClock, admit_for_run,
    populate_audit_substrate, stash_plan_for_bridge,
};
use super::plan_builder::SynthesisInput;
use super::policy_resolver::{
    LOCAL_DEFAULT, ResolveError, resolve_policy_bundle, resolve_policy_bundle_with_dir,
    resolve_supervisor_components, resolve_supervisor_components_with_dir,
};
use super::shared::{
    VmStartParams, VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    env_vars_to_drive_file, materialize_disk_volume, merge_volume_specs, parse_port_specs,
    parse_volume_spec, ports_to_drive_file, read_dir_to_drive_files, request_port_forward,
    resolve_flake_ref, resolve_network_policy, start_port_proxy, vm_volume_from_spec_validated,
    wait_for_guest_agent,
};
use mvm_core::policy::PolicyBundle;

/// Inputs for [`admit_plan_for_boot`]. Grouped so the helper avoids
/// the workspace `clippy::too_many_arguments = "deny"` ceiling and so
/// future callers (policy slots) can extend the shape without
/// churning every call site.
/// In-memory `BundleResolver` scoped to a single admission. Used
/// when `mvmctl up --bundle-pin <path>` already has the archive
/// bytes — no need to walk the filesystem registry again.
struct InMemoryBundleResolver {
    bytes: Vec<u8>,
}

impl InMemoryBundleResolver {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl mvm_core::plan::BundleResolver for InMemoryBundleResolver {
    fn resolve(
        &self,
        _bundle_sha256: &str,
    ) -> std::result::Result<Vec<u8>, mvm_core::plan::BundleResolveError> {
        Ok(self.bytes.clone())
    }
}

use super::readiness::record_vm_readiness;

/// Cadence at which the foreground `mvmctl up` Ctrl+C wait loop
/// re-polls integration health to detect `Active` → `Error`
/// regressions (the "Degraded follow-up"). Set
/// at 10 s — slow enough that the registry file isn't thrashed when
/// services are stable, fast enough that an operator running
/// `mvmctl ls --json` sees the new state within one breath of a
/// service flipping unhealthy.
const DEGRADED_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Build a `PlanArtifact` pin from a verified bundle archive.
/// Pulls the 64-byte signature out of the `manifest.sig` entry,
/// hashes the archive for the bundle_sha256 field, and stamps the
/// publisher's `key_id`.
fn bundle_pin_from_archive(
    archive: &[u8],
    key_id: mvm_core::plan::KeyId,
) -> Result<mvm_core::plan::PlanArtifact> {
    let mut tar = tar::Archive::new(std::io::Cursor::new(archive));
    for entry in tar.entries().context("walking archive entries")? {
        let mut entry = entry.context("reading archive entry")?;
        let path = entry
            .path()
            .context("reading archive entry path")?
            .to_string_lossy()
            .into_owned();
        if path == "manifest.sig" {
            let mut bytes = Vec::with_capacity(64);
            std::io::Read::read_to_end(&mut entry, &mut bytes)
                .context("reading manifest.sig bytes")?;
            let sig_arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("manifest.sig is {} bytes; expected 64", bytes.len())
            })?;
            return Ok(mvm_core::plan::PlanArtifact::new(
                mvm_core::plan::bundle_sha256(archive),
                &sig_arr,
                key_id,
            ));
        }
    }
    anyhow::bail!("archive has no manifest.sig entry")
}

pub(super) struct AdmitPlanForBootParams<'a> {
    pub tenant: &'a str,
    pub vm_name: &'a str,
    pub backend_name: &'a str,
    pub rootfs_path: &'a std::path::Path,
    /// Skip re-hashing `rootfs_path` and admit with this sha256 instead.
    /// Only sound when a fail-closed integrity check re-hashes the same
    /// bytes before boot (the checkpoint fork path: `verify_content`
    /// refuses a tampered blob before any supervisor spawns) — a
    /// mismatch then aborts the launch, never boots a mis-admitted image.
    pub precomputed_image_sha256: Option<String>,
    pub cpus: u32,
    pub mem_mib: u64,
    pub seccomp_tier: mvm_core::plan::PlanSeccompTier,
    pub secret_release: mvm_core::plan::SecretReleasePolicy,
    pub secrets: Vec<mvm_core::plan::SecretBinding>,
    pub no_supervisor: bool,
    pub ledger: &'a InMemoryNonceLedger,
    /// Override for the host-signer keys directory. Production callers
    /// pass `None`, which resolves to `~/.mvm/keys/`; tests pass a
    /// tempdir so they don't write into the real user's home.
    pub keys_dir: Option<&'a std::path::Path>,
    /// Override for the audit-chain directory (`~/.mvm/audit/`).
    /// Tests inject a tempdir; production passes `None`.
    pub audit_dir: Option<&'a std::path::Path>,
    /// Override for the policy-bundle root (`~/.mvm/policies/`). The
    /// resolver reads `<dir>/<tenant>/<workload>.toml` when a
    /// plan's policy refs name a tenant-scoped bundle; tests inject a
    /// tempdir so a bogus bundle can be staged without touching the
    /// real user's home.
    pub policy_dir: Option<&'a std::path::Path>,
    /// Optional path to a `.mvmpkg` bundle archive. When set, the
    /// archive is read + verified at admit time, the resulting
    /// `PlanArtifact` is embedded into the plan, and the supervisor's
    /// admit path re-verifies on every launch. Production callers
    /// thread `args.bundle_pin`; tests pass `None`.
    pub bundle_pin: Option<&'a std::path::Path>,
    /// Optional deps-volume binding produced by `mvmctl up`'s
    /// install pipeline. When `Some`, the
    /// synthesised `ExecutionPlan` carries `deps_volume = Some(...)`,
    /// and the supervisor's admission gate re-verifies
    /// the on-disk sealed volume before launch — claim 9.
    /// `None` preserves the claim-8 baseline (no deps gate).
    pub deps_volume: Option<mvm_core::plan::DepsVolumeBinding>,
    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`) baked
    /// into the signed plan + emitted to the chain-signed audit log
    /// (claim 1 / claim 8). Empty for the common no-volume case.
    pub shares: Vec<mvm_core::plan::HostShareGrant>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// Default (all-off) preserves the curated-only baseline.
    pub redaction: mvm_core::policy::RedactionPolicy,
}

/// Build the signed-plan host-fs grant list from the resolved volume
/// config. The `uvol{idx}` tag matches the id the backend assigns when
/// it attaches each volume (same `VmStartConfig.volumes` order), so the
/// admitted grants line up 1:1 with what actually gets attached.
fn shares_from_volume_cfg(vols: &[image::RuntimeVolume]) -> Vec<mvm_core::plan::HostShareGrant> {
    vols.iter()
        .enumerate()
        .map(|(idx, v)| mvm_core::plan::HostShareGrant {
            tag: format!("uvol{idx}"),
            host_path: v.host.clone(),
            guest_path: v.guest.clone(),
            kind: match v.kind {
                mvm_core::vm_backend::VmVolumeKind::Disk => mvm_core::plan::ShareKind::Disk,
                mvm_core::vm_backend::VmVolumeKind::DirShare => mvm_core::plan::ShareKind::DirShare,
            },
            read_only: v.read_only,
            encrypted: v.encrypted,
        })
        .collect()
}

fn plan_seccomp_tier(
    tier: mvm_core::crypto::seccomp::SeccompTier,
) -> Result<mvm_core::plan::PlanSeccompTier> {
    tier.to_string()
        .parse()
        .context("converting runtime seccomp tier into plan seccomp tier")
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
pub(super) struct AdmissionContext {
    pub(super) admitted: AdmittedPlan,
    pub(super) emitter: AuditEmitter,
    /// The resolved tenant `PolicyBundle` (Slice 3 (b)) the bridge enforces
    /// per-tenant L4 egress against; `None` for a local-default plan.
    pub(super) policy_bundle: Option<PolicyBundle>,
}

// allow(secret-debug): hand-written Debug elides the AuditEmitter's
// underlying FileAuditSigner (Ed25519 secret key); prints plan_id +
// signer_id only.
impl std::fmt::Debug for AdmissionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionContext")
            .field("plan_id", &self.admitted.plan_id)
            .field("signer_id", &self.admitted.signer_id)
            .field("emitter", &"<redacted: FileAuditSigner>")
            .finish()
    }
}

/// Run admission (`synthesize → sign → verify → check_window →
/// nonce`) right before a backend `start()`. Called from every
/// `mvmctl up` call site that boots a VM: the main path, the
/// `MVM_DIRECT_BOOT` launchd branch, and the `--watch` rebuild loop.
///
/// `no_supervisor = true` short-circuits to `Ok(None)` so the legacy
/// path keeps working while the deprecation grace window is open.
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
pub(super) fn admit_plan_for_boot(
    p: AdmitPlanForBootParams<'_>,
) -> Result<Option<AdmissionContext>> {
    if p.no_supervisor {
        return Ok(None);
    }
    let sha = match p.precomputed_image_sha256 {
        Some(sha) => sha,
        None => mvm_core::crypto::image_verify::sha256_file(p.rootfs_path).with_context(|| {
            format!(
                "hashing rootfs at {} for plan admission",
                p.rootfs_path.display()
            )
        })?,
    };

    // Claim 9 — bundle pin (when supplied).
    //
    // Read the archive bytes, verify them against the local trust
    // store, then construct the `PlanArtifact` triple
    // (bundle_sha256 + manifest_sig + key_id). The supervisor's
    // admit path re-runs the same verifier against the on-disk
    // archive — defence in depth between CLI synth and backend
    // dispatch. Errors surface before admit so the user sees them
    // without a confusing post-sign rejection.
    let (bundle_pin, bundle_resolver, bundle_trust) = match p.bundle_pin {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading bundle archive at {}", path.display()))?;
            let trust = mvm_core::plan::FsTrustStore::default_path()
                .context("resolving default trust-store path (~/.mvm/trusted-publishers/)")?;
            let verified = mvm_core::plan::read_and_verify_bundle(&bytes, &trust)
                .with_context(|| format!("verifying bundle at {}", path.display()))?;
            let pin =
                bundle_pin_from_archive(&bytes, verified.key_id.clone()).with_context(|| {
                    format!("extracting signature from bundle at {}", path.display())
                })?;
            // Use an in-memory resolver scoped to this admission —
            // the caller supplied the path, so we already have the
            // bytes; no need to walk the FS registry again.
            let resolver = InMemoryBundleResolver::new(bytes);
            (Some(pin), Some(resolver), Some(trust))
        }
        None => (None, None, None),
    };

    let input = SynthesisInput {
        vm_name: p.vm_name,
        tenant: Some(p.tenant),
        backend_name: p.backend_name,
        image_name: p.vm_name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: p.seccomp_tier,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: p.secret_release,
        secrets: p.secrets.clone(),
        audit_event_prefix: None,
        cpus: p.cpus,
        mem_mib: p.mem_mib,
        disk_mib: 0,
        boot_timeout_secs: 60,
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: bundle_pin.clone(),
        deps_volume: p.deps_volume.clone(),
        shares: p.shares.clone(),
        redaction: p.redaction.clone(),
        audit_labels: Default::default(),
    };
    let admission_ctx = match (&bundle_resolver, &bundle_trust) {
        (Some(r), Some(t)) => Some(BundleAdmissionContext {
            resolver: r,
            trust: t,
        }),
        _ => None,
    };
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        p.ledger,
        p.keys_dir,
        admission_ctx.as_ref(),
    )?;
    tracing::info!(
        plan_id = %admitted.plan_id.0,
        signer_id = %admitted.signer_id,
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
    // here surface as `Err` so the caller sees them; in production
    // mvmctl up degrades gracefully (logs a warning, continues).
    let signer = match p.keys_dir {
        Some(dir) => load_or_init_at(dir),
        None => super::host_signer::load_or_init(),
    }
    .context("loading host signer for audit emitter")?;

    // Resolve policy before constructing the final emitter so
    // `[audit]` can control chain-signing and stream replication for
    // every success-path audit record. If policy resolution itself
    // fails, fall back to the default local chain for the failure
    // record so the rejection is still visible.
    let resolved = match resolve_policy_for_admission(&admitted.plan, p.policy_dir) {
        Ok(resolved) => resolved,
        Err(err) => {
            let fallback = build_default_audit_emitter(signer.signing, p.audit_dir)
                .context("opening fallback audit chain emitter")?;
            emit_policy_resolve_failure(&admitted.plan, &fallback, &err);
            return Err(err);
        }
    };

    let emitter = match build_policy_audit_emitter(
        signer.signing.clone(),
        p.audit_dir,
        resolved.audit.as_ref(),
    ) {
        Ok(emitter) => emitter,
        Err(err) => {
            let err = err.context("opening audit chain emitter");
            match build_default_audit_emitter(signer.signing, p.audit_dir) {
                Ok(fallback) => emit_policy_audit_invalid(&admitted.plan, &fallback, &err),
                Err(fallback_err) => tracing::warn!(
                    error = %fallback_err,
                    "audit emit_failed for policy-audit-invalid skipped; fallback emitter failed"
                ),
            }
            return Err(err);
        }
    };

    if let Err(e) = emitter.emit_admitted(&admitted.plan, &admitted.signer_id) {
        tracing::warn!(error = %e, "audit emit_admitted failed (non-fatal)");
    }
    // Claim 1 / claim 8 — record the admitted host-fs grants in the
    // chain-signed log (no-op when there are none).
    if let Err(e) = emitter.emit_shares_admitted(&admitted.plan) {
        tracing::warn!(error = %e, "audit emit_shares_admitted failed (non-fatal)");
    }

    // Resolve the plan's four policy refs into concrete supervisor
    // component slots. Today the slots are constructed-and-dropped —
    // no `Supervisor::launch` integration exists in mvmctl yet (that
    // ships with the mvm-hostd lift). The call here is operator-
    // facing: it validates the policy refs against the on-disk
    // bundle so a missing file / typo / bad L4 CIDR fails the boot
    // loudly *now* instead of silently passing through with Noops.
    emit_policy_resolved(&admitted.plan, &emitter, resolved.slots_mode);

    // Slice 3 (b) — load the resolved tenant PolicyBundle (None for a
    // local-default plan) so populate_audit_substrate can deliver it to the
    // bridge for per-tenant L4 egress enforcement. resolve_policy_for_admission
    // above already validated the refs, so a well-formed bundle won't surface a
    // new error class here.
    let policy_bundle = match p.policy_dir {
        Some(dir) => resolve_policy_bundle_with_dir(&admitted.plan, dir),
        None => resolve_policy_bundle(&admitted.plan),
    }
    .context("loading the tenant policy bundle for the bridge")?;

    Ok(Some(AdmissionContext {
        admitted,
        emitter,
        policy_bundle,
    }))
}

#[derive(Debug)]
struct PolicyAdmissionResolution {
    slots_mode: &'static str,
    audit: Option<mvm_core::policy::AuditPolicy>,
}

fn build_default_audit_emitter(
    signing_key: ed25519_dalek::SigningKey,
    audit_dir: Option<&std::path::Path>,
) -> Result<AuditEmitter> {
    match audit_dir {
        Some(dir) => AuditEmitter::with_dir(signing_key, dir),
        None => AuditEmitter::new(signing_key),
    }
}

fn build_policy_audit_emitter(
    signing_key: ed25519_dalek::SigningKey,
    audit_dir: Option<&std::path::Path>,
    policy: Option<&mvm_core::policy::AuditPolicy>,
) -> Result<AuditEmitter> {
    match policy {
        Some(policy) => {
            let dir = match audit_dir {
                Some(dir) => dir.to_path_buf(),
                None => default_audit_dir()?,
            };
            AuditEmitter::with_policy(signing_key, &dir, policy)
        }
        None => build_default_audit_emitter(signing_key, audit_dir),
    }
}

/// Run the policy resolver against the admitted plan and return the
/// policy-derived audit configuration for emitter construction.
///
/// `policy_dir` is the override for `~/.mvm/policies/`; production
/// callers pass `None` and the resolver resolves it from `$HOME`.
/// Tests inject a tempdir to stage / omit bundles deterministically.
///
fn resolve_policy_for_admission(
    plan: &mvm_core::plan::ExecutionPlan,
    policy_dir: Option<&std::path::Path>,
) -> Result<PolicyAdmissionResolution> {
    let resolved = match policy_dir {
        Some(dir) => resolve_supervisor_components_with_dir(plan, dir),
        None => resolve_supervisor_components(plan),
    };
    match resolved {
        Ok(slots) => {
            // Drop the slots — no live consumer in mvmctl today. The
            // construction itself is the validation. Return the
            // resolved-mode so the caller can audit it after the
            // policy-derived emitter is constructed.
            let mode = if plan.network_policy.0 == LOCAL_DEFAULT {
                "noop"
            } else {
                "live"
            };
            tracing::info!(
                plan_id = %plan.plan_id.0,
                slots_mode = mode,
                "policy refs resolved",
            );
            Ok(PolicyAdmissionResolution {
                slots_mode: mode,
                audit: slots.audit,
            })
        }
        Err(rerr) => Err(anyhow::Error::new(rerr).context("resolving plan policy refs")),
    }
}

fn emit_policy_resolved(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    slots_mode: &'static str,
) {
    if let Err(e) = emitter.emit_policy_resolved(plan, slots_mode) {
        tracing::warn!(error = %e, "audit emit_policy_resolved failed (non-fatal)");
    }
}

fn emit_policy_resolve_failure(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    let class = match err.downcast_ref::<ResolveError>() {
        Some(ResolveError::BundleNotFound { .. }) => "policy-bundle-not-found",
        Some(ResolveError::BundleParseFailed { .. }) => "policy-bundle-parse-failed",
        Some(ResolveError::MixedRefs { .. }) => "policy-refs-mixed",
        Some(ResolveError::Unrecognized { .. }) => "policy-ref-unrecognized",
        Some(ResolveError::L4SpecInvalid { .. }) => "policy-l4-spec-invalid",
        Some(ResolveError::EgressPolicyInvalid { .. }) => "policy-egress-invalid",
        Some(ResolveError::PiiPolicyInvalid { .. }) => "policy-pii-invalid",
        Some(ResolveError::AuditPolicyInvalid { .. }) => "policy-audit-invalid",
        None => "policy-resolve",
    };
    if let Err(audit_err) = emitter.emit_failed(plan, class, &format!("{err:#}")) {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for policy-resolve failed (non-fatal)"
        );
    }
}

fn emit_policy_audit_invalid(
    plan: &mvm_core::plan::ExecutionPlan,
    emitter: &AuditEmitter,
    err: &anyhow::Error,
) {
    if let Err(audit_err) = emitter.emit_failed(plan, "policy-audit-invalid", &format!("{err:#}")) {
        tracing::warn!(
            error = %audit_err,
            "audit emit_failed for policy-audit-invalid failed (non-fatal)"
        );
    }
}

/// Emit `plan.launched` against the supplied admission context. No-op
/// when admission was skipped (`--no-supervisor`). Tolerates emission
/// failure with a `tracing::warn` so a flaky audit fs can't block a
/// VM that already booted.
///
/// Also persists the admitted plan into the VM state dir so
/// out-of-process lifecycle verbs (e.g. `mvmctl checkpoint create`) can
/// rehydrate it and bind their audit events to the same plan_id.
/// Plan persistence failure is non-fatal — the launch already
/// succeeded; the cost is that lifecycle audit will be unbound on
/// this VM until the next launch.
pub(super) fn emit_launched_if(ctx: &Option<AdmissionContext>, backend: &str) {
    let Some(ctx) = ctx else { return };
    if let Err(e) = ctx.emitter.emit_launched(&ctx.admitted.plan, backend) {
        tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
    }
    if let Err(e) =
        super::plan_persist::write_plan(&ctx.admitted.plan.workload.0, &ctx.admitted.plan)
    {
        tracing::warn!(
            error = %e,
            "persisting admitted plan to ~/.mvm/vms/<vm>/plan.json failed (non-fatal)"
        );
    }
}

/// Tier A.1 admission enforcement: refuse to boot if any volume about to
/// be attached isn't named in the verified `ExecutionPlan.shares`. No-op
/// when admission was skipped (no plan to enforce against). Called right
/// before every `backend.start()` so no host-fs grant reaches a guest
/// unless the signed plan admitted it (claim 1 / claim 8).
fn enforce_shares_if(
    ctx: &Option<AdmissionContext>,
    volumes: &[mvm_core::vm_backend::VmVolume],
) -> Result<()> {
    if let Some(ctx) = ctx {
        super::plan_admission::enforce_admitted_shares(volumes, &ctx.admitted.plan)
            .context("admission share check")?;
    }
    Ok(())
}

/// Emit `plan.failed` against the supplied admission context. No-op
/// when admission was skipped. `class` is a short grep-friendly tag
/// (e.g. `backend-start`, `snapshot-restore`); `err` becomes the
/// rendered error chain.
pub(super) fn emit_failed_if(ctx: &Option<AdmissionContext>, class: &str, err: &anyhow::Error) {
    let Some(ctx) = ctx else { return };
    let msg = format!("{err:#}");
    if let Err(e) = ctx.emitter.emit_failed(&ctx.admitted.plan, class, &msg) {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
}

/// Resolve a deps-volume binding for the
/// supplied Workload IR.
///
/// When `workload_ir_path = None` the function returns `Ok(None)` and
/// the synthesized plan carries `deps_volume = None` (claim-8 preserved).
///
/// When the IR loads cleanly + has a `Dependencies::Python` /
/// `Dependencies::Node` declaration, runs `install_app_deps` against
/// the host cache (driver = `None`: cache-hit-only — `mvmctl up`
/// does not spawn the builder VM today; `mvmctl deps build`
/// is the verb that drives the cache-miss path) and
/// then runs `apply_install_gate` on the resolved volume. On `--prod`
/// any gate-error bubbles as `anyhow::Error`; on `--dev` warnings
/// are logged and the function still returns the binding.
///
/// IR-load errors propagate verbatim so the user sees them (a typo in
/// `--from-workload-ir <path>` should fail before VM boot, not silently
/// degrade to "no deps").
fn resolve_deps_volume_binding(
    workload_ir_path: Option<&std::path::Path>,
    build_mode: mvm_build::pipeline::BuildMode,
) -> Result<Option<mvm_core::plan::DepsVolumeBinding>> {
    resolve_deps_volume_binding_with_cache(workload_ir_path, build_mode, None)
}

/// Resolve the Workload IR path the admission flow lowers into `plan.secrets`.
///
/// An explicit `--from-workload-ir` always wins. Otherwise, when `--flake`
/// points at a local directory a `mvmctl compile` run wrote `workload.json`
/// into, default to it. This makes a secret-declaring compiled artifact
/// (`mvmctl up --flake <out>`) lower its managed `SecretRef`s — and so spawn
/// the per-VM substitution endpoint at boot — without the user re-naming the
/// IR by hand. It also closes a footgun: the secrets are lowered whenever the
/// artifact declares them, so a forgotten flag can't silently boot a workload
/// without the binding it needs. A remote/attr flake ref or a missing file
/// yields `None` (a plain flake, no managed secrets).
fn resolve_workload_ir_path(
    from_workload_ir: Option<&std::path::Path>,
    flake_ref: Option<&str>,
) -> Option<std::path::PathBuf> {
    if let Some(p) = from_workload_ir {
        return Some(p.to_path_buf());
    }
    let candidate = std::path::Path::new(flake_ref?).join("workload.json");
    candidate.is_file().then_some(candidate)
}

/// Whether `up` threads the signed plan + tenant (`populate_audit_substrate`)
/// onto the backend `VmStartConfig`. Two independent consumers want it:
///
/// - **QEMU substitution endpoint**: spawned when the
///   admitted plan carries secrets — `QemuBackend::start` reads
///   `config.plan_json` + `tenant_id` to launch the per-VM moat. QEMU has **no**
///   gateway-bridge path, so threading the plan only enables the endpoint;
///   always do it for QEMU.
/// - **libkrun/Vz gateway-bridge** factory: those backends branch into the
///   bridge supervisor on `plan_json` presence, and that gvproxy wiring isn't
///   working end-to-end yet, so it stays opt-in behind `MVM_GATEWAY_BRIDGE=1`
///   (`gateway_bridge_enabled`); the default keeps them on the legacy path.
fn should_thread_signed_plan(gateway_bridge_enabled: bool, hypervisor: &str) -> bool {
    gateway_bridge_enabled || hypervisor == "qemu"
}

fn should_wait_for_direct_boot_agent(detach: bool, ports_env: Option<&str>) -> bool {
    !detach || ports_env.is_some_and(|ports| !ports.is_empty())
}

pub(super) fn load_workload_ir(
    workload_ir_path: Option<&std::path::Path>,
) -> Result<Option<mvm_sdk::ir::Workload>> {
    let Some(ir_path) = workload_ir_path else {
        return Ok(None);
    };
    let bytes = std::fs::read(ir_path)
        .with_context(|| format!("reading workload IR at {}", ir_path.display()))?;
    let workload: mvm_sdk::ir::Workload = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing workload IR at {}", ir_path.display()))?;
    Ok(Some(workload))
}

/// Cache-root-overridable form of [`resolve_deps_volume_binding`].
/// Tests inject a per-tempdir override so they don't touch the user's
/// `~/.mvm/volumes/deps/` and don't race each other through the
/// shared `MVM_DEPS_VOLUMES_DIR` env var. Production callers route
/// through the no-override helper which resolves the canonical path.
fn resolve_deps_volume_binding_with_cache(
    workload_ir_path: Option<&std::path::Path>,
    build_mode: mvm_build::pipeline::BuildMode,
    cache_root_override: Option<&std::path::Path>,
) -> Result<Option<mvm_core::plan::DepsVolumeBinding>> {
    let Some(ir_path) = workload_ir_path else {
        return Ok(None);
    };
    let bytes = std::fs::read(ir_path)
        .with_context(|| format!("reading workload IR at {}", ir_path.display()))?;
    let workload: mvm_sdk::ir::Workload = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing workload IR at {}", ir_path.display()))?;

    // v1 surface: one app per workload. The IR validator
    // (`mvm validate`) rejects empty `apps`, so `[0]` is safe on a
    // validated IR. Multi-app workloads with mixed dep declarations
    // are a future concern — punt now.
    let Some(app) = workload.apps.first() else {
        anyhow::bail!(
            "workload IR at {} has no apps; --from-workload-ir requires at least one app",
            ir_path.display()
        );
    };

    // `Dependencies::None` and absent-field both mean "no lockfile".
    let dep = match &app.dependencies {
        None | Some(mvm_sdk::ir::Dependencies::None) => return Ok(None),
        Some(d) => d,
    };

    // Resolve lockfile path + language from the IR.
    let (language, lockfile_rel) = match dep {
        mvm_sdk::ir::Dependencies::Python { lockfile, .. } => {
            (mvm_build::app_deps::Language::Python, lockfile)
        }
        mvm_sdk::ir::Dependencies::Node { lockfile, .. } => {
            (mvm_build::app_deps::Language::Node, lockfile)
        }
        // unreachable: handled above.
        mvm_sdk::ir::Dependencies::None => return Ok(None),
    };
    let source_root = source_root_for_app(app, ir_path)?;
    let lockfile_path = source_root.join(lockfile_rel);
    let gate = match build_mode {
        mvm_build::pipeline::BuildMode::Prod => mvm_build::app_deps::GateLevel::Prod,
        mvm_build::pipeline::BuildMode::Dev => mvm_build::app_deps::GateLevel::Dev,
    };

    let spec = mvm_build::app_deps::InstallSpec {
        lockfile: lockfile_path,
        source_root,
        language,
        gate,
        cache_root_override: cache_root_override.map(std::path::Path::to_path_buf),
    };

    // Driver = None: `mvmctl up` is the consumer of an already-built
    // deps volume. The cache-miss → builder-VM dispatch is the job of
    // `mvmctl deps build`. On a miss we surface the
    // typed `DriverNotProvided` to the user with a pointer to that
    // verb.
    let install = mvm_build::app_deps::install_app_deps(&spec, None).map_err(|e| match e {
        mvm_build::app_deps::InstallError::DriverNotProvided { .. } => anyhow::anyhow!(
            "no cached deps volume for this lockfile; run `mvmctl deps build \
                 --from-workload-ir {}` first",
            ir_path.display()
        ),
        other => anyhow::Error::new(other),
    })?;

    // Gate. On --prod a typed `GateError` aborts the boot; on --dev
    // every issue is logged + we proceed with the binding.
    mvm_build::app_deps_gate::apply_install_gate(&install, gate)
        .with_context(|| format!("app-deps gate ({gate:?}) refused the install"))?;

    let binding =
        mvm_core::plan::DepsVolumeBinding::new(&install.volume_hash, &install.manifest_sha256)
            .map_err(|e| {
                anyhow::anyhow!(
                    "install pipeline returned a malformed hash pair: {e} \
                     (volume_hash={}, manifest_sha256={})",
                    install.volume_hash,
                    install.manifest_sha256
                )
            })?;
    Ok(Some(binding))
}

/// Stage the per-VM egress-TLS material for a
/// secret-bearing plan. Mints the name-constrained intermediate, pushes its
/// **cert** onto the guest secrets drive (`secret_files`, so the guest can trust
/// host-terminated bound-host TLS once the boot step installs it), and
/// persists the cert+**key** to a host-only `egress-intermediate.json`
/// (mode 0600) in the VM state dir for `spawn_egress_endpoint` to hand the
/// terminator endpoint. The key never enters `secret_files` / the guest.
///
/// Bound hosts = the union of every plan secret's `allowed_hosts` from the host
/// binding store — the SAME claim-12 egress allow-list, so the intermediate's
/// `nameConstraints` can never exceed it. A plan with no secrets, or whose
/// secrets carry no recorded binding, stages nothing (no https leg).
fn stage_egress_tls_delivery(
    plan_secrets: &[mvm_core::plan::SecretBinding],
    tenant: &str,
    vm_name: &str,
    secret_files: &mut Vec<microvm::DriveFile>,
) -> anyhow::Result<()> {
    use mvm_hostd::keyholder::{BindingStore, FileBindingStore};

    if plan_secrets.is_empty() {
        return Ok(());
    }
    let store = FileBindingStore::default_location()?;
    let mut bound: Vec<String> = Vec::new();
    for s in plan_secrets {
        if let Some(meta) = store.get(tenant, &s.name)? {
            for h in meta.allowed_hosts {
                if !bound.contains(&h) {
                    bound.push(h);
                }
            }
        }
    }
    if bound.is_empty() {
        return Ok(());
    }

    let ca_dir = mvm_core::config::egress_ca_dir();
    std::fs::create_dir_all(&ca_dir)
        .with_context(|| format!("create egress CA dir {}", ca_dir.display()))?;
    let refs: Vec<&str> = bound.iter().map(String::as_str).collect();
    let delivery = mvm_backend::build_egress_tls_delivery(&refs, &ca_dir)?;

    // Guest trusts the cert (delivered via the secrets drive; the boot step installs it).
    secret_files.push(delivery.guest_cert.clone());

    // Host-only intermediate (cert+key) for the terminator endpoint — mode 0600
    // private key material that must never reach the guest.
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("create VM state dir {}", state_dir.display()))?;
    let path = state_dir.join("egress-intermediate.json");
    let json = serde_json::to_vec(&serde_json::json!({
        "cert_pem": delivery.endpoint_cert_pem,
        "key_pem": delivery.endpoint_key_pem,
    }))?;
    write_host_only_file(&path, &json)
        .with_context(|| format!("persist egress intermediate at {}", path.display()))?;
    Ok(())
}

/// Atomically write `bytes` to `path` at mode 0600 (tmp + rename, so a reader
/// never sees a half-written file). Used for host-only private key material.
fn write_host_only_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all().ok();
    std::fs::rename(&tmp, path)
}

/// Resolve the `source_root` for an app's lockfile path. For
/// `Source::LocalPath { path, .. }` the source root is the directory
/// the path resolves against — relative paths root at the IR file's
/// parent; absolute paths are used verbatim. Other source kinds (`Nix
/// derivation`, `OCI image`) carry no host-resolvable source root, so
/// they're refused here with a hint.
fn source_root_for_app(
    app: &mvm_sdk::ir::App,
    ir_path: &std::path::Path,
) -> Result<std::path::PathBuf> {
    match &app.source {
        mvm_sdk::ir::Source::LocalPath { path, .. } => {
            let p = std::path::Path::new(path);
            if p.is_absolute() {
                Ok(p.to_path_buf())
            } else {
                let base = ir_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                Ok(base.join(p))
            }
        }
        mvm_sdk::ir::Source::NixDerivation { .. } | mvm_sdk::ir::Source::OciImage { .. } => {
            anyhow::bail!(
                "Workload IR app source is {:?}; --from-workload-ir + dependency \
             installation only supports `Source::LocalPath` today",
                app.source
            )
        }
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Nix flake reference (local path or remote URI)
    #[arg(long, value_parser = clap_flake_ref, conflicts_with = "manifest")]
    pub flake: Option<String>,
    /// Boot a pre-built manifest (path to `mvm.toml`, its directory, or a
    /// legacy slot name). Mutually exclusive with `--flake`.
    #[arg(short = 'm', long)]
    pub manifest: Option<String>,
    /// VM name (auto-generated if omitted)
    #[arg(long, value_parser = clap_vm_name)]
    pub name: Option<String>,
    /// Flake package variant (e.g. worker, gateway). Omit to use flake default
    #[arg(long)]
    pub profile: Option<String>,
    /// vCPU cores
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Memory (supports human-readable sizes: 512M, 4G, 1024K, or plain MB)
    #[arg(long)]
    pub memory: Option<String>,
    /// Runtime config (TOML) for persistent resources/volumes
    #[arg(long)]
    pub config: Option<String>,
    /// Attach a volume (repeatable). `host:/guest` shares a host dir
    /// (virtio-fs); `host:/guest:SIZE` is an ext4 disk image. Read-only
    /// by default — append `:rw` to grant writes. Guest path must be
    /// under /data, /work, or /mnt (system mounts are read-only).
    #[arg(short, long, value_parser = clap_volume_spec)]
    pub volume: Vec<String>,
    /// Hypervisor backend (firecracker, libkrun, qemu, vz). Default: auto-detect per host
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Port mapping (format: HOST:GUEST or PORT). Repeatable
    #[arg(short, long, value_parser = clap_port_spec)]
    pub port: Vec<String>,
    /// Environment variable to inject (format: KEY=VALUE). Repeatable
    #[arg(short, long)]
    pub env: Vec<String>,
    /// Auto-forward declared ports after boot (blocks until Ctrl-C)
    #[arg(long)]
    pub forward: bool,
    /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
    #[arg(long, default_value = "0")]
    pub metrics_port: u16,
    /// Keep this many prelaunched supervisor standbys warm so the next
    /// auto-named `up` claims one instead of cold-booting. 0 (default) = feature off. Only
    /// the libkrun backend has a standby pool today; a claim uses the gateway-bridge path.
    #[arg(long, default_value = "0")]
    pub warm_pool_size: u32,
    /// Reload ~/.mvm/config.toml automatically when it changes
    #[arg(long)]
    pub watch_config: bool,
    /// Watch the flake for changes and auto-rebuild + reboot (requires local --flake)
    #[arg(long)]
    pub watch: bool,
    /// Run in background (detached mode, like docker run -d)
    #[arg(short, long)]
    pub detach: bool,
    /// Block until the workload powers off, then exit with its code
    /// (one-shot workloads).
    #[arg(long, conflicts_with_all = ["detach", "up_json"])]
    pub wait: bool,
    /// After boot, drop into an interactive PTY console in the guest
    /// (like `docker run -it`). Implies the dev image for the bundled
    /// default microVM — a sealed prod image ships no console agent.
    /// The VM keeps running after the shell exits; `down` stops it.
    #[arg(long, conflicts_with_all = ["detach", "up_json", "wait", "forward"])]
    pub console: bool,
    /// Network preset (unrestricted, none, registries, dev)
    #[arg(long)]
    pub network_preset: Option<String>,
    /// Network allowlist entry (format: HOST:PORT). Repeatable
    #[arg(long)]
    pub network_allow: Vec<String>,
    /// Seccomp profile tier (essential, minimal, standard, network, unrestricted).
    ///
    /// Default: `standard`. `unrestricted` is opt-in only; the project's
    /// posture is "defaults must be safe."
    #[arg(long, default_value = "standard")]
    pub seccomp: String,
    /// Named dev network to attach VM to (default: "default")
    #[arg(long, default_value = "default")]
    pub network: String,
    /// Sandbox tag in `KEY=VALUE` form. Repeatable. Validated against
    /// `mvm_core::crypto::policy::InputValidator` charset/length rules.
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Sandbox time-to-live (e.g. `30s`, `5m`, `2h`, `7d`). After
    /// expiry the supervisor reaper tears the VM down. Omit for no
    /// TTL.
    #[arg(long)]
    pub ttl: Option<String>,
    /// Disable auto-resume when a caller connects to a sleeping VM.
    /// Default behaviour resumes on connect.
    #[arg(long)]
    pub no_auto_resume: bool,
    /// Tenant for the synthesized `ExecutionPlan`. When
    /// unset the value is resolved via the 4-level precedence chain
    /// (built-in `"local"` →
    /// `~/.mvm/config.toml` `[tenant] name` → `MVM_TENANT` env →
    /// `--tenant` flag). Identity / `mvmctl auth` is the subject of
    /// a separate effort; this flag is just the audit
    /// chain string label.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Skip admission (`synthesize → sign → verify → check_window
    /// → nonce`). One-release escape hatch; prints a deprecation warning
    /// when set. Will be removed once admission is the only path.
    #[arg(long)]
    pub no_supervisor: bool,
    /// Pin the launch to a specific `.mvmpkg` bundle. The path is
    /// read at admit time, verified against the local trust store
    /// (`~/.mvm/trusted-publishers/`), and embedded into the
    /// `ExecutionPlan` as a `PlanArtifact`. The supervisor's admit
    /// path then re-verifies the bundle against the pin before
    /// backend dispatch — claim 9 load-bearing at launch. Use the
    /// same path you handed to `mvmctl bundle fetch` /
    /// `mvmctl bundle install`.
    #[arg(long, value_name = "PATH")]
    pub bundle_pin: Option<std::path::PathBuf>,
    /// Build-mode override flags (`--dev` / `--prod`). Default: `--prod`.
    /// These also drive the app-deps gate when
    /// `--from-workload-ir` is set: `--prod` fails closed on missing
    /// SBOM / missing CVE scan / high or critical CVE findings;
    /// `--dev` warns and continues.
    #[command(flatten)]
    pub build_mode: super::super::shared::BuildModeFlags,
    /// Path to a Workload IR JSON describing the app being booted.
    /// When the IR carries `App.dependencies = Dependencies::Python
    /// | Dependencies::Node`, `mvmctl up` resolves the lockfile
    /// through `mvm_build::app_deps::install_app_deps` (cache-hit
    /// only — `mvmctl up` does not spawn the builder VM
    /// from this path; the volume must already exist) and pins
    /// the resulting `DepsVolumeBinding` into the synthesized
    /// `ExecutionPlan`. When omitted or when the IR carries
    /// `Dependencies::None`, the plan's `deps_volume` is `None`
    /// (claim-8 preserved; claim 9).
    #[arg(long = "from-workload-ir", value_name = "PATH")]
    pub from_workload_ir: Option<std::path::PathBuf>,
    /// Explicit operator acknowledgement that the
    /// selected backend's isolation tier is acceptable for this launch.
    /// A non-Tier-1 backend (libkrun, qemu, Apple Container, vz) requires
    /// this flag. A future `--prod` mode will *block* rather than warn;
    /// today we surface the signal without changing default behaviour.
    /// libkrun isolation is not Firecracker isolation.
    #[arg(long)]
    pub accept_tier2_isolation: bool,

    /// Emit a one-line JSON envelope on stdout when the VM is up.
    /// Routes the friendly `[mvm]` chrome to stderr so the SDK
    /// live-mode transport can parse a
    /// single JSON document instead of teaching the SDK to scrape
    /// the human-formatted log.
    ///
    /// Envelope shape (schema_version=1):
    ///
    /// ```json
    /// {"schema_version": 1, "vm_id": "myvm",
    ///  "build_mode": "dev"|"prod"}
    /// ```
    ///
    /// `build_mode` is read from the resolved template's
    /// `TemplateRevision.build_mode` (defaulting to `prod`) and
    /// is the load-bearing signal the SDK uses to enforce the
    /// claim-4 dev-only `do_exec` rule client-side.
    #[arg(long = "up-json")]
    pub up_json: bool,
    /// Scrub undeclared secrets/PII on egress to HOST (masks); `HOST=audit` only
    /// reports. Repeatable. Per-destination egress redaction.
    #[arg(long = "redact", value_name = "HOST[=audit]")]
    pub redact: Vec<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    // Reap helpers (gvproxy/supervisor) leaked by a prior killed run
    // before booting this workload's microVM. Kill-only, quiet,
    // non-fatal — see `sweep_orphaned_vm_helpers_on_startup`.
    super::super::env::dev_vz::sweep_orphaned_vm_helpers_on_startup();

    // Surface the backend's isolation tier
    // when it isn't Tier 1, unless the operator explicitly
    // acknowledged the downgrade. This is observational today;
    // a future `--prod` mode will hard-fail instead.
    {
        let backend = mvm_backend::backend::AnyBackend::from_hypervisor(&args.hypervisor);
        let tier = backend.tier();
        if tier != mvm_backend::backend::BackendTier::Tier1 && !args.accept_tier2_isolation {
            crate::ui::warn(&format!(
                "backend '{}' is {} (not Tier 1). Pass --accept-tier2-isolation to suppress \
                 this warning on production-like launches. See plan 76 §\"libkrun isolation \
                 is not Firecracker isolation\".",
                backend.name(),
                tier.label()
            ));
        }
    }

    let memory_mb = args
        .memory
        .as_ref()
        .map(|s| parse_human_size(s))
        .transpose()
        .context("Invalid memory size")?;
    // CLI flag takes precedence; fall back to per-user config defaults.
    let effective_cpus = args.cpus.or(Some(cfg.default_cpus));
    let effective_memory = memory_mb.or(Some(cfg.default_memory_mib));

    // `--manifest <PATH>` accepts a manifest path or its
    // directory in addition to legacy names. Resolve the arg up front
    // and substitute the slot hash for downstream lookups; the
    // dispatched variants in lifecycle.rs branch on
    // `is_slot_hash_dirname` internally so the rest of `cmd_run`
    // doesn't need to know whether a name or a slot hash was used.
    let resolved_template_arg: Option<String> = match args.manifest.as_deref() {
        Some(arg) => match super::shared::resolve_manifest_arg(arg)? {
            super::shared::ManifestArgRef::Name(n) => Some(n),
            super::shared::ManifestArgRef::Slot { slot_hash } => Some(slot_hash),
        },
        None => None,
    };

    // If neither --network-preset nor
    // --network-allow is supplied, consult the template's baked-in
    // `default_network_policy` (only legacy name-keyed templates carry
    // this field; manifest-keyed slots don't — runtime policy moves
    // to `mvmctl up` flags / `~/.mvm/config.toml` / mvmd). Explicit
    // CLI flags always win.
    let explicit_cli_network = args.network_preset.is_some() || !args.network_allow.is_empty();
    let network_policy = if explicit_cli_network {
        resolve_network_policy(args.network_preset.as_deref(), &args.network_allow)?
    } else if let Some(id_or_slot) = resolved_template_arg.as_deref()
        && let Ok(spec) = mvm::vm::template::lifecycle::template_load_dispatched(id_or_slot)
        && let Some(default_policy) = spec.default_network_policy.clone()
    {
        crate::ui::info(&format!(
            "Using template '{id_or_slot}' default network policy"
        ));
        default_policy
    } else {
        resolve_network_policy(None, &[])?
    };

    // Claim 10 — deny-by-default network. When the resolved
    // policy is `unrestricted`, the user (or a template they
    // selected) explicitly opted out of the safe default. Surface
    // that as a one-line warning so operators are never surprised
    // by wide-open egress. Suppressible via
    // `MVM_ACK_UNRESTRICTED_NETWORK=1` for CI / scripted use that
    // already knows what it's doing.
    if network_policy.is_unrestricted()
        && std::env::var_os("MVM_ACK_UNRESTRICTED_NETWORK").is_none()
    {
        let source = if explicit_cli_network {
            "--network-preset unrestricted (CLI flag)"
        } else {
            "template's default_network_policy (baked at build time)"
        };
        // vm_name isn't bound at this point in the flow; use the
        // user-supplied --name (or "(unnamed)" placeholder) which
        // matches what the rest of the boot log shows.
        let label = args.name.as_deref().unwrap_or("(unnamed)");
        crate::ui::warn(&format!(
            "⚠ VM '{label}' will boot with UNRESTRICTED network egress (source: {source}).\n   \
             ADR-002 claim 10 sets deny-all as the safe default; \
             this workload opted out. Set MVM_ACK_UNRESTRICTED_NETWORK=1 \
             to suppress this warning."
        ));
    }
    let seccomp_tier: mvm_core::crypto::seccomp::SeccompTier =
        args.seccomp.parse().context("Invalid --seccomp value")?;
    let plan_seccomp_tier = plan_seccomp_tier(seccomp_tier)?;
    // `--from-workload-ir`, or the `workload.json` a compiled `--flake`
    // artifact carries. Resolved once, used for both
    // secret lowering and the deps-volume binding below.
    let effective_workload_ir =
        resolve_workload_ir_path(args.from_workload_ir.as_deref(), args.flake.as_deref());
    let lowered_plan_secrets = load_workload_ir(effective_workload_ir.as_deref())?
        .map(|workload| lower_workload_secrets(&workload))
        .unwrap_or_default();
    let plan_secret_release = lowered_plan_secrets.secret_release;
    // Sandbox metadata. Tag charset/length
    // validation happens in the security crate so audit-event emission
    // and webhook bodies see only validated input. TTL parsing rejects
    // out-of-range values (< 1s, > 30d) up front.
    let mut sandbox_tags: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for raw in &args.tags {
        let (k, v) = mvm_core::crypto::policy::InputValidator::parse_tag_arg(raw)
            .with_context(|| format!("Invalid --tag value: {:?}", raw))?;
        sandbox_tags.insert(k, v);
    }
    mvm_core::crypto::policy::InputValidator::validate_tag_map(&sandbox_tags)
        .context("Tag map exceeds aggregate caps")?;
    let sandbox_ttl = args
        .ttl
        .as_deref()
        .map(mvm_core::crypto::policy::parse_ttl)
        .transpose()
        .context("Invalid --ttl value")?;
    let auto_resume = !args.no_auto_resume;
    let mut build_mode = args.build_mode.resolve();
    if args.console && matches!(build_mode, mvm_build::pipeline::BuildMode::Prod) {
        // The interactive console is served only by the accessible dev
        // agent; a sealed prod image ships none (claim 15). Boot the dev
        // variant so `up --console` lands in a shell instead of being
        // refused at attach.
        ui::info("--console implies the dev image (prod ships no console agent); using dev.");
        build_mode = mvm_build::pipeline::BuildMode::Dev;
    }

    if args.no_supervisor {
        ui::warn(
            "--no-supervisor is a one-release escape hatch and will be removed; \
             plan-64 admission becomes mandatory in the next minor release.",
        );
    }

    // `--up-json` routes the friendly `[mvm]` chrome to stderr and
    // suppresses the auto-watch / auto-forward loops that would
    // otherwise block forever — the SDK live-mode transport
    // drives subsequent `proc start`/`fs write`/
    // `down` calls from outside, so `mvmctl up` must return as soon
    // as the VM is up. We also imply `--detach` for the Apple
    // Container launchd path so the agent owns the VM lifecycle.
    if args.up_json {
        mvm::ui::set_chrome_to_stderr(true);
        if args.watch {
            anyhow::bail!(
                "--up-json is incompatible with --watch (the JSON envelope is emitted once on first boot; watch reboots the VM repeatedly)."
            );
        }
        if args.forward {
            anyhow::bail!(
                "--up-json is incompatible with --forward (--forward blocks until Ctrl+C; --up-json must return as soon as the VM is up)."
            );
        }
    }

    // Capture the effective up-json + name eagerly so we can emit
    // the envelope on stdout after `cmd_run` returns. The friendly
    // chrome is already routed to stderr above.
    let up_json_resolved = args.up_json;
    let user_supplied_name = args.name.clone();
    let template_name_for_envelope = resolved_template_arg.clone();

    // 4-level tenant value
    // precedence: built-in `"local"` → `~/.mvm/config.toml`
    // `[tenant] name` → `MVM_TENANT` env → `--tenant` flag (highest).
    // Identity / `mvmctl auth` is a separate effort; this
    // value is only the string label that names the audit chain file.
    let resolved_tenant = super::tenant_resolution::resolve_tenant(args.tenant.as_deref());

    // Author the per-destination egress redaction policy from
    // `--redact HOST[=audit]`. Empty → all-off (curated-only baseline).
    let redaction = super::redaction_flags::parse_redaction_flags(&args.redact)?;

    cmd_run(RunParams {
        flake_ref: args.flake.as_deref(),
        template_name: resolved_template_arg.as_deref(),
        name: args.name.as_deref(),
        profile: args.profile.as_deref(),
        cpus: effective_cpus,
        memory: effective_memory,
        config_path: args.config.as_deref(),
        volumes: &args.volume,
        hypervisor: &args.hypervisor,
        ports: &args.port,
        env_vars: &args.env,
        forward: args.forward,
        metrics_port: args.metrics_port,
        warm_pool_size: args.warm_pool_size,
        watch_config: args.watch_config,
        watch: args.watch,
        detach: args.detach || args.up_json,
        network_policy,
        network_name: &args.network,
        seccomp_tier,
        plan_seccomp_tier,
        plan_secret_release,
        plan_secrets: lowered_plan_secrets.secrets,
        redaction,
        sandbox_tags,
        sandbox_ttl,
        auto_resume,
        tenant: &resolved_tenant,
        no_supervisor: args.no_supervisor,
        bundle_pin: args.bundle_pin.as_deref(),
        build_mode,
        workload_ir_path: effective_workload_ir.as_deref(),
        up_json: args.up_json,
        services_health_timeout_secs: cfg.effective_services_health_timeout_secs(),
        wait: args.wait,
        console: args.console,
    })?;

    // After a successful boot, emit a
    // one-line JSON envelope on stdout. The SDK live-mode transport
    // reads this envelope verbatim and threads `vm_id` + `build_mode`
    // through to subsequent `proc start` / `fs write` / `down`
    // shells. The friendly chrome already went to stderr above.
    if up_json_resolved {
        let vm_id = user_supplied_name
            .or_else(|| std::env::var("MVM_REEXEC_NAME").ok())
            .unwrap_or_default();
        let build_mode_str = match template_name_for_envelope.as_deref() {
            Some(t) => template_build_mode_for_envelope(t).unwrap_or("prod"),
            None => match build_mode {
                mvm_build::pipeline::BuildMode::Dev => "dev",
                mvm_build::pipeline::BuildMode::Prod => "prod",
            },
        };
        let envelope = serde_json::json!({
            "schema_version": 1,
            "vm_id": vm_id,
            "build_mode": build_mode_str,
        });
        println!("{}", envelope);
    }
    Ok(())
}

/// Resolve a template's `TemplateRevision.build_mode` for the
/// `--up-json` envelope. Returns `Some("dev")` / `Some("prod")` when
/// the revision parses cleanly, `None` when the template isn't on
/// disk (no spec to read, treat as prod downstream). Tolerates I/O
/// errors by returning `None` — the envelope's `build_mode` is a
/// hint, not a security boundary (the agent's `do_exec` strip is
/// the load-bearing gate). Live-mode SDK
/// clients use it to reject `commands.start` against a prod
/// template *before* any vsock round-trip; a missing / unreadable
/// spec falls through to the agent's response (the agent still
/// fails closed).
fn template_build_mode_for_envelope(template_name: &str) -> Option<&'static str> {
    // `template_load_current_revision` walks the same `current`
    // symlink the boot path uses, so the resolution matches what the
    // running VM was built from.
    let revision =
        mvm::vm::template::lifecycle::template_load_current_revision(template_name).ok()??;
    match revision.build_mode.as_deref() {
        Some("dev") => Some("dev"),
        _ => Some("prod"),
    }
}

pub(in crate::commands) struct RunParams<'a> {
    pub(super) flake_ref: Option<&'a str>,
    pub(super) template_name: Option<&'a str>,
    pub(super) name: Option<&'a str>,
    pub(super) profile: Option<&'a str>,
    pub(super) cpus: Option<u32>,
    pub(super) memory: Option<u32>,
    pub(super) config_path: Option<&'a str>,
    pub(super) volumes: &'a [String],
    pub(super) hypervisor: &'a str,
    pub(super) ports: &'a [String],
    pub(super) env_vars: &'a [String],
    pub(super) forward: bool,
    pub(super) metrics_port: u16,
    /// `--warm-pool-size`; 0 = off.
    pub(super) warm_pool_size: u32,
    pub(super) watch_config: bool,
    pub(super) watch: bool,
    pub(super) detach: bool,
    pub(super) network_policy: mvm_core::network_policy::NetworkPolicy,
    pub(super) network_name: &'a str,
    pub(super) seccomp_tier: mvm_core::crypto::seccomp::SeccompTier,
    pub(super) plan_seccomp_tier: mvm_core::plan::PlanSeccompTier,
    pub(super) plan_secret_release: mvm_core::plan::SecretReleasePolicy,
    pub(super) plan_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// All-off default preserves the curated-only baseline.
    pub(super) redaction: mvm_core::policy::RedactionPolicy,
    /// Validated sandbox tags from `--tag k=v`.
    pub(super) sandbox_tags: std::collections::BTreeMap<String, String>,
    /// Parsed `--ttl` duration; reaper tears VM down after this elapses.
    pub(super) sandbox_ttl: Option<std::time::Duration>,
    /// `false` when `--no-auto-resume` is set.
    pub(super) auto_resume: bool,
    /// Tenant string for `ExecutionPlan` synthesis.
    pub(super) tenant: &'a str,
    /// `true` when `--no-supervisor` is set — disables admission.
    pub(super) no_supervisor: bool,
    /// Optional `.mvmpkg` archive path that admit_for_run re-verifies
    /// against the local trust store before backend dispatch.
    /// `Some(p)` populates `PlanArtifact` in the synthesised plan.
    pub(super) bundle_pin: Option<&'a std::path::Path>,
    pub(super) build_mode: mvm_build::pipeline::BuildMode,
    /// Optional path to a Workload IR JSON. When set + the IR
    /// carries `App.dependencies = Dependencies::Python |
    /// Dependencies::Node`, the deps install pipeline runs +
    /// pins a `DepsVolumeBinding` into the synthesized plan.
    pub(super) workload_ir_path: Option<&'a std::path::Path>,
    /// When `true`, `cmd_run` emits a one-line JSON envelope on
    /// stdout right before returning. The
    /// SDK live-mode transport parses this envelope to thread the
    /// generated VM id + the template's `build_mode` through to
    /// subsequent `proc start` / `fs write` / `down` calls.
    pub(super) up_json: bool,
    /// Resolved services-health wait timeout
    /// (`InstanceReadiness::ServicesStarting` →
    /// `InstanceReadiness::ServicesReady`). Comes from
    /// `MvmConfig::effective_services_health_timeout_secs()` so an
    /// `MVM_SERVICES_HEALTH_TIMEOUT_SECS` env-var override or a
    /// `services_health_timeout_secs = N` line in
    /// `~/.mvm/config.toml` flow through without `cmd_run` itself
    /// re-reading the config.
    pub(super) services_health_timeout_secs: u64,
    /// `true` when `--wait` was set. After the agent-ready check
    /// confirms the workload booted, block until it powers off and
    /// propagate its exit code.
    pub(super) wait: bool,
    /// `true` when `--console` was set. After the agent-ready check,
    /// attach an interactive PTY console to the guest and return when
    /// the shell exits (the VM stays running).
    pub(super) console: bool,
}

pub(super) fn cmd_run(params: RunParams<'_>) -> Result<()> {
    let RunParams {
        flake_ref,
        template_name,
        name,
        profile,
        cpus,
        memory,
        config_path,
        volumes,
        hypervisor,
        ports,
        env_vars,
        forward,
        metrics_port,
        warm_pool_size,
        watch_config,
        watch,
        detach,
        network_policy,
        network_name,
        seccomp_tier,
        plan_seccomp_tier,
        plan_secret_release,
        plan_secrets,
        redaction,
        sandbox_tags,
        sandbox_ttl,
        auto_resume,
        tenant,
        no_supervisor,
        bundle_pin,
        build_mode,
        workload_ir_path,
        up_json: _up_json,
        services_health_timeout_secs,
        wait,
        console,
    } = params;
    let _span =
        tracing::info_span!("cmd_run", name = ?name, cpus = ?cpus, memory_mib = ?memory).entered();
    if let Some(n) = name {
        validate_vm_name(n).with_context(|| format!("Invalid VM name: {:?}", n))?;
    }
    if let Some(f) = flake_ref {
        validate_flake_ref(f).with_context(|| format!("Invalid flake reference: {:?}", f))?;
    }
    if let Some(t) = template_name {
        // Slot hashes (64-char lowercase hex) bypass the template-name
        // validator since they exceed the 63-char name length cap.
        if !mvm_core::manifest::is_slot_hash_dirname(t) {
            validate_template_name(t).with_context(|| format!("Invalid template name: {:?}", t))?;
        }
    }
    // Auto-select backend when no explicit hypervisor is specified.
    // Mirrors AnyBackend::auto_select()'s priority so the CLI default
    // matches the rest of the codebase: native KVM → Apple Container
    // (macOS 26+) → libkrun (typical macOS 13-25 contributor box with
    // the slp/krun Homebrew tap).
    // Shared with `mvmctl pool` so both agree on the effective backend.
    let effective_hypervisor_owned = super::super::shared::resolve_effective_hypervisor(hypervisor);
    let effective_hypervisor: &str = &effective_hypervisor_owned;

    // Fail fast before boot so the user sees a clear
    // error instead of booting then hitting the generic backend bail.
    if wait && effective_hypervisor != "libkrun" {
        anyhow::bail!(
            "--wait is currently only supported on the libkrun backend (Plan 152 WS-A); \
             other backends gain it in a later slice"
        );
    }

    // Lima is gone; no upfront VM check needed. The
    // libkrun-as-Linux-builder follow-up will reintroduce
    // a builder-availability gate at this point when it lands.
    let _metrics_server = if metrics_port > 0 {
        Some(crate::metrics_server::MetricsServer::start(metrics_port)?)
    } else {
        None
    };

    // Start config watcher so the user is notified if the config file changes
    // while the build or boot is in progress.
    let _config_watcher = if watch_config {
        let config_path =
            std::path::PathBuf::from(mvm_core::config::mvm_data_dir()).join("config.toml");
        if config_path.exists() {
            match crate::config_watcher::ConfigWatcher::start(&config_path) {
                Ok(w) => {
                    tracing::info!("Watching ~/.mvm/config.toml for changes");
                    Some(w)
                }
                Err(e) => {
                    tracing::warn!("Could not start config watcher: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    // Generate a VM name if not provided.
    // After codesign re-exec (macOS), the env var preserves the originally
    // generated name so we don't produce a second random name.
    let vm_name = match name {
        Some(n) => n.to_string(),
        None => std::env::var("MVM_REEXEC_NAME").unwrap_or_else(|_| {
            let mut generator = names::Generator::default();
            generator.next().unwrap_or_else(|| "vm-0".to_string())
        }),
    };

    // Register the VM name in the persistent registry (best-effort).
    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        // Deregister stale entry with the same name if it exists
        registry.deregister(&vm_name);
        let expires_at = sandbox_ttl.map(mvm_core::util::time::utc_plus_duration);
        let _ = registry.register_with_metadata(mvm::vm::name_registry::RegisterParams {
            name: &vm_name,
            vm_dir: "",
            network: network_name,
            guest_ip: None,
            slot_index: 0,
            tags: sandbox_tags.clone(),
            expires_at,
            auto_resume,
        });
        let _ = registry.save(&registry_path);
    }

    // Admission ledger. One per `cmd_run`; the watch-mode loop
    // reuses it across rebuilds so synthesized plans share a single
    // replay-window across the lifetime of the process.
    let admission_ledger = InMemoryNonceLedger::new();

    // Resolve the deps-volume binding once
    // (cache-hit path only — `mvmctl up` does not spawn the builder
    // VM today; that's `mvmctl deps build`) and thread
    // it to every admit_plan_for_boot call site below. Returns
    // `Ok(None)` when `--from-workload-ir` is absent or the IR
    // carries no lockfile (claim-8 preserved).
    let deps_volume_binding = resolve_deps_volume_binding(workload_ir_path, build_mode)?;

    // Direct boot mode: launchd agent passes kernel/rootfs via env vars.
    // Skip the build/template loading entirely.
    if std::env::var("MVM_DIRECT_BOOT").as_deref() == Ok("1") {
        let kernel = std::env::var("MVM_KERNEL_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_KERNEL_PATH not set"))?;
        let rootfs = std::env::var("MVM_ROOTFS_PATH")
            .map_err(|_| anyhow::anyhow!("MVM_ROOTFS_PATH not set"))?;

        let direct_cpus = cpus.unwrap_or(2);
        let direct_mem = memory.unwrap_or(512);
        let admission = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant,
            vm_name: &vm_name,
            backend_name: effective_hypervisor,
            rootfs_path: std::path::Path::new(&rootfs),
            precomputed_image_sha256: None,
            cpus: direct_cpus,
            mem_mib: direct_mem as u64,
            seccomp_tier: plan_seccomp_tier,
            secret_release: plan_secret_release,
            secrets: plan_secrets.clone(),
            no_supervisor,
            ledger: &admission_ledger,
            keys_dir: None,
            audit_dir: None,
            policy_dir: None,
            bundle_pin,
            deps_volume: deps_volume_binding.clone(),
            // Re-exec path: user volumes aren't threaded here.
            shares: Vec::new(),
            redaction: redaction.clone(),
        })?;

        let mut start_config = mvm_core::vm_backend::VmStartConfig {
            name: vm_name.clone(),
            rootfs_path: rootfs,
            kernel_path: Some(kernel),
            cpus: direct_cpus,
            memory_mib: direct_mem,
            ..Default::default()
        };
        // Attach the verity-sealed runtime overlay (Firecracker only, non-fatal).
        attach_runtime_overlay_if_cached(&mut start_config, effective_hypervisor);
        // When admission produced an AdmissionContext,
        // thread tenant_id / plan_json / bundle_json so libkrun/Vz take
        // the bridge-factory path. None keeps the legacy supervisor path
        // for no-admission flows.
        if let Some(ctx) = admission.as_ref() {
            populate_audit_substrate(&mut start_config, &ctx.admitted, ctx.policy_bundle.as_ref())?;
            // Firecracker bridge sidecar reads
            // plan.json + bundle.json from the per-VM state dir at
            // spawn time. Stash them now (mode 0600, tmp+rename).
            stash_plan_for_bridge(&start_config)?;
        }

        enforce_shares_if(&admission, &start_config.volumes)?;
        let backend = AnyBackend::from_hypervisor(effective_hypervisor);
        if let Err(e) = mvm_backend::workload_backend::require_workload_backend(&backend) {
            emit_failed_if(&admission, "backend-start", &e);
            return Err(e);
        }
        if let Err(e) = backend.start(&start_config) {
            emit_failed_if(&admission, "backend-start", &e);
            return Err(e);
        }
        emit_launched_if(&admission, effective_hypervisor);
        record_vm_readiness(&vm_name, InstanceReadiness::LaunchAccepted);

        // Match the main path's VmStart LocalAudit emit.
        // Without this the launchd-spawned direct-boot
        // surface skips the LocalAudit stream entirely, breaking the
        // "every state-changing CLI verb emits one record per attempt"
        // invariant for the only verb that runs under launchd. Also
        // unblocks hermetic end-to-end tests of `mvmctl up` via
        // MVM_DIRECT_BOOT + `--hypervisor mock`.
        mvm_core::audit_emit!(VmStart, vm: &vm_name);

        let direct_boot_ports = std::env::var("MVM_PORTS").ok();

        // Services-health: foreground direct boot waits for the
        // guest agent, then polls integration health. Detached direct
        // boot is fire-and-forget unless port forwarding was
        // requested via MVM_PORTS; forwarding still needs the agent
        // before the CLI exits so the host proxy can be established.
        // The wait was previously gated on `MVM_PORTS` because port
        // forwarding was the only existing reason to block here. The
        // gate moved off — every up now records `AgentConnecting` /
        // `AgentReady` / `ServicesStarting` / `ServicesReady` so
        // `mvmctl ls --json` shows a useful wait reason for every
        // VM, not just port-forwarded ones.
        let should_wait_for_agent =
            should_wait_for_direct_boot_agent(detach, direct_boot_ports.as_deref());
        let agent_ready = if should_wait_for_agent {
            ui::info("Waiting for guest agent...");
            record_vm_readiness(&vm_name, InstanceReadiness::AgentConnecting);
            wait_for_guest_agent(&vm_name, 30)
        } else {
            false
        };
        if agent_ready {
            record_vm_readiness(&vm_name, InstanceReadiness::AgentReady);
            // Agent ready means /init ran, which
            // means `mvm-guest-netinit` produced its report.
            // Parse the console log and emit
            // `NetworkMandatoryDeny` audit records. Best-effort:
            // a missing marker (older template) or unreadable
            // log is fine, we just skip silently.
            if let Err(e) = mvm_backend::netinit_audit::emit_for_vm(&vm_name) {
                tracing::debug!(
                    vm = %vm_name,
                    error = %e,
                    "netinit audit emit skipped (best-effort)"
                );
            }
            let timeout = std::time::Duration::from_secs(services_health_timeout_secs);
            super::readiness::wait_for_services_ready(&vm_name, timeout);
        } else if should_wait_for_agent {
            ui::warn("Guest agent not reachable.");
        }

        // Set up port forwarding from MVM_PORTS env var (via vsock).
        // Requires the agent — skip silently if the wait above gave
        // up.
        if agent_ready
            && let Some(ports_str) = direct_boot_ports.as_deref()
            && !ports_str.is_empty()
        {
            for spec in ports_str.split(',') {
                if let Some((host, guest)) = spec.split_once(':')
                    && let (Ok(h), Ok(g)) = (host.parse::<u16>(), guest.parse::<u16>())
                {
                    let _ = request_port_forward(&vm_name, g);
                    start_port_proxy(&vm_name, h, g);
                    ui::info(&format!("Forwarding localhost:{h} → guest tcp/{g} (vsock)"));
                }
            }
        }

        // `--detach` short-circuits the Ctrl+C loop. The launchd
        // agent always passes `--detach` (it owns the VM lifecycle
        // and uses launchd's own restart/keepalive semantics — the
        // long-lived CLI process would be redundant). Same shape as
        // the main path's detach branch.
        if detach {
            return Ok(());
        }

        ui::info(&format!("VM '{}' running. Press Ctrl+C to stop.", vm_name));

        // Block until signaled. Degraded follow-up: every ~10 s
        // while the foreground wait is
        // active, poll integration health and flip readiness to
        // `Degraded { unhealthy }` when an `Active` service flips to
        // `Error`. Recovers to `ServicesReady` automatically when the
        // service comes back. The monitor dedupes; identical
        // snapshots don't thrash the registry file.
        let pair = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let pair2 = pair.clone();
        let _ = ctrlc::set_handler(move || {
            let (lock, cvar) = &*pair2;
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cvar.notify_all();
        });
        let (lock, cvar) = &*pair;
        let mut stopped = lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut monitor = super::readiness::ServicesHealthMonitor::new();
        let mut next_health_poll = std::time::Instant::now() + DEGRADED_POLL_INTERVAL;
        while !*stopped {
            stopped = cvar
                .wait_timeout(stopped, std::time::Duration::from_secs(1))
                .unwrap_or_else(|e| e.into_inner())
                .0;
            if !*stopped && std::time::Instant::now() >= next_health_poll {
                let _ = monitor.observe_and_record(&vm_name);
                next_health_poll = std::time::Instant::now() + DEGRADED_POLL_INTERVAL;
            }
        }
        let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name));
        return Ok(());
    }

    // Resolve artifact paths from either a pre-built template or a flake build.
    let (
        vmlinux_path,
        initrd_path,
        rootfs_path,
        revision_hash,
        source_flake,
        source_profile,
        tmpl_cpus,
        tmpl_mem,
        tmpl_mem_initial,
        snapshot_info,
    ) = if let Some(tmpl) = template_name {
        ui::step(
            1,
            2,
            &format!("Loading template '{}' for VM '{}'", tmpl, vm_name),
        );
        let (spec, vmlinux, initrd, rootfs, rev) =
            mvm::vm::template::lifecycle::template_artifacts_dispatched(tmpl)?;
        ui::info(&format!("Using revision {}", rev));

        // Check for pre-built snapshot
        let snap_info = mvm::vm::template::lifecycle::template_snapshot_info_dispatched(tmpl)?;
        if snap_info.is_some() {
            ui::info("Snapshot available — will restore instantly");
        }

        (
            vmlinux,
            initrd,
            rootfs,
            rev,
            spec.flake_ref.clone(),
            Some(spec.profile.clone()),
            Some(spec.vcpus as u32),
            Some(spec.mem_mib),
            spec.mem_initial_mib,
            snap_info,
        )
    } else if let Some(flake) = flake_ref {
        let resolved = resolve_flake_ref(flake)?;
        let profile_display = profile.unwrap_or("default");
        ui::step(
            1,
            2,
            &format!(
                "Building flake {} (profile={}, name={})",
                resolved, profile_display, vm_name
            ),
        );
        let run_build_env = mvm::build_env::default_build_env();
        let env = run_build_env.as_ref();
        let result = mvm_build::dev_build::dev_build(env, &resolved, profile, build_mode)?;
        if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
            ui::warn(&format!(
                "Could not verify guest agent ({}). If built with mkGuest, the agent is already included.",
                e
            ));
        }
        if result.cached {
            ui::info(&format!("Cache hit — revision {}", result.revision_hash));
        } else {
            ui::info(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));
        }
        (
            result.vmlinux_path,
            result.initrd_path,
            result.rootfs_path,
            result.revision_hash,
            flake.to_string(),
            profile.map(|s| s.to_string()),
            None,
            None,
            None, // tmpl_mem_initial — flake builds don't carry it
            None, // No snapshot for flake builds
        )
    } else {
        ui::step(
            1,
            2,
            &format!(
                "No --flake or --manifest; using bundled default microVM image for '{}'",
                vm_name
            ),
        );
        let (kernel, rootfs) = ensure_default_microvm_image(build_mode)?;
        (
            kernel,
            None,
            rootfs,
            String::new(),
            "default-microvm".to_string(),
            None,
            None,
            None,
            None, // tmpl_mem_initial
            None,
        )
    };

    let backend_label = match effective_hypervisor {
        "vz" => "Apple Virtualization",
        "qemu" => "QEMU",
        _ => "Firecracker VM",
    };
    ui::step(2, 2, &format!("Booting {} '{}'", backend_label, vm_name));

    let rt_config = match config_path {
        Some(p) => image::parse_runtime_config(p)?,
        None => image::RuntimeConfig::default(),
    };

    // Partition volume specs (MVM_VOLUMES env baseline + --volume flags)
    // into the config/secret-drive special-cases and generic
    // shares/disks. `/mnt/config` + `/mnt/secrets` *directory* specs are
    // intercepted as RO config/secret drives (the long-standing
    // contract); everything else becomes a virtio-fs share or virtio-blk
    // disk, validated against the reserved-mount list and the
    // encryption-not-yet gate.
    let mut volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
    let mut config_files: Vec<microvm::DriveFile> = Vec::new();
    let mut secret_files: Vec<microvm::DriveFile> = Vec::new();

    let merged_volumes = merge_volume_specs(volumes);
    if !merged_volumes.is_empty() {
        for v in &merged_volumes {
            let spec = parse_volume_spec(v)?;
            match &spec {
                VolumeSpec::DirShare {
                    host_dir,
                    guest_mount,
                    ..
                } if guest_mount == "/mnt/config" => {
                    config_files.extend(
                        read_dir_to_drive_files(host_dir, 0o444)
                            .with_context(|| format!("reading volume '{v}'"))?,
                    );
                }
                VolumeSpec::DirShare {
                    host_dir,
                    guest_mount,
                    ..
                } if guest_mount == "/mnt/secrets" => {
                    secret_files.extend(
                        read_dir_to_drive_files(host_dir, 0o400)
                            .with_context(|| format!("reading volume '{v}'"))?,
                    );
                }
                _ => {
                    let vmv = vm_volume_from_spec_validated(&spec)
                        .with_context(|| format!("volume '{v}'"))?;
                    // Claim-1 visibility: host-fs access is never silent.
                    // A read-WRITE grant lets a (possibly untrusted) guest
                    // modify host files — warn loudly; a read-only share
                    // is the safe default, so just note it.
                    let kind_label = match vmv.kind {
                        mvm_core::vm_backend::VmVolumeKind::DirShare => "host directory",
                        mvm_core::vm_backend::VmVolumeKind::Disk => "disk image",
                    };
                    if vmv.read_only {
                        ui::info(&format!(
                            "Sharing {kind_label} '{}' into the guest at '{}' (read-only).",
                            vmv.host, vmv.guest,
                        ));
                    } else {
                        ui::warn(&format!(
                            "READ-WRITE: {kind_label} '{}' is mounted writable at '{}' — \
                             the guest can modify this host path. Drop ':rw' to share read-only.",
                            vmv.host, vmv.guest,
                        ));
                    }
                    // Sparse-create a disk-image volume's backing file so
                    // the hypervisor can attach it (no-op for dir shares).
                    materialize_disk_volume(&vmv).with_context(|| format!("volume '{v}'"))?;
                    volume_cfg.push(image::RuntimeVolume::from(&vmv));
                }
            }
        }
    } else {
        volume_cfg = rt_config.volumes.clone();
    };

    // If the plan carries secrets bound to egress hosts, mint
    // the per-VM name-constrained egress intermediate and stage it: cert → the
    // guest secrets drive (below), key → a host-only sidecar the terminator
    // endpoint reads. No-op when the plan has no secrets / no egress bindings.
    stage_egress_tls_delivery(&plan_secrets, tenant, &vm_name, &mut secret_files)
        .context("staging per-VM egress TLS material")?;

    let user_cfg = mvm_core::user_config::load(None);
    let final_cpus = cpus
        .or(rt_config.cpus)
        .or(tmpl_cpus)
        .unwrap_or(user_cfg.default_cpus);
    let final_memory = memory
        .or(rt_config.memory)
        .or(tmpl_mem)
        .unwrap_or(user_cfg.default_memory_mib);
    // Balloon opt-in resolution. Precedence:
    //   1. `--config` runtime override (`rt_config.mem_initial`)
    //   2. Template-baked value (manifest's `mem_initial` from the
    //      slot's PersistedManifest, via TemplateSpec.mem_initial_mib)
    //   3. Off (legacy commit-mem_mib-at-boot shape)
    // The final value must be strictly inside `(0, final_memory)`;
    // anything else gets filtered to `None` so the FC + CH backends
    // never see a value they'd reject anyway.
    let final_mem_initial = rt_config
        .mem_initial
        .or(tmpl_mem_initial)
        .filter(|n| *n > 0 && *n < final_memory);

    // Parse port mappings and inject as config drive file
    let port_mappings = parse_port_specs(ports)?;
    if let Some(f) = ports_to_drive_file(&port_mappings) {
        config_files.push(f);
    }

    // Inject env vars as config drive file
    if let Some(f) = env_vars_to_drive_file(env_vars) {
        config_files.push(f);
    }

    // Inject seccomp manifest into config drive if not unrestricted
    if let Some(manifest) = seccomp_tier.to_manifest() {
        let json = serde_json::to_string_pretty(&manifest)
            .context("failed to serialize seccomp manifest")?;
        config_files.push(microvm::DriveFile {
            name: "seccomp.json".to_string(),
            content: json,
            mode: 0o644,
        });
    }

    // `mut` so a warm-pool claim can rebind it to the claimed standby-id.
    let mut vm_name_owned = vm_name.clone();
    let has_ports = !port_mappings.is_empty();

    // Stash the generated VM name so that if the Apple Container backend
    // re-execs after codesigning, the new process reuses the same name.
    // SAFETY: called early in single-threaded CLI startup before spawning
    // worker threads; no other threads are reading env vars concurrently.
    unsafe { std::env::set_var("MVM_REEXEC_NAME", &vm_name) };

    // Admission for the regular boot path. Snapshot restore
    // and cold-boot both consume `rootfs_path` below, so admission
    // happens here before either branch moves the path. The launchd
    // detach-fork further down inside the else-branch boots through
    // the same start_config, so it inherits this admission.
    let admission_main = admit_plan_for_boot(AdmitPlanForBootParams {
        tenant,
        vm_name: &vm_name,
        backend_name: effective_hypervisor,
        rootfs_path: std::path::Path::new(&rootfs_path),
        precomputed_image_sha256: None,
        cpus: final_cpus,
        mem_mib: final_memory as u64,
        seccomp_tier: plan_seccomp_tier,
        secret_release: plan_secret_release,
        secrets: plan_secrets.clone(),
        no_supervisor,
        ledger: &admission_ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin,
        deps_volume: deps_volume_binding.clone(),
        shares: shares_from_volume_cfg(&volume_cfg),
        redaction: redaction.clone(),
    })?;

    // Vz-family backends need a real kernel file; mkGuest workload images ship
    // none (libkrun self-materializes its bundled kernel). Resolve the fallback
    // before either the snapshot-restore or cold-boot arm consumes vmlinux_path.
    let vmlinux_path = resolve_vz_workload_kernel(&vmlinux_path, effective_hypervisor)?;

    // If a template snapshot exists AND the backend supports snapshots,
    // restore from it instead of cold-booting.
    let backend = AnyBackend::from_hypervisor(effective_hypervisor);
    // (Workload images ship no kernel; libkrun's boot path materializes the
    // bundled libkrunfw kernel centrally in `mvm-libkrun` — see
    // `KrunContext` set_kernel — so every caller, not just `up`, gets it.)

    if let Some(ref snap_info) = snapshot_info
        && let Some(tmpl) = template_name
        && backend.capabilities().snapshots
    {
        let slot = microvm::allocate_slot(&vm_name)?;
        // Probe for the verity sidecar alongside the rootfs so the
        // restored VM boots through dm-verity when the template was
        // built with `verifiedBoot = true`.
        let (verity_path, roothash) = microvm::probe_verity_sidecar(&rootfs_path);
        let run_config = microvm::FlakeRunConfig {
            name: vm_name,
            slot,
            vmlinux_path,
            initrd_path,
            rootfs_path,
            verity_path,
            roothash,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory: final_memory,
            mem_initial: final_mem_initial,
            volumes: volume_cfg,
            config_files,
            secret_files,
            ports: port_mappings,
            network_policy: network_policy.clone(),
        };
        let rev = if mvm_core::manifest::is_slot_hash_dirname(tmpl) {
            mvm::vm::template::lifecycle::current_revision_id_for_slot(tmpl)?
        } else {
            mvm::vm::template::lifecycle::current_revision_id(tmpl)?
        };
        let snap_dir = if mvm_core::manifest::is_slot_hash_dirname(tmpl) {
            mvm_core::manifest::slot_snapshot_dir(tmpl, &rev)
        } else {
            mvm_core::template::template_snapshot_dir(tmpl, &rev)
        };
        ui::step(
            2,
            2,
            &format!("Restoring VM '{}' from snapshot", vm_name_owned),
        );
        if let Err(e) =
            microvm::restore_from_template_snapshot(tmpl, &run_config, &snap_dir, snap_info)
        {
            emit_failed_if(&admission_main, "snapshot-restore", &e);
            return Err(e);
        }
        emit_launched_if(&admission_main, effective_hypervisor);
    } else {
        let (verity_path, roothash) = microvm::probe_verity_sidecar(&rootfs_path);
        let mut start_config = VmStartParams {
            name: vm_name,
            rootfs_path,
            vmlinux_path,
            initrd_path,
            verity_path,
            roothash,
            revision_hash,
            flake_ref: source_flake,
            profile: source_profile,
            cpus: final_cpus,
            memory_mib: final_memory,
            mem_initial_mib: final_mem_initial,
            volumes: &volume_cfg,
            config_files: &config_files,
            secret_files: &secret_files,
            port_mappings: &port_mappings,
            warm_pool_size,
        }
        .into_start_config();
        // Attach the verity-sealed runtime overlay (Firecracker only, non-fatal).
        attach_runtime_overlay_if_cached(&mut start_config, effective_hypervisor);
        // Thread audit substrate from admission_main
        // through to backend.start() so libkrun/Vz take the bridge-factory
        // path. None keeps the legacy supervisor path for no-admission flows.
        //
        // The in-VM gateway-audit bridge (claim 10/12) is gated behind an
        // explicit opt-in: its libkrun gvproxy wiring
        // (`run_supervisor_with_bridge`) is not yet working end-to-end
        // (gvproxy exits with "vfkit socket address is empty"), so the
        // default routes `up --flake` through the proven legacy supervisor —
        // the same path the builder VM boots on, with the per-OS gateway.
        // Host-side admission (claim 8) above still applies. Re-enable with
        // MVM_GATEWAY_BRIDGE=1 once the bridge gvproxy path is fixed.
        let gateway_bridge_enabled = std::env::var("MVM_GATEWAY_BRIDGE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if should_thread_signed_plan(gateway_bridge_enabled, effective_hypervisor)
            && let Some(ctx) = admission_main.as_ref()
        {
            populate_audit_substrate(&mut start_config, &ctx.admitted, ctx.policy_bundle.as_ref())?;
            // Stash plan.json + bundle.json for the
            // Firecracker bridge sidecar to read at spawn time. Bridge-only:
            // the QEMU substitution endpoint reads the in-memory config, so it
            // needs no on-disk copy (and must not overwrite the persisted plan).
            if gateway_bridge_enabled {
                stash_plan_for_bridge(&start_config)?;
            }
        }

        // The Vz supervisor detaches on its own — `backend.start()`
        // spawns a background child that writes a PID file under the
        // per-VM state dir and outlives this process, reaped later by
        // `down`. So `up -d` on Vz needs no separate daemon machinery;
        // it falls through to the normal start path below and returns
        // (the persistent-agent wait further down is skipped for `detach`).

        enforce_shares_if(&admission_main, &start_config.volumes)?;
        // The Firecracker egress moat (substitution endpoint + nft TAP
        // redirect) reads the admitted plan from the per-VM state dir
        // *before* boot, so a secret-bearing plan must be persisted
        // pre-start — the post-launch persist in `emit_launched_if` is
        // too late for it. Other backends read the in-memory config.
        // Fail closed: a secret-declaring workload must not boot without
        // its substitution path.
        if effective_hypervisor == "firecracker"
            && let Some(ctx) = admission_main.as_ref()
            && !ctx.admitted.plan.secrets.is_empty()
        {
            super::plan_persist::write_plan(&ctx.admitted.plan.workload.0, &ctx.admitted.plan)
                .context("persisting admitted plan for the Firecracker egress moat")?;
        }
        // Try a warm-pool claim first (auto-named + bridge-admitted
        // launches only; fail-open to cold boot). A claimed VM runs under its standby-id,
        // so rebind `vm_name_owned` for all downstream (agent wait, audit, readiness, stop).
        // Hand the claim the rootfs sha admission already computed so it doesn't
        // re-hash the rootfs to build the image compat key.
        let admitted_image_sha = admission_main
            .as_ref()
            .map(|ctx| ctx.admitted.plan.image.sha256.clone());
        let claimed: Option<String> = match super::super::pool::try_warm_claim(
            &backend,
            &start_config,
            name.is_some(),
            admitted_image_sha.as_deref(),
        ) {
            Ok(Some(id)) => {
                ui::info(&format!(
                    "Claimed a warm standby ({}) — skipping cold boot.",
                    id.0
                ));
                Some(id.0)
            }
            Ok(None) => None,
            Err(e) => {
                // try_warm_claim itself erroring (pool I/O, etc.) must not fail the launch.
                tracing::warn!(error = %e, "warm-claim attempt errored; cold-booting");
                None
            }
        };
        match claimed {
            Some(name) => vm_name_owned = name,
            None => {
                if let Err(e) = mvm_backend::workload_backend::require_workload_backend(&backend) {
                    emit_failed_if(&admission_main, "backend-start", &e);
                    return Err(e);
                }
                if let Err(e) = backend.start(&start_config) {
                    emit_failed_if(&admission_main, "backend-start", &e);
                    return Err(e);
                }
            }
        }
        emit_launched_if(&admission_main, effective_hypervisor);
        record_vm_readiness(&vm_name_owned, InstanceReadiness::LaunchAccepted);
        // Replenish the pool toward target after launch — best-effort, no daemon.
        if let Err(e) = super::super::pool::replenish_after_launch(&backend, &start_config) {
            tracing::debug!(error = %e, "pool replenish skipped (best-effort)");
        }
    }

    mvm_core::audit_emit!(VmStart, vm: &vm_name_owned);

    // Vz with -d: the supervisor already detached during `start()`, so
    // there is nothing to keep alive in this process. Print the name
    // (scripting contract) and return without the agent-wait below.
    if detach && effective_hypervisor == "vz" {
        println!("{vm_name_owned}");
        return Ok(());
    }

    // libkrun / firecracker / vz all launch a detached supervisor daemon,
    // so `up` returns after launch. Verify the guest agent here anyway:
    // without it, `up` exits 0 the instant the daemon spawns — never
    // checking that the guest actually booted and the agent answered —
    // so a real boot failure passes silently and `core_demo_e2e`'s
    // boot→ping proof is hollow (it only watches for this exact warning).
    // `--detach` opted out above (fire-and-forget). `--wait` (one-shot)
    // skips this persistent-agent probe: the workload runs then
    // `poweroff -f`s, so there is no agent to wait for — we wait for the
    // VM to power off in the `wait` block below and read its captured exit
    // code instead.
    if matches!(effective_hypervisor, "libkrun" | "firecracker" | "vz") && !detach && !wait {
        ui::info("Waiting for guest agent...");
        record_vm_readiness(&vm_name_owned, InstanceReadiness::AgentConnecting);
        if wait_for_guest_agent(&vm_name_owned, 30) {
            record_vm_readiness(&vm_name_owned, InstanceReadiness::AgentReady);
            if let Err(e) = mvm_backend::netinit_audit::emit_for_vm(&vm_name_owned) {
                tracing::debug!(
                    vm = %vm_name_owned,
                    error = %e,
                    "netinit audit emit skipped (best-effort)"
                );
            }
        } else {
            // A non-detached `up` means "bring the workload up and confirm
            // it" — a daemon that spawned but whose agent never answered
            // within the boot timeout has failed. Stop the orphaned daemon
            // and exit non-zero so the failure is unmissable. (Exit code,
            // not the warning string: `ui::warn` routes to stdout by
            // default, which a stderr-only check would miss; `ui::error`
            // below keeps the message on stderr regardless.)
            ui::error("Guest agent not reachable.");
            let _ = backend.stop(&mvm_core::vm_backend::VmId(vm_name_owned.clone()));
            let err = anyhow::anyhow!(
                "guest agent for '{vm_name_owned}' not reachable within 30s of boot"
            );
            emit_failed_if(&admission_main, "agent-unreachable", &err);
            return Err(err);
        }
    }

    // `--console`: drop straight into an interactive PTY in the
    // just-booted guest, reusing the same PTY-over-vsock transport as
    // `mvmctl console`. Only the dev agent serves it (a sealed prod image
    // ships none — claim 15), which is why `--console` forced the dev
    // image upstream. The VM keeps running after the shell exits;
    // `mvmctl down <name>` stops it.
    if console {
        return super::console::console_interactive(&vm_name_owned);
    }

    // Block until the workload powers off and propagate its
    // exit code. `--wait` is parse-time mutually exclusive with `--detach`
    // and `--up-json` (see Args); only the foreground libkrun path reaches here.
    if wait && effective_hypervisor == "libkrun" {
        let id = mvm_core::vm_backend::VmId(vm_name_owned.clone());
        let status = backend.wait(&id)?;
        let code = status.code.unwrap_or(1);
        if let Some(ctx) = &admission_main
            && let Err(e) = ctx
                .emitter
                .emit_exited(&ctx.admitted.plan, code, effective_hypervisor)
        {
            tracing::warn!(error = %e, "audit emit_exited failed (non-fatal)");
        }
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }

    if forward {
        if has_ports {
            forward_ports(&vm_name_owned, &[])?;
        } else {
            ui::warn("--forward was set but no ports were declared. Use -p to specify ports.");
        }
    }

    // Watch mode: on each .nix / flake.lock change, stop the VM, rebuild, reboot.
    if watch {
        let Some(flake) = flake_ref else {
            // Template mode — watch not supported.
            return Ok(());
        };
        if flake.contains(':') {
            ui::warn("--watch requires a local flake; running a single boot instead.");
            return Ok(());
        }
        let flake_dir = resolve_flake_ref(flake)?;
        loop {
            ui::info("Watching for .nix and .lock changes (Ctrl+C to exit)...");
            match crate::watch::wait_for_changes(&flake_dir) {
                Ok(trigger) => {
                    let display = crate::watch::display_trigger(&trigger, &flake_dir);
                    ui::info(&format!("\nChange detected: {display} — rebuilding..."));
                }
                Err(e) => {
                    tracing::warn!("Watch error: {e}");
                    break;
                }
            }

            // Stop the running VM.
            let backend = AnyBackend::default_backend();
            if let Err(e) = backend.stop(&VmId::from(vm_name_owned.as_str())) {
                tracing::warn!("Could not stop '{}': {e}", vm_name_owned);
            }

            // Rebuild the flake.
            let env = mvm::build_env::RuntimeBuildEnv;
            let result =
                match mvm_build::dev_build::dev_build(&env, &flake_dir, profile, build_mode) {
                    Ok(r) => r,
                    Err(e) => {
                        ui::warn(&format!("Rebuild failed: {e}; waiting for next change..."));
                        continue;
                    }
                };
            if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result) {
                tracing::warn!("Guest agent check failed: {e}");
            }
            ui::success(&format!(
                "Build complete — revision {}",
                result.revision_hash
            ));

            // Re-parse volumes, ports and env vars for the fresh boot.
            let rt_cfg_watch = match config_path {
                Some(p) => image::parse_runtime_config(p).unwrap_or_default(),
                None => image::RuntimeConfig::default(),
            };
            let mut w_volume_cfg: Vec<image::RuntimeVolume> = Vec::new();
            let mut w_config_files: Vec<microvm::DriveFile> = Vec::new();
            let mut w_secret_files: Vec<microvm::DriveFile> = Vec::new();
            let w_merged_volumes = merge_volume_specs(volumes);
            if !w_merged_volumes.is_empty() {
                for v in &w_merged_volumes {
                    match parse_volume_spec(v) {
                        Ok(VolumeSpec::DirShare {
                            host_dir,
                            guest_mount,
                            ..
                        }) if guest_mount == "/mnt/config" => {
                            if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o444) {
                                w_config_files.extend(files);
                            }
                        }
                        Ok(VolumeSpec::DirShare {
                            host_dir,
                            guest_mount,
                            ..
                        }) if guest_mount == "/mnt/secrets" => {
                            if let Ok(files) = read_dir_to_drive_files(&host_dir, 0o400) {
                                w_secret_files.extend(files);
                            }
                        }
                        Ok(spec) => {
                            if let Ok(vmv) = vm_volume_from_spec_validated(&spec) {
                                w_volume_cfg.push(image::RuntimeVolume::from(&vmv));
                            }
                        }
                        Err(_) => {}
                    }
                }
            } else {
                w_volume_cfg = rt_cfg_watch.volumes.clone();
            }
            // Same egress-TLS staging on the watch-mode
            // rebuild path (cert → guest secrets drive, key → host sidecar).
            stage_egress_tls_delivery(&plan_secrets, tenant, &vm_name_owned, &mut w_secret_files)
                .context("staging per-VM egress TLS material (watch rebuild)")?;
            let w_port_mappings = parse_port_specs(ports).unwrap_or_default();
            if let Some(f) = ports_to_drive_file(&w_port_mappings) {
                w_config_files.push(f);
            }
            if let Some(f) = env_vars_to_drive_file(env_vars) {
                w_config_files.push(f);
            }
            let (w_verity_path, w_roothash) = microvm::probe_verity_sidecar(&result.rootfs_path);
            // Admission for the watch-mode rebuild path. The
            // shared `admission_ledger` provides replay protection across
            // rebuilds — a synthesized plan can only admit once even if
            // the same artifact hash recurs (nonce is fresh per call).
            let watch_admission = match admit_plan_for_boot(AdmitPlanForBootParams {
                tenant,
                vm_name: &vm_name_owned,
                backend_name: effective_hypervisor,
                rootfs_path: std::path::Path::new(&result.rootfs_path),
                precomputed_image_sha256: None,
                cpus: final_cpus,
                mem_mib: final_memory as u64,
                seccomp_tier: plan_seccomp_tier,
                secret_release: plan_secret_release,
                secrets: plan_secrets.clone(),
                no_supervisor,
                ledger: &admission_ledger,
                keys_dir: None,
                audit_dir: None,
                policy_dir: None,
                bundle_pin,
                deps_volume: deps_volume_binding.clone(),
                shares: shares_from_volume_cfg(&w_volume_cfg),
                redaction: redaction.clone(),
            }) {
                Ok(ctx) => ctx,
                Err(e) => {
                    ui::warn(&format!(
                        "Plan admission failed: {e}; waiting for next change..."
                    ));
                    continue;
                }
            };
            let mut w_start_config = VmStartParams {
                name: vm_name_owned.clone(),
                rootfs_path: result.rootfs_path,
                vmlinux_path: result.vmlinux_path,
                initrd_path: result.initrd_path,
                verity_path: w_verity_path,
                roothash: w_roothash,
                revision_hash: result.revision_hash,
                flake_ref: flake.to_string(),
                profile: profile.map(|s| s.to_string()),
                cpus: final_cpus,
                memory_mib: final_memory,
                mem_initial_mib: final_mem_initial,
                volumes: &w_volume_cfg,
                config_files: &w_config_files,
                secret_files: &w_secret_files,
                port_mappings: &w_port_mappings,
                // `--wait` is a one-shot workload; no warm-pool claim on this path.
                warm_pool_size: 0,
            }
            .into_start_config();
            // Attach the verity-sealed runtime overlay (Firecracker only, non-fatal).
            attach_runtime_overlay_if_cached(&mut w_start_config, effective_hypervisor);
            // Watch-loop re-boot uses its own fresh
            // admission (watch_admission); same substrate threading as the
            // main path. None → legacy supervisor path.
            if let Some(ctx) = watch_admission.as_ref() {
                populate_audit_substrate(
                    &mut w_start_config,
                    &ctx.admitted,
                    ctx.policy_bundle.as_ref(),
                )?;
                // Re-stash plan.json + bundle.json
                // for the Firecracker bridge sidecar on every watch-loop
                // re-boot; the prior admission's files are stale.
                stash_plan_for_bridge(&w_start_config)?;
            }
            enforce_shares_if(&watch_admission, &w_start_config.volumes)?;
            let w_backend = AnyBackend::from_hypervisor(effective_hypervisor);
            if let Err(e) = mvm_backend::workload_backend::require_workload_backend(&w_backend) {
                emit_failed_if(&watch_admission, "backend-start", &e);
                ui::warn(&format!(
                    "Could not start VM: {e}; waiting for next change..."
                ));
                continue;
            }
            if let Err(e) = w_backend.start(&w_start_config) {
                emit_failed_if(&watch_admission, "backend-start", &e);
                ui::warn(&format!(
                    "Could not start VM: {e}; waiting for next change..."
                ));
            } else {
                emit_launched_if(&watch_admission, effective_hypervisor);
                record_vm_readiness(&vm_name_owned, InstanceReadiness::LaunchAccepted);
                mvm_core::audit_emit!(VmStart, vm: &vm_name_owned);
                ui::success(&format!("VM '{}' rebooted.", vm_name_owned));
            }
        }
    }

    Ok(())
}

/// Attach the verity-sealed runtime overlay by
/// populating `VmStartConfig`'s overlay fields from the resolver's cache
/// probe. **Firecracker-only**: it's the sole backend that attaches the
/// overlay (a second virtio-blk + `mvm.runtime_roothash=` on the cmdline);
/// libkrun/Vz ignore the fields, so we skip them.
/// **Non-fatal**: a cold cache or a non-verity dev rootfs leaves the
/// fields `None` and the VM boots legacy. `resolve()` is a pure cache read
/// — no build, no download, no `nix` — so this is safe on every host.
fn attach_runtime_overlay(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
    resolver: &mvm_build::runtime_overlay::RuntimeOverlayResolver,
    arch: mvm_core::arch::GuestArch,
) {
    if hypervisor != "firecracker" {
        return;
    }
    match resolver.resolve(arch) {
        Ok(a) => {
            start_config.runtime_overlay_path = Some(a.overlay_ext4.display().to_string());
            start_config.runtime_overlay_verity_path = Some(a.sidecar.display().to_string());
            start_config.runtime_overlay_roothash = Some(a.roothash);
        }
        // Cold cache / dev rootfs / version drift — boot legacy, don't fail.
        Err(e) => tracing::debug!(error = %e, "runtime overlay not attached (firecracker)"),
    }
}

/// Kernel-less images (mkGuest ships no kernel) boot fine on libkrun,
/// which materializes its own bundled kernel and ignores this path. The
/// VZ-family backends need a real kernel file; fall back to the cached
/// builder-VM kernel (an ARM64 boot Image, the same kernel the Vz builder
/// and dev VMs boot) rather than handing VZ a missing path.
pub(super) fn resolve_vz_workload_kernel(
    vmlinux_path: &str,
    hypervisor: &str,
) -> anyhow::Result<String> {
    if std::path::Path::new(vmlinux_path).exists() {
        return Ok(vmlinux_path.to_string());
    }
    // `virtualization` is the long-form alias the backend dispatcher
    // accepts for vz; missing it here would skip the fallback and hand
    // VZ a nonexistent kernel path.
    if !matches!(hypervisor, "vz" | "virtualization") {
        return Ok(vmlinux_path.to_string());
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let fallback = format!(
        "{}/builder-vm/{arch}/vmlinux",
        mvm_core::config::mvm_cache_dir()
    );
    if std::path::Path::new(&fallback).exists() {
        return Ok(fallback);
    }
    anyhow::bail!(
        "image has no kernel ({vmlinux_path} missing) and the {hypervisor} backend \
         needs one; the builder-VM kernel fallback at {fallback} is also absent — \
         run `mvmctl dev up` once to bootstrap it"
    )
}

/// Production wrapper: build the resolver from the mvm cache dir + the
/// running mvmctl version, then attach for `hypervisor`. Called at each
/// workload-boot `VmStartConfig` construction in [`run`].
fn attach_runtime_overlay_if_cached(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    hypervisor: &str,
) {
    let resolver = mvm_build::runtime_overlay::RuntimeOverlayResolver::new(
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    attach_runtime_overlay(
        start_config,
        hypervisor,
        &resolver,
        mvm_core::arch::GuestArch::host(),
    );
}

#[cfg(test)]
mod runtime_overlay_attach_tests {
    use super::*;
    use mvm_build::runtime_overlay::RuntimeOverlayResolver;
    use mvm_core::arch::GuestArch;
    use mvm_core::vm_backend::VmStartConfig;

    /// Stage a complete overlay cache entry (the four files the resolver
    /// validates) in the layout `resolve` expects.
    fn seed_cache(cache: &std::path::Path, version: &str, arch: GuestArch) {
        let layout =
            RuntimeOverlayResolver::new(cache.to_path_buf(), version.to_string()).layout(arch);
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();
        std::fs::write(&layout.overlay_ext4, b"ext4-bytes").unwrap();
        std::fs::write(&layout.sidecar, b"verity-bytes").unwrap();
        std::fs::write(&layout.roothash_file, format!("{}\n", "a".repeat(64))).unwrap();
        std::fs::write(&layout.version_file, format!("{version}\n")).unwrap();
    }

    #[test]
    fn firecracker_with_cached_overlay_populates_all_three_fields() {
        let dir = tempfile::tempdir().unwrap();
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch);
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig::default();
        attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch);
        assert!(sc.runtime_overlay_path.is_some(), "ext4 path set");
        assert!(sc.runtime_overlay_verity_path.is_some(), "verity path set");
        assert_eq!(
            sc.runtime_overlay_roothash.as_deref(),
            Some("a".repeat(64).as_str())
        );
    }

    #[test]
    fn non_firecracker_backend_never_attaches() {
        let dir = tempfile::tempdir().unwrap();
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        seed_cache(dir.path(), ver, arch); // overlay IS cached…
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig::default();
        attach_runtime_overlay(&mut sc, "libkrun", &resolver, arch); // …but libkrun ignores it
        assert!(sc.runtime_overlay_path.is_none());
        assert!(sc.runtime_overlay_roothash.is_none());
    }

    #[test]
    fn firecracker_cold_cache_leaves_fields_unset_non_fatal() {
        let dir = tempfile::tempdir().unwrap(); // empty cache
        let ver = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let resolver = RuntimeOverlayResolver::new(dir.path().to_path_buf(), ver.to_string());
        let mut sc = VmStartConfig::default();
        attach_runtime_overlay(&mut sc, "firecracker", &resolver, arch);
        assert!(
            sc.runtime_overlay_path.is_none(),
            "cold cache must not attach (legacy boot)"
        );
    }
}

#[cfg(test)]
mod resolve_vz_workload_kernel_tests {
    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn existing_path_passes_through_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let vmlinux = tmp.path().join("vmlinux");
        std::fs::write(&vmlinux, b"kernel").unwrap();
        let result = resolve_vz_workload_kernel(vmlinux.to_str().unwrap(), "vz").unwrap();
        assert_eq!(result, vmlinux.to_str().unwrap());
    }

    #[test]
    fn non_vz_hypervisor_passes_through_even_when_missing() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MVM_CACHE_DIR", tmp.path()) };
        let result = resolve_vz_workload_kernel("/nonexistent/vmlinux", "libkrun").unwrap();
        assert_eq!(result, "/nonexistent/vmlinux");
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
    }

    #[test]
    fn vz_missing_kernel_falls_back_to_builder_vm_cache() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };
        let fallback_dir = tmp.path().join("builder-vm").join(arch);
        std::fs::create_dir_all(&fallback_dir).unwrap();
        let fallback = fallback_dir.join("vmlinux");
        std::fs::write(&fallback, b"builder-kernel").unwrap();
        unsafe { std::env::set_var("MVM_CACHE_DIR", tmp.path()) };
        let result = resolve_vz_workload_kernel("/nonexistent/vmlinux", "vz").unwrap();
        assert_eq!(result, fallback.to_str().unwrap());
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
    }

    #[test]
    fn vz_both_missing_returns_error_mentioning_dev_up() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MVM_CACHE_DIR", tmp.path()) };
        let err = resolve_vz_workload_kernel("/nonexistent/vmlinux", "vz").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dev up"), "expected 'dev up' in: {msg}");
        assert!(msg.contains("vz"), "expected hypervisor name in: {msg}");
        unsafe { std::env::remove_var("MVM_CACHE_DIR") };
    }
}

// ── admit_plan_for_boot tests ────────────────────────────
//
// These tests stay scoped to the helper rather than `cmd_run` itself
// because the dispatcher (`cmd_run`) calls into Lima/Firecracker
// backends that need a live host environment. `admit_plan_for_boot`
// is the bridge between CLI args and admission, so verifying it
// in isolation covers the contract the dispatcher depends on without
// pulling in `AnyBackend::from_hypervisor` startup.

#[cfg(test)]
mod admit_plan_tests {
    use super::*;
    use std::io::Write;

    fn write_rootfs(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join("rootfs.ext4");
        let mut f = std::fs::File::create(&path).expect("create rootfs");
        f.write_all(bytes).expect("write rootfs");
        path
    }

    /// Build a signed `.mvmpkg` archive in-memory so the
    /// `--bundle-pin` test path doesn't need a real fetched bundle.
    /// Uses mvm_plan's own writer + signing primitives.
    fn make_bundle_for_pin(sk: &ed25519_dalek::SigningKey) -> (Vec<u8>, mvm_core::plan::KeyId) {
        use mvm_core::plan::{
            ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, KeyId, sha256_hex,
            write_bundle,
        };
        let key_id = KeyId::from_pubkey(&sk.verifying_key());
        let kernel = b"kernel-bytes".to_vec();
        let rootfs = b"rootfs-bytes".to_vec();
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            publisher: "test".to_string(),
            key_id: key_id.clone(),
            arch: "aarch64".to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-05-13T00:00:00Z".to_string(),
            labels: Default::default(),
            artifacts: vec![
                BundleArtifact {
                    name: "vmlinux".to_string(),
                    role: ArtifactRole::Kernel,
                    path: "artifacts/vmlinux".to_string(),
                    sha256: sha256_hex(&kernel),
                    size_bytes: kernel.len() as u64,
                },
                BundleArtifact {
                    name: "rootfs.ext4".to_string(),
                    role: ArtifactRole::Rootfs,
                    path: "artifacts/rootfs.ext4".to_string(),
                    sha256: sha256_hex(&rootfs),
                    size_bytes: rootfs.len() as u64,
                },
            ],
            verity: None,
            resources: None,
        };
        let archive = write_bundle(
            &manifest,
            sk,
            vec![
                ("artifacts/vmlinux".to_string(), kernel),
                ("artifacts/rootfs.ext4".to_string(), rootfs),
            ],
        )
        .expect("write_bundle");
        (archive, key_id)
    }

    #[test]
    fn bundle_pin_from_archive_recovers_signature_and_sha() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let (archive, key_id) = make_bundle_for_pin(&sk);
        let pin = bundle_pin_from_archive(&archive, key_id.clone()).expect("recovers pin");
        assert_eq!(pin.bundle_sha256, mvm_core::plan::bundle_sha256(&archive));
        assert_eq!(pin.key_id, key_id);
        // Signature round-trips through base64 → bytes → verify.
        let sig_arr = pin.signature_bytes().expect("base64 decodes");
        assert_eq!(sig_arr.len(), 64);
    }

    #[test]
    fn bundle_pin_from_archive_missing_signature_errors() {
        // Bundle without a `manifest.sig` entry — built by hand so
        // the helper sees the gap. The function must bail with a
        // clear message rather than panic.
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut tar = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "manifest.json", std::io::Cursor::new(b""))
                .unwrap();
            tar.finish().unwrap();
        }
        let archive = buf.into_inner();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let key_id = mvm_core::plan::KeyId::from_pubkey(&sk.verifying_key());
        let err = bundle_pin_from_archive(&archive, key_id).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("manifest.sig"), "msg was: {msg}");
    }

    #[test]
    fn in_memory_bundle_resolver_returns_archive_bytes() {
        let bytes = b"hello-archive".to_vec();
        let resolver = InMemoryBundleResolver::new(bytes.clone());
        let out = mvm_core::plan::BundleResolver::resolve(&resolver, "anything").unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn no_supervisor_short_circuits_to_none() {
        // The escape hatch must skip admission entirely — no host
        // signer load, no rootfs hash, no nonce burn.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(dir.path(), b"unused");
        let ledger = InMemoryNonceLedger::new();
        let result = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-skip",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: true,
            ledger: &ledger,
            keys_dir: None, // not read — short-circuit returns first
            audit_dir: None,
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .expect("must succeed");
        assert!(result.is_none(), "no_supervisor must return None");
    }

    #[test]
    fn admits_real_rootfs_and_returns_plan_id() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-happy",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Network,
            secret_release: mvm_core::plan::SecretReleasePolicy::PlanBound,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .expect("admission")
        .expect("Some when admission ran");
        assert!(!ctx.admitted.plan_id.0.is_empty());
        assert_eq!(ctx.admitted.plan.workload.0, "vm-happy");
        assert_eq!(ctx.admitted.plan.tenant.0, "local");
        assert_eq!(ctx.admitted.plan.resources.cpus, 2);
        assert_eq!(ctx.admitted.plan.resources.mem_mib, 512);
        assert_eq!(
            ctx.admitted.plan.admission_profile.seccomp_tier,
            mvm_core::plan::PlanSeccompTier::Network
        );
        assert_eq!(
            ctx.admitted.plan.admission_profile.secret_release,
            mvm_core::plan::SecretReleasePolicy::PlanBound
        );

        // The `plan.admitted` audit line must be present in the
        // tenant's chain file already (admit_plan_for_boot emits
        // it inline before returning).
        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.admitted"));
        assert!(content.contains(&ctx.admitted.plan_id.0));
    }

    #[test]
    fn admission_failure_when_rootfs_missing() {
        // sha256_file fails when the file does not exist; the helper
        // must propagate the error with context naming the rootfs path.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();
        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-missing",
            backend_name: "firecracker",
            rootfs_path: std::path::Path::new("/nonexistent/rootfs.ext4"),
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .expect_err("missing rootfs must fail");
        assert!(
            err.chain().any(|e| e.to_string().contains("rootfs")),
            "error must name rootfs: {err}"
        );
    }

    #[test]
    fn two_admissions_in_same_run_produce_distinct_plan_ids() {
        // The shared ledger is the per-`cmd_run` replay-store. Two
        // admissions with different rootfs hashes (or even same hash —
        // synthesize_plan generates fresh nonces) must both succeed.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"first");
        let ledger = InMemoryNonceLedger::new();

        let a1 = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-1",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .unwrap()
        .unwrap();
        let a2 = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-2",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .unwrap()
        .unwrap();
        assert_ne!(a1.admitted.plan_id, a2.admitted.plan_id);
        assert_ne!(a1.admitted.plan.nonce, a2.admitted.plan.nonce);
    }

    #[test]
    fn emit_launched_and_failed_no_op_when_admission_skipped() {
        // emit_*_if must be a no-op when admission was skipped — the
        // legacy --no-supervisor path must not panic or write audit
        // lines.
        let none: Option<AdmissionContext> = None;
        emit_launched_if(&none, "firecracker");
        emit_failed_if(
            &none,
            "backend-start",
            &anyhow::anyhow!("simulated failure"),
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Policy resolver wired into admission
    //
    // The default synthesized plan ships `local-default` policy refs,
    // so the happy-path admission must succeed and emit
    // `plan.policy_resolved` with `slots_mode="noop"`. Tests that
    // need to exercise the resolver-failure path manually stage a
    // bogus bundle into a tempdir + drive admission with a plan
    // whose refs name that tenant. Tests use the existing
    // `policy_dir` test seam so they can stage / omit bundles
    // deterministically.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn admission_emits_policy_resolved_for_default_local_default_refs() {
        // The synthesized plan defaults to `local-default` on every
        // ref; the resolver returns Noop slots. The hook must
        // emit `plan.policy_resolved` with mode=noop.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"local-default-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-local-default",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: Some(policy_dir.path()),
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.admitted"));
        assert!(
            content.contains("plan.policy_resolved"),
            "audit chain must include plan.policy_resolved: {content}"
        );
        assert!(
            content.contains("\"slots_mode\":\"noop\""),
            "audit chain must record slots_mode=noop for local-default refs: {content}"
        );
        // Sanity: plan_id matches.
        assert!(content.contains(&ctx.admitted.plan_id.0));
    }

    #[test]
    fn admission_emits_policy_resolved_live_when_bundle_parses() {
        // Manually stage a bundle whose tenant matches the synthesized
        // plan's tenant. We can't trivially make the synthesizer emit
        // `<tenant>:<workload>` refs (the plan_builder hard-codes
        // `local-default`), so this test exercises the audit-mode
        // branch via `resolve_policy_for_admission` directly with an
        // ExecutionPlan we mutate post-synthesis.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();

        // Stage a parseable bundle the live path will consume.
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-live.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-live"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = true
"#,
        )
        .unwrap();

        // Synthesize a default-refs plan, then rewrite the four
        // policy fields to `acme:vm-live`. The resolver requires
        // all four to agree on the same ref.
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"live-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-live",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-live",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:vm-live".to_string());
        plan.egress_policy = PolicyRef("acme:vm-live".to_string());
        plan.tool_policy = PolicyRef("acme:vm-live".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-live".to_string());

        // Resolve policy, then construct the policy-derived emitter
        // and emit the hook. This mirrors `admit_plan_for_boot`'s
        // ordering: the `[audit]` section affects the success-path
        // audit emitter.
        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("live bundle must resolve");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = build_policy_audit_emitter(
            signer.signing,
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        )
        .unwrap();
        emit_policy_resolved(&plan, &emitter, resolved.slots_mode);

        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"slots_mode\":\"live\""),
            "audit chain must record slots_mode=live for tenant-scoped refs: {content}"
        );
    }

    #[test]
    fn admission_uses_bundle_audit_file_destination() {
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let stream_dir = tempfile::tempdir().unwrap();
        let stream_path = stream_dir.path().join("acme-audit.jsonl");
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-stream.toml"),
            format!(
                r#"
schema_version = 1
bundle_id      = "acme/vm-stream"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = true
stream_destinations = ["file://{}"]
"#,
                stream_path.display()
            ),
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"stream-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-stream",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-stream",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:vm-stream".to_string());
        plan.egress_policy = PolicyRef("acme:vm-stream".to_string());
        plan.tool_policy = PolicyRef("acme:vm-stream".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-stream".to_string());

        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("stream bundle resolves");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let vk = signer.signing.verifying_key();
        let emitter = build_policy_audit_emitter(
            signer.signing,
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        )
        .unwrap();
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emit_policy_resolved(&plan, &emitter, resolved.slots_mode);

        let default_path = audit_dir.path().join("acme.jsonl");
        let default_content = std::fs::read_to_string(&default_path).unwrap();
        let stream_content = std::fs::read_to_string(&stream_path).unwrap();
        assert!(default_content.contains("plan.admitted"));
        assert!(stream_content.contains("plan.admitted"));
        assert_eq!(
            mvm_hostd::supervisor::verify_audit_chain(&default_path, &vk).unwrap(),
            2
        );
        assert_eq!(
            mvm_hostd::supervisor::verify_audit_chain(&stream_path, &vk).unwrap(),
            2
        );
    }

    #[test]
    fn admission_audits_rejected_unsigned_policy_audit() {
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-unsigned-audit.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-unsigned-audit"
bundle_version = 1

[network]
[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
chain_signing = false
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unsigned-audit-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-unsigned-audit",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-unsigned-audit",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.egress_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.tool_policy = PolicyRef("acme:vm-unsigned-audit".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-unsigned-audit".to_string());

        let resolved = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect("bundle shape still resolves");
        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let err = match build_policy_audit_emitter(
            signer.signing.clone(),
            Some(audit_dir.path()),
            resolved.audit.as_ref(),
        ) {
            Ok(_) => panic!("chain_signing=false must reject admission audit construction"),
            Err(err) => err.context("opening audit chain emitter"),
        };
        let fallback = build_default_audit_emitter(signer.signing, Some(audit_dir.path())).unwrap();
        emit_policy_audit_invalid(&plan, &fallback, &err);

        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(content.contains("plan.failed"));
        assert!(content.contains("policy-audit-invalid"));
        assert!(content.contains("chain_signing"));
    }

    #[test]
    fn admission_fails_when_policy_bundle_missing() {
        // A plan whose refs name `acme:nope` but no bundle exists on
        // disk must fail admission with a typed `policy-bundle-not-found`
        // error and emit `plan.failed` with that class.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"missing-bundle-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-nope",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-nope",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:nope".to_string());
        plan.egress_policy = PolicyRef("acme:nope".to_string());
        plan.tool_policy = PolicyRef("acme:nope".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:nope".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("missing bundle must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("acme") && msg.contains("nope"),
            "error must name the missing bundle: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-bundle-not-found\""),
            "audit chain must classify the failure: {content}"
        );
    }

    #[test]
    fn admission_fails_when_policy_bundle_has_unknown_disabled_inspector() {
        // Tightening regression: an `[egress].disabled_inspectors`
        // typo must fail admission with
        // `error_class=policy-egress-invalid` rather than silently
        // booting with the inspector still enforced.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-typo.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-typo"
bundle_version = 1

[network]
[egress]
disabled_inspectors = ["ssrf_guarrd"]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"typo-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-typo",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-typo",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:vm-typo".to_string());
        plan.egress_policy = PolicyRef("acme:vm-typo".to_string());
        plan.tool_policy = PolicyRef("acme:vm-typo".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-typo".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("typo must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ssrf_guarrd"),
            "error must name the typo: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-egress-invalid\""),
            "audit chain must classify the failure: {content}"
        );
    }

    #[test]
    fn admission_fails_when_policy_bundle_has_bad_l4_cidr() {
        // A bundle that parses through TOML but carries an
        // unparseable `dst_cidr` must fail admission with
        // `policy-l4-spec-invalid`. Same hermetic shape as the
        // missing-bundle test.
        use mvm_core::plan::PolicyRef;
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let policy_dir = tempfile::tempdir().unwrap();
        let tenant_dir = policy_dir.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(
            tenant_dir.join("vm-bad.toml"),
            r#"
schema_version = 1
bundle_id      = "acme/vm-bad"
bundle_version = 1

[network]

[[network.l4]]
proto    = "tcp"
dst_cidr = "not-a-cidr"
port_lo  = 443
port_hi  = 443

[egress]
[pii]
[tool]
[artifact]
[keys]
[audit]
"#,
        )
        .unwrap();

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"bad-cidr-payload");
        let ledger = InMemoryNonceLedger::new();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let mut plan = admit_for_run(
            &SynthesisInput {
                vm_name: "vm-bad",
                tenant: Some("acme"),
                backend_name: "firecracker",
                image_name: "vm-bad",
                image_sha256: &sha,
                image_cosign_bundle: None,
                intent: None,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                network_policy_ref: None,
                fs_policy_ref: None,
                egress_policy_ref: None,
                tool_policy_ref: None,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                audit_event_prefix: None,
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                boot_timeout_secs: 60,
                exec_timeout_secs: 0,
                destroy_on_exit: true,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                audit_labels: Default::default(),
            },
            &SystemClock,
            &ledger,
            Some(keys_dir.path()),
            None,
        )
        .expect("admit")
        .plan;
        plan.network_policy = PolicyRef("acme:vm-bad".to_string());
        plan.egress_policy = PolicyRef("acme:vm-bad".to_string());
        plan.tool_policy = PolicyRef("acme:vm-bad".to_string());
        plan.fs_policy = mvm_core::plan::FsPolicyRef("acme:vm-bad".to_string());

        let err = resolve_policy_for_admission(&plan, Some(policy_dir.path()))
            .expect_err("bad CIDR must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not-a-cidr"),
            "error must name the bad CIDR: {msg}"
        );

        let signer = load_or_init_at(keys_dir.path()).expect("signer");
        let emitter = AuditEmitter::with_dir(signer.signing, audit_dir.path()).unwrap();
        emit_policy_resolve_failure(&plan, &emitter, &err);
        let audit_path = audit_dir.path().join("acme.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("\"error_class\":\"policy-l4-spec-invalid\""),
            "audit chain must classify the failure: {content}"
        );
    }
}

// `resolve_deps_volume_binding` unit tests.
//
// These cover the helper that turns a Workload IR + a build-mode
// flag into an `Option<DepsVolumeBinding>` for plan synthesis. The
// cache-miss path (which would dispatch the libkrun builder VM)
// surfaces as `DriverNotProvided` ("mvmctl
// up consumes a cached volume; mvmctl deps build is the verb that
// drives the cache-miss path"); cache-hit fixtures use the same
// `seal_volume` primitives as `mvm-build/tests/app_deps_orchestrator.rs`
// so the wire format stays pinned.
#[cfg(test)]
mod resolve_deps_volume_tests {
    use super::*;
    use mvm_sdk::compile::deps_audit::{
        FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, seal_volume,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    /// Build a workload-IR JSON file with the supplied `dependencies`
    /// shape. Returns the path the test should pass to
    /// `resolve_deps_volume_binding`.
    fn write_workload_ir(
        dir: &Path,
        deps: Option<serde_json::Value>,
        source_path: &str,
    ) -> std::path::PathBuf {
        let mut app = serde_json::json!({
            "name": "app1",
            "source": { "kind": "local_path", "path": source_path },
            "image": { "kind": "nix_packages", "packages": ["python3"] },
            "entrypoints": [
                { "kind": "command", "command": ["/bin/true"] }
            ],
            "resources": { "memory_mb": 256, "cpu_cores": 1, "rootfs_size_mb": 512 }
        });
        if let Some(d) = deps {
            app["dependencies"] = d;
        }
        let workload = serde_json::json!({
            "schema_version": "0.1.0",
            "id": "test-workload",
            "apps": [app]
        });
        let path = dir.join("workload.ir.json");
        std::fs::write(&path, serde_json::to_string_pretty(&workload).unwrap()).unwrap();
        path
    }

    /// Seal a deps volume into `cache_root/<volume_hash>/` and write
    /// the index pointer so a subsequent `install_app_deps` call
    /// returns `cache_hit = true`. Mirrors `seal_into_cache` in
    /// `crates/mvm-build/tests/app_deps_orchestrator.rs`.
    fn seal_volume_into_cache(
        cache_root: &Path,
        lockfile_path: &Path,
        sbom_body: &[u8],
        cve_body: &[u8],
    ) -> String {
        let scratch = cache_root.join("scratch");
        let content_dir = scratch.join(FILE_CONTENT_DIR);
        std::fs::create_dir_all(&content_dir).unwrap();
        std::fs::write(content_dir.join("placeholder"), b"installed\n").unwrap();
        let sbom = scratch.join(FILE_SBOM);
        std::fs::write(&sbom, sbom_body).unwrap();
        let fetch_log = scratch.join(FILE_FETCH_LOG);
        std::fs::write(&fetch_log, b"GET https://pypi.org/x\n").unwrap();
        let cve = scratch.join(FILE_CVE);
        std::fs::write(&cve, cve_body).unwrap();

        let sealed = seal_volume(
            &content_dir,
            &sbom,
            &fetch_log,
            &cve,
            "2026-05-14T00:00:00Z",
            BTreeMap::new(),
        )
        .expect("seal");
        let final_dir = cache_root.join(&sealed.volume_hash);
        std::fs::rename(&scratch, &final_dir).unwrap();
        std::fs::write(final_dir.join(FILE_MANIFEST), &sealed.manifest_bytes).unwrap();

        // Index pointer.
        let lockfile_bytes = std::fs::read(lockfile_path).unwrap();
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&lockfile_bytes);
        let mut lock_sha = String::new();
        for b in h.finalize() {
            lock_sha.push_str(&format!("{b:02x}"));
        }
        let lockfile_hash = mvm_build::app_deps::derive_lockfile_hash(
            &lock_sha,
            mvm_build::app_deps::Language::Python,
            mvm_build::app_deps::GateLevel::Prod,
        );
        let index = cache_root.join("index");
        std::fs::create_dir_all(&index).unwrap();
        std::fs::write(index.join(&lockfile_hash), &sealed.volume_hash).unwrap();
        sealed.volume_hash
    }

    const REAL_SBOM: &[u8] =
        br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"requests"}]}"#;
    const REAL_CVE: &[u8] = br#"{"results":[],"dependencies":[],"summary":{"fixed":0}}"#;

    #[test]
    fn no_workload_ir_returns_none() {
        // Claim-8 preservation: `mvmctl up` without `--from-workload-ir`
        // never touches the deps cache and produces a plan whose
        // `deps_volume` is `None`.
        let binding =
            resolve_deps_volume_binding(None, mvm_build::pipeline::BuildMode::Prod).unwrap();
        assert!(binding.is_none());
    }

    #[test]
    fn qemu_threads_signed_plan_for_substitution_endpoint() {
        // The QEMU per-VM substitution endpoint reads config.plan_json /
        // tenant_id to spawn when the plan carries secrets — it must be threaded
        // even with the libkrun/Vz gateway bridge off (the default).
        assert!(should_thread_signed_plan(false, "qemu"));
        assert!(should_thread_signed_plan(true, "qemu"));
    }

    #[test]
    fn libkrun_threads_signed_plan_only_under_gateway_bridge_flag() {
        // libkrun/Vz branch into the (not-yet-working) bridge factory on
        // plan_json presence, so the default keeps them on the legacy path.
        assert!(!should_thread_signed_plan(false, "libkrun"));
        assert!(!should_thread_signed_plan(false, "vz"));
        assert!(should_thread_signed_plan(true, "libkrun"));
    }

    #[test]
    fn direct_boot_detach_without_ports_skips_agent_wait() {
        assert!(!should_wait_for_direct_boot_agent(true, None));
        assert!(!should_wait_for_direct_boot_agent(true, Some("")));
    }

    #[test]
    fn direct_boot_waits_for_foreground_or_ports() {
        assert!(should_wait_for_direct_boot_agent(false, None));
        assert!(should_wait_for_direct_boot_agent(false, Some("")));
        assert!(should_wait_for_direct_boot_agent(true, Some("8080:80")));
    }

    #[test]
    fn explicit_from_workload_ir_wins() {
        let p = std::path::Path::new("/some/explicit/ir.json");
        let got = resolve_workload_ir_path(Some(p), Some("/ignored/flake/dir"));
        assert_eq!(got.as_deref(), Some(p));
    }

    #[test]
    fn discovers_workload_json_in_compiled_flake_dir() {
        // A `mvmctl compile` artifact carries `workload.json`; `up --flake <dir>`
        // must default to it so managed secrets are lowered without the flag.
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("artifact");
        std::fs::create_dir_all(&flake).unwrap();
        let ir = flake.join("workload.json");
        std::fs::write(&ir, "{}").unwrap();
        let got = resolve_workload_ir_path(None, flake.to_str());
        assert_eq!(got.as_deref(), Some(ir.as_path()));
    }

    #[test]
    fn plain_flake_without_workload_json_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        let flake = tmp.path().join("plain");
        std::fs::create_dir_all(&flake).unwrap();
        assert!(resolve_workload_ir_path(None, flake.to_str()).is_none());
        // A remote/attr flake ref is not a local dir → None, no panic.
        assert!(resolve_workload_ir_path(None, Some("github:foo/bar#worker")).is_none());
        assert!(resolve_workload_ir_path(None, None).is_none());
    }

    #[test]
    fn workload_ir_without_dependencies_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let ir = write_workload_ir(tmp.path(), None, project.to_str().unwrap());
        let binding =
            resolve_deps_volume_binding(Some(&ir), mvm_build::pipeline::BuildMode::Prod).unwrap();
        assert!(binding.is_none());
    }

    #[test]
    fn workload_ir_with_dependencies_none_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let ir = write_workload_ir(
            tmp.path(),
            Some(serde_json::json!({ "kind": "none" })),
            project.to_str().unwrap(),
        );
        let binding =
            resolve_deps_volume_binding(Some(&ir), mvm_build::pipeline::BuildMode::Prod).unwrap();
        assert!(binding.is_none());
    }

    #[test]
    fn workload_ir_with_python_lockfile_cache_hit_returns_binding() {
        // Happy path: workload declares a
        // `Dependencies::Python` with a lockfile; the cache already
        // holds a sealed volume; resolve_deps_volume_binding produces
        // a `DepsVolumeBinding` whose hashes match the seal result.
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("uv.lock"),
            b"version = 1\n[[package]]\nname = \"requests\"\n",
        )
        .unwrap();

        let ir = write_workload_ir(
            tmp.path(),
            Some(serde_json::json!({
                "kind": "python",
                "lockfile": "uv.lock",
                "tool": "uv"
            })),
            project.to_str().unwrap(),
        );

        // Per-test cache root keeps parallel `cargo test` from
        // racing on `~/.mvm/volumes/deps/` or a shared env var.
        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();
        let volume_hash =
            seal_volume_into_cache(&cache_root, &project.join("uv.lock"), REAL_SBOM, REAL_CVE);

        let binding = resolve_deps_volume_binding_with_cache(
            Some(&ir),
            mvm_build::pipeline::BuildMode::Prod,
            Some(&cache_root),
        )
        .expect("cache hit + clean prod gate")
        .expect("Some when IR carries Python deps");
        assert_eq!(binding.volume_hash, volume_hash);
    }

    #[test]
    fn workload_ir_with_python_lockfile_cache_miss_surfaces_typed_error() {
        // Cache miss under `mvmctl up` is currently a hard error
        // pointing at `mvmctl deps build`. The error
        // message must mention that verb so the user knows how to
        // proceed.
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("uv.lock"), b"unique-bytes-12345\n").unwrap();

        let ir = write_workload_ir(
            tmp.path(),
            Some(serde_json::json!({
                "kind": "python",
                "lockfile": "uv.lock",
                "tool": "uv"
            })),
            project.to_str().unwrap(),
        );

        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();

        let err = resolve_deps_volume_binding_with_cache(
            Some(&ir),
            mvm_build::pipeline::BuildMode::Prod,
            Some(&cache_root),
        )
        .expect_err("must fail on cache miss");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mvmctl deps build"),
            "miss diagnostic must point at the C verb: {msg}"
        );
    }

    #[test]
    fn workload_ir_prod_gate_rejects_stub_sbom() {
        // Cache holds a sealed volume whose SBOM is the documented
        // empty-tool stub — `cyclonedx-py` wasn't on the builder VM
        // PATH. `--prod` (the default for `mvmctl up`) must refuse.
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("uv.lock"), b"some-stub-lockfile\n").unwrap();

        let ir = write_workload_ir(
            tmp.path(),
            Some(serde_json::json!({
                "kind": "python",
                "lockfile": "uv.lock",
                "tool": "uv"
            })),
            project.to_str().unwrap(),
        );

        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();
        let stub_sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
        let _ = seal_volume_into_cache(&cache_root, &project.join("uv.lock"), stub_sbom, REAL_CVE);

        let err = resolve_deps_volume_binding_with_cache(
            Some(&ir),
            mvm_build::pipeline::BuildMode::Prod,
            Some(&cache_root),
        )
        .expect_err("stub SBOM must fail prod gate");
        let chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
        assert!(
            chain
                .iter()
                .any(|s| s.contains("empty-tool stub") || s.contains("SBOM")),
            "error chain must mention SBOM stub: {chain:?}"
        );
    }

    #[test]
    fn workload_ir_dev_gate_warns_and_returns_binding_for_stub_sbom() {
        // Same stub-SBOM scenario, but `--dev`: the helper logs a
        // warning and returns the binding. The plan synthesizer
        // gets `Some(...)` and the supervisor's admit gate verifies
        // the on-disk volume the normal way.
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("uv.lock"), b"dev-stub-lockfile\n").unwrap();

        let ir = write_workload_ir(
            tmp.path(),
            Some(serde_json::json!({
                "kind": "python",
                "lockfile": "uv.lock",
                "tool": "uv"
            })),
            project.to_str().unwrap(),
        );

        let cache_root = tmp.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();

        // Re-seal the cache under the *dev* lockfile_hash variant.
        let scratch = cache_root.join("dev-scratch");
        let content_dir = scratch.join(FILE_CONTENT_DIR);
        std::fs::create_dir_all(&content_dir).unwrap();
        std::fs::write(content_dir.join("placeholder"), b"installed\n").unwrap();
        let sbom = scratch.join(FILE_SBOM);
        std::fs::write(
            &sbom,
            br#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let fetch_log = scratch.join(FILE_FETCH_LOG);
        std::fs::write(&fetch_log, b"").unwrap();
        let cve = scratch.join(FILE_CVE);
        std::fs::write(&cve, REAL_CVE).unwrap();
        let sealed = seal_volume(
            &content_dir,
            &sbom,
            &fetch_log,
            &cve,
            "2026-05-14T00:00:00Z",
            BTreeMap::new(),
        )
        .unwrap();
        let final_dir = cache_root.join(&sealed.volume_hash);
        std::fs::rename(&scratch, &final_dir).unwrap();
        std::fs::write(final_dir.join(FILE_MANIFEST), &sealed.manifest_bytes).unwrap();
        let lockfile_bytes = std::fs::read(project.join("uv.lock")).unwrap();
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&lockfile_bytes);
        let mut lock_sha = String::new();
        for b in h.finalize() {
            lock_sha.push_str(&format!("{b:02x}"));
        }
        let lockfile_hash = mvm_build::app_deps::derive_lockfile_hash(
            &lock_sha,
            mvm_build::app_deps::Language::Python,
            mvm_build::app_deps::GateLevel::Dev,
        );
        let index = cache_root.join("index");
        std::fs::create_dir_all(&index).unwrap();
        std::fs::write(index.join(&lockfile_hash), &sealed.volume_hash).unwrap();

        let binding = resolve_deps_volume_binding_with_cache(
            Some(&ir),
            mvm_build::pipeline::BuildMode::Dev,
            Some(&cache_root),
        )
        .expect("dev gate warns + returns Ok")
        .expect("Some when IR carries Python deps");
        assert_eq!(binding.volume_hash, sealed.volume_hash);
    }

    #[test]
    fn workload_ir_with_unparseable_json_propagates_error() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("garbage.ir.json");
        std::fs::write(&bad, b"this is not json").unwrap();
        let err = resolve_deps_volume_binding(Some(&bad), mvm_build::pipeline::BuildMode::Prod)
            .expect_err("must fail on bad JSON");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("parsing workload IR"),
            "error must mention parsing: {msg}"
        );
    }

    #[test]
    fn workload_ir_non_local_path_source_rejected() {
        // `Source::OciImage` doesn't carry a host-resolvable
        // source root for the install pipeline. Surface a clear
        // error rather than silently failing later.
        let tmp = tempfile::tempdir().unwrap();
        let workload = serde_json::json!({
            "schema_version": "0.1.0",
            "id": "oci-workload",
            "apps": [{
                "name": "app1",
                "source": {
                    "kind": "oci_image",
                    "reference": "library/python:3.12",
                    "digest": "sha256:abc"
                },
                "image": { "kind": "nix_packages", "packages": ["python3"] },
                "entrypoints": [{ "kind": "command", "command": ["/bin/true"] }],
                "resources": { "memory_mb": 256, "cpu_cores": 1, "rootfs_size_mb": 512 },
                "dependencies": { "kind": "python", "lockfile": "uv.lock", "tool": "uv" }
            }]
        });
        let path = tmp.path().join("workload.ir.json");
        std::fs::write(&path, serde_json::to_string_pretty(&workload).unwrap()).unwrap();
        let err = resolve_deps_volume_binding(Some(&path), mvm_build::pipeline::BuildMode::Prod)
            .expect_err("non-local source must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Source::LocalPath") || msg.contains("LocalPath"),
            "error must name the unsupported source kind: {msg}"
        );
    }

    // ── egress-TLS staging splits cert ↔ key ──

    #[test]
    fn stage_egress_tls_delivery_noop_without_secrets() {
        // No secrets ⇒ no https leg, nothing staged.
        let mut secret_files: Vec<microvm::DriveFile> = Vec::new();
        stage_egress_tls_delivery(&[], "local", "vm-no-secrets", &mut secret_files).unwrap();
        assert!(secret_files.is_empty());
    }

    #[test]
    fn stage_egress_tls_delivery_splits_cert_to_guest_key_to_host() {
        use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
        use std::os::unix::fs::PermissionsExt;

        // MVM_DATA_DIR isolates the binding store, egress CA, and VM state dir.
        // Process-per-test under nextest already isolates env; the shared
        // guard keeps plain `cargo test` (shared process) safe.
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_DATA_DIR", tmp.path());

        // Record the egress binding the helper resolves bound hosts from.
        FileBindingStore::default_location()
            .unwrap()
            .put(
                "local",
                "OPENAI_API_KEY",
                &SecretBindingMeta {
                    auth_type: mvm_sdk::ir::AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                    sigv4: None,
                },
            )
            .unwrap();

        let plan_secrets = vec![mvm_core::plan::SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: mvm_core::plan::SecretSource::Keystore {
                address: "openai".into(),
            },
        }];
        let mut secret_files: Vec<microvm::DriveFile> = Vec::new();
        stage_egress_tls_delivery(&plan_secrets, "local", "vm-secret", &mut secret_files).unwrap();

        // The guest got exactly the cert — never the key.
        assert_eq!(secret_files.len(), 1);
        let cert_file = &secret_files[0];
        assert_eq!(cert_file.name, mvm_backend::EGRESS_CERT_DRIVE_NAME);
        assert!(cert_file.content.contains("BEGIN CERTIFICATE"));
        assert!(
            !cert_file.content.contains("PRIVATE KEY"),
            "intermediate key leaked into the guest cert file"
        );

        // The host-only intermediate sidecar holds the key at mode 0600.
        let inter = mvm_core::config::vm_state_dir("vm-secret").join("egress-intermediate.json");
        let meta = std::fs::metadata(&inter).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&inter).unwrap()).unwrap();
        assert!(v["key_pem"].as_str().unwrap().contains("PRIVATE KEY"));
        // The guest must trust exactly the cert the endpoint terminates under.
        assert_eq!(
            v["cert_pem"].as_str().unwrap().trim(),
            cert_file.content.trim()
        );
    }
}
