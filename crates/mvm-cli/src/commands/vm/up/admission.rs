//! Signed `ExecutionPlan` admission for `mvmctl up` — synthesize, sign,
//! verify, and audit-emit the plan right before a backend `start()`, plus
//! the guest boot-config attachments (host-signer pubkey, security policy)
//! that ride along with an admitted plan.

use anyhow::{Context, Result, bail};

use mvm_core::plan::SynthesisInput;
use mvm_core::policy::PolicyBundle;
use mvm_core::security::{AgentProfile, SecurityPolicy};
use mvm_hostd::plan_admission::{
    AdmittedPlan, BundleAdmissionContext, InMemoryNonceLedger, SystemClock, admit_for_run,
};

use crate::commands::vm::audit_chain::AuditEmitter;
use crate::commands::vm::host_signer::{PUBLIC_FILENAME, load_or_init_at};
use crate::commands::vm::policy_resolver::{
    LOCAL_DEFAULT, resolve_policy_bundle, resolve_policy_bundle_with_dir,
    resolve_supervisor_components, resolve_supervisor_components_with_dir,
};

use super::audit::{
    build_default_audit_emitter, build_policy_audit_emitter, emit_policy_audit_invalid,
    emit_policy_resolve_failure, emit_policy_resolved,
};
use super::policy::{
    InMemoryBundleResolver, bundle_pin_from_archive, generated_policy_bundle_for_network_policy,
};

pub(in crate::commands::vm) const SECURITY_POLICY_FILENAME: &str = "security-policy.json";

pub(in crate::commands::vm) struct AdmitPlanForBootParams<'a> {
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
    /// The resolved runtime egress policy (`--network-preset`,
    /// `--network-allow`, template default, or deny-all default). Non-deny
    /// policies are lowered into a generated PolicyBundle and referenced by the
    /// signed plan so the bridge never relies on an unsigned bare carrier to
    /// authorize outbound traffic.
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
    pub services: Vec<mvm_protocol::protocol::broker::ServiceId>,
    /// True iff this run should receive an attenuated (ProdSafe-only) agent-verb
    /// grant. Set this with `grant_eligible(pty, has_ad_hoc_argv, is_dev_profile)`.
    /// Interactive / ad-hoc / dev runs must pass `false`: they issue DevOnly verbs
    /// (ConsoleOpen, Exec) that a ProdSafe grant would refuse.
    pub restrict_agent_verbs: bool,
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
pub(in crate::commands::vm) struct AdmissionContext {
    pub(in crate::commands::vm) admitted: AdmittedPlan,
    pub(in crate::commands::vm) emitter: AuditEmitter,
    /// The resolved tenant `PolicyBundle` (Slice 3 (b)) the bridge enforces
    /// per-tenant L4 egress against; `None` for a local-default plan.
    pub(in crate::commands::vm) policy_bundle: Option<PolicyBundle>,
    pub(in crate::commands::vm) host_signer_public_path: std::path::PathBuf,
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
pub(in crate::commands::vm) fn admit_plan_for_boot(
    p: AdmitPlanForBootParams<'_>,
) -> Result<Option<AdmissionContext>> {
    if p.no_supervisor {
        return Ok(None);
    }
    let sha = resolve_image_sha256(p.rootfs_path, p.precomputed_image_sha256)?;

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

    let generated_network_policy_bundle =
        generated_policy_bundle_for_network_policy(p.tenant, p.vm_name, &p.network_policy)?;
    let generated_policy_ref = generated_network_policy_bundle
        .as_ref()
        .map(|(policy_ref, _)| policy_ref.as_str());

    let input = SynthesisInput {
        kernel_sha256: None,
        network_mode: Default::default(),
        l3_network: None,
        vm_name: p.vm_name,
        tenant: Some(p.tenant),
        backend_name: p.backend_name,
        image_name: p.vm_name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: p.seccomp_tier,
        network_policy_ref: generated_policy_ref,
        fs_policy_ref: generated_policy_ref,
        egress_policy_ref: generated_policy_ref,
        tool_policy_ref: generated_policy_ref,
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
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: crate::commands::vm::agent_verbs::parse_agent_verb_override(
            &p.agent_verb_override,
        )?
        .or_else(|| {
            crate::commands::vm::agent_verbs::default_agent_verbs(
                p.restrict_agent_verbs,
                !p.shares.is_empty(),
            )
        }),
        services: p.services.clone(),
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
        None => crate::commands::vm::host_signer::load_or_init(),
    }
    .context("loading host signer for audit emitter")?;

    // Resolve policy before constructing the final emitter so
    // `[audit]` can control chain-signing and stream replication for
    // every success-path audit record. If policy resolution itself
    // fails, fall back to the default local chain for the failure
    // record so the rejection is still visible.
    let generated_bundle = generated_network_policy_bundle.map(|(_, bundle)| bundle);
    let resolved = if let Some(bundle) = generated_bundle.as_ref() {
        // The signed plan refs point at this generated in-memory bundle. Validate
        // the L4 rows before using its audit policy; the bundle is then threaded
        // to the bridge as `bundle_json`, so the signed plan path, not the bare
        // VmStartConfig carrier, authorizes the allow-list.
        if let Err(err) = mvm_core::policy::canonicalize_l4(&bundle.network.l4)
            .context("validating generated signed network policy")
        {
            let fallback = build_default_audit_emitter(signer.signing, p.audit_dir)
                .context("opening fallback audit chain emitter")?;
            emit_policy_resolve_failure(&admitted.plan, &fallback, &err);
            return Err(err);
        }
        PolicyAdmissionResolution {
            slots_mode: "live",
            audit: Some(bundle.audit.clone()),
        }
    } else {
        match resolve_policy_for_admission(&admitted.plan, p.policy_dir) {
            Ok(resolved) => resolved,
            Err(err) => {
                let fallback = build_default_audit_emitter(signer.signing, p.audit_dir)
                    .context("opening fallback audit chain emitter")?;
                emit_policy_resolve_failure(&admitted.plan, &fallback, &err);
                return Err(err);
            }
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
    if let Some(verbs) = admitted.plan.agent_verbs.as_ref()
        && let Err(e) = emitter.emit_grant_required(&admitted.plan, verbs)
    {
        tracing::warn!(error = %e, "audit emit_grant_required failed (non-fatal)");
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
    let policy_bundle = match generated_bundle {
        Some(bundle) => Some(bundle),
        None => match p.policy_dir {
            Some(dir) => resolve_policy_bundle_with_dir(&admitted.plan, dir),
            None => resolve_policy_bundle(&admitted.plan),
        }
        .context("loading the tenant policy bundle for the bridge")?,
    };

    Ok(Some(AdmissionContext {
        admitted,
        emitter,
        policy_bundle,
        host_signer_public_path: signer.public_path,
    }))
}

/// Resolve the image digest used by the signed plan, verifying any caller-
/// supplied digest against the exact rootfs bytes first.
///
/// The ordinary boot path uses the size/mtime cache because the rootfs is
/// immutable across repeated launches. A precomputed digest is different: it
/// is an external attestation claim, so it must be checked with an uncached
/// read before it can influence admission. A mismatch fails closed.
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

pub(in crate::commands::vm) fn guest_profile_for_boot(
    is_dev_mode: bool,
    rootfs_path: &std::path::Path,
) -> AgentProfile {
    if is_dev_mode || !crate::commands::vm::agent_verbs::image_is_sealed(rootfs_path) {
        AgentProfile::Dev
    } else {
        AgentProfile::SealedProd
    }
}

fn security_policy_for_profile(profile: AgentProfile) -> SecurityPolicy {
    match profile {
        AgentProfile::SealedProd => SecurityPolicy::default(),
        AgentProfile::Dev => SecurityPolicy::dev_defaults(),
        AgentProfile::Builder => SecurityPolicy {
            profile: AgentProfile::Builder,
            ..SecurityPolicy::default()
        },
    }
}

pub(super) fn attach_guest_security_policy_config(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    profile: AgentProfile,
) -> Result<()> {
    let content = serde_json::to_string(&security_policy_for_profile(profile))
        .context("serializing guest security policy for config drive")?;
    start_config
        .config_files
        .retain(|f| f.name != SECURITY_POLICY_FILENAME);
    start_config
        .config_files
        .push(mvm_core::vm_backend::VmFile {
            name: SECURITY_POLICY_FILENAME.to_string(),
            content,
            mode: 0o444,
        });
    Ok(())
}

pub(in crate::commands::vm) fn attach_guest_boot_config_for_plan(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    plan: &mvm_core::plan::ExecutionPlan,
    host_signer_public_path: &std::path::Path,
    profile: AgentProfile,
) -> Result<()> {
    attach_host_signer_pubkey_config_for_plan(start_config, plan, host_signer_public_path)?;
    attach_guest_security_policy_config(start_config, profile)
}

pub(super) fn attach_guest_boot_config(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    admission: &AdmissionContext,
    profile: AgentProfile,
) -> Result<()> {
    attach_guest_boot_config_for_plan(
        start_config,
        &admission.admitted.plan,
        &admission.host_signer_public_path,
        profile,
    )
}

pub(super) fn attach_host_signer_pubkey_config_for_plan(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    plan: &mvm_core::plan::ExecutionPlan,
    host_signer_public_path: &std::path::Path,
) -> Result<()> {
    if plan.agent_verbs.is_none() {
        return Ok(());
    }
    let public_bytes = std::fs::read(host_signer_public_path).with_context(|| {
        format!(
            "reading host-signer public key for config drive at {}",
            host_signer_public_path.display()
        )
    })?;
    let public_array: [u8; 32] = public_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "host-signer public key at {} must be 32 bytes, got {}",
            host_signer_public_path.display(),
            public_bytes.len()
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&public_array).with_context(|| {
        format!(
            "parsing host-signer public key at {}",
            host_signer_public_path.display()
        )
    })?;
    let content = format!("{}\n", hex::encode(public_bytes));
    start_config
        .config_files
        .retain(|f| f.name != PUBLIC_FILENAME);
    start_config
        .config_files
        .push(mvm_core::vm_backend::VmFile {
            name: PUBLIC_FILENAME.to_string(),
            content,
            mode: 0o444,
        });
    Ok(())
}

#[derive(Debug)]
pub(super) struct PolicyAdmissionResolution {
    pub(super) slots_mode: &'static str,
    pub(super) audit: Option<mvm_core::policy::AuditPolicy>,
}

/// Run the policy resolver against the admitted plan and return the
/// policy-derived audit configuration for emitter construction.
///
/// `policy_dir` is the override for `~/.mvm/policies/`; production
/// callers pass `None` and the resolver resolves it from `$HOME`.
/// Tests inject a tempdir to stage / omit bundles deterministically.
///
pub(super) fn resolve_policy_for_admission(
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
pub(in crate::commands::vm) fn emit_launched_if(
    ctx: &Option<AdmissionContext>,
    backend: &str,
    persist_plan: bool,
) {
    let Some(ctx) = ctx else { return };
    if let Err(e) = ctx.emitter.emit_launched(&ctx.admitted.plan, backend) {
        tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
    }
    if persist_plan
        && let Err(e) = crate::commands::vm::plan_persist::write_plan(
            &ctx.admitted.plan.workload.0,
            &ctx.admitted.plan,
        )
    {
        tracing::warn!(
            error = %e,
            "persisting admitted plan to ~/.mvm/vms/<vm>/plan.json failed (non-fatal)"
        );
    }
}

/// Record the resolved boot posture (which rootfs strategy the run-path tier
/// gate actually selected) on the chain-signed admission log. Fires alongside
/// `plan.launched`, reflecting the decision `run_inner` made — never a
/// re-derivation — so a virtiofs-root dev boot and an Option-B block boot are
/// distinguishable in the tamper-evident chain. No-op when admission was
/// skipped (no plan to bind to).
pub(in crate::commands::vm) fn emit_boot_posture_if(
    ctx: &Option<AdmissionContext>,
    strategy: mvm_build::run_image::RootStrategy,
    runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
) {
    let Some(ctx) = ctx else { return };
    let label = match strategy {
        mvm_build::run_image::RootStrategy::VirtiofsRoot => "virtiofs-root",
        mvm_build::run_image::RootStrategy::BlockExt4 => "block-ext4",
    };
    if let Err(e) = ctx.emitter.emit_boot_posture(
        &ctx.admitted.plan,
        label,
        runtime_source_policy.audit_label(),
    ) {
        tracing::warn!(error = %e, "audit emit_boot_posture failed (non-fatal)");
    }
}

/// Tier A.1 admission enforcement: refuse to boot if any volume about to
/// be attached isn't named in the verified `ExecutionPlan.shares`. No-op
/// when admission was skipped (no plan to enforce against). Called right
/// before every `backend.start()` so no host-fs grant reaches a guest
/// unless the signed plan admitted it (claim 1 / claim 8).
pub(super) fn enforce_shares_if(
    ctx: &Option<AdmissionContext>,
    volumes: &[mvm_core::vm_backend::VmVolume],
) -> Result<()> {
    if let Some(ctx) = ctx {
        mvm_hostd::plan_admission::enforce_admitted_shares(volumes, &ctx.admitted.plan)
            .context("admission share check")?;
    }
    Ok(())
}

/// Emit `plan.failed` against the supplied admission context. No-op
/// when admission was skipped. `class` is a short grep-friendly tag
/// (e.g. `backend-start`, `snapshot-restore`); `err` becomes the
/// rendered error chain.
pub(in crate::commands::vm) fn emit_failed_if(
    ctx: &Option<AdmissionContext>,
    class: &str,
    err: &anyhow::Error,
) {
    let Some(ctx) = ctx else { return };
    let msg = format!("{err:#}");
    if let Err(e) = ctx.emitter.emit_failed(&ctx.admitted.plan, class, &msg) {
        tracing::warn!(error = %e, "audit emit_failed failed (non-fatal)");
    }
}

#[cfg(test)]
mod host_signer_pubkey_config_tests {
    use super::*;
    use mvm_core::plan::{VerbId, test_support::PlanFixture};
    use mvm_core::vm_backend::VmStartConfig;

    #[test]
    fn attaches_pubkey_when_plan_has_agent_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let signer = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = signer.verifying_key().to_bytes();
        std::fs::write(&pubkey_path, pubkey).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = Some(vec![VerbId::new("ping").unwrap()]);
        let mut start_config = VmStartConfig::default();

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert_eq!(start_config.config_files.len(), 1);
        let file = &start_config.config_files[0];
        assert_eq!(file.name, PUBLIC_FILENAME);
        assert_eq!(file.content, format!("{}\n", hex::encode(pubkey)));
        assert_eq!(file.mode, 0o444);
    }

    #[test]
    fn skips_pubkey_when_plan_has_no_agent_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = None;
        let mut start_config = VmStartConfig::default();

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert!(start_config.config_files.is_empty());
    }

    #[test]
    fn attaches_sealed_security_policy_for_prod_boots() {
        let mut start_config = VmStartConfig::default();

        attach_guest_security_policy_config(&mut start_config, AgentProfile::SealedProd).unwrap();

        let file = start_config
            .config_files
            .iter()
            .find(|file| file.name == SECURITY_POLICY_FILENAME)
            .expect("security policy file attached");
        let policy: SecurityPolicy =
            serde_json::from_str(&file.content).expect("parse security policy");
        assert_eq!(policy.profile, AgentProfile::SealedProd);
        assert!(policy.require_auth);
        assert!(!policy.access.console);
    }

    #[test]
    fn attaches_dev_security_policy_for_dev_boots() {
        let mut start_config = VmStartConfig::default();

        attach_guest_security_policy_config(&mut start_config, AgentProfile::Dev).unwrap();

        let file = start_config
            .config_files
            .iter()
            .find(|file| file.name == SECURITY_POLICY_FILENAME)
            .expect("security policy file attached");
        let policy: SecurityPolicy =
            serde_json::from_str(&file.content).expect("parse security policy");
        assert_eq!(policy.profile, AgentProfile::Dev);
        assert!(!policy.require_auth);
        assert!(policy.access.console);
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
mod admit_plan_tests {
    use super::*;
    use std::io::Write;

    fn write_rootfs(dir: &std::path::Path, bytes: &[u8]) -> std::path::PathBuf {
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
        emit_launched_if(&none, "firecracker", true);
        emit_failed_if(
            &none,
            "backend-start",
            &anyhow::anyhow!("simulated failure"),
        );
    }

    #[test]
    fn emit_boot_posture_audits_runtime_source_policy_label() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"boot-posture-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-boot-posture",
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        emit_boot_posture_if(
            &Some(ctx),
            mvm_build::run_image::RootStrategy::BlockExt4,
            mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
        );

        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("plan.boot_posture"),
            "audit chain must include boot posture event: {content}"
        );
        assert!(
            content.contains("\"root_strategy\":\"block-ext4\""),
            "audit chain must carry selected root strategy: {content}"
        );
        assert!(
            content.contains("\"runtime_source_policy\":\"required-overlay\""),
            "audit chain must carry runtime_source_policy label from the enum: {content}"
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
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
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
    fn admission_weaves_allow_list_into_signed_generated_policy_bundle() {
        use mvm_core::network_policy::{HostPort, NetworkPolicy};

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"allow-list-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-allow-list",
            backend_name: "libkrun",
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
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("93.184.216.34", 443)]),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_ne!(ctx.admitted.plan.network_policy.0, LOCAL_DEFAULT);
        assert_eq!(
            ctx.admitted.plan.network_policy.0,
            ctx.admitted.plan.egress_policy.0
        );
        let bundle = ctx.policy_bundle.expect("generated policy bundle");
        assert_eq!(bundle.network.l4.len(), 1);
        assert_eq!(bundle.network.l4[0].proto, "tcp");
        assert_eq!(bundle.network.l4[0].dst_cidr, "93.184.216.34/32");
        assert_eq!(bundle.network.l4[0].port_lo, 443);
        assert_eq!(bundle.network.l4[0].port_hi, 443);
        assert_eq!(
            bundle.egress.allow_list,
            vec![("93.184.216.34".to_string(), 443)]
        );

        let content =
            std::fs::read_to_string(audit_dir.path().join("local.jsonl")).expect("audit file");
        assert!(
            content.contains("\"slots_mode\":\"live\""),
            "generated bundle must audit as live policy resolution: {content}"
        );
    }

    #[test]
    fn admission_weaves_unrestricted_policy_into_signed_generated_policy_bundle() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"unrestricted-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-unrestricted",
            backend_name: "hvf",
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
            network_policy: mvm_core::network_policy::NetworkPolicy::unrestricted(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_ne!(ctx.admitted.plan.network_policy.0, LOCAL_DEFAULT);
        let bundle = ctx.policy_bundle.expect("generated policy bundle");
        assert_eq!(bundle.egress.mode.as_deref(), Some("open"));
        assert!(bundle.network.l4.is_empty());
    }

    #[test]
    fn up_populates_agent_verbs_default_and_override() {
        use crate::commands::vm::agent_verbs::{default_agent_verbs, parse_agent_verb_override};
        // Default path: sealed-prod, no shares → run-entrypoint present, mount-volume absent.
        let d = parse_agent_verb_override(&[])
            .unwrap()
            .or_else(|| default_agent_verbs(true, false))
            .unwrap();
        assert!(d.iter().any(|v| v.as_str() == "run-entrypoint"));
        assert!(!d.iter().any(|v| v.as_str() == "mount-volume"));
        // Override path: explicit set replaces the default.
        let o = parse_agent_verb_override(&["run-entrypoint".into()])
            .unwrap()
            .or_else(|| default_agent_verbs(true, false))
            .unwrap();
        assert_eq!(
            o.iter().map(|v| v.as_str()).collect::<Vec<_>>(),
            ["run-entrypoint"]
        );
        // Dev path: None (class-gate only).
        assert!(
            parse_agent_verb_override(&[])
                .unwrap()
                .or_else(|| default_agent_verbs(false, false))
                .is_none()
        );
    }
}
