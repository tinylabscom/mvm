//! Signed `ExecutionPlan` admission for `mvmctl up` — synthesize, sign,
//! verify, and audit-emit the plan right before a backend `start()`, plus
//! the guest boot-config attachments (host-signer pubkey, security policy)
//! that ride along with an admitted plan.

use anyhow::{Context, Result, bail};

use mvm_core::plan::{StreamRetention, SynthesisInput, Variant};
use mvm_core::policy::PolicyBundle;
use mvm_core::security::{AgentProfile, SecurityPolicy};
use mvm_hostd::plan_admission::{
    AdmittedPlan, BundleAdmissionContext, InMemoryNonceLedger, RunPosture, SystemClock,
    admit_for_run,
};
use mvm_sdk::deploy::{BootArtifactIdentity, read_deploy_record, verify_boot_artifact};

use crate::commands::vm::audit_chain::AuditEmitter;
use crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint;
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
    /// Declared `--asset KIND:HOST_PATH` bindings hashed into content
    /// identities at admission and recorded in the signed plan's
    /// `asset_identities` (with the environment, bundle, deps volume,
    /// digested shares, and the resolved network policy). Empty for runs
    /// that declare no assets.
    pub assets: Vec<crate::commands::shared::AssetSpec>,
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
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
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
pub(in crate::commands::vm) fn entrypoint_is_shell_shaped(
    argv: &[String],
    shebang: Option<&[u8]>,
) -> bool {
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
            .field("plan_id", self.admitted.plan_id())
            .field("signer_id", &self.admitted.signer_id())
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
    admit_plan_for_boot_with_ingress(p, Vec::new())
}

pub(in crate::commands::vm) fn admit_plan_for_boot_with_ingress(
    p: AdmitPlanForBootParams<'_>,
    ingress: Vec<mvm_core::plan::IngressMapping>,
) -> Result<Option<AdmissionContext>> {
    if p.no_supervisor {
        return Ok(None);
    }

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
            ResolvedEntrypoint::Unresolved { because } => anyhow::bail!(
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
    let sha = resolve_image_sha256(p.rootfs_path, p.precomputed_image_sha256.or(attested_sha))?;
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

    // Pin the kernel alongside the image. Through the shared digest cache, the
    // same way `image_sha256` above is derived — a pin that re-read the whole
    // kernel would put a multi-MB read back on every launch to reproduce a
    // value the kernel's own cache check just computed from the same bytes.
    let kernel_sha256 = p
        .kernel_path
        .map(|kernel| {
            mvm_core::crypto::image_verify::sha256_file_cached(kernel)
                .with_context(|| format!("hashing kernel at {} for the plan pin", kernel.display()))
        })
        .transpose()?;

    let generated_network_policy_bundle =
        generated_policy_bundle_for_network_policy(p.tenant, p.vm_name, &p.network_policy)?;
    let generated_policy_ref = generated_network_policy_bundle
        .as_ref()
        .map(|(policy_ref, _)| policy_ref.as_str());

    // Content-derived asset identities. Directory shares that don't carry a
    // digest yet are hashed here, at admission, so the signed plan records
    // what the granted tree actually was; enforcement re-hashes at attach
    // time and refuses drift (hostd `enforce_admitted_shares`). The path is
    // canonicalized first so a symlink alias (macOS `/tmp`) hashes the same
    // tree `hash_source` would refuse as a symlink root.
    let mut shares = p.shares.clone();
    for grant in &mut shares {
        if grant.kind == mvm_core::plan::ShareKind::DirShare && grant.content_sha256.is_none() {
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

    // Caller-declared `--asset` files/dirs: the canonical tree hash is the
    // asset's identity. A missing path fails admission here, before signing.
    let mut caller_assets = Vec::with_capacity(p.assets.len());
    for spec in &p.assets {
        let resolved = std::fs::canonicalize(&spec.host_path)?;
        let digest = mvm_fs::hash::hash_source(&resolved).with_context(|| {
            format!(
                "hashing declared {} asset {} for its content identity",
                serde_json::to_string(&spec.kind).expect("asset kind serializes"),
                spec.host_path
            )
        })?;
        let name = std::path::Path::new(&spec.host_path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| spec.host_path.clone());
        caller_assets.push(mvm_core::plan::AssetIdentity::new(spec.kind, name, digest)?);
    }

    // The resolved network policy's identity: the plan pins policies by
    // reference name, so the caller adds the resolved bytes' hash — an
    // operator comparing identities sees which exact policy content was
    // admitted, not just its name.
    let network_policy_digest = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(serde_json::to_vec(&p.network_policy).expect("policy serializes"));
        hex::encode(hasher.finalize())
    };

    let input = SynthesisInput {
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
        audit_labels: Default::default(),
        agent_verbs: crate::commands::vm::agent_verbs::parse_agent_verb_override(
            &p.agent_verb_override,
        )?
        .or_else(|| {
            crate::commands::vm::agent_verbs::default_agent_verbs(
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
        }),
        _ => None,
    };
    // The posture the grant gate reads. `restrict_agent_verbs` is this
    // codebase's sealed-production signal — the same one the input-grant
    // refusal above is scoped to — so a sealed boot refuses a grant nothing
    // can enforce, and a dev boot is told about it and proceeds.
    let variant = if p.restrict_agent_verbs {
        Variant::Prod
    } else {
        Variant::Dev
    };
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
        // A caller that already resolved its backend hands the typed kind over,
        // and the grant gate measures against the mechanisms that tier really
        // has. A caller that has not resolved one yet passes `None` and gets
        // the fail-closed answer: a sealed run refuses a grant whose
        // enforceability nothing can confirm, a dev run is warned. The plan's
        // own `runtime_profile` is never consulted for this — it is a label its
        // author chose, and believing it would let a mislabelled plan pick the
        // controls it is measured against.
        match p.backend_kind {
            Some(kind) => RunPosture::on_backend(variant, kind),
            None => RunPosture::without_backend(variant),
        },
    )?;
    let t_signed = std::time::Instant::now();
    tracing::debug!(
        ms = (t_signed - t_pre_sign).as_secs_f64() * 1000.0,
        "admit: sign+verify"
    );
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
    // here surface as `Err` so the caller sees them; in production
    // mvmctl up degrades gracefully (logs a warning, continues).
    let signer = match p.keys_dir {
        Some(dir) => load_or_init_at(dir),
        None => crate::commands::vm::host_signer::load_or_init(),
    }
    .context("loading host signer for audit emitter")?;
    let t_signer = std::time::Instant::now();
    tracing::debug!(
        ms = (t_signer - t_signed).as_secs_f64() * 1000.0,
        "admit: load host signer"
    );

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
            emit_policy_resolve_failure(admitted.plan(), &fallback, &err);
            return Err(err);
        }
        PolicyAdmissionResolution {
            slots_mode: "live",
            audit: Some(bundle.audit.clone()),
        }
    } else {
        match resolve_policy_for_admission(admitted.plan(), p.policy_dir) {
            Ok(resolved) => resolved,
            Err(err) => {
                let fallback = build_default_audit_emitter(signer.signing, p.audit_dir)
                    .context("opening fallback audit chain emitter")?;
                emit_policy_resolve_failure(admitted.plan(), &fallback, &err);
                return Err(err);
            }
        }
    };

    let emitter = match build_policy_audit_emitter(
        signer.signing.clone(),
        p.audit_dir,
        resolved.audit.as_ref(),
    ) {
        Ok(emitter) => emitter.with_receipts(),
        Err(err) => {
            let err = err.context("opening audit chain emitter");
            match build_default_audit_emitter(signer.signing, p.audit_dir) {
                Ok(fallback) => emit_policy_audit_invalid(admitted.plan(), &fallback, &err),
                Err(fallback_err) => tracing::warn!(
                    error = %fallback_err,
                    "audit emit_failed for policy-audit-invalid skipped; fallback emitter failed"
                ),
            }
            return Err(err);
        }
    };

    // A sealed-production run that cannot record its admission does not boot.
    // The chain can prove nothing was altered among the entries it holds, but
    // an entry that was never written leaves no gap for it to find — so the
    // only moment this is catchable is right here. `restrict_agent_verbs` is
    // the same sealed-tier signal the shell-entrypoint refusal above keys on.
    let t_emitter = std::time::Instant::now();
    tracing::debug!(
        ms = (t_emitter - t_signer).as_secs_f64() * 1000.0,
        "admit: policy + emitter build"
    );
    // One batch, one fsync. These entries all have to be durable before the
    // same thing — this plan booting — and nothing between them acts on the
    // one before it, so syncing each separately bought no ordering. It cost
    // one `F_FULLFSYNC` each, which is 7.4ms on an Apple-silicon host and
    // ~42ms on the KVM box's array. The batch closes here, before the caller
    // gets an `AdmissionContext` to boot from, and a failed flush is an error
    // rather than a warning.
    emitter.batched(|| {
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
        // records none).
        if let Err(e) = emitter.emit_asset_identities(admitted.plan()) {
            tracing::warn!(error = %e, "audit emit_asset_identities failed (non-fatal)");
        }
        Ok(())
    })?;
    tracing::debug!(
        ms = t_emitter.elapsed().as_secs_f64() * 1000.0,
        "admit: record_admission (batched fsync)"
    );

    // Resolve the plan's four policy refs into concrete supervisor
    // component slots. Today the slots are constructed-and-dropped —
    // no `Supervisor::launch` integration exists in mvmctl yet (that
    // ships with the mvm-hostd lift). The call here is operator-
    // facing: it validates the policy refs against the on-disk
    // bundle so a missing file / typo / bad L4 CIDR fails the boot
    // loudly *now* instead of silently passing through with Noops.
    emit_policy_resolved(admitted.plan(), &emitter, resolved.slots_mode);

    // Slice 3 (b) — load the resolved tenant PolicyBundle (None for a
    // local-default plan) so populate_audit_substrate can deliver it to the
    // bridge for per-tenant L4 egress enforcement. resolve_policy_for_admission
    // above already validated the refs, so a well-formed bundle won't surface a
    // new error class here.
    let policy_bundle = match generated_bundle {
        Some(bundle) => Some(bundle),
        None => match p.policy_dir {
            Some(dir) => resolve_policy_bundle_with_dir(admitted.plan(), dir),
            None => resolve_policy_bundle(admitted.plan()),
        }
        .context("loading the tenant policy bundle for the bridge")?,
    };

    // Record the admitted L7 egress boundary in the chain-signed log so a
    // receipt can name the destinations without re-resolving policy refs.
    let egress_destinations = policy_bundle
        .as_ref()
        .map(|b| b.egress.allow_list.clone())
        .unwrap_or_default();
    if let Err(e) = emitter.emit_egress_destinations(admitted.plan(), &egress_destinations) {
        tracing::warn!(error = %e, "audit emit_egress_destinations failed (non-fatal)");
    }

    Ok(Some(AdmissionContext {
        admitted,
        emitter,
        policy_bundle,
        host_signer_public_path: signer.public_path,
    }))
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
        admission.admitted.plan(),
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
    if let Err(e) = ctx.emitter.emit_launched(ctx.admitted.plan(), backend) {
        tracing::warn!(error = %e, "audit emit_launched failed (non-fatal)");
    }
    if persist_plan
        && let Err(e) = crate::commands::vm::plan_persist::write_plan(
            &ctx.admitted.plan().workload.0,
            ctx.admitted.plan(),
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
) {
    let Some(ctx) = ctx else { return };
    let label = match strategy {
        mvm_build::run_image::RootStrategy::BlockExt4 => "block-ext4",
    };
    if let Err(e) = ctx.emitter.emit_boot_posture(ctx.admitted.plan(), label) {
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
        mvm_hostd::plan_admission::enforce_admitted_shares(volumes, ctx.admitted.plan())
            .context("admission share check")?;
    }
    Ok(())
}

/// Refuse to boot if the kernel about to be loaded is not the one the verified
/// `ExecutionPlan` pinned. No-op when admission was skipped.
///
/// The sibling of [`enforce_shares_if`], called at the same point for the same
/// reason: `mvmctl` admits its plan and then starts the backend itself rather
/// than going through `start_admitted`, so every gate that path runs has to be
/// run here too or it does not run at all. The admitted-environment gate was
/// the one nobody called.
pub(super) fn enforce_kernel_if(
    ctx: &Option<AdmissionContext>,
    kernel_path: Option<&std::path::Path>,
) -> Result<()> {
    if let Some(ctx) = ctx {
        mvm_hostd::plan_admission::enforce_admitted_environment(kernel_path, ctx.admitted.plan())
            .context("admission kernel check")?;
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
    if let Err(e) = ctx.emitter.emit_failed(ctx.admitted.plan(), class, &msg) {
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
    fn replacing_pubkey_preserves_other_config_files_and_removes_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let signer = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let pubkey = signer.verifying_key().to_bytes();
        std::fs::write(&pubkey_path, pubkey).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = Some(vec![VerbId::new("ping").unwrap()]);
        let mut start_config = VmStartConfig {
            config_files: vec![
                mvm_core::vm_backend::VmFile {
                    name: "other-config".into(),
                    content: "keep".into(),
                    mode: 0o444,
                },
                mvm_core::vm_backend::VmFile {
                    name: PUBLIC_FILENAME.into(),
                    content: "stale".into(),
                    mode: 0o444,
                },
            ],
            ..VmStartConfig::default()
        };

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert_eq!(
            start_config
                .config_files
                .iter()
                .filter(|file| file.name == PUBLIC_FILENAME)
                .count(),
            1
        );
        assert!(
            start_config
                .config_files
                .iter()
                .any(|file| file.name == "other-config" && file.content == "keep")
        );
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

    #[test]
    fn builder_security_policy_preserves_the_builder_profile() {
        assert_eq!(
            security_policy_for_profile(AgentProfile::Builder).profile,
            AgentProfile::Builder
        );
    }

    #[test]
    fn guest_profile_requires_both_dev_override_and_sealed_image_checks() {
        use mvm_build::builder_vm::GuestSidecar;

        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let mut sidecar = GuestSidecar::for_oci_run("test", false, false);
        sidecar.accessible = false;
        sidecar.sealed = true;
        sidecar.write_to_dir(dir.path()).unwrap();

        assert_eq!(
            guest_profile_for_boot(false, &rootfs),
            AgentProfile::SealedProd
        );
        assert_eq!(guest_profile_for_boot(true, &rootfs), AgentProfile::Dev);
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
    fn sibling_deploy_record_is_only_used_for_its_rootfs_directory() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(dir.path(), b"recorded rootfs");
        let boot_artifact = mvm_sdk::deploy::digest_boot_artifact(&rootfs).unwrap();
        let record = mvm_sdk::deploy::DeployRecord {
            schema_version: mvm_sdk::deploy::DEPLOY_RECORD_SCHEMA_VERSION,
            workload_id: "vm-test".to_string(),
            ir_hash: "ir-hash".to_string(),
            image: mvm_sdk::deploy::ArtifactDigests {
                blake3: "b".repeat(64),
                sha256: "a".repeat(64),
                size_bytes: 1,
            },
            boot_artifact: boot_artifact.clone(),
            environment: None,
            dependency_volume: None,
        };
        mvm_sdk::deploy::write_deploy_record(&record, &dir.path().join("deploy.json")).unwrap();

        assert_eq!(
            sibling_deploy_boot_artifact(&rootfs).unwrap(),
            Some(boot_artifact)
        );
        let unrelated = dir.path().join("other").join("rootfs.ext4");
        assert!(sibling_deploy_boot_artifact(&unrelated).unwrap().is_none());
    }

    /// A minimal admission that really runs — signs, verifies, burns a nonce.
    /// Callers override only the fields their assertion is about.
    fn pinning_params<'a>(
        rootfs: &'a std::path::Path,
        ledger: &'a InMemoryNonceLedger,
    ) -> AdmitPlanForBootParams<'a> {
        AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-pinned",
            backend_name: "firecracker",
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
            no_supervisor: false,
            ledger,
            keys_dir: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        }
    }

    #[test]
    fn admission_binds_the_caller_commitment_into_the_plan() {
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

        let admitted = admit_plan_for_boot(params)
            .expect("admission succeeds")
            .expect("supervisor admission is enabled");
        assert_eq!(admitted.admitted.plan().caller_commitment, Some(commitment));
    }

    /// The image digest says what the workload *is* and nothing about what
    /// confines it, so a plan that names the image but not the kernel admits a
    /// workload onto whatever kernel the host happened to have cached. This is
    /// the assertion that would have caught `kernel_sha256: None` sitting on
    /// the CLI's only admission seam.
    #[test]
    fn the_booting_kernel_is_pinned_into_the_signed_plan() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let kernel = rootfs_dir.path().join("vmlinux");
        std::fs::write(&kernel, b"workload-kernel-bytes").unwrap();
        let expected = mvm_core::crypto::image_verify::sha256_file(&kernel).unwrap();
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            kernel_path: Some(kernel.as_path()),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission")
        .expect("Some when admission ran");

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

    /// A kernel swapped between admission and boot is refused. Same plan, same
    /// image, a different confinement — the substitution the pin exists to make
    /// visible.
    #[test]
    fn a_kernel_swapped_after_admission_is_refused() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"hello rootfs");
        let kernel = rootfs_dir.path().join("vmlinux");
        std::fs::write(&kernel, b"workload-kernel-bytes").unwrap();
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            kernel_path: Some(kernel.as_path()),
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            ..pinning_params(&rootfs, &ledger)
        })
        .expect("admission")
        .expect("Some when admission ran");

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
    fn no_supervisor_short_circuits_to_none() {
        // The escape hatch must skip admission entirely — no host
        // signer load, no rootfs hash, no nonce burn.
        let dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(dir.path(), b"unused");
        let ledger = InMemoryNonceLedger::new();
        let result = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-skip",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: true,
            ledger: &ledger,
            keys_dir: None, // not read — short-circuit returns first
            audit_dir: None,
            policy_dir: None,
            bundle_pin: None,
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
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
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
        let boot_artifact = mvm_sdk::deploy::digest_boot_artifact(&rootfs).unwrap();
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-happy",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: Some(&boot_artifact),
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Network,
            secret_release: mvm_core::plan::SecretReleasePolicy::PlanBound,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
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
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
        })
        .expect("admission")
        .expect("Some when admission ran");
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
        // sha256_file fails when the file does not exist; the helper
        // must propagate the error with context naming the rootfs path.
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let ledger = InMemoryNonceLedger::new();
        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-missing",
            backend_name: "firecracker",
            rootfs_path: std::path::Path::new("/nonexistent/rootfs.ext4"),
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
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
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
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
                network_mode: mode,
                grants: None,
                backend_kind: None,
                tenant: "local",
                vm_name: "vm-transport",
                backend_name: "firecracker",
                rootfs_path: &rootfs,
                kernel_path: None,
                precomputed_image_sha256: None,
                boot_artifact_identity: None,
                cpus: 1,
                mem_mib: 128,
                seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
                secret_release: mvm_core::plan::SecretReleasePolicy::None,
                secrets: Vec::new(),
                caller_commitment: None,
                no_supervisor: false,
                ledger: &ledger,
                keys_dir: Some(keys_dir.path()),
                audit_dir: Some(audit_dir.path()),
                policy_dir: None,
                bundle_pin: None,
                deps_volume: None,
                shares: Vec::new(),
                assets: Vec::new(),
                redaction: mvm_core::policy::RedactionPolicy::default(),
                network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
                agent_verb_override: vec![],
                restrict_agent_verbs: false,
                services: Vec::new(),
                entrypoint: crate::commands::vm::entrypoint_resolve::ResolvedEntrypoint::unresolved(
                    "test",
                ),
            })
            .expect("admit")
            .expect("a supervisor-backed admission returns a context");

            assert_eq!(
                ctx.admitted.plan().network_mode,
                mode,
                "the plan must record the mode the launch was admitted with"
            );
        }
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-1",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            services: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            assets: Vec::new(),
            restrict_agent_verbs: true,
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
        })
        .unwrap()
        .unwrap();
        let a2 = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-2",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .unwrap()
        .unwrap();
        assert_ne!(a1.admitted.plan_id(), a2.admitted.plan_id());
        assert_ne!(a1.admitted.plan().nonce, a2.admitted.plan().nonce);
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
    fn emit_boot_posture_audits_the_root_strategy_label() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"boot-posture-payload");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-boot-posture",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        emit_boot_posture_if(&Some(ctx), mvm_build::run_image::RootStrategy::BlockExt4);

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
            content.contains("\"root_strategy\":\"block-ext4\""),
            "audit chain must carry the root_strategy label: {content}"
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-local-default",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
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
        assert!(content.contains(&ctx.admitted.plan_id().0));
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-allow-list",
            backend_name: "libkrun",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_ne!(ctx.admitted.plan().network_policy.0, LOCAL_DEFAULT);
        assert_eq!(
            ctx.admitted.plan().network_policy.0,
            ctx.admitted.plan().egress_policy.0
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-unrestricted",
            backend_name: "hvf",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
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
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_ne!(ctx.admitted.plan().network_policy.0, LOCAL_DEFAULT);
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

    #[test]
    fn a_non_shell_entrypoint_with_the_grant_is_admitted_under_prod() {
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-non-shell-granted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: vec![mvm_core::plan::HostShareGrant {
                tag: "uvol0".into(),
                host_path: share_dir.path().to_string_lossy().into_owned(),
                guest_path: "/data".into(),
                kind: mvm_core::plan::ShareKind::DirShare,
                read_only: true,
                encrypted: false,
                content_sha256: None,
            }],
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec!["python".to_string(), "-m".to_string(), "app".to_string()],
                shebang: None,
            },
        })
        .expect("a non-shell entrypoint must not be refused")
        .expect("Some when admission ran");

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
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"shell-entrypoint-no-grant-payload");
        let ledger = InMemoryNonceLedger::new();

        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-shell-ungranted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(), // no host.stream.v1 grant
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
        })
        .expect("a shell entrypoint must still boot when nothing granted it input")
        .expect("Some when admission ran");

        assert!(!ctx.admitted.plan_id().0.is_empty());
    }

    #[test]
    fn a_shell_entrypoint_with_the_grant_is_refused_and_names_the_reason() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"shell-entrypoint-granted-payload");
        let ledger = InMemoryNonceLedger::new();

        let err = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-shell-granted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
        })
        .expect_err("a shell entrypoint carrying the grant must be refused");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("shell-shaped"),
            "the refusal must name the reason: {rendered}"
        );
    }

    #[test]
    fn an_unresolved_entrypoint_with_the_grant_is_refused() {
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-entrypoint-unknown",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: vec![stream_grant_service()],
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::unresolved("this launch path resolves no entrypoint"),
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-entrypoint-unknown-ungranted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
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
        })
        .expect("an unresolved entrypoint that asked for nothing must still boot")
        .expect("Some when admission ran");

        assert!(!ctx.admitted.plan_id().0.is_empty());
    }

    #[test]
    fn a_dev_profile_shell_entrypoint_with_the_grant_is_not_refused() {
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            boot_artifact_identity: None,
            tenant: "local",
            vm_name: "vm-dev-shell",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            assets: Vec::new(),
            no_supervisor: false,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            ledger: &ledger,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
            agent_verb_override: vec![],
            restrict_agent_verbs: false,
            services: vec![stream_grant_service()],
            grants: None,
            backend_kind: None,
            entrypoint: ResolvedEntrypoint::Known {
                argv: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
                shebang: None,
            },
        })
        .expect("dev-tier runs are out of the shell-entrypoint refusal's scope")
        .expect("Some when admission ran");

        assert!(!ctx.admitted.plan_id().0.is_empty());
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
    use super::*;
    use crate::commands::shared::{GrantInputs, resolve_run_grants};
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
            }
        };

        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path());
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-shares",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 1,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
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
            services: Vec::new(),
            grants: None,
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-granted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 4,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            agent_verb_override: vec![],
            // A dev posture: the grant is recorded and, on a tier without a
            // CPU mechanism, warned about rather than refused. The refusal
            // half is `plan_admission`'s to test; this one is about reach.
            restrict_agent_verbs: false,
            services: Vec::new(),
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");

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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-over-ceiling",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 4,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            agent_verb_override: vec![],
            restrict_agent_verbs: false,
            services: Vec::new(),
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
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
            network_mode: mvm_contract::plan::NetworkMode::default(),
            tenant: "local",
            vm_name: "vm-ungranted",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            kernel_path: None,
            precomputed_image_sha256: None,
            boot_artifact_identity: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            caller_commitment: None,
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: Some(keys_dir.path()),
            audit_dir: Some(audit_dir.path()),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: resolved.network_policy.clone(),
            agent_verb_override: vec![],
            restrict_agent_verbs: true,
            services: Vec::new(),
            grants: resolved.plan_grants.clone(),
            backend_kind: Some(mvm_contract::protocol::vm_backend::BackendKind::Firecracker),
            entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
            assets: Vec::new(),
        })
        .expect("admission")
        .expect("Some when admission ran");
        assert_eq!(ctx.admitted.plan().grants, None);
        assert_eq!(
            resolved.network_policy.resolve_rules().as_deref(),
            Some(&[][..]),
            "granting nothing still means deny-all"
        );
    }
}
