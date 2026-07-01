//! Internal admission and boot helpers consumed by `machine/mod.rs`:
//! `start_persistent_oci_machine`, `admit_plan_for_boot`, `AdmitPlanForBootParams`,
//! `AdmissionContext`, `emit_launched_if`, `emit_failed_if`,
//! `persists_plan_before_start`, `resolve_workload_kernel`, `untrusted_transient_admit`,
//! and `load_workload_ir`.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_backend::backend::AnyBackend;
use mvm_backend::image;
use mvm_core::domain::instance::InstanceReadiness;
use mvm_core::naming::validate_vm_name;

use super::super::env::dev_vz::ensure_default_microvm_image;
use super::audit_chain::{AuditEmitter, default_audit_dir};
use super::host_signer::load_or_init_at;
use super::plan_admission::{
    AdmittedPlan, BundleAdmissionContext, InMemoryNonceLedger, SystemClock, admit_for_run,
    populate_audit_substrate, stash_plan_for_bridge, thread_tenant_id,
};
use super::plan_builder::SynthesisInput;
use super::policy_resolver::{
    LOCAL_DEFAULT, ResolveError, resolve_policy_bundle, resolve_policy_bundle_with_dir,
    resolve_supervisor_components, resolve_supervisor_components_with_dir,
};
use super::shared::{
    VmStartParams, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
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
    pub auth: mvm_core::plan::AuthPolicy,
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

fn generated_policy_ref(tenant: &str, vm_name: &str) -> Result<String> {
    fn valid_component(s: &str) -> bool {
        !s.is_empty() && !s.contains('/') && !s.contains('\\') && !s.contains(':')
    }
    if !valid_component(tenant) {
        anyhow::bail!(
            "tenant {tenant:?} cannot be encoded into a generated signed network policy ref"
        );
    }
    if !valid_component(vm_name) {
        anyhow::bail!(
            "vm name {vm_name:?} cannot be encoded into a generated signed network policy ref"
        );
    }
    Ok(format!("{tenant}:{vm_name}"))
}

fn generated_policy_bundle_for_network_policy(
    tenant: &str,
    vm_name: &str,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<Option<(String, PolicyBundle)>> {
    use mvm_core::policy::bundle::{PolicyId, SCHEMA_VERSION as POLICY_SCHEMA_VERSION};
    use mvm_core::policy::policies::{
        ArtifactPolicy, AuditPolicy, EgressPolicy, KeyPolicy, L4RuleSpec, NetworkPolicy, PiiPolicy,
        ToolPolicy, WasiCapPolicy,
    };
    use std::net::{IpAddr, ToSocketAddrs};

    let Some(rules) = policy.resolve_rules() else {
        let policy_ref = generated_policy_ref(tenant, vm_name)?;
        let mut egress = EgressPolicy {
            mode: Some("open".to_string()),
            ..Default::default()
        };
        egress.redaction = mvm_core::policy::RedactionPolicy::default();
        return Ok(Some((
            policy_ref,
            PolicyBundle {
                schema_version: POLICY_SCHEMA_VERSION,
                bundle_id: PolicyId(format!("{tenant}/{vm_name}/cli-egress")),
                bundle_version: 1,
                network: NetworkPolicy::default(),
                egress,
                pii: PiiPolicy::default(),
                tool: ToolPolicy::default(),
                artifact: ArtifactPolicy::default(),
                keys: KeyPolicy::default(),
                audit: AuditPolicy {
                    chain_signing: true,
                    ..Default::default()
                },
                wasi: WasiCapPolicy::default(),
                tenant_overlays: std::collections::BTreeMap::new(),
            },
        )));
    };
    if rules.is_empty() {
        return Ok(None);
    }

    let policy_ref = generated_policy_ref(tenant, vm_name)?;
    let mut l4 = Vec::new();
    let mut egress_allow = Vec::new();
    for rule in rules {
        let ips: Vec<IpAddr> = if let Ok(ip) = rule.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (rule.host.as_str(), 0u16)
                .to_socket_addrs()
                .with_context(|| {
                    format!(
                        "resolving {} for generated signed network policy",
                        rule.host
                    )
                })?
                .map(|sa| sa.ip())
                .collect()
        };
        if ips.is_empty() {
            anyhow::bail!(
                "resolving {} for generated signed network policy returned no addresses",
                rule.host
            );
        }
        egress_allow.push((rule.host.clone(), rule.port));
        for ip in ips {
            let dst_cidr = match ip {
                IpAddr::V4(v4) => format!("{v4}/32"),
                IpAddr::V6(v6) => format!("{v6}/128"),
            };
            l4.push(L4RuleSpec {
                proto: "tcp".to_string(),
                dst_cidr,
                port_lo: rule.port,
                port_hi: rule.port,
            });
        }
    }
    l4.sort_by(|a, b| {
        (&a.proto, &a.dst_cidr, a.port_lo, a.port_hi).cmp(&(
            &b.proto,
            &b.dst_cidr,
            b.port_lo,
            b.port_hi,
        ))
    });
    l4.dedup();
    egress_allow.sort();
    egress_allow.dedup();

    let bundle = PolicyBundle {
        schema_version: POLICY_SCHEMA_VERSION,
        bundle_id: PolicyId(format!("{tenant}/{vm_name}/cli-egress")),
        bundle_version: 1,
        network: NetworkPolicy {
            preset: Some("cli-allow-list".to_string()),
            l4,
            observers: Vec::new(),
            flow_byte_log: None,
        },
        egress: EgressPolicy {
            allow_list: egress_allow,
            redaction: mvm_core::policy::RedactionPolicy::default(),
            ..Default::default()
        },
        pii: PiiPolicy::default(),
        tool: ToolPolicy::default(),
        artifact: ArtifactPolicy::default(),
        keys: KeyPolicy::default(),
        audit: AuditPolicy {
            chain_signing: true,
            ..Default::default()
        },
        wasi: WasiCapPolicy::default(),
        tenant_overlays: std::collections::BTreeMap::new(),
    };
    mvm_core::policy::canonicalize_l4(&bundle.network.l4)
        .context("validating generated signed network policy L4 rules")?;
    Ok(Some((policy_ref, bundle)))
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
        // Cached on a `<rootfs>.sha256cache` sidecar keyed on size+mtime: the
        // rootfs is immutable across boots of the same image, so re-hashing
        // ~100MB every `up` is the single biggest cost left on the boot path.
        None => mvm_core::crypto::image_verify::sha256_file_cached(p.rootfs_path).with_context(
            || {
                format!(
                    "hashing rootfs at {} for plan admission",
                    p.rootfs_path.display()
                )
            },
        )?,
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

    let generated_network_policy_bundle =
        generated_policy_bundle_for_network_policy(p.tenant, p.vm_name, &p.network_policy)?;
    let generated_policy_ref = generated_network_policy_bundle
        .as_ref()
        .map(|(policy_ref, _)| policy_ref.as_str());

    let input = SynthesisInput {
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
        auth: p.auth.clone(),
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
        agent_verbs: None,
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
    }))
}

/// Build the boot-time admission hook for an **untrusted transient run** —
/// deny-all egress, no secrets, tenant `local`. The locally-signed
/// `ExecutionPlan` sets `tenant_id`, which makes the libkrun/Vz supervisor
/// spawn the enforcing gateway bridge (so the resolved egress policy is
/// actually applied) instead of the legacy unfiltered path; Firecracker reads
/// the same field through nftables. Shared by `mvmctl run` and the MCP
/// code-runner so both admit identically — neither leaves a deny-all inert on
/// the bridge backends.
///
/// The returned closure owns a fresh nonce ledger per boot and yields the
/// `SessionAuditSubstrate` (tenant + signed plan) the exec layer hands to the
/// backend, persisting the bare plan first on the backends that read it from
/// disk before `start()`.
pub(in crate::commands) fn untrusted_transient_admit(
    backend_name: String,
    cpus: u32,
    mem_mib: u64,
) -> impl Fn(&std::path::Path, &str) -> Result<Option<crate::exec::SessionAuditSubstrate>> {
    untrusted_transient_admit_in(backend_name, cpus, mem_mib, None, None)
}

/// [`untrusted_transient_admit`] with explicit signer / audit directories so
/// tests can admit against isolated `TempDir`s; production passes `None` (the
/// default `~/.mvm` locations).
fn untrusted_transient_admit_in(
    backend_name: String,
    cpus: u32,
    mem_mib: u64,
    keys_dir: Option<std::path::PathBuf>,
    audit_dir: Option<std::path::PathBuf>,
) -> impl Fn(&std::path::Path, &str) -> Result<Option<crate::exec::SessionAuditSubstrate>> {
    move |rootfs: &std::path::Path, vm_name: &str| {
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name,
            backend_name: &backend_name,
            rootfs_path: rootfs,
            precomputed_image_sha256: None,
            cpus,
            mem_mib,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            // No secrets on the untrusted transient path; deny secret release.
            secret_release: mvm_core::plan::SecretReleasePolicy::default(),
            secrets: Vec::new(),
            auth: mvm_core::plan::AuthPolicy::none(),
            no_supervisor: false,
            ledger: &ledger,
            keys_dir: keys_dir.as_deref(),
            audit_dir: audit_dir.as_deref(),
            policy_dir: None,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            network_policy: mvm_core::network_policy::NetworkPolicy::deny_all(),
        })?;
        let Some(c) = ctx else { return Ok(None) };
        // Persist the bare plan so the pre-start moat / endpoint can read it on
        // the backends that consume it from disk.
        if persists_plan_before_start(&backend_name) {
            super::plan_persist::write_plan(vm_name, &c.admitted.plan)
                .context("persisting admitted plan for the untrusted transient run")?;
        }
        let plan_json = serde_json::to_string(&c.admitted.signed)
            .context("serializing admitted plan for the untrusted transient run")?;
        Ok(Some(crate::exec::SessionAuditSubstrate {
            tenant_id: c.admitted.plan.tenant.0.clone(),
            plan_json,
            bundle_json: None,
        }))
    }
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

/// Whether the admitted plan must be persisted to `<state_dir>/plan.json`
/// *before* `backend.start()`. Every backend whose `start()` reads that file
/// off disk to decide whether to stand up its egress moat needs the pre-start
/// persist:
///
/// - **Firecracker**: the nft TAP-redirect moat reads the plan at spawn time.
/// - **vz / libkrun (macOS)**: the substitution endpoint reads
///   `<state_dir>/plan.json` inside `start()` to decide whether to spawn.
///
/// QEMU is excluded: it reads the in-memory config and must not overwrite the
/// persisted plan.
pub(super) fn persists_plan_before_start(hypervisor: &str) -> bool {
    matches!(hypervisor, "firecracker" | "vz" | "libkrun")
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
    /// Bind a named secret to an egress destination (format:
    /// NAME:HOST[,HOST...]). Adds a `SecretRef` to the workload — the guest
    /// only ever sees a placeholder; the host substitutes the real credential
    /// on outbound requests to the allow-listed hosts. Bearer auth +
    /// env-var mount by default; use `mvmctl secret set` for sigv4/hmac/file.
    /// Repeatable.
    #[arg(long = "secret")]
    pub secret: Vec<String>,
    /// Auto-forward declared ports after boot (blocks until Ctrl-C)
    #[arg(long)]
    pub forward: bool,
    /// Bind a Prometheus metrics endpoint on this port (0 = disabled)
    #[arg(long, default_value = "0")]
    pub metrics_port: u16,
    /// Keep this many prelaunched supervisor standbys warm so the next
    /// auto-named `up` claims one instead of cold-booting. Omit to use the
    /// residency-policy default (`MVM_RESIDENCY`); pass `0` to disable.
    /// Supported by Firecracker, libkrun, and platform-gated Vz.
    #[arg(long)]
    pub warm_pool_size: Option<u32>,
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
    /// Named security profile selecting the per-seam capability matrix
    /// (seccomp tier + egress posture). Defaults to `production`: the
    /// highest-security, deployable posture (seccomp floor + deny-all egress).
    /// The only alternative is `dev` — looser for development and never
    /// deployable (refused under `--prod`). Explicit `--seccomp` /
    /// `--network-preset` override the profile.
    #[arg(long = "security-profile")]
    pub security_profile: Option<String>,
    /// Seccomp profile tier (essential, minimal, standard, network, unrestricted).
    ///
    /// Overrides the `--security-profile` seccomp tier. `unrestricted` is
    /// opt-in only; the project's posture is "defaults must be safe."
    #[arg(long)]
    pub seccomp: Option<String>,
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
    /// Pin the workload kernel to the locally-built slim kernel in the mvm
    /// cache (`mvmctl build kernel build --which workload`). When set, the
    /// boot path uses the cached workload kernel instead of whatever the
    /// image shipped; the image's own kernel file is ignored. If the cache
    /// entry is absent, the boot fails with a clear build hint.
    #[arg(long = "kernel-pin")]
    pub kernel_pin: Option<String>,
    /// Scrub undeclared secrets/PII on egress to HOST (masks); `HOST=audit` only
    /// reports. Repeatable. Per-destination egress redaction.
    #[arg(long = "redact", value_name = "HOST[=audit]")]
    pub redact: Vec<String>,
}

pub(in crate::commands) struct PersistentImageStartParams<'a> {
    pub name: &'a str,
    pub image_label: &'a str,
    pub resolved_digest: &'a str,
    pub rootfs_path: &'a std::path::Path,
    pub profile: &'a str,
    pub cpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    pub volumes: &'a [image::RuntimeVolume],
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
    pub auth: mvm_core::plan::AuthPolicy,
    /// Override the backend (test escape; `None` = auto-detect).
    pub hypervisor_override: Option<&'a str>,
    /// Skip plan-admission signing (test escape).
    pub no_supervisor: bool,
    /// Pre-built kernel path: skips `ensure_default_microvm_image` when set.
    pub kernel_path: Option<String>,
}

fn register_vm_name(vm_name: &str, network_name: &str) {
    let registry_path = mvm::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
        registry.deregister(vm_name);
        let _ = registry.register_with_metadata(mvm::vm::name_registry::RegisterParams {
            name: vm_name,
            vm_dir: "",
            network: network_name,
            guest_ip: None,
            slot_index: 0,
            tags: std::collections::BTreeMap::new(),
            expires_at: None,
            auto_resume: true,
        });
        let _ = registry.save(&registry_path);
    }
}

pub(in crate::commands) fn start_persistent_oci_machine(
    params: PersistentImageStartParams<'_>,
) -> Result<()> {
    let PersistentImageStartParams {
        name,
        image_label,
        resolved_digest,
        rootfs_path,
        profile,
        cpus,
        memory_mib,
        mem_initial_mib,
        volumes,
        network_policy,
        auth,
        hypervisor_override,
        no_supervisor,
        kernel_path,
    } = params;
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    let effective_hypervisor = hypervisor_override
        .map(String::from)
        .unwrap_or_else(|| super::shared::resolve_effective_hypervisor("firecracker"));
    let kernel_path = if let Some(k) = kernel_path {
        k
    } else {
        let (k, _) = ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Dev)?;
        k
    };
    register_vm_name(name, "default");

    let backend = AnyBackend::from_hypervisor(&effective_hypervisor);
    let admission_ledger = InMemoryNonceLedger::new();
    let admission = admit_plan_for_boot(AdmitPlanForBootParams {
        tenant: "local",
        vm_name: name,
        backend_name: &effective_hypervisor,
        rootfs_path,
        precomputed_image_sha256: None,
        cpus,
        mem_mib: u64::from(memory_mib),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: mvm_core::plan::SecretReleasePolicy::default(),
        secrets: vec![],
        auth,
        no_supervisor,
        ledger: &admission_ledger,
        keys_dir: None,
        audit_dir: None,
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: shares_from_volume_cfg(volumes),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: network_policy.clone(),
    })?;
    let mut start_config = VmStartParams {
        name: name.to_string(),
        rootfs_path: rootfs_path.display().to_string(),
        vmlinux_path: kernel_path,
        initrd_path: None,
        verity_path: None,
        roothash: None,
        revision_hash: resolved_digest.to_string(),
        flake_ref: format!("oci:{image_label}"),
        profile: Some(profile.to_string()),
        cpus,
        memory_mib,
        mem_initial_mib,
        volumes,
        config_files: &[],
        secret_files: &[],
        port_mappings: &[],
        // Persistent named machines are long-lived; they are not transient
        // auto-named launches and are never claimed from the warm standby pool.
        warm_pool_size: 0,
        network_policy,
    }
    .into_start_config();
    // A persistent named/detached machine is dev-accessible for its lifetime:
    // `machine run -t` boots through here, and `machine shell` / `machine
    // console` attach to it later. Pre-open the interactive-console data range
    // so those attaches reach the agent's dynamic data port on the
    // per-port-UDS backends (libkrun, Vz). Claim 15 still bars a sealed prod
    // guest at the agent + `enforce_accessible_gate`, leaving the listeners
    // inert there.
    start_config.dev_console = true;
    attach_runtime_overlay_if_cached(&mut start_config, &effective_hypervisor);
    if let Some(ctx) = admission.as_ref() {
        thread_tenant_id(&mut start_config, &ctx.admitted);
        populate_audit_substrate(&mut start_config, &ctx.admitted, ctx.policy_bundle.as_ref())?;
        if persists_plan_before_start(&effective_hypervisor) {
            stash_plan_for_bridge(&start_config)?;
        }
    }
    enforce_shares_if(&admission, &start_config.volumes)?;
    if let Err(err) = mvm_backend::workload_backend::require_workload_backend(&backend) {
        emit_failed_if(&admission, "backend-start", &err);
        return Err(err);
    }
    if let Err(err) = backend.start(&start_config) {
        emit_failed_if(&admission, "backend-start", &err);
        return Err(err);
    }
    emit_launched_if(&admission, &effective_hypervisor);
    record_vm_readiness(name, InstanceReadiness::LaunchAccepted);
    mvm_core::audit_emit!(VmStart, vm: name);
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
/// out-of-process backends (vz and firecracker) need a real kernel file;
/// fall back to the cached builder-VM kernel — the same kernel the builder
/// and dev VMs boot — rather than handing them a missing path.
///
/// Firecracker's direct/manifest boot path already performs this same
/// fallback; without it here the flake path would refuse a kernel-less
/// mkGuest workload that the manifest path boots fine.
pub(super) fn resolve_workload_kernel(
    vmlinux_path: &str,
    hypervisor: &str,
) -> anyhow::Result<String> {
    if std::path::Path::new(vmlinux_path).exists() {
        return Ok(vmlinux_path.to_string());
    }
    // `virtualization` is the long-form alias the backend dispatcher
    // accepts for vz; missing it here would skip the fallback and hand
    // the backend a nonexistent kernel path. libkrun supplies its own
    // bundled kernel, so it never needs the fallback.
    if !matches!(hypervisor, "vz" | "virtualization" | "firecracker") {
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

/// Resolve the locally-built workload kernel from the mvm cache for a
/// `--kernel-pin` boot. Does not fall back to the image-supplied kernel or
/// the builder-VM fallback: the pin is explicit, so an absent cache entry
/// is always a hard error with a build hint.
///
/// Returns `Ok(path_string)` when the kernel is cached, `Err` otherwise with
/// a message that names the required build command.
pub(super) fn resolve_pinned_kernel(
    cache_dir: &std::path::Path,
    arch: &str,
    source_checkout: bool,
) -> anyhow::Result<String> {
    use mvm_build::kernel_fetch::{KernelResolution, resolve_kernel};
    match resolve_kernel(cache_dir, arch, "workload", source_checkout) {
        KernelResolution::Cached(p) => Ok(p.display().to_string()),
        KernelResolution::NeedsBuild(p) => {
            anyhow::bail!(
                "kernel-pin: workload kernel not built yet (expected at {}); \
                 run `mvmctl build kernel build --which workload` first",
                p.display()
            )
        }
        KernelResolution::NeedsFetch(_) => {
            anyhow::bail!(
                "kernel-pin: fetching pre-built workload kernels is not yet supported on \
                 installed binaries; build from source or omit --kernel-pin"
            )
        }
    }
}

/// Resolve a `--kernel-pin` request to a concrete workload-kernel path, or
/// `None` when no pin was requested (the caller then falls back to the image's
/// own kernel / the default microVM image). The pin selects the locally-built
/// workload kernel from the mvm cache; presence is the signal — the value is a
/// human label only. Shared by the canonical `machine run` boot path.
pub(in crate::commands) fn resolve_kernel_pin_path(pinned: bool) -> anyhow::Result<Option<String>> {
    if !pinned {
        return Ok(None);
    }
    let cache_dir = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    let source_checkout = super::super::env::dev_vz::find_builder_vm_flake_is_source_checkout();
    Ok(Some(resolve_pinned_kernel(
        &cache_dir,
        arch,
        source_checkout,
    )?))
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
mod resolve_workload_kernel_tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn existing_path_passes_through_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let vmlinux = tmp.path().join("vmlinux");
        std::fs::write(&vmlinux, b"kernel").unwrap();
        let result = resolve_workload_kernel(vmlinux.to_str().unwrap(), "vz").unwrap();
        assert_eq!(result, vmlinux.to_str().unwrap());
    }

    #[test]
    fn non_vz_hypervisor_passes_through_even_when_missing() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_CACHE_DIR", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "libkrun").unwrap();
        assert_eq!(result, "/nonexistent/vmlinux");
    }

    #[test]
    fn vz_missing_kernel_falls_back_to_builder_vm_cache() {
        let mut env = TestEnv::new();
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
        env.set("MVM_CACHE_DIR", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "vz").unwrap();
        assert_eq!(result, fallback.to_str().unwrap());
    }

    #[test]
    fn firecracker_missing_kernel_falls_back_to_builder_vm_cache() {
        // The firecracker flake path must reuse the cached builder-VM
        // kernel for a kernel-less mkGuest workload, exactly as the
        // firecracker manifest path does — otherwise a `sleeper`-style
        // image (no emitted vmlinux) can't boot under firecracker.
        let mut env = TestEnv::new();
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
        env.set("MVM_CACHE_DIR", tmp.path());
        let result = resolve_workload_kernel("/nonexistent/vmlinux", "firecracker").unwrap();
        assert_eq!(result, fallback.to_str().unwrap());
    }

    #[test]
    fn vz_both_missing_returns_error_mentioning_dev_up() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_CACHE_DIR", tmp.path());
        let err = resolve_workload_kernel("/nonexistent/vmlinux", "vz").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dev up"), "expected 'dev up' in: {msg}");
        assert!(msg.contains("vz"), "expected hypervisor name in: {msg}");
    }
}

#[cfg(test)]
mod resolve_pinned_kernel_tests {
    use super::*;

    #[test]
    fn cached_kernel_returns_its_path() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel_path =
            mvm_build::kernel_fetch::cached_kernel_path(tmp.path(), "aarch64", "workload");
        std::fs::create_dir_all(kernel_path.parent().unwrap()).unwrap();
        std::fs::write(&kernel_path, b"vmlinux").unwrap();
        let result = resolve_pinned_kernel(tmp.path(), "aarch64", true).unwrap();
        assert_eq!(result, kernel_path.display().to_string());
    }

    #[test]
    fn source_checkout_without_cache_returns_err_with_build_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_pinned_kernel(tmp.path(), "aarch64", true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mvmctl build kernel build"),
            "expected build hint in: {msg}"
        );
    }

    #[test]
    fn installed_binary_without_cache_returns_err_about_fetch_not_supported() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_pinned_kernel(tmp.path(), "x86_64", false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not yet supported"),
            "expected fetch-unsupported note in: {msg}"
        );
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
    fn admission_plan_carries_ssh_agent_auth_policy() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"ssh agent rootfs");
        let ledger = InMemoryNonceLedger::new();
        let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
            tenant: "local",
            vm_name: "vm-auth",
            backend_name: "firecracker",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 2,
            mem_mib: 512,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            auth: mvm_core::plan::AuthPolicy::ssh_agent_socket(),
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
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_eq!(
            ctx.admitted.plan.auth,
            mvm_core::plan::AuthPolicy::ssh_agent_socket()
        );
        let signed_json = serde_json::to_string(&ctx.admitted.signed).expect("signed plan json");
        let signed: mvm_core::plan::SignedExecutionPlan =
            serde_json::from_str(&signed_json).expect("signed envelope parses");
        let plan: mvm_core::plan::ExecutionPlan =
            serde_json::from_slice(&signed.0.payload).expect("payload plan parses");
        assert_eq!(plan.auth.mode, mvm_core::plan::AuthMode::SshAgentSocket);

        let audit_path = audit_dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&audit_path).expect("audit file exists");
        assert!(
            content.contains("ssh-agent-socket"),
            "plan.admitted audit should carry auth policy: {content}"
        );
    }

    // The shared untrusted-transient admit closure (used by both `mvmctl run`
    // and the MCP code-runner) must produce a real audit substrate — a
    // non-empty `tenant_id` + signed `plan_json`. That substrate is precisely
    // what makes the libkrun/Vz supervisor spawn the enforcing gateway bridge,
    // so a `Some` here is the proof that a deny-all is no longer inert on the
    // bridge backends (the bug: the MCP path passed `admit = None`).
    #[test]
    fn untrusted_transient_admit_yields_bridge_substrate() {
        let keys_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = write_rootfs(rootfs_dir.path(), b"untrusted code rootfs");

        let admit = untrusted_transient_admit_in(
            "firecracker".to_string(),
            2,
            1024,
            Some(keys_dir.path().to_path_buf()),
            Some(audit_dir.path().to_path_buf()),
        );
        let substrate = admit(&rootfs, "mcp-cold-vm")
            .expect("admission runs")
            .expect("untrusted transient run is admitted (Some), not bypassed");

        assert_eq!(substrate.tenant_id, "local");
        assert!(
            !substrate.plan_json.is_empty(),
            "the signed plan must travel to the backend so the bridge spawns"
        );
        assert!(
            substrate.bundle_json.is_none(),
            "the bare untrusted path pins no bundle"
        );
        // The admission emitted its `plan.admitted` chain entry to the isolated
        // audit dir, confirming the closure went through real admission.
        let chain = std::fs::read_to_string(audit_dir.path().join("local.jsonl"))
            .expect("audit chain file exists");
        assert!(chain.contains("plan.admitted"));
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            auth: mvm_core::plan::AuthPolicy::none(),
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
            backend_name: "vz",
            rootfs_path: &rootfs,
            precomputed_image_sha256: None,
            cpus: 1,
            mem_mib: 128,
            seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
            secret_release: mvm_core::plan::SecretReleasePolicy::None,
            secrets: Vec::new(),
            auth: mvm_core::plan::AuthPolicy::none(),
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
        })
        .expect("admission")
        .expect("Some when admission ran");

        assert_ne!(ctx.admitted.plan.network_policy.0, LOCAL_DEFAULT);
        let bundle = ctx.policy_bundle.expect("generated policy bundle");
        assert_eq!(bundle.egress.mode.as_deref(), Some("open"));
        assert!(bundle.network.l4.is_empty());
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
                auth: mvm_core::plan::AuthPolicy::none(),
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
                agent_verbs: None,
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
