//! In-process local-run seam: boot a host-materialized rootfs through the
//! signed-plan admission gate without shelling out to the CLI.
//!
//! [`admit_and_boot_local`] is the thin, safe-by-default entrypoint the
//! `mvm-client` local backend calls. It hashes the already-materialized
//! `rootfs.ext4`, synthesizes an `ExecutionPlan` with the conservative facade
//! defaults (deny-all egress, standard seccomp, no secrets, no bundle, no
//! host-fs shares), and hands the whole thing to [`admit_and_start`]. The
//! backend never boots until the plan is signed, verified, inside its validity
//! window, and non-replayed — the same gate `mvmctl up`/`run` go through.
//!
//! The richer knobs the CLI threads (secrets, bundle pins, deps volumes,
//! per-destination redaction) are deliberately absent: the facade
//! `MachineSpec` does not carry them, so exposing them here would invent a
//! surface no caller can fill. When a driver needs them it uses the CLI
//! admission path directly. Egress is the exception, and only because the
//! facade grew a way to say it: an egress *grant* is carried, and the launch
//! config's policy is derived from it, so the plan the boot was signed under
//! and the policy the gate reads come from one authored value.
//!
//! One request shape skips synthesis: a `LocalRunRequest` carrying a
//! `signed_plan` admits that externally-signed envelope instead — verified
//! against the operator-pinned `trusted_plan_signers`, never re-signed under
//! the host key — with the plan body (not the request's sizing fields) as the
//! authority for what boots.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_core::vm_backend::{VmStartConfig, VmVolume};
use mvm_runtime::AnyBackend;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::{
    AdmitAndStartParams, Clock, InMemoryNonceLedger, StartedMachine, admit_and_start,
};

/// The tenant every locally-run machine is admitted under. Local runs are
/// single-tenant by construction (one host, one operator), so the audit chain
/// and gateway substrate key off this fixed label rather than a fleet tenant.
pub(crate) const LOCAL_TENANT: &str = "local";

/// A minimal, safe-by-default request to admit and boot a locally-materialized
/// rootfs. The caller resolves the image to `rootfs_path` (and its optional
/// dm-verity sidecars) before constructing this; everything security-relevant
/// that the facade doesn't expose defaults to the most restrictive value.
pub struct LocalRunRequest {
    /// Machine name — also the synthesized plan's `image_name` and the mock
    /// backend's per-VM directory key.
    pub name: String,
    /// Absolute path to the already-materialized ext4 rootfs. Hashed for the
    /// plan's `image_sha256`, so it must exist and be readable.
    pub rootfs_path: PathBuf,
    /// Kernel image path. `None` for backends that carry their own kernel
    /// (libkrun's bundled kernel, the mock backend); `Some` for Firecracker.
    pub kernel_path: Option<PathBuf>,
    /// dm-verity Merkle-tree sidecar, paired with `roothash`. Both `Some` for a
    /// verified-boot rootfs; both `None` otherwise.
    pub verity_path: Option<PathBuf>,
    /// 64-char lowercase-hex dm-verity root hash, paired with `verity_path`.
    pub roothash: Option<String>,
    pub cpus: u32,
    pub mem_mib: u32,
    /// Backend name recorded in the signed plan (`firecracker`, `libkrun`,
    /// `mock`, …) — must match the backend the caller starts.
    pub backend_name: String,
    /// Volumes to attach. Every entry is baked into the signed plan's
    /// `shares` (same order, `uvol{idx}` tags) and onto the launch config, so
    /// the claim-1 admitted-shares gate passes exactly when the two agree —
    /// no host-fs grant reaches the guest outside the signed plan.
    pub volumes: Vec<VmVolume>,
    /// Recorded plan intent: `true` for a transient run-to-completion
    /// workload, `false` for a persistent machine that outlives the
    /// admitting call.
    pub destroy_on_exit: bool,
    /// What this workload is permitted to consume or reach. Baked into the
    /// signed plan and checked against the host's ceiling during admission; the
    /// egress dimension additionally becomes the launch config's network
    /// policy, so what the gate enforces is what the plan was signed for.
    /// `None` keeps the pre-grant baseline: no CPU cap, no wall-clock bound,
    /// deny-all egress.
    pub grants: Option<mvm_contract::grants::Grants>,
    /// An externally-signed plan to admit instead of synthesizing and
    /// self-signing one — a fleet-issued plan whose signer the operator pinned
    /// in the host config's `trusted_plan_signers`.
    ///
    /// When present, the plan is the authority: sizing, grants, and teardown
    /// intent come from it (the `cpus` / `mem_mib` / `grants` /
    /// `destroy_on_exit` fields above are not consulted), and the resolved
    /// rootfs must hash to the plan's pinned image digest. `None` is every
    /// ordinary local run, which synthesizes its plan as before.
    pub signed_plan: Option<mvm_core::plan::SignedExecutionPlan>,
}

/// Admission substrate for a local run: the clock and replay ledger that drive
/// the validity-window + nonce checks, plus an optional host-signer keys dir
/// override (production passes `None` → `~/.mvm/keys/`; tests inject a tempdir).
pub struct LocalRunContext<'a> {
    pub clock: &'a dyn Clock,
    pub ledger: &'a InMemoryNonceLedger,
    pub host_signer_keys_dir: Option<&'a Path>,
    /// Chain-signed audit emitter for `plan.admitted` / `plan.launched` /
    /// `plan.failed` entries around this admission. `None` skips emission
    /// (the caller owns its own audit wiring, e.g. the CLI's up path).
    pub emitter: Option<&'a AuditEmitter>,
    /// An operator-declared assurance campaign to open against this boot.
    ///
    /// `None` — the default everywhere except a run that explicitly asked for
    /// one — means no assurance work happens at all, so campaign discovery
    /// never sits on the ordinary launch path.
    pub assurance: Option<&'a crate::assurance_session::CampaignRequest>,
}

/// Build the signed-plan host-fs grant list from the launch volume set. The
/// `uvol{idx}` tag matches the id the backend assigns when it attaches each
/// volume (same `VmStartConfig.volumes` order), so the admitted grants line
/// up 1:1 with what actually gets attached — the claim-1 check compares them.
pub fn shares_from_vm_volumes(volumes: &[VmVolume]) -> Vec<mvm_core::plan::HostShareGrant> {
    volumes
        .iter()
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

/// Attach the verity-sealed runtime overlay (the guest-binary disk carrying
/// the agent) from the version-keyed cache, through the same resolver the
/// CLI's boot paths consume (`RuntimeOverlayResolver` +
/// `resolve_or_seed_from_default_cache` — a pure cache probe: no build, no
/// download, no nix). Without the overlay a runtime-lean OCI rootfs has no
/// guest agent to exec and panics init, so this runs on every in-process
/// boot exactly as it does on the CLI path. Non-fatal on a cold cache under
/// `PreferOverlay` (the guest falls back to a baked agent when it has one);
/// fails closed when the policy is `RequiredOverlay`.
pub(crate) fn attach_runtime_overlay_from_cache(
    config: &mut VmStartConfig,
    backend_name: &str,
) -> Result<()> {
    use mvm_build::runtime_overlay::{RuntimeOverlayResolver, resolve_or_seed_from_default_cache};
    if !matches!(backend_name, "firecracker" | "hvf" | "qemu" | "libkrun") {
        return Ok(());
    }
    let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let resolver = RuntimeOverlayResolver::new(cache_root, env!("CARGO_PKG_VERSION").to_string());
    match resolve_or_seed_from_default_cache(&resolver, mvm_core::arch::GuestArch::host()) {
        Ok(artifact) => {
            config.runtime_overlay_path = Some(artifact.overlay_ext4.display().to_string());
            config.runtime_overlay_verity_path = Some(artifact.sidecar.display().to_string());
            config.runtime_overlay_roothash = Some(artifact.roothash);
            config.runtime_overlay_version = Some(artifact.version);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "runtime overlay required for {backend_name} boot but unavailable: {e}"
        )),
    }
}

/// Admit `req` through the signed-plan gate and boot it on `backend`.
///
/// On success the plan was either synthesized here and signed under the host
/// key, or — when `req.signed_plan` carries a fleet-issued envelope — verified
/// against the operator-pinned `trusted_plan_signers`; in both cases it was
/// verified, inside its validity window, and non-replayed before the backend
/// saw a single byte of launch config. Any failure returns with no VM created.
pub fn admit_and_boot_local(
    backend: &AnyBackend,
    req: &LocalRunRequest,
    ctx: LocalRunContext<'_>,
) -> Result<StartedMachine> {
    let sha = mvm_core::crypto::image_verify::sha256_file_cached(&req.rootfs_path)
        .with_context(|| format!("hashing rootfs at {}", req.rootfs_path.display()))?;

    // An externally-signed plan takes the other admission door: verified
    // against the operator-pinned signer set, never synthesized or re-signed
    // under the host key.
    if let Some(signed) = req.signed_plan.as_ref() {
        return admit_signed_and_boot_local(backend, req, signed, &sha, ctx);
    }

    // Pin the kernel into the signed plan. Deliberately the uncached digest: a
    // path+mtime-keyed cache can hand back a stale hash, which for an integrity
    // pin would defeat the point of having one.
    let kernel_sha = req
        .kernel_path
        .as_ref()
        .map(|k| {
            mvm_core::crypto::image_verify::sha256_file(k)
                .with_context(|| format!("hashing kernel at {}", k.display()))
        })
        .transpose()?;

    let synthesis = SynthesisInput {
        grants: req.grants.clone(),
        stream_edges: Vec::new(),
        kernel_sha256: kernel_sha.as_deref(),
        network_mode: Default::default(),
        ingress: Vec::new(),
        vm_name: &req.name,
        tenant: Some(LOCAL_TENANT),
        backend_name: &req.backend_name,
        image_name: &req.name,
        image_sha256: &sha,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: req.cpus,
        mem_mib: u64::from(req.mem_mib),
        disk_mib: 0,
        boot_timeout_secs: 60,
        // A persistent local machine outlives the admitting call; a transient
        // run-to-completion workload records the teardown intent.
        destroy_on_exit: req.destroy_on_exit,
        bundle_pin: None,
        deps_volume: None,
        shares: shares_from_vm_volumes(&req.volumes),
        redaction: Default::default(),
        reversible_replacement: Default::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    };

    let path_string = |p: &Path| p.to_string_lossy().into_owned();
    let mut config = VmStartConfig {
        name: req.name.clone(),
        rootfs_path: path_string(&req.rootfs_path),
        kernel_path: req.kernel_path.as_deref().map(path_string),
        verity_path: req.verity_path.as_deref().map(path_string),
        roothash: req.roothash.clone(),
        cpus: req.cpus,
        memory_mib: req.mem_mib,
        volumes: req.volumes.clone(),
        tenant_id: Some(LOCAL_TENANT.to_string()),
        // With no egress grant the deny-all default from `VmStartConfig` stands;
        // a granted allow-list is projected onto it, so the policy the gate
        // enforces is derived from the same grants the plan was signed for.
        network_policy: match req.grants.as_ref() {
            Some(grants) if grants.egress.is_some() => {
                mvm_contract::grants::projection::network_policy_from_grants(grants)
            }
            _ => mvm_core::network_policy::NetworkPolicy::deny_all(),
        },
        ..Default::default()
    };
    attach_runtime_overlay_from_cache(&mut config, &req.backend_name)?;

    admit_and_start(
        backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: ctx.clock,
            ledger: ctx.ledger,
            host_signer_keys_dir: ctx.host_signer_keys_dir,
            bundle_ctx: None,
            extension_ctx: None,
            variant: mvm_core::plan::Variant::Dev,
            policy_bundle: None,
            emitter: ctx.emitter,
            // The local boot path launches unsealed (`sealed: false` above)
            // and issues no attenuated verb grant, so it is not the tier whose
            // admission has to be provable afterwards. Stated rather than
            // defaulted: a run that silently picks its own audit durability is
            // how this control erodes.
            audit_durability: crate::audit::durability::AuditDurability::BestEffort,
            assurance: ctx.assurance,
        },
    )
}

/// Admit an externally-signed plan through
/// [`crate::plan_admission::admit_signed_plan_for_run`] and boot it on
/// `backend` — the local-run tail for the fleet-issued seam.
///
/// The admitted plan, not the request, decides what runs: sizing, grants, and
/// teardown intent are read from the verified plan body, and the resolved
/// rootfs must hash to the image digest the plan pins — otherwise the host
/// would be booting bytes the signer never authorized. The caller's
/// `cpus`/`mem_mib`/`grants`/`destroy_on_exit` are not consulted here;
/// `admit_and_boot_local` only routes here when `req.signed_plan` is set.
fn admit_signed_and_boot_local(
    backend: &AnyBackend,
    req: &LocalRunRequest,
    signed: &mvm_core::plan::SignedExecutionPlan,
    rootfs_sha: &str,
    ctx: LocalRunContext<'_>,
) -> Result<StartedMachine> {
    use crate::plan_admission::{RunPosture, StartAdmittedParams, start_admitted};

    let posture = RunPosture::on_backend(mvm_core::plan::Variant::Dev, backend.kind());
    let admitted = crate::plan_admission::admit_signed_plan_for_run(
        signed, ctx.clock, ctx.ledger, None, posture,
    )?;
    let plan = admitted.plan();

    // The plan pins the workload image by digest; the resolved rootfs must BE
    // that image. Synthesized plans get this by construction (synthesis stamps
    // the hash it just measured); an externally-signed plan gets it by
    // comparison.
    if rootfs_sha != plan.image.sha256 {
        anyhow::bail!(
            "the signed plan pins image sha256 {} but the resolved rootfs at {} hashes to \
             {rootfs_sha}; refusing to boot an image the plan does not authorize",
            plan.image.sha256,
            req.rootfs_path.display(),
        );
    }

    let path_string = |p: &Path| p.to_string_lossy().into_owned();
    let mut config = VmStartConfig {
        name: req.name.clone(),
        rootfs_path: path_string(&req.rootfs_path),
        kernel_path: req.kernel_path.as_deref().map(path_string),
        verity_path: req.verity_path.as_deref().map(path_string),
        roothash: req.roothash.clone(),
        cpus: plan.resources.cpus,
        memory_mib: u32::try_from(plan.resources.mem_mib)
            .context("plan memory does not fit the launch config")?,
        volumes: req.volumes.clone(),
        tenant_id: Some(plan.tenant.0.clone()),
        // The plan's egress grant projects onto the launch config's policy,
        // exactly as a synthesized plan's does: what the gate enforces is what
        // the plan was signed for. No grant means deny-all.
        network_policy: match plan.grants.as_ref() {
            Some(grants) if grants.egress.is_some() => {
                mvm_contract::grants::projection::network_policy_from_grants(grants)
            }
            _ => mvm_core::network_policy::NetworkPolicy::deny_all(),
        },
        ..Default::default()
    };
    attach_runtime_overlay_from_cache(&mut config, &req.backend_name)?;

    crate::audit::durability::record_admission(
        ctx.emitter,
        plan,
        admitted.signer_id(),
        crate::audit::durability::AuditDurability::BestEffort,
    )?;

    start_admitted(StartAdmittedParams {
        backend,
        admitted,
        config,
        policy_bundle: None,
        emitter: ctx.emitter,
        assurance: ctx.assurance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan_admission::SystemClock;
    use mvm_core::util::test_env::TestEnv;

    /// A local run over the mock backend admits a signed plan and boots — no
    /// subprocess, no CLI. Proves the seam the local backend calls is real.
    #[test]
    fn admit_and_boot_local_over_mock_boots_admitted_plan() {
        let data = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(data.path());
        let keys = tempfile::tempdir().unwrap();

        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"not-a-real-ext4-but-hashable\n").unwrap();

        let backend = AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let req = LocalRunRequest {
            name: "local-run-seam-test".into(),
            rootfs_path: rootfs,
            kernel_path: None,
            verity_path: None,
            roothash: None,
            cpus: 1,
            mem_mib: 128,
            backend_name: "mock".into(),
            volumes: Vec::new(),
            destroy_on_exit: false,
            grants: None,
            signed_plan: None,
        };

        let started = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
                emitter: None,
                assurance: None,
            },
        )
        .expect("admit + boot over mock");

        assert_eq!(started.vm_id.0, "local-run-seam-test");
        assert_eq!(started.admitted.plan().tenant.0, LOCAL_TENANT);
        // The plan was actually signed under the host key (proves admission,
        // not a stub): a signer id is present and the plan bound the exact
        // rootfs bytes we handed it (64-hex sha256) on our backend.
        assert!(!started.admitted.signer_id().is_empty());
        assert_eq!(started.admitted.plan().image.sha256.len(), 64);
        assert_eq!(started.admitted.plan().runtime_profile.0, "mock");
    }

    /// The launch volume set is baked into the signed plan's shares in the
    /// same order and with matching tags/kinds, so the claim-1 gate passes
    /// exactly when the attached volumes are the admitted ones.
    #[test]
    fn shares_mirror_the_launch_volume_set() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let volumes = vec![
            VmVolume {
                materialized_image: None,
                volume_label: None,
                host: "/h/work.ext4".into(),
                guest: "/data/work".into(),
                size: "16M".into(),
                read_only: true,
                kind: VmVolumeKind::Disk,
                encrypted: false,
            },
            VmVolume {
                materialized_image: None,
                volume_label: None,
                host: "/h/src".into(),
                guest: "/data/src".into(),
                size: String::new(),
                read_only: false,
                kind: VmVolumeKind::DirShare,
                encrypted: false,
            },
        ];
        let shares = shares_from_vm_volumes(&volumes);
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].tag, "uvol0");
        assert_eq!(shares[0].kind, mvm_core::plan::ShareKind::Disk);
        assert!(shares[0].read_only);
        assert_eq!(shares[1].tag, "uvol1");
        assert_eq!(shares[1].kind, mvm_core::plan::ShareKind::DirShare);
        assert_eq!(shares[1].guest_path, "/data/src");
        assert!(shares_from_vm_volumes(&[]).is_empty());
    }

    /// A boot with a volume passes the claim-1 admitted-shares gate (the
    /// plan's shares and the config's volumes come from one source), and the
    /// wired emitter records the admitted → launched pair.
    #[test]
    fn admit_and_boot_local_admits_volumes_and_emits_chain_entries() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let data = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(data.path());
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();

        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable\n").unwrap();
        let volume = data.path().join("work.ext4");
        std::fs::write(&volume, b"volume-bytes\n").unwrap();

        let signer = crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let emitter =
            crate::audit::emitter::AuditEmitter::with_dir(signer.signing, audit.path()).unwrap();

        let backend = AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let req = LocalRunRequest {
            name: "local-run-volumes".into(),
            rootfs_path: rootfs,
            kernel_path: None,
            verity_path: None,
            roothash: None,
            cpus: 1,
            mem_mib: 128,
            backend_name: "mock".into(),
            volumes: vec![VmVolume {
                materialized_image: None,
                volume_label: None,
                host: volume.to_string_lossy().into_owned(),
                guest: "/data/work".into(),
                size: String::new(),
                read_only: true,
                kind: VmVolumeKind::Disk,
                encrypted: false,
            }],
            destroy_on_exit: true,
            grants: None,
            signed_plan: None,
        };
        let started = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
                emitter: Some(&emitter),
                assurance: None,
            },
        )
        .expect("admitted boot with a volume");
        assert_eq!(started.admitted.plan().shares.len(), 1);
        assert_eq!(started.admitted.plan().shares[0].guest_path, "/data/work");
        assert!(started.admitted.plan().post_run.destroy_on_exit);

        let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
        assert!(chain.contains("plan.admitted"), "got: {chain}");
        assert!(chain.contains("plan.launched"), "got: {chain}");
    }

    /// A refusal in a post-admission gate (here the SDK-sidecar gate: a
    /// volume at the sidecar mount point with no SDK service binding) still
    /// terminates the chain — `plan.admitted` is followed by a `plan.failed`
    /// naming the refusing stage, never left dangling.
    #[test]
    fn gate_refusal_after_admission_emits_plan_failed() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let data = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(data.path());
        let keys = tempfile::tempdir().unwrap();
        let audit = tempfile::tempdir().unwrap();

        let rootfs = data.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"hashable\n").unwrap();
        let sidecar = data.path().join("sdk.ext4");
        std::fs::write(&sidecar, b"sidecar-bytes\n").unwrap();

        let signer = crate::audit::host_keypair::load_or_init_at(keys.path()).unwrap();
        let emitter =
            crate::audit::emitter::AuditEmitter::with_dir(signer.signing, audit.path()).unwrap();

        let backend = AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let req = LocalRunRequest {
            name: "local-run-gate-refusal".into(),
            rootfs_path: rootfs,
            kernel_path: None,
            verity_path: None,
            roothash: None,
            cpus: 1,
            mem_mib: 128,
            backend_name: "mock".into(),
            volumes: vec![VmVolume {
                materialized_image: None,
                volume_label: None,
                host: sidecar.to_string_lossy().into_owned(),
                guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
                size: String::new(),
                read_only: true,
                kind: VmVolumeKind::Disk,
                encrypted: false,
            }],
            destroy_on_exit: true,
            grants: None,
            signed_plan: None,
        };
        let err = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
                emitter: Some(&emitter),
                assurance: None,
            },
        )
        .expect_err("the SDK-sidecar gate must refuse");
        assert!(
            format!("{err:#}").contains("binds no SDK host service"),
            "got: {err:#}"
        );

        let chain = std::fs::read_to_string(audit.path().join("local.jsonl")).unwrap();
        assert!(chain.contains("plan.admitted"), "got: {chain}");
        assert!(chain.contains("plan.failed"), "got: {chain}");
        assert!(chain.contains("sdk-sidecar"), "got: {chain}");
        assert!(
            !chain.contains("plan.launched"),
            "a refused launch must not read as launched: {chain}"
        );
    }

    /// The overlay attachment mirrors the CLI's matrix: workload VMM
    /// backends probe the version-keyed cache (cold cache falls back to a
    /// legacy boot under `PreferOverlay`, fails closed under
    /// `RequiredOverlay`); non-VMM backends (the mock) skip entirely.
    #[test]
    fn runtime_overlay_attachment_fails_closed_on_a_cold_cache() {
        let data = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(data.path());

        // Mock backend: never probed, fields untouched.
        let mut config = VmStartConfig::default();
        attach_runtime_overlay_from_cache(&mut config, "mock").expect("mock skips");
        assert!(config.runtime_overlay_path.is_none());

        // A real backend with a cold cache fails closed. There is no second
        // arm any more: the overlay is the only source of the guest binaries,
        // so "boot anyway with nothing attached" is not a posture a backend
        // can select.
        let mut config = VmStartConfig {
            ..Default::default()
        };
        let err = attach_runtime_overlay_from_cache(&mut config, "firecracker")
            .expect_err("a cold cache must refuse");
        assert!(
            err.to_string().contains("runtime overlay required"),
            "got: {err:#}"
        );
    }

    /// A missing rootfs fails at the hash step, before any admission or boot.
    #[test]
    fn admit_and_boot_local_missing_rootfs_fails_before_boot() {
        let keys = tempfile::tempdir().unwrap();
        let backend = AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        let req = LocalRunRequest {
            name: "missing-rootfs".into(),
            rootfs_path: PathBuf::from("/nonexistent/rootfs.ext4"),
            kernel_path: None,
            verity_path: None,
            roothash: None,
            cpus: 1,
            mem_mib: 128,
            backend_name: "mock".into(),
            volumes: Vec::new(),
            destroy_on_exit: false,
            grants: None,
            signed_plan: None,
        };
        let err = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
                emitter: None,
                assurance: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("hashing rootfs"));
    }
}

#[cfg(test)]
mod signed_boot_tests {
    //! The fleet-issued door of the local-run seam, end to end over the
    //! hermetic mock backend: admit an externally-signed plan and boot it —
    //! or refuse and boot nothing.
    use super::*;
    use crate::plan_admission::SystemClock;
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::user_config::{MvmConfig, TrustedPlanSigner};
    use mvm_core::util::test_env::TestEnv;

    fn fleet_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    /// Isolate `MVM_HOME` and write the host config; the trusted-signer set
    /// lives in operator config, so a test that wants a trusting host has to
    /// be one.
    fn host_with(cfg: MvmConfig) -> (TestEnv, tempfile::TempDir) {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        mvm_core::user_config::save(&cfg, None).unwrap();
        (env, home)
    }

    fn pinned_host() -> (TestEnv, tempfile::TempDir) {
        host_with(MvmConfig {
            trusted_plan_signers: vec![TrustedPlanSigner {
                signer_id: "fleet-prod".to_string(),
                ed25519_pubkey_hex: hex::encode(fleet_key().verifying_key().as_bytes()),
            }],
            ..MvmConfig::default()
        })
    }

    /// A request whose signed plan pins the exact bytes of `rootfs`.
    fn signed_request(
        name: &str,
        rootfs: &Path,
        plan: mvm_core::plan::ExecutionPlan,
    ) -> LocalRunRequest {
        LocalRunRequest {
            name: name.to_string(),
            rootfs_path: rootfs.to_path_buf(),
            kernel_path: None,
            verity_path: None,
            roothash: None,
            cpus: 1,
            mem_mib: 128,
            backend_name: "mock".into(),
            volumes: Vec::new(),
            destroy_on_exit: true,
            grants: None,
            signed_plan: Some(mvm_core::plan::sign_plan(&plan, &fleet_key(), "fleet-prod")),
        }
    }

    fn boot(req: &LocalRunRequest) -> Result<StartedMachine> {
        let backend = AnyBackend::from_hypervisor("mock");
        let ledger = InMemoryNonceLedger::new();
        admit_and_boot_local(
            &backend,
            req,
            LocalRunContext {
                clock: &SystemClock,
                ledger: &ledger,
                host_signer_keys_dir: None,
                emitter: None,
                assurance: None,
            },
        )
    }

    #[test]
    fn a_fleet_signed_plan_boots_through_the_local_seam() {
        let (_env, home) = pinned_host();
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fleet workload bytes\n").unwrap();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();

        let mut plan = PlanFixture::new()
            .runtime_profile("mock")
            .tenant("fleet-tenant")
            .build();
        plan.image.sha256 = sha;
        let req = signed_request("fleet-vm", &rootfs, plan);

        let started = boot(&req).expect("a pinned fleet-signed plan admits and boots");
        assert_eq!(started.vm_id.0, "fleet-vm");
        assert_eq!(started.admitted.signer_id(), "fleet-prod");
        assert_eq!(started.admitted.plan().tenant.0, "fleet-tenant");
    }

    #[test]
    fn a_fleet_signed_plan_is_refused_when_the_host_pins_nobody() {
        let (_env, home) = host_with(MvmConfig::default());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fleet workload bytes\n").unwrap();
        let sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();

        let mut plan = PlanFixture::new().runtime_profile("mock").build();
        plan.image.sha256 = sha;
        let req = signed_request("fleet-vm-refused", &rootfs, plan);

        let err = boot(&req).expect_err("an unpinned host must refuse");
        assert!(
            format!("{err:#}").contains("pins no trusted plan signers"),
            "got: {err:#}"
        );
    }

    #[test]
    fn a_rootfs_that_is_not_the_pinned_image_is_refused() {
        let (_env, home) = pinned_host();
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"bytes the plan did not authorize\n").unwrap();

        // The plan pins the fixture's digest, not this rootfs's — a validly
        // signed plan booting different bytes must not pass.
        let plan = PlanFixture::new().runtime_profile("mock").build();
        let req = signed_request("fleet-vm-wrong-image", &rootfs, plan);

        let err = boot(&req).expect_err("an image mismatch must refuse the boot");
        assert!(
            format!("{err:#}").contains("refusing to boot an image the plan does not authorize"),
            "got: {err:#}"
        );
    }
}
