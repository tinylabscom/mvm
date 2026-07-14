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
//! per-destination redaction, custom egress policy) are deliberately absent:
//! the facade `MachineSpec` does not carry them, so exposing them here would
//! invent a surface no caller can fill. When a driver needs them it uses the
//! CLI admission path directly.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_backend::AnyBackend;
use mvm_core::plan::{AuthPolicy, PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_core::vm_backend::VmStartConfig;

use crate::plan_admission::{
    AdmitAndStartParams, Clock, InMemoryNonceLedger, StartedMachine, admit_and_start,
};

/// The tenant every locally-run machine is admitted under. Local runs are
/// single-tenant by construction (one host, one operator), so the audit chain
/// and gateway substrate key off this fixed label rather than a fleet tenant.
const LOCAL_TENANT: &str = "local";

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
}

/// Admission substrate for a local run: the clock and replay ledger that drive
/// the validity-window + nonce checks, plus an optional host-signer keys dir
/// override (production passes `None` → `~/.mvm/keys/`; tests inject a tempdir).
pub struct LocalRunContext<'a> {
    pub clock: &'a dyn Clock,
    pub ledger: &'a InMemoryNonceLedger,
    pub host_signer_keys_dir: Option<&'a Path>,
}

/// Admit `req` through the signed-plan gate and boot it on `backend`.
///
/// On success the plan was signed under the host key, verified, inside its
/// validity window, and non-replayed before the backend saw a single byte of
/// launch config. Any failure returns with no VM created.
pub fn admit_and_boot_local(
    backend: &AnyBackend,
    req: &LocalRunRequest,
    ctx: LocalRunContext<'_>,
) -> Result<StartedMachine> {
    let sha = mvm_core::crypto::image_verify::sha256_file_cached(&req.rootfs_path)
        .with_context(|| format!("hashing rootfs at {}", req.rootfs_path.display()))?;

    let synthesis = SynthesisInput {
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
        auth: AuthPolicy::none(),
        audit_event_prefix: None,
        cpus: req.cpus,
        mem_mib: u64::from(req.mem_mib),
        disk_mib: 0,
        boot_timeout_secs: 60,
        exec_timeout_secs: 0,
        // A persistent local machine outlives the admitting call, so it must
        // not be torn down when this function returns.
        destroy_on_exit: false,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: Default::default(),
        reversible_replacement: Default::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        build_provenance: None,
    };

    let path_string = |p: &Path| p.to_string_lossy().into_owned();
    let config = VmStartConfig {
        name: req.name.clone(),
        rootfs_path: path_string(&req.rootfs_path),
        kernel_path: req.kernel_path.as_deref().map(path_string),
        verity_path: req.verity_path.as_deref().map(path_string),
        roothash: req.roothash.clone(),
        cpus: req.cpus,
        memory_mib: req.mem_mib,
        tenant_id: Some(LOCAL_TENANT.to_string()),
        runtime_source_policy: mvm_core::vm_backend::select_runtime_source_policy(
            mvm_core::vm_backend::RuntimeSourcePolicySelection {
                backend_name: None,
                sealed: false,
                root_strategy: None,
                launch_kind: mvm_core::vm_backend::RuntimeSourceLaunchKind::WorkloadImage,
            },
        ),
        // network_policy defaults to deny-all via VmStartConfig's Default.
        ..Default::default()
    };

    admit_and_start(
        backend,
        AdmitAndStartParams {
            synthesis: &synthesis,
            config,
            clock: ctx.clock,
            ledger: ctx.ledger,
            host_signer_keys_dir: ctx.host_signer_keys_dir,
            bundle_ctx: None,
            policy_bundle: None,
        },
    )
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
        env.set("MVM_DATA_DIR", data.path());
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
        };

        let started = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
            },
        )
        .expect("admit + boot over mock");

        assert_eq!(started.vm_id.0, "local-run-seam-test");
        assert_eq!(started.admitted.plan.tenant.0, LOCAL_TENANT);
        // The plan was actually signed under the host key (proves admission,
        // not a stub): a signer id is present and the plan bound the exact
        // rootfs bytes we handed it (64-hex sha256) on our backend.
        assert!(!started.admitted.signer_id.is_empty());
        assert_eq!(started.admitted.plan.image.sha256.len(), 64);
        assert_eq!(started.admitted.plan.runtime_profile.0, "mock");
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
        };
        let err = admit_and_boot_local(
            &backend,
            &req,
            LocalRunContext {
                clock: &clock,
                ledger: &ledger,
                host_signer_keys_dir: Some(keys.path()),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("hashing rootfs"));
    }
}
