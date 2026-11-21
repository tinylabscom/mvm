//! Planless warm-parent preparation and refill.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointDigest, CheckpointId, CheckpointMeta};
use mvm_core::vm_backend::{
    RuntimeSourceRootStrategy, StandbyCompat, StandbyHandle, StandbySpec, VmStartConfig,
};
use mvm_hostd::plan_admission::PreparedBuiltPackRuntime;
use mvm_runtime::checkpoint::{CheckpointChainAnchor, CheckpointStore};
use mvm_runtime::runtime_evidence::VerifiedRuntimeSet;
use rand::Rng;
use sha2::{Digest, Sha256};

use super::SupervisorStandbyPool;
use crate::{AnyBackend, SpawnContext};

/// A resolved warm factory parent that cannot carry workload admission authority.
///
/// Fields are private so callers can neither add an admitted plan nor replace
/// the boot shape after its compatibility key has been calculated.
pub struct PreparedWarmParent {
    backend: AnyBackend,
    config: VmStartConfig,
    compat: StandbyCompat,
    _verified_runtime: Option<Arc<VerifiedRuntimeSet>>,
    _built_runtime: Option<PreparedBuiltPackRuntime>,
}

/// Summary of a best-effort warm-parent refill.
#[derive(Debug, PartialEq, Eq)]
pub struct WarmRefillResult {
    /// Parents newly captured, evidenced and recorded.
    pub spawned: u32,
    /// Best-effort spawn or evidence attempts that failed.
    pub failed: u32,
    /// Full error chains for the failed attempts.
    pub failures: Vec<String>,
}

impl PreparedWarmParent {
    /// Consume resolved planless boot inputs into the opaque standby capability.
    ///
    /// # Errors
    ///
    /// Refuses any workload authority or per-workload host channel.
    #[doc(hidden)]
    pub fn from_resolved(
        backend: AnyBackend,
        config: VmStartConfig,
        verified_runtime: Option<Arc<VerifiedRuntimeSet>>,
        built_runtime: Option<PreparedBuiltPackRuntime>,
    ) -> Result<Self> {
        ensure_planless(&config)?;
        let compat = standby_compat(&config)?;
        Ok(Self {
            backend,
            config,
            compat,
            _verified_runtime: verified_runtime,
            _built_runtime: built_runtime,
        })
    }

    /// Backend selected while resolving the source.
    #[must_use]
    pub fn backend(&self) -> &AnyBackend {
        &self.backend
    }

    /// Canonical compatibility key shared with claim lookup.
    #[must_use]
    pub fn compat(&self) -> &StandbyCompat {
        &self.compat
    }

    /// Prepare parents until this source has `target` compatible idle entries.
    ///
    /// Individual spawn failures are retained in the result. An ownership-uncertain
    /// native failure is returned immediately with its custody guards intact.
    pub fn refill_to(&self, pool: &SupervisorStandbyPool, target: u32) -> Result<WarmRefillResult> {
        refill_planless(pool, &self.backend, &self.config, &self.compat, target)
    }
}

/// Exercise the production refill implementation with a borrowed test backend.
///
/// This exists only with `test-support` so CLI regression tests can retain the
/// exact configured mock backend without exposing an alternate production
/// entry point around [`PreparedWarmParent`].
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn refill_borrowed_for_test(
    pool: &SupervisorStandbyPool,
    backend: &AnyBackend,
    config: &VmStartConfig,
    target: u32,
) -> Result<WarmRefillResult> {
    ensure_planless(config)?;
    let compat = standby_compat(config)?;
    refill_planless(pool, backend, config, &compat, target)
}

/// Refill implementation shared with narrow compatibility callers.
///
/// # Errors
///
/// Returns host setup, pool persistence, or ownership-uncertain backend errors.
fn refill_planless(
    pool: &SupervisorStandbyPool,
    backend: &AnyBackend,
    config: &VmStartConfig,
    compat: &StandbyCompat,
    target: u32,
) -> Result<WarmRefillResult> {
    if target == 0 {
        return Ok(WarmRefillResult {
            spawned: 0,
            failed: 0,
            failures: Vec::new(),
        });
    }
    if !backend.capabilities().standby_pool {
        if !matches!(
            mvm_core::residency::resolve_residency().1,
            mvm_core::residency::ResidencySource::EnvOverride
        ) {
            return Ok(WarmRefillResult {
                spawned: 0,
                failed: 0,
                failures: Vec::new(),
            });
        }
        return Err(anyhow::Error::new(
            mvm_core::vm_backend::StandbyError::Unsupported {
                backend: backend.name().to_string(),
            },
        ));
    }

    let mut warm_guard = Some(mvm_core::atomic_io::FileLock::acquire(
        &pool.root().join("warm"),
    )?);
    let have = pool.idle_count_compatible(compat)? as u32;
    if have < target {
        crate::snapshot::ensure_host_snapshot_key()
            .context("preparing the host snapshot key for warm parents")?;
    }
    let signer = crate::host_keypair::load_or_init()?;
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    let vms_root = mvm_core::config::vms_dir();
    let checkpoints = CheckpointStore::open();
    let spawn_ctx = SpawnContext {
        checkpoints: &checkpoints,
        launch: Some(config),
    };
    let mut result = WarmRefillResult {
        spawned: 0,
        failed: 0,
        failures: Vec::new(),
    };

    for _ in have..target {
        let spec = standby_spec(
            &pool_root,
            &vms_root,
            &signer.secret_path,
            &crate::host_keypair::host_signer_id(),
            config,
            compat,
        )?;
        match backend.spawn_standby_via_runner_owned(&spawn_ctx, &spec) {
            Ok(handle) => {
                if let Err(error) = sign_planless_parent_evidence(&checkpoints, &handle) {
                    discard_parent(backend, &checkpoints, &handle, &mut warm_guard).with_context(
                        || {
                            format!(
                                "discarding standby '{}' after source-evidence failure: {error:#}",
                                handle.id
                            )
                        },
                    )?;
                    result.failures.push(format!(
                        "signing planless standby '{}': {error:#}",
                        handle.id
                    ));
                    result.failed += 1;
                    continue;
                }
                if let Err(error) = pool.record(&handle) {
                    discard_parent(backend, &checkpoints, &handle, &mut warm_guard).with_context(
                        || {
                            format!(
                                "discarding standby '{}' after pool-publication failure: {error:#}",
                                handle.id
                            )
                        },
                    )?;
                    return Err(error);
                }
                result.spawned += 1;
            }
            Err(error) => {
                let error = match error.downcast::<mvm_backends::driver::hvf::ColdHvfBootFailure>()
                {
                    Ok(native) => match native.into_released_error() {
                        Ok(error) => error,
                        Err(native) => {
                            let warm_guard =
                                warm_guard.take().expect("warm refill retains its lock");
                            return Err(anyhow::Error::new(
                                        native.retain_support(warm_guard),
                                    )
                                    .context(
                                        "native standby launch remains owned; retain error for stop retry",
                                    ));
                        }
                    },
                    Err(error) => error,
                };
                result.failures.push(format!("spawning standby: {error:#}"));
                tracing::warn!(%error, "spawn standby failed; pool stays under target");
                result.failed += 1;
            }
        }
    }

    let max_memory_mib = u64::from(target).saturating_mul(u64::from(compat.mem_mib));
    pool.evict_compatible_to_memory_budget(compat, max_memory_mib)?;
    Ok(result)
}

/// Calculate the one compatibility key used by both parent creation and lookup.
///
/// # Errors
///
/// Returns an error when the kernel or rootfs cannot be read and hashed.
pub fn standby_compat(config: &VmStartConfig) -> Result<StandbyCompat> {
    let kernel = config
        .kernel_path
        .as_deref()
        .context("launch config has no kernel path for the compat key")?;
    let kernel = std::fs::read(kernel).with_context(|| format!("read kernel {kernel}"))?;
    let image_sha256 =
        mvm_core::crypto::image_verify::sha256_file_cached(Path::new(&config.rootfs_path))
            .with_context(|| {
                format!(
                    "hashing rootfs for the warm-pool compat key: {}",
                    config.rootfs_path
                )
            })?;
    Ok(StandbyCompat {
        template_id: config.template_id.clone(),
        kernel_sha256: hex::encode(Sha256::digest(kernel)),
        vcpus: u8::try_from(config.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX),
        mem_mib: config.memory_mib,
        image_sha256: Some(image_sha256),
        root_strategy: RuntimeSourceRootStrategy::BlockExt4,
        vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(config),
    })
}

fn ensure_planless(config: &VmStartConfig) -> Result<()> {
    anyhow::ensure!(
        config.plan_json.is_none()
            && config.tenant_id.is_none()
            && config.cpu_grant.is_none()
            && config.allowed_cpus.is_none()
            && config.config_files.is_empty()
            && config.secret_files.is_empty()
            && config.service_proxies.is_empty()
            && config.mailbox_conversation.is_none()
            && config.ports.is_empty()
            && config.caller_registration.is_none()
            && config.admission_durability.is_none(),
        "warm factory parent preparation refuses workload authority"
    );
    Ok(())
}

fn standby_spec(
    pool_root: &Path,
    vms_root: &Path,
    signing_key_path: &Path,
    signer_id: &str,
    config: &VmStartConfig,
    compat: &StandbyCompat,
) -> Result<StandbySpec> {
    let mut nonce_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let id = format!("standby-{}", &nonce[..16]);
    Ok(StandbySpec {
        id: id.clone(),
        template_id: compat.template_id.clone(),
        kernel_path: config
            .kernel_path
            .clone()
            .context("warm parent has no kernel")?,
        kernel_sha256: compat.kernel_sha256.clone(),
        vcpus: compat.vcpus,
        mem_mib: compat.mem_mib,
        signer_id: signer_id.to_string(),
        signing_key_path: signing_key_path.to_string_lossy().into_owned(),
        control_socket: pool_root
            .join(&id)
            .join("control.sock")
            .to_string_lossy()
            .into_owned(),
        vm_state_dir: vms_root.join(&id).to_string_lossy().into_owned(),
        binding_nonce: nonce,
        image_path: Some(config.rootfs_path.clone()),
        image_sha256: compat.image_sha256.clone(),
        root_strategy: compat.root_strategy,
        vsock_egress: compat.vsock_egress,
    })
}

fn sign_planless_parent_evidence(
    checkpoints: &CheckpointStore,
    handle: &StandbyHandle,
) -> Result<()> {
    let id = handle
        .parent_checkpoint
        .as_deref()
        .context("captured warm parent has no checkpoint")?;
    let meta = checkpoints.read_meta(&CheckpointId::new(id.to_string()))?;
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()?;
    mvm_core::crypto::snapshot_sign::sign_manifest(
        &checkpoints.content_dir(&meta.id),
        meta.meta_digest.as_str(),
        &identity.signing,
    )?;
    Ok(())
}

struct WarmParentCleanupUncertain {
    parent: String,
    cause: String,
    _warm_guard: mvm_core::atomic_io::FileLock,
}

impl std::fmt::Debug for WarmParentCleanupUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WarmParentCleanupUncertain")
            .field("parent", &self.parent)
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for WarmParentCleanupUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "standby parent '{}' may remain live after cleanup: {}",
            self.parent, self.cause
        )
    }
}

impl std::error::Error for WarmParentCleanupUncertain {}

/// Whether a warm-parent operation retains unresolved native cleanup custody.
///
/// Callers that aggregate best-effort refill failures must propagate this
/// outcome immediately rather than format and drop the lock-owning error.
#[must_use]
pub fn is_warm_parent_ownership_uncertain(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<WarmParentCleanupUncertain>()
            .is_some()
            || source
                .downcast_ref::<mvm_backends::driver::hvf::ColdHvfBootFailure>()
                .is_some()
    })
}

/// Construct an uncertain cleanup outcome for cross-crate orchestration tests.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn warm_parent_cleanup_uncertain_for_test(path: &Path) -> Result<anyhow::Error> {
    Ok(anyhow::Error::new(WarmParentCleanupUncertain {
        parent: "test-parent".into(),
        cause: "injected unconfirmed stop".into(),
        _warm_guard: mvm_core::atomic_io::FileLock::acquire(path)?,
    }))
}

/// Construct native boot custody for cross-crate aggregation tests.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn warm_parent_native_custody_for_test() -> anyhow::Error {
    anyhow::Error::new(mvm_backends::driver::hvf::ColdHvfBootFailure::test_fixture())
}

fn discard_parent(
    backend: &AnyBackend,
    checkpoints: &CheckpointStore,
    handle: &StandbyHandle,
    warm_guard: &mut Option<mvm_core::atomic_io::FileLock>,
) -> Result<()> {
    if !handle.is_saved_state()
        && let Err(error) = backend.stop_transient(&mvm_core::vm_backend::VmId(handle.id.clone()))
    {
        return Err(anyhow::Error::new(WarmParentCleanupUncertain {
            parent: handle.id.clone(),
            cause: format!("{error:#}"),
            _warm_guard: warm_guard
                .take()
                .expect("warm-parent cleanup retains its refill lock"),
        }));
    }
    if let Some(id) = handle.parent_checkpoint.as_deref() {
        checkpoints
            .remove(&CheckpointId::new(id.to_string()))
            .with_context(|| format!("removing unusable warm-parent checkpoint '{id}'"))?;
    }
    Ok(())
}

/// Signature-authenticated planless checkpoint evidence used by warm claims.
pub struct PlanlessWarmParentAnchor {
    checkpoints_root: std::path::PathBuf,
    id: CheckpointId,
    legacy: crate::checkpoint::anchor::ClaimChainAnchor,
}

impl PlanlessWarmParentAnchor {
    /// Defer evidence verification until the runner has reserved the parent.
    ///
    /// # Errors
    /// Refuses when the legacy audit-chain fallback cannot be prepared.
    pub fn for_checkpoint(checkpoints: &CheckpointStore, id: &CheckpointId) -> Result<Self> {
        Ok(Self {
            checkpoints_root: checkpoints.root().to_path_buf(),
            id: id.clone(),
            legacy: crate::checkpoint::anchor::ClaimChainAnchor::for_checkpoint(id)?,
        })
    }

    fn planless_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        if meta.id != self.id {
            return Ok(None);
        }
        let checkpoints = CheckpointStore::at(&self.checkpoints_root);
        let recorded = checkpoints.read_meta(&self.id)?;
        let content_dir = checkpoints.content_dir(&self.id);
        let signature =
            content_dir.join(mvm_core::crypto::snapshot_sign::MANIFEST_SIGNATURE_FILENAME);
        match std::fs::symlink_metadata(&signature) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspecting planless warm-parent source evidence: {}",
                        signature.display()
                    )
                });
            }
        }
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()?;
        mvm_core::crypto::snapshot_sign::verify_manifest(
            &content_dir,
            recorded.meta_digest.as_str(),
            &[identity.verifying_key()],
        )
        .context("authenticating planless warm-parent source evidence")?;
        Ok(Some(recorded.meta_digest))
    }
}

impl CheckpointChainAnchor for PlanlessWarmParentAnchor {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        if let Some(digest) = self.planless_digest(meta)? {
            return Ok(Some(digest));
        }
        self.legacy.recorded_creation_digest(meta)
    }

    fn recorded_creation_tenant(&self, meta: &CheckpointMeta) -> Result<Option<String>> {
        if self.planless_digest(meta)?.is_some() {
            return Ok(None);
        }
        self.legacy.recorded_creation_tenant(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_runtime::checkpoint::CheckpointChainAnchor;

    fn planless_config(dir: &Path) -> VmStartConfig {
        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kernel, b"kernel").unwrap();
        std::fs::write(&rootfs, b"rootfs").unwrap();
        VmStartConfig {
            kernel_path: Some(kernel.to_string_lossy().into_owned()),
            rootfs_path: rootfs.to_string_lossy().into_owned(),
            cpus: 2,
            memory_mib: 512,
            ..VmStartConfig::default()
        }
    }

    #[test]
    fn one_compat_calculation_serves_preparation_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let config = planless_config(dir.path());
        let expected = standby_compat(&config).unwrap();
        let prepared = PreparedWarmParent::from_resolved(
            AnyBackend::from_hypervisor("qemu"),
            config,
            None,
            None,
        )
        .unwrap();

        assert_eq!(prepared.compat(), &expected);
    }

    #[test]
    fn compatibility_does_not_include_workload_grant_ceilings() {
        let dir = tempfile::tempdir().unwrap();
        let plain = planless_config(dir.path());
        let mut granted = plain.clone();
        granted.cpu_grant = Some(mvm_contract::grants::CpuGrant::Share { millicores: 250 });
        granted.allowed_cpus = Some(mvm_contract::protocol::cpu_set::CpuSet::parse("0").unwrap());

        assert_eq!(
            standby_compat(&plain).unwrap(),
            standby_compat(&granted).unwrap()
        );
    }

    #[test]
    fn admitted_authority_cannot_enter_the_planless_facade() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = planless_config(dir.path());
        config.plan_json = Some("{\"signed\":\"plan\"}".into());
        config.tenant_id = Some("tenant-a".into());

        let error = PreparedWarmParent::from_resolved(
            AnyBackend::from_hypervisor("qemu"),
            config,
            None,
            None,
        )
        .err()
        .expect("workload authority must be refused");

        assert!(
            error.to_string().contains("refuses workload authority"),
            "{error:#}"
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn refill_facade_records_the_same_canonical_compatibility_it_prepared() {
        let _lock = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let config = planless_config(home.path());
        let prepared = PreparedWarmParent::from_resolved(
            AnyBackend::Mock(mvm_runtime::mock::MockBackend::new().with_standby()),
            config,
            None,
            None,
        )
        .unwrap();
        let compat = prepared.compat().clone();
        let pool = SupervisorStandbyPool::at(home.path().join("pool"));

        let result = prepared.refill_to(&pool, 1).unwrap();

        assert_eq!(result.spawned, 1, "{:?}", result.failures);
        assert_eq!(result.failed, 0, "{:?}", result.failures);
        assert_eq!(pool.idle_count_compatible(&compat).unwrap(), 1);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn failed_unpublished_parent_stop_retains_checkpoint_and_reports_uncertain_cleanup() {
        let home = tempfile::tempdir().unwrap();
        let checkpoints = CheckpointStore::at(home.path().join("checkpoints"));
        let checkpoint = CheckpointId::new("unpublished-parent-checkpoint");
        let meta = CheckpointMeta::builder(
            checkpoint.clone(),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "standby-parent",
        )
        .build();
        checkpoints.write_meta(&meta).unwrap();
        let handle = StandbyHandle {
            id: "unpublished-resident-parent".into(),
            template_id: None,
            control_socket: String::new(),
            pid: 42,
            vcpus: 1,
            mem_mib: 128,
            binding_nonce: "nonce".into(),
            spawned_unix_secs: 1,
            state: mvm_core::vm_backend::StandbyState::Idle,
            parent_checkpoint: Some(checkpoint.as_str().to_string()),
            kernel_sha256: "a".repeat(64),
            image_sha256: Some("b".repeat(64)),
            root_strategy: RuntimeSourceRootStrategy::BlockExt4,
            vsock_egress: false,
            preloaded_child_vm_name: None,
        };
        let backend = AnyBackend::Mock(
            mvm_runtime::mock::MockBackend::new()
                .with_standby()
                .with_failing_stop(),
        );
        let mut warm_guard =
            Some(mvm_core::atomic_io::FileLock::acquire(&home.path().join("warm")).unwrap());

        let error = discard_parent(&backend, &checkpoints, &handle, &mut warm_guard)
            .expect_err("an unconfirmed stop must remain uncertain");

        assert!(error.to_string().contains("may remain live"), "{error:#}");
        assert!(
            warm_guard.is_none(),
            "the returned error must retain the refill lock"
        );
        assert!(
            checkpoints.read_meta(&checkpoint).is_ok(),
            "uncertain cleanup must retain checkpoint custody"
        );
    }

    #[test]
    fn planless_source_evidence_authenticates_metadata_without_a_plan() {
        let _lock = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        let meta = CheckpointMeta::builder(
            CheckpointId::new("standby-parent"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "standby",
        )
        .build();
        store.write_meta(&meta).unwrap();
        std::fs::create_dir_all(store.content_dir(&meta.id)).unwrap();
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
        mvm_core::crypto::snapshot_sign::sign_manifest(
            &store.content_dir(&meta.id),
            meta.meta_digest.as_str(),
            &identity.signing,
        )
        .unwrap();

        let anchor = PlanlessWarmParentAnchor::for_checkpoint(&store, &meta.id).unwrap();
        assert_eq!(
            anchor.recorded_creation_digest(&meta).unwrap(),
            Some(meta.meta_digest.clone())
        );
        assert_eq!(anchor.recorded_creation_tenant(&meta).unwrap(), None);
    }

    #[test]
    fn legacy_audit_anchored_parent_remains_claimable_without_planless_manifest() {
        let _lock = mvm_runtime::vm::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        let meta = CheckpointMeta::builder(
            CheckpointId::new("legacy-standby-parent"),
            mvm_core::checkpoint::CheckpointClass::VmFull,
            "standby",
        )
        .build();
        store.write_meta(&meta).unwrap();
        let signer = crate::host_keypair::load_or_init().unwrap();
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("standby")
            .workload("legacy-parent")
            .build();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        drop(emitter);

        let anchor = PlanlessWarmParentAnchor::for_checkpoint(&store, &meta.id).unwrap();
        assert_eq!(
            anchor.recorded_creation_digest(&meta).unwrap(),
            Some(meta.meta_digest.clone())
        );
        assert_eq!(
            anchor.recorded_creation_tenant(&meta).unwrap().as_deref(),
            Some("standby")
        );

        let content_dir = store.content_dir(&meta.id);
        std::fs::create_dir_all(&content_dir).unwrap();
        std::fs::write(
            content_dir.join(mvm_core::crypto::snapshot_sign::MANIFEST_SIGNATURE_FILENAME),
            b"tampered planless evidence",
        )
        .unwrap();
        let error = anchor
            .recorded_creation_digest(&meta)
            .expect_err("present but invalid planless evidence must not fall back");
        assert!(
            error
                .to_string()
                .contains("authenticating planless warm-parent source evidence"),
            "{error:#}"
        );

        #[cfg(unix)]
        {
            let signature =
                content_dir.join(mvm_core::crypto::snapshot_sign::MANIFEST_SIGNATURE_FILENAME);
            std::fs::remove_file(&signature).unwrap();
            std::os::unix::fs::symlink(content_dir.join("missing-signature-target"), &signature)
                .unwrap();
            let error = anchor
                .recorded_creation_digest(&meta)
                .expect_err("a dangling evidence entry must not be treated as absent");
            assert!(
                error
                    .to_string()
                    .contains("authenticating planless warm-parent source evidence"),
                "{error:#}"
            );
        }
    }
}
