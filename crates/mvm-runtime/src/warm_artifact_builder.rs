//! Worker-side preparation of boot artifacts for warm objects.
//!
//! The launch service never calls this module. A prewarm worker calls
//! [`WarmArtifactBuildPlan::prepare`] after it has been scheduled, so image
//! materialization and support-artifact resolution cannot extend the warm
//! claim window.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_core::vm_backend::WarmPrewarmSource;

use crate::warm_artifacts::{
    PrewarmJob, PrewarmQueue, WarmArtifactInput, WarmArtifactKey, WarmArtifactStore,
};
use crate::warm_readiness::WarmGoldenVmFactory;

struct HostShellEnvironment;

impl mvm_core::build_env::ShellEnvironment for HostShellEnvironment {
    fn shell_exec(&self, script: &str) -> Result<()> {
        let output = std::process::Command::new("bash")
            .args(["-c", script])
            .output()
            .context("run host build command")?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "host build command failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn shell_exec_stdout(&self, script: &str) -> Result<String> {
        let output = std::process::Command::new("bash")
            .args(["-c", script])
            .output()
            .context("run host build command")?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            anyhow::bail!(
                "host build command failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        let status = std::process::Command::new("bash")
            .args(["-c", script])
            .status()
            .context("run host build command")?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("host build command failed (exit {:?})", status.code());
        }
    }

    fn log_info(&self, message: &str) {
        tracing::info!(message = %message, "warm artifact builder");
    }

    fn log_success(&self, message: &str) {
        tracing::info!(message = %message, "warm artifact builder completed");
    }
}

/// Resolved workload inputs plus the cache root used by support-artifact
/// builders. The rootfs and kernel are supplied by the image/source adapter;
/// initramfs and runtime-overlay resolution happens here in the worker.
#[derive(Debug, Clone)]
pub struct WarmArtifactBuildPlan {
    /// Content-addressed workload rootfs already resolved by the source adapter.
    pub rootfs_path: PathBuf,
    /// Workload kernel path already resolved by the source adapter.
    pub kernel_path: PathBuf,
    /// Guest architecture for universal initramfs and runtime overlay.
    pub arch: GuestArch,
    /// Configured mvm cache root.
    pub cache_root: PathBuf,
}

/// Already-resolved support artifacts passed to the staging half. Keeping this
/// separate makes the expensive resolver calls injectable in tests and keeps
/// publication independent from how a support artifact was obtained.
#[derive(Debug, Clone)]
pub struct WarmArtifactSupportPaths {
    /// Universal initramfs image.
    pub initramfs_path: PathBuf,
    /// Runtime overlay ext4 image.
    pub overlay_ext4: PathBuf,
    /// Runtime overlay dm-verity sidecar.
    pub overlay_verity: PathBuf,
    /// Runtime overlay root-hash text file.
    pub overlay_roothash: PathBuf,
}

/// Resolver used by the resident prewarm worker to turn a content identity
/// into source-specific paths. The resolver may consult an OCI cache, a
/// deployment registry, or another trusted local source; it runs only after
/// a job has left the claim path.
pub type WarmArtifactPlanResolver = Arc<
    dyn Fn(&WarmPrewarmSource, &WarmArtifactKey) -> Result<WarmArtifactBuildPlan> + Send + Sync,
>;

/// Verifies that a prepared golden VM booted the expected artifact set and
/// completed the authenticated guest-agent readiness handshake. Publication
/// is refused when this verifier returns an error.
pub type WarmGoldenVmReadinessVerifier =
    Arc<dyn Fn(&WarmPrewarmSource, &WarmArtifactKey, &Path) -> Result<()> + Send + Sync>;

/// Durable worker that connects the prewarm journal to real artifact
/// preparation. It owns no active VM lease and therefore cannot extend a
/// warm claim's latency window.
pub struct WarmArtifactWorker {
    queue: PrewarmQueue,
    resolve_plan: WarmArtifactPlanResolver,
    verify_readiness: WarmGoldenVmReadinessVerifier,
}

impl WarmArtifactWorker {
    /// Create a worker backed by the supplied artifact store and source-plan
    /// resolver.
    pub fn new(
        store: WarmArtifactStore,
        resolve_plan: WarmArtifactPlanResolver,
        verify_readiness: WarmGoldenVmReadinessVerifier,
    ) -> Self {
        Self {
            queue: PrewarmQueue::new(store),
            resolve_plan,
            verify_readiness,
        }
    }

    /// Create a worker with the shared authenticated readiness verifier and a
    /// backend-specific disposable golden-VM factory.
    pub fn with_authenticated_readiness(
        store: WarmArtifactStore,
        resolve_plan: WarmArtifactPlanResolver,
        factory: WarmGoldenVmFactory,
    ) -> Self {
        let verifier =
            Arc::new(crate::warm_readiness::AuthenticatedWarmGoldenVmVerifier::new(factory));
        Self::new(store, resolve_plan, verifier.callback())
    }

    /// Enqueue one immutable artifact identity for asynchronous preparation.
    pub fn enqueue(&self, source: WarmPrewarmSource, key: WarmArtifactKey) -> Result<PrewarmJob> {
        source.validate().map_err(anyhow::Error::msg)?;
        self.queue.enqueue(source, key).map_err(anyhow::Error::new)
    }

    /// Process one queued job, resolving source paths and preparing support
    /// artifacts before the store performs authenticated publication.
    pub fn process_next(&self) -> Result<Option<PrewarmJob>> {
        let resolve_plan = Arc::clone(&self.resolve_plan);
        let verify_readiness = Arc::clone(&self.verify_readiness);
        self.queue
            .process_next_with_readiness(
                |source, key, staging_root| {
                    let plan =
                        resolve_plan(source, key).context("resolve warm artifact source plan")?;
                    plan.prepare(key, staging_root)
                },
                |source, key, staging_root| verify_readiness(source, key, staging_root),
            )
            .map_err(anyhow::Error::new)
    }

    /// Access the journal for restart recovery and status inspection.
    pub fn store(&self) -> &WarmArtifactStore {
        self.queue.store()
    }

    /// Build the callback consumed by the resident warm-launch service. The
    /// callback only validates the typed identity and enqueues work; the
    /// expensive resolver and readiness verifier run on [`Self::process_next`].
    pub fn prewarm_callback(self: &Arc<Self>) -> crate::warm_service::PrewarmFn {
        let worker = Arc::clone(self);
        Arc::new(move |_, source, artifact, target| {
            if target == 0 {
                return Ok(0);
            }
            let key = WarmArtifactKey::try_from(artifact.clone())
                .map_err(anyhow::Error::new)
                .context("validate warm artifact identity")?;
            if worker
                .store()
                .resolve(&key)
                .map_err(anyhow::Error::new)?
                .is_some()
            {
                return Ok(1);
            }
            worker
                .enqueue(source.clone(), key)
                .context("enqueue warm artifact job")?;
            Ok(0)
        })
    }
}

impl WarmArtifactBuildPlan {
    /// Resolve/build support artifacts, copy every boot input into the worker
    /// staging directory, and return verified publication inputs.
    pub fn prepare(
        &self,
        key: &WarmArtifactKey,
        staging_root: &Path,
    ) -> Result<Vec<WarmArtifactInput>> {
        key.validate().map_err(anyhow::Error::new)?;
        ensure_regular_file(&self.rootfs_path, "rootfs.ext4")?;
        ensure_regular_file(&self.kernel_path, "kernel")?;

        let initramfs_cache = self.cache_root.join("initramfs");
        let initramfs = mvm_build::initramfs::resolve_or_build_local_initramfs(
            &HostShellEnvironment,
            &initramfs_cache,
            env!("CARGO_PKG_VERSION"),
            self.arch,
        )
        .context("resolve or build universal initramfs")?;

        let overlay_cache = self.cache_root.join("runtime-overlay");
        let overlay = mvm_build::runtime_overlay::resolve_or_build_local_runtime_overlay(
            &overlay_cache,
            env!("CARGO_PKG_VERSION"),
            self.arch,
        )
        .context("resolve or build runtime overlay")?;

        let support = WarmArtifactSupportPaths {
            initramfs_path: initramfs.image_path,
            overlay_ext4: overlay.overlay_ext4,
            overlay_verity: overlay.sidecar,
            overlay_roothash: overlay.roothash_file,
        };
        self.prepare_with_support_paths(key, staging_root, &support)
    }

    /// Stage a set of already-resolved support artifacts. This is also the
    /// seam used by platform-specific source adapters after they have resolved
    /// an OCI image or another immutable rootfs source.
    pub fn prepare_with_support_paths(
        &self,
        key: &WarmArtifactKey,
        staging_root: &Path,
        support: &WarmArtifactSupportPaths,
    ) -> Result<Vec<WarmArtifactInput>> {
        key.validate().map_err(anyhow::Error::new)?;
        fs::create_dir_all(staging_root)
            .with_context(|| format!("create warm staging root {}", staging_root.display()))?;
        ensure_regular_file(&self.rootfs_path, "rootfs.ext4")?;
        ensure_regular_file(&self.kernel_path, "kernel")?;
        let sources = [
            ("rootfs.ext4", self.rootfs_path.as_path()),
            ("kernel", self.kernel_path.as_path()),
            ("initramfs.cpio.gz", support.initramfs_path.as_path()),
            ("runtime-overlay.ext4", support.overlay_ext4.as_path()),
            ("runtime-overlay.verity", support.overlay_verity.as_path()),
            (
                "runtime-overlay.roothash",
                support.overlay_roothash.as_path(),
            ),
        ];
        let mut inputs = Vec::with_capacity(sources.len());
        for (name, source) in sources {
            ensure_regular_file(source, name)?;
            let destination = staging_root.join(name);
            fs::copy(source, &destination).with_context(|| {
                format!("stage warm artifact {} from {}", name, source.display())
            })?;
            let input =
                WarmArtifactInput::from_file(name, &destination).map_err(anyhow::Error::new)?;
            if let Some(expected) = expected_digest(key, name)
                && input.sha256 != expected
            {
                anyhow::bail!(
                    "warm artifact {name} does not match its compatibility key: expected {expected}, got {}",
                    input.sha256
                );
            }
            inputs.push(input);
        }
        Ok(inputs)
    }
}

fn expected_digest<'a>(key: &'a WarmArtifactKey, name: &str) -> Option<&'a str> {
    match name {
        "rootfs.ext4" => Some(&key.rootfs_sha256),
        "kernel" => Some(&key.kernel_sha256),
        "initramfs.cpio.gz" => Some(&key.initramfs_sha256),
        "runtime-overlay.ext4" => key.runtime_overlay_sha256.as_deref(),
        _ => None,
    }
}

fn ensure_regular_file(path: &Path, name: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("resolved warm artifact {name} at {}", path.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("resolved warm artifact {name} is not a regular file");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_rejects_missing_resolved_inputs_before_building_support_artifacts() {
        let root = tempfile::tempdir().expect("cache root");
        let staging = tempfile::tempdir().expect("staging root");
        let plan = WarmArtifactBuildPlan {
            rootfs_path: root.path().join("missing-rootfs"),
            kernel_path: root.path().join("missing-kernel"),
            arch: GuestArch::Aarch64,
            cache_root: root.path().join("cache"),
        };
        let key = crate::warm_artifacts::WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        };
        let error = plan
            .prepare(&key, staging.path())
            .expect_err("missing rootfs fails");
        assert!(
            error
                .to_string()
                .contains("resolved warm artifact rootfs.ext4")
        );
        assert!(!staging.path().join("rootfs.ext4").exists());
    }

    #[test]
    fn plan_stages_resolved_support_artifacts_without_rebuilding_them() {
        let root = tempfile::tempdir().expect("artifact root");
        let staging = tempfile::tempdir().expect("staging root");
        let names = [
            "rootfs",
            "kernel",
            "initramfs",
            "overlay",
            "verity",
            "roothash",
        ];
        let paths = names
            .iter()
            .map(|name| {
                let path = root.path().join(name);
                fs::write(&path, name.as_bytes()).expect("write source");
                path
            })
            .collect::<Vec<_>>();
        let plan = WarmArtifactBuildPlan {
            rootfs_path: paths[0].clone(),
            kernel_path: paths[1].clone(),
            arch: GuestArch::Aarch64,
            cache_root: root.path().join("cache"),
        };
        let key = crate::warm_artifacts::WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: WarmArtifactInput::from_file("kernel", &paths[1])
                .expect("hash kernel")
                .sha256,
            initramfs_sha256: WarmArtifactInput::from_file("initramfs", &paths[2])
                .expect("hash initramfs")
                .sha256,
            rootfs_sha256: WarmArtifactInput::from_file("rootfs", &paths[0])
                .expect("hash rootfs")
                .sha256,
            runtime_overlay_sha256: Some(
                WarmArtifactInput::from_file("overlay", &paths[3])
                    .expect("hash overlay")
                    .sha256,
            ),
        };
        let inputs = plan
            .prepare_with_support_paths(
                &key,
                staging.path(),
                &WarmArtifactSupportPaths {
                    initramfs_path: paths[2].clone(),
                    overlay_ext4: paths[3].clone(),
                    overlay_verity: paths[4].clone(),
                    overlay_roothash: paths[5].clone(),
                },
            )
            .expect("staging succeeds");
        assert_eq!(inputs.len(), 6);
        assert_eq!(
            fs::read(staging.path().join("kernel")).expect("staged kernel"),
            b"kernel"
        );
        assert_eq!(
            fs::read(staging.path().join("runtime-overlay.roothash")).expect("staged roothash"),
            b"roothash"
        );
    }

    #[test]
    fn worker_records_source_resolution_failure_as_a_retryable_job() {
        let root = tempfile::tempdir().expect("artifact root");
        let key = WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        };
        let worker = WarmArtifactWorker::new(
            WarmArtifactStore::at(root.path()),
            Arc::new(|_, _| anyhow::bail!("source unavailable")),
            Arc::new(|_, _, _| anyhow::bail!("golden VM unavailable")),
        );
        worker
            .enqueue(
                WarmPrewarmSource::OciImage {
                    reference: "python:3.12".into(),
                },
                key,
            )
            .expect("enqueue source job");
        let error = worker
            .process_next()
            .expect_err("source resolution failure is returned");
        assert_eq!(error.root_cause().to_string(), "source unavailable");
        let jobs = worker.store().jobs().expect("read durable jobs");
        assert!(matches!(
            jobs.first().map(|job| &job.state),
            Some(crate::warm_artifacts::PrewarmJobState::Failed { .. })
        ));
    }
}
