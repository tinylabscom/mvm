//! One flake build through a builder VM, as a request and a result.
//!
//! [`dev_build`](crate::pipeline::dev_build) builds a flake for `mvmctl
//! build`: it picks the attribute from a profile, stages the output into the
//! dev build cache, and reports through a shell environment. A caller that
//! already knows its flake attribute and wants the artifacts where it asked
//! for them needs none of that. This is the narrower path: mounts and job from
//! a [`BuildRequest`], one [`BuilderVm::run_build`], and a [`BuilderResult`]
//! naming what was produced.
//!
//! The result always has a guest sidecar. The runtime refuses to boot a rootfs
//! without one, so a build that produced a rootfs and no sidecar is reported
//! here, where the build log is, and not at a boot some time later.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::builder_backend_select as bbs;
use crate::builder_vm::{BuilderArtifacts, BuilderJob, BuilderMounts, BuilderVm, SIDECAR_FILENAME};

/// One flake attribute to build, and where its inputs and outputs live on the
/// host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRequest {
    /// The flake's source directory, mounted read-only at `/work`.
    pub workspace_root: PathBuf,
    /// The flake reference as the builder sees it, for example `/work`.
    pub flake_ref: String,
    /// The attribute to build, for example
    /// `packages.aarch64-linux.default`.
    pub attr_path: String,
    /// Where the builder writes the rootfs, the kernel, and the sidecar.
    pub artifact_out: PathBuf,
    /// A host directory to reuse as the builder's Nix store, if any.
    pub host_nix_store: Option<PathBuf>,
    /// The directory holding mvm's builder binaries, mounted at `/mvm-bins`.
    pub host_bin_dir: PathBuf,
}

/// What a flake build left on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderResult {
    pub rootfs_path: PathBuf,
    /// Absent when the flake emits no kernel of its own.
    pub kernel_path: Option<PathBuf>,
    /// The guest sidecar beside the rootfs. Always present on disk.
    pub sidecar_path: PathBuf,
    /// The leading hash segment of the build's Nix store path.
    pub revision_hash: String,
    /// SHA-256 of the flake's lock file, when the builder recorded one.
    pub lock_hash: Option<String>,
    /// Whether the image allows console access, when the flake says.
    pub accessible: Option<bool>,
}

/// Build `request` on the builder backend this host resolves to.
///
/// The backend is chosen the way every other build chooses it: `--builder`,
/// then `MVM_BUILDER_BACKEND`, then auto-detect. A backend this process has no
/// constructor for refuses by name.
pub fn run_builder_for_request(request: &BuildRequest) -> Result<BuilderResult> {
    let selected = bbs::resolve_choice(None);
    let explicit = bbs::resolve_env_override().is_some();
    bbs::run_with_builder_fallback_anyhow(selected, explicit, |choice| {
        let builder = bbs::try_resolve_builder_backend(Some(choice)).map_err(anyhow::Error::new)?;
        run_builder_for_request_on(request, builder.as_ref())
    })
}

/// Build `request` on `builder`.
pub fn run_builder_for_request_on(
    request: &BuildRequest,
    builder: &dyn BuilderVm,
) -> Result<BuilderResult> {
    let artifacts = builder
        .run_build(&job_for(request), &mounts_for(request))
        // Kept as a downcastable source, not a string, so the backend
        // fallback can still tell a VMM failure from a build failure.
        .map_err(|e| anyhow::Error::new(e).context("builder VM"))?;
    result_from(artifacts)
}

fn job_for(request: &BuildRequest) -> BuilderJob {
    BuilderJob::Flake {
        flake_ref: request.flake_ref.clone(),
        attr_path: request.attr_path.clone(),
    }
}

fn mounts_for(request: &BuildRequest) -> BuilderMounts {
    BuilderMounts {
        flake_src: request.workspace_root.clone(),
        host_nix_store: request.host_nix_store.clone(),
        artifact_out: request.artifact_out.clone(),
        host_bin_dir: request.host_bin_dir.clone(),
        staged_user_flake: None,
    }
}

fn result_from(artifacts: BuilderArtifacts) -> Result<BuilderResult> {
    let BuilderArtifacts::Image {
        rootfs_path,
        kernel_path,
        revision_hash,
        lock_hash,
        accessible,
    } = artifacts
    else {
        anyhow::bail!("builder VM returned install-volume artifacts for a flake build");
    };
    let sidecar_path = sidecar_beside(&rootfs_path)?;
    Ok(BuilderResult {
        rootfs_path,
        kernel_path,
        sidecar_path,
        revision_hash,
        lock_hash,
        accessible,
    })
}

fn sidecar_beside(rootfs: &std::path::Path) -> Result<PathBuf> {
    let dir = rootfs
        .parent()
        .with_context(|| format!("rootfs path {} has no parent directory", rootfs.display()))?;
    let sidecar = dir.join(SIDECAR_FILENAME);
    anyhow::ensure!(
        sidecar.is_file(),
        "the build wrote {} without {SIDECAR_FILENAME} beside it; the runtime refuses to boot \
         a rootfs with no sidecar, so this flake's output cannot be used as built",
        rootfs.display(),
    );
    Ok(sidecar)
}
