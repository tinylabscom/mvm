//! Resolving a declared rootfs source to a host `rootfs.ext4`: planning the
//! work a source implies, pulling and unpacking OCI layers, injecting the
//! guest runtime, and materializing the bootable image through the same
//! `run_image` orchestration the CLI boots through.
//!
//! Split out of `local.rs`; the OCI pull half already lives in `oci.rs` and
//! builds on this module's unpack and materialize primitives.

use std::collections::HashSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use mvm_core::client::{MvmError, Result};
use mvm_core::rootfs_source::RootfsSource;
use mvm_fs::oci::{ImageReference, LayerDescriptor, UnpackOptions, UnpackReport, unpack_layer};

use super::backend_err;
use super::oci::pull_image_to_dir;

/// The work a declared rootfs source implies. One variant per verification
/// path: a materialized blob is booted as-is, a tree is injected and
/// materialized, and a reference is fetched from a registry first.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RootfsPlan {
    /// An already-materialized `rootfs.ext4` — boot it directly.
    Materialized(PathBuf),
    /// An unpacked OCI rootfs directory — inject runtime + materialize.
    UnpackedDir(PathBuf),
    /// A registry reference — pull + unpack + inject + materialize.
    Pull(ImageReference),
}

/// Turn a caller-declared rootfs source into the work it implies.
///
/// The declaration arrives parsed, so a mistyped path stops here instead of
/// falling through to the registry arm: the arms differ in how the bytes they
/// produce are verified, and which one runs must not depend on the caller's
/// working directory.
pub(crate) fn plan_rootfs_source(source: RootfsSource) -> Result<RootfsPlan> {
    match source {
        // The filesystem is consulted only to tell a blob from a tree, and
        // only once the caller has declared the source local.
        RootfsSource::LocalPath(path) if path.is_file() => Ok(RootfsPlan::Materialized(path)),
        RootfsSource::LocalPath(path) if path.is_dir() => Ok(RootfsPlan::UnpackedDir(path)),
        RootfsSource::LocalPath(path) => Err(MvmError::InvalidSpec {
            reason: format!(
                "declared local rootfs path does not exist: {} — no registry fetch was \
                 attempted; write `oci:<reference>` to boot a registry image instead",
                path.display()
            ),
        }),
        RootfsSource::Oci { image_ref } => image_ref
            .parse::<ImageReference>()
            .map(RootfsPlan::Pull)
            .map_err(|e| MvmError::InvalidSpec {
                reason: format!(
                    "not a usable OCI reference: {image_ref:?}: {e}{}",
                    path_collision_hint(&image_ref)
                ),
            }),
        RootfsSource::Flake { flake_ref, attr } => Err(MvmError::InvalidSpec {
            reason: format!(
                "a flake source is built, not booted: build {flake_ref}#{attr} first, then \
                 declare the resulting rootfs path"
            ),
        }),
    }
}

/// A bare name is a registry reference by declaration, so a same-named file in
/// the caller's working directory is not silently preferred — but it is almost
/// certainly what they meant, so say so once the reference has failed to parse.
fn path_collision_hint(image_ref: &str) -> String {
    if Path::new(image_ref).exists() {
        format!(
            " (a filesystem entry named {image_ref:?} exists — write `./{image_ref}` or `path:{image_ref}` to boot it)"
        )
    } else {
        String::new()
    }
}

/// Materialize an OCI reference into a host `rootfs.ext4`, for a caller that
/// wants the artifact rather than a running machine.
///
/// The build path uses this so an image-backed `mvm.toml` is materialized by
/// exactly the code a `run --image` boots through — same pull, same hardened
/// unpack, same runtime injection, and the same `mvm-meta.json` sidecar written
/// beside the rootfs. A second materializer would be a second answer to "what
/// does this image become", and the two would drift.
///
/// `cache_key` names the cache slot under `~/.mvm/cache/local-run/`.
pub async fn materialize_image_rootfs(image_ref: &str, cache_key: &str) -> Result<PathBuf> {
    resolve_local_rootfs(
        &RootfsSource::Oci {
            image_ref: image_ref.to_string(),
        },
        cache_key,
    )
    .await
}

/// Resolve `spec.image` to a host `rootfs.ext4` path, materializing in-process
/// as needed (no subprocess, no CLI). Registry pulls are async; the dir +
/// pre-materialized cases are synchronous.
pub(crate) async fn resolve_local_rootfs(image: &RootfsSource, name: &str) -> Result<PathBuf> {
    match plan_rootfs_source(image.clone())? {
        RootfsPlan::Materialized(path) => Ok(path),
        // An already-unpacked tree carries no unpack report, so there is
        // nothing the host filesystem deferred to merge back in.
        RootfsPlan::UnpackedDir(dir) => materialize_from_dir(&dir, name, UnpackedLayers::default()),
        RootfsPlan::Pull(image_ref) => {
            let staging = tempfile::tempdir().map_err(backend_err)?;
            let pulled = pull_image_to_dir(&image_ref, staging.path()).await?;
            let output = run_rootfs_output(name);
            materialize_tree(
                staging.path(),
                &output,
                name,
                pulled.layers,
                TreeMaterializeOptions {
                    config: Some(&pulled.config),
                    ..TreeMaterializeOptions::default()
                },
            )?;
            Ok(output)
        }
    }
}

/// Cache location for a locally-materialized run rootfs, keyed by machine name.
pub(crate) fn run_rootfs_output(name: &str) -> PathBuf {
    let key: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("local-run")
        .join(key)
        .join("rootfs.ext4")
}

/// What unpacking an image's layers produced beyond the host tree: the nodes
/// the host filesystem could not hold, and the owners it could not apply.
#[derive(Default)]
pub(crate) struct UnpackedLayers {
    pub(crate) deferred_nodes: Vec<mvm_fs::ext4::Node>,
    pub(crate) owners: mvm_fs::ownership::OwnerTable,
}

/// Inject the mvm runtime into an unpacked tree and materialize it into the
/// run-rootfs cache, reusing the CLI's shared `run_image` orchestration.
pub(crate) fn materialize_from_dir(
    dir: &Path,
    name: &str,
    layers: UnpackedLayers,
) -> Result<PathBuf> {
    let output = run_rootfs_output(name);
    materialize_tree(
        dir,
        &output,
        name,
        layers,
        TreeMaterializeOptions::default(),
    )?;
    Ok(output)
}

#[derive(Default)]
pub(crate) struct TreeMaterializeOptions<'a> {
    pub(crate) config: Option<&'a mvm_build::oci_runtime_inject::ImageRuntimeConfig>,
    pub(crate) sealed: bool,
    pub(crate) runtime_binaries: Option<&'a mvm_build::oci_runtime_inject::MvmRuntimeBinaries>,
    pub(crate) policy: mvm_build::run_image::RootfsMaterializationPolicy,
}

pub(crate) fn materialize_tree(
    dir: &Path,
    output: &Path,
    name: &str,
    layers: UnpackedLayers,
    options: TreeMaterializeOptions<'_>,
) -> Result<()> {
    let cache_root = mvm_core::config::oci_cache_dir(); // where the CLI prepares runtimes
    if options.runtime_binaries.is_none() {
        crate::launch::runtime_overlay::require_prepared_oci_guest_runtime(&cache_root)
            .map_err(|e| backend_err(format!("{e:#}")))?;
    }
    mvm_build::run_image::inject_and_materialize(
        mvm_build::run_image::InjectAndMaterializeRequest::builder(&cache_root, dir, output, name)
            .sealed(options.sealed)
            .entrypoint(options.config)
            .runtime_binaries(options.runtime_binaries)
            .materialization_policy(options.policy)
            .reuse_published(false)
            .deferred_nodes(layers.deferred_nodes)
            .owners(layers.owners)
            .build(),
    )
    .map_err(|e| backend_err(format!("{e:#}")))
}

/// Unpack one layer's bytes into `dest`, decompressing gzip layers first.
pub(crate) fn unpack_one_layer(
    layer: &LayerDescriptor,
    bytes: &[u8],
    dest: &Path,
    prior_layer_paths: &HashSet<PathBuf>,
) -> Result<UnpackReport> {
    let mt = &layer.media_type;
    let report = if mt.ends_with("+gzip") || mt.ends_with(".gzip") || mt.contains("tar.gzip") {
        unpack_layer(
            GzDecoder::new(Cursor::new(bytes)),
            dest,
            &UnpackOptions::default(),
            Some(prior_layer_paths),
        )
    } else {
        unpack_layer(
            Cursor::new(bytes),
            dest,
            &UnpackOptions::default(),
            Some(prior_layer_paths),
        )
    }
    .map_err(|e| backend_err(format!("unpack layer {}: {e}", layer.digest)))?;
    if !report.refused.is_empty() {
        return Err(backend_err(format!(
            "layer {} unpack refused entries: {:?}",
            layer.digest, report.refused
        )));
    }
    Ok(report)
}

/// Probe the dm-verity sidecars the pure materializer writes beside the image
/// (`rootfs.verity` + `rootfs.roothash`) from the host filesystem. Returns
/// `(verity_path, roothash)` when both are present and the hash is well-formed
/// (64-hex); `(None, None)` for an unverified image. A `&Path` adapter over
/// `mvm_runtime::microvm::probe_verity_sidecar`, which does the host-side read.
pub(crate) fn host_verity_sidecars(rootfs: &Path) -> (Option<String>, Option<String>) {
    mvm_runtime::microvm::probe_verity_sidecar(&rootfs.to_string_lossy())
}
