//! OCI cache index + on-disk file I/O: load/save the index, read/write
//! digest-verified cache blobs, and the `ls` / `inspect` / `rm` verb bodies
//! that assemble their results from it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use mvm_fs::oci::verify_sha256_digest;

use super::super::shared::human_bytes;
use super::oci_types::{
    CachedOciImage, INDEX_FILE, ImageListRow, InspectOutput, OciCacheIndex, RemoveOutcome,
};

pub(super) fn list_rows(cache_root: &Path, registry: Option<&str>) -> Result<Vec<ImageListRow>> {
    let index = load_index(cache_root)?;
    let rows = index
        .images
        .iter()
        .filter(|image| registry.is_none_or(|want| image.registry == want))
        .map(|image| ImageListRow {
            reference: image.reference.clone(),
            registry: image.registry.clone(),
            repository: image.repository.clone(),
            tag: image.tag.clone(),
            resolved_digest: image.resolved_digest.clone(),
            fetched_at: image.fetched_at.clone(),
            size_bytes: image_size_bytes(cache_root, image),
            layers: image.layers.len(),
        })
        .collect();
    Ok(rows)
}

pub(super) fn inspect_image(cache_root: &Path, reference: &str) -> Result<InspectOutput> {
    let index = load_index(cache_root)?;
    let image = find_image(&index, reference)
        .with_context(|| format!("cached OCI image not found for '{reference}'"))?
        .clone();
    Ok(InspectOutput {
        size_bytes: image_size_bytes(cache_root, &image),
        manifest: read_json_optional(cache_root, &image.manifest_path)?,
        config: image
            .config_path
            .as_deref()
            .map(|p| read_json_optional(cache_root, p))
            .transpose()?
            .flatten(),
        claims: image
            .claims_path
            .as_deref()
            .map(|p| read_json_optional(cache_root, p))
            .transpose()?
            .flatten(),
        image,
    })
}

pub(super) fn remove_image(cache_root: &Path, reference: &str) -> Result<RemoveOutcome> {
    remove_image_with(cache_root, reference, || {})
}

fn remove_image_with(
    cache_root: &Path,
    reference: &str,
    resources_locked: impl FnMut(),
) -> Result<RemoveOutcome> {
    remove_image_with_wait_observer(cache_root, reference, |_| {}, resources_locked)
}

fn remove_image_with_wait_observer(
    cache_root: &Path,
    reference: &str,
    mut on_wait: impl FnMut(CacheLockWait),
    mut resources_locked: impl FnMut(),
) -> Result<RemoveOutcome> {
    loop {
        let snapshot = load_index(cache_root)?;
        let image = find_image(&snapshot, reference)
            .with_context(|| format!("cached OCI image not found for '{reference}'"))?
            .clone();
        let resources = ImageResources::for_image(cache_root, &image)?;
        let _resource_locks =
            resources.acquire_with_wait_observer(|| on_wait(CacheLockWait::Resource))?;
        let _index_lock =
            lock_index_with_wait_observer(cache_root, || on_wait(CacheLockWait::Index))?;
        let index = load_index(cache_root)?;
        let Some(position) = index
            .images
            .iter()
            .position(|current| image_matches(current, reference))
        else {
            bail!("cached OCI image not found for '{reference}'");
        };
        let current = &index.images[position];
        if current != &image || ImageResources::for_image(cache_root, current)? != resources {
            continue;
        }
        resources_locked();
        return remove_image_holding(cache_root, index, position);
    }
}

fn remove_image_holding(
    cache_root: &Path,
    mut index: OciCacheIndex,
    position: usize,
) -> Result<RemoveOutcome> {
    let image = index.images.remove(position);
    let mut removed_files = 0usize;
    let mut freed_bytes = 0u64;
    let shared_layer_paths = remaining_layer_paths(&index);
    // Every file another cached reference still names stays: two references
    // to one digest share its digest-keyed manifest, config and claims, and
    // removing them left the other unable to rebuild ("read OCI config").
    let shared_paths: BTreeSet<String> = index.images.iter().flat_map(all_image_paths).collect();
    validate_image_paths(cache_root, &image)?;

    let rootfs_shared = index
        .images
        .iter()
        .any(|other| other.resolved_digest == image.resolved_digest);
    // The durable index commit is the ownership transfer: after it succeeds,
    // a crash may leave unreachable cache bytes, but never a live entry whose
    // files were already reclaimed. The index lock stays held through cleanup
    // so no concurrent upsert can start referring to those files mid-sweep.
    save_index(cache_root, &index)?;
    for path in metadata_paths(&image) {
        if shared_paths.contains(&path) {
            continue;
        }
        if image.rootfs_path.as_deref() == Some(path.as_str()) {
            // A rootfs under `rootfs/` goes with its whole directory below; a
            // legacy one anywhere else in the cache is removed as a file.
            if rootfs_shared || is_rootfs_dir_member(cache_root, &path)? {
                continue;
            }
        }
        remove_cache_file(cache_root, &path, &mut removed_files, &mut freed_bytes)?;
    }
    if !rootfs_shared {
        for dir in rootfs_dirs_of(cache_root, &image)? {
            remove_directory_tree(cache_root, &dir, &mut removed_files, &mut freed_bytes)?;
        }
        remove_unpacked_state_holding(
            cache_root,
            &image.resolved_digest,
            &mut removed_files,
            &mut freed_bytes,
        )?;
    }

    for layer in &image.layers {
        let Some(path) = layer.path.as_deref() else {
            continue;
        };
        if shared_layer_paths.contains(path) {
            continue;
        }
        remove_cache_file(cache_root, path, &mut removed_files, &mut freed_bytes)?;
    }

    Ok(RemoveOutcome {
        reference: image.reference,
        removed_files,
        freed_bytes,
    })
}

pub(super) fn load_index(cache_root: &Path) -> Result<OciCacheIndex> {
    let path = cache_root.join(INDEX_FILE);
    if !path.exists() {
        return Ok(OciCacheIndex::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let index: OciCacheIndex =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    if index.schema_version != 1 {
        bail!(
            "unsupported OCI cache index schema_version {} at {}",
            index.schema_version,
            path.display()
        );
    }
    Ok(index)
}

pub(super) fn save_index(cache_root: &Path, index: &OciCacheIndex) -> Result<()> {
    fs::create_dir_all(cache_root).with_context(|| format!("create {}", cache_root.display()))?;
    let path = cache_root.join(INDEX_FILE);
    let bytes = serde_json::to_vec_pretty(index).context("serialize OCI cache index")?;
    mvm_core::util::atomic_io::atomic_write_durable(&path, &bytes)
        .with_context(|| format!("write {}", path.display()))
}

fn lock_index_with_wait_observer(
    cache_root: &Path,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    fs::create_dir_all(cache_root).with_context(|| format!("create {}", cache_root.display()))?;
    let index_path = cache_root.join(INDEX_FILE);
    if let Some(held) = mvm_core::util::atomic_io::FileLock::try_acquire(&index_path)
        .context("try lock OCI cache index")?
    {
        return Ok(held);
    }
    on_wait();
    mvm_core::util::atomic_io::FileLock::acquire(&index_path).context("lock OCI cache index")
}

pub(super) fn upsert_cached_image(cache_root: &Path, image: CachedOciImage) -> Result<()> {
    upsert_cached_image_with_wait_observer(cache_root, image, |_| {})
}

fn upsert_cached_image_with_wait_observer(
    cache_root: &Path,
    image: CachedOciImage,
    mut on_wait: impl FnMut(CacheLockWait),
) -> Result<()> {
    let rootfs_rel = image
        .rootfs_path
        .as_deref()
        .context("cannot register an OCI image without a materialized rootfs")?;
    let rootfs = safe_cache_path(cache_root, rootfs_rel)?;
    let hex = sha256_hex(&image.resolved_digest)?;
    let unpacked = cache_root.join("unpacked").join(hex);
    let _resources =
        mvm_build::run_image::HeldTreeLocks::acquire_observed(&unpacked, &rootfs, || {
            on_wait(CacheLockWait::Resource)
        })?;
    if read_cached_unpack(cache_root, &image.resolved_digest)?.is_none() {
        bail!(
            "refusing to register OCI image {} without its complete unpacked tree",
            image.reference
        );
    }
    if !mvm_build::run_image::rootfs_build_is_complete(&rootfs) {
        bail!(
            "refusing to register OCI image {} without its complete rootfs",
            image.reference
        );
    }
    let _index_lock = lock_index_with_wait_observer(cache_root, || on_wait(CacheLockWait::Index))?;
    let mut index = load_index(cache_root)?;
    upsert_image(&mut index, image);
    save_index(cache_root, &index)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheLockWait {
    Resource,
    Index,
}

pub(super) fn read_verified_cache_file(
    cache_root: &Path,
    relative: &str,
    digest: &str,
) -> Result<Option<Vec<u8>>> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    verify_sha256_digest(&bytes, digest)
        .with_context(|| format!("verify cached blob {}", path.display()))?;
    Ok(Some(bytes))
}

pub(super) fn write_cache_file(cache_root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let path = safe_cache_path(cache_root, relative)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
}

pub(super) fn layer_blob_path(digest: &str) -> Result<String> {
    Ok(format!("blobs/sha256/{}", sha256_hex(digest)?))
}

/// The unpacked+injected OCI tree for `resolved_digest`, iff present on disk.
/// Its location is deterministic (`<cache>/unpacked/<sha256_hex(digest)>`); a
/// virtiofs-root dev boot serves it directly, so gate on existence.
pub(super) fn unpacked_dir_if_present(cache_root: &Path, resolved_digest: &str) -> Option<PathBuf> {
    if resolved_digest.is_empty() {
        return None;
    }
    let hex = sha256_hex(resolved_digest).ok()?;
    let dir = cache_root.join("unpacked").join(hex);
    dir.is_dir().then_some(dir)
}

/// Sidecar holding the nodes the layer unpack could not place on the
/// host tree. It sits *beside* the unpacked root, never inside it, so it
/// can never be walked into the image as a file of its own.
fn deferred_nodes_sidecar(cache_root: &Path, resolved_digest: &str) -> Result<PathBuf> {
    let hex = sha256_hex(resolved_digest)?;
    Ok(cache_root
        .join("unpacked")
        .join(format!("{hex}.deferred-nodes.json")))
}

/// Persist the unpack's deferred nodes next to the unpacked tree.
///
/// Without this, the cache self-heal path — which re-materializes an
/// ext4 from a surviving unpacked tree, with no layer tarballs in hand —
/// would emit an image quietly missing every path a case-folding host
/// could not hold. Writing nothing for the (overwhelmingly common) empty
/// case keeps the cache layout unchanged on a case-sensitive host.
pub(super) fn write_deferred_nodes(
    cache_root: &Path,
    resolved_digest: &str,
    nodes: &[mvm_fs::ext4::Node],
) -> Result<()> {
    let path = deferred_nodes_sidecar(cache_root, resolved_digest)?;
    if nodes.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(nodes).context("serialize deferred unpack nodes")?;
    mvm_core::util::atomic_io::atomic_write(&path, &body)
}

/// Read back what [`write_deferred_nodes`] stored.
///
/// A missing sidecar is the normal case — nothing was deferred — and reads as
/// an empty list. A sidecar that exists and cannot be parsed is a different
/// answer: it means nodes were deferred and we no longer know which, so it
/// reads as `None` and the tree has to be unpacked again. Reading it as empty
/// would build an image quietly missing paths.
pub(super) fn read_deferred_nodes(
    cache_root: &Path,
    resolved_digest: &str,
) -> Result<Option<Vec<mvm_fs::ext4::Node>>> {
    let path = deferred_nodes_sidecar(cache_root, resolved_digest)?;
    // Only an absent sidecar means "nothing deferred". One that is there and
    // cannot be read — permissions, a directory in its place, an I/O error —
    // says nothing about what was deferred, and reading it as empty would
    // build an image quietly missing paths.
    let body = match fs::read(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Some(Vec::new())),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    Ok(parse_sidecar(&path, &body))
}

/// Decode a sidecar, treating a corrupt one as absent.
///
/// A sidecar is a cache, and the tree it sits beside can always be unpacked
/// again. A write interrupted by a crash or a full disk left a truncated file
/// that returned a hard error on every later read, so the image stayed
/// unusable until someone deleted the file by hand — a worse outcome than the
/// re-unpack the cache was built to allow.
fn parse_sidecar<T: serde::de::DeserializeOwned>(path: &Path, body: &[u8]) -> Option<T> {
    match serde_json::from_slice(body) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "unreadable OCI cache sidecar; unpacking the layers again"
            );
            None
        }
    }
}

/// Sidecar holding the owners the image's layers declared, beside the
/// unpacked tree for the same reason the deferred nodes sit there: the tree
/// cannot hold them, and a rebuild from the tree must not lose them.
fn layer_owners_sidecar(cache_root: &Path, resolved_digest: &str) -> Result<PathBuf> {
    let hex = sha256_hex(resolved_digest)?;
    Ok(cache_root
        .join("unpacked")
        .join(format!("{hex}.owners.json")))
}

/// Persist the layers' owners next to the unpacked tree.
///
/// Written even when every owner is root. Its absence is what marks a tree
/// unpacked before owners were recorded, and such a tree cannot rebuild a
/// faithful image.
pub(super) fn write_layer_owners(
    cache_root: &Path,
    resolved_digest: &str,
    owners: &mvm_fs::ownership::OwnerTable,
) -> Result<()> {
    let path = layer_owners_sidecar(cache_root, resolved_digest)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let body = serde_json::to_vec(owners).context("serialize layer owners")?;
    mvm_core::util::atomic_io::atomic_write(&path, &body)
}

/// Read back what [`write_layer_owners`] stored, or `None` when the unpacked
/// tree predates owner recording, or records owners we can no longer read, and
/// must be unpacked again.
pub(super) fn read_layer_owners(
    cache_root: &Path,
    resolved_digest: &str,
) -> Result<Option<mvm_fs::ownership::OwnerTable>> {
    let path = layer_owners_sidecar(cache_root, resolved_digest)?;
    let body = match fs::read(&path) {
        Ok(body) => body,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    Ok(parse_sidecar(&path, &body))
}

/// An unpacked tree and everything a faithful image rebuild needs beside it.
///
/// The three are read together because they are only usable together: a tree
/// whose owners or deferred nodes are missing rebuilds an image that is wrong
/// rather than one that fails, so a caller that has the tree must not proceed
/// without the rest.
pub(super) struct CachedUnpack {
    pub(super) root: PathBuf,
    pub(super) owners: mvm_fs::ownership::OwnerTable,
    pub(super) deferred_nodes: Vec<mvm_fs::ext4::Node>,
}

/// Read a cached unpacked tree, or `None` when it is gone or incomplete and
/// the layers have to be unpacked again.
pub(super) fn read_cached_unpack(
    cache_root: &Path,
    resolved_digest: &str,
) -> Result<Option<CachedUnpack>> {
    let Some(root) = unpacked_dir_if_present(cache_root, resolved_digest) else {
        return Ok(None);
    };
    let Some(owners) = read_layer_owners(cache_root, resolved_digest)? else {
        return Ok(None);
    };
    let Some(deferred_nodes) = read_deferred_nodes(cache_root, resolved_digest)? else {
        return Ok(None);
    };
    Ok(Some(CachedUnpack {
        root,
        owners,
        deferred_nodes,
    }))
}

pub(super) fn sha256_hex(digest: &str) -> Result<String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("unsupported digest algorithm in {digest:?}");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("malformed sha256 digest: {digest:?}");
    }
    Ok(hex.to_string())
}

pub(super) fn upsert_image(index: &mut OciCacheIndex, image: CachedOciImage) {
    if let Some(existing) = index
        .images
        .iter_mut()
        .find(|cached| cached.reference == image.reference)
    {
        *existing = image;
    } else {
        index.images.push(image);
    }
}

pub(super) fn find_image<'a>(
    index: &'a OciCacheIndex,
    reference: &str,
) -> Option<&'a CachedOciImage> {
    index
        .images
        .iter()
        .find(|image| image_matches(image, reference))
}

pub(super) fn image_matches(image: &CachedOciImage, reference: &str) -> bool {
    image.reference == reference
        || image.resolved_digest == reference
        || image
            .resolved_digest
            .strip_prefix("sha256:")
            .is_some_and(|digest| digest == reference)
}

pub(super) fn image_size_bytes(cache_root: &Path, image: &CachedOciImage) -> u64 {
    let mut total = 0u64;
    let mut seen = BTreeSet::new();
    for path in all_image_paths(image) {
        if !seen.insert(path.clone()) {
            continue;
        }
        if let Ok(path) = safe_cache_path(cache_root, &path)
            && let Ok(meta) = path.metadata()
            && meta.is_file()
        {
            total = total.saturating_add(meta.len());
        }
    }
    if total == 0 {
        image
            .layers
            .iter()
            .map(|layer| layer.size_bytes)
            .fold(0u64, u64::saturating_add)
    } else {
        total
    }
}

pub(super) fn all_image_paths(image: &CachedOciImage) -> Vec<String> {
    let mut paths = metadata_paths(image);
    paths.extend(image.layers.iter().filter_map(|layer| layer.path.clone()));
    paths
}

pub(super) fn metadata_paths(image: &CachedOciImage) -> Vec<String> {
    let mut paths = vec![image.manifest_path.clone()];
    paths.extend(image.config_path.clone());
    paths.extend(image.rootfs_path.clone());
    paths.extend(image.claims_path.clone());
    paths
}

pub(super) fn remaining_layer_paths(index: &OciCacheIndex) -> BTreeSet<String> {
    index
        .images
        .iter()
        .flat_map(|image| image.layers.iter())
        .filter_map(|layer| layer.path.clone())
        .collect()
}

pub(super) fn validate_image_paths(cache_root: &Path, image: &CachedOciImage) -> Result<()> {
    for path in all_image_paths(image) {
        let _ = safe_cache_path(cache_root, &path)?;
    }
    Ok(())
}

pub(super) fn read_json_optional(cache_root: &Path, relative: &str) -> Result<Option<Value>> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .with_context(|| format!("parse {}", path.display()))
}

/// Whether `relative` sits in a rootfs directory of its own under `rootfs/`,
/// which [`remove_directory_tree`] removes whole.
fn is_rootfs_dir_member(cache_root: &Path, relative: &str) -> Result<bool> {
    let path = safe_cache_path(cache_root, relative)?;
    Ok(path.parent().is_some_and(|dir| {
        dir.starts_with(cache_root.join("rootfs")) && dir != cache_root.join("rootfs")
    }))
}

/// Every materialized rootfs directory of `image`: the one its index entry
/// names, and each directory derived from its digest — both variants, sealed
/// and dev, under any runtime tag. Each holds one image and its sidecars.
fn rootfs_dirs_of(cache_root: &Path, image: &CachedOciImage) -> Result<BTreeSet<PathBuf>> {
    let mut dirs = BTreeSet::new();
    if let Some(rel) = image.rootfs_path.as_deref() {
        let path = safe_cache_path(cache_root, rel)?;
        if is_rootfs_dir_member(cache_root, rel)?
            && let Some(dir) = path.parent()
            && dir.file_name().is_some_and(|name| name != ".locks")
        {
            dirs.insert(dir.to_path_buf());
        }
    }
    // A digest this cache cannot key has no derived directories to find.
    let Ok(hex) = sha256_hex(&image.resolved_digest) else {
        return Ok(dirs);
    };
    let prefix = format!("{hex}-");
    let rootfs_root = cache_root.join("rootfs");
    let entries = match fs::read_dir(&rootfs_root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(dirs),
        Err(err) => return Err(err).with_context(|| format!("list {}", rootfs_root.display())),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) && entry.file_type()?.is_dir() {
            dirs.insert(entry.path());
        }
    }
    Ok(dirs)
}

#[derive(Debug, PartialEq, Eq)]
struct ImageResources {
    unpacked_root: Option<PathBuf>,
    rootfs_dirs: BTreeSet<PathBuf>,
}

impl ImageResources {
    fn for_image(cache_root: &Path, image: &CachedOciImage) -> Result<Self> {
        let unpacked_root = sha256_hex(&image.resolved_digest)
            .ok()
            .map(|hex| cache_root.join("unpacked").join(hex));
        Ok(Self {
            unpacked_root,
            rootfs_dirs: rootfs_dirs_of(cache_root, image)?,
        })
    }

    fn acquire_with_wait_observer(&self, mut on_wait: impl FnMut()) -> Result<HeldImageResources> {
        let tree = self
            .unpacked_root
            .as_deref()
            .map(|root| mvm_build::run_image::lock_unpacked_tree_observed(root, &mut on_wait))
            .transpose()?;
        let outputs = self
            .rootfs_dirs
            .iter()
            .map(|dir| {
                mvm_build::run_image::lock_rootfs_output_observed(
                    &dir.join("rootfs.ext4"),
                    &mut on_wait,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(HeldImageResources {
            _tree: tree,
            _outputs: outputs,
        })
    }
}

struct HeldImageResources {
    _tree: Option<mvm_core::util::atomic_io::FileLock>,
    _outputs: Vec<mvm_core::util::atomic_io::FileLock>,
}

fn remove_unpacked_state_holding(
    cache_root: &Path,
    resolved_digest: &str,
    removed_files: &mut usize,
    freed_bytes: &mut u64,
) -> Result<()> {
    let Ok(hex) = sha256_hex(resolved_digest) else {
        return Ok(());
    };
    let unpacked_root = cache_root.join("unpacked").join(&hex);
    remove_directory_tree(cache_root, &unpacked_root, removed_files, freed_bytes)?;
    for suffix in ["owners.json", "deferred-nodes.json"] {
        remove_cache_file(
            cache_root,
            &format!("unpacked/{hex}.{suffix}"),
            removed_files,
            freed_bytes,
        )?;
    }
    Ok(())
}

fn remove_directory_tree(
    cache_root: &Path,
    dir: &Path,
    removed_files: &mut usize,
    freed_bytes: &mut u64,
) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        let entries = match fs::read_dir(&at) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("list {}", at.display())),
        };
        for entry in entries {
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())
                .with_context(|| format!("stat {}", entry.path().display()))?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                *removed_files += 1;
                *freed_bytes = freed_bytes.saturating_add(meta.len());
            }
        }
    }
    match fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("remove {}", dir.display())),
    }
    prune_empty_parents(cache_root, dir.parent())
}

pub(super) fn remove_cache_file(
    cache_root: &Path,
    relative: &str,
    removed_files: &mut usize,
    freed_bytes: &mut u64,
) -> Result<()> {
    let path = safe_cache_path(cache_root, relative)?;
    if !path.exists() {
        return Ok(());
    }
    let meta = path
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    if !meta.is_file() {
        bail!("refusing to remove non-file cache path {}", path.display());
    }
    let len = meta.len();
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    *removed_files += 1;
    *freed_bytes = freed_bytes.saturating_add(len);
    prune_empty_parents(cache_root, path.parent())?;
    Ok(())
}

pub(super) fn prune_empty_parents(cache_root: &Path, mut current: Option<&Path>) -> Result<()> {
    while let Some(dir) = current {
        if dir == cache_root {
            break;
        }
        match fs::remove_dir(dir) {
            Ok(()) => current = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => current = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(e) => return Err(e).with_context(|| format!("remove {}", dir.display())),
        }
    }
    Ok(())
}

pub(super) fn safe_cache_path(cache_root: &Path, relative: &str) -> Result<PathBuf> {
    let rel = Path::new(relative);
    if rel.is_absolute() {
        bail!("OCI cache path must be relative: {relative}");
    }
    if rel.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("OCI cache path escapes cache root: {relative}");
    }
    Ok(cache_root.join(rel))
}

pub(super) fn render_list(rows: &[ImageListRow]) {
    if rows.is_empty() {
        println!("No cached OCI images.");
        return;
    }
    println!(
        "{:<38} {:<20} {:<18} {:>10}",
        "REFERENCE", "DIGEST", "FETCHED", "SIZE"
    );
    for row in rows {
        println!(
            "{:<38} {:<20} {:<18} {:>10}",
            truncate(&row.reference, 38),
            truncate(&row.resolved_digest, 20),
            truncate(&row.fetched_at, 18),
            human_bytes(row.size_bytes)
        );
    }
}

pub(super) fn render_inspect(output: &InspectOutput) {
    let image = &output.image;
    println!("Reference: {}", image.reference);
    println!("Registry: {}", image.registry);
    println!("Repository: {}", image.repository);
    if let Some(tag) = &image.tag {
        println!("Tag: {tag}");
    }
    println!("Resolved digest: {}", image.resolved_digest);
    println!("Fetched at: {}", image.fetched_at);
    println!("Size: {}", human_bytes(output.size_bytes));
    println!("Manifest: {}", image.manifest_path);
    if let Some(path) = &image.config_path {
        println!("Config: {path}");
    }
    if let Some(path) = &image.rootfs_path {
        println!("Rootfs: {path}");
    }
    println!(
        "mvm-claims.json: {}",
        if output.claims.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    println!("Layers:");
    for layer in &image.layers {
        let path = layer.path.as_deref().unwrap_or("-");
        println!(
            "  {}  {}  {}",
            layer.digest,
            human_bytes(layer.size_bytes),
            path
        );
    }
    if let Some(claims) = &output.claims
        && let Some(labels) = claims.as_object().and_then(|obj| obj.get("labels"))
    {
        let labels: BTreeMap<_, _> = labels
            .as_object()
            .into_iter()
            .flat_map(|obj| obj.iter())
            .collect();
        if !labels.is_empty() {
            println!("Claim labels:");
            for (key, value) in labels {
                println!("  {key}: {value}");
            }
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
    s.push('~');
    s
}

#[cfg(test)]
mod tests {
    use super::super::oci_types::{CachedOciLayer, schema_version};
    use super::*;

    fn sample_image(reference: &str, digest: &str, layer_path: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest: digest.to_string(),
            fetched_at: "2026-05-18T00:00:00Z".to_string(),
            manifest_path: "manifests/alpine.json".to_string(),
            config_path: Some("configs/alpine.json".to_string()),
            rootfs_path: None,
            runtime_tag: None,
            claims_path: Some("claims/alpine.json".to_string()),
            layers: vec![CachedOciLayer {
                digest: "sha256:layer".to_string(),
                size_bytes: 4,
                path: Some(layer_path.to_string()),
            }],
        }
    }

    fn write_index(cache_root: &Path, index: &OciCacheIndex) {
        fs::create_dir_all(cache_root).expect("create cache root");
        fs::write(
            cache_root.join(INDEX_FILE),
            serde_json::to_vec_pretty(index).expect("serialize index"),
        )
        .expect("write index");
    }

    #[test]
    fn default_index_round_trips_through_save_and_load() {
        // Regression: a derived `Default` set schema_version = 0, which
        // save_index persisted and load_index then rejected — breaking
        // `image ls` / `run --image` on a freshly-created OCI cache.
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(OciCacheIndex::default().schema_version, schema_version());
        save_index(tmp.path(), &OciCacheIndex::default()).expect("save a default index");
        let loaded = load_index(tmp.path()).expect("a freshly-saved default index must load");
        assert_eq!(loaded.schema_version, schema_version());
        assert!(loaded.images.is_empty());
    }

    fn write_file(cache_root: &Path, relative: &str, body: &[u8]) {
        let path = cache_root.join(relative);
        fs::create_dir_all(path.parent().expect("relative has parent")).expect("create parent");
        fs::write(path, body).expect("write cache file");
    }

    fn seed_materialized_state(cache_root: &Path, image: &mut CachedOciImage) {
        let hex = sha256_hex(&image.resolved_digest).expect("valid digest");
        let rootfs_rel = format!("rootfs/{hex}-test-dev/rootfs.ext4");
        image.rootfs_path = Some(rootfs_rel.clone());
        image.runtime_tag = Some("test".to_string());
        let unpacked = cache_root.join("unpacked").join(hex);
        fs::create_dir_all(&unpacked).expect("create unpacked tree");
        fs::write(unpacked.join("file"), b"unpacked").expect("write unpacked file");
        write_layer_owners(
            cache_root,
            &image.resolved_digest,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .expect("write owners");
        let rootfs = cache_root.join(rootfs_rel);
        fs::create_dir_all(rootfs.parent().expect("rootfs parent")).expect("create rootfs dir");
        fs::write(&rootfs, b"rootfs").expect("write rootfs");
        mvm_build::builder_vm::GuestSidecar::for_oci_run(&image.reference, false, true)
            .write_to_dir(rootfs.parent().expect("rootfs parent"))
            .expect("write guest sidecar");
    }

    #[test]
    fn upsert_replaces_existing_reference_entry() {
        let mut index = OciCacheIndex {
            schema_version: 1,
            images: vec![sample_image(
                "docker.io/library/alpine:3.20",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "blobs/old",
            )],
        };
        let replacement = sample_image(
            "docker.io/library/alpine:3.20",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blobs/new",
        );

        upsert_image(&mut index, replacement);

        assert_eq!(index.images.len(), 1);
        assert_eq!(index.images[0].layers[0].path.as_deref(), Some("blobs/new"));
    }

    #[test]
    fn upsert_keeps_distinct_references_to_same_digest() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut index = OciCacheIndex {
            schema_version: 1,
            images: vec![sample_image(
                "docker.io/library/alpine:3.20",
                digest,
                "blobs/shared",
            )],
        };
        let second = sample_image(
            &format!("docker.io/library/alpine@{digest}"),
            digest,
            "blobs/shared",
        );

        upsert_image(&mut index, second);

        assert_eq!(index.images.len(), 2);
    }

    #[test]
    fn concurrent_remove_and_upsert_do_not_lose_the_new_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let removed = sample_image(
            "docker.io/library/alpine:3.20",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "blobs/alpine",
        );
        let mut added = sample_image(
            "docker.io/library/busybox:1",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "blobs/busybox",
        );
        seed_materialized_state(tmp.path(), &mut added);
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![removed],
            },
        );
        let held = mvm_core::util::atomic_io::FileLock::acquire(&tmp.path().join(INDEX_FILE))
            .expect("hold index lock");
        let (remove_wait_tx, remove_wait_rx) = std::sync::mpsc::channel();
        let remove_cache = tmp.path().to_path_buf();
        let remover = std::thread::spawn(move || {
            remove_image_with_wait_observer(
                &remove_cache,
                "docker.io/library/alpine:3.20",
                |wait| remove_wait_tx.send(wait).expect("report remove wait"),
                || {},
            )
        });
        let (upsert_wait_tx, upsert_wait_rx) = std::sync::mpsc::channel();
        let upsert_cache = tmp.path().to_path_buf();
        let upserter = std::thread::spawn(move || {
            upsert_cached_image_with_wait_observer(&upsert_cache, added, |wait| {
                upsert_wait_tx.send(wait).expect("report upsert wait");
            })
        });
        assert_eq!(
            remove_wait_rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("remove reaches held index lock"),
            CacheLockWait::Index
        );
        assert_eq!(
            upsert_wait_rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("upsert reaches held index lock"),
            CacheLockWait::Index
        );
        drop(held);

        remover.join().unwrap().expect("remove");
        upserter.join().unwrap().expect("upsert");
        let index = load_index(tmp.path()).expect("load final index");
        assert_eq!(index.images.len(), 1);
        assert_eq!(index.images[0].reference, "docker.io/library/busybox:1");
    }

    #[test]
    fn upsert_cannot_resurrect_resources_removed_while_it_waits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut existing = sample_image(
            "docker.io/library/alpine:3.20",
            SAMPLE_DIGEST,
            "blobs/shared",
        );
        seed_materialized_state(tmp.path(), &mut existing);
        let mut added = existing.clone();
        added.reference = "docker.io/library/alpine:latest".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![existing.clone()],
            },
        );
        let unpacked = unpacked_dir_if_present(tmp.path(), SAMPLE_DIGEST).unwrap();
        let rootfs = safe_cache_path(tmp.path(), existing.rootfs_path.as_deref().unwrap()).unwrap();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let remove_cache = tmp.path().to_path_buf();
        let remover = std::thread::spawn(move || {
            remove_image_with(&remove_cache, "docker.io/library/alpine:3.20", || {
                locked_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
            })
        });
        locked_rx.recv().expect("remover holds resources");

        let (wait_tx, wait_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let upsert_cache = tmp.path().to_path_buf();
        let upserter = std::thread::spawn(move || {
            let result = upsert_cached_image_with_wait_observer(&upsert_cache, added, |wait| {
                wait_tx.send(wait).expect("report upsert wait");
            });
            result_tx.send(result).unwrap();
        });
        assert_eq!(
            wait_rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("upsert reaches remover's resource lock"),
            CacheLockWait::Resource
        );
        continue_tx.send(()).unwrap();
        remover.join().unwrap().expect("remove wins");
        let err = result_rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap()
            .expect_err("deleted resources must not be registered");
        upserter.join().unwrap();

        assert!(format!("{err:#}").contains("complete unpacked tree"));
        assert!(load_index(tmp.path()).unwrap().images.is_empty());
        assert!(!unpacked.exists());
        assert!(!rootfs.exists());
    }

    #[test]
    fn missing_index_lists_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rows = list_rows(tmp.path(), None).expect("list");
        assert!(rows.is_empty());
    }

    #[test]
    fn registry_filter_limits_list_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut other = sample_image("ghcr.io/acme/app:1", "sha256:app", "blobs/app");
        other.registry = "ghcr.io".to_string();
        other.repository = "acme/app".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![
                    sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "blobs/a"),
                    other,
                ],
            },
        );

        let rows = list_rows(tmp.path(), Some("ghcr.io")).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reference, "ghcr.io/acme/app:1");
    }

    #[test]
    fn inspect_resolves_by_reference_and_digest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let image = sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "blobs/a");
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(
            tmp.path(),
            "manifests/alpine.json",
            br#"{"schemaVersion":2}"#,
        );
        write_file(
            tmp.path(),
            "configs/alpine.json",
            br#"{"architecture":"arm64"}"#,
        );
        write_file(
            tmp.path(),
            "claims/alpine.json",
            br#"{"labels":{"mvm":"yes"}}"#,
        );

        let by_ref =
            inspect_image(tmp.path(), "docker.io/library/alpine:3.20").expect("inspect by ref");
        let by_digest = inspect_image(tmp.path(), "alpine").expect("inspect by short digest");
        assert_eq!(by_ref.image.reference, by_digest.image.reference);
        assert!(by_ref.manifest.is_some());
        assert!(by_ref.config.is_some());
        assert!(by_ref.claims.is_some());
    }

    #[test]
    fn remove_refuses_paths_that_escape_cache_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut image = sample_image("docker.io/library/alpine:3.20", "sha256:alpine", "../bad");
        image.manifest_path = "../manifest.json".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );

        let err = remove_image(tmp.path(), "sha256:alpine").expect_err("unsafe path rejected");
        assert!(err.to_string().contains("escapes cache root"));
        let index = load_index(tmp.path()).expect("index still readable");
        assert_eq!(index.images.len(), 1);
    }

    #[test]
    fn remove_preserves_shared_layers_and_updates_index() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = sample_image(
            "docker.io/library/alpine:3.20",
            "sha256:first",
            "blobs/shared",
        );
        let mut second = sample_image(
            "docker.io/library/busybox:1",
            "sha256:second",
            "blobs/shared",
        );
        second.manifest_path = "manifests/busybox.json".to_string();
        second.config_path = None;
        second.claims_path = None;
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![first, second],
            },
        );
        write_file(tmp.path(), "manifests/alpine.json", b"{}");
        write_file(tmp.path(), "configs/alpine.json", b"{}");
        write_file(tmp.path(), "claims/alpine.json", b"{}");
        write_file(tmp.path(), "blobs/shared", b"layer");

        let outcome = remove_image(tmp.path(), "sha256:first").expect("remove");
        assert_eq!(outcome.removed_files, 3);
        assert!(tmp.path().join("blobs/shared").exists());
        let index = load_index(tmp.path()).expect("load index");
        assert_eq!(index.images.len(), 1);
        assert_eq!(index.images[0].reference, "docker.io/library/busybox:1");
    }

    const SAMPLE_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    /// `image rm` removes both variants of the image's rootfs, each with its
    /// sidecars, and nothing belonging to another digest.
    #[test]
    fn removing_an_image_removes_both_rootfs_variants_and_their_sidecars() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let other_hex =
            sha256_hex("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
                .unwrap();
        let mut image = sample_image("docker.io/library/alpine:3.20", SAMPLE_DIGEST, "blobs/a");
        image.config_path = None;
        image.claims_path = None;
        image.rootfs_path = Some(format!("rootfs/{hex}-tag-sealed/rootfs.ext4"));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(tmp.path(), "manifests/alpine.json", b"{}");
        for variant in ["sealed", "dev"] {
            for file in [
                "rootfs.ext4",
                "rootfs.verity",
                "rootfs.roothash",
                "mvm-meta.json",
            ] {
                write_file(
                    tmp.path(),
                    &format!("rootfs/{hex}-tag-{variant}/{file}"),
                    b"x",
                );
            }
        }
        write_file(
            tmp.path(),
            &format!("rootfs/{other_hex}-tag-dev/rootfs.ext4"),
            b"x",
        );

        let outcome = remove_image(tmp.path(), "docker.io/library/alpine:3.20").expect("remove");

        assert!(!tmp.path().join(format!("rootfs/{hex}-tag-sealed")).exists());
        assert!(!tmp.path().join(format!("rootfs/{hex}-tag-dev")).exists());
        assert!(
            tmp.path()
                .join(format!("rootfs/{other_hex}-tag-dev/rootfs.ext4"))
                .exists(),
            "another digest's rootfs is untouched"
        );
        assert_eq!(
            outcome.removed_files,
            1 + 8,
            "the manifest and both variants' files"
        );
    }

    /// Two references to one digest share everything keyed by that digest —
    /// manifest, config, claims and rootfs. Removing one keeps all of it for
    /// the other; removing the last removes it.
    #[test]
    fn removing_one_reference_keeps_what_another_reference_shares() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let config_hex =
            sha256_hex("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                .unwrap();
        let shared = [
            format!("manifests/{hex}.json"),
            format!("configs/{config_hex}.json"),
            format!("claims/{hex}.provenance.json"),
            format!("rootfs/{hex}-tag-dev/rootfs.ext4"),
        ];
        let mut by_tag = sample_image("docker.io/library/alpine:3.20", SAMPLE_DIGEST, "blobs/a");
        by_tag.manifest_path = shared[0].clone();
        by_tag.config_path = Some(shared[1].clone());
        by_tag.claims_path = Some(shared[2].clone());
        by_tag.rootfs_path = Some(shared[3].clone());
        let mut by_other = by_tag.clone();
        by_other.reference = "docker.io/library/alpine:latest".to_string();
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![by_tag, by_other],
            },
        );
        for path in &shared {
            write_file(tmp.path(), path, b"x");
        }
        write_file(tmp.path(), "blobs/a", b"layer");

        remove_image(tmp.path(), "docker.io/library/alpine:3.20").expect("remove");

        for path in &shared {
            assert!(
                tmp.path().join(path).exists(),
                "{path} is still the other reference's"
            );
        }

        remove_image(tmp.path(), "docker.io/library/alpine:latest").expect("remove the last");

        for path in &shared {
            assert!(
                !tmp.path().join(path).exists(),
                "{path} goes with the last reference"
            );
        }
    }

    #[test]
    fn unpacked_state_is_removed_only_with_the_last_digest_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let mut by_tag = sample_image(
            "docker.io/library/alpine:3.20",
            SAMPLE_DIGEST,
            "blobs/shared",
        );
        by_tag.config_path = None;
        by_tag.claims_path = None;
        let mut by_digest = by_tag.clone();
        by_digest.reference = format!("docker.io/library/alpine@{SAMPLE_DIGEST}");
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![by_tag, by_digest],
            },
        );
        let unpacked = tmp.path().join("unpacked").join(&hex);
        std::fs::create_dir_all(unpacked.join("usr/bin")).unwrap();
        std::fs::write(unpacked.join("usr/bin/tool"), b"tool").unwrap();
        write_layer_owners(
            tmp.path(),
            SAMPLE_DIGEST,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .unwrap();
        write_deferred_nodes(
            tmp.path(),
            SAMPLE_DIGEST,
            &[mvm_fs::ext4::Node::Symlink {
                path: "/usr/bin/alias".to_string(),
                target: "tool".to_string(),
                owner: mvm_fs::ext4::Owner::ROOT,
            }],
        )
        .unwrap();
        let owners = tmp
            .path()
            .join("unpacked")
            .join(format!("{hex}.owners.json"));
        let deferred = tmp
            .path()
            .join("unpacked")
            .join(format!("{hex}.deferred-nodes.json"));

        remove_image(tmp.path(), "docker.io/library/alpine:3.20").expect("remove one ref");
        assert!(unpacked.exists());
        assert!(owners.exists());
        assert!(deferred.exists());

        remove_image(
            tmp.path(),
            &format!("docker.io/library/alpine@{SAMPLE_DIGEST}"),
        )
        .expect("remove last ref");
        assert!(!unpacked.exists());
        assert!(!owners.exists());
        assert!(!deferred.exists());
    }

    #[test]
    fn removing_last_reference_waits_for_unpacked_tree_readers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let image = sample_image(
            "docker.io/library/alpine:3.20",
            SAMPLE_DIGEST,
            "blobs/alpine",
        );
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        let unpacked = tmp.path().join("unpacked").join(hex);
        std::fs::create_dir_all(&unpacked).unwrap();
        std::fs::write(unpacked.join("file"), b"body").unwrap();
        let reading = mvm_build::run_image::lock_unpacked_tree(&unpacked).expect("tree lock");
        let (wait_tx, wait_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let cache = tmp.path().to_path_buf();
        let remover = std::thread::spawn(move || {
            done_tx
                .send(remove_image_with_wait_observer(
                    &cache,
                    "docker.io/library/alpine:3.20",
                    |wait| wait_tx.send(wait).expect("report remove wait"),
                    || {},
                ))
                .unwrap();
        });

        assert_eq!(
            wait_rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("remove reaches reader's unpacked-tree lock"),
            CacheLockWait::Resource
        );
        drop(reading);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap()
            .expect("remove after reader exits");
        remover.join().unwrap();
        assert!(!unpacked.exists());
    }

    /// A rootfs recorded outside `rootfs/` by an older cache is still removed.
    #[test]
    fn removing_an_image_removes_a_legacy_rootfs_outside_the_rootfs_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut image = sample_image("docker.io/library/alpine:3.20", SAMPLE_DIGEST, "blobs/a");
        image.config_path = None;
        image.claims_path = None;
        image.rootfs_path = Some("legacy/alpine.ext4".to_string());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(tmp.path(), "manifests/alpine.json", b"{}");
        write_file(tmp.path(), "legacy/alpine.ext4", b"x");

        remove_image(tmp.path(), "docker.io/library/alpine:3.20").expect("remove");

        assert!(!tmp.path().join("legacy/alpine.ext4").exists());
    }

    /// `image rm` waits for a run building the image, and leaves the build
    /// lock's file in place, outside the directory it removes: a waiter must
    /// never end up holding a lock on a file the next run cannot see.
    #[test]
    fn removing_an_image_waits_for_its_build_and_keeps_the_lock_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let rel = format!("rootfs/{hex}-tag-dev/rootfs.ext4");
        let mut image = sample_image("docker.io/library/alpine:3.20", SAMPLE_DIGEST, "blobs/a");
        image.config_path = None;
        image.claims_path = None;
        image.rootfs_path = Some(rel.clone());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(tmp.path(), &rel, b"x");
        let rootfs = tmp.path().join(&rel);
        let building = mvm_build::run_image::lock_rootfs_output(&rootfs).expect("build lock");

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let cache = tmp.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let result = remove_image(&cache, "docker.io/library/alpine:3.20");
            done_tx.send(result.is_ok()).unwrap();
        });
        assert!(
            matches!(
                done_rx.recv_timeout(std::time::Duration::from_millis(500)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "image rm removed a rootfs a run was still building"
        );
        drop(building);
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .unwrap()
        );
        worker.join().unwrap();

        assert!(!rootfs.parent().unwrap().exists());
        let lock_files: Vec<_> = std::fs::read_dir(tmp.path().join("rootfs/.locks"))
            .expect("the lock directory survives")
            .collect();
        assert_eq!(
            lock_files.len(),
            1,
            "the build lock's file is not removed with the image"
        );
    }

    #[test]
    fn deferred_nodes_roundtrip_through_the_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nodes = vec![
            mvm_fs::ext4::Node::Symlink {
                path: "/usr/share/man/man7/pam.7.gz".to_string(),
                target: "PAM.7.gz".to_string(),
                owner: mvm_fs::ext4::Owner::ROOT,
            },
            mvm_fs::ext4::Node::File {
                path: "/opt/run".to_string(),
                mode: 0o755,
                data: b"body".to_vec(),
                xattrs: Vec::new(),
                owner: mvm_fs::ext4::Owner::ROOT,
            },
        ];
        write_deferred_nodes(tmp.path(), SAMPLE_DIGEST, &nodes).expect("write");
        assert_eq!(
            read_deferred_nodes(tmp.path(), SAMPLE_DIGEST).expect("read"),
            Some(nodes)
        );
    }

    #[test]
    fn absent_sidecar_reads_as_nothing_deferred() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(
            read_deferred_nodes(tmp.path(), SAMPLE_DIGEST)
                .expect("read")
                .is_some_and(|nodes| nodes.is_empty()),
            "a case-sensitive host writes no sidecar, and that is not an error"
        );
    }

    #[test]
    fn writing_an_empty_set_clears_a_stale_sidecar() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nodes = vec![mvm_fs::ext4::Node::Symlink {
            path: "/a".to_string(),
            target: "b".to_string(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }];
        write_deferred_nodes(tmp.path(), SAMPLE_DIGEST, &nodes).expect("write");
        write_deferred_nodes(tmp.path(), SAMPLE_DIGEST, &[]).expect("clear");
        assert!(
            read_deferred_nodes(tmp.path(), SAMPLE_DIGEST)
                .expect("read")
                .is_some_and(|nodes| nodes.is_empty()),
            "a re-pull that defers nothing must not inherit the old sidecar"
        );
    }

    #[test]
    fn layer_owners_roundtrip_through_their_sidecar() {
        use mvm_fs::oci::unpack::{UnpackOptions, unpack_layer};

        let tmp = tempfile::tempdir().expect("tempdir");
        let unpacked = tempfile::tempdir().expect("unpacked");
        let mut header = tar::Header::new_gnu();
        header.set_path("var/lib/svc/").unwrap();
        header.set_size(0);
        header.set_mode(0o750);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_uid(999);
        header.set_gid(70_000);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, std::io::empty()).unwrap();
        let layer = builder.into_inner().unwrap();
        let report = unpack_layer(layer.as_slice(), unpacked.path(), &UnpackOptions::default())
            .expect("unpack");
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        owners.absorb(&report.ownership);

        write_layer_owners(tmp.path(), SAMPLE_DIGEST, &owners).expect("write");
        let read = read_layer_owners(tmp.path(), SAMPLE_DIGEST)
            .expect("read")
            .expect("sidecar present");
        assert_eq!(read, owners);
        assert_eq!(
            read.owner_of("/var/lib/svc"),
            mvm_fs::ext4::Owner::new(999, 70_000)
        );
    }

    #[test]
    fn a_tree_with_no_owner_sidecar_reads_as_unrecorded_not_as_root_owned() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(
            read_layer_owners(tmp.path(), SAMPLE_DIGEST)
                .expect("read")
                .is_none(),
            "a tree unpacked before owners were recorded must not pass for an all-root image"
        );
        write_layer_owners(
            tmp.path(),
            SAMPLE_DIGEST,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .expect("write");
        assert_eq!(
            read_layer_owners(tmp.path(), SAMPLE_DIGEST).expect("read"),
            Some(mvm_fs::ownership::OwnerTable::new()),
            "an image whose layers declare only root is still recorded"
        );
    }

    /// Overwrite a sidecar with `body`, as a crash mid-write or a stray edit
    /// would leave it.
    fn clobber(tmp: &Path, suffix: &str, body: &[u8]) {
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let path = tmp.join("unpacked").join(format!("{hex}.{suffix}"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn owner_table_json() -> Vec<u8> {
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        let tree = tempfile::tempdir().unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_path("srv/").unwrap();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_uid(999);
        header.set_gid(999);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, std::io::empty()).unwrap();
        let report = mvm_fs::oci::unpack::unpack_layer(
            builder.into_inner().unwrap().as_slice(),
            tree.path(),
            &mvm_fs::oci::unpack::UnpackOptions::default(),
        )
        .unwrap();
        owners.absorb(&report.ownership);
        serde_json::to_vec(&owners).unwrap()
    }

    /// A write cut short leaves a prefix of valid JSON. That used to be a hard
    /// error on every read, wedging the image until the file was deleted by
    /// hand; it now reads as unrecorded, which sends the caller to unpack again.
    #[test]
    fn a_truncated_owner_sidecar_reads_as_unrecorded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let full = owner_table_json();
        clobber(tmp.path(), "owners.json", &full[..full.len() / 2]);
        assert_eq!(
            read_layer_owners(tmp.path(), SAMPLE_DIGEST).expect("not an error"),
            None
        );
    }

    #[test]
    fn a_garbage_owner_sidecar_reads_as_unrecorded() {
        let tmp = tempfile::tempdir().expect("tempdir");
        clobber(tmp.path(), "owners.json", b"\x00\xffnot json");
        assert_eq!(
            read_layer_owners(tmp.path(), SAMPLE_DIGEST).expect("not an error"),
            None
        );
    }

    /// An unreadable deferred-node sidecar is not "nothing deferred": nodes
    /// were deferred and we no longer know which, so an image rebuilt as if
    /// the list were empty would be quietly missing paths.
    #[test]
    fn a_truncated_deferred_sidecar_reads_as_unknown_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nodes = vec![mvm_fs::ext4::Node::Symlink {
            path: "/a".to_string(),
            target: "b".to_string(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }];
        let full = serde_json::to_vec_pretty(&nodes).unwrap();
        clobber(tmp.path(), "deferred-nodes.json", &full[..full.len() - 3]);
        assert_eq!(
            read_deferred_nodes(tmp.path(), SAMPLE_DIGEST).expect("not an error"),
            None
        );
    }

    /// A sidecar that exists and cannot be read is an error, never "nothing
    /// deferred": here a directory stands where the file should be.
    #[test]
    fn an_unreadable_deferred_sidecar_is_an_error_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let path = tmp
            .path()
            .join("unpacked")
            .join(format!("{hex}.deferred-nodes.json"));
        std::fs::create_dir_all(&path).unwrap();
        let err = read_deferred_nodes(tmp.path(), SAMPLE_DIGEST)
            .expect_err("an unreadable sidecar must not read as empty");
        assert!(
            format!("{err:#}").contains("deferred-nodes.json"),
            "{err:#}"
        );
    }

    #[test]
    fn a_garbage_deferred_sidecar_reads_as_unknown_not_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        clobber(tmp.path(), "deferred-nodes.json", b"}{");
        assert_eq!(
            read_deferred_nodes(tmp.path(), SAMPLE_DIGEST).expect("not an error"),
            None
        );
    }

    /// The tree survives, but either sidecar is unreadable: the cached unpack
    /// is unusable as a whole, so the caller unpacks again rather than
    /// building an image with the wrong owners or missing paths.
    #[test]
    fn a_cached_unpack_with_a_corrupt_sidecar_is_not_offered() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        std::fs::create_dir_all(tmp.path().join("unpacked").join(&hex)).unwrap();
        write_layer_owners(
            tmp.path(),
            SAMPLE_DIGEST,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .unwrap();
        assert!(
            read_cached_unpack(tmp.path(), SAMPLE_DIGEST)
                .unwrap()
                .is_some(),
            "a complete cached unpack is offered"
        );

        clobber(tmp.path(), "deferred-nodes.json", b"{");
        assert!(
            read_cached_unpack(tmp.path(), SAMPLE_DIGEST)
                .unwrap()
                .is_none()
        );

        write_deferred_nodes(tmp.path(), SAMPLE_DIGEST, &[]).unwrap();
        clobber(tmp.path(), "owners.json", b"{\"/srv\":");
        assert!(
            read_cached_unpack(tmp.path(), SAMPLE_DIGEST)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_sidecar_sits_beside_the_unpacked_tree_not_inside_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let nodes = vec![mvm_fs::ext4::Node::Symlink {
            path: "/a".to_string(),
            target: "b".to_string(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }];
        write_deferred_nodes(tmp.path(), SAMPLE_DIGEST, &nodes).expect("write");

        let hex = sha256_hex(SAMPLE_DIGEST).unwrap();
        let unpacked_root = tmp.path().join("unpacked").join(&hex);
        std::fs::create_dir_all(&unpacked_root).unwrap();
        assert!(
            std::fs::read_dir(&unpacked_root).unwrap().next().is_none(),
            "the sidecar must never be walked into the image as a file of its own"
        );
    }
}
