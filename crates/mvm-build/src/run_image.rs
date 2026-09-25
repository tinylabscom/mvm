//! Run-path rootfs materialization: turn an unpacked OCI tree into the bootable
//! `rootfs.ext4`, in-process by default (the pure-Rust `mvm-ext4` writer — no
//! builder VM, no `mkfs`, no subprocess).
//!
//! Shared by the CLI's `run --image` path and the `mvm-client` local backend so
//! both drive one orchestration: resolve the guest-agent binaries, inject the
//! mvm runtime into the unpacked tree, materialize the ext4 image, and write the
//! overlay-aware guest sidecar beside it.

use std::path::Path;

use anyhow::{Context, Result};

use crate::oci_runtime_inject::{ImageRuntimeConfig, MvmRuntimeBinaries};
use crate::provenance_mark::SealEvidence;
use crate::rootfs::MaterializeExt4Input;
use mvm_fs::oci_to_rootfs::{
    MaterializedRootfs, OciUnpackError, VeritySealedRootfs, VeritysetupOptions, seal_with_verity,
};

pub struct InjectAndMaterializeRequest<'a> {
    cache_root: &'a Path,
    unpacked_root: &'a Path,
    output: &'a Path,
    label: &'a str,
    entrypoint: Option<&'a ImageRuntimeConfig>,
    sealed: bool,
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
    owners: mvm_fs::ownership::OwnerTable,
    evidence: Option<SealEvidence<'a>>,
    reuse_published: bool,
}

impl<'a> InjectAndMaterializeRequest<'a> {
    pub fn builder(
        cache_root: &'a Path,
        unpacked_root: &'a Path,
        output: &'a Path,
        label: &'a str,
    ) -> InjectAndMaterializeRequestBuilder<'a> {
        InjectAndMaterializeRequestBuilder {
            cache_root,
            unpacked_root,
            output,
            label,
            entrypoint: None,
            sealed: false,
            deferred_nodes: Vec::new(),
            owners: mvm_fs::ownership::OwnerTable::new(),
            evidence: None,
            reuse_published: false,
        }
    }
}

pub struct InjectAndMaterializeRequestBuilder<'a> {
    cache_root: &'a Path,
    unpacked_root: &'a Path,
    output: &'a Path,
    label: &'a str,
    entrypoint: Option<&'a ImageRuntimeConfig>,
    sealed: bool,
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
    owners: mvm_fs::ownership::OwnerTable,
    evidence: Option<SealEvidence<'a>>,
    reuse_published: bool,
}

impl<'a> InjectAndMaterializeRequestBuilder<'a> {
    pub fn entrypoint(mut self, entrypoint: Option<&'a ImageRuntimeConfig>) -> Self {
        self.entrypoint = entrypoint;
        self
    }

    pub fn sealed(mut self, sealed: bool) -> Self {
        self.sealed = sealed;
        self
    }

    /// Carry the OCI unpacker's deferred nodes — entries a case-folding
    /// host filesystem could not hold — into the materialized image.
    pub fn deferred_nodes(mut self, deferred_nodes: Vec<mvm_fs::ext4::Node>) -> Self {
        self.deferred_nodes = deferred_nodes;
        self
    }

    /// Give the materialized image the owners its layers declared. The
    /// unpacked tree cannot hold them, so without this every file in the
    /// image is root-owned.
    pub fn owners(mut self, owners: mvm_fs::ownership::OwnerTable) -> Self {
        self.owners = owners;
        self
    }

    /// Seal-evidence inputs: when set on a `sealed` request, a signed
    /// provenance mark is written into the rootfs before the dm-verity
    /// hash is computed (so the mark is tamper-evident under verified
    /// boot) and an in-toto/DSSE provenance sidecar is written beside
    /// the sealed image. Ignored for unsealed requests.
    /// Keep a complete, matching build already published at the output
    /// instead of rebuilding it, deciding under the output lock. Only for an
    /// output whose path names its content — the image digest, the guest
    /// runtime and the variant — so that "complete and matching" means "this
    /// image". A reader's view of a published set is then never replaced
    /// under it: nothing rebuilds a set that is complete.
    pub fn reuse_published(mut self, reuse_published: bool) -> Self {
        self.reuse_published = reuse_published;
        self
    }

    pub fn evidence(mut self, evidence: Option<SealEvidence<'a>>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn build(self) -> InjectAndMaterializeRequest<'a> {
        InjectAndMaterializeRequest {
            cache_root: self.cache_root,
            unpacked_root: self.unpacked_root,
            output: self.output,
            label: self.label,
            entrypoint: self.entrypoint,
            sealed: self.sealed,
            deferred_nodes: self.deferred_nodes,
            owners: self.owners,
            evidence: self.evidence,
            reuse_published: self.reuse_published,
        }
    }
}

/// Hold `root`'s tree exclusively against every other writer and reader that
/// takes this lock, across processes.
///
/// An image's unpacked tree lives once in the cache and is injected in place,
/// so two runs of one image share it. Without the lock a dev run's clearing of
/// `/etc/mvm` and rewriting of `variant` and `/etc/passwd` can land between a
/// prod run's post-injection check and its image walk, and the sealed image
/// then carries `variant=dev` and no trust policy. Everything that removes,
/// unpacks, injects into or copies from a tree takes this lock first; nothing
/// holds it while taking another tree's lock in the other order.
///
/// The lock file sits beside the tree as `<name>.tree.lock`, so it survives
/// the tree being removed and re-unpacked under it.
pub fn lock_unpacked_tree(root: &Path) -> Result<mvm_core::util::atomic_io::FileLock> {
    lock_unpacked_tree_observed(root, || {})
}

/// Hold an unpacked tree lock and report only when another holder makes this
/// acquisition wait.
///
/// The observer runs after a non-blocking acquisition proves contention and
/// immediately before the blocking acquisition. It is primarily useful to
/// coordinate tests around the real locking seam without timing guesses.
pub fn lock_unpacked_tree_observed(
    root: &Path,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    lock_beside_with_wait(root, "tree", on_wait)
}

/// Hold the materialized image at `output` exclusively.
///
/// The lock file lives outside the image's directory, in a `.locks`
/// directory beside it (see [`output_lock_key`]). Removing an image removes
/// its directory whole, and a lock file inside it would go too: a run already
/// waiting would then hold a lock on the unlinked file while the next run
/// took one on a new file, and both would build.
fn lock_output(output: &Path) -> Result<mvm_core::util::atomic_io::FileLock> {
    lock_output_with_wait(output, || {})
}

fn lock_output_with_wait(
    output: &Path,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    take_lock_with_wait(&output_lock_key(output)?, output, "output", on_wait)
}

/// `<dir>/../.locks/<dir name>.<file name>.output.key` for an output at
/// `<dir>/<file name>`; the lock file itself replaces the `key` extension.
fn output_lock_key(output: &Path) -> Result<std::path::PathBuf> {
    let file = output
        .file_name()
        .with_context(|| format!("{} has no name to lock", output.display()))?;
    let dir = output
        .parent()
        .with_context(|| format!("{} has no directory to lock", output.display()))?;
    let dir_name = dir
        .file_name()
        .with_context(|| format!("{} has no name to lock", dir.display()))?;
    let locks = dir
        .parent()
        .with_context(|| format!("{} has no parent for its lock", dir.display()))?
        .join(".locks");
    let mut key = dir_name.to_os_string();
    key.push(".");
    key.push(file);
    key.push(".output.key");
    Ok(locks.join(key))
}

fn lock_beside_with_wait(
    path: &Path,
    role: &str,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    take_lock_with_wait(&lock_key(path, role)?, path, role, on_wait)
}

/// Take the lock at `key` for `path` in `role`, saying so when another holder
/// makes this wait: a run that stops while another materializes the same
/// image would otherwise look hung.
fn take_lock_with_wait(
    key: &Path,
    path: &Path,
    role: &str,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    let context = || format!("lock {} ({role})", path.display());
    if let Some(held) =
        mvm_core::util::atomic_io::FileLock::try_acquire(key).with_context(context)?
    {
        return Ok(held);
    }
    tracing::info!(
        path = %path.display(),
        role,
        "another run is materializing this image; waiting for it"
    );
    let waiting = mvm_vmm::host::ui::activity::start(format!(
        "waiting for another process materializing the same image ({})",
        path.display()
    ));
    on_wait();
    let held = mvm_core::util::atomic_io::FileLock::acquire(key).with_context(context);
    drop(waiting);
    held
}

/// The path [`mvm_core::util::atomic_io::FileLock`] turns into the lock file
/// for `path` in `role`. It replaces the last extension with `lock`, so the
/// key carries a throwaway one: `rootfs` locks as `rootfs.tree.lock` and
/// `rootfs.ext4` as `rootfs.ext4.output.lock`, and no two roles or names can
/// land on one file — which in one process would deadlock.
fn lock_key(path: &Path, role: &str) -> Result<std::path::PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("{} has no name to lock", path.display()))?;
    let mut key = name.to_os_string();
    key.push(format!(".{role}.key"));
    Ok(path.with_file_name(key))
}

/// An unpacked tree's lock and the lock on the image being built from it,
/// taken together in one order.
///
/// `inject_and_materialize_holding` takes `&HeldTreeLocks`, so the borrow
/// keeps both locks alive until that call returns. That is all the type
/// guarantees: it does not make the code inside the call use them, and a
/// caller holding the value may keep it longer than the call.
pub struct HeldTreeLocks {
    _tree: mvm_core::util::atomic_io::FileLock,
    _output: mvm_core::util::atomic_io::FileLock,
}

impl HeldTreeLocks {
    /// Take the tree's lock, then the output's. Every holder of both takes
    /// them in this order.
    pub fn acquire(tree: &Path, output: &Path) -> Result<Self> {
        Self::acquire_observed(tree, output, || {})
    }

    /// Take the tree and output locks in canonical order, reporting each
    /// acquisition that must wait for another holder.
    pub fn acquire_observed(tree: &Path, output: &Path, mut on_wait: impl FnMut()) -> Result<Self> {
        Ok(Self {
            _tree: lock_unpacked_tree_observed(tree, &mut on_wait)?,
            _output: lock_output_with_wait(output, on_wait)?,
        })
    }
}

/// Inject the mvm runtime into `unpacked_root`, materialize it into `output` (a
/// `rootfs.ext4` path), and write the overlay-aware guest sidecar beside it.
/// `cache_root` holds the guest-agent binary cache; `label` names the image in
/// the sidecar.
///
/// When `sealed` is set (the `--prod` OCI run), the materialized rootfs is
/// dm-verity-sealed (see [`seal_rootfs_for_run`]) and the sidecar is written
/// `sealed`, so the runtime routes the block+ext4 verity boot and refuses
/// interactive access.
///
/// Guest binaries resolve from the invoking source checkout's content-keyed
/// cache or an existing compatibility cache. The host executable does not carry
/// workload binaries.
///
/// The tree and the output are locked before any work starts and stay locked
/// until it returns ([`HeldTreeLocks`]): the injection, the post-injection
/// check, the walk, the seal and the publish all read or write one or the
/// other.
pub fn inject_and_materialize(request: InjectAndMaterializeRequest<'_>) -> Result<()> {
    let held = HeldTreeLocks::acquire(request.unpacked_root, request.output)?;
    inject_and_materialize_holding(request, &held)
}

fn inject_and_materialize_holding(
    request: InjectAndMaterializeRequest<'_>,
    _held: &HeldTreeLocks,
) -> Result<()> {
    let InjectAndMaterializeRequest {
        cache_root,
        unpacked_root,
        output,
        label,
        entrypoint,
        sealed,
        deferred_nodes,
        owners,
        evidence,
        reuse_published,
    } = request;
    let rootfs_dir = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent dir: {}", output.display()))?;
    std::fs::create_dir_all(rootfs_dir)
        .with_context(|| format!("create {}", rootfs_dir.display()))?;
    // Decided under the output lock: a caller's own reuse check ran before it
    // took the lock, and another run may have published this set since. A
    // complete, matching set is never rebuilt, so one a reader has chosen is
    // never swapped out beneath it.
    if reuse_published && published_build_matches(output, sealed) {
        return Ok(());
    }
    remove_stale_builds(rootfs_dir)?;
    crate::oci_runtime_inject::refuse_layer_nodes_at_injected_paths(&deferred_nodes)
        .context("admit the image's deferred layer nodes")?;
    let bins = resolve_guest_binaries(cache_root)?;
    crate::oci_runtime_inject::inject_mvm_runtime(unpacked_root, &bins, entrypoint, sealed)
        .context("inject mvm runtime into OCI rootfs")?;
    ensure_volume_mount_roots(unpacked_root)?;

    // The provenance mark must land inside the tree BEFORE any hashing:
    // both the materializer's sizing pass below and the verity seal hash
    // the exact bytes they see, so a mark written later would change the
    // roothash and break the signature's coverage.
    let seal_started = chrono::Utc::now().to_rfc3339();
    maybe_write_provenance_mark(unpacked_root, sealed, evidence.as_ref())?;

    // The whole artifact set — image, verity tree, root hash, provenance, and
    // last the guest sidecar — is built in a scratch directory beside the
    // output and published into place only once it is complete. Built in place,
    // a run that died part-way left a partial image next to the previous
    // build's sidecars, and every later run reused it and failed at dm-verity.
    let staging = tempfile::Builder::new()
        .prefix(ROOTFS_BUILD_PREFIX)
        .tempdir_in(rootfs_dir)
        .with_context(|| format!("create a build dir in {}", rootfs_dir.display()))?;
    let staged_output =
        staging.path().join(output.file_name().ok_or_else(|| {
            anyhow::anyhow!("rootfs path has no file name: {}", output.display())
        })?);

    // Measure AFTER injection so the ext4 sizing covers everything injected.
    let tree_size = unpacked_tree_size(unpacked_root)
        .with_context(|| format!("measure unpacked root {}", unpacked_root.display()))?;
    materialize_run_rootfs(
        &MaterializeExt4Input::new(
            unpacked_root.to_path_buf(),
            staged_output.clone(),
            tree_size,
        )
        .with_deferred_nodes(deferred_nodes)
        .with_owners(owners),
    )?;

    // `--prod`: seal the rootfs before the sidecar is written. If this fails we
    // surface it and never write a `sealed` sidecar over a rootfs that can't
    // verity-boot.
    if sealed {
        seal_rootfs_for_run(&staged_output)?;
        if let Some(evidence) = &evidence {
            let subject_sha256 = mvm_core::crypto::image_verify::sha256_file(&staged_output)
                .context("hash sealed rootfs for provenance sidecar")?;
            crate::intoto::write_sidecar(
                &staged_output,
                &subject_sha256,
                evidence,
                &seal_started,
                &chrono::Utc::now().to_rfc3339(),
            )
            .context("write in-toto provenance sidecar")?;
        }
    }

    // The sidecar lives next to rootfs.ext4 so the backend's admit_runtime_overlay_contract
    // gate reads it at start.
    oci_run_sidecar(unpacked_root, label, sealed, entrypoint)
        .write_to_dir(staging.path())
        .with_context(|| format!("write OCI sidecar in {}", staging.path().display()))?;
    publish_rootfs_build(staging.path(), rootfs_dir)?;
    Ok(())
}

/// Prefix of the scratch directory an image is built in beside its output.
const ROOTFS_BUILD_PREFIX: &str = ".rootfs-build-";

/// Remove scratch build directories a run that died left in `rootfs_dir`.
/// Called under the output lock, so none of them belongs to a live build.
fn remove_stale_builds(rootfs_dir: &Path) -> Result<()> {
    for entry in
        std::fs::read_dir(rootfs_dir).with_context(|| format!("list {}", rootfs_dir.display()))?
    {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(ROOTFS_BUILD_PREFIX)
            && entry.file_type()?.is_dir()
        {
            std::fs::remove_dir_all(entry.path())
                .with_context(|| format!("remove stale build {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Move a complete artifact set from `staging` into `rootfs_dir`.
///
/// The guest sidecar is what marks a set complete: a reuse check requires it
/// (see [`rootfs_build_is_complete`]). So the published sidecar is removed
/// before anything else is replaced, every other file is renamed into place,
/// and the new sidecar is renamed in last. A run that dies at any point leaves
/// either the old set whole or a set with no sidecar, which is rebuilt.
fn publish_rootfs_build(staging: &Path, rootfs_dir: &Path) -> Result<()> {
    publish_rootfs_build_with(staging, rootfs_dir, mvm_core::util::atomic_io::sync_dir)
}

fn publish_rootfs_build_with(
    staging: &Path,
    rootfs_dir: &Path,
    sync_dir: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let sidecar = crate::builder_vm::SIDECAR_FILENAME;
    // On disk before the published set is touched, so a crash after a rename
    // cannot leave a published name pointing at data that never reached it.
    for entry in
        std::fs::read_dir(staging).with_context(|| format!("list {}", staging.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::File::open(entry.path())
                .and_then(|file| file.sync_all())
                .with_context(|| format!("flush {}", entry.path().display()))?;
        }
    }
    match std::fs::remove_file(rootfs_dir.join(sidecar)) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("retire the sidecar in {}", rootfs_dir.display()));
        }
    }
    for entry in
        std::fs::read_dir(staging).with_context(|| format!("list {}", staging.display()))?
    {
        let entry = entry?;
        if entry.file_name() == sidecar || !entry.file_type()?.is_file() {
            continue;
        }
        let target = rootfs_dir.join(entry.file_name());
        std::fs::rename(entry.path(), &target)
            .with_context(|| format!("publish {}", target.display()))?;
    }
    std::fs::rename(staging.join(sidecar), rootfs_dir.join(sidecar))
        .with_context(|| format!("publish the sidecar in {}", rootfs_dir.display()))?;
    sync_dir(rootfs_dir)
        .with_context(|| format!("sync published rootfs directory {}", rootfs_dir.display()))
}

/// Whether the artifact set beside `rootfs` finished publishing: its guest
/// sidecar, renamed in last by [`publish_rootfs_build`], is there and reads.
pub fn rootfs_build_is_complete(rootfs: &Path) -> bool {
    rootfs.is_file()
        && rootfs.parent().is_some_and(|dir| {
            matches!(
                crate::builder_vm::GuestSidecar::read_from_dir(dir),
                Ok(Some(_))
            )
        })
}

/// Whether the set published at `rootfs` is a finished build of this variant:
/// complete ([`rootfs_build_is_complete`]), with its verity tree and root
/// hash, and a sidecar recording `sealed` exactly when `sealed` is asked for.
/// Read under the output lock to mean anything.
pub fn published_build_matches(rootfs: &Path, sealed: bool) -> bool {
    let Some(dir) = rootfs.parent() else {
        return false;
    };
    rootfs_build_is_complete(rootfs)
        && dir.join("rootfs.verity").is_file()
        && dir.join("rootfs.roothash").is_file()
        && matches!(
            crate::builder_vm::GuestSidecar::read_from_dir(dir),
            Ok(Some(sidecar)) if sidecar.sealed == sealed
        )
}

/// Hold the output lock of the image at `rootfs`, for a caller that decides
/// whether to reuse it: no build can be publishing while the lock is held.
pub fn lock_rootfs_output(rootfs: &Path) -> Result<mvm_core::util::atomic_io::FileLock> {
    lock_output(rootfs)
}

/// Hold a materialized image lock and report only when another holder makes
/// this acquisition wait.
pub fn lock_rootfs_output_observed(
    rootfs: &Path,
    on_wait: impl FnOnce(),
) -> Result<mvm_core::util::atomic_io::FileLock> {
    lock_output_with_wait(rootfs, on_wait)
}

/// Write the signed provenance mark into the tree being sealed, when the
/// caller asked for a sealed image and supplied seal evidence.
///
/// A sealed image with no evidence is a caller mistake worth a loud warning,
/// not a hard failure: the verity seal itself still stands, and the run-path
/// self-heal may seal again with evidence present. An unsealed image never
/// carries the mark — without the verity boot chain there is nothing for the
/// signature to be tamper-evident under.
fn maybe_write_provenance_mark(
    unpacked_root: &Path,
    sealed: bool,
    evidence: Option<&SealEvidence<'_>>,
) -> Result<()> {
    if !sealed {
        return Ok(());
    }
    match evidence {
        Some(evidence) => crate::provenance_mark::write_mark(unpacked_root, evidence)
            .context("write provenance mark into rootfs"),
        None => {
            tracing::warn!(
                "sealed rootfs carries no provenance mark: caller supplied no seal evidence"
            );
            Ok(())
        }
    }
}

/// Build the sidecar describing a materialized OCI run rootfs.
///
/// Both recorded facts are things the host can establish only while
/// `unpacked_root` is still a directory: once this tree is an ext4 blob nothing
/// on the host opens it again. The argv is what admission needs to know an
/// image runs before deciding whether anything may drive its stdin; the libc is
/// what decides whether the SDK host-services cdylib can load in this image at
/// all.
///
/// Reading the libc after `inject_mvm_runtime` is deliberate and safe: the
/// injected guest binaries are statically linked and land in `usr/local/bin`,
/// so they add no dynamic loader to `lib` or `lib64` and cannot change the
/// verdict.
///
/// Always runtime-lean: the overlay is the single source of the guest binaries,
/// so an injected rootfs never carries a copy of them.
fn oci_run_sidecar(
    unpacked_root: &Path,
    label: &str,
    sealed: bool,
    entrypoint: Option<&ImageRuntimeConfig>,
) -> crate::builder_vm::GuestSidecar {
    crate::builder_vm::GuestSidecar::for_oci_run(label, sealed, true)
        .with_entrypoint_argv(entrypoint.map(|e| e.argv.clone()).unwrap_or_default())
        .with_libc(crate::guest_libc::detect_guest_libc(unpacked_root))
}

/// Materialize the admitted top-level guest volume roots into every sealed OCI
/// image. The root becomes dm-verity read-only before PID 1 runs, so mountpoints
/// cannot be created lazily inside the guest.
fn ensure_volume_mount_roots(unpacked_root: &Path) -> Result<()> {
    for relative in ["data", "work", "mnt"] {
        let path = unpacked_root.join(relative);
        std::fs::create_dir_all(&path)
            .with_context(|| format!("create guest volume mount root {}", path.display()))?;
    }
    Ok(())
}

/// Seal an already-materialized `rootfs_ext4`, writing its dm-verity sidecars
/// (`rootfs.verity` + `rootfs.roothash`).
///
/// There is no longer a sibling `rootfs.initrd` to keep in step: the universal
/// initramfs is the only initramfs, it is attached from the shared cache rather
/// than assembled per rootfs, and the guest agent it boots sets up the
/// dm-verity target itself before pivoting. So this is a plain seal, with none
/// of the write-first/roll-back ordering the paired artifacts used to need.
fn seal_rootfs_for_run(rootfs_ext4: &Path) -> Result<()> {
    seal_run_rootfs_for_runtime(rootfs_ext4)
        .with_context(|| format!("dm-verity seal {}", rootfs_ext4.display()))
}

fn seal_run_rootfs_for_runtime(rootfs_ext4: &Path) -> Result<()> {
    seal_run_rootfs_for_runtime_with(
        rootfs_ext4,
        seal_run_rootfs_with_verity,
        seal_run_rootfs_with_verity_builder_vm,
    )
}

fn seal_run_rootfs_for_runtime_with(
    rootfs_ext4: &Path,
    seal_local: impl FnOnce(&Path) -> std::result::Result<VeritySealedRootfs, OciUnpackError>,
    seal_builder_vm: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    match seal_local(rootfs_ext4) {
        Ok(_) => Ok(()),
        Err(OciUnpackError::HostUnsupported { .. }) => seal_builder_vm(rootfs_ext4),
        Err(e) => Err(anyhow::Error::new(e)),
    }
}

fn seal_run_rootfs_with_verity_builder_vm(rootfs_ext4: &Path) -> Result<()> {
    use crate::builder_vm::BuilderShellJob;

    let artifact_out = rootfs_ext4
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent dir: {}", rootfs_ext4.display()))?
        .to_path_buf();
    let script = verity_seal_script(rootfs_ext4)?;
    let shell_job = BuilderShellJob {
        work_dir: artifact_out.clone(),
        artifact_out,
        script,
        extra_disks: vec![],
    };

    let selected = crate::builder_backend_select::resolve_choice();
    let explicit = crate::builder_backend_select::resolve_env_override().is_some();
    crate::builder_backend_select::run_with_builder_fallback(selected, explicit, |choice| {
        // Through the trait, so the backend the selection resolved is the one
        // that runs the job. This used to match on the choice here, and mapped
        // `Hvf` onto `LibkrunBuilderVm` — which quietly ran an HVF host's shell
        // jobs on libkrun, and is exactly the coupling the builder path is
        // meant not to have.
        crate::builder_backend_select::try_resolve_builder_backend_for(choice)?
            .run_shell_script(&shell_job)
            .map(|_| ())
    })?;
    Ok(())
}

fn verity_seal_script(rootfs_ext4: &Path) -> Result<String> {
    let rootfs_name = rootfs_ext4
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rootfs path has no UTF-8 file name: {}",
                rootfs_ext4.display()
            )
        })?;
    let stem = rootfs_ext4
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "rootfs path has no UTF-8 file stem: {}",
                rootfs_ext4.display()
            )
        })?;
    let sidecar_name = format!("{stem}.verity");
    let roothash_name = format!("{stem}.roothash");
    Ok(format!(
        r#"#!/bin/sh
set -eu

ROOTFS="/out/{rootfs_name}"
VERITY="/out/{sidecar_name}"
ROOTHASH="/out/{roothash_name}"

rm -f "$VERITY" "$ROOTHASH"
veritysetup_out="$(
  veritysetup format \
    --data-block-size={data_block_size} \
    --hash-block-size={hash_block_size} \
    --salt={salt} \
    --uuid={uuid} \
    --hash={algorithm} \
    "$ROOTFS" \
    "$VERITY"
)"
roothash="$(
  printf '%s\n' "$veritysetup_out" \
    | sed -n 's/^Root hash:[[:space:]]*//p' \
    | tr 'A-F' 'a-f' \
    | head -n1
)"
[ -n "$roothash" ] || {{
  echo "veritysetup format succeeded but produced no Root hash: line" >&2
  exit 1
}}
printf '%s\n' "$roothash" > "$ROOTHASH"
"#,
        rootfs_name = rootfs_name,
        sidecar_name = sidecar_name,
        roothash_name = roothash_name,
        data_block_size = mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE,
        hash_block_size = mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE,
        salt = mvm_fs::oci_to_rootfs::MVM_VERITY_PINNED_SALT,
        uuid = mvm_fs::oci_to_rootfs::verity::MVM_VERITY_PINNED_UUID,
        algorithm = mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM,
    ))
}

/// Resolve the guest-agent binaries.
///
/// A source checkout resolves the invoking checkout's guest sources through a
/// content-keyed cache, so local edits rebuild instead of serving a stale
/// version+arch entry. An installed caller may reuse a complete compatibility
/// cache, but the released workload path obtains guest code from the universal
/// initramfs and runtime overlay.
pub fn resolve_guest_binaries(cache_root: &Path) -> Result<MvmRuntimeBinaries> {
    let arch = mvm_core::arch::GuestArch::host();

    match crate::guest_agent_build::guest_binary_source()
        .context("resolve the guest-binary cache key for this host")?
    {
        crate::guest_agent_build::GuestBinarySource::SourceCheckout {
            workspace_root,
            cache_key,
        } => {
            return crate::guest_agent_build::resolve_or_build_guest_binaries(
                cache_root,
                &cache_key,
                arch,
                &workspace_root,
            )
            .context("build guest agent binaries from the source checkout");
        }
        crate::guest_agent_build::GuestBinarySource::EmbeddedVersion { cache_key } => {
            if let Some(cached) =
                crate::guest_agent_build::cached_guest_binaries(cache_root, &cache_key, arch)
            {
                return Ok(cached);
            }
        }
    }

    anyhow::bail!(
        "legacy rootfs guest-runtime injection is unavailable for mvmctl {} on {arch}; \
         run from a source checkout or use the universal initramfs/runtime-overlay path",
        env!("CARGO_PKG_VERSION")
    )
}

/// Materialize a run-path rootfs from an already-complete unpacked tree.
///
/// Default: the pure in-process `mvm-ext4` writer. `MVM_MATERIALIZE_BUILDER_VM`
/// (any value) routes back through the builder-VM `mkfs` path for parity /
/// debugging. Both paths emit `rootfs.verity` + `rootfs.roothash` beside the
/// image so block-backed OCI runs are sealed uniformly across backends.
pub fn materialize_run_rootfs(input: &MaterializeExt4Input) -> Result<()> {
    let input = input.clone().with_verity();
    match run_in_process_materializer(&input)? {
        InProcessOutcome::Materialized => Ok(()),
        InProcessOutcome::UseBuilderVm(route) => materialize_run_rootfs_builder_vm(&input, &route),
    }
}

/// What the in-process attempt settled: either the image is written, or the
/// builder VM runs next and this is why.
enum InProcessOutcome {
    Materialized,
    UseBuilderVm(crate::rootfs::BuilderVmRoute),
}

/// Run the in-process writer unless the builder VM was asked for outright.
///
/// A genuine failure — a malformed tree, an I/O error — surfaces here and is
/// never retried. Only a structural limit of the in-process writer routes on,
/// and it carries its own message so the refusal that may follow can name the
/// real cause instead of a setting nobody touched.
fn run_in_process_materializer(input: &MaterializeExt4Input) -> Result<InProcessOutcome> {
    if std::env::var_os("MVM_MATERIALIZE_BUILDER_VM").is_some() {
        return Ok(InProcessOutcome::UseBuilderVm(
            crate::rootfs::BuilderVmRoute::Selected,
        ));
    }
    match crate::rootfs::materialize_ext4_pure(input) {
        Ok(_) => Ok(InProcessOutcome::Materialized),
        // The in-process writer structurally can't emit a faithful image —
        // too large / too fragmented / a directory over one block, or an
        // xattr too big for it — so retry via the builder VM, which has no
        // size limits. That writer carries no extended attributes, so a tree
        // that has any is refused there, naming this failure. Logged, never
        // silent.
        Err(e) if e.pure_should_fall_back() => {
            tracing::warn!(
                error = %e,
                "in-process rootfs materialize needs the builder VM; falling back"
            );
            Ok(InProcessOutcome::UseBuilderVm(
                crate::rootfs::BuilderVmRoute::PureFallback {
                    because: e.to_string(),
                },
            ))
        }
        Err(e) => {
            Err(e).with_context(|| format!("materialize {} in-process", input.output.display()))
        }
    }
}

fn materialize_run_rootfs_builder_vm(
    input: &MaterializeExt4Input,
    route: &crate::rootfs::BuilderVmRoute,
) -> Result<()> {
    crate::rootfs::materialize_ext4(
        input,
        &crate::rootfs::MaterializeExt4Options::default(),
        route,
    )
    .map(|_| ())
    .with_context(|| format!("materialize {} via builder VM", input.output.display()))
}

/// Sum of regular-file sizes under `root` (symlink-aware, never follows) — the
/// ext4 sizing input.
pub fn unpacked_tree_size(root: &Path) -> Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("stat unpacked path {}", path.display()))?;
        if metadata.is_dir() {
            for entry in
                std::fs::read_dir(&path).with_context(|| format!("read {}", path.display()))?
            {
                stack.push(entry?.path());
            }
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

/// Seal an already-materialized `rootfs.ext4` at `rootfs_ext4` into a dm-verity
/// artifact set, emitting the sibling `rootfs.verity` (Merkle hash tree) and
/// `rootfs.roothash` (lowercase-hex root hash) files. Those are the exact sibling
/// names the backend's boot-time sidecar probe reads to decide a sealed boot.
///
/// Delegates to [`seal_with_verity`], which pins the 4096-byte data block size
/// the verity initramfs expects. Do **not** swap in a different dm-verity
/// geometry here: the initramfs probes the rootfs geometry at boot, so a
/// mismatched sidecar will fail closed before `/init` pivots into the real
/// rootfs.
///
/// Linux-only at runtime. On macOS `veritysetup` is unavailable, so this returns
/// [`OciUnpackError::HostUnsupported`] rather than a fabricated hash — the seal
/// runs on Linux or via the builder VM when the host cannot execute
/// `veritysetup` directly.
pub fn seal_run_rootfs_with_verity(
    rootfs_ext4: &Path,
) -> Result<VeritySealedRootfs, OciUnpackError> {
    let size_bytes = std::fs::metadata(rootfs_ext4)?.len();
    // `seal_with_verity` only reads `path`; the descriptor's label/uuid are
    // metadata mirrored for diagnostics. Name them like the materialize path so
    // the two artifacts read together coherently.
    let descriptor = MaterializedRootfs {
        path: rootfs_ext4.to_path_buf(),
        size_bytes,
        label: "mvm-rootfs".to_string(),
        uuid: String::new(),
    };
    seal_with_verity(&descriptor, &VeritysetupOptions::default())
}

/// Which rootfs strategy the run path uses for a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootStrategy {
    /// Materialize a block ext4 image — the only root shape. Witnesses claim 3
    /// via dm-verity. Kept as an enum because the launch record and the initrd
    /// resolver both name the shape they booted.
    BlockExt4,
}

/// Identity of the guest runtime that [`resolve_guest_binaries`] would inject,
/// without building it.
///
/// This is the rootfs cache key. It is consulted on the cache-hit gate — before
/// anything has decided a materialization is needed — so it must never trigger
/// the cross-compile that `resolve_guest_binaries` performs on a cold cache.
///
/// When the artifacts are present, the identity is their content digest, read
/// through [`crate::runtime_identity`]'s sidecar so the steady-state cost is a
/// small read plus one stat per artifact.
///
/// When they are absent there are no bytes to digest and building them here
/// would cost a minute to answer a question asked on every invocation. The
/// cache generation is returned instead, marked so it can never collide with a
/// real digest. That case implies a build is imminent anyway (materialization
/// needs the artifacts), after which the identity becomes the artifact digest
/// and the rootfs re-materializes once.
pub fn resolve_guest_runtime_identity(cache_root: &Path) -> Result<String> {
    let arch = mvm_core::arch::GuestArch::host();
    let source = crate::guest_agent_build::guest_binary_source()
        .context("resolve the guest-binary cache key for this host")?;
    let layout =
        crate::guest_agent_build::GuestAgentLayout::under(cache_root, source.cache_key(), arch);

    if !layout.is_complete() {
        return Ok(format!("pending-{}", source.cache_key()));
    }

    crate::runtime_identity::identity_with_sidecar(&layout.binaries(), &layout.dir)
        .with_context(|| format!("identify the guest runtime in {}", layout.dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed `cache_root` with stand-in guest binaries, so a test that reaches
    /// binary resolution by mistake fails in milliseconds instead of
    /// cross-compiling the guest runtime.
    fn seed_stub_guest_binaries(cache_root: &Path) {
        let source = crate::guest_agent_build::guest_binary_source().unwrap();
        let layout = crate::guest_agent_build::GuestAgentLayout::under(
            cache_root,
            source.cache_key(),
            mvm_core::arch::GuestArch::host(),
        );
        std::fs::create_dir_all(&layout.dir).unwrap();
        for bin in [
            &layout.agent,
            &layout.netinit,
            &layout.egress_client,
            &layout.entrypoint_runner,
        ] {
            std::fs::write(bin, b"\x7fELF-stub").unwrap();
        }
    }

    fn hostile_request<'a>(
        cache_root: &'a Path,
        root: &'a Path,
        output: &'a Path,
    ) -> InjectAndMaterializeRequest<'a> {
        InjectAndMaterializeRequest::builder(cache_root, root, output, "hostile")
            .deferred_nodes(vec![mvm_fs::ext4::Node::Symlink {
                path: "/etc/passwd".to_string(),
                target: "/srv/accounts".to_string(),
                owner: mvm_fs::ext4::Owner::ROOT,
            }])
            .build()
    }

    /// The production entry point refuses a deferred layer node at an
    /// injected path before it touches the tree or resolves a single guest
    /// binary, so the refusal is not something a later step can undo.
    #[test]
    fn a_deferred_node_at_an_injected_path_stops_the_run_before_injection() {
        let tmp = tempfile::tempdir().unwrap();
        seed_stub_guest_binaries(tmp.path());
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let output = tmp.path().join("out/rootfs.ext4");
        let err = inject_and_materialize(hostile_request(tmp.path(), &root, &output))
            .expect_err("a layer must not replace the account database");
        assert!(format!("{err:#}").contains("/etc/passwd"), "{err:#}");
        assert!(!root.join("etc").exists(), "nothing was injected");
        assert!(!output.exists());
    }

    /// Two runs of one image share its unpacked tree. A run waits for the
    /// tree's lock before doing anything at all, so another run holding it —
    /// mid-injection, mid-walk — cannot have the tree changed under it.
    #[test]
    fn a_run_waits_for_the_tree_lock_before_touching_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        seed_stub_guest_binaries(tmp.path());
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let output = tmp.path().join("out/rootfs.ext4");

        let held = lock_unpacked_tree(&root).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = {
            let (cache, root, output) = (tmp.path().to_path_buf(), root.clone(), output.clone());
            std::thread::spawn(move || {
                let result = inject_and_materialize(hostile_request(&cache, &root, &output));
                done_tx.send(format!("{:#}", result.unwrap_err())).unwrap();
            })
        };

        assert!(
            matches!(
                done_rx.recv_timeout(std::time::Duration::from_millis(500)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "the run proceeded while another held the tree"
        );
        drop(held);
        let err = done_rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the run proceeds once the lock is released");
        assert!(err.contains("/etc/passwd"), "{err}");
        worker.join().unwrap();
    }

    fn write_set(dir: &Path, tag: &str) {
        std::fs::create_dir_all(dir).unwrap();
        for file in ["rootfs.ext4", "rootfs.verity", "rootfs.roothash"] {
            std::fs::write(dir.join(file), tag).unwrap();
        }
        crate::builder_vm::GuestSidecar::for_oci_run(tag, false, true)
            .write_to_dir(dir)
            .unwrap();
    }

    /// A finished build replaces the old set whole, sidecar last.
    #[test]
    fn a_published_build_replaces_the_previous_set() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("rootfs");
        write_set(&live, "old");
        let staging = tmp.path().join("rootfs/.rootfs-build-x");
        write_set(&staging, "new");

        publish_rootfs_build(&staging, &live).unwrap();

        assert_eq!(std::fs::read(live.join("rootfs.ext4")).unwrap(), b"new");
        assert_eq!(std::fs::read(live.join("rootfs.verity")).unwrap(), b"new");
        assert!(rootfs_build_is_complete(&live.join("rootfs.ext4")));
    }

    /// The sidecar rename is not a durable commit until the containing
    /// directory has been synced. A sync failure must be visible to the
    /// caller instead of reporting a crash-safe publication.
    #[test]
    fn a_publish_reports_directory_sync_failure_after_renames() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("rootfs");
        write_set(&live, "old");
        let staging = tmp.path().join("rootfs/.rootfs-build-x");
        write_set(&staging, "new");
        let sync_called = std::cell::Cell::new(false);

        let err = publish_rootfs_build_with(&staging, &live, |dir| {
            assert_eq!(dir, live);
            sync_called.set(true);
            Err(anyhow::anyhow!("injected directory sync failure"))
        })
        .expect_err("directory sync failure must fail publication");

        assert!(sync_called.get(), "the published directory was not synced");
        assert!(format!("{err:#}").contains("sync published rootfs directory"));
    }

    /// A publish that fails part-way — here one file cannot be renamed over a
    /// directory — leaves no sidecar, so the half-replaced set is never reused
    /// and the next run builds it again.
    #[test]
    fn a_publish_that_dies_part_way_leaves_a_set_that_is_not_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("rootfs");
        write_set(&live, "old");
        assert!(rootfs_build_is_complete(&live.join("rootfs.ext4")));
        let staging = tmp.path().join("staging");
        write_set(&staging, "new");
        std::fs::write(staging.join("blocker"), b"x").unwrap();
        std::fs::create_dir_all(live.join("blocker/occupied")).unwrap();

        publish_rootfs_build(&staging, &live).expect_err("the rename over a directory fails");

        assert!(
            !rootfs_build_is_complete(&live.join("rootfs.ext4")),
            "a half-published set must not read as complete"
        );
    }

    /// A build killed before it published leaves only its scratch directory,
    /// which the next build removes.
    #[test]
    fn a_stale_build_directory_is_removed_by_the_next_build() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("rootfs");
        std::fs::create_dir_all(dir.join(".rootfs-build-dead/sub")).unwrap();
        std::fs::write(dir.join(".rootfs-build-dead/rootfs.ext4"), b"partial").unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"live").unwrap();

        remove_stale_builds(&dir).unwrap();

        assert!(!dir.join(".rootfs-build-dead").exists());
        assert_eq!(std::fs::read(dir.join("rootfs.ext4")).unwrap(), b"live");
    }

    /// The locks the whole materialization runs under are held for exactly as
    /// long as their proof lives: a second holder of either waits, and both
    /// are free again once it is gone.
    #[test]
    fn held_tree_locks_exclude_other_holders_until_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = tmp.path().join("rootfs");
        let output = tmp.path().join("out/rootfs.ext4");
        let try_both = || {
            let tree_free =
                mvm_core::util::atomic_io::FileLock::try_acquire(&lock_key(&tree, "tree").unwrap())
                    .unwrap()
                    .is_some();
            let output_free = mvm_core::util::atomic_io::FileLock::try_acquire(
                &output_lock_key(&output).unwrap(),
            )
            .unwrap()
            .is_some();
            (tree_free, output_free)
        };

        let held = HeldTreeLocks::acquire(&tree, &output).unwrap();
        assert_eq!(try_both(), (false, false), "both are held");
        drop(held);
        assert_eq!(try_both(), (true, true), "both are released");
    }

    #[test]
    fn the_tree_lock_is_exclusive_and_named_for_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        let held = lock_unpacked_tree(&root).unwrap();
        assert!(tmp.path().join("rootfs.tree.lock").is_file());
        assert!(
            mvm_core::util::atomic_io::FileLock::try_acquire(&lock_key(&root, "tree").unwrap())
                .unwrap()
                .is_none(),
            "a second holder must wait"
        );
        drop(held);
        assert!(
            mvm_core::util::atomic_io::FileLock::try_acquire(&lock_key(&root, "tree").unwrap())
                .unwrap()
                .is_some()
        );
    }

    /// A tree and the image built from it never share a lock file: one run
    /// holds both, and flock on a second descriptor of the same file would
    /// wait on itself. The image's lock lives outside the image's directory,
    /// so removing that directory cannot take the lock with it.
    #[test]
    fn the_output_lock_lives_outside_the_directory_it_guards() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = lock_unpacked_tree(&tmp.path().join("rootfs")).unwrap();
        let image_dir = tmp.path().join("images/abc-tag-dev");
        let output = lock_output(&image_dir.join("rootfs.ext4")).unwrap();
        assert!(tmp.path().join("rootfs.tree.lock").is_file());
        let lock_file = tmp
            .path()
            .join("images/.locks/abc-tag-dev.rootfs.ext4.output.lock");
        assert!(lock_file.is_file());
        assert!(!lock_file.starts_with(&image_dir));
        drop((tree, output));
    }

    /// Under the output lock, a complete build of the asked-for variant that
    /// is already published is kept, not rebuilt: a reader that chose it is
    /// never handed a different set beneath it. The request here would fail
    /// the moment it did any work, so success means nothing was redone.
    #[test]
    fn a_complete_matching_build_is_kept_under_the_lock() {
        let tmp = tempfile::tempdir().unwrap();
        seed_stub_guest_binaries(tmp.path());
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let output = tmp.path().join("out/rootfs.ext4");
        write_set(output.parent().unwrap(), "published");

        let reusing = |reuse: bool| {
            let request = InjectAndMaterializeRequest::builder(tmp.path(), &root, &output, "x")
                .deferred_nodes(vec![mvm_fs::ext4::Node::Symlink {
                    path: "/etc/passwd".to_string(),
                    target: "/srv/accounts".to_string(),
                    owner: mvm_fs::ext4::Owner::ROOT,
                }])
                .reuse_published(reuse)
                .build();
            inject_and_materialize(request)
        };

        reusing(true).expect("a complete dev build is kept");
        assert_eq!(std::fs::read(&output).unwrap(), b"published");
        assert!(
            reusing(false).is_err(),
            "without reuse the request does its work, and is refused"
        );

        // The sealed variant is not the dev build that is published.
        let sealed = InjectAndMaterializeRequest::builder(tmp.path(), &root, &output, "x")
            .sealed(true)
            .deferred_nodes(vec![mvm_fs::ext4::Node::Symlink {
                path: "/etc/passwd".to_string(),
                target: "/srv/accounts".to_string(),
                owner: mvm_fs::ext4::Owner::ROOT,
            }])
            .reuse_published(true)
            .build();
        assert!(inject_and_materialize(sealed).is_err());
    }

    /// The real entry point clears a build directory a killed run left behind
    /// before it builds.
    #[test]
    fn inject_and_materialize_removes_a_stale_build_directory() {
        let tmp = tempfile::tempdir().unwrap();
        seed_stub_guest_binaries(tmp.path());
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let output = tmp.path().join("out/rootfs.ext4");
        let stale = output.parent().unwrap().join(".rootfs-build-killed");
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::write(stale.join("rootfs.ext4"), b"partial").unwrap();

        inject_and_materialize(hostile_request(tmp.path(), &root, &output))
            .expect_err("the hostile request is refused after the cleanup");

        assert!(!stale.exists(), "the killed run's build directory is gone");
    }

    /// Build an unpacked-rootfs tree whose `lib/` carries `loader`.
    fn tree_with_loader(loader: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::write(dir.path().join("lib").join(loader), b"").unwrap();
        dir
    }

    #[test]
    fn the_sidecar_records_the_libc_of_the_tree_it_describes() {
        let musl = tree_with_loader("ld-musl-aarch64.so.1");
        assert_eq!(
            oci_run_sidecar(musl.path(), "alpine:3", false, None).libc,
            crate::guest_libc::GuestLibc::Musl
        );

        let glibc = tree_with_loader("ld-linux-aarch64.so.1");
        assert_eq!(
            oci_run_sidecar(glibc.path(), "debian:12", false, None).libc,
            crate::guest_libc::GuestLibc::Glibc
        );
    }

    /// An image whose loader we cannot identify must not be recorded as either
    /// libc. A caller gating on this refuses on unknown, so mislabelling here
    /// would turn a refusal into a mismatched load.
    #[test]
    fn a_tree_with_no_recognisable_loader_records_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            oci_run_sidecar(dir.path(), "scratch", false, None).libc,
            crate::guest_libc::GuestLibc::Unknown
        );
    }

    /// A sidecar written before the field existed must deserialize as unknown,
    /// not as a libc that happens to sort first.
    #[test]
    fn a_sidecar_predating_the_libc_field_reads_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let mut json: serde_json::Value = serde_json::to_value(
            crate::builder_vm::GuestSidecar::for_oci_run("old", false, true),
        )
        .unwrap();
        json.as_object_mut().unwrap().remove("libc");
        assert!(!json.as_object().unwrap().contains_key("libc"));
        std::fs::write(
            crate::builder_vm::GuestSidecar::path_in(dir.path()),
            serde_json::to_string(&json).unwrap(),
        )
        .unwrap();

        let read = crate::builder_vm::GuestSidecar::read_from_dir(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(read.libc, crate::guest_libc::GuestLibc::Unknown);
    }

    fn test_evidence<'a>(
        signer: &'a ed25519_dalek::SigningKey,
        image_ref: &'a str,
        image_digest: &'a str,
    ) -> SealEvidence<'a> {
        SealEvidence::builder(signer)
            .with_image_ref(image_ref)
            .with_image_digest(image_digest)
            .build()
    }

    #[test]
    fn sealed_request_with_evidence_writes_a_verifiable_mark() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let tree = tempfile::tempdir().unwrap();

        maybe_write_provenance_mark(
            tree.path(),
            true,
            Some(&test_evidence(&signer, "app:1", "sha256:abc")),
        )
        .expect("mark write succeeds");

        let mark_path = tree.path().join("mvm/provenance.json");
        let sig_path = tree.path().join("mvm/provenance.sig");
        assert!(mark_path.is_file(), "mark must land in the tree");
        assert!(
            sig_path.is_file(),
            "detached signature must land beside the mark"
        );
        let verified = crate::provenance_mark::verify_mark(
            &std::fs::read(&mark_path).unwrap(),
            std::fs::read_to_string(&sig_path).unwrap().trim(),
        )
        .expect("mark verifies against the signer");
        assert_eq!(verified.mark.image_ref.as_deref(), Some("app:1"));
    }

    #[test]
    fn sealed_request_without_evidence_warns_but_leaves_no_mark() {
        let tree = tempfile::tempdir().unwrap();

        maybe_write_provenance_mark(tree.path(), true, None)
            .expect("missing evidence is not a hard failure");

        assert!(!tree.path().join("mvm/provenance.json").exists());
        assert!(!tree.path().join("mvm/provenance.sig").exists());
    }

    #[test]
    fn unsealed_request_never_carries_the_mark() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let tree = tempfile::tempdir().unwrap();

        maybe_write_provenance_mark(
            tree.path(),
            false,
            Some(&test_evidence(&signer, "app:1", "sha256:abc")),
        )
        .expect("unsealed request is a no-op");

        assert!(!tree.path().join("mvm/provenance.json").exists());
    }

    #[test]
    fn sealed_oci_tree_contains_volume_mount_roots() {
        let root = tempfile::tempdir().unwrap();

        ensure_volume_mount_roots(root.path()).expect("create mount roots");

        for relative in ["data", "work", "mnt"] {
            assert!(root.path().join(relative).is_dir());
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seal_run_rootfs_surfaces_host_unsupported_on_non_linux() {
        // On macOS the sealing capability is compiled and callable, but the
        // underlying `veritysetup` is Linux-only, so it must surface
        // `HostUnsupported` — never a fabricated roothash. The real seal runs on
        // Linux / via the builder VM.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let err = seal_run_rootfs_with_verity(&rootfs).expect_err("veritysetup is Linux-only");
        assert!(
            matches!(err, OciUnpackError::HostUnsupported { .. }),
            "expected HostUnsupported on non-Linux, got {err:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seal_run_rootfs_errors_on_missing_input_file() {
        // A missing input surfaces the metadata I/O error before any host probe —
        // fail closed, never a silent success.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("rootfs.ext4");
        let err = seal_run_rootfs_with_verity(&missing).expect_err("missing input must error");
        assert!(
            matches!(err, OciUnpackError::Io(_)),
            "expected Io error for missing input, got {err:?}"
        );
    }

    /// A gzip stream starts with the two-byte magic `1f 8b`.

    #[test]
    fn verity_seal_script_uses_pinned_paths_and_parameters() {
        let script = verity_seal_script(Path::new("/tmp/build/rootfs.ext4")).expect("script");
        assert!(script.contains("ROOTFS=\"/out/rootfs.ext4\""));
        assert!(script.contains("VERITY=\"/out/rootfs.verity\""));
        assert!(script.contains("ROOTHASH=\"/out/rootfs.roothash\""));
        assert!(script.contains("veritysetup format"));
        assert!(script.contains(&format!(
            "--data-block-size={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE
        )));
        assert!(script.contains(&format!(
            "--hash-block-size={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_BLOCK_SIZE
        )));
        assert!(script.contains(&format!(
            "--salt={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_PINNED_SALT
        )));
        assert!(script.contains(&format!(
            "--uuid={}",
            mvm_fs::oci_to_rootfs::verity::MVM_VERITY_PINNED_UUID
        )));
        assert!(script.contains(&format!(
            "--hash={}",
            mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM
        )));
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_falls_back_on_host_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        seal_run_rootfs_for_runtime_with(
            &rootfs,
            |_rootfs| {
                Err(OciUnpackError::HostUnsupported {
                    operation: "veritysetup",
                    reason: "test host lacks local verity support",
                })
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect("host unsupported should fall back to the builder VM");

        assert!(builder_called.get());
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_keeps_local_success_local() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        seal_run_rootfs_for_runtime_with(
            &rootfs,
            |rootfs| {
                Ok(VeritySealedRootfs {
                    rootfs_path: rootfs.to_path_buf(),
                    sidecar_path: rootfs.with_extension("verity"),
                    roothash_path: rootfs.with_extension("roothash"),
                    roothash: "abcd".repeat(16),
                    algorithm: mvm_fs::oci_to_rootfs::MVM_VERITY_HASH_ALGORITHM.to_string(),
                    data_block_size: mvm_fs::oci_to_rootfs::MVM_VERITY_DATA_BLOCK_SIZE,
                })
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect("local seal success should not need the builder VM");

        assert!(!builder_called.get());
    }

    #[test]
    fn seal_run_rootfs_for_runtime_with_propagates_non_host_unsupported_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"ext4-bytes").unwrap();
        let builder_called = std::cell::Cell::new(false);

        let err = seal_run_rootfs_for_runtime_with(
            &rootfs,
            |_rootfs| {
                Err(OciUnpackError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "stat rootfs: missing",
                )))
            },
            |_rootfs| {
                builder_called.set(true);
                Ok(())
            },
        )
        .expect_err("non-host-unsupported errors must surface");

        assert!(err.to_string().contains("stat rootfs"));
        assert!(!builder_called.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealing_emits_both_verity_sidecars() {
        // The load-bearing `--prod` invariant: a sealed rootfs carries both
        // dm-verity sidecars. There is no longer a paired `rootfs.initrd` to
        // land with them — the universal initramfs is attached from the shared
        // cache and its agent sets the dm-verity target up itself.
        // Skips cleanly when `veritysetup` (cryptsetup) is not installed.
        if which::which("veritysetup").is_err() {
            eprintln!("skipped: veritysetup not on $PATH (install cryptsetup)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        // veritysetup formats over the raw device bytes; a multiple of the
        // 1024-byte data-block size is enough (no real ext4 needed here).
        std::fs::write(&rootfs, vec![0u8; 4096]).unwrap();

        seal_rootfs_for_run(&rootfs).expect("seal");

        let roothash = tmp.path().join("rootfs.roothash");
        let verity = tmp.path().join("rootfs.verity");
        assert!(verity.is_file(), "rootfs.verity present");
        assert!(roothash.is_file(), "rootfs.roothash present");
        assert!(
            !tmp.path().join("rootfs.initrd").exists(),
            "no per-rootfs initrd is assembled any more"
        );
        let hash = std::fs::read_to_string(&roothash).unwrap();
        assert!(
            hash.trim().len() == 64 && hash.trim().bytes().all(|b| b.is_ascii_hexdigit()),
            "roothash is 64-hex: {hash:?}"
        );
    }
}
