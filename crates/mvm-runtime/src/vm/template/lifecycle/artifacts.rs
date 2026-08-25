//! Artifact resolution and installation: mapping a template/slot to its
//! on-disk kernel/rootfs/sidecar paths, and installing a finished dev
//! build's outputs into a slot's revision directory.

use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_core::manifest::{PersistedManifest, slot_current_symlink, slot_revision_dir};
use mvm_core::template::{
    TemplateRevision, TemplateSpec, template_current_symlink, template_revision_dir,
};
use tracing::instrument;

use super::crud::template_load;
use super::slots::template_load_slot;

pub(super) fn slot_kernel_source(
    built_vmlinux: &std::path::Path,
    cache_root: &std::path::Path,
    arch: GuestArch,
) -> Result<std::path::PathBuf> {
    if built_vmlinux.is_file() {
        return Ok(built_vmlinux.to_path_buf());
    }
    // Workload images rarely embed their own kernel (mkGuest outputs a rootfs).
    // Boot a verified workload kernel when one is cached; it carries dm-verity
    // and the virtio drivers the guest needs. Fall back to the builder kernel
    // only when no workload kernel is available.
    let arch_str = arch.to_string();
    if let mvm_build::kernel_fetch::KernelResolution::Cached(verified) =
        mvm_build::kernel_fetch::resolve_kernel(cache_root, &arch_str, "workload", false)
    {
        return Ok(verified.path().to_path_buf());
    }
    let fallback = cache_root
        .join("builder-vm")
        .join(&arch_str)
        .join("vmlinux");
    if fallback.is_file() {
        return Ok(fallback);
    }
    let workload_path =
        mvm_build::kernel_fetch::cached_kernel_path(cache_root, &arch_str, "workload");
    anyhow::bail!(
        "flake build produced no vmlinux at {} and no verified workload kernel is cached at {} \
         (create one with `mvmctl kernel build --which workload`)",
        built_vmlinux.display(),
        workload_path.display()
    )
}

pub(super) fn slot_sidecar_source(build_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let sidecar = build_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME);
    if sidecar.is_file() {
        return Ok(sidecar);
    }
    anyhow::bail!(
        "flake build produced no runtime sidecar at {}",
        sidecar.display()
    )
}

/// Host-side artifact sources resolved from a finished dev build,
/// ready to install into a template slot's revision directory.
/// Bundled into a struct so [`install_revision_artifacts`] takes one
/// argument per concern instead of one per file.
pub(super) struct RevisionArtifactSources {
    pub(super) kernel: std::path::PathBuf,
    pub(super) initrd: Option<std::path::PathBuf>,
    pub(super) rootfs: std::path::PathBuf,
    pub(super) sidecar: std::path::PathBuf,
    /// OCI image tarball a flake's `mkGuest` emits via
    /// `dockerTools.streamLayeredImage`. Best-effort: installed only
    /// if this path exists.
    pub(super) oci_tarball: std::path::PathBuf,
    pub(super) fc_base_json: String,
}

/// Installs one dev build's resolved artifacts into a template
/// slot's revision directory and repoints the slot's `current`
/// symlink at it.
///
/// `sources` and `rev_dst` are both host paths — the finished build
/// lives under the dev-build cache and the slot under the templates
/// tree, both on the host filesystem — so this is a plain host-to-host
/// file install, never a VM operation.
pub(super) fn install_revision_artifacts(
    sources: &RevisionArtifactSources,
    rev_dst: &std::path::Path,
    current_symlink: &std::path::Path,
    revision_hash: &str,
) -> Result<()> {
    std::fs::create_dir_all(rev_dst)
        .with_context(|| format!("creating revision directory {}", rev_dst.display()))?;

    copy_artifact(&sources.kernel, &rev_dst.join("vmlinux"))?;

    if let Some(initrd) = &sources.initrd {
        copy_artifact(initrd, &rev_dst.join("initrd"))?;
    }

    let rootfs_dst = rev_dst.join("rootfs.ext4");
    copy_artifact(&sources.rootfs, &rootfs_dst)?;
    // Nix store outputs are read-only; the running microVM needs to
    // open the installed rootfs read-write.
    make_owner_writable(&rootfs_dst)?;

    copy_artifact(
        &sources.sidecar,
        &rev_dst.join(mvm_build::builder_vm::SIDECAR_FILENAME),
    )?;

    if sources.oci_tarball.is_file() {
        copy_artifact(&sources.oci_tarball, &rev_dst.join("image.tar.gz"))?;
    }

    std::fs::write(rev_dst.join("fc-base.json"), &sources.fc_base_json)
        .with_context(|| format!("writing {}/fc-base.json", rev_dst.display()))?;

    relink_current(current_symlink, revision_hash)
}

/// `cp -a <src> <dst>` minus the VM shell hop: both paths are already
/// host paths. `std::fs::copy` preserves the source's permission
/// bits, matching `cp -a`'s mode-preserving behavior.
fn copy_artifact(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
    Ok(())
}

/// `chmod u+w <path>`: adds the owner-write bit without disturbing
/// the rest of the mode.
fn make_owner_writable(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(path).with_context(|| format!("statting {}", path.display()))?;
    let mut perms = metadata.permissions();
    perms.set_mode(perms.mode() | 0o200);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod u+w {}", path.display()))
}

/// Repoints `current_symlink` at `artifacts/revisions/<revision_hash>`
/// — a relative target so the slot stays portable across host
/// filesystems. Mirrors `ln -snf`: removes whatever is already at
/// `current_symlink` first, since `symlink()` errors if the
/// destination already exists.
fn relink_current(current_symlink: &std::path::Path, revision_hash: &str) -> Result<()> {
    if std::fs::symlink_metadata(current_symlink).is_ok() {
        std::fs::remove_file(current_symlink)
            .with_context(|| format!("removing existing symlink {}", current_symlink.display()))?;
    }
    let target = format!("artifacts/revisions/{revision_hash}");
    std::os::unix::fs::symlink(&target, current_symlink)
        .with_context(|| format!("linking {} -> {target}", current_symlink.display()))
}

/// Read a slot's `current` symlink and return the revision hash it
/// points at. Mirrors [`current_revision_id`] for the slot-keyed world.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn current_revision_id_for_slot(slot_hash: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let link = slot_current_symlink(slot_hash);
    let target = std::fs::read_link(&link)
        .with_context(|| format!("Slot has no current revision: {}", link))?;
    let raw = target.as_os_str().as_bytes();
    let raw = std::str::from_utf8(raw)
        .unwrap_or_default()
        .trim()
        .to_string();
    // Symlink target is relative `artifacts/revisions/<rev>`; strip the
    // prefix to recover the bare revision hash.
    let rev = raw
        .strip_prefix("artifacts/revisions/")
        .unwrap_or(&raw)
        .to_string();
    if rev.is_empty() {
        anyhow::bail!("Slot current symlink is empty: {}", link);
    }
    Ok(rev)
}

/// Resolve a slot to its current artifact paths. Mirrors
/// [`template_artifacts`] but keyed by slot hash; returns the
/// [`PersistedManifest`] in place of [`TemplateSpec`].
///
/// Returns `(persisted_manifest, vmlinux, initrd, rootfs, revision_hash)`.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn template_artifacts_for_slot(
    slot_hash: &str,
) -> Result<(PersistedManifest, String, Option<String>, String, String)> {
    let persisted = template_load_slot(slot_hash)?;
    let rev = current_revision_id_for_slot(slot_hash)?;
    template_artifacts_for_slot_revision_with_manifest(slot_hash, &rev, persisted)
}

/// Resolve a specific stored revision in a manifest-keyed slot.
///
/// Unlike [`template_artifacts_for_slot`], this never follows the slot's
/// `current` symlink. Callers use it for content-addressed restore, where
/// selecting the current revision would silently boot newer artifacts than
/// the recorded node names.
#[instrument(skip_all, fields(slot_hash = slot_hash, revision = revision_hash))]
pub fn template_artifacts_for_slot_revision(
    slot_hash: &str,
    revision_hash: &str,
) -> Result<(PersistedManifest, String, Option<String>, String, String)> {
    let persisted = template_load_slot(slot_hash)?;
    template_artifacts_for_slot_revision_with_manifest(slot_hash, revision_hash, persisted)
}

fn template_artifacts_for_slot_revision_with_manifest(
    slot_hash: &str,
    revision_hash: &str,
    persisted: PersistedManifest,
) -> Result<(PersistedManifest, String, Option<String>, String, String)> {
    if revision_hash.is_empty()
        || revision_hash.contains('/')
        || revision_hash.contains('\\')
        || revision_hash == "."
        || revision_hash == ".."
    {
        anyhow::bail!("invalid slot revision hash {revision_hash:?}");
    }
    let rev_dir = slot_revision_dir(slot_hash, revision_hash);

    let vmlinux = format!("{rev_dir}/vmlinux");
    let rootfs = format!("{rev_dir}/rootfs.ext4");
    let initrd_candidate = format!("{rev_dir}/initrd");

    if !std::path::Path::new(&vmlinux).exists() {
        anyhow::bail!(
            "Slot '{}' has no vmlinux (run `mvmctl build {}`)",
            slot_hash,
            persisted.manifest_path
        );
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!(
            "Slot '{}' has no rootfs (run `mvmctl build {}`)",
            slot_hash,
            persisted.manifest_path
        );
    }

    let has_initrd = std::path::Path::new(&initrd_candidate).exists();
    let initrd_path = if has_initrd {
        Some(initrd_candidate)
    } else {
        None
    };

    Ok((
        persisted,
        vmlinux,
        initrd_path,
        rootfs,
        revision_hash.to_string(),
    ))
}

/// Resolve a bundle-sha256 reference through
/// [`mvm_core::plan::BundleRegistry`] (default path
/// `~/.mvm/bundles/<sha>/`). Returns the same shape as
/// [`template_artifacts`] / [`template_artifacts_for_slot`] so the
/// dispatch fan-in is uniform.
///
/// `revision_hash` for a bundle equals the bundle sha — bundles are
/// content-addressed, so the "revision" of a content-addressed unit
/// is just its hash. `TemplateSpec.template_id` is set the same way.
///
/// `vcpus` / `mem_mib` come from operator config defaults because
/// the bundle manifest doesn't carry resources today (a future
/// schema bump would let bundles declare them; for now `mvmctl up`
/// `--cpus` / `--memory` override). The CLI surfaces this as a
/// "bundle X uses default resources" info line so users aren't
/// surprised when no per-template defaults flow through.
pub(super) fn bundle_artifacts_for_sha(
    bundle_sha256: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    use mvm_core::plan::ArtifactRole;

    let registry = mvm_core::plan::BundleRegistry::default_path()
        .context("resolving default bundle registry root")?;
    let installed = registry
        .find(bundle_sha256)
        .with_context(|| format!("looking up bundle {bundle_sha256} in registry"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no installed bundle for {bundle_sha256} — run `mvmctl bundle install` first"
            )
        })?;

    let kernel = installed
        .path_for_role(&ArtifactRole::Kernel)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "bundle {bundle_sha256} has no Kernel artifact — manifest is missing a vmlinux entry"
            )
        })?
        .to_string_lossy()
        .into_owned();
    let rootfs = installed
        .path_for_role(&ArtifactRole::Rootfs)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "bundle {bundle_sha256} has no Rootfs artifact — manifest is missing a rootfs entry"
            )
        })?
        .to_string_lossy()
        .into_owned();
    let initrd = installed
        .path_for_role(&ArtifactRole::Initrd)
        .map(|p| p.to_string_lossy().into_owned());

    // Resource resolution: bundle manifest's `resources` field
    // wins when set (BUNDLE_SCHEMA_VERSION 2+ bundles ship this).
    // Falls back to operator config for v1 bundles or when the
    // publisher chose to omit. CLI `--cpus` / `--memory` still
    // override both at `mvmctl up` time.
    let user_cfg = mvm_core::user_config::load(None);
    let (vcpus_u32, mem_mib) = match installed.manifest.resources.as_ref() {
        Some(r) => (r.vcpus, r.mem_mib),
        None => (user_cfg.default_cpus, user_cfg.default_memory_mib),
    };
    let now = chrono::Utc::now().to_rfc3339();
    let spec = TemplateSpec {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        template_id: bundle_sha256.to_string(),
        flake_ref: format!("bundle:{bundle_sha256}"),
        profile: installed.manifest.profile.clone().unwrap_or_default(),
        role: String::new(),
        vcpus: u8::try_from(vcpus_u32.min(u32::from(u8::MAX))).unwrap_or(u8::MAX),
        mem_mib,
        mem_initial_mib: None,
        data_disk_mib: 0,
        created_at: installed.manifest.created_at.clone(),
        updated_at: now,
        default_network_policy: None,
    };

    // Bundle sha == revision, since bundles are content-addressed.
    Ok((spec, kernel, initrd, rootfs, bundle_sha256.to_string()))
}

/// Verify a slot's artifacts against its `checksums.json`. Returns
/// `Ok(())` if every recorded file matches; an error otherwise listing
/// which file mismatched. The checksums file is written by
/// `template_push_slot` and is also produced inline by
/// `template_build_from_manifest` once push lands; until then a slot
/// without a `checksums.json` errors with a hint.
///
/// `revision` selects a specific revision; `None` resolves the slot's
/// `current` symlink.
#[instrument(skip_all, fields(slot_hash = slot_hash, revision = ?revision))]
pub fn template_verify_slot(slot_hash: &str, revision: Option<&str>) -> Result<()> {
    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id_for_slot(slot_hash)?,
    };
    let rev_dir = std::path::PathBuf::from(slot_revision_dir(slot_hash, &rev));
    let sums_path = rev_dir.join("checksums.json");
    let sums_bytes = std::fs::read(&sums_path).with_context(|| {
        format!(
            "Missing {} — checksums are written by `mvmctl manifest push` (slice 8b not yet shipped). Run `mvmctl build --force` to repopulate the slot, then verify will work after push lands.",
            sums_path.display()
        )
    })?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)
        .with_context(|| format!("Corrupt {}", sums_path.display()))?;

    let mut mismatches = Vec::new();
    for (name, expected_hex) in &checksums.files {
        let path = rev_dir.join(name);
        if !path.exists() {
            mismatches.push(format!("{}: missing", name));
            continue;
        }
        let actual = sha256_hex(&path)?;
        if &actual != expected_hex {
            mismatches.push(format!(
                "{}: expected {}, got {}",
                name,
                &expected_hex[..expected_hex.len().min(12)],
                &actual[..actual.len().min(12)]
            ));
        }
    }

    if !mismatches.is_empty() {
        anyhow::bail!(
            "Slot {} revision {} failed verification:\n  - {}",
            slot_hash,
            rev,
            mismatches.join("\n  - ")
        );
    }
    Ok(())
}

/// Load the current revision metadata for a template (if any).
///
/// Returns `None` if the template has no built revision or if `revision.json`
/// cannot be read/parsed.
pub fn template_load_current_revision(id: &str) -> Result<Option<TemplateRevision>> {
    let rev = match current_revision_id(id) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let rev_dir = template_revision_dir(id, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    let data = match std::fs::read_to_string(&meta_path) {
        Ok(d) if !d.trim().is_empty() => d,
        _ => return Ok(None),
    };
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for template {}", id))?;
    Ok(Some(revision))
}

/// Artifact integrity manifest used by template push/pull.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Checksums {
    #[serde(default)]
    pub schema_version: u32,
    pub template_id: String,
    pub revision_hash: String,
    pub files: std::collections::BTreeMap<String, String>,
}

/// Resolve a built template to its current artifact paths.
///
/// Returns `(spec, vmlinux, initrd, rootfs, revision_hash)`.
/// The artifact paths are absolute and valid on the host.
#[instrument(skip_all, fields(template_id = id))]
pub fn template_artifacts(
    id: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    let spec = template_load(id)?;
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);

    let vmlinux = format!("{rev_dir}/vmlinux");
    let rootfs = format!("{rev_dir}/rootfs.ext4");
    let initrd_candidate = format!("{rev_dir}/initrd");

    if !std::path::Path::new(&vmlinux).exists() {
        anyhow::bail!(
            "Template '{}' has no vmlinux (run `mvmctl template build {}`)",
            id,
            id
        );
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!(
            "Template '{}' has no rootfs (run `mvmctl template build {}`)",
            id,
            id
        );
    }

    let has_initrd = std::path::Path::new(&initrd_candidate).exists();

    Ok((
        spec,
        vmlinux,
        if has_initrd {
            Some(initrd_candidate)
        } else {
            None
        },
        rootfs,
        rev,
    ))
}

#[instrument(skip_all, fields(template_id))]
pub fn current_revision_id(template_id: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let link = template_current_symlink(template_id);
    let target = std::fs::read_link(&link)
        .with_context(|| format!("Template has no current revision: {}", template_id))?;
    let raw = target.as_os_str().as_bytes();
    let raw = std::str::from_utf8(raw)
        .unwrap_or_default()
        .trim()
        .to_string();
    let rev = raw.strip_prefix("revisions/").unwrap_or(&raw).to_string();
    if rev.is_empty() {
        anyhow::bail!("Template current symlink is empty: {}", link);
    }
    Ok(rev)
}

/// Compute the SHA-256 hex digest of a file.
pub fn sha256_hex(path: &std::path::Path) -> Result<String> {
    use sha2::Digest;

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_kernel_source_prefers_built_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("build").join("vmlinux");
        std::fs::create_dir_all(built.parent().unwrap()).unwrap();
        std::fs::write(&built, b"built-kernel").unwrap();
        let cache = tmp.path().join("cache");

        let selected = slot_kernel_source(&built, &cache, GuestArch::X86_64).unwrap();

        assert_eq!(selected, built);
    }

    #[test]
    fn slot_kernel_source_prefers_verified_workload_kernel_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("build").join("vmlinux");
        let workload = tmp
            .path()
            .join("cache")
            .join("builder-vm")
            .join("x86_64")
            .join("kernels")
            .join("workload")
            .join("vmlinux");
        std::fs::create_dir_all(workload.parent().unwrap()).unwrap();
        std::fs::write(&workload, b"workload-kernel").unwrap();
        mvm_build::kernel_fetch::record_kernel_digest(&workload).unwrap();

        let selected =
            slot_kernel_source(&built, &tmp.path().join("cache"), GuestArch::X86_64).unwrap();

        assert_eq!(selected, workload);
    }

    #[test]
    fn slot_kernel_source_falls_back_to_builder_kernel_when_workload_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("build").join("vmlinux");
        let fallback = tmp
            .path()
            .join("cache")
            .join("builder-vm")
            .join("x86_64")
            .join("vmlinux");
        std::fs::create_dir_all(fallback.parent().unwrap()).unwrap();
        std::fs::write(&fallback, b"fallback-kernel").unwrap();

        let selected =
            slot_kernel_source(&built, &tmp.path().join("cache"), GuestArch::X86_64).unwrap();

        assert_eq!(selected, fallback);
    }

    #[test]
    fn slot_kernel_source_errors_without_built_or_fallback_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let built = tmp.path().join("build").join("vmlinux");
        let err = slot_kernel_source(&built, &tmp.path().join("cache"), GuestArch::X86_64)
            .unwrap_err()
            .to_string();

        assert!(err.contains("flake build produced no vmlinux"));
        assert!(err.contains("builder-vm/x86_64/kernels/workload/vmlinux"));
    }

    #[test]
    fn slot_sidecar_source_selects_builder_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let sidecar = tmp.path().join(mvm_build::builder_vm::SIDECAR_FILENAME);
        std::fs::write(&sidecar, b"{\"overlay_aware\":true}").unwrap();

        let selected = slot_sidecar_source(tmp.path()).unwrap();

        assert_eq!(selected, sidecar);
    }

    #[test]
    fn slot_sidecar_source_errors_without_builder_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let err = slot_sidecar_source(tmp.path()).unwrap_err().to_string();

        assert!(err.contains("flake build produced no runtime sidecar"));
        assert!(err.contains(mvm_build::builder_vm::SIDECAR_FILENAME));
    }

    // -----------------------------------------------------------------
    // install_revision_artifacts (pure helper, no VM). This is the
    // host-to-host copy that `template_build_from_manifest` used to
    // wrongly shell through `run_in_vm` — both the build output and
    // the slot's revision directory are host paths.
    // -----------------------------------------------------------------

    fn fake_sources(build: &std::path::Path) -> RevisionArtifactSources {
        RevisionArtifactSources {
            kernel: build.join("vmlinux"),
            initrd: Some(build.join("initrd")),
            rootfs: build.join("rootfs.ext4"),
            sidecar: build.join(mvm_build::builder_vm::SIDECAR_FILENAME),
            // Deliberately does not exist: exercises the best-effort
            // "only install if present" path.
            oci_tarball: build.join("image.tar.gz"),
            fc_base_json: "{\"boot-source\":{}}".to_string(),
        }
    }

    #[test]
    fn install_revision_artifacts_copies_kernel_rootfs_and_relinks_current_without_a_vm() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let build = tmp.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("vmlinux"), b"K").unwrap();
        std::fs::write(build.join("initrd"), b"I").unwrap();
        std::fs::write(build.join("rootfs.ext4"), b"R").unwrap();
        std::fs::write(build.join(mvm_build::builder_vm::SIDECAR_FILENAME), b"{}").unwrap();
        // Nix store outputs are read-only; the helper must chmod the
        // installed rootfs writable regardless.
        std::fs::set_permissions(
            build.join("rootfs.ext4"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();

        let slot_dir = tmp.path().join("slot");
        let rev_dst = slot_dir.join("artifacts").join("revisions").join("rev-1");
        let current_link = slot_dir.join("current");
        let sources = fake_sources(&build);

        install_revision_artifacts(&sources, &rev_dst, &current_link, "rev-1").unwrap();

        assert_eq!(std::fs::read(rev_dst.join("vmlinux")).unwrap(), b"K");
        assert_eq!(std::fs::read(rev_dst.join("initrd")).unwrap(), b"I");
        assert_eq!(std::fs::read(rev_dst.join("rootfs.ext4")).unwrap(), b"R");
        assert_eq!(
            std::fs::read(rev_dst.join(mvm_build::builder_vm::SIDECAR_FILENAME)).unwrap(),
            b"{}"
        );
        assert_eq!(
            std::fs::read(rev_dst.join("fc-base.json")).unwrap(),
            sources.fc_base_json.as_bytes()
        );
        // Best-effort OCI tarball was never created by the test fixture.
        assert!(!rev_dst.join("image.tar.gz").exists());

        let rootfs_mode = std::fs::metadata(rev_dst.join("rootfs.ext4"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            rootfs_mode & 0o200,
            0o200,
            "installed rootfs must be owner-writable"
        );

        let target = std::fs::read_link(&current_link).unwrap();
        assert_eq!(
            target,
            std::path::PathBuf::from("artifacts/revisions/rev-1")
        );
    }

    #[test]
    fn install_revision_artifacts_installs_oci_tarball_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let build = tmp.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("vmlinux"), b"K").unwrap();
        std::fs::write(build.join("rootfs.ext4"), b"R").unwrap();
        std::fs::write(build.join(mvm_build::builder_vm::SIDECAR_FILENAME), b"{}").unwrap();
        std::fs::write(build.join("image.tar.gz"), b"OCI").unwrap();

        let rev_dst = tmp.path().join("slot/artifacts/revisions/rev-1");
        let current_link = tmp.path().join("slot/current");
        let mut sources = fake_sources(&build);
        sources.initrd = None;

        install_revision_artifacts(&sources, &rev_dst, &current_link, "rev-1").unwrap();

        assert_eq!(std::fs::read(rev_dst.join("image.tar.gz")).unwrap(), b"OCI");
        assert!(!rev_dst.join("initrd").exists());
    }

    #[test]
    fn install_revision_artifacts_overwrites_an_existing_current_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let build = tmp.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("vmlinux"), b"K").unwrap();
        std::fs::write(build.join("rootfs.ext4"), b"R").unwrap();
        std::fs::write(build.join(mvm_build::builder_vm::SIDECAR_FILENAME), b"{}").unwrap();

        let slot_dir = tmp.path().join("slot");
        std::fs::create_dir_all(&slot_dir).unwrap();
        let current_link = slot_dir.join("current");
        std::os::unix::fs::symlink("artifacts/revisions/rev-0", &current_link).unwrap();

        let rev_dst = slot_dir.join("artifacts").join("revisions").join("rev-1");
        let mut sources = fake_sources(&build);
        sources.initrd = None;

        install_revision_artifacts(&sources, &rev_dst, &current_link, "rev-1").unwrap();

        let target = std::fs::read_link(&current_link).unwrap();
        assert_eq!(
            target,
            std::path::PathBuf::from("artifacts/revisions/rev-1")
        );
    }

    #[test]
    fn test_checksums_serde_roundtrip() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("vmlinux".to_string(), "abc123".to_string());
        files.insert("rootfs.squashfs".to_string(), "def456".to_string());
        let checksums = Checksums {
            schema_version: 1,
            template_id: "gateway".to_string(),
            revision_hash: "rev-abc".to_string(),
            files,
        };
        let json = serde_json::to_string(&checksums).unwrap();
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.template_id, "gateway");
        assert_eq!(parsed.revision_hash, "rev-abc");
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files["vmlinux"], "abc123");
    }

    #[test]
    fn test_checksums_empty_files() {
        let checksums = Checksums {
            schema_version: 1,
            template_id: "empty".to_string(),
            revision_hash: "rev-000".to_string(),
            files: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&checksums).unwrap();
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        assert!(parsed.files.is_empty());
    }

    #[test]
    fn test_checksums_files_sorted() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("z-file".to_string(), "zzz".to_string());
        files.insert("a-file".to_string(), "aaa".to_string());
        files.insert("m-file".to_string(), "mmm".to_string());
        let checksums = Checksums {
            schema_version: 1,
            template_id: "t".to_string(),
            revision_hash: "r".to_string(),
            files,
        };
        let json = serde_json::to_string(&checksums).unwrap();
        // BTreeMap serializes in sorted order
        let keys: Vec<&str> = checksums.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["a-file", "m-file", "z-file"]);
        // Roundtrip preserves order
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        let parsed_keys: Vec<&str> = parsed.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(parsed_keys, vec!["a-file", "m-file", "z-file"]);
    }
}
