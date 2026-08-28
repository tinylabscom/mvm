//! Building a manifest-keyed slot from an OCI image instead of a Nix flake.
//!
//! `mvm.toml` has carried an `image` source selector, mutually exclusive with
//! `flake`, since the manifest primitive was introduced — but the build path
//! only ever handled flakes and refused an image manifest with "not wired yet".
//! This is the other arm.
//!
//! It is deliberately thin, because the hard parts already exist. The caller
//! materializes the image through the same path `run --image` uses, which
//! writes `rootfs.ext4` and the overlay-aware `mvm-meta.json` sidecar beside
//! each other; the workload kernel is the one every OCI run already boots. So
//! what is left is assembling those into a slot revision using the identical
//! [`install_revision_artifacts`] the flake path uses — one revision layout,
//! one `current` symlink, one `revision.json`, whatever the source was.
//!
//! That sameness is the point. A slot built from an image has to be
//! indistinguishable at boot from one built from a flake, or `--manifest`
//! would need to know which arm produced it.

use anyhow::{Context, Result};
use mvm_core::manifest::{PersistedManifest, Provenance, slot_current_symlink, slot_revision_dir};
use mvm_core::pool::{ArtifactPaths, ArtifactSizes};
use mvm_core::template::TemplateRevision;
use mvm_core::time::utc_now;
use tracing::instrument;

use crate::ui;

use super::artifacts::{RevisionArtifactSources, install_revision_artifacts};
use super::build_mode_label;
use super::slots::template_persist_slot;

/// The host artifacts an image-backed build starts from.
///
/// The caller resolves these because both come from layers above this one: the
/// rootfs from the OCI materialization in `mvm-client`, the kernel from the
/// CLI's workload-kernel acquisition. Passing them in keeps this function a
/// pure assemble-and-install step with no network and no VM.
pub struct ImageBuildSources {
    /// The materialized `rootfs.ext4`. Its directory must also hold the
    /// `mvm-meta.json` sidecar the materialization wrote.
    pub rootfs: std::path::PathBuf,
    /// The verified workload kernel this slot boots.
    pub kernel: std::path::PathBuf,
    /// The OCI reference this was built from, recorded on the revision.
    pub image_ref: String,
}

/// Install an already-materialized OCI rootfs as a manifest-keyed slot revision.
///
/// Mirrors `template_build_from_manifest`'s post-build half exactly: same
/// revision directory, same `current` relink, same `revision.json`, same slot
/// refresh. Returns the [`TemplateRevision`] for display.
#[instrument(skip_all, fields(slot_hash = %persisted.manifest_hash, image = %sources.image_ref))]
pub fn template_build_from_image(
    persisted: &PersistedManifest,
    sources: &ImageBuildSources,
    mode: mvm_build::pipeline::BuildMode,
) -> Result<TemplateRevision> {
    let sidecar = sources
        .rootfs
        .parent()
        .map(|d| d.join(mvm_build::builder_vm::SIDECAR_FILENAME))
        .filter(|p| p.is_file())
        .with_context(|| {
            format!(
                "image materialization wrote no `{}` sidecar beside {}; the slot would boot \
                 without the overlay-awareness the backend reads from it",
                mvm_build::builder_vm::SIDECAR_FILENAME,
                sources.rootfs.display()
            )
        })?;

    // The revision is keyed by the rootfs content, so rebuilding the same
    // digest-pinned image is idempotent and a changed image gets a new
    // revision without the caller tracking anything.
    let revision_hash = mvm_fs::hash::hash_source(&sources.rootfs)
        .with_context(|| format!("hashing {}", sources.rootfs.display()))?;

    let slot_hash = &persisted.manifest_hash;
    let rev_dst = slot_revision_dir(slot_hash, &revision_hash);
    let current_link = slot_current_symlink(slot_hash);

    // An OCI rootfs carries no initrd: the guest boots the kernel directly
    // onto /dev/vda, which is the same shape a flake guest without an initrd
    // gets, so the cmdline is the same one.
    let fc_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": "vmlinux",
            "boot_args": "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0"
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": "rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": persisted.vcpus,
            "mem_size_mib": persisted.mem_mib
        }
    });

    ui::info("Storing image artifacts in slot revision directory...");
    install_revision_artifacts(
        &RevisionArtifactSources {
            kernel: sources.kernel.clone(),
            initrd: None,
            rootfs: sources.rootfs.clone(),
            sidecar,
            // Emitted only by a flake's `mkGuest`; an image-sourced slot has
            // no re-exportable tarball, and `export-oci` says so.
            oci_tarball: std::path::PathBuf::from(""),
            fc_base_json: serde_json::to_string_pretty(&fc_config)?,
        },
        std::path::Path::new(&rev_dst),
        std::path::Path::new(&current_link),
        &revision_hash,
    )?;

    let sizes = ArtifactSizes {
        rootfs_bytes: file_len(&sources.rootfs),
        vmlinux_bytes: file_len(&sources.kernel),
        initrd_bytes: None,
        // A flake build measures its Nix closure; an image build has none.
        nix_closure_bytes: None,
    };

    let revision = TemplateRevision {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        revision_hash: revision_hash.clone(),
        // `flake_ref` is the source field on the on-disk record. An
        // image-sourced slot records its reference here rather than a
        // fabricated flake path, so `revision.json` says what it was built
        // from instead of implying a flake that never existed.
        flake_ref: sources.image_ref.clone(),
        // Content hash of the rootfs: the image equivalent of a flake.lock
        // hash, and the thing a cache key wants.
        flake_lock_hash: revision_hash.clone(),
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: None,
            sizes: Some(sizes.clone()),
        },
        built_at: utc_now(),
        profile: persisted.profile.clone(),
        vcpus: persisted.vcpus,
        mem_mib: persisted.mem_mib,
        data_disk_mib: persisted.data_disk_mib,
        snapshot: None,
        build_mode: Some(build_mode_label(mode).to_string()),
    };

    let rev_meta_path = format!("{rev_dst}/revision.json");
    std::fs::write(&rev_meta_path, serde_json::to_string_pretty(&revision)?)
        .with_context(|| format!("writing {rev_meta_path}"))?;

    template_persist_slot(&persisted.clone().touch(Provenance::current()))?;

    use mvm_core::pool::format_bytes;
    ui::success(&format!(
        "Manifest at '{}' built from image {} (revision: {}, rootfs: {})",
        persisted.manifest_path,
        sources.image_ref,
        &revision_hash[..revision_hash.len().min(12)],
        format_bytes(sizes.rootfs_bytes),
    ));

    Ok(revision)
}

/// Size in bytes, or 0 when it cannot be read. Sizes are display and
/// budgeting metadata; a build should not fail over one.
fn file_len(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::manifest::slot_manifest_path;
    use mvm_core::util::test_env::TestEnv;

    /// A materialized image: `rootfs.ext4` with the sidecar beside it, which is
    /// the shape `mvm-client`'s materialization actually produces.
    fn materialized(dir: &std::path::Path, rootfs_bytes: &[u8]) -> std::path::PathBuf {
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&rootfs, rootfs_bytes).expect("rootfs");
        std::fs::write(
            dir.join(mvm_build::builder_vm::SIDECAR_FILENAME),
            br#"{"overlay_aware":true}"#,
        )
        .expect("sidecar");
        rootfs
    }

    fn persisted(path: &str) -> PersistedManifest {
        PersistedManifest {
            schema_version: 1,
            manifest_path: path.to_string(),
            manifest_hash: "a".repeat(64),
            flake_ref: String::new(),
            profile: "default".to_string(),
            vcpus: 2,
            mem_mib: 512,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: Some("imgdemo".to_string()),
            backend: "mock".to_string(),
            provenance: Provenance::current(),
            created_at: utc_now(),
            updated_at: utc_now(),
        }
    }

    fn sources(dir: &std::path::Path, rootfs_bytes: &[u8]) -> ImageBuildSources {
        let kernel = dir.join("vmlinux");
        std::fs::write(&kernel, b"kernel").expect("kernel");
        ImageBuildSources {
            rootfs: materialized(dir, rootfs_bytes),
            kernel,
            image_ref: "alpine:3.20".to_string(),
        }
    }

    #[test]
    fn an_image_slot_gets_the_same_revision_layout_as_a_flake_slot() {
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let src = tempfile::tempdir().expect("tmp");
        let p = persisted("/tmp/imgproj/mvm.toml");

        let rev = template_build_from_image(
            &p,
            &sources(src.path(), b"rootfs-contents"),
            mvm_build::pipeline::BuildMode::Prod,
        )
        .expect("image build");

        let dir = std::path::PathBuf::from(slot_revision_dir(&p.manifest_hash, &rev.revision_hash));
        for artifact in [
            "rootfs.ext4",
            "vmlinux",
            "fc-base.json",
            "revision.json",
            mvm_build::builder_vm::SIDECAR_FILENAME,
        ] {
            assert!(dir.join(artifact).is_file(), "missing {artifact}");
        }
        assert!(
            std::path::PathBuf::from(slot_current_symlink(&p.manifest_hash)).exists(),
            "`current` must point at the new revision"
        );
        assert!(
            std::path::PathBuf::from(slot_manifest_path(&p.manifest_hash)).is_file(),
            "the slot record must be persisted so `--manifest` can find it"
        );
        drop(env);
        drop(home);
    }

    /// Same digest in, same revision out — so rebuilding a pinned image does
    /// not accumulate revisions, and a changed image gets a new one without
    /// the caller tracking anything.
    #[test]
    fn the_revision_is_keyed_by_rootfs_content() {
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let a = tempfile::tempdir().expect("tmp");
        let b = tempfile::tempdir().expect("tmp");
        let c = tempfile::tempdir().expect("tmp");
        let p = persisted("/tmp/imgproj/mvm.toml");
        let mode = mvm_build::pipeline::BuildMode::Prod;

        let first = template_build_from_image(&p, &sources(a.path(), b"same"), mode)
            .expect("first")
            .revision_hash;
        let again = template_build_from_image(&p, &sources(b.path(), b"same"), mode)
            .expect("again")
            .revision_hash;
        let changed = template_build_from_image(&p, &sources(c.path(), b"different"), mode)
            .expect("changed")
            .revision_hash;

        assert_eq!(first, again, "identical content must reuse the revision");
        assert_ne!(first, changed, "changed content must be a new revision");
        drop(env);
        drop(home);
    }

    /// The sidecar carries the overlay-awareness the backend reads at boot.
    /// Installing a slot without it would produce a revision that boots
    /// differently from the `run --image` it was supposed to mirror, so this
    /// refuses rather than shipping a subtly wrong slot.
    #[test]
    fn a_materialization_with_no_sidecar_refuses() {
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let dir = tempfile::tempdir().expect("tmp");
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        let kernel = dir.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel").expect("kernel");

        let err = template_build_from_image(
            &persisted("/tmp/imgproj/mvm.toml"),
            &ImageBuildSources {
                rootfs,
                kernel,
                image_ref: "alpine:3.20".to_string(),
            },
            mvm_build::pipeline::BuildMode::Prod,
        )
        .expect_err("no sidecar must refuse");
        assert!(
            err.to_string().contains("sidecar"),
            "the refusal must name what is missing: {err}"
        );
        drop(env);
        drop(home);
    }

    /// `revision.json` must say what the slot was built from. A fabricated
    /// flake path would imply a flake that never existed.
    #[test]
    fn the_revision_records_the_image_reference() {
        let home = tempfile::tempdir().expect("home");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let dir = tempfile::tempdir().expect("tmp");
        let rev = template_build_from_image(
            &persisted("/tmp/imgproj/mvm.toml"),
            &sources(dir.path(), b"rootfs"),
            mvm_build::pipeline::BuildMode::Prod,
        )
        .expect("image build");
        assert_eq!(rev.flake_ref, "alpine:3.20");
        assert!(
            rev.artifact_paths.initrd.is_none(),
            "an OCI rootfs has none"
        );
        drop(env);
        drop(home);
    }
}
