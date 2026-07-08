//! `--runtime-pack`: boot straight from a verified, attested
//! [`mvm_core::packs::PackKind::Runtime`] cache entry instead of building or
//! pulling an image. This is an explicit source selection — a caller who
//! passes `--runtime-pack` gets exactly that pack or a refusal, never a
//! silent fallback to a build. The kernel + rootfs paths it hands back are a
//! plain `ImageSource::Prebuilt`, so verity sidecar auto-discovery and plan
//! admission run unchanged, same as every other image source.

use anyhow::Result;

use crate::exec::ImageSource;

/// Resolve the local, verified runtime pack for this host into the
/// `ImageSource` the launch path boots. `prod` only feeds the provenance
/// audit line — pack verification itself carries no prod/dev distinction, a
/// runtime pack either verifies or it doesn't.
///
/// Fails closed: no compatible verified pack (`resolve_pack` returning
/// `Ok(None)`), or any resolve error, is an `Err` here — never a fallback to
/// building or pulling an image. The caller asked for this specific source.
#[cfg(feature = "manifest-verify")]
pub(super) fn resolve_runtime_pack_image_source(prod: bool) -> Result<ImageSource> {
    use std::collections::BTreeSet;

    use anyhow::Context;
    use mvm_core::arch::GuestArch;
    use mvm_core::config::mvm_keys_dir;
    use mvm_core::pack_cache::{PackVerifyCtx, resolve_pack};
    use mvm_core::pack_trust::load_pack_trust_config;
    use mvm_core::packs::{
        HostCapability, LocalPackPolicy, PackBackend, PackKind, host_pack_policy_hash,
    };

    let arch = GuestArch::host();
    let trust = load_pack_trust_config(&mvm_keys_dir().join("pack-trust.json"))
        .context("loading pack trust config for --runtime-pack resolution")?
        .unwrap_or_default();

    // Same trust root a runtime pack from the project's own release pipeline
    // carries: the operator's on-disk publishers unioned with the compiled-in
    // release channels, so a stock binary accepts its own release packs with
    // no operator config required. Mirrors the attested builder-pack
    // acceleration path's policy construction.
    let mut policy = LocalPackPolicy {
        host_arch: arch,
        backend: PackBackend::Hvf,
        host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
        policy_hash: host_pack_policy_hash(arch),
        allowed_channels: trust.allowed_channels(),
        now: chrono::Utc::now(),
    };
    policy
        .allowed_channels
        .extend(mvm_core::release_trust::release_channels());
    let keyless = mvm_core::release_trust::release_keyless_trust(env!("CARGO_PKG_VERSION"));
    let ctx = PackVerifyCtx::keyless(&policy, &keyless, &trust);

    let dir = resolve_pack(PackKind::Runtime, arch, PackBackend::Hvf, &ctx)
        .context("resolving verified runtime pack from the local cache")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--runtime-pack requested but no verified attested runtime pack for this host \
                 is cached; produce/promote one first, or drop --runtime-pack to build or pull \
                 an image instead"
            )
        })?;

    mvm_core::audit_emit!(
        ImageFetch,
        "source=runtime_pack pack_hash={} prod={}",
        dir.verified.pack_hash.as_str(),
        prod
    );

    Ok(runtime_pack_image_source(&dir))
}

#[cfg(not(feature = "manifest-verify"))]
pub(super) fn resolve_runtime_pack_image_source(_prod: bool) -> Result<ImageSource> {
    anyhow::bail!(
        "--runtime-pack requires an mvmctl build with keyless pack verification (the \
         manifest-verify feature); this binary was built without it"
    )
}

/// Pure mapping from a verified runtime pack dir to the `ImageSource` the
/// launch path boots: the pack's own kernel + rootfs paths, labeled by its
/// content-addressed pack hash. No I/O beyond what's already inside `dir`, so
/// it's unit-testable without a promoted pack cache.
#[cfg(feature = "manifest-verify")]
fn runtime_pack_image_source(dir: &mvm_core::pack_cache::VerifiedPackDir) -> ImageSource {
    ImageSource::Prebuilt {
        kernel_path: dir
            .root
            .join(mvm_build::builder_pack::KERNEL_FILE)
            .display()
            .to_string(),
        rootfs_path: dir
            .root
            .join(mvm_build::builder_pack::ROOTFS_FILE)
            .display()
            .to_string(),
        initrd_path: None,
        label: format!("runtime-pack:{}", dir.verified.pack_hash.as_str()),
        virtiofs_oci_root: None,
    }
}

#[cfg(all(test, feature = "manifest-verify"))]
mod tests {
    use std::path::PathBuf;

    use mvm_core::pack_cache::VerifiedPackDir;
    use mvm_core::packs::Sha256Hex;
    use mvm_core::plan::bundle::KeyId;
    use mvm_core::util::test_env::TestEnv;

    use super::*;

    fn verified_pack_dir(root: &str) -> VerifiedPackDir {
        VerifiedPackDir {
            root: PathBuf::from(root),
            verified: mvm_core::packs::VerifiedPack {
                pack_hash: Sha256Hex::from_bytes(b"runtime-pack-test"),
                file_count: 4,
                signer_key_id: KeyId::from_identity("test-identity"),
            },
        }
    }

    #[test]
    fn maps_kernel_and_rootfs_paths_under_pack_root() {
        let dir = verified_pack_dir("/cache/packs/deadbeef");
        let image = runtime_pack_image_source(&dir);
        let ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            virtiofs_oci_root,
            ..
        } = &image
        else {
            panic!("expected ImageSource::Prebuilt");
        };
        assert_eq!(kernel_path, "/cache/packs/deadbeef/vmlinux");
        assert_eq!(rootfs_path, "/cache/packs/deadbeef/rootfs.ext4");
        assert!(rootfs_path.ends_with("rootfs.ext4"));
        assert!(initrd_path.is_none());
        assert!(virtiofs_oci_root.is_none());
    }

    #[test]
    fn label_starts_with_runtime_pack_prefix_and_carries_hash() {
        let dir = verified_pack_dir("/cache/packs/deadbeef");
        let image = runtime_pack_image_source(&dir);
        let ImageSource::Prebuilt { label, .. } = &image else {
            panic!("expected ImageSource::Prebuilt");
        };
        assert!(label.starts_with("runtime-pack:"));
        assert_eq!(
            label,
            &format!("runtime-pack:{}", dir.verified.pack_hash.as_str())
        );
    }

    /// A cache with no promoted packs must fail closed — never fall back to
    /// building or pulling an image just because the operator asked for the
    /// runtime-pack source specifically.
    #[test]
    fn resolve_fails_closed_when_no_pack_is_cached() {
        let cache = tempfile::TempDir::new().expect("cache tempdir");
        let data = tempfile::TempDir::new().expect("data tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", cache.path());
        env.set("MVM_DATA_DIR", data.path());

        let err = resolve_runtime_pack_image_source(false)
            .expect_err("no promoted runtime pack must refuse rather than fall back");
        assert!(
            err.to_string()
                .contains("no verified attested runtime pack")
        );
    }
}
