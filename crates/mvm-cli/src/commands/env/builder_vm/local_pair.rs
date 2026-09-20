//! The builder VM image built from a selected local image checkout.
//!
//! When `MVM_IMAGES_DIR` names a checkout, the builder VM a consumer boots is
//! the `builder-vm` target of that checkout pair: built once by the shared
//! local-image-set build, served from the local image cache, and installed
//! into the builder-VM cache layout with a provenance record naming the pair.
//! The build that produces it runs inside the in-tree or published tool
//! builder — never inside the image it is building, which would recurse.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_build::image_source::{
    CachedImageSet, ImageBuildTarget, LocalImageCache, LocalImageCacheKey, LocalImageCheckout,
    PairBuild, build_target_for_pair,
};
use mvm_core::arch::GuestArch;

use super::shell_job::ShellJobBuilder;
use super::{bootstrap, stage0_cache};

/// The canonical identity string the builder-VM cache sidecars record for a
/// pair-built image: the SHA-256 of the pair cache key's canonical JSON. A
/// change in either checkout, the toolchain pins or a flake lock changes it,
/// which is what makes the install cache single-sidedly invalidating.
pub(crate) fn pair_fingerprint(key: &LocalImageCacheKey) -> String {
    let digest = key.digest();
    digest.as_str().to_string()
}

/// Derive the cache key for `target` under the pair as it is now. Used by
/// consumers that need the pair's identity before deciding whether a build
/// is needed; refuses a checkout that moved since it was selected.
pub(crate) fn derive_pair_key(
    checkout: &LocalImageCheckout,
    target: &ImageBuildTarget,
) -> Result<LocalImageCacheKey> {
    let channel = mvm_build::artifact_acquisition::compiled_channel();
    let mvm_root =
        mvm_build::image_source::mvm_source_checkout(channel).context(
            "a local image set is built against the mvm checkout this binary was compiled              from, and that checkout is no longer on disk",
        )?;
    LocalImageCacheKey::derive(&mvm_build::image_source::KeyInputs {
        images: checkout,
        mvm_checkout: &mvm_root,
        target,
        arch: GuestArch::host(),
    })
    .context("reading the pair's cache key inputs")
}

/// Build `target` for the pair (answering a cache hit without booting
/// anything) and return the entry and the key it answers.
///
/// The builder the job runs in is the tool builder — the in-tree or published
/// one — via the exempt bootstrap, so building the `builder-vm` target from a
/// pair never routes through the image being built.
pub(crate) fn ensure_pair_built(
    checkout: &LocalImageCheckout,
    target: ImageBuildTarget,
) -> Result<PairBuild> {
    let channel = mvm_build::artifact_acquisition::compiled_channel();
    let mvm_root = mvm_build::image_source::mvm_source_checkout(channel).context(
        "a local image set is built against the mvm checkout this binary was compiled \
             from, and that checkout is no longer on disk",
    )?;
    let cache = LocalImageCache::open_default();
    let arch = GuestArch::host();
    let target_label = target.to_string();
    build_target_for_pair(
        checkout,
        &mvm_root,
        target,
        arch,
        &cache,
        &mut || bootstrap::bootstrap_tool_builder_vm_image().map_err(|error| format!("{error:#}")),
        &mut |job| {
            let choice = mvm_build::builder_backend_select::resolve_choice();
            let builder = ShellJobBuilder::for_choice(choice).ok_or_else(|| {
                format!(
                    "the {choice:?} builder has no shell-job path to build a local image set \
                     on; select `--builder hvf` or `--builder firecracker`"
                )
            })?;
            builder.run(job).map_err(|error| format!("{error:#}"))
        },
    )
    .with_context(|| format!("building {target_label} from the local image checkout"))
}

/// Install a pair-built `builder-vm` entry into the builder-VM cache that
/// `up` and the build paths read, staging and promoting through the same
/// sidecar-validated swap Stage 0 uses.
pub(crate) fn install_pair_builder_vm(
    entry: &CachedImageSet,
    arch: &str,
    fingerprint: &str,
) -> Result<()> {
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    let out_dir_path = Path::new(&out_dir);
    if let Some(parent) = out_dir_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let staging = stage0_cache::unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    for name in mvm_build::cache_install::BUILDER_VM_CACHE_ARTIFACTS {
        let from = entry.dir.join(name);
        std::fs::copy(&from, staging.join(name))
            .with_context(|| format!("copying {} into {}", from.display(), staging.display()))?;
    }
    stage0_cache::write_local_pair_cache_sidecars(&staging, fingerprint)?;
    stage0_cache::promote_local_pair_cache(&staging, out_dir_path, fingerprint)?;
    crate::ui::info(&format!(
        "Builder VM image installed from the local image checkout at {out_dir}."
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::env::builder_vm::test_pair::{Pair, TestArtifact, write};
    use mvm_build::image_source::ImageBuildRole;
    use mvm_core::util::test_env::TestEnv;

    /// Builder-vm artifacts with the sizes and ext4 magic the Stage 0 cache
    /// validator requires.
    fn builder_vm_files() -> Vec<TestArtifact> {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        let mut vmlinux = vec![0x7fu8; 1024 * 1024 + 1];
        vmlinux.extend_from_slice(b"\n");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        vec![
            TestArtifact {
                name: "vmlinux",
                bytes: vmlinux,
                format: "kernel:image",
            },
            TestArtifact {
                name: "rootfs.ext4",
                bytes: rootfs,
                format: "ext4",
            },
            TestArtifact {
                name: "cmdline.txt",
                bytes: b"console=hvc0\n".to_vec(),
                format: "text",
            },
            TestArtifact {
                name: "manifest.json",
                bytes: b"{}\n".to_vec(),
                format: "json",
            },
        ]
    }

    #[test]
    fn the_selector_routes_the_bootstrap_to_a_checkout_only_when_one_is_selected() {
        let mut env = TestEnv::new();
        env.remove(mvm_build::image_source::MVM_IMAGES_DIR_ENV);
        assert!(
            super::super::bootstrap::selected_local_checkout()
                .expect("no selector resolves")
                .is_none(),
            "without a selector the bootstrap stays on the tool builder"
        );

        let pair = Pair::new();
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            pair.images.root(),
        );
        let selected = super::super::bootstrap::selected_local_checkout()
            .expect("a valid checkout resolves")
            .expect("a selected checkout routes the bootstrap to the pair");
        assert_eq!(selected.root(), pair.images.root());

        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            "/nonexistent/mvm-images",
        );
        let err = super::super::bootstrap::selected_local_checkout()
            .expect_err("an unusable configured path is an error, never a quiet fall-through");
        assert!(
            err.to_string()
                .contains(mvm_build::image_source::MVM_IMAGES_DIR_ENV),
            "{err:#}"
        );
    }

    #[test]
    fn the_pair_fingerprint_is_the_key_digest_and_moves_with_a_checkout_edit() {
        let pair = Pair::new();
        let key = pair.key(ImageBuildRole::BuilderVm, "default");
        let first = pair_fingerprint(&key);
        assert_eq!(first, pair_fingerprint(&key));

        // An edit after selection is refused at key-derivation time — before
        // anything can publish the new tree under the old identity — so the
        // fingerprint that moves is the one derived from a checkout edited
        // before it was selected.
        write(
            &pair.images.root().join("images/builder-vm/image.nix"),
            b"# edited after selection\n",
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pair.key(ImageBuildRole::BuilderVm, "default");
            }))
            .is_err(),
            "deriving a key from an edited selection must refuse"
        );

        let edited = Pair::new_with_image("# builder-vm image, edited\n");
        let second = pair_fingerprint(&edited.key(ImageBuildRole::BuilderVm, "default"));
        assert_ne!(
            first, second,
            "an image edit must change the pair fingerprint"
        );
    }

    #[test]
    fn installing_a_pair_entry_writes_a_ready_local_pair_cache() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        let target = Pair::target(ImageBuildRole::BuilderVm, "default");
        let key = pair.key(ImageBuildRole::BuilderVm, "default");
        let cache = mvm_build::image_source::LocalImageCache::at(
            pair.mvm.parent().expect("tmp").join("cache"),
        );
        let contract = mvm_build::image_source::contract_for(&target).expect("builder-vm contract");
        let ctx = mvm_build::image_source::EntryContext {
            images: &pair.images,
            mvm_checkout: &pair.mvm,
            roles: contract.set_roles,
        };
        let staged = cache.stage(&key).expect("stage");
        Pair::emit_set(
            staged.dir(),
            &key.checkouts,
            key.arch,
            &[(
                "builder_vm",
                Some("linux_direct"),
                builder_vm_files(),
                &["virtio_vsock", "virtio_blk"],
            )],
        );
        let published = cache.publish(staged, &ctx).expect("publish");
        let entry = published.entry().clone();

        // The install lands in MVM_HOME's builder-vm cache; keep it inside
        // the pair's temp dir.
        let home = pair.mvm.parent().expect("tmp").join("home");
        std::fs::create_dir_all(&home).expect("mkdir home");
        env.set("MVM_HOME", &home);
        let fingerprint = pair_fingerprint(&key);
        install_pair_builder_vm(&entry, &key.arch.to_string(), &fingerprint).expect("install");

        let out_dir = home.join("cache/builder-vm").join(key.arch.to_string());
        assert!(
            super::stage0_cache::local_pair_cache_ready(&out_dir, &fingerprint),
            "the installed cache must be ready under the pair fingerprint"
        );
        // And it is not a Stage 0 cache: the provenance kind differs.
        assert!(
            !super::stage0_cache::builder_vm_source_cache_ready(&out_dir, &fingerprint),
            "a pair-installed cache must not verify as a Stage 0 cache"
        );
    }
}
