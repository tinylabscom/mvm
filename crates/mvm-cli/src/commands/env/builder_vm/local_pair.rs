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
use mvm_core::image_set::WorkloadImageProfile;

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
    // Answered from the local image cache when the pair is unchanged, which is
    // quick enough never to be announced; a changed pair builds in a builder
    // VM, whose own line nests under this one.
    let phase = mvm_runtime::ui::activity::start(format!(
        "Preparing {target_label} from the local image checkout"
    ));
    let built = build_target_for_pair(
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
    .with_context(|| format!("building {target_label} from the local image checkout"))?;
    phase.finish();
    Ok(built)
}

/// Resolve the workload kernel from the pair's requested generic profile. The
/// set carries that profile's `workload_kernel` member, so an unchanged pair answers from
/// the local image cache and a changed pair builds once; the returned path
/// is the file the set's manifest digests were verified over.
///
/// The verity-capability check the in-tree path applies reads an optional
/// config sidecar the set does not carry; the pair kernel is the same
/// kernel the sealed default image boots, so the absence of that witness
/// is not a rejection here either.
pub(crate) fn ensure_pair_workload_kernel(
    checkout: &LocalImageCheckout,
    profile: WorkloadImageProfile,
) -> Result<std::path::PathBuf> {
    let target = ImageBuildTarget {
        role: mvm_build::image_source::ImageBuildRole::for_workload_profile(profile),
        attr: mvm_build::image_source::FlakeAttr::new("default")
            .expect("default is a valid flake attribute"),
    };
    let build = ensure_pair_built(checkout, target)?;
    let artifact = build
        .entry
        .set
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.role == mvm_core::image_set::ImageSetRole::WorkloadKernel(profile)
        })
        .with_context(|| format!("the pair's {profile} set has no workload kernel member"))?;
    Ok(artifact.path.clone())
}

/// Copy a sealed (read-only) entry file into a writable cache: the entry's
/// files are sealed at 0444, and cache consumers (the HVF bake opens the
/// builder rootfs read-write; the sidecar stamp rewrites the default
/// image's) must not inherit that.
#[cfg(unix)]
pub(crate) fn copy_contract_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to)
        .with_context(|| format!("copying {} into {}", from.display(), to.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("making {} writable", to.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn copy_contract_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to)
        .with_context(|| format!("copying {} into {}", from.display(), to.display()))?;
    Ok(())
}

/// A staging directory holding a pair entry's contract files under their
/// canonical names, for installers that read a fixed layout (the overlay
/// reader, the SDK sidecar installer). Removed on drop.
pub(crate) fn staged_contract_files(
    entry: &mvm_build::image_source::CachedImageSet,
    files: &[(&str, &str)],
) -> Result<tempfile::TempDir> {
    let parent = Path::new(&mvm_core::config::mvm_cache_dir()).join("local-image-builds");
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix("contract-")
        .tempdir_in(&parent)
        .with_context(|| format!("creating a staging directory in {}", parent.display()))?;
    mvm_build::image_source::stage_contract_files(entry, files, tmp.path())?;
    Ok(tmp)
}

/// Under a selected checkout, put the pair's workload kernel where the
/// template path's kernel fallback reads it. The template source prefers a
/// built vmlinux, then the verified workload-kernel cache, and only then the
/// builder kernel — which is built without device-mapper on purpose and dies
/// at dm-verity activation, so every sealed workload needs the middle rung
/// to answer. The pair's kernel is that answer; without this seed a
/// kernel-less mkGuest image (the common shape) falls through to the builder
/// kernel the moment a checkout is selected.
#[cfg(feature = "builder-vm")]
pub(crate) fn seed_pair_workload_kernel_cache() -> Result<()> {
    let Some(checkout) = super::bootstrap::selected_local_checkout()? else {
        return Ok(());
    };
    let kernel = ensure_pair_workload_kernel(
        &checkout,
        mvm_core::image_set::WorkloadImageProfile::DefaultTenant,
    )?;
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let dest = mvm_build::kernel_fetch::cached_kernel_path(
        std::path::Path::new(&mvm_core::config::mvm_cache_dir()),
        &arch,
        "workload",
    );
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    copy_contract_file(&kernel, &dest)?;
    mvm_build::kernel_fetch::record_kernel_digest(&dest)
        .with_context(|| format!("recording the digest of {}", dest.display()))?;
    Ok(())
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
        // Entry files are named by the producer's manifest
        // (<role>-<arch>-<name>); resolve through the manifest so the
        // installed bytes are the ones the set's digests verified.
        let from = entry
            .contract_file("builder_vm", name)
            .with_context(|| format!("the pair's set has no builder_vm artifact {name}"))?;
        copy_contract_file(from, &staging.join(name))?;
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

    /// W5m's concurrency witness: two pairs — two image checkouts with
    /// different content, each with its own MVM_HOME the way `bin/dev` scopes
    /// pair state — publish the same target. Each pair's cache holds exactly
    /// its own entry under its own key in its own home; the two entries
    /// coexist, and neither side's build touches the other.
    #[test]
    fn two_pairs_publish_concurrently_without_sharing_cache_entries() {
        let mut env = TestEnv::new();
        // Distinct committed identities so the pair keys differ no matter
        // when the fixtures are created.
        let pair_a = Pair::from_builder_vm_image("# pair A builder-vm image\n");
        let pair_b = Pair::from_builder_vm_image("# pair B builder-vm image, different\n");
        let home_a = pair_a.tmp.path().join("home-a");
        let home_b = pair_b.tmp.path().join("home-b");
        std::fs::create_dir_all(&home_a).unwrap();
        std::fs::create_dir_all(&home_b).unwrap();
        let members = |checkout: &str| {
            vec![(
                mvm_core::image_set::ImageSetRole::BuilderVm,
                Some("linux_direct"),
                {
                    let mut files = builder_vm_files();
                    // Make each pair's bytes distinct so the entries cannot
                    // be confused even if a key ever collided.
                    files[3].bytes = format!("{{\"marker\": \"{checkout}\"}}\n").into_bytes();
                    files
                },
                &["virtio_vsock", "virtio_blk"][..],
            )]
        };

        env.set("MVM_HOME", &home_a);
        let entry_a = pair_a.publish(ImageBuildRole::BuilderVm, "default", &members("pair-a"));
        env.set("MVM_HOME", &home_b);
        let entry_b = pair_b.publish(ImageBuildRole::BuilderVm, "default", &members("pair-b"));

        // Distinct keys, distinct entry dirs, each under its own home: no
        // mutable state is shared, and the digest-keyed pair identities keep
        // the two apart before any bytes are compared.
        assert_ne!(entry_a.key, entry_b.key);
        assert!(entry_a.dir.starts_with(home_a.join("cache")));
        assert!(entry_b.dir.starts_with(home_b.join("cache")));

        // Each home resolves its own pair's entry, and the other pair's
        // build has not touched it: single-sided invalidation is per pair.
        let contract = mvm_build::image_source::contract_for(&Pair::target(
            ImageBuildRole::BuilderVm,
            "default",
        ))
        .expect("builder-vm contract");
        let mvm_root = mvm_build::image_source::mvm_source_checkout(
            mvm_build::artifact_acquisition::compiled_channel(),
        )
        .unwrap();

        env.set("MVM_HOME", &home_a);
        let cache_a = mvm_build::image_source::LocalImageCache::open_default();
        let ctx_a = mvm_build::image_source::EntryContext {
            images: &pair_a.images,
            mvm_checkout: &mvm_root,
            roles: contract.set_roles,
        };
        assert!(
            matches!(
                cache_a.lookup(&entry_a.key, &ctx_a).unwrap(),
                mvm_build::image_source::CacheLookup::Hit(_)
            ),
            "pair A's home still resolves pair A's entry after pair B built"
        );

        env.set("MVM_HOME", &home_b);
        let cache_b = mvm_build::image_source::LocalImageCache::open_default();
        let ctx_b = mvm_build::image_source::EntryContext {
            images: &pair_b.images,
            mvm_checkout: &mvm_root,
            roles: contract.set_roles,
        };
        assert!(
            matches!(
                cache_b.lookup(&entry_b.key, &ctx_b).unwrap(),
                mvm_build::image_source::CacheLookup::Hit(_)
            ),
            "pair B's home resolves pair B's entry"
        );
    }

    /// A kernel-less mkGuest image (the common flake shape) boots through
    /// the template kernel fallback, whose middle rung is the verified
    /// workload kernel. Under a selected checkout that rung
    /// must carry the pair's kernel — otherwise the fallback lands on the
    /// builder kernel, which has no device-mapper and dies at dm-verity
    /// activation.
    #[test]
    fn the_pair_kernel_seeds_the_template_fallback_cache() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        env.set("MVM_HOME", pair.tmp.path().join("home"));
        std::fs::create_dir_all(pair.tmp.path().join("home")).unwrap();
        env.set(
            mvm_build::image_source::MVM_IMAGES_DIR_ENV,
            pair.images.root(),
        );
        let entry = pair.publish_default_tenant();
        let kernel_artifact = entry
            .set
            .artifacts
            .iter()
            .find(|artifact| artifact.role.to_string().contains("kernel"))
            .expect("the fixture set carries the workload kernel");

        super::seed_pair_workload_kernel_cache().expect("the seed installs the pair kernel");

        let cache = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
        let arch = mvm_core::arch::GuestArch::host().to_string();
        let (resolution, _label) =
            mvm_build::kernel_fetch::resolve_kernel_for_workload(&cache, &arch, false);
        let verified = match resolution {
            mvm_build::kernel_fetch::KernelResolution::Cached(verified) => verified,
            other => panic!("the template fallback must find the pair kernel, got {other:?}"),
        };
        // The seed copies: the cache path differs from the entry path, so
        // compare the verified bytes.
        let cached = std::fs::read(verified.path()).unwrap();
        let from_pair = std::fs::read(&kernel_artifact.path).unwrap();
        assert_eq!(
            cached, from_pair,
            "the cached kernel is the pair's verified artifact"
        );
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

        let edited = Pair::from_builder_vm_image("# builder-vm image, edited\n");
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
                mvm_core::image_set::ImageSetRole::BuilderVm,
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
