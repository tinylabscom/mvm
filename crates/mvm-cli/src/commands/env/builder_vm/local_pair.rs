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
    use mvm_build::image_source::{
        ImageBuildRole, ImageBuildTarget, KeyInputs, LocalImageCache, LocalImageCacheKey,
    };
    use mvm_core::image_set::LOCAL_SET_MANIFEST_NAME;
    use mvm_core::util::test_env::TestEnv;
    use std::path::PathBuf;

    const MVM_CARGO_TOML: &str = r#"[workspace]

[workspace.metadata.mvm.toolchain]
rust = "nightly-2026-08-25"
zig = "0.14.1"
cargo-zigbuild = "0.20.1"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64 = "x86-unknown-linux-musl"
"#;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, bytes).expect("write");
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }

    /// A synthetic mvm-images checkout: the layout markers as regular files,
    /// plus any `image.nix` edit, committed before the selection records the
    /// identity.
    fn images_checkout(dir: &Path, builder_vm_image: &str) {
        std::fs::create_dir_all(dir).expect("mkdir images");
        for marker in mvm_build::image_source::IMAGES_CHECKOUT_MARKERS {
            write(&dir.join(marker), format!("# {marker}\n").as_bytes());
        }
        write(
            &dir.join("images/builder-vm/image.nix"),
            builder_vm_image.as_bytes(),
        );
        git(dir, &["init", "-q"]);
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", "images"]);
    }

    /// A synthetic mvm checkout with the toolchain tables key derivation reads.
    fn mvm_checkout(dir: &Path) {
        write(&dir.join("Cargo.toml"), MVM_CARGO_TOML.as_bytes());
        write(
            &dir.join("rust-toolchain.toml"),
            b"[toolchain]\nchannel = \"nightly-2026-08-25\"\n",
        );
        git(dir, &["init", "-q"]);
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", "mvm"]);
    }

    fn builder_vm_target() -> ImageBuildTarget {
        ImageBuildTarget {
            role: ImageBuildRole::BuilderVm,
            attr: mvm_build::image_source::FlakeAttr::new("default").unwrap(),
        }
    }

    /// The builder-vm member manifest the image repository's emitter writes,
    /// over the four contract artifacts.
    fn emit_builder_vm_set(
        dir: &Path,
        checkouts: &mvm_core::image_set::LocalCheckouts,
        arch: GuestArch,
    ) {
        use mvm_core::packs::Sha256Hex;
        // The sizes and the ext4 magic satisfy the same artifact validator the
        // Stage 0 cache promotion runs.
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        let mut vmlinux = vec![0x7fu8; 1024 * 1024 + 1];
        vmlinux.extend_from_slice(b"\n");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let files: Vec<(&str, Vec<u8>, &str)> = vec![
            ("vmlinux", vmlinux, "kernel:image"),
            ("rootfs.ext4", rootfs, "ext4"),
            ("cmdline.txt", b"console=hvc0\n".to_vec(), "text"),
            ("manifest.json", b"{}\n".to_vec(), "json"),
        ];
        let mut artifacts = Vec::new();
        for (name, bytes, format) in &files {
            write(&dir.join(name), bytes);
            let (kind, fmt) = format.split_once(':').unwrap_or(("file", format));
            artifacts.push(serde_json::json!({
                "name": name,
                "format": if kind == "kernel" { serde_json::json!({"kernel": fmt}) } else { serde_json::json!(fmt) },
                "sha256": Sha256Hex::from_bytes(bytes).as_str(),
                "size": bytes.len(),
            }));
        }
        let manifest = serde_json::json!({
            "schema_version": 1,
            "set_version": "0.0.0-local",
            "issued_at": "2026-01-01T00:00:00Z",
            "producer": {"local_checkouts": checkouts},
            "mvm_source_commit": checkouts.mvm.commit,
            "compatibility": {
                "guest_agent_protocol": {"min": 2, "max": 2},
                "builder_cache_contract": 1
            },
            "nix_inputs": {
                "flake_locks": [{
                    "reference": "mvm-images:flake.lock",
                    "lock_hash": Sha256Hex::from_bytes(b"lock").as_str()
                }],
                "source_revisions": []
            },
            "members": [{
                "role": "builder_vm",
                "target": {"arch": arch.to_string()},
                "boot_protocol": "linux_direct",
                "artifacts": artifacts,
                "required_capabilities": ["virtio_vsock", "virtio_blk"]
            }]
        });
        write(
            &dir.join(LOCAL_SET_MANIFEST_NAME),
            &serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        );
    }

    struct Pair {
        _tmp: tempfile::TempDir,
        images: mvm_build::image_source::LocalImageCheckout,
        mvm: PathBuf,
    }

    impl Pair {
        fn new() -> Self {
            Self::new_with_image("# builder-vm image\n")
        }

        fn new_with_image(builder_vm_image: &str) -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let images_dir = tmp.path().join("mvm-images");
            images_checkout(&images_dir, builder_vm_image);
            let mvm = tmp.path().join("mvm");
            mvm_checkout(&mvm);
            let images = mvm_build::image_source::LocalImageCheckout::open(&images_dir)
                .expect("synthetic images checkout opens");
            Self {
                _tmp: tmp,
                images,
                mvm,
            }
        }

        fn key(&self, cache_arch: GuestArch) -> LocalImageCacheKey {
            LocalImageCacheKey::derive(&KeyInputs {
                images: &self.images,
                mvm_checkout: &self.mvm,
                target: &builder_vm_target(),
                arch: cache_arch,
            })
            .expect("key derives from the synthetic pair")
        }
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
        let key = pair.key(GuestArch::host());
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
                pair.key(GuestArch::host());
            }))
            .is_err(),
            "deriving a key from an edited selection must refuse"
        );

        let edited = Pair::new_with_image("# builder-vm image, edited\n");
        let second = pair_fingerprint(&edited.key(GuestArch::host()));
        assert_ne!(
            first, second,
            "an image edit must change the pair fingerprint"
        );
    }

    #[test]
    fn installing_a_pair_entry_writes_a_ready_local_pair_cache() {
        let mut env = TestEnv::new();
        let pair = Pair::new();
        let arch = GuestArch::host();
        let key = pair.key(arch);
        let cache = LocalImageCache::at(pair.mvm.parent().expect("tmp").join("cache"));
        let contract = mvm_build::image_source::contract_for(&builder_vm_target())
            .expect("builder-vm has a contract");
        let ctx = mvm_build::image_source::EntryContext {
            images: &pair.images,
            mvm_checkout: &pair.mvm,
            roles: contract.set_roles,
        };
        let staged = cache.stage(&key).expect("stage");
        emit_builder_vm_set(staged.dir(), &key.checkouts, arch);
        let published = cache.publish(staged, &ctx).expect("publish");
        let entry = published.entry().clone();

        // The install lands in MVM_HOME's builder-vm cache; keep it inside
        // the pair's temp dir.
        let home = pair.mvm.parent().expect("tmp").join("home");
        std::fs::create_dir_all(&home).expect("mkdir home");
        env.set("MVM_HOME", &home);
        let fingerprint = pair_fingerprint(&key);
        install_pair_builder_vm(&entry, &arch.to_string(), &fingerprint).expect("install");

        let out_dir = home.join("cache/builder-vm").join(arch.to_string());
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
