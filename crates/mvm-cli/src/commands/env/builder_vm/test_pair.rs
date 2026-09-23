//! A synthetic checkout pair for tests: an `mvm-images` checkout and a paired
//! mvm checkout, side by side in one temporary directory, with just enough
//! content for `LocalImageCheckout::open` and `LocalImageCacheKey::derive` to
//! accept them, and a manifest emitter in the release schema's local shape.

use std::path::{Path, PathBuf};

use mvm_build::image_source::{FlakeAttr, ImageBuildRole, ImageBuildTarget, LocalImageCacheKey};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, LocalCheckouts, WorkloadImageProfile};

pub(crate) const MVM_CARGO_TOML: &str = r#"[workspace]

[workspace.metadata.mvm.toolchain]
rust = "nightly-2026-08-25"
zig = "0.14.1"
cargo-zigbuild = "0.20.1"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64 = "x86_64-unknown-linux-musl"
"#;

pub(crate) fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, bytes).expect("write");
}

pub(crate) fn git(dir: &Path, args: &[&str]) {
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
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// A synthetic mvm-images checkout: the layout markers as regular files, plus
/// the `builder-vm` image source, committed before any selection records the
/// identity.
pub(crate) fn images_checkout(dir: &Path, builder_vm_image: &str) {
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
pub(crate) fn mvm_checkout(dir: &Path) {
    write(&dir.join("Cargo.toml"), MVM_CARGO_TOML.as_bytes());
    write(
        &dir.join("rust-toolchain.toml"),
        b"[toolchain]\nchannel = \"nightly-2026-08-25\"\n",
    );
    git(dir, &["init", "-q"]);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", "mvm"]);
}

/// One artifact of a member: its file name, bytes, the manifest `format`
/// value (`"kernel:image"` becomes `{"kernel": "image"}`, anything else a
/// plain string), and its declared format name.
pub(crate) struct TestArtifact {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub format: &'static str,
}

/// One member of a test set: its role, its boot protocol (`Some("linux_direct")`
/// for bootable roles, `None` otherwise), its artifacts and its required
/// capabilities.
pub(crate) type TestMember = (
    ImageSetRole,
    Option<&'static str>,
    Vec<TestArtifact>,
    &'static [&'static str],
);

/// The sidecar an image producer emits: build facts present, acquisition
/// facts absent.
pub(crate) fn produced_sidecar() -> &'static str {
    r#"{
        "name": "mvm-default-microvm",
        "accessible": false,
        "sealed": true,
        "entrypointKind": "command",
        "initSystem": "busybox",
        "expectedBootMs": 300,
        "agentBinary": "real",
        "rootlessEntrypoint": true,
        "hypervisor": "libkrun",
        "protocolVersion": 2,
        "generatorRev": "abc123",
        "source": "built-local"
    }"#
}

/// A synthetic checkout pair in one temporary directory.
pub(crate) struct Pair {
    pub tmp: tempfile::TempDir,
    pub images: mvm_build::image_source::LocalImageCheckout,
    pub mvm: PathBuf,
}

impl Pair {
    pub(crate) fn new() -> Self {
        Self::from_builder_vm_image("# builder-vm image\n")
    }

    pub(crate) fn from_builder_vm_image(builder_vm_image: &str) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let images_dir = tmp.path().join("mvm-images");
        images_checkout(&images_dir, builder_vm_image);
        let mvm = tmp.path().join("mvm");
        mvm_checkout(&mvm);
        let images = mvm_build::image_source::LocalImageCheckout::open(&images_dir)
            .expect("synthetic images checkout opens");
        Self { tmp, images, mvm }
    }

    pub(crate) fn target(role: ImageBuildRole, attr: &str) -> ImageBuildTarget {
        ImageBuildTarget {
            role,
            attr: FlakeAttr::new(attr).unwrap(),
        }
    }

    pub(crate) fn key(&self, role: ImageBuildRole, attr: &str) -> LocalImageCacheKey {
        LocalImageCacheKey::derive(&mvm_build::image_source::KeyInputs {
            images: &self.images,
            mvm_checkout: &self.mvm,
            target: &Self::target(role, attr),
            arch: GuestArch::host(),
        })
        .expect("key derives from the synthetic pair")
    }

    /// Publish this pair's `default-tenant.default` set into the current
    /// `MVM_HOME`'s local image cache (set `MVM_HOME` before calling). The
    /// five artifacts are the default-tenant contract; the sidecar is a
    /// producer-shaped `mvm-meta.json`.
    pub(crate) fn publish_default_tenant(&self) -> mvm_build::image_source::CachedImageSet {
        self.publish_workload_profile(WorkloadImageProfile::DefaultTenant)
    }

    /// Publish either generic workload profile with the same artifact layout
    /// but distinct profile-qualified manifest roles and cache identity.
    pub(crate) fn publish_workload_profile(
        &self,
        profile: WorkloadImageProfile,
    ) -> mvm_build::image_source::CachedImageSet {
        const EXT4_MAGIC_OFFSET: usize = 1024 + 56;
        let mut vmlinux = vec![0x7fu8; 1024 * 1024 + 1];
        vmlinux.extend_from_slice(b"\n");
        let mut rootfs = vec![0u8; 4 * 1024 * 1024 + 1];
        rootfs[EXT4_MAGIC_OFFSET] = 0x53;
        rootfs[EXT4_MAGIC_OFFSET + 1] = 0xEF;
        let rootfs_sidecar = TestArtifact {
            name: "mvm-meta.json",
            bytes: produced_sidecar().as_bytes().to_vec(),
            format: "json",
        };
        self.publish(
            mvm_build::image_source::ImageBuildRole::for_workload_profile(profile),
            "default",
            &[
                (
                    ImageSetRole::WorkloadKernel(profile),
                    Some("linux_direct"),
                    vec![TestArtifact {
                        name: "vmlinux",
                        bytes: vmlinux,
                        format: "kernel:image",
                    }],
                    &["virtio_vsock"],
                ),
                (
                    ImageSetRole::WorkloadRootfs(profile),
                    None,
                    vec![
                        TestArtifact {
                            name: "rootfs.ext4",
                            bytes: rootfs,
                            format: "ext4",
                        },
                        TestArtifact {
                            name: "rootfs.verity",
                            bytes: b"verity tree\n".to_vec(),
                            format: "verity_hash_tree",
                        },
                        TestArtifact {
                            name: "rootfs.roothash",
                            bytes: b"root hash\n".to_vec(),
                            format: "verity_root_hash",
                        },
                        rootfs_sidecar,
                    ],
                    &["virtio_blk", "dm_verity"],
                ),
            ],
        )
    }

    /// Publish a set for any target into the current `MVM_HOME`'s local
    /// image cache (set `MVM_HOME` before calling). The set is keyed on the
    /// mvm checkout the test binary was compiled from, the same input the
    /// build path derives, so a later lookup hits.
    pub(crate) fn publish(
        &self,
        role: mvm_build::image_source::ImageBuildRole,
        attr: &str,
        members: &[TestMember],
    ) -> mvm_build::image_source::CachedImageSet {
        let target = Self::target(role, attr);
        let mvm_root = mvm_build::image_source::mvm_source_checkout(
            mvm_build::artifact_acquisition::compiled_channel(),
        )
        .expect("the compiled-from mvm checkout is on disk");
        let key = mvm_build::image_source::LocalImageCacheKey::derive(
            &mvm_build::image_source::KeyInputs {
                images: &self.images,
                mvm_checkout: &mvm_root,
                target: &target,
                arch: GuestArch::host(),
            },
        )
        .expect("key derives");
        let cache = mvm_build::image_source::LocalImageCache::open_default();
        let contract =
            mvm_build::image_source::contract_for(&target).expect("contract for the role");
        let ctx = mvm_build::image_source::EntryContext {
            images: &self.images,
            mvm_checkout: &mvm_root,
            roles: contract.set_roles,
        };
        let staged = cache.stage(&key).expect("stage");
        Self::emit_set(staged.dir(), &key.checkouts, key.arch, members);
        cache
            .publish(staged, &ctx)
            .expect("publish")
            .entry()
            .clone()
    }

    /// Write a local-set manifest over `members` into `dir`, the shape the
    /// image repository's emitter produces. Each member is its role, its boot
    /// protocol (`Some("linux_direct")` for bootable roles, `None` otherwise),
    /// its artifacts and its required capabilities.
    pub(crate) fn emit_set(
        dir: &Path,
        checkouts: &LocalCheckouts,
        arch: GuestArch,
        members: &[TestMember],
    ) {
        use mvm_core::image_set::LOCAL_SET_MANIFEST_NAME;
        use mvm_core::packs::Sha256Hex;
        let mut manifest_members = Vec::new();
        for (role, boot_protocol, artifacts, capabilities) in members {
            let mut manifest_artifacts = Vec::new();
            for artifact in artifacts {
                // Name the file the way the image repository's manifest
                // emitter does — <role-kebab>-<arch>-<contract-name> — so
                // tests exercise the same layout a real build publishes.
                let produced = format!("{}-{}-{}", role.replace('_', "-"), arch, artifact.name);
                write(&dir.join(&produced), &artifact.bytes);
                let format = if let Some(kind) = artifact.format.strip_prefix("kernel:") {
                    serde_json::json!({"kernel": kind})
                } else {
                    serde_json::json!(artifact.format)
                };
                manifest_artifacts.push(serde_json::json!({
                    "name": produced,
                    "format": format,
                    "sha256": Sha256Hex::from_bytes(&artifact.bytes).as_str(),
                    "size": artifact.bytes.len(),
                }));
            }
            manifest_members.push(serde_json::json!({
                "role": role,
                "target": {"arch": arch.to_string()},
                "boot_protocol": boot_protocol,
                "artifacts": manifest_artifacts,
                "required_capabilities": capabilities,
            }));
        }
        let manifest = serde_json::json!({
            "schema_version": 2,
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
            "members": manifest_members,
        });
        write(
            &dir.join(LOCAL_SET_MANIFEST_NAME),
            &serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        );
    }
}
