//! A synthetic checkout pair for tests: an `mvm-images` checkout and a paired
//! mvm checkout, side by side in one temporary directory, with just enough
//! content for `LocalImageCheckout::open` and `LocalImageCacheKey::derive` to
//! accept them, and a manifest emitter in the release schema's local shape.

use std::path::{Path, PathBuf};

use mvm_build::image_source::{FlakeAttr, ImageBuildRole, ImageBuildTarget, LocalImageCacheKey};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::LocalCheckouts;

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
    &'static str,
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
        Self::new_with_image("# builder-vm image\n")
    }

    pub(crate) fn new_with_image(builder_vm_image: &str) -> Self {
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
                write(&dir.join(artifact.name), &artifact.bytes);
                let format = if let Some(kind) = artifact.format.strip_prefix("kernel:") {
                    serde_json::json!({"kernel": kind})
                } else {
                    serde_json::json!(artifact.format)
                };
                manifest_artifacts.push(serde_json::json!({
                    "name": artifact.name,
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
            "members": manifest_members,
        });
        write(
            &dir.join(LOCAL_SET_MANIFEST_NAME),
            &serde_json::to_vec_pretty(&manifest).expect("manifest json"),
        );
    }
}
