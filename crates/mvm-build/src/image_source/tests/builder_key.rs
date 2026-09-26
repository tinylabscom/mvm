//! The builder image's cache key names only the mvm sources the image reads,
//! over real git checkouts shaped like the real pair.

use std::path::PathBuf;

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetRole, LOCAL_SET_MANIFEST_NAME, LocalCheckouts, WorkloadImageProfile,
};
use mvm_core::packs::Sha256Hex;

use super::*;

/// How the image checkout's builder source reads the mvm tree, the way the
/// real one does.
const BUILDER_IMAGE_NIX: &str = r#"{
  outputs = { mvm-src, ... }:
    let
      workspaceRoot = mvm-src.outPath;
      workspace = import (workspaceRoot + "/nix/lib/workspace-filter.nix") { };
      mvm = (import (workspaceRoot + "/nix/flake.nix")).outputs { };
    in { };
}
"#;

const MVM_CARGO_TOML: &str = r#"[workspace]
members = ["crates/*"]

[workspace.dependencies]
libc = "0.2"
clap = "4"

[profile.release]
lto = true

[workspace.metadata.mvm.toolchain]
rust = "nightly-2026-08-25"
zig = "0.14.1"
cargo-zigbuild = "0.20.1"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64 = "x86_64-unknown-linux-musl"
"#;

fn cargo_lock(libc: &str, clap: &str) -> String {
    format!(
        r#"version = 4

[[package]]
name = "mvm-setpriv"
version = "0.1.0"
dependencies = ["libc"]

[[package]]
name = "mvm-build"
version = "0.1.0"
dependencies = ["mvm-setpriv"]

[[package]]
name = "mvm-cli"
version = "0.1.0"
dependencies = ["clap", "mvm-build"]

[[package]]
name = "libc"
version = "{libc}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "libc-{libc}"

[[package]]
name = "clap"
version = "{clap}"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "clap-{clap}"
"#
    )
}

fn crate_at(mvm: &Path, name: &str, deps: &str) {
    write(
        &mvm.join("crates").join(name).join("Cargo.toml"),
        &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n\n{deps}"),
    );
    write(
        &mvm.join("crates").join(name).join("src/lib.rs"),
        "pub fn f() {}\n",
    );
}

/// An mvm checkout with the sources the builder image reads — the Nix inputs,
/// the setpriv leaf, the host-binary package — and one crate it does not.
fn mvm_checkout(mvm: &Path) {
    write(&mvm.join("Cargo.toml"), MVM_CARGO_TOML);
    write(&mvm.join("Cargo.lock"), &cargo_lock("0.2.0", "4.0.0"));
    write(
        &mvm.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"nightly-2026-08-25\"\n",
    );
    write(&mvm.join(".cargo/config.toml"), "[build]\n");
    crate_at(
        mvm,
        "mvm-setpriv",
        "[dependencies]\nlibc.workspace = true\n",
    );
    crate_at(
        mvm,
        "mvm-build",
        "[dependencies]\nmvm-setpriv = { path = \"../mvm-setpriv\" }\n",
    );
    crate_at(
        mvm,
        "mvm-cli",
        "[dependencies]\nclap.workspace = true\nmvm-build = { path = \"../mvm-build\" }\n",
    );
    write(&mvm.join("nix/flake.nix"), "{ outputs = _: { }; }\n");
    write(&mvm.join("nix/lib/workspace-filter.nix"), "{ }\n");
    write(&mvm.join("nix/packages/mvm-setpriv.nix"), "{ }\n");
    write(&mvm.join("docs/guide.md"), "# guide\n");
    commit_all(mvm, "mvm");
}

fn commit_all(dir: &Path, message: &str) {
    git(dir, &["init", "-q"]);
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "-m", message]);
}

/// An image checkout whose builder source is `builder_image_nix`.
fn images_checkout_reading(dir: &Path, builder_image_nix: &str) {
    std::fs::create_dir_all(dir).unwrap();
    for marker in IMAGES_CHECKOUT_MARKERS {
        write(&dir.join(marker), &format!("# {marker}\n"));
    }
    write(&dir.join("images/builder-vm/image.nix"), builder_image_nix);
    commit_all(dir, "images");
}

struct Pair {
    tmp: tempfile::TempDir,
    images: LocalImageCheckout,
}

impl Pair {
    fn new() -> Self {
        Self::reading(BUILDER_IMAGE_NIX)
    }

    fn reading(builder_image_nix: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        images_checkout_reading(&tmp.path().join("mvm-images"), builder_image_nix);
        mvm_checkout(&tmp.path().join("mvm"));
        let images = LocalImageCheckout::open(&tmp.path().join("mvm-images")).unwrap();
        Self { tmp, images }
    }

    fn mvm(&self) -> PathBuf {
        self.tmp.path().join("mvm")
    }

    fn key_for(&self, role: ImageBuildRole) -> LocalImageCacheKey {
        LocalImageCacheKey::derive(&KeyInputs {
            images: &self.images,
            mvm_checkout: &self.mvm(),
            target: &ImageBuildTarget {
                role,
                attr: FlakeAttr::new("default").unwrap(),
            },
            arch: GuestArch::Aarch64,
        })
        .unwrap()
    }

    fn builder_key(&self) -> LocalImageCacheKey {
        self.key_for(ImageBuildRole::BuilderVm)
    }

    fn whole_checkout(&self) -> RepoIdentity {
        probe_identity(&self.mvm()).unwrap()
    }
}

type MvmEdit = (&'static str, fn(&Path));

#[test]
fn the_builder_image_is_keyed_on_the_sources_it_reads_not_the_checkout() {
    let pair = Pair::new();
    assert!(
        matches!(pair.builder_key().mvm, MvmSourceIdentity::ConsumedInputs(_)),
        "{}",
        pair.builder_key().mvm
    );
}

#[test]
fn an_mvm_edit_outside_what_the_builder_image_reads_leaves_its_key_alone() {
    let edits: [MvmEdit; 4] = [
        ("a crate the image never compiles", |mvm| {
            write(&mvm.join("crates/mvm-cli/src/lib.rs"), "pub fn g() {}\n");
        }),
        ("a document", |mvm| {
            write(&mvm.join("docs/guide.md"), "# guide, edited\n");
        }),
        ("a lock bump of a crate only mvm-cli uses", |mvm| {
            write(&mvm.join("Cargo.lock"), &cargo_lock("0.2.0", "4.1.0"));
        }),
        ("a new untracked file at the root", |mvm| {
            write(&mvm.join("NOTES.txt"), "scratch\n");
        }),
    ];
    for (what, edit) in edits {
        let pair = Pair::new();
        let before = pair.builder_key();
        let checkout_before = pair.whole_checkout();

        edit(&pair.mvm());

        assert_ne!(
            pair.whole_checkout(),
            checkout_before,
            "{what}: the edit must change the checkout, or this proves nothing"
        );
        assert_eq!(
            pair.builder_key(),
            before,
            "{what} must not change the builder image key"
        );
    }
}

#[test]
fn an_edit_to_each_source_the_builder_image_reads_changes_its_key() {
    let edits: [MvmEdit; 9] = [
        ("the top-level Nix flake", |mvm| {
            write(&mvm.join("nix/flake.nix"), "{ outputs = _: { x = 1; }; }\n");
        }),
        ("the shared Nix library", |mvm| {
            write(&mvm.join("nix/lib/workspace-filter.nix"), "{ x = 1; }\n");
        }),
        ("a guest recipe", |mvm| {
            write(&mvm.join("nix/packages/mvm-setpriv.nix"), "{ x = 1; }\n");
        }),
        ("the setpriv leaf", |mvm| {
            write(
                &mvm.join("crates/mvm-setpriv/src/lib.rs"),
                "pub fn g() {}\n",
            );
        }),
        ("the package the baked host binaries come from", |mvm| {
            write(&mvm.join("crates/mvm-build/src/lib.rs"), "pub fn g() {}\n");
        }),
        ("a lock bump of a crate setpriv reaches", |mvm| {
            write(&mvm.join("Cargo.lock"), &cargo_lock("0.2.1", "4.0.0"));
        }),
        ("the release profile", |mvm| {
            write(
                &mvm.join("Cargo.toml"),
                &MVM_CARGO_TOML.replace("lto = true", "lto = false"),
            );
        }),
        (
            "the cargo configuration the host binaries build under",
            |mvm| {
                write(&mvm.join(".cargo/config.toml"), "[build]\nrustflags = []\n");
            },
        ),
        ("the pinned toolchain", |mvm| {
            write(
                &mvm.join("rust-toolchain.toml"),
                "[toolchain]\nchannel = \"nightly-2026-09-01\"\n",
            );
        }),
    ];
    for (what, edit) in edits {
        let pair = Pair::new();
        let before = pair.builder_key();

        edit(&pair.mvm());

        assert_ne!(
            pair.builder_key().digest(),
            before.digest(),
            "an edit to {what} must change the builder image key"
        );
    }
}

#[test]
fn other_roles_still_key_on_the_whole_mvm_checkout() {
    let pair = Pair::new();
    let before = pair.key_for(ImageBuildRole::RuntimeOverlay);
    assert_eq!(
        before.mvm,
        MvmSourceIdentity::Checkout(pair.whole_checkout())
    );

    write(
        &pair.mvm().join("crates/mvm-cli/src/lib.rs"),
        "pub fn g() {}\n",
    );

    assert_ne!(pair.key_for(ImageBuildRole::RuntimeOverlay), before);
}

#[test]
fn a_builder_image_reading_an_unlisted_mvm_path_keys_on_the_whole_checkout() {
    for (what, nix) in [
        (
            "a read outside the listed inputs",
            r#"{ x = import (workspaceRoot + "/nix/flake.nix"); y = workspaceRoot + "/crates/mvm-cli/data"; }"#,
        ),
        ("no recognisable read at all", "{ outputs = _: { }; }\n"),
    ] {
        let pair = Pair::reading(nix);
        assert_eq!(
            pair.builder_key().mvm,
            MvmSourceIdentity::Checkout(pair.whole_checkout()),
            "{what}"
        );
    }
}

#[test]
fn a_builder_entry_is_served_after_an_unrelated_mvm_commit() {
    let pair = Pair::new();
    let cache = LocalImageCache::at(pair.tmp.path().join("cache"));
    let roles = &[ImageSetRole::WorkloadKernel(
        WorkloadImageProfile::DefaultTenant,
    )];
    let ctx = EntryContext {
        images: &pair.images,
        mvm_checkout: &pair.mvm(),
        roles,
    };
    let key = pair.builder_key();
    let built_from = pair.images.current_checkouts(&pair.mvm()).unwrap();
    let staged = cache.stage(&key).unwrap();
    emit_kernel_set(staged.dir(), &built_from);
    cache.publish(staged, &ctx).unwrap();

    write(
        &pair.mvm().join("crates/mvm-cli/src/lib.rs"),
        "pub fn g() {}\n",
    );
    git(&pair.mvm(), &["add", "-A"]);
    git(&pair.mvm(), &["commit", "-q", "-m", "an unrelated change"]);
    assert_ne!(pair.whole_checkout(), built_from.mvm);

    let again = pair.builder_key();
    assert_eq!(again, key);
    let CacheLookup::Hit(entry) = cache.lookup(&again, &ctx).unwrap() else {
        panic!("the entry for unchanged builder inputs must be served");
    };
    assert_eq!(
        entry.set.checkouts, built_from,
        "the set still names the mvm commit it was built at, as provenance"
    );
}

#[test]
fn a_builder_entry_is_not_served_after_an_edit_to_what_it_reads() {
    let pair = Pair::new();
    let key = pair.builder_key();
    let cache = LocalImageCache::at(pair.tmp.path().join("cache"));
    let ctx = EntryContext {
        images: &pair.images,
        mvm_checkout: &pair.mvm(),
        roles: &[],
    };

    write(
        &pair.mvm().join("crates/mvm-setpriv/src/lib.rs"),
        "pub fn g() {}\n",
    );

    let err = cache.lookup(&key, &ctx).unwrap_err();
    assert!(
        matches!(err, LocalImageCacheError::KeyStale { .. }),
        "{err}"
    );
}

/// A one-member set, the shape the image repository's emitter writes.
fn emit_kernel_set(dir: &Path, checkouts: &LocalCheckouts) {
    let kernel = b"kernel bytes\n";
    let name = "workload-kernel-aarch64-vmlinux";
    std::fs::write(dir.join(name), kernel).unwrap();
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
        "members": [{
            "role": {"workload_kernel": "default_tenant"},
            "target": {"arch": "aarch64"},
            "boot_protocol": "linux_direct",
            "artifacts": [{
                "name": name,
                "format": {"kernel": "image"},
                "sha256": Sha256Hex::from_bytes(kernel).as_str(),
                "size": kernel.len()
            }],
            "required_capabilities": ["virtio_vsock"]
        }]
    });
    std::fs::write(
        dir.join(LOCAL_SET_MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
