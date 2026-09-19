//! The local image cache, over real git checkouts and a real cache directory.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, ImageTrustTier, LOCAL_SET_MANIFEST_NAME, LocalCheckouts};
use mvm_core::packs::Sha256Hex;

use super::*;

const KERNEL: &[u8] = b"kernel bytes\n";
const ROLES: &[ImageSetRole] = &[ImageSetRole::WorkloadKernel];

const MVM_CARGO_TOML: &str = r#"[workspace]

[workspace.metadata.mvm.toolchain]
rust = "nightly-2026-08-25"
zig = "0.14.1"
cargo-zigbuild = "0.20.1"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
x86_64 = "x86_64-unknown-linux-musl"
"#;

/// An image checkout, a paired mvm checkout and a cache root, side by side in
/// one temporary directory.
struct Fixture {
    tmp: tempfile::TempDir,
    images: LocalImageCheckout,
    mvm: PathBuf,
    cache: LocalImageCache,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let images_dir = tmp.path().join("mvm-images");
        std::fs::create_dir_all(&images_dir).unwrap();
        write(&images_dir.join("kernel/flake.lock"), "{\"kernel\": 1}\n");
        images_checkout(&images_dir);
        let mvm = tmp.path().join("mvm");
        write(&mvm.join("Cargo.toml"), MVM_CARGO_TOML);
        write(
            &mvm.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"nightly-2026-08-25\"\n",
        );
        git(&mvm, &["init", "-q"]);
        git(&mvm, &["add", "-A"]);
        git(&mvm, &["commit", "-q", "-m", "mvm"]);
        let images = open(&images_dir).unwrap();
        let cache = LocalImageCache::at(tmp.path().join("cache"));
        Self {
            tmp,
            images,
            mvm,
            cache,
        }
    }

    fn images_dir(&self) -> PathBuf {
        self.tmp.path().join("mvm-images")
    }

    fn mvm(&self) -> PathBuf {
        self.mvm.clone()
    }

    /// Select the image checkout again, as a new run would after an edit.
    fn reselect(&mut self) {
        self.images = open(&self.images_dir()).unwrap();
    }

    fn ctx(&self) -> EntryContext<'_> {
        EntryContext {
            images: &self.images,
            mvm_checkout: &self.mvm,
            roles: ROLES,
        }
    }

    fn key_for(&self, target: &ImageBuildTarget, arch: GuestArch) -> LocalImageCacheKey {
        LocalImageCacheKey::derive(&KeyInputs {
            images: &self.images,
            mvm_checkout: &self.mvm(),
            target,
            arch,
        })
        .unwrap()
    }

    fn key(&self) -> LocalImageCacheKey {
        self.key_for(&kernel_target(), GuestArch::Aarch64)
    }

    /// Stage a set for `key` recording the key's checkouts, as a build would.
    fn stage_set(&self, key: &LocalImageCacheKey) -> StagedEntry {
        let staged = self.cache.stage(key).unwrap();
        emit(staged.dir(), &key.checkouts, key.arch, KERNEL);
        staged
    }

    fn publish(&self, key: &LocalImageCacheKey) -> PublishOutcome {
        self.cache
            .publish(self.stage_set(key), &self.ctx())
            .unwrap()
    }

    fn lookup(&self, key: &LocalImageCacheKey) -> CacheLookup {
        self.cache.lookup(key, &self.ctx()).unwrap()
    }

    fn staging_children(&self) -> Vec<String> {
        children(&self.cache.root().join("v1").join(".staging"))
    }
}

fn kernel_target() -> ImageBuildTarget {
    ImageBuildTarget {
        role: ImageBuildRole::Kernel,
        attr: FlakeAttr::new("workload-vmlinux").unwrap(),
    }
}

fn overlay_target() -> ImageBuildTarget {
    ImageBuildTarget {
        role: ImageBuildRole::RuntimeOverlay,
        attr: FlakeAttr::new("default").unwrap(),
    }
}

fn kernel_name(arch: GuestArch) -> String {
    format!("workload-kernel-{arch}-vmlinux")
}

/// Write a one-member set into `dir`, the shape the image repository's
/// emitter produces.
fn emit(dir: &Path, checkouts: &LocalCheckouts, arch: GuestArch, kernel: &[u8]) {
    std::fs::write(dir.join(kernel_name(arch)), kernel).unwrap();
    let manifest = manifest_json(checkouts, arch, &kernel_name(arch), kernel);
    std::fs::write(
        dir.join(LOCAL_SET_MANIFEST_NAME),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn manifest_json(
    checkouts: &LocalCheckouts,
    arch: GuestArch,
    name: &str,
    kernel: &[u8],
) -> serde_json::Value {
    serde_json::json!({
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
                "reference": "mvm-images:kernel/flake.lock",
                "lock_hash": Sha256Hex::from_bytes(b"lock").as_str()
            }],
            "source_revisions": []
        },
        "members": [{
            "role": "workload_kernel",
            "target": {"arch": arch.to_string()},
            "boot_protocol": "linux_direct",
            "artifacts": [{
                "name": name,
                "format": {"kernel": "image"},
                "sha256": Sha256Hex::from_bytes(kernel).as_str(),
                "size": kernel.len()
            }],
            "required_capabilities": ["virtio_vsock"]
        }]
    })
}

fn children(dir: &Path) -> Vec<String> {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            let mut names: Vec<String> = entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
        Err(_) => Vec::new(),
    }
}

/// Published files are read-only; a test that tampers with one has to lift
/// that first, as anyone tampering would.
#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn expect_hit(lookup: CacheLookup) -> CachedImageSet {
    match lookup {
        CacheLookup::Hit(entry) => *entry,
        other => panic!("expected a hit, got {other:?}"),
    }
}

fn expect_evicted(lookup: CacheLookup) -> String {
    match lookup {
        CacheLookup::Evicted { reason } => reason,
        other => panic!("expected an eviction, got {other:?}"),
    }
}

fn staged_refusal(err: LocalImageCacheError) -> String {
    match err {
        LocalImageCacheError::StagedEntryRefused { detail, .. } => detail,
        LocalImageCacheError::StagedSetRefused { source, .. } => source.to_string(),
        other => panic!("expected the staged entry to be refused, got {other}"),
    }
}

#[test]
fn an_unchanged_pair_misses_once_then_hits() {
    let fx = Fixture::new();
    let key = fx.key();
    assert!(matches!(fx.lookup(&key), CacheLookup::Miss));

    let published = fx.publish(&key);
    assert!(matches!(published, PublishOutcome::Published(_)));

    // A second run re-derives the key from the unchanged checkouts.
    let again = fx.key();
    assert_eq!(again, key);
    assert_eq!(again.digest(), key.digest());
    let entry = expect_hit(fx.lookup(&again));
    assert_eq!(entry.dir, fx.cache.entry_dir(&key));
    assert_eq!(entry.tier(), ImageTrustTier::LocalDev);
    assert_eq!(entry.set.artifacts.len(), 1);
    assert!(entry.set.artifacts[0].path.starts_with(&entry.dir));
    assert!(fx.staging_children().is_empty(), "no staging left behind");
}

#[test]
fn the_key_names_every_input_it_was_derived_from() {
    let fx = Fixture::new();
    let key = fx.key();

    assert_eq!(&key.checkouts.images, fx.images.identity());
    assert_eq!(key.checkouts.mvm, probe_identity(&fx.mvm()).unwrap());
    assert_eq!(key.target, kernel_target());
    assert_eq!(key.arch, GuestArch::Aarch64);
    assert_eq!(key.toolchain.zig, "0.14.1");
    assert_eq!(key.toolchain.cargo_zigbuild, "0.20.1");
    assert_eq!(key.toolchain.rust, "nightly-2026-08-25");
    assert_eq!(key.toolchain.target, "aarch64-unknown-linux-musl");
    assert_eq!(
        key.toolchain.rust_toolchain_sha256,
        Sha256Hex::from_bytes(b"[toolchain]\nchannel = \"nightly-2026-08-25\"\n")
    );
    assert_eq!(key.flake_locks.len(), 1);
    assert_eq!(key.flake_locks[0].path, "kernel/flake.lock");
    assert_eq!(
        key.flake_locks[0].sha256,
        Sha256Hex::from_bytes(b"{\"kernel\": 1}\n")
    );
    // The root flake's lock is what an image role evaluates instead.
    let overlay = fx.key_for(&overlay_target(), GuestArch::Aarch64);
    assert_eq!(overlay.flake_locks[0].path, "flake.lock");
}

#[test]
fn every_input_changes_the_key() {
    let mut fx = Fixture::new();
    let base = fx.key();
    let mut digests = vec![base.digest()];

    digests.push(fx.key_for(&kernel_target(), GuestArch::X86_64).digest());
    digests.push(fx.key_for(&overlay_target(), GuestArch::Aarch64).digest());
    let other_attr = ImageBuildTarget {
        role: ImageBuildRole::Kernel,
        attr: FlakeAttr::new("workload-vmlinux-debug").unwrap(),
    };
    digests.push(fx.key_for(&other_attr, GuestArch::Aarch64).digest());

    // An image-side edit, a lock edit, and mvm-side toolchain and source edits,
    // each on its own.
    write(&fx.images_dir().join("README"), "edited\n");
    fx.reselect();
    digests.push(fx.key().digest());
    std::fs::remove_file(fx.images_dir().join("README")).unwrap();
    write(
        &fx.images_dir().join("kernel/flake.lock"),
        "{\"kernel\": 2}\n",
    );
    fx.reselect();
    let relocked = fx.key();
    assert_ne!(relocked.flake_locks, base.flake_locks);
    digests.push(relocked.digest());
    write(
        &fx.images_dir().join("kernel/flake.lock"),
        "{\"kernel\": 1}\n",
    );
    fx.reselect();
    assert_eq!(fx.key(), base, "a reverted edit restores the key");

    write(
        &fx.mvm().join("Cargo.toml"),
        &MVM_CARGO_TOML.replace("0.14.1", "0.15.0"),
    );
    let rezigged = fx.key();
    assert_eq!(rezigged.toolchain.zig, "0.15.0");
    digests.push(rezigged.digest());
    write(&fx.mvm().join("Cargo.toml"), MVM_CARGO_TOML);
    write(&fx.mvm().join("src.rs"), "fn main() {}\n");
    digests.push(fx.key().digest());

    let unique: std::collections::BTreeSet<&str> = digests.iter().map(Sha256Hex::as_str).collect();
    assert_eq!(
        unique.len(),
        digests.len(),
        "every input yields its own key"
    );
}

#[test]
fn an_edit_misses_without_destroying_the_entry_for_the_old_state() {
    let fx = Fixture::new();
    let before = fx.key();
    fx.publish(&before);

    write(&fx.mvm().join("src.rs"), "fn main() {}\n");
    let after = fx.key();
    assert_ne!(after.digest(), before.digest());
    assert!(matches!(fx.lookup(&after), CacheLookup::Miss));
    fx.publish(&after);
    expect_hit(fx.lookup(&after));

    // Back to the old tree: its entry is still there and still served.
    std::fs::remove_file(fx.mvm().join("src.rs")).unwrap();
    assert_eq!(fx.key(), before);
    expect_hit(fx.lookup(&before));
}

#[test]
fn an_entry_for_one_target_survives_a_build_of_another() {
    let fx = Fixture::new();
    let kernel = fx.key();
    fx.publish(&kernel);
    let x86 = fx.key_for(&kernel_target(), GuestArch::X86_64);
    fx.publish(&x86);

    expect_hit(fx.lookup(&kernel));
    expect_hit(fx.lookup(&x86));
}

#[test]
fn a_key_from_checkouts_that_have_since_changed_is_an_error_not_a_lookup() {
    let fx = Fixture::new();
    let key = fx.key();
    fx.publish(&key);
    write(&fx.mvm().join("src.rs"), "fn main() {}\n");

    let err = fx.cache.lookup(&key, &fx.ctx()).unwrap_err();

    assert!(
        matches!(err, LocalImageCacheError::KeyStale { .. }),
        "{err}"
    );
    assert!(
        fx.cache.entry_dir(&key).is_dir(),
        "the entry is not evicted"
    );
}

#[test]
fn an_image_edit_after_selection_is_refused_before_the_cache_is_read() {
    let fx = Fixture::new();
    let key = fx.key();
    fx.publish(&key);
    write(&fx.images_dir().join("README"), "edited\n");

    let err = fx.cache.lookup(&key, &fx.ctx()).unwrap_err();

    assert!(matches!(err, LocalImageCacheError::Selection(_)), "{err}");
}

#[test]
fn a_stale_set_cannot_be_published_under_a_fresh_key() {
    let fx = Fixture::new();
    let old = fx.key();
    write(&fx.mvm().join("src.rs"), "fn main() {}\n");
    let fresh = fx.key();
    let staged = fx.cache.stage(&fresh).unwrap();
    emit(staged.dir(), &old.checkouts, GuestArch::Aarch64, KERNEL);

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(staged_refusal(err).contains("freshness"));
    assert!(matches!(fx.lookup(&fresh), CacheLookup::Miss));
}

#[test]
fn a_crash_mid_publish_leaves_no_visible_entry() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.cache.stage(&key).unwrap();
    // Half a set, and then the process dies: nothing runs its cleanup.
    std::fs::write(staged.dir().join(kernel_name(GuestArch::Aarch64)), KERNEL).unwrap();
    let orphan = staged.dir().to_path_buf();
    std::mem::forget(staged);

    assert!(matches!(fx.lookup(&key), CacheLookup::Miss));
    assert!(!fx.cache.entry_dir(&key).exists());

    // The next run publishes normally beside the orphan.
    assert!(matches!(fx.publish(&key), PublishOutcome::Published(_)));
    expect_hit(fx.lookup(&key));
    assert!(orphan.is_dir(), "a young orphan may belong to a live build");
}

#[test]
fn an_abandoned_staging_directory_is_reaped() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.cache.stage(&key).unwrap();
    let orphan = staged.dir().to_path_buf();
    std::mem::forget(staged);
    let long_ago = SystemTime::now() - Duration::from_secs(7 * 60 * 60);
    std::fs::File::open(&orphan)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();

    let next = fx.cache.stage(&key).unwrap();

    assert!(!orphan.exists());
    assert!(next.dir().is_dir());
}

#[test]
fn an_unpublished_staging_directory_is_removed_when_dropped() {
    let fx = Fixture::new();
    let staged = fx.stage_set(&fx.key());
    let dir = staged.dir().to_path_buf();

    drop(staged);

    assert!(!dir.exists());
}

#[test]
fn concurrent_publishers_of_one_key_agree_on_one_entry() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged: Vec<StagedEntry> = (0..4).map(|_| fx.stage_set(&key)).collect();

    let outcomes: Vec<PublishOutcome> = std::thread::scope(|scope| {
        let handles: Vec<_> = staged
            .into_iter()
            .map(|staged| {
                let fx = &fx;
                scope.spawn(move || fx.cache.publish(staged, &fx.ctx()).unwrap())
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let won = outcomes
        .iter()
        .filter(|o| matches!(o, PublishOutcome::Published(_)))
        .count();
    assert_eq!(won, 1, "exactly one publisher's copy becomes the entry");
    for outcome in &outcomes {
        assert_eq!(outcome.entry().dir, fx.cache.entry_dir(&key));
    }
    expect_hit(fx.lookup(&key));
    assert!(
        fx.staging_children().is_empty(),
        "losers discard their copy"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_in_a_staged_entry_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.stage_set(&key);
    let outside = fx.tmp.path().join("outside");
    std::fs::write(&outside, KERNEL).unwrap();
    let artifact = staged.dir().join(kernel_name(GuestArch::Aarch64));
    std::fs::remove_file(&artifact).unwrap();
    std::os::unix::fs::symlink(&outside, &artifact).unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(staged_refusal(err).contains("symlink"));
    assert!(matches!(fx.lookup(&key), CacheLookup::Miss));
}

#[test]
fn a_subdirectory_in_a_staged_entry_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.stage_set(&key);
    std::fs::create_dir(staged.dir().join("nested")).unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(staged_refusal(err).contains("nested is not a regular file"));
}

#[test]
fn a_file_the_manifest_does_not_name_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.stage_set(&key);
    std::fs::write(staged.dir().join("extra"), b"unverified").unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(staged_refusal(err).contains("extra is not part of the set"));
}

#[test]
fn an_artifact_name_that_leaves_the_entry_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.cache.stage(&key).unwrap();
    std::fs::write(fx.tmp.path().join("cache/v1/escape"), KERNEL).unwrap();
    let manifest = manifest_json(&key.checkouts, key.arch, "../escape", KERNEL);
    std::fs::write(
        staged.dir().join(LOCAL_SET_MANIFEST_NAME),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(
        matches!(err, LocalImageCacheError::StagedSetRefused { .. }),
        "{err}"
    );
}

#[test]
fn a_staged_set_claiming_a_release_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.stage_set(&key);
    let path = staged.dir().join(LOCAL_SET_MANIFEST_NAME);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["producer"] = serde_json::json!({
        "repository": "tinylabscom/mvm-images",
        "workflow": ".github/workflows/release.yml",
        "release_tag": "v1.0.0",
        "source_commit": key.checkouts.images.commit,
    });
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(
        matches!(err, LocalImageCacheError::StagedSetRefused { .. }),
        "{err}"
    );
    assert!(matches!(fx.lookup(&key), CacheLookup::Miss));
}

#[test]
fn a_set_for_another_architecture_is_refused() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.cache.stage(&key).unwrap();
    emit(staged.dir(), &key.checkouts, GuestArch::X86_64, KERNEL);

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(
        matches!(err, LocalImageCacheError::StagedSetRefused { .. }),
        "{err}"
    );
}

#[test]
fn a_build_cannot_write_the_entry_record() {
    let fx = Fixture::new();
    let key = fx.key();
    let staged = fx.stage_set(&key);
    std::fs::write(staged.dir().join(ENTRY_RECORD_NAME), b"{}").unwrap();

    let err = fx.cache.publish(staged, &fx.ctx()).unwrap_err();

    assert!(staged_refusal(err).contains("written by the cache"));
}

#[cfg(unix)]
#[test]
fn an_entry_recording_the_release_tier_is_evicted_not_served() {
    let fx = Fixture::new();
    let key = fx.key();
    fx.publish(&key);
    let record = fx.cache.entry_dir(&key).join(ENTRY_RECORD_NAME);
    make_writable(&record);
    let body = std::fs::read_to_string(&record).unwrap();
    assert!(body.contains("\"local-dev\""));
    std::fs::write(
        &record,
        body.replace("\"local-dev\"", "\"verified-release\""),
    )
    .unwrap();

    let reason = expect_evicted(fx.lookup(&key));

    assert!(reason.contains("verified-release"), "{reason}");
    assert!(!fx.cache.entry_dir(&key).exists());
    assert!(matches!(fx.lookup(&key), CacheLookup::Miss));
}

#[cfg(unix)]
#[test]
fn a_tampered_artifact_is_evicted_not_served() {
    let fx = Fixture::new();
    let key = fx.key();
    fx.publish(&key);
    let artifact = fx
        .cache
        .entry_dir(&key)
        .join(kernel_name(GuestArch::Aarch64));
    make_writable(&artifact);
    std::fs::write(&artifact, b"kernel BYTES\n").unwrap();

    expect_evicted(fx.lookup(&key));

    assert!(children(&fx.cache.root().join("v1").join(".evicted")).is_empty());
    // The next run rebuilds and publishes as on any miss.
    assert!(matches!(fx.publish(&key), PublishOutcome::Published(_)));
}

#[test]
fn an_entry_moved_under_another_key_is_evicted() {
    let fx = Fixture::new();
    let kernel = fx.key();
    fx.publish(&kernel);
    let x86 = fx.key_for(&kernel_target(), GuestArch::X86_64);
    std::fs::rename(fx.cache.entry_dir(&kernel), fx.cache.entry_dir(&x86)).unwrap();

    let reason = expect_evicted(fx.lookup(&x86));

    assert!(reason.contains("different key"), "{reason}");
}

#[test]
fn a_publish_over_a_corrupt_entry_replaces_it() {
    let fx = Fixture::new();
    let key = fx.key();
    std::fs::create_dir_all(fx.cache.entry_dir(&key)).unwrap();
    std::fs::write(fx.cache.entry_dir(&key).join("junk"), b"junk").unwrap();

    assert!(matches!(fx.publish(&key), PublishOutcome::Published(_)));
    expect_hit(fx.lookup(&key));
}

#[test]
fn the_default_cache_lives_in_its_own_directory_of_the_mvm_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(tmp.path());

    let cache = LocalImageCache::open_default();

    assert_eq!(
        cache.root(),
        Path::new(&mvm_core::config::mvm_cache_dir()).join(LOCAL_IMAGE_CACHE_DIR)
    );
    assert!(cache.root().starts_with(tmp.path()));
}

#[test]
fn a_key_digest_is_domain_separated() {
    let fx = Fixture::new();
    let key = fx.key();
    let plain = Sha256Hex::from_bytes(&serde_json::to_vec(&key).unwrap());

    assert_ne!(key.digest(), plain);
    assert_eq!(
        fx.cache.entry_dir(&key),
        fx.cache.root().join("v1").join(key.digest().as_str())
    );
}

#[test]
fn a_linked_flake_lock_cannot_key_an_entry() {
    let fx = Fixture::new();
    let lock = fx.images_dir().join("kernel/flake.lock");
    std::fs::remove_file(&lock).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(fx.tmp.path().join("outside.lock"), &lock).unwrap();
    let images = open(&fx.images_dir()).unwrap();

    let err = LocalImageCacheKey::derive(&KeyInputs {
        images: &images,
        mvm_checkout: &fx.mvm(),
        target: &kernel_target(),
        arch: GuestArch::Aarch64,
    })
    .unwrap_err();

    assert!(matches!(err, LocalImageCacheError::Input { .. }), "{err}");
}

#[test]
fn an_mvm_checkout_without_a_toolchain_pin_cannot_key_an_entry() {
    let fx = Fixture::new();
    std::fs::remove_file(fx.mvm().join("rust-toolchain.toml")).unwrap();

    let err = LocalImageCacheKey::derive(&KeyInputs {
        images: &fx.images,
        mvm_checkout: &fx.mvm(),
        target: &kernel_target(),
        arch: GuestArch::Aarch64,
    })
    .unwrap_err();

    assert!(err.to_string().contains("rust-toolchain.toml"), "{err}");
}

#[test]
fn role_names_round_trip_and_unknown_ones_are_refused() {
    for role in ImageBuildRole::ALL {
        assert_eq!(role.name().parse::<ImageBuildRole>().unwrap(), role);
        assert_eq!(
            serde_json::to_string(&role).unwrap(),
            format!("\"{}\"", role.name())
        );
    }
    assert!("builder_vm".parse::<ImageBuildRole>().is_err());
    assert!("".parse::<ImageBuildRole>().is_err());
}

#[test]
fn a_flake_attribute_is_one_plain_segment() {
    for good in [
        "default",
        "sdk-sidecar-image-musl",
        "workload-vmlinux",
        "v1.2",
    ] {
        assert!(FlakeAttr::new(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        ".hidden",
        "a/b",
        "a..b",
        "a b",
        "a#b",
        "-flag",
        &"x".repeat(129),
    ] {
        assert!(FlakeAttr::new(bad).is_err(), "{bad:?}");
    }
    assert!(serde_json::from_str::<FlakeAttr>("\"a/b\"").is_err());
}
