//! Sealing, verifying, and installing a bundle hold an artifact in a fixed
//! buffer, not in memory whole.
//!
//! A counting allocator records the peak heap in use while each phase runs
//! over a bundle whose rootfs is many times the allowed peak. A phase that
//! read the rootfs into a `Vec` would cross the bound by the rootfs's size.
//! This binary holds one test so no other test's allocations share the count.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, BundlePayload,
    BundleRegistry, KeyId, TrustStore, key_id_from_pubkey, verify_bundle_file, write_bundle_to,
};

struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = IN_USE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this `layout`.
        unsafe { System.dealloc(ptr, layout) };
        IN_USE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `phase` and return how far the heap rose above where it started.
fn peak_growth<T>(phase: impl FnOnce() -> T) -> (T, usize) {
    let base = IN_USE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = phase();
    (out, PEAK.load(Ordering::SeqCst).saturating_sub(base))
}

const ROOTFS_BYTES: u64 = 96 * 1024 * 1024;
const PEAK_BOUND: usize = 8 * 1024 * 1024;

struct OneKey(VerifyingKey);

impl TrustStore for OneKey {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        (*key_id == key_id_from_pubkey(&self.0)).then_some(self.0)
    }
}

/// Write `size` bytes of a repeating pattern without holding them.
fn write_pattern(path: &Path, size: u64) {
    let mut file = File::create(path).expect("create rootfs");
    let chunk: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut left = size;
    while left > 0 {
        let n = left.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..n]).expect("write rootfs");
        left -= n as u64;
    }
}

fn declared(name: &str, role: ArtifactRole, path: &Path) -> BundleArtifact {
    BundleArtifact {
        name: name.to_string(),
        role,
        path: format!("artifacts/{name}"),
        sha256: sha256_file(path).expect("hash artifact"),
        size_bytes: std::fs::metadata(path).expect("stat artifact").len(),
    }
}

#[test]
fn sealing_verifying_and_installing_a_large_bundle_stay_within_a_fixed_heap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs.ext4");
    let kernel = dir.path().join("vmlinux");
    write_pattern(&rootfs, ROOTFS_BYTES);
    std::fs::write(&kernel, b"kernel").expect("write kernel");

    let key = SigningKey::from_bytes(&[21; 32]);
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "memory-test".to_string(),
        key_id: key_id_from_pubkey(&key.verifying_key()),
        arch: "x86_64".to_string(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts: vec![
            declared("vmlinux", ArtifactRole::Kernel, &kernel),
            declared("rootfs.ext4", ArtifactRole::Rootfs, &rootfs),
        ],
        members: Vec::new(),
        verity: None,
        resources: None,
    };
    let archive = dir.path().join("big.mvmpkg");
    let trust = OneKey(key.verifying_key());

    let (sealed, seal_peak) = peak_growth(|| {
        write_bundle_to(
            &manifest,
            &key,
            vec![
                (
                    "artifacts/vmlinux".to_string(),
                    BundlePayload::File(kernel.clone()),
                ),
                (
                    "artifacts/rootfs.ext4".to_string(),
                    BundlePayload::File(rootfs.clone()),
                ),
            ],
            File::create(&archive).expect("create archive"),
        )
    });
    sealed.expect("seal");

    let (verified, verify_peak) = peak_growth(|| verify_bundle_file(&archive, &trust));
    let verified = verified.expect("verify");
    assert_eq!(verified.manifest, manifest);

    let registry = BundleRegistry::new(dir.path().join("registry"));
    let (installed, install_peak) = peak_growth(|| registry.install_file(&archive, &trust, false));
    let installed = installed.expect("install");
    assert_eq!(
        std::fs::metadata(installed.root.join("artifacts/rootfs.ext4"))
            .expect("installed rootfs")
            .len(),
        ROOTFS_BYTES
    );

    let peaks = HashMap::from([
        ("seal", seal_peak),
        ("verify", verify_peak),
        ("install", install_peak),
    ]);
    for (phase, peak) in &peaks {
        assert!(
            *peak < PEAK_BOUND,
            "{phase} peaked at {peak} heap bytes over a {ROOTFS_BYTES}-byte rootfs; bound {PEAK_BOUND}"
        );
    }
}
