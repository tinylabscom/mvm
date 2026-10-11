#[path = "support/live_runtime.rs"]
mod live_runtime;

use std::collections::BTreeMap;
use std::fs;

use mvm_build::guest_agent_build::{RUNTIME_OVERLAY_ADDON_BINS, RUNTIME_OVERLAY_SEALED_BINS};
use mvm_build::guest_bins::{GPU_SHIM_CDYLIBS, GuestBinsManifest};
use mvm_build::guest_runtime::GuestRuntime;
use mvm_core::arch::GuestArch;
use sha2::{Digest, Sha256};

fn fixture() -> (tempfile::TempDir, GuestRuntime) {
    let root = tempfile::tempdir().unwrap();
    let arch = GuestArch::host();
    let mut members: Vec<String> = RUNTIME_OVERLAY_SEALED_BINS
        .into_iter()
        .chain(RUNTIME_OVERLAY_ADDON_BINS)
        .map(|name| format!("{arch}/bin/{name}"))
        .collect();
    // Built outside the overlay invocations, staged into the overlay all the same.
    members.push(format!("{arch}/bin/mvm-setpriv"));
    members.push(format!("{arch}/initramfs/mvm-guest-agent"));
    members.push("sdk-py/mvm/__init__.py".into());
    for libc in ["glibc", "musl"] {
        for library in GPU_SHIM_CDYLIBS {
            members.push(format!("{arch}/lib/{libc}/{}", library.soname));
        }
    }
    let mut files = BTreeMap::new();
    for member in members {
        let path = root.path().join(&member);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, member.as_bytes()).unwrap();
        files.insert(
            member.clone(),
            hex::encode(Sha256::digest(member.as_bytes())),
        );
    }
    let runtime = GuestRuntime {
        root: root.path().to_path_buf(),
        digest: "d".repeat(64),
        manifest: GuestBinsManifest {
            schema_version: mvm_build::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
            version: env!("CARGO_PKG_VERSION").into(),
            guest_source_fingerprint: "g".repeat(64),
            sdk_cdylib_source_fingerprint: "s".repeat(64),
            source: mvm_build::image_source::RepoIdentity {
                commit: mvm_core::image_set::GitCommit::new("a".repeat(40)).unwrap(),
                worktree: mvm_core::image_set::WorktreeState::Clean,
            },
            files,
        },
    };
    (root, runtime)
}

#[test]
fn prepared_live_fixture_resolves_both_artifacts_from_its_own_cache() {
    let (_source, runtime) = fixture();
    let home = tempfile::tempdir().unwrap();
    let cache = home.path().join("cache");
    let (overlay, initramfs) = live_runtime::prepare(&cache, &runtime).unwrap();
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let resolver = mvm_fs::overlay::RuntimeOverlayResolver::new(cache.clone(), version.into());
    assert_eq!(
        resolver.resolve(&arch.to_string()).unwrap().overlay_ext4,
        overlay.overlay_ext4
    );
    assert_eq!(
        mvm_fs::initramfs::InitramfsResolver::new(cache.join("initramfs"), version)
            .resolve(&arch.to_string())
            .unwrap()
            .image_path,
        initramfs.image_path
    );
    assert!(overlay.overlay_ext4.starts_with(&cache));
    assert!(initramfs.image_path.starts_with(&cache));
}

#[test]
fn live_fixture_refuses_a_tampered_overlay_member() {
    let (_source, runtime) = fixture();
    let member = format!("{}/bin/mvm-guest-agent", GuestArch::host());
    fs::write(runtime.root.join(member), b"changed").unwrap();
    let home = tempfile::tempdir().unwrap();
    let error = live_runtime::prepare(&home.path().join("cache"), &runtime).unwrap_err();
    assert!(
        error.to_string().contains("changed while staging"),
        "{error:#}"
    );
}

#[test]
fn live_fixture_refuses_missing_or_tampered_pid_one_before_overlay_assembly() {
    for tamper in [false, true] {
        let (_source, mut runtime) = fixture();
        let member = format!("{}/initramfs/mvm-guest-agent", GuestArch::host());
        if tamper {
            fs::write(runtime.root.join(&member), b"changed").unwrap();
        } else {
            runtime.manifest.files.remove(&member);
        }
        let home = tempfile::tempdir().unwrap();
        let cache = home.path().join("cache");
        let error = live_runtime::prepare(&cache, &runtime).unwrap_err();
        assert!(
            error.to_string().contains(if tamper {
                "changed while packing"
            } else {
                "does not contain"
            }),
            "{error:#}"
        );
        assert!(
            !cache.exists(),
            "failed admission must not prepare an overlay"
        );
    }
}
