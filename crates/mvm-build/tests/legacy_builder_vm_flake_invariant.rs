//! LegacyBuilderVm must not pull a prebuilt builder VM image from the
//! network.
//!
//! When `mvmctl` runs from a source checkout, every VM image is built
//! locally from the in-repo flakes. The LegacyMacos builder
//! must honour this invariant as strictly as the libkrun builder
//! does: no `reqwest::get`, no `https://github.com/.../releases/`,
//! no "fall back to a prebuilt if the local cache is empty" backdoor.
//!
//! These tests are hermetic source-grep assertions — they read
//! `crates/mvm-build/src/legacy_builder_vm.rs` and check it doesn't contain
//! the forbidden patterns. A future regression where someone adds a
//! download path to LegacyBuilderVm fails here, not silently in
//! production.
//!
//! Both backends route image resolution through
//! [`mvm_build::libkrun_builder::ensure_builder_vm_image`] which
//! reads `~/.cache/mvm/builder-vm/<arch>/{vmlinux,rootfs.ext4,cmdline.txt}`
//! — populated by `nix build ./nix/images/builder-vm` from the
//! in-repo flake. No network code paths are reached.

use std::path::PathBuf;

fn legacy_macos_builder_source() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set in tests");
    let path = PathBuf::from(manifest)
        .join("src")
        .join("legacy_builder_vm.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "expected to read legacy_builder_vm.rs at {} (got {e})",
            path.display(),
        )
    })
}

#[test]
fn legacy_macos_builder_does_not_import_reqwest() {
    // `reqwest` is the workspace's HTTP client; libkrun + LegacyMacos builders
    // are pure local-fs + spawn. Importing reqwest in legacy_macos_builder is
    // a strong "we're about to add a download path" signal.
    let src = legacy_macos_builder_source();
    assert!(
        !src.contains("use reqwest") && !src.contains("reqwest::") && !src.contains("reqwest_"),
        "legacy_builder_vm.rs must not import reqwest (Plan 98 §2.11 / ADR-046 \
         §\"Source-checkout builds never depend on mvm-published artifacts\")"
    );
}

#[test]
fn legacy_macos_builder_does_not_reference_release_download_urls() {
    // The published prebuilt layout lives under
    // `https://github.com/tinylabscom/mvm/releases/download/...`.
    // Hitting it from legacy_macos_builder would mean LegacyMacos is downloading what
    // libkrun builds locally. Refuse.
    let src = legacy_macos_builder_source();
    let forbidden = [
        "github.com/tinylabscom",
        "releases/download",
        "http://",
        "https://",
    ];
    for needle in forbidden {
        assert!(
            !src.contains(needle),
            "legacy_builder_vm.rs must not reference {needle:?} \
             (Plan 98 §2.11 / ADR-046). Removing this assertion is a real \
             scope-creep escalation — go read ADR-046 §\"Why the contributor \
             path doesn't download\" first."
        );
    }
}

#[test]
fn legacy_macos_builder_does_not_define_a_download_function() {
    // A new `fn download_*` / `fn fetch_prebuilt_*` is the obvious
    // shape a future regression would take. Cover it explicitly so
    // grep on the symbol name catches it.
    let src = legacy_macos_builder_source();
    let forbidden = ["fn download_", "fn fetch_prebuilt", "fn pull_prebuilt"];
    for needle in forbidden {
        assert!(
            !src.contains(needle),
            "legacy_builder_vm.rs must not define {needle:?} (Plan 98 §2.11 / ADR-046)"
        );
    }
}

#[test]
fn in_repo_builder_vm_flake_exists_in_source_checkout() {
    // The path `nix/images/builder-vm/flake.nix` is the canonical
    // source the cache-populating `nix build` command points at
    // (per the error message in `ensure_builder_vm_image`). If this
    // file ever moves without updating the error hint, contributors
    // will follow the wrong nix command — and LegacyMacos / libkrun will
    // diverge silently because the hint message lives only in
    // `libkrun_builder.rs`.
    //
    // The test runs from `crates/mvm-build` so the repo root is two
    // levels up.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set in tests");
    let repo_root = PathBuf::from(&manifest)
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root resolvable from CARGO_MANIFEST_DIR")
        .to_path_buf();
    let flake = repo_root
        .join("nix")
        .join("images")
        .join("builder-vm")
        .join("flake.nix");
    assert!(
        flake.is_file(),
        "in-repo builder VM flake missing at {} — both libkrun + LegacyMacos \
         drivers depend on this being the canonical source per \
         ADR-046",
        flake.display()
    );
}

#[test]
fn legacy_macos_builder_image_resolution_goes_through_shared_helper() {
    // Both `LegacyBuilderVm::run_build` and `LegacyPersistentBuilderVm::start`
    // call `ensure_builder_vm_image()` from `libkrun_builder` when
    // the per-driver `image_override` is None. This is the
    // single-entry-point invariant: any future "LegacyMacos pulls a different
    // image source" change would break here.
    let src = legacy_macos_builder_source();
    let call_count = src.matches("ensure_builder_vm_image()").count();
    assert!(
        call_count >= 2,
        "expected `ensure_builder_vm_image()` reachable from both the \
         one-shot driver (LegacyBuilderVm::run_build) and the persistent \
         driver (LegacyPersistentBuilderVm::start); found {call_count} call site(s). \
         Plan 98 §2.11 invariant: both drivers go through the shared \
         helper, no LegacyMacos-specific image resolver."
    );
}
