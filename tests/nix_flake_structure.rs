//! Structural guard for `nix/flake.nix` and `nix/profiles/*.nix`
//! (Phase 1 W4 — plan 60).
//!
//! These tests don't run `nix flake check` (that requires Nix on the
//! test host and adds a network dep on github:microvm-nix/microvm.nix).
//! Instead they assert the flake's *shape* — the file is present, has
//! the expected top-level inputs/outputs, and references the
//! microvm.nix module by hash-pinned input. A regression that
//! deletes the flake or removes the microvm.nix dependency trips
//! these tests on every PR's `cargo test`.
//!
//! For full evaluation, run on a host with Nix:
//!
//!   cd nix && nix flake check --no-build
//!
//! Documented in `specs/runbooks/cross-platform-install.md` (Phase 5).

use std::fs;
use std::path::{Path, PathBuf};

fn nix_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests");
    PathBuf::from(manifest).join("nix")
}

fn repo_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests");
    PathBuf::from(manifest)
}

fn normalized_whitespace(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn every_rust_derivation_uses_the_static_crates_registry() {
    let helper = nix_dir().join("lib").join("static-crates-cargo-lock.nix");
    let helper_content = fs::read_to_string(&helper)
        .unwrap_or_else(|e| panic!("static crate registry helper must be present: {e}"));

    assert!(
        helper_content.contains("https://github.com/rust-lang/crates.io-index")
            && helper_content.contains("https://static.crates.io/crates"),
        "the cargo-lock helper must redirect the crates.io index to its static CDN"
    );

    let mut nix_files = Vec::new();
    collect_nix_files(&nix_dir(), &mut nix_files);
    let mut rust_derivations = 0;
    for path in nix_files {
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
        if !content.contains("rustPlatform.buildRustPackage {") {
            continue;
        }
        rust_derivations += 1;
        assert!(
            content.contains("static-crates-cargo-lock.nix"),
            "{} builds Rust without the static crates.io registry helper",
            path.display()
        );
    }

    assert!(
        rust_derivations > 0,
        "expected at least one Rust Nix derivation"
    );
}

fn collect_nix_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in
        fs::read_dir(dir).unwrap_or_else(|e| panic!("{} must be readable: {e}", dir.display()))
    {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_nix_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("nix") {
            files.push(path);
        }
    }
}

#[test]
fn flake_nix_exists_and_imports_microvm_nix() {
    let path = nix_dir().join("flake.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("nix/flake.nix must be present: {e}"));

    // ADR-004 invariant: the flake imports microvm.nix as the foundation.
    // Any future PR that drops this input violates the ADR.
    assert!(
        content.contains("microvm-nix/microvm.nix"),
        "nix/flake.nix must reference microvm-nix/microvm.nix as an input \
         (per ADR-004); content excerpt: {}",
        &content[..content.len().min(200)]
    );

    // The flake must declare nixosConfigurations — that's how
    // microvm.nix's NixOS module composition works. A regression
    // that drops this would silently produce a flake with no
    // buildable output.
    assert!(
        content.contains("nixosConfigurations"),
        "nix/flake.nix must declare nixosConfigurations to expose the \
         microvm.nix-built test fixtures"
    );

    // The user-facing library output. User flakes consume
    // `mvm.lib.<system>.mkGuest`; if that path stops being exposed,
    // every user project breaks at next nix evaluation. Guarding it
    // here means a refactor of the flake can't accidentally drop
    // the user contract.
    assert!(
        content.contains("lib") && content.contains("mkGuest"),
        "nix/flake.nix must expose lib.<system>.mkGuest as the \
         user-facing API (per ADR-004 + plan 60). Got: ...{}",
        &content[..content.len().min(200)]
    );

    // Internal-prefix convention: test fixtures live under
    // `internal-*` so the boundary between user-facing and mvm-
    // internal is mechanical. A regression that exposes a fixture
    // under a bare name (without the prefix) is a UX-leak waiting
    // to happen.
    assert!(
        content.contains("internal-minimal"),
        "nix/flake.nix must expose internal fixtures under the \
         internal-* namespace; bare names suggest user-facing API"
    );
}

#[test]
fn flake_exposes_source_built_host_package_without_changing_mk_guest_contract() {
    let path = nix_dir().join("flake.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("nix/flake.nix must be present: {e}"));

    assert!(
        content.contains("overlays.default"),
        "nix/flake.nix must expose the source-built host package overlay"
    );
    assert!(
        content.contains("hostSystems")
            && content.contains("\"aarch64-darwin\"")
            && content.contains("\"x86_64-linux\""),
        "nix/flake.nix must separate host package systems from Linux-only image systems"
    );
    assert!(
        content.contains("mvmctl = hostPackages.mvmctl")
            && content.contains("default = hostPackages.mvmctl"),
        "nix/flake.nix must expose packages.<system>.mvmctl and make it the default package"
    );
    assert!(
        content.contains("lib = forAllSystems"),
        "the user-facing mkGuest library must remain restricted to the Linux image systems"
    );
}

#[test]
fn host_mvmctl_package_is_source_only() {
    let path = nix_dir().join("packages").join("mvmctl.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/packages/mvmctl.nix must be present: {e}"));

    assert!(
        content.contains("rustPlatform.buildRustPackage"),
        "mvmctl package must build from source with rustPlatform.buildRustPackage"
    );
    assert!(
        content.contains("src = mvmSrc")
            && content.contains("static-crates-cargo-lock.nix")
            && content.contains("lockFile = mvmSrc + \"/Cargo.lock\""),
        "mvmctl package must use the source checkout and committed Cargo.lock"
    );
    assert!(
        content.contains("unpackPhase")
            && content.contains("cp -R ${mvmSrc}/. source")
            && content.contains("sourceRoot=source"),
        "mvmctl package must normalize the path:.. workspace source before buildRustPackage unpacks it"
    );
    assert!(
        content.contains("\"--package\"") && content.contains("\"mvmctl\""),
        "mvmctl package must explicitly build the root CLI package"
    );
    assert!(
        content.contains("cargo-zigbuild") && content.contains("lld") && content.contains("zig"),
        "mvmctl package must provide the zigbuild and LLD toolchain required by embedded binaries and audited links"
    );
    assert!(
        content.contains("embeddedCargo")
            && content.contains("embeddedRustc")
            && content.contains("MVM_EMBED_CARGO")
            && content.contains("MVM_EMBED_RUSTC"),
        "mvmctl package must pass explicit musl-target Rust tools to the embedded-binary build"
    );
    assert!(
        content.contains("nativeCheckInputs") && content.contains("curl"),
        "mvmctl package must provide install.sh test tools during Nix checkPhase"
    );
    assert!(
        content.contains("auditable = !withNativeLibkrun"),
        "only the native-libkrun package may disable cargo-auditable for the package-qualified feature set"
    );

    let forbidden = [
        "fetchurl",
        "fetchzip",
        "releases/download",
        "github.com/tinylabscom/mvm/releases",
        "binaryNativeCode",
    ];
    for needle in forbidden {
        assert!(
            !content.contains(needle),
            "nix/packages/mvmctl.nix must not use {needle:?}; host packages \
             must be source-built rather than project-published binaries"
        );
    }
}

#[test]
fn host_mvmctl_package_keeps_native_vmm_linkage_explicit() {
    let path = nix_dir().join("packages").join("mvmctl.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/packages/mvmctl.nix must be present: {e}"));

    assert!(
        content.contains("withNativeLibkrun ? false"),
        "native libkrun FFI must be opt-in in the host package"
    );
    assert!(
        content.contains("assert withNativeLibkrun -> libkrun != null"),
        "enabling native libkrun FFI must require an explicit Nix libkrun package"
    );
    assert!(
        content.contains("assert withNativeLibkrun -> libkrunfw != null"),
        "enabling native libkrun FFI must require an explicit Nix libkrunfw package"
    );
    assert!(
        content.contains("assert withNativeLibkrun -> withBuilderVm")
            && content.contains("\"mvm-cli/builder-vm\"")
            && content.contains("\"mvm-build/builder-vm\""),
        "feature flags must stay package-qualified when mvmctl and sidecars build together"
    );
    assert!(
        content.contains("lib.optionals withTpm2 [ \"mvmctl/attestation-tpm2\" ]"),
        "TPM2 must forward through the root package so cargo-auditable can resolve the feature"
    );
    assert!(
        content.contains("\"mvm-cli/libkrun-sys\"")
            && content.contains("\"mvm-hostd/libkrun-sys\""),
        "the native libkrun feature must enable both CLI probing and the supervisor binary"
    );
    assert!(
        content.contains("MVM_LIBKRUN_HEADER"),
        "the Nix package must pass an explicit libkrun.h path to bindgen"
    );
    assert!(
        content.contains("lib.optionals withNativeLibkrun") && content.contains("libkrunfw"),
        "the Nix package must link libkrunfw explicitly; libkrun does not propagate it"
    );
}

#[test]
fn native_vmm_recipes_are_source_built_and_pinned() {
    let packages_dir = nix_dir().join("packages");
    let libkrunfw = fs::read_to_string(packages_dir.join("libkrunfw.nix"))
        .unwrap_or_else(|e| panic!("nix/packages/libkrunfw.nix must be present: {e}"));
    let libkrun = fs::read_to_string(packages_dir.join("libkrun.nix"))
        .unwrap_or_else(|e| panic!("nix/packages/libkrun.nix must be present: {e}"));
    let kernel_base = fs::read_to_string(nix_dir().join("images/kernel/base.nix"))
        .unwrap_or_else(|e| panic!("nix/images/kernel/base.nix must be present: {e}"));

    for (name, content) in [
        ("libkrunfw.nix", libkrunfw.as_str()),
        ("libkrun.nix", libkrun.as_str()),
    ] {
        assert!(
            content.contains("stdenv.mkDerivation"),
            "nix/packages/{name} must use a source-built derivation"
        );
        assert!(
            content.contains("owner = \"libkrun\"")
                && content.contains("tag = \"v${finalAttrs.version}\"")
                && content.contains("hash = \"sha256-"),
            "nix/packages/{name} must fetch pinned upstream source by tag and hash"
        );
        assert!(
            !content.contains("github.com/tinylabscom/mvm/releases")
                && !content.contains("binaryNativeCode"),
            "nix/packages/{name} must not use mvm release binaries"
        );
    }

    const KERNEL_VERSION: &str = "6.12.105";
    const KERNEL_HASH: &str = "sha256-6zaAHhGVKbE1E8NFncIOKjL3BTYp86q7Y+pQGk2I9j0=";
    assert!(
        libkrunfw.contains(&format!("linux-{KERNEL_VERSION}.tar.xz"))
            && libkrunfw.contains(&format!("hash = \"{KERNEL_HASH}\""))
            && libkrunfw.contains("KERNEL_REMOTE")
            && libkrunfw.contains(&format!(
                "'KERNEL_VERSION = linux-6.12.91' 'KERNEL_VERSION = linux-{KERNEL_VERSION}'"
            ))
            && libkrunfw.contains("ln -s ${kernelSrc} $(KERNEL_TARBALL)")
            && libkrunfw.contains("'virtio_transport_alloc_skb(&info, dgram_len, false, NULL,'"),
        "libkrunfw must pin the kernel version, substitute the source, and keep its datagram patch compatible with that kernel"
    );
    assert!(
        kernel_base.contains(&format!("kernelVersion = \"{KERNEL_VERSION}\""))
            && kernel_base.contains(&format!("hash = \"{KERNEL_HASH}\"")),
        "the custom kernel must use the same verified point-release pin as libkrunfw"
    );
    assert!(
        libkrun.contains("rustPlatform.fetchCargoVendor")
            && libkrun.contains("hash = \"sha256-dfIe2pl957MRcY1hIv6wPPX/4He+ou+eCZLbylVeGAE=\""),
        "libkrun must carry a verified Cargo vendor hash"
    );
    assert!(
        libkrun.contains("withBlk ? true")
            && libkrun.contains("withNet ? true")
            && libkrun.contains("\"BLK=1\"")
            && libkrun.contains("\"NET=1\""),
        "mvm's native libkrun recipe must build virtio-block and virtio-net support by default"
    );
}

#[test]
fn native_vmm_outputs_stay_optional_and_non_default() {
    let packages = fs::read_to_string(nix_dir().join("packages").join("default.nix"))
        .unwrap_or_else(|e| panic!("nix/packages/default.nix must be present: {e}"));
    let flake = fs::read_to_string(nix_dir().join("flake.nix"))
        .unwrap_or_else(|e| panic!("nix/flake.nix must be present: {e}"));

    assert!(
        packages.contains("nativeVmmPackages")
            && packages.contains("pkgs.stdenv.hostPlatform.isLinux"),
        "native VMM packages must be exposed only for Linux host package sets"
    );
    assert!(
        packages.contains("embeddedRustTarget")
            && packages.contains("aarch64-unknown-linux-musl")
            && packages.contains("x86_64-unknown-linux-musl")
            && packages.contains("embeddedRustToolchain")
            && packages.contains("./embedded-rust-toolchain.nix")
            && packages.contains("pkgs.rust_1_91.packages.prebuilt.cargo")
            && packages.contains("pkgs.rust_1_91.packages.prebuilt.rustc")
            && packages.contains("embeddedCargo = embeddedRustToolchain")
            && packages.contains("embeddedRustc = embeddedRustToolchain"),
        "host packages must use the pinned musl std Rust wrapper for real embedded host binaries"
    );
    assert!(
        packages.contains("mvmctl-native-libkrun = mvmctl.override")
            && packages.contains("withNativeLibkrun = true")
            && packages.contains("inherit libkrun libkrunfw"),
        "the native mvmctl package must consume the explicit libkrun/libkrunfw override seam"
    );
    assert!(
        flake.contains("default = hostPackages.mvmctl")
            && flake.contains("mvmctl-native-libkrun")
            && !flake.contains("default = hostPackages.mvmctl-native-libkrun"),
        "packages.default must remain the non-native mvmctl package"
    );
    assert!(
        flake.contains("final.stdenv.hostPlatform.isLinux")
            && flake.contains("inherit (hostPackages) libkrun libkrunfw mvmctl-native-libkrun"),
        "the host overlay must expose native VMM packages only on Linux"
    );
}

#[test]
fn embedded_rust_toolchain_pins_musl_std_components() {
    let path = nix_dir()
        .join("packages")
        .join("embedded-rust-toolchain.nix");
    let content = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("nix/packages/embedded-rust-toolchain.nix must be present: {e}")
    });

    assert!(
        content.contains("rust-std-${version}-${target}.tar.gz")
            && content.contains("sha256-W95G9gKLSyz+ogTZiIt93mYDG3eKuEtoXrUjQ1kpt7U=")
            && content.contains("sha256-fcoP5fERdHCAB+tTVG6pWq2MN9/Ww8sGTF8cZS7WsPI="),
        "embedded Rust toolchain must pin official musl std components for both supported host arches"
    );
    assert!(
        content.contains("--sysroot=$out")
            && content.contains("--target ${target} --print target-libdir"),
        "embedded Rust toolchain must wrap rustc with a target-aware sysroot and validate it"
    );
}

#[test]
fn mk_guest_rejects_ssh_template_inputs_structurally() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("mk-guest.nix must be present: {e}"));

    for needle in [
        "assertNoSshTemplateInputs",
        "SSH is banned in microVM templates",
        "openssh",
        "sshpass",
        "sshfs",
        "autossh",
        "authorized_keys",
        "known_hosts",
        "closureInfo",
        "SSH-related Nix store paths are banned",
        "sshTemplateBan",
    ] {
        assert!(
            content.contains(needle),
            "mkGuest must keep the SSH template-input ban marker {needle:?}"
        );
    }

    let extra_files_arg = content
        .find(", extraFiles     ? { }")
        .expect("mkGuest must bind the extraFiles argument");
    let extra_file_label = content
        .find("extraFileLabel = path:")
        .expect("mkGuest must inspect extraFiles for SSH material");
    assert!(
        extra_file_label > extra_files_arg,
        "extraFiles-dependent SSH ban helpers must stay inside the mkGuest argument scope"
    );
    assert!(
        !content.contains("(ssh|openssh|dropbear)"),
        "closure-level SSH ban must not match library names such as libssh2"
    );
}

#[test]
fn installation_docs_keep_host_nix_optional() {
    let path = repo_dir()
        .join("public")
        .join("src")
        .join("content")
        .join("docs")
        .join("getting-started")
        .join("installation.md");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("installation guide must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    assert!(
        content.contains("## Optional Nix Package"),
        "the Nix install path must be explicitly documented as optional"
    );
    assert!(
        normalized.contains("mvm does not require Nix on the host for normal use")
            && normalized.contains("You don't need Nix on the host"),
        "installation docs must preserve the no-host-Nix default UX"
    );
    assert!(
        content.contains("Linux image builds still\nrun inside the builder VM"),
        "installation docs must keep Linux Nix work assigned to the builder VM"
    );
}

#[test]
fn installation_docs_keep_binary_install_primary() {
    let path = repo_dir()
        .join("public")
        .join("src")
        .join("content")
        .join("docs")
        .join("getting-started")
        .join("installation.md");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("installation guide must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    assert!(
        content.contains("The default install model is binary-first"),
        "installation docs must lead with the release-binary install model"
    );
    assert!(
        content.contains("mvmctl run --image alpine -- uname -a"),
        "installation docs must show the current image-backed one-shot path"
    );
    assert!(
        normalized.contains("future package-manager expression installs release binaries")
            && normalized.contains("separate from this source-built package"),
        "installation docs must keep release-binary packaging separate from source-built Nix"
    );
}

#[test]
fn quickstart_docs_lead_with_image_backed_run() {
    let path = repo_dir()
        .join("public")
        .join("src")
        .join("content")
        .join("docs")
        .join("getting-started")
        .join("quickstart.md");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("quickstart must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    let image_heading = content
        .find("## 1. Run an OCI Image")
        .expect("quickstart must lead with an OCI image run section");
    let builder_heading = content
        .find("## 2. Prepare the Builder VM")
        .expect("quickstart must still document the builder VM after the image path");

    assert!(
        image_heading < builder_heading,
        "quickstart must put the image-backed one-shot path before the builder/flake workflows"
    );
    assert!(
        content.contains("mvmctl machine run --image alpine -- uname -a")
            && normalized.contains("You do not need host Nix for this path"),
        "quickstart must preserve the no-host-Nix image-backed command"
    );
}

#[test]
fn happy_paths_include_oci_image_audience() {
    let path = repo_dir()
        .join("public")
        .join("src")
        .join("content")
        .join("docs")
        .join("getting-started")
        .join("happy-paths.md");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("happy paths must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    assert!(
        content.contains("mvm has six primary audiences"),
        "happy paths must count the OCI-image path as a first-class audience"
    );
    assert!(
        content.contains("CLI user with an OCI image")
            && content.contains("mvmctl run --image alpine -- uname -a")
            && normalized.contains("Image-backed one-shot runs do not require host Nix"),
        "happy paths must document the image-backed no-host-Nix audience"
    );
}

#[test]
fn minimal_profile_exists_and_has_required_settings() {
    let path = nix_dir().join("profiles").join("minimal.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/profiles/minimal.nix must be present: {e}"));

    // SSH disabled — load-bearing invariant from ADR-001 / CLAUDE.md
    // ("No SSH in microVMs, ever"). Asserted as plain string match
    // because a NixOS module's effective `services.openssh.enable`
    // can only be checked by evaluating the flake; the source line
    // is the closest we can get without booting Nix.
    assert!(
        content.contains("services.openssh.enable = false"),
        "minimal profile must explicitly disable SSH per ADR-001"
    );

    // The microvm.hypervisor must be declared — that's what
    // selects the runner. Even if it's `firecracker` (the default),
    // the explicit declaration makes the profile self-documenting.
    assert!(
        content.contains("microvm.hypervisor") || content.contains("hypervisor"),
        "minimal profile must declare a microvm.hypervisor (defaults \
         to firecracker per ADR-004)"
    );

    // system.stateVersion is mandatory for any NixOS module — a
    // missing one breaks evaluation. Guard it explicitly so the
    // failure mode is "this test fails" rather than "nix flake
    // check is the only way to find out."
    assert!(
        content.contains("system.stateVersion"),
        "minimal profile must declare system.stateVersion (NixOS \
         module evaluation requirement)"
    );
}

/// Optional: shell out to `nix eval` against `nix/tests/mk-guest-eval.nix`
/// and assert every check returns true. Skipped silently when `nix`
/// isn't on PATH (most macOS dev hosts) so this test stays cheap on
/// every PR; CI runners with Nix exercise the real eval.
///
/// This is the strongest guard we have on the user-facing
/// `lib.<system>.mkGuest` surface — it actually invokes the function
/// with each of the three entrypoint shapes (`shell` / `command` /
/// `services`) plus the explicit `dev` overrides, and asserts the
/// `passthru.mvm.{accessible, sealed, entrypointKind}` metadata is
/// inferred correctly.
#[test]
fn mk_guest_eval_assertions_all_pass_when_nix_available() {
    use std::process::Command;

    // Skip when nix isn't on PATH. Cheap precondition — a single
    // process spawn per skipped test.
    let nix_check = Command::new("nix").arg("--version").output();
    if nix_check.is_err() {
        eprintln!("[nix_flake_structure::mk_guest_eval] skipped — `nix` not on PATH");
        return;
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests");
    let eval_file = std::path::PathBuf::from(&manifest)
        .join("nix")
        .join("tests")
        .join("mk-guest-eval.nix");

    let out = Command::new("nix")
        .arg("--extra-experimental-features")
        .arg("nix-command flakes")
        .arg("eval")
        .arg("--json")
        .arg("--file")
        .arg(&eval_file)
        .output()
        .expect("nix eval invocation");

    assert!(
        out.status.success(),
        "nix eval failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The eval file returns an attribute set of named boolean
    // assertions. Parse the JSON and verify every value is `true`.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("nix eval output isn't JSON: {e}\nstdout: {stdout}"));
    let obj = json
        .as_object()
        .expect("mk-guest-eval.nix must return an attribute set");

    let mut failures: Vec<String> = Vec::new();
    for (name, value) in obj {
        match value.as_bool() {
            Some(true) => { /* ok */ }
            Some(false) => failures.push(format!("{name} = false")),
            None => failures.push(format!("{name} not a bool")),
        }
    }
    assert!(
        failures.is_empty(),
        "mkGuest eval assertions failed: {}\nFull output: {stdout}",
        failures.join(", ")
    );
}

/// Plan 74 W1.4b (ADR-018) — `mkGuest` must carry the overlay-
/// aware contract in its rootfs + /init script. We can't easily
/// build the rootfs without Nix on the host, but the source of
/// truth is a single file we can scan for the three load-bearing
/// signals. A regression that removes any of them surfaces as a
/// failing test on every PR's `cargo test`, before the overlay
/// boot regression is observable in a live VM.
///
/// What gets checked:
/// 1. The rootfs tree creates `/mvm/runtime` (the bind-mount
///    target). Without this, the verity-init bind-mount fails at
///    boot and the agent never starts.
/// 2. The /init script prefers `/mvm/runtime/agent` over the
///    baked-in copy. Without this, the overlay-attached agent
///    isn't used.
/// 3. The mvmMeta passthru carries `overlayAware = true`. Without
///    this, admission-time gates can't enforce overlay-aware
///    rootfs as a precondition.
/// 4. The mvmMeta passthru carries `runtimeLean = true`. mkGuest bakes
///    no guest-runtime binaries into any rootfs, so every image is
///    runtime-lean; the required-overlay admission gate reads this to
///    refuse a rootfs that could silently degrade to a baked fallback.
#[test]
fn mk_guest_carries_overlay_aware_contract() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("mkdir -p \"$out/mvm/runtime\""),
        "mk-guest.nix must create /mvm/runtime in the rootfs as the \
         ADR-018 bind-mount target. Missing the `mkdir -p \"$out/mvm/runtime\"` \
         line means the verity-init bind-mount target is missing and the \
         agent never starts."
    );

    assert!(
        content.contains("/mvm/runtime/agent"),
        "mk-guest.nix /init must reference /mvm/runtime/agent (ADR-018). \
         Without this resolution path the overlay-attached agent isn't \
         exec'd and the rootfs falls back to the baked-in copy on every \
         boot — defeating the W1.4b refactor."
    );

    assert!(
        content.contains("overlayAware = true"),
        "mk-guest.nix mvmMeta passthru must declare `overlayAware = true` \
         (Plan 74 W1.4b / ADR-018). Admission-time gates read this to \
         refuse boot of cached pre-W1.4b templates."
    );

    assert!(
        content.contains("mvm\\.chain_init=") && content.contains("exec \"$MVM_CHAIN_INIT\""),
        "mk-guest.nix /init must support the builder-only chained-init \
         handoff so the builder image can bootstrap through the generic \
         busybox /init path before entering mvm-host-vm-init."
    );
    assert!(
        content.contains("runtimeLean = true;"),
        "mk-guest.nix must surface `passthru.mvm.runtimeLean = true` for every \
         image: mkGuest bakes no guest-runtime binaries, so the required-overlay \
         admission gate can rely on the runtime-lean claim being universal."
    );
    assert!(
        !content.contains("$out/usr/local/bin/mvm-guest-agent"),
        "mk-guest.nix must not bake the guest-runtime binaries into the rootfs \
         tree ($out/usr/local/bin); the agent (and netinit/addon-dns/exit-report/\
         egress-client) are sourced from the runtime overlay at /mvm/runtime. The \
         /init resolution ladders may still name the runtime `/usr/local/bin` path \
         for rootfs-only / prefer-overlay boots, but nothing is cp'd there."
    );

    let builder_path = nix_dir()
        .join("images")
        .join("builder-vm")
        .join("flake.nix");
    let builder = fs::read_to_string(&builder_path)
        .unwrap_or_else(|e| panic!("nix/images/builder-vm/flake.nix must be present: {e}"));
    assert!(
        builder.contains(
            "builderCmdline = \"console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\";"
        ),
        "builder-vm flake must bake the hardened builder rootfs cmdline \
         (rootfstype=ext4 + rootwait + panic=-1 + loglevel=8 + chained \
         builder init) so every backend starts from the same disk-builder \
         boot contract."
    );
}

/// Render the `initText = ''…''` block of `mk-guest.nix` the way Nix
/// renders an indented string: strip the common indentation, which Nix
/// derives from the *least*-indented line that carries content.
fn rendered_init_text(content: &str) -> String {
    let open = "  initText = ''\n";
    let start = content
        .find(open)
        .expect("mk-guest.nix must bind the /init body to `initText`")
        + open.len();
    let rest = &content[start..];
    let end = rest
        .find("\n  '';\n")
        .expect("the `initText` block must be closed by a `'';` at two-space indentation");

    let body = &rest[..end];
    let baseline = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start_matches(' ').len())
        .min()
        .expect("the /init body is not empty");

    body.lines()
        .map(|line| {
            if line.len() >= baseline {
                &line[baseline..]
            } else {
                ""
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The kernel `exec()`s `/init` directly, so `#!` must be the first two
/// bytes of the file. Nix takes an indented string's baseline from its
/// least-indented line, so one line indented less than its neighbours
/// shifts every other line — the shebang included — one column right, and
/// the guest dies with `Kernel panic … Requested init /init failed (error
/// -8)` before any userspace runs.
///
/// This asserts the rendered bytes rather than the source spelling. An
/// earlier revision asserted a literal source substring instead, which
/// stayed green while the emitted `/init` shipped a leading space for two
/// releases.
#[test]
fn mk_guest_init_shebang_lands_at_byte_zero() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    let rendered = rendered_init_text(&content);
    let first = rendered.lines().next().unwrap_or_default();
    assert_eq!(
        first, "#!/bin/sh",
        "the rendered /init must open with the shebang at byte 0, got {first:?}. \
         Some line in the `initText` block of nix/lib/mk-guest.nix is indented \
         less than the rest, which moves the whole script right and makes the \
         built rootfs unbootable (ENOEXEC)."
    );
}

/// `mkGuest`'s `/init` must resolve `mvm-guest-netinit` from the
/// runtime overlay before forking the agent. Without this, the
/// guest-side defense (kernel blackhole routes for
/// `MANDATORY_DENY_RANGES`) never installs, leaving the guest with
/// no firewall at all. The source-grep here catches a regression
/// that drops the /init invocation before it reaches a live VM boot.
#[test]
fn mk_guest_installs_netinit_at_boot() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("/mvm/runtime/netinit"),
        "mk-guest.nix /init must resolve the netinit binary from the \
         runtime-overlay path (`/mvm/runtime/netinit`). A drop here means \
         guest-side network defense never runs at boot, leaving the guest \
         with no kernel-level defense against IMDS exfil."
    );

    assert!(
        content.contains(
            "echo \"mvm-init: runtime overlay required but /mvm/runtime/netinit is missing\""
        ),
        "mk-guest.nix /init netinit ladder must fail closed under \
         required_overlay when the overlay binary is absent, matching the \
         agent/egress-client ladders — never silently boot without netinit."
    );

    assert!(
        content.contains("/mvm/runtime/egress-client"),
        "mk-guest.nix /init must prefer the runtime-overlay path \
         (`/mvm/runtime/egress-client`) for the vsock egress shim on \
         overlay-backed boots."
    );
}

#[test]
fn mk_guest_assigns_ipv4_loopback_before_starting_guest_services() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));
    let address = content
        .find("ip addr replace 127.0.0.1/8 dev lo")
        .expect("guest init assigns the canonical IPv4 loopback address");
    let agent = content
        .find("# Stage 2.5 — guest agent supervisor")
        .expect("guest init starts the guest agent");

    assert!(
        address < agent,
        "loopback must have an address before any guest service binds it"
    );
    assert!(
        content.contains("ifconfig lo 127.0.0.1 netmask 255.0.0.0 up"),
        "the no-ip-applet fallback must assign the same address"
    );
}

#[test]
fn mk_guest_starts_the_forward_proxy_before_dropping_privileges() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));
    let proxy_start = content
        .find("# Stage 2.49 — loopback forward proxy")
        .expect("guest init starts the forward proxy");
    let agent_start = content[proxy_start..]
        .find("# Stage 2.5 — guest agent supervisor")
        .map(|offset| proxy_start + offset)
        .expect("the unprivileged guest agent starts after the forward proxy");
    let proxy_block = &content[proxy_start..agent_start];

    assert!(
        proxy_block.contains("/mvm/runtime/forward-proxy")
            && proxy_block.contains("/usr/local/bin/mvm-forward-proxy"),
        "both runtime-source policies must resolve the privileged helper"
    );
    assert!(
        proxy_block.contains("/bin/busybox setsid \"$MVM_FORWARD_PROXY_BIN\" &"),
        "the init-owned process must start the proxy directly"
    );
    assert!(
        !proxy_block.contains("mvm-setpriv"),
        "the proxy reads the root-only FlowMux key and must not inherit the workload uid"
    );
}

#[test]
fn mk_guest_provisions_vsock_egress_identity_before_privilege_drop() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));
    let egress_start = content
        .find("# Stage 2.6 — vsock egress shim")
        .expect("vsock egress init block starts");
    let agent_start = content[egress_start..]
        .find("# Stage 2.5 — guest agent supervisor")
        .map(|offset| egress_start + offset)
        .expect("guest agent init block follows egress");
    let egress_block = &content[egress_start..agent_start];

    let loopback_up = egress_block
        .find("ip link set lo up")
        .expect("egress init raises loopback");
    let resolver_seed = egress_block
        .find("printf 'nameserver 127.0.0.1\\n' > /run/mvm/resolv.conf")
        .expect("egress init seeds the loopback DNS stub");
    let required_mode = egress_block
        .find("MVM_IDENTITY_PROVISION_COMMAND=provision-identity-for")
        .expect("egress-enabled boots require the service identity");
    let optional_mode = egress_block
        .find("MVM_IDENTITY_PROVISION_COMMAND=provision-identity-for-if-present")
        .expect("other boots provision an attached identity without requiring one");
    let provision = egress_block
        .find(
            "\"$MVM_EGRESS_CLIENT_BIN\" \"$MVM_IDENTITY_PROVISION_COMMAND\" ${toString egressUid}",
        )
        .expect("root init provisions according to the boot's egress requirement");
    let spawn = egress_block
        .find("--reuid=${toString egressUid} --regid=${toString egressUid}")
        .expect("egress init spawns the client");

    assert!(
        required_mode < provision
            && optional_mode < provision
            && provision < loopback_up
            && loopback_up < resolver_seed
            && resolver_seed < spawn,
        "the root-owned identity handoff and loopback must be ready before the egress client drops privilege"
    );
    assert!(
        egress_block.contains("--inh-caps=+net_bind_service --ambient-caps=+net_bind_service")
            && egress_block.contains("--no-new-privs"),
        "the long-lived client must retain only its low-port bind capability"
    );
    assert!(
        !egress_block.contains("--inh-caps=+sys_admin")
            && !egress_block.contains("--ambient-caps=+sys_admin"),
        "the long-lived client must not retain mount privilege"
    );
    assert!(
        content.contains("egressUid = 989;")
            && content.contains("uid 989 is reserved for the FlowMux egress service"),
        "the dedicated service uid must be fixed and protected from workload, agent, or builder reuse"
    );
}

#[test]
fn shared_kernel_base_forces_backend_console_support() {
    let path = nix_dir().join("images").join("kernel").join("base.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/kernel/base.nix must be present: {e}"));

    let enables = content
        .split_once("baseEnables =")
        .and_then(|(_, tail)| tail.split_once("requiredDisables ="))
        .map(|(enables, _)| enables)
        .expect("base kernel enables precede required disables");
    for symbol in [
        "VIRTIO_CONSOLE",
        "HVC_DRIVER",
        "SERIAL_8250",
        "SERIAL_8250_CONSOLE",
        "SERIAL_OF_PLATFORM",
    ] {
        assert!(
            enables.contains(&format!("\"{symbol}\"")),
            "the shared microVM kernel base must force CONFIG_{symbol} for a supported backend console"
        );
    }
}

#[test]
fn shared_kernel_base_enforces_audited_subsystem_removals() {
    let path = nix_dir().join("images").join("kernel").join("base.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/kernel/base.nix must be present: {e}"));
    let required_start = content
        .find("requiredDisables =")
        .expect("required kernel-disable set starts");
    let base_start = content[required_start..]
        .find("baseDisables =")
        .map(|offset| required_start + offset)
        .expect("base kernel-disable set follows required cuts");
    let required = &content[required_start..base_start];

    for symbol in [
        "SOUNDWIRE",
        "NFC",
        "RFKILL",
        "VIRTIO_INPUT",
        "VT",
        "SQUASHFS",
        "KEXEC",
        "DEBUG_FS",
        "KALLSYMS",
        "NLS_UTF8",
        "NETLABEL",
        "NET_SCHED",
        "IOSCHED_BFQ",
        "MQ_IOSCHED_KYBER",
        "NUMA",
        "CMA",
        "QRTR",
        "BLK_DEV_BSG_COMMON",
        "BLK_DEV_BSGLIB",
        "PACKET",
        "TASKSTATS",
        "HUGETLB_PAGE",
        "ACPI_PROCESSOR",
        "X86_PLATFORM_DEVICES",
        "ARM_SCMI_PROTOCOL",
    ] {
        assert!(
            required.contains(&format!("\"{symbol}\"")),
            "the audited kernel cut must retain CONFIG_{symbol} in requiredDisables"
        );
    }
    assert!(
        content.contains("requiredDisableList =")
            && content.contains("required kernel disables were reverted by olddefconfig"),
        "the resolved config must fail if Kconfig selectors silently restore an audited cut"
    );
}

#[test]
fn workload_kernel_optimizes_for_size_by_default() {
    let path = nix_dir().join("images").join("kernel").join("workload.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/kernel/workload.nix must be present: {e}"));
    let required_extra = content
        .split_once("requiredExtraDisables =")
        .map(|(_, tail)| tail)
        .expect("workload-specific required kernel cuts are present");

    assert!(
        content.contains("optimizeForSize ? true")
            && content.contains("\"CC_OPTIMIZE_FOR_SIZE\"")
            && content.contains("\"CC_OPTIMIZE_FOR_PERFORMANCE\"")
            && required_extra.contains("\"NAMESPACES\"")
            && required_extra.contains("\"CGROUPS\""),
        "the default workload kernel must select size optimization and enforce workload-only namespace and cgroup cuts"
    );
}

#[test]
fn mk_guest_deindents_pid1_script_before_writing_init() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("${pkgs.gnused}/bin/sed -i '1s/^ *//' \"$out/init\""),
        "mk-guest.nix must normalize the generated /init shebang to byte zero before \
         sealing the rootfs. \
         Without this, the rendered rootfs can carry a leading space before `#!`, \
         and the kernel rejects PID 1 with exec format error."
    );
}

#[test]
fn mk_guest_mounts_config_drive_before_reading_host_signer_pubkey() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains(
            "/bin/busybox mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdb /mnt/config || true"
        ),
        "mk-guest.nix must mount the config drive at /mnt/config before any boot-time code \
         reads host-signer.pub or security-policy.json from that path."
    );
}

#[test]
fn mk_guest_sealed_images_require_launch_provisioned_grants() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("\"require_grant\":true,\"grant_key_source\":\"launch_provisioned\""),
        "mk-guest.nix must bake sealed images with require_grant=true so \
         launch-provisioned agent verb grants are enforced fail-closed on \
         the live boot path."
    );
}

/// Plan 74 W2 (deferred-list item) — the runtime overlay flake
/// must stage `mvm-guest-netinit` at the canonical `/netinit`
/// path inside the overlay so OCI-imported workloads get
/// Layer 1 network defense too. The `mk-guest.nix` /init prefers
/// `/mvm/runtime/netinit` over the baked-in copy; without this
/// line, the prefer-overlay fallback falls through silently on
/// OCI workloads (which don't have a baked-in copy at all).
#[test]
fn runtime_overlay_flake_stages_netinit_binary() {
    let path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));

    assert!(
        content.contains("cp ${guest}/bin/mvm-guest-netinit    \"$staging/netinit\""),
        "runtime-overlay flake must stage `mvm-guest-netinit` at \
         `/netinit` inside the overlay ext4. The W1.4b mkGuest \
         /init resolution prefers `/mvm/runtime/netinit`; if the \
         overlay doesn't stage the binary, OCI workloads silently \
         fall through to the no-defense path. Pinned exact-string \
         match (with the canonical column alignment) to catch a \
         drop or rename in one regression-shaped commit."
    );
}

#[test]
fn runtime_overlay_flake_stages_egress_client_binary() {
    let path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));

    assert!(
        content.contains("cp ${egressClient}/bin/mvm-egress-client \"$staging/egress-client\""),
        "runtime-overlay flake must stage `mvm-egress-client` at \
         `/egress-client` inside the overlay ext4 so runtime-lean \
         sealed boots can source the egress shim from the mounted \
         runtime filesystem."
    );
}

#[test]
fn runtime_overlay_guest_packages_use_static_musl_and_have_no_loader_bundle() {
    let path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));
    let normalized = normalized_whitespace(&content);
    let runtime = normalized
        .split("mkRuntimeOverlay = system:")
        .nth(1)
        .and_then(|tail| tail.split(" in {").next())
        .expect("runtime-overlay derivation body");

    assert!(
        content.contains("pkgs = pkgs.pkgsStatic;"),
        "all runtime-overlay guest package recipes must be instantiated from pkgsStatic"
    );
    assert!(
        content.contains("staticPkgs.rustPlatform.buildRustPackage"),
        "the runner must use the static-musl Rust platform too"
    );
    for forbidden in [
        "runtimeLoaderFor",
        "runtimeLibcFor",
        "runtimeLibgccFor",
        "relocate_runtime_exe",
        "patchelf",
        "libc.so.6",
        "libgcc_s.so.1",
        "hostsvc",
    ] {
        assert!(
            !runtime.contains(forbidden),
            "static runtime-overlay body must not carry the dynamic loader bundle or SDK FFI: {forbidden}"
        );
    }
}

#[test]
fn runtime_overlay_exposes_sdk_sidecar_separately() {
    let path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    assert!(
        normalized.contains("mkSdkSidecar = system:"),
        "the glibc SDK FFI must have a distinct sidecar derivation"
    );
    assert!(
        content.contains("sdk-sidecar = mkSdkSidecar system;"),
        "the runtime-overlay flake must publish the SDK sidecar output"
    );
    assert!(
        content.contains("/mvm/sdk/lib"),
        "the sidecar must use the stable /mvm/sdk mount contract"
    );
    assert!(
        content.contains("sdkRuntimeLoaderFor")
            && content.contains("--set-rpath /mvm/sdk/lib")
            && !content.contains("--set-interpreter /mvm/sdk/lib/"),
        "the sidecar must carry its matching glibc loader and set the cdylib RPATH without treating the shared object as an executable"
    );
}

/// The sidecar has to ship as an attachable read-only ext4 with the exact file
/// set `mvm_fs::sdk_sidecar::SdkSidecarResolver` verifies. A directory output
/// alone can't be attached to a microVM.
#[test]
fn runtime_overlay_publishes_an_attachable_sdk_sidecar_image() {
    let path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));
    let normalized = normalized_whitespace(&content);

    assert!(
        normalized.contains("mkSdkSidecarImage = system:"),
        "the sidecar must have an ext4-image derivation, not just a directory tree"
    );
    assert!(
        content.contains("sdk-sidecar-image = mkSdkSidecarImage system;"),
        "the flake must publish the attachable sidecar image output"
    );
    // Exactly the resolver's canonical file set, and the manifest that covers it.
    for required in [
        "$out/sdk.ext4",
        "$out/VERSION",
        "sha256sum sdk.ext4 VERSION > checksums-sha256.txt",
    ] {
        assert!(
            content.contains(required),
            "the sidecar image must emit {required} for the host-side resolver"
        );
    }
    assert!(
        content.contains("-L mvm-sdk-sidecar"),
        "the sidecar image must carry a distinct filesystem label"
    );
    assert!(
        content.contains("sdkSidecarSizeBytes = 8 * 1024 * 1024;"),
        "the sidecar allocation must stay pinned to the ledger's separate budget"
    );
}

/// Both closure gates, and the direction of each. A change that deleted the SDK
/// cdylib outright would satisfy every no-glibc assertion and look like a
/// footprint win, so the positive gate is what makes the split meaningful.
///
/// The overlay-facing gates run as a CI step rather than a flake `check`: the
/// runtime-overlay flake reaches the workspace through a path outside its own
/// flake root, so `closureInfo` against its sources cannot be instantiated under
/// a pure `nix flake check`. Querying the closure of the artifacts CI has
/// already built is equally build-backed and does not rebuild them.
#[test]
fn closure_gates_pin_glibc_out_of_the_base_and_into_the_sidecar() {
    let root = fs::read_to_string(nix_dir().join("flake.nix")).expect("root flake must be present");
    let ci = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github")
            .join("workflows")
            .join("ci.yml"),
    )
    .expect("ci.yml must be present");

    // Hash-anchored matches only: a bare `-glibc` pattern would fire on any
    // derivation whose *name* happens to contain the string.
    assert!(
        root.contains(r"'/nix/store/[a-z0-9]+-glibc(-|$)'"),
        "the rootfs no-glibc gate must anchor its grep on the glibc store path"
    );
    assert!(
        ci.contains(r"glibc_re='/nix/store/[a-z0-9]+-glibc(-|$)'"),
        "the overlay/sidecar gates must anchor their grep on the glibc store path"
    );

    // The negative direction must close over the executables actually staged
    // into the overlay; an empty root-path set would make it vacuously green.
    for staged in ["guest", "runner", "egressClient", "addonDns", "exitReport"] {
        assert!(
            ci.contains(staged),
            "the overlay no-glibc closure must include the staged {staged} binary"
        );
    }
    assert!(
        ci.contains("nix path-info -r"),
        "the gates must query a realized closure, not a bare evaluation"
    );

    // And the positive direction, plus the files the sidecar has to ship.
    assert!(
        ci.contains("sdk-sidecar.passthru.hostsvc"),
        "the positive gate must query the SDK cdylib's own closure"
    );
    assert!(
        ci.contains("no longer depends on glibc"),
        "the positive gate must fail when the cdylib stops depending on glibc"
    );
    for required in ["libmvm_host_services.so", "libc.so.6", "libgcc_s.so.1"] {
        assert!(
            ci.contains(required),
            "the sidecar gate must assert {required} is shipped"
        );
    }
}

/// The guest mounts the sidecar from the device the host names on the cmdline.
/// Without the mountpoint on the read-only rootfs the mount fails with an
/// unactionable EACCES, so both halves are pinned here.
#[test]
fn mk_guest_mounts_the_sdk_sidecar_read_only_from_the_host_named_device() {
    let content = fs::read_to_string(nix_dir().join("lib").join("mk-guest.nix"))
        .expect("nix/lib/mk-guest.nix must be present");

    assert!(
        content.contains(r"mvm\.sdk_dev="),
        "the generated init must read the sidecar device from the kernel cmdline"
    );
    assert!(
        content.contains(r#"mount -t ext4 -o ro,nosuid,nodev "$MVM_SDK_DEV" /mvm/sdk"#),
        "the sidecar must be mounted read-only, nosuid, nodev"
    );
    assert!(
        content.contains(r#"mkdir -p "$out/mvm/sdk""#),
        "the read-only rootfs must carry the sidecar mountpoint"
    );
    // The cdylib is dlopen'd, so the mount must not be noexec — assert the
    // option set explicitly rather than trusting the absence of a token.
    assert!(
        !content.contains(r#"mount -t ext4 -o ro,noexec,nosuid,nodev "$MVM_SDK_DEV""#),
        "the sidecar mount must not be noexec: the workload dlopens the cdylib"
    );
}

#[test]
fn mk_guest_accepts_compact_and_legacy_egress_ca_cmdline_tokens() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("mvm.egress_ca=pem:<body>"),
        "mk-guest.nix must document the compact egress CA cmdline token so \
         the sealed guest/runtime contract matches the host encoder."
    );
    assert!(
        content.contains("/bin/busybox grep -q '^pem:'"),
        "mk-guest.nix must detect the compact egress CA token format at boot."
    );
    assert!(
        content.contains("-----BEGIN CERTIFICATE-----"),
        "mk-guest.nix must reconstruct PEM armor for the compact egress CA token."
    );
    assert!(
        content.contains("echo \"$MVM_EGRESS_CA_TOKEN\" | /bin/busybox sed 's/../\\\\x&/g'"),
        "mk-guest.nix must keep the legacy hex-encoded egress CA decode path \
         so older boots remain compatible during the token-format rollout."
    );
}

/// ADR-017 / issue #223 — the OCI-pull verity path runs
/// `veritysetup format` inside the builder VM, while the Nix-built
/// runtime-overlay baseline runs it in the runtime-overlay flake.
/// Both must use the same explicit cryptsetup release pin so a
/// nixpkgs bump cannot silently change sidecar bytes. The live
/// Linux integration test `seal_is_byte_deterministic_for_identical_rootfs_bytes`
/// verifies byte-identical sidecars for fixed input bytes when
/// `veritysetup` is present; this structural guard verifies the
/// two Nix closures consume the same pinned toolchain.
#[test]
fn cryptsetup_pin_is_shared_by_builder_vm_and_runtime_overlay() {
    let builder_path = nix_dir()
        .join("images")
        .join("builder-vm")
        .join("flake.nix");
    let runtime_path = nix_dir()
        .join("images")
        .join("runtime-overlay")
        .join("flake.nix");
    let builder = fs::read_to_string(&builder_path)
        .unwrap_or_else(|e| panic!("nix/images/builder-vm/flake.nix must be present: {e}"));
    let runtime = fs::read_to_string(&runtime_path)
        .unwrap_or_else(|e| panic!("nix/images/runtime-overlay/flake.nix must be present: {e}"));

    for (name, content) in [
        ("builder-vm flake", builder.as_str()),
        ("runtime-overlay flake", runtime.as_str()),
    ] {
        let normalized = normalized_whitespace(content);
        assert!(
            normalized.contains("pinnedCryptsetupVersion = \"2.8.6\""),
            "{name} must pin cryptsetup 2.8.6 explicitly for ADR-017 / #223"
        );
        assert!(
            normalized.contains(
                "pinnedCryptsetupSrcHash = \"sha256-gAQmX9mTiF0I97Yz2+BWhR3hohAwdhOk693HQ/zO/lo=\""
            ),
            "{name} must pin the cryptsetup 2.8.6 release tarball hash"
        );
        assert!(
            normalized.contains("pinnedCryptsetupFor = pkgs:"),
            "{name} must expose a pinned cryptsetup helper instead of using raw pkgs.cryptsetup"
        );
        assert!(
            content.contains("pkgs.cryptsetup.overrideAttrs"),
            "{name} must override cryptsetup source/version, not only document the desired version"
        );
        assert!(
            content.contains("cryptsetup-${pinnedCryptsetupVersion}.tar.xz"),
            "{name} must fetch the exact cryptsetup release tarball named by the pin"
        );
    }

    assert!(
        builder.contains("(pinnedCryptsetupFor pkgs) # provides pinned veritysetup"),
        "builder VM packages must include the pinned cryptsetup package so OCI-pull \
         verity generation runs the pinned veritysetup binary"
    );
    assert!(
        runtime.contains("(pinnedCryptsetupFor pkgs) # provides pinned veritysetup"),
        "runtime-overlay nativeBuildInputs must use the pinned cryptsetup package so \
         the Nix-built verity baseline matches the builder VM"
    );
}

#[test]
fn flake_lock_pins_microvm_input_by_hash() {
    // The flake.lock must exist and pin the microvm.nix input by
    // commit hash, not by tag or branch — that's the supply-chain
    // gate from ADR-004 §"Threat model impact" / plan 60 §"Code
    // review gate." A PR that removes flake.lock or drops the
    // microvm pin breaks this assertion.
    let path = nix_dir().join("flake.lock");
    let content = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "nix/flake.lock must be committed for hash-pinned supply \
             chain (run `cd nix && nix flake lock` to generate): {e}"
        )
    });

    // Pinned by hash means the lockfile carries a `rev` field for
    // the microvm input. We don't pin a *specific* hash here (CI's
    // `xtask audit-flake` does that on bump) — we just verify the
    // microvm input is present in the lockfile.
    assert!(
        content.contains("\"microvm\""),
        "flake.lock must contain the 'microvm' input pin"
    );
    assert!(
        content.contains("\"rev\""),
        "flake.lock must pin inputs by `rev` (commit hash)"
    );
}

/// Plan 199 WS-B — the no-release-binary contract (ADR-007) must hold for
/// *every* host package under `nix/packages/`, not just `mvmctl.nix`. A new
/// sidecar package that pulled a project release tarball or carried
/// `binaryNativeCode` provenance would silently bypass the source-build
/// guarantee. This scans the whole directory (so adding such a package fails
/// CI immediately) rather than naming files.
///
/// Note the forbidden set is deliberately *project-release-specific*: a host
/// package may legitimately `fetchurl` its own **upstream source** (the future
/// source-built `libkrun` / `libkrunfw` recipes do exactly this — Plan 199 WS-B
/// native-VMM recipes). Source-building from a pinned upstream tarball is the
/// contract; pulling an mvm-published release binary or shipping prebuilt
/// native code is what's banned. The stricter "no fetch at all" rule stays
/// scoped to `mvmctl.nix` (which builds purely from `mvmSrc`).
#[test]
fn no_host_package_uses_release_binary_provenance() {
    let dir = nix_dir().join("packages");
    // Project-release / prebuilt-binary provenance — never source.
    let forbidden = [
        "github.com/tinylabscom/mvm/releases",
        "tinylabscom/mvm/releases",
        "binaryNativeCode",
    ];
    let mut scanned = 0usize;
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("nix/packages/ must be present: {e}"))
    {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("nix") {
            continue;
        }
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let name = path.file_name().unwrap().to_string_lossy();
        for needle in forbidden {
            assert!(
                !content.contains(needle),
                "host package nix/packages/{name} must not use {needle:?} — host \
                 packages are source-built, never mvm-published release binaries \
                 (ADR-007 / Plan 199 WS-B)"
            );
        }
        scanned += 1;
    }
    // Guard against the scan silently matching nothing (wrong dir / glob drift).
    assert!(
        scanned >= 5,
        "expected to scan every nix/packages/*.nix host package; only saw {scanned}"
    );
}

#[test]
fn mk_guest_copies_only_module_dependency_metadata() {
    let path = nix_dir().join("lib/mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("cp -a --reflink=auto \"$src/modules.dep\""),
        "mkGuest must retain the dependency index required by busybox modprobe"
    );
    assert!(
        content.contains("vmw_vsock_virtio_transport")
            && content.contains("virtiofs")
            && content.contains("fuse"),
        "mkGuest must retain the module closures needed by guest boot and virtio-fs"
    );
    assert!(
        !content.contains("for metadata in \"$src\"/modules.*"),
        "mkGuest must not copy unused kernel module indexes into the rootfs"
    );
}

#[test]
fn mk_guest_uses_the_static_custom_privilege_helper() {
    let path = nix_dir().join("lib/mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("import ../packages/mvm-setpriv.nix")
            && content.contains("rustPlatform = pkgs.pkgsStatic.rustPlatform"),
        "mkGuest must build the privilege helper through the static package set"
    );
    assert!(
        content.contains("setprivPkg") && content.contains("/bin/mvm-setpriv"),
        "mkGuest init must resolve the dedicated helper, not util-linux"
    );
    assert!(
        !content.contains("pkgs.pkgsStatic.util-linux"),
        "mkGuest must not retain the util-linux setpriv closure"
    );
}

#[test]
fn builder_hook_uses_util_linux_losetup_before_the_mount_syscall() {
    let builder_flake_path = nix_dir().join("images/builder-vm/flake.nix");
    let builder_flake = fs::read_to_string(&builder_flake_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", builder_flake_path.display()));
    assert!(
        builder_flake.contains("        util-linux"),
        "the builder image must retain util-linux for file-backed loop mounts"
    );

    let hook_path = repo_dir().join("crates/mvm-build/src/bin/mvm-host-vm-init/builder_hooks.rs");
    let hook = fs::read_to_string(&hook_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", hook_path.display()));
    assert!(
        hook.contains("const UTIL_LINUX_LOSETUP: &str = \"/sbin/losetup\";")
            && hook.contains("Command::new(UTIL_LINUX_LOSETUP)")
            && hook.contains("mount("),
        "the hook runner must allocate the loop device with util-linux before mounting it"
    );
    assert!(
        !hook.contains("Command::new(\"mount\")"),
        "a PATH-resolved mount can select BusyBox, which cannot allocate the loop device"
    );
}

/// Every recipe whose `src` is the whole workspace must normalize it before the
/// generic unpacker runs: a `path:` input evaluated from the `nix/` subflake can
/// retain a trailing `nix/..` shape and the unpacker then fails with
/// "destination already exists". The workaround lives in one shared snippet, so
/// this asserts both that the snippet does the normalization and that every such
/// recipe uses it — a recipe that forgets it builds from the root flake's
/// closure gates and fails only in CI.
#[test]
fn workspace_sourced_packages_normalize_the_workspace_source() {
    let snippet_path = nix_dir().join("packages/workspace-unpack.nix");
    let snippet = fs::read_to_string(&snippet_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", snippet_path.display()));
    assert!(
        snippet.contains("cp -R ${mvmSrc}/. source") && snippet.contains("sourceRoot=source"),
        "the shared unpack snippet must copy the workspace into a plain source dir"
    );

    for recipe in [
        "mvm-setpriv.nix",
        "mvm-guest-agent.nix",
        "mvm-egress-client.nix",
        "mvm-addon-dns.nix",
        "mvm-exit-report.nix",
        "mvm-sdk-cdylib.nix",
    ] {
        let path = nix_dir().join("packages").join(recipe);
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert!(
            content.contains("src = mvmSrc;"),
            "{recipe} is expected to build from the whole workspace"
        );
        assert!(
            content.contains("unpackPhase = import ./workspace-unpack.nix { inherit mvmSrc; };"),
            "{recipe} must normalize its workspace source through the shared snippet"
        );
    }
}

#[test]
fn mk_guest_copies_ca_bundle_without_retaining_cacert_store_path() {
    let path = nix_dir().join("lib/mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("rootPaths = [ busybox setprivPkg ] ++ packages ++ extraFileSourceRoots")
            && !content.contains(
                "rootPaths = [ busybox setprivPkg pkgs.cacert ] ++ packages ++ extraFileSourceRoots"
            ),
        "mkGuest's registered runtime closure must not retain the copied cacert source"
    );
    assert!(
        content.contains(
            "cp ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \"$out/etc/ssl/certs/ca-bundle.crt\""
        ),
        "mkGuest must still copy the Mozilla CA bundle into the FHS rootfs"
    );
    assert!(
        content.contains("inherit rootfsClosureInfo"),
        "mkGuest must expose its closure for the build-backed package-count gate"
    );
}

#[test]
fn mk_guest_removes_the_ext4_growth_reserve() {
    let path = nix_dir().join("lib/mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("rootfsImageWithGrowthReserve")
            && content.contains("resize2fs -M \"$out\""),
        "mkGuest must minimize the immutable ext4 image after nixpkgs adds its generic growth reserve"
    );
}

#[test]
fn nix_flake_caps_the_lean_guest_rootfs_package_count() {
    let path = nix_dir().join("flake.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("guest-rootfs-package-budget")
            && content.contains("guest.passthru.rootfsClosureInfo")
            && content.contains("wc -l")
            && content.contains("-gt 2"),
        "the Nix check must cap the realized lean rootfs closure at two store paths"
    );
}

#[test]
fn nix_flake_uses_the_builder_workspace_override_for_build_backed_checks() {
    let path = nix_dir().join("flake.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("builtins.getEnv \"MVM_WORKSPACE_PATH\"")
            && content.contains("workspaceSrc")
            && content.contains("mvmSrc = workspaceSrc"),
        "the root Nix flake must use the mounted workspace when evaluated in the builder VM"
    );
}

#[test]
fn ci_builds_the_guest_rootfs_package_budget() {
    let path = repo_dir().join(".github/workflows/ci.yml");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("./nix#checks.x86_64-linux.guest-rootfs-package-budget"),
        "CI must realize the rootfs package-count budget, not only eval it"
    );
}

#[test]
fn ci_counts_the_kernel_in_the_guest_footprint() {
    let path = repo_dir().join(".github/workflows/ci.yml");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("--kernel \"$image_path/vmlinux\""),
        "the 50 MB CI ledger must include the workload kernel"
    );
}

#[test]
fn default_tenant_exports_and_ci_counts_the_rootfs_closure() {
    let flake_path = nix_dir().join("images/default-tenant/flake.nix");
    let flake = fs::read_to_string(&flake_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", flake_path.display()));
    let ci_path = repo_dir().join(".github/workflows/ci.yml");
    let ci = fs::read_to_string(&ci_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", ci_path.display()));

    assert!(
        flake.contains("rootfsPkg.passthru.rootfsClosureInfo")
            && flake.contains("$out/rootfs-closure-paths"),
        "the default tenant must export its realized rootfs closure inventory"
    );
    assert!(
        ci.contains("--closure-paths \"$image_path/rootfs-closure-paths\""),
        "the footprint CI gate must consume the exported closure inventory"
    );
}

/// No published-image fetch may build its release URL from the CLI's own
/// version.
///
/// The CLI ships from `v<crate version>`; the guest images ship from
/// `boot-image/vN`, on a counter that moves independently so a kernel fix does
/// not wait for a CLI release. Deriving an image URL from `CARGO_PKG_VERSION`
/// therefore points at a tag nobody has published for most of a release cycle —
/// a 404 on the first boot of a fresh install, which is exactly how it shipped.
///
/// `runtime_overlay.rs` and `sdk_sidecar.rs` are deliberately excluded: their
/// version is also the on-disk cache key, so splitting their download tag from
/// their cache identity is a separate change, not a rename.
#[test]
fn image_fetches_do_not_derive_their_release_url_from_the_cli_version() {
    let cli = repo_dir().join("crates/mvm-cli/src");
    let offenders: Vec<String> = [
        "commands/env/builder_vm/default_microvm.rs",
        "commands/env/builder_vm/stage0_cache.rs",
        "commands/image/boot/update.rs",
        "update.rs",
    ]
    .iter()
    .filter(|rel| {
        fs::read_to_string(cli.join(rel))
            .unwrap_or_default()
            .contains("releases/download/v{version}")
    })
    .map(|rel| (*rel).to_string())
    .collect();

    assert!(
        offenders.is_empty(),
        "these build an image release URL from the CLI version, which 404s \
         whenever the crate version is ahead of the last CLI tag: {offenders:?}. \
         Use `update::boot_image_release()`."
    );
}
