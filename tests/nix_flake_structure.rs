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
use std::path::PathBuf;

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
fn flake_nix_exists_and_imports_microvm_nix() {
    let path = nix_dir().join("flake.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("nix/flake.nix must be present: {e}"));

    // ADR-013 invariant: the flake imports microvm.nix as the foundation.
    // Any future PR that drops this input violates the ADR.
    assert!(
        content.contains("microvm-nix/microvm.nix"),
        "nix/flake.nix must reference microvm-nix/microvm.nix as an input \
         (per ADR-013); content excerpt: {}",
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
         user-facing API (per ADR-013 + plan 60). Got: ...{}",
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
            && content.contains("cargoLock.lockFile = mvmSrc + \"/Cargo.lock\""),
        "mvmctl package must use the source checkout and committed Cargo.lock"
    );
    assert!(
        content.contains("\"--package\"") && content.contains("\"mvmctl\""),
        "mvmctl package must explicitly build the root CLI package"
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
        content.contains("assert withNativeLibkrun -> withBuilderVm")
            && content.contains("\"mvmctl/builder-vm\""),
        "feature flags must stay package-qualified when mvmctl and sidecars build together"
    );
    assert!(
        content.contains("\"mvm-cli/libkrun-sys\"")
            && content.contains("\"mvm-vm-host/libkrun-sys\""),
        "the native libkrun feature must enable both CLI probing and the supervisor binary"
    );
    assert!(
        content.contains("MVM_LIBKRUN_HEADER"),
        "the Nix package must pass an explicit libkrun.h path to bindgen"
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
    let dev_heading = content
        .find("## 2. Launch the Dev Environment")
        .expect("quickstart must still document the dev environment");

    assert!(
        image_heading < dev_heading,
        "quickstart must put the image-backed one-shot path before dev/flake workflows"
    );
    assert!(
        content.contains("mvmctl run --image alpine -- uname -a")
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

    // SSH disabled — load-bearing invariant from ADR-002 / CLAUDE.md
    // ("No SSH in microVMs, ever"). Asserted as plain string match
    // because a NixOS module's effective `services.openssh.enable`
    // can only be checked by evaluating the flake; the source line
    // is the closest we can get without booting Nix.
    assert!(
        content.contains("services.openssh.enable = false"),
        "minimal profile must explicitly disable SSH per ADR-002"
    );

    // The microvm.hypervisor must be declared — that's what
    // selects the runner. Even if it's `firecracker` (the default),
    // the explicit declaration makes the profile self-documenting.
    assert!(
        content.contains("microvm.hypervisor") || content.contains("hypervisor"),
        "minimal profile must declare a microvm.hypervisor (defaults \
         to firecracker per ADR-013)"
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

/// Plan 74 W1.4b (ADR-051) — `mkGuest` must carry the overlay-
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
#[test]
fn mk_guest_carries_overlay_aware_contract() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("mkdir -p \"$out/mvm/runtime\""),
        "mk-guest.nix must create /mvm/runtime in the rootfs as the \
         ADR-051 bind-mount target. Missing the `mkdir -p \"$out/mvm/runtime\"` \
         line means the verity-init bind-mount target is missing and the \
         agent never starts."
    );

    assert!(
        content.contains("/mvm/runtime/agent"),
        "mk-guest.nix /init must reference /mvm/runtime/agent (ADR-051). \
         Without this resolution path the overlay-attached agent isn't \
         exec'd and the rootfs falls back to the baked-in copy on every \
         boot — defeating the W1.4b refactor."
    );

    assert!(
        content.contains("overlayAware = true"),
        "mk-guest.nix mvmMeta passthru must declare `overlayAware = true` \
         (Plan 74 W1.4b / ADR-051). Admission-time gates read this to \
         refuse boot of cached pre-W1.4b templates."
    );
}

/// Plan 74 W2 — `mkGuest` must bake `mvm-guest-netinit` into the
/// rootfs AND invoke it from `/init` before forking the agent.
/// Without this, the guest-side defense (kernel blackhole routes
/// for `MANDATORY_DENY_RANGES`) never installs, leaving the
/// macOS Apple Container path with no firewall at all. The
/// source-grep here catches a regression that drops either the
/// binary copy or the /init invocation before it reaches a live
/// VM boot.
#[test]
fn mk_guest_installs_netinit_at_boot() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        content.contains("mvmGuestNetinitBinary = \"${guestAgentPkg}/bin/mvm-guest-netinit\""),
        "mk-guest.nix must reference the mvm-guest-netinit binary \
         from the guest-agent derivation. Plan 74 W2 — guest-side \
         network defense relies on this binary being baked into \
         every mvm-built rootfs."
    );

    assert!(
        content.contains("/usr/local/bin/mvm-guest-netinit"),
        "mk-guest.nix /init must invoke the netinit binary at its \
         canonical path. A drop here means the binary is built but \
         never runs at boot, leaving the guest with no kernel-level \
         defense against IMDS exfil."
    );

    assert!(
        content.contains("/mvm/runtime/netinit"),
        "mk-guest.nix /init must prefer the runtime-overlay path \
         (`/mvm/runtime/netinit`) over the baked-in copy when the \
         W1.4b overlay is mounted. Mirrors the agent-bin resolution \
         pattern; preserves the host-bake fallback for backends \
         that don't attach the overlay yet."
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

/// ADR-050 / issue #223 — the OCI-pull verity path runs
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
        assert!(
            content.contains("pinnedCryptsetupVersion = \"2.8.6\""),
            "{name} must pin cryptsetup 2.8.6 explicitly for ADR-050 / #223"
        );
        assert!(
            content.contains(
                "pinnedCryptsetupSrcHash = \"sha256-gAQmX9mTiF0I97Yz2+BWhR3hohAwdhOk693HQ/zO/lo=\""
            ),
            "{name} must pin the cryptsetup 2.8.6 release tarball hash"
        );
        assert!(
            content.contains("pinnedCryptsetupFor = pkgs:"),
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
    // gate from ADR-013 §"Threat model impact" / plan 60 §"Code
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

/// Plan 199 WS-B — the no-release-binary contract (ADR-046) must hold for
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
        "releases/download",
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
                 (ADR-046 / Plan 199 WS-B)"
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
