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

#[test]
fn mk_guest_sealed_entrypoint_is_executable_by_the_guest_agent() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));
    assert!(
        content.contains(
            "cp ${entrypointFile} \"$out/etc/mvm/entrypoint\"\n    chmod 0755 \"$out/etc/mvm/entrypoint\""
        ),
        "the sealed script must use the executable mode required by the guest agent"
    );
}

fn normalized_whitespace(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

const CRATES_IO_API: &str = "https://crates.io/api/v1/crates";

/// Load kernel pins from the external data file
fn load_kernel_pins() -> (String, String) {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for integration tests");
    let data_path = Path::new(&manifest)
        .join("xtask")
        .join("data")
        .join("kernel-pins.json");
    let content = fs::read_to_string(&data_path)
        .unwrap_or_else(|e| panic!("kernel-pins.json must be present: {e}"));

    let json: serde_json::Value = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("kernel-pins.json must be valid JSON: {e}"));

    let version = json["kernel_version"]
        .as_str()
        .unwrap_or_else(|| panic!("kernel-pins.json must have kernel_version string"));
    let hash = json["kernel_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("kernel-pins.json must have kernel_hash string"));

    (version.to_string(), hash.to_string())
}

#[test]
fn the_crate_source_helper_rewrites_the_api_host_to_the_cdn() {
    let source = nix_dir().join("lib").join("crates-io.nix");
    let content = fs::read_to_string(&source)
        .unwrap_or_else(|e| panic!("crate source helper must be present: {e}"));

    assert!(
        content.contains(CRATES_IO_API)
            && content.contains("https://static.crates.io/crates")
            && content.contains("builtins.replaceStrings"),
        "nix/lib/crates-io.nix must rewrite crates.io API downloads to the CDN"
    );
}

#[test]
fn the_cargo_deps_helper_routes_downloads_through_the_crate_source_helper() {
    let helper = nix_dir().join("lib").join("static-crates-cargo-deps.nix");
    let helper_content = fs::read_to_string(&helper)
        .unwrap_or_else(|e| panic!("static crate registry helper must be present: {e}"));

    assert!(
        helper_content.contains("crates-io.nix")
            && helper_content.contains("toCdn")
            && helper_content.contains("fetchurl = fetchStaticCrate"),
        "the cargo-deps helper must route lockfile downloads through crates-io.nix"
    );
    assert!(
        !helper_content.contains("extraRegistries"),
        "the helper must not redefine Cargo's built-in crates.io source"
    );
}

#[test]
fn every_rust_derivation_uses_the_static_crates_registry() {
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
            content.contains("cargoDeps = import")
                && content.contains("static-crates-cargo-deps.nix"),
            "{} builds Rust without the static crates.io registry helper",
            path.display()
        );
    }

    assert!(
        rust_derivations > 0,
        "expected at least one Rust Nix derivation"
    );
}

/// crates.io's API host answers a plain curl User-Agent with 403, which is what
/// Nix's fetchurl sends. A hand-written crate fetch against that host therefore
/// cannot build — it fails with `curl: (22) ... error: 403` on a derivation
/// named `download`, naming neither the crate nor the host. `crates-io.nix` is
/// the one place allowed to name the API host, and only to rewrite it away.
#[test]
fn no_nix_file_fetches_a_crate_from_the_api_host() {
    let allowed = nix_dir().join("lib").join("crates-io.nix");

    let mut nix_files = Vec::new();
    collect_nix_files(&nix_dir(), &mut nix_files);

    let offenders: Vec<PathBuf> = nix_files
        .into_iter()
        .filter(|path| *path != allowed)
        .filter(|path| {
            fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()))
                .contains(CRATES_IO_API)
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these files fetch crates from the crates.io API host, which 403s Nix's \
         fetchurl; use the fetchCrate helper in nix/lib/crates-io.nix instead: {offenders:?}"
    );
}

#[test]
fn mvm_setpriv_imports_pass_pkgs_to_the_static_crates_helper() {
    let mk_guest = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("lib").join("mk-guest.nix"))
            .expect("mk-guest.nix must be readable"),
    );
    assert!(
        mk_guest.contains(
            "import ../packages/mvm-setpriv.nix { inherit pkgs; rustPlatform = pkgs.pkgsStatic.rustPlatform;"
        ),
        "the workload guest must pass pkgs into mvm-setpriv.nix"
    );

    let guest_recipes = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("packages").join("guest.nix"))
            .expect("nix/packages/guest.nix must be readable"),
    );
    assert!(
        guest_recipes.contains(
            "mvm-setpriv = import ./mvm-setpriv.nix { inherit pkgs lib mvmSrc; rustPlatform = staticPkgs.rustPlatform;"
        ),
        "the exported setpriv recipe must pass pkgs into mvm-setpriv.nix"
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
            && content.contains("static-crates-cargo-deps.nix")
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

/// The packages that ship the workspace's own release version read it from
/// `Cargo.toml` rather than restating it, so a version bump cannot leave a
/// package naming the previous release. The expression reads the same
/// `mvmSrc` their vendored dependencies read `Cargo.lock` from; the manifest
/// half of this test proves the path it walks exists and is a string.
#[test]
fn workspace_versioned_packages_read_the_version_from_the_manifest() {
    const READ_VERSION_DIRECTLY: &str =
        "workspaceVersion = (lib.importTOML (mvmSrc + \"/Cargo.toml\")).workspace.package.version;";
    const READ_VERSION_BY_DEFAULT: &str =
        "workspaceVersion ? (lib.importTOML (mvmSrc + \"/Cargo.toml\")).workspace.package.version,";

    let manifest_path = repo_dir().join("Cargo.toml");
    let manifest: toml::Value = toml::from_str(
        &fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", manifest_path.display())),
    )
    .unwrap_or_else(|e| panic!("parsing {}: {e}", manifest_path.display()));
    let version = manifest
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str);
    assert!(
        version.is_some_and(|v| !v.is_empty()),
        "Cargo.toml must carry workspace.package.version as a string; the nix packages read it"
    );

    for (recipe, version_read) in [
        ("mvmctl.nix", READ_VERSION_DIRECTLY),
        ("mvm-sdk-cdylib.nix", READ_VERSION_BY_DEFAULT),
    ] {
        let path = nix_dir().join("packages").join(recipe);
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert!(
            content.contains(version_read) && content.contains("version = workspaceVersion;"),
            "{recipe} must take its version from the workspace manifest"
        );
        let literal = content
            .lines()
            .map(str::trim_start)
            .find(|line| line.starts_with("version = \""));
        assert!(
            literal.is_none(),
            "{recipe} must not hardcode a version literal: {literal:?}"
        );
    }

    // The exported recipes read the version from the unfiltered workspace
    // root, never from the filtered source store path.
    let flake = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("flake.nix")).expect("read nix/flake.nix"),
    );
    assert!(
        flake.contains(
            "manifest = if envPath != \"\" then /. + envPath + \"/Cargo.toml\" else ../Cargo.toml;"
        ) && flake.contains("(nixpkgs.lib.importTOML manifest).workspace.package.version;"),
        "nix/flake.nix must read the workspace version from its stable workspace root"
    );
    let guest_recipes = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("packages").join("guest.nix"))
            .expect("read nix/packages/guest.nix"),
    );
    assert!(
        guest_recipes.contains("inherit pkgs lib mvmSrc libc workspaceVersion;")
            && guest_recipes.contains("version = workspaceVersion;"),
        "the exported SDK cdylib and runner must take the manifest version"
    );
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
        !content.contains("withBuilderVm") && !content.contains("builder-vm\""),
        "builder orchestration is unconditional; the Nix package must not revive a builder-vm feature"
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

    let (kernel_version, kernel_hash) = load_kernel_pins();
    assert!(
        libkrunfw.contains(&format!("linux-{kernel_version}.tar.xz"))
            && libkrunfw.contains(&format!("hash = \"{kernel_hash}\""))
            && libkrunfw.contains("KERNEL_REMOTE")
            && libkrunfw.contains(&format!(
                "'KERNEL_VERSION = linux-6.12.91' 'KERNEL_VERSION = linux-{kernel_version}'"
            ))
            && libkrunfw.contains("ln -s ${kernelSrc} $(KERNEL_TARBALL)")
            && libkrunfw.contains("'virtio_transport_alloc_skb(&info, dgram_len, false, NULL,'"),
        "libkrunfw must pin the kernel version, substitute the source, and keep its datagram patch compatible with that kernel"
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

    let flake = fs::read_to_string(nix_dir().join("flake.nix")).unwrap();
    let lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(nix_dir().join("flake.lock")).unwrap()).unwrap();
    let root_lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(repo_dir().join("flake.lock")).unwrap()).unwrap();
    assert!(
        content.contains("version = \"1.97.1\"")
            && content.contains("rust-bin.stable.${version}.minimal.override")
            && content.contains("targets = [ target ];")
            && flake.contains("rust-overlay ? null,")
            && flake
                .matches(".extend rust-overlay.overlays.default")
                .count()
                == 3
            && lock["nodes"]["rust-overlay"] == root_lock["nodes"]["rust-overlay"]
            && lock["nodes"]["root"]["inputs"]["rust-overlay"] == "rust-overlay",
        "embedded Rust toolchain must use the locked Rust overlay with the matching musl target"
    );
    for package in ["default.nix", "mvm-gpu-shims.nix", "mvm-sdk-cdylib.nix"] {
        let package = fs::read_to_string(nix_dir().join("packages").join(package)).unwrap();
        assert!(package.contains("./embedded-rust-toolchain.nix"));
    }
}

#[test]
fn mk_guest_rejects_ssh_template_inputs_structurally() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("mk-guest.nix must be present: {e}"));
    let normalized = normalized_whitespace(&content);

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

    let extra_files_arg = normalized
        .find("extraFiles ? { },")
        .expect("mkGuest must bind the extraFiles argument");
    let extra_file_label = normalized
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
        normalized.contains("repository root exposes a release binary pinned by archive hash")
            && normalized.contains("nix run github:tinylabscom/mvm#prebuilt")
            && normalized.contains("nix profile add github:tinylabscom/mvm#prebuilt")
            && normalized.contains("two outputs are separate: `#prebuilt`")
            && normalized.contains("`nix/#mvmctl` builds the checkout's source"),
        "installation docs must distinguish pinned release binaries from source-built Nix"
    );
    // The release job pushes a pin branch but cannot open the pull request, so
    // the pin trails releases until someone opens it.
    assert!(
        normalized.contains("The pin is bumped by hand and can trail the latest release")
            && !normalized.contains("updated by a pull request after a release"),
        "installation docs must not claim the prebuilt pin updates itself"
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
/// A workspace root reached through a symlink must be refused by name, not
/// filtered to an empty tree: Nix hands the filter symlink-resolved paths, and
/// the filter strips the root as text. On macOS every path under `/tmp` is such
/// a root.
#[test]
fn workspace_filter_refuses_a_symlinked_root_when_nix_available() {
    use std::process::Command;

    if !cfg!(target_os = "linux") {
        eprintln!("Nix evaluation requires the project Linux execution boundary");
        return;
    }
    if Command::new("nix").arg("--version").output().is_err() {
        eprintln!("[nix_flake_structure::workspace_filter_eval] skipped — `nix` not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let canonical = tmp
        .path()
        .canonicalize()
        .expect("canonical tempdir")
        .join("ws");
    fs::create_dir_all(canonical.join("docs")).expect("mkdir workspace");
    fs::write(canonical.join("Cargo.toml"), "[workspace]\n").expect("write manifest");
    fs::write(canonical.join("Cargo.lock"), "version = 4\n").expect("write lockfile");
    fs::write(canonical.join("docs/a.md"), "not admitted\n").expect("write doc");
    let linked = tmp
        .path()
        .canonicalize()
        .expect("canonical tempdir")
        .join("link");
    std::os::unix::fs::symlink(&canonical, &linked).expect("symlink the workspace");

    let eval_file = repo_dir().join("nix/tests/workspace-filter-eval.nix");
    let expr = format!(
        "import {} {{ canonical = \"{}\"; linked = \"{}\"; }}",
        eval_file.display(),
        canonical.display(),
        linked.display()
    );
    let out = Command::new("nix")
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["eval", "--impure", "--json", "--expr", &expr])
        .output()
        .expect("nix eval invocation");
    assert!(
        out.status.success(),
        "nix eval failed:\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("workspace-filter-eval.nix returns JSON");
    for check in [
        "canonicalKeepsTheLockfile",
        "canonicalDropsUnlistedEntries",
        "linkedRootIsRefused",
    ] {
        assert_eq!(
            json[check],
            serde_json::Value::Bool(true),
            "{check}: {json}"
        );
    }
}

#[test]
fn mk_guest_eval_assertions_all_pass_when_nix_available() {
    use std::process::Command;

    if !cfg!(target_os = "linux") {
        eprintln!("mkGuest evaluation requires the project Linux execution boundary");
        return;
    }
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

/// The rootfs carries runtime mount targets and metadata, not boot logic.
/// The universal agent owns mounting the runtime and starting its services.
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
        content.contains("overlayAware = true"),
        "mk-guest.nix mvmMeta passthru must declare `overlayAware = true` \
         (Plan 74 W1.4b / ADR-018). Admission-time gates read this to \
         refuse boot of cached pre-W1.4b templates."
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
         universal initramfs agent owns runtime activation."
    );
}

#[test]
fn mk_guest_has_no_shell_init_or_legacy_boot_stages() {
    let content = fs::read_to_string(nix_dir().join("lib/mk-guest.nix"))
        .expect("mk-guest.nix must be readable");
    for obsolete in [
        "initText =",
        "initScript =",
        "\"$out/init\"",
        "\"$out/sbin/init\"",
        "mvm.chain_init",
        "mvm\\.chain_init",
        "/mnt/config",
        "/mnt/secrets",
        "mvm.secret_env",
        "bootCommand",
        "\"$out/etc/mvm/boot\"",
        "poweroff -f",
        "exec </dev/console",
        "MVM_RUNTIME_SOURCE_POLICY",
    ] {
        assert!(
            !content.contains(obsolete),
            "obsolete shell stage: {obsolete}"
        );
    }
    assert!(content.contains("initSystem = \"initramfs-agent\";"));
    assert!(content.contains(
        "\"mkGuest: /etc/mvm/base-image-contract is reserved for the base image contract\" 1;"
    ));
    assert!(content.contains("\"${toString baseImageContract}\\n\""));
    assert!(content.contains("cp ${baseImageContractFile} \"$out/etc/mvm/base-image-contract\""));
    assert!(content.contains("passwdText = builtins.seq assertDedicatedServiceUids"));
    let meta_start = content.find("mvmMeta = {").expect("metadata");
    let metadata = &content[meta_start..];
    assert!(metadata.contains("agent = workloadUid;"));
    assert!(metadata.contains("entrypoint = workloadUid;"));
    assert!(metadata.contains("rootlessEntrypoint = true;"));
    assert!(metadata.contains("declaredUids = resolvedUids;"));
}

#[test]
fn function_workloads_preserve_dispatch_payload_without_a_boot_command() {
    let workload = fs::read_to_string(nix_dir().join("lib/mkFunctionWorkload.nix"))
        .expect("function workload composition");
    assert!(workload.contains("command = [ \"/usr/lib/mvm/wrappers/runner\" ];"));
    assert!(workload.contains("extraFiles = factory.extraFiles // extraExtraFiles;"));
    let factory = fs::read_to_string(nix_dir().join("lib/factories/mkFunctionService.nix"))
        .expect("function service factory");
    for payload in [
        "link = appPkg;",
        "\"/etc/mvm/entrypoint\"",
        "\"/usr/lib/mvm/wrappers/runner\"",
        "\"/etc/mvm/wrapper.json\"",
        "\"/etc/mvm/runtime.json\"",
        "\"/etc/mvm/hooks/before_build.sh\"",
        "\"/etc/mvm/hooks/before_start.sh\"",
        "\"/etc/mvm/hooks/after_start.sh\"",
        "\"/etc/mvm/hooks/before_stop.sh\"",
        "source = hookScripts.before_start;",
        "servicePackages = lang.servicePackages;",
    ] {
        assert!(
            factory.contains(payload),
            "missing workload payload: {payload}"
        );
    }
    assert!(!factory.contains("bootScript"));
    assert!(!factory.contains("bootCommand"));
    let flake = fs::read_to_string(nix_dir().join("flake.nix")).expect("Nix flake");
    for witness in [
        "guest-initramfs-contract =",
        "test ! -e ${functionGuest.rootfsTree}/init",
        "test ! -L ${functionGuest.rootfsTree}/sbin/init",
        "cmp expected-contract ${functionGuest.rootfsTree}/etc/mvm/base-image-contract",
    ] {
        assert!(
            flake.contains(witness),
            "missing built-tree witness: {witness}"
        );
    }
}

/// Every mkGuest root names the identities the universal initramfs agent drops
/// to, under the same numbers and the workload's name and home. The agent
/// mounts the root read-only, so a number it uses that the root does not name
/// stays unnamed for the life of the guest.
#[test]
fn mk_guest_names_the_identities_the_initramfs_agent_uses() {
    use mvmctl::guest::guest_mount::{
        ADDON_DNS_IDENTITY, CRNG_RESEED_HELPER_UID, EGRESS_CLIENT_IDENTITY, WORKLOAD_HOME,
        WORKLOAD_UID,
    };
    use mvmctl::guest::workload_identity::WORKLOAD_USER;
    let content = fs::read_to_string(nix_dir().join("lib/mk-guest.nix"))
        .expect("mk-guest.nix must be readable");

    for binding in [
        format!("workloadUid = {WORKLOAD_UID};"),
        format!("addonDnsUid = {};", ADDON_DNS_IDENTITY.uid()),
        format!("crngReseedUid = {CRNG_RESEED_HELPER_UID};"),
        format!("egressUid = {};", EGRESS_CLIENT_IDENTITY.uid()),
    ] {
        assert!(content.contains(&binding), "mkGuest must bind {binding}");
    }
    let fixed_start = content
        .find("fixedIdentities = [")
        .expect("mkGuest declares its fixed identities");
    let fixed = &content[fixed_start..];
    let fixed = &fixed[..fixed.find("\n  ];").expect("the fixed list closes")];
    for uid in [
        "uid = 0;",
        "uid = workloadUid;",
        "uid = addonDnsUid;",
        "uid = crngReseedUid;",
        "uid = egressUid;",
    ] {
        assert!(fixed.contains(uid), "the fixed identities must carry {uid}");
    }
    assert!(
        fixed.contains(&format!("name = \"{WORKLOAD_USER}\";"))
            && fixed.contains(&format!("home = \"{WORKLOAD_HOME}\";")),
        "the workload row must use the agent's account name and home"
    );
    for (uid, service, guard) in [
        (987, "addon DNS resolver", "assertDedicatedAddonDnsUid"),
        (988, "CRNG reseed helper", "assertDedicatedCrngReseedUid"),
        (989, "FlowMux egress service", "assertDedicatedEgressUid"),
    ] {
        assert!(
            content.contains(&format!("uid {uid} is reserved for the {service}"))
                && content.contains(guard),
            "a collision with {service} uid {uid} must fail the image build"
        );
    }
    assert!(
        content.contains(r#"printf '%s' ${lib.escapeShellArg passwdText} > "$out/etc/passwd""#)
            && content
                .contains(r#"printf '%s' ${lib.escapeShellArg groupText} > "$out/etc/group""#),
        "the account databases are written from the identity rows and nothing else"
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

#[test]
fn guest_runtime_recipes_are_static_musl() {
    let guest_recipes = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("packages").join("guest.nix"))
            .expect("read nix/packages/guest.nix"),
    );
    for recipe in [
        "mvm-guest-agent",
        "mvm-egress-client",
        "mvm-addon-dns",
        "mvm-exit-report",
    ] {
        assert!(
            guest_recipes.contains(&format!(
                "{recipe} = import ./{recipe}.nix {{ pkgs = staticPkgs;"
            )),
            "the exported {recipe} recipe must be instantiated from pkgsStatic"
        );
    }
    let runner = fs::read_to_string(nix_dir().join("packages").join("mvm-runner.nix"))
        .expect("read nix/packages/mvm-runner.nix");
    assert!(
        runner.contains("pkgs.pkgsStatic.rustPlatform.buildRustPackage"),
        "the runner must use the static-musl Rust platform too"
    );
}

#[test]
fn sdk_sidecar_build_keeps_cargo_out_of_nixs_sentinel_home() {
    let content = fs::read_to_string("nix/packages/mvm-sdk-cdylib.nix")
        .expect("read SDK sidecar cdylib package");
    assert!(
        content.contains("HOME = \"/tmp\";"),
        "Stage 0 runs Nix without its inner sandbox, so Cargo must not create /homeless-shelter and wedge the next derivation"
    );
}

#[test]
fn gpu_shim_musl_build_uses_the_prebuilt_target_toolchain() {
    let content =
        fs::read_to_string("nix/packages/mvm-gpu-shims.nix").expect("read GPU shim package");

    assert!(
        content.contains("./embedded-rust-toolchain.nix")
            && content.contains("CARGO_BUILD_TARGET = muslTarget;")
            && content.contains("target-feature=-crt-static")
            && content.contains("linker=${muslLinker}"),
        "musl GPU cdylibs must use the cached native Rust toolchain with the musl target and linker"
    );
    assert!(
        !content.contains("pkgs.pkgsMusl.rustPlatform")
            && !content.contains("pkgsStatic.rustPlatform"),
        "GPU cdylibs must not rebuild a musl/static Rust and LLVM toolchain"
    );
    assert!(
        content.contains("buildMusl ? false") && content.contains("isMusl = buildMusl;"),
        "the musl selector must not be named `musl`, which callPackage auto-fills with pkgs.musl"
    );
    assert!(
        content.contains("expected a musl object (NEEDED libc.so)"),
        "the package must reject a musl-labelled shim linked against the wrong libc"
    );
}

/// The rootfs no-glibc gate anchors its grep on the glibc store path. A bare
/// `-glibc` pattern would fire on any derivation whose *name* happens to
/// contain the string. The overlay and SDK-sidecar closure gates live with the
/// images that carry them, in mvm-images.
#[test]
fn the_rootfs_closure_gate_pins_glibc_out_by_store_path() {
    let root = fs::read_to_string(nix_dir().join("flake.nix")).expect("root flake must be present");
    assert!(
        root.contains(r"'/nix/store/[a-z0-9]+-glibc(-|$)'"),
        "the rootfs no-glibc gate must anchor its grep on the glibc store path"
    );
}

/// The agent needs the sidecar mount target on the read-only root.
#[test]
fn mk_guest_carries_the_sdk_sidecar_mountpoint() {
    let content = fs::read_to_string(nix_dir().join("lib").join("mk-guest.nix"))
        .expect("nix/lib/mk-guest.nix must be present");

    assert!(
        content.contains(r#"mkdir -p "$out/mvm/sdk""#),
        "the read-only rootfs must carry the sidecar mountpoint"
    );
}

/// Egress identity and trust provisioning belong to the runtime, not Nix.
#[test]
fn mk_guest_does_not_reimplement_runtime_egress_provisioning() {
    let path = nix_dir().join("lib").join("mk-guest.nix");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("nix/lib/mk-guest.nix must be present: {e}"));

    assert!(
        !content.contains("mvm.egress_ca"),
        "mk-guest.nix must not read the egress CA off the kernel cmdline: the \
         certificate rides the per-boot identity drive and nothing emits that token."
    );

    // `cat baked egress-ca.crt` fuses the two armor lines when the baked bundle
    // has no trailing newline, and every PEM parser then reads one truncated
    // certificate. The Rust helper separates them; the shell must not reimplement it.
    assert!(
        !content.contains("cat /etc/ssl/certs/ca-bundle.crt /run/mvm/egress-ca.crt"),
        "the trust bundle must not be assembled by concatenation in the shell"
    );

    for obsolete in [
        "MVM_IDENTITY_PROVISION_COMMAND",
        "install-egress-ca-trust",
        "export SSL_CERT_FILE",
        "export NODE_EXTRA_CA_CERTS",
    ] {
        assert!(
            !content.contains(obsolete),
            "runtime-owned stage: {obsolete}"
        );
    }
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
fn mk_guest_can_omit_setpriv_for_a_builder_boot_payload() {
    let content = fs::read_to_string(nix_dir().join("lib/mk-guest.nix"))
        .expect("mk-guest.nix must be readable");
    let normalized = normalized_whitespace(&content);
    assert!(content.contains("withSetpriv ? true,"));
    assert!(normalized.contains("++ lib.optional withSetpriv setprivPkg ++"));
    assert!(content.contains("lib.optionalString withSetpriv"));
    assert!(normalized.contains(&format!(
        "else \"{}/mvm-setpriv\";",
        mvm_build::builder_guest_paths::RUNTIME_HOST_BIN_DIR
    )));
}

#[test]
fn builder_hook_uses_util_linux_losetup_before_the_mount_syscall() {
    let hook_path =
        repo_dir().join("crates/mvm-builder-guest/src/bin/mvm-host-vm-init/builder_hooks.rs");
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
    let normalized = normalized_whitespace(&content);

    assert!(
        normalized
            .contains("rootPaths = [ busybox ] ++ lib.optional withSetpriv setprivPkg ++ packages ++ extraFileSourceRoots")
            && !normalized.contains(
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
    let path = repo_dir().join(".github/workflows/ci-main.yml");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    assert!(
        content.contains("./nix#checks.x86_64-linux.guest-rootfs-package-budget"),
        "CI must realize the rootfs package-count budget, not only eval it"
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

/// The guest recipes every image needs, exported by `nix/flake.nix` as
/// `packages.<linux-system>.*`. This list is the interface an image
/// repository pins `mvm` for; renaming or dropping one breaks it.
const EXPORTED_GUEST_RECIPES: &[&str] = &[
    "mvm-guest-agent",
    "mvm-guest-agent-static",
    "mvm-setpriv",
    "mvm-runner",
    "mvm-egress-client",
    "mvm-addon-dns",
    "mvm-exit-report",
    "mvm-sdk-cdylib-glibc",
    "mvm-sdk-cdylib-musl",
];

#[test]
fn nix_flake_exports_the_guest_recipes_for_the_linux_systems() {
    let guest = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("packages").join("guest.nix"))
            .expect("nix/packages/guest.nix must be present"),
    );
    for name in EXPORTED_GUEST_RECIPES {
        assert!(
            guest.contains(&format!("{name} = ")),
            "nix/packages/guest.nix must define the exported recipe {name}"
        );
    }

    let flake = normalized_whitespace(
        &fs::read_to_string(nix_dir().join("flake.nix")).expect("nix/flake.nix must be present"),
    );
    assert!(
        flake.contains("guestPackagesFor = system: import ./packages/guest.nix {")
            && flake.contains("mvmSrc = workspaceSrc;"),
        "nix/flake.nix must build the guest recipes from the same workspace source as mkGuest"
    );
    assert!(
        flake.contains(
            "// nixpkgs.lib.optionalAttrs (builtins.elem system systems) (guestPackagesFor system)"
        ),
        "the guest recipes must be exported under packages for the Linux image systems only"
    );
    assert!(
        flake.contains("hostBinaries = import ./lib/mvm-host-binaries.nix;"),
        "nix/flake.nix must export the host-binaries manifest under lib.<system>"
    );
    assert!(
        flake.contains("libFor { inherit system; } // {"),
        "the exported lib.<system> must still be the mkGuest library, extended not replaced"
    );
}
