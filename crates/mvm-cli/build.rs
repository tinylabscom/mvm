#[path = "build_aux_helpers.rs"]
mod build_aux_helpers;
#[path = "src/host_binaries/toolchain.rs"]
mod host_binaries_toolchain;

use std::path::{Path, PathBuf};
use std::process::Command;

use host_binaries_toolchain::{
    Pin, pinned_zig_path_or_fail, rustup_cargo_and_rustc, strip_glibc,
    workspace_root_from_manifest_dir,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmbeddedSourceBinary {
    package: String,
    name: String,
    features: String,
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = workspace_root_from_manifest_dir(&manifest_dir);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let bins_out = out_dir.join("mvm-host-bins");
    std::fs::create_dir_all(&bins_out).expect("create OUT_DIR/mvm-host-bins");

    // The nested `cargo {build,zigbuild}` that compiles the host-vm binaries
    // MUST use its own target dir. The outer `cargo build` (mvmctl) holds an
    // exclusive lock on the workspace `target/` for its whole run, including
    // while this build script executes; a nested cargo aimed at the same
    // `target/` blocks on that lock forever — the outer build waits on this
    // script, this script waits on the nested cargo, the nested cargo waits
    // on the outer's lock. That deadlock is why cold release builds hung
    // (warm builds slip through because the nested step does almost nothing).
    // A separate target dir under the profile's build directory has its own
    // lock → no contention. It is shared across mvm-cli feature fingerprints,
    // so identical embedded binaries are not rebuilt for each OUT_DIR.
    let nested_target_dir = build_aux_helpers::shared_nested_target_dir(&out_dir);
    let host_target_dir = nested_target_dir.join("host-vm-target");

    let pin = read_pinned_toolchain(&workspace_root);
    println!("cargo:rustc-env=MVM_PINNED_ZIG={}", pin.zig);
    println!(
        "cargo:rustc-env=MVM_PINNED_CARGO_ZIGBUILD={}",
        pin.cargo_zigbuild
    );
    println!("cargo:rustc-env=MVM_PINNED_TARGET={}", pin.target);
    println!("cargo:rerun-if-env-changed=MVM_EMBED_CARGO");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_RUSTC");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_ZIG");

    // HOST_BINARIES (installed into the builder/dev VM rootfs), SEED_BINARIES
    // (host-side only, e.g. the Stage 0 nix-seed's /init), and bootstrap
    // support binaries all get cross-compiled + embedded. The support list
    // includes binaries owned by crates other than mvm-build, so retain the
    // package name alongside each binary instead of assuming one package.
    let mut manifest: Vec<EmbeddedSourceBinary> = read_rust_manifest(&workspace_root)
        .into_iter()
        .chain(read_seed_binaries(&workspace_root))
        .map(|name| EmbeddedSourceBinary {
            package: "mvm-build".to_string(),
            name,
            features: String::new(),
        })
        .collect();
    manifest.extend(read_bootstrap_support_binaries(&workspace_root));
    let mut entries = Vec::new();

    // The host-vm bins are statically musl-linked and embedded for the host
    // arch (`pin.target`, picked from CARGO_CFG_TARGET_ARCH). They
    // are always cross-compiled with cargo-zigbuild, even when host arch ==
    // target arch: `ring` (pulled transitively) compiles C, so the musl target
    // needs a musl *C* cross-compiler. zig supplies it; a plain
    // `cargo build --target <arch>-musl` would instead demand a system
    // `<arch>-linux-musl-gcc`, which neither CI nor the documented contributor
    // setup carries (both standardize on zig + cargo-zigbuild — see CLAUDE.md
    // "Host dependencies"). zigbuild is the single portable path. (A same-arch
    // plain-`cargo build` fast-path was once tried on the false premise that
    // the bins are C-free; it broke CI, which has no musl-gcc.)

    // The musl cross-compile is ~93% of this build script's wall time (measured:
    // 105s for one binary, ~163s for the set, against 13s for the whole native
    // aux-helper leg). Every one of these binaries links `mvm-build` ->
    // `mvm-core`, so any edit under `mvm-core/src` invalidates all six and a
    // one-line change costs ~176s before a single test runs.
    //
    // Outside `--release`, reuse an already-cross-compiled binary instead of
    // rebuilding it. The embedded set still exists and still hashes, so the
    // extraction tests and the manifest gate keep passing on their real bytes;
    // they assert the *name set*, the *SHA match* and *idempotency*, none of
    // which require the bytes to be freshly compiled. A release build never
    // takes this path, so shipped binaries are always rebuilt from source.
    //
    // The native per-VM helpers deliberately do NOT get this treatment: they
    // are the supervisors where a stale binary silently produces a running
    // guest that ignores your edit, and rebuilding them costs 13s.
    // Explicitly opt IN only the plain debug profile. Cargo reports PROFILE as
    // "debug"/"release"; keying on `!= "release"` would silently take the reuse
    // path for any custom profile (e.g. `release-witness`) that reports
    // something else, which is exactly the case where fresh bytes matter.
    let reuse_prebuilt_embedded = std::env::var("PROFILE").unwrap_or_default() == "debug";
    let mut reused_any = false;

    for binary in &manifest {
        let out_file = bins_out.join(&binary.name);
        let prebuilt = host_target_dir
            .join(strip_glibc(&pin.target))
            .join("release")
            .join(&binary.name);
        if reuse_prebuilt_embedded && prebuilt.is_file() {
            eprintln!(
                "[build.rs] reusing prebuilt {} (dev profile; `cargo build --release` \
                 or `just embed-refresh` rebuilds it)",
                binary.name
            );
            std::fs::copy(&prebuilt, &out_file).unwrap_or_else(|e| {
                panic!("copy {} -> {}: {e}", prebuilt.display(), out_file.display())
            });
            reused_any = true;
            let sha = sha256_hex(&out_file);
            entries.push((binary.name.clone(), out_file.clone(), sha));
            continue;
        }
        run_cargo_zigbuild(
            ZigbuildRequest::default()
                .with_root(&workspace_root)
                .with_target_dir(&host_target_dir)
                .with_package(&binary.package)
                .with_binary(&binary.name)
                .with_features(&binary.features)
                .with_target(&pin.target)
                .with_zig_pin(&pin.zig)
                .with_output(&out_file)
                .build(),
        );
        let sha = sha256_hex(&out_file);
        entries.push((binary.name.clone(), out_file.clone(), sha));
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join("crates/mvm-build/src/bin").display()
        );
    }

    // Loud, not silent: the runtime can tell the user their embedded set was
    // reused rather than rebuilt, which is the difference between a confusing
    // "my edit did nothing" boot and an actionable message.
    println!(
        "cargo:rustc-env=MVM_EMBEDDED_BINS_REUSED={}",
        if reused_any { "1" } else { "0" }
    );

    build_native_aux_helpers(&workspace_root, &nested_target_dir);

    let embedded_rs = render_embedded_rs(&entries);
    std::fs::write(out_dir.join("embedded.rs"), embedded_rs).unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root
            .join("crates/mvm-cli/src/host_binaries/manifest.rs")
            .display()
    );
    // The embedded binaries' bytes are the authoritative builder-VM
    // fingerprint input, so they must rebuild when their real inputs change —
    // not just their `src/bin/` entrypoints. Watch the workspace lockfile (a
    // dep bump in their closure) and the whole `mvm-build` lib they link.
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    // Same file-by-file watch for the `mvm-build` lib the host bins link (a
    // content edit there must re-cross-compile the embedded host bins).
    emit_rerun_for_tree(&workspace_root.join("crates/mvm-build/src"));
}

/// Emit one `cargo:rerun-if-changed` per file under `root`, recursively. Unlike
/// a single directory-level `rerun-if-changed` (which cargo does not reliably
/// re-trigger on a content edit to an existing file), this forces the build
/// script — and therefore the embedded-binary cross-compile — to re-run whenever
/// any watched source file changes. Missing trees are silently skipped (the
/// dir-level watch already fails soft the same way).
fn emit_rerun_for_tree(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_for_tree(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Compile the native per-VM host helpers into a dedicated target dir under
/// OUT_DIR and export that dir as `MVM_AUX_BIN_DIR`, so `cargo run` produces
/// them during its build phase rather than mvmctl shelling out to `cargo` at
/// run time. The dedicated target dir avoids the outer build-lock deadlock the
/// same way the embedded-bins path does (see the note in `main`).
fn build_native_aux_helpers(workspace_root: &Path, nested_target_dir: &Path) {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let aux_target = nested_target_dir.join("aux-helper-target");
    let bin_dir = aux_target.join(&profile);

    // Always export the dir — even on skip or an unbuildable helper — so
    // `env!("MVM_AUX_BIN_DIR")` compiles in mvm-cli; resolution `is_file`-checks
    // each candidate, so a dir with missing bins is harmless.
    println!("cargo:rustc-env=MVM_AUX_BIN_DIR={}", bin_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-hostd/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-core/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/deps/libkrun-sys/src").display()
    );
    // The per-VM supervisors link `mvm-runtime` — it owns the VMM, the device
    // model, and the FDT the guest boots on. Without this watch an edit there
    // rebuilds `mvmctl` but leaves the supervisor binaries stale, so the change
    // never reaches a running guest and the edit appears to do nothing. Use the
    // file-by-file walk rather than a directory entry, for the same reason the
    // `mvm-build` watch does.
    emit_rerun_for_tree(&workspace_root.join("crates/mvm-runtime/src"));

    let libkrun_present = libkrun_header_present();
    for spec in build_aux_helpers::aux_helper_specs(&target_os, &target_arch, libkrun_present) {
        run_cargo_native_build(workspace_root, &aux_target, &profile, &spec);
    }
}

/// Nested native `cargo build` for one helper into `target_dir`. Fail-open: a
/// helper this host can't build must not break the outer compile — aux_bin
/// surfaces a precise error only if the helper is actually needed at run time.
fn run_cargo_native_build(
    root: &Path,
    target_dir: &Path,
    profile: &str,
    spec: &build_aux_helpers::AuxHelperSpec,
) {
    eprintln!(
        "[build.rs] building per-VM host helper: {} (-p {})",
        spec.bin, spec.package
    );
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "-p", spec.package, "--bin", spec.bin]);
    if profile == "release" {
        cmd.arg("--release");
    }
    if !spec.features.is_empty() {
        cmd.arg("--features").arg(spec.features.join(","));
    }
    // Dedicated target dir — the outer `cargo` holds the workspace `target/`
    // lock for the whole build-script run; a nested cargo aimed at it deadlocks.
    cmd.env("CARGO_TARGET_DIR", target_dir).current_dir(root);
    match cmd.status() {
        Ok(status) if status.success() => {}
        other => eprintln!(
            "[build.rs] per-VM helper {} not built ({other:?}); it will be \
             resolved at run time only if needed",
            spec.bin
        ),
    }
}

/// Whether `libkrun.h` is installed, mirroring the probe `libkrun-sys`'s build
/// script uses to decide the `-lkrun` link. Gate for building the libkrun
/// supervisor so an HVF-only / CI host does not attempt (and noisily fail) it.
fn libkrun_header_present() -> bool {
    if let Some(p) = std::env::var_os("MVM_LIBKRUN_HEADER")
        && Path::new(&p).is_file()
    {
        return true;
    }
    [
        "/opt/homebrew/include/libkrun.h",
        "/usr/local/include/libkrun.h",
        "/usr/include/libkrun.h",
    ]
    .iter()
    .any(|p| Path::new(p).is_file())
}

fn read_pinned_toolchain(root: &Path) -> Pin {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH is set by cargo for build scripts");
    host_binaries_toolchain::read_pinned_toolchain(root, &arch)
}

#[cfg(test)]
fn resolve_target_for_arch(toolchain: &toml::Value, arch: &str) -> String {
    host_binaries_toolchain::resolve_target_for_arch(toolchain, arch)
}

/// Parse `name:` fields from the Rust struct literals in
/// `crates/mvm-cli/src/host_binaries/manifest.rs`.
///
/// Returns binary names in declaration order. Each name is a `[[bin]]`
/// of `mvm-build` — the build script cross-compiles each
/// with `cargo build -p mvm-build --bin <name>`.
fn read_rust_manifest(root: &Path) -> Vec<String> {
    let src =
        std::fs::read_to_string(root.join("crates/mvm-cli/src/host_binaries/manifest.rs")).unwrap();
    read_quoted_field_block(&src, "HOST_BINARIES", "name:")
}

/// Parse the bare-string array `pub const SEED_BINARIES: &[&str] = &[ ... ]`
/// from `manifest.rs`. These are host-side-only embedded binaries (no VM
/// install_path, absent from the nix attrset).
fn read_seed_binaries(root: &Path) -> Vec<String> {
    let src =
        std::fs::read_to_string(root.join("crates/mvm-cli/src/host_binaries/manifest.rs")).unwrap();
    read_quoted_strings_block(&src, "SEED_BINARIES")
}

/// Parse bootstrap support binaries from `manifest.rs`. These binaries are
/// mounted under `/mvm-bins` before the builder rootfs has its normal runtime
/// contents, so they must be embedded even though they are not installed into
/// the steady-state VM image.
fn read_bootstrap_support_binaries(root: &Path) -> Vec<EmbeddedSourceBinary> {
    let src =
        std::fs::read_to_string(root.join("crates/mvm-cli/src/host_binaries/manifest.rs")).unwrap();
    parse_bootstrap_support_binaries(&src)
}

fn parse_bootstrap_support_binaries(src: &str) -> Vec<EmbeddedSourceBinary> {
    let packages = read_quoted_field_block(src, "BOOTSTRAP_SUPPORT_BINARIES", "package:");
    let names = read_quoted_field_block(src, "BOOTSTRAP_SUPPORT_BINARIES", "name:");
    let features = read_quoted_field_block(src, "BOOTSTRAP_SUPPORT_BINARIES", "features:");
    assert_eq!(
        packages.len(),
        names.len(),
        "bootstrap support binary package/name entries must be paired"
    );
    assert_eq!(
        packages.len(),
        features.len(),
        "bootstrap support binary package/name/features entries must be paired"
    );
    packages
        .into_iter()
        .zip(names)
        .zip(features)
        .map(|((package, name), features)| EmbeddedSourceBinary {
            package,
            name,
            features,
        })
        .collect()
}

fn read_manifest_section<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(name)
        .unwrap_or_else(|| panic!("{name} declaration in manifest.rs"));
    let rest = &src[start..];
    let end = rest.find("];").map(|i| i + 2).unwrap_or(rest.len());
    &rest[..end]
}

fn read_quoted_field_block(src: &str, section: &str, field: &str) -> Vec<String> {
    read_manifest_section(src, section)
        .lines()
        .filter_map(|line| build_aux_helpers::extract_quoted_after(line, field))
        .collect()
}

fn read_quoted_strings_block(src: &str, section: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut s = read_manifest_section(src, section);
    while let Some(q1) = s.find('"') {
        let after = &s[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        out.push(after[..q2].to_string());
        s = &after[q2 + 1..];
    }
    out
}

#[derive(Default)]
struct ZigbuildRequest<'a> {
    root: Option<&'a Path>,
    target_dir: Option<&'a Path>,
    package: Option<&'a str>,
    binary: Option<&'a str>,
    features: Option<&'a str>,
    target: Option<&'a str>,
    zig_pin: Option<&'a str>,
    output: Option<&'a Path>,
}

impl<'a> ZigbuildRequest<'a> {
    fn with_root(mut self, root: &'a Path) -> Self {
        self.root = Some(root);
        self
    }

    fn with_target_dir(mut self, target_dir: &'a Path) -> Self {
        self.target_dir = Some(target_dir);
        self
    }

    fn with_package(mut self, package: &'a str) -> Self {
        self.package = Some(package);
        self
    }

    fn with_binary(mut self, binary: &'a str) -> Self {
        self.binary = Some(binary);
        self
    }

    fn with_features(mut self, features: &'a str) -> Self {
        self.features = Some(features);
        self
    }

    fn with_target(mut self, target: &'a str) -> Self {
        self.target = Some(target);
        self
    }

    fn with_zig_pin(mut self, zig_pin: &'a str) -> Self {
        self.zig_pin = Some(zig_pin);
        self
    }

    fn with_output(mut self, output: &'a Path) -> Self {
        self.output = Some(output);
        self
    }

    fn build(self) -> ZigbuildSpec<'a> {
        ZigbuildSpec {
            root: self.root.expect("zigbuild request root"),
            target_dir: self.target_dir.expect("zigbuild request target dir"),
            package: self.package.expect("zigbuild request package"),
            binary: self.binary.expect("zigbuild request binary"),
            features: self.features.expect("zigbuild request features"),
            target: self.target.expect("zigbuild request target"),
            zig_pin: self.zig_pin.expect("zigbuild request Zig pin"),
            output: self.output.expect("zigbuild request output"),
        }
    }
}

struct ZigbuildSpec<'a> {
    root: &'a Path,
    target_dir: &'a Path,
    package: &'a str,
    binary: &'a str,
    features: &'a str,
    target: &'a str,
    zig_pin: &'a str,
    output: &'a Path,
}

fn run_cargo_zigbuild(spec: ZigbuildSpec<'_>) {
    eprintln!(
        "[build.rs] cargo zigbuild --release --target {} -p {} --bin {}",
        spec.target, spec.package, spec.binary
    );
    // We need the rustup-managed cargo, not the Homebrew one. The Homebrew
    // cargo sets RUSTC=rustc which doesn't have the cross targets, and that
    // value propagates into the nested `cargo build` that cargo-zigbuild
    // spawns. Using the rustup cargo avoids that.
    let (cargo, rustc) = rustup_cargo_and_rustc(strip_glibc(spec.target));
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "zigbuild",
        "--release",
        "--target",
        spec.target,
        "-p",
        spec.package,
        "--bin",
        spec.binary,
    ]);
    if !spec.features.is_empty() {
        cmd.args(["--features", spec.features]);
    }
    cmd.env("RUSTC", &rustc)
        // Dedicated target dir — see the deadlock note in main().
        .env("CARGO_TARGET_DIR", spec.target_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .current_dir(spec.root);
    apply_zigbuild_env(&mut cmd, spec.target_dir);
    // Pin the zig binary cargo-zigbuild uses. Left to PATH, a Homebrew-upgraded
    // zig (newer than the pin) fails downstream with a cryptic `CacheCheckFailed`.
    if let Some(zig) = pinned_zig_path_or_fail(spec.zig_pin) {
        cmd.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    let status = cmd.status().expect(
        "spawn `cargo zigbuild` — \
         install with: `cargo install cargo-zigbuild --version 0.20.0`",
    );
    assert!(
        status.success(),
        "cargo zigbuild failed for package {}, binary {}",
        spec.package,
        spec.binary
    );
    let built = spec
        .target_dir
        .join(strip_glibc(spec.target))
        .join("release")
        .join(spec.binary);
    std::fs::copy(&built, spec.output)
        .unwrap_or_else(|e| panic!("copy {} → {}: {e}", built.display(), spec.output.display()));
}

fn apply_zigbuild_env(cmd: &mut Command, target_dir: &Path) {
    // Keep cargo-zigbuild and Zig caches scoped under the dedicated nested
    // target root instead of platform-global defaults like
    // `~/Library/Caches/cargo-zigbuild`, which makes source builds depend on
    // unrelated host cache permissions and breaks sandboxed verification.
    let zigbuild_cache_dir = zigbuild_cache_dir(target_dir);
    let zig_global_cache_dir = zig_global_cache_dir(target_dir);
    std::fs::create_dir_all(&zigbuild_cache_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", zigbuild_cache_dir.display()));
    std::fs::create_dir_all(&zig_global_cache_dir)
        .unwrap_or_else(|e| panic!("create {}: {e}", zig_global_cache_dir.display()));
    cmd.env("CARGO_ZIGBUILD_CACHE_DIR", zigbuild_cache_dir);
    cmd.env("ZIG_GLOBAL_CACHE_DIR", zig_global_cache_dir);
}

fn zigbuild_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("cargo-zigbuild", target_dir)
}

fn zig_global_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("zig", target_dir)
}

fn scoped_tool_cache_dir(tool: &str, target_dir: &Path) -> PathBuf {
    target_dir
        .parent()
        .unwrap_or(target_dir)
        .join("tool-cache")
        .join(tool)
}

fn sha256_hex(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

fn render_embedded_rs(entries: &[(String, PathBuf, String)]) -> String {
    let mut s = String::new();
    s.push_str("// Generated by mvm-cli/build.rs. Do not edit.\n\n");
    s.push_str(
        "pub struct EmbeddedBinary { \
         pub name: &'static str, \
         pub bytes: &'static [u8], \
         pub sha256_hex: &'static str \
         }\n\n",
    );
    s.push_str("pub const EMBEDDED: &[EmbeddedBinary] = &[\n");
    for (name, path, sha) in entries {
        s.push_str(&format!(
            "    EmbeddedBinary {{ name: {name:?}, bytes: include_bytes!({path:?}), sha256_hex: {sha:?} }},\n"
        ));
    }
    s.push_str("];\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_glibc_removes_version_suffix() {
        assert_eq!(
            strip_glibc("aarch64-unknown-linux-gnu.2.17"),
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(
            strip_glibc("aarch64-unknown-linux-gnu"),
            "aarch64-unknown-linux-gnu"
        );
    }

    #[test]
    fn parses_bootstrap_support_binaries_with_their_own_package() {
        let src = r#"
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[
    SourceBuiltBinary {
        package: "mvm-agentd",
        name: "mvm-egress-client",
        features: "addons",
    },
];
"#;
        assert_eq!(
            parse_bootstrap_support_binaries(src),
            vec![EmbeddedSourceBinary {
                package: "mvm-agentd".to_string(),
                name: "mvm-egress-client".to_string(),
                features: "addons".to_string(),
            }]
        );
    }

    #[test]
    fn resolve_target_for_arch_picks_pinned_triple() {
        let toolchain: toml::Value = toml::from_str(
            "zig = \"0.13.0\"\n\
             cargo-zigbuild = \"0.20.0\"\n\
             [targets]\n\
             aarch64 = \"aarch64-unknown-linux-musl\"\n\
             x86_64 = \"x86_64-unknown-linux-musl\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_target_for_arch(&toolchain, "aarch64"),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            resolve_target_for_arch(&toolchain, "x86_64"),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    #[should_panic(expected = "does not yet")]
    fn resolve_target_for_arch_unsupported_arch_panics() {
        let toolchain: toml::Value =
            toml::from_str("[targets]\naarch64 = \"aarch64-unknown-linux-musl\"\n").unwrap();
        let _ = resolve_target_for_arch(&toolchain, "riscv64");
    }

    #[test]
    fn configured_embed_tools_prefers_explicit_rustc() {
        assert_eq!(
            configured_embed_tools_from(
                Some("/nix/store/cargo/bin/cargo".to_string()),
                Some("/nix/store/rustc/bin/rustc".to_string()),
            ),
            Some((
                "/nix/store/cargo/bin/cargo".to_string(),
                "/nix/store/rustc/bin/rustc".to_string(),
            ))
        );
    }

    #[test]
    fn configured_embed_tools_defaults_cargo_when_only_rustc_is_set() {
        assert_eq!(
            configured_embed_tools_from(None, Some("/toolchain/bin/rustc".to_string())),
            Some(("cargo".to_string(), "/toolchain/bin/rustc".to_string()))
        );
    }

    #[test]
    fn zigbuild_cache_dirs_live_next_to_nested_target_dir() {
        let target_dir = Path::new("/tmp/build/out/host-vm-target");
        assert_eq!(
            zigbuild_cache_dir(target_dir),
            PathBuf::from("/tmp/build/out/tool-cache/cargo-zigbuild")
        );
        assert_eq!(
            zig_global_cache_dir(target_dir),
            PathBuf::from("/tmp/build/out/tool-cache/zig")
        );
    }

    #[test]
    fn host_binary_manifest_excludes_bootstrap_support_entries() {
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary { name: "mvm-host-vm-init", install_path: "/sbin/mvm-host-vm-init", mode: 0o755 },
    HostBinary { name: "mvm-builderd", install_path: "/sbin/mvm-builderd", mode: 0o755 },
];
pub const SEED_BINARIES: &[&str] = &["stage0-init"];
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-agentd",
    name: "mvm-egress-client",
    features: "addons",
}];
"#;
        assert_eq!(
            read_quoted_field_block(src, "HOST_BINARIES", "name:"),
            vec!["mvm-host-vm-init".to_string(), "mvm-builderd".to_string()]
        );
    }
}
