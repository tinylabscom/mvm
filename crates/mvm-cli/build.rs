#[path = "build_embed_mode.rs"]
mod build_embed_mode;

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
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
    // A separate target dir under OUT_DIR has its own lock → no contention,
    // and it persists across rebuilds for incremental reuse.
    let host_target_dir = out_dir.join("host-vm-target");

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

    // HOST_BINARIES (installed into the builder/dev VM rootfs) + SEED_BINARIES
    // (host-side only, e.g. the Stage 0 nix-seed's /init). Both are
    // `mvm-build` `[[bin]]`s; both get cross-compiled + embedded the same way.
    let mut manifest = read_rust_manifest(&workspace_root);
    manifest.extend(read_seed_binaries(&workspace_root));
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

    // Build policy:
    // - `MVM_SKIP_EMBED_BINARIES=1` always skips the nested cross-compile.
    // - `MVM_EMBED_BINARIES=1` always performs the real embed, even in dev/test.
    // - Otherwise, release builds embed the real binaries and non-release
    //   builds bake zero-byte stubs.
    //
    // This keeps production artifacts reproducible by default while removing
    // the dominant cold-build tax from ordinary `cargo check`/`cargo test`
    // contributor workflows.
    let skip_embed = should_skip_embed_binaries();
    println!("cargo:rerun-if-env-changed=MVM_SKIP_EMBED_BINARIES");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_BINARIES");
    if skip_embed {
        println!(
            "cargo:warning=embedding zero-byte host-vm stubs for this non-release build; \
             set MVM_EMBED_BINARIES=1 to force real embedded binaries"
        );
    }

    for name in manifest.iter() {
        let out_file = bins_out.join(name);
        if skip_embed {
            std::fs::write(&out_file, b"")
                .unwrap_or_else(|e| panic!("write stub {}: {e}", out_file.display()));
        } else {
            run_cargo_zigbuild(
                &workspace_root,
                &host_target_dir,
                name,
                &pin.target,
                &pin.zig,
                &out_file,
            );
        }
        let sha = sha256_hex(&out_file);
        entries.push((name.clone(), out_file.clone(), sha));
        println!(
            "cargo:rerun-if-changed={}",
            workspace_root.join("crates/mvm-build/src/bin").display()
        );
    }

    // Guest runtime binaries (OCI PID 1 + entrypoint runner + agent + netinit + egress-client,
    // guest arch = host arch). Embedded alongside the host bins so an end-user mvmctl with no
    // source checkout can inject them into an OCI `run --image` rootfs. Built in
    // one cargo invocation; they ride the same `EMBEDDED` array and are looked
    // up by name. Honors MVM_SKIP_EMBED_BINARIES (zero-byte stubs) — a stub
    // build can't materialize an OCI run, same as the host bins.
    if !skip_embed {
        run_guest_zigbuild(
            &workspace_root,
            &host_target_dir,
            &pin.target,
            &pin.zig,
            &bins_out,
        );
    }
    for name in [
        "mvm-oci-init",
        "mvm-oci-entrypoint",
        "mvm-guest-agent",
        "mvm-guest-netinit",
        "mvm-egress-client",
    ] {
        let out_file = bins_out.join(name);
        if skip_embed {
            std::fs::write(&out_file, b"")
                .unwrap_or_else(|e| panic!("write stub {}: {e}", out_file.display()));
        }
        let sha = sha256_hex(&out_file);
        entries.push((name.to_string(), out_file, sha));
    }
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-guest/src").display()
    );

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
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/mvm-build/src").display()
    );
}

struct Pin {
    zig: String,
    cargo_zigbuild: String,
    target: String,
}

fn should_skip_embed_binaries() -> bool {
    build_embed_mode::should_skip_embed_binaries(
        std::env::var("PROFILE").ok().as_deref(),
        std::env::var("MVM_SKIP_EMBED_BINARIES").ok().as_deref(),
        std::env::var("MVM_EMBED_BINARIES").ok().as_deref(),
    )
}

fn read_pinned_toolchain(root: &Path) -> Pin {
    let toml_str = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let v: toml::Value = toml::from_str(&toml_str).unwrap();
    let p = &v["workspace"]["metadata"]["mvm"]["toolchain"];
    // The embed target follows the arch mvmctl is built for: the local
    // builder/Stage 0 VM is always same-arch as the host, so an x86_64
    // mvmctl must embed x86_64 bins and an aarch64 mvmctl aarch64 bins.
    // `CARGO_CFG_TARGET_ARCH` is set by cargo for build scripts.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH is set by cargo for build scripts");
    Pin {
        zig: p["zig"].as_str().unwrap().to_string(),
        cargo_zigbuild: p["cargo-zigbuild"].as_str().unwrap().to_string(),
        target: resolve_target_for_arch(p, &arch),
    }
}

/// Resolve the pinned musl target triple for `arch` from the
/// `[workspace.metadata.mvm.toolchain.targets]` table. Fails closed on an
/// arch with no pinned target (mvmctl doesn't support that guest arch yet).
fn resolve_target_for_arch(toolchain: &toml::Value, arch: &str) -> String {
    toolchain
        .get("targets")
        .and_then(|t| t.get(arch))
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| {
            panic!(
                "no embedded-host-binary target pinned for arch `{arch}` in \
                 [workspace.metadata.mvm.toolchain.targets] — mvmctl does not yet \
                 support this guest arch (Plan 164). Add a `{arch} = \"...-musl\"` entry."
            )
        })
        .to_string()
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
    let mut out = Vec::new();
    for line in src.lines() {
        if let Some(n) = extract_quoted_after(line, "name:") {
            out.push(n);
        }
    }
    out
}

/// Parse the bare-string array `pub const SEED_BINARIES: &[&str] = &[ ... ]`
/// from `manifest.rs`. These are host-side-only embedded binaries (no VM
/// install_path, absent from the nix attrset).
fn read_seed_binaries(root: &Path) -> Vec<String> {
    let src =
        std::fs::read_to_string(root.join("crates/mvm-cli/src/host_binaries/manifest.rs")).unwrap();
    let Some(start) = src.find("SEED_BINARIES") else {
        return Vec::new();
    };
    // Everything from the declaration to the array terminator `];`.
    let rest = &src[start..];
    let end = rest.find("];").map(|i| i + 2).unwrap_or(rest.len());
    let block = &rest[..end];
    let mut out = Vec::new();
    let mut s = block;
    while let Some(q1) = s.find('"') {
        let after = &s[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        out.push(after[..q2].to_string());
        s = &after[q2 + 1..];
    }
    out
}

/// Extract the first double-quoted string on `line` that appears after `key`.
fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)? + key.len();
    let rest = &line[i..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')?;
    Some(rest[q1..q1 + q2].to_string())
}

/// Strip the optional glibc version suffix from a target triple to get
/// the rustup target name / `target/<triple>` output dir.
/// e.g. `aarch64-unknown-linux-gnu.2.17` → `aarch64-unknown-linux-gnu`;
/// a suffix-less triple like `aarch64-unknown-linux-musl` is unchanged.
fn strip_glibc(t: &str) -> &str {
    t.split('.').next().unwrap()
}

fn run_cargo_zigbuild(
    root: &Path,
    target_dir: &Path,
    pkg: &str,
    target: &str,
    zig_pin: &str,
    out: &Path,
) {
    eprintln!("[build.rs] cargo zigbuild --release --target {target} -p mvm-build --bin {pkg}");
    // We need the rustup-managed cargo, not the Homebrew one. The Homebrew
    // cargo sets RUSTC=rustc which doesn't have the cross targets, and that
    // value propagates into the nested `cargo build` that cargo-zigbuild
    // spawns. Using the rustup cargo avoids that.
    let (cargo, rustc) = rustup_cargo_and_rustc(strip_glibc(target));
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "zigbuild",
        "--release",
        "--target",
        target,
        "-p",
        "mvm-build",
        "--bin",
        pkg,
    ])
    .env("RUSTC", &rustc)
    // Dedicated target dir — see the deadlock note in main().
    .env("CARGO_TARGET_DIR", target_dir)
    .env_remove("RUSTUP_TOOLCHAIN")
    .env_remove("RUSTC_WRAPPER")
    .env_remove("RUSTC_WORKSPACE_WRAPPER")
    .current_dir(root);
    // Pin the zig binary cargo-zigbuild uses. Left to PATH, a Homebrew-upgraded
    // zig (newer than the pin) fails downstream with a cryptic `CacheCheckFailed`.
    if let Some(zig) = pinned_zig_path_or_fail(zig_pin) {
        cmd.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    let status = cmd.status().expect(
        "spawn `cargo zigbuild` — \
         install with: `cargo install cargo-zigbuild --version 0.20.0`",
    );
    assert!(status.success(), "cargo zigbuild failed for {pkg}");
    let built = target_dir
        .join(strip_glibc(target))
        .join("release")
        .join(pkg);
    std::fs::copy(&built, out)
        .unwrap_or_else(|e| panic!("copy {} → {}: {e}", built.display(), out.display()));
}

/// Cross-compile the guest runtime binaries (one invocation, dev-shell feature)
/// to the static musl `target`, copying them into `out_dir`. Same zig/rustup
/// handling as `run_cargo_zigbuild`.
fn run_guest_zigbuild(root: &Path, target_dir: &Path, target: &str, zig_pin: &str, out_dir: &Path) {
    eprintln!(
        "[build.rs] cargo zigbuild --release --target {target} -p mvm-guest \
         --bin mvm-oci-init --bin mvm-oci-entrypoint --bin mvm-guest-agent --bin mvm-guest-netinit -p mvm-guest-helpers \
         --bin mvm-egress-client --features mvm-guest/dev-shell"
    );
    let (cargo, rustc) = rustup_cargo_and_rustc(strip_glibc(target));
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "zigbuild",
        "--release",
        "--target",
        target,
        "-p",
        "mvm-guest",
        "--bin",
        "mvm-oci-init",
        "--bin",
        "mvm-oci-entrypoint",
        "--bin",
        "mvm-guest-agent",
        "--bin",
        "mvm-guest-netinit",
        "-p",
        "mvm-guest-helpers",
        "--bin",
        "mvm-egress-client",
        "--features",
        "mvm-guest/dev-shell",
    ])
    .env("RUSTC", &rustc)
    .env("CARGO_TARGET_DIR", target_dir)
    .env_remove("RUSTUP_TOOLCHAIN")
    .env_remove("RUSTC_WRAPPER")
    .env_remove("RUSTC_WORKSPACE_WRAPPER")
    .current_dir(root);
    if let Some(zig) = pinned_zig_path_or_fail(zig_pin) {
        cmd.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    let status = cmd
        .status()
        .expect("spawn `cargo zigbuild` for the guest agent");
    assert!(
        status.success(),
        "cargo zigbuild failed for the guest agent"
    );
    let rel = target_dir.join(strip_glibc(target)).join("release");
    for name in [
        "mvm-oci-init",
        "mvm-oci-entrypoint",
        "mvm-guest-agent",
        "mvm-guest-netinit",
        "mvm-egress-client",
    ] {
        let built = rel.join(name);
        let dest = out_dir.join(name);
        std::fs::copy(&built, &dest)
            .unwrap_or_else(|e| panic!("copy {} → {}: {e}", built.display(), dest.display()));
    }
}

/// Resolve the zig binary cargo-zigbuild must use, pinned to `zig_pin`.
///
/// Order: explicit `MVM_EMBED_ZIG` → the `ziglang` PyPI package (version-exact,
/// Homebrew-independent) → a PATH `zig` that already matches the pin (returns
/// `None`, letting cargo-zigbuild find it). Panics with an actionable message
/// when nothing matches — the alternative is cargo-zigbuild picking a
/// Homebrew-upgraded zig and failing far downstream with `CacheCheckFailed`.
fn pinned_zig_path_or_fail(zig_pin: &str) -> Option<String> {
    if let Ok(p) = std::env::var("MVM_EMBED_ZIG")
        && !p.is_empty()
    {
        return Some(p);
    }
    if let Some(path) = ziglang_zig_path(zig_pin) {
        return Some(path);
    }
    if zig_on_path_matches(zig_pin) {
        return None;
    }
    panic!(
        "zig {zig_pin} is required to cross-compile the embedded host binaries but was not \
         found. Install it with `pip install ziglang=={zig_pin}` (recommended — the build \
         auto-detects it), put zig {zig_pin} on PATH, or set MVM_EMBED_ZIG=/path/to/zig. \
         Homebrew's `zig` is usually a newer, incompatible release that fails downstream with \
         `CacheCheckFailed`."
    );
}

/// Absolute path to the `ziglang` PyPI package's bundled zig, iff its version is
/// exactly `zig_pin`. `python3 -m ziglang version` prints the version; the binary
/// sits next to the package's `__init__`.
fn ziglang_zig_path(zig_pin: &str) -> Option<String> {
    let ver = Command::new("python3")
        .args(["-m", "ziglang", "version"])
        .output()
        .ok()?;
    if !ver.status.success() || String::from_utf8_lossy(&ver.stdout).trim() != zig_pin {
        return None;
    }
    let path = Command::new("python3")
        .args([
            "-c",
            "import ziglang, os; print(os.path.join(os.path.dirname(ziglang.__file__), 'zig'))",
        ])
        .output()
        .ok()?;
    if !path.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&path.stdout).trim().to_string();
    (!p.is_empty()).then_some(p)
}

/// True when a PATH `zig` reports exactly the pinned version.
fn zig_on_path_matches(zig_pin: &str) -> bool {
    Command::new("zig")
        .arg("version")
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == zig_pin)
        .unwrap_or(false)
}

/// Find a `(cargo, rustc)` pair that has `target` installed in its sysroot.
fn rustup_cargo_and_rustc(target: &str) -> (String, String) {
    if let Some((cargo, rustc)) = configured_embed_tools() {
        assert!(
            rustc_has_target(&rustc, target),
            "MVM_EMBED_RUSTC={rustc:?} does not provide target {target}; \
             unset MVM_EMBED_RUSTC or point it at a Rust toolchain with that std target"
        );
        return (cargo, rustc);
    }

    let env_rustc = std::env::var("RUSTC").unwrap_or_default();
    let env_cargo = std::env::var("CARGO").unwrap_or_default();
    if !env_rustc.is_empty() && rustc_has_target(&env_rustc, target) {
        return (
            if env_cargo.is_empty() {
                "cargo".to_string()
            } else {
                env_cargo
            },
            env_rustc,
        );
    }

    let home = std::env::var("HOME").unwrap_or_default();
    let rustup_candidates = vec!["rustup".to_string(), format!("{home}/.cargo/bin/rustup")];
    for rustup in &rustup_candidates {
        let rustc_out = Command::new(rustup).args(["which", "rustc"]).output();
        let cargo_out = Command::new(rustup).args(["which", "cargo"]).output();
        if let (Ok(rc), Ok(ca)) = (rustc_out, cargo_out)
            && rc.status.success()
            && ca.status.success()
        {
            let rc_path = String::from_utf8_lossy(&rc.stdout).trim().to_string();
            let ca_path = String::from_utf8_lossy(&ca.stdout).trim().to_string();
            if !rc_path.is_empty() && !ca_path.is_empty() && rustc_has_target(&rc_path, target) {
                return (ca_path, rc_path);
            }
        }
    }

    (
        if env_cargo.is_empty() {
            "cargo".to_string()
        } else {
            env_cargo
        },
        if env_rustc.is_empty() {
            "rustc".to_string()
        } else {
            env_rustc
        },
    )
}

fn configured_embed_tools() -> Option<(String, String)> {
    configured_embed_tools_from(
        std::env::var("MVM_EMBED_CARGO").ok(),
        std::env::var("MVM_EMBED_RUSTC").ok(),
    )
}

fn configured_embed_tools_from(
    embed_cargo: Option<String>,
    embed_rustc: Option<String>,
) -> Option<(String, String)> {
    let rustc = embed_rustc?.trim().to_string();
    assert!(
        !rustc.is_empty(),
        "MVM_EMBED_RUSTC must not be empty when set"
    );
    let cargo = embed_cargo
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cargo".to_string());
    Some((cargo, rustc))
}

fn rustc_has_target(rustc: &str, target: &str) -> bool {
    let out = Command::new(rustc)
        .args(["--target", target, "--print", "target-libdir"])
        .output();
    if let Ok(o) = out
        && o.status.success()
    {
        let dir = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !dir.is_empty() && std::path::Path::new(&dir).exists() {
            return true;
        }
    }
    false
}

fn sha256_hex(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let mut h = Sha256::new();
    h.update(&bytes);
    format!("{:x}", h.finalize())
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
    fn extract_quoted_after_basic() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
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
}
