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

    // HOST_BINARIES (installed into the builder/dev VM rootfs) + SEED_BINARIES
    // (host-side only, e.g. the Stage 0 nix-seed's /init — plan 160). Both are
    // `mvm-build` `[[bin]]`s; both get cross-compiled + embedded the same way.
    let mut manifest = read_rust_manifest(&workspace_root);
    manifest.extend(read_seed_binaries(&workspace_root));
    let mut entries = Vec::new();

    // The host-vm bins are statically musl-linked and embedded for the host
    // arch (`pin.target`, picked from CARGO_CFG_TARGET_ARCH — Plan 164). They
    // are always cross-compiled with cargo-zigbuild, even when host arch ==
    // target arch: `ring` (pulled transitively) compiles C, so the musl target
    // needs a musl *C* cross-compiler. zig supplies it; a plain
    // `cargo build --target <arch>-musl` would instead demand a system
    // `<arch>-linux-musl-gcc`, which neither CI nor the documented contributor
    // setup carries (both standardize on zig + cargo-zigbuild — see CLAUDE.md
    // "Host dependencies"). zigbuild is the single portable path. (Plan 164
    // briefly added a same-arch plain-`cargo build` fast-path on the false
    // premise that the bins are C-free; it broke CI, which has no musl-gcc.)

    // Fast path for local test/dev iteration: skip the nested
    // `cargo zigbuild --release` cross-compile of the host-vm binaries and
    // bake zero-byte stubs instead. Cuts the dominant cold-build tax on
    // macOS (and any fresh worktree) for everyone who isn't exercising a
    // builder-VM boot. The only consumers that read the *bytes* are the
    // env-gated boot/E2E tests (`MVM_E2E_SMOKE`, libkrun lifecycle), which
    // are skipped in a default `cargo test`/`nextest` run — and the
    // `e2e-core-demo` recipe never sets this var, so a stub build can't
    // masquerade as a passing E2E. NEVER set this in CI release builds:
    // the shipped mvmctl must embed the real reproducible binaries
    // (Plan 115 / ADR-065 claim 11).
    let skip_embed = std::env::var("MVM_SKIP_EMBED_BINARIES").as_deref() == Ok("1");
    println!("cargo:rerun-if-env-changed=MVM_SKIP_EMBED_BINARIES");
    if skip_embed {
        println!(
            "cargo:warning=MVM_SKIP_EMBED_BINARIES=1: embedding zero-byte host-vm \
             stubs; builder-VM boot is unavailable in this build"
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
}

struct Pin {
    zig: String,
    cargo_zigbuild: String,
    target: String,
}

fn read_pinned_toolchain(root: &Path) -> Pin {
    let toml_str = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let v: toml::Value = toml::from_str(&toml_str).unwrap();
    let p = &v["workspace"]["metadata"]["mvm"]["toolchain"];
    // The embed target follows the arch mvmctl is built for: the local
    // builder/Stage 0 VM is always same-arch as the host, so an x86_64
    // mvmctl must embed x86_64 bins and an aarch64 mvmctl aarch64 bins
    // (Plan 164). `CARGO_CFG_TARGET_ARCH` is set by cargo for build scripts.
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
/// of `mvm-build` (plan 121 D4) — the build script cross-compiles each
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
/// install_path, absent from the nix attrset) — plan 160.
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

fn run_cargo_zigbuild(root: &Path, target_dir: &Path, pkg: &str, target: &str, out: &Path) {
    eprintln!("[build.rs] cargo zigbuild --release --target {target} -p mvm-build --bin {pkg}");
    // We need the rustup-managed cargo, not the Homebrew one. The Homebrew
    // cargo sets RUSTC=rustc which doesn't have the cross targets, and that
    // value propagates into the nested `cargo build` that cargo-zigbuild
    // spawns. Using the rustup cargo avoids that.
    let (cargo, rustc) = rustup_cargo_and_rustc(strip_glibc(target));
    let status = Command::new(&cargo)
        .args([
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
        .current_dir(root)
        .status()
        .expect(
            "spawn `cargo zigbuild` — \
             install with: `cargo install cargo-zigbuild --version 0.20.0` \
             and `brew install zig` (or equivalent)",
        );
    assert!(status.success(), "cargo zigbuild failed for {pkg}");
    let built = target_dir
        .join(strip_glibc(target))
        .join("release")
        .join(pkg);
    std::fs::copy(&built, out)
        .unwrap_or_else(|e| panic!("copy {} → {}: {e}", built.display(), out.display()));
}

/// Find a `(cargo, rustc)` pair that has `target` installed in its sysroot.
fn rustup_cargo_and_rustc(target: &str) -> (String, String) {
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
}
