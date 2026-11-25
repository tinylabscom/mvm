//! Contributor embedding is an explicit workflow. Keep its macOS LLVM loader
//! repair reachable from every recipe that links host binaries.
//!
//! CI also compiles this file by itself with plain `rustc`, outside Cargo, so
//! it may use only `std` and no Cargo-provided environment variables or
//! dev-dependencies. A passing `nextest` run does not prove it still compiles
//! that way.

const JUSTFILE: &str = include_str!("../../../Justfile");

/// The body of the `build` recipe, which holds every arm that links host
/// binaries. Recipe bodies are the unit these guards assert over.
fn build_recipe() -> &'static str {
    JUSTFILE
        .split("\nbuild WHAT=\"\" *ARGS:")
        .nth(1)
        .expect("build recipe")
        .split("\n    esac")
        .next()
        .expect("build recipe body")
}

/// The shared helper build the `embed` and `supervisors` arms both call.
fn supervisors_function() -> &'static str {
    build_recipe()
        .split("supervisors() {")
        .nth(1)
        .expect("supervisors function")
        .split("\n    }")
        .next()
        .expect("supervisors function body")
}

/// One arm of the `build` recipe's `case`, up to its `;;`.
fn build_arm(name: &str) -> &'static str {
    build_recipe()
        .split(&format!("\n      {name})"))
        .nth(1)
        .unwrap_or_else(|| panic!("{name} arm"))
        .split(";;")
        .next()
        .unwrap_or_else(|| panic!("{name} arm body"))
}

/// The repair lives in a shared script so every arm that links host binaries
/// can reuse it. Assert the reference, not the mechanism — the mechanism is
/// asserted once, against the script, below.
#[test]
fn embed_recipe_exposes_the_pinned_rust_sysroot_to_macos_llvm_tools() {
    assert!(build_recipe().contains("scripts/macos-objcopy-env.sh"));
    assert!(build_arm("embed").contains("supervisors \"$@\""));
}

/// `build supervisors` links the same `mvm-hostd` binaries `build embed` does.
/// It went without this repair and shipped every supervisor unstripped, which
/// is what this guard exists to catch a second time.
#[test]
fn build_supervisors_recipe_exposes_the_pinned_rust_sysroot_too() {
    let helpers = supervisors_function();
    assert!(helpers.contains("objcopy_env"), "{helpers}");
    assert!(
        helpers.contains("build -p mvm-hostd --bins \"$@\""),
        "{helpers}"
    );
    assert!(build_arm("supervisors").contains("supervisors \"$@\""));
}

#[test]
fn embed_recipe_builds_native_vm_helpers_in_the_requested_profile() {
    let recipe = build_arm("embed");

    let helper_build = recipe
        .find("supervisors \"$@\"")
        .expect("embed recipe builds native per-VM helpers");
    let mvmctl_build = recipe
        .find(r#"./scripts/cargo.sh build --features "$FEATURES" "$@""#)
        .expect("embed recipe builds embedded mvmctl");
    assert!(
        helper_build < mvmctl_build,
        "native helpers must be ready before mvmctl is linked: {recipe}"
    );
}

const OBJCOPY_ENV: &str = "scripts/macos-objcopy-env.sh";

/// Writes an executable shell stub named `name` into `dir`.
fn stub(dir: &std::path::Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// This file is also compiled on its own with plain `rustc` from the repo
/// root, so it uses only `std` and finds the checkout by walking up from the
/// working directory to the `Justfile`.
fn script(rel: &str) -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap()
        .ancestors()
        .find(|dir| dir.join("Justfile").is_file())
        .expect("repo root")
        .join(rel)
}

/// A scratch directory removed on drop.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "embed-recipe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sources the env script under a stubbed `uname` and `rustup`, then prints
/// the two variables it is responsible for.
fn sourced_env(uname: &str, inherited_loader_path: Option<&str>) -> String {
    let tmp = Scratch::new();
    let bin = tmp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    stub(&bin, "uname", &format!("echo {uname}"));
    stub(&bin, "rustup", "echo /fake/sysroot");
    std::fs::write(
        tmp.path().join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"nightly-test\"\n",
    )
    .unwrap();
    let mut cmd = std::process::Command::new("bash");
    cmd.arg("-c")
        .arg(r#"[ -n "$3" ] && export DYLD_FALLBACK_LIBRARY_PATH="$3"; source "$1" "$2"; echo "loader=${DYLD_FALLBACK_LIBRARY_PATH:-}"; echo "wrapper=${RUSTC_WRAPPER:-}""#)
        .arg("bash")
        .arg(script(OBJCOPY_ENV))
        .arg(tmp.path())
        .arg(inherited_loader_path.unwrap_or(""))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
        .env_remove("RUSTC_WRAPPER");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    format!(
        "{}\nroot={}",
        String::from_utf8(out.stdout).unwrap(),
        tmp.path().display()
    )
}

#[test]
fn macos_objcopy_env_seeds_the_loader_path_and_the_rustc_wrapper() {
    let out = sourced_env("Darwin", None);
    let root = out.rsplit("root=").next().unwrap();
    assert!(out.contains("loader=/fake/sysroot/lib\n"), "{out}");
    assert!(
        out.contains(&format!("wrapper={root}/scripts/rustc-macos-loader.sh")),
        "{out}"
    );
}

#[test]
fn macos_objcopy_env_keeps_an_inherited_loader_path_behind_the_sysroot() {
    let out = sourced_env("Darwin", Some("/already/there"));
    assert!(
        out.contains("loader=/fake/sysroot/lib:/already/there\n"),
        "{out}"
    );
}

/// A no-op off Darwin, or every Linux contributor inherits a macOS repair.
#[test]
fn macos_objcopy_env_changes_nothing_off_darwin() {
    let out = sourced_env("Linux", None);
    assert!(out.contains("loader=\n"), "{out}");
    assert!(out.contains("wrapper=\n"), "{out}");
}

/// SIP strips `DYLD_*` across the exec of the `/bin/sh` stub on macOS, so the
/// exported value can only be observed from a child on other hosts.
#[cfg(not(target_os = "macos"))]
#[test]
fn macos_rustc_wrapper_restores_the_sysroot_loader_path() {
    const RUSTC_WRAPPER: &str = "scripts/rustc-macos-loader.sh";
    let tmp = Scratch::new();
    stub(
        tmp.path(),
        "fake-rustc",
        r#"if [ "$1" = "--print" ]; then echo /fake/sysroot; else echo "args=$*"; echo "loader=$DYLD_FALLBACK_LIBRARY_PATH"; fi"#,
    );
    let run = |existing: Option<&str>| {
        let mut cmd = std::process::Command::new(script(RUSTC_WRAPPER));
        cmd.arg(tmp.path().join("fake-rustc"))
            .args(["--crate-name", "x"])
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH");
        if let Some(existing) = existing {
            cmd.env("DYLD_FALLBACK_LIBRARY_PATH", existing);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let fresh = run(None);
    assert!(fresh.contains("args=--crate-name x\n"), "{fresh}");
    assert!(fresh.contains("loader=/fake/sysroot/lib\n"), "{fresh}");
    let kept = run(Some("/cargo/set"));
    assert!(
        kept.contains("loader=/fake/sysroot/lib:/cargo/set\n"),
        "{kept}"
    );
}
