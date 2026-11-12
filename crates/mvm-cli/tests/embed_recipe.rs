//! Contributor embedding is an explicit workflow. Keep its macOS LLVM loader
//! repair reachable from every recipe that links host binaries.
//!
//! CI also compiles this file by itself with plain `rustc`, outside Cargo, so
//! it may use only `std` and no Cargo-provided environment variables or
//! dev-dependencies. A passing `nextest` run does not prove it still compiles
//! that way.

const JUSTFILE: &str = include_str!("../../../Justfile");
const EMBED_MOD: &str = include_str!("../../../just/payload/mod.just");

/// The body of `name`, up to the recipe that follows it. Recipe bodies are the
/// unit these guards assert over, and slicing them by hand three times over is
/// how one of them ends up bounded by the wrong marker.
fn recipe_body(name: &str, next: &str) -> &'static str {
    JUSTFILE
        .split(name)
        .nth(1)
        .unwrap_or_else(|| panic!("{name} recipe"))
        .split(next)
        .next()
        .unwrap_or_else(|| panic!("{name} recipe body"))
}

/// The repair moved out of `embed` and into a shared script so a second recipe
/// could reuse it. Assert the reference, not the mechanism — the mechanism is
/// asserted once, against the script, below.
#[test]
fn embed_recipe_exposes_the_pinned_rust_sysroot_to_macos_llvm_tools() {
    let recipe = recipe_body("embed *ARGS:", "\nrelease-build:");
    assert!(recipe.contains("scripts/macos-objcopy-env.sh"), "{recipe}");
}

/// `payload::supervisors` links the same `mvm-hostd` binaries `embed` does. It
/// went without this repair and shipped every supervisor unstripped, which is
/// what this guard exists to catch a second time.
#[test]
fn build_supervisors_recipe_exposes_the_pinned_rust_sysroot_too() {
    let recipe = EMBED_MOD
        .split("supervisors *ARGS:")
        .nth(1)
        .unwrap_or_else(|| panic!("supervisors recipe"))
        .split("\nlibkrun-supervisor *ARGS:")
        .next()
        .unwrap_or_else(|| panic!("supervisors recipe body"));
    assert!(recipe.contains("scripts/macos-objcopy-env.sh"), "{recipe}");
    assert!(
        recipe.contains("build -p mvm-hostd --bins {{ARGS}}"),
        "{recipe}"
    );
}

#[test]
fn embed_recipe_builds_native_vm_helpers_in_the_requested_profile() {
    let recipe = recipe_body("embed *ARGS:", "embed-refresh:");

    let helper_build = recipe
        .find("build -p mvm-hostd --bins {{ARGS}}")
        .expect("embed recipe builds native per-VM helpers");
    let mvmctl_build = recipe
        .find(r#"./scripts/cargo.sh build --features "$FEATURES" {{ARGS}}"#)
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
