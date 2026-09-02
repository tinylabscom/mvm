//! The pinned cross-compile toolchain that produces mvmctl's embedded Linux
//! host binaries: which zig, which Rust, which musl target.
//!
//! Two consumers, which is why this sits in `mvm-build` rather than in the
//! crate that owns the embed table. `crates/mvm-cli/build.rs` `#[path]`-includes
//! it to *run* the cross-compile, and panics are the right failure there — a
//! build script that cannot find its toolchain has nothing to fall back on.
//! `libkrun_builder`'s bootstrap-helper resolution calls the `try_` variants to
//! decide, in milliseconds, whether spawning that build is worth the wait.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub struct Pin {
    pub rust: String,
    pub zig: String,
    pub cargo_zigbuild: String,
    pub target: String,
}

pub fn workspace_root_from_manifest_dir(manifest_dir: &Path) -> PathBuf {
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest_dir)
        .to_path_buf()
}

pub fn read_pinned_toolchain(root: &Path, arch: &str) -> Pin {
    try_read_pinned_toolchain(root, arch).unwrap_or_else(|reason| panic!("{reason}"))
}

/// `read_pinned_toolchain` for a caller that has somewhere to go on failure.
pub fn try_read_pinned_toolchain(root: &Path, arch: &str) -> Result<Pin, String> {
    let manifest = root.join("Cargo.toml");
    let toml_str = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("read {}: {e}", manifest.display()))?;
    let v: toml::Value =
        toml::from_str(&toml_str).map_err(|e| format!("parse workspace Cargo.toml: {e}"))?;
    let pinned = v
        .get("workspace")
        .and_then(|item| item.get("metadata"))
        .and_then(|item| item.get("mvm"))
        .and_then(|item| item.get("toolchain"))
        .ok_or_else(|| {
            format!(
                "{} is missing [workspace.metadata.mvm.toolchain]",
                manifest.display()
            )
        })?;
    Ok(Pin {
        rust: pinned_string(pinned, "rust", &manifest)?,
        zig: pinned_string(pinned, "zig", &manifest)?,
        cargo_zigbuild: pinned_string(pinned, "cargo-zigbuild", &manifest)?,
        target: resolve_target_for_arch(pinned, arch)?,
    })
}

fn pinned_string(toolchain: &toml::Value, key: &str, manifest: &Path) -> Result<String, String> {
    toolchain
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "{} is missing workspace.metadata.mvm.toolchain.{key}",
                manifest.display()
            )
        })
}

pub fn resolve_target_for_arch(toolchain: &toml::Value, arch: &str) -> Result<String, String> {
    toolchain
        .get("targets")
        .and_then(|t| t.get(arch))
        .and_then(|t| t.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "no embedded-host-binary target pinned for arch `{arch}` in \
                 [workspace.metadata.mvm.toolchain.targets] — mvmctl does not yet \
                 support this guest arch. Add a `{arch} = \"...-musl\"` entry."
            )
        })
}

pub fn strip_glibc(t: &str) -> &str {
    t.split('.').next().unwrap()
}

pub fn pinned_zig_path_or_fail(zig_pin: &str) -> Option<String> {
    resolve_pinned_zig(zig_pin).unwrap_or_else(|reason| panic!("{reason}"))
}

/// The pinned zig, or why it could not be found.
///
/// `Ok(None)` means a matching zig is already on `PATH`: nothing to pin
/// explicitly, which is what leaving `CARGO_ZIGBUILD_ZIG_PATH` unset says.
pub fn resolve_pinned_zig(zig_pin: &str) -> Result<Option<String>, String> {
    if let Ok(p) = std::env::var("MVM_EMBED_ZIG")
        && !p.is_empty()
    {
        return Ok(Some(p));
    }
    if let Some(path) = ziglang_zig_path(zig_pin) {
        return Ok(Some(path));
    }
    if zig_on_path_matches(zig_pin) {
        return Ok(None);
    }
    Err(format!(
        "zig {zig_pin} is required to cross-compile the embedded host binaries but was not \
         found. Install it with `just toolchain-embed` (recommended — it installs the exact \
         pinned zig and the musl Rust targets), put zig {zig_pin} on PATH, or set \
         MVM_EMBED_ZIG=/path/to/zig. Homebrew's `zig` is usually a newer, incompatible \
         release that fails downstream with `CacheCheckFailed`."
    ))
}

pub fn rustup_cargo_and_rustc(target: &str, toolchain: &str) -> (String, String) {
    try_rustup_cargo_and_rustc(target, toolchain).unwrap_or_else(|reason| panic!("{reason}"))
}

/// `rustup_cargo_and_rustc` for a caller that has somewhere to go on failure.
pub fn try_rustup_cargo_and_rustc(
    target: &str,
    toolchain: &str,
) -> Result<(String, String), String> {
    if let Some((cargo, rustc)) = configured_embed_tools()? {
        if !rustc_has_target(&rustc, target) {
            return Err(format!(
                "MVM_EMBED_RUSTC={rustc:?} does not provide target {target}; \
                 unset MVM_EMBED_RUSTC or point it at a Rust toolchain with that std target"
            ));
        }
        return Ok((cargo, rustc));
    }

    let home = std::env::var("HOME").unwrap_or_default();
    let rustup_candidates = vec!["rustup".to_string(), format!("{home}/.cargo/bin/rustup")];
    for rustup in &rustup_candidates {
        let rustc_out = Command::new(rustup)
            .args(["which", "rustc", "--toolchain", toolchain])
            .output();
        let cargo_out = Command::new(rustup)
            .args(["which", "cargo", "--toolchain", toolchain])
            .output();
        if let (Ok(rc), Ok(ca)) = (rustc_out, cargo_out)
            && rc.status.success()
            && ca.status.success()
        {
            let rc_path = String::from_utf8_lossy(&rc.stdout).trim().to_string();
            let ca_path = String::from_utf8_lossy(&ca.stdout).trim().to_string();
            if !rc_path.is_empty() && !ca_path.is_empty() && rustc_has_target(&rc_path, target) {
                return Ok((ca_path, rc_path));
            }
        }
    }

    Err(format!(
        "Rust toolchain {toolchain} with target {target} is required for embedded host binaries. \
         Install it with `just toolchain-embed`, or with `rustup toolchain install {toolchain} \
         --profile minimal` followed by `rustup target add {target} --toolchain {toolchain}`, or \
         set MVM_EMBED_CARGO and MVM_EMBED_RUSTC to an equivalent pinned toolchain"
    ))
}

fn ziglang_zig_path(zig_pin: &str) -> Option<String> {
    let ver = Command::new("python3")
        .args(["-m", "ziglang", "version"])
        .output()
        .ok()?;
    if !ver.status.success() || String::from_utf8_lossy(&ver.stdout).trim() != zig_pin {
        return home_dir().and_then(|home| ziglang_mise_path(zig_pin, &home));
    }
    let path = Command::new("python3")
        .args([
            "-c",
            "import ziglang, os; print(os.path.join(os.path.dirname(ziglang.__file__), 'zig'))",
        ])
        .output()
        .ok()?;
    if !path.status.success() {
        return home_dir().and_then(|home| ziglang_mise_path(zig_pin, &home));
    }
    let p = String::from_utf8_lossy(&path.stdout).trim().to_string();
    if zig_path_matches(&p, zig_pin) {
        return Some(p);
    }
    home_dir().and_then(|home| ziglang_mise_path(zig_pin, &home))
}

fn zig_on_path_matches(zig_pin: &str) -> bool {
    Command::new("zig")
        .arg("version")
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == zig_pin)
        .unwrap_or(false)
}

fn configured_embed_tools() -> Result<Option<(String, String)>, String> {
    configured_embed_tools_from(
        std::env::var("MVM_EMBED_CARGO").ok(),
        std::env::var("MVM_EMBED_RUSTC").ok(),
    )
}

fn zig_path_matches(path: &str, zig_pin: &str) -> bool {
    !path.trim().is_empty()
        && Command::new(path)
            .arg("version")
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == zig_pin)
            .unwrap_or(false)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub(crate) fn ziglang_mise_path(zig_pin: &str, home: &Path) -> Option<String> {
    let installs = home.join(".local/share/mise/installs/python");
    let python_installs = std::fs::read_dir(installs).ok()?;
    for python_install in python_installs.flatten() {
        let lib_dir = python_install.path().join("lib");
        let python_libs = match std::fs::read_dir(&lib_dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for python_lib in python_libs.flatten() {
            let candidate = python_lib.path().join("site-packages/ziglang/zig");
            let candidate_string = candidate.display().to_string();
            if zig_path_matches(&candidate_string, zig_pin) {
                return Some(candidate_string);
            }
        }
    }
    None
}

fn configured_embed_tools_from(
    embed_cargo: Option<String>,
    embed_rustc: Option<String>,
) -> Result<Option<(String, String)>, String> {
    let Some(rustc) = embed_rustc else {
        return Ok(None);
    };
    let rustc = rustc.trim().to_string();
    if rustc.is_empty() {
        return Err("MVM_EMBED_RUSTC must not be empty when set".to_string());
    }
    let cargo = embed_cargo
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "cargo".to_string());
    Ok(Some((cargo, rustc)))
}

fn rustc_has_target(rustc: &str, target: &str) -> bool {
    let out = Command::new(rustc)
        .args(["--target", target, "--print", "target-libdir"])
        .output();
    if let Ok(o) = out
        && o.status.success()
    {
        let dir = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !dir.is_empty() && Path::new(&dir).exists() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_complete_embedded_toolchain_pin() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.metadata.mvm.toolchain]
rust = "1.91.1"
zig = "0.13.0"
cargo-zigbuild = "0.23.0"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
"#,
        )
        .expect("write Cargo.toml");

        let pin = read_pinned_toolchain(tmp.path(), "aarch64");
        assert_eq!(pin.rust, "1.91.1");
        assert_eq!(pin.zig, "0.13.0");
        assert_eq!(pin.cargo_zigbuild, "0.23.0");
        assert_eq!(pin.target, "aarch64-unknown-linux-musl");
    }

    /// The readiness probe reports rather than panics, so its caller has to be
    /// able to say *what* is wrong — a bare "toolchain unavailable" sends a
    /// contributor looking in the wrong place.
    #[test]
    fn a_manifest_without_the_toolchain_table_names_what_is_missing() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = []\n")
            .expect("write Cargo.toml");

        let reason = try_read_pinned_toolchain(tmp.path(), "aarch64").unwrap_err();
        assert!(
            reason.contains("[workspace.metadata.mvm.toolchain]"),
            "{reason}"
        );
    }

    #[test]
    fn a_toolchain_table_missing_a_pin_names_the_key() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"
[workspace.metadata.mvm.toolchain]
rust = "1.91.1"

[workspace.metadata.mvm.toolchain.targets]
aarch64 = "aarch64-unknown-linux-musl"
"#,
        )
        .expect("write Cargo.toml");

        let reason = try_read_pinned_toolchain(tmp.path(), "aarch64").unwrap_err();
        assert!(reason.contains("toolchain.zig"), "{reason}");
    }

    #[test]
    fn an_unreadable_manifest_is_reported_by_path() {
        let tmp = tempfile::TempDir::new().expect("tempdir");

        let reason = try_read_pinned_toolchain(tmp.path(), "aarch64").unwrap_err();
        assert!(reason.contains("Cargo.toml"), "{reason}");
    }

    #[test]
    fn configured_embed_tools_require_rustc_and_default_cargo() {
        assert_eq!(configured_embed_tools_from(None, None), Ok(None));
        assert_eq!(
            configured_embed_tools_from(None, Some(" /toolchain/rustc ".to_string())),
            Ok(Some(("cargo".to_string(), "/toolchain/rustc".to_string())))
        );
        assert_eq!(
            configured_embed_tools_from(
                Some(" /toolchain/cargo ".to_string()),
                Some(" /toolchain/rustc ".to_string())
            ),
            Ok(Some((
                "/toolchain/cargo".to_string(),
                "/toolchain/rustc".to_string()
            )))
        );
        assert!(configured_embed_tools_from(None, Some("   ".to_string())).is_err());
    }

    #[test]
    fn ziglang_mise_path_finds_matching_installed_zig() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let zig = tmp.path().join(
            ".local/share/mise/installs/python/3.12.10/lib/python3.12.10/site-packages/ziglang",
        );
        std::fs::create_dir_all(&zig).expect("mkdir zig dir");
        let zig_bin = zig.join("zig");
        std::fs::write(&zig_bin, "#!/bin/sh\necho 0.13.0\n").expect("write zig");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&zig_bin).expect("stat zig").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&zig_bin, perms).expect("chmod zig");
        }

        let found = ziglang_mise_path("0.13.0", tmp.path()).expect("find zig");
        assert!(found.ends_with("/ziglang/zig"));
    }

    #[test]
    fn ziglang_mise_path_rejects_wrong_version() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let zig = tmp.path().join(
            ".local/share/mise/installs/python/3.12.10/lib/python3.12.10/site-packages/ziglang",
        );
        std::fs::create_dir_all(&zig).expect("mkdir zig dir");
        let zig_bin = zig.join("zig");
        std::fs::write(&zig_bin, "#!/bin/sh\necho 0.14.0\n").expect("write zig");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&zig_bin).expect("stat zig").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&zig_bin, perms).expect("chmod zig");
        }

        assert!(ziglang_mise_path("0.13.0", tmp.path()).is_none());
    }
}
