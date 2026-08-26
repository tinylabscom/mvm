//! Resolver for the per-VM host helper binaries `mvmctl` spawns — the backend
//! supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`) and the
//! substitution endpoint. Each is a separate `[[bin]]` in a workspace crate,
//! which cargo does not build for a plain `cargo run` of mvmctl; the mvm-cli
//! build script compiles them during the build phase instead.
//!
//! Resolution order (first existing file wins): `$<ENV_VAR>` override →
//! `$MVM_AUX_BIN_DIR` (the build script's dir, bridged into the env at startup)
//! → alongside the current exe (a downloaded release ships them there) →
//! workspace `target/{release,debug}` (an explicit `just build-supervisors`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// A per-VM helper binary and its path-override env var.
pub struct AuxBin<'a> {
    /// Binary/file name, e.g. `mvm-hvf-supervisor`.
    pub bin: &'a str,
    /// Path-override env var, e.g. `MVM_HVF_SUPERVISOR_PATH`.
    pub env_var: &'a str,
}

/// Resolve `spec` to an on-disk binary. Never builds — the build script
/// produces these; a missing one is a hard error with a recovery hint.
pub fn resolve(spec: &AuxBin) -> Result<PathBuf> {
    resolve_from(
        spec,
        &Lookup {
            override_path: std::env::var_os(spec.env_var).map(PathBuf::from),
            dirs: assemble_candidate_dirs(
                current_exe_dir(),
                aux_bin_dir_from_env(),
                workspace_target_dirs(),
            ),
            allow_stale: stale_reuse_allowed(),
        },
    )
}

/// Everything `resolve` reads from the environment, gathered so the resolution
/// rules — including the staleness refusal — are testable without mutating
/// process-global env.
pub(crate) struct Lookup {
    pub(crate) override_path: Option<PathBuf>,
    pub(crate) dirs: Vec<PathBuf>,
    pub(crate) allow_stale: bool,
}

fn resolve_from(spec: &AuxBin, lookup: &Lookup) -> Result<PathBuf> {
    if let Some(p) = lookup.override_path.clone() {
        if p.is_file() {
            refuse_if_stale(&p, lookup.allow_stale)?;
            return Ok(p);
        }
        bail!(
            "{} points at {} which is not a file",
            spec.env_var,
            p.display()
        );
    }
    if let Some(found) = first_existing_bin(spec.bin, &lookup.dirs) {
        refuse_if_stale(&found, lookup.allow_stale)?;
        return Ok(found);
    }
    bail!(
        "{bin} not found. It is a per-VM host helper compiled by mvmctl's build \
         script; on a source checkout run `cargo build` (or `just \
         build-supervisors`), or set {env}=<path>.{hint}",
        bin = spec.bin,
        env = spec.env_var,
        hint = missing_hint(spec.bin),
    )
}

/// Marker `mvm-cli`'s build script writes beside a helper it reused from a
/// previous build instead of recompiling.
///
/// The build script only recompiles these when the content key misses, and an
/// edit anywhere under `mvm-hostd`'s closure misses by construction — so
/// rebuilding unconditionally cost 17.8s of every inner-loop build. Reusing
/// silently is worse than slow, though: a supervisor that ignores your edit
/// produces a guest that misbehaves with no visible cause. Detecting it here,
/// at the moment of spawn, gets both — a fast build and a loud failure.
///
/// Only ever present in a source checkout's build-script directory. A
/// downloaded release ships binaries with no marker beside them.
fn stale_marker_for(bin: &Path) -> PathBuf {
    let name = bin.file_name().unwrap_or_default().to_string_lossy();
    bin.with_file_name(format!("{name}.mvm-stale"))
}

/// Escape hatch for the case where you know the reused helper is fine — for
/// example an edit that touched only host-side CLI code.
fn stale_reuse_allowed() -> bool {
    std::env::var_os("MVM_ALLOW_STALE_AUX").is_some_and(|v| !v.is_empty())
}

/// Refuse a helper the build script flagged as not carrying this tree's
/// changes. Fail closed: spawning it would silently produce a guest that
/// ignores the edit under test.
fn refuse_if_stale(bin: &Path, allowed: bool) -> Result<()> {
    if allowed || !stale_marker_for(bin).is_file() {
        return Ok(());
    }
    bail!(
        "{} was reused from an earlier build and does NOT contain this source \
         tree's changes, so spawning it would run a guest that ignores your \
         edit. Run `just embed-refresh` to rebuild it, or set \
         MVM_ALLOW_STALE_AUX=1 to use it anyway.",
        bin.display()
    );
}

/// Ordered directories to search for a helper: the build script's dir, then
/// the exe dir, then the workspace target dirs. Absent optional dirs are
/// dropped. The build script's dir comes first so a freshly built helper
/// there isn't shadowed by a stale copy sitting next to a dev `cargo run`
/// exe (`target/debug/mvmctl`, which cargo never refreshes for a `[[bin]]`
/// it didn't just build).
fn assemble_candidate_dirs(
    exe_dir: Option<PathBuf>,
    aux_dir: Option<PathBuf>,
    target_dirs: Vec<PathBuf>,
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.extend(aux_dir);
    dirs.extend(exe_dir);
    dirs.extend(target_dirs);
    dirs
}

fn first_existing_bin(bin: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter().map(|d| d.join(bin)).find(|p| p.is_file())
}

/// Extra recovery hint for helpers with a host prerequisite. Empty otherwise.
fn missing_hint(bin: &str) -> &'static str {
    if bin == "mvm-libkrun-supervisor" {
        " This helper links libkrun; install it (`brew install slp/krun/libkrun`) and rebuild."
    } else {
        ""
    }
}

fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
}

fn aux_bin_dir_from_env() -> Option<PathBuf> {
    let dir = std::env::var_os("MVM_AUX_BIN_DIR")?;
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir))
}

fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

/// `target/{release,debug}` under each workspace target dir (default plus a
/// `CARGO_TARGET_DIR` override), the fallback for `just build-supervisors`.
fn workspace_target_dirs() -> Vec<PathBuf> {
    let Some(root) = workspace_root_from_manifest_dir() else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for base in source_checkout_target_dirs(&root) {
        dirs.push(base.join("release"));
        dirs.push(base.join("debug"));
    }
    dirs
}

fn source_checkout_target_dirs(workspace_root: &Path) -> Vec<PathBuf> {
    let default_target_dir = workspace_root.join("target");
    let effective_target_dir = effective_cargo_target_dir(workspace_root);
    if effective_target_dir == default_target_dir {
        vec![default_target_dir]
    } else {
        vec![effective_target_dir, default_target_dir]
    }
}

fn effective_cargo_target_dir(workspace_root: &Path) -> PathBuf {
    cargo_target_dir_from_env(workspace_root, std::env::var_os("CARGO_TARGET_DIR"))
}

fn cargo_target_dir_from_env(workspace_root: &Path, target_dir: Option<OsString>) -> PathBuf {
    let Some(target_dir) = target_dir else {
        return workspace_root.join("target");
    };
    if target_dir.is_empty() {
        return workspace_root.join("target");
    }
    let target_dir = PathBuf::from(target_dir);
    if target_dir.is_absolute() {
        target_dir
    } else {
        workspace_root.join(target_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_order_is_aux_then_exe_then_targets() {
        let dirs = assemble_candidate_dirs(
            Some(PathBuf::from("/exe")),
            Some(PathBuf::from("/aux/debug")),
            vec![
                PathBuf::from("/repo/target/release"),
                PathBuf::from("/repo/target/debug"),
            ],
        );
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/aux/debug"),
                PathBuf::from("/exe"),
                PathBuf::from("/repo/target/release"),
                PathBuf::from("/repo/target/debug"),
            ]
        );
    }

    #[test]
    fn candidate_order_skips_absent_exe_and_aux() {
        let dirs = assemble_candidate_dirs(None, None, vec![PathBuf::from("/repo/target/debug")]);
        assert_eq!(dirs, vec![PathBuf::from("/repo/target/debug")]);
    }

    #[test]
    fn first_existing_returns_first_dir_holding_the_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("mvm-hvf-supervisor"), b"bin").unwrap();
        let found = first_existing_bin("mvm-hvf-supervisor", &[a.clone(), b.clone()]);
        assert_eq!(found, Some(b.join("mvm-hvf-supervisor")));
    }

    #[test]
    fn first_existing_none_when_absent_everywhere() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            first_existing_bin("mvm-hvf-supervisor", &[tmp.path().to_path_buf()]),
            None
        );
    }

    #[test]
    fn stale_marker_sits_beside_the_binary() {
        assert_eq!(
            stale_marker_for(Path::new("/aux/debug/mvm-hvf-supervisor")),
            PathBuf::from("/aux/debug/mvm-hvf-supervisor.mvm-stale")
        );
    }

    #[test]
    fn unmarked_binary_is_admitted() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        assert!(refuse_if_stale(&bin, false).is_ok());
    }

    #[test]
    fn marked_binary_is_refused_with_an_actionable_message() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();

        let err = refuse_if_stale(&bin, false).unwrap_err().to_string();
        assert!(err.contains("does NOT contain this source"), "{err}");
        assert!(err.contains("just embed-refresh"), "{err}");
        assert!(err.contains("MVM_ALLOW_STALE_AUX"), "{err}");
    }

    #[test]
    fn marked_binary_is_admitted_when_the_override_is_set() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();
        assert!(refuse_if_stale(&bin, true).is_ok());
    }

    /// A marker for one helper must not condemn its neighbours — the build
    /// script reuses and rebuilds them independently.
    #[test]
    fn marker_is_scoped_to_one_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let stale = tmp.path().join("mvm-hvf-supervisor");
        let fresh = tmp.path().join("mvm-network-endpoint");
        std::fs::write(&stale, b"bin").unwrap();
        std::fs::write(&fresh, b"bin").unwrap();
        std::fs::write(stale_marker_for(&stale), b"stale").unwrap();

        assert!(refuse_if_stale(&stale, false).is_err());
        assert!(refuse_if_stale(&fresh, false).is_ok());
    }

    fn hvf_spec() -> AuxBin<'static> {
        AuxBin {
            bin: "mvm-hvf-supervisor",
            env_var: "MVM_HVF_SUPERVISOR_PATH",
        }
    }

    /// The refusal must be reachable through `resolve`, not merely defined —
    /// an unwired gate is indistinguishable from no gate at all.
    #[test]
    fn resolve_refuses_a_stale_helper_found_by_directory_search() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();

        let err = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
                allow_stale: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("just embed-refresh"), "{err}");
    }

    /// An explicit path override names a specific file but does not vouch for
    /// its freshness, so it is gated on the same marker.
    #[test]
    fn resolve_refuses_a_stale_helper_reached_by_env_override() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();

        let err = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: Some(bin.clone()),
                dirs: Vec::new(),
                allow_stale: false,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("just embed-refresh"), "{err}");
    }

    #[test]
    fn resolve_admits_a_fresh_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();

        let got = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
                allow_stale: false,
            },
        )
        .unwrap();
        assert_eq!(got, bin);
    }

    #[test]
    fn resolve_admits_a_stale_helper_under_the_override() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();

        let got = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
                allow_stale: true,
            },
        )
        .unwrap();
        assert_eq!(got, bin);
    }

    /// A marker must not be mistaken for the binary itself.
    #[test]
    fn resolve_does_not_return_the_marker_file() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();
        std::fs::write(stale_marker_for(&bin), b"stale").unwrap();

        let got = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
                allow_stale: true,
            },
        )
        .unwrap();
        assert!(!got.to_string_lossy().ends_with(".mvm-stale"), "{got:?}");
    }

    #[test]
    fn libkrun_missing_hint_mentions_libkrun() {
        assert!(missing_hint("mvm-libkrun-supervisor").contains("libkrun"));
        assert_eq!(missing_hint("mvm-hvf-supervisor"), "");
    }

    #[test]
    fn cargo_target_dir_from_env_honors_absolute_and_relative_overrides() {
        let root = Path::new("/repo/mvm");
        assert_eq!(cargo_target_dir_from_env(root, None), root.join("target"));
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("/tmp/mvm-target"))),
            Path::new("/tmp/mvm-target")
        );
        assert_eq!(
            cargo_target_dir_from_env(root, Some(OsString::from("build/target"))),
            root.join("build/target")
        );
    }
}
