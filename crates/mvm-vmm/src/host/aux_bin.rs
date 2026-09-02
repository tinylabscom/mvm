//! Resolver for the per-VM host helper binaries `mvmctl` spawns — the backend
//! supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`) and the
//! substitution endpoint. Each is a separate `[[bin]]` of `mvm-hostd`, produced
//! by an ordinary workspace `cargo build` into `target/<profile>/`.
//!
//! Resolution order (first existing file wins): `$<ENV_VAR>` override →
//! `$MVM_AUX_BIN_DIR` (a directory override, for a packaged helper set) →
//! alongside the current exe (a downloaded release ships them there) →
//! workspace `target/{release,debug}`.
//!
//! Freshness is cargo's, not ours. `mvm-cli`'s build script used to compile
//! these into a private target dir so that `cargo run -p mvm-cli` — which
//! builds no sibling `[[bin]]`s — would produce them, and then had to mark the
//! ones it reused so a stale supervisor could be refused at spawn. That cost a
//! duplicate build of `mvm-hostd`'s whole closure per worktree and made
//! staleness representable in the first place. Letting the workspace build own
//! them removes both: cargo rebuilds a helper when its sources change.
//!
//! That holds *within* a profile and not across one, which this resolver spans
//! by design — `target/release` then `target/debug`. Cargo never rebuilds a
//! debug helper because a release binary is about to run it, so a release
//! `mvmctl` with no release helper beside it is answered by whichever debug
//! helper was built last, at whatever revision. When the config contract has
//! moved since, the helper refuses to start and says only that it does not
//! recognise a field. [`profile_mismatch`] is what makes that attributable.

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

/// Resolve `spec` to an on-disk binary. Never builds — a missing one is a hard
/// error with a recovery hint.
pub fn resolve(spec: &AuxBin) -> Result<PathBuf> {
    let resolved = resolve_from(
        spec,
        &Lookup {
            override_path: std::env::var_os(spec.env_var).map(PathBuf::from),
            dirs: assemble_candidate_dirs(
                current_exe_dir(),
                aux_bin_dir_from_env(),
                workspace_target_dirs(),
            ),
        },
    )?;
    warn_once_on_profile_mismatch(spec, &resolved);
    Ok(resolved)
}

/// Say once per process that a helper came from the other build profile.
///
/// Once, not once per helper: a process that picks one helper cross-profile
/// picks all of them that way, because the cause is which profile was built
/// rather than anything about the individual binary. Repeating it per spawn
/// would bury the line that matters under two identical ones.
///
/// A warning and not a refusal. A cross-profile helper is wrong-looking, not
/// necessarily broken — it works whenever the config contract has not moved —
/// and refusing here would break a working setup for a mismatch that is only
/// sometimes fatal. The failure it precedes is already loud; what was missing
/// is the attribution, so that is what this adds.
fn warn_once_on_profile_mismatch(spec: &AuxBin, resolved: &Path) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    let exe = std::env::current_exe().ok();
    let Some(mismatch) = profile_mismatch(exe.as_deref(), resolved) else {
        return;
    };
    if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    crate::host::ui::warn(&profile_mismatch_warning(spec.bin, &mismatch));
}

/// The text for a cross-profile pick, split out so it is assertable without
/// capturing stderr.
fn profile_mismatch_warning(bin: &str, mismatch: &ProfileMismatch) -> String {
    format!(
        "this mvmctl is the {exe} build but {bin} resolved to the {helper} one ({path}). \
         Helpers are searched in target/release before target/debug, so a missing helper \
         beside the running binary is answered silently by the other profile's — at \
         whatever revision it was last built. If their config contract has moved since, \
         {bin} will refuse to start. Build the matching one with `cargo build{flag} \
         -p mvm-hostd --bins`.",
        exe = mismatch.exe.as_str(),
        helper = mismatch.helper.as_str(),
        path = mismatch.helper_path.display(),
        flag = mismatch.exe.cargo_flag(),
    )
}

/// The cargo build profile a binary was produced under.
///
/// Only the two cargo emits without a custom profile. A custom one lands in
/// `target/<name>/` and reads as [`None`] rather than being guessed at: this
/// type exists to compare two binaries, and an unrecognised name on either side
/// would manufacture a mismatch out of no information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    /// `target/debug`.
    Debug,
    /// `target/release`.
    Release,
}

impl BuildProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    /// The cargo flag that selects this profile, ready to interpolate after
    /// `cargo build`. Empty for debug, which is cargo's default.
    pub fn cargo_flag(self) -> &'static str {
        match self {
            Self::Debug => "",
            Self::Release => " --release",
        }
    }
}

/// A helper resolved from a different build profile than the running binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileMismatch {
    /// The running executable's profile.
    pub exe: BuildProfile,
    /// The resolved helper's profile.
    pub helper: BuildProfile,
    /// Where the helper was found.
    pub helper_path: PathBuf,
}

/// Which profile a binary sits under, read from its parent directory name.
pub fn build_profile_of(path: &Path) -> Option<BuildProfile> {
    match path.parent()?.file_name()?.to_str()? {
        "debug" => Some(BuildProfile::Debug),
        "release" => Some(BuildProfile::Release),
        _ => None,
    }
}

/// Describe a cross-profile pick, or [`None`] when there is nothing to say.
///
/// Silent unless *both* sides are recognisable and they differ, so an installed
/// binary — a downloaded release in `~/.local/bin` with its helpers beside it,
/// neither under a cargo target dir — is never accused of a mismatch it cannot
/// have.
pub fn profile_mismatch(exe: Option<&Path>, helper: &Path) -> Option<ProfileMismatch> {
    let exe_profile = build_profile_of(exe?)?;
    let helper_profile = build_profile_of(helper)?;
    (exe_profile != helper_profile).then(|| ProfileMismatch {
        exe: exe_profile,
        helper: helper_profile,
        helper_path: helper.to_path_buf(),
    })
}

/// Everything `resolve` reads from the environment, gathered so the resolution
/// rules are testable without mutating process-global env.
pub(crate) struct Lookup {
    pub(crate) override_path: Option<PathBuf>,
    pub(crate) dirs: Vec<PathBuf>,
}

fn resolve_from(spec: &AuxBin, lookup: &Lookup) -> Result<PathBuf> {
    if let Some(p) = lookup.override_path.clone() {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "{} points at {} which is not a file",
            spec.env_var,
            p.display()
        );
    }
    if let Some(found) = first_existing_bin(spec.bin, &lookup.dirs) {
        return Ok(found);
    }
    bail!(
        "{bin} not found. It is a per-VM host helper `[[bin]]` of mvm-hostd; on \
         a source checkout run `cargo build --bins` (or `just \
         build-supervisors`), or set {env}=<path>.{hint}",
        bin = spec.bin,
        env = spec.env_var,
        hint = missing_hint(spec.bin),
    )
}

/// Ordered directories to search for a helper: the `MVM_AUX_BIN_DIR` override,
/// then the exe dir, then the workspace target dirs. Absent optional dirs are
/// dropped. The override comes first so that pointing at a packaged helper set
/// wins over whatever happens to sit beside the running exe.
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

    /// The failure this exists to attribute: a release `mvmctl` whose own
    /// directory has no helper is answered by `target/debug`, because the
    /// search spans profiles and cargo never rebuilds across one. It works
    /// until the config contract moves, and then the supervisor refuses with a
    /// message about a JSON field.
    #[test]
    fn a_release_exe_answered_by_a_debug_helper_is_a_mismatch() {
        let mismatch = profile_mismatch(
            Some(Path::new("/repo/target/release/mvmctl")),
            Path::new("/repo/target/debug/mvm-hvf-supervisor"),
        )
        .expect("crossing profiles must be reported");

        assert_eq!(mismatch.exe, BuildProfile::Release);
        assert_eq!(mismatch.helper, BuildProfile::Debug);
        assert_eq!(
            mismatch.helper_path,
            Path::new("/repo/target/debug/mvm-hvf-supervisor")
        );
    }

    /// Both directions, because the resolver searches `release` before `debug`
    /// but the exe's own directory before either — so which way the fallthrough
    /// runs depends on which helper is missing, not on a fixed precedence.
    #[test]
    fn a_debug_exe_answered_by_a_release_helper_is_also_a_mismatch() {
        let mismatch = profile_mismatch(
            Some(Path::new("/repo/target/debug/mvmctl")),
            Path::new("/repo/target/release/mvm-libkrun-supervisor"),
        )
        .expect("crossing profiles must be reported in either direction");

        assert_eq!(mismatch.exe, BuildProfile::Debug);
        assert_eq!(mismatch.helper, BuildProfile::Release);
    }

    #[test]
    fn matching_profiles_are_not_a_mismatch() {
        for profile in ["debug", "release"] {
            assert_eq!(
                profile_mismatch(
                    Some(&PathBuf::from(format!("/repo/target/{profile}/mvmctl"))),
                    &PathBuf::from(format!("/repo/target/{profile}/mvm-hvf-supervisor")),
                ),
                None,
                "{profile} against itself is the ordinary case"
            );
        }
    }

    /// A downloaded release ships its helpers beside the binary, and neither
    /// side sits under a cargo target dir. Accusing that layout of a mismatch
    /// would put a rebuild instruction in front of someone with no checkout to
    /// run it in, so an unreadable profile on either side stays silent.
    #[test]
    fn an_installed_binary_is_never_accused_of_a_mismatch() {
        assert_eq!(
            profile_mismatch(
                Some(Path::new("/usr/local/bin/mvmctl")),
                Path::new("/usr/local/bin/mvm-hvf-supervisor"),
            ),
            None
        );
        // One side recognisable is still not enough to conclude anything.
        assert_eq!(
            profile_mismatch(
                Some(Path::new("/usr/local/bin/mvmctl")),
                Path::new("/repo/target/debug/mvm-hvf-supervisor"),
            ),
            None
        );
        assert_eq!(
            profile_mismatch(
                Some(Path::new("/repo/target/release/mvmctl")),
                Path::new("/usr/local/bin/mvm-hvf-supervisor"),
            ),
            None
        );
    }

    /// `current_exe()` can fail, and a diagnostic that cannot read one side has
    /// nothing to compare rather than something to report.
    #[test]
    fn an_unknown_exe_yields_no_mismatch() {
        assert_eq!(
            profile_mismatch(None, Path::new("/repo/target/debug/mvm-hvf-supervisor")),
            None
        );
    }

    /// A custom cargo profile lands in `target/<name>/`, and a test binary in
    /// `target/<profile>/deps/`. Neither is one of the two names, and guessing
    /// at them would manufacture a mismatch out of no information.
    #[test]
    fn only_the_two_cargo_profiles_are_recognised() {
        assert_eq!(
            build_profile_of(Path::new("/repo/target/debug/mvmctl")),
            Some(BuildProfile::Debug)
        );
        assert_eq!(
            build_profile_of(Path::new("/repo/target/release/mvmctl")),
            Some(BuildProfile::Release)
        );
        assert_eq!(
            build_profile_of(Path::new("/repo/target/profiling/mvmctl")),
            None
        );
        assert_eq!(
            build_profile_of(Path::new("/repo/target/debug/deps/mvm_vmm-abc123")),
            None
        );
    }

    /// The warning has to carry the path, both profiles, and a rebuild whose
    /// flag follows the *running* binary rather than the helper that was found.
    #[test]
    fn the_warning_names_both_profiles_and_a_profile_correct_rebuild() {
        let mismatch = profile_mismatch(
            Some(Path::new("/repo/target/release/mvmctl")),
            Path::new("/repo/target/debug/mvm-hvf-supervisor"),
        )
        .unwrap();
        let warning = profile_mismatch_warning("mvm-hvf-supervisor", &mismatch);

        assert!(warning.contains("mvm-hvf-supervisor"), "{warning}");
        assert!(warning.contains("release build"), "{warning}");
        assert!(warning.contains("the debug one"), "{warning}");
        assert!(
            warning.contains("/repo/target/debug/mvm-hvf-supervisor"),
            "naming the file is what makes it checkable: {warning}"
        );
        assert!(
            warning.contains("cargo build --release -p mvm-hostd --bins"),
            "the rebuild must name the running binary's profile, not the helper's: {warning}"
        );
    }

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

    fn hvf_spec() -> AuxBin<'static> {
        AuxBin {
            bin: "mvm-hvf-supervisor",
            env_var: "MVM_HVF_SUPERVISOR_PATH",
        }
    }

    #[test]
    fn resolve_returns_the_first_directory_holding_the_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&bin, b"bin").unwrap();

        let got = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
        )
        .unwrap();
        assert_eq!(got, bin);
    }

    #[test]
    fn resolve_prefers_an_explicit_path_override() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("packaged-hvf-supervisor");
        let decoy = tmp.path().join("mvm-hvf-supervisor");
        std::fs::write(&elsewhere, b"bin").unwrap();
        std::fs::write(&decoy, b"bin").unwrap();

        let got = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: Some(elsewhere.clone()),
                dirs: vec![tmp.path().to_path_buf()],
            },
        )
        .unwrap();
        assert_eq!(got, elsewhere);
    }

    /// The recovery hint has to name a command that actually produces the
    /// helper. Nothing builds it on demand, so a wrong hint is a dead end.
    #[test]
    fn resolve_missing_helper_names_the_command_that_builds_it() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cargo build --bins"), "{err}");
        assert!(err.contains("just build-supervisors"), "{err}");
    }

    #[test]
    fn resolve_reports_an_override_that_is_not_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let err = resolve_from(
            &hvf_spec(),
            &Lookup {
                override_path: Some(missing.clone()),
                dirs: Vec::new(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("MVM_HVF_SUPERVISOR_PATH"), "{err}");
        assert!(err.contains("is not a file"), "{err}");
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
