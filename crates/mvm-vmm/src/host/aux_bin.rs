//! Resolver for the per-VM host helper binaries `mvmctl` spawns — the backend
//! supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`), the
//! substitution endpoint, and the qemu bridge (a re-exec of `mvmctl`
//! itself). Each is an ordinary workspace `[[bin]]`, produced by `cargo
//! build` into `target/<profile>/`.
//!
//! Path resolution (first existing file wins) is [`resolve`]:
//! `$<ENV_VAR>` override → `$MVM_AUX_BIN_DIR` → alongside the current exe →
//! workspace `target/{release,debug}`. That order spans build profiles on
//! purpose, and cargo never rebuilds a helper because the other profile's
//! binary is about to run it — so a release `mvmctl` with no release helper
//! beside it is answered by whichever debug helper was built last, at
//! whatever revision. When the config contract has moved since, the helper
//! refuses to start with a JSON parse error deep into a `machine run`.
//!
//! [`resolve_verified`] closes that hole. Every helper compiled from this
//! tree answers the `--contract-version` probe with
//! [`helper_contract::HOST_HELPER_CONTRACT_VERSION`]; a helper that answers
//! differently — or not at all, since pre-probe binaries exit non-zero — is
//! stale. A stale helper found inside this checkout's own `target/`
//! directories is rebuilt automatically in the running binary's profile;
//! anything else (an installed layout, an exe-dir copy, an env override) is
//! a hard error naming both sides and the exact command that fixes it. A
//! stale helper is never returned.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use crate::host::helper_contract;

/// A per-VM helper binary, its path-override env var, and the cargo package
/// that builds it (used when an automatic rebuild is required).
pub struct AuxBin<'a> {
    /// Binary/file name, e.g. `mvm-hvf-supervisor`.
    pub bin: &'a str,
    /// Path-override env var, e.g. `MVM_HVF_SUPERVISOR_PATH`.
    pub env_var: &'a str,
    /// Cargo package whose build produces this helper, e.g. `mvm-hostd`.
    pub rebuild_package: &'a str,
}

/// Resolve `spec` to an on-disk binary. Never builds — a missing one is a
/// hard error with a recovery hint. Availability probes (doctor, backend
/// selection) use this; everything that is about to *spawn* the helper must
/// use [`resolve_verified`].
pub fn resolve(spec: &AuxBin) -> Result<PathBuf> {
    resolve_from(spec, &lookup_from_env(spec))
}

/// Resolve `spec` and refuse to return a helper that does not provably speak
/// this build's config contract. See the module doc.
pub fn resolve_verified(spec: &AuxBin) -> Result<PathBuf> {
    resolve_verified_in(spec, &lookup_from_env(spec), &VerifyEnv::from_process())
}

pub(crate) fn resolve_verified_in(
    spec: &AuxBin,
    lookup: &Lookup,
    env: &VerifyEnv,
) -> Result<PathBuf> {
    let resolved = resolve_from(spec, lookup)?;
    match probe_contract(&resolved, env.probe_timeout) {
        ProbeOutcome::Answered(version)
            if version == helper_contract::HOST_HELPER_CONTRACT_VERSION =>
        {
            Ok(resolved)
        }
        stale => recover_stale_helper(spec, lookup, env, &resolved, &stale),
    }
}

/// How a helper answered (or failed to answer) the contract probe.
enum ProbeOutcome {
    /// It printed a parseable contract version.
    Answered(u32),
    /// It ran but the answer was unreadable — or it predates the probe flag
    /// and exited non-zero on the unexpected argument.
    Refused {
        /// What the probe observed, for error attribution.
        detail: String,
    },
    /// It did not finish within the deadline.
    TimedOut,
}

/// Deadline for one contract probe. Helpers answer instantly (the probe is
/// handled before anything else in their `main`); a helper that exceeds this
/// is pathological.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `helper --contract-version` and classify the answer.
fn probe_contract(helper: &Path, timeout: Duration) -> ProbeOutcome {
    let child = match Command::new(helper)
        .arg(helper_contract::CONTRACT_PROBE_FLAG)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return ProbeOutcome::Refused {
                detail: format!("could not execute it: {e}"),
            };
        }
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // On a timeout the outcome is decided without this result; the
        // thread still reaps the child when it eventually exits.
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return ProbeOutcome::Refused {
                detail: format!("waiting on it failed: {e}"),
            };
        }
        Err(mpsc::RecvTimeoutError::Timeout) => return ProbeOutcome::TimedOut,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return ProbeOutcome::Refused {
                detail: "the probe observer died".to_string(),
            };
        }
    };
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        match helper_contract::parse_probe_version(&stdout) {
            Some(version) => ProbeOutcome::Answered(version),
            None => ProbeOutcome::Refused {
                detail: format!("unrecognized probe answer {stdout:?}"),
            },
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = stderr
            .lines()
            .filter(|line| !line.trim().is_empty())
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" ");
        ProbeOutcome::Refused {
            detail: format!("probe exited with {}: {}", output.status, tail.trim()),
        }
    }
}

/// One-sentence description of a stale probe, grammatically fit for both
/// "helper at path {detail}" messages.
fn stale_detail(stale: &ProbeOutcome) -> String {
    match stale {
        ProbeOutcome::Answered(version) => format!("speaks contract version {version}"),
        ProbeOutcome::Refused { detail } => {
            format!("does not answer the contract probe ({detail})")
        }
        ProbeOutcome::TimedOut => {
            "did not answer the contract probe within the deadline".to_string()
        }
    }
}

/// Everything [`resolve_verified_in`] reads from the process, gathered into
/// one struct so the verification rules are testable without mutating
/// process-global env or invoking a real cargo build.
pub(crate) struct VerifyEnv {
    /// Root of the source checkout this binary was built from, when that
    /// root still looks like a checkout (a workspace `Cargo.toml` present).
    workspace_root: Option<PathBuf>,
    /// Build profile of the running exe, when its path reveals one.
    exe_profile: Option<BuildProfile>,
    /// `cargo` used for an automatic rebuild.
    cargo: PathBuf,
    probe_timeout: Duration,
}

impl VerifyEnv {
    fn from_process() -> Self {
        let workspace_root =
            workspace_root_from_manifest_dir().filter(|root| root.join("Cargo.toml").is_file());
        Self {
            workspace_root,
            exe_profile: std::env::current_exe()
                .ok()
                .as_deref()
                .and_then(build_profile_of),
            cargo: PathBuf::from("cargo"),
            probe_timeout: PROBE_TIMEOUT,
        }
    }
}

fn recover_stale_helper(
    spec: &AuxBin,
    lookup: &Lookup,
    env: &VerifyEnv,
    resolved: &Path,
    stale: &ProbeOutcome,
) -> Result<PathBuf> {
    let Some(plan) = RebuildPlan::new(spec, resolved, env) else {
        let command = manual_rebuild_command(spec, env.exe_profile);
        let mut advice = format!("Rebuild the matching helper with `{command}`.");
        if lookup.override_path.is_some() {
            advice = format!(
                "{env_var} overrides helper resolution; point it at a matching build or \
                 unset it. Then rebuild with `{command}` if needed.",
                env_var = spec.env_var,
            );
        }
        bail!(
            "{bin} at {path} {detail}, but this mvmctl requires contract version \
             {required}. {advice}",
            bin = spec.bin,
            path = resolved.display(),
            detail = stale_detail(stale),
            required = helper_contract::HOST_HELPER_CONTRACT_VERSION,
        );
    };

    crate::host::ui::warn(&format!(
        "{bin} at {path} {detail}; rebuilding with `{command}` …",
        bin = spec.bin,
        path = resolved.display(),
        detail = stale_detail(stale),
        command = plan.command_line(),
    ));
    plan.run(env)?;
    let rebuilt = resolve_from(spec, lookup)?;
    match probe_contract(&rebuilt, env.probe_timeout) {
        ProbeOutcome::Answered(version)
            if version == helper_contract::HOST_HELPER_CONTRACT_VERSION =>
        {
            Ok(rebuilt)
        }
        still_stale => bail!(
            "rebuilt {bin} at {path} {detail}; the rebuild did not produce a helper \
             speaking contract version {required}. Run `{command}` yourself and check \
             its output.",
            bin = spec.bin,
            path = rebuilt.display(),
            detail = stale_detail(&still_stale),
            required = helper_contract::HOST_HELPER_CONTRACT_VERSION,
            command = plan.command_line(),
        ),
    }
}

/// The build command a person can run by hand: the package that produces the
/// helper, in the running binary's profile when it is known (advising a bare
/// `cargo build` from a release `mvmctl` rebuilds the debug helper the
/// release one does not use, so the command appears to succeed and the next
/// launch fails identically).
fn manual_rebuild_command(spec: &AuxBin, exe_profile: Option<BuildProfile>) -> String {
    let flag = exe_profile.map_or("", BuildProfile::cargo_flag);
    format!("cargo build{flag} -p {} --bins", spec.rebuild_package)
}

/// One automatic rebuild of a stale helper.
#[derive(Debug, PartialEq, Eq)]
struct RebuildPlan {
    root: PathBuf,
    args: Vec<String>,
}

impl RebuildPlan {
    /// A rebuild can fix `resolved` only when the helper lives in this
    /// checkout's own `target/` directories — rebuilding the workspace is
    /// what changes what resolution picks there. An installed helper, an
    /// exe-dir copy, or an env-pointed one is outside cargo's reach, and no
    /// plan is the honest answer.
    fn new(spec: &AuxBin, resolved: &Path, env: &VerifyEnv) -> Option<Self> {
        let root = env.workspace_root.as_ref()?;
        let parent = resolved.parent()?;
        if !workspace_target_dirs_for(root)
            .iter()
            .any(|dir| dir == parent)
        {
            return None;
        }
        let profile = env.exe_profile.or_else(|| build_profile_of(resolved))?;
        let mut args = vec!["build".to_string()];
        if profile == BuildProfile::Release {
            args.push("--release".to_string());
        }
        args.push("-p".to_string());
        args.push(spec.rebuild_package.to_string());
        args.push("--bins".to_string());
        Some(Self {
            root: root.clone(),
            args,
        })
    }

    fn command_line(&self) -> String {
        format!("cargo {}", self.args.join(" "))
    }

    fn run(&self, env: &VerifyEnv) -> Result<()> {
        let output = Command::new(&env.cargo)
            .args(&self.args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| {
                anyhow!(
                    "could not run `{}` ({e}); run it yourself from {}",
                    self.command_line(),
                    self.root.display(),
                )
            })?;
        if output.status.success() {
            return Ok(());
        }
        let tail = [output.stdout, output.stderr]
            .iter()
            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
            .collect::<Vec<_>>()
            .concat();
        let tail = tail
            .lines()
            .filter(|line| !line.trim().is_empty())
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "`{}` failed ({}) with:\n{tail}\nrun it yourself from {} and fix the errors",
            self.command_line(),
            output.status,
            self.root.display(),
        )
    }
}

/// Everything `resolve` reads from the environment, gathered so the
/// resolution rules are testable without mutating process-global env.
pub(crate) struct Lookup {
    pub(crate) override_path: Option<PathBuf>,
    pub(crate) dirs: Vec<PathBuf>,
}

fn lookup_from_env(spec: &AuxBin) -> Lookup {
    Lookup {
        override_path: std::env::var_os(spec.env_var).map(PathBuf::from),
        dirs: assemble_candidate_dirs(
            current_exe_dir(),
            aux_bin_dir_from_env(),
            workspace_target_dirs(),
        ),
    }
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
        "{bin} not found. It is a per-VM host helper `[[bin]]` of {pkg}; on \
         a source checkout run `cargo build --bins` (or `just \
         build-supervisors`), or set {env}=<path>.{hint}",
        bin = spec.bin,
        pkg = spec.rebuild_package,
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
    workspace_root_from_manifest_dir()
        .map_or_else(Vec::new, |root| workspace_target_dirs_for(&root))
}

fn workspace_target_dirs_for(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for base in source_checkout_target_dirs(root) {
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

/// The cargo build profile a binary was produced under.
///
/// Only the two cargo emits without a custom profile. A custom one lands in
/// `target/<name>/` and reads as [`None`] rather than being guessed at: this
/// type exists to pick a rebuild profile, and an unrecognised name would
/// manufacture a choice out of no information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    /// `target/debug`.
    Debug,
    /// `target/release`.
    Release,
}

impl BuildProfile {
    /// The cargo flag that selects this profile, ready to interpolate after
    /// `cargo build`. Empty for debug, which is cargo's default.
    pub fn cargo_flag(self) -> &'static str {
        match self {
            Self::Debug => "",
            Self::Release => " --release",
        }
    }
}

/// Which profile a binary sits under, read from its parent directory name.
pub fn build_profile_of(path: &Path) -> Option<BuildProfile> {
    match path.parent()?.file_name()?.to_str()? {
        "debug" => Some(BuildProfile::Debug),
        "release" => Some(BuildProfile::Release),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn hvf_spec() -> AuxBin<'static> {
        AuxBin {
            bin: "mvm-hvf-supervisor",
            env_var: "MVM_HVF_SUPERVISOR_PATH",
            rebuild_package: "mvm-hostd",
        }
    }

    fn write_exe(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// A helper script that answers the probe with `version`.
    fn answering_helper(bin: &str, version: u32) -> String {
        format!("#!/bin/sh\nprintf '%s\\n' '{bin} contract-version={version}'\n")
    }

    /// A stand-in for `cargo` that rebuilds every requested host helper as a
    /// probe-answering script under `target/<profile>/`, relative to its cwd
    /// (the workspace root the resolver sets).
    fn fixing_cargo(bin: &str) -> String {
        format!(
            "#!/bin/sh\n\
             profile=debug\n\
             for arg in \"$@\"; do\n\
             \x20   if [ \"$arg\" = \"--release\" ]; then profile=release; fi\n\
             done\n\
             mkdir -p \"target/$profile\"\n\
             cat > \"target/$profile/{bin}\" <<'PROBE_EOF'\n\
             #!/bin/sh\n\
             printf '%s\\n' '{bin} contract-version={current}'\n\
             PROBE_EOF\n\
             chmod +x \"target/$profile/{bin}\"\n",
            current = helper_contract::HOST_HELPER_CONTRACT_VERSION,
        )
    }

    /// A stand-in for `cargo` that succeeds without producing anything —
    /// the rebuild-that-doesn't-fix case.
    fn no_op_cargo() -> String {
        "#!/bin/sh\nexit 0\n".to_string()
    }

    /// A stand-in for `cargo` that leaves a marker file when run, so tests
    /// can assert no rebuild was attempted.
    fn marker_cargo(marker: &Path) -> String {
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display())
    }

    fn test_env(workspace_root: Option<PathBuf>) -> VerifyEnv {
        VerifyEnv {
            workspace_root,
            exe_profile: None,
            cargo: PathBuf::from("cargo"),
            probe_timeout: PROBE_TIMEOUT,
        }
    }

    /// A scratch workspace: a `Cargo.toml` plus `target/{release,debug}/`.
    fn scratch_checkout(tmp: &Path) -> PathBuf {
        let root = tmp.join("ws");
        std::fs::create_dir_all(root.join("target/release")).unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        root
    }

    #[test]
    fn verified_resolve_accepts_a_helper_with_the_current_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("mvm-hvf-supervisor");
        write_exe(
            &bin,
            &answering_helper(
                "mvm-hvf-supervisor",
                helper_contract::HOST_HELPER_CONTRACT_VERSION,
            ),
        );

        let got = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
            &test_env(None),
        )
        .unwrap();
        assert_eq!(got, bin);
    }

    #[test]
    fn verified_resolve_rejects_an_older_contract_without_a_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        write_exe(
            &tmp.path().join("mvm-hvf-supervisor"),
            &answering_helper("mvm-hvf-supervisor", 0),
        );

        let err = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
            &test_env(None),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("contract version 0"), "{err}");
        assert!(
            err.contains(&format!(
                "requires contract version {}",
                helper_contract::HOST_HELPER_CONTRACT_VERSION
            )),
            "{err}"
        );
        assert!(err.contains("cargo build -p mvm-hostd --bins"), "{err}");
    }

    #[test]
    fn verified_resolve_rebuilds_a_stale_helper_inside_the_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let stale = root.join("target/debug/mvm-hvf-supervisor");
        write_exe(&stale, &answering_helper("mvm-hvf-supervisor", 0));

        let cargo = tmp.path().join("cargo");
        write_exe(&cargo, &fixing_cargo("mvm-hvf-supervisor"));

        let mut env = test_env(Some(root.clone()));
        env.exe_profile = Some(BuildProfile::Release);
        env.cargo = cargo;

        // Resolution order inside a checkout is release before debug, so the
        // rebuilt helper must win over the stale debug one.
        let lookup = Lookup {
            override_path: None,
            dirs: workspace_target_dirs_for(&root),
        };
        let got = resolve_verified_in(&hvf_spec(), &lookup, &env).unwrap();
        assert_eq!(got, root.join("target/release/mvm-hvf-supervisor"));
        assert_ne!(got, stale);
    }

    #[test]
    fn verified_resolve_bails_when_the_rebuild_does_not_fix_the_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        write_exe(
            &root.join("target/debug/mvm-hvf-supervisor"),
            &answering_helper("mvm-hvf-supervisor", 0),
        );
        let cargo = tmp.path().join("cargo");
        write_exe(&cargo, &no_op_cargo());

        let mut env = test_env(Some(root.clone()));
        env.cargo = cargo;
        let lookup = Lookup {
            override_path: None,
            dirs: workspace_target_dirs_for(&root),
        };
        let err = resolve_verified_in(&hvf_spec(), &lookup, &env)
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not produce a helper"), "{err}");
        assert!(err.contains("cargo build -p mvm-hostd --bins"), "{err}");
    }

    #[test]
    fn verified_resolve_reports_a_failed_rebuild_with_cargo_output() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        write_exe(
            &root.join("target/debug/mvm-hvf-supervisor"),
            &answering_helper("mvm-hvf-supervisor", 0),
        );
        let cargo = tmp.path().join("cargo");
        write_exe(
            &cargo,
            "#!/bin/sh\necho 'error: broken workspace' >&2\nexit 1\n",
        );

        let mut env = test_env(Some(root.clone()));
        env.cargo = cargo;
        let lookup = Lookup {
            override_path: None,
            dirs: workspace_target_dirs_for(&root),
        };
        let err = resolve_verified_in(&hvf_spec(), &lookup, &env)
            .unwrap_err()
            .to_string();
        assert!(err.contains("broken workspace"), "{err}");
        assert!(err.contains("cargo build -p mvm-hostd --bins"), "{err}");
    }

    #[test]
    fn verified_resolve_never_rebuilds_a_helper_outside_the_checkout_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let plain = tmp.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        write_exe(
            &plain.join("mvm-hvf-supervisor"),
            &answering_helper("mvm-hvf-supervisor", 0),
        );
        let marker = tmp.path().join("ran");
        let cargo = tmp.path().join("cargo");
        write_exe(&cargo, &marker_cargo(&marker));

        let mut env = test_env(Some(root));
        env.cargo = cargo;
        let err = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![plain],
            },
            &env,
        )
        .unwrap_err()
        .to_string();
        assert!(!marker.exists(), "no rebuild may be attempted: {err}");
        assert!(err.contains("requires contract version"), "{err}");
    }

    #[test]
    fn verified_resolve_never_rebuilds_an_env_override() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let override_path = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&override_path).unwrap();
        write_exe(
            &override_path.join("mvm-hvf-supervisor"),
            &answering_helper("mvm-hvf-supervisor", 0),
        );
        let marker = tmp.path().join("ran");
        let cargo = tmp.path().join("cargo");
        write_exe(&cargo, &marker_cargo(&marker));

        let mut env = test_env(Some(root));
        env.cargo = cargo;
        let err = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: Some(override_path.join("mvm-hvf-supervisor")),
                dirs: vec![],
            },
            &env,
        )
        .unwrap_err()
        .to_string();
        assert!(!marker.exists(), "no rebuild may be attempted: {err}");
        assert!(err.contains("MVM_HVF_SUPERVISOR_PATH"), "{err}");
    }

    #[test]
    fn a_helper_that_exits_without_answering_is_treated_as_stale() {
        // Pre-probe helpers fail reading their stdin config instead of
        // answering — the resolver must read that as "stale", never as a
        // usable helper.
        let tmp = tempfile::tempdir().unwrap();
        write_exe(
            &tmp.path().join("mvm-hvf-supervisor"),
            "#!/bin/sh\nexit 1\n",
        );

        let err = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
            &test_env(None),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not answer the contract probe"), "{err}");
    }

    #[test]
    fn a_probe_that_times_out_is_treated_as_stale() {
        let tmp = tempfile::tempdir().unwrap();
        write_exe(
            &tmp.path().join("mvm-hvf-supervisor"),
            "#!/bin/sh\nsleep 60\n",
        );

        let mut env = test_env(None);
        env.probe_timeout = Duration::from_millis(100);
        let err = resolve_verified_in(
            &hvf_spec(),
            &Lookup {
                override_path: None,
                dirs: vec![tmp.path().to_path_buf()],
            },
            &env,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("within the deadline"), "{err}");
    }

    #[test]
    fn rebuild_plan_matches_the_running_exes_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let helper = root.join("target/debug/mvm-hvf-supervisor");
        write_exe(&helper, "#!/bin/sh\n");

        for (exe_profile, expect_release) in [(Some(BuildProfile::Release), true), (None, false)] {
            let env = VerifyEnv {
                workspace_root: Some(root.clone()),
                exe_profile,
                cargo: PathBuf::from("cargo"),
                probe_timeout: PROBE_TIMEOUT,
            };
            let plan = RebuildPlan::new(&hvf_spec(), &helper, &env)
                .unwrap_or_else(|| panic!("plan must exist for {exe_profile:?}"));
            assert_eq!(plan.args.contains(&"--release".to_string()), expect_release);
            assert_eq!(
                plan.command_line(),
                if expect_release {
                    "cargo build --release -p mvm-hostd --bins"
                } else {
                    "cargo build -p mvm-hostd --bins"
                }
            );
        }
    }

    #[test]
    fn rebuild_plan_exists_only_for_checkout_target_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let env = VerifyEnv {
            workspace_root: Some(root.clone()),
            exe_profile: None,
            cargo: PathBuf::from("cargo"),
            probe_timeout: PROBE_TIMEOUT,
        };

        let in_checkout = root.join("target/release/mvm-hvf-supervisor");
        write_exe(&in_checkout, "#!/bin/sh\n");
        assert!(RebuildPlan::new(&hvf_spec(), &in_checkout, &env).is_some());

        let elsewhere = tmp.path().join("plain").join("mvm-hvf-supervisor");
        std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        write_exe(&elsewhere, "#!/bin/sh\n");
        assert_eq!(RebuildPlan::new(&hvf_spec(), &elsewhere, &env), None);

        let no_root = VerifyEnv {
            workspace_root: None,
            ..env
        };
        assert_eq!(RebuildPlan::new(&hvf_spec(), &in_checkout, &no_root), None);
    }

    #[test]
    fn build_profile_of_reads_the_parent_dir_name() {
        for (profile, expected) in [
            ("debug", BuildProfile::Debug),
            ("release", BuildProfile::Release),
        ] {
            assert_eq!(
                build_profile_of(&PathBuf::from(format!("/repo/target/{profile}/mvmctl"))),
                Some(expected)
            );
        }
    }

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
