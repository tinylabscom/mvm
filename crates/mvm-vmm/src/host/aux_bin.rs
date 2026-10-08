//! Resolver for the per-VM host helper binaries `mvmctl` spawns — the backend
//! supervisors (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`), the
//! substitution endpoint, and the qemu bridge (a re-exec of `mvmctl`
//! itself). Each is an ordinary workspace `[[bin]]`, produced by `cargo
//! build` into `target/<profile>/`.
//!
//! Path resolution (first existing file wins) is [`resolve`]:
//! `$<ENV_VAR>` override → `$MVM_AUX_BIN_DIR` → the host binary directory →
//! workspace `target/{release,debug}`. The host binary directory is the one a
//! library embedder declared through [`declare_host_binary_dir`], or else the
//! running executable's own ([`HostProcess::binary_dir`]). That order spans
//! build profiles on purpose, and cargo never rebuilds a helper because the
//! other profile's binary is about to run it — so a release `mvmctl` with no
//! release helper beside it is answered by whichever debug helper was built
//! last, at whatever revision. When the config contract has moved since, the helper
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
//!
//! A contributor build goes one step further, because a root `cargo build`
//! builds `mvmctl` and none of these helpers. Once `mvmctl` has declared
//! [`allow_helper_builds_from_source`], a helper that belongs in the running
//! binary's own `target/<profile>/` is built there with `cargo`, with an
//! announcement, before it is spawned — when it is missing, and when any
//! source cargo recorded for it is newer than it. The contract probe only
//! catches a config shape that moved; this catches every other change, so a
//! fix in a helper cannot be masked by a leftover binary. A helper that needs
//! a macOS entitlement is signed right after the build. An official release, a
//! library embedder, and any helper supplied from outside the checkout never
//! reach `cargo`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use crate::host::codesign::{self, RequiredEntitlement, SignTarget};
use crate::host::helper_contract;
use source_build::{Built, SourceBuild};

mod host_process;
mod source_build;

pub use host_process::{
    CLI_BIN, CliSpawn, CliSpawnRefused, HostBinaryDirError, HostProcess,
    allow_helper_builds_from_source, declare_host_binary_dir, declare_library_embedder,
};

/// A per-VM helper binary, its path-override env var, and how a source
/// checkout builds it.
pub struct AuxBin<'a> {
    /// Binary/file name, e.g. `mvm-hvf-supervisor`.
    pub bin: &'a str,
    /// Path-override env var, e.g. `MVM_HVF_SUPERVISOR_PATH`.
    pub env_var: &'a str,
    /// Cargo package whose build produces this helper, e.g. `mvm-hostd`.
    pub rebuild_package: &'a str,
    /// Features the `[[bin]]` lists under `required-features`. Cargo skips or
    /// refuses the target without them.
    pub required_features: &'a [&'a str],
    /// The macOS entitlement the helper needs, applied as soon as this process
    /// has built it.
    pub entitlement: Option<RequiredEntitlement>,
    /// Other `[[bin]]`s of the same package that the helper itself spawns
    /// from its own directory. A source build builds them with it, since the
    /// helper has no way to build them.
    pub companions: &'a [&'a str],
}

impl<'a> AuxBin<'a> {
    /// A helper that needs no features and no entitlement.
    pub const fn new(bin: &'a str, env_var: &'a str, rebuild_package: &'a str) -> Self {
        Self {
            bin,
            env_var,
            rebuild_package,
            required_features: &[],
            entitlement: None,
            companions: &[],
        }
    }

    /// This helper, built with `features` enabled.
    pub const fn requiring_features(mut self, features: &'a [&'a str]) -> Self {
        self.required_features = features;
        self
    }

    /// This helper, signed with `entitlement` after a build.
    pub const fn signed_with(mut self, entitlement: RequiredEntitlement) -> Self {
        self.entitlement = Some(entitlement);
        self
    }

    /// This helper, built together with the `companions` it spawns.
    pub const fn with_companions(mut self, companions: &'a [&'a str]) -> Self {
        self.companions = companions;
        self
    }
}

/// Resolve `spec` to an on-disk binary. Never builds — a missing one is a
/// hard error with a recovery hint. Code that lists what is installed (the
/// signing sweep) uses this; availability probes use [`available`], and
/// everything that is about to *spawn* the helper must use
/// [`resolve_verified`].
pub fn resolve(spec: &AuxBin) -> Result<PathBuf> {
    resolve_for(spec, &HostProcess::current())
}

/// Whether `spec` can be spawned: it resolves now, or this process builds it
/// from its checkout on first use. Backend selection and doctor ask this, so a
/// contributor build does not report a backend unavailable for want of a
/// helper it would build itself.
pub fn available(spec: &AuxBin) -> bool {
    let host = HostProcess::current();
    let Ok(lookup) = lookup_for(spec, &host) else {
        return false;
    };
    resolve_from(spec, &lookup).is_ok()
        || SourceBuild::plan(spec, &lookup, &VerifyEnv::for_host(&host)).is_some()
}

/// Build `spec` from this process's checkout when this process may and the
/// helper is missing or older than its sources; the built path, or `None` when
/// nothing was built and ordinary resolution applies.
///
/// For helpers spawned without [`resolve_verified`] — the ones that do not
/// answer the contract probe. [`resolve_verified`] does this itself.
pub fn build_from_source_if_needed(spec: &AuxBin, host: &HostProcess) -> Result<Option<PathBuf>> {
    let lookup = lookup_for(spec, host)?;
    Ok(build_if_needed(spec, &lookup, &VerifyEnv::for_host(host))?.map(|built| built.path))
}

fn build_if_needed(spec: &AuxBin, lookup: &Lookup, env: &VerifyEnv) -> Result<Option<Built>> {
    let Some(build) = SourceBuild::plan(spec, lookup, env) else {
        return Ok(None);
    };
    let Some(reason) = build.needed() else {
        return Ok(None);
    };
    crate::host::ui::admit_cold_build(&format!("the `{}` host helper", spec.bin))
        .map_err(anyhow::Error::msg)?;
    build.run(spec, env, reason).map(Some)
}

/// [`resolve`] on behalf of an explicitly described process.
pub fn resolve_for(spec: &AuxBin, host: &HostProcess) -> Result<PathBuf> {
    resolve_from(spec, &lookup_for(spec, host)?)
}

/// Resolve `spec` and refuse to return a helper that does not provably speak
/// this build's config contract. See the module doc.
pub fn resolve_verified(spec: &AuxBin) -> Result<PathBuf> {
    resolve_verified_for(spec, &HostProcess::current())
}

/// [`resolve_verified`] on behalf of an explicitly described process.
pub fn resolve_verified_for(spec: &AuxBin, host: &HostProcess) -> Result<PathBuf> {
    resolve_verified_in(spec, &lookup_for(spec, host)?, &VerifyEnv::for_host(host))
}

pub(crate) fn resolve_verified_in(
    spec: &AuxBin,
    lookup: &Lookup,
    env: &VerifyEnv,
) -> Result<PathBuf> {
    if let Some(built) = build_if_needed(spec, lookup, env)? {
        return match probe_built_helper(&built.path, env.probe_timeout) {
            ProbeOutcome::Answered(version)
                if version == helper_contract::HOST_HELPER_CONTRACT_VERSION =>
            {
                Ok(built.path)
            }
            stale => Err(build_did_not_fix(spec, &built.path, &stale, &built.command)),
        };
    }
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
    let child = match mvm_core::env_hygiene::helper_command(helper)
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
/// process-global env, invoking a real cargo build, or running `codesign`.
pub(crate) struct VerifyEnv {
    /// Root of the source checkout this binary was built from, when that
    /// root still looks like a checkout (a workspace `Cargo.toml` present).
    workspace_root: Option<PathBuf>,
    /// Build profile of the running exe, when its path reveals one.
    exe_profile: Option<BuildProfile>,
    /// The directory this process's helpers belong in
    /// ([`HostProcess::binary_dir`]); a source build writes there.
    binary_dir: Option<PathBuf>,
    /// Whether this process may build helpers from its checkout
    /// ([`HostProcess::builds_helpers_from_source`]).
    source_builds: bool,
    /// `cargo` used for an automatic build.
    cargo: PathBuf,
    probe_timeout: Duration,
    signer: Box<dyn HelperSigner>,
    /// Where the line announcing a helper build goes.
    notice: Box<dyn Fn(&str)>,
}

impl VerifyEnv {
    fn for_host(host: &HostProcess) -> Self {
        let workspace_root =
            workspace_root_from_manifest_dir().filter(|root| root.join("Cargo.toml").is_file());
        Self {
            workspace_root,
            exe_profile: host.build_profile(),
            binary_dir: host.binary_dir(),
            source_builds: host.builds_helpers_from_source()
                && explicit_helper_source_build_requested(),
            // The cargo that launched `cargo run`, when that is how this
            // process started, so the helper is built by the same toolchain.
            cargo: std::env::var_os("CARGO")
                .filter(|cargo| !cargo.is_empty())
                .map_or_else(|| PathBuf::from("cargo"), PathBuf::from),
            probe_timeout: PROBE_TIMEOUT,
            signer: Box::new(Codesign),
            // Stderr, above any live status line, so neither a JSON verb's
            // stdout nor the spinner of the phase that needed the helper is
            // torn by it.
            notice: Box::new(|line| {
                crate::host::ui::activity::println_above(&format!("[mvm] {line}"));
            }),
        }
    }
}

fn explicit_helper_source_build_requested() -> bool {
    std::env::var("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE").as_deref() == Ok("build")
        || std::env::var_os("MVM_IMAGES_DIR").is_some_and(|value| !value.is_empty())
}

/// Applies a helper's macOS entitlement once this process has built it. A
/// seam so tests can observe the call without running `codesign`.
pub(crate) trait HelperSigner {
    fn sign(&self, helper: &Path, entitlement: RequiredEntitlement) -> Result<()>;
}

/// Ad-hoc signing through [`crate::host::codesign`]; nothing to do off macOS.
struct Codesign;

impl HelperSigner for Codesign {
    fn sign(&self, helper: &Path, entitlement: RequiredEntitlement) -> Result<()> {
        let target = SignTarget {
            path: helper.to_path_buf(),
            required: entitlement,
        };
        match codesign::sign_targets(std::slice::from_ref(&target)).first() {
            Some(report) if !report.entitlements_present => bail!(
                "built {} but `codesign` did not give it the {entitlement:?} entitlement it \
                 needs to run; check that `codesign` works on this host",
                helper.display()
            ),
            _ => Ok(()),
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
    plan.run(env, &format!("Rebuilding {}", spec.bin))?;
    let rebuilt = resolve_from(spec, lookup)?;
    match probe_built_helper(&rebuilt, env.probe_timeout) {
        ProbeOutcome::Answered(version)
            if version == helper_contract::HOST_HELPER_CONTRACT_VERSION =>
        {
            Ok(rebuilt)
        }
        still_stale => Err(build_did_not_fix(
            spec,
            &rebuilt,
            &still_stale,
            &plan.command_line(),
        )),
    }
}

/// Probe a helper cargo has just produced.
///
/// A freshly linked macOS executable can miss its first bounded launch
/// deadline while the host validates it, then answer immediately on the next
/// exec. Cargo already completed successfully, so only this post-build timeout
/// gets one retry; malformed and wrong-version answers still fail closed
/// without retrying.
fn probe_built_helper(helper: &Path, timeout: Duration) -> ProbeOutcome {
    match probe_contract(helper, timeout) {
        ProbeOutcome::TimedOut => probe_contract(helper, timeout),
        answered => answered,
    }
}

fn build_did_not_fix(
    spec: &AuxBin,
    helper: &Path,
    stale: &ProbeOutcome,
    command: &str,
) -> anyhow::Error {
    anyhow!(
        "rebuilt {bin} at {path} {detail}; the rebuild did not produce a helper \
         speaking contract version {required}. Run `{command}` yourself and check \
         its output.",
        bin = spec.bin,
        path = helper.display(),
        detail = stale_detail(stale),
        required = helper_contract::HOST_HELPER_CONTRACT_VERSION,
    )
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

/// One automatic `cargo build` of a helper.
#[derive(Debug, PartialEq, Eq)]
struct RebuildPlan {
    root: PathBuf,
    args: Vec<String>,
    /// The target directory cargo must write to, when that is fixed by where
    /// the running binary lives rather than by whatever `CARGO_TARGET_DIR`
    /// this process inherited.
    target_dir: Option<PathBuf>,
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
        push_features(&mut args, spec.required_features);
        Some(Self {
            root: root.clone(),
            args,
            target_dir: None,
        })
    }

    /// Build just `spec`'s binary, in `profile`, into the target directory
    /// that holds `binary_dir`.
    fn for_helper(spec: &AuxBin, root: &Path, binary_dir: &Path, profile: BuildProfile) -> Self {
        let mut args = vec!["build".to_string()];
        if profile == BuildProfile::Release {
            args.push("--release".to_string());
        }
        args.extend(["-p".to_string(), spec.rebuild_package.to_string()]);
        push_bins(&mut args, spec);
        push_features(&mut args, spec.required_features);
        Self {
            root: root.to_path_buf(),
            args,
            target_dir: binary_dir.parent().map(Path::to_path_buf),
        }
    }

    fn command_line(&self) -> String {
        format!("cargo {}", self.args.join(" "))
    }

    /// Run the build under a status line named `label`. The line appears
    /// only once the build has run long enough to be noticed, so a cargo
    /// freshness check that finds nothing to do leaves no trace; while it
    /// runs, it shows cargo's latest progress line — including cargo waiting
    /// on another build's lock, which would otherwise look like a hang.
    fn run(&self, env: &VerifyEnv, label: &str) -> Result<()> {
        let activity = crate::host::ui::activity::start(label);
        let mut command = mvm_core::env_hygiene::helper_command(&env.cargo);
        command
            .args(&self.args)
            .current_dir(&self.root)
            .env("CARGO_TERM_COLOR", "never")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Some(dir) = &self.target_dir {
            command.env("CARGO_TARGET_DIR", dir);
        }
        let mut child = command.spawn().map_err(|e| {
            anyhow!(
                "could not run `{}` ({e}); run it yourself from {}",
                self.command_line(),
                self.root.display(),
            )
        })?;
        let mut tail = VecDeque::with_capacity(FAILURE_TAIL_LINES);
        if let Some(stderr) = child.stderr.take() {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                activity.set_detail(line);
                if tail.len() == FAILURE_TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line.to_string());
            }
        }
        let status = child.wait().map_err(|e| {
            anyhow!(
                "waiting on `{}` failed ({e}); run it yourself from {}",
                self.command_line(),
                self.root.display(),
            )
        })?;
        if status.success() {
            activity.finish();
            return Ok(());
        }
        drop(activity);
        bail!(
            "`{}` failed ({status}) with:\n{}\nrun it yourself from {} and fix the errors",
            self.command_line(),
            Vec::from(tail).join("\n"),
            self.root.display(),
        )
    }
}

/// How many of cargo's last output lines a failed build reports.
const FAILURE_TAIL_LINES: usize = 5;

/// `--bin` for the helper and for each companion it spawns.
fn push_bins(args: &mut Vec<String>, spec: &AuxBin) {
    for bin in std::iter::once(spec.bin).chain(spec.companions.iter().copied()) {
        args.extend(["--bin".to_string(), bin.to_string()]);
    }
}

fn push_features(args: &mut Vec<String>, features: &[&str]) {
    if !features.is_empty() {
        args.push("--features".to_string());
        args.push(features.join(","));
    }
}

/// Everything `resolve` reads from the environment, gathered so the
/// resolution rules are testable without mutating process-global env.
pub(crate) struct Lookup {
    pub(crate) override_path: Option<PathBuf>,
    pub(crate) dirs: Vec<PathBuf>,
}

/// The lookup for `spec` on behalf of `host`. A library embedder is refused
/// before anything is searched when the helper is `mvmctl` itself: whatever
/// path resolution found, the caller would run it.
fn lookup_for(spec: &AuxBin, host: &HostProcess) -> Result<Lookup> {
    if spec.bin == CLI_BIN {
        host.refuse_cli_spawn(CliSpawn::HostHelper {
            env_var: spec.env_var.to_string(),
        })?;
    }
    Ok(Lookup {
        override_path: std::env::var_os(spec.env_var).map(PathBuf::from),
        dirs: assemble_candidate_dirs(
            host.binary_dir(),
            aux_bin_dir_from_env(),
            workspace_target_dirs(),
        ),
    })
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
         a source checkout build it with `{command}` (add `--release` to match a \
         release build, or use `just payload::supervisors`), or set {env}=<path>.{hint}",
        bin = spec.bin,
        pkg = spec.rebuild_package,
        command = manual_build_command(spec),
        env = spec.env_var,
        hint = missing_hint(spec.bin),
    )
}

/// The command that builds just `spec`, for a person to run. A root
/// `cargo build --bins` is not it: that builds the root package's binaries,
/// and every helper belongs to another package.
fn manual_build_command(spec: &AuxBin) -> String {
    let mut args = vec![
        "cargo".to_string(),
        "build".to_string(),
        "-p".to_string(),
        spec.rebuild_package.to_string(),
    ];
    push_bins(&mut args, spec);
    push_features(&mut args, spec.required_features);
    args.join(" ")
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

/// Whether `dir` names the same directory as one of `dirs`. Compared through
/// symlinks, because the running executable's path is whatever it was invoked
/// by, and a relative or linked spelling must not turn a checkout binary into a
/// stranger.
fn is_one_of(dir: &Path, dirs: &[PathBuf]) -> bool {
    let canonical = |path: &Path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let dir = canonical(dir);
    dirs.iter().any(|candidate| canonical(candidate) == dir)
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
/// `CARGO_TARGET_DIR` override), the fallback for `just payload::supervisors`.
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
    build_profile_of_dir(path.parent()?)
}

/// Which profile a directory of binaries is, read from its own name.
pub fn build_profile_of_dir(dir: &Path) -> Option<BuildProfile> {
    match dir.file_name()?.to_str()? {
        "debug" => Some(BuildProfile::Debug),
        "release" => Some(BuildProfile::Release),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    use super::*;

    fn hvf_spec() -> AuxBin<'static> {
        AuxBin::new("mvm-hvf-supervisor", "MVM_HVF_SUPERVISOR_PATH", "mvm-hostd")
            .signed_with(RequiredEntitlement::Hypervisor)
    }

    fn endpoint_spec() -> AuxBin<'static> {
        AuxBin::new(
            "mvm-network-endpoint",
            "MVM_SUBSTITUTION_ENDPOINT_PATH",
            "mvm-hostd",
        )
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

    /// A stand-in for `cargo` whose freshly rebuilt helper stalls only on its
    /// first probe, then answers normally on the next invocation.
    fn cargo_with_transient_first_probe(bin: &str, marker: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             profile=debug\n\
             for arg in \"$@\"; do\n\
             \x20   if [ \"$arg\" = \"--release\" ]; then profile=release; fi\n\
             done\n\
             mkdir -p \"target/$profile\"\n\
             cat > \"target/$profile/{bin}\" <<'PROBE_EOF'\n\
             #!/bin/sh\n\
             if [ ! -f '{marker}' ]; then\n\
             \x20   touch '{marker}'\n\
             \x20   sleep 1\n\
             \x20   exit 0\n\
             fi\n\
             printf '%s\\n' '{bin} contract-version={current}'\n\
             PROBE_EOF\n\
             chmod +x \"target/$profile/{bin}\"\n",
            marker = marker.display(),
            current = helper_contract::HOST_HELPER_CONTRACT_VERSION,
        )
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
            binary_dir: None,
            source_builds: false,
            cargo: PathBuf::from("cargo"),
            probe_timeout: PROBE_TIMEOUT,
            signer: Box::new(RecordingSigner::default()),
            notice: Box::new(|_| {}),
        }
    }

    /// Records every signing request instead of running `codesign`.
    #[derive(Default, Clone)]
    struct RecordingSigner(Rc<RefCell<Vec<(PathBuf, RequiredEntitlement)>>>);

    impl HelperSigner for RecordingSigner {
        fn sign(&self, helper: &Path, entitlement: RequiredEntitlement) -> Result<()> {
            self.0
                .borrow_mut()
                .push((helper.to_path_buf(), entitlement));
            Ok(())
        }
    }

    /// A contributor `mvmctl` running from `root/target/<profile>`, with the
    /// build, the announcement and the signer all observable.
    struct SourceFixture {
        env: VerifyEnv,
        notices: Rc<RefCell<Vec<String>>>,
        signed: RecordingSigner,
        cargo_log: PathBuf,
    }

    fn source_fixture(tmp: &Path, root: &Path, profile: &str, cargo_body: &str) -> SourceFixture {
        let cargo = tmp.join("cargo");
        write_exe(&cargo, cargo_body);
        let notices = Rc::new(RefCell::new(Vec::new()));
        let signed = RecordingSigner::default();
        let sink = Rc::clone(&notices);
        let mut env = test_env(Some(root.to_path_buf()));
        env.binary_dir = Some(root.join("target").join(profile));
        env.exe_profile = build_profile_of_dir(&root.join("target").join(profile));
        env.source_builds = true;
        env.cargo = cargo;
        env.signer = Box::new(signed.clone());
        env.notice = Box::new(move |line| sink.borrow_mut().push(line.to_string()));
        SourceFixture {
            env,
            notices,
            signed,
            cargo_log: tmp.join("cargo.log"),
        }
    }

    /// A stand-in for `cargo` that logs its arguments and writes every named
    /// `--bin` as a current-contract helper under `$CARGO_TARGET_DIR/<profile>`
    /// — the directory a source build pins, never the process's inherited one.
    fn building_cargo(log: &Path) -> String {
        format!(
            "#!/bin/sh\n\
             echo \"$@\" >> '{log}'\n\
             profile=debug\n\
             bins=\n\
             take_bin=\n\
             for arg in \"$@\"; do\n\
             \x20   if [ -n \"$take_bin\" ]; then bins=\"$bins $arg\"; take_bin=; fi\n\
             \x20   if [ \"$arg\" = \"--release\" ]; then profile=release; fi\n\
             \x20   if [ \"$arg\" = \"--bin\" ]; then take_bin=1; fi\n\
             done\n\
             mkdir -p \"$CARGO_TARGET_DIR/$profile\"\n\
             for bin in $bins; do\n\
             \x20   out=\"$CARGO_TARGET_DIR/$profile/$bin\"\n\
             \x20   printf '#!/bin/sh\\necho \"%s contract-version={current}\"\\n' \"$bin\" > \"$out\"\n\
             \x20   chmod +x \"$out\"\n\
             done\n",
            log = log.display(),
            current = helper_contract::HOST_HELPER_CONTRACT_VERSION,
        )
    }

    /// A stand-in for `cargo` that logs its arguments and changes nothing:
    /// cargo finding every unit fresh.
    fn fresh_cargo(log: &Path) -> String {
        format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display())
    }

    fn cargo_invocations(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn checkout_lookup(root: &Path) -> Lookup {
        Lookup {
            override_path: None,
            dirs: vec![root.join("target/release"), root.join("target/debug")],
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
        // Explicit scratch dirs, not workspace_target_dirs_for: that helper
        // also honors the process CARGO_TARGET_DIR, and under the per-worktree
        // isolation env it would let a real helper shadow the fixture.
        let lookup = Lookup {
            override_path: None,
            dirs: vec![root.join("target/release"), root.join("target/debug")],
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
        // Explicit scratch dirs, not workspace_target_dirs_for: that helper
        // also honors the process CARGO_TARGET_DIR, and under the per-worktree
        // isolation env it would let a real helper shadow the fixture.
        let lookup = Lookup {
            override_path: None,
            dirs: vec![root.join("target/release"), root.join("target/debug")],
        };
        let err = resolve_verified_in(&hvf_spec(), &lookup, &env)
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not produce a helper"), "{err}");
        assert!(err.contains("cargo build -p mvm-hostd --bins"), "{err}");
    }

    #[test]
    fn verified_resolve_retries_a_transient_timeout_after_rebuild() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let stale = root.join("target/debug/mvm-hvf-supervisor");
        write_exe(&stale, &answering_helper("mvm-hvf-supervisor", 0));

        let marker = tmp.path().join("first-probe-started");
        let cargo = tmp.path().join("cargo");
        write_exe(
            &cargo,
            &cargo_with_transient_first_probe("mvm-hvf-supervisor", &marker),
        );

        let mut env = test_env(Some(root.clone()));
        env.cargo = cargo;
        env.probe_timeout = Duration::from_millis(250);
        let lookup = Lookup {
            override_path: None,
            dirs: vec![root.join("target/release"), root.join("target/debug")],
        };

        let got = resolve_verified_in(&hvf_spec(), &lookup, &env).unwrap();
        assert_eq!(got, root.join("target/debug/mvm-hvf-supervisor"));
        assert!(marker.is_file());
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
        // Explicit scratch dirs, not workspace_target_dirs_for: that helper
        // also honors the process CARGO_TARGET_DIR, and under the per-worktree
        // isolation env it would let a real helper shadow the fixture.
        let lookup = Lookup {
            override_path: None,
            dirs: vec![root.join("target/release"), root.join("target/debug")],
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
            let mut env = test_env(Some(root.clone()));
            env.exe_profile = exe_profile;
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
        let env = test_env(Some(root.clone()));

        let in_checkout = root.join("target/release/mvm-hvf-supervisor");
        write_exe(&in_checkout, "#!/bin/sh\n");
        assert!(RebuildPlan::new(&hvf_spec(), &in_checkout, &env).is_some());

        let elsewhere = tmp.path().join("plain").join("mvm-hvf-supervisor");
        std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        write_exe(&elsewhere, "#!/bin/sh\n");
        assert_eq!(RebuildPlan::new(&hvf_spec(), &elsewhere, &env), None);

        let no_root = test_env(None);
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
    /// helper. Where nothing builds it on demand, a wrong hint is a dead end —
    /// and a root `cargo build --bins` builds no helper at all.
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
        assert!(
            err.contains("cargo build -p mvm-hostd --bin mvm-hvf-supervisor"),
            "{err}"
        );
        assert!(!err.contains("cargo build --bins"), "{err}");
        assert!(err.contains("just payload::supervisors"), "{err}");
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

    /// A helper name and override variable no real environment sets, so the
    /// lookup's answer depends only on the process description.
    fn declared_only_spec() -> AuxBin<'static> {
        AuxBin::new(
            "mvm-declared-dir-probe-helper",
            "MVM_DECLARED_DIR_PROBE_HELPER_PATH",
            "mvm-hostd",
        )
    }

    #[test]
    fn a_declared_host_binary_dir_is_searched_in_place_of_the_exe_dir() {
        let declared = tempfile::tempdir().unwrap();
        std::fs::write(declared.path().join(declared_only_spec().bin), b"bin").unwrap();
        let host = HostProcess::undeclared().with_binary_dir(declared.path());

        let lookup = lookup_for(&declared_only_spec(), &host).unwrap();

        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(lookup.dirs.contains(&declared.path().to_path_buf()));
        assert!(!lookup.dirs.contains(&exe_dir), "{:?}", lookup.dirs);
        assert_eq!(
            resolve_from(&declared_only_spec(), &lookup).unwrap(),
            declared.path().join(declared_only_spec().bin)
        );
    }

    #[test]
    fn an_undeclared_process_searches_beside_its_own_executable() {
        let lookup = lookup_for(&declared_only_spec(), &HostProcess::undeclared()).unwrap();

        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(lookup.dirs.contains(&exe_dir), "{:?}", lookup.dirs);
    }

    #[test]
    fn a_library_embedder_is_refused_mvmctl_as_a_helper() {
        let spec = AuxBin::new(CLI_BIN, "MVM_QEMU_BRIDGE_PATH", "mvmctl");
        let host = HostProcess::undeclared().as_library_embedder();

        let err = lookup_for(&spec, &host)
            .err()
            .expect("mvmctl is never resolved for an embedder");
        let refused = err
            .downcast_ref::<CliSpawnRefused>()
            .expect("refusal is typed");
        assert_eq!(
            refused.spawn(),
            &CliSpawn::HostHelper {
                env_var: "MVM_QEMU_BRIDGE_PATH".to_string()
            }
        );
        assert!(resolve_verified_for(&spec, &host).is_err());
    }

    #[test]
    fn mvmctl_is_still_a_helper_for_mvmctl_and_other_helpers_for_an_embedder() {
        let mvmctl = AuxBin::new(CLI_BIN, "MVM_DECLARED_DIR_PROBE_CLI_PATH", "mvmctl");
        assert!(lookup_for(&mvmctl, &HostProcess::undeclared()).is_ok());
        assert!(
            lookup_for(
                &declared_only_spec(),
                &HostProcess::undeclared().as_library_embedder()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_missing_helper_is_built_once_announced_signed_and_resolved() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "release", &building_cargo(&log));

        let got = resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env).unwrap();

        let built = root.join("target/release/mvm-hvf-supervisor");
        assert_eq!(got, built);
        assert_eq!(
            cargo_invocations(&fixture.cargo_log),
            vec!["build --release -p mvm-hostd --bin mvm-hvf-supervisor"]
        );
        let notices = fixture.notices.borrow();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("has not been built"), "{notices:?}");
        assert!(
            notices[0].contains("cargo build --release -p mvm-hostd --bin mvm-hvf-supervisor"),
            "{notices:?}"
        );
        assert_eq!(
            *fixture.signed.0.borrow(),
            vec![(built, RequiredEntitlement::Hypervisor)]
        );
    }

    /// Set `path`'s modification time `age` before now.
    fn age(path: &Path, age: Duration) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }

    /// A current-contract helper under `root/target/<profile>/` whose dep-info
    /// names one source file, with the source and lockfile an hour old.
    fn helper_with_dep_info(root: &Path, profile: &str, bin: &str) -> (PathBuf, PathBuf) {
        let helper = root.join("target").join(profile).join(bin);
        write_exe(
            &helper,
            &answering_helper(bin, helper_contract::HOST_HELPER_CONTRACT_VERSION),
        );
        let source = root.join("crates/mvm-hostd/src/bin/helper main.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "fn main() {}\n").unwrap();
        std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
        let mut dep_info = helper.as_os_str().to_os_string();
        dep_info.push(".d");
        std::fs::write(
            PathBuf::from(dep_info),
            format!(
                "{}: {}\n",
                helper.display(),
                source.display().to_string().replace(' ', "\\ ")
            ),
        )
        .unwrap();
        age(&source, Duration::from_secs(3600));
        age(&root.join("Cargo.lock"), Duration::from_secs(3600));
        (helper, source)
    }

    #[test]
    fn a_helper_newer_than_its_sources_is_neither_built_nor_announced() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let (helper, _) = helper_with_dep_info(&root, "debug", "mvm-hvf-supervisor");
        let body = std::fs::read_to_string(&helper).unwrap();
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "debug", &fresh_cargo(&log));

        let got = resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env).unwrap();

        assert_eq!(got, helper);
        assert_eq!(std::fs::read_to_string(&helper).unwrap(), body);
        assert!(cargo_invocations(&fixture.cargo_log).is_empty());
        assert!(fixture.notices.borrow().is_empty());
        assert!(fixture.signed.0.borrow().is_empty());
    }

    #[test]
    fn a_helper_older_than_a_source_is_rebuilt_announced_and_signed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let (helper, source) = helper_with_dep_info(&root, "release", "mvm-hvf-supervisor");
        age(&helper, Duration::from_secs(7200));
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "release", &building_cargo(&log));

        let got = resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env).unwrap();

        assert_eq!(got, helper);
        assert_eq!(
            cargo_invocations(&fixture.cargo_log),
            vec!["build --release -p mvm-hostd --bin mvm-hvf-supervisor"]
        );
        let notices = fixture.notices.borrow();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("older than its sources"), "{notices:?}");
        assert_eq!(
            *fixture.signed.0.borrow(),
            vec![(helper, RequiredEntitlement::Hypervisor)]
        );
        assert!(source.is_file());
    }

    #[test]
    fn a_helper_cargo_left_no_record_for_is_handed_to_cargo() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let helper = root.join("target/debug/mvm-network-endpoint");
        write_exe(
            &helper,
            &answering_helper(
                "mvm-network-endpoint",
                helper_contract::HOST_HELPER_CONTRACT_VERSION,
            ),
        );
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "debug", &fresh_cargo(&log));

        let got =
            resolve_verified_in(&endpoint_spec(), &checkout_lookup(&root), &fixture.env).unwrap();

        assert_eq!(got, helper);
        assert_eq!(
            cargo_invocations(&fixture.cargo_log),
            vec!["build -p mvm-hostd --bin mvm-network-endpoint"]
        );
        assert!(
            fixture.signed.0.borrow().is_empty(),
            "a helper needing no entitlement is never signed"
        );
    }

    #[test]
    fn a_changed_lockfile_makes_a_helper_out_of_date() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let (helper, _) = helper_with_dep_info(&root, "debug", "mvm-hvf-supervisor");
        assert!(source_build::built_from_current_sources(&helper, &root));

        std::fs::write(root.join("Cargo.lock"), "version = 4\n# bumped\n").unwrap();
        age(&helper, Duration::from_secs(60));

        assert!(!source_build::built_from_current_sources(&helper, &root));
    }

    #[test]
    fn dep_info_inputs_read_every_prerequisite_and_unescape_spaces() {
        let text = "/r/target/debug/h: /r/src/main.rs /r/My\\ Dir/lib.rs\n\n/r/src/main.rs:\n";
        assert_eq!(
            source_build::dep_info_inputs(text),
            vec![
                PathBuf::from("/r/src/main.rs"),
                PathBuf::from("/r/My Dir/lib.rs"),
            ]
        );
    }

    fn host_agent_spec() -> AuxBin<'static> {
        AuxBin::new("mvm-host-agent", "MVM_HOST_AGENT_PATH", "mvm-hostd")
            .with_companions(&["mvm-signer-helper"])
    }

    #[test]
    fn a_helper_is_built_together_with_the_companions_it_spawns() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "release", &building_cargo(&log));

        let built = build_if_needed(&host_agent_spec(), &checkout_lookup(&root), &fixture.env)
            .unwrap()
            .expect("a missing helper is built");

        assert_eq!(built.path, root.join("target/release/mvm-host-agent"));
        assert!(root.join("target/release/mvm-signer-helper").is_file());
        assert_eq!(
            cargo_invocations(&fixture.cargo_log),
            vec!["build --release -p mvm-hostd --bin mvm-host-agent --bin mvm-signer-helper"]
        );
        assert_eq!(fixture.notices.borrow().len(), 1);
    }

    #[test]
    fn a_missing_companion_is_reason_enough_to_build() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        helper_with_dep_info(&root, "debug", "mvm-host-agent");
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "debug", &building_cargo(&log));

        assert!(
            build_if_needed(&host_agent_spec(), &checkout_lookup(&root), &fixture.env)
                .unwrap()
                .is_some()
        );
        assert!(root.join("target/debug/mvm-signer-helper").is_file());
    }

    #[test]
    fn nothing_is_built_for_a_process_without_source_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let marker = tmp.path().join("ran");
        let mut fixture = source_fixture(tmp.path(), &root, "release", &marker_cargo(&marker));
        fixture.env.source_builds = false;

        assert!(
            build_if_needed(&host_agent_spec(), &checkout_lookup(&root), &fixture.env)
                .unwrap()
                .is_none()
        );
        assert!(!marker.exists());
    }

    #[test]
    fn a_source_build_names_the_features_the_helper_requires() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "debug", &building_cargo(&log));
        let spec = AuxBin::new(
            "mvm-libkrun-supervisor",
            "MVM_LIBKRUN_SUPERVISOR_PATH",
            "mvm-hostd",
        )
        .requiring_features(&["libkrun-sys"]);

        resolve_verified_in(&spec, &checkout_lookup(&root), &fixture.env).unwrap();

        assert_eq!(
            cargo_invocations(&fixture.cargo_log),
            vec!["build -p mvm-hostd --bin mvm-libkrun-supervisor --features libkrun-sys"]
        );
    }

    #[test]
    fn without_source_builds_a_missing_helper_gets_the_refusal_it_always_did() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let marker = tmp.path().join("ran");
        let lookup = checkout_lookup(&root);
        let expected = resolve_from(&hvf_spec(), &lookup).unwrap_err().to_string();

        // A release build never declares source builds; a library embedder is
        // refused them even when the declaration was made.
        for host in [
            HostProcess::undeclared(),
            HostProcess::undeclared()
                .allowing_helper_builds_from_source()
                .as_library_embedder(),
        ] {
            let fixture = source_fixture(tmp.path(), &root, "release", &marker_cargo(&marker));
            let env = VerifyEnv {
                source_builds: host.builds_helpers_from_source(),
                ..fixture.env
            };

            let err = resolve_verified_in(&hvf_spec(), &lookup, &env)
                .unwrap_err()
                .to_string();

            assert_eq!(err, expected);
            assert!(err.contains("not found"), "{err}");
            assert!(!marker.exists(), "no build may be attempted for {host:?}");
            assert!(fixture.notices.borrow().is_empty());
            assert!(fixture.signed.0.borrow().is_empty());
        }
    }

    #[test]
    fn a_helper_supplied_from_outside_the_checkout_is_never_built() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let packaged = tmp.path().join("packaged");
        std::fs::create_dir_all(&packaged).unwrap();
        write_exe(
            &packaged.join("mvm-hvf-supervisor"),
            &answering_helper(
                "mvm-hvf-supervisor",
                helper_contract::HOST_HELPER_CONTRACT_VERSION,
            ),
        );
        let marker = tmp.path().join("ran");
        let fixture = source_fixture(tmp.path(), &root, "release", &marker_cargo(&marker));
        let lookup = Lookup {
            override_path: None,
            dirs: vec![packaged.clone(), root.join("target/release")],
        };

        let got = resolve_verified_in(&hvf_spec(), &lookup, &fixture.env).unwrap();

        assert_eq!(got, packaged.join("mvm-hvf-supervisor"));
        assert!(!marker.exists());
    }

    #[test]
    fn a_binary_outside_its_checkout_target_never_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let marker = tmp.path().join("ran");
        let mut fixture = source_fixture(tmp.path(), &root, "release", &marker_cargo(&marker));
        fixture.env.binary_dir = Some(tmp.path().join("installed/bin"));

        assert!(SourceBuild::plan(&hvf_spec(), &checkout_lookup(&root), &fixture.env).is_none());
        assert!(resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env).is_err());
        assert!(!marker.exists());
    }

    #[test]
    fn mvmctl_itself_is_never_built_as_a_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let fixture = source_fixture(tmp.path(), &root, "release", "#!/bin/sh\nexit 1\n");
        let spec = AuxBin::new(CLI_BIN, "MVM_QEMU_BRIDGE_PATH", "mvmctl");

        assert!(SourceBuild::plan(&spec, &checkout_lookup(&root), &fixture.env).is_none());
    }

    #[test]
    fn a_source_build_that_produces_nothing_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let log = tmp.path().join("cargo.log");
        let fixture = source_fixture(tmp.path(), &root, "debug", &fresh_cargo(&log));

        let err = resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env)
            .unwrap_err()
            .to_string();

        assert!(err.contains("did not produce"), "{err}");
        assert!(
            err.contains("cargo build -p mvm-hostd --bin mvm-hvf-supervisor"),
            "{err}"
        );
        assert!(fixture.signed.0.borrow().is_empty());
    }

    #[test]
    fn a_failed_source_build_reports_cargo_output_and_signs_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = scratch_checkout(tmp.path());
        let fixture = source_fixture(
            tmp.path(),
            &root,
            "debug",
            "#!/bin/sh\necho 'error: could not compile mvm-hostd' >&2\nexit 101\n",
        );

        let err = resolve_verified_in(&hvf_spec(), &checkout_lookup(&root), &fixture.env)
            .unwrap_err()
            .to_string();

        assert!(err.contains("could not compile mvm-hostd"), "{err}");
        assert!(fixture.signed.0.borrow().is_empty());
    }

    #[test]
    fn a_source_build_writes_to_the_running_binarys_target_dir() {
        let root = Path::new("/repo/mvm");
        let plan = RebuildPlan::for_helper(
            &hvf_spec(),
            root,
            &root.join("target/release"),
            BuildProfile::Release,
        );
        assert_eq!(plan.target_dir, Some(root.join("target")));
        assert_eq!(
            plan.command_line(),
            "cargo build --release -p mvm-hostd --bin mvm-hvf-supervisor"
        );
    }
}
