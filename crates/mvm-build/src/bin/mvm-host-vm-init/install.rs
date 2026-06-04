//! Install-pipeline runner. Plan 73 Followup B.2, ADR-047.
//!
//! Given an [`InstallSpec`] (parsed from `/job/install_spec.json`)
//! and a job directory, run the per-language installer + the audit
//! sidecars, then write `/job/result.json` describing the outcome.
//!
//! ## Pipeline
//!
//! For each language:
//!
//! 1. **Installer.** `uv pip install --no-deps --requirement
//!    <lockfile> --target <content_dir>` (Python) or `pnpm install
//!    --frozen-lockfile --dir <content_dir>` (Node). stdout + stderr
//!    are tee'd to `<job_dir>/fetch.log` so every URL the installer
//!    dialed is captured for the ADR-047 audit gate.
//! 2. **SBOM.** `cyclonedx-py environment <content_dir>` (Python)
//!    or `pnpm sbom --dir <content_dir>` (Node). Output written to
//!    `<job_dir>/sbom.cdx.json`. **Optional gate**: if the tool
//!    isn't on PATH, write a CycloneDX-1.5 empty-stub and log a
//!    warning rather than fail the install. Hard-gating on missing
//!    SBOM tools is a follow-on slice (B.2.x) once the builder VM
//!    flake guarantees their presence.
//! 3. **CVE scan.** `pip-audit --requirement <lockfile> --format
//!    json` or `pnpm audit --json` against the populated content
//!    dir. Same fallback as SBOM: missing tool → stub + warn.
//! 4. **Result manifest.** `result.json` with the installer exit
//!    code, sidecar paths, and per-sidecar success flags.
//!
//! ## Cross-platform
//!
//! The runner is cross-platform on purpose so unit tests can
//! exercise the dispatch logic on macOS via shell stubs. Linux is
//! where it runs in production (inside the libkrun builder VM);
//! macOS is where contributors run `cargo test`. Both pin the same
//! `InstallSpec` → command-line mapping so a tool-shape drift
//! surfaces at test time, not at first boot inside the VM.
//!
//! The runner takes a `&dyn CommandRunner` so the same code path
//! drives a real `Command::spawn` in production and an injected
//! shell-stub in tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install_spec::{GateLevel, InstallSpec, Language};
use crate::proxy::{PROXY_URL, ProxyLifecycle};

/// Subdir under `<job_dir>` that holds the installed payload. Same
/// name as the canonical sealed-volume layout
/// (`mvm_sdk::compile::deps_audit::FILE_CONTENT_DIR`) so the host
/// can rename `<job_dir>` straight into a sealed volume without
/// shuffling files. Mirrors that constant explicitly rather than
/// re-exporting because `mvm-host-vm-init` doesn't depend on
/// `mvm-sdk` (kept tiny per Plan 72 §W3 size budget).
pub const CONTENT_SUBDIR: &str = "content";
pub const SBOM_FILENAME: &str = "sbom.cdx.json";
pub const FETCH_LOG_FILENAME: &str = "fetch.log";
pub const CVE_FILENAME: &str = "cve.json";
pub const RESULT_FILENAME: &str = "result.json";

/// CycloneDX-1.5 empty stub. Emitted when the SBOM tool is missing
/// from the builder VM PATH. ADR-047 §"Lifecycle gates" treats a
/// stub SBOM as a `dev`-gate-only artifact; `prod` gating on a stub
/// is wired in a follow-on slice (B.2.x).
const SBOM_EMPTY_STUB: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;

/// Minimal pip-audit / pnpm-audit empty stub. Same dev-vs-prod
/// gating note as the SBOM stub.
const CVE_EMPTY_STUB: &str = r#"{"results":[]}"#;

/// Result of the install pipeline. Serialized to `result.json`
/// inside the job dir; the host (`LibkrunBuilderVm::run_build`
/// Install arm) reads it after the VM powers off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub installer_exit_code: i32,
    pub sbom_emitted: bool,
    pub cve_emitted: bool,
    pub language: Language,
    pub gate: GateLevel,
    pub content_path: String,
    pub sbom_path: String,
    pub fetch_log_path: String,
    pub cve_path: String,
}

impl InstallReport {
    /// Hand-rolled JSON serializer — matches the style of
    /// `mvm-host-vm-init::linux::write_result`. Keeps `serde_json`
    /// out of the init binary's closure.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"installer_exit_code":{exit},"sbom_emitted":{sbom},"cve_emitted":{cve},"language":"{lang}","gate":"{gate}","content_path":"{content}","sbom_path":"{sbom_path}","fetch_log_path":"{fetch}","cve_path":"{cve_path}"}}"#,
            exit = self.installer_exit_code,
            sbom = self.sbom_emitted,
            cve = self.cve_emitted,
            lang = self.language.as_str(),
            gate = self.gate.as_str(),
            content = json_escape(&self.content_path),
            sbom_path = json_escape(&self.sbom_path),
            fetch = json_escape(&self.fetch_log_path),
            cve_path = json_escape(&self.cve_path),
        )
    }
}

/// Abstraction over the `Command::spawn`-and-tee dance so unit
/// tests can inject shell stubs. Production callers use
/// [`SystemCommandRunner`] which spawns real subprocesses.
pub trait CommandRunner {
    /// Run `program` with `args` (cwd: any working dir the runner
    /// picks). Tee stdout + stderr to `log_path` if `Some`; ignore
    /// them otherwise. Returns the child's exit code on clean exit,
    /// or a string error otherwise (program not on PATH, spawn
    /// failure, …).
    ///
    /// `extra_path` is prepended to the runner's `PATH` lookup —
    /// production drives it from `MVM_INSTALL_TOOLS_PATH`; tests
    /// hand it a tempdir full of shell stubs.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        log_path: Option<&Path>,
        extra_path: Option<&Path>,
    ) -> Result<i32, String> {
        self.run_with_env(program, args, log_path, extra_path, &[])
    }

    /// Like [`Self::run`] but accepts extra environment variables
    /// to set on the child. The installer wrap path
    /// ([`run_install`]) uses this to inject `HTTP_PROXY` +
    /// `HTTPS_PROXY` pointing at the in-VM `mvm-egress-proxy`
    /// (Plan 73 Followup B.2.x). Implementors that don't need
    /// env-var injection can rely on the default impl of
    /// [`Self::run`] and override only this method.
    fn run_with_env(
        &self,
        program: &str,
        args: &[&str],
        log_path: Option<&Path>,
        extra_path: Option<&Path>,
        env: &[(&str, &str)],
    ) -> Result<i32, String>;

    /// Whether `program` resolves on PATH (with `extra_path`
    /// prepended). Used by the SBOM + CVE optional-gate paths to
    /// fall back to a stub when the tool isn't installed.
    fn is_available(&self, program: &str, extra_path: Option<&Path>) -> bool;
}

/// Real `Command`-backed runner. Spawns each command with the
/// inherited environment plus `extra_path` prepended to `PATH`,
/// tees combined stdout/stderr to `log_path`, and returns the
/// child's exit code.
///
/// Tee semantics: we open `log_path` in append mode and pass it as
/// the child's stdout+stderr (via `Stdio::from`). That captures
/// every byte the installer wrote — including the URLs `uv` /
/// `pnpm` print to stderr during fetch — into one merged log the
/// host seals later.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_with_env(
        &self,
        program: &str,
        args: &[&str],
        log_path: Option<&Path>,
        extra_path: Option<&Path>,
        env: &[(&str, &str)],
    ) -> Result<i32, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        if let Some(extra) = extra_path {
            let path_env = std::env::var_os("PATH").unwrap_or_default();
            let mut prepended = std::ffi::OsString::from(extra);
            if !path_env.is_empty() {
                prepended.push(":");
                prepended.push(&path_env);
            }
            cmd.env("PATH", prepended);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }

        match log_path {
            Some(path) => {
                let f = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| format!("open {} for log: {e}", path.display()))?;
                let f_err = f
                    .try_clone()
                    .map_err(|e| format!("clone log handle for stderr: {e}"))?;
                cmd.stdout(Stdio::from(f));
                cmd.stderr(Stdio::from(f_err));
            }
            None => {
                cmd.stdout(Stdio::null());
                cmd.stderr(Stdio::null());
            }
        }

        let status = cmd
            .status()
            .map_err(|e| format!("spawn `{program}`: {e}"))?;
        Ok(status.code().unwrap_or(-1))
    }

    fn is_available(&self, program: &str, extra_path: Option<&Path>) -> bool {
        let path_env = std::env::var_os("PATH").unwrap_or_default();
        let mut paths: Vec<PathBuf> = Vec::new();
        if let Some(extra) = extra_path {
            paths.push(extra.to_path_buf());
        }
        for p in std::env::split_paths(&path_env) {
            paths.push(p);
        }
        for dir in paths {
            let candidate = dir.join(program);
            if candidate.is_file() {
                return true;
            }
        }
        false
    }
}

/// Errors from the install pipeline. The installer-exit-code path
/// is not an error — we always emit `result.json` so the host can
/// distinguish "installer ran and failed" from "init crashed
/// before it could run."
#[derive(Debug)]
pub enum InstallError {
    /// Directory create / file write / spec parse failed before
    /// any installer could run.
    Io(String),
    /// Installer binary (`uv` / `pnpm`) wasn't on PATH at all.
    /// Distinct from a non-zero exit (which lands in
    /// `installer_exit_code`); a missing installer is a builder-VM
    /// configuration bug, not a user's lockfile issue.
    InstallerMissing { program: String },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "install IO: {s}"),
            Self::InstallerMissing { program } => {
                write!(f, "installer `{program}` not on PATH inside the builder VM")
            }
        }
    }
}

impl std::error::Error for InstallError {}

/// Bundle of parameters [`run_install`] needs. Grouped into a
/// struct so the signature stays under the workspace's
/// `clippy::too_many_arguments = "deny"` lint (CLAUDE.md: "never
/// suppress this lint"). All fields are mandatory except
/// `extra_path` (which is `None` in production and a tempdir-
/// of-stubs in tests).
pub struct InstallContext<'a> {
    pub spec: &'a InstallSpec,
    pub job_dir: &'a Path,
    pub out_dir: &'a Path,
    pub runner: &'a dyn CommandRunner,
    pub extra_path: Option<&'a Path>,
    /// Egress-proxy lifecycle. Started before the installer
    /// spawns, stopped after. Plan 73 Followup B.2.x. Production
    /// uses [`crate::proxy::ChildProxyLifecycle`]; tests use
    /// [`crate::proxy::NoopProxyLifecycle`] or a fake.
    pub proxy: &'a mut dyn ProxyLifecycle,
}

/// Public entry point. Run the install pipeline for the spec in
/// `ctx`, writing the four sealed-volume artifacts (`content/`,
/// SBOM, fetch log, CVE) into `ctx.out_dir` and the install
/// report into `ctx.job_dir/result.json`. The runner spawns each
/// subprocess; `extra_path` flows into the runner so tests can
/// stub binaries.
///
/// Splitting `out_dir` from `job_dir` keeps the host's mount
/// layout honest: the host bind-mounts the (writable) sealed-
/// volume directory at `/out` and the per-job scratch at `/job`.
/// Co-locating the sidecars in `/out` lets the host rename the
/// whole directory into the deps cache in one syscall, without
/// shuffling files across mount points.
///
/// ## Egress allowlist (Plan 73 Followup B.2.x)
///
/// Before invoking the installer we start `ctx.proxy` (an HTTP
/// CONNECT proxy that refuses anything outside ADR-047's four
/// hostnames) and set `HTTP_PROXY` + `HTTPS_PROXY` on the
/// installer's env to `http://127.0.0.1:8443`. After the
/// installer exits — whether successfully or not — we tear the
/// proxy down. SBOM + CVE sidecars run *without* the proxy env:
/// they operate against on-disk content the installer already
/// fetched, so they don't need network.
pub fn run_install(ctx: InstallContext<'_>) -> Result<InstallReport, InstallError> {
    let InstallContext {
        spec,
        job_dir,
        out_dir,
        runner,
        extra_path,
        proxy,
    } = ctx;
    fs::create_dir_all(out_dir)
        .map_err(|e| InstallError::Io(format!("create {}: {e}", out_dir.display())))?;
    let content_dir = out_dir.join(CONTENT_SUBDIR);
    fs::create_dir_all(&content_dir)
        .map_err(|e| InstallError::Io(format!("create {}: {e}", content_dir.display())))?;
    let fetch_log = out_dir.join(FETCH_LOG_FILENAME);
    let sbom = out_dir.join(SBOM_FILENAME);
    let cve = out_dir.join(CVE_FILENAME);
    fs::create_dir_all(job_dir)
        .map_err(|e| InstallError::Io(format!("create {}: {e}", job_dir.display())))?;

    // Truncate fetch.log so a retry doesn't append onto a stale
    // half-written log. The installer step appends; if we skipped
    // this we'd accumulate logs across re-runs of the same job dir.
    fs::write(&fetch_log, b"")
        .map_err(|e| InstallError::Io(format!("truncate {}: {e}", fetch_log.display())))?;

    let lockfile_in_vm = format!("{}/{}", spec.source_mount, spec.lockfile_relative_path);
    let installer = installer_for(spec.language);
    if !runner.is_available(installer.program, extra_path) {
        return Err(InstallError::InstallerMissing {
            program: installer.program.to_string(),
        });
    }

    // Bring the egress proxy up before the installer. The
    // installer dials `http://127.0.0.1:8443` for every fetch;
    // it must be listening before `uv` / `pnpm` makes the first
    // request. A proxy startup failure is a hard error — without
    // the allowlist the install would bypass ADR-047's gate.
    proxy
        .start()
        .map_err(|e| InstallError::Io(format!("egress proxy start: {e}")))?;

    // Inject HTTP_PROXY + HTTPS_PROXY on the installer's env. Both
    // are set so `uv` (HTTPS_PROXY-aware) and `npm`-style tools
    // that occasionally consult HTTP_PROXY both route through us.
    // The lowercase forms (`https_proxy` / `http_proxy`) are also
    // honored by some installers — we set them for safety even
    // though uv/pnpm don't strictly need them.
    let env = [
        ("HTTPS_PROXY", PROXY_URL),
        ("HTTP_PROXY", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("http_proxy", PROXY_URL),
    ];

    let installer_args = installer.args(&lockfile_in_vm, &content_dir);
    let installer_args_refs: Vec<&str> = installer_args.iter().map(|s| s.as_str()).collect();
    let installer_result = runner.run_with_env(
        installer.program,
        &installer_args_refs,
        Some(&fetch_log),
        extra_path,
        &env,
    );

    // Tear the proxy down before propagating errors / running the
    // sidecars. SBOM + CVE don't go through the proxy (no network),
    // so leaving it up would only delay shutdown.
    proxy.stop();

    let installer_exit_code = installer_result.map_err(InstallError::Io)?;

    // Best-effort SBOM + CVE; the optional-gate fallback emits a
    // CycloneDX-1.5 empty stub if the tool isn't available. The
    // host's audit-gate slice (B.3) decides whether a stub is
    // acceptable for `--prod`; today both gate levels accept it
    // with a warning.
    let sbom_emitted = run_sbom(spec.language, &content_dir, &sbom, runner, extra_path);
    let cve_emitted = run_cve(spec.language, &lockfile_in_vm, &cve, runner, extra_path);

    Ok(InstallReport {
        installer_exit_code,
        sbom_emitted,
        cve_emitted,
        language: spec.language,
        gate: spec.gate,
        content_path: content_dir.to_string_lossy().into_owned(),
        sbom_path: sbom.to_string_lossy().into_owned(),
        fetch_log_path: fetch_log.to_string_lossy().into_owned(),
        cve_path: cve.to_string_lossy().into_owned(),
    })
}

/// Per-language installer dispatch table. Returned as a value
/// rather than a const so the args list can interpolate the
/// caller's `lockfile_in_vm` / `content_dir` strings without
/// allocations leaking through the surface.
struct Installer {
    program: &'static str,
}

fn installer_for(language: Language) -> Installer {
    match language {
        // `uv pip install --no-deps --requirements <lock> --target
        // <dir>` is the documented "install a lockfile into a
        // target directory without writing the source tree"
        // invocation (uv docs §"Installing into a target
        // directory"). `--no-deps` skips transitive resolution
        // because the lockfile is already fully resolved.
        Language::Python => Installer { program: "uv" },
        // `pnpm install --frozen-lockfile --dir <dir>` installs the
        // lockfile-pinned tree into `<dir>/node_modules` without
        // mutating the lockfile or fetching anything not in it.
        // `--prefix` is the older flag; `--dir` is the documented
        // current one.
        Language::Node => Installer { program: "pnpm" },
    }
}

impl Installer {
    fn args(&self, lockfile_in_vm: &str, content_dir: &Path) -> Vec<String> {
        match self.program {
            "uv" => vec![
                "pip".to_string(),
                "install".to_string(),
                "--no-deps".to_string(),
                "--requirements".to_string(),
                lockfile_in_vm.to_string(),
                "--target".to_string(),
                content_dir.to_string_lossy().into_owned(),
            ],
            "pnpm" => vec![
                "install".to_string(),
                "--frozen-lockfile".to_string(),
                "--dir".to_string(),
                content_dir.to_string_lossy().into_owned(),
            ],
            _ => Vec::new(),
        }
    }
}

/// Run the SBOM emitter, returning `true` if the tool ran cleanly,
/// `false` if we fell back to the stub. Side effect: writes the
/// SBOM (real or stub) to `sbom_path`.
fn run_sbom(
    language: Language,
    content_dir: &Path,
    sbom_path: &Path,
    runner: &dyn CommandRunner,
    extra_path: Option<&Path>,
) -> bool {
    let (program, args): (&str, Vec<String>) = match language {
        Language::Python => (
            "cyclonedx-py",
            vec![
                "environment".to_string(),
                content_dir.to_string_lossy().into_owned(),
                "--output-file".to_string(),
                sbom_path.to_string_lossy().into_owned(),
            ],
        ),
        Language::Node => (
            "pnpm",
            vec![
                "sbom".to_string(),
                "--dir".to_string(),
                content_dir.to_string_lossy().into_owned(),
                "--output".to_string(),
                sbom_path.to_string_lossy().into_owned(),
            ],
        ),
    };
    if !runner.is_available(program, extra_path) {
        eprintln!(
            "mvm-host-vm-init: SBOM tool `{program}` not on PATH — writing CycloneDX empty stub. \
             B.2.x will hard-gate this once the builder VM flake guarantees the tool."
        );
        let _ = fs::write(sbom_path, SBOM_EMPTY_STUB);
        return false;
    }
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match runner.run(program, &args_refs, None, extra_path) {
        Ok(0) => true,
        Ok(code) => {
            eprintln!(
                "mvm-host-vm-init: SBOM tool `{program}` exited {code} — writing CycloneDX stub"
            );
            let _ = fs::write(sbom_path, SBOM_EMPTY_STUB);
            false
        }
        Err(e) => {
            eprintln!("mvm-host-vm-init: SBOM tool spawn failed: {e}");
            let _ = fs::write(sbom_path, SBOM_EMPTY_STUB);
            false
        }
    }
}

/// Same pattern as [`run_sbom`] for the CVE-scan side.
fn run_cve(
    language: Language,
    lockfile_in_vm: &str,
    cve_path: &Path,
    runner: &dyn CommandRunner,
    extra_path: Option<&Path>,
) -> bool {
    let (program, args): (&str, Vec<String>) = match language {
        Language::Python => (
            "pip-audit",
            vec![
                "--requirement".to_string(),
                lockfile_in_vm.to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                cve_path.to_string_lossy().into_owned(),
            ],
        ),
        Language::Node => (
            "pnpm",
            vec![
                "audit".to_string(),
                "--json".to_string(),
                "--output".to_string(),
                cve_path.to_string_lossy().into_owned(),
            ],
        ),
    };
    if !runner.is_available(program, extra_path) {
        eprintln!(
            "mvm-host-vm-init: CVE tool `{program}` not on PATH — writing empty-results stub. \
             B.2.x will hard-gate this once the builder VM flake guarantees the tool."
        );
        let _ = fs::write(cve_path, CVE_EMPTY_STUB);
        return false;
    }
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match runner.run(program, &args_refs, None, extra_path) {
        // `pip-audit` and `pnpm audit` both exit nonzero when they
        // *find* vulnerabilities — that's the whole point of the
        // scan. The output file still represents a successful
        // emission. Treat any "ran without crashing" as a success
        // (the host audit gate inspects the JSON shape, not the
        // exit code). Anything truly broken (spawn failure, signal
        // termination) propagates as a stub fallback.
        Ok(_code) => cve_path.is_file(),
        Err(e) => {
            eprintln!("mvm-host-vm-init: CVE tool spawn failed: {e}");
            let _ = fs::write(cve_path, CVE_EMPTY_STUB);
            false
        }
    }
}

/// Same minimal JSON escaper as `linux::json_escape` (kept local so
/// `install` doesn't pull from a Linux-only module). Handles the
/// RFC 8259 §7 must-escape set; UTF-8 passes through.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Mutex;

    fn ok_spec() -> InstallSpec {
        InstallSpec {
            language: Language::Python,
            lockfile_relative_path: "uv.lock".to_string(),
            source_mount: "/work".to_string(),
            gate: GateLevel::Dev,
        }
    }

    #[test]
    fn report_to_json_round_trips_through_serde_json() {
        // We hand-roll the writer, but the contract is "valid JSON
        // a serde_json reader can parse." Use serde_json::Value
        // (test-only, via the workspace dev-deps) to assert that.
        let report = InstallReport {
            installer_exit_code: 0,
            sbom_emitted: true,
            cve_emitted: false,
            language: Language::Python,
            gate: GateLevel::Prod,
            content_path: "/job/content".to_string(),
            sbom_path: "/job/sbom.cdx.json".to_string(),
            fetch_log_path: "/job/fetch.log".to_string(),
            cve_path: "/job/cve.json".to_string(),
        };
        let body = report.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["installer_exit_code"], 0);
        assert_eq!(parsed["sbom_emitted"], true);
        assert_eq!(parsed["cve_emitted"], false);
        assert_eq!(parsed["language"], "python");
        assert_eq!(parsed["gate"], "prod");
        assert_eq!(parsed["content_path"], "/job/content");
    }

    #[test]
    fn report_json_escapes_quotes_in_paths() {
        let report = InstallReport {
            installer_exit_code: 0,
            sbom_emitted: true,
            cve_emitted: true,
            language: Language::Node,
            gate: GateLevel::Dev,
            content_path: r#"/job/content "weird""#.to_string(),
            sbom_path: "/job/sbom.cdx.json".to_string(),
            fetch_log_path: "/job/fetch.log".to_string(),
            cve_path: "/job/cve.json".to_string(),
        };
        let body = report.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["content_path"], r#"/job/content "weird""#);
    }

    /// Record of every command the stub runner saw. Per-call entry
    /// has the program name, arg list, whether log_path was set,
    /// and the env vars injected. Tests assert the right sequence
    /// of invocations and that the proxy env reached the installer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Invocation {
        program: String,
        args: Vec<String>,
        logged: bool,
        env: Vec<(String, String)>,
    }

    struct StubRunner {
        // Set of program names the runner pretends are installed.
        available: Vec<String>,
        // Exit code each program returns when invoked. Defaults to
        // 0 for any not in the table.
        exits: Vec<(String, i32)>,
        // Captured invocations. RefCell so the test stays
        // `&dyn CommandRunner`; Mutex would be overkill (one-
        // threaded test runner).
        calls: Mutex<RefCell<Vec<Invocation>>>,
    }

    impl StubRunner {
        fn new(available: &[&str]) -> Self {
            Self {
                available: available.iter().map(|s| s.to_string()).collect(),
                exits: Vec::new(),
                calls: Mutex::new(RefCell::new(Vec::new())),
            }
        }

        fn with_exit(mut self, program: &str, code: i32) -> Self {
            self.exits.push((program.to_string(), code));
            self
        }

        fn calls(&self) -> Vec<Invocation> {
            self.calls.lock().unwrap().borrow().clone()
        }

        fn exit_for(&self, program: &str) -> i32 {
            self.exits
                .iter()
                .find(|(p, _)| p == program)
                .map(|(_, c)| *c)
                .unwrap_or(0)
        }
    }

    impl CommandRunner for StubRunner {
        fn run_with_env(
            &self,
            program: &str,
            args: &[&str],
            log_path: Option<&Path>,
            _extra_path: Option<&Path>,
            env: &[(&str, &str)],
        ) -> Result<i32, String> {
            self.calls.lock().unwrap().borrow_mut().push(Invocation {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                logged: log_path.is_some(),
                env: env
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            });
            // Make the side-effect of writing real output for SBOM
            // / CVE tools explicit — without it the test for
            // `--output <path>` flags wouldn't see a file land.
            // We sniff for `--output` / `--output-file` and write
            // a placeholder so downstream checks see a real file.
            for (i, a) in args.iter().enumerate() {
                if (*a == "--output" || *a == "--output-file")
                    && let Some(path) = args.get(i + 1)
                {
                    let _ = fs::write(path, br#"{"stub":true}"#);
                }
            }
            // Tee log behavior: write a marker into log_path so
            // tests can assert tee'd capture happened.
            if let Some(path) = log_path {
                let _ = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| {
                        use std::io::Write;
                        writeln!(f, "STUB: {program}")
                    });
            }
            Ok(self.exit_for(program))
        }

        fn is_available(&self, program: &str, _extra_path: Option<&Path>) -> bool {
            self.available.iter().any(|p| p == program)
        }
    }

    /// Test-only proxy lifecycle that records start / stop calls
    /// so tests can assert the install pipeline starts the proxy
    /// before the installer + stops it after. Used in addition to
    /// `crate::proxy::NoopProxyLifecycle` because the noop version
    /// doesn't capture call order — and the order is the whole
    /// point of the integration test.
    #[derive(Debug)]
    struct FakeProxy {
        events: Mutex<RefCell<Vec<&'static str>>>,
        start_result: Result<(), String>,
    }

    impl FakeProxy {
        fn ok() -> Self {
            Self {
                events: Mutex::new(RefCell::new(Vec::new())),
                start_result: Ok(()),
            }
        }

        fn failing(reason: &str) -> Self {
            Self {
                events: Mutex::new(RefCell::new(Vec::new())),
                start_result: Err(reason.to_string()),
            }
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().borrow().clone()
        }
    }

    impl ProxyLifecycle for FakeProxy {
        fn start(&mut self) -> Result<(), String> {
            self.events.lock().unwrap().borrow_mut().push("start");
            self.start_result.clone()
        }

        fn stop(&mut self) {
            self.events.lock().unwrap().borrow_mut().push("stop");
        }

        fn is_running(&self) -> bool {
            // Crude: we're "running" iff start was the last event.
            self.events
                .lock()
                .unwrap()
                .borrow()
                .last()
                .copied()
                .unwrap_or("")
                == "start"
        }
    }

    /// Convenience: run_install against the stub runner + a fake
    /// proxy, returning both the install report and the proxy's
    /// observed start/stop events. Keeps test arms readable.
    fn run_install_with_fakes(
        spec: &InstallSpec,
        job_dir: &Path,
        out_dir: &Path,
        runner: &dyn CommandRunner,
    ) -> (Result<InstallReport, InstallError>, Vec<&'static str>) {
        let mut proxy = FakeProxy::ok();
        let ctx = InstallContext {
            spec,
            job_dir,
            out_dir,
            runner,
            extra_path: None,
            proxy: &mut proxy,
        };
        let report = run_install(ctx);
        let events = proxy.events();
        (report, events)
    }

    #[test]
    fn python_happy_path_runs_uv_then_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py", "pip-audit"]);
        let (report, events) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert_eq!(report.installer_exit_code, 0);
        assert!(report.sbom_emitted);
        assert!(report.cve_emitted);
        assert!(report.content_path.ends_with("/content"));

        // Proxy lifecycle: start before the installer, stop after.
        assert_eq!(events, vec!["start", "stop"]);

        let calls = runner.calls();
        // First call: uv pip install --no-deps --requirements
        // /work/uv.lock --target <content_dir>.
        assert_eq!(calls[0].program, "uv");
        assert_eq!(calls[0].args[0], "pip");
        assert_eq!(calls[0].args[1], "install");
        assert!(calls[0].args.contains(&"--no-deps".to_string()));
        assert!(calls[0].args.contains(&"/work/uv.lock".to_string()));
        assert!(calls[0].logged, "installer must tee to fetch.log");
        // Plan 73 Followup B.2.x: HTTPS_PROXY + HTTP_PROXY env on
        // the installer's invocation.
        let env_keys: Vec<&str> = calls[0].env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(env_keys.contains(&"HTTPS_PROXY"), "env: {:?}", calls[0].env);
        assert!(env_keys.contains(&"HTTP_PROXY"), "env: {:?}", calls[0].env);
        let https = calls[0]
            .env
            .iter()
            .find(|(k, _)| k == "HTTPS_PROXY")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(https, "http://127.0.0.1:8443");

        // Subsequent: cyclonedx-py + pip-audit. Sidecars run
        // *without* the proxy env (no network — they read on-disk
        // content the installer fetched).
        let sbom_call = calls
            .iter()
            .find(|c| c.program == "cyclonedx-py")
            .expect("cyclonedx-py invoked");
        assert!(
            sbom_call.env.is_empty(),
            "sidecars must not inherit proxy env: {:?}",
            sbom_call.env
        );
        assert!(calls.iter().any(|c| c.program == "pip-audit"));

        // Artifacts on disk.
        assert!(tmp.path().join(CONTENT_SUBDIR).is_dir());
        assert!(tmp.path().join(FETCH_LOG_FILENAME).is_file());
        assert!(tmp.path().join(SBOM_FILENAME).is_file());
        assert!(tmp.path().join(CVE_FILENAME).is_file());
    }

    #[test]
    fn node_happy_path_runs_pnpm() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = InstallSpec {
            language: Language::Node,
            lockfile_relative_path: "pnpm-lock.yaml".to_string(),
            source_mount: "/work".to_string(),
            gate: GateLevel::Prod,
        };
        let runner = StubRunner::new(&["pnpm"]);
        let (report, events) =
            run_install_with_fakes(&spec, &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert_eq!(report.language, Language::Node);
        assert_eq!(report.gate, GateLevel::Prod);
        assert_eq!(events, vec!["start", "stop"]);
        let calls = runner.calls();
        assert_eq!(calls[0].program, "pnpm");
        assert_eq!(calls[0].args[0], "install");
        assert!(calls[0].args.contains(&"--frozen-lockfile".to_string()));
        // Node installer also gets proxy env.
        assert!(calls[0].env.iter().any(|(k, _)| k == "HTTPS_PROXY"));
    }

    #[test]
    fn missing_installer_returns_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        // "uv" absent → InstallerMissing.
        let runner = StubRunner::new(&["cyclonedx-py", "pip-audit"]);
        let (result, events) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let err = result.unwrap_err();
        match err {
            InstallError::InstallerMissing { program } => assert_eq!(program, "uv"),
            other => panic!("wrong variant: {other:?}"),
        }
        // Proxy is *not* started when the installer is missing —
        // we bail before reaching the proxy.start() call.
        assert!(events.is_empty(), "proxy must not run if installer absent");
    }

    #[test]
    fn nonzero_installer_exit_lands_in_report() {
        // Installer ran but failed — the report carries the exit
        // code; the host treats nonzero as a hard failure. Critical
        // distinction from the missing-installer case.
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py", "pip-audit"]).with_exit("uv", 1);
        let (report, events) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert_eq!(report.installer_exit_code, 1);
        // Sidecars still run — the SBOM / CVE captures empty
        // state for the partial install, which is informative.
        assert!(report.sbom_emitted);
        // Proxy still goes through its lifecycle even on installer
        // failure (we tear it down before propagating the error so
        // we don't leak a listening port).
        assert_eq!(events, vec!["start", "stop"]);
    }

    #[test]
    fn missing_sbom_tool_emits_stub_and_logs_warning() {
        let tmp = tempfile::tempdir().unwrap();
        // No `cyclonedx-py`.
        let runner = StubRunner::new(&["uv", "pip-audit"]);
        let (report, _events) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert!(
            !report.sbom_emitted,
            "stub fallback marks sbom_emitted=false"
        );
        let body = fs::read_to_string(tmp.path().join(SBOM_FILENAME)).unwrap();
        // Stub matches the CycloneDX-1.5 empty shape.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert!(parsed["components"].as_array().unwrap().is_empty());
    }

    #[test]
    fn missing_cve_tool_emits_stub() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py"]);
        let (report, _events) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert!(!report.cve_emitted);
        let body = fs::read_to_string(tmp.path().join(CVE_FILENAME)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn pnpm_node_spec_dispatches_pnpm_sbom_and_audit() {
        let tmp = tempfile::tempdir().unwrap();
        let spec = InstallSpec {
            language: Language::Node,
            lockfile_relative_path: "pnpm-lock.yaml".to_string(),
            source_mount: "/work".to_string(),
            gate: GateLevel::Dev,
        };
        let runner = StubRunner::new(&["pnpm"]);
        let (report, _events) =
            run_install_with_fakes(&spec, &tmp.path().join("job"), tmp.path(), &runner);
        let report = report.unwrap();
        assert!(report.sbom_emitted);
        assert!(report.cve_emitted);
        let calls = runner.calls();
        // Both the SBOM and the audit invocation hit pnpm — three
        // pnpm calls total (install, sbom, audit).
        let pnpm_invocations: Vec<&Invocation> =
            calls.iter().filter(|c| c.program == "pnpm").collect();
        assert_eq!(pnpm_invocations.len(), 3, "calls: {calls:?}");
        let subs: Vec<&str> = pnpm_invocations
            .iter()
            .map(|c| c.args[0].as_str())
            .collect();
        assert!(subs.contains(&"install"));
        assert!(subs.contains(&"sbom"));
        assert!(subs.contains(&"audit"));
    }

    #[test]
    fn fetch_log_is_truncated_per_run() {
        // Two runs against the same job dir must not concatenate
        // their fetch logs. The runner truncates the log before
        // dispatch so a retry produces a fresh transcript.
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py", "pip-audit"]);
        let (_, _) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let first = fs::read_to_string(tmp.path().join(FETCH_LOG_FILENAME)).unwrap();
        let (_, _) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let second = fs::read_to_string(tmp.path().join(FETCH_LOG_FILENAME)).unwrap();
        // Truncation means we don't see the first run's content
        // duplicated in the second.
        let first_marker = "STUB: uv";
        assert_eq!(
            second.matches(first_marker).count(),
            first.matches(first_marker).count(),
            "log was not truncated between runs"
        );
    }

    /// Plan 73 Followup B.2.x: if the egress proxy can't be
    /// started, the install fails *before* the installer runs.
    /// Bypassing the proxy would violate ADR-047's allowlist
    /// invariant — fail-closed is mandatory.
    #[test]
    fn proxy_start_failure_aborts_before_installer() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py", "pip-audit"]);
        let mut proxy = FakeProxy::failing("bind 127.0.0.1:8443: address in use");
        let ctx = InstallContext {
            spec: &ok_spec(),
            job_dir: &tmp.path().join("job"),
            out_dir: tmp.path(),
            runner: &runner,
            extra_path: None,
            proxy: &mut proxy,
        };
        let err = run_install(ctx).unwrap_err();
        match err {
            InstallError::Io(msg) => {
                assert!(msg.contains("egress proxy"), "msg: {msg}");
                assert!(msg.contains("address in use"), "msg: {msg}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // The installer never spawned — no uv invocation recorded.
        let calls = runner.calls();
        assert!(
            !calls.iter().any(|c| c.program == "uv"),
            "uv ran even though proxy failed: {calls:?}"
        );
    }

    /// Plan 73 Followup B.2.x: the proxy env vars match the
    /// `crate::proxy::PROXY_URL` constant. If someone changes
    /// the URL on one side and forgets the other, this test
    /// flags the drift.
    #[test]
    fn installer_env_uses_constant_proxy_url() {
        use crate::proxy::PROXY_URL;
        let tmp = tempfile::tempdir().unwrap();
        let runner = StubRunner::new(&["uv", "cyclonedx-py", "pip-audit"]);
        let (_, _) =
            run_install_with_fakes(&ok_spec(), &tmp.path().join("job"), tmp.path(), &runner);
        let calls = runner.calls();
        let uv_call = calls.iter().find(|c| c.program == "uv").unwrap();
        for key in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"] {
            let v = uv_call
                .env
                .iter()
                .find(|(k, _)| k == key)
                .unwrap_or_else(|| panic!("missing env var {key} in {:?}", uv_call.env));
            assert_eq!(v.1, PROXY_URL, "env {key} drift");
        }
    }

    #[test]
    fn json_escape_handles_quotes_backslashes_controls() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("\x01"), "\\u0001");
    }
}
