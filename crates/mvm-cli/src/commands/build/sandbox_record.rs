//! Shared helpers for the SDK record-mode auto-exec path.
//!
//! Both `mvmctl compile <Sandbox-script>` (Phase 7e/7f) and
//! `mvmctl run --mode plan <Sandbox-script>` (Followup H plan half)
//! need to: spawn the user's script under
//! `MVM_SDK_MODE=record + MVM_SDK_OUT_PATH=<tmp>`, then lower the
//! atexit-hook-emitted recording into a `Workload`. Pulling the
//! mechanics out lets the two verbs share a single implementation
//! (and a single test seam) instead of duplicating the spawn-and-
//! lower dance.
//!
//! **Security**: running the user's script on the host is a
//! deliberate departure from the decorator path's "never executes
//! user code on the host" rule. Documented in the SDK guide; the
//! literal-only AST gate (Decision I) inside the language SDKs is
//! the host-side defence. Callers should keep this routine
//! opt-in — `mvmctl compile`'s decorator path stays the default.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use mvm_sdk::ir::Workload;
use mvm_sdk::runtime::{
    Divergence, RuntimeRecording, compile_recording_with_findings, recording_sha256_hex,
    verify_recording_digest,
};

/// Hard cap on recording bytes read from disk — guards the JSON parser
/// against a multi-GiB file before serde ever runs. Far above any
/// legitimate recording (ops are capped downstream).
const MAX_RECORDING_BYTES: u64 = 64 * 1024 * 1024;

/// A recording loaded from disk: the lowered workload, the divergence
/// findings the admission path gates on, and the content digest captured
/// at read time.
pub(in crate::commands) struct LoadedRecording {
    pub workload: Workload,
    pub findings: Vec<Divergence>,
    pub digest_hex: String,
}

/// Languages the auto-exec path supports.
#[derive(Debug, Clone, Copy)]
pub(in crate::commands) enum ScriptLanguage {
    /// Python via `python3` (or `python`).
    Python,
    /// Plain JavaScript via `node`.
    Node,
    /// TypeScript via `tsx`, `bun`, or `deno`. The `node` binary
    /// alone can't run `.ts` files in mvm's supported Node range,
    /// so the CLI insists on a TS-aware runner.
    TypeScript,
}

/// Infer a [`ScriptLanguage`] from a script path's extension.
///
/// Returns `None` for unsupported / unknown extensions; callers
/// surface their own diagnostic ("could not infer kind from …").
pub(in crate::commands) fn script_language_from_path(path: &Path) -> Option<ScriptLanguage> {
    match path.extension().and_then(|e| e.to_str())? {
        "py" => Some(ScriptLanguage::Python),
        "ts" | "tsx" | "mts" | "cts" => Some(ScriptLanguage::TypeScript),
        "js" | "mjs" | "cjs" => Some(ScriptLanguage::Node),
        _ => None,
    }
}

/// Run `<interpreter> <script>` on the host with
/// `MVM_SDK_MODE=record` and `MVM_SDK_OUT_PATH=<tempfile>`, then
/// load the recording the SDK's atexit hook wrote and lower it
/// to a [`LoadedRecording`].
///
/// The digest is captured the moment the tempfile is read — right
/// after the subprocess exits — making it the trusted baseline for
/// downstream audit and verification.
///
/// **Security**: this *runs the user's script on the host*. Per
/// S2 in the SDK plan, this is a deliberate departure from the
/// decorator path's "never executes user code on the host" rule;
/// callers gate behind an explicit opt-in.
pub(in crate::commands) fn auto_exec_record_script(
    script: &Path,
    lang: ScriptLanguage,
) -> Result<LoadedRecording> {
    let interpreter = resolve_interpreter(lang)?;
    let tmp = tempfile::Builder::new()
        .prefix("mvm-recording-")
        .suffix(".json")
        .tempfile()
        .context("creating tempfile for runtime recording capture")?;
    let out_path = tmp.path().to_path_buf();

    eprintln!(
        "running {} on the host with MVM_SDK_MODE=record (Phase 7e/7f auto-exec)",
        script.display()
    );

    let mut cmd = Command::new(&interpreter);
    // Deno's default sandbox refuses fs writes; the SDK's atexit
    // hook needs to write the recording, so opt out explicitly.
    let basename = interpreter
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if basename.starts_with("deno") {
        cmd.arg("run").arg("--allow-all");
    }
    let status = cmd
        .arg(script)
        .env("MVM_SDK_MODE", "record")
        .env("MVM_SDK_OUT_PATH", &out_path)
        .status()
        .with_context(|| {
            format!(
                "spawning {} to run record-mode script {}",
                interpreter.display(),
                script.display()
            )
        })?;
    if !status.success() {
        bail!(
            "record-mode script {} exited with {:?} (no Workload emitted). \
             Re-run it under {} with MVM_SDK_MODE=record to see the error.",
            script.display(),
            status.code(),
            interpreter.display()
        );
    }
    if !out_path.exists() {
        bail!(
            "record-mode script {} did not emit a recording. Confirm the \
             script imports `mvm` and calls `Sandbox.create(...)`; the SDK's \
             atexit hook writes the recording to MVM_SDK_OUT_PATH on process \
             exit, which only fires when a Sandbox was constructed.",
            script.display()
        );
    }
    load_recording(&out_path, None)
}

/// Load a recording JSON from disk, verify its size and optionally its
/// digest, lower it through the SDK, and return the workload together
/// with divergence findings and the captured digest.
///
/// Reused by `mvmctl compile --from-recording` and the auto-exec path
/// above. The `expected_sha256` argument is `None` in the auto-exec
/// path (freshly captured) and `Some` when the caller supplies
/// `--recording-sha256`.
pub(in crate::commands) fn load_recording(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<LoadedRecording> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    if meta.len() > MAX_RECORDING_BYTES {
        bail!(
            "recording file {} is {} bytes, exceeding the {} byte cap — \
             a legitimate recording never approaches this size; a runaway \
             loop or adversarial file does.",
            path.display(),
            meta.len(),
            MAX_RECORDING_BYTES
        );
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading runtime recording from {}", path.display()))?;
    let digest_hex = recording_sha256_hex(&bytes);
    if let Some(expected) = expected_sha256 {
        verify_recording_digest(&bytes, expected)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .with_context(|| format!("digest verification failed for {}", path.display()))?;
    }
    let recording: RuntimeRecording = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing runtime recording JSON from {}", path.display()))?;
    let (workload, findings) = compile_recording_with_findings(&recording)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("lowering runtime recording from {}", path.display()))?;
    Ok(LoadedRecording {
        workload,
        findings,
        digest_hex,
    })
}

/// Resolve which interpreter to spawn for a given language. Each
/// language has a discrete env-var override (`MVM_PYTHON`, `MVM_NODE`,
/// `MVM_TSX`) so users with non-standard layouts can pin a binary
/// explicitly. The fallback search order is best-effort but explicit
/// in the error message when nothing is found.
pub(in crate::commands) fn resolve_interpreter(lang: ScriptLanguage) -> Result<PathBuf> {
    match lang {
        ScriptLanguage::Python => {
            if let Some(p) = env_override("MVM_PYTHON") {
                return Ok(p);
            }
            for candidate in ["python3", "python"] {
                if let Ok(found) = which::which(candidate) {
                    return Ok(found);
                }
            }
            bail!(
                "no Python interpreter found on PATH (tried `python3`, `python`). \
                 Install Python 3.10+ or set `MVM_PYTHON=<path>` and re-run."
            )
        }
        ScriptLanguage::Node => {
            if let Some(p) = env_override("MVM_NODE") {
                return Ok(p);
            }
            if let Ok(found) = which::which("node") {
                return Ok(found);
            }
            bail!(
                "no Node.js interpreter found on PATH (tried `node`). \
                 Install Node 20+ or set `MVM_NODE=<path>` and re-run."
            )
        }
        ScriptLanguage::TypeScript => {
            if let Some(p) = env_override("MVM_TSX") {
                return Ok(p);
            }
            // Project-local `./node_modules/.bin/<runner>` wins over a
            // PATH-installed runner: this lets a `package.json` /
            // lockfile pin the exact version without forcing the user
            // to install one globally. Resolution is cwd-relative
            // because the verb is run from a project root.
            // See `crate::ts_runner` for the full resolution order.
            if let Some(p) = crate::ts_runner::resolve() {
                return Ok(p);
            }
            bail!("{}", crate::ts_runner::install_hint())
        }
    }
}

fn env_override(name: &str) -> Option<PathBuf> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate `MVM_TSX` (process-wide).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Restore-on-drop guard for `MVM_TSX`. Used to exercise the
    /// env-override short-circuit in `resolve_interpreter` without
    /// leaking state into sibling tests.
    struct TsxGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
    }

    impl TsxGuard {
        fn set(value: Option<&str>) -> Self {
            let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var("MVM_TSX").ok();
            unsafe {
                match value {
                    Some(v) => std::env::set_var("MVM_TSX", v),
                    None => std::env::remove_var("MVM_TSX"),
                }
            }
            TsxGuard { _guard: g, prev }
        }
    }

    impl Drop for TsxGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MVM_TSX", v),
                    None => std::env::remove_var("MVM_TSX"),
                }
            }
        }
    }

    #[test]
    fn resolve_interpreter_typescript_honours_mvm_tsx_override() {
        let _g = TsxGuard::set(Some("/usr/local/bin/tsx-pinned"));
        let resolved =
            resolve_interpreter(ScriptLanguage::TypeScript).expect("MVM_TSX must short-circuit");
        assert_eq!(resolved, PathBuf::from("/usr/local/bin/tsx-pinned"));
    }

    #[test]
    fn script_language_inferred_from_extension() {
        let py = PathBuf::from("/tmp/foo.py");
        let ts = PathBuf::from("/tmp/foo.ts");
        let js = PathBuf::from("/tmp/foo.js");
        let unk = PathBuf::from("/tmp/foo.txt");
        assert!(matches!(
            script_language_from_path(&py),
            Some(ScriptLanguage::Python)
        ));
        assert!(matches!(
            script_language_from_path(&ts),
            Some(ScriptLanguage::TypeScript)
        ));
        assert!(matches!(
            script_language_from_path(&js),
            Some(ScriptLanguage::Node)
        ));
        assert!(script_language_from_path(&unk).is_none());
    }
}
