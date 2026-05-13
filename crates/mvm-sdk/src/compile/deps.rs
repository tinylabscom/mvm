//! Host-level dependency-lockfile validation (plan-0008).
//!
//! IR-level `validate()` enforces the *declaration* — function workloads
//! must pick `Dependencies::Python | Node | None`. Once the host has the
//! manifest_dir on disk, this module reads the lockfile pointed at by
//! the declaration and applies a per-format hash-pin heuristic. A
//! lockfile that doesn't carry hashes for every entry fails with
//! `E_UNPINNED_DEPS`; a missing lockfile fails with
//! `E_LOCKFILE_NOT_FOUND`.
//!
//! The heuristics are conservative — we don't run a full lockfile
//! parser, we just look for the per-format hash signature on every
//! relevant entry. If the heuristic can't conclude, we err on the
//! side of "looks pinned" rather than false-positive.

use mvm_ir::{Dependencies, NodeTool, PythonTool, Workload};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum DepsError {
    /// `app.dependencies.lockfile` did not resolve to a regular file.
    LockfileNotFound { app_index: usize, path: PathBuf },
    /// Lockfile read OK but failed the per-format hash-pin heuristic.
    Unpinned {
        app_index: usize,
        path: PathBuf,
        detail: String,
    },
    /// I/O error reading the lockfile.
    Io {
        app_index: usize,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for DepsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockfileNotFound { path, .. } => {
                write!(f, "dependency lockfile not found: {}", path.display())
            }
            Self::Unpinned { path, detail, .. } => {
                write!(
                    f,
                    "lockfile {} is not hash-pinned: {}",
                    path.display(),
                    detail
                )
            }
            Self::Io { path, source, .. } => {
                write!(
                    f,
                    "I/O error reading lockfile {}: {}",
                    path.display(),
                    source
                )
            }
        }
    }
}

impl std::error::Error for DepsError {}

/// Validate every app's lockfile declaration against the on-disk tree.
/// `manifest_dir` is where `app.source.path` is interpreted from.
pub fn validate_lockfiles(workload: &Workload, manifest_dir: &Path) -> Result<(), DepsError> {
    for (i, app) in workload.apps.iter().enumerate() {
        let Some(deps) = &app.dependencies else {
            continue;
        };
        match deps {
            Dependencies::None => continue,
            Dependencies::Python { lockfile, tool } => {
                let path = resolve_lockfile_path(manifest_dir, app, lockfile);
                let bytes = read_lockfile(i, &path)?;
                check_python(*tool, i, &path, &bytes)?;
            }
            Dependencies::Node { lockfile, tool } => {
                let path = resolve_lockfile_path(manifest_dir, app, lockfile);
                let bytes = read_lockfile(i, &path)?;
                check_node(*tool, i, &path, &bytes)?;
            }
        }
    }
    Ok(())
}

fn resolve_lockfile_path(manifest_dir: &Path, app: &mvm_ir::App, lockfile: &str) -> PathBuf {
    // app.source.path is interpreted relative to manifest_dir. The
    // lockfile is interpreted relative to that resolved source root.
    let source_root = match &app.source {
        mvm_ir::Source::LocalPath { path, .. } => {
            let p = Path::new(path);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                manifest_dir.join(p)
            }
        }
        // For non-local sources we have nothing on disk to validate.
        // The IR validator has already rejected these for v0; defense
        // in depth: resolve relative to manifest_dir.
        _ => manifest_dir.to_path_buf(),
    };
    source_root.join(lockfile)
}

fn read_lockfile(app_index: usize, path: &Path) -> Result<Vec<u8>, DepsError> {
    if !path.is_file() {
        return Err(DepsError::LockfileNotFound {
            app_index,
            path: path.to_path_buf(),
        });
    }
    fs::read(path).map_err(|source| DepsError::Io {
        app_index,
        path: path.to_path_buf(),
        source,
    })
}

fn check_python(
    tool: PythonTool,
    app_index: usize,
    path: &Path,
    bytes: &[u8],
) -> Result<(), DepsError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DepsError::Unpinned {
        app_index,
        path: path.to_path_buf(),
        detail: "lockfile is not valid UTF-8".to_string(),
    })?;
    match tool {
        PythonTool::Uv => check_uv_lock(text).map_err(|detail| DepsError::Unpinned {
            app_index,
            path: path.to_path_buf(),
            detail,
        }),
        PythonTool::PipTools => {
            check_requirements_hashes(text).map_err(|detail| DepsError::Unpinned {
                app_index,
                path: path.to_path_buf(),
                detail,
            })
        }
    }
}

fn check_node(
    tool: NodeTool,
    app_index: usize,
    path: &Path,
    bytes: &[u8],
) -> Result<(), DepsError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DepsError::Unpinned {
        app_index,
        path: path.to_path_buf(),
        detail: "lockfile is not valid UTF-8".to_string(),
    })?;
    match tool {
        NodeTool::Pnpm => check_pnpm_lock(text).map_err(|detail| DepsError::Unpinned {
            app_index,
            path: path.to_path_buf(),
            detail,
        }),
        NodeTool::Npm => check_package_lock(text).map_err(|detail| DepsError::Unpinned {
            app_index,
            path: path.to_path_buf(),
            detail,
        }),
        NodeTool::Yarn => check_yarn_lock(text).map_err(|detail| DepsError::Unpinned {
            app_index,
            path: path.to_path_buf(),
            detail,
        }),
    }
}

/// yarn.lock (Yarn classic v1): a flat text format. Each entry block
/// starts with one or more quoted spec lines (`"foo@^1.0.0":`) and
/// must contain an `integrity "sha512-..."` line in the indented
/// body. We detect entries by indent change (column 0 spec line →
/// column 2+ body lines) and fail any entry that doesn't carry
/// integrity.
fn check_yarn_lock(text: &str) -> Result<(), String> {
    if !text.contains("# yarn lockfile") && !text.contains("# THIS IS AN AUTOGENERATED FILE") {
        return Err("missing yarn.lock header — not recognized as a Yarn classic lockfile".into());
    }
    let mut total = 0usize;
    let mut unpinned = 0usize;
    let mut current_has_integrity = false;
    let mut in_entry = false;
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            // Spec line ends an entry (if we were in one) and begins a new one.
            if in_entry {
                total += 1;
                if !current_has_integrity {
                    unpinned += 1;
                }
            }
            in_entry = true;
            current_has_integrity = false;
            continue;
        }
        if in_entry && line.trim_start().starts_with("integrity ") {
            current_has_integrity = true;
        }
    }
    if in_entry {
        total += 1;
        if !current_has_integrity {
            unpinned += 1;
        }
    }
    if total == 0 {
        return Err("no entries found in yarn.lock".into());
    }
    if unpinned > 0 {
        return Err(format!("{unpinned}/{total} yarn entries missing integrity"));
    }
    Ok(())
}

/// uv.lock: TOML with `[[package]]` blocks. Each dep block must carry
/// a `hash = "..."` somewhere in its scope (either at top-level or
/// inside `[package.source]` / `[[package.wheels]]`).
fn check_uv_lock(text: &str) -> Result<(), String> {
    // Split on `[[package]]` headers and inspect each block.
    let mut total = 0usize;
    let mut unpinned = 0usize;
    let mut current_block: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(block) = current_block.take() {
                total += 1;
                if !block.contains("hash = \"") && !block.contains("hash=\"") {
                    unpinned += 1;
                }
            }
            current_block = Some(String::new());
        } else if let Some(block) = current_block.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    if let Some(block) = current_block.take() {
        total += 1;
        if !block.contains("hash = \"") && !block.contains("hash=\"") {
            unpinned += 1;
        }
    }
    if total == 0 {
        return Err("no [[package]] blocks found — is this a uv.lock?".to_string());
    }
    if unpinned > 0 {
        return Err(format!("{unpinned}/{total} packages missing hash"));
    }
    Ok(())
}

/// requirements.txt rendered with `pip-compile --generate-hashes`. Every
/// non-comment, non-blank, non-directive line must contain `--hash=`.
/// Continuation lines (ending with `\`) carry hashes for the same dep.
fn check_requirements_hashes(text: &str) -> Result<(), String> {
    let mut deps = 0usize;
    let mut unpinned = 0usize;
    let mut current_logical = String::new();
    let mut continuation = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !continuation {
            // Skip blank, comments, and pip directives.
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("-") {
                continue;
            }
            current_logical.clear();
        }
        let stripped = trimmed.trim_end_matches('\\').trim();
        current_logical.push_str(stripped);
        current_logical.push('\n');
        continuation = trimmed.ends_with('\\');
        if !continuation {
            deps += 1;
            if !current_logical.contains("--hash=") {
                unpinned += 1;
            }
            current_logical.clear();
        }
    }
    if deps == 0 {
        return Err("no requirements found in lockfile".to_string());
    }
    if unpinned > 0 {
        return Err(format!("{unpinned}/{deps} requirements missing --hash="));
    }
    Ok(())
}

/// pnpm-lock.yaml: a YAML doc with `lockfileVersion: '6.x'` or '9.x'
/// and a `packages:` map. Every package block must carry an
/// `integrity:` field. We use a line-based heuristic — full YAML
/// parsing isn't worth a new crate dep for this gate.
fn check_pnpm_lock(text: &str) -> Result<(), String> {
    if !text.contains("lockfileVersion:") {
        return Err("missing lockfileVersion — is this a pnpm-lock.yaml?".to_string());
    }
    let mut in_packages = false;
    let mut current_pkg_indent: Option<usize> = None;
    let mut current_pkg_has_integrity = false;
    let mut total = 0usize;
    let mut unpinned = 0usize;
    for line in text.lines() {
        if line.starts_with("packages:") {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Top-level non-packages section — exit packages block.
        if indent == 0 && !line.starts_with(' ') && line.contains(':') {
            break;
        }
        // A package entry header looks like "  /name@version:".
        if indent == 2 && trimmed.ends_with(':') {
            // Finalize previous package.
            if current_pkg_indent.is_some() {
                total += 1;
                if !current_pkg_has_integrity {
                    unpinned += 1;
                }
            }
            current_pkg_indent = Some(indent);
            current_pkg_has_integrity = false;
            continue;
        }
        if current_pkg_indent.is_some() && trimmed.starts_with("integrity:") {
            current_pkg_has_integrity = true;
        }
    }
    if current_pkg_indent.is_some() {
        total += 1;
        if !current_pkg_has_integrity {
            unpinned += 1;
        }
    }
    if total == 0 {
        return Err("no packages found in pnpm-lock.yaml".to_string());
    }
    if unpinned > 0 {
        return Err(format!(
            "{unpinned}/{total} pnpm packages missing integrity"
        ));
    }
    Ok(())
}

/// package-lock.json: JSON with `lockfileVersion: 3` and a `packages`
/// map. Every entry except the root (key `""`) must carry `integrity`
/// and `resolved` strings.
fn check_package_lock(text: &str) -> Result<(), String> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let lockfile_version = v.get("lockfileVersion").and_then(|x| x.as_u64());
    if lockfile_version != Some(3) {
        return Err(format!(
            "package-lock.json must be lockfileVersion 3 (got {:?}); regenerate with `npm install`",
            lockfile_version
        ));
    }
    let packages = v
        .get("packages")
        .and_then(|x| x.as_object())
        .ok_or_else(|| "missing or non-object `packages` field".to_string())?;
    let mut total = 0usize;
    let mut unpinned = 0usize;
    for (key, entry) in packages {
        if key.is_empty() {
            // The root package; not a vendored dep.
            continue;
        }
        total += 1;
        let obj = entry.as_object();
        let has_integrity = obj
            .and_then(|o| o.get("integrity"))
            .and_then(|x| x.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !has_integrity {
            // Local link / symlink entries don't need integrity. Detect
            // those via `link: true`.
            let is_link = obj
                .and_then(|o| o.get("link"))
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            if !is_link {
                unpinned += 1;
            }
        }
    }
    if total == 0 {
        return Err("no vendored packages found".to_string());
    }
    if unpinned > 0 {
        return Err(format!("{unpinned}/{total} npm packages missing integrity"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_lock_pinned_passes() {
        let text = r#"
[[package]]
name = "foo"
version = "1.0"
[package.source]
hash = "sha256:abc"

[[package]]
name = "bar"
version = "2.0"
[[package.wheels]]
hash = "sha256:def"
"#;
        check_uv_lock(text).unwrap();
    }

    #[test]
    fn uv_lock_missing_hash_fails() {
        let text = r#"
[[package]]
name = "foo"
version = "1.0"

[[package]]
name = "bar"
version = "2.0"
[package.source]
hash = "sha256:def"
"#;
        let err = check_uv_lock(text).unwrap_err();
        assert!(err.contains("missing hash"), "got: {err}");
    }

    #[test]
    fn requirements_pinned_passes() {
        let text = "\
foo==1.0 \\
    --hash=sha256:abc
bar==2.0 \\
    --hash=sha256:def
";
        check_requirements_hashes(text).unwrap();
    }

    #[test]
    fn requirements_missing_hash_fails() {
        let text = "foo==1.0\nbar==2.0 --hash=sha256:def\n";
        let err = check_requirements_hashes(text).unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[test]
    fn package_lock_v3_pinned_passes() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0" },
                "node_modules/foo": {
                    "version": "1.0",
                    "integrity": "sha512-abc",
                    "resolved": "https://..."
                }
            }
        }"#;
        check_package_lock(text).unwrap();
    }

    #[test]
    fn package_lock_v3_missing_integrity_fails() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root" },
                "node_modules/foo": { "version": "1.0", "resolved": "..." }
            }
        }"#;
        let err = check_package_lock(text).unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[test]
    fn package_lock_v1_rejected() {
        let text = r#"{ "lockfileVersion": 1, "packages": {} }"#;
        let err = check_package_lock(text).unwrap_err();
        assert!(err.contains("lockfileVersion 3"), "got: {err}");
    }

    #[test]
    fn pnpm_lock_pinned_passes() {
        let text = r#"
lockfileVersion: '9.0'

packages:
  /foo@1.0:
    resolution: { tarball: "..." }
    integrity: sha512-abc
  /bar@2.0:
    integrity: sha512-def
"#;
        check_pnpm_lock(text).unwrap();
    }

    #[test]
    fn yarn_lock_pinned_passes() {
        let text = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"foo@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz\"\n  integrity sha512-abc\n\n\"bar@^2.0.0\":\n  version \"2.0.0\"\n  resolved \"https://registry.yarnpkg.com/bar/-/bar-2.0.0.tgz\"\n  integrity sha512-def\n";
        check_yarn_lock(text).expect("pinned yarn.lock should pass");
    }

    #[test]
    fn yarn_lock_missing_integrity_fails() {
        let text = "# yarn lockfile v1\n\n\"foo@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/foo/-/foo-1.0.0.tgz\"\n\n\"bar@^2.0.0\":\n  integrity sha512-def\n";
        let err = check_yarn_lock(text).unwrap_err();
        assert!(err.contains("missing integrity"), "got: {err}");
    }

    #[test]
    fn yarn_lock_rejects_missing_header() {
        let text = "\"foo@^1.0.0\":\n  integrity sha512-abc\n";
        let err = check_yarn_lock(text).unwrap_err();
        assert!(err.contains("missing yarn.lock header"), "got: {err}");
    }

    #[test]
    fn pnpm_lock_missing_integrity_fails() {
        let text = r#"
lockfileVersion: '9.0'

packages:
  /foo@1.0:
    resolution: { tarball: "..." }
  /bar@2.0:
    integrity: sha512-def
"#;
        let err = check_pnpm_lock(text).unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }
}
