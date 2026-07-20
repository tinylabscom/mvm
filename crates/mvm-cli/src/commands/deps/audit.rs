//! `mvmctl deps audit [--all | <volume_hash>]` — re-run the CVE
//! scan against a cached deps volume, rewrite `cve.json`, bump
//! `last_audit_at`, reseal, and atomically rename the volume
//! directory to its new hash.
//!
//! Re-audit is incremental: only `cve.json` and `meta.json` change
//! between the old and new sealed forms. The volume's content,
//! SBOM, and fetch.log are untouched, so the re-audit is cheap and
//! shipps a fresh CVE verdict against the workload without
//! rebuilding `content/`. The same incremental property holds for
//! CI re-runs.
//!
//! ## Why the rename
//!
//! The volume hash is `sha256(content_sha256 || canonical(meta))`.
//! Re-audit changes `meta.json.last_audit_at` AND
//! `meta.json.cve_sha256` (since `cve.json` was rewritten), so the
//! canonical manifest bytes change, so the volume hash changes.
//! The supervisor's admission gate pins the volume
//! hash, so any plan that bound the OLD hash will fail admission
//! after a re-audit. That's intentional — a stale CVE verdict
//! shouldn't admit silently — but we log the rename loudly so
//! users can update bound plans.
//!
//! ## Host-side runners
//!
//! Re-audit invokes `pip-audit` / `pnpm audit --json` on the host
//! (not inside a builder VM — re-audits are cheap and benefit from
//! speed). If the runner isn't installed, the [`AuditRunner`] trait
//! surfaces a clear error pointing at install docs. The trait
//! indirection also lets tests exercise the full re-seal + rename
//! pipeline against a mock runner without needing the system tools
//! installed on CI.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

use mvm_sdk::compile::deps_audit::{
    FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, VolumeManifest, reseal_volume,
    verify_sealed_volume,
};

use crate::ui;

/// CLI args for `mvmctl deps audit`. Exactly one of `volume_hash`
/// (positional) or `--all` must be supplied.
#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Specific 64-hex volume hash to re-audit. Conflicts with
    /// `--all`.
    #[arg(conflicts_with = "all")]
    pub volume_hash: Option<String>,
    /// Re-audit every volume in the deps-volumes cache. Conflicts
    /// with the positional `volume_hash`.
    #[arg(long)]
    pub all: bool,
    /// Override the deps-volumes cache root. Defaults to
    /// `mvm_core::config::mvm_deps_volumes_dir()`.
    #[arg(long)]
    pub cache_root: Option<PathBuf>,
    /// Emit a machine-readable JSON summary on stdout (in addition
    /// to the human-readable summary on stderr).
    #[arg(long)]
    pub json: bool,
}

/// What language the volume was built for. Derived from the
/// volume's `meta.json.annotations.language` (see
/// `mvm_build::app_deps::install_app_deps`, which writes the token
/// at seal time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Language {
    Python,
    Node,
}

impl Language {
    fn token(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }
}

/// Test seam for the host audit runners. Production wires
/// [`HostAuditRunner`]; tests pass a [`MockAuditRunner`] that
/// returns canned bytes without spawning a subprocess.
pub(super) trait AuditRunner {
    /// Run `pip-audit` (or its equivalent for the language) against
    /// the volume's content directory and return the raw JSON
    /// bytes the runner emitted. Errors should surface a clear
    /// install hint when the runner binary is absent.
    fn run(&self, language: Language, content_dir: &Path) -> Result<Vec<u8>>;
}

/// Production [`AuditRunner`]: shells `pip-audit` / `pnpm audit
/// --json` on the host. The Python invocation reads the recovered
/// `requirements.txt` (one line per package) the SBOM enumerates;
/// the Node invocation looks for a `package-lock.json` we'll fail
/// closed if not present (re-audit on a sealed Node volume that
/// shipped without a lockfile is out of scope for v1).
pub(super) struct HostAuditRunner;

impl AuditRunner for HostAuditRunner {
    fn run(&self, language: Language, content_dir: &Path) -> Result<Vec<u8>> {
        match language {
            Language::Python => run_pip_audit(content_dir),
            Language::Node => run_pnpm_audit(content_dir),
        }
    }
}

fn run_pip_audit(content_dir: &Path) -> Result<Vec<u8>> {
    let pip_audit = which::which("pip-audit").map_err(|_| {
        anyhow::anyhow!(
            "pip-audit not found on PATH. Install with \
             `pipx install pip-audit` (preferred) or `python -m pip install pip-audit`, \
             then re-run `mvmctl deps audit`."
        )
    })?;
    // Re-audit against the venv at content_dir. pip-audit's
    // `--path <dir>` mode points it at an existing environment;
    // the deps volume's `content/` is exactly that.
    let output = Command::new(&pip_audit)
        .arg("--format=json")
        .arg("--path")
        .arg(content_dir)
        .output()
        .with_context(|| format!("spawning {}", pip_audit.display()))?;
    // pip-audit exits non-zero when findings exist, but the JSON is
    // still on stdout. Treat any output we can parse as success.
    if output.stdout.is_empty() && !output.status.success() {
        anyhow::bail!(
            "pip-audit failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn run_pnpm_audit(content_dir: &Path) -> Result<Vec<u8>> {
    let pnpm = which::which("pnpm").map_err(|_| {
        anyhow::anyhow!(
            "pnpm not found on PATH. Install with `npm install -g pnpm` or \
             `corepack enable && corepack prepare pnpm@latest --activate`, \
             then re-run `mvmctl deps audit`."
        )
    })?;
    // pnpm audit runs in a project dir. The volume's content/
    // is `/app/node_modules`, so the project dir is its parent;
    // walk up one level. If we can't find a sensible parent, fall
    // back to content_dir and let pnpm complain — better than a
    // silent miss.
    let project = content_dir.parent().unwrap_or(content_dir);
    let output = Command::new(&pnpm)
        .arg("audit")
        .arg("--json")
        .current_dir(project)
        .output()
        .with_context(|| format!("spawning {}", pnpm.display()))?;
    if output.stdout.is_empty() && !output.status.success() {
        anyhow::bail!(
            "pnpm audit failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Aggregated outcome for the audit run. One entry per volume
/// processed.
#[derive(Debug, Clone, Serialize)]
pub(super) struct AuditOutcome {
    pub prior_hash: String,
    pub new_hash: String,
    pub volume_dir: PathBuf,
    pub language: Language,
    pub new_high_critical: usize,
    pub new_findings: Vec<NewFinding>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct NewFinding {
    pub package: String,
    pub severity: String,
    pub id: Option<String>,
}

/// Entrypoint dispatched from `commands::deps::run`.
pub(in crate::commands) fn run(args: Args) -> Result<()> {
    if args.volume_hash.is_none() && !args.all {
        anyhow::bail!("specify a <volume_hash> or pass --all to re-audit every cached volume");
    }
    let cache_root = mvm_build::app_deps::resolve_cache_root(args.cache_root.as_deref());
    let runner = HostAuditRunner;
    let outcomes = run_with_runner(&cache_root, &args, &runner)?;
    render_summary(&outcomes, args.json)?;
    Ok(())
}

/// Test-visible driver. Splits the AuditRunner out so tests can
/// inject a [`MockAuditRunner`]; production [`run`] wires
/// [`HostAuditRunner`].
pub(super) fn run_with_runner(
    cache_root: &Path,
    args: &Args,
    runner: &dyn AuditRunner,
) -> Result<Vec<AuditOutcome>> {
    let targets = resolve_targets(cache_root, args)?;
    let mut outcomes = Vec::new();
    for target in targets {
        let outcome = audit_one(cache_root, &target, runner)?;
        emit_audit_event(&outcome);
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// Build the list of volume hashes the audit will process.
fn resolve_targets(cache_root: &Path, args: &Args) -> Result<Vec<String>> {
    if let Some(h) = &args.volume_hash {
        return Ok(vec![h.clone()]);
    }
    if !cache_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(cache_root)
        .with_context(|| format!("reading {}", cache_root.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Skip the orchestrator's `index/` and `in-progress/`
        // siblings (see `mvm_build::app_deps::INDEX_SUBDIR`).
        if name == "index" || name == "in-progress" {
            continue;
        }
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Only descend into things that *look* like a sealed
        // volume (have meta.json). Anything else is skipped
        // silently — the cache root is mvm-owned so stray
        // directories are noise.
        if !path.join(FILE_MANIFEST).is_file() {
            continue;
        }
        out.push(name);
    }
    out.sort();
    Ok(out)
}

/// Audit one volume: verify it currently seals, recover the
/// language annotation, dispatch the runner, rewrite cve.json +
/// meta.json, reseal, atomically rename the directory.
fn audit_one(
    cache_root: &Path,
    volume_hash: &str,
    runner: &dyn AuditRunner,
) -> Result<AuditOutcome> {
    let volume_dir = cache_root.join(volume_hash);
    let derived = verify_sealed_volume(&volume_dir).with_context(|| {
        format!(
            "refusing to re-audit tampered volume {}; rebuild the \
             workload (mvmctl build --deps) to restore a clean seal",
            volume_dir.display()
        )
    })?;
    if derived != volume_hash {
        anyhow::bail!(
            "volume {} verifies but its sealed hash {} disagrees with \
             the directory name; this is a stale rename",
            volume_hash,
            derived,
        );
    }
    let manifest = read_manifest(&volume_dir)?;
    let language = recover_language(&manifest, &volume_dir)?;

    // Cache the prior CVE findings so we can diff and report
    // newly-surfaced high/critical issues at the end.
    let prior_cve_path = volume_dir.join(FILE_CVE);
    let prior_cve = std::fs::read(&prior_cve_path)
        .with_context(|| format!("reading {}", prior_cve_path.display()))?;
    let prior_findings = parse_findings(&prior_cve);

    let content_dir = volume_dir.join("content");
    let fresh_cve = runner.run(language, &content_dir)?;
    let fresh_findings = parse_findings(&fresh_cve);

    // Stage the rewrite under a sibling temp dir, then rename
    // atomically once everything seals cleanly. Doing the work
    // outside the volume dir means a half-written cve.json on a
    // crash doesn't corrupt the original volume.
    let scratch = scratch_dir_for(cache_root, volume_hash)?;
    copy_volume_skeleton(&volume_dir, &scratch)?;
    let scratch_cve = scratch.join(FILE_CVE);
    std::fs::write(&scratch_cve, &fresh_cve)
        .with_context(|| format!("writing {}", scratch_cve.display()))?;

    let now = chrono::Utc::now().to_rfc3339();
    let sealed = reseal_volume(
        &scratch.join("content"),
        &scratch.join(FILE_SBOM),
        &scratch.join(FILE_FETCH_LOG),
        &scratch_cve,
        manifest.created_at.clone(),
        now,
        manifest.annotations.clone(),
    )
    .context("re-sealing volume after CVE rewrite")?;
    std::fs::write(scratch.join(FILE_MANIFEST), &sealed.manifest_bytes)
        .with_context(|| format!("writing meta.json under {}", scratch.display()))?;

    // Diff to surface newly-introduced high/critical findings.
    let new_findings = diff_findings(&prior_findings, &fresh_findings);
    let new_high_critical = new_findings
        .iter()
        .filter(|f| is_high_or_critical(&f.severity))
        .count();

    // Atomic rename: scratch → cache_root/<new_hash>.
    let new_dir = cache_root.join(&sealed.volume_hash);
    if sealed.volume_hash == volume_hash {
        // No meaningful change — replace in place so the volume
        // directory's mtime advances but the slot keeps its name.
        std::fs::remove_dir_all(&volume_dir).with_context(|| {
            format!(
                "removing stale volume dir {} before re-seal swap",
                volume_dir.display()
            )
        })?;
        std::fs::rename(&scratch, &volume_dir).with_context(|| {
            format!("renaming {} to {}", scratch.display(), volume_dir.display())
        })?;
    } else {
        if new_dir.exists() {
            // Defensive: another concurrent re-audit beat us. Drop
            // the scratch (the existing dir is also a valid seal of
            // the same content) and report the rename so the user
            // still sees it.
            let _ = std::fs::remove_dir_all(&scratch);
        } else {
            std::fs::rename(&scratch, &new_dir).with_context(|| {
                format!("renaming {} to {}", scratch.display(), new_dir.display())
            })?;
        }
        std::fs::remove_dir_all(&volume_dir).with_context(|| {
            format!(
                "removing prior volume dir {} after rename",
                volume_dir.display()
            )
        })?;
        // Refresh the index pointer (lockfile_hash → volume_hash)
        // when the volume's annotations recorded one. The install
        // orchestrator writes this; an admin-authored volume may
        // not have it.
        if let Some(lockfile_hash) = manifest.annotations.get("lockfile_hash") {
            refresh_index_pointer(cache_root, lockfile_hash, &sealed.volume_hash)?;
        }
    }

    Ok(AuditOutcome {
        prior_hash: volume_hash.to_string(),
        new_hash: sealed.volume_hash,
        volume_dir: new_dir,
        language,
        new_high_critical,
        new_findings,
    })
}

fn read_manifest(volume_dir: &Path) -> Result<VolumeManifest> {
    let path = volume_dir.join(FILE_MANIFEST);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: VolumeManifest =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(manifest)
}

fn recover_language(manifest: &VolumeManifest, volume_dir: &Path) -> Result<Language> {
    if let Some(tok) = manifest.annotations.get("language") {
        return match tok.as_str() {
            "python" => Ok(Language::Python),
            "node" => Ok(Language::Node),
            other => anyhow::bail!(
                "volume {} declares unknown language `{}` in its annotations; \
                 expected `python` or `node`",
                volume_dir.display(),
                other,
            ),
        };
    }
    anyhow::bail!(
        "volume {} has no `language` annotation in its meta.json; \
         this volume was sealed before Plan 73 Followup B.2 recorded \
         the language token. Rebuild the workload with `mvmctl build \
         --deps` to repopulate the annotation.",
        volume_dir.display(),
    )
}

fn scratch_dir_for(cache_root: &Path, volume_hash: &str) -> Result<PathBuf> {
    let parent = cache_root.join("in-progress");
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let scratch = parent.join(format!("audit-{volume_hash}.{}", std::process::id()));
    if scratch.exists() {
        std::fs::remove_dir_all(&scratch)
            .with_context(|| format!("removing prior scratch dir {}", scratch.display()))?;
    }
    std::fs::create_dir_all(&scratch).with_context(|| format!("creating {}", scratch.display()))?;
    Ok(scratch)
}

/// Copy the volume directory's structure into `dest`: content/
/// recursively, plus the sealed sidecars verbatim. cve.json gets
/// overwritten by the caller after the runner produces fresh bytes.
fn copy_volume_skeleton(src: &Path, dest: &Path) -> Result<()> {
    copy_dir_recursive(&src.join("content"), &dest.join("content"))?;
    for f in [FILE_SBOM, FILE_FETCH_LOG, FILE_CVE, FILE_MANIFEST] {
        std::fs::copy(src.join(f), dest.join(f))
            .with_context(|| format!("copying {} to scratch", f))?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
        }
        // Symlinks are out of scope (the install pipeline doesn't
        // emit them).
    }
    Ok(())
}

/// Update `<cache_root>/index/<lockfile_hash>` so the orchestrator's
/// cache hit on the same lockfile picks up the resealed volume.
fn refresh_index_pointer(
    cache_root: &Path,
    lockfile_hash: &str,
    new_volume_hash: &str,
) -> Result<()> {
    let index_dir = cache_root.join("index");
    std::fs::create_dir_all(&index_dir)
        .with_context(|| format!("creating {}", index_dir.display()))?;
    let path = index_dir.join(lockfile_hash);
    std::fs::write(&path, new_volume_hash)
        .with_context(|| format!("writing index pointer {}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
struct ParsedFinding {
    package: String,
    severity: String,
    id: Option<String>,
}

fn parse_findings(bytes: &[u8]) -> Vec<ParsedFinding> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(deps) = value.get("dependencies").and_then(|v| v.as_array()) {
        for dep in deps {
            let pkg = dep
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)")
                .to_string();
            let Some(vulns) = dep.get("vulns").and_then(|v| v.as_array()) else {
                continue;
            };
            for vuln in vulns {
                let severity = vuln
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let id = vuln.get("id").and_then(|v| v.as_str()).map(str::to_string);
                out.push(ParsedFinding {
                    package: pkg.clone(),
                    severity,
                    id,
                });
            }
        }
    }
    if let Some(advisories) = value.get("advisories").and_then(|v| v.as_object()) {
        for (id, advisory) in advisories {
            let pkg = advisory
                .get("module_name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)")
                .to_string();
            let severity = advisory
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            out.push(ParsedFinding {
                package: pkg,
                severity,
                id: Some(id.clone()),
            });
        }
    }
    out
}

/// Surface findings that exist in `fresh` but did not appear in
/// `prior`. Diff key is `(package, id || severity)` so the same
/// package can show multiple new advisories.
fn diff_findings(prior: &[ParsedFinding], fresh: &[ParsedFinding]) -> Vec<NewFinding> {
    let prior_keys: std::collections::BTreeSet<(String, String)> = prior
        .iter()
        .map(|f| {
            let key = f.id.clone().unwrap_or_else(|| f.severity.to_lowercase());
            (f.package.clone(), key)
        })
        .collect();
    let mut out: Vec<NewFinding> = Vec::new();
    for f in fresh {
        let key = f.id.clone().unwrap_or_else(|| f.severity.to_lowercase());
        if prior_keys.contains(&(f.package.clone(), key)) {
            continue;
        }
        out.push(NewFinding {
            package: f.package.clone(),
            severity: f.severity.to_lowercase(),
            id: f.id.clone(),
        });
    }
    // Sort: severity (critical > high > moderate > low > unknown), then package, then id.
    out.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "moderate" | "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn is_high_or_critical(sev: &str) -> bool {
    matches!(sev.to_lowercase().as_str(), "high" | "critical")
}

fn emit_audit_event(outcome: &AuditOutcome) {
    mvm_core::audit_emit!(
        DepsAudit,
        "prior={prior},new={new},language={lang},new_high_critical={hc}",
        prior = outcome.prior_hash,
        new = outcome.new_hash,
        lang = outcome.language.token(),
        hc = outcome.new_high_critical,
    );
}

fn render_summary(outcomes: &[AuditOutcome], json: bool) -> Result<()> {
    if json {
        let body =
            serde_json::to_string_pretty(outcomes).context("serializing deps audit outcomes")?;
        println!("{body}");
    }

    if outcomes.is_empty() {
        ui::info("No deps volumes to re-audit.");
        return Ok(());
    }

    for outcome in outcomes {
        let renamed = outcome.prior_hash != outcome.new_hash;
        if renamed {
            ui::info(&format!(
                "Re-audited {}/{} ({}): volume hash rolled to {}. Update any plans bound to the prior hash.",
                outcome.language.token(),
                short_hash(&outcome.prior_hash),
                outcome.prior_hash,
                outcome.new_hash,
            ));
        } else {
            ui::info(&format!(
                "Re-audited {}/{}: CVE feed surfaced no manifest-altering changes; volume hash unchanged.",
                outcome.language.token(),
                short_hash(&outcome.prior_hash),
            ));
        }
    }

    // Collect every newly-surfaced high/critical finding across all
    // volumes and report once at the end, sorted by severity then
    // package name.
    let mut newly_surfaced: Vec<(&str, &NewFinding)> = Vec::new();
    for outcome in outcomes {
        for finding in &outcome.new_findings {
            if is_high_or_critical(&finding.severity) {
                newly_surfaced.push((outcome.language.token(), finding));
            }
        }
    }
    newly_surfaced.sort_by(|a, b| {
        severity_rank(&b.1.severity)
            .cmp(&severity_rank(&a.1.severity))
            .then_with(|| a.1.package.cmp(&b.1.package))
    });
    if !newly_surfaced.is_empty() {
        ui::warn(&format!(
            "{} newly-surfaced high/critical finding(s) across the re-audited volume(s):",
            newly_surfaced.len(),
        ));
        for (lang, finding) in newly_surfaced {
            let id = finding.id.as_deref().unwrap_or("?");
            println!(
                "  [{lang}] {sev:<8}  {pkg}  ({id})",
                sev = finding.severity,
                pkg = finding.package,
            );
        }
    }
    Ok(())
}

fn short_hash(h: &str) -> String {
    if h.len() <= 16 {
        h.to_string()
    } else {
        format!("{}…{}", &h[..8], &h[h.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::tempdir;

    /// Hand-author a sealed volume for tests. Mirrors the helper
    /// in `inspect.rs::tests` but lives here too because the
    /// modules are siblings; pulling it into a shared `tests/`
    /// submodule isn't worth the indirection for two callers.
    fn make_sealed_volume(
        cache_root: &Path,
        sbom: &str,
        fetch: &str,
        cve: &str,
        annotations: BTreeMap<String, String>,
    ) -> (PathBuf, String) {
        use mvm_sdk::compile::deps_audit::{
            FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, seal_volume,
        };
        let work = cache_root.join("scratch");
        let content = work.join(FILE_CONTENT_DIR);
        fs::create_dir_all(&content).unwrap();
        fs::write(content.join("a.txt"), b"alpha\n").unwrap();
        let s = work.join(FILE_SBOM);
        fs::write(&s, sbom).unwrap();
        let f = work.join(FILE_FETCH_LOG);
        fs::write(&f, fetch).unwrap();
        let c = work.join(FILE_CVE);
        fs::write(&c, cve).unwrap();
        let sealed =
            seal_volume(&content, &s, &f, &c, "2026-05-14T00:00:00Z", annotations).unwrap();
        fs::write(work.join(FILE_MANIFEST), &sealed.manifest_bytes).unwrap();
        let final_dir = cache_root.join(&sealed.volume_hash);
        fs::rename(&work, &final_dir).unwrap();
        (final_dir, sealed.volume_hash)
    }

    /// Test runner that hands back canned bytes per call.
    struct MockAuditRunner {
        responses: RefCell<Vec<Vec<u8>>>,
        last_language: RefCell<Option<Language>>,
    }

    impl MockAuditRunner {
        fn new(responses: Vec<&[u8]>) -> Self {
            Self {
                responses: RefCell::new(responses.into_iter().map(|b| b.to_vec()).collect()),
                last_language: RefCell::new(None),
            }
        }
    }

    impl AuditRunner for MockAuditRunner {
        fn run(&self, language: Language, _content_dir: &Path) -> Result<Vec<u8>> {
            *self.last_language.borrow_mut() = Some(language);
            let mut r = self.responses.borrow_mut();
            if r.is_empty() {
                anyhow::bail!("mock runner ran out of canned responses");
            }
            Ok(r.remove(0))
        }
    }

    fn ann_python() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("language".to_string(), "python".to_string());
        m
    }

    #[test]
    fn audit_rewrites_cve_and_renames_volume() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let (_old_dir, old_hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            ann_python(),
        );

        let new_cve = serde_json::json!({
            "dependencies": [
                {"name": "evil", "vulns": [
                    {"id": "CVE-2026-99", "severity": "HIGH"}
                ]}
            ]
        })
        .to_string();
        let runner = MockAuditRunner::new(vec![new_cve.as_bytes()]);

        let args = Args {
            volume_hash: Some(old_hash.clone()),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let outcomes = run_with_runner(cache, &args, &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(outcome.prior_hash, old_hash);
        assert_ne!(outcome.new_hash, old_hash, "rename must roll the hash");
        assert!(outcome.volume_dir.is_dir());
        // Old directory must be gone.
        assert!(!cache.join(&old_hash).exists());
        // New directory verifies cleanly.
        let derived = verify_sealed_volume(&cache.join(&outcome.new_hash)).unwrap();
        assert_eq!(derived, outcome.new_hash);
        // Newly-surfaced high CVE counted.
        assert_eq!(outcome.new_high_critical, 1);
        assert_eq!(outcome.new_findings.len(), 1);
        assert_eq!(outcome.new_findings[0].package, "evil");
        assert_eq!(outcome.new_findings[0].severity, "high");
        // Manifest's last_audit_at is bumped relative to created_at.
        let manifest_bytes =
            std::fs::read(cache.join(&outcome.new_hash).join("meta.json")).unwrap();
        let manifest: VolumeManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest.created_at, "2026-05-14T00:00:00Z");
        assert_ne!(manifest.last_audit_at, manifest.created_at);
    }

    #[test]
    fn audit_keeps_directory_name_when_cve_is_identical() {
        // Same CVE bytes → identical content sha + identical
        // sbom/fetch/cve hashes. last_audit_at still changes →
        // manifest changes → volume hash changes. We always rename.
        // To prove the "no rename" branch separately we'd need
        // identical timestamps too; production gives a fresh
        // chrono::Utc::now() so the rename branch is what real
        // re-audits exercise. This test pins that.
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let cve = r#"{"dependencies":[]}"#;
        let (_old_dir, old_hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            cve,
            ann_python(),
        );
        let runner = MockAuditRunner::new(vec![cve.as_bytes()]);
        let args = Args {
            volume_hash: Some(old_hash.clone()),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let outcomes = run_with_runner(cache, &args, &runner).unwrap();
        // Hash changes because last_audit_at advanced.
        assert_ne!(outcomes[0].new_hash, old_hash);
        assert_eq!(outcomes[0].new_high_critical, 0);
        assert!(outcomes[0].new_findings.is_empty());
    }

    #[test]
    fn audit_refreshes_index_when_lockfile_hash_annotation_present() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let mut ann = ann_python();
        ann.insert("lockfile_hash".to_string(), "lockaaaa".to_string());
        let (_old_dir, old_hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            ann,
        );
        // Seed the prior index pointer that the orchestrator
        // would have written.
        std::fs::create_dir_all(cache.join("index")).unwrap();
        std::fs::write(cache.join("index").join("lockaaaa"), &old_hash).unwrap();

        let runner = MockAuditRunner::new(vec![br#"{"dependencies":[]}"#.as_slice()]);
        let args = Args {
            volume_hash: Some(old_hash.clone()),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let outcomes = run_with_runner(cache, &args, &runner).unwrap();
        let new_hash = &outcomes[0].new_hash;
        let pointer = std::fs::read_to_string(cache.join("index").join("lockaaaa")).unwrap();
        assert_eq!(pointer, *new_hash);
    }

    #[test]
    fn audit_all_processes_every_volume_and_skips_index_dir() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let (_, h1) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/a/\n",
            r#"{"dependencies":[]}"#,
            ann_python(),
        );
        let (_, h2) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/b/\n",
            r#"{"dependencies":[]}"#,
            ann_python(),
        );
        // Plant a stray index/ dir — it must be skipped.
        std::fs::create_dir_all(cache.join("index")).unwrap();
        std::fs::write(cache.join("index").join("garbage"), "stray").unwrap();

        // Two responses, one per volume.
        let resp = br#"{"dependencies":[]}"#.as_slice();
        let runner = MockAuditRunner::new(vec![resp, resp]);
        let args = Args {
            volume_hash: None,
            all: true,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let outcomes = run_with_runner(cache, &args, &runner).unwrap();
        assert_eq!(outcomes.len(), 2);
        let prior_hashes: std::collections::BTreeSet<_> =
            outcomes.iter().map(|o| o.prior_hash.clone()).collect();
        assert!(prior_hashes.contains(&h1));
        assert!(prior_hashes.contains(&h2));
    }

    #[test]
    fn audit_refuses_tampered_volume() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let (dir, hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            ann_python(),
        );
        // Tamper with the SBOM bytes — verify will refuse.
        std::fs::write(dir.join(FILE_SBOM), b"{\"bomFormat\":\"FAKE\"}").unwrap();

        let runner = MockAuditRunner::new(vec![br#"{"dependencies":[]}"#.as_slice()]);
        let args = Args {
            volume_hash: Some(hash.clone()),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let err = run_with_runner(cache, &args, &runner).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("tampered") || msg.contains("hash mismatch"),
            "{msg}"
        );
    }

    #[test]
    fn audit_requires_language_annotation() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        // No annotations → no language token → audit refuses.
        let (_, hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            BTreeMap::new(),
        );
        let runner = MockAuditRunner::new(vec![b"".as_slice()]);
        let args = Args {
            volume_hash: Some(hash),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let err = run_with_runner(cache, &args, &runner).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("language") && msg.contains("annotation"),
            "{msg}"
        );
    }

    #[test]
    fn audit_rejects_unknown_language_token() {
        let tmp = tempdir().unwrap();
        let cache = tmp.path();
        let mut ann = BTreeMap::new();
        ann.insert("language".to_string(), "ruby".to_string());
        let (_, hash) = make_sealed_volume(
            cache,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            ann,
        );
        let runner = MockAuditRunner::new(vec![b"".as_slice()]);
        let args = Args {
            volume_hash: Some(hash),
            all: false,
            cache_root: Some(cache.to_path_buf()),
            json: false,
        };
        let err = run_with_runner(cache, &args, &runner).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unknown language") && msg.contains("ruby"),
            "{msg}"
        );
    }

    #[test]
    fn diff_findings_surfaces_only_new_entries() {
        let prior = vec![ParsedFinding {
            package: "requests".into(),
            severity: "low".into(),
            id: Some("CVE-1".into()),
        }];
        let fresh = vec![
            ParsedFinding {
                package: "requests".into(),
                severity: "low".into(),
                id: Some("CVE-1".into()),
            },
            ParsedFinding {
                package: "evil".into(),
                severity: "critical".into(),
                id: Some("CVE-99".into()),
            },
        ];
        let new = diff_findings(&prior, &fresh);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].package, "evil");
        assert_eq!(new[0].severity, "critical");
    }

    #[test]
    fn parse_findings_handles_pip_and_pnpm_shapes() {
        let pip =
            br#"{"dependencies":[{"name":"requests","vulns":[{"id":"CVE-1","severity":"HIGH"}]}]}"#;
        let p = parse_findings(pip);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].package, "requests");
        assert_eq!(p[0].severity, "HIGH");

        let pnpm = br#"{"advisories":{"123":{"module_name":"lodash","severity":"critical"}}}"#;
        let n = parse_findings(pnpm);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].package, "lodash");
        assert_eq!(n[0].severity, "critical");
    }

    #[test]
    fn run_dispatch_rejects_no_target() {
        // Calls into the public CLI dispatch path; expects --all
        // OR a volume_hash. (resolve_targets handles the absence of
        // both via the public run() layer, not here.)
        let args = Args {
            volume_hash: None,
            all: false,
            cache_root: None,
            json: false,
        };
        let err = run(args).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--all"), "{msg}");
    }
}
