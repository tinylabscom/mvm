//! `mvmctl deps inspect <volume_hash>` — pretty-print the sealed
//! sidecars of one deps volume.
//!
//! Read-only. Resolves the volume directory under the deps-volumes
//! cache root (`mvm_core::config::mvm_deps_volumes_dir()` by default,
//! overridable per-call), runs `verify_sealed_volume` to refuse
//! tampered cache entries (the supervisor admission gate would refuse
//! them too — inspect agreeing with admission is the right posture),
//! and prints a human-friendly summary of:
//!
//! - `meta.json` — schema version, creation + last-audit timestamps,
//!   the four artifact sha256s, the annotation map (carries language,
//!   gate, lockfile hash, etc. — written by `install_app_deps` at
//!   seal time).
//! - `sbom.cdx.json` — CycloneDX 1.5 document. Counts components,
//!   shows the top 10 by `name`, and the bomFormat / specVersion
//!   header.
//! - `fetch.log` — newline-delimited installer fetch log. Counts
//!   lines, extracts and counts unique registries dialed.
//! - `cve.json` — pip-audit / pnpm audit output. Counts results per
//!   severity (critical / high / moderate / low / unknown) and
//!   shows the top 10 affected packages.
//!
//! The `--json` flag emits the same data as a machine-readable
//! object on stdout. Human summary always goes to stdout (not stderr)
//! so users can `mvmctl deps inspect ... | less`.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mvm_sdk::compile::deps_audit::{
    FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, VolumeManifest, verify_sealed_volume,
};

/// Inspect summary surfaced to the user / `--json` consumers.
#[derive(Debug, Clone, Serialize)]
pub(super) struct InspectReport {
    pub volume_hash: String,
    pub volume_dir: PathBuf,
    pub meta: MetaSummary,
    pub sbom: SbomSummary,
    pub fetch_log: FetchLogSummary,
    pub cve: CveSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MetaSummary {
    pub schema_version: u32,
    pub created_at: String,
    pub last_audit_at: String,
    pub content_sha256: String,
    pub sbom_sha256: String,
    pub fetch_log_sha256: String,
    pub cve_sha256: String,
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SbomSummary {
    pub bom_format: Option<String>,
    pub spec_version: Option<String>,
    pub component_count: usize,
    /// Top 10 component names + versions (when present). Stable
    /// order: as listed in the SBOM, truncated to 10.
    pub top_components: Vec<SbomComponent>,
    /// `true` when the file couldn't be parsed as JSON. The volume
    /// still verifies (hash match is the gate); the inspector just
    /// can't peer inside.
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SbomComponent {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct FetchLogSummary {
    pub line_count: usize,
    pub byte_count: u64,
    /// Unique hosts dialed across the log. Derived by scanning
    /// each line for the first `https?://` token and extracting
    /// the host slice. Best-effort — lines that don't follow the
    /// shape just don't contribute.
    pub registries: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CveSummary {
    pub severity_histogram: BTreeMap<String, usize>,
    pub total_findings: usize,
    /// Top 10 affected package names (by occurrence, ties broken
    /// alphabetically).
    pub top_affected: Vec<String>,
    pub parse_error: Option<String>,
}

/// Entrypoint for `mvmctl deps inspect`. Resolves the cache root,
/// verifies the volume, builds the report, and renders.
pub(super) fn run(volume_hash: &str, cache_root_override: Option<&Path>, json: bool) -> Result<()> {
    let cache_root = mvm_build::app_deps::resolve_cache_root(cache_root_override);
    let report = build_report(&cache_root, volume_hash)?;
    if json {
        let body =
            serde_json::to_string_pretty(&report).context("serializing inspect report as JSON")?;
        println!("{body}");
    } else {
        render_human(&report);
    }
    Ok(())
}

/// Construct an [`InspectReport`] for one volume. Public-in-module
/// so the tests can drive it directly without a CLI dispatch.
pub(super) fn build_report(cache_root: &Path, volume_hash: &str) -> Result<InspectReport> {
    let volume_dir = cache_root.join(volume_hash);
    if !volume_dir.is_dir() {
        anyhow::bail!(
            "no deps volume at {} — list available volumes with `ls {}`",
            volume_dir.display(),
            cache_root.display()
        );
    }
    // Refuse to operate on a tampered cache entry. Admission would
    // reject it too; agreeing here keeps the inspector honest.
    let derived = verify_sealed_volume(&volume_dir).with_context(|| {
        format!(
            "volume {} failed integrity check; the directory was \
             modified after sealing. Reseal with `mvmctl deps audit \
             {}` or rebuild the workload.",
            volume_dir.display(),
            volume_hash,
        )
    })?;
    if derived != volume_hash {
        anyhow::bail!(
            "volume directory name {} disagrees with its computed seal hash {}; \
             this is a tamper or a stale rename. Run `mvmctl deps audit --all` to fix.",
            volume_hash,
            derived,
        );
    }
    let meta = read_meta(&volume_dir)?;
    let sbom = summarize_sbom(&volume_dir.join(FILE_SBOM))?;
    let fetch_log = summarize_fetch_log(&volume_dir.join(FILE_FETCH_LOG))?;
    let cve = summarize_cve(&volume_dir.join(FILE_CVE))?;
    Ok(InspectReport {
        volume_hash: volume_hash.to_string(),
        volume_dir,
        meta,
        sbom,
        fetch_log,
        cve,
    })
}

fn read_meta(volume_dir: &Path) -> Result<MetaSummary> {
    let path = volume_dir.join(FILE_MANIFEST);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: VolumeManifest =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(MetaSummary {
        schema_version: manifest.schema_version,
        created_at: manifest.created_at,
        last_audit_at: manifest.last_audit_at,
        content_sha256: manifest.content_sha256,
        sbom_sha256: manifest.sbom_sha256,
        fetch_log_sha256: manifest.fetch_log_sha256,
        cve_sha256: manifest.cve_sha256,
        annotations: manifest.annotations,
    })
}

fn summarize_sbom(path: &Path) -> Result<SbomSummary> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(SbomSummary {
                bom_format: None,
                spec_version: None,
                component_count: 0,
                top_components: Vec::new(),
                parse_error: Some(e.to_string()),
            });
        }
    };
    let bom_format = value
        .get("bomFormat")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let spec_version = value
        .get("specVersion")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let components: Vec<SbomComponent> = value
        .get("components")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let name = c.get("name").and_then(|v| v.as_str())?.to_string();
                    let version = c
                        .get("version")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    Some(SbomComponent { name, version })
                })
                .collect()
        })
        .unwrap_or_default();
    let component_count = components.len();
    let top_components = components.into_iter().take(10).collect();
    Ok(SbomSummary {
        bom_format,
        spec_version,
        component_count,
        top_components,
        parse_error: None,
    })
}

fn summarize_fetch_log(path: &Path) -> Result<FetchLogSummary> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let byte_count = bytes.len() as u64;
    let s = String::from_utf8_lossy(&bytes);
    let mut line_count = 0usize;
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        line_count += 1;
        if let Some(host) = extract_host(trimmed) {
            hosts.insert(host);
        }
    }
    Ok(FetchLogSummary {
        line_count,
        byte_count,
        registries: hosts.into_iter().collect(),
    })
}

/// Best-effort host extractor: find `http://` or `https://` and pull
/// the host span up to the next `/`, whitespace, or end-of-line.
fn extract_host(line: &str) -> Option<String> {
    let idx = line
        .find("https://")
        .map(|i| i + "https://".len())
        .or_else(|| line.find("http://").map(|i| i + "http://".len()))?;
    let tail = &line[idx..];
    let end = tail
        .find(|c: char| c == '/' || c.is_whitespace())
        .unwrap_or(tail.len());
    if end == 0 {
        return None;
    }
    Some(tail[..end].to_string())
}

fn summarize_cve(path: &Path) -> Result<CveSummary> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(CveSummary {
                severity_histogram: BTreeMap::new(),
                total_findings: 0,
                top_affected: Vec::new(),
                parse_error: Some(e.to_string()),
            });
        }
    };
    let findings = collect_cve_findings(&value);
    let total_findings = findings.len();
    let mut severity_histogram: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_package: BTreeMap<String, usize> = BTreeMap::new();
    for f in &findings {
        let sev = f
            .severity
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
            .to_lowercase();
        *severity_histogram.entry(sev).or_default() += 1;
        if let Some(pkg) = &f.package {
            *per_package.entry(pkg.clone()).or_default() += 1;
        }
    }
    // Sort packages by count desc, then name asc; take 10.
    let mut packages: Vec<(String, usize)> = per_package.into_iter().collect();
    packages.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_affected = packages.into_iter().map(|(p, _)| p).take(10).collect();
    Ok(CveSummary {
        severity_histogram,
        total_findings,
        top_affected,
        parse_error: None,
    })
}

#[derive(Debug, Clone)]
struct CveFinding {
    package: Option<String>,
    severity: Option<String>,
}

/// Pull a flat list of findings from either the pip-audit shape
/// (`{"dependencies":[{"name":"X","vulns":[{"severity":"HIGH"}, ...]}]}`)
/// or the pnpm-audit shape
/// (`{"advisories":{"123":{"module_name":"X","severity":"high"}}}`).
/// Falls back gracefully when neither matches — the volume still
/// verifies, the inspector just reports `total_findings = 0`.
fn collect_cve_findings(value: &serde_json::Value) -> Vec<CveFinding> {
    let mut out = Vec::new();
    if let Some(deps) = value.get("dependencies").and_then(|v| v.as_array()) {
        for dep in deps {
            let pkg = dep.get("name").and_then(|v| v.as_str()).map(str::to_string);
            let Some(vulns) = dep.get("vulns").and_then(|v| v.as_array()) else {
                continue;
            };
            for vuln in vulns {
                let severity = vuln
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                out.push(CveFinding {
                    package: pkg.clone(),
                    severity,
                });
            }
        }
    }
    if let Some(advisories) = value.get("advisories").and_then(|v| v.as_object()) {
        for advisory in advisories.values() {
            let pkg = advisory
                .get("module_name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let severity = advisory
                .get("severity")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            out.push(CveFinding {
                package: pkg,
                severity,
            });
        }
    }
    if let Some(results) = value.get("results").and_then(|v| v.as_array()) {
        for result in results {
            let pkg = result
                .get("package")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let severity = result
                .get("severity")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            out.push(CveFinding {
                package: pkg,
                severity,
            });
        }
    }
    out
}

fn render_human(report: &InspectReport) {
    println!("deps volume: {}", report.volume_hash);
    println!("  directory:        {}", report.volume_dir.display());
    println!("  schema version:   {}", report.meta.schema_version);
    println!("  created at:       {}", report.meta.created_at);
    println!("  last audit at:    {}", report.meta.last_audit_at);
    println!(
        "  content sha256:   {}",
        short_hash(&report.meta.content_sha256)
    );
    println!(
        "  sbom sha256:      {}",
        short_hash(&report.meta.sbom_sha256)
    );
    println!(
        "  fetch.log sha256: {}",
        short_hash(&report.meta.fetch_log_sha256)
    );
    println!(
        "  cve.json sha256:  {}",
        short_hash(&report.meta.cve_sha256)
    );
    if !report.meta.annotations.is_empty() {
        println!("  annotations:");
        for (k, v) in &report.meta.annotations {
            println!("    {k} = {v}");
        }
    }

    println!();
    println!("sbom ({}):", FILE_SBOM);
    if let Some(err) = &report.sbom.parse_error {
        println!("  (could not parse: {err})");
    } else {
        let header = match (&report.sbom.bom_format, &report.sbom.spec_version) {
            (Some(f), Some(v)) => format!("{f} {v}"),
            (Some(f), None) => f.clone(),
            (None, Some(v)) => v.clone(),
            (None, None) => "(no header)".to_string(),
        };
        println!("  format:           {header}");
        println!("  components:       {}", report.sbom.component_count);
        if !report.sbom.top_components.is_empty() {
            println!("  top 10:");
            for c in &report.sbom.top_components {
                match &c.version {
                    Some(v) => println!("    {} {}", c.name, v),
                    None => println!("    {}", c.name),
                }
            }
        }
    }

    println!();
    println!("fetch.log:");
    println!("  lines:            {}", report.fetch_log.line_count);
    println!("  bytes:            {}", report.fetch_log.byte_count);
    if !report.fetch_log.registries.is_empty() {
        println!("  hosts dialed:");
        for h in &report.fetch_log.registries {
            println!("    {h}");
        }
    }

    println!();
    println!("cve.json:");
    if let Some(err) = &report.cve.parse_error {
        println!("  (could not parse: {err})");
    } else {
        println!("  total findings:   {}", report.cve.total_findings);
        if !report.cve.severity_histogram.is_empty() {
            println!("  by severity:");
            for (sev, count) in &report.cve.severity_histogram {
                println!("    {sev}: {count}");
            }
        }
        if !report.cve.top_affected.is_empty() {
            println!("  top affected:");
            for p in &report.cve.top_affected {
                println!("    {p}");
            }
        }
    }
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
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::tempdir;

    /// Build a fully-sealed volume under `<tmp>/<hash>/` and return
    /// the path + the hash. Mirrors the helper in `deps_audit.rs`'s
    /// own tests so the wire shape is what production seals.
    fn make_sealed_volume(
        cache_root: &Path,
        sbom_body: &str,
        fetch_body: &str,
        cve_body: &str,
        annotations: BTreeMap<String, String>,
    ) -> (PathBuf, String) {
        use mvm_sdk::compile::deps_audit::{
            FILE_CONTENT_DIR, FILE_CVE, FILE_FETCH_LOG, FILE_MANIFEST, FILE_SBOM, seal_volume,
        };
        let work = cache_root.join("scratch");
        let content = work.join(FILE_CONTENT_DIR);
        fs::create_dir_all(&content).unwrap();
        fs::write(content.join("payload.txt"), b"payload\n").unwrap();
        let sbom = work.join(FILE_SBOM);
        fs::write(&sbom, sbom_body).unwrap();
        let fl = work.join(FILE_FETCH_LOG);
        fs::write(&fl, fetch_body).unwrap();
        let cve = work.join(FILE_CVE);
        fs::write(&cve, cve_body).unwrap();
        let sealed = seal_volume(
            &content,
            &sbom,
            &fl,
            &cve,
            "2026-05-14T00:00:00Z",
            annotations,
        )
        .unwrap();
        fs::write(work.join(FILE_MANIFEST), &sealed.manifest_bytes).unwrap();
        let final_dir = cache_root.join(&sealed.volume_hash);
        fs::rename(&work, &final_dir).unwrap();
        (final_dir, sealed.volume_hash)
    }

    #[test]
    fn build_report_reads_meta_sbom_fetch_cve() {
        let tmp = tempdir().unwrap();
        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "requests", "version": "2.31.0"},
                {"name": "urllib3", "version": "2.0.0"},
            ],
        });
        let fetch = "\
GET https://pypi.org/simple/requests/
GET https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz
GET https://pypi.org/simple/urllib3/
";
        let cve = serde_json::json!({
            "dependencies": [
                {"name": "requests", "vulns": [
                    {"id": "CVE-2024-1", "severity": "HIGH"},
                    {"id": "CVE-2024-2", "severity": "LOW"},
                ]},
            ],
        });
        let mut ann = BTreeMap::new();
        ann.insert("language".to_string(), "python".to_string());
        ann.insert("gate".to_string(), "prod".to_string());
        let (_dir, hash) =
            make_sealed_volume(tmp.path(), &sbom.to_string(), fetch, &cve.to_string(), ann);

        let report = build_report(tmp.path(), &hash).unwrap();
        assert_eq!(report.volume_hash, hash);
        assert_eq!(report.meta.schema_version, 1);
        assert_eq!(
            report.meta.annotations.get("language"),
            Some(&"python".to_string()),
        );
        assert_eq!(report.sbom.bom_format.as_deref(), Some("CycloneDX"));
        assert_eq!(report.sbom.component_count, 2);
        assert_eq!(report.fetch_log.line_count, 3);
        // Two unique hosts: pypi.org + files.pythonhosted.org.
        assert!(
            report
                .fetch_log
                .registries
                .contains(&"pypi.org".to_string())
        );
        assert!(
            report
                .fetch_log
                .registries
                .contains(&"files.pythonhosted.org".to_string())
        );
        assert_eq!(report.cve.total_findings, 2);
        assert_eq!(
            report.cve.severity_histogram.get("high").copied(),
            Some(1usize)
        );
        assert_eq!(
            report.cve.severity_histogram.get("low").copied(),
            Some(1usize)
        );
        assert_eq!(report.cve.top_affected, vec!["requests".to_string()],);
    }

    #[test]
    fn build_report_rejects_tampered_volume() {
        let tmp = tempdir().unwrap();
        let (dir, hash) = make_sealed_volume(
            tmp.path(),
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://pypi.org/simple/x/\n",
            r#"{"dependencies":[]}"#,
            BTreeMap::new(),
        );
        // Tamper with the SBOM bytes — hash check must fail.
        fs::write(dir.join(FILE_SBOM), b"{\"bomFormat\":\"FORGED\"}").unwrap();
        let err = build_report(tmp.path(), &hash).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("integrity check") || msg.contains("hash mismatch"),
            "{msg}"
        );
    }

    #[test]
    fn build_report_rejects_missing_volume() {
        let tmp = tempdir().unwrap();
        let err = build_report(
            tmp.path(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no deps volume"), "{msg}");
    }

    #[test]
    fn build_report_handles_pnpm_audit_shape() {
        let tmp = tempdir().unwrap();
        let cve = serde_json::json!({
            "advisories": {
                "123": {"module_name": "lodash", "severity": "critical"},
                "456": {"module_name": "lodash", "severity": "moderate"},
                "789": {"module_name": "minimist", "severity": "high"},
            },
        });
        let (_dir, hash) = make_sealed_volume(
            tmp.path(),
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#,
            "GET https://registry.npmjs.org/lodash\n",
            &cve.to_string(),
            BTreeMap::new(),
        );
        let report = build_report(tmp.path(), &hash).unwrap();
        assert_eq!(report.cve.total_findings, 3);
        assert_eq!(
            report.cve.severity_histogram.get("critical").copied(),
            Some(1usize)
        );
        assert_eq!(
            report.cve.severity_histogram.get("moderate").copied(),
            Some(1usize)
        );
        assert_eq!(
            report.cve.severity_histogram.get("high").copied(),
            Some(1usize)
        );
        // lodash should be first (2 findings vs minimist's 1).
        assert_eq!(report.cve.top_affected[0], "lodash");
    }

    #[test]
    fn build_report_tolerates_unparseable_sbom_and_cve() {
        let tmp = tempdir().unwrap();
        // Both files are non-JSON but the hashes still match what
        // was sealed, so verify_sealed_volume succeeds and inspect
        // surfaces a parse_error rather than crashing.
        let (_dir, hash) = make_sealed_volume(
            tmp.path(),
            "not json at all",
            "GET https://pypi.org/simple/\n",
            "also not json",
            BTreeMap::new(),
        );
        let report = build_report(tmp.path(), &hash).unwrap();
        assert!(report.sbom.parse_error.is_some());
        assert!(report.cve.parse_error.is_some());
        assert_eq!(report.sbom.component_count, 0);
        assert_eq!(report.cve.total_findings, 0);
    }

    #[test]
    fn extract_host_handles_http_and_https() {
        assert_eq!(
            extract_host("GET https://pypi.org/simple/requests/"),
            Some("pypi.org".to_string()),
        );
        assert_eq!(
            extract_host("GET http://example.com/x"),
            Some("example.com".to_string()),
        );
        assert_eq!(extract_host("no url here"), None);
        assert_eq!(
            extract_host("https://registry.npmjs.org"),
            Some("registry.npmjs.org".to_string()),
        );
    }

    #[test]
    fn short_hash_shortens_long_values_but_passes_short_through() {
        assert_eq!(short_hash("abc"), "abc");
        let long = "a".repeat(64);
        let shortened = short_hash(&long);
        assert!(shortened.contains("…"));
        assert!(shortened.len() < long.len());
    }
}
