//! Build-time gate for the [`crate::app_deps::InstallResult`] artifacts
//! produced by the libkrun builder VM. Inspects the sealed-volume
//! sidecars on disk (`sbom.cdx.json`, `cve.json`)
//! and either:
//!
//! - **`GateLevel::Prod`** — fails closed (typed [`GateError`] variants)
//!   on missing artifacts, the documented "tool not on PATH" stubs, or
//!   any CVE finding whose `severity` parses to `high` / `critical`.
//! - **`GateLevel::Dev`** — every prod-rejection condition becomes a
//!   `tracing::warn!` line; the install still succeeds and the
//!   surrounding `mvmctl up` flow continues to admit the workload.
//!
//! This module is the host-side enforcer. The matching
//! builder-VM-side fallbacks emit:
//!
//! - `SBOM_EMPTY_STUB` =
//!   `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`
//!   when `cyclonedx-py` / `pnpm sbom` is missing.
//! - `CVE_EMPTY_STUB` = `{"results":[]}` when `pip-audit` /
//!   `pnpm audit --json` is missing.
//!
//! Both stubs are deliberately distinguishable from a legitimate
//! "zero findings" install (a real SBOM always has ≥1 component for
//! a non-empty install; a real CVE scan emits at least the tool's
//! schema marker even with no findings). The prod gate rejects both
//! shapes; the dev gate logs and continues. The CI gate sits on top
//! of the prod variant: stub-fallback is acceptable for local `--dev`
//! iteration, never for the release path.
//!
//! ### Why parse with `serde_json::Value`
//!
//! The SBOM + CVE shapes are tool-defined and evolve out of band of
//! mvm releases (`pip-audit` adds fields between minor versions;
//! CycloneDX 1.6 ships during the followup window). A typed struct
//! would force a coordinated cargo bump every time. `serde_json::Value`
//! lets the gate inspect the two fields it actually cares about
//! (`components.len()` on SBOM; `severity` / `aliases` / `name` on
//! every CVE-finding shape) and ignore everything else.

use std::path::Path;
use std::{fs, io};

use mvm_sdk::compile::deps_audit::{FILE_CVE, FILE_SBOM};
use thiserror::Error;

use crate::app_deps::{GateLevel, InstallResult};

/// Typed gate failure surfaced under [`GateLevel::Prod`]. Each variant
/// maps 1:1 to a lifecycle-gate rejection condition; the
/// caller (`mvmctl up`) bubbles these to the user with the underlying
/// path so an operator can debug without reading mvm internals.
#[derive(Debug, Error)]
pub enum GateError {
    /// `sbom.cdx.json` is missing entirely (the install pipeline always
    /// writes one, so this only fires on a manually-tampered volume).
    #[error("SBOM file missing at {path}; prod admission requires a CycloneDX 1.5 SBOM")]
    SbomMissingFile { path: String },

    /// `sbom.cdx.json` is unreadable. Almost always a permissions
    /// issue; surfaced separately so the operator sees the underlying
    /// io::Error.
    #[error("failed to read SBOM at {path}: {source}")]
    SbomReadFailed {
        path: String,
        #[source]
        source: io::Error,
    },

    /// `sbom.cdx.json` parsed as JSON but is the documented empty-stub
    /// shape (`components: []`). Means `cyclonedx-py` / `pnpm sbom`
    /// was missing on the builder-VM PATH at install time — fine for
    /// `--dev`, refused for `--prod`.
    #[error(
        "SBOM at {path} is the empty-tool stub (zero components); the SBOM tool was missing \
         in the builder VM. Acceptable for --dev; --prod requires a real SBOM"
    )]
    MissingSbom { path: String },

    /// `sbom.cdx.json` could not be parsed as JSON.
    #[error("SBOM at {path} could not be parsed as JSON: {source}")]
    SbomParseFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// `cve.json` is missing entirely.
    #[error(
        "CVE scan file missing at {path}; prod admission requires a pip-audit / pnpm-audit result"
    )]
    CveMissingFile { path: String },

    /// `cve.json` is unreadable.
    #[error("failed to read CVE scan at {path}: {source}")]
    CveReadFailed {
        path: String,
        #[source]
        source: io::Error,
    },

    /// `cve.json` is the documented empty-tool stub (`{"results":[]}`).
    /// Means `pip-audit` / `pnpm audit --json` was missing on the
    /// builder-VM PATH — fine for `--dev`, refused for `--prod`.
    #[error(
        "CVE scan at {path} is the empty-tool stub (no scan run); the CVE tool was missing \
         in the builder VM. Acceptable for --dev; --prod requires a real scan"
    )]
    MissingCveScan { path: String },

    /// `cve.json` could not be parsed as JSON.
    #[error("CVE scan at {path} could not be parsed as JSON: {source}")]
    CveParseFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// At least one CVE finding has a `severity` of `high` or
    /// `critical`. The first such finding wins so the operator sees a
    /// concrete name; remaining findings are not enumerated here but
    /// remain available via `mvmctl deps inspect`.
    #[error(
        "CVE scan at {path} reports a {severity} severity finding for {package}; \
         --prod refuses to admit"
    )]
    HighCveFinding {
        path: String,
        package: String,
        severity: String,
    },
}

/// Apply the build-time gate to an [`InstallResult`]. Reads the
/// SBOM + CVE sidecars from `result.volume_dir` and either fails
/// closed (`--prod`) or warns and continues (`--dev`).
///
/// ### Prod-gate rejection order
///
/// 1. SBOM missing / unreadable / unparseable → typed error
///    (`SbomMissingFile`, `SbomReadFailed`, `SbomParseFailed`).
/// 2. SBOM is the empty-tool stub → [`GateError::MissingSbom`].
/// 3. CVE file missing / unreadable / unparseable → typed error.
/// 4. CVE file is the empty-tool stub → [`GateError::MissingCveScan`].
/// 5. CVE file carries a `high` / `critical` finding →
///    [`GateError::HighCveFinding`] (first such finding wins).
///
/// On dev, every step that would fail closed emits a `tracing::warn!`
/// line with the same content; the function returns `Ok(())`.
pub fn apply_install_gate(result: &InstallResult, gate: GateLevel) -> Result<(), GateError> {
    let sbom_path = result.volume_dir.join(FILE_SBOM);
    let cve_path = result.volume_dir.join(FILE_CVE);

    let sbom_outcome = inspect_sbom(&sbom_path);
    let cve_outcome = inspect_cve(&cve_path);

    match gate {
        GateLevel::Prod => {
            apply_outcome_prod(sbom_outcome)?;
            apply_outcome_prod(cve_outcome)?;
            Ok(())
        }
        GateLevel::Dev => {
            warn_outcome_dev(sbom_outcome, "SBOM");
            warn_outcome_dev(cve_outcome, "CVE scan");
            Ok(())
        }
    }
}

/// Internal: enumerate every gate signal a single artifact can carry.
/// Keeping outcomes typed (rather than mapping straight to
/// `Result<(), GateError>`) makes the `--dev` warn-and-continue path
/// trivial: each outcome renders to one warning line.
enum Outcome {
    Ok,
    Fail(GateError),
}

fn apply_outcome_prod(o: Outcome) -> Result<(), GateError> {
    match o {
        Outcome::Ok => Ok(()),
        Outcome::Fail(e) => Err(e),
    }
}

fn warn_outcome_dev(o: Outcome, kind: &str) {
    if let Outcome::Fail(e) = o {
        tracing::warn!(
            kind = kind,
            error = %e,
            "app-deps gate (dev): rejection condition observed; admitting anyway"
        );
    }
}

/// Read + classify the SBOM sidecar.
fn inspect_sbom(path: &Path) -> Outcome {
    let bytes = match read_artifact(path) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Outcome::Fail(GateError::SbomMissingFile {
                path: path.display().to_string(),
            });
        }
        Err(source) => {
            return Outcome::Fail(GateError::SbomReadFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(source) => {
            return Outcome::Fail(GateError::SbomParseFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };

    if sbom_is_empty_stub(&parsed) {
        return Outcome::Fail(GateError::MissingSbom {
            path: path.display().to_string(),
        });
    }

    Outcome::Ok
}

/// Read + classify the CVE-scan sidecar.
fn inspect_cve(path: &Path) -> Outcome {
    let bytes = match read_artifact(path) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Outcome::Fail(GateError::CveMissingFile {
                path: path.display().to_string(),
            });
        }
        Err(source) => {
            return Outcome::Fail(GateError::CveReadFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(source) => {
            return Outcome::Fail(GateError::CveParseFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };

    if cve_is_empty_stub(&parsed) {
        return Outcome::Fail(GateError::MissingCveScan {
            path: path.display().to_string(),
        });
    }

    if let Some((package, severity)) = first_high_or_critical_finding(&parsed) {
        return Outcome::Fail(GateError::HighCveFinding {
            path: path.display().to_string(),
            package,
            severity,
        });
    }

    Outcome::Ok
}

/// Read a sidecar path, distinguishing "missing" (Ok(None)) from
/// "unreadable" (Err) so the caller can fork the typed error.
fn read_artifact(path: &Path) -> Result<Option<Vec<u8>>, io::Error> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Recognize the builder-VM-emitted empty SBOM stub. The fingerprint
/// the prod gate rejects: CycloneDX shape with zero components. Real
/// installs always emit ≥1 component, so this is a stable signal
/// that `cyclonedx-py` / `pnpm sbom` wasn't on the builder VM PATH.
fn sbom_is_empty_stub(value: &serde_json::Value) -> bool {
    let bom_format = value.get("bomFormat").and_then(|v| v.as_str());
    let components = value.get("components").and_then(|v| v.as_array());
    matches!(bom_format, Some("CycloneDX")) && components.map(|c| c.is_empty()).unwrap_or(false)
}

/// Recognize the builder-VM-emitted empty CVE stub:
/// `{"results":[]}`. Real `pip-audit` runs always emit additional
/// schema markers (`dependencies`, `summary`); `pnpm audit --json`
/// always emits a `metadata` object. An empty `results` array with
/// no companions is the stub signature.
fn cve_is_empty_stub(value: &serde_json::Value) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    let Some(results) = obj.get("results").and_then(|v| v.as_array()) else {
        return false;
    };
    if !results.is_empty() {
        return false;
    }
    // Real-tool output always carries at least one companion key.
    // The stub literally has `{"results":[]}` and nothing else.
    obj.len() == 1
}

/// Walk the CVE-scan JSON for the first `high` / `critical` finding.
///
/// Tolerant of both `pip-audit` and `pnpm audit` shapes:
///
/// - `pip-audit`: top-level `{"dependencies":[{"name":"...","vulns":[
///   {"id":"...","aliases":[...]} ]}], ...}` — severity carried per-vuln
///   under `severity` (sometimes `fix_versions[].severity`).
/// - `pnpm audit --json`: top-level
///   `{"advisories":{"ID":{"module_name":"...","severity":"high",...}}}`.
///
/// Rather than encode each tool's shape, this walks every nested
/// object/array and inspects any node that carries a `severity` field.
/// If the severity parses to `high` / `critical`, return its closest
/// "name-like" sibling (`package`, `name`, `module_name`, `package_name`,
/// or "unknown"). First hit wins.
fn first_high_or_critical_finding(value: &serde_json::Value) -> Option<(String, String)> {
    fn walk(node: &serde_json::Value, current_name: Option<String>) -> Option<(String, String)> {
        match node {
            serde_json::Value::Object(map) => {
                // Prefer the local node's name field, fall back to the
                // parent's. `pnpm audit` keys advisories by ID so the
                // name lives on the node itself.
                let local_name = name_from_object(map);
                let effective_name = local_name.clone().or(current_name.clone());
                if let Some(sev) = map.get("severity").and_then(|v| v.as_str()) {
                    let normalized = sev.to_ascii_lowercase();
                    if matches!(normalized.as_str(), "high" | "critical") {
                        let pkg = effective_name
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string());
                        return Some((pkg, normalized));
                    }
                }
                for (k, v) in map {
                    // `pnpm audit` keyed by advisory ID; inject the key
                    // as a context name when no explicit name field is
                    // present on the child.
                    let pass_name = local_name.clone().or_else(|| {
                        if k == "advisories" || k == "vulnerabilities" {
                            None
                        } else {
                            Some(k.clone())
                        }
                    });
                    if let Some(hit) = walk(v, pass_name) {
                        return Some(hit);
                    }
                }
                None
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    if let Some(hit) = walk(item, current_name.clone()) {
                        return Some(hit);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn name_from_object(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
        for key in ["package", "package_name", "module_name", "name"] {
            if let Some(s) = map.get(key).and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
        }
        None
    }

    walk(value, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_deps::InstallResult;
    use std::path::Path;
    use tempfile::TempDir;

    /// Build a fake [`InstallResult`] backed by a fresh tempdir.
    /// Returns the dir guard alongside so the caller can drop it
    /// after the assertion runs.
    fn fixture() -> (TempDir, InstallResult) {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().to_path_buf();
        let result = InstallResult {
            volume_hash: "a".repeat(64),
            manifest_sha256: "b".repeat(64),
            cache_hit: false,
            volume_dir: dir,
            lockfile_sha256: "c".repeat(64),
        };
        (tmp, result)
    }

    fn write_artifact(volume_dir: &Path, name: &str, body: &[u8]) {
        std::fs::write(volume_dir.join(name), body).unwrap();
    }

    const REAL_SBOM: &str = r#"{
        "bomFormat":"CycloneDX","specVersion":"1.5",
        "components":[{"type":"library","name":"requests","version":"2.31.0"}]
    }"#;

    const REAL_CVE_NO_FINDINGS: &str = r#"{
        "results":[],
        "dependencies":[],
        "summary":{"fixed":0,"vulnerable":0,"skipped":0}
    }"#;

    const REAL_CVE_HIGH: &str = r#"{
        "dependencies":[
            {"name":"flask","vulns":[
                {"id":"PYSEC-2023-1","severity":"high","aliases":["CVE-2023-30861"]}
            ]}
        ]
    }"#;

    const REAL_CVE_CRITICAL_PNPM: &str = r#"{
        "advisories":{
            "1234":{"module_name":"lodash","severity":"critical","title":"prototype poll"}
        },
        "metadata":{"vulnerabilities":{"critical":1}}
    }"#;

    const STUB_SBOM: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
    const STUB_CVE: &str = r#"{"results":[]}"#;

    #[test]
    fn prod_passes_with_real_sbom_and_clean_cve() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_NO_FINDINGS.as_bytes());
        apply_install_gate(&r, GateLevel::Prod).expect("clean run passes prod");
    }

    #[test]
    fn prod_rejects_stub_sbom_as_missing_sbom() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, STUB_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_NO_FINDINGS.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(matches!(err, GateError::MissingSbom { .. }), "got {err:?}");
    }

    #[test]
    fn prod_rejects_stub_cve_as_missing_cve_scan() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, STUB_CVE.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(
            matches!(err, GateError::MissingCveScan { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_rejects_high_cve_finding_pip_audit_shape() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_HIGH.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        match err {
            GateError::HighCveFinding {
                package, severity, ..
            } => {
                assert_eq!(package, "flask");
                assert_eq!(severity, "high");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn prod_rejects_critical_cve_finding_pnpm_shape() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_CRITICAL_PNPM.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        match err {
            GateError::HighCveFinding {
                package, severity, ..
            } => {
                assert_eq!(package, "lodash");
                assert_eq!(severity, "critical");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn prod_rejects_missing_sbom_file() {
        let (_g, r) = fixture();
        // Only CVE — no SBOM file at all.
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_NO_FINDINGS.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(
            matches!(err, GateError::SbomMissingFile { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_rejects_missing_cve_file() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(
            matches!(err, GateError::CveMissingFile { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_rejects_malformed_sbom_json() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, b"{ not json }");
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_NO_FINDINGS.as_bytes());
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(
            matches!(err, GateError::SbomParseFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_rejects_malformed_cve_json() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, b"{ not json }");
        let err = apply_install_gate(&r, GateLevel::Prod).expect_err("must fail");
        assert!(
            matches!(err, GateError::CveParseFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn dev_warns_and_continues_on_every_prod_rejection() {
        // Both sidecars are stubs + the cve stub has no high findings
        // (it can't — it's empty). On --dev the function returns Ok
        // and the operator sees warnings instead.
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, STUB_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, STUB_CVE.as_bytes());
        apply_install_gate(&r, GateLevel::Dev).expect("dev never errors");
    }

    #[test]
    fn dev_with_high_cve_finding_warns_and_continues() {
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_HIGH.as_bytes());
        apply_install_gate(&r, GateLevel::Dev).expect("dev never errors");
    }

    #[test]
    fn medium_and_low_severity_pass_prod() {
        // Only high / critical fail closed; "medium" and "low" are
        // tolerated.
        let cve = r#"{
            "dependencies":[
                {"name":"foo","vulns":[
                    {"id":"X","severity":"medium"},
                    {"id":"Y","severity":"low"}
                ]}
            ]
        }"#;
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, cve.as_bytes());
        apply_install_gate(&r, GateLevel::Prod).expect("medium/low passes prod");
    }

    #[test]
    fn empty_results_with_companion_keys_is_not_a_stub() {
        // A real `pip-audit` run with zero findings ships the
        // `dependencies` + `summary` companions; not the stub shape.
        let (_g, r) = fixture();
        write_artifact(&r.volume_dir, FILE_SBOM, REAL_SBOM.as_bytes());
        write_artifact(&r.volume_dir, FILE_CVE, REAL_CVE_NO_FINDINGS.as_bytes());
        apply_install_gate(&r, GateLevel::Prod).expect("real clean scan passes prod");
    }
}
