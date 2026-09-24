//! Production admission gate for the base-image CVE scan.
//!
//! The sibling of [`crate::app_deps_gate`] for the OCI base image: where
//! the app-deps gate reads sidecars from a sealed deps volume, this gate
//! reads the `cve.json` / SBOM sidecar pair the pull pipeline
//! (`mvm-build`'s [`crate::base_image_scan`], wired into the CLI's image
//! pull) wrote into the OCI cache, keyed by the image's resolved manifest
//! digest.
//!
//! - **`GateLevel::Prod`** fails closed on: missing or unreadable
//!   sidecars (a scan that never ran is indistinguishable from one that
//!   was deleted), a `cve.json` that is not a real scan (wrong or absent
//!   schema marker), a sidecar bound to a different image digest (a
//!   copied-over file is not a scan of this image), and any finding whose
//!   `severity` is `high` / `critical`.
//! - **`GateLevel::Dev`** turns every rejection into a `tracing::warn!`
//!   line and admits, matching how the app-deps gate treats tiers.
//!
//! The digest binding is the integrity check: the sidecars live in a
//! cache the host controls, so the gate cannot prove they were produced
//! by an honest scan — only that the scan that was recorded names the
//! exact image digest being admitted, was produced by this code (schema
//! marker), and reported no high/critical findings. A host-insider
//! forgery of the sidecar is out of scope here; the image bytes
//! themselves remain digest-pinned and dm-verity sealed.

use std::path::Path;
use std::{fs, io};

use thiserror::Error;

use crate::app_deps::GateLevel;
use crate::app_deps_gate::first_high_or_critical_finding;
use crate::base_image_scan::CVE_SCHEMA;

/// Typed gate failure surfaced under [`GateLevel::Prod`]. Each variant
/// maps 1:1 to a rejection condition; the caller bubbles these to the
/// user with the underlying path so an operator can debug without
/// reading mvm internals.
#[derive(Debug, Error)]
pub enum BaseImageGateError {
    /// `sbom.cdx.json` is missing entirely.
    #[error(
        "base-image SBOM missing at {path}; prod admission requires the pull-time CycloneDX SBOM"
    )]
    SbomMissing { path: String },

    /// `sbom.cdx.json` is unreadable.
    #[error("failed to read base-image SBOM at {path}: {source}")]
    SbomUnreadable {
        path: String,
        #[source]
        source: io::Error,
    },

    /// `sbom.cdx.json` could not be parsed as JSON.
    #[error("base-image SBOM at {path} could not be parsed as JSON: {source}")]
    SbomParseFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// `sbom.cdx.json` is not a CycloneDX document with a metadata
    /// component — the shape the pull-time scan always emits.
    #[error(
        "base-image SBOM at {path} is not a CycloneDX document with a metadata component; \
         it was not produced by the pull-time inventory"
    )]
    SbomNotCycloneDx { path: String },

    /// `cve.json` is missing entirely.
    #[error(
        "base-image CVE scan missing at {path}; prod admission requires the pull-time OSV scan. \
         Re-pull the image (`mvmctl image pull`) to run one"
    )]
    ScanMissing { path: String },

    /// `cve.json` is unreadable.
    #[error("failed to read base-image CVE scan at {path}: {source}")]
    ScanUnreadable {
        path: String,
        #[source]
        source: io::Error,
    },

    /// `cve.json` could not be parsed as JSON.
    #[error("base-image CVE scan at {path} could not be parsed as JSON: {source}")]
    ScanParseFailed {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    /// `cve.json` does not carry the base-image scan schema marker, so
    /// it is not a scan this pipeline produced (an app-deps volume
    /// sidecar, a hand-written file, or a stub).
    #[error(
        "base-image CVE scan at {path} does not carry the base-image scan schema marker \
         (found {found}); it was not produced by the pull-time scan"
    )]
    ScanSchemaMismatch { path: String, found: String },

    /// The scan names a different image digest than the one being
    /// admitted — a sidecar copied across images or left behind by a
    /// stale cache entry is not evidence about this image.
    #[error(
        "base-image CVE scan at {path} is bound to image digest {recorded} but the admitted \
         image resolves to {expected}"
    )]
    ScanDigestMismatch {
        path: String,
        expected: String,
        recorded: String,
    },

    /// At least one finding has a `severity` of `high` or `critical`.
    /// The first such finding wins so the operator sees a concrete
    /// package; the full list is in the sidecar itself.
    #[error(
        "base-image CVE scan at {path} reports a {severity} severity finding for {package}; \
         --prod refuses to admit"
    )]
    HighCriticalFinding {
        path: String,
        package: String,
        severity: String,
    },
}

/// Apply the base-image gate to the sidecar pair at `sbom_path` /
/// `cve_path`, which must describe the image digest `expected_digest`.
///
/// ### Prod-gate rejection order
///
/// 1. SBOM missing / unreadable / unparseable / not the pull-time
///    CycloneDX shape.
/// 2. Scan missing / unreadable / unparseable / wrong schema.
/// 3. Scan bound to a different image digest.
/// 4. Scan carries a `high` / `critical` finding.
///
/// On dev, every step that would fail closed emits a `tracing::warn!`
/// line with the same content; the function returns `Ok(())`.
pub fn apply_base_image_gate(
    sbom_path: &Path,
    cve_path: &Path,
    expected_digest: &str,
    gate: GateLevel,
) -> Result<(), BaseImageGateError> {
    let sbom_outcome = inspect_sbom(sbom_path);
    let scan_outcome = inspect_scan(cve_path, expected_digest);

    match gate {
        GateLevel::Prod => {
            apply_outcome_prod(sbom_outcome)?;
            apply_outcome_prod(scan_outcome)?;
            Ok(())
        }
        GateLevel::Dev => {
            warn_outcome_dev(sbom_outcome, "base-image SBOM");
            warn_outcome_dev(scan_outcome, "base-image CVE scan");
            Ok(())
        }
    }
}

/// Internal: every gate signal one artifact can carry, typed so the dev
/// path can render each as one warning line — the same shape the
/// app-deps gate uses.
enum Outcome {
    Ok,
    Fail(BaseImageGateError),
}

fn apply_outcome_prod(outcome: Outcome) -> Result<(), BaseImageGateError> {
    match outcome {
        Outcome::Ok => Ok(()),
        Outcome::Fail(error) => Err(error),
    }
}

/// Warn that the dev gate is admitting something the prod gate would
/// reject. Returns whether it warned, so "dev admits, but says so" is
/// assertable without a tracing subscriber harness.
fn warn_outcome_dev(outcome: Outcome, kind: &str) -> bool {
    if let Outcome::Fail(error) = outcome {
        tracing::warn!(
            kind = kind,
            error = %error,
            "base-image gate (dev): rejection condition observed; admitting anyway"
        );
        return true;
    }
    false
}

fn inspect_sbom(path: &Path) -> Outcome {
    let bytes = match read_artifact(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Outcome::Fail(BaseImageGateError::SbomMissing {
                path: path.display().to_string(),
            });
        }
        Err(source) => {
            return Outcome::Fail(BaseImageGateError::SbomUnreadable {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(source) => {
            return Outcome::Fail(BaseImageGateError::SbomParseFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };
    // The pull-time SBOM always carries `bomFormat: CycloneDX` and a
    // `metadata.component` naming the image — even for a distroless tree
    // with zero packages — so the pair distinguishes a real inventory
    // from an empty-tool stub.
    let is_cyclonedx = parsed.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX");
    let has_metadata_component = parsed
        .get("metadata")
        .and_then(|metadata| metadata.get("component"))
        .is_some_and(serde_json::Value::is_object);
    if !(is_cyclonedx && has_metadata_component) {
        return Outcome::Fail(BaseImageGateError::SbomNotCycloneDx {
            path: path.display().to_string(),
        });
    }
    Outcome::Ok
}

fn inspect_scan(path: &Path, expected_digest: &str) -> Outcome {
    let bytes = match read_artifact(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Outcome::Fail(BaseImageGateError::ScanMissing {
                path: path.display().to_string(),
            });
        }
        Err(source) => {
            return Outcome::Fail(BaseImageGateError::ScanUnreadable {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(source) => {
            return Outcome::Fail(BaseImageGateError::ScanParseFailed {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let found_schema = parsed
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("<absent>");
    if found_schema != CVE_SCHEMA {
        return Outcome::Fail(BaseImageGateError::ScanSchemaMismatch {
            path: path.display().to_string(),
            found: found_schema.to_string(),
        });
    }
    let recorded = parsed
        .get("image")
        .and_then(|image| image.get("digest"))
        .and_then(|digest| digest.as_str())
        .unwrap_or("<absent>");
    if recorded != expected_digest {
        return Outcome::Fail(BaseImageGateError::ScanDigestMismatch {
            path: path.display().to_string(),
            expected: expected_digest.to_string(),
            recorded: recorded.to_string(),
        });
    }
    if let Some((package, severity)) = first_high_or_critical_finding(&parsed) {
        return Outcome::Fail(BaseImageGateError::HighCriticalFinding {
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
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn real_sbom() -> String {
        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"component": {"type": "container", "name": "img", "version": DIGEST}},
            "components": [
                {"type": "operating-system", "name": "debian", "version": "12"},
                {"type": "library", "name": "openssl", "version": "3.0.11"},
            ],
        })
        .to_string()
    }

    fn real_scan(findings: serde_json::Value) -> String {
        serde_json::json!({
            "schema": CVE_SCHEMA,
            "image": {"reference": "img", "digest": DIGEST},
            "scanned_at": "2026-09-24T00:00:00Z",
            "results": findings,
            "summary": {"components_scanned": 1, "findings": 0},
            "limitations": [],
        })
        .to_string()
    }

    fn high_scan() -> String {
        real_scan(serde_json::json!([
            {
                "id": "CVE-2026-80521",
                "package": "linux-kernel",
                "ecosystem": "Linux",
                "version": "6.1.0-21-amd64",
                "severity": "critical",
            }
        ]))
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        sbom: std::path::PathBuf,
        cve: std::path::PathBuf,
    }

    fn fixture(sbom: Option<&str>, cve: Option<&str>) -> Fixture {
        let tmp = tempfile::tempdir().expect("tmp");
        let sbom_path = tmp.path().join("sbom.cdx.json");
        let cve_path = tmp.path().join("cve.json");
        if let Some(body) = sbom {
            fs::write(&sbom_path, body).expect("write sbom");
        }
        if let Some(body) = cve {
            fs::write(&cve_path, body).expect("write cve");
        }
        Fixture {
            _tmp: tmp,
            sbom: sbom_path,
            cve: cve_path,
        }
    }

    #[test]
    fn prod_admits_a_clean_scan() {
        let fixture = fixture(Some(&real_sbom()), Some(&real_scan(serde_json::json!([]))));
        apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect("clean scan passes prod");
    }

    #[test]
    fn prod_refuses_a_missing_scan() {
        let fixture = fixture(Some(&real_sbom()), None);
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("missing scan must fail");
        assert!(
            matches!(err, BaseImageGateError::ScanMissing { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_refuses_a_missing_sbom() {
        let fixture = fixture(None, Some(&real_scan(serde_json::json!([]))));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("missing SBOM must fail");
        assert!(
            matches!(err, BaseImageGateError::SbomMissing { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_refuses_a_high_severity_finding() {
        let fixture = fixture(Some(&real_sbom()), Some(&high_scan()));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("high finding must fail");
        match err {
            BaseImageGateError::HighCriticalFinding {
                package, severity, ..
            } => {
                assert_eq!(package, "linux-kernel");
                assert_eq!(severity, "critical");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn prod_admits_medium_and_low_findings() {
        let scan = real_scan(serde_json::json!([
            {"id": "CVE-1", "package": "openssl", "severity": "medium"},
            {"id": "CVE-2", "package": "zlib", "severity": "low"},
            {"id": "CVE-3", "package": "musl", "severity": "unknown"},
        ]));
        let fixture = fixture(Some(&real_sbom()), Some(&scan));
        apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect("medium/low/unknown pass prod");
    }

    #[test]
    fn prod_refuses_a_scan_bound_to_a_different_digest() {
        let scan = real_scan(serde_json::json!([])).replace(
            DIGEST,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let fixture = fixture(Some(&real_sbom()), Some(&scan));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("digest mismatch must fail");
        assert!(
            matches!(err, BaseImageGateError::ScanDigestMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_refuses_a_scan_without_the_schema_marker() {
        // The app-deps pip-audit shape is a real scan of something else;
        // it is not a base-image scan.
        let app_deps_shape = r#"{"dependencies":[],"summary":{"fixed":0}}"#;
        let fixture = fixture(Some(&real_sbom()), Some(app_deps_shape));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("foreign scan shape must fail");
        match err {
            BaseImageGateError::ScanSchemaMismatch { found, .. } => {
                assert_eq!(found, "<absent>");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn prod_refuses_malformed_sidecar_json() {
        let fixture = fixture(Some("{ not json"), Some(&real_scan(serde_json::json!([]))));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("malformed SBOM must fail");
        assert!(
            matches!(err, BaseImageGateError::SbomParseFailed { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prod_refuses_an_empty_stub_sbom() {
        // The app-deps empty-tool stub shape: CycloneDX with zero
        // components and no metadata. Not a pull-time inventory.
        let stub = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
        let fixture = fixture(Some(stub), Some(&real_scan(serde_json::json!([]))));
        let err = apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Prod)
            .expect_err("stub SBOM must fail");
        assert!(
            matches!(err, BaseImageGateError::SbomNotCycloneDx { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn dev_warns_and_admits_every_prod_rejection() {
        let fixture = fixture(Some("{ not json"), Some(&high_scan()));
        apply_base_image_gate(&fixture.sbom, &fixture.cve, DIGEST, GateLevel::Dev)
            .expect("dev never errors");
    }

    #[test]
    fn the_dev_gate_warns_exactly_when_it_admits_a_rejection() {
        assert!(warn_outcome_dev(
            Outcome::Fail(BaseImageGateError::ScanMissing {
                path: "/nonexistent/cve.json".to_string(),
            }),
            "base-image CVE scan"
        ));
        assert!(!warn_outcome_dev(Outcome::Ok, "base-image CVE scan"));
    }

    /// A sidecar that exists but cannot be read is not a sidecar that is
    /// absent; the two fork different typed errors.
    #[test]
    fn read_artifact_separates_absent_from_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("not-there.json");
        assert!(matches!(read_artifact(&absent), Ok(None)));
        let unreadable = tmp.path().join("cve.json");
        std::fs::create_dir_all(&unreadable).unwrap();
        assert!(read_artifact(&unreadable).is_err());
    }
}
