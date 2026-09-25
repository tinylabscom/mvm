//! Base-image CVE scan wiring for the OCI image cache.
//!
//! The pull pipeline calls [`scan_and_record_base_image`] once a
//! registry image's layers are unpacked: the unpacked tree is
//! inventoried (`mvm_fs::os_inventory`), correlated against OSV
//! (`mvm_build::base_image_scan`), and the resulting `cve.json` +
//! CycloneDX SBOM pair is written into the image cache under
//! `claims/<manifest-hex>.{cve.json,sbom.cdx.json}`, keyed by the
//! resolved manifest digest. The production admission gate
//! ([`apply_prod_base_image_gate`]) re-reads that pair when a `--prod`
//! run resolves the image and refuses on a missing scan, a foreign or
//! digest-mismatched sidecar, or any high/critical finding.
//!
//! Tier behavior mirrors the app-deps gate: under `--prod` a scan that
//! cannot run (offline host, OSV error) fails the pull closed; under dev
//! it is a warning and the pull proceeds without sidecars. A later
//! `--prod` run of that image then refuses on the missing scan and names
//! the re-pull as the remedy.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mvm_build::app_deps::GateLevel;
use mvm_build::base_image_gate::apply_base_image_gate;
use mvm_build::base_image_scan::{
    BlockingOsvClient, ImageIdentity, OsvClient, render_cve_sidecar, render_sbom_sidecar,
    scan_inventory,
};
use mvm_fs::os_inventory::inventory_rootfs;

use super::cache::{safe_cache_path, sha256_hex, write_cache_file};

/// Cache-relative paths of the base-image sidecar pair for one resolved
/// manifest digest: `(sbom, cve)`.
fn sidecar_rel(digest: &str) -> Result<(String, String)> {
    let hex = sha256_hex(digest)?;
    Ok((
        format!("claims/{hex}.sbom.cdx.json"),
        format!("claims/{hex}.cve.json"),
    ))
}

/// Absolute paths of the sidecar pair under `cache_root`: `(sbom, cve)`.
pub(super) fn sidecar_paths(cache_root: &Path, digest: &str) -> Result<(PathBuf, PathBuf)> {
    let (sbom_rel, cve_rel) = sidecar_rel(digest)?;
    Ok((
        safe_cache_path(cache_root, &sbom_rel)?,
        safe_cache_path(cache_root, &cve_rel)?,
    ))
}

/// Inventory the unpacked rootfs, scan it against OSV, and record the
/// sidecar pair in the image cache. See the module docs for the
/// prod/dev tier behavior.
pub(super) fn scan_and_record_base_image(
    cache_root: &Path,
    reference: &str,
    resolved_digest: &str,
    unpacked_root: &Path,
    prod: bool,
) -> Result<()> {
    // One OSV request per matched advisory, in sequence: an image with a large
    // package set spends real time here, and it used to spend it silently.
    let phase =
        mvm_runtime::ui::activity::start("Scanning the base image for known vulnerabilities");
    let report = |detail: &str| phase.set_detail(detail);
    let osv = BlockingOsvClient::default();
    let client = ReportingOsvClient::new(&osv, &report);
    scan_and_record_base_image_with(
        cache_root,
        reference,
        resolved_digest,
        unpacked_root,
        prod,
        &client,
    )?;
    phase.finish();
    Ok(())
}

/// An [`OsvClient`] that reports how far through the advisory fetches a scan
/// is, and otherwise defers to `inner`.
struct ReportingOsvClient<'a> {
    inner: &'a dyn OsvClient,
    report: &'a dyn Fn(&str),
    total: std::cell::Cell<usize>,
    fetched: std::cell::Cell<usize>,
}

impl<'a> ReportingOsvClient<'a> {
    fn new(inner: &'a dyn OsvClient, report: &'a dyn Fn(&str)) -> Self {
        Self {
            inner,
            report,
            total: std::cell::Cell::new(0),
            fetched: std::cell::Cell::new(0),
        }
    }
}

impl OsvClient for ReportingOsvClient<'_> {
    fn query_batch(
        &self,
        components: &[mvm_fs::os_inventory::OsComponent],
    ) -> Result<Vec<Vec<String>>, mvm_build::base_image_scan::ScanError> {
        (self.report)(&format!("querying OSV for {} packages", components.len()));
        let matched = self.inner.query_batch(components)?;
        self.total.set(matched.iter().map(Vec::len).sum());
        Ok(matched)
    }

    fn fetch_vulnerability(
        &self,
        id: &str,
    ) -> Result<mvm_build::base_image_scan::OsvVulnerability, mvm_build::base_image_scan::ScanError>
    {
        let fetched = self.fetched.get().saturating_add(1);
        self.fetched.set(fetched);
        (self.report)(&format!(
            "fetching advisory {fetched}/{}",
            self.total.get().max(fetched)
        ));
        self.inner.fetch_vulnerability(id)
    }
}

/// Test-visible driver: the [`OsvClient`] is a parameter so tests
/// exercise the full inventory → scan → sidecar pipeline without a
/// network. Production [`scan_and_record_base_image`] wires
/// [`BlockingOsvClient`].
fn scan_and_record_base_image_with(
    cache_root: &Path,
    reference: &str,
    resolved_digest: &str,
    unpacked_root: &Path,
    prod: bool,
    client: &dyn OsvClient,
) -> Result<()> {
    let identity = ImageIdentity {
        reference: reference.to_string(),
        digest: resolved_digest.to_string(),
    };
    let outcome = inventory_rootfs(unpacked_root)
        .map_err(mvm_build::base_image_scan::ScanError::from)
        .and_then(|inventory| {
            let report = scan_inventory(&inventory, &identity, client)?;
            let cve = render_cve_sidecar(&report);
            let sbom = render_sbom_sidecar(&inventory, &identity, &report.scanned_at);
            Ok((report, cve, sbom))
        });
    let (report, cve, sbom) = match outcome {
        Ok(done) => done,
        Err(error) if prod => {
            return Err(error).with_context(|| {
                format!(
                    "base-image CVE scan failed for {reference}; --prod refuses an image it \
                     could not scan"
                )
            });
        }
        Err(error) => {
            tracing::warn!(
                reference = reference,
                error = %error,
                "base-image CVE scan failed; recording no sidecars (a later --prod run will refuse this image)"
            );
            return Ok(());
        }
    };
    let (sbom_rel, cve_rel) = sidecar_rel(resolved_digest)?;
    write_cache_file(
        cache_root,
        &sbom_rel,
        &serde_json::to_vec_pretty(&sbom).context("serialize base-image SBOM")?,
    )?;
    write_cache_file(
        cache_root,
        &cve_rel,
        &serde_json::to_vec_pretty(&cve).context("serialize base-image CVE scan")?,
    )?;
    tracing::info!(
        reference = reference,
        components = report.components_scanned,
        findings = report.findings.len(),
        high_critical = report.high_critical_count(),
        "base-image CVE scan recorded"
    );
    Ok(())
}

/// The production admission gate for a resolved OCI run image: the
/// sidecar pair must exist, be real pull-time scans bound to the
/// image's resolved digest, and carry no high/critical finding. Dev
/// runs warn and continue.
pub(super) fn apply_prod_base_image_gate(
    cache_root: &Path,
    resolved_digest: &str,
    prod: bool,
) -> Result<()> {
    let gate = if prod {
        GateLevel::Prod
    } else {
        GateLevel::Dev
    };
    let (sbom, cve) = sidecar_paths(cache_root, resolved_digest)?;
    apply_base_image_gate(&sbom, &cve, resolved_digest, gate)
        .with_context(|| format!("base-image CVE gate refused image digest {resolved_digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::base_image_scan::{OsvVulnerability, ScanError};
    use mvm_fs::os_inventory::OsComponent;
    use std::collections::BTreeMap;

    struct MockOsv {
        batch: BTreeMap<String, Vec<String>>,
        records: BTreeMap<String, OsvVulnerability>,
    }

    impl OsvClient for MockOsv {
        fn query_batch(&self, components: &[OsComponent]) -> Result<Vec<Vec<String>>, ScanError> {
            Ok(components
                .iter()
                .map(|component| self.batch.get(&component.name).cloned().unwrap_or_default())
                .collect())
        }

        fn fetch_vulnerability(&self, id: &str) -> Result<OsvVulnerability, ScanError> {
            self.records
                .get(id)
                .cloned()
                .ok_or_else(|| ScanError::MalformedResponse(format!("no record for {id}")))
        }
    }

    #[test]
    fn the_reporting_client_counts_advisories_against_the_batch_total() {
        let inner = MockOsv {
            batch: BTreeMap::from([("openssl".to_string(), vec!["A".into(), "B".into()])]),
            records: BTreeMap::from([
                ("A".to_string(), OsvVulnerability::default()),
                ("B".to_string(), OsvVulnerability::default()),
            ]),
        };
        let seen = std::cell::RefCell::new(Vec::new());
        let record = |detail: &str| seen.borrow_mut().push(detail.to_string());
        let client = ReportingOsvClient::new(&inner, &record);
        let component = OsComponent {
            name: "openssl".into(),
            version: "3.0.11".into(),
            ecosystem: "Debian:12".into(),
            source: "var/lib/dpkg/status".into(),
        };

        let matched = client
            .query_batch(std::slice::from_ref(&component))
            .expect("batch");
        for id in &matched[0] {
            client.fetch_vulnerability(id).expect("record");
        }
        assert_eq!(
            *seen.borrow(),
            vec![
                "querying OSV for 1 packages",
                "fetching advisory 1/2",
                "fetching advisory 2/2",
            ]
        );
    }

    fn empty_osv() -> MockOsv {
        MockOsv {
            batch: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn write_unpacked_root(root: &Path) {
        let status = root.join("var/lib/dpkg/status");
        std::fs::create_dir_all(status.parent().expect("parent")).expect("mkdir");
        std::fs::write(&status, "Package: openssl\nVersion: 3.0.11\n\n").expect("write status");
        let os_release = root.join("etc/os-release");
        std::fs::create_dir_all(os_release.parent().expect("parent")).expect("mkdir");
        std::fs::write(&os_release, "ID=debian\nVERSION_ID=\"12\"\n").expect("write os-release");
    }

    #[test]
    fn scan_records_sidecars_keyed_by_digest() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache = tmp.path().join("cache");
        let unpacked = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpacked).expect("mkdir");
        write_unpacked_root(&unpacked);

        scan_and_record_base_image_with(&cache, "img", DIGEST, &unpacked, false, &empty_osv())
            .expect("scan records");

        let (sbom, cve) = sidecar_paths(&cache, DIGEST).expect("paths");
        let sbom: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&sbom).expect("read sbom")).expect("sbom json");
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        let cve: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&cve).expect("read cve")).expect("cve json");
        assert_eq!(cve["schema"], mvm_build::base_image_scan::CVE_SCHEMA);
        assert_eq!(cve["image"]["digest"], DIGEST);
        assert_eq!(cve["summary"]["components_scanned"], 1);
    }

    #[test]
    fn a_failing_scan_is_a_dev_warning_and_a_prod_refusal() {
        struct FailingOsv;
        impl OsvClient for FailingOsv {
            fn query_batch(&self, _: &[OsComponent]) -> Result<Vec<Vec<String>>, ScanError> {
                Err(ScanError::Http("offline".to_string()))
            }
            fn fetch_vulnerability(&self, _: &str) -> Result<OsvVulnerability, ScanError> {
                Err(ScanError::Http("offline".to_string()))
            }
        }
        let tmp = tempfile::tempdir().expect("tmp");
        let cache = tmp.path().join("cache");
        let unpacked = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpacked).expect("mkdir");
        write_unpacked_root(&unpacked);

        scan_and_record_base_image_with(&cache, "img", DIGEST, &unpacked, false, &FailingOsv)
            .expect("dev warns and continues");
        let (_, cve) = sidecar_paths(&cache, DIGEST).expect("paths");
        assert!(!cve.exists(), "a failed scan writes no sidecar");

        let err =
            scan_and_record_base_image_with(&cache, "img", DIGEST, &unpacked, true, &FailingOsv)
                .expect_err("prod refuses an unscannable image");
        assert!(
            format!("{err:#}").contains("refuses an image it could not scan"),
            "{err:#}"
        );
    }

    #[test]
    fn the_gate_admits_a_recorded_clean_scan_and_refuses_a_missing_one() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache = tmp.path().join("cache");
        let unpacked = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpacked).expect("mkdir");
        write_unpacked_root(&unpacked);

        apply_prod_base_image_gate(&cache, DIGEST, true)
            .expect_err("no scan recorded: prod refuses");
        scan_and_record_base_image_with(&cache, "img", DIGEST, &unpacked, false, &empty_osv())
            .expect("scan records");
        apply_prod_base_image_gate(&cache, DIGEST, true).expect("clean scan admits");
    }

    #[test]
    fn the_gate_refuses_a_recorded_high_finding_under_prod_only() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cache = tmp.path().join("cache");
        let unpacked = tmp.path().join("unpacked");
        std::fs::create_dir_all(&unpacked).expect("mkdir");
        write_unpacked_root(&unpacked);
        let mut batch = BTreeMap::new();
        batch.insert("openssl".to_string(), vec!["CVE-1".to_string()]);
        let mut records = BTreeMap::new();
        records.insert(
            "CVE-1".to_string(),
            OsvVulnerability {
                id: "CVE-1".to_string(),
                database_severity: Some("HIGH".to_string()),
                ..OsvVulnerability::default()
            },
        );
        let osv = MockOsv { batch, records };
        scan_and_record_base_image_with(&cache, "img", DIGEST, &unpacked, false, &osv)
            .expect("scan records");

        let err = apply_prod_base_image_gate(&cache, DIGEST, true)
            .expect_err("high finding refuses prod");
        assert!(format!("{err:#}").contains("high"), "{err:#}");
        apply_prod_base_image_gate(&cache, DIGEST, false).expect("dev warns and admits");
    }
}
