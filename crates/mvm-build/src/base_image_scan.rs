//! Base-image CVE scan: correlate an [`OsInventory`] against the OSV
//! vulnerability database and render the scan as the same sidecar pair
//! the app-deps lane produces — a `cve.json` report and a CycloneDX SBOM.
//!
//! The app-deps path shells out to ecosystem auditors (`pip-audit`,
//! `pnpm audit`) because what it scans is a language-package install. An
//! OS package inventory is pure data — names, versions, ecosystems — so
//! the base-image scan queries OSV directly over the repo's own HTTP
//! machinery (`mvm_http::blocking`) instead of requiring a scanner binary
//! on the host. `querybatch` answers "which advisory ids match this
//! component" and nothing more, so each matched id is then fetched
//! individually for its severity and fix metadata.
//!
//! Offline behavior is deliberate: a scan error fails a `--prod` pull
//! closed and is a warning with no sidecars on dev. The production
//! admission gate then refuses the image on the missing scan — a scan
//! that could not run is indistinguishable from one that was never run.
//!
//! Severity is best-effort and says so: `database_specific.severity` is
//! used when the record carries it, otherwise a CVSS v3.x vector is
//! scored with the in-tree [`cvss3_base_score`]. Records with neither —
//! most Debian and Alpine OSV entries — report `severity: "unknown"` and
//! are surfaced in the report but never trigger the gate's
//! high/critical refusal.

use std::time::Duration;

use mvm_fs::os_inventory::{OsComponent, OsInventory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema marker on the `cve.json` sidecar. The admission gate refuses a
/// scan file that does not carry it, which is what distinguishes a real
/// base-image scan from the app-deps empty-tool stub shape.
pub const CVE_SCHEMA: &str = "mvm.base-image-cve/v1";

/// The default OSV API base. Package metadata and advisory ids are the
/// only payload — no secrets cross this connection.
const DEFAULT_OSV_BASE_URL: &str = "https://api.osv.dev";

/// `querybatch` request size cap. Base images carry a few hundred
/// packages; the cap keeps a pathological inventory from producing one
/// unbounded request body.
const QUERY_BATCH_SIZE: usize = 1000;

/// The image the scan describes. The digest is the binding the admission
/// gate re-verifies: a sidecar naming a different digest is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageIdentity {
    /// Canonical reference (`registry/repository@sha256:...`).
    pub reference: String,
    /// Resolved manifest digest (`sha256:...`).
    pub digest: String,
}

/// One vulnerability matched against one inventoried component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseImageFinding {
    /// OSV advisory id (`CVE-...`, `GHSA-...`, `DSA-...`, ...).
    pub id: String,
    pub package: String,
    pub ecosystem: String,
    /// Installed version the advisory matched.
    pub version: String,
    /// Lowercase severity token: `critical` / `high` / `medium` / `low` /
    /// `none` / `unknown`.
    pub severity: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    /// First fixed version the record names for this package, when known.
    #[serde(default)]
    pub fixed_version: Option<String>,
}

/// The scan verdict for one image: the full finding list plus the
/// inventory limitations the findings must be read with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseImageScanReport {
    pub schema: String,
    pub image: ImageIdentity,
    pub scanned_at: String,
    pub components_scanned: usize,
    pub findings: Vec<BaseImageFinding>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

impl BaseImageScanReport {
    /// Findings whose severity is `high` or `critical` — the set the
    /// production gate refuses on.
    pub fn high_critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| matches!(finding.severity.as_str(), "high" | "critical"))
            .count()
    }
}

/// Scan failures. Every variant means "no verdict was produced"; callers
/// treat any of them as fail-closed under `--prod`.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("OSV request failed: {0}")]
    Http(String),
    #[error("OSV response was malformed: {0}")]
    MalformedResponse(String),
    #[error("inventory failed: {0}")]
    Inventory(#[from] mvm_fs::os_inventory::InventoryError),
}

/// The OSV seam. Production wires [`BlockingOsvClient`]; tests inject a
/// mock so the full scan pipeline is exercised without a network.
pub trait OsvClient {
    /// For each component, the advisory ids OSV matches to it. The
    /// returned vector is index-aligned with `components`.
    fn query_batch(&self, components: &[OsComponent]) -> Result<Vec<Vec<String>>, ScanError>;
    /// Fetch one full advisory record.
    fn fetch_vulnerability(&self, id: &str) -> Result<OsvVulnerability, ScanError>;
}

/// The fields of an OSV advisory record the scan reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    /// `database_specific.severity` when the record carries it.
    #[serde(default)]
    pub database_severity: Option<String>,
    /// `(type, vector)` pairs from the record's `severity` array
    /// (`CVSS_V3`, `CVSS_V4`, ...).
    #[serde(default)]
    pub severity_vectors: Vec<(String, String)>,
    /// `(package name, fixed version)` pairs mined from the record's
    /// affected ranges — the first `fixed` event per affected package.
    /// The scan picks the entry matching the component it queried.
    #[serde(default)]
    pub fixed_versions: Vec<(String, String)>,
}

/// Raw OSV record shape on the wire.
#[derive(Debug, Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

impl OsvRecord {
    fn into_vulnerability(self) -> OsvVulnerability {
        let fixed_versions = self
            .affected
            .iter()
            .filter_map(|affected| {
                let name = affected.package.as_ref()?.name.clone()?;
                let fixed = affected
                    .ranges
                    .iter()
                    .flat_map(|range| &range.events)
                    .find_map(|event| event.fixed.clone())?;
                Some((name, fixed))
            })
            .collect();
        OsvVulnerability {
            id: self.id,
            aliases: self.aliases,
            summary: self.summary,
            database_severity: self
                .database_specific
                .as_ref()
                .and_then(|value| value.get("severity"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            severity_vectors: self
                .severity
                .into_iter()
                .map(|entry| (entry.kind, entry.score))
                .collect(),
            fixed_versions,
        }
    }
}

/// Production [`OsvClient`] over `mvm_http::blocking`. One blocking
/// client, no runtime of its own; call sites are synchronous pull-path
/// code, matching how the Stage 0 asset fetch uses the same machinery.
pub struct BlockingOsvClient {
    base_url: String,
    timeout: Duration,
}

impl Default for BlockingOsvClient {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_OSV_BASE_URL.to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

impl BlockingOsvClient {
    /// Test seam: point the client at a stub OSV endpoint.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            ..Self::default()
        }
    }

    fn http(&self) -> Result<mvm_http::blocking::Client, ScanError> {
        mvm_http::blocking::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(Duration::from_secs(10))
            .max_response_bytes(4 * 1024 * 1024)
            .build()
            .map_err(|error| ScanError::Http(error.to_string()))
    }
}

/// The querybatch request body for one chunk of components.
#[derive(Serialize)]
struct QueryBatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Serialize)]
struct Query<'a> {
    version: &'a str,
    package: QueryPackage<'a>,
}

#[derive(Serialize)]
struct QueryPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

/// The slice of the querybatch response the scan reads.
#[derive(Deserialize)]
struct QueryBatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<QueryVuln>,
}

#[derive(Deserialize)]
struct QueryVuln {
    id: String,
}

impl OsvClient for BlockingOsvClient {
    fn query_batch(&self, components: &[OsComponent]) -> Result<Vec<Vec<String>>, ScanError> {
        let client = self.http()?;
        let mut all: Vec<Vec<String>> = Vec::with_capacity(components.len());
        for chunk in components.chunks(QUERY_BATCH_SIZE) {
            let request = QueryBatchRequest {
                queries: chunk
                    .iter()
                    .map(|component| Query {
                        version: &component.version,
                        package: QueryPackage {
                            name: &component.name,
                            ecosystem: &component.ecosystem,
                        },
                    })
                    .collect(),
            };
            let body = client
                .post(format!("{}/v1/querybatch", self.base_url))
                .json(&request)
                .send()
                .map_err(|error| ScanError::Http(error.to_string()))?
                .error_for_status()
                .map_err(|error| ScanError::Http(error.to_string()))?
                .bytes()
                .map_err(|error| ScanError::MalformedResponse(error.to_string()))?;
            all.extend(parse_query_batch_response(&body, chunk.len())?);
        }
        Ok(all)
    }

    fn fetch_vulnerability(&self, id: &str) -> Result<OsvVulnerability, ScanError> {
        let client = self.http()?;
        let record: OsvRecord = client
            .get(format!("{}/v1/vulns/{id}", self.base_url))
            .send()
            .map_err(|error| ScanError::Http(error.to_string()))?
            .error_for_status()
            .map_err(|error| ScanError::Http(error.to_string()))?
            .json()
            .map_err(|error| ScanError::MalformedResponse(error.to_string()))?;
        Ok(record.into_vulnerability())
    }
}

/// Parse one querybatch response body into the per-query advisory id
/// lists. Fail-closed on shape: a result count that does not match the
/// query count is a malformed response, not a partial answer — zipping a
/// short result list against the components would silently drop the
/// packages at the tail from the scan.
fn parse_query_batch_response(
    body: &[u8],
    expected_queries: usize,
) -> Result<Vec<Vec<String>>, ScanError> {
    let response: QueryBatchResponse = serde_json::from_slice(body)
        .map_err(|error| ScanError::MalformedResponse(error.to_string()))?;
    if response.results.len() != expected_queries {
        return Err(ScanError::MalformedResponse(format!(
            "querybatch returned {} results for {} queries",
            response.results.len(),
            expected_queries
        )));
    }
    Ok(response
        .results
        .into_iter()
        .map(|result| result.vulns.into_iter().map(|vuln| vuln.id).collect())
        .collect())
}

/// The component list a scan queries: the OS packages plus, when the
/// image carries a kernel, a `Linux`-ecosystem `Kernel` component. OSV
/// resolves kernel versions against its GIT-range records server-side.
fn query_components(inventory: &OsInventory) -> Vec<OsComponent> {
    let mut components = inventory.components.clone();
    if let Some(version) = &inventory.kernel_version {
        components.push(OsComponent {
            ecosystem: "Linux".to_string(),
            name: "Kernel".to_string(),
            version: version.clone(),
            source: "in-image kernel".to_string(),
        });
    }
    components
}

/// The severity token a finding reports: the record's own
/// `database_specific.severity` when present (normalized, `moderate`
/// folded to `medium`), else the NVD band of its CVSS v3.x base score,
/// else `unknown`.
pub fn classify_severity(vulnerability: &OsvVulnerability) -> String {
    if let Some(severity) = &vulnerability.database_severity {
        let normalized = severity.to_ascii_lowercase();
        return match normalized.as_str() {
            "moderate" => "medium".to_string(),
            other => other.to_string(),
        };
    }
    for (kind, vector) in &vulnerability.severity_vectors {
        if kind == "CVSS_V3"
            && let Some(score) = cvss3_base_score(vector)
        {
            return severity_band(score).to_string();
        }
    }
    "unknown".to_string()
}

/// NVD severity bands for a CVSS v3.x base score.
fn severity_band(score: f64) -> &'static str {
    if score <= 0.0 {
        "none"
    } else if score < 4.0 {
        "low"
    } else if score < 7.0 {
        "medium"
    } else if score < 9.0 {
        "high"
    } else {
        "critical"
    }
}

/// Scan one inventoried rootfs against OSV and produce the verdict.
///
/// Deterministic: findings are deduplicated on `(id, package)` and sorted
/// by severity (critical first), then package, then id, so the sidecar
/// bytes are stable for a stable OSV answer set.
pub fn scan_inventory(
    inventory: &OsInventory,
    image: &ImageIdentity,
    client: &dyn OsvClient,
) -> Result<BaseImageScanReport, ScanError> {
    let components = query_components(inventory);
    let matched = client.query_batch(&components)?;
    let mut findings: Vec<BaseImageFinding> = Vec::new();
    for (component, ids) in components.iter().zip(matched.iter()) {
        for id in ids {
            let record = client.fetch_vulnerability(id)?;
            let fixed_version = record
                .fixed_versions
                .iter()
                .find(|(name, _)| *name == component.name)
                .map(|(_, version)| version.clone());
            findings.push(BaseImageFinding {
                severity: classify_severity(&record),
                id: record.id,
                package: component.name.clone(),
                ecosystem: component.ecosystem.clone(),
                version: component.version.clone(),
                aliases: record.aliases,
                summary: record.summary,
                fixed_version,
            });
        }
    }
    findings.sort_by(|left, right| {
        severity_rank(&right.severity)
            .cmp(&severity_rank(&left.severity))
            .then_with(|| left.package.cmp(&right.package))
            .then_with(|| left.id.cmp(&right.id))
    });
    findings.dedup_by(|left, right| left.id == right.id && left.package == right.package);
    Ok(BaseImageScanReport {
        schema: CVE_SCHEMA.to_string(),
        image: image.clone(),
        scanned_at: chrono::Utc::now().to_rfc3339(),
        components_scanned: components.len(),
        findings,
        limitations: inventory.limitations.clone(),
    })
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 5,
        "high" => 4,
        "medium" | "moderate" => 3,
        "low" => 2,
        "none" => 1,
        _ => 0,
    }
}

/// Render the report as the `cve.json` sidecar. The shape always carries
/// companion keys beside `results`, so a real zero-finding scan can never
/// read as the app-deps empty-tool stub (`{"results":[]}` alone).
pub fn render_cve_sidecar(report: &BaseImageScanReport) -> serde_json::Value {
    let high = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "high")
        .count();
    let critical = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count();
    let unknown = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "unknown")
        .count();
    serde_json::json!({
        "schema": report.schema,
        "image": {
            "reference": report.image.reference,
            "digest": report.image.digest,
        },
        "scanned_at": report.scanned_at,
        "results": report.findings,
        "summary": {
            "components_scanned": report.components_scanned,
            "findings": report.findings.len(),
            "high": high,
            "critical": critical,
            "unknown_severity": unknown,
        },
        "limitations": report.limitations,
    })
}

/// Render the inventory as a CycloneDX 1.5 SBOM. The image itself is the
/// `metadata.component` (type `container`) and the distribution — when
/// os-release named one — plus the in-image kernel are `operating-system`
/// components, so even a distroless tree with zero packages yields a
/// non-empty, non-stub SBOM.
pub fn render_sbom_sidecar(
    inventory: &OsInventory,
    image: &ImageIdentity,
    scanned_at: &str,
) -> serde_json::Value {
    let mut components: Vec<serde_json::Value> = Vec::new();
    if let Some(release) = &inventory.distribution {
        components.push(serde_json::json!({
            "type": "operating-system",
            "name": release.id,
            "version": release.version_id,
        }));
    }
    if let Some(version) = &inventory.kernel_version {
        components.push(serde_json::json!({
            "type": "operating-system",
            "name": "linux-kernel",
            "version": version,
        }));
    }
    for component in &inventory.components {
        components.push(serde_json::json!({
            "type": "library",
            "name": component.name,
            "version": component.version,
            "properties": [
                {"name": "mvm:ecosystem", "value": component.ecosystem},
                {"name": "mvm:source", "value": component.source},
            ],
        }));
    }
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": scanned_at,
            "component": {
                "type": "container",
                "name": image.reference,
                "version": image.digest,
            },
        },
        "components": components,
    })
}

/// CVSS v3.x base score for a vector string
/// (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), per the FIRST
/// specification including its roundup rule. `None` when the vector is
/// malformed or missing a required base metric.
pub fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut attack_vector = None;
    let mut attack_complexity = None;
    let mut privileges_required = None;
    let mut user_interaction = None;
    let mut scope_changed = None;
    let mut confidentiality = None;
    let mut integrity = None;
    let mut availability = None;
    for part in vector.split('/') {
        let (metric, value) = part.split_once(':')?;
        match metric {
            "CVSS" => {
                if !(value == "3.0" || value == "3.1") {
                    return None;
                }
            }
            "AV" => {
                attack_vector = Some(metric_value(
                    value,
                    &[('N', 0.85), ('A', 0.62), ('L', 0.55), ('P', 0.2)],
                )?)
            }
            "AC" => attack_complexity = Some(metric_value(value, &[('L', 0.77), ('H', 0.44)])?),
            "PR" => privileges_required = Some(value.to_string()),
            "UI" => user_interaction = Some(metric_value(value, &[('N', 0.85), ('R', 0.62)])?),
            "S" => scope_changed = Some(value == "C"),
            "C" => {
                confidentiality = Some(metric_value(
                    value,
                    &[('N', 0.0), ('L', 0.22), ('H', 0.56)],
                )?)
            }
            "I" => {
                integrity = Some(metric_value(
                    value,
                    &[('N', 0.0), ('L', 0.22), ('H', 0.56)],
                )?)
            }
            "A" => {
                availability = Some(metric_value(
                    value,
                    &[('N', 0.0), ('L', 0.22), ('H', 0.56)],
                )?)
            }
            _ => {}
        }
    }
    let scope_changed = scope_changed?;
    // PR's values depend on scope: unchanged uses (0.85, 0.62, 0.27),
    // changed uses (0.85, 0.68, 0.50).
    let pr_table: &[(&str, f64)] = if scope_changed {
        &[("N", 0.85), ("L", 0.68), ("H", 0.50)]
    } else {
        &[("N", 0.85), ("L", 0.62), ("H", 0.27)]
    };
    let privileges_token = privileges_required?;
    let privileges_required = pr_table
        .iter()
        .find(|(token, _)| *token == privileges_token)
        .map(|(_, value)| *value)?;
    let attack_vector = attack_vector?;
    let attack_complexity = attack_complexity?;
    let user_interaction = user_interaction?;
    let confidentiality = confidentiality?;
    let integrity = integrity?;
    let availability = availability?;

    let iss = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability =
        8.22 * attack_vector * attack_complexity * privileges_required * user_interaction;
    let base = if scope_changed {
        roundup(1.08 * (impact + exploitability)).min(10.0)
    } else {
        roundup(impact + exploitability).min(10.0)
    };
    Some(base)
}

fn metric_value(value: &str, table: &[(char, f64)]) -> Option<f64> {
    let token = value.chars().next()?;
    table
        .iter()
        .find(|(candidate, _)| *candidate == token)
        .map(|(_, score)| *score)
}

/// The FIRST CVSS v3.x Roundup: round to one decimal, rounding up —
/// unless the input is already exact at five decimals, in which case it
/// is returned unchanged.
fn roundup(value: f64) -> f64 {
    let scaled = (value * 100000.0).round() as i64;
    if scaled % 10000 == 0 {
        scaled as f64 / 100000.0
    } else {
        (scaled.div_euclid(10000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_fs::os_inventory::OsRelease;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn component(ecosystem: &str, name: &str, version: &str) -> OsComponent {
        OsComponent {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source: "var/lib/dpkg/status".to_string(),
        }
    }

    fn image() -> ImageIdentity {
        ImageIdentity {
            reference: "docker.io/library/alpine@sha256:aa".to_string(),
            digest: "sha256:aa".to_string(),
        }
    }

    /// Mock OSV: maps package name to advisory ids, and id to record.
    struct MockOsv {
        batch: BTreeMap<String, Vec<String>>,
        records: BTreeMap<String, OsvVulnerability>,
        batches_seen: RefCell<Vec<usize>>,
    }

    impl OsvClient for MockOsv {
        fn query_batch(&self, components: &[OsComponent]) -> Result<Vec<Vec<String>>, ScanError> {
            self.batches_seen.borrow_mut().push(components.len());
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

    fn vuln(id: &str, database_severity: Option<&str>) -> OsvVulnerability {
        OsvVulnerability {
            id: id.to_string(),
            database_severity: database_severity.map(str::to_string),
            ..OsvVulnerability::default()
        }
    }

    fn inventory_with(components: Vec<OsComponent>) -> OsInventory {
        OsInventory {
            distribution: Some(OsRelease {
                id: "debian".to_string(),
                version_id: Some("12".to_string()),
                pretty_name: None,
            }),
            components,
            ..OsInventory::default()
        }
    }

    #[test]
    fn a_clean_inventory_scans_to_zero_findings() {
        let client = MockOsv {
            batch: BTreeMap::new(),
            records: BTreeMap::new(),
            batches_seen: RefCell::new(Vec::new()),
        };
        let report = scan_inventory(
            &inventory_with(vec![component("Debian", "openssl", "3.0.11")]),
            &image(),
            &client,
        )
        .expect("scan");
        assert_eq!(report.schema, CVE_SCHEMA);
        assert!(report.findings.is_empty());
        assert_eq!(report.components_scanned, 1);
        assert_eq!(report.high_critical_count(), 0);
    }

    #[test]
    fn findings_carry_the_classified_severity_and_sort_critical_first() {
        let mut batch = BTreeMap::new();
        batch.insert(
            "openssl".to_string(),
            vec!["CVE-1".to_string(), "CVE-2".to_string()],
        );
        batch.insert("zlib1g".to_string(), vec!["CVE-3".to_string()]);
        let mut records = BTreeMap::new();
        records.insert("CVE-1".to_string(), vuln("CVE-1", Some("LOW")));
        records.insert("CVE-2".to_string(), vuln("CVE-2", Some("CRITICAL")));
        records.insert("CVE-3".to_string(), vuln("CVE-3", Some("HIGH")));
        let client = MockOsv {
            batch,
            records,
            batches_seen: RefCell::new(Vec::new()),
        };
        let report = scan_inventory(
            &inventory_with(vec![
                component("Debian", "openssl", "3.0.11"),
                component("Debian", "zlib1g", "1.2.13"),
            ]),
            &image(),
            &client,
        )
        .expect("scan");
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.findings[0].severity, "critical");
        assert_eq!(report.findings[1].severity, "high");
        assert_eq!(report.findings[2].severity, "low");
        assert_eq!(report.high_critical_count(), 2);
    }

    #[test]
    fn an_in_image_kernel_is_queried_as_a_linux_component() {
        let mut batch = BTreeMap::new();
        batch.insert("Kernel".to_string(), vec!["CVE-2026-80521".to_string()]);
        let mut records = BTreeMap::new();
        records.insert(
            "CVE-2026-80521".to_string(),
            vuln("CVE-2026-80521", Some("HIGH")),
        );
        let client = MockOsv {
            batch,
            records,
            batches_seen: RefCell::new(Vec::new()),
        };
        let inventory = OsInventory {
            kernel_version: Some("6.1.0-21-amd64".to_string()),
            ..inventory_with(vec![component("Debian", "openssl", "3.0.11")])
        };
        let report = scan_inventory(&inventory, &image(), &client).expect("scan");
        assert_eq!(report.components_scanned, 2);
        let kernel = report
            .findings
            .iter()
            .find(|finding| finding.id == "CVE-2026-80521")
            .expect("kernel finding");
        assert_eq!(kernel.package, "Kernel");
        assert_eq!(kernel.ecosystem, "Linux");
        assert_eq!(kernel.version, "6.1.0-21-amd64");
        assert_eq!(kernel.severity, "high");
    }

    #[test]
    fn querybatch_response_parses_per_query_id_lists() {
        let body =
            br#"{"results":[{"vulns":[{"id":"CVE-1","modified":"2026-01-01"}]},{}, {"vulns":[]}]}"#;
        let ids = parse_query_batch_response(body, 3).expect("parses");
        assert_eq!(ids, vec![vec!["CVE-1".to_string()], vec![], vec![]]);
    }

    #[test]
    fn a_querybatch_result_count_mismatch_is_refused_not_truncated() {
        let body = br#"{"results":[{"vulns":[{"id":"CVE-1"}]}]}"#;
        let err = parse_query_batch_response(body, 2).expect_err("short answer must fail");
        assert!(
            matches!(err, ScanError::MalformedResponse(ref reason) if reason.contains("1 results for 2 queries")),
            "{err:?}"
        );
    }

    #[test]
    fn a_malformed_querybatch_body_is_refused() {
        let err = parse_query_batch_response(b"{ not json", 1).expect_err("must fail");
        assert!(matches!(err, ScanError::MalformedResponse(_)));
    }

    #[test]
    fn severity_prefers_database_specific_then_cvss_then_unknown() {
        assert_eq!(classify_severity(&vuln("X", Some("HIGH"))), "high");
        assert_eq!(classify_severity(&vuln("X", Some("Moderate"))), "medium");
        let cvss = OsvVulnerability {
            severity_vectors: vec![(
                "CVSS_V3".to_string(),
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            )],
            ..vuln("X", None)
        };
        assert_eq!(classify_severity(&cvss), "critical");
        assert_eq!(classify_severity(&vuln("X", None)), "unknown");
    }

    #[test]
    fn cvss3_base_scores_match_the_first_spec_examples() {
        // Spec examples from the FIRST CVSS v3.1 specification document.
        let cases: &[(&str, f64)] = &[
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
            ("CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.9),
        ];
        for (vector, expected) in cases {
            let score = cvss3_base_score(vector).expect("vector parses");
            assert!(
                (score - expected).abs() < 1e-9,
                "{vector}: expected {expected}, got {score}"
            );
        }
    }

    #[test]
    fn cvss3_rejects_malformed_vectors() {
        assert_eq!(cvss3_base_score("not a vector"), None);
        assert_eq!(cvss3_base_score("CVSS:2.0/AV:N/AC:L"), None);
        // Missing base metrics (no C/I/A).
        assert_eq!(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U"), None);
    }

    #[test]
    fn cve_sidecar_shape_is_not_the_app_deps_stub_and_binds_the_digest() {
        let report = BaseImageScanReport {
            schema: CVE_SCHEMA.to_string(),
            image: image(),
            scanned_at: "2026-09-24T00:00:00Z".to_string(),
            components_scanned: 1,
            findings: Vec::new(),
            limitations: vec!["rpm gap".to_string()],
        };
        let value = render_cve_sidecar(&report);
        // The app-deps empty stub is exactly {"results":[]} with no
        // companions; a real scan must never collapse to that shape.
        let object = value.as_object().expect("object");
        assert!(object.len() > 1);
        assert_eq!(value["image"]["digest"], "sha256:aa");
        assert_eq!(value["summary"]["findings"], 0);
        assert!(value["results"].as_array().expect("array").is_empty());
    }

    #[test]
    fn sbom_sidecar_enumerates_os_kernel_and_packages() {
        let inventory = OsInventory {
            kernel_version: Some("6.1.0-21-amd64".to_string()),
            ..inventory_with(vec![component("Debian", "openssl", "3.0.11")])
        };
        let value = render_sbom_sidecar(&inventory, &image(), "2026-09-24T00:00:00Z");
        assert_eq!(value["bomFormat"], "CycloneDX");
        assert_eq!(value["specVersion"], "1.5");
        assert_eq!(value["metadata"]["component"]["type"], "container");
        let components = value["components"].as_array().expect("components");
        assert_eq!(components.len(), 3);
        assert_eq!(components[0]["type"], "operating-system");
        assert_eq!(components[0]["name"], "debian");
        assert_eq!(components[1]["name"], "linux-kernel");
        assert_eq!(components[2]["name"], "openssl");
        assert_eq!(
            components[2]["properties"][0]["value"],
            serde_json::json!("Debian")
        );
    }

    #[test]
    fn a_distroless_inventory_still_yields_a_non_stub_sbom() {
        let value = render_sbom_sidecar(&OsInventory::default(), &image(), "2026-09-24T00:00:00Z");
        assert!(value["metadata"]["component"].is_object());
        assert!(
            value["components"]
                .as_array()
                .expect("components")
                .is_empty(),
            "no os-release, no kernel, no packages: only metadata identifies the image"
        );
    }

    #[test]
    fn osv_record_mines_severity_and_package_scoped_fix_versions() {
        let record: OsvRecord = serde_json::from_str(
            r#"{
                "id": "CVE-2026-80521",
                "aliases": ["GHSA-xxxx"],
                "summary": "AF_UNIX SCM_RIGHTS gc UAF",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}],
                "affected": [
                    {"package": {"name": "openssl"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.12"}]}]},
                    {"package": {"name": "zlib1g"}, "ranges": [{"events": [{"introduced": "0"}]}]}
                ]
            }"#,
        )
        .expect("record parses");
        let vulnerability = record.into_vulnerability();
        assert_eq!(vulnerability.id, "CVE-2026-80521");
        assert_eq!(vulnerability.aliases, vec!["GHSA-xxxx".to_string()]);
        assert_eq!(vulnerability.database_severity, None);
        assert_eq!(classify_severity(&vulnerability), "high");
        assert_eq!(
            vulnerability.fixed_versions,
            vec![("openssl".to_string(), "3.0.12".to_string())],
            "a package with no fixed event contributes no entry"
        );
    }

    #[test]
    fn report_types_round_trip_through_serde() {
        let report = BaseImageScanReport {
            schema: CVE_SCHEMA.to_string(),
            image: image(),
            scanned_at: "2026-09-24T00:00:00Z".to_string(),
            components_scanned: 1,
            findings: vec![BaseImageFinding {
                id: "CVE-1".to_string(),
                package: "openssl".to_string(),
                ecosystem: "Debian".to_string(),
                version: "3.0.11".to_string(),
                severity: "high".to_string(),
                aliases: vec!["GHSA-x".to_string()],
                summary: Some("summary".to_string()),
                fixed_version: Some("3.0.12".to_string()),
            }],
            limitations: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let back: BaseImageScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }
}
