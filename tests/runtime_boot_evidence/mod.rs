//! Pure evidence storage/comparison; no VM, environment discovery, or runtime calls.
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCOPE: &str = "backend launch / agent-ready only; attribution activation/first-tool not measured; not production attribution evidence";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Options {
    pub report_path: Option<PathBuf>,
    /// Operator-supplied nonsecret host/config identity, not a hostname dump.
    pub host_tag: Option<String>,
    pub source_tag: Option<String>,
    pub kernel_source: Option<String>,
    pub guest_profile: Option<String>,
    pub kernel_config: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integrity {
    pub initramfs: Artifact,
    pub verity: Artifact,
    pub roothash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overlay {
    pub artifact: Artifact,
    pub verity: Artifact,
    pub roothash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub host_os: String,
    pub host_arch: String,
    pub host_tag: Option<String>,
    pub source_tag: Option<String>,
    pub guest_profile: Option<String>,
    pub backend: String,
    pub ready: String,
    pub cpus: u32,
    pub memory_mib: u32,
    pub grant: bool,
    pub runs: usize,
    pub concurrent: usize,
    pub rootfs: Artifact,
    pub rootfs_integrity: Option<Integrity>,
    pub overlay: Option<Overlay>,
    pub ready_timeout_ns: u64,
    pub ready_poll_ns: u64,
}

pub fn artifact(path: &Path) -> Result<Artifact> {
    let mut file = File::open(path).context("open evidence artifact")?;
    let mut digest = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).context("hash evidence artifact")?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        bytes += count as u64;
    }
    Ok(Artifact {
        sha256: hex::encode(digest.finalize()),
        bytes,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    /// Instant elapsed, not a wall-clock timestamp; origin is backend.start.
    pub elapsed_ns: u64,
    pub stop_ns: Option<u64>,
    pub within_budget: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    NotRun,
    Measured,
    MeasurementFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub status: Status,
    pub samples: Vec<Sample>,
}

impl Default for Phase {
    fn default() -> Self {
        Self {
            status: Status::NotRun,
            samples: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: u32,
    pub scope: String,
    /// Explicit allowlist assembled by the harness. Never the raw launch config.
    pub shared_identity: Identity,
    pub kernel: Artifact,
    pub kernel_config: Option<Artifact>,
    pub kernel_source: Option<String>,
    pub budget_ns: u64,
    pub serial: Phase,
    pub concurrent: Phase,
}

/// Reserve the explicit output before any boot. Never overwrite an old report
/// or follow an existing symlink. The caller keeps this same descriptor.
pub fn create(path: &Path) -> Result<File> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("create new evidence report (path must not exist)")?;
    // Hashing or signer setup can fail before any measurement. Never leave an
    // empty file that could be mistaken for a successful evidence capture.
    file.write_all(br#"{"schema":1,"status":"preflight-incomplete","measurements":[]}"#)?;
    file.sync_all().context("reserve boot evidence output")?;
    Ok(file)
}

pub fn persist(file: &mut File, report: &Report) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all().context("persist boot evidence")
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Delta {
    pub phase: &'static str,
    pub p50_ns: i128,
    pub p95_ns: i128,
    pub max_ns: i128,
}

/// Candidate minus baseline. No relative pass/fail policy is applied.
pub fn compare(baseline: &Report, candidate: &Report) -> Result<Vec<Delta>> {
    ensure!(
        baseline.schema == 1
            && candidate.schema == 1
            && baseline.scope == SCOPE
            && candidate.scope == SCOPE,
        "unsupported evidence schema or measurement scope"
    );
    for (key, value) in [
        ("host_tag", &baseline.shared_identity.host_tag),
        ("source_tag", &baseline.shared_identity.source_tag),
        ("guest_profile", &baseline.shared_identity.guest_profile),
    ] {
        ensure!(
            value.as_deref().is_some_and(|s| !s.trim().is_empty()),
            "comparison requires explicit {key}"
        );
    }
    ensure!(
        baseline.shared_identity == candidate.shared_identity
            && baseline.budget_ns == candidate.budget_ns,
        "A/B shared artifacts, host, or benchmark settings differ"
    );
    let mut deltas = Vec::new();
    for (label, a, b) in [
        ("serial", &baseline.serial, &candidate.serial),
        ("concurrent", &baseline.concurrent, &candidate.concurrent),
    ] {
        ensure!(a.status == b.status, "A/B phase coverage differs: {label}");
        if a.status == Status::NotRun {
            ensure!(
                a.samples.is_empty() && b.samples.is_empty(),
                "unrun phase has samples"
            );
            continue;
        }
        ensure!(
            a.status == Status::Measured
                && !a.samples.is_empty()
                && a.samples.len() == b.samples.len(),
            "failed or unmatched measurements: {label}"
        );
        let stats = |phase: &Phase| {
            let mut values: Vec<_> = phase.samples.iter().map(|s| s.elapsed_ns).collect();
            values.sort_unstable();
            let percentile = |pct: usize| values[(values.len() * pct).div_ceil(100) - 1];
            [percentile(50), percentile(95), *values.last().unwrap()]
        };
        let a = stats(a);
        let b = stats(b);
        deltas.push(Delta {
            phase: label,
            p50_ns: i128::from(b[0]) - i128::from(a[0]),
            p95_ns: i128::from(b[1]) - i128::from(a[1]),
            max_ns: i128::from(b[2]) - i128::from(a[2]),
        });
    }
    ensure!(!deltas.is_empty(), "no measured phases to compare");
    Ok(deltas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Report {
        Report {
            schema: 1,
            scope: SCOPE.into(),
            shared_identity: serde_json::from_value(json!({
                "host_os": "linux", "host_arch": "x86_64",
                "host_tag": "fake-host", "source_tag": "fake-runtime",
                "guest_profile": "default-tenant",
                "rootfs": {"sha256": "a".repeat(64), "bytes": 3},
                "rootfs_integrity": null, "overlay": null, "cpus": 1,
                "memory_mib": 256, "backend": "firecracker", "ready": "guest-agent",
                "grant": false, "runs": 1, "concurrent": 1,
                "ready_timeout_ns": 5_000_000_000u64, "ready_poll_ns": 5_000_000
            }))
            .unwrap(),
            kernel: Artifact {
                sha256: "a".repeat(64),
                bytes: 3,
            },
            kernel_config: None,
            kernel_source: Some("fake-kernel".into()),
            budget_ns: 200,
            serial: Phase {
                status: Status::Measured,
                samples: vec![Sample {
                    elapsed_ns: 201,
                    stop_ns: None,
                    within_budget: false,
                }],
            },
            concurrent: Phase::default(),
        }
    }

    #[test]
    fn evidence_roundtrip_retains_failed_budget_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let mut file = create(&path).unwrap();
        let reserved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(reserved["status"], "preflight-incomplete");
        assert!(serde_json::from_value::<Report>(reserved).is_err());
        persist(&mut file, &fixture()).unwrap();
        let report: Report = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(!report.serial.samples[0].within_budget);
        assert!(report.serial.samples[0].stop_ns.is_none());
        assert_eq!(report.concurrent.status, Status::NotRun);
        assert!(create(&path).is_err());
        assert!(create(&dir.path().join("missing/report.json")).is_err());
        let mut failed = report;
        failed.concurrent.status = Status::MeasurementFailed;
        persist(&mut file, &failed).unwrap();
        let restored: Report = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(restored.concurrent.status, Status::MeasurementFailed);
        assert_eq!(restored.serial.samples[0].elapsed_ns, 201);
    }

    #[test]
    #[cfg(unix)]
    fn report_reservation_refuses_existing_and_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        let link = dir.path().join("report.json");
        symlink(&target, &link).unwrap();
        assert!(create(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&target).unwrap();
        symlink(&target, &link).unwrap();
        assert!(create(&link).is_err());
        assert!(!target.exists(), "dangling target was unexpectedly created");
    }

    #[test]
    fn hashing_records_actual_bytes_without_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        std::fs::write(&path, b"abc").unwrap();
        let result = artifact(&path).unwrap();
        assert_eq!(result.bytes, 3);
        assert_eq!(
            result.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(artifact(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn comparison_allows_only_kernel_variation_and_reports_delta_without_threshold() {
        let a = fixture();
        let mut b = a.clone();
        b.kernel.sha256 = "b".repeat(64);
        b.kernel_config = Some(b.kernel.clone());
        b.kernel_source = Some("new-source".into());
        b.serial.samples[0].elapsed_ns = 401;
        assert_eq!(compare(&a, &b).unwrap()[0].max_ns, 200);
        let artifact = serde_json::to_value(&a.kernel).unwrap();
        for (key, value) in [
            ("rootfs", json!({"sha256": "b".repeat(64), "bytes": 4})),
            (
                "rootfs_integrity",
                json!({
                    "initramfs": artifact, "verity": artifact, "roothash": "c".repeat(64)
                }),
            ),
            (
                "overlay",
                json!({
                    "artifact": artifact, "verity": artifact, "roothash": "d".repeat(64)
                }),
            ),
            ("cpus", json!(2)),
            ("memory_mib", json!(512)),
            ("backend", json!("hvf")),
            ("guest_profile", json!("rootless-tenant")),
            ("host_tag", json!("different")),
            ("source_tag", json!("different")),
            ("ready", json!("start-return")),
            ("grant", json!(true)),
            ("runs", json!(2)),
            ("concurrent", json!(2)),
        ] {
            let mut different = b.clone();
            let mut identity = serde_json::to_value(&different.shared_identity).unwrap();
            identity[key] = value;
            different.shared_identity = serde_json::from_value(identity).unwrap();
            assert!(compare(&a, &different).is_err(), "{key}");
        }
        b.concurrent.status = Status::MeasurementFailed;
        assert!(compare(&a, &b).is_err());
        let mut unknown = a.clone();
        unknown.shared_identity.guest_profile = None;
        assert!(compare(&unknown, &unknown).is_err());
    }

    #[test]
    fn comparison_rejects_changed_initramfs_in_an_existing_integrity_set() {
        let mut a = fixture();
        a.shared_identity.rootfs_integrity = Some(Integrity {
            initramfs: a.kernel.clone(),
            verity: a.kernel.clone(),
            roothash: "a".repeat(64),
        });
        let mut b = a.clone();
        b.shared_identity
            .rootfs_integrity
            .as_mut()
            .unwrap()
            .initramfs
            .bytes += 1;
        assert!(compare(&a, &b).is_err());
        let mut malformed = serde_json::to_value(&a).unwrap();
        malformed["shared_identity"]
            .as_object_mut()
            .unwrap()
            .remove("rootfs");
        assert!(serde_json::from_value::<Report>(malformed).is_err());
    }
}
