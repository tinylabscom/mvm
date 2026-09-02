//! Identity of the guest runtime injected into a rootfs.
//!
//! The rootfs cache is keyed on *which runtime is baked into it*. Deriving that
//! key from the bytes of the artifacts that actually get injected is the only
//! way the key cannot drift from the thing it names — a fingerprint over a
//! subset of the sources structurally cannot see `/init`, the egress shim or
//! the verity initramfs, and every gap there has to be closed by hand.
//!
//! The constraint that shapes this module is cost, not correctness:
//! [`crate::run_image::resolve_guest_binaries`] *builds* the artifacts on a
//! cold cache, and the identity is consulted on the cache-hit gate, before
//! anything has decided a build is needed. Reading 5 MiB of artifacts on every
//! invocation would be acceptable; cross-compiling them would not.
//!
//! So the identity is recorded in a sidecar beside the artifacts when they are
//! resolved, and the hot path reads the sidecar plus one `stat` per artifact.
//! The sidecar is a cache, never an authority: it carries each artifact's
//! length and mtime and is discarded the moment one of them disagrees.

use std::io;
use std::path::{Path, PathBuf};

use crate::oci_runtime_inject::MvmRuntimeBinaries;

/// Sidecar file name, written into the directory holding the artifacts.
pub const SIDECAR_NAME: &str = "runtime-id";

/// What the sidecar records about one artifact, so a stale digest can be
/// detected without re-reading the bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactStamp {
    name: String,
    len: u64,
    /// Nanoseconds since the Unix epoch. `None` when the platform declined to
    /// report a modification time, which downgrades this entry to a
    /// length-only check rather than failing the read.
    #[serde(default)]
    mtime_ns: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Sidecar {
    digest: String,
    artifacts: Vec<ArtifactStamp>,
}

fn stamp(name: &str, path: &Path) -> Result<ArtifactStamp, io::Error> {
    let meta = std::fs::metadata(path)?;
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());
    Ok(ArtifactStamp {
        name: name.to_string(),
        len: meta.len(),
        mtime_ns,
    })
}

fn stamps(bins: &MvmRuntimeBinaries) -> Result<Vec<ArtifactStamp>, io::Error> {
    bins.artifacts()
        .into_iter()
        .map(|(name, path)| stamp(name, path))
        .collect()
}

fn sidecar_path(dir: &Path) -> PathBuf {
    dir.join(SIDECAR_NAME)
}

/// The runtime identity for `bins`, using the sidecar in `dir` when it is
/// still valid.
///
/// Reads the artifacts' bytes only when the sidecar is absent, unparsable, or
/// contradicted by a `stat`. Writing the refreshed sidecar is best-effort: a
/// read-only or racing cache costs a recomputation next time, not a failure.
pub fn identity_with_sidecar(bins: &MvmRuntimeBinaries, dir: &Path) -> Result<String, io::Error> {
    let current = stamps(bins)?;

    if let Some(cached) = read_sidecar(&sidecar_path(dir))
        && cached.artifacts == current
    {
        return Ok(cached.digest);
    }

    let digest = bins.content_digest()?;
    let _ = write_sidecar(
        &sidecar_path(dir),
        &Sidecar {
            digest: digest.clone(),
            artifacts: current,
        },
    );
    Ok(digest)
}

fn read_sidecar(path: &Path) -> Option<Sidecar> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_sidecar(path: &Path, sidecar: &Sidecar) -> Result<(), io::Error> {
    let bytes = serde_json::to_vec(sidecar).map_err(io::Error::other)?;
    mvm_core::util::atomic_io::atomic_write(path, &bytes).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins_in(dir: &Path) -> MvmRuntimeBinaries {
        let mk = |name: &str, content: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, content).unwrap();
            p
        };
        MvmRuntimeBinaries {
            agent: mk("mvm-guest-agent", b"agent-bytes"),
            netinit: mk("mvm-guest-netinit", b"netinit-bytes"),
            egress_client: mk("mvm-egress-client", b"egress-bytes"),
            entrypoint_runner: mk("mvm-oci-entrypoint", b"entrypoint-bytes"),
        }
    }

    #[test]
    fn first_call_computes_and_records_the_digest() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());

        let id = identity_with_sidecar(&bins, dir.path()).unwrap();

        assert_eq!(id, bins.content_digest().unwrap());
        assert!(
            sidecar_path(dir.path()).is_file(),
            "sidecar must be written"
        );
    }

    /// The whole point of the sidecar: the steady-state path must not read the
    /// artifacts.
    ///
    /// Proven by swapping every artifact's *content* while holding its length
    /// and mtime fixed, so the recorded stamps still match. Anything that read
    /// the bytes would now digest different content and produce a different
    /// identity; only a path that trusts the sidecar returns the original.
    ///
    /// An earlier version made the artifacts unreadable (mode 0000) instead.
    /// That proves nothing when the suite runs as root — root bypasses the
    /// permission check, the read succeeds, and the assertion passes for the
    /// wrong reason. CI containers routinely run as root.
    #[test]
    fn a_valid_sidecar_is_used_without_reading_artifact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        let expected = identity_with_sidecar(&bins, dir.path()).unwrap();

        for (_, path) in bins.artifacts() {
            let original = std::fs::read(path).unwrap();
            let mtime = std::fs::metadata(path).unwrap().modified().unwrap();
            // Same length, different bytes.
            let swapped: Vec<u8> = original.iter().map(|b| b ^ 0xFF).collect();
            std::fs::write(path, &swapped).unwrap();
            let f = std::fs::File::options().write(true).open(path).unwrap();
            f.set_times(std::fs::FileTimes::new().set_modified(mtime))
                .unwrap();
            drop(f);
        }

        assert_eq!(
            identity_with_sidecar(&bins, dir.path()).unwrap(),
            expected,
            "a valid sidecar must be trusted without re-reading the artifacts"
        );
    }

    /// The sidecar is a cache, not an authority. A rebuilt artifact must not be
    /// masked by a stale record of it.
    #[test]
    fn a_changed_artifact_invalidates_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        let before = identity_with_sidecar(&bins, dir.path()).unwrap();

        // Same length, different bytes, and a moved mtime — which is what a
        // rebuild produces.
        std::fs::write(&bins.agent, b"AGENT-BYTES").unwrap();
        let f = std::fs::File::options()
            .write(true)
            .open(&bins.agent)
            .unwrap();
        f.set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000),
            ),
        )
        .unwrap();
        drop(f);

        let after = identity_with_sidecar(&bins, dir.path()).unwrap();
        assert_ne!(before, after, "a rebuilt artifact must change the identity");
        assert_eq!(
            after,
            bins.content_digest().unwrap(),
            "the refreshed identity must match the artifacts on disk"
        );
    }

    /// A length change alone must invalidate, with mtime held constant so that
    /// `len` is what carries the assertion. Without pinning mtime back, the
    /// rewrite moves it and this passes even if `len` is never recorded.
    #[test]
    fn a_resized_artifact_invalidates_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        let original_mtime = std::fs::metadata(&bins.netinit)
            .unwrap()
            .modified()
            .unwrap();
        let before = identity_with_sidecar(&bins, dir.path()).unwrap();

        std::fs::write(&bins.netinit, b"netinit-bytes-but-longer").unwrap();
        let f = std::fs::File::options()
            .write(true)
            .open(&bins.netinit)
            .unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        drop(f);
        assert_eq!(
            std::fs::metadata(&bins.netinit)
                .unwrap()
                .modified()
                .unwrap(),
            original_mtime,
            "mtime must be held constant or this test does not exercise len"
        );

        assert_ne!(before, identity_with_sidecar(&bins, dir.path()).unwrap());
    }

    #[test]
    fn a_corrupt_sidecar_falls_back_to_the_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        let expected = identity_with_sidecar(&bins, dir.path()).unwrap();

        std::fs::write(sidecar_path(dir.path()), b"{not json").unwrap();

        assert_eq!(
            identity_with_sidecar(&bins, dir.path()).unwrap(),
            expected,
            "an unparsable sidecar must be recomputed, not fatal"
        );
    }

    /// A sidecar claiming a digest the artifacts do not have must not be
    /// believed. This is the forged-sidecar case.
    #[test]
    fn a_sidecar_with_a_forged_digest_is_rejected_by_the_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        identity_with_sidecar(&bins, dir.path()).unwrap();

        // Keep the stamps honest but claim a different digest: this is
        // believed, and is exactly why the stamps must be checked.
        let mut forged: Sidecar =
            serde_json::from_slice(&std::fs::read(sidecar_path(dir.path())).unwrap()).unwrap();
        forged.digest = "0".repeat(64);
        forged.artifacts[0].len += 1; // ...but the artifact says otherwise.
        std::fs::write(
            sidecar_path(dir.path()),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();

        assert_eq!(
            identity_with_sidecar(&bins, dir.path()).unwrap(),
            bins.content_digest().unwrap(),
            "a sidecar contradicted by the artifacts must be discarded"
        );
    }

    #[test]
    fn a_missing_artifact_is_an_error_not_a_stale_identity() {
        let dir = tempfile::tempdir().unwrap();
        let bins = bins_in(dir.path());
        identity_with_sidecar(&bins, dir.path()).unwrap();
        std::fs::remove_file(&bins.egress_client).unwrap();

        assert!(
            identity_with_sidecar(&bins, dir.path()).is_err(),
            "a vanished artifact must not resolve to the recorded identity"
        );
    }
}
