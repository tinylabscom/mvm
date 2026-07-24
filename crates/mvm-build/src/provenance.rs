//! Build-provenance recorder.
//!
//! Turns the artifacts a build produced into the signed plan's
//! [`BuildProvenance`] by content-addressing each one. The recorder is the
//! host-side bridge between the deterministic build pipeline (which writes the
//! kernel / rootfs / `mvm-init` / snapshot-base files) and the
//! signed [`ExecutionPlan`](mvm_core::plan::ExecutionPlan), so a launch is
//! traceable to exact input and output bytes. Producing the artifacts is the
//! builder VM's job; recording what it produced is this module's.

use std::io;
use std::path::Path;

use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::plan::types::{ArtifactDigests, BuildProvenance, InputKind};

/// Paths to the artifacts a build produced. Any field may be absent (e.g. a
/// workload with no initramfs, or a build that hasn't captured a snapshot base).
#[derive(Debug, Default, Clone)]
pub struct ArtifactPaths<'a> {
    pub kernel: Option<&'a Path>,
    pub rootfs: Option<&'a Path>,
    pub initramfs: Option<&'a Path>,
    pub mvm_init: Option<&'a Path>,
    pub snapshot_base: Option<&'a Path>,
}

/// The build input identity recorded alongside the artifact digests: what
/// source was consumed, pinned how, by which builder.
#[derive(Debug, Clone)]
pub struct ProvenanceInput {
    pub input_kind: InputKind,
    pub input_ref: String,
    pub lock_digest: Option<String>,
    pub builder_id: Option<String>,
}

/// Content-address each present artifact and assemble the [`BuildProvenance`]
/// for the signed plan. Absent paths record as `None`; a present-but-unreadable
/// path is an error (a build claiming an artifact it can't hash is not
/// recordable).
pub fn record_provenance(
    input: ProvenanceInput,
    paths: &ArtifactPaths,
) -> io::Result<BuildProvenance> {
    let digest = |p: Option<&Path>| -> io::Result<Option<String>> {
        match p {
            Some(p) => Ok(Some(sha256_file(p)?)),
            None => Ok(None),
        }
    };
    Ok(BuildProvenance {
        input_kind: input.input_kind,
        input_ref: input.input_ref,
        lock_digest: input.lock_digest,
        builder_id: input.builder_id,
        artifacts: ArtifactDigests {
            kernel: digest(paths.kernel)?,
            rootfs: digest(paths.rootfs)?,
            initramfs: digest(paths.initramfs)?,
            mvm_init: digest(paths.mvm_init)?,
            snapshot_base: digest(paths.snapshot_base)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("mvm-prov-test-{name}-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    fn input() -> ProvenanceInput {
        ProvenanceInput {
            input_kind: InputKind::NixFlake,
            input_ref: ".#app".to_string(),
            lock_digest: Some("sha256:lock".to_string()),
            builder_id: Some("builder-01".to_string()),
        }
    }

    #[test]
    fn records_digests_of_present_artifacts() {
        let kernel = write_temp("kernel", b"vmlinux-bytes");
        let rootfs = write_temp("rootfs", b"ext4-bytes");
        let paths = ArtifactPaths {
            kernel: Some(&kernel),
            rootfs: Some(&rootfs),
            ..Default::default()
        };
        let prov = record_provenance(input(), &paths).unwrap();

        assert_eq!(prov.input_kind, InputKind::NixFlake);
        assert_eq!(prov.input_ref, ".#app");
        // Digests match the canonical file hasher.
        assert_eq!(prov.artifacts.kernel, Some(sha256_file(&kernel).unwrap()));
        assert_eq!(prov.artifacts.rootfs, Some(sha256_file(&rootfs).unwrap()));
        // Absent artifacts stay None.
        assert_eq!(prov.artifacts.initramfs, None);
        assert_eq!(prov.artifacts.mvm_init, None);

        std::fs::remove_file(kernel).ok();
        std::fs::remove_file(rootfs).ok();
    }

    #[test]
    fn distinct_bytes_produce_distinct_digests() {
        let a = write_temp("init-a", b"AAAA");
        let b = write_temp("snapshot-b", b"BBBB");
        let paths = ArtifactPaths {
            mvm_init: Some(&a),
            snapshot_base: Some(&b),
            ..Default::default()
        };
        let prov = record_provenance(input(), &paths).unwrap();
        assert!(prov.artifacts.mvm_init.is_some());
        assert_ne!(prov.artifacts.mvm_init, prov.artifacts.snapshot_base);
        std::fs::remove_file(a).ok();
        std::fs::remove_file(b).ok();
    }

    #[test]
    fn no_artifacts_records_all_none_but_keeps_input() {
        let prov = record_provenance(input(), &ArtifactPaths::default()).unwrap();
        assert_eq!(prov.artifacts, ArtifactDigests::default());
        assert_eq!(prov.builder_id.as_deref(), Some("builder-01"));
    }

    #[test]
    fn present_but_unreadable_artifact_is_an_error() {
        let missing = Path::new("/nonexistent/mvm-init-does-not-exist");
        let paths = ArtifactPaths {
            mvm_init: Some(missing),
            ..Default::default()
        };
        assert!(record_provenance(input(), &paths).is_err());
    }
}
