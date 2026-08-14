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

use mvm_contract::builder::BuilderError;
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

impl ProvenanceInput {
    /// Start building a [`ProvenanceInput`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> ProvenanceInputBuilder {
        ProvenanceInputBuilder::new()
    }
}

/// Builder for [`ProvenanceInput`]. Required fields are checked by
/// [`ProvenanceInputBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct ProvenanceInputBuilder {
    input_kind: Option<InputKind>,
    input_ref: Option<String>,
    lock_digest: Option<String>,
    builder_id: Option<String>,
}

impl ProvenanceInputBuilder {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input_kind: None,
            input_ref: None,
            lock_digest: None,
            builder_id: None,
        }
    }

    /// Set `input_kind`.
    #[must_use]
    pub fn input_kind(mut self, input_kind: InputKind) -> Self {
        self.input_kind = Some(input_kind);
        self
    }

    /// Set `input_ref`.
    #[must_use]
    pub fn input_ref(mut self, input_ref: String) -> Self {
        self.input_ref = Some(input_ref);
        self
    }

    /// Set `lock_digest`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn lock_digest(mut self, lock_digest: impl Into<Option<String>>) -> Self {
        self.lock_digest = lock_digest.into();
        self
    }

    /// Set `builder_id`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn builder_id(mut self, builder_id: impl Into<Option<String>>) -> Self {
        self.builder_id = builder_id.into();
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<ProvenanceInput, BuilderError> {
        Ok(ProvenanceInput {
            input_kind: self
                .input_kind
                .ok_or(BuilderError::missing("ProvenanceInput", "input_kind"))?,
            input_ref: self
                .input_ref
                .ok_or(BuilderError::missing("ProvenanceInput", "input_ref"))?,
            lock_digest: self.lock_digest,
            builder_id: self.builder_id,
        })
    }
}

impl Default for ProvenanceInputBuilder {
    fn default() -> Self {
        Self::new()
    }
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

#[cfg(test)]
mod provenance_input_builder_tests {
    use super::*;

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = ProvenanceInput::builder().build() else {
            panic!("an empty ProvenanceInput builder must not build");
        };
        assert_eq!(err, BuilderError::missing("ProvenanceInput", "input_kind"));
    }
}
