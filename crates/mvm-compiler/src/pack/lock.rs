//! Deriving a [`PackLock`] from its inputs and naming what a stale lock no
//! longer matches.

use super::PackError;
use crate::launch::{ARTIFACT_FORMAT_VERSION, TOOLCHAIN_VERSION};
use crate::mvm_pin::PinnedMvmRevision;
use mvm_contract::ir::{Workload, ir_hash};
use mvm_contract::pack_lock::{LockedCompiler, PackLock, PackLockSchema};
use mvm_contract::pack_spec::PackSpec;
use sha2::{Digest, Sha256};
use std::fmt;

/// A lock field that disagrees with what its inputs resolve to now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockField {
    Schema,
    Identity,
    Target,
    Spec,
    Source,
    Workload,
    Compiler,
}

impl fmt::Display for LockField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Schema => "schema",
            Self::Identity => "identity",
            Self::Target => "target",
            Self::Spec => "spec_sha256",
            Self::Source => "source_tree_sha256",
            Self::Workload => "workload_sha256",
            Self::Compiler => "compiler",
        })
    }
}

/// The inputs a lock is derived from, after the source has been snapshotted.
pub(super) struct LockInputs<'a> {
    pub spec: &'a PackSpec,
    pub workload: &'a Workload,
    pub source_tree_sha256: &'a str,
    pub revision: &'a PinnedMvmRevision,
}

/// SHA-256 of the spec's canonical JSON.
pub fn spec_sha256(spec: &PackSpec) -> Result<String, PackError> {
    let canonical = spec.canonical_json()?;
    Ok(hex(&Sha256::digest(canonical)))
}

pub(super) fn derive_lock(inputs: &LockInputs<'_>) -> Result<PackLock, PackError> {
    let lock = PackLock {
        schema: PackLockSchema::V1,
        identity: inputs.spec.identity.clone(),
        target: inputs.spec.target,
        spec_sha256: spec_sha256(inputs.spec)?,
        source_tree_sha256: inputs.source_tree_sha256.to_string(),
        workload_sha256: ir_hash(inputs.workload).map_err(PackError::Digest)?,
        compiler: LockedCompiler {
            toolchain_version: TOOLCHAIN_VERSION.to_string(),
            artifact_format_version: ARTIFACT_FORMAT_VERSION.to_string(),
            mvm_revision: inputs.revision.as_str().to_string(),
        },
    };
    lock.validate()?;
    Ok(lock)
}

/// Every field where `locked` differs from `expected`, in wire order.
pub fn stale_fields(expected: &PackLock, locked: &PackLock) -> Vec<LockField> {
    [
        (LockField::Schema, expected.schema == locked.schema),
        (LockField::Identity, expected.identity == locked.identity),
        (LockField::Target, expected.target == locked.target),
        (LockField::Spec, expected.spec_sha256 == locked.spec_sha256),
        (
            LockField::Source,
            expected.source_tree_sha256 == locked.source_tree_sha256,
        ),
        (
            LockField::Workload,
            expected.workload_sha256 == locked.workload_sha256,
        ),
        (LockField::Compiler, expected.compiler == locked.compiler),
    ]
    .into_iter()
    .filter_map(|(field, same)| (!same).then_some(field))
    .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::lower::lower;
    use crate::pack::test_support::{revision, spec};

    fn derived() -> PackLock {
        let spec = spec();
        let workload = lower(&spec).unwrap();
        derive_lock(&LockInputs {
            spec: &spec,
            workload: &workload,
            source_tree_sha256: &"a".repeat(64),
            revision: &revision(),
        })
        .unwrap()
    }

    #[test]
    fn derived_lock_binds_identity_target_and_compiler_pins() {
        let lock = derived();
        assert_eq!(lock.identity, spec().identity);
        assert_eq!(lock.target, spec().target);
        assert_eq!(lock.spec_sha256, spec_sha256(&spec()).unwrap());
        assert_eq!(lock.compiler.toolchain_version, TOOLCHAIN_VERSION);
        assert_eq!(
            lock.compiler.artifact_format_version,
            ARTIFACT_FORMAT_VERSION
        );
        assert_eq!(lock.compiler.mvm_revision, revision().as_str());
        assert_eq!(derived(), lock);
    }

    #[test]
    fn spec_digest_tracks_every_authored_change() {
        let base = spec_sha256(&spec()).unwrap();
        let mut changed = spec();
        changed.entrypoint.push("--verbose".into());
        assert_ne!(spec_sha256(&changed).unwrap(), base);
        let mut changed = spec();
        changed.resources.memory_mb += 1;
        assert_ne!(spec_sha256(&changed).unwrap(), base);
    }

    #[test]
    fn a_matching_lock_has_no_stale_fields() {
        assert!(stale_fields(&derived(), &derived()).is_empty());
    }

    #[test]
    fn each_drifted_field_is_named() {
        let expected = derived();
        let mut locked = derived();
        locked.identity.version = "1.0.1".into();
        locked.source_tree_sha256 = "b".repeat(64);
        locked.compiler.mvm_revision = "0".repeat(40);
        assert_eq!(
            stale_fields(&expected, &locked),
            vec![LockField::Identity, LockField::Source, LockField::Compiler]
        );
        let mut locked = derived();
        locked.target = mvm_contract::pack_spec::PackTarget::X86_64Linux;
        locked.spec_sha256 = "c".repeat(64);
        locked.workload_sha256 = "d".repeat(64);
        assert_eq!(
            stale_fields(&expected, &locked),
            vec![LockField::Target, LockField::Spec, LockField::Workload]
        );
    }
}
