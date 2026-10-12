//! Snapshotting a pack's source, locking it, and compiling it frozen.

use super::lock::{LockInputs, derive_lock, stale_fields};
use super::lower::lower;
use super::{PackError, PackInput};
use crate::orchestrator::compile_pinned;
use crate::source::copy_source;
use mvm_contract::ir::Workload;
use mvm_contract::pack_lock::PackLock;
use mvm_contract::pack_spec::PackSource;
use std::path::Path;

/// Resolve `input` against its current source tree and return the lock a
/// frozen build would accept.
pub fn lock_pack(input: &PackInput<'_>) -> Result<PackLock, PackError> {
    let staging = staging_dir()?;
    let (_, lock) = resolve(input, staging.path())?;
    Ok(lock)
}

/// Compile `input` into `out` only if `locked` still describes it exactly.
///
/// Lowering, source containment and every lock field are checked before the
/// compiler runs, and the compiler reads the verified snapshot rather than the
/// live tree, so an edit made after the check cannot reach the artifact.
/// Nothing is written to `out` when any check fails.
pub fn compile_frozen(
    input: &PackInput<'_>,
    locked: &PackLock,
    out: &Path,
) -> Result<(), PackError> {
    locked.validate()?;
    let staging = staging_dir()?;
    let (workload, expected) = resolve(input, staging.path())?;
    let fields = stale_fields(&expected, locked);
    if !fields.is_empty() {
        return Err(PackError::StaleLock { fields });
    }
    compile_pinned(&workload, out, staging.path(), input.revision).map_err(PackError::Compile)
}

/// Lower the spec, snapshot its source under `staging`, and derive the lock.
/// The snapshot sits at the same relative path the lowered workload names, so
/// `staging` serves as the compiler's manifest directory.
fn resolve(input: &PackInput<'_>, staging: &Path) -> Result<(Workload, PackLock), PackError> {
    let workload = lower(input.spec)?;
    let PackSource::Local { path } = &input.spec.source;
    let root = contained_source_root(input.spec_dir, path)?;
    let plan = copy_source(&root, &staging.join(path), &[], &[]).map_err(PackError::Source)?;
    let lock = derive_lock(&LockInputs {
        spec: input.spec,
        workload: &workload,
        source_tree_sha256: &plan.tree_hash,
        revision: input.revision,
    })?;
    Ok((workload, lock))
}

/// Resolve the source root and refuse one that leaves the spec directory
/// through a symlinked component. The spec's lexical validation already
/// rejects `..` and absolute paths.
fn contained_source_root(spec_dir: &Path, path: &str) -> Result<std::path::PathBuf, PackError> {
    let base = spec_dir
        .canonicalize()
        .map_err(|source| PackError::SourceRoot {
            path: spec_dir.to_path_buf(),
            source,
        })?;
    let joined = spec_dir.join(path);
    let root = joined
        .canonicalize()
        .map_err(|source| PackError::SourceRoot {
            path: joined.clone(),
            source,
        })?;
    if !root.starts_with(&base) {
        return Err(PackError::SourceEscape {
            path: path.to_string(),
        });
    }
    if !root.is_dir() {
        return Err(PackError::SourceRoot {
            path: joined,
            source: std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a directory"),
        });
    }
    Ok(root)
}

fn staging_dir() -> Result<tempfile::TempDir, PackError> {
    tempfile::Builder::new()
        .prefix(".mvm-pack-snapshot-")
        .tempdir()
        .map_err(PackError::Staging)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvm_pin::PinnedMvmRevision;
    use crate::pack::LockField;
    use crate::pack::test_support::{revision, spec};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn source_tree() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hello.txt"), "hi\n").unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        fs::write(dir.path().join("bin/run"), "#!/bin/busybox\n").unwrap();
        fs::set_permissions(
            dir.path().join("bin/run"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        dir
    }

    fn lock_for(dir: &Path) -> PackLock {
        let spec = spec();
        lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir,
            revision: &revision(),
        })
        .unwrap()
    }

    fn compile_with(dir: &Path, locked: &PackLock, out: &Path) -> Result<(), PackError> {
        let spec = spec();
        compile_frozen(
            &PackInput {
                spec: &spec,
                spec_dir: dir,
                revision: &revision(),
            },
            locked,
            out,
        )
    }

    fn stale(result: Result<(), PackError>) -> Vec<LockField> {
        match result {
            Err(PackError::StaleLock { fields }) => fields,
            other => panic!("expected a stale lock, got {other:?}"),
        }
    }

    #[test]
    fn locking_is_deterministic_for_an_unchanged_tree() {
        let dir = source_tree();
        assert_eq!(lock_for(dir.path()), lock_for(dir.path()));
    }

    #[test]
    fn lock_binds_content_and_file_modes() {
        let dir = source_tree();
        let before = lock_for(dir.path()).source_tree_sha256;
        fs::set_permissions(
            dir.path().join("bin/run"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let after_mode = lock_for(dir.path()).source_tree_sha256;
        assert_ne!(before, after_mode);
        fs::write(dir.path().join("hello.txt"), "bye\n").unwrap();
        assert_ne!(after_mode, lock_for(dir.path()).source_tree_sha256);
    }

    #[test]
    fn a_fresh_lock_compiles_from_the_verified_snapshot() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        compile_with(dir.path(), &locked, &artifact).unwrap();

        let flake = fs::read_to_string(artifact.join("flake.nix")).unwrap();
        assert!(flake.contains(&revision().flake_url()));
        let launch: serde_json::Value =
            serde_json::from_slice(&fs::read(artifact.join("launch.json")).unwrap()).unwrap();
        assert_eq!(launch["source"]["tree_hash"], locked.source_tree_sha256);
        assert_eq!(launch["ir_hash"], locked.workload_sha256);
        assert_eq!(
            fs::read_to_string(artifact.join("src/hello.txt")).unwrap(),
            "hi\n"
        );
        let workload: serde_json::Value =
            serde_json::from_slice(&fs::read(artifact.join("workload.json")).unwrap()).unwrap();
        assert_eq!(workload["apps"][0]["source"]["path"], ".");
    }

    #[test]
    fn compiling_twice_renders_identical_artifacts() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        let out = TempDir::new().unwrap();
        let (a, b) = (out.path().join("a"), out.path().join("b"));
        compile_with(dir.path(), &locked, &a).unwrap();
        compile_with(dir.path(), &locked, &b).unwrap();
        for file in ["flake.nix", "launch.json", "workload.json"] {
            assert_eq!(
                fs::read(a.join(file)).unwrap(),
                fs::read(b.join(file)).unwrap(),
                "{file}"
            );
        }
    }

    #[test]
    fn a_source_edit_after_locking_is_refused_before_build() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        fs::write(dir.path().join("hello.txt"), "tampered\n").unwrap();
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        assert_eq!(
            stale(compile_with(dir.path(), &locked, &artifact)),
            vec![LockField::Source]
        );
        assert!(!artifact.exists());
    }

    #[test]
    fn a_different_mvm_revision_is_refused() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        let spec = spec();
        let other = PinnedMvmRevision::parse(&"0".repeat(40)).unwrap();
        let out = TempDir::new().unwrap();
        let result = compile_frozen(
            &PackInput {
                spec: &spec,
                spec_dir: dir.path(),
                revision: &other,
            },
            &locked,
            &out.path().join("artifact"),
        );
        assert_eq!(stale(result), vec![LockField::Compiler]);
    }

    #[test]
    fn an_edited_spec_is_refused_against_its_old_lock() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        let mut edited = spec();
        edited.entrypoint.push("--extra".into());
        let out = TempDir::new().unwrap();
        let result = compile_frozen(
            &PackInput {
                spec: &edited,
                spec_dir: dir.path(),
                revision: &revision(),
            },
            &locked,
            &out.path().join("artifact"),
        );
        assert_eq!(stale(result), vec![LockField::Spec, LockField::Workload]);
    }

    #[test]
    fn a_lock_for_another_pack_or_target_is_refused() {
        let dir = source_tree();
        let mut locked = lock_for(dir.path());
        locked.identity.name = "acme/other".into();
        locked.target = mvm_contract::pack_spec::PackTarget::X86_64Linux;
        let out = TempDir::new().unwrap();
        assert_eq!(
            stale(compile_with(dir.path(), &locked, &out.path().join("a"))),
            vec![LockField::Identity, LockField::Target]
        );
    }

    #[test]
    fn a_malformed_lock_is_refused_before_resolution() {
        let dir = source_tree();
        let mut locked = lock_for(dir.path());
        locked.workload_sha256 = "not-a-digest".into();
        let out = TempDir::new().unwrap();
        assert!(matches!(
            compile_with(dir.path(), &locked, &out.path().join("a")),
            Err(PackError::Lock(_))
        ));
    }

    #[test]
    fn a_symlinked_source_root_outside_the_spec_dir_is_refused() {
        let outside = source_tree();
        let dir = TempDir::new().unwrap();
        symlink(outside.path(), dir.path().join("app")).unwrap();
        let mut spec = spec();
        spec.source = PackSource::Local { path: "app".into() };
        let result = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::SourceEscape { path }) if path == "app"));
    }

    #[test]
    fn a_symlink_escaping_the_source_tree_is_refused() {
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), "x").unwrap();
        let dir = source_tree();
        symlink(outside.path().join("secret"), dir.path().join("leak")).unwrap();
        let spec = spec();
        let result = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::Source(_))));
    }

    #[test]
    fn a_missing_source_root_is_refused() {
        let dir = TempDir::new().unwrap();
        let mut spec = spec();
        spec.source = PackSource::Local {
            path: "absent".into(),
        };
        let result = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::SourceRoot { .. })));
    }

    #[test]
    fn unsupported_requests_fail_before_touching_the_source() {
        let dir = TempDir::new().unwrap();
        let mut spec = spec();
        spec.packages[0].scope = mvm_contract::pack_spec::PackageScope::Build;
        spec.source = PackSource::Local {
            path: "absent".into(),
        };
        let result = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(
            result,
            Err(PackError::UnsupportedBuildScope { .. })
        ));
    }
}
