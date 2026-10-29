//! Snapshotting a pack's source, locking it, and compiling it frozen.

use super::app_tree::assemble;
use super::lock::{LockInputs, derive_lock, stale_fields};
use super::lower::{APP_TREE, build_packages, lower, record_python_environment};
use super::python::{self, Interpreter, PythonEnvironment, UV_LOCKFILE};
use super::{LOCK_FILE, PACK_BUILD_FILE, PackError, PackInput};
use crate::deps::validate_lockfiles;
use crate::orchestrator::{GeneratedFile, compile_pinned_with};
use crate::source::copy_source;
use mvm_contract::ir::{Dependencies, Workload, canonicalize};
use mvm_contract::pack_lock::PackLock;
use mvm_contract::pack_spec::PackSource;
use std::path::{Path, PathBuf};

/// Resolve `input` against its current source tree and return the lock a
/// frozen build would accept.
pub fn lock_pack(input: &PackInput<'_>) -> Result<PackLock, PackError> {
    let staging = staging_dir()?;
    let resolved = resolve(input, staging.path())?;
    Ok(resolved.lock)
}

/// Compile `input` into `out` only if `locked` still describes it exactly.
///
/// Lowering, source containment, copy materialization, the dependency
/// lockfile's pins and every lock field are checked before the compiler runs,
/// and the compiler reads the verified snapshot rather than the live tree, so
/// an edit made after the check cannot reach the artifact. Pack-only build
/// inputs, such as a resolved Python environment, are published as
/// [`PACK_BUILD_FILE`] with the rest of the artifact. Nothing is written to
/// `out` when any check fails.
pub fn compile_frozen(
    input: &PackInput<'_>,
    locked: &PackLock,
    out: &Path,
) -> Result<(), PackError> {
    locked.validate()?;
    let staging = staging_dir()?;
    let resolved = resolve(input, staging.path())?;
    let fields = stale_fields(&resolved.lock, locked);
    if !fields.is_empty() {
        return Err(PackError::StaleLock { fields });
    }
    let build_packages = build_packages(input.spec)?;
    let extra = pack_build_file(&PackBuild {
        python: resolved.python.as_ref(),
        build_packages: &build_packages,
    })?;
    compile_pinned_with(
        &resolved.workload,
        out,
        &resolved.manifest_dir,
        input.revision,
        &extra,
    )
    .map_err(PackError::Compile)
}

/// The contents of [`PACK_BUILD_FILE`]. Every member is optional, and the
/// file is written only when one is present.
#[derive(serde::Serialize)]
struct PackBuild<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    python: Option<&'a PythonEnvironment>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    build_packages: &'a [String],
}

impl PackBuild<'_> {
    fn is_empty(&self) -> bool {
        self.python.is_none() && self.build_packages.is_empty()
    }
}

fn pack_build_file(build: &PackBuild<'_>) -> Result<Vec<GeneratedFile<'static>>, PackError> {
    if build.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![GeneratedFile {
        name: PACK_BUILD_FILE,
        contents: canonicalize(build).map_err(PackError::Digest)?,
    }])
}

/// A spec resolved against one snapshot of its source.
struct Resolved {
    workload: Workload,
    lock: PackLock,
    /// Where the lowered workload's source path resolves: the snapshot, or the
    /// tree assembled from copy operations.
    manifest_dir: PathBuf,
    /// The wheels a uv lockfile resolves to for the pack's target.
    python: Option<PythonEnvironment>,
}

/// Lower the spec, snapshot its source under `staging`, assemble the
/// application tree when the spec copies, check the dependency lockfile,
/// resolve a uv lockfile into the workload, and derive the lock. The snapshot
/// sits at the same relative path the spec names, so its tree digest is
/// independent of what the copies select.
fn resolve(input: &PackInput<'_>, staging: &Path) -> Result<Resolved, PackError> {
    let mut workload = lower(input.spec)?;
    let PackSource::Local { path } = &input.spec.source;
    let root = contained_source_root(input.spec_dir, path)?;
    let snapshot_dir = staging.join("snapshot");
    std::fs::create_dir_all(&snapshot_dir).map_err(PackError::Staging)?;
    let snapshot = snapshot_dir.join(path);
    let plan =
        copy_source(&root, &snapshot, &[], &[LOCK_FILE.to_string()]).map_err(PackError::Source)?;
    let manifest_dir = if input.spec.copy.is_empty() {
        snapshot_dir
    } else {
        let app_dir = staging.join("app");
        assemble(
            input.spec,
            workload.apps[0].dependencies.as_ref(),
            &snapshot,
            &app_dir.join(APP_TREE),
        )?;
        app_dir
    };
    validate_lockfiles(&workload, &manifest_dir).map_err(PackError::Lockfile)?;
    let python = resolve_python(input, &workload, &snapshot)?;
    if let Some(environment) = &python {
        record_python_environment(&mut workload, environment)?;
    }
    let lock = derive_lock(&LockInputs {
        spec: input.spec,
        workload: &workload,
        source_tree_sha256: &plan.tree_hash,
        revision: input.revision,
    })?;
    Ok(Resolved {
        workload,
        lock,
        manifest_dir,
        python,
    })
}

/// Resolve the snapshot's uv lockfile for the pack's interpreter and target,
/// when the workload declares Python dependencies.
fn resolve_python(
    input: &PackInput<'_>,
    workload: &Workload,
    snapshot: &Path,
) -> Result<Option<PythonEnvironment>, PackError> {
    let Some(Dependencies::Python { .. }) = workload.apps[0].dependencies else {
        return Ok(None);
    };
    let path = snapshot.join(UV_LOCKFILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|source| PackError::ReadLockfile { path, source })?;
    let interpreter = Interpreter::from_spec(input.spec)?;
    Ok(Some(python::resolve(
        &text,
        &interpreter,
        input.spec.target,
    )?))
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
    use crate::pack::APP_TREE;
    use crate::pack::LockField;
    use crate::pack::python::PythonError;
    use crate::pack::test_support::{revision, spec};
    use mvm_contract::ir::NodeTool;
    use mvm_contract::pack_spec::{CopyOperation, DependencyFiles, PackSpec};
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

    fn compile_spec(spec: &PackSpec, dir: &Path, out: &Path) -> Result<PackLock, PackError> {
        let input = PackInput {
            spec,
            spec_dir: dir,
            revision: &revision(),
        };
        let locked = lock_pack(&input)?;
        compile_frozen(&input, &locked, out)?;
        Ok(locked)
    }

    fn copying(copies: &[(&str, &str)]) -> PackSpec {
        let mut spec = spec();
        spec.copy = copies
            .iter()
            .map(|(source, destination)| CopyOperation {
                source: (*source).into(),
                destination: (*destination).into(),
            })
            .collect();
        spec
    }

    #[test]
    fn copies_select_the_application_tree() {
        let dir = source_tree();
        let spec = copying(&[("hello.txt", "/app/hello.txt"), ("bin", "/app/bin")]);
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        let locked = compile_spec(&spec, dir.path(), &artifact).unwrap();
        assert_eq!(
            fs::read_to_string(artifact.join("src/hello.txt")).unwrap(),
            "hi\n"
        );
        assert!(artifact.join("src/bin/run").is_file());
        assert_eq!(
            fs::metadata(artifact.join("src/bin/run"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0o111,
            "copy selection, snapshotting and compilation preserve executable bits"
        );
        let workload: serde_json::Value =
            serde_json::from_slice(&fs::read(artifact.join("workload.json")).unwrap()).unwrap();
        assert_eq!(workload["apps"][0]["source"]["path"], APP_TREE);
        assert_eq!(launch_ir_hash(&artifact), locked.workload_sha256);
    }

    #[test]
    fn a_copied_executable_mode_change_refuses_frozen_compile() {
        let dir = source_tree();
        let spec = copying(&[("bin/run", "/app/bin/run")]);
        let input = PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        };
        let locked = lock_pack(&input).unwrap();
        fs::set_permissions(
            dir.path().join("bin/run"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        assert_eq!(
            stale(compile_frozen(&input, &locked, &artifact)),
            vec![LockField::Source]
        );
        assert!(!artifact.exists());
    }

    #[test]
    fn uncopied_source_edits_still_stale_the_lock() {
        let dir = source_tree();
        fs::write(dir.path().join("notes.txt"), "a").unwrap();
        let spec = copying(&[("hello.txt", "/app/hello.txt")]);
        let input = PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        };
        let locked = lock_pack(&input).unwrap();
        fs::write(dir.path().join("notes.txt"), "b").unwrap();
        let out = TempDir::new().unwrap();
        assert_eq!(
            stale(compile_frozen(&input, &locked, &out.path().join("a"))),
            vec![LockField::Source]
        );
    }

    #[test]
    fn a_copy_outside_the_application_tree_is_refused_before_snapshot() {
        let dir = source_tree();
        let spec = copying(&[("hello.txt", "/etc/hello.txt")]);
        let result = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::CopyOutsideApp { .. })));
    }

    fn npm_spec() -> PackSpec {
        let mut spec = spec();
        spec.dependencies = vec![DependencyFiles::Node {
            tool: NodeTool::Npm,
            manifest: "package.json".into(),
            lockfile: "package-lock.json".into(),
        }];
        spec
    }

    fn write_npm(dir: &Path, integrity: bool) {
        fs::write(
            dir.join("package.json"),
            r#"{"name":"a","version":"1.0.0"}"#,
        )
        .unwrap();
        let entry = if integrity {
            r#""integrity": "sha512-AAAA""#
        } else {
            r#""license": "MIT""#
        };
        fs::write(
            dir.join("package-lock.json"),
            format!(
                r#"{{"lockfileVersion": 3, "packages": {{"": {{"name": "a"}}, "node_modules/left-pad": {{"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", {entry}}}}}}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn a_pinned_npm_lockfile_lowers_to_node_dependencies() {
        let dir = source_tree();
        write_npm(dir.path(), true);
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        compile_spec(&npm_spec(), dir.path(), &artifact).unwrap();
        let launch: serde_json::Value =
            serde_json::from_slice(&fs::read(artifact.join("launch.json")).unwrap()).unwrap();
        assert_eq!(launch["dependencies"]["kind"], "node");
        assert_eq!(launch["dependencies"]["tool"], "npm");
        assert!(artifact.join("src/package-lock.json").is_file());
    }

    #[test]
    fn npm_files_follow_copies_into_the_application_tree() {
        let dir = source_tree();
        write_npm(dir.path(), true);
        let mut spec = npm_spec();
        spec.copy = copying(&[("hello.txt", "/app/hello.txt")]).copy;
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        compile_spec(&spec, dir.path(), &artifact).unwrap();
        assert!(artifact.join("src/package.json").is_file());
        assert!(artifact.join("src/package-lock.json").is_file());
        assert!(!artifact.join("src/bin").exists());
    }

    #[test]
    fn an_unpinned_npm_lockfile_is_refused() {
        let dir = source_tree();
        write_npm(dir.path(), false);
        let result = lock_pack(&PackInput {
            spec: &npm_spec(),
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::Lockfile(_))));
    }

    #[test]
    fn a_missing_npm_lockfile_is_refused() {
        let dir = source_tree();
        let result = lock_pack(&PackInput {
            spec: &npm_spec(),
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::Lockfile(_))));
    }

    const UV_FIXTURE: &str = include_str!("../../tests/fixtures/pack-python/uv.lock");
    const PYPROJECT_FIXTURE: &str = include_str!("../../tests/fixtures/pack-python/pyproject.toml");

    fn uv_spec() -> PackSpec {
        let mut spec = spec();
        spec.packages.push(mvm_contract::pack_spec::PackageRequest {
            name: "python312".into(),
            version: None,
            scope: mvm_contract::pack_spec::PackageScope::Runtime,
        });
        spec.dependencies = vec![DependencyFiles::Python {
            tool: mvm_contract::ir::PythonTool::Uv,
            manifest: "pyproject.toml".into(),
            lockfile: "uv.lock".into(),
        }];
        spec
    }

    fn write_uv(dir: &Path, lock: &str) {
        fs::write(dir.join("pyproject.toml"), PYPROJECT_FIXTURE).unwrap();
        fs::write(dir.join("uv.lock"), lock).unwrap();
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn a_uv_lockfile_compiles_to_its_resolved_wheel_set() {
        let dir = source_tree();
        write_uv(dir.path(), UV_FIXTURE);
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        let locked = compile_spec(&uv_spec(), dir.path(), &artifact).unwrap();

        let launch = read_json(&artifact.join("launch.json"));
        assert_eq!(launch["dependencies"]["kind"], "python");
        assert_eq!(launch["dependencies"]["tool"], "uv");
        assert_eq!(launch["ir_hash"], locked.workload_sha256);

        let build = read_json(&artifact.join(PACK_BUILD_FILE));
        let python = &build["python"];
        assert_eq!(python["interpreter"], "python312");
        let wheels = python["wheels"].as_array().unwrap();
        assert_eq!(wheels.len(), 11);
        let core = wheels
            .iter()
            .find(|w| w["name"] == "pydantic-core")
            .unwrap();
        assert!(
            core["filename"]
                .as_str()
                .unwrap()
                .contains("manylinux_2_17_aarch64"),
            "the spec targets aarch64-linux"
        );

        let workload = read_json(&artifact.join("workload.json"));
        assert_eq!(
            workload["extensions"][crate::pack::PACK_EXTENSION]["python"],
            *python,
            "the digested workload carries exactly the wheel set the flake installs"
        );
        assert!(artifact.join("src/uv.lock").is_file());
    }

    #[test]
    fn the_pack_build_file_is_canonical_and_reproducible() {
        let dir = source_tree();
        write_uv(dir.path(), UV_FIXTURE);
        let out = TempDir::new().unwrap();
        let (a, b) = (out.path().join("a"), out.path().join("b"));
        compile_spec(&uv_spec(), dir.path(), &a).unwrap();
        compile_spec(&uv_spec(), dir.path(), &b).unwrap();
        let first = fs::read_to_string(a.join(PACK_BUILD_FILE)).unwrap();
        assert_eq!(first, fs::read_to_string(b.join(PACK_BUILD_FILE)).unwrap());
        assert_eq!(
            first,
            canonicalize(&read_json(&a.join(PACK_BUILD_FILE))).unwrap()
        );
    }

    #[test]
    fn build_packages_are_written_to_the_pack_build_file_and_bound_by_the_lock() {
        let dir = source_tree();
        let mut spec = spec();
        let plain = lock_pack(&PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        })
        .unwrap();
        spec.packages.push(mvm_contract::pack_spec::PackageRequest {
            name: "gcc".into(),
            version: None,
            scope: mvm_contract::pack_spec::PackageScope::Build,
        });
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("a");
        let locked = compile_spec(&spec, dir.path(), &artifact).unwrap();
        assert_eq!(
            read_json(&artifact.join(PACK_BUILD_FILE)),
            serde_json::json!({"build_packages": ["gcc"]})
        );
        let launch = read_json(&artifact.join("launch.json"));
        assert!(
            !launch.to_string().contains("gcc"),
            "a build package is not in the image: {launch}"
        );
        assert_ne!(locked, plain, "the lock binds the build set");
        let result = compile_frozen(
            &PackInput {
                spec: &spec,
                spec_dir: dir.path(),
                revision: &revision(),
            },
            &plain,
            &out.path().join("b"),
        );
        assert!(matches!(result, Err(PackError::StaleLock { .. })));
    }

    #[test]
    fn a_pack_without_python_dependencies_writes_no_pack_build_file() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        let out = TempDir::new().unwrap();
        compile_with(dir.path(), &locked, &out.path().join("a")).unwrap();
        assert!(!out.path().join("a").join(PACK_BUILD_FILE).exists());
        let workload = read_json(&out.path().join("a/workload.json"));
        assert!(
            workload["extensions"][crate::pack::PACK_EXTENSION]
                .get("python")
                .is_none()
        );
    }

    #[test]
    fn a_changed_wheel_hash_stales_the_lock() {
        let dir = source_tree();
        write_uv(dir.path(), UV_FIXTURE);
        let spec = uv_spec();
        let input = PackInput {
            spec: &spec,
            spec_dir: dir.path(),
            revision: &revision(),
        };
        let locked = lock_pack(&input).unwrap();
        let core = "sha256:7d3c";
        let start = UV_FIXTURE
            .find("pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_aarch64")
            .unwrap();
        let hash_at = start + UV_FIXTURE[start..].find("sha256:").unwrap();
        let mut edited = UV_FIXTURE.to_string();
        edited.replace_range(hash_at..hash_at + core.len(), core);
        assert_ne!(edited, UV_FIXTURE);
        write_uv(dir.path(), &edited);
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        assert_eq!(
            stale(compile_frozen(&input, &locked, &artifact)),
            vec![LockField::Source, LockField::Workload],
            "the lockfile is in the snapshot, and the selected wheel's hash is in the workload"
        );
        assert!(!artifact.exists());
    }

    #[test]
    fn an_unavailable_package_version_is_refused_before_anything_is_written() {
        let dir = source_tree();
        let sdist_only = UV_FIXTURE.replace(
            "url = \"https://files.pythonhosted.org/packages/0b/a7/71ac2cff56fec219ed242bb11b8efb69fcc4bec75db06fb7bfe35de520e6/certifi-2026.7.22-py3-none-any.whl\"",
            "url = \"https://files.pythonhosted.org/packages/certifi-2026.7.22-cp312-cp312-win_amd64.whl\"",
        );
        assert_ne!(sdist_only, UV_FIXTURE);
        write_uv(dir.path(), &sdist_only);
        let result = lock_pack(&PackInput {
            spec: &uv_spec(),
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(
            result,
            Err(PackError::Python(PythonError::NoCompatibleWheel { package, .. })) if package == "certifi"
        ));
    }

    #[test]
    fn uv_files_follow_copies_into_the_application_tree() {
        let dir = source_tree();
        write_uv(dir.path(), UV_FIXTURE);
        let mut spec = uv_spec();
        spec.copy = copying(&[("hello.txt", "/app/hello.txt")]).copy;
        let out = TempDir::new().unwrap();
        let artifact = out.path().join("artifact");
        compile_spec(&spec, dir.path(), &artifact).unwrap();
        assert!(artifact.join("src/pyproject.toml").is_file());
        assert!(artifact.join("src/uv.lock").is_file());
        assert!(artifact.join(PACK_BUILD_FILE).is_file());
    }

    #[test]
    fn a_missing_uv_lockfile_is_refused() {
        let dir = source_tree();
        let result = lock_pack(&PackInput {
            spec: &uv_spec(),
            spec_dir: dir.path(),
            revision: &revision(),
        });
        assert!(matches!(result, Err(PackError::Lockfile(_))));
    }

    fn launch_ir_hash(artifact: &Path) -> String {
        let launch: serde_json::Value =
            serde_json::from_slice(&fs::read(artifact.join("launch.json")).unwrap()).unwrap();
        launch["ir_hash"].as_str().unwrap().to_string()
    }

    #[test]
    fn a_lock_written_at_the_source_root_does_not_stale_itself() {
        let dir = source_tree();
        let locked = lock_for(dir.path());
        fs::write(
            dir.path().join(LOCK_FILE),
            serde_json::to_vec(&locked).unwrap(),
        )
        .unwrap();
        assert_eq!(lock_for(dir.path()), locked);
        let out = TempDir::new().unwrap();
        compile_with(dir.path(), &locked, &out.path().join("a")).unwrap();
        assert!(!out.path().join("a/src").join(LOCK_FILE).exists());
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
        spec.packages[0].version = Some("1.36.1".into());
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
            Err(PackError::UnsupportedPackageVersion { .. })
        ));
    }
}
