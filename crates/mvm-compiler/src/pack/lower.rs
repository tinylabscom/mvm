//! Pure PackSpec -> Workload IR lowering. No filesystem access.

use super::PackError;
use super::python::{Interpreter, PythonEnvironment, PythonError, UV_LOCKFILE, UV_MANIFEST};
use mvm_contract::ir::{
    App, Dependencies, Entrypoint, IR_MAJOR, IR_MINOR, Image, NodeTool, PythonTool, Resources,
    Source, Workload, validate,
};
use mvm_contract::pack_spec::{DependencyFiles, PackSource, PackSpec, PackageScope};
use std::collections::BTreeMap;

/// Workload extension key carrying the full pack identity and target, which
/// the IR id cannot hold.
pub const PACK_EXTENSION: &str = "mvm.pack";

/// Root filesystem size for lowered packs. PackSpec deliberately carries no
/// rootfs request; this matches the SDK's default.
pub const PACK_ROOTFS_SIZE_MIB: u32 = 512;

/// Working directory of a lowered command, the IR's own default. The
/// application tree is mounted here in the guest.
pub const APP_DIR: &str = "/app";

/// Source path a lowered workload names when the spec declares copy
/// operations: the compiler reads the tree assembled from them, never the
/// author's whole source directory.
pub const APP_TREE: &str = ".mvm-pack-app";

/// The npm manifest and lockfile a Node dependency must name. The Nix factory
/// builds `node_modules` from exactly these two files at the application root.
pub const NPM_MANIFEST: &str = "package.json";
pub const NPM_LOCKFILE: &str = "package-lock.json";

/// Key under [`PACK_EXTENSION`] holding the resolved Python environment, so
/// the workload digest a lock records covers every wheel's URL and hash.
pub const PACK_PYTHON_KEY: &str = "python";

/// Key under [`PACK_EXTENSION`] holding the build-scoped package names.
pub const PACK_BUILD_PACKAGES_KEY: &str = "build_packages";

/// Lower a validated spec into a single-app, command-entrypoint Workload and
/// validate the result.
///
/// Copy operations select what lands in the application tree at [`APP_DIR`];
/// without any, the whole source tree does. An npm lockfile lowers to the IR's
/// Node dependency declaration, which the Nix factory installs at build time.
/// A uv lockfile lowers to the IR's Python declaration; which wheels it
/// installs is decided when the lockfile is read from the source snapshot,
/// and recorded with [`record_python_environment`].
///
/// Requests the current IR and Nix factories cannot honor are refused rather
/// than dropped: exact package versions (nixpkgs is pinned only through the mvm revision),
/// Python dependency files other than a uv lockfile at the source root, uv
/// dependencies without exactly one `python3NN` interpreter package, non-npm
/// Node lockfiles (nothing installs them for a command workload yet), and
/// copies outside the application tree.
///
/// The IR has one package list, so only runtime packages go in the image.
/// Build-scoped packages ride in the pack extension, which the workload digest
/// covers, and the generated flake puts them on the build derivations only.
pub fn lower(spec: &PackSpec) -> Result<Workload, PackError> {
    spec.validate()?;
    let packages = scoped_packages(spec, PackageScope::Runtime)?;
    let build_packages = build_packages(spec)?;
    let dependencies = lower_dependencies(spec)?;
    let path = source_path(spec)?;
    let id = workload_id(spec);
    let workload = Workload {
        schema_version: format!("{IR_MAJOR}.{IR_MINOR}"),
        id: id.clone(),
        apps: vec![App {
            name: id,
            source: Source::LocalPath {
                path,
                include: vec!["**".to_string()],
                exclude: Vec::new(),
            },
            image: Image::NixPackages { packages },
            entrypoints: vec![Entrypoint::Command {
                command: spec.entrypoint.clone(),
                working_dir: APP_DIR.to_string(),
                env: BTreeMap::new(),
            }],
            env: BTreeMap::new(),
            mounts: Vec::new(),
            network: None,
            resources: Resources {
                cpu_cores: spec.resources.cpu_cores,
                memory_mb: spec.resources.memory_mb,
                rootfs_size_mb: PACK_ROOTFS_SIZE_MIB,
            },
            dependencies,
            threat_tier: Default::default(),
            addons: Vec::new(),
            hooks: Default::default(),
            files: Vec::new(),
            health_check: None,
        }],
        volumes: Vec::new(),
        extensions: pack_extension(spec, &build_packages),
    };
    validate(&workload).map_err(PackError::InvalidWorkload)?;
    Ok(workload)
}

/// Names of the packages in `scope`, in authored order.
fn scoped_packages(spec: &PackSpec, scope: PackageScope) -> Result<Vec<String>, PackError> {
    spec.packages
        .iter()
        .filter(|package| package.scope == scope)
        .map(|package| {
            if let Some(version) = &package.version {
                return Err(PackError::UnsupportedPackageVersion {
                    package: package.name.clone(),
                    version: version.clone(),
                });
            }
            Ok(package.name.clone())
        })
        .collect()
}

/// At most one dependency declaration: an npm lockfile or a uv lockfile at
/// the source root, the shapes the factory installs for a command workload.
fn lower_dependencies(spec: &PackSpec) -> Result<Option<Dependencies>, PackError> {
    match spec.dependencies.as_slice() {
        [] => Ok(None),
        [
            DependencyFiles::Node {
                tool: NodeTool::Npm,
                manifest,
                lockfile,
            },
        ] if manifest == NPM_MANIFEST && lockfile == NPM_LOCKFILE => Ok(Some(Dependencies::Node {
            lockfile: NPM_LOCKFILE.to_string(),
            tool: NodeTool::Npm,
        })),
        [DependencyFiles::Node { .. }] => Err(PackError::UnsupportedNodeDependencies),
        [
            DependencyFiles::Python {
                tool: PythonTool::Uv,
                manifest,
                lockfile,
            },
        ] if manifest == UV_MANIFEST && lockfile == UV_LOCKFILE => {
            Interpreter::from_spec(spec)?;
            Ok(Some(Dependencies::Python {
                lockfile: UV_LOCKFILE.to_string(),
                tool: PythonTool::Uv,
            }))
        }
        [
            DependencyFiles::Python {
                tool,
                manifest,
                lockfile,
            },
        ] => Err(PythonError::UnsupportedShape {
            tool: python_tool_name(*tool).to_string(),
            manifest: manifest.clone(),
            lockfile: lockfile.clone(),
        }
        .into()),
        _ => Err(PackError::MultipleDependencies),
    }
}

fn python_tool_name(tool: PythonTool) -> &'static str {
    match tool {
        PythonTool::Uv => "uv",
        PythonTool::PipTools => "pip_tools",
    }
}

/// Record the environment resolved from the pack's uv lockfile in the
/// workload's pack extension. The extension is part of the workload digest,
/// so a lock taken over this workload binds the exact wheel set.
pub(super) fn record_python_environment(
    workload: &mut Workload,
    environment: &PythonEnvironment,
) -> Result<(), PackError> {
    let value = serde_json::to_value(environment).map_err(PackError::Digest)?;
    if let Some(serde_json::Value::Object(pack)) = workload.extensions.get_mut(PACK_EXTENSION) {
        pack.insert(PACK_PYTHON_KEY.to_string(), value);
    }
    Ok(())
}

/// The tree the compiler reads: the authored source, or the tree assembled
/// from copy operations, each of which must land inside [`APP_DIR`].
fn source_path(spec: &PackSpec) -> Result<String, PackError> {
    let PackSource::Local { path } = &spec.source;
    if spec.copy.is_empty() {
        return Ok(path.clone());
    }
    for copy in &spec.copy {
        app_relative(&copy.destination)?;
    }
    Ok(APP_TREE.to_string())
}

/// A copy destination's path inside the application tree. The tree itself is
/// not a valid destination, and neither is anything outside it: the image
/// carries no other writable location a pack can populate.
pub(crate) fn app_relative(destination: &str) -> Result<&str, PackError> {
    destination
        .strip_prefix(APP_DIR)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|rest| !rest.is_empty())
        .ok_or_else(|| PackError::CopyOutsideApp {
            destination: destination.to_string(),
        })
}

/// The name segment of `namespace/name`. IR validation refuses a segment the
/// IR id grammar cannot carry instead of rewriting it.
fn workload_id(spec: &PackSpec) -> String {
    spec.identity
        .name
        .split_once('/')
        .map_or(spec.identity.name.as_str(), |(_, name)| name)
        .to_string()
}

/// Build-scoped package names in authored order.
pub(super) fn build_packages(spec: &PackSpec) -> Result<Vec<String>, PackError> {
    scoped_packages(spec, PackageScope::Build)
}

fn pack_extension(
    spec: &PackSpec,
    build_packages: &[String],
) -> BTreeMap<String, serde_json::Value> {
    let mut value = serde_json::json!({
        "name": spec.identity.name,
        "version": spec.identity.version,
        "target": spec.target,
    });
    if !build_packages.is_empty() {
        value[PACK_BUILD_PACKAGES_KEY] = serde_json::json!(build_packages);
    }
    BTreeMap::from([(PACK_EXTENSION.to_string(), value)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::test_support::spec;
    use mvm_contract::ir::{ErrorCode, ir_hash};
    use mvm_contract::pack_spec::{CopyOperation, PackageRequest};

    #[test]
    fn lowers_identity_packages_entrypoint_and_resources() {
        let workload = lower(&spec()).unwrap();
        assert_eq!(workload.id, "hello");
        assert_eq!(workload.schema_version, format!("{IR_MAJOR}.{IR_MINOR}"));
        let app = &workload.apps[0];
        assert_eq!(app.name, "hello");
        assert_eq!(
            app.source,
            Source::LocalPath {
                path: ".".into(),
                include: vec!["**".into()],
                exclude: vec![],
            }
        );
        assert_eq!(
            app.image,
            Image::NixPackages {
                packages: vec!["busybox".into(), "jq".into()]
            }
        );
        assert_eq!(
            app.entrypoints,
            vec![Entrypoint::Command {
                command: vec!["cat".into(), "/app/hello.txt".into()],
                working_dir: "/app".into(),
                env: BTreeMap::new(),
            }]
        );
        assert_eq!(
            app.resources,
            Resources {
                cpu_cores: 1,
                memory_mb: 128,
                rootfs_size_mb: PACK_ROOTFS_SIZE_MIB,
            }
        );
        assert!(app.network.is_none());
        assert!(app.dependencies.is_none());
        assert_eq!(
            workload.extensions[PACK_EXTENSION],
            serde_json::json!({
                "name": "acme/hello",
                "version": "1.0.0",
                "target": "aarch64-linux",
            })
        );
    }

    #[test]
    fn lowering_is_deterministic() {
        let first = lower(&spec()).unwrap();
        let second = lower(&spec()).unwrap();
        assert_eq!(first, second);
        assert_eq!(ir_hash(&first).unwrap(), ir_hash(&second).unwrap());
    }

    #[test]
    fn identity_and_target_change_the_lowered_digest() {
        let base = ir_hash(&lower(&spec()).unwrap()).unwrap();
        let mut renamed = spec();
        renamed.identity.name = "other/hello".into();
        assert_ne!(ir_hash(&lower(&renamed).unwrap()).unwrap(), base);
        let mut retargeted = spec();
        retargeted.target = mvm_contract::pack_spec::PackTarget::X86_64Linux;
        assert_ne!(ir_hash(&lower(&retargeted).unwrap()).unwrap(), base);
    }

    #[test]
    fn build_scoped_packages_stay_out_of_the_image_and_into_the_digest() {
        let base = spec();
        let mut scoped = spec();
        scoped.packages.push(PackageRequest {
            name: "gcc".into(),
            version: None,
            scope: PackageScope::Build,
        });
        let workload = lower(&scoped).unwrap();
        assert_eq!(workload.apps[0].image, lower(&base).unwrap().apps[0].image);
        assert_eq!(
            workload.extensions[PACK_EXTENSION][PACK_BUILD_PACKAGES_KEY],
            serde_json::json!(["gcc"])
        );
        assert_ne!(
            ir_hash(&workload).unwrap(),
            ir_hash(&lower(&base).unwrap()).unwrap()
        );
    }

    #[test]
    fn a_versioned_build_package_is_refused() {
        let mut spec = spec();
        spec.packages.push(PackageRequest {
            name: "gcc".into(),
            version: Some("13".into()),
            scope: PackageScope::Build,
        });
        assert!(matches!(
            lower(&spec),
            Err(PackError::UnsupportedPackageVersion { package, .. }) if package == "gcc"
        ));
    }

    #[test]
    fn exact_package_versions_are_refused() {
        let mut spec = spec();
        spec.packages[0].version = Some("1.36.1".into());
        assert!(matches!(
            lower(&spec),
            Err(PackError::UnsupportedPackageVersion { package, version })
                if package == "busybox" && version == "1.36.1"
        ));
    }

    fn with_dependencies(dependencies: Vec<DependencyFiles>) -> PackSpec {
        let mut spec = spec();
        spec.dependencies = dependencies;
        spec
    }

    fn npm(manifest: &str, lockfile: &str) -> DependencyFiles {
        DependencyFiles::Node {
            tool: NodeTool::Npm,
            manifest: manifest.into(),
            lockfile: lockfile.into(),
        }
    }

    #[test]
    fn an_npm_lockfile_lowers_to_node_dependencies() {
        let workload = lower(&with_dependencies(vec![npm(
            "package.json",
            "package-lock.json",
        )]))
        .unwrap();
        assert_eq!(
            workload.apps[0].dependencies,
            Some(Dependencies::Node {
                lockfile: "package-lock.json".into(),
                tool: NodeTool::Npm,
            })
        );
    }

    fn uv(manifest: &str, lockfile: &str) -> DependencyFiles {
        DependencyFiles::Python {
            tool: PythonTool::Uv,
            manifest: manifest.into(),
            lockfile: lockfile.into(),
        }
    }

    fn with_python(dependency: DependencyFiles) -> PackSpec {
        let mut spec = with_dependencies(vec![dependency]);
        spec.packages.push(PackageRequest {
            name: "python312".into(),
            version: None,
            scope: PackageScope::Runtime,
        });
        spec
    }

    #[test]
    fn a_uv_lockfile_lowers_to_python_dependencies() {
        let workload = lower(&with_python(uv("pyproject.toml", "uv.lock"))).unwrap();
        assert_eq!(
            workload.apps[0].dependencies,
            Some(Dependencies::Python {
                lockfile: "uv.lock".into(),
                tool: PythonTool::Uv,
            })
        );
        assert!(
            workload.extensions[PACK_EXTENSION]
                .get(PACK_PYTHON_KEY)
                .is_none(),
            "lowering reads no lockfile; the environment is recorded after resolution"
        );
    }

    #[test]
    fn python_dependency_shapes_other_than_uv_at_the_root_are_refused() {
        for dependency in [
            uv("app/pyproject.toml", "app/uv.lock"),
            uv("pyproject.toml", "requirements.lock"),
            DependencyFiles::Python {
                tool: PythonTool::PipTools,
                manifest: "requirements.in".into(),
                lockfile: "requirements.txt".into(),
            },
        ] {
            assert!(
                matches!(
                    lower(&with_python(dependency.clone())),
                    Err(PackError::Python(PythonError::UnsupportedShape { .. }))
                ),
                "{dependency:?}"
            );
        }
    }

    #[test]
    fn uv_dependencies_without_an_interpreter_package_are_refused() {
        let spec = with_dependencies(vec![uv("pyproject.toml", "uv.lock")]);
        assert!(matches!(
            lower(&spec),
            Err(PackError::Python(PythonError::NoInterpreter))
        ));
    }

    #[test]
    fn a_recorded_environment_changes_the_workload_digest() {
        let mut workload = lower(&with_python(uv("pyproject.toml", "uv.lock"))).unwrap();
        let before = ir_hash(&workload).unwrap();
        let environment = PythonEnvironment {
            interpreter: "python312".into(),
            wheels: vec![crate::pack::python::LockedWheel {
                name: "a".into(),
                version: "1.0".into(),
                filename: "a-1.0-py3-none-any.whl".into(),
                url: "https://files.example/a-1.0-py3-none-any.whl".into(),
                sha256: "0".repeat(64),
            }],
        };
        record_python_environment(&mut workload, &environment).unwrap();
        assert_eq!(
            workload.extensions[PACK_EXTENSION][PACK_PYTHON_KEY]["wheels"][0]["name"],
            "a"
        );
        assert_ne!(ir_hash(&workload).unwrap(), before);
    }

    #[test]
    fn other_node_lockfile_shapes_are_refused() {
        for dependency in [
            npm("web/package.json", "web/package-lock.json"),
            npm("package.json", "npm-shrinkwrap.json"),
            DependencyFiles::Node {
                tool: NodeTool::Pnpm,
                manifest: "package.json".into(),
                lockfile: "pnpm-lock.yaml".into(),
            },
        ] {
            assert!(matches!(
                lower(&with_dependencies(vec![dependency])),
                Err(PackError::UnsupportedNodeDependencies)
            ));
        }
    }

    #[test]
    fn more_than_one_dependency_declaration_is_refused() {
        let spec = with_dependencies(vec![
            npm("package.json", "package-lock.json"),
            npm("package.json", "package-lock.json"),
        ]);
        assert!(matches!(lower(&spec), Err(PackError::MultipleDependencies)));
    }

    #[test]
    fn copies_lower_to_the_assembled_application_tree() {
        let mut spec = spec();
        spec.copy.push(CopyOperation {
            source: "hello.txt".into(),
            destination: "/app/hello.txt".into(),
        });
        let workload = lower(&spec).unwrap();
        assert!(matches!(
            &workload.apps[0].source,
            Source::LocalPath { path, .. } if path == APP_TREE
        ));
    }

    #[test]
    fn copies_outside_the_application_tree_are_refused() {
        for destination in ["/app", "/etc/hello.txt", "/application/x", "/apps/x"] {
            let mut spec = spec();
            spec.copy.push(CopyOperation {
                source: "hello.txt".into(),
                destination: destination.into(),
            });
            assert!(
                matches!(lower(&spec), Err(PackError::CopyOutsideApp { .. })),
                "{destination}"
            );
        }
    }

    #[test]
    fn names_outside_the_ir_id_grammar_are_refused_not_rewritten() {
        let mut spec = spec();
        spec.identity.name = "acme/hello.world".into();
        let Err(PackError::InvalidWorkload(errors)) = lower(&spec) else {
            panic!("expected IR validation failure");
        };
        assert!(errors.iter().any(|e| e.code == ErrorCode::InvalidId));
    }

    #[test]
    fn shell_entrypoints_fail_ir_validation() {
        let mut spec = spec();
        spec.entrypoint = vec!["sh".into(), "-c".into(), "echo hi".into()];
        let Err(PackError::InvalidWorkload(errors)) = lower(&spec) else {
            panic!("expected IR validation failure");
        };
        assert!(
            errors
                .iter()
                .any(|e| e.code == ErrorCode::ShellEntrypointForbidden)
        );
    }

    #[test]
    fn invalid_specs_are_refused_before_lowering() {
        let mut spec = spec();
        spec.entrypoint.clear();
        assert!(matches!(lower(&spec), Err(PackError::Spec(_))));
    }
}
