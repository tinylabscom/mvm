//! Pure PackSpec -> Workload IR lowering. No filesystem access.

use super::PackError;
use mvm_contract::ir::{
    App, Entrypoint, IR_MAJOR, IR_MINOR, Image, Resources, Source, Workload, validate,
};
use mvm_contract::pack_spec::{PackSource, PackSpec, PackageScope};
use std::collections::BTreeMap;

/// Workload extension key carrying the full pack identity and target, which
/// the IR id cannot hold.
pub const PACK_EXTENSION: &str = "mvm.pack";

/// Root filesystem size for lowered packs. PackSpec deliberately carries no
/// rootfs request; this matches the SDK's default.
pub const PACK_ROOTFS_SIZE_MIB: u32 = 512;

/// Working directory of a lowered command, the IR's own default.
const WORKING_DIR: &str = "/app";

/// Lower a validated spec into a single-app, command-entrypoint Workload and
/// validate the result.
///
/// Requests the current IR and Nix factories cannot honor are refused rather
/// than dropped: build-scoped packages (the IR has one unscoped package list),
/// exact package versions (nixpkgs is pinned only through the mvm revision),
/// language dependency files (nothing installs them yet), and copy operations.
pub fn lower(spec: &PackSpec) -> Result<Workload, PackError> {
    spec.validate()?;
    let packages = runtime_packages(spec)?;
    reject_unmaterialized_inputs(spec)?;
    let id = workload_id(spec);
    let PackSource::Local { path } = &spec.source;
    let workload = Workload {
        schema_version: format!("{IR_MAJOR}.{IR_MINOR}"),
        id: id.clone(),
        apps: vec![App {
            name: id,
            source: Source::LocalPath {
                path: path.clone(),
                include: vec!["**".to_string()],
                exclude: Vec::new(),
            },
            image: Image::NixPackages { packages },
            entrypoints: vec![Entrypoint::Command {
                command: spec.entrypoint.clone(),
                working_dir: WORKING_DIR.to_string(),
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
            dependencies: None,
            threat_tier: Default::default(),
            addons: Vec::new(),
            hooks: Default::default(),
            files: Vec::new(),
            health_check: None,
        }],
        volumes: Vec::new(),
        extensions: pack_extension(spec),
    };
    validate(&workload).map_err(PackError::InvalidWorkload)?;
    Ok(workload)
}

/// Runtime package names in authored order.
fn runtime_packages(spec: &PackSpec) -> Result<Vec<String>, PackError> {
    spec.packages
        .iter()
        .map(|package| {
            if package.scope == PackageScope::Build {
                return Err(PackError::UnsupportedBuildScope {
                    package: package.name.clone(),
                });
            }
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

fn reject_unmaterialized_inputs(spec: &PackSpec) -> Result<(), PackError> {
    if !spec.dependencies.is_empty() {
        return Err(PackError::UnsupportedDependencies);
    }
    if !spec.copy.is_empty() {
        return Err(PackError::UnsupportedCopy);
    }
    Ok(())
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

fn pack_extension(spec: &PackSpec) -> BTreeMap<String, serde_json::Value> {
    let value = serde_json::json!({
        "name": spec.identity.name,
        "version": spec.identity.version,
        "target": spec.target,
    });
    BTreeMap::from([(PACK_EXTENSION.to_string(), value)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::test_support::spec;
    use mvm_contract::ir::{ErrorCode, PythonTool, ir_hash};
    use mvm_contract::pack_spec::{CopyOperation, DependencyFiles, PackageRequest};

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
    fn build_scoped_packages_are_refused() {
        let mut spec = spec();
        spec.packages.push(PackageRequest {
            name: "gcc".into(),
            version: None,
            scope: PackageScope::Build,
        });
        assert!(matches!(
            lower(&spec),
            Err(PackError::UnsupportedBuildScope { package }) if package == "gcc"
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

    #[test]
    fn dependency_files_are_refused_rather_than_declared() {
        let mut spec = spec();
        spec.dependencies.push(DependencyFiles::Python {
            tool: PythonTool::Uv,
            manifest: "pyproject.toml".into(),
            lockfile: "uv.lock".into(),
        });
        assert!(matches!(
            lower(&spec),
            Err(PackError::UnsupportedDependencies)
        ));
    }

    #[test]
    fn copy_operations_are_refused_rather_than_dropped() {
        let mut spec = spec();
        spec.copy.push(CopyOperation {
            source: "hello.txt".into(),
            destination: "/app/hello.txt".into(),
        });
        assert!(matches!(lower(&spec), Err(PackError::UnsupportedCopy)));
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
