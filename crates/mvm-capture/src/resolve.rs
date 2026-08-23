//! Deterministic resolution from raw capture report to canonical MVM IR.

pub use crate::report::ResolutionResult;

use crate::CaptureError;
use crate::report::{
    CaptureReportV1, Confidence, Observation, ObservationKind, ResolutionRecord,
    ResolutionStrategy, UnresolvedItem,
};
use mvm_contract::ir::{App, Entrypoint, EnvValue, Image, Resources, Source, Workload};
use std::collections::BTreeMap;

/// Resolve a capture report into the canonical MVM workload IR.
pub fn resolve_report(report: &CaptureReportV1) -> Result<ResolutionResult, CaptureError> {
    let mut resolved_records = Vec::new();
    let mut unresolved = Vec::new();
    let mut warnings = report.warnings.clone();

    let mut packages: Vec<String> = Vec::new();
    let mut entrypoint_command: Vec<String> = vec!["true".to_owned()];
    let mut source_path = ".".to_owned();
    let mut env: BTreeMap<String, EnvValue> = BTreeMap::new();

    let has_manifest = report
        .observations
        .iter()
        .any(|o| o.kind == ObservationKind::ProjectManifest);
    if !has_manifest {
        warnings.push("no project manifest observed; workload may be incomplete".to_owned());
    }

    for obs in &report.observations {
        match obs.kind {
            ObservationKind::ProjectManifest => {
                resolved_records.push(resolve_manifest(obs, &mut packages, &mut source_path)?);
            }
            ObservationKind::Executable => {
                if let Some(ref name) = obs.evidence.executable_name {
                    if name == "cargo" {
                        entrypoint_command = vec!["cargo".to_owned(), "run".to_owned()];
                        packages.push("cargo".to_owned());
                        packages.push("rustc".to_owned());
                        resolved_records.push(ResolutionRecord {
                            observation_id: obs.id.clone(),
                            strategy: ResolutionStrategy::NativePackage,
                            confidence: Confidence::Inferred,
                            evidence: vec!["cargo on PATH".to_owned()],
                            warnings: vec![],
                            needs_review: false,
                        });
                    }
                }
            }
            ObservationKind::NativePackage => {
                if let Some(ref name) = obs.evidence.package_name {
                    let manager = obs.evidence.package_manager.as_deref().unwrap_or("unknown");
                    if manager == "nix-index" {
                        // nix-index returns attributes like "pkg.out"; the
                        // nixpkgs attribute is the part before ".out".
                        let attr = name.strip_suffix(".out").unwrap_or(name);
                        packages.push(attr.to_owned());
                        resolved_records.push(ResolutionRecord {
                            observation_id: obs.id.clone(),
                            strategy: ResolutionStrategy::NixIndex,
                            confidence: Confidence::Inferred,
                            evidence: vec![format!(
                                "nix-index mapped {} to {}",
                                obs.evidence.observed_path.as_deref().unwrap_or("path"),
                                attr
                            )],
                            warnings: vec![
                                "nix-index mapping is heuristic and may need review".to_owned(),
                            ],
                            needs_review: false,
                        });
                    } else {
                        // Native package names are not nixpkgs attributes; keep
                        // them explicit unresolved items for this slice.
                        unresolved.push(UnresolvedItem {
                            observation_id: obs.id.clone(),
                            reason: format!(
                                "native package {} ({}) has no deterministic nixpkgs mapping yet",
                                name, manager
                            ),
                            needs_review: true,
                        });
                    }
                }
            }
            ObservationKind::ConfigurationFile if obs.path.as_deref() == Some(".env") => {
                env.insert(
                    "DATABASE_URL".to_owned(),
                    EnvValue::SecretRef {
                        reference: mvm_contract::ir::SecretRef {
                            name: "DATABASE_URL".to_owned(),
                            mount: mvm_contract::ir::SecretMount::Env {
                                var: "DATABASE_URL".to_owned(),
                            },
                            auth_type: mvm_contract::ir::AuthType::Bearer,
                            allowed_hosts: vec!["*.example.com".to_owned()],
                            sigv4: None,
                        },
                    },
                );
                resolved_records.push(ResolutionRecord {
                    observation_id: obs.id.clone(),
                    strategy: ResolutionStrategy::ProjectManifest,
                    confidence: Confidence::Inferred,
                    evidence: vec![".env observed; value treated as runtime secret".to_owned()],
                    warnings: vec!["secret value was not captured".to_owned()],
                    needs_review: true,
                });
            }
            _ => {}
        }
    }

    // Ensure at least a minimal Rust toolchain is present when Cargo is used.
    if packages.iter().any(|p| p == "cargo") && !packages.iter().any(|p| p == "gcc") {
        packages.push("gcc".to_owned());
        warnings.push(
            "cargo was observed but no linker package was identified; added gcc placeholder"
                .to_owned(),
        );
    }

    packages.sort();
    packages.dedup();

    let workload = Workload {
        schema_version: format!(
            "{}.{}",
            mvm_contract::ir::IR_MAJOR,
            mvm_contract::ir::IR_MINOR
        ),
        id: "captured-project".to_owned(),
        apps: vec![App {
            name: "app".to_owned(),
            source: Source::LocalPath {
                path: source_path,
                include: vec!["**".to_owned()],
                exclude: vec![".git".to_owned(), "target".to_owned()],
            },
            image: Image::NixPackages { packages },
            entrypoints: vec![Entrypoint::Command {
                command: entrypoint_command,
                working_dir: "/app".to_owned(),
                env,
            }],
            env: BTreeMap::new(),
            mounts: vec![],
            network: None,
            resources: Resources {
                cpu_cores: 1,
                memory_mb: 512,
                rootfs_size_mb: 1024,
            },
            dependencies: None,
            threat_tier: Default::default(),
            addons: vec![],
            hooks: Default::default(),
            files: vec![],
            health_check: None,
        }],
        volumes: vec![],
        extensions: BTreeMap::new(),
    };

    Ok(ResolutionResult {
        workload,
        resolved: resolved_records,
        unresolved,
        warnings,
        verification: Vec::new(),
    })
}

fn resolve_manifest(
    obs: &Observation,
    packages: &mut Vec<String>,
    source_path: &mut String,
) -> Result<ResolutionRecord, CaptureError> {
    let path = obs.path.as_deref().unwrap_or("unknown");
    match path {
        "Cargo.toml" => {
            packages.push("cargo".to_owned());
            packages.push("rustc".to_owned());
            *source_path = ".".to_owned();
            Ok(ResolutionRecord {
                observation_id: obs.id.clone(),
                strategy: ResolutionStrategy::ProjectManifest,
                confidence: Confidence::Inferred,
                evidence: vec!["Cargo.toml detected".to_owned()],
                warnings: vec![],
                needs_review: false,
            })
        }
        "package.json" => {
            packages.push("nodejs".to_owned());
            Ok(ResolutionRecord {
                observation_id: obs.id.clone(),
                strategy: ResolutionStrategy::ProjectManifest,
                confidence: Confidence::Inferred,
                evidence: vec!["package.json detected".to_owned()],
                warnings: vec![],
                needs_review: false,
            })
        }
        "pyproject.toml" | "requirements.txt" => {
            packages.push("python3".to_owned());
            Ok(ResolutionRecord {
                observation_id: obs.id.clone(),
                strategy: ResolutionStrategy::ProjectManifest,
                confidence: Confidence::Inferred,
                evidence: vec![format!("{} detected", path)],
                warnings: vec![],
                needs_review: false,
            })
        }
        "Dockerfile" => Ok(ResolutionRecord {
            observation_id: obs.id.clone(),
            strategy: ResolutionStrategy::ProjectManifest,
            confidence: Confidence::Heuristic,
            evidence: vec!["Dockerfile detected".to_owned()],
            warnings: vec!["Dockerfile instructions are not translated in this slice".to_owned()],
            needs_review: true,
        }),
        ".env" => Ok(ResolutionRecord {
            observation_id: obs.id.clone(),
            strategy: ResolutionStrategy::ProjectManifest,
            confidence: Confidence::Observed,
            evidence: vec![".env detected; value redacted".to_owned()],
            warnings: vec!["secret values are omitted from the workload IR".to_owned()],
            needs_review: true,
        }),
        _ => Ok(ResolutionRecord {
            observation_id: obs.id.clone(),
            strategy: ResolutionStrategy::ProjectManifest,
            confidence: Confidence::Observed,
            evidence: vec![format!("observed {}", path)],
            warnings: vec!["no specific resolver for this manifest".to_owned()],
            needs_review: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{CaptureReportV1, Confidence, Evidence, Observation, ObservationKind};
    use mvm_contract::ir::Image;

    fn nix_index_obs(package_name: &str) -> Observation {
        Observation {
            id: "pkg-test".to_owned(),
            kind: ObservationKind::NativePackage,
            path: Some("/bin/hello".to_owned()),
            source: "linux-nix-index".to_owned(),
            evidence: Evidence {
                observed_path: Some("/bin/hello".to_owned()),
                package_name: Some(package_name.to_owned()),
                package_manager: Some("nix-index".to_owned()),
                installed: true,
                ..Default::default()
            },
            confidence: Confidence::Inferred,
            warnings: vec![],
            provenance: vec![],
        }
    }

    #[test]
    fn nix_index_native_package_resolves_to_nixpkgs_attribute() {
        let mut report = CaptureReportV1::new("mvm-capture/1.0");
        report.observations.push(nix_index_obs("hello.out"));
        let result = resolve_report(&report).expect("resolve succeeds");

        let packages = match &result.workload.apps[0].image {
            Image::NixPackages { packages } => packages.clone(),
            other => panic!("expected NixPackages image, got {:?}", other),
        };
        assert!(packages.contains(&"hello".to_owned()));
        assert!(
            result
                .resolved
                .iter()
                .any(|r| r.observation_id == "pkg-test"
                    && r.strategy == ResolutionStrategy::NixIndex)
        );
        assert!(result.unresolved.is_empty());
    }

    #[test]
    fn unknown_native_package_remains_unresolved() {
        let mut report = CaptureReportV1::new("mvm-capture/1.0");
        report.observations.push(Observation {
            id: "pkg-deb".to_owned(),
            kind: ObservationKind::NativePackage,
            path: Some("/bin/foo".to_owned()),
            source: "linux-dpkg".to_owned(),
            evidence: Evidence {
                observed_path: Some("/bin/foo".to_owned()),
                package_name: Some("foo".to_owned()),
                package_manager: Some("dpkg".to_owned()),
                installed: true,
                ..Default::default()
            },
            confidence: Confidence::Observed,
            warnings: vec![],
            provenance: vec![],
        });
        let result = resolve_report(&report).expect("resolve succeeds");
        assert!(
            result
                .unresolved
                .iter()
                .any(|u| u.observation_id == "pkg-deb")
        );
    }
}
