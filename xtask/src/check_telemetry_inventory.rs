//! Static binary inventory, not evidence that a telemetry path is operational.
//!
//! This offline, allocation-conscious maintenance gate delegates target discovery
//! to Cargo, including implicit and feature-gated targets. It does not execute
//! binaries, infer subscriber installation, or certify a backend's coverage.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const INVENTORY: &str = "specs/telemetry/binaries.toml";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u32,
    binary: Vec<Binary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binary {
    package: String,
    name: String,
    source: PathBuf,
    required_features: BTreeSet<String>,
    capture: Capture,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Capture {
    RuntimeGap {
        role: Role,
        owner: String,
        signals: BTreeSet<Signal>,
        entrypoint: String,
        gap: String,
        required_witness: String,
    },
    NonRuntime {
        category: NonRuntimeCategory,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    WorkloadGuest,
    BuilderGuest,
    Host,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Signal {
    Diagnostics,
    Spans,
    Events,
    Stdio,
    Logs,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NonRuntimeCategory {
    CodeGenerator,
    TestFixture,
    DeveloperTool,
    ArtifactTool,
}

// Cargo owns this schema; only the fields needed for discovery are projected.
#[derive(Debug, Deserialize)]
struct Metadata {
    workspace_members: BTreeSet<String>,
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    targets: Vec<Target>,
}

#[derive(Debug, Deserialize)]
struct Target {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
    #[serde(default, rename = "required-features")]
    required_features: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct BinaryTarget {
    package: String,
    name: String,
    source: PathBuf,
    required_features: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct Summary {
    runtime_gaps: usize,
    non_runtime: usize,
}

fn discover(workspace: &Path) -> Result<Vec<BinaryTarget>> {
    let workspace = workspace.canonicalize().context("resolve workspace root")?;
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--locked",
        ])
        .current_dir(&workspace)
        .output()
        .context("discover telemetry binary targets with cargo metadata")?;
    ensure!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
    let mut binaries = Vec::new();
    for package in metadata.packages {
        if !metadata.workspace_members.contains(&package.id) {
            continue;
        }
        for target in package.targets {
            if !target.kind.iter().any(|kind| kind == "bin") {
                continue;
            }
            let source = target
                .src_path
                .canonicalize()
                .with_context(|| format!("resolve binary source {}", target.src_path.display()))?
                .strip_prefix(&workspace)
                .with_context(|| {
                    format!(
                        "binary {}/{} is outside the workspace",
                        package.name, target.name
                    )
                })?
                .to_path_buf();
            binaries.push(BinaryTarget {
                package: package.name.clone(),
                name: target.name,
                source,
                required_features: target.required_features,
            });
        }
    }
    ensure!(
        !binaries.is_empty(),
        "Cargo discovered no workspace binaries"
    );
    Ok(binaries)
}

fn validate_binary(root: &Path, binary: &Binary, target: &BinaryTarget) -> Result<()> {
    ensure!(
        binary.source == target.source,
        "source path drift: expected {}",
        target.source.display()
    );
    ensure!(
        binary.required_features == target.required_features,
        "required feature drift: expected {:?}",
        target.required_features
    );
    ensure!(
        !binary.source.as_os_str().is_empty()
            && binary
                .source
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "source must be workspace-relative without traversal"
    );
    let source = std::fs::read_to_string(root.join(&binary.source))
        .with_context(|| format!("read {}", binary.source.display()))?;
    match &binary.capture {
        Capture::RuntimeGap {
            owner,
            signals,
            entrypoint,
            gap,
            required_witness,
            ..
        } => {
            for (field, value) in [
                ("owner", owner),
                ("entrypoint", entrypoint),
                ("gap", gap),
                ("required_witness", required_witness),
            ] {
                ensure!(!value.trim().is_empty(), "{field} must not be empty");
            }
            ensure!(!signals.is_empty(), "runtime source needs declared signals");
            ensure!(
                source.contains(entrypoint),
                "entrypoint anchor not found in {}",
                binary.source.display()
            );
        }
        Capture::NonRuntime { reason, .. } => ensure!(
            !reason.trim().is_empty(),
            "non-runtime classification requires a reason"
        ),
    }
    Ok(())
}

fn validate(root: &Path, inventory: &Inventory, targets: &[BinaryTarget]) -> Result<Summary> {
    ensure!(
        inventory.version == 1,
        "unsupported telemetry inventory version {}",
        inventory.version
    );
    ensure!(
        !inventory.binary.is_empty() && !targets.is_empty(),
        "telemetry binary inventory and discovered targets must not be empty"
    );
    let mut pending: BTreeMap<_, _> = targets
        .iter()
        .map(|target| ((target.package.as_str(), target.name.as_str()), target))
        .collect();
    ensure!(
        pending.len() == targets.len(),
        "duplicate discovered binary"
    );
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    let mut summary = Summary::default();
    for binary in &inventory.binary {
        let key = (binary.package.as_str(), binary.name.as_str());
        let label = format!("{}/{}", binary.package, binary.name);
        if !seen.insert(key) {
            errors.push(format!("duplicate inventory binary {label}"));
            continue;
        }
        let Some(target) = pending.remove(&key) else {
            errors.push(format!("stale inventory binary {label}"));
            continue;
        };
        if let Err(error) = validate_binary(root, binary, target) {
            errors.push(format!("{label}: {error:#}"));
        }
        match binary.capture {
            Capture::RuntimeGap { .. } => summary.runtime_gaps += 1,
            Capture::NonRuntime { .. } => summary.non_runtime += 1,
        }
    }
    for (package, name) in pending.keys() {
        errors.push(format!("unregistered binary {package}/{name}"));
    }
    if !errors.is_empty() {
        bail!("telemetry inventory drift:\n  {}", errors.join("\n  "));
    }
    Ok(summary)
}

/// Validate static target classification without certifying runtime capture.
pub fn run(workspace: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(workspace.join(INVENTORY)).context("read telemetry inventory")?;
    let inventory: Inventory = toml::from_str(&text).context("parse telemetry inventory")?;
    let summary = validate(workspace, &inventory, &discover(workspace)?)?;
    eprintln!(
        "check-telemetry-inventory: {} runtime gaps, {} non-runtime binaries classified; runtime coverage is NOT certified",
        summary.runtime_gaps, summary.non_runtime
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Inventory, Vec<BinaryTarget>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        let inventory: Inventory = toml::from_str(
            r#"
version = 1
[[binary]]
package = "agent"
name = "agent"
source = "src/main.rs"
required_features = ["guest"]
[binary.capture]
kind = "runtime-gap"
role = "workload-guest"
owner = "guest init"
signals = ["diagnostics", "spans", "events", "logs", "stdio"]
entrypoint = "fn main("
gap = "No VM-lifetime authenticated telemetry collector."
required_witness = "Detached host receives source startup and standalone event."
"#,
        )
        .unwrap();
        let targets = vec![BinaryTarget {
            package: "agent".into(),
            name: "agent".into(),
            source: "src/main.rs".into(),
            required_features: BTreeSet::from(["guest".into()]),
        }];
        (root, inventory, targets)
    }

    #[test]
    fn explicit_runtime_gap_is_a_valid_inventory_not_coverage() {
        let (root, inventory, targets) = fixture();
        let summary = validate(root.path(), &inventory, &targets).unwrap();
        assert_eq!(summary.runtime_gaps, 1);
        assert_eq!(summary.non_runtime, 0);
    }

    #[test]
    fn new_binary_fails_until_classified() {
        let (root, inventory, mut targets) = fixture();
        let mut added = targets[0].clone();
        added.name = "new-helper".into();
        targets.push(added);
        let error = validate(root.path(), &inventory, &targets).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unregistered binary agent/new-helper")
        );
    }

    #[test]
    fn removed_binary_leaves_an_error_not_stale_credit() {
        let (root, mut inventory, targets) = fixture();
        let mut removed = inventory.binary[0].clone();
        removed.name = "removed".into();
        inventory.binary.push(removed);
        let error = validate(root.path(), &inventory, &targets).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("stale inventory binary agent/removed")
        );
    }

    #[test]
    fn duplicate_entry_is_rejected() {
        let (root, mut inventory, targets) = fixture();
        inventory.binary.push(inventory.binary[0].clone());
        assert!(
            validate(root.path(), &inventory, &targets)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn path_and_feature_drift_require_inventory_review() {
        let (root, inventory, targets) = fixture();
        let mut changed = targets.clone();
        changed[0].source = "src/moved.rs".into();
        assert!(validate(root.path(), &inventory, &changed).is_err());
        changed = targets;
        changed[0].required_features.clear();
        assert!(validate(root.path(), &inventory, &changed).is_err());
    }

    #[test]
    fn missing_source_or_entrypoint_fails() {
        let (root, inventory, targets) = fixture();
        std::fs::write(root.path().join("src/main.rs"), "// renamed entrypoint\n").unwrap();
        assert!(validate(root.path(), &inventory, &targets).is_err());
        std::fs::remove_file(root.path().join("src/main.rs")).unwrap();
        assert!(validate(root.path(), &inventory, &targets).is_err());
    }

    #[test]
    fn unknown_fields_statuses_and_versions_fail_closed() {
        let (root, mut inventory, targets) = fixture();
        inventory.version = 2;
        assert!(
            validate(root.path(), &inventory, &targets)
                .unwrap_err()
                .to_string()
                .contains("unsupported telemetry inventory version")
        );
        inventory.version = 1;
        let base = serde_json::to_value(&inventory).unwrap();
        let mut changed = base.clone();
        changed["surprise"] = json!(true);
        assert!(serde_json::from_value::<Inventory>(changed).is_err());
        let mut changed = base.clone();
        changed["binary"][0]["capture"]["kind"] = json!("covered");
        assert!(serde_json::from_value::<Inventory>(changed).is_err());
        let mut changed = base;
        changed["binary"][0]["capture"]["surprise"] = json!(true);
        assert!(serde_json::from_value::<Inventory>(changed).is_err());
    }

    #[test]
    fn classification_requires_nonempty_evidence_and_signals() {
        let (root, inventory, targets) = fixture();
        let base = serde_json::to_value(&inventory).unwrap();
        for field in ["owner", "entrypoint", "gap", "required_witness"] {
            let mut changed = base.clone();
            changed["binary"][0]["capture"][field] = json!("  ");
            let inventory = serde_json::from_value(changed).unwrap();
            assert!(
                validate(root.path(), &inventory, &targets).is_err(),
                "{field}"
            );
        }
        let mut changed = base;
        changed["binary"][0]["capture"]["signals"] = json!([]);
        let inventory = serde_json::from_value(changed).unwrap();
        assert!(validate(root.path(), &inventory, &targets).is_err());
    }

    #[test]
    fn non_runtime_tools_need_a_reason_and_never_count_as_runtime() {
        let (root, mut inventory, targets) = fixture();
        inventory.binary[0].capture = Capture::NonRuntime {
            category: NonRuntimeCategory::TestFixture,
            reason: "Only a protocol test fixture; not installed in production images.".into(),
        };
        let summary = validate(root.path(), &inventory, &targets).unwrap();
        assert_eq!(summary.runtime_gaps, 0);
        assert_eq!(summary.non_runtime, 1);
        inventory.binary[0].capture = Capture::NonRuntime {
            category: NonRuntimeCategory::TestFixture,
            reason: String::new(),
        };
        assert!(validate(root.path(), &inventory, &targets).is_err());
    }

    #[test]
    fn cargo_discovers_implicit_and_feature_gated_binaries() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/bin/implicit")).unwrap();
        std::fs::write(
            root.path().join("Cargo.toml"),
            r#"
[package]
name = "inventory-fixture"
version = "0.1.0"
edition = "2024"
[workspace]
[features]
hidden = []
[[bin]]
name = "feature-gated"
path = "src/feature.rs"
required-features = ["hidden"]
"#,
        )
        .unwrap();
        for file in ["src/main.rs", "src/feature.rs", "src/bin/implicit/main.rs"] {
            std::fs::write(root.path().join(file), "fn main() {}\n").unwrap();
        }
        let targets = discover(root.path()).unwrap();
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().any(|t| t.name == "implicit"));
        assert!(
            targets
                .iter()
                .any(|t| t.name == "feature-gated" && t.required_features.contains("hidden"))
        );
    }

    #[test]
    fn invalid_workspace_returns_error() {
        let root = tempfile::tempdir().unwrap();
        assert!(discover(root.path()).is_err());
    }

    #[test]
    fn inventory_roundtrip_preserves_the_classification() {
        let (root, inventory, targets) = fixture();
        let encoded = toml::to_string(&inventory).unwrap();
        let decoded: Inventory = toml::from_str(&encoded).unwrap();
        assert_eq!(
            serde_json::to_value(&inventory).unwrap(),
            serde_json::to_value(&decoded).unwrap()
        );
        assert_eq!(
            validate(root.path(), &decoded, &targets)
                .unwrap()
                .runtime_gaps,
            1
        );
    }

    #[test]
    fn empty_inventory_and_duplicate_discovery_fail() {
        let (root, mut inventory, mut targets) = fixture();
        targets.push(targets[0].clone());
        assert!(validate(root.path(), &inventory, &targets).is_err());
        targets.pop();
        inventory.binary.clear();
        assert!(validate(root.path(), &inventory, &targets).is_err());
    }

    #[test]
    fn missing_or_malformed_inventory_returns_contextual_error() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            run(root.path())
                .unwrap_err()
                .to_string()
                .contains("read telemetry inventory")
        );
        std::fs::create_dir_all(root.path().join("specs/telemetry")).unwrap();
        std::fs::write(root.path().join(INVENTORY), "not = [valid").unwrap();
        assert!(
            run(root.path())
                .unwrap_err()
                .to_string()
                .contains("parse telemetry inventory")
        );
    }

    #[test]
    fn source_traversal_is_rejected_even_if_discovery_matches() {
        let (root, mut inventory, mut targets) = fixture();
        for path in ["../outside.rs", "/outside.rs"] {
            inventory.binary[0].source = path.into();
            targets[0].source = path.into();
            assert!(
                validate(root.path(), &inventory, &targets)
                    .unwrap_err()
                    .to_string()
                    .contains("without traversal")
            );
        }
    }

    #[test]
    fn inventory_keeps_protocol_and_result_outputs_out_of_stdio() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = std::fs::read_to_string(root.join(INVENTORY)).unwrap();
        let inventory: Inventory = toml::from_str(&text).unwrap();
        for (package, name) in [
            ("mvm-agentd", "mvm-runner"),
            ("mvm-hostd", "mvm-extension-provider"),
            ("mvmctl", "mvmctl"),
        ] {
            let binary = inventory
                .binary
                .iter()
                .find(|b| b.package == package && b.name == name)
                .unwrap();
            let Capture::RuntimeGap { signals, .. } = &binary.capture else {
                panic!("{name} diagnostics must remain in the runtime inventory");
            };
            assert!(signals.contains(&Signal::Diagnostics));
            assert!(
                !signals.contains(&Signal::Stdio),
                "{name} protocol/result bytes are not telemetry"
            );
        }
    }

    #[test]
    fn real_workspace_inventory_matches() {
        run(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()).unwrap();
    }
}
