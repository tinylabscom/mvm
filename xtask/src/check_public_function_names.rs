//! Ratchet public `f` / `f_with_*` sibling pairs down module by module.

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_SIBLING_PAIRS: usize = 24;
const CLEARED_MODULES: &[&str] = &[
    "crates/mvm-build/src/builder_backend_select.rs",
    "crates/mvm-build/src/builder_vm_runtime.rs",
    "crates/mvm-build/src/builderd.rs",
    "crates/mvm-build/src/pipeline/build.rs",
    "crates/mvm-build/src/pipeline/orchestrator.rs",
    "crates/mvm-build/src/rootfs.rs",
    "crates/mvm-cli/src/commands/deps/audit.rs",
    "crates/mvm-cli/src/commands/env/builder_vm/vm_helpers.rs",
    "crates/mvm-cli/src/commands/machine/prewarm.rs",
    "crates/mvm-cli/src/commands/vm/console.rs",
    "crates/mvm-cli/src/commands/vm/exec.rs",
    "crates/mvm-cli/src/commands/vm/exec/preflight.rs",
    "crates/mvm-cli/src/commands/vm/fs.rs",
    "crates/mvm-cli/src/config_watcher.rs",
    "crates/mvm-cli/src/exec.rs",
    "crates/mvm-client/src/admission/policy_resolver.rs",
    "crates/mvm-client/src/admission/run_network.rs",
    "crates/mvm-contract/src/policy/network_policy.rs",
    "crates/mvm-contract/src/protocol/network_flow/state.rs",
    "crates/mvm-fs/src/ext4/mod.rs",
    "crates/mvm-hostd/src/broker/daemon.rs",
    "crates/mvm-hostd/src/plan_admission.rs",
    "crates/mvm-observability/src/logging.rs",
    "crates/mvm-runtime/src/backend.rs",
    "crates/mvm-runtime/src/microvm/boot_config.rs",
    "crates/mvm-runtime/src/mock_guest_agent.rs",
    "crates/mvm-runtime/src/vm/name_registry.rs",
    "crates/mvm-runtime/src/warm_artifact_builder.rs",
    "crates/mvm-runtime/src/warm_artifacts.rs",
    "crates/mvm-sdk/src/runtime.rs",
    "crates/mvm-vmm/src/quota/controller.rs",
    "crates/mvm-vmm/src/vmm/run.rs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SiblingPair {
    path: String,
    base: String,
    extended: String,
}

pub fn run(workspace: &Path) -> Result<()> {
    let pairs = sibling_pairs(workspace)?;
    validate(&pairs, MAX_SIBLING_PAIRS, CLEARED_MODULES)?;
    eprintln!(
        "check-public-function-names: {} sibling pairs remain; {} modules cleared",
        pairs.len(),
        CLEARED_MODULES.len()
    );
    Ok(())
}

fn sibling_pairs(workspace: &Path) -> Result<Vec<SiblingPair>> {
    let function_pattern = Regex::new(
        r#"(?m)^\s*pub(?:\([^)]*\))?\s+(?:(?:const|async|unsafe)\s+|extern\s+"[^"]+"\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)"#,
    )?;
    let mut functions_by_file = BTreeMap::<String, BTreeSet<String>>::new();
    crate::fs_walk::for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, contents| {
            let Ok(relative) = path.strip_prefix(workspace) else {
                return;
            };
            let names = functions_by_file
                .entry(relative.to_string_lossy().into_owned())
                .or_default();
            for captures in function_pattern.captures_iter(contents) {
                names.insert(captures[1].to_string());
            }
        },
    )?;

    let mut pairs = Vec::new();
    for (path, names) in functions_by_file {
        for extended in &names {
            let Some((base, _)) = extended.split_once("_with_") else {
                continue;
            };
            if names.contains(base) {
                pairs.push(SiblingPair {
                    path: path.clone(),
                    base: base.to_string(),
                    extended: extended.clone(),
                });
            }
        }
    }
    Ok(pairs)
}

fn validate(pairs: &[SiblingPair], maximum: usize, cleared_modules: &[&str]) -> Result<()> {
    let cleared_regressions: Vec<&SiblingPair> = pairs
        .iter()
        .filter(|pair| cleared_modules.contains(&pair.path.as_str()))
        .collect();
    if !cleared_regressions.is_empty() {
        bail!(
            "public function sibling pairs returned to a cleared module: {}",
            format_pairs(cleared_regressions.into_iter())
        );
    }
    if pairs.len() > maximum {
        bail!(
            "public function sibling pairs grew from the ratcheted maximum {maximum} to {}: {}",
            pairs.len(),
            format_pairs(pairs.iter())
        );
    }
    Ok(())
}

fn format_pairs<'a>(pairs: impl Iterator<Item = &'a SiblingPair>) -> String {
    pairs
        .map(|pair| format!("{}:{} / {}", pair.path, pair.base, pair.extended))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("test path has a parent"))
            .expect("create test directory");
        std::fs::write(path, contents).expect("write test fixture");
    }

    #[test]
    fn finds_public_siblings_in_the_same_file() {
        let workspace = tempfile::tempdir().expect("tempdir");
        write(
            &workspace.path().join("crates/demo/src/lib.rs"),
            "pub fn open() {}\npub async fn open_with_policy() {}\nfn private_with_policy() {}\n",
        );

        assert_eq!(
            sibling_pairs(workspace.path()).expect("scan succeeds"),
            vec![SiblingPair {
                path: "crates/demo/src/lib.rs".to_string(),
                base: "open".to_string(),
                extended: "open_with_policy".to_string(),
            }]
        );
    }

    #[test]
    fn does_not_pair_functions_from_different_files() {
        let workspace = tempfile::tempdir().expect("tempdir");
        write(
            &workspace.path().join("crates/demo/src/base.rs"),
            "pub fn open() {}\n",
        );
        write(
            &workspace.path().join("crates/demo/src/extended.rs"),
            "pub fn open_with_policy() {}\n",
        );

        assert!(
            sibling_pairs(workspace.path())
                .expect("scan succeeds")
                .is_empty()
        );
    }

    #[test]
    fn rejects_growth_above_the_ratcheted_maximum() {
        let pair = SiblingPair {
            path: "crates/demo/src/lib.rs".to_string(),
            base: "open".to_string(),
            extended: "open_with_policy".to_string(),
        };
        let error = validate(&[pair], 0, &[]).expect_err("growth must fail");
        assert!(
            error
                .to_string()
                .contains("grew from the ratcheted maximum")
        );
    }

    #[test]
    fn rejects_a_pair_returning_to_a_cleared_module() {
        let pair = SiblingPair {
            path: "crates/demo/src/lib.rs".to_string(),
            base: "open".to_string(),
            extended: "open_with_policy".to_string(),
        };
        let error = validate(&[pair], 1, &["crates/demo/src/lib.rs"])
            .expect_err("cleared module regression must fail");
        assert!(error.to_string().contains("returned to a cleared module"));
    }
}
