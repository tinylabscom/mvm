//! Builder for `launch.json` per ADR-0006 §4.
//!
//! The launch plan is the canonical-JSON document `mvm` reads to know what to
//! run. It carries the IR's effective fields plus toolchain/IR provenance so
//! `mvm` can fail fast on configuration errors before evaluating the flake.

use crate::compile::hooks::merge_hooks;
use crate::compile::source::SourcePlan;
use mvm_ir::{Hooks, Workload, canonicalize, ir_hash};
use serde::Serialize;

/// Bumped from `"1.0"` to `"1.1"` at addon GA (ADR-0018). The
/// `addons` and `mesh` fields below are the additive payload; older
/// mvmd MUST refuse `1.1` artifacts with a clear "requires mvmd ≥ X.Y"
/// error so consumers can't silently lose addon connectivity.
pub const ARTIFACT_FORMAT_VERSION: &str = "1.1";
pub const TOOLCHAIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Stable launch-plan attribute path consumed from the generated flake.
pub const FLAKE_ATTRIBUTE: &str = "mvm.workload";

#[derive(Serialize)]
struct LaunchPlan<'a> {
    artifact_format_version: &'static str,
    flake_attribute: &'static str,
    flake_path: &'static str,
    ir_hash: String,
    ir_schema_version: &'a str,
    toolchain_version: &'static str,
    workload_id: &'a str,
    image: serde_json::Value,
    /// The workload's primary entrypoint — the function `mvmctl
    /// invoke <id>` (no `--fn` selector) dispatches. For
    /// single-entrypoint apps (the common case) this is the sole
    /// entry. For multi-function apps (ADR-0014 Phase 2) this is
    /// the entry with `primary = true`.
    entrypoint: serde_json::Value,
    /// All entrypoints, in IR order. Multi-function apps surface
    /// non-primary entries here; the wrapper resolves `--fn <name>`
    /// against this list. Single-entrypoint apps include the same
    /// single entry as `entrypoint` above.
    entrypoints: serde_json::Value,
    env: serde_json::Value,
    mounts: serde_json::Value,
    network: serde_json::Value,
    source: &'a SourcePlan,
    /// Composer's threat tier (ADR-0018). Drives mvmd's SMT-affinity
    /// scheduler matrix together with each addon's `[security].trust_tier`.
    threat_tier: serde_json::Value,
    /// Addon-uses passed through from the IR. v1 carries the raw
    /// AddonUse list (name, alias, tier, ref, sha256, params); the
    /// manifest-expanded fields (exports, persistent_storage_gb,
    /// security.seccomp_profile, egress_allowlist) are folded in by
    /// `addon::resolve_and_validate` in a follow-up patch and become
    /// the authoritative input for mvmd's instantiation flow.
    addons: serde_json::Value,
    /// Mesh declaration (ADR-0020). `enabled` is `true` whenever
    /// `addons` is non-empty; `expected_peers` is the alias-resolved
    /// (or name-resolved) `*.mesh.local` host names mvmd will set up
    /// for the consumer's in-guest DNS resolver.
    mesh: serde_json::Value,
    /// Per-phase lifecycle command lists — addons first (in
    /// attachment order), then the app's own commands. Pre-merged so
    /// the Nix factory consuming launch.json can iterate flat vecs
    /// without re-merging at flake-evaluation time. Empty phases
    /// serialize as empty arrays.
    hooks: serde_json::Value,
}

pub fn build_launch_json(
    workload: &Workload,
    source: &SourcePlan,
) -> Result<String, serde_json::Error> {
    let app = workload
        .apps
        .first()
        .expect("validate() ensures at least one app");
    let mesh_enabled = !app.addons.is_empty();
    let expected_peers: Vec<String> = app
        .addons
        .iter()
        .map(|a| {
            let host = a.alias.as_deref().unwrap_or(a.name.as_str());
            format!("{host}.mesh.local")
        })
        .collect();
    // Merge per-phase hook commands: addons (in attachment order),
    // then the app. The Nix factory reads `launch.hooks.<phase>` as
    // a flat array.
    let addon_hooks: Vec<&Hooks> = app.addons.iter().map(|a| &a.hooks).collect();
    let merged_hooks = merge_hooks(&app.hooks, &addon_hooks);
    let plan = LaunchPlan {
        artifact_format_version: ARTIFACT_FORMAT_VERSION,
        flake_attribute: FLAKE_ATTRIBUTE,
        flake_path: ".",
        ir_hash: ir_hash(workload)?,
        ir_schema_version: &workload.schema_version,
        toolchain_version: TOOLCHAIN_VERSION,
        workload_id: &workload.id,
        image: serde_json::to_value(&app.image)?,
        entrypoint: serde_json::to_value(app.primary_entrypoint())?,
        entrypoints: serde_json::to_value(&app.entrypoints)?,
        env: serde_json::to_value(&app.env)?,
        mounts: serde_json::to_value(&app.mounts)?,
        network: serde_json::to_value(&app.network)?,
        source,
        threat_tier: serde_json::to_value(app.threat_tier)?,
        addons: serde_json::to_value(&app.addons)?,
        mesh: serde_json::json!({
            "enabled": mesh_enabled,
            "expected_peers": expected_peers,
        }),
        hooks: serde_json::to_value(&merged_hooks)?,
    };
    canonicalize(&plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_ir::{App, Entrypoint, Image, Resources, Source};

    fn sample() -> Workload {
        Workload {
            schema_version: "0.1".into(),
            id: "hello".into(),
            apps: vec![App {
                name: "hello".into(),
                source: Source::LocalPath {
                    path: ".".into(),
                    include: vec!["**".into()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".into()],
                },
                entrypoints: vec![Entrypoint::Command {
                    command: vec!["python".into(), "-m".into(), "hello".into()],
                    working_dir: "/app".into(),
                    env: Default::default(),
                }],
                env: Default::default(),
                mounts: vec![],
                network: None,
                resources: Resources {
                    cpu_cores: 1,
                    memory_mb: 256,
                    rootfs_size_mb: 512,
                },
                dependencies: None,
                threat_tier: Default::default(),
                addons: vec![],
                hooks: Default::default(),
            }],
            volumes: vec![],
            extensions: Default::default(),
        }
    }

    fn empty_source_plan() -> SourcePlan {
        SourcePlan {
            kind: "local_path",
            subdir: "src",
            file_count: 0,
            tree_hash: "0".repeat(64),
        }
    }

    #[test]
    fn launch_json_is_canonical_and_idempotent() {
        let src = empty_source_plan();
        let once = build_launch_json(&sample(), &src).unwrap();
        let twice = build_launch_json(&sample(), &src).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn launch_json_contains_required_fields() {
        let src = empty_source_plan();
        let s = build_launch_json(&sample(), &src).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["artifact_format_version"], "1.1");
        assert_eq!(v["flake_attribute"], "mvm.workload");
        assert_eq!(v["flake_path"], ".");
        assert_eq!(v["ir_schema_version"], "0.1");
        assert_eq!(v["workload_id"], "hello");
        assert_eq!(v["toolchain_version"], TOOLCHAIN_VERSION);
        assert_eq!(v["ir_hash"].as_str().unwrap().len(), 64);
        assert_eq!(v["source"]["kind"], "local_path");
        assert_eq!(v["source"]["subdir"], "src");
        assert_eq!(v["source"]["file_count"], 0);
    }

    #[test]
    fn launch_json_keys_are_sorted() {
        let src = empty_source_plan();
        let s = build_launch_json(&sample(), &src).unwrap();
        let af = s.find("\"artifact_format_version\"").unwrap();
        let fa = s.find("\"flake_attribute\"").unwrap();
        let fp = s.find("\"flake_path\"").unwrap();
        let ih = s.find("\"ir_hash\"").unwrap();
        assert!(af < fa && fa < fp && fp < ih);
    }
}
