//! `mvmctl build address` — print a Workload IR's content identities.
//!
//! Reads a Workload IR JSON (the cross-language interop shape the SDKs emit)
//! and prints its two content identities: the UOR-ADDR-compatible
//! `sha256(JCS(ir))` workload address and mvm's internal `ir_hash`. Both are
//! stable across key order and whitespace. The workload address additionally
//! normalizes Unicode to match the external UOR-ADDR contract; the two values
//! are therefore reported independently rather than treated as interchangeable.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_contract::ir::{Workload, ir_hash};
use mvm_core::user_config::MvmConfig;
use mvm_core::workload_address;

use super::Cli;
use super::ir_input::load_ir_json_workload;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// IR JSON path, or `-` for stdin. Omit to use `--from-ir`.
    #[arg(value_name = "ENTRY")]
    pub entry: Option<String>,

    /// Read the Workload IR from this JSON file (alternative to the
    /// positional entry).
    #[arg(long = "from-ir", value_name = "PATH")]
    pub from_ir: Option<PathBuf>,

    /// Emit JSON instead of the human-readable lines.
    #[arg(long)]
    pub json: bool,
}

/// The two independent content identities of a workload.
#[derive(Debug)]
struct Identities {
    workload_address: String,
    ir_hash: String,
}

#[derive(Serialize)]
struct AddressReport {
    workload_address: String,
    ir_hash: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let workload = load_ir_json_workload(args.from_ir.as_deref(), args.entry.as_deref())?;
    let identities = compute_identities(&workload)?;
    print!("{}", render(&identities, args.json)?);
    Ok(())
}

/// Compute both identities. The workload address is the cross-language UOR-ADDR
/// label; `ir_hash` remains mvm's internal fingerprint for launch plans and
/// audit records. They intentionally use separate normalization boundaries.
fn compute_identities(workload: &Workload) -> Result<Identities> {
    let addr = workload_address(workload).context("computing workload address")?;
    let ih = ir_hash(workload).context("computing ir_hash")?;
    let addr = addr.as_str().to_string();
    Ok(Identities {
        workload_address: addr,
        ir_hash: ih,
    })
}

fn render(identities: &Identities, json: bool) -> Result<String> {
    if json {
        let report = AddressReport {
            workload_address: identities.workload_address.clone(),
            ir_hash: identities.ir_hash.clone(),
        };
        let mut out = serde_json::to_string(&report).context("serializing address report")?;
        out.push('\n');
        Ok(out)
    } else {
        Ok(format!(
            "workload-address: {}\nir-hash: {}\n",
            identities.workload_address, identities.ir_hash
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{App, Entrypoint, Image, Resources, Source as IrSource};

    fn sample_workload() -> Workload {
        Workload {
            schema_version: "0.1".to_string(),
            id: "hello".to_string(),
            apps: vec![App {
                name: "hello".to_string(),
                source: IrSource::LocalPath {
                    path: ".".to_string(),
                    include: vec!["**".to_string()],
                    exclude: vec![],
                },
                image: Image::NixPackages {
                    packages: vec!["python312".to_string()],
                },
                entrypoints: vec![Entrypoint::Command {
                    command: vec!["python".to_string(), "-m".to_string(), "hello".to_string()],
                    working_dir: "/app".to_string(),
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
                files: vec![],
                health_check: None,
            }],
            volumes: vec![],
            extensions: Default::default(),
        }
    }

    #[test]
    fn reordered_keys_produce_equal_address() {
        let w = sample_workload();
        let compact = serde_json::to_vec(&w).unwrap();
        // Round-trip through a Value and pretty-print to force a different byte
        // encoding (whitespace + serde_json::Map re-ordering) of the same IR.
        let value: serde_json::Value = serde_json::from_slice(&compact).unwrap();
        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert_ne!(compact, pretty, "the two encodings must differ in bytes");

        let from_compact: Workload = serde_json::from_slice(&compact).unwrap();
        let from_pretty: Workload = serde_json::from_slice(&pretty).unwrap();
        let a = compute_identities(&from_compact).unwrap();
        let b = compute_identities(&from_pretty).unwrap();
        assert_eq!(a.workload_address, b.workload_address);
    }

    #[test]
    fn different_workload_produces_different_address() {
        let a = sample_workload();
        let mut b = sample_workload();
        b.id = "goodbye".to_string();
        let ia = compute_identities(&a).unwrap();
        let ib = compute_identities(&b).unwrap();
        assert_ne!(ia.workload_address, ib.workload_address);
    }

    #[test]
    fn identities_have_distinct_valid_shapes() {
        let ids = compute_identities(&sample_workload()).unwrap();
        assert!(ids.workload_address.starts_with("sha256:"));
        assert_eq!(ids.workload_address.len(), "sha256:".len() + 64);
        assert_eq!(ids.ir_hash.len(), 64);
    }

    #[test]
    fn unicode_normalization_does_not_fail_address_reporting() {
        let mut composed = sample_workload();
        composed.id = "café".to_string();
        let mut decomposed = sample_workload();
        decomposed.id = "cafe\u{301}".to_string();

        let composed_ids = compute_identities(&composed).unwrap();
        let decomposed_ids = compute_identities(&decomposed).unwrap();
        assert_eq!(
            composed_ids.workload_address,
            decomposed_ids.workload_address
        );
        assert_ne!(composed_ids.ir_hash, decomposed_ids.ir_hash);
    }

    #[test]
    fn unknown_schema_fails_closed() {
        let mut w = sample_workload();
        w.schema_version = "1.0".to_string();
        let err = compute_identities(&w).unwrap_err();
        assert!(
            err.chain().any(|e| e.to_string().contains("schema")),
            "error chain should mention the schema: {err:#}"
        );
    }

    #[test]
    fn human_render_is_two_stable_lines() {
        let ids = compute_identities(&sample_workload()).unwrap();
        let out = render(&ids, false).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            format!("workload-address: {}", ids.workload_address)
        );
        assert_eq!(lines[1], format!("ir-hash: {}", ids.ir_hash));
    }

    #[test]
    fn json_render_carries_both_identities() {
        let ids = compute_identities(&sample_workload()).unwrap();
        let out = render(&ids, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["workload_address"], ids.workload_address);
        assert_eq!(parsed["ir_hash"], ids.ir_hash);
    }
}
