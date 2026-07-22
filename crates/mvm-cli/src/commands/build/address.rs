//! `mvmctl build address` — print a Workload IR's semantic identities.
//!
//! Reads a Workload IR JSON (the cross-language interop shape the SDKs emit)
//! and prints its content identity: the `sha256(JCS(ir))` semantic address and
//! the matching `ir_hash`. Two IR documents that mean the same thing hash the
//! same regardless of key order or whitespace, so this is the boundary where a
//! host and an SDK can agree on a workload's identity. Computing both and
//! asserting they line up makes this verb a conformance check on the two
//! canonical-form realizations, not just a printer.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;

use mvm_core::semantic_address::semantic_address;
use mvm_core::user_config::MvmConfig;
use mvm_protocol::ir::{Workload, ir_hash};

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

/// The two content identities of a workload, already self-checked to agree.
#[derive(Debug)]
struct Identities {
    semantic_address: String,
    ir_hash: String,
}

#[derive(Serialize)]
struct AddressReport {
    semantic_address: String,
    ir_hash: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let workload = load_ir_json_workload(args.from_ir.as_deref(), args.entry.as_deref())?;
    let identities = compute_identities(&workload)?;
    print!("{}", render(&identities, args.json)?);
    Ok(())
}

/// Compute both identities and prove they agree. The agreement is what makes
/// the semantic address and the `ir_hash` interchangeable identifiers for the
/// same workload; a mismatch means the two canonical-form realizations drifted,
/// so fail loud rather than print two identities that disagree.
fn compute_identities(workload: &Workload) -> Result<Identities> {
    let addr = semantic_address(workload).context("computing semantic address")?;
    let ih = ir_hash(workload).context("computing ir_hash")?;
    let addr = addr.as_str().to_string();
    if addr.strip_prefix("sha256:") != Some(ih.as_str()) {
        bail!("semantic address {addr} does not match ir_hash {ih} — canonicalizer drift");
    }
    Ok(Identities {
        semantic_address: addr,
        ir_hash: ih,
    })
}

fn render(identities: &Identities, json: bool) -> Result<String> {
    if json {
        let report = AddressReport {
            semantic_address: identities.semantic_address.clone(),
            ir_hash: identities.ir_hash.clone(),
        };
        let mut out = serde_json::to_string(&report).context("serializing address report")?;
        out.push('\n');
        Ok(out)
    } else {
        Ok(format!(
            "semantic-address: {}\nir-hash: {}\n",
            identities.semantic_address, identities.ir_hash
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::ir::{App, Entrypoint, Image, Resources, Source as IrSource};

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
        assert_eq!(a.semantic_address, b.semantic_address);
    }

    #[test]
    fn different_meaning_produces_different_address() {
        let a = sample_workload();
        let mut b = sample_workload();
        b.id = "goodbye".to_string();
        let ia = compute_identities(&a).unwrap();
        let ib = compute_identities(&b).unwrap();
        assert_ne!(ia.semantic_address, ib.semantic_address);
    }

    #[test]
    fn identities_self_check_agrees() {
        let ids = compute_identities(&sample_workload()).unwrap();
        assert_eq!(
            ids.semantic_address.strip_prefix("sha256:"),
            Some(ids.ir_hash.as_str())
        );
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
            format!("semantic-address: {}", ids.semantic_address)
        );
        assert_eq!(lines[1], format!("ir-hash: {}", ids.ir_hash));
    }

    #[test]
    fn json_render_carries_both_identities() {
        let ids = compute_identities(&sample_workload()).unwrap();
        let out = render(&ids, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(parsed["semantic_address"], ids.semantic_address);
        assert_eq!(parsed["ir_hash"], ids.ir_hash);
    }
}
