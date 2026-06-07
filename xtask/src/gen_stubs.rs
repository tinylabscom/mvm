//! `xtask gen-stubs` and `xtask check-stubs`
//!
//! Plan 60 Phase 5 — codegen pipeline for the Python and TypeScript
//! SDKs' lower-layer IR types. Single source of truth is the Rust
//! `mvm-sdk` crate's `ir::Workload` struct (via `schemars`); the JSON
//! Schema is emitted to `schema/workload-ir-v0.json` and downstream
//! generators produce per-language dataclasses / interfaces.
//!
//! (Plan 121 folded the former `mvm-ir` crate into `mvm-sdk::ir`; the
//! schema-emit bin moved with it — Plan 124 D fixed the stale `-p
//! mvm-ir` invocation that left this pipeline unrunnable.)
//!
//! Modeled on mvmforge's `just schema-gen` / `sdk-python-gen` /
//! `sdk-ts-gen` recipes (`/Users/auser/work/tinylabs/mvmco/mvmforge/
//! Justfile`). The xtask packages all three into one command so a dev
//! who edits the IR types runs `cargo xtask gen-stubs` and gets
//! everything refreshed; CI runs `cargo xtask check-stubs` and fails
//! on drift.
//!
//! Toolchain:
//!
//! * Rust schema emit: `cargo run -q -p mvm-sdk --bin
//!   emit_workload_schema` (the binary lives in `mvm-sdk` post-121).
//! * Python: `uvx --from datamodel-code-generator==<PIN>
//!   datamodel-codegen ...` — zero-install via `uv`. Devs don't need
//!   to `uv sync` a Python env first.
//! * TypeScript: `npx --yes json-schema-to-typescript@<PIN> json2ts
//!   ...` — zero-install via `npx`. Devs don't need to
//!   `pnpm install` first.
//!
//! Pinning the generator versions in the xtask (not in
//! `pyproject.toml` / `package.json`) means CI and local always run
//! the same generator. If a SDK's own `pyproject.toml` /
//! `package.json` later pins the same versions for IDE / test
//! tooling, that's a redundancy — but two redundant pins is a
//! cheaper failure mode than a drift between them.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// Pinned generator versions. Bumping a pin is a deliberate one-line
/// change in this file; bump, re-run `cargo xtask gen-stubs`, commit
/// the regenerated files and the pin in the same patch.
const DATAMODEL_CODEGEN_VERSION: &str = "0.25.9";
const JSON_SCHEMA_TO_TS_VERSION: &str = "15.0.3";

/// Workspace-relative paths the generated artifacts are committed at.
/// `xtask check-stubs` diffs fresh output against these.
const SCHEMA_PATH: &str = "schema/workload-ir-v0.json";
const PYTHON_OUTPUT_PATH: &str = "sdks/python/mvm/_ir/workload.py";
const TS_OUTPUT_PATH: &str = "sdks/typescript/src/ir/workload.ts";

/// Generate the schema + Python + TypeScript IR types in place.
pub fn generate(workspace: &Path) -> Result<()> {
    let schema_path = workspace.join(SCHEMA_PATH);
    let py_path = workspace.join(PYTHON_OUTPUT_PATH);
    let ts_path = workspace.join(TS_OUTPUT_PATH);

    ensure_parent_dir(&schema_path)?;
    ensure_parent_dir(&py_path)?;
    ensure_parent_dir(&ts_path)?;

    println!("==> emitting JSON Schema");
    let schema = emit_schema(workspace)?;
    std::fs::write(&schema_path, &schema)
        .with_context(|| format!("writing {}", schema_path.display()))?;
    println!("    wrote {}", schema_path.display());

    println!("==> generating Python dataclasses");
    run_python_codegen(workspace, &schema_path, &py_path)?;
    println!("    wrote {}", py_path.display());

    println!("==> generating TypeScript interfaces");
    run_ts_codegen(workspace, &schema_path, &ts_path)?;
    println!("    wrote {}", ts_path.display());

    println!("\ngen-stubs complete. Commit the regenerated files.");
    Ok(())
}

/// CI guard: regenerate to a tempdir, diff against committed paths,
/// fail if any artifact has drifted. Exit 0 = no drift.
pub fn check(workspace: &Path) -> Result<()> {
    let tmp = tempfile::tempdir().context("creating tempdir")?;
    let fresh_schema = tmp.path().join("workload-ir-v0.json");
    let fresh_py = tmp.path().join("workload.py");
    let fresh_ts = tmp.path().join("workload.ts");

    let schema = emit_schema(workspace)?;
    std::fs::write(&fresh_schema, &schema)
        .with_context(|| format!("writing {}", fresh_schema.display()))?;
    run_python_codegen(workspace, &fresh_schema, &fresh_py)?;
    run_ts_codegen(workspace, &fresh_schema, &fresh_ts)?;

    let mut drift = false;
    drift |= diff_or_report(&fresh_schema, &workspace.join(SCHEMA_PATH))?;
    drift |= diff_or_report(&fresh_py, &workspace.join(PYTHON_OUTPUT_PATH))?;
    drift |= diff_or_report(&fresh_ts, &workspace.join(TS_OUTPUT_PATH))?;

    if drift {
        bail!("generated stubs are stale — run `cargo xtask gen-stubs` and commit the result");
    }
    println!("check-stubs: no drift");
    Ok(())
}

fn emit_schema(workspace: &Path) -> Result<Vec<u8>> {
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "mvm-sdk",
            "--bin",
            "emit_workload_schema",
        ])
        .current_dir(workspace)
        .output()
        .context("spawning cargo run -p mvm-sdk --bin emit_workload_schema")?;
    if !output.status.success() {
        bail!(
            "emit_workload_schema exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn run_python_codegen(workspace: &Path, schema: &Path, out: &Path) -> Result<()> {
    let from = format!("datamodel-code-generator=={DATAMODEL_CODEGEN_VERSION}");
    let status = Command::new("uvx")
        .args([
            "--from",
            &from,
            "datamodel-codegen",
            "--input",
        ])
        .arg(schema)
        .args([
            "--input-file-type",
            "jsonschema",
            "--output-model-type",
            "dataclasses.dataclass",
            "--class-name",
            "Workload",
            "--target-python-version",
            "3.10",
            "--disable-timestamp",
            "--output",
        ])
        .arg(out)
        .current_dir(workspace)
        .status()
        .context(
            "spawning uvx datamodel-codegen — install uv (https://docs.astral.sh/uv/) to run codegen",
        )?;
    if !status.success() {
        bail!("datamodel-codegen exited {status}");
    }
    Ok(())
}

fn run_ts_codegen(workspace: &Path, schema: &Path, out: &Path) -> Result<()> {
    let pkg = format!("json-schema-to-typescript@{JSON_SCHEMA_TO_TS_VERSION}");
    let status = Command::new("npx")
        .args(["--yes", &pkg, "--input"])
        .arg(schema)
        .arg("--output")
        .arg(out)
        .arg("--no-additionalProperties")
        .current_dir(workspace)
        .status()
        .context("spawning npx json-schema-to-typescript — install node + npx to run codegen")?;
    if !status.success() {
        bail!("json-schema-to-typescript exited {status}");
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

fn diff_or_report(fresh: &Path, committed: &Path) -> Result<bool> {
    if !committed.exists() {
        eprintln!(
            "drift: {} is missing — run `cargo xtask gen-stubs` to create it",
            committed.display()
        );
        return Ok(true);
    }
    let fresh_bytes =
        std::fs::read(fresh).with_context(|| format!("reading {}", fresh.display()))?;
    let committed_bytes =
        std::fs::read(committed).with_context(|| format!("reading {}", committed.display()))?;
    if fresh_bytes == committed_bytes {
        return Ok(false);
    }

    eprintln!("drift: {} differs from fresh output", committed.display());
    // Best-effort unified diff via the `diff` binary; we don't fail
    // the check if `diff` itself is unavailable, since the equality
    // check above is the source of truth.
    let _ = Command::new("diff")
        .args(["-u", "--label", "committed", "--label", "fresh"])
        .arg(committed)
        .arg(fresh)
        .status();
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn diff_or_report_returns_false_when_identical() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::write(&a, b"same").unwrap();
        std::fs::write(&b, b"same").unwrap();
        assert!(!diff_or_report(&a, &b).unwrap());
    }

    #[test]
    fn diff_or_report_returns_true_when_committed_missing() {
        let tmp = tempdir().unwrap();
        let fresh = tmp.path().join("fresh");
        let missing = tmp.path().join("never-existed");
        std::fs::write(&fresh, b"x").unwrap();
        assert!(diff_or_report(&fresh, &missing).unwrap());
    }

    #[test]
    fn diff_or_report_returns_true_on_drift() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        std::fs::write(&a, b"hello").unwrap();
        std::fs::write(&b, b"world").unwrap();
        assert!(diff_or_report(&a, &b).unwrap());
    }

    #[test]
    fn ensure_parent_dir_creates_missing_path() {
        let tmp = tempdir().unwrap();
        let nested = tmp.path().join("a/b/c/file.txt");
        ensure_parent_dir(&nested).unwrap();
        assert!(nested.parent().unwrap().is_dir());
    }
}
