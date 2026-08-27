//! `xtask gen-ir-parity` and `xtask check-ir-parity`
//!
//! Executes the shared workload declaration through the Python and
//! TypeScript SDKs. Generated IR documents are committed so Rust tests can
//! deserialize them and prove all three language surfaces resolve to the same
//! workload address. CI re-executes both SDKs and rejects fixture drift.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

const TSX_VERSION: &str = "4.20.3";
const PYTHON_SDK: &str = "crates/mvm-sdk/sdks/python";

#[derive(Clone, Copy)]
enum Runner {
    Python,
    TypeScript,
}

struct ParityFixture {
    language: &'static str,
    runner: Runner,
    source: &'static str,
    generated: &'static str,
}

fn fixtures() -> &'static [ParityFixture] {
    &[
        ParityFixture {
            language: "Python",
            runner: Runner::Python,
            source: "tests/ir-parity-fixtures/hello-parity.py",
            generated: "tests/ir-parity-fixtures/hello-parity.python.ir.json",
        },
        ParityFixture {
            language: "TypeScript",
            runner: Runner::TypeScript,
            source: "tests/ir-parity-fixtures/hello-parity.ts",
            generated: "tests/ir-parity-fixtures/hello-parity.typescript.ir.json",
        },
    ]
}

pub fn generate(workspace: &Path) -> Result<()> {
    for fixture in fixtures() {
        let generated = workspace.join(fixture.generated);
        let bytes = emit_fixture(workspace, fixture)?;
        std::fs::write(&generated, bytes)
            .with_context(|| format!("writing {}", generated.display()))?;
        println!("wrote {}", generated.display());
    }
    Ok(())
}

pub fn check(workspace: &Path) -> Result<()> {
    let mut drift = false;
    for fixture in fixtures() {
        let fresh = emit_fixture(workspace, fixture)?;
        let committed_path = workspace.join(fixture.generated);
        drift |= differs(&fresh, &committed_path)?;
    }

    if drift {
        bail!("IR parity fixtures are stale — run `cargo run -p xtask -- gen-ir-parity`");
    }
    println!("check-ir-parity: no drift");
    Ok(())
}

fn emit_fixture(workspace: &Path, fixture: &ParityFixture) -> Result<Vec<u8>> {
    let source = workspace.join(fixture.source);
    let output = match fixture.runner {
        Runner::Python => Command::new("python3")
            .arg(&source)
            .env("PYTHONPATH", workspace.join(PYTHON_SDK))
            .current_dir(workspace)
            .output()
            .context("spawning Python IR parity fixture")?,
        Runner::TypeScript => {
            let package = format!("tsx@{TSX_VERSION}");
            Command::new("npx")
                .args(["--yes", &package])
                .arg(&source)
                .current_dir(workspace)
                .output()
                .context("spawning pinned tsx IR parity fixture runner")?
        }
    };

    if !output.status.success() {
        bail!(
            "{} IR parity fixture exited {}: {}",
            fixture.language,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    normalize_json(&output.stdout).with_context(|| {
        format!(
            "{} fixture did not emit one JSON document",
            fixture.language
        )
    })
}

fn normalize_json(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut normalized = serde_json::to_vec(&value)?;
    normalized.push(b'\n');
    Ok(normalized)
}

fn differs(fresh: &[u8], committed: &Path) -> Result<bool> {
    if !committed.exists() {
        eprintln!(
            "drift: {} is missing — run `cargo run -p xtask -- gen-ir-parity`",
            committed.display()
        );
        return Ok(true);
    }
    let existing =
        std::fs::read(committed).with_context(|| format!("reading {}", committed.display()))?;
    if fresh == existing {
        return Ok(false);
    }
    eprintln!(
        "drift: {} differs from fresh SDK output",
        committed.display()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn normalize_json_produces_compact_newline_terminated_output() {
        let normalized = normalize_json(b" { \"answer\" : 42 } ").unwrap();
        assert_eq!(normalized, b"{\"answer\":42}\n");
    }

    #[test]
    fn normalize_json_rejects_non_json_output() {
        assert!(normalize_json(b"warning before JSON").is_err());
    }

    #[test]
    fn differs_detects_equal_changed_and_missing_files() {
        let tmp = tempdir().unwrap();
        let committed = tmp.path().join("fixture.json");
        std::fs::write(&committed, b"same").unwrap();

        assert!(!differs(b"same", &committed).unwrap());
        assert!(differs(b"changed", &committed).unwrap());
        assert!(differs(b"same", &tmp.path().join("missing.json")).unwrap());
    }
}
