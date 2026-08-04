//! Shared IR-JSON input loading for the build-time verbs.
//!
//! Both `build address` and `build compile` accept a Workload IR document from
//! a `--from-ir <path>`, a positional path, or `-` (stdin). This module owns
//! the one copy of that resolution + read + parse so the two verbs can't drift.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use mvm_contract::ir::Workload;

/// A resolved place to read IR-JSON bytes from.
#[derive(Debug)]
pub(in crate::commands) enum IrJsonSource {
    Path(PathBuf),
    Stdin,
}

/// Resolve the IR-JSON source from a `--from-ir` path and an optional
/// positional entry. An empty (or whitespace-only) positional counts as no
/// positional, so a stray `""` argument never silently competes with
/// `--from-ir`. Errors when both are given (ambiguous) or neither is.
pub(in crate::commands) fn resolve_ir_json_source(
    from_ir: Option<&Path>,
    entry: Option<&str>,
) -> Result<IrJsonSource> {
    let entry = entry.map(str::trim).filter(|s| !s.is_empty());
    match (from_ir, entry) {
        (Some(_), Some(_)) => {
            bail!(
                "--from-ir and the positional entry are mutually exclusive — pass one or the other."
            )
        }
        (Some(path), None) => Ok(IrJsonSource::Path(path.to_path_buf())),
        (None, Some("-")) => Ok(IrJsonSource::Stdin),
        (None, Some(s)) => Ok(IrJsonSource::Path(PathBuf::from(s))),
        (None, None) => {
            bail!("missing entry: pass an IR JSON path, `-` for stdin, or `--from-ir <path>`.")
        }
    }
}

/// Read and parse a `Workload` from a resolved IR-JSON source.
pub(in crate::commands) fn read_ir_json_workload(source: &IrJsonSource) -> Result<Workload> {
    let (bytes, label) = read_bytes(source)?;
    parse_ir_json(&bytes, &label)
}

fn parse_ir_json(bytes: &[u8], label: &str) -> Result<Workload> {
    serde_json::from_slice(bytes).with_context(|| format!("parsing IR JSON from {label}"))
}

/// Resolve, read, and parse in one step — the shape the single-source verbs use.
pub(in crate::commands) fn load_ir_json_workload(
    from_ir: Option<&Path>,
    entry: Option<&str>,
) -> Result<Workload> {
    read_ir_json_workload(&resolve_ir_json_source(from_ir, entry)?)
}

fn read_bytes(source: &IrJsonSource) -> Result<(Vec<u8>, String)> {
    match source {
        IrJsonSource::Path(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading IR JSON from {}", path.display()))?;
            Ok((bytes, path.display().to_string()))
        }
        IrJsonSource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading IR JSON from stdin")?;
            Ok((buf, "stdin".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ir_resolves_to_its_path() {
        let source = resolve_ir_json_source(Some(Path::new("ir.json")), None).unwrap();
        assert!(matches!(source, IrJsonSource::Path(p) if p == Path::new("ir.json")));
    }

    #[test]
    fn dash_positional_resolves_to_stdin() {
        let source = resolve_ir_json_source(None, Some("-")).unwrap();
        assert!(matches!(source, IrJsonSource::Stdin));
    }

    #[test]
    fn positional_path_resolves_to_path() {
        let source = resolve_ir_json_source(None, Some("workload.json")).unwrap();
        assert!(matches!(source, IrJsonSource::Path(p) if p == Path::new("workload.json")));
    }

    #[test]
    fn empty_positional_is_ignored_so_from_ir_wins() {
        // A stray empty arg alongside --from-ir is not an ambiguity; the flag
        // is the sole real input.
        let source = resolve_ir_json_source(Some(Path::new("ir.json")), Some("")).unwrap();
        assert!(matches!(source, IrJsonSource::Path(p) if p == Path::new("ir.json")));
        let whitespace = resolve_ir_json_source(Some(Path::new("ir.json")), Some("   ")).unwrap();
        assert!(matches!(whitespace, IrJsonSource::Path(p) if p == Path::new("ir.json")));
    }

    #[test]
    fn conflicting_inputs_are_rejected() {
        let err = resolve_ir_json_source(Some(Path::new("a.json")), Some("b.json")).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn missing_input_is_rejected() {
        let err = resolve_ir_json_source(None, None).unwrap_err();
        assert!(err.to_string().contains("missing entry"));
        // An empty positional with no flag is still "no input".
        let empty = resolve_ir_json_source(None, Some("")).unwrap_err();
        assert!(empty.to_string().contains("missing entry"));
    }

    #[test]
    fn missing_file_is_reported() {
        let err = read_ir_json_workload(&IrJsonSource::Path(PathBuf::from(
            "/nonexistent/does-not-exist.json",
        )))
        .unwrap_err();
        assert!(err.to_string().contains("reading IR JSON"));
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = parse_ir_json(b"{ not json", "fixture").unwrap_err();
        assert!(err.to_string().contains("parsing IR JSON"));
    }
}
