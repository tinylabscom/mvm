//! Bench report persistence.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

/// Serialize `report` to `path` (pretty JSON), creating parent dirs.
pub fn write_json_report<T: Serialize>(report: &T, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating bench report dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing bench report")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Persist a refused sample without ever exposing a truncated JSON artifact.
pub fn write_json_report_atomic<T: Serialize>(report: &T, path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating bench evidence dir {}", parent.display()))?;
    let json = serde_json::to_vec_pretty(report).context("serializing bench evidence")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary bench evidence in {}", parent.display()))?;
    temp.write_all(&json)
        .with_context(|| format!("writing temporary bench evidence for {}", path.display()))?;
    temp.flush().context("flushing temporary bench evidence")?;
    temp.persist(path)
        .with_context(|| format!("publishing bench evidence at {}", path.display()))?;
    Ok(())
}
