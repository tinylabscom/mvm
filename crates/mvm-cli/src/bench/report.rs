//! Bench report persistence.

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
