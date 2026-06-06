//! Single JSON-output path for the CLI: pretty-printed, newline-
//! terminated, written to stdout. Keeps `--json` shape consistent
//! across commands (no envelope framework — YAGNI).

use anyhow::Result;
use serde::Serialize;

pub fn emit_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Render to a `String` (test seam; `emit_json` prints this + newline).
pub fn to_json_string<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_json_string_is_pretty() {
        let v = serde_json::json!({"a": 1, "b": [2, 3]});
        let s = to_json_string(&v).unwrap();
        assert!(s.contains("\n"), "pretty output should be multi-line");
        assert!(s.contains("\"a\""));
    }
}
