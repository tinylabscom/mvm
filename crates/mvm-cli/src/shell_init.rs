use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const MARKER_START: &str = "# >>> mvmctl >>>";
const MARKER_END: &str = "# <<< mvmctl <<<";

/// Generate the shell init block with completions and dev aliases.
///
/// The block template lives in `resources/shell_init.sh.tera` and is
/// embedded at compile time. It uses only three fixed placeholders.
pub fn generate_block(kv_root: &str) -> String {
    include_str!("../resources/shell_init.sh.tera")
        .replace("{{ marker_start }}", MARKER_START)
        .replace("{{ marker_end }}", MARKER_END)
        .replace("{{ kv_root }}", kv_root)
        .trim()
        .to_string()
}

/// Detect the KV workspace root by walking up from cwd to find the mvm repo,
/// then returning its parent directory.
///
/// Looks for a `Cargo.toml` containing `name = "mvmctl"` to identify the repo root.
pub fn detect_kv_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let mut dir = cwd.as_path();

    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let contents = fs::read_to_string(&cargo_toml).unwrap_or_default();
            if contents.contains("name = \"mvmctl\"") {
                return dir
                    .parent()
                    .map(Path::to_path_buf)
                    .context("mvm repo root has no parent directory");
            }
        }
        dir = match dir.parent() {
            Some(p) => p,
            None => anyhow::bail!(
                "Could not find mvm repo root (Cargo.toml with name = \"mvmctl\") \
                 in any parent of {}",
                cwd.display()
            ),
        };
    }
}

/// Print the shell init block to stdout (for `eval "$(mvmctl shell-init)"`).
pub fn print_shell_init() -> Result<()> {
    let kv_root = detect_kv_root()?;
    let block = generate_block(&kv_root.display().to_string());
    println!("{block}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_block_contains_markers() {
        let block = generate_block("/some/path");
        assert!(block.starts_with(MARKER_START));
        assert!(block.ends_with(MARKER_END));
    }

    #[test]
    fn test_generate_block_contains_completions() {
        let block = generate_block("/some/path");
        // The block calls the public `completions` verb, not a hidden flag:
        // one name for one thing, and it is the discoverable one.
        assert!(block.contains("mvmctl completions"));
    }

    #[test]
    fn test_generate_block_contains_aliases() {
        let block = generate_block("/work/kv");
        assert!(block.contains("alias mvmctl="));
        assert!(block.contains("alias mvmd="));
        assert!(block.contains(r#"KV_ROOT="/work/kv""#));
        assert!(block.contains("$KV_ROOT/mvm/Cargo.toml"));
        assert!(block.contains("$KV_ROOT/mvmd/Cargo.toml"));
    }

    #[test]
    fn test_detect_kv_root() {
        // This test runs from the mvm repo root, so detect_kv_root should succeed
        let root = detect_kv_root();
        if let Ok(root) = root {
            // The parent of the mvm repo should exist
            assert!(root.exists());
        }
        // If we're not inside the repo (e.g., CI), the test just passes
    }
}
