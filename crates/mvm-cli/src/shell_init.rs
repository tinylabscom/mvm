use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ui;

const MARKER_START: &str = "# >>> mvmctl >>>";
const MARKER_END: &str = "# <<< mvmctl <<<";

/// Generate the shell init block with completions and dev aliases.
///
/// The block template lives in `resources/shell_init.sh.tera` and is
/// embedded at compile time, then rendered via Tera at runtime.
pub fn generate_block(kv_root: &str) -> String {
    let mut tera = tera::Tera::default();
    tera.add_raw_template(
        "shell_init",
        include_str!("../resources/shell_init.sh.tera"),
    )
    .expect("embedded shell_init template should parse");
    let mut ctx = tera::Context::new();
    ctx.insert("kv_root", kv_root);
    ctx.insert("marker_start", MARKER_START);
    ctx.insert("marker_end", MARKER_END);
    tera.render("shell_init", &ctx)
        .expect("shell_init template should render")
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

/// Return the path to the host shell rc file.
///
/// Uses ~/.zshrc on macOS (default shell is zsh) and ~/.bashrc elsewhere.
fn host_rc_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let rc_name = if cfg!(target_os = "macos") {
        ".zshrc"
    } else {
        ".bashrc"
    };
    Ok(PathBuf::from(home).join(rc_name))
}

/// Check if the given rc file already contains the mvmctl marker block.
fn has_marker(contents: &str) -> bool {
    contents.contains(MARKER_START)
}

/// Ensure the shell init block is present in the host's shell rc file.
/// Appends it if the marker is not found. Idempotent.
pub fn ensure_shell_init() -> Result<()> {
    let kv_root = match detect_kv_root() {
        Ok(p) => p,
        Err(e) => {
            ui::warn(&format!("Skipping shell init: {e}"));
            return Ok(());
        }
    };

    let rc_path = host_rc_path()?;
    let existing = if rc_path.exists() {
        fs::read_to_string(&rc_path)
            .with_context(|| format!("Failed to read {}", rc_path.display()))?
    } else {
        String::new()
    };

    if has_marker(&existing) {
        ui::info(&format!(
            "Shell init already configured in {}",
            rc_path.display()
        ));
        return Ok(());
    }

    let block = generate_block(&kv_root.display().to_string());
    let separator = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let new_contents = format!("{existing}{separator}\n{block}\n");

    fs::write(&rc_path, new_contents)
        .with_context(|| format!("Failed to write {}", rc_path.display()))?;

    ui::success(&format!("Added mvmctl shell init to {}", rc_path.display()));
    Ok(())
}

/// Print the shell init block to stdout (for `eval "$(mvmctl shell-init)"`).
pub fn print_shell_init() -> Result<()> {
    let kv_root = detect_kv_root()?;
    let block = generate_block(&kv_root.display().to_string());
    println!("{block}");
    Ok(())
}

/// Ensure the shell init block is present in the Lima VM's ~/.bashrc.
///
/// Lima VMs have a separate home directory from the host, so the host's
/// shell config modifications are not visible inside the VM. This function
/// runs inside the VM to patch the VM's own ~/.bashrc.
pub fn ensure_shell_init_in_vm() -> Result<()> {
    use mvm_runtime::shell;

    let kv_root = match detect_kv_root() {
        Ok(p) => p,
        Err(e) => {
            ui::warn(&format!("Skipping VM shell init: {e}"));
            return Ok(());
        }
    };

    let block = generate_block(&kv_root.display().to_string());
    let escaped_marker = MARKER_START.replace('"', r#"\""#);
    let escaped_block = block.replace('\\', r"\\").replace('"', r#"\""#);

    // Idempotent: only append if marker not already present
    let script = format!(
        r#"
        if grep -qF '{marker}' ~/.bashrc 2>/dev/null; then
            true
        else
            printf '\n{block}\n' >> ~/.bashrc
        fi
        "#,
        marker = escaped_marker,
        block = escaped_block,
    );

    shell::run_in_vm(&script).map(|_| ())?;
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
        // Plan 40: the standalone `completions` verb was folded into
        // `shell-init --emit-completions`; the block now calls back
        // into shell-init for the per-shell completion script.
        assert!(block.contains("mvmctl shell-init --emit-completions"));
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
    fn test_has_marker_positive() {
        let contents = format!("some stuff\n{MARKER_START}\nmore\n{MARKER_END}\n");
        assert!(has_marker(&contents));
    }

    #[test]
    fn test_has_marker_negative() {
        assert!(!has_marker("just some zshrc content\n"));
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
