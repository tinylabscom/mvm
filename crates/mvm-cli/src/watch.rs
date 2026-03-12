use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Result;
use notify_debouncer_mini::{DebouncedEventKind, new_debouncer};

/// Wait for filesystem changes in the given flake directory.
///
/// Watches `flake.nix`, `flake.lock`, and all `.nix` files recursively.
/// Returns the path of the file that triggered the change, or None on error/timeout.
///
/// Uses the `notify` crate for native filesystem events (FSEvents on macOS,
/// inotify on Linux) instead of polling. Changes are debounced by 500ms to
/// avoid redundant rebuilds from rapid file saves.
pub fn wait_for_changes(flake_dir: &str) -> Result<PathBuf> {
    let flake_path = Path::new(flake_dir).canonicalize()?;

    let (tx, rx) = mpsc::channel();

    let mut debouncer = new_debouncer(Duration::from_millis(500), tx)?;

    // Watch the flake directory recursively for .nix and .lock changes
    debouncer
        .watcher()
        .watch(&flake_path, notify::RecursiveMode::Recursive)?;

    // Wait for a relevant change
    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                for event in &events {
                    if event.kind == DebouncedEventKind::Any && is_nix_file(&event.path) {
                        return Ok(event.path.clone());
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("watch error: {e}");
            }
            Err(e) => {
                anyhow::bail!("watch channel closed: {e}");
            }
        }
    }
}

/// Check if a path is a Nix-related file we care about.
fn is_nix_file(path: &Path) -> bool {
    let Some(ext) = path.extension() else {
        // flake.lock has no extension — check by filename
        return path
            .file_name()
            .is_some_and(|n| n == "flake.lock" || n == "flake.nix");
    };

    ext == "nix" || ext == "lock"
}

/// Format a trigger path for display, relative to the flake directory if possible.
pub fn display_trigger(trigger: &Path, flake_dir: &str) -> String {
    let flake_path = Path::new(flake_dir).canonicalize().ok();
    if let Some(base) = flake_path
        && let Ok(rel) = trigger.strip_prefix(&base)
    {
        return rel.display().to_string();
    }
    trigger
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| trigger.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_nix_file_flake_nix() {
        assert!(is_nix_file(Path::new("/foo/flake.nix")));
    }

    #[test]
    fn is_nix_file_flake_lock() {
        assert!(is_nix_file(Path::new("/foo/flake.lock")));
    }

    #[test]
    fn is_nix_file_module() {
        assert!(is_nix_file(Path::new("/foo/bar/minimal-init.nix")));
    }

    #[test]
    fn is_nix_file_rejects_rust() {
        assert!(!is_nix_file(Path::new("/foo/main.rs")));
    }

    #[test]
    fn is_nix_file_rejects_random() {
        assert!(!is_nix_file(Path::new("/foo/README.md")));
    }

    #[test]
    fn is_nix_file_lock_extension() {
        assert!(is_nix_file(Path::new("/foo/something.lock")));
    }

    #[test]
    fn display_trigger_relative() {
        // Create a temp dir to get a real canonicalized path
        let dir = tempfile::tempdir().expect("temp dir");
        let nix_file = dir.path().join("flake.nix");
        std::fs::write(&nix_file, "").expect("write");

        let result = display_trigger(&nix_file, dir.path().to_str().expect("utf8"));
        assert_eq!(result, "flake.nix");
    }

    #[test]
    fn display_trigger_fallback() {
        let result = display_trigger(Path::new("/nonexistent/dir/foo.nix"), "/nonexistent/other");
        assert_eq!(result, "foo.nix");
    }
}
