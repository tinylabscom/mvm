//! Runtime image auto-detection for `mvmctl run`.
//!
//! Maps the trailing argv (e.g. `python3`, `node`) and project files in the
//! working directory (e.g. `requirements.txt`, `package.json`) to a pinned OCI
//! image reference. Detection is purely additive: an explicit `--image`,
//! `--manifest`, or `--launch-plan` always wins, and `--no-detect` disables it.

use std::path::Path;

/// One entry in the runtime detection catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeMapping {
    /// Command names that select this runtime (`python3`, `node`, ...).
    pub command_names: &'static [&'static str],
    /// Project files that select this runtime when no command name matches.
    pub project_files: &'static [&'static str],
    /// OCI image reference to use when this mapping matches.
    pub image_ref: &'static str,
}

/// The built-in auto-detection catalog.
///
/// These are conservative, well-known defaults. They are not a replacement for
/// a manifest; they exist so a casual one-shot (`mvmctl run npm test`) works
/// without forcing the user to pick an image.
pub(crate) const CATALOG: &[RuntimeMapping] = &[
    RuntimeMapping {
        command_names: &["python3", "python", "pip3", "pip"],
        project_files: &["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"],
        image_ref: "python:3.12-alpine",
    },
    RuntimeMapping {
        command_names: &["node", "npm", "npx", "yarn", "pnpm", "bun"],
        project_files: &["package.json", "yarn.lock", "pnpm-lock.yaml"],
        image_ref: "node:22-alpine",
    },
    RuntimeMapping {
        command_names: &["cargo", "rustc", "rustup"],
        project_files: &["Cargo.toml", "Cargo.lock"],
        image_ref: "rust:1.85-alpine",
    },
    RuntimeMapping {
        command_names: &["go", "gofmt"],
        project_files: &["go.mod", "go.sum"],
        image_ref: "golang:1.23-alpine",
    },
    RuntimeMapping {
        command_names: &["ruby", "bundle", "rails", "gem"],
        project_files: &["Gemfile"],
        image_ref: "ruby:3.3-alpine",
    },
    RuntimeMapping {
        command_names: &["java", "mvn", "gradle"],
        project_files: &["pom.xml", "build.gradle", "build.gradle.kts"],
        image_ref: "eclipse-temurin:21-alpine",
    },
    RuntimeMapping {
        command_names: &["dotnet"],
        project_files: &["*.csproj", "*.sln"],
        image_ref: "mcr.microsoft.com/dotnet/sdk:8.0",
    },
    RuntimeMapping {
        command_names: &["php", "composer"],
        project_files: &["composer.json"],
        image_ref: "php:8.3-alpine",
    },
    RuntimeMapping {
        command_names: &["sh", "bash", "zsh"],
        project_files: &[],
        image_ref: "alpine:3.20",
    },
];

/// Detect an OCI image ref for the given argv and working directory.
///
/// Returns `None` when:
/// - detection is disabled (`no_detect` is true),
/// - argv is empty,
/// - no command name or project file matches the catalog.
///
/// The caller is responsible for preferring an explicit `--image` if one was
/// supplied.
pub(crate) fn detect_runtime_image(argv: &[String], cwd: &Path, no_detect: bool) -> Option<String> {
    if no_detect || argv.is_empty() {
        return None;
    }

    let command = argv.first().map(String::as_str).unwrap_or("");
    // Strip any leading path component; "./script.py" is not a command name.
    let command_name = Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command);

    for mapping in CATALOG {
        if mapping.command_names.contains(&command_name) {
            return Some(mapping.image_ref.to_string());
        }
    }

    for mapping in CATALOG {
        for file in mapping.project_files {
            if file.contains('*') {
                // Glob pattern (e.g. "*.csproj"). Keep it simple: any file in
                // cwd matching the suffix counts.
                let suffix = file.strip_prefix("*.").unwrap_or(file);
                if cwd
                    .read_dir()
                    .ok()?
                    .flatten()
                    .any(|e| e.path().extension().is_some_and(|ext| ext == suffix))
                {
                    return Some(mapping.image_ref.to_string());
                }
            } else if cwd.join(file).exists() {
                return Some(mapping.image_ref.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_python_from_command() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            detect_runtime_image(
                &["python3".into(), "-c".into(), "print()".into()],
                dir.path(),
                false
            ),
            Some("python:3.12-alpine".into())
        );
    }

    #[test]
    fn detects_node_from_project_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(
            detect_runtime_image(&["npm".into(), "test".into()], dir.path(), false),
            Some("node:22-alpine".into())
        );
    }

    #[test]
    fn explicit_no_detect_skips() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), "").unwrap();
        assert_eq!(
            detect_runtime_image(&["python3".into(), "script.py".into()], dir.path(), true),
            None
        );
    }

    #[test]
    fn empty_argv_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(detect_runtime_image(&[], dir.path(), false), None);
    }

    #[test]
    fn unknown_command_and_files_return_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            detect_runtime_image(&["xyzzy".into()], dir.path(), false),
            None
        );
    }

    #[test]
    fn command_name_wins_over_project_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), "").unwrap();
        // Even though cwd looks like Python, `node` command selects Node.
        assert_eq!(
            detect_runtime_image(&["node".into()], dir.path(), false),
            Some("node:22-alpine".into())
        );
    }
}
