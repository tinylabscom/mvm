//! Map a command or a project file to the OCI image that can run it.
//!
//! `mvmctl run npm test` should boot a Node image without the user naming one.
//! The mapping is a curated, in-tree table — versioned with the code, reviewed
//! like code, never fetched at runtime — for the same reason the service-binding
//! catalog is: a security-relevant default that can change under you between two
//! invocations is not a default, it is a remote input.
//!
//! Detection here is pure. The caller decides what the working directory
//! contains and passes the filenames in, so every rule is unit-testable without
//! a filesystem and the ordering between rules is visible in one place.
//!
//! The pinned refs are tags, not digests, and that is deliberate rather than an
//! oversight: they are a convenience for dev-tier runs. `--prod` refuses a
//! mutable reference before any network fetch, so a production run cannot
//! inherit a detected tag — it has to name a digest.

use serde::{Deserialize, Serialize};

/// One runtime the catalog can recognise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeEntry {
    /// Selector name, e.g. "python". What `--runtime <name>` takes.
    pub name: String,
    /// Short description, shown when listing.
    pub description: String,
    /// The OCI reference a detected run boots.
    pub image: String,
    /// argv[0] values that select this runtime, e.g. `python`, `python3`, `pip`.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Project filenames that select this runtime, e.g. `pyproject.toml`.
    #[serde(default)]
    pub project_files: Vec<String>,
    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A collection of runtime entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCatalog {
    /// Schema version for forward compatibility.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// The runtime entries.
    pub entries: Vec<RuntimeEntry>,
}

fn default_schema_version() -> u32 {
    1
}

/// Why a runtime was chosen. Carried so the CLI can say what it did — a boot
/// the user did not ask for should never be silent about why it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedVia {
    /// The command being run, e.g. `npm` → node.
    Command(String),
    /// A file in the working directory, e.g. `Cargo.toml` → rust.
    ProjectFile(String),
}

impl DetectedVia {
    /// Human-readable cause, for the line the CLI prints before booting.
    pub fn describe(&self) -> String {
        match self {
            DetectedVia::Command(cmd) => format!("the command `{cmd}`"),
            DetectedVia::ProjectFile(file) => format!("`{file}` in the working directory"),
        }
    }
}

/// A resolved detection: which runtime, which image, and what caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The entry's `name`.
    pub runtime: String,
    /// The entry's `image`.
    pub image: String,
    /// What selected it.
    pub via: DetectedVia,
}

impl RuntimeCatalog {
    /// The curated in-tree table. Small on purpose: a short list that is right
    /// beats a long one that is stale, and every entry here is a default
    /// somebody gets without asking for it.
    pub fn builtin() -> Self {
        let entry = |name: &str,
                     description: &str,
                     image: &str,
                     commands: &[&str],
                     project_files: &[&str],
                     tags: &[&str]| RuntimeEntry {
            name: name.to_string(),
            description: description.to_string(),
            image: image.to_string(),
            commands: commands.iter().map(|s| s.to_string()).collect(),
            project_files: project_files.iter().map(|s| s.to_string()).collect(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        };

        Self {
            schema_version: default_schema_version(),
            entries: vec![
                entry(
                    "python",
                    "CPython with pip",
                    "python:3.12-alpine",
                    &["python", "python3", "pip", "pip3", "pytest"],
                    &["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"],
                    &["python", "script"],
                ),
                entry(
                    "node",
                    "Node.js with npm",
                    "node:22-alpine",
                    &["node", "npm", "npx", "yarn", "pnpm"],
                    &["package.json"],
                    &["node", "javascript", "typescript"],
                ),
                entry(
                    "rust",
                    "Rust toolchain with cargo",
                    "rust:1-alpine",
                    &["cargo", "rustc"],
                    &["Cargo.toml"],
                    &["rust", "compiled"],
                ),
                entry(
                    "go",
                    "Go toolchain",
                    "golang:1-alpine",
                    &["go", "gofmt"],
                    &["go.mod"],
                    &["go", "compiled"],
                ),
                entry(
                    "ruby",
                    "Ruby with bundler",
                    "ruby:3-alpine",
                    &["ruby", "bundle", "rake", "gem"],
                    &["Gemfile", "Rakefile"],
                    &["ruby", "script"],
                ),
                entry(
                    "shell",
                    "POSIX shell and core utilities",
                    "alpine:3",
                    &["sh", "bash", "ash"],
                    &[],
                    &["shell", "minimal"],
                ),
            ],
        }
    }

    /// Find an entry by exact name.
    pub fn find(&self, name: &str) -> Option<&RuntimeEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Search entries by name, description, or tag substring (case-insensitive).
    pub fn search(&self, query: &str) -> Vec<&RuntimeEntry> {
        let q = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.name.to_lowercase().contains(&q)
                    || e.description.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Every selector name, in catalog order. For error messages and listings.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Resolve an explicitly named runtime.
    ///
    /// An unknown name is an error, never a fall-through to a default: a typo'd
    /// `--runtime pyhton` must not silently boot the bundled image and leave the
    /// user reading a "command not found" from inside a guest that was never the
    /// one they asked for.
    pub fn resolve_named(&self, name: &str) -> Result<Detection, UnknownRuntime> {
        self.find(name)
            .map(|e| Detection {
                runtime: e.name.clone(),
                image: e.image.clone(),
                via: DetectedVia::Command(name.to_string()),
            })
            .ok_or_else(|| UnknownRuntime {
                requested: name.to_string(),
                known: self.names().iter().map(|s| s.to_string()).collect(),
            })
    }

    /// Detect a runtime from the command being run and the files present.
    ///
    /// Command wins over project file: `mvmctl run python3 script.py` inside a
    /// Node project means Python, because argv is what the user just typed and
    /// the directory is only where they happen to be standing.
    ///
    /// `present_files` is the caller's view of the working directory. Passing it
    /// in rather than reading the filesystem keeps every rule testable and keeps
    /// the ordering decision here instead of spread across two layers.
    pub fn detect(&self, argv0: Option<&str>, present_files: &[String]) -> Option<Detection> {
        if let Some(argv0) = argv0
            && let Some(entry) = self.for_command(argv0)
        {
            return Some(Detection {
                runtime: entry.name.clone(),
                image: entry.image.clone(),
                via: DetectedVia::Command(command_basename(argv0).to_string()),
            });
        }

        // Catalog order decides between two matching project files, so the
        // answer does not depend on directory-listing order.
        for entry in &self.entries {
            for candidate in &entry.project_files {
                if present_files.iter().any(|f| f == candidate) {
                    return Some(Detection {
                        runtime: entry.name.clone(),
                        image: entry.image.clone(),
                        via: DetectedVia::ProjectFile(candidate.clone()),
                    });
                }
            }
        }
        None
    }

    /// The entry whose `commands` contains this argv[0], matched on its
    /// basename so `/usr/bin/python3` resolves like `python3`.
    pub fn for_command(&self, argv0: &str) -> Option<&RuntimeEntry> {
        let base = command_basename(argv0);
        self.entries
            .iter()
            .find(|e| e.commands.iter().any(|c| c == base))
    }
}

/// Strip any directory prefix from argv[0].
fn command_basename(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or(argv0)
}

/// A `--runtime <name>` that names nothing in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRuntime {
    /// What the user asked for.
    pub requested: String,
    /// What they could have asked for.
    pub known: Vec<String>,
}

impl std::fmt::Display for UnknownRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown runtime `{}`; known runtimes: {}",
            self.requested,
            self.known.join(", ")
        )
    }
}

impl std::error::Error for UnknownRuntime {}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_command_selects_its_runtime() {
        let c = RuntimeCatalog::builtin();
        let d = c.detect(Some("npm"), &[]).expect("npm is a node command");
        assert_eq!(d.runtime, "node");
        assert_eq!(d.image, "node:22-alpine");
        assert_eq!(d.via, DetectedVia::Command("npm".to_string()));
    }

    #[test]
    fn a_project_file_selects_its_runtime_when_the_command_is_unknown() {
        let c = RuntimeCatalog::builtin();
        let d = c
            .detect(Some("./build.sh"), &files(&["Cargo.toml"]))
            .expect("Cargo.toml is rust");
        assert_eq!(d.runtime, "rust");
        assert_eq!(d.via, DetectedVia::ProjectFile("Cargo.toml".to_string()));
    }

    #[test]
    fn the_command_wins_over_the_directory() {
        // Running a Python script inside a Node project means Python. argv is
        // what the user just typed; the directory is where they were standing.
        let c = RuntimeCatalog::builtin();
        let d = c
            .detect(Some("python3"), &files(&["package.json"]))
            .expect("argv0 wins");
        assert_eq!(d.runtime, "python");
    }

    #[test]
    fn an_absolute_command_path_matches_on_its_basename() {
        let c = RuntimeCatalog::builtin();
        let d = c.detect(Some("/usr/local/bin/cargo"), &[]).expect("cargo");
        assert_eq!(d.runtime, "rust");
        assert_eq!(d.via, DetectedVia::Command("cargo".to_string()));
    }

    #[test]
    fn nothing_recognised_detects_nothing() {
        let c = RuntimeCatalog::builtin();
        assert!(
            c.detect(Some("./mystery"), &files(&["README.md"]))
                .is_none()
        );
        assert!(c.detect(None, &[]).is_none());
    }

    #[test]
    fn two_matching_project_files_resolve_by_catalog_order_not_listing_order() {
        let c = RuntimeCatalog::builtin();
        let forward = c.detect(None, &files(&["package.json", "pyproject.toml"]));
        let reversed = c.detect(None, &files(&["pyproject.toml", "package.json"]));
        assert_eq!(forward, reversed, "detection must not depend on file order");
        assert_eq!(forward.expect("a match").runtime, "python");
    }

    #[test]
    fn an_unknown_named_runtime_refuses_rather_than_falling_through() {
        let c = RuntimeCatalog::builtin();
        let err = c.resolve_named("pyhton").expect_err("a typo must refuse");
        assert_eq!(err.requested, "pyhton");
        assert!(err.known.contains(&"python".to_string()));
        assert!(err.to_string().contains("known runtimes"));
    }

    #[test]
    fn a_known_named_runtime_resolves_to_its_image() {
        let c = RuntimeCatalog::builtin();
        let d = c.resolve_named("go").expect("go is known");
        assert_eq!(d.image, "golang:1-alpine");
    }

    #[test]
    fn every_entry_is_reachable_by_name_and_declares_an_image() {
        let c = RuntimeCatalog::builtin();
        assert!(!c.entries.is_empty());
        for e in &c.entries {
            assert!(c.find(&e.name).is_some(), "{} not findable", e.name);
            assert!(!e.image.is_empty(), "{} has no image", e.name);
            assert!(
                !e.commands.is_empty() || !e.project_files.is_empty(),
                "{} can never be detected",
                e.name
            );
        }
    }

    #[test]
    fn no_command_or_project_file_is_claimed_by_two_runtimes() {
        // An ambiguous trigger would make detection depend on catalog order for
        // a case the user has no way to see.
        let c = RuntimeCatalog::builtin();
        let mut seen_commands = std::collections::BTreeMap::new();
        let mut seen_files = std::collections::BTreeMap::new();
        for e in &c.entries {
            for cmd in &e.commands {
                if let Some(prev) = seen_commands.insert(cmd.clone(), e.name.clone()) {
                    panic!("command `{cmd}` claimed by both {prev} and {}", e.name);
                }
            }
            for file in &e.project_files {
                if let Some(prev) = seen_files.insert(file.clone(), e.name.clone()) {
                    panic!("file `{file}` claimed by both {prev} and {}", e.name);
                }
            }
        }
    }

    #[test]
    fn search_finds_by_tag_and_description() {
        let c = RuntimeCatalog::builtin();
        assert!(c.search("typescript").iter().any(|e| e.name == "node"));
        assert!(c.search("cargo").iter().any(|e| e.name == "rust"));
    }

    #[test]
    fn catalog_round_trips_through_json() {
        let c = RuntimeCatalog::builtin();
        let json = serde_json::to_string(&c).expect("serialize");
        let back: RuntimeCatalog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(c, back);
    }
}
