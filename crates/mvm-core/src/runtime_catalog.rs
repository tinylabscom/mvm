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

pub use mvm_contract::guest_libc::GuestLibc;
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
    /// The C library `image` is built against.
    ///
    /// Declared rather than probed: the catalog pins the reference, so its libc
    /// is known when the table is written and does not need the image
    /// materialized to be read. That matters because the SDK sidecar is chosen
    /// before the rootfs exists, and a guest can only `dlopen` the variant
    /// matching its own libc.
    ///
    /// Required, with no serde default. The catalog is built in-tree and never
    /// read from a file, so there is no older shape to tolerate — and a default
    /// here would silently be [`GuestLibc::Unknown`], which refuses
    /// `--host-service` outright. An entry that forgets to say should fail to
    /// parse, not boot into a refusal.
    pub libc: GuestLibc,
    /// argv[0] values that select this runtime, e.g. `python`, `python3`, `pip`.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Project filenames that select this runtime, e.g. `pyproject.toml`.
    #[serde(default)]
    pub project_files: Vec<String>,
    /// Searchable tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Host services this runtime needs bound, as `ServiceId` strings (e.g.
    /// `host.kv.v1`).
    ///
    /// Declared on the entry rather than remembered as a flag: a runtime that
    /// cannot work without a store should say so once, here, instead of every
    /// operator learning it from a failure. Empty (the common case) binds
    /// nothing, so the broker answers `NotBound` exactly as it does today.
    #[serde(default)]
    pub services: Vec<String>,
    /// Peer names this runtime may dial, as `PeerName` strings (e.g.
    /// `db.mvm.peer`). Empty means it addresses no peer.
    #[serde(default)]
    pub peers: Vec<String>,
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

/// Why resolving a named runtime failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No entry carries that name.
    Unknown(UnknownRuntime),
    /// The entry exists but its declared bindings do not parse.
    Bindings(EntryBindingsInvalid),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(e) => e.fmt(f),
            Self::Bindings(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ResolveError {}

/// A resolved detection: which runtime, which image, and what caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The entry's `name`.
    pub runtime: String,
    /// The entry's `image`.
    pub image: String,
    /// The entry's declared `libc`.
    ///
    /// Carried onto the detection so the SDK sidecar variant can be chosen
    /// from it. The choice has to be made before the rootfs is materialized,
    /// and for a catalogued runtime it can be: the entry pins the reference,
    /// so its libc is a fact about the table rather than an observation of an
    /// unpacked tree.
    pub libc: GuestLibc,
    /// What selected it.
    pub via: DetectedVia,
    /// The entry's declared host-service bindings, validated.
    ///
    /// Parsed here rather than passed on as strings so a malformed entry is a
    /// catalog error at resolution, not a plan carrying a binding no handler
    /// could satisfy.
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// The entry's declared peer routes, validated.
    pub peers: Vec<mvm_contract::peer::PeerName>,
}

/// Why a catalog entry's declared bindings are unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryBindingsInvalid {
    /// A `services` string is not a valid service id.
    BadService {
        /// The entry that declared it.
        runtime: String,
        /// The unparseable value.
        raw: String,
    },
    /// A `peers` string is not a valid peer name.
    BadPeer {
        /// The entry that declared it.
        runtime: String,
        /// The unparseable value.
        raw: String,
    },
}

impl std::fmt::Display for EntryBindingsInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadService { runtime, raw } => write!(
                f,
                "runtime `{runtime}` declares service `{raw}`, which is not a valid service id \
                 (expected e.g. `host.kv.v1`)"
            ),
            Self::BadPeer { runtime, raw } => write!(
                f,
                "runtime `{runtime}` declares peer `{raw}`, which is not a valid peer name \
                 (expected e.g. `db.mvm.peer`)"
            ),
        }
    }
}

impl std::error::Error for EntryBindingsInvalid {}

impl RuntimeEntry {
    /// Parse this entry's declared bindings.
    fn parse_bindings(
        &self,
    ) -> Result<
        (
            Vec<mvm_contract::protocol::broker::ServiceId>,
            Vec<mvm_contract::peer::PeerName>,
        ),
        EntryBindingsInvalid,
    > {
        let mut services = Vec::with_capacity(self.services.len());
        for raw in &self.services {
            services.push(
                mvm_contract::protocol::broker::ServiceId::parse(raw.as_str()).map_err(|_| {
                    EntryBindingsInvalid::BadService {
                        runtime: self.name.clone(),
                        raw: raw.clone(),
                    }
                })?,
            );
        }
        let mut peers = Vec::with_capacity(self.peers.len());
        for raw in &self.peers {
            peers.push(mvm_contract::peer::PeerName::parse(raw).map_err(|_| {
                EntryBindingsInvalid::BadPeer {
                    runtime: self.name.clone(),
                    raw: raw.clone(),
                }
            })?);
        }
        Ok((services, peers))
    }

    /// Build a [`Detection`] for this entry, validating its declared bindings.
    fn detection(&self, via: DetectedVia) -> Result<Detection, EntryBindingsInvalid> {
        let (services, peers) = self.parse_bindings()?;
        Ok(Detection {
            runtime: self.name.clone(),
            image: self.image.clone(),
            libc: self.libc,
            via,
            services,
            peers,
        })
    }
}

impl RuntimeCatalog {
    /// The curated in-tree table. Small on purpose: a short list that is right
    /// beats a long one that is stale, and every entry here is a default
    /// somebody gets without asking for it.
    pub fn builtin() -> Self {
        let entry = |name: &str,
                     description: &str,
                     image: &str,
                     libc: GuestLibc,
                     commands: &[&str],
                     project_files: &[&str],
                     tags: &[&str]| RuntimeEntry {
            name: name.to_string(),
            description: description.to_string(),
            image: image.to_string(),
            libc,
            commands: commands.iter().map(|s| s.to_string()).collect(),
            project_files: project_files.iter().map(|s| s.to_string()).collect(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            // No bundled runtime declares a binding. Each is a language
            // runtime that works with nothing bound, and inventing a default
            // binding would hand every user of `--runtime python` a service
            // they never asked for.
            services: Vec::new(),
            peers: Vec::new(),
        };

        Self {
            schema_version: default_schema_version(),
            entries: vec![
                entry(
                    "python",
                    "CPython with pip",
                    "python:3.12-alpine",
                    GuestLibc::Musl,
                    &["python", "python3", "pip", "pip3", "pytest"],
                    &["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"],
                    &["python", "script"],
                ),
                entry(
                    "node",
                    "Node.js with npm",
                    "node:22-alpine",
                    GuestLibc::Musl,
                    &["node", "npm", "npx", "yarn", "pnpm"],
                    &["package.json"],
                    &["node", "javascript", "typescript"],
                ),
                entry(
                    "rust",
                    "Rust toolchain with cargo",
                    "rust:1-alpine",
                    GuestLibc::Musl,
                    &["cargo", "rustc"],
                    &["Cargo.toml"],
                    &["rust", "compiled"],
                ),
                entry(
                    "go",
                    "Go toolchain",
                    "golang:1-alpine",
                    GuestLibc::Musl,
                    &["go", "gofmt"],
                    &["go.mod"],
                    &["go", "compiled"],
                ),
                entry(
                    "ruby",
                    "Ruby with bundler",
                    "ruby:3-alpine",
                    GuestLibc::Musl,
                    &["ruby", "bundle", "rake", "gem"],
                    &["Gemfile", "Rakefile"],
                    &["ruby", "script"],
                ),
                entry(
                    "shell",
                    "POSIX shell and core utilities",
                    "alpine:3",
                    GuestLibc::Musl,
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
    pub fn resolve_named(&self, name: &str) -> Result<Detection, ResolveError> {
        let entry = self.find(name).ok_or_else(|| {
            ResolveError::Unknown(UnknownRuntime {
                requested: name.to_string(),
                known: self.names().iter().map(|s| s.to_string()).collect(),
            })
        })?;
        entry
            .detection(DetectedVia::Command(name.to_string()))
            .map_err(ResolveError::Bindings)
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
    /// A matched entry whose declared bindings do not parse is an error rather
    /// than a miss. Returning `Ok(None)` there would report "nothing detected"
    /// for an entry that plainly matched, and the run would proceed on a
    /// different image than the catalog intended.
    pub fn detect(
        &self,
        argv0: Option<&str>,
        present_files: &[String],
    ) -> Result<Option<Detection>, EntryBindingsInvalid> {
        if let Some(argv0) = argv0
            && let Some(entry) = self.for_command(argv0)
        {
            let via = DetectedVia::Command(command_basename(argv0).to_string());
            return entry.detection(via).map(Some);
        }

        // Catalog order decides between two matching project files, so the
        // answer does not depend on directory-listing order.
        for entry in &self.entries {
            for candidate in &entry.project_files {
                if present_files.iter().any(|f| f == candidate) {
                    let via = DetectedVia::ProjectFile(candidate.clone());
                    return entry.detection(via).map(Some);
                }
            }
        }
        Ok(None)
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
impl RuntimeCatalog {
    /// Test shim: `detect` with the binding error unwrapped.
    ///
    /// The builtin table declares no bindings, so the error arm is
    /// unreachable for it and is covered separately by tests that build a
    /// catalog with a malformed entry.
    fn detect_for_test(&self, argv0: Option<&str>, present_files: &[String]) -> Option<Detection> {
        self.detect(argv0, present_files)
            .expect("builtin catalog entries declare no bindings")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_command_selects_its_runtime() {
        let c = RuntimeCatalog::builtin();
        let d = c
            .detect_for_test(Some("npm"), &[])
            .expect("npm is a node command");
        assert_eq!(d.runtime, "node");
        assert_eq!(d.image, "node:22-alpine");
        assert_eq!(d.via, DetectedVia::Command("npm".to_string()));
    }

    #[test]
    fn a_project_file_selects_its_runtime_when_the_command_is_unknown() {
        let c = RuntimeCatalog::builtin();
        let d = c
            .detect_for_test(Some("./build.sh"), &files(&["Cargo.toml"]))
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
            .detect_for_test(Some("python3"), &files(&["package.json"]))
            .expect("argv0 wins");
        assert_eq!(d.runtime, "python");
    }

    #[test]
    fn an_absolute_command_path_matches_on_its_basename() {
        let c = RuntimeCatalog::builtin();
        let d = c
            .detect_for_test(Some("/usr/local/bin/cargo"), &[])
            .expect("cargo");
        assert_eq!(d.runtime, "rust");
        assert_eq!(d.via, DetectedVia::Command("cargo".to_string()));
    }

    #[test]
    fn nothing_recognised_detects_nothing() {
        let c = RuntimeCatalog::builtin();
        assert!(
            c.detect_for_test(Some("./mystery"), &files(&["README.md"]))
                .is_none()
        );
        assert!(c.detect_for_test(None, &[]).is_none());
    }

    #[test]
    fn two_matching_project_files_resolve_by_catalog_order_not_listing_order() {
        let c = RuntimeCatalog::builtin();
        let forward = c.detect_for_test(None, &files(&["package.json", "pyproject.toml"]));
        let reversed = c.detect_for_test(None, &files(&["pyproject.toml", "package.json"]));
        assert_eq!(forward, reversed, "detection must not depend on file order");
        assert_eq!(forward.expect("a match").runtime, "python");
    }

    #[test]
    fn an_unknown_named_runtime_refuses_rather_than_falling_through() {
        let c = RuntimeCatalog::builtin();
        let err = c.resolve_named("pyhton").expect_err("a typo must refuse");
        let ResolveError::Unknown(err) = err else {
            panic!("a typo is an unknown-runtime error, not a bindings error");
        };
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

    // ---- declared bindings on a catalog entry ----

    fn entry_with(services: &[&str], peers: &[&str]) -> RuntimeEntry {
        RuntimeEntry {
            name: "svc".to_string(),
            description: "test".to_string(),
            image: "example:1".to_string(),
            libc: GuestLibc::Musl,
            commands: vec!["svc".to_string()],
            project_files: vec!["svc.toml".to_string()],
            tags: Vec::new(),
            services: services.iter().map(|s| s.to_string()).collect(),
            peers: peers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn catalog_of(entry: RuntimeEntry) -> RuntimeCatalog {
        RuntimeCatalog {
            schema_version: 1,
            entries: vec![entry],
        }
    }

    /// Every catalogued runtime states the libc of the image it pins.
    ///
    /// The sidecar variant is chosen from this, before the rootfs exists, so an
    /// entry that leaves it `Unknown` silently costs its users `--host-service`
    /// entirely: `Unknown` is refused rather than guessed. Adding a runtime
    /// means saying which libc its image carries.
    #[test]
    fn every_builtin_runtime_declares_its_libc() {
        for entry in RuntimeCatalog::builtin().entries {
            assert_ne!(
                entry.libc,
                GuestLibc::Unknown,
                "runtime '{}' ({}) must declare the libc of the image it pins",
                entry.name,
                entry.image
            );
        }
    }

    /// The declaration is only worth having if it matches the image. Every
    /// pinned reference today is Alpine, which is musl; a future glibc entry
    /// should fail this and be given its own arm rather than silently inherit.
    #[test]
    fn the_declared_libc_matches_the_pinned_image() {
        for entry in RuntimeCatalog::builtin().entries {
            assert!(
                entry.image.contains("alpine"),
                "runtime '{}' pins {}, which is not Alpine — state its libc \
                 deliberately rather than letting this test assume musl",
                entry.name,
                entry.image
            );
            assert_eq!(
                entry.libc,
                GuestLibc::Musl,
                "runtime '{}' pins the Alpine image {} but declares {}",
                entry.name,
                entry.image,
                entry.libc
            );
        }
    }

    /// No bundled runtime declares a binding. A default binding would hand
    /// every `--runtime python` user a service they never asked for.
    #[test]
    fn no_builtin_runtime_declares_a_binding() {
        for entry in &RuntimeCatalog::builtin().entries {
            assert!(
                entry.services.is_empty() && entry.peers.is_empty(),
                "{} declares a binding; that is a default nobody opted into",
                entry.name
            );
        }
    }

    #[test]
    fn a_declared_binding_is_parsed_onto_the_detection() {
        let c = catalog_of(entry_with(&["host.kv.v1"], &["db.mvm.peer"]));
        let d = c.resolve_named("svc").expect("resolves");
        assert_eq!(d.services.len(), 1);
        assert_eq!(d.services[0].as_str(), "host.kv.v1");
        assert_eq!(d.peers.len(), 1);
        assert_eq!(d.peers[0].as_str(), "db.mvm.peer");
    }

    /// Parsed at resolution, so a malformed entry is a catalog error rather
    /// than a plan carrying a binding no handler could satisfy.
    #[test]
    fn a_malformed_declared_service_refuses_at_resolution() {
        let c = catalog_of(entry_with(&["not a service"], &[]));
        let err = c.resolve_named("svc").expect_err("must refuse");
        assert!(matches!(err, ResolveError::Bindings(_)));
        assert!(err.to_string().contains("not a service"));
        assert!(
            err.to_string().contains("svc"),
            "the refusal names the entry"
        );
    }

    #[test]
    fn a_malformed_declared_peer_refuses_at_resolution() {
        let c = catalog_of(entry_with(&[], &["api.example.com"]));
        let err = c.resolve_named("svc").expect_err("must refuse");
        assert!(matches!(err, ResolveError::Bindings(_)));
        assert!(err.to_string().contains("api.example.com"));
    }

    /// A matched entry whose bindings do not parse is an error, not a miss.
    /// `Ok(None)` there would report "nothing detected" for an entry that
    /// plainly matched, and the run would proceed on a different image.
    #[test]
    fn detection_surfaces_a_malformed_binding_instead_of_reporting_no_match() {
        let c = catalog_of(entry_with(&["not a service"], &[]));

        let by_command = c.detect(Some("svc"), &[]);
        assert!(
            by_command.is_err(),
            "a command match must not degrade to None"
        );

        let by_file = c.detect(None, &["svc.toml".to_string()]);
        assert!(
            by_file.is_err(),
            "a project-file match must not degrade to None"
        );
    }

    #[test]
    fn a_genuine_miss_is_still_none() {
        let c = catalog_of(entry_with(&["host.kv.v1"], &[]));
        assert_eq!(
            c.detect(Some("unrelated"), &["nothing.txt".to_string()])
                .expect("no binding error"),
            None
        );
    }

    #[test]
    fn an_entry_without_declared_bindings_still_parses() {
        let parsed: RuntimeEntry = serde_json::from_value(serde_json::json!({
            "name": "python",
            "description": "CPython",
            "image": "python:3.12-alpine",
            "libc": "musl"
        }))
        .expect("an entry declaring no bindings parses");
        assert!(parsed.services.is_empty());
        assert!(parsed.peers.is_empty());
    }

    /// Bindings are optional; the libc is not. An entry that omits it would
    /// deserialize to `Unknown`, which refuses `--host-service` outright — a
    /// runtime that silently cannot serve host services is worse than one that
    /// fails to parse. There is no older catalog shape to accommodate: the
    /// table is built in-tree and never read from a file.
    #[test]
    fn an_entry_omitting_its_libc_does_not_parse() {
        let err = serde_json::from_value::<RuntimeEntry>(serde_json::json!({
            "name": "python",
            "description": "CPython",
            "image": "python:3.12-alpine"
        }))
        .expect_err("an entry that does not say its libc must not parse");

        assert!(
            err.to_string().contains("libc"),
            "the error must name the missing field: {err}"
        );
    }
}
