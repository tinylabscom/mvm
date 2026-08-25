use serde::{Deserialize, Serialize};

/// An entry in the Nix-based image catalog.
///
/// Each entry maps a human-friendly name to a Nix flake reference.
/// Running `mvmctl image fetch <name>` creates a template from this
/// entry's flake_ref and builds it via Nix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Human-friendly image name (e.g. "minimal", "http-server").
    pub name: String,
    /// Short description of the image.
    pub description: String,
    /// Nix flake reference (e.g. "github:tinylabscom/mvm-images#minimal").
    pub flake_ref: String,
    /// Nix profile to build (e.g. "minimal", "gateway").
    pub profile: String,
    /// Default vCPU count.
    pub default_cpus: u8,
    /// Default memory in MiB.
    pub default_memory_mib: u32,
    /// Searchable tags (e.g. ["base", "minimal", "nix"]).
    #[serde(default)]
    pub tags: Vec<String>,
    /// What running this entry means, when it is runnable at all.
    ///
    /// `None` is an entry you can read about but not launch — a base image
    /// with no entrypoint of its own. Absence is the honest encoding: the
    /// alternative is a default entrypoint that boots something the entry's
    /// author never chose.
    #[serde(default)]
    pub workload: Option<CatalogWorkload>,
}

/// The bound shape of a runnable catalog entry: what it starts, what host
/// services it needs, and the ceiling it runs under.
///
/// This is the bridge from a catalogued name to an admitted plan. It carries
/// only what admission consumes, so no field here is decorative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CatalogWorkload {
    /// Command the guest runs. Empty means the image's own entrypoint, as
    /// resolved from its metadata sidecar.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Host services this entry needs bound, as `ServiceId` strings (e.g.
    /// `host.kv.v1`). Populated into the plan's `services` list at admission,
    /// so an entry that needs a store declares it here rather than the
    /// operator remembering a flag.
    #[serde(default)]
    pub services: Vec<String>,
    /// Peer names this entry may dial, as `PeerName` strings (e.g.
    /// `db.mvm.peer`). Empty means the workload addresses no peer.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Artifact digest this entry is pinned to. Required under `--prod`: a
    /// mutable reference is refused before any network fetch, so a tag cannot
    /// resolve to different bytes between admission and boot.
    #[serde(default)]
    pub digest: Option<String>,
}

/// Why a catalog entry cannot be run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryNotRunnable {
    /// The entry has no bound workload shape at all.
    NotRunnable,
    /// A `services` string is not a valid `ServiceId`.
    BadService(String),
    /// A `peers` string is not a valid peer name.
    BadPeer(String),
    /// Running under `--prod` without a pinned digest.
    UnpinnedUnderProd,
    /// The entry asks for more than the admission ceiling allows.
    OverCeiling {
        /// What the entry asked for.
        requested: u32,
        /// The most it may have.
        ceiling: u32,
    },
}

impl std::fmt::Display for EntryNotRunnable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunnable => write!(
                f,
                "this catalog entry has no entrypoint, so there is nothing to run;                  it is a base image to build on"
            ),
            Self::BadService(raw) => {
                write!(
                    f,
                    "`{raw}` is not a valid service id (expected e.g. `host.kv.v1`)"
                )
            }
            Self::BadPeer(raw) => {
                write!(
                    f,
                    "`{raw}` is not a valid peer name (expected e.g. `db.mvm.peer`)"
                )
            }
            Self::UnpinnedUnderProd => write!(
                f,
                "--prod requires a pinned digest; this entry names a mutable reference"
            ),
            Self::OverCeiling { requested, ceiling } => write!(
                f,
                "entry requests {requested} MiB, over the {ceiling} MiB admission ceiling"
            ),
        }
    }
}

impl std::error::Error for EntryNotRunnable {}

/// A catalog is a collection of image entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Catalog {
    /// Schema version for forward compatibility.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// The image entries.
    pub entries: Vec<CatalogEntry>,
}

fn default_schema_version() -> u32 {
    1
}

impl Catalog {
    /// Search entries by name or tag substring (case-insensitive).
    pub fn search(&self, query: &str) -> Vec<&CatalogEntry> {
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

    /// Find an entry by exact name.
    pub fn find(&self, name: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

impl CatalogEntry {
    /// Whether this entry can be launched at all.
    pub fn is_runnable(&self) -> bool {
        self.workload.is_some()
    }

    /// Validate everything about this entry that can be decided before any
    /// side effect, and return the parsed bindings.
    ///
    /// Ordering is deliberate: the `--prod` pin check runs before anything
    /// that would fetch, so an unpinned entry is refused without a network
    /// round trip. The ceiling check reuses the operator's configured
    /// per-workload memory limit rather than introducing a second one.
    pub fn resolve(
        &self,
        prod: bool,
        memory_ceiling_mib: Option<u32>,
    ) -> Result<ResolvedEntry, EntryNotRunnable> {
        let Some(workload) = self.workload.as_ref() else {
            return Err(EntryNotRunnable::NotRunnable);
        };
        if prod && workload.digest.is_none() {
            return Err(EntryNotRunnable::UnpinnedUnderProd);
        }
        if let Some(ceiling) = memory_ceiling_mib
            && self.default_memory_mib > ceiling
        {
            return Err(EntryNotRunnable::OverCeiling {
                requested: self.default_memory_mib,
                ceiling,
            });
        }
        let mut services = Vec::with_capacity(workload.services.len());
        for raw in &workload.services {
            let parsed = mvm_contract::protocol::broker::ServiceId::parse(raw.as_str())
                .map_err(|_| EntryNotRunnable::BadService(raw.clone()))?;
            services.push(parsed);
        }
        let mut peers = Vec::with_capacity(workload.peers.len());
        for raw in &workload.peers {
            let parsed = mvm_contract::peer::PeerName::parse(raw)
                .map_err(|_| EntryNotRunnable::BadPeer(raw.clone()))?;
            peers.push(parsed);
        }
        Ok(ResolvedEntry {
            entrypoint: workload.entrypoint.clone(),
            services,
            peers,
            cpus: self.default_cpus,
            memory_mib: self.default_memory_mib,
        })
    }
}

/// A catalog entry that passed every pre-admission check, with its bindings
/// parsed into the types the plan carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntry {
    /// Command the guest runs; empty means the image's own entrypoint.
    pub entrypoint: Vec<String>,
    /// Host services to thread into the plan's `services` list.
    pub services: Vec<mvm_contract::protocol::broker::ServiceId>,
    /// Peers this workload may dial.
    pub peers: Vec<mvm_contract::peer::PeerName>,
    /// vCPU count.
    pub cpus: u8,
    /// Memory in MiB.
    pub memory_mib: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_catalog() -> Catalog {
        Catalog {
            schema_version: 1,
            entries: vec![
                CatalogEntry {
                    name: "minimal".to_string(),
                    description: "Bare-bones microVM image".to_string(),
                    flake_ref: "github:tinylabscom/mvm-images#minimal".to_string(),
                    profile: "minimal".to_string(),
                    default_cpus: 1,
                    default_memory_mib: 256,
                    tags: vec!["base".to_string(), "minimal".to_string()],
                    workload: None,
                },
                CatalogEntry {
                    name: "http-server".to_string(),
                    description: "Nginx-based HTTP server".to_string(),
                    flake_ref: "github:tinylabscom/mvm-images#http".to_string(),
                    profile: "http".to_string(),
                    default_cpus: 2,
                    default_memory_mib: 512,
                    tags: vec!["web".to_string(), "nginx".to_string()],
                    workload: Some(CatalogWorkload {
                        entrypoint: vec!["/bin/nginx".to_string()],
                        ..CatalogWorkload::default()
                    }),
                },
                CatalogEntry {
                    name: "postgres".to_string(),
                    description: "PostgreSQL database server".to_string(),
                    flake_ref: "github:tinylabscom/mvm-images#postgres".to_string(),
                    profile: "postgres".to_string(),
                    default_cpus: 2,
                    default_memory_mib: 1024,
                    tags: vec!["database".to_string(), "sql".to_string()],
                    workload: Some(CatalogWorkload {
                        entrypoint: vec!["/bin/postgres".to_string()],
                        services: vec!["host.kv.v1".to_string()],
                        digest: Some("sha256:aaaa".to_string()),
                        ..CatalogWorkload::default()
                    }),
                },
            ],
        }
    }

    #[test]
    fn test_serde_roundtrip() {
        let cat = sample_catalog();
        let json = serde_json::to_string_pretty(&cat).unwrap();
        let parsed: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, parsed);
    }

    #[test]
    fn test_find_by_name() {
        let cat = sample_catalog();
        assert_eq!(cat.find("minimal").unwrap().name, "minimal");
        assert_eq!(cat.find("postgres").unwrap().default_memory_mib, 1024);
        assert!(cat.find("nonexistent").is_none());
    }

    #[test]
    fn test_search_by_name() {
        let cat = sample_catalog();
        let results = cat.search("http");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "http-server");
    }

    #[test]
    fn test_search_by_tag() {
        let cat = sample_catalog();
        let results = cat.search("database");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "postgres");
    }

    #[test]
    fn test_search_by_description() {
        let cat = sample_catalog();
        let results = cat.search("bare-bones");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "minimal");
    }

    #[test]
    fn test_search_case_insensitive() {
        let cat = sample_catalog();
        let results = cat.search("NGINX");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_no_results() {
        let cat = sample_catalog();
        let results = cat.search("zzz-nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_schema_version_default() {
        let json = r#"{"entries": []}"#;
        let cat: Catalog = serde_json::from_str(json).unwrap();
        assert_eq!(cat.schema_version, 1);
    }

    #[test]
    fn test_catalog_entry_no_tags() {
        let json = r#"{
            "name": "test",
            "description": "test image",
            "flake_ref": ".",
            "profile": "test",
            "default_cpus": 1,
            "default_memory_mib": 256
        }"#;
        let entry: CatalogEntry = serde_json::from_str(json).unwrap();
        assert!(entry.tags.is_empty());
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn entry(workload: Option<CatalogWorkload>, memory_mib: u32) -> CatalogEntry {
        CatalogEntry {
            name: "svc".to_string(),
            description: "test entry".to_string(),
            flake_ref: ".".to_string(),
            profile: "minimal".to_string(),
            default_cpus: 1,
            default_memory_mib: memory_mib,
            tags: Vec::new(),
            workload,
        }
    }

    fn runnable() -> CatalogWorkload {
        CatalogWorkload {
            entrypoint: vec!["/bin/app".to_string()],
            services: vec!["host.kv.v1".to_string()],
            peers: vec!["db.mvm.peer".to_string()],
            digest: Some("sha256:beef".to_string()),
        }
    }

    #[test]
    fn a_runnable_entry_resolves_its_bindings_into_plan_types() {
        let resolved = entry(Some(runnable()), 256)
            .resolve(false, None)
            .expect("runnable");
        assert_eq!(resolved.entrypoint, vec!["/bin/app"]);
        assert_eq!(resolved.services.len(), 1);
        assert_eq!(resolved.services[0].as_str(), "host.kv.v1");
        assert_eq!(resolved.peers.len(), 1);
        assert_eq!(resolved.peers[0].as_str(), "db.mvm.peer");
        assert_eq!(resolved.memory_mib, 256);
    }

    /// A base image is not a failure to describe a workload; it is an entry
    /// that has none. The refusal says so rather than reporting a missing
    /// field.
    #[test]
    fn an_entry_without_a_workload_is_not_runnable() {
        let error = entry(None, 256).resolve(false, None).unwrap_err();
        assert_eq!(error, EntryNotRunnable::NotRunnable);
        assert!(error.to_string().contains("base image"));
        assert!(!entry(None, 256).is_runnable());
    }

    #[test]
    fn prod_refuses_an_unpinned_entry() {
        let unpinned = CatalogWorkload {
            digest: None,
            ..runnable()
        };
        assert_eq!(
            entry(Some(unpinned.clone()), 256)
                .resolve(true, None)
                .unwrap_err(),
            EntryNotRunnable::UnpinnedUnderProd
        );
        // The same entry is fine outside prod.
        assert!(entry(Some(unpinned), 256).resolve(false, None).is_ok());
    }

    /// The pin check runs before anything that could fetch, so the refusal
    /// costs no network round trip. Ordering is the property under test:
    /// an entry that is both unpinned and over-ceiling reports the pin.
    #[test]
    fn the_prod_pin_check_precedes_the_ceiling_check() {
        let unpinned = CatalogWorkload {
            digest: None,
            ..runnable()
        };
        assert_eq!(
            entry(Some(unpinned), 4096)
                .resolve(true, Some(512))
                .unwrap_err(),
            EntryNotRunnable::UnpinnedUnderProd
        );
    }

    #[test]
    fn an_over_ceiling_entry_is_refused_with_both_numbers() {
        let error = entry(Some(runnable()), 4096)
            .resolve(false, Some(512))
            .unwrap_err();
        assert_eq!(
            error,
            EntryNotRunnable::OverCeiling {
                requested: 4096,
                ceiling: 512
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains("4096") && rendered.contains("512"));
    }

    #[test]
    fn an_entry_at_the_ceiling_is_admitted() {
        assert!(
            entry(Some(runnable()), 512)
                .resolve(false, Some(512))
                .is_ok()
        );
    }

    #[test]
    fn a_malformed_service_or_peer_is_refused_by_name() {
        let bad_service = CatalogWorkload {
            services: vec!["not a service".to_string()],
            ..runnable()
        };
        assert_eq!(
            entry(Some(bad_service), 256)
                .resolve(false, None)
                .unwrap_err(),
            EntryNotRunnable::BadService("not a service".to_string())
        );

        let bad_peer = CatalogWorkload {
            peers: vec!["api.example.com".to_string()],
            ..runnable()
        };
        assert_eq!(
            entry(Some(bad_peer), 256).resolve(false, None).unwrap_err(),
            EntryNotRunnable::BadPeer("api.example.com".to_string())
        );
    }

    /// New fields carry `#[serde(default)]`, so an entry written before the
    /// workload shape existed still parses.
    #[test]
    fn an_entry_without_the_workload_field_still_parses() {
        let parsed: CatalogEntry = serde_json::from_value(serde_json::json!({
            "name": "minimal",
            "description": "base",
            "flake_ref": ".",
            "profile": "minimal",
            "default_cpus": 1,
            "default_memory_mib": 256
        }))
        .expect("legacy entry parses");
        assert!(parsed.workload.is_none());
        assert!(parsed.tags.is_empty());
    }

    #[test]
    fn a_workload_shape_round_trips() {
        let original = entry(Some(runnable()), 256);
        let json = serde_json::to_string(&original).unwrap();
        let parsed: CatalogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }
}
