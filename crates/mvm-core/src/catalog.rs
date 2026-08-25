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
}

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
                },
                CatalogEntry {
                    name: "http-server".to_string(),
                    description: "Nginx-based HTTP server".to_string(),
                    flake_ref: "github:tinylabscom/mvm-images#http".to_string(),
                    profile: "http".to_string(),
                    default_cpus: 2,
                    default_memory_mib: 512,
                    tags: vec!["web".to_string(), "nginx".to_string()],
                },
                CatalogEntry {
                    name: "postgres".to_string(),
                    description: "PostgreSQL database server".to_string(),
                    flake_ref: "github:tinylabscom/mvm-images#postgres".to_string(),
                    profile: "postgres".to_string(),
                    default_cpus: 2,
                    default_memory_mib: 1024,
                    tags: vec!["database".to_string(), "sql".to_string()],
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
