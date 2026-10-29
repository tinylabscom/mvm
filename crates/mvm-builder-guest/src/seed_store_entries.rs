//! Stable identity for the top-level entries in a seeded Nix store.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Hash sorted top-level store entry names, one name per line.
pub fn seed_store_entries_hash(seed_store: &Path) -> Result<String, String> {
    let mut entries = std::fs::read_dir(seed_store)
        .map_err(|error| format!("read {}: {error}", seed_store.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(|error| format!("read entry under {}: {error}", seed_store.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable();

    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_order_independent_and_changes_with_membership() {
        let first = tempfile::tempdir().unwrap();
        std::fs::create_dir(first.path().join("b")).unwrap();
        std::fs::create_dir(first.path().join("a")).unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::create_dir(second.path().join("a")).unwrap();
        std::fs::create_dir(second.path().join("b")).unwrap();

        assert_eq!(
            seed_store_entries_hash(first.path()).unwrap(),
            seed_store_entries_hash(second.path()).unwrap()
        );
        std::fs::create_dir(second.path().join("c")).unwrap();
        assert_ne!(
            seed_store_entries_hash(first.path()).unwrap(),
            seed_store_entries_hash(second.path()).unwrap()
        );
    }

    #[test]
    fn missing_store_returns_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let error = seed_store_entries_hash(&temp.path().join("missing")).unwrap_err();
        assert!(error.contains("read"));
    }
}
