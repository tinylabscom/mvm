//! The record of what a collection brought back, and its canonical digest.
//!
//! The digest is what the audit chain carries, so its encoding is fixed here
//! and nowhere else: a domain tag, the entry count, then each entry in path
//! order as a kind byte and length-prefixed fields. Length prefixes make the
//! encoding unambiguous for any name a guest can choose; the tag keeps an
//! output digest from ever equalling a digest of some other structure that
//! happens to hash the same bytes.

use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::OutputRefusal;

/// Domain-separation tag hashed ahead of every output manifest.
pub const MANIFEST_DOMAIN: &[u8] = b"mvm.output-manifest.v1\0";

const KIND_DIRECTORY: u8 = 1;
const KIND_FILE: u8 = 2;

/// What one collected path is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputEntryKind {
    Directory,
    File {
        size: u64,
        /// Lowercase-hex SHA-256 of the file's bytes.
        sha256: String,
    },
}

/// One collected path, relative to the destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEntry {
    pub path: String,
    #[serde(flatten)]
    pub kind: OutputEntryKind,
}

/// The full, sorted record of one collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputManifest {
    /// Lowercase-hex canonical digest over `entries`.
    pub digest: String,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub entries: Vec<OutputEntry>,
}

impl OutputManifest {
    /// Build a manifest from entries in any order. Entries are sorted by path
    /// bytes, so the digest depends on what was collected and not on the order
    /// a directory happened to list it. A path given twice is refused: two
    /// records for one path cannot both be true.
    pub fn from_entries(mut entries: Vec<OutputEntry>) -> Result<Self, OutputRefusal> {
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].path == pair[1].path) {
            return Err(OutputRefusal::DuplicateName {
                path: pair[0].path.clone(),
            });
        }
        let total_bytes = entries
            .iter()
            .map(|entry| match entry.kind {
                OutputEntryKind::File { size, .. } => size,
                OutputEntryKind::Directory => 0,
            })
            .sum();
        let digest = canonical_digest(&entries)?;
        Ok(Self {
            digest,
            entry_count: entries.len() as u64,
            total_bytes,
            entries,
        })
    }

    /// Write the manifest as JSON at `path`, refusing to replace anything.
    pub fn write_new(&self, path: &Path) -> Result<(), OutputRefusal> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let body = serde_json::to_vec_pretty(self).map_err(|error| {
            OutputRefusal::io("encoding the output manifest", std::io::Error::other(error))
        })?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => OutputRefusal::ManifestExists {
                    path: path.to_path_buf(),
                },
                _ => OutputRefusal::io(format!("creating {}", path.display()), error),
            })?;
        file.write_all(&body)
            .and_then(|()| file.sync_all())
            .map_err(|error| OutputRefusal::io(format!("writing {}", path.display()), error))
    }
}

/// The digest: SHA-256 over the domain tag followed by the canonical encoding.
fn canonical_digest(entries: &[OutputEntry]) -> Result<String, OutputRefusal> {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(canonical_encoding(entries)?);
    Ok(hex::encode(hasher.finalize()))
}

/// The bytes the digest covers after the tag: the entry count, then each
/// entry as a kind byte and length-prefixed fields. Entries must be sorted.
fn canonical_encoding(entries: &[OutputEntry]) -> Result<Vec<u8>, OutputRefusal> {
    let mut out = Vec::new();
    out.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        let path = entry.path.as_bytes();
        let kind = match &entry.kind {
            OutputEntryKind::Directory => KIND_DIRECTORY,
            OutputEntryKind::File { .. } => KIND_FILE,
        };
        out.push(kind);
        out.extend_from_slice(&(path.len() as u64).to_be_bytes());
        out.extend_from_slice(path);
        if let OutputEntryKind::File { size, sha256 } = &entry.kind {
            let raw = decode_sha256(sha256).ok_or_else(|| OutputRefusal::Unreadable {
                reason: format!("manifest entry {:?} carries a malformed sha256", entry.path),
            })?;
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&raw);
        }
    }
    Ok(out)
}

fn decode_sha256(hex_digest: &str) -> Option<[u8; 32]> {
    if hex_digest.len() != 64 || hex_digest.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(hex_digest).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, body: &[u8]) -> OutputEntry {
        OutputEntry {
            path: path.to_string(),
            kind: OutputEntryKind::File {
                size: body.len() as u64,
                sha256: hex::encode(Sha256::digest(body)),
            },
        }
    }

    fn dir(path: &str) -> OutputEntry {
        OutputEntry {
            path: path.to_string(),
            kind: OutputEntryKind::Directory,
        }
    }

    fn sample() -> Vec<OutputEntry> {
        vec![
            dir("logs"),
            file("result.json", b"{\"ok\":true}"),
            file("logs/run.txt", b"done\n"),
        ]
    }

    #[test]
    fn digest_does_not_depend_on_input_order() {
        let forward = OutputManifest::from_entries(sample()).unwrap();
        let mut reversed = sample();
        reversed.reverse();
        let backward = OutputManifest::from_entries(reversed).unwrap();
        assert_eq!(forward, backward);
        assert_eq!(
            forward
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["logs", "logs/run.txt", "result.json"]
        );
        assert_eq!(forward.entry_count, 3);
        assert_eq!(forward.total_bytes, 16);
    }

    #[test]
    fn digest_is_stable_across_releases() {
        // Pinned: a change to the encoding must be a deliberate one, because
        // every recorded `plan.outputs` entry was computed with it. The value
        // was cross-checked against an independent implementation of the
        // documented encoding, not only copied from this one's output.
        let manifest = OutputManifest::from_entries(sample()).unwrap();
        assert_eq!(
            manifest.digest,
            "29abf522e42cae0a0e20ed529348a8c15b623d1fd424ce1f5dee79d7b791aa42"
        );
    }

    #[test]
    fn digest_is_domain_separated() {
        let manifest = OutputManifest::from_entries(sample()).unwrap();
        let encoding = canonical_encoding(&manifest.entries).unwrap();
        let untagged = hex::encode(Sha256::digest(&encoding));
        assert_ne!(
            manifest.digest, untagged,
            "the tag must be part of the digest"
        );

        let mut other = Sha256::new();
        other.update(b"mvm.some-other-structure.v1\0");
        other.update(&encoding);
        assert_ne!(manifest.digest, hex::encode(other.finalize()));

        let mut tagged = Sha256::new();
        tagged.update(MANIFEST_DOMAIN);
        tagged.update(&encoding);
        assert_eq!(manifest.digest, hex::encode(tagged.finalize()));
    }

    #[test]
    fn a_malformed_file_digest_is_refused() {
        let mut entry = file("a", b"x");
        entry.kind = OutputEntryKind::File {
            size: 1,
            sha256: "ABC".into(),
        };
        let err = OutputManifest::from_entries(vec![entry]).unwrap_err();
        assert!(matches!(err, OutputRefusal::Unreadable { .. }), "{err}");
    }

    #[test]
    fn length_prefixes_keep_adjacent_fields_from_sliding() {
        // Both sets are two directories, and concatenating kind byte then name
        // gives `01 'a' 01 'b' 01 'c'` for each: a name may legally contain the
        // byte the next entry's kind is spelled with. Only the length prefix
        // tells them apart.
        let one = OutputManifest::from_entries(vec![dir("a\u{1}b"), dir("c")]).unwrap();
        let two = OutputManifest::from_entries(vec![dir("a"), dir("b\u{1}c")]).unwrap();
        let naive = |m: &OutputManifest| {
            m.entries
                .iter()
                .flat_map(|e| std::iter::once(KIND_DIRECTORY).chain(e.path.bytes()))
                .collect::<Vec<u8>>()
        };
        assert_eq!(naive(&one), naive(&two), "the fixture must collide naively");
        assert_ne!(one.digest, two.digest);

        let as_dir = OutputManifest::from_entries(vec![dir("x")]).unwrap();
        let as_file = OutputManifest::from_entries(vec![file("x", b"")]).unwrap();
        assert_ne!(
            as_dir.digest, as_file.digest,
            "the kind is part of identity"
        );
    }

    #[test]
    fn content_changes_move_the_digest() {
        let base = OutputManifest::from_entries(vec![file("a", b"one")]).unwrap();
        let changed = OutputManifest::from_entries(vec![file("a", b"two")]).unwrap();
        let renamed = OutputManifest::from_entries(vec![file("b", b"one")]).unwrap();
        assert_ne!(base.digest, changed.digest);
        assert_ne!(base.digest, renamed.digest);
    }

    #[test]
    fn a_path_recorded_twice_is_refused() {
        let err = OutputManifest::from_entries(vec![file("a", b"1"), dir("a")]).unwrap_err();
        assert!(matches!(err, OutputRefusal::DuplicateName { .. }), "{err}");
    }

    #[test]
    fn writes_json_once_and_refuses_to_overwrite() {
        let dir_path = tempfile::tempdir().unwrap();
        let path = dir_path.path().join("out.manifest.json");
        let manifest = OutputManifest::from_entries(sample()).unwrap();
        manifest.write_new(&path).unwrap();
        let back: OutputManifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(back, manifest);
        let err = manifest.write_new(&path).unwrap_err();
        assert!(matches!(err, OutputRefusal::ManifestExists { .. }), "{err}");
    }
}
