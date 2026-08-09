//! Chain head + JSONL append + secondary persistence.
//!
//! Holds the chain-signing key (software in-memory) + the
//! `O_APPEND`-only FD on the JSONL + the latest chain head. The single
//! entry point is `Chain::append_entry`: takes a typed
//! `AppendEntryRequest::AppendEntry`, synthesizes a `CanonicalEntry`
//! with the current `prev_hash`, JCS-canonicalizes, signs, appends,
//! fsyncs, updates head, persists secondary, returns the new head.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use mvm_core::protocol::audit_signer::AuditSignerErrorCode;
use mvm_core::security::SIG_ALG_ED25519;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit_signer::canonical::CanonicalEntry;

/// The full on-disk JSONL line. `canonical` is the JCS-canonical entry
/// bytes (base64); `sig` is the chain key's signature over those
/// bytes; `sig_alg` is one of [`SIG_ALG_ED25519`] etc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OnDiskEntry {
    /// JCS-canonical entry bytes, base64-encoded.
    pub canonical: String,
    /// Signature of `canonical` bytes by the chain key.
    pub sig: String,
    /// Signature algorithm (`SIG_ALG_ED25519`, `SIG_ALG_ECDSA_P256`).
    pub sig_alg: u8,
    /// Hex-encoded SHA-256 hash of `prev_hash || canonical_bytes`.
    /// Provided so a verifier can re-derive the chain head without
    /// rebuilding it from the canonical-bytes hashing pipeline.
    pub entry_hash: String,
}

pub struct Chain {
    signing_key: SigningKey,
    pub_key_bytes: Vec<u8>,
    head: String,
    jsonl_file: File,
    jsonl_path: std::path::PathBuf,
    secondary_head_path: std::path::PathBuf,
    /// Set when an append failed partway. The next append re-seeds the head
    /// from the on-disk tail rather than trusting memory — see [`Chain::append`].
    resync_needed: bool,
}

impl Chain {
    /// Open or create the chain. If the JSONL exists and has entries,
    /// scans the file to find the latest entry-hash and uses it as the
    /// initial head. Otherwise initializes with [`CanonicalEntry::
    /// genesis_prev_hash`].
    ///
    /// Takes an exclusive advisory lock on the JSONL and holds it for the
    /// chain's lifetime, so a second signer on the same file is refused rather
    /// than admitted to fork it. This type caches the head in memory and only
    /// re-reads it on recovery, which is sound exactly as long as it is the
    /// only writer — the lock is what makes that an enforced property instead
    /// of a convention. Fails fast rather than blocking: a signer waiting on a
    /// lock is a boot hanging with no explanation.
    pub fn open(
        jsonl_path: &Path,
        secondary_head_path: &Path,
        software_chain_key_path: Option<&Path>,
    ) -> Result<Self> {
        let signing_key = match software_chain_key_path {
            Some(p) => {
                let bytes = std::fs::read(p).with_context(|| {
                    format!("mvm-audit-signer chain key read failed: {}", p.display())
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    anyhow::anyhow!(
                        "mvm-audit-signer chain key must be 32 bytes; got {}",
                        v.len()
                    )
                })?;
                SigningKey::from_bytes(&arr)
            }
            None => {
                let mut rng = OsRng;
                {
                    let mut __ed_seed = [0u8; 32];
                    rand::RngCore::fill_bytes(&mut rng, &mut __ed_seed);
                    SigningKey::from_bytes(&__ed_seed)
                }
            }
        };
        let pub_key_bytes = signing_key.verifying_key().to_bytes().to_vec();

        // O_APPEND-only. Combined with the dir-immutable flag the
        // supervisor sets on the parent dir, this means we can only
        // append; we can't rewrite, truncate, or unlink.
        let jsonl_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(jsonl_path)
            .with_context(|| {
                format!(
                    "mvm-audit-signer JSONL O_APPEND open failed: {}",
                    jsonl_path.display()
                )
            })?;

        lock_sole_writer(&jsonl_file).with_context(|| {
            format!(
                "mvm-audit-signer chain already held by another writer: {}",
                jsonl_path.display()
            )
        })?;

        let head = recover_head(jsonl_path, secondary_head_path)?;

        Ok(Self {
            signing_key,
            pub_key_bytes,
            head,
            jsonl_file,
            jsonl_path: jsonl_path.to_path_buf(),
            secondary_head_path: secondary_head_path.to_path_buf(),
            resync_needed: false,
        })
    }

    /// Current head hash (hex). For tests + supervisor inspection.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Public key bytes of the chain-signing key (32 for Ed25519).
    pub fn pub_key(&self) -> Vec<u8> {
        self.pub_key_bytes.clone()
    }

    /// Append one canonical entry. Returns the new head on success.
    pub fn append(&mut self, entry: CanonicalEntry) -> Result<String, AuditSignerErrorCode> {
        // Allow-list gate: unknown categories are rejected before any
        // signing work happens. Keeps the chain to a known set of values
        // so downstream tooling can rely on category meaning.
        if !crate::audit_signer::category::is_allowed(&entry.category) {
            return Err(AuditSignerErrorCode::InvalidRequest);
        }
        // An earlier append failed after it had begun writing. Whether its
        // line reached the file is not knowable from here, so believe the file
        // rather than memory: a head left behind the tail would hand this
        // entry a parent the tail has already claimed, forking the chain on
        // our own recovery path. The caller's stale prev_hash then fails the
        // drift check below, which is the correct fail-closed answer.
        if self.resync_needed {
            self.head = recover_head(&self.jsonl_path, &self.secondary_head_path)
                .map_err(|_| AuditSignerErrorCode::InternalError)?;
            self.resync_needed = false;
        }
        // Cross-check the caller's prev_hash matches our in-memory head.
        // If a caller (the audit-signer's own RPC handler) hands us an
        // entry with prev_hash != head we treat it as drift and refuse.
        if entry.prev_hash != self.head {
            return Err(AuditSignerErrorCode::ChainDriftDetected);
        }
        // JCS-canonical bytes (the bytes-to-sign + the bytes-on-disk).
        let canonical_bytes = entry
            .jcs_bytes()
            .map_err(|_| AuditSignerErrorCode::InternalError)?;
        // entry_hash = SHA256(prev_hash || canonical_bytes).
        let entry_hash = compute_entry_hash(&entry.prev_hash, &canonical_bytes);
        // Sign the canonical bytes.
        let sig = self.signing_key.sign(&canonical_bytes);
        let on_disk = OnDiskEntry {
            canonical: base64_encode(&canonical_bytes),
            sig: base64_encode(&sig.to_bytes()),
            sig_alg: SIG_ALG_ED25519,
            entry_hash: entry_hash.clone(),
        };
        let mut line =
            serde_json::to_string(&on_disk).map_err(|_| AuditSignerErrorCode::InternalError)?;
        // One buffer, one `write_all`. `writeln!` emits the payload and the
        // newline as separate writes, and O_APPEND makes each of those atomic
        // without making the pair atomic — a second writer can land a whole
        // line between them and splice two entries into one unparseable line.
        // The exclusive lock this chain holds rules that out, but a single
        // write costs nothing and keeps the guarantee local to this function.
        line.push('\n');
        if let Err(e) = self.write_line(line.as_bytes()) {
            // Part of the line may be on disk. Don't trust the in-memory head
            // again until it has been re-derived from the file.
            self.resync_needed = true;
            return Err(e);
        }
        self.head = entry_hash.clone();
        if std::fs::write(&self.secondary_head_path, &self.head).is_err() {
            self.resync_needed = true;
            return Err(AuditSignerErrorCode::FsyncFailed);
        }
        Ok(entry_hash)
    }

    /// Write one already-newline-terminated line and flush it to stable
    /// storage.
    fn write_line(&mut self, bytes: &[u8]) -> Result<(), AuditSignerErrorCode> {
        self.jsonl_file
            .write_all(bytes)
            .map_err(|_| AuditSignerErrorCode::FsyncFailed)?;
        self.jsonl_file
            .sync_all()
            .map_err(|_| AuditSignerErrorCode::FsyncFailed)
    }
}

/// Take the sole-writer lock on an open chain file, failing immediately if
/// another process holds it. Advisory and released by the kernel when the fd
/// closes, so a crashed signer cannot wedge the chain.
fn lock_sole_writer(file: &File) -> Result<()> {
    use rustix::fs::{FlockOperation, flock};
    use std::os::fd::AsFd;
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|e| anyhow::anyhow!("exclusive chain lock unavailable: {e}"))
}

fn recover_head(jsonl_path: &Path, secondary_head_path: &Path) -> Result<String> {
    let jsonl_head = head_from_jsonl_tail(jsonl_path)?;
    match read_secondary_head(secondary_head_path)? {
        Some(secondary_head) if secondary_head == jsonl_head => Ok(jsonl_head),
        Some(_) | None => {
            if jsonl_head != CanonicalEntry::genesis_prev_hash() {
                std::fs::write(secondary_head_path, &jsonl_head).with_context(|| {
                    format!(
                        "mvm-audit-signer secondary head repair write failed: {}",
                        secondary_head_path.display()
                    )
                })?;
            }
            Ok(jsonl_head)
        }
    }
}

fn head_from_jsonl_tail(jsonl_path: &Path) -> Result<String> {
    let contents = match std::fs::read_to_string(jsonl_path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CanonicalEntry::genesis_prev_hash());
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "mvm-audit-signer existing chain read failed: {}",
                    jsonl_path.display()
                )
            });
        }
    };
    let Some(last_line) = contents.lines().rev().find(|line| !line.trim().is_empty()) else {
        return Ok(CanonicalEntry::genesis_prev_hash());
    };
    let parsed: OnDiskEntry = serde_json::from_str(last_line).with_context(|| {
        format!(
            "mvm-audit-signer existing chain tail malformed: {}",
            jsonl_path.display()
        )
    })?;
    Ok(parsed.entry_hash)
}

fn read_secondary_head(secondary_head_path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(secondary_head_path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| {
            format!(
                "mvm-audit-signer secondary head read failed: {}",
                secondary_head_path.display()
            )
        }),
    }
}

/// `entry_hash = hex(SHA256(prev_hash_ascii || canonical_bytes))` — the
/// chain link. Each entry commits to the previous head plus its own JCS
/// canonical bytes. Shared by the writer ([`Chain::append`]) and the
/// verifier (`super::verify`) so the two computations can't drift.
pub(crate) fn compute_entry_hash(prev_hash: &str, canonical_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_bytes);
    hex::encode(hasher.finalize())
}

// hex + base64 — kept tiny so we don't pull in extra workspace deps.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};
    use tempfile::tempdir;

    use super::*;

    fn sample_entry(prev: String) -> CanonicalEntry {
        CanonicalEntry {
            category: "plan".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"verb": "now"}),
            prev_hash: prev,
            session_id: "sess-001".into(),
            tenant_id: "t-001".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
        }
    }

    #[test]
    fn fresh_chain_starts_at_genesis_head() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let chain = Chain::open(&jsonl, &head, None).unwrap();
        assert_eq!(chain.head(), CanonicalEntry::genesis_prev_hash());
    }

    #[test]
    fn append_advances_head_persists_secondary_and_verifies_signature() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head_path = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head_path, None).unwrap();
        let pub_key = chain.pub_key();

        let entry = sample_entry(chain.head().to_string());
        let entry_clone = entry.clone();
        let new_head = chain.append(entry).expect("append must succeed");
        assert_ne!(new_head, CanonicalEntry::genesis_prev_hash());
        assert_eq!(chain.head(), new_head);

        // Secondary head file matches.
        let secondary = std::fs::read_to_string(&head_path).unwrap();
        assert_eq!(secondary, new_head);

        // Signature verifies against the chain pub key.
        let jsonl_contents = std::fs::read_to_string(&jsonl).unwrap();
        let last_line = jsonl_contents.lines().last().unwrap();
        let on_disk: OnDiskEntry = serde_json::from_str(last_line).unwrap();
        let canonical_bytes = entry_clone.jcs_bytes().unwrap();
        use base64::Engine;
        let on_disk_canonical = base64::engine::general_purpose::STANDARD
            .decode(&on_disk.canonical)
            .unwrap();
        assert_eq!(canonical_bytes, on_disk_canonical);
        let pk_arr: [u8; 32] = pub_key.try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_arr).unwrap();
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&on_disk.sig)
            .unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(&canonical_bytes, &sig)
            .expect("on-disk signature must verify");
    }

    #[test]
    fn append_rejects_drifted_prev_hash() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, None).unwrap();
        let bogus_entry = sample_entry("deadbeef".repeat(8));
        let err = chain.append(bogus_entry).unwrap_err();
        assert_eq!(err, AuditSignerErrorCode::ChainDriftDetected);
    }

    #[test]
    fn reopening_chain_recovers_head_from_jsonl_tail() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let first_head = {
            let mut chain = Chain::open(&jsonl, &head, None).unwrap();
            let entry = sample_entry(chain.head().to_string());
            chain.append(entry).unwrap()
        };
        // Reopen — should resume at the first-append head.
        let chain = Chain::open(&jsonl, &head, None).unwrap();
        assert_eq!(chain.head(), first_head);
    }

    #[test]
    fn reopening_chain_repairs_stale_secondary_head_from_jsonl_tail() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        {
            let mut chain = Chain::open(&jsonl, &head, None).unwrap();
            let entry = sample_entry(chain.head().to_string());
            chain.append(entry).unwrap();
        }
        std::fs::write(&head, CanonicalEntry::genesis_prev_hash()).unwrap();

        let chain = Chain::open(&jsonl, &head, None).unwrap();
        let repaired_head = std::fs::read_to_string(&head).unwrap();
        assert_eq!(chain.head(), repaired_head);
        assert_ne!(chain.head(), CanonicalEntry::genesis_prev_hash());
    }

    #[test]
    fn reopening_chain_repairs_missing_secondary_head_from_jsonl_tail() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let expected_head = {
            let mut chain = Chain::open(&jsonl, &head, None).unwrap();
            let entry = sample_entry(chain.head().to_string());
            chain.append(entry).unwrap()
        };
        std::fs::remove_file(&head).unwrap();

        let chain = Chain::open(&jsonl, &head, None).unwrap();
        assert_eq!(chain.head(), expected_head);
        assert_eq!(std::fs::read_to_string(&head).unwrap(), expected_head);
    }

    /// A second writer on one chain file is refused, not admitted to fork it.
    ///
    /// The head lives in memory between appends, which is only sound while
    /// this is the sole writer. Two open chains would each believe they held
    /// the tail and hand out the same parent twice.
    #[test]
    fn a_second_chain_on_the_same_file_is_refused() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");

        let first = Chain::open(&jsonl, &head, None).unwrap();
        // `Chain` owns a signing key and deliberately has no `Debug`, so
        // unwrap the result by hand rather than via `expect_err`.
        let Err(err) = Chain::open(&jsonl, &head, None) else {
            panic!("a second writer must not get the chain");
        };
        assert!(
            err.to_string().contains("already held by another writer"),
            "unexpected error: {err:#}"
        );

        // Releasing the first hands the chain over cleanly.
        drop(first);
        Chain::open(&jsonl, &head, None).expect("the lock is released on drop");
    }

    /// Each entry is one write, so nothing can be spliced into the middle of a
    /// line — including the gap between the payload and its newline.
    #[test]
    fn an_entry_and_its_newline_are_written_together() {
        use std::io::Read;

        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, None).unwrap();

        // A payload past any single-page write the append path might otherwise
        // get away with.
        let mut entry = sample_entry(chain.head().to_string());
        entry.fields = serde_json::json!({ "verb": "now", "filler": "x".repeat(16 * 1024) });
        chain.append(entry).unwrap();

        let mut raw = Vec::new();
        File::open(&jsonl).unwrap().read_to_end(&mut raw).unwrap();
        assert!(raw.len() > 16 * 1024, "fixture must exceed one page");
        assert_eq!(
            raw.iter().filter(|b| **b == b'\n').count(),
            1,
            "exactly one line terminator"
        );
        assert_eq!(raw.last(), Some(&b'\n'), "the line is newline-terminated");
        let parsed: OnDiskEntry =
            serde_json::from_slice(&raw[..raw.len() - 1]).expect("the line parses whole");
        assert_eq!(parsed.entry_hash, chain.head());
    }

    /// If persisting an append fails partway, the head must not stay behind
    /// the file — the next entry would otherwise claim a parent the tail has
    /// already claimed, forking the chain from the inside.
    #[test]
    fn a_failed_append_does_not_leave_the_head_behind_the_tail() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head_path = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head_path, None).unwrap();

        // Make the secondary-head write fail: the line lands, the head file
        // does not. Point it at a directory, which is never writable as a file.
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        chain.secondary_head_path = blocked;

        let before = chain.head().to_string();
        let err = chain.append(sample_entry(before.clone())).unwrap_err();
        assert_eq!(err, AuditSignerErrorCode::FsyncFailed);

        // The entry did reach the file, so the tail has moved on.
        let contents = std::fs::read_to_string(&jsonl).unwrap();
        let written: OnDiskEntry = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_ne!(written.entry_hash, before);

        // Recovery: repoint at a writable head file and re-drive. The chain
        // must refuse the stale parent, then accept the real tail.
        chain.secondary_head_path = dir.path().join("HEAD2");
        assert_eq!(
            chain.append(sample_entry(before)).unwrap_err(),
            AuditSignerErrorCode::ChainDriftDetected,
            "the parent the failed append consumed must not be reusable"
        );
        assert_eq!(
            chain.head(),
            written.entry_hash,
            "the head re-seeded from the on-disk tail"
        );
        chain
            .append(sample_entry(written.entry_hash.clone()))
            .expect("appending onto the true tail succeeds");
    }

    #[test]
    fn two_appends_chain_correctly() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let mut chain = Chain::open(&jsonl, &head, None).unwrap();
        let h0 = chain.head().to_string();

        let e1 = sample_entry(h0.clone());
        let h1 = chain.append(e1).unwrap();
        assert_ne!(h1, h0);

        let e2 = sample_entry(h1.clone());
        let h2 = chain.append(e2).unwrap();
        assert_ne!(h2, h1);

        // Both lines on disk, ordered, with the correct entry_hash chain.
        let jsonl_contents = std::fs::read_to_string(&jsonl).unwrap();
        let lines: Vec<&str> = jsonl_contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed_1: OnDiskEntry = serde_json::from_str(lines[0]).unwrap();
        let parsed_2: OnDiskEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed_1.entry_hash, h1);
        assert_eq!(parsed_2.entry_hash, h2);
    }
}
