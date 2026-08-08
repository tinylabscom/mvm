//! Persistent store for runtime-emitted execution receipts.
//!
//! Receipts are a derived, content-addressed cache alongside the chain-signed
//! audit log. The audit log remains the source of truth; this store only
//! holds already-signed [`ExecutionReceipt`]s so they can be re-exported or
//! verified offline without recomputing them from the audit chain.
//!
//! Layout under the audit directory:
//!
//! ```text
//! <audit_dir>/receipts/<tenant>/
//!   head.json          { "last_receipt_id": "sha256:...", "sequence": N }
//!   <seq>-<type>.json  one signed receipt per file
//! ```
//!
//! Each receipt's `prev_receipt_id` points at the previous receipt emitted
//! for the same tenant, forming a host-signer chain. Reading the chain head,
//! linking a receipt to it, signing, and persisting all happen inside one
//! exclusive per-tenant lock ([`ReceiptStore::append_chained`]) — the read is
//! what has to be serialized, not just the write. Two writers that observe
//! the same head produce two receipts naming the same parent, which every
//! offline verifier is obliged to read as a deleted or reordered receipt.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::receipt::SignedExecutionReceipt;
use serde::{Deserialize, Serialize};

use crate::audit::emitter::write_atomic;
use crate::supervisor::audit_file::flock_exclusive;

/// Head file content: the chain tip for one tenant's receipt store.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Head {
    /// `receipt_id` of the most recently stored receipt, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_receipt_id: Option<String>,
    /// Monotonic sequence number assigned to the most recent receipt.
    #[serde(default)]
    sequence: u64,
}

/// File-backed receipt store for one tenant.
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    tenant_dir: PathBuf,
    lock_path: PathBuf,
    head_path: PathBuf,
}

impl ReceiptStore {
    /// Open (and create if missing) the receipt store for `tenant` under
    /// `audit_dir`.
    pub fn open(audit_dir: &Path, tenant: &str) -> Result<Self> {
        let tenant_dir = audit_dir.join("receipts").join(tenant);
        std::fs::create_dir_all(&tenant_dir)
            .with_context(|| format!("creating receipt dir {}", tenant_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&tenant_dir, perms)
                .with_context(|| format!("setting 0700 on {}", tenant_dir.display()))?;
        }
        let lock_path = tenant_dir.join(".lock");
        let head_path = tenant_dir.join("head.json");
        Ok(Self {
            tenant_dir,
            lock_path,
            head_path,
        })
    }

    /// Link a receipt to the current chain head, sign it, and persist it,
    /// returning the assigned sequence number.
    ///
    /// `build` receives the head's `prev_receipt_id` and returns the finished
    /// signed receipt. It runs *inside* the tenant lock, which is the whole
    /// point: the head a receipt commits to has to still be the head when the
    /// receipt lands. Handing the caller a head to link against and taking the
    /// lock only for the write leaves a window in which two writers claim one
    /// parent — a fork, indistinguishable to a verifier from a deleted line.
    ///
    /// Signing happens under the lock because the parent is inside the signed
    /// bytes; a receipt cannot be re-linked after the fact without re-signing.
    pub fn append_chained<F>(&self, build: F) -> Result<u64>
    where
        F: FnOnce(Option<String>) -> Result<SignedExecutionReceipt>,
    {
        let _guard = self.lock()?;
        let mut head = self.read_head();
        let receipt = build(head.last_receipt_id.take())?;

        head.sequence += 1;
        let seq = head.sequence;
        let receipt_path = self.receipt_path(seq, &receipt.payload.receipt_type);

        let bytes =
            serde_json::to_vec_pretty(&receipt).context("serializing signed execution receipt")?;
        write_atomic(&receipt_path, &bytes)?;

        head.last_receipt_id = Some(receipt.payload.receipt_id.clone());
        self.write_head(&head)?;

        Ok(seq)
    }

    /// Return the current chain head for this tenant.
    pub fn head(&self) -> Result<ReceiptHead> {
        let _guard = self.lock()?;
        let head = self.read_head();
        Ok(ReceiptHead {
            last_receipt_id: head.last_receipt_id,
            sequence: head.sequence,
        })
    }

    /// Return the path that would be used for sequence `seq` and receipt
    /// type `receipt_type`.
    pub fn receipt_path(&self, seq: u64, receipt_type: &str) -> PathBuf {
        self.tenant_dir
            .join(format!("{seq:0>8}-{receipt_type}.json"))
    }

    fn read_head(&self) -> Head {
        if !self.head_path.exists() {
            return Head::default();
        }
        std::fs::read_to_string(&self.head_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Head>(&s).ok())
            .unwrap_or_default()
    }

    fn write_head(&self, head: &Head) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(head).context("serializing receipt head")?;
        write_atomic(&self.head_path, &bytes)
    }

    /// Take the exclusive per-tenant lock, blocking until it is available.
    /// Released when the returned guard drops.
    fn lock(&self) -> Result<LockGuard> {
        let file = OpenOptions::new()
            .create(true)
            // The file is a lock, never a payload — its contents are
            // irrelevant and truncating it would be pointless churn.
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("opening lock file {}", self.lock_path.display()))?;
        flock_exclusive(&file)
            .with_context(|| format!("locking receipt store {}", self.lock_path.display()))?;
        Ok(LockGuard { _file: file })
    }
}

/// Snapshot of a receipt store's chain head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptHead {
    /// `receipt_id` of the most recently stored receipt, if any.
    pub last_receipt_id: Option<String>,
    /// Sequence number of the most recently stored receipt.
    pub sequence: u64,
}

/// Holds the receipt store's exclusive lock for as long as it is alive. The
/// `flock` is advisory and released by the kernel when the fd closes, so a
/// crashed writer cannot wedge the store behind a lock nobody holds.
struct LockGuard {
    _file: std::fs::File,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mvm_core::did_key::DidKey;
    use mvm_core::receipt::{
        ExecutionReceipt, ReceiptAction, ReceiptOutcome, SignedExecutionReceipt, receipt_type,
    };
    use std::collections::BTreeMap;

    fn sample_receipt(prev: Option<String>, seq: u64) -> SignedExecutionReceipt {
        let signing_key = SigningKey::from_bytes(&[seq as u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
        let mut receipt = ExecutionReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            receipt_type: receipt_type::PLAN_ADMITTED.into(),
            plan_id: format!("sha256:{seq:064x}"),
            image_node_digest: None,
            agent_id: None,
            principal_did: None,
            host_did,
            action: ReceiptAction {
                verb: "run".into(),
                resource: format!("sha256:{seq:064x}"),
                params: BTreeMap::new(),
            },
            outcome: ReceiptOutcome::Authorized,
            granted_by: None,
            prev_receipt_id: prev,
            issued_at: "2026-08-06T00:00:00+00:00".into(),
            extensions: BTreeMap::new(),
        };
        receipt.receipt_id = receipt.compute_id().unwrap();
        SignedExecutionReceipt::sign(receipt, &signing_key, "2026-08-06T00:00:00+00:00").unwrap()
    }

    #[test]
    fn append_bumps_sequence_and_head() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open(dir.path(), "local").unwrap();

        // The store supplies the parent; the first receipt gets none.
        let mut first_id = None;
        let seq1 = store
            .append_chained(|prev| {
                assert_eq!(prev, None, "a fresh store has no head to chain to");
                let r = sample_receipt(prev, 1);
                first_id = Some(r.payload.receipt_id.clone());
                Ok(r)
            })
            .unwrap();
        assert_eq!(seq1, 1);
        let first_id = first_id.unwrap();

        let head = store.head().unwrap();
        assert_eq!(head.sequence, 1);
        assert_eq!(head.last_receipt_id, Some(first_id.clone()));

        let seq2 = store
            .append_chained(|prev| {
                assert_eq!(prev.as_deref(), Some(first_id.as_str()));
                Ok(sample_receipt(prev, 2))
            })
            .unwrap();
        assert_eq!(seq2, 2);

        let head = store.head().unwrap();
        assert_eq!(head.sequence, 2);
        assert_ne!(head.last_receipt_id, Some(first_id));
    }

    /// Concurrent writers must extend one chain, never fork it.
    ///
    /// A fork — two receipts naming the same parent — is what an offline
    /// verifier reads as "a preceding receipt was deleted or reordered". It
    /// can only be created at write time, by two writers that both observed
    /// the same head, so the head read and the link it produces have to sit
    /// inside one lock rather than two.
    #[test]
    fn concurrent_writers_extend_one_chain_without_forking() {
        const WRITERS: u64 = 8;
        const EACH: u64 = 12;

        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open(dir.path(), "local").unwrap();

        std::thread::scope(|scope| {
            for w in 0..WRITERS {
                let store = store.clone();
                scope.spawn(move || {
                    for i in 0..EACH {
                        store
                            .append_chained(|prev| Ok(sample_receipt(prev, w * EACH + i)))
                            .unwrap();
                    }
                });
            }
        });

        let total = WRITERS * EACH;
        assert_eq!(store.head().unwrap().sequence, total);

        // Walk the store in sequence order: each receipt must name exactly its
        // predecessor, and the genesis receipt must name nobody.
        let chain: Vec<SignedExecutionReceipt> = (1..=total)
            .map(|seq| {
                let path = store.receipt_path(seq, receipt_type::PLAN_ADMITTED);
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|e| panic!("receipt {seq} missing at {}: {e}", path.display()));
                serde_json::from_slice(&bytes).expect("stored receipt parses")
            })
            .collect();

        assert_eq!(
            chain[0].payload.prev_receipt_id, None,
            "genesis has no parent"
        );
        for (idx, pair) in chain.windows(2).enumerate() {
            assert_eq!(
                pair[1].payload.prev_receipt_id.as_deref(),
                Some(pair[0].payload.receipt_id.as_str()),
                "receipt at sequence {} must chain to sequence {}",
                idx + 2,
                idx + 1,
            );
        }

        // State the fork property directly: no parent is ever claimed twice.
        let mut parents: Vec<&str> = chain
            .iter()
            .filter_map(|r| r.payload.prev_receipt_id.as_deref())
            .collect();
        let claimed = parents.len();
        parents.sort_unstable();
        parents.dedup();
        assert_eq!(
            parents.len(),
            claimed,
            "a parent was claimed by two receipts"
        );
    }

    #[test]
    fn receipt_files_are_written_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open(dir.path(), "local").unwrap();
        let mut expected_id = None;
        store
            .append_chained(|prev| {
                let r = sample_receipt(prev, 3);
                expected_id = Some(r.payload.receipt_id.clone());
                Ok(r)
            })
            .unwrap();

        let path = store.receipt_path(1, receipt_type::PLAN_ADMITTED);
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        let loaded: SignedExecutionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(Some(loaded.payload.receipt_id), expected_id);

        // No temp file survives a successful write, whatever it was named.
        let leftovers: Vec<_> = std::fs::read_dir(&store.tenant_dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n.to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// A failure inside `build` must leave the store exactly as it was: no
    /// sequence burned, no head moved, no partial receipt on disk. A receipt
    /// that could not be signed is a receipt that never happened.
    #[test]
    fn a_failed_build_advances_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open(dir.path(), "local").unwrap();
        store
            .append_chained(|prev| Ok(sample_receipt(prev, 1)))
            .unwrap();
        let before = store.head().unwrap();

        let err = store
            .append_chained(|_| anyhow::bail!("signing key unavailable"))
            .unwrap_err();
        assert!(err.to_string().contains("signing key unavailable"));

        assert_eq!(store.head().unwrap(), before, "head must not have moved");
        assert!(
            !store.receipt_path(2, receipt_type::PLAN_ADMITTED).exists(),
            "no receipt file for the sequence that was never assigned"
        );

        // And the next real append takes the sequence the failure did not.
        let seq = store
            .append_chained(|prev| Ok(sample_receipt(prev, 2)))
            .unwrap();
        assert_eq!(seq, 2);
    }
}
