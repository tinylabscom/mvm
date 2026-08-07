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
//! for the same tenant, forming a host-signer chain. Updates to `head.json`
//! and receipt files are made under a per-tenant file lock so concurrent
//! emitters cannot interleave sequences or lose the chain head.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::receipt::SignedExecutionReceipt;
use serde::{Deserialize, Serialize};

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

    /// Append a signed receipt to the store, returning the assigned sequence
    /// number. The caller is responsible for setting the receipt's
    /// `prev_receipt_id` to the value returned by [`Self::head`] before
    /// calling this method; this method only persists the receipt and bumps
    /// the head.
    ///
    /// The write is atomic: the receipt is written to a temp file and
    /// renamed, and the head is rewritten atomically under the tenant lock.
    pub fn append(&self, receipt: &SignedExecutionReceipt) -> Result<u64> {
        let _guard = self.lock()?;
        let mut head = self.read_head();
        head.sequence += 1;
        let seq = head.sequence;
        let receipt_path = self.receipt_path(seq, &receipt.payload.receipt_type);

        // Write receipt atomically.
        let tmp_path = receipt_path.with_extension("tmp");
        let bytes =
            serde_json::to_vec_pretty(receipt).context("serializing signed execution receipt")?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("writing receipt temp file {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &receipt_path).with_context(|| {
            format!(
                "renaming receipt file {} -> {}",
                tmp_path.display(),
                receipt_path.display()
            )
        })?;

        // Update head atomically.
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
        let tmp_path = self.head_path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(head).context("serializing receipt head")?;
        std::fs::write(&tmp_path, bytes)
            .with_context(|| format!("writing head temp file {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &self.head_path).with_context(|| {
            format!(
                "renaming head file {} -> {}",
                tmp_path.display(),
                self.head_path.display()
            )
        })?;
        Ok(())
    }

    #[cfg(unix)]
    fn lock(&self) -> Result<LockGuard> {
        use std::os::fd::AsRawFd;
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("opening lock file {}", self.lock_path.display()))?;
        let fd = file.as_raw_fd();
        // SAFETY: fcntl flock is safe when fd is valid and we hold the file
        // object for the lifetime of the guard.
        unsafe {
            let mut flock: libc::flock = std::mem::zeroed();
            flock.l_type = libc::F_WRLCK as _;
            flock.l_whence = libc::SEEK_SET as _;
            if libc::fcntl(fd, libc::F_SETLKW, &flock) != 0 {
                anyhow::bail!("failed to acquire receipt store lock");
            }
        }
        Ok(LockGuard { _file: file })
    }

    #[cfg(not(unix))]
    fn lock(&self) -> Result<LockGuard> {
        // Non-Unix platforms get a best-effort guard with no locking.
        Ok(LockGuard)
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

#[cfg(unix)]
struct LockGuard {
    _file: std::fs::File,
}

#[cfg(not(unix))]
struct LockGuard;

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

        let r1 = sample_receipt(None, 1);
        let seq1 = store.append(&r1).unwrap();
        assert_eq!(seq1, 1);

        let head = store.head().unwrap();
        assert_eq!(head.sequence, 1);
        assert_eq!(head.last_receipt_id, Some(r1.payload.receipt_id.clone()));

        let r2 = sample_receipt(Some(r1.payload.receipt_id.clone()), 2);
        let seq2 = store.append(&r2).unwrap();
        assert_eq!(seq2, 2);

        let head = store.head().unwrap();
        assert_eq!(head.sequence, 2);
        assert_eq!(head.last_receipt_id, Some(r2.payload.receipt_id.clone()));
    }

    #[test]
    fn receipt_files_are_written_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open(dir.path(), "local").unwrap();
        let receipt = sample_receipt(None, 3);
        store.append(&receipt).unwrap();

        let path = store.receipt_path(1, receipt_type::PLAN_ADMITTED);
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        let loaded: SignedExecutionReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded.payload.receipt_id, receipt.payload.receipt_id);
        assert!(
            !store
                .tenant_dir
                .join("00000001-plan.admitted.json.tmp")
                .exists()
        );
    }
}
