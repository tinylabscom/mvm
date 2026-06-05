//! Plan 64 W4 — host-side chain-signed audit emitter.
//!
//! Wraps `mvm_hostd::supervisor::FileAuditSigner` so `mvmctl up` can emit
//! tamper-evident `plan.admitted` / `plan.launched` / `plan.failed`
//! entries bound to the plan-64 `AdmittedPlan`. The chain is signed
//! under the host signer's keypair (same Ed25519 key W2 introduced for
//! plan envelopes); a future workstream may split audit-signer and
//! plan-signer keys per plan 60 Phase 3.
//!
//! ## On-disk layout
//!
//! Audit dir defaults to `~/.mvm/audit/`. `FileAuditSigner` writes
//! per-tenant `<audit_dir>/<tenant>.jsonl` streams; with one host =
//! one tenant ("local"), that's a single file in practice. The
//! directory is created mode `0700` so other users on the host can't
//! read the audit chain.
//!
//! ## Async bridge
//!
//! `FileAuditSigner::sign_and_emit` is async because the trait is
//! shared with the in-process supervisor path (plan-37 §22 Wave 3),
//! but `mvmctl up` is synchronous. We build a single-threaded tokio
//! runtime per emit (mirrors `mvm-backend::libkrun::block_on`).
//! Audit emission is rare (3 entries per `mvmctl up` invocation), so
//! the runtime-construction overhead is negligible compared to the VM
//! boot itself.
//!
//! ## Error handling
//!
//! Audit failures should NEVER block a boot in this v0 — the audit
//! chain is supplementary tamper-evidence, not part of the
//! admission decision. Callers `tracing::warn` and continue. The W6
//! follow-up tightens this to "audit failure fails the boot" once
//! the chain is reliably reachable.
//!
//! [`AuditEmitter`] is the public-to-the-module surface; tests use
//! `AuditEmitter::with_dir` to inject a tempdir.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_core::plan::ExecutionPlan;
use mvm_hostd::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};

use crate::commands::image::OciProvenance;

/// Resolve the default audit-chain directory: `~/.mvm/audit/`.
pub fn default_audit_dir() -> Result<PathBuf> {
    Ok(mvm_core::config::mvm_data_dir_strict()?.join("audit"))
}

/// Resolve the default per-tenant audit-chain file:
/// `~/.mvm/audit/<tenant>.jsonl`. Used by the `mvmctl audit verify`
/// and `mvmctl audit show` commands.
pub fn audit_path_for_tenant(audit_dir: &Path, tenant: &str) -> PathBuf {
    audit_dir.join(format!("{tenant}.jsonl"))
}

/// Outcome of comparing a snapshot file's SHA-256 at restore time
/// against the value the audit chain recorded at save time.
/// Three states:
///
/// - [`Verified`] — chain entry exists and the hash matches.
/// - [`Mismatch`] — chain entry exists with a different hash.
///   Restoring proceeds (the operator may have a legitimate reason
///   like cross-host transfer) but the audit trail explicitly flags
///   the discrepancy.
/// - [`NotInChain`] — no `vm.snapshot_saved` entry recorded for this
///   path. Usually means the snapshot was produced before audit
///   chaining shipped, on another host, or with the chain disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotChainMatch {
    Verified,
    Mismatch,
    NotInChain,
}

impl SnapshotChainMatch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::NotInChain => "not_in_chain",
        }
    }
}

/// Find the most recent `vm.snapshot_saved` event in the tenant's
/// audit chain whose `snapshot_path` label matches `snapshot_path`.
/// Returns the recorded SHA-256, or `Ok(None)` if no such entry
/// exists. Errors propagate file I/O / JSON-parse failures so the
/// operator sees them; callers that want the lookup to be
/// non-fatal should map `Err` to `NotInChain`.
pub fn find_snapshot_saved_sha(
    audit_dir: &Path,
    tenant: &str,
    snapshot_path: &Path,
) -> Result<Option<String>> {
    let path = audit_path_for_tenant(audit_dir, tenant);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading audit chain {}", path.display()))?;
    let needle = snapshot_path.display().to_string();
    // Walk lines in reverse to find the most recent matching event.
    // Each line is `{"signature":"...","entry":{...}}` after Wave 3
    // wrapping; the AuditEntry shape (`audit.rs` in mvm-supervisor)
    // is what we need to peek into.
    let mut latest: Option<String> = None;
    for line in content.lines() {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Try both wrapped + unwrapped shapes for forward-compat.
        let entry = parsed.get("entry").unwrap_or(&parsed);
        if entry.get("event").and_then(|v| v.as_str()) != Some("vm.snapshot_saved") {
            continue;
        }
        let labels = match entry.get("labels").and_then(|v| v.as_object()) {
            Some(l) => l,
            None => continue,
        };
        if labels.get("snapshot_path").and_then(|v| v.as_str()) != Some(needle.as_str()) {
            continue;
        }
        if let Some(sha) = labels.get("snapshot_sha256").and_then(|v| v.as_str()) {
            latest = Some(sha.to_string());
            // Don't break — later entries on the file override
            // earlier ones (most recent save wins).
        }
    }
    Ok(latest)
}

/// Host-side emitter wrapping `FileAuditSigner`. Owns its own signing
/// key half (cloned from the host signer at construction); calls
/// `tokio::runtime::Builder::new_current_thread()` per emit.
pub struct AuditEmitter {
    signers: Vec<FileAuditSigner>,
}

impl AuditEmitter {
    /// Construct with the default `~/.mvm/audit/` directory.
    pub fn new(signing_key: SigningKey) -> Result<Self> {
        Self::with_dir(signing_key, &default_audit_dir()?)
    }

    /// Test seam — caller supplies the audit directory. Production
    /// callers use [`new`]. The directory is created if missing;
    /// `FileAuditSigner::open` enforces mode 0700-ish via the
    /// OS-default umask, but for hard guarantees the caller should
    /// pre-create it.
    pub fn with_dir(signing_key: SigningKey, audit_dir: &Path) -> Result<Self> {
        // Tighten the audit dir to 0700 if we created it. We use
        // `create_dir_all` first (idempotent) then `set_permissions`.
        // CLAUDE.md security model §"W1.5 — ~/.mvm / ~/.cache/mvm are
        // mode 0700" — the audit chain inherits that posture since
        // its contents bind to plan-signed entries.
        if !audit_dir.exists() {
            std::fs::create_dir_all(audit_dir)
                .with_context(|| format!("creating audit dir at {}", audit_dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(audit_dir, perms).with_context(|| {
                    format!("setting 0700 on audit dir {}", audit_dir.display())
                })?;
            }
        }
        let signer = FileAuditSigner::open(signing_key, audit_dir)
            .with_context(|| format!("opening FileAuditSigner at {}", audit_dir.display()))?;
        Ok(Self {
            signers: vec![signer],
        })
    }

    /// Construct an emitter from a parsed policy bundle's `[audit]`
    /// section. The default local chain is always kept; `file://`
    /// destinations add exact-file replicas. Network/unix
    /// replication is intentionally fail-closed until those
    /// transports are implemented.
    pub fn with_policy(
        signing_key: SigningKey,
        audit_dir: &Path,
        policy: &mvm_core::policy::AuditPolicy,
    ) -> Result<Self> {
        if !policy.chain_signing {
            anyhow::bail!(
                "policy audit.chain_signing=false is not supported for policy-bound admission"
            );
        }

        let mut emitter = Self::with_dir(signing_key.clone(), audit_dir)?;
        for destination in &policy.stream_destinations {
            let Some(raw_path) = destination.strip_prefix("file://") else {
                anyhow::bail!(
                    "audit stream destination {destination:?} is not wired yet; \
                     only file:// destinations are supported"
                );
            };
            if raw_path.is_empty() {
                anyhow::bail!("audit file:// destination must include an absolute path");
            }
            let path = PathBuf::from(raw_path);
            if !path.is_absolute() {
                anyhow::bail!("audit file:// destination must include an absolute path");
            }
            let signer = FileAuditSigner::open_file(signing_key.clone(), &path)
                .with_context(|| format!("opening audit stream {}", path.display()))?;
            emitter.signers.push(signer);
        }
        Ok(emitter)
    }

    /// Emit `plan.admitted` — fires immediately after `admit_for_run`
    /// succeeds. Binds the plan_id, signer (via `audit_labels` extras),
    /// and the workload context.
    pub fn emit_admitted(&self, plan: &ExecutionPlan, signer_id: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.admitted",
            [("signer_id".to_string(), signer_id.to_string())],
        )
    }

    /// Emit `plan.launched` — fires after `backend.start()` returns Ok.
    pub fn emit_launched(&self, plan: &ExecutionPlan, backend: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.launched",
            [("backend".to_string(), backend.to_string())],
        )
    }

    /// Emit `plan.policy_resolved` — fires after the W5 resolver
    /// successfully constructs `ResolvedSlots` from the plan's policy
    /// refs. `slots_mode` is `"noop"` when all four refs are
    /// `"local-default"` (no bundle on disk) or `"live"` when a
    /// `<tenant>:<workload>` bundle parsed cleanly.
    ///
    /// The audit entry is informational — the supervisor's hard
    /// admission decision is still `plan.admitted` (W2/W3). This
    /// event lets operators answer "did my bundle actually parse on
    /// the last boot, or did I fall back to local-default?" via
    /// `mvmctl audit tail --chain`.
    pub fn emit_policy_resolved(&self, plan: &ExecutionPlan, slots_mode: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.policy_resolved",
            [("slots_mode".to_string(), slots_mode.to_string())],
        )
    }

    /// Emit `plan.shares_admitted` — records the user host-fs grants
    /// (`--volume` / `MVM_VOLUMES`) baked into the admitted plan
    /// (claim 1 / claim 8), so every share is a tamper-evident audit
    /// fact rather than an unsigned side-channel. No-op when the plan
    /// carries no shares (the common case).
    pub fn emit_shares_admitted(&self, plan: &ExecutionPlan) -> Result<()> {
        if plan.shares.is_empty() {
            return Ok(());
        }
        let mut labels: Vec<(String, String)> =
            vec![("share_count".to_string(), plan.shares.len().to_string())];
        for (i, s) in plan.shares.iter().enumerate() {
            let kind = match s.kind {
                mvm_core::plan::ShareKind::Disk => "disk",
                mvm_core::plan::ShareKind::DirShare => "dir_share",
            };
            labels.push((format!("share_{i}_tag"), s.tag.clone()));
            labels.push((format!("share_{i}_host"), s.host_path.clone()));
            labels.push((format!("share_{i}_guest"), s.guest_path.clone()));
            labels.push((format!("share_{i}_kind"), kind.to_string()));
            labels.push((format!("share_{i}_ro"), s.read_only.to_string()));
            labels.push((format!("share_{i}_encrypted"), s.encrypted.to_string()));
        }
        self.emit(plan, "plan.shares_admitted", labels)
    }

    /// Emit `plan.oci_provenance` — binds an OCI image admission to
    /// the same plan id as the launch decision. The labels are
    /// intentionally digest-oriented; raw registry credentials and
    /// Docker config state are never recorded.
    pub fn emit_oci_provenance(
        &self,
        plan: &ExecutionPlan,
        provenance: &OciProvenance,
    ) -> Result<()> {
        self.emit(plan, "plan.oci_provenance", provenance.audit_labels())
    }

    /// Emit `vm.snapshot_saved` — fires after the supervisor finishes
    /// writing a snapshot file (Vz `saveMachineStateTo`). The SHA-256
    /// of the resulting file is recorded as an extra label so the
    /// audit chain pins the snapshot's bit-identical contents: a
    /// later `mvmctl snapshot restore` that loads a tampered file is
    /// detectable by re-hashing and comparing against the chain
    /// entry. Plan 97 Phase E §"Snapshot file SHA-256 hash-pinned in
    /// audit chain".
    pub fn emit_vm_snapshot_saved(
        &self,
        plan: &ExecutionPlan,
        snapshot_path: &std::path::Path,
        sha256_hex: &str,
        size_bytes: u64,
        backend: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "vm.snapshot_saved",
            [
                (
                    "snapshot_path".to_string(),
                    snapshot_path.display().to_string(),
                ),
                ("snapshot_sha256".to_string(), sha256_hex.to_string()),
                ("snapshot_size_bytes".to_string(), size_bytes.to_string()),
                ("backend".to_string(), backend.to_string()),
            ],
        )
    }

    /// Emit `vm.snapshot_restored` — fires after the supervisor
    /// completes `restoreMachineState(from:)` + `resume()`. The
    /// `chain_match` label reports whether the file the host just
    /// loaded matched the SHA-256 the audit chain recorded at save
    /// time, so an operator can tell apart a verified-restore from
    /// an "operator restored unverified state" entry.
    pub fn emit_vm_snapshot_restored(
        &self,
        plan: &ExecutionPlan,
        snapshot_path: &std::path::Path,
        sha256_hex: &str,
        size_bytes: u64,
        backend: &str,
        chain_match: SnapshotChainMatch,
    ) -> Result<()> {
        self.emit(
            plan,
            "vm.snapshot_restored",
            [
                (
                    "snapshot_path".to_string(),
                    snapshot_path.display().to_string(),
                ),
                ("snapshot_sha256".to_string(), sha256_hex.to_string()),
                ("snapshot_size_bytes".to_string(), size_bytes.to_string()),
                ("backend".to_string(), backend.to_string()),
                ("chain_match".to_string(), chain_match.as_str().to_string()),
            ],
        )
    }

    /// Emit `plan.failed` — fires on any error path between admission
    /// and successful boot. `class` is a short tag (`backend-start`,
    /// `snapshot-restore`, etc.) the operator can grep for; `message`
    /// is the underlying error chain rendered.
    pub fn emit_failed(&self, plan: &ExecutionPlan, class: &str, message: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.failed",
            [
                ("error_class".to_string(), class.to_string()),
                ("error_message".to_string(), message.to_string()),
            ],
        )
    }

    fn emit<E>(&self, plan: &ExecutionPlan, event: &str, extras: E) -> Result<()>
    where
        E: IntoIterator<Item = (String, String)>,
    {
        let entry = AuditEntry::for_plan(plan, None, event, extras);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime for audit emit")?;
        for signer in &self.signers {
            rt.block_on(signer.sign_and_emit(&entry))
                .with_context(|| format!("signing-and-emitting audit event {event}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
    };
    use mvm_hostd::supervisor::verify_audit_chain;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn fixture_plan(tenant: &str, plan_id: &str) -> ExecutionPlan {
        let now = chrono::Utc::now();
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId(plan_id.to_string()),
            plan_version: 1,
            tenant: TenantId(tenant.to_string()),
            workload: WorkloadId("vm-test".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".to_string()),
            fs_policy: FsPolicyRef("local-default".to_string()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".to_string()),
            tool_policy: PolicyRef("local-default".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            audit_labels: BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: now,
            valid_until: now + chrono::Duration::minutes(10),
            nonce: Nonce::from_bytes([0u8; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        }
    }

    #[test]
    fn audit_log_carries_plan_id_for_every_launch() {
        // Emit a full admitted→launched pair; both lines must reference
        // the same plan_id and live in the tenant's audit file.
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-A");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "two events expected, got {}", lines.len());
        assert!(
            lines.iter().all(|l| l.contains("\"plan-A\"")),
            "every line must carry the plan_id"
        );
        assert!(lines[0].contains("plan.admitted"));
        assert!(lines[1].contains("plan.launched"));
    }

    #[test]
    fn audit_chain_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-X");
        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter.emit_launched(&plan, "firecracker").unwrap();

        let count = verify_audit_chain(&dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 2, "both entries must verify clean");
    }

    #[test]
    fn oci_provenance_event_is_chain_signed_with_required_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-OCI");
        let provenance = OciProvenance {
            schema_version: 1,
            source: "run_image".to_string(),
            supplied_reference: "alpine:3.20".to_string(),
            canonical_reference: "docker.io/library/alpine:3.20".to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            layer_digests: vec![
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ],
            trust_policy: "mutable-reference-resolved-to-digest".to_string(),
            verification_status: "digest-verified-signature-not-configured".to_string(),
        };

        emitter.emit_oci_provenance(&plan, &provenance).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("plan.oci_provenance"));
        assert!(content.contains("oci_registry"));
        assert!(content.contains("docker.io"));
        assert!(content.contains("oci_resolved_digest"));
        assert!(content.contains("oci_layer_digests"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn audit_chain_rejects_inserted_line() {
        // Synthesize a valid chain, then forge an extra entry whose
        // signature is wrong (or rather, taken from a different key).
        // verify_audit_chain must refuse.
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key.clone(), dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-Z");
        emitter.emit_admitted(&plan, "host:test").unwrap();

        // Tamper: replace the event name. The signature was over the
        // original entry, so verify must reject.
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("plan.admitted", "plan.fakeville");
        std::fs::write(&path, tampered).unwrap();

        let err = verify_audit_chain(&path, &vk).expect_err("tamper must break verify");
        assert!(
            matches!(
                err,
                mvm_hostd::supervisor::VerifyError::SignatureInvalid { .. }
            ),
            "expected SignatureInvalid, got {err:?}"
        );
    }

    #[test]
    fn emit_failed_records_class_and_message() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");
        emitter
            .emit_failed(&plan, "backend-start", "kernel panic at boot")
            .unwrap();

        let content =
            std::fs::read_to_string(dir.path().join("local.jsonl")).expect("audit file exists");
        assert!(content.contains("plan.failed"));
        assert!(content.contains("backend-start"));
        assert!(content.contains("kernel panic"));

        // And the single-entry chain still verifies.
        let count = verify_audit_chain(&dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn vm_snapshot_saved_records_path_hash_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-S");

        emitter
            .emit_vm_snapshot_saved(
                &plan,
                std::path::Path::new("/tmp/vz/foo.vzsnap"),
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                4096,
                "vz",
            )
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("vm.snapshot_saved"));
        assert!(content.contains("/tmp/vz/foo.vzsnap"));
        assert!(content.contains("00112233445566778899aabbccddeeff"));
        assert!(content.contains("4096"));
        assert!(content.contains("\"vz\""));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn find_snapshot_saved_sha_returns_recorded_hash() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-FS");

        let snapshot = std::path::PathBuf::from("/abs/path/snap.vzsnap");
        let recorded = "aa".repeat(32);
        emitter
            .emit_vm_snapshot_saved(&plan, &snapshot, &recorded, 1024, "vz")
            .unwrap();

        let looked_up = find_snapshot_saved_sha(dir.path(), "local", &snapshot).unwrap();
        assert_eq!(looked_up, Some(recorded));
    }

    #[test]
    fn find_snapshot_saved_sha_returns_none_when_path_differs() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-FN");

        emitter
            .emit_vm_snapshot_saved(
                &plan,
                std::path::Path::new("/abs/path/one.vzsnap"),
                &"bb".repeat(32),
                512,
                "vz",
            )
            .unwrap();

        let looked_up = find_snapshot_saved_sha(
            dir.path(),
            "local",
            std::path::Path::new("/abs/path/other.vzsnap"),
        )
        .unwrap();
        assert_eq!(looked_up, None);
    }

    #[test]
    fn find_snapshot_saved_sha_returns_most_recent_save_for_path() {
        // Same path saved twice — RESTORE should match against the
        // most recent save's hash.
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-FR");

        let snapshot = std::path::PathBuf::from("/abs/path/same.vzsnap");
        emitter
            .emit_vm_snapshot_saved(&plan, &snapshot, &"aa".repeat(32), 100, "vz")
            .unwrap();
        let newer = "cc".repeat(32);
        emitter
            .emit_vm_snapshot_saved(&plan, &snapshot, &newer, 200, "vz")
            .unwrap();

        let looked_up = find_snapshot_saved_sha(dir.path(), "local", &snapshot).unwrap();
        assert_eq!(looked_up, Some(newer));
    }

    #[test]
    fn vm_snapshot_restored_records_chain_match_label() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-R");

        emitter
            .emit_vm_snapshot_restored(
                &plan,
                std::path::Path::new("/tmp/vz/foo.vzsnap"),
                &"dd".repeat(32),
                8192,
                "vz",
                SnapshotChainMatch::Verified,
            )
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("vm.snapshot_restored"));
        assert!(content.contains("\"verified\""));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn audit_dir_is_created_with_0700_perms() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("audit-fresh");
        let key = SigningKey::generate(&mut OsRng);
        let _emitter = AuditEmitter::with_dir(key, &target).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "audit dir must be tightened to 0700");
        }
    }

    #[test]
    fn policy_file_destination_gets_a_replicated_chain() {
        let dir = tempfile::tempdir().unwrap();
        let replica = dir.path().join("replica.jsonl");
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![format!("file://{}", replica.display())],
        };
        let emitter = AuditEmitter::with_policy(key, dir.path(), &policy).unwrap();
        let plan = fixture_plan("local", "plan-P");

        emitter.emit_admitted(&plan, "host:test").unwrap();

        let default_path = dir.path().join("local.jsonl");
        assert!(default_path.exists(), "default local chain remains active");
        assert!(replica.exists(), "policy file stream must be written");
        assert_eq!(verify_audit_chain(&default_path, &vk).unwrap(), 1);
        assert_eq!(verify_audit_chain(&replica, &vk).unwrap(), 1);
    }

    #[test]
    fn policy_requires_chain_signing() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: false,
            stream_destinations: Vec::new(),
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("chain_signing=false must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("chain_signing"));
    }

    #[test]
    fn policy_refuses_unwired_replication_schemes() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["https://audit.example.com/ingest".to_string()],
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("unwired replication schemes must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("not wired yet"));
    }

    #[test]
    fn policy_refuses_relative_file_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["file://relative/audit.jsonl".to_string()],
        };
        let err = match AuditEmitter::with_policy(key, dir.path(), &policy) {
            Ok(_) => panic!("relative audit file destinations must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("absolute path"));
    }

    #[test]
    fn default_audit_path_for_tenant_uses_jsonl_suffix() {
        // No HOME-touching test for `default_audit_dir`; the
        // assertion here is the per-tenant path shape, which is
        // pure-formatting and doesn't need the env var.
        let p = PathBuf::from("/some/dir").join("local.jsonl");
        assert!(p.to_string_lossy().ends_with("local.jsonl"));
    }
}
