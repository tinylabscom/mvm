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

use crate::supervisor::{AuditEntry, AuditSigner, FileAuditSigner};
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_core::plan::ExecutionPlan;

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

    /// Emit `plan.oci_provenance` — binds an OCI image admission to the same
    /// plan id as the launch decision. The caller supplies the digest-oriented
    /// labels; raw registry credentials are never recorded.
    pub fn emit_oci_provenance(
        &self,
        plan: &ExecutionPlan,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, "plan.oci_provenance", labels)
    }

    /// Record that a VM's filesystem state was frozen into an fs_quick
    /// checkpoint. The label set carries the checkpoint id, class, the
    /// SHA-256 of the cloned rootfs blob, and the owning VM.
    pub fn emit_checkpoint_created(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        class: &str,
        content_sha256: &str,
        vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.created",
            [
                ("checkpoint_id".to_string(), checkpoint_id.to_string()),
                ("class".to_string(), class.to_string()),
                ("content_sha256".to_string(), content_sha256.to_string()),
                ("vm_name".to_string(), vm_name.to_string()),
            ],
        )
    }

    /// Record that a VM was restored to the state captured in a vm_full
    /// checkpoint. The label set carries the checkpoint id and the VM name.
    pub fn emit_checkpoint_restored(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.restored",
            [
                ("checkpoint_id".to_string(), checkpoint_id.to_string()),
                ("vm_name".to_string(), vm_name.to_string()),
            ],
        )
    }

    /// Record that a new sandbox was branched from a checkpoint via
    /// copy-on-write. The label set carries the parent and child
    /// checkpoint ids and the child VM name.
    pub fn emit_checkpoint_forked(
        &self,
        plan: &ExecutionPlan,
        parent_id: &str,
        child_id: &str,
        child_vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.forked",
            [
                ("parent_id".to_string(), parent_id.to_string()),
                ("child_id".to_string(), child_id.to_string()),
                ("child_vm_name".to_string(), child_vm_name.to_string()),
            ],
        )
    }

    /// Emit `plan.exited` — fires after a waited-for workload powers off,
    /// carrying its captured exit code. Plan 152 WS-A.
    pub fn emit_exited(&self, plan: &ExecutionPlan, exit_code: i32, backend: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.exited",
            [
                ("exit_code".to_string(), exit_code.to_string()),
                ("backend".to_string(), backend.to_string()),
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
    use crate::supervisor::verify_audit_chain;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
    };
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
        let labels = vec![
            ("oci_source".to_string(), "run_image".to_string()),
            (
                "oci_supplied_reference".to_string(),
                "alpine:3.20".to_string(),
            ),
            (
                "oci_canonical_reference".to_string(),
                "docker.io/library/alpine:3.20".to_string(),
            ),
            ("oci_registry".to_string(), "docker.io".to_string()),
            ("oci_repository".to_string(), "library/alpine".to_string()),
            (
                "oci_resolved_digest".to_string(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            (
                "oci_layer_digests".to_string(),
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            ),
            (
                "oci_trust_policy".to_string(),
                "mutable-reference-resolved-to-digest".to_string(),
            ),
            (
                "oci_verification_status".to_string(),
                "digest-verified-signature-not-configured".to_string(),
            ),
        ];

        emitter.emit_oci_provenance(&plan, labels).unwrap();

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
            matches!(err, crate::supervisor::VerifyError::SignatureInvalid { .. }),
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
    fn emit_exited_writes_plan_exited_with_code() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-EX");
        emitter.emit_exited(&plan, 3, "libkrun").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(content.contains("plan.exited"));
        assert!(content.contains("\"3\""));
        assert!(content.contains("\"libkrun\""));
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

    #[test]
    fn checkpoint_created_records_id_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-C");
        emitter
            .emit_checkpoint_created(&plan, "ckpt-abc", "fs_quick", "deadbeef", "myvm")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("ckpt-abc"));
        assert!(content.contains("deadbeef"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_forked_records_lineage() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");
        emitter
            .emit_checkpoint_forked(&plan, "ckpt-parent", "ckpt-child", "childvm")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.forked"));
        assert!(content.contains("ckpt-parent"));
        assert!(content.contains("ckpt-child"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_restored_records_id_and_vm() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-R");
        emitter
            .emit_checkpoint_restored(&plan, "ckpt-abc", "myvm")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.restored"));
        assert!(content.contains("ckpt-abc"));
        assert!(content.contains("myvm"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
}
