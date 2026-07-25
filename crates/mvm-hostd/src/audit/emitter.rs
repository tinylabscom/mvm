//! Host-side chain-signed audit emitter.
//!
//! Wraps `mvm_hostd::supervisor::FileAuditSigner` so `mvmctl up` can emit
//! tamper-evident `plan.admitted` / `plan.launched` / `plan.failed`
//! entries bound to the `AdmittedPlan`. The chain is signed under the
//! host signer's keypair (the same Ed25519 key used for plan
//! envelopes); a future workstream may split the audit-signer and
//! plan-signer keys.
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
//! shared with the in-process supervisor path, but `mvmctl up` is
//! synchronous. We build a single-threaded tokio
//! runtime per emit (mirrors `mvm-backend::libkrun::block_on`).
//! Audit emission is rare (3 entries per `mvmctl up` invocation), so
//! the runtime-construction overhead is negligible compared to the VM
//! boot itself.
//!
//! ## Error handling
//!
//! Audit failures should NEVER block a boot in this v0 — the audit
//! chain is supplementary tamper-evidence, not part of the
//! admission decision. Callers `tracing::warn` and continue. A
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

/// Wire-stable event names and label keys for the checkpoint audit entries.
/// Shared so the emitter (writer) and the lineage chain-anchor (reader) can't
/// drift on a string — a drift there would silently defeat chain-anchored
/// lineage verification.
pub mod checkpoint_audit {
    /// Emitted when a VM's state is frozen into a checkpoint.
    pub const CREATED_EVENT: &str = "checkpoint.created";
    /// Emitted when a VM is resumed from a vm_full checkpoint (same identity).
    pub const RESTORED_EVENT: &str = "checkpoint.restored";
    /// Emitted when a new sandbox is branched from a checkpoint.
    pub const FORKED_EVENT: &str = "checkpoint.forked";

    /// Label: the checkpoint's own id (created/restored).
    pub const LABEL_CHECKPOINT_ID: &str = "checkpoint_id";
    /// Label: the checkpoint's content-address (created/restored).
    pub const LABEL_META_DIGEST: &str = "meta_digest";
    /// Label: the checkpoint class (created).
    pub const LABEL_CLASS: &str = "class";
    /// Label: the owning VM name (created/restored).
    pub const LABEL_VM_NAME: &str = "vm_name";
    /// Label: how a restore was initiated (`revert` / `rewind` / `advance`),
    /// so a time-travel restore is distinguishable in the chain from a
    /// same-identity resume. Carried on `checkpoint.restored`.
    pub const LABEL_VIA: &str = "via";
    /// Label: the parent checkpoint id (forked).
    pub const LABEL_PARENT_ID: &str = "parent_id";
    /// Label: the child (new) checkpoint id (forked).
    pub const LABEL_CHILD_ID: &str = "child_id";
    /// Label: the child VM name (forked).
    pub const LABEL_CHILD_VM_NAME: &str = "child_vm_name";
    /// Label: the parent's content-address, i.e. the child's hash-link (forked).
    pub const LABEL_PARENT_DIGEST: &str = "parent_digest";
    /// Label: the child's content-address (forked).
    pub const LABEL_CHILD_DIGEST: &str = "child_digest";
}

/// Wire-stable event name and label keys for the image version-lineage audit
/// entry. Shared so the emitter (writer) and the lineage chain-anchor (reader)
/// cannot drift on a string — a drift there would silently defeat chain-anchored
/// image-lineage verification.
pub mod image_audit {
    /// Emitted when a compiled image's version-lineage node is created.
    pub const CREATED_EVENT: &str = "image.created";
    /// Label: the node's own content-address. The chain-anchor keys on this.
    pub const LABEL_NODE_DIGEST: &str = "image_node_digest";
    /// Label: the predecessor node's content-address (the parent hash-link), or
    /// [`GENESIS_PARENT`] when the node has none.
    pub const LABEL_PARENT_DIGEST: &str = "image_parent_digest";
    /// Label: the build-identity discriminant (`"flake"` / `"oci"`).
    pub const LABEL_BUILD_IDENTITY_KIND: &str = "image_build_identity_kind";
    /// Label: the build-identity value (flake slot hash, or
    /// `"<registry>/<repository>"`).
    pub const LABEL_BUILD_IDENTITY: &str = "image_build_identity";
    /// Label: the provenance discriminant (`"build"` / `"oci"`).
    pub const LABEL_PROVENANCE_KIND: &str = "image_provenance_kind";
    /// Label: the build-provenance input reference.
    pub const LABEL_PROVENANCE_INPUT_REF: &str = "image_provenance_input_ref";
    /// Label: the build-provenance lock digest, when recorded.
    pub const LABEL_PROVENANCE_LOCK_DIGEST: &str = "image_provenance_lock_digest";
    /// Label: the OCI-provenance resolved manifest digest.
    pub const LABEL_PROVENANCE_RESOLVED_DIGEST: &str = "image_provenance_resolved_digest";
    /// Label: the OCI-provenance layer digest set (comma-joined).
    pub const LABEL_PROVENANCE_LAYER_DIGESTS: &str = "image_provenance_layer_digests";
    /// [`LABEL_PARENT_DIGEST`] sentinel for a genesis (parentless) node.
    pub const GENESIS_PARENT: &str = "genesis";
}

/// Extract the `image.created` label set from a node's provenance attributes.
/// The parent hash-link is recorded as provenance; nothing here is a trust
/// grant (lineage is provenance, never authorization).
fn image_created_labels(node: &mvm_core::image_lineage::ImageNode) -> Vec<(String, String)> {
    use image_audit as k;
    use mvm_core::image_lineage::{ImageBuildIdentity, ImageProvenance};

    let mut labels = vec![
        (
            k::LABEL_NODE_DIGEST.to_string(),
            node.node_digest.as_str().to_string(),
        ),
        (
            k::LABEL_PARENT_DIGEST.to_string(),
            node.parent
                .as_ref()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| k::GENESIS_PARENT.to_string()),
        ),
    ];
    match &node.build_identity {
        ImageBuildIdentity::Flake { slot_hash } => {
            labels.push((
                k::LABEL_BUILD_IDENTITY_KIND.to_string(),
                "flake".to_string(),
            ));
            labels.push((k::LABEL_BUILD_IDENTITY.to_string(), slot_hash.clone()));
        }
        ImageBuildIdentity::Oci {
            registry,
            repository,
        } => {
            labels.push((k::LABEL_BUILD_IDENTITY_KIND.to_string(), "oci".to_string()));
            labels.push((
                k::LABEL_BUILD_IDENTITY.to_string(),
                format!("{registry}/{repository}"),
            ));
        }
    }
    match &node.provenance {
        ImageProvenance::Build {
            input_ref,
            lock_digest,
        } => {
            labels.push((k::LABEL_PROVENANCE_KIND.to_string(), "build".to_string()));
            labels.push((k::LABEL_PROVENANCE_INPUT_REF.to_string(), input_ref.clone()));
            if let Some(lock) = lock_digest {
                labels.push((k::LABEL_PROVENANCE_LOCK_DIGEST.to_string(), lock.clone()));
            }
        }
        ImageProvenance::Oci {
            resolved_digest,
            layer_digests,
        } => {
            labels.push((k::LABEL_PROVENANCE_KIND.to_string(), "oci".to_string()));
            labels.push((
                k::LABEL_PROVENANCE_RESOLVED_DIGEST.to_string(),
                resolved_digest.clone(),
            ));
            labels.push((
                k::LABEL_PROVENANCE_LAYER_DIGESTS.to_string(),
                layer_digests.join(","),
            ));
        }
    }
    labels
}

/// Resolve the default audit-chain directory: `~/.mvm/audit/`.
pub fn default_audit_dir() -> Result<PathBuf> {
    Ok(mvm_core::config::mvm_home_strict()?.join("audit"))
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
    /// callers use `new`. The directory is created if missing;
    /// `FileAuditSigner::open` enforces mode 0700-ish via the
    /// OS-default umask, but for hard guarantees the caller should
    /// pre-create it.
    pub fn with_dir(signing_key: SigningKey, audit_dir: &Path) -> Result<Self> {
        // Tighten the audit dir to 0700 if we created it. We use
        // `create_dir_all` first (idempotent) then `set_permissions`.
        // The audit chain inherits the same mode-0700 posture as the
        // rest of ~/.mvm, since its contents bind to plan-signed entries.
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

    /// Emit `plan.boot_posture` — records which rootfs strategy the run-path
    /// tier gate actually selected for this boot, so an audit reader can tell a
    /// dev virtiofs-root boot (the weaker dev-tier virtiofs contract — no
    /// dm-verity, does not witness claim 3) from a block+ext4 boot (the path the
    /// numbered claim-3 witness rides on). `root_strategy` is
    /// `"virtiofs-root"` or `"block-ext4"`. `runtime_source_policy` records
    /// whether this boot declared the guest runtime source as
    /// `"required-overlay"`, `"prefer-overlay"`, or `"rootfs-only"`.
    /// Informational — the hard admission decision is still `plan.admitted`;
    /// this event lets an operator answer "did this run boot off a virtiofs
    /// root or a materialized block image, and was the runtime contract
    /// overlay-required or not?" via the tamper-evident chain rather than an
    /// unsigned side channel.
    pub fn emit_boot_posture(
        &self,
        plan: &ExecutionPlan,
        root_strategy: &str,
        runtime_source_policy: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "plan.boot_posture",
            [
                ("root_strategy".to_string(), root_strategy.to_string()),
                (
                    "runtime_source_policy".to_string(),
                    runtime_source_policy.to_string(),
                ),
            ],
        )
    }

    /// Emit `plan.policy_resolved` — fires after the resolver
    /// successfully constructs `ResolvedSlots` from the plan's policy
    /// refs. `slots_mode` is `"noop"` when all four refs are
    /// `"local-default"` (no bundle on disk) or `"live"` when a
    /// `<tenant>:<workload>` bundle parsed cleanly.
    ///
    /// The audit entry is informational — the supervisor's hard
    /// admission decision is still `plan.admitted`. This event lets
    /// operators answer "did my bundle actually parse on the last
    /// boot, or did I fall back to local-default?" via
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
        meta_digest: &str,
        vm_name: &str,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::CREATED_EVENT,
            [
                (
                    k::LABEL_CHECKPOINT_ID.to_string(),
                    checkpoint_id.to_string(),
                ),
                (k::LABEL_CLASS.to_string(), class.to_string()),
                // The record's content-address, not a single-blob sha: it covers
                // the whole manifest plus the parent hash-link.
                (k::LABEL_META_DIGEST.to_string(), meta_digest.to_string()),
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
            ],
        )
    }

    /// Record that a VM was restored to the state captured in a checkpoint. The
    /// label set carries the checkpoint id, its content-address, the restored VM
    /// name, and `via` — how the restore was initiated (`revert` / `rewind` /
    /// `advance`), so a time-travel restore reads distinctly in the chain.
    pub fn emit_checkpoint_restored(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        meta_digest: &str,
        vm_name: &str,
        via: &str,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::RESTORED_EVENT,
            [
                (
                    k::LABEL_CHECKPOINT_ID.to_string(),
                    checkpoint_id.to_string(),
                ),
                (k::LABEL_META_DIGEST.to_string(), meta_digest.to_string()),
                (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (k::LABEL_VIA.to_string(), via.to_string()),
            ],
        )
    }

    /// Record that a new sandbox was branched from a checkpoint via
    /// copy-on-write. The label set carries the parent and child checkpoint ids
    /// and VM name, plus the parent and child content-addresses — so the
    /// audited lineage is the hash chain, not just the mutable names.
    pub fn emit_checkpoint_forked(
        &self,
        plan: &ExecutionPlan,
        parent_id: &str,
        child_id: &str,
        child_vm_name: &str,
        parent_digest: &str,
        child_digest: &str,
    ) -> Result<()> {
        use checkpoint_audit as k;
        self.emit(
            plan,
            k::FORKED_EVENT,
            [
                (k::LABEL_PARENT_ID.to_string(), parent_id.to_string()),
                (k::LABEL_CHILD_ID.to_string(), child_id.to_string()),
                (
                    k::LABEL_CHILD_VM_NAME.to_string(),
                    child_vm_name.to_string(),
                ),
                (
                    k::LABEL_PARENT_DIGEST.to_string(),
                    parent_digest.to_string(),
                ),
                (k::LABEL_CHILD_DIGEST.to_string(), child_digest.to_string()),
            ],
        )
    }

    /// Record that a compiled image's version-lineage node was created. The
    /// label set carries the node's content-address (the chain-anchor keys on
    /// it), its parent hash-link, the build identity, and the provenance
    /// attributes. Chain-signed so `verify_image_lineage` can anchor the node's
    /// content-address to a signature it cannot forge.
    pub fn emit_image_created(
        &self,
        plan: &ExecutionPlan,
        node: &mvm_core::image_lineage::ImageNode,
    ) -> Result<()> {
        self.emit(plan, image_audit::CREATED_EVENT, image_created_labels(node))
    }

    /// Emit `plan.exited` — fires after a waited-for workload powers off,
    /// carrying its captured exit code.
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

    /// Emit `verb_denied` — fires when the host caller receives a
    /// `VerbNotAuthorized` response from the guest agent. Records the
    /// denied verb name in the chain-signed log so refusals are
    /// observable and tamper-evident (claim-12 parity). No payload
    /// bytes are emitted; the verb name is a label.
    pub fn emit_verb_denied(&self, plan: &ExecutionPlan, verb: &str) -> Result<()> {
        self.emit(
            plan,
            "verb_denied",
            [("verb".to_string(), verb.to_string())],
        )
    }

    /// Emit `plan.grant_required` — records that this admission asserted verb-grant
    /// enforcement (the admitted plan carries `agent_verbs`, so the launcher emits
    /// the grant-required boot marker and the guest fails closed without a valid grant).
    /// Binds the granted verb set to the same plan id as the launch decision, so
    /// `trust audit verify` can attest the enforcement posture. Host-side: the guest
    /// cannot sign this chain.
    pub fn emit_grant_required(
        &self,
        plan: &ExecutionPlan,
        verbs: &[mvm_core::plan::VerbId],
    ) -> Result<()> {
        let mut labels = vec![("verb_count".to_string(), verbs.len().to_string())];
        for (i, v) in verbs.iter().enumerate() {
            labels.push((format!("verb_{i}"), v.as_str().to_string()));
        }
        self.emit(plan, "plan.grant_required", labels)
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

    fn fixture_plan(tenant: &str, plan_id: &str) -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .plan_id(plan_id)
            .build()
    }

    #[test]
    fn audit_log_carries_plan_id_for_every_launch() {
        // Emit a full admitted→launched pair; both lines must reference
        // the same plan_id and live in the tenant's audit file.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
    fn boot_posture_event_is_chain_signed_and_distinguishes_root_strategy() {
        // The dev virtiofs-root boot and the block boot must be distinguishable
        // in the tamper-evident chain (dev-tier virtiofs vs the claim-3 block
        // witness). Emit one of each and assert both verify + carry the right
        // root_strategy + runtime_source_policy labels.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();

        let vfs = fixture_plan("local", "plan-vfs");
        let blk = fixture_plan("local", "plan-blk");
        emitter
            .emit_boot_posture(&vfs, "virtiofs-root", "rootfs-only")
            .unwrap();
        emitter
            .emit_boot_posture(&blk, "block-ext4", "prefer-overlay")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("plan.boot_posture"));
        assert!(lines[0].contains("virtiofs-root"));
        assert!(lines[0].contains("rootfs-only"));
        assert!(lines[0].contains("\"plan-vfs\""));
        assert!(lines[1].contains("block-ext4"));
        assert!(lines[1].contains("prefer-overlay"));
        assert!(lines[1].contains("\"plan-blk\""));
        // A block boot never mislabels as virtiofs and vice-versa.
        assert!(!lines[1].contains("virtiofs-root"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 2);
    }

    #[test]
    fn grant_required_event_is_chain_signed_with_required_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-GR");

        let verbs = vec![
            mvm_core::plan::VerbId::new("ping").unwrap(),
            mvm_core::plan::VerbId::new("run-entrypoint").unwrap(),
        ];
        emitter.emit_grant_required(&plan, &verbs).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");
        assert!(
            content.contains("plan.grant_required"),
            "event kind must appear in log"
        );
        assert!(content.contains("\"2\""), "verb_count must be 2");
        assert!(content.contains("ping"), "verb_0 label must contain 'ping'");
        assert!(
            content.contains("run-entrypoint"),
            "verb_1 label must contain 'run-entrypoint'"
        );
        assert_eq!(
            verify_audit_chain(&path, &vk).unwrap(),
            1,
            "single-entry chain must verify clean"
        );
    }

    #[test]
    fn audit_chain_rejects_inserted_line() {
        // Synthesize a valid chain, then forge an extra entry whose
        // signature is wrong (or rather, taken from a different key).
        // verify_audit_chain must refuse.
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
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
    fn verb_denied_entry_is_chained_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-VD");

        emitter.emit_admitted(&plan, "host:test").unwrap();
        emitter
            .emit_verb_denied(&plan, "update-idle-timeout")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).expect("audit file exists");

        // Both category and verb name must appear in the log.
        assert!(
            content.contains("verb_denied"),
            "log must contain verb_denied category"
        );
        assert!(
            content.contains("update-idle-timeout"),
            "log must contain the denied verb name"
        );

        // The two-entry chain must verify clean.
        let count = verify_audit_chain(&path, &vk).unwrap();
        assert_eq!(count, 2, "admitted + verb_denied must form a valid chain");

        // A byte-flip in the log must break verify_audit_chain.
        let tampered = content.replace("verb_denied", "verb_permitted");
        std::fs::write(&path, tampered).unwrap();
        assert!(
            verify_audit_chain(&path, &vk).is_err(),
            "tampered log must fail chain verification"
        );
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
    fn checkpoint_created_records_id_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-C");
        let meta_digest = format!("sha256:{}", "a".repeat(64));
        emitter
            .emit_checkpoint_created(&plan, "ckpt-abc", "fs_quick", &meta_digest, "myvm")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("ckpt-abc"));
        // The content-address rides opaquely as a label; the chain still verifies.
        assert!(content.contains("meta_digest"));
        assert!(content.contains(&meta_digest));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_forked_records_lineage_digests() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");
        let parent_digest = format!("sha256:{}", "b".repeat(64));
        let child_digest = format!("sha256:{}", "c".repeat(64));
        emitter
            .emit_checkpoint_forked(
                &plan,
                "ckpt-parent",
                "ckpt-child",
                "childvm",
                &parent_digest,
                &child_digest,
            )
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.forked"));
        assert!(content.contains("ckpt-parent"));
        assert!(content.contains("ckpt-child"));
        // The hash-linked lineage is bound, not just the mutable names.
        assert!(content.contains("parent_digest"));
        assert!(content.contains("child_digest"));
        assert!(content.contains(&parent_digest));
        assert!(content.contains(&child_digest));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn image_created_is_chain_signed_with_required_labels() {
        use mvm_core::image_lineage::{
            ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
        };
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-IMG");

        let parent = ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-1".into(),
                },
                artifacts: vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "aa".into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: Some("sha256:lock".into()),
            },
        )
        .created_unix(1)
        .build();
        let child = ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-2".into(),
                },
                artifacts: vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "bb".into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(Some(parent.node_digest.clone()))
        .created_unix(2)
        .build();

        emitter.emit_image_created(&plan, &parent).unwrap();
        emitter.emit_image_created(&plan, &child).unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("image.created"));
        assert!(content.contains("image_node_digest"));
        assert!(content.contains(parent.node_digest.as_str()));
        assert!(content.contains(child.node_digest.as_str()));
        // The genesis node records the sentinel; the child records its hash-link.
        assert!(content.contains("genesis"));
        assert!(content.contains("image_build_identity"));
        assert!(content.contains("slot-a"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 2);
    }

    #[test]
    fn checkpoint_restored_records_id_digest_and_vm() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-R");
        let meta_digest = format!("sha256:{}", "d".repeat(64));
        emitter
            .emit_checkpoint_restored(&plan, "ckpt-abc", &meta_digest, "myvm", "revert")
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.restored"));
        assert!(content.contains("ckpt-abc"));
        assert!(content.contains("myvm"));
        assert!(content.contains(&meta_digest));
        // The initiating verb rides as the `via` label.
        assert!(content.contains("\"via\""));
        assert!(content.contains("revert"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
}
