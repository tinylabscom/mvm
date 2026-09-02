//! `mvmctl trust audit transcript` — operator surface for opt-in forensic network
//! transcript captures.
//!
//! `arm` provisions a capture (per-capture data key wrapped under the host KEK
//! into the manifest) and records it in the audit log; the live byte-capture
//! that fills a capture's chunks happens at the host bridge, out of band. `list`
//! enumerates captures, `disarm` seals one, and `export` verifies + decrypts a
//! sealed capture (failing closed on tamper / wrong key / bound). Every
//! lifecycle step emits a chain-visible audit kind; raw payload bytes never
//! enter the audit log.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;

use mvm_core::config;
use mvm_core::crypto::aead;
use mvm_core::policy::audit::{LocalAuditBuilder, LocalAuditKind, event};
use mvm_core::transcript::{
    self, CaptureBinding, CaptureBounds, MANIFEST_FILENAME, RetentionPolicy,
    TRANSCRIPT_KEK_RECIPIENT as KEK_RECIPIENT, TranscriptManifest, TranscriptWriter,
    TranscriptWriterConfig,
};
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::plan_persist::{PLAN_FILENAME, read_plan_at};
use mvm_hostd::supervisor::audit::{
    LABEL_CAPTURE_ID, LABEL_CHUNK_COUNT, LABEL_TRANSCRIPT_ROOT, LABEL_VM_NAME,
    TRANSCRIPT_SEALED_EVENT,
};
use mvm_hostd::supervisor::verify_audit_chain_entries;

use super::super::vm::host_signer::PUBLIC_FILENAME;

const DEFAULT_TENANT: &str = "local";
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_CHUNKS: u64 = 100_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 3600;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TranscriptAction {
    /// Arm a forensic capture for a tenant/VM (optionally a session). Prints
    /// the new capture id.
    Arm {
        /// VM name the capture is bound to.
        vm: String,
        /// Tenant. Defaults to `local`.
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
        /// Optional session id.
        #[arg(long)]
        session: Option<String>,
        /// Max captured payload bytes before capture fails closed.
        #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Max captured chunks before capture fails closed.
        #[arg(long, default_value_t = DEFAULT_MAX_CHUNKS)]
        max_chunks: u64,
        /// Max capture wall-clock seconds.
        #[arg(long, default_value_t = DEFAULT_MAX_DURATION_SECS)]
        max_duration: u64,
    },
    /// Seal (disarm) an armed capture — records that no further bytes will be
    /// captured.
    Disarm {
        /// Capture id (as printed by `arm`).
        capture_id: String,
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
    },
    /// List captures, optionally filtered by tenant.
    List {
        #[arg(long)]
        tenant: Option<String>,
        /// Emit a JSON array instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Verify + decrypt a sealed capture to `--out` (or stdout).
    Export {
        capture_id: String,
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
        /// Destination file. Omit to write the decrypted bytes to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

pub(in crate::commands) fn run(action: TranscriptAction) -> Result<()> {
    let ctx = TranscriptCtx::from_config();
    match action {
        TranscriptAction::Arm {
            vm,
            tenant,
            session,
            max_bytes,
            max_chunks,
            max_duration,
        } => {
            let bounds = CaptureBounds {
                max_duration_secs: max_duration,
                max_bytes,
                max_chunks,
            };
            let id = ctx.arm(&tenant, &vm, session.as_deref(), bounds)?;
            println!("{id}");
            Ok(())
        }
        TranscriptAction::Disarm { capture_id, tenant } => ctx.disarm(&tenant, &capture_id),
        TranscriptAction::List { tenant, json } => {
            let rows = ctx.list(tenant.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if rows.is_empty() {
                println!("no captures");
            } else {
                for r in &rows {
                    println!(
                        "{}  tenant={} vm={} session={} chunks={} bytes={}",
                        r.capture_id,
                        r.tenant,
                        r.vm,
                        r.session.as_deref().unwrap_or("-"),
                        r.chunks,
                        r.bytes
                    );
                }
            }
            Ok(())
        }
        TranscriptAction::Export {
            capture_id,
            tenant,
            out,
        } => {
            let bytes = ctx.export(&tenant, &capture_id)?;
            match &out {
                Some(p) => std::fs::write(p, &bytes)
                    .with_context(|| format!("writing decrypted transcript to {}", p.display()))?,
                None => {
                    use std::io::Write as _;
                    std::io::stdout().write_all(&bytes).ok();
                }
            }
            Ok(())
        }
    }
}

/// One row of `transcript list`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CaptureSummary {
    capture_id: String,
    tenant: String,
    vm: String,
    session: Option<String>,
    chunks: usize,
    bytes: u64,
}

/// Where captures, keys, and the audit log live. Carried so tests can point at
/// temp dirs instead of the real `~/.mvm` tree.
struct TranscriptCtx {
    transcripts_dir: PathBuf,
    keys_dir: PathBuf,
    vms_dir: PathBuf,
    audit_dir: PathBuf,
    verifying_key_path: PathBuf,
    /// Audit-log path override (tests). `None` → the default local audit log.
    audit_path: Option<PathBuf>,
}

impl TranscriptCtx {
    fn from_config() -> Self {
        let keys_dir = config::mvm_keys_dir();
        Self {
            transcripts_dir: config::mvm_transcripts_dir(),
            verifying_key_path: keys_dir.join(PUBLIC_FILENAME),
            keys_dir,
            vms_dir: config::vms_dir(),
            audit_dir: config::mvm_audit_dir(),
            audit_path: None,
        }
    }

    fn capture_dir(&self, tenant: &str, capture_id: &str) -> PathBuf {
        config::transcript_capture_dir_at(&self.transcripts_dir, tenant, capture_id)
    }

    fn load_manifest(
        &self,
        tenant: &str,
        capture_id: &str,
    ) -> Result<(PathBuf, TranscriptManifest)> {
        let dir = self.capture_dir(tenant, capture_id);
        let path = dir.join(MANIFEST_FILENAME);
        let raw = std::fs::read_to_string(&path).with_context(|| {
            format!("no such capture {capture_id} (looked in {})", dir.display())
        })?;
        let manifest: TranscriptManifest =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok((dir, manifest))
    }

    fn arm(
        &self,
        tenant: &str,
        vm: &str,
        session: Option<&str>,
        bounds: CaptureBounds,
    ) -> Result<String> {
        let capture_id = uuid::Uuid::new_v4().to_string();
        let dir = self.capture_dir(tenant, &capture_id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating capture dir {}", dir.display()))?;

        // Per-capture data key, wrapped under the host KEK for the manifest.
        let kek = transcript::load_or_init_kek(&self.keys_dir)
            .context("loading the host transcript KEK")?;
        let data_key = aead::Key::random();
        let wrapped = transcript::wrap_data_key(&kek, &data_key);

        let cfg = TranscriptWriterConfig {
            capture_id: capture_id.clone(),
            binding: CaptureBinding {
                tenant_id: tenant.to_string(),
                vm_name: vm.to_string(),
                session_id: session.map(str::to_string),
            },
            bounds,
            // A forensic capture of discrete frames is right to stop at its
            // bound rather than quietly drop the start of what it recorded.
            retention: RetentionPolicy::FailClosed,
            created_unix_secs: now_unix_secs(),
            recipient: KEK_RECIPIENT.to_string(),
            wrapped_data_key_b64: wrapped,
        };
        // No chunks yet — the live bridge sink fills them out of band.
        let manifest = TranscriptWriter::new(&dir, data_key, cfg).seal();
        write_manifest(&dir, &manifest)?;

        self.audit(LocalAuditKind::TranscriptArmed, vm)
            .detail(format!(
                "tenant={tenant} vm={vm} capture={capture_id} max_bytes={} max_chunks={}",
                bounds.max_bytes, bounds.max_chunks
            ))
            .emit();
        Ok(capture_id)
    }

    fn disarm(&self, tenant: &str, capture_id: &str) -> Result<()> {
        let (_dir, manifest) = self.load_manifest(tenant, capture_id)?;
        self.validate_manifest_binding(tenant, capture_id, &manifest)?;

        let plan_path = self
            .vms_dir
            .join(&manifest.binding.vm_name)
            .join(PLAN_FILENAME);
        let plan = read_plan_at(&plan_path).with_context(|| {
            format!(
                "reading the admitted plan for transcript VM '{}'",
                manifest.binding.vm_name
            )
        })?;
        if plan.tenant.0 != manifest.binding.tenant_id {
            anyhow::bail!(
                "admitted plan tenant '{}' does not match transcript tenant '{}'",
                plan.tenant.0,
                manifest.binding.tenant_id
            );
        }
        if plan.workload.0 != manifest.binding.vm_name {
            anyhow::bail!(
                "admitted plan workload '{}' does not match transcript VM '{}'",
                plan.workload.0,
                manifest.binding.vm_name
            );
        }

        let signer = super::super::vm::host_signer::load_or_init_at(&self.keys_dir)
            .context("loading the host signer to anchor the sealed transcript")?;
        match self.matching_chain_anchors(tenant, capture_id, &manifest)? {
            0 => AuditEmitter::with_dir(signer.signing, &self.audit_dir)
                .context("opening the host audit chain for the sealed transcript")?
                .emit_transcript_sealed(
                    &plan,
                    capture_id,
                    &manifest.binding.vm_name,
                    &manifest.sealed_root_hex,
                    manifest.chunks.len(),
                    manifest.adopted,
                )
                .context("anchoring the sealed transcript in the host audit chain")?,
            1 => {}
            count => anyhow::bail!(
                "expected at most one host-signed transcript seal in the audit chain for capture {capture_id}, found {count}"
            ),
        }

        self.audit(LocalAuditKind::TranscriptSealed, &manifest.binding.vm_name)
            .detail(format!(
                "tenant={tenant} vm={} capture={capture_id} chunks={}",
                manifest.binding.vm_name,
                manifest.chunks.len()
            ))
            .emit();
        Ok(())
    }

    fn list(&self, tenant_filter: Option<&str>) -> Result<Vec<CaptureSummary>> {
        let mut rows = Vec::new();
        let tenants = read_subdirs(&self.transcripts_dir);
        for tenant in tenants {
            if let Some(want) = tenant_filter
                && want != tenant
            {
                continue;
            }
            for capture_id in read_subdirs(&self.transcripts_dir.join(&tenant)) {
                let Ok((_d, m)) = self.load_manifest(&tenant, &capture_id) else {
                    continue;
                };
                rows.push(CaptureSummary {
                    capture_id,
                    tenant: m.binding.tenant_id.clone(),
                    vm: m.binding.vm_name.clone(),
                    session: m.binding.session_id.clone(),
                    chunks: m.chunks.len(),
                    bytes: m.chunks.iter().map(|c| c.size_bytes).sum(),
                });
            }
        }
        rows.sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
        Ok(rows)
    }

    fn export(&self, tenant: &str, capture_id: &str) -> Result<Vec<u8>> {
        let (dir, manifest) = self.load_manifest(tenant, capture_id)?;
        let vm = manifest.binding.vm_name.clone();

        let recover = || -> Result<Vec<u8>> {
            self.verify_chain_anchor(tenant, capture_id, &manifest)?;
            let kek = transcript::load_or_init_kek(&self.keys_dir)
                .context("loading the host transcript KEK")?;
            let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)
                .context("unwrapping the per-capture key")?;
            transcript::export(&manifest, &dir, &data_key).context("verifying + decrypting")
        };

        match recover() {
            Ok(bytes) => {
                self.audit(LocalAuditKind::TranscriptExported, &vm)
                    .detail(format!(
                        "tenant={tenant} vm={vm} capture={capture_id} bytes={}",
                        bytes.len()
                    ))
                    .emit();
                Ok(bytes)
            }
            Err(e) => {
                self.audit(LocalAuditKind::TranscriptRefused, &vm)
                    .detail(format!(
                        "tenant={tenant} vm={vm} capture={capture_id} reason={e}"
                    ))
                    .emit();
                Err(e)
            }
        }
    }

    fn verify_chain_anchor(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<()> {
        let count = self.matching_chain_anchors(tenant, capture_id, manifest)?;
        if count != 1 {
            anyhow::bail!(
                "expected exactly one host-signed transcript seal in the audit chain for capture {capture_id}, found {count}"
            );
        }
        Ok(())
    }

    fn validate_manifest_binding(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<()> {
        transcript::verify_sealed_root(manifest).context("verifying transcript manifest root")?;
        if manifest.capture_id != capture_id || manifest.binding.tenant_id != tenant {
            anyhow::bail!(
                "transcript binding does not match requested tenant/capture ({tenant}/{capture_id})"
            );
        }
        Ok(())
    }

    fn matching_chain_anchors(
        &self,
        tenant: &str,
        capture_id: &str,
        manifest: &TranscriptManifest,
    ) -> Result<usize> {
        self.validate_manifest_binding(tenant, capture_id, manifest)?;

        let verifying_key = super::audit::load_verifying_key(&self.verifying_key_path)
            .context("loading trusted host audit verifying key")?;
        let chain_path = self.audit_dir.join(format!("{tenant}.jsonl"));
        if !chain_path.exists() {
            return Ok(0);
        }
        let entries = verify_audit_chain_entries(&chain_path, &verifying_key)
            .with_context(|| format!("verifying audit chain {}", chain_path.display()))?;
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.tenant.0 == tenant
                    && entry.event == TRANSCRIPT_SEALED_EVENT
                    && entry
                        .labels
                        .get(LABEL_CAPTURE_ID)
                        .is_some_and(|value| value == capture_id)
            })
            .collect();
        let expected_chunks = manifest.chunks.len().to_string();
        for entry in &matching {
            if entry.labels.get(LABEL_VM_NAME) != Some(&manifest.binding.vm_name)
                || entry.labels.get(LABEL_TRANSCRIPT_ROOT) != Some(&manifest.sealed_root_hex)
                || entry.labels.get(LABEL_CHUNK_COUNT) != Some(&expected_chunks)
            {
                anyhow::bail!(
                    "host-signed transcript seal does not match capture {capture_id} binding, root, or chunk count"
                );
            }
        }
        Ok(matching.len())
    }

    fn audit(&self, kind: LocalAuditKind, vm: &str) -> LocalAuditBuilder {
        let b = event(kind).vm_name(vm);
        match &self.audit_path {
            Some(p) => b.to_path(p.clone()),
            None => b,
        }
    }
}

fn write_manifest(dir: &Path, manifest: &TranscriptManifest) -> Result<()> {
    let path = dir.join(MANIFEST_FILENAME);
    let json = serde_json::to_string_pretty(manifest)?;
    mvm_core::atomic_io::atomic_write(&path, json.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// Immediate subdirectory names of `dir` (empty if `dir` is missing).
fn read_subdirs(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::transcript::Direction;

    fn ctx(root: &Path) -> TranscriptCtx {
        TranscriptCtx {
            transcripts_dir: root.join("transcripts"),
            keys_dir: root.join("keys"),
            vms_dir: root.join("vms"),
            audit_dir: root.join("chain-audit"),
            verifying_key_path: root.join("keys/host-signer.pub"),
            audit_path: Some(root.join("audit.jsonl")),
        }
    }

    fn persist_plan(c: &TranscriptCtx, tenant: &str, vm: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .workload(vm)
            .plan_id(format!("transcript-{vm}"))
            .build();
        let vm_dir = c.vms_dir.join(vm);
        std::fs::create_dir_all(&vm_dir).unwrap();
        let path = vm_dir.join(mvm_hostd::audit::plan_persist::PLAN_FILENAME);
        std::fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn trusted_host_key(c: &TranscriptCtx) -> ed25519_dalek::SigningKey {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[7u8; 32]);
        std::fs::create_dir_all(c.verifying_key_path.parent().unwrap()).unwrap();
        std::fs::write(&c.verifying_key_path, key.verifying_key().to_bytes()).unwrap();
        key
    }

    fn anchor(c: &TranscriptCtx, manifest: &TranscriptManifest, root: &str) {
        use mvm_hostd::audit::emitter::AuditEmitter;

        let key = trusted_host_key(c);
        let emitter = AuditEmitter::with_dir(key, &c.audit_dir).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant(&manifest.binding.tenant_id)
            .plan_id("transcript-test-plan")
            .build();
        emitter
            .emit_transcript_sealed(
                &plan,
                &manifest.capture_id,
                &manifest.binding.vm_name,
                root,
                manifest.chunks.len(),
                manifest.adopted,
            )
            .unwrap();
    }

    fn anchor_manifest(c: &TranscriptCtx, manifest: &TranscriptManifest) {
        anchor(c, manifest, &manifest.sealed_root_hex);
    }

    fn bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: 3600,
            max_bytes: 1 << 20,
            max_chunks: 1000,
        }
    }

    fn audit_contains(c: &TranscriptCtx, token: &str) -> bool {
        std::fs::read_to_string(c.audit_path.as_ref().unwrap())
            .map(|s| s.contains(token))
            .unwrap_or(false)
    }

    #[test]
    fn arm_creates_a_manifest_with_a_wrapped_key_and_audits() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", Some("s1"), bounds()).unwrap();
        let (_dir, m) = c.load_manifest("t1", &id).unwrap();
        assert_eq!(m.binding.vm_name, "vm1");
        assert_eq!(m.binding.session_id.as_deref(), Some("s1"));
        assert!(!m.wrapped_data_key_b64.is_empty(), "data key is wrapped");
        assert!(m.chunks.is_empty(), "armed capture has no chunks yet");
        assert!(audit_contains(&c, "transcript_armed"));
    }

    #[test]
    fn list_reports_armed_captures() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        c.arm("t2", "vm2", None, bounds()).unwrap();
        let all = c.list(None).unwrap();
        assert_eq!(all.len(), 2);
        let only_t1 = c.list(Some("t1")).unwrap();
        assert_eq!(only_t1.len(), 1);
        assert_eq!(only_t1[0].capture_id, id);
        assert_eq!(only_t1[0].vm, "vm1");
    }

    #[test]
    fn disarm_emits_one_host_signed_seal_from_the_persisted_plan() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        persist_plan(&c, "t1", "vm1");
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        c.disarm("t1", &id).unwrap();
        c.disarm("t1", &id).unwrap();

        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        c.verify_chain_anchor("t1", &id, &manifest).unwrap();
        let key = crate::commands::ops::audit::load_verifying_key(&c.verifying_key_path).unwrap();
        let entries = verify_audit_chain_entries(&c.audit_dir.join("t1.jsonl"), &key).unwrap();
        let seals: Vec<_> = entries
            .iter()
            .filter(|entry| entry.event == TRANSCRIPT_SEALED_EVENT)
            .collect();
        assert_eq!(seals.len(), 1, "repeated disarm must not fork evidence");
        assert_eq!(
            seals[0].labels.get(LABEL_TRANSCRIPT_ROOT),
            Some(&manifest.sealed_root_hex)
        );
        assert!(audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn disarm_refuses_without_the_vms_persisted_plan() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        let err = c
            .disarm("t1", &id)
            .expect_err("an unbound transcript must not be declared sealed");

        assert!(format!("{err:#}").contains("plan.json"));
        assert!(!c.audit_dir.join("t1.jsonl").exists());
        assert!(!audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn disarm_refuses_a_plan_from_a_different_tenant() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        persist_plan(&c, "other-tenant", "vm1");
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        let err = c
            .disarm("t1", &id)
            .expect_err("a cross-tenant plan must not anchor the transcript");

        assert!(format!("{err:#}").contains("tenant"));
        assert!(!c.audit_dir.join("t1.jsonl").exists());
        assert!(!audit_contains(&c, "transcript_sealed"));
    }

    #[test]
    fn export_round_trips_captured_chunks_and_audits() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();

        // Simulate the live sink: rewrite the manifest with real encrypted
        // chunks under the same (unwrapped) data key.
        let (dir, manifest) = c.load_manifest("t1", &id).unwrap();
        let kek = transcript::load_or_init_kek(&c.keys_dir).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let mut w = TranscriptWriter::new(
            &dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: manifest.capture_id.clone(),
                binding: manifest.binding.clone(),
                bounds: manifest.bounds,
                retention: manifest.retention,
                created_unix_secs: manifest.created_unix_secs,
                recipient: manifest.recipient.clone(),
                wrapped_data_key_b64: manifest.wrapped_data_key_b64.clone(),
            },
        );
        w.push(Direction::Egress, b"GET / HTTP/1.1\r\n").unwrap();
        w.push(Direction::Ingress, b"HTTP/1.1 200 OK\r\n").unwrap();
        let sealed = w.seal();
        write_manifest(&dir, &sealed).unwrap();
        anchor_manifest(&c, &sealed);

        let out = c.export("t1", &id).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n");
        assert!(audit_contains(&c, "transcript_exported"));
    }

    #[test]
    fn export_refuses_a_tampered_chunk_and_audits_refusal() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (dir, manifest) = c.load_manifest("t1", &id).unwrap();
        let kek = transcript::load_or_init_kek(&c.keys_dir).unwrap();
        let data_key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        let mut w = TranscriptWriter::new(
            &dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: manifest.capture_id.clone(),
                binding: manifest.binding.clone(),
                bounds: manifest.bounds,
                retention: manifest.retention,
                created_unix_secs: manifest.created_unix_secs,
                recipient: manifest.recipient.clone(),
                wrapped_data_key_b64: manifest.wrapped_data_key_b64.clone(),
            },
        );
        w.push(Direction::Egress, b"secret").unwrap();
        let sealed = w.seal();
        write_manifest(&dir, &sealed).unwrap();
        anchor_manifest(&c, &sealed);
        // Same-length byte flip → hash mismatch on export.
        let mut ct = std::fs::read(dir.join("0.seg")).unwrap();
        ct[0] ^= 0xff;
        std::fs::write(dir.join("0.seg"), &ct).unwrap();

        assert!(c.export("t1", &id).is_err());
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_when_the_host_signed_anchor_is_missing() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        trusted_host_key(&c);

        let err = c
            .export("t1", &id)
            .expect_err("unanchored evidence is refused");
        assert!(err.to_string().contains("audit chain"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_when_the_host_signed_root_does_not_match() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor(&c, &manifest, &"00".repeat(32));

        let err = c
            .export("t1", &id)
            .expect_err("mismatched signed root is refused");
        assert!(err.to_string().contains("does not match"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_refuses_a_tampered_host_audit_chain() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let id = c.arm("t1", "vm1", None, bounds()).unwrap();
        let (_dir, manifest) = c.load_manifest("t1", &id).unwrap();
        anchor_manifest(&c, &manifest);

        let path = c.audit_dir.join("t1.jsonl");
        let chain = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            chain.replace("gateway.transcript_sealed", "gateway.forged"),
        )
        .unwrap();

        let err = c.export("t1", &id).expect_err("tampered chain is refused");
        assert!(err.to_string().contains("verifying audit chain"));
        assert!(audit_contains(&c, "transcript_refused"));
    }

    #[test]
    fn export_of_unknown_capture_errors() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        assert!(c.export("t1", "does-not-exist").is_err());
    }
}
