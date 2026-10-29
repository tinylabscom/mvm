//! Host-local capture configuration and authenticated reads, not producer control.
//!
//! Manual arm creates encryption material and unsigned configuration only. It
//! establishes neither an authenticated opening nor an arm-to-seal lifecycle.
//! Disarm only recognizes an existing original seal; recovery without an
//! authorized, quiescent lifecycle owner is unavailable here. Reads do not mint
//! keys or audit authority. Export writes only its supplied sink; delivery
//! adapters remain responsible for any later delivery-success audit.

use std::path::Path;

use anyhow::Result;
use mvm_core::transcript::CaptureBounds;
use serde::{Deserialize, Serialize};

/// Plain discovered metadata, not an authenticated seal or transferable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureSummary {
    pub capture_id: String,
    pub tenant: String,
    pub vm: String,
    pub session: Option<String>,
    pub chunks: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TranscriptReconcileRequest {
    pub tenant: String,
    pub capture_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum TranscriptReconcileReport {
    LegacyIneligible,
    NotSealed,
    NotDue,
    Retired { removed_segments: usize },
}

/// The convenience buffer limit; streaming export retains the capture's own bounds.
pub const MAX_IN_MEMORY_EXPORT_BYTES: usize = ((4 * 1024 * 1024 - 1024) / 4) * 3;

#[cfg(unix)]
pub struct TranscriptService {
    home: std::path::PathBuf,
    transcripts_dir: std::path::PathBuf,
    #[cfg(test)]
    keys_dir: std::path::PathBuf,
    audit_dir: std::path::PathBuf,
    local_audit: Option<std::path::PathBuf>,
}

#[cfg(not(unix))]
pub struct TranscriptService;

#[cfg(unix)]
impl TranscriptService {
    /// Resolve fixed host configuration without creating storage.
    pub fn from_config() -> Self {
        Self {
            home: mvm_core::config::mvm_home().into(),
            transcripts_dir: mvm_core::config::mvm_transcripts_dir(),
            #[cfg(test)]
            keys_dir: mvm_core::config::mvm_keys_dir(),
            audit_dir: mvm_core::config::mvm_audit_dir(),
            local_audit: None,
        }
    }

    /// Resolve the same roots beneath an explicit local home. Performs no I/O.
    pub fn at_home(home: &Path) -> Self {
        Self {
            home: home.into(),
            transcripts_dir: home.join("audit/transcripts"),
            #[cfg(test)]
            keys_dir: mvm_core::config::mvm_keys_dir_at(home),
            audit_dir: home.join("audit"),
            local_audit: Some(home.join("audit.jsonl")),
        }
    }

    /// Create unsigned capture configuration and encryption material, not a
    /// host-signed opening, a running producer, or a future disarm permission.
    pub fn arm(
        &self,
        tenant: &str,
        vm: &str,
        session: Option<&str>,
        bounds: CaptureBounds,
    ) -> Result<String> {
        use mvm_core::policy::audit::{LocalAuditKind, event};
        use mvm_core::transcript::{self, CaptureBinding, RetentionPolicy, TranscriptWriterConfig};

        component(tenant)?;
        component(vm)?;
        if session.is_some_and(|value| value.is_empty() || value.len() > 4096) {
            anyhow::bail!("invalid capture session");
        }
        let now = transcript::retention_now()?;
        let capture_id = hex::encode(rand::random::<[u8; 16]>());
        let config = TranscriptWriterConfig {
            capture_id: capture_id.clone(),
            binding: CaptureBinding {
                tenant_id: tenant.into(),
                vm_name: vm.into(),
                session_id: session.map(str::to_owned),
            },
            bounds,
            retention: RetentionPolicy::FailClosed,
            created_unix_secs: now,
            at_rest: Some(transcript::AtRestRetention::default()),
            generation_budget: None,
            payload_encoding: transcript::PayloadEncoding::Raw,
            recipient: transcript::TRANSCRIPT_KEK_RECIPIENT.into(),
            wrapped_data_key_b64: String::new(),
        };
        self.store()?.create_unsigned_configuration(config)?;
        let event = event(LocalAuditKind::TranscriptArmed)
            .vm_name(vm)
            .detail("unsigned capture configuration; producer lifecycle not established");
        match &self.local_audit {
            Some(path) => event.to_path(path.clone()).emit(),
            None => event.emit(),
        }
        Ok(capture_id)
    }

    /// Recognize an exact existing seal under exclusive capture ownership.
    /// This neither seals a candidate nor claims to stop its producer.
    pub fn disarm(&self, tenant: &str, capture_id: &str) -> Result<()> {
        let store = self.store()?;
        let capture = store
            .exclusive_capture(tenant, capture_id)
            .map_err(|_| anyhow::anyhow!("exclusive capture access unavailable"))?;
        let manifest = capture
            .read_manifest()
            .map_err(|error| anyhow::anyhow!("reading leased capture manifest: {error}"))?;
        binding(&manifest, tenant, capture_id)?;
        let public = store.existing_host_public_key()?;
        self.require_seal(&manifest, &public)?;
        Ok(())
    }

    /// Discover metadata only. Missing storage stays absent and no key is loaded.
    pub fn list(&self, tenant_filter: Option<&str>) -> Result<Vec<CaptureSummary>> {
        let store = match self.store() {
            Ok(store) => store,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut rows = Vec::new();
        for (tenant, capture_id) in store.capture_ids(tenant_filter)? {
            let capture = store
                .read_capture(&tenant, &capture_id)
                .map_err(|_| anyhow::anyhow!("capture discovery lease unavailable"))?;
            let manifest = capture
                .read_manifest()
                .map_err(|error| anyhow::anyhow!("reading leased capture manifest: {error}"))?;
            binding(&manifest, &tenant, &capture_id)?;
            rows.push(CaptureSummary {
                capture_id,
                tenant: tenant.clone(),
                vm: manifest.binding.vm_name.clone(),
                session: manifest.binding.session_id.clone(),
                chunks: manifest.chunks.len(),
                bytes: manifest.chunks.iter().try_fold(0u64, |total, chunk| {
                    total
                        .checked_add(chunk.size_bytes)
                        .ok_or_else(|| anyhow::anyhow!("capture size overflow"))
                })?,
            });
        }
        rows.sort_by(|a, b| (&a.tenant, &a.capture_id).cmp(&(&b.tenant, &b.capture_id)));
        Ok(rows)
    }

    pub fn export(&self, tenant: &str, capture_id: &str) -> Result<Vec<u8>> {
        let mut output = BoundedExport::default();
        self.export_guarded(tenant, capture_id, &mut output, true)?;
        Ok(output.0)
    }

    /// A failed writer may have received a prefix; that is not successful export.
    /// Checks occur after callbacks return, never interrupting them.
    pub fn export_to_writer(
        &self,
        tenant: &str,
        capture_id: &str,
        writer: &mut impl std::io::Write,
    ) -> Result<u64> {
        self.export_guarded(tenant, capture_id, writer, false)
    }

    fn export_guarded(
        &self,
        tenant: &str,
        capture_id: &str,
        writer: &mut impl std::io::Write,
        bounded: bool,
    ) -> Result<u64> {
        use mvm_core::transcript;
        let store = self.store()?;
        let capture = store
            .read_capture(tenant, capture_id)
            .map_err(|_| anyhow::anyhow!("capture read lease unavailable"))?;
        let manifest = capture
            .read_manifest()
            .map_err(|error| anyhow::anyhow!("reading leased capture manifest: {error}"))?;
        binding(&manifest, tenant, capture_id)?;
        let now = transcript::retention_now()?;
        let retired =
            self.retirement_evidence(&manifest, &store.existing_host_public_key()?, now)?;
        anyhow::ensure!(!retired, "capture payload is retired");
        manifest
            .check_readable_at(now)
            .map_err(|_| anyhow::anyhow!("capture retention check refuses export"))?;
        if bounded {
            transcript::bounded_export_size(&manifest, MAX_IN_MEMORY_EXPORT_BYTES)
                .map_err(|_| anyhow::anyhow!("in-memory export size limit exceeded"))?;
        }
        let kek = store
            .existing_kek()
            .map_err(|_| anyhow::anyhow!("existing capture encryption key unavailable"))?;
        let key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64)
            .map_err(|_| anyhow::anyhow!("original capture key cannot be unwrapped"))?;
        let written =
            transcript::export_to_writer(&manifest, &capture, &key, writer).map_err(|_| {
                anyhow::anyhow!("capture verification, writer or retention check refused")
            })?;
        manifest
            .check_readable_at(transcript::retention_now()?)
            .map_err(|_| anyhow::anyhow!("capture retention check refused delivery"))?;
        Ok(written)
    }

    /// Preflight original evidence without mutation, then delegate the unchanged
    /// target operation which reacquires and rechecks before signing/unlinking.
    pub fn reconcile(
        &self,
        request: &TranscriptReconcileRequest,
    ) -> Result<TranscriptReconcileReport> {
        use mvm_core::transcript;
        use mvm_hostd::audit::transcript_retirement::{
            RetirementContext, RetirementOutcome, reconcile_capture,
        };
        let relative = relative(&request.tenant, &request.capture_id)?;
        let store = self.store()?;
        let (vm, public) = {
            let capture = store
                .exclusive_capture(&request.tenant, &request.capture_id)
                .map_err(|_| anyhow::anyhow!("exclusive capture discovery unavailable"))?;
            let manifest = capture
                .read_manifest()
                .map_err(|error| anyhow::anyhow!("reading leased capture manifest: {error}"))?;
            binding(&manifest, &request.tenant, &request.capture_id)?;
            let public = store.existing_host_public_key()?;
            self.retirement_evidence(&manifest, &public, transcript::retention_now()?)?;
            (manifest.binding.vm_name.clone(), public)
        };
        #[cfg(test)]
        tests::after_discovery();
        let (signing, existing_public) = store.existing_host_keypair().map_err(|_| {
            anyhow::anyhow!("existing audit signing authority unavailable; no replacement created")
        })?;
        anyhow::ensure!(
            existing_public == public,
            "audit authority changed after discovery"
        );
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::with_dir(signing, &self.audit_dir)
            .map_err(|_| anyhow::anyhow!("existing audit chain unavailable"))?;
        let outcome = reconcile_capture(
            RetirementContext {
                root: &self.transcripts_dir,
                relative_capture: &relative,
                capture_id: &request.capture_id,
                tenant: &request.tenant,
                vm: &vm,
                emitter: &emitter,
            },
            transcript::retention_now()?,
        )
        .map_err(|_| anyhow::anyhow!("authenticated retirement recheck refused"))?;
        Ok(match outcome {
            RetirementOutcome::LegacyIneligible => TranscriptReconcileReport::LegacyIneligible,
            RetirementOutcome::NotSealed => TranscriptReconcileReport::NotSealed,
            RetirementOutcome::NotDue => TranscriptReconcileReport::NotDue,
            RetirementOutcome::Retired { removed_segments } => {
                TranscriptReconcileReport::Retired { removed_segments }
            }
        })
    }

    fn store(&self) -> std::io::Result<mvm_core::transcript::local_store::LocalTranscriptStore> {
        mvm_core::transcript::local_store::LocalTranscriptStore::open(&self.home)
    }

    fn require_seal(
        &self,
        manifest: &mvm_core::transcript::TranscriptManifest,
        public: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        let seal =
            mvm_core::transcript::evidence::authenticated_seal(&self.audit_dir, public, manifest)
                .map_err(|_| anyhow::anyhow!("original transcript seal authentication failed"))?;
        anyhow::ensure!(
            seal.is_some(),
            "original authenticated seal unavailable; lifecycle sealing/recovery is not available here"
        );
        Ok(())
    }

    fn retirement_evidence(
        &self,
        manifest: &mvm_core::transcript::TranscriptManifest,
        public: &ed25519_dalek::VerifyingKey,
        now: u64,
    ) -> Result<bool> {
        mvm_core::transcript::evidence::authenticated_retirement_at(
            &self.audit_dir,
            public,
            manifest,
            Some(now),
        )
        .map(|(_, retired)| retired)
        .map_err(|_| {
            anyhow::anyhow!("original transcript retirement evidence authentication failed")
        })
    }
}

#[cfg(unix)]
fn component(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value != "."
            && value != ".."
            && !value.contains(['/', '\\', '\0']),
        "invalid capture component"
    );
    Ok(())
}

#[cfg(unix)]
fn relative(tenant: &str, capture: &str) -> Result<std::path::PathBuf> {
    component(tenant)?;
    component(capture)?;
    Ok(Path::new(tenant).join(capture))
}

#[cfg(unix)]
fn binding(
    manifest: &mvm_core::transcript::TranscriptManifest,
    tenant: &str,
    capture: &str,
) -> Result<()> {
    anyhow::ensure!(
        manifest.capture_id == capture && manifest.binding.tenant_id == tenant,
        "capture binding mismatch"
    );
    component(&manifest.binding.vm_name)?;
    mvm_core::transcript::verify_sealed_root(manifest)
        .map_err(|_| anyhow::anyhow!("capture integrity root invalid"))?;
    Ok(())
}

#[cfg(unix)]
#[derive(Default)]
struct BoundedExport(Vec<u8>);

#[cfg(unix)]
impl std::io::Write for BoundedExport {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .0
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_IN_MEMORY_EXPORT_BYTES)
            .ok_or_else(|| std::io::Error::other("in-memory export size limit exceeded"))?;
        self.0
            .try_reserve_exact(next - self.0.len())
            .map_err(|_| std::io::Error::other("in-memory export allocation refused"))?;
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(not(unix))]
impl TranscriptService {
    pub fn from_config() -> Self {
        Self
    }
    pub fn at_home(_home: &Path) -> Self {
        Self
    }
    pub fn arm(
        &self,
        _tenant: &str,
        _vm: &str,
        _session: Option<&str>,
        _bounds: CaptureBounds,
    ) -> Result<String> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
    pub fn disarm(&self, _tenant: &str, _capture: &str) -> Result<()> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
    pub fn list(&self, _tenant: Option<&str>) -> Result<Vec<CaptureSummary>> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
    pub fn export(&self, _tenant: &str, _capture: &str) -> Result<Vec<u8>> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
    pub fn export_to_writer(
        &self,
        _tenant: &str,
        _capture: &str,
        _writer: &mut impl std::io::Write,
    ) -> Result<u64> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
    pub fn reconcile(
        &self,
        _request: &TranscriptReconcileRequest,
    ) -> Result<TranscriptReconcileReport> {
        anyhow::bail!("guarded transcript operations require Unix directory leases")
    }
}

#[cfg(all(test, unix))]
#[path = "transcript_tests.rs"]
mod tests;
