//! Recording validation and dry admission for SDK Sandbox scripts.
//!
//! This service never executes a script, builds an image, or launches a VM.
//! Admission uses the normal host signer and policy gates, including their
//! existing local key-store effects. Image hashes describe app identity, not
//! built artifacts; backend launch checks and bundle verification are not run.

use anyhow::{Context, Result};
use mvm_contract::ir::{App, PortProto, PortTransform, Workload};
use mvm_core::plan::{IngressMapping, IngressProtocol, IngressTransform, SynthesisInput};
use mvm_hostd::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
use mvm_sdk::runtime::{Divergence, RuntimeRecording};
use sha2::{Digest, Sha256};

use crate::builder::{RecordingSecretScanner, SecretFinding, scan_recording_for_secrets};

/// Maximum accepted recording size, checked on bytes as well as file metadata.
pub const MAX_RECORDING_BYTES: u64 = 64 * 1024 * 1024;

/// Lowered recording and the evidence its admission gates consume.
#[derive(Debug)]
pub struct LoadedRecording {
    pub workload: Workload,
    pub findings: Vec<Divergence>,
    pub digest_hex: String,
    pub secret_findings: Vec<SecretFinding>,
}

/// Refusals before any host admission is attempted.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("recording is {size} bytes, exceeding the {MAX_RECORDING_BYTES} byte cap")]
    TooLarge { size: usize },
    #[error("digest verification failed: {0}")]
    Digest(String),
    #[error("parsing runtime recording JSON: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("lowering runtime recording: {0}")]
    Lower(String),
    #[error(
        "refusing plan-mode admission: {count} location(s) carry raw secret-shaped material. Replace each literal with a SecretRef so the value substitutes host-side and never enters the workload definition. This is not acknowledgeable — remove the secret."
    )]
    EmbeddedSecrets { count: usize },
    #[error(
        "refusing plan-mode admission: {count} unacknowledged divergence finding(s). Re-run with --ack-divergence <kind> for each class you accept (kinds above in brackets), or fix the script so the recording lowers cleanly."
    )]
    Unacknowledged { count: usize, findings: Vec<String> },
    #[error(
        "Sandbox recording produced no apps to admit — the script must call `Sandbox.create(...)` at least once."
    )]
    NoApps,
    #[error("synthesizing app {app}: {source:#}")]
    Synthesis {
        app: String,
        #[source]
        source: anyhow::Error,
    },
}

/// Verify, scan, and lower captured bytes using the SDK's recording format.
/// File IO and execution of the user's script belong to the caller.
pub fn load_recording_bytes(
    bytes: &[u8],
    expected_sha256: Option<&str>,
) -> std::result::Result<LoadedRecording, PlanError> {
    if bytes.len() as u64 > MAX_RECORDING_BYTES {
        return Err(PlanError::TooLarge { size: bytes.len() });
    }
    if let Some(expected) = expected_sha256 {
        mvm_sdk::runtime::verify_recording_digest(bytes, expected)
            .map_err(|error| PlanError::Digest(error.to_string()))?;
    }
    let recording: RuntimeRecording = serde_json::from_slice(bytes).map_err(PlanError::Parse)?;
    let secret_findings =
        scan_recording_for_secrets(&recording, &RecordingSecretScanner::default());
    let compiled = mvm_sdk::runtime::compile_recording(&recording)
        .map_err(|error| PlanError::Lower(error.to_string()))?;
    Ok(LoadedRecording {
        workload: compiled.workload,
        findings: compiled.findings,
        digest_hex: mvm_sdk::runtime::recording_sha256_hex(bytes),
        secret_findings,
    })
}

/// Embedded literals have no acknowledgment escape hatch.
pub fn refuse_embedded_secrets(findings: &[SecretFinding]) -> std::result::Result<(), PlanError> {
    if findings.is_empty() {
        Ok(())
    } else {
        Err(PlanError::EmbeddedSecrets {
            count: findings.len(),
        })
    }
}

/// Require acknowledgment of every divergence class.
pub fn require_acknowledged(
    findings: &[Divergence],
    acks: &[String],
) -> std::result::Result<(), PlanError> {
    let findings: Vec<String> = findings
        .iter()
        .filter(|f| !acks.iter().any(|a| a == f.kind_slug()))
        .map(ToString::to_string)
        .collect();
    if findings.is_empty() {
        Ok(())
    } else {
        Err(PlanError::Unacknowledged {
            count: findings.len(),
            findings,
        })
    }
}

/// Inputs controlled by an embedder, independent of CLI argument parsing.
#[derive(Debug, Default)]
pub struct PlanOptions {
    pub acknowledged_divergences: Vec<String>,
    pub caller_commitment: Option<mvm_core::plan::CallerCommitment>,
}

/// Public admission facts, without a supervisor or launch-capable handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionSummary {
    pub plan_id: String,
    pub signer_id: String,
    pub cpus: u32,
    pub mem_mib: u64,
    pub workload: String,
    pub tenant: String,
}

#[derive(Debug)]
pub struct AppAdmission {
    pub app: String,
    pub result: std::result::Result<AdmissionSummary, String>,
}

#[derive(Debug)]
pub struct PlanReport {
    pub apps: Vec<AppAdmission>,
}

impl PlanReport {
    pub fn admitted_count(&self) -> usize {
        self.apps.iter().filter(|app| app.result.is_ok()).count()
    }

    pub fn rejected_count(&self) -> usize {
        self.apps.len() - self.admitted_count()
    }
}

impl LoadedRecording {
    /// All recording gates run before host signing or admission.
    pub fn validate(&self, options: &PlanOptions) -> std::result::Result<(), PlanError> {
        refuse_embedded_secrets(&self.secret_findings)?;
        require_acknowledged(&self.findings, &options.acknowledged_divergences)?;
        if self.workload.apps.is_empty() {
            return Err(PlanError::NoApps);
        }
        Ok(())
    }

    /// Shape-check every app using one clock and nonce ledger for the recording.
    /// Admission failures are collected; synthesis failures stop the operation.
    /// No backend is instantiated or launched.
    pub fn admit(&self, options: &PlanOptions) -> std::result::Result<PlanReport, PlanError> {
        self.admit_observing(options, |_| {})
    }

    /// Observe each completed admission before the next app is synthesized.
    /// This preserves partial diagnostics if a later app cannot be synthesized.
    pub fn admit_observing(
        &self,
        options: &PlanOptions,
        observe: impl FnMut(&AppAdmission),
    ) -> std::result::Result<PlanReport, PlanError> {
        self.validate(options)?;
        let ledger = InMemoryNonceLedger::new();
        let clock = SystemClock;
        self.admit_with_observer(
            options,
            |input| {
                let admitted = admit_for_run(
                    input,
                    &clock,
                    &ledger,
                    None,
                    None,
                    mvm_hostd::plan_admission::RunPosture::without_backend(
                        mvm_core::plan::Variant::Dev,
                    ),
                )?;
                Ok(AdmissionSummary {
                    plan_id: admitted.plan_id().0.clone(),
                    signer_id: admitted.signer_id().to_string(),
                    cpus: admitted.plan().resources.cpus,
                    mem_mib: admitted.plan().resources.mem_mib,
                    workload: admitted.plan().workload.0.clone(),
                    tenant: admitted.plan().tenant.0.clone(),
                })
            },
            observe,
        )
    }

    fn admit_with_observer(
        &self,
        options: &PlanOptions,
        mut admit: impl FnMut(&SynthesisInput<'_>) -> Result<AdmissionSummary>,
        mut observe: impl FnMut(&AppAdmission),
    ) -> std::result::Result<PlanReport, PlanError> {
        self.validate(options)?;
        let mut apps = Vec::with_capacity(self.workload.apps.len());
        for app in &self.workload.apps {
            let image_sha = placeholder_image_sha(&self.workload.id, &app.name);
            let input = synthesis_input_for_app(app, &image_sha, options.caller_commitment.clone())
                .map_err(|source| PlanError::Synthesis {
                    app: app.name.clone(),
                    source,
                })?;
            let admission = AppAdmission {
                app: app.name.clone(),
                result: admit(&input).map_err(|error| format!("{error:#}")),
            };
            observe(&admission);
            apps.push(admission);
        }
        Ok(PlanReport { apps })
    }

    #[cfg(test)]
    fn admit_with(
        &self,
        options: &PlanOptions,
        admit: impl FnMut(&SynthesisInput<'_>) -> Result<AdmissionSummary>,
    ) -> std::result::Result<PlanReport, PlanError> {
        self.admit_with_observer(options, admit, |_| {})
    }
}

fn synthesis_input_for_app<'a>(
    app: &'a App,
    image_sha256: &'a str,
    caller_commitment: Option<mvm_core::plan::CallerCommitment>,
) -> Result<SynthesisInput<'a>> {
    let lowered_secrets = crate::admission::secrets::lower_app_secrets(app);
    Ok(SynthesisInput {
        outputs: Vec::new(),
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode: crate::launch::persistent::preflight_network(),
        ingress: lower_ingress(app)?,
        vm_name: &app.name,
        tenant: None,
        backend_name: "firecracker",
        image_name: &app.name,
        image_sha256,
        image_cosign_bundle: None,
        intent: Some("code:execute"),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: lowered_secrets.secret_release,
        secrets: lowered_secrets.secrets,
        audit_event_prefix: None,
        cpus: app.resources.cpu_cores.max(1) as u32,
        mem_mib: app.resources.memory_mb.max(64) as u64,
        disk_mib: app.resources.rootfs_size_mb as u64,
        boot_timeout_secs: 60,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        assets: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        tools: Default::default(),
        caller_commitment,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    })
}

fn lower_ingress(app: &App) -> Result<Vec<IngressMapping>> {
    app.network
        .as_ref()
        .map(|network| {
            network
                .ports
                .iter()
                .map(|mapping| {
                    let builder = IngressMapping::builder()
                        .mapping_id(mapping.mapping_id)
                        .protocol(match mapping.proto {
                            PortProto::Tcp => IngressProtocol::Tcp,
                            PortProto::Udp => IngressProtocol::Udp,
                        })
                        .host_addr(&mapping.host_addr)
                        .host_port(mapping.host)
                        .guest_addr(&mapping.guest_addr)
                        .guest_port(mapping.guest)
                        .transform(match mapping.transform {
                            PortTransform::Opaque => IngressTransform::Opaque,
                            PortTransform::Http => IngressTransform::Http,
                            PortTransform::Tls => IngressTransform::Tls,
                        });
                    let builder = match mapping.tls_secret.as_deref() {
                        Some(secret) => builder.tls_secret(secret),
                        None => builder,
                    };
                    builder
                        .build()
                        .with_context(|| format!("invalid ingress mapping {}", mapping.mapping_id))
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn placeholder_image_sha(workload_id: &str, app_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workload_id.as_bytes());
    hasher.update(b"::");
    hasher.update(app_name.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests;
