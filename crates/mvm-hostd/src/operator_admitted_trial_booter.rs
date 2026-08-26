//! Operator-configured admission and boot for optional assurance extensions.
//!
//! The provider frame carries campaign identities only. Every host path,
//! backend, policy reference, destination resolution, authority ceiling, and
//! resource bound comes from one strict private file beneath the explicit
//! provider state root.

use std::collections::{BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use mvm_contract::assurance::{
    ApprovalSet, AssuranceId, AssuranceSessionRequest, AuthorityCeiling, CampaignProviderRequest,
    Sha256Digest, ToolId,
};
use mvm_contract::plan::{AttestationMode, VerbId};
use mvm_contract::protocol::extension_pack::{
    ExtensionBudgets, ExtensionId, ExtensionPlacement, ExtensionVersion,
};
use mvm_core::extension_admission::{
    ExtensionAdmissionPolicy, ExtensionAuthority, admit_extension,
};
use mvm_core::pack_cache::{PackVerifyCtx, promote_at};
use mvm_core::pack_trust::PackTrustConfig;
use mvm_core::packs::{
    HostCapability, LocalPackPolicy, PackBackend, PackKind, PackManifest, Sha256Hex,
};
use mvm_core::plan::{
    PlanSeccompTier, SecretReleasePolicy, StreamRetention, SynthesisInput, Variant,
};
use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
use mvm_core::protocol::broker::ServiceId;
use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::AnyBackend;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::admitted_campaign_runner::{
    AdmittedTrialBoot, AdmittedTrialBooter, AssuranceRuntimeTier,
};
use crate::assurance_session::{
    CampaignDeclaration, CampaignRequest, DeclaredEdge, SOURCE_DIGEST_LABEL, SOURCE_RUN_LABEL,
    host_assurance_plane,
};
use crate::audit::durability::AuditDurability;
use crate::audit::emitter::AuditEmitter;
use crate::audit::host_keypair::load_or_init_at;
use crate::broker::handlers::host_assurance_v1::HOST_ASSURANCE_SERVICE;
use crate::plan_admission::{
    AdmitAndStartParams, ExtensionAdmissionContext, InMemoryNonceLedger, SystemClock,
    admit_and_start,
};
use mvm_contract::assurance::policy_digest_from_refs;

/// Fixed filename beneath the explicit provider state root.
pub const PROVIDER_BOOT_CONFIG_FILE: &str = "boot-config.json";
/// Versioned strict local configuration contract.
pub const PROVIDER_BOOT_CONFIG_SCHEMA: &str = "mvm.assurance.provider-boot-config/v1";

const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_TRUST_BYTES: u64 = 1024 * 1024;
const MAX_DESTINATIONS: usize = 32;
/// Assurance extensions require the current guest sidecar contract. Older
/// OCI materializations cannot activate the read-only extension volume.
const MIN_ASSURANCE_GUEST_PROTOCOL_VERSION: u8 = 2;

/// Strict operator-owned configuration for a concrete admitted provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBootConfig {
    pub schema: String,
    pub tenant: AssuranceId,
    #[serde(default)]
    pub admission_tier: ProviderAdmissionTier,
    /// Existing host-wide MVM state root. The cleared launcher environment
    /// must explicitly bind `MVM_HOME` to this exact path so assurance boots
    /// share resource accounting with ordinary admitted workloads.
    pub host_mvm_home: PathBuf,
    pub extension: ProviderExtensionConfig,
    pub workload: ProviderWorkloadConfig,
    #[serde(default)]
    pub attestation: ProviderAttestationConfig,
    pub policy: ProviderPolicyConfig,
    pub authority: ProviderAuthorityConfig,
    pub destinations: Vec<ProviderDestination>,
}

/// Operator-owned attestation posture for the admitted runtime. The safe
/// default preserves ordinary non-attesting campaigns; a Scout request cannot
/// promote it to hardware attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttestationConfig {
    pub mode: AttestationMode,
}

impl Default for ProviderAttestationConfig {
    fn default() -> Self {
        Self {
            mode: AttestationMode::Noop,
        }
    }
}

impl ProviderAttestationConfig {
    fn validate_request(&self, require_attestation: bool) -> Result<()> {
        if require_attestation && matches!(self.mode, AttestationMode::Noop) {
            anyhow::bail!(
                "the Scout campaign requires attestation but operator configuration selects noop"
            );
        }
        Ok(())
    }
}

/// Exact independently signed extension selected by the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExtensionConfig {
    pub pack_root: PathBuf,
    pub trust_config: PathBuf,
    pub expected_pack_digest: Sha256Hex,
    pub expected_extension_id: ExtensionId,
    pub expected_version: ExtensionVersion,
    pub policy_compatibility_hash: Sha256Hex,
    pub budgets: ExtensionBudgets,
}

/// Exact workload and runtime selected by the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderWorkloadConfig {
    pub image_name: AssuranceId,
    pub rootfs_path: PathBuf,
    pub artifact_digest: Sha256Digest,
    pub kernel_path: Option<PathBuf>,
    pub kernel_digest: Option<Sha256Digest>,
    pub verity_path: Option<PathBuf>,
    pub roothash: Option<String>,
    pub backend: ProviderBackend,
    pub cpus: u32,
    pub memory_mib: u32,
    pub boot_timeout_seconds: u32,
}

/// Closed backend vocabulary. Admission still applies the backend's typed
/// production tier after this value is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderBackend {
    Firecracker,
    Libkrun,
    Qemu,
    Hvf,
    Mock,
}

/// Explicit assurance admission tier. The default is the fail-closed
/// production posture; selecting `dev_test` is required to use QEMU.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAdmissionTier {
    #[default]
    Production,
    DevTest,
}

impl ProviderAdmissionTier {
    fn plan_variant(self) -> Variant {
        match self {
            Self::Production => Variant::Prod,
            Self::DevTest => Variant::Dev,
        }
    }

    fn runtime_tier(self) -> AssuranceRuntimeTier {
        match self {
            Self::Production => AssuranceRuntimeTier::Production,
            Self::DevTest => AssuranceRuntimeTier::DevTest,
        }
    }
}

impl ProviderBackend {
    fn name(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Libkrun => "libkrun",
            Self::Qemu => "qemu",
            Self::Hvf => "hvf",
            Self::Mock => "mock",
        }
    }

    fn pack_backend(self) -> PackBackend {
        match self {
            Self::Firecracker => PackBackend::Firecracker,
            Self::Libkrun => PackBackend::Libkrun,
            Self::Qemu | Self::Mock => PackBackend::Qemu,
            Self::Hvf => PackBackend::Hvf,
        }
    }

    fn ensure_assurance_admissible(self, tier: ProviderAdmissionTier) -> Result<()> {
        match (tier, self) {
            (ProviderAdmissionTier::Production, Self::Qemu | Self::Mock) => anyhow::bail!(
                "configured backend {} is dev/test-only and cannot enter production assurance admission",
                self.name()
            ),
            (ProviderAdmissionTier::DevTest, Self::Mock) => {
                anyhow::bail!("the mock backend cannot execute a live assurance campaign")
            }
            (ProviderAdmissionTier::Production, Self::Firecracker | Self::Libkrun | Self::Hvf)
            | (
                ProviderAdmissionTier::DevTest,
                Self::Firecracker | Self::Libkrun | Self::Qemu | Self::Hvf,
            ) => Ok(()),
        }
    }
}

/// Policy references signed into the plan plus the only permitted concrete
/// egress posture: deny all, or allow operator-declared destinations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicyConfig {
    pub network_policy_ref: String,
    pub egress_policy_ref: String,
    pub fs_policy_ref: String,
    pub tool_policy_ref: String,
}

/// Host/tenant ceiling and explicit approvals. Deserializing `ApprovalSet`
/// directly is intentionally avoided because its representation is private.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuthorityConfig {
    pub ceiling: AuthorityCeiling,
    pub approved_tools: Vec<ToolId>,
    pub grant_ttl_ms: u64,
}

/// One operator-resolved destination label. `allow_egress=false` makes the
/// destination observable to the campaign while retaining deny-all egress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDestination {
    pub label: AssuranceId,
    pub host: String,
    pub port: u16,
    pub allow_egress: bool,
}

/// Concrete implementation injected into the provider lifecycle runner.
pub struct OperatorConfiguredTrialBooter {
    state_root: PathBuf,
    config: ProviderBootConfig,
    ledger: InMemoryNonceLedger,
    emitter: Arc<AuditEmitter>,
}

impl OperatorConfiguredTrialBooter {
    /// Load the fixed private config and initialize only state beneath the
    /// explicit provider root.
    pub fn load(state_root: &Path) -> Result<Self> {
        let config_path = state_root.join(PROVIDER_BOOT_CONFIG_FILE);
        let bytes = read_bounded_regular_file(&config_path, MAX_CONFIG_BYTES, true)?;
        let config: ProviderBootConfig = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing provider boot config {}", config_path.display()))?;
        config.validate()?;
        validate_active_mvm_home(&config.host_mvm_home)?;
        let keys_root = state_root.join("host-signing-keys");
        let signer = load_or_init_at(&keys_root).context("loading provider host signer")?;
        let emitter = Arc::new(
            AuditEmitter::with_dir(signer.signing, &state_root.join("audit"))?.with_receipts(),
        );
        Ok(Self {
            state_root: state_root.to_path_buf(),
            config,
            ledger: InMemoryNonceLedger::new(),
            emitter,
        })
    }

    fn boot_inner(
        &self,
        request: &CampaignProviderRequest,
        session: &AssuranceSessionRequest,
    ) -> Result<AdmittedTrialBoot> {
        request
            .join_session_request(session.clone())
            .context("joining configured boot to the provider campaign")?;
        self.config
            .attestation
            .validate_request(request.require_attestation)?;
        self.verify_policy_identity(session)?;
        self.config
            .workload
            .backend
            .ensure_assurance_admissible(self.config.admission_tier)?;
        let artifact_digest = verify_digest_file(
            &self.config.workload.rootfs_path,
            &self.config.workload.artifact_digest,
            "workload rootfs",
        )?;
        verify_assurance_guest_protocol(&self.config.workload.rootfs_path)?;
        let kernel_sha = self.verify_kernel()?;
        let backend_name = self.config.workload.backend.name();
        AnyBackend::require_hypervisor_selectable(backend_name)?;
        let backend = AnyBackend::from_hypervisor(backend_name);
        if backend.name() != backend_name {
            anyhow::bail!("configured backend resolved to a different runtime");
        }

        let now = Utc::now();
        let trust_bytes =
            read_bounded_regular_file(&self.config.extension.trust_config, MAX_TRUST_BYTES, false)?;
        let trust: PackTrustConfig =
            serde_json::from_slice(&trust_bytes).context("parsing extension trust config")?;
        let pack_metadata = std::fs::symlink_metadata(&self.config.extension.pack_root)
            .context("inspecting configured extension pack root")?;
        if pack_metadata.file_type().is_symlink() || !pack_metadata.is_dir() {
            anyhow::bail!("configured extension pack root must be a non-symlink directory");
        }
        let manifest_path = self.config.extension.pack_root.join("manifest.json");
        let manifest_bytes = read_bounded_regular_file(&manifest_path, MAX_MANIFEST_BYTES, false)?;
        let manifest: PackManifest =
            serde_json::from_slice(&manifest_bytes).context("parsing extension pack manifest")?;
        self.verify_expected_extension(&manifest)?;

        let mut host_capabilities =
            BTreeSet::from([HostCapability("host.assurance.v1::probe".to_string())]);
        if backend.capabilities().vsock {
            host_capabilities.insert(HostCapability("vsock".to_string()));
        }
        let pack_policy = LocalPackPolicy {
            host_arch: mvm_core::arch::GuestArch::host(),
            backend: self.config.workload.backend.pack_backend(),
            host_capabilities,
            policy_hash: self.config.extension.policy_compatibility_hash.clone(),
            allowed_channels: trust.allowed_channels(),
            now,
        };
        let verify = PackVerifyCtx::ed25519(&pack_policy, &trust, &trust);
        let cache_root = self.state_root.join("pack-cache");
        let promoted = promote_at(
            &cache_root,
            &self.config.extension.pack_root,
            &manifest,
            &verify,
        )
        .context("verifying and installing configured extension pack")?;

        let capability = mvm_contract::assurance::probe_capability_descriptor().id;
        let requested = capability_set_for_session(session);
        let policy_ceiling = if self
            .config
            .authority
            .ceiling
            .tools
            .contains(&ToolId::CampaignProbeV1)
        {
            HashSet::from([capability.clone()])
        } else {
            HashSet::new()
        };
        let approved = if self
            .config
            .authority
            .approved_tools
            .contains(&ToolId::CampaignProbeV1)
        {
            HashSet::from([capability.clone()])
        } else {
            HashSet::new()
        };
        let admitted_budgets = narrow_budgets(
            self.config.extension.budgets,
            session,
            self.config.authority.ceiling.max_steps,
            self.config.authority.ceiling.max_output_bytes,
        );
        let placements = BTreeSet::from([ExtensionPlacement::GuestWorkload]);
        let extension = admit_extension(
            &manifest,
            &promoted.verified,
            ExtensionAuthority {
                requested: &requested,
                policy_ceiling: &policy_ceiling,
                session_grant: &requested,
                explicit_approval: &approved,
            },
            ExtensionAdmissionPolicy {
                placements: &placements,
                budgets: admitted_budgets,
            },
        )
        .context("admitting configured extension authority")?;

        let declaration = self.declaration(request, session, &artifact_digest)?;
        let network_policy = self.network_policy(session);
        let vm_name = vm_name(request, session);
        let mut audit_labels = std::collections::BTreeMap::new();
        audit_labels.insert(
            SOURCE_RUN_LABEL.to_string(),
            session.session.source_run_id.as_str().to_string(),
        );
        audit_labels.insert(
            SOURCE_DIGEST_LABEL.to_string(),
            session.source.source_digest.as_str().to_string(),
        );
        let artifact_hex = artifact_digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("validated digest always has its prefix");
        let synthesis = SynthesisInput {
            vm_name: &vm_name,
            tenant: Some(self.config.tenant.as_str()),
            backend_name,
            image_name: self.config.workload.image_name.as_str(),
            image_sha256: artifact_hex,
            kernel_sha256: kernel_sha.as_deref(),
            image_cosign_bundle: None,
            intent: Some("assurance:campaign"),
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: Some(&self.config.policy.network_policy_ref),
            fs_policy_ref: Some(&self.config.policy.fs_policy_ref),
            egress_policy_ref: Some(&self.config.policy.egress_policy_ref),
            tool_policy_ref: Some(&self.config.policy.tool_policy_ref),
            secret_release: SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: Some("assurance.campaign"),
            network_mode: Default::default(),
            ingress: Vec::new(),
            grants: None,
            cpus: self.config.workload.cpus,
            mem_mib: u64::from(self.config.workload.memory_mib),
            disk_mib: 0,
            boot_timeout_secs: self.config.workload.boot_timeout_seconds,
            destroy_on_exit: true,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            audit_labels,
            agent_verbs: Some(vec![
                VerbId::new("run-extension")?,
                VerbId::new("cancel-extension")?,
            ]),
            services: vec![ServiceId::parse(HOST_ASSURANCE_SERVICE)?],
            extensions: vec![extension],
            stream_edges: Vec::new(),
            stream_retention: StreamRetention::Ephemeral,
            attestation_mode: self.config.attestation.mode.clone(),
        };
        let config = VmStartConfig {
            name: vm_name.clone(),
            rootfs_path: self.config.workload.rootfs_path.display().to_string(),
            kernel_path: self
                .config
                .workload
                .kernel_path
                .as_ref()
                .map(|path| path.display().to_string()),
            verity_path: self
                .config
                .workload
                .verity_path
                .as_ref()
                .map(|path| path.display().to_string()),
            roothash: self.config.workload.roothash.clone(),
            cpus: self.config.workload.cpus,
            memory_mib: self.config.workload.memory_mib,
            tenant_id: Some(self.config.tenant.as_str().to_string()),
            network_policy: network_policy.clone(),
            ..Default::default()
        };
        let campaign_now_unix_ms = now_unix_ms()?;
        let extension_context = ExtensionAdmissionContext::at(&cache_root, &verify);
        let keys_root = self.state_root.join("host-signing-keys");
        let clock = SystemClock;
        let started = {
            let campaign = CampaignRequest {
                declaration: declaration.clone(),
                emitter: Arc::clone(&self.emitter),
                policy_ceiling: self.config.authority.ceiling.clone(),
                policy: network_policy,
                backend: backend_name.to_string(),
                now_unix_ms: campaign_now_unix_ms,
            };
            admit_and_start(
                &backend,
                AdmitAndStartParams::builder()
                    .synthesis(&synthesis)
                    .config(config)
                    .clock(&clock)
                    .ledger(&self.ledger)
                    .host_signer_keys_dir(keys_root.as_path())
                    .extension_ctx(&extension_context)
                    .variant(self.config.admission_tier.plan_variant())
                    .emitter(self.emitter.as_ref())
                    .audit_durability(AuditDurability::Required)
                    .assurance(&campaign)
                    .build()?,
            )?
        };
        let plane = host_assurance_plane().ok_or_else(|| {
            anyhow::anyhow!("admitted assurance boot did not install its controller plane")
        })?;
        Ok(AdmittedTrialBoot {
            backend,
            started,
            declaration,
            plane,
            now_unix_ms: campaign_now_unix_ms,
            runtime_tier: self.config.admission_tier.runtime_tier(),
            attestation_verifier: None,
        })
    }

    fn verify_policy_identity(&self, session: &AssuranceSessionRequest) -> Result<()> {
        let effective = policy_digest_from_refs(
            &self.config.policy.network_policy_ref,
            &self.config.policy.egress_policy_ref,
            &self.config.policy.fs_policy_ref,
            &self.config.policy.tool_policy_ref,
        );
        if effective != session.source.requested_policy_digest {
            anyhow::bail!("operator policy references do not match the requested policy digest");
        }
        Ok(())
    }

    fn verify_kernel(&self) -> Result<Option<String>> {
        match (
            self.config.workload.kernel_path.as_deref(),
            self.config.workload.kernel_digest.as_ref(),
        ) {
            (Some(path), Some(digest)) => {
                let verified = verify_digest_file(path, digest, "workload kernel")?;
                Ok(Some(
                    verified
                        .as_str()
                        .strip_prefix("sha256:")
                        .expect("validated digest always has its prefix")
                        .to_string(),
                ))
            }
            (None, None) => Ok(None),
            _ => anyhow::bail!("kernel path and digest must be supplied together"),
        }
    }

    fn verify_expected_extension(&self, manifest: &PackManifest) -> Result<()> {
        if manifest.kind != PackKind::Extension
            || manifest.outputs.pack_hash != self.config.extension.expected_pack_digest
        {
            anyhow::bail!("configured extension pack identity does not match its manifest");
        }
        let contract = manifest
            .extension
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("configured pack has no extension contract"))?;
        if contract.extension_id != self.config.extension.expected_extension_id
            || contract.version != self.config.extension.expected_version
        {
            anyhow::bail!("configured extension identity or version does not match its manifest");
        }
        Ok(())
    }

    fn declaration(
        &self,
        request: &CampaignProviderRequest,
        session: &AssuranceSessionRequest,
        artifact_digest: &Sha256Digest,
    ) -> Result<CampaignDeclaration> {
        let requested: BTreeSet<_> = session
            .synthetic_inputs
            .destination_labels
            .iter()
            .cloned()
            .collect();
        let edges: Vec<_> = self
            .config
            .destinations
            .iter()
            .filter(|destination| requested.contains(&destination.label))
            .map(|destination| DeclaredEdge {
                label: destination.label.clone(),
                host: destination.host.clone(),
                port: destination.port,
            })
            .collect();
        let resolved: BTreeSet<_> = edges.iter().map(|edge| edge.label.clone()).collect();
        if resolved != requested {
            anyhow::bail!("operator destination map does not cover the requested labels");
        }
        let approvals = self
            .config
            .authority
            .approved_tools
            .iter()
            .copied()
            .fold(ApprovalSet::none(), ApprovalSet::with);
        Ok(CampaignDeclaration {
            request_id: request.request_id.clone(),
            idempotency_key: session.session.idempotency_key.clone(),
            campaign_id: session.session.campaign_id.clone(),
            trial_id: session.session.trial_id.clone(),
            source_run_id: request.source_run_id.clone(),
            source_digest: request.source_digest.clone(),
            artifact_digest: artifact_digest.clone(),
            edges,
            approvals,
            requested: session.authority.clone(),
            grant_ttl_ms: self.config.authority.grant_ttl_ms,
        })
    }

    fn network_policy(&self, session: &AssuranceSessionRequest) -> NetworkPolicy {
        let requested: BTreeSet<_> = session.synthetic_inputs.destination_labels.iter().collect();
        let allowed = self
            .config
            .destinations
            .iter()
            .filter(|destination| {
                destination.allow_egress && requested.contains(&destination.label)
            })
            .map(|destination| HostPort::new(destination.host.clone(), destination.port))
            .collect::<Vec<_>>();
        if allowed.is_empty() {
            NetworkPolicy::deny_all()
        } else {
            NetworkPolicy::allow_list(allowed)
        }
    }
}

fn verify_assurance_guest_protocol(rootfs: &Path) -> Result<()> {
    let parent = rootfs
        .parent()
        .ok_or_else(|| anyhow::anyhow!("workload rootfs has no parent directory"))?;
    let sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(parent)
        .context("reading workload guest metadata")?
        .ok_or_else(|| anyhow::anyhow!("workload rootfs is missing mvm-meta.json metadata"))?;
    if sidecar.protocol_version < MIN_ASSURANCE_GUEST_PROTOCOL_VERSION {
        anyhow::bail!(
            "workload guest protocol {} is too old for assurance extensions; need at least {}",
            sidecar.protocol_version,
            MIN_ASSURANCE_GUEST_PROTOCOL_VERSION
        );
    }
    Ok(())
}

impl AdmittedTrialBooter for OperatorConfiguredTrialBooter {
    fn boot(
        &self,
        request: &CampaignProviderRequest,
        session: &AssuranceSessionRequest,
    ) -> Result<AdmittedTrialBoot> {
        self.boot_inner(request, session)
            .context("operator-configured admitted trial boot failed")
    }
}

impl ProviderBootConfig {
    fn validate(&self) -> Result<()> {
        if self.schema != PROVIDER_BOOT_CONFIG_SCHEMA {
            anyhow::bail!("unsupported provider boot config schema");
        }
        for path in [
            &self.host_mvm_home,
            &self.extension.pack_root,
            &self.extension.trust_config,
            &self.workload.rootfs_path,
        ] {
            require_absolute(path)?;
        }
        for path in [
            self.workload.kernel_path.as_deref(),
            self.workload.verity_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            require_absolute(path)?;
        }
        if self.workload.kernel_path.is_some() != self.workload.kernel_digest.is_some() {
            anyhow::bail!("kernel path and digest must be supplied together");
        }
        if self.workload.verity_path.is_some() != self.workload.roothash.is_some() {
            anyhow::bail!("verity path and root hash must be supplied together");
        }
        if self.workload.cpus == 0
            || self.workload.memory_mib < 64
            || self.workload.boot_timeout_seconds == 0
            || self.workload.boot_timeout_seconds > 600
        {
            anyhow::bail!("workload resource configuration is outside supported bounds");
        }
        validate_policy_ref(&self.policy.network_policy_ref)?;
        validate_policy_ref(&self.policy.egress_policy_ref)?;
        validate_policy_ref(&self.policy.fs_policy_ref)?;
        validate_policy_ref(&self.policy.tool_policy_ref)?;
        if self.authority.grant_ttl_ms == 0
            || self.authority.grant_ttl_ms > crate::assurance_session::MAX_GRANT_TTL_MS
        {
            anyhow::bail!("provider grant TTL is outside supported bounds");
        }
        if self.destinations.is_empty() || self.destinations.len() > MAX_DESTINATIONS {
            anyhow::bail!("provider destination map is outside supported bounds");
        }
        let mut labels = BTreeSet::new();
        for destination in &self.destinations {
            if !labels.insert(destination.label.clone())
                || destination.host.is_empty()
                || destination.host.len() > 253
                || destination.host.chars().any(char::is_control)
                || destination.port == 0
            {
                anyhow::bail!("provider destination map contains an invalid entry");
            }
        }
        Ok(())
    }
}

fn validate_active_mvm_home(expected: &Path) -> Result<()> {
    let active = mvm_core::config::mvm_home_strict()
        .context("the provider launcher must explicitly establish the global MVM home")?;
    if active != expected {
        anyhow::bail!("provider boot config does not match the active global MVM home");
    }
    let metadata =
        std::fs::symlink_metadata(expected).context("inspecting the configured global MVM home")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("configured global MVM home must be a non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("configured global MVM home must not be group- or world-accessible");
        }
    }
    Ok(())
}

fn capability_set_for_session(
    session: &AssuranceSessionRequest,
) -> HashSet<mvm_contract::protocol::agent_capability::CapabilityId> {
    if session
        .authority
        .allowed_tools
        .contains(&ToolId::CampaignProbeV1)
    {
        HashSet::from([mvm_contract::assurance::probe_capability_descriptor().id])
    } else {
        HashSet::new()
    }
}

fn narrow_budgets(
    mut budgets: ExtensionBudgets,
    session: &AssuranceSessionRequest,
    ceiling_steps: u32,
    ceiling_output: u32,
) -> ExtensionBudgets {
    budgets.max_steps = budgets
        .max_steps
        .min(session.authority.max_steps)
        .min(ceiling_steps);
    budgets.max_output_bytes = budgets
        .max_output_bytes
        .min(session.authority.max_output_bytes)
        .min(ceiling_output);
    budgets
}

fn verify_digest_file(path: &Path, expected: &Sha256Digest, label: &str) -> Result<Sha256Digest> {
    require_regular_nonsymlink(path, label)?;
    let actual = mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {label} at {}", path.display()))?;
    let actual = Sha256Digest::parse(format!("sha256:{actual}"))?;
    if &actual != expected {
        anyhow::bail!("{label} digest does not match operator configuration");
    }
    Ok(actual)
}

fn vm_name(request: &CampaignProviderRequest, session: &AssuranceSessionRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.request_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(session.session.campaign_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(session.session.trial_id.as_str().as_bytes());
    format!("assurance-{}", &hex::encode(hasher.finalize())[..24])
}

fn now_unix_ms() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    u64::try_from(duration.as_millis()).context("current time does not fit in milliseconds")
}

fn validate_policy_ref(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        anyhow::bail!("provider policy reference is outside supported bounds");
    }
    Ok(())
}

fn require_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("provider boot paths must be absolute");
    }
    Ok(())
}

fn require_regular_nonsymlink(path: &Path, label: &str) -> Result<()> {
    require_absolute(path)?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{label} must be a non-symlink regular file");
    }
    Ok(())
}

fn read_bounded_regular_file(path: &Path, max_bytes: u64, private: bool) -> Result<Vec<u8>> {
    require_regular_nonsymlink(path, "provider configuration input")?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.len() > max_bytes {
        anyhow::bail!("provider configuration input exceeds its byte limit");
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("provider boot config must not be group- or world-readable");
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("opening provider configuration input {}", path.display()))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        anyhow::bail!("provider configuration input exceeds its byte limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_guest_protocol_requires_current_sidecar() {
        let root = tempfile::tempdir().expect("sidecar directory");
        let rootfs = root.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        let mut sidecar =
            mvm_build::builder_vm::GuestSidecar::for_oci_run("assurance-workload", true, false);
        sidecar.protocol_version = MIN_ASSURANCE_GUEST_PROTOCOL_VERSION;
        sidecar.write_to_dir(root.path()).expect("sidecar");
        verify_assurance_guest_protocol(&rootfs).expect("current sidecar is accepted");
    }

    #[test]
    fn assurance_guest_protocol_refuses_legacy_sidecar() {
        let root = tempfile::tempdir().expect("sidecar directory");
        let rootfs = root.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        let mut sidecar =
            mvm_build::builder_vm::GuestSidecar::for_oci_run("assurance-workload", true, false);
        sidecar.protocol_version = MIN_ASSURANCE_GUEST_PROTOCOL_VERSION - 1;
        sidecar.write_to_dir(root.path()).expect("sidecar");
        let error = verify_assurance_guest_protocol(&rootfs).expect_err("legacy sidecar");
        assert!(error.to_string().contains("too old"));
    }

    #[test]
    fn assurance_guest_protocol_refuses_missing_sidecar() {
        let root = tempfile::tempdir().expect("sidecar directory");
        let rootfs = root.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").expect("rootfs");
        let error = verify_assurance_guest_protocol(&rootfs).expect_err("missing sidecar");
        assert!(error.to_string().contains("missing mvm-meta.json"));
    }

    fn signed_extension_pack(
        root: &Path,
    ) -> (PackManifest, ed25519_dalek::SigningKey, ExtensionBudgets) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        let policy_hash = Sha256Hex::from_bytes(b"operator-test-policy");
        let budgets = ExtensionBudgets {
            cpu_millis: 500,
            memory_bytes: 128 * 1024 * 1024,
            duration_ms: 60_000,
            max_steps: 12,
            max_concurrency: 1,
            max_payload_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
            max_artifact_bytes: 1024 * 1024,
        };
        std::fs::write(root.join("extension.ext4"), b"signed extension artifact")
            .expect("extension artifact");
        let metadata = mvm_core::packs::PackMetadata {
            kind: PackKind::Extension,
            target_arch: mvm_core::arch::GuestArch::host(),
            backend_compatibility: vec![PackBackend::Firecracker],
            required_host_capabilities: vec![HostCapability(
                "host.assurance.v1::probe".to_string(),
            )],
            policy_compatibility: mvm_core::packs::PolicyCompatibility {
                policy_hash,
                local_rebuild_required: false,
                allowed_channels: vec!["assurance".to_string()],
            },
            inputs: mvm_core::packs::PackInputs {
                flake_locks: Vec::new(),
                derivations: Vec::new(),
                nar_hashes: Vec::new(),
                oci_images: Vec::new(),
                setup_commands: Vec::new(),
                source_revisions: Vec::new(),
                toolchain_versions: Default::default(),
            },
            provenance: mvm_core::packs::PackProvenanceMeta {
                builder_identity: "assurance-release-test".to_string(),
                build_environment_identity: "hermetic-test".to_string(),
                build_timestamp: chrono::DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                reproducibility: mvm_core::packs::ReproducibilityStatus::NotChecked,
                sbom: mvm_core::packs::SbomReference {
                    uri: "urn:sbom:operator-test".to_string(),
                    sha256: Sha256Hex::from_bytes(b"sbom"),
                },
            },
            trust: mvm_core::packs::PackTrustMeta {
                expires_at: chrono::DateTime::parse_from_rfc3339("2100-01-01T00:00:00Z")
                    .expect("expiry")
                    .with_timezone(&Utc),
                revocation_channel: "https://example.invalid/revocations".to_string(),
                channel_identity: "assurance".to_string(),
                mirror_identity: None,
                transparency_log: None,
            },
            signature: mvm_core::packs::SignatureValidity {
                signed_at: chrono::DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
                    .expect("signed at")
                    .with_timezone(&Utc),
                expires_at: chrono::DateTime::parse_from_rfc3339("2100-01-01T00:00:00Z")
                    .expect("signature expiry")
                    .with_timezone(&Utc),
            },
        };
        let extension = mvm_contract::protocol::extension_pack::ExtensionPackContract {
            schema: mvm_contract::protocol::extension_pack::EXTENSION_PACK_SCHEMA.to_string(),
            extension_id: ExtensionId::parse("org.example.assurance-extension")
                .expect("extension id"),
            version: ExtensionVersion::parse("1.0.0").expect("extension version"),
            protocol: mvm_contract::protocol::extension_pack::ExtensionProtocolRange {
                min_mvm_version: ExtensionVersion::parse("0.18.0").expect("minimum version"),
                max_mvm_version: ExtensionVersion::parse("0.18.99").expect("maximum version"),
                min_protocol: 1,
                max_protocol: 1,
            },
            placement: ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/assurance-extension".to_string(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor()],
            budgets,
            revocation_identity: "org.example.assurance-extension.release".to_string(),
            permission_delta: "May execute one declared assurance probe.".to_string(),
        };
        let manifest = mvm_core::packs::PackBuilder::new(root, metadata, &signing_key)
            .file("extension.ext4")
            .extension(extension)
            .build()
            .expect("signed extension pack");
        std::fs::write(
            root.join("manifest.json"),
            manifest.canonical_bytes().expect("canonical manifest"),
        )
        .expect("pack manifest");
        (manifest, signing_key, budgets)
    }

    #[cfg(unix)]
    fn write_config(root: &Path, body: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(root.join(PROVIDER_BOOT_CONFIG_FILE), body).expect("write config");
        std::fs::set_permissions(
            root.join(PROVIDER_BOOT_CONFIG_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("config mode");
    }

    #[cfg(unix)]
    #[test]
    fn unknown_config_fields_fail_closed_before_state_initialization() {
        let root = tempfile::tempdir().expect("state root");
        write_config(
            root.path(),
            br#"{"schema":"mvm.assurance.provider-boot-config/v1","command":"sh"}"#,
        );
        let Err(error) = OperatorConfiguredTrialBooter::load(root.path()) else {
            panic!("unknown command field must be refused");
        };
        assert!(format!("{error:#}").contains("unknown field"), "{error:#}");
        assert!(!root.path().join("host-signing-keys").exists());
    }

    #[cfg(unix)]
    #[test]
    fn loosely_readable_config_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("state root");
        let path = root.path().join(PROVIDER_BOOT_CONFIG_FILE);
        std::fs::write(&path, b"{}").expect("write config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("config mode");
        let Err(error) = OperatorConfiguredTrialBooter::load(root.path()) else {
            panic!("loose config must be refused");
        };
        assert!(error.to_string().contains("group- or world-readable"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_refused() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("state root");
        let outside = tempfile::NamedTempFile::new().expect("outside config");
        symlink(outside.path(), root.path().join(PROVIDER_BOOT_CONFIG_FILE))
            .expect("config symlink");
        let Err(error) = OperatorConfiguredTrialBooter::load(root.path()) else {
            panic!("symlinked config must be refused");
        };
        assert!(error.to_string().contains("non-symlink regular file"));
    }

    #[test]
    fn backend_vocabulary_is_closed() {
        assert!(serde_json::from_str::<ProviderBackend>("\"firecracker\"").is_ok());
        assert!(serde_json::from_str::<ProviderBackend>("\"docker\"").is_err());
        assert!(serde_json::from_str::<ProviderBackend>("\"wasm\"").is_err());
    }

    #[test]
    fn attestation_required_request_cannot_promote_operator_noop() {
        let error = ProviderAttestationConfig::default()
            .validate_request(true)
            .expect_err("request data must not promote the operator attestation posture");

        assert!(
            error
                .to_string()
                .contains("requires attestation but operator configuration selects noop")
        );
    }

    #[test]
    fn operator_hardware_mode_accepts_required_request_but_not_unknown_config() {
        let configured: ProviderAttestationConfig =
            serde_json::from_str(r#"{"mode":"tpm2"}"#).expect("closed hardware mode parses");
        configured
            .validate_request(true)
            .expect("operator-selected hardware mode matches the request posture");
        assert!(
            serde_json::from_str::<ProviderAttestationConfig>(
                r#"{"mode":"tpm2","quote_verified":true}"#
            )
            .is_err(),
            "no software verification boolean may enter operator configuration"
        );
    }

    #[test]
    fn assurance_production_refuses_dev_test_backends() {
        for backend in [ProviderBackend::Qemu, ProviderBackend::Mock] {
            let error = backend
                .ensure_assurance_admissible(ProviderAdmissionTier::Production)
                .expect_err("a dev/test backend must not enter production assurance admission");
            assert!(error.to_string().contains("dev/test"), "{error:#}");
        }
        for backend in [
            ProviderBackend::Firecracker,
            ProviderBackend::Libkrun,
            ProviderBackend::Hvf,
        ] {
            backend
                .ensure_assurance_admissible(ProviderAdmissionTier::Production)
                .expect("a supported runtime may proceed to ordinary production admission");
        }
    }

    #[test]
    fn assurance_dev_test_tier_admits_qemu_but_never_mock() {
        ProviderBackend::Qemu
            .ensure_assurance_admissible(ProviderAdmissionTier::DevTest)
            .expect("the explicit dev/test tier may use the real QEMU substrate");
        let error = ProviderBackend::Mock
            .ensure_assurance_admissible(ProviderAdmissionTier::DevTest)
            .expect_err("a mock is not a live assurance runtime");
        assert!(error.to_string().contains("mock"), "{error:#}");
    }

    #[test]
    fn narrowed_budgets_never_widen_the_request_or_host_ceiling() {
        let session = AssuranceSessionRequest::parse_json(include_bytes!(
            "../../mvm-contract/fixtures/assurance-ai-session-request-v1.json"
        ))
        .expect("session fixture");
        let budgets = narrow_budgets(
            ExtensionBudgets {
                cpu_millis: 30_000,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 120_000,
                max_steps: 100,
                max_concurrency: 1,
                max_payload_bytes: 512 * 1024,
                max_output_bytes: 512 * 1024,
                max_artifact_bytes: 64 * 1024 * 1024,
            },
            &session,
            4,
            4096,
        );
        assert_eq!(budgets.max_steps, 4);
        assert_eq!(budgets.max_output_bytes, 4096);
    }

    #[test]
    fn default_host_ceiling_remains_narrower_than_extension_maximum() {
        let ceiling = crate::assurance_session::default_policy_ceiling();
        assert!(ceiling.tools.contains(&ToolId::CampaignProbeV1));
        assert!(
            ceiling
                .scopes
                .contains(&mvm_contract::assurance::ObservationScope::HostAuditRefs)
        );
    }

    #[cfg(unix)]
    #[test]
    fn configured_booter_reverifies_and_promotes_the_exact_signed_pack() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;

        let state = tempfile::tempdir().expect("provider state");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private provider state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.isolate_mvm_home(state.path());
        let staged = tempfile::tempdir().expect("staged extension pack");
        let (manifest, signing_key, budgets) = signed_extension_pack(staged.path());
        let trust_path = state.path().join("pack-trust.json");
        let trust = PackTrustConfig {
            publishers: vec![mvm_core::pack_trust::TrustedPublisher {
                pubkey_base64: STANDARD.encode(signing_key.verifying_key().to_bytes()),
                channels: vec!["assurance".to_string()],
            }],
            fetch_mode: mvm_core::pack_trust::PackFetchMode::OfflinePinned,
            ..Default::default()
        };
        std::fs::write(&trust_path, serde_json::to_vec(&trust).expect("trust JSON"))
            .expect("trust config");
        let rootfs_path = state.path().join("workload.ext4");
        std::fs::write(&rootfs_path, b"admitted workload").expect("workload rootfs");
        let mut guest_sidecar =
            mvm_build::builder_vm::GuestSidecar::for_oci_run("assurance-workload", true, false);
        guest_sidecar.protocol_version = MIN_ASSURANCE_GUEST_PROTOCOL_VERSION;
        guest_sidecar
            .write_to_dir(state.path())
            .expect("guest sidecar");
        let artifact_digest = Sha256Digest::parse(format!(
            "sha256:{}",
            mvm_core::crypto::image_verify::sha256_file(&rootfs_path).expect("rootfs digest")
        ))
        .expect("typed rootfs digest");
        let policy = ProviderPolicyConfig {
            network_policy_ref: "operator-network-v1".to_string(),
            egress_policy_ref: "operator-egress-v1".to_string(),
            fs_policy_ref: "operator-fs-v1".to_string(),
            tool_policy_ref: "operator-tools-v1".to_string(),
        };
        let policy_digest = policy_digest_from_refs(
            &policy.network_policy_ref,
            &policy.egress_policy_ref,
            &policy.fs_policy_ref,
            &policy.tool_policy_ref,
        );
        let config = ProviderBootConfig {
            schema: PROVIDER_BOOT_CONFIG_SCHEMA.to_string(),
            tenant: AssuranceId::parse("tenant-assurance-test").expect("tenant"),
            admission_tier: ProviderAdmissionTier::Production,
            host_mvm_home: state.path().to_path_buf(),
            extension: ProviderExtensionConfig {
                pack_root: staged.path().to_path_buf(),
                trust_config: trust_path,
                expected_pack_digest: manifest.outputs.pack_hash.clone(),
                expected_extension_id: ExtensionId::parse("org.example.assurance-extension")
                    .expect("extension id"),
                expected_version: ExtensionVersion::parse("1.0.0").expect("extension version"),
                policy_compatibility_hash: Sha256Hex::from_bytes(b"operator-test-policy"),
                budgets,
            },
            workload: ProviderWorkloadConfig {
                image_name: AssuranceId::parse("assurance-workload").expect("image name"),
                rootfs_path,
                artifact_digest,
                kernel_path: None,
                kernel_digest: None,
                verity_path: None,
                roothash: None,
                backend: ProviderBackend::Firecracker,
                cpus: 1,
                memory_mib: 128,
                boot_timeout_seconds: 30,
            },
            attestation: ProviderAttestationConfig::default(),
            policy,
            authority: ProviderAuthorityConfig {
                ceiling: AuthorityCeiling::extension_maximum(),
                approved_tools: vec![ToolId::CampaignProbeV1],
                grant_ttl_ms: 30_000,
            },
            destinations: vec![ProviderDestination {
                label: AssuranceId::parse("different.synthetic.destination")
                    .expect("destination label"),
                host: "127.0.0.1".to_string(),
                port: 9,
                allow_egress: false,
            }],
        };
        write_config(
            state.path(),
            &serde_json::to_vec(&config).expect("boot config JSON"),
        );
        let booter = OperatorConfiguredTrialBooter::load(state.path()).expect("configured booter");
        let mut request = CampaignProviderRequest::parse_json(include_bytes!(
            "../../mvm-contract/fixtures/campaign-provider-request-v1.json"
        ))
        .expect("provider request");
        request.requested_policy_digest = policy_digest.clone();
        let mut session = AssuranceSessionRequest::parse_json(include_bytes!(
            "../../mvm-contract/fixtures/assurance-ai-session-request-v1.json"
        ))
        .expect("session request");
        session.source.requested_policy_digest = policy_digest;

        let Err(error) = booter.boot(&request, &session) else {
            panic!("undeclared destination must stop before VM admission");
        };
        assert!(
            format!("{error:#}").contains("destination map does not cover"),
            "{error:#}"
        );
        assert!(
            state
                .path()
                .join("pack-cache")
                .join(manifest.outputs.pack_hash.as_str())
                .join(".pack-manifest.json")
                .is_file(),
            "the exact signed pack must be verified and promoted before admission input assembly"
        );
    }
}
