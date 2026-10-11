//! Read-only pack inventory and the same trust inputs used by launch resolution.

use anyhow::Result;

#[derive(serde::Serialize)]
pub struct CacheStatusReport {
    pub packs: Vec<CacheStatusEntry>,
    pub instant_launch_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instant_launch_reason: Option<String>,
}

#[derive(serde::Serialize)]
pub struct CacheStatusEntry {
    pub pack_hash: String,
    pub kind: mvm_core::packs::PackKind,
    pub arch: mvm_core::arch::GuestArch,
    pub backends: Vec<mvm_core::packs::PackBackend>,
    pub channel: String,
    pub size_bytes: u64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub expired: bool,
    pub signing_key_id: mvm_core::plan::bundle::KeyId,
    pub revocation_channel: String,
    pub last_used_unix: Option<i64>,
}

pub fn status() -> Result<CacheStatusReport> {
    let packs = mvm_core::pack_cache::list_cached_packs()?;
    let now = chrono::Utc::now();
    let reason = not_instant_reason(&runtime_pack_diagnosis()?);
    Ok(CacheStatusReport {
        packs: packs
            .into_iter()
            .map(|p| CacheStatusEntry {
                pack_hash: p.pack_hash.as_str().to_string(),
                kind: p.kind,
                arch: p.arch,
                backends: p.backends,
                channel: p.channel,
                size_bytes: p.size_bytes,
                expires_at: p.expires_at,
                expired: p.expires_at < now,
                signing_key_id: p.signing_key_id,
                revocation_channel: p.revocation_channel,
                last_used_unix: p.last_used_unix,
            })
            .collect(),
        instant_launch_ready: reason.is_none(),
        instant_launch_reason: reason,
    })
}

/// Owned inputs shared with launch resolution; no keys or files are written.
#[cfg(feature = "manifest-verify")]
pub struct RuntimePackTrustInputs {
    pub policy: mvm_core::packs::LocalPackPolicy,
    pub keyless: mvm_core::packs::KeylessTrust,
    pub trust: mvm_core::pack_trust::PackTrustConfig,
}

#[cfg(feature = "manifest-verify")]
impl RuntimePackTrustInputs {
    pub fn load() -> Result<Self> {
        use anyhow::Context;
        use mvm_core::packs::{
            HostCapability, LocalPackPolicy, PackBackend, host_pack_policy_hash,
        };
        let arch = mvm_core::arch::GuestArch::host();
        let trust = mvm_core::pack_trust::load_pack_trust_config(
            &mvm_core::config::mvm_keys_dir().join("pack-trust.json"),
        )
        .context("loading pack trust config for runtime pack resolution")?
        .unwrap_or_default();
        let mut policy = LocalPackPolicy {
            host_arch: arch,
            backend: PackBackend::Hvf,
            host_capabilities: std::collections::BTreeSet::from([HostCapability(
                "vsock".to_string(),
            )]),
            policy_hash: host_pack_policy_hash(arch),
            allowed_channels: trust.allowed_channels(),
            now: chrono::Utc::now(),
        };
        policy
            .allowed_channels
            .extend(mvm_core::release_trust::release_channels());
        let keyless = mvm_core::release_trust::release_keyless_trust(env!("CARGO_PKG_VERSION"));
        Ok(Self {
            policy,
            keyless,
            trust,
        })
    }
}

#[cfg(feature = "manifest-verify")]
pub fn runtime_pack_diagnosis() -> Result<mvm_core::pack_cache::PackDiagnosis> {
    use anyhow::Context;
    let inputs = RuntimePackTrustInputs::load()
        .context("building trust inputs for --runtime-pack resolution")?;
    let ctx = mvm_core::pack_cache::PackVerifyCtx::keyless(
        &inputs.policy,
        &inputs.keyless,
        &inputs.trust,
    );
    mvm_core::pack_cache::diagnose_pack(mvm_core::packs::PackKind::Runtime, &ctx)
        .context("diagnosing the local runtime pack cache")
}

#[cfg(not(feature = "manifest-verify"))]
pub fn runtime_pack_diagnosis() -> Result<mvm_core::pack_cache::PackDiagnosis> {
    Ok(mvm_core::pack_cache::PackDiagnosis::NoCompatiblePack)
}

pub fn not_instant_reason(d: &mvm_core::pack_cache::PackDiagnosis) -> Option<String> {
    use mvm_core::pack_cache::PackDiagnosis;
    use mvm_core::packs::PackVerifyError;
    match d {
        PackDiagnosis::Ready { .. } => None,
        PackDiagnosis::NoCompatiblePack => {
            Some("no verified runtime pack is cached for this host".to_string())
        }
        PackDiagnosis::Rejected { reason, .. } => Some(match reason {
            PackVerifyError::IncompatibleArchitecture { got, expected } => {
                format!("cached runtime pack was built for {got} but this host is {expected}")
            }
            PackVerifyError::IncompatibleBackend { backend } => {
                format!("cached runtime pack does not support this host's backend ({backend})")
            }
            PackVerifyError::MissingHostCapability(capability) => format!(
                "cached runtime pack requires host capability {capability}, which is unavailable"
            ),
            PackVerifyError::ExpiredTrustMetadata { expired_at }
            | PackVerifyError::ExpiredSignature { expired_at, .. } => {
                format!("cached runtime pack signature expired at {expired_at}")
            }
            PackVerifyError::Revoked { reason, .. } => {
                format!("cached runtime pack signer is revoked: {reason}")
            }
            PackVerifyError::UnknownSigningKey { .. } => {
                "cached runtime pack is signed by an untrusted key".to_string()
            }
            PackVerifyError::ChannelNotAllowed(channel) => {
                format!("cached runtime pack channel {channel:?} is not allowed by local policy")
            }
            PackVerifyError::PolicyHashMismatch { .. } => {
                "cached runtime pack was built for a different local policy".to_string()
            }
            PackVerifyError::MutableOciReference { .. } => {
                "cached runtime pack references a mutable OCI tag, which is not instant-eligible"
                    .to_string()
            }
            PackVerifyError::FileHashMismatch { .. }
            | PackVerifyError::PackHashMismatch { .. }
            | PackVerifyError::FileSizeMismatch { .. }
            | PackVerifyError::UnsafeFilePath(_)
            | PackVerifyError::DuplicateFile(_) => {
                "cached runtime pack failed integrity verification (tampered or corrupt)"
                    .to_string()
            }
            other => format!("cached runtime pack failed verification: {other}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_configured_home_has_no_ready_packs_and_status_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let report = status().unwrap();
        assert!(report.packs.is_empty());
        assert!(!report.instant_launch_ready);
        assert_eq!(
            report.instant_launch_reason.as_deref(),
            Some("no verified runtime pack is cached for this host")
        );
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["packs"], serde_json::json!([]));
        assert_eq!(json["instant_launch_ready"], false);
    }
}
