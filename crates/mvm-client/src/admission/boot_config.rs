//! Guest boot-config attachments an admitted plan rides in with: the
//! host-signer public key the guest verifies receipts against, and the
//! security policy the guest agent enforces. Both land on the config drive
//! as read-only files, each replacing any stale copy of itself.

use anyhow::{Context, Result};
use mvm_core::security::{AgentProfile, SecurityPolicy};
use mvm_hostd::audit::host_keypair::PUBLIC_FILENAME;

use super::AdmissionContext;

pub const SECURITY_POLICY_FILENAME: &str = "security-policy.json";

pub fn guest_profile_for_boot(is_dev_mode: bool, rootfs_path: &std::path::Path) -> AgentProfile {
    if is_dev_mode || !crate::admission::agent_verbs::image_is_sealed(rootfs_path) {
        AgentProfile::Dev
    } else {
        AgentProfile::SealedProd
    }
}

fn security_policy_for_profile(profile: AgentProfile) -> SecurityPolicy {
    match profile {
        AgentProfile::SealedProd => SecurityPolicy::default(),
        AgentProfile::Dev => SecurityPolicy::dev_defaults(),
        AgentProfile::Builder => SecurityPolicy {
            profile: AgentProfile::Builder,
            ..SecurityPolicy::default()
        },
    }
}

pub fn attach_guest_security_policy_config(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    profile: AgentProfile,
) -> Result<()> {
    let content = serde_json::to_string(&security_policy_for_profile(profile))
        .context("serializing guest security policy for config drive")?;
    start_config
        .config_files
        .retain(|f| f.name != SECURITY_POLICY_FILENAME);
    start_config
        .config_files
        .push(mvm_core::vm_backend::VmFile {
            name: SECURITY_POLICY_FILENAME.to_string(),
            content,
            mode: 0o444,
        });
    Ok(())
}

pub fn attach_guest_boot_config_for_plan(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    plan: &mvm_core::plan::ExecutionPlan,
    host_signer_public_path: &std::path::Path,
    profile: AgentProfile,
) -> Result<()> {
    attach_host_signer_pubkey_config_for_plan(start_config, plan, host_signer_public_path)?;
    attach_guest_security_policy_config(start_config, profile)
}

pub fn attach_guest_boot_config(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    admission: &AdmissionContext,
    profile: AgentProfile,
) -> Result<()> {
    attach_guest_boot_config_for_plan(
        start_config,
        admission.admitted.plan(),
        &admission.host_signer_public_path,
        profile,
    )
}

pub fn attach_host_signer_pubkey_config_for_plan(
    start_config: &mut mvm_core::vm_backend::VmStartConfig,
    plan: &mvm_core::plan::ExecutionPlan,
    host_signer_public_path: &std::path::Path,
) -> Result<()> {
    if plan.agent_verbs.is_none() {
        return Ok(());
    }
    let public_bytes = std::fs::read(host_signer_public_path).with_context(|| {
        format!(
            "reading host-signer public key for config drive at {}",
            host_signer_public_path.display()
        )
    })?;
    let public_array: [u8; 32] = public_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "host-signer public key at {} must be 32 bytes, got {}",
            host_signer_public_path.display(),
            public_bytes.len()
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&public_array).with_context(|| {
        format!(
            "parsing host-signer public key at {}",
            host_signer_public_path.display()
        )
    })?;
    let content = format!("{}\n", hex::encode(public_bytes));
    start_config
        .config_files
        .retain(|f| f.name != PUBLIC_FILENAME);
    start_config
        .config_files
        .push(mvm_core::vm_backend::VmFile {
            name: PUBLIC_FILENAME.to_string(),
            content,
            mode: 0o444,
        });
    Ok(())
}

#[cfg(test)]
mod host_signer_pubkey_config_tests {
    use super::*;
    use mvm_core::plan::{VerbId, test_support::PlanFixture};
    use mvm_core::vm_backend::VmStartConfig;

    #[test]
    fn attaches_pubkey_when_plan_has_agent_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let signer = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = signer.verifying_key().to_bytes();
        std::fs::write(&pubkey_path, pubkey).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = Some(vec![VerbId::new("ping").unwrap()]);
        let mut start_config = VmStartConfig::default();

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert_eq!(start_config.config_files.len(), 1);
        let file = &start_config.config_files[0];
        assert_eq!(file.name, PUBLIC_FILENAME);
        assert_eq!(file.content, format!("{}\n", hex::encode(pubkey)));
        assert_eq!(file.mode, 0o444);
    }

    #[test]
    fn replacing_pubkey_preserves_other_config_files_and_removes_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let signer = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
        let pubkey = signer.verifying_key().to_bytes();
        std::fs::write(&pubkey_path, pubkey).unwrap();
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = Some(vec![VerbId::new("ping").unwrap()]);
        let mut start_config = VmStartConfig {
            config_files: vec![
                mvm_core::vm_backend::VmFile {
                    name: "other-config".into(),
                    content: "keep".into(),
                    mode: 0o444,
                },
                mvm_core::vm_backend::VmFile {
                    name: PUBLIC_FILENAME.into(),
                    content: "stale".into(),
                    mode: 0o444,
                },
            ],
            ..VmStartConfig::default()
        };

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert_eq!(
            start_config
                .config_files
                .iter()
                .filter(|file| file.name == PUBLIC_FILENAME)
                .count(),
            1
        );
        assert!(
            start_config
                .config_files
                .iter()
                .any(|file| file.name == "other-config" && file.content == "keep")
        );
    }

    #[test]
    fn skips_pubkey_when_plan_has_no_agent_verbs() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey_path = dir.path().join(PUBLIC_FILENAME);
        let mut plan = PlanFixture::new().build();
        plan.agent_verbs = None;
        let mut start_config = VmStartConfig::default();

        attach_host_signer_pubkey_config_for_plan(&mut start_config, &plan, &pubkey_path).unwrap();

        assert!(start_config.config_files.is_empty());
    }

    #[test]
    fn attaches_sealed_security_policy_for_prod_boots() {
        let mut start_config = VmStartConfig::default();

        attach_guest_security_policy_config(&mut start_config, AgentProfile::SealedProd).unwrap();

        let file = start_config
            .config_files
            .iter()
            .find(|file| file.name == SECURITY_POLICY_FILENAME)
            .expect("security policy file attached");
        let policy: SecurityPolicy =
            serde_json::from_str(&file.content).expect("parse security policy");
        assert_eq!(policy.profile, AgentProfile::SealedProd);
        assert!(policy.require_auth);
        assert!(!policy.access.console);
    }

    /// The policy attach must replace a stale policy file, keep every
    /// unrelated config file, and never duplicate the policy. The retain
    /// predicate is the whole guarantee: inverted, every sibling config file
    /// is dropped and the policy multiplies.
    #[test]
    fn attaching_the_security_policy_replaces_only_the_policy_file() {
        let mut start_config = VmStartConfig::default();
        start_config
            .config_files
            .push(mvm_core::vm_backend::VmFile {
                name: "other-config".to_string(),
                content: "keep".to_string(),
                mode: 0o444,
            });

        attach_guest_security_policy_config(&mut start_config, AgentProfile::SealedProd).unwrap();
        attach_guest_security_policy_config(&mut start_config, AgentProfile::SealedProd).unwrap();

        assert_eq!(
            start_config
                .config_files
                .iter()
                .filter(|file| file.name == SECURITY_POLICY_FILENAME)
                .count(),
            1,
            "a second attach replaces the stale policy instead of stacking another"
        );
        assert!(
            start_config
                .config_files
                .iter()
                .any(|file| file.name == "other-config" && file.content == "keep"),
            "an unrelated config file must survive the policy attach"
        );
    }

    #[test]
    fn attaches_dev_security_policy_for_dev_boots() {
        let mut start_config = VmStartConfig::default();

        attach_guest_security_policy_config(&mut start_config, AgentProfile::Dev).unwrap();

        let file = start_config
            .config_files
            .iter()
            .find(|file| file.name == SECURITY_POLICY_FILENAME)
            .expect("security policy file attached");
        let policy: SecurityPolicy =
            serde_json::from_str(&file.content).expect("parse security policy");
        assert_eq!(policy.profile, AgentProfile::Dev);
        assert!(!policy.require_auth);
        assert!(policy.access.console);
    }

    #[test]
    fn builder_security_policy_preserves_the_builder_profile() {
        assert_eq!(
            security_policy_for_profile(AgentProfile::Builder).profile,
            AgentProfile::Builder
        );
    }

    #[test]
    fn guest_profile_requires_both_dev_override_and_sealed_image_checks() {
        use mvm_build::builder_vm::GuestSidecar;

        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let mut sidecar = GuestSidecar::for_oci_run("test", false, false);
        sidecar.accessible = false;
        sidecar.sealed = true;
        sidecar.write_to_dir(dir.path()).unwrap();

        assert_eq!(
            guest_profile_for_boot(false, &rootfs),
            AgentProfile::SealedProd
        );
        assert_eq!(guest_profile_for_boot(true, &rootfs), AgentProfile::Dev);
    }
}
