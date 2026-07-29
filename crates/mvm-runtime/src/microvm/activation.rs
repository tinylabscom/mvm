//! Host-side activation for the universal initramfs boot path.
//!
//! After the VMM boots, the guest PID-1 agent waits in a fail-closed state
//! that only accepts [`mvm_agentd::vsock::ActivateEnvironment`]. This module
//! builds that message from the admitted [`VmStartConfig`] and the fixed
//! virtio-blk slot layout produced by [`crate::workload_runner::spec_map::workload_blocks`],
//! then sends it over the agent vsock channel.

use std::path::Path;

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{
    ActivateEnvironment, GuestRequest, GuestResponse, RootfsConfig, RuntimeOverlayConfig,
    VolumeConfig,
};
use mvm_core::protocol::vm_backend::{VerbGrantEnvelope, VmStartConfig, VmVolumeKind};

use crate::driver::traits::RunningVm;

/// Fixed guest device nodes matching [`crate::workload_runner::spec_map::workload_blocks`].
const ROOTFS_DATA_DEV: &str = "/dev/vda";
const ROOTFS_HASH_DEV: &str = "/dev/vdb";
const RUNTIME_DATA_DEV: &str = "/dev/vdc";
const RUNTIME_HASH_DEV: &str = "/dev/vdd";

/// Activate a workload that booted with the universal initramfs.
///
/// Sends [`ActivateEnvironment`] over the agent vsock port and waits for an
/// ACK. If the guest replies with an error or an unexpected response, the
/// boot fails closed.
pub fn activate_workload(vm: &dyn RunningVm, config: &VmStartConfig) -> Result<()> {
    let env = build_activation_environment(config)?;
    let mut stream = vm
        .vsock_connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
        .context("connect to guest agent for activation")?;
    let response = mvm_agentd::vsock::send_request_stream(
        &mut stream,
        &GuestRequest::ActivateEnvironment(env),
    )
    .context("send ActivateEnvironment to guest")?;
    match response {
        GuestResponse::ActivateEnvironmentAck => Ok(()),
        GuestResponse::ActivateEnvironmentError { message } => {
            bail!("guest activation failed: {message}")
        }
        other => bail!("unexpected response to ActivateEnvironment: {other:?}"),
    }
}

/// Build an [`ActivateEnvironment`] from the admitted launch config.
///
/// Roothashes are taken from the config sidecars; the virtio-blk slot layout
/// is fixed by the runner. Custom volumes are translated to virtio-fs tags
/// when the config carries directory shares.
fn build_activation_environment(config: &VmStartConfig) -> Result<ActivateEnvironment> {
    let rootfs_roothash = resolve_rootfs_roothash(config)?;
    let runtime_roothash = config
        .runtime_overlay_roothash
        .as_deref()
        .context("runtime overlay roothash is required for universal initramfs boot")?;

    let rootfs = RootfsConfig {
        data_dev: ROOTFS_DATA_DEV.to_string(),
        hash_dev: ROOTFS_HASH_DEV.to_string(),
        roothash: rootfs_roothash.to_string(),
    };

    let runtime = RuntimeOverlayConfig {
        data_dev: RUNTIME_DATA_DEV.to_string(),
        hash_dev: RUNTIME_HASH_DEV.to_string(),
        roothash: runtime_roothash.to_string(),
    };

    let volumes = build_volume_configs(config);
    let verb_grant_envelope = read_verb_grant_envelope(&config.name)?;

    Ok(ActivateEnvironment {
        rootfs,
        runtime,
        volumes,
        verb_grant_envelope,
    })
}

/// Resolve the rootfs roothash from the host sidecar file when available.
fn resolve_rootfs_roothash(config: &VmStartConfig) -> Result<String> {
    if let Some(hash) = &config.roothash
        && hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Ok(hash.clone());
    }

    let Some(sidecar) = probe_roothash_sidecar(&config.rootfs_path) else {
        bail!(
            "rootfs roothash missing: config.roothash is empty and no sidecar found for {}",
            config.rootfs_path
        );
    };
    Ok(sidecar)
}

/// Read `<parent>/rootfs.roothash` next to the rootfs image, if it exists and
/// contains a well-formed 64-char lowercase hex hash.
fn probe_roothash_sidecar(rootfs_path: &str) -> Option<String> {
    let parent = Path::new(rootfs_path).parent()?;
    let raw = std::fs::read_to_string(parent.join("rootfs.roothash")).ok()?;
    let hash = raw.trim();
    (hash.len() == 64
        && hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
    .then(|| hash.to_string())
}

/// Translate configured volumes into virtio-fs volume configs.
///
/// `Disk` volumes are attached as virtio-blk devices by the runner and are not
/// part of the activation message. `DirShare` volumes become virtio-fs tags
/// with the index-based tag name used by the existing cmdline encoder.
fn build_volume_configs(config: &VmStartConfig) -> Vec<VolumeConfig> {
    config
        .volumes
        .iter()
        .enumerate()
        .filter(|(_, v)| matches!(v.kind, VmVolumeKind::DirShare))
        .map(|(idx, v)| VolumeConfig {
            tag: format!("uvol{idx}"),
            mountpoint: v.guest.clone(),
            read_only: v.read_only,
        })
        .collect()
}

/// Load the signed verb-grant envelope written by the host signer, if present.
fn read_verb_grant_envelope(vm_name: &str) -> Result<Option<VerbGrantEnvelope>> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read verb-grant envelope from {}", path.display()))?;
    let envelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse verb-grant envelope from {}", path.display()))?;
    Ok(Some(envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn test_env() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", dir.path());
        (env, dir)
    }

    fn base_config() -> VmStartConfig {
        VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    #[test]
    fn build_env_uses_config_roothash_and_sidecar_overlay() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.data_dev, "/dev/vda");
        assert_eq!(env.rootfs.hash_dev, "/dev/vdb");
        assert_eq!(env.rootfs.roothash, VALID_HASH);
        assert_eq!(env.runtime.data_dev, "/dev/vdc");
        assert_eq!(env.runtime.hash_dev, "/dev/vdd");
        assert_eq!(env.runtime.roothash, VALID_HASH);
        assert!(env.volumes.is_empty());
        assert!(env.verb_grant_envelope.is_none());
    }

    #[test]
    fn build_env_reads_roothash_sidecar_when_config_empty() {
        let (_env, dir) = test_env();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"data").unwrap();
        std::fs::write(
            dir.path().join("rootfs.roothash"),
            format!("{VALID_HASH}\n"),
        )
        .unwrap();

        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: rootfs.to_string_lossy().into_owned(),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..Default::default()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.rootfs.roothash, VALID_HASH);
    }

    #[test]
    fn build_env_rejects_missing_rootfs_roothash() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..base_config()
        };

        assert!(build_activation_environment(&config).is_err());
    }

    #[test]
    fn build_env_maps_dir_share_volumes() {
        let (_env, _dir) = test_env();
        let config = VmStartConfig {
            name: "test-vm".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            volumes: vec![
                VmVolumeKind::DirShare.into_volume("/host/share", "/guest/share", false),
                VmVolumeKind::Disk.into_volume("/host/disk", "/guest/disk", true),
            ],
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert_eq!(env.volumes.len(), 1);
        assert_eq!(env.volumes[0].tag, "uvol0");
        assert_eq!(env.volumes[0].mountpoint, "/guest/share");
        assert!(!env.volumes[0].read_only);
    }

    #[test]
    fn build_env_loads_verb_grant_envelope() {
        let (_env, _dir) = test_env();
        let state = mvm_core::config::vm_state_dir("granted-vm");
        std::fs::create_dir_all(&state).unwrap();
        let grant = mvm_core::plan::VerbGrant {
            session_id: "session-1".into(),
            plan_nonce: mvm_core::plan::Nonce::from_hex("0123456789abcdef0123456789abcdef")
                .unwrap(),
            not_after: chrono::Utc::now(),
            verbs: vec![mvm_core::plan::VerbId::new("ping").unwrap()],
            sig: vec![0u8; 64],
        };
        let envelope = VerbGrantEnvelope {
            pubkey_hex: VALID_HASH.into(),
            plan_nonce_hex: VALID_HASH.into(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant,
        };
        std::fs::write(
            state.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

        let config = VmStartConfig {
            name: "granted-vm".into(),
            roothash: Some(VALID_HASH.into()),
            runtime_overlay_roothash: Some(VALID_HASH.into()),
            ..base_config()
        };

        let env = build_activation_environment(&config).unwrap();
        assert!(env.verb_grant_envelope.is_some());
    }

    trait VolumeExt {
        fn into_volume(
            self,
            host: &str,
            guest: &str,
            read_only: bool,
        ) -> mvm_core::protocol::vm_backend::VmVolume;
    }

    impl VolumeExt for VmVolumeKind {
        fn into_volume(
            self,
            host: &str,
            guest: &str,
            read_only: bool,
        ) -> mvm_core::protocol::vm_backend::VmVolume {
            mvm_core::protocol::vm_backend::VmVolume {
                host: host.into(),
                guest: guest.into(),
                size: String::new(),
                read_only,
                kind: self,
                encrypted: false,
            }
        }
    }
}
