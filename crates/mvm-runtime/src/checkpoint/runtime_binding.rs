//! Bind authenticated runtime generations to the paused backend's inputs.

use anyhow::{Context, Result, ensure};
use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta};
use mvm_core::protocol::runtime_release::RuntimeLaunchBinding;
use mvm_vmm::runtime_artifacts::{RuntimeArtifact, RuntimeArtifacts};

use super::CheckpointStore;

pub(super) const EVIDENCE_BLOB: &str = "runtime-artifacts.json";

/// Plaintext digest of a small metadata blob, authenticated by the checkpoint
/// manifest directly or by its sealed index. This never opens content chunks.
pub(crate) fn metadata_blob_sha256(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    name: &str,
) -> Result<String> {
    let blob = meta
        .content
        .iter()
        .find(|blob| blob.name == name)
        .with_context(|| format!("checkpoint has no {name} blob"))?;
    if meta.protection.is_sealed() {
        super::materialized_blob_sha256(store, meta, name)
    } else {
        Ok(blob.sha256.clone())
    }
}

/// The caller must collect `actual` while the VM is paused. Runtime metadata
/// supplies only a candidate: it cannot establish what the VMM loaded.
/// Absence of external runtime inputs does not authenticate a baked agent:
/// the existing checkpoint/rootfs integrity and image-admission gates still
/// establish the base image's provenance and compatibility.
pub(crate) fn verify_capture(
    binding: Option<&RuntimeLaunchBinding>,
    actual: &RuntimeArtifacts,
) -> Result<()> {
    if actual.firecracker_drives.is_some() {
        mvm_backends::fc::runtime_artifacts::validate_artifacts(actual, binding)?;
    }
    let Some(binding) = binding else {
        ensure!(
            actual.initramfs.is_none()
                && !actual
                    .kernel_cmdline
                    .split_whitespace()
                    .any(|token| token.starts_with("mvm.runtime_")),
            "externally loaded runtime has no authenticated runtime binding; restart the VM with a verified runtime before capturing it"
        );
        return Ok(());
    };
    if matches!(binding, RuntimeLaunchBinding::CliAssembly(_)) {
        crate::runtime_evidence::verify_runtime_binding(binding)?;
    }
    verify_bound_artifacts(binding, actual)
}

fn verify_bound_artifacts(binding: &RuntimeLaunchBinding, actual: &RuntimeArtifacts) -> Result<()> {
    if let RuntimeLaunchBinding::LegacyPortable {
        overlay_path,
        overlay_verity_path,
        initramfs_path,
        kernel_path,
        ..
    } = binding
    {
        let mut config = mvm_core::vm_backend::VmStartConfig::default();
        binding.apply_to_config(&mut config);
        let verified = crate::runtime_evidence::verify_retained_portable_runtime(&config)?;
        ensure!(
            actual
                .kernel
                .as_ref()
                .is_some_and(|kernel| kernel.path == *kernel_path
                    && kernel.sha256 == verified.kernel_sha256()),
            "paused portable kernel differs from signed bundle or lacks loaded-kernel evidence"
        );
        let root = actual
            .disks
            .first()
            .context("portable rootfs absent from paused VM")?;
        ensure!(
            root.sha256 == verified.rootfs_sha256(),
            "paused portable rootfs differs from signed bundle"
        );
        verify_artifact(root, &root.path)?;
        ensure!(
            mvm_core::crypto::image_verify::sha256_file(kernel_path)? == verified.kernel_sha256(),
            "retained portable kernel differs from signed bundle"
        );
        return verify_overlay_artifacts(actual, overlay_path, overlay_verity_path, initramfs_path);
    }
    let RuntimeLaunchBinding::CliAssembly(binding) = binding else {
        let RuntimeLaunchBinding::LegacyBundle { initramfs_path, .. } = binding else {
            unreachable!()
        };
        ensure!(
            !actual
                .kernel_cmdline
                .split_whitespace()
                .any(|token| token.starts_with("mvm.runtime_")),
            "legacy bundle cannot supply external runtime devices"
        );
        match (&actual.initramfs, initramfs_path) {
            (Some(actual), Some(expected)) => verify_artifact(actual, expected)?,
            (None, None) => {}
            _ => anyhow::bail!("legacy initrd differs from authenticated selection"),
        }
        let root = actual
            .disks
            .first()
            .context("legacy rootfs is absent from paused VM")?;
        let mut config = mvm_core::vm_backend::VmStartConfig::default();
        binding.apply_to_config(&mut config);
        let verified = crate::runtime_evidence::verify_retained_legacy_runtime(&config)?;
        // Forks may copy the rootfs to a child path, but not change its bytes.
        ensure!(
            root.sha256 == verified.rootfs_sha256(),
            "paused legacy rootfs differs from signed bundle"
        );
        verify_artifact(root, &root.path)?;
        return Ok(());
    };
    verify_overlay_artifacts(
        actual,
        &binding.overlay_path,
        &binding.overlay_verity_path,
        &binding.initramfs_path,
    )
}

fn verify_overlay_artifacts(
    actual: &RuntimeArtifacts,
    overlay_path: &std::path::Path,
    overlay_verity_path: &std::path::Path,
    initramfs_path: &std::path::Path,
) -> Result<()> {
    let initramfs = actual
        .initramfs
        .as_ref()
        .context("bound runtime is absent from the paused VM's initramfs configuration")?;
    verify_artifact(initramfs, initramfs_path)?;
    for path in [overlay_path, overlay_verity_path] {
        let matches = actual
            .disks
            .iter()
            .filter(|artifact| artifact.path == path)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "bound runtime device {} is absent or duplicated in the paused VM",
            path.display()
        );
        verify_artifact(matches[0], path)?;
    }
    ensure!(
        actual
            .disks
            .windows(2)
            .any(|pair| { pair[0].path == overlay_path && pair[1].path == overlay_verity_path }),
        "runtime data and verity devices are not in their authenticated role order"
    );
    Ok(())
}

fn verify_artifact(artifact: &RuntimeArtifact, expected: &std::path::Path) -> Result<()> {
    ensure!(
        artifact.path == expected,
        "paused runtime artifact does not match the authenticated generation"
    );
    let digest = mvm_core::crypto::verified_digest::sha256_file_verified(expected)?;
    ensure!(
        artifact.sha256 == digest,
        "paused runtime artifact changed from the authenticated generation"
    );
    Ok(())
}

/// Validate the launch shape that restore will consume against the observation,
/// not against a second copy of launch metadata.
pub(super) fn capture_supervisor_config(
    source: &std::path::Path,
    destination: &std::path::Path,
    actual: &RuntimeArtifacts,
) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Config {
        kernel: Option<std::path::PathBuf>,
        initramfs: Option<std::path::PathBuf>,
        disks: Vec<Disk>,
        cmdline: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Disk {
        path: std::path::PathBuf,
        read_only: bool,
    }
    let bytes = std::fs::read(source)?;
    let config: Config = serde_json::from_slice(&bytes)?;
    if let Some(kernel) = &actual.kernel {
        ensure!(
            config.kernel.as_ref() == Some(&kernel.path),
            "saved supervisor kernel differs from the paused runtime"
        );
    }
    ensure!(
        config.initramfs.as_ref() == actual.initramfs.as_ref().map(|artifact| &artifact.path),
        "saved supervisor initramfs differs from the paused runtime"
    );
    // Full HVF snapshots support only read-only disks. Keeping every slot
    // makes vector position the actual /dev/vd device identity, rather than
    // losing writable slots while comparing a filtered or unordered set.
    ensure!(
        config.disks.iter().all(|disk| disk.read_only),
        "full HVF capture cannot authenticate writable disk slots"
    );
    let configured = config
        .disks
        .iter()
        .map(|disk| &disk.path)
        .collect::<Vec<_>>();
    let observed = actual
        .disks
        .iter()
        .map(|disk| &disk.path)
        .collect::<Vec<_>>();
    ensure!(
        configured == observed,
        "saved supervisor disks differ from the paused runtime"
    );
    let runtime_tokens = |cmdline: &str| {
        cmdline
            .split_whitespace()
            .filter(|token| token.starts_with("mvm.runtime_"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    ensure!(
        runtime_tokens(config.cmdline.as_deref().unwrap_or_default())
            == runtime_tokens(&actual.kernel_cmdline),
        "saved supervisor runtime command line differs from the paused runtime"
    );
    std::fs::write(destination, bytes)?;
    Ok(())
}

/// Call only after authenticating the checkpoint metadata against its chain.
/// The evidence is independently checked against that authenticated manifest,
/// including when the large memory image is verified lazily on load.
pub fn verify_checkpoint_runtime(store: &CheckpointStore, meta: &CheckpointMeta) -> Result<()> {
    if meta.protection.is_sealed() && meta.class == CheckpointClass::VmFull {
        let scratch = crate::private_staging::create(
            store.root(),
            super::staging::RESTORE_MATERIALIZATION_PREFIX,
        )?;
        let _remove_on_interrupt = {
            let path = scratch.path().to_path_buf();
            crate::interrupt_cleanup::on_interrupt("runtime evidence staging", move || {
                let _ = std::fs::remove_dir_all(&path);
            })
        };
        super::materialized_source(store, meta, EVIDENCE_BLOB, scratch.path())?;
        return verify_checkpoint_runtime_at(store, meta, scratch.path());
    }
    verify_checkpoint_runtime_at(store, meta, &store.content_dir(&meta.id))
}

/// Verify private materialized evidence against the chain-authenticated parent.
/// Prepared children reuse this copy without reopening sealed content chunks.
pub(crate) fn verify_checkpoint_runtime_at(
    store: &CheckpointStore,
    meta: &CheckpointMeta,
    content_dir: &std::path::Path,
) -> Result<()> {
    if meta.class != CheckpointClass::VmFull {
        return Ok(());
    }
    meta
        .content
        .iter()
        .find(|blob| blob.name == EVIDENCE_BLOB)
        .context("checkpoint has no authenticated paused-runtime evidence; recapture the VM with a runtime-aware backend before restoring or forking it")?;
    let digest = metadata_blob_sha256(store, meta, EVIDENCE_BLOB)?;
    let path = content_dir.join(EVIDENCE_BLOB);
    let bytes = std::fs::read(path).context("reading paused-runtime evidence")?;
    let actual = decode_authenticated_observation(&bytes, &digest)?;
    match mvm_core::checkpoint::vm_full_origin(meta) {
        Some(mvm_core::checkpoint::VmFullOrigin::Firecracker) => {
            mvm_backends::fc::runtime_artifacts::validate_artifacts(
                &actual,
                meta.runtime_launch_binding.as_ref(),
            )?;
        }
        Some(mvm_core::checkpoint::VmFullOrigin::Hvf) => {
            ensure!(
                actual.firecracker_drives.is_none(),
                "HVF checkpoint carries a Firecracker device observation"
            );
        }
        Some(mvm_core::checkpoint::VmFullOrigin::Retired) | None => {
            anyhow::bail!("checkpoint has no supported authenticated runtime backend identity");
        }
    }
    verify_capture(meta.runtime_launch_binding.as_ref(), &actual)
}

fn decode_authenticated_observation(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<RuntimeArtifacts> {
    ensure!(
        mvm_core::crypto::image_verify::sha256_reader(bytes)? == expected_sha256,
        "checkpoint paused-runtime evidence digest mismatch"
    );
    serde_json::from_slice(bytes).context("decoding authenticated paused-runtime evidence")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::runtime_release::RuntimeBindingProvenance;

    fn baked() -> RuntimeArtifacts {
        RuntimeArtifacts {
            kernel: None,
            firecracker_drives: None,
            initramfs: None,
            disks: Vec::new(),
            kernel_cmdline: "console=hvc0".into(),
        }
    }

    #[test]
    fn only_observed_baked_runtime_can_omit_a_binding() {
        let mut actual = baked();
        verify_capture(None, &actual).unwrap();
        actual.kernel_cmdline.push_str(" mvm.runtime_data=/dev/vdb");
        assert!(verify_capture(None, &actual).is_err());
        actual = baked();
        actual.initramfs = Some(RuntimeArtifact {
            path: "/external/initramfs".into(),
            sha256: "ab".repeat(32),
        });
        assert!(verify_capture(None, &actual).is_err());
    }

    #[test]
    fn bound_generation_requires_exact_present_unchanged_devices() {
        let dir = tempfile::tempdir().unwrap();
        let paths = ["initramfs", "overlay", "verity"].map(|name| dir.path().join(name));
        for (index, path) in paths.iter().enumerate() {
            std::fs::write(path, [index as u8]).unwrap();
        }
        let artifacts = paths.each_ref().map(|path| RuntimeArtifact {
            path: path.clone(),
            sha256: mvm_core::crypto::image_verify::sha256_file(path).unwrap(),
        });
        let binding = RuntimeLaunchBinding::CliAssembly(
            mvm_core::protocol::runtime_release::CliRuntimeLaunchBinding {
                provenance: RuntimeBindingProvenance::Source {
                    version: "1.2.3".into(),
                    arch: mvm_core::arch::GuestArch::host(),
                    archive_sha256: "ab".repeat(32),
                },
                initramfs_path: paths[0].clone(),
                overlay_path: paths[1].clone(),
                overlay_verity_path: paths[2].clone(),
                overlay_roothash: "ab".repeat(32),
            },
        );
        let actual = RuntimeArtifacts {
            kernel: None,
            firecracker_drives: None,
            initramfs: Some(artifacts[0].clone()),
            disks: artifacts[1..].to_vec(),
            kernel_cmdline: "console=hvc0".into(),
        };
        verify_bound_artifacts(&binding, &actual).unwrap();
        let mut missing = actual.clone();
        missing.disks.pop();
        assert!(verify_bound_artifacts(&binding, &missing).is_err());
        let mut mismatch = actual.clone();
        mismatch.initramfs.as_mut().unwrap().path = "/another/generation/initramfs".into();
        assert!(verify_bound_artifacts(&binding, &mismatch).is_err());
        let mut duplicate = actual.clone();
        duplicate.disks.push(actual.disks[0].clone());
        assert!(verify_bound_artifacts(&binding, &duplicate).is_err());
        let mut reversed_roles = actual.clone();
        reversed_roles.disks.reverse();
        assert!(verify_bound_artifacts(&binding, &reversed_roles).is_err());
        std::fs::write(&paths[1], b"changed after launch").unwrap();
        assert!(verify_bound_artifacts(&binding, &actual).is_err());
        std::fs::remove_file(&paths[1]).unwrap();
        assert!(verify_bound_artifacts(&binding, &actual).is_err());
    }

    #[test]
    fn stored_supervisor_config_must_match_the_paused_observation() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("supervisor.json");
        let destination = dir.path().join("captured.json");
        let observed = baked();
        let matching = br#"{"initramfs":null,"disks":[],"cmdline":"console=hvc0"}"#;
        std::fs::write(&source, matching).unwrap();
        capture_supervisor_config(&source, &destination, &observed).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), matching);
        for changed in [
            r#"{"initramfs":"/another/initrd","disks":[],"cmdline":null}"#,
            r#"{"initramfs":null,"disks":[{"path":"/runtime","read_only":true}],"cmdline":null}"#,
            r#"{"initramfs":null,"disks":[],"cmdline":"mvm.runtime_data=/dev/vdb"}"#,
        ] {
            std::fs::write(&source, changed).unwrap();
            assert!(capture_supervisor_config(&source, &destination, &observed).is_err());
            assert_eq!(std::fs::read(&destination).unwrap(), matching);
        }
    }

    #[test]
    fn supervisor_disk_slots_cannot_be_reordered_duplicated_or_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("supervisor.json");
        let destination = dir.path().join("captured.json");
        let paths = ["/rootfs", "/overlay", "/verity"];
        let mut observed = baked();
        observed.disks = paths
            .map(|path| RuntimeArtifact {
                path: path.into(),
                sha256: "ab".repeat(32),
            })
            .to_vec();
        let config = |paths: &[&str], read_only: bool| {
            serde_json::json!({
                "initramfs": null,
                "cmdline": null,
                "disks": paths.iter().map(|path| serde_json::json!({
                    "path": path, "read_only": read_only
                })).collect::<Vec<_>>()
            })
            .to_string()
        };
        let original = config(&paths, true);
        std::fs::write(&source, &original).unwrap();
        capture_supervisor_config(&source, &destination, &observed).unwrap();
        for changed in [
            config(&["/overlay", "/rootfs", "/verity"], true),
            config(&["/rootfs", "/verity", "/overlay"], true),
            config(&["/rootfs", "/overlay", "/overlay", "/verity"], true),
            config(&["/rootfs", "/overlay"], true),
            config(&paths, false),
        ] {
            std::fs::write(&source, changed).unwrap();
            assert!(capture_supervisor_config(&source, &destination, &observed).is_err());
            assert_eq!(std::fs::read_to_string(&destination).unwrap(), original);
        }
    }

    #[test]
    fn observation_parser_uses_only_the_authenticated_buffer() {
        let bytes = serde_json::to_vec(&baked()).unwrap();
        let digest = mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice()).unwrap();
        decode_authenticated_observation(&bytes, &digest).unwrap();
        let mut changed = baked();
        changed.kernel_cmdline = "mvm.runtime_data=/dev/vdb".into();
        let replacement = serde_json::to_vec(&changed).unwrap();
        assert!(decode_authenticated_observation(&replacement, &digest).is_err());
        assert!(decode_authenticated_observation(&bytes, &"00".repeat(32)).is_err());
    }
}
