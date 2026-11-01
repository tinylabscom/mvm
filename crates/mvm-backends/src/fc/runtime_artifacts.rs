//! Read Firecracker's actual paused boot configuration, never a launch sidecar.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_vmm::runtime_artifacts::{FirecrackerDrive, RuntimeArtifact, RuntimeArtifacts};
use serde::Deserialize;

#[derive(Deserialize)]
struct InstanceInfo {
    state: String,
}

#[derive(Deserialize)]
struct VmConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<Drive>,
}

#[derive(Deserialize)]
struct BootSource {
    kernel_image_path: PathBuf,
    initrd_path: Option<PathBuf>,
    boot_args: Option<String>,
}

#[derive(Deserialize)]
struct Drive {
    drive_id: String,
    is_root_device: bool,
    path_on_host: PathBuf,
    is_read_only: bool,
}

/// Verify configured writable backings against the original held objects after
/// Firecracker opened their paths and before the guest may start.
pub(crate) fn verify_writable_backings(
    socket: &Path,
    expected: &std::collections::BTreeMap<u8, (u64, u64)>,
) -> Result<()> {
    let config = super::call(socket, "GET", "/vm/config", None)
        .context("querying Firecracker's writable backing configuration")?;
    verify_config_backings(&config, expected)
}

fn verify_config_backings(
    json: &str,
    expected: &std::collections::BTreeMap<u8, (u64, u64)>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let config: VmConfig = serde_json::from_str(json)
        .context("parsing Firecracker's writable backing configuration")?;
    let mut seen = std::collections::BTreeSet::new();
    for drive in config.drives.iter().filter(|drive| !drive.is_read_only) {
        let slot = u8::try_from(canonical_slot(&drive.drive_id)?)?;
        let identity = expected
            .get(&slot)
            .context("configured writable disk was not prepared")?;
        let selected = std::fs::symlink_metadata(&drive.path_on_host)?;
        ensure!(
            selected.is_file() && (selected.dev(), selected.ino()) == *identity,
            "Firecracker writable backing differs from the original held object"
        );
        seen.insert(slot);
    }
    ensure!(
        seen == expected.keys().copied().collect(),
        "Firecracker writable backing set differs from the prepared set"
    );
    Ok(())
}

pub(super) fn query(socket: &Path) -> Result<RuntimeArtifacts> {
    let info: InstanceInfo = serde_json::from_str(&super::call(socket, "GET", "/", None)?)?;
    ensure!(
        info.state == "Paused",
        "runtime observation requires a paused Firecracker VM"
    );
    let config = super::call(socket, "GET", "/vm/config", None)
        .context("querying Firecracker's actual runtime configuration")?;
    from_config(&config)
}

fn from_config(json: &str) -> Result<RuntimeArtifacts> {
    let mut config: VmConfig =
        serde_json::from_str(json).context("parsing Firecracker's actual runtime configuration")?;
    ensure!(
        config.boot_source.kernel_image_path.is_absolute(),
        "Firecracker did not report its boot-source kernel identity"
    );
    // Managed launches assign blk{slot} in numeric slot order. Firecracker's
    // snapshot save traverses a HashMap and restores resource configuration in
    // that traversal order, so GET array order is not stable after restore.
    // Native snapshot authentication preserves the ID/device-info association;
    // these canonical IDs recover the managed driver's slot order.
    for drive in &config.drives {
        canonical_slot(&drive.drive_id)?;
    }
    config
        .drives
        .sort_by_key(|drive| canonical_slot(&drive.drive_id).expect("validated drive ID"));
    // These are configuration observations, not a measurement of loaded RAM.
    // Admission compares their exact paths to a protected retained generation
    // and verifies that generation independently. Writable devices cannot
    // establish an immutable runtime binding.
    let firecracker_drives = config
        .drives
        .iter()
        .map(|drive| FirecrackerDrive {
            drive_id: drive.drive_id.clone(),
            path: drive.path_on_host.clone(),
            is_root_device: drive.is_root_device,
            is_read_only: drive.is_read_only,
        })
        .collect::<Vec<_>>();
    validate_layout(&firecracker_drives)?;
    let disks = config
        .drives
        .into_iter()
        .filter(|drive| drive.is_read_only)
        .map(|drive| observe_file(drive.path_on_host))
        .collect::<Result<Vec<_>>>()?;
    Ok(RuntimeArtifacts {
        kernel: Some(observe_file(config.boot_source.kernel_image_path)?),
        initramfs: config.boot_source.initrd_path.map(observe_file).transpose()?,
        disks,
        firecracker_drives: Some(firecracker_drives),
        // Firecracker v1.14.1 vmm_config/boot_source.rs DEFAULT_KERNEL_CMDLINE.
        // persist.rs VmInfo saves boot_source and builder.rs restores it into
        // VmResources, which GET /vm/config serializes even after snapshot load.
        kernel_cmdline: config.boot_source.boot_args.unwrap_or_else(|| {
            "reboot=k panic=1 nomodule 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.dumbkbd swiotlb=noforce".into()
        }),
    })
}

fn observe_file(path: PathBuf) -> Result<RuntimeArtifact> {
    ensure!(
        path.is_absolute(),
        "Firecracker runtime device path is not absolute"
    );
    let sha256 = mvm_core::crypto::verified_digest::sha256_file_verified(&path)?;
    Ok(RuntimeArtifact { path, sha256 })
}

fn validate_layout(drives: &[FirecrackerDrive]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for (slot, drive) in drives.iter().enumerate() {
        let numeric_slot = canonical_slot(&drive.drive_id)?;
        if slot > 0 {
            ensure!(
                canonical_slot(&drives[slot - 1].drive_id)? < numeric_slot,
                "Firecracker device layout is not in canonical managed slot order"
            );
        }
        ensure!(
            !drive.drive_id.is_empty() && ids.insert(&drive.drive_id),
            "Firecracker drive IDs are missing or duplicated"
        );
        ensure!(
            drive.path.is_absolute() && paths.insert(&drive.path),
            "Firecracker drive paths are invalid or duplicated"
        );
        ensure!(
            drive.is_root_device == (slot == 0),
            "Firecracker root device must occupy exactly the first slot"
        );
    }
    Ok(())
}

fn canonical_slot(id: &str) -> Result<u32> {
    let suffix = id
        .strip_prefix("blk")
        .context("runtime capture requires managed Firecracker blk{slot} device IDs")?;
    let slot = suffix
        .parse::<u32>()
        .context("invalid managed Firecracker device slot")?;
    ensure!(
        id == format!("blk{slot}"),
        "noncanonical managed Firecracker device ID"
    );
    Ok(slot)
}

/// Validate all configured slots, including writable devices that are not
/// eligible to attest immutable runtime bytes.
pub fn validate_artifacts(
    actual: &RuntimeArtifacts,
    binding: Option<&mvm_core::protocol::runtime_release::RuntimeLaunchBinding>,
) -> Result<()> {
    let drives = actual
        .firecracker_drives
        .as_ref()
        .context("Firecracker runtime observation lacks its full device layout; recapture it")?;
    validate_layout(drives)?;
    let readonly = drives
        .iter()
        .filter(|drive| drive.is_read_only)
        .map(|drive| &drive.path)
        .collect::<Vec<_>>();
    let measured = actual
        .disks
        .iter()
        .map(|artifact| &artifact.path)
        .collect::<Vec<_>>();
    ensure!(
        readonly == measured,
        "Firecracker readonly evidence differs from its configured slots"
    );
    if let Some(
        mvm_core::protocol::runtime_release::RuntimeLaunchBinding::LegacyBundle { .. }
        | mvm_core::protocol::runtime_release::RuntimeLaunchBinding::LegacyPortable { .. },
    ) = binding
    {
        ensure!(
            drives
                .first()
                .is_some_and(|drive| drive.is_root_device && drive.is_read_only),
            "legacy runtime requires a measured read-only Firecracker rootfs"
        );
    }
    let runtime_paths = match binding {
        Some(mvm_core::protocol::runtime_release::RuntimeLaunchBinding::CliAssembly(binding)) => {
            Some((&binding.overlay_path, &binding.overlay_verity_path))
        }
        Some(mvm_core::protocol::runtime_release::RuntimeLaunchBinding::LegacyPortable {
            overlay_path,
            overlay_verity_path,
            ..
        }) => Some((overlay_path, overlay_verity_path)),
        Some(mvm_core::protocol::runtime_release::RuntimeLaunchBinding::LegacyBundle {
            ..
        })
        | None => None,
    };
    if let Some((overlay_path, overlay_verity_path)) = runtime_paths {
        ensure!(
            drives.windows(2).any(|pair| {
                &pair[0].path == overlay_path
                    && &pair[1].path == overlay_verity_path
                    && pair
                        .iter()
                        .all(|drive| drive.is_read_only && !drive.is_root_device)
            }),
            "Firecracker runtime data/verity role slots differ from the bound generation"
        );
    }
    Ok(())
}

pub(crate) fn authenticated_capture(
    directory: &Path,
    expected_sha256: &str,
) -> Result<RuntimeArtifacts> {
    let bytes = std::fs::read(directory.join("runtime-artifacts.json"))?;
    ensure!(
        mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice())? == expected_sha256,
        "restored runtime observation differs from the authenticated checkpoint"
    );
    let expected: RuntimeArtifacts = serde_json::from_slice(&bytes)?;
    validate_artifacts(&expected, None)?;
    Ok(expected)
}

/// Values derived from an authenticated parent manifest and, only for an
/// explicit identity-changing fork, from the newly minted child's drive.
pub struct ForkRuntimeEvidence<'a> {
    pub observation_sha256: &'a str,
    pub anchors_sha256: &'a str,
    pub reseeded_identity_sha256: Option<&'a str>,
}

pub(crate) fn authenticated_fork_capture(
    directory: &Path,
    evidence: &ForkRuntimeEvidence<'_>,
) -> Result<RuntimeArtifacts> {
    let mut expected = authenticated_capture(directory, evidence.observation_sha256)?;
    let bytes = std::fs::read(directory.join("device-anchors.json"))?;
    ensure!(
        mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice())? == evidence.anchors_sha256,
        "fork device anchors differ from the authenticated checkpoint"
    );
    let anchors: mvm_core::checkpoint::DeviceAnchors = serde_json::from_slice(&bytes)?;
    if let Some(digest) = evidence.reseeded_identity_sha256 {
        let identity = anchors
            .identity
            .context("reseeded identity has no authenticated parent mapping")?;
        let matches = expected
            .disks
            .iter_mut()
            .filter(|disk| disk.path == identity)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "identity remap must name exactly one authenticated readonly device"
        );
        for disk in matches {
            disk.sha256 = digest.to_owned();
        }
    }
    Ok(expected)
}

/// Compare the paused child's actual layout with the authenticated capture of
/// its parent, after the child's own drive files have replaced the parent's.
pub(crate) fn verify_restored_layout(
    io: &super::io::FirecrackerIO,
    expected: RuntimeArtifacts,
) -> Result<RuntimeArtifacts> {
    let devices = io
        .fork_devices()
        .context("a restored fork's layout is checked against the child's own devices")?;
    let actual = query(&io.socket_path)?;
    compare_restored_layout(&actual, &devices.as_child_capture(expected))?;
    Ok(actual)
}

/// Let later processes reuse the digests a layout verification just accepted.
///
/// Called at refill, never on a claim: it creates the digest-cache key if this
/// is the first use, waits out the settle window so a file written moments ago
/// can be sealed, and re-reads each file once. Only a digest equal to the one
/// the verification accepted is sealed, so the claim that later finds it still
/// compares it with the authenticated expectation exactly as before. Any doubt
/// seals nothing and the claim hashes.
pub(crate) fn seal_accepted_digests(accepted: &RuntimeArtifacts) {
    use mvm_core::crypto::digest_cache::FileIdentity;
    use mvm_core::crypto::verified_digest::RACY_WINDOW;

    if mvm_core::crypto::digest_cache::process_key().is_none() {
        return;
    }
    let artifacts: Vec<&RuntimeArtifact> = accepted
        .kernel
        .iter()
        .chain(accepted.initramfs.iter())
        .chain(accepted.disks.iter())
        .collect();
    let now = std::time::SystemTime::now();
    let delay = artifacts
        .iter()
        .filter_map(|artifact| {
            let meta = std::fs::metadata(&artifact.path).ok()?;
            FileIdentity::of(&meta)?.settle_delay(now, RACY_WINDOW)
        })
        .max()
        .unwrap_or_default();
    if !delay.is_zero() {
        // A few ms past the window, so the seal that follows sees it as elapsed.
        std::thread::sleep(delay + std::time::Duration::from_millis(10));
    }
    for artifact in artifacts {
        let _ = mvm_core::crypto::image_verify::seal_digest_if_matches(
            &artifact.path,
            &artifact.sha256,
        );
    }
}

fn compare_restored_layout(actual: &RuntimeArtifacts, expected: &RuntimeArtifacts) -> Result<()> {
    validate_artifacts(actual, None)?;
    validate_artifacts(expected, None)?;
    if let Some(kernel) = &expected.kernel {
        ensure!(
            actual.kernel.as_ref() == Some(kernel),
            "restored Firecracker kernel differs from authenticated capture"
        );
    }
    ensure!(
        actual.firecracker_drives == expected.firecracker_drives,
        "restored Firecracker drive roles differ from authenticated capture"
    );
    ensure!(
        actual.initramfs == expected.initramfs,
        "restored Firecracker initramfs differs from authenticated capture"
    );
    ensure!(
        actual.disks == expected.disks,
        "restored Firecracker readonly backing bytes differ from authenticated capture"
    );
    ensure!(
        actual.kernel_cmdline == expected.kernel_cmdline,
        "restored Firecracker command line differs from authenticated capture"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_writable_backings_must_match_the_original_objects() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        std::fs::write(&original, b"original").unwrap();
        let identity = {
            let metadata = std::fs::metadata(&original).unwrap();
            (metadata.dev(), metadata.ino())
        };
        let expected = std::collections::BTreeMap::from([(0, identity)]);
        let config = |path| {
            serde_json::json!({
                "boot-source": {"kernel_image_path": "/kernel", "initrd_path": null},
                "drives": [
                    {"drive_id":"blk0", "is_root_device":true, "path_on_host": path, "is_read_only": false}
                ]
            })
            .to_string()
        };
        verify_config_backings(&config(&original), &expected).unwrap();
        std::fs::rename(&original, dir.path().join("renamed")).unwrap();
        std::fs::write(&original, b"replacement").unwrap();
        assert!(verify_config_backings(&config(&original), &expected).is_err());
        assert!(verify_config_backings(&config(&dir.path().join("renamed")), &expected).is_ok());
        assert!(
            verify_config_backings(
                &serde_json::json!({"boot-source": {"kernel_image_path": "/kernel"}, "drives": []})
                    .to_string(),
                &expected,
            )
            .is_err()
        );
    }

    #[test]
    fn configured_files_are_observed_and_writable_drives_cannot_attest_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let initrd = dir.path().join("initrd");
        let overlay = dir.path().join("overlay");
        let kernel = dir.path().join("kernel");
        std::fs::write(&kernel, b"loaded kernel").unwrap();
        std::fs::write(&initrd, b"loaded initrd").unwrap();
        std::fs::write(&overlay, b"runtime").unwrap();
        let config = serde_json::json!({
            "boot-source": {"kernel_image_path": kernel, "initrd_path": initrd, "boot_args": "console=hvc0"},
            "drives": [
                {"drive_id":"blk0", "is_root_device":true, "path_on_host": "/unreadable/writable/root", "is_read_only": false},
                {"drive_id":"blk1", "is_root_device":false, "path_on_host": overlay, "is_read_only": true}
            ]
        });
        let observed = from_config(&config.to_string()).unwrap();
        assert_eq!(observed.initramfs.unwrap().path, initrd);
        assert_eq!(observed.disks.len(), 1);
        assert_eq!(observed.disks[0].path, overlay);
        assert_eq!(
            observed.disks[0].sha256,
            mvm_core::crypto::image_verify::sha256_file(&overlay).unwrap()
        );
        let old = observed.disks[0].sha256.clone();
        std::fs::write(&overlay, b"changed").unwrap();
        assert_ne!(
            from_config(&config.to_string()).unwrap().disks[0].sha256,
            old
        );
        std::fs::remove_file(&overlay).unwrap();
        assert!(from_config(&config.to_string()).is_err());
    }

    #[test]
    fn absent_configuration_is_not_baked_runtime_evidence() {
        for config in ["{}", r#"{"boot-source":{},"drives":[]}"#] {
            assert!(from_config(config).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("kernel");
        std::fs::write(&kernel, b"kernel").unwrap();
        let baked = from_config(&serde_json::json!({
            "boot-source":{"kernel_image_path":kernel,"initrd_path":null,"boot_args":null},"drives":[]
        }).to_string()).unwrap();
        assert!(baked.initramfs.is_none());
        assert!(
            baked
                .kernel_cmdline
                .starts_with("reboot=k panic=1 nomodule")
        );
    }

    fn observed_layout() -> RuntimeArtifacts {
        let drives = [
            ("/root", true, false),
            ("/overlay", false, true),
            ("/verity", false, true),
        ]
        .into_iter()
        .enumerate()
        .map(|(slot, (path, root, readonly))| FirecrackerDrive {
            drive_id: format!("blk{slot}"),
            path: path.into(),
            is_root_device: root,
            is_read_only: readonly,
        })
        .collect::<Vec<_>>();
        RuntimeArtifacts {
            kernel: None,
            initramfs: None,
            disks: drives
                .iter()
                .filter(|d| d.is_read_only)
                .map(|d| RuntimeArtifact {
                    path: d.path.clone(),
                    sha256: "ab".repeat(32),
                })
                .collect(),
            kernel_cmdline: String::new(),
            firecracker_drives: Some(drives),
        }
    }

    #[test]
    fn restored_layout_preserves_writable_root_and_every_drive_identity() {
        let expected = observed_layout();
        compare_restored_layout(&expected, &expected).unwrap();
        for mutation in 0..6 {
            let mut changed = expected.clone();
            let drives = changed.firecracker_drives.as_mut().unwrap();
            match mutation {
                0 => drives.swap(1, 2),
                1 => drives[1].drive_id = "different".into(),
                2 => drives[0].is_root_device = false,
                3 => drives[1].is_read_only = false,
                4 => drives[2].drive_id = drives[1].drive_id.clone(),
                5 => drives[2].path = drives[1].path.clone(),
                _ => unreachable!(),
            }
            assert!(compare_restored_layout(&changed, &expected).is_err());
        }
    }

    #[test]
    fn writable_interleave_cannot_hide_runtime_role_slot_drift() {
        use mvm_core::protocol::runtime_release::{RuntimeBindingProvenance, RuntimeLaunchBinding};
        let mut observed = observed_layout();
        let binding = RuntimeLaunchBinding::CliAssembly(
            mvm_core::protocol::runtime_release::CliRuntimeLaunchBinding {
                provenance: RuntimeBindingProvenance::Source {
                    version: "1".into(),
                    arch: mvm_core::arch::GuestArch::host(),
                    archive_sha256: "ab".repeat(32),
                },
                overlay_path: "/overlay".into(),
                overlay_verity_path: "/verity".into(),
                initramfs_path: "/initrd".into(),
                overlay_roothash: "ab".repeat(32),
            },
        );
        validate_artifacts(&observed, Some(&binding)).unwrap();
        observed.firecracker_drives.as_mut().unwrap()[2].drive_id = "blk3".into();
        observed.firecracker_drives.as_mut().unwrap().insert(
            2,
            FirecrackerDrive {
                drive_id: "blk2".into(),
                path: "/writable-volume".into(),
                is_root_device: false,
                is_read_only: false,
            },
        );
        // The filtered read-only list did not change, but the actual slot did.
        validate_artifacts(&observed, None).unwrap();
        assert!(validate_artifacts(&observed, Some(&binding)).is_err());
    }

    #[test]
    fn expected_layout_is_authenticated_before_it_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let observed = observed_layout();
        let bytes = serde_json::to_vec(&observed).unwrap();
        let digest = mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice()).unwrap();
        let path = dir.path().join("runtime-artifacts.json");
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            authenticated_capture(dir.path(), &digest).unwrap(),
            observed
        );
        let mut changed = observed;
        changed.firecracker_drives.as_mut().unwrap()[1].drive_id = "different".into();
        std::fs::write(path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(authenticated_capture(dir.path(), &digest).is_err());
    }

    #[test]
    fn restored_hashmap_api_order_does_not_change_managed_device_slots() {
        // Firecracker v1.14.1 device_manager/persist.rs saves block devices by
        // traversing MMIODeviceManager.virtio_devices, a HashMap, and restores
        // VmResources in that order. Device info and IDs remain in native state.
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("kernel");
        std::fs::write(&kernel, b"kernel").unwrap();
        let mut config = serde_json::json!({
            "boot-source":{"kernel_image_path":kernel,"boot_args":"console=hvc0"},
            "drives":[
                {"drive_id":"blk0","path_on_host":"/root","is_root_device":true,"is_read_only":false},
                {"drive_id":"blk1","path_on_host":"/volume","is_root_device":false,"is_read_only":false}
            ]
        });
        let expected = from_config(&config.to_string()).unwrap();
        config["drives"].as_array_mut().unwrap().reverse();
        let shuffled = from_config(&config.to_string()).unwrap();
        compare_restored_layout(&shuffled, &expected).unwrap();
        let mut wrong_kernel = shuffled.clone();
        wrong_kernel.kernel.as_mut().unwrap().sha256 = "0".repeat(64);
        assert!(compare_restored_layout(&wrong_kernel, &expected).is_err());
        wrong_kernel.kernel = None;
        assert!(compare_restored_layout(&wrong_kernel, &expected).is_err());
        config["drives"][0]["drive_id"] = "blk01".into();
        assert!(from_config(&config.to_string()).is_err());
        config["drives"][0]["drive_id"] = "unmanaged".into();
        assert!(from_config(&config.to_string()).is_err());
    }

    #[test]
    fn readonly_bytes_and_command_line_cannot_change_at_the_same_paths() {
        let expected = observed_layout();
        let mut changed = expected.clone();
        changed.disks[0].sha256 = "cd".repeat(32);
        assert!(compare_restored_layout(&changed, &expected).is_err());
        changed = expected.clone();
        changed.kernel_cmdline = "different boot".into();
        assert!(compare_restored_layout(&changed, &expected).is_err());
    }

    #[test]
    fn only_authenticated_identity_mapping_accepts_exact_fresh_digest() {
        let dir = tempfile::tempdir().unwrap();
        let mut captured = observed_layout();
        captured
            .firecracker_drives
            .as_mut()
            .unwrap()
            .push(FirecrackerDrive {
                drive_id: "blk3".into(),
                path: "/parent/identity".into(),
                is_root_device: false,
                is_read_only: true,
            });
        captured.disks.push(RuntimeArtifact {
            path: "/parent/identity".into(),
            sha256: "11".repeat(32),
        });
        let bytes = serde_json::to_vec(&captured).unwrap();
        std::fs::write(dir.path().join("runtime-artifacts.json"), &bytes).unwrap();
        let observation_digest =
            mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice()).unwrap();
        let anchors = mvm_core::checkpoint::DeviceAnchors {
            rootfs: "/root".into(),
            vsock: "/parent/runtime/v.sock".into(),
            rootfs_verity: None,
            config: None,
            secrets: None,
            identity: Some("/parent/identity".into()),
        };
        let bytes = serde_json::to_vec(&anchors).unwrap();
        std::fs::write(dir.path().join("device-anchors.json"), &bytes).unwrap();
        let anchors_digest =
            mvm_core::crypto::image_verify::sha256_reader(bytes.as_slice()).unwrap();
        let fresh = "22".repeat(32);
        let evidence = ForkRuntimeEvidence {
            observation_sha256: &observation_digest,
            anchors_sha256: &anchors_digest,
            reseeded_identity_sha256: Some(&fresh),
        };
        let expected = authenticated_fork_capture(dir.path(), &evidence).unwrap();
        let mut actual = captured.clone();
        actual.disks[2].sha256 = fresh.clone();
        compare_restored_layout(&actual, &expected).unwrap();
        assert!(
            compare_restored_layout(&actual, &captured).is_err(),
            "warm inherited identity has no reseed exemption"
        );
        actual.disks[2].sha256 = "33".repeat(32);
        assert!(
            compare_restored_layout(&actual, &expected).is_err(),
            "post-mint mutation refused"
        );
        actual = expected.clone();
        actual.disks[0].sha256 = "44".repeat(32);
        assert!(
            compare_restored_layout(&actual, &expected).is_err(),
            "other readonly device is not exempt"
        );
        std::fs::write(dir.path().join("device-anchors.json"), b"forged").unwrap();
        assert!(authenticated_fork_capture(dir.path(), &evidence).is_err());
    }
}
