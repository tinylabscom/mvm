//! `FirecrackerConfigWriter` — generates `firecracker.json` from a
//! `MicrovmArtifact`.
//!
//! The output matches Firecracker's API body format: `boot-source`,
//! `drives` (rootfs as root device), `machine-config`, and `vsock`
//! (when applicable — always emitted here so consumers can paste
//! the config into the API socket without modification).
//!
//! Paths come from the artifact; no host-absolute paths are hardcoded.
//! The config file is written next to the artifact (adjacent to the
//! kernel and rootfs in the same directory).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::artifacts::artifact::{BackendConfigArtifact, MicrovmArtifact};
use crate::artifacts::traits::{ArtifactError, BackendConfigWriter};
use crate::compat::MicrovmBackend;

pub const FC_CONFIG_FILENAME: &str = "firecracker.json";

// ── typed config structs ──────────────────────────────────────────────────────
//
// A lightweight typed representation rather than raw serde_json::Value so the
// output key order is stable across runs (struct field order == JSON key order
// in serde_json's serializer). This makes snapshot tests reliable.

#[derive(Debug, Serialize, Deserialize)]
struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Drive {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MachineConfig {
    vcpu_count: u32,
    mem_size_mib: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct VsockDevice {
    vsock_id: String,
    guest_cid: u32,
    uds_path: String,
}

/// The full Firecracker config as written to `firecracker.json`.
///
/// `vsock` is always populated here with defaults so the file can be used
/// verbatim; callers that don't need vsock can clear the field before
/// passing to the API socket.
///
/// Named `FcConfigFile` (not `FirecrackerConfig`) to avoid shadowing the
/// public `crate::backend::FirecrackerConfig` type.
#[derive(Debug, Serialize, Deserialize)]
struct FcConfigFile {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    vsock: VsockDevice,
}

// ── defaults (mirrors Firecracker's own example configs) ─────────────────────

const DEFAULT_VCPU_COUNT: u32 = 1;
const DEFAULT_MEM_SIZE_MIB: u64 = 512;
// Guest CID for vsock — mirrors `mvm_guest::vsock::GUEST_CID` without pulling
// in the dep. The value is fixed by the mvm vsock protocol (claim 12/13).
const DEFAULT_GUEST_CID: u32 = 3;

// ── writer ────────────────────────────────────────────────────────────────────

/// Writes a `firecracker.json` next to the artifact files.
///
/// The output directory is derived from the rootfs path (both kernel and
/// rootfs are expected to live in the same directory). If the rootfs has
/// no parent, the current directory is used.
pub struct FirecrackerConfigWriter;

impl BackendConfigWriter for FirecrackerConfigWriter {
    fn write_config(
        &self,
        artifact: &MicrovmArtifact,
    ) -> Result<BackendConfigArtifact, ArtifactError> {
        if artifact.backend != MicrovmBackend::Firecracker {
            return Err(ArtifactError::NotImplemented {
                backend: artifact.backend,
            });
        }

        let artifact_dir = artifact
            .rootfs
            .path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        let config = build_config(artifact, artifact_dir);

        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let out_path = artifact_dir.join(FC_CONFIG_FILENAME);
        std::fs::write(&out_path, format!("{json}\n"))?;

        Ok(BackendConfigArtifact {
            backend: MicrovmBackend::Firecracker,
            path: out_path,
        })
    }
}

/// Build the `FcConfigFile` value from `artifact`.
///
/// Extracted so the snapshot test can inspect the JSON without writing a file.
fn build_config(artifact: &MicrovmArtifact, artifact_dir: &std::path::Path) -> FcConfigFile {
    let boot_args = artifact.boot_args.join(" ");

    let vsock_uds = artifact_dir.join("v.sock");

    FcConfigFile {
        boot_source: BootSource {
            kernel_image_path: artifact.kernel.path.display().to_string(),
            boot_args,
        },
        drives: vec![Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: artifact.rootfs.path.display().to_string(),
            is_root_device: true,
            // Derived from the artifact: verified-boot/prod sets read_only=true
            // (ADR-002 W3 — dm-verity requires RO so the Merkle check holds);
            // dev/sandbox may set read_only=false for writable overlay mounts.
            is_read_only: artifact.rootfs.read_only,
        }],
        machine_config: MachineConfig {
            vcpu_count: DEFAULT_VCPU_COUNT,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
        },
        vsock: VsockDevice {
            vsock_id: "vsock0".to_string(),
            guest_cid: DEFAULT_GUEST_CID,
            uds_path: vsock_uds.display().to_string(),
        },
    }
}

// ── derive the config path ────────────────────────────────────────────────────

/// Resolve the path where `FirecrackerConfigWriter` would write the config,
/// given an artifact. Used by callers that need to know the path before
/// actually writing.
pub fn config_path_for(artifact: &MicrovmArtifact) -> PathBuf {
    let dir = artifact
        .rootfs
        .path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    dir.join(FC_CONFIG_FILENAME)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::artifact::{KernelArtifact, RootfsArtifact};
    use crate::compat::RootfsFormat;
    use mvm_core::arch::GuestArch;
    use mvm_core::kernel_format::KernelFormat;
    use uuid::Uuid;

    fn fixture_artifact(dir: &std::path::Path) -> MicrovmArtifact {
        // Write stub files so paths exist (validator may check, writer does not)
        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        std::fs::write(&kernel, b"stub").unwrap();
        std::fs::write(&rootfs, b"stub").unwrap();

        MicrovmArtifact {
            id: Uuid::parse_str("aaaabbbb-cccc-dddd-eeee-ffffffffffff").unwrap(),
            arch: GuestArch::X86_64,
            backend: MicrovmBackend::Firecracker,
            kernel: KernelArtifact {
                path: kernel,
                format: KernelFormat::Elf,
                hash: "deadbeef".to_string(),
                version: Some("6.1.0".to_string()),
            },
            rootfs: RootfsArtifact {
                path: rootfs,
                format: RootfsFormat::Ext4,
                hash: "cafebabe".to_string(),
                size_bytes: 1_073_741_824,
                read_only: true,
            },
            boot_args: vec![
                "console=ttyS0".to_string(),
                "reboot=k".to_string(),
                "panic=1".to_string(),
            ],
            config_path: None,
        }
    }

    #[test]
    fn firecracker_config_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = fixture_artifact(tmp.path());

        let writer = FirecrackerConfigWriter;
        let result = writer.write_config(&artifact).unwrap();

        assert_eq!(result.backend, MicrovmBackend::Firecracker);
        assert_eq!(result.path, tmp.path().join(FC_CONFIG_FILENAME));
        assert!(result.path.exists());

        let raw = std::fs::read_to_string(&result.path).unwrap();

        // The config file must be newline-terminated.
        assert!(raw.ends_with('\n'), "config file must end with newline");

        // Parse back and verify structure — more robust than string snapshot
        // since path separators differ across platforms.
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();

        let boot = &parsed["boot-source"];
        assert!(
            boot["kernel_image_path"]
                .as_str()
                .unwrap()
                .ends_with("vmlinux"),
            "kernel_image_path must end with vmlinux"
        );
        assert_eq!(
            boot["boot_args"].as_str().unwrap(),
            "console=ttyS0 reboot=k panic=1"
        );

        let drives = parsed["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 1);
        let rootfs_drive = &drives[0];
        assert_eq!(rootfs_drive["drive_id"].as_str().unwrap(), "rootfs");
        assert!(rootfs_drive["is_root_device"].as_bool().unwrap());
        assert!(rootfs_drive["is_read_only"].as_bool().unwrap());
        assert!(
            rootfs_drive["path_on_host"]
                .as_str()
                .unwrap()
                .ends_with("rootfs.ext4"),
            "path_on_host must end with rootfs.ext4"
        );

        let mc = &parsed["machine-config"];
        assert_eq!(
            mc["vcpu_count"].as_u64().unwrap(),
            DEFAULT_VCPU_COUNT as u64
        );
        assert_eq!(mc["mem_size_mib"].as_u64().unwrap(), DEFAULT_MEM_SIZE_MIB);

        let vsock = &parsed["vsock"];
        assert_eq!(vsock["vsock_id"].as_str().unwrap(), "vsock0");
        assert_eq!(
            vsock["guest_cid"].as_u64().unwrap(),
            DEFAULT_GUEST_CID as u64
        );
        assert!(
            vsock["uds_path"].as_str().unwrap().ends_with("v.sock"),
            "uds_path must end with v.sock"
        );
    }

    #[test]
    fn non_firecracker_backend_returns_not_implemented() {
        let tmp = tempfile::tempdir().unwrap();
        let mut artifact = fixture_artifact(tmp.path());
        artifact.backend = MicrovmBackend::Libkrun;

        let writer = FirecrackerConfigWriter;
        let err = writer.write_config(&artifact).unwrap_err();
        assert!(
            matches!(
                err,
                ArtifactError::NotImplemented {
                    backend: MicrovmBackend::Libkrun
                }
            ),
            "expected NotImplemented for Libkrun, got: {err}"
        );
    }

    /// Stable JSON structure check — assert every expected top-level key is present
    /// and the key set matches exactly what the spec requires.
    #[test]
    fn firecracker_config_json_has_required_top_level_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = fixture_artifact(tmp.path());
        let config = build_config(&artifact, tmp.path());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();

        let obj = json.as_object().unwrap();
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["boot-source", "drives", "machine-config", "vsock"]
                .iter()
                .copied()
                .collect();
        assert_eq!(keys, expected, "unexpected or missing top-level keys");
    }

    #[test]
    fn config_path_for_helper_returns_expected_path() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = fixture_artifact(tmp.path());
        let p = config_path_for(&artifact);
        assert_eq!(p, tmp.path().join(FC_CONFIG_FILENAME));
    }
}
