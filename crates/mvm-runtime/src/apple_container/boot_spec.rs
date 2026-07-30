//! Pure mapping from a workload config to the HVF supervisor config that
//! boots the Apple Container guest stack.
//!
//! The Apple Container boot differs from the workload runner's boot in one
//! structural way: the root block device is Apple's `initfs.ext4` (so the
//! kernel runs `/sbin/vminitd` as PID 1), and the workload disks attach
//! *before* it. The disk slots therefore follow the activation
//! environment's fixed device names — rootfs data at `/dev/vda`, rootfs
//! hash at `/dev/vdb`, runtime-overlay data at `/dev/vdc`, overlay hash at
//! `/dev/vdd` — with the initfs appended last and named in `root=` on the
//! cmdline. Only the two self-consistent shapes are supported: a sealed
//! boot (both verity sidecars present) and a plain boot (neither); partial
//! shapes are refused with a typed error rather than silently mounting the
//! wrong device.
//!
//! The serial console is the in-house VMM's PL011 UART (`ttyAMA0`), not the
//! virtio-console (`hvc0`) Apple's own runtime uses — the cmdline here says
//! so explicitly, mirroring the other HVF boots.
//!
//! Everything in this module is a pure function of its inputs: no
//! filesystem probing, no process spawning — that lives in
//! [`crate::apple_container_backend`].

use std::path::{Path, PathBuf};

use mvm_build::hvf_supervisor::{ConsoleDataSocket, HvfDisk, HvfSupervisorConfig};
use mvm_core::vm_backend::VmStartConfig;

use super::artifacts::AppleContainerArtifacts;
use super::vminitd::VMINITD_VSOCK_PORT;
use crate::apple_container_backend::AppleContainerError;
use crate::vmm::fdt;

/// Host UDS name (inside the VM state dir) the supervisor binds for the
/// guest's vminitd vsock port.
pub const VMINITD_HOST_SOCKET_NAME: &str = "vminitd.sock";

/// Guest path the injected agent binary is written to.
pub const AGENT_GUEST_PATH: &str = "/run/mvm/mvm-guest-agent";
/// Guest path the activation environment JSON is written to.
pub const ACTIVATION_GUEST_PATH: &str = "/run/mvm/activation.json";
/// Guest directory holding both injected files.
pub const INJECTION_GUEST_DIR: &str = "/run/mvm";

/// One virtio-blk slot letter: slot 0 is `vda`, slot 1 is `vdb`, …
fn block_device_name(slot: usize) -> String {
    debug_assert!(slot < 26, "virtio-blk slot {slot} exceeds /dev/vdz");
    // The caller builds disks in attach order with far fewer than 26 slots.
    let letter = char::from(*b"abcdefghijklmnopqrstuvwxyz".get(slot).unwrap_or(&b'z'));
    format!("/dev/vd{letter}")
}

/// The kernel cmdline for the Apple Container boot: the VMM's standard
/// PL011 console preamble (the in-house VMM has no virtio-console, so
/// `console=hvc0` would be silent here), then the initfs as root with
/// vminitd as PID 1.
pub fn cmdline(root_device: &str) -> String {
    format!(
        "earlycon=pl011,0x{uart:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8 \
         root={root_device} rw init=/sbin/vminitd",
        uart = fdt::SERIAL_MMIO_BASE,
    )
}

/// Which workload disk shapes the config carries, validated as a unit.
enum DiskShape<'a> {
    /// Sealed: rootfs + verity + runtime overlay + overlay verity.
    Sealed {
        rootfs: &'a str,
        rootfs_verity: &'a str,
        overlay: &'a str,
        overlay_verity: &'a str,
    },
    /// Plain: an unverified rootfs only.
    Plain { rootfs: &'a str },
}

impl DiskShape<'_> {
    /// The ordered attach list (initfs excluded — the caller appends it).
    fn disks(&self) -> Vec<HvfDisk> {
        match self {
            DiskShape::Sealed {
                rootfs,
                rootfs_verity,
                overlay,
                overlay_verity,
            } => [rootfs, rootfs_verity, overlay, overlay_verity]
                .iter()
                .map(|path| HvfDisk {
                    path: PathBuf::from(path),
                    read_only: true,
                    ephemeral: false,
                })
                .collect(),
            DiskShape::Plain { rootfs } => vec![HvfDisk {
                path: PathBuf::from(rootfs),
                // A plain rootfs mounts read-write; writes stay in guest RAM
                // and are dropped on exit, matching the workload default.
                read_only: false,
                ephemeral: true,
            }],
        }
    }
}

/// Classify the config's disk fields into a supported shape, refusing
/// partial verity/overlay combinations with a typed error.
fn disk_shape(config: &VmStartConfig) -> Result<DiskShape<'_>, AppleContainerError> {
    if config.rootfs_path.trim().is_empty() {
        return Err(AppleContainerError::UnsupportedConfig {
            feature: "a boot without a rootfs image",
            reason: "rootfs_path is empty — the Apple Container boot attaches the workload \
                     rootfs as /dev/vda",
        });
    }
    let fields = (
        config.verity_path.is_some(),
        config.runtime_overlay_path.is_some(),
        config.runtime_overlay_verity_path.is_some(),
    );
    match fields {
        (false, false, false) => Ok(DiskShape::Plain {
            rootfs: config.rootfs_path.as_str(),
        }),
        (true, true, true) => Ok(DiskShape::Sealed {
            rootfs: config.rootfs_path.as_str(),
            rootfs_verity: config
                .verity_path
                .as_deref()
                .expect("verity_path checked above"),
            overlay: config
                .runtime_overlay_path
                .as_deref()
                .expect("runtime_overlay_path checked above"),
            overlay_verity: config
                .runtime_overlay_verity_path
                .as_deref()
                .expect("runtime_overlay_verity_path checked above"),
        }),
        _ => Err(AppleContainerError::UnsupportedConfig {
            feature: "a partial verity/overlay disk set",
            reason: "the activation environment names fixed device slots (/dev/vda../dev/vdd), \
                     so the boot supports only the sealed (all sidecars) or plain (none) shapes",
        }),
    }
}

/// Inputs for [`build_supervisor_config`], grouped so the mapping stays a
/// two-argument pure function.
pub struct BootSpecInput<'a> {
    /// The workload start config (rootfs/verity paths, memory, name).
    pub config: &'a VmStartConfig,
    /// The resolved Apple Container boot artifacts.
    pub artifacts: &'a AppleContainerArtifacts,
    /// Per-VM state dir (console log, pid file, vsock bridge sockets).
    pub state_dir: &'a Path,
    /// Run budget in seconds (`0` = persistent until stopped).
    pub timeout_secs: u64,
}

/// Map a validated workload config to the supervisor config that boots the
/// Apple Container guest stack on the in-house HVF VMM. Pure: all
/// validation failures are typed, all outputs derive only from the inputs.
pub fn build_supervisor_config(
    input: &BootSpecInput<'_>,
) -> Result<HvfSupervisorConfig, AppleContainerError> {
    let config = input.config;
    if config.virtiofs_root.is_some() {
        return Err(AppleContainerError::UnsupportedConfig {
            feature: "a virtiofs-root dev boot",
            reason: "the Apple Container boot's root block device is the vminitd initfs; \
                     the workload rootfs must be a block image",
        });
    }
    if config.initrd_path.is_some() {
        return Err(AppleContainerError::UnsupportedConfig {
            feature: "a separate initrd",
            reason: "the vminitd initfs boots as the root block device, not as an initramfs",
        });
    }
    if config
        .volumes
        .iter()
        .any(|v| v.kind == mvm_core::vm_backend::VmVolumeKind::Disk)
    {
        return Err(AppleContainerError::UnsupportedConfig {
            feature: "block-device volumes",
            reason: "the fixed device slots leave no attach order for extra block devices yet",
        });
    }

    let shape = disk_shape(config)?;
    let mut disks = shape.disks();
    // The initfs is the root block device and always attaches last, so the
    // workload disks keep the activation environment's fixed slot names.
    disks.push(HvfDisk {
        path: input.artifacts.initfs.clone(),
        read_only: true,
        ephemeral: false,
    });
    let root_device = block_device_name(disks.len() - 1);

    let state_dir = input.state_dir;
    Ok(HvfSupervisorConfig {
        kernel: input.artifacts.kernel.clone(),
        cmdline: Some(cmdline(&root_device)),
        memory_mib: config.memory_mib,
        initramfs: None,
        disks,
        virtiofs_root: None,
        vsock: true,
        console_log: state_dir.join("console.log"),
        pid_file: state_dir.join(crate::hvf_backend::PID_FILE_NAME),
        workload_exit: state_dir.join("workload.exit"),
        timeout_secs: input.timeout_secs,
        agent_socket: Some(mvm_core::config::vm_hvf_agent_socket_at(state_dir)),
        substitution_socket: None,
        egress_relay_socket: None,
        broker_socket: None,
        // vminitd's control channel rides the supervisor's port-bridge
        // mechanism (one host UDS per guest vsock port), the same splice the
        // dev console uses.
        console_data_sockets: vec![ConsoleDataSocket {
            guest_port: VMINITD_VSOCK_PORT,
            host_socket: state_dir.join(VMINITD_HOST_SOCKET_NAME),
        }],
    })
}

/// The host UDS the supervisor binds for vminitd's vsock port.
pub fn vminitd_host_socket(state_dir: &Path) -> PathBuf {
    state_dir.join(VMINITD_HOST_SOCKET_NAME)
}

/// The serialized OCI runtime spec `CreateProcess.configuration` carries
/// for the guest agent: run the injected binary as uid 0 (the mount
/// namespace work the follow-up milestone adds needs the privilege; the
/// agent drops to its service uid itself).
pub fn agent_process_config() -> Vec<u8> {
    serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "user": { "uid": 0, "gid": 0 },
            "args": [AGENT_GUEST_PATH],
            "env": ["MVM_ACTIVATION_FILE=/run/mvm/activation.json"],
            "cwd": "/"
        },
        "root": { "path": "/", "readonly": false }
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifacts() -> AppleContainerArtifacts {
        AppleContainerArtifacts {
            kernel: PathBuf::from("/cache/apple-container/vmlinux"),
            initfs: PathBuf::from("/cache/apple-container/initfs.ext4"),
        }
    }

    fn input<'a>(
        config: &'a VmStartConfig,
        artifacts: &'a AppleContainerArtifacts,
        state_dir: &'a Path,
    ) -> BootSpecInput<'a> {
        BootSpecInput {
            config,
            artifacts,
            state_dir,
            timeout_secs: 0,
        }
    }

    fn plain_config() -> VmStartConfig {
        VmStartConfig {
            name: "ac-test".to_string(),
            rootfs_path: "/img/rootfs.ext4".to_string(),
            memory_mib: 1024,
            ..Default::default()
        }
    }

    fn sealed_config() -> VmStartConfig {
        VmStartConfig {
            verity_path: Some("/img/rootfs.verity".to_string()),
            roothash: Some("ab".repeat(32)),
            runtime_overlay_path: Some("/img/overlay.ext4".to_string()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".to_string()),
            runtime_overlay_roothash: Some("cd".repeat(32)),
            ..plain_config()
        }
    }

    #[test]
    fn plain_boot_maps_disks_cmdline_and_vsock_bridge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = build_supervisor_config(&input(&plain_config(), &artifacts(), dir.path()))
            .expect("plain spec");

        assert_eq!(cfg.kernel, PathBuf::from("/cache/apple-container/vmlinux"));
        // Rootfs at vda (writable, ephemeral), initfs last at vdb, root= says so.
        assert_eq!(cfg.disks.len(), 2);
        assert_eq!(cfg.disks[0].path, PathBuf::from("/img/rootfs.ext4"));
        assert!(!cfg.disks[0].read_only);
        assert!(cfg.disks[0].ephemeral);
        assert_eq!(
            cfg.disks[1].path,
            PathBuf::from("/cache/apple-container/initfs.ext4")
        );
        assert!(cfg.disks[1].read_only);
        let cmdline = cfg.cmdline.expect("cmdline");
        assert!(
            cmdline.contains("console=ttyAMA0"),
            "the VMM has a PL011 UART, not virtio-console: {cmdline}"
        );
        assert!(cmdline.contains("root=/dev/vdb rw"), "{cmdline}");
        assert!(cmdline.contains("init=/sbin/vminitd"), "{cmdline}");

        assert!(cfg.vsock);
        assert_eq!(cfg.memory_mib, 1024);
        assert!(cfg.initramfs.is_none());
        assert!(cfg.virtiofs_root.is_none());
        assert_eq!(cfg.pid_file, dir.path().join("hvf.pid"));
        assert_eq!(
            cfg.agent_socket,
            Some(mvm_core::config::vm_hvf_agent_socket_at(dir.path()))
        );
        assert_eq!(cfg.console_data_sockets.len(), 1);
        assert_eq!(cfg.console_data_sockets[0].guest_port, VMINITD_VSOCK_PORT);
        assert_eq!(
            cfg.console_data_sockets[0].host_socket,
            dir.path().join(VMINITD_HOST_SOCKET_NAME)
        );
    }

    #[test]
    fn sealed_boot_attaches_all_sidecars_in_activation_slot_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = build_supervisor_config(&input(&sealed_config(), &artifacts(), dir.path()))
            .expect("sealed spec");

        let paths: Vec<&Path> = cfg.disks.iter().map(|d| d.path.as_path()).collect();
        assert_eq!(
            paths,
            vec![
                Path::new("/img/rootfs.ext4"),
                Path::new("/img/rootfs.verity"),
                Path::new("/img/overlay.ext4"),
                Path::new("/img/overlay.verity"),
                Path::new("/cache/apple-container/initfs.ext4"),
            ]
        );
        assert!(cfg.disks.iter().all(|d| d.read_only));
        // The activation env names vda..vdd for the workload disks, so the
        // initfs (root) lands at vde.
        let cmdline = cfg.cmdline.expect("cmdline");
        assert!(cmdline.contains("root=/dev/vde rw"), "{cmdline}");
    }

    #[test]
    fn partial_disk_shapes_fail_closed() {
        let partial = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".to_string()),
            ..plain_config()
        };
        let err = build_supervisor_config(&BootSpecInput {
            config: &partial,
            artifacts: &artifacts(),
            state_dir: Path::new("/tmp"),
            timeout_secs: 0,
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                AppleContainerError::UnsupportedConfig { feature, .. }
                    if feature.contains("partial")
            ),
            "expected a partial-shape refusal, got {err:?}"
        );
    }

    #[test]
    fn virtiofs_root_and_initrd_are_refused_with_typed_errors() {
        let virtiofs = VmStartConfig {
            virtiofs_root: Some("/tree".to_string()),
            ..plain_config()
        };
        let err = build_supervisor_config(&BootSpecInput {
            config: &virtiofs,
            artifacts: &artifacts(),
            state_dir: Path::new("/tmp"),
            timeout_secs: 0,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            AppleContainerError::UnsupportedConfig { feature, .. } if feature.contains("virtiofs")
        ));

        let initrd = VmStartConfig {
            initrd_path: Some("/initrd.cpio".to_string()),
            ..plain_config()
        };
        let err = build_supervisor_config(&BootSpecInput {
            config: &initrd,
            artifacts: &artifacts(),
            state_dir: Path::new("/tmp"),
            timeout_secs: 0,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            AppleContainerError::UnsupportedConfig { feature, .. } if feature.contains("initrd")
        ));
    }

    #[test]
    fn empty_rootfs_and_disk_volumes_are_refused() {
        let empty = VmStartConfig::default();
        let err = build_supervisor_config(&BootSpecInput {
            config: &empty,
            artifacts: &artifacts(),
            state_dir: Path::new("/tmp"),
            timeout_secs: 0,
        })
        .unwrap_err();
        assert!(matches!(err, AppleContainerError::UnsupportedConfig { .. }));

        let with_disk = VmStartConfig {
            volumes: vec![mvm_core::vm_backend::VmVolume {
                host: "/img/extra.ext4".to_string(),
                guest: "/mnt/extra".to_string(),
                read_only: true,
                kind: mvm_core::vm_backend::VmVolumeKind::Disk,
                ..Default::default()
            }],
            ..plain_config()
        };
        let err = build_supervisor_config(&BootSpecInput {
            config: &with_disk,
            artifacts: &artifacts(),
            state_dir: Path::new("/tmp"),
            timeout_secs: 0,
        })
        .unwrap_err();
        assert!(matches!(
            err,
            AppleContainerError::UnsupportedConfig { feature, .. } if feature.contains("block-device")
        ));
    }

    #[test]
    fn agent_process_config_runs_the_injected_agent_as_root_with_activation_env() {
        let bytes = agent_process_config();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(json["process"]["args"][0], AGENT_GUEST_PATH);
        assert_eq!(json["process"]["user"]["uid"], 0);
        assert_eq!(
            json["process"]["env"][0],
            format!("MVM_ACTIVATION_FILE={ACTIVATION_GUEST_PATH}")
        );
    }

    #[test]
    fn block_device_names_track_attach_order() {
        assert_eq!(block_device_name(0), "/dev/vda");
        assert_eq!(block_device_name(4), "/dev/vde");
    }
}
