//! The `FlakeRunConfig` descriptor: what to boot and with which resources.
//!
//! Pure data plus validation. The raw flake launcher this once accompanied
//! is gone — workloads enter through the vsock runner, which is enforced by
//! the egress gates rather than by a refusal here.

use anyhow::Result;

use crate::base::config::VmSlot;
use crate::image::RuntimeVolume;

use mvm_vmm::host::drive_file::DriveFile;

/// Configuration for running a Firecracker VM from flake-built artifacts.
pub struct FlakeRunConfig {
    /// VM name (user-provided or auto-generated).
    pub name: String,
    /// Network slot for this VM.
    pub slot: VmSlot,
    /// Absolute path to the kernel image on the Linux host.
    pub vmlinux_path: String,
    /// Absolute path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Absolute path to the root filesystem on the Linux host.
    pub rootfs_path: String,
    /// Absolute path to the dm-verity sidecar (Merkle hash tree) on
    /// the Linux host. Present when the flake was built with
    /// `verifiedBoot = true` (the production default).
    /// Must be paired with `roothash`.
    pub verity_path: Option<String>,
    /// 64-char lowercase-hex root hash from `rootfs.roothash`. Baked
    /// into the kernel cmdline as `dm-mod.create=`.
    pub roothash: Option<String>,
    /// Absolute path to the mvm runtime overlay ext4. When all three
    /// `runtime_overlay_*` fields are `Some`, this drive is attached
    /// as `/dev/vdc` and `mvm-verity-init` bind-mounts it at
    /// `/sysroot/mvm/runtime`.
    pub runtime_overlay_path: Option<String>,
    /// Absolute path to the runtime overlay verity sidecar; attached
    /// as `/dev/vdd`.
    pub runtime_overlay_verity_path: Option<String>,
    /// 64-char lowercase-hex root hash for the overlay; baked into
    /// the cmdline as `mvm.runtime_roothash=`.
    pub runtime_overlay_roothash: Option<String>,
    /// Nix store revision hash.
    pub revision_hash: String,
    /// Original flake reference (for display / status).
    pub flake_ref: String,
    /// Flake profile name (e.g. "worker", "gateway"), if specified.
    pub profile: Option<String>,
    /// Number of vCPUs.
    pub cpus: u32,
    /// Memory cap in MiB.
    pub memory: u32,
    /// Initial host commitment in MiB when opting into virtio-balloon.
    /// `None` = full commitment at boot (legacy default). `Some(n)`
    /// attaches a virtio-balloon device pre-inflated to
    /// `memory - n` MiB so the host commits only `n` MiB at boot;
    /// the host-side controller can PATCH the balloon target at
    /// runtime via Firecracker's `/balloon` endpoint.
    pub mem_initial: Option<u32>,
    /// Extra volumes to attach (mounted via config drive, not SSH).
    pub volumes: Vec<RuntimeVolume>,
    /// Extra files to write onto the config drive.
    pub config_files: Vec<DriveFile>,
    /// Extra files to write onto the secrets drive.
    pub secret_files: Vec<DriveFile>,
    /// Declared port mappings (host:guest) for forwarding and guest config.
    pub ports: Vec<crate::base::config::PortMapping>,
}

impl FlakeRunConfig {
    /// Validate resource bounds and required fields.
    pub fn validate(&self) -> Result<()> {
        if self.cpus == 0 || self.cpus > 32 {
            anyhow::bail!("cpus must be between 1 and 32 (got {})", self.cpus);
        }
        if self.memory < 128 || self.memory > 65536 {
            anyhow::bail!(
                "memory must be between 128 and 65536 MiB (got {})",
                self.memory
            );
        }
        if let Some(initial) = self.mem_initial {
            // The balloon device must leave the guest with some
            // headroom; 0-byte commitment doesn't boot, and a value
            // >= memory is nonsensical (balloon would claim 0 or
            // negative pages). The CLI clamps these via filter() but
            // backends are the second line of defence.
            if initial == 0 {
                anyhow::bail!(
                    "mem_initial must be > 0 when set; got 0 (use None to opt out of balloon)"
                );
            }
            if initial >= self.memory {
                anyhow::bail!(
                    "mem_initial ({initial}) must be strictly less than memory ({}); \
                     the balloon needs a non-zero inflation target",
                    self.memory
                );
            }
        }
        if self.name.is_empty() {
            anyhow::bail!("VM name must not be empty");
        }
        if self.vmlinux_path.is_empty() {
            anyhow::bail!("vmlinux_path must not be empty");
        }
        if self.rootfs_path.is_empty() {
            anyhow::bail!("rootfs_path must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_file_default() {
        let f = DriveFile::default();
        assert!(f.name.is_empty());
        assert!(f.content.is_empty());
        assert_eq!(f.mode, 0o444);
    }

    fn baseline_run_config(mem_initial: Option<u32>) -> FlakeRunConfig {
        FlakeRunConfig {
            name: "v".to_string(),
            slot: VmSlot::new("v", 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
        }
    }

    #[test]
    fn flake_run_config_validate_accepts_none_mem_initial() {
        baseline_run_config(None).validate().unwrap();
    }

    #[test]
    fn flake_run_config_validate_accepts_valid_mem_initial() {
        // 256 < 1024 → balloon device gets `1024 - 256 = 768` MiB
        // inflation, host commits 256 MiB.
        baseline_run_config(Some(256)).validate().unwrap();
    }

    #[test]
    fn flake_run_config_validate_rejects_zero_mem_initial() {
        let err = baseline_run_config(Some(0))
            .validate()
            .expect_err("rejects zero mem_initial");
        let msg = format!("{err:#}");
        assert!(msg.contains("mem_initial"), "msg was: {msg}");
    }

    #[test]
    fn flake_run_config_validate_rejects_mem_initial_equal_to_memory() {
        let err = baseline_run_config(Some(1024))
            .validate()
            .expect_err("rejects mem_initial == memory");
        assert!(format!("{err:#}").contains("strictly less than"));
    }

    #[test]
    fn flake_run_config_validate_rejects_mem_initial_above_memory() {
        let err = baseline_run_config(Some(2048))
            .validate()
            .expect_err("rejects mem_initial > memory");
        assert!(format!("{err:#}").contains("strictly less than"));
    }

    #[test]
    fn drive_file_construction() {
        let f = DriveFile {
            name: "openclaw.json".into(),
            content: r#"{"gateway":{"port":18789}}"#.into(),
            mode: 0o444,
        };
        assert_eq!(f.name, "openclaw.json");
        assert!(f.content.contains("gateway"));
        assert_eq!(f.mode, 0o444);
    }
}
