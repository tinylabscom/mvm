//! Compatibility data types for the retired raw Firecracker flake launcher.

use anyhow::Result;
use tracing::instrument;

use crate::base::config::VmSlot;
use crate::base::shell::run_in_vm;
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
    /// Declared guest-runtime source contract carried through the kernel
    /// cmdline so the guest launcher can distinguish required-overlay vs
    /// preferred-overlay boots.
    pub runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy,
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

/// Refuse the retired raw Firecracker flake launcher.
///
/// Workloads must enter through the runner so the guest has no NIC and all
/// admitted egress crosses the host-vsock endpoint.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_build(config: &FlakeRunConfig) -> Result<()> {
    config.validate()?;
    anyhow::bail!("raw Firecracker flake launch is disabled; use the vsock workload runner")
}

/// Refuse the retired raw Firecracker standby claim path.
#[instrument(skip_all, fields(name = %config.name))]
pub fn run_from_prestarted_build(
    config: &FlakeRunConfig,
    abs_dir: &str,
    abs_socket: &str,
) -> Result<()> {
    config.validate()?;
    let _ = (abs_dir, abs_socket);
    anyhow::bail!("raw Firecracker standby claim is disabled; use the vsock workload runner")
}

/// Generate shell commands to inject `DriveFile`s into a mounted drive.
///
/// Each file is written via `sudo tee` with shell-escaped content, then
/// `chmod`'d to the requested permission mode. The caller must have the
/// drive mounted at `$MOUNT_DIR` before these commands run.
fn drive_file_inject_commands(files: &[DriveFile]) -> String {
    let mut cmds = String::new();
    for f in files {
        let escaped = f.content.replace('\'', "'\\''");
        let mode = format!("{:04o}", f.mode);
        // Stage the file into `$STAGE`; `mkfs.ext4 -d` copies the staged
        // tree into the image at format time (preserving mode), so no
        // loop mount / sudo is needed on the drive-build hot path.
        cmds.push_str(&format!(
            "echo '{content}' > \"$STAGE/{name}\"\nchmod {mode} \"$STAGE/{name}\"\n",
            content = escaped,
            name = f.name,
            mode = mode,
        ));
    }
    cmds
}

/// Create a config drive (mvm-config label) with config.json and role-specific toml.
pub fn create_dev_config_drive(abs_dir: &str, config: &FlakeRunConfig) -> Result<String> {
    let path = format!("{}/config.ext4", abs_dir);
    let slot = &config.slot;

    let config_json = serde_json::json!({
        "instance_id": config.name,
        "guest_ip": slot.guest_ip,
        "role": config.profile.as_deref().unwrap_or("worker"),
    });
    let escaped_json = config_json.to_string().replace('\'', "'\\''");

    // Determine role-specific config filename and stub content
    let role = config.profile.as_deref().unwrap_or("worker");
    let toml_name = format!("{}.toml", role);
    let toml_content = format!("# Dev-mode {} config stub\n", role);
    let escaped_toml = toml_content.replace('\'', "'\\''");

    // Build injection commands for custom config files
    let extra_cmds = drive_file_inject_commands(&config.config_files);

    // Populate-at-format via `mkfs.ext4 -d`: stage the files on the host,
    // then format the image directly from the staging dir. This replaces a
    // `mkfs` + loop `mount`/`tee`/`umount` round-trip (a sudo round-trip
    // that cost hundreds of ms per drive) with a single mkfs call.
    run_in_vm(&format!(
        r#"
        set -e
        STAGE=$(mktemp -d)
        echo '{json}' > "$STAGE/config.json"
        echo '{toml}' > "$STAGE/{toml_name}"
        chmod 0444 "$STAGE/config.json" "$STAGE/{toml_name}"
        {extra}
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-config -d "$STAGE" {path}
        rm -rf "$STAGE"
        chmod 0644 {path}
        "#,
        path = path,
        json = escaped_json,
        toml = escaped_toml,
        toml_name = toml_name,
        extra = extra_cmds,
    ))?;
    Ok(path)
}

/// Create a secrets drive (mvm-secrets label) with a stub secrets.json plus extra files.
pub fn create_dev_secrets_drive(abs_dir: &str, secret_files: &[DriveFile]) -> Result<String> {
    let path = format!("{}/secrets.ext4", abs_dir);

    let extra_cmds = drive_file_inject_commands(secret_files);

    // Populate-at-format via `mkfs.ext4 -d` (see `create_dev_config_drive`):
    // no loop mount, so a no-secrets workload no longer pays a sudo
    // mount/umount round-trip for an empty drive.
    run_in_vm(&format!(
        r#"
        set -e
        STAGE=$(mktemp -d)
        echo '{{}}' > "$STAGE/secrets.json"
        chmod 0400 "$STAGE/secrets.json"
        {extra}
        rm -f {path}
        truncate -s 4M {path}
        mkfs.ext4 -q -L mvm-secrets -d "$STAGE" {path}
        rm -rf "$STAGE"
        chmod 0600 {path}
        "#,
        path = path,
        extra = extra_cmds,
    ))?;
    Ok(path)
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
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
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
    fn raw_flake_launch_refuses_before_starting_firecracker() {
        let err = run_from_build(&baseline_run_config(None)).expect_err("raw launch is retired");
        assert!(err.to_string().contains("vsock workload runner"));
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

    #[test]
    fn drive_file_inject_commands_empty() {
        let cmds = drive_file_inject_commands(&[]);
        assert!(cmds.is_empty());
    }

    #[test]
    fn drive_file_inject_commands_single_file() {
        let files = vec![DriveFile {
            name: "test.txt".into(),
            content: "hello world".into(),
            mode: 0o444,
        }];
        let cmds = drive_file_inject_commands(&files);
        assert!(cmds.contains("hello world"));
        assert!(cmds.contains("test.txt"));
        assert!(cmds.contains("0444"));
    }

    #[test]
    fn drive_file_inject_commands_escapes_quotes() {
        let files = vec![DriveFile {
            name: "config.json".into(),
            content: "it's a test".into(),
            mode: 0o400,
        }];
        let cmds = drive_file_inject_commands(&files);
        // Single quotes in content should be escaped for shell safety
        assert!(cmds.contains(r"'\''"));
        assert!(cmds.contains("0400"));
    }

    #[test]
    fn drive_file_inject_commands_multiple_files() {
        let files = vec![
            DriveFile {
                name: "a.txt".into(),
                content: "aaa".into(),
                mode: 0o444,
            },
            DriveFile {
                name: "b.env".into(),
                content: "KEY=val".into(),
                mode: 0o400,
            },
        ];
        let cmds = drive_file_inject_commands(&files);
        assert!(cmds.contains("a.txt"));
        assert!(cmds.contains("b.env"));
        assert!(cmds.contains("KEY=val"));
    }
}
