//! `VmStartParams` — a scoped builder that turns runtime types into a
//! `mvm_core::vm_backend::VmStartConfig` without exposing the conversion
//! surface to every command file.

use mvm::config;
use mvm_backend::{image, microvm};

/// Parameters for building a `VmStartConfig` from runtime-specific types.
pub struct VmStartParams<'a> {
    pub name: String,
    pub rootfs_path: String,
    pub vmlinux_path: String,
    pub initrd_path: Option<String>,
    /// Optional dm-verity sidecar (Merkle tree). Production microVMs
    /// built with `verifiedBoot = true` ship this alongside the rootfs;
    /// dev VMs leave it None. ADR-002 §W3.
    pub verity_path: Option<String>,
    /// Lowercase-hex root hash; required when `verity_path` is Some.
    pub roothash: Option<String>,
    pub revision_hash: String,
    pub flake_ref: String,
    pub profile: Option<String>,
    pub cpus: u32,
    pub memory_mib: u32,
    /// Opt into virtio-balloon: when `Some(n)`, the host commits `n`
    /// MiB at boot and the balloon claws back `memory_mib - n` MiB.
    /// `None` keeps the legacy "commit memory_mib at boot" behaviour.
    pub mem_initial_mib: Option<u32>,
    pub volumes: &'a [image::RuntimeVolume],
    pub config_files: &'a [microvm::DriveFile],
    pub secret_files: &'a [microvm::DriveFile],
    pub port_mappings: &'a [config::PortMapping],
}

impl VmStartParams<'_> {
    pub fn into_start_config(self) -> mvm_core::vm_backend::VmStartConfig {
        mvm_core::vm_backend::VmStartConfig {
            name: self.name,
            rootfs_path: self.rootfs_path,
            kernel_path: Some(self.vmlinux_path),
            initrd_path: self.initrd_path,
            verity_path: self.verity_path,
            roothash: self.roothash,
            revision_hash: self.revision_hash,
            flake_ref: self.flake_ref,
            profile: self.profile,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
            mem_initial_mib: self.mem_initial_mib,
            ports: self
                .port_mappings
                .iter()
                .map(|p| mvm_core::vm_backend::VmPortMapping {
                    host: p.host,
                    guest: p.guest,
                })
                .collect(),
            volumes: self
                .volumes
                .iter()
                .map(|v| mvm_core::vm_backend::VmVolume {
                    host: v.host.clone(),
                    guest: v.guest.clone(),
                    size: v.size.clone(),
                    read_only: v.read_only,
                    kind: v.kind,
                    encrypted: v.encrypted,
                })
                .collect(),
            config_files: self
                .config_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            secret_files: self
                .secret_files
                .iter()
                .map(|f| mvm_core::vm_backend::VmFile {
                    name: f.name.clone(),
                    content: f.content.clone(),
                    mode: f.mode,
                })
                .collect(),
            runner_dir: None,
            // Plan 74 W1.4b — runtime overlay wiring lives behind
            // the `mvmctl run --runtime-overlay` opt-in surface,
            // not this generic params struct. Leaving the three
            // overlay fields at their `None` defaults keeps the
            // boot path identical to pre-W1.4b for every caller
            // that goes through `VmStartParams`.
            ..Default::default()
        }
    }
}
