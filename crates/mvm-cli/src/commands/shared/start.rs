//! `VmStartParams` — a scoped builder that turns runtime types into a
//! `mvm_core::vm_backend::VmStartConfig` without exposing the conversion
//! surface to every command file.

use mvm_runtime::config;
use mvm_runtime::vm::{image, microvm};

/// Parameters for building a `VmStartConfig` from runtime-specific types.
pub struct VmStartParams<'a> {
    pub name: String,
    pub rootfs_path: String,
    pub vmlinux_path: String,
    pub initrd_path: Option<String>,
    pub revision_hash: String,
    pub flake_ref: String,
    pub profile: Option<String>,
    pub cpus: u32,
    pub memory_mib: u32,
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
            revision_hash: self.revision_hash,
            flake_ref: self.flake_ref,
            profile: self.profile,
            cpus: self.cpus,
            memory_mib: self.memory_mib,
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
        }
    }
}
