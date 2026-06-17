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
    /// dev VMs leave it None.
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
    /// Warm-pool target (`--warm-pool-size`); 0 = off.
    pub warm_pool_size: u32,
    /// Resolved egress policy (deny-all default, or the `--network-preset` /
    /// `--network-allow` selection). Threaded onto `VmStartConfig` so the
    /// gateway-bridge backends enforce the chosen posture instead of
    /// fail-closing to deny-all regardless of the request.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
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
            network_policy: self.network_policy,
            warm_pool_size: self.warm_pool_size,
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
            // Runtime overlay wiring lives behind the `mvmctl run
            // --runtime-overlay` opt-in surface, not this generic
            // params struct. Leaving the three overlay fields at
            // their `None` defaults keeps the boot path identical
            // for every caller that goes through `VmStartParams`.
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::NetworkPolicy;

    fn params(network_policy: NetworkPolicy) -> VmStartParams<'static> {
        VmStartParams {
            name: "vm".into(),
            rootfs_path: "/rootfs.ext4".into(),
            vmlinux_path: "/vmlinux".into(),
            initrd_path: None,
            verity_path: None,
            roothash: None,
            revision_hash: "rev".into(),
            flake_ref: ".".into(),
            profile: None,
            cpus: 1,
            memory_mib: 256,
            mem_initial_mib: None,
            volumes: &[],
            config_files: &[],
            secret_files: &[],
            port_mappings: &[],
            warm_pool_size: 0,
            network_policy,
        }
    }

    // Regression: `VmStartParams` previously carried no egress policy, so
    // `into_start_config()` fell through to `VmStartConfig::default()` =
    // deny-all for every `up` boot — silently ignoring `--network-preset` /
    // `--network-allow`. The resolved policy must survive the conversion so the
    // backend (Firecracker nftables; the libkrun/Vz gateway bridge) enforces
    // the requested posture instead of always deny-all.
    #[test]
    fn into_start_config_preserves_the_resolved_network_policy() {
        let unrestricted = NetworkPolicy::unrestricted();
        let sc = params(unrestricted.clone()).into_start_config();
        assert_eq!(sc.network_policy, unrestricted);
        assert!(sc.network_policy.is_unrestricted());

        let deny = NetworkPolicy::deny_all();
        let sc = params(deny.clone()).into_start_config();
        assert_eq!(sc.network_policy, deny);
        assert!(!sc.network_policy.is_unrestricted());
    }
}
