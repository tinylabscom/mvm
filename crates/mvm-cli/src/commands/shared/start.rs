//! `VmStartParams` — a scoped builder that turns runtime types into a
//! `mvm_core::vm_backend::VmStartConfig` without exposing the conversion
//! surface to every command file.

use mvm_contract::builder::BuilderError;
use mvm_runtime::config;
use mvm_runtime::image;

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
    pub config_files: &'a [mvm_vmm::host::drive_file::DriveFile],
    pub secret_files: &'a [mvm_vmm::host::drive_file::DriveFile],
    pub port_mappings: &'a [config::PortMapping],
    /// Warm-pool target (`--warm-pool-size`); 0 = off.
    pub warm_pool_size: u32,
    /// Resolved egress policy (deny-all default, or the `--net` /
    /// `--allow-host` selection). Threaded onto `VmStartConfig` so the
    /// gateway-bridge backends enforce the chosen posture instead of
    /// fail-closing to deny-all regardless of the request.
    pub network_policy: mvm_core::network_policy::NetworkPolicy,
}

impl<'a> VmStartParams<'a> {
    /// Start building a [`VmStartParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> VmStartParamsBuilder<'a> {
        VmStartParamsBuilder::new()
    }
}

/// Builder for [`VmStartParams`]. Required fields are checked by
/// [`VmStartParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct VmStartParamsBuilder<'a> {
    name: Option<String>,
    rootfs_path: Option<String>,
    vmlinux_path: Option<String>,
    initrd_path: Option<String>,
    verity_path: Option<String>,
    roothash: Option<String>,
    revision_hash: Option<String>,
    flake_ref: Option<String>,
    profile: Option<String>,
    cpus: Option<u32>,
    memory_mib: Option<u32>,
    mem_initial_mib: Option<u32>,
    volumes: Option<&'a [image::RuntimeVolume]>,
    config_files: Option<&'a [mvm_vmm::host::drive_file::DriveFile]>,
    secret_files: Option<&'a [mvm_vmm::host::drive_file::DriveFile]>,
    port_mappings: Option<&'a [config::PortMapping]>,
    warm_pool_size: Option<u32>,
    network_policy: Option<mvm_core::network_policy::NetworkPolicy>,
}

impl<'a> VmStartParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            rootfs_path: None,
            vmlinux_path: None,
            initrd_path: None,
            verity_path: None,
            roothash: None,
            revision_hash: None,
            flake_ref: None,
            profile: None,
            cpus: None,
            memory_mib: None,
            mem_initial_mib: None,
            volumes: None,
            config_files: None,
            secret_files: None,
            port_mappings: None,
            warm_pool_size: None,
            network_policy: None,
        }
    }

    /// Set `name`.
    #[must_use]
    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Set `rootfs_path`.
    #[must_use]
    pub fn rootfs_path(mut self, rootfs_path: String) -> Self {
        self.rootfs_path = Some(rootfs_path);
        self
    }

    /// Set `vmlinux_path`.
    #[must_use]
    pub fn vmlinux_path(mut self, vmlinux_path: String) -> Self {
        self.vmlinux_path = Some(vmlinux_path);
        self
    }

    /// Set `initrd_path`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn initrd_path(mut self, initrd_path: impl Into<Option<String>>) -> Self {
        self.initrd_path = initrd_path.into();
        self
    }

    /// Set `verity_path`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn verity_path(mut self, verity_path: impl Into<Option<String>>) -> Self {
        self.verity_path = verity_path.into();
        self
    }

    /// Set `roothash`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn roothash(mut self, roothash: impl Into<Option<String>>) -> Self {
        self.roothash = roothash.into();
        self
    }

    /// Set `revision_hash`.
    #[must_use]
    pub fn revision_hash(mut self, revision_hash: String) -> Self {
        self.revision_hash = Some(revision_hash);
        self
    }

    /// Set `flake_ref`.
    #[must_use]
    pub fn flake_ref(mut self, flake_ref: String) -> Self {
        self.flake_ref = Some(flake_ref);
        self
    }

    /// Set `profile`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn profile(mut self, profile: impl Into<Option<String>>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Set `cpus`.
    #[must_use]
    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Set `memory_mib`.
    #[must_use]
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = Some(memory_mib);
        self
    }

    /// Set `mem_initial_mib`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn mem_initial_mib(mut self, mem_initial_mib: impl Into<Option<u32>>) -> Self {
        self.mem_initial_mib = mem_initial_mib.into();
        self
    }

    /// Set `volumes`.
    #[must_use]
    pub fn volumes(mut self, volumes: &'a [image::RuntimeVolume]) -> Self {
        self.volumes = Some(volumes);
        self
    }

    /// Set `config_files`.
    #[must_use]
    pub fn config_files(
        mut self,
        config_files: &'a [mvm_vmm::host::drive_file::DriveFile],
    ) -> Self {
        self.config_files = Some(config_files);
        self
    }

    /// Set `secret_files`.
    #[must_use]
    pub fn secret_files(
        mut self,
        secret_files: &'a [mvm_vmm::host::drive_file::DriveFile],
    ) -> Self {
        self.secret_files = Some(secret_files);
        self
    }

    /// Set `port_mappings`.
    #[must_use]
    pub fn port_mappings(mut self, port_mappings: &'a [config::PortMapping]) -> Self {
        self.port_mappings = Some(port_mappings);
        self
    }

    /// Set `warm_pool_size`.
    #[must_use]
    pub fn warm_pool_size(mut self, warm_pool_size: u32) -> Self {
        self.warm_pool_size = Some(warm_pool_size);
        self
    }

    /// Set `network_policy`.
    #[must_use]
    pub fn network_policy(
        mut self,
        network_policy: mvm_core::network_policy::NetworkPolicy,
    ) -> Self {
        self.network_policy = Some(network_policy);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<VmStartParams<'a>, BuilderError> {
        Ok(VmStartParams {
            name: self
                .name
                .ok_or(BuilderError::missing("VmStartParams", "name"))?,
            rootfs_path: self
                .rootfs_path
                .ok_or(BuilderError::missing("VmStartParams", "rootfs_path"))?,
            vmlinux_path: self
                .vmlinux_path
                .ok_or(BuilderError::missing("VmStartParams", "vmlinux_path"))?,
            initrd_path: self.initrd_path,
            verity_path: self.verity_path,
            roothash: self.roothash,
            revision_hash: self
                .revision_hash
                .ok_or(BuilderError::missing("VmStartParams", "revision_hash"))?,
            flake_ref: self
                .flake_ref
                .ok_or(BuilderError::missing("VmStartParams", "flake_ref"))?,
            profile: self.profile,
            cpus: self
                .cpus
                .ok_or(BuilderError::missing("VmStartParams", "cpus"))?,
            memory_mib: self
                .memory_mib
                .ok_or(BuilderError::missing("VmStartParams", "memory_mib"))?,
            mem_initial_mib: self.mem_initial_mib,
            volumes: self
                .volumes
                .ok_or(BuilderError::missing("VmStartParams", "volumes"))?,
            config_files: self
                .config_files
                .ok_or(BuilderError::missing("VmStartParams", "config_files"))?,
            secret_files: self
                .secret_files
                .ok_or(BuilderError::missing("VmStartParams", "secret_files"))?,
            port_mappings: self
                .port_mappings
                .ok_or(BuilderError::missing("VmStartParams", "port_mappings"))?,
            warm_pool_size: self
                .warm_pool_size
                .ok_or(BuilderError::missing("VmStartParams", "warm_pool_size"))?,
            network_policy: self
                .network_policy
                .ok_or(BuilderError::missing("VmStartParams", "network_policy"))?,
        })
    }
}

impl<'a> Default for VmStartParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl VmStartParams<'_> {
    pub fn into_start_config(self) -> mvm_core::vm_backend::VmStartConfig {
        mvm_core::vm_backend::VmStartConfig {
            name: self.name,
            rootfs_path: self.rootfs_path,
            kernel_path: if self.vmlinux_path.is_empty() {
                None
            } else {
                Some(self.vmlinux_path)
            },
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
                    materialized_image: None,
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
        let Ok(params) = VmStartParams::builder()
            .name("vm".into())
            .rootfs_path("/rootfs.ext4".into())
            .vmlinux_path("/vmlinux".into())
            .revision_hash("rev".into())
            .flake_ref(".".into())
            .cpus(1)
            .memory_mib(256)
            .volumes(&[])
            .config_files(&[])
            .secret_files(&[])
            .port_mappings(&[])
            .warm_pool_size(0)
            .network_policy(network_policy)
            .build()
        else {
            panic!("every required field is set");
        };
        params
    }

    /// The optional fields are the ones a call site forgets, so each has to
    /// survive its setter instead of staying `None`.
    #[test]
    fn the_optional_setters_reach_the_built_value() {
        let Ok(built) = VmStartParams::builder()
            .name("vm".into())
            .rootfs_path("/rootfs.ext4".into())
            .vmlinux_path("/vmlinux".into())
            .initrd_path("/initrd".to_string())
            .verity_path("/rootfs.verity".to_string())
            .roothash("abc123".to_string())
            .revision_hash("rev".into())
            .flake_ref(".".into())
            .profile("prod".to_string())
            .cpus(2)
            .memory_mib(512)
            .mem_initial_mib(128)
            .volumes(&[])
            .config_files(&[])
            .secret_files(&[])
            .port_mappings(&[])
            .warm_pool_size(3)
            .network_policy(NetworkPolicy::deny_all())
            .build()
        else {
            panic!("every field is set");
        };
        assert_eq!(built.initrd_path.as_deref(), Some("/initrd"));
        assert_eq!(built.verity_path.as_deref(), Some("/rootfs.verity"));
        assert_eq!(built.roothash.as_deref(), Some("abc123"));
        assert_eq!(built.profile.as_deref(), Some("prod"));
        assert_eq!(built.mem_initial_mib, Some(128));
    }

    /// A required field left unset is named, never defaulted into an empty
    /// path that would boot something other than what the caller asked for.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = VmStartParams::builder().build() else {
            panic!("an empty VmStartParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("VmStartParams", "name"));
    }

    // Regression: `VmStartParams` previously carried no egress policy, so
    // `into_start_config()` fell through to `VmStartConfig::default()` =
    // deny-all for every boot — silently ignoring `--net` / `--allow-host`.
    // The resolved policy must survive the conversion so the
    // backend (Firecracker nftables; the libkrun/HVF gateway bridge) enforces
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
