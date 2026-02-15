use anyhow::{Result, anyhow};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::pool::PoolSpec;
use mvm_core::tenant::TenantNet;

use super::{BackendBuildResult, BackendParams, BuilderBackend};
use crate::build::{
    PoolBuildOpts, builder_ssh_key_path, ensure_nix_installed, extract_artifacts, flake_lock_hash,
    run_nix_build, sync_local_flake_if_needed,
};
use crate::firecracker::{boot_builder, teardown_builder};

pub(crate) struct SshBackend<'a> {
    pub(crate) build_run_dir: &'a str,
    pub(crate) builder_net: &'a InstanceNet,
    pub(crate) tenant_net: &'a TenantNet,
    pub(crate) spec: &'a PoolSpec,
    pub(crate) timeout: u64,
    pub(crate) opts: &'a PoolBuildOpts,
    pub(crate) tenant_id: &'a str,
    pub(crate) pool_id: &'a str,
    builder_pid: Option<u32>,
    flake_ref: Option<String>,
    lock_hash: Option<String>,
    nix_output_path: Option<String>,
}

impl<'a> SshBackend<'a> {
    pub(crate) fn new(params: BackendParams<'a>) -> Self {
        Self {
            build_run_dir: params.build_run_dir,
            builder_net: params.builder_net,
            tenant_net: params.tenant_net,
            spec: params.spec,
            timeout: params.timeout,
            opts: params.opts,
            tenant_id: params.tenant_id,
            pool_id: params.pool_id,
            builder_pid: None,
            flake_ref: None,
            lock_hash: None,
            nix_output_path: None,
        }
    }
}

impl BuilderBackend for SshBackend<'_> {
    fn prepare(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        env.shell_exec(&format!("mkdir -p {}", self.build_run_dir))?;
        Ok(())
    }

    fn boot(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let pid = boot_builder(
            env,
            self.build_run_dir,
            self.builder_net,
            self.tenant_net,
            self.opts
                .builder_vcpus
                .unwrap_or(crate::build::BUILDER_VCPUS),
            self.opts
                .builder_mem_mib
                .unwrap_or(crate::build::BUILDER_MEM_MIB),
        )?;
        self.builder_pid = Some(pid);
        Ok(())
    }

    fn build(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let builder_key = builder_ssh_key_path();

        let synced_flake = sync_local_flake_if_needed(
            env,
            &self.builder_net.guest_ip,
            &builder_key,
            &self.spec.flake_ref,
        );
        let flake_ref = synced_flake
            .as_deref()
            .unwrap_or(&self.spec.flake_ref)
            .to_string();

        self.lock_hash = flake_lock_hash(env, &self.builder_net.guest_ip, &builder_key, &flake_ref);
        ensure_nix_installed(env, &self.builder_net.guest_ip, &builder_key)?;

        let nix_output_path = run_nix_build(
            env,
            &self.builder_net.guest_ip,
            &builder_key,
            &flake_ref,
            &self.spec.role,
            &self.spec.profile,
            self.timeout,
        )?;
        self.flake_ref = Some(flake_ref);
        self.nix_output_path = Some(nix_output_path);
        Ok(())
    }

    fn extract_artifacts(&mut self, env: &dyn BuildEnvironment) -> Result<BackendBuildResult> {
        let builder_key = builder_ssh_key_path();
        let nix_output_path = self
            .nix_output_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing nix output path before extract"))?;
        let revision_hash = extract_artifacts(
            env,
            &self.builder_net.guest_ip,
            &builder_key,
            nix_output_path,
            self.tenant_id,
            self.pool_id,
        )?;
        Ok(BackendBuildResult {
            revision_hash,
            lock_hash: self.lock_hash.clone(),
        })
    }

    fn teardown(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        if let Some(pid) = self.builder_pid {
            teardown_builder(env, pid, self.builder_net, self.build_run_dir)?;
            self.builder_pid = None;
        }
        Ok(())
    }
}
