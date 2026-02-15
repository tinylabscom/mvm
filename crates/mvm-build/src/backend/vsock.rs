use anyhow::{Result, anyhow};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::pool::PoolSpec;
use mvm_core::tenant::TenantNet;

use super::{BackendBuildResult, BackendParams, BuilderBackend};
use crate::artifacts::extract_artifacts_from_output_disk;
use crate::build::{
    BUILDER_OUTPUT_DISK_MIB, BUILDER_VCPUS, PoolBuildOpts, create_builder_input_disk,
    create_builder_output_disk,
};
use crate::firecracker::{boot_builder_vsock, teardown_builder};
use crate::vsock_builder::build_via_vsock;

pub(crate) struct VsockBackend<'a> {
    pub(crate) build_run_dir: &'a str,
    pub(crate) builder_net: &'a InstanceNet,
    pub(crate) tenant_net: &'a TenantNet,
    pub(crate) spec: &'a PoolSpec,
    pub(crate) timeout: u64,
    pub(crate) opts: &'a PoolBuildOpts,
    pub(crate) tenant_id: &'a str,
    pub(crate) pool_id: &'a str,
    builder_pid: Option<u32>,
    out_disk: Option<String>,
    in_disk: Option<String>,
    vsock_uds: Option<String>,
}

impl<'a> VsockBackend<'a> {
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
            out_disk: None,
            in_disk: None,
            vsock_uds: None,
        }
    }
}

impl BuilderBackend for VsockBackend<'_> {
    fn prepare(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let out_disk = create_builder_output_disk(self.build_run_dir, BUILDER_OUTPUT_DISK_MIB);
        let in_disk = create_builder_input_disk(env, self.build_run_dir, &self.spec.flake_ref)?;
        let vsock_uds = format!("{}/v.sock", self.build_run_dir);
        self.out_disk = Some(out_disk);
        self.in_disk = in_disk;
        self.vsock_uds = Some(vsock_uds);
        Ok(())
    }

    fn boot(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let out_disk = self
            .out_disk
            .as_deref()
            .ok_or_else(|| anyhow!("missing out disk before vsock boot"))?;
        let vsock_uds = self
            .vsock_uds
            .as_deref()
            .ok_or_else(|| anyhow!("missing vsock uds before boot"))?;
        let pid = boot_builder_vsock(
            env,
            self.build_run_dir,
            self.builder_net,
            self.tenant_net,
            self.opts.builder_vcpus.unwrap_or(BUILDER_VCPUS),
            self.opts
                .builder_mem_mib
                .unwrap_or(crate::build::BUILDER_MEM_MIB),
            out_disk,
            self.in_disk.as_deref(),
            vsock_uds,
        )?;
        self.builder_pid = Some(pid);
        Ok(())
    }

    fn build(&mut self, _env: &dyn BuildEnvironment) -> Result<()> {
        let system = if cfg!(target_arch = "aarch64") {
            "aarch64-linux"
        } else {
            "x86_64-linux"
        };
        let attr = format!(
            "packages.{system}.tenant-{}-{}",
            self.spec.role, self.spec.profile
        );
        let flake_ref = if self.in_disk.is_some() {
            "/build-in"
        } else {
            &self.spec.flake_ref
        };
        let vsock_uds = self
            .vsock_uds
            .as_deref()
            .ok_or_else(|| anyhow!("missing vsock uds before build"))?;
        build_via_vsock(vsock_uds, flake_ref, &attr, self.timeout)?;
        Ok(())
    }

    fn extract_artifacts(&mut self, env: &dyn BuildEnvironment) -> Result<BackendBuildResult> {
        let out_disk = self
            .out_disk
            .as_deref()
            .ok_or_else(|| anyhow!("missing out disk before extract"))?;
        let revision_hash =
            extract_artifacts_from_output_disk(env, out_disk, self.tenant_id, self.pool_id)?;
        Ok(BackendBuildResult {
            revision_hash,
            lock_hash: None,
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
