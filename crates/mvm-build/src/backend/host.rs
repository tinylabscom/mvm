use std::collections::BTreeMap;

use anyhow::{Result, anyhow};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::{PoolSpec, pool_artifacts_dir};

use super::{BackendBuildResult, BackendParams, BuilderBackend};
use crate::nix_manifest::NixManifest;
use crate::scripts::render_script;

/// Host backend: runs `nix build` directly on the host (Lima VM or bare metal).
///
/// No Firecracker builder VM is needed. This is faster and avoids the networking
/// complexity of FC-based builds while still producing the same artifacts
/// (kernel + rootfs) that run inside Firecracker microVMs at runtime.
pub(crate) struct HostBackend<'a> {
    pub(crate) build_run_dir: &'a str,
    pub(crate) spec: &'a PoolSpec,
    pub(crate) timeout: u64,
    pub(crate) tenant_id: &'a str,
    pub(crate) pool_id: &'a str,
    nix_output_path: Option<String>,
    lock_hash: Option<String>,
}

impl<'a> HostBackend<'a> {
    pub(crate) fn new(params: BackendParams<'a>) -> Self {
        Self {
            build_run_dir: params.build_run_dir,
            spec: params.spec,
            timeout: params.timeout,
            tenant_id: params.tenant_id,
            pool_id: params.pool_id,
            nix_output_path: None,
            lock_hash: None,
        }
    }
}

fn resolve_build_attribute_host(
    env: &dyn BuildEnvironment,
    flake_ref: &str,
    role: &mvm_core::pool::Role,
    profile: &str,
) -> String {
    let system = if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    };

    // Read mvm-profiles.toml directly from the flake directory (no SSH needed).
    let manifest_path = format!("{}/mvm-profiles.toml", flake_ref);
    let manifest_check = env.shell_exec_stdout(&format!(
        "cat {} 2>/dev/null || echo __NOT_FOUND__",
        manifest_path
    ));

    if let Ok(content) = manifest_check
        && !content.contains("__NOT_FOUND__")
        && let Ok(manifest) = NixManifest::from_toml(&content)
        && manifest.resolve(role, profile).is_ok()
    {
        let attr = format!(
            "{}#packages.{}.tenant-{}-{}",
            flake_ref, system, role, profile
        );
        env.log_info(&format!(
            "Manifest found, using role-aware attribute: {}",
            attr
        ));
        return attr;
    }

    let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, profile);
    env.log_info(&format!(
        "No manifest found, using legacy attribute: {}",
        attr
    ));
    attr
}

impl BuilderBackend for HostBackend<'_> {
    fn prepare(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        // Verify nix is available on the host.
        env.shell_exec("command -v nix >/dev/null 2>&1")
            .map_err(|_| anyhow!("nix not found on host; install Nix to use host builder mode"))?;
        env.shell_exec(&format!("mkdir -p {}", self.build_run_dir))?;
        Ok(())
    }

    fn boot(&mut self, _env: &dyn BuildEnvironment) -> Result<()> {
        // No VM to boot — we run directly on the host.
        Ok(())
    }

    fn build(&mut self, env: &dyn BuildEnvironment) -> Result<()> {
        let attr = resolve_build_attribute_host(
            env,
            &self.spec.flake_ref,
            &self.spec.role,
            &self.spec.profile,
        );

        env.log_info(&format!("Running: nix build {}", attr));

        let log_path = format!("{}/nix-build.log", self.build_run_dir);

        // Compute flake lock hash for cache tracking.
        let lock_path = format!("{}/flake.lock", self.spec.flake_ref);
        self.lock_hash = env
            .shell_exec_stdout(&format!(
                "sha256sum {} 2>/dev/null | cut -d' ' -f1",
                lock_path
            ))
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());

        let mut ctx = BTreeMap::new();
        ctx.insert("timeout", self.timeout.to_string());
        ctx.insert("attr", attr.clone());
        ctx.insert("log", log_path.clone());

        if let Err(build_err) = env.shell_exec_visible(&render_script("run_nix_build_host", &ctx)?)
        {
            let log_tail = env
                .shell_exec_stdout(&format!("tail -50 {} 2>/dev/null || true", log_path))
                .unwrap_or_default();
            let log_tail = log_tail.trim();
            if log_tail.is_empty() {
                return Err(build_err.context(format!("nix build failed for {}", attr)));
            }
            return Err(build_err.context(format!(
                "nix build failed for {}. Build output (last 50 lines):\n{}",
                attr, log_tail
            )));
        }

        let output = env.shell_exec_stdout(&format!("cat {} 2>/dev/null", log_path))?;
        let out_path = output
            .lines()
            .rev()
            .find(|l| l.starts_with("/nix/store/"))
            .ok_or_else(|| anyhow!("nix build did not produce an output path"))?
            .to_string();

        env.log_info(&format!("Build output: {}", out_path));
        self.nix_output_path = Some(out_path);
        Ok(())
    }

    fn extract_artifacts(&mut self, env: &dyn BuildEnvironment) -> Result<BackendBuildResult> {
        let nix_output_path = self
            .nix_output_path
            .as_deref()
            .ok_or_else(|| anyhow!("missing nix output path before extract"))?;

        let revision_hash = nix_output_path
            .strip_prefix("/nix/store/")
            .and_then(|s| s.split('-').next())
            .unwrap_or("unknown")
            .to_string();

        let artifacts_dir = pool_artifacts_dir(self.tenant_id, self.pool_id);
        let rev_dir = format!("{}/revisions/{}", artifacts_dir, revision_hash);
        env.shell_exec(&format!("mkdir -p {}", rev_dir))?;

        let mut ctx = BTreeMap::new();
        ctx.insert("out_path", nix_output_path.to_string());
        ctx.insert("rev_dir", rev_dir.clone());
        env.shell_exec_visible(&render_script("extract_artifacts_host", &ctx)?)?;

        Ok(BackendBuildResult {
            revision_hash,
            lock_hash: self.lock_hash.clone(),
        })
    }

    fn teardown(&mut self, _env: &dyn BuildEnvironment) -> Result<()> {
        // Nothing to tear down — no VM, no TAP, no bridge.
        Ok(())
    }
}
