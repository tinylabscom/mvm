use anyhow::Result;
use std::env;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::naming;
use mvm_core::pool::{ArtifactPaths, BuildRevision, pool_artifacts_dir};
use mvm_core::time::utc_now;

use crate::artifacts::ensure_builder_artifacts;
use crate::backend::host::HostBackend;
use crate::backend::ssh::SshBackend;
use crate::backend::vsock::VsockBackend;
use crate::backend::{BackendParams, BuilderBackend};
use crate::build::{
    DEFAULT_TIMEOUT_SECS, PoolBuildOpts, builder_instance_net, record_build_history,
};
use crate::cache::maybe_skip_by_lock_hash;
use crate::template_reuse::reuse_template_artifacts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BuilderMode {
    /// Run `nix build` directly on the host. Default mode.
    Host,
    /// Boot an FC builder VM and communicate via vsock.
    Vsock,
    /// Boot an FC builder VM and communicate via SSH.
    Ssh,
    /// Try vsock first, fall back to SSH (FC-based).
    Auto,
}

fn builder_mode() -> BuilderMode {
    match env::var("MVM_BUILDER_MODE")
        .unwrap_or_else(|_| "host".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "vsock" => BuilderMode::Vsock,
        "ssh" => BuilderMode::Ssh,
        "auto" => BuilderMode::Auto,
        _ => BuilderMode::Host,
    }
}

/// Build artifacts for a pool. Default mode runs `nix build` on the host.
/// Set `MVM_BUILDER_MODE=vsock|ssh|auto` to use FC-based builders instead.
pub fn pool_build(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    let opts = PoolBuildOpts {
        timeout_secs,
        builder_vcpus: None,
        builder_mem_mib: None,
        force_rebuild: false,
    };
    pool_build_with_opts(env, tenant_id, pool_id, opts)
}

/// Build artifacts for a pool with optional resource overrides.
pub fn pool_build_with_opts(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    opts: PoolBuildOpts,
) -> Result<()> {
    let timeout = opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let spec = env.load_pool_spec(tenant_id, pool_id)?;
    let tenant = env.load_tenant_config(tenant_id)?;

    env.log_info(&format!(
        "Building {}/{} (flake: {}, profile: {})",
        tenant_id, pool_id, spec.flake_ref, spec.profile
    ));

    // Fast path: if the pool references a template, reuse its artifacts.
    if !spec.template_id.is_empty()
        && reuse_template_artifacts(
            env,
            &spec.template_id,
            tenant_id,
            pool_id,
            opts.force_rebuild,
        )?
    {
        env.log_success(&format!(
            "Reused template '{}' artifacts for {}/{}",
            spec.template_id, tenant_id, pool_id
        ));
        return Ok(());
    }

    if !opts.force_rebuild && maybe_skip_by_lock_hash(env, tenant_id, pool_id, &spec.flake_ref)? {
        return Ok(());
    }

    let mode = builder_mode();

    // FC-based builders need rootfs/kernel artifacts and a tenant bridge.
    let needs_fc = matches!(
        mode,
        BuilderMode::Vsock | BuilderMode::Ssh | BuilderMode::Auto
    );
    if needs_fc {
        ensure_builder_artifacts(env, mode != BuilderMode::Vsock)?;
        env.ensure_bridge(&tenant.net)?;
    }

    // Create a unique build ID for this run.
    let build_id = naming::generate_instance_id().replace("i-", "b-");
    let build_run_dir = format!("{}/run/{}", crate::build::BUILDER_DIR, build_id);
    env.shell_exec(&format!("mkdir -p {}", build_run_dir))?;

    env.log_info(&format!("Build ID: {}", build_id));

    // The build pipeline uses a per-build run directory. Always clean it up, even on failures.
    let build_result: Result<()> = (|| {
        let builder_net = builder_instance_net(&tenant.net);
        let params = BackendParams {
            build_run_dir: &build_run_dir,
            builder_net: &builder_net,
            tenant_net: &tenant.net,
            spec: &spec,
            timeout,
            opts: &opts,
            tenant_id,
            pool_id,
        };

        let backend_result = match mode {
            BuilderMode::Host => {
                env.log_info("Builder backend: host");
                let mut backend = HostBackend::new(params);
                let result: Result<_> = (|| {
                    backend.prepare(env)?;
                    backend.boot(env)?;
                    backend.build(env)?;
                    backend.extract_artifacts(env)
                })();
                let _ = backend.teardown(env);
                result?
            }
            BuilderMode::Vsock | BuilderMode::Auto => {
                env.log_info("Builder backend: vsock");
                let mut vsock_backend = VsockBackend::new(BackendParams {
                    build_run_dir: &build_run_dir,
                    builder_net: &builder_net,
                    tenant_net: &tenant.net,
                    spec: &spec,
                    timeout,
                    opts: &opts,
                    tenant_id,
                    pool_id,
                });
                let vsock_result: Result<_> = (|| {
                    vsock_backend.prepare(env)?;
                    vsock_backend.boot(env)?;
                    vsock_backend.build(env)?;
                    vsock_backend.extract_artifacts(env)
                })();
                let _ = vsock_backend.teardown(env);

                match (mode, vsock_result) {
                    (_, Ok(result)) => result,
                    (BuilderMode::Vsock, Err(e)) => return Err(e),
                    (BuilderMode::Auto, Err(e)) => {
                        env.log_warn(&format!("vsock build failed, falling back to SSH: {}", e));
                        env.log_info("Builder backend: ssh (fallback)");
                        let mut ssh_backend = SshBackend::new(BackendParams {
                            build_run_dir: &build_run_dir,
                            builder_net: &builder_net,
                            tenant_net: &tenant.net,
                            spec: &spec,
                            timeout,
                            opts: &opts,
                            tenant_id,
                            pool_id,
                        });
                        let ssh_result: Result<_> = (|| {
                            ssh_backend.prepare(env)?;
                            ssh_backend.boot(env)?;
                            ssh_backend.build(env)?;
                            ssh_backend.extract_artifacts(env)
                        })();
                        let _ = ssh_backend.teardown(env);
                        ssh_result?
                    }
                    _ => unreachable!(),
                }
            }
            BuilderMode::Ssh => {
                env.log_info("Builder backend: ssh");
                let mut ssh_backend = SshBackend::new(params);
                let ssh_result: Result<_> = (|| {
                    ssh_backend.prepare(env)?;
                    ssh_backend.boot(env)?;
                    ssh_backend.build(env)?;
                    ssh_backend.extract_artifacts(env)
                })();
                let _ = ssh_backend.teardown(env);
                ssh_result?
            }
        };
        let revision_hash = backend_result.revision_hash;
        let lock_hash = backend_result.lock_hash;

        // Inject the mvm guest agent into the rootfs.
        let rev_dir = format!(
            "{}/revisions/{}",
            pool_artifacts_dir(tenant_id, pool_id),
            revision_hash
        );
        let rootfs_path = format!("{}/rootfs.ext4", rev_dir);
        crate::guest_agent::ensure_guest_agent(env, &rootfs_path)?;

        // Record revision.
        let revision = BuildRevision {
            revision_hash: revision_hash.clone(),
            flake_ref: spec.flake_ref.clone(),
            flake_lock_hash: lock_hash.clone().unwrap_or_else(|| revision_hash.clone()),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".to_string(),
                rootfs: "rootfs.ext4".to_string(),
                fc_base_config: "fc-base.json".to_string(),
            },
            built_at: utc_now(),
        };

        env.record_revision(tenant_id, pool_id, &revision)?;
        record_build_history(env, tenant_id, pool_id, &revision)?;

        if let Some(hash) = lock_hash {
            let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
            let lock_hash_path = format!("{}/last_flake_lock.hash", artifacts_dir);
            env.shell_exec(&format!(
                "mkdir -p {dir} && echo '{hash}' > {path}",
                dir = artifacts_dir,
                hash = hash,
                path = lock_hash_path
            ))?;
        }

        env.log_success(&format!(
            "Build complete: {}/{} revision {}",
            tenant_id, pool_id, revision_hash
        ));

        Ok(())
    })();

    let _ = env.shell_exec(&format!("rm -rf {}", build_run_dir));

    build_result
}
