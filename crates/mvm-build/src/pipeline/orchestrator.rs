use anyhow::{Result, bail};
use std::env;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::naming;
use mvm_core::pool::{ArtifactPaths, BuildRevision, pool_artifacts_dir};
use mvm_core::time::utc_now;

use crate::backend::host::HostBackend;
use crate::backend::{BackendParams, BuilderBackend};
use crate::build::{DEFAULT_TIMEOUT_SECS, PoolBuildOpts, record_build_history};
use crate::cache::maybe_skip_by_lock_hash;
use crate::template_reuse::reuse_template_artifacts;

fn validate_builder_mode(value: Option<&str>) -> Result<()> {
    match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("host") => Ok(()),
        Some("vsock" | "auto") => bail!(
            "MVM_BUILDER_MODE=vsock|auto is retired: the old Firecracker builder attached a TAP NIC"
        ),
        Some(other) => bail!("unsupported MVM_BUILDER_MODE={other}"),
    }
}

/// Build artifacts for a pool. Default mode runs `nix build` on the host;
/// `opts` carries the timeout and builder resource overrides.
#[tracing::instrument(skip_all, fields(tenant_id, pool_id))]
pub fn pool_build(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    opts: PoolBuildOpts,
) -> Result<()> {
    let mode = env::var("MVM_BUILDER_MODE").ok();
    validate_builder_mode(mode.as_deref())?;
    let timeout = opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let spec = env.load_pool_spec(tenant_id, pool_id)?;
    let _tenant = env.load_tenant_config(tenant_id)?;

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

    // Create a unique build ID for this run.
    let build_id = naming::generate_instance_id().replace("i-", "b-");
    let build_run_dir = format!("{}/run/{}", crate::build::BUILDER_DIR, build_id);
    env.shell_exec(&format!("mkdir -p {}", build_run_dir))?;

    env.log_info(&format!("Build ID: {}", build_id));

    // The build pipeline uses a per-build run directory. Always clean it up, even on failures.
    let build_result: Result<()> = (|| {
        let params = BackendParams {
            build_run_dir: &build_run_dir,
            spec: &spec,
            timeout,
            tenant_id,
            pool_id,
        };

        env.log_info("Builder backend: host");
        let mut backend = HostBackend::new(params);
        let result: Result<_> = (|| {
            backend.prepare(env)?;
            backend.boot(env)?;
            backend.build(env)?;
            backend.extract_artifacts(env)
        })();
        let _ = backend.teardown(env);
        let backend_result = result?;
        let revision_hash = backend_result.revision_hash;
        let lock_hash = backend_result.lock_hash;

        // Record revision.
        // Check if initrd was produced (NixOS guests generate one)
        let arts_dir = pool_artifacts_dir(tenant_id, pool_id);
        let rev_dir = format!("{}/revisions/{}", arts_dir, revision_hash);
        let has_initrd = env
            .shell_exec_stdout(&format!(
                "test -f {}/initrd && echo yes || echo no",
                rev_dir
            ))
            .map(|s| s.trim() == "yes")
            .unwrap_or(false);

        let revision = BuildRevision {
            revision_hash: revision_hash.clone(),
            flake_ref: spec.flake_ref.clone(),
            flake_lock_hash: lock_hash.clone().unwrap_or_else(|| revision_hash.clone()),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".to_string(),
                rootfs: "rootfs.ext4".to_string(),
                fc_base_config: "fc-base.json".to_string(),
                initrd: if has_initrd {
                    Some("initrd".to_string())
                } else {
                    None
                },
                sizes: None,
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

#[cfg(test)]
mod tests {
    use super::validate_builder_mode;

    #[test]
    fn retired_tap_builder_modes_fail_closed() {
        assert!(validate_builder_mode(None).is_ok());
        assert!(validate_builder_mode(Some("host")).is_ok());
        for mode in ["vsock", "AUTO", "unknown"] {
            assert!(validate_builder_mode(Some(mode)).is_err(), "{mode}");
        }
    }
}
