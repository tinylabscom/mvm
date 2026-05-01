use anyhow::Result;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::pool_artifacts_dir;
use mvm_core::template::{TemplateRevision, template_current_symlink, template_revision_dir};

/// Attempt to reuse artifacts from a global template. Returns true if reused.
pub(crate) fn reuse_template_artifacts(
    env: &dyn BuildEnvironment,
    template_id: &str,
    tenant_id: &str,
    pool_id: &str,
    force_rebuild: bool,
) -> Result<bool> {
    if force_rebuild {
        // If forcing rebuild, skip reuse so caller proceeds to full build.
        return Ok(false);
    }

    let current_link = template_current_symlink(template_id);
    let has_current = env
        .shell_exec_stdout(&format!("test -L {current_link} && echo yes || echo no"))?
        .trim()
        .to_string();
    if has_current != "yes" {
        return Ok(false);
    }

    let rel = env.shell_exec_stdout(&format!("readlink {current_link}"))?;
    let rel = rel.trim();
    let rev = rel.strip_prefix("revisions/").unwrap_or(rel);
    if rev.is_empty() {
        return Ok(false);
    }

    let src = template_revision_dir(template_id, rev);
    let dst_root = pool_artifacts_dir(tenant_id, pool_id);
    let dst = format!("{}/revisions/{}", dst_root, rev);

    // Verify compatibility using revision metadata
    let meta_json = env.shell_exec_stdout(&format!("cat {}/revision.json", src))?;
    let rev_meta: TemplateRevision = serde_json::from_str(&meta_json)?;
    let spec = env.load_pool_spec(tenant_id, pool_id)?;

    // Build-identity check: profile + flake.lock must match (via composite cache key).
    // Build a pool-side "expected" cache key from the pool spec and the template's
    // flake_lock_hash. Plan 38 dropped `role` from this key: role-shaped flake
    // variants now live behind the flake's profile selector or its passthru, not
    // in the host-side cache identity.
    let pool_cache_key = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(rev_meta.flake_lock_hash.as_bytes());
        h.update(b":");
        h.update(spec.profile.as_bytes());
        format!("{:x}", h.finalize())
    };
    if rev_meta.cache_key() != pool_cache_key {
        env.log_warn("Template cache key mismatch (profile/flake.lock); skipping reuse");
        return Ok(false);
    }

    // Resource compatibility: pool may request different vCPU/mem sizing than the template.
    if rev_meta.vcpus != spec.instance_resources.vcpus
        || rev_meta.mem_mib != spec.instance_resources.mem_mib
        || rev_meta.data_disk_mib != spec.instance_resources.data_disk_mib
    {
        env.log_warn("Template revision resource mismatch (vcpus/mem/disk); skipping reuse");
        return Ok(false);
    }
    if !spec.flake_ref.is_empty() && spec.flake_ref != rev_meta.flake_ref {
        env.log_warn("Template revision flake_ref differs; skipping reuse");
        return Ok(false);
    }

    env.shell_exec(&format!("mkdir -p {dst_root}/revisions"))?;
    env.shell_exec(&format!("rm -rf {dst}"))?;
    env.shell_exec(&format!("cp -a {src} {dst}"))?;
    env.shell_exec(&format!("ln -snf revisions/{rev} {dst_root}/current"))?;

    Ok(true)
}
