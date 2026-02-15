use anyhow::{Context, Result};
use mvm_core::template::{TemplateSpec, template_dir, template_spec_path};

use crate::build_env::RuntimeBuildEnv;
use crate::shell;
use crate::vm::pool::artifacts as pool_artifacts;
use crate::vm::pool::lifecycle as pool_lifecycle;
use crate::vm::tenant::lifecycle as tenant_lifecycle;
use mvm_build::build::{PoolBuildOpts, pool_build_with_opts};
use mvm_core::pool::{InstanceResources, Role, pool_artifacts_dir};
use mvm_core::template::{TemplateRevision, template_current_symlink, template_revision_dir};
use mvm_core::tenant::{TenantNet, TenantQuota};
use mvm_core::time::utc_now;

pub fn template_create(spec: &TemplateSpec) -> Result<()> {
    let dir = template_dir(&spec.template_id);
    shell::run_in_vm(&format!("mkdir -p {dir}"))?;
    let path = template_spec_path(&spec.template_id);
    let json = serde_json::to_string_pretty(spec)?;
    shell::run_in_vm(&format!("cat > {path} << 'MVMEOF'\n{json}\nMVMEOF"))?;
    Ok(())
}

pub fn template_load(id: &str) -> Result<TemplateSpec> {
    let path = template_spec_path(id);
    let data = shell::run_in_vm_stdout(&format!("cat {path}"))
        .with_context(|| format!("Failed to load template {}", id))?;
    let spec: TemplateSpec =
        serde_json::from_str(&data).with_context(|| format!("Corrupt template {}", id))?;
    Ok(spec)
}

pub fn template_list() -> Result<Vec<String>> {
    let out = shell::run_in_vm_stdout("ls -1 /var/lib/mvm/templates 2>/dev/null || true")?
        .trim()
        .to_string();
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect())
}

pub fn template_delete(id: &str, force: bool) -> Result<()> {
    let dir = template_dir(id);
    let flag = if force { "-rf" } else { "-r" };
    shell::run_in_vm(&format!("rm {flag} {dir}"))?;
    Ok(())
}

/// Initialize an on-disk template directory layout (empty artifacts, no spec).
/// Safe to call multiple times; existing contents are preserved.
pub fn template_init(id: &str) -> Result<()> {
    let dir = template_dir(id);
    let artifacts = format!("{}/artifacts/revisions", dir);
    shell::run_in_vm(&format!("mkdir -p {dir} {artifacts}"))?;
    Ok(())
}

fn parse_role(role: &str) -> Role {
    match role {
        "gateway" => Role::Gateway,
        "builder" => Role::Builder,
        "capability-imessage" => Role::CapabilityImessage,
        _ => Role::Worker,
    }
}

/// Build a template by reusing the existing pool build pipeline under a special internal tenant.
/// Artifacts are copied into /var/lib/mvm/templates/<id>/artifacts and the current symlink is updated.
pub fn template_build(id: &str, force: bool) -> Result<()> {
    let spec = template_load(id)?;

    // Ensure internal tenant exists (isolated, no real users)
    // Internal tenant used for building templates; must satisfy naming rules.
    const TEMPLATE_TENANT: &str = "templates";
    if !tenant_lifecycle::tenant_exists(TEMPLATE_TENANT)? {
        let net = TenantNet::new(4095, "10.254.0.0/24", "10.254.0.1");
        tenant_lifecycle::tenant_create(TEMPLATE_TENANT, net, TenantQuota::default())?;
    }

    // Ensure pool spec is present under the internal tenant
    let resources = InstanceResources {
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        data_disk_mib: spec.data_disk_mib,
    };
    // Overwrite/create the pool spec each build to keep in sync
    let _ = pool_lifecycle::pool_create(
        TEMPLATE_TENANT,
        &spec.template_id,
        &spec.flake_ref,
        &spec.profile,
        resources,
        parse_role(&spec.role),
        id,
    )?;

    // Build via existing pipeline
    let env = RuntimeBuildEnv;
    let opts = PoolBuildOpts {
        force_rebuild: force,
        ..Default::default()
    };
    pool_build_with_opts(&env, TEMPLATE_TENANT, &spec.template_id, opts)?;

    // Resolve current revision hash from the internal pool
    let current_rev = pool_artifacts::current_revision(TEMPLATE_TENANT, &spec.template_id)?
        .context("Template build produced no revision")?;
    let pool_artifacts = pool_artifacts_dir(TEMPLATE_TENANT, &spec.template_id);

    // Copy artifacts into template path
    let rev_dst = template_revision_dir(id, &current_rev);
    let rev_src = format!("{}/revisions/{}", pool_artifacts, current_rev);
    shell::run_in_vm(&format!(
        "mkdir -p {} && cp -a {}/* {}",
        rev_dst, rev_src, rev_dst
    ))?;

    // Update template current symlink
    let current_link = template_current_symlink(id);
    shell::run_in_vm(&format!(
        "ln -snf revisions/{} {}",
        current_rev, current_link
    ))?;

    // Record template revision metadata
    let lock_hash = shell::run_in_vm_stdout(&format!(
        "cat {}/last_flake_lock.hash 2>/dev/null || echo ''",
        pool_artifacts
    ))?;
    let flake_lock_hash = lock_hash.trim();
    let revision = TemplateRevision {
        revision_hash: current_rev.clone(),
        flake_ref: spec.flake_ref.clone(),
        flake_lock_hash: if flake_lock_hash.is_empty() {
            current_rev.clone()
        } else {
            flake_lock_hash.to_string()
        },
        artifact_paths: mvm_core::pool::ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
        },
        built_at: utc_now(),
        profile: spec.profile.clone(),
        role: spec.role.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        data_disk_mib: spec.data_disk_mib,
    };
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{}/revision.json", rev_dst);
    shell::run_in_vm(&format!(
        "cat > {rev_meta_path} << 'MVMEOF'\n{rev_json}\nMVMEOF"
    ))?;

    Ok(())
}
