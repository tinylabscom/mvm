use anyhow::Result;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::pool_artifacts_dir;

use crate::shell_scripts;

pub(crate) fn maybe_skip_by_lock_hash(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    flake_ref: &str,
) -> Result<bool> {
    if flake_ref.contains(':') {
        return Ok(false); // remote ref: don't hash
    }

    let hash = match env.shell_exec_stdout(&shell_scripts::nix_hash_of_lock(flake_ref)) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    let trimmed = hash.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }

    let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
    let lock_hash_path = format!("{}/last_flake_lock.hash", artifacts_dir);
    let current_exists = env
        .shell_exec_stdout(&shell_scripts::test_link(&format!(
            "{artifacts_dir}/current"
        )))
        .unwrap_or_default();
    let existing = env
        .shell_exec_stdout(&shell_scripts::cat_or_echo(&lock_hash_path, ""))
        .unwrap_or_default();

    if current_exists.trim() == "yes" && existing.trim() == trimmed {
        env.log_success("flake.lock unchanged — skipping rebuild (cache hit)");
        return Ok(true);
    }

    Ok(false)
}
