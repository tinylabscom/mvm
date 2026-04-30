//! Validate the `env` parameter of `tools/call run` against the
//! installed template registry.
//!
//! Stdio-only: this is the bridge between the wire protocol (which
//! accepts arbitrary strings) and the local template artifacts on
//! disk. Plan 33's hosted variant in mvmd implements its own
//! validator that resolves `tenant/pool/template@revision`.

use anyhow::Result;

/// Returns the list of template names known to mvmctl. Equivalent to
/// `mvmctl template list`. Used to validate incoming `env` values.
pub fn known_envs() -> Result<Vec<String>> {
    mvm_runtime::vm::template::lifecycle::template_list().map_err(Into::into)
}

/// Check that `env` is a known template. Returns `Ok(())` if so;
/// otherwise an error whose message lists the available envs (the
/// LLM gets to recover by re-issuing with a valid name).
pub fn validate_env(env: &str) -> Result<()> {
    let envs = known_envs()?;
    if envs.iter().any(|e| e == env) {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "env '{env}' is not a registered mvmctl template. \
         Available envs: [{}]. Build new ones via `mvmctl template create … && mvmctl template build <name>`.",
        envs.join(", ")
    ))
}
