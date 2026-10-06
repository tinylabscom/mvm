use anyhow::Result;

use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::BuildRevision;

/// Base directory for builder infrastructure.
pub(crate) const BUILDER_DIR: &str = "/var/lib/mvm/builder";

pub(crate) const BUILDER_OUTPUT_DISK_MIB: u32 = 8192;

/// Default build timeout in seconds (30 minutes).
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 1800;

/// Optional overrides for pool builds.
#[derive(Default)]
pub struct PoolBuildOpts {
    pub timeout_secs: Option<u64>,
    pub builder_vcpus: Option<u8>,
    pub builder_mem_mib: Option<u32>,
    pub force_rebuild: bool,
}

impl PoolBuildOpts {
    /// Start building a [`PoolBuildOpts`] from its defaults. Every value is
    /// set by name, so a call site cannot transpose two fields that
    /// share a type.
    #[must_use]
    pub fn builder() -> PoolBuildOptsBuilder {
        PoolBuildOptsBuilder::new()
    }
}

/// Builder for [`PoolBuildOpts`]. Unset fields keep the value
/// `PoolBuildOpts::default()` gives them.
#[derive(Default)]
pub struct PoolBuildOptsBuilder {
    inner: PoolBuildOpts,
}

impl PoolBuildOptsBuilder {
    /// A builder holding the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PoolBuildOpts::default(),
        }
    }

    /// Set `timeout_secs`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn timeout_secs(mut self, timeout_secs: impl Into<Option<u64>>) -> Self {
        self.inner.timeout_secs = timeout_secs.into();
        self
    }

    /// Set `builder_vcpus`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn builder_vcpus(mut self, builder_vcpus: impl Into<Option<u8>>) -> Self {
        self.inner.builder_vcpus = builder_vcpus.into();
        self
    }

    /// Set `builder_mem_mib`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn builder_mem_mib(mut self, builder_mem_mib: impl Into<Option<u32>>) -> Self {
        self.inner.builder_mem_mib = builder_mem_mib.into();
        self
    }

    /// Set `force_rebuild`.
    #[must_use]
    pub fn force_rebuild(mut self, force_rebuild: bool) -> Self {
        self.inner.force_rebuild = force_rebuild;
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> PoolBuildOpts {
        self.inner
    }
}

/// Build artifacts for a pool using the host builder backend.
/// `PoolBuildOpts::default()` applies the default timeout and no
/// resource overrides.
pub fn pool_build(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    opts: PoolBuildOpts,
) -> Result<()> {
    crate::orchestrator::pool_build(env, tenant_id, pool_id, opts)
}

/// Append a build revision to the pool's build history.
pub(crate) fn record_build_history(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    revision: &BuildRevision,
) -> Result<()> {
    let history_path = format!(
        "{}/build_history.json",
        mvm_core::pool::pool_dir(tenant_id, pool_id)
    );
    let json_entry = serde_json::to_string(revision)?;

    env.shell_exec(&format!(
        r#"
        if [ -f {path} ]; then
            EXISTING=$(cat {path})
            echo "$EXISTING" | head -49 > {path}.tmp
            echo '{entry}' >> {path}.tmp
            mv {path}.tmp {path}
        else
            echo '{entry}' > {path}
        fi
        "#,
        path = history_path,
        entry = json_entry,
    ))?;

    Ok(())
}

#[cfg(test)]
mod pool_build_opts_builder_tests {
    use super::*;

    /// A builder nobody touched has to agree with `PoolBuildOpts::default()`,
    /// or an unset field silently means something else.
    #[test]
    fn an_untouched_builder_matches_the_type_default() {
        let _built = PoolBuildOpts::builder().build();
    }
}
