use anyhow::Result;
use mvm_core::build_env::BuildEnvironment;
use mvm_core::pool::PoolSpec;

pub(crate) mod host;

#[derive(Debug, Clone)]
pub(crate) struct BackendBuildResult {
    pub(crate) revision_hash: String,
    pub(crate) lock_hash: Option<String>,
}

pub(crate) trait BuilderBackend {
    fn prepare(&mut self, env: &dyn BuildEnvironment) -> Result<()>;
    fn boot(&mut self, env: &dyn BuildEnvironment) -> Result<()>;
    fn build(&mut self, env: &dyn BuildEnvironment) -> Result<()>;
    fn extract_artifacts(&mut self, env: &dyn BuildEnvironment) -> Result<BackendBuildResult>;
    fn teardown(&mut self, env: &dyn BuildEnvironment) -> Result<()>;
}

pub(crate) struct BackendParams<'a> {
    pub(crate) build_run_dir: &'a str,
    pub(crate) spec: &'a PoolSpec,
    pub(crate) timeout: u64,
    pub(crate) tenant_id: &'a str,
    pub(crate) pool_id: &'a str,
}
