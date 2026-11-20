//! Lifetime-owned isolation for audit fixtures that use one directory.

use std::path::Path;

pub(super) struct AuditDir {
    dir: tempfile::TempDir,
    _env: mvm_core::util::test_env::TestEnv,
}

impl AuditDir {
    pub(super) fn new() -> Self {
        // Explicit audit roots still classify directories against MVM_HOME.
        let env = mvm_core::util::test_env::TestEnv::new();
        Self {
            dir: tempfile::tempdir().expect("audit fixture directory"),
            _env: env,
        }
    }

    pub(super) fn path(&self) -> &Path {
        self.dir.path()
    }
}
