//! Registry/runtime convergence pass behind `mvmctl reconcile`.

pub use mvm_runtime::vm::reconcile::ConvergeReport;
use mvm_runtime::vm::reconcile::{self, ConvergeOpts};

/// Heal registry/runtime drift, or with `dry_run` only report it.
pub fn converge(dry_run: bool) -> ConvergeReport {
    reconcile::converge(&ConvergeOpts { dry_run })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn an_empty_registry_converges_clean() {
        let temp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(temp.path());
        assert!(converge(true).is_clean());
    }
}
