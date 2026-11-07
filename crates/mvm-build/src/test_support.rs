//! Process isolation for tests that require control of descriptor lifetimes.

pub(crate) use mvm_core::util::test_env::isolated_lock_probe;
