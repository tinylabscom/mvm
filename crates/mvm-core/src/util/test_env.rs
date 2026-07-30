// The one `unsafe` carve-out under the crate's `deny(unsafe_code)`: this module
// centralizes the process-wide env mutation Rust 2024 marks unsafe, serialized
// behind `ENV_LOCK` and restored on drop.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Process-wide environment guard for tests.
///
/// Rust 2024 makes environment mutation unsafe because it races with other
/// threads. Tests that need env overrides should hold one guard per test and
/// let `Drop` restore the previous values.
pub struct TestEnv {
    _guard: MutexGuard<'static, ()>,
    saved: Vec<(OsString, Option<OsString>)>,
}

impl TestEnv {
    pub fn new() -> Self {
        Self {
            _guard: ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            saved: Vec::new(),
        }
    }

    pub fn set<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let key = key.as_ref();
        self.save_once(key);
        // SAFETY: all project tests that use this helper serialize process-wide
        // env mutation behind ENV_LOCK and restore the previous value on drop.
        unsafe { std::env::set_var(key, value) };
    }

    /// Point the whole mvm world at `root`: sets `MVM_HOME` **and** `HOME`.
    ///
    /// `MVM_HOME` on its own does not isolate a test. A few resolvers
    /// deliberately ignore it and read `$HOME/.mvm/cache` directly so an
    /// isolated session can seed expensive artifacts — the builder VM image,
    /// the runtime overlay — from the host's shared cache instead of
    /// rebuilding them. That seed is correct for real use and wrong under
    /// test: a test that moves only `MVM_HOME` still reads the developer's
    /// real cache through it, so an assertion that an artifact is *absent*
    /// holds only on a machine that has never built one. CI is such a
    /// machine and a contributor's laptop is not, which is how a green
    /// suite ends up hiding a live regression.
    pub fn isolate_mvm_home<V>(&mut self, root: V)
    where
        V: AsRef<OsStr>,
    {
        let root = root.as_ref();
        self.set("MVM_HOME", root);
        self.set("HOME", root);
    }

    pub fn remove<K>(&mut self, key: K)
    where
        K: AsRef<OsStr>,
    {
        let key = key.as_ref();
        self.save_once(key);
        // SAFETY: all project tests that use this helper serialize process-wide
        // env mutation behind ENV_LOCK and restore the previous value on drop.
        unsafe { std::env::remove_var(key) };
    }

    fn save_once(&mut self, key: &OsStr) {
        if self.saved.iter().any(|(saved, _)| saved == key) {
            return;
        }
        self.saved.push((key.to_os_string(), std::env::var_os(key)));
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, value) in self.saved.iter().rev() {
            match value {
                Some(value) => {
                    // SAFETY: TestEnv still holds ENV_LOCK while restoring the
                    // process-wide environment to its pre-test state.
                    unsafe { std::env::set_var(key, value) };
                }
                None => {
                    // SAFETY: TestEnv still holds ENV_LOCK while restoring the
                    // process-wide environment to its pre-test state.
                    unsafe { std::env::remove_var(key) };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TestEnv;

    fn unique_key(suffix: &str) -> String {
        format!("MVM_TEST_ENV_GUARD_{suffix}_{}", std::process::id())
    }

    #[test]
    fn restores_missing_var_after_set() {
        let key = unique_key("MISSING_AFTER_SET");

        {
            let mut env = TestEnv::new();
            env.remove(&key);
        }
        {
            let mut env = TestEnv::new();
            env.set(&key, "value");
            assert_eq!(std::env::var(&key).as_deref(), Ok("value"));
        }

        assert!(std::env::var_os(&key).is_none());
    }

    #[test]
    fn restores_previous_value_after_remove() {
        let key = unique_key("PREVIOUS_AFTER_REMOVE");

        // SAFETY: this test uses a process-unique variable name and immediately
        // hands subsequent mutation to TestEnv, which serializes and restores it.
        unsafe { std::env::set_var(&key, "before") };
        {
            let mut env = TestEnv::new();
            env.remove(&key);
            assert!(std::env::var_os(&key).is_none());
        }

        assert_eq!(std::env::var(&key).as_deref(), Ok("before"));
        // SAFETY: cleanup for the same process-unique variable used by this test.
        unsafe { std::env::remove_var(&key) };
    }

    #[test]
    fn isolate_mvm_home_sets_both_roots_and_restores_them() {
        let before_home = std::env::var_os("HOME");
        let before_mvm_home = std::env::var_os("MVM_HOME");
        let root = "/tmp/mvm-test-env-isolate-both";

        {
            let mut env = TestEnv::new();
            env.isolate_mvm_home(root);
            assert_eq!(std::env::var("MVM_HOME").as_deref(), Ok(root));
            // The whole point: HOME moves too, so the MVM_HOME-ignoring
            // default-cache resolvers cannot reach the real one.
            assert_eq!(std::env::var("HOME").as_deref(), Ok(root));
        }

        assert_eq!(std::env::var_os("MVM_HOME"), before_mvm_home);
        assert_eq!(std::env::var_os("HOME"), before_home);
    }

    #[test]
    fn saves_original_value_once() {
        let key = unique_key("SAVE_ONCE");

        {
            let mut env = TestEnv::new();
            env.set(&key, "first");
            env.set(&key, "second");
            assert_eq!(std::env::var(&key).as_deref(), Ok("second"));
        }

        assert!(std::env::var_os(&key).is_none());
    }
}
