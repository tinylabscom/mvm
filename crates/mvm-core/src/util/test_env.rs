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
    /// Dropped after `Drop` has put the real environment back.
    _home: tempfile::TempDir,
}

impl TestEnv {
    /// Takes the lock and points `MVM_HOME` and `HOME` at a fresh temp dir, so a
    /// test that never mentions a home still cannot touch the developer's keys,
    /// audit chain or caches. Call [`TestEnv::isolate_mvm_home`] or [`TestEnv::set`]
    /// to use a directory of the test's own.
    pub fn new() -> Self {
        let mut env = Self {
            _guard: ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            saved: Vec::new(),
            _home: tempfile::tempdir().expect("temp home for a test"),
        };
        let home = env._home.path().to_owned();
        env.isolate_mvm_home(home);
        env
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

/// Run a complete lock-lifetime fixture in its own exact-test process.
///
/// Call before opening fixture resources and without holding a [`TestEnv`].
/// The parent guards the spawn environment; the child releases its guard before
/// running the fixture so the fixture may acquire its own non-reentrant guard.
#[cfg(unix)]
pub fn isolated_lock_probe(probe: impl FnOnce()) {
    let env = TestEnv::new();
    const CHILD_ENV: &str = "MVM_TEST_ISOLATED_PRE_EXEC_LOCK_PROBE";
    let thread = std::thread::current();
    let name = thread.name().expect("libtest names the probe thread");
    let completed = format!("completed isolated pre-exec lock probe: {name}");
    if let Some(child_name) = std::env::var_os(CHILD_ENV) {
        assert_eq!(
            child_name,
            std::ffi::OsStr::new(name),
            "the isolated child must run only its intended test"
        );
        // The single-test child may take its own non-reentrant environment guard.
        drop(env);
        probe();
        eprintln!("{completed}");
        return;
    }

    // Any concurrent fork inherits open descriptions, even CLOEXEC ones.
    // Exec a private test process before opening probe resources so last-close
    // assertions cannot race another libtest thread's fork-before-exec window.
    let output =
        crate::env_hygiene::helper_command(std::env::current_exe().expect("test executable"))
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, name)
            .output()
            .expect("run the isolated lock probe");
    assert_isolated_probe_completed(name, &output);
}

#[cfg(unix)]
fn assert_isolated_probe_completed(name: &str, output: &std::process::Output) {
    let completed = format!("completed isolated pre-exec lock probe: {name}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stderr.lines().filter(|line| *line == completed).count() == 1,
        "isolated lock probe {name} failed:\n{}\n{}",
        stdout,
        stderr,
    );
}

#[cfg(all(test, unix))]
mod isolated_lock_probe_tests {
    use super::{TestEnv, assert_isolated_probe_completed, isolated_lock_probe};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    const NAME: &str = "synthetic::exact_lock_fixture";
    const COMPLETED: &str =
        "completed isolated pre-exec lock probe: synthetic::exact_lock_fixture\n";

    fn output(stderr: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(0),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    fn isolated_lock_probe_executes_exact_fixture_without_nested_env_guard() {
        isolated_lock_probe(|| {
            let _env = TestEnv::new();
            let thread = std::thread::current();
            assert_eq!(
                std::env::var_os("MVM_TEST_ISOLATED_PRE_EXEC_LOCK_PROBE").as_deref(),
                thread.name().map(std::ffi::OsStr::new),
                "only the selected exact child may execute the fixture"
            );
            assert_eq!(std::env::var_os("HOME"), std::env::var_os("MVM_HOME"));
        });
    }

    #[test]
    fn isolated_lock_probe_accepts_one_exact_stderr_completion() {
        assert_isolated_probe_completed(NAME, &output(&format!("noise\n{COMPLETED}after\n")));
    }

    #[test]
    #[should_panic(expected = "isolated lock probe synthetic::exact_lock_fixture failed")]
    fn isolated_lock_probe_refuses_zero_child_success() {
        let mut result = output("");
        result.stdout = b"running 0 tests\n\ntest result: ok. 0 passed\n".to_vec();
        assert_isolated_probe_completed(NAME, &result);
    }

    #[test]
    #[should_panic(expected = "isolated lock probe synthetic::exact_lock_fixture failed")]
    fn isolated_lock_probe_refuses_duplicate_completion() {
        assert_isolated_probe_completed(NAME, &output(&COMPLETED.repeat(2)));
    }

    #[test]
    #[should_panic(expected = "isolated lock probe synthetic::exact_lock_fixture failed")]
    fn isolated_lock_probe_refuses_stdout_only_completion() {
        let mut result = output("");
        result.stdout = COMPLETED.as_bytes().to_vec();
        assert_isolated_probe_completed(NAME, &result);
    }

    #[test]
    #[should_panic(expected = "isolated lock probe synthetic::exact_lock_fixture failed")]
    fn isolated_lock_probe_refuses_completion_from_another_test() {
        assert_isolated_probe_completed(
            NAME,
            &output("completed isolated pre-exec lock probe: another::test\n"),
        );
    }

    #[test]
    #[should_panic(expected = "isolated lock probe synthetic::exact_lock_fixture failed")]
    fn isolated_lock_probe_refuses_failed_child_even_with_completion() {
        let mut result = output(COMPLETED);
        result.status = ExitStatus::from_raw(1 << 8);
        assert_isolated_probe_completed(NAME, &result);
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
        let root = "/tmp/mvm-test-env-isolate-both";

        // The before-values must be read with the guard already held: an
        // unlocked read can observe another thread's in-flight mutation and
        // the final restore check would then compare against that thread's
        // value rather than the value this thread will actually restore.
        let mut env = TestEnv::new();
        // `new` already isolates, so these are the guard's own temp home.
        let before_home = std::env::var_os("HOME");
        let before_mvm_home = std::env::var_os("MVM_HOME");
        assert_eq!(before_home, before_mvm_home);
        assert_ne!(before_home.as_deref(), Some(root.as_ref()));

        env.isolate_mvm_home(root);
        assert_eq!(std::env::var("MVM_HOME").as_deref(), Ok(root));
        // The whole point: HOME moves too, so the MVM_HOME-ignoring
        // default-cache resolvers cannot reach the real one.
        assert_eq!(std::env::var("HOME").as_deref(), Ok(root));

        // Both roots go back to what the guard set on entry, not to root.
        drop(env);
        let _guard = TestEnv::new();
        assert_ne!(std::env::var("MVM_HOME").as_deref(), Ok(root));
        assert_ne!(std::env::var("HOME").as_deref(), Ok(root));
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
