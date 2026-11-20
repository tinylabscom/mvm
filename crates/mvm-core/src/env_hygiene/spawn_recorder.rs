//! A per-thread record of the programs [`super::helper_command_with`] is asked
//! to build, for tests that prove an API constructs no host process.
//!
//! What it records is *construction* at the one sanctioned process
//! constructor, not execution: a program named here may never have been run,
//! and a process created some other way is invisible to it. The raw sites the
//! `check-helper-env-hygiene` inventory classifies as guest or builder code
//! are outside it, and so is anything a mock backend never reaches, such as
//! the VMM launch chain.
//!
//! The scope is thread-local, so concurrent tests under threaded
//! `cargo test` cannot see one another's constructions. The converse is a
//! limit: a process built on a thread the code under test spawned itself is
//! not recorded.

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};

thread_local! {
    static RECORD: RefCell<Option<Vec<OsString>>> = const { RefCell::new(None) };
}

/// Records every program built on this thread until dropped.
#[must_use = "the scope records only while it is alive"]
pub struct SpawnScope {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl SpawnScope {
    /// Start recording on this thread.
    ///
    /// # Panics
    /// When a scope is already open on this thread: two scopes would split
    /// one test's constructions between them.
    pub fn begin() -> Self {
        RECORD.with(|record| {
            let mut record = record.borrow_mut();
            assert!(record.is_none(), "a spawn scope is already open");
            *record = Some(Vec::new());
        });
        Self {
            _not_send: std::marker::PhantomData,
        }
    }

    /// The programs built so far, in order.
    #[must_use]
    pub fn programs(&self) -> Vec<OsString> {
        RECORD.with(|record| record.borrow().clone().unwrap_or_default())
    }

    /// Fail unless every program built so far is in `allowed`.
    ///
    /// # Panics
    /// Naming each program built outside `allowed`.
    pub fn assert_only(&self, allowed: &[&str]) {
        let unexpected: Vec<OsString> = self
            .programs()
            .into_iter()
            .filter(|program| !allowed.iter().any(|name| OsStr::new(name) == program))
            .collect();
        assert!(
            unexpected.is_empty(),
            "constructed a host process outside the allowlist {allowed:?}: {unexpected:?}"
        );
    }
}

impl Drop for SpawnScope {
    fn drop(&mut self) {
        RECORD.with(|record| *record.borrow_mut() = None);
    }
}

/// Note one construction, when a scope is open on this thread.
pub(super) fn note(program: &OsStr) {
    RECORD.with(|record| {
        if let Some(programs) = record.borrow_mut().as_mut() {
            programs.push(program.to_os_string());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_hygiene::{helper_command, helper_command_with};

    #[test]
    fn a_constructed_program_is_recorded_in_order() {
        let scope = SpawnScope::begin();
        let _ = helper_command("first");
        let _ = helper_command_with("second", &crate::env_hygiene::EnvReadmit::none());
        assert_eq!(scope.programs(), ["first", "second"]);
    }

    #[test]
    fn nothing_is_recorded_outside_a_scope() {
        let _ = helper_command("before");
        let scope = SpawnScope::begin();
        assert!(scope.programs().is_empty());
    }

    #[test]
    fn a_scope_on_another_thread_sees_nothing_of_this_one() {
        let scope = SpawnScope::begin();
        std::thread::spawn(|| {
            let other = SpawnScope::begin();
            let _ = helper_command("elsewhere");
            assert_eq!(other.programs(), ["elsewhere"]);
        })
        .join()
        .expect("the other thread's scope");
        assert!(scope.programs().is_empty());
    }

    #[test]
    fn dropping_a_scope_stops_recording() {
        drop(SpawnScope::begin());
        let scope = SpawnScope::begin();
        let _ = helper_command("after");
        assert_eq!(scope.programs(), ["after"]);
    }

    #[test]
    #[should_panic(expected = "a spawn scope is already open")]
    fn a_second_scope_on_one_thread_is_refused() {
        let _first = SpawnScope::begin();
        let _second = SpawnScope::begin();
    }

    #[test]
    fn an_allowlisted_program_passes() {
        let scope = SpawnScope::begin();
        let _ = helper_command("ip");
        scope.assert_only(&["ip"]);
    }

    #[test]
    #[should_panic(expected = "\"sh\"")]
    fn a_program_outside_the_allowlist_fails() {
        let scope = SpawnScope::begin();
        let _ = helper_command("sh");
        scope.assert_only(&["ip"]);
    }
}
