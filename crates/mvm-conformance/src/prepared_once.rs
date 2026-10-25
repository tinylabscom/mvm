//! Process-wide memo of preparation work a suite only needs to do once.
//!
//! Scenarios run sequentially in one process against one shared home, so an
//! idempotent preparation (pulling an image into the home's cache) repeated in
//! every scenario's `Background` costs minutes per scenario for no new
//! guarantee. Anything a scenario consumes (a warm standby) must not go here.

use std::collections::BTreeSet;
use std::sync::Mutex;

/// Keys whose preparation has already succeeded in this process.
pub struct PreparedOnce {
    done: Mutex<BTreeSet<String>>,
}

impl PreparedOnce {
    pub const fn new() -> Self {
        Self {
            done: Mutex::new(BTreeSet::new()),
        }
    }

    /// Run `prepare` unless it already succeeded for `key`. A failure is not
    /// recorded, so the next scenario retries rather than inheriting a
    /// half-prepared home.
    pub fn ensure<E>(&self, key: &str, prepare: impl FnOnce() -> Result<(), E>) -> Result<(), E> {
        let mut done = self
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if done.contains(key) {
            return Ok(());
        }
        prepare()?;
        done.insert(key.to_owned());
        Ok(())
    }
}

impl Default for PreparedOnce {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::PreparedOnce;
    use std::cell::Cell;

    #[test]
    fn a_key_is_prepared_once() {
        let once = PreparedOnce::new();
        let calls = Cell::new(0);
        for _ in 0..3 {
            once.ensure("alpine", || {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            })
            .unwrap();
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn distinct_keys_are_each_prepared() {
        let once = PreparedOnce::new();
        let calls = Cell::new(0);
        for key in ["alpine", "rust"] {
            once.ensure(key, || {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            })
            .unwrap();
        }
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn a_failed_preparation_is_retried() {
        let once = PreparedOnce::new();
        assert_eq!(
            once.ensure("alpine", || Err("pull failed")),
            Err("pull failed")
        );
        let calls = Cell::new(0);
        once.ensure("alpine", || {
            calls.set(calls.get() + 1);
            Ok::<(), &str>(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
    }
}
