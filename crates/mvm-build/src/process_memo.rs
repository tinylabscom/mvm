//! A process-lifetime memo for answers that are expensive to compute and
//! cannot usefully differ between the call sites of one `mvmctl` invocation.
//!
//! `mvmctl` is one-shot: every caller in a launch runs within a few hundred
//! milliseconds of the others. Asking the same source-tree or cache question
//! several times in that window costs a full walk each time and can produce
//! disagreeing answers if the tree is edited mid-command; the memo makes the
//! answer both cheap and consistent.
//!
//! Only successes are stored. An error can be transient — a file being written
//! as a walk passes it — and caching one would make a single unlucky moment
//! permanent for the rest of the run.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, OnceLock};

/// A map from `K` to the first successful `V` computed for it in this process.
pub(crate) struct ProcessMemo<K, V> {
    entries: OnceLock<Mutex<HashMap<K, V>>>,
}

impl<K: Eq + Hash, V: Clone> ProcessMemo<K, V> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: OnceLock::new(),
        }
    }

    /// The stored value for `key`, if one has been recorded.
    pub(crate) fn get(&self, key: &K) -> Option<V> {
        self.entries
            .get_or_init(Default::default)
            .lock()
            .ok()?
            .get(key)
            .cloned()
    }

    /// Record `value` for `key`, replacing any earlier one.
    pub(crate) fn insert(&self, key: K, value: V) {
        if let Ok(mut entries) = self.entries.get_or_init(Default::default).lock() {
            entries.insert(key, value);
        }
    }

    /// The stored value for `key`, or the result of `compute`, which is
    /// recorded only when it succeeds.
    pub(crate) fn get_or_try_insert<E>(
        &self,
        key: K,
        compute: impl FnOnce() -> Result<V, E>,
    ) -> Result<V, E> {
        if let Some(hit) = self.get(&key) {
            return Ok(hit);
        }
        let value = compute()?;
        self.insert(key, value.clone());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_once_per_key_and_never_records_a_failure() {
        let memo: ProcessMemo<&str, u32> = ProcessMemo::new();
        let mut calls = 0;
        let failed: Result<u32, &str> = memo.get_or_try_insert("a", || {
            calls += 1;
            Err("transient")
        });
        assert_eq!(failed, Err("transient"));
        for _ in 0..3 {
            let value: Result<u32, &str> = memo.get_or_try_insert("a", || {
                calls += 1;
                Ok(7)
            });
            assert_eq!(value, Ok(7));
        }
        assert_eq!(calls, 2, "one failed attempt, then one success reused");
        assert_eq!(memo.get(&"b"), None);
        memo.insert("b", 9);
        assert_eq!(memo.get(&"b"), Some(9));
    }
}
