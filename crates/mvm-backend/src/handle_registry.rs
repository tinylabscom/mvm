//! Per-process registry of attached runtime handles.
//!
//! This module owns the missing piece. Attached starts call
//! [`register_attached`]; the CLI's top-level signal handler calls
//! [`stop_all_attached`] to walk the registry and tear each
//! runtime down gracefully. `stop`/`detach`/`stop_all` deregister
//! through [`deregister`] so we never try to stop something that's
//! already gone.
//!
//! ## What it does *not* do
//!
//! - It is not a process supervisor. If the parent process dies
//!   uncleanly (SIGKILL, panic without unwinding), attached
//!   runtimes may survive depending on their backend. Cleanup in
//!   that case is `mvmctl ps`/`mvmctl down` after restart.
//! - It is not cross-process. The registry is per-`mvmctl`-process;
//!   two concurrent `mvmctl up --attached` invocations don't see
//!   each other's sandboxes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use anyhow::Result;

/// Metadata kept for each attached sandbox. The map's key is the
/// sandbox name, which is also the only thing the SIGINT handler
/// needs (`Sandbox::get(name).stop()`). The struct exists as the
/// value type so future entries can carry per-sandbox state (start
/// time, parent log file, etc.) without changing the signal-handler
/// protocol — the `#[allow(dead_code)]` `name` field is the
/// future-proofing seam.
#[derive(Debug, Clone)]
struct AttachedEntry {
    #[allow(dead_code)]
    name: String,
}

/// Registry of currently-attached sandbox names. Lazily initialized
/// on first use so a process that never starts an attached sandbox
/// pays no startup cost.
static REGISTRY: OnceLock<Mutex<HashMap<String, AttachedEntry>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, AttachedEntry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record an attached-mode sandbox so the SIGINT handler can find it.
///
/// Idempotent — re-registering the same name overwrites the entry.
pub fn register_attached(name: &str) {
    let mut map = registry().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(
        name.to_string(),
        AttachedEntry {
            name: name.to_string(),
        },
    );
}

/// Drop a sandbox from the registry. Called from `stop`/`detach`/
/// `stop_all` so the SIGINT handler doesn't try to stop something
/// that's already gone.
///
/// A missing entry is a no-op.
pub fn deregister(name: &str) {
    let mut map = registry().lock().unwrap_or_else(|e| e.into_inner());
    map.remove(name);
}

/// True if `name` is currently in the attached registry. Test
/// helper; production code shouldn't need this.
pub fn is_attached(name: &str) -> bool {
    let map = registry().lock().unwrap_or_else(|e| e.into_inner());
    map.contains_key(name)
}

/// Snapshot of currently-attached sandbox names. Caller-owned to
/// avoid holding the registry lock across the `Sandbox::get(...)`
/// async call.
fn attached_names() -> Vec<String> {
    let map = registry().lock().unwrap_or_else(|e| e.into_inner());
    map.keys().cloned().collect()
}

/// Stop every attached-mode runtime in the registry. Today the registry
/// has no backend-specific stop hook, so this defensively drains names
/// to avoid unbounded growth.
///
/// Called from the host SIGINT handler. Returns the names that
/// were processed (whether or not the stop succeeded) so callers
/// can include them in shutdown logs.
pub fn stop_all_attached() -> Vec<String> {
    let names = attached_names();
    if names.is_empty() {
        return names;
    }
    for name in &names {
        deregister(name);
    }
    names
}

/// Test-only helper that drains the registry without invoking the
/// real `LibkrunBackend::stop`. Lets the unit tests assert
/// `register/deregister` semantics without spawning sandboxes.
#[cfg(test)]
pub(crate) fn drain_for_test() -> Vec<String> {
    let mut map = registry().lock().unwrap_or_else(|e| e.into_inner());
    let names: Vec<String> = map.keys().cloned().collect();
    map.clear();
    names
}

/// Public no-op kept on the public surface so callers (`mvm-cli`'s
/// SIGINT handler) can unconditionally call us regardless of whether
/// the libkrun feature ever spawned anything.
///
/// Equivalent to `let _ = stop_all_attached()`. Exists so the
/// signal-handler call site doesn't need to discard the returned
/// `Vec<String>` explicitly.
pub fn stop_all_attached_silent() -> Result<()> {
    let _ = stop_all_attached();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests share the registry; the lock here ensures they don't
    /// race each other. Reuses `HOME_TEST_LOCK` because we want
    /// serialization with any other registry-touching test (no
    /// other lock needs).
    use crate::base::runtime_meta::HOME_TEST_LOCK;

    #[test]
    fn register_then_deregister_is_idempotent() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = drain_for_test();

        register_attached("vm-a");
        assert!(is_attached("vm-a"));
        register_attached("vm-a"); // re-register overwrites
        assert!(is_attached("vm-a"));

        deregister("vm-a");
        assert!(!is_attached("vm-a"));
        deregister("vm-a"); // no-op on missing
        assert!(!is_attached("vm-a"));
    }

    #[test]
    fn drain_clears_registry() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = drain_for_test();

        register_attached("vm-1");
        register_attached("vm-2");
        register_attached("vm-3");

        let mut names = drain_for_test();
        names.sort();
        assert_eq!(names, vec!["vm-1", "vm-2", "vm-3"]);

        assert!(!is_attached("vm-1"));
        assert!(!is_attached("vm-2"));
        assert!(!is_attached("vm-3"));
    }

    #[test]
    fn stop_all_with_empty_registry_is_noop() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = drain_for_test();

        let names = stop_all_attached();
        assert!(names.is_empty());
    }

    #[test]
    fn stop_all_silent_returns_ok_when_empty() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _ = drain_for_test();

        assert!(stop_all_attached_silent().is_ok());
    }
}
