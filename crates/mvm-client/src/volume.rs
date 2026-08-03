//! Reusable local encrypted-volume lifecycle service.
//!
//! Issue #2080 composes the existing volume backend, encryption, registry,
//! admission, and attachment primitives behind one object-safe service so
//! local presentation surfaces never duplicate policy or cleanup logic.
