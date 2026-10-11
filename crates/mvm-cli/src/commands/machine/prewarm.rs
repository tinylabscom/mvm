//! Compatibility entry points for native warm-artifact callers.
//!
//! Source verification and preparation policy belong to the client.

pub use mvm_client::launch::prewarm::{resolve_warm_artifact_plan, warm_artifact_worker};
