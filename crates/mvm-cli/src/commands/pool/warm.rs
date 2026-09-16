//! Inputs and result types for warm-pool replenishment.

use std::path::Path;

use mvm_core::vm_backend::VmStartConfig;
use mvm_runtime::backend::AnyBackend;

/// Parameters for [`super::warm_to_target`] — grouped to keep the signature small.
pub struct WarmParams<'a> {
    pub backend: &'a AnyBackend,
    pub signer_id: &'a str,
    pub signing_key_path: &'a Path,
    pub target: u32,
    /// The resolved launch config the warm parents mirror, carrying everything
    /// the run path resolves for a boot — the rootfs and its verity sidecar, the
    /// runtime overlay that holds the guest agent, the universal initramfs, and
    /// the cmdline-bearing policy fields.
    ///
    /// Every other input to the parent's shape is derived from this one value:
    /// template, kernel, vCPUs, memory, image digest and egress enablement all
    /// come out of the launch compatibility calculation. They used to be
    /// separate fields, which let a caller record a compat key describing
    /// something other than what booted — a pool that fills and never drains,
    /// with no error anywhere.
    pub launch: &'a VmStartConfig,
}

/// Summary returned by [`super::warm_to_target`].
#[derive(Debug, PartialEq, Eq)]
pub struct WarmResult {
    /// Standbys newly spawned and recorded in this call.
    pub spawned: u32,
    /// Spawn attempts that failed (each was logged as a warning).
    pub failed: u32,
    /// Human-readable failure chains, one for each failed attempt.
    ///
    /// Pool warming is best-effort across attempts, so failures cannot be
    /// returned immediately. Keep their full context for the command boundary
    /// instead of requiring a tracing subscriber to explain why the target was
    /// not reached.
    pub failures: Vec<String>,
}
