//! `mvm-capture` — project-environment capture frontend for mvm.
//!
//! This crate implements the isolated host-inspection component for the
//! `mvm capture` workflow. It produces a versioned, evidence-oriented
//! [`CaptureReportV1`](report::CaptureReportV1) and resolves it into the
//! existing canonical MVM [`Workload`](mvm_contract::ir::Workload) so the
//! existing Nix renderer can consume it unchanged.
//!
//! Host inspection is read-only by default and gated by platform: the crate
//! compiles everywhere, but Linux-specific collectors only run on Linux.
//! The crate never executes discovered files; only commands explicitly
//! supplied by the user may be traced.

pub mod collect;
pub mod report;
pub mod resolve;
pub mod verify;

use std::path::PathBuf;
use thiserror::Error;

/// Errors returned by the capture pipeline.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("I/O error at {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),

    #[error("path is not a regular file: {0}")]
    NotAFile(PathBuf),

    #[error("file too large: {path} ({size} bytes; max {max})")]
    FileTooLarge { path: PathBuf, size: u64, max: u64 },

    #[error("traversal limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("malformed manifest at {0}: {1}")]
    MalformedManifest(PathBuf, String),

    #[error("package database query failed: {0}")]
    PackageQueryFailed(String),

    #[error("resolution failed: {0}")]
    ResolutionFailed(String),

    #[error("unsupported on this platform: {0}")]
    Unsupported(String),

    #[error("invalid observation: {0}")]
    InvalidObservation(String),
}

/// Convenience re-export of the canonical IR workload type.
pub type Workload = mvm_contract::ir::Workload;
