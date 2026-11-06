//! The hvf-VMM builder's host↔guest build session, over one vsock stream.
//!
//! A builder VM booted by the hvf VMM (HVF/KVM) has no host-mounted share, so
//! a whole build is driven over a single vsock connection using the
//! [`builder_transfer`](crate::builder_transfer) file primitive plus a few control
//! messages. The sequence on one stream, in order (no interleaving, so each side
//! always knows what to read next):
//!
//! 1. host → guest: the source tree (`/work`) as a transfer.
//! 2. host → guest: the host-binary tree (`/mvm-bins`) as a transfer.
//! 3. host → guest: a [`BuildRequest`].
//! 4. guest → host: zero or more [`SessionEvent::Log`] lines.
//! 5. guest → host: [`SessionEvent::Done`] carrying the [`BuildOutcome`].
//! 6. guest → host (only on success): the artifact tree (`/out`) as a transfer.
//!
//! The guest is untrusted on the return leg, so step 6's receive is the
//! path-sanitized [`builder_transfer::receive_into`] — a hostile guest cannot
//! write outside the host's artifact dir.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::builder_transfer::{read_msg, receive_into, send_dir, write_msg};

/// What the host asks the builder guest to build. `flake_ref`/`attr` are the
/// same validated inputs the existing builder agent takes; the guest resolves
/// them against the staged `/work` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRequest {
    pub flake_ref: String,
    pub attr: String,
    pub timeout_secs: Option<u64>,
}

/// Terminal result of a build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BuildOutcome {
    /// The build succeeded; the artifact tree follows on the stream.
    Success,
    /// The build failed; no artifact tree follows.
    Failure { message: String },
}

/// A guest→host event during/after the build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    /// A streamed build log line.
    Log { line: String },
    /// The build finished with this outcome (last control message).
    Done { outcome: BuildOutcome },
}

/// What the guest's build closure returns: the outcome, the directory to stream
/// back as `/out` on success, and any log lines to surface to the host.
pub struct BuildProduct {
    pub outcome: BuildOutcome,
    /// Directory whose tree is streamed to the host on success. Ignored on failure.
    pub out_dir: PathBuf,
    pub logs: Vec<String>,
}

/// Guest side: serve one build session on `stream`. Receives `/work` +
/// `/mvm-bins` into the given destinations, reads the request, runs `build`, then
/// streams the logs + outcome (+ the artifact tree on success) back.
pub fn serve_build<S, F>(
    stream: &mut S,
    work_dest: &Path,
    mvm_bins_dest: &Path,
    build: F,
) -> Result<()>
where
    S: Read + Write,
    F: FnOnce(&Path, &Path, &BuildRequest) -> BuildProduct,
{
    receive_into(stream, work_dest)?;
    receive_into(stream, mvm_bins_dest)?;
    let request: BuildRequest = read_msg(stream)?;
    let product = build(work_dest, mvm_bins_dest, &request);
    for line in &product.logs {
        write_msg(stream, &SessionEvent::Log { line: line.clone() })?;
    }
    write_msg(
        stream,
        &SessionEvent::Done {
            outcome: product.outcome.clone(),
        },
    )?;
    if matches!(product.outcome, BuildOutcome::Success) {
        send_dir(stream, &product.out_dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {}
