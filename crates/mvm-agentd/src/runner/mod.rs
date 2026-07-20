//! Library half of the in-guest function runtime. The `mvm-runner`
//! binary lives at `src/bin/mvm-runner.rs`; this module exposes the
//! testable units it composes. (Folded in from the former `mvm-runner`
//! crate.)
//!
//! The runtime is the in-guest entrypoint for function-call workloads.
//! At image build time the Nix factories
//! (`nix/factories/mkPythonFunctionService.nix`, `mkNodeFunctionService`)
//! bake:
//!
//! - `/usr/lib/mvm/wrappers/runner` — the `mvm-runtime` binary,
//!   mode 0755, owned root (the `RunEntrypoint` agent path policy).
//! - `/etc/mvm/entrypoint` — mode 0644, points at the runner.
//! - `/etc/mvm/runtime.json` — mode 0644, declares `runtime`,
//!   `module`, `function`, `format`, `working_dir`.
//! - `/usr/lib/mvm/runtime/dispatch.{py,mjs}` — language-specific
//!   dispatch fragment (~20 lines).
//!
//! At call time the agent (`RunEntrypoint` verb) execs the runner with
//! stdin piped in. The runtime:
//!
//! 1. Sets `PR_SET_DUMPABLE = 0` (Linux) before the first stdin byte,
//!    so a panic in the dispatched child cannot leak in-flight payload
//!    bytes via a coredump on disk.
//! 2. Reads `/etc/mvm/runtime.json` to learn what to dispatch.
//! 3. Reads stdin up to a hard cap (1 MiB v1, parametric in v2).
//! 4. Forks the language interpreter (`python3` or `node`) with the
//!    matching dispatch fragment as `argv[1]` and the runtime config
//!    as a small set of environment variables (`MVM_MODULE`,
//!    `MVM_FUNCTION`, `MVM_FORMAT`, `MVM_SOURCE_PATH`).
//! 5. Pipes the captured stdin to the child's stdin and lets the
//!    child write to the runner's stdout/stderr directly.
//! 6. On the child exiting non-zero — or on a panic in the runtime
//!    itself — emits a sanitized error envelope on stderr
//!    (`{kind, error_id, message}`). Never logs payload contents.
//!
//! Crash hardening + sanitized envelope lives here in audited Rust;
//! the per-language dispatch fragments stay small enough to read at a
//! glance.

pub mod config;
pub mod envelope;
pub mod hardening;
pub mod paths;

pub use config::{Format, Language, RuntimeConfig};
pub use envelope::{ErrorEnvelope, ErrorKind};
pub use paths::{DEFAULT_CONFIG_PATH, DEFAULT_DISPATCH_DIR};

/// Hard cap on inbound stdin payload size, in bytes (1 MiB v1).
/// A larger payload is rejected before reaching the dispatched child.
pub const STDIN_CAP_BYTES: usize = 1024 * 1024;
