//! The operator's side of runtime approvals.
//!
//! A workload's network endpoint holds a flow whose decision is `ask` and
//! puts the question to the approval broker listening on the VM's approval
//! socket. The broker is whoever launched the run: `mvmctl` in the
//! foreground, or an application embedding the host library. It answers with
//! one [`ApprovalBackend`]:
//!
//! - [`DenyBackend`] — refuses everything; the default when nobody can be
//!   asked.
//! - [`WebhookBackend`] — POSTs the question as JSON and reads the answer.
//! - [`ChainBackend`] — several backends, all of which must approve, or any
//!   one of which may.
//! - [`CallbackBackend`] — a function, for an SDK's in-process callback.
//! - The terminal backend lives in `mvm-cli`, which owns the controlling TTY.
//!
//! Every backend fails closed: anything but an explicit approval — an error,
//! a timeout, an unreachable URL, a malformed reply — is a denial.
//!
//! The endpoint enforces the timeout, the rate limit and the ledger, and
//! audits every step; a backend only answers.

mod backends;
mod server;
mod webhook;

pub use backends::{
    ApprovalBackend, CallbackBackend, ChainBackend, ChainMode, DenyBackend, approval_label,
};
pub use server::ApprovalServer;
pub use webhook::{WebhookBackend, WebhookError};

pub use mvm_contract::policy::approval_prompt::{
    ApprovalAnswer, ApprovalPrompt, ApprovalScope, ApprovalSubject, display_safe,
};
