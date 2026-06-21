//! mvm-hostd — host-side daemon roles.
//!
//! Consolidates five former crates into one, each a module; the
//! broker / host-signer / audit-signer additionally ship as separate
//! `[[bin]]`s so each key subprocess stays its own process (the
//! process moat).
//!
//! - [`supervisor`] — the trusted host-side supervisor library (egress
//!   proxy, tool gate, key release, audit signing, plan execution state
//!   machine). Run in-process by `mvm-vm-host`'s per-VM bins, not as a
//!   standalone process.
//! - [`broker`] — host services broker subprocess (vsock dispatch).
//! - [`host_signer`] — Ed25519 host-key signer subprocess.
//! - [`audit_signer`] — chain-signing audit subprocess.
//! - [`jailer`] — the `mvm-jailer-lite` seccomp + landlock confinement
//!   helper, applied in-process by each role before it touches keys or
//!   untrusted input.

pub mod audit;
pub mod audit_signer;
pub mod broker;
/// Length-prefixed message framing (4-byte BE length + body,
/// cap-before-alloc) for the same-uid UDS control channels. Relocated
/// from `mvm_core::framing` so `mvm-core`'s default build pulls no
/// async runtime.
pub mod framing;
pub mod host_signer;
pub mod jailer;
/// Secret keyholder — the `SecretRef` → credential boundary: the
/// [`keyholder::SecretResolver`] trait + the single-host
/// [`keyholder::LocalResolver`].
pub mod keyholder;
/// Child-side parent-death watchdog: each subprocess-moat bin exits the
/// instant its supervisor dies, closing the macOS / abnormal-death gap the
/// spawn-side `PR_SET_PDEATHSIG` attach leaves open.
pub mod parent_death;
pub mod supervisor;
