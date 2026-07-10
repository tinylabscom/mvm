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
/// Host->guest healthcheck probe: run a workload's healthcheck command via
/// the guest agent's exec protocol and decide pass/fail.
pub mod health_probe;
/// Idle-registration self-termination logic for the `mvm-host-agent` worker.
pub mod host_agent_idle;
pub mod host_signer;
/// Host-side `/dev/net/tun` helper for the shared packet-tunnel data plane.
pub mod host_tun;
pub mod jailer;
/// Secret keyholder — the `SecretRef` → credential boundary: the
/// [`keyholder::SecretResolver`] trait + the single-host
/// [`keyholder::LocalResolver`].
pub mod keyholder;
/// Host-side session validation helpers for the shared network tunnel contract.
pub mod network_tunnel;
/// Child-side parent-death watchdog: each subprocess-moat bin exits the
/// instant its supervisor dies, closing the macOS / abnormal-death gap the
/// spawn-side `PR_SET_PDEATHSIG` attach leaves open.
pub mod parent_death;
pub mod plan_admission;
pub mod run;
pub mod supervisor;
