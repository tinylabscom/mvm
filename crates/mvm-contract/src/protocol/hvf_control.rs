//! Trusted-operator lifetime control, separate from producer or caller grants.
//!
//! Public nonces identify instances and connections; they are not credentials.
//! Every response and stop command travels inside the existing host-root-signed
//! `SignedControl` envelope. Filesystem access alone never authorizes stop.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Concrete ownership generation. A resident handoff generates a new boot nonce
/// even though the operating-system process remains the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfInstance {
    pub vm_id: String,
    pub boot_nonce: [u8; 32],
}

/// Messages signed under the `hvf_instance_v1` control domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HvfInstanceControl {
    /// Proves that this connected instance answered a challenge generated after
    /// the client armed its kernel process-exit observer.
    Challenge {
        instance: HvfInstance,
        client_nonce: [u8; 32],
        connection_nonce: [u8; 32],
    },
    /// Single-use, connection-bound authorization. Receiving it is not proof
    /// that the process exited or that capture finalized.
    StopHvfInstance {
        instance: HvfInstance,
        connection_nonce: [u8; 32],
        issued_at_secs: u64,
    },
    /// Persisted only after guest quiescence and capture finalization. Even a
    /// valid record requires independent process-lifetime exit evidence.
    Finalized { instance: HvfInstance },
}
