//! Shared kernel-cmdline token builders for governed workload grants.
//!
//! Backend-agnostic helpers now live in `mvm-vmm::host::egress_bridge` and are
//! re-exported here while callers migrate.

pub use mvm_vmm::host::egress_bridge::{
    host_signer_pub_cmdline_token, require_grant_cmdline_token, verb_grant_cmdline_token,
};
