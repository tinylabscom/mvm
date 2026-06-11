//! Re-export shim: the host signing keypair now lives in
//! `mvm_hostd::audit::host_keypair`. The `host_signer` path here is preserved
//! so existing call sites compile unchanged.
pub use mvm_hostd::audit::host_keypair::*;
