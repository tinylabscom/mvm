//! Re-export shim: the host signing keypair is `mvm_client::host_keypair`. The
//! `host_signer` path here is preserved so existing call sites compile unchanged.
pub(crate) use mvm_client::host_keypair::*;
