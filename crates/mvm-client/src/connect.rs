//! Backend selection: turn a [`Target`] into a boxed [`MvmClient`], so a caller
//! (CLI, studio) asks for "local" or "a gateway" and gets a backend without
//! knowing — or being able to pick apart — the transport underneath.

use mvm_core::client::MvmClient;
use mvm_core::client::error::Result;

use crate::local::LocalBackend;

/// Which backend to talk to.
pub enum Target {
    /// This host's microVMs, driven in-process.
    Local,
    /// A gateway — a local sidecar or a remote fleet — over REST.
    Gateway { base_url: String, token: String },
}

// Hand-written so the bearer token never lands in a debug line.
impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Local => f.write_str("Target::Local"),
            Target::Gateway { base_url, .. } => f
                .debug_struct("Target::Gateway")
                .field("base_url", base_url)
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

/// Construct the backend for `target`. The returned trait object hides which
/// transport is underneath. `Target::Local` builds the in-process
/// [`LocalBackend`] (auto-selected VMM); `Target::Gateway` needs the `remote`
/// feature.
pub fn connect(target: Target) -> Result<Box<dyn MvmClient>> {
    match target {
        Target::Local => Ok(Box::new(LocalBackend::new())),
        Target::Gateway { base_url, token } => gateway_backend(base_url, token),
    }
}

#[cfg(feature = "remote")]
fn gateway_backend(base_url: String, token: String) -> Result<Box<dyn MvmClient>> {
    use mvm_core::client::gateway::{GatewayBackend, GatewayConfig};
    let backend = GatewayBackend::new(GatewayConfig { base_url, token })?;
    Ok(Box::new(backend))
}

#[cfg(not(feature = "remote"))]
fn gateway_backend(_base_url: String, _token: String) -> Result<Box<dyn MvmClient>> {
    Err(mvm_core::client::MvmError::Backend {
        reason: "gateway target requires the 'remote' feature".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_local_builds_a_local_backend() {
        // Construction only (auto-selects the VMM); no VM boots here.
        assert!(connect(Target::Local).is_ok());
    }

    #[test]
    fn target_debug_redacts_token() {
        let t = Target::Gateway {
            base_url: "https://x".into(),
            token: "secret123".into(),
        };
        let s = format!("{t:?}");
        assert!(!s.contains("secret123"), "token must not appear in Debug");
        assert!(s.contains("<redacted>"));
    }

    #[cfg(feature = "remote")]
    #[test]
    fn connect_gateway_builds_a_client() {
        assert!(
            connect(Target::Gateway {
                base_url: "https://fleet.example.com".into(),
                token: "t".into(),
            })
            .is_ok()
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn connect_gateway_fails_closed_on_cleartext_remote() {
        assert!(
            connect(Target::Gateway {
                base_url: "http://fleet.example.com".into(),
                token: "t".into(),
            })
            .is_err()
        );
    }
}
