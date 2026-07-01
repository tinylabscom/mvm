//! Backend selection: turn a [`Target`] into a boxed [`MvmClient`], so a caller
//! (CLI, studio) asks for "local" or "a gateway" and gets a backend without
//! knowing — or being able to pick apart — the transport underneath.

use crate::client::MvmClient;
use crate::error::Result;

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
/// transport is underneath.
pub fn connect(target: Target) -> Result<Box<dyn MvmClient>> {
    match target {
        Target::Gateway { base_url, token } => gateway_backend(base_url, token),
        Target::Local => local_backend(),
    }
}

#[cfg(feature = "remote")]
fn gateway_backend(base_url: String, token: String) -> Result<Box<dyn MvmClient>> {
    let backend =
        crate::gateway::GatewayBackend::new(crate::gateway::GatewayConfig { base_url, token })?;
    Ok(Box::new(backend))
}

#[cfg(not(feature = "remote"))]
fn gateway_backend(_base_url: String, _token: String) -> Result<Box<dyn MvmClient>> {
    Err(crate::error::MvmError::Backend {
        reason: "gateway target requires the 'remote' feature".into(),
    })
}

#[cfg(feature = "local")]
fn local_backend() -> Result<Box<dyn MvmClient>> {
    Ok(Box::new(crate::local::LocalBackend::new()))
}

#[cfg(not(feature = "local"))]
fn local_backend() -> Result<Box<dyn MvmClient>> {
    Err(crate::error::MvmError::Backend {
        reason: "local target requires the 'local' feature".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "local"))]
    #[test]
    fn connect_local_reports_not_available() {
        assert!(connect(Target::Local).is_err());
    }

    #[cfg(feature = "local")]
    #[test]
    fn connect_local_builds_when_feature_on() {
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
