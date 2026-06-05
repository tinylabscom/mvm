//! Resolves an IR `NetworkMode` to a registered [`NetworkProvider`].
//!
//! The WireGuard/Tailscale mesh providers themselves are mvmd's — this crate
//! only exports the registry seam so a `NetworkMode::Custom { provider }`
//! routes to whatever mvmd registered, without a core edit. The built-in
//! `None`/`Bridge`/`Host` modes resolve to a provider of the matching kind.

use std::collections::HashMap;
use std::sync::Arc;

use mvm_sdk::ir::NetworkMode;

use crate::provider::{NetworkError, NetworkProvider};

/// Maps a `NetworkMode` to its provider. Unregistered kinds fail closed with
/// [`NetworkError::UnknownProvider`] — never a silent default.
#[derive(Default)]
pub struct NetworkProviderRegistry {
    providers: HashMap<String, Arc<dyn NetworkProvider>>,
}

impl NetworkProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider under its `kind()`. A later registration with the
    /// same kind replaces the earlier one.
    pub fn register(&mut self, provider: Arc<dyn NetworkProvider>) {
        self.providers.insert(provider.kind().to_string(), provider);
    }

    /// Resolve the provider for `mode`. Built-ins map to their kind string;
    /// `Custom` routes by its `provider`.
    pub fn resolve(&self, mode: &NetworkMode) -> Result<&Arc<dyn NetworkProvider>, NetworkError> {
        let kind = mode_kind(mode);
        self.providers
            .get(kind)
            .ok_or_else(|| NetworkError::UnknownProvider {
                kind: kind.to_string(),
            })
    }
}

/// The provider-kind string a `NetworkMode` selects.
fn mode_kind(mode: &NetworkMode) -> &str {
    match mode {
        NetworkMode::None => "none",
        NetworkMode::Bridge => "bridge",
        NetworkMode::Host => "host",
        NetworkMode::Custom { provider, .. } => provider.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{NetHandle, NetworkSpec};
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::protocol::vm_backend::VmId;

    struct StubProvider {
        kind: String,
        policy: NetworkPolicy,
    }

    impl NetworkProvider for StubProvider {
        fn kind(&self) -> &str {
            &self.kind
        }
        fn provision(&self, vm: &VmId, _spec: &NetworkSpec) -> Result<NetHandle, NetworkError> {
            Ok(NetHandle {
                vm: vm.clone(),
                tag: format!("{}-tag", self.kind),
            })
        }
        fn policy(&self) -> &NetworkPolicy {
            &self.policy
        }
        fn teardown(&self, _handle: NetHandle) -> Result<(), NetworkError> {
            Ok(())
        }
    }

    fn stub(kind: &str) -> Arc<dyn NetworkProvider> {
        Arc::new(StubProvider {
            kind: kind.into(),
            policy: NetworkPolicy::default(),
        })
    }

    #[test]
    fn registry_resolves_builtin_and_custom_modes() {
        let mut reg = NetworkProviderRegistry::new();
        reg.register(stub("bridge"));
        reg.register(stub("wireguard"));

        assert_eq!(reg.resolve(&NetworkMode::Bridge).unwrap().kind(), "bridge");
        let custom = NetworkMode::Custom {
            provider: "wireguard".into(),
            config: serde_json::json!({ "peer": "x" }),
        };
        assert_eq!(reg.resolve(&custom).unwrap().kind(), "wireguard");
    }

    #[test]
    fn registry_rejects_unregistered_custom_provider() {
        let reg = NetworkProviderRegistry::new();
        let custom = NetworkMode::Custom {
            provider: "tailscale".into(),
            config: serde_json::json!({}),
        };
        // Can't `{:?}` the Ok side (a trait object isn't Debug), so branch
        // explicitly and format the error via Display.
        match reg.resolve(&custom) {
            Err(NetworkError::UnknownProvider { kind }) => assert_eq!(kind, "tailscale"),
            Err(e) => panic!("expected UnknownProvider, got {e}"),
            Ok(_) => panic!("expected UnknownProvider, got Ok"),
        }
    }

    #[test]
    fn network_mode_custom_roundtrips_json() {
        let mode = NetworkMode::Custom {
            provider: "wireguard".into(),
            config: serde_json::json!({ "endpoint": "1.2.3.4:51820" }),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: NetworkMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}
