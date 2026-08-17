use std::collections::BTreeMap;

use crate::ir::{AddonRef, AddonTier, AddonUse, Hooks};

/// The placeholder `sha256` an unlocked addon use carries until
/// `mvm addon lock` resolves it. Downstream tooling treats it as the
/// "needs locking" marker.
pub const UNRESOLVED_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Use a registry-published addon at `version`.
///
/// The dynamic SDKs expose one `addon_use` taking `version=` or `path=`
/// and reject passing both or neither at runtime. Rust splits the two
/// instead, so the invalid combination cannot be written — the same
/// reason a port range is a `u16` rather than a check.
pub fn addon_use_registry(name: impl Into<String>, version: impl Into<String>) -> AddonUse {
    let name = name.into();
    AddonUse {
        r#ref: AddonRef::Registry {
            url: format!("addons.mvm.io/{name}"),
            version: version.into(),
        },
        name,
        alias: None,
        tier: AddonTier::Separate,
        sha256: UNRESOLVED_SHA256.to_string(),
        params: BTreeMap::new(),
        hooks: Hooks::default(),
    }
}

/// Use a local-path addon during development.
///
/// `mvm addon publish` refuses a workload carrying any local-path use.
pub fn addon_use_local(name: impl Into<String>, path: impl Into<String>) -> AddonUse {
    AddonUse {
        name: name.into(),
        alias: None,
        tier: AddonTier::Separate,
        r#ref: AddonRef::Local { path: path.into() },
        sha256: UNRESOLVED_SHA256.to_string(),
        params: BTreeMap::new(),
        hooks: Hooks::default(),
    }
}

/// Chained setters over [`AddonUse`]. Bring into scope via
/// `use mvm_sdk::*;`.
pub trait AddonUseExt: Sized {
    /// Prefix every env var the addon exports with `<ALIAS_UPPER>_`.
    fn with_alias(self, alias: impl Into<String>) -> Self;
    /// Pin the resolved artifact hash instead of the placeholder.
    fn with_sha256(self, sha256: impl Into<String>) -> Self;
    /// Set a param value passed to the addon.
    fn with_param(self, key: impl Into<String>, value: serde_json::Value) -> Self;
}

impl AddonUseExt for AddonUse {
    fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = sha256.into();
        self
    }

    fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.params.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registry_use_derives_its_url_from_the_name() {
        let used = addon_use_registry("postgres", "16");
        assert_eq!(
            used.r#ref,
            AddonRef::Registry {
                url: "addons.mvm.io/postgres".to_string(),
                version: "16".to_string(),
            }
        );
        assert_eq!(used.name, "postgres");
    }

    #[test]
    fn an_unlocked_use_carries_the_placeholder_hash() {
        assert_eq!(
            addon_use_registry("postgres", "16").sha256,
            UNRESOLVED_SHA256
        );
        assert_eq!(
            addon_use_local("my-db", "./addons/my-db").sha256,
            UNRESOLVED_SHA256
        );
        assert_eq!(UNRESOLVED_SHA256.len(), 64);
        assert!(UNRESOLVED_SHA256.chars().all(|c| c == '0'));
    }

    #[test]
    fn a_local_use_keeps_the_path_verbatim() {
        let used = addon_use_local("my-db", "./addons/my-db");
        assert_eq!(
            used.r#ref,
            AddonRef::Local {
                path: "./addons/my-db".to_string()
            }
        );
    }

    #[test]
    fn setters_compose() {
        let used = addon_use_registry("postgres", "16")
            .with_alias("db")
            .with_param("max_connections", serde_json::json!(20));
        assert_eq!(used.alias.as_deref(), Some("db"));
        assert_eq!(
            used.params.get("max_connections"),
            Some(&serde_json::json!(20))
        );
    }

    #[test]
    fn the_default_tier_is_separate() {
        // `InVm` is reserved and rejected by validation, so the
        // constructor must never hand one out.
        assert_eq!(
            addon_use_registry("postgres", "16").tier,
            AddonTier::Separate
        );
        assert_eq!(addon_use_local("my-db", ".").tier, AddonTier::Separate);
    }
}
