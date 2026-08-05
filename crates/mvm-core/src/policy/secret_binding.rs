//! Host-side secret resolution. The [`SecretBinding`] DTO, its builders,
//! and its `FromStr`/`Display` CLI syntax live in
//! `mvm_contract::policy::secret_binding`, re-exported here so every
//! existing `crate::policy::secret_binding::{SecretBinding,
//! PLACEHOLDER_PREFIX, SecretBindingParseError}` path keeps resolving
//! unchanged.

pub use mvm_contract::policy::secret_binding::{
    PLACEHOLDER_PREFIX, SecretBinding, SecretBindingParseError,
};

/// Resolve the secret value: use the explicit value if set,
/// otherwise read from the host environment.
///
/// A free function rather than an inherent method on [`SecretBinding`]:
/// that type now lives in `mvm-contract`, and the orphan rule forbids
/// `mvm-core` from adding inherent `impl`s to a foreign type.
/// `std::env::var` also needs `std`, unavailable in the no_std
/// `mvm-contract` crate.
pub fn resolve_value(binding: &SecretBinding) -> anyhow::Result<String> {
    if let Some(ref v) = binding.value {
        Ok(v.clone())
    } else {
        std::env::var(&binding.env_var).map_err(|_| {
            anyhow::anyhow!(
                "secret {:?} not set in host environment and no explicit value provided",
                binding.env_var
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::test_env::TestEnv;

    #[test]
    fn resolve_value_explicit() {
        let b = SecretBinding::new("NONEXISTENT_VAR", "host.com").with_value("explicit");
        assert_eq!(resolve_value(&b).unwrap(), "explicit");
    }

    #[test]
    fn resolve_value_from_env() {
        let mut env = TestEnv::new();
        env.set("MVM_TEST_SECRET_42", "from-env");
        let b = SecretBinding::new("MVM_TEST_SECRET_42", "host.com");
        assert_eq!(resolve_value(&b).unwrap(), "from-env");
        // `env` restores the prior value on drop.
    }

    #[test]
    fn resolve_value_missing_env() {
        let b = SecretBinding::new("DEFINITELY_NOT_SET_XYZ", "host.com");
        assert!(resolve_value(&b).is_err());
    }
}
