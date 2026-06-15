//! 4-level tenant value precedence.
//!
//! Resolution order, lowest precedence first:
//!   1. Built-in default `"local"`
//!   2. `~/.mvm/config.toml`  `[tenant] name = "..."`
//!   3. `MVM_TENANT` env var (non-empty)
//!   4. `--tenant` CLI flag
//!
//! Identity / `mvmctl auth` is the subject of separate design work;
//! this resolver only handles the tenant *value* — a string label for
//! the audit chain file — not identity / authentication / credential
//! storage.

#[derive(serde::Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    tenant: Option<TenantBlock>,
}

#[derive(serde::Deserialize)]
struct TenantBlock {
    name: String,
}

pub fn resolve_tenant(flag_value: Option<&str>) -> String {
    if let Some(v) = flag_value
        && !v.is_empty()
    {
        return v.to_string();
    }
    if let Ok(v) = std::env::var("MVM_TENANT")
        && !v.is_empty()
    {
        return v;
    }
    if let Some(v) = read_config_tenant() {
        return v;
    }
    "local".to_string()
}

fn read_config_tenant() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(home).join(".mvm/config.toml");
    let body = std::fs::read_to_string(&path).ok()?;
    let parsed: ConfigFile = toml::from_str(&body).ok()?;
    parsed.tenant.and_then(|t| {
        if t.name.is_empty() {
            None
        } else {
            Some(t.name)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    // These tests mutate MVM_TENANT (process-global). `TestEnv` serializes
    // them behind a shared lock and restores the prior value on drop, so
    // they're safe under the default multi-threaded test runner.

    #[test]
    fn flag_beats_env() {
        let mut env = TestEnv::new();
        env.set("MVM_TENANT", "from-env");
        assert_eq!(resolve_tenant(Some("from-flag")), "from-flag");
    }

    #[test]
    fn env_beats_default_when_no_flag() {
        let mut env = TestEnv::new();
        env.set("MVM_TENANT", "from-env");
        assert_eq!(resolve_tenant(None), "from-env");
    }

    #[test]
    fn empty_flag_falls_through_to_env() {
        let mut env = TestEnv::new();
        env.set("MVM_TENANT", "from-env");
        assert_eq!(resolve_tenant(Some("")), "from-env");
    }

    #[test]
    fn empty_env_falls_through_to_default() {
        let mut env = TestEnv::new();
        env.set("MVM_TENANT", "");
        // Either default or whatever ~/.mvm/config.toml says; both
        // are non-empty. The empty MVM_TENANT must NOT come through.
        let resolved = resolve_tenant(None);
        assert!(!resolved.is_empty());
    }
}
