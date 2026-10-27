//! Host proxy settings carried privately to the network endpoint.

use anyhow::Result;

/// The upstream proxy, as strings the endpoint parses.
///
/// Strings carry host settings to the endpoint's stdin without exposing them
/// in argv or environment. Both the launcher and endpoint validate them with
/// the forward client's parser.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EgressProxySpawnConfig {
    pub https: Option<String>,
    pub http: Option<String>,
    pub no_proxy: Option<String>,
}

impl std::fmt::Debug for EgressProxySpawnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EgressProxySpawnConfig { <redacted> }")
    }
}

impl EgressProxySpawnConfig {
    /// Resolve the operator's host config before considering ambient variables.
    /// A present, even empty, table is a complete override.
    pub fn from_host_config() -> Result<Option<Self>> {
        let config = mvm_core::user_config::load_strict(None)?;
        let proxy = Self::from_config_and_env(config.egress_proxy, Self::from_host_env);
        if let Some(proxy) = &proxy {
            proxy.resolve()?;
        }
        Ok(proxy)
    }

    fn from_config_and_env(
        config: Option<mvm_core::user_config::HostEgressProxyConfig>,
        ambient: impl FnOnce() -> Option<Self>,
    ) -> Option<Self> {
        match config {
            Some(config) => Some(Self {
                https: config.https,
                http: config.http,
                no_proxy: config.no_proxy,
            }),
            None => ambient(),
        }
    }

    /// Validate using the same parser as the endpoint. Errors never contain
    /// input URLs, including malformed userinfo.
    pub fn resolve(&self) -> Result<Option<mvm_http::ProxyConfig>> {
        mvm_http::ProxyConfig::from_lookup(|key| match key {
            "https_proxy" => self.https.clone(),
            "http_proxy" => self.http.clone(),
            "no_proxy" => self.no_proxy.clone(),
            _ => None,
        })
        .map_err(Into::into)
    }

    /// Read the conventional proxy environment of the host process.
    ///
    /// Returns `None` when nothing is configured, so the common case emits no
    /// keys at all and the endpoint's defaults keep meaning "dial direct".
    #[must_use]
    pub fn from_host_env() -> Option<Self> {
        let pick = |names: &[&str]| -> Option<String> {
            names
                .iter()
                .find_map(|n| std::env::var(n).ok())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let all = pick(&["all_proxy", "ALL_PROXY"]);
        let cfg = Self {
            https: pick(&["https_proxy", "HTTPS_PROXY"]).or_else(|| all.clone()),
            http: pick(&["http_proxy", "HTTP_PROXY"]).or(all),
            no_proxy: pick(&["no_proxy", "NO_PROXY"]),
        };
        (cfg.https.is_some() || cfg.http.is_some()).then_some(cfg)
    }
}

#[cfg(test)]
mod host_proxy_override_tests {
    use super::*;
    use mvm_core::user_config::HostEgressProxyConfig;
    use std::path::PathBuf;

    /// Clear every proxy name this reads, so a contributor whose own shell
    /// exports one does not get a different answer from CI.
    fn proxy_env() -> mvm_core::util::test_env::TestEnv {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        for k in [
            "https_proxy",
            "HTTPS_PROXY",
            "http_proxy",
            "HTTP_PROXY",
            "all_proxy",
            "ALL_PROXY",
            "no_proxy",
            "NO_PROXY",
        ] {
            env.remove(k);
        }
        env
    }

    /// Nothing configured is the common case, and it has to stay
    /// distinguishable from "configured with empty values" — the endpoint's
    /// default for absent keys is "dial direct", so a `Some` of all-`None`
    /// would emit keys that say nothing and mean something.
    #[test]
    fn an_unconfigured_host_carries_no_proxy_config() {
        let _env = proxy_env();
        assert_eq!(EgressProxySpawnConfig::from_host_env(), None);
    }

    /// The value has to survive the trip. A `Some` whose fields are all `None`
    /// looks configured and forwards nothing.
    #[test]
    fn a_configured_https_proxy_reaches_the_endpoint_config() {
        let mut env = proxy_env();
        env.set("https_proxy", "http://proxy.internal:3128");

        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("a host with https_proxy set is proxy-configured");
        assert_eq!(cfg.https.as_deref(), Some("http://proxy.internal:3128"));
        assert_eq!(cfg.http, None);
    }

    /// Either leg alone is a configured host. Requiring both would silently
    /// dial direct on a host that set only one, which is the shape most
    /// http-only and https-only environments actually have.
    #[test]
    fn either_proxy_leg_alone_configures_egress() {
        let mut env = proxy_env();
        env.set("http_proxy", "http://only-http:3128");
        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("http_proxy alone must configure egress");
        assert_eq!(cfg.http.as_deref(), Some("http://only-http:3128"));
        assert_eq!(cfg.https, None);
        drop(env);

        let mut env = proxy_env();
        env.set("HTTPS_PROXY", "http://only-https:3128");
        let cfg = EgressProxySpawnConfig::from_host_env()
            .expect("HTTPS_PROXY alone must configure egress");
        assert_eq!(cfg.https.as_deref(), Some("http://only-https:3128"));
        assert_eq!(cfg.http, None);
    }

    /// An exported-but-empty proxy var is how a shell spells "unset". Taking
    /// it literally hands the endpoint an empty upstream and every request
    /// fails to reach anything.
    #[test]
    fn an_empty_or_whitespace_proxy_var_reads_as_unset() {
        let mut env = proxy_env();
        env.set("https_proxy", "");
        env.set("http_proxy", "   ");
        assert_eq!(
            EgressProxySpawnConfig::from_host_env(),
            None,
            "an empty proxy value must not count as configured"
        );
    }

    /// `no_proxy` is an exception list, not a proxy. On its own it configures
    /// nothing, or every unproxied host would start emitting proxy keys.
    #[test]
    fn no_proxy_alone_does_not_configure_a_proxy() {
        let mut env = proxy_env();
        env.set("no_proxy", "localhost,127.0.0.1");
        assert_eq!(EgressProxySpawnConfig::from_host_env(), None);
    }

    /// all_proxy is the fallback for both legs, and must not override a
    /// specific one.
    #[test]
    fn all_proxy_fills_both_legs_but_yields_to_a_specific_one() {
        let mut env = proxy_env();
        env.set("all_proxy", "socks5://fallback:1080");
        env.set("https_proxy", "http://specific:3128");

        let cfg = EgressProxySpawnConfig::from_host_env().expect("configured");
        assert_eq!(cfg.https.as_deref(), Some("http://specific:3128"));
        assert_eq!(cfg.http.as_deref(), Some("socks5://fallback:1080"));
    }

    #[test]
    fn host_config_file_overrides_ambient_and_fails_closed() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        for key in [
            "https_proxy",
            "HTTPS_PROXY",
            "http_proxy",
            "HTTP_PROXY",
            "no_proxy",
            "all_proxy",
        ] {
            env.remove(key);
        }
        env.set("ALL_PROXY", "http://ambient.corp:3128");
        env.set("NO_PROXY", "*");
        let dir = PathBuf::from(mvm_core::config::mvm_config_dir());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let ambient = EgressProxySpawnConfig::from_host_config().unwrap().unwrap();
        assert_eq!(ambient.https.as_deref(), Some("http://ambient.corp:3128"));
        assert_eq!(ambient.no_proxy.as_deref(), Some("*"));
        assert!(!path.exists(), "resolution must not create operator config");

        std::fs::write(
            &path,
            "[egress_proxy]\nhttps = 'socks5h://explicit.corp:1080'\nno_proxy = 'internal.example'",
        )
        .unwrap();
        let explicit = EgressProxySpawnConfig::from_host_config().unwrap().unwrap();
        let resolved = explicit.resolve().unwrap().unwrap();
        assert!(resolved.select("api.example", true).is_some());
        assert!(resolved.select("internal.example", true).is_none());
        assert!(resolved.select("api.example", false).is_none());

        std::fs::write(&path, "[egress_proxy]").unwrap();
        assert!(
            EgressProxySpawnConfig::from_host_config()
                .unwrap()
                .unwrap()
                .resolve()
                .unwrap()
                .is_none()
        );
        for text in [
            "[egress_proxy]\nhttps = 'ftp://proxy.corp'",
            "[egress_proxy]\nhttps = 42",
            "[egress_proxy",
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(EgressProxySpawnConfig::from_host_config().is_err());
        }
    }

    #[test]
    fn explicit_proxy_and_no_proxy_replace_ambient_without_reading_it() {
        let proxy = EgressProxySpawnConfig::from_config_and_env(
            Some(HostEgressProxyConfig {
                https: Some("http://explicit.corp:3128".into()),
                http: Some("socks5h://explicit.corp:1080".into()),
                no_proxy: Some("internal.example".into()),
            }),
            || panic!("explicit config must not read ambient values"),
        )
        .unwrap();
        let resolved = proxy.resolve().unwrap().unwrap();
        assert_eq!(
            resolved.select("api.example", true).unwrap().host,
            "explicit.corp"
        );
        assert_eq!(resolved.select("api.example", false).unwrap().port, 1080);
        assert!(resolved.select("api.internal.example", true).is_none());
    }

    #[test]
    fn missing_table_inherits_ambient() {
        let ambient = EgressProxySpawnConfig {
            https: Some("http://ambient.corp:3128".into()),
            http: None,
            no_proxy: Some("*".into()),
        };
        let result = EgressProxySpawnConfig::from_config_and_env(None, || Some(ambient.clone()));
        assert_eq!(result, Some(ambient));
    }

    #[test]
    fn empty_table_and_empty_scheme_values_disable_ambient() {
        for config in [
            HostEgressProxyConfig::default(),
            HostEgressProxyConfig {
                https: Some("  ".into()),
                http: Some("".into()),
                no_proxy: None,
            },
        ] {
            let proxy = EgressProxySpawnConfig::from_config_and_env(Some(config), || {
                panic!("disabled config must not inherit ambient ALL_PROXY")
            })
            .unwrap();
            assert!(proxy.resolve().unwrap().is_none());
        }
    }

    #[test]
    fn omitted_scheme_and_no_proxy_do_not_inherit_ambient() {
        let proxy = EgressProxySpawnConfig::from_config_and_env(
            Some(HostEgressProxyConfig {
                https: Some("http://explicit.corp:3128".into()),
                ..Default::default()
            }),
            || panic!("partial table is still a complete override"),
        )
        .unwrap();
        let resolved = proxy.resolve().unwrap().unwrap();
        assert!(resolved.select("api.example", false).is_none());
        assert!(resolved.select("api.example", true).is_some());
    }

    #[test]
    fn malformed_override_refuses_instead_of_inheriting_or_dialling_direct() {
        for url in ["not a url", "ftp://proxy.corp", "http://"] {
            let proxy = EgressProxySpawnConfig::from_config_and_env(
                Some(HostEgressProxyConfig {
                    https: Some(url.into()),
                    ..Default::default()
                }),
                || panic!("malformed override must not fall back to ambient"),
            )
            .unwrap();
            assert!(proxy.resolve().is_err());
        }
    }

    #[test]
    fn diagnostics_redact_valid_and_malformed_credentials() {
        let sensitive = format!("private-{}", std::process::id());
        for scheme in ["http", "socks5h", "unsupported"] {
            let proxy = EgressProxySpawnConfig {
                https: Some(format!(
                    "{scheme}://{sensitive}:{sensitive}@proxy.corp:3128"
                )),
                ..Default::default()
            };
            assert!(!format!("{proxy:?}").contains(&sensitive));
            match proxy.resolve() {
                Ok(Some(cfg)) => assert!(!cfg.summary().contains(&sensitive)),
                Err(err) => assert!(!format!("{err:?}").contains(&sensitive)),
                Ok(None) => panic!("nonempty proxy must not resolve to direct"),
            }
        }
    }
}
