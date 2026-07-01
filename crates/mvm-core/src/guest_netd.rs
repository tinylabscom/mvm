//! Guest `mvm-netd` helpers.
//!
//! `mvm-netd` listens on guest loopback and forwards over vsock to the host
//! egress broker. Cooperative apps are pointed at it via the standard proxy
//! environment variables; loopback is excluded via `NO_PROXY` so the app's
//! traffic to the local daemon (and to localhost) is not itself proxied. This
//! module builds that env set deterministically.

/// Loopback hosts excluded from proxying, so an app's calls to the local
/// daemon and to localhost are not themselves routed through the broker.
pub const NO_PROXY_LOOPBACK: &str = "localhost,127.0.0.1,::1";

/// Build the standard proxy environment for a cooperative app, pointing it at
/// the in-guest `mvm-netd` proxy at `proxy_addr` (e.g. `127.0.0.1:3128`). Both
/// upper- and lower-case variants are emitted because tooling is inconsistent
/// about which it reads. `NO_PROXY` excludes loopback.
pub fn proxy_env_vars(proxy_addr: &str) -> Vec<(String, String)> {
    let url = format!("http://{proxy_addr}");
    let mut env = Vec::with_capacity(8);
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        env.push((key.to_string(), url.clone()));
        env.push((key.to_lowercase(), url.clone()));
    }
    env.push(("NO_PROXY".to_string(), NO_PROXY_LOOPBACK.to_string()));
    env.push(("no_proxy".to_string(), NO_PROXY_LOOPBACK.to_string()));
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn proxy_env_points_http_and_https_at_the_local_proxy() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(
            env.get("ALL_PROXY").map(String::as_str),
            Some("http://127.0.0.1:3128")
        );
    }

    #[test]
    fn no_proxy_excludes_loopback() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        let no_proxy = env.get("NO_PROXY").map(String::as_str).unwrap_or_default();
        assert!(no_proxy.contains("127.0.0.1"));
        assert!(no_proxy.contains("localhost"));
    }

    #[test]
    fn lower_and_upper_case_variants_both_present() {
        let env: HashMap<_, _> = proxy_env_vars("127.0.0.1:3128").into_iter().collect();
        for key in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
            assert!(env.contains_key(key), "missing {key}");
        }
    }
}
