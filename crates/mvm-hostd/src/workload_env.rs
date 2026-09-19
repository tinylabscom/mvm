//! The one host-side environment synthesis seam for workload processes.
//!
//! Both ordinary entrypoint invocation and the drive plane call this module.
//! Keeping the projection here prevents a driven program from losing the
//! placeholder variables and proxy settings that keep plaintext credentials
//! out of the guest.

/// Build the workload environment for the egress mode provisioned on `vm`.
#[must_use]
pub fn workload_egress_env(vm: &str) -> Vec<(String, String)> {
    let substitution = substitution_env(vm);
    if substitution.is_empty() {
        vsock_egress_env(vm)
    } else {
        substitution
    }
}

fn substitution_env(vm: &str) -> Vec<(String, String)> {
    let path = mvm_core::config::vm_substitution_env_path(vm);
    let placeholders: Vec<(String, String)> = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    with_egress_ca_env(build_substitution_env(placeholders), egress_ca_present(vm))
}

fn vsock_egress_env(vm: &str) -> Vec<(String, String)> {
    if !mvm_core::config::vm_vsock_egress_marker_path(vm).is_file() {
        return Vec::new();
    }
    mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN)
}

fn egress_ca_present(vm: &str) -> bool {
    mvm_core::config::vm_state_dir(vm)
        .join(mvm_vmm::host::network_endpoint_spawn::EGRESS_CA_STATE_FILE)
        .exists()
}

fn with_egress_ca_env(
    env: Vec<(String, String)>,
    egress_ca_present: bool,
) -> Vec<(String, String)> {
    if !egress_ca_present {
        return env;
    }
    let mut ca = vec![
        (
            "SSL_CERT_FILE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "CURL_CA_BUNDLE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "REQUESTS_CA_BUNDLE".to_string(),
            "/run/mvm/ca-bundle.crt".to_string(),
        ),
        (
            "NODE_EXTRA_CA_CERTS".to_string(),
            "/run/mvm/egress-ca.crt".to_string(),
        ),
    ];
    ca.extend(env);
    ca
}

fn build_substitution_env(placeholders: Vec<(String, String)>) -> Vec<(String, String)> {
    if placeholders.is_empty() {
        return Vec::new();
    }
    let mut env =
        mvm_core::guest_netd::proxy_env_vars(mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN);
    env.extend(placeholders);
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_open_receives_substituted_placeholder_not_a_secret() {
        let env = build_substitution_env(vec![(
            "MVM_API_TOKEN".to_string(),
            "mvm-placeholder:binding-7".to_string(),
        )]);

        assert!(env.iter().any(|(key, value)| {
            key == "MVM_API_TOKEN" && value == "mvm-placeholder:binding-7"
        }));
        assert!(!env.iter().any(|(_, value)| value == "plaintext-secret"));
        assert!(env.iter().any(|(key, _)| key == "HTTPS_PROXY"));
    }
}
