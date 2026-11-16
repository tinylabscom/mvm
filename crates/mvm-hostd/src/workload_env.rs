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
    let env = if substitution.is_empty() {
        vsock_egress_env(vm)
    } else {
        substitution
    };
    with_egress_ca_env(env, egress_ca_present(vm))
}

fn substitution_env(vm: &str) -> Vec<(String, String)> {
    let path = mvm_core::config::vm_substitution_env_path(vm);
    let placeholders: Vec<(String, String)> = std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    build_substitution_env(placeholders)
}

fn vsock_egress_env(vm: &str) -> Vec<(String, String)> {
    let authenticated = mvm_vmm::host::network_endpoint_spawn::endpoint_session_established(
        &mvm_core::config::vm_state_dir(vm),
    );
    if !authenticated && !mvm_core::config::vm_vsock_egress_marker_path(vm).is_file() {
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
    fn authenticated_endpoint_supplies_proxy_without_legacy_marker_or_placeholders() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let vm = "plain-authenticated-endpoint";
        let state = mvm_core::config::vm_state_dir(vm);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(mvm_vmm::host::network_endpoint_spawn::SUBST_SESSION_FILE),
            b"1",
        )
        .unwrap();
        assert!(!mvm_core::config::vm_vsock_egress_marker_path(vm).exists());
        assert!(!mvm_core::config::vm_substitution_env_path(vm).exists());

        for with_ca in [false, true] {
            if with_ca {
                std::fs::write(
                    state.join(mvm_vmm::host::network_endpoint_spawn::EGRESS_CA_STATE_FILE),
                    b"certificate state present",
                )
                .unwrap();
            }
            let projected = workload_egress_env(vm);
            for expected in mvm_core::guest_netd::proxy_env_vars(
                mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN,
            ) {
                assert!(projected.contains(&expected), "{projected:?}");
            }
            assert_eq!(
                projected.iter().any(|(key, _)| key == "SSL_CERT_FILE"),
                with_ca
            );
        }
    }

    #[test]
    fn endpoint_process_without_authenticated_session_does_not_supply_proxy() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let vm = "unready-endpoint";
        let state = mvm_core::config::vm_state_dir(vm);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(mvm_vmm::host::network_endpoint_spawn::SUBST_PID_FILE),
            b"123",
        )
        .unwrap();
        assert!(workload_egress_env(vm).is_empty());
    }

    #[test]
    fn workload_synthesis_delivers_the_stored_substitution_pair() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let path = mvm_core::config::vm_substitution_env_path("substitution-delivery");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, br#"[["API_KEY","mvm-secret://opaque-placeholder"]]"#).unwrap();

        let projected = workload_egress_env("substitution-delivery");
        assert!(projected.iter().any(|(key, value)| {
            key == "API_KEY" && value == "mvm-secret://opaque-placeholder"
        }));
        assert!(projected.iter().any(|(key, _)| key == "HTTPS_PROXY"));
    }

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
