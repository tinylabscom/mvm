pub(crate) const EGRESS_CA_BUNDLE_PATH: &str = "/run/mvm/ca-bundle.crt";
pub(crate) const EGRESS_CA_CERT_PATH: &str = "/run/mvm/egress-ca.crt";

/// Whether the per-VM egress CA sidecar exists — i.e. egress substitution
/// provisioned a CA whose PEM the launcher put on the guest kernel cmdline
/// (`mvm.egress_ca=`) and the guest `/init` decoded to the runtime trust paths.
pub(crate) fn egress_ca_present(vm_name: &str) -> bool {
    mvm_core::config::vm_state_dir(vm_name)
        .join("egress-intermediate.json")
        .exists()
}

/// Point the workload's TLS stack at the guest-side egress CA bundle when one
/// is provisioned. An OCI entrypoint runs under `env_clear()` + the request
/// env, so these trust vars must ride the agent request/wrapper env. No CA
/// provisioned ⇒ env unchanged.
pub(crate) fn with_egress_ca_env(
    env: Vec<(String, String)>,
    egress_ca_present: bool,
) -> Vec<(String, String)> {
    if !egress_ca_present {
        return env;
    }
    let mut ca = vec![
        (
            "SSL_CERT_FILE".to_string(),
            EGRESS_CA_BUNDLE_PATH.to_string(),
        ),
        (
            "CURL_CA_BUNDLE".to_string(),
            EGRESS_CA_BUNDLE_PATH.to_string(),
        ),
        (
            "REQUESTS_CA_BUNDLE".to_string(),
            EGRESS_CA_BUNDLE_PATH.to_string(),
        ),
        (
            "NODE_EXTRA_CA_CERTS".to_string(),
            EGRESS_CA_CERT_PATH.to_string(),
        ),
    ];
    ca.extend(env);
    ca
}

pub(crate) fn inject_vm_egress_ca_env(
    vm_name: &str,
    env: Vec<(String, String)>,
) -> Vec<(String, String)> {
    with_egress_ca_env(env, egress_ca_present(vm_name))
}

#[cfg(test)]
mod tests {
    use super::{
        EGRESS_CA_BUNDLE_PATH, EGRESS_CA_CERT_PATH, inject_vm_egress_ca_env, with_egress_ca_env,
    };
    use mvm_core::util::test_env::TestEnv;
    use tempfile::tempdir;

    #[test]
    fn with_egress_ca_env_noop_when_absent() {
        let base = vec![("HTTP_PROXY".to_string(), "http://x".to_string())];
        assert_eq!(with_egress_ca_env(base.clone(), false), base);
    }

    #[test]
    fn with_egress_ca_env_prepends_ca_vars_before_existing() {
        let env = with_egress_ca_env(
            vec![("OPENAI_API_KEY".to_string(), "mvm-secret".to_string())],
            true,
        );
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "SSL_CERT_FILE")
                .map(|(_, v)| v.as_str()),
            Some(EGRESS_CA_BUNDLE_PATH)
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "CURL_CA_BUNDLE" && v == EGRESS_CA_BUNDLE_PATH)
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "REQUESTS_CA_BUNDLE" && v == EGRESS_CA_BUNDLE_PATH)
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "NODE_EXTRA_CA_CERTS" && v == EGRESS_CA_CERT_PATH)
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "OPENAI_API_KEY" && v == "mvm-secret")
        );
        let ca_at = env
            .iter()
            .position(|(k, _)| k == "SSL_CERT_FILE")
            .expect("CA env present");
        let key_at = env
            .iter()
            .position(|(k, _)| k == "OPENAI_API_KEY")
            .expect("placeholder env present");
        assert!(ca_at < key_at, "CA vars must precede the placeholder vars");
    }

    #[test]
    fn inject_vm_egress_ca_env_detects_sidecar_from_vm_state_dir() {
        let scratch = tempdir().expect("create tempdir");
        let mut env = TestEnv::new();
        env.set("MVM_DATA_DIR", scratch.path());

        let vm_state = mvm_core::config::vm_state_dir("vm-ca");
        std::fs::create_dir_all(&vm_state).expect("create vm state dir");
        std::fs::write(vm_state.join("egress-intermediate.json"), "{}")
            .expect("write egress intermediate marker");

        let resolved = inject_vm_egress_ca_env(
            "vm-ca",
            vec![("HTTPS_PROXY".to_string(), "http://guest".to_string())],
        );
        assert!(
            resolved
                .iter()
                .any(|(k, v)| k == "SSL_CERT_FILE" && v == EGRESS_CA_BUNDLE_PATH)
        );
        assert!(
            resolved
                .iter()
                .any(|(k, v)| k == "HTTPS_PROXY" && v == "http://guest")
        );
    }
}
