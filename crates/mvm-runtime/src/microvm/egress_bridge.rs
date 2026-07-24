//! Shared kernel-cmdline token builders for governed workload grants.
//!
//! Firecracker's old bridge, TAP redirect, and pre-boot endpoint machinery
//! was retired with the raw launch path. These tokens remain shared by the
//! runner-backed libkrun, HVF, and QEMU command-line builders.

/// The `mvm.verb_grant=<hex>` kernel-cmdline token for `vm_name`.
pub(crate) fn verb_grant_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    let bytes = std::fs::read(&path).ok()?;
    let envelope: mvm_core::protocol::vm_backend::VerbGrantEnvelope =
        serde_json::from_slice(&bytes).ok()?;
    mvm_core::vm_backend::encode_verb_grant_cmdline(&envelope)
}

/// The `mvm.require_grant=1` token when a verb-grant sidecar exists.
pub(crate) fn require_grant_cmdline_token(vm_name: &str) -> Option<String> {
    let path = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    path.exists().then(|| "mvm.require_grant=1".to_string())
}

const HOST_SIGNER_PUBKEY_FILENAME: &str = "host-signer.pub";

/// The public host-signer key token used to verify an admitted verb grant.
pub(crate) fn host_signer_pub_cmdline_token(vm_name: &str) -> Option<String> {
    let sidecar = mvm_core::config::vm_state_dir(vm_name).join("verb-grant.json");
    if !sidecar.exists() {
        return None;
    }
    let pubkey_path = mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_PUBKEY_FILENAME);
    let bytes = std::fs::read(&pubkey_path).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("mvm.host_signer_pub={hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_tokens_require_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let vm_name = "missing-grant";
        assert!(verb_grant_cmdline_token(vm_name).is_none());
        assert!(require_grant_cmdline_token(vm_name).is_none());
        assert!(host_signer_pub_cmdline_token(vm_name).is_none());
    }

    #[test]
    fn require_grant_token_keys_only_on_file_existence() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let state = mvm_core::config::vm_state_dir("grant");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("verb-grant.json"), b"not-json").unwrap();
        assert_eq!(
            require_grant_cmdline_token("grant").as_deref(),
            Some("mvm.require_grant=1")
        );
        assert!(verb_grant_cmdline_token("grant").is_none());
    }

    #[test]
    fn host_signer_token_requires_a_32_byte_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let state = mvm_core::config::vm_state_dir("grant");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("verb-grant.json"), b"{}").unwrap();
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join(HOST_SIGNER_PUBKEY_FILENAME), [0u8; 31]).unwrap();
        assert!(host_signer_pub_cmdline_token("grant").is_none());
        std::fs::write(keys.join(HOST_SIGNER_PUBKEY_FILENAME), [0xABu8; 32]).unwrap();
        assert_eq!(
            host_signer_pub_cmdline_token("grant").as_deref(),
            Some(
                "mvm.host_signer_pub=abababababababababababababababababababababababababababababababab"
            )
        );
    }
}
