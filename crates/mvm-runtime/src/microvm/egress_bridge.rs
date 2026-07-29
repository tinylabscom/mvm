//! Shared kernel-cmdline token builders for governed workload grants.
//!
//! Firecracker's old bridge, TAP redirect, and pre-boot endpoint machinery
//! was retired with the raw launch path. These tokens remain shared by the
//! runner-backed libkrun, HVF, and QEMU command-line builders.

/// The `mvm.verb_grant=<base64>` kernel-cmdline token for `vm_name`.
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

/// The host's public signing key, pinned into every guest as the anchor its
/// agent authenticates the control channel against.
///
/// Deliberately NOT gated on the verb-grant sidecar. The host-signer key is host
/// *identity* — who the guest is talking to — while a verb grant is workload
/// *authority*, what that workload may ask for. They are separate questions, and
/// tying the anchor to the grant meant a launch that mints no grant (the
/// transient run path, and a factory standby parent) shipped no anchor either:
/// the agent then rejects every control connection for want of a pinned key and
/// the run dies at the first RPC.
///
/// Withholding the grant still withholds authority — `mvm.verb_grant` and
/// `mvm.require_grant` below remain sidecar-gated, so a guest that gets only
/// this token is reachable but no more privileged than before.
pub(crate) fn host_signer_pub_cmdline_token(vm_name: &str) -> Option<String> {
    let _ = vm_name;
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

    /// Authority tokens stay sidecar-gated: no grant, no verbs.
    #[test]
    fn grant_tokens_require_the_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let vm_name = "missing-grant";
        assert!(verb_grant_cmdline_token(vm_name).is_none());
        assert!(require_grant_cmdline_token(vm_name).is_none());
    }

    /// The host-identity anchor ships even when no grant is minted. Gating it on
    /// the sidecar left the transient run path (which mints none) with no pinned
    /// key, so the agent refused every control connection and the run died at
    /// its first RPC. Identity is not authority.
    #[test]
    fn host_signer_token_ships_without_a_grant_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join(HOST_SIGNER_PUBKEY_FILENAME), [0xABu8; 32]).unwrap();

        let vm_name = "no-grant-but-reachable";
        assert!(
            host_signer_pub_cmdline_token(vm_name).is_some(),
            "a guest with no verb grant must still be able to authenticate the host"
        );
        // ...and it gains no authority from that.
        assert!(verb_grant_cmdline_token(vm_name).is_none());
        assert!(require_grant_cmdline_token(vm_name).is_none());
    }

    /// No host key on disk is still no token — the anchor is only emitted when
    /// there is a real key to pin.
    #[test]
    fn host_signer_token_absent_when_the_host_has_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        assert!(host_signer_pub_cmdline_token("no-key").is_none());
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
