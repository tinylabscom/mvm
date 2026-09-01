//! Cfg-free HVF workload boot-args helpers.
//!
//! The raw-HVF boot flow is macOS-only, but the workload cmdline choice is pure
//! string assembly and is shared by cfg-free backend glue that still compiles on
//! Linux CI. Keep that helper out of the macOS-only `crate::hvf` module.

use mvm_vmm::vmm::fdt;

const UART_BASE: u64 = fdt::SERIAL_MMIO_BASE;

/// Cmdline used for block-rootfs workload boots.
pub fn default_bootargs(has_disk: bool) -> String {
    let mut args =
        format!("earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8");
    if has_disk {
        args.push_str(" root=/dev/vda ro init=/init");
    }
    args
}

/// Default workload kernel cmdline.
pub fn workload_bootargs(has_disk: bool) -> String {
    default_bootargs(has_disk)
}

#[cfg(test)]
mod tests {
    fn grant_tokens(vm_name: &str) -> Vec<String> {
        [
            mvm_vmm::host::egress_bridge::verb_grant_cmdline_token(vm_name),
            mvm_vmm::host::egress_bridge::require_grant_cmdline_token(vm_name),
            mvm_vmm::host::egress_bridge::host_signer_pub_cmdline_token(vm_name),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn seed_grant_sidecar_and_key(vm_name: &str) {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        let nonce = Nonce::from_bytes([3u8; 16]);
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "cc".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: VerbGrant {
                session_id: vm_name.to_string(),
                plan_nonce: nonce,
                not_after,
                verbs: vec![VerbId::new("run-entrypoint").unwrap()],
                sig: vec![0u8; 64],
            },
        };
        std::fs::write(
            state_dir.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
    }

    #[test]
    fn grant_tokens_appends_all_three_for_parity_with_libkrun() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        let vm_name = "hvf-grant-parity";
        seed_grant_sidecar_and_key(vm_name);

        let tokens = grant_tokens(vm_name);
        assert_eq!(tokens.len(), 3, "must emit all three grant tokens");
        assert!(tokens[0].starts_with("mvm.verb_grant="), "verb grant first");
        assert_eq!(
            tokens[1],
            mvm_vmm::host::egress_bridge::require_grant_cmdline_token(vm_name).unwrap(),
            "enforcement token matches the canonical emitter"
        );
        assert!(
            tokens[2].starts_with("mvm.host_signer_pub="),
            "trust anchor last"
        );
    }

    #[test]
    fn grant_tokens_empty_without_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());

        assert!(
            grant_tokens("hvf-no-grant").is_empty(),
            "no sidecar ⇒ no grant tokens"
        );
    }
}
