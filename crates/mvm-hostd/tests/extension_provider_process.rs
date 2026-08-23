//! Process-level conformance for the generic admitted-provider executable.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use mvm_contract::assurance::CampaignProviderResponse;
use mvm_contract::protocol::extension_controller::{
    ExtensionFrame, ExtensionMessageKind, decode_extension_frame, encode_extension_frame,
};

const MAX_PAYLOAD: usize = 1024 * 1024;

fn write_boot_config(state: &Path) {
    let config = serde_json::json!({
        "schema": "mvm.assurance.provider-boot-config/v1",
        "tenant": "assurance-tenant",
        "host_mvm_home": state,
        "extension": {
            "pack_root": state.join("unavailable-extension-pack"),
            "trust_config": state.join("unavailable-pack-trust.json"),
            "expected_pack_digest": "1111111111111111111111111111111111111111111111111111111111111111",
            "expected_extension_id": "org.tinylabs.scoutd",
            "expected_version": "0.3.0",
            "policy_compatibility_hash": "2222222222222222222222222222222222222222222222222222222222222222",
            "budgets": {
                "cpu_millis": 30000,
                "memory_bytes": 268435456,
                "duration_ms": 120000,
                "max_steps": 12,
                "max_concurrency": 1,
                "max_payload_bytes": 524288,
                "max_output_bytes": 65536,
                "max_artifact_bytes": 67108864
            }
        },
        "workload": {
            "image_name": "assurance-workload",
            "rootfs_path": state.join("unavailable-rootfs.ext4"),
            "artifact_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "kernel_path": null,
            "kernel_digest": null,
            "verity_path": null,
            "roothash": null,
            "backend": "firecracker",
            "cpus": 1,
            "memory_mib": 256,
            "boot_timeout_seconds": 60
        },
        "policy": {
            "network_policy_ref": "provider-deny-all-v1",
            "egress_policy_ref": "provider-deny-all-v1",
            "fs_policy_ref": "provider-readonly-v1",
            "tool_policy_ref": "provider-assurance-probe-v1"
        },
        "authority": {
            "ceiling": {
                "tools": ["campaign_probe.v1"],
                "scopes": ["guest.stdout.digest", "host.audit.refs"],
                "max_steps": 12,
                "max_output_bytes": 65536
            },
            "approved_tools": ["campaign_probe.v1"],
            "grant_ttl_ms": 600000
        },
        "destinations": [{
            "label": "undeclared.synthetic.destination",
            "host": "synthetic.invalid",
            "port": 443,
            "allow_egress": false
        }]
    });
    let path = state.join("boot-config.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&config).expect("encode boot config"),
    )
    .expect("write boot config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("boot config mode");
    }
}

fn frame(kind: ExtensionMessageKind, sequence: u64, payload: &[u8]) -> Vec<u8> {
    encode_extension_frame(
        &ExtensionFrame {
            kind,
            sequence,
            payload: payload.to_vec(),
        },
        MAX_PAYLOAD,
    )
    .expect("fixture frame encodes")
}

/// Path to the provider binary under test.
///
/// `CARGO_BIN_EXE_<name>` is a **compile-time** variable cargo provides to
/// `env!`. `cargo test` also happens to export it into the test process, so
/// reading it at runtime worked there and failed under `cargo nextest`, which
/// runs the test binary directly — and nextest is the named gate. Resolving it
/// at compile time works under both.
fn provider_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mvm-extension-provider")
}

#[test]
fn provider_process_injects_configured_runner_and_fails_closed_without_admitted_boot() {
    let state = tempfile::tempdir().expect("provider state");
    write_boot_config(state.path());
    let mut child = Command::new(provider_bin())
        .arg("--state-root")
        .arg(state.path())
        .env_clear()
        .env("MVM_HOME", state.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start provider process");

    let bundle = include_bytes!("../../mvm-contract/fixtures/operator-session-bundle-v1.json");
    let request = include_bytes!("../../mvm-contract/fixtures/campaign-provider-request-v1.json");
    let mut input = frame(ExtensionMessageKind::Hello, 1, &[]);
    input.extend(frame(ExtensionMessageKind::OpenSession, 2, bundle));
    input.extend(frame(ExtensionMessageKind::Start, 3, request));
    input.extend(frame(ExtensionMessageKind::Shutdown, 4, &[]));

    child
        .stdin
        .take()
        .expect("provider stdin")
        .write_all(&input)
        .expect("write provider frames");

    let mut output = Vec::new();
    child
        .stdout
        .take()
        .expect("provider stdout")
        .read_to_end(&mut output)
        .expect("read provider frames");
    let status = child.wait().expect("wait for provider");
    assert!(status.success(), "provider exited with {status}");

    let (descriptor, first) = decode_extension_frame(&output, MAX_PAYLOAD).expect("descriptor");
    assert_eq!(descriptor.kind, ExtensionMessageKind::Describe);
    assert!(String::from_utf8_lossy(&descriptor.payload).contains("mvm.boundary.campaign.v1"));

    let (opened, second) =
        decode_extension_frame(&output[first..], MAX_PAYLOAD).expect("open-session response");
    assert_eq!(opened.kind, ExtensionMessageKind::Complete);
    assert!(String::from_utf8_lossy(&opened.payload).contains("session_count"));

    let (completed, third) =
        decode_extension_frame(&output[first + second..], MAX_PAYLOAD).expect("start response");
    assert_eq!(completed.kind, ExtensionMessageKind::Complete);
    let response: CampaignProviderResponse =
        serde_json::from_slice(&completed.payload).expect("provider response");
    assert_eq!(response.status, "inconclusive_evidence");
    assert!(!response.certifying);
    assert!(response.evidence.is_empty());
    assert!(
        response
            .missing_brokers
            .iter()
            .any(|broker| broker == "mvm.assurance.admitted_boot")
    );
    assert!(
        response
            .missing_brokers
            .iter()
            .all(|broker| broker != "mvm.extension.admitted_campaign_runner"),
        "the executable must not inject the retired placeholder runner"
    );

    let (shutdown, fourth) = decode_extension_frame(&output[first + second + third..], MAX_PAYLOAD)
        .expect("shutdown response");
    assert_eq!(shutdown.kind, ExtensionMessageKind::Complete);
    assert_eq!(first + second + third + fourth, output.len());

    let journal = state.path().join("mvm-request-1.json");
    assert!(
        journal.is_file(),
        "the explicit durable root owns replay state"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            std::fs::metadata(state.path())
                .expect("state root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(journal)
                .expect("journal metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn provider_process_never_uses_ambient_home_or_mvm_state() {
    let ambient = tempfile::tempdir().expect("ambient trap");
    let output = Command::new(provider_bin())
        .env_clear()
        .env("HOME", ambient.path())
        .env("MVM_HOME", ambient.path())
        .output()
        .expect("run provider without explicit state");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--state-root is required"));
    assert!(
        std::fs::read_dir(ambient.path())
            .expect("ambient trap")
            .next()
            .is_none(),
        "ambient paths must remain untouched"
    );
}

#[test]
fn provider_refuses_boot_config_without_an_explicit_matching_global_mvm_home() {
    let state = tempfile::tempdir().expect("provider state");
    write_boot_config(state.path());
    let output = Command::new(provider_bin())
        .arg("--state-root")
        .arg(state.path())
        .env_clear()
        .output()
        .expect("run provider without global MVM home");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("explicitly establish the global MVM home")
    );
    assert!(
        !state.path().join("host-signing-keys").exists(),
        "an unbound host state root must fail before signing state is initialized"
    );
}
