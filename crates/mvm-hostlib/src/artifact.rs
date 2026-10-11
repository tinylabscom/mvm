//! Artifact-store operations delegated to the client.

use crate::status::Outcome;
use mvm_client::artifact::{ArtifactRequest, report};

pub const INSPECT: &str = "artifact.inspect";
pub const VALIDATE: &str = "artifact.validate";
pub const CONFIGURE_FIRECRACKER: &str = "artifact.configure_firecracker";
pub const METHODS: &[&str] = &[INSPECT, VALIDATE, CONFIGURE_FIRECRACKER];

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    let request: ArtifactRequest = match super::host_local::parse(request) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let result = match method {
        INSPECT => report::inspect(&request).map(|reply| Outcome::ok(&reply)),
        VALIDATE => report::validate(&request).map(|reply| Outcome::ok(&reply)),
        CONFIGURE_FIRECRACKER => {
            if let Err(outcome) = crate::declared() {
                return outcome;
            }
            report::configure_firecracker(&request).map(|reply| Outcome::ok(&reply))
        }
        _ => return Outcome::invalid_input("unknown artifact method"),
    };
    result.unwrap_or_else(super::host_local::error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_fixture_inspects_validates_and_configures() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let id = "01234567-89ab-4cde-8fab-0123456789ab";
        let dir = mvm_core::config::artifacts_dir().join(id);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = serde_json::json!({
            "artifact_id": id, "build_id": "fixture", "tenant_id": null,
            "arch": "x86_64", "backend": "firecracker",
            "kernel": {"path": "vmlinux", "format": "elf", "hash": "kernel", "version": null},
            "rootfs": {"path": "rootfs.ext4", "format": "ext4", "hash": "rootfs", "size": 4},
            "config_path": null, "provenance": {"flake_ref": "fixture", "lock_hash": null},
            "builder_version": "test", "timestamp_unix": 1, "validation": null
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("vmlinux"), b"\x7fELF").unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"root").unwrap();
        let input = serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
        let inspected = dispatch(INSPECT, &input);
        assert_eq!(inspected.status, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&inspected.body).unwrap(),
            manifest
        );
        let validated = dispatch(VALIDATE, &input);
        assert_eq!(
            validated.status,
            0,
            "{}",
            String::from_utf8_lossy(&validated.body)
        );
        let report: serde_json::Value = serde_json::from_slice(&validated.body).unwrap();
        assert!(report["checks"].is_array());
        let configured = dispatch(CONFIGURE_FIRECRACKER, &input);
        assert_eq!(
            configured.status,
            0,
            "{}",
            String::from_utf8_lossy(&configured.body)
        );
        assert!(dir.join("firecracker.json").is_file());
    }

    #[test]
    fn strict_requests_and_error_chains() {
        for method in METHODS {
            for body in [
                b"null".as_slice(),
                br#"{"id":"x","root":"/tmp"}"#,
                br#"{"id":2}"#,
            ] {
                assert_eq!(
                    dispatch(method, body).status,
                    crate::status::MVM_HOSTLIB_INVALID_INPUT
                );
            }
        }
        let input = ArtifactRequest {
            id: "../escape".into(),
        };
        let expected = report::inspect(&input).unwrap_err();
        let outcome = dispatch(INSPECT, &serde_json::to_vec(&input).unwrap());
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{expected:#}"))
        );
    }
}
