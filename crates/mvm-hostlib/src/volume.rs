//! Registered local volumes; policy and lifecycle remain client-owned.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::volume::{VolumeService, wire};

pub const LIST: &str = "volume.list";
pub const INSPECT: &str = "volume.inspect";
pub const CREATE: &str = "volume.create";
pub const UNLOCK: &str = "volume.unlock";
pub const LOCK: &str = "volume.lock";
pub const MOUNT: &str = "volume.mount";
pub const DETACH: &str = "volume.detach";
pub const ATTACHMENTS: &str = "volume.attachments";
pub const SNAPSHOT: &str = "volume.snapshot";
pub const RESTORE: &str = "volume.restore";
pub const METHODS: &[&str] = &[
    LIST,
    INSPECT,
    CREATE,
    UNLOCK,
    LOCK,
    MOUNT,
    DETACH,
    ATTACHMENTS,
    SNAPSHOT,
    RESTORE,
];

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    // Every service operation can perform lifecycle recovery and use helpers.
    // Decode first so malformed requests cannot initialize that machinery.
    let result = match method {
        LIST => {
            let _: wire::Empty = parse(request)?;
            crate::declared()?;
            wire::service()
                .list_volumes()
                .map(|reply| Outcome::ok(&reply))
        }
        INSPECT | UNLOCK | LOCK => {
            let request: wire::NameRequest = parse(request)?;
            crate::declared()?;
            let service = wire::service();
            let result = match method {
                INSPECT => service.describe_volume(&request.name),
                UNLOCK => service.unlock_volume(&request.name),
                _ => service.lock_volume(&request.name),
            };
            result.map(|reply| Outcome::ok(&reply))
        }
        CREATE => {
            let request: wire::CreateRequest = parse(request)?;
            crate::declared()?;
            wire::create(&request).map(|reply| Outcome::ok(&reply))
        }
        MOUNT => {
            let request: wire::MountRequest = parse(request)?;
            crate::declared()?;
            wire::mount(&request).map(|reply| Outcome::ok(&reply))
        }
        DETACH => {
            let request: wire::DetachRequest = parse(request)?;
            crate::declared()?;
            wire::service()
                .detach(&request.vm, &request.guest_path)
                .map(|reply| Outcome::ok(&reply))
        }
        ATTACHMENTS => {
            let request: wire::MachineRequest = parse(request)?;
            crate::declared()?;
            wire::service()
                .list_attachments(&request.vm)
                .map(|reply| Outcome::ok(&reply))
        }
        SNAPSHOT | RESTORE => {
            let request: wire::SnapshotRequest = parse(request)?;
            crate::declared()?;
            let service = wire::service();
            let result = if method == SNAPSHOT {
                service.snapshot_volume(&request.name, &request.snapshot)
            } else {
                service.restore_volume(&request.name, &request.snapshot)
            };
            result.map(|()| Outcome::ok(&wire::Empty::default()))
        }
        _ => return Err(Outcome::invalid_input("unknown volume method")),
    };
    result.map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_requests_and_empty_catalog() {
        for method in METHODS {
            for body in [b"null".as_slice(), br#"{"unexpected":true}"#] {
                assert_eq!(
                    dispatch(method, body).status,
                    crate::status::MVM_HOSTLIB_INVALID_INPUT
                );
            }
        }
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let outcome = dispatch(LIST, b"{}");
        assert_eq!(
            outcome.status,
            0,
            "{}",
            String::from_utf8_lossy(&outcome.body)
        );
        assert_eq!(outcome.body, b"[]");
        let request: wire::MountRequest =
            serde_json::from_slice(br#"{"vm":"a","volume":"b","guest_path":"/data"}"#).unwrap();
        assert!(request.access.is_read_only());
    }

    #[test]
    fn client_refusals_retain_context_without_accepting_keys_or_profiles() {
        for (method, request) in [
            (UNLOCK, br#"{"name":"work","key":[1,2,3]}"#.as_slice()),
            (
                MOUNT,
                br#"{"vm":"worker","volume":"work","guest_path":"/data","profile":"dev"}"#,
            ),
            (
                RESTORE,
                br#"{"name":"work","snapshot":"before","skip_verification":true}"#,
            ),
        ] {
            assert_eq!(
                dispatch(method, request).status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
        let request = wire::CreateRequest {
            name: "../outside".into(),
            capacity_mib: 16,
            root: None,
        };
        let expected = wire::create(&request).unwrap_err();
        let outcome = dispatch(CREATE, &serde_json::to_vec(&request).unwrap());
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{expected:#}"))
        );
    }
}
