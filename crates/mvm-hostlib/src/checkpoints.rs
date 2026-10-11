//! Complete checkpoint operations; image-revert handoffs are not an ABI operation.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::checkpoint::{self, Checkpoints, wire};

pub const METHODS: &[&str] = &[
    "checkpoints.list",
    "checkpoints.info",
    "checkpoints.diff",
    "checkpoints.remove",
    "checkpoints.verify",
    "checkpoints.timeline",
    "checkpoints.capture",
    "checkpoints.restore",
    "checkpoints.fork",
];

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    let result = match method {
        "checkpoints.list" => {
            let _: wire::Empty = parse(request)?;
            Checkpoints::open().list().map(|reply| Outcome::ok(&reply))
        }
        "checkpoints.info" | "checkpoints.verify" => {
            let request: wire::IdRequest = parse(request)?;
            let id = checkpoint::validated_id(&request.id).map_err(error)?;
            if method == "checkpoints.info" {
                Checkpoints::open()
                    .read(&id)
                    .map(|reply| Outcome::ok(&reply))
            } else {
                Checkpoints::open()
                    .verify(&id)
                    .map(|()| Outcome::ok(&wire::Empty::default()))
            }
        }
        "checkpoints.diff" => {
            let request: wire::DiffRequest = parse(request)?;
            let a = checkpoint::validated_id(&request.a).map_err(error)?;
            let b = checkpoint::validated_id(&request.b).map_err(error)?;
            Checkpoints::open()
                .diff(&a, &b)
                .map(|reply| Outcome::ok(&reply))
        }
        "checkpoints.timeline" => {
            let request: wire::TimelineRequest = parse(request)?;
            Checkpoints::open()
                .timeline(&request.target, request.kind)
                .map(|reply| Outcome::ok(&reply))
        }
        "checkpoints.remove" => {
            let request: wire::Mutation<wire::IdRequest> = parse(request)?;
            let id = checkpoint::validated_id(&request.request.id).map_err(error)?;
            crate::declared()?;
            Checkpoints::open()
                .remove(&id)
                .map(|()| Outcome::ok(&wire::Empty::default()))
        }
        "checkpoints.capture" => {
            let request: wire::Mutation<checkpoint::CaptureRequest> = parse(request)?;
            crate::declared()?;
            Checkpoints::open()
                .capture(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        "checkpoints.restore" => {
            let request: wire::Mutation<checkpoint::RestoreRequest> = parse(request)?;
            crate::declared()?;
            Checkpoints::open()
                .restore(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        "checkpoints.fork" => {
            let request: wire::Mutation<wire::ForkRequest> = parse(request)?;
            let request = request.request.into_client().map_err(error)?;
            crate::declared()?;
            Checkpoints::open()
                .fork(
                    &request,
                    &mut mvm_client::entrypoint::CapturedOutput::default(),
                )
                .map(|reply| Outcome::ok(&reply))
        }
        _ => return Err(Outcome::invalid_input("unknown checkpoint method")),
    };
    result.map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn real_catalog_reports_and_guarded_refusals() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        assert_eq!(dispatch("checkpoints.list", b"{}").body, b"[]");
        let meta = mvm_core::checkpoint::CheckpointMeta::builder(
            mvm_core::checkpoint::CheckpointId::new("fixture"),
            mvm_core::checkpoint::CheckpointClass::FsQuick,
            "fixture-machine",
        )
        .build();
        let dir = mvm_core::config::checkpoints_dir().join(meta.id.as_str());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
        let info = dispatch("checkpoints.info", br#"{"id":"fixture"}"#);
        assert_eq!(info.status, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&info.body).unwrap()["id"],
            "fixture"
        );
        let diff = dispatch("checkpoints.diff", br#"{"a":"fixture","b":"fixture"}"#);
        assert_eq!(diff.status, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&diff.body).unwrap()["lineage"],
            "same"
        );
        let restore = dispatch(
            "checkpoints.restore",
            br#"{"intent":"execute","request":{"id":"fixture","tenant":"local"}}"#,
        );
        assert_ne!(restore.status, 0);
        assert!(String::from_utf8_lossy(&restore.body).contains("fork an fs_quick"));
        let verify = dispatch("checkpoints.verify", br#"{"id":"fixture"}"#);
        assert_ne!(verify.status, 0, "unsigned metadata must not verify");
        let capture = dispatch(
            "checkpoints.capture",
            br#"{"intent":"execute","request":{"name":"bad name!","class":"fs_quick"}}"#,
        );
        assert_ne!(capture.status, 0);
        let fork = dispatch(
            "checkpoints.fork",
            &serde_json::to_vec(&json!({
                "intent": "execute", "request": {"id": "fixture", "new_id": "fixture-machine",
                    "boot": false, "hypervisor": "", "tenant": "local"}
            }))
            .unwrap(),
        );
        assert_ne!(fork.status, 0);
        assert!(String::from_utf8_lossy(&fork.body).contains("fresh VM name"));
        assert_eq!(
            dispatch(
                "checkpoints.remove",
                br#"{"intent":"execute","request":{"id":"fixture"}}"#
            )
            .status,
            0
        );
        assert_eq!(dispatch("checkpoints.list", b"{}").body, b"[]");
    }

    #[test]
    fn strict_requests_and_no_partial_time_travel() {
        for method in METHODS {
            assert_eq!(
                dispatch(method, br#"{"raw_backend":{}}"#).status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
        for request in [
            br#"{"request":{"id":"a"}}"#.as_slice(),
            br#"{"intent":"preview","request":{"id":"a"}}"#,
            br#"{"intent":"execute","request":{"id":"a","root":"/outside"}}"#,
        ] {
            assert_eq!(
                dispatch("checkpoints.remove", request).status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
        assert_ne!(
            dispatch("checkpoints.info", br#"{"id":"../escape"}"#).status,
            0
        );
        for method in [
            "checkpoints.revert",
            "checkpoints.rewind",
            "checkpoints.advance",
        ] {
            assert!(!METHODS.contains(&method));
            assert_eq!(
                dispatch(method, b"{}").status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
    }
}
