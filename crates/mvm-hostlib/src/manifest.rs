//! Built-manifest inspection over the shared client facade.
//!
//! These local registry operations need neither a running machine nor guest
//! helpers. Requests and reports are owned by the client, not re-modeled here.

use mvm_client::manifest::{self, InfoRequest, ListRequest, PruneRequest, VerifyRequest};
use mvm_core::client::MvmError;

use crate::status::Outcome;

pub const LIST: &str = "manifest.list";
pub const INFO: &str = "manifest.info";
pub const VERIFY: &str = "manifest.verify";
pub const REMOVE: &str = "manifest.remove";
pub const PRUNE: &str = "manifest.prune";
pub const METHODS: &[&str] = &[LIST, INFO, VERIFY, REMOVE, PRUNE];

/// Remove one built slot. There is deliberately no way to name a source file:
/// the client's path resolution accepts any regular file, so deleting one over
/// this surface would delete arbitrary files. Only the registry slot is removed.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveRequest {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    force: bool,
}

/// The slot `manifest.remove` deleted.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Serialize)]
pub(crate) struct RemovedSlot {
    slot_hash: String,
    manifest_path: String,
}

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        LIST => {
            let request: ListRequest = parse(request)?;
            manifest::list(&request).map(|reply| Outcome::ok(&reply))
        }
        INFO => {
            let request: InfoRequest = parse(request)?;
            manifest::info(&request).map(|reply| Outcome::ok(&reply))
        }
        VERIFY => {
            let request: VerifyRequest = parse(request)?;
            manifest::verify(&request).map(|reply| Outcome::ok(&reply))
        }
        REMOVE => {
            let request: RemoveRequest = parse(request)?;
            manifest::remove(&manifest::RemoveRequest {
                path: request.path,
                force: request.force,
                manifest_file: false,
            })
            .map(|removed| {
                Outcome::ok(&RemovedSlot {
                    slot_hash: removed.slot_hash,
                    manifest_path: removed.manifest_path.display().to_string(),
                })
            })
        }
        PRUNE => {
            let request: PruneRequest = parse(request)?;
            manifest::prune(&request).map(|reply| Outcome::ok(&reply))
        }
        _ => {
            return Err(Outcome::invalid_input(&format!(
                "unknown method `{method}`"
            )));
        }
    }
    .map_err(|error| {
        // A typed client refusal (not found, invalid spec) keeps its code.
        match error
            .chain()
            .find_map(|cause| cause.downcast_ref::<MvmError>())
        {
            Some(typed) => Outcome::from(typed.clone()),
            None => Outcome::from(MvmError::Backend {
                reason: format!("{error:#}"),
            }),
        }
    })
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|error| Outcome::invalid_input(&format!("invalid request JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT};

    #[test]
    fn requests_reject_unknown_fields_and_wrong_types() {
        for method in METHODS {
            for request in [br#"{"unexpected":true}"#.as_slice(), b"null", b"not json"] {
                assert_eq!(
                    dispatch(method, request).status,
                    MVM_HOSTLIB_INVALID_INPUT,
                    "{method}"
                );
            }
        }
        assert_eq!(
            dispatch(LIST, br#"{"orphans":"yes"}"#).status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }

    #[test]
    fn signature_refusal_preserves_the_facade_error_chain() {
        let request = br#"{"check_signature":true}"#;
        let error = manifest::verify(&serde_json::from_slice(request).unwrap()).unwrap_err();
        let outcome = dispatch(VERIFY, request);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{error:#}"))
        );
        assert_eq!(body["retryable"], false);
    }

    #[test]
    fn missing_manifest_preserves_the_facade_error_chain() {
        let dir = tempfile::tempdir().unwrap();
        let request = serde_json::json!({"path": dir.path().join("absent.toml")});
        let bytes = serde_json::to_vec(&request).unwrap();
        let error = manifest::info(&serde_json::from_slice(&bytes).unwrap()).unwrap_err();
        let outcome = dispatch(INFO, &bytes);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
        let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains(&format!("{error:#}"))
        );
    }

    #[test]
    fn only_the_listed_methods_are_known() {
        for method in METHODS {
            assert!(is_known(method));
        }
        assert_eq!(
            METHODS,
            [
                "manifest.list",
                "manifest.info",
                "manifest.verify",
                "manifest.remove",
                "manifest.prune"
            ]
        );
        assert!(!is_known("manifest.delete"));
        assert_eq!(
            dispatch("manifest.delete", b"{}").status,
            MVM_HOSTLIB_INVALID_INPUT
        );
    }

    /// An isolated home holding one manifest file with a built slot.
    fn built_slot() -> (
        tempfile::TempDir,
        mvm_core::util::test_env::TestEnv,
        std::path::PathBuf,
        String,
    ) {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let manifest = home.path().join("src").join("mvm.toml");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, "flake = \".\"\nprofile = \"default\"\n").unwrap();
        let canonical = manifest.canonicalize().unwrap();
        let slot = mvm_core::manifest::canonical_key_for_path(&canonical).unwrap();
        let dir = mvm_core::manifest::slot_dir(&slot);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/manifest.json"), "{}").unwrap();
        (home, env, canonical, slot)
    }

    fn body(outcome: &Outcome) -> serde_json::Value {
        serde_json::from_slice(&outcome.body).unwrap()
    }

    #[test]
    fn remove_deletes_the_slot_and_keeps_the_source_file_by_default() {
        let (_home, _env, path, slot) = built_slot();
        let request = serde_json::json!({"path": path});
        let outcome = dispatch(REMOVE, &serde_json::to_vec(&request).unwrap());
        assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_OK);
        let reply = body(&outcome);
        assert_eq!(reply["slot_hash"], slot);
        assert!(reply.get("manifest_file_deleted").is_none());
        assert!(!std::path::Path::new(&mvm_core::manifest::slot_dir(&slot)).exists());
        assert!(path.exists());
    }

    #[test]
    fn remove_refuses_manifest_file_and_never_touches_a_file_on_disk() {
        let (_home, _env, path, slot) = built_slot();
        let bystander = path.with_file_name("precious.txt");
        std::fs::write(&bystander, "keep").unwrap();
        for request in [
            serde_json::json!({"path": path, "manifest_file": true}),
            serde_json::json!({"path": bystander, "force": true, "manifest_file": true}),
        ] {
            let outcome = dispatch(REMOVE, &serde_json::to_vec(&request).unwrap());
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
        }
        assert!(path.exists() && bystander.exists());
        assert!(std::path::Path::new(&mvm_core::manifest::slot_dir(&slot)).exists());
    }

    #[test]
    fn forced_remove_of_a_plain_file_leaves_the_file_alone() {
        let (_home, _env, path, _slot) = built_slot();
        let bystander = path.with_file_name("precious.txt");
        std::fs::write(&bystander, "keep").unwrap();
        let request = serde_json::json!({"path": bystander, "force": true});
        let outcome = dispatch(REMOVE, &serde_json::to_vec(&request).unwrap());
        assert_eq!(body(&outcome).get("manifest_file_deleted"), None);
        assert_eq!(std::fs::read_to_string(&bystander).unwrap(), "keep");
        assert!(path.exists());
    }

    #[test]
    fn removing_a_missing_slot_is_a_typed_not_found_unless_forced() {
        let (_home, _env, path, slot) = built_slot();
        std::fs::remove_dir_all(mvm_core::manifest::slot_dir(&slot)).unwrap();
        let request = serde_json::json!({"path": path});
        let outcome = dispatch(REMOVE, &serde_json::to_vec(&request).unwrap());
        assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_NOT_FOUND);
        assert_eq!(body(&outcome)["code"], mvm_core::error_codes::NOT_FOUND);
        assert!(path.exists());
        let request = serde_json::json!({"path": path, "force": true});
        assert_eq!(
            dispatch(REMOVE, &serde_json::to_vec(&request).unwrap()).status,
            crate::status::MVM_HOSTLIB_OK
        );
    }

    #[test]
    fn prune_with_nothing_to_prune_returns_an_empty_list() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let outcome = dispatch(PRUNE, br#"{"orphans":true}"#);
        assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_OK);
        assert_eq!(body(&outcome), serde_json::json!([]));
    }

    #[test]
    fn prune_dry_run_reports_and_a_real_prune_removes_orphans() {
        let (_home, _env, path, slot) = built_slot();
        let persisted = mvm_core::manifest::slot_dir(&slot);
        std::fs::write(
            format!("{persisted}/manifest.json"),
            serde_json::json!({"manifest_path": path.with_file_name("gone.toml")}).to_string(),
        )
        .unwrap();
        let dry = dispatch(PRUNE, br#"{"orphans":true,"dry_run":true}"#);
        assert_eq!(dry.status, crate::status::MVM_HOSTLIB_OK);
        assert_eq!(body(&dry)[0]["slot_hash"], slot);
        assert!(std::path::Path::new(&persisted).exists());
        let real = dispatch(PRUNE, br#"{"orphans":true}"#);
        assert_eq!(real.status, crate::status::MVM_HOSTLIB_OK);
        assert_eq!(body(&real)[0]["slot_hash"], slot);
        assert!(!std::path::Path::new(&persisted).exists());
    }

    #[test]
    fn prune_without_a_named_mode_is_refused_and_deletes_nothing() {
        let (_home, _env, _path, slot) = built_slot();
        let outcome = dispatch(PRUNE, b"{}");
        assert_eq!(body(&outcome)["code"], mvm_core::error_codes::INVALID_SPEC);
        assert!(std::path::Path::new(&mvm_core::manifest::slot_dir(&slot)).exists());
    }

    #[test]
    fn mutating_requests_refuse_unknown_and_mistyped_fields() {
        for (method, request) in [
            (REMOVE, br#"{"force":"yes"}"#.as_slice()),
            (REMOVE, br#"{"path":null,"recursive":true}"#),
            (PRUNE, br#"{"orphans":true,"all":true}"#),
            (PRUNE, br#"{"dry_run":1}"#),
        ] {
            assert_eq!(dispatch(method, request).status, MVM_HOSTLIB_INVALID_INPUT);
        }
    }
}
