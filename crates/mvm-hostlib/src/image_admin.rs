//! Canonical offline revocation administration; no acquisition or trust override.

use std::path::Path;

use mvm_client::image_admin::revocations as client;
use serde::{Deserialize, Serialize};

use crate::{
    host_local::{error, parse},
    status::Outcome,
};

pub const UPDATE: &str = "image_revocations.update";
pub const STATUS: &str = "image_revocations.status";
pub const METHODS: &[&str] = &[UPDATE, STATUS];

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "ImageRevocationsEmpty"))]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    pub document_path: String,
    pub bundle_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CheckpointReport {
    pub publication: u64,
    pub issued_at: String,
    pub sha256: String,
}

impl From<&client::ImageSetRevocationCheckpoint> for CheckpointReport {
    fn from(checkpoint: &client::ImageSetRevocationCheckpoint) -> Self {
        Self {
            publication: checkpoint.publication,
            issued_at: checkpoint.issued_at.to_rfc3339(),
            sha256: checkpoint.sha256.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    pub publication: u64,
    pub issued_at: String,
    pub sha256: String,
    pub signer_identity: String,
    pub not_after: String,
    pub entries: usize,
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        UPDATE => {
            let request: UpdateRequest = parse(request)?;
            let checkpoint = client::update(
                Path::new(&request.document_path),
                Path::new(&request.bundle_path),
            )
            .map_err(error)?;
            Ok(Outcome::ok(&CheckpointReport::from(&checkpoint)))
        }
        STATUS => {
            let _: Empty = parse(request)?;
            let status = client::status().map_err(error)?;
            let checkpoint = status.checkpoint();
            Ok(Outcome::ok(&StatusReport {
                publication: checkpoint.publication,
                issued_at: checkpoint.issued_at.to_rfc3339(),
                sha256: checkpoint.sha256.as_str().to_owned(),
                signer_identity: status.signer_identity().into(),
                not_after: status.not_after().to_rfc3339(),
                entries: status.entry_count(),
            }))
        }
        _ => Err(Outcome::invalid_input("unknown image revocation method")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_input_refuses_overrides_and_duplicate_fields_before_store_access() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        for method in METHODS {
            for input in [
                "",
                "null",
                "[]",
                "42",
                "\"private-marker\"",
                r#"{"root":"x"}"#,
            ] {
                let refused = dispatch(method, input.as_bytes());
                assert_eq!(refused.status, 8);
                assert!(
                    !String::from_utf8(refused.body)
                        .unwrap()
                        .contains("private-marker")
                );
            }
        }
        for input in [
            r#"{"document_path":"d","bundle_path":"b","issuer":"x"}"#,
            r#"{"document_path":"d","document_path":"e","bundle_path":"b"}"#,
            r#"{"document_path":"d","bundle_path":"b","bundle_path":"c"}"#,
            r#"{"document_path":"d","bundle_path":null}"#,
            r#"["document","bundle"]"#,
        ] {
            assert_eq!(dispatch(UPDATE, input.as_bytes()).status, 8);
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn canonical_refusals_do_not_establish_an_applied_list() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        assert_ne!(dispatch(STATUS, b"{}").status, 0);
        let document = root.path().join("document");
        let bundle = root.path().join("bundle");
        std::fs::write(&document, b"{}").unwrap();
        std::fs::write(&bundle, b"not a bundle").unwrap();
        let request = serde_json::to_vec(&UpdateRequest {
            document_path: document.to_string_lossy().into_owned(),
            bundle_path: bundle.to_string_lossy().into_owned(),
        })
        .unwrap();
        assert!(client::update(&document, &bundle).is_err());
        assert_ne!(dispatch(UPDATE, &request).status, 0);
        let store = mvm_core::config::image_set_revocation_store_dir();
        assert!(!store.join("feed.json").exists());
        assert!(!store.join("checkpoint.json").exists());
    }
}
