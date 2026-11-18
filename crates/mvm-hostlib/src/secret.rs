//! Host-local secret metadata lookup, using the same audited service as the CLI.

use mvm_client::secret::SecretService;

use crate::{host_local, status::Outcome};

/// Metadata-only lookup. An absent secret succeeds with JSON `null`.
pub const GET: &str = "secret.get";
/// The sole host-local secret method exposed by this ABI.
pub const METHODS: &[&str] = &[GET];

/// A scope and secret name only; no value, store override, or reveal option.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GetRequest {
    tenant: String,
    name: String,
}

pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    if method != GET {
        return Outcome::invalid_input("unknown secret method");
    }
    let request = match host_local::parse::<GetRequest>(request) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    if mvm_core::crypto::keystore::validate_shell_id(&request.tenant).is_err()
        || mvm_core::crypto::keystore::validate_shell_id(&request.name).is_err()
    {
        return Outcome::invalid_input("invalid secret scope or name");
    }
    match SecretService::local() {
        Ok(service) => lookup(&service, &request),
        Err(_) => host_local::error(anyhow::anyhow!("opening local secret service failed")),
    }
}

fn lookup(service: &SecretService, request: &GetRequest) -> Outcome {
    match service.metadata(&request.tenant, &request.name) {
        Ok(metadata) => Outcome::ok(&metadata),
        Err(_) => host_local::error(anyhow::anyhow!("secret metadata lookup failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_OK};
    use mvm_client::secret::{SecretAudit, SecretValueInput};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use std::sync::Arc;

    struct ListOnlyStore;

    impl SecretStore for ListOnlyStore {
        fn put(
            &self,
            _tenant: &str,
            _name: &str,
            _value: &secrecy::SecretBox<String>,
        ) -> anyhow::Result<()> {
            anyhow::bail!("write not expected")
        }

        fn get(&self, _tenant: &str, _name: &str) -> anyhow::Result<secrecy::SecretBox<String>> {
            panic!("a metadata lookup must never read stored material")
        }

        fn delete(&self, _tenant: &str, _name: &str) -> anyhow::Result<()> {
            anyhow::bail!("delete not expected")
        }

        fn list(&self, _tenant: &str) -> anyhow::Result<Vec<String>> {
            Ok(vec!["sample".into()])
        }
    }

    #[test]
    fn lookup_never_reads_stored_material() {
        let temp = tempfile::tempdir().unwrap();
        let service = SecretService::builder()
            .store(Arc::new(ListOnlyStore))
            .bindings(Arc::new(
                mvm_client::secret::keyholder::FileBindingStore::with_dir(
                    temp.path().join("bindings"),
                ),
            ))
            .machines_root(temp.path().join("machines"))
            .build()
            .unwrap();
        let outcome = lookup(
            &service,
            &GetRequest {
                tenant: "local".into(),
                name: "sample".into(),
            },
        );
        assert_eq!(outcome.status, MVM_HOSTLIB_OK);
        assert!(!String::from_utf8(outcome.body).unwrap().contains("value"));
    }

    #[test]
    fn lookup_returns_only_metadata_and_audits_hits_misses_and_faults() {
        let temp = tempfile::tempdir().unwrap();
        let audit_path = temp.path().join("audit.jsonl");
        let store_dir = temp.path().join("values");
        let service = SecretService::builder()
            .store(Arc::new(FileSecretStore::with_dir(&store_dir)))
            .bindings(Arc::new(
                mvm_client::secret::keyholder::FileBindingStore::with_dir(
                    temp.path().join("bindings"),
                ),
            ))
            .machines_root(temp.path().join("machines"))
            .audit(SecretAudit::with_path(audit_path.clone()))
            .build()
            .unwrap();
        let request = GetRequest {
            tenant: "local".into(),
            name: "sample".into(),
        };
        let missing = lookup(&service, &request);
        assert_eq!(missing.status, MVM_HOSTLIB_OK);
        assert_eq!(missing.body, b"null");

        service
            .put(
                "local",
                "sample",
                SecretValueInput::new("private-marker".into()),
            )
            .unwrap();
        let hit = lookup(&service, &request);
        assert_eq!(hit.status, MVM_HOSTLIB_OK);
        let value: serde_json::Value = serde_json::from_slice(&hit.body).unwrap();
        assert_eq!(value["name"], "sample");
        assert_eq!(value["tenant"], "local");
        assert!(value["binding"].is_null());
        assert_eq!(value["referenced_by"], serde_json::json!([]));
        assert!(
            !String::from_utf8(hit.body)
                .unwrap()
                .contains("private-marker")
        );

        let binding = temp.path().join("bindings/local/sample.json");
        std::fs::create_dir_all(binding.parent().unwrap()).unwrap();
        std::fs::write(&binding, br#"{"auth_type":"private-marker"}"#).unwrap();
        let malformed = lookup(&service, &request);
        assert_eq!(malformed.status, MVM_HOSTLIB_BACKEND);
        assert!(
            !String::from_utf8(malformed.body)
                .unwrap()
                .contains("private-marker")
        );
        std::fs::remove_file(binding).unwrap();

        // A store fault must not masquerade as an absent secret.
        std::fs::remove_dir_all(store_dir.join("local")).unwrap();
        std::fs::write(store_dir.join("local"), "not a directory").unwrap();
        let fault = lookup(&service, &request);
        assert_eq!(fault.status, MVM_HOSTLIB_BACKEND);
        assert!(
            !String::from_utf8(fault.body)
                .unwrap()
                .contains("private-marker")
        );
        let audit = std::fs::read_to_string(audit_path).unwrap();
        let outcomes: Vec<&str> = audit
            .lines()
            .filter_map(|line| {
                let event: serde_json::Value = serde_json::from_str(line).unwrap();
                (event["action"] == "get").then(|| match event["outcome"].as_str().unwrap() {
                    "miss" => "miss",
                    "ok" => "ok",
                    "err" => "err",
                    other => panic!("unexpected audit outcome {other}"),
                })
            })
            .collect();
        assert_eq!(outcomes, ["miss", "ok", "err", "err"]);
        assert!(!audit.contains("private-marker"));
    }

    #[test]
    fn request_refuses_value_and_authority_overrides_before_store_access() {
        for request in [
            b"{}".as_slice(),
            b"null",
            br#"{"tenant":"local","name":"x","reveal":true}"#,
            br#"{"tenant":"local","name":"x","value":"private-marker"}"#,
            br#"{"tenant":"local","name":"x","root":"/tmp"}"#,
            br#"{"tenant":"local","name":"x","name":"y"}"#,
            br#"{"tenant":"../other","name":"x"}"#,
            br#"{"tenant":"local","name":"../other"}"#,
        ] {
            let outcome = dispatch(GET, request);
            assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
            assert!(
                !String::from_utf8(outcome.body)
                    .unwrap()
                    .contains("private-marker")
            );
        }
        assert!(!is_known("secret.metadata"));
        assert!(!is_known("secret.value"));
    }

    #[test]
    fn public_c_abi_returns_metadata_miss_and_failure_without_cli() {
        use mvm_core::crypto::secret_store::BACKEND_ENV;

        let temp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(temp.path());
        env.set(BACKEND_ENV, "file");
        let service = SecretService::local().unwrap();
        service
            .put(
                "local",
                "sample",
                SecretValueInput::new("private-marker".into()),
            )
            .unwrap();

        let call = |name: &str| {
            assert_eq!(
                crate::mvm_hostlib_abi_is_compatible(
                    crate::MVM_HOSTLIB_ABI_MAJOR,
                    crate::MVM_HOSTLIB_ABI_MINOR
                ),
                1
            );
            let mut out = crate::MvmHostlibBuf {
                data: std::ptr::null_mut(),
                len: 0,
            };
            let request = serde_json::json!({"tenant":"local","name":name}).to_string();
            // SAFETY: both byte slices remain alive through the call and `out`
            // is writable; the returned buffer is freed exactly once below.
            let status = unsafe {
                crate::mvm_hostlib_call(
                    GET.as_ptr(),
                    GET.len(),
                    request.as_ptr(),
                    request.len(),
                    &mut out,
                )
            };
            // SAFETY: a nonempty ABI buffer points to `len` initialized bytes;
            // an empty buffer may be null and must not form a Rust slice.
            let body = if out.len == 0 {
                Vec::new()
            } else {
                // SAFETY: `out.data` points to `out.len` bytes owned by the
                // live ABI allocation until the paired free below.
                unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec()
            };
            // SAFETY: `out` was returned by the call and has not been freed.
            unsafe { crate::mvm_hostlib_free(out) };
            (status, body)
        };

        let (status, body) = call("sample");
        assert_eq!(status, MVM_HOSTLIB_OK);
        let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(metadata["name"], "sample");
        assert!(!String::from_utf8(body).unwrap().contains("private-marker"));
        let (status, body) = call("absent");
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body, b"null");

        let dir = mvm_core::crypto::secret_store::default_secrets_dir()
            .unwrap()
            .join("local");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "not a directory").unwrap();
        let (status, body) = call("sample");
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert!(!String::from_utf8(body).unwrap().contains("private-marker"));
        let audit = std::fs::read_to_string(temp.path().join("audit/secrets.jsonl")).unwrap();
        assert!(audit.contains("\"outcome\":\"ok\""));
        assert!(audit.contains("\"outcome\":\"miss\""));
        assert!(audit.contains("\"outcome\":\"err\""));
    }
}
