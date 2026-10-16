//! Public identity data, not a hardware or measured-boot authority.

use std::path::Path;

use mvm_client::attestation as client;
use serde::{Deserialize, Serialize};

use crate::{
    host_local::{error, parse},
    status::Outcome,
};

pub const EXPORT: &str = "attestation.export";
pub const VERIFY: &str = "attestation.verify";
pub const STATUS: &str = "attestation.status";
pub const METHODS: &[&str] = &[EXPORT, VERIFY, STATUS];

pub fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationEmpty {}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttestationTrust {
    SelfIdentity {},
    PublicKeyFile { path: String },
}

impl<'de> Deserialize<'de> for AttestationTrust {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TrustObject;
        impl<'de> serde::de::Visitor<'de> for TrustObject {
            type Value = AttestationTrust;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an attestation trust object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let mut kind: Option<String> = None;
                let mut path: Option<String> = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "kind" if kind.is_none() => kind = Some(map.next_value()?),
                        "path" if path.is_none() => path = Some(map.next_value()?),
                        _ => return Err(A::Error::custom("unknown or duplicate trust field")),
                    }
                }
                match (kind.as_deref(), path) {
                    (Some("self_identity"), None) => Ok(AttestationTrust::SelfIdentity {}),
                    (Some("public_key_file"), Some(path)) => {
                        Ok(AttestationTrust::PublicKeyFile { path })
                    }
                    _ => Err(A::Error::custom("invalid attestation trust object")),
                }
            }
        }
        // A map visitor rejects sequence forms without a Value roundtrip that
        // would collapse duplicate fields before validation.
        deserializer.deserialize_map(TrustObject)
    }
}

#[cfg(feature = "schema")]
struct AttestationSelfIdentityKind;

#[cfg(feature = "schema")]
struct AttestationPublicKeyFileKind;

#[cfg(feature = "schema")]
fn singleton_kind(value: &str) -> schemars::schema::Schema {
    schemars::schema::Schema::Object(schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::String.into()),
        enum_values: Some(vec![serde_json::Value::String(value.into())]),
        ..Default::default()
    })
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AttestationSelfIdentityKind {
    fn schema_name() -> String {
        "AttestationSelfIdentityKind".into()
    }
    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        singleton_kind("self_identity")
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AttestationPublicKeyFileKind {
    fn schema_name() -> String {
        "AttestationPublicKeyFileKind".into()
    }
    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        singleton_kind("public_key_file")
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AttestationTrust {
    fn schema_name() -> String {
        "AttestationTrust".into()
    }
    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        let self_kind = generator.subschema_for::<AttestationSelfIdentityKind>();
        let public_kind = generator.subschema_for::<AttestationPublicKeyFileKind>();
        serde_json::from_value(serde_json::json!({
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"kind": self_kind},
                    "required": ["kind"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"kind": public_kind, "path": {"type": "string"}},
                    "required": ["kind", "path"],
                    "additionalProperties": false
                }
            ]
        }))
        .expect("authored attestation trust schema is valid")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationVerifyRequest {
    pub report_path: String,
    pub trust: AttestationTrust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationReportData {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HardwareMeasurementData {
    pub provider: String,
    pub measurement_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationBodyData {
    pub schema_version: u32,
    pub boot_measurement: String,
    pub identity_pubkey_hex: String,
    pub nonce_hex: String,
    pub hw_measurement: Option<HardwareMeasurementData>,
}

impl From<client::AttestationBody> for AttestationBodyData {
    fn from(body: client::AttestationBody) -> Self {
        Self {
            schema_version: body.schema_version,
            boot_measurement: body.boot_measurement,
            identity_pubkey_hex: body.identity_pubkey_hex,
            nonce_hex: body.nonce_hex,
            hw_measurement: body
                .hw_measurement
                .map(|measurement| HardwareMeasurementData {
                    provider: measurement.provider.as_str().into(),
                    measurement_hex: measurement.measurement_hex,
                }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationVerificationData {
    pub signer_id: String,
    pub body: AttestationBodyData,
    pub trust: AttestationTrust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationProviderData {
    pub name: String,
    pub feature: String,
    pub compiled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AttestationStatusData {
    pub signer_id: String,
    pub pubkey_hex: String,
    pub secret_path: String,
    pub public_path: String,
    pub providers: Vec<AttestationProviderData>,
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    match method {
        EXPORT => {
            let _: AttestationEmpty = parse(request)?;
            let report = client::export().map_err(|e| error(e.into()))?.0;
            Ok(Outcome::ok(&AttestationReportData {
                payload: report.payload,
                signature: report.signature,
                signer_id: report.signer_id,
            }))
        }
        VERIFY => {
            let request: AttestationVerifyRequest = parse(request)?;
            let trust = match &request.trust {
                AttestationTrust::SelfIdentity {} => client::Trust::SelfIdentity,
                AttestationTrust::PublicKeyFile { path } => {
                    client::Trust::PublicKeyFile(path.into())
                }
            };
            let verified = client::verify(Path::new(&request.report_path), trust)
                .map_err(|e| error(e.into()))?;
            Ok(Outcome::ok(&AttestationVerificationData {
                signer_id: verified.signer_id,
                body: verified.body.into(),
                trust: request.trust,
            }))
        }
        STATUS => {
            let _: AttestationEmpty = parse(request)?;
            let status = client::status().map_err(|e| error(e.into()))?;
            Ok(Outcome::ok(&AttestationStatusData {
                signer_id: status.signer_id,
                pubkey_hex: status.pubkey_hex,
                secret_path: status.secret_path.to_string_lossy().into_owned(),
                public_path: status.public_path.to_string_lossy().into_owned(),
                providers: status
                    .providers
                    .into_iter()
                    .map(|provider| AttestationProviderData {
                        name: provider.name.into(),
                        feature: provider.feature.into(),
                        compiled: provider.compiled,
                    })
                    .collect(),
            }))
        }
        _ => Err(Outcome::invalid_input("unknown attestation method")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_requests_do_not_initialize_identity_or_echo_payloads() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        for method in METHODS {
            for request in [
                "",
                "null",
                "1",
                "[]",
                "\"private-input\"",
                "{",
                r#"{"key":"private-input"}"#,
                r#"{"root":"other"}"#,
            ] {
                let outcome = dispatch(method, request.as_bytes());
                assert_eq!(outcome.status, crate::status::MVM_HOSTLIB_INVALID_INPUT);
                assert!(
                    !String::from_utf8(outcome.body)
                        .unwrap()
                        .contains("private-input")
                );
            }
        }
        for request in [
            r#"{"report_path":"r"}"#,
            r#"{"report_path":"r","report_path":"s","trust":{"kind":"self_identity"}}"#,
            r#"{"report_path":"r","trust":{"kind":"self_identity","path":"key"}}"#,
            r#"{"report_path":"r","trust":{"kind":"self_identity","kind":"public_key_file"}}"#,
            r#"{"report_path":"r","trust":{"kind":"public_key_file","path":"k","path":"j"}}"#,
            r#"{"report_path":"r","trust":{"kind":"public_key_file","path":"k","issuer":"x"}}"#,
            r#"{"report_path":"r","trust":null}"#,
            r#"{"report_path":"r","trust":[]}"#,
            r#"{"report_path":"r","trust":["self_identity"]}"#,
            r#"{"report_path":"r","trust":["public_key_file","key"]}"#,
            r#"{"report_path":"r","trust":"self_identity"}"#,
            r#"{"report_path":"r","trust":{"kind":"self_identity"},"trust":{"kind":"self_identity"}}"#,
            r#"["r",{"kind":"self_identity"}]"#,
        ] {
            assert_eq!(dispatch(VERIFY, request.as_bytes()).status, 8, "{request}");
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn explicit_file_trust_verifies_without_initializing_current_identity() {
        let authority = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let reports = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(authority.path());
        let report = client::export().unwrap();
        let public = client::status().unwrap().public_path;
        let path = reports.path().join("report.json");
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        env.isolate_mvm_home(destination.path());
        let request = serde_json::to_vec(&AttestationVerifyRequest {
            report_path: path.to_string_lossy().into_owned(),
            trust: AttestationTrust::PublicKeyFile {
                path: public.to_string_lossy().into_owned(),
            },
        })
        .unwrap();
        let verified = dispatch(VERIFY, &request);
        assert_eq!(verified.status, 0);
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    #[test]
    fn export_and_verification_delegate_and_preserve_v0_data() {
        let root = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(root.path());
        let exported = dispatch(EXPORT, b"{}");
        assert_eq!(exported.status, 0);
        let report: AttestationReportData = serde_json::from_slice(&exported.body).unwrap();
        let _: client::AttestationReport = serde_json::from_slice(&exported.body).unwrap();
        let path = root.path().join("report.json");
        std::fs::write(&path, &exported.body).unwrap();
        let request = serde_json::to_vec(&AttestationVerifyRequest {
            report_path: path.to_string_lossy().into_owned(),
            trust: AttestationTrust::SelfIdentity {},
        })
        .unwrap();
        let verified = dispatch(VERIFY, &request);
        assert_eq!(verified.status, 0);
        let value: serde_json::Value = serde_json::from_slice(&verified.body).unwrap();
        assert_eq!(
            value["body"]["boot_measurement"],
            client::PLACEHOLDER_BOOT_MEASUREMENT
        );
        assert!(value["body"]["hw_measurement"].is_null());
        assert!(value["body"].get("hw_measurement").is_some());
        let decoded: AttestationVerificationData = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        assert!(!report.payload.is_empty());
        assert_eq!(dispatch(STATUS, b"{}").status, 0);
        let mut report = report;
        report.payload[0] ^= 1;
        std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
        let refused = dispatch(VERIFY, &request);
        assert_ne!(refused.status, 0);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&refused.body).unwrap()["retryable"],
            false
        );
    }
}
