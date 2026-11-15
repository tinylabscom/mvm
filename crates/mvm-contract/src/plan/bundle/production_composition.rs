//! Reserved production-composition evidence shape; admission still refuses schema 9.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Names the signed frozen lock and original runtime proofs, never an
/// invented signature for the locally authored application. This is data
/// only until protected production admission is implemented. Each layer must
/// inventory exactly the policy documents declared by its signed descriptor;
/// the future recipient must authenticate and compare those documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionComposition {
    pub lock_artifact: String,
    pub layers: Vec<ProductionCompositionLayer>,
}

/// Original runtime evidence and every descriptor-declared policy document.
/// Neither a missing document nor an extra one is authorized by this inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ProductionCompositionLayerWire")]
pub struct ProductionCompositionLayer {
    pub manifest_artifact: String,
    pub signature_artifact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_artifact: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionCompositionLayerWire {
    manifest_artifact: String,
    signature_artifact: String,
    group_artifact: Option<String>,
    profile_artifact: Option<String>,
}

impl TryFrom<ProductionCompositionLayerWire> for ProductionCompositionLayer {
    type Error = &'static str;

    fn try_from(wire: ProductionCompositionLayerWire) -> Result<Self, Self::Error> {
        if wire.manifest_artifact.trim().is_empty()
            || wire.signature_artifact.trim().is_empty()
            || (wire.group_artifact.is_none() && wire.profile_artifact.is_none())
            || wire
                .group_artifact
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            || wire
                .profile_artifact
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            || (wire.group_artifact.is_some() && wire.group_artifact == wire.profile_artifact)
        {
            return Err("production composition layer requires distinct nonempty evidence names");
        }
        Ok(Self {
            manifest_artifact: wire.manifest_artifact,
            signature_artifact: wire.signature_artifact,
            group_artifact: wire.group_artifact,
            profile_artifact: wire.profile_artifact,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::bundle::{BundleMember, PRODUCTION_COMPOSITION_MIN_SCHEMA};

    #[test]
    fn proposed_production_composition_is_distinct_closed_and_requires_schema_nine() {
        for (group, profile) in [
            (Some("runtime-group.toml"), None),
            (None, Some("runtime-profile.toml")),
            (Some("runtime-group.toml"), Some("runtime-profile.toml")),
        ] {
            let member = BundleMember::ProductionComposition(ProductionComposition {
                lock_artifact: "frozen-lock.json".into(),
                layers: vec![ProductionCompositionLayer {
                    manifest_artifact: "runtime-manifest.json".into(),
                    signature_artifact: "runtime-manifest.bundle".into(),
                    group_artifact: group.map(str::to_owned),
                    profile_artifact: profile.map(str::to_owned),
                }],
            });
            assert_eq!(
                member.minimum_schema_version(),
                PRODUCTION_COMPOSITION_MIN_SCHEMA
            );
            let encoded = serde_json::to_value(&member).unwrap();
            assert_eq!(encoded["class"], "production_composition");
            assert_eq!(
                encoded["layers"][0].get("group_artifact").is_some(),
                group.is_some()
            );
            assert_eq!(
                encoded["layers"][0].get("profile_artifact").is_some(),
                profile.is_some()
            );
            assert_eq!(
                serde_json::from_value::<BundleMember>(encoded.clone()).unwrap(),
                member
            );
            for nested in [false, true] {
                let mut forged = encoded.clone();
                if nested {
                    forged["layers"][0]["publisher_verified"] = true.into();
                } else {
                    forged["publisher_verified"] = true.into();
                }
                assert!(serde_json::from_value::<BundleMember>(forged).is_err());
            }
            let mut missing = encoded.clone();
            missing["layers"][0]
                .as_object_mut()
                .unwrap()
                .remove("group_artifact");
            missing["layers"][0]
                .as_object_mut()
                .unwrap()
                .remove("profile_artifact");
            assert!(serde_json::from_value::<BundleMember>(missing).is_err());
            for field in [
                "manifest_artifact",
                "signature_artifact",
                "group_artifact",
                "profile_artifact",
            ] {
                let mut empty = encoded.clone();
                if empty["layers"][0].get(field).is_some() {
                    empty["layers"][0][field] = " ".into();
                    assert!(
                        serde_json::from_value::<BundleMember>(empty).is_err(),
                        "{field}"
                    );
                }
            }
            let mut duplicate = encoded.clone();
            duplicate["layers"][0]["group_artifact"] = "same.toml".into();
            duplicate["layers"][0]["profile_artifact"] = "same.toml".into();
            assert!(serde_json::from_value::<BundleMember>(duplicate).is_err());
            let mut absent = encoded;
            absent["layers"][0]["group_artifact"] = serde_json::Value::Null;
            absent["layers"][0]["profile_artifact"] = serde_json::Value::Null;
            assert!(serde_json::from_value::<BundleMember>(absent).is_err());
        }
        let with_null_profile = r#"{"class":"production_composition","lock_artifact":"lock.json","layers":[{"manifest_artifact":"manifest.json","signature_artifact":"signature.bundle","group_artifact":"group.toml","profile_artifact":null}]}"#;
        assert!(serde_json::from_str::<BundleMember>(with_null_profile).is_ok());
        let duplicate_key = r#"{"class":"production_composition","lock_artifact":"lock.json","layers":[{"manifest_artifact":"manifest.json","signature_artifact":"signature.bundle","group_artifact":null,"group_artifact":"group.toml"}]}"#;
        assert!(serde_json::from_str::<BundleMember>(duplicate_key).is_err());
    }
}
