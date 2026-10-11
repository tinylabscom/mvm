#![cfg(feature = "schema")]

use mvm_client::checkpoint::{ForkReport, ForkRequest};
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
use serde_json::json;

#[test]
fn fork_request_schema_preserves_secret_reference_shapes() {
    let schema = serde_json::to_value(schemars::schema_for!(ForkRequest)).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["declared_secrets"]["items"]["$ref"],
        "#/definitions/SecretBinding"
    );
    let binding = &schema["definitions"]["SecretBinding"];
    assert_eq!(binding["type"], "object");
    assert_eq!(binding["additionalProperties"], false);
    assert_eq!(binding["required"], json!(["name", "source"]));
    assert_eq!(
        binding["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["approval_required", "destinations", "name", "source"]
    );
    let sources = schema["definitions"]["SecretSource"]["oneOf"]
        .as_array()
        .unwrap();
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0]["properties"]["kind"]["enum"],
        json!(["keystore"])
    );
    assert_eq!(sources[0]["required"], json!(["address", "kind"]));
    assert_eq!(
        sources[1]["properties"]["kind"]["enum"],
        json!(["external"])
    );
    assert_eq!(sources[1]["required"], json!(["kind", "path", "provider"]));

    let wire = json!({
        "id": "parent", "new_id": null, "boot": false, "hypervisor": "auto",
        "cpus": null, "memory": null, "allow_secret_drop": false,
        "intent": "ordinary", "tenant": "local",
        "declared_secrets": [
            {"name": "TOKEN", "source": {"kind": "keystore", "address": "token"}},
            {"name": "REMOTE", "source": {"kind": "external", "provider": "vault", "path": "team/token"},
             "destinations": ["api.example.com"], "approval_required": true}
        ]
    });
    let request: ForkRequest = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), wire);
    let mut invalid = wire;
    invalid["declared_secrets"][0]["value"] = json!("not-a-reference");
    assert!(serde_json::from_value::<ForkRequest>(invalid).is_err());
}

#[test]
fn fork_report_schema_keeps_checkpoint_metadata_typed() {
    let schema = serde_json::to_value(schemars::schema_for!(ForkReport)).unwrap();
    assert_eq!(
        schema["properties"]["checkpoint"]["$ref"],
        "#/definitions/CheckpointMeta"
    );
    let definitions = &schema["definitions"];
    let metadata = &definitions["CheckpointMeta"];
    assert_eq!(metadata["type"], "object");
    assert_eq!(metadata["additionalProperties"], false);
    assert!(
        metadata["required"]
            .as_array()
            .unwrap()
            .contains(&json!("meta_digest"))
    );
    assert_eq!(
        metadata["properties"]["content"]["items"]["$ref"],
        "#/definitions/ContentBlob"
    );
    for name in [
        "CheckpointId",
        "CheckpointDigest",
        "CheckpointKeyDomain",
        "ApprovalHead",
        "AgentSessionId",
    ] {
        assert_eq!(definitions[name]["type"], "string", "{name}");
    }
    for name in ["ContentBlob", "SessionBinding", "Grants", "EgressGrant"] {
        assert_eq!(definitions[name]["type"], "object", "{name}");
        assert_eq!(definitions[name]["additionalProperties"], false, "{name}");
    }
    assert_eq!(
        definitions["CpuGrant"]["oneOf"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        definitions["WallClockGrant"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let checkpoint = CheckpointMeta::builder(
        CheckpointId::new("child"),
        CheckpointClass::FsQuick,
        "child-vm",
    )
    .build();
    let report = ForkReport {
        schema_version: 1,
        action: "fork".into(),
        parent_id: CheckpointId::new("parent"),
        child_vm_name: "child-vm".into(),
        booted: false,
        checkpoint,
    };
    let wire = serde_json::to_value(&report).unwrap();
    assert_eq!(
        wire["checkpoint"],
        serde_json::to_value(&report.checkpoint).unwrap()
    );
    assert_eq!(wire["checkpoint"]["id"], "child");
    assert_eq!(wire["checkpoint"]["class"], "fs_quick");
    assert!(wire["checkpoint"].get("key_domain").is_none());
    let decoded: ForkReport = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
    let mut missing_digest = wire;
    missing_digest["checkpoint"]
        .as_object_mut()
        .unwrap()
        .remove("meta_digest");
    assert!(serde_json::from_value::<ForkReport>(missing_digest).is_err());
}
