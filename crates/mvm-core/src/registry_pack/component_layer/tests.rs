use serde_json::{Value, json};

use super::*;
use crate::registry_pack::tests::{accept_signature, publisher_policy, reject_signature};
use crate::registry_pack::{
    OFFICIAL_PACK_SIGNING_IDENTITY, OFFICIAL_PACK_SIGNING_ISSUER, RegistryPackPublisher,
};

const ARCHIVE: &[u8] = b"component archive";
const POLICY: &[u8] = b"required = true\n";

fn document(kind: ComponentLayerKind) -> Value {
    let (kind_name, field, reference) = match kind {
        ComponentLayerKind::Runtime => (
            "runtime_component",
            "runtime_component",
            "runtime/python@1.2.3",
        ),
        ComponentLayerKind::Tool => ("tool_component", "tool_component", "tool/git@1.2.3"),
    };
    let mut value = json!({
        "schema_version": 4,
        "kind": kind_name,
        "reference": reference,
        "description": "portable signed component",
        "files": [{
            "path": "pack/group.toml",
            "sha256": Sha256Hex::from_bytes(POLICY),
            "size": POLICY.len()
        }]
    });
    value[field] = json!({
        "schema_version": 1,
        "guest_arch": "aarch64",
        "requirements": {
            "filesystem_abi": 1,
            "libc": "musl",
            "loader": "/lib/ld-musl-aarch64.so.1",
            "minimum_kernel": "6.1.0",
            "required_capabilities": ["pty"]
        },
        "dependencies": [{
            "reference": "runtime/base@1.0.0",
            "manifest_sha256": Sha256Hex::from_bytes(b"base manifest")
        }, {
            "reference": "tool/helper@2.0.0",
            "manifest_sha256": Sha256Hex::from_bytes(b"helper manifest")
        }],
        "archive": {
            "source": "https://example.test/component.tar",
            "archive_sha256": Sha256Hex::from_bytes(ARCHIVE),
            "archive_size": ARCHIVE.len()
        }
    });
    value
}

fn parse(value: &Value) -> Result<RegistryComponentLayerManifest, RegistryPackVerificationError> {
    parse_component_layer_manifest(&serde_json::to_vec(value).unwrap())
}

fn policy_for(reference: &PackReference) -> RegistryPackPublisherPolicy {
    if reference.namespace() == "tool" {
        RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "tool",
                OFFICIAL_PACK_SIGNING_ISSUER,
                vec![OFFICIAL_PACK_SIGNING_IDENTITY.to_owned()],
            )
            .unwrap(),
        ])
        .unwrap()
    } else {
        publisher_policy()
    }
}

fn authenticated(value: &Value) -> VerifiedRegistryComponentLayer {
    let bytes = serde_json::to_vec(value).unwrap();
    let reference: PackReference = value["reference"].as_str().unwrap().parse().unwrap();
    let pin = PackPin::new(reference.clone(), Sha256Hex::from_bytes(&bytes)).unwrap();
    let lock = PackLockfile::new(vec![pin]).unwrap();
    let policy = policy_for(&reference);
    verify_component_layer_with(
        &RegistryPackVerification::new(&reference, &bytes, b"signed", &lock, &policy),
        accept_signature,
    )
    .unwrap()
}

#[test]
fn both_kinds_have_closed_schema4_shapes_and_roundtrip() {
    for kind in [ComponentLayerKind::Runtime, ComponentLayerKind::Tool] {
        let value = document(kind);
        let parsed = parse(&value).unwrap();
        assert_eq!(parsed.kind(), kind);
        assert_eq!(parsed.component().dependencies.len(), 2);
        assert_eq!(parsed.component().requirements.minimum_kernel, "6.1.0");
        assert_eq!(
            parse(&serde_json::to_value(&parsed).unwrap()).unwrap(),
            parsed
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(super::super::runtime_layer::parse_runtime_layer_manifest(&bytes).is_err());
        assert!(
            super::super::application_component::parse_application_component_manifest(&bytes)
                .is_err()
        );
        let (field, other) = match kind {
            ComponentLayerKind::Runtime => ("runtime_component", "tool_component"),
            ComponentLayerKind::Tool => ("tool_component", "runtime_component"),
        };
        for (path, replacement) in [
            (vec!["schema_version"], json!(3)),
            (vec!["description"], json!(" ")),
            (vec![field, "schema_version"], json!(2)),
            (vec![field, "guest_arch"], json!("amd64")),
            (vec![field, "archive", "archive_size"], json!(0)),
            (
                vec![field, "archive", "source"],
                json!("http://example.test/app.tar"),
            ),
            (vec![field, "requirements", "filesystem_abi"], json!(2)),
            (
                vec![field, "requirements", "required_capabilities"],
                json!(["pty", "pty"]),
            ),
            (vec![field, "requirements", "loader"], Value::Null),
        ] {
            let mut changed = value.clone();
            let mut slot = &mut changed;
            for segment in path {
                slot = &mut slot[segment];
            }
            *slot = replacement;
            assert!(parse(&changed).is_err(), "{changed}");
        }
        let mut hybrid = value.clone();
        hybrid[other] = value[field].clone();
        assert!(parse(&hybrid).is_err());
        let mut unknown = value.clone();
        unknown[field]["role"] = json!("application");
        assert!(parse(&unknown).is_err());
        let mut null = value.clone();
        null[field] = Value::Null;
        assert!(parse(&null).is_err());
        let mut duplicate = serde_json::to_string(&value).unwrap();
        duplicate = duplicate.replacen("\"kind\":", "\"kind\":\"runtime_component\",\"kind\":", 1);
        assert!(parse_component_layer_manifest(duplicate.as_bytes()).is_err());
    }
    assert!(
        parse_component_layer_manifest(&vec![b' '; MAX_REGISTRY_DESCRIPTOR_BYTES + 1]).is_err()
    );
}

#[test]
fn namespace_requirements_and_dependencies_are_exact() {
    for kind in [ComponentLayerKind::Runtime, ComponentLayerKind::Tool] {
        let value = document(kind);
        let field = match kind {
            ComponentLayerKind::Runtime => "runtime_component",
            ComponentLayerKind::Tool => "tool_component",
        };
        for bad in [
            "agent/worker@1.2.3",
            "runtime/worker@1.2.3+build",
            "tool/worker",
        ] {
            let mut changed = value.clone();
            changed["reference"] = json!(bad);
            assert!(parse(&changed).is_err(), "{bad}");
        }
        for bad in [
            "agent/worker@1.0.0",
            "runtime/base",
            "runtime/base@1.0.0+build",
            value["reference"].as_str().unwrap(),
        ] {
            let mut changed = value.clone();
            changed[field]["dependencies"][0]["reference"] = json!(bad);
            assert!(parse(&changed).is_err(), "{bad}");
        }
        let mut duplicate = value.clone();
        duplicate[field]["dependencies"][1]["reference"] = json!("runtime/base@2.0.0");
        assert!(parse(&duplicate).is_err());
        let mut too_many = value.clone();
        too_many[field]["dependencies"] = json!(vec![value[field]["dependencies"][0].clone(); 17]);
        assert!(parse(&too_many).is_err());
        let mut static_ok = value.clone();
        static_ok[field]["requirements"]["libc"] = json!("static");
        static_ok[field]["requirements"]
            .as_object_mut()
            .unwrap()
            .remove("loader");
        assert!(parse(&static_ok).is_ok());
    }
}

#[test]
fn files_only_name_signed_policy_documents() {
    let base = document(ComponentLayerKind::Runtime);
    for files in [
        json!([]),
        json!([base["files"][0].clone(), base["files"][0].clone()]),
        json!([{"path": "pack/other.toml", "sha256": Sha256Hex::from_bytes(POLICY), "size": POLICY.len()}]),
        json!([{"path": "pack/group.toml", "sha256": Sha256Hex::from_bytes(POLICY), "size": 0}]),
    ] {
        let mut changed = base.clone();
        changed["files"] = files;
        assert!(parse(&changed).is_err());
    }
    let mut good = base;
    good["files"].as_array_mut().unwrap().push(json!({
        "path": PROFILE_FILE,
        "sha256": Sha256Hex::from_bytes(b"profile"),
        "size": 7
    }));
    assert!(parse(&good).is_ok());
}

#[test]
fn dependency_graph_requires_each_exact_signed_pin_in_dependency_first_order() {
    let mut base = document(ComponentLayerKind::Runtime);
    base["reference"] = json!("runtime/base@1.0.0");
    base["runtime_component"]["dependencies"] = json!([]);
    let base = authenticated(&base);
    let mut tool = document(ComponentLayerKind::Tool);
    tool["reference"] = json!("tool/helper@2.0.0");
    tool["tool_component"]["dependencies"] = json!([]);
    let tool = authenticated(&tool);
    let mut root = document(ComponentLayerKind::Runtime);
    root["runtime_component"]["dependencies"][0]["manifest_sha256"] = json!(base.manifest_sha256());
    root["runtime_component"]["dependencies"][1]["manifest_sha256"] = json!(tool.manifest_sha256());
    let root = authenticated(&root);
    let roots = vec![
        PackPin::new(
            root.manifest().reference().clone(),
            root.manifest_sha256().clone(),
        )
        .unwrap(),
    ];
    let candidates = vec![root.clone(), base.clone(), tool.clone()];
    let ordered = resolve_graph(&roots, &candidates, "aarch64").unwrap();
    let names: Vec<_> = ordered
        .iter()
        .map(|component| component.manifest().reference().to_string())
        .collect();
    assert_eq!(
        names,
        [
            "runtime/base@1.0.0",
            "tool/helper@2.0.0",
            "runtime/python@1.2.3"
        ]
    );

    assert!(matches!(
        resolve_graph(&roots, &[root.clone(), base.clone()], "aarch64"),
        Err(ComponentLayerResolveError::Missing(_))
    ));
    assert!(matches!(
        resolve_graph(&roots, &[root.clone(), base.clone(), base], "aarch64"),
        Err(ComponentLayerResolveError::InvalidGraph)
    ));
    assert!(matches!(
        resolve_graph(
            &[roots[0].clone(), roots[0].clone()],
            &candidates,
            "aarch64"
        ),
        Err(ComponentLayerResolveError::InvalidGraph)
    ));
    assert!(matches!(
        resolve_graph(&roots, &candidates, "x86_64"),
        Err(ComponentLayerResolveError::Drift(_))
    ));
    let wrong_pin = PackPin::new(
        root.manifest().reference().clone(),
        Sha256Hex::from_bytes(b"different"),
    )
    .unwrap();
    assert!(matches!(
        resolve_graph(&[wrong_pin], &candidates, "aarch64"),
        Err(ComponentLayerResolveError::Drift(_))
    ));
    let mut tampered = candidates;
    if let RegistryComponentLayerManifest::RuntimeComponent {
        runtime_component, ..
    } = &mut tampered[0].manifest
    {
        runtime_component.dependencies[0] = PackPin::new(
            tool.manifest().reference().clone(),
            Sha256Hex::from_bytes(b"wrong dependency"),
        )
        .unwrap();
    }
    assert!(matches!(
        resolve_graph(&roots, &tampered, "aarch64"),
        Err(ComponentLayerResolveError::Drift(_))
    ));
}

#[test]
fn publisher_and_lock_bind_original_bytes_not_reserialized_metadata() {
    let value = document(ComponentLayerKind::Runtime);
    let verified = authenticated(&value);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(verified.manifest_bytes(), bytes);
    assert_eq!(verified.signature_bundle(), b"signed");
    assert_eq!(verified.manifest_sha256(), &Sha256Hex::from_bytes(&bytes));
    let policy = publisher_policy();
    verified
        .reverify_publisher_with(&policy, accept_signature)
        .unwrap();
    assert!(
        verified
            .reverify_publisher_with(
                &RegistryPackPublisherPolicy::new(vec![]).unwrap(),
                accept_signature
            )
            .is_err()
    );
    let reference = verified.manifest().reference();
    let pin = PackPin::new(reference.clone(), verified.manifest_sha256().clone()).unwrap();
    let lock = PackLockfile::new(vec![pin]).unwrap();
    assert!(
        verify_component_layer_with(
            &RegistryPackVerification::new(reference, &bytes, b"unsigned", &lock, &policy),
            reject_signature
        )
        .is_err()
    );
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(
        verify_component_layer_with(
            &RegistryPackVerification::new(reference, &changed, b"signed", &lock, &policy),
            accept_signature
        )
        .is_err()
    );
    let other: PackReference = "runtime/other@1.2.3".parse().unwrap();
    assert!(
        verify_component_layer_with(
            &RegistryPackVerification::new(&other, &bytes, b"signed", &lock, &policy),
            accept_signature
        )
        .is_err()
    );
}

#[test]
fn signed_current_feed_revokes_identity_digest_and_expired_document() {
    use crate::packs::KeylessTrust;
    use crate::registry_pack_revocation::{
        RegistryPackRevocationError, verify_registry_pack_revocations_with,
    };

    let verified = authenticated(&document(ComponentLayerKind::Tool));
    let now = chrono::Utc::now();
    let trust = KeylessTrust {
        issuer: "test issuer".into(),
        accepted_identities: vec!["test feed signer".into()],
    };
    for (identities, digests, revoked) in [
        (Vec::new(), Vec::new(), false),
        (vec![verified.signer().identity.clone()], Vec::new(), true),
        (Vec::new(), vec![verified.manifest_sha256().clone()], true),
    ] {
        let document = json!({
            "schema_version": 1,
            "sequence": 1,
            "issued_at": now - chrono::Duration::hours(1),
            "not_after": now + chrono::Duration::hours(1),
            "revoked_identities": identities,
            "revoked_manifests": digests,
        });
        let feed = verify_registry_pack_revocations_with(
            &serde_json::to_vec(&document).unwrap(),
            b"signed feed",
            &trust,
            now,
            None,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            feed.check_verified_pack_at(&verified, now).is_err(),
            revoked
        );
        assert!(matches!(
            feed.check_verified_pack_at(&verified, now + chrono::Duration::hours(2)),
            Err(RegistryPackRevocationError::Expired)
        ));
    }
}

#[test]
fn private_inputs_pin_archive_and_policy_and_refuse_mutation() {
    let verified = authenticated(&document(ComponentLayerKind::Runtime));
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive.tar");
    let payload = directory.path().join("payload");
    std::fs::create_dir_all(payload.join("pack")).unwrap();
    std::fs::write(&archive, ARCHIVE).unwrap();
    std::fs::write(payload.join(GROUP_FILE), POLICY).unwrap();

    std::fs::write(&archive, b"bad").unwrap();
    assert!(verify_inputs_with(&verified, &archive, &payload, |_| Ok(()), |_| Ok(())).is_err());
    std::fs::write(&archive, b"component archivE").unwrap();
    assert!(matches!(
        verify_inputs_with(&verified, &archive, &payload, |_| Ok(()), |_| Ok(())),
        Err(ComponentLayerInputError::Digest)
    ));
    std::fs::write(&archive, ARCHIVE).unwrap();
    std::fs::write(payload.join(GROUP_FILE), b"wrong policy...\n").unwrap();
    assert!(verify_inputs_with(&verified, &archive, &payload, |_| Ok(()), |_| Ok(())).is_err());
    std::fs::write(payload.join(GROUP_FILE), POLICY).unwrap();
    let held = verify_inputs_with(&verified, &archive, &payload, |_| Ok(()), |_| Ok(())).unwrap();
    std::fs::write(&archive, b"changed original").unwrap();
    std::fs::write(payload.join(GROUP_FILE), b"changed original").unwrap();
    assert!(held.reverify_bytes().is_ok());
    assert_eq!(held.group(), Some(POLICY));
    let mut snapshot = held.snapshot.reopen().unwrap();
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, ARCHIVE);
    std::fs::write(held.snapshot.path(), b"tampered private").unwrap();
    assert!(matches!(
        held.reverify_bytes(),
        Err(ComponentLayerInputError::Digest | ComponentLayerInputError::Size)
    ));
}
