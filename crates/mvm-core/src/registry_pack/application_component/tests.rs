use serde_json::{Value, json};

use super::*;
use crate::registry_pack::tests::{accept_signature, publisher_policy};
use crate::registry_pack::{PackLockfile, PackPin};

const POLICY: &[u8] = b"required = true\n";
const ARCHIVE: &[u8] = b"application tar bytes";

fn document() -> Value {
    json!({
        "schema_version": 3,
        "kind": "application_component",
        "reference": "runtime/worker@1.2.3",
        "description": "portable worker",
        "application_component": {
            "schema_version": 1,
            "guest_arch": "aarch64",
            "requirements": {
                "filesystem_abi": 1,
                "libc": "musl",
                "loader": "/lib/ld-musl-aarch64.so.1",
                "minimum_kernel": "6.1.0",
                "required_capabilities": ["pty"]
            },
            "archive": {
                "source": "https://example.test/worker.tar",
                "archive_sha256": Sha256Hex::from_bytes(ARCHIVE),
                "archive_size": ARCHIVE.len()
            },
            "entrypoints": [
                {"name": "default", "argv": ["/usr/bin/worker", "--serve"]},
                {"name": "migrate", "argv": ["/usr/bin/worker", "--migrate"]}
            ]
        },
        "files": [{
            "path": "pack/group.toml",
            "sha256": Sha256Hex::from_bytes(POLICY),
            "size": POLICY.len()
        }]
    })
}

fn parse(
    value: &Value,
) -> Result<RegistryApplicationComponentManifest, RegistryPackVerificationError> {
    parse_application_component_manifest(&serde_json::to_vec(value).unwrap())
}

fn authenticated(value: &Value) -> VerifiedRegistryApplicationComponent {
    let bytes = serde_json::to_vec(value).unwrap();
    let reference: PackReference = value["reference"].as_str().unwrap().parse().unwrap();
    let lock = PackLockfile::new(vec![
        PackPin::new(reference.clone(), Sha256Hex::from_bytes(&bytes)).unwrap(),
    ])
    .unwrap();
    let policy = publisher_policy();
    super::super::dispatch::verify_component_with(
        &RegistryPackVerification::new(&reference, &bytes, b"signed", &lock, &policy),
        accept_signature,
    )
    .unwrap()
}

#[test]
fn component_has_exact_versioned_shape_and_does_not_fall_back() {
    let manifest = parse(&document()).unwrap();
    assert_eq!(manifest.reference.to_string(), "runtime/worker@1.2.3");
    assert_eq!(
        manifest.application_component.entrypoints[0].name,
        "default"
    );
    let bytes = serde_json::to_vec(&document()).unwrap();
    assert!(super::super::application::parse_application_manifest(&bytes).is_err());
    assert!(super::super::runtime_layer::parse_runtime_layer_manifest(&bytes).is_err());
    for (field, replacement) in [
        ("schema_version", json!(2)),
        ("kind", json!("runtime_layer")),
        ("reference", json!("runtime/worker@1.2.3+build")),
        ("description", json!("  ")),
    ] {
        let mut value = document();
        value[field] = replacement;
        assert!(parse(&value).is_err(), "{field}");
    }
    for field in [
        "image",
        "kernel",
        "application",
        "payload",
        "network",
        "role",
    ] {
        let mut value = document();
        value[field] = json!({});
        assert!(parse(&value).is_err(), "{field}");
    }
    let mut duplicate = serde_json::to_string(&document()).unwrap();
    duplicate = duplicate.replacen(
        "\"kind\":",
        "\"kind\":\"application_component\",\"kind\":",
        1,
    );
    assert!(parse_application_component_manifest(duplicate.as_bytes()).is_err());
    assert!(
        parse_application_component_manifest(&vec![b' '; MAX_REGISTRY_DESCRIPTOR_BYTES + 1])
            .is_err()
    );
}

#[test]
fn requirements_and_entrypoints_are_strict_and_bounded() {
    let base = document();
    let mut cases = Vec::new();
    for (key, bad) in [
        ("filesystem_abi", json!(2)),
        ("libc", json!("unknown")),
        ("loader", json!("/lib/../ld.so")),
        ("loader", json!("/lib/ld-musl-x86_64.so.1")),
        ("minimum_kernel", json!("06.1.0")),
        ("required_capabilities", json!(["pty", "pty"])),
    ] {
        let mut value = base.clone();
        value["application_component"]["requirements"][key] = bad;
        cases.push(value);
    }
    for (key, bad) in [
        ("source", json!("http://example.test/app.tar")),
        ("archive_sha256", json!("A".repeat(64))),
        ("archive_size", json!(MAX_COMPONENT_BYTES + 1)),
    ] {
        let mut value = base.clone();
        value["application_component"]["archive"][key] = bad;
        cases.push(value);
    }
    for (key, bad) in [
        ("name", json!("NotCanonical")),
        ("argv", json!(["relative"])),
    ] {
        let mut value = base.clone();
        value["application_component"]["entrypoints"][0][key] = bad;
        cases.push(value);
    }
    let mut value = base.clone();
    value["application_component"]["requirements"]["loader"] = Value::Null;
    cases.push(value);
    let mut value = base.clone();
    value["application_component"]["requirements"]["libc"] = json!("static");
    cases.push(value);
    let mut value = base.clone();
    value["application_component"]["entrypoints"][1]["name"] = json!("default");
    cases.push(value);
    let mut value = base.clone();
    value["application_component"]["entrypoints"][0]["argv"] = json!(["/bin/app", "\0"]);
    cases.push(value);
    for (index, value) in cases.iter().enumerate() {
        assert!(parse(value).is_err(), "invalid case {index}");
    }
    let mut static_ok = base;
    static_ok["application_component"]["requirements"]["libc"] = json!("static");
    static_ok["application_component"]["requirements"]
        .as_object_mut()
        .unwrap()
        .remove("loader");
    static_ok["application_component"]["entrypoints"] = json!([]);
    assert!(parse(&static_ok).is_ok());
}

#[test]
fn policy_inventory_requires_exact_signed_files() {
    let base = document();
    for bad in [
        json!([]),
        json!([{"path": "pack/other.toml", "sha256": Sha256Hex::from_bytes(POLICY), "size": POLICY.len()}]),
        json!([base["files"][0].clone(), base["files"][0].clone()]),
        json!([{"path": "pack/group.toml", "sha256": Sha256Hex::from_bytes(POLICY), "size": 0}]),
    ] {
        let mut value = base.clone();
        value["files"] = bad;
        assert!(parse(&value).is_err());
    }
    let mut good = base;
    good["files"].as_array_mut().unwrap().push(json!({
        "path": "pack/profile.toml", "sha256": Sha256Hex::from_bytes(b"profile"), "size": 7
    }));
    assert!(parse(&good).is_ok());
}

#[test]
fn locked_publisher_identity_and_retained_bytes_are_bound() {
    let value = document();
    let bytes = serde_json::to_vec(&value).unwrap();
    let reference: PackReference = "runtime/worker@1.2.3".parse().unwrap();
    let lock = PackLockfile::new(vec![
        PackPin::new(reference.clone(), Sha256Hex::from_bytes(&bytes)).unwrap(),
    ])
    .unwrap();
    let policy = publisher_policy();
    let request = RegistryPackVerification::new(&reference, &bytes, b"signed", &lock, &policy);
    let verified =
        super::super::dispatch::verify_component_with(&request, accept_signature).unwrap();
    assert_eq!(verified.manifest_bytes(), bytes);
    assert_eq!(verified.signature_bundle(), b"signed");
    assert_eq!(verified.manifest_sha256(), &Sha256Hex::from_bytes(&bytes));
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
    let mut altered = bytes.clone();
    altered.push(b' ');
    assert!(
        super::super::dispatch::verify_component_with(
            &RegistryPackVerification::new(&reference, &altered, b"signed", &lock, &policy),
            accept_signature,
        )
        .is_err()
    );
    let other: PackReference = "runtime/other@1.2.3".parse().unwrap();
    assert!(
        super::super::dispatch::verify_component_with(
            &RegistryPackVerification::new(&other, &bytes, b"signed", &lock, &policy),
            accept_signature,
        )
        .is_err()
    );
}

#[test]
fn authenticated_component_uses_signed_current_revocation_feed() {
    use crate::packs::KeylessTrust;
    use crate::registry_pack_revocation::{
        RegistryPackRevocationError, verify_registry_pack_revocations_with,
    };

    let descriptor = authenticated(&document());
    let now = chrono::Utc::now();
    let trust = KeylessTrust {
        issuer: "test revocation issuer".into(),
        accepted_identities: vec!["test revocation signer".into()],
    };
    for (identities, digests, revoked) in [
        (Vec::new(), Vec::new(), false),
        (vec![descriptor.signer().identity.clone()], Vec::new(), true),
        (Vec::new(), vec![descriptor.manifest_sha256().clone()], true),
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
        let result = feed.check_verified_pack_at(&descriptor, now);
        assert_eq!(result.is_err(), revoked);
        if revoked {
            assert!(matches!(
                result,
                Err(RegistryPackRevocationError::RevokedIdentity { .. }
                    | RegistryPackRevocationError::RevokedManifest { .. })
            ));
        }
        assert!(matches!(
            feed.check_verified_pack_at(&descriptor, now + chrono::Duration::hours(2)),
            Err(RegistryPackRevocationError::Expired)
        ));
    }
}

#[test]
fn private_snapshots_refuse_changed_archive_and_policy() {
    let descriptor = authenticated(&document());
    let temporary = tempfile::tempdir().unwrap();
    let archive = temporary.path().join("app.tar");
    let policies = temporary.path().join("payload");
    std::fs::create_dir_all(policies.join("pack")).unwrap();
    std::fs::write(&archive, ARCHIVE).unwrap();
    std::fs::write(policies.join(GROUP_FILE), POLICY).unwrap();
    // The production entrypoint also requires current publisher enrollment and
    // a signed feed; exercise its byte-verification core without a network feed.
    std::fs::write(&archive, b"wrong length").unwrap();
    assert!(verify_inputs_with(&descriptor, &archive, &policies, |_| Ok(()), |_| Ok(())).is_err());
    std::fs::write(&archive, b"wrong archive bytes!!").unwrap();
    assert!(matches!(
        verify_inputs_with(&descriptor, &archive, &policies, |_| Ok(()), |_| Ok(())),
        Err(ApplicationComponentInputError::Digest)
    ));
    std::fs::write(&archive, ARCHIVE).unwrap();
    std::fs::write(policies.join(GROUP_FILE), b"wrong policy...\n").unwrap();
    assert!(matches!(
        verify_inputs_with(&descriptor, &archive, &policies, |_| Ok(()), |_| Ok(())),
        Err(ApplicationComponentInputError::Digest)
    ));
    std::fs::write(policies.join(GROUP_FILE), POLICY).unwrap();
    let input =
        verify_inputs_with(&descriptor, &archive, &policies, |_| Ok(()), |_| Ok(())).unwrap();
    std::fs::write(&archive, b"different source").unwrap();
    std::fs::write(policies.join(GROUP_FILE), b"changed policy").unwrap();
    assert!(
        input.reverify_bytes().is_ok(),
        "held bytes outlive mutable source paths"
    );
    assert_eq!(input.group(), Some(POLICY));
    let mut reader = input.snapshot.reopen().unwrap();
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, ARCHIVE);
    std::fs::write(input.snapshot.path(), b"changed snapshot").unwrap();
    assert!(matches!(
        input.reverify_bytes(),
        Err(ApplicationComponentInputError::Size | ApplicationComponentInputError::Digest)
    ));
}
