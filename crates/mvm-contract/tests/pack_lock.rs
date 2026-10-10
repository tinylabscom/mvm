//! PackLock wire witnesses. Digests here are shape fixtures, not real snapshots.
use mvm_contract::pack_lock::{PackLock, PackLockError};
use serde_json::{Value, json};

const MINIMAL: &str = include_str!("fixtures/pack-lock-v1/minimal.json");

fn document() -> Value {
    serde_json::from_str(MINIMAL).unwrap()
}

fn lock() -> PackLock {
    serde_json::from_str(MINIMAL).unwrap()
}

#[test]
fn golden_lock_round_trips_through_canonical_json() {
    let lock = lock();
    lock.validate().unwrap();
    let bytes = lock.canonical_json().unwrap();
    let decoded: PackLock = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lock, decoded);
    assert_eq!(bytes, decoded.canonical_json().unwrap());
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        concat!(
            r#"{"compiler":{"artifact_format_version":"1.1","mvm_revision":"4e65b221744885e536ec91a3f2948cdc508dcb49","toolchain_version":"0.23.1"},"#,
            r#""identity":{"name":"acme/hello","version":"1.0.0"},"schema":"mvm.pack-lock/v1","#,
            r#""source_tree_sha256":"2222222222222222222222222222222222222222222222222222222222222222","#,
            r#""spec_sha256":"1111111111111111111111111111111111111111111111111111111111111111","#,
            r#""target":"aarch64-linux","#,
            r#""workload_sha256":"3333333333333333333333333333333333333333333333333333333333333333"}"#
        )
    );
}

#[test]
fn every_field_is_required_and_unknown_fields_fail_at_every_level() {
    for field in document().as_object().unwrap().keys() {
        let mut value = document();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<PackLock>(value).is_err(),
            "{field}"
        );
    }
    for field in [
        "toolchain_version",
        "artifact_format_version",
        "mvm_revision",
    ] {
        let mut value = document();
        value["compiler"].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<PackLock>(value).is_err(),
            "{field}"
        );
    }
    for pointer in ["", "/identity", "/compiler"] {
        let mut value = document();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unsupported".into(), json!(true));
        assert!(
            serde_json::from_value::<PackLock>(value).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn unknown_schema_and_target_are_rejected() {
    let mut value = document();
    value["schema"] = json!("mvm.pack-lock/v2");
    assert!(serde_json::from_value::<PackLock>(value).is_err());
    let mut value = document();
    value["target"] = json!("riscv64-linux");
    assert!(serde_json::from_value::<PackLock>(value).is_err());
}

#[test]
fn malformed_digests_are_rejected_in_every_digest_field() {
    for field in ["spec_sha256", "source_tree_sha256", "workload_sha256"] {
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
            &"1".repeat(63),
            &"1".repeat(65),
            &format!("sha256:{}", "1".repeat(57)),
        ] {
            let mut value = document();
            value[field] = json!(bad);
            assert!(
                serde_json::from_value::<PackLock>(value).is_err(),
                "{field}={bad:?}"
            );
            let mut direct = lock();
            match field {
                "spec_sha256" => direct.spec_sha256 = bad.into(),
                "source_tree_sha256" => direct.source_tree_sha256 = bad.into(),
                _ => direct.workload_sha256 = bad.into(),
            }
            assert_eq!(direct.validate(), Err(PackLockError::Digest));
            assert_eq!(direct.canonical_json(), Err(PackLockError::Digest));
        }
    }
}

#[test]
fn compiler_pins_must_be_exact() {
    for bad in [
        "main",
        "4e65b221",
        "4E65B221744885E536EC91A3F2948CDC508DCB49",
        "zzzzb221744885e536ec91a3f2948cdc508dcb49",
    ] {
        let mut direct = lock();
        direct.compiler.mvm_revision = bad.into();
        assert_eq!(direct.validate(), Err(PackLockError::Revision), "{bad}");
    }
    for bad in ["", " 1.0", "1.0\n", "-1", "1/0"] {
        let mut direct = lock();
        direct.compiler.toolchain_version = bad.into();
        assert_eq!(direct.validate(), Err(PackLockError::Compiler), "{bad:?}");
        let mut direct = lock();
        direct.compiler.artifact_format_version = bad.into();
        assert_eq!(direct.validate(), Err(PackLockError::Compiler), "{bad:?}");
    }
}

#[test]
fn identity_follows_the_pack_spec_grammar() {
    for (name, version) in [
        ("bare", "1.0.0"),
        ("acme/../x", "1.0.0"),
        ("Acme/x", "1.0.0"),
        ("acme/x", "1.0"),
        ("acme/x", "01.0.0"),
    ] {
        let mut value = document();
        value["identity"] = json!({ "name": name, "version": version });
        assert!(
            serde_json::from_value::<PackLock>(value).is_err(),
            "{name} {version}"
        );
    }
}
