use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn fixture(arm: bool) -> Vec<u8> {
    // MH_EXECUTE; these fixtures are parsed and validated, never executed.
    let mut bytes = vec![0; 16386];
    let word = |bytes: &mut [u8], at: usize, value: u32| {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    let wide = |bytes: &mut [u8], at: usize, value: u64| {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    for (at, value) in [
        (0, 0xfeed_facf),
        (4, if arm { 0x0100_000c } else { 0x0100_0007 }),
        (8, if arm { 0 } else { 3 }),
        (12, 2),
        (16, 3),
        (20, 248),
    ] {
        word(&mut bytes, at, value);
    }
    for (at, name, offset, size, sections) in [
        (32, b"__TEXT".as_slice(), 0, 16384, 1),
        (184, b"__LINKEDIT".as_slice(), 16384, 2, 0),
    ] {
        word(&mut bytes, at, 0x19);
        word(&mut bytes, at + 4, 72 + 80 * sections);
        bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
        wide(&mut bytes, at + 24, 0x1_0000_0000 + offset);
        wide(&mut bytes, at + 32, 16384);
        wide(&mut bytes, at + 40, offset);
        wide(&mut bytes, at + 48, size);
        word(&mut bytes, at + 56, 5);
        word(&mut bytes, at + 60, 5);
        word(&mut bytes, at + 64, sections);
    }
    bytes[104..110].copy_from_slice(b"__text");
    bytes[120..126].copy_from_slice(b"__TEXT");
    wide(&mut bytes, 136, 0x1_0000_0200);
    wide(&mut bytes, 144, 4);
    word(&mut bytes, 152, 512);
    for (at, value) in [
        (256, 0x32),
        (260, 24),
        (264, 1),
        (268, 0x000e_0000),
        (272, 0x000e_0000),
    ] {
        word(&mut bytes, at, value);
    }
    bytes
}

fn target(dir: &Path, bytes: &[u8], required: RequiredEntitlement) -> SignTarget {
    let path = dir.join("fixture");
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o751)).unwrap();
    SignTarget { path, required }
}

#[test]
fn native_signing_is_atomic_role_specific_and_idempotent() {
    for required in [
        RequiredEntitlement::Hypervisor,
        RequiredEntitlement::Virtualization,
        RequiredEntitlement::VirtualizationAndHypervisor,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let target = target(dir.path(), &fixture(true), required);
        let old_inode = std::fs::metadata(&target.path).unwrap().ino();
        let report = sign_path(&target);
        assert!(report.applied, "{report:?}");
        assert!(report.entitlements_present, "{report:?}");
        assert!(report.error.is_none());
        verify(&target.path, required).unwrap();
        assert_ne!(old_inode, std::fs::metadata(&target.path).unwrap().ino());
        assert_eq!(
            std::fs::metadata(&target.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        if required != RequiredEntitlement::VirtualizationAndHypervisor {
            let other = if required == RequiredEntitlement::Hypervisor {
                RequiredEntitlement::Virtualization
            } else {
                RequiredEntitlement::Hypervisor
            };
            assert!(verify(&target.path, other).is_err());
        }
        let bytes = std::fs::read(&target.path).unwrap();
        let inode = std::fs::metadata(&target.path).unwrap().ino();
        let report = sign_path(&target);
        assert!(!report.applied, "{report:?}");
        assert!(report.entitlements_present);
        assert_eq!(bytes, std::fs::read(&target.path).unwrap());
        assert_eq!(inode, std::fs::metadata(&target.path).unwrap().ino());
    }
}

#[test]
fn native_validity_rejects_tampered_code_even_with_entitlements() {
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &fixture(true), RequiredEntitlement::Hypervisor);
    assert!(sign_path(&target).applied);
    let mut bytes = std::fs::read(&target.path).unwrap();
    // Padding in the signed __TEXT page; leaves the Mach-O and plist parseable.
    bytes[2048] ^= 1;
    verify_slices(&bytes, target.required).unwrap();
    std::fs::write(&target.path, bytes).unwrap();
    assert!(verify(&target.path, target.required).is_err());
}

#[test]
fn changing_role_does_not_inherit_previous_entitlements() {
    let dir = tempfile::tempdir().unwrap();
    let mut target = target(
        dir.path(),
        &fixture(true),
        RequiredEntitlement::Virtualization,
    );
    assert!(sign_path(&target).applied);
    target.required = RequiredEntitlement::Hypervisor;
    let report = sign_path(&target);
    assert!(report.applied, "{report:?}");
    verify(&target.path, target.required).unwrap();
    assert!(verify(&target.path, RequiredEntitlement::Virtualization).is_err());
}

#[test]
fn false_and_string_entitlements_are_not_authority() {
    for value in [
        plist::Value::Boolean(false),
        plist::Value::String("true".into()),
    ] {
        let mut dict = plist::Dictionary::new();
        dict.insert("com.apple.security.hypervisor".into(), value);
        let bytes = mvm_macho_sign::sign(&fixture(true), &plist::Value::Dictionary(dict)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = target(dir.path(), &bytes, RequiredEntitlement::Hypervisor);
        // The OS accepts the signature itself, but our typed policy refuses it.
        let url = CFURL::from_path(&target.path, false).unwrap();
        let code = SecStaticCode::from_path(&url, Flags::NONE).unwrap();
        code.check_validity(Flags::CHECK_ALL_ARCHITECTURES, &"true".parse().unwrap())
            .unwrap();
        assert!(verify(&target.path, target.required).is_err());
    }
}

#[test]
fn xml_and_der_must_agree_beyond_the_required_entitlement() {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "com.apple.security.hypervisor".into(),
        plist::Value::Boolean(true),
    );
    dict.insert(
        "com.mvm.test-marker".into(),
        plist::Value::String("same".into()),
    );
    let mut bytes = mvm_macho_sign::sign(&fixture(true), &plist::Value::Dictionary(dict)).unwrap();
    verify_slices(&bytes, RequiredEntitlement::Hypervisor).unwrap();

    let magic = 0xfade_7172u32.to_be_bytes();
    let start = bytes.windows(4).position(|value| value == magic).unwrap();
    let length = u32::from_be_bytes(bytes[start + 4..start + 8].try_into().unwrap()) as usize;
    let der = &mut bytes[start + 8..start + length];
    let marker = der.windows(4).position(|value| value == b"same").unwrap();
    der[marker..marker + 4].copy_from_slice(b"diff");

    // Check the parser rule directly: native signature validation would also
    // reject these altered bytes, but cannot witness XML/DER equality itself.
    let error = verify_slices(&bytes, RequiredEntitlement::Hypervisor).unwrap_err();
    assert!(
        error.contains("XML and DER entitlements disagree"),
        "{error}"
    );
}

#[test]
fn failed_preparation_keeps_original_and_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = b"not a Mach-O";
    let target = target(dir.path(), bytes, RequiredEntitlement::Hypervisor);
    let inode = std::fs::metadata(&target.path).unwrap().ino();
    let report = sign_path(&target);
    assert!(!report.applied);
    assert!(!report.entitlements_present);
    assert!(report.error.is_some());
    assert_eq!(std::fs::read(&target.path).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&target.path).unwrap().ino(), inode);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn universal_requires_every_slice_and_signs_both() {
    let required = RequiredEntitlement::Hypervisor;
    let bytes = mvm_macho_sign::universal_binary(&[
        signed_bytes(&fixture(true), required).unwrap(),
        signed_bytes(&fixture(false), RequiredEntitlement::Virtualization).unwrap(),
    ])
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &bytes, required);
    assert!(verify(&target.path, required).is_err());
    let report = sign_path(&target);
    assert!(report.applied, "{report:?}");
    verify(&target.path, required).unwrap();
    let bytes = std::fs::read(&target.path).unwrap();
    assert_eq!(mvm_macho_sign::slices(&bytes).unwrap().len(), 2);
}

#[test]
fn failed_native_staging_validation_preserves_original_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let original = fixture(true);
    let target = target(dir.path(), &original, RequiredEntitlement::Hypervisor);
    let mut corrupted = signed_bytes(&original, target.required).unwrap();
    corrupted[2048] ^= 1;
    verify_slices(&corrupted, target.required).unwrap();
    let metadata = std::fs::metadata(&target.path).unwrap();
    assert!(install(&target, &original, &corrupted, metadata.permissions()).is_err());
    assert_eq!(std::fs::read(&target.path).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&target.path).unwrap().ino(),
        metadata.ino()
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn symlink_is_not_a_signing_destination() {
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &fixture(true), RequiredEntitlement::Hypervisor);
    let bytes = std::fs::read(&target.path).unwrap();
    let link = dir.path().join("symlink");
    std::os::unix::fs::symlink(&target.path, &link).unwrap();
    let report = sign_path(&SignTarget {
        path: link,
        required: target.required,
    });
    assert!(!report.applied);
    assert!(report.error.is_some());
    assert_eq!(std::fs::read(&target.path).unwrap(), bytes);
}

#[test]
fn native_validity_checks_tampered_nonhost_fat_slice() {
    let required = RequiredEntitlement::Hypervisor;
    let mut bytes = mvm_macho_sign::universal_binary(&[
        signed_bytes(&fixture(true), required).unwrap(),
        signed_bytes(&fixture(false), required).unwrap(),
    ])
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let target = target(dir.path(), &bytes, required);
    verify(&target.path, required).unwrap();
    let parsed = mvm_macho_sign::slices(&bytes).unwrap();
    let other = parsed
        .iter()
        .find(|slice| {
            slice.cpu_type().unwrap()
                != if cfg!(target_arch = "aarch64") {
                    0x0100_000c
                } else {
                    0x0100_0007
                }
        })
        .unwrap()
        .offset;
    bytes[other + 2048] ^= 1;
    verify_slices(&bytes, required).unwrap();
    std::fs::write(&target.path, bytes).unwrap();
    assert!(verify(&target.path, required).is_err());
}

#[test]
fn changed_or_missing_target_is_not_destroyed_during_install() {
    let dir = tempfile::tempdir().unwrap();
    let original = fixture(true);
    let target = target(dir.path(), &original, RequiredEntitlement::Hypervisor);
    let output = signed_bytes(&original, target.required).unwrap();
    let metadata = std::fs::metadata(&target.path).unwrap();
    std::fs::write(&target.path, b"replacement").unwrap();
    assert!(install(&target, &original, &output, metadata.permissions()).is_err());
    assert_eq!(std::fs::read(&target.path).unwrap(), b"replacement");
    std::fs::remove_file(&target.path).unwrap();
    assert!(install(&target, &original, &output, metadata.permissions()).is_err());
    assert!(!target.path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
