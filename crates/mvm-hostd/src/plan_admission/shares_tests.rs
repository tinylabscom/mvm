#![cfg(test)]

use super::test_support::*;
use super::*;

/// Claim 1: a volume that the signed plan didn't admit — or that
/// mismatches the admitted ro/rw — is refused before launch.
/// Materializing a granted directory must not change what it has to be
/// granted *as*.
///
/// `enforce_admitted_shares` is the trust-boundary hook for claim 1: a
/// volume reaches a guest only if the signed plan admitted that exact
/// host path, guest path and kind. `--mount` now attaches an ext4 image
/// rather than the directory, and the volume records which image in
/// `materialized_image` — but `host` stays the directory that was
/// granted, so the grant still matches.
///
/// This is not cosmetic. Had the materialized mount become a `Disk` whose
/// `host` was the image under `~/.mvm`, this check would compare that path
/// against the granted directory and refuse the boot. The field exists so
/// the transport can change without the grant changing.
#[test]
fn a_materialized_grant_still_satisfies_the_directory_share_it_was_granted_as() {
    let grant = mvm_core::plan::HostShareGrant {
        tag: "uvol0".into(),
        host_path: "/h/src".into(),
        guest_path: "/data".into(),
        kind: mvm_core::plan::ShareKind::DirShare,
        read_only: true,
        encrypted: false,
        content_sha256: None,
        include: Vec::new(),
        exclude: Vec::new(),
    };
    let mut input = fixture_input("vm-materialized-share");
    input.shares = vec![grant];
    let plan = synthesize_plan(&input).unwrap();

    let materialized = mvm_core::vm_backend::VmVolume {
        host: "/h/src".into(),
        guest: "/data".into(),
        read_only: true,
        materialized_image: Some("/state/mount-0.ext4".into()),
        volume_label: None,
        ..Default::default()
    };
    enforce_admitted_shares(std::slice::from_ref(&materialized), &plan)
        .expect("a materialized grant is still the grant that was admitted");

    // And the image path is not what is checked: a volume claiming a host
    // path nobody granted is refused whatever it materialized into.
    let ungranted = mvm_core::vm_backend::VmVolume {
        host: "/state/mount-0.ext4".into(),
        ..materialized.clone()
    };
    assert!(
        enforce_admitted_shares(std::slice::from_ref(&ungranted), &plan).is_err(),
        "only the granted host path may reach a guest"
    );

    let mut disk_input = fixture_input("vm-materialized-share-as-disk");
    disk_input.shares = vec![mvm_core::plan::HostShareGrant {
        tag: "uvol0".into(),
        host_path: "/h/src".into(),
        guest_path: "/data".into(),
        kind: mvm_core::plan::ShareKind::Disk,
        read_only: true,
        encrypted: false,
        content_sha256: None,
        include: Vec::new(),
        exclude: Vec::new(),
    }];
    let disk_plan = synthesize_plan(&disk_input).expect("synthesize disk plan");
    assert!(
        enforce_admitted_shares(std::slice::from_ref(&materialized), &disk_plan).is_err(),
        "a materialized directory must not satisfy a disk grant"
    );
}

/// A re-bind under a different deny set refuses: claim-time binding
/// binds the include/exclude vectors, so a volume whose share grants it
/// a different effective tree than the plan admitted cannot attach —
/// the deny set cannot be weakened between admission and boot.
#[test]
fn a_rebind_with_a_different_deny_set_is_refused() {
    let grant = mvm_core::plan::HostShareGrant {
        tag: "uvol0".into(),
        host_path: "/h/src".into(),
        guest_path: "/data".into(),
        kind: mvm_core::plan::ShareKind::DirShare,
        read_only: true,
        encrypted: false,
        content_sha256: None,
        include: Vec::new(),
        exclude: vec![mvm_contract::policy::protected_paths::ProtectedPath::new(
            "**/target",
        )],
    };
    let mut input = fixture_input("vm-share-deny-rebind");
    input.shares = vec![grant];
    let plan = synthesize_plan(&input).unwrap();

    let matching = mvm_core::vm_backend::VmVolume {
        host: "/h/src".into(),
        guest: "/data".into(),
        read_only: true,
        materialized_image: Some("/state/mount-0.ext4".into()),
        share_include: Vec::new(),
        share_exclude: vec![mvm_contract::policy::protected_paths::ProtectedPath::new(
            "**/target",
        )],
        ..Default::default()
    };
    enforce_admitted_shares(std::slice::from_ref(&matching), &plan)
        .expect("the admitted deny set attaches");

    let weakened = mvm_core::vm_backend::VmVolume {
        share_exclude: Vec::new(),
        ..matching.clone()
    };
    assert!(
        enforce_admitted_shares(std::slice::from_ref(&weakened), &plan).is_err(),
        "a re-bind that drops the additional deny set must refuse"
    );
}

#[test]
fn admitted_share_digest_refuses_directory_changed_after_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).expect("mkdir");
    std::fs::write(data.join("rows.csv"), b"a,b\n1,2\n").expect("write");
    let image = tmp.path().join("mount.ext4");
    std::fs::write(&image, b"frozen image bytes").expect("write image");
    let digest = mvm_core::crypto::image_verify::sha256_file(&image).expect("hash admitted image");
    let grant = mvm_core::plan::HostShareGrant {
        tag: "uvol0".into(),
        host_path: data.to_string_lossy().into_owned(),
        guest_path: "/data".into(),
        kind: mvm_core::plan::ShareKind::DirShare,
        read_only: true,
        encrypted: false,
        content_sha256: Some(digest.clone()),
        include: Vec::new(),
        exclude: Vec::new(),
    };
    let mut input = fixture_input("vm-share-digest-drift");
    input.shares = vec![grant];
    let plan = synthesize_plan(&input).expect("synthesize");

    let volume = |host: &str| mvm_core::vm_backend::VmVolume {
        host: host.into(),
        guest: "/data".into(),
        read_only: true,
        materialized_image: Some(image.display().to_string()),
        ..Default::default()
    };

    // Unchanged frozen image: the admitted identity still matches.
    enforce_admitted_shares(
        std::slice::from_ref(&volume(&plan.shares[0].host_path)),
        &plan,
    )
    .expect("unchanged tree attaches");

    // A byte flips between admission and attach: refused, and the error
    // names both identities.
    std::fs::write(&image, b"tampered frozen image").expect("tamper");
    let err = enforce_admitted_shares(
        std::slice::from_ref(&volume(&plan.shares[0].host_path)),
        &plan,
    )
    .expect_err("a changed image must not attach under the admitted identity");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(&digest),
        "error names the admitted digest: {msg}"
    );
    assert!(
        msg.contains("changed after admission"),
        "error says why: {msg}"
    );
}

#[test]
fn enforce_admitted_shares_refuses_unadmitted_or_mismatched() {
    use mvm_core::vm_backend::VmVolume;
    let grant = mvm_core::plan::HostShareGrant {
        tag: "uvol0".into(),
        host_path: "/h/src".into(),
        guest_path: "/data".into(),
        kind: mvm_core::plan::ShareKind::DirShare,
        read_only: true,
        encrypted: false,
        content_sha256: None,
        include: Vec::new(),
        exclude: Vec::new(),
    };
    let mut input = fixture_input("vm-shares");
    input.shares = vec![grant];
    let plan = synthesize_plan(&input).unwrap();

    let admitted_vol = VmVolume {
        host: "/h/src".into(),
        guest: "/data".into(),
        read_only: true,
        materialized_image: Some("/state/mount-0.ext4".into()),
        ..Default::default()
    };
    // The exact admitted volume passes.
    assert!(enforce_admitted_shares(std::slice::from_ref(&admitted_vol), &plan).is_ok());

    // A volume the plan never named is refused.
    let unadmitted = VmVolume {
        host: "/etc".into(),
        guest: "/data".into(),
        read_only: true,
        materialized_image: Some("/state/mount-1.ext4".into()),
        ..Default::default()
    };
    assert!(enforce_admitted_shares(&[unadmitted], &plan).is_err());

    // Same path/kind, but read-WRITE when the plan admitted read-only:
    // an unauthorized escalation, refused.
    let escalated = VmVolume {
        read_only: false,
        ..admitted_vol
    };
    assert!(enforce_admitted_shares(&[escalated], &plan).is_err());
}
