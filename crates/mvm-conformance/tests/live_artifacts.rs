#[path = "support/live_artifacts.rs"]
mod live_artifacts;

use mvm_build::guest_libc::GuestLibc;
use mvm_build::published_image_set::{MemberVersion, SetMemberCache};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, MemberTarget};
use mvm_fs::sdk_sidecar::SdkSidecarLayout;

#[test]
fn sealing_uses_only_a_completed_manifest_build_slot() {
    let slot = "ab".repeat(32);
    let event = serde_json::json!({
        "command": "build", "phase": "manifest", "status": "completed",
        "slot_hash": slot,
    });
    let output = format!("diagnostic before JSON\n{event}\n");
    assert_eq!(
        live_artifacts::built_manifest_slot(output.as_bytes()),
        Some(slot)
    );
    for (field, value) in [
        ("command", "run"),
        ("phase", "nix-build"),
        ("status", "started"),
        ("status", "failed"),
        ("slot_hash", "../../unrelated"),
        ("slot_hash", ""),
    ] {
        let mut invalid = event.clone();
        invalid[field] = value.into();
        assert_eq!(
            live_artifacts::built_manifest_slot(invalid.to_string().as_bytes()),
            None
        );
    }
    assert_eq!(live_artifacts::built_manifest_slot(b""), None);
}

fn install_fixture(cache: &std::path::Path, version: &str) -> SdkSidecarLayout {
    use mvm_fs::ext4::{Node, Owner};
    let libc = GuestLibc::Glibc;
    let image = mvm_fs::ext4::build_image(
        vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: vec![],
                owner: Owner::ROOT,
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: mvm_fs::elf::test_fixture::shared_object(&["libc.so.6"]),
                xattrs: vec![],
                owner: Owner::ROOT,
            },
        ],
        &Default::default(),
    )
    .expect("sidecar fixture");
    let layout = SdkSidecarLayout::under(cache, version, &GuestArch::host().to_string(), libc);
    std::fs::create_dir_all(&layout.artifact_dir).unwrap();
    std::fs::write(&layout.image, &image).unwrap();
    std::fs::write(&layout.version_file, version).unwrap();
    std::fs::write(
        &layout.checksum_manifest_file,
        format!(
            "{}  sdk.ext4\n{}  VERSION\n",
            mvm_fs::overlay::compute_file_sha256(&layout.image).unwrap(),
            mvm_fs::overlay::compute_file_sha256(&layout.version_file).unwrap(),
        ),
    )
    .unwrap();
    layout
}

#[test]
fn sdk_gate_resolves_current_cli_cache_and_rejects_tampering() {
    let cache = tempfile::tempdir().unwrap();
    assert!(!live_artifacts::sdk_sidecar_cached_in(cache.path()));
    let layout = install_fixture(cache.path(), env!("CARGO_PKG_VERSION"));
    assert!(live_artifacts::sdk_sidecar_cached_in(cache.path()));
    std::fs::write(&layout.image, b"tampered").unwrap();
    assert!(!live_artifacts::sdk_sidecar_cached_in(cache.path()));
}

#[test]
fn sdk_gate_resolves_only_recorded_members_of_the_pinned_set() {
    let cache = tempfile::tempdir().unwrap();
    let set = SetMemberCache::locked();
    let version = MemberVersion::parse("1.2.3").unwrap();
    let layout = install_fixture(&set.cache_root(cache.path()), version.as_str());
    assert!(
        !live_artifacts::sdk_sidecar_cached_in(cache.path()),
        "unrecorded install"
    );
    set.record(
        cache.path(),
        ImageSetRole::SdkSidecar(GuestLibc::Glibc),
        MemberTarget::Arch(GuestArch::host()),
        &version,
    )
    .unwrap();
    assert!(
        live_artifacts::sdk_sidecar_cached_in(cache.path()),
        "pinned member"
    );
    std::fs::write(&layout.image, b"tampered").unwrap();
    assert!(
        !live_artifacts::sdk_sidecar_cached_in(cache.path()),
        "invalid member"
    );
}

#[test]
fn another_image_sets_sidecar_does_not_satisfy_the_gate() {
    let cache = tempfile::tempdir().unwrap();
    let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"other set"));
    let version = MemberVersion::parse("1.2.3").unwrap();
    install_fixture(&set.cache_root(cache.path()), version.as_str());
    set.record(
        cache.path(),
        ImageSetRole::SdkSidecar(GuestLibc::Glibc),
        MemberTarget::Arch(GuestArch::host()),
        &version,
    )
    .unwrap();
    assert!(!live_artifacts::sdk_sidecar_cached_in(cache.path()));
}

#[test]
fn sealing_scenario_registers_its_own_slot_without_replacing_the_flake_witness() {
    let feature =
        include_str!("../../../features/suites/s29_doc_examples/documented_build_live.feature");
    assert!(feature.contains("with \"machine build --flake examples/exit_code\""));
    let sealing = feature
        .split("Scenario: the documented flake build seals")
        .nth(1)
        .unwrap();
    assert!(sealing.contains("machine build --mvm-config examples/exit_code/mvm.toml --json"));
    assert!(sealing.contains("I seal the live manifest build into a bundle"));
}

#[test]
fn docker_volume_scenario_witnesses_the_current_selector_refusal() {
    let feature = include_str!("../../../features/suites/s26_volumes/volume_lifecycle.feature");
    let scenario = feature
        .split("Scenario: the removed Docker backend")
        .nth(1)
        .unwrap()
        .split("\n  Scenario:")
        .next()
        .unwrap();
    assert!(scenario.contains("machine volume mount bdd-docker-volume --volume work"));
    assert!(scenario.contains(
        "I attempt a direct start of machine \"bdd-docker-volume\" with backend \"docker\""
    ));
    assert!(scenario.contains("the local volume attachment lease catalog is empty"));
    let error = mvm_client::boot::require_hypervisor_selectable("docker").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Docker backend has been removed")
    );
    assert!(scenario.contains("the error output contains \"Docker backend has been removed\""));
}
