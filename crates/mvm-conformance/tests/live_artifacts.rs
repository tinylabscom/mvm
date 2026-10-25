#[path = "support/live_artifacts.rs"]
mod live_artifacts;

use mvm_build::guest_libc::GuestLibc;
use mvm_build::published_image_set::{MemberVersion, SetMemberCache};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, MemberTarget, RetiredGuestRuntimeRole};
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

/// A sidecar an older CLI installed from the pinned image set does not
/// satisfy the gate: a launch never attaches it.
#[test]
fn an_image_set_sidecar_does_not_satisfy_the_gate() {
    let cache = tempfile::tempdir().unwrap();
    let set = SetMemberCache::locked();
    let version = MemberVersion::parse(env!("CARGO_PKG_VERSION")).unwrap();
    install_fixture(&set.cache_root(cache.path()), version.as_str());
    set.record(
        cache.path(),
        ImageSetRole::RetiredGuestRuntime(RetiredGuestRuntimeRole::SdkSidecar(GuestLibc::Glibc)),
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

const LIVE_HOME_PREPARATION: &str = "And the isolated mvm home is prepared for live launches";

fn scenario_steps<'a>(feature: &'a str, name: &str) -> Result<Vec<&'a str>, String> {
    let mut found = false;
    let mut steps = Vec::new();
    let mut doc_string_delimiter = None;

    for raw_line in feature.lines() {
        let line = raw_line.trim();
        if let Some(delimiter) = doc_string_delimiter {
            if line.starts_with(delimiter) {
                doc_string_delimiter = None;
            }
            continue;
        }
        if let Some(delimiter) = gherkin_doc_string_delimiter(line) {
            doc_string_delimiter = Some(delimiter);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(scenario_name) = scenario_name(line) {
            if found {
                break;
            }
            found = scenario_name == name;
            continue;
        }
        if found && is_gherkin_step(line) {
            steps.push(line);
        }
    }

    found
        .then_some(steps)
        .ok_or_else(|| format!("feature contains scenario {name:?}"))
}

fn gherkin_doc_string_delimiter(line: &str) -> Option<&'static str> {
    ["\"\"\"", "```"]
        .into_iter()
        .find(|delimiter| line.starts_with(delimiter))
}

fn scenario_name(line: &str) -> Option<&str> {
    line.strip_prefix("Scenario:")
        .or_else(|| line.strip_prefix("Scenario Outline:"))
        .map(str::trim)
}

fn is_gherkin_step(line: &str) -> bool {
    ["Given ", "When ", "Then ", "And ", "But ", "* "]
        .iter()
        .any(|keyword| line.starts_with(keyword))
}

fn scenario_prepares_home_before_command(
    feature: &str,
    name: &str,
    consuming_command: &str,
) -> Result<(), String> {
    let steps = scenario_steps(feature, name)?;
    let prepared = steps
        .iter()
        .position(|step| *step == LIVE_HOME_PREPARATION)
        .ok_or_else(|| format!("{name} must prepare its source-built runtime"))?;
    let launch = steps
        .iter()
        .position(|step| *step == consuming_command)
        .ok_or_else(|| format!("{name} contains its runtime-consuming command"))?;
    (prepared < launch).then_some(()).ok_or_else(|| {
        format!("{name} must prepare its source-built runtime before the command uses it")
    })
}

#[test]
fn source_tree_live_scenarios_prepare_their_home_before_selecting_tree_runtime() {
    let bundle_boot =
        include_str!("../../../features/suites/s13_bundle_boot/verify_and_boot.feature");
    let documented =
        include_str!("../../../features/suites/s29_doc_examples/documented_build_live.feature");
    let oci_bundle =
        include_str!("../../../features/suites/s13_bundle_boot/oci_bundle_build.feature");

    for (feature, name, command) in [
        (
            bundle_boot,
            "A signed OCI artifact boots as the positional source",
            "When I seal \"docker.io/library/alpine:3.20\" into a signed artifact in the live home",
        ),
        (
            documented,
            "the documented pack build health-boots and signs a frozen workload",
            "When I run mvmctl against the live pack fixture with \"build pack.json --out build.mvmpkg\"",
        ),
        (
            oci_bundle,
            "Build and inspect an Alpine OCI package under local authority",
            "When I run mvmctl in the scratch directory with \"build docker.io/library/alpine:3.20 --from image --out alpine.mvmpkg --debug-out alpine.bundle.json\"",
        ),
    ] {
        scenario_prepares_home_before_command(feature, name, command)
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn source_tree_live_scenarios_reject_commented_or_late_home_preparation() {
    let commented_preparation = concat!(
        "Scenario: source tree launch\n",
        "  # And the isolated mvm home is prepared for live launches\n",
        "  When I select the source-built runtime\n",
    );
    assert!(
        scenario_prepares_home_before_command(
            commented_preparation,
            "source tree launch",
            "When I select the source-built runtime",
        )
        .is_err()
    );

    let late_preparation = concat!(
        "Scenario: source tree launch\n",
        "  When I select the source-built runtime\n",
        "  And the isolated mvm home is prepared for live launches\n",
    );
    assert!(
        scenario_prepares_home_before_command(
            late_preparation,
            "source tree launch",
            "When I select the source-built runtime",
        )
        .is_err()
    );
}

#[test]
fn scenario_steps_require_an_exact_header_and_stop_at_scenario_outline() {
    let feature = concat!(
        "Scenario:  source tree launch  \n",
        "  When I select the source-built runtime\n",
        "Scenario Outline:source tree launch with examples\n",
        "  And the isolated mvm home is prepared for live launches\n",
    );

    assert_eq!(
        scenario_steps(feature, "source tree launch").unwrap(),
        ["When I select the source-built runtime"]
    );
    assert!(scenario_steps(feature, "source tree").is_err());
}

#[test]
fn scenario_steps_stop_at_unnamed_scenario_boundaries() {
    let feature = concat!(
        "Scenario Outline: source tree launch\n",
        "  When I select the source-built runtime\n",
        "Scenario:\n",
        "  And the isolated mvm home is prepared for live launches\n",
    );

    assert_eq!(
        scenario_steps(feature, "source tree launch").unwrap(),
        ["When I select the source-built runtime"]
    );
    assert_eq!(
        scenario_steps(feature, "").unwrap(),
        [LIVE_HOME_PREPARATION]
    );
}

#[test]
fn scenario_steps_ignore_structure_inside_doc_strings() {
    for delimiter in ["\"\"\"", "```"] {
        let feature = format!(
            "Scenario: source tree launch\n\
             {delimiter}\n\
             Scenario: misleading boundary\n\
             And the isolated mvm home is prepared for live launches\n\
             {delimiter}\n\
             When I select the source-built runtime\n"
        );

        assert_eq!(
            scenario_steps(&feature, "source tree launch").unwrap(),
            ["When I select the source-built runtime"],
            "{delimiter} doc string must not supply a step or a boundary"
        );
        assert!(
            scenario_prepares_home_before_command(
                &feature,
                "source tree launch",
                "When I select the source-built runtime",
            )
            .is_err(),
            "{delimiter} doc string must not supply preparation or a boundary"
        );
    }
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
