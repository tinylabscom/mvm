#[path = "../build_aux_helpers.rs"]
mod build_aux_helpers;

use std::path::Path;

use build_aux_helpers::{AuxHelperSpec, aux_helper_specs_from, shared_nested_target_dir};

/// The canonical registry itself, so a manifest edit is what these tests see.
const MANIFEST: &str = include_str!("../src/host_binaries/manifest.rs");

fn specs(os: &str, arch: &str, libkrun: bool) -> Vec<AuxHelperSpec> {
    aux_helper_specs_from(MANIFEST, os, arch, libkrun)
}

fn bins(specs: &[AuxHelperSpec]) -> Vec<&str> {
    specs.iter().map(|s| s.bin.as_str()).collect()
}

/// Every host/arch combination mvmctl builds for.
const HOSTS: &[(&str, &str)] = &[
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("macos", "x86_64"),
    ("macos", "aarch64"),
];

#[test]
fn the_registry_is_not_silently_empty() {
    // The parser is text-based, so a refactor of manifest.rs that renamed the
    // const or reshaped the literal would otherwise turn every assertion below
    // into a vacuous pass over an empty list.
    assert!(
        build_aux_helpers::parse_per_vm_binaries(MANIFEST).len() >= 6,
        "PER_VM_HOST_BINARIES failed to parse out of manifest.rs"
    );
}

#[test]
fn the_host_independent_helpers_build_on_every_host() {
    // The egress endpoint is not gated on host capability: every supported
    // backend routes admitted network access through the same per-VM seam.
    for (os, arch) in HOSTS {
        for libkrun in [false, true] {
            let s = specs(os, arch, libkrun);
            let bins = bins(&s);
            assert!(
                bins.contains(&"mvm-network-endpoint"),
                "mvm-network-endpoint must build on {os}/{arch} (libkrun={libkrun}), got {bins:?}"
            );
        }
    }
}

/// The regression this registry exists for. `resolve_subprocess_bin` finds
/// these only adjacent to the executable on a downloaded install, and
/// `host_agent_daemon_enabled()` defaults to on — so the agent pair is what a
/// plain `up` reaches, and the broker pair is what `MVM_HOST_AGENT_DAEMON=0`
/// reaches. A host that ships none of them fails at spawn, not at build.
#[test]
fn every_spawnable_service_binary_builds_on_every_host() {
    for (os, arch) in HOSTS {
        let s = specs(os, arch, false);
        let bins = bins(&s);
        for required in [
            "mvm-host-agent",
            "mvm-signer-helper",
            "mvm-broker",
            "mvm-audit-signer",
        ] {
            assert!(
                bins.contains(&required),
                "{required} must build on {os}/{arch}, got {bins:?}"
            );
        }
    }
}

#[test]
fn hvf_supervisor_only_on_macos_aarch64() {
    assert!(bins(&specs("macos", "aarch64", false)).contains(&"mvm-hvf-supervisor"));
    assert!(!bins(&specs("linux", "aarch64", false)).contains(&"mvm-hvf-supervisor"));
    assert!(!bins(&specs("macos", "x86_64", false)).contains(&"mvm-hvf-supervisor"));
}

#[test]
fn libkrun_supervisor_only_when_libkrun_present() {
    let present = specs("macos", "aarch64", true);
    let spec = present
        .iter()
        .find(|s| s.bin == "mvm-libkrun-supervisor")
        .expect("libkrun supervisor present");
    assert_eq!(spec.features, vec!["libkrun-sys".to_string()]);
    assert!(!bins(&specs("macos", "aarch64", false)).contains(&"mvm-libkrun-supervisor"));
}

#[test]
fn helper_specs_are_never_globally_skipped() {
    assert!(!specs("linux", "x86_64", false).is_empty());
    assert!(!specs("macos", "aarch64", true).is_empty());
}

#[test]
fn nested_builds_share_one_target_across_feature_fingerprints() {
    let default_out = Path::new("/workspace/target/debug/build/mvm-cli-default/out");
    let feature_out = Path::new("/workspace/target/debug/build/mvm-cli-feature/out");

    assert_eq!(
        shared_nested_target_dir(default_out),
        shared_nested_target_dir(feature_out)
    );
    assert_eq!(
        shared_nested_target_dir(default_out),
        Path::new("/workspace/target/debug/build/mvm-cli-nested-target")
    );
}
