#[path = "../build_aux_helpers.rs"]
mod build_aux_helpers;

use std::path::Path;

use build_aux_helpers::{AuxHelperSpec, aux_helper_specs, shared_nested_target_dir};

fn bins(specs: &[AuxHelperSpec]) -> Vec<&str> {
    specs.iter().map(|s| s.bin).collect()
}

/// Every host/arch combination mvmctl builds for.
const HOSTS: &[(&str, &str)] = &[
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("macos", "x86_64"),
    ("macos", "aarch64"),
];

#[test]
fn the_host_independent_helpers_build_on_every_host() {
    // Neither of these is gated on host capability, and the reason is the
    // same for both: whether a launch uses the egress endpoint or the L3
    // gateway is decided at admission from the signed plan. A binary that
    // existed on some hosts and not others would turn that into a
    // host-dependent decision.
    for (os, arch) in HOSTS {
        for libkrun in [false, true] {
            let specs = aux_helper_specs(os, arch, libkrun);
            let bins = bins(&specs);
            for required in ["mvm-network-endpoint", "mvm-netd"] {
                assert!(
                    bins.contains(&required),
                    "{required} must build on {os}/{arch} (libkrun={libkrun}), got {bins:?}"
                );
            }
        }
    }
}

#[test]
fn hvf_supervisor_only_on_macos_aarch64() {
    let mac = aux_helper_specs("macos", "aarch64", false);
    assert!(bins(&mac).contains(&"mvm-hvf-supervisor"));
    let linux = aux_helper_specs("linux", "aarch64", false);
    assert!(!bins(&linux).contains(&"mvm-hvf-supervisor"));
    let intel_mac = aux_helper_specs("macos", "x86_64", false);
    assert!(!bins(&intel_mac).contains(&"mvm-hvf-supervisor"));
}

#[test]
fn libkrun_supervisor_only_when_libkrun_present() {
    let present = aux_helper_specs("macos", "aarch64", true);
    let spec = present
        .iter()
        .find(|s| s.bin == "mvm-libkrun-supervisor")
        .expect("libkrun supervisor present");
    assert_eq!(spec.features, &["libkrun-sys"]);
    let absent = aux_helper_specs("macos", "aarch64", false);
    assert!(!bins(&absent).contains(&"mvm-libkrun-supervisor"));
}

#[test]
fn helper_specs_are_never_globally_skipped() {
    assert!(!aux_helper_specs("linux", "x86_64", false).is_empty());
    assert!(!aux_helper_specs("macos", "aarch64", true).is_empty());
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
