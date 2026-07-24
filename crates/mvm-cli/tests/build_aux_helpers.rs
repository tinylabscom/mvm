#[path = "../build_aux_helpers.rs"]
mod build_aux_helpers;

use build_aux_helpers::{AuxHelperSpec, aux_helper_specs};

fn bins(specs: &[AuxHelperSpec]) -> Vec<&str> {
    specs.iter().map(|s| s.bin).collect()
}

#[test]
fn substitution_endpoint_builds_on_every_host() {
    let specs = aux_helper_specs("linux", "x86_64", false);
    assert_eq!(bins(&specs), vec!["mvm-substitution-endpoint"]);
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
