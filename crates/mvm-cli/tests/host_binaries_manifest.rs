#[cfg(feature = "embed-host-bins")]
use mvm_cli::host_binaries::embedded::EMBEDDED;
use mvm_cli::host_binaries::manifest::{BOOTSTRAP_SUPPORT_BINARIES, HOST_BINARIES, HostBinary};

#[test]
fn manifest_lists_expected_host_binaries() {
    let names: Vec<&str> = HOST_BINARIES.iter().map(|b| b.name).collect();
    assert!(names.contains(&"mvm-host-vm-init"));
    assert!(names.contains(&"mvm-egress-proxy"));
    // The resident builder control daemon, baked into the builder/dev rootfs.
    assert!(names.contains(&"mvm-builderd"));
    assert_eq!(
        HOST_BINARIES.len(),
        3,
        "expected exactly three rootfs-installed host binaries"
    );
}

#[test]
fn manifest_install_paths_match_adr_064() {
    let by_name = |n: &str| -> &HostBinary { HOST_BINARIES.iter().find(|b| b.name == n).unwrap() };
    assert_eq!(
        by_name("mvm-host-vm-init").install_path,
        "/sbin/mvm-host-vm-init"
    );
    assert_eq!(by_name("mvm-host-vm-init").mode, 0o755);
    assert_eq!(
        by_name("mvm-egress-proxy").install_path,
        "/sbin/mvm-egress-proxy"
    );
    assert_eq!(by_name("mvm-egress-proxy").mode, 0o755);
    assert_eq!(by_name("mvm-builderd").install_path, "/sbin/mvm-builderd");
    assert_eq!(by_name("mvm-builderd").mode, 0o755);
}

/// The other tests here are about the manifest constants and hold in every
/// configuration. This one is about the payload, so it exists only where there
/// is a payload to inspect.
#[cfg(feature = "embed-host-bins")]
#[test]
fn embedded_bootstrap_support_binaries_include_egress_client() {
    assert!(
        EMBEDDED
            .iter()
            .any(|binary| binary.name == "mvm-egress-client")
    );
}

#[test]
fn egress_client_manifest_selects_the_addons_feature() {
    let binary = BOOTSTRAP_SUPPORT_BINARIES
        .iter()
        .find(|binary| binary.name == "mvm-egress-client")
        .expect("bootstrap manifest must include mvm-egress-client");
    assert_eq!(binary.package, "mvm-agentd");
    assert_eq!(binary.features, "addons");
}
