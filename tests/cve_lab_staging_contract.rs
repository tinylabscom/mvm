use std::fs;
use std::path::Path;

#[test]
fn detonation_initramfs_matches_the_pinned_poc_success_contract() {
    let script_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/stage-cve-2026-80521-lab.sh");
    let script = fs::read_to_string(&script_path).expect("read the CVE staging script");

    for required in [
        "CONTAINER_ESCAPE_SUCCESS uid=",
        "*/payload)",
        "initramfs-root/payload",
        "initramfs-root/bin/$applet",
        "initramfs-root/usr/bin/readlink",
        "\n/payload\n",
    ] {
        assert!(
            script.contains(required),
            "staging script lost the pinned PoC contract token {required:?}"
        );
    }
    assert!(
        !script.contains("initramfs-root/exploit"),
        "renaming the binary to /exploit prevents the PoC helper finding /payload"
    );
}

#[test]
fn detonation_waits_for_boot_noise_before_starting_the_timing_oracle() {
    let script_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/stage-cve-2026-80521-lab.sh");
    let script = fs::read_to_string(&script_path).expect("read the CVE staging script");
    let settle = script
        .find("/bin/busybox sleep 2\n")
        .expect("initramfs must let asynchronous kernel initialization settle");
    let marker = script
        .find("echo \"CVE-LAB-BOOT:")
        .expect("initramfs must print the boot marker");
    let payload = script
        .find("\n/payload\n")
        .expect("initramfs must execute the pinned payload");

    assert!(
        settle < marker && marker < payload,
        "the quiet period must precede both the marker and timing-sensitive payload"
    );
}

#[test]
fn target_kernel_and_evidence_initramfs_are_independently_pinned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = fs::read_to_string(root.join("scripts/stage-cve-2026-80521-lab.sh"))
        .expect("read the CVE staging script");
    let pins = fs::read_to_string(root.join("features/suites/s37_cve_containment/pins.toml"))
        .expect("read the CVE pins");

    for required in [
        "deb_url = \"https://archive.ubuntu.com/ubuntu/",
        "deb_sha256 = \"f144b113c6957c186c404f31646ca749bf30107b12d78ad30d04ff1f3beb08ef\"",
        "initramfs_sha256 = \"c184ec04011d0086c43a430be4919d2fe9de7af62ea8565301eb69d7499f20ad\"",
    ] {
        assert!(pins.contains(required), "missing concrete pin {required:?}");
    }
    for required in [
        "deb_url=\"$(pin deb_url)\"",
        "deb_sha=\"$(pin deb_sha256)\"",
        "digest mismatch against the reviewed pin",
        "touch -h -d '@0'",
        "--reproducible --owner=0:0",
    ] {
        assert!(
            script.contains(required),
            "staging script lost authenticity/reproducibility check {required:?}"
        );
    }
    assert!(
        !script.contains("MVM_CVE_LAB_DEB_URL"),
        "the environment must not override reviewed kernel package pins"
    );
}
