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
