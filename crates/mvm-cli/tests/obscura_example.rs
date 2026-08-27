use std::fs;
use std::path::PathBuf;

fn example_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/obscura")
        .join(name)
}

#[test]
fn obscura_example_pins_both_release_architectures() {
    let flake =
        fs::read_to_string(example_file("flake.nix")).expect("Obscura flake must be readable");
    assert!(flake.contains("8ac11fb7db704d2a5acfd917804e066b8f9a102f2f0a8eaef110322848e12565"));
    assert!(flake.contains("d601f4f542319c3b9fa8dca9f5ccfc134a2ca001648da528db5f03c9e6c2599b"));
    assert!(flake.contains("x86_64-linux"));
    assert!(flake.contains("aarch64-linux"));
}

#[test]
fn obscura_example_fixes_proxy_loopback_and_deny_by_default() {
    let flake =
        fs::read_to_string(example_file("flake.nix")).expect("Obscura flake must be readable");
    let manifest =
        fs::read_to_string(example_file("mvm.toml")).expect("Obscura manifest must be readable");
    assert!(flake.contains("--proxy \"$ALL_PROXY\""));
    assert!(flake.contains("serve --host 127.0.0.1 --port 9222"));
    assert!(!flake.contains("private-network"));
    assert!(!flake.contains("stealth"));
    assert!(manifest.contains("net = false"));
}

#[test]
fn obscura_example_documents_explicit_opt_in() {
    let readme =
        fs::read_to_string(example_file("README.md")).expect("Obscura README must be readable");
    assert!(readme.contains("MVM_SDK_MODE=live"));
    assert!(readme.contains("Chromium remains the default"));
    assert!(readme.contains("Apache-2.0"));
}

#[test]
fn obscura_example_declares_ingress_before_a_detached_boot() {
    let readme =
        fs::read_to_string(example_file("README.md")).expect("Obscura README must be readable");

    assert!(readme.contains("machine run -d"));
    assert!(readme.contains("--port 9222:9222"));
    assert!(!readme.contains("machine forward"));
}
