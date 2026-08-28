#[path = "../build_support.rs"]
mod build_support;

use std::path::{Path, PathBuf};

use build_support::{extract_quoted_after, shared_nested_target_dir};

#[test]
fn manifest_fields_are_read_out_of_the_struct_literal() {
    let manifest = include_str!("../src/host_binaries/manifest.rs");
    let names: Vec<String> = manifest
        .lines()
        .filter_map(|line| extract_quoted_after(line, "name:"))
        .collect();
    assert!(
        names.iter().any(|n| n == "mvm-network-endpoint"),
        "manifest.rs no longer parses with the build script's reader: {names:?}"
    );
}

#[test]
fn nested_target_dir_is_shared_across_feature_fingerprints() {
    assert_eq!(
        shared_nested_target_dir(Path::new("/t/debug/build/mvm-cli/aaaa/out")),
        PathBuf::from("/t/debug/build/mvm-cli/mvm-cli-nested-target")
    );
}
