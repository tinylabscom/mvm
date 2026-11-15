#[path = "../build_support.rs"]
mod build_support;

use std::path::{Path, PathBuf};

use build_support::{SOURCE_IDENTITY_PATHS, shared_nested_target_dir};

#[test]
fn source_identity_watches_only_existing_workspace_inputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate is under crates/");
    for path in SOURCE_IDENTITY_PATHS {
        assert!(
            root.join(path).exists(),
            "watching missing {path} forces every unchanged build to recompile"
        );
    }
}

#[test]
fn nested_target_dir_is_shared_across_feature_fingerprints() {
    assert_eq!(
        shared_nested_target_dir(Path::new("/t/debug/build/mvm-cli/aaaa/out")),
        PathBuf::from("/t/debug/build/mvm-cli/mvm-cli-nested-target")
    );
}
