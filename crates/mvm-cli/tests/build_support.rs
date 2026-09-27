#[path = "../build_support.rs"]
mod build_support;

use std::path::{Path, PathBuf};

use build_support::shared_nested_target_dir;

#[test]
fn nested_target_dir_is_shared_across_feature_fingerprints() {
    assert_eq!(
        shared_nested_target_dir(Path::new("/t/debug/build/mvm-cli/aaaa/out")),
        PathBuf::from("/t/debug/build/mvm-cli/mvm-cli-nested-target")
    );
}
