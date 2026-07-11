#[path = "../build_embed_mode.rs"]
mod build_embed_mode;

use build_embed_mode::should_skip_embed_binaries;

#[test]
fn source_builds_skip_embeds_by_default() {
    assert!(should_skip_embed_binaries(None, None, None));
}

#[test]
fn release_artifact_bootstrap_embeds_by_default() {
    assert!(!should_skip_embed_binaries(None, None, Some("1")));
}

#[test]
fn explicit_env_overrides_default() {
    assert!(!should_skip_embed_binaries(None, Some("1"), None));
    assert!(should_skip_embed_binaries(Some("1"), None, Some("1")));
}
