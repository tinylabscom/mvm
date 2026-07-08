#[path = "../build_embed_mode.rs"]
mod build_embed_mode;

use build_embed_mode::should_skip_embed_binaries;

#[test]
fn non_release_builds_skip_embeds_by_default() {
    assert!(should_skip_embed_binaries(Some("debug"), None, None));
    assert!(should_skip_embed_binaries(Some("test"), None, None));
}

#[test]
fn release_builds_embed_by_default() {
    assert!(!should_skip_embed_binaries(Some("release"), None, None));
}

#[test]
fn explicit_env_overrides_profile_default() {
    assert!(!should_skip_embed_binaries(Some("debug"), None, Some("1")));
    assert!(should_skip_embed_binaries(Some("release"), Some("1"), None));
}
