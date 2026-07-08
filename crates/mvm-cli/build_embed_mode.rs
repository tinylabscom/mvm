pub(crate) fn should_skip_embed_binaries(
    profile: Option<&str>,
    skip_env: Option<&str>,
    embed_env: Option<&str>,
) -> bool {
    if env_flag_enabled(skip_env) {
        return true;
    }
    if env_flag_enabled(embed_env) {
        return false;
    }
    !matches!(profile, Some("release"))
}

fn env_flag_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

#[cfg(test)]
mod tests {
    use super::should_skip_embed_binaries;

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
        assert!(!should_skip_embed_binaries(Some("debug"), None, Some("1"),));
        assert!(should_skip_embed_binaries(Some("release"), Some("1"), None,));
    }
}
