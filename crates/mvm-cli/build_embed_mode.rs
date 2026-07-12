pub(crate) fn should_skip_embed_binaries(
    skip_env: Option<&str>,
    embed_env: Option<&str>,
    release_artifact_bootstrap_feature: Option<&str>,
) -> bool {
    if env_flag_enabled(skip_env) {
        return true;
    }
    if env_flag_enabled(embed_env) {
        return false;
    }
    !env_flag_enabled(release_artifact_bootstrap_feature)
}

fn env_flag_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

#[cfg(test)]
mod tests {
    use super::should_skip_embed_binaries;

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
        assert!(!should_skip_embed_binaries(None, Some("1"), None,));
        assert!(should_skip_embed_binaries(Some("1"), None, Some("1"),));
    }
}
