use crate::packs::KeylessTrust;

/// OIDC issuer a stock binary trusts for its own release packs.
pub const RELEASE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Identity templates for the workflow that signs release packs. `{version}`
/// is replaced with the running binary's version before matching.
const RELEASE_IDENTITY_TEMPLATES: &[&str] =
    &["https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"];

/// Interpolate `{version}` into every release identity template.
pub fn accepted_release_identities(version: &str) -> Vec<String> {
    RELEASE_IDENTITY_TEMPLATES
        .iter()
        .map(|template| template.replace("{version}", version))
        .collect()
}

/// Build the keyless trust root a stock binary uses to verify its own
/// release packs, for the given version.
pub fn release_keyless_trust(version: &str) -> KeylessTrust {
    KeylessTrust {
        accepted_identities: accepted_release_identities(version),
        issuer: RELEASE_OIDC_ISSUER.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_interpolate_version_exactly() {
        let ids = accepted_release_identities("0.17.0");
        assert!(!ids.is_empty());
        assert!(
            ids.iter()
                .all(|i| i.contains("@refs/tags/v0.17.0") && !i.contains("{version}"))
        );
        assert!(
            ids.iter()
                .any(|i| i.contains(".github/workflows/release.yml"))
        );
    }

    #[test]
    fn keyless_trust_carries_issuer_and_ids() {
        let t = release_keyless_trust("0.17.0");
        assert_eq!(t.issuer, RELEASE_OIDC_ISSUER);
        assert_eq!(t.accepted_identities, accepted_release_identities("0.17.0"));
    }
}
