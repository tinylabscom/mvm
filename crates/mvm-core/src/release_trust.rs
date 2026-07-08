use crate::packs::KeylessTrust;

/// OIDC issuer a stock binary trusts for its own release packs.
pub const RELEASE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Identity templates for the workflow that signs release packs. `{version}`
/// is replaced with the running binary's version before matching.
const RELEASE_IDENTITY_TEMPLATES: &[&str] =
    &["https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"];

/// Channel the release pipeline signs builder and runtime packs on. A stock
/// binary's local policy must allow this channel for its own release packs to
/// verify, alongside whatever channels the operator's ed25519 trust config
/// already allows.
pub const RELEASE_CHANNELS: &[&str] = &["stable"];

/// Owned copy of [`RELEASE_CHANNELS`] for callers building a `BTreeSet`/`Vec`.
pub fn release_channels() -> Vec<String> {
    RELEASE_CHANNELS.iter().map(|c| c.to_string()).collect()
}

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

/// Identity for the workflow that signs the pack revocation list. Unlike
/// `RELEASE_IDENTITY_TEMPLATES`, this carries no `{version}` placeholder — a
/// revocation list applies across every released version, so its signing
/// identity is bound to a dedicated `revocations` tag instead of a
/// per-release one. A separate identity from the release workflow also means
/// a leaked release-signing cert can't forge a revocation entry.
const REVOCATION_IDENTITY_TEMPLATES: &[&str] =
    &["https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations"];

/// Build the keyless trust root a stock binary uses to verify the fetched
/// pack revocation list.
pub fn revocation_keyless_trust() -> KeylessTrust {
    KeylessTrust {
        accepted_identities: REVOCATION_IDENTITY_TEMPLATES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        issuer: RELEASE_OIDC_ISSUER.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_channels_non_empty() {
        let channels = release_channels();
        assert!(!channels.is_empty());
        assert!(channels.iter().any(|c| c == "stable"));
    }

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

    #[test]
    fn revocation_keyless_trust_uses_release_issuer() {
        let t = revocation_keyless_trust();
        assert_eq!(t.issuer, RELEASE_OIDC_ISSUER);
    }

    #[test]
    fn revocation_keyless_trust_identities_target_revocations_tag() {
        let t = revocation_keyless_trust();
        assert!(
            t.accepted_identities
                .iter()
                .any(|i| i.contains("revocations.yml@refs/tags/revocations"))
        );
    }

    #[test]
    fn revocation_keyless_trust_has_no_version_placeholder() {
        let t = revocation_keyless_trust();
        assert!(
            t.accepted_identities
                .iter()
                .all(|i| !i.contains("{version}"))
        );
    }
}
