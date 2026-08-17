use crate::packs::KeylessTrust;

/// OIDC issuer a stock binary trusts for its own release packs.
pub const RELEASE_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Identity templates for the workflow that signs release packs. `{version}`
/// is replaced with the running binary's version before matching.
const RELEASE_IDENTITY_TEMPLATES: &[&str] =
    &["https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v{version}"];

/// Identity template for the workflow that signs boot image releases.
///
/// Deliberately a **separate** list from [`RELEASE_IDENTITY_TEMPLATES`] rather
/// than another entry in it. The two trains sign different artifact classes
/// under different refs, and folding them together would mean a signature
/// minted over a boot image could validate a CLI tarball and the reverse. Two
/// lists keeps each class verifiable only by the workflow that actually
/// produces it.
///
/// `{version}` is the bare semver of the image line — `0.1.0` for the
/// `boot-image/v0.1.0` tag — so the interpolation matches the ref exactly.
const BOOT_IMAGE_IDENTITY_TEMPLATES: &[&str] = &[
    "https://github.com/tinylabscom/mvm/.github/workflows/release-boot-image.yml@refs/tags/boot-image/v{version}",
];

/// Interpolate an image-line version into every boot image identity template.
pub fn accepted_boot_image_identities(version: &str) -> Vec<String> {
    BOOT_IMAGE_IDENTITY_TEMPLATES
        .iter()
        .map(|template| template.replace("{version}", version))
        .collect()
}

/// Keyless trust root for artifacts fetched from a boot image release.
pub fn boot_image_keyless_trust(version: &str) -> KeylessTrust {
    KeylessTrust {
        accepted_identities: accepted_boot_image_identities(version),
        issuer: RELEASE_OIDC_ISSUER.to_string(),
    }
}

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

#[cfg(test)]
mod boot_image_trust_tests {
    use super::*;

    /// The two trains must not be able to vouch for each other's artifacts.
    /// One shared list would mean a signature over a boot image also validates
    /// a CLI tarball, which is a strictly larger grant than either train needs.
    #[test]
    fn the_boot_image_and_cli_identity_sets_are_disjoint() {
        let cli = accepted_release_identities("0.18.0");
        let image = accepted_boot_image_identities("0.1.0");
        assert!(!cli.is_empty() && !image.is_empty());
        for identity in &image {
            assert!(
                !cli.contains(identity),
                "boot image identity {identity} must not be accepted for CLI artifacts"
            );
        }
    }

    /// The interpolated identity has to match the ref the workflow actually
    /// runs under, or every verification fails closed at first use.
    #[test]
    fn the_boot_image_identity_matches_the_published_tag_ref() {
        let identities = accepted_boot_image_identities("0.1.0");
        assert_eq!(
            identities,
            vec![
                "https://github.com/tinylabscom/mvm/.github/workflows/release-boot-image.yml@refs/tags/boot-image/v0.1.0"
                    .to_string()
            ]
        );
    }

    #[test]
    fn the_boot_image_trust_root_uses_the_release_issuer() {
        let trust = boot_image_keyless_trust("0.1.0");
        assert_eq!(trust.issuer, RELEASE_OIDC_ISSUER);
        assert_eq!(trust.accepted_identities.len(), 1);
    }
}
