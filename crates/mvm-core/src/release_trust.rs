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

/// Identity template for the canonical image-set producer.
///
/// This is intentionally separate from the legacy boot-image identities. The
/// compatibility window accepts both *for their own repositories and tags*;
/// it never lets either workflow sign the other producer's bytes.
const IMAGE_SET_IDENTITY_TEMPLATES: &[&str] = &[
    "https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/image-set/v{version}",
];

/// Identity for the rolling, commit-addressed source-helper producer.
const SOURCE_HELPER_IDENTITY_TEMPLATES: &[&str] = &[
    "https://github.com/tinylabscom/mvm/.github/workflows/source-host-helpers.yml@refs/heads/main",
];

/// Accepted workflow identities for commit-addressed source helper bundles.
pub fn accepted_source_helper_identities() -> Vec<String> {
    SOURCE_HELPER_IDENTITY_TEMPLATES
        .iter()
        .map(|identity| (*identity).to_string())
        .collect()
}

/// Interpolate an image-set version into the canonical producer identity.
pub fn accepted_image_set_identities(version: &str) -> Vec<String> {
    IMAGE_SET_IDENTITY_TEMPLATES
        .iter()
        .map(|template| template.replace("{version}", version))
        .collect()
}

/// Keyless trust root for the canonical signed image-set train.
pub fn image_set_keyless_trust(version: &str) -> KeylessTrust {
    KeylessTrust {
        accepted_identities: accepted_image_set_identities(version),
        issuer: RELEASE_OIDC_ISSUER.to_string(),
    }
}

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

/// Workflow that signs the image-set revocation list, up to the ref.
///
/// This authority is separate from three others on purpose: the image-set
/// release workflow (which signs the sets being revoked, and so must not be
/// able to un-revoke them), this repository's pack revocation workflow, and
/// the registry-pack revocation feed. A signature from any of those is refused
/// here, and this identity is accepted by none of them.
const IMAGE_SET_REVOCATION_WORKFLOW: &str =
    "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml";

/// The only ref the image-set revocation workflow publishes from. The producer
/// pushes the next `revocation-list/v<N>` tag for every publication, so `N` is
/// an authenticated publication counter carried by the signing certificate.
const IMAGE_SET_REVOCATION_REF_PREFIX: &str = "@refs/tags/revocation-list/v";

/// The publication number `N` of an image-set revocation signer identity, or
/// `None` when `identity` is not exactly
/// `<revocations workflow>@refs/tags/revocation-list/v<N>`.
///
/// `N` must be a canonical positive decimal: no sign, no leading zero, no
/// suffix. Any other repository, workflow, branch, or tag shape is refused.
pub fn image_set_revocation_publication(identity: &str) -> Option<u64> {
    let digits = identity
        .strip_prefix(IMAGE_SET_REVOCATION_WORKFLOW)?
        .strip_prefix(IMAGE_SET_REVOCATION_REF_PREFIX)?;
    if digits.is_empty()
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

/// The signer identity for publication `n` of the image-set revocation list.
pub fn image_set_revocation_identity(publication: u64) -> String {
    format!("{IMAGE_SET_REVOCATION_WORKFLOW}{IMAGE_SET_REVOCATION_REF_PREFIX}{publication}")
}

#[cfg(test)]
mod image_set_revocation_trust_tests {
    use super::*;

    #[test]
    fn the_published_identity_parses_to_its_publication_number() {
        assert_eq!(
            image_set_revocation_publication(
                "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v1"
            ),
            Some(1)
        );
        assert_eq!(
            image_set_revocation_publication(&image_set_revocation_identity(42)),
            Some(42)
        );
    }

    #[test]
    fn every_other_identity_shape_is_refused() {
        let refused = [
            // Another repository's revocation workflow.
            "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocation-list/v1",
            "https://github.com/tinylabscom/mvm/.github/workflows/revocations.yml@refs/tags/revocations",
            // The image-set release workflow signs sets, not their revocation.
            "https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/revocation-list/v1",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/image-set/v0.1.0",
            // A branch, the retired tag namespace, and malformed counters.
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/heads/main",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocations/v1",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v0",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v01",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v1.0",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v+1",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v1 ",
            "https://github.com/tinylabscom/mvm-images/.github/workflows/revocations.yml@refs/tags/revocation-list/v99999999999999999999999",
        ];
        for identity in refused {
            assert_eq!(
                image_set_revocation_publication(identity),
                None,
                "{identity} must not be an image-set revocation signer"
            );
        }
    }

    #[test]
    fn the_authority_is_disjoint_from_every_other_compiled_identity() {
        let others = revocation_keyless_trust()
            .accepted_identities
            .into_iter()
            .chain(accepted_image_set_identities("0.1.0"))
            .chain(accepted_boot_image_identities("0.1.0"))
            .chain(accepted_release_identities("0.1.0"));
        for identity in others {
            assert_eq!(image_set_revocation_publication(&identity), None);
        }
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

    #[test]
    fn source_helpers_trust_only_the_main_branch_producer() {
        assert_eq!(
            accepted_source_helper_identities(),
            vec![
                "https://github.com/tinylabscom/mvm/.github/workflows/source-host-helpers.yml@refs/heads/main"
                    .to_string()
            ]
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

    #[test]
    fn the_old_and_new_image_identities_are_explicit_and_disjoint() {
        let legacy = accepted_boot_image_identities("0.1.5");
        let canonical = accepted_image_set_identities("0.1.0");
        assert_eq!(
            canonical,
            vec![
                "https://github.com/tinylabscom/mvm-images/.github/workflows/release.yml@refs/tags/image-set/v0.1.0"
                    .to_string()
            ]
        );
        assert!(canonical.iter().all(|identity| !legacy.contains(identity)));
        assert_eq!(image_set_keyless_trust("0.1.0").issuer, RELEASE_OIDC_ISSUER);
    }
}
