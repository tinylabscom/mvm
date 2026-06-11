//! OCI image reference parsing.
//!
//! Accepts the spectrum of reference shapes that show up in
//! practice:
//!
//! - `alpine` — bare image name, defaults to Docker Hub `library/`
//!   namespace + `latest` tag.
//! - `alpine:3.19` — tag-pinned bare image.
//! - `alpine@sha256:…` — digest-pinned bare image.
//! - `library/alpine:3.19` — explicit Docker Hub namespace.
//! - `ghcr.io/foo/bar:v1` — explicit registry, no `library/` rewrite.
//! - `registry.local:5000/foo/bar:v1` — registry with port (the
//!   port is what distinguishes a registry host from a Docker Hub
//!   organization).
//! - `ghcr.io/foo/bar@sha256:…` — fully-qualified digest pin.
//! - `ghcr.io/foo/bar:v1@sha256:…` — tag *and* digest. Both are
//!   preserved; production-profile admission uses the digest.
//!
//! Production-profile admission rejects references that resolve to a
//! tag *without* a digest — the mutable-tag-rejection rule for OCI
//! ingest.

use crate::OciError;
use std::fmt;
use std::str::FromStr;

/// Default registry when the reference omits one. Matches Docker
/// CLI behaviour.
const DEFAULT_REGISTRY: &str = "docker.io";
/// Docker Hub rewrites single-component repositories like `alpine`
/// to `library/alpine`. We follow the same convention so users can
/// paste references from Docker Hub URLs without modification.
const DOCKER_HUB_LIBRARY_NAMESPACE: &str = "library";
/// Default tag when the reference omits both a tag and a digest.
/// Matches Docker CLI behaviour.
const DEFAULT_TAG: &str = "latest";

/// Structured OCI image reference. Equality and hashing are over
/// the canonical form, not the user-supplied string — `alpine` and
/// `docker.io/library/alpine:latest` are the same image.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageReference {
    /// Registry hostname (`docker.io`, `ghcr.io`,
    /// `registry.local:5000`, …). Always lowercase. Never includes
    /// a scheme.
    pub registry: String,
    /// Repository path within the registry (`library/alpine`,
    /// `foo/bar`, …). Lowercase per the OCI spec's repository
    /// constraints.
    pub repository: String,
    /// Tag when present. `None` only when the reference is
    /// digest-pinned and the user did not supply a tag.
    pub tag: Option<String>,
    /// Content digest when present. `Some` is what production
    /// profile requires.
    pub digest: Option<String>,
}

impl ImageReference {
    /// True when the reference pins a content digest. The production
    /// profile only admits digest-pinned references.
    pub fn is_digest_pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// Canonical string form: `<registry>/<repository>[:<tag>][@<digest>]`.
    /// Used as the round-trip representation in tests and as the
    /// audit-log identifier on resolve/fetch/launch events.
    pub fn canonical(&self) -> String {
        let mut out = format!("{}/{}", self.registry, self.repository);
        if let Some(tag) = &self.tag {
            out.push(':');
            out.push_str(tag);
        }
        if let Some(digest) = &self.digest {
            out.push('@');
            out.push_str(digest);
        }
        out
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl FromStr for ImageReference {
    type Err = OciError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Deliberately do NOT trim. Docker CLI doesn't, and silently
        // accepting `\talpine` or trailing whitespace turns a
        // pasted-from-docs typo into a working reference — bad for
        // users debugging a real "image not found" message.
        if s.is_empty() {
            return Err(OciError::InvalidReference("empty reference".to_string()));
        }
        if s.contains(char::is_whitespace) {
            return Err(OciError::InvalidReference(
                "reference contains whitespace".to_string(),
            ));
        }

        // Split off an optional `@<digest>` suffix first. The digest is
        // always the last component; everything before it is the
        // tag-bearing portion.
        let (tag_bearing, digest) = match s.rsplit_once('@') {
            Some((head, digest)) => (head, Some(digest.to_string())),
            None => (s, None),
        };
        if let Some(d) = &digest {
            validate_digest(d)?;
        }

        // Decide whether the first slash-separated component is a
        // registry hostname or a Docker Hub organization. The OCI
        // spec's distinguishing rule: if the component contains a
        // `.`, a `:`, or equals `localhost`, treat it as a registry.
        // Otherwise the whole repository sits on the default
        // registry.
        let (registry, path_after_registry) = match tag_bearing.split_once('/') {
            Some((first, rest))
                if first == "localhost" || first.contains('.') || first.contains(':') =>
            {
                (first.to_lowercase(), rest)
            }
            _ => (DEFAULT_REGISTRY.to_string(), tag_bearing),
        };

        // Within the registry-less portion, split off an optional
        // `:<tag>` suffix. The tag is delimited by the *last* colon
        // because Docker-Hub-style refs never have colons in the
        // repository path.
        let (repository, tag) = match path_after_registry.rsplit_once(':') {
            Some((repo, tag)) if !tag.is_empty() && !tag.contains('/') => {
                (repo, Some(tag.to_string()))
            }
            _ => (path_after_registry, None),
        };

        if repository.is_empty() {
            return Err(OciError::InvalidReference(format!(
                "missing repository in reference: {s:?}"
            )));
        }

        // Docker Hub's `library/` rewrite kicks in only on the
        // default registry and only for single-component repos.
        let repository = if registry == DEFAULT_REGISTRY && !repository.contains('/') {
            format!("{DOCKER_HUB_LIBRARY_NAMESPACE}/{repository}")
        } else {
            repository.to_string()
        };

        validate_repository(&repository)?;

        // If neither a tag nor a digest is supplied, fall back to
        // `latest`. This matches Docker CLI behaviour but is the
        // *least secure* default — production-profile admission
        // rejects it because there is no digest pin.
        let tag = tag.or_else(|| {
            if digest.is_none() {
                Some(DEFAULT_TAG.to_string())
            } else {
                None
            }
        });

        Ok(ImageReference {
            registry,
            repository,
            tag,
            digest,
        })
    }
}

fn validate_digest(d: &str) -> Result<(), OciError> {
    // Format: `<algorithm>:<hex>` where `<algorithm>` is sha256 in
    // v1 and `<hex>` is the canonical lowercase hex digest. The OCI
    // spec allows multi-algorithm refs; we narrow on purpose and
    // surface the unsupported case as a distinct error.
    let (alg, hex) = d
        .split_once(':')
        .ok_or_else(|| OciError::MalformedDigest(format!("missing algorithm prefix: {d:?}")))?;
    match alg {
        "sha256" => {}
        other => {
            return Err(OciError::UnsupportedDigestAlgorithm(other.to_string()));
        }
    }
    if hex.len() != 64 {
        return Err(OciError::MalformedDigest(format!(
            "sha256 digest must be 64 hex chars, got {} in {d:?}",
            hex.len()
        )));
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(OciError::MalformedDigest(format!(
            "digest hex must be lowercase ascii: {d:?}"
        )));
    }
    Ok(())
}

fn validate_repository(repo: &str) -> Result<(), OciError> {
    // OCI spec: repository components are
    // [a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)* separated by `/`.
    // We enforce the lower bound — non-empty, lowercase, only the
    // allowed bytes — and leave the more elaborate constraints (no
    // consecutive separators, etc.) to the registry. The point of
    // validation here is to fail fast on obviously broken inputs
    // before we hit the network.
    if repo.is_empty() {
        return Err(OciError::InvalidReference("empty repository".to_string()));
    }
    let allowed = |b: u8| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'.' | b'_' | b'-')
    };
    for byte in repo.bytes() {
        if !allowed(byte) {
            return Err(OciError::InvalidReference(format!(
                "repository contains forbidden byte {:?}: {repo:?}",
                byte as char
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> ImageReference {
        s.parse::<ImageReference>().unwrap_or_else(|e| {
            panic!("parse failed for {s:?}: {e}");
        })
    }

    #[test]
    fn bare_image_defaults_to_docker_hub_library_and_latest() {
        let r = parse("alpine");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("latest"));
        assert!(r.digest.is_none());
        assert!(!r.is_digest_pinned());
    }

    #[test]
    fn bare_image_with_tag() {
        let r = parse("alpine:3.19");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag.as_deref(), Some("3.19"));
        assert!(r.digest.is_none());
    }

    #[test]
    fn bare_image_with_digest_no_tag() {
        let r =
            parse("alpine@sha256:abc12345abc12345abc12345abc12345abc12345abc12345abc12345abc12345");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert!(r.tag.is_none(), "digest-only refs should not default a tag");
        assert!(r.is_digest_pinned());
    }

    #[test]
    fn docker_hub_namespaced_repo_does_not_get_library_prefix() {
        let r = parse("myorg/myapp:v1");
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "myorg/myapp");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn explicit_registry_via_dot_in_first_component() {
        let r = parse("ghcr.io/foo/bar:v1");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn explicit_registry_with_port_uses_colon_marker() {
        let r = parse("registry.local:5000/foo/bar:v1");
        assert_eq!(r.registry, "registry.local:5000");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn localhost_is_a_registry_even_without_dot() {
        let r = parse("localhost/foo:v1");
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "foo");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn tag_and_digest_both_preserved() {
        let r = parse(
            "ghcr.io/foo/bar:v1@sha256:abc12345abc12345abc12345abc12345abc12345abc12345abc12345abc12345",
        );
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "foo/bar");
        assert_eq!(r.tag.as_deref(), Some("v1"));
        assert!(r.is_digest_pinned());
    }

    #[test]
    fn canonical_round_trip_for_default_registry() {
        let r = parse("alpine:3.19");
        assert_eq!(r.canonical(), "docker.io/library/alpine:3.19");
    }

    #[test]
    fn canonical_round_trip_for_digest_pinned() {
        let digest = "sha256:abc12345abc12345abc12345abc12345abc12345abc12345abc12345abc12345";
        let r = parse(&format!("ghcr.io/foo/bar@{digest}"));
        assert_eq!(r.canonical(), format!("ghcr.io/foo/bar@{digest}"));
    }

    #[test]
    fn empty_string_rejected() {
        assert!("".parse::<ImageReference>().is_err());
    }

    #[test]
    fn whitespace_in_reference_rejected() {
        assert!("alpine :3.19".parse::<ImageReference>().is_err());
        assert!("\talpine".parse::<ImageReference>().is_err());
    }

    #[test]
    fn uppercase_repository_rejected() {
        // OCI spec requires lowercase repositories.
        let err = "Foo/Bar:v1".parse::<ImageReference>().unwrap_err();
        match err {
            OciError::InvalidReference(_) => {}
            other => panic!("expected InvalidReference, got {other:?}"),
        }
    }

    #[test]
    fn digest_must_be_sha256_in_v1() {
        let err = "alpine@sha512:abc".parse::<ImageReference>().unwrap_err();
        match err {
            OciError::UnsupportedDigestAlgorithm(alg) => {
                assert_eq!(alg, "sha512");
            }
            other => panic!("expected UnsupportedDigestAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn digest_must_be_64_lowercase_hex_chars() {
        // wrong length
        let err = "alpine@sha256:abc".parse::<ImageReference>().unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");

        // uppercase
        let upper = format!("alpine@sha256:{}", "ABC".repeat(64 / 3));
        let err = upper.parse::<ImageReference>().unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");

        // non-hex
        let err = "alpine@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            .parse::<ImageReference>()
            .unwrap_err();
        assert!(matches!(err, OciError::MalformedDigest(_)), "got {err:?}");
    }

    #[test]
    fn registry_hostname_normalizes_to_lowercase() {
        let r = parse("GHCR.IO/foo/bar:v1");
        assert_eq!(r.registry, "ghcr.io");
    }

    #[test]
    fn missing_repository_rejected() {
        // `docker.io/` has a registry but no repo.
        assert!("docker.io/".parse::<ImageReference>().is_err());
        assert!("docker.io/:tag".parse::<ImageReference>().is_err());
    }

    #[test]
    fn equality_is_over_canonical_form() {
        let a: ImageReference = "alpine:3.19".parse().unwrap();
        let b: ImageReference = "docker.io/library/alpine:3.19".parse().unwrap();
        assert_eq!(a, b, "{} vs {}", a.canonical(), b.canonical());
    }
}
