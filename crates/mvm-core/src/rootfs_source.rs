//! What a caller declared a machine should boot from.
//!
//! One type answers the question for both layers that ask it: the declaration
//! a caller hands in ([`crate::client::dto::MachineSpec::image`]) and the build
//! input a builder consumes (`mvm_runtime::artifacts::spec::RootfsSpec`). It
//! lives here rather than in the runtime because the declaration boundary sits
//! below the runtime, and here rather than in `mvm-contract` because
//! [`RootfsSource::LocalPath`] carries a [`PathBuf`], which `core` + `alloc`
//! has no equivalent of — and a host filesystem path means nothing on the
//! `wasm32` target that crate exists to serve.
//!
//! The string grammar is total and lossless: every value has a written form
//! that parses back to itself, and every well-formed string names exactly one
//! value. That is what lets a declaration travel as the plain string a user
//! typed (`--image alpine:3.20`) while still being a parsed value in memory.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Scheme prefixes that let a caller state which kind of source a string is,
/// overriding the shape heuristic below.
const PATH_SCHEME: &str = "path:";
const OCI_SCHEME: &str = "oci:";
const FLAKE_SCHEME: &str = "flake:";
/// Separates a flake reference from its output attribute, matching nix's own
/// `<flake-ref>#<attr>` spelling.
const FLAKE_ATTR_SEPARATOR: char = '#';

/// Where the rootfs comes from.
///
/// Serialized as its string form, not as a tagged enum: the same value reaches
/// a guest as `--image <string>` argv, and two spellings of one declaration are
/// two things that can disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum RootfsSource {
    /// Build from a Nix flake output at the given path/URL.
    Flake { flake_ref: String, attr: String },
    /// Use a pre-built rootfs image at the given local path.
    LocalPath(PathBuf),
    /// Import from an OCI image reference (pulled by the builder VM).
    Oci { image_ref: String },
}

/// Why a caller-supplied string is not a rootfs source at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootfsSourceParseError {
    #[error("empty rootfs source")]
    Empty,
    #[error("`{scheme}` prefix with no value")]
    EmptyPayload { scheme: &'static str },
    #[error("flake source `{flake_ref}` names no output attribute (write `flake:<ref>#<attr>`)")]
    MissingFlakeAttr { flake_ref: String },
}

impl RootfsSource {
    /// True for strings whose *shape* declares a filesystem location: an
    /// absolute path, an explicitly-relative one, or a home-relative one. An
    /// OCI reference can take none of these forms, so the two spaces do not
    /// overlap and the answer needs no filesystem lookup.
    fn is_path_shaped(s: &str) -> bool {
        s.starts_with('/')
            || s.starts_with("./")
            || s.starts_with("../")
            || s == "."
            || s == ".."
            || s.starts_with("~/")
    }
}

impl FromStr for RootfsSource {
    type Err = RootfsSourceParseError;

    /// Classify a caller-declared rootfs string **without consulting the
    /// filesystem**. What a string means is what the caller declared, not a
    /// function of what happens to exist in their working directory — probing
    /// makes a typo fall through to a different arm, and the arms differ in
    /// how the resulting bytes are verified.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Command substitution and file reads routinely carry a trailing
        // newline; the surrounding whitespace is never part of the intent.
        let s = s.trim();
        if s.is_empty() {
            return Err(RootfsSourceParseError::Empty);
        }
        if let Some(rest) = s.strip_prefix(PATH_SCHEME) {
            return non_empty(rest, PATH_SCHEME).map(|v| Self::LocalPath(PathBuf::from(v)));
        }
        if let Some(rest) = s.strip_prefix(OCI_SCHEME) {
            return non_empty(rest, OCI_SCHEME).map(|v| Self::Oci {
                image_ref: v.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix(FLAKE_SCHEME) {
            let rest = non_empty(rest, FLAKE_SCHEME)?;
            // Split on the *last* separator so a flake ref that carries its own
            // `#` still yields the attribute the caller wrote last.
            let (flake_ref, attr) = rest.rsplit_once(FLAKE_ATTR_SEPARATOR).ok_or_else(|| {
                RootfsSourceParseError::MissingFlakeAttr {
                    flake_ref: rest.to_string(),
                }
            })?;
            if flake_ref.is_empty() || attr.is_empty() {
                return Err(RootfsSourceParseError::MissingFlakeAttr {
                    flake_ref: rest.to_string(),
                });
            }
            return Ok(Self::Flake {
                flake_ref: flake_ref.to_string(),
                attr: attr.to_string(),
            });
        }
        if Self::is_path_shaped(s) {
            Ok(Self::LocalPath(PathBuf::from(s)))
        } else {
            Ok(Self::Oci {
                image_ref: s.to_string(),
            })
        }
    }
}

impl fmt::Display for RootfsSource {
    /// The shortest spelling that parses back to `self`. A declaration whose
    /// shape already speaks for itself is written verbatim, so a value that
    /// arrived as `alpine:3.20` leaves as `alpine:3.20` — the exact token the
    /// SDKs pass through as `--image`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalPath(path) => {
                write_bare_or_qualified(f, PATH_SCHEME, &path.to_string_lossy(), self)
            }
            Self::Oci { image_ref } => write_bare_or_qualified(f, OCI_SCHEME, image_ref, self),
            // A flake is never shape-inferable, so it always names its scheme.
            Self::Flake { flake_ref, attr } => {
                write!(f, "{FLAKE_SCHEME}{flake_ref}{FLAKE_ATTR_SEPARATOR}{attr}")
            }
        }
    }
}

/// Write `payload` on its own when it parses back to `value`, and
/// scheme-qualified otherwise. Deciding by re-parsing rather than by a second
/// copy of the shape rules keeps the written form correct by construction:
/// there is no heuristic here that can drift out of step with `FromStr`.
fn write_bare_or_qualified(
    f: &mut fmt::Formatter<'_>,
    scheme: &str,
    payload: &str,
    value: &RootfsSource,
) -> fmt::Result {
    if payload.parse::<RootfsSource>().as_ref() == Ok(value) {
        f.write_str(payload)
    } else {
        write!(f, "{scheme}{payload}")
    }
}

impl TryFrom<String> for RootfsSource {
    type Error = RootfsSourceParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<RootfsSource> for String {
    fn from(value: RootfsSource) -> Self {
        value.to_string()
    }
}

fn non_empty<'a>(value: &'a str, scheme: &'static str) -> Result<&'a str, RootfsSourceParseError> {
    if value.is_empty() {
        Err(RootfsSourceParseError::EmptyPayload { scheme })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod rootfs_source_parse_tests {
    use super::*;

    fn parse(s: &str) -> Result<RootfsSource, RootfsSourceParseError> {
        s.parse()
    }

    fn local(p: &str) -> RootfsSource {
        RootfsSource::LocalPath(PathBuf::from(p))
    }

    fn oci(r: &str) -> RootfsSource {
        RootfsSource::Oci {
            image_ref: r.to_string(),
        }
    }

    fn flake(flake_ref: &str, attr: &str) -> RootfsSource {
        RootfsSource::Flake {
            flake_ref: flake_ref.to_string(),
            attr: attr.to_string(),
        }
    }

    #[test]
    fn path_shapes_parse_as_local_paths() {
        assert_eq!(
            parse("/var/lib/rootfs.ext4").unwrap(),
            local("/var/lib/rootfs.ext4")
        );
        assert_eq!(parse("./rootfs.ext4").unwrap(), local("./rootfs.ext4"));
        assert_eq!(
            parse("../out/rootfs.ext4").unwrap(),
            local("../out/rootfs.ext4")
        );
        assert_eq!(
            parse("~/images/rootfs.ext4").unwrap(),
            local("~/images/rootfs.ext4")
        );
        assert_eq!(parse(".").unwrap(), local("."));
    }

    #[test]
    fn registry_shapes_parse_as_oci_references() {
        assert_eq!(parse("alpine:3.20").unwrap(), oci("alpine:3.20"));
        assert_eq!(
            parse("docker.io/library/alpine:3.20").unwrap(),
            oci("docker.io/library/alpine:3.20")
        );
        // A bare name that could name a file in someone's cwd is still a
        // reference — nothing here looks at the filesystem.
        assert_eq!(parse("rootfs.ext4").unwrap(), oci("rootfs.ext4"));
    }

    #[test]
    fn schemes_override_the_shape_heuristic() {
        assert_eq!(parse("path:rootfs.ext4").unwrap(), local("rootfs.ext4"));
        assert_eq!(
            parse("oci:/weird/repo:tag").unwrap(),
            oci("/weird/repo:tag")
        );
    }

    #[test]
    fn flake_sources_carry_a_reference_and_an_attribute() {
        assert_eq!(parse("flake:.#default").unwrap(), flake(".", "default"));
        assert_eq!(
            parse("flake:github:o/r?ref=main#packages.aarch64-linux.rootfs").unwrap(),
            flake("github:o/r?ref=main", "packages.aarch64-linux.rootfs")
        );
    }

    #[test]
    fn a_flake_without_an_attribute_is_an_error() {
        assert_eq!(
            parse("flake:.").unwrap_err(),
            RootfsSourceParseError::MissingFlakeAttr {
                flake_ref: ".".to_string()
            }
        );
        assert_eq!(
            parse("flake:.#").unwrap_err(),
            RootfsSourceParseError::MissingFlakeAttr {
                flake_ref: ".#".to_string()
            }
        );
    }

    #[test]
    fn empty_and_valueless_schemes_are_errors() {
        assert_eq!(parse("").unwrap_err(), RootfsSourceParseError::Empty);
        assert_eq!(parse("   \n").unwrap_err(), RootfsSourceParseError::Empty);
        assert_eq!(
            parse("path:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload {
                scheme: PATH_SCHEME
            }
        );
        assert_eq!(
            parse("oci:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload { scheme: OCI_SCHEME }
        );
        assert_eq!(
            parse("flake:").unwrap_err(),
            RootfsSourceParseError::EmptyPayload {
                scheme: FLAKE_SCHEME
            }
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_declaration() {
        assert_eq!(
            parse("  /var/rootfs.ext4\n").unwrap(),
            local("/var/rootfs.ext4")
        );
    }

    #[test]
    fn the_written_form_is_the_token_the_caller_typed() {
        // A declaration that needs no help keeps its exact bytes: this is the
        // same string the SDKs hand to `--image`, and a canonicalization that
        // rewrote it would put the declaration and the argv out of step.
        assert_eq!(oci("alpine:3.20").to_string(), "alpine:3.20");
        assert_eq!(
            local("/var/lib/rootfs.ext4").to_string(),
            "/var/lib/rootfs.ext4"
        );
        assert_eq!(local("./rootfs.ext4").to_string(), "./rootfs.ext4");
        // Only a value the shape heuristic would misread names its scheme.
        assert_eq!(local("rootfs.ext4").to_string(), "path:rootfs.ext4");
        assert_eq!(oci("/weird/repo:tag").to_string(), "oci:/weird/repo:tag");
        assert_eq!(flake(".", "default").to_string(), "flake:.#default");
    }

    #[test]
    fn every_value_round_trips_through_its_written_form() {
        // Totality is what lets the serialized form be the plain string: no
        // variant is unwritable, so serialization can never fail.
        for value in [
            local("/var/lib/rootfs.ext4"),
            local("./rootfs.ext4"),
            local("rootfs.ext4"),
            local("~/img/rootfs.ext4"),
            oci("alpine:3.20"),
            oci("ghcr.io/o/r@sha256:abc"),
            oci("path:not-a-path"),
            oci("/weird/repo:tag"),
            flake(".", "default"),
            flake("github:o/r?ref=main", "packages.rootfs"),
        ] {
            let written = value.to_string();
            assert_eq!(
                parse(&written).unwrap(),
                value,
                "{written:?} did not parse back to what wrote it"
            );
        }
    }

    #[test]
    fn serde_uses_the_string_form_and_rejects_a_meaningless_one() {
        let value = oci("alpine:3.20");
        assert_eq!(serde_json::to_string(&value).unwrap(), "\"alpine:3.20\"");
        assert_eq!(
            serde_json::from_str::<RootfsSource>("\"alpine:3.20\"").unwrap(),
            value
        );
        let err = serde_json::from_str::<RootfsSource>("\"\"").unwrap_err();
        assert!(
            err.to_string().contains("empty rootfs source"),
            "got: {err}"
        );
    }
}
