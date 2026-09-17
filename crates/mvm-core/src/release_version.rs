//! A released version, ordered by semantic-version precedence.
//!
//! One parser serves two kinds of input. Tags already published and versions
//! a binary reports about itself are read leniently, because refusing a shape
//! that has shipped would leave an updater unable to order what it installed.
//! Identities a new manifest declares are read strictly, because a publisher
//! can be held to the grammar before anything depends on the value.

use std::cmp::Ordering;

/// How much of the semver 2.0.0 grammar a parse enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSyntax {
    /// Accepts surrounding whitespace, a leading `v`, and leading zeros, and
    /// discards build metadata without inspecting it.
    Lenient,
    /// The semver grammar exactly: no prefix, no leading zeros in numeric
    /// identifiers, identifiers drawn from `[0-9A-Za-z-]`, and well-formed
    /// build metadata.
    Strict,
}

/// A version reduced to what semver precedence compares: the release triple
/// and the pre-release identifiers. Build metadata is not part of it, so two
/// versions that differ only there are equal, which keeps `Eq` and `Ord`
/// consistent.
///
/// A pre-release ranks below the release it precedes. Dropping the suffix
/// instead would make `0.18.0-rc.1` compare equal to `0.18.0`, which is the
/// comparison an updater most needs to get right.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReleaseVersion {
    core: [u64; 3],
    /// Empty for a normal release.
    pre_release: Vec<PreReleaseId>,
}

/// Declared numeric-first, so the derived `Ord` ranks numeric identifiers
/// below alphanumeric ones, numeric pairs by value, and alphanumeric pairs in
/// ASCII order, as semver §11 requires.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PreReleaseId {
    Numeric(u64),
    Alphanumeric(String),
}

impl ReleaseVersion {
    /// Parse `X.Y.Z[-pre][+build]` under `syntax`. Anything else returns
    /// `None`: a version that cannot be ordered is one a caller must not claim
    /// to have ordered.
    pub fn parse(raw: &str, syntax: VersionSyntax) -> Option<Self> {
        let raw = match syntax {
            VersionSyntax::Lenient => {
                let trimmed = raw.trim();
                trimmed.strip_prefix('v').unwrap_or(trimmed)
            }
            VersionSyntax::Strict => raw,
        };
        let (versioned, build) = match raw.split_once('+') {
            Some((versioned, build)) => (versioned, Some(build)),
            None => (raw, None),
        };
        if syntax == VersionSyntax::Strict
            && build.is_some_and(|build| !build.split('.').all(is_identifier))
        {
            return None;
        }
        // No hyphen is a normal release; a trailing hyphen (`0.18.0-`) is
        // malformed, not a release, so the two must not collapse together.
        let (core, pre_release) = match versioned.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (versioned, None),
        };
        let core = parse_core(core, syntax)?;
        let pre_release = match pre_release {
            Some(pre) => pre
                .split('.')
                .map(|id| parse_pre_release_id(id, syntax))
                .collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        Some(Self { core, pre_release })
    }

    pub fn is_pre_release(&self) -> bool {
        !self.pre_release.is_empty()
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| {
            match (self.pre_release.is_empty(), other.pre_release.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // Lexicographic, so when every shared identifier is equal the
                // longer set wins: `rc.1.1` outranks `rc.1`.
                (false, false) => self.pre_release.cmp(&other.pre_release),
            }
        })
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_core(core: &str, syntax: VersionSyntax) -> Option<[u64; 3]> {
    let mut parts = core.split('.');
    let mut next = || parts.next().and_then(|part| parse_number(part, syntax));
    let parsed = [next()?, next()?, next()?];
    parts.next().is_none().then_some(parsed)
}

fn parse_pre_release_id(id: &str, syntax: VersionSyntax) -> Option<PreReleaseId> {
    // An empty identifier (`1.0.0-rc..1`) has no precedence against a real one
    // under either syntax.
    if id.is_empty() || (syntax == VersionSyntax::Strict && !is_identifier(id)) {
        return None;
    }
    if !id.bytes().all(|b| b.is_ascii_digit()) {
        return Some(PreReleaseId::Alphanumeric(id.to_string()));
    }
    match (parse_number(id, syntax), syntax) {
        (Some(number), _) => Some(PreReleaseId::Numeric(number)),
        // Too large for `u64`: leniently it still orders, as text.
        (None, VersionSyntax::Lenient) => Some(PreReleaseId::Alphanumeric(id.to_string())),
        (None, VersionSyntax::Strict) => None,
    }
}

/// Digits only. Strict syntax also refuses a leading zero on anything but
/// zero itself.
fn parse_number(value: &str, syntax: VersionSyntax) -> Option<u64> {
    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    let canonical = syntax == VersionSyntax::Lenient || value == "0" || !value.starts_with('0');
    if digits && canonical {
        value.parse().ok()
    } else {
        None
    }
}

fn is_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::{ReleaseVersion, VersionSyntax};

    fn v(raw: &str) -> ReleaseVersion {
        ReleaseVersion::parse(raw, VersionSyntax::Lenient)
            .unwrap_or_else(|| panic!("{raw} should parse"))
    }

    fn strict(raw: &str) -> Option<ReleaseVersion> {
        ReleaseVersion::parse(raw, VersionSyntax::Strict)
    }

    #[test]
    fn a_prerelease_ranks_below_the_release_it_precedes() {
        assert!(v("0.18.0-rc.1") < v("0.18.0"));
        assert!(v("0.18.0") > v("0.18.0-rc.1"));
        // ...and still above everything before it, which is the half a
        // suffix-dropping parse would get right by accident.
        assert!(v("0.18.0-rc.1") > v("0.17.0"));
        assert!(v("0.18.0-rc.1").is_pre_release());
        assert!(!v("0.18.0").is_pre_release());
    }

    #[test]
    fn prerelease_identifiers_compare_by_semver_rules() {
        // Numeric identifiers compare numerically, not as strings: the string
        // ordering would put rc.10 before rc.9.
        assert!(v("0.18.0-rc.2") < v("0.18.0-rc.10"));
        // Numeric identifiers rank below alphanumeric ones.
        assert!(v("0.18.0-1") < v("0.18.0-alpha"));
        // Alphanumeric identifiers compare in ASCII order.
        assert!(v("0.18.0-alpha") < v("0.18.0-beta"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.beta"));
        // A longer set wins when every shared identifier is equal.
        assert!(v("0.18.0-rc.1") < v("0.18.0-rc.1.1"));
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
    }

    #[test]
    fn the_release_triple_still_dominates_the_suffix() {
        assert!(
            v("0.9.0") < v("0.10.0"),
            "string ordering would invert this"
        );
        assert!(v("0.18.1-rc.1") > v("0.18.0"));
        assert_eq!(v("0.18.0"), v("0.18.0"));
    }

    #[test]
    fn lenient_parse_accepts_the_shapes_a_tag_actually_takes_and_rejects_the_rest() {
        assert_eq!(v("v0.18.0"), v("0.18.0"), "a leading v is the tag form");
        assert_eq!(v(" 0.18.0\n"), v("0.18.0"));
        // Build metadata is excluded from precedence by semver, so two
        // versions differing only there are the same release.
        assert_eq!(v("0.18.0+deadbeef"), v("0.18.0"));

        for bad in [
            "",
            "0.18",
            "0.18.0.1",
            "not-a-version",
            "0.x.0",
            "0.18.0-",
            "0.18.0-rc..1",
        ] {
            assert!(
                ReleaseVersion::parse(bad, VersionSyntax::Lenient).is_none(),
                "{bad:?} is not orderable and must not parse"
            );
        }
    }

    #[test]
    fn strict_parse_accepts_the_semver_grammar() {
        for value in [
            "0.1.0",
            "1.20.300",
            "1.0.0-rc.1",
            "1.0.0-alpha-2.x",
            "1.0.0-0",
            "1.0.0+build.7",
            "1.0.0-rc.1+001",
        ] {
            assert!(strict(value).is_some(), "{value:?} is valid semver");
        }
    }

    #[test]
    fn strict_parse_refuses_what_semver_refuses() {
        for value in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            " 1.2.3",
            "01.2.3",
            "1.02.3",
            "1.2.x",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3-rc_1",
            "1.2.3+",
            "1.2.3+a+b",
            "1.2.3-99999999999999999999",
        ] {
            assert!(strict(value).is_none(), "{value:?} must be refused");
        }
    }

    #[test]
    fn lenient_parse_orders_what_strict_parse_refuses() {
        assert_eq!(v("01.2.3"), v("1.2.3"));
        assert!(v("1.0.0-rc_1") > v("1.0.0-rc"));
        assert!(v("1.0.0-99999999999999999999") > v("1.0.0-1"));
    }

    #[test]
    fn build_metadata_does_not_affect_equality_or_precedence() {
        let a = strict("1.0.0+a").unwrap();
        let b = strict("1.0.0+b").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }
}
