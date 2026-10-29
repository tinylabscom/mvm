//! PEP 440 versions and specifiers, as far as checking an interpreter against
//! `requires-python` and environment markers needs them.
//!
//! Candidates here are always final CPython releases, so the pre-release
//! admission rules that matter when choosing among published versions do not
//! arise; ordering, wildcards, compatible-release and the exclusive-comparison
//! rules do.

use std::cmp::Ordering;
use std::fmt;

/// A parsed PEP 440 version. Equality follows the specification, so `3.12`
/// and `3.12.0` are equal.
#[derive(Debug, Clone)]
pub(crate) struct Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Vec<LocalSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    Alpha,
    Beta,
    Candidate,
}

/// Local segments compare alphanumeric-before-numeric, hence the variant
/// order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSegment {
    Alpha(String),
    Number(u64),
}

/// A bound used to place absent components in the ordering key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key<T> {
    Low,
    Value(T),
    High,
}

impl Version {
    /// Parse a version in normalized or common alternative spellings
    /// (`v` prefix, `alpha`/`beta`/`c`/`pre`/`preview`, `rev`/`r`, implicit
    /// numbers, `-`/`_`/`.` separators). Anything else is `None`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let lowered = text.trim().to_ascii_lowercase();
        let unprefixed = lowered.strip_prefix('v').unwrap_or(&lowered);
        let (public, local) = match unprefixed.split_once('+') {
            Some((public, local)) => (public, parse_local(local)?),
            None => (unprefixed, Vec::new()),
        };
        let (epoch, rest) = match public.split_once('!') {
            Some((epoch, rest)) => (parse_number(epoch)?, rest),
            None => (0, public),
        };
        let mut cursor = Cursor { rest };
        let release = cursor.release()?;
        let pre = cursor.pre()?;
        let post = cursor.post()?;
        let dev = cursor.dev()?;
        if !cursor.rest.is_empty() {
            return None;
        }
        Some(Self {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    /// A final release `3.minor.patch`.
    pub(crate) fn python(minor: u32, patch: u64) -> Self {
        Self {
            epoch: 0,
            release: vec![3, u64::from(minor), patch],
            pre: None,
            post: None,
            dev: None,
            local: Vec::new(),
        }
    }

    fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    fn without_local(&self) -> Self {
        Self {
            local: Vec::new(),
            ..self.clone()
        }
    }

    /// Epoch and release with trailing zeros dropped: the part two versions
    /// must share to be "the same release" under the exclusive comparisons.
    fn base(&self) -> (u64, &[u64]) {
        (self.epoch, trimmed(&self.release))
    }

    fn key(&self) -> VersionKey<'_> {
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => Key::Low,
            (None, _, _) => Key::High,
            (Some(pre), _, _) => Key::Value(pre),
        };
        let local = if self.local.is_empty() {
            Key::Low
        } else {
            Key::Value(self.local.as_slice())
        };
        (
            self.epoch,
            trimmed(&self.release),
            pre,
            self.post.map_or(Key::Low, Key::Value),
            self.dev.map_or(Key::High, Key::Value),
            local,
        )
    }
}

type VersionKey<'a> = (
    u64,
    &'a [u64],
    Key<(PreKind, u64)>,
    Key<u64>,
    Key<u64>,
    Key<&'a [LocalSegment]>,
);

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}!", self.epoch)?;
        }
        let release: Vec<String> = self.release.iter().map(u64::to_string).collect();
        f.write_str(&release.join("."))?;
        if let Some((kind, number)) = self.pre {
            let tag = match kind {
                PreKind::Alpha => "a",
                PreKind::Beta => "b",
                PreKind::Candidate => "rc",
            };
            write!(f, "{tag}{number}")?;
        }
        if let Some(post) = self.post {
            write!(f, ".post{post}")?;
        }
        if let Some(dev) = self.dev {
            write!(f, ".dev{dev}")?;
        }
        if !self.local.is_empty() {
            let local: Vec<String> = self
                .local
                .iter()
                .map(|segment| match segment {
                    LocalSegment::Alpha(text) => text.clone(),
                    LocalSegment::Number(number) => number.to_string(),
                })
                .collect();
            write!(f, "+{}", local.join("."))?;
        }
        Ok(())
    }
}

fn trimmed(release: &[u64]) -> &[u64] {
    let len = release
        .iter()
        .rposition(|&part| part != 0)
        .map_or(0, |last| last + 1);
    &release[..len]
}

fn parse_number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_local(text: &str) -> Option<Vec<LocalSegment>> {
    text.split(['.', '-', '_'])
        .map(|segment| {
            if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_alphanumeric()) {
                None
            } else if let Some(number) = parse_number(segment) {
                Some(LocalSegment::Number(number))
            } else {
                Some(LocalSegment::Alpha(segment.to_string()))
            }
        })
        .collect()
}

/// A left-to-right reader over the public part of a version string.
struct Cursor<'a> {
    rest: &'a str,
}

impl Cursor<'_> {
    fn digits(&mut self) -> Option<u64> {
        let end = self
            .rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(self.rest.len());
        if end == 0 {
            return None;
        }
        let number = self.rest[..end].parse().ok()?;
        self.rest = &self.rest[end..];
        Some(number)
    }

    fn release(&mut self) -> Option<Vec<u64>> {
        let mut release = vec![self.digits()?];
        while let Some(after) = self.rest.strip_prefix('.') {
            if !after.starts_with(|c: char| c.is_ascii_digit()) {
                break;
            }
            self.rest = after;
            release.push(self.digits()?);
        }
        Some(release)
    }

    /// Consume an optional separator followed by one of `words`, returning
    /// the word's index. The separator is consumed only with the word.
    fn word(&mut self, words: &[&str]) -> Option<usize> {
        let unseparated = self.rest.trim_start_matches(['.', '-', '_']);
        if self.rest.len() - unseparated.len() > 1 {
            return None;
        }
        let (index, word) = words
            .iter()
            .enumerate()
            .filter(|(_, word)| unseparated.starts_with(**word))
            .max_by_key(|(_, word)| word.len())?;
        self.rest = &unseparated[word.len()..];
        Some(index)
    }

    /// The number after a pre, post or dev word, with an optional separator;
    /// an absent number is zero.
    fn implicit_number(&mut self) -> Option<u64> {
        let unseparated = self.rest.strip_prefix(['.', '-', '_']).unwrap_or(self.rest);
        if unseparated.starts_with(|c: char| c.is_ascii_digit()) {
            self.rest = unseparated;
            return self.digits();
        }
        Some(0)
    }

    fn pre(&mut self) -> Option<Option<(PreKind, u64)>> {
        const WORDS: [&str; 7] = ["a", "alpha", "b", "beta", "rc", "c", "pre"];
        const KINDS: [PreKind; 7] = [
            PreKind::Alpha,
            PreKind::Alpha,
            PreKind::Beta,
            PreKind::Beta,
            PreKind::Candidate,
            PreKind::Candidate,
            PreKind::Candidate,
        ];
        let Some(index) = self.word(&WORDS) else {
            return Some(None);
        };
        // `preview` is a spelling of `rc`; `pre` already matched its prefix.
        if index == 6 {
            self.rest = self.rest.strip_prefix("view").unwrap_or(self.rest);
        }
        Some(Some((KINDS[index], self.implicit_number()?)))
    }

    fn post(&mut self) -> Option<Option<u64>> {
        if let Some(after) = self.rest.strip_prefix('-')
            && after.starts_with(|c: char| c.is_ascii_digit())
        {
            self.rest = after;
            return Some(Some(self.digits()?));
        }
        if self.word(&["post", "rev", "r"]).is_none() {
            return Some(None);
        }
        Some(Some(self.implicit_number()?))
    }

    fn dev(&mut self) -> Option<Option<u64>> {
        if self.word(&["dev"]).is_none() {
            return Some(None);
        }
        Some(Some(self.implicit_number()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Compatible,
    Arbitrary,
}

impl Operator {
    /// Longest spellings first, so `===` is not read as `==`.
    pub(crate) const SPELLINGS: [(&'static str, Self); 8] = [
        ("===", Self::Arbitrary),
        ("==", Self::Equal),
        ("!=", Self::NotEqual),
        ("<=", Self::LessEqual),
        (">=", Self::GreaterEqual),
        ("~=", Self::Compatible),
        ("<", Self::Less),
        (">", Self::Greater),
    ];

    pub(crate) fn split(text: &str) -> Option<(Self, &str)> {
        Self::SPELLINGS
            .iter()
            .find_map(|(spelling, op)| text.strip_prefix(spelling).map(|rest| (*op, rest)))
    }
}

/// One PEP 440 version clause, such as `>=3.10` or `==3.12.*`.
#[derive(Debug, Clone)]
pub(crate) struct Specifier {
    operator: Operator,
    target: Target,
}

#[derive(Debug, Clone)]
enum Target {
    Version(Version),
    /// `==V.*` / `!=V.*`: the release prefix of `V`.
    Prefix(Version),
    /// `===`: an arbitrary string, compared case-insensitively.
    Text(String),
}

impl Specifier {
    /// Parse `<op><version>` with optional whitespace between them.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (operator, rest) = Operator::split(text.trim())?;
        Self::new(operator, rest.trim())
    }

    /// The clause `operator version`, refused where PEP 440 forbids the
    /// combination (a wildcard outside `==`/`!=`, a local label on an ordered
    /// comparison, a one-segment compatible release).
    pub(crate) fn new(operator: Operator, version: &str) -> Option<Self> {
        if operator == Operator::Arbitrary {
            return (!version.is_empty() && !version.contains(char::is_whitespace)).then(|| Self {
                operator,
                target: Target::Text(version.to_string()),
            });
        }
        if let Some(prefix) = version.strip_suffix(".*") {
            if !matches!(operator, Operator::Equal | Operator::NotEqual) {
                return None;
            }
            let parsed = Version::parse(prefix)?;
            if parsed.pre.is_some()
                || parsed.post.is_some()
                || parsed.dev.is_some()
                || !parsed.local.is_empty()
            {
                return None;
            }
            return Some(Self {
                operator,
                target: Target::Prefix(parsed),
            });
        }
        let parsed = Version::parse(version)?;
        let local_allowed = matches!(operator, Operator::Equal | Operator::NotEqual);
        if !parsed.local.is_empty() && !local_allowed {
            return None;
        }
        if operator == Operator::Compatible && parsed.release.len() < 2 {
            return None;
        }
        Some(Self {
            operator,
            target: Target::Version(parsed),
        })
    }

    pub(crate) fn contains(&self, candidate: &Version) -> bool {
        match (&self.target, self.operator) {
            (Target::Text(text), _) => candidate.to_string().eq_ignore_ascii_case(text),
            (Target::Prefix(prefix), Operator::Equal) => prefix_matches(prefix, candidate),
            (Target::Prefix(prefix), _) => !prefix_matches(prefix, candidate),
            (Target::Version(version), operator) => ordered(operator, version, candidate),
        }
    }
}

fn prefix_matches(prefix: &Version, candidate: &Version) -> bool {
    if prefix.epoch != candidate.epoch {
        return false;
    }
    let mut release = candidate.release.clone();
    if release.len() < prefix.release.len() {
        release.resize(prefix.release.len(), 0);
    }
    release[..prefix.release.len()] == prefix.release[..]
}

fn ordered(operator: Operator, spec: &Version, candidate: &Version) -> bool {
    let public = candidate.without_local();
    match operator {
        Operator::Equal if spec.local.is_empty() => public == *spec,
        Operator::Equal => candidate == spec,
        Operator::NotEqual => !ordered(Operator::Equal, spec, candidate),
        Operator::LessEqual => public <= *spec,
        Operator::GreaterEqual => public >= *spec,
        Operator::Less => {
            public < *spec
                && !(candidate.is_prerelease()
                    && !spec.is_prerelease()
                    && candidate.base() == spec.base())
        }
        Operator::Greater => {
            public > *spec
                && !(candidate.post.is_some()
                    && spec.post.is_none()
                    && candidate.base() == spec.base())
                && !(!candidate.local.is_empty() && public == *spec)
        }
        Operator::Compatible => {
            let prefix = Version {
                release: spec.release[..spec.release.len() - 1].to_vec(),
                pre: None,
                post: None,
                dev: None,
                local: Vec::new(),
                ..spec.clone()
            };
            public >= *spec && prefix_matches(&prefix, candidate)
        }
        Operator::Arbitrary => false,
    }
}

/// A comma-separated conjunction of specifiers. An empty set admits every
/// version.
#[derive(Debug, Clone)]
pub(crate) struct SpecifierSet(Vec<Specifier>);

impl SpecifierSet {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if text.trim().is_empty() {
            return Some(Self(Vec::new()));
        }
        text.split(',')
            .map(Specifier::parse)
            .collect::<Option<_>>()
            .map(Self)
    }

    pub(crate) fn contains(&self, candidate: &Version) -> bool {
        self.0.iter().all(|specifier| specifier.contains(candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} parses"))
    }

    fn admits(spec: &str, candidate: &str) -> bool {
        SpecifierSet::parse(spec)
            .unwrap_or_else(|| panic!("{spec} parses"))
            .contains(&v(candidate))
    }

    #[test]
    fn versions_order_as_pep_440_requires() {
        let ordered = [
            "1.0.dev0",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a2",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0+local",
            "1.0.post1.dev0",
            "1.0.post1",
            "1.1",
            "1!0.1",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn trailing_zeros_and_alternative_spellings_are_equal() {
        assert_eq!(v("3.12"), v("3.12.0"));
        assert_eq!(v("1.0alpha1"), v("1.0a1"));
        assert_eq!(v("1.0-beta.2"), v("1.0b2"));
        assert_eq!(v("1.0c1"), v("1.0rc1"));
        assert_eq!(v("1.0preview1"), v("1.0rc1"));
        assert_eq!(v("1.0-1"), v("1.0.post1"));
        assert_eq!(v("1.0rev"), v("1.0.post0"));
        assert_eq!(v("v2.0"), v("2.0"));
        assert_eq!(v("1.0.DEV"), v("1.0.dev0"));
    }

    #[test]
    fn malformed_versions_are_refused() {
        for text in ["", "a", "1..0", "1.0x", "1.0+", "1.0+a..b", "1!", "3.*"] {
            assert!(Version::parse(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn every_operator_compares() {
        assert!(admits("==3.12", "3.12.0"));
        assert!(!admits("==3.12", "3.12.1"));
        assert!(admits("!=3.11", "3.12.0"));
        assert!(admits("<3.13", "3.12.9"));
        assert!(!admits("<3.12", "3.12.0"));
        assert!(admits("<=3.12", "3.12.0"));
        assert!(admits(">3.11", "3.12.0"));
        assert!(!admits(">3.12", "3.12.0"));
        assert!(admits(">=3.12", "3.12.0"));
        assert!(admits("~=3.10", "3.12.0"));
        assert!(!admits("~=3.10", "4.0"));
        assert!(admits("~=3.12.1", "3.12.5"));
        assert!(!admits("~=3.12.1", "3.13.0"));
        assert!(!admits("~=3.12.1", "3.12.0"));
        assert!(admits("===3.12.0", "3.12.0"));
        assert!(!admits("===3.12", "3.12.0"));
    }

    #[test]
    fn wildcards_match_release_prefixes() {
        assert!(admits("==3.12.*", "3.12.7"));
        assert!(admits("==3.*", "3.12.0"));
        assert!(!admits("==3.11.*", "3.12.0"));
        assert!(admits("!=3.11.*", "3.12.0"));
        assert!(!admits("!=3.12.*", "3.12.0"));
        assert!(admits("==3.12.0.*", "3.12"));
    }

    #[test]
    fn exclusive_comparisons_exclude_their_own_pre_and_post_releases() {
        assert!(!admits("<3.12", "3.12.0rc1"));
        assert!(admits("<3.12rc2", "3.12.0rc1"));
        assert!(!admits(">3.12", "3.12.post1"));
        assert!(admits(">3.12.post0", "3.12.post1"));
        assert!(!admits(">3.12", "3.12+local"));
    }

    #[test]
    fn sets_are_conjunctions() {
        assert!(admits(">=3.10, <4", "3.12.0"));
        assert!(!admits(">=3.10,<3.12", "3.12.0"));
        assert!(admits("", "3.12.0"));
    }

    #[test]
    fn forbidden_specifier_shapes_are_refused() {
        for text in [
            ">=3.*",
            "~=3",
            "<1.0+local",
            "==3.12a1.*",
            "3.12",
            "=>3",
            "=== ",
        ] {
            assert!(Specifier::parse(text).is_none(), "{text:?}");
        }
    }
}
