//! `xtask check-image-lock`
//!
//! One published image tag used to be hand-copied into `mvm-core`'s config,
//! `mvm-build`'s Stage 0 pins, three workflows, a shell script and two
//! integration tests, and kept in step by eye. A copy left behind is not a type
//! error and fails no test: it is a 404 on a fresh install's first boot, or a
//! CI lane validating different bytes from the ones users receive.
//!
//! The pins live in `crates/mvm-core/images.lock` now, and this gate holds the files that
//! cannot call a Rust API to it. Two things fail:
//!
//!   - A boot-image tag written out as a literal that is not the locked one.
//!   - A boot-image tag written as a *pattern* that enumerates published
//!     releases — the mechanism by which a workflow picks "the newest one".
//!     That makes what mvm fetches a property of whoever published last rather
//!     than of this tree, and a pin that nobody reviewed is not a pin.
//!
//! Two spellings are deliberately not findings, because neither selects
//! anything: the `boot-image/v*` push-tag glob that fires the publishing
//! workflow, and the `boot-image/v.*` wildcard inside a keyless signing
//! identity, which constrains who may have signed rather than what to fetch.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

use mvm_core::image_set::ImageTrainLock;

/// The lock, relative to the workspace root.
const LOCK_FILE: &str = "crates/mvm-core/images.lock";

/// The reader every shell and YAML consumer goes through.
const READER: &str = "scripts/locked-image-tag.sh";

/// Trees whose files are expected to name a boot-image tag and have no way to
/// call the Rust API. Documentation and specs are excluded: prose about a
/// historical release is a record, not a pin.
const SCANNED_DIRS: [&str; 3] = [".github/workflows", "scripts", "tests"];

/// The prefix every boot-image tag starts with.
const TAG_PREFIX: &str = "boot-image/v";

/// How one `boot-image/v…` mention behaves.
#[derive(Debug, PartialEq, Eq)]
enum TagMention {
    /// A concrete tag. Must be the locked one.
    Pinned(String),
    /// `boot-image/v*` — the push-tag glob that fires the publishing workflow.
    TriggerGlob,
    /// `boot-image/v.*` — a wildcard inside a signing-identity regexp.
    IdentityRegexp,
    /// `boot-image/vN`, `boot-image/vX.Y.Z` — a placeholder in prose.
    ProsePlaceholder,
    /// `boot-image/v` with nothing after it — the prefix itself, as a test
    /// asserts a composed URL sits under it. Names no release.
    BarePrefix,
    /// `boot-image/v[0-9]+\.…` — a pattern matching every published release,
    /// which exists only to pick one of them.
    Enumeration,
}

/// One refusal, located precisely enough to fix without searching.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    detail: String,
}

impl Finding {
    fn render(&self) -> String {
        format!("  {}:{}: {}", self.file, self.line, self.detail)
    }
}

pub fn run(workspace: &Path) -> Result<()> {
    let lock_path = workspace.join(LOCK_FILE);
    let lock_text = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock = ImageTrainLock::parse(&lock_text)
        .with_context(|| format!("parsing {}", lock_path.display()))?;
    let locked = lock.boot_image.release_tag.as_str();

    let mut findings = Vec::new();
    for dir in SCANNED_DIRS {
        let root = workspace.join(dir);
        crate::fs_walk::walk_files(&root, &mut |path| {
            let Ok(text) = std::fs::read_to_string(path) else {
                // Binary fixtures live under these trees; a file that is not
                // UTF-8 names no tag.
                return;
            };
            let relative = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .display()
                .to_string();
            findings.extend(findings_in(&relative, &text, locked));
        })?;
    }

    if !findings.is_empty() {
        let rendered: Vec<String> = findings.iter().map(Finding::render).collect();
        bail!(
            "check-image-lock: {} boot-image pin(s) do not come from {LOCK_FILE} (locked tag: {locked}):\n{}\n\n\
             Read the pin instead of copying it: `$({READER})` from shell or YAML, \
             `cargo run -p xtask -- release-boot-image tag` where a toolchain is available, \
             or `mvm_core::config::default_boot_image_tag()` from Rust.",
            findings.len(),
            rendered.join("\n")
        );
    }

    check_reader_agrees(workspace, locked)?;

    eprintln!("check-image-lock: clean (boot image pinned to {locked} by {LOCK_FILE})");
    Ok(())
}

/// The shell reader is the only path to the lock for jobs with no Rust
/// toolchain, so a reader that stopped parsing the file would hand every one of
/// them an empty tag — or, worse, a stale one — with nothing else noticing.
fn check_reader_agrees(workspace: &Path, locked: &str) -> Result<()> {
    let reader = workspace.join(READER);
    let output = Command::new(&reader)
        .output()
        .with_context(|| format!("running {}", reader.display()))?;
    if !output.status.success() {
        bail!(
            "check-image-lock: {READER} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if printed != locked {
        bail!(
            "check-image-lock: {READER} prints {printed:?} but {LOCK_FILE} pins {locked:?}; \
             every workflow that cannot call Rust reads the lock through that script, so the \
             two must agree"
        );
    }
    Ok(())
}

/// Every refusal one file's text earns.
fn findings_in(file: &str, text: &str, locked: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for mention in mentions_in(line) {
            let detail = match mention {
                TagMention::Pinned(tag) if tag == locked => continue,
                TagMention::Pinned(tag) => {
                    format!("pins boot image {tag:?}, but {LOCK_FILE} pins {locked:?}")
                }
                TagMention::Enumeration => format!(
                    "matches every published {TAG_PREFIX}* release by pattern, which selects \
                     an image by whoever published last instead of by the locked pin"
                ),
                TagMention::TriggerGlob
                | TagMention::IdentityRegexp
                | TagMention::ProsePlaceholder
                | TagMention::BarePrefix => continue,
            };
            findings.push(Finding {
                file: file.to_string(),
                line: index + 1,
                detail,
            });
        }
    }
    findings
}

/// Classify every `boot-image/v…` on one line.
fn mentions_in(line: &str) -> Vec<TagMention> {
    let mut mentions = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(TAG_PREFIX) {
        let after = &rest[at + TAG_PREFIX.len()..];
        mentions.push(classify(after));
        rest = after;
    }
    mentions
}

/// Classify by what follows `boot-image/v`, which is total over the alphabet:
/// a digit starts a version, `*` is the push-tag glob, `.` starts a regexp
/// wildcard, an uppercase letter is a prose placeholder, the end of the token
/// leaves the bare prefix, and everything else is a regexp metacharacter, which
/// can only be there to match more than one tag.
fn classify(after_prefix: &str) -> TagMention {
    match after_prefix.chars().next() {
        Some(c) if c.is_ascii_digit() => TagMention::Pinned(format!(
            "{TAG_PREFIX}{}",
            after_prefix
                .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .next()
                .unwrap_or_default()
                .trim_end_matches('.')
        )),
        Some('*') => TagMention::TriggerGlob,
        Some('.') => TagMention::IdentityRegexp,
        Some(c) if c.is_ascii_uppercase() => TagMention::ProsePlaceholder,
        None => TagMention::BarePrefix,
        Some(c) if c.is_whitespace() || matches!(c, '"' | '\'' | '`') => TagMention::BarePrefix,
        _ => TagMention::Enumeration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKED: &str = "boot-image/v0.1.5";

    #[test]
    fn a_tree_that_names_only_the_locked_tag_passes() {
        let text = "IMAGE_TAG: boot-image/v0.1.5\n\
                    release boot-image/v0.1.5 2026-09-08T00:00:00Z\n";
        assert_eq!(findings_in("ci.yml", text, LOCKED), Vec::new());
    }

    #[test]
    fn a_drifted_tag_fails_and_names_the_file_and_line() {
        let text = "env:\n  IMAGE_TAG: boot-image/v0.1.4\n";
        let findings = findings_in(".github/workflows/ci.yml", text, LOCKED);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, ".github/workflows/ci.yml");
        assert_eq!(findings[0].line, 2);
        assert!(
            findings[0].detail.contains("boot-image/v0.1.4") && findings[0].detail.contains(LOCKED),
            "the refusal must name both tags: {}",
            findings[0].detail
        );
    }

    #[test]
    fn a_latest_selection_by_tag_enumeration_fails_and_names_the_file() {
        let text = "  TAG=$(gh release list --json tagName --jq '\n\
                    \x20   [ .[].tagName | select(test(\"^boot-image/v[0-9]+\\\\.[0-9]+\\\\.[0-9]+$\"))\n";
        let findings = findings_in("scripts/download-qemu-wasm-smoke-pack.sh", text, LOCKED);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, "scripts/download-qemu-wasm-smoke-pack.sh");
        assert_eq!(findings[0].line, 2);
        assert!(
            findings[0].detail.contains("published last"),
            "the refusal must say why enumeration is the problem: {}",
            findings[0].detail
        );
    }

    /// The glob that fires `release-boot-image.yml` selects nothing — it
    /// decides which pushed tag publishes a release.
    #[test]
    fn a_push_tag_glob_is_not_a_finding() {
        let text = "    tags:\n      - 'boot-image/v*'\n";
        assert_eq!(findings_in(".github/workflows/x.yml", text, LOCKED), vec![]);
    }

    /// A signing identity constrains who may have signed, not what to fetch.
    #[test]
    fn a_signing_identity_regexp_is_not_a_finding() {
        let text = "COSIGN_IDENTITY_REGEXP: \"^https://github.com/o/r/.github/workflows/\
                    release-boot-image.yml@refs/tags/boot-image/v.*$\"\n";
        assert_eq!(findings_in(".github/workflows/x.yml", text, LOCKED), vec![]);
    }

    #[test]
    fn a_prose_placeholder_is_not_a_finding() {
        let text = "/// images ship on their own boot-image/vN counter\n\
                    # gh release download boot-image/vX.Y.Z --pattern '*'\n";
        assert_eq!(findings_in("tests/release_assets.rs", text, LOCKED), vec![]);
    }

    /// A test that a composed URL sits under the tag prefix names no release.
    #[test]
    fn the_bare_prefix_is_not_a_finding() {
        let text = "url.contains(\"/releases/download/boot-image/v\")\n\
                    the prefix is boot-image/v\n";
        assert_eq!(findings_in("tests/release_assets.rs", text, LOCKED), vec![]);
    }

    #[test]
    fn two_tags_on_one_line_are_classified_independently() {
        let text = "assert boot-image/v0.1.5 != boot-image/v9.9.9\n";
        let findings = findings_in("tests/x.rs", text, LOCKED);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("boot-image/v9.9.9"));
    }

    #[test]
    fn a_version_is_read_up_to_the_first_non_version_character() {
        assert_eq!(
            classify("0.1.5/builder-vm-vmlinux-x86_64"),
            TagMention::Pinned("boot-image/v0.1.5".to_string())
        );
        assert_eq!(
            classify("0.1.5\""),
            TagMention::Pinned("boot-image/v0.1.5".to_string())
        );
    }

    #[test]
    fn every_regexp_metacharacter_after_the_prefix_is_an_enumeration() {
        for after in ["[0-9]+", "\\\\d+", "(0|1)", "?"] {
            assert_eq!(
                classify(after),
                TagMention::Enumeration,
                "{after:?} matches more than one release"
            );
        }
    }

    /// The shipped tree is the gate's real subject; a green unit suite over
    /// fixtures says nothing about it.
    #[test]
    fn the_shipped_tree_is_clean() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits under the workspace root")
            .to_path_buf();
        run(&workspace).expect("the checked-in tree must satisfy the gate");
    }
}
