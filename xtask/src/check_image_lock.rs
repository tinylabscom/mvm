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
//!   - An image-set tag written out as a literal that is not the locked one.
//!   - An image-set tag written as a *pattern* that enumerates published
//!     releases — the mechanism by which a workflow picks "the newest one".
//!     That makes what mvm fetches a property of whoever published last rather
//!     than of this tree, and a pin that nobody reviewed is not a pin.
//!
//! Two spellings are deliberately not findings, because neither selects
//! anything: the `image-set/v*` push-tag glob that fires the publishing
//! workflow, and the `image-set/v.*` wildcard inside a keyless signing
//! identity, which constrains who may have signed rather than what to fetch.
//!
//! The same reasoning covers source checkouts of the image repository. A
//! workflow that checks it out to build from it must take the ref from `xtask
//! image-source-ref`, the commit that produced the locked set. A checkout of
//! `main`, or of no ref at all, is a finding: v0.18.0's release failed after
//! it was tagged because the image repository's `main` gained a manifest field
//! this tree did not parse yet. A workflow whose purpose is to test the two
//! `main`s together is listed as a canary, and must not be reachable from a
//! pull request, the merge queue, a push or another workflow — so it can go
//! red without blocking anything.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

use mvm_core::image_set::ImageTrainLock;

/// The lock, relative to the workspace root.
const LOCK_FILE: &str = "crates/mvm-core/images.lock";

/// The reader every shell and YAML consumer goes through.
const READER: &str = "scripts/locked-image-tag.sh";
const PIN_UPDATER: &str = ".github/workflows/update-image-pin.yml";

/// Trees whose files are expected to name an image-set tag and have no way to
/// call the Rust API. Documentation and specs are excluded: prose about a
/// historical release is a record, not a pin.
const SCANNED_DIRS: [&str; 3] = [".github/workflows", "scripts", "tests"];

/// The prefix every image-set tag starts with.
const TAG_PREFIX: &str = "image-set/v";

/// Where a source checkout of the image repository can be declared.
const WORKFLOW_DIR: &str = ".github/workflows";

/// The command whose output every source checkout of the image repository
/// must take its ref from.
const SOURCE_REF_RESOLVER: &str = "xtask -- image-source-ref";

/// Workflows that check the image repository out at its `main` on purpose:
/// they exist to find out, before a pin advances, whether the two `main`s
/// still work together. Each must stay off every gating path.
const CANARY_WORKFLOWS: [&str; 1] = [".github/workflows/image-pair.yml"];

/// Triggers that make a workflow's result block a merge or a release.
const GATING_TRIGGERS: [&str; 5] = [
    "pull_request",
    "pull_request_target",
    "merge_group",
    "push",
    "workflow_call",
];

/// How one `image-set/v…` mention behaves.
#[derive(Debug, PartialEq, Eq)]
enum TagMention {
    /// A concrete tag. Must be the locked one.
    Pinned(String),
    /// `image-set/v*` — the push-tag glob that fires the publishing workflow.
    TriggerGlob,
    /// `image-set/v.*` — a wildcard inside a signing-identity regexp.
    IdentityRegexp,
    /// `image-set/vN`, `image-set/vX.Y.Z` — a placeholder in prose.
    ProsePlaceholder,
    /// `image-set/v` with nothing after it — the prefix itself, as a test
    /// asserts a composed URL sits under it. Names no release.
    BarePrefix,
    /// `image-set/v[0-9]+\.…` — a pattern matching every published release,
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
    let locked = lock.image_set.release_tag.as_str();

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
            if relative == PIN_UPDATER {
                return;
            }
            findings.extend(findings_in(&relative, &text, locked));
        })?;
    }
    let images_repository = lock.image_set.repository.as_str();
    crate::fs_walk::walk_files(&workspace.join(WORKFLOW_DIR), &mut |path| {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let relative = path
            .strip_prefix(workspace)
            .unwrap_or(path)
            .display()
            .to_string();
        findings.extend(checkout_findings(&relative, &text, images_repository));
    })?;

    if !findings.is_empty() {
        let rendered: Vec<String> = findings.iter().map(Finding::render).collect();
        bail!(
            "check-image-lock: {} image pin(s) do not come from {LOCK_FILE} (locked tag: {locked}):\n{}\n\n\
             Read the pin instead of copying it: `$({READER})` from shell or YAML, \
             `cargo run -p xtask -- release-boot-image tag` where a toolchain is available, \
             or `mvm_core::config::default_boot_image_tag()` from Rust. Check the image \
             repository out at `ref: ${{{{ steps.<id>.outputs.ref }}}}`, where step <id> \
             writes `ref=$(cargo run -q -p xtask -- image-source-ref)` to $GITHUB_OUTPUT.",
            findings.len(),
            rendered.join("\n")
        );
    }

    check_reader_agrees(workspace, locked)?;

    eprintln!("check-image-lock: clean (image set pinned to {locked} by {LOCK_FILE})");
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
                    format!("pins image set {tag:?}, but {LOCK_FILE} pins {locked:?}")
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

/// Every source checkout of `images_repository` in one workflow that does not
/// take its ref from the lock, and every gating trigger on a canary.
fn checkout_findings(file: &str, text: &str, images_repository: &str) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().collect();
    let finding = |line: usize, detail: String| Finding {
        file: file.to_string(),
        line: line + 1,
        detail,
    };
    if CANARY_WORKFLOWS.contains(&file) {
        return triggers(&lines)
            .into_iter()
            .filter(|(_, trigger)| GATING_TRIGGERS.contains(&trigger.as_str()))
            .map(|(line, trigger)| {
                finding(
                    line,
                    format!(
                        "is a canary that checks out {images_repository} at a ref the lock does \
                         not pin, so it must not run on `{trigger}`: a canary on a gating path \
                         lets the other repository's `main` block this one"
                    ),
                )
            })
            .collect();
    }

    let mut findings = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if yaml_value(line, "repository") != Some(images_repository) {
            continue;
        }
        let step = &lines[step_bounds(&lines, index)];
        let Some(reference) = step.iter().find_map(|l| yaml_value(l, "ref")) else {
            findings.push(finding(
                index,
                format!(
                    "checks out {images_repository} with no ref, which is its default branch; \
                     take the ref from `{SOURCE_REF_RESOLVER}`"
                ),
            ));
            continue;
        };
        let Some(id) = resolver_step_id(reference) else {
            findings.push(finding(
                index,
                format!(
                    "checks out {images_repository} at {reference:?}, which {LOCK_FILE} does not \
                     pin; take the ref from `{SOURCE_REF_RESOLVER}`"
                ),
            ));
            continue;
        };
        if !step_runs_resolver(&lines, id) {
            findings.push(finding(
                index,
                format!(
                    "checks out {images_repository} at the output of step {id:?}, which does not \
                     run `{SOURCE_REF_RESOLVER}`"
                ),
            ));
        }
    }
    findings
}

/// The value of a `key: value` line, unquoted, or `None` when the line assigns
/// another key. A list item's leading `- ` is part of the indentation.
fn yaml_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start().trim_start_matches("- ").trim_start();
    let value = trimmed.strip_prefix(key)?.strip_prefix(':')?.trim();
    Some(value.trim_matches(|c| c == '"' || c == '\''))
}

/// `step-id` from `${{ steps.step-id.outputs.ref }}`, the only ref spelling a
/// resolver step can feed.
fn resolver_step_id(reference: &str) -> Option<&str> {
    let inner = reference
        .strip_prefix("${{")?
        .strip_suffix("}}")?
        .trim()
        .strip_prefix("steps.")?
        .strip_suffix(".outputs.ref")?;
    (!inner.is_empty() && !inner.contains(char::is_whitespace)).then_some(inner)
}

/// Whether the step declaring `id: <id>` runs the resolver.
fn step_runs_resolver(lines: &[&str], id: &str) -> bool {
    lines.iter().enumerate().any(|(index, line)| {
        yaml_value(line, "id") == Some(id)
            && lines[step_bounds(lines, index)]
                .iter()
                .any(|l| l.contains(SOURCE_REF_RESOLVER))
    })
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The lines of the list item — the workflow step — that contains `index`:
/// from its `- ` to the next line at or left of that dash.
fn step_bounds(lines: &[&str], index: usize) -> std::ops::Range<usize> {
    let key_indent = indentation(lines[index]);
    let is_item = |i: usize| lines[i].trim_start().starts_with("- ");
    let start = (0..=index)
        .rev()
        .find(|&i| is_item(i) && (i == index || indentation(lines[i]) < key_indent))
        .unwrap_or(index);
    let dash = indentation(lines[start]);
    let end = (start + 1..lines.len())
        .find(|&i| {
            let trimmed = lines[i].trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#') && indentation(lines[i]) <= dash
        })
        .unwrap_or(lines.len());
    start..end
}

/// A workflow's triggers, each with the line it is declared on. Covers the
/// block form (`on:` then one key per line) and the inline forms
/// (`on: push`, `on: [push, pull_request]`).
fn triggers(lines: &[&str]) -> Vec<(usize, String)> {
    let Some(on) = lines
        .iter()
        .position(|line| line.starts_with("on:") || line.starts_with("\"on\":"))
    else {
        return Vec::new();
    };
    let inline = lines[on]
        .split_once(':')
        .map_or("", |(_, rest)| rest)
        .trim();
    if !inline.is_empty() {
        return inline
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|trigger| (on, trigger.trim().to_string()))
            .filter(|(_, trigger)| !trigger.is_empty())
            .collect();
    }
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(on + 1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indentation(line) == 0 {
            break;
        }
        if indentation(line) == 2
            && let Some((key, _)) = trimmed.split_once(':')
        {
            found.push((index, key.trim().to_string()));
        }
    }
    found
}

/// Classify every `image-set/v…` on one line.
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

/// Classify by what follows `image-set/v`, which is total over the alphabet:
/// a digit starts a version, `*` is the push-tag glob, `.` starts a regexp
/// wildcard, a letter means the path names an artifact such as
/// `image-set/vmlinux`, the end of the token leaves the bare prefix, and
/// everything else is a regexp metacharacter, which can only be there to match
/// more than one tag.
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
        Some(c) if c.is_ascii_alphabetic() => TagMention::ProsePlaceholder,
        None => TagMention::BarePrefix,
        Some(c) if c.is_whitespace() || matches!(c, '"' | '\'' | '`') => TagMention::BarePrefix,
        _ => TagMention::Enumeration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKED: &str = "image-set/v0.1.0";

    #[test]
    fn a_tree_that_names_only_the_locked_tag_passes() {
        let text = "IMAGE_TAG: image-set/v0.1.0\n\
                    release image-set/v0.1.0 2026-09-08T00:00:00Z\n";
        assert_eq!(findings_in("ci.yml", text, LOCKED), Vec::new());
    }

    #[test]
    fn a_drifted_tag_fails_and_names_the_file_and_line() {
        let text = "env:\n  IMAGE_TAG: image-set/v0.0.9\n";
        let findings = findings_in(".github/workflows/ci.yml", text, LOCKED);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, ".github/workflows/ci.yml");
        assert_eq!(findings[0].line, 2);
        assert!(
            findings[0].detail.contains("image-set/v0.0.9") && findings[0].detail.contains(LOCKED),
            "the refusal must name both tags: {}",
            findings[0].detail
        );
    }

    #[test]
    fn a_latest_selection_by_tag_enumeration_fails_and_names_the_file() {
        let text = "  TAG=$(gh release list --json tagName --jq '\n\
                    \x20   [ .[].tagName | select(test(\"^image-set/v[0-9]+\\\\.[0-9]+\\\\.[0-9]+$\"))\n";
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

    /// The glob that fires the image publisher selects nothing — it
    /// decides which pushed tag publishes a release.
    #[test]
    fn a_push_tag_glob_is_not_a_finding() {
        let text = "    tags:\n      - 'image-set/v*'\n";
        assert_eq!(findings_in(".github/workflows/x.yml", text, LOCKED), vec![]);
    }

    /// A signing identity constrains who may have signed, not what to fetch.
    #[test]
    fn a_signing_identity_regexp_is_not_a_finding() {
        let text = "COSIGN_IDENTITY_REGEXP: \"^https://github.com/o/r/.github/workflows/\
                    release.yml@refs/tags/image-set/v.*$\"\n";
        assert_eq!(findings_in(".github/workflows/x.yml", text, LOCKED), vec![]);
    }

    #[test]
    fn a_prose_placeholder_is_not_a_finding() {
        let text = "/// images ship on their own image-set/vN counter\n\
                    # gh release download image-set/vX.Y.Z --pattern '*'\n\
                    cp image-set/vmlinux cache/kernel\n";
        assert_eq!(findings_in("tests/release_assets.rs", text, LOCKED), vec![]);
    }

    /// A test that a composed URL sits under the tag prefix names no release.
    #[test]
    fn the_bare_prefix_is_not_a_finding() {
        let text = "url.contains(\"/releases/download/image-set/v\")\n\
                    the prefix is image-set/v\n";
        assert_eq!(findings_in("tests/release_assets.rs", text, LOCKED), vec![]);
    }

    #[test]
    fn two_tags_on_one_line_are_classified_independently() {
        let text = "assert image-set/v0.1.0 != image-set/v9.9.9\n";
        let findings = findings_in("tests/x.rs", text, LOCKED);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("image-set/v9.9.9"));
    }

    #[test]
    fn a_version_is_read_up_to_the_first_non_version_character() {
        assert_eq!(
            classify("0.1.5/builder-vm-vmlinux-x86_64"),
            TagMention::Pinned("image-set/v0.1.5".to_string())
        );
        assert_eq!(
            classify("0.1.5\""),
            TagMention::Pinned("image-set/v0.1.5".to_string())
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

    const IMAGES: &str = "tinylabscom/mvm-images";

    fn checkout_workflow(reference: Option<&str>, resolver: &str) -> String {
        let reference = reference.map_or(String::new(), |r| format!("          ref: {r}\n"));
        format!(
            "on:\n  merge_group:\njobs:\n  build:\n    steps:\n\
             \x20     - uses: actions/checkout@v6\n\
             \x20     - name: Resolve\n        id: images-ref\n        run: |\n\
             \x20         ref=\"$(cargo run -q -p {resolver})\"\n\
             \x20         echo \"ref=$ref\" >> \"$GITHUB_OUTPUT\"\n\
             \x20     - name: Check out mvm-images\n        uses: actions/checkout@v6\n\
             \x20       with:\n          repository: {IMAGES}\n{reference}\
             \x20         path: mvm-images\n\
             \x20     - name: Build\n        run: nix build\n"
        )
    }

    const LOCKED_REF: &str = "${{ steps.images-ref.outputs.ref }}";

    #[test]
    fn a_checkout_at_the_resolved_ref_passes() {
        let text = checkout_workflow(Some(LOCKED_REF), "xtask -- image-source-ref");
        assert_eq!(
            checkout_findings(".github/workflows/ci.yml", &text, IMAGES),
            vec![]
        );
    }

    #[test]
    fn a_checkout_of_main_fails_and_names_the_line() {
        let text = checkout_workflow(Some("main"), "xtask -- image-source-ref");
        let findings = checkout_findings(".github/workflows/e2e-docs.yml", &text, IMAGES);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let line = text.lines().nth(findings[0].line - 1).unwrap();
        assert!(
            line.contains("repository: tinylabscom/mvm-images"),
            "{line}"
        );
        assert!(
            findings[0].detail.contains("\"main\""),
            "{}",
            findings[0].detail
        );
    }

    /// No `ref:` is the repository's default branch, which is `main` by
    /// another spelling.
    #[test]
    fn a_checkout_without_a_ref_fails() {
        let text = checkout_workflow(None, "xtask -- image-source-ref");
        let findings = checkout_findings(".github/workflows/ci.yml", &text, IMAGES);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("default branch"));
    }

    #[test]
    fn a_ref_from_a_step_that_does_not_resolve_the_lock_fails() {
        let text = checkout_workflow(Some(LOCKED_REF), "xtask -- release-boot-image tag");
        let findings = checkout_findings(".github/workflows/ci.yml", &text, IMAGES);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("\"images-ref\""));
    }

    #[test]
    fn a_hardcoded_commit_fails() {
        let text = checkout_workflow(Some(&"a".repeat(40)), "xtask -- image-source-ref");
        assert_eq!(
            checkout_findings(".github/workflows/ci.yml", &text, IMAGES).len(),
            1
        );
    }

    #[test]
    fn a_checkout_of_another_repository_is_not_a_finding() {
        let text = checkout_workflow(Some("main"), "true").replace(IMAGES, "tinylabscom/mvmd");
        assert_eq!(
            checkout_findings(".github/workflows/ci.yml", &text, IMAGES),
            vec![]
        );
    }

    #[test]
    fn a_canary_on_schedule_and_dispatch_passes() {
        let text = "on:\n  schedule:\n    - cron: \"0 0 * * *\"\n  workflow_dispatch:\n\
                    jobs:\n  pair:\n    steps:\n      - uses: actions/checkout@v6\n\
                    \x20       with:\n          repository: tinylabscom/mvm-images\n\
                    \x20         ref: main\n";
        assert_eq!(checkout_findings(CANARY_WORKFLOWS[0], text, IMAGES), vec![]);
    }

    #[test]
    fn a_canary_on_a_gating_trigger_fails_in_either_form() {
        for (text, trigger) in [
            (
                "on:\n  schedule:\n  pull_request:\njobs: {}\n",
                "pull_request",
            ),
            ("on:\n  workflow_call:\njobs: {}\n", "workflow_call"),
            ("on: [schedule, merge_group]\njobs: {}\n", "merge_group"),
            ("on: push\njobs: {}\n", "push"),
        ] {
            let findings = checkout_findings(CANARY_WORKFLOWS[0], text, IMAGES);
            assert_eq!(findings.len(), 1, "{text:?}: {findings:?}");
            assert!(
                findings[0].detail.contains(trigger),
                "{}",
                findings[0].detail
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
