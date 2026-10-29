//! Run the scope job's real classifier patterns against synthetic diffs.
//!
//! The patterns live in a `grep -zE` inside `ci.yml`. Lifting the real
//! pattern out and feeding it the NUL-separated list `git diff --name-only -z`
//! produces catches an anchoring or escaping mistake in the YAML here rather
//! than as a lane that never runs.

use std::process::{Command, Stdio};

/// Lift the `grep -zE` pattern that decides `{output}=true` out of the scope
/// job.
fn classifier_pattern(output: &str) -> String {
    let workflow = std::fs::read_to_string(".github/workflows/ci.yml")
        .expect("failed to read .github/workflows/ci.yml");
    let lines: Vec<&str> = workflow.lines().collect();
    let marker = format!(r#"echo "{output}=true""#);
    let emit = lines
        .iter()
        .position(|line| line.contains(&marker))
        .unwrap_or_else(|| panic!("the scope job must emit {output}=true"));
    let grep = lines[..emit]
        .iter()
        .rev()
        .find(|line| line.contains("grep -zE"))
        .unwrap_or_else(|| panic!("{output}=true must follow its grep"));
    grep.split_once("grep -zE '")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(pattern, _)| pattern.to_string())
        .unwrap_or_else(|| panic!("the {output} grep must carry a single-quoted pattern: {grep}"))
}

/// `true` when the code classifier puts a diff naming `paths` in the Rust
/// lanes' scope.
fn classified_as_code(paths: &[&str]) -> bool {
    classified_as(&classifier_pattern("code"), paths)
}

/// `true` when `pattern` matches the NUL-separated list naming `paths`.
fn classified_as(pattern: &str, paths: &[&str]) -> bool {
    let mut input = Vec::new();
    for path in paths {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
    }
    let mut child = Command::new("grep")
        .arg("-zE")
        .arg(pattern)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn grep");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("grep stdin")
            .write_all(&input)
            .expect("write the changed-file list");
    }
    child.wait().expect("grep did not exit").success()
}

/// The code scope is what turns every Rust lane on, so a miss here is a
/// change merging without the suite that reads it. Prose a Rust test parses
/// belongs in it; prose nothing compiled reads does not, or a docs edit pays
/// for the whole matrix.
#[test]
fn the_code_classifier_covers_what_rust_reads_and_skips_plain_prose() {
    for path in [
        "Cargo.lock",
        "crates/mvm-core/src/lib.rs",
        "xtask/src/main.rs",
        "tests/cli.rs",
        "nix/lib/mk-guest.nix",
        "model/claims.toml",
        "scripts/ci-linux-coverage.sh",
        ".github/workflows/ci.yml",
        ".github/actions/rust-cache/action.yml",
        "specs/adrs/001-microvm-security-posture.md",
        "CLAUDE.md",
        "CLAUDE.md.sigstore.json",
        "AGENTS.md",
        "README.md",
        "flake.nix",
        "flake.lock",
        "deny.toml",
        "examples/python/hello-app-with-deps/README.md",
        "public/src/content/docs/reference/performance.md",
        "public/src/content/docs/security/cve-demonstrations.md",
        "public/src/content/docs/contributing/development.md",
        "public/src/content/docs/contributing/ai-coding-workflow.md",
    ] {
        assert!(classified_as_code(&[path]), "{path} must set code=true");
    }
    for path in [
        "public/src/content/docs/guides/troubleshooting.md",
        "public/src/pages/index.astro",
        "specs/plans/2026-08-15-example.md",
        "specs/README.md",
        "CHANGELOG.md",
        "docs/README.md",
        "crates.md",
        "README.md.orig",
    ] {
        assert!(
            !classified_as_code(&[path]),
            "{path} must not set code=true"
        );
    }
}
