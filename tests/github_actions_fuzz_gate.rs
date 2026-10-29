//! Regression checks for the CI gate that compiles workspace-excluded fuzz crates.

/// `ci-full.yml` used to be the second entry here. It was deleted after
/// running zero times since it was written: a gate that lives only in a
/// workflow nobody triggers is not a gate, and asserting on its text made
/// it look like one.
const WORKFLOWS: [&str; 1] = [include_str!("../.github/workflows/ci.yml")];

#[test]
fn fuzz_compile_gates_use_committed_lockfiles() {
    for workflow in WORKFLOWS {
        let step = workflow
            .split("- name: cargo-fuzz crates still compile")
            .nth(1)
            .expect("workflow must compile workspace-excluded fuzz crates");
        let command = step
            .lines()
            .find(|line| line.contains("cargo check ") && line.contains("--manifest-path"))
            .expect("fuzz compile step must contain cargo check");

        assert!(
            command.contains("--locked"),
            "fuzz compile gate must reject stale lockfiles: {command}"
        );
    }
}

#[test]
fn pull_request_fuzz_detection_compares_the_fetched_trees() {
    let workflow = WORKFLOWS[0];
    let step = workflow
        .split("- name: Detect fuzz-crate changes")
        .nth(1)
        .expect("pull-request workflow must detect fuzz-crate changes");
    let command = step
        .lines()
        .find(|line| line.contains("git diff --name-only"))
        .expect("fuzz change detector must compare the base and head trees");

    assert!(
        command.contains("\"$BASE_SHA\" HEAD"),
        "depth-one checkouts must compare trees without finding a merge base: {command}"
    );
}

#[test]
fn fuzz_detection_covers_dependency_manifests_and_fails_closed() {
    let step = WORKFLOWS[0]
        .split("- name: Detect fuzz-crate changes")
        .nth(1)
        .expect("fuzz detector step")
        .split("- name:")
        .next()
        .unwrap();
    let script = step
        .split("run: |\n")
        .nth(1)
        .expect("fuzz detector shell script")
        .lines()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    for (path, base, diff_status, expected) in [
        ("crates/mvm-runtime/Cargo.toml", "base", "0", true),
        ("crates/mvm-vmm/Cargo.toml", "base", "0", true),
        ("Cargo.toml", "base", "0", true),
        (
            "crates/mvm-runtime/fuzz/fuzz_targets/run.rs",
            "base",
            "0",
            true,
        ),
        ("fuzz-extra/target.rs", "base", "0", true),
        ("docs/guide.md", "base", "0", false),
        ("crates/mvm-runtime/src/lib.rs", "base", "0", false),
        ("Cargo.lock", "base", "0", false),
        ("docs/fuzzy.md", "base", "0", false),
        ("docs/\nfuzz/not-a-directory.md", "base", "0", false),
        ("docs/guide.md", "", "0", true),
        ("docs/guide.md", "base", "1", true),
    ] {
        let output = std::process::Command::new("bash")
            .args(["--noprofile", "--norc", "-c"])
            .arg(format!(
                r#"
git() {{
    case "$1" in
        fetch) return 0 ;;
        diff)
            case " $* " in
                *" -z "*) printf '%s\0' "$MOCK_PATH" ;;
                *) printf '%s\n' "$MOCK_PATH" ;;
            esac
            return "$MOCK_DIFF_STATUS"
            ;;
        *) return 99 ;;
    esac
}}
{script}
"#
            ))
            .env("BASE_SHA", base)
            .env("MOCK_PATH", path)
            .env("MOCK_DIFF_STATUS", diff_status)
            .env("GITHUB_OUTPUT", "/dev/stdout")
            .output()
            .expect("execute actual fuzz detector with mocked git");
        assert!(
            output.status.success(),
            "{path:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("changed={expected}"),
            "{path:?}, base={base:?}, diff status={diff_status}"
        );
    }
}
