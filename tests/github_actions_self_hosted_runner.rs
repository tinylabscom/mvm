//! Only trusted events may reach the self-hosted Apple Silicon runner.
//!
//! The repository is public, and the `m1` runner is a physical machine that
//! keeps its home directory between jobs. Code from a fork pull request must
//! never execute on it. GitHub's fork-approval policy is one control, but it is
//! a human clicking "approve"; this is the in-tree half: no workflow that an
//! untrusted event can start may place a job on the runner, directly or through
//! a reusable workflow it calls.
//!
//! What this does not cover: a fork PR that *edits* a workflow to target the
//! label. That code only runs if a maintainer approves it, and refusing it
//! mechanically needs a runner group restricted to selected workflows, which is
//! repository settings rather than repository content.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// The custom label that identifies the self-hosted Apple Silicon runner.
const RUNNER_LABEL: &str = "m1";

/// Triggers that run code which has not been merged to `main` by someone with
/// write access: pull-request events (including a fork's), the merge queue's
/// pre-merge build, and comment/review events a fork contributor can cause.
const UNTRUSTED_EVENTS: &[&str] = &[
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issue_comment",
    "merge_group",
    "workflow_run",
];

/// A workflow file, by name, with its text.
struct Workflow {
    name: String,
    text: String,
}

fn workflows() -> Vec<Workflow> {
    let dir = Path::new(".github/workflows");
    let mut out: Vec<Workflow> = fs::read_dir(dir)
        .expect("read .github/workflows")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .map(|path| Workflow {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            text: fs::read_to_string(&path).expect("read workflow"),
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The body of the top-level `on:` block — every line after `on:` up to the
/// next top-level key. `None` when the block is written inline (`on: [push]`),
/// which [`trigger_events`] refuses rather than guesses at.
fn on_block(text: &str) -> Option<String> {
    let mut lines = text.lines().skip_while(|line| !line.starts_with("on:"));
    let header = lines.next()?;
    if header.trim_end() != "on:" {
        return None;
    }
    Some(
        lines
            .take_while(|line| line.is_empty() || line.starts_with(' ') || line.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The event names declared directly under `on:`.
fn trigger_events(text: &str) -> Result<BTreeSet<String>, String> {
    let block = on_block(text).ok_or("the `on:` block must be a mapping, not inline")?;
    Ok(block
        .lines()
        .filter_map(|line| {
            let key = line.strip_prefix("  ")?;
            if key.starts_with(' ') || key.starts_with('#') {
                return None;
            }
            Some(key.split(':').next()?.trim().to_string())
        })
        .filter(|key| !key.is_empty())
        .collect())
}

/// The lines nested under `push:` in the `on:` block, trimmed.
fn push_section(text: &str) -> Option<Vec<String>> {
    let block = on_block(text)?;
    let mut lines = block
        .lines()
        .skip_while(|line| line.trim_end() != "  push:");
    lines.next()?;
    Some(
        lines
            .take_while(|line| line.starts_with("    ") || line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect(),
    )
}

/// Whether a workflow places a job on the runner by label: in `runs-on:`
/// itself, or in the matrix `runner:` value a `runs-on: ${{ matrix.runner }}`
/// job expands.
fn targets_runner(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("- ").unwrap_or(line);
        let Some(value) = line
            .strip_prefix("runs-on:")
            .or_else(|| line.strip_prefix("runner:"))
        else {
            return false;
        };
        value
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .any(|label| label.trim() == RUNNER_LABEL)
    })
}

/// Every workflow that can put a job on the runner: those naming the label,
/// and, to a fixed point, every workflow that calls one of those.
fn workflows_reaching_runner(all: &[Workflow]) -> BTreeSet<String> {
    let mut reaching: BTreeSet<String> = all
        .iter()
        .filter(|w| targets_runner(&w.text))
        .map(|w| w.name.clone())
        .collect();
    loop {
        let callers: Vec<String> = all
            .iter()
            .filter(|w| !reaching.contains(&w.name))
            .filter(|w| {
                reaching.iter().any(|callee| {
                    w.text
                        .contains(&format!("uses: ./.github/workflows/{callee}"))
                })
            })
            .map(|w| w.name.clone())
            .collect();
        if callers.is_empty() {
            return reaching;
        }
        reaching.extend(callers);
    }
}

/// Why a workflow that reaches the runner is not allowed to, if it is not.
fn untrusted_reach(text: &str) -> Option<String> {
    let events = match trigger_events(text) {
        Ok(events) => events,
        Err(why) => return Some(why),
    };
    if let Some(event) = events
        .iter()
        .find(|e| UNTRUSTED_EVENTS.contains(&e.as_str()))
    {
        return Some(format!("triggered by `{event}`, which runs unmerged code"));
    }
    if events.contains("push") {
        let section = push_section(text).unwrap_or_default();
        let branches = section.iter().find(|line| line.starts_with("branches"));
        let tags = section.iter().any(|line| line.starts_with("tags"));
        match branches {
            Some(filter) if filter != "branches: [main]" => {
                return Some(format!(
                    "`push` filter `{filter}` admits branches other than main"
                ));
            }
            None if !tags => {
                return Some("`push` without a branch or tag filter runs any branch".into());
            }
            _ => {}
        }
    }
    None
}

#[test]
fn no_untrusted_event_can_place_a_job_on_the_self_hosted_runner() {
    let all = workflows();
    let reaching = workflows_reaching_runner(&all);
    assert!(
        reaching.contains("e2e-docs.yml"),
        "the macOS documented-surface lane must target the `{RUNNER_LABEL}` runner; \
         if it moved, this test is no longer guarding it"
    );
    assert!(
        reaching.contains("first-run-smoke.yml") && reaching.contains("release.yml"),
        "the macOS first-run lane must target the `{RUNNER_LABEL}` runner through its \
         matrix, and the release that calls it must be seen to reach it"
    );

    let violations: Vec<String> = all
        .iter()
        .filter(|w| reaching.contains(&w.name))
        .filter_map(|w| untrusted_reach(&w.text).map(|why| format!("{}: {why}", w.name)))
        .collect();
    assert!(
        violations.is_empty(),
        "a workflow that can put a job on the self-hosted `{RUNNER_LABEL}` runner is \
         reachable from an untrusted event — fork code could execute on a persistent \
         physical machine:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn a_pull_request_trigger_is_refused() {
    let text = "on:\n  pull_request:\n  workflow_dispatch:\njobs:\n";
    assert!(untrusted_reach(text).unwrap().contains("pull_request"));
}

#[test]
fn the_merge_queue_trigger_is_refused() {
    let text = "on:\n  merge_group:\njobs:\n";
    assert!(untrusted_reach(text).unwrap().contains("merge_group"));
}

#[test]
fn a_push_to_any_branch_is_refused_and_tags_or_main_are_not() {
    assert!(untrusted_reach("on:\n  push:\njobs:\n").is_some());
    assert!(untrusted_reach("on:\n  push:\n    branches: [feature]\njobs:\n").is_some());
    assert!(untrusted_reach("on:\n  push:\n    tags:\n      - \"v*\"\njobs:\n").is_none());
    assert!(untrusted_reach("on:\n  push:\n    branches: [main]\njobs:\n").is_none());
}

#[test]
fn schedules_dispatch_and_reusable_calls_are_trusted() {
    let text = "on:\n  schedule:\n    - cron: \"0 0 * * *\"\n  workflow_dispatch:\n  workflow_call:\njobs:\n";
    assert_eq!(untrusted_reach(text), None);
}

#[test]
fn a_matrix_runner_value_is_a_runner_target() {
    assert!(targets_runner(
        "jobs:\n  a:\n    strategy:\n      matrix:\n        include:\n          - runner: [self-hosted, m1]\n    runs-on: ${{ matrix.runner }}\n"
    ));
    assert!(!targets_runner(
        "jobs:\n  a:\n    strategy:\n      matrix:\n        include:\n          - runner: ubuntu-latest\n    runs-on: ${{ matrix.runner }}\n"
    ));
}

#[test]
fn an_inline_trigger_list_is_refused_rather_than_guessed_at() {
    assert!(untrusted_reach("on: [push, pull_request]\njobs:\n").is_some());
}

#[test]
fn reach_follows_reusable_workflow_callers() {
    let all = vec![
        Workflow {
            name: "lane.yml".into(),
            text: "on:\n  workflow_call:\njobs:\n  a:\n    runs-on: [self-hosted, m1]\n".into(),
        },
        Workflow {
            name: "caller.yml".into(),
            text: "on:\n  pull_request:\njobs:\n  b:\n    uses: ./.github/workflows/lane.yml\n"
                .into(),
        },
        Workflow {
            name: "unrelated.yml".into(),
            text: "on:\n  pull_request:\njobs:\n  c:\n    runs-on: ubuntu-latest\n".into(),
        },
    ];
    let reaching = workflows_reaching_runner(&all);
    assert!(reaching.contains("lane.yml") && reaching.contains("caller.yml"));
    assert!(!reaching.contains("unrelated.yml"));
}

#[test]
fn a_label_that_merely_contains_m1_does_not_count() {
    assert!(!targets_runner("    runs-on: [self-hosted, m1-large]\n"));
    assert!(targets_runner(
        "    runs-on: [self-hosted, macOS, ARM64, m1]\n"
    ));
}

/// The self-hosted x86_64 KVM pool, as the shard worker spells its labels.
const KVM_POOL: &str = r#"["self-hosted","Linux","X64","mvm","hetzner","kvm"]"#;

/// The required CI workflow is the one untrusted-event workflow allowed to
/// reach the KVM pool, and only through the runner picker. The picker reads
/// the pull request's head repository before it reads the token, and a fork
/// resolves to a hosted runner. A pull request from a branch of this
/// repository was pushed by someone with write access; a fork's was not.
#[test]
fn only_the_runner_picker_routes_ci_to_the_kvm_pool_and_never_for_a_fork() {
    let all = workflows();
    let shard = all
        .iter()
        .find(|w| w.name == "workspace-shard.yml")
        .expect("the workspace shard worker must exist");
    assert!(
        shard.text.contains(&format!("fromJSON('{KVM_POOL}')")),
        "the shard worker is what places a job on the KVM pool; if it moved, \
         this test is no longer guarding it"
    );
    assert!(
        shard
            .text
            .contains("runs-on: ${{ inputs.runner_kind == 'hetzner' && fromJSON("),
        "only `runner_kind: hetzner` may select the KVM pool"
    );

    for workflow in &all {
        let untrusted = untrusted_reach(&workflow.text).is_some();
        if !untrusted || workflow.name == "workspace-shard.yml" {
            continue;
        }
        for line in workflow.text.lines() {
            let line = line.trim();
            let line = line.strip_prefix("- ").unwrap_or(line);
            if line.starts_with("runs-on:") || line.starts_with("runner:") {
                assert!(
                    !line.contains("hetzner"),
                    "{}: an untrusted-event workflow places a job on the KVM pool \
                     directly: {line:?}",
                    workflow.name
                );
            }
            // A literal `github` pins the hosted pool and is always safe;
            // anything else must be the picker's answer.
            if let Some(kind) = line.strip_prefix("runner_kind:") {
                let kind = kind.trim();
                assert!(
                    kind == "github"
                        || (workflow.name == "ci.yml"
                            && kind
                                == "${{ needs.runners.outputs.workspace == 'hetzner' && 'hetzner' || 'github' }}"),
                    "{}: `runner_kind` must be `github` or ci.yml's runner picker, found {line:?}",
                    workflow.name
                );
            }
        }
    }

    let ci = all
        .iter()
        .find(|w| w.name == "ci.yml")
        .expect("ci.yml must exist");
    let picker = ci
        .text
        .split_once("\n  runners:\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once("\n  lint-core:\n").map(|(job, _)| job))
        .expect("ci.yml must define the runner picker before lint-core");
    let fork_check = picker
        .find(r#"[ "$EVENT" = pull_request ] && [ "$HEAD_REPO" != "$REPO" ]"#)
        .expect("the picker must refuse a fork's pull request");
    let token_use = picker
        .find(r#"GH_TOKEN="$PICKER_TOKEN""#)
        .expect("the picker lists runners with its own token");
    assert!(
        fork_check < token_use,
        "the fork refusal must come before the token is used"
    );
    for expected in [
        "HEAD_REPO: ${{ github.event.pull_request.head.repo.full_name }}",
        "PICKER_TOKEN: ${{ secrets.RUNNER_PICKER_TOKEN }}",
        "WORKSPACE_ROUTING: ${{ vars.RUNNER_PICKER_WORKSPACE }}",
        r#"[ "$WORKSPACE_ROUTING" != true ]"#,
        "workspace=github",
        r#"select(.status == "online" and .busy == false)"#,
        "exit 0",
    ] {
        assert!(
            picker.contains(expected),
            "the picker must fall back to hosted and only pick an idle online runner: \
             missing {expected:?}"
        );
    }
    assert!(
        !picker.contains("run: |\n          set -e"),
        "the picker must never fail a run, so it cannot run under `set -e`"
    );
}
