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

/// Whether a workflow places a job on the runner by label.
fn targets_runner(text: &str) -> bool {
    text.lines().any(|line| {
        let Some(value) = line.trim_start().strip_prefix("runs-on:") else {
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
