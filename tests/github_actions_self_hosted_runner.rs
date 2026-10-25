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

/// The script every job that can run on the KVM pool runs as its last step.
const JOB_CLEANUP: &str = "nix/ops/hetzner/job-cleanup.sh";

/// Top-level jobs of a workflow as `(name, body)`. Jobs sit at two-space
/// indent under `jobs:`; a body ends at the next job or top-level key.
fn jobs(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() && !line.starts_with('#') {
            in_jobs = line.trim_end() == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        let is_header = line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && line.trim_end().ends_with(':');
        if is_header {
            out.push((line.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// Whether a job's runner selection can name the KVM pool, directly or
/// through a matrix `runner:` value.
fn can_run_on_kvm_pool(body: &str) -> bool {
    body.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("- ").unwrap_or(line);
        (line.starts_with("runs-on:") || line.starts_with("runner:")) && line.contains("hetzner")
    })
}

/// The text of a job's last step: everything from the last list item at
/// step indent (six spaces) to the end of the job.
fn last_step(body: &str) -> Option<&str> {
    let at = body.rfind("\n      - ")?;
    Some(&body[at + 1..])
}

/// Why a KVM-pool job does not clean up after itself, if it does not.
fn missing_cleanup(body: &str) -> Option<String> {
    let Some(step) = last_step(body) else {
        return Some("it has no steps".into());
    };
    let always = step.lines().any(|line| line.trim() == "if: always()");
    if !step.contains(JOB_CLEANUP) {
        return Some(format!("its last step does not run {JOB_CLEANUP}"));
    }
    if !always {
        return Some(format!(
            "its last step runs {JOB_CLEANUP} but not under `if: always()`, so a failed \
             or cancelled job skips it"
        ));
    }
    None
}

/// The KVM box is one persistent machine shared by CI and by people. A job
/// that leaves a VMM running or a temporary tree behind costs every later
/// job and session: a leaked Firecracker ran at full CPU for days, and
/// leftovers filled half the root disk. Every job that can run there must
/// end with the always-run cleanup that kills what it started by PID and
/// removes its isolated HOME, MVM_HOME and TMPDIR.
#[test]
fn every_kvm_pool_job_ends_with_the_always_run_cleanup() {
    let mut checked = 0;
    let mut violations = Vec::new();
    for workflow in workflows() {
        for (job, body) in jobs(&workflow.text) {
            if !can_run_on_kvm_pool(&body) {
                continue;
            }
            if workflow.name == "workspace-shard.yml" && job == "inventory" {
                // This exception is command-allowlisted, not a general opt-out.
                assert_read_only_inventory(&body);
                continue;
            }
            checked += 1;
            if let Some(why) = missing_cleanup(&body) {
                violations.push(format!("{}: job `{job}`: {why}", workflow.name));
            }
        }
    }
    assert!(
        checked > 0,
        "no job can run on the KVM pool; if the pool moved, this test is no longer guarding it"
    );
    assert!(
        violations.is_empty(),
        "a job that can run on the self-hosted KVM pool does not clean up after itself:\n  {}",
        violations.join("\n  ")
    );
    assert!(
        Path::new(JOB_CLEANUP).is_file(),
        "{JOB_CLEANUP} is what every KVM-pool job runs last; it must exist"
    );
}

#[test]
fn a_kvm_pool_job_without_the_cleanup_is_refused() {
    let text = "on:\n  workflow_dispatch:\njobs:\n  a:\n    runs-on: [self-hosted, hetzner]\n    steps:\n      - run: cargo test\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n";
    let found = jobs(text);
    assert_eq!(found.len(), 2);
    assert!(can_run_on_kvm_pool(&found[0].1));
    assert!(!can_run_on_kvm_pool(&found[1].1));
    assert!(
        missing_cleanup(&found[0].1)
            .unwrap()
            .contains("does not run")
    );
}

#[test]
fn the_cleanup_must_be_last_and_always_run() {
    let not_last = "    runs-on: hetzner\n    steps:\n      - if: always()\n        run: bash nix/ops/hetzner/job-cleanup.sh /tmp/x\n      - run: cargo test\n";
    assert!(missing_cleanup(not_last).is_some());
    let not_always = "    runs-on: hetzner\n    steps:\n      - run: cargo test\n      - run: bash nix/ops/hetzner/job-cleanup.sh /tmp/x\n";
    assert!(missing_cleanup(not_always).unwrap().contains("always()"));
    let good = "    runs-on: hetzner\n    steps:\n      - run: cargo test\n      - name: Clean\n        if: always()\n        run: bash nix/ops/hetzner/job-cleanup.sh /tmp/x\n";
    assert_eq!(missing_cleanup(good), None);
}

#[test]
fn a_matrix_runner_naming_the_pool_counts() {
    let body = "    strategy:\n      matrix:\n        include:\n          - runner: [self-hosted, hetzner, kvm]\n    runs-on: ${{ matrix.runner }}\n";
    assert!(can_run_on_kvm_pool(body));
}

#[test]
fn extended_ci_places_live_temp_state_on_the_runner_disk() {
    let workflow =
        fs::read_to_string(".github/workflows/ci-full.yml").expect("read Extended CI workflow");
    assert!(
        workflow.contains("base=\"${RUNNER_TEMP}/mvm-w-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-"),
        "live OCI preparation must not use the small /tmp tmpfs"
    );
    assert!(
        workflow.contains(
            "job-cleanup.sh \"${RUNNER_TEMP}/mvm-w-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-"
        ),
        "the always-run cleanup must own the same disk-backed temp tree"
    );
}

#[test]
fn job_cleanup_accepts_a_private_base_under_runner_temp() {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let runner_temp = std::env::temp_dir().join(format!(
        "mvm-runner-temp-cleanup-{}-{suffix}",
        std::process::id()
    ));
    let base = runner_temp.join("mvm-w-123-1-1");
    std::fs::create_dir_all(&base).expect("create isolated base");

    let result = std::process::Command::new("bash")
        .arg(JOB_CLEANUP)
        .arg(&base)
        .env("RUNNER_TEMP", &runner_temp)
        .env("DRY_RUN", "1")
        .output()
        .expect("run cleanup validation");
    assert!(
        result.status.success(),
        "cleanup rejected runner-temp base: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("removing"),
        "dry-run should validate and report the base: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(base.is_dir(), "dry-run must leave the isolated base intact");
    std::fs::remove_dir_all(runner_temp).expect("remove test directory");
}

fn inventory_script(body: &str) -> String {
    body.split_once("        run: |\n")
        .expect("one inline inventory script")
        .1
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| line.strip_prefix("          ").expect("script indentation"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Keep the cleanup exception limited to these reviewed read-only commands.
fn assert_read_only_inventory(body: &str) {
    for required in [
        "if: github.event_name == 'workflow_dispatch' && inputs.inventory_only",
        "permissions: {}",
        "timeout-minutes: 5",
        "shell: bash",
        "RUNNER_KIND: ${{ inputs.runner_kind }}",
    ] {
        assert!(
            body.contains(required),
            "missing inventory guard: {required}"
        );
    }
    assert_eq!(body.matches("      - ").count(), 1);
    assert!(!body.contains("uses:"));
    assert!(!body.contains("secrets."));
    assert!(!body.contains("GITHUB_ENV"));
    assert!(body.contains(&format!(
        "runs-on: ${{{{ inputs.runner_kind == 'hetzner' && fromJSON('{KVM_POOL}') || 'ubuntu-24.04' }}}}"
    )));
    let allowed = [
        "set -euo pipefail",
        "if [[ \"$RUNNER_KIND\" != hetzner ]]; then",
        "echo \"inventory_only requires runner_kind=hetzner\" | tee -a \"$GITHUB_STEP_SUMMARY\"",
        "exit 1",
        "fi",
        "{",
        "uname -m",
        "LC_ALL=C lscpu | awk -F: '/^(Architecture|CPU\\(s\\)|Model name|Socket\\(s\\)|Core\\(s\\) per socket|Thread\\(s\\) per core):/ { print }'",
        "nproc",
        "free -h",
        "df -h / \"$GITHUB_WORKSPACE\"",
        "lsblk -o NAME,TYPE,SIZE",
        "if command -v rustup >/dev/null 2>&1; then",
        "rustup toolchain list",
        "else",
        "for tool in rustc cargo gcc clang cc zig cargo-zigbuild cargo-nextest ld.lld nix go python3 node; do",
        "command -v \"$tool\" || printf '%s: not on PATH\\n' \"$tool\"",
        "done",
        "if [[ -e /dev/kvm ]]; then",
        "ls -l /dev/kvm",
        "if [[ -r /dev/kvm && -w /dev/kvm ]]; then",
        "} | tee -a \"$GITHUB_STEP_SUMMARY\"",
    ];
    for line in inventory_script(body).lines().map(str::trim) {
        // Literal single-quoted headings cannot execute or redirect anything.
        let literal_printf = line
            .strip_prefix("printf '")
            .and_then(|text| text.strip_suffix('\''))
            .is_some_and(|text| !text.contains('\''));
        assert!(
            line.starts_with('#') || literal_printf || allowed.contains(&line),
            "inventory cleanup exception cannot run unreviewed command: {line}"
        );
    }
}

#[test]
fn inventory_is_opt_in_and_leaves_reusable_and_default_dispatch_tests_unchanged() {
    let text = fs::read_to_string(".github/workflows/workspace-shard.yml").unwrap();
    let (call, dispatch) = text.split_once("  workflow_dispatch:").unwrap();
    assert!(!call.contains("inventory_only"));
    assert!(
        dispatch.contains("        required: false\n        type: boolean\n        default: false")
    );
    let found = jobs(&text);
    let inventory = &found
        .iter()
        .find(|(name, _)| name == "inventory")
        .unwrap()
        .1;
    assert_read_only_inventory(inventory);
    let test = &found.iter().find(|(name, _)| name == "test").unwrap().1;
    assert!(
        test.contains("if: github.event_name != 'workflow_dispatch' || !inputs.inventory_only")
    );
    assert_eq!(missing_cleanup(test), None);
}

#[test]
#[should_panic(expected = "inventory cleanup exception cannot run unreviewed command")]
fn inventory_cleanup_exception_refuses_stateful_commands() {
    let text = fs::read_to_string(".github/workflows/workspace-shard.yml").unwrap();
    let found = jobs(&text);
    let body = &found
        .iter()
        .find(|(name, _)| name == "inventory")
        .unwrap()
        .1;
    assert_read_only_inventory(&body.replace("            uname -m", "            cargo test"));
}

#[test]
fn inventory_reports_to_stdout_and_summary_and_rejects_other_runners() {
    let text = fs::read_to_string(".github/workflows/workspace-shard.yml").unwrap();
    let found = jobs(&text);
    let body = &found
        .iter()
        .find(|(name, _)| name == "inventory")
        .unwrap()
        .1;
    assert_read_only_inventory(body);
    // Mock Linux hardware tools: this test must not inventory the developer host.
    // Compiler/tool shims deliberately fail if the script ever invokes them.
    let mocks = r#"
uname() { echo x86_64; }
lscpu() { printf 'Model name: fixture CPU\nCPU(s): 8\n'; }
nproc() { echo 8; }
free() { echo 'Mem: 16Gi'; }
df() { echo 'disk 100G'; }
lsblk() { echo 'vda disk 100G'; }
ls() { echo '/dev/kvm metadata'; }
rustup() { [[ "$*" == 'toolchain list' ]] || return 99; echo stable-fixture; }
rustc() { echo 'compiler shim invoked' >&2; return 99; }
cargo() { echo 'cargo shim invoked' >&2; return 99; }
command() {
  if [[ "$*" == '-v rustup' && "$TEST_RUSTUP_PRESENT" == false ]]; then
    return 1
  fi
  builtin command "$@"
}
"#;
    let summary = std::env::temp_dir().join(format!(
        "mvm-inventory-summary-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for (selector, rustup_present) in [
        ("hetzner", true),
        ("hetzner", false),
        ("github", true),
        ("invalid", true),
        ("", true),
    ] {
        let result = std::process::Command::new("/bin/bash")
            .args(["--noprofile", "--norc", "-c"])
            .arg(format!("{mocks}\n{}", inventory_script(body)))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RUNNER_KIND", selector)
            .env("TEST_RUSTUP_PRESENT", rustup_present.to_string())
            .env("GITHUB_WORKSPACE", "/unused-mocked-workspace")
            .env("GITHUB_STEP_SUMMARY", &summary)
            .output()
            .expect("run mocked inventory");
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert_eq!(stdout, fs::read_to_string(&summary).unwrap());
        fs::remove_file(&summary).unwrap();
        assert_eq!(result.status.success(), selector == "hetzner");
        if selector == "hetzner" {
            for expected in [
                "x86_64",
                "fixture CPU",
                "8",
                "16Gi",
                "100G",
                if rustup_present {
                    "stable-fixture"
                } else {
                    "rustup not installed"
                },
                "/dev/kvm",
            ] {
                assert!(
                    stdout.contains(expected),
                    "missing inventory field: {expected}"
                );
            }
        } else {
            assert_eq!(stdout.trim(), "inventory_only requires runner_kind=hetzner");
        }
        assert!(result.stderr.is_empty(), "{:?}", result.stderr);
    }
}
