use super::*;
use mvm_contract::pack_scenario::PackScenario;
use std::fs;
use tempfile::TempDir;

const BUNDLE: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn document() -> serde_json::Value {
    serde_json::json!({
        "schema": "mvm.pack-scenario/v1",
        "name": "answer",
        "version": "1.0.0",
        "environment": {
            "identity": {"name": "acme/hello", "version": "1.0.0"},
            "target": "aarch64-linux",
            "bundle_sha256": BUNDLE
        },
        "instructions": "write the answer",
        "initial_files": [{"source": "seed", "destination": "work/seed"}],
        "outputs": ["out"],
        "limits": {"wall_clock_secs": 60, "max_output_bytes": 1024, "max_output_files": 4},
        "checks": [
            {"kind": "file_exists", "name": "wrote", "path": "out/answer.json"},
            {"kind": "json_matches", "name": "answer", "path": "out/answer.json",
             "pointer": "/answer", "expected": "answer.json"},
            {"kind": "file_matches", "name": "notes", "path": "out/notes.txt",
             "expected": "notes.txt"},
            {"kind": "command", "name": "hidden", "argv": ["grade"], "exit_code": 0}
        ]
    })
}

/// A scenario directory with a public seed and private answers.
fn layout(value: serde_json::Value) -> (TempDir, ScenarioLayout, PackScenario) {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("scenario.json"), value.to_string()).unwrap();
    fs::create_dir_all(root.path().join("public/seed")).unwrap();
    fs::write(root.path().join("public/seed/input.txt"), "question").unwrap();
    fs::create_dir(root.path().join("private")).unwrap();
    fs::write(root.path().join("private/answer.json"), "42").unwrap();
    fs::write(root.path().join("private/notes.txt"), "SECRET-ANSWER").unwrap();
    let (layout, scenario) = ScenarioLayout::open(root.path()).unwrap();
    (root, layout, scenario)
}

type Step = Box<dyn FnMut(&Path) -> RunExit>;

/// A runner that performs `workload` against the workspace and records what
/// every instance was shown.
struct FakeRunner {
    workload: Step,
    verifier_exit: RunExit,
    seen_workspaces: Vec<PathBuf>,
    workload_saw_private: bool,
    verifier_saw: Vec<(PathBuf, PathBuf)>,
}

impl FakeRunner {
    fn new(workload: impl FnMut(&Path) -> RunExit + 'static) -> Self {
        Self {
            workload: Box::new(workload),
            verifier_exit: RunExit::Exited(0),
            seen_workspaces: Vec::new(),
            workload_saw_private: false,
            verifier_saw: Vec::new(),
        }
    }
}

fn contains_text(root: &Path, needle: &str) -> bool {
    walk(root)
        .any(|path| fs::read(&path).is_ok_and(|b| String::from_utf8_lossy(&b).contains(needle)))
}

fn walk(root: &Path) -> impl Iterator<Item = PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.into_iter()
}

impl ScenarioRunner for FakeRunner {
    fn run_workload(&mut self, run: WorkloadRun<'_>) -> Result<RunExit, ScenarioError> {
        assert_eq!(run.bundle_sha256, BUNDLE);
        assert_eq!(run.instructions, "write the answer");
        self.workload_saw_private |= contains_text(run.workspace, "SECRET-ANSWER");
        self.seen_workspaces.push(run.workspace.to_path_buf());
        Ok((self.workload)(run.workspace))
    }

    fn run_verifier(&mut self, run: VerifierRun<'_>) -> Result<RunExit, ScenarioError> {
        assert_eq!(run.argv, ["grade".to_string()]);
        self.verifier_saw
            .push((run.outputs.to_path_buf(), run.private.to_path_buf()));
        Ok(self.verifier_exit)
    }
}

fn answer(workspace: &Path, value: &str) {
    fs::create_dir_all(workspace.join("out")).unwrap();
    fs::write(
        workspace.join("out/answer.json"),
        format!(r#"{{"answer": {value}}}"#),
    )
    .unwrap();
    fs::write(workspace.join("out/notes.txt"), "SECRET-ANSWER").unwrap();
}

fn options(scratch: &TempDir, runs: u32) -> RunOptions {
    RunOptions {
        scratch: scratch.path().to_path_buf(),
        runs,
    }
}

fn outcomes(report: &RunReport) -> Vec<(&str, bool)> {
    report
        .checks
        .iter()
        .map(|c| (c.name.as_str(), c.outcome == CheckOutcome::Passed))
        .collect()
}

#[test]
fn a_correct_run_passes_every_check() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|ws| {
        assert_eq!(
            fs::read_to_string(ws.join("work/seed/input.txt")).unwrap(),
            "question"
        );
        answer(ws, "42");
        RunExit::Exited(0)
    });
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert!(report.passed(), "{report:#?}");
    assert_eq!(report.scenario_sha256, scenario.sha256().unwrap());
    assert_eq!(report.runs[0].collected_files, 2);
    assert!(!runner.workload_saw_private);
}

#[test]
fn a_wrong_answer_fails_without_revealing_the_expected_value() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|ws| {
        answer(ws, "41");
        RunExit::Exited(0)
    });
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert!(!report.passed());
    assert_eq!(
        outcomes(&report.runs[0]),
        [
            ("wrote", true),
            ("answer", false),
            ("notes", true),
            ("hidden", true)
        ]
    );
    let rendered = serde_json::to_string(&report).unwrap();
    assert!(!rendered.contains("42"), "{rendered}");
    assert!(!rendered.contains("SECRET-ANSWER"), "{rendered}");
}

#[test]
fn a_different_archive_is_refused_before_anything_runs() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|_| panic!("must not run"));
    let error = run_scenario(
        &layout,
        &scenario,
        &"5".repeat(64),
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap_err();
    assert!(
        matches!(error, ScenarioError::EnvironmentMismatch { .. }),
        "{error}"
    );
    assert!(error.to_string().contains(BUNDLE));
    assert!(runner.seen_workspaces.is_empty());
}

#[test]
fn repeated_runs_each_start_from_a_fresh_workspace() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut run = 0;
    let mut runner = FakeRunner::new(move |ws| {
        // State left by an earlier run must never be visible.
        assert!(!ws.join("leftover").exists(), "run {run} saw earlier state");
        assert!(!ws.join("out").exists(), "run {run} saw earlier outputs");
        fs::write(ws.join("leftover"), "from an earlier run").unwrap();
        fs::write(ws.join("work/seed/input.txt"), "tampered").unwrap();
        answer(ws, "42");
        run += 1;
        RunExit::Exited(0)
    });
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 3),
    )
    .unwrap();
    assert_eq!(report.runs.len(), 3);
    assert!(report.passed(), "{report:#?}");
    let distinct: std::collections::BTreeSet<_> = runner.seen_workspaces.iter().collect();
    assert_eq!(distinct.len(), 3);
    for workspace in &runner.seen_workspaces {
        assert!(
            !workspace.exists(),
            "{} survived its run",
            workspace.display()
        );
    }
    // The public seed is not modified by a run that edits its staged copy.
    assert_eq!(
        fs::read_to_string(layout.public_dir().join("seed/input.txt")).unwrap(),
        "question"
    );
    assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[test]
fn private_answers_reach_only_the_verifier_and_after_the_workspace_is_gone() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|ws| {
        answer(ws, "42");
        RunExit::Exited(0)
    });
    run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert!(!runner.workload_saw_private);
    let (outputs, private) = &runner.verifier_saw[0];
    assert_eq!(private, &layout.private_dir());
    assert!(outputs.ends_with("collected"));
    assert!(!runner.seen_workspaces[0].exists());
}

#[test]
fn a_failing_verifier_fails_only_its_check() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|ws| {
        answer(ws, "42");
        RunExit::Exited(0)
    });
    runner.verifier_exit = RunExit::Exited(3);
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert_eq!(
        outcomes(&report.runs[0]),
        [
            ("wrote", true),
            ("answer", true),
            ("notes", true),
            ("hidden", false)
        ]
    );
    runner.verifier_exit = RunExit::TimedOut;
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert!(matches!(
        &report.runs[0].checks[3].outcome,
        CheckOutcome::Failed(reason) if reason.contains("wall clock")
    ));
}

#[test]
fn a_timed_out_workload_is_not_graded() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|ws| {
        answer(ws, "42");
        RunExit::TimedOut
    });
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    assert!(!report.passed());
    assert_eq!(report.runs[0].exit, RunExit::TimedOut);
    assert!(report.runs[0].checks.is_empty());
    assert!(runner.verifier_saw.is_empty());
}

#[test]
fn a_runner_returning_after_the_wall_clock_is_a_timeout() {
    let limit = Duration::from_millis(1);
    let exit = bounded(limit, || {
        std::thread::sleep(Duration::from_millis(20));
        Ok(RunExit::Exited(0))
    })
    .unwrap();
    assert_eq!(exit, RunExit::TimedOut);
    let exit = bounded(Duration::from_secs(60), || Ok(RunExit::Exited(0))).unwrap();
    assert_eq!(exit, RunExit::Exited(0));
}

#[cfg(unix)]
#[test]
fn a_symlinked_output_fails_the_run_instead_of_reading_the_host() {
    let host = TempDir::new().unwrap();
    fs::write(host.path().join("host-secret"), "HOST-ONLY").unwrap();
    let target = host.path().join("host-secret");
    for plant in [
        // A symlink in place of a collected file.
        |ws: &Path, target: &Path| {
            fs::create_dir(ws.join("out")).unwrap();
            std::os::unix::fs::symlink(target, ws.join("out/answer.json")).unwrap();
        },
        // A symlink in place of the collected directory itself.
        |ws: &Path, target: &Path| {
            std::os::unix::fs::symlink(target.parent().unwrap(), ws.join("out")).unwrap();
        },
    ] {
        let (_root, layout, scenario) = layout(document());
        let scratch = TempDir::new().unwrap();
        let target = target.clone();
        let mut runner = FakeRunner::new(move |ws| {
            plant(ws, &target);
            RunExit::Exited(0)
        });
        let report = run_scenario(
            &layout,
            &scenario,
            BUNDLE,
            &mut runner,
            &options(&scratch, 1),
        )
        .unwrap();
        let run = &report.runs[0];
        assert!(!run.passed());
        assert!(
            run.error
                .as_deref()
                .is_some_and(|e| e.contains("symbolic link")),
            "{run:#?}"
        );
        assert!(run.checks.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn staging_refuses_a_symlink_in_the_public_tree() {
    let (root, layout, scenario) = layout(document());
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("x"), "outside").unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("x"),
        root.path().join("public/seed/link"),
    )
    .unwrap();
    let workspace = TempDir::new().unwrap();
    let error = stage_workspace(&layout.public_dir(), &scenario, workspace.path()).unwrap_err();
    assert!(matches!(error, ScenarioError::PathEscape { .. }), "{error}");
}

#[test]
fn staging_requires_an_empty_workspace() {
    let (_root, layout, scenario) = layout(document());
    let workspace = TempDir::new().unwrap();
    fs::write(workspace.path().join("stale"), "x").unwrap();
    let error = stage_workspace(&layout.public_dir(), &scenario, workspace.path()).unwrap_err();
    assert!(
        matches!(error, ScenarioError::WorkspaceNotFresh(_)),
        "{error}"
    );
}

#[test]
fn collection_enforces_the_byte_and_file_limits() {
    for (limits, write) in [
        (
            serde_json::json!({"wall_clock_secs": 60, "max_output_bytes": 8, "max_output_files": 4}),
            (|ws: &Path| fs::write(ws.join("out/big"), "123456789").unwrap()) as fn(&Path),
        ),
        (
            serde_json::json!({"wall_clock_secs": 60, "max_output_bytes": 1024, "max_output_files": 1}),
            |ws: &Path| {
                fs::write(ws.join("out/a"), "a").unwrap();
                fs::write(ws.join("out/b"), "b").unwrap();
            },
        ),
    ] {
        let mut value = document();
        value["limits"] = limits;
        value["checks"] = serde_json::json!([
            {"kind": "file_exists", "name": "wrote", "path": "out/a"}
        ]);
        let scenario: PackScenario = serde_json::from_value(value).unwrap();
        let workspace = TempDir::new().unwrap();
        fs::create_dir(workspace.path().join("out")).unwrap();
        write(workspace.path());
        let dest = TempDir::new().unwrap();
        let error = collect_outputs(workspace.path(), &scenario, dest.path()).unwrap_err();
        assert!(matches!(error, ScenarioError::Limit { .. }), "{error}");
    }
}

#[test]
fn an_absent_output_collects_nothing_and_fails_its_checks() {
    let (_root, layout, scenario) = layout(document());
    let scratch = TempDir::new().unwrap();
    let mut runner = FakeRunner::new(|_| RunExit::Exited(0));
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    let run = &report.runs[0];
    assert!(run.error.is_none());
    assert_eq!(run.collected_files, 0);
    assert_eq!(
        outcomes(run),
        [
            ("wrote", false),
            ("answer", false),
            ("notes", false),
            ("hidden", true)
        ]
    );
}

#[test]
fn opening_a_layout_validates_the_document_and_requires_private_when_read() {
    let (root, _layout, _scenario) = layout(document());
    fs::remove_dir_all(root.path().join("private")).unwrap();
    assert!(ScenarioLayout::open(root.path()).is_err());
    fs::write(
        root.path().join("scenario.json"),
        r#"{"schema":"mvm.pack-scenario/v1"}"#,
    )
    .unwrap();
    assert!(matches!(
        ScenarioLayout::open(root.path()).unwrap_err(),
        ScenarioError::Document(_)
    ));
}

/// A scenario collecting `out` under the given byte and entry limits.
fn bounded_scenario(bytes: u64, files: u32) -> PackScenario {
    let mut value = document();
    value["limits"] = serde_json::json!({
        "wall_clock_secs": 60, "max_output_bytes": bytes, "max_output_files": files
    });
    value["checks"] = serde_json::json!([
        {"kind": "file_exists", "name": "wrote", "path": "out/a"}
    ]);
    serde_json::from_value(value).unwrap()
}

fn collect_error(scenario: &PackScenario, plant: impl FnOnce(&Path)) -> (ScenarioError, TempDir) {
    let workspace = TempDir::new().unwrap();
    fs::create_dir(workspace.path().join("out")).unwrap();
    plant(workspace.path());
    let dest = TempDir::new().unwrap();
    let error = collect_outputs(workspace.path(), scenario, dest.path()).unwrap_err();
    (error, dest)
}

fn copied_bytes(root: &Path) -> u64 {
    walk(root)
        .map(|path| fs::symlink_metadata(path).unwrap().len())
        .sum()
}

#[test]
fn an_oversized_file_is_refused_after_reading_one_byte_past_the_limit() {
    let scenario = bounded_scenario(1024, 8);
    let (error, dest) = collect_error(&scenario, |ws| {
        fs::write(ws.join("out/a"), vec![b'x'; 8 * 1024 * 1024]).unwrap();
    });
    assert!(
        matches!(error, ScenarioError::Limit { unit: "bytes", .. }),
        "{error}"
    );
    // Nothing beyond the limit reached the copy.
    assert!(copied_bytes(dest.path()) <= 1024);
}

#[test]
fn empty_directories_count_against_the_entry_limit() {
    let scenario = bounded_scenario(1024, 16);
    let (error, _dest) = collect_error(&scenario, |ws| {
        for index in 0..100 {
            fs::create_dir(ws.join(format!("out/d{index}"))).unwrap();
        }
    });
    assert!(
        matches!(
            error,
            ScenarioError::Limit {
                unit: "files and directories",
                limit: 16,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn a_tree_nested_past_the_depth_limit_is_refused() {
    let scenario = bounded_scenario(1024, 65_536);
    let (error, _dest) = collect_error(&scenario, |ws| {
        let mut dir = ws.join("out");
        for _ in 0..(MAX_TREE_DEPTH + 4) {
            dir.push("d");
        }
        fs::create_dir_all(dir).unwrap();
    });
    assert!(
        matches!(
            error,
            ScenarioError::Limit {
                unit: "levels of nesting",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn staging_walks_the_public_tree_under_the_same_bounds() {
    let (root, layout, scenario) = layout(document());
    let mut deep = root.path().join("public/seed");
    for _ in 0..(MAX_TREE_DEPTH + 4) {
        deep.push("d");
    }
    fs::create_dir_all(deep).unwrap();
    let workspace = TempDir::new().unwrap();
    let error = stage_workspace(&layout.public_dir(), &scenario, workspace.path()).unwrap_err();
    assert!(
        matches!(
            error,
            ScenarioError::Limit {
                tree: "staged files",
                ..
            }
        ),
        "{error}"
    );
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn a_fifo_output_is_refused_without_blocking() {
    let scenario = bounded_scenario(1024, 8);
    let (error, _dest) = collect_error(&scenario, |ws| {
        mkfifo(&ws.join("out/a"));
    });
    assert!(matches!(error, ScenarioError::PathEscape { .. }), "{error}");
}

#[cfg(unix)]
#[test]
fn opening_a_symlink_or_fifo_directly_is_refused() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("target"), "HOST-ONLY").unwrap();
    std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("link")).unwrap();
    let error = super::fs::read_bounded(&dir.path().join("link"), 1024).unwrap_err();
    assert!(
        matches!(
            error,
            ScenarioError::PathEscape {
                reason: "symbolic link",
                ..
            }
        ),
        "{error}"
    );
    mkfifo(&dir.path().join("fifo"));
    let error = super::fs::read_bounded(&dir.path().join("fifo"), 1024).unwrap_err();
    assert!(matches!(error, ScenarioError::PathEscape { .. }), "{error}");
}

#[test]
fn command_checks_share_one_wall_clock_and_reasons_are_clipped() {
    struct SlowRunner {
        started: u32,
    }
    impl ScenarioRunner for SlowRunner {
        fn run_workload(&mut self, run: WorkloadRun<'_>) -> Result<RunExit, ScenarioError> {
            answer(run.workspace, "42");
            Ok(RunExit::Exited(0))
        }
        fn run_verifier(&mut self, _run: VerifierRun<'_>) -> Result<RunExit, ScenarioError> {
            self.started += 1;
            std::thread::sleep(Duration::from_millis(1100));
            Err(ScenarioError::Runner("x".repeat(64 * 1024)))
        }
    }
    let mut value = document();
    value["limits"]["wall_clock_secs"] = serde_json::json!(1);
    value["checks"] = serde_json::json!(
        (0..5)
            .map(|i| serde_json::json!({
                "kind": "command", "name": format!("c{i}"), "argv": ["grade"], "exit_code": 0
            }))
            .collect::<Vec<_>>()
    );
    let (_root, layout, scenario) = layout(value);
    let scratch = TempDir::new().unwrap();
    let mut runner = SlowRunner { started: 0 };
    let report = run_scenario(
        &layout,
        &scenario,
        BUNDLE,
        &mut runner,
        &options(&scratch, 1),
    )
    .unwrap();
    // The first verifier spends the whole shared clock; no other one starts.
    assert_eq!(runner.started, 1);
    let run = &report.runs[0];
    assert_eq!(run.checks.len(), 5);
    for check in &run.checks {
        let CheckOutcome::Failed(reason) = &check.outcome else {
            panic!("{check:?}");
        };
        assert!(reason.len() <= MAX_REASON_BYTES + 3, "{}", reason.len());
    }
}
