//! Host side of an optional pack scenario: bind, stage, run fresh, collect,
//! grade.
//!
//! A [`PackScenario`] names the exact environment archive it was written for.
//! [`run_scenario`] refuses any other archive before anything runs, then gives
//! every run a workspace created empty for that run alone, stages the
//! scenario's public files into it, runs the workload through a
//! [`ScenarioRunner`], collects only the declared outputs under the
//! scenario's byte and file bounds, and grades them. The workspace is deleted
//! before the next run starts, so no state carries from one run to the next.
//!
//! Expected answers stay on the host. The workload's request carries the
//! workspace and the instructions and nothing else, so a runner cannot hand
//! `private/` to the workload even by mistake. File and JSON checks compare
//! collected copies against `private/` here. A command check runs in a
//! separate verifier instance that the runner starts after the workload's
//! has gone, and only that instance sees `private/`.
//!
//! Every path is walked component by component with `symlink_metadata`: a
//! symlink anywhere under `public/` or under a collected output is refused
//! rather than followed, so neither staging nor collection can read outside
//! its tree. Both are bounded while they read: bytes, entries (directories
//! included) and nesting depth, so an oversized tree is refused without being
//! read past its bound. A refused collection fails that run; it does not stop
//! the remaining runs. Every command check of one run shares a single wall
//! clock, so the number of checks cannot multiply grading time.

mod fs;
mod grade;

#[cfg(test)]
mod tests;

pub use fs::{Collected, MAX_TREE_DEPTH, collect_outputs, stage_workspace};
pub use grade::{CheckOutcome, CheckResult, MAX_REASON_BYTES, grade_collected};

use mvm_contract::pack_scenario::{PackScenario, ScenarioCheck};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Largest scenario document [`ScenarioLayout::open`] reads.
pub const MAX_SCENARIO_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    #[error(
        "scenario {scenario} is bound to environment archive {expected}, not {actual}; \
         run it against the archive it was written for"
    )]
    EnvironmentMismatch {
        scenario: String,
        expected: String,
        actual: String,
    },
    #[error("invalid scenario document: {0}")]
    Document(String),
    #[error("{path:?} escapes its tree: {reason}")]
    PathEscape { path: String, reason: &'static str },
    #[error("{tree} exceed the limit of {limit} {unit}")]
    Limit {
        tree: &'static str,
        limit: u64,
        unit: &'static str,
    },
    #[error("the workspace for a fresh run must be an existing empty directory: {}", .0.display())]
    WorkspaceNotFresh(PathBuf),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("runner failed: {0}")]
    Runner(String),
}

impl ScenarioError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// A scenario directory: `scenario.json`, `public/`, and `private/`.
#[derive(Debug, Clone)]
pub struct ScenarioLayout {
    root: PathBuf,
}

impl ScenarioLayout {
    /// Open and validate a scenario directory. `public/` and `private/` must be
    /// real directories (an absent `private/` is allowed when nothing reads
    /// it); a symlinked tree is refused.
    pub fn open(root: &Path) -> Result<(Self, PackScenario), ScenarioError> {
        let layout = Self {
            root: root.to_path_buf(),
        };
        let document = layout.root.join("scenario.json");
        let bytes = fs::read_bounded(&document, MAX_SCENARIO_BYTES)?;
        let scenario: PackScenario =
            serde_json::from_slice(&bytes).map_err(|e| ScenarioError::Document(e.to_string()))?;
        fs::require_real_dir(&layout.public_dir(), "public")?;
        let reads_private = scenario
            .checks
            .iter()
            .any(|c| c.expected_path().is_some() || matches!(c, ScenarioCheck::Command { .. }));
        if reads_private {
            fs::require_real_dir(&layout.private_dir(), "private")?;
        }
        Ok((layout, scenario))
    }

    pub fn public_dir(&self) -> PathBuf {
        self.root.join("public")
    }

    pub fn private_dir(&self) -> PathBuf {
        self.root.join("private")
    }
}

/// Refuse a scenario run against any archive but the one it names.
pub fn check_environment(
    scenario: &PackScenario,
    bundle_sha256: &str,
) -> Result<(), ScenarioError> {
    if scenario.environment.bundle_sha256 == bundle_sha256 {
        Ok(())
    } else {
        Err(ScenarioError::EnvironmentMismatch {
            scenario: format!("{}@{}", scenario.name, scenario.version),
            expected: scenario.environment.bundle_sha256.clone(),
            actual: bundle_sha256.to_string(),
        })
    }
}

/// How a bounded run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum RunExit {
    Exited(i32),
    TimedOut,
}

/// What the workload's instance is given. There is deliberately no private
/// path here.
#[derive(Debug, Clone, Copy)]
pub struct WorkloadRun<'a> {
    pub bundle_sha256: &'a str,
    /// Fresh, staged workspace the instance works in.
    pub workspace: &'a Path,
    pub instructions: &'a str,
    pub wall_clock: Duration,
}

/// What a verifier instance is given, after the workload's has gone.
#[derive(Debug, Clone, Copy)]
pub struct VerifierRun<'a> {
    pub bundle_sha256: &'a str,
    /// Copies of the collected outputs, not the workload's workspace.
    pub outputs: &'a Path,
    pub private: &'a Path,
    pub argv: &'a [String],
    /// What is left of the wall clock every verifier of this run shares.
    pub wall_clock: Duration,
}

/// Starts fresh instances of the bound environment. An implementation must
/// stop each instance before returning and enforce `wall_clock` itself;
/// [`run_scenario`] additionally treats a return after the limit as a
/// timeout.
pub trait ScenarioRunner {
    fn run_workload(&mut self, run: WorkloadRun<'_>) -> Result<RunExit, ScenarioError>;
    fn run_verifier(&mut self, run: VerifierRun<'_>) -> Result<RunExit, ScenarioError>;
}

/// One fresh run's result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunReport {
    pub index: u32,
    pub exit: RunExit,
    /// Why the run could not be graded, when it could not.
    pub error: Option<String>,
    pub collected_bytes: u64,
    pub collected_files: u32,
    pub checks: Vec<CheckResult>,
}

impl RunReport {
    pub fn passed(&self) -> bool {
        self.error.is_none()
            && !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| c.outcome == CheckOutcome::Passed)
    }
}

/// Every run of one scenario against one archive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScenarioReport {
    pub scenario: String,
    pub scenario_sha256: String,
    pub bundle_sha256: String,
    pub runs: Vec<RunReport>,
}

impl ScenarioReport {
    pub fn passed(&self) -> bool {
        !self.runs.is_empty() && self.runs.iter().all(RunReport::passed)
    }
}

/// Where fresh runs are created, and how many there are.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Parent of each run's private scratch directory. Must exist.
    pub scratch: PathBuf,
    pub runs: u32,
}

/// Bind `scenario` to `bundle_sha256`, then perform `options.runs` fresh runs.
pub fn run_scenario<R: ScenarioRunner>(
    layout: &ScenarioLayout,
    scenario: &PackScenario,
    bundle_sha256: &str,
    runner: &mut R,
    options: &RunOptions,
) -> Result<ScenarioReport, ScenarioError> {
    scenario
        .validate()
        .map_err(|e| ScenarioError::Document(e.to_string()))?;
    check_environment(scenario, bundle_sha256)?;
    let scenario_sha256 = scenario
        .sha256()
        .map_err(|e| ScenarioError::Document(e.to_string()))?;
    let mut runs = Vec::with_capacity(options.runs as usize);
    for index in 0..options.runs {
        let scratch = tempfile::Builder::new()
            .prefix("scenario-run-")
            .tempdir_in(&options.scratch)
            .map_err(|e| ScenarioError::io("creating run scratch", e))?;
        runs.push(one_run(
            layout,
            scenario,
            bundle_sha256,
            runner,
            scratch.path(),
            index,
        )?);
        // Dropping the scratch removes the workspace and the collected copy
        // before the next run's are created.
        scratch
            .close()
            .map_err(|e| ScenarioError::io("removing run scratch", e))?;
    }
    Ok(ScenarioReport {
        scenario: format!("{}@{}", scenario.name, scenario.version),
        scenario_sha256,
        bundle_sha256: bundle_sha256.to_string(),
        runs,
    })
}

fn one_run<R: ScenarioRunner>(
    layout: &ScenarioLayout,
    scenario: &PackScenario,
    bundle_sha256: &str,
    runner: &mut R,
    scratch: &Path,
    index: u32,
) -> Result<RunReport, ScenarioError> {
    let workspace = scratch.join("workspace");
    let collected_dir = scratch.join("collected");
    for dir in [&workspace, &collected_dir] {
        std::fs::create_dir(dir).map_err(|e| ScenarioError::io("creating run directory", e))?;
    }
    stage_workspace(&layout.public_dir(), scenario, &workspace)?;
    let wall_clock = Duration::from_secs(u64::from(scenario.limits.wall_clock_secs));
    let exit = bounded(wall_clock, || {
        runner.run_workload(WorkloadRun {
            bundle_sha256,
            workspace: &workspace,
            instructions: &scenario.instructions,
            wall_clock,
        })
    })?;
    let mut report = RunReport {
        index,
        exit,
        error: None,
        collected_bytes: 0,
        collected_files: 0,
        checks: Vec::new(),
    };
    if exit == RunExit::TimedOut {
        report.error = Some(format!(
            "workload exceeded its {}s wall clock",
            scenario.limits.wall_clock_secs
        ));
        return Ok(report);
    }
    let collected = match collect_outputs(&workspace, scenario, &collected_dir) {
        Ok(collected) => collected,
        Err(error) => {
            report.error = Some(error.to_string());
            return Ok(report);
        }
    };
    report.collected_bytes = collected.bytes;
    report.collected_files = collected.files.len() as u32;
    // The workload's workspace is gone before any verifier starts.
    std::fs::remove_dir_all(&workspace)
        .map_err(|e| ScenarioError::io("removing the workload workspace", e))?;
    let grading = Deadline::start(wall_clock);
    report.checks = grade_collected(scenario, &collected, &layout.private_dir(), |argv| {
        let Some(wall_clock) = grading.remaining() else {
            return Ok(RunExit::TimedOut);
        };
        bounded(wall_clock, || {
            runner.run_verifier(VerifierRun {
                bundle_sha256,
                outputs: &collected.root,
                private: &layout.private_dir(),
                argv,
                wall_clock,
            })
        })
    });
    Ok(report)
}

/// One wall clock shared by every verifier of a run.
struct Deadline {
    started: Instant,
    limit: Duration,
}

impl Deadline {
    fn start(limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            limit,
        }
    }

    /// What is left, or `None` once it has run out: a verifier is not
    /// started with nothing left.
    fn remaining(&self) -> Option<Duration> {
        self.limit
            .checked_sub(self.started.elapsed())
            .filter(|left| !left.is_zero())
    }
}

/// Run `f`, reporting a timeout when it returns after `limit` whatever it
/// says.
fn bounded(
    limit: Duration,
    f: impl FnOnce() -> Result<RunExit, ScenarioError>,
) -> Result<RunExit, ScenarioError> {
    let started = Instant::now();
    let exit = f()?;
    Ok(if started.elapsed() > limit {
        RunExit::TimedOut
    } else {
        exit
    })
}
