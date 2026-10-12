//! Grading collected outputs against private expectations.

use super::fs::{Collected, read_bounded};
use super::{RunExit, ScenarioError};
use mvm_contract::pack_scenario::{PackScenario, ScenarioCheck};
use std::path::Path;

/// Largest private expectation a check reads.
const MAX_EXPECTED_BYTES: u64 = 64 * 1024 * 1024;

/// Longest failure reason a report carries. A runner's error text is not
/// ours to size, so it is cut here rather than copied whole into every report.
pub const MAX_REASON_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    /// The reason names what differed, never the expected value.
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CheckResult {
    pub name: String,
    pub outcome: CheckOutcome,
}

/// Grade every check in declaration order. `verify` runs a command check in a
/// verifier instance; file and JSON checks never start one.
pub fn grade_collected(
    scenario: &PackScenario,
    collected: &Collected,
    private: &Path,
    mut verify: impl FnMut(&[String]) -> Result<RunExit, ScenarioError>,
) -> Vec<CheckResult> {
    scenario
        .checks
        .iter()
        .map(|check| CheckResult {
            name: check.name().to_string(),
            outcome: match one(check, collected, private, &mut verify) {
                Ok(()) => CheckOutcome::Passed,
                Err(reason) => CheckOutcome::Failed(clip(reason)),
            },
        })
        .collect()
}

fn one(
    check: &ScenarioCheck,
    collected: &Collected,
    private: &Path,
    verify: &mut impl FnMut(&[String]) -> Result<RunExit, ScenarioError>,
) -> Result<(), String> {
    match check {
        ScenarioCheck::FileExists { path, .. } => {
            collected.file(path).map(drop).ok_or_else(|| missing(path))
        }
        ScenarioCheck::FileMatches { path, expected, .. } => {
            let actual = collected_bytes(collected, path)?;
            let expected = expected_bytes(private, expected)?;
            (actual == expected)
                .then_some(())
                .ok_or_else(|| format!("{path:?} differs from the expected file"))
        }
        ScenarioCheck::JsonMatches {
            path,
            pointer,
            expected,
            ..
        } => {
            let actual: serde_json::Value =
                serde_json::from_slice(&collected_bytes(collected, path)?)
                    .map_err(|_| format!("{path:?} is not valid JSON"))?;
            let expected: serde_json::Value =
                serde_json::from_slice(&expected_bytes(private, expected)?)
                    .map_err(|_| "the expected JSON is not valid JSON".to_string())?;
            let value = actual
                .pointer(pointer)
                .ok_or_else(|| format!("{path:?} has no value at {pointer:?}"))?;
            (value == &expected)
                .then_some(())
                .ok_or_else(|| format!("{path:?} at {pointer:?} differs from the expected value"))
        }
        ScenarioCheck::Command {
            argv, exit_code, ..
        } => match verify(argv) {
            Ok(RunExit::Exited(code)) if code == *exit_code => Ok(()),
            Ok(RunExit::Exited(code)) => {
                Err(format!("verifier exited {code}, expected {exit_code}"))
            }
            Ok(RunExit::TimedOut) => Err("verifier exceeded its wall clock".to_string()),
            Err(error) => Err(format!("verifier could not run: {error}")),
        },
    }
}

fn clip(mut reason: String) -> String {
    if reason.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
        reason.push_str("...");
    }
    reason
}

fn missing(path: &str) -> String {
    format!("{path:?} was not collected as a regular file")
}

fn collected_bytes(collected: &Collected, path: &str) -> Result<Vec<u8>, String> {
    let file = collected.file(path).ok_or_else(|| missing(path))?;
    read_bounded(&file, collected.byte_limit)
        .map_err(|e| format!("reading collected {path:?}: {e}"))
}

fn expected_bytes(private: &Path, relative: &str) -> Result<Vec<u8>, String> {
    // The private tree is authored by the scenario publisher, but it is still
    // walked without following symlinks so a check cannot read host files.
    let mut path = private.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("the expected file path contains a symbolic link".to_string());
        }
    }
    read_bounded(&path, MAX_EXPECTED_BYTES)
        .map_err(|_| "the expected file is missing or unreadable".to_string())
}
