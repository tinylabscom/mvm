//! The versioned contract between `mvmctl` and the builder guest for one job.
//!
//! A builder boot carries two contracts. The builder boot ABI
//! ([`crate::builder_boot::abi`]) says which images a boot payload can boot.
//! This one says what a staged job directory means to the guest that runs it,
//! and what that guest writes back.
//!
//! **Request.** Every job directory the host stages carries
//! [`CONTRACT_MARKER`], holding [`BUILDER_JOB_CONTRACT_VERSION`] as decimal
//! text. Before it runs anything in that directory, `mvm-host-vm-init` reads
//! the marker through [`check_job_dir`] and refuses a directory without one,
//! with a malformed one, or with a version it does not speak. The refusal is a
//! [`JobOutcome`] whose failure is [`FailureCategory::Version`] and whose tail
//! names both versions, so the host reports it like any other failed job.
//!
//! **Result.** The guest writes [`RESULT_FILE`] as a [`JobOutcome`]: the
//! contract version it speaks, the job's exit code, a bounded stderr tail, a
//! [`FailureCategory`] when the job failed, and how long the job ran. The host
//! parses it with unknown fields denied and refuses an outcome stamped with
//! another version through [`JobOutcome::check_version`].
//!
//! The policy is exact match, the same as the typed `mvm-builderd` handshake
//! ([`crate::builderd_protocol::negotiate`]). The guest's binaries normally
//! come from the boot payload of the very `mvmctl` that staged the job, so the
//! two sides agree by construction. The check is for the boots where they do
//! not: a builder image booted without a payload runs the init it bakes, and
//! that init may predate this contract or postdate it.
//!
//! The guest writes the outcome with a hand-rolled renderer rather than
//! `serde_json`, to keep its size budget; the renderer's test parses its
//! output with [`JobOutcome`] so the two sides cannot drift apart.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::builderd_protocol::FailureCategory;

/// The job contract version this build stages and accepts. Bumped on any
/// change to what a job directory carries or to [`JobOutcome`]'s shape.
pub const BUILDER_JOB_CONTRACT_VERSION: u32 = 1;

/// The file in a job directory holding the contract version it was staged
/// under.
pub const CONTRACT_MARKER: &str = "contract-version";

/// The file the guest writes a [`JobOutcome`] to, in the job directory and
/// mirrored into the output directory.
pub const RESULT_FILE: &str = "result";

/// The guest's capture of the build's stderr, beside [`RESULT_FILE`].
pub const NIX_STDERR_LOG: &str = "nix-stderr.log";

/// The guest's capture of the build's stdout, beside [`RESULT_FILE`].
pub const NIX_STDOUT_LOG: &str = "nix-stdout.log";

/// The guest's boot phase timings, beside [`RESULT_FILE`].
pub const BOOT_TIMINGS_FILE: &str = "boot-timings.json";

/// The most stderr a [`JobOutcome`] carries. The full log stays in
/// [`NIX_STDERR_LOG`]; the tail is what fits in an error message.
pub const STDERR_TAIL_MAX_BYTES: usize = 4096;

/// How much of [`NIX_STDERR_LOG`]'s end the guest reads to classify a failure.
/// Nix prints the error that stopped it last, so the end is where the cause is.
pub const CLASSIFY_WINDOW_BYTES: usize = 16 * 1024;

/// Why a job directory or an outcome was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JobContractError {
    #[error(
        "the job directory carries no {CONTRACT_MARKER}; it was staged by a host that \
         predates builder job contract {BUILDER_JOB_CONTRACT_VERSION}"
    )]
    Missing,
    #[error("the job directory's {CONTRACT_MARKER} holds {contents:?}, which is not a number")]
    Malformed { contents: String },
    #[error(
        "the job was staged under builder job contract {staged}, and this builder speaks \
         {BUILDER_JOB_CONTRACT_VERSION}; run the build with an mvmctl and builder image of \
         the same release"
    )]
    Unsupported { staged: u32 },
    #[error(
        "the builder guest answered under builder job contract {reported}, and this mvmctl \
         speaks {BUILDER_JOB_CONTRACT_VERSION}; the builder image runs an init from another \
         release, so rebuild or refetch it, or boot it with this mvmctl's boot payload"
    )]
    OutcomeVersion { reported: u32 },
    #[error(
        "the builder guest answered without a contract version; its init predates builder \
         job contract {BUILDER_JOB_CONTRACT_VERSION}, so rebuild or refetch the builder \
         image, or boot it with this mvmctl's boot payload"
    )]
    OutcomePredatesContract,
    #[error(
        "the builder guest's outcome is not a contract {BUILDER_JOB_CONTRACT_VERSION} outcome: {detail}"
    )]
    OutcomeMalformed { detail: String },
}

/// Stamp `job_dir` with this build's contract version.
pub fn write_marker(job_dir: &Path) -> std::io::Result<()> {
    std::fs::write(
        job_dir.join(CONTRACT_MARKER),
        format!("{BUILDER_JOB_CONTRACT_VERSION}\n"),
    )
}

/// Decide a job directory's marker, given its contents. `None` is a directory
/// without one.
pub fn check_marker(contents: Option<&str>) -> Result<(), JobContractError> {
    let contents = contents.ok_or(JobContractError::Missing)?;
    let staged = contents
        .trim()
        .parse::<u32>()
        .map_err(|_| JobContractError::Malformed {
            contents: contents.to_string(),
        })?;
    if staged == BUILDER_JOB_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(JobContractError::Unsupported { staged })
    }
}

/// Read and decide `job_dir`'s marker. An unreadable marker is a missing one.
pub fn check_job_dir(job_dir: &Path) -> Result<(), JobContractError> {
    let contents = std::fs::read_to_string(job_dir.join(CONTRACT_MARKER)).ok();
    check_marker(contents.as_deref())
}

/// What the guest reports for one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobOutcome {
    /// The contract version the reporting guest speaks.
    pub contract_version: u32,
    /// The job's exit code. Zero is success.
    pub exit_code: i32,
    /// The end of the job's stderr, at most [`STDERR_TAIL_MAX_BYTES`].
    pub stderr_tail: String,
    /// Why the job failed. `None` exactly when it succeeded.
    pub failure: Option<FailureCategory>,
    /// How long the job ran. `None` when it never started.
    pub build_ms: Option<u64>,
}

impl JobOutcome {
    /// Refuse an outcome from a guest that speaks another contract version.
    pub fn check_version(&self) -> Result<(), JobContractError> {
        if self.contract_version == BUILDER_JOB_CONTRACT_VERSION {
            Ok(())
        } else {
            Err(JobContractError::OutcomeVersion {
                reported: self.contract_version,
            })
        }
    }

    /// The category a failed outcome reports, or [`FailureCategory::Unknown`]
    /// for a non-zero exit that came with none.
    pub fn failure_category(&self) -> Option<FailureCategory> {
        match (self.exit_code, self.failure) {
            (0, None) => None,
            (_, Some(category)) => Some(category),
            (_, None) => Some(FailureCategory::Unknown),
        }
    }
}

/// Parse a guest's [`RESULT_FILE`].
///
/// The version is read before the shape is checked, so an outcome from
/// another release is refused for its version rather than for a field this
/// build does not know.
pub fn parse_outcome(body: &str) -> Result<JobOutcome, JobContractError> {
    let malformed = |detail: String| JobContractError::OutcomeMalformed { detail };
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| malformed(e.to_string()))?;
    let reported = match value.get("contract_version") {
        None => return Err(JobContractError::OutcomePredatesContract),
        Some(version) => version
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| malformed(format!("contract_version is {version}")))?,
    };
    if reported != BUILDER_JOB_CONTRACT_VERSION {
        return Err(JobContractError::OutcomeVersion { reported });
    }
    serde_json::from_value(value).map_err(|e| malformed(e.to_string()))
}

/// The last [`STDERR_TAIL_MAX_BYTES`] of `text`, cut on a character boundary.
pub fn bounded_tail(text: &str) -> &str {
    tail_bytes(text, STDERR_TAIL_MAX_BYTES)
}

/// The last `max` bytes of `text`, cut forward to the next character boundary.
pub fn tail_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Substrings that mean an input could not be fetched. Checked first: a fetch
/// that fails inside a fixed-output derivation is also reported as a failed
/// builder, and the fetch is the cause.
const FETCH_MARKERS: &[&str] = &[
    "unable to download",
    "could not resolve host",
    "couldn't resolve host",
    "temporary failure in name resolution",
    "failed to connect to",
    "connection refused",
    "network is unreachable",
    "timeout was reached",
    "unable to fetch",
    "failed to fetch",
    "cannot fetch",
];

/// Substrings that mean a derivation ran and failed.
const BUILD_MARKERS: &[&str] = &["builder for '", "cannot build '", "build of '"];

/// Substrings that mean evaluation failed before anything was built.
const EVAL_MARKERS: &[&str] = &[
    "while evaluating",
    "error: attribute '",
    "does not provide attribute",
    "undefined variable",
    "syntax error",
    "infinite recursion",
    "evaluation aborted",
    "cannot coerce",
    "assertion '",
];

/// Classify a failed Nix invocation by its stderr.
///
/// Lines Nix prints as warnings are skipped: an unreachable substituter is a
/// warning, after which Nix builds from source, and the build is what decides
/// the outcome. A log that matches nothing is [`FailureCategory::Unknown`].
pub fn classify_nix_failure(stderr: &str) -> FailureCategory {
    let lines: Vec<String> = stderr
        .lines()
        .map(|line| line.trim().to_ascii_lowercase())
        .filter(|line| !line.starts_with("warning:"))
        .collect();
    let any = |markers: &[&str]| {
        lines
            .iter()
            .any(|line| markers.iter().any(|marker| line.contains(marker)))
    };
    if any(FETCH_MARKERS) {
        FailureCategory::Fetch
    } else if any(BUILD_MARKERS) {
        FailureCategory::NixBuild
    } else if any(EVAL_MARKERS) {
        FailureCategory::NixEval
    } else {
        FailureCategory::Unknown
    }
}

/// Classify a failed job: by the build's own stderr first, since that is where
/// Nix reports, and by the job script's stderr tail when the build log names
/// nothing or never got written.
pub fn classify_job_failure(nix_stderr: Option<&str>, script_tail: &str) -> FailureCategory {
    match nix_stderr.map(classify_nix_failure) {
        Some(FailureCategory::Unknown) | None => classify_nix_failure(script_tail),
        Some(category) => category,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(exit_code: i32, failure: Option<FailureCategory>) -> JobOutcome {
        JobOutcome {
            contract_version: BUILDER_JOB_CONTRACT_VERSION,
            exit_code,
            stderr_tail: "tail".to_string(),
            failure,
            build_ms: Some(12),
        }
    }

    #[test]
    fn a_staged_directory_passes_its_own_check() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path()).unwrap();
        check_job_dir(dir.path()).unwrap();
    }

    #[test]
    fn a_directory_without_a_marker_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_job_dir(dir.path()), Err(JobContractError::Missing));
    }

    #[test]
    fn another_version_is_refused_naming_both() {
        let err = check_marker(Some("2\n")).unwrap_err();
        assert_eq!(err, JobContractError::Unsupported { staged: 2 });
        let message = err.to_string();
        assert!(message.contains("contract 2"), "{message}");
        assert!(
            message.contains(&format!("speaks {BUILDER_JOB_CONTRACT_VERSION}")),
            "{message}"
        );
    }

    #[test]
    fn a_malformed_marker_is_refused() {
        assert!(matches!(
            check_marker(Some("one")),
            Err(JobContractError::Malformed { .. })
        ));
        assert!(matches!(
            check_marker(Some("")),
            Err(JobContractError::Malformed { .. })
        ));
    }

    #[test]
    fn the_outcome_round_trips_through_serde() {
        let original = outcome(1, Some(FailureCategory::NixEval));
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(serde_json::from_str::<JobOutcome>(&json).unwrap(), original);
    }

    #[test]
    fn an_outcome_with_an_unknown_field_is_refused() {
        let json = r#"{"contract_version":1,"exit_code":0,"stderr_tail":"","failure":null,
            "build_ms":null,"extra":true}"#;
        assert!(serde_json::from_str::<JobOutcome>(json).is_err());
    }

    #[test]
    fn a_pre_contract_outcome_is_refused_as_such() {
        // The shape the guest wrote before the contract existed.
        assert_eq!(
            parse_outcome(r#"{"exit_code":0,"stderr_tail":""}"#),
            Err(JobContractError::OutcomePredatesContract)
        );
    }

    #[test]
    fn a_newer_outcome_is_refused_for_its_version_not_its_fields() {
        let body = r#"{"contract_version":2,"exit_code":0,"stderr_tail":"","failure":null,
            "build_ms":null,"phases":[]}"#;
        assert_eq!(
            parse_outcome(body),
            Err(JobContractError::OutcomeVersion { reported: 2 })
        );
    }

    #[test]
    fn parse_outcome_accepts_its_own_version_and_refuses_garbage() {
        let original = outcome(0, None);
        let body = serde_json::to_string(&original).unwrap();
        assert_eq!(parse_outcome(&body).unwrap(), original);
        assert!(matches!(
            parse_outcome("{not json"),
            Err(JobContractError::OutcomeMalformed { .. })
        ));
        assert!(matches!(
            parse_outcome(r#"{"contract_version":"1"}"#),
            Err(JobContractError::OutcomeMalformed { .. })
        ));
    }

    #[test]
    fn an_outcome_from_another_version_is_refused() {
        let mut other = outcome(0, None);
        other.contract_version = BUILDER_JOB_CONTRACT_VERSION + 1;
        assert!(matches!(
            other.check_version(),
            Err(JobContractError::OutcomeVersion { .. })
        ));
        outcome(0, None).check_version().unwrap();
    }

    #[test]
    fn a_failure_without_a_category_reads_as_unknown() {
        assert_eq!(outcome(0, None).failure_category(), None);
        assert_eq!(
            outcome(3, None).failure_category(),
            Some(FailureCategory::Unknown)
        );
        assert_eq!(
            outcome(3, Some(FailureCategory::Fetch)).failure_category(),
            Some(FailureCategory::Fetch)
        );
    }

    #[test]
    fn the_tail_is_bounded_on_a_character_boundary() {
        let long = format!("{}é", "a".repeat(STDERR_TAIL_MAX_BYTES));
        let tail = bounded_tail(&long);
        assert!(tail.len() <= STDERR_TAIL_MAX_BYTES);
        assert!(tail.ends_with('é'));
        assert_eq!(bounded_tail("short"), "short");
        // A cut that lands inside a multi-byte character moves forward.
        assert_eq!(tail_bytes("éé", 3), "é");
    }

    #[test]
    fn evaluation_errors_classify_as_eval() {
        let log = "error:\n       … while evaluating the attribute 'packages'\n\
                   error: attribute 'defualt' missing";
        assert_eq!(classify_nix_failure(log), FailureCategory::NixEval);
        assert_eq!(
            classify_nix_failure("error: flake 'path:/work' does not provide attribute 'x'"),
            FailureCategory::NixEval
        );
    }

    #[test]
    fn a_failed_derivation_classifies_as_build() {
        let log = "error: builder for '/nix/store/abc-guest.drv' failed with exit code 2;\n\
                   last 10 log lines:\n> make: *** [all] Error 1";
        assert_eq!(classify_nix_failure(log), FailureCategory::NixBuild);
    }

    #[test]
    fn a_failed_download_classifies_as_fetch_even_inside_a_builder() {
        let log = "error: builder for '/nix/store/abc-source.drv' failed with exit code 1;\n\
                   > curl: (6) Could not resolve host: example.invalid";
        assert_eq!(classify_nix_failure(log), FailureCategory::Fetch);
        assert_eq!(
            classify_nix_failure("error: unable to download 'https://example.invalid/x': HTTP 404"),
            FailureCategory::Fetch
        );
    }

    #[test]
    fn substituter_warnings_do_not_make_a_build_failure_a_fetch() {
        let log = "warning: unable to download 'https://cache.nixos.org/x.narinfo'\n\
                   error: builder for '/nix/store/abc.drv' failed with exit code 1";
        assert_eq!(classify_nix_failure(log), FailureCategory::NixBuild);
    }

    #[test]
    fn a_job_is_classified_by_its_build_log_before_its_script_tail() {
        assert_eq!(
            classify_job_failure(
                Some("error: builder for '/nix/store/a.drv' failed"),
                "error: attribute 'x' missing"
            ),
            FailureCategory::NixBuild
        );
        assert_eq!(
            classify_job_failure(Some("nothing useful"), "error: attribute 'x' missing"),
            FailureCategory::NixEval
        );
        assert_eq!(
            classify_job_failure(None, "unable to download 'https://x'"),
            FailureCategory::Fetch
        );
        assert_eq!(classify_job_failure(None, ""), FailureCategory::Unknown);
    }

    #[test]
    fn an_unrecognized_log_is_unknown() {
        assert_eq!(classify_nix_failure(""), FailureCategory::Unknown);
        assert_eq!(
            classify_nix_failure("cp: cannot stat '/out/x'"),
            FailureCategory::Unknown
        );
    }
}
