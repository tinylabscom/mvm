//! Verification runners for captured workloads.
//!
//! The default `RecordOnlyVerifier` captures the verification command without
//! executing it. `BuilderVmVerifier` dispatches a builder-VM shell job to
//! build the rendered flake; `BootReplayVerifier` boots a microVM inside the
//! builder VM and replays the command as the guest entrypoint. Both require
//! `mvmctl __builder-shell-job` and a usable Linux builder VM.

use crate::CaptureError;
use crate::report::{VerificationRecord, VerificationStatus};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A request to verify a captured workload by replaying a command.
#[derive(Clone, Debug)]
pub struct VerificationRequest {
    pub command: Vec<String>,
}

/// Abstraction over ways to verify a workload.
pub trait Verifier {
    /// Run or record the requested verification.
    fn verify(&self, request: &VerificationRequest) -> Result<VerificationRecord, CaptureError>;
}

/// Records the verification command as pending without executing anything.
pub struct RecordOnlyVerifier;

impl Verifier for RecordOnlyVerifier {
    fn verify(&self, request: &VerificationRequest) -> Result<VerificationRecord, CaptureError> {
        Ok(VerificationRecord {
            command: request.command.clone(),
            status: VerificationStatus::Recorded,
            exit_code: None,
            stdout: None,
            stderr: None,
        })
    }
}

/// Shared configuration for builder-VM verifiers.
#[derive(Clone, Debug)]
pub struct BuilderVmConfig {
    /// Host directory containing the rendered `flake.nix` (bound read-only at
    /// `/work` inside the builder VM).
    pub work_dir: PathBuf,
    /// Optional path to the `mvmctl` binary. If omitted, `mvmctl` is resolved
    /// from `PATH`.
    pub mvmctl_path: Option<PathBuf>,
}

impl BuilderVmConfig {
    /// Check whether `mvmctl __builder-shell-job` is available on the host.
    pub fn is_available(&self) -> bool {
        let bin = self
            .mvmctl_path
            .as_deref()
            .unwrap_or_else(|| Path::new("mvmctl"));
        which::which(bin).is_ok()
    }

    fn mvmctl(&self) -> PathBuf {
        self.mvmctl_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("mvmctl"))
    }
}

/// Verifies by building the rendered flake inside the Linux builder VM.
pub struct BuilderVmVerifier {
    pub config: BuilderVmConfig,
}

impl Verifier for BuilderVmVerifier {
    fn verify(&self, request: &VerificationRequest) -> Result<VerificationRecord, CaptureError> {
        require_non_empty(request)?;

        let script = build_flake_build_script();
        let outcome = run_builder_shell_job(&self.config, &script)?;

        if !outcome.success {
            return Ok(VerificationRecord {
                command: request.command.clone(),
                status: VerificationStatus::Failed {
                    reason: format!(
                        "__builder-shell-job exited with status {}",
                        outcome.status_string()
                    ),
                },
                exit_code: outcome.exit_code(),
                stdout: Some(outcome.stdout),
                stderr: Some(outcome.stderr),
            });
        }

        let build_exit_code = read_exit_code(&outcome.artifact_out, "build_exit_code");
        let build_log = read_optional_file(&outcome.artifact_out, "build.log");

        let status = match build_exit_code {
            Some(0) => VerificationStatus::Built,
            Some(code) => VerificationStatus::Failed {
                reason: format!("nix build exited with code {}", code),
            },
            None => VerificationStatus::Failed {
                reason: "builder job did not write build_exit_code".to_owned(),
            },
        };

        Ok(VerificationRecord {
            command: request.command.clone(),
            status,
            exit_code: build_exit_code,
            stdout: build_log.clone(),
            stderr: build_log,
        })
    }
}

/// Verifies by booting a microVM inside the builder VM and replaying the
/// command as the guest entrypoint.
pub struct BootReplayVerifier {
    pub config: BuilderVmConfig,
    /// Wall-clock timeout for the guest replay, in seconds.
    pub max_seconds: u64,
}

impl Verifier for BootReplayVerifier {
    fn verify(&self, request: &VerificationRequest) -> Result<VerificationRecord, CaptureError> {
        require_non_empty(request)?;

        let script = build_boot_replay_script(&request.command, self.max_seconds);
        let outcome = run_builder_shell_job(&self.config, &script)?;

        if !outcome.success {
            return Ok(VerificationRecord {
                command: request.command.clone(),
                status: VerificationStatus::Failed {
                    reason: format!(
                        "__builder-shell-job exited with status {}",
                        outcome.status_string()
                    ),
                },
                exit_code: outcome.exit_code(),
                stdout: Some(outcome.stdout),
                stderr: Some(outcome.stderr),
            });
        }

        let run_exit_code = read_exit_code(&outcome.artifact_out, "run_exit_code");
        let run_log = read_optional_file(&outcome.artifact_out, "run.log");

        let status = match run_exit_code {
            Some(0) => VerificationStatus::Replayed,
            Some(code) => VerificationStatus::Failed {
                reason: format!("guest command exited with code {}", code),
            },
            None => VerificationStatus::Failed {
                reason: "builder job did not write run_exit_code".to_owned(),
            },
        };

        Ok(VerificationRecord {
            command: request.command.clone(),
            status,
            exit_code: run_exit_code,
            stdout: run_log.clone(),
            stderr: run_log,
        })
    }
}

fn require_non_empty(request: &VerificationRequest) -> Result<(), CaptureError> {
    if request.command.is_empty() {
        return Err(CaptureError::InvalidObservation(
            "empty verification command".to_owned(),
        ));
    }
    Ok(())
}

struct BuilderJobOutcome {
    artifact_out: PathBuf,
    stdout: String,
    stderr: String,
    success: bool,
    status_code: Option<i32>,
}

impl BuilderJobOutcome {
    fn exit_code(&self) -> Option<i32> {
        self.status_code
    }

    fn status_string(&self) -> String {
        match self.status_code {
            Some(code) => code.to_string(),
            None => "unknown".to_owned(),
        }
    }
}

fn run_builder_shell_job(
    config: &BuilderVmConfig,
    script: &str,
) -> Result<BuilderJobOutcome, CaptureError> {
    let script_path = write_temp_script(script)?;
    let artifact_out = tempfile::tempdir()
        .map_err(|e| CaptureError::Io(PathBuf::from("<verify-artifacts>"), e))?
        .keep();

    let bin = config.mvmctl();
    let output = Command::new(&bin)
        .arg("__builder-shell-job")
        .arg("--script")
        .arg(&script_path)
        .arg("--work-dir")
        .arg(&config.work_dir)
        .arg("--artifact-out")
        .arg(&artifact_out)
        .output()
        .map_err(|e| CaptureError::Io(bin.clone(), e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    Ok(BuilderJobOutcome {
        artifact_out,
        stdout,
        stderr,
        success: output.status.success(),
        status_code: output.status.code(),
    })
}

fn read_exit_code(dir: &Path, name: &str) -> Option<i32> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn read_optional_file(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name)).ok()
}

fn build_flake_build_script() -> String {
    r#"#!/bin/bash
set -uo pipefail
mkdir -p /out
cd /work
nix build .#default --extra-experimental-features 'nix-command flakes' > /out/build.log 2>&1
echo $? > /out/build_exit_code
"#
    .to_owned()
}

fn build_boot_replay_script(command: &[String], max_seconds: u64) -> String {
    let escaped = shell_join(command);
    format!(
        r#"#!/bin/bash
set -uo pipefail
mkdir -p /out
MVM_HOME=/tmp/mvm-capture-verify-home
export MVM_HOME
rm -rf "$MVM_HOME"
mkdir -p "$MVM_HOME"
cd /work
mvmctl --home "$MVM_HOME" bootstrap > /out/bootstrap.log 2>&1 || true
mvmctl --home "$MVM_HOME" machine run --flake path:/work#default --timeout {max_seconds} -- /bin/sh -c {escaped} > /out/run.log 2>&1
echo $? > /out/run_exit_code
"#
    )
}

/// Join shell words with single-quote escaping.
fn shell_join(words: &[String]) -> String {
    words
        .iter()
        .map(|w| {
            if w.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-./=:@".contains(c))
            {
                w.clone()
            } else {
                format!("'{}'", w.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn write_temp_script(script: &str) -> Result<PathBuf, CaptureError> {
    let dir =
        tempfile::tempdir().map_err(|e| CaptureError::Io(PathBuf::from("<script-tmp>"), e))?;
    let path = dir.keep();
    let script_path = path.join("verify.sh");
    std::fs::write(&script_path, script).map_err(|e| CaptureError::Io(script_path.clone(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .map_err(|e| CaptureError::Io(script_path.clone(), e))?
            .permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(&script_path, perms)
            .map_err(|e| CaptureError::Io(script_path.clone(), e))?;
    }
    Ok(script_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_only_verifier_records_command() {
        let verifier = RecordOnlyVerifier;
        let request = VerificationRequest {
            command: vec!["cargo".to_owned(), "test".to_owned()],
        };
        let record = verifier.verify(&request).expect("verify succeeds");
        assert_eq!(record.command, request.command);
        assert_eq!(record.status, VerificationStatus::Recorded);
        assert!(record.exit_code.is_none());
    }

    #[test]
    fn build_script_contains_nix_build() {
        let script = build_flake_build_script();
        assert!(script.contains("nix build .#default"));
        assert!(script.contains("build_exit_code"));
    }

    #[test]
    fn boot_replay_script_contains_machine_run() {
        let script = build_boot_replay_script(&["cargo".to_owned(), "test".to_owned()], 30);
        assert!(script.contains("mvmctl --home \"$MVM_HOME\" machine run"));
        assert!(script.contains("path:/work#default"));
        assert!(script.contains("run_exit_code"));
        assert!(script.contains("cargo test"));
    }

    #[test]
    fn shell_join_escapes_special_characters() {
        assert_eq!(
            shell_join(&["echo".to_owned(), "a'b".to_owned()]),
            "echo 'a'\"'\"'b'"
        );
    }
}
