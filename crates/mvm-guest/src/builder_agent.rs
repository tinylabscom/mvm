use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Incoming request from host to the builder agent (guest side, via vsock/serial).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BuilderRequest {
    /// Build a flake attribute with an optional timeout (seconds).
    Build {
        flake_ref: String,
        attr: String,
        timeout_secs: Option<u64>,
    },
    /// Health probe.
    Ping,
}

/// Outgoing responses/log frames from the builder agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BuilderResponse {
    /// Build succeeded; artifact root placed in /build-out.
    Ok { out_path: String },
    /// Build failed.
    Err { message: String },
    /// Streaming log line (stdout/stderr).
    Log { line: String },
    /// Pong for health probes.
    Pong,
}

fn log_frame(line: &str) -> BuilderResponse {
    BuilderResponse::Log {
        line: line.to_string(),
    }
}

/// Run the requested build using nix inside the guest and stage artifacts into /build-out.
pub fn handle_request(req: BuilderRequest) -> Result<BuilderResponse> {
    match req {
        BuilderRequest::Ping => Ok(BuilderResponse::Pong),
        BuilderRequest::Build {
            flake_ref,
            attr,
            timeout_secs,
        } => {
            let timeout = timeout_secs.unwrap_or(1800);

            let out_mount = Path::new("/build-out");
            if !out_mount.is_dir() {
                return Ok(BuilderResponse::Err {
                    message: "/build-out missing or not a directory".into(),
                });
            }
            // Best-effort mount of /dev/vdb -> /build-out if not already mounted.
            if Command::new("sh")
                .arg("-c")
                .arg("mountpoint -q /build-out || (mkdir -p /build-out && mount /dev/vdb /build-out)")
                .status()
                .is_err()
            {
                // continue; the copy will fail and report
            }
            if flake_ref == "/build-in" {
                let _ = Command::new("sh").arg("-c").arg(
                    "mountpoint -q /build-in || (mkdir -p /build-in && mount /dev/vdc /build-in)",
                ).status();
            }

            // nix build
            let build_cmd = format!(
                "timeout {} nix build {}#{} --no-link --print-out-paths",
                timeout, flake_ref, attr
            );
            let output = Command::new("sh")
                .arg("-c")
                .arg(&build_cmd)
                .output()
                .with_context(|| "failed to run nix build")?;

            // Emit stdout/stderr as log frames (best-effort)
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let _ = log_frame(line);
            }
            for line in String::from_utf8_lossy(&output.stderr).lines() {
                let _ = log_frame(line);
            }

            if !output.status.success() {
                return Ok(BuilderResponse::Err {
                    message: format!("nix build failed (exit {}): {}", output.status, build_cmd),
                });
            }

            // Last store path from stdout
            let stdout = String::from_utf8_lossy(&output.stdout);
            let out_path = stdout
                .lines()
                .rev()
                .find(|l| l.starts_with("/nix/store/"))
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("nix build produced no store path"))?;

            // Copy artifacts to /build-out
            let copy_cmd = format!(
                "set -euo pipefail; \
                 cp {p}/kernel /build-out/vmlinux 2>/dev/null || cp {p}/vmlinux /build-out/vmlinux; \
                 cp {p}/rootfs /build-out/rootfs.ext4 2>/dev/null || cp {p}/rootfs.ext4 /build-out/rootfs.ext4; \
                 echo '{{\"note\":\"Base fc config placeholder\"}}' > /build-out/fc-base.json",
                p = out_path
            );
            let copy_out = Command::new("sh")
                .arg("-c")
                .arg(&copy_cmd)
                .output()
                .with_context(|| "failed to copy build artifacts")?;
            if !copy_out.status.success() {
                return Ok(BuilderResponse::Err {
                    message: format!("failed to copy artifacts: exit {}", copy_out.status),
                });
            }

            Ok(BuilderResponse::Ok { out_path })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let req = BuilderRequest::Build {
            flake_ref: ".".into(),
            attr: "packages.aarch64-linux.tenant-worker".into(),
            timeout_secs: Some(123),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: BuilderRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }
}
