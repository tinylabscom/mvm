//! The in-house-VMM builder's guest-side nix build.
//!
//! Runs `nix build` against the vsock-staged `/work` tree (with `/mvm-bins`
//! exposed as `MVM_HOST_BIN_DIR`) and stages the kernel + rootfs into a local dir
//! the [build session](crate::builder_session) streams back to the host. It is
//! the transport-free build core the builder server's `serve_build` closure runs.
//! Mirrors the legacy builder agent's nix invocation, but stages to a plain
//! directory instead of a `/dev/vdb` disk mount — the in-house VMM has no writable
//! host-shared disk, so artifacts go back over vsock.

use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;

use crate::builder_agent::{validate_build_attr, validate_flake_ref};
use crate::builder_session::{BuildOutcome, BuildProduct, BuildRequest, serve_build};

/// Default build timeout when the request leaves it unset (30 min).
const DEFAULT_TIMEOUT_SECS: u64 = 1800;

/// The shell command that builds `flake_ref#attr` and prints the store path.
/// `flake_ref`/`attr` are validated by [`run_nix_build`] before this is built, so
/// they carry no shell metacharacters.
pub fn nix_build_command(flake_ref: &str, attr: &str, timeout_secs: u64) -> String {
    format!("timeout {timeout_secs} nix build {flake_ref}#{attr} --no-link --print-out-paths")
}

/// The built output path — the last `/nix/store/...` line of nix's stdout.
pub fn extract_store_path(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .rev()
        .find(|l| l.starts_with("/nix/store/"))
        .map(str::to_string)
}

/// The shell command that copies the kernel + rootfs out of `store_path` into
/// `out_dir`, accepting either output naming (`kernel`/`vmlinux`,
/// `rootfs`/`rootfs.ext4`).
pub fn stage_command(store_path: &str, out_dir: &str) -> String {
    format!(
        "set -eu; \
         cp {s}/kernel {o}/vmlinux 2>/dev/null || cp {s}/vmlinux {o}/vmlinux; \
         cp {s}/rootfs {o}/rootfs.ext4 2>/dev/null || cp {s}/rootfs.ext4 {o}/rootfs.ext4",
        s = store_path,
        o = out_dir
    )
}

/// Run a build for one session: validate the inputs, `nix build` in `work` with
/// `MVM_HOST_BIN_DIR=mvm_bins`, stage the kernel + rootfs into `out_dir`, and
/// return a [`BuildProduct`]. Every failure (bad input, nix error, missing store
/// path, staging error) returns [`BuildOutcome::Failure`] with the captured logs
/// — never a panic, so the session always completes cleanly.
pub fn run_nix_build(
    work: &Path,
    mvm_bins: &Path,
    out_dir: &Path,
    req: &BuildRequest,
) -> BuildProduct {
    let mut logs = Vec::new();
    let fail = |logs: Vec<String>, message: String| BuildProduct {
        outcome: BuildOutcome::Failure { message },
        out_dir: std::path::PathBuf::new(),
        logs,
    };

    // Reuse the legacy agent's input validation (no shell metacharacters / no
    // path traversal) before the inputs reach a shell.
    if let Err(e) = validate_flake_ref(&req.flake_ref) {
        return fail(logs, format!("invalid flake_ref: {e}"));
    }
    if let Err(e) = validate_build_attr(&req.attr) {
        return fail(logs, format!("invalid attr: {e}"));
    }
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        return fail(logs, format!("create out dir: {e}"));
    }

    let timeout = req.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let build = nix_build_command(&req.flake_ref, &req.attr, timeout);
    let output = match Command::new("sh")
        .arg("-c")
        .arg(&build)
        .current_dir(work)
        .env("MVM_HOST_BIN_DIR", mvm_bins)
        .output()
    {
        Ok(o) => o,
        Err(e) => return fail(logs, format!("spawn nix build: {e}")),
    };
    capture_lines(&mut logs, &output.stdout);
    capture_lines(&mut logs, &output.stderr);

    if !output.status.success() {
        return fail(logs, format!("nix build failed (exit {})", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(store_path) = extract_store_path(&stdout) else {
        return fail(logs, "nix build produced no store path".into());
    };

    let stage = stage_command(&store_path, &out_dir.to_string_lossy());
    match Command::new("sh").arg("-c").arg(&stage).output() {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            capture_lines(&mut logs, &o.stderr);
            return fail(logs, format!("stage artifacts failed (exit {})", o.status));
        }
        Err(e) => return fail(logs, format!("spawn artifact staging: {e}")),
    }

    BuildProduct {
        outcome: BuildOutcome::Success,
        out_dir: out_dir.to_path_buf(),
        logs,
    }
}

fn capture_lines(logs: &mut Vec<String>, bytes: &[u8]) {
    for line in String::from_utf8_lossy(bytes).lines() {
        logs.push(line.to_string());
    }
}

/// Serve one builder session on `stream`: receive `/work` + `/mvm-bins` into the
/// given destinations, run the nix build into `out_dir`, and stream logs +
/// outcome (+ artifacts on success) back. The transport glue between
/// [`serve_build`] and [`run_nix_build`] the builder server's accept loop calls
/// per connection.
pub fn serve_builder_session<S: Read + Write>(
    stream: &mut S,
    work_dest: &Path,
    mvm_bins_dest: &Path,
    out_dir: &Path,
) -> anyhow::Result<()> {
    serve_build(stream, work_dest, mvm_bins_dest, |w, b, req| {
        run_nix_build(w, b, out_dir, req)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_build_command_is_well_formed() {
        let cmd = nix_build_command(".", "packages.aarch64-linux.default", 600);
        assert_eq!(
            cmd,
            "timeout 600 nix build .#packages.aarch64-linux.default --no-link --print-out-paths"
        );
    }

    #[test]
    fn extract_store_path_takes_the_last_store_line() {
        let stdout = "evaluating...\n\
                      /nix/store/aaa-first\n\
                      warning: x\n\
                      /nix/store/bbb-final\n";
        assert_eq!(
            extract_store_path(stdout),
            Some("/nix/store/bbb-final".to_string())
        );
    }

    #[test]
    fn extract_store_path_none_when_absent() {
        assert_eq!(extract_store_path("error: eval failed\n"), None);
    }

    #[test]
    fn stage_command_handles_both_artifact_namings() {
        let cmd = stage_command("/nix/store/xyz-out", "/tmp/o");
        // kernel→vmlinux with a vmlinux fallback.
        assert!(cmd.contains("cp /nix/store/xyz-out/kernel /tmp/o/vmlinux"));
        assert!(cmd.contains("cp /nix/store/xyz-out/vmlinux /tmp/o/vmlinux"));
        // rootfs→rootfs.ext4 with a rootfs.ext4 fallback.
        assert!(cmd.contains("cp /nix/store/xyz-out/rootfs /tmp/o/rootfs.ext4"));
        assert!(cmd.contains("cp /nix/store/xyz-out/rootfs.ext4 /tmp/o/rootfs.ext4"));
    }

    #[test]
    fn run_nix_build_refuses_a_malicious_flake_ref_before_any_exec() {
        let work = tempfile::tempdir().unwrap();
        let bins = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let req = BuildRequest {
            flake_ref: ".#x; rm -rf /".into(),
            attr: "packages.default".into(),
            timeout_secs: Some(60),
        };
        let product = run_nix_build(work.path(), bins.path(), out.path(), &req);
        assert!(
            matches!(product.outcome, BuildOutcome::Failure { ref message } if message.contains("invalid flake_ref")),
            "a shell-metachar flake_ref must fail validation: {:?}",
            product.outcome
        );
    }

    #[test]
    fn run_nix_build_refuses_a_malicious_attr() {
        let work = tempfile::tempdir().unwrap();
        let bins = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let req = BuildRequest {
            flake_ref: ".".into(),
            attr: "packages.default && curl evil".into(),
            timeout_secs: Some(60),
        };
        let product = run_nix_build(work.path(), bins.path(), out.path(), &req);
        assert!(
            matches!(product.outcome, BuildOutcome::Failure { ref message } if message.contains("invalid attr")),
            "a shell-metachar attr must fail validation: {:?}",
            product.outcome
        );
    }
}
