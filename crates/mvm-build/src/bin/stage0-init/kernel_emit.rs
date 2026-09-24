//! Resolved-kernel-config emission for Stage 0 (`kernel` output mode).
//!
//! Realises the configfile attr for the kernel that was just built and
//! copies it to `/out/mvm-kernel.config`, streaming the nix stderr to the
//! console so a config-only failure is diagnosable from the console log.
//! Extracted from `stage0-init.rs` to keep that file inside the
//! production-line budget.

use std::path::Path;
use std::process::{Command, Stdio};

/// Realise the resolved-`.config` flake attr and copy it to
/// `/out/mvm-kernel.config`. Cheap — it's a cached dependency of the
/// kernel just built. `flake_base` is the same conf-driven base the
/// kernel attr was built from: when the host stages a non-default flake
/// at `/work` (an mvm-images kernel checkout names its own attrs), the
/// config attr only resolves under that same base — hardcoding the
/// in-repo base here builds a config for the WRONG kernel and the host
/// publishes a sidecar that misdescribes the artifact.
///
/// Guest-side only: it depends on the linux-gated vsock-egress helpers in
/// `crate::linux`. Only `run_streaming` is host-testable.
#[cfg(target_os = "linux")]
pub(crate) fn emit_resolved_config(
    nix: &Path,
    arch: &str,
    config_attr: &str,
    flake_base: &str,
) -> Result<(), String> {
    let flake_ref = format!("{flake_base}.{arch}-linux.{config_attr}");
    eprintln!("stage0-init: emitting resolved config via {flake_ref}");
    let mut cmd = Command::new(nix);
    cmd.args([
        "build",
        &flake_ref,
        "--extra-experimental-features",
        "nix-command flakes",
        "--option",
        "build-users-group",
        "",
        "--max-jobs",
        "1",
        "--no-link",
        "--no-write-lock-file",
        "--impure",
        "--print-out-paths",
    ]);
    // The guest has no direct network: every fetch rides the loopback
    // egress proxy, exactly like the main build above. Without these the
    // emit cannot substitute from cache.nixos.org and falls back to
    // upstream mirrors the egress refuses.
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if crate::linux::should_enable_vsock_egress(crate::linux::is_qemu(), &cmdline) {
        crate::linux::apply_vsock_egress_proxy_env(&mut cmd);
    }
    // Stream stderr to the console like the main build: a config-only
    // failure (e.g. a missing attr on a non-default flake base) is
    // otherwise invisible — the host only sees a bare exit code and
    // publishes a kernel with no config sidecar, misdescribed.
    let (status, stderr_log, stdout) = run_streaming(cmd, &mut std::io::stderr().lock())
        .map_err(|e| format!("nix build config: {e}"))?;
    if !status.success() {
        return Err(format!(
            "nix build config exit {}: {}",
            status.code().unwrap_or(-1),
            String::from_utf8_lossy(&stderr_log)
        ));
    }
    let store_path = stdout.trim().to_string();
    if store_path.is_empty() {
        return Err("config build emitted no /nix/store path".into());
    }
    crate::linux::copy_deref(Path::new(&store_path), Path::new("/out/mvm-kernel.config"))?;
    // Root the config output separately from the kernel: it is only a
    // build-time input of the kernel derivation, so rooting the kernel
    // does not keep it, and without a root the post-build collection
    // deletes it — the next run's emit then rebuilds it from a cold
    // store, which needs network fetches the egress may not admit.
    crate::store_gc::collect::root_stage0_output(Path::new(&store_path), "kernel-config");
    Ok(())
}

/// Spawn `cmd`, streaming its stderr line-by-line to `live` (flushed per
/// line so a host tailing the console sees progress as it arrives) while
/// accumulating the full stderr for a post-mortem log, and capturing stdout
/// (nix's single trailing out-path). Returns `(status, stderr_log, stdout)`.
///
/// Draining stderr to EOF before reading stdout can't deadlock here: nix
/// writes only the short out-path to stdout (well under the pipe buffer), so
/// it never blocks waiting for us to read it.
pub(crate) fn run_streaming(
    mut cmd: Command,
    live: &mut dyn std::io::Write,
) -> Result<(std::process::ExitStatus, Vec<u8>, String), String> {
    use std::io::{BufRead, Read};
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;

    let mut stderr_log: Vec<u8> = Vec::new();
    if let Some(child_stderr) = child.stderr.take() {
        let reader = std::io::BufReader::new(child_stderr);
        for chunk in reader.split(b'\n') {
            let Ok(mut chunk) = chunk else { break };
            chunk.push(b'\n');
            let _ = live.write_all(&chunk);
            let _ = live.flush();
            stderr_log.extend_from_slice(&chunk);
        }
    }
    let mut stdout = String::new();
    if let Some(mut child_stdout) = child.stdout.take() {
        let _ = child_stdout.read_to_string(&mut stdout);
    }
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    Ok((status, stderr_log, stdout))
}
