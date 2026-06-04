use anyhow::{Context, Result};
use std::process::{Command, Output, Stdio};
use tracing::instrument;

use crate::base::config::VM_NAME;
use crate::base::linux_env;

/// Run a command on the host, capturing output.
#[instrument(skip_all, fields(cmd, args_count = args.len()))]
pub fn run_host(cmd: &str, args: &[&str]) -> Result<Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))
}

/// Run a command on the host, inheriting stdio (visible to user).
#[instrument(skip_all, fields(cmd, args_count = args.len()))]
pub fn run_host_visible(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Failed to run: {} {}", cmd, args.join(" ")))?;

    if !status.success() {
        anyhow::bail!(
            "Command failed (exit {}): {} {}",
            status.code().unwrap_or(-1),
            cmd,
            args.join(" ")
        );
    }
    Ok(())
}

/// Run a bash script in the Linux environment, capturing output.
///
/// On native Linux with KVM: runs `bash -c` directly on the host.
/// On macOS or Linux without KVM: runs via `limactl shell` inside a Lima VM.
///
/// When `vm_name` matches the default VM name, this delegates to the
/// [`LinuxEnv`](mvm_core::linux_env::LinuxEnv) abstraction. For custom
/// VM names, it uses the platform-specific command directly.
#[instrument(skip_all, fields(vm_name))]
pub fn run_on_vm(vm_name: &str, script: &str) -> Result<Output> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run(script);
    }

    // Custom VM name — can't use the default LinuxEnv (it's bound to VM_NAME)
    if let Some(output) = crate::base::shell_mock::intercept(script) {
        return Ok(output);
    }

    Command::new("bash")
        .args(["-c", script])
        .output()
        .with_context(|| "Failed to run command on host")
}

/// Run a bash script in the Linux environment, with output visible to user.
#[instrument(skip_all, fields(vm_name))]
pub fn run_on_vm_visible(vm_name: &str, script: &str) -> Result<()> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_visible(script);
    }

    let status = Command::new("bash")
        .args(["-c", script])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| "Failed to run command on host")?;

    if !status.success() {
        anyhow::bail!("Command failed (exit {})", status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Run a bash script in the Linux environment, returning stdout as String.
#[instrument(skip_all, fields(vm_name))]
pub fn run_on_vm_stdout(vm_name: &str, script: &str) -> Result<String> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_stdout(script);
    }
    let output = run_on_vm(vm_name, script)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a bash script in the default Linux environment, capturing output.
#[instrument(skip_all)]
pub fn run_in_vm(script: &str) -> Result<Output> {
    linux_env::default_env().run(script)
}

/// Run a bash script in the default Linux environment, with output visible to user.
#[instrument(skip_all)]
pub fn run_in_vm_visible(script: &str) -> Result<()> {
    linux_env::default_env().run_visible(script)
}

/// Run a bash script in the default Linux environment, returning stdout as String.
#[instrument(skip_all)]
pub fn run_in_vm_stdout(script: &str) -> Result<String> {
    linux_env::default_env().run_stdout(script)
}

/// Run a bash script in the Linux environment, capturing stdout and stderr
/// into an `Output` struct (piped, not inherited).
///
/// Unlike `run_on_vm_visible`, the output is **not** shown to the user in real time.
/// Use this when you need to capture error messages (e.g., nix build failures) for
/// structured reporting.
#[instrument(skip_all, fields(vm_name))]
pub fn run_on_vm_capture(vm_name: &str, script: &str) -> Result<Output> {
    if vm_name == VM_NAME {
        return linux_env::default_env().run_capture(script);
    }

    if let Some(output) = crate::base::shell_mock::intercept(script) {
        return Ok(output);
    }

    Command::new("bash")
        .args(["-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| "Failed to run command on host")
}

/// Run a bash script in the default Linux environment, capturing stdout and stderr.
#[instrument(skip_all)]
pub fn run_in_vm_capture(script: &str) -> Result<Output> {
    linux_env::default_env().run_capture(script)
}

/// Quote `arg` so it can be safely interpolated as a single token in
/// a bash script. Wraps the input in single quotes and escapes any
/// embedded single quotes via the `'\''` idiom — works for arbitrary
/// content (paths with spaces, dollar signs, backticks, embedded
/// newlines) without further shell expansion.
///
/// Use this whenever a path or other untrusted-shape string flows
/// into a `bash -c` script, especially for `run_in_vm*` callers.
pub fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Replace the current process with an interactive command (for SSH/TTY).
/// Uses Unix's process replacement — the Rust process is fully replaced, no return on success.
/// Note: This is safe because all arguments are passed as an array, not via shell interpolation.
#[cfg(unix)]
pub fn replace_process(cmd: &str, args: &[&str]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let err = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();

    // exec() only returns on error
    Err(err).with_context(|| format!("Failed to replace process: {} {}", cmd, args.join(" ")))
}

/// Replace the current process with `cmd args...`, wrapped for the VM runtime.
///
/// Mirrors [`run_in_vm`] but uses process replacement (Unix exec) instead of
/// spawning a child. Needed for interactive TTY pass-through (e.g. interactive
/// shells launched from `mvmctl`).
#[cfg(unix)]
pub fn replace_process_in_vm(cmd: &str, args: &[&str]) -> Result<()> {
    replace_process(cmd, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_host_echo() {
        let output = run_host("echo", &["hello"]).unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "hello");
    }

    #[test]
    fn test_run_host_failure() {
        let output = run_host("false", &[]).unwrap();
        assert!(!output.status.success());
    }

    #[test]
    fn test_run_host_nonexistent_command() {
        let result = run_host("definitely-not-a-real-command-12345", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_run_host_visible_success() {
        let result = run_host_visible("true", &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_host_visible_failure() {
        let result = run_host_visible("false", &[]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Command failed"));
    }

    #[test]
    fn shell_quote_wraps_in_single_quotes() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn shell_quote_preserves_shell_metacharacters() {
        // The point of single-quote wrapping: no further expansion.
        assert_eq!(shell_quote("a$b`c;d|e&f"), "'a$b`c;d|e&f'");
    }

    #[test]
    fn shell_quote_handles_spaces_and_paths() {
        assert_eq!(
            shell_quote("/tmp/path with spaces/file"),
            "'/tmp/path with spaces/file'"
        );
    }

    #[test]
    fn shell_quote_handles_empty_string() {
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn shell_quote_round_trips_through_bash() {
        // The strongest test: actually run bash and verify the quoted
        // arg comes back unchanged. Covers the corner cases (newlines,
        // backslashes, sequences that look like substitutions).
        for &arg in &[
            "simple",
            "spaces here",
            "$VAR",
            "`backticks`",
            "a'b",
            "a\nb",
            "a\\b",
            "$(injection attempt)",
            "&& rm -rf /",
        ] {
            let quoted = shell_quote(arg);
            let out =
                run_host("bash", &["-c", &format!("printf '%s' {quoted}")]).expect("bash echo");
            assert_eq!(
                std::str::from_utf8(&out.stdout).unwrap(),
                arg,
                "shell_quote failed to round-trip {arg:?} (quoted as {quoted:?})"
            );
        }
    }
}
