//! Shared entrypoint policy helpers.
//!
//! Production workload entrypoints must not be shell launchers. Dev-only
//! interactivity is handled through the console/exec surfaces; declared
//! production entrypoints should be typed workload runners or direct argv
//! programs, never `/bin/sh`, `bash -lc`, `/usr/bin/env sh`, or `busybox sh`.

use std::path::Path;

/// Shell launch detected in an entrypoint argv or wrapper shebang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellEntrypoint {
    /// The shell program that would be launched.
    pub shell: String,
}

/// Return the shell program if `argv` launches a shell entrypoint.
pub fn detect_shell_entrypoint_argv<S: AsRef<str>>(argv: &[S]) -> Option<ShellEntrypoint> {
    let first = argv.first()?.as_ref();
    let first_name = program_basename(first);
    if is_shell_name(first_name) {
        return Some(shell_entrypoint(first_name));
    }

    if is_env_name(first_name) {
        return detect_env_shell(argv);
    }

    if first_name == "busybox"
        && let Some(applet) = argv.get(1).map(AsRef::as_ref).map(program_basename)
        && is_shell_name(applet)
    {
        return Some(shell_entrypoint(applet));
    }

    None
}

/// Return the shell program if a shebang line names a shell interpreter.
pub fn detect_shell_shebang(bytes: &[u8]) -> Option<ShellEntrypoint> {
    let line = first_line(bytes)?;
    let trimmed = line.strip_prefix("#!")?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let argv = split_shebang_words(trimmed);
    detect_shell_entrypoint_argv(&argv)
}

fn detect_env_shell<S: AsRef<str>>(argv: &[S]) -> Option<ShellEntrypoint> {
    let mut iter = argv.iter().skip(1).map(AsRef::as_ref).peekable();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return detect_first_env_command(iter);
        }
        if arg == "-S" || arg == "--split-string" {
            let split_args = iter.next()?;
            return detect_shell_entrypoint_argv(&split_shebang_words(split_args));
        }
        if let Some(split_args) = arg.strip_prefix("--split-string=") {
            return detect_shell_entrypoint_argv(&split_shebang_words(split_args));
        }
        if takes_env_option_argument(arg) {
            let _ = iter.next();
            continue;
        }
        if arg.starts_with('-') || is_env_assignment(arg) {
            continue;
        }
        let name = program_basename(arg);
        if is_shell_name(name) {
            return Some(shell_entrypoint(name));
        }
    }
    None
}

fn detect_first_env_command<'a>(
    mut iter: impl Iterator<Item = &'a str>,
) -> Option<ShellEntrypoint> {
    iter.find(|arg| !is_env_assignment(arg))
        .map(program_basename)
        .filter(|name| is_shell_name(name))
        .map(shell_entrypoint)
}

fn takes_env_option_argument(arg: &str) -> bool {
    matches!(arg, "-u" | "--unset" | "-C" | "--chdir" | "-a" | "--argv0")
}

fn is_env_assignment(arg: &str) -> bool {
    let Some((name, _value)) = arg.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    let len = bytes
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).ok()
}

fn split_shebang_words(line: &str) -> Vec<String> {
    line.split_ascii_whitespace()
        .map(ToString::to_string)
        .collect()
}

fn program_basename(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

fn is_env_name(name: &str) -> bool {
    name == "env"
}

fn is_shell_name(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "ash" | "zsh" | "fish" | "ksh" | "mksh" | "csh" | "tcsh"
    )
}

fn shell_entrypoint(shell: &str) -> ShellEntrypoint {
    ShellEntrypoint {
        shell: shell.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_direct_shell_argv() {
        let found = detect_shell_entrypoint_argv(&["/bin/sh", "-c", "echo no"])
            .expect("must reject direct shell");
        assert_eq!(found.shell, "sh");
    }

    #[test]
    fn detects_env_shell_argv() {
        let found = detect_shell_entrypoint_argv(&["/usr/bin/env", "bash", "-lc", "echo no"])
            .expect("must reject env shell");
        assert_eq!(found.shell, "bash");
    }

    #[test]
    fn detects_env_option_shell_argv() {
        let found = detect_shell_entrypoint_argv(&["/usr/bin/env", "-u", "PATH", "bash"])
            .expect("must reject env shell after option argument");
        assert_eq!(found.shell, "bash");
    }

    #[test]
    fn detects_env_assignment_shell_argv() {
        let found = detect_shell_entrypoint_argv(&["env", "FOO=bar", "/bin/sh"])
            .expect("must reject env shell after assignment");
        assert_eq!(found.shell, "sh");
    }

    #[test]
    fn detects_env_split_shell_shebang() {
        let found = detect_shell_shebang(b"#!/usr/bin/env -S bash -eu\n")
            .expect("must reject env -S shell shebang");
        assert_eq!(found.shell, "bash");
    }

    #[test]
    fn detects_busybox_shell_argv() {
        let found = detect_shell_entrypoint_argv(&["/bin/busybox", "ash"])
            .expect("must reject busybox shell applet");
        assert_eq!(found.shell, "ash");
    }

    #[test]
    fn allows_non_shell_argv() {
        assert!(detect_shell_entrypoint_argv(&["python", "-m", "hello"]).is_none());
        assert!(detect_shell_entrypoint_argv(&["/bin/busybox", "true"]).is_none());
    }

    #[test]
    fn allows_non_shell_shebang() {
        assert!(detect_shell_shebang(b"#!/usr/bin/env python3\n").is_none());
        assert!(detect_shell_shebang(b"\x7fELF....").is_none());
    }
}
