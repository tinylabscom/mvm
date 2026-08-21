//! Bounded `strace`-backed dynamic tracer for explicit user commands.

use crate::CaptureError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Events that a dynamic tracer may observe.
#[derive(Clone, Debug, PartialEq)]
pub enum TraceEvent {
    Execve { argv: Vec<String> },
    Open { path: String },
    Connect { endpoint: String },
}

/// Limits applied to a traced run.
#[derive(Clone, Debug)]
pub struct StraceLimits {
    pub max_seconds: u64,
    pub max_output_bytes: u64,
    pub max_events: usize,
}

impl Default for StraceLimits {
    fn default() -> Self {
        Self {
            max_seconds: 10,
            max_output_bytes: 10 * 1024 * 1024,
            max_events: 1_000,
        }
    }
}

/// Linux `strace` tracer.
pub struct StraceTracer {
    limits: StraceLimits,
}

impl StraceTracer {
    pub fn new(limits: StraceLimits) -> Self {
        Self { limits }
    }
}

impl StraceTracer {
    /// Run `strace` against `command` and return observed events.
    pub fn trace_command(&self, command: &[String]) -> Result<Vec<TraceEvent>, CaptureError> {
        if command.is_empty() {
            return Err(CaptureError::InvalidObservation(
                "empty command cannot be traced".to_owned(),
            ));
        }

        let output_file = tempfile::NamedTempFile::new()
            .map_err(|e| CaptureError::Io(PathBuf::from("<strace-output>"), e))?;
        let output_path = output_file.path().to_path_buf();

        let mut cmd = build_trace_command(command, &output_path, self.limits.max_seconds);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| CaptureError::Io(PathBuf::from("strace"), e))?;

        let status = child
            .wait()
            .map_err(|e| CaptureError::Io(PathBuf::from("strace"), e))?;

        let stderr = child
            .stderr
            .take()
            .map(|mut r| {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut r, &mut buf).ok();
                buf
            })
            .unwrap_or_default();

        // strace exits with the traced process's status; 124 means timeout killed it.
        if !status.success() && status.code() == Some(124) {
            return Err(CaptureError::LimitExceeded(format!(
                "strace timed out after {} seconds",
                self.limits.max_seconds
            )));
        }

        let output = read_limited(&output_path, self.limits.max_output_bytes)
            .map_err(|e| CaptureError::Io(output_path.clone(), e))?;
        let text = String::from_utf8_lossy(&output);
        let events = parse_strace_output(&text, self.limits.max_events);

        if events.is_empty() && !stderr.is_empty() {
            return Err(CaptureError::PackageQueryFailed(format!(
                "strace produced no parseable events; stderr: {}",
                stderr.lines().next().unwrap_or("unknown")
            )));
        }

        Ok(events)
    }
}

fn read_limited(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut limited = file.take(max_bytes);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

fn build_trace_command(command: &[String], output_path: &Path, max_seconds: u64) -> Command {
    let has_timeout = which::which("timeout").is_ok();
    if has_timeout {
        let mut cmd = Command::new("timeout");
        cmd.arg("--signal=KILL")
            .arg("--kill-after=1s")
            .arg(format!("{}", max_seconds))
            .arg("strace")
            .arg("-f")
            .arg("-e")
            .arg("trace=openat,open,connect,execve,execveat")
            .arg("-s")
            .arg("256")
            .arg("-o")
            .arg(output_path)
            .arg("--")
            .args(command);
        cmd
    } else {
        let mut cmd = Command::new("strace");
        cmd.arg("-f")
            .arg("-e")
            .arg("trace=openat,open,connect,execve,execveat")
            .arg("-s")
            .arg("256")
            .arg("-o")
            .arg(output_path)
            .arg("--")
            .args(command);
        cmd
    }
}

fn parse_strace_output(output: &str, max_events: usize) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    for line in output.lines().take(max_events) {
        if let Some(event) = parse_strace_line(line) {
            events.push(event);
        }
    }
    events
}

fn parse_strace_line(line: &str) -> Option<TraceEvent> {
    let line = strip_pid_prefix(line);
    if line.contains("<unfinished ...>") || line.contains("<resumed>") {
        return None;
    }

    if let Some(path) = parse_open_path(line) {
        return Some(TraceEvent::Open { path });
    }
    if let Some(endpoint) = parse_connect_endpoint(line) {
        return Some(TraceEvent::Connect { endpoint });
    }
    if let Some(argv) = parse_execve(line) {
        return Some(TraceEvent::Execve { argv });
    }
    None
}

fn strip_pid_prefix(line: &str) -> &str {
    let line = line.trim_start();
    if line.starts_with("[pid ") {
        line.find("] ").map(|i| &line[i + 2..]).unwrap_or(line)
    } else {
        line
    }
}

fn parse_open_path(line: &str) -> Option<String> {
    if !line.starts_with("openat(") && !line.starts_with("open(") {
        return None;
    }
    let after_paren = line.find('(').map(|i| &line[i + 1..])?;
    extract_quoted_string(after_paren)
}

fn parse_connect_endpoint(line: &str) -> Option<String> {
    if !line.starts_with("connect(") {
        return None;
    }
    let after = &line["connect(".len()..];
    let ip = {
        let key = "sin_addr=inet_addr(\"";
        let start = after.find(key).map(|i| i + key.len())?;
        let end = after[start..].find("\")").map(|i| start + i)?;
        &after[start..end]
    };
    let port = {
        let key = "sin_port=htons(";
        let start = after.find(key).map(|i| i + key.len())?;
        let end = after[start..].find(')').map(|i| start + i)?;
        after[start..end].parse::<u16>().ok()?
    };
    Some(format!("{}:{}", ip, port))
}

fn parse_execve(line: &str) -> Option<Vec<String>> {
    if !line.starts_with("execve(") {
        return None;
    }
    let after = &line["execve(".len()..];
    let path = extract_quoted_string(after)?;
    let argv_start = after.find('[')?;
    let argv_end = after[argv_start..].find(']')? + argv_start;
    let argv_str = &after[argv_start + 1..argv_end];
    let mut argv = vec![path];
    for part in argv_str.split(',') {
        let trimmed = part.trim();
        if let Some(arg) = extract_quoted_string(trimmed) {
            argv.push(arg);
        }
    }
    Some(argv)
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let rest = &s[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openat_extracts_path() {
        let line = r#"openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3"#;
        assert_eq!(
            parse_strace_line(line),
            Some(TraceEvent::Open {
                path: "/etc/ld.so.cache".to_owned()
            })
        );
    }

    #[test]
    fn parse_open_extracts_path() {
        let line = r#"open("/dev/null", O_RDONLY) = 3"#;
        assert_eq!(
            parse_strace_line(line),
            Some(TraceEvent::Open {
                path: "/dev/null".to_owned()
            })
        );
    }

    #[test]
    fn parse_connect_extracts_ipv4_endpoint() {
        let line = r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = 0"#;
        assert_eq!(
            parse_strace_line(line),
            Some(TraceEvent::Connect {
                endpoint: "1.2.3.4:443".to_owned()
            })
        );
    }

    #[test]
    fn parse_execve_extracts_argv() {
        let line = r#"execve("/bin/ls", ["ls", "-l"], 0x7ffd0000 /* 50 vars */) = 0"#;
        assert_eq!(
            parse_strace_line(line),
            Some(TraceEvent::Execve {
                argv: vec!["/bin/ls".to_owned(), "ls".to_owned(), "-l".to_owned()]
            })
        );
    }

    #[test]
    fn unfinished_lines_are_skipped() {
        let line = r#"openat(AT_FDCWD, "/some/path" <unfinished ...>"#;
        assert_eq!(parse_strace_line(line), None);
    }

    #[test]
    fn strip_pid_prefix_parses_followed_lines() {
        let line = r#"[pid  1234] openat(AT_FDCWD, "/tmp/file", O_RDONLY) = 3"#;
        assert_eq!(
            parse_strace_line(line),
            Some(TraceEvent::Open {
                path: "/tmp/file".to_owned()
            })
        );
    }

    #[test]
    fn output_is_bounded_by_max_events() {
        let output = "open(\"a\")\nopen(\"b\")\nopen(\"c\")\n";
        let events = parse_strace_output(output, 2);
        assert_eq!(events.len(), 2);
    }
}
