//! `xtask check-no-guest-tool-client`
//!
//! An agent's in-guest toolbox is deliberately ungoverned:
//! a shell, a browser driver, an interpreter, or a tool server the agent talks
//! to over its own stdio or loopback are all the image's business, and the
//! microVM boundary is what bounds them rather than any list the host keeps.
//!
//! What the boundary cannot bound is the guest *originating* a connection to a
//! remote server. That would reintroduce an unaudited egress path and a tool
//! namespace that mutates under a running admission, which is what the
//! vsock-only posture exists to prevent.
//!
//! # Why this greps for connection setup and not for a protocol
//!
//! Grepping for a tool protocol's name gets the scope exactly backwards. It
//! refuses the supported case — a local tool server named after that protocol —
//! while missing the unsupported one, because an outbound client written
//! against any other protocol sails through. Connection-setup primitives are
//! the thing that actually distinguishes the two.
//!
//! # The single exception, and why it is pinned rather than carved out
//!
//! The guest agent forwards a host-initiated port to a service running inside
//! the guest, which is a loopback connect. Allowing the file outright would let
//! that same call become a remote client with no gate firing, so the exception
//! is conditional: the gate re-reads the destination constant and fails if it
//! is no longer a loopback literal.

use anyhow::{Result, bail};
use std::path::Path;

/// The code that actually ships inside a workload guest and runs there.
///
/// A missing directory is a hard error rather than zero files scanned: a gate
/// that silently guards nothing after a refactor is worse than no gate, and
/// this repository has already paid for that once.
const GUARDED_DIR: &str = "crates/mvm-agentd/src/bin/mvm-guest-agent";

/// Connection-setup primitives. A guest that reaches for one of these is
/// originating a connection, whatever protocol it then speaks.
const FORBIDDEN: &[&str] = &[
    "TcpStream::connect",
    "UdpSocket::bind",
    "UdpSocket::connect",
    "reqwest",
    "hyper::client",
    "mvm_http",
];

/// The one file permitted to connect, the constant that makes it safe, and the
/// literal that constant must still hold.
const LOOPBACK_EXCEPTION: (&str, &str, &[&str]) = (
    "port_forward.rs",
    "PORT_FORWARD_TCP_HOST",
    &["\"127.0.0.1\"", "\"::1\""],
);

pub fn run(workspace: &Path) -> Result<()> {
    let dir = workspace.join(GUARDED_DIR);
    if !dir.is_dir() {
        bail!(
            "check-no-guest-tool-client: guarded directory `{GUARDED_DIR}` does not exist. \
             It moved or was renamed; re-point this gate rather than leaving it scanning nothing."
        );
    }
    let violations = scan_dir(&dir)?;
    if !violations.is_empty() {
        for violation in &violations {
            eprintln!("[error] {violation}");
        }
        bail!(
            "check-no-guest-tool-client: {} outbound-client site(s) in guest-shipped code. \
             A guest may run any tool it likes; it may not originate a connection to a \
             remote server. Route it through the host so the destination is admitted.",
            violations.len()
        );
    }
    println!("check-no-guest-tool-client: clean ({GUARDED_DIR})");
    Ok(())
}

/// Walk one directory tree, returning a message per violation.
fn scan_dir(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut saw_exception_file = false;
    for entry in walk(dir)? {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let text = std::fs::read_to_string(&entry)?;
        if name == LOOPBACK_EXCEPTION.0 {
            saw_exception_file = true;
            if let Some(problem) = loopback_still_holds(&text) {
                out.push(format!("{}: {problem}", entry.display()));
            }
            continue;
        }
        out.extend(forbidden_hits(&text).into_iter().map(|(line, token)| {
            format!(
                "{}:{line}: `{token}` in guest-shipped code",
                entry.display()
            )
        }));
    }
    // The exception is only sound while the file it names is present. If it is
    // gone the allowance is stale, and a stale allowance permits by accident.
    if !saw_exception_file {
        out.push(format!(
            "the loopback exception names `{}`, which no longer exists under {}. \
             Remove the exception rather than leaving it permitting nothing.",
            LOOPBACK_EXCEPTION.0,
            dir.display()
        ));
    }
    Ok(out)
}

/// Lines carrying a forbidden token, ignoring comments.
fn forbidden_hits(text: &str) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        for token in FORBIDDEN {
            if line.contains(token) {
                hits.push((index + 1, *token));
            }
        }
    }
    hits
}

/// Whether the excepted file still pins its destination to loopback.
///
/// Returns a problem description when it does not.
fn loopback_still_holds(text: &str) -> Option<String> {
    let (_, konst, literals) = LOOPBACK_EXCEPTION;
    let defining = text
        .lines()
        .find(|line| line.contains(&format!("const {konst}")))?;
    if literals.iter().any(|literal| defining.contains(literal)) {
        return None;
    }
    Some(format!(
        "`{konst}` is no longer a loopback literal, so the connect it guards is \
         no longer an in-guest forward. This gate's exception rests on that constant."
    ))
}

/// Every `.rs` file under `dir`.
fn walk(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guest_agent_originates_no_remote_connection() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        run(workspace).expect("guest-shipped code stays free of outbound clients");
    }

    #[test]
    fn an_outbound_client_in_guest_code_is_a_violation() {
        let hits = forbidden_hits("let s = TcpStream::connect(remote).unwrap();\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, "TcpStream::connect");
    }

    #[test]
    fn a_commented_mention_is_not_a_violation() {
        assert!(forbidden_hits("// TcpStream::connect is refused here\n").is_empty());
    }

    #[test]
    fn a_local_tool_server_over_stdio_is_not_a_violation() {
        // The supported in-guest case: a subprocess spoken to over stdio. A
        // gate that greps for a protocol name would refuse exactly this.
        let source =
            "let child = Command::new(\"some-mcp-server\").stdin(Stdio::piped()).spawn()?;\n";
        assert!(forbidden_hits(source).is_empty());
    }

    #[test]
    fn a_loopback_constant_turned_remote_is_caught() {
        let good = "pub(crate) const PORT_FORWARD_TCP_HOST: &str = \"127.0.0.1\";\n";
        assert!(loopback_still_holds(good).is_none());

        let bad = "pub(crate) const PORT_FORWARD_TCP_HOST: &str = \"api.example.com\";\n";
        assert!(
            loopback_still_holds(bad).is_some(),
            "the exception is only sound while the destination is loopback"
        );
    }
}
