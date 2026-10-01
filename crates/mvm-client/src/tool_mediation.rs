//! Host-local tool questions for the per-VM network endpoint.
//!
//! The caller sends only the guest-reported invocation. The endpoint owns the
//! admitted rules, approval supervisor, and chain recorder; a missing or
//! malformed answer is never an allow.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolDecisionReply};
use mvm_core::net::session::{read_json_frame, write_json_frame};

const MAX_TOOL_FRAME_BYTES: usize = 20 * 1024;
const TOOL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// The endpoint holds an operator approval for at most 120 seconds; return
// before the guest's 130-second tool-reply deadline expires.
const TOOL_READ_TIMEOUT: Duration = Duration::from_secs(125);

/// Ask this VM's admitted endpoint to decide and audit the exact invocation.
/// Transport, parse, and endpoint failures are errors, never approvals.
pub fn decide_declared_tool(vm_name: &str, question: &ToolCheckRequest) -> Result<bool> {
    mvm_core::naming::validate_vm_name(vm_name).context("invalid VM name for tool decision")?;
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    let socket = mvm_core::config::vm_socket_dir_at(&state_dir)
        .join(mvm_vmm::host::network_endpoint_spawn::SUBST_CONNECTOR_SOCKET);
    decide_at(&socket, question)
}

fn decide_at(socket: &Path, question: &ToolCheckRequest) -> Result<bool> {
    ensure!(question.is_valid(), "invalid declared tool invocation");
    let mut stream = UnixStream::connect(socket).context("tool decision endpoint unavailable")?;
    stream
        .set_write_timeout(Some(TOOL_WRITE_TIMEOUT))
        .context("setting tool question write deadline")?;
    stream
        .set_read_timeout(Some(TOOL_READ_TIMEOUT))
        .context("setting tool decision read deadline")?;
    write_json_frame(&mut stream, question, MAX_TOOL_FRAME_BYTES)
        .context("sending declared tool question")?;
    let reply: ToolDecisionReply = read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES)
        .context("reading declared tool decision")?;
    Ok(matches!(reply, ToolDecisionReply::Allow))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    fn question() -> ToolCheckRequest {
        ToolCheckRequest {
            tool: "read".into(),
            argv: "read private-file".into(),
        }
    }

    #[test]
    fn host_local_decision_roundtrips_both_verdicts() {
        for (reply, expected) in [
            (ToolDecisionReply::Allow, true),
            (ToolDecisionReply::Deny, false),
        ] {
            let dir = tempfile::tempdir().expect("temporary socket directory");
            let socket = dir.path().join("tool.sock");
            let listener = UnixListener::bind(&socket).expect("bind socket");
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept question");
                let reported: ToolCheckRequest =
                    read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES).expect("read question");
                assert_eq!(reported, question());
                write_json_frame(&mut stream, &reply, MAX_TOOL_FRAME_BYTES)
                    .expect("write decision");
            });
            assert_eq!(decide_at(&socket, &question()).expect("decision"), expected);
            server.join().expect("server join");
        }
    }

    #[test]
    fn missing_or_malformed_endpoint_answer_is_not_allow() {
        let dir = tempfile::tempdir().expect("temporary socket directory");
        let socket = dir.path().join("tool.sock");
        assert!(decide_at(&socket, &question()).is_err());

        let listener = UnixListener::bind(&socket).expect("bind socket");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept question");
            let _: ToolCheckRequest =
                read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES).expect("read question");
            write_json_frame(&mut stream, &"invalid", MAX_TOOL_FRAME_BYTES)
                .expect("write malformed decision");
        });
        assert!(decide_at(&socket, &question()).is_err());
        server.join().expect("server join");
    }

    #[test]
    fn invalid_question_is_rejected_before_connecting() {
        let mut invalid = question();
        invalid.tool.clear();
        assert!(decide_at(Path::new("/nonexistent-tool-socket"), &invalid).is_err());
    }
}
