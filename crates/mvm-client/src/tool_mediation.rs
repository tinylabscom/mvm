//! Host-local tool questions for the per-VM network endpoint.
//!
//! The caller sends only the guest-reported invocation. The endpoint owns the
//! admitted rules, approval supervisor, and chain recorder; a missing or
//! malformed answer is never an allow.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use mvm_contract::protocol::network_flow::attribution::{
    ToolInvocationBinding, ToolInvocationRelease,
};
use mvm_contract::protocol::network_flow::tool::{ToolCheckRequest, ToolDecisionReply};
use mvm_core::net::session::{read_json_frame, write_json_frame};

const MAX_TOOL_FRAME_BYTES: usize = 20 * 1024;
const TOOL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// The endpoint holds an operator approval for at most 120 seconds; return
// before the guest's 130-second tool-reply deadline expires.
const TOOL_READ_TIMEOUT: Duration = Duration::from_secs(125);

/// Ask this VM's admitted endpoint to decide and audit the exact invocation.
/// Transport, parse, and endpoint failures are errors, never approvals. An
/// `AllowBound` answer carries the binding the guest attributes the
/// invocation's flows to; release it with [`release_declared_tool`] once the
/// command has finished.
pub fn decide_declared_tool(
    vm_name: &str,
    question: &ToolCheckRequest,
) -> Result<ToolDecisionReply> {
    decide_at(&connector_socket(vm_name)?, question)
}

/// Retire an invocation's binding, so a flow opened after the command ended
/// cannot use the tool's routes or secrets.
pub fn release_declared_tool(vm_name: &str, binding: &ToolInvocationBinding) -> Result<()> {
    release_at(&connector_socket(vm_name)?, binding)
}

fn connector_socket(vm_name: &str) -> Result<PathBuf> {
    mvm_core::naming::validate_vm_name(vm_name).context("invalid VM name for tool decision")?;
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    Ok(mvm_core::config::vm_socket_dir_at(&state_dir)
        .join(mvm_vmm::host::network_endpoint_spawn::SUBST_CONNECTOR_SOCKET))
}

fn connect(socket: &Path) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket).context("tool decision endpoint unavailable")?;
    stream
        .set_write_timeout(Some(TOOL_WRITE_TIMEOUT))
        .context("setting tool question write deadline")?;
    stream
        .set_read_timeout(Some(TOOL_READ_TIMEOUT))
        .context("setting tool decision read deadline")?;
    Ok(stream)
}

fn decide_at(socket: &Path, question: &ToolCheckRequest) -> Result<ToolDecisionReply> {
    ensure!(question.is_valid(), "invalid declared tool invocation");
    let mut stream = connect(socket)?;
    write_json_frame(&mut stream, question, MAX_TOOL_FRAME_BYTES)
        .context("sending declared tool question")?;
    read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES).context("reading declared tool decision")
}

fn release_at(socket: &Path, binding: &ToolInvocationBinding) -> Result<()> {
    let mut stream = connect(socket)?;
    write_json_frame(
        &mut stream,
        &ToolInvocationRelease {
            release: binding.clone(),
        },
        MAX_TOOL_FRAME_BYTES,
    )
    .context("releasing the declared tool invocation")
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    fn question() -> ToolCheckRequest {
        ToolCheckRequest {
            tool: "read".into(),
            executable: Some("/bin/read".into()),
            argv: "read private-file".into(),
        }
    }

    #[test]
    fn host_local_decision_roundtrips_every_verdict() {
        for reply in [
            ToolDecisionReply::Allow,
            ToolDecisionReply::AllowBound {
                binding: ToolInvocationBinding::from_random([4; 16]),
            },
            ToolDecisionReply::Deny,
        ] {
            let expected = reply.clone();
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
    fn a_release_names_only_the_binding() {
        let dir = tempfile::tempdir().expect("temporary socket directory");
        let socket = dir.path().join("tool.sock");
        let listener = UnixListener::bind(&socket).expect("bind socket");
        let binding = ToolInvocationBinding::from_random([6; 16]);
        let expected = binding.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept release");
            let release: ToolInvocationRelease =
                read_json_frame(&mut stream, MAX_TOOL_FRAME_BYTES).expect("read release");
            assert_eq!(release.release, expected);
        });
        release_at(&socket, &binding).expect("release");
        server.join().expect("server join");
    }

    #[test]
    fn invalid_question_is_rejected_before_connecting() {
        let mut invalid = question();
        invalid.tool.clear();
        assert!(decide_at(Path::new("/nonexistent-tool-socket"), &invalid).is_err());
    }
}
