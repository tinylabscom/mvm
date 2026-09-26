//! Guest process and filesystem operations on a running machine.
//!
//! These are DevOnly guest-agent verbs: the agent refuses them on a sealed
//! production image, and they are not part of `MvmClient`, which must stay
//! answerable by a remote backend. They live here, rather than in the CLI, so
//! that `mvmctl machine proc`/`fs`/`cp` and the host library reach a guest
//! through one implementation, with the same audit entries.
//!
//! Every request first records a chain entry for the RPC itself
//! (`NetworkPolicyAllow`, `verb=<kind>`). Operations that change the guest
//! also record their own entry (`VmProcStart`, `VmProcSignal`, `Kill`,
//! `VmProcStdin`, `VmFsMutate`), exactly as the CLI verbs always did.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{
    FsEntry, FsResult, FsStat, GuestRequest, ProcInfo, ProcResult, ProcWaitEvent,
};

/// Record the host→guest RPC in the audit chain, before it is sent.
///
/// The verb name lands in the entry as `verb=<kebab-name>`, so every guest
/// request a host issues has a footprint even when the request itself fails.
pub fn emit_vsock_rpc_audit(vm_id: &str, request: &GuestRequest) {
    let verb = request.kind_name();
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_id,
        "scope=rpc,direction=in,kind=vsock,verb={verb}",
        verb = verb,
    );
}

fn validate(name: &str) -> Result<()> {
    mvm_core::naming::validate_vm_name(name).with_context(|| format!("Invalid VM name: {name:?}"))
}

/// Open the agent connection for `name` on whichever transport its backend
/// uses. The in-memory mock backend has no entry in the transport probe, so
/// when it is compiled in and owns this VM, its socket is returned instead.
fn mock_agent_dir(name: &str) -> Option<String> {
    #[cfg(feature = "test-support")]
    {
        let mock_dir = mvm_runtime::MockBackend::vm_dir(name);
        if mock_dir.join("runtime").join("v.sock").exists() {
            return Some(mock_dir.to_string_lossy().into_owned());
        }
    }
    let _ = name;
    None
}

fn connect(name: &str) -> Result<std::os::unix::net::UnixStream> {
    mvm_runtime::vsock_transport::for_vm(name)?.connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
}

// ── processes ────────────────────────────────────────────────────────────

/// Send one non-streaming process RPC.
pub fn proc_request(name: &str, request: GuestRequest) -> Result<ProcResult> {
    validate(name)?;
    if let Some(dir) = mock_agent_dir(name) {
        return mvm_agentd::vsock::send_proc_request(&dir, request);
    }
    mvm_agentd::vsock::send_proc_request_on(&mut connect(name)?, request)
}

fn unwrap_proc(result: ProcResult) -> Result<ProcResult> {
    if let ProcResult::Error { kind, message } = &result {
        bail!("Guest proc error ({kind:?}): {message}");
    }
    Ok(result)
}

/// A process to start in the guest.
#[derive(Debug, Clone, Default)]
pub struct ProcStart {
    /// The program and its arguments. Must not be empty.
    pub argv: Vec<String>,
    /// Environment for the process.
    pub env: BTreeMap<String, String>,
    /// Working directory, or the agent's default.
    pub cwd: Option<String>,
    /// Denied variables the caller re-admits by exact name.
    pub allow_env: mvm_core::env_hygiene::EnvReadmit,
}

/// Start a process in `name`'s guest and return the token that names it.
///
/// A denied variable in `env` (loader, shell, interpreter, or password-manager
/// session) refuses the start unless `allow_env` names it: the caller supplied
/// it explicitly, so it is told which variable and why.
pub fn start_process(name: &str, start: ProcStart) -> Result<String> {
    let Some(argv0) = start.argv.first().cloned() else {
        bail!("argv cannot be empty");
    };
    mvm_core::env_hygiene::EnvFilter::new(start.allow_env)
        .refuse_denied(start.env.keys().map(String::as_str))
        .context("guest process environment")?;
    let request = GuestRequest::ProcStart {
        argv: start.argv,
        env: start.env,
        cwd: start.cwd,
        stdin: vec![],
        timeout_secs: None,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_proc(proc_request(name, request)?)? {
        ProcResult::Started { pid_token } => {
            mvm_core::audit_emit!(VmProcStart, vm: name, "argv0={} token={pid_token}", argv0);
            Ok(pid_token)
        }
        other => bail!("Unexpected ProcResult variant for Start: {other:?}"),
    }
}

/// The processes the guest agent is tracking.
pub fn list_processes(name: &str) -> Result<Vec<ProcInfo>> {
    emit_vsock_rpc_audit(name, &GuestRequest::ProcList);
    match unwrap_proc(proc_request(name, GuestRequest::ProcList)?)? {
        ProcResult::List { processes } => Ok(processes),
        other => bail!("Unexpected ProcResult variant for List: {other:?}"),
    }
}

/// Send `signum` to the process `token`.
pub fn signal_process(name: &str, token: &str, signum: i32) -> Result<()> {
    let request = GuestRequest::ProcSignal {
        pid_token: token.to_string(),
        signum,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_proc(proc_request(name, request)?)? {
        ProcResult::Signaled => {
            mvm_core::audit_emit!(VmProcSignal, vm: name, "token={token} signum={signum}");
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for Signal: {other:?}"),
    }
}

/// Kill the process `token`.
pub fn kill_process(name: &str, token: &str) -> Result<()> {
    let request = GuestRequest::ProcKill {
        pid_token: token.to_string(),
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_proc(proc_request(name, request)?)? {
        ProcResult::Killed => {
            mvm_core::audit_emit!(Kill, vm: name, "scope=guest_proc token={token}");
            Ok(())
        }
        other => bail!("Unexpected ProcResult variant for Kill: {other:?}"),
    }
}

/// Write `bytes` to the stdin of the process `token`, in wire-sized chunks.
/// An empty slice sends one empty chunk, which the agent reads as a write of
/// nothing. Returns the number of bytes the guest accepted.
pub fn send_process_input(name: &str, token: &str, bytes: &[u8]) -> Result<u64> {
    let mut total_accepted = 0_u64;
    for chunk in bytes
        .chunks(mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE)
        .chain(bytes.is_empty().then_some(bytes))
    {
        let request = GuestRequest::ProcSendInput {
            pid_token: token.to_string(),
            bytes: chunk.to_vec(),
        };
        emit_vsock_rpc_audit(name, &request);
        match unwrap_proc(proc_request(name, request)?)? {
            ProcResult::InputAccepted { bytes_accepted } => {
                let expected = u64::try_from(chunk.len()).context("chunk length fits u64")?;
                if bytes_accepted != expected {
                    bail!("Guest accepted {bytes_accepted} stdin bytes, expected {expected}");
                }
                total_accepted = total_accepted
                    .checked_add(bytes_accepted)
                    .ok_or_else(|| anyhow::anyhow!("Accepted stdin byte count overflow"))?;
            }
            other => bail!("Unexpected ProcResult variant for SendInput: {other:?}"),
        }
    }
    mvm_core::audit_emit!(VmProcStdin, vm: name, "token={token} bytes={total_accepted}");
    Ok(total_accepted)
}

/// Wait for the process `token` to end, handing each streamed event to
/// `on_event` as it arrives, and return the terminal event.
pub fn wait_process<F: FnMut(&ProcWaitEvent)>(
    name: &str,
    token: &str,
    timeout: Option<u64>,
    on_event: F,
) -> Result<ProcWaitEvent> {
    validate(name)?;
    emit_vsock_rpc_audit(
        name,
        &GuestRequest::ProcWait {
            pid_token: token.to_string(),
            timeout_secs: timeout,
        },
    );
    if let Some(dir) = mock_agent_dir(name) {
        return mvm_agentd::vsock::send_proc_wait(&dir, token, timeout, on_event);
    }
    mvm_agentd::vsock::send_proc_wait_on(&mut connect(name)?, token, timeout, on_event)
}

// ── filesystem ───────────────────────────────────────────────────────────

/// Send one filesystem RPC.
pub fn fs_request(name: &str, request: GuestRequest) -> Result<FsResult> {
    validate(name)?;
    if let Some(dir) = mock_agent_dir(name) {
        return mvm_agentd::vsock::send_fs_request(&dir, request);
    }
    mvm_agentd::vsock::send_fs_request_on(&mut connect(name)?, request)
}

/// Fail on the agent's error variant, naming its kind.
pub fn unwrap_fs(result: FsResult) -> Result<FsResult> {
    if let FsResult::Error { kind, message } = &result {
        bail!("Guest FS error ({kind:?}): {message}");
    }
    Ok(result)
}

/// The `FsRead` request for one chunk.
pub fn fs_read_request(
    path: &str,
    offset: u64,
    length: u64,
    follow_symlinks: bool,
) -> GuestRequest {
    GuestRequest::FsRead {
        path: path.to_string(),
        offset: Some(offset),
        length,
        follow_symlinks,
    }
}

/// Read up to `length` bytes of `path` from `start_offset`, in wire-sized
/// chunks, stopping early at end of file.
pub fn read_file_chunks(
    name: &str,
    path: &str,
    start_offset: u64,
    length: u64,
    follow_symlinks: bool,
) -> Result<Vec<u8>> {
    let chunk_cap = u64::try_from(mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE)
        .context("wire chunk size fits u64")?;
    let capacity = usize::try_from(length).unwrap_or(usize::MAX);
    let mut content = Vec::with_capacity(capacity.min(mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE));
    let mut offset = start_offset;
    let mut remaining = length;
    while remaining > 0 {
        let requested = remaining.min(chunk_cap);
        let request = fs_read_request(path, offset, requested, follow_symlinks);
        emit_vsock_rpc_audit(name, &request);
        match unwrap_fs(fs_request(name, request)?)? {
            FsResult::Read {
                content: chunk,
                total_size,
            } => {
                let chunk_len = u64::try_from(chunk.len()).context("chunk length fits u64")?;
                if chunk_len > requested {
                    bail!("Guest read returned a chunk larger than requested");
                }
                content.extend_from_slice(&chunk);
                offset = offset
                    .checked_add(chunk_len)
                    .ok_or_else(|| anyhow::anyhow!("Guest read offset overflow"))?;
                remaining -= chunk_len;
                if chunk_len < requested || offset >= total_size {
                    break;
                }
            }
            other => bail!("Unexpected FsResult variant for Read: {other:?}"),
        }
    }
    Ok(content)
}

/// How to write a guest file.
#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// Mode for a file the write creates.
    pub mode: u32,
    /// Create missing parent directories.
    pub create_parents: bool,
    /// Follow a symlink at `path` rather than refusing it.
    pub follow_symlinks: bool,
}

/// Write `content` to `path`, replacing it, in wire-sized chunks. Records
/// only the per-chunk RPC entries: the caller records what the write was for
/// (a file write, or one side of a copy). Returns the bytes written.
pub fn write_file_chunks(
    name: &str,
    path: &str,
    content: &[u8],
    options: WriteOptions,
) -> Result<u64> {
    let mut offset = 0_u64;
    for (index, chunk) in content
        .chunks(mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE)
        .chain(content.is_empty().then_some(content))
        .enumerate()
    {
        let request = GuestRequest::FsWrite {
            path: path.to_string(),
            content: chunk.to_vec(),
            mode: options.mode,
            create_parents: options.create_parents && index == 0,
            follow_symlinks: options.follow_symlinks,
            offset: Some(offset),
            truncate: index == 0,
        };
        emit_vsock_rpc_audit(name, &request);
        match unwrap_fs(fs_request(name, request)?)? {
            FsResult::Write { bytes_written } => {
                let expected = u64::try_from(chunk.len()).context("chunk length fits u64")?;
                if bytes_written != expected {
                    bail!("Guest wrote {bytes_written} bytes, expected {expected}");
                }
                offset = offset
                    .checked_add(bytes_written)
                    .ok_or_else(|| anyhow::anyhow!("Guest write offset overflow"))?;
            }
            other => bail!("Unexpected FsResult variant for Write: {other:?}"),
        }
    }
    Ok(offset)
}

/// Write a guest file and record it as a filesystem change.
pub fn write_file(name: &str, path: &str, content: &[u8], options: WriteOptions) -> Result<u64> {
    let bytes_written = write_file_chunks(name, path, content, options)?;
    mvm_core::audit_emit!(VmFsMutate, vm: name, "op=write path={path} bytes={bytes_written}");
    Ok(bytes_written)
}

/// A directory listing, and whether the agent capped it.
#[derive(Debug, Clone)]
pub struct Listing {
    pub entries: Vec<FsEntry>,
    pub truncated: bool,
}

/// List a guest directory, following a symlink at `path`.
pub fn list_dir(name: &str, path: &str) -> Result<Listing> {
    let request = GuestRequest::FsList {
        path: path.to_string(),
        follow_symlinks: true,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_fs(fs_request(name, request)?)? {
        FsResult::List { entries, truncated } => Ok(Listing { entries, truncated }),
        other => bail!("Unexpected FsResult variant for List: {other:?}"),
    }
}

/// Stat a guest path.
pub fn stat(name: &str, path: &str, follow_symlinks: bool) -> Result<FsStat> {
    let request = GuestRequest::FsStat {
        path: path.to_string(),
        follow_symlinks,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_fs(fs_request(name, request)?)? {
        FsResult::Stat(stat) => Ok(stat),
        other => bail!("Unexpected FsResult variant for Stat: {other:?}"),
    }
}

/// Create a guest directory.
pub fn make_dir(name: &str, path: &str, mode: u32, parents: bool) -> Result<()> {
    let request = GuestRequest::FsMkdir {
        path: path.to_string(),
        mode,
        parents,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_fs(fs_request(name, request)?)? {
        FsResult::Mkdir => {
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=mkdir path={path} mode={mode:o} parents={parents}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Mkdir: {other:?}"),
    }
}

/// Remove a guest path, never following a symlink at it. Returns the number
/// of entries removed.
pub fn remove(name: &str, path: &str, recursive: bool) -> Result<u64> {
    let request = GuestRequest::FsRemove {
        path: path.to_string(),
        recursive,
        follow_symlinks: false,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_fs(fs_request(name, request)?)? {
        FsResult::Remove { entries_removed } => {
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=rm path={path} recursive={recursive} entries={entries_removed}");
            Ok(entries_removed)
        }
        other => bail!("Unexpected FsResult variant for Remove: {other:?}"),
    }
}

/// Move a guest path, never following a symlink at either end.
pub fn rename(name: &str, from: &str, to: &str) -> Result<()> {
    let request = GuestRequest::FsMove {
        from: from.to_string(),
        to: to.to_string(),
        follow_symlinks: false,
    };
    emit_vsock_rpc_audit(name, &request);
    match unwrap_fs(fs_request(name, request)?)? {
        FsResult::Move => {
            mvm_core::audit_emit!(VmFsMutate, vm: name, "op=mv from={from} to={to}");
            Ok(())
        }
        other => bail!("Unexpected FsResult variant for Move: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_request_preserves_the_symlink_policy() {
        let request = fs_read_request("/deps/site.py", 8, 16, false);
        assert!(matches!(
            request,
            GuestRequest::FsRead {
                path,
                offset: Some(8),
                length: 16,
                follow_symlinks: false,
            } if path == "/deps/site.py"
        ));
    }

    /// The RPC entry composes with every common verb.
    #[test]
    fn the_rpc_audit_accepts_every_common_verb() {
        let cases = [
            GuestRequest::Ping,
            GuestRequest::ReadinessStatus,
            GuestRequest::EntrypointStatus,
            GuestRequest::FsDiff,
            GuestRequest::Exec {
                command: "echo hello".to_string(),
                stdin: None,
                timeout_secs: Some(30),
            },
        ];
        for request in cases {
            emit_vsock_rpc_audit("vm-test", &request);
        }
    }

    #[test]
    fn starting_an_empty_argv_is_refused_before_any_rpc() {
        let err = start_process("vm-test", ProcStart::default()).expect_err("empty argv");
        assert!(err.to_string().contains("argv cannot be empty"), "{err:#}");
    }

    fn start_with_env(name: &str, allow: &[&str]) -> ProcStart {
        ProcStart {
            argv: vec!["/bin/true".to_string()],
            env: BTreeMap::from([(name.to_string(), "/tmp/payload".to_string())]),
            cwd: None,
            allow_env: mvm_core::env_hygiene::EnvReadmit::from_names(allow).expect("exact names"),
        }
    }

    #[test]
    fn a_denied_variable_is_refused_before_any_rpc() {
        for name in ["LD_PRELOAD", "BASH_ENV", "PYTHONSTARTUP", "BW_SESSION"] {
            let err = start_process("../escape", start_with_env(name, &[])).expect_err(name);
            let message = format!("{err:#}");
            assert!(message.contains(name), "{message}");
            assert!(
                message.contains("refused environment variable"),
                "{message}"
            );
            assert!(!message.contains("/tmp/payload"), "{message}");
        }
    }

    #[test]
    fn a_readmitted_variable_passes_the_filter() {
        let err = start_process("../escape", start_with_env("LD_PRELOAD", &["LD_PRELOAD"]))
            .expect_err("the invalid machine name still refuses");
        assert!(
            !format!("{err:#}").contains("refused environment variable"),
            "{err:#}"
        );
    }

    #[test]
    fn an_invalid_machine_name_is_refused_before_any_rpc() {
        assert!(proc_request("../escape", GuestRequest::ProcList).is_err());
        assert!(fs_request("../escape", GuestRequest::FsDiff).is_err());
        assert!(wait_process("../escape", "t", None, |_| {}).is_err());
    }

    #[test]
    fn an_agent_error_is_an_error() {
        let err = unwrap_fs(FsResult::Error {
            kind: mvm_agentd::vsock::FsErrorKind::NotFound,
            message: "nope".into(),
        })
        .expect_err("error variant");
        assert!(err.to_string().contains("nope"), "{err:#}");
    }
}
