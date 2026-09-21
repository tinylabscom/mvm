//! The `guest.*` methods: process and file operations on a running machine.
//!
//! Every method names the machine by `id` and goes through
//! `mvm_client::guest`, the implementation `mvmctl machine proc`/`fs` use, so
//! a call records the same audit entries whichever surface made it. These are
//! DevOnly guest-agent verbs; the agent refuses them on a sealed image, and
//! that refusal reaches the binding as a `BACKEND` error carrying the agent's
//! message.
//!
//! Byte payloads cross as base64, because JSON strings are not byte strings.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_agentd::vsock::{FsEntry, FsStat, ProcInfo, ProcWaitEvent};
use mvm_client::guest::{Listing, ProcStart, WriteOptions};
use serde::{Deserialize, Serialize};

use crate::status::Outcome;

/// Starts a process. Request: `{"id", "argv", "env"?, "cwd"?}`. Reply:
/// `{"token"}`.
pub const PROC_START: &str = "guest.proc.start";
/// Lists tracked processes. Request: `{"id"}`. Reply: an array of process
/// records.
pub const PROC_LIST: &str = "guest.proc.list";
/// Signals a process. Request: `{"id", "token", "signum"}`. Reply: `{}`.
pub const PROC_SIGNAL: &str = "guest.proc.signal";
/// Kills a process. Request: `{"id", "token"}`. Reply: `{}`.
pub const PROC_KILL: &str = "guest.proc.kill";
/// Writes a process's stdin. Request: `{"id", "token", "data_b64"}`. Reply:
/// `{"accepted"}`.
pub const PROC_STDIN: &str = "guest.proc.stdin";
/// Waits for a process to end. Request: `{"id", "token", "timeout_secs"?}`.
/// Reply: `{"stdout_b64", "stderr_b64", "truncated", "outcome"}`.
pub const PROC_WAIT: &str = "guest.proc.wait";
/// Reads a file. Request: `{"id", "path", "offset"?, "length",
/// "follow_symlinks"?}`. Reply: `{"data_b64"}`.
pub const FS_READ: &str = "guest.fs.read";
/// Writes a file. Request: `{"id", "path", "data_b64", "mode"?,
/// "create_parents"?, "follow_symlinks"?}`. Reply: `{"bytes_written"}`.
pub const FS_WRITE: &str = "guest.fs.write";
/// Lists a directory. Request: `{"id", "path"}`. Reply: `{"entries",
/// "truncated"}`.
pub const FS_LIST: &str = "guest.fs.list";
/// Stats a path. Request: `{"id", "path", "follow_symlinks"?}`. Reply: a stat
/// record.
pub const FS_STAT: &str = "guest.fs.stat";
/// Creates a directory. Request: `{"id", "path", "mode"?, "parents"?}`.
/// Reply: `{}`.
pub const FS_MKDIR: &str = "guest.fs.mkdir";
/// Removes a path. Request: `{"id", "path", "recursive"?}`. Reply:
/// `{"entries_removed"}`.
pub const FS_REMOVE: &str = "guest.fs.remove";
/// Moves a path. Request: `{"id", "from", "to"}`. Reply: `{}`.
pub const FS_RENAME: &str = "guest.fs.rename";
/// Copies a file between the host and the guest. Request: `{"id",
/// "direction", "host_path", "guest_path"}`. Reply: `{}`.
pub const CP: &str = "guest.cp";

/// Every `guest.*` method.
pub const METHODS: [&str; 14] = [
    PROC_START,
    PROC_LIST,
    PROC_SIGNAL,
    PROC_KILL,
    PROC_STDIN,
    PROC_WAIT,
    FS_READ,
    FS_WRITE,
    FS_LIST,
    FS_STAT,
    FS_MKDIR,
    FS_REMOVE,
    FS_RENAME,
    CP,
];

/// The most output of each stream `guest.proc.wait` holds. One call returns
/// once, so it buffers; past this the rest of the stream is dropped and the
/// reply says so, rather than growing the host process without bound.
pub const WAIT_OUTPUT_CAP: usize = 8 * 1024 * 1024;

/// Mode for a file or directory a request creates when it names none.
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o755;

/// The guest operations the methods call. One production implementation,
/// over `mvm_client::guest`; the tests use a recording double, so dispatch is
/// checkable without a running machine.
pub(crate) trait GuestOps {
    fn start_process(&self, id: &str, start: ProcStart) -> Result<String>;
    fn list_processes(&self, id: &str) -> Result<Vec<ProcInfo>>;
    fn signal_process(&self, id: &str, token: &str, signum: i32) -> Result<()>;
    fn kill_process(&self, id: &str, token: &str) -> Result<()>;
    fn send_process_input(&self, id: &str, token: &str, bytes: &[u8]) -> Result<u64>;
    fn wait_process(
        &self,
        id: &str,
        token: &str,
        timeout: Option<u64>,
        on_event: &mut dyn FnMut(&ProcWaitEvent),
    ) -> Result<ProcWaitEvent>;
    fn read_file(
        &self,
        id: &str,
        path: &str,
        offset: u64,
        length: u64,
        follow: bool,
    ) -> Result<Vec<u8>>;
    fn write_file(
        &self,
        id: &str,
        path: &str,
        content: &[u8],
        options: WriteOptions,
    ) -> Result<u64>;
    fn list_dir(&self, id: &str, path: &str) -> Result<Listing>;
    fn stat(&self, id: &str, path: &str, follow: bool) -> Result<FsStat>;
    fn make_dir(&self, id: &str, path: &str, mode: u32, parents: bool) -> Result<()>;
    fn remove(&self, id: &str, path: &str, recursive: bool) -> Result<u64>;
    fn rename(&self, id: &str, from: &str, to: &str) -> Result<()>;
}

/// The guest operations on this host's machines.
pub(crate) struct LocalGuest;

impl GuestOps for LocalGuest {
    fn start_process(&self, id: &str, start: ProcStart) -> Result<String> {
        mvm_client::guest::start_process(id, start)
    }
    fn list_processes(&self, id: &str) -> Result<Vec<ProcInfo>> {
        mvm_client::guest::list_processes(id)
    }
    fn signal_process(&self, id: &str, token: &str, signum: i32) -> Result<()> {
        mvm_client::guest::signal_process(id, token, signum)
    }
    fn kill_process(&self, id: &str, token: &str) -> Result<()> {
        mvm_client::guest::kill_process(id, token)
    }
    fn send_process_input(&self, id: &str, token: &str, bytes: &[u8]) -> Result<u64> {
        mvm_client::guest::send_process_input(id, token, bytes)
    }
    fn wait_process(
        &self,
        id: &str,
        token: &str,
        timeout: Option<u64>,
        on_event: &mut dyn FnMut(&ProcWaitEvent),
    ) -> Result<ProcWaitEvent> {
        mvm_client::guest::wait_process(id, token, timeout, on_event)
    }
    fn read_file(
        &self,
        id: &str,
        path: &str,
        offset: u64,
        length: u64,
        follow: bool,
    ) -> Result<Vec<u8>> {
        mvm_client::guest::read_file_chunks(id, path, offset, length, follow)
    }
    fn write_file(
        &self,
        id: &str,
        path: &str,
        content: &[u8],
        options: WriteOptions,
    ) -> Result<u64> {
        mvm_client::guest::write_file(id, path, content, options)
    }
    fn list_dir(&self, id: &str, path: &str) -> Result<Listing> {
        mvm_client::guest::list_dir(id, path)
    }
    fn stat(&self, id: &str, path: &str, follow: bool) -> Result<FsStat> {
        mvm_client::guest::stat(id, path, follow)
    }
    fn make_dir(&self, id: &str, path: &str, mode: u32, parents: bool) -> Result<()> {
        mvm_client::guest::make_dir(id, path, mode, parents)
    }
    fn remove(&self, id: &str, path: &str, recursive: bool) -> Result<u64> {
        mvm_client::guest::remove(id, path, recursive)
    }
    fn rename(&self, id: &str, from: &str, to: &str) -> Result<()> {
        mvm_client::guest::rename(id, from, to)
    }
}

// ── requests ─────────────────────────────────────────────────────────────

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartRequest {
    id: String,
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MachineRequest {
    id: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignalRequest {
    id: String,
    token: String,
    signum: i32,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessRequest {
    id: String,
    token: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StdinRequest {
    id: String,
    token: String,
    data_b64: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WaitRequest {
    id: String,
    token: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadRequest {
    id: String,
    path: String,
    #[serde(default)]
    offset: u64,
    length: u64,
    #[serde(default = "follow_by_default")]
    follow_symlinks: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WriteRequest {
    id: String,
    path: String,
    data_b64: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    create_parents: bool,
    #[serde(default)]
    follow_symlinks: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathRequest {
    id: String,
    path: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatRequest {
    id: String,
    path: String,
    #[serde(default = "follow_by_default")]
    follow_symlinks: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MkdirRequest {
    id: String,
    path: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    parents: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveRequest {
    id: String,
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameRequest {
    id: String,
    from: String,
    to: String,
}

/// Which way `guest.cp` moves the file.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CopyDirection {
    /// Read the host file, write it into the guest.
    HostToGuest,
    /// Read the guest file, write it to the host.
    GuestToHost,
}

/// A `guest.cp` request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CopyRequest {
    id: String,
    direction: CopyDirection,
    host_path: String,
    guest_path: String,
}

fn follow_by_default() -> bool {
    true
}

// ── replies ──────────────────────────────────────────────────────────────

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct Empty {}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct StartedReply {
    token: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct AcceptedReply {
    accepted: u64,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct DataReply {
    data_b64: String,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct WrittenReply {
    bytes_written: u64,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct ListReply {
    entries: Vec<FsEntry>,
    truncated: bool,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct RemovedReply {
    entries_removed: u64,
}

/// How a waited-on process ended.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum WaitOutcome {
    Exited { code: i32 },
    Killed { signal: i32 },
    TimedOut,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Serialize)]
pub(crate) struct WaitReply {
    stdout_b64: String,
    stderr_b64: String,
    /// Output past [`WAIT_OUTPUT_CAP`] on either stream was dropped.
    truncated: bool,
    outcome: WaitOutcome,
}

/// Output collected from a wait, bounded per stream.
#[derive(Default)]
struct WaitOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

impl WaitOutput {
    fn push(&mut self, event: &ProcWaitEvent) {
        let (buffer, chunk) = match event {
            ProcWaitEvent::Stdout { chunk } => (&mut self.stdout, chunk),
            ProcWaitEvent::Stderr { chunk } => (&mut self.stderr, chunk),
            _ => return,
        };
        let room = WAIT_OUTPUT_CAP.saturating_sub(buffer.len());
        if chunk.len() > room {
            self.truncated = true;
        }
        buffer.extend_from_slice(&chunk[..chunk.len().min(room)]);
    }
}

// ── dispatch ─────────────────────────────────────────────────────────────

/// Whether `method` is a `guest.*` method this library answers.
pub(crate) fn is_known(method: &str) -> bool {
    METHODS.contains(&method)
}

/// Answer the `guest.*` method `method` using `ops`.
pub(crate) fn dispatch(ops: &dyn GuestOps, method: &str, request: &[u8]) -> Outcome {
    match answer(ops, method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(ops: &dyn GuestOps, method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    Ok(match method {
        PROC_START => {
            let r: StartRequest = parse(request)?;
            let token = ops
                .start_process(
                    &r.id,
                    ProcStart {
                        argv: r.argv,
                        env: r.env,
                        cwd: r.cwd,
                    },
                )
                .map_err(guest_error)?;
            Outcome::ok(&StartedReply { token })
        }
        PROC_LIST => {
            let r: MachineRequest = parse(request)?;
            Outcome::ok(&ops.list_processes(&r.id).map_err(guest_error)?)
        }
        PROC_SIGNAL => {
            let r: SignalRequest = parse(request)?;
            ops.signal_process(&r.id, &r.token, r.signum)
                .map_err(guest_error)?;
            Outcome::ok(&Empty {})
        }
        PROC_KILL => {
            let r: ProcessRequest = parse(request)?;
            ops.kill_process(&r.id, &r.token).map_err(guest_error)?;
            Outcome::ok(&Empty {})
        }
        PROC_STDIN => {
            let r: StdinRequest = parse(request)?;
            let bytes = decode(&r.data_b64)?;
            let accepted = ops
                .send_process_input(&r.id, &r.token, &bytes)
                .map_err(guest_error)?;
            Outcome::ok(&AcceptedReply { accepted })
        }
        PROC_WAIT => {
            let r: WaitRequest = parse(request)?;
            let mut output = WaitOutput::default();
            let terminal = ops
                .wait_process(&r.id, &r.token, r.timeout_secs, &mut |event| {
                    output.push(event)
                })
                .map_err(guest_error)?;
            let outcome = match terminal {
                ProcWaitEvent::Exit { code } => WaitOutcome::Exited { code },
                ProcWaitEvent::Killed { signal } => WaitOutcome::Killed { signal },
                ProcWaitEvent::TimedOut => WaitOutcome::TimedOut,
                ProcWaitEvent::Error { kind, message } => {
                    return Err(guest_error(anyhow::anyhow!(
                        "ProcWait error ({kind:?}): {message}"
                    )));
                }
                other => {
                    return Err(guest_error(anyhow::anyhow!(
                        "unexpected terminal wait event: {other:?}"
                    )));
                }
            };
            Outcome::ok(&WaitReply {
                stdout_b64: B64.encode(&output.stdout),
                stderr_b64: B64.encode(&output.stderr),
                truncated: output.truncated,
                outcome,
            })
        }
        FS_READ => {
            let r: ReadRequest = parse(request)?;
            let data = ops
                .read_file(&r.id, &r.path, r.offset, r.length, r.follow_symlinks)
                .map_err(guest_error)?;
            Outcome::ok(&DataReply {
                data_b64: B64.encode(data),
            })
        }
        FS_WRITE => {
            let r: WriteRequest = parse(request)?;
            let bytes = decode(&r.data_b64)?;
            let bytes_written = ops
                .write_file(
                    &r.id,
                    &r.path,
                    &bytes,
                    WriteOptions {
                        mode: r.mode.unwrap_or(DEFAULT_FILE_MODE),
                        create_parents: r.create_parents,
                        follow_symlinks: r.follow_symlinks,
                    },
                )
                .map_err(guest_error)?;
            Outcome::ok(&WrittenReply { bytes_written })
        }
        FS_LIST => {
            let r: PathRequest = parse(request)?;
            let Listing { entries, truncated } =
                ops.list_dir(&r.id, &r.path).map_err(guest_error)?;
            Outcome::ok(&ListReply { entries, truncated })
        }
        FS_STAT => {
            let r: StatRequest = parse(request)?;
            Outcome::ok(
                &ops.stat(&r.id, &r.path, r.follow_symlinks)
                    .map_err(guest_error)?,
            )
        }
        FS_MKDIR => {
            let r: MkdirRequest = parse(request)?;
            ops.make_dir(
                &r.id,
                &r.path,
                r.mode.unwrap_or(DEFAULT_DIR_MODE),
                r.parents,
            )
            .map_err(guest_error)?;
            Outcome::ok(&Empty {})
        }
        FS_REMOVE => {
            let r: RemoveRequest = parse(request)?;
            let entries_removed = ops
                .remove(&r.id, &r.path, r.recursive)
                .map_err(guest_error)?;
            Outcome::ok(&RemovedReply { entries_removed })
        }
        FS_RENAME => {
            let r: RenameRequest = parse(request)?;
            ops.rename(&r.id, &r.from, &r.to).map_err(guest_error)?;
            Outcome::ok(&Empty {})
        }
        CP => {
            let r: CopyRequest = parse(request)?;
            copy_file(ops, &r).map_err(guest_error)?;
            Outcome::ok(&Empty {})
        }
        other => return Err(Outcome::invalid_input(&format!("unknown method `{other}`"))),
    })
}

/// Move one file across the host/guest boundary, composing the copy from
/// the read and write operations so both directions record the same audit
/// entries as every other guest file operation. The guest side rides the
/// chunked fs RPC, so any file size travels wire-sized pieces.
fn copy_file(ops: &dyn GuestOps, request: &CopyRequest) -> Result<()> {
    const CHUNK: u64 = mvm_agentd::vsock::MAX_DATA_CHUNK_SIZE as u64;
    match request.direction {
        CopyDirection::HostToGuest => {
            let content = std::fs::read(&request.host_path)
                .with_context(|| format!("reading {}", request.host_path))?;
            let written = ops.write_file(
                &request.id,
                &request.guest_path,
                &content,
                WriteOptions {
                    mode: DEFAULT_FILE_MODE,
                    create_parents: true,
                    follow_symlinks: false,
                },
            )?;
            anyhow::ensure!(
                written == content.len() as u64,
                "guest accepted {written} of {} bytes",
                content.len()
            );
            Ok(())
        }
        CopyDirection::GuestToHost => {
            let mut content = Vec::new();
            let mut offset = 0_u64;
            loop {
                let piece =
                    ops.read_file(&request.id, &request.guest_path, offset, CHUNK, false)?;
                let last = piece.len() < CHUNK as usize;
                offset += piece.len() as u64;
                content.extend_from_slice(&piece);
                if last {
                    break;
                }
            }
            std::fs::write(&request.host_path, &content)
                .with_context(|| format!("writing {}", request.host_path))?;
            Ok(())
        }
    }
}

fn parse<T: serde::de::DeserializeOwned>(request: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(request)
        .map_err(|e| Outcome::invalid_input(&format!("request did not parse: {e}")))
}

fn decode(data_b64: &str) -> Result<Vec<u8>, Outcome> {
    B64.decode(data_b64)
        .map_err(|e| Outcome::invalid_input(&format!("data_b64 is not base64: {e}")))
}

/// A guest operation that failed: the agent refused it, the transport could
/// not reach the machine, or the machine name was invalid. All are the
/// backend's answer to the request, so they carry its code.
fn guest_error(error: anyhow::Error) -> Outcome {
    Outcome::from(mvm_core::client::MvmError::Backend {
        reason: format!("{error:#}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{MVM_HOSTLIB_BACKEND, MVM_HOSTLIB_INVALID_INPUT, MVM_HOSTLIB_OK};
    use std::cell::RefCell;

    /// Records each call it receives and answers from fixed values, so a test
    /// sees exactly what dispatch passed down.
    #[derive(Default)]
    struct Recording {
        calls: RefCell<Vec<String>>,
        wait_events: Vec<ProcWaitEvent>,
        fail: bool,
    }

    impl Recording {
        fn note(&self, call: String) -> Result<()> {
            self.calls.borrow_mut().push(call);
            if self.fail {
                anyhow::bail!("the agent refused");
            }
            Ok(())
        }
    }

    impl GuestOps for Recording {
        fn start_process(&self, id: &str, start: ProcStart) -> Result<String> {
            self.note(format!(
                "start {id} {:?} {:?} {:?}",
                start.argv, start.env, start.cwd
            ))?;
            Ok("tok-1".into())
        }
        fn list_processes(&self, id: &str) -> Result<Vec<ProcInfo>> {
            self.note(format!("list {id}"))?;
            Ok(Vec::new())
        }
        fn signal_process(&self, id: &str, token: &str, signum: i32) -> Result<()> {
            self.note(format!("signal {id} {token} {signum}"))
        }
        fn kill_process(&self, id: &str, token: &str) -> Result<()> {
            self.note(format!("kill {id} {token}"))
        }
        fn send_process_input(&self, id: &str, token: &str, bytes: &[u8]) -> Result<u64> {
            self.note(format!("stdin {id} {token} {bytes:?}"))?;
            Ok(bytes.len() as u64)
        }
        fn wait_process(
            &self,
            id: &str,
            token: &str,
            timeout: Option<u64>,
            on_event: &mut dyn FnMut(&ProcWaitEvent),
        ) -> Result<ProcWaitEvent> {
            self.note(format!("wait {id} {token} {timeout:?}"))?;
            let (terminal, streamed) = self
                .wait_events
                .split_last()
                .expect("a wait fixture ends in a terminal event");
            for event in streamed {
                on_event(event);
            }
            Ok(terminal.clone())
        }
        fn read_file(
            &self,
            id: &str,
            path: &str,
            offset: u64,
            length: u64,
            follow: bool,
        ) -> Result<Vec<u8>> {
            self.note(format!("read {id} {path} {offset} {length} {follow}"))?;
            Ok(b"hello".to_vec())
        }
        fn write_file(
            &self,
            id: &str,
            path: &str,
            content: &[u8],
            options: WriteOptions,
        ) -> Result<u64> {
            self.note(format!(
                "write {id} {path} {content:?} {:o} {} {}",
                options.mode, options.create_parents, options.follow_symlinks
            ))?;
            Ok(content.len() as u64)
        }
        fn list_dir(&self, id: &str, path: &str) -> Result<Listing> {
            self.note(format!("ls {id} {path}"))?;
            Ok(Listing {
                entries: Vec::new(),
                truncated: false,
            })
        }
        fn stat(&self, id: &str, path: &str, follow: bool) -> Result<FsStat> {
            self.note(format!("stat {id} {path} {follow}"))?;
            anyhow::bail!("no such path")
        }
        fn make_dir(&self, id: &str, path: &str, mode: u32, parents: bool) -> Result<()> {
            self.note(format!("mkdir {id} {path} {mode:o} {parents}"))
        }
        fn remove(&self, id: &str, path: &str, recursive: bool) -> Result<u64> {
            self.note(format!("rm {id} {path} {recursive}"))?;
            Ok(3)
        }
        fn rename(&self, id: &str, from: &str, to: &str) -> Result<()> {
            self.note(format!("mv {id} {from} {to}"))
        }
    }

    fn call(ops: &Recording, method: &str, request: serde_json::Value) -> (i32, serde_json::Value) {
        let outcome = dispatch(ops, method, &serde_json::to_vec(&request).unwrap());
        let body = serde_json::from_slice(&outcome.body).unwrap_or(serde_json::Value::Null);
        (outcome.status, body)
    }

    #[test]
    fn a_start_passes_argv_env_and_cwd_through_and_returns_the_token() {
        let ops = Recording::default();
        let (status, body) = call(
            &ops,
            PROC_START,
            serde_json::json!({"id": "web", "argv": ["ls", "-l"], "env": {"A": "1"}, "cwd": "/w"}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body, serde_json::json!({"token": "tok-1"}));
        assert_eq!(
            ops.calls.borrow().as_slice(),
            [r#"start web ["ls", "-l"] {"A": "1"} Some("/w")"#]
        );
    }

    #[test]
    fn stdin_and_write_decode_their_base64_payloads() {
        let ops = Recording::default();
        let data = B64.encode(b"abc");
        let (status, body) = call(
            &ops,
            PROC_STDIN,
            serde_json::json!({"id": "web", "token": "t", "data_b64": data}),
        );
        assert_eq!(
            (status, body),
            (MVM_HOSTLIB_OK, serde_json::json!({"accepted": 3}))
        );
        let (status, body) = call(
            &ops,
            FS_WRITE,
            serde_json::json!({"id": "web", "path": "/f", "data_b64": data}),
        );
        assert_eq!(
            (status, body),
            (MVM_HOSTLIB_OK, serde_json::json!({"bytes_written": 3}))
        );
        assert_eq!(
            ops.calls.borrow().last().unwrap(),
            "write web /f [97, 98, 99] 644 false false",
            "a write names no mode, so the default applies, and never follows a symlink by default"
        );
    }

    #[test]
    fn a_payload_that_is_not_base64_is_refused_before_any_call() {
        let ops = Recording::default();
        let (status, _) = call(
            &ops,
            FS_WRITE,
            serde_json::json!({"id": "web", "path": "/f", "data_b64": "***"}),
        );
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
        assert!(ops.calls.borrow().is_empty());
    }

    #[test]
    fn a_read_returns_base64_and_follows_symlinks_unless_told_not_to() {
        let ops = Recording::default();
        let (status, body) = call(
            &ops,
            FS_READ,
            serde_json::json!({"id": "web", "path": "/f", "length": 5}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body["data_b64"], B64.encode(b"hello"));
        assert_eq!(ops.calls.borrow().last().unwrap(), "read web /f 0 5 true");
    }

    #[test]
    fn a_wait_collects_output_and_reports_how_the_process_ended() {
        let ops = Recording {
            wait_events: vec![
                ProcWaitEvent::Stdout {
                    chunk: b"out".to_vec(),
                },
                ProcWaitEvent::Stderr {
                    chunk: b"err".to_vec(),
                },
                ProcWaitEvent::Exit { code: 7 },
            ],
            ..Recording::default()
        };
        let (status, body) = call(
            &ops,
            PROC_WAIT,
            serde_json::json!({"id": "web", "token": "t", "timeout_secs": 30}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body["stdout_b64"], B64.encode(b"out"));
        assert_eq!(body["stderr_b64"], B64.encode(b"err"));
        assert_eq!(body["truncated"], false);
        assert_eq!(
            body["outcome"],
            serde_json::json!({"kind": "exited", "code": 7})
        );
    }

    /// Output past the cap is dropped and the reply says so, rather than the
    /// host process buffering without bound.
    #[test]
    fn a_wait_stops_buffering_at_the_cap_and_says_so() {
        let ops = Recording {
            wait_events: vec![
                ProcWaitEvent::Stdout {
                    chunk: vec![b'x'; WAIT_OUTPUT_CAP],
                },
                ProcWaitEvent::Stdout {
                    chunk: b"more".to_vec(),
                },
                ProcWaitEvent::TimedOut,
            ],
            ..Recording::default()
        };
        let (status, body) = call(
            &ops,
            PROC_WAIT,
            serde_json::json!({"id": "web", "token": "t"}),
        );
        assert_eq!(status, MVM_HOSTLIB_OK);
        assert_eq!(body["truncated"], true);
        let stdout = B64.decode(body["stdout_b64"].as_str().unwrap()).unwrap();
        assert_eq!(stdout.len(), WAIT_OUTPUT_CAP);
        assert_eq!(body["outcome"], serde_json::json!({"kind": "timed_out"}));
    }

    #[test]
    fn an_agent_error_ending_a_wait_is_a_backend_error() {
        let ops = Recording {
            wait_events: vec![ProcWaitEvent::Error {
                kind: mvm_agentd::vsock::ProcErrorKind::UnknownToken,
                message: "unknown token".into(),
            }],
            ..Recording::default()
        };
        let (status, body) = call(
            &ops,
            PROC_WAIT,
            serde_json::json!({"id": "web", "token": "t"}),
        );
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert!(body["message"].as_str().unwrap().contains("unknown token"));
    }

    /// A refusal from the agent (a sealed image, say) reaches the binding as
    /// the backend's answer, carrying the agent's message.
    #[test]
    fn a_failed_operation_is_a_backend_error_with_its_message() {
        let ops = Recording {
            fail: true,
            ..Recording::default()
        };
        let (status, body) = call(
            &ops,
            PROC_KILL,
            serde_json::json!({"id": "web", "token": "t"}),
        );
        assert_eq!(status, MVM_HOSTLIB_BACKEND);
        assert_eq!(body["code"], "BACKEND_ERROR");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("the agent refused")
        );
    }

    #[test]
    fn mkdir_and_remove_and_rename_pass_their_arguments_through() {
        let ops = Recording::default();
        assert_eq!(
            call(
                &ops,
                FS_MKDIR,
                serde_json::json!({"id": "web", "path": "/d", "parents": true})
            )
            .0,
            MVM_HOSTLIB_OK
        );
        let (status, body) = call(
            &ops,
            FS_REMOVE,
            serde_json::json!({"id": "web", "path": "/d", "recursive": true}),
        );
        assert_eq!(
            (status, body),
            (MVM_HOSTLIB_OK, serde_json::json!({"entries_removed": 3}))
        );
        assert_eq!(
            call(
                &ops,
                FS_RENAME,
                serde_json::json!({"id": "web", "from": "/a", "to": "/b"})
            )
            .0,
            MVM_HOSTLIB_OK
        );
        assert_eq!(
            ops.calls.borrow().as_slice(),
            ["mkdir web /d 755 true", "rm web /d true", "mv web /a /b"]
        );
    }

    #[test]
    fn cp_host_to_guest_reads_the_host_file_and_writes_the_guest() {
        let dir = std::env::temp_dir().join(format!("mvm-hostlib-cp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let host_path = dir.join("payload.bin");
        std::fs::write(&host_path, b"copy me").expect("write host file");
        let ops = Recording::default();
        let request = serde_json::to_vec(&serde_json::json!({
            "id": "web",
            "direction": "host_to_guest",
            "host_path": host_path,
            "guest_path": "/tmp/payload.bin",
        }))
        .unwrap();
        let outcome = dispatch(&ops, CP, &request);
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_OK,
            "{}",
            String::from_utf8_lossy(&outcome.body)
        );
        let calls = ops.calls.borrow();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(
            calls[0].starts_with("write web /tmp/payload.bin [99, 111, 112, 121, 32, 109, 101]"),
            "{calls:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cp_guest_to_host_reads_until_a_short_chunk_and_writes_the_host() {
        let dir = std::env::temp_dir().join(format!("mvm-hostlib-cp-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let host_path = dir.join("out.bin");
        let ops = Recording::default();
        let request = serde_json::to_vec(&serde_json::json!({
            "id": "web",
            "direction": "guest_to_host",
            "host_path": host_path,
            "guest_path": "/var/out.bin",
        }))
        .unwrap();
        let outcome = dispatch(&ops, CP, &request);
        assert_eq!(
            outcome.status,
            MVM_HOSTLIB_OK,
            "{}",
            String::from_utf8_lossy(&outcome.body)
        );
        // Recording answers five bytes per read; a five-byte chunk is short,
        // so one read ends the copy.
        assert_eq!(std::fs::read(&host_path).expect("host file"), b"hello");
        let calls = ops.calls.borrow();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].starts_with("read web /var/out.bin 0"), "{calls:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cp_refuses_an_unknown_direction() {
        let ops = Recording::default();
        let request = serde_json::to_vec(&serde_json::json!({
            "id": "web",
            "direction": "sideways",
            "host_path": "/a",
            "guest_path": "/b",
        }))
        .unwrap();
        let outcome = dispatch(&ops, CP, &request);
        assert_eq!(outcome.status, MVM_HOSTLIB_INVALID_INPUT);
    }

    #[test]
    fn an_unknown_request_field_is_refused_before_any_call() {
        let ops = Recording::default();
        let (status, _) = call(
            &ops,
            PROC_KILL,
            serde_json::json!({"id": "web", "token": "t", "force": true}),
        );
        assert_eq!(status, MVM_HOSTLIB_INVALID_INPUT);
        assert!(ops.calls.borrow().is_empty());
    }

    #[test]
    fn every_listed_method_is_known_and_answered() {
        for method in METHODS {
            assert!(is_known(method), "{method}");
        }
        assert!(!is_known("guest.shell"));
    }

    /// Through the real implementation, an invalid machine name is refused by
    /// `mvm_client::guest` before any RPC, and reaches the binding as an error.
    #[test]
    fn the_local_implementation_refuses_an_invalid_machine_name() {
        let outcome = dispatch(&LocalGuest, PROC_LIST, br#"{"id": "../escape"}"#);
        assert_eq!(outcome.status, MVM_HOSTLIB_BACKEND);
    }
}
