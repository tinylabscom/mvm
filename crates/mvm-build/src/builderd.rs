//! Request-handling core of the resident builder-VM daemon
//! (`mvm-builderd`).
//!
//! This module is the cross-platform, unit-testable heart of the
//! daemon: it turns a decoded [`BuilderRequest`] into a
//! [`BuilderResponse`] ([`dispatch`]) and runs the read-dispatch-write
//! loop over a framed connection ([`serve_connection`]). The binary
//! entrypoint and the Linux AF_VSOCK listener are deliberately *not*
//! here — they land with the builder-VM boot wiring. Keeping the core
//! in the library lets it be driven from a `UnixStream` pair in tests
//! without booting the builder VM.
//!
//! ## Skeleton scope
//!
//! Only [`BuilderRequest::Handshake`] and [`BuilderRequest::Probe`] are
//! fully served (plus a no-op [`BuilderRequest::CancelJob`]
//! acknowledgement, since nothing is in flight yet). The real build/eval
//! operations are recognized and answered with a fail-closed
//! [`BuilderResponse::Failed`] / [`FailureCategory::Unsupported`] until
//! their handlers land. This is honest: a client gets a typed "this
//! daemon build does not implement that operation" rather than a hang or
//! a silently-dropped request.

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::builderd_protocol::{
    BuilderRequest, BuilderResponse, FailureCategory, OperationId, PROTOCOL_VERSION,
    handshake_reply,
};

/// Map one [`BuilderRequest`] to its [`BuilderResponse`]. Pure and
/// stateless: the skeleton daemon holds no per-connection or
/// cross-request state yet, so a handshake/probe is answered the same
/// regardless of order. Stateful "must handshake first" enforcement and
/// real operation handlers are later slices.
pub fn dispatch(request: &BuilderRequest) -> BuilderResponse {
    match request {
        BuilderRequest::Handshake { protocol_version } => handshake_reply(*protocol_version),

        BuilderRequest::Probe { op } => BuilderResponse::Accepted {
            op: *op,
            protocol_version: PROTOCOL_VERSION,
        },

        // Nothing is in flight in the skeleton, so a cancel for any id
        // is a no-op the daemon still acknowledges — matching the
        // protocol contract that cancelling an unknown/finished id is a
        // benign ack rather than an error.
        BuilderRequest::CancelJob { target } => BuilderResponse::Cancelled { op: *target },

        // Recognized build/eval operations whose handlers have not
        // landed yet. Fail closed with a typed Unsupported category so
        // the host shows an actionable message and does not retry.
        BuilderRequest::FlakeCheck { op, .. }
        | BuilderRequest::BuildGuestImage { op, .. }
        | BuilderRequest::BuildHostTool { op, .. }
        | BuilderRequest::PrefetchSource { op, .. }
        | BuilderRequest::QueryStorePath { op, .. } => unsupported(*op, request),
    }
}

/// Build the fail-closed [`BuilderResponse::Failed`] for a recognized
/// but not-yet-implemented operation.
fn unsupported(op: OperationId, request: &BuilderRequest) -> BuilderResponse {
    BuilderResponse::Failed {
        op,
        category: FailureCategory::Unsupported,
        message: format!(
            "operation {} is not implemented by this builder daemon",
            request_kind(request)
        ),
        retryable: false,
    }
}

/// The snake_case wire tag for a request, for use in human-readable
/// messages. Cheap and allocation-free; reuses the serde tag so the
/// message and the wire stay in lock-step.
fn request_kind(request: &BuilderRequest) -> &'static str {
    match request {
        BuilderRequest::Handshake { .. } => "handshake",
        BuilderRequest::Probe { .. } => "probe",
        BuilderRequest::FlakeCheck { .. } => "flake_check",
        BuilderRequest::BuildGuestImage { .. } => "build_guest_image",
        BuilderRequest::BuildHostTool { .. } => "build_host_tool",
        BuilderRequest::PrefetchSource { .. } => "prefetch_source",
        BuilderRequest::QueryStorePath { .. } => "query_store_path",
        BuilderRequest::CancelJob { .. } => "cancel_job",
    }
}

/// Serve one control connection, dispatching each request through
/// `dispatch_one`: read framed [`BuilderRequest`]s, write each framed
/// [`BuilderResponse`] back, until the peer closes the connection (clean
/// EOF).
///
/// Framing reuses [`mvm_agentd::vsock::read_frame`] /
/// [`mvm_agentd::vsock::write_frame`], inheriting the 256 KiB
/// pre-deserialize cap. A clean EOF before a frame starts is the normal
/// end-of-connection and returns `Ok(())`. A malformed/oversized frame
/// or a write failure returns the underlying error so the caller can
/// log it and drop the connection — the daemon keeps serving other
/// connections.
fn serve_loop(
    stream: &mut UnixStream,
    mut dispatch_one: impl FnMut(&BuilderRequest) -> BuilderResponse,
) -> std::io::Result<()> {
    loop {
        match mvm_agentd::vsock::read_frame::<BuilderRequest>(stream) {
            Ok(request) => {
                let response = dispatch_one(&request);
                mvm_agentd::vsock::write_frame(stream, &response)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            Err(e) => {
                // A clean EOF at a frame boundary is the expected end of
                // a connection, not an error. `read_frame` surfaces it
                // as an io::Error with kind UnexpectedEof chained
                // underneath anyhow; walk the chain to classify.
                if let Some(io_err) = e.source().and_then(|s| s.downcast_ref::<std::io::Error>())
                    && io_err.kind() == ErrorKind::UnexpectedEof
                {
                    return Ok(());
                }
                return Err(std::io::Error::other(e.to_string()));
            }
        }
    }
}

/// Serve one control connection with the stateless [`dispatch`] (no
/// operation executor): build/eval operations answer
/// [`FailureCategory::Unsupported`]. Used where the daemon has no
/// builder-side execution context (the skeleton path and tests).
pub fn serve_connection(stream: &mut UnixStream) -> std::io::Result<()> {
    serve_loop(stream, dispatch)
}

/// Serve one control connection with an [`OpExecutor`] so recognized
/// build/eval operations actually run inside the builder VM (e.g.
/// [`BuilderRequest::FlakeCheck`] → `nix flake check`). Operations
/// without a handler still answer [`FailureCategory::Unsupported`].
pub fn serve_connection_with_executor(
    stream: &mut UnixStream,
    executor: &dyn OpExecutor,
) -> std::io::Result<()> {
    serve_loop(stream, |request| dispatch_with_executor(request, executor))
}

// ============================================================================
// Typed operation execution (builder-VM side)
// ============================================================================

/// Result of running an operation's subprocess inside the builder VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpExecResult {
    /// Process exit code (0 = success).
    pub exit_code: i32,
    /// Captured stdout. Build/eval operations read their output here —
    /// e.g. the `/nix/store/...` path `nix build --print-out-paths`
    /// emits, or the `storePath` JSON `nix flake prefetch --json` emits.
    /// These commands print paths, not bulk data; the build log proper
    /// streams as `LogChunk`s.
    pub stdout: String,
    /// Tail of the process's stderr, capped by the caller, for the
    /// failure message. Never the full stream — that goes out as
    /// streamed [`BuilderResponse::LogChunk`]s by the daemon.
    pub stderr_tail: String,
}

/// Runs a builder operation's subprocess (Nix/Linux-only work) inside
/// the builder VM. Injected so the dispatch logic is unit-testable
/// without spawning a real process; the daemon supplies
/// [`CommandExecutor`].
pub trait OpExecutor {
    /// Run `argv` (argv[0] is the program) and return its exit code and
    /// a bounded stderr tail.
    fn run(&self, argv: &[String]) -> std::io::Result<OpExecResult>;
}

/// Production [`OpExecutor`] that spawns the program with
/// [`std::process::Command`]. The daemon uses this inside the builder
/// VM, where `nix` is on `PATH`; on a developer host the program is
/// absent and `run` returns an `Err`, which dispatch maps to a typed
/// [`FailureCategory::Internal`] failure.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandExecutor;

/// Writable `HOME`/XDG locations the daemon's `nix` needs inside the builder
/// VM. The rootfs is mounted read-only, so without these `nix` dies creating
/// its cache under `//.cache`. Mirrors the env the in-VM shell build script
/// exports: the cache sits on the persistent `/nix-store` overlay so eval and
/// tarball caches survive across builds, while state stays on `/tmp` tmpfs.
const BUILDERD_NIX_ENV: [(&str, &str); 3] = [
    ("HOME", "/tmp"),
    ("XDG_CACHE_HOME", "/nix-store/.cache"),
    ("XDG_STATE_HOME", "/tmp/.local/state"),
];

/// Persistent cache/state dirs the daemon creates before a `nix` run so the
/// first build can write them (the shell build script `mkdir -p`s the same).
const BUILDERD_NIX_DIRS: [&str; 2] = ["/nix-store/.cache", "/tmp/.local/state"];

/// The env a daemon command needs: the writable `HOME`/XDG contract for `nix`
/// (the only program the daemon spawns), nothing for anything else. Pure so the
/// contract is unit-tested without executing Nix.
fn daemon_command_env(program: &str) -> &'static [(&'static str, &'static str)] {
    if program == "nix" {
        &BUILDERD_NIX_ENV
    } else {
        &[]
    }
}

impl OpExecutor for CommandExecutor {
    fn run(&self, argv: &[String]) -> std::io::Result<OpExecResult> {
        let (program, rest) = argv
            .split_first()
            .ok_or_else(|| std::io::Error::other("empty argv"))?;
        let mut cmd = std::process::Command::new(program);
        cmd.args(rest);
        let env = daemon_command_env(program);
        if !env.is_empty() {
            for dir in BUILDERD_NIX_DIRS {
                let _ = std::fs::create_dir_all(dir);
            }
            cmd.envs(env.iter().copied());
        }
        let output = cmd.output()?;
        Ok(OpExecResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr_tail: tail_lines(&String::from_utf8_lossy(&output.stderr), 20),
        })
    }
}

/// Keep at most the last `n` lines of `text`, joined with newlines, so a
/// failure message stays bounded.
fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Experimental Nix features every daemon `nix` invocation requires
/// (`nix-command` for the new CLI, `flakes` for flake refs). The daemon
/// passes them explicitly rather than relying on the builder image's
/// `nix.conf`, so its commands are correct regardless of the image's
/// global Nix configuration.
const NIX_EXPERIMENTAL_FEATURES: &str = "nix-command flakes";

/// The leading `nix --extra-experimental-features …` tokens shared by
/// every daemon Nix invocation, followed by `args`.
fn nix_argv(args: &[&str]) -> Vec<String> {
    let mut argv = vec![
        "nix".to_string(),
        "--extra-experimental-features".to_string(),
        NIX_EXPERIMENTAL_FEATURES.to_string(),
    ];
    argv.extend(args.iter().map(|a| a.to_string()));
    argv
}

/// The `nix flake check` argv the daemon runs for a
/// [`BuilderRequest::FlakeCheck`]. Pure so the command shape is
/// unit-tested without executing Nix. `--no-build` keeps it an
/// evaluation check (fast, no derivation realisation).
pub fn flake_check_argv(flake_path: &str) -> Vec<String> {
    let target = flake_ref_target(flake_path);
    nix_argv(&["flake", "check", "--no-build", &target])
}

/// Turn a caller-supplied flake reference into a nix-ready target. A
/// scheme-qualified ref (`github:…`, `path:…`, `git+https:…` — anything nix
/// already understands as a flake URL) passes through unchanged; a bare
/// filesystem path is wrapped in `path:` so nix treats it as a path flake.
/// Wrapping a scheme ref (the prior unconditional `path:{flake}`) produced
/// `path:github:…`, which nix reads as a non-existent path.
fn flake_ref_target(flake: &str) -> String {
    if has_uri_scheme(flake) {
        flake.to_string()
    } else {
        format!("path:{flake}")
    }
}

/// True if `s` begins with a URI scheme (`alpha (alnum|+|-|.)* ':'`), the way
/// nix flake refs are scheme-qualified. A bare path (`/work/nix`, `.`, `./x`)
/// has none.
fn has_uri_scheme(s: &str) -> bool {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for (i, c) in chars {
        if c == ':' {
            return i > 0;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return false;
        }
    }
    false
}

/// Map a flake-check process result to its terminal response: a clean
/// exit is [`BuilderResponse::Completed`]; a non-zero exit is a
/// [`FailureCategory::NixEval`] failure carrying the stderr tail.
fn flake_check_outcome(op: OperationId, result: &OpExecResult) -> BuilderResponse {
    if result.exit_code == 0 {
        BuilderResponse::Completed { op }
    } else {
        BuilderResponse::Failed {
            op,
            category: FailureCategory::NixEval,
            message: format!(
                "nix flake check failed (exit {}): {}",
                result.exit_code, result.stderr_tail
            ),
            retryable: false,
        }
    }
}

/// Run a [`BuilderRequest::FlakeCheck`] through `executor` and classify
/// the result. An executor error (e.g. `nix` not found) is a typed
/// retryable [`FailureCategory::Internal`] failure, distinct from a
/// flake that evaluated and failed.
pub fn dispatch_flake_check(
    op: OperationId,
    flake_path: &str,
    executor: &dyn OpExecutor,
) -> BuilderResponse {
    match executor.run(&flake_check_argv(flake_path)) {
        Ok(result) => flake_check_outcome(op, &result),
        Err(e) => BuilderResponse::Failed {
            op,
            category: FailureCategory::Internal,
            message: format!("failed to run nix flake check: {e}"),
            retryable: true,
        },
    }
}

/// The `nix build` argv for a [`BuilderRequest::BuildGuestImage`] /
/// [`BuilderRequest::BuildHostTool`]. `--no-link` skips the `result`
/// symlink and `--print-out-paths` writes the realised `/nix/store/...`
/// path(s) to stdout so the daemon can report provenance. Pure for
/// testing.
pub fn nix_build_argv(flake_ref: &str, attr_path: &str) -> Vec<String> {
    let target = format!("{flake_ref}#{attr_path}");
    nix_argv(&["build", &target, "--no-link", "--print-out-paths"])
}

/// The last non-empty line of `stdout` — the store path
/// `nix build --print-out-paths` emits last. Trims surrounding
/// whitespace.
fn last_out_path(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(String::from)
}

/// Map a `nix build` result to its terminal response. A clean exit with
/// an out-path is [`BuilderResponse::ArtifactReady`] (the artifact lives
/// at the store path, reachable via the builder VM's `/nix`; a
/// copy-to-mounted-output step is a later addition). A non-zero exit is
/// a [`FailureCategory::NixBuild`] failure.
fn nix_build_outcome(op: OperationId, result: &OpExecResult) -> BuilderResponse {
    if result.exit_code != 0 {
        return BuilderResponse::Failed {
            op,
            category: FailureCategory::NixBuild,
            message: format!(
                "nix build failed (exit {}): {}",
                result.exit_code, result.stderr_tail
            ),
            retryable: false,
        };
    }
    match last_out_path(&result.stdout) {
        Some(path) => BuilderResponse::ArtifactReady {
            op,
            artifact_path: path.clone(),
            store_path: Some(path),
        },
        None => BuilderResponse::Failed {
            op,
            category: FailureCategory::NixBuild,
            message: "nix build succeeded but printed no out-path".to_string(),
            retryable: false,
        },
    }
}

/// Run a `nix build` (shared by [`BuilderRequest::BuildGuestImage`] and
/// [`BuilderRequest::BuildHostTool`]) through `executor` and classify
/// the result. An executor error is a retryable
/// [`FailureCategory::Internal`] failure.
pub fn dispatch_nix_build(
    op: OperationId,
    flake_ref: &str,
    attr_path: &str,
    output_dir: Option<&str>,
    executor: &dyn OpExecutor,
) -> BuilderResponse {
    let outcome = match executor.run(&nix_build_argv(flake_ref, attr_path)) {
        Ok(result) => nix_build_outcome(op, &result),
        Err(e) => {
            return BuilderResponse::Failed {
                op,
                category: FailureCategory::Internal,
                message: format!("failed to run nix build: {e}"),
                retryable: true,
            };
        }
    };
    // When the host asked for an export dir (a path under the `/job` share),
    // copy the image's host-facing artifacts (kernel + rootfs) out of the nix
    // store so the host can read them — the typed equivalent of the legacy
    // cmd.sh `cp -L "$NIX_OUT/..." /out/...` block. The reported `artifact_path`
    // then points at the host-readable dir; `store_path` stays the in-store
    // path for provenance.
    match (&outcome, output_dir) {
        (
            BuilderResponse::ArtifactReady {
                store_path: Some(store_path),
                ..
            },
            Some(out),
        ) => match export_image_artifacts(Path::new(store_path), Path::new(out)) {
            Ok(()) => BuilderResponse::ArtifactReady {
                op,
                artifact_path: out.to_string(),
                store_path: Some(store_path.clone()),
            },
            Err(e) => BuilderResponse::Failed {
                op,
                category: FailureCategory::NixBuild,
                message: format!("exporting image artifacts to {out}: {e}"),
                retryable: false,
            },
        },
        _ => outcome,
    }
}

/// Copy a built guest image's host-facing artifacts out of the nix store into
/// `output_dir` (a directory on a host-shared mount), so the host can read
/// `vmlinux` + `rootfs.ext4` without reaching into the builder's store. Mirrors
/// the legacy `render_flake_cmd_sh` copy block: an out-path that is itself a
/// file is the rootfs; an out-path that is a directory carries the kernel under
/// `vmlinux`/`Image`/`bzImage` plus `rootfs.ext4`.
///
/// Before the rootfs is copied to `output_dir`, a writable copy is mounted and
/// the `before_build` lifecycle hook (`/etc/mvm/hooks/before_build.sh`) is run
/// inside it. The hook is baked into workload rootfses by
/// `mkFunctionService.nix`; if the script is absent (e.g., a host-tool image) it
/// is treated as a no-op by the runner.
fn export_image_artifacts(nix_out: &Path, output_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("create {}: {e}", output_dir.display()))?;
    let meta =
        std::fs::metadata(nix_out).map_err(|e| format!("stat {}: {e}", nix_out.display()))?;
    if meta.is_file() {
        copy_rootfs_with_hook(nix_out, &output_dir.join("rootfs.ext4"))?;
        return Ok(());
    }
    if let Some(kernel) = ["vmlinux", "Image", "bzImage"]
        .iter()
        .map(|n| nix_out.join(n))
        .find(|p| p.is_file())
    {
        copy_artifact(&kernel, &output_dir.join("vmlinux"))?;
    }
    let rootfs = nix_out.join("rootfs.ext4");
    if rootfs.is_file() {
        copy_rootfs_with_hook(&rootfs, &output_dir.join("rootfs.ext4"))?;
    } else {
        return Err(format!("no rootfs.ext4 in {}", nix_out.display()));
    }
    Ok(())
}

/// Copy `src_rootfs` to `dst`, running the `before_build` hook on a writable
/// temp copy first. The temp copy lives on `/tmp` inside the builder VM so the
/// original Nix store output is never modified.
fn copy_rootfs_with_hook(src_rootfs: &Path, dst: &Path) -> Result<(), String> {
    let tmp = tempfile::NamedTempFile::with_suffix(".ext4")
        .map_err(|e| format!("create temp rootfs copy: {e}"))?;
    let tmp_path = tmp.path().to_path_buf();
    std::fs::copy(src_rootfs, &tmp_path).map_err(|e| {
        format!(
            "copy {} -> {}: {e}",
            src_rootfs.display(),
            tmp_path.display()
        )
    })?;
    run_before_build_hook(&tmp_path)?;
    copy_artifact(&tmp_path, dst)?;
    let _ = tmp.close();
    Ok(())
}

/// Run the builder-VM before_build hook runner on `rootfs_path`.
///
/// If the runner binary is not present (e.g., unit tests driving
/// `export_image_artifacts` on a dev host), the hook is skipped. The
/// binary is always baked into the builder VM rootfs in production.
fn run_before_build_hook(rootfs_path: &Path) -> Result<(), String> {
    run_builder_rootfs_command("run-before-build-hook", rootfs_path)
}

fn run_builder_rootfs_command(command: &str, rootfs_path: &Path) -> Result<(), String> {
    let runner = std::path::Path::new("/sbin/mvm-host-vm-init");
    if !runner.is_file() {
        return Ok(());
    }
    let status = std::process::Command::new(runner)
        .arg(command)
        .arg(rootfs_path)
        .status()
        .map_err(|e| format!("spawn rootfs command {command}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "rootfs command {command} failed (exit {:?})",
            status.code()
        ))
    }
}

/// Copy one artifact, dereferencing symlinks (nix store paths are read-only
/// symlink farms), with a path-named error.
fn copy_artifact(src: &Path, dst: &Path) -> Result<(), String> {
    let permissions = std::fs::metadata(src)
        .map_err(|e| format!("stat {}: {e}", src.display()))?
        .permissions();
    let mut source =
        std::fs::File::open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    let mut output =
        std::fs::File::create(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    std::io::copy(&mut source, &mut output)
        .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
    output
        .set_permissions(permissions)
        .map_err(|e| format!("set permissions on {}: {e}", dst.display()))?;
    output
        .sync_all()
        .map_err(|e| format!("sync {}: {e}", dst.display()))
}

/// The `nix flake prefetch --json` argv for a
/// [`BuilderRequest::PrefetchSource`]. `--json` makes the resolved
/// `storePath` machine-readable on stdout.
pub fn prefetch_source_argv(source_ref: &str) -> Vec<String> {
    nix_argv(&["flake", "prefetch", source_ref, "--json"])
}

/// Extract `storePath` from `nix flake prefetch --json` stdout.
fn parse_prefetch_store_path(stdout: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(stdout)
        .ok()?
        .get("storePath")?
        .as_str()
        .map(String::from)
}

/// Run a [`BuilderRequest::PrefetchSource`] through `executor`. Success
/// is [`BuilderResponse::StorePathReady`] (prefetch ensures presence, so
/// `already_present` is reported `false`). A non-zero exit is a
/// retryable [`FailureCategory::Fetch`] failure (network/missing input);
/// an executor error is a retryable [`FailureCategory::Internal`].
pub fn dispatch_prefetch_source(
    op: OperationId,
    source_ref: &str,
    executor: &dyn OpExecutor,
) -> BuilderResponse {
    let result = match executor.run(&prefetch_source_argv(source_ref)) {
        Ok(result) => result,
        Err(e) => {
            return BuilderResponse::Failed {
                op,
                category: FailureCategory::Internal,
                message: format!("failed to run nix flake prefetch: {e}"),
                retryable: true,
            };
        }
    };
    if result.exit_code != 0 {
        return BuilderResponse::Failed {
            op,
            category: FailureCategory::Fetch,
            message: format!(
                "nix flake prefetch failed (exit {}): {}",
                result.exit_code, result.stderr_tail
            ),
            retryable: true,
        };
    }
    match parse_prefetch_store_path(&result.stdout) {
        Some(store_path) => BuilderResponse::StorePathReady {
            op,
            store_path,
            already_present: false,
        },
        None => BuilderResponse::Failed {
            op,
            category: FailureCategory::Fetch,
            message: "nix flake prefetch produced no storePath".to_string(),
            retryable: false,
        },
    }
}

/// The `nix path-info` argv for a [`BuilderRequest::QueryStorePath`]. It
/// exits zero iff the path is a valid, present store path.
pub fn query_store_path_argv(store_path: &str) -> Vec<String> {
    nix_argv(&["path-info", store_path])
}

/// Run a [`BuilderRequest::QueryStorePath`] through `executor`. The
/// query itself always succeeds: a clean exit means the path is present
/// (`already_present = true`), a non-zero exit means absent
/// (`already_present = false`) — both are [`BuilderResponse::StorePathReady`].
/// Only an executor (spawn) error is a failure.
pub fn dispatch_query_store_path(
    op: OperationId,
    store_path: &str,
    executor: &dyn OpExecutor,
) -> BuilderResponse {
    match executor.run(&query_store_path_argv(store_path)) {
        Ok(result) => BuilderResponse::StorePathReady {
            op,
            store_path: store_path.to_string(),
            already_present: result.exit_code == 0,
        },
        Err(e) => BuilderResponse::Failed {
            op,
            category: FailureCategory::Internal,
            message: format!("failed to run nix path-info: {e}"),
            retryable: true,
        },
    }
}

/// Dispatch with an [`OpExecutor`]: recognized build/eval operations
/// that have a handler run through the executor; everything else falls
/// back to the stateless [`dispatch`] (Handshake / Probe / CancelJob).
pub fn dispatch_with_executor(
    request: &BuilderRequest,
    executor: &dyn OpExecutor,
) -> BuilderResponse {
    match request {
        BuilderRequest::FlakeCheck { op, flake_path } => {
            dispatch_flake_check(*op, flake_path, executor)
        }
        BuilderRequest::BuildGuestImage {
            op,
            flake_ref,
            attr_path,
            // The cache short-circuit on `fingerprint` is a later
            // addition; this handler always builds.
            fingerprint: _,
            output_dir,
        } => dispatch_nix_build(*op, flake_ref, attr_path, output_dir.as_deref(), executor),
        BuilderRequest::BuildHostTool {
            op,
            flake_ref,
            attr_path,
            fingerprint: _,
            // Host tools have no image-artifact export (no kernel/rootfs).
        } => dispatch_nix_build(*op, flake_ref, attr_path, None, executor),
        BuilderRequest::PrefetchSource { op, source_ref } => {
            dispatch_prefetch_source(*op, source_ref, executor)
        }
        BuilderRequest::QueryStorePath { op, store_path } => {
            dispatch_query_store_path(*op, store_path, executor)
        }
        other => dispatch(other),
    }
}

// ============================================================================
// Host-side client (readiness probe)
// ============================================================================

/// The **libkrun**-shape control socket for a builder VM rooted at
/// `vm_state_dir`: normally `<vm_state_dir>/vsock-<port>.sock`. libkrun binds
/// one socket per forwarded port directly in the resolved socket directory;
/// deep state paths use the short namespace selected by
/// `mvm_core::config::vm_socket_dir_at` (matching
/// `persistent_builder::dispatch_socket_path`).
///
/// HVF nests its per-port sockets one level deeper, under a `vsock/`
/// subdir — use [`builderd_hvf_control_socket_path`] there, or
/// [`builderd_control_socket_candidates`] when the backend is unknown
/// (e.g. scanning the builder-VM `vms/` root). Mixing the two shapes is
/// the libkrun-vs-HVF socket-path bug class that has bitten the broker
/// path before.
pub fn builderd_control_socket_path(vm_state_dir: &Path) -> PathBuf {
    mvm_core::config::vm_vsock_port_socket_at(
        vm_state_dir,
        mvm_agentd::builder_agent::BUILDERD_CONTROL_PORT,
    )
}

/// The **HVF**-shape control socket for a builder VM rooted at
/// `vm_state_dir`: normally `<vm_state_dir>/vsock/vsock-<port>.sock`. The HVF
/// supervisor nests per-port sockets under a `vsock/` subdir of the resolved
/// socket directory (see `mvm_core::config::vm_hvf_vsock_dir_at`).
pub fn builderd_hvf_control_socket_path(vm_state_dir: &Path) -> PathBuf {
    mvm_core::config::vm_hvf_vsock_port_socket_at(
        vm_state_dir,
        mvm_agentd::builder_agent::BUILDERD_CONTROL_PORT,
    )
}

/// Both candidate control-socket paths (libkrun shape, then HVF shape)
/// for a builder VM rooted at `vm_state_dir`. Use when the backend isn't
/// known up front — e.g. `mvmctl doctor` scanning the builder-VM `vms/`
/// root, where a dir may be a libkrun or an HVF builder VM. Probe whichever
/// exists.
pub fn builderd_control_socket_candidates(vm_state_dir: &Path) -> [PathBuf; 2] {
    [
        builderd_control_socket_path(vm_state_dir),
        builderd_hvf_control_socket_path(vm_state_dir),
    ]
}

/// Outcome of a host-side readiness probe against a builder daemon's
/// control socket. Surfaced by `mvmctl doctor` and used by the host
/// client to decide whether the daemon is usable before sending real
/// operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderdReadiness {
    /// The daemon answered a handshake and agreed a protocol version.
    Ready {
        /// Protocol version the daemon speaks.
        version: u32,
    },
    /// The daemon answered but refused our protocol version
    /// (fail-closed). The daemon and host need a compatible build.
    VersionMismatch {
        /// The daemon's human-readable refusal detail.
        detail: String,
    },
    /// No control socket exists — the daemon is not running (e.g. the
    /// builder VM is down). The expected first-run state; non-blocking.
    NotRunning,
    /// A control socket exists but the daemon did not complete a clean
    /// handshake (connect refused, timed out, or answered unexpectedly).
    /// Usually a stale socket from a crashed daemon.
    Unreachable {
        /// Diagnostic detail for the operator.
        detail: String,
    },
}

/// Connect to a daemon control socket and arm both read and write
/// timeouts. Shared by the readiness probe and the host client so the
/// connect convention lives in one place.
pub(crate) fn connect_with_timeout(
    socket_path: &Path,
    timeout: Duration,
) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Classified outcome of the protocol handshake on a connected stream.
/// Shared by the readiness probe and the host client so the handshake
/// wire is interpreted in exactly one place.
pub(crate) enum HandshakeOutcome {
    /// Daemon agreed on this protocol version.
    Agreed(u32),
    /// Daemon refused our version fail-closed; detail is its message.
    VersionRefused(String),
    /// Connected, but the reply was not a handshake answer.
    Unexpected(String),
    /// Transport error writing or reading the handshake.
    Transport(String),
}

/// Write our [`BuilderRequest::Handshake`] on an already-connected
/// stream (timeouts pre-armed by the caller), read one reply, and
/// classify it.
pub(crate) fn perform_handshake(stream: &mut UnixStream) -> HandshakeOutcome {
    let handshake = BuilderRequest::Handshake {
        protocol_version: PROTOCOL_VERSION,
    };
    if let Err(e) = mvm_agentd::vsock::write_frame(stream, &handshake) {
        return HandshakeOutcome::Transport(format!("handshake write failed: {e}"));
    }
    match mvm_agentd::vsock::read_frame::<BuilderResponse>(stream) {
        Ok(BuilderResponse::Accepted {
            protocol_version, ..
        }) => HandshakeOutcome::Agreed(protocol_version),
        Ok(BuilderResponse::Failed {
            category: FailureCategory::Version,
            message,
            ..
        }) => HandshakeOutcome::VersionRefused(message),
        Ok(other) => {
            HandshakeOutcome::Unexpected(format!("unexpected handshake response: {other:?}"))
        }
        Err(e) => HandshakeOutcome::Transport(format!("handshake read failed: {e}")),
    }
}

/// Probe a builder daemon's readiness by connecting to `socket_path`
/// and completing a [`BuilderRequest::Handshake`] within `timeout`.
///
/// Pure transport over the typed protocol — no side effects beyond the
/// connection. A missing socket is [`BuilderdReadiness::NotRunning`]
/// (the normal "builder VM down" case), so callers treat absence as
/// informational, not a failure.
pub fn probe_builderd_readiness(socket_path: &Path, timeout: Duration) -> BuilderdReadiness {
    if !socket_path.exists() {
        return BuilderdReadiness::NotRunning;
    }
    let mut stream = match connect_with_timeout(socket_path, timeout) {
        Ok(s) => s,
        Err(e) => {
            return BuilderdReadiness::Unreachable {
                detail: format!("connect failed: {e}"),
            };
        }
    };
    match perform_handshake(&mut stream) {
        HandshakeOutcome::Agreed(version) => BuilderdReadiness::Ready { version },
        HandshakeOutcome::VersionRefused(detail) => BuilderdReadiness::VersionMismatch { detail },
        HandshakeOutcome::Unexpected(detail) | HandshakeOutcome::Transport(detail) => {
            BuilderdReadiness::Unreachable { detail }
        }
    }
}

/// One-line human summary of a [`BuilderdReadiness`] for `mvmctl
/// doctor`. Pure so the mapping is unit-testable without a socket.
pub fn readiness_summary(readiness: &BuilderdReadiness) -> String {
    match readiness {
        BuilderdReadiness::Ready { version } => format!("ready (protocol v{version})"),
        BuilderdReadiness::VersionMismatch { detail } => format!("version mismatch — {detail}"),
        BuilderdReadiness::NotRunning => "not running".to_string(),
        BuilderdReadiness::Unreachable { detail } => format!("unreachable — {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn op() -> OperationId {
        OperationId(Uuid::nil())
    }

    // ---- command env ---------------------------------------------------

    #[test]
    fn daemon_command_env_gives_nix_writable_home_and_xdg() {
        // The read-only rootfs has no writable `HOME`; without these the
        // daemon's `nix` dies creating `//.cache/nix`. The cache must sit on
        // the persistent `/nix-store` overlay, mirroring the shell build script.
        assert_eq!(
            daemon_command_env("nix"),
            &[
                ("HOME", "/tmp"),
                ("XDG_CACHE_HOME", "/nix-store/.cache"),
                ("XDG_STATE_HOME", "/tmp/.local/state"),
            ]
        );
    }

    #[test]
    fn daemon_command_env_is_empty_for_non_nix_programs() {
        assert!(daemon_command_env("ls").is_empty());
        assert!(daemon_command_env("/sbin/mvm-builderd").is_empty());
    }

    // ---- dispatch ------------------------------------------------------

    #[test]
    fn dispatch_handshake_accepts_supported_version() {
        let resp = dispatch(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        });
        assert!(matches!(
            resp,
            BuilderResponse::Accepted {
                protocol_version,
                ..
            } if protocol_version == PROTOCOL_VERSION
        ));
    }

    #[test]
    fn dispatch_handshake_refuses_bad_version() {
        let resp = dispatch(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION + 1,
        });
        assert!(matches!(
            resp,
            BuilderResponse::Failed {
                category: FailureCategory::Version,
                ..
            }
        ));
    }

    #[test]
    fn dispatch_probe_echoes_op() {
        let resp = dispatch(&BuilderRequest::Probe { op: op() });
        match resp {
            BuilderResponse::Accepted {
                op: got,
                protocol_version,
            } => {
                assert_eq!(got, op());
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_cancel_acks() {
        let resp = dispatch(&BuilderRequest::CancelJob { target: op() });
        assert!(matches!(resp, BuilderResponse::Cancelled { op: got } if got == op()));
    }

    #[test]
    fn dispatch_unimplemented_ops_fail_unsupported_and_echo_op() {
        let cases = [
            BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
            BuilderRequest::BuildGuestImage {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
                fingerprint: None,
                output_dir: None,
            },
            BuilderRequest::BuildHostTool {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.mvm-host-vm-init".to_string(),
                fingerprint: None,
            },
            BuilderRequest::PrefetchSource {
                op: op(),
                source_ref: "github:nixos/nixpkgs".to_string(),
            },
            BuilderRequest::QueryStorePath {
                op: op(),
                store_path: "/nix/store/aaaa-foo".to_string(),
            },
        ];
        for req in cases {
            match dispatch(&req) {
                BuilderResponse::Failed {
                    op: got,
                    category,
                    retryable,
                    ..
                } => {
                    assert_eq!(got, op());
                    assert_eq!(category, FailureCategory::Unsupported);
                    assert!(!retryable);
                }
                other => panic!("expected Failed/Unsupported for {req:?}, got {other:?}"),
            }
        }
    }

    // ---- serve_connection ---------------------------------------------

    /// Drive a request through the serve loop over a `UnixStream` pair
    /// and read back the single response. Single-threaded: the client
    /// writes one request, half-closes its write side so the loop sees
    /// EOF after that frame, the loop serves it and exits, then we read
    /// the buffered response.
    fn roundtrip_one(request: &BuilderRequest) -> BuilderResponse {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_agentd::vsock::write_frame(&mut client, request).expect("write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close write");
        serve_connection(&mut server).expect("serve");
        mvm_agentd::vsock::read_frame::<BuilderResponse>(&mut client).expect("read response")
    }

    #[test]
    fn serve_handshake_over_the_wire() {
        let resp = roundtrip_one(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        });
        assert!(matches!(resp, BuilderResponse::Accepted { .. }));
    }

    #[test]
    fn serve_probe_over_the_wire() {
        let resp = roundtrip_one(&BuilderRequest::Probe { op: op() });
        assert!(matches!(resp, BuilderResponse::Accepted { op: got, .. } if got == op()));
    }

    #[test]
    fn serve_handles_multiple_requests_then_clean_eof() {
        // Two requests on one connection, then EOF. The loop must
        // answer both and return Ok on the clean close.
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_agentd::vsock::write_frame(
            &mut client,
            &BuilderRequest::Handshake {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .expect("write handshake");
        mvm_agentd::vsock::write_frame(&mut client, &BuilderRequest::Probe { op: op() })
            .expect("write probe");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close write");

        serve_connection(&mut server).expect("serve returns Ok on clean eof");

        let first = mvm_agentd::vsock::read_frame::<BuilderResponse>(&mut client).expect("first");
        let second = mvm_agentd::vsock::read_frame::<BuilderResponse>(&mut client).expect("second");
        assert!(matches!(first, BuilderResponse::Accepted { .. }));
        assert!(matches!(second, BuilderResponse::Accepted { op: got, .. } if got == op()));
    }

    #[test]
    fn serve_returns_ok_on_immediate_eof() {
        // A peer that connects and closes without sending anything is a
        // normal, non-error end of connection.
        let (client, mut server) = UnixStream::pair().expect("socketpair");
        drop(client);
        serve_connection(&mut server).expect("immediate eof is Ok");
    }

    // ---- typed operation execution (FlakeCheck) -----------------------

    /// A scripted executor: returns a fixed result, or an error, and
    /// records the argv it was asked to run.
    struct FakeExecutor {
        result: std::io::Result<OpExecResult>,
        seen: std::cell::RefCell<Option<Vec<String>>>,
    }

    impl FakeExecutor {
        fn ok(exit_code: i32, stderr_tail: &str) -> Self {
            Self::full(exit_code, "", stderr_tail)
        }
        /// Like [`Self::ok`] but with scripted stdout (build/prefetch
        /// ops read their store path from stdout).
        fn full(exit_code: i32, stdout: &str, stderr_tail: &str) -> Self {
            Self {
                result: Ok(OpExecResult {
                    exit_code,
                    stdout: stdout.to_string(),
                    stderr_tail: stderr_tail.to_string(),
                }),
                seen: std::cell::RefCell::new(None),
            }
        }
        fn erroring() -> Self {
            Self {
                result: Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "nix not found",
                )),
                seen: std::cell::RefCell::new(None),
            }
        }
    }

    impl OpExecutor for FakeExecutor {
        fn run(&self, argv: &[String]) -> std::io::Result<OpExecResult> {
            *self.seen.borrow_mut() = Some(argv.to_vec());
            // io::Error isn't Clone; rebuild the same kind on the error arm.
            match &self.result {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    #[test]
    fn nix_argv_prepends_experimental_features() {
        assert_eq!(
            nix_argv(&["path-info", "/nix/store/x"]),
            vec![
                "nix".to_string(),
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "path-info".to_string(),
                "/nix/store/x".to_string(),
            ]
        );
    }

    #[test]
    fn flake_check_argv_is_a_no_build_eval_check() {
        assert_eq!(
            flake_check_argv("/work/nix"),
            vec![
                "nix".to_string(),
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "flake".to_string(),
                "check".to_string(),
                "--no-build".to_string(),
                "path:/work/nix".to_string(),
            ]
        );
    }

    #[test]
    fn flake_check_argv_passes_scheme_refs_through_unwrapped() {
        // A scheme-qualified flake ref must NOT be `path:`-wrapped (that yields
        // `path:github:…`, a non-existent path).
        assert_eq!(
            flake_check_argv("github:numtide/flake-utils")
                .last()
                .unwrap(),
            "github:numtide/flake-utils"
        );
        assert_eq!(
            flake_check_argv("git+https://example.com/r")
                .last()
                .unwrap(),
            "git+https://example.com/r"
        );
        // An explicit `path:` ref is already qualified — no double wrap.
        assert_eq!(
            flake_check_argv("path:/work/nix").last().unwrap(),
            "path:/work/nix"
        );
        // Bare paths still get wrapped.
        assert_eq!(flake_check_argv(".").last().unwrap(), "path:.");
        assert_eq!(
            flake_check_argv("/abs/dir").last().unwrap(),
            "path:/abs/dir"
        );
    }

    #[test]
    fn has_uri_scheme_distinguishes_refs_from_paths() {
        assert!(has_uri_scheme("github:x/y"));
        assert!(has_uri_scheme("path:/a"));
        assert!(has_uri_scheme("git+https://h/r"));
        assert!(!has_uri_scheme("/work/nix"));
        assert!(!has_uri_scheme("."));
        assert!(!has_uri_scheme("./rel"));
        assert!(!has_uri_scheme(":leadingcolon"));
    }

    #[test]
    fn tail_lines_keeps_only_the_last_n() {
        assert_eq!(tail_lines("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(tail_lines("only", 5), "only");
        assert_eq!(tail_lines("", 3), "");
    }

    #[test]
    fn flake_check_clean_exit_completes() {
        let exec = FakeExecutor::ok(0, "");
        let resp = dispatch_flake_check(op(), "/work/nix", &exec);
        assert!(matches!(resp, BuilderResponse::Completed { op: got } if got == op()));
        // The executor was handed the no-build eval argv.
        assert_eq!(
            exec.seen.into_inner().unwrap(),
            flake_check_argv("/work/nix")
        );
    }

    #[test]
    fn flake_check_nonzero_exit_is_nix_eval_failure() {
        let exec = FakeExecutor::ok(1, "error: attribute 'foo' missing");
        match dispatch_flake_check(op(), "/work/nix", &exec) {
            BuilderResponse::Failed {
                category, message, ..
            } => {
                assert_eq!(category, FailureCategory::NixEval);
                assert!(message.contains("attribute 'foo' missing"), "{message}");
            }
            other => panic!("expected Failed/NixEval, got {other:?}"),
        }
    }

    #[test]
    fn flake_check_executor_error_is_internal_and_retryable() {
        let exec = FakeExecutor::erroring();
        match dispatch_flake_check(op(), "/work/nix", &exec) {
            BuilderResponse::Failed {
                category,
                retryable,
                ..
            } => {
                assert_eq!(category, FailureCategory::Internal);
                assert!(retryable, "an executor (spawn) error is retryable");
            }
            other => panic!("expected Failed/Internal, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_with_executor_routes_build_ops_but_delegates_control_ops() {
        // A clean build emits an out-path on stdout.
        let exec = FakeExecutor::full(0, "/nix/store/aaaa-img\n", "");
        // FlakeCheck reaches the executor → Completed.
        assert!(matches!(
            dispatch_with_executor(
                &BuilderRequest::FlakeCheck {
                    op: op(),
                    flake_path: "/work/nix".to_string(),
                },
                &exec,
            ),
            BuilderResponse::Completed { .. }
        ));
        // BuildGuestImage now reaches the executor → ArtifactReady.
        assert!(matches!(
            dispatch_with_executor(
                &BuilderRequest::BuildGuestImage {
                    op: op(),
                    flake_ref: "path:.".to_string(),
                    attr_path: "packages.aarch64-linux.default".to_string(),
                    fingerprint: None,
                    output_dir: None,
                },
                &exec,
            ),
            BuilderResponse::ArtifactReady { .. }
        ));
        // Control ops still delegate to the stateless dispatch.
        assert!(matches!(
            dispatch_with_executor(&BuilderRequest::Probe { op: op() }, &exec),
            BuilderResponse::Accepted { .. }
        ));
        assert!(matches!(
            dispatch_with_executor(&BuilderRequest::CancelJob { target: op() }, &exec),
            BuilderResponse::Cancelled { .. }
        ));
    }

    #[test]
    fn nix_build_argv_targets_the_flake_attr_with_print_out_paths() {
        assert_eq!(
            nix_build_argv("path:.", "packages.aarch64-linux.default"),
            vec![
                "nix".to_string(),
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "build".to_string(),
                "path:.#packages.aarch64-linux.default".to_string(),
                "--no-link".to_string(),
                "--print-out-paths".to_string(),
            ]
        );
    }

    #[test]
    fn nix_build_clean_exit_reports_artifact_from_last_out_path() {
        let exec = FakeExecutor::full(0, "/nix/store/bbbb-old\n/nix/store/cccc-img\n", "");
        match dispatch_nix_build(op(), "path:.", "x", None, &exec) {
            BuilderResponse::ArtifactReady {
                artifact_path,
                store_path,
                ..
            } => {
                assert_eq!(artifact_path, "/nix/store/cccc-img");
                assert_eq!(store_path, Some("/nix/store/cccc-img".to_string()));
            }
            other => panic!("expected ArtifactReady, got {other:?}"),
        }
    }

    #[test]
    fn export_copies_kernel_and_rootfs_from_a_dir_out_path() {
        let tmp = tempfile::tempdir().unwrap();
        let nix_out = tmp.path().join("store-img");
        std::fs::create_dir_all(&nix_out).unwrap();
        std::fs::write(nix_out.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(nix_out.join("rootfs.ext4"), b"rootfs").unwrap();
        let out = tmp.path().join("job-out");
        export_image_artifacts(&nix_out, &out).unwrap();
        assert_eq!(std::fs::read(out.join("vmlinux")).unwrap(), b"kernel");
        assert_eq!(std::fs::read(out.join("rootfs.ext4")).unwrap(), b"rootfs");
    }

    #[test]
    fn export_treats_a_file_out_path_as_the_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let nix_out = tmp.path().join("just-rootfs.ext4");
        std::fs::write(&nix_out, b"rootfs-bytes").unwrap();
        let out = tmp.path().join("job-out");
        export_image_artifacts(&nix_out, &out).unwrap();
        assert_eq!(
            std::fs::read(out.join("rootfs.ext4")).unwrap(),
            b"rootfs-bytes"
        );
        assert!(!out.join("vmlinux").exists());
    }

    #[test]
    fn copy_artifact_flushes_a_read_only_source_without_changing_its_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let destination = tmp.path().join("destination");
        std::fs::write(&source, b"sealed artifact").unwrap();
        let mut permissions = std::fs::metadata(&source).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&source, permissions).unwrap();

        copy_artifact(&source, &destination).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"sealed artifact");
        assert!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .readonly()
        );
    }

    #[test]
    fn copy_artifact_names_a_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("missing");
        let destination = tmp.path().join("destination");

        let error = copy_artifact(&source, &destination).unwrap_err();

        assert!(error.contains(&source.display().to_string()), "{error}");
        assert!(!destination.exists());
    }

    #[test]
    fn export_errors_when_dir_out_path_has_no_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let nix_out = tmp.path().join("store-img");
        std::fs::create_dir_all(&nix_out).unwrap();
        std::fs::write(nix_out.join("vmlinux"), b"kernel").unwrap();
        let out = tmp.path().join("job-out");
        assert!(export_image_artifacts(&nix_out, &out).is_err());
    }

    #[test]
    fn dispatch_nix_build_with_output_dir_exports_and_reports_the_dir() {
        // The executor prints the out-path; point it at a real dir with
        // artifacts so the export step copies them and `artifact_path` becomes
        // the host-readable output dir while `store_path` stays the out-path.
        let tmp = tempfile::tempdir().unwrap();
        let nix_out = tmp.path().join("store-img");
        std::fs::create_dir_all(&nix_out).unwrap();
        std::fs::write(nix_out.join("vmlinux"), b"k").unwrap();
        std::fs::write(nix_out.join("rootfs.ext4"), b"r").unwrap();
        let out = tmp.path().join("job-out");
        let exec = FakeExecutor::full(0, &format!("{}\n", nix_out.display()), "");
        match dispatch_nix_build(op(), "path:.", "x", Some(out.to_str().unwrap()), &exec) {
            BuilderResponse::ArtifactReady {
                artifact_path,
                store_path,
                ..
            } => {
                assert_eq!(artifact_path, out.to_str().unwrap());
                assert_eq!(store_path, Some(nix_out.to_string_lossy().into_owned()));
                assert!(out.join("rootfs.ext4").is_file());
                assert!(out.join("vmlinux").is_file());
            }
            other => panic!("expected ArtifactReady, got {other:?}"),
        }
    }

    #[test]
    fn nix_build_clean_exit_without_out_path_is_nix_build_failure() {
        let exec = FakeExecutor::full(0, "   \n", "");
        assert!(matches!(
            dispatch_nix_build(op(), "path:.", "x", None, &exec),
            BuilderResponse::Failed {
                category: FailureCategory::NixBuild,
                ..
            }
        ));
    }

    #[test]
    fn nix_build_nonzero_exit_is_nix_build_failure() {
        let exec = FakeExecutor::full(1, "", "error: builder failed");
        match dispatch_nix_build(op(), "path:.", "x", None, &exec) {
            BuilderResponse::Failed {
                category, message, ..
            } => {
                assert_eq!(category, FailureCategory::NixBuild);
                assert!(message.contains("builder failed"), "{message}");
            }
            other => panic!("expected Failed/NixBuild, got {other:?}"),
        }
    }

    #[test]
    fn nix_build_executor_error_is_internal_and_retryable() {
        match dispatch_nix_build(op(), "path:.", "x", None, &FakeExecutor::erroring()) {
            BuilderResponse::Failed {
                category,
                retryable,
                ..
            } => {
                assert_eq!(category, FailureCategory::Internal);
                assert!(retryable);
            }
            other => panic!("expected Failed/Internal, got {other:?}"),
        }
    }

    #[test]
    fn build_host_tool_uses_the_same_nix_build_path() {
        let exec = FakeExecutor::full(0, "/nix/store/dddd-tool\n", "");
        assert!(matches!(
            dispatch_with_executor(
                &BuilderRequest::BuildHostTool {
                    op: op(),
                    flake_ref: "path:.".to_string(),
                    attr_path: "packages.aarch64-linux.mvm-host-vm-init".to_string(),
                    fingerprint: Some("blake3:abcd".to_string()),
                },
                &exec,
            ),
            BuilderResponse::ArtifactReady { .. }
        ));
    }

    #[test]
    fn prefetch_source_argv_requests_json() {
        assert_eq!(
            prefetch_source_argv("github:nixos/nixpkgs"),
            vec![
                "nix".to_string(),
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "flake".to_string(),
                "prefetch".to_string(),
                "github:nixos/nixpkgs".to_string(),
                "--json".to_string(),
            ]
        );
    }

    #[test]
    fn prefetch_clean_exit_parses_store_path_json() {
        let exec = FakeExecutor::full(
            0,
            r#"{"hash":"sha256-abc","storePath":"/nix/store/eeee-src"}"#,
            "",
        );
        match dispatch_prefetch_source(op(), "github:nixos/nixpkgs", &exec) {
            BuilderResponse::StorePathReady {
                store_path,
                already_present,
                ..
            } => {
                assert_eq!(store_path, "/nix/store/eeee-src");
                assert!(!already_present);
            }
            other => panic!("expected StorePathReady, got {other:?}"),
        }
    }

    #[test]
    fn prefetch_nonzero_exit_is_retryable_fetch_failure() {
        let exec = FakeExecutor::full(1, "", "error: unable to download");
        match dispatch_prefetch_source(op(), "github:x/y", &exec) {
            BuilderResponse::Failed {
                category,
                retryable,
                ..
            } => {
                assert_eq!(category, FailureCategory::Fetch);
                assert!(retryable);
            }
            other => panic!("expected Failed/Fetch, got {other:?}"),
        }
    }

    #[test]
    fn prefetch_clean_exit_without_store_path_is_fetch_failure() {
        let exec = FakeExecutor::full(0, "not json", "");
        assert!(matches!(
            dispatch_prefetch_source(op(), "github:x/y", &exec),
            BuilderResponse::Failed {
                category: FailureCategory::Fetch,
                ..
            }
        ));
    }

    #[test]
    fn query_store_path_argv_uses_path_info() {
        assert_eq!(
            query_store_path_argv("/nix/store/ffff-foo"),
            vec![
                "nix".to_string(),
                "--extra-experimental-features".to_string(),
                "nix-command flakes".to_string(),
                "path-info".to_string(),
                "/nix/store/ffff-foo".to_string(),
            ]
        );
    }

    #[test]
    fn query_store_path_present_when_exit_zero_absent_otherwise() {
        let present = FakeExecutor::ok(0, "");
        match dispatch_query_store_path(op(), "/nix/store/ffff-foo", &present) {
            BuilderResponse::StorePathReady {
                store_path,
                already_present,
                ..
            } => {
                assert_eq!(store_path, "/nix/store/ffff-foo");
                assert!(already_present);
            }
            other => panic!("expected StorePathReady present, got {other:?}"),
        }
        let absent = FakeExecutor::ok(1, "path is not valid");
        assert!(matches!(
            dispatch_query_store_path(op(), "/nix/store/ffff-foo", &absent),
            BuilderResponse::StorePathReady {
                already_present: false,
                ..
            }
        ));
    }

    #[test]
    fn query_store_path_executor_error_is_internal() {
        assert!(matches!(
            dispatch_query_store_path(op(), "/nix/store/x", &FakeExecutor::erroring()),
            BuilderResponse::Failed {
                category: FailureCategory::Internal,
                ..
            }
        ));
    }

    #[test]
    fn serve_connection_with_executor_runs_a_build_over_the_wire() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_agentd::vsock::write_frame(
            &mut client,
            &BuilderRequest::BuildGuestImage {
                op: op(),
                flake_ref: "path:.".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
                fingerprint: None,
                output_dir: None,
            },
        )
        .expect("write");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");
        let exec = FakeExecutor::full(0, "/nix/store/gggg-img\n", "");
        serve_connection_with_executor(&mut server, &exec).expect("serve");
        let resp = mvm_agentd::vsock::read_frame::<BuilderResponse>(&mut client).expect("read");
        assert!(
            matches!(resp, BuilderResponse::ArtifactReady { op: got, store_path: Some(p), .. }
                if got == op() && p == "/nix/store/gggg-img")
        );
    }

    #[test]
    fn serve_connection_with_executor_runs_flake_check_over_the_wire() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        mvm_agentd::vsock::write_frame(
            &mut client,
            &BuilderRequest::FlakeCheck {
                op: op(),
                flake_path: "/work/nix".to_string(),
            },
        )
        .expect("write");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-close");
        let exec = FakeExecutor::ok(0, "");
        serve_connection_with_executor(&mut server, &exec).expect("serve");
        let resp = mvm_agentd::vsock::read_frame::<BuilderResponse>(&mut client).expect("read");
        assert!(matches!(resp, BuilderResponse::Completed { op: got } if got == op()));
    }

    // ---- host-side readiness probe ------------------------------------

    #[test]
    fn control_socket_path_uses_builderd_port() {
        let port = mvm_agentd::builder_agent::BUILDERD_CONTROL_PORT;
        let dir = Path::new("/var/lib/mvm/vm-foo");
        // libkrun: directly in the state dir.
        assert_eq!(
            builderd_control_socket_path(dir),
            Path::new(&format!("/var/lib/mvm/vm-foo/vsock-{port}.sock"))
        );
        // HVF: one subdir deeper, under `vsock/` (the bug the live HVF boot
        // surfaced — doctor/client must not assume the libkrun shape).
        assert_eq!(
            builderd_hvf_control_socket_path(dir),
            Path::new(&format!("/var/lib/mvm/vm-foo/vsock/vsock-{port}.sock"))
        );
        // Candidates: libkrun first, then HVF.
        assert_eq!(
            builderd_control_socket_candidates(dir),
            [
                builderd_control_socket_path(dir),
                builderd_hvf_control_socket_path(dir),
            ]
        );
    }

    #[test]
    fn control_socket_path_shortens_deep_worktree_state_dirs() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("x".repeat(120));
        std::fs::create_dir_all(&dir).unwrap();

        let socket = builderd_control_socket_path(&dir);
        assert_ne!(socket.parent(), Some(dir.as_path()));
        assert!(socket.to_string_lossy().len() <= 103);
    }

    #[test]
    fn probe_reports_not_running_when_socket_absent() {
        let missing = std::path::Path::new("/nonexistent/mvm/builderd/vsock-21473.sock");
        assert_eq!(
            probe_builderd_readiness(missing, Duration::from_millis(100)),
            BuilderdReadiness::NotRunning
        );
    }

    #[test]
    fn probe_reports_ready_against_a_live_daemon() {
        use std::os::unix::net::UnixListener;
        // Stand up the real serve loop behind a UnixListener and probe
        // it end-to-end over the typed handshake.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock-21473.sock");
        let listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping test: sandbox denied binding Unix socket {}: {err}",
                    sock.display()
                );
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let handle = std::thread::spawn(move || {
            // Serve exactly one connection then return.
            let (mut conn, _addr) = listener.accept().expect("accept");
            serve_connection(&mut conn).expect("serve");
        });

        let readiness = probe_builderd_readiness(&sock, Duration::from_secs(2));
        assert_eq!(
            readiness,
            BuilderdReadiness::Ready {
                version: PROTOCOL_VERSION
            }
        );
        handle.join().expect("server thread");
    }

    #[test]
    fn probe_reports_unreachable_on_stale_socket() {
        use std::os::unix::net::UnixListener;
        // A bound socket whose owner never accepts/serves: connect
        // succeeds (queued), but the handshake read times out. Models a
        // crashed daemon that left its socket behind.
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("vsock-21473.sock");
        let _listener = match UnixListener::bind(&sock) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping test: sandbox denied binding Unix socket {}: {err}",
                    sock.display()
                );
                return;
            }
            Err(err) => panic!("bind: {err}"),
        };
        let readiness = probe_builderd_readiness(&sock, Duration::from_millis(150));
        assert!(
            matches!(readiness, BuilderdReadiness::Unreachable { .. }),
            "expected Unreachable, got {readiness:?}"
        );
    }

    #[test]
    fn readiness_summary_maps_every_variant() {
        assert_eq!(
            readiness_summary(&BuilderdReadiness::Ready { version: 1 }),
            "ready (protocol v1)"
        );
        assert_eq!(
            readiness_summary(&BuilderdReadiness::NotRunning),
            "not running"
        );
        assert!(
            readiness_summary(&BuilderdReadiness::VersionMismatch {
                detail: "speaks 2".to_string()
            })
            .starts_with("version mismatch")
        );
        assert!(
            readiness_summary(&BuilderdReadiness::Unreachable {
                detail: "boom".to_string()
            })
            .starts_with("unreachable")
        );
    }
}
